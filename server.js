require("dotenv").config();
const express=require("express");
const multer=require("multer");
const fs=require("fs");
const path=require("path");
const crypto=require("crypto");
const {google}=require("googleapis");

const app=express();
const PORT=process.env.PORT||3000;
const MAX_CHANNELS=7;

const SCOPES=[
  "https://www.googleapis.com/auth/youtube.upload",
  "https://www.googleapis.com/auth/youtube.readonly",
  "https://www.googleapis.com/auth/youtube"
];

const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||"";
const SESSION_SECRET=process.env.SESSION_SECRET||ADMIN_PASSWORD;
const SESSION_TTL=7*24*60*60*1000;

const uploadDir=path.join(__dirname,"uploads");
const dataDir=path.join(__dirname,"data");
if(!fs.existsSync(uploadDir))fs.mkdirSync(uploadDir,{recursive:true});
if(!fs.existsSync(dataDir))fs.mkdirSync(dataDir,{recursive:true});
const dbFile=path.join(dataDir,"channels.json");

const upload=multer({
  dest:uploadDir,
  limits:{fileSize:20*1024*1024*1024}
});

app.use(express.json({limit:"2mb"}));
app.use(express.urlencoded({extended:true}));
app.use(express.static(path.join(__dirname,"public")));

const baseUrl=(process.env.RENDER_EXTERNAL_URL||`http://localhost:${PORT}`).replace(/\/$/,"");
const redirectUri=`${baseUrl}/oauth2callback`;

function dbRead(){try{return JSON.parse(fs.readFileSync(dbFile,"utf8"))}catch{return{channels:[]}}}
function dbWrite(db){fs.writeFileSync(dbFile,JSON.stringify(db,null,2))}
function oauth(){return new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET,redirectUri)}

function signSession(exp){
  const raw=`${exp}`;
  const sig=crypto.createHmac("sha256",SESSION_SECRET).update(raw).digest("hex");
  return `${raw}.${sig}`;
}
function validSession(token){
  if(!token||!SESSION_SECRET)return false;
  const [exp,sig]=String(token).split(".");
  if(!exp||!sig||Number(exp)<Date.now())return false;
  const expected=crypto.createHmac("sha256",SESSION_SECRET).update(exp).digest("hex");
  return crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(expected));
}
function cookieSession(req){return (req.headers.cookie||"").split(";").map(x=>x.trim()).find(x=>x.startsWith("admin_session="))?.split("=")[1]||""}
function isAdmin(req){return validSession(cookieSession(req))||validSession(req.headers["x-admin-session"])||validSession(req.query.session)}
function requireAdmin(req,res,next){if(!isAdmin(req))return res.status(401).json({error:"Admin login required."});next()}
function publicChannel(c){return{slot:c.slot,connected:!!c.tokens,title:c.title||`Channel ${c.slot}`,thumbnail:c.thumbnail||"",enabled:!!c.enabled,channelId:c.channelId||""}}

async function channelInfo(o){
  const y=google.youtube({version:"v3",auth:o});
  const r=await y.channels.list({part:["snippet","statistics","contentDetails"],mine:true});
  const c=r.data.items?.[0];if(!c)return null;
  return{
    channelId:c.id,
    title:c.snippet?.title||"YouTube Channel",
    thumbnail:c.snippet?.thumbnails?.high?.url||c.snippet?.thumbnails?.default?.url||"",
    subscribers:c.statistics?.subscriberCount||"0",
    videos:c.statistics?.videoCount||"0",
    views:c.statistics?.viewCount||"0",
    uploadsPlaylistId:c.contentDetails?.relatedPlaylists?.uploads||""
  };
}

app.get("/",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));

app.post("/api/login",(req,res)=>{
  if(!ADMIN_PASSWORD)return res.status(500).json({error:"ADMIN_PASSWORD is not configured."});
  const p=String(req.body.password||"");
  const a=Buffer.from(p),b=Buffer.from(ADMIN_PASSWORD);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return res.status(401).json({error:"Incorrect password."});
  const token=signSession(Date.now()+SESSION_TTL);
  res.setHeader("Set-Cookie",`admin_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_TTL/1000}`);
  res.json({success:true});
});
app.post("/api/logout",(req,res)=>{
  res.setHeader("Set-Cookie","admin_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0");
  res.json({success:true});
});
app.get("/api/auth-status",(req,res)=>res.json({loggedIn:isAdmin(req)}));

app.get("/auth/:slot",(req,res)=>{
  if(!isAdmin(req))return res.redirect("/");
  const slot=Number(req.params.slot);
  if(!Number.isInteger(slot)||slot<1||slot>MAX_CHANNELS)return res.status(400).send("Invalid channel slot.");
  const statePayload={slot,nonce:crypto.randomBytes(18).toString("hex"),exp:Date.now()+10*60*1000};
  const body=JSON.stringify(statePayload);
  const sig=crypto.createHmac("sha256",SESSION_SECRET).update(body).digest("hex");
  const state=Buffer.from(JSON.stringify({p:statePayload,sig})).toString("base64url");
  const o=oauth();
  const url=o.generateAuthUrl({access_type:"offline",prompt:"consent",include_granted_scopes:true,scope:SCOPES,state});
  res.redirect(url);
});

app.get("/oauth2callback",async(req,res)=>{
  try{
    if(req.query.error)return res.redirect("/?error=oauth_cancelled");
    if(!req.query.code||!req.query.state)return res.status(400).send("Authorization data missing.");
    const state=JSON.parse(Buffer.from(req.query.state,"base64url").toString("utf8"));
    const body=JSON.stringify(state.p);
    const sig=crypto.createHmac("sha256",SESSION_SECRET).update(body).digest("hex");
    if(state.sig!==sig||Number(state.p.exp)<Date.now())return res.status(401).send("OAuth state expired or invalid. Please try again.");
    const slot=Number(state.p.slot);
    if(slot<1||slot>MAX_CHANNELS)return res.status(400).send("Invalid channel slot.");
    const o=oauth();
    const {tokens}=await o.getToken(req.query.code);
    o.setCredentials(tokens);
    const info=await channelInfo(o);
    if(!info)return res.status(400).send("No YouTube channel found.");
    const db=dbRead();db.channels=db.channels||[];
    const old=db.channels.find(c=>c.slot===slot);
    const record={slot,tokens:{...(old?.tokens||{}),...tokens},enabled:old?.enabled??true,...info};
    db.channels=db.channels.filter(c=>c.slot!==slot);db.channels.push(record);db.channels.sort((a,b)=>a.slot-b.slot);dbWrite(db);
    res.redirect("/?connected=1");
  }catch(e){console.error("OAuth callback:",e.response?.data||e);res.status(500).send("YouTube authorization failed. Check Render logs.")}
});

app.get("/api/channels",requireAdmin,async(req,res)=>{
  const db=dbRead();db.channels=db.channels||[];const out=[];
  for(let slot=1;slot<=MAX_CHANNELS;slot++){
    const c=db.channels.find(x=>x.slot===slot);
    if(!c){out.push({slot,connected:false,title:`Channel ${slot}`,enabled:false});continue}
    try{
      const o=oauth();o.setCredentials(c.tokens);const fresh=await channelInfo(o);
      if(fresh)Object.assign(c,fresh);
      out.push(publicChannel(c));
    }catch{out.push({...publicChannel(c),connected:false})}
  }
  dbWrite(db);res.json({channels:out});
});

app.post("/api/channels/:slot/toggle",requireAdmin,(req,res)=>{
  const slot=Number(req.params.slot),db=dbRead();const c=(db.channels||[]).find(x=>x.slot===slot);
  if(!c?.tokens)return res.status(404).json({error:"Channel is not connected."});
  c.enabled=!!req.body.enabled;dbWrite(db);res.json({success:true,enabled:c.enabled});
});

app.get("/api/playlists/:slot",requireAdmin,async(req,res)=>{
  try{
    const slot=Number(req.params.slot),c=dbRead().channels.find(x=>x.slot===slot);
    if(!c?.tokens)return res.status(404).json({error:"Channel is not connected."});
    const o=oauth();o.setCredentials(c.tokens);const y=google.youtube({version:"v3",auth:o});
    let items=[],pageToken="";
    do{
      const r=await y.playlists.list({part:["snippet","status","contentDetails"],mine:true,maxResults:50,pageToken:pageToken||undefined});
      items.push(...(r.data.items||[]));pageToken=r.data.nextPageToken||"";
    }while(pageToken&&items.length<200);
    res.json({playlists:items.map(p=>({id:p.id,title:p.snippet?.title||"",privacy:p.status?.privacyStatus||""}))});
  }catch(e){res.status(500).json({error:e.response?.data?.error?.message||e.message})}
});

function parseDateTime(v){
  if(!v)return null;
  const d=new Date(v);
  if(Number.isNaN(d.getTime()))return null;
  return d.toISOString();
}

app.post("/api/upload",requireAdmin,upload.fields([{name:"video",maxCount:1},{name:"thumbnail",maxCount:1}]),async(req,res)=>{
  const video=req.files?.video?.[0],thumb=req.files?.thumbnail?.[0];
  try{
    if(!video)return res.status(400).json({error:"Video is required."});
    const db=dbRead();const targets=(db.channels||[]).filter(c=>c.tokens&&c.enabled);
    if(!targets.length)return res.status(400).json({error:"Enable at least one connected channel."});

    const title=(req.body.title||"Untitled Video").trim();
    const description=req.body.description||"";
    const schedule=parseDateTime(req.body.publishAt);
    const privacy= req.body.publishMode==="schedule" ? "private" :
      ["public","unlisted","private"].includes(req.body.privacy)?req.body.privacy:"private";
    if(req.body.publishMode==="schedule" && (!schedule||new Date(schedule)<=new Date()))
      return res.status(400).json({error:"Choose a valid future schedule time."});

    const tags=(req.body.tags||"").split(",").map(x=>x.trim()).filter(Boolean);
    const categoryId=String(req.body.categoryId||"22");
    const language=req.body.language||"";
    const license=["youtube","creativeCommon"].includes(req.body.license)?req.body.license:"youtube";
    const embeddable=req.body.embeddable!=="false";
    const publicStats=req.body.publicStats!=="false";
    const kids=req.body.madeForKids==="true";
    const synthetic=req.body.syntheticMedia==="true";
    const notify=req.body.notifySubscribers!=="false";
    const recordingDate=req.body.recordingDate?parseDateTime(req.body.recordingDate):null;
    let playlistSelection={};
try { playlistSelection=JSON.parse(req.body.playlistSelection||"{}"); } catch {}


    const results=[];
    for(const c of targets){
      try{
        const o=oauth();o.setCredentials(c.tokens);
        o.on("tokens",t=>{c.tokens={...(c.tokens||{}),...t};dbWrite(db)});
        const y=google.youtube({version:"v3",auth:o});

        const snippet={title,description,tags,categoryId};
        if(language)snippet.defaultLanguage=language;

        const status={
          privacyStatus:privacy,
          embeddable,
          publicStatsViewable:publicStats,
          selfDeclaredMadeForKids:kids,
          containsSyntheticMedia:synthetic,
          license
        };
        if(schedule)status.publishAt=schedule;

        const body={snippet,status};
        if(recordingDate)body.recordingDetails={recordingDate};

        const r=await y.videos.insert({
          part:["snippet","status","recordingDetails"],
          notifySubscribers:notify,
          requestBody:body,
          media:{mimeType:video.mimetype||"video/*",body:fs.createReadStream(video.path)},
          resumable:true
        });

        const videoId=r.data.id;let thumbOK=false;
        if(thumb&&videoId){
          try{await y.thumbnails.set({videoId,media:{mimeType:thumb.mimetype,body:fs.createReadStream(thumb.path)}});thumbOK=true}catch(e){console.error("thumb",e.response?.data||e)}
        }

        const added=[];
        const playlistIds=Array.isArray(playlistSelection[String(c.slot)]) ? playlistSelection[String(c.slot)] : [];
        for(const pid of playlistIds){
          try{
            await y.playlistItems.insert({
              part:["snippet"],
              requestBody:{snippet:{playlistId:pid,resourceId:{kind:"youtube#video",videoId}}}
            });
            added.push(pid);
          }catch(e){console.error("playlist",e.response?.data||e)}
        }

        results.push({slot:c.slot,title:c.title,success:true,videoId,thumbnailUploaded:thumbOK,playlistsAdded:added.length,url:`https://www.youtube.com/watch?v=${videoId}`});
      }catch(e){
        console.error(`upload slot ${c.slot}`,e.response?.data||e);
        results.push({slot:c.slot,title:c.title,success:false,error:e.response?.data?.error?.message||e.message||"Upload failed."});
      }
    }
    res.json({success:results.some(x=>x.success),results});
  }catch(e){console.error("multi upload",e);res.status(500).json({error:e.message||"Upload failed."})}
  finally{for(const f of [video,thumb])if(f?.path)try{fs.unlinkSync(f.path)}catch{}}
});

app.get("/health",(req,res)=>res.json({status:"ok",service:"YT Admin Studio",redirectUri}));

app.listen(PORT,()=>console.log("YT Admin Studio running on",PORT));
