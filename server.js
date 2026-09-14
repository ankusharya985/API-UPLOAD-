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
const metaBaseUrl=`${baseUrl}/meta`;
const META_GRAPH_VERSION=process.env.META_GRAPH_VERSION||"v23.0";
const META_APP_ID=process.env.META_APP_ID||"";
const META_APP_SECRET=process.env.META_APP_SECRET||"";
const META_CONFIG_ID=process.env.META_CONFIG_ID||"";
const META_REDIRECT_URI=`${baseUrl}/meta/oauth/callback`;
const META_SCOPES=(process.env.META_SCOPES||"pages_show_list,pages_read_engagement,publish_video,instagram_basic,instagram_content_publish,business_management").split(",").map(s=>s.trim()).filter(Boolean);
const socialFile=path.join(dataDir,"social.json");
function socialRead(){try{return JSON.parse(fs.readFileSync(socialFile,"utf8"))}catch{return{facebook:[],instagram:[]}}}
function socialWrite(db){fs.writeFileSync(socialFile,JSON.stringify(db,null,2))}
function metaUrl(pathname,params={}){const u=new URL(`https://graph.facebook.com/${META_GRAPH_VERSION}${pathname}`);for(const [k,v] of Object.entries(params))if(v!==undefined&&v!==null)u.searchParams.set(k,String(v));return u}
async function metaJson(pathname,params={},options={}){const u=metaUrl(pathname,params);const r=await fetch(u,{method:options.method||"GET",headers:options.headers||{},body:options.body});const text=await r.text();let data={};try{data=JSON.parse(text)}catch{}if(!r.ok||data.error)throw new Error(data?.error?.message||`Meta API HTTP ${r.status}`);return data}
function signMetaState(payload){const body=JSON.stringify(payload);const sig=crypto.createHmac("sha256",SESSION_SECRET).update(body).digest("hex");return Buffer.from(JSON.stringify({p:payload,sig})).toString("base64url")}
function verifyMetaState(raw){const state=JSON.parse(Buffer.from(String(raw),"base64url").toString("utf8"));const body=JSON.stringify(state.p);const sig=crypto.createHmac("sha256",SESSION_SECRET).update(body).digest("hex");if(state.sig!==sig||Number(state.p.exp)<Date.now())throw new Error("Meta OAuth state expired or invalid.");return state.p}
function publicSocial(db){return{facebook:(db.facebook||[]).map(x=>({id:x.id,name:x.name,picture:x.picture||"",connectedAt:x.connectedAt||null})),instagram:(db.instagram||[]).map(x=>({id:x.id,username:x.username||x.name||"Instagram",name:x.name||"Instagram",picture:x.picture||"",pageId:x.pageId||"",connectedAt:x.connectedAt||null}))}}
function metaMediaToken(filePath){const payload={p:filePath,e:Date.now()+15*60*1000,n:crypto.randomBytes(12).toString("hex")};return signMetaState(payload)}


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

app.get("/meta/connect",requireAdmin,(req,res)=>{
  if(!META_APP_ID||!META_APP_SECRET)return res.status(500).send("Meta integration is not configured on Render. Add META_APP_ID and META_APP_SECRET first.");
  const payload={nonce:crypto.randomBytes(18).toString("hex"),exp:Date.now()+10*60*1000};
  const state=signMetaState(payload);
  const u=new URL(`https://www.facebook.com/${META_GRAPH_VERSION}/dialog/oauth`);
  u.searchParams.set("client_id",META_APP_ID);u.searchParams.set("redirect_uri",META_REDIRECT_URI);u.searchParams.set("state",state);u.searchParams.set("response_type","code");
  if(META_CONFIG_ID)u.searchParams.set("config_id",META_CONFIG_ID);else u.searchParams.set("scope",META_SCOPES.join(","));
  res.redirect(u.toString());
});

app.get("/meta/oauth/callback",async(req,res)=>{
  try{
    if(req.query.error)return res.redirect("/?meta=cancelled");
    if(!req.query.code||!req.query.state)return res.status(400).send("Meta authorization data missing.");
    verifyMetaState(req.query.state);
    const tokenRes=await fetch(metaUrl("/oauth/access_token",{client_id:META_APP_ID,client_secret:META_APP_SECRET,redirect_uri:META_REDIRECT_URI,code:req.query.code}));
    const tokenText=await tokenRes.text();let tokenData={};try{tokenData=JSON.parse(tokenText)}catch{}
    if(!tokenRes.ok||tokenData.error)throw new Error(tokenData?.error?.message||"Meta token exchange failed.");
    const userToken=tokenData.access_token;
    const pages=await metaJson("/me/accounts",{access_token:userToken,fields:"id,name,access_token,picture,instagram_business_account{id,username,name,profile_picture_url}"});
    const db=socialRead();db.facebook=db.facebook||[];db.instagram=db.instagram||[];
    for(const p of pages.data||[]){
      const existing=db.facebook.find(x=>x.id===p.id);
      const rec={id:p.id,name:p.name||"Facebook Page",accessToken:p.access_token,picture:p.picture?.data?.url||"",userToken,connectedAt:existing?.connectedAt||new Date().toISOString()};
      db.facebook=db.facebook.filter(x=>x.id!==p.id);db.facebook.push(rec);
      const ig=p.instagram_business_account;
      if(ig?.id){
        const ie=db.instagram.find(x=>x.id===ig.id);db.instagram=db.instagram.filter(x=>x.id!==ig.id);db.instagram.push({id:ig.id,username:ig.username||ig.name||"Instagram",name:ig.name||ig.username||"Instagram",picture:ig.profile_picture_url||"",pageId:p.id,pageName:p.name||"",accessToken:p.access_token,connectedAt:ie?.connectedAt||new Date().toISOString()});
      }
    }
    socialWrite(db);res.redirect("/?meta=connected");
  }catch(e){console.error("Meta OAuth callback:",e);res.status(500).send("Meta authorization failed. Check Render logs and Meta permissions.")}
});

app.get("/api/social",requireAdmin,(req,res)=>res.json(publicSocial(socialRead())));
app.post("/api/social/disconnect",requireAdmin,(req,res)=>{const {type,id}=req.body||{};const db=socialRead();if(type==="facebook")db.facebook=(db.facebook||[]).filter(x=>x.id!==String(id));if(type==="instagram")db.instagram=(db.instagram||[]).filter(x=>x.id!==String(id));socialWrite(db);res.json({success:true,...publicSocial(db)});});

app.get("/media/:token",async(req,res)=>{
  try{
    const p=verifyMetaState(req.params.token);if(!p.p||Number(p.e)<Date.now())return res.status(410).send("Expired media URL");
    if(!fs.existsSync(p.p))return res.status(404).send("Media not found");
    res.sendFile(path.resolve(p.p));
  }catch{return res.status(403).send("Invalid media URL")}
});

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
    const social=socialRead();
    const fbTargets=(social.facebook||[]).filter(c=>Array.isArray(req.body.facebookPages)&&req.body.facebookPages.includes(c.id));
    const igTargets=(social.instagram||[]).filter(c=>Array.isArray(req.body.instagramAccounts)&&req.body.instagramAccounts.includes(c.id));
    if(!targets.length&&!fbTargets.length&&!igTargets.length)return res.status(400).json({error:"Enable at least one YouTube channel or select a Facebook/Instagram account."});

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
    let facebookPages=[],instagramAccounts=[];try{facebookPages=JSON.parse(req.body.facebookPages||"[]")}catch{}try{instagramAccounts=JSON.parse(req.body.instagramAccounts||"[]")}catch{}
    const facebookCaption=String(req.body.facebookCaption||description);
    const instagramCaption=String(req.body.instagramCaption||description);
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
    // Meta social publishing is deliberately isolated from the existing YouTube loop.
    // If Meta fails, YouTube results remain intact and are still returned.
    for(const p of fbTargets){
      try{
        const u=metaUrl(`/${p.id}/videos`);
        const form=new FormData();form.append("access_token",p.accessToken);form.append("description",facebookCaption);form.append("published","true");
        form.append("source",new Blob([fs.readFileSync(video.path)],{type:video.mimetype||"video/mp4"}),path.basename(video.originalname||video.path));
        const r=await fetch(u,{method:"POST",body:form});const d=await r.json();if(!r.ok||d.error)throw new Error(d?.error?.message||`Facebook HTTP ${r.status}`);
        results.push({platform:"facebook",title:p.name,success:true,id:d.id,url:`https://www.facebook.com/${d.id}`});
      }catch(e){console.error("facebook publish",p.id,e);results.push({platform:"facebook",title:p.name,success:false,error:e.message||"Facebook publish failed."})}
    }
    for(const ig of igTargets){
      try{
        const token=metaMediaToken(video.path);const publicUrl=`${baseUrl}/media/${encodeURIComponent(token)}`;
        const container=await metaJson(`/${ig.id}/media`,{}, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({access_token:ig.accessToken,media_type:"REELS",video_url:publicUrl,caption:instagramCaption})});
        let status="IN_PROGRESS";let info={};
        for(let i=0;i<30&&status!="FINISHED";i++){
          await new Promise(r=>setTimeout(r,2000));info=await metaJson(`/${container.id}`,{access_token:ig.accessToken,fields:"status_code,status"});status=info.status_code||info.status||"";
          if(status==="ERROR"||status==="EXPIRED")throw new Error(`Instagram media processing ${status}.`);
        }
        if(status!=="FINISHED")throw new Error("Instagram media processing timed out. Try again.");
        const published=await metaJson(`/${ig.id}/media_publish`,{}, {method:"POST",headers:{"Content-Type":"application/x-www-form-urlencoded"},body:new URLSearchParams({access_token:ig.accessToken,creation_id:container.id})});
        results.push({platform:"instagram",title:ig.username||ig.name,success:true,id:published.id||container.id});
      }catch(e){console.error("instagram publish",ig.id,e);results.push({platform:"instagram",title:ig.username||ig.name,success:false,error:e.message||"Instagram publish failed."})}
    }
    res.json({success:results.some(x=>x.success),results});
  }catch(e){console.error("multi upload",e);res.status(500).json({error:e.message||"Upload failed."})}
  finally{for(const f of [video,thumb])if(f?.path)try{fs.unlinkSync(f.path)}catch{}}
});

app.get("/health",(req,res)=>res.json({status:"ok",service:"YT Admin Studio",redirectUri}));

app.listen(PORT,()=>console.log("YT Admin Studio running on",PORT));
