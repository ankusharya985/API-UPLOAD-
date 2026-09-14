require("dotenv").config();
const express=require("express"),multer=require("multer"),fs=require("fs"),path=require("path"),{google}=require("googleapis");
const app=express(),PORT=process.env.PORT||3000,dir=path.join(__dirname,"uploads");
fs.mkdirSync(dir,{recursive:true});
const upload=multer({dest:dir,limits:{fileSize:20*1024*1024*1024}});
const base=process.env.RENDER_EXTERNAL_URL||`http://localhost:${PORT}`,redirectUri=`${base}/oauth2callback`;
const oauth=new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID,process.env.GOOGLE_CLIENT_SECRET,redirectUri);
const tokenFile=path.join(__dirname,"tokens.json");
if(fs.existsSync(tokenFile))try{oauth.setCredentials(JSON.parse(fs.readFileSync(tokenFile)))}catch{}
app.use(express.json());
app.get("/",(q,s)=>s.sendFile(path.join(__dirname,"index.html")));
app.get("/auth",(q,s)=>s.redirect(oauth.generateAuthUrl({access_type:"offline",prompt:"consent",scope:["https://www.googleapis.com/auth/youtube.upload"]})));
app.get("/oauth2callback",async(q,s)=>{try{const {tokens}=await oauth.getToken(q.query.code);oauth.setCredentials(tokens);fs.writeFileSync(tokenFile,JSON.stringify(tokens));s.redirect("/?connected=1")}catch(e){console.error(e.response?.data||e);s.status(500).send("YouTube authorization failed. Check Render logs.")}});
app.get("/api/status",async(q,s)=>{try{if(!fs.existsSync(tokenFile))return s.json({connected:false});oauth.setCredentials(JSON.parse(fs.readFileSync(tokenFile)));const y=google.youtube({version:"v3",auth:oauth}),r=await y.channels.list({part:["snippet"],mine:true}),c=r.data.items?.[0];s.json({connected:!!c,channel:c?{id:c.id,title:c.snippet.title}:null})}catch(e){s.json({connected:false})}});
app.post("/api/upload",upload.fields([{name:"video",maxCount:1},{name:"thumbnail",maxCount:1}]),async(q,s)=>{
let v=q.files?.video?.[0],t=q.files?.thumbnail?.[0];
try{if(!fs.existsSync(tokenFile))return s.status(401).json({error:"Connect YouTube first."});oauth.setCredentials(JSON.parse(fs.readFileSync(tokenFile)));
const y=google.youtube({version:"v3",auth:oauth}),privacy=["public","unlisted","private"].includes(q.body.privacy)?q.body.privacy:"private",tags=(q.body.tags||"").split(",").map(x=>x.trim()).filter(Boolean);
if(!v)return s.status(400).json({error:"Video is required."});
const r=await y.videos.insert({part:["snippet","status"],requestBody:{snippet:{title:q.body.title||"Untitled",description:q.body.description||"",tags},status:{privacyStatus:privacy}},media:{body:fs.createReadStream(v.path)}});
if(t&&r.data.id)await y.thumbnails.set({videoId:r.data.id,media:{mimeType:t.mimetype,body:fs.createReadStream(t.path)}});
s.json({success:true,videoId:r.data.id,url:`https://www.youtube.com/watch?v=${r.data.id}`});
}catch(e){console.error(e.response?.data||e);s.status(500).json({error:e.response?.data?.error?.message||"YouTube upload failed."})}
finally{for(const f of [v,t])if(f?.path)try{fs.unlinkSync(f.path)}catch{}}
});
app.listen(PORT,()=>console.log("YT Admin running; OAuth:",redirectUri));