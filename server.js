
const path = require("path");
const http = require("http");
const express = require("express");
const { Server } = require("socket.io");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;

if (!JWT_SECRET) throw new Error("JWT_SECRET is required.");
if (!DATABASE_URL) throw new Error("DATABASE_URL is required.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined,
  max: 10
});

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.set("trust proxy", 1);
app.use(helmet({ crossOriginEmbedderPolicy: false }));
app.use(express.json({limit:"6mb"}));
app.use(rateLimit({windowMs:60*1000, max:120, standardHeaders:true, legacyHeaders:false}));
app.use(express.static(path.join(__dirname,"public")));

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(24) UNIQUE NOT NULL,
      display_name VARCHAR(40) NOT NULL,
      password_hash TEXT NOT NULL,
      avatar TEXT DEFAULT '',
      lat DOUBLE PRECISION,
      lng DOUBLE PRECISION,
      location_visibility VARCHAR(16) NOT NULL DEFAULT 'approximate'
        CHECK(location_visibility IN ('approximate','friends','hidden')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS friendships (
      id SERIAL PRIMARY KEY,
      requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      addressee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      status VARCHAR(16) NOT NULL DEFAULT 'pending'
        CHECK(status IN ('pending','accepted','rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(requester_id, addressee_id)
    );
    CREATE TABLE IF NOT EXISTS messages (
      id BIGSERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      body TEXT NOT NULL,
      pigeon_id VARCHAR(16) NOT NULL DEFAULT 'classic',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      delivered_at TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS messages_pair_idx
      ON messages(sender_id, receiver_id, id);
    CREATE INDEX IF NOT EXISTS users_username_idx
      ON users(username);
  `);
}

function cleanUsername(v){return String(v||"").trim().replace(/^@/,"").toLowerCase();}
function tokenFor(u){return jwt.sign({id:u.id,username:u.username},JWT_SECRET,{expiresIn:"7d"});}
function auth(req,res,next){
  const h=req.headers.authorization||"";
  if(!h.startsWith("Bearer ")) return res.status(401).json({error:"Authentication required"});
  try{req.user=jwt.verify(h.slice(7),JWT_SECRET);next();}
  catch(e){return res.status(401).json({error:"Invalid or expired session"});}
}
function publicUser(u, viewerId){
  if(!u)return null;
  return {
    id:u.id, username:u.username, displayName:u.display_name, avatar:u.avatar||"",
    locationVisibility:u.location_visibility,
    location:u.id===viewerId && u.lat!=null ? {lat:u.lat,lng:u.lng}:null
  };
}
function distanceKm(a,b){
  if(a?.lat==null||b?.lat==null)return null;
  const R=6371,rad=x=>x*Math.PI/180;
  const dLat=rad(b.lat-a.lat),dLon=rad(b.lng-a.lng);
  const q=Math.sin(dLat/2)**2+Math.cos(rad(a.lat))*Math.cos(rad(b.lat))*Math.sin(dLon/2)**2;
  return R*2*Math.atan2(Math.sqrt(q),Math.sqrt(1-q));
}
async function userWithDistance(viewerId,u){
  const {rows}=await pool.query("SELECT lat,lng FROM users WHERE id=$1",[viewerId]);
  const v=rows[0];
  const out=publicUser(u,viewerId);
  const d=distanceKm(v,u);
  out.distance=d==null?null:Number(d.toFixed(1));
  return out;
}
const validPigeons=new Set(["classic","royal","night","spark","snow","fire"]);

app.get("/health",(req,res)=>res.json({ok:true,service:"wingoo"}));

app.post("/api/auth/register",async(req,res)=>{
  try{
    const username=cleanUsername(req.body.username);
    const displayName=String(req.body.displayName||username).trim().slice(0,40);
    const password=String(req.body.password||"");
    if(!/^[a-z0-9_.-]{3,24}$/.test(username))return res.status(400).json({error:"Username must be 3–24 characters: letters, numbers, _, ., -"});
    if(password.length<6)return res.status(400).json({error:"Password must be at least 6 characters"});
    const hash=bcrypt.hashSync(password,10);
    const {rows}=await pool.query(
      "INSERT INTO users(username,display_name,password_hash) VALUES($1,$2,$3) RETURNING *",
      [username,displayName,hash]
    );
    const u=rows[0];
    res.json({token:tokenFor(u),user:publicUser(u,u.id)});
  }catch(e){
    if(e.code==="23505")return res.status(409).json({error:"That username is already taken."});
    console.error(e);res.status(500).json({error:"Registration failed"});
  }
});

app.post("/api/auth/login",async(req,res)=>{
  try{
    const username=cleanUsername(req.body.username),password=String(req.body.password||"");
    const {rows}=await pool.query("SELECT * FROM users WHERE username=$1",[username]);
    const u=rows[0];
    if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:"Wrong username or password"});
    res.json({token:tokenFor(u),user:publicUser(u,u.id)});
  }catch(e){console.error(e);res.status(500).json({error:"Login failed"});}
});

app.get("/api/me",auth,async(req,res)=>{
  const {rows}=await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id]);
  if(!rows[0])return res.status(404).json({error:"User not found"});
  res.json({user:publicUser(rows[0],req.user.id)});
});

app.patch("/api/me",auth,async(req,res)=>{
  const current=(await pool.query("SELECT * FROM users WHERE id=$1",[req.user.id])).rows[0];
  if(!current)return res.status(404).json({error:"User not found"});
  const name=String(req.body.displayName??current.display_name).trim().slice(0,40);
  const avatar=String((req.body.avatar??current.avatar)||"").slice(0,200000);
  const vis=["approximate","friends","hidden"].includes(req.body.locationVisibility)?req.body.locationVisibility:current.location_visibility;
  const {rows}=await pool.query(
    "UPDATE users SET display_name=$1,avatar=$2,location_visibility=$3 WHERE id=$4 RETURNING *",
    [name,avatar,vis,req.user.id]
  );
  res.json({user:publicUser(rows[0],req.user.id)});
});

app.post("/api/location",auth,async(req,res)=>{
  const lat=Number(req.body.lat),lng=Number(req.body.lng);
  if(!Number.isFinite(lat)||!Number.isFinite(lng)||lat<-90||lat>90||lng<-180||lng>180)return res.status(400).json({error:"Invalid location"});
  await pool.query("UPDATE users SET lat=$1,lng=$2 WHERE id=$3",[lat,lng,req.user.id]);
  res.json({ok:true});
});

app.get("/api/users/search",auth,async(req,res)=>{
  const q=cleanUsername(req.query.q);
  if(q.length<2)return res.json({users:[]});
  const {rows}=await pool.query("SELECT * FROM users WHERE username LIKE $1 AND id<>$2 ORDER BY username LIMIT 10",[q+"%",req.user.id]);
  const users=[];
  for(const u of rows)users.push(await userWithDistance(req.user.id,u));
  res.json({users});
});

app.post("/api/friends/request",auth,async(req,res)=>{
  const target=(await pool.query("SELECT * FROM users WHERE username=$1",[cleanUsername(req.body.username)])).rows[0];
  if(!target||target.id===req.user.id)return res.status(404).json({error:"User not found"});
  try{
    await pool.query("INSERT INTO friendships(requester_id,addressee_id,status) VALUES($1,$2,'pending')",[req.user.id,target.id]);
    res.json({ok:true});
  }catch(e){
    if(e.code==="23505")return res.status(409).json({error:"A request already exists."});
    res.status(500).json({error:"Could not send request"});
  }
});

app.get("/api/friends",auth,async(req,res)=>{
  const {rows}=await pool.query(`
    SELECT u.* FROM users u JOIN friendships f ON
    ((f.requester_id=$1 AND f.addressee_id=u.id) OR (f.addressee_id=$1 AND f.requester_id=u.id))
    WHERE f.status='accepted' ORDER BY u.display_name`,[req.user.id]);
  const friends=[];for(const u of rows)friends.push(await userWithDistance(req.user.id,u));
  res.json({friends});
});

app.get("/api/friend-requests",auth,async(req,res)=>{
  const {rows}=await pool.query(`
    SELECT u.username,u.display_name,u.avatar
    FROM users u JOIN friendships f ON f.requester_id=u.id
    WHERE f.addressee_id=$1 AND f.status='pending'`,[req.user.id]);
  res.json({requests:rows});
});

app.post("/api/friends/accept",auth,async(req,res)=>{
  const target=(await pool.query("SELECT id FROM users WHERE username=$1",[cleanUsername(req.body.username)])).rows[0];
  if(!target)return res.status(404).json({error:"User not found"});
  await pool.query("UPDATE friendships SET status='accepted' WHERE requester_id=$1 AND addressee_id=$2",[target.id,req.user.id]);
  res.json({ok:true});
});

app.get("/api/messages/:username",auth,async(req,res)=>{
  const other=(await pool.query("SELECT * FROM users WHERE username=$1",[cleanUsername(req.params.username)])).rows[0];
  if(!other)return res.status(404).json({error:"User not found"});
  const {rows}=await pool.query(`
    SELECT m.id,m.body,m.pigeon_id,m.created_at,m.delivered_at,u.username sender
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE (m.sender_id=$1 AND m.receiver_id=$2) OR (m.sender_id=$2 AND m.receiver_id=$1)
    ORDER BY m.id`,[req.user.id,other.id]);
  res.json({messages:rows});
});

app.post("/api/messages",auth,async(req,res)=>{
  const receiver=(await pool.query("SELECT * FROM users WHERE username=$1",[cleanUsername(req.body.username)])).rows[0];
  const body=String(req.body.body||"").trim();
  if(!receiver||!body)return res.status(400).json({error:"Recipient and message are required"});
  if(body.length>5000)return res.status(400).json({error:"Message is too long"});
  const pigeon=validPigeons.has(req.body.pigeonId)?req.body.pigeonId:"classic";
  const {rows}=await pool.query(`
    INSERT INTO messages(sender_id,receiver_id,body,pigeon_id)
    VALUES($1,$2,$3,$4)
    RETURNING id,body,pigeon_id,created_at,delivered_at`,[req.user.id,receiver.id,body,pigeon]);
  const msg={...rows[0],sender:req.user.username};
  io.to("user:"+receiver.id).emit("message:new",msg);
  res.json({message:msg});
});

io.use((socket,next)=>{
  try{
    const token=String(socket.handshake.auth?.token||"");
    socket.user=jwt.verify(token,JWT_SECRET);next();
  }catch(e){next(new Error("Authentication required"));}
});
io.on("connection",socket=>socket.join("user:"+socket.user.id));

app.get("/{*splat}",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));

(async()=>{
  await initDb();
  server.listen(PORT,()=>console.log(`WINGOO running on port ${PORT}`));
})().catch(err=>{console.error(err);process.exit(1)});
