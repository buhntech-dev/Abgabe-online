const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { Server } = require('socket.io');
const { S3Client, GetObjectCommand, PutObjectCommand } = require('@aws-sdk/client-s3');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: false } });
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const STATE_KEY = 'app-state.json';
const localStatePath = path.join('/tmp', STATE_KEY);
const s3 = process.env.S3_ENDPOINT && process.env.S3_BUCKET && process.env.S3_ACCESS_KEY_ID && process.env.S3_SECRET_ACCESS_KEY
  ? new S3Client({ region: process.env.S3_REGION || 'auto', endpoint: process.env.S3_ENDPOINT, forcePathStyle: true, credentials: { accessKeyId: process.env.S3_ACCESS_KEY_ID, secretAccessKey: process.env.S3_SECRET_ACCESS_KEY } })
  : null;

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin'); next(); });

let state = { users: [], classes: [], messages: [], assignments: [], submissions: [], files: [], roles: ['Owner','Admin','Lehrer','Schüler'] };
let saveQueue = Promise.resolve();
async function bodyToString(stream) { const chunks=[]; for await (const chunk of stream) chunks.push(chunk); return Buffer.concat(chunks).toString('utf8'); }
async function loadState() {
  try {
    if (s3) {
      const obj = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: STATE_KEY }));
      state = JSON.parse(await bodyToString(obj.Body));
    } else if (fs.existsSync(localStatePath)) state = JSON.parse(fs.readFileSync(localStatePath, 'utf8'));
  } catch (e) { if (e.name !== 'NoSuchKey' && e.$metadata?.httpStatusCode !== 404) console.error('State load:', e.message); }
  const email = (process.env.OWNER_EMAIL || 'owner@abgabe-online.de').toLowerCase();
  const password = process.env.OWNER_PASSWORD || 'Change-this-owner-password-now!';
  let owner = state.users.find(u => u.email === email);
  if (!owner) {
    owner = { id: crypto.randomUUID(), name: 'Plattform-Owner', email, password: await bcrypt.hash(password, 12), role: 'Owner', createdAt: new Date().toISOString() };
    state.users.push(owner);
    await persist();
  } else if (process.env.OWNER_PASSWORD && !(await bcrypt.compare(password, owner.password))) {
    // Keep the Owner login synchronized with the Railway secret so credentials can be reset safely.
    owner.password = await bcrypt.hash(password, 12);
    await persist();
  }
}
function persist() {
  saveQueue = saveQueue.then(async () => {
    const data = JSON.stringify(state);
    if (s3) await s3.send(new PutObjectCommand({ Bucket: process.env.S3_BUCKET, Key: STATE_KEY, Body: data, ContentType: 'application/json' }));
    else fs.writeFileSync(localStatePath, data);
  }).catch(e => console.error('State save:', e.message));
  return saveQueue;
}
const tokenFor = user => jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
function auth(req,res,next) {
  const raw = (req.headers.authorization || '').replace(/^Bearer /i,'') || req.headers.cookie?.split('; ').find(x=>x.startsWith('abgabe_token='))?.split('=')[1];
  try { const p=jwt.verify(raw,JWT_SECRET); const user=state.users.find(u=>u.id===p.id); if(!user) throw new Error('user'); req.user=user; next(); }
  catch { res.status(401).json({error:'Bitte melde dich an.'}); }
}
const allow = (...roles) => (req,res,next) => roles.includes(req.user.role) ? next() : res.status(403).json({error:'Dafür hast du keine Berechtigung.'});
const safeUser = u => ({id:u.id,name:u.name,email:u.email,role:u.role});
const makeCode = () => crypto.randomBytes(3).toString('hex').toUpperCase();
function classForUser(c,user) { return c && (c.ownerId===user.id || c.members.some(m=>m.userId===user.id)); }
function requireClass(req,res,next) { const c=state.classes.find(x=>x.id===req.params.id); if(!classForUser(c,req.user)) return res.status(404).json({error:'Klasse nicht gefunden.'}); req.schoolClass=c; next(); }

app.post('/api/login', async (req,res) => {
  const email=String(req.body.email||'').toLowerCase().trim(), password=String(req.body.password||'');
  const user=state.users.find(u=>u.email===email);
  if(!user || !await bcrypt.compare(password,user.password)) return res.status(401).json({error:'E-Mail oder Passwort ist falsch.'});
  const token=tokenFor(user); res.cookie('abgabe_token',token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*86400000}); res.json({token,user:safeUser(user)});
});
app.post('/api/register',async(req,res)=>{
  const name=String(req.body.name||'').trim(), email=String(req.body.email||'').toLowerCase().trim(), password=String(req.body.password||''), code=String(req.body.code||'').trim().toUpperCase();
  if(!name||!email||password.length<8||code.length!==6) return res.status(400).json({error:'Bitte fülle alle Felder aus. Das Passwort braucht mindestens 8 Zeichen und der Klassen-Code 6 Zeichen.'});
  if(state.users.some(u=>u.email===email)) return res.status(409).json({error:'Diese E-Mail-Adresse ist bereits registriert. Bitte melde dich an.'});
  const schoolClass=state.classes.find(c=>c.code===code);
  if(!schoolClass) return res.status(404).json({error:'Der Klassen-Code ist ungültig. Bitte prüfe ihn bei deiner Lehrkraft.'});
  const user={id:crypto.randomUUID(),name:name.slice(0,80),email,password:await bcrypt.hash(password,12),role:'Schüler',createdAt:new Date().toISOString()};
  state.users.push(user);
  schoolClass.members.push({userId:user.id,joinedAt:new Date().toISOString()});
  await persist();
  const token=tokenFor(user);
  res.cookie('abgabe_token',token,{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*86400000});
  res.status(201).json({token,user:safeUser(user),class:{id:schoolClass.id,name:schoolClass.name}});
});
app.get('/api/me',auth,(req,res)=>res.json({user:safeUser(req.user)}));
app.post('/api/logout',(req,res)=>{res.clearCookie('abgabe_token');res.json({ok:true});});
app.post('/api/owner/teachers',auth,allow('Owner','Admin'),async(req,res)=>{
  const {name,email,password,role='Lehrer'}=req.body;
  if(!name||!email||!password||password.length<10) return res.status(400).json({error:'Name, E-Mail und ein Passwort mit mindestens 10 Zeichen sind erforderlich.'});
  if(!['Lehrer','Admin'].includes(role)) return res.status(400).json({error:'Ungültige Rolle.'});
  if(state.users.some(u=>u.email===String(email).toLowerCase())) return res.status(409).json({error:'Diese E-Mail ist bereits vergeben.'});
  const user={id:crypto.randomUUID(),name:String(name).slice(0,80),email:String(email).toLowerCase(),password:await bcrypt.hash(password,12),role,createdAt:new Date().toISOString()};
  state.users.push(user); await persist(); res.json({user:safeUser(user)});
});
app.get('/api/owner/users',auth,allow('Owner','Admin'),(req,res)=>res.json({users:state.users.map(safeUser)}));
app.patch('/api/owner/users/:id/role',auth,allow('Owner'),async(req,res)=>{
  const u=state.users.find(x=>x.id===req.params.id); if(!u||u.id===req.user.id) return res.status(400).json({error:'Aktion nicht möglich.'});
  if(!['Admin','Lehrer','Schüler'].includes(req.body.role)) return res.status(400).json({error:'Ungültige Rolle.'});
  u.role=req.body.role; await persist(); res.json({user:safeUser(u)});
});
app.post('/api/classes',auth,allow('Owner','Admin','Lehrer'),async(req,res)=>{
  const name=String(req.body.name||'').trim(); if(!name) return res.status(400).json({error:'Bitte gib einen Klassennamen ein.'});
  const c={id:crypto.randomUUID(),name:name.slice(0,80),code:makeCode(),ownerId:req.user.id,teacherIds:[req.user.id],members:[{userId:req.user.id,joinedAt:new Date().toISOString()}],createdAt:new Date().toISOString()};
  state.classes.push(c); await persist(); res.json({class:c});
});
app.get('/api/classes',auth,(req,res)=>res.json({classes:state.classes.filter(c=>classForUser(c,req.user)).map(c=>({...c,memberCount:c.members.length,teacherName:state.users.find(u=>u.id===c.ownerId)?.name||'Lehrkraft'}))}));
app.post('/api/classes/join',auth,async(req,res)=>{
  const code=String(req.body.code||'').trim().toUpperCase(); const c=state.classes.find(x=>x.code===code);
  if(!c) return res.status(404).json({error:'Der Beitrittscode ist ungültig.'});
  if(!c.members.some(m=>m.userId===req.user.id)) c.members.push({userId:req.user.id,joinedAt:new Date().toISOString()});
  await persist(); res.json({class:c});
});
app.get('/api/classes/:id',auth,requireClass,(req,res)=>{
  const c=req.schoolClass; res.json({class:{...c,members:c.members.map(m=>({...m,user:safeUser(state.users.find(u=>u.id===m.userId)||{id:m.userId,name:'Unbekannt',email:'',role:'Schüler'})}))},messages:state.messages.filter(m=>m.classId===c.id).slice(-100),assignments:state.assignments.filter(a=>a.classId===c.id),files:state.files.filter(f=>f.classId===c.id)});
});
app.get('/api/classes/:id/messages',auth,requireClass,(req,res)=>res.json({messages:state.messages.filter(m=>m.classId===req.schoolClass.id).slice(-100)}));
app.post('/api/classes/:id/messages',auth,requireClass,async(req,res)=>{
  const content=String(req.body.content||'').trim(); if(!content||content.length>3000) return res.status(400).json({error:'Nachricht ist leer oder zu lang.'});
  const message={id:crypto.randomUUID(),classId:req.schoolClass.id,userId:req.user.id,userName:req.user.name,content,createdAt:new Date().toISOString()};
  state.messages.push(message); if(state.messages.length>10000) state.messages=state.messages.slice(-10000); await persist(); io.to(req.schoolClass.id).emit('chat:message',message); res.json({message});
});
app.post('/api/classes/:id/assignments',auth,allow('Owner','Admin','Lehrer'),requireClass,async(req,res)=>{
  const title=String(req.body.title||'').trim(), description=String(req.body.description||'').trim(), dueDate=req.body.dueDate||null;
  if(!title) return res.status(400).json({error:'Bitte gib einen Aufgabentitel ein.'});
  const a={id:crypto.randomUUID(),classId:req.schoolClass.id,title:title.slice(0,120),description:description.slice(0,3000),dueDate,createdBy:req.user.id,createdAt:new Date().toISOString()};
  state.assignments.push(a); await persist(); io.to(req.schoolClass.id).emit('assignment:new',a); res.json({assignment:a});
});
app.post('/api/assignments/:id/submit',auth,async(req,res)=>{
  const a=state.assignments.find(x=>x.id===req.params.id); if(!a) return res.status(404).json({error:'Aufgabe nicht gefunden.'});
  const c=state.classes.find(x=>x.id===a.classId); if(!classForUser(c,req.user)) return res.status(403).json({error:'Kein Zugriff.'});
  const entry={id:crypto.randomUUID(),assignmentId:a.id,classId:c.id,userId:req.user.id,text:String(req.body.text||'').slice(0,5000),createdAt:new Date().toISOString()};
  state.submissions=state.submissions.filter(x=>!(x.assignmentId===a.id&&x.userId===req.user.id)); state.submissions.push(entry); await persist(); res.json({submission:entry});
});
app.get('/api/assignments/:id/submissions',auth,allow('Owner','Admin','Lehrer'),(req,res)=>{
  const a=state.assignments.find(x=>x.id===req.params.id); if(!a) return res.status(404).json({error:'Aufgabe nicht gefunden.'});
  const c=state.classes.find(x=>x.id===a.classId); if(!classForUser(c,req.user)) return res.status(403).json({error:'Kein Zugriff.'});
  res.json({submissions:state.submissions.filter(x=>x.assignmentId===a.id).map(x=>({...x,user:safeUser(state.users.find(u=>u.id===x.userId))}))});
});
const upload=multer({storage:multer.memoryStorage(),limits:{fileSize:25*1024*1024}});
app.post('/api/classes/:id/files',auth,requireClass,upload.single('file'),async(req,res)=>{
  if(!req.file) return res.status(400).json({error:'Bitte wähle eine Datei aus.'});
  if(!s3) return res.status(503).json({error:'Dateispeicher ist noch nicht eingerichtet.'});
  const id=crypto.randomUUID(), key='uploads/'+req.schoolClass.id+'/'+id;
  await s3.send(new PutObjectCommand({Bucket:process.env.S3_BUCKET,Key:key,Body:req.file.buffer,ContentType:req.file.mimetype}));
  const file={id,classId:req.schoolClass.id,name:req.file.originalname.slice(0,180),size:req.file.size,mime:req.file.mimetype,key,uploadedBy:req.user.id,uploadedByName:req.user.name,createdAt:new Date().toISOString()};
  state.files.push(file); await persist(); io.to(req.schoolClass.id).emit('file:new',file); res.json({file});
});
app.get('/api/files/:id/download',auth,async(req,res)=>{
  const f=state.files.find(x=>x.id===req.params.id); const c=f&&state.classes.find(x=>x.id===f.classId);
  if(!f||!classForUser(c,req.user)||!s3) return res.status(404).json({error:'Datei nicht gefunden.'});
  const { GetObjectCommand }=require('@aws-sdk/client-s3'); const obj=await s3.send(new GetObjectCommand({Bucket:process.env.S3_BUCKET,Key:f.key}));
  res.setHeader('Content-Type',f.mime||'application/octet-stream'); res.setHeader('Content-Disposition','attachment; filename*=UTF-8\'\''+encodeURIComponent(f.name)); obj.Body.pipe(res);
});
io.use((socket,next)=>{
  try { const raw=socket.handshake.auth?.token||socket.handshake.headers.cookie?.split('; ').find(x=>x.startsWith('abgabe_token='))?.split('=')[1]; const p=jwt.verify(raw,JWT_SECRET); const u=state.users.find(x=>x.id===p.id); if(!u) throw new Error(); socket.user=u; next(); }
  catch { next(new Error('Nicht angemeldet')); }
});
io.on('connection',socket=>{
  socket.on('class:join',id=>{const c=state.classes.find(x=>x.id===id); if(classForUser(c,socket.user)) socket.join(id);});
  socket.on('call:join',({classId})=>{const c=state.classes.find(x=>x.id===classId); if(!classForUser(c,socket.user)) return; socket.join('call:'+classId); socket.to('call:'+classId).emit('call:peer-joined',{peerId:socket.id,user:safeUser(socket.user)});});
  socket.on('call:leave',({classId})=>{socket.to('call:'+classId).emit('call:peer-left',{peerId:socket.id});socket.leave('call:'+classId);});
  for(const event of ['call:offer','call:answer','call:ice']) socket.on(event,payload=>{const c=state.classes.find(x=>x.id===payload.classId);if(classForUser(c,socket.user)&&payload.to) io.to(payload.to).emit(event,{...payload,from:socket.id,user:safeUser(socket.user)});});
  socket.on('disconnect',()=>{for(const room of socket.rooms) if(room.startsWith('call:')) socket.to(room).emit('call:peer-left',{peerId:socket.id});});
});
app.get(/.*/,(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
loadState().then(()=>server.listen(PORT,'0.0.0.0',()=>console.log('Abgabe-online listening on '+PORT))).catch(e=>{console.error(e);process.exit(1);});
