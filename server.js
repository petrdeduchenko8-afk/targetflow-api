// Target Flow PRO — API (single-file, JSON storage)
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const dotenv = require('dotenv');
const jwt = require('jsonwebtoken');
const { v4: uuid } = require('uuid');
const fetch = (...args) => import('node-fetch').then(({default: f}) => f(...args));
const XLSX = require('xlsx');
const nodemailer = require('nodemailer');
const { addDays, format } = require('date-fns');

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

// Root & health checks (no auth)
app.get('/', (req, res) => res.send('Target Flow API • OK'));
app.get('/healthz', (req, res) =>
  res.json({ ok: true, ts: new Date().toISOString(), uptime: process.uptime() })
);


const DATA_DIR = path.join(process.cwd(), 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

async function loadDB(){
  if(!fs.existsSync(DB_FILE)){
    const seeded = await seedDB();
    return seeded;
  }
  const txt = await fsp.readFile(DB_FILE,'utf8');
  return JSON.parse(txt);
}
async function saveDB(db){ await fsp.writeFile(DB_FILE, JSON.stringify(db, null, 2), 'utf8'); }

async function seedDB(){
  const nowISO = () => new Date().toISOString();
  const db = {
    users: [{ id: uuid(), email: 'demo@istudio.local', password: 'demo123', role: 'admin' }],
    campaigns: [], activity: [], metrics: [], audit: [], webhooks: [], provider_accounts: []
  };
  const addCamp = (name, channel, dailyBudget, status='Активна', ai=false)=>{
    const id = uuid(), now = nowISO();
    db.campaigns.push({ id, name, channel, dailyBudget, status, aiOptimized: ai, createdAt: now, updatedAt: now });
    db.activity.push({ id: uuid(), campaignId: id, message:`Инициализация кампании «${name}»`, createdAt: now });
    return id;
  };
  const c1 = addCamp('Весенняя распродажа','Instagram',1500,'Активна',false);
  const c2 = addCamp('Набор на вебинар','VK',1000,'На оптимизации AI',true);
  const c3 = addCamp('Реклама в Telegram','Telegram Ads',2000,'Активна',false);

  const start = addDays(new Date(), -120);
  for (let i=0;i<=120;i++){
    const d = addDays(start, i);
    const date = format(d, 'yyyy-MM-dd');
    for (const cid of [c1,c2,c3]){
      const base = cid===c3?2000:cid===c1?1500:1000;
      const impressions = 1000 + Math.floor(Math.random()*4000);
      const clicks = Math.floor(impressions * (0.02 + Math.random()*0.03));
      const spend = base * (0.7 + Math.random()*0.6);
      const leads = Math.floor(clicks * (0.02 + Math.random()*0.06));
      db.metrics.push({ id: uuid(), campaignId: cid, date, impressions, clicks, spend, leads });
    }
  }
  await saveDB(db);
  return db;
}

// ---- Auth ----
const SECRET = process.env.JWT_SECRET || 'dev-secret';
function sign(u){ return jwt.sign(u, SECRET, { expiresIn: '7d' }); }
function auth(req,res,next){
  const hdr = req.headers.authorization;
  if(!hdr) return res.status(401).json({error:'No token'});
  try{ req.user = jwt.verify(hdr.replace('Bearer ','').trim(), SECRET); next(); }
  catch{ return res.status(401).json({error:'Invalid token'}); }
}
function ensureRole(...roles){
  return (req,res,next)=>{
    const u = req.user;
    if(!u) return res.status(401).json({error:'No user'});
    if(!roles.includes(u.role)) return res.status(403).json({error:'Forbidden'});
    next();
  };
}

// ---- Utils ----
async function addAudit(db, userId, action, payload){
  db.audit.unshift({ id: uuid(), userId, action, payload: payload?JSON.stringify(payload):null, createdAt: new Date().toISOString() });
  if (db.audit.length>1000) db.audit.length = 1000;
}
async function dispatchWebhooks(db, event, body){
  const hooks = db.webhooks.filter(h=>h.event===event);
  await Promise.all(hooks.map(async h=>{
    try{
      await fetch(h.url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({event, data: body, secret: h.secret||null}) });
    }catch(e){}
  }));
}
async function sendTelegram(msg){
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;
  if(!token || !chatId) return { ok:false, error:'No telegram env' };
  const url = `https://api.telegram.org/bot${token}/sendMessage`;
  const r = await fetch(url, { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ chat_id: chatId, text: msg, parse_mode: 'HTML' }) });
  return r.json();
}
async function sendEmail(subject, html){
  const { SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, SMTP_TO } = process.env;
  if(!SMTP_HOST || !SMTP_USER || !SMTP_PASS || !SMTP_TO) return { ok:false, error:'No SMTP env' };
  const tr = nodemailer.createTransport({ host: SMTP_HOST, port: Number(SMTP_PORT||587), secure:false, auth: { user: SMTP_USER, pass: SMTP_PASS } });
  return tr.sendMail({ from: SMTP_FROM||SMTP_USER, to: SMTP_TO, subject, html });
}

// ---- Routes ----
app.post('/api/login', async (req,res)=>{
  const { email, password } = req.body||{};
  const db = await loadDB();
  const u = db.users.find(x=>x.email===email);
  if(!u || u.password!==password) return res.status(401).json({error:'Invalid creds'});
  return res.json({ token: sign({ uid: u.id, email: u.email, role: u.role }) });
});
app.get('/api/kpi', auth, async (req,res)=>{
  const db = await loadDB();
  const activeCount = db.campaigns.filter(c=>c.status==='Активна').length;
  const monthlyBudget = db.campaigns.filter(c=>c.status==='Активна').reduce((a,c)=>a+c.dailyBudget,0)*30;
  const sums = db.metrics.reduce((a,m)=>{a.i+=m.impressions;a.c+=m.clicks;return a},{i:0,c:0});
  const avgCTR = sums.i ? Number(((sums.c/sums.i)*100).toFixed(2)) : 0;
  const today = new Date();
  const d = (n)=> format(addDays(today, n), 'yyyy-MM-dd');
  const inRange = (s,e)=> (r)=> r.date>=s && r.date<=e;
  const last7 = db.metrics.filter(inRange(d(-6), d(0))).reduce((a,m)=>a+m.leads,0);
  const prev7 = db.metrics.filter(inRange(d(-13), d(-7))).reduce((a,m)=>a+m.leads,0);
  const conversionsDelta = prev7? ((last7-prev7)/prev7)*100 : 0;
  return res.json({ activeCount, monthlyBudget, avgCTR, weeklyConversions: last7, trend:{ ctrDelta:-0.8, conversionsDelta } });
});
app.get('/api/timeseries', auth, async (req,res)=>{
  const { from, to } = req.query;
  if(!from||!to) return res.status(400).json({error:'from/to required'});
  const db = await loadDB();
  const map = new Map();
  db.metrics.forEach(m=>{
    if(m.date<from || m.date>to) return;
    if(!map.has(m.date)) map.set(m.date,{date:m.date, leads:0, spend:0});
    const r = map.get(m.date); r.leads+=m.leads; r.spend+=m.spend;
  });
  const rows = Array.from(map.values()).sort((a,b)=>a.date.localeCompare(b.date));
  res.json(rows);
});
app.get('/api/activity', auth, async (req,res)=>{
  const db = await loadDB();
  res.json(db.activity.slice().sort((a,b)=> b.createdAt.localeCompare(a.createdAt)).slice(0,20));
});
app.get('/api/campaigns', auth, async (req,res)=>{
  const db = await loadDB();
  res.json(db.campaigns.slice().sort((a,b)=> b.createdAt.localeCompare(a.createdAt)));
});
app.post('/api/campaigns', auth, async (req,res)=>{
  const db = await loadDB();
  const { name, channel, dailyBudget, status, aiOptimized=false } = req.body||{};
  if(!name || !channel) return res.status(400).json({error:'name/channel required'});
  const now = new Date().toISOString();
  const id = uuid();
  const row = { id, name, channel, dailyBudget:Number(dailyBudget||0), status, aiOptimized: !!aiOptimized, createdAt: now, updatedAt: now };
  db.campaigns.push(row);
  db.activity.push({ id: uuid(), campaignId:id, message:`Создана кампания «${name}»`, createdAt: now });
  db.audit.unshift({ id: uuid(), userId: req.user.uid, action: 'campaign.create', payload: JSON.stringify({id}), createdAt: now });
  await dispatchWebhooks(db, 'campaign.created', {id});
  await saveDB(db);
  res.json(row);
});
app.patch('/api/campaigns/:id', auth, async (req,res)=>{
  const db = await loadDB();
  const id = req.params.id;
  const it = db.campaigns.find(c=>c.id===id);
  if(!it) return res.status(404).json({error:'Not found'});
  Object.assign(it, req.body||{}, { updatedAt: new Date().toISOString() });
  db.activity.push({ id: uuid(), campaignId:id, message:`Обновлена кампания «${it.name}»`, createdAt: new Date().toISOString() });
  db.audit.unshift({ id: uuid(), userId: req.user.uid, action: 'campaign.update', payload: JSON.stringify({id}), createdAt: new Date().toISOString() });
  await dispatchWebhooks(db, 'campaign.updated', {id});
  await saveDB(db);
  res.json(it);
});
app.delete('/api/campaigns/:id', auth, async (req,res)=>{
  const db = await loadDB();
  const id = req.params.id;
  db.campaigns = db.campaigns.filter(c=>c.id!==id);
  db.metrics = db.metrics.filter(m=>m.campaignId!==id);
  db.activity.push({ id: uuid(), campaignId:id, message:`Кампания удалена`, createdAt: new Date().toISOString() });
  db.audit.unshift({ id: uuid(), userId: req.user.uid, action: 'campaign.delete', payload: JSON.stringify({id}), createdAt: new Date().toISOString() });
  await dispatchWebhooks(db, 'campaign.deleted', {id});
  await saveDB(db);
  res.json({ok:true});
});
app.get('/api/analytics/summary', auth, async (req,res)=>{
  const { from, to } = req.query;
  if(!from||!to) return res.status(400).json({error:'from/to required'});
  const db = await loadDB();
  const byChMap = new Map();
  for(const m of db.metrics){
    if(m.date<from || m.date>to) continue;
    const ch = (db.campaigns.find(c=>c.id===m.campaignId)||{}).channel || 'Unknown';
    if(!byChMap.has(ch)) byChMap.set(ch, { channel: ch, spend:0, leads:0, ctr:0, _impr:0, _clicks:0 });
    const r = byChMap.get(ch);
    r.spend += m.spend; r.leads += m.leads; r._impr += m.impressions; r._clicks += m.clicks;
  }
  const byChannel = Array.from(byChMap.values()).map(r=>({ channel:r.channel, spend:r.spend, leads:r.leads, ctr: r._impr? (r._clicks/r._impr*100):0 }));
  const totalSpend = byChannel.reduce((a,b)=>a+b.spend,0);
  const totalLeads = byChannel.reduce((a,b)=>a+b.leads,0);
  const cpl = totalLeads? (totalSpend/totalLeads) : 0;
  res.json({ byChannel, cpl, totalLeads, totalSpend });
});
app.get('/api/settings', auth, async (req,res)=>{
  res.json({ currency: 'RUB', timezone: 'Europe/Moscow', webhookUrl: 'https://example.com/webhook', telegramBot: '@istudio_ads_bot', apiToken: 'demo-token' });
});
app.get('/api/export', auth, async (req,res)=>{
  const { from, to, format='csv' } = req.query;
  if(!from||!to) return res.status(400).json({error:'from/to required'});
  const db = await loadDB();
  const rows = db.metrics.filter(r=>r.date>=from && r.date<=to).map(r=>{
    const ch = (db.campaigns.find(c=>c.id===r.campaignId)||{}).channel||'Unknown';
    return { channel: ch, date: r.date, impressions: r.impressions, clicks: r.clicks, spend: r.spend, leads: r.leads };
  });
  if(format==='xlsx'){
    const ws = XLSX.utils.json_to_sheet(rows);
    const wb = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(wb, ws, 'report');
    const buf = XLSX.write(wb, { type:'buffer', bookType:'xlsx' });
    res.setHeader('Content-Disposition','attachment; filename="report.xlsx"');
    res.type('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    return res.send(buf);
  }else{
    const header = 'channel,date,impressions,clicks,spend,leads\n';
    const csv = header + rows.map(r=>[r.channel,r.date,r.impressions,r.clicks,r.spend,r.leads].join(',')).join('\n');
    res.setHeader('Content-Disposition','attachment; filename="report.csv"');
    res.type('text/csv');
    return res.send(csv);
  }
});
app.post('/api/export/send', auth, async (req,res)=>{
  const { from, to, dest='telegram' } = req.body||{};
  const db = await loadDB();
  const inRange = db.metrics.filter(r=>r.date>=from && r.date<=to);
  const totalSpend = inRange.reduce((a,b)=>a+b.spend,0);
  const totalLeads = inRange.reduce((a,b)=>a+b.leads,0);
  const cpl = totalLeads? totalSpend/totalLeads : 0;
  const msg = `<b>Отчёт</b> ${from} — ${to}\nЛиды: ${totalLeads}\nРасходы: ${Math.round(totalSpend)} ₽\nCPL: ${cpl.toFixed(2)} ₽`;
  if(dest==='telegram'){ 
    try { const r = await sendTelegram(msg); return res.json(r); } catch(e){ return res.json({ok:false, error:String(e)}); }
  } else {
    try { const r = await sendEmail('Отчёт Target Flow', msg.replace(/\n/g,'<br>')); return res.json(r); } catch(e){ return res.json({ok:false, error:String(e)}); }
  }
});
app.get('/api/webhooks', auth, async (req,res)=>{ const db = await loadDB(); res.json(db.webhooks); });
app.post('/api/webhooks', auth, ensureRole('admin'), async (req,res)=>{
  const db = await loadDB();
  const { event, url, secret } = req.body||{};
  const id = uuid();
  db.webhooks.push({ id, event, url, secret: secret||null });
  db.audit.unshift({ id: uuid(), userId: req.user.uid, action: 'webhook.create', payload: JSON.stringify({id,event,url}), createdAt: new Date().toISOString() });
  await saveDB(db);
  res.json({id,event,url,secret:secret||null});
});
app.delete('/api/webhooks/:id', auth, ensureRole('admin'), async (req,res)=>{
  const db = await loadDB();
  db.webhooks = db.webhooks.filter(h=>h.id!==req.params.id);
  db.audit.unshift({ id: uuid(), userId: req.user.uid, action: 'webhook.delete', payload: JSON.stringify({id:req.params.id}), createdAt: new Date().toISOString() });
  await saveDB(db);
  res.json({ok:true});
});
app.post('/api/providers/import', auth, ensureRole('admin','manager'), async (req,res)=>{
  const db = await loadDB();
  const b = req.body||{};
  if(!b.rows?.length) return res.status(400).json({error:'rows required'});
  const rows = b.rows.map(r=>({ id:uuid(), campaignId:b.campaignId, date:r.date, impressions:r.impressions, clicks:r.clicks, spend:r.spend, leads:r.leads }));
  db.metrics.push(...rows);
  db.audit.unshift({ id: uuid(), userId: req.user.uid, action: 'metrics.import', payload: JSON.stringify({count: rows.length}), createdAt: new Date().toISOString() });
  await dispatchWebhooks(db, 'metrics.imported', {count: rows.length});
  await saveDB(db);
  res.json({ok:true, imported: rows.length});
});
app.get('/api/audit', auth, ensureRole('admin'), async (req,res)=>{
  const db = await loadDB();
  res.json(db.audit.slice(0,200));
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=> console.log('API on :' + PORT));
