import express from 'express';
import http from 'http';
import { WebSocketServer } from 'ws';
import { ExpressPeerServer } from '@peerjs/server';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-in-production';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';
const DB_PATH = path.join(__dirname, 'data.json');

function loadDB() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch { return { users: [], reports: [], bans: [] }; }
}
let db = loadDB();
function saveDB() { fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2)); }

app.use(express.json({ limit: '200kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const peerServer = ExpressPeerServer(server, { path: '/', proxied: true, allow_discovery: false });
app.use('/peerjs', peerServer);

function tokenFor(user) { return jwt.sign({ sub: user.id, username: user.username, role: user.role || 'user' }, JWT_SECRET, { expiresIn: '7d' }); }
function auth(req, res, next) {
  const raw = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  try { req.user = jwt.verify(raw, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}
function adminOnly(req, res, next) { if (req.user?.role !== 'admin') return res.status(403).json({ error: 'Admin only' }); next(); }

app.post('/api/register', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,20}$/.test(username) || password.length < 6) return res.status(400).json({ error: 'Username 3-20 chars; password 6+ chars' });
  if (db.users.some(u => u.username === username)) return res.status(409).json({ error: 'Username already exists' });
  const user = { id: crypto.randomUUID(), username, passwordHash: await bcrypt.hash(password, 10), role: 'user', createdAt: Date.now(), reports: 0 };
  db.users.push(user); saveDB();
  res.json({ token: tokenFor(user), user: { id: user.id, username: user.username, role: user.role } });
});

app.post('/api/login', async (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  if (username === 'admin' && password === ADMIN_PASSWORD) {
    const user = { id: 'admin', username: 'admin', role: 'admin' };
    return res.json({ token: tokenFor(user), user });
  }
  const user = db.users.find(u => u.username === username);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Wrong username or password' });
  res.json({ token: tokenFor(user), user: { id: user.id, username: user.username, role: user.role } });
});

app.get('/api/me', auth, (req, res) => res.json({ user: req.user }));
app.post('/api/report', auth, (req, res) => {
  const report = { id: crypto.randomUUID(), reporterId: req.user.sub, targetPeerId: String(req.body.targetPeerId || ''), reason: String(req.body.reason || 'other').slice(0, 80), createdAt: Date.now(), status: 'open' };
  db.reports.unshift(report); saveDB();
  broadcastAdmins({ type: 'report:new', report });
  res.json({ ok: true });
});
app.get('/api/admin/stats', auth, adminOnly, (req, res) => res.json({ users: db.users.length, reports: db.reports.filter(r => r.status === 'open').length, online: clients.size, queued: queue.length }));
app.get('/api/admin/reports', auth, adminOnly, (req, res) => res.json({ reports: db.reports.slice(0, 100) }));
app.post('/api/admin/reports/:id/resolve', auth, adminOnly, (req, res) => { const r = db.reports.find(x => x.id === req.params.id); if (r) r.status = 'resolved'; saveDB(); res.json({ ok: true }); });

const wss = new WebSocketServer({ server, path: '/ws' });
const clients = new Map();
const queue = [];

function send(ws, payload) { if (ws?.readyState === 1) ws.send(JSON.stringify(payload)); }
function removeFromQueue(id) { let i; while ((i = queue.indexOf(id)) !== -1) queue.splice(i, 1); }
function broadcastAdmins(payload) { for (const c of clients.values()) if (c.role === 'admin') send(c.ws, payload); }
function tryMatch() {
  while (queue.length >= 2) {
    const aId = queue.shift(); const bId = queue.shift();
    const a = clients.get(aId); const b = clients.get(bId);
    if (!a || !b || !a.peerId || !b.peerId || a.partner || b.partner) continue;
    a.partner = bId; b.partner = aId;
    const matchId = crypto.randomUUID();
    send(a.ws, { type: 'matched', matchId, partnerPeerId: b.peerId, initiator: true });
    send(b.ws, { type: 'matched', matchId, partnerPeerId: a.peerId, initiator: false });
  }
}
function endPair(client, reason = 'ended', requeuePartner = true) {
  if (!client.partner) return;
  const partnerId = client.partner; const partner = clients.get(partnerId);
  client.partner = null;
  if (partner) {
    partner.partner = null;
    send(partner.ws, { type: 'partner-left', reason });
    if (requeuePartner && partner.peerId) { removeFromQueue(partnerId); queue.push(partnerId); send(partner.ws, { type: 'queue', position: queue.length }); }
  }
}

wss.on('connection', (ws) => {
  const id = crypto.randomUUID();
  const client = { id, ws, peerId: '', partner: null, role: 'guest', userId: null };
  clients.set(id, client);
  send(ws, { type: 'hello', clientId: id });

  ws.on('message', raw => {
    let msg; try { msg = JSON.parse(raw); } catch { return; }
    if (msg.type === 'auth' && msg.token) { try { const u = jwt.verify(msg.token, JWT_SECRET); client.role = u.role; client.userId = u.sub; } catch {} }
    if (msg.type === 'ready') {
      client.peerId = String(msg.peerId || '').slice(0, 100);
      if (!client.peerId) return;
      if (client.partner) endPair(client, 'next', false);
      removeFromQueue(id); queue.push(id); send(ws, { type: 'queue', position: queue.length }); tryMatch();
    }
    if (msg.type === 'next') {
      endPair(client, 'next', true); removeFromQueue(id); if (client.peerId) queue.push(id); send(ws, { type: 'queue', position: queue.length }); tryMatch();
    }
    if (msg.type === 'stop') { endPair(client, 'stop', true); removeFromQueue(id); send(ws, { type: 'stopped' }); tryMatch(); }
    if (msg.type === 'signal' && client.partner) { const p = clients.get(client.partner); if (p) send(p.ws, { ...msg, type: 'signal' }); }
  });
  ws.on('close', () => { endPair(client, 'disconnect', true); removeFromQueue(id); clients.delete(id); tryMatch(); });
});

server.listen(PORT, () => console.log(`RANDO running on :${PORT}`));
