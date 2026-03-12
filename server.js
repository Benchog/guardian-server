/**
 * GUARDIAN — Backend Server
 * Uses sql.js (pure JS SQLite) — works on Windows without Visual Studio
 * Save as: backend/server.js
 */

const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'guardian-dev-secret-change-in-production';
const DB_FILE = process.env.DB_PATH || './guardian.db';

// ── Database Setup (sql.js) ───────────────────────────────────────────────────
const initSqlJs = require('sql.js');

let db;

async function initDB() {
  const SQL = await initSqlJs();

  // Load existing DB from disk if it exists
  if (fs.existsSync(DB_FILE)) {
    const fileBuffer = fs.readFileSync(DB_FILE);
    db = new SQL.Database(fileBuffer);
  } else {
    db = new SQL.Database();
  }

  // Save DB to disk every 5 seconds
  function saveToDisk() {
    const data = db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
  }
  setInterval(saveToDisk, 5000);
  process.on('exit', saveToDisk);
  process.on('SIGINT', () => { saveToDisk(); process.exit(); });

  db.run(`
    CREATE TABLE IF NOT EXISTS families (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS children (
      id TEXT PRIMARY KEY,
      family_id TEXT NOT NULL,
      name TEXT NOT NULL,
      age INTEGER,
      grade TEXT,
      platform TEXT DEFAULT 'android',
      bedtime_enabled INTEGER DEFAULT 1,
      wake_hour INTEGER DEFAULT 6,
      wake_minute INTEGER DEFAULT 30,
      study_mode_active INTEGER DEFAULT 0,
      device_locked INTEGER DEFAULT 0,
      daily_limit_minutes INTEGER DEFAULT 180,
      bedtime_hour INTEGER DEFAULT 20,
      bedtime_minute INTEGER DEFAULT 30,
      wake_hour INTEGER DEFAULT 7,
      wake_minute INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS devices (
      id TEXT PRIMARY KEY,
      family_id TEXT NOT NULL,
      child_id TEXT NOT NULL,
      device_name TEXT,
      platform TEXT DEFAULT 'android',
      device_token TEXT UNIQUE NOT NULL,
      battery_level INTEGER,
      last_seen INTEGER,
      is_online INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS blocked_apps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      child_id TEXT NOT NULL,
      family_id TEXT NOT NULL,
      package_name TEXT NOT NULL,
      app_name TEXT,
      blocked INTEGER DEFAULT 1,
      reason TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now')),
      UNIQUE(child_id, package_name)
    );
    CREATE TABLE IF NOT EXISTS website_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id TEXT NOT NULL,
      child_id TEXT,
      domain TEXT NOT NULL,
      rule_type TEXT DEFAULT 'block',
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS activity_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id TEXT NOT NULL,
      child_id TEXT NOT NULL,
      child_name TEXT,
      event_type TEXT NOT NULL,
      app_name TEXT,
      package_name TEXT,
      domain TEXT,
      was_blocked INTEGER DEFAULT 0,
      block_reason TEXT,
      timestamp INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS screen_time_usage (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      child_id TEXT NOT NULL,
      family_id TEXT NOT NULL,
      date TEXT NOT NULL,
      minutes_used INTEGER DEFAULT 0,
      UNIQUE(child_id, date)
    );
  `);

  console.log('✅ Database ready');
}

// ── DB helpers ────────────────────────────────────────────────────────────────
function dbGet(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const result = stmt.step() ? stmt.getAsObject() : null;
    stmt.free();
    return result;
  } catch (e) { console.error('dbGet:', e.message); return null; }
}

function dbAll(sql, params = []) {
  try {
    const rows = [];
    const stmt = db.prepare(sql);
    stmt.bind(params);
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } catch (e) { console.error('dbAll:', e.message); return []; }
}

function dbRun(sql, params = []) {
  try {
    db.run(sql, params);
    const r = dbGet('SELECT last_insert_rowid() as id');
    return { lastInsertRowid: r?.id };
  } catch (e) { console.error('dbRun:', e.message); throw e; }
}

// ── Middleware ────────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../dashboard')));

function authMiddleware(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.family = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
const parentConnections = new Map();
const deviceConnections = new Map();

function broadcastToParents(familyId, msg) {
  const conns = parentConnections.get(familyId);
  if (!conns) return;
  const data = JSON.stringify(msg);
  conns.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(data); });
}

function sendToDevice(deviceId, msg) {
  const ws = deviceConnections.get(deviceId);
  if (ws?.readyState === WebSocket.OPEN) { ws.send(JSON.stringify(msg)); return true; }
  return false;
}

wss.on('connection', (ws) => {
  let authenticated = false, familyId = null, deviceId = null, isDevice = false;
  const authTimeout = setTimeout(() => { if (!authenticated) ws.close(1008, 'Auth timeout'); }, 10000);

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch { return; }

    if (msg.type === 'AUTH') {
      // Parent auth
      if (msg.token) {
        try {
          const decoded = jwt.verify(msg.token, JWT_SECRET);
          familyId = decoded.familyId; authenticated = true;
          clearTimeout(authTimeout);
          if (!parentConnections.has(familyId)) parentConnections.set(familyId, new Set());
          parentConnections.get(familyId).add(ws);
          const children = dbAll(`SELECT c.*, COALESCE(s.minutes_used,0) as today_minutes, d.battery_level, d.is_online FROM children c LEFT JOIN screen_time_usage s ON c.id=s.child_id AND s.date=date('now') LEFT JOIN devices d ON c.id=d.child_id WHERE c.family_id=?`, [familyId]);
          ws.send(JSON.stringify({ type: 'STATE_SNAPSHOT', children }));
        } catch { ws.send(JSON.stringify({ type: 'AUTH_FAILED' })); ws.close(); }
      }
      // Device auth
      if (msg.deviceToken) {
        const device = dbGet('SELECT * FROM devices WHERE device_token=?', [msg.deviceToken]);
        if (!device) { ws.send(JSON.stringify({ type: 'AUTH_FAILED' })); ws.close(); return; }
        deviceId = device.id; familyId = device.family_id; isDevice = true; authenticated = true;
        clearTimeout(authTimeout);
        deviceConnections.set(deviceId, ws);
        dbRun(`UPDATE devices SET is_online=1, last_seen=strftime('%s','now') WHERE id=?`, [deviceId]);
        const child = dbGet('SELECT * FROM children WHERE id=?', [device.child_id]);
        const blockedApps = dbAll('SELECT package_name FROM blocked_apps WHERE child_id=? AND blocked=1', [device.child_id]).map(r => r.package_name);
        const websiteRules = dbAll('SELECT domain, rule_type FROM website_rules WHERE family_id=?', [familyId]);
        ws.send(JSON.stringify({ type: 'RULES_SYNC', rules: { studyModeActive: !!child?.study_mode_active, deviceLocked: !!child?.device_locked, dailyLimitMinutes: child?.daily_limit_minutes || 180, bedtimeHour: child?.bedtime_hour || 20, bedtimeMinute: child?.bedtime_minute || 30, wakeHour: child?.wake_hour || 7, wakeMinute: child?.wake_minute || 0, blockedApps, websiteRules } }));
        broadcastToParents(familyId, { type: 'DEVICE_ONLINE', deviceId, childId: device.child_id, childName: child?.name });
      }
      return;
    }

    if (!authenticated) return;

    // Parent commands
    if (!isDevice) {
      if (msg.type === 'LOCK_DEVICE') {
        dbRun('UPDATE children SET device_locked=1 WHERE id=? AND family_id=?', [msg.childId, familyId]);
        const d = dbGet('SELECT id FROM devices WHERE child_id=?', [msg.childId]);
        if (d) { sendToDevice(d.id, { type: 'LOCK', durationMinutes: msg.durationMinutes }); if (msg.durationMinutes) setTimeout(() => { dbRun('UPDATE children SET device_locked=0 WHERE id=?', [msg.childId]); sendToDevice(d.id, { type: 'UNLOCK' }); broadcastToParents(familyId, { type: 'DEVICE_UNLOCKED', childId: msg.childId }); }, msg.durationMinutes * 60000); }
      }
      if (msg.type === 'UNLOCK_DEVICE') { dbRun('UPDATE children SET device_locked=0 WHERE id=? AND family_id=?', [msg.childId, familyId]); const d = dbGet('SELECT id FROM devices WHERE child_id=?', [msg.childId]); if (d) sendToDevice(d.id, { type: 'UNLOCK' }); }
      if (msg.type === 'SET_STUDY_MODE') { dbRun('UPDATE children SET study_mode_active=? WHERE id=? AND family_id=?', [msg.active ? 1 : 0, msg.childId, familyId]); const d = dbGet('SELECT id FROM devices WHERE child_id=?', [msg.childId]); if (d) sendToDevice(d.id, { type: msg.active ? 'STUDY_MODE_ON' : 'STUDY_MODE_OFF' }); }
      if (msg.type === 'PUSH_RULES') {
        const d = dbGet('SELECT id FROM devices WHERE child_id=?', [msg.childId]);
        if (d) sendToDevice(d.id, { type: 'RULES_SYNC', rules: msg.rules });
      }
      if (msg.type === 'LOCK_ALL') { dbAll('SELECT id FROM children WHERE family_id=?', [familyId]).forEach(c => { dbRun('UPDATE children SET device_locked=1 WHERE id=?', [c.id]); const d = dbGet('SELECT id FROM devices WHERE child_id=?', [c.id]); if (d) sendToDevice(d.id, { type: 'LOCK' }); }); }
      if (msg.type === 'REQUEST_SCREENSHOT') { const d = dbGet('SELECT id FROM devices WHERE child_id=?', [msg.childId]); if (d) sendToDevice(d.id, { type: 'TAKE_SCREENSHOT' }); }
      if (msg.type === 'SEND_MESSAGE') { const d = dbGet('SELECT id FROM devices WHERE child_id=?', [msg.childId]); if (d) sendToDevice(d.id, { type: 'PARENT_MESSAGE', message: msg.message }); }
    }

    // Device events
    if (isDevice) {
      if (msg.type === 'HEARTBEAT') {
        dbRun(`UPDATE devices SET battery_level=?, last_seen=strftime('%s','now') WHERE id=?`, [msg.battery, deviceId]);
        const d = dbGet('SELECT child_id FROM devices WHERE id=?', [deviceId]);
        if (d) broadcastToParents(familyId, { type: 'DEVICE_HEARTBEAT', childId: d.child_id, battery: msg.battery, currentApp: msg.currentApp });
      }
      if (msg.type === 'ACTIVITY_EVENT') {
        const d = dbGet('SELECT child_id FROM devices WHERE id=?', [deviceId]);
        if (!d) return;
        const child = dbGet('SELECT name FROM children WHERE id=?', [d.child_id]);
        dbRun('INSERT INTO activity_log (family_id,child_id,child_name,event_type,app_name,package_name,domain,was_blocked,block_reason) VALUES (?,?,?,?,?,?,?,?,?)', [familyId, d.child_id, child?.name, msg.eventType, msg.appName, msg.packageName, msg.domain, msg.wasBlocked ? 1 : 0, msg.blockReason]);
        broadcastToParents(familyId, { type: 'ACTIVITY_EVENT', childId: d.child_id, childName: child?.name, eventType: msg.eventType, appName: msg.appName, domain: msg.domain, wasBlocked: msg.wasBlocked, blockReason: msg.blockReason, timestamp: Date.now() });
      }
      if (msg.type === 'SCREENSHOT') { const d = dbGet('SELECT child_id FROM devices WHERE id=?', [deviceId]); broadcastToParents(familyId, { type: 'SCREENSHOT', childId: d?.child_id, imageBase64: msg.imageBase64, timestamp: Date.now() }); }
      if (msg.type === 'SCREEN_TIME_UPDATE') {
        const d = dbGet('SELECT child_id FROM devices WHERE id=?', [deviceId]);
        if (!d) return;
        dbRun(`INSERT INTO screen_time_usage (child_id,family_id,date,minutes_used) VALUES (?,?,date('now'),?) ON CONFLICT(child_id,date) DO UPDATE SET minutes_used=excluded.minutes_used`, [d.child_id, familyId, msg.minutesUsed]);
        broadcastToParents(familyId, { type: 'SCREEN_TIME_UPDATE', childId: d.child_id, minutesUsed: msg.minutesUsed });
      }
      if (msg.type === 'UNLOCK_REQUEST') {
        const d = dbGet('SELECT child_id FROM devices WHERE id=?', [deviceId]);
        if (!d) return;
        const child = dbGet('SELECT name FROM children WHERE id=?', [d.child_id]);
        const reqId = require('crypto').randomBytes(8).toString('hex');
        dbRun(`INSERT INTO activity_log (family_id,child_id,child_name,event_type,app_name,block_reason) VALUES (?,?,?,?,?,?)`,
          [familyId, d.child_id, child?.name, 'UNLOCK_REQUEST', 'unlock', msg.reason || 'No reason given']);
        broadcastToParents(familyId, {
          type: 'UNLOCK_REQUEST',
          requestId: reqId,
          childId: d.child_id,
          childName: child?.name,
          reason: msg.reason || 'No reason given',
          timestamp: Date.now()
        });
      }
      if (msg.type === 'MOOD_CHECKIN') {
        const d = dbGet('SELECT child_id FROM devices WHERE id=?', [deviceId]);
        if (!d) return;
        const child = dbGet('SELECT name FROM children WHERE id=?', [d.child_id]);
        broadcastToParents(familyId, {
          type: 'MOOD_CHECKIN',
          childId: d.child_id,
          childName: child?.name,
          emoji: msg.emoji,
          label: msg.label,
          timestamp: Date.now()
        });
      }
    }
  });

  ws.on('close', () => {
    if (isDevice && deviceId) {
      deviceConnections.delete(deviceId);
      dbRun('UPDATE devices SET is_online=0 WHERE id=?', [deviceId]);
      const d = dbGet('SELECT child_id FROM devices WHERE id=?', [deviceId]);
      if (d && familyId) broadcastToParents(familyId, { type: 'DEVICE_OFFLINE', childId: d.child_id });
    }
    if (!isDevice && familyId) { const c = parentConnections.get(familyId); if (c) { c.delete(ws); if (c.size === 0) parentConnections.delete(familyId); } }
  });
});

// ── REST Routes ───────────────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', connectedDevices: deviceConnections.size, uptime: Math.floor(process.uptime()) }));

app.post('/api/auth/register', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'name, email and password required' });
  if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (dbGet('SELECT id FROM families WHERE email=?', [email])) return res.status(400).json({ error: 'Email already registered' });
  const id = uuidv4();
  dbRun('INSERT INTO families (id,name,email,password_hash) VALUES (?,?,?,?)', [id, name, email, bcrypt.hashSync(password, 10)]);
  res.status(201).json({ token: jwt.sign({ familyId: id, email }, JWT_SECRET, { expiresIn: '30d' }), familyId: id, name });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  const family = dbGet('SELECT * FROM families WHERE email=?', [email]);
  if (!family || !bcrypt.compareSync(password, family.password_hash)) return res.status(401).json({ error: 'Invalid email or password' });
  res.json({ token: jwt.sign({ familyId: family.id, email }, JWT_SECRET, { expiresIn: '30d' }), familyId: family.id, name: family.name });
});

app.get('/api/children', authMiddleware, (req, res) => res.json(dbAll(`SELECT c.*, COALESCE(s.minutes_used,0) as today_minutes, d.battery_level, d.is_online FROM children c LEFT JOIN screen_time_usage s ON c.id=s.child_id AND s.date=date('now') LEFT JOIN devices d ON c.id=d.child_id WHERE c.family_id=?`, [req.family.familyId])));

app.get('/api/children/:id', authMiddleware, (req, res) => { const c = dbGet('SELECT * FROM children WHERE id=? AND family_id=?', [req.params.id, req.family.familyId]); c ? res.json(c) : res.status(404).json({ error: 'Not found' }); });

app.post('/api/children', authMiddleware, (req, res) => {
  const { name, age, grade, platform = 'android' } = req.body;
  if (!name) return res.status(400).json({ error: 'name required' });
  const id = uuidv4();
  dbRun('INSERT INTO children (id,family_id,name,age,grade,platform) VALUES (?,?,?,?,?,?)', [id, req.family.familyId, name, age || null, grade || null, platform]);
  res.status(201).json(dbGet('SELECT * FROM children WHERE id=?', [id]));
});

app.put('/api/children/:id', authMiddleware, (req, res) => {
  if (!dbGet('SELECT id FROM children WHERE id=? AND family_id=?', [req.params.id, req.family.familyId])) return res.status(404).json({ error: 'Not found' });
  const { name, age, grade, daily_limit_minutes, bedtime_hour, bedtime_minute } = req.body;
  const { name, age, grade, daily_limit_minutes, bedtime_hour, bedtime_minute, wake_hour, wake_minute, bedtime_enabled } = req.body;
  dbRun('UPDATE children SET name=COALESCE(?,name),age=COALESCE(?,age),grade=COALESCE(?,grade),daily_limit_minutes=COALESCE(?,daily_limit_minutes),bedtime_hour=COALESCE(?,bedtime_hour),bedtime_minute=COALESCE(?,bedtime_minute),wake_hour=COALESCE(?,wake_hour),wake_minute=COALESCE(?,wake_minute),bedtime_enabled=COALESCE(?,bedtime_enabled) WHERE id=?', [name, age, grade, daily_limit_minutes, bedtime_hour, bedtime_minute, wake_hour, wake_minute, bedtime_enabled != null ? (bedtime_enabled ? 1 : 0) : null, req.params.id]);
  res.json(dbGet('SELECT * FROM children WHERE id=?', [req.params.id]));
});

app.post('/api/devices/pair', (req, res) => {
  const { childId, deviceName, platform = 'android' } = req.body;
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '');

  let familyId = null;

  // Accept either a real JWT or the setup token (setup_FAMILYID)
  if (token.startsWith('setup_')) {
    familyId = token.replace('setup_', '');
  } else {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'guardian_patrick_secret_2024_xyz');
      familyId = decoded.familyId;
    } catch (e) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }

  if (!familyId || !childId) return res.status(400).json({ error: 'familyId and childId required' });
  const child = dbGet('SELECT * FROM children WHERE id=? AND family_id=?', [childId, familyId]);
  if (!child) return res.status(404).json({ error: 'Child not found' });
  const deviceToken = uuidv4() + '-' + uuidv4();
  const deviceId = uuidv4();
  dbRun('INSERT OR REPLACE INTO devices (id,family_id,child_id,device_name,platform,device_token) VALUES (?,?,?,?,?,?)', [deviceId, familyId, childId, deviceName || `${child.name}'s tablet`, platform, deviceToken]);
  res.json({ deviceToken, deviceId, rules: { studyModeActive: false, deviceLocked: false, dailyLimitMinutes: child.daily_limit_minutes, bedtimeHour: child.bedtime_hour, bedtimeMinute: child.bedtime_minute, wakeHour: child.wake_hour, wakeMinute: child.wake_minute, blockedApps: dbAll('SELECT package_name FROM blocked_apps WHERE child_id=? AND blocked=1', [childId]).map(r => r.package_name), websiteRules: dbAll('SELECT domain,rule_type FROM website_rules WHERE family_id=?', [familyId]) } });
});

app.get('/api/children/:id/apps', authMiddleware, (req, res) => { if (!dbGet('SELECT id FROM children WHERE id=? AND family_id=?', [req.params.id, req.family.familyId])) return res.status(404).json({ error: 'Not found' }); res.json(dbAll('SELECT * FROM blocked_apps WHERE child_id=?', [req.params.id])); });

app.post('/api/children/:id/apps', authMiddleware, (req, res) => {
  if (!dbGet('SELECT id FROM children WHERE id=? AND family_id=?', [req.params.id, req.family.familyId])) return res.status(404).json({ error: 'Not found' });
  const { packageName, appName, blocked = true, reason } = req.body;
  if (!packageName) return res.status(400).json({ error: 'packageName required' });
  dbRun('INSERT INTO blocked_apps (child_id,family_id,package_name,app_name,blocked,reason) VALUES (?,?,?,?,?,?) ON CONFLICT(child_id,package_name) DO UPDATE SET blocked=excluded.blocked,app_name=excluded.app_name,reason=excluded.reason', [req.params.id, req.family.familyId, packageName, appName || packageName, blocked ? 1 : 0, reason || null]);
  // Push updated rules to the child's device immediately
  const d = dbGet('SELECT id FROM devices WHERE child_id=?', [req.params.id]);
  if (d) {
    const blockedApps = dbAll('SELECT package_name FROM blocked_apps WHERE child_id=? AND blocked=1', [req.params.id]).map(r => r.package_name);
    sendToDevice(d.id, { type: 'RULES_SYNC', rules: { blockedApps } });
  }
  res.status(201).json(dbGet('SELECT * FROM blocked_apps WHERE child_id=? AND package_name=?', [req.params.id, packageName]));
});

// DELETE a specific blocked app by package name
app.delete('/api/children/:id/apps/:pkg', authMiddleware, (req, res) => {
  if (!dbGet('SELECT id FROM children WHERE id=? AND family_id=?', [req.params.id, req.family.familyId])) return res.status(404).json({ error: 'Not found' });
  dbRun('DELETE FROM blocked_apps WHERE child_id=? AND package_name=?', [req.params.id, decodeURIComponent(req.params.pkg)]);
  // Push updated rules to device
  const d = dbGet('SELECT id FROM devices WHERE child_id=?', [req.params.id]);
  if (d) {
    const blockedApps = dbAll('SELECT package_name FROM blocked_apps WHERE child_id=? AND blocked=1', [req.params.id]).map(r => r.package_name);
    sendToDevice(d.id, { type: 'RULES_SYNC', rules: { blockedApps } });
  }
  res.json({ deleted: true });
});

// Also support legacy /api/app-rules/:id DELETE (dashboard uses this)
app.delete('/api/app-rules/:id', authMiddleware, (req, res) => {
  const app_row = dbGet('SELECT * FROM blocked_apps WHERE id=? AND family_id=?', [req.params.id, req.family.familyId]);
  if (!app_row) return res.status(404).json({ error: 'Not found' });
  dbRun('DELETE FROM blocked_apps WHERE id=?', [req.params.id]);
  // Push updated rules to device
  const d = dbGet('SELECT id FROM devices WHERE child_id=?', [app_row.child_id]);
  if (d) {
    const blockedApps = dbAll('SELECT package_name FROM blocked_apps WHERE child_id=? AND blocked=1', [app_row.child_id]).map(r => r.package_name);
    sendToDevice(d.id, { type: 'RULES_SYNC', rules: { blockedApps } });
  }
  res.json({ deleted: true });
});

// DELETE a child and all their data
app.delete('/api/children/:id', authMiddleware, (req, res) => {
  const child = dbGet('SELECT * FROM children WHERE id=? AND family_id=?', [req.params.id, req.family.familyId]);
  if (!child) return res.status(404).json({ error: 'Not found' });
  // Disconnect device if online
  const d = dbGet('SELECT id FROM devices WHERE child_id=?', [req.params.id]);
  if (d) {
    try { sendToDevice(d.id, { type: 'PARENT_MESSAGE', message: 'Your profile has been removed by your parent.' }); } catch(e) {}
    dbRun('DELETE FROM devices WHERE child_id=?', [req.params.id]);
  }
  dbRun('DELETE FROM blocked_apps WHERE child_id=?', [req.params.id]);
  dbRun('DELETE FROM screen_time_usage WHERE child_id=?', [req.params.id]);
  dbRun('DELETE FROM activity_log WHERE child_id=?', [req.params.id]);
  dbRun('DELETE FROM children WHERE id=?', [req.params.id]);
  res.json({ deleted: true });
});

app.post('/api/children/:id/reward', authMiddleware, (req, res) => {
  if (!dbGet('SELECT id FROM children WHERE id=? AND family_id=?', [req.params.id, req.family.familyId]))
    return res.status(404).json({ error: 'Not found' });
  const { extraMinutes, reason } = req.body;
  dbRun('INSERT INTO activity_log (family_id,child_id,event_type,app_name,block_reason) VALUES (?,?,?,?,?)',
    [req.family.familyId, req.params.id, 'REWARD', `+${extraMinutes}min`, reason || '']);
  res.json({ ok: true });
});

app.get('/api/website-rules', authMiddleware, (req, res) => res.json(dbAll('SELECT * FROM website_rules WHERE family_id=? ORDER BY created_at DESC', [req.family.familyId])));
app.post('/api/website-rules', authMiddleware, (req, res) => { const { domain, ruleType = 'block', childId } = req.body; if (!domain) return res.status(400).json({ error: 'domain required' }); const r = dbRun('INSERT INTO website_rules (family_id,child_id,domain,rule_type) VALUES (?,?,?,?)', [req.family.familyId, childId || null, domain, ruleType]); res.status(201).json(dbGet('SELECT * FROM website_rules WHERE id=?', [r.lastInsertRowid])); });
app.delete('/api/website-rules/:id', authMiddleware, (req, res) => { dbRun('DELETE FROM website_rules WHERE id=? AND family_id=?', [req.params.id, req.family.familyId]); res.json({ deleted: true }); });

app.get('/api/activity', authMiddleware, (req, res) => { const limit = Math.min(parseInt(req.query.limit) || 50, 200); res.json(dbAll('SELECT a.*,c.name as child_name FROM activity_log a LEFT JOIN children c ON a.child_id=c.id WHERE a.family_id=? ORDER BY a.timestamp DESC LIMIT ?', [req.family.familyId, limit])); });

app.get('/api/reports/weekly', authMiddleware, (req, res) => {
  const days = Array.from({ length: 7 }, (_, i) => {
    const date = new Date(Date.now() - (6 - i) * 86400000).toISOString().slice(0, 10);
    const row = dbGet(`SELECT COALESCE(SUM(minutes_used),0) as m FROM screen_time_usage WHERE family_id=? AND date=?`, [req.family.familyId, date]);
    const blocks = dbGet(`SELECT COUNT(*) as c FROM activity_log WHERE family_id=? AND was_blocked=1 AND date(timestamp,'unixepoch')=?`, [req.family.familyId, date]);
    return { date, totalMinutes: row?.m || 0, blocks: blocks?.c || 0 };
  });
  res.json({ days, totalMinutes: days.reduce((a, d) => a + d.totalMinutes, 0), totalBlocks: days.reduce((a, d) => a + d.blocks, 0) });
});

// ── Start ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`🛡️  Guardian server running on port ${PORT}`);
    console.log(`   Health: http://localhost:${PORT}/health`);
    console.log(`   Dashboard: http://localhost:${PORT}`);
  });
}).catch(err => { console.error('Failed to start:', err); process.exit(1); });

module.exports = { app, server };
