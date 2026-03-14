'use strict';
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const initSqlJs = require('sql.js');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'guardian_patrick_secret_2024_xyz';
const DB_FILE = process.env.DB_FILE || '/app/guardian.db';

let db;

// ── DB ──────────────────────────────────────────────────────────────────────
function saveToDisk() {
  try {
    const data = db.export();
    fs.writeFileSync(DB_FILE, Buffer.from(data));
  } catch(e) { console.error('DB save error:', e.message); }
}

function dbRun(sql, params = []) {
  db.run(sql, params);
}

function dbGet(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  if (stmt.step()) {
    const row = stmt.getAsObject();
    stmt.free();
    return row;
  }
  stmt.free();
  return null;
}

function dbAll(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

async function initDB() {
  const SQL = await initSqlJs();

  if (fs.existsSync(DB_FILE)) {
    const fileBuffer = fs.readFileSync(DB_FILE);
    db = new SQL.Database(fileBuffer);
    console.log('✅ DB loaded from disk');
  } else {
    db = new SQL.Database();
    console.log('✅ Fresh DB created');
  }

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
      study_mode_active INTEGER DEFAULT 0,
      device_locked INTEGER DEFAULT 0,
      daily_limit_minutes INTEGER DEFAULT 180,
      today_minutes INTEGER DEFAULT 0,
      bedtime_hour INTEGER DEFAULT 21,
      bedtime_minute INTEGER DEFAULT 0,
      wake_hour INTEGER DEFAULT 6,
      wake_minute INTEGER DEFAULT 30,
      bedtime_enabled INTEGER DEFAULT 1,
      battery_level INTEGER,
      is_online INTEGER DEFAULT 0,
      device_token TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS blocked_apps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      child_id TEXT NOT NULL,
      family_id TEXT NOT NULL,
      package_name TEXT NOT NULL,
      app_name TEXT,
      blocked INTEGER DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS website_rules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id TEXT NOT NULL,
      domain TEXT NOT NULL,
      rule_type TEXT DEFAULT 'block'
    );
    CREATE TABLE IF NOT EXISTS activity_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      family_id TEXT NOT NULL,
      child_id TEXT NOT NULL,
      child_name TEXT,
      event_type TEXT,
      app_name TEXT,
      package_name TEXT,
      domain TEXT,
      was_blocked INTEGER DEFAULT 0,
      block_reason TEXT,
      timestamp INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS device_tokens (
      token TEXT PRIMARY KEY,
      child_id TEXT NOT NULL,
      family_id TEXT NOT NULL,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
  `);

  setInterval(saveToDisk, 5000);
  process.on('exit', saveToDisk);
  process.on('SIGINT', () => { saveToDisk(); process.exit(); });
  process.on('SIGTERM', () => { saveToDisk(); process.exit(); });
}

// ── WS device map ───────────────────────────────────────────────────────────
const deviceConnections = new Map(); // deviceId → ws

function sendToDevice(deviceId, msg) {
  const ws = deviceConnections.get(deviceId);
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
    return true;
  }
  return false;
}

// ── App ─────────────────────────────────────────────────────────────────────
const app = express();
app.use(express.json({ limit: '5mb' }));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Auth middleware ──────────────────────────────────────────────────────────
function authRequired(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.familyId = payload.familyId;
    req.familyName = payload.name;
    next();
  } catch(e) { return res.status(401).json({ error: 'Invalid token' }); }
}

// ── Auth routes ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  if (dbGet('SELECT id FROM families WHERE email=?', [email]))
    return res.status(400).json({ error: 'Email already registered' });
  const hash = await bcrypt.hash(password, 10);
  const id = uuidv4();
  dbRun('INSERT INTO families (id, name, email, password_hash) VALUES (?,?,?,?)', [id, name, email, hash]);
  saveToDisk();
  const token = jwt.sign({ familyId: id, name }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, familyId: id, name });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Missing fields' });
  const family = dbGet('SELECT * FROM families WHERE email=?', [email]);
  if (!family) return res.status(401).json({ error: 'Invalid email or password' });
  const ok = await bcrypt.compare(password, family.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
  const token = jwt.sign({ familyId: family.id, name: family.name }, JWT_SECRET, { expiresIn: '90d' });
  res.json({ token, familyId: family.id, name: family.name });
});

// ── Children ──────────────────────────────────────────────────────────────────
app.get('/api/children', authRequired, (req, res) => {
  const children = dbAll('SELECT * FROM children WHERE family_id=? ORDER BY created_at', [req.familyId]);
  // Attach live online status
  children.forEach(c => {
    c.is_online = deviceConnections.has(c.id) ? 1 : 0;
  });
  res.json(children);
});

app.post('/api/children', authRequired, (req, res) => {
  const { name, age, grade } = req.body;
  if (!name) return res.status(400).json({ error: 'Name required' });
  const id = uuidv4();
  dbRun('INSERT INTO children (id, family_id, name, age, grade) VALUES (?,?,?,?,?)',
    [id, req.familyId, name, age || null, grade || null]);
  saveToDisk();
  res.json(dbGet('SELECT * FROM children WHERE id=?', [id]));
});

app.put('/api/children/:id', authRequired, (req, res) => {
  const { name, age, grade, daily_limit_minutes, bedtime_hour, bedtime_minute,
          wake_hour, wake_minute, bedtime_enabled, study_mode_active, device_locked } = req.body;
  dbRun(`UPDATE children SET
    name=COALESCE(?,name), age=COALESCE(?,age), grade=COALESCE(?,grade),
    daily_limit_minutes=COALESCE(?,daily_limit_minutes),
    bedtime_hour=COALESCE(?,bedtime_hour), bedtime_minute=COALESCE(?,bedtime_minute),
    wake_hour=COALESCE(?,wake_hour), wake_minute=COALESCE(?,wake_minute),
    bedtime_enabled=COALESCE(?,bedtime_enabled),
    study_mode_active=COALESCE(?,study_mode_active),
    device_locked=COALESCE(?,device_locked)
    WHERE id=? AND family_id=?`,
    [name, age, grade, daily_limit_minutes, bedtime_hour, bedtime_minute,
     wake_hour, wake_minute,
     bedtime_enabled != null ? (bedtime_enabled ? 1 : 0) : null,
     study_mode_active != null ? (study_mode_active ? 1 : 0) : null,
     device_locked != null ? (device_locked ? 1 : 0) : null,
     req.params.id, req.familyId]);
  saveToDisk();
  res.json(dbGet('SELECT * FROM children WHERE id=?', [req.params.id]));
});

app.delete('/api/children/:id', authRequired, (req, res) => {
  dbRun('DELETE FROM children WHERE id=? AND family_id=?', [req.params.id, req.familyId]);
  saveToDisk();
  res.json({ ok: true });
});

// ── Blocked apps ──────────────────────────────────────────────────────────────
app.get('/api/children/:id/apps', authRequired, (req, res) => {
  res.json(dbAll('SELECT * FROM blocked_apps WHERE child_id=?', [req.params.id]));
});

app.post('/api/children/:id/apps', authRequired, (req, res) => {
  const { packageName, appName, blocked } = req.body;
  dbRun('INSERT INTO blocked_apps (child_id, family_id, package_name, app_name, blocked) VALUES (?,?,?,?,?)',
    [req.params.id, req.familyId, packageName, appName || packageName, blocked ? 1 : 0]);
  saveToDisk();
  // Push rules to device
  pushRulesToDevice(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/apps/:id', authRequired, (req, res) => {
  dbRun('DELETE FROM blocked_apps WHERE id=?', [req.params.id]);
  saveToDisk();
  res.json({ ok: true });
});

// ── Website rules ──────────────────────────────────────────────────────────────
app.get('/api/web-rules', authRequired, (req, res) => {
  res.json(dbAll('SELECT * FROM website_rules WHERE family_id=?', [req.familyId]));
});

app.post('/api/web-rules', authRequired, (req, res) => {
  const { domain, ruleType } = req.body;
  dbRun('INSERT INTO website_rules (family_id, domain, rule_type) VALUES (?,?,?)',
    [req.familyId, domain, ruleType || 'block']);
  saveToDisk();
  res.json({ ok: true });
});

app.delete('/api/web-rules/:id', authRequired, (req, res) => {
  dbRun('DELETE FROM website_rules WHERE id=? AND family_id=?', [req.params.id, req.familyId]);
  saveToDisk();
  res.json({ ok: true });
});

// ── Activity ──────────────────────────────────────────────────────────────────
app.get('/api/activity', authRequired, (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json(dbAll('SELECT * FROM activity_log WHERE family_id=? ORDER BY timestamp DESC LIMIT ?',
    [req.familyId, limit]));
});

// ── Device pairing ────────────────────────────────────────────────────────────
app.post('/api/pair', (req, res) => {
  const { childId, familyId } = req.body;
  if (!childId || !familyId) return res.status(400).json({ error: 'Missing childId or familyId' });
  const child = dbGet('SELECT * FROM children WHERE id=? AND family_id=?', [childId, familyId]);
  if (!child) return res.status(404).json({ error: 'Child not found' });
  const token = uuidv4();
  dbRun('UPDATE children SET device_token=? WHERE id=?', [token, childId]);
  // Clean up old token entries
  dbRun('DELETE FROM device_tokens WHERE child_id=?', [childId]);
  dbRun('INSERT INTO device_tokens (token, child_id, family_id) VALUES (?,?,?)',
    [token, childId, familyId]);
  saveToDisk();
  const blockedApps = dbAll('SELECT package_name FROM blocked_apps WHERE child_id=? AND blocked=1', [childId])
    .map(r => r.package_name);
  const websiteRules = dbAll('SELECT domain, rule_type FROM website_rules WHERE family_id=?', [familyId]);
  res.json({
    deviceToken: token,
    deviceId: childId,
    childName: child.name,
    rules: {
      studyModeActive: !!child.study_mode_active,
      deviceLocked: !!child.device_locked,
      dailyLimitMinutes: child.daily_limit_minutes,
      bedtimeHour: child.bedtime_hour,
      bedtimeMinute: child.bedtime_minute,
      wakeHour: child.wake_hour,
      wakeMinute: child.wake_minute,
      bedtimeEnabled: !!child.bedtime_enabled,
      blockedApps,
      websiteRules
    }
  });
});

// ── Commands (REST fallback) ──────────────────────────────────────────────────
app.post('/api/command', authRequired, (req, res) => {
  const { type, childId, ...rest } = req.body;
  const child = dbGet('SELECT * FROM children WHERE id=? AND family_id=?', [childId, req.familyId]);
  if (!child) return res.status(404).json({ error: 'Child not found' });

  if (type === 'LOCK_DEVICE') {
    dbRun('UPDATE children SET device_locked=1 WHERE id=?', [childId]);
    saveToDisk();
    sendToDevice(childId, { type: 'LOCK_DEVICE' });
  } else if (type === 'UNLOCK_DEVICE') {
    dbRun('UPDATE children SET device_locked=0 WHERE id=?', [childId]);
    saveToDisk();
    sendToDevice(childId, { type: 'UNLOCK_DEVICE' });
  } else if (type === 'SET_STUDY_MODE') {
    const active = rest.active ? 1 : 0;
    dbRun('UPDATE children SET study_mode_active=? WHERE id=?', [active, childId]);
    saveToDisk();
    sendToDevice(childId, { type: 'SET_STUDY_MODE', active: !!rest.active });
  } else if (type === 'SEND_MESSAGE') {
    sendToDevice(childId, { type: 'PARENT_MESSAGE', message: rest.message });
  }
  res.json({ ok: true, delivered: deviceConnections.has(childId) });
});

// ── Reward ────────────────────────────────────────────────────────────────────
app.post('/api/children/:id/reward', authRequired, (req, res) => {
  const { extraMinutes, reason } = req.body;
  const childId = req.params.id;
  dbRun('UPDATE children SET daily_limit_minutes = daily_limit_minutes + ? WHERE id=? AND family_id=?',
    [extraMinutes || 0, childId, req.familyId]);
  saveToDisk();
  sendToDevice(childId, { type: 'GIVE_REWARD', extraMinutes, reason });
  res.json({ ok: true });
});

// ── Debug ─────────────────────────────────────────────────────────────────────
app.get('/debug/devices', (req, res) => {
  const devices = [];
  deviceConnections.forEach((ws, id) => {
    devices.push({ id, ws_connected: ws.readyState === WebSocket.OPEN });
  });
  res.json({ connected: devices.length, devices });
});

app.get('/health', (req, res) => res.json({ ok: true, devices: deviceConnections.size }));

// ── Helper: push rules to device ─────────────────────────────────────────────
function pushRulesToDevice(childId) {
  const child = dbGet('SELECT * FROM children WHERE id=?', [childId]);
  if (!child) return;
  const blockedApps = dbAll('SELECT package_name FROM blocked_apps WHERE child_id=? AND blocked=1', [childId])
    .map(r => r.package_name);
  const websiteRules = dbAll('SELECT domain, rule_type FROM website_rules WHERE family_id=?', [child.family_id]);
  sendToDevice(childId, {
    type: 'RULES_SYNC',
    rules: {
      studyModeActive: !!child.study_mode_active,
      deviceLocked: !!child.device_locked,
      dailyLimitMinutes: child.daily_limit_minutes,
      bedtimeHour: child.bedtime_hour,
      bedtimeMinute: child.bedtime_minute,
      wakeHour: child.wake_hour,
      wakeMinute: child.wake_minute,
      bedtimeEnabled: !!child.bedtime_enabled,
      blockedApps,
      websiteRules
    }
  });
}

// ── Dashboard ─────────────────────────────────────────────────────────────────
// Serve from file if exists (for development), otherwise inline
app.get('/', (req, res) => {
  const dashPath = path.join(__dirname, 'dashboard.html');
  if (fs.existsSync(dashPath)) {
    res.sendFile(dashPath);
  } else {
    res.send('<h1>Guardian Server Running</h1><p>Dashboard not found. Add dashboard.html.</p>');
  }
});

app.get('/dashboard.html', (req, res) => {
  const dashPath = path.join(__dirname, 'dashboard.html');
  if (fs.existsSync(dashPath)) res.sendFile(dashPath);
  else res.redirect('/');
});

// ── HTTP server + WebSocket ───────────────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  console.log('🔌 WS upgrade:', req.url);
  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', (ws, req) => {
  console.log('🔌 New WS connection');
  let deviceId = null;
  let familyId = null;
  let isParent = false;

  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw); } catch(e) { return; }

    // ── Device auth ──
    if (msg.type === 'AUTH') {
      const tokenRecord = dbGet('SELECT * FROM device_tokens WHERE token=?', [msg.deviceToken]);
      if (!tokenRecord) { ws.send(JSON.stringify({ type: 'AUTH_FAILED' })); return; }
      deviceId = tokenRecord.child_id;
      familyId = tokenRecord.family_id;
      deviceConnections.set(deviceId, ws);
      dbRun('UPDATE children SET is_online=1 WHERE id=?', [deviceId]);
      saveToDisk();
      console.log(`✅ Device authenticated: ${deviceId}`);

      // Send current rules
      pushRulesToDevice(deviceId);

      // Notify parent dashboards
      broadcastToFamily(familyId, {
        type: 'DEVICE_ONLINE',
        childId: deviceId,
        childName: dbGet('SELECT name FROM children WHERE id=?', [deviceId])?.name
      }, ws);
      return;
    }

    // ── Parent dashboard auth ──
    if (msg.type === 'PARENT_AUTH') {
      try {
        const payload = jwt.verify(msg.token, JWT_SECRET);
        familyId = payload.familyId;
        isParent = true;
        parentConnections.set(ws, familyId);
        console.log(`✅ Parent dashboard connected: ${familyId}`);
        ws.send(JSON.stringify({ type: 'PARENT_AUTH_OK' }));
      } catch(e) {
        ws.send(JSON.stringify({ type: 'AUTH_FAILED' }));
      }
      return;
    }

    // ── Commands from parent dashboard ──
    if (isParent && familyId) {
      handleParentCommand(msg, familyId, ws);
      return;
    }

    // ── Messages from device ──
    if (deviceId) {
      handleDeviceMessage(msg, deviceId, familyId);
    }
  });

  ws.on('close', () => {
    if (deviceId) {
      deviceConnections.delete(deviceId);
      dbRun('UPDATE children SET is_online=0 WHERE id=?', [deviceId]);
      saveToDisk();
      broadcastToFamily(familyId, { type: 'DEVICE_OFFLINE', childId: deviceId }, null);
    }
    if (isParent) {
      parentConnections.delete(ws);
    }
  });

  ws.on('error', (e) => console.error('WS error:', e.message));
});

// Parent connections map: ws → familyId
const parentConnections = new Map();

function broadcastToFamily(familyId, msg, excludeWs) {
  parentConnections.forEach((fid, ws) => {
    if (fid === familyId && ws !== excludeWs && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(msg));
    }
  });
}

function handleParentCommand(msg, familyId, ws) {
  const { type, childId } = msg;
  if (!childId) return;

  const child = dbGet('SELECT * FROM children WHERE id=? AND family_id=?', [childId, familyId]);
  if (!child) return;

  console.log(`📲 Parent command: ${type} → child ${childId}`);

  if (type === 'LOCK_DEVICE') {
    dbRun('UPDATE children SET device_locked=1 WHERE id=?', [childId]);
    saveToDisk();
    const delivered = sendToDevice(childId, { type: 'LOCK_DEVICE' });
    ws.send(JSON.stringify({ type: 'CMD_RESULT', command: type, childId, delivered }));
  } else if (type === 'UNLOCK_DEVICE') {
    dbRun('UPDATE children SET device_locked=0 WHERE id=?', [childId]);
    saveToDisk();
    const delivered = sendToDevice(childId, { type: 'UNLOCK_DEVICE' });
    ws.send(JSON.stringify({ type: 'CMD_RESULT', command: type, childId, delivered }));
  } else if (type === 'SET_STUDY_MODE') {
    const active = msg.active ? 1 : 0;
    dbRun('UPDATE children SET study_mode_active=? WHERE id=?', [active, childId]);
    saveToDisk();
    const delivered = sendToDevice(childId, { type: 'SET_STUDY_MODE', active: !!msg.active });
    ws.send(JSON.stringify({ type: 'CMD_RESULT', command: type, childId, delivered }));
  } else if (type === 'SEND_MESSAGE') {
    sendToDevice(childId, { type: 'PARENT_MESSAGE', message: msg.message });
  } else if (type === 'GIVE_REWARD') {
    dbRun('UPDATE children SET daily_limit_minutes = daily_limit_minutes + ? WHERE id=?',
      [msg.extraMinutes || 0, childId]);
    saveToDisk();
    sendToDevice(childId, { type: 'GIVE_REWARD', extraMinutes: msg.extraMinutes, reason: msg.reason });
  } else if (type === 'PUSH_RULES') {
    pushRulesToDevice(childId);
  }
}

function handleDeviceMessage(msg, deviceId, familyId) {
  const { type } = msg;
  const child = dbGet('SELECT name FROM children WHERE id=?', [deviceId]);
  const childName = child?.name || 'Unknown';

  if (type === 'HEARTBEAT') {
    if (msg.battery != null) {
      dbRun('UPDATE children SET battery_level=?, today_minutes=? WHERE id=?',
        [msg.battery, msg.todayMinutes || 0, deviceId]);
    }
    broadcastToFamily(familyId, {
      type: 'DEVICE_HEARTBEAT',
      childId: deviceId,
      battery: msg.battery,
      todayMinutes: msg.todayMinutes
    }, null);
  } else if (type === 'ACTIVITY_EVENT') {
    const { appName, packageName, domain, wasBlocked, blockReason, eventType } = msg;
    dbRun(`INSERT INTO activity_log (family_id, child_id, child_name, event_type, app_name, package_name, domain, was_blocked, block_reason)
           VALUES (?,?,?,?,?,?,?,?,?)`,
      [familyId, deviceId, childName, eventType || 'app', appName, packageName, domain,
       wasBlocked ? 1 : 0, blockReason || null]);
    broadcastToFamily(familyId, {
      type: 'ACTIVITY_EVENT',
      childId: deviceId,
      childName,
      appName, packageName, domain,
      wasBlocked, blockReason,
      timestamp: Date.now()
    }, null);
  } else if (type === 'UNLOCK_REQUEST') {
    broadcastToFamily(familyId, {
      type: 'UNLOCK_REQUEST',
      childId: deviceId,
      childName,
      reason: msg.reason,
      timestamp: Date.now()
    }, null);
  } else if (type === 'MOOD_CHECKIN') {
    broadcastToFamily(familyId, {
      type: 'MOOD_CHECKIN',
      childId: deviceId,
      childName,
      mood: msg.mood,
      timestamp: Date.now()
    }, null);
  } else if (type === 'SCREEN_TIME_UPDATE') {
    dbRun('UPDATE children SET today_minutes=? WHERE id=?', [msg.minutes || 0, deviceId]);
    broadcastToFamily(familyId, {
      type: 'SCREEN_TIME_UPDATE',
      childId: deviceId,
      minutes: msg.minutes
    }, null);
  }
}

// ── Start ─────────────────────────────────────────────────────────────────────
initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`🛡️  Guardian Server running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Failed to init DB:', err);
  process.exit(1);
});
