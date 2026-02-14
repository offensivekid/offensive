import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';
import session from 'express-session';
import connectSqlite3 from 'connect-sqlite3';import helmet from 'helmet';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// SQLite Session Store
const SQLiteStore = connectSqlite3(session);6
// Database connection
const db = new Database(process.env.DB_PATH || './database.sqlite');
db.pragma('foreign_keys = ON');

console.log('🔧 Initializing offensive-forum...');

// ============= AUTO-INITIALIZE DATABASE =============

function initDB() {
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  const tableNames = tables.map(t => t.name);
  
  if (!tableNames.includes('users')) {
    console.log('📦 Creating database tables...');
    
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0,
        has_private_access BOOLEAN DEFAULT 0,
        created_at INTEGER NOT NULL,
        last_login INTEGER
      );
      
      CREATE TABLE IF NOT EXISTS threads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        author_id INTEGER NOT NULL,
        is_private BOOLEAN DEFAULT 0,
        views INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
      );
      
      CREATE TABLE IF NOT EXISTS replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE
      );
      
      CREATE TABLE IF NOT EXISTS access_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        created_by INTEGER NOT NULL,
        used_by INTEGER,
        created_at INTEGER NOT NULL,
        used_at INTEGER,
        FOREIGN KEY (created_by) REFERENCES users(id)
      );
      
      CREATE TABLE IF NOT EXISTS siem_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        user_id INTEGER,
        ip_address TEXT,
        details TEXT,
        created_at INTEGER NOT NULL
      );
      
      CREATE INDEX idx_threads_created ON threads(created_at DESC);
      CREATE INDEX idx_replies_thread ON replies(thread_id);
      CREATE INDEX idx_access_keys_code ON access_keys(key_code);
    `);
    
    console.log('✅ Tables created');
    
    // Create admin
    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@offensive-forum.local';
    
    const hash = bcrypt.hashSync(adminPassword, 12);
    const adminResult = db.prepare(`
      INSERT INTO users (username, email, password_hash, is_admin, has_private_access, created_at)
      VALUES (?, ?, ?, 1, 1, ?)
    `).run(adminUsername, adminEmail, hash, Date.now());
    
    console.log(`✅ Admin created: ${adminUsername}`);
    
    // Sample threads
    const adminId = adminResult.lastInsertRowid;
    
    db.prepare(`
      INSERT INTO threads (title, body, author_id, is_private, created_at)
      VALUES (?, ?, ?, 0, ?)
    `).run('Welcome to offensive-forum', 'This is a public thread. Everyone can see this!', adminId, Date.now());
    
    db.prepare(`
      INSERT INTO threads (title, body, author_id, is_private, created_at)
      VALUES (?, ?, ?, 1, ?)
    `).run('Private: Advanced Topics', 'This is private. Only users with access key can see this.', adminId, Date.now());
    
    // Sample key
    const key = generateKey();
    db.prepare(`
      INSERT INTO access_keys (key_code, created_by, created_at)
      VALUES (?, ?, ?)
    `).run(key, adminId, Date.now());
    
    console.log(`🔑 Sample key: ${key}`);
  } else {
    console.log('✅ Database ready');
  }
}

function generateKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  return Array(4).fill(0).map(() => 
    Array(4).fill(0).map(() => chars[Math.floor(Math.random() * chars.length)]).join('')
  ).join('-');
}

initDB();

// ============= MIDDLEWARE =============

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Session with SQLite store
app.use(session({
  store: new SQLiteStore({
    db: 'sessions.sqlite',
    dir: '.'
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 86400000 // 24h
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 60000,
  max: 100
});
app.use('/api/', limiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// ============= HELPERS =============

function sanitize(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/[<>]/g, '').trim();
}

function logSIEM(type, severity, req, details = {}) {
  try {
    db.prepare(`
      INSERT INTO siem_events (event_type, severity, user_id, ip_address, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(type, severity, req.session?.userId || null, req.ip, JSON.stringify(details), Date.now());
  } catch (e) {
    console.error('SIEM error:', e);
  }
}

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId || !req.session.isAdmin) {
    return res.status(403).json({ error: 'Admin required' });
  }
  next();
}

// ============= AUTH API =============

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || username.length < 3 || username.length > 50) {
      return res.status(400).json({ error: 'Invalid username' });
    }
    
    if (!email || !email.includes('@')) {
      return res.status(400).json({ error: 'Invalid email' });
    }
    
    if (!password || password.length < 6) {
      return res.status(400).json({ error: 'Password too short' });
    }
    
    const exists = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    if (exists) {
      return res.status(400).json({ error: 'User already exists' });
    }
    
    const hash = await bcrypt.hash(password, 12);
    
    db.prepare(`
      INSERT INTO users (username, email, password_hash, created_at)
      VALUES (?, ?, ?, ?)
    `).run(sanitize(username), email.toLowerCase(), hash, Date.now());
    
    logSIEM('user_registered', 'low', req, { username });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, accessKey } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user) {
      logSIEM('failed_login', 'medium', req, { username, reason: 'not_found' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const valid = await bcrypt.compare(password, user.password_hash);
    
    if (!valid) {
      logSIEM('failed_login', 'medium', req, { username, reason: 'wrong_password' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check access key if provided
    if (accessKey && accessKey.trim()) {
      const key = db.prepare('SELECT * FROM access_keys WHERE key_code = ? AND is_active = 1').get(accessKey.toUpperCase());
      
      if (key) {
        db.prepare('UPDATE users SET has_private_access = 1 WHERE id = ?').run(user.id);
        db.prepare('UPDATE access_keys SET is_active = 0, used_by = ?, used_at = ? WHERE id = ?')
          .run(user.id, Date.now(), key.id);
        user.has_private_access = 1;
        logSIEM('key_used', 'low', req, { userId: user.id, keyId: key.id });
      }
    }
    
    db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(Date.now(), user.id);
    
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = Boolean(user.is_admin);
    req.session.hasPrivateAccess = Boolean(user.has_private_access);
    
    logSIEM('successful_login', 'low', req, { userId: user.id });
    
    res.json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        isAdmin: Boolean(user.is_admin),
        hasPrivateAccess: Boolean(user.has_private_access)
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

app.get('/api/auth/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, username, is_admin, has_private_access FROM users WHERE id = ?')
    .get(req.session.userId);
  
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  
  res.json({
    id: user.id,
    username: user.username,
    isAdmin: Boolean(user.is_admin),
    hasPrivateAccess: Boolean(user.has_private_access)
  });
});

// ============= THREADS API =============

app.get('/api/threads', (req, res) => {
  try {
    const userId = req.session?.userId;
    const user = userId ? db.prepare('SELECT has_private_access, is_admin FROM users WHERE id = ?').get(userId) : null;
    
    let query = `
      SELECT t.*, u.username as author_username,
        (SELECT COUNT(*) FROM replies WHERE thread_id = t.id) as reply_count
      FROM threads t
      JOIN users u ON t.author_id = u.id
    `;
    
    if (!user || (!user.is_admin && !user.has_private_access)) {
      query += ' WHERE t.is_private = 0';
    }
    
    query += ' ORDER BY t.created_at DESC';
    
    const threads = db.prepare(query).all();
    
    res.json(threads.map(t => ({
      ...t,
      is_private: Boolean(t.is_private)
    })));
  } catch (error) {
    console.error('Get threads error:', error);
    res.status(500).json({ error: 'Failed to fetch threads' });
  }
});

app.get('/api/threads/:id', (req, res) => {
  try {
    const threadId = parseInt(req.params.id);
    const userId = req.session?.userId;
    
    const thread = db.prepare(`
      SELECT t.*, u.username as author_username
      FROM threads t
      JOIN users u ON t.author_id = u.id
      WHERE t.id = ?
    `).get(threadId);
    
    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }
    
    if (thread.is_private) {
      if (!userId) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      const user = db.prepare('SELECT has_private_access, is_admin FROM users WHERE id = ?').get(userId);
      
      if (!user || (!user.is_admin && !user.has_private_access)) {
        logSIEM('unauthorized_access', 'medium', req, { threadId });
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    db.prepare('UPDATE threads SET views = views + 1 WHERE id = ?').run(threadId);
    
    res.json({
      ...thread,
      is_private: Boolean(thread.is_private)
    });
  } catch (error) {
    console.error('Get thread error:', error);
    res.status(500).json({ error: 'Failed to fetch thread' });
  }
});

app.post('/api/threads', requireAuth, (req, res) => {
  try {
    const { title, body, isPrivate } = req.body;
    const userId = req.session.userId;
    
    if (!title || title.length < 5 || title.length > 200) {
      return res.status(400).json({ error: 'Invalid title' });
    }
    
    if (!body || body.length < 10 || body.length > 5000) {
      return res.status(400).json({ error: 'Invalid body' });
    }
    
    if (isPrivate && !req.session.isAdmin) {
      logSIEM('unauthorized_private_thread', 'high', req, { userId });
      return res.status(403).json({ error: 'Only admins can create private threads' });
    }
    
    const result = db.prepare(`
      INSERT INTO threads (title, body, author_id, is_private, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(sanitize(title), sanitize(body), userId, isPrivate ? 1 : 0, Date.now());
    
    logSIEM('thread_created', 'low', req, { threadId: result.lastInsertRowid, isPrivate });
    
    res.json({ success: true, threadId: result.lastInsertRowid });
  } catch (error) {
    console.error('Create thread error:', error);
    res.status(500).json({ error: 'Failed to create thread' });
  }
});

// ============= REPLIES API =============

app.get('/api/threads/:id/replies', (req, res) => {
  try {
    const threadId = parseInt(req.params.id);
    
    const replies = db.prepare(`
      SELECT r.*, u.username as author_username
      FROM replies r
      JOIN users u ON r.author_id = u.id
      WHERE r.thread_id = ?
      ORDER BY r.created_at ASC
    `).all(threadId);
    
    res.json(replies);
  } catch (error) {
    console.error('Get replies error:', error);
    res.status(500).json({ error: 'Failed to fetch replies' });
  }
});

app.post('/api/threads/:id/replies', requireAuth, (req, res) => {
  try {
    const threadId = parseInt(req.params.id);
    const { text } = req.body;
    const userId = req.session.userId;
    
    if (!text || text.length < 5 || text.length > 2000) {
      return res.status(400).json({ error: 'Invalid reply text' });
    }
    
    const thread = db.prepare('SELECT is_private FROM threads WHERE id = ?').get(threadId);
    
    if (!thread) {
      return res.status(404).json({ error: 'Thread not found' });
    }
    
    if (thread.is_private) {
      const user = db.prepare('SELECT has_private_access, is_admin FROM users WHERE id = ?').get(userId);
      
      if (!user || (!user.is_admin && !user.has_private_access)) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    const result = db.prepare(`
      INSERT INTO replies (thread_id, author_id, text, created_at)
      VALUES (?, ?, ?, ?)
    `).run(threadId, userId, sanitize(text), Date.now());
    
    logSIEM('reply_created', 'low', req, { threadId, replyId: result.lastInsertRowid });
    
    res.json({ success: true, replyId: result.lastInsertRowid });
  } catch (error) {
    console.error('Create reply error:', error);
    res.status(500).json({ error: 'Failed to create reply' });
  }
});

// ============= ADMIN API =============

app.post('/api/admin/keys/generate', requireAdmin, (req, res) => {
  try {
    const { count } = req.body;
    const userId = req.session.userId;
    
    if (!count || count < 1 || count > 50) {
      return res.status(400).json({ error: 'Invalid count' });
    }
    
    const keys = [];
    
    for (let i = 0; i < count; i++) {
      const key = generateKey();
      
      db.prepare(`
        INSERT INTO access_keys (key_code, created_by, created_at)
        VALUES (?, ?, ?)
      `).run(key, userId, Date.now());
      
      keys.push(key);
    }
    
    logSIEM('keys_generated', 'medium', req, { count });
    
    res.json({ success: true, keys });
  } catch (error) {
    console.error('Generate keys error:', error);
    res.status(500).json({ error: 'Failed to generate keys' });
  }
});

app.get('/api/admin/keys', requireAdmin, (req, res) => {
  try {
    const keys = db.prepare(`
      SELECT ak.*, 
        creator.username as created_by_username,
        user.username as used_by_username
      FROM access_keys ak
      JOIN users creator ON ak.created_by = creator.id
      LEFT JOIN users user ON ak.used_by = user.id
      ORDER BY ak.created_at DESC
    `).all();
    
    res.json(keys.map(k => ({
      ...k,
      is_active: Boolean(k.is_active)
    })));
  } catch (error) {
    console.error('Get keys error:', error);
    res.status(500).json({ error: 'Failed to fetch keys' });
  }
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  try {
    const stats = {
      users: db.prepare('SELECT COUNT(*) as count FROM users').get().count,
      threads: db.prepare('SELECT COUNT(*) as count FROM threads').get().count,
      publicThreads: db.prepare('SELECT COUNT(*) as count FROM threads WHERE is_private = 0').get().count,
      privateThreads: db.prepare('SELECT COUNT(*) as count FROM threads WHERE is_private = 1').get().count,
      replies: db.prepare('SELECT COUNT(*) as count FROM replies').get().count,
      totalKeys: db.prepare('SELECT COUNT(*) as count FROM access_keys').get().count,
      activeKeys: db.prepare('SELECT COUNT(*) as count FROM access_keys WHERE is_active = 1').get().count,
      usedKeys: db.prepare('SELECT COUNT(*) as count FROM access_keys WHERE is_active = 0').get().count
    };
    
    res.json(stats);
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

// ============= SERVE FRONTEND =============

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============= ERROR HANDLING =============

app.use((err, req, res, next) => {
  console.error('Server error:', err);
  logSIEM('server_error', 'high', req, { error: err.message });
  res.status(500).json({ error: 'Internal server error' });
});

// ============= START SERVER =============

app.listen(PORT, () => {
  console.log(`🚀 offensive-forum running on http://localhost:${PORT}`);
  console.log(`📊 Database: ${process.env.DB_PATH || './database.sqlite'}`);
  console.log('');
});

process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down...');
  db.close();
  process.exit(0);
});
