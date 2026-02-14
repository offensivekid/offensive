import express from 'express';
import Database from 'better-sqlite3';
import bcrypt from 'bcrypt';
import session from 'express-session';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import cors from 'cors';
import { v4 as uuidv4 } from 'uuid';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const db = new Database(process.env.DB_PATH || './database.sqlite');
db.pragma('foreign_keys = ON');

// ============= AUTO-INITIALIZE DATABASE =============

function initializeDatabase() {
  console.log('🔧 Checking database...');
  
  // Check if tables exist
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table'").all();
  const tableNames = tables.map(t => t.name);
  
  if (!tableNames.includes('users')) {
    console.log('📦 Initializing database tables...');
    
    // Users table
    db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN DEFAULT 0,
        has_private_access BOOLEAN DEFAULT 0,
        created_at INTEGER NOT NULL,
        last_login INTEGER,
        CONSTRAINT username_length CHECK (length(username) >= 3 AND length(username) <= 50),
        CONSTRAINT email_format CHECK (email LIKE '%@%')
      )
    `);
    
    // Sessions table
    db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        expires_at INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    
    // Threads table
    db.exec(`
      CREATE TABLE IF NOT EXISTS threads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        body TEXT NOT NULL,
        author_id INTEGER NOT NULL,
        is_private BOOLEAN DEFAULT 0,
        views INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT title_length CHECK (length(title) >= 5 AND length(title) <= 200),
        CONSTRAINT body_length CHECK (length(body) >= 10 AND length(body) <= 5000)
      )
    `);
    
    // Replies table
    db.exec(`
      CREATE TABLE IF NOT EXISTS replies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        thread_id INTEGER NOT NULL,
        author_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (thread_id) REFERENCES threads(id) ON DELETE CASCADE,
        FOREIGN KEY (author_id) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT text_length CHECK (length(text) >= 5 AND length(text) <= 2000)
      )
    `);
    
    // Access Keys table
    db.exec(`
      CREATE TABLE IF NOT EXISTS access_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_code TEXT UNIQUE NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        created_by INTEGER NOT NULL,
        used_by INTEGER,
        created_at INTEGER NOT NULL,
        used_at INTEGER,
        FOREIGN KEY (created_by) REFERENCES users(id),
        FOREIGN KEY (used_by) REFERENCES users(id)
      )
    `);
    
    // SIEM Events table
    db.exec(`
      CREATE TABLE IF NOT EXISTS siem_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        user_id INTEGER,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
      )
    `);
    
    // Indexes
    db.exec(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_threads_author ON threads(author_id)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_threads_created ON threads(created_at DESC)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_replies_thread ON replies(thread_id)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_replies_author ON replies(author_id)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_access_keys_code ON access_keys(key_code)`);
    db.exec(`CREATE INDEX IF NOT EXISTS idx_siem_events_created ON siem_events(created_at DESC)`);
    
    console.log('✅ Database tables created');
    
    // Create admin user
    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@offensive-forum.local';
    
    const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get(adminUsername);
    
    if (!existingAdmin) {
      const passwordHash = bcrypt.hashSync(adminPassword, parseInt(process.env.BCRYPT_ROUNDS) || 12);
      
      const adminResult = db.prepare(`
        INSERT INTO users (username, email, password_hash, is_admin, has_private_access, created_at)
        VALUES (?, ?, ?, 1, 1, ?)
      `).run(adminUsername, adminEmail, passwordHash, Date.now());
      
      console.log(`✅ Admin user created: ${adminUsername}`);
      console.log(`⚠️  Default password: ${adminPassword}`);
      console.log(`🔒 CHANGE THE PASSWORD IMMEDIATELY!`);
      
      // Create sample threads
      const adminId = adminResult.lastInsertRowid;
      
      db.prepare(`
        INSERT INTO threads (title, body, author_id, is_private, created_at, updated_at)
        VALUES (?, ?, ?, 0, ?, ?)
      `).run(
        'Welcome to offensive-forum',
        'This is the first public thread. Everyone can see this!',
        adminId,
        Date.now(),
        Date.now()
      );
      
      db.prepare(`
        INSERT INTO threads (title, body, author_id, is_private, created_at, updated_at)
        VALUES (?, ?, ?, 1, ?, ?)
      `).run(
        'Private: Advanced Security Topics',
        'This thread is private and only visible to users with special access keys.',
        adminId,
        Date.now(),
        Date.now()
      );
      
      // Generate sample access key
      const sampleKey = generateAccessKey();
      
      db.prepare(`
        INSERT INTO access_keys (key_code, created_by, created_at)
        VALUES (?, ?, ?)
      `).run(sampleKey, adminId, Date.now());
      
      console.log(`🔑 Sample access key: ${sampleKey}`);
      console.log(`💡 Use this key to access private threads!`);
    }
  } else {
    console.log('✅ Database already initialized');
  }
}

// Helper function for key generation
function generateAccessKey() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const parts = [];
  
  for (let i = 0; i < 4; i++) {
    let part = '';
    for (let j = 0; j < 4; j++) {
      part += chars[Math.floor(Math.random() * chars.length)];
    }
    parts.push(part);
  }
  
  return parts.join('-');
}

// Initialize database on startup
initializeDatabase();

// ============= MIDDLEWARE =============

app.use(helmet({
  contentSecurityPolicy: false // Отключаем строгий CSP для работы inline-скриптов
}));

app.use(cors({
  origin: true, // Разрешаем все origins
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: parseInt(process.env.SESSION_MAX_AGE) || 86400000
  }
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests, please try again later'
});

app.use('/api/', limiter);

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// ============= SIEM LOGGING =============

function logSIEMEvent(type, severity, req, details = {}) {
  try {
    db.prepare(`
      INSERT INTO siem_events (event_type, severity, user_id, ip_address, user_agent, details, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      type,
      severity,
      req.session?.userId || null,
      req.ip,
      req.get('user-agent') || 'unknown',
      JSON.stringify(details),
      Date.now()
    );
  } catch (error) {
    console.error('SIEM logging error:', error);
  }
}

// ============= HELPER FUNCTIONS =============

function sanitizeInput(input) {
  if (typeof input !== 'string') return '';
  return input
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;')
    .trim();
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return false;
  if (username.length < 3 || username.length > 50) return false;
  return /^[a-zA-Z0-9_\-]+$/.test(username);
}

function validateEmail(email) {
  if (!email || typeof email !== 'string') return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  if (!password || typeof password !== 'string') return false;
  return password.length >= 6 && password.length <= 100;
}

function detectXSS(input) {
  const xssPatterns = [
    /<script[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /<iframe/i,
    /eval\(/i
  ];
  
  for (const pattern of xssPatterns) {
    if (pattern.test(input)) {
      return true;
    }
  }
  return false;
}

// ============= AUTH MIDDLEWARE =============

function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(req.session.userId);
  
  if (!user || !user.is_admin) {
    logSIEMEvent('unauthorized_admin_access', 'high', req, { userId: req.session.userId });
    return res.status(403).json({ error: 'Admin access required' });
  }
  
  next();
}

// ============= API ROUTES =============

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validation
    if (!validateUsername(username)) {
      return res.status(400).json({ error: 'Invalid username format' });
    }
    
    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Invalid email format' });
    }
    
    if (!validatePassword(password)) {
      return res.status(400).json({ error: 'Password must be 6-100 characters' });
    }
    
    // XSS check
    if (detectXSS(username) || detectXSS(email)) {
      logSIEMEvent('xss_attempt', 'high', req, { username, email });
      return res.status(400).json({ error: 'Invalid input detected' });
    }
    
    // Check if user exists
    const existingUser = db.prepare('SELECT id FROM users WHERE username = ? OR email = ?').get(username, email);
    
    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 12);
    
    // Create user
    const result = db.prepare(`
      INSERT INTO users (username, email, password_hash, created_at)
      VALUES (?, ?, ?, ?)
    `).run(sanitizeInput(username), email.toLowerCase(), passwordHash, Date.now());
    
    logSIEMEvent('user_registered', 'low', req, { userId: result.lastInsertRowid, username });
    
    res.json({ success: true, message: 'Registration successful' });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, accessKey } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password required' });
    }
    
    // Get user
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user) {
      logSIEMEvent('failed_login', 'medium', req, { username, reason: 'user_not_found' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check password
    const validPassword = await bcrypt.compare(password, user.password_hash);
    
    if (!validPassword) {
      logSIEMEvent('failed_login', 'medium', req, { username, reason: 'wrong_password' });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Check access key (если предоставлен)
    if (accessKey && accessKey.trim()) {
      const key = db.prepare('SELECT * FROM access_keys WHERE key_code = ? AND is_active = 1').get(accessKey);
      
      if (key) {
        // Activate private access
        db.prepare('UPDATE users SET has_private_access = 1 WHERE id = ?').run(user.id);
        
        // Mark key as used
        db.prepare('UPDATE access_keys SET is_active = 0, used_by = ?, used_at = ? WHERE id = ?')
          .run(user.id, Date.now(), key.id);
        
        logSIEMEvent('access_key_used', 'low', req, { userId: user.id, keyId: key.id });
      }
    }
    
    // Update last login
    db.prepare('UPDATE users SET last_login = ? WHERE id = ?').run(Date.now(), user.id);
    
    // Create session
    req.session.userId = user.id;
    req.session.username = user.username;
    req.session.isAdmin = Boolean(user.is_admin);
    req.session.hasPrivateAccess = Boolean(user.has_private_access);
    
    logSIEMEvent('successful_login', 'low', req, { userId: user.id, username: user.username });
    
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

// Logout
app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(err => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.json({ success: true });
  });
});

// Get current user
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

// ============= THREADS =============

// Get all threads
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
    
    // Если не админ и нет приватного доступа - показываем только публичные
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

// Get single thread
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
    
    // Проверка доступа к приватной теме
    if (thread.is_private) {
      if (!userId) {
        return res.status(403).json({ error: 'Access denied' });
      }
      
      const user = db.prepare('SELECT has_private_access, is_admin FROM users WHERE id = ?').get(userId);
      
      if (!user || (!user.is_admin && !user.has_private_access)) {
        logSIEMEvent('unauthorized_private_thread_access', 'medium', req, { threadId, userId });
        return res.status(403).json({ error: 'Access denied to private thread' });
      }
    }
    
    // Increment views
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

// Create thread
app.post('/api/threads', requireAuth, (req, res) => {
  try {
    const { title, body, isPrivate } = req.body;
    const userId = req.session.userId;
    
    // Валидация
    if (!title || title.length < 5 || title.length > 200) {
      return res.status(400).json({ error: 'Title must be 5-200 characters' });
    }
    
    if (!body || body.length < 10 || body.length > 5000) {
      return res.status(400).json({ error: 'Body must be 10-5000 characters' });
    }
    
    // XSS check
    if (detectXSS(title) || detectXSS(body)) {
      logSIEMEvent('xss_attempt', 'high', req, { title, body });
      return res.status(400).json({ error: 'Invalid input detected' });
    }
    
    // КРИТИЧНО: Проверка прав на создание приватных тем
    if (isPrivate) {
      const user = db.prepare('SELECT is_admin FROM users WHERE id = ?').get(userId);
      
      if (!user || !user.is_admin) {
        logSIEMEvent('unauthorized_private_thread_creation', 'high', req, { userId, title });
        return res.status(403).json({ error: 'Only admins can create private threads' });
      }
    }
    
    const result = db.prepare(`
      INSERT INTO threads (title, body, author_id, is_private, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(
      sanitizeInput(title),
      sanitizeInput(body),
      userId,
      isPrivate ? 1 : 0,
      Date.now(),
      Date.now()
    );
    
    logSIEMEvent('thread_created', 'low', req, { threadId: result.lastInsertRowid, isPrivate });
    
    res.json({
      success: true,
      threadId: result.lastInsertRowid
    });
    
  } catch (error) {
    console.error('Create thread error:', error);
    res.status(500).json({ error: 'Failed to create thread' });
  }
});

// ============= REPLIES =============

// Get replies for thread
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

// Create reply
app.post('/api/threads/:id/replies', requireAuth, (req, res) => {
  try {
    const threadId = parseInt(req.params.id);
    const { text } = req.body;
    const userId = req.session.userId;
    
    if (!text || text.length < 5 || text.length > 2000) {
      return res.status(400).json({ error: 'Reply must be 5-2000 characters' });
    }
    
    if (detectXSS(text)) {
      logSIEMEvent('xss_attempt', 'high', req, { text });
      return res.status(400).json({ error: 'Invalid input detected' });
    }
    
    // Check if thread exists and user has access
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
    `).run(threadId, userId, sanitizeInput(text), Date.now());
    
    logSIEMEvent('reply_created', 'low', req, { threadId, replyId: result.lastInsertRowid });
    
    res.json({
      success: true,
      replyId: result.lastInsertRowid
    });
    
  } catch (error) {
    console.error('Create reply error:', error);
    res.status(500).json({ error: 'Failed to create reply' });
  }
});

// ============= ADMIN ROUTES =============

// Generate access keys
app.post('/api/admin/keys/generate', requireAdmin, (req, res) => {
  try {
    const { count } = req.body;
    const userId = req.session.userId;
    
    if (!count || count < 1 || count > 50) {
      return res.status(400).json({ error: 'Count must be 1-50' });
    }
    
    const keys = [];
    
    for (let i = 0; i < count; i++) {
      const keyCode = generateAccessKey();
      
      db.prepare(`
        INSERT INTO access_keys (key_code, created_by, created_at)
        VALUES (?, ?, ?)
      `).run(keyCode, userId, Date.now());
      
      keys.push(keyCode);
    }
    
    logSIEMEvent('keys_generated', 'medium', req, { count, keys });
    
    res.json({ success: true, keys });
    
  } catch (error) {
    console.error('Generate keys error:', error);
    res.status(500).json({ error: 'Failed to generate keys' });
  }
});

// Get all keys
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

// Get stats
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
  logSIEMEvent('server_error', 'high', req, { error: err.message });
  res.status(500).json({ error: 'Internal server error' });
});

// ============= START SERVER =============

app.listen(PORT, () => {
  console.log(`🚀 offensive-forum running on http://localhost:${PORT}`);
  console.log(`📊 Database: ${process.env.DB_PATH || './database.sqlite'}`);
  console.log(`🔒 Session secret: ${process.env.SESSION_SECRET ? 'SET' : 'DEFAULT (CHANGE IT!)'}`);
  console.log('');
  console.log('📝 To initialize database: npm run init-db');
  console.log('');
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down gracefully...');
  db.close();
  process.exit(0);
});
