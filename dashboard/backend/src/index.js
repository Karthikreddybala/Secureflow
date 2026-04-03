import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const SALT_ROUNDS = 10;

// JWT secret — MUST be set via environment variable in production
if (!process.env.JWT_SECRET && process.env.NODE_ENV === 'production') {
  console.error('FATAL: JWT_SECRET environment variable is not set. Refusing to start in production.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-insecure-secret-do-not-use-in-prod';

// ===== MIDDLEWARE =====
// In production, set FRONTEND_URL env var to restrict CORS to your frontend domain.
// e.g. FRONTEND_URL=https://yourdomain.com
const FRONTEND_URL = process.env.FRONTEND_URL || null;
app.use(cors({
  origin: FRONTEND_URL
    ? (origin, callback) => {
        if (!origin || origin === FRONTEND_URL) return callback(null, true);
        return callback(new Error('Not allowed by CORS'));
      }
    : true,   // allow all in dev (no FRONTEND_URL set)
  credentials: true,
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ===== DATABASE =====
const db = new pg.Client({
  user: process.env.db_username,
  host: process.env.db_host,
  database: process.env.db_name,
  password: process.env.db_password,
  port: process.env.db_port,
});

db.connect().then(async () => {
  console.log('Database connected successfully');
  // Auto-migrate: add role column if not exists
  await db.query(`
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(10) DEFAULT 'user';
  `).catch(() => {});
  // Create alert_actions table if not exists
  await db.query(`
    CREATE TABLE IF NOT EXISTS alert_actions (
      id SERIAL PRIMARY KEY,
      alert_src_ip VARCHAR(45),
      action VARCHAR(20) NOT NULL,
      reason TEXT,
      performed_by VARCHAR(255),
      performed_at TIMESTAMP DEFAULT NOW()
    );
  `).catch(() => {});
}).catch(err => console.error('DB connection failed:', err));

// ===== AUTH MIDDLEWARE =====
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ===== ROUTES =====

// ── LOGIN ──────────────────────────────────────────────────────────────────────
app.post('/login', async (req, res) => {
  if (!req.body?.username || !req.body?.password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  const { username, password } = req.body;

  try {
    const result = await db.query('SELECT * FROM users WHERE email = $1', [username]);
    if (result.rows.length === 0) {
      return res.json({ status: 'failure', error: 'Invalid credentials' });
    }

    const user = result.rows[0];
    // Support both bcrypt hashes and legacy plain-text passwords
    let isValid = false;
    if (user.password_user.startsWith('$2b$') || user.password_user.startsWith('$2a$')) {
      isValid = await bcrypt.compare(password, user.password_user);
    } else {
      isValid = (password === user.password_user);
    }

    if (!isValid) {
      return res.json({ status: 'failure', error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.email, role: user.role || 'user' },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    console.log(`Login successful: ${username} [${user.role || 'user'}]`);
    return res.json({
      status: 'success',
      token,
      role: user.role || 'user',
      username: user.email,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// ── REGISTER ───────────────────────────────────────────────────────────────────
app.post('/register', async (req, res) => {
  if (!req.body?.username || !req.body?.password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (!/\S+@\S+\.\S+/.test(req.body.username)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (/\s/.test(req.body.password)) {
    return res.status(400).json({ error: 'Password cannot contain spaces' });
  }

  const { username, password, role = 'user' } = req.body;
  // Only allow 'user' role from self-registration
  const safeRole = role === 'admin' ? 'user' : role;

  try {
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [username]);
    if (existing.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    await db.query(
      'INSERT INTO users (email, password_user, role) VALUES ($1, $2, $3)',
      [username, hashedPassword, safeRole]
    );
    console.log(`Registration successful: ${username} [${safeRole}]`);
    return res.json({ status: 'success', message: `Registered as ${safeRole}` });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ error: 'Database error' });
  }
});

// ── GET CURRENT USER ───────────────────────────────────────────────────────────
app.get('/me', authenticate, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

// ── ADMIN: LIST USERS ─────────────────────────────────────────────────────────
app.get('/admin/users', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT id, email, role FROM users ORDER BY id');
    res.json({ users: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ── ADMIN: UPDATE USER ROLE ───────────────────────────────────────────────────
app.put('/admin/users/:id/role', authenticate, requireAdmin, async (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Must be user or admin.' });
  }
  try {
    await db.query('UPDATE users SET role = $1 WHERE id = $2', [role, req.params.id]);
    res.json({ status: 'success', message: `Role updated to ${role}` });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ── ALERT ACTIONS (block/dismiss decisions log) ───────────────────────────────
app.post('/alerts/action', authenticate, async (req, res) => {
  const { alert_src_ip, action, reason } = req.body;
  if (!alert_src_ip || !action) {
    return res.status(400).json({ error: 'alert_src_ip and action are required' });
  }
  try {
    await db.query(
      'INSERT INTO alert_actions (alert_src_ip, action, reason, performed_by) VALUES ($1, $2, $3, $4)',
      [alert_src_ip, action, reason || '', req.user.username]
    );
    res.json({ status: 'success' });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

app.get('/alerts/actions', authenticate, requireAdmin, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM alert_actions ORDER BY performed_at DESC LIMIT 200');
    res.json({ actions: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'Database error' });
  }
});

// ── HEALTH CHECK ──────────────────────────────────────────────────────────────
app.get('/health', (_, res) => res.json({ status: 'ok', service: 'SecureFlow Auth API' }));

// ── START SERVER ──────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`SecureFlow Auth Server running on port ${PORT}`);
});