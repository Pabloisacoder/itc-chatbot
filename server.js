// server/server.js
import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { fileURLToPath } from 'url';

dotenv.config();

// ---- App & config ----
const app = express();
const PORT = process.env.PORT || 3001;
const ORIGIN = process.env.CORS_ORIGIN || '*';
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || '';
const JWT_SECRET = process.env.JWT_SECRET || 'change-me';
const TOKEN_EXPIRES = process.env.TOKEN_EXPIRES || '7d';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(cors({ origin: ORIGIN }));
app.use(express.json());

// Serve static files from the 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// ---- Tickets "DB" (server/db.json) ----
const DB_PATH = path.join(__dirname, 'db.json');
function ensureDb() {
  if (!fs.existsSync(DB_PATH)) {
    fs.writeFileSync(DB_PATH, JSON.stringify({ tickets: [] }, null, 2));
  }
}
function readDb() {
  ensureDb();
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function writeDb(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));
}

// ---- Users store (server/users.json) ----
const USERS_PATH = path.join(__dirname, 'users.json');
function ensureUsers() {
  if (!fs.existsSync(USERS_PATH)) {
    fs.writeFileSync(USERS_PATH, JSON.stringify({ users: [] }, null, 2));
  }
}
function readUsers() {
  ensureUsers();
  return JSON.parse(fs.readFileSync(USERS_PATH, 'utf8'));
}
function writeUsers(data) {
  fs.writeFileSync(USERS_PATH, JSON.stringify(data, null, 2));
}

// ---- Auth helpers ----
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: TOKEN_EXPIRES });
}
function authRequired(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.startsWith('Bearer ') ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { username, role }
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminRequired(req, res, next) {
  // First, run the standard auth check to get req.user
  authRequired(req, res, () => {
    // Now, check if the authenticated user is an Admin
    if (req.user && req.user.role === 'Admin') {
      next(); // User is an Admin, proceed
    } else {
      res.status(403).json({ error: 'Forbidden: Admin access required' });
    }
  });
}
const ALLOWED_ROLES = ['Employee', 'Worker', 'Security', 'Contractor', 'SSP', 'Admin'];

// ---- Routes ----

// Health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// REGISTER (public; lock down later if needed)
app.post('/api/auth/register', async (req, res) => {
  console.log('Register attempt for:', req.body?.username);
  let { username, password, role, contractor } = req.body || {};
  if (!role) role = 'Employee'; // Default role if not provided
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }

  // Normalize
  username = String(username).trim();
  role = String(role).trim();
  if (!ALLOWED_ROLES.includes(role)) {
    console.log(`DEBUG: Received role '${role}'. Allowed: ${JSON.stringify(ALLOWED_ROLES)}`);
    console.log(`Registration failed: Invalid role '${role}'`);
    return res.status(400).json({ error: 'Invalid role' });
  }
  if (role === 'SSP' && !contractor) {
    return res.status(400).json({ error: 'Contractor name is required for SSP' });
  }
  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ error: 'Username or password too short' });
  }

  const store = readUsers();
  const exists = store.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  if (exists) return res.status(409).json({ error: 'Username already exists' });

  // The first user to register as 'Admin' is automatically approved.
  const hasAdmin = store.users.some(u => u.role === 'Admin' && u.status === 'approved');
  const isFirstAdmin = role === 'Admin' && !hasAdmin;
  const status = isFirstAdmin ? 'approved' : 'pending';

  const passwordHash = await bcrypt.hash(password, 10);
  store.users.push({
    username,
    passwordHash,
    role,
    contractor: role === 'SSP' ? String(contractor).trim() : undefined,
    status, // Use the calculated status
    registeredAt: new Date().toISOString()
  });
  writeUsers(store);

  const message = isFirstAdmin
    ? 'Admin registration successful! You can now log in via the Admin Portal.'
    : 'Registration successful, pending approval.';
  return res.json({ ok: true, message });
});

// LOGIN
app.post('/api/auth/login', async (req, res) => {
  console.log('Login attempt for:', req.body?.username);
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }
  const { users } = readUsers();
  const user = users.find(u => u.username.toLowerCase() === String(username).toLowerCase());
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  // Check approval status. Default to 'approved' if status is not set for existing users.
  const status = user.status || 'approved';
  if (status === 'pending') {
    return res.status(403).json({ error: 'Your account is pending approval.' });
  }

  // Admins must use the admin portal to log in
  if (user.role === 'Admin') {
    return res.status(403).json({ error: 'Administrators must use the admin portal.' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

  const token = signToken({ username: user.username, role: user.role });
  res.json({ ok: true, token, role: user.role, username: user.username });
});

// ADMIN LOGIN
app.post('/api/auth/admin/login', async (req, res) => {
  console.log('Admin Login attempt for:', req.body?.username);
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password' });
  }
  const { users } = readUsers();
  const user = users.find(u => u.username.toLowerCase() === String(username).toLowerCase());

  // Check if user is an admin
  if (!user || user.role !== 'Admin') {
    return res.status(401).json({ error: 'Invalid admin credentials' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Invalid admin credentials' });

  const token = signToken({ username: user.username, role: user.role });
  res.json({ ok: true, token, role: user.role, username: user.username });
});

// Create ticket (requires login)
app.post('/api/tickets', authRequired, (req, res) => {
  console.log('Ticket create attempt:', req.body);
  const { empId, category, desc } = req.body || {};

  const missing = [];
  if (!empId) missing.push('empId');
  if (!category) missing.push('category');
  if (!desc) missing.push('desc');

  if (missing.length > 0) {
    return res.status(400).json({ error: `Missing fields: ${missing.join(', ')}` });
  }
  const db = readDb();
  const ticket = {
    id: 'T' + (db.tickets.length + 1).toString().padStart(5, '0'),
    empId: String(empId).trim(),
    email: 'N/A',
    category,
    desc: String(desc).trim(),
    status: 'Open',
    createdBy: { username: req.user.username, role: req.user.role },
    createdAt: new Date().toISOString()
  };
  db.tickets.push(ticket);
  writeDb(db);
  res.json({ ok: true, ticket });
});

// Get ticket by id (open)
app.get('/api/tickets/:id', (req, res) => {
  const db = readDb();
  const t = db.tickets.find(x => x.id === req.params.id);
  if (!t) return res.status(404).json({ error: 'Not found' });
  res.json(t);
});

// List tickets (admin only)
app.get('/api/tickets', adminRequired, (req, res) => {
  const db = readDb();
  res.json(db.tickets);
});

// Update ticket status (admin only)
app.patch('/api/tickets/:id', adminRequired, (req, res) => {
  const { status } = req.body || {};
  const allowed = ['Open', 'In Progress', 'Resolved', 'Closed'];
  if (!allowed.includes(status)) return res.status(400).json({ error: 'Bad status' });

  const db = readDb();
  const idx = db.tickets.findIndex(x => x.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found' });

  db.tickets[idx].status = status;
  writeDb(db);
  res.json({ ok: true, ticket: db.tickets[idx] });
});

// ---- Admin User Management Routes ----

// List all users (admin only)
app.get('/api/admin/users', adminRequired, (req, res) => {
  const { users } = readUsers();
  // Don't send password hashes to the client
  res.json(users.map(({ passwordHash, ...user }) => user));
});

// Update user status (admin only)
app.patch('/api/admin/users/:username', adminRequired, (req, res) => {
  const { status } = req.body;
  if (!['approved', 'rejected'].includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }
  const store = readUsers();
  const userIndex = store.users.findIndex(u => u.username.toLowerCase() === req.params.username.toLowerCase());

  if (userIndex === -1) {
    return res.status(404).json({ error: 'User not found' });
  }

  store.users[userIndex].status = status;
  writeUsers(store);

  const { passwordHash, ...updatedUser } = store.users[userIndex];
  res.json({ ok: true, user: updatedUser });
});

// Chatbot Intro (supports language)
app.get('/api/bot/intro', (req, res) => {
  const lang = req.query.lang || 'en';
  const intros = {
    en: ["Hello! I am the ITC Helpdesk Bot.", "How can I assist you today?"],
    hi: ["नमस्ते! मैं आईटीसी हेल्पडेस्क बॉट हूँ।", "मैं आज आपकी कैसे सहायता कर सकता हूँ?"]
  };
  res.json({ lines: intros[lang] || intros['en'] });
});

// Handle React/Vite routing, return all requests to React app
app.get('*', (req, res) => {
  const indexPath = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath, (err) => {
      if (err) {
        console.error('SendFile error:', err);
        if (!res.headersSent) res.status(500).send('Error loading frontend.');
      }
    });
  } else {
    res.status(404).send('Error: public/index.html not found. Please build the frontend and copy it to server/public.');
  }
});

app.listen(PORT, () => {
  console.log('Server starting... (Version with safety checks)');
  console.log(`API running on http://localhost:${PORT}`);
  console.log('Allowed Roles:', ALLOWED_ROLES);

  // DEBUG: Check if public folder exists and log contents
  const publicPath = path.join(__dirname, 'public');
  if (fs.existsSync(publicPath)) {
    console.log('Public folder found. Contents:', fs.readdirSync(publicPath));
  } else {
    console.log('WARNING: Public folder is MISSING at:', publicPath);
  }
});
