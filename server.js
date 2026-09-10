require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = Number(process.env.PORT || 3000);
// Backward-compatible migration for project assignment.

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('ERROR: Set JWT_SECRET in .env to a random value of at least 32 characters.');
  process.exit(1);
}

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new Database(path.join(dataDir, 'pran.db'));

db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// Project assignment migration
try {
  const cols = db.prepare('PRAGMA table_info(projects)').all();

  if (!cols.some(c => c.name === 'assigned_to')) {
    db.exec('ALTER TABLE projects ADD COLUMN assigned_to INTEGER');
    console.log('Project assignment column added successfully.');
  }
} catch (e) {
  console.error('Project assignment migration failed:', e.message);
}

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  mobile TEXT DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','employee','customer')),
  department TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Active',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_code TEXT NOT NULL UNIQUE,
  full_name TEXT NOT NULL,
  company TEXT DEFAULT '',
  email TEXT NOT NULL,
  mobile TEXT NOT NULL,
  project_name TEXT NOT NULL,
  type TEXT NOT NULL,
  budget TEXT NOT NULL,
  timeline TEXT DEFAULT '',
  platform TEXT DEFAULT '',
  contact_preference TEXT DEFAULT '',
  description TEXT NOT NULL,
  features TEXT DEFAULT '',
  reference TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Idea Registered',
  progress INTEGER NOT NULL DEFAULT 10,
  owner_user_id INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT DEFAULT '',
  subject TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'New',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  project TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'Medium',
  deadline TEXT DEFAULT '',
  status TEXT NOT NULL DEFAULT 'Pending',
  assigned_to INTEGER,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(assigned_to) REFERENCES users(id) ON DELETE SET NULL
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  sender_role TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

function clean(v, max = 2000) { return String(v ?? '').trim().slice(0, max); }
function validEmail(v) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v); }
function publicUser(u) { return { id: u.id, name: u.name, email: u.email, mobile: u.mobile, role: u.role, department: u.department, status: u.status }; }
function signToken(u) { return jwt.sign({ sub: u.id, role: u.role }, JWT_SECRET, { expiresIn: '8h' }); }
function auth(req, res, next) {
  const token = req.cookies.pran_token;
  if (!token) return res.status(401).json({ error: 'Authentication required.' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.sub);
    if (!user || user.status !== 'Active') return res.status(401).json({ error: 'Account is not active.' });
    req.user = user;
    next();
  } catch { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
}
function roles(...allowed) { return (req, res, next) => allowed.includes(req.user.role) ? next() : res.status(403).json({ error: 'You do not have permission for this action.' }); }
function code() { return `CN-${new Date().getFullYear()}-${String(Date.now()).slice(-6)}`; }

function seedUser(email, password, name, role, department = '') {
  if (!email || !password || password.startsWith('CHANGE_THIS')) return;
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (!exists) {
    const hash = bcrypt.hashSync(password, 12);
    db.prepare('INSERT INTO users (name,email,password_hash,role,department) VALUES (?,?,?,?,?)')
      .run(name, email.toLowerCase(), hash, role, department);
    console.log(`Seeded ${role}: ${email}`);
  }
}
seedUser(process.env.ADMIN_EMAIL, process.env.ADMIN_PASSWORD, 'PRAN Admin', 'admin');
seedUser(process.env.EMPLOYEE_EMAIL, process.env.EMPLOYEE_PASSWORD, 'PRAN Employee', 'employee', 'Development');

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many login attempts. Please try again later.' } });
const writeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 80, standardHeaders: true, legacyHeaders: false });

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'PRAN backend' }));

app.post('/api/auth/signup', writeLimiter, async (req, res) => {
  const name = clean(req.body.name, 100), email = clean(req.body.email, 150).toLowerCase(), mobile = clean(req.body.mobile, 30), password = String(req.body.password || '');
  if (name.length < 2 || !validEmail(email) || mobile.length < 5 || password.length < 8) return res.status(400).json({ error: 'Please provide valid details. Password must be at least 8 characters.' });
  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) return res.status(409).json({ error: 'An account already exists with this email.' });
  const hash = await bcrypt.hash(password, 12);
  const result = db.prepare('INSERT INTO users (name,email,mobile,password_hash,role) VALUES (?,?,?,?,?)').run(name, email, mobile, hash, 'customer');
  res.status(201).json({ message: 'Account created successfully.', user: publicUser(db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid)) });
});

app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const email = clean(req.body.email, 150).toLowerCase(), password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user || !(await bcrypt.compare(password, user.password_hash)) || user.status !== 'Active') return res.status(401).json({ error: 'Invalid login credentials.' });
  const token = signToken(user);
  res.cookie('pran_token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 8 * 60 * 60 * 1000, path: '/' });
  res.json({ user: publicUser(user) });
});

app.post('/api/auth/logout', (req, res) => { res.clearCookie('pran_token', { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', path: '/' }); res.json({ ok: true }); });
app.get('/api/auth/me', auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post('/api/projects', writeLimiter, async (req, res) => {
  const b = req.body;
  const fullName = clean(b.fullName, 100), company = clean(b.company, 120), email = clean(b.email, 150).toLowerCase(), mobile = clean(b.mobile, 30), projectName = clean(b.projectName, 150), type = clean(b.type, 50), budget = clean(b.budget, 80), description = clean(b.description, 4000);
  if (!fullName || !validEmail(email) || !mobile || !projectName || !type || !budget || description.length < 5) return res.status(400).json({ error: 'Please complete all required project fields.' });
  let owner = null;
  if (req.cookies.pran_token) { try { const p = jwt.verify(req.cookies.pran_token, JWT_SECRET); owner = db.prepare('SELECT id FROM users WHERE id = ?').get(p.sub)?.id || null; } catch {} }
  const result = db.prepare(`INSERT INTO projects (project_code,full_name,company,email,mobile,project_name,type,budget,timeline,platform,contact_preference,description,features,reference,owner_user_id) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(code(), fullName, company, email, mobile, projectName, type, budget, clean(b.timeline, 80), clean(b.platform, 50), clean(b.contact, 80), description, clean(b.features, 4000), clean(b.reference, 500), owner);
  const project = db.prepare('SELECT * FROM projects WHERE id = ?').get(result.lastInsertRowid);
  res.status(201).json({ message: 'Project registered successfully.', project });
});

app.get('/api/projects', auth, (req, res) => {
  let rows;
  if (req.user.role === 'admin') {
    rows = db.prepare(`SELECT p.*, u.name AS assigned_name, u.email AS assigned_email
      FROM projects p LEFT JOIN users u ON u.id = p.assigned_to ORDER BY p.id DESC`).all();
  } else if (req.user.role === 'employee') {
    rows = db.prepare(`SELECT p.*, u.name AS assigned_name, u.email AS assigned_email
      FROM projects p LEFT JOIN users u ON u.id = p.assigned_to
      WHERE p.assigned_to = ? ORDER BY p.id DESC`).all(req.user.id);
  } else {
    rows = db.prepare('SELECT * FROM projects WHERE owner_user_id = ? OR email = ? ORDER BY id DESC').all(req.user.id, req.user.email);
  }
  res.json({ projects: rows });
});

app.patch('/api/projects/:id/assign', auth, roles('admin'), (req, res) => {
  const id = Number(req.params.id);
  const assignedTo = req.body.assignedTo === null || req.body.assignedTo === '' ? null : Number(req.body.assignedTo);
  if (!Number.isInteger(id)) return res.status(400).json({ error: 'Invalid project ID.' });
  if (assignedTo !== null && (!Number.isInteger(assignedTo) || !db.prepare("SELECT id FROM users WHERE id=? AND role='employee' AND status='Active'").get(assignedTo))) {
    return res.status(400).json({ error: 'Please select a valid active employee.' });
  }
  const result = db.prepare('UPDATE projects SET assigned_to=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(assignedTo, id);
  if (!result.changes) return res.status(404).json({ error: 'Project not found.' });
  const project = db.prepare(`SELECT p.*, u.name AS assigned_name, u.email AS assigned_email
    FROM projects p LEFT JOIN users u ON u.id=p.assigned_to WHERE p.id=?`).get(id);
  res.json({ project });
});
app.patch('/api/projects/:id', auth, roles('admin'), (req, res) => {
  const id = Number(req.params.id); const status = clean(req.body.status, 50); const progress = Math.max(0, Math.min(100, Number(req.body.progress)));
  if (!Number.isInteger(id) || !status || !Number.isFinite(progress)) return res.status(400).json({ error: 'Invalid project update.' });
  const result = db.prepare('UPDATE projects SET status=?, progress=?, updated_at=CURRENT_TIMESTAMP WHERE id=?').run(status, progress, id);
  if (!result.changes) return res.status(404).json({ error: 'Project not found.' });
  res.json({ project: db.prepare('SELECT * FROM projects WHERE id=?').get(id) });
});

app.post('/api/contacts', writeLimiter, (req, res) => {
  const name = clean(req.body.name, 100), email = clean(req.body.email, 150).toLowerCase(), phone = clean(req.body.phone, 30), subject = clean(req.body.subject, 150), message = clean(req.body.message, 4000);
  if (!name || !validEmail(email) || !subject || message.length < 5) return res.status(400).json({ error: 'Please complete the consultation form.' });
  db.prepare('INSERT INTO contacts (name,email,phone,subject,message) VALUES (?,?,?,?,?)').run(name,email,phone,subject,message);
  res.status(201).json({ message: 'Thanks! Your consultation request has been saved.' });
});
app.get('/api/contacts', auth, roles('admin'), (req, res) => res.json({ contacts: db.prepare('SELECT * FROM contacts ORDER BY id DESC').all() }));
app.patch('/api/contacts/:id', auth, roles('admin'), (req, res) => { const status=clean(req.body.status,30); const r=db.prepare('UPDATE contacts SET status=? WHERE id=?').run(status,Number(req.params.id)); if(!r.changes)return res.status(404).json({error:'Request not found.'}); res.json({ok:true}); });

app.get('/api/users', auth, roles('admin'), (req, res) => res.json({ users: db.prepare("SELECT id,name,email,mobile,role,department,status,created_at FROM users WHERE role != 'admin' ORDER BY id DESC").all() }));
app.post('/api/users/employee', auth, roles('admin'), async (req,res)=>{
  const name=clean(req.body.name,100),email=clean(req.body.email,150).toLowerCase(),mobile=clean(req.body.mobile,30),department=clean(req.body.department,100),password=String(req.body.password||'');
  if(!name||!validEmail(email)||password.length<8)return res.status(400).json({error:'Name, valid email and 8+ character password are required.'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(email))return res.status(409).json({error:'Email already exists.'});
  const hash=await bcrypt.hash(password,12);const r=db.prepare("INSERT INTO users (name,email,mobile,password_hash,role,department) VALUES (?,?,?,?, 'employee',?)").run(name,email,mobile,hash,department);res.status(201).json({user:publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid))});
});
app.patch('/api/users/:id/status', auth, roles('admin'), (req,res)=>{const status=clean(req.body.status,20);const r=db.prepare('UPDATE users SET status=? WHERE id=? AND role!=\'admin\'').run(status,Number(req.params.id));if(!r.changes)return res.status(404).json({error:'User not found.'});res.json({ok:true});});

app.get('/api/tasks', auth, (req,res)=>{ const tasks=req.user.role==='admin'?db.prepare('SELECT t.*,u.name assigned_name FROM tasks t LEFT JOIN users u ON u.id=t.assigned_to ORDER BY t.id DESC').all():db.prepare('SELECT t.*,u.name assigned_name FROM tasks t LEFT JOIN users u ON u.id=t.assigned_to WHERE t.assigned_to=? OR t.assigned_to IS NULL ORDER BY t.id DESC').all(req.user.id); res.json({tasks}); });
app.post('/api/tasks', auth, roles('admin'), (req,res)=>{const name=clean(req.body.name,200),project=clean(req.body.project,150),priority=clean(req.body.priority,20),deadline=clean(req.body.deadline,50),assignedTo=Number(req.body.assignedTo)||null;if(!name||!project)return res.status(400).json({error:'Task name and project are required.'});const r=db.prepare('INSERT INTO tasks (name,project,priority,deadline,assigned_to) VALUES (?,?,?,?,?)').run(name,project,priority||'Medium',deadline,assignedTo);res.status(201).json({task:db.prepare('SELECT * FROM tasks WHERE id=?').get(r.lastInsertRowid)});});
app.patch('/api/tasks/:id', auth, (req,res)=>{const id=Number(req.params.id),status=clean(req.body.status,30);const task=db.prepare('SELECT * FROM tasks WHERE id=?').get(id);if(!task)return res.status(404).json({error:'Task not found.'});if(req.user.role!=='admin'&&task.assigned_to!==req.user.id)return res.status(403).json({error:'Not allowed.'});db.prepare('UPDATE tasks SET status=? WHERE id=?').run(status,id);res.json({ok:true});});

app.get('/api/messages', auth, (req,res)=>{const messages=req.user.role==='admin'?db.prepare('SELECT m.*,u.name FROM messages m LEFT JOIN users u ON u.id=m.user_id ORDER BY m.id ASC').all():db.prepare('SELECT m.*,u.name FROM messages m LEFT JOIN users u ON u.id=m.user_id WHERE m.user_id=? ORDER BY m.id ASC').all(req.user.id);res.json({messages});});
app.post('/api/messages', auth, writeLimiter, (req,res)=>{const message=clean(req.body.message,2000);if(message.length<1)return res.status(400).json({error:'Message cannot be empty.'});db.prepare('INSERT INTO messages (user_id,sender_role,message) VALUES (?,?,?)').run(req.user.id,req.user.role,message);res.status(201).json({ok:true});});

app.get('/api/admin/summary', auth, roles('admin'), (req,res)=>{const customers=db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c;const employees=db.prepare("SELECT COUNT(*) c FROM users WHERE role='employee'").get().c;const projects=db.prepare('SELECT COUNT(*) c FROM projects').get().c;const pending=db.prepare("SELECT COUNT(*) c FROM projects WHERE status='Idea Registered'").get().c;const contacts=db.prepare("SELECT COUNT(*) c FROM contacts WHERE status='New'").get().c;res.json({customers,employees,projects,pending,contacts});});

app.use(express.static(path.join(__dirname, 'public')));
app.get(/^(?!\/api).*/, (req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'Server error.'});});
app.listen(PORT,()=>console.log(`PRAN server running at http://localhost:${PORT}`));
