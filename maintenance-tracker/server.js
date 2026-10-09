const express = require('express'), crypto = require('crypto'), path = require('path');
const { DatabaseSync } = require('node:sqlite');
const db = new DatabaseSync(path.join(__dirname, 'data.db'));
const SECRET = process.env.SECRET || 'dev-secret-change-me';
const PORT = process.env.PORT || 4000;

db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, password TEXT, role TEXT DEFAULT 'technician');
CREATE TABLE IF NOT EXISTS machines(id INTEGER PRIMARY KEY, name TEXT, type TEXT, location TEXT, last_service TEXT, interval_days INTEGER DEFAULT 90);
CREATE TABLE IF NOT EXISTS breakdowns(id INTEGER PRIMARY KEY, machine_id INTEGER, issue TEXT, downtime_hours REAL, cost REAL, date TEXT);
CREATE TABLE IF NOT EXISTS parts(id INTEGER PRIMARY KEY, name TEXT, qty INTEGER, min_qty INTEGER DEFAULT 5);
CREATE TABLE IF NOT EXISTS service_logs(id INTEGER PRIMARY KEY, machine_id INTEGER, date TEXT, type TEXT, description TEXT, cost REAL DEFAULT 0, technician TEXT, part_id INTEGER, part_qty INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS activity(id INTEGER PRIMARY KEY, at TEXT, user TEXT, action TEXT);`);
// migrations: safe for databases created by v1
const addCol = (t, c, def) => { if (!db.prepare(`PRAGMA table_info(${t})`).all().some(x => x.name === c)) db.exec(`ALTER TABLE ${t} ADD COLUMN ${c} ${def}`); };
[['serial_no', "TEXT DEFAULT ''"], ['manufacturer', "TEXT DEFAULT ''"], ['status', "TEXT DEFAULT 'Operational'"], ['hours_run', 'INTEGER DEFAULT 0'], ['notes', "TEXT DEFAULT ''"], ['image', "TEXT DEFAULT ''"]].forEach(([c, d]) => addCol('machines', c, d));
[['severity', "TEXT DEFAULT 'Medium'"], ['status', "TEXT DEFAULT 'Resolved'"], ['resolved_date', "TEXT DEFAULT ''"], ['reported_by', "TEXT DEFAULT ''"]].forEach(([c, d]) => addCol('breakdowns', c, d));
addCol('parts', 'unit_cost', 'REAL DEFAULT 0');

// ---------- helpers ----------
const hash = (p, salt = crypto.randomBytes(16).toString('hex')) => salt + ':' + crypto.scryptSync(p, salt, 32).toString('hex');
const check = (p, h) => { const [s, k] = h.split(':'); return crypto.timingSafeEqual(Buffer.from(hash(p, s).split(':')[1], 'hex'), Buffer.from(k, 'hex')); };
const mac = b => crypto.createHmac('sha256', SECRET).update(b).digest('base64url');
const sign = u => { const b = Buffer.from(JSON.stringify({ id: u.id, name: u.name, role: u.role, exp: Date.now() + 864e5 })).toString('base64url'); return b + '.' + mac(b); };
const auth = (req, res, next) => {
  const [b, s] = (req.headers.authorization || '').replace('Bearer ', '').split('.');
  if (!b || !s || s !== mac(b)) return res.status(401).json({ error: 'Login required' });
  const u = JSON.parse(Buffer.from(b, 'base64url'));
  if (u.exp < Date.now()) return res.status(401).json({ error: 'Session expired' });
  req.user = u; next();
};
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admin only' });
const today = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => new Date(new Date(d).getTime() + n * 864e5).toISOString().slice(0, 10);
const str = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const num = (v, name, min = 0) => { const n = Number(v === '' || v == null ? 0 : v); if (!Number.isFinite(n) || n < min) throw new Error(name + ' must be a number >= ' + min); return n; };
const need = (...v) => { if (v.some(x => x === undefined || x === null || String(x).trim() === '')) throw new Error('All required fields must be filled'); };
const wrap = f => (req, res) => { try { res.json(f(req)); } catch (e) { res.status(400).json({ error: e.message.includes('UNIQUE') ? 'Email already registered' : e.message }); } };
const log = (u, action) => db.prepare('INSERT INTO activity(at,user,action) VALUES(?,?,?)').run(new Date().toISOString().slice(0, 16).replace('T', ' '), u.name, action);
const STATUS = ['Operational', 'Under Maintenance', 'Breakdown', 'Retired'], SEV = ['Low', 'Medium', 'High', 'Critical'], STYPE = ['Preventive', 'Corrective', 'Inspection'];
const decorate = m => {
  const next = m.last_service ? addDays(m.last_service, m.interval_days) : today();
  const left = Math.ceil((new Date(next) - new Date(today())) / 864e5);
  const service = m.status === 'Retired' ? 'N/A' : left < 0 ? 'Overdue' : left <= 7 ? 'Due soon' : 'OK';
  return { ...m, next_service: next, days_left: left, service };
};
const getMachine = id => { const m = db.prepare('SELECT * FROM machines WHERE id=?').get(id); if (!m) throw new Error('Machine not found'); return m; };
// keep machine status in step with open breakdowns
const syncMachine = id => {
  const m = db.prepare('SELECT status FROM machines WHERE id=?').get(id); if (!m || m.status === 'Retired') return;
  const open = db.prepare("SELECT COUNT(*) c FROM breakdowns WHERE machine_id=? AND status='Open'").get(id).c;
  if (open > 0) db.prepare("UPDATE machines SET status='Breakdown' WHERE id=?").run(id);
  else if (m.status === 'Breakdown') db.prepare("UPDATE machines SET status='Operational' WHERE id=?").run(id);
};
const csvCell = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };
const toCsv = (head, rows) => head.join(',') + '\n' + rows.map(r => r.map(csvCell).join(',')).join('\n');
const fails = new Map(); // login rate limit: 6 failures / 10 min
const limited = k => { const a = (fails.get(k) || []).filter(t => Date.now() - t < 6e5); fails.set(k, a); return a.length >= 6; };

// ---------- seed demo data ----------
if (!db.prepare('SELECT id FROM users LIMIT 1').get()) {
  const u = db.prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)');
  u.run('Admin', 'admin@demo.com', hash('admin123'), 'admin'); u.run('Site Technician', 'tech@demo.com', hash('tech123'), 'technician');
  const m = db.prepare('INSERT INTO machines(name,type,location,serial_no,manufacturer,status,last_service,interval_days,hours_run,notes) VALUES(?,?,?,?,?,?,?,?,?,?)');
  m.run('Gantry Crane GC-01', 'Crane', 'Zojila Portal', 'GC-2023-001', 'Demo Cranes', 'Operational', addDays(today(), -100), 90, 4120, 'Hoist brake checked monthly');
  m.run('Diesel Generator 250kVA', 'Generator', 'Camp A', 'DG-250-17', 'Kirloskar', 'Operational', addDays(today(), -30), 90, 1850, '');
  m.run('Hydraulic Pump Motor', 'Motor', 'Workshop', 'HM-77', 'Bosch Rexroth', 'Operational', addDays(today(), -85), 90, 2760, '');
  m.run('Gearbox GB-12', 'Gearbox', 'Tunnel Face', 'GB-12-09', 'Demo Drives', 'Breakdown', addDays(today(), -40), 60, 3300, 'Oil leak under observation');
  m.run('Air Compressor AC-3', 'Compressor', 'Camp B', 'AC-3-55', 'Demo Air', 'Operational', addDays(today(), -10), 120, 900, '');
  m.run('Old Diesel Pump', 'Pump', 'Store', 'DP-01', 'Demo Pumps', 'Retired', addDays(today(), -400), 90, 7800, 'Retired 2026');
  const p = db.prepare('INSERT INTO parts(name,qty,min_qty,unit_cost) VALUES(?,?,?,?)');
  p.run('Hydraulic Oil (20L)', 3, 5, 4200); p.run('Oil Filter', 12, 4, 650); p.run('Gearbox Seal', 6, 2, 1800); p.run('Brake Pad Set', 2, 2, 5200); p.run('V-Belt', 9, 3, 450);
  const b = db.prepare('INSERT INTO breakdowns(machine_id,issue,severity,downtime_hours,cost,date,status,resolved_date,reported_by) VALUES(?,?,?,?,?,?,?,?,?)');
  b.run(1, 'Hoist brake slipping', 'High', 6, 8500, addDays(today(), -20), 'Resolved', addDays(today(), -20), 'Site Technician');
  b.run(3, 'Motor overheating', 'Medium', 4, 3200, addDays(today(), -52), 'Resolved', addDays(today(), -52), 'Site Technician');
  b.run(2, 'Fuel injector clogged', 'Medium', 5, 4100, addDays(today(), -85), 'Resolved', addDays(today(), -85), 'Admin');
  b.run(1, 'Limit switch failure', 'Low', 2, 900, addDays(today(), -118), 'Resolved', addDays(today(), -118), 'Admin');
  b.run(4, 'Gearbox oil leak', 'High', 0, 0, addDays(today(), -2), 'Open', '', 'Site Technician');
  const s = db.prepare('INSERT INTO service_logs(machine_id,date,type,description,cost,technician,part_id,part_qty) VALUES(?,?,?,?,?,?,?,?)');
  s.run(2, addDays(today(), -30), 'Preventive', 'Oil and filter change, belt check', 5400, 'Site Technician', 2, 2);
  s.run(5, addDays(today(), -10), 'Preventive', 'Filter cleaning, pressure test', 1800, 'Site Technician', null, 0);
  s.run(1, addDays(today(), -100), 'Preventive', 'Full inspection and greasing', 3500, 'Admin', null, 0);
  s.run(3, addDays(today(), -85), 'Corrective', 'Bearing replaced after overheating', 6000, 'Site Technician', null, 0);
}

const app = express();
app.use(express.json({ limit: '500kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- auth ----------
app.post('/api/register', wrap(req => {
  const { name, email, password } = req.body; need(name, email, password);
  if (!/^\S+@\S+\.\S+$/.test(email)) throw new Error('Enter a valid email');
  if (String(password).length < 6) throw new Error('Password must be 6+ characters');
  db.prepare('INSERT INTO users(name,email,password) VALUES(?,?,?)').run(str(name, 60), str(email, 100).toLowerCase(), hash(String(password)));
  return { ok: true };
}));
app.post('/api/login', (req, res) => {
  try {
    const { email, password } = req.body; need(email, password);
    const key = req.ip + String(email).toLowerCase();
    if (limited(key)) return res.status(429).json({ error: 'Too many attempts. Try again in 10 minutes.' });
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(email).toLowerCase());
    if (!u || !check(String(password), u.password)) { fails.get(key).push(Date.now()); return res.status(400).json({ error: 'Wrong email or password' }); }
    res.json({ token: sign(u), name: u.name, role: u.role });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ---------- machines ----------
const img = b => { const s = String(b.image || ''); if (!s) return ''; if (s.length > 300000 || !/^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(s)) throw new Error('Invalid or too large image (use JPG/PNG/WEBP)'); return s; };
const machineArgs = b => {
  need(b.name, b.type, b.interval_days);
  const status = b.status || 'Operational'; if (!STATUS.includes(status)) throw new Error('Invalid status');
  return [str(b.name, 80), str(b.type, 40), str(b.location, 80), str(b.serial_no, 40), str(b.manufacturer, 60), status, Math.max(1, Math.round(num(b.interval_days, 'Service interval', 1))), Math.round(num(b.hours_run, 'Hours run')), str(b.notes, 300), img(b)];
};
app.get('/api/machines', auth, wrap(req => {
  const { q = '', type = '', status = '' } = req.query, L = s => `%${String(s).slice(0, 60)}%`;
  return db.prepare('SELECT * FROM machines WHERE (name LIKE ? OR serial_no LIKE ? OR location LIKE ?) AND type LIKE ? AND status LIKE ? ORDER BY id').all(L(q), L(q), L(q), L(type), L(status)).map(decorate);
}));
app.get('/api/machines/:id', auth, wrap(req => ({
  machine: decorate(getMachine(req.params.id)),
  services: db.prepare('SELECT s.*, p.name part FROM service_logs s LEFT JOIN parts p ON p.id=s.part_id WHERE machine_id=? ORDER BY s.id DESC').all(req.params.id),
  breakdowns: db.prepare('SELECT * FROM breakdowns WHERE machine_id=? ORDER BY id DESC').all(req.params.id)
})));
app.post('/api/machines', auth, wrap(req => {
  const a = machineArgs(req.body);
  db.prepare('INSERT INTO machines(name,type,location,serial_no,manufacturer,status,interval_days,hours_run,notes,image,last_service) VALUES(?,?,?,?,?,?,?,?,?,?,?)').run(...a, today());
  log(req.user, 'Added machine ' + a[0]); return { ok: true };
}));
app.put('/api/machines/:id', auth, wrap(req => {
  const m = getMachine(req.params.id), a = machineArgs(req.body);
  db.prepare('UPDATE machines SET name=?,type=?,location=?,serial_no=?,manufacturer=?,status=?,interval_days=?,hours_run=?,notes=?,image=? WHERE id=?').run(...a, m.id);
  syncMachine(m.id); log(req.user, 'Edited machine ' + a[0]); return { ok: true };
}));
app.delete('/api/machines/:id', auth, admin, wrap(req => {
  const m = getMachine(req.params.id);
  db.prepare('DELETE FROM service_logs WHERE machine_id=?').run(m.id); db.prepare('DELETE FROM breakdowns WHERE machine_id=?').run(m.id);
  db.prepare('DELETE FROM machines WHERE id=?').run(m.id); log(req.user, 'Deleted machine ' + m.name); return { ok: true };
}));
app.post('/api/machines/:id/service', auth, wrap(req => {
  const m = getMachine(req.params.id), b = req.body;
  if (m.status === 'Retired') throw new Error('Machine is retired');
  if (!STYPE.includes(b.type)) throw new Error('Choose a service type');
  const cost = num(b.cost, 'Cost'), partId = b.part_id ? +b.part_id : null, qty = partId ? Math.round(num(b.part_qty, 'Part quantity', 1)) : 0;
  if (partId) { const p = db.prepare('SELECT * FROM parts WHERE id=?').get(partId); if (!p) throw new Error('Part not found'); if (p.qty < qty) throw new Error('Only ' + p.qty + ' x ' + p.name + ' in stock'); db.prepare('UPDATE parts SET qty=qty-? WHERE id=?').run(qty, partId); }
  db.prepare('INSERT INTO service_logs(machine_id,date,type,description,cost,technician,part_id,part_qty) VALUES(?,?,?,?,?,?,?,?)').run(m.id, today(), b.type, str(b.description, 400), cost, str(b.technician, 60) || req.user.name, partId, qty);
  db.prepare('UPDATE machines SET last_service=?, hours_run=?, status=? WHERE id=?').run(today(), b.hours_run ? Math.round(num(b.hours_run, 'Hours run')) : m.hours_run, m.status === 'Under Maintenance' ? 'Operational' : m.status, m.id);
  log(req.user, b.type + ' service on ' + m.name); return { ok: true };
}));

// ---------- breakdowns ----------
app.get('/api/breakdowns', auth, wrap(req => {
  const { status = '' } = req.query;
  return db.prepare('SELECT b.*, m.name machine FROM breakdowns b LEFT JOIN machines m ON m.id=b.machine_id WHERE b.status LIKE ? ORDER BY (b.status=\'Open\') DESC, b.id DESC').all(`%${String(status).slice(0, 10)}%`);
}));
app.post('/api/breakdowns', auth, wrap(req => {
  const b = req.body; need(b.machine_id, b.issue);
  const m = getMachine(b.machine_id); if (m.status === 'Retired') throw new Error('Machine is retired');
  const sev = b.severity || 'Medium'; if (!SEV.includes(sev)) throw new Error('Invalid severity');
  db.prepare("INSERT INTO breakdowns(machine_id,issue,severity,downtime_hours,cost,date,status,reported_by) VALUES(?,?,?,?,?,?,'Open',?)").run(m.id, str(b.issue, 300), sev, num(b.downtime_hours, 'Downtime'), num(b.cost, 'Cost'), today(), req.user.name);
  syncMachine(m.id); log(req.user, 'Breakdown reported: ' + m.name + ' (' + sev + ')'); return { ok: true };
}));
app.put('/api/breakdowns/:id/resolve', auth, wrap(req => {
  const b = db.prepare('SELECT * FROM breakdowns WHERE id=?').get(req.params.id); if (!b) throw new Error('Not found');
  if (b.status === 'Resolved') throw new Error('Already resolved');
  db.prepare("UPDATE breakdowns SET status='Resolved', resolved_date=?, downtime_hours=?, cost=? WHERE id=?").run(today(), num(req.body.downtime_hours ?? b.downtime_hours, 'Downtime'), num(req.body.cost ?? b.cost, 'Cost'), b.id);
  syncMachine(b.machine_id); log(req.user, 'Breakdown resolved #' + b.id); return { ok: true };
}));
app.delete('/api/breakdowns/:id', auth, admin, wrap(req => {
  const b = db.prepare('SELECT * FROM breakdowns WHERE id=?').get(req.params.id); if (!b) throw new Error('Not found');
  db.prepare('DELETE FROM breakdowns WHERE id=?').run(b.id); syncMachine(b.machine_id); log(req.user, 'Deleted breakdown #' + b.id); return { ok: true };
}));

// ---------- parts ----------
app.get('/api/parts', auth, wrap(() => db.prepare('SELECT * FROM parts ORDER BY name').all()));
app.post('/api/parts', auth, wrap(req => {
  const b = req.body; need(b.name, b.qty, b.min_qty);
  db.prepare('INSERT INTO parts(name,qty,min_qty,unit_cost) VALUES(?,?,?,?)').run(str(b.name, 80), Math.round(num(b.qty, 'Quantity')), Math.round(num(b.min_qty, 'Minimum')), num(b.unit_cost, 'Unit cost'));
  log(req.user, 'Added part ' + str(b.name, 80)); return { ok: true };
}));
app.put('/api/parts/:id', auth, wrap(req => { db.prepare('UPDATE parts SET qty=MAX(0,qty+?) WHERE id=?').run(Math.round(Number(req.body.delta) || 0), req.params.id); return { ok: true }; }));
app.delete('/api/parts/:id', auth, admin, wrap(req => { db.prepare('DELETE FROM parts WHERE id=?').run(req.params.id); log(req.user, 'Deleted part #' + req.params.id); return { ok: true }; }));

// ---------- team (admin) ----------
app.get('/api/users', auth, admin, wrap(() => db.prepare('SELECT id,name,email,role FROM users ORDER BY id').all()));
app.put('/api/users/:id/role', auth, admin, wrap(req => {
  if (!['admin', 'technician'].includes(req.body.role)) throw new Error('Invalid role');
  if (+req.params.id === req.user.id) throw new Error('You cannot change your own role');
  db.prepare('UPDATE users SET role=? WHERE id=?').run(req.body.role, req.params.id); log(req.user, 'Changed role of user #' + req.params.id + ' to ' + req.body.role); return { ok: true };
}));
app.get('/api/activity', auth, admin, wrap(() => db.prepare('SELECT * FROM activity ORDER BY id DESC LIMIT 25').all()));

// ---------- dashboard ----------
app.get('/api/dashboard', auth, wrap(() => {
  const ms = db.prepare('SELECT * FROM machines').all().map(decorate), active = ms.filter(m => m.status !== 'Retired');
  const one = (sql) => db.prepare(sql).get();
  const bd = one("SELECT COUNT(*) c, COALESCE(SUM(cost),0) cost, COALESCE(SUM(downtime_hours),0) d FROM breakdowns");
  const mttr = one("SELECT AVG(downtime_hours) a FROM breakdowns WHERE status='Resolved' AND downtime_hours>0").a;
  const svcCost = one('SELECT COALESCE(SUM(cost),0) c FROM service_logs').c;
  const months = []; for (let i = 5; i >= 0; i--) { const d = new Date(); d.setUTCDate(1); d.setUTCMonth(d.getUTCMonth() - i); months.push(d.toISOString().slice(0, 7)); }
  const bm = Object.fromEntries(db.prepare('SELECT substr(date,1,7) m, COUNT(*) c, SUM(cost) cost FROM breakdowns GROUP BY m').all().map(r => [r.m, r]));
  const sm = Object.fromEntries(db.prepare('SELECT substr(date,1,7) m, SUM(cost) cost FROM service_logs GROUP BY m').all().map(r => [r.m, r]));
  return {
    machines: active.length,
    by_status: STATUS.map(s => ({ status: s, count: ms.filter(m => m.status === s).length })),
    overdue: active.filter(m => m.service === 'Overdue').length, due_soon: active.filter(m => m.service === 'Due soon').length,
    open_breakdowns: one("SELECT COUNT(*) c FROM breakdowns WHERE status='Open'").c,
    breakdowns: bd.c, total_downtime: bd.d, mttr: mttr ? Math.round(mttr * 10) / 10 : 0,
    total_cost: bd.cost + svcCost, breakdown_cost: bd.cost, service_cost: svcCost,
    availability: active.length ? Math.round(active.filter(m => m.status === 'Operational').length / active.length * 100) : 100,
    alerts: active.filter(m => m.service !== 'OK').sort((a, b) => a.days_left - b.days_left),
    low_stock: db.prepare('SELECT * FROM parts WHERE qty<=min_qty ORDER BY qty').all(),
    top_downtime: db.prepare('SELECT m.name, SUM(b.downtime_hours) hours, COUNT(*) breakdowns FROM breakdowns b JOIN machines m ON m.id=b.machine_id GROUP BY m.id ORDER BY hours DESC, breakdowns DESC LIMIT 5').all(),
    monthly: months.map(m => ({ month: m, breakdowns: bm[m]?.c || 0, breakdown_cost: bm[m]?.cost || 0, service_cost: sm[m]?.cost || 0 }))
  };
}));

// ---------- export ----------
app.get('/api/export/:what', auth, (req, res) => {
  const w = req.params.what; let csv;
  if (w === 'machines') csv = toCsv(['Name', 'Type', 'Location', 'Serial', 'Status', 'Hours run', 'Last service', 'Next service', 'Service state'], db.prepare('SELECT * FROM machines').all().map(decorate).map(m => [m.name, m.type, m.location, m.serial_no, m.status, m.hours_run, m.last_service, m.next_service, m.service]));
  else if (w === 'breakdowns') csv = toCsv(['Date', 'Machine', 'Issue', 'Severity', 'Status', 'Downtime (h)', 'Cost', 'Resolved on'], db.prepare('SELECT b.*, m.name machine FROM breakdowns b LEFT JOIN machines m ON m.id=b.machine_id ORDER BY b.id DESC').all().map(b => [b.date, b.machine, b.issue, b.severity, b.status, b.downtime_hours, b.cost, b.resolved_date]));
  else if (w === 'services') csv = toCsv(['Date', 'Machine', 'Type', 'Description', 'Cost', 'Technician'], db.prepare('SELECT s.*, m.name machine FROM service_logs s LEFT JOIN machines m ON m.id=s.machine_id ORDER BY s.id DESC').all().map(s => [s.date, s.machine, s.type, s.description, s.cost, s.technician]));
  else return res.status(404).json({ error: 'Unknown export' });
  res.type('text/csv').send(csv);
});

app.listen(PORT, () => console.log('Running on http://localhost:' + PORT + '  (admin@demo.com / admin123)'));
