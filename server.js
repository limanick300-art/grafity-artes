require("dotenv").config();
process.env.TZ = process.env.TZ || "America/Sao_Paulo";
const express = require("express"), { Pool } = require("pg"), bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken"), cookieParser = require("cookie-parser"), crypto = require("crypto");

const SECRET = process.env.JWT_SECRET, DBURL = process.env.DATABASE_URL;
if (!SECRET || SECRET.length < 32) { console.error("Defina JWT_SECRET (32+ caracteres)."); process.exit(1); }
if (!DBURL) { console.error("Defina DATABASE_URL (endereço do banco Postgres)."); process.exit(1); }
const PROD = process.env.NODE_ENV === "production";
const pool = new Pool({ connectionString: DBURL, max: 5, ssl: /localhost|127\.0\.0\.1/.test(DBURL) ? false : { rejectUnauthorized: false } });
const q = (sql, args) => pool.query(sql, args).then(r => r.rows);

const PAY = ["Pix", "Cartão de crédito", "Cartão de débito", "Dinheiro"];
const HOURS = []; for (let h = 9; h < 19; h++) HOURS.push(String(h).padStart(2, "0") + ":00", String(h).padStart(2, "0") + ":30");
const DUMMY = bcrypt.hashSync("dummy-password", 12);
const ID = /^[a-z0-9]{1,20}$/, DATE = /^\d{4}-\d{2}-\d{2}$/;
const getWa = async () => (await q("SELECT v FROM settings WHERE k='wa'"))[0].v;

async function setup() {
  await q(`CREATE TABLE IF NOT EXISTS users(name TEXT NOT NULL, hash TEXT NOT NULL);
    CREATE UNIQUE INDEX IF NOT EXISTS uq_user ON users(lower(name));
    ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'dono';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS barber TEXT;
    CREATE TABLE IF NOT EXISTS barbers(id TEXT PRIMARY KEY, name TEXT NOT NULL, active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS services(id TEXT PRIMARY KEY, name TEXT NOT NULL, price DOUBLE PRECISION NOT NULL, min INTEGER DEFAULT 30, active INTEGER DEFAULT 1);
    CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
    CREATE TABLE IF NOT EXISTS bookings(id TEXT PRIMARY KEY, client TEXT, phone TEXT, service TEXT, barber TEXT, date TEXT, time TEXT,
      pay TEXT, price DOUBLE PRECISION, status TEXT DEFAULT 'agendado', sent INTEGER DEFAULT 0, created TIMESTAMPTZ DEFAULT now());
    CREATE UNIQUE INDEX IF NOT EXISTS uq_slot ON bookings(barber, date, time) WHERE status <> 'cancelado';`);
  if (!(await q("SELECT 1 FROM users LIMIT 1")).length) {
    const n = (process.env.ADMIN_NAME || "").trim(), p = process.env.ADMIN_PASS || "";
    if (!n || p.length < 8) { console.error("Defina ADMIN_NAME e ADMIN_PASS (8+ caracteres) para criar o primeiro login."); process.exit(1); }
    await q("INSERT INTO users VALUES($1,$2)", [n, bcrypt.hashSync(p, 12)]);
    await q("INSERT INTO barbers VALUES('b1','Barbeiro 1',1) ON CONFLICT DO NOTHING");
    for (const [i, nm, pr, m] of [["s1", "Corte", 40, 30], ["s2", "Barba", 30, 30], ["s3", "Corte + barba", 65, 60]])
      await q("INSERT INTO services VALUES($1,$2,$3,$4,1) ON CONFLICT DO NOTHING", [i, nm, pr, m]);
  }
  await q("INSERT INTO settings VALUES('wa',$1) ON CONFLICT DO NOTHING", [(process.env.SHOP_WHATSAPP || "5562900000000").replace(/\D/g, "")]);
}

const app = express();
app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.set({ "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; frame-ancestors 'none'" });
  next();
});
app.use(express.json({ limit: "50kb" }), cookieParser());
app.get("/", (req, res) => res.sendFile(__dirname + "/index.html"));
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
app.get("/health", (req, res) => res.send("ok"));

// ---- sessão ----
const fails = new Map();
const limited = ip => { const f = fails.get(ip); return f && f.n >= 8 && Date.now() - f.t < 15 * 60e3; };
const fail = ip => { const f = fails.get(ip); fails.set(ip, f && Date.now() - f.t < 15 * 60e3 ? { n: f.n + 1, t: f.t } : { n: 1, t: Date.now() }); };
const setSession = (res, data) => res.cookie("ga", jwt.sign(data, SECRET, { expiresIn: "12h" }),
  { httpOnly: true, sameSite: "lax", secure: PROD, maxAge: 12 * 3600e3 });
const readSession = req => { try { return jwt.verify(req.cookies.ga, SECRET); } catch (e) { return null; } };
const need = role => wrap(async (req, res, next) => {
  const s = readSession(req);
  if (!s || (role && s.role !== role)) return res.status(401).json({ error: "auth" });
  if (s.role === "admin") {
    const u = (await q("SELECT role,barber FROM users WHERE lower(name)=lower($1)", [s.name]))[0];
    if (!u) return res.status(401).json({ error: "auth" });
    s.owner = u.role !== "barbeiro"; s.barber = u.barber;
  }
  req.s = s; next();
});

app.post("/api/login", wrap(async (req, res) => {
  const name = String(req.body.name || "").trim().slice(0, 60), sec = String(req.body.secret || "").trim().slice(0, 100);
  if (!name || !sec) return res.status(400).json({ error: "dados" });
  if (limited(req.ip)) return res.status(429).json({ error: "limite" });
  const u = (await q("SELECT * FROM users WHERE lower(name)=lower($1)", [name]))[0];
  const ok = bcrypt.compareSync(sec, u ? u.hash : DUMMY);
  if (u && ok) { fails.delete(req.ip); setSession(res, { role: "admin", name: u.name }); return res.json({ role: "admin", name: u.name }); }
  if (u) { fail(req.ip); return res.status(401).json({ error: "login" }); }
  const phone = sec.replace(/\D/g, "");
  if (/[a-z]/i.test(sec) || phone.length < 10 || phone.length > 13) return res.status(401).json({ error: "login" });
  setSession(res, { role: "client", name, phone });
  res.json({ role: "client", name, phone });
}));
app.get("/api/me", need(), (req, res) => res.json(req.s));
app.post("/api/logout", (req, res) => { res.clearCookie("ga"); res.json({ ok: true }); });

// ---- público (logado) ----
const cfg = async () => ({ wa: await getWa(),
  barbers: await q("SELECT id,name FROM barbers WHERE active=1 ORDER BY name"),
  services: await q("SELECT id,name,price,min FROM services WHERE active=1 ORDER BY price") });
app.get("/api/config", wrap(async (req, res) => res.json(await cfg())));
app.get("/api/slots", need(), wrap(async (req, res) => {
  const { barber, date } = req.query;
  if (!ID.test(barber || "") || !DATE.test(date || "")) return res.status(400).json({ error: "dados" });
  res.json({ slots: await q("SELECT barber,date,time,status FROM bookings WHERE barber=$1 AND date=$2 AND status<>'cancelado'", [barber, date]) });
}));

async function notifyShop(b, svc, bar) {
  const { WHATSAPP_TOKEN: tk, WHATSAPP_PHONE_ID: pid, WHATSAPP_TEMPLATE: tpl } = process.env;
  if (!tk || !pid) return false;
  const when = b.date.split("-").reverse().join("/") + " às " + b.time;
  const body = tpl
    ? { type: "template", template: { name: tpl, language: { code: "pt_BR" }, components: [{ type: "body",
        parameters: [b.client + " (" + b.phone + ")", svc.name + " – R$ " + svc.price.toFixed(2), bar.name, when, b.pay].map(text => ({ type: "text", text })) }] } }
    : { type: "text", text: { body: `Novo agendamento\nCliente: ${b.client} (${b.phone})\nServiço: ${svc.name} – R$ ${svc.price.toFixed(2)}\nBarbeiro: ${bar.name}\nQuando: ${when}\nPagamento: ${b.pay}` } };
  try {
    const r = await fetch(`https://graph.facebook.com/v20.0/${pid}/messages`, { method: "POST",
      headers: { Authorization: "Bearer " + tk, "Content-Type": "application/json" },
      body: JSON.stringify({ messaging_product: "whatsapp", to: await getWa(), ...body }) });
    if (!r.ok) console.error("WhatsApp:", r.status, await r.text());
    return r.ok;
  } catch (e) { console.error("WhatsApp:", e.message); return false; }
}

app.post("/api/book", need(), wrap(async (req, res) => {
  const { service, barber, date, time, pay } = req.body || {};
  const svc = (await q("SELECT * FROM services WHERE id=$1 AND active=1", [String(service)]))[0];
  const bar = (await q("SELECT * FROM barbers WHERE id=$1 AND active=1", [String(barber)]))[0];
  const now = new Date(), today = now.toLocaleDateString("sv-SE");
  if (!svc || !bar || !DATE.test(date || "") || !HOURS.includes(time) || !PAY.includes(pay) || date < today ||
      (date === today && time <= now.toTimeString().slice(0, 5))) return res.status(400).json({ error: "dados" });
  const b = { id: crypto.randomUUID().slice(0, 8), client: req.s.name, phone: req.s.phone || "", service: svc.id, barber: bar.id, date, time, pay, price: svc.price };
  try {
    await q("INSERT INTO bookings(id,client,phone,service,barber,date,time,pay,price) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)",
      [b.id, b.client, b.phone, b.service, b.barber, b.date, b.time, b.pay, b.price]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "ocupado" });
    throw e;
  }
  const sent = await notifyShop(b, svc, bar);
  if (sent) await q("UPDATE bookings SET sent=1 WHERE id=$1", [b.id]);
  res.json({ booking: { ...b, status: "agendado", sent } });
}));

// ---- administrador ----
const admin = need("admin");
const ownerOnly = (req, res, next) => req.s.owner ? next() : res.status(403).json({ error: "dono" });
const staff = () => q("SELECT name,role,barber FROM users ORDER BY lower(name)");
app.get("/api/admin/state", admin, wrap(async (req, res) => res.json({ ...(await cfg()), owner: req.s.owner, barber: req.s.barber, admins: req.s.owner ? await staff() : [] })));
app.get("/api/admin/bookings", admin, wrap(async (req, res) => {
  const { date, barber } = req.query;
  if (!DATE.test(date || "")) return res.status(400).json({ error: "dados" });
  const args = [date]; let sql = `SELECT b.id,b.client,b.phone,b.service,b.barber,b.date,b.time,b.pay,b.price,b.status,b.sent,br.name AS "barberName", s.name AS "serviceName"
    FROM bookings b LEFT JOIN barbers br ON br.id=b.barber LEFT JOIN services s ON s.id=b.service WHERE b.date=$1`;
  const bf = req.s.owner ? barber : (req.s.barber || "none");
  if (bf) { sql += " AND b.barber=$2"; args.push(String(bf)); }
  res.json({ bookings: await q(sql + " ORDER BY b.time", args) });
}));
app.patch("/api/admin/bookings/:id", admin, wrap(async (req, res) => {
  const st = req.body && req.body.status;
  if (!["agendado", "concluído", "cancelado"].includes(st)) return res.status(400).json({ error: "dados" });
  try { await (req.s.owner ? q("UPDATE bookings SET status=$1 WHERE id=$2", [st, req.params.id]) : q("UPDATE bookings SET status=$1 WHERE id=$2 AND barber=$3", [st, req.params.id, req.s.barber || "none"])); } catch (e) { return res.status(409).json({ error: "ocupado" }); }
  res.json({ ok: true });
}));
app.put("/api/admin/config", admin, ownerOnly, wrap(async (req, res) => {
  const { wa, barbers, services } = req.body || {};
  const w = String(wa || "").replace(/\D/g, "");
  const okB = Array.isArray(barbers) && barbers.length >= 1 && barbers.length <= 50 && barbers.every(x => ID.test(x.id) && String(x.name || "").trim());
  const okS = Array.isArray(services) && services.length >= 1 && services.length <= 50 &&
    services.every(x => ID.test(x.id) && String(x.name || "").trim() && Number(x.price) >= 0 && Number(x.price) < 100000);
  if (w.length < 10 || w.length > 15 || !okB || !okS) return res.status(400).json({ error: "dados" });
  const c = await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("UPDATE settings SET v=$1 WHERE k='wa'", [w]);
    await c.query("UPDATE barbers SET active=0"); await c.query("UPDATE services SET active=0");
    for (const b of barbers) await c.query("INSERT INTO barbers VALUES($1,$2,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name, active=1", [b.id, String(b.name).trim().slice(0, 40)]);
    for (const s of services) await c.query("INSERT INTO services VALUES($1,$2,$3,$4,1) ON CONFLICT(id) DO UPDATE SET name=excluded.name, price=excluded.price, min=excluded.min, active=1",
      [s.id, String(s.name).trim().slice(0, 40), Number(s.price), Math.max(5, Math.min(240, parseInt(s.min) || 30))]);
    await c.query("COMMIT");
  } catch (e) { await c.query("ROLLBACK"); throw e; } finally { c.release(); }
  res.json({ ok: true });
}));
app.post("/api/admin/users", admin, ownerOnly, wrap(async (req, res) => {
  const name = String((req.body || {}).name || "").trim().slice(0, 40), pass = String((req.body || {}).pass || "");
  if (!name || (!/[a-z]/i.test(name) && name.replace(/\D/g, "").length >= 10)) return res.status(400).json({ error: "Nome de login inválido." });
  if (pass.length < 8) return res.status(400).json({ error: "A senha precisa ter 8 caracteres ou mais." });
  if ((await q("SELECT 1 FROM users WHERE lower(name)=lower($1)", [name])).length) return res.status(409).json({ error: "Esse login já existe." });
  const bid = String((req.body || {}).barber || "");
  if (bid && !(await q("SELECT 1 FROM barbers WHERE id=$1 AND active=1", [bid])).length) return res.status(400).json({ error: "Barbeiro inválido." });
  await q("INSERT INTO users(name,hash,role,barber) VALUES($1,$2,$3,$4)", [name, bcrypt.hashSync(pass, 12), bid ? "barbeiro" : "dono", bid || null]);
  res.json({ ok: true });
}));
app.delete("/api/admin/users/:name", admin, ownerOnly, wrap(async (req, res) => {
  if (req.params.name.toLowerCase() === req.s.name.toLowerCase()) return res.status(400).json({ error: "Você não pode remover o seu próprio login." });
  const t = (await q("SELECT role FROM users WHERE lower(name)=lower($1)", [req.params.name]))[0];
  if (t && t.role !== "barbeiro" && !(await q("SELECT 1 FROM users WHERE lower(name)<>lower($1) AND role<>'barbeiro'", [req.params.name])).length)
    return res.status(400).json({ error: "É preciso manter pelo menos um login de dono." });
  await q("DELETE FROM users WHERE lower(name)=lower($1)", [req.params.name]);
  res.json({ ok: true });
}));

app.use((err, req, res, next) => { console.error(err); res.status(500).json({ error: "erro" }); });
setup().then(() => app.listen(process.env.PORT || 3000, () => console.log("Grafity Artes rodando"))).catch(e => { console.error(e); process.exit(1); });
