require('dotenv').config();
const express = require('express'), helmet = require('helmet'), cookieParser = require('cookie-parser'), rateLimit = require('express-rate-limit');
const { Pool } = require('pg'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), crypto = require('crypto'), path = require('path');

const { DATABASE_URL, JWT_SECRET, APP_ORIGIN, PORT = 3000, NODE_ENV } = process.env;
if (!DATABASE_URL || !JWT_SECRET || JWT_SECRET.length < 32) { console.error('.env ফাইলে DATABASE_URL এবং কমপক্ষে ৩২ অক্ষরের JWT_SECRET দিন।'); process.exit(1); }
const pool = new Pool({ connectionString: DATABASE_URL });

// ব্যবসার নিয়ম: এগুলো শুধু সার্ভারে ঠিক হয়, ব্রাউজার বদলাতে পারে না
const DAILY_LIMIT = 500, MIN_SECONDS = 10, REWARD_PAISA = 50, MIN_WITHDRAW_PAISA = 50000;
const DAY = "(now() AT TIME ZONE 'Asia/Dhaka')::date";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12);

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
  fontSrc: ['https://fonts.gstatic.com'], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], upgradeInsecureRequests: null } } }));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use('/api', rateLimit({ windowMs: 60000, limit: 120, message: { message: 'অনেক বেশি অনুরোধ। কিছুক্ষণ পরে চেষ্টা করুন।' } }));
const authLimit = rateLimit({ windowMs: 15 * 60000, limit: 15, message: { message: 'অনেকবার চেষ্টা হয়েছে। ১৫ মিনিট পরে আবার চেষ্টা করুন।' } });
// CSRF সুরক্ষা: POST অনুরোধ শুধু নিজের সাইট থেকেই গ্রহণ করা হবে
app.use('/api', (req, res, next) => {
  if (req.method !== 'GET' && APP_ORIGIN && req.headers.origin !== APP_ORIGIN) return res.status(403).json({ message: 'অনুমোদিত নয়।' });
  next();
});

const fail = (status, message) => { throw Object.assign(new Error(message), { status }); };
const h = fn => (req, res) => fn(req, res).catch(e => {
  if (e.status) return res.status(e.status).json({ message: e.message });
  if (e.code === '23505') return res.status(409).json({ message: 'এই তথ্য আগেই জমা বা ব্যবহার করা হয়েছে।' });
  console.error(e); res.status(500).json({ message: 'সার্ভারে সমস্যা হয়েছে। আবার চেষ্টা করুন।' });
});
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query('BEGIN'); const r = await fn(c); await c.query('COMMIT'); return r; }
  catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}
const lockWallet = (c, uid) => c.query('SELECT 1 FROM wallets WHERE user_id=$1 FOR UPDATE', [uid]);
// ২৪ ঘণ্টার চক্র: দিনের প্রথম বিজ্ঞাপন কমপ্লিট হলে চক্র শুরু; ২৪ ঘণ্টা পর গণনা নতুন করে ০ থেকে শুরু
async function cycle(c, uid) {
  const w = (await c.query(`SELECT cycle_started_at, (cycle_started_at IS NOT NULL AND cycle_started_at > now() - interval '24 hours') AS active FROM wallets WHERE user_id=$1`, [uid])).rows[0];
  if (!w || !w.active) return { done: 0, resets_at: null };
  const n = (await c.query('SELECT count(*)::int n FROM ad_views WHERE user_id=$1 AND completed_at >= $2', [uid, w.cycle_started_at])).rows[0].n;
  return { done: n, resets_at: new Date(new Date(w.cycle_started_at).getTime() + 864e5) };
}
const taka = p => Number(p) / 100;

// ---------- পরিচয় ও অনুমতি ----------
const setCookie = (res, u) => res.cookie('t', jwt.sign({ sub: u.id }, JWT_SECRET, { expiresIn: '7d' }), { httpOnly: true, sameSite: 'strict', secure: NODE_ENV === 'production', maxAge: 7 * 864e5 });
async function auth(req, res, next) {
  try {
    const p = jwt.verify(req.cookies.t, JWT_SECRET);
    const r = (await pool.query('SELECT id, role FROM users WHERE id=$1 AND active', [p.sub])).rows[0];
    if (!r) throw 0; req.user = r; next();   // ভূমিকা (role) প্রতিবার ডাটাবেস থেকে আসে, টোকেন থেকে নয়
  } catch { res.status(401).json({ message: 'আবার লগইন করুন।' }); }
}
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ message: 'শুধু অ্যাডমিনের জন্য।' });

app.post('/api/auth/register', authLimit, h(async (req, res) => {
  const id = String(req.body.identifier || '').trim().toLowerCase(), pw = String(req.body.password || '');
  if (!(/^01[3-9]\d{8}$/.test(id) || /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(id))) fail(400, 'সঠিক মোবাইল নম্বর বা ইমেইল দিন।');
  if (pw.length < 8 || pw.length > 72) fail(400, 'পাসওয়ার্ড ৮ থেকে ৭২ অক্ষরের মধ্যে হতে হবে।');
  const hash = await bcrypt.hash(pw, 12);
  const u = await tx(async c => {
    const r = await c.query('INSERT INTO users(identifier,password_hash,signup_ip) VALUES($1,$2,$3) ON CONFLICT DO NOTHING RETURNING id', [id, hash, req.ip]);
    if (!r.rows[0]) fail(409, 'এই অ্যাকাউন্ট আগে থেকেই আছে।');
    await c.query('INSERT INTO wallets(user_id) VALUES($1)', [r.rows[0].id]); return r.rows[0];
  });
  setCookie(res, u); res.json({ ok: true });
}));
app.post('/api/auth/login', authLimit, h(async (req, res) => {
  const id = String(req.body.identifier || '').trim().toLowerCase(), pw = String(req.body.password || '');
  const u = (await pool.query('SELECT id, password_hash, active FROM users WHERE identifier=$1', [id])).rows[0];
  const ok = await bcrypt.compare(pw, u ? u.password_hash : DUMMY_HASH);
  if (!u || !ok || !u.active) fail(401, 'মোবাইল/ইমেইল বা পাসওয়ার্ড ভুল।');
  setCookie(res, u); res.json({ ok: true });
}));
app.post('/api/auth/logout', (req, res) => { res.clearCookie('t'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json(req.user));

// ---------- ওয়ালেট ----------
app.get('/api/wallet', auth, h(async (req, res) => {
  const w = (await pool.query('SELECT * FROM wallets WHERE user_id=$1', [req.user.id])).rows[0];
  const wd = (await pool.query(`SELECT txn_id, 'withdrawal' AS type, amount_paisa, method, status, reference, created_at FROM withdrawals WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`, [req.user.id])).rows;
  const ad = (await pool.query(`SELECT 'ADS-'||to_char(day,'YYYY-MM-DD') AS txn_id, 'ad_earning' AS type, SUM(reward_paisa) AS amount_paisa, NULL AS method, NULL AS status, NULL AS reference, MAX(completed_at) AS created_at FROM ad_views WHERE user_id=$1 AND completed_at IS NOT NULL GROUP BY day ORDER BY day DESC LIMIT 30`, [req.user.id])).rows;
  const tx2 = [...wd, ...ad].map(r => ({ txn_id: r.txn_id, type: r.type, amount: taka(r.amount_paisa), method: r.method, status: r.status, reference: r.reference, created_at: r.created_at }))
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
  res.json({ verified: taka(w.verified_paisa), available: taka(w.available_paisa), pending: taka(w.pending_paisa), withdrawn: taka(w.withdrawn_paisa), tx: tx2 });
}));

// ---------- বিজ্ঞাপন দেখা ----------
app.get('/api/ads/today', auth, h(async (req, res) => {
  const cy = await cycle(pool, req.user.id);
  const r = (await pool.query(`SELECT (SELECT COALESCE(SUM(amount_paisa),0) FROM advertiser_payments) AS paid, (SELECT COALESCE(SUM(reward_paisa),0) FROM ad_views WHERE completed_at IS NOT NULL) AS owed`)).rows[0];
  // বিজ্ঞাপনদাতার নিশ্চিত পেমেন্ট দিয়ে ব্যবহারকারীদের দেওয়া মোট আয় কতটা ঢাকা পড়েছে, সেই শতাংশ
  const pct = Number(r.owed) === 0 ? null : Math.min(100, Math.floor(Number(r.paid) * 100 / Number(r.owed)));
  res.json({ done: cy.done, resets_at: cy.resets_at, limit: DAILY_LIMIT, reward: taka(REWARD_PAISA), advertiser_paid_percent: pct });
}));
app.post('/api/ads/start', auth, h(async (req, res) => {
  const v = await tx(async c => {
    await lockWallet(c, req.user.id);
    if ((await cycle(c, req.user.id)).done >= DAILY_LIMIT) fail(429, 'আপনার ৫০০টি বিজ্ঞাপনের সীমা শেষ। ২৪ ঘণ্টা পূর্ণ হলে আবার নতুন করে শুরু করতে পারবেন।');
    // একসাথে একটির বেশি চলমান বিজ্ঞাপন নেই, তাই ১০ সেকেন্ডে একটির বেশি কমপ্লিট করা যায় না
    let o = (await c.query(`SELECT v.id, a.title, a.link FROM ad_views v JOIN ads a ON a.id=v.ad_id WHERE v.user_id=$1 AND v.completed_at IS NULL AND v.started_at > now() - interval '10 minutes' ORDER BY v.started_at DESC LIMIT 1`, [req.user.id])).rows[0];
    if (o) return o;
    const a = (await c.query('SELECT id, title, link FROM ads WHERE active ORDER BY random() LIMIT 1')).rows[0];
    if (!a) fail(404, 'এই মুহূর্তে কোনো বিজ্ঞাপন নেই।');
    const n = (await c.query(`INSERT INTO ad_views(user_id,ad_id,reward_paisa,day,ip) VALUES($1,$2,$3,${DAY},$4) RETURNING id`, [req.user.id, a.id, REWARD_PAISA, req.ip])).rows[0];
    return { id: n.id, title: a.title, link: a.link };
  });
  res.json({ token: v.id, title: v.title, link: v.link, seconds: MIN_SECONDS });
}));
app.post('/api/ads/complete', auth, h(async (req, res) => {
  const t = String(req.body.token || ''); if (!UUID.test(t)) fail(400, 'ভুল অনুরোধ।');
  await tx(async c => {
    await lockWallet(c, req.user.id);
    const v = (await c.query('SELECT id, reward_paisa, completed_at, extract(epoch from now() - started_at) AS el FROM ad_views WHERE id=$1 AND user_id=$2 FOR UPDATE', [t, req.user.id])).rows[0];
    if (!v) fail(404, 'বিজ্ঞাপনটি পাওয়া যায়নি।');
    if (v.completed_at) fail(409, 'এই বিজ্ঞাপনের আয় আগেই যোগ হয়েছে।');
    if (Number(v.el) < MIN_SECONDS - 0.5) fail(400, '১০ সেকেন্ড পূর্ণ হয়নি। আবার চেষ্টা করুন।');
    if ((await cycle(c, req.user.id)).done >= DAILY_LIMIT) fail(429, '৫০০টির সীমা শেষ। ২৪ ঘণ্টা পূর্ণ হলে আবার শুরু করুন।');
    await c.query('UPDATE ad_views SET completed_at=now() WHERE id=$1', [v.id]);
    await c.query(`UPDATE wallets SET verified_paisa=verified_paisa+$2, available_paisa=available_paisa+$2, cycle_started_at = CASE WHEN cycle_started_at IS NULL OR cycle_started_at <= now() - interval '24 hours' THEN now() ELSE cycle_started_at END WHERE user_id=$1`, [req.user.id, v.reward_paisa]);
    await c.query(`INSERT INTO ledger(user_id,kind,amount_paisa,ref) VALUES($1,'ad_earning',$2,$3)`, [req.user.id, v.reward_paisa, v.id]);
  });
  res.json({ ok: true });
}));

// ---------- উত্তোলনের আবেদন ----------
app.post('/api/withdrawals', auth, h(async (req, res) => {
  const b = req.body, amount = Number(b.amount), method = b.method, num = String(b.wallet_number || '').trim();
  const name = String(b.holder_name || '').trim().slice(0, 80), key = String(b.idempotency_key || '');
  if (!Number.isInteger(amount) || amount * 100 < MIN_WITHDRAW_PAISA) fail(400, 'সর্বনিম্ন উত্তোলন ৳৫০০।');
  if (!['bkash', 'nagad'].includes(method)) fail(400, 'বিকাশ বা নগদ বেছে নিন।');
  if (!/^01[3-9]\d{8}$/.test(num)) fail(400, 'সঠিক ১১ ডিজিটের নম্বর দিন।');
  if (!/^[\w-]{8,64}$/.test(key)) fail(400, 'ভুল অনুরোধ। পেজ রিফ্রেশ করুন।');
  const paisa = amount * 100;
  const txn = await tx(async c => {
    await lockWallet(c, req.user.id);                         // একই ব্যবহারকারীর অনুরোধগুলো একটার পর একটা চলে
    const same = (await c.query('SELECT txn_id FROM withdrawals WHERE user_id=$1 AND idempotency_key=$2', [req.user.id, key])).rows[0];
    if (same) return same.txn_id;                             // একই আবেদন দ্বিতীয়বার এলে নতুন কিছু তৈরি হয় না
    const open = (await c.query(`SELECT 1 FROM withdrawals WHERE user_id=$1 AND status IN ('pending','approved')`, [req.user.id])).rows[0];
    if (open) fail(409, 'আপনার আগের একটি আবেদন এখনো শেষ হয়নি। সেটি শেষ হওয়ার পর নতুন আবেদন করুন।');
    const w = (await c.query('SELECT available_paisa FROM wallets WHERE user_id=$1', [req.user.id])).rows[0];
    if (Number(w.available_paisa) < paisa) fail(400, 'আপনার উত্তোলনযোগ্য ব্যালেন্স ' + taka(w.available_paisa) + ' টাকা। এর বেশি উত্তোলন করা যাবে না।');
    const txnId = 'PW-' + crypto.randomBytes(5).toString('hex').toUpperCase();
    await c.query('UPDATE wallets SET available_paisa=available_paisa-$2, pending_paisa=pending_paisa+$2 WHERE user_id=$1', [req.user.id, paisa]);
    await c.query('INSERT INTO withdrawals(txn_id,user_id,amount_paisa,method,wallet_number,holder_name,idempotency_key) VALUES($1,$2,$3,$4,$5,$6,$7)', [txnId, req.user.id, paisa, method, num, name || null, key]);
    await c.query(`INSERT INTO ledger(user_id,kind,amount_paisa,ref) VALUES($1,'withdraw_reserve',$2,$3)`, [req.user.id, paisa, txnId]);
    return txnId;
  });
  res.json({ txn_id: txn });
}));

// ---------- অ্যাডমিন ----------
app.get('/api/admin/withdrawals', auth, admin, h(async (req, res) => {
  const st = ['pending', 'approved', 'paid', 'rejected'].includes(req.query.status) ? req.query.status : null;
  const { rows } = await pool.query(`SELECT id, txn_id, user_id AS publisher_id, amount_paisa, method, wallet_number, holder_name, status, reference, admin_note, created_at FROM withdrawals WHERE ($1::text IS NULL OR status=$1) ORDER BY created_at DESC LIMIT 300`, [st]);
  res.json({ items: rows.map(r => ({ ...r, amount: taka(r.amount_paisa) })) });
}));
async function move(req, res, to) {
  if (!UUID.test(req.params.id)) fail(400, 'ভুল অনুরোধ।');
  const note = String(req.body.note || '').trim().slice(0, 300), ref = String(req.body.ref || '').trim().slice(0, 60);
  if (to === 'paid' && !ref) fail(400, 'পেমেন্ট সম্পন্ন করতে ট্রানজেকশন রেফারেন্স দিন।');
  await tx(async c => {
    const w = (await c.query('SELECT * FROM withdrawals WHERE id=$1 FOR UPDATE', [req.params.id])).rows[0];
    if (!w) fail(404, 'আবেদন পাওয়া যায়নি।');
    const from = { approved: ['pending'], rejected: ['pending', 'approved'], paid: ['approved'] }[to];
    if (!from.includes(w.status)) fail(409, 'আবেদনের অবস্থা বদলে গেছে। পেজ রিফ্রেশ করুন।');
    await lockWallet(c, w.user_id);
    if (to === 'rejected') { // সংরক্ষিত টাকা ব্যালেন্সে ফেরত
      await c.query('UPDATE wallets SET pending_paisa=pending_paisa-$2, available_paisa=available_paisa+$2 WHERE user_id=$1', [w.user_id, w.amount_paisa]);
      await c.query(`INSERT INTO ledger(user_id,kind,amount_paisa,ref) VALUES($1,'withdraw_release',$2,$3)`, [w.user_id, w.amount_paisa, w.txn_id]);
    }
    if (to === 'paid') {     // বাস্তবে টাকা পাঠানোর পর: অপেক্ষমাণ থেকে মোট উত্তোলনে
      await c.query('UPDATE wallets SET pending_paisa=pending_paisa-$2, withdrawn_paisa=withdrawn_paisa+$2 WHERE user_id=$1', [w.user_id, w.amount_paisa]);
      await c.query(`INSERT INTO ledger(user_id,kind,amount_paisa,ref) VALUES($1,'withdraw_paid',$2,$3)`, [w.user_id, w.amount_paisa, w.txn_id]);
    }
    await c.query(`UPDATE withdrawals SET status=$2, admin_note=COALESCE(NULLIF($3,''),admin_note), reference=COALESCE(NULLIF($4,''),reference), processed_by=$5, updated_at=now() WHERE id=$1`, [w.id, to, note, ref, req.user.id]);
  });
  res.json({ ok: true });
}
app.post('/api/admin/withdrawals/:id/approve', auth, admin, h((q, s) => move(q, s, 'approved')));
app.post('/api/admin/withdrawals/:id/reject', auth, admin, h((q, s) => move(q, s, 'rejected')));
app.post('/api/admin/withdrawals/:id/paid', auth, admin, h((q, s) => move(q, s, 'paid')));

app.get('/api/admin/users', auth, admin, h(async (req, res) => {
  const { rows } = await pool.query('SELECT u.id, u.identifier, u.role, u.active, u.created_at, w.verified_paisa, w.available_paisa, w.pending_paisa, w.withdrawn_paisa FROM users u JOIN wallets w ON w.user_id=u.id ORDER BY u.created_at DESC LIMIT 500');
  res.json({ items: rows.map(r => ({ id: r.id, identifier: r.identifier, role: r.role, active: r.active, created_at: r.created_at, verified: taka(r.verified_paisa), available: taka(r.available_paisa), pending: taka(r.pending_paisa), withdrawn: taka(r.withdrawn_paisa) })) });
}));
app.post('/api/admin/ads', auth, admin, h(async (req, res) => {
  const t = String(req.body.title || '').trim().slice(0, 120), l = String(req.body.link || '').trim(), a = String(req.body.advertiser || '').trim().slice(0, 80);
  if (!t || !a || !/^https:\/\/\S+$/.test(l)) fail(400, 'শিরোনাম, বিজ্ঞাপনদাতার নাম ও https লিংক দিন।');
  res.json({ id: (await pool.query('INSERT INTO ads(advertiser,title,link) VALUES($1,$2,$3) RETURNING id', [a, t, l])).rows[0].id });
}));
app.post('/api/admin/advertiser-payments', auth, admin, h(async (req, res) => {   // বিজ্ঞাপনদাতার টাকা সত্যিই হাতে পাওয়ার পরই লিখুন
  const amt = Math.round(Number(req.body.amount) * 100), a = String(req.body.advertiser || '').trim().slice(0, 80), ref = String(req.body.reference || '').trim().slice(0, 60);
  if (!(amt > 0) || !a || !ref) fail(400, 'বিজ্ঞাপনদাতার নাম, টাকার পরিমাণ ও রেফারেন্স দিন।');
  await pool.query('INSERT INTO advertiser_payments(advertiser,amount_paisa,reference,recorded_by) VALUES($1,$2,$3,$4)', [a, amt, ref, req.user.id]);
  res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, 'public')));
app.listen(PORT, () => console.log('চালু: পোর্ট ' + PORT));
