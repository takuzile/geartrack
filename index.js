const express  = require('express');
const axios    = require('axios');
const path     = require('path');
const fs       = require('fs');
const bcrypt   = require('bcrypt');
const session  = require('express-session');
const app      = express();

const CLIENT_ID     = process.env.STRAVA_CLIENT_ID     || '256853';
const CLIENT_SECRET = process.env.STRAVA_CLIENT_SECRET || 'a6b802bd711da2ce0516955711df2cdab521e7bc';
const PORT          = process.env.PORT                 || 3000;
const DB_FILE       = path.join(__dirname, 'data.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'geartrack_session_secret_2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 },
}));

const DEFAULT_DATA = { users: [], gears: {}, products: [], bikes: {}, actAssign: {} };

function loadDB() {
  try {
    if (fs.existsSync(DB_FILE)) return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch(e) { console.error('DB load error:', e.message); }
  return JSON.parse(JSON.stringify(DEFAULT_DATA));
}
function saveDB() {
  try { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8'); }
  catch(e) { console.error('DB save error:', e.message); }
}

const db = loadDB();
if (!db.users)     db.users     = [];
if (!db.gears)     db.gears     = {};
if (!db.products)  db.products  = [];
if (!db.bikes)     db.bikes     = {};
if (!db.actAssign) db.actAssign = {};

const stravaTokens     = {};
const stravaActivities = {};

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Login required' });
  next();
}

// ---- bikes ----
function ensureBikes(uid) {
  if (!db.bikes[uid] || !db.bikes[uid].length) {
    db.bikes[uid] = [{ id: Date.now(), name: 'メインバイク', isMain: true }];
    saveDB();
  }
  if (!db.bikes[uid].find(b => b.isMain)) db.bikes[uid][0].isMain = true;
  return db.bikes[uid];
}
function mainBike(uid) {
  const bikes = ensureBikes(uid);
  return bikes.find(b => b.isMain) || bikes[0];
}

// ---- user tier: past 28 days weekly average ----
function calcTier(userId) {
  const acts = stravaActivities[userId];
  if (!acts || !acts.length) return null;
  const cutoff = Date.now() - 28 * 24 * 60 * 60 * 1000;
  const totalKm = acts
    .filter(a => new Date(a.start_date_local).getTime() >= cutoff)
    .reduce((s, a) => s + a.distance / 1000, 0);
  const weekly = totalKm / 4;
  if (weekly >= 300) return 'heavy';
  if (weekly >= 100) return 'mid';
  return 'light';
}
function tierLabel(t) {
  return t === 'heavy' ? 'ヘビー' : t === 'mid' ? 'ミドル' : t === 'light' ? 'ライト' : '未連携';
}

// ---- products ----
function productView(p) {
  const reviews = p.reviews || [];
  const kms     = reviews.map(r => r.km).filter(k => k > 0);
  const avgKm   = kms.length ? Math.round(kms.reduce((a,b)=>a+b,0) / kms.length) : 0;
  const tiers   = { heavy:0, mid:0, light:0, unknown:0 };
  reviews.forEach(r => { tiers[r.tier || 'unknown']++; });
  const total   = reviews.length || 1;
  return {
    id: p.id, cat: p.cat, brand: p.brand, type: p.type || '', name: p.name,
    avgKm,
    users: new Set(reviews.map(r => r.userId)).size,
    reviewCount: reviews.length,
    heavy: Math.round(tiers.heavy / total * 100),
    mid:   Math.round(tiers.mid   / total * 100),
    light: Math.round(tiers.light / total * 100),
    reviews: reviews.map(r => ({
      user: r.user, tier: r.tier, tierLabel: tierLabel(r.tier),
      km: r.km, stars: r.stars, text: r.text, date: r.date,
    })),
  };
}
function normalize(s) { return (s || '').trim().toLowerCase().replace(/\s+/g, ' '); }

// ================= AUTH =================
app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.json({ error: '全項目を入力してください' });
  if (db.users.find(u => u.email === email)) return res.json({ error: 'このメールアドレスは登録済みです' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), email, name, password: hash, created_at: new Date().toISOString() };
  db.users.push(user);
  db.gears[user.id] = [];
  db.bikes[user.id] = [{ id: Date.now()+1, name: 'メインバイク', isMain: true }];
  saveDB();
  req.session.userId   = user.id;
  req.session.userName = user.name;
  res.json({ ok: true, name: user.name });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: 'メールアドレスまたはパスワードが違います' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok)  return res.json({ error: 'メールアドレスまたはパスワードが違います' });
  req.session.userId   = user.id;
  req.session.userName = user.name;
  res.json({ ok: true, name: user.name });
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, name: req.session.userName, id: req.session.userId });
});

// ================= STRAVA =================
app.get('/auth', requireAuth, (req, res) => {
  const host = process.env.RAILWAY_PUBLIC_DOMAIN
    ? 'https://' + process.env.RAILWAY_PUBLIC_DOMAIN
    : 'http://localhost:' + PORT;
  res.redirect(
    'https://www.strava.com/oauth/authorize?client_id=' + CLIENT_ID +
    '&redirect_uri=' + host + '/callback' +
    '&response_type=code&approval_prompt=auto&scope=activity:read_all&state=' + req.session.userId
  );
});

app.get('/callback', async (req, res) => {
  const userId = req.query.state;
  if (!userId) return res.redirect('/');
  try {
    const { data } = await axios.post('https://www.strava.com/oauth/token', {
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      code: req.query.code, grant_type: 'authorization_code',
    });
    stravaTokens[userId] = {
      access_token:  data.access_token,
      refresh_token: data.refresh_token,
      expires_at:    data.expires_at,
      athlete_name:  data.athlete.firstname + ' ' + data.athlete.lastname,
    };
    await fetchActivities(userId);
    recalcGears(userId);
    saveDB();
    res.redirect('/');
  } catch(e) { res.send('Error: ' + JSON.stringify(e.response?.data)); }
});

app.get('/strava/logout', requireAuth, (req, res) => {
  delete stravaTokens[req.session.userId];
  delete stravaActivities[req.session.userId];
  res.redirect('/');
});

async function fetchActivities(userId) {
  const token = stravaTokens[userId];
  if (!token) return;
  await refreshToken(userId);
  let page = 1, all = [];
  while (true) {
    const { data } = await axios.get('https://www.strava.com/api/v3/athlete/activities', {
      headers: { Authorization: 'Bearer ' + stravaTokens[userId].access_token },
      params:  { per_page: 100, page },
    });
    if (!data.length) break;
    all = all.concat(data);
    if (data.length < 100) break;
    page++;
  }
  stravaActivities[userId]         = all;
  stravaTokens[userId].last_sync   = new Date().toLocaleString('ja-JP');
  stravaTokens[userId].total_count = all.length;
}

// gear distance = activities after start_date whose bike matches the gear's assigned bikes
function recalcGears(userId) {
  const acts   = stravaActivities[userId] || [];
  const gears  = db.gears[userId]         || [];
  const main   = mainBike(userId);
  const assign = db.actAssign[userId]     || {};
  gears.forEach(g => {
    if (!g.start_date) { g.used = 0; return; }
    const gearBikes = (g.bikeIds && g.bikeIds.length) ? g.bikeIds : (main ? [main.id] : []);
    const start = new Date(g.start_date).getTime();
    g.used = Math.round(
      acts.filter(a => {
        if (new Date(a.start_date_local).getTime() < start) return false;
        const actBike = assign[a.id] || (main && main.id);
        return gearBikes.includes(actBike);
      }).reduce((sum, a) => sum + a.distance / 1000, 0)
    );
  });
}

async function refreshToken(userId) {
  const token = stravaTokens[userId];
  if (!token) return;
  const now = Math.floor(Date.now() / 1000);
  if (token.expires_at - now > 300) return;
  const { data } = await axios.post('https://www.strava.com/oauth/token', {
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    refresh_token: token.refresh_token, grant_type: 'refresh_token',
  });
  token.access_token  = data.access_token;
  token.refresh_token = data.refresh_token;
  token.expires_at    = data.expires_at;
}

// ================= STATUS =================
app.get('/api/status', requireAuth, (req, res) => {
  const uid   = req.session.userId;
  const token = stravaTokens[uid];
  const tier  = calcTier(uid);
  res.json({
    connected:   !!token,
    athlete:     token?.athlete_name  || null,
    last_sync:   token?.last_sync     || null,
    total_count: token?.total_count   || 0,
    tier, tierLabel: tierLabel(tier),
  });
});

// ================= BIKES =================
app.get('/api/bikes', requireAuth, (req, res) => res.json(ensureBikes(req.session.userId)));

app.post('/api/bikes', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const bikes = ensureBikes(uid);
  const { name } = req.body;
  if (!name || !name.trim()) return res.json({ error: '名前を入力してください' });
  const b = { id: Date.now(), name: name.trim(), isMain: false };
  bikes.push(b);
  saveDB();
  res.json(b);
});

app.post('/api/bikes/:id/rename', requireAuth, (req, res) => {
  const bikes = ensureBikes(req.session.userId);
  const b = bikes.find(x => x.id == req.params.id);
  if (!b) return res.json({ error: 'not found' });
  if (req.body.name && req.body.name.trim()) b.name = req.body.name.trim();
  saveDB();
  res.json(b);
});

app.post('/api/bikes/:id/main', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const bikes = ensureBikes(uid);
  bikes.forEach(b => { b.isMain = (b.id == req.params.id); });
  recalcGears(uid);
  saveDB();
  res.json({ ok: true });
});

app.delete('/api/bikes/:id', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const bikes = ensureBikes(uid);
  if (bikes.length <= 1) return res.json({ error: '最後の1台は削除できません' });
  const target = bikes.find(b => b.id == req.params.id);
  if (!target) return res.json({ error: 'not found' });
  db.bikes[uid] = bikes.filter(b => b.id != req.params.id);
  if (target.isMain) db.bikes[uid][0].isMain = true;
  // remove bike from gear assignments and activity assignments
  (db.gears[uid] || []).forEach(g => {
    if (g.bikeIds) g.bikeIds = g.bikeIds.filter(id => id != req.params.id);
  });
  const assign = db.actAssign[uid] || {};
  Object.keys(assign).forEach(actId => { if (assign[actId] == req.params.id) delete assign[actId]; });
  recalcGears(uid);
  saveDB();
  res.json({ ok: true });
});

// ================= ACTIVITIES (bike assignment) =================
app.get('/api/activities', requireAuth, (req, res) => {
  const uid    = req.session.userId;
  const acts   = stravaActivities[uid] || [];
  const main   = mainBike(uid);
  const assign = db.actAssign[uid] || {};
  res.json(acts.slice(0, 20).map(a => ({
    id: a.id, name: a.name, type: a.type,
    km: Math.round(a.distance / 100) / 10,
    date: a.start_date_local ? a.start_date_local.slice(0, 10) : '',
    bikeId: assign[a.id] || (main && main.id),
  })));
});

app.post('/api/activities/:id/bike', requireAuth, (req, res) => {
  const uid = req.session.userId;
  if (!db.actAssign[uid]) db.actAssign[uid] = {};
  const main = mainBike(uid);
  const bikeId = Number(req.body.bikeId);
  if (main && bikeId === main.id) delete db.actAssign[uid][req.params.id];
  else db.actAssign[uid][req.params.id] = bikeId;
  recalcGears(uid);
  saveDB();
  res.json({ ok: true });
});

// ================= GEARS =================
app.get('/api/gears', requireAuth, (req, res) => {
  const uid  = req.session.userId;
  const main = mainBike(uid);
  const gears = (db.gears[uid] || []).map(g => ({
    ...g,
    bikeIds: (g.bikeIds && g.bikeIds.length) ? g.bikeIds : (main ? [main.id] : []),
  }));
  res.json(gears);
});

app.post('/api/gears', requireAuth, (req, res) => {
  const uid = req.session.userId;
  if (!db.gears[uid]) db.gears[uid] = [];
  const { name, cat, limit, start_date, product, bikeIds } = req.body;
  const g = {
    id: Date.now(), name, cat: cat || 'custom', limit: Number(limit), used: 0,
    start_date: start_date || null, product: product || '',
    bikeIds: Array.isArray(bikeIds) && bikeIds.length ? bikeIds.map(Number) : [mainBike(uid).id],
  };
  db.gears[uid].push(g);
  recalcGears(uid);
  saveDB();
  res.json(g);
});

app.post('/api/gears/:id/bikes', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const g = (db.gears[uid] || []).find(x => x.id == req.params.id);
  if (!g) return res.json({ error: 'not found' });
  const ids = Array.isArray(req.body.bikeIds) ? req.body.bikeIds.map(Number) : [];
  g.bikeIds = ids.length ? ids : [mainBike(uid).id];
  recalcGears(uid);
  saveDB();
  res.json(g);
});

app.post('/api/gears/:id/start_date', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const g = (db.gears[uid] || []).find(x => x.id == req.params.id);
  if (!g) return res.json({ error: 'not found' });
  g.start_date = req.body.start_date;
  recalcGears(uid);
  saveDB();
  res.json(g);
});

app.post('/api/gears/:id/reset', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const g = (db.gears[uid] || []).find(x => x.id == req.params.id);
  if (!g) return res.json({ error: 'not found' });
  g.start_date = new Date().toISOString().slice(0, 10);
  recalcGears(uid);
  saveDB();
  res.json(g);
});

app.delete('/api/gears/:id', requireAuth, (req, res) => {
  const uid = req.session.userId;
  db.gears[uid] = (db.gears[uid] || []).filter(x => x.id != req.params.id);
  saveDB();
  res.json({ ok: true });
});

app.post('/api/sync', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  if (!stravaTokens[uid]) return res.json({ error: 'Not connected' });
  try {
    await fetchActivities(uid);
    recalcGears(uid);
    saveDB();
    res.json({ ok: true });
  } catch(e) { res.json({ error: e.message }); }
});

// ================= PRODUCT DB =================
app.get('/api/products', (req, res) => {
  const { cat, brand, type, q } = req.query;
  let list = db.products;
  if (cat && cat !== 'all') list = list.filter(p => p.cat === cat);
  if (brand) list = list.filter(p => normalize(p.brand) === normalize(brand));
  if (type)  list = list.filter(p => p.type === type);
  if (q) {
    const nq = normalize(q);
    list = list.filter(p =>
      normalize(p.brand).includes(nq) ||
      normalize(p.name).includes(nq) ||
      normalize(p.brand + ' ' + p.name).includes(nq)
    );
  }
  res.json(list.map(productView).sort((a, b) => b.reviewCount - a.reviewCount));
});

app.get('/api/products/brands', (req, res) => {
  const { cat } = req.query;
  const counts = {};
  db.products.filter(p => !cat || p.cat === cat).forEach(p => {
    counts[p.brand] = (counts[p.brand] || 0) + (p.reviews ? p.reviews.length : 0) + 1;
  });
  res.json(Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([name, count]) => ({ name, count })));
});

app.post('/api/products', requireAuth, (req, res) => {
  const { cat, brand, type, name, km, stars, review, force } = req.body;
  if (!cat || !brand || !name) return res.json({ error: 'カテゴリ・メーカー・商品名は必須です' });
  const nName = normalize(name);
  const candidates = db.products.filter(p =>
    p.cat === cat &&
    normalize(p.brand) === normalize(brand) &&
    (normalize(p.name) === nName || normalize(p.name).includes(nName) || nName.includes(normalize(p.name)))
  );
  if (candidates.length && !force) {
    return res.json({ duplicate: true, candidates: candidates.map(productView) });
  }
  const uid  = req.session.userId;
  const tier = calcTier(uid);
  const p = {
    id: Date.now(), cat, brand: brand.trim(), type: type || '', name: name.trim(),
    createdBy: uid, reviews: [],
  };
  if (km || review) {
    p.reviews.push({
      userId: uid, user: req.session.userName, tier,
      km: Number(km) || 0, stars: Number(stars) || 5, text: review || '',
      date: new Date().toISOString().slice(0, 10),
    });
  }
  db.products.push(p);
  saveDB();
  res.json({ ok: true, product: productView(p) });
});

app.post('/api/products/:id/reviews', requireAuth, (req, res) => {
  const p = db.products.find(x => x.id == req.params.id);
  if (!p) return res.json({ error: 'not found' });
  const uid  = req.session.userId;
  const tier = calcTier(uid);
  const { km, stars, review } = req.body;
  if (!p.reviews) p.reviews = [];
  p.reviews = p.reviews.filter(r => r.userId !== uid);
  p.reviews.push({
    userId: uid, user: req.session.userName, tier,
    km: Number(km) || 0, stars: Number(stars) || 5, text: review || '',
    date: new Date().toISOString().slice(0, 10),
  });
  saveDB();
  res.json({ ok: true, product: productView(p) });
});

app.post('/api/products/merge', requireAuth, (req, res) => {
  const { sourceId, targetId } = req.body;
  if (sourceId == targetId) return res.json({ error: '同じ商品です' });
  const source = db.products.find(p => p.id == sourceId);
  const target = db.products.find(p => p.id == targetId);
  if (!source || !target) return res.json({ error: 'not found' });
  if (source.cat !== target.cat) return res.json({ error: 'カテゴリが異なる商品は統合できません' });
  if (!target.reviews) target.reviews = [];
  (source.reviews || []).forEach(r => {
    if (!target.reviews.find(t => t.userId === r.userId)) target.reviews.push(r);
  });
  db.products = db.products.filter(p => p.id != sourceId);
  saveDB();
  res.json({ ok: true, product: productView(target) });
});

// ================= STATS =================
app.get('/api/stats', (req, res) => {
  function catStats(cat) {
    const tiers = { heavy: [], mid: [], light: [] };
    db.products.filter(p => p.cat === cat).forEach(p => {
      (p.reviews || []).forEach(r => {
        if (r.km > 0 && tiers[r.tier]) tiers[r.tier].push(r.km);
      });
    });
    const avg = arr => arr.length ? Math.round(arr.reduce((a,b)=>a+b,0)/arr.length) : 0;
    return { heavy: avg(tiers.heavy), mid: avg(tiers.mid), light: avg(tiers.light) };
  }
  res.json({
    totalUsers:    db.users.length,
    totalProducts: db.products.length,
    tireByLevel:   catStats('tire'),
    chainByLevel:  catStats('chain'),
    tireProducts:  db.products.filter(p => p.cat==='tire').map(productView).sort((a,b)=>b.reviewCount-a.reviewCount).slice(0,8),
    chainProducts: db.products.filter(p => p.cat==='chain').map(productView).sort((a,b)=>b.reviewCount-a.reviewCount).slice(0,8),
    allProducts:   db.products.map(productView).sort((a,b)=>b.reviewCount-a.reviewCount).slice(0,15),
  });
});

app.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
  console.log('Users:', db.users.length, '/ Products:', db.products.length);
});