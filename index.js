require('dotenv').config();
const express   = require('express');
const axios     = require('axios');
const path      = require('path');
const bcrypt    = require('bcrypt');
const session   = require('express-session');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool, types } = require('pg');

// BIGINT を数値として扱う(Strava activity ID 用)
types.setTypeParser(20, v => Number(v));

const CLIENT_ID     = process.env.STRAVA_CLIENT_ID     || '256853';
const CLIENT_SECRET = process.env.STRAVA_CLIENT_SECRET || 'a6b802bd711da2ce0516955711df2cdab521e7bc';
const PORT          = process.env.PORT                 || 3000;

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set. Add PostgreSQL on Railway and set DATABASE_URL.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('railway.internal') ? false : { rejectUnauthorized: false },
});
const q = (text, params) => pool.query(text, params);

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

const pgSession = require('connect-pg-simple')(session);
app.use(session({
  store: new pgSession({ pool, createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET || 'geartrack_session_secret_2024',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.RAILWAY_PUBLIC_DOMAIN ? true : false,
  },
}));

// 認証系エンドポイントのレート制限(総当たり対策)
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true });
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);

// ---- テーブル初期化 ----
async function initDB() {
  await q(`CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    strava_access TEXT, strava_refresh TEXT, strava_expires BIGINT,
    strava_athlete TEXT, strava_last_sync TEXT, strava_count INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS bikes (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    is_main BOOLEAN DEFAULT false
  )`);
  await q(`CREATE TABLE IF NOT EXISTS gears (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    cat TEXT DEFAULT 'custom',
    limit_km INT NOT NULL,
    used INT DEFAULT 0,
    start_date TEXT,
    product TEXT DEFAULT '',
    bike_ids INTEGER[] DEFAULT '{}'
  )`);
  await q(`CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    cat TEXT NOT NULL, brand TEXT NOT NULL, type TEXT DEFAULT '', name TEXT NOT NULL,
    created_by INT,
    created_at TIMESTAMPTZ DEFAULT now()
  )`);
  await q(`CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    product_id INT REFERENCES products(id) ON DELETE CASCADE,
    user_id INT, user_name TEXT, tier TEXT,
    km INT DEFAULT 0, stars INT DEFAULT 5, text TEXT DEFAULT '', date TEXT,
    UNIQUE(product_id, user_id)
  )`);
  await q(`CREATE TABLE IF NOT EXISTS act_assign (
    user_id INT, activity_id BIGINT, bike_id INT,
    PRIMARY KEY(user_id, activity_id)
  )`);
  console.log('DB tables ready');
}

// ---- Strava activity cache (メモリ。トークンはDBに永続化) ----
const activityCache = {};

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Login required' });
  next();
}

async function getUser(uid) {
  return (await q('SELECT * FROM users WHERE id=$1', [uid])).rows[0];
}

// ---- bikes ----
async function ensureBikes(uid) {
  let bikes = (await q('SELECT id, name, is_main AS "isMain" FROM bikes WHERE user_id=$1 ORDER BY id', [uid])).rows;
  if (!bikes.length) {
    await q('INSERT INTO bikes (user_id, name, is_main) VALUES ($1, $2, true)', [uid, 'メインバイク']);
    bikes = (await q('SELECT id, name, is_main AS "isMain" FROM bikes WHERE user_id=$1 ORDER BY id', [uid])).rows;
  }
  if (!bikes.find(b => b.isMain)) {
    await q('UPDATE bikes SET is_main=true WHERE id=$1', [bikes[0].id]);
    bikes[0].isMain = true;
  }
  return bikes;
}
async function mainBike(uid) {
  const bikes = await ensureBikes(uid);
  return bikes.find(b => b.isMain) || bikes[0];
}

// ---- Strava ----
async function refreshTokenIfNeeded(user) {
  const now = Math.floor(Date.now() / 1000);
  if (!user.strava_refresh) return user;
  if (user.strava_expires && user.strava_expires - now > 300) return user;
  const { data } = await axios.post('https://www.strava.com/oauth/token', {
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    refresh_token: user.strava_refresh, grant_type: 'refresh_token',
  });
  await q('UPDATE users SET strava_access=$1, strava_refresh=$2, strava_expires=$3 WHERE id=$4',
    [data.access_token, data.refresh_token, data.expires_at, user.id]);
  user.strava_access  = data.access_token;
  user.strava_refresh = data.refresh_token;
  user.strava_expires = data.expires_at;
  return user;
}

async function fetchActivities(uid) {
  let user = await getUser(uid);
  if (!user || !user.strava_refresh) return [];
  user = await refreshTokenIfNeeded(user);
  let page = 1, all = [];
  while (true) {
    const { data } = await axios.get('https://www.strava.com/api/v3/athlete/activities', {
      headers: { Authorization: 'Bearer ' + user.strava_access },
      params:  { per_page: 100, page },
    });
    if (!data.length) break;
    all = all.concat(data);
    if (data.length < 100) break;
    page++;
  }
  activityCache[uid] = all;
  await q('UPDATE users SET strava_last_sync=$1, strava_count=$2 WHERE id=$3',
    [new Date().toLocaleString('ja-JP'), all.length, uid]);
  return all;
}

async function ensureActivities(uid) {
  if (activityCache[uid]) return activityCache[uid];
  const user = await getUser(uid);
  if (!user || !user.strava_refresh) return [];
  try { return await fetchActivities(uid); } catch(e) { return []; }
}

function calcTierFromActs(acts) {
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

async function recalcGears(uid) {
  const acts  = await ensureActivities(uid);
  const main  = await mainBike(uid);
  const gears = (await q('SELECT * FROM gears WHERE user_id=$1', [uid])).rows;
  const aRows = (await q('SELECT activity_id, bike_id FROM act_assign WHERE user_id=$1', [uid])).rows;
  const assign = {};
  aRows.forEach(r => { assign[r.activity_id] = r.bike_id; });
  for (const g of gears) {
    let used = 0;
    if (g.start_date) {
      const gearBikes = (g.bike_ids && g.bike_ids.length) ? g.bike_ids : (main ? [main.id] : []);
      const start = new Date(g.start_date).getTime();
      used = Math.round(
        acts.filter(a => {
          if (new Date(a.start_date_local).getTime() < start) return false;
          const actBike = assign[a.id] || (main && main.id);
          return gearBikes.includes(actBike);
        }).reduce((s, a) => s + a.distance / 1000, 0)
      );
    }
    await q('UPDATE gears SET used=$1 WHERE id=$2', [used, g.id]);
  }
}

// ================= AUTH =================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) return res.json({ error: '全項目を入力してください' });
    if (String(password).length < 6)   return res.json({ error: 'パスワードは6文字以上です' });
    if (String(email).length > 200 || String(name).length > 50) return res.json({ error: '入力が長すぎます' });
    const exists = (await q('SELECT id FROM users WHERE email=$1', [email])).rows[0];
    if (exists) return res.json({ error: 'このメールアドレスは登録済みです' });
    const hash = await bcrypt.hash(password, 10);
    const r = await q('INSERT INTO users (email, name, password) VALUES ($1,$2,$3) RETURNING id, name', [email, name, hash]);
    const user = r.rows[0];
    await q('INSERT INTO bikes (user_id, name, is_main) VALUES ($1, $2, true)', [user.id, 'メインバイク']);
    req.session.userId   = user.id;
    req.session.userName = user.name;
    res.json({ ok: true, name: user.name });
  } catch(e) { console.error(e); res.json({ error: '登録に失敗しました' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = (await q('SELECT * FROM users WHERE email=$1', [email])).rows[0];
    if (!user) return res.json({ error: 'メールアドレスまたはパスワードが違います' });
    const ok = await bcrypt.compare(password || '', user.password);
    if (!ok)  return res.json({ error: 'メールアドレスまたはパスワードが違います' });
    req.session.userId   = user.id;
    req.session.userName = user.name;
    res.json({ ok: true, name: user.name });
  } catch(e) { console.error(e); res.json({ error: 'ログインに失敗しました' }); }
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(() => res.json({ ok: true })); });

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
  const userId = Number(req.query.state);
  if (!userId || userId !== req.session.userId) return res.redirect('/');
  try {
    const { data } = await axios.post('https://www.strava.com/oauth/token', {
      client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
      code: req.query.code, grant_type: 'authorization_code',
    });
    await q('UPDATE users SET strava_access=$1, strava_refresh=$2, strava_expires=$3, strava_athlete=$4 WHERE id=$5',
      [data.access_token, data.refresh_token, data.expires_at,
       data.athlete.firstname + ' ' + data.athlete.lastname, userId]);
    await fetchActivities(userId);
    await recalcGears(userId);
    res.redirect('/');
  } catch(e) { console.error(e.response?.data || e.message); res.redirect('/'); }
});

app.get('/strava/logout', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  await q('UPDATE users SET strava_access=NULL, strava_refresh=NULL, strava_expires=NULL, strava_athlete=NULL, strava_count=0 WHERE id=$1', [uid]);
  delete activityCache[uid];
  res.redirect('/');
});

// ================= STATUS =================
app.get('/api/status', requireAuth, async (req, res) => {
  const uid  = req.session.userId;
  const user = await getUser(uid);
  const acts = user && user.strava_refresh ? await ensureActivities(uid) : [];
  const tier = calcTierFromActs(acts);
  res.json({
    connected:   !!(user && user.strava_refresh),
    athlete:     user?.strava_athlete  || null,
    last_sync:   user?.strava_last_sync || null,
    total_count: user?.strava_count     || 0,
    tier, tierLabel: tierLabel(tier),
  });
});

// ================= BIKES =================
app.get('/api/bikes', requireAuth, async (req, res) => res.json(await ensureBikes(req.session.userId)));

app.post('/api/bikes', requireAuth, async (req, res) => {
  const name = (req.body.name || '').trim();
  if (!name) return res.json({ error: '名前を入力してください' });
  if (name.length > 40) return res.json({ error: '名前が長すぎます' });
  const r = await q('INSERT INTO bikes (user_id, name, is_main) VALUES ($1,$2,false) RETURNING id, name, is_main AS "isMain"',
    [req.session.userId, name]);
  res.json(r.rows[0]);
});

app.post('/api/bikes/:id/rename', requireAuth, async (req, res) => {
  const name = (req.body.name || '').trim();
  if (!name || name.length > 40) return res.json({ error: '名前が不正です' });
  await q('UPDATE bikes SET name=$1 WHERE id=$2 AND user_id=$3', [name, req.params.id, req.session.userId]);
  res.json({ ok: true });
});

app.post('/api/bikes/:id/main', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  await q('UPDATE bikes SET is_main=false WHERE user_id=$1', [uid]);
  await q('UPDATE bikes SET is_main=true WHERE id=$1 AND user_id=$2', [req.params.id, uid]);
  await recalcGears(uid);
  res.json({ ok: true });
});

app.delete('/api/bikes/:id', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  const bikes = await ensureBikes(uid);
  if (bikes.length <= 1) return res.json({ error: '最後の1台は削除できません' });
  const target = bikes.find(b => b.id == req.params.id);
  if (!target) return res.json({ error: 'not found' });
  await q('DELETE FROM bikes WHERE id=$1 AND user_id=$2', [req.params.id, uid]);
  await q('UPDATE gears SET bike_ids=array_remove(bike_ids, $1) WHERE user_id=$2', [Number(req.params.id), uid]);
  await q('DELETE FROM act_assign WHERE user_id=$1 AND bike_id=$2', [uid, req.params.id]);
  if (target.isMain) {
    const rest = (await q('SELECT id FROM bikes WHERE user_id=$1 ORDER BY id LIMIT 1', [uid])).rows[0];
    if (rest) await q('UPDATE bikes SET is_main=true WHERE id=$1', [rest.id]);
  }
  await recalcGears(uid);
  res.json({ ok: true });
});

// ================= ACTIVITIES =================
app.get('/api/activities', requireAuth, async (req, res) => {
  const uid    = req.session.userId;
  const acts   = await ensureActivities(uid);
  const main   = await mainBike(uid);
  const aRows  = (await q('SELECT activity_id, bike_id FROM act_assign WHERE user_id=$1', [uid])).rows;
  const assign = {};
  aRows.forEach(r => { assign[r.activity_id] = r.bike_id; });
  res.json(acts.slice(0, 20).map(a => ({
    id: a.id, name: a.name, type: a.type,
    km: Math.round(a.distance / 100) / 10,
    date: a.start_date_local ? a.start_date_local.slice(0, 10) : '',
    bikeId: assign[a.id] || (main && main.id),
  })));
});

app.post('/api/activities/:id/bike', requireAuth, async (req, res) => {
  const uid    = req.session.userId;
  const main   = await mainBike(uid);
  const bikeId = Number(req.body.bikeId);
  if (main && bikeId === main.id) {
    await q('DELETE FROM act_assign WHERE user_id=$1 AND activity_id=$2', [uid, req.params.id]);
  } else {
    await q(`INSERT INTO act_assign (user_id, activity_id, bike_id) VALUES ($1,$2,$3)
             ON CONFLICT (user_id, activity_id) DO UPDATE SET bike_id=$3`, [uid, req.params.id, bikeId]);
  }
  await recalcGears(uid);
  res.json({ ok: true });
});

// ================= GEARS =================
const GEAR_SELECT = `SELECT id, name, cat, limit_km AS "limit", used, start_date, product, bike_ids AS "bikeIds" FROM gears WHERE user_id=$1 ORDER BY id`;

app.get('/api/gears', requireAuth, async (req, res) => {
  const uid  = req.session.userId;
  const main = await mainBike(uid);
  const gears = (await q(GEAR_SELECT, [uid])).rows.map(g => ({
    ...g, bikeIds: (g.bikeIds && g.bikeIds.length) ? g.bikeIds : (main ? [main.id] : []),
  }));
  res.json(gears);
});

app.post('/api/gears', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  const { name, cat, limit, start_date, product, bikeIds } = req.body;
  if (!name || !limit) return res.json({ error: '名前と交換目安は必須です' });
  if (String(name).length > 60) return res.json({ error: '名前が長すぎます' });
  const main = await mainBike(uid);
  const ids = Array.isArray(bikeIds) && bikeIds.length ? bikeIds.map(Number) : [main.id];
  await q(`INSERT INTO gears (user_id, name, cat, limit_km, start_date, product, bike_ids)
           VALUES ($1,$2,$3,$4,$5,$6,$7)`,
    [uid, name.trim(), cat || 'custom', Number(limit), start_date || null, (product||'').slice(0,100), ids]);
  await recalcGears(uid);
  res.json({ ok: true });
});

app.post('/api/gears/:id/bikes', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  const main = await mainBike(uid);
  const ids = Array.isArray(req.body.bikeIds) && req.body.bikeIds.length ? req.body.bikeIds.map(Number) : [main.id];
  await q('UPDATE gears SET bike_ids=$1 WHERE id=$2 AND user_id=$3', [ids, req.params.id, uid]);
  await recalcGears(uid);
  res.json({ ok: true });
});

app.post('/api/gears/:id/start_date', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  await q('UPDATE gears SET start_date=$1 WHERE id=$2 AND user_id=$3', [req.body.start_date || null, req.params.id, uid]);
  await recalcGears(uid);
  res.json({ ok: true });
});

app.post('/api/gears/:id/reset', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  await q('UPDATE gears SET start_date=$1 WHERE id=$2 AND user_id=$3',
    [new Date().toISOString().slice(0, 10), req.params.id, uid]);
  await recalcGears(uid);
  res.json({ ok: true });
});

app.delete('/api/gears/:id', requireAuth, async (req, res) => {
  await q('DELETE FROM gears WHERE id=$1 AND user_id=$2', [req.params.id, req.session.userId]);
  res.json({ ok: true });
});

app.post('/api/sync', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  const user = await getUser(uid);
  if (!user || !user.strava_refresh) return res.json({ error: 'Not connected' });
  try {
    await fetchActivities(uid);
    await recalcGears(uid);
    res.json({ ok: true });
  } catch(e) { console.error(e.message); res.json({ error: '同期に失敗しました' }); }
});

// ================= PRODUCT DB =================
function normalize(s) { return (s || '').trim().toLowerCase().replace(/\s+/g, ' '); }

async function productViews(where = '', params = []) {
  const prods = (await q(`SELECT * FROM products ${where} ORDER BY id`, params)).rows;
  if (!prods.length) return [];
  const ids = prods.map(p => p.id);
  const revs = (await q('SELECT * FROM reviews WHERE product_id = ANY($1)', [ids])).rows;
  return prods.map(p => {
    const reviews = revs.filter(r => r.product_id === p.id);
    const kms = reviews.map(r => r.km).filter(k => k > 0);
    const avgKm = kms.length ? Math.round(kms.reduce((a,b)=>a+b,0)/kms.length) : 0;
    const tiers = { heavy:0, mid:0, light:0, unknown:0 };
    reviews.forEach(r => { tiers[r.tier || 'unknown']++; });
    const total = reviews.length || 1;
    return {
      id: p.id, cat: p.cat, brand: p.brand, type: p.type || '', name: p.name,
      avgKm,
      users: new Set(reviews.map(r => r.user_id)).size,
      reviewCount: reviews.length,
      heavy: Math.round(tiers.heavy/total*100),
      mid:   Math.round(tiers.mid/total*100),
      light: Math.round(tiers.light/total*100),
      reviews: reviews.map(r => ({
        user: r.user_name, tier: r.tier, tierLabel: tierLabel(r.tier),
        km: r.km, stars: r.stars, text: r.text, date: r.date,
      })),
    };
  });
}

app.get('/api/products', async (req, res) => {
  const { cat, brand, type, q: query } = req.query;
  let list = await productViews();
  if (cat && cat !== 'all') list = list.filter(p => p.cat === cat);
  if (brand) list = list.filter(p => normalize(p.brand) === normalize(brand));
  if (type)  list = list.filter(p => p.type === type);
  if (query) {
    const nq = normalize(query);
    list = list.filter(p => normalize(p.brand + ' ' + p.name).includes(nq));
  }
  res.json(list.sort((a, b) => b.reviewCount - a.reviewCount));
});

app.get('/api/products/brands', async (req, res) => {
  const { cat } = req.query;
  const r = await q(`
    SELECT p.brand AS name, COUNT(r.id) + COUNT(DISTINCT p.id) AS count
    FROM products p LEFT JOIN reviews r ON r.product_id = p.id
    ${cat ? 'WHERE p.cat = $1' : ''}
    GROUP BY p.brand ORDER BY count DESC`, cat ? [cat] : []);
  res.json(r.rows.map(x => ({ name: x.name, count: Number(x.count) })));
});

app.post('/api/products', requireAuth, async (req, res) => {
  const { cat, brand, type, name, km, stars, review, force } = req.body;
  if (!cat || !brand || !name) return res.json({ error: 'カテゴリ・メーカー・商品名は必須です' });
  if (String(brand).length > 60 || String(name).length > 100 || String(review||'').length > 1000)
    return res.json({ error: '入力が長すぎます' });

  const all = await productViews('WHERE cat=$1', [cat]);
  const nName = normalize(name);
  const candidates = all.filter(p =>
    normalize(p.brand) === normalize(brand) &&
    (normalize(p.name) === nName || normalize(p.name).includes(nName) || nName.includes(normalize(p.name)))
  );
  if (candidates.length && !force) return res.json({ duplicate: true, candidates });

  const uid  = req.session.userId;
  const acts = await ensureActivities(uid);
  const tier = calcTierFromActs(acts);
  const r = await q('INSERT INTO products (cat, brand, type, name, created_by) VALUES ($1,$2,$3,$4,$5) RETURNING id',
    [cat, brand.trim(), type || '', name.trim(), uid]);
  if (km || review) {
    await q(`INSERT INTO reviews (product_id, user_id, user_name, tier, km, stars, text, date)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
      [r.rows[0].id, uid, req.session.userName, tier, Number(km)||0, Math.min(Math.max(Number(stars)||5,1),5), review||'', new Date().toISOString().slice(0,10)]);
  }
  res.json({ ok: true });
});

app.post('/api/products/:id/reviews', requireAuth, async (req, res) => {
  const uid  = req.session.userId;
  const { km, stars, review } = req.body;
  if (String(review||'').length > 1000) return res.json({ error: 'レビューが長すぎます' });
  const acts = await ensureActivities(uid);
  const tier = calcTierFromActs(acts);
  await q(`INSERT INTO reviews (product_id, user_id, user_name, tier, km, stars, text, date)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
           ON CONFLICT (product_id, user_id)
           DO UPDATE SET tier=$4, km=$5, stars=$6, text=$7, date=$8, user_name=$3`,
    [req.params.id, uid, req.session.userName, tier, Number(km)||0, Math.min(Math.max(Number(stars)||5,1),5), review||'', new Date().toISOString().slice(0,10)]);
  res.json({ ok: true });
});

app.post('/api/products/merge', requireAuth, async (req, res) => {
  const { sourceId, targetId } = req.body;
  if (sourceId == targetId) return res.json({ error: '同じ商品です' });
  const source = (await q('SELECT * FROM products WHERE id=$1', [sourceId])).rows[0];
  const target = (await q('SELECT * FROM products WHERE id=$1', [targetId])).rows[0];
  if (!source || !target) return res.json({ error: 'not found' });
  if (source.cat !== target.cat) return res.json({ error: 'カテゴリが異なる商品は統合できません' });
  // 同一ユーザーのレビューが両方にある場合は統合先を優先(元側を削除)
  await q(`DELETE FROM reviews WHERE product_id=$1 AND user_id IN (SELECT user_id FROM reviews WHERE product_id=$2)`,
    [sourceId, targetId]);
  await q('UPDATE reviews SET product_id=$1 WHERE product_id=$2', [targetId, sourceId]);
  await q('DELETE FROM products WHERE id=$1', [sourceId]);
  res.json({ ok: true });
});

// ================= STATS =================
app.get('/api/stats', async (req, res) => {
  async function catStats(cat) {
    const r = await q(`
      SELECT r.tier, AVG(r.km)::int AS avg FROM reviews r
      JOIN products p ON p.id = r.product_id
      WHERE p.cat=$1 AND r.km > 0 AND r.tier IS NOT NULL
      GROUP BY r.tier`, [cat]);
    const out = { heavy:0, mid:0, light:0 };
    r.rows.forEach(x => { out[x.tier] = x.avg; });
    return out;
  }
  const users    = Number((await q('SELECT COUNT(*) FROM users')).rows[0].count);
  const allViews = await productViews();
  const sorted   = allViews.sort((a,b)=>b.reviewCount-a.reviewCount);
  res.json({
    totalUsers:    users,
    totalProducts: allViews.length,
    tireByLevel:   await catStats('tire'),
    chainByLevel:  await catStats('chain'),
    tireProducts:  sorted.filter(p=>p.cat==='tire').slice(0,8),
    chainProducts: sorted.filter(p=>p.cat==='chain').slice(0,8),
    allProducts:   sorted.slice(0,15),
  });
});

initDB().then(() => {
  app.listen(PORT, () => console.log('Server running on port ' + PORT));
}).catch(e => { console.error('DB init failed:', e); process.exit(1); });