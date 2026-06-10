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

const DEFAULT_DATA = {
  users: [],
  gears: {},
  products: [
    { id:1, cat:'tire', brand:'Continental', name:'GP5000 28c', avgKm:4100, users:1240, heavy:68, mid:24, light:8,
      reviews:[
        { user:'Heavy (380km/month)', km:3980, stars:5, text:'Great grip even in rain. Lasted nearly 4000km.' },
        { user:'Mid (180km/month)',   km:4300, stars:4, text:'Good value. Light users might get 5000km.' },
      ],
      rivals:[{name:'Corsa Pro',km:3900},{name:'P Zero Race',km:3750},{name:'Power Cup',km:3400}]
    },
    { id:2, cat:'tire', brand:'Vittoria', name:'Corsa Pro TLR', avgKm:3900, users:560, heavy:55, mid:35, light:10,
      reviews:[{ user:'Heavy (420km/month)', km:3600, stars:4, text:'Best grip. Wears a bit fast.' }],
      rivals:[{name:'GP5000',km:4100},{name:'P Zero Race',km:3750}]
    },
    { id:3, cat:'chain', brand:'Shimano', name:'CN-M7100', avgKm:3200, users:980, heavy:40, mid:45, light:15,
      reviews:[{ user:'Mid (220km/month)', km:3100, stars:4, text:'Smooth shifting. Lasts with proper maintenance.' }],
      rivals:[{name:'KMC X12-EL',km:3200},{name:'SRAM Red AXS',km:2700}]
    },
    { id:4, cat:'chain', brand:'KMC', name:'X12-EL', avgKm:3200, users:420, heavy:60, mid:30, light:10,
      reviews:[{ user:'Heavy (350km/month)', km:2900, stars:5, text:'More durable than Shimano in my experience.' }],
      rivals:[{name:'CN-M7100',km:3200},{name:'SRAM Red AXS',km:2700}]
    },
    { id:5, cat:'wheel', brand:'Zipp', name:'303 S', avgKm:18000, users:210, heavy:70, mid:25, light:5,
      reviews:[{ user:'Heavy (400km/month)', km:16000, stars:5, text:'Excellent stiffness. Rim wear is minimal.' }],
      rivals:[{name:'Fulcrum Racing 4',km:15000}]
    },
  ],
  rewards: [
    { id:1, brand:'Continental', product:'GP5000',   target:8000, reward:'15% OFF next purchase', code:'CONT-15-2024' },
    { id:2, brand:'Shimano',     product:'CN-M7100', target:6000, reward:'Free grease',            code:'SHI-GREASE' },
  ],
};

const DEFAULT_GEARS = [
  { id:1, name:'Rear Tire',   cat:'tire',  limit:4000, used:0, start_date:null, product:'Continental GP5000' },
  { id:2, name:'Front Tire',  cat:'tire',  limit:4000, used:0, start_date:null, product:'Continental GP5000' },
  { id:3, name:'Chain',       cat:'chain', limit:3000, used:0, start_date:null, product:'Shimano CN-M7100' },
  { id:4, name:'Bar Tape',    cat:'bar',   limit:5000, used:0, start_date:null, product:'' },
  { id:5, name:'Brake Pads',  cat:'brake', limit:5000, used:0, start_date:null, product:'' },
];

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
if (!db.users)    db.users    = [];
if (!db.gears)    db.gears    = {};
if (!db.products) db.products = DEFAULT_DATA.products;
if (!db.rewards)  db.rewards  = DEFAULT_DATA.rewards;

const stravaTokens     = {};
const stravaActivities = {};

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: 'Login required' });
  next();
}

app.post('/api/auth/register', async (req, res) => {
  const { email, password, name } = req.body;
  if (!email || !password || !name) return res.json({ error: 'All fields required' });
  if (db.users.find(u => u.email === email)) return res.json({ error: 'Email already registered' });
  const hash = await bcrypt.hash(password, 10);
  const user = { id: Date.now(), email, name, password: hash, created_at: new Date().toISOString() };
  db.users.push(user);
  db.gears[user.id] = JSON.parse(JSON.stringify(DEFAULT_GEARS));
  saveDB();
  req.session.userId   = user.id;
  req.session.userName = user.name;
  res.json({ ok: true, name: user.name });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: 'Invalid email or password' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok)  return res.json({ error: 'Invalid email or password' });
  req.session.userId   = user.id;
  req.session.userName = user.name;
  res.json({ ok: true, name: user.name });
});

app.post('/api/auth/logout', (req, res) => { req.session.destroy(); res.json({ ok: true }); });

app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, name: req.session.userName, id: req.session.userId });
});

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

function recalcGears(userId) {
  const acts  = stravaActivities[userId] || [];
  const gears = db.gears[userId]         || [];
  gears.forEach(g => {
    if (!g.start_date) { g.used = 0; return; }
    const start = new Date(g.start_date).getTime();
    g.used = Math.round(
      acts.filter(a => new Date(a.start_date_local).getTime() >= start)
          .reduce((sum, a) => sum + a.distance / 1000, 0)
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

app.get('/api/status', requireAuth, (req, res) => {
  const uid   = req.session.userId;
  const token = stravaTokens[uid];
  const acts  = stravaActivities[uid] || [];
  res.json({
    connected:   !!token,
    athlete:     token?.athlete_name  || null,
    last_sync:   token?.last_sync     || null,
    total_count: token?.total_count   || 0,
    activities:  acts.slice(0, 10),
  });
});

app.get('/api/gears', requireAuth, (req, res) => res.json(db.gears[req.session.userId] || []));

app.post('/api/gears', requireAuth, (req, res) => {
  const uid = req.session.userId;
  if (!db.gears[uid]) db.gears[uid] = [];
  const { name, cat, limit, start_date, product } = req.body;
  const g = { id: Date.now(), name, cat: cat||'custom', limit: Number(limit), used:0, start_date: start_date||null, product: product||'' };
  db.gears[uid].push(g);
  recalcGears(uid);
  saveDB();
  res.json(g);
});

app.post('/api/gears/:id/start_date', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const g = (db.gears[uid]||[]).find(x => x.id == req.params.id);
  if (!g) return res.json({ error: 'not found' });
  g.start_date = req.body.start_date;
  recalcGears(uid);
  saveDB();
  res.json(g);
});

app.post('/api/gears/:id/reset', requireAuth, (req, res) => {
  const uid = req.session.userId;
  const g = (db.gears[uid]||[]).find(x => x.id == req.params.id);
  if (!g) return res.json({ error: 'not found' });
  g.start_date = new Date().toISOString().slice(0, 10);
  recalcGears(uid);
  saveDB();
  res.json(g);
});

app.delete('/api/gears/:id', requireAuth, (req, res) => {
  const uid = req.session.userId;
  db.gears[uid] = (db.gears[uid]||[]).filter(x => x.id != req.params.id);
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
    res.json({ ok: true, total_count: stravaTokens[uid].total_count, last_sync: stravaTokens[uid].last_sync });
  } catch(e) { res.json({ error: e.message }); }
});

app.get('/api/products', (req, res) => {
  const { cat } = req.query;
  res.json(cat && cat !== 'all' ? db.products.filter(p => p.cat === cat) : db.products);
});

app.post('/api/products', requireAuth, (req, res) => {
  const { cat, brand, name, avgKm, review, stars } = req.body;
  const existing = db.products.find(p => p.brand === brand && p.name === name);
  if (existing) {
    if (review) existing.reviews.push({ user: req.session.userName, km: Number(avgKm), stars: Number(stars)||5, text: review });
    const allKm = existing.reviews.map(r => r.km);
    existing.avgKm = Math.round(allKm.reduce((a,b)=>a+b,0) / allKm.length);
    existing.users++;
    saveDB();
    return res.json(existing);
  }
  const p = { id: Date.now(), cat, brand, name, avgKm: Number(avgKm), users:1, heavy:0, mid:0, light:0,
    reviews: review ? [{ user: req.session.userName, km: Number(avgKm), stars: Number(stars)||5, text: review }] : [],
    rivals: [],
  };
  db.products.push(p);
  saveDB();
  res.json(p);
});

app.get('/api/rewards', requireAuth, (req, res) => {
  const uid   = req.session.userId;
  const gears = db.gears[uid] || [];
  const result = db.rewards.map(r => {
    const current = gears.filter(g => g.product && g.product.includes(r.brand)).reduce((s, g) => s + g.used, 0);
    return { ...r, current, earned: current >= r.target };
  });
  res.json(result);
});

app.get('/api/stats', (req, res) => res.json({
  userLevels:    { heavy:22, mid:45, light:33 },
  tireByLevel:   { heavy:3920, mid:4400, light:4750 },
  chainByLevel:  { heavy:2800, mid:3200, light:3500 },
  tireProducts:  db.products.filter(p => p.cat==='tire').map(p  => ({ name:p.name, avgKm:p.avgKm, heavy:p.heavy, mid:p.mid, light:p.light })),
  chainProducts: db.products.filter(p => p.cat==='chain').map(p => ({ name:p.name, avgKm:p.avgKm, heavy:p.heavy, mid:p.mid, light:p.light })),
}));

app.listen(PORT, () => {
  console.log('Server running on port ' + PORT);
  console.log('Users:', db.users.length);
});