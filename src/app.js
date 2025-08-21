// app.js (ESM)

import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

import helmet from 'helmet';
import morgan from 'morgan';
import csrf from 'csurf';
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import expressLayouts from 'express-ejs-layouts';

import { pool, query } from './db.js';

const NAV_ITEMS = [
  { key: 'dashboard', label: 'Dashboard', href: '/dashboard', perm: 'dashboard:view' },
  { key: 'reports', label: 'Raporty', href: '/reports', perm: 'reports:view' },
  { key: 'integrations', label: 'Integracje', href: '/integrations', perm: 'integrations:view' },
  { key: 'users', label: 'Użytkownicy', href: '/admin/users', perm: 'users:manage' }, // tylko admin
];

function requireAuth(req, res, next) {
  if (!req.session?.user) return res.redirect('/login?e=' + encodeURIComponent('Zaloguj się'));
  next();
}
function requirePermission(perm) {
  return (req, res, next) => {
    const perms = req.session?.user?.permissions || [];
    if (!perms.includes(perm)) return res.status(403).send('Brak uprawnień');
    next();
  };
}

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PgSession = pgSession(session);

// --- Ustawienia podstawowe ---
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// --- Layout EJS ---
app.use(expressLayouts);
app.set('layout', 'layout'); // korzystamy z views/layout.ejs

// --- Security headers (CSP dostosowane do fontów/CSS) ---
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        "default-src": ["'self'"],
        "script-src": ["'self'"],
        "style-src": ["'self'", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'"],
        "frame-ancestors": ["'none'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

// --- Logi + body parsing + statyki ---
app.use(morgan('combined'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// --- Sesje (PostgreSQL store) ---
app.use(
  session({
    store: new PgSession({
      pool,
      tableName: 'session',
      createTableIfMissing: true
    }),
    name: 'cah.sid',
    secret: process.env.SESSION_SECRET || 'change_me',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: true,                               // stałe Secure (bo za HTTPS + trust proxy)
      domain: '.cracovautomationhub.pl',          // jeden cookie dla apex + www
      maxAge: 1000 * 60 * 60 * 8
    }
  })
);

// --- CSRF ---
const csrfProtection = csrf();
app.use(csrfProtection);

// --- Zmienne globalne do widoków (user/csrf) ---
app.use((req, res, next) => {
  res.locals.user = req.session?.user || null;
  // Jeśli masz csurf – zostaw jak jest; ważne by csrfToken trafiał do widoków
  try { res.locals.csrfToken = req.csrfToken(); } catch { res.locals.csrfToken = ''; }
  res.locals.currentPath = req.path || '';
  res.locals.navItems = NAV_ITEMS;
  next();
});
// --- Rate limit tylko na /login ---
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

// --- ROUTES ---
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  // już zalogowany? -> dashboard
  if (req.session?.user) return res.redirect('/dashboard');

  // nie cache’ujemy HTML z tokenem CSRF
  res.set('Cache-Control', 'no-store');

  // --- KLUCZ: zainicjuj sesję, żeby Set-Cookie poszło już przy GET /login ---
  // (saveUninitialized=false potrafi NIE wysłać cookie jeśli nic nie zmienisz w sesji)
  if (!req.session._loginPageTouched) {
    req.session._loginPageTouched = Date.now(); // dowolna flaga, by oznaczyć "zmieniono sesję"
  }

  // Na wszelki wypadek wymuś zapis przed renderem (nie zaszkodzi, a daje pewność)
  req.session.save(() => {
    const { e } = req.query;
    return res.render('login', { title: 'Logowanie', error: e || null });
  });
});

app.post(
  '/login',
  loginLimiter,
  body('username').trim().isLength({ min: 1 }).withMessage('Podaj nazwę użytkownika.'),
  body('password').isLength({ min: 1 }).withMessage('Podaj hasło.'),
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.redirect('/login?e=' + encodeURIComponent(errors.array()[0].msg));
    }

    const { username, password } = req.body;

    try {
      const { rows } = await query(
        'SELECT id, username, password, permissions FROM users WHERE username = $1',
        [username]
      );

      if (rows.length === 0) {
        return res.redirect('/login?e=' + encodeURIComponent('Nieprawidłowy login lub hasło.'));
      }

      const user = rows[0];
      const plaintext = String(process.env.PLAINTEXT_PASSWORDS || '').toLowerCase() === 'true';

      const ok = plaintext ? password === user.password : await bcrypt.compare(password, user.password);
      if (!ok) {
        return res.redirect('/login?e=' + encodeURIComponent('Nieprawidłowy login lub hasło.'));
      }

      req.session.user = {
        id: user.id,
        username: user.username,
        permissions: user.permissions || []
      };
      return res.redirect('/dashboard');
    } catch (err) {
      console.error('Login error:', err);
      return res.redirect('/login?e=' + encodeURIComponent('Błąd serwera. Spróbuj ponownie.'));
    }
  }
);

app.get('/dashboard', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');

  const stats = { automations: 3, webhooks: 2, errors24h: 1 };
  const events = [
    { date: '2025‑08‑20 10:20', type: 'Webhook', source: '/github/push', ok: true },
    { date: '2025‑08‑20 10:12', type: 'Run',     source: 'Zap #42',     ok: false },
    { date: '2025‑08‑19 19:03', type: 'Run',     source: 'Zap #41',     ok: true }
  ];

  res.render('dashboard', {
    title: 'Dashboard',
    stats,
    events
  });
});

// === PANEL ADMINA: lista użytkowników (wymaga users:manage) ===
app.get('/admin/users', requireAuth, requirePermission('users:manage'), async (req, res) => {
  const { rows: users } = await query('SELECT id, username, permissions FROM users ORDER BY id ASC');
  res.render('admin-users', { title: 'Użytkownicy', users });
});

// === PANEL ADMINA: zapis uprawnień (checkboxy) ===
app.post('/admin/users/:id/permissions', requireAuth, requirePermission('users:manage'), async (req, res) => {
  const { id } = req.params;
  let { permissions = [] } = req.body;
  if (!Array.isArray(permissions)) permissions = [permissions]; // 1 checkbox => string
  await query('UPDATE users SET permissions = $1 WHERE id = $2', [permissions, id]);

  // Jeśli admin zmienił samego siebie — odśwież sesję
  if (Number(req.session.user.id) === Number(id)) {
    const { rows } = await query('SELECT permissions FROM users WHERE id = $1', [id]);
    req.session.user.permissions = rows[0]?.permissions || [];
  }
  res.redirect('/admin/users');
});

app.post('/logout', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  req.session.destroy(() => {
    res.clearCookie('cah.sid');
    res.redirect('/login');
  });
});

// --- CSRF errors ---
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('Sesja wygasła lub niepoprawny token CSRF. Odśwież stronę.');
  }
  return next(err);
});

const PORT = Number(process.env.PORT) || 3000;
// Słuchamy na 127.0.0.1 (reverse proxy Nginx) — zmień na '0.0.0.0' jeśli chcesz wystawiać bezpośrednio.
app.listen(PORT, '127.0.0.1', () => {
  console.log(`App listening on http://127.0.0.1:${PORT}`);
});
