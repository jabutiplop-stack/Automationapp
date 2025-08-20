import express from 'express';
import session from 'express-session';
import pgSession from 'connect-pg-simple';
import helmet from 'helmet';
import morgan from 'morgan';
import csrf from 'csurf';
import { body, validationResult } from 'express-validator';
import bcrypt from 'bcrypt';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import { pool, query } from './db.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();             // <— TO MUSI BYĆ PRZED app.get/app.post!
const PgSession = pgSession(session);

// Ustawienia
app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "style-src": ["'self'"],
      "img-src": ["'self'"],
      "font-src": ["'self'"],
      "connect-src": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(morgan('combined'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(process.cwd(), 'public')));

// Sesje w Postgres
app.use(session({
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
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 8,
    domain: process.env.NODE_ENV === 'production' ? (process.env.COOKIE_DOMAIN || undefined) : undefined
  }
}));

// CSRF
const csrfProtection = csrf();
app.use(csrfProtection);

// Rate limit tylko na /login
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

// Routes
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  return res.redirect('/login');
});

app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  const { e } = req.query;
  res.render('login', { csrfToken: req.csrfToken(), error: e || null });
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
      const { rows } = await query('SELECT id, username, password FROM users WHERE username = $1', [username]);
      if (rows.length === 0) {
        return res.redirect('/login?e=' + encodeURIComponent('Nieprawidłowy login lub hasło.'));
      }
      const user = rows[0];

      let ok = false;
      if (String(process.env.PLAINTEXT_PASSWORDS).toLowerCase() === 'true') {
        ok = password === user.password; // tylko tymczasowo!
      } else {
        ok = await bcrypt.compare(password, user.password);
      }
      if (!ok) {
        return res.redirect('/login?e=' + encodeURIComponent('Nieprawidłowy login lub hasło.'));
      }

      req.session.user = { id: user.id, username: user.username };
      return res.redirect('/dashboard');
    } catch (err) {
      console.error('Login error:', err);
      return res.redirect('/login?e=' + encodeURIComponent('Błąd serwera. Spróbuj ponownie.'));
    }
  }
);

app.get('/dashboard', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  res.render('dashboard', { user: req.session.user, csrfToken: req.csrfToken() });
});

app.post('/logout', (req, res) => {
  if (!req.session?.user) return res.redirect('/login');
  req.session.destroy(() => {
    res.clearCookie('cah.sid');
    res.redirect('/login');
  });
});

// CSRF error handler
app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    return res.status(403).send('Sesja wygasła lub niepoprawny token CSRF. Odśwież stronę.');
  }
  return next(err);
});

const PORT = Number(process.env.PORT) || 3000;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`App listening on http://127.0.0.1:${PORT}`);
});