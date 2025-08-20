import dotenv from 'dotenv';
// <<— PODAJ BEZWZGLĘDNĄ ŚCIEŻKĘ DO .env
dotenv.config({ path: '/var/www/Automationapp/.env' });
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import pgSessionFactory from 'connect-pg-simple';
import morgan from 'morgan';

import { pool } from './db.js';
import routes from './routes.js';
import { helmetMw, compressMw, loginLimiter } from './security.js';
import csrf from 'csurf';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

if (!process.env.SESSION_SECRET) {
    console.error('ERROR: SESSION_SECRET is missing. Check /var/www/Automationapp/.env');
    process.exit(1);
  }

if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}

// Widoki (HTML renderujemy EJS-em)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Statyki i parsowanie
app.use('/public', express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));

// Logi, kompresja, nagłówki bezpieczeństwa
app.use(morgan(process.env.NODE_ENV === 'production' ? 'combined' : 'dev'));
app.use(compressMw);
app.use(helmetMw);

// Sesje w Postgres
const PgSession = pgSessionFactory(session);
app.use(session({
  name: process.env.SESSION_NAME || 'sid',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new PgSession({
    pool,
    tableName: 'session', // zostanie utworzone automatycznie przy pierwszym użyciu
    createTableIfMissing: true
  }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.SESSION_SECURE === 'true',
    maxAge: 1000 * 60 * 60 * 2 // 2h
  }
}));

// Ogranicznik tylko na POST /login
app.post('/login', loginLimiter, (req, res, next) => next());

// Trasy
app.use(routes);

// 404
app.use((req, res) => res.status(404).send('404 Not Found'));

// Start
const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, '127.0.0.1', () => {
  console.log(`Server on http://127.0.0.1:${PORT}`);
});