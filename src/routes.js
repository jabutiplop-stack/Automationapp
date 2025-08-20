import express from 'express';
import csrf from 'csurf';
import { findUserByUsername, verifyPassword, requireAuth } from './auth.js';

const router = express.Router();
const csrfProtection = csrf();

router.get('/', (req, res) => res.redirect('/dashboard'));

router.get('/login', csrfProtection, (req, res) => {
  if (req.session?.user) return res.redirect('/dashboard');
  res.render('login', { csrfToken: req.csrfToken(), error: null });
});

router.post('/login', csrfProtection, async (req, res) => {
  const { username, password } = req.body ?? {};
  try {
    const user = await findUserByUsername(username);
    const ok = user ? await verifyPassword(password, user.password) : false;

    if (!ok) {
      return res.status(401).render('login', { csrfToken: req.csrfToken(), error: 'Błędny login lub hasło.' });
    }

    // Minimalny profil zapisany w sesji
    req.session.user = { id: user.id, username: user.username };
    res.redirect('/dashboard');
  } catch (e) {
    console.error(e);
    res.status(500).render('login', { csrfToken: req.csrfToken(), error: 'Błąd serwera. Spróbuj ponownie.' });
  }
});

router.get('/dashboard', requireAuth, (req, res) => {
  const user = req.session.user;
  res.render('dashboard', { user });
});

router.post('/logout', csrfProtection, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie(process.env.SESSION_NAME || 'sid');
    res.redirect('/login');
  });
});

export default router;