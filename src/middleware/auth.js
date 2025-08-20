export function ensureLoggedIn(req, res, next) {
  if (req.session?.user) return next();
  return res.redirect('/login');
  }
  app.use((req, res, next) => {
    // pokaż w logu ID sesji i czy przyszedł cookie
    const hasCookie = (req.headers.cookie || '').includes('cah.sid');
    console.log(`[DBG] ${req.method} ${req.path} sid=${req.sessionID} cookie=${hasCookie}`);
    next();
  });