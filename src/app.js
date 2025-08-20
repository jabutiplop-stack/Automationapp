import express from 'express';


// Obsługa logowania
app.post('/login', loginLimiter,
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
ok = password === user.password; // TYLKO tymczasowo w dev!
} else {
ok = await bcrypt.compare(password, user.password);
}


if (!ok) {
return res.redirect('/login?e=' + encodeURIComponent('Nieprawidłowy login lub hasło.'));
}


// Zaloguj
req.session.user = { id: user.id, username: user.username };
return res.redirect('/dashboard');
} catch (err) {
console.error('Login error:', err);
return res.redirect('/login?e=' + encodeURIComponent('Błąd serwera. Spróbuj ponownie.'));
}
}
);


// Dashboard (chroniony)
app.get('/dashboard', ensureLoggedIn, (req, res) => {
res.render('dashboard', { user: req.session.user, csrfToken: req.csrfToken() });
});


// Wylogowanie
app.post('/logout', ensureLoggedIn, (req, res) => {
req.session.destroy(() => {
res.clearCookie('cah.sid');
res.redirect('/login');
});
});


// Obsługa błędów CSRF – 403 zamiast crasha
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