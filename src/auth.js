import bcrypt from 'bcrypt';
import { pool } from './db.js';

export async function findUserByUsername(username) {
  const q = 'SELECT id, username, password FROM users WHERE username = $1 LIMIT 1';
  const { rows } = await pool.query(q, [username]);
  return rows[0] || null;
}

export async function verifyPassword(plain, hash) {
  // jeśli Twoje hasła w DB są w postaci jawnej (niezalecane),
  // tymczasowo użyj: return plain === hash;
  // Lepiej od razu zmigrować do bcrypt.
  return bcrypt.compare(plain, hash);
}

export function requireAuth(req, res, next) {
  if (req.session?.user) return next();
  res.redirect('/login');
}