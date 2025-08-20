import pkg from 'pg';
const { Pool } = pkg;

export const pool = new Pool({
  host: process.env.PGHOST,
  port: Number(process.env.PGPORT || 5000),
  database: process.env.PGDATABASE,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  max: 10,
  idleTimeoutMillis: 30_000
});

// proste zdrowie połączenia
export async function dbHealth() {
  const { rows } = await pool.query('SELECT 1 as ok');
  return rows[0]?.ok === 1;
}