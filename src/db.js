import pg from 'pg';
import dotenv from 'dotenv';
dotenv.config();


export const pool = new pg.Pool({
host: process.env.PGHOST || 'localhost',
port: Number(process.env.PGPORT) || 5432,
user: process.env.PGUSER,
password: process.env.PGPASSWORD,
database: process.env.PGDATABASE || 'uzytkownicy',
ssl: false // jeżeli potrzebujesz SSL do DB, ustaw właściwie
});


// Prosta funkcja pomocnicza
export const query = (text, params) => pool.query(text, params);