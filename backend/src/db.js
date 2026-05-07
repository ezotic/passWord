'use strict';

const mysql = require('mysql2/promise');

const pool = mysql.createPool({
  host:               process.env.DB_HOST,
  port:               parseInt(process.env.DB_PORT, 10) || 3306,
  database:           process.env.DB_NAME,
  user:               process.env.DB_USER,
  password:           process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit:    10,
  queueLimit:         0,
  connectTimeout:     10_000,
});

async function checkConnection() {
  const conn = await pool.getConnection();
  await conn.ping();
  conn.release();
  console.log('[db] MySQL connection pool ready');
}

module.exports = { pool, checkConnection };
