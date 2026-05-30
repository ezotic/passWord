'use strict';

const express = require('express');
const { pool } = require('../db');

const router = express.Router();

// GET /api/admin/users — list all registered users
router.get('/users', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, username, is_admin, created_at FROM app_users ORDER BY created_at ASC'
    );
    return res.json(rows.map(r => ({
      id:        r.id,
      username:  r.username,
      isAdmin:   r.is_admin === 1,
      createdAt: r.created_at,
    })));
  } catch (err) {
    console.error('[GET /api/admin/users]', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// DELETE /api/admin/users/:id — delete a user account (and all their entries via CASCADE)
router.delete('/users/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Invalid id.' });
  }

  if (id === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account.' });
  }

  try {
    const [result] = await pool.execute(
      'DELETE FROM app_users WHERE id = ?', [id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    return res.json({ message: 'User deleted.' });
  } catch (err) {
    console.error('[DELETE /api/admin/users/:id]', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// GET /api/admin/backup — stream a SQL dump of all tables as a downloadable file
router.get('/backup', async (req, res) => {
  const TABLES = ['app_users', 'users'];

  function escapeStr(val) {
    return val
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/\0/g, '\\0')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\x1a/g, '\\Z');
  }

  function fmtDate(d) {
    const p = n => String(n).padStart(2, '0');
    return `${d.getUTCFullYear()}-${p(d.getUTCMonth()+1)}-${p(d.getUTCDate())} ` +
           `${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())}`;
  }

  function sqlVal(val) {
    if (val === null || val === undefined) return 'NULL';
    if (Buffer.isBuffer(val)) return `0x${val.toString('hex')}`;
    if (val instanceof Date) return `'${escapeStr(fmtDate(val))}'`;
    if (typeof val === 'number' || typeof val === 'bigint') return String(val);
    return `'${escapeStr(String(val))}'`;
  }

  try {
    const lines = [
      '-- passWORD database backup',
      `-- Generated: ${new Date().toISOString()}`,
      '',
      'SET FOREIGN_KEY_CHECKS=0;',
      'SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";',
      '',
    ];

    for (const table of TABLES) {
      const [[ddlRow]] = await pool.execute(`SHOW CREATE TABLE \`${table}\``);
      lines.push(
        `-- Table: ${table}`,
        `DROP TABLE IF EXISTS \`${table}\`;`,
        ddlRow['Create Table'] + ';',
        ''
      );

      const [rows] = await pool.execute(`SELECT * FROM \`${table}\``);
      if (rows.length) {
        const cols = Object.keys(rows[0]).map(c => `\`${c}\``).join(', ');
        for (const row of rows) {
          const vals = Object.values(row).map(sqlVal).join(', ');
          lines.push(`INSERT INTO \`${table}\` (${cols}) VALUES (${vals});`);
        }
      }
      lines.push('');
    }

    lines.push('SET FOREIGN_KEY_CHECKS=1;', '');

    const sql = lines.join('\n');
    const ts  = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="backup-${ts}.sql"`);
    res.setHeader('Content-Length', Buffer.byteLength(sql, 'utf8'));
    return res.send(sql);
  } catch (err) {
    console.error('[GET /api/admin/backup]', err.message);
    return res.status(500).json({ error: 'Backup failed.' });
  }
});

module.exports = router;
