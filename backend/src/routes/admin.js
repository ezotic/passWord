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

module.exports = router;
