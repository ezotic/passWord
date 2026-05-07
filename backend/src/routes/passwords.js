'use strict';

const express    = require('express');
const { body, validationResult } = require('express-validator');
const { pool }   = require('../db');
const { encrypt, decrypt } = require('../crypto');

const router = express.Router();

const createRules = [
  body('website')
    .optional({ checkFalsy: true })
    .trim()
    .isURL({ require_protocol: true }) .withMessage('Website must be a valid URL (include http:// or https://)')
    .isLength({ max: 255 })            .withMessage('Website must be at most 255 characters'),

  body('username')
    .trim()
    .notEmpty()                        .withMessage('Username is required')
    .isLength({ min: 3, max: 64 })     .withMessage('Username must be 3-64 characters')
    .matches(/^[a-zA-Z0-9_\-.]+$/)     .withMessage('Username: letters, numbers, _ - . only'),

  body('password')
    .isLength({ min: 8, max: 128 })    .withMessage('Password must be 8-128 characters'),
];

// POST /api/passwords — save entry for the authenticated user
router.post('/', createRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array() });
  }

  const { website, username, password } = req.body;

  try {
    const encrypted = encrypt(password);
    await pool.execute(
      'INSERT INTO users (user_id, website, username, password) VALUES (?, ?, ?, ?)',
      [req.user.id, website || '', username, encrypted]
    );
    return res.status(201).json({ message: 'Saved successfully', username });
  } catch (err) {
    console.error('[POST /api/passwords]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/passwords — list entries for the authenticated user
router.get('/', async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT id, website, username, password, created_at FROM users WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    const result = rows.map(row => {
      let password;
      try {
        password = decrypt(row.password);
      } catch {
        password = '[re-save required]';
      }
      return { id: row.id, website: row.website, username: row.username, password, created_at: row.created_at };
    });
    return res.json(result);
  } catch (err) {
    console.error('[GET /api/passwords]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/passwords/:id — remove a single entry owned by the authenticated user
router.delete('/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id < 1) {
    return res.status(400).json({ error: 'Invalid id' });
  }

  try {
    const [result] = await pool.execute(
      'DELETE FROM users WHERE id = ? AND user_id = ?',
      [id, req.user.id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Entry not found' });
    }
    return res.json({ message: 'Deleted' });
  } catch (err) {
    console.error('[DELETE /api/passwords/:id]', err.message);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

module.exports = router;
