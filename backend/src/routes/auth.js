'use strict';

const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { pool } = require('../db');
const { authenticate } = require('../middleware/authenticate');

const router = express.Router();
const BCRYPT_ROUNDS = 12;
const TOKEN_TTL     = '8h';

const passwordRules = [
  body('password')
    .isLength({ min: 12, max: 20 })  .withMessage('Password must be 12–20 characters.')
    .matches(/[a-z]/)                .withMessage('Password must contain a lowercase letter.')
    .matches(/[A-Z]/)                .withMessage('Password must contain an uppercase letter.')
    .matches(/[0-9]/)                .withMessage('Password must contain a number.')
    .matches(/[^a-zA-Z0-9]/)         .withMessage('Password must contain a special character.'),
];

const registerRules = [
  body('username')
    .trim()
    .notEmpty()                      .withMessage('Username is required.')
    .isLength({ min: 3, max: 64 })   .withMessage('Username must be 3–64 characters.')
    .matches(/^[a-zA-Z0-9_\-.]+$/)   .withMessage('Username: letters, numbers, _ - . only.'),
  ...passwordRules,
];

const loginRules = [
  body('username').trim().notEmpty().withMessage('Username is required.'),
  body('password').notEmpty()       .withMessage('Password is required.'),
];

const changePasswordRules = [
  body('currentPassword').notEmpty().withMessage('Current password is required.'),
  ...passwordRules,
];

// POST /api/auth/register
router.post('/register', registerRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    const [existing] = await pool.execute(
      'SELECT id FROM app_users WHERE username = ?', [username]
    );
    if (existing.length > 0) {
      return res.status(409).json({ error: 'Username already in use.' });
    }

    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    await pool.execute(
      'INSERT INTO app_users (username, is_admin, must_change_password, password_hash) VALUES (?, 0, 0, ?)',
      [username, hash]
    );
    return res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error('[POST /api/auth/register]', err.message);
    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ error: 'Username already in use.' });
    }
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/login
router.post('/login', loginRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    const [rows] = await pool.execute(
      'SELECT id, is_admin, must_change_password, password_hash FROM app_users WHERE username = ?',
      [username]
    );

    // Always run bcrypt to prevent timing-based username enumeration
    const dummyHash = '$2a$12$invalidhashforthispurposeXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';
    const hash = rows.length > 0 ? rows[0].password_hash : dummyHash;
    const valid = await bcrypt.compare(password, hash);

    if (!valid || rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const user = rows[0];
    const mustChangePassword = user.must_change_password === 1;

    const token = jwt.sign(
      { sub: user.id, username, isAdmin: user.is_admin === 1, mustChangePassword },
      process.env.JWT_SECRET,
      { algorithm: 'HS256', expiresIn: TOKEN_TTL }
    );

    return res.json({ token, username, isAdmin: user.is_admin === 1, mustChangePassword });
  } catch (err) {
    console.error('[POST /api/auth/login]', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

// POST /api/auth/change-password — requires valid JWT
router.post('/change-password', authenticate, changePasswordRules, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({ errors: errors.array() });
  }

  const { currentPassword, password: newPassword } = req.body;

  try {
    const [rows] = await pool.execute(
      'SELECT password_hash FROM app_users WHERE id = ?', [req.user.id]
    );
    if (rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const valid = await bcrypt.compare(currentPassword, rows[0].password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const newHash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await pool.execute(
      'UPDATE app_users SET password_hash = ?, must_change_password = 0 WHERE id = ?',
      [newHash, req.user.id]
    );

    return res.json({ message: 'Password updated successfully.' });
  } catch (err) {
    console.error('[POST /api/auth/change-password]', err.message);
    return res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
