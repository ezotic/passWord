'use strict';

require('dotenv').config();

const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const morgan       = require('morgan');
const rateLimit    = require('express-rate-limit');
const bcrypt               = require('bcryptjs');
const { checkConnection, pool } = require('./db');
const { authenticate }     = require('./middleware/authenticate');
const { requireAdmin }     = require('./middleware/requireAdmin');
const authRouter           = require('./routes/auth');
const adminRouter          = require('./routes/admin');
const passwordsRouter      = require('./routes/passwords');

const app  = express();
const PORT = process.env.PORT || 3000;

app.set('trust proxy', 1); // one Nginx hop between client and backend
app.use(helmet());
app.use(cors({ origin: false, methods: ['GET', 'POST', 'DELETE'] }));
app.use(morgan('combined'));
app.use(express.json({ limit: '10kb' }));

const writeLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

const readLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict limiter for auth endpoints — brute-force protection
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts, please try again later.' },
  skipSuccessfulRequests: true,
});

// Auth routes (public — no authenticate middleware)
app.use('/api/auth', authLimiter, authRouter);

// Admin-only routes
app.use('/api/admin', authenticate, requireAdmin, adminRouter);

// Protected password routes
app.get('/api/passwords',        readLimiter,  authenticate);
app.post('/api/passwords',       writeLimiter, authenticate);
app.delete('/api/passwords/:id', writeLimiter, authenticate);
app.use('/api/passwords', passwordsRouter);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));

app.use((err, req, res, _next) => {
  console.error('[unhandled]', err);
  res.status(500).json({ error: 'Internal server error' });
});

async function seedAdmin() {
  const [rows] = await pool.execute('SELECT COUNT(*) AS cnt FROM app_users WHERE is_admin = 1');
  if (rows[0].cnt > 0) {
    console.log('[seed] Admin already exists, skipping.');
    return;
  }
  const hash = await bcrypt.hash('password', 12);
  await pool.execute(
    'INSERT INTO app_users (username, is_admin, must_change_password, password_hash) VALUES (?, 1, 1, ?)',
    ['admin', hash]
  );
  console.log('[seed] Default admin created — username: admin, password: password (must change on first login)');
}

async function start() {
  await checkConnection();
  await seedAdmin();
  app.listen(PORT, () => console.log(`[server] Listening on port ${PORT}`));
}

start().catch(err => {
  console.error('[fatal]', err);
  process.exit(1);
});
