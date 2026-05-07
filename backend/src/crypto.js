'use strict';

const crypto = require('crypto');

const ALGORITHM  = 'aes-256-gcm';
const IV_BYTES   = 12;
const TAG_BYTES  = 16;

function key() {
  const hex = process.env.ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be a 64-character hex string — run: openssl rand -hex 32');
  }
  return Buffer.from(hex, 'hex');
}

function encrypt(plaintext) {
  const iv     = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key(), iv, { authTagLength: TAG_BYTES });
  const ct     = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return [iv.toString('base64'), cipher.getAuthTag().toString('base64'), ct.toString('base64')].join(':');
}

function decrypt(stored) {
  const parts = stored.split(':');
  if (parts.length !== 3) throw new Error('unexpected format');
  const [ivB64, tagB64, ctB64] = parts;
  const decipher = crypto.createDecipheriv(ALGORITHM, key(), Buffer.from(ivB64, 'base64'), { authTagLength: TAG_BYTES });
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  return decipher.update(Buffer.from(ctB64, 'base64')) + decipher.final('utf8');
}

module.exports = { encrypt, decrypt };
