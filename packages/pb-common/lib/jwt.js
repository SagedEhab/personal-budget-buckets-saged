// Minimal HS256 JSON Web Token implementation using only Node's crypto module.
// Written by hand (no library) so every step can be explained in the discussion:
//   token = base64url(header) . base64url(payload) . base64url(HMAC-SHA256(secret, header.payload))
// The signing secret is NOT in the code: it is loaded from AWS Secrets Manager (lib/secrets.js).
const crypto = require('crypto');

const b64url = (input) => Buffer.from(input).toString('base64url');
const fromB64url = (input) => Buffer.from(input, 'base64url').toString('utf8');

function hmac(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

function sign(claims, secret, { expiresInSec = 3600, issuer, audience } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { ...claims, iat: now, exp: now + expiresInSec };
  if (issuer) payload.iss = issuer;
  if (audience) payload.aud = audience;
  const body = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(payload))}`;
  return `${body}.${hmac(secret, body)}`;
}

// Returns { ok: true, claims } or { ok: false, reason }.
function verify(token, secret, { issuer, audience } = {}) {
  if (typeof token !== 'string') return { ok: false, reason: 'missing' };
  const parts = token.split('.');
  if (parts.length !== 3) return { ok: false, reason: 'malformed' };
  const [h, p, s] = parts;

  let header;
  let payload;
  try {
    header = JSON.parse(fromB64url(h));
    payload = JSON.parse(fromB64url(p));
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  // Only HS256 is accepted: blocks the "alg: none" and algorithm-confusion attacks.
  if (!header || header.alg !== 'HS256') return { ok: false, reason: 'bad_algorithm' };

  const expected = Buffer.from(hmac(secret, `${h}.${p}`));
  const given = Buffer.from(s);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) {
    return { ok: false, reason: 'bad_signature' };
  }
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== 'number' || payload.exp <= now) return { ok: false, reason: 'expired' };
  if (issuer && payload.iss !== issuer) return { ok: false, reason: 'bad_issuer' };
  if (audience && payload.aud !== audience) return { ok: false, reason: 'bad_audience' };
  return { ok: true, claims: payload };
}

module.exports = { sign, verify };
