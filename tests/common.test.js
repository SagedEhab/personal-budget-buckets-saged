// Unit tests of the shared library packages/pb-common (JWT, validator). Owner: Saged.
// Test IDs: UT-09, UT-10 (report §12). The HTTP-level shared checks (headers, CORS, body limit, key
// rotation) are in tests/buckets-security.test.js and tests/lambda-transport.test.js.
// Run: node --test tests/common.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { recorder, root } = require('./helpers');

const { jwt, validate } = require(path.join(root, 'services/buckets-service/node_modules/pb-common'));
const rec = recorder('common');

test('UT-09 JWT rejects alg none, tampering and expiry', () => {
  const secret = 'k'.repeat(40);
  const good = jwt.sign({ sub: 'u1', role: 'user' }, secret);
  const [h, p] = good.split('.');
  const none = `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')}.${p}.`;
  const tampered = `${h}.${Buffer.from(JSON.stringify({ sub: 'u1', role: 'admin', exp: 9999999999 })).toString('base64url')}.${good.split('.')[2]}`;
  const expired = jwt.sign({ sub: 'u1', role: 'user' }, secret, { expiresInSec: -10 });
  const r = [jwt.verify(good, secret).ok, jwt.verify(none, secret).reason, jwt.verify(tampered, secret).reason, jwt.verify(expired, secret).reason].join(', ');
  rec.add('UT-09', 'Shared auth', 'valid / alg none / role changed / expired', 'true, bad_algorithm, bad_signature, expired', r, r === 'true, bad_algorithm, bad_signature, expired');
  assert.strictEqual(r, 'true, bad_algorithm, bad_signature, expired');
});

test('UT-10 validator rejects unknown fields', () => {
  let message = '';
  try { validate({ name: 'x', role: 'admin' }, { name: { type: 'string' } }); } catch (e) { message = `${e.status} ${e.message}`; }
  rec.add('UT-10', 'Shared', 'mass assignment: extra field "role"', '400 role is not an allowed field.', message, message === '400 role is not an allowed field.');
  assert.strictEqual(message, '400 role is not an allowed field.');
});

