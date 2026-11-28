// Controlled security tests for the Buckets service and the shared library (local gateway, real HTTP).
// Owner: Saged. Test IDs (report §12): ST-05, ST-07, ST-08, ST-12, ST-13, plus ST-18 (5f, download and
// delete my Buckets data) and ST-19 (5l, JWT key rotation).
// ST-01/02/06/11/14/16/17 are Salma's (tests/security/transactions-security.mjs);
// ST-03/04/09/10/15 are Omar's.
// Run: node --test tests/buckets-security.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { startGateway, client, recorder, short, today, root } = require('./helpers');

const rec = recorder('buckets-security');
let gw;
let api;
const s = {};

test.before(async () => {
  gw = await startGateway('buckets-security');
  api = client(gw.base);
  const a = await api.post('/api/auth/register', { name: 'Alice', email: 'alice@example.com', password: 'AlicePass2026' });
  const b = await api.post('/api/auth/register', { name: 'Bob', email: 'bob@example.com', password: 'BobPass20266' });
  s.alice = a.body.token; s.bob = b.body.token;
  const bucket = await api.post('/api/buckets', { name: 'Alice Food', monthlyLimit: 900 }, { token: s.alice });
  s.aliceBucket = bucket.body.id;
  const txn = await api.post('/api/transactions', { type: 'expense', amount: 120, date: today(), bucketId: s.aliceBucket, paymentMethod: 'card', note: '<img src=x onerror=alert(1)>' }, { token: s.alice });
  s.aliceTxn = txn.body.transaction.id;
  const rep = await api.post('/api/insights/reports', { type: 'transactions', from: `${today().slice(0, 7)}-01`, to: today() }, { token: s.alice });
  s.aliceReport = rep.body.id;
});
test.after(() => gw.server.close());

test('ST-05 ownership: Bob cannot read, change or delete Alice\'s bucket', async () => {
  const r = await Promise.all([
    api.get(`/api/buckets/${s.aliceBucket}`, { token: s.bob }),
    api.patch(`/api/buckets/${s.aliceBucket}`, { monthlyLimit: 1 }, { token: s.bob }),
    api.del(`/api/buckets/${s.aliceBucket}`, { token: s.bob })
  ]);
  const still = await api.get(`/api/buckets/${s.aliceBucket}`, { token: s.alice });
  const actual = `${r.map(short).join(', ')}; Alice's limit still ${still.body.monthlyLimit}`;
  const pass = r.every((x) => x.status === 404) && still.body.monthlyLimit === 900;
  rec.add('ST-05', 'Ownership (IDOR)', 'Bob uses Alice\'s bucket id with GET, PATCH, DELETE', '404 ×3, Alice\'s bucket unchanged', actual, pass);
  assert.ok(pass, actual);
});

test('ST-07 cross-service ownership: expense into another user\'s bucket', async () => {
  const r = await api.post('/api/transactions', { type: 'expense', amount: 10, date: today(), bucketId: s.aliceBucket, paymentMethod: 'cash' }, { token: s.bob });
  const pass = r.status === 400 && /not refer to one of your buckets/.test(r.body.error.message);
  rec.add('ST-07', 'Ownership (cross-service)', 'Bob logs an expense with Alice\'s bucketId', '400 "not one of your buckets"', `${short(r)} "${r.body.error.message}"`, pass);
  assert.ok(pass);
});

test('ST-08 invalid input rejected safely', async () => {
  const cases = [
    api.post('/api/transactions', { type: 'expense', amount: -50, date: today(), bucketId: s.aliceBucket, paymentMethod: 'card' }, { token: s.alice }),
    api.post('/api/transactions', { type: 'expense', amount: 50, date: '2026-02-30', bucketId: s.aliceBucket, paymentMethod: 'card' }, { token: s.alice }),
    api.post('/api/transactions', { type: 'expense', amount: 'abc', date: today(), bucketId: s.aliceBucket, paymentMethod: 'card' }, { token: s.alice }),
    api.post('/api/buckets', { name: 'x'.repeat(41), monthlyLimit: 10 }, { token: s.alice }),
    api.post('/api/transactions', { type: 'expense', amount: 5, date: today(), bucketId: "' OR 1=1 --", paymentMethod: 'card' }, { token: s.alice }),
    api.call('POST', '/api/buckets', { token: s.alice, headers: { 'content-type': 'application/json' }, raw: '{"name": "broken' })
  ];
  const r = await Promise.all(cases);
  const actual = r.map((x) => `${x.status} ${x.body.error.message}`).join(' | ');
  const pass = r.every((x) => x.status === 400);
  rec.add('ST-08', 'Input validation', 'amount -50; date 2026-02-30; amount "abc"; 41-char name; injection-style bucketId; broken JSON', '400 ×6 with a clear message', actual, pass);
  assert.ok(pass, actual);
});

test('ST-12 security headers and CORS allow-list', async () => {
  const ok = await api.get('/api/auth/health', { headers: { origin: 'http://localhost:8080' } });
  const evil = await api.get('/api/auth/health', { headers: { origin: 'https://evil.example' } });
  const h = ok.headers;
  const actual = `nosniff=${h.get('x-content-type-options')}, frame=${h.get('x-frame-options')}, x-powered-by=${h.get('x-powered-by')}; ACAO for allowed origin=${h.get('access-control-allow-origin')}, for evil origin=${evil.headers.get('access-control-allow-origin')}`;
  const pass = h.get('x-content-type-options') === 'nosniff' && h.get('x-frame-options') === 'DENY' && !h.get('x-powered-by')
    && h.get('access-control-allow-origin') === 'http://localhost:8080' && !evil.headers.get('access-control-allow-origin');
  rec.add('ST-12', 'Secure configuration', 'Response headers; CORS from allowed vs unknown origin', 'nosniff, DENY, no x-powered-by; CORS only for localhost:8080', actual, pass);
  assert.ok(pass, actual);
});

test('ST-13 stored XSS / CSV injection payloads stay inert data', async () => {
  const t = await api.get(`/api/transactions/${s.aliceTxn}`, { token: s.alice });
  await api.post('/api/transactions', { type: 'expense', amount: 1, date: today(), bucketId: s.aliceBucket, paymentMethod: 'cash', note: '=HYPERLINK("http://evil","click")' }, { token: s.alice });
  const rep = await api.post('/api/insights/reports', { type: 'transactions', from: `${today().slice(0, 7)}-01`, to: today() }, { token: s.alice });
  const dl = await api.get(`/api/insights/reports/${rep.body.id}/download`, { token: s.alice });
  const csvSafe = dl.body.content.includes('"\'=HYPERLINK') && !/,=HYPERLINK/.test(dl.body.content);
  const usesInnerHtml = fs.readdirSync(path.join(root, 'frontend/js')).some((f) => /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(/.test(fs.readFileSync(path.join(root, 'frontend/js', f), 'utf8')));
  const actual = `note stored as text "${t.body.note}"; CSV cell escaped=${csvSafe}; frontend uses innerHTML=${usesInnerHtml}`;
  const pass = t.body.note === '<img src=x onerror=alert(1)>' && csvSafe && !usesInnerHtml;
  rec.add('ST-13', 'Application', 'XSS payload in a note; =HYPERLINK formula in a note exported to CSV; frontend code review', 'stored as plain text; CSV cell prefixed with \'; no innerHTML in frontend', actual, pass);
  assert.ok(pass, actual);
});

test('ST-18 privacy rights: export and erase own buckets data only (Egypt PDPL)', async () => {
  // ENHANCEMENTS 5f (Buckets part). Same contract as the other services: {"confirm": true}. Dina and Eslam each have a bucket; Dina downloads and then erases her data.
  const dina = (await api.post('/api/auth/register', { name: 'Dina', email: 'dina@example.com', password: 'DinaPass2026' })).body.token;
  const eslam = (await api.post('/api/auth/register', { name: 'Eslam', email: 'eslam@example.com', password: 'EslamPass2026' })).body.token;
  await api.post('/api/buckets', { name: 'Books', monthlyLimit: 300 }, { token: dina });
  await api.post('/api/buckets', { name: 'Coffee', monthlyLimit: 200 }, { token: eslam });
  const noToken = await api.get('/api/buckets/me/export');
  const exp = await api.get('/api/buckets/me/export', { token: dina });
  const leaks = JSON.stringify(exp.body).includes('Coffee');
  const noConfirm = await api.del('/api/buckets/me', { token: dina, body: {} });
  const erase = await api.del('/api/buckets/me', { token: dina, body: { confirm: true } });
  const dinaAfter = await api.get('/api/buckets?includeArchived=true', { token: dina });
  const eslamAfter = await api.get('/api/buckets', { token: eslam });
  const actual = `no token ${noToken.status}; export ${exp.status} buckets=${exp.body.buckets && exp.body.buckets.map((b) => b.name)} ` +
    `other user's data=${leaks}; erase without confirm ${short(noConfirm)}; erase ${erase.status} deleted=${erase.body.deleted}; ` +
    `Dina now ${dinaAfter.body.count} buckets; Eslam still ${eslamAfter.body.count}`;
  const pass = noToken.status === 401 && exp.status === 200 && exp.body.buckets.length === 1 && exp.body.buckets[0].name === 'Books' &&
    !leaks && !('pk' in exp.body.buckets[0]) && noConfirm.status === 400 && erase.status === 200 && erase.body.deleted >= 1 &&
    dinaAfter.body.count === 0 && eslamAfter.body.count === 1;
  rec.add('ST-18', 'Privacy (PDPL)', 'Dina exports her buckets data, tries to erase without confirming, then erases it; Eslam\'s data is checked',
    '401 without token; 200 with only Dina\'s bucket; 400; 200; Dina 0 buckets, Eslam 1', actual, pass);
  assert.ok(pass, actual);
});

test('ST-19 JWT key rotation: old tokens still work, forged keys do not', async () => {
  // Rotation (infra/security/setup-rotation.sh): new key signs, previous key still verifies.
  const crypto = require('crypto');
  const services = ['auth', 'buckets', 'transactions', 'insights'];
  const resetKeys = () => services.forEach((s) =>
    require(path.join(root, `services/${s}-service/node_modules/pb-common/lib/secrets.js`)).clearSecretCache());
  const key1 = process.env.JWT_SECRET;
  const key2 = crypto.randomBytes(32).toString('hex');
  await api.post('/api/auth/register', { name: 'Farah', email: 'farah@example.com', password: 'FarahPass2026' });
  const login = async () => (await api.post('/api/auth/login', { email: 'farah@example.com', password: 'FarahPass2026' })).body.token;
  const oldToken = await login();
  process.env.JWT_SECRET = key2; process.env.JWT_SECRET_PREVIOUS = key1; resetKeys();   // the rotation
  const oldAfter = await api.get('/api/buckets', { token: oldToken });
  const newToken = await login();
  const newAfter = await api.get('/api/buckets', { token: newToken });
  const { jwt, ISSUER, AUDIENCE } = require(path.join(root, 'services/auth-service/node_modules/pb-common'));
  const claims = JSON.parse(Buffer.from(newToken.split('.')[1], 'base64url').toString());
  const forged = jwt.sign({ sub: claims.sub, role: 'admin' }, crypto.randomBytes(32).toString('hex'), { issuer: ISSUER, audience: AUDIENCE });
  const forgedR = await api.get('/api/buckets', { token: forged });
  delete process.env.JWT_SECRET_PREVIOUS; resetKeys();                                    // next rotation: key1 retired
  const retired = await api.get('/api/buckets', { token: oldToken });
  process.env.JWT_SECRET = key1; resetKeys();
  const actual = `old token after rotation ${oldAfter.status}; new token ${newAfter.status}; token from an unknown key ${forgedR.status}; old token once its key is retired ${retired.status}`;
  const pass = oldAfter.status === 200 && newAfter.status === 200 && forgedR.status === 401 && retired.status === 401;
  rec.add('ST-19', 'Authentication', 'Farah logs in, the signing key is rotated, she uses the old and a new token; a token signed with an unknown key; the old key is retired',
    '200; 200; 401; 401', actual, pass);
  assert.ok(pass, actual);
});
