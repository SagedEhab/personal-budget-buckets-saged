// Race-condition tests found by the attack pack (owner: Saged). Local gateway, in-memory data, real HTTP.
// AT-06: parallel wrong passwords must not get more than 5 guesses past the lockout.
// AT-05: parallel expenses must not push a hard-limit bucket over its limit.
// The live versions run against Floci in tests/security/attack-pack.mjs.
// Run: node --test tests/attack-races.test.js
const test = require('node:test');
const assert = require('node:assert');
const { startGateway, client, recorder, today } = require('./helpers');

const rec = recorder('attack-races');
let gw;
let api;

test.before(async () => {
  gw = await startGateway('attack-races');
  api = client(gw.base);
});
test.after(() => gw.server.close());

test('AT-06 lockout holds under 20 parallel wrong passwords', async () => {
  await api.post('/api/auth/register', { name: 'Race', email: 'race@example.com', password: 'RacePass2026' });
  const shots = await Promise.all(Array.from({ length: 20 }, () =>
    api.post('/api/auth/login', { email: 'race@example.com', password: 'WrongPass123' })));
  const checked = shots.filter((r) => r.status === 401).length;
  const locked = shots.filter((r) => r.status === 429).length;
  const right = await api.post('/api/auth/login', { email: 'race@example.com', password: 'RacePass2026' });
  const pass = checked <= 5 && right.status === 429;
  rec.add('AT-06', 'Brute force (race)', '20 wrong passwords in parallel, then the right one',
    'at most 5 checked (401), rest 429; right password refused while locked (429)',
    `${checked} checked, ${locked} got 429; right password → ${right.status}`, pass);
  assert.ok(checked <= 5, `${checked} guesses were checked`);
  assert.strictEqual(right.status, 429);
});

test('AT-05 hard limit holds under 10 parallel expenses', async () => {
  const u = await api.post('/api/auth/register', { name: 'Cap', email: 'cap@example.com', password: 'CapPass20266' });
  const token = u.body.token;
  const b = await api.post('/api/buckets', { name: 'Capped', monthlyLimit: 100, hardLimit: true }, { token });
  const shots = await Promise.all(Array.from({ length: 10 }, () => api.post('/api/transactions',
    { type: 'expense', amount: 30, date: today(), bucketId: b.body.id, paymentMethod: 'cash' }, { token })));
  const accepted = shots.filter((r) => r.status === 201).length;
  const status = await api.get(`/api/buckets/${b.body.id}`, { token });
  const spent = status.body.budget.spent;
  rec.add('AT-05', 'Business logic (race)', '10 expenses of 30 in parallel on a hard limit of 100',
    'spent never above 100', `${accepted} accepted, spent ${spent}`, spent <= 100);
  assert.ok(spent <= 100, `spent ${spent}`);
});
