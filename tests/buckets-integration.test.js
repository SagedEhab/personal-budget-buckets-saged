// Integrated tests of the Buckets service with Transactions (real HTTP through the local gateway,
// in-memory data). Owner: Saged. Test IDs: IT-02, IT-03, IT-05, IT-06, IT-07 (report §12).
// IT-01, IT-10, IT-12 are Omar's; IT-04, IT-08, IT-09, IT-11 are Salma's.
// Run: node --test tests/buckets-integration.test.js
const test = require('node:test');
const assert = require('node:assert');
const { startGateway, client, recorder, short, today, month } = require('./helpers');

const rec = recorder('buckets-integration');
let gw;
let api;
const s = {}; // shared state between steps

test.before(async () => {
  gw = await startGateway('buckets-integration');
  api = client(gw.base);
  await api.post('/api/auth/register', { name: 'Mona Test', email: 'mona@example.com', password: 'BudgetPass2026' });
  s.token = (await api.post('/api/auth/login', { email: 'mona@example.com', password: 'BudgetPass2026' })).body.token;
});
test.after(() => gw.server.close());

test('IT-02 create buckets; duplicate name; invalid limit', async () => {
  const food = await api.post('/api/buckets', { name: 'Food', monthlyLimit: 1000, alertThreshold: 80 }, { token: s.token });
  const fun = await api.post('/api/buckets', { name: 'Fun', monthlyLimit: 2000 }, { token: s.token });
  const rent = await api.post('/api/buckets', { name: 'Transport', monthlyLimit: 300, hardLimit: true }, { token: s.token });
  s.food = food.body.id; s.fun = fun.body.id; s.transport = rent.body.id;
  const dup = await api.post('/api/buckets', { name: 'food', monthlyLimit: 10 }, { token: s.token });
  const bad = await api.post('/api/buckets', { name: 'X', monthlyLimit: -5 }, { token: s.token });
  const actual = `${food.status}, ${fun.status}, ${rent.status}; dup ${short(dup)}; invalid ${short(bad)}`;
  const pass = food.status === 201 && fun.status === 201 && rent.status === 201 && dup.status === 409 && bad.status === 400;
  rec.add('IT-02', 'Buckets', 'Create Food 1000, Fun 2000, Transport 300 (hard limit); duplicate "food"; name "X" with limit -5', '201 ×3; dup 409 BUCKET_NAME_TAKEN; invalid 400', actual, pass);
  assert.ok(pass, actual);
});

test('IT-03 expense reaches 85% → NEAR_LIMIT alert; future date rejected', async () => {
  const r = await api.post('/api/transactions', { type: 'expense', amount: 850, date: today(), bucketId: s.food, paymentMethod: 'card', note: 'Groceries' }, { token: s.token });
  const alerts = await api.get('/api/buckets/alerts', { token: s.token });
  const future = await api.post('/api/transactions', { type: 'expense', amount: 5, date: '2099-01-01', bucketId: s.food, paymentMethod: 'cash' }, { token: s.token });
  const actual = `${r.status} state=${r.body.budget && r.body.budget.state} alertRaised=${r.body.alertRaised}; alerts=${alerts.body.items.map((a) => a.level).join('/')}; future ${short(future)}`;
  const pass = r.status === 201 && r.body.budget.state === 'NEAR_LIMIT' && r.body.alertRaised && alerts.body.items.length === 1 && future.status === 400;
  rec.add('IT-03', 'Transactions → Buckets', 'Log 850 EGP in Food (limit 1000, alert 80%); log an expense dated 2099', '201 NEAR_LIMIT + 1 alert; future 400', actual, pass);
  assert.ok(pass, actual);
});

test('IT-05 hard-limit bucket blocks overspend', async () => {
  const ok = await api.post('/api/transactions', { type: 'expense', amount: 250, date: today(), bucketId: s.transport, paymentMethod: 'mobile_wallet' }, { token: s.token });
  const blocked = await api.post('/api/transactions', { type: 'expense', amount: 100, date: today(), bucketId: s.transport, paymentMethod: 'cash' }, { token: s.token });
  const list = await api.get('/api/transactions', { token: s.token });
  const count = list.body.items.filter((t) => t.bucketId === s.transport).length;
  const actual = `${ok.status}; then ${short(blocked)}; transactions in bucket = ${count}`;
  const pass = ok.status === 201 && blocked.status === 422 && blocked.body.error.code === 'BUDGET_HARD_LIMIT' && count === 1;
  rec.add('IT-05', 'Transactions → Buckets', 'Transport (hard limit 300): 250 then 100', '201; 422 BUDGET_HARD_LIMIT, nothing saved', actual, pass);
  assert.ok(pass, actual);
});

test('IT-06 budget transfer; too large transfer', async () => {
  const before = await api.get(`/api/buckets/${s.fun}`, { token: s.token });
  const tr = await api.post('/api/buckets/transfers', { fromBucketId: s.fun, toBucketId: s.food, amount: 200, month: month() }, { token: s.token });
  const food = await api.get(`/api/buckets/${s.food}`, { token: s.token });
  const tooBig = await api.post('/api/buckets/transfers', { fromBucketId: s.fun, toBucketId: s.food, amount: 100000, month: month() }, { token: s.token });
  const actual = `${tr.status}; Food effectiveLimit=${food.body.budget.effectiveLimit} state=${food.body.budget.state}; Fun had ${before.body.budget.remaining} left; 100000 → ${short(tooBig)}`;
  const pass = tr.status === 201 && food.body.budget.effectiveLimit === 1200 && tooBig.status === 422 && tooBig.body.error.code === 'INSUFFICIENT_BUDGET';
  rec.add('IT-06', 'Buckets', 'Move 200 from Fun to Food; then move 100000', '201, Food limit 1200; 422 INSUFFICIENT_BUDGET', actual, pass);
  assert.ok(pass, actual);
});

test('IT-07 delete bucket with transactions → 409; archive; expense into archived bucket', async () => {
  // Fun needs at least one expense (the old suite used IT-04's USD expense, which needs the live API)
  await api.post('/api/transactions', { type: 'expense', amount: 40, date: today(), bucketId: s.fun, paymentMethod: 'cash', note: 'Cinema' }, { token: s.token });
  const del = await api.del(`/api/buckets/${s.fun}`, { token: s.token });
  const arch = await api.post(`/api/buckets/${s.fun}/archive`, undefined, { token: s.token });
  const exp = await api.post('/api/transactions', { type: 'expense', amount: 5, date: today(), bucketId: s.fun, paymentMethod: 'cash' }, { token: s.token });
  const empty = await api.post('/api/buckets', { name: 'Gifts', monthlyLimit: 100 }, { token: s.token });
  const delEmpty = await api.del(`/api/buckets/${empty.body.id}`, { token: s.token });
  const actual = `${short(del)}; archive ${arch.status} status=${arch.body.status}; expense ${short(exp)}; empty bucket delete ${delEmpty.status}`;
  const pass = del.status === 409 && arch.status === 200 && exp.status === 409 && delEmpty.status === 204;
  rec.add('IT-07', 'Buckets ↔ Transactions', 'Delete Fun (has transactions), archive it, log expense into it; delete an empty bucket', '409 BUCKET_HAS_TRANSACTIONS; 200 archived; 409 BUCKET_ARCHIVED; 204', actual, pass);
  assert.ok(pass, actual);
});
