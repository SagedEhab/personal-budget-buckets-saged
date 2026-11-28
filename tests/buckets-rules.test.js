// Unit tests of the Buckets budget rules (services/buckets-service/lib/budget.js): no HTTP, no database.
// Owner: Saged. Test IDs: UT-01 ... UT-06 (report §12).
// Run: node --test tests/buckets-rules.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { recorder, root } = require('./helpers');

const budget = require(path.join(root, 'services/buckets-service/lib/budget.js'));
const rec = recorder('buckets-rules');

const bucket = (over = {}) => ({ id: 'b1', name: 'Food', monthlyLimit: 1000, alertThreshold: 80, rollover: false, hardLimit: false, status: 'active', createdAt: '2026-09-15T10:00:00Z', ...over });

test('UT-01 effective limit with transfers', () => {
  const s = budget.bucketStatus(bucket(), '2026-11', { spent: 500, transfers: [{ toBucketId: 'b1', amount: 200 }, { fromBucketId: 'b1', amount: 50 }] });
  rec.add('UT-01', 'Buckets', 'effectiveLimit = 1000 + 200 in - 50 out, spent 500', '1150, OK', `${s.effectiveLimit}, ${s.state}`, s.effectiveLimit === 1150 && s.state === 'OK');
  assert.strictEqual(s.effectiveLimit, 1150);
});

test('UT-02 rollover capped at one monthly limit', () => {
  const s = budget.bucketStatus(bucket({ rollover: true }), '2026-11', { spent: 0, prevSpent: 100, prevTransfers: [{ toBucketId: 'b1', amount: 800 }] });
  rec.add('UT-02', 'Buckets', 'rollover of 1700 unused is capped at 1000', 'rolloverIn 1000', `rolloverIn ${s.rolloverIn}`, s.rolloverIn === 1000);
  assert.strictEqual(s.rolloverIn, 1000);
});

test('UT-03 no rollover in the creation month', () => {
  const s = budget.bucketStatus(bucket({ rollover: true, createdAt: '2026-11-02T00:00:00Z' }), '2026-11', { spent: 0, prevSpent: 0 });
  rec.add('UT-03', 'Buckets', 'bucket created this month gets no rollover', 'rolloverIn 0', `rolloverIn ${s.rolloverIn}`, s.rolloverIn === 0);
  assert.strictEqual(s.rolloverIn, 0);
});

test('UT-04 state thresholds', () => {
  const states = [790, 800, 1000, 1000.01].map((spent) => budget.classify(spent, 1000, 80));
  rec.add('UT-04', 'Buckets', 'states at 79%, 80%, 100%, >100%', 'OK, NEAR_LIMIT, NEAR_LIMIT, OVER_LIMIT', states.join(', '),
    states.join() === 'OK,NEAR_LIMIT,NEAR_LIMIT,OVER_LIMIT');
  assert.deepStrictEqual(states, ['OK', 'NEAR_LIMIT', 'NEAR_LIMIT', 'OVER_LIMIT']);
});

test('UT-05 hard limit projection, edit replaces old amount', () => {
  const b = bucket({ hardLimit: true });
  const s = budget.bucketStatus(b, '2026-11', { spent: 900 });
  const blocked = budget.projectSpend(b, s, 150);
  const edit = budget.projectSpend(b, s, 150, 100);
  rec.add('UT-05', 'Buckets', 'hard limit: +150 on 900/1000 blocked; editing a 100 expense to 150 allowed', 'false, true', `${blocked.allowed}, ${edit.allowed}`, !blocked.allowed && edit.allowed);
  assert.strictEqual(blocked.allowed, false);
  assert.strictEqual(edit.allowed, true);
});

test('UT-06 transfer rules', () => {
  const from = bucket();
  const to = bucket({ id: 'b2', name: 'Fun' });
  const st = { remaining: 300 };
  const a = budget.checkTransfer({ from, to, fromStatus: st, amount: 400, month: '2026-11', current: '2026-11' });
  const b = budget.checkTransfer({ from, to, fromStatus: st, amount: 100, month: '2026-10', current: '2026-11' });
  const c = budget.checkTransfer({ from, to: from, fromStatus: st, amount: 100, month: '2026-11', current: '2026-11' });
  const ok = budget.checkTransfer({ from, to, fromStatus: st, amount: 300, month: '2026-11', current: '2026-11' });
  const actual = [a && a.code, b && b.code, c && c.code, ok].join(', ');
  rec.add('UT-06', 'Buckets', 'too much / past month / same bucket / valid', 'INSUFFICIENT_BUDGET, PAST_MONTH, SAME_BUCKET, null', actual,
    actual === 'INSUFFICIENT_BUDGET, PAST_MONTH, SAME_BUCKET, ');
  assert.strictEqual(ok, null);
});

