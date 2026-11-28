// Buckets & Budgets service (owner: Student 244694).
// Business capability: plan spending with buckets and enforce monthly budgets.
//
// Table PBBuckets (env BUCKETS_TABLE), pk/sk design:
//   USER#<uid>  BUCKET#<id>                       a spending bucket with its monthly budget
//   USER#<uid>  TRANSFER#<YYYY-MM>#<id>           budget moved between two buckets for a month
//   USER#<uid>  ALERT#<id>                        near-limit / over-limit alert
//   USER#<uid>  ALERTKEY#<month>#<bucket>#<level> alert de-duplication marker
//   TEMPLATE    TEMPLATE#<id>                     admin-defined bucket template
//
// Talks to the Transactions service (GET /api/transactions/summary, /count) for the amounts
// spent, and is called by it (POST /:id/check-spend, POST /:id/evaluate) before/after an
// expense is saved.
const crypto = require('crypto');
const express = require('express');
const {
  createStore, createAuth, validate, wrap, errors, checkId, callService,
  parseMonth, parseDay, currentMonth, addMonths, round2
} = require('pb-common');
const { bucketStatus, projectSpend, checkTransfer } = require('../lib/budget');
const { createAlerts } = require('../lib/alerts');

const MAX_ACTIVE_BUCKETS = 15;
const COLOR = /^#[0-9a-fA-F]{6}$/;

const bucketSchema = {
  name: { type: 'string', required: true, minLength: 2, maxLength: 40 },
  monthlyLimit: { type: 'number', required: true, min: 0, max: 10000000, decimals: 2 },
  alertThreshold: { type: 'integer', min: 50, max: 100, default: 80 },
  rollover: { type: 'boolean', default: false },
  hardLimit: { type: 'boolean', default: false },
  color: { type: 'string', pattern: COLOR, default: '#2E7D6B', patternMessage: 'color must be a hex colour like #2E7D6B.' },
  templateId: { type: 'string', pattern: /^[A-Za-z0-9_-]{6,64}$/ }
};
const updateSchema = { ...bucketSchema };
delete updateSchema.templateId;
const transferSchema = {
  fromBucketId: { type: 'string', required: true, pattern: /^[A-Za-z0-9_-]{6,64}$/ },
  toBucketId: { type: 'string', required: true, pattern: /^[A-Za-z0-9_-]{6,64}$/ },
  amount: { type: 'number', required: true, min: 0.01, max: 10000000, decimals: 2 },
  month: { type: 'string', required: true, pattern: /^\d{4}-(0[1-9]|1[0-2])$/, patternMessage: 'month must be YYYY-MM.' },
  note: { type: 'string', maxLength: 120 }
};
const checkSpendSchema = {
  amount: { type: 'number', required: true, min: 0.01, max: 10000000 },
  date: { type: 'string', required: true },
  replacingAmount: { type: 'number', min: 0, max: 10000000, default: 0 }
};
const templateSchema = {
  name: { type: 'string', required: true, minLength: 2, maxLength: 40 },
  suggestedLimit: { type: 'number', required: true, min: 0, max: 10000000, decimals: 2 },
  alertThreshold: { type: 'integer', min: 50, max: 100, default: 80 },
  color: { type: 'string', pattern: COLOR, default: '#2E7D6B' }
};

const newId = () => crypto.randomUUID().replace(/-/g, '').slice(0, 20);
const userPk = (req) => `USER#${req.user.id}`;

function publicBucket(b) {
  const { pk, sk, nameKey, ...rest } = b;
  return rest;
}

function createBucketRoutes(logger) {
  const store = createStore('BUCKETS_TABLE');
  const alerts = createAlerts(store, logger);
  const { requireAuth, requireRole } = createAuth(logger);
  const router = express.Router();
  router.use(requireAuth);

  // ----- helpers -----
  async function loadBucket(req, id) {
    checkId(id, 'bucket id');
    const bucket = await store.get(userPk(req), `BUCKET#${id}`);
    if (!bucket) {
      // Another user's bucket id gives the same 404 as a missing one (no information leak)
      logger.warn('BUCKET_NOT_FOUND_OR_NOT_OWNED', { requestId: req.requestId, userId: req.user.id, bucketId: id });
      throw errors.notFound('Bucket');
    }
    return bucket;
  }

  async function listBuckets(req) {
    return store.query(userPk(req), { prefix: 'BUCKET#' });
  }

  async function transfersFor(req, month) {
    return store.query(userPk(req), { prefix: `TRANSFER#${month}#` });
  }

  // Spending per bucket for a month and the month before it (from the Transactions service)
  async function spendingFor(req, month) {
    const prev = addMonths(month, -1);
    const r = await callService('transactions', {
      path: '/api/transactions/summary',
      query: { fromMonth: prev, toMonth: month },
      authHeader: req.authHeader,
      requestId: req.requestId
    });
    if (r.status !== 200) {
      logger.error('DEPENDENCY_ERROR', { requestId: req.requestId, target: 'transactions', status: r.status });
      throw errors.unavailable('DEPENDENCY_ERROR', 'Spending data is not available right now.');
    }
    const months = r.body.months || {};
    return {
      current: (months[month] && months[month].byBucket) || {},
      previous: (months[prev] && months[prev].byBucket) || {}
    };
  }

  async function statusFor(req, buckets, month) {
    const [spending, transfers, prevTransfers] = await Promise.all([
      spendingFor(req, month), transfersFor(req, month), transfersFor(req, addMonths(month, -1))
    ]);
    return buckets.map((b) => ({
      ...publicBucket(b),
      budget: bucketStatus(b, month, {
        spent: spending.current[b.id] || 0,
        prevSpent: spending.previous[b.id] || 0,
        transfers,
        prevTransfers
      })
    }));
  }

  async function ensureUniqueName(req, name, exceptId) {
    const key = name.toLowerCase();
    const clash = (await listBuckets(req)).find((b) => b.nameKey === key && b.status === 'active' && b.id !== exceptId);
    if (clash) throw errors.conflict('BUCKET_NAME_TAKEN', `You already have an active bucket named "${clash.name}".`);
  }

  // ----- templates (admin manages, everyone can read) -----
  router.get('/templates', wrap(async (req, res) => {
    const items = (await store.query('TEMPLATE', { prefix: 'TEMPLATE#' })).map(publicBucket);
    res.status(200).json({ items, count: items.length });
  }));

  router.post('/templates', requireRole('admin'), wrap(async (req, res) => {
    const input = validate(req.body, templateSchema);
    const id = newId();
    const item = { pk: 'TEMPLATE', sk: `TEMPLATE#${id}`, id, ...input, createdBy: req.user.id, createdAt: new Date().toISOString() };
    await store.put(item);
    logger.info('TEMPLATE_CREATED', { requestId: req.requestId, adminId: req.user.id, templateId: id });
    res.status(201).json(publicBucket(item));
  }));

  router.delete('/templates/:id', requireRole('admin'), wrap(async (req, res) => {
    const id = checkId(req.params.id, 'template id');
    const removed = await store.remove('TEMPLATE', `TEMPLATE#${id}`);
    if (!removed) throw errors.notFound('Template');
    logger.info('TEMPLATE_DELETED', { requestId: req.requestId, adminId: req.user.id, templateId: id });
    res.status(204).end();
  }));

  // ----- admin statistics (aggregated: no personal amounts) -----
  router.get('/admin/stats', requireRole('admin'), wrap(async (req, res) => {
    const all = await store.scan();
    const buckets = all.filter((i) => i.sk.startsWith('BUCKET#'));
    const alertItems = all.filter((i) => i.sk.startsWith('ALERT#'));
    res.status(200).json({
      buckets: buckets.length,
      activeBuckets: buckets.filter((b) => b.status === 'active').length,
      usersWithBuckets: new Set(buckets.map((b) => b.userId)).size,
      alertsRaised: alertItems.length,
      overLimitAlerts: alertItems.filter((a) => a.level === 'OVER_LIMIT').length,
      templates: all.filter((i) => i.pk === 'TEMPLATE').length
    });
  }));

  // ----- alerts -----
  router.get('/alerts', wrap(async (req, res) => {
    const onlyOpen = req.query.unacknowledged === 'true';
    let items = await store.query(userPk(req), { prefix: 'ALERT#', desc: true, limit: 100 });
    if (onlyOpen) items = items.filter((a) => !a.acknowledged);
    res.status(200).json({ items: items.map(publicBucket), count: items.length });
  }));

  router.patch('/alerts/:id', wrap(async (req, res) => {
    const id = checkId(req.params.id, 'alert id');
    const { acknowledged } = validate(req.body, { acknowledged: { type: 'boolean', required: true } });
    const updated = await store.update(userPk(req), `ALERT#${id}`, { acknowledged, acknowledgedAt: new Date().toISOString() });
    if (!updated) throw errors.notFound('Alert');
    res.status(200).json(publicBucket(updated));
  }));

  // ----- transfers (move budget between buckets) -----
  router.get('/transfers', wrap(async (req, res) => {
    const month = parseMonth(req.query.month, 'month', { def: currentMonth() });
    const items = (await transfersFor(req, month)).map(publicBucket);
    res.status(200).json({ month, items, count: items.length });
  }));

  router.post('/transfers', wrap(async (req, res) => {
    const input = validate(req.body, transferSchema);
    const from = await loadBucket(req, input.fromBucketId);
    const to = await loadBucket(req, input.toBucketId);
    const [fromWithStatus] = await statusFor(req, [from], input.month);
    const problem = checkTransfer({
      from, to, fromStatus: fromWithStatus.budget, amount: input.amount, month: input.month, current: currentMonth()
    });
    if (problem) {
      const status = problem.code === 'SAME_BUCKET' ? 400 : problem.code === 'BUCKET_ARCHIVED' ? 409 : 422;
      const e = errors.unprocessable(problem.code, problem.message, problem.details);
      e.status = status;
      throw e;
    }
    const id = newId();
    const transfer = {
      pk: userPk(req), sk: `TRANSFER#${input.month}#${id}`, id, userId: req.user.id,
      fromBucketId: from.id, fromBucketName: from.name, toBucketId: to.id, toBucketName: to.name,
      amount: round2(input.amount), month: input.month, note: input.note || '', createdAt: new Date().toISOString()
    };
    await store.put(transfer);
    logger.info('BUDGET_TRANSFERRED', { requestId: req.requestId, userId: req.user.id, transferId: id, month: input.month });
    res.status(201).json(publicBucket(transfer));
  }));

  // ----- privacy rights (ENHANCEMENTS 5f, Egypt PDPL 151/2020: access and erasure) -----
  // Only the caller's own partition (USER#<their id>) is read or deleted: the key design makes it
  // impossible to reach another user's data. The Auth service calls both with the user's token
  // when the user asks to download their data or delete their account.
  const EXPORT_KIND = { BUCKET: 'buckets', TRANSFER: 'transfers', ALERT: 'alerts' };

  router.get('/me/export', wrap(async (req, res) => {
    const items = await store.query(userPk(req));
    const data = { buckets: [], transfers: [], alerts: [] };
    for (const item of items) {
      const kind = EXPORT_KIND[item.sk.split('#')[0]];
      if (kind) data[kind].push(publicBucket(item));   // ALERTKEY markers are internal: not personal data
    }
    logger.info('DATA_EXPORTED', { requestId: req.requestId, userId: req.user.id, items: items.length });
    res.set('Content-Disposition', 'attachment; filename="my-buckets-data.json"');
    res.status(200).json({ service: 'buckets', userId: req.user.id, exportedAt: new Date().toISOString(), ...data });
  }));

  router.delete('/me', wrap(async (req, res) => {
    // Same contract as Transactions and Insights: the Auth service sends {"confirm": true} to every service
    const { confirm } = validate(req.body || {}, { confirm: { type: 'boolean', required: true } });
    if (confirm !== true) throw errors.badRequest('Send {"confirm": true} to delete all your buckets data.');
    const items = await store.query(userPk(req));
    for (const item of items) await store.remove(item.pk, item.sk);
    logger.info('DATA_ERASED', { requestId: req.requestId, userId: req.user.id, items: items.length });
    res.status(200).json({ service: 'buckets', deleted: items.length });
  }));

  // ----- buckets -----
  // List buckets with their live budget status for a month (default: this month)
  router.get('/', wrap(async (req, res) => {
    const month = parseMonth(req.query.month, 'month', { def: currentMonth() });
    let buckets = await listBuckets(req);
    if (req.query.includeArchived !== 'true') buckets = buckets.filter((b) => b.status === 'active');
    buckets.sort((a, b) => a.name.localeCompare(b.name));
    const items = await statusFor(req, buckets, month);
    for (const item of items) {
      const stored = buckets.find((b) => b.id === item.id);
      if (stored.status === 'active') await alerts.raiseIfNeeded(req.user.id, stored, item.budget, req.requestId);
    }
    const totals = items.reduce((acc, b) => ({
      effectiveLimit: round2(acc.effectiveLimit + b.budget.effectiveLimit),
      spent: round2(acc.spent + b.budget.spent)
    }), { effectiveLimit: 0, spent: 0 });
    totals.remaining = round2(totals.effectiveLimit - totals.spent);
    res.status(200).json({ month, items, count: items.length, totals });
  }));

  router.post('/', wrap(async (req, res) => {
    const input = validate(req.body, bucketSchema);
    if (input.templateId) {
      const template = await store.get('TEMPLATE', `TEMPLATE#${input.templateId}`);
      if (!template) throw errors.notFound('Template');
    }
    await ensureUniqueName(req, input.name);
    const active = (await listBuckets(req)).filter((b) => b.status === 'active');
    if (active.length >= MAX_ACTIVE_BUCKETS) {
      throw errors.unprocessable('BUCKET_LIMIT_REACHED', `You can have at most ${MAX_ACTIVE_BUCKETS} active buckets. Archive one first.`);
    }
    const id = newId();
    const now = new Date().toISOString();
    const bucket = {
      pk: userPk(req), sk: `BUCKET#${id}`, id, userId: req.user.id,
      name: input.name, nameKey: input.name.toLowerCase(), monthlyLimit: round2(input.monthlyLimit),
      alertThreshold: input.alertThreshold, rollover: input.rollover, hardLimit: input.hardLimit,
      color: input.color, templateId: input.templateId || null, status: 'active', createdAt: now, updatedAt: now
    };
    await store.put(bucket);
    logger.info('BUCKET_CREATED', { requestId: req.requestId, userId: req.user.id, bucketId: id });
    res.status(201).json(publicBucket(bucket));
  }));

  router.get('/:id', wrap(async (req, res) => {
    const bucket = await loadBucket(req, req.params.id);
    const month = parseMonth(req.query.month, 'month', { def: currentMonth() });
    const [item] = await statusFor(req, [bucket], month);
    res.status(200).json(item);
  }));

  router.patch('/:id', wrap(async (req, res) => {
    const bucket = await loadBucket(req, req.params.id);
    if (bucket.status !== 'active') throw errors.conflict('BUCKET_ARCHIVED', 'Restore the bucket before editing it.');
    const changes = validate(req.body, updateSchema, { partial: true });
    if (changes.name) {
      await ensureUniqueName(req, changes.name, bucket.id);
      changes.nameKey = changes.name.toLowerCase();
    }
    if (changes.monthlyLimit !== undefined) changes.monthlyLimit = round2(changes.monthlyLimit);
    const updated = await store.update(bucket.pk, bucket.sk, { ...changes, updatedAt: new Date().toISOString() });
    const [item] = await statusFor(req, [updated], currentMonth());
    await alerts.raiseIfNeeded(req.user.id, updated, item.budget, req.requestId);
    const body = { ...item };
    if (item.budget.state === 'OVER_LIMIT') body.warning = 'The new limit is lower than what was already spent this month.';
    logger.info('BUCKET_UPDATED', { requestId: req.requestId, userId: req.user.id, bucketId: bucket.id, fields: Object.keys(changes) });
    res.status(200).json(body);
  }));

  // Delete only when no transaction uses the bucket; otherwise it must be archived (keeps history)
  router.delete('/:id', wrap(async (req, res) => {
    const bucket = await loadBucket(req, req.params.id);
    const r = await callService('transactions', {
      path: `/api/transactions/by-bucket/${bucket.id}/count`, authHeader: req.authHeader, requestId: req.requestId
    });
    if (r.status !== 200) throw errors.unavailable('DEPENDENCY_ERROR', 'Could not check the bucket transactions.');
    if (r.body.count > 0) {
      throw errors.conflict('BUCKET_HAS_TRANSACTIONS',
        `This bucket has ${r.body.count} transaction(s). Archive it instead to keep your history.`, { count: r.body.count });
    }
    await store.remove(bucket.pk, bucket.sk);
    logger.info('BUCKET_DELETED', { requestId: req.requestId, userId: req.user.id, bucketId: bucket.id });
    res.status(204).end();
  }));

  router.post('/:id/archive', wrap(async (req, res) => {
    const bucket = await loadBucket(req, req.params.id);
    if (bucket.status === 'archived') throw errors.conflict('ALREADY_ARCHIVED', 'The bucket is already archived.');
    const updated = await store.update(bucket.pk, bucket.sk, { status: 'archived', updatedAt: new Date().toISOString() });
    logger.info('BUCKET_ARCHIVED', { requestId: req.requestId, userId: req.user.id, bucketId: bucket.id });
    res.status(200).json(publicBucket(updated));
  }));

  router.post('/:id/restore', wrap(async (req, res) => {
    const bucket = await loadBucket(req, req.params.id);
    if (bucket.status === 'active') throw errors.conflict('ALREADY_ACTIVE', 'The bucket is already active.');
    await ensureUniqueName(req, bucket.name, bucket.id);
    const active = (await listBuckets(req)).filter((b) => b.status === 'active');
    if (active.length >= MAX_ACTIVE_BUCKETS) {
      throw errors.unprocessable('BUCKET_LIMIT_REACHED', `You can have at most ${MAX_ACTIVE_BUCKETS} active buckets.`);
    }
    const updated = await store.update(bucket.pk, bucket.sk, { status: 'active', updatedAt: new Date().toISOString() });
    res.status(200).json(publicBucket(updated));
  }));

  // Hard-limit lock (attack pack AT-05): with a hard limit, two expenses sent at the same moment both
  // saw the old total and both passed (10 x 30 on a limit of 100 → 300 spent). Now check-spend takes a
  // short lock on the bucket, and evaluate (called after the expense is saved) releases it, so the next
  // expense sees the new total. The lock expires by itself if the Transactions service stops half-way.
  const SPEND_LOCK_MS = 5000;
  const SPEND_LOCK_WAIT_MS = 8000;
  const spendLockKey = (bucketId) => `SPENDLOCK#${bucketId}`;
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  async function takeSpendLock(req, bucketId) {
    const deadline = Date.now() + SPEND_LOCK_WAIT_MS;
    let wait = 20;
    while (Date.now() < deadline) {
      if (await store.acquireLock(userPk(req), spendLockKey(bucketId), req.requestId, SPEND_LOCK_MS)) return true;
      await sleep(wait + Math.floor(Math.random() * wait));
      wait = Math.min(wait * 2, 250);
    }
    return false;
  }

  // Called by the Transactions service BEFORE saving an expense
  router.post('/:id/check-spend', wrap(async (req, res) => {
    const bucket = await loadBucket(req, req.params.id);
    if (bucket.status !== 'active') throw errors.conflict('BUCKET_ARCHIVED', 'This bucket is archived and cannot receive new expenses.');
    const input = validate(req.body, checkSpendSchema);
    const day = parseDay(input.date);
    const month = day.slice(0, 7);
    if (bucket.hardLimit && !(await takeSpendLock(req, bucket.id))) {
      logger.warn('SPEND_LOCK_BUSY', { requestId: req.requestId, userId: req.user.id, bucketId: bucket.id });
      throw errors.conflict('BUCKET_BUSY', 'Another expense for this bucket is being saved. Please try again.');
    }
    const [item] = await statusFor(req, [bucket], month);
    const projection = projectSpend(bucket, item.budget, input.amount, input.replacingAmount);
    if (!projection.allowed) {
      logger.warn('SPEND_BLOCKED_HARD_LIMIT', { requestId: req.requestId, userId: req.user.id, bucketId: bucket.id, month });
      if (bucket.hardLimit) await store.releaseLock(userPk(req), spendLockKey(bucket.id), req.requestId);
    }
    res.status(200).json({ bucket: { id: bucket.id, name: bucket.name, hardLimit: bucket.hardLimit }, month, ...projection });
  }));

  // Called by the Transactions service AFTER an expense was saved: raises alerts if needed
  router.post('/:id/evaluate', wrap(async (req, res) => {
    const bucket = await loadBucket(req, req.params.id);
    const { month } = validate(req.body, {
      month: { type: 'string', required: true, pattern: /^\d{4}-(0[1-9]|1[0-2])$/ }
    });
    // The expense is saved now: let the next expense for this bucket through (only the holder can release)
    if (bucket.hardLimit) await store.releaseLock(userPk(req), spendLockKey(bucket.id), req.requestId);
    const [item] = await statusFor(req, [bucket], month);
    const alert = bucket.status === 'active' ? await alerts.raiseIfNeeded(req.user.id, bucket, item.budget, req.requestId) : null;
    res.status(200).json({ budget: item.budget, alertRaised: Boolean(alert), alert: alert ? publicBucket(alert) : null });
  }));

  return router;
}

module.exports = { createBucketRoutes };
