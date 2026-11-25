// Budget business rules for the Buckets & Budgets service (pure functions: no database,
// no HTTP), so each rule can be unit-tested and explained on its own.
//
// Effective limit of a bucket for a month:
//   effectiveLimit = monthlyLimit + rolloverIn + transfersIn - transfersOut
//   rolloverIn     = unused budget of the previous month, only when rollover is ON,
//                    capped at one monthlyLimit (so savings cannot snowball forever)
// State:
//   OVER_LIMIT  spent > effectiveLimit
//   NEAR_LIMIT  spent >= alertThreshold % of effectiveLimit
//   OK          otherwise
const { round2 } = require('pb-common');

function sumTransfers(transfers, bucketId) {
  let inAmount = 0;
  let outAmount = 0;
  for (const t of transfers) {
    if (t.toBucketId === bucketId) inAmount += t.amount;
    if (t.fromBucketId === bucketId) outAmount += t.amount;
  }
  return { inAmount: round2(inAmount), outAmount: round2(outAmount) };
}

function computeRollover(bucket, month, prevSpent, prevTransfers) {
  if (!bucket.rollover) return 0;
  // A bucket created this month has no previous month to roll over from.
  if (!bucket.createdAt || bucket.createdAt.slice(0, 7) >= month) return 0;
  const prev = sumTransfers(prevTransfers, bucket.id);
  const prevLimit = bucket.monthlyLimit + prev.inAmount - prev.outAmount;
  const unused = prevLimit - (prevSpent || 0);
  return round2(Math.min(bucket.monthlyLimit, Math.max(0, unused)));
}

function classify(spent, effectiveLimit, alertThreshold) {
  if (spent > effectiveLimit) return 'OVER_LIMIT';
  if (effectiveLimit <= 0) return spent > 0 ? 'OVER_LIMIT' : 'OK';
  if ((spent / effectiveLimit) * 100 >= alertThreshold) return 'NEAR_LIMIT';
  return 'OK';
}

function percent(spent, effectiveLimit) {
  if (effectiveLimit <= 0) return spent > 0 ? 100 : 0;
  return round2((spent / effectiveLimit) * 100);
}

// bucket: stored bucket; month: 'YYYY-MM'; ctx: { spent, prevSpent, transfers, prevTransfers }
function bucketStatus(bucket, month, ctx) {
  const spent = round2(ctx.spent || 0);
  const rolloverIn = computeRollover(bucket, month, ctx.prevSpent || 0, ctx.prevTransfers || []);
  const t = sumTransfers(ctx.transfers || [], bucket.id);
  const effectiveLimit = round2(bucket.monthlyLimit + rolloverIn + t.inAmount - t.outAmount);
  return {
    month,
    monthlyLimit: bucket.monthlyLimit,
    rolloverIn,
    transfersIn: t.inAmount,
    transfersOut: t.outAmount,
    effectiveLimit,
    spent,
    remaining: round2(effectiveLimit - spent),
    percentUsed: percent(spent, effectiveLimit),
    state: classify(spent, effectiveLimit, bucket.alertThreshold)
  };
}

// Would a new (or edited) expense fit in the bucket?
//   replacingAmount: the old amount when an existing expense in the same bucket is edited
function projectSpend(bucket, status, amount, replacingAmount = 0) {
  const spentAfter = round2(status.spent - replacingAmount + amount);
  const stateAfter = classify(spentAfter, status.effectiveLimit, bucket.alertThreshold);
  const allowed = !(bucket.hardLimit && spentAfter > status.effectiveLimit);
  return {
    allowed,
    spentBefore: status.spent,
    spentAfter,
    effectiveLimit: status.effectiveLimit,
    percentAfter: percent(spentAfter, status.effectiveLimit),
    stateAfter,
    remainingAfter: round2(status.effectiveLimit - spentAfter)
  };
}

// Budget transfer between two buckets of the same user for one month.
function checkTransfer({ from, to, fromStatus, amount, month, current }) {
  if (from.id === to.id) return { code: 'SAME_BUCKET', message: 'Choose two different buckets.' };
  if (from.status !== 'active' || to.status !== 'active') {
    return { code: 'BUCKET_ARCHIVED', message: 'Transfers are only possible between active buckets.' };
  }
  if (month < current) return { code: 'PAST_MONTH', message: 'Budgets of past months cannot be changed.' };
  if (amount > fromStatus.remaining) {
    return {
      code: 'INSUFFICIENT_BUDGET',
      message: `Only ${fromStatus.remaining} is left in "${from.name}" for ${month}.`,
      details: { available: fromStatus.remaining }
    };
  }
  return null;
}

module.exports = { bucketStatus, projectSpend, checkTransfer, classify, computeRollover, sumTransfers };
