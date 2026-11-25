// Date and money helpers shared by the services. Months are 'YYYY-MM', days 'YYYY-MM-DD' (UTC).
const { errors } = require('./errors');

const MONTH_RE = /^(\d{4})-(0[1-9]|1[0-2])$/;
const DAY_RE = /^(\d{4})-(\d{2})-(\d{2})$/;

function currentMonth(now = new Date()) {
  return now.toISOString().slice(0, 7);
}

function today(now = new Date()) {
  return now.toISOString().slice(0, 10);
}

function parseMonth(value, name = 'month', { def } = {}) {
  if (value === undefined || value === '') {
    if (def !== undefined) return def;
    throw errors.badRequest(`${name} is required (YYYY-MM).`);
  }
  const m = MONTH_RE.exec(String(value));
  if (!m || Number(m[1]) < 2000 || Number(m[1]) > 2100) throw errors.badRequest(`${name} must be a month in the format YYYY-MM.`);
  return value;
}

function isValidDay(value) {
  const m = DAY_RE.exec(String(value));
  if (!m) return false;
  const d = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === value && Number(m[1]) >= 2000 && Number(m[1]) <= 2100;
}

function parseDay(value, name = 'date', { def } = {}) {
  if (value === undefined || value === '') {
    if (def !== undefined) return def;
    throw errors.badRequest(`${name} is required (YYYY-MM-DD).`);
  }
  if (!isValidDay(value)) throw errors.badRequest(`${name} must be a real date in the format YYYY-MM-DD.`);
  return value;
}

function addMonths(month, delta) {
  const [y, m] = month.split('-').map(Number);
  const d = new Date(Date.UTC(y, m - 1 + delta, 1));
  return d.toISOString().slice(0, 7);
}

function monthRange(month) {
  const [y, m] = month.split('-').map(Number);
  const last = new Date(Date.UTC(y, m, 0)).getUTCDate();
  return { from: `${month}-01`, to: `${month}-${String(last).padStart(2, '0')}`, days: last };
}

function daysBetween(from, to) {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86400000);
}

function monthsBetween(fromMonth, toMonth) {
  const [fy, fm] = fromMonth.split('-').map(Number);
  const [ty, tm] = toMonth.split('-').map(Number);
  return (ty - fy) * 12 + (tm - fm);
}

const round2 = (n) => Math.round((n + Number.EPSILON) * 100) / 100;

module.exports = {
  currentMonth, today, parseMonth, parseDay, isValidDay, addMonths, monthRange,
  daysBetween, monthsBetween, round2
};
