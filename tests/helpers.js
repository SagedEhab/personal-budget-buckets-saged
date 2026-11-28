// Test harness (owner: Saged): starts all four services behind the local gateway (in-memory data,
// real HTTP), gives small request helpers, and records every check into evidence/<suite>.json.
// Results come from actually running the code: nothing is typed in by hand.
// Used by tests/buckets-*.test.js, tests/common.test.js and tests/lambda-transport.test.js.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.join(__dirname, '..');
const outDir = path.join(root, 'evidence');
fs.mkdirSync(outDir, { recursive: true });

process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
process.env.CORS_ORIGINS = 'http://localhost:8080';

// Offline and repeatable: registration checks passwords against Have I Been Pwned (Omar's 5c, tested in
// tests/auth-breach.test.js). Here every password counts as "not breached", so no internet is needed.
function offlineBreachCheck() {
  require(path.join(root, 'services', 'auth-service', 'lib', 'breachedPasswords'))
    .setFetch(async () => ({ ok: true, text: async () => '' }));
}

function startGateway(suite) {
  offlineBreachCheck();
  process.env.LOG_FILE = path.join(outDir, `${suite}.log.jsonl`);
  fs.writeFileSync(process.env.LOG_FILE, '');
  const { createGateway } = require(path.join(root, 'infra', 'local-gateway.js'));
  const { server, apps } = createGateway();
  return new Promise((resolve) => {
    server.listen(0, () => {
      const base = `http://localhost:${server.address().port}`;
      process.env.INTERNAL_API_URL = base;
      resolve({ server, apps, base });
    });
  });
}

function client(base) {
  async function call(method, p, { body, token, headers = {}, raw } = {}) {
    const h = { ...headers };
    if (body !== undefined && !raw) h['content-type'] = 'application/json';
    if (token) h.authorization = `Bearer ${token}`;
    const res = await fetch(base + p, { method, headers: h, body: raw !== undefined ? raw : body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = text; }
    return { status: res.status, body: json, headers: res.headers };
  }
  return {
    call,
    get: (p, o) => call('GET', p, o),
    post: (p, body, o = {}) => call('POST', p, { ...o, body }),
    patch: (p, body, o = {}) => call('PATCH', p, { ...o, body }),
    del: (p, o) => call('DELETE', p, o)
  };
}

function recorder(suite) {
  const rows = [];
  const file = path.join(outDir, `${suite}.json`);
  return {
    // expected/actual are short human-readable strings; pass is a boolean computed by the test
    add(id, area, scenario, expected, actual, pass, evidence) {
      rows.push({ id, area, scenario, expected, actual, pass: Boolean(pass), evidence: evidence || '' });
      fs.writeFileSync(file, JSON.stringify({ suite, ranAt: new Date().toISOString(), node: process.version, rows }, null, 2));
    }
  };
}

const short = (r) => `${r.status}${r.body && r.body.error ? ` ${r.body.error.code}` : ''}`;
const today = () => new Date().toISOString().slice(0, 10);
const month = () => new Date().toISOString().slice(0, 7);

module.exports = { startGateway, client, recorder, short, today, month, root, outDir, offlineBreachCheck };
