// Attack pack: a scripted penetration test of the whole app deployed on Floci (ENHANCEMENTS, Saged).
// It attacks the live API the way an outsider or a malicious logged-in user would, and records for each
// attack what a secure app must do (expected) and what our app did (actual).
// The narrower per-service tests (ST-01..ST-19) stay with their owners; this pack covers attack classes
// they do not: IDOR across every service, more token forgeries, injection and type confusion, mass
// assignment of keys, race conditions on the hard limit and the lockout, user enumeration, CORS, error
// leaks, stored XSS payloads, request flooding and anonymous S3 access.
// No token, password or key is ever printed or saved. Test passwords are random and kept in memory.
//
// Run (Floci running, app deployed):
//   node tests/security/attack-pack.mjs
//   API=http://<api-id>.execute-api.localhost.floci.io:4566 node tests/security/attack-pack.mjs
import { writeFileSync, mkdirSync } from 'node:fs';
import { execSync } from 'node:child_process';
import crypto from 'node:crypto';

const API = process.env.API || 'http://7a84593305.execute-api.localhost.floci.io:4566';
const S3 = process.env.S3 || 'http://localhost:4566';
const results = [];

async function call(method, path, { token, body, raw, type = 'application/json', headers: extra = {} } = {}) {
  const headers = { ...extra };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body !== undefined || raw !== undefined) headers['Content-Type'] = type;
  const res = await fetch(API + path, {
    method, headers, body: raw !== undefined ? raw : (body !== undefined ? JSON.stringify(body) : undefined)
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { data = text; }
  return { status: res.status, data, text, headers: res.headers };
}

function record(id, category, attack, expected, actual, pass, note = '') {
  results.push({ id, category, attack, expected, actual, pass, note });
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${id}  ${attack}\n      expected: ${expected}\n      actual:   ${actual}${note ? `\n      note:     ${note}` : ''}\n`);
}

const randomPassword = () => `Atk${crypto.randomBytes(6).toString('hex')}9`;
const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
const sign = (h, p, key) => {
  const body = `${b64url(h)}.${b64url(p)}`;
  return `${body}.${crypto.createHmac('sha256', key).update(body).digest('base64url')}`;
};
const decode = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
const stamp = Date.now();
const extraUsers = [];

async function newUser(label) {
  const email = `atk-${label}-${stamp}@example.com`;
  const password = randomPassword();
  const reg = await call('POST', '/api/auth/register', { body: { name: `Attack ${label}`, email, password } });
  if (reg.status !== 201) throw new Error(`could not register ${label} (${reg.status})`);
  return { email, password, token: reg.data.token, id: reg.data.user.id };
}

console.log(`Attack pack against ${API}\n`);

// ---------- set-up: victim A with data in every service, attacker B ----------
const A = await newUser('victim');
const B = await newUser('attacker');
const bucketA = (await call('POST', '/api/buckets', { token: A.token, body: { name: 'Rent', monthlyLimit: 1000, hardLimit: true } })).data;
const bucketA2 = (await call('POST', '/api/buckets', { token: A.token, body: { name: 'Savings', monthlyLimit: 500 } })).data;
const bucketB = (await call('POST', '/api/buckets', { token: B.token, body: { name: 'Mine', monthlyLimit: 300 } })).data;
const today = new Date().toISOString().slice(0, 10);
const txnA = (await call('POST', '/api/transactions', {
  token: A.token, body: { type: 'expense', amount: 100, date: today, bucketId: bucketA.id, paymentMethod: 'cash', note: 'victim data' }
})).data.transaction;
const reportA = (await call('POST', '/api/insights/reports', { token: A.token, body: { type: 'transactions', from: today, to: today } })).data;
const reportId = reportA && (reportA.id || (reportA.report && reportA.report.id));
if (!bucketA.id || !txnA || !bucketB.id) throw new Error('set-up failed');
console.log(`Set-up: victim A (bucket, transaction${reportId ? ', report' : ''}) and attacker B ready\n`);

// ---------- AT-01 IDOR sweep: B uses A's ids on every service ----------
{
  const tries = [
    ['GET', `/api/buckets/${bucketA.id}`],
    ['PATCH', `/api/buckets/${bucketA.id}`, { monthlyLimit: 1 }],
    ['DELETE', `/api/buckets/${bucketA.id}`],
    ['POST', `/api/buckets/${bucketA.id}/archive`],
    ['POST', `/api/buckets/${bucketA.id}/check-spend`, { amount: 1, date: today }],
    ['POST', '/api/buckets/transfers', { fromBucketId: bucketA.id, toBucketId: bucketB.id, amount: 100 }],
    ['GET', `/api/transactions/${txnA.id}`],
    ['PATCH', `/api/transactions/${txnA.id}`, { amount: 1 }],
    ['DELETE', `/api/transactions/${txnA.id}`],
    ['GET', `/api/transactions/${txnA.id}/receipt`],
    ['POST', '/api/transactions', { type: 'expense', amount: 5, date: today, bucketId: bucketA.id, paymentMethod: 'cash' }]
  ];
  if (reportId) tries.push(['GET', `/api/insights/reports/${reportId}/download`], ['DELETE', `/api/insights/reports/${reportId}`]);
  const got = [];
  for (const [m, p, body] of tries) {
    const r = await call(m, p, { token: B.token, body });
    got.push(`${m} ${p.replace(/[0-9a-f-]{12,}/g, '<A-id>')} → ${r.status}`);
  }
  const allBlocked = got.every((g) => /→ (400|403|404|422)$/.test(g));
  const stillThere = (await call('GET', `/api/buckets/${bucketA.id}`, { token: A.token })).status === 200
    && (await call('GET', `/api/transactions/${txnA.id}`, { token: A.token })).data.amount === 100;
  record('AT-01', 'Broken access control (IDOR)', `Attacker B sends ${tries.length} requests with victim A's bucket, transaction and report ids across Buckets, Transactions and Insights`,
    'every request refused (404/403/4xx), A\'s data unchanged', `${got.filter((g) => /→ (400|403|404|422)$/.test(g)).length}/${tries.length} refused; A's data ${stillThere ? 'unchanged' : 'CHANGED'}`,
    allBlocked && stillThere, got.join('; '));
}

// ---------- AT-02 token forgery: weak keys, header tricks, claim swaps ----------
{
  const claims = decode(B.token);
  const now = Math.floor(Date.now() / 1000);
  const asA = { ...claims, sub: A.id, id: A.id, userId: A.id, role: 'admin', iat: now, exp: now + 3600 };
  const weakKeys = ['secret', 'changeme', 'password', 'jwt-secret', 'pb-jwt-secret', 'personal-budget-buckets', ''];
  const forged = [
    ...weakKeys.map((k) => [`HS256 signed with guessed key "${k}"`, sign({ alg: 'HS256', typ: 'JWT' }, asA, k)]),
    ['alg "HS512"', sign({ alg: 'HS512', typ: 'JWT' }, asA, 'secret')],
    ['alg "none", empty signature', `${b64url({ alg: 'none', typ: 'JWT' })}.${b64url(asA)}.`],
    ['alg "None" (case trick)', `${b64url({ alg: 'None', typ: 'JWT' })}.${b64url(asA)}.`],
    ['jku header pointing to attacker keys', sign({ alg: 'HS256', typ: 'JWT', jku: 'https://evil.example/keys.json' }, asA, 'secret')],
    ['kid path traversal (../../dev/null, empty key)', sign({ alg: 'HS256', typ: 'JWT', kid: '../../../../dev/null' }, asA, '')],
    ['B\'s real signature with A\'s id swapped in', `${B.token.split('.')[0]}.${b64url(asA)}.${B.token.split('.')[2]}`],
    ['B\'s real token with signature removed', B.token.split('.').slice(0, 2).join('.') + '.'],
    ['token in a query string instead of the header', null]
  ];
  const got = [];
  for (const [label, token] of forged) {
    const r = token === null
      ? await call('GET', `/api/buckets?access_token=${encodeURIComponent(B.token)}`)
      : await call('GET', '/api/buckets', { token });
    got.push(`${label} → ${r.status}`);
  }
  const all401 = got.every((g) => g.endsWith('→ 401'));
  record('AT-02', 'Authentication (token forgery)', `${forged.length} forged or misplaced tokens claiming to be victim A as admin`,
    'all 401', `${got.filter((g) => g.endsWith('→ 401')).length}/${forged.length} got 401`, all401, got.join('; '));
}

// ---------- AT-03 injection and type confusion ----------
{
  const cases = [
    ['login with {"$ne": null} as e-mail and password', 'POST', '/api/auth/login', { email: { $ne: null }, password: { $ne: null } }, null],
    ['login with e-mail "a@b.c\' OR 1=1 --"', 'POST', '/api/auth/login', { email: "a@b.c' OR 1=1 --", password: 'x' }, null],
    ['bucket with monthlyLimit as an object', 'POST', '/api/buckets', { name: 'inj1', monthlyLimit: { $gt: 0 } }, B.token],
    ['bucket with monthlyLimit as an array', 'POST', '/api/buckets', { name: 'inj2', monthlyLimit: [100] }, B.token],
    ['bucket with monthlyLimit 1e309 (Infinity)', 'POST', '/api/buckets', null, B.token, '{"name":"inj3","monthlyLimit":1e309}'],
    ['bucket with monthlyLimit -500', 'POST', '/api/buckets', { name: 'inj4', monthlyLimit: -500 }, B.token],
    ['expense with amount "100; DROP TABLE"', 'POST', '/api/transactions', { type: 'expense', amount: '100; DROP TABLE', date: today, bucketId: bucketB.id, paymentMethod: 'cash' }, B.token],
    ['expense with amount 0.000001', 'POST', '/api/transactions', { type: 'expense', amount: 0.000001, date: today, bucketId: bucketB.id, paymentMethod: 'cash' }, B.token],
    ['expense dated 9999-12-31', 'POST', '/api/transactions', { type: 'expense', amount: 5, date: '9999-12-31', bucketId: bucketB.id, paymentMethod: 'cash' }, B.token],
    ['bucket id "../../USER#<A>" in the path', 'GET', `/api/buckets/${encodeURIComponent(`../../USER#${A.id}`)}`, undefined, B.token],
    ['month query "2026-11\' OR \'1\'=\'1"', 'GET', `/api/buckets?month=${encodeURIComponent("2026-11' OR '1'='1")}`, undefined, B.token],
    ['__proto__ pollution in body', 'POST', '/api/buckets', null, B.token, '{"name":"inj5","monthlyLimit":10,"__proto__":{"role":"admin","isAdmin":true}}']
  ];
  const got = [];
  for (const [label, m, p, body, token, raw] of cases) {
    const r = await call(m, p, { token, body: body === null ? undefined : body, raw });
    got.push(`${label} → ${r.status}`);
  }
  // __proto__ must not have made B an admin
  const adminAfter = await call('GET', '/api/auth/users', { token: B.token });
  got.push(`B on admin endpoint afterwards → ${adminAfter.status}`);
  const okCodes = (g) => /→ (400|401|404|422)$/.test(g) || (g.startsWith('__proto__') && /→ (201|400)$/.test(g)) || (g.startsWith('B on admin') && g.endsWith('403'));
  const allOk = got.every(okCodes);
  record('AT-03', 'Injection and type confusion', `${cases.length} NoSQL/SQL-style, operator, type-confusion, path and prototype-pollution payloads`,
    'all rejected by validation (400/401/404/422); no 500; pollution does not give admin', `${got.filter(okCodes).length}/${got.length} as expected; 500s: ${got.filter((g) => g.endsWith('500')).length}`,
    allOk, got.join('; '));
}

// ---------- AT-04 mass assignment of keys and ownership fields ----------
{
  const body = { name: 'Planted', monthlyLimit: 50, pk: `USER#${A.id}`, sk: 'BUCKET#planted', userId: A.id, id: 'planted', status: 'archived', role: 'admin' };
  const r = await call('POST', '/api/buckets', { token: B.token, body });
  const aList = (await call('GET', '/api/buckets?includeArchived=true', { token: A.token })).data.items || [];
  const planted = aList.some((b) => b.name === 'Planted' || b.id === 'planted');
  const ownedByB = r.status === 201 && r.data.userId === B.id && r.data.id !== 'planted' && r.data.status === 'active';
  const t = await call('PATCH', `/api/transactions/${txnA.id}`, { token: A.token, body: { userId: B.id, pk: `USER#${B.id}` } });
  const stillA = (await call('GET', `/api/transactions/${txnA.id}`, { token: A.token })).status === 200;
  record('AT-04', 'Mass assignment', 'B creates a bucket with pk/sk/userId/id/status of victim A in the body; A tries to move a transaction to B by PATCHing userId/pk',
    'extra fields ignored or refused: nothing planted in A\'s account, the transaction stays A\'s',
    `bucket ${r.status === 201 ? `created in B's own account (userId ${ownedByB ? 'B' : 'NOT B'})` : `refused ${r.status}`}; planted in A: ${planted ? 'YES' : 'no'}; PATCH → ${t.status}, still A's: ${stillA ? 'yes' : 'NO'}`,
    !planted && (r.status !== 201 || ownedByB) && stillA);
}

// ---------- AT-05 race condition on the hard limit ----------
{
  const C = await newUser('race');
  extraUsers.push(C);
  const capped = (await call('POST', '/api/buckets', { token: C.token, body: { name: 'Capped', monthlyLimit: 100, hardLimit: true } })).data;
  const N = 10;
  const shots = await Promise.all(Array.from({ length: N }, (_, i) => call('POST', '/api/transactions', {
    token: C.token, body: { type: 'expense', amount: 30, date: today, bucketId: capped.id, paymentMethod: 'cash', note: `race ${i}` }
  })));
  const accepted = shots.filter((s) => s.status === 201).length;
  const status = (await call('GET', `/api/buckets/${capped.id}`, { token: C.token })).data;
  const spent = status.budget ? status.budget.spent : NaN;
  record('AT-05', 'Race condition (business logic)', `${N} expenses of 30 sent at the same moment to a bucket with a hard limit of 100`,
    'at most 3 accepted (90), total spent never above 100', `${accepted} accepted, spent ${spent} of 100`, spent <= 100,
    spent > 100 ? 'check-spend and the write are separate steps, so parallel requests all see the old total' : '');
}

// ---------- AT-06 race condition on the login lockout ----------
{
  const D = await newUser('lockrace');
  extraUsers.push(D);
  const N = 20;
  const shots = await Promise.all(Array.from({ length: N }, () => call('POST', '/api/auth/login', { body: { email: D.email, password: 'WrongPass123' } })));
  const evaluated = shots.filter((s) => s.status === 401).length;
  const after = await call('POST', '/api/auth/login', { body: { email: D.email, password: D.password } });
  record('AT-06', 'Race condition (brute force)', `${N} wrong passwords sent in parallel to one account (lockout is after 5)`,
    'at most 5 guesses checked, then locked (429); the right password is then refused while locked',
    `${evaluated} guesses checked (401), ${shots.filter((s) => s.status === 429).length} got 429; right password afterwards → ${after.status}`,
    evaluated <= 5 && after.status === 429,
    evaluated > 5 ? 'the failed-login counter is read and written in two steps, so parallel guesses are not all counted' : '');
}

// ---------- AT-07 user enumeration ----------
{
  const timeIt = async (email) => {
    const t0 = performance.now();
    const r = await call('POST', '/api/auth/login', { body: { email, password: 'NotTheRight1' } });
    return { ms: performance.now() - t0, status: r.status, message: r.data && r.data.error && r.data.error.message };
  };
  const E = await newUser('enum');
  extraUsers.push(E);
  const known = []; const unknown = [];
  for (let i = 0; i < 3; i++) { known.push(await timeIt(E.email)); unknown.push(await timeIt(`nobody-${stamp}-${i}@example.com`)); }
  const avg = (a) => a.reduce((s, x) => s + x.ms, 0) / a.length;
  const sameMsg = known[0].message === unknown[0].message && known[0].status === unknown[0].status;
  const gap = Math.abs(avg(known) - avg(unknown));
  const reg = await call('POST', '/api/auth/register', { body: { name: 'Dup', email: E.email, password: randomPassword() } });
  record('AT-07', 'User enumeration', 'Compare login answers and timing for a real and a made-up e-mail; register an e-mail that exists',
    'login: same status, message and similar timing; register: reveals the e-mail exists (accepted risk, see note)',
    `login same answer: ${sameMsg ? 'yes' : 'NO'} (${known[0].status}); avg time ${avg(known).toFixed(0)} ms vs ${avg(unknown).toFixed(0)} ms; register existing → ${reg.status} ${reg.data && reg.data.error ? reg.data.error.code : ''}`,
    sameMsg && gap < 250,
    'Register says EMAIL_TAKEN, so sign-up can confirm an account exists. Most sites accept this for usability; the mitigations are the API rate limit and the CloudWatch FailedLogins alarm.');
  // finding recorded separately so it is visible in the summary
  results.push({ id: 'AT-07b', category: 'User enumeration', attack: 'Register with an e-mail that already exists', expected: 'documented low-risk finding', actual: `${reg.status} ${reg.data && reg.data.error ? reg.data.error.code : ''}`, pass: null, note: 'finding (low): accepted risk' });
}

// ---------- AT-08 CORS from a hostile site ----------
{
  const evil = await call('OPTIONS', '/api/buckets', { headers: { Origin: 'https://evil.example', 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'authorization' } });
  const evilGet = await call('GET', '/api/buckets', { token: B.token, headers: { Origin: 'https://evil.example' } });
  const good = await call('OPTIONS', '/api/buckets', { headers: { Origin: 'http://localhost:4566', 'Access-Control-Request-Method': 'GET' } });
  const evilAllowed = evil.headers.get('access-control-allow-origin') || evilGet.headers.get('access-control-allow-origin');
  const goodAllowed = good.headers.get('access-control-allow-origin');
  record('AT-08', 'CORS', 'Browser pre-flight and GET from https://evil.example, compared with the real frontend origin',
    'no Access-Control-Allow-Origin for evil.example (the browser blocks it); the frontend origin is allowed',
    `evil.example → ${evilAllowed || 'no ACAO header'}; frontend → ${goodAllowed || 'no ACAO header'}`,
    !evilAllowed || (evilAllowed !== '*' && evilAllowed !== 'https://evil.example'));
}

// ---------- AT-09 error messages and fingerprinting ----------
{
  const probes = [
    await call('GET', '/api/buckets/x'.repeat(1), { token: B.token }),
    await call('POST', '/api/buckets', { token: B.token, raw: '{"name": "broken', type: 'application/json' }),
    await call('GET', '/api/nope/../../etc/passwd'),
    await call('TRACE', '/api/buckets', { token: B.token }).catch(() => ({ status: 'refused by client', text: '', headers: new Headers() })),
    await call('GET', '/api/buckets/%00', { token: B.token })
  ];
  const leaks = probes.filter((p) => /at [\w.<>]+ \(|node_modules|stack|Error:|\/var\/task|ENOENT|DynamoDB|express/i.test(p.text || ''));
  const powered = probes.some((p) => p.headers && p.headers.get && p.headers.get('x-powered-by'));
  const secHeaders = probes[0].headers.get('x-content-type-options') === 'nosniff' && !!probes[0].headers.get('strict-transport-security');
  record('AT-09', 'Information leakage', 'Malformed JSON, unknown and traversal paths, TRACE, null byte',
    'short JSON errors with no stack trace, file path or library name; no X-Powered-By; security headers present',
    `${leaks.length} responses leaked internals; X-Powered-By ${powered ? 'PRESENT' : 'absent'}; nosniff + HSTS ${secHeaders ? 'present' : 'MISSING'}; statuses ${probes.map((p) => p.status).join(', ')}`,
    leaks.length === 0 && !powered && secHeaders);
}

// ---------- AT-10 stored XSS payloads ----------
{
  const payload = '<img src=x onerror=alert(document.cookie)>';
  const r = await call('POST', '/api/buckets', { token: B.token, body: { name: payload.slice(0, 40), monthlyLimit: 10 } });
  const back = r.status === 201 ? r.data.name : null;
  const page = await (await fetch(`${S3}/pb-web/index.html`)).text().catch(() => '');
  const csp = /Content-Security-Policy/i.test(page);
  const js = await Promise.all(['js/buckets.js', 'js/transactions.js', 'js/insights.js', 'js/admin.js', 'js/auth.js', 'js/main.js', 'js/ui.js', 'js/charts.js'].map((f) => fetch(`${S3}/pb-web/${f}`).then((x) => x.ok ? x.text() : '').catch(() => '')));
  const unsafeSinks = js.join('\n').split('\n').filter((l) => /innerHTML\s*=|insertAdjacentHTML|document\.write/.test(l) && !/escape|esc\(|textContent|''|""|``/.test(l)).length;
  record('AT-10', 'Cross-site scripting (stored)', 'Bucket named with an <img onerror> script payload, then check how the frontend would show it',
    'API stores it as plain text or rejects it; frontend writes names with textContent/escaping; CSP present',
    `API → ${r.status}${back !== null ? ` (stored as text: ${back === payload.slice(0, 40)})` : ''}; CSP meta tag: ${csp ? 'yes' : 'NO'}; unescaped HTML sinks in the frontend scripts: ${unsafeSinks}`,
    csp && unsafeSinks === 0, 'unescaped sinks = lines that assign innerHTML without an escape helper');
}

// ---------- AT-11 request flooding ----------
{
  const N = 60;
  const t0 = performance.now();
  const shots = await Promise.all(Array.from({ length: N }, () => call('GET', '/api/buckets', { token: B.token }).catch(() => ({ status: 'error' }))));
  const secs = ((performance.now() - t0) / 1000).toFixed(1);
  const counts = shots.reduce((m, s) => ({ ...m, [s.status]: (m[s.status] || 0) + 1 }), {});
  const limited = (counts[429] || 0) + (counts[503] || 0);
  record('AT-11', 'Denial of service (flooding)', `${N} requests at once from one user (stage limit 10/s, burst 20; Lambda reserved concurrency)`,
    'excess requests refused with 429 or 503, service still answers afterwards',
    `${JSON.stringify(counts)} in ${secs} s; afterwards → ${(await call('GET', '/api/buckets/health')).status}`,
    limited > 0, limited === 0 ? 'Floci may not enforce API Gateway throttling; reserved concurrency was proved separately (3b)' : '');
}

// ---------- AT-12 anonymous access to private S3 buckets ----------
{
  const tries = [];
  // Uploads go only to the receipts and reports buckets (and are removed again): the audit-log bucket is
  // write-once (Object Lock), so a test file there could not be deleted. It is only listed.
  for (const b of ['pb-receipts-244694', 'pb-reports-244694', 'pb-audit-logs-244694']) {
    const list = await fetch(`${S3}/${b}?list-type=2`).then((r) => r.status).catch(() => 'error');
    let put = 'not tried (write-once bucket)';
    if (!b.includes('audit')) {
      const url = `${S3}/${b}/attack-${stamp}.txt`;
      put = await fetch(url, { method: 'PUT', body: 'x' }).then((r) => r.status).catch(() => 'error');
      if (put === 200) await fetch(url, { method: 'DELETE' }).catch(() => {});
    }
    tries.push(`${b}: list ${list}, put ${put}`);
  }
  const blocked = tries.every((t) => /list 403, put (403|not tried)/.test(t));
  // Floci does not check S3 signatures, so an anonymous call is treated as the account owner. When that
  // happens, prove the protection that AWS enforces instead: all 4 Block Public Access settings on, no
  // public bucket policy, no public ACL grant.
  const env = { ...process.env, AWS_PROFILE: process.env.AWS_PROFILE || 'floci', AWS_PAGER: '', MSYS_NO_PATHCONV: '1' };
  const aws = (cmd) => { try { return execSync(`aws ${cmd}`, { env, stdio: ['ignore', 'pipe', 'pipe'] }).toString().trim(); } catch (e) { return String(e.stderr || e.message).trim(); } };
  const config = ['pb-receipts-244694', 'pb-reports-244694', 'pb-audit-logs-244694'].map((b) => {
    const bpa = aws(`s3api get-public-access-block --bucket ${b} --query "PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]" --output text`);
    const policy = aws(`s3api get-bucket-policy-status --bucket ${b} --query PolicyStatus.IsPublic --output text`);
    const acl = aws(`s3api get-bucket-acl --bucket ${b} --query "Grants[].Grantee.URI" --output text`);
    const ok = /^True\s+True\s+True\s+True$/.test(bpa) && !/^True$/.test(policy) && !/AllUsers|AuthenticatedUsers/.test(acl);
    return { b, ok, text: `${b}: Block Public Access ${bpa.replace(/\s+/g, '/')}, public policy ${/NoSuchBucketPolicy/.test(policy) ? 'none' : policy}, public ACL grants ${acl && !/None/.test(acl) ? acl : 'none'}` };
  });
  const configOk = config.every((c) => c.ok);
  record('AT-12', 'Cloud storage exposure', 'Unsigned (anonymous) list and upload on the receipts, reports and audit-log buckets',
    '403 for every request; where the emulator cannot enforce it, the bucket settings that AWS enforces must block all public access',
    blocked ? tries.join('; ') : `anonymous: ${tries.join('; ')} → Floci does not enforce S3 signatures. Settings: ${config.map((c) => c.text).join('; ')}`,
    blocked || configOk,
    blocked ? '' : 'PASS by configuration, not by an enforced 403: Floci treats every S3 call as the account owner. On AWS, Block Public Access (all 4 settings) makes unsigned requests fail with 403.');
}

// ---------- clean-up: delete the test accounts' data ----------
// AT-11 floods the API on purpose, so wait for it to recover and retry while it is still throttled.
await new Promise((r) => setTimeout(r, 5000));
const cleanup = [];
for (const u of [A, B, ...extraUsers]) {
  let status = 0;
  for (let i = 0; i < 5 && status !== 200; i++) {
    if (i) await new Promise((r) => setTimeout(r, 3000));
    status = (await call('DELETE', '/api/auth/me', { token: u.token, body: { password: u.password, confirm: true } })).status;
  }
  cleanup.push(status);
}
console.log(`Clean-up: ${cleanup.filter((x) => x === 200).length}/${cleanup.length} test accounts deleted (${cleanup.join(', ')})
`);

// ---------- summary + evidence ----------
const scored = results.filter((r) => r.pass !== null);
const passed = scored.filter((r) => r.pass).length;
console.log(`Attack pack: ${passed}/${scored.length} attacks stopped`);
mkdirSync('evidence', { recursive: true });
writeFileSync('evidence/attack-pack.json', JSON.stringify({ api: API, ranAt: new Date().toISOString(), passed, total: scored.length, results }, null, 2));
const md = [
  '# Attack pack results (Saged)',
  '',
  `Run: ${new Date().toISOString()} against \`${API}\` (Floci). Script: \`tests/security/attack-pack.mjs\`.`,
  `Result: **${passed}/${scored.length} attacks stopped.** No token, password or key is stored here.`,
  '',
  '| ID | Category | Attack | Expected | Actual | Result |',
  '|---|---|---|---|---|---|',
  ...results.map((r) => `| ${r.id} | ${r.category} | ${r.attack} | ${r.expected} | ${String(r.actual).replace(/\|/g, '/')} | ${r.pass === null ? 'FINDING' : r.pass ? 'PASS' : 'FAIL'} |`),
  '',
  '## Details',
  ...results.filter((r) => r.note).map((r) => `- **${r.id}:** ${r.note.replace(/\|/g, '/')}`)
].join('\n');
writeFileSync('evidence/attack-pack.md', md + '\n');
process.exit(passed === scored.length ? 0 : 1);
