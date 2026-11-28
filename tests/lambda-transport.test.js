// Lambda transport tests: each service's lambda.handler answers an API Gateway v2 event
// (the event shape Floci/AWS API Gateway sends), and the Lambda-Invoke service-to-service path works.
// This proves the handler wiring locally; it is NOT a Floci deployment test.
// Owner: Saged. Test IDs: LT-01, LT-02, LT-03 (the 20 KB body limit and the JSON-only rule on Lambda,
// the bug Salma found in ST-11).
// Run: node --test tests/lambda-transport.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { recorder, root, today, offlineBreachCheck } = require('./helpers');

const rec = recorder('lambda-transport');
const svc = (name) => path.join(root, 'services', `${name}-service`);

test('LT-01 every lambda.handler answers an API Gateway v2 event', async () => {
  process.env.AWS_LAMBDA_FUNCTION_NAME = 'local-test';
  const { toApiGatewayEvent } = require(path.join(svc('auth'), 'node_modules/pb-common'));
  const results = [];
  for (const name of ['auth', 'buckets', 'transactions', 'insights']) {
    const { handler } = require(path.join(svc(name), 'lambda.js'));
    const res = await handler(toApiGatewayEvent({ method: 'GET', path: `/api/${name}/health`, headers: {} }), {});
    results.push(`${name}:${res.statusCode}:${JSON.parse(res.body).runtime}`);
  }
  delete process.env.AWS_LAMBDA_FUNCTION_NAME;
  const pass = results.every((r) => r.endsWith(':200:lambda'));
  rec.add('LT-01', 'Lambda packaging', 'Invoke each handler with a v2 health event', '200 runtime=lambda ×4', results.join(', '), pass);
  assert.ok(pass, results.join());
});

test('LT-02 service-to-service calls over Lambda Invoke transport', async () => {
  offlineBreachCheck(); // no internet needed for the breached-password check at register
  // Route calls to the target handler in-process instead of the AWS SDK (no Floci here)
  const handlers = {};
  for (const name of ['auth', 'buckets', 'transactions', 'insights']) handlers[`pb-${name}-api`] = require(path.join(svc(name), 'lambda.js')).handler;
  const invoked = [];
  for (const name of ['auth', 'buckets', 'transactions', 'insights']) {
    const common = require(path.join(svc(name), 'node_modules/pb-common'));
    common.setInvoker(async (fn, event) => { invoked.push(`${name}→${fn} ${event.requestContext.http.method} ${event.rawPath}`); return handlers[fn](event, {}); });
  }
  Object.assign(process.env, {
    SERVICE_TRANSPORT: 'lambda', AUTH_FUNCTION: 'pb-auth-api', BUCKETS_FUNCTION: 'pb-buckets-api',
    TRANSACTIONS_FUNCTION: 'pb-transactions-api', INSIGHTS_FUNCTION: 'pb-insights-api'
  });
  const { toApiGatewayEvent } = require(path.join(svc('auth'), 'node_modules/pb-common'));
  const call = async (fn, method, p, body, token) => {
    const res = await handlers[fn](toApiGatewayEvent({ method, path: p, body, headers: token ? { authorization: `Bearer ${token}` } : {} }), {});
    return { status: res.statusCode, body: res.body ? JSON.parse(res.body) : null };
  };
  const reg = await call('pb-auth-api', 'POST', '/api/auth/register', { name: 'Lambda User', email: 'lambda@example.com', password: 'LambdaPass2026' });
  const token = reg.body.token;
  const b = await call('pb-buckets-api', 'POST', '/api/buckets', { name: 'Bills', monthlyLimit: 500 }, token);
  const t = await call('pb-transactions-api', 'POST', '/api/transactions', { type: 'expense', amount: 450, date: today(), bucketId: b.body.id, paymentMethod: 'card' }, token);
  const d = await call('pb-insights-api', 'GET', '/api/insights/dashboard', undefined, token);
  delete process.env.SERVICE_TRANSPORT;
  const actual = `register ${reg.status}, bucket ${b.status}, expense ${t.status} state=${t.body.budget && t.body.budget.state}, dashboard ${d.status} expense=${d.body.expense}; ${invoked.length} invokes: ${[...new Set(invoked.map((i) => i.split(' ')[0]))].join(', ')}`;
  const pass = t.status === 201 && t.body.budget.state === 'NEAR_LIMIT' && d.status === 200 && d.body.expense === 450 && invoked.length >= 4;
  rec.add('LT-02', 'Integration (Lambda Invoke)', 'Register → bucket → expense → dashboard with SERVICE_TRANSPORT=lambda', 'expense 201 NEAR_LIMIT; dashboard 450; cross-function invokes happen', actual, pass);
  assert.ok(pass, actual);
});

test('LT-03 Lambda body rules: 20 KB limit and JSON only, also for base64 bodies', async () => {
  process.env.AWS_LAMBDA_FUNCTION_NAME = 'local-test';
  const { handler } = require(path.join(svc('buckets'), 'lambda.js'));
  const event = (body, type, base64) => ({
    version: '2.0', routeKey: '$default', rawPath: '/api/buckets', rawQueryString: '',
    headers: { 'content-type': type, authorization: 'Bearer not-checked-before-body-rules' },
    requestContext: { http: { method: 'POST', path: '/api/buckets', protocol: 'HTTP/1.1', sourceIp: '127.0.0.1', userAgent: 'lt-03' }, requestId: `lt-03-${Date.now()}`, stage: '$default' },
    body: base64 ? Buffer.from(body).toString('base64') : body,
    isBase64Encoded: !!base64
  });
  const big = JSON.stringify({ name: 'x'.repeat(30 * 1024), monthlyLimit: 100 });
  const results = {};
  for (const [label, ev] of Object.entries({
    big: event(big, 'application/json', false),
    bigBase64: event(big, 'application/json', true),
    text: event('{"name":"Food"}', 'text/plain', false),
    textBase64: event('{"name":"Food"}', 'text/plain', true)
  })) results[label] = (await handler(ev, {})).statusCode;
  delete process.env.AWS_LAMBDA_FUNCTION_NAME;
  const actual = Object.entries(results).map(([k, v]) => `${k} ${v}`).join(', ');
  const pass = results.big === 413 && results.bigBase64 === 413 && results.text === 415 && results.textBase64 === 415;
  rec.add('LT-03', 'Security (Lambda body rules)', 'POST a 30 KB JSON body and a text/plain body to the Buckets handler, plain and base64', 'big 413, text 415 in both forms', actual, pass);
  assert.ok(pass, actual);
});
