// LOCAL ONLY: plays the role of Amazon API Gateway on your PC.
// One URL (http://localhost:3000) routes each path prefix to the matching service app,
// exactly like the API Gateway routes do on Floci/AWS:
//   /api/auth/*          -> auth-service          (Lambda pb-auth-api)
//   /api/buckets/*       -> buckets-service       (Lambda pb-buckets-api)
//   /api/transactions/*  -> transactions-service  (Lambda pb-transactions-api)
//   /api/insights/*      -> insights-service      (Lambda pb-insights-api)
// Usage (from the code folder):  node infra/local-gateway.js
// Data is kept in memory, or in JSON files when LOCAL_DATA_DIR is set (survives restarts).
const http = require('http');
const path = require('path');
const fs = require('fs');

function loadEnv(file) {
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m && process.env[m[1]] === undefined) process.env[m[1]] = m[2];
  }
}

function createGateway() {
  const root = path.join(__dirname, '..', 'services');
  const apps = {
    auth: require(path.join(root, 'auth-service', 'app')),
    buckets: require(path.join(root, 'buckets-service', 'app')),
    transactions: require(path.join(root, 'transactions-service', 'app')),
    insights: require(path.join(root, 'insights-service', 'app'))
  };
  const server = http.createServer((req, res) => {
    const match = /^\/api\/(auth|buckets|transactions|insights)(\/|\?|$)/.exec(req.url);
    if (!match) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: { code: 'ROUTE_NOT_FOUND', message: 'Route not found.' } }));
      return;
    }
    apps[match[1]](req, res);
  });
  return { server, apps };
}

if (require.main === module) {
  loadEnv(path.join(__dirname, '..', '.env'));
  const port = Number(process.env.GATEWAY_PORT) || 3000;
  process.env.INTERNAL_API_URL = process.env.INTERNAL_API_URL || `http://localhost:${port}`;
  const { server } = createGateway();
  server.listen(port, () => console.log(`Local API gateway on http://localhost:${port}`));
}

module.exports = { createGateway, loadEnv };
