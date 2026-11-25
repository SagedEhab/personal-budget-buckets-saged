// One-command local run: API gateway (all four services) on :3000 and the frontend on :8080.
// Uses .env when present; otherwise makes a throw-away JWT secret for this run only
// (everyone is logged out on restart) and keeps data in memory.
const path = require('path');
const crypto = require('crypto');
const { createGateway, loadEnv } = require('../infra/local-gateway');

const root = path.join(__dirname, '..');
loadEnv(path.join(root, '.env'));
if (!process.env.JWT_SECRET) {
  process.env.JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.log('No .env found: using a temporary JWT secret and in-memory data for this run.');
}
if (process.env.LOCAL_DATA_DIR) process.env.LOCAL_DATA_DIR = path.resolve(root, process.env.LOCAL_DATA_DIR);
const port = Number(process.env.GATEWAY_PORT) || 3000;
process.env.INTERNAL_API_URL = process.env.INTERNAL_API_URL || `http://localhost:${port}`;
createGateway().server.listen(port, () => console.log(`Local API gateway on http://localhost:${port}`));
require('../infra/local-frontend');

// Optional demo admin for the local run only: DEV_ADMIN_EMAIL / DEV_ADMIN_PASSWORD in your shell.
if (process.env.DEV_ADMIN_EMAIL && process.env.DEV_ADMIN_PASSWORD) {
  const auth = require('../services/auth-service/app');
  auth.locals.createUser({ name: 'Administrator', email: process.env.DEV_ADMIN_EMAIL, password: process.env.DEV_ADMIN_PASSWORD, role: 'admin' })
    .then((u) => console.log(u ? 'Local admin account created.' : 'Local admin already exists.'))
    .catch((e) => console.error(e.message));
}
