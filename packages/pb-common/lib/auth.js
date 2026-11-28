// Authentication and authorization middleware used by every service.
//   requireAuth        -> 401 unless the request has a valid "Authorization: Bearer <JWT>",
//                         403 if the account has been disabled (even while the token is still valid)
//   requireRole(role)  -> 403 unless the user's CURRENT role, read from the users table, matches
//                         (enforced in the BACKEND; hiding a button in the frontend is not access control)
//
// Account check (Phase 1 proposal, threat 6: "role re-checked in the database on admin routes,
// disabled accounts blocked with a valid token"):
//   - Auth service: reads the users table directly (it owns that table).
//   - Other services: ask the Auth service (GET /api/auth/me with the user's own token).
//   Normal routes reuse an answer for up to 60 s; admin routes always ask again.
//   If the check cannot be made, the request is refused (fail closed), never let through.
const jwt = require('./jwt');
const { getJwtSecret, getJwtSecrets, refreshAllowed } = require('./secrets');
const { errors } = require('./errors');
const { callService } = require('./serviceClient');

const ISSUER = 'pb-auth-service';
const AUDIENCE = 'personal-budget-buckets';
const ROLES = ['user', 'admin'];
const cacheMs = () => Number(process.env.ACCOUNT_CHECK_CACHE_MS ?? 60000);

// Default account lookup for every service except Auth: ask the Auth service.
async function lookupViaAuthService(req) {
  const r = await callService('auth', { method: 'GET', path: '/api/auth/me', authHeader: req.authHeader, requestId: req.requestId });
  if (r.status === 200 && r.body) return { status: r.body.status, role: r.body.role };
  if (r.status === 403) return { status: 'disabled' };
  if (r.status === 401 || r.status === 404) return null;
  throw errors.unavailable('ACCOUNT_CHECK_FAILED', 'Your account could not be checked right now. Please try again.');
}

// cache: false for the Auth service, whose lookup is already a direct table read.
function createAuth(logger, { lookupUser = lookupViaAuthService, cache: useCache = true } = {}) {
  const cache = new Map(); // userId -> { account, at }

  async function currentAccount(req, { fresh = false } = {}) {
    const hit = cache.get(req.user.id);
    if (useCache && !fresh && hit && Date.now() - hit.at < cacheMs()) return hit.account;
    const account = await lookupUser(req);
    if (account) cache.set(req.user.id, { account, at: Date.now() });
    else cache.delete(req.user.id);
    if (cache.size > 5000) cache.clear(); // keep memory bounded in a long-lived Lambda container
    return account;
  }

  function applyAccount(req, account) {
    if (!account) {
      logger.warn('AUTH_ACCOUNT_NOT_FOUND', { requestId: req.requestId, userId: req.user.id });
      throw errors.unauthorized('Invalid authentication token.');
    }
    if (account.status !== 'active') {
      logger.warn('AUTH_ACCOUNT_DISABLED', { requestId: req.requestId, userId: req.user.id, path: req.path });
      throw errors.forbidden('This account has been disabled. Contact the administrator.');
    }
    if (ROLES.includes(account.role)) req.user.role = account.role; // the table, not the token, is the truth
  }

  async function requireAuth(req, res, next) {
    try {
      const header = req.get('authorization') || '';
      const match = /^Bearer ([A-Za-z0-9_\-.]+)$/.exec(header);
      if (!match) {
        logger.warn('AUTH_TOKEN_MISSING', { requestId: req.requestId, path: req.path, ip: req.ip });
        throw errors.unauthorized();
      }
      const result = await verifyWithRotation(match[1]);
      if (!result.ok) {
        logger.warn('AUTH_TOKEN_REJECTED', { requestId: req.requestId, path: req.path, reason: result.reason, ip: req.ip });
        throw errors.unauthorized(result.reason === 'expired' ? 'Session expired. Please log in again.' : 'Invalid authentication token.');
      }
      const c = result.claims;
      if (!c.sub || !ROLES.includes(c.role)) throw errors.unauthorized('Invalid authentication token.');
      req.user = { id: c.sub, role: c.role, baseCurrency: c.cur || 'EGP', name: c.name };
      req.authHeader = header; // forwarded unchanged on service-to-service calls
      applyAccount(req, await currentAccount(req));
      next();
    } catch (error) {
      next(error);
    }
  }

  function requireRole(role) {
    return async (req, res, next) => {
      try {
        if (!req.user) throw errors.unauthorized();
        applyAccount(req, await currentAccount(req, { fresh: true })); // admin routes: always re-check the table
        if (req.user.role !== role) {
          logger.warn('ACCESS_DENIED', {
            requestId: req.requestId, userId: req.user.id, role: req.user.role,
            requiredRole: role, method: req.method, path: req.path
          });
          throw errors.forbidden();
        }
        next();
      } catch (error) {
        next(error);
      }
    };
  }

  return { requireAuth, requireRole };
}

// Verify with the current key, then the previous one (tokens signed before a key rotation stay valid
// until they expire). If neither matches, the keys may have just been rotated: reload them once.
async function verifyWithRotation(token) {
  const opts = { issuer: ISSUER, audience: AUDIENCE };
  const attempt = async () => {
    const { current, previous } = await getJwtSecrets();
    let result = jwt.verify(token, current, opts);
    if (result.reason === 'bad_signature' && previous) result = jwt.verify(token, previous, opts);
    return result;
  };
  let result = await attempt();
  if (result.reason === 'bad_signature' && refreshAllowed()) result = await attempt();
  return result;
}

async function issueToken(user, { expiresInSec = 3600 } = {}) {
  const secret = await getJwtSecret();
  return jwt.sign(
    { sub: user.id, role: user.role, cur: user.baseCurrency, name: user.name },
    secret,
    { expiresInSec, issuer: ISSUER, audience: AUDIENCE }
  );
}

module.exports = { createAuth, issueToken, ISSUER, AUDIENCE, ROLES };
