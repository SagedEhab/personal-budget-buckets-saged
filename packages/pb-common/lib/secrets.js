// Loads the JWT signing keys.
//   Cloud (Lambda on Floci/AWS): from AWS Secrets Manager, secret name in JWT_SECRET_ID.
//     The Lambda's IAM role may only call secretsmanager:GetSecretValue on that one secret.
//   Local development: from JWT_SECRET (and optionally JWT_SECRET_PREVIOUS) in the git-ignored .env file.
//
// Key rotation (infra/security/setup-rotation.sh): every 30 days a rotation Lambda creates a new key.
//   current  (AWSCURRENT)  signs new tokens and verifies them
//   previous (AWSPREVIOUS) only verifies tokens signed before the rotation, so nobody is logged out;
//                          those tokens expire within 1 hour anyway
// The keys are cached for 10 minutes. If a token does not match either cached key (a rotation just
// happened elsewhere), auth.js asks for a refresh, allowed at most once a minute so forged tokens
// cannot flood Secrets Manager.
const CACHE_MS = 10 * 60 * 1000;
const MIN_REFRESH_MS = 60 * 1000;
let cached = null;
let cachedAt = 0;

async function loadFromSecretsManager(secretId) {
  const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
  const client = new SecretsManagerClient({});
  const read = async (stage) => {
    try {
      return (await client.send(new GetSecretValueCommand({ SecretId: secretId, VersionStage: stage }))).SecretString;
    } catch (error) {
      if (stage === 'AWSPREVIOUS' && error.name === 'ResourceNotFoundException') return null; // never rotated yet
      throw error;
    }
  };
  const [current, previous] = await Promise.all([read('AWSCURRENT'), read('AWSPREVIOUS')]);
  return { current, previous };
}

async function getJwtSecrets() {
  if (cached && Date.now() - cachedAt < CACHE_MS) return cached;

  let keys;
  if (process.env.JWT_SECRET_ID) {
    keys = await loadFromSecretsManager(process.env.JWT_SECRET_ID);
  } else if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET_ID must be set in production (Secrets Manager).');
  } else {
    keys = { current: process.env.JWT_SECRET, previous: process.env.JWT_SECRET_PREVIOUS || null };
  }
  if (!keys.current || keys.current.length < 32) {
    throw new Error('JWT signing secret is missing or shorter than 32 characters.');
  }
  if (!keys.previous || keys.previous.length < 32) keys.previous = null;
  cached = keys;
  cachedAt = Date.now();
  return keys;
}

// The key used to sign new tokens
async function getJwtSecret() {
  return (await getJwtSecrets()).current;
}

// Reload the keys early (after a token matched neither key). Returns false if refreshed < 1 min ago.
function refreshAllowed() {
  if (cached && Date.now() - cachedAt < MIN_REFRESH_MS) return false;
  cached = null;
  return true;
}

function clearSecretCache() {
  cached = null;
  cachedAt = 0;
}

module.exports = { getJwtSecret, getJwtSecrets, refreshAllowed, clearSecretCache };
