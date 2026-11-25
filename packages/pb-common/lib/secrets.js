// Loads the JWT signing key.
//   Cloud (Lambda on Floci/AWS): from AWS Secrets Manager, secret name in JWT_SECRET_ID.
//     The Lambda's IAM role may only call secretsmanager:GetSecretValue on that one secret.
//   Local development: from JWT_SECRET in the git-ignored .env file.
// The value is cached for 10 minutes so a rotated secret is picked up without a redeploy.
const CACHE_MS = 10 * 60 * 1000;
let cached = null;
let cachedAt = 0;

async function loadFromSecretsManager(secretId) {
  const { SecretsManagerClient, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
  const client = new SecretsManagerClient({});
  const result = await client.send(new GetSecretValueCommand({ SecretId: secretId }));
  return result.SecretString;
}

async function getJwtSecret() {
  if (cached && Date.now() - cachedAt < CACHE_MS) return cached;

  let secret;
  if (process.env.JWT_SECRET_ID) {
    secret = await loadFromSecretsManager(process.env.JWT_SECRET_ID);
  } else if (process.env.NODE_ENV === 'production') {
    throw new Error('JWT_SECRET_ID must be set in production (Secrets Manager).');
  } else {
    secret = process.env.JWT_SECRET;
  }
  if (!secret || secret.length < 32) {
    throw new Error('JWT signing secret is missing or shorter than 32 characters.');
  }
  cached = secret;
  cachedAt = Date.now();
  return secret;
}

function clearSecretCache() {
  cached = null;
  cachedAt = 0;
}

module.exports = { getJwtSecret, clearSecretCache };
