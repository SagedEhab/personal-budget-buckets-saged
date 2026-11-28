// Rotation Lambda for the JWT signing secret pb/jwt-secret (report sections 6 and 8).
// Secrets Manager calls it with four steps; it follows the standard AWS rotation contract:
//   createSecret  make a new random 96-character key and store it as version AWSPENDING
//   setSecret     nothing to do: the key is only used by our own Lambdas (no database password to change)
//   testSecret    check the pending key is long enough to be a safe HMAC-SHA256 key
//   finishSecret  move the AWSCURRENT label to the new version; Secrets Manager then labels the old
//                 one AWSPREVIOUS
// The services sign new tokens with AWSCURRENT and still accept AWSPREVIOUS (pb-common/lib/secrets.js),
// so people who are logged in are not thrown out when the key changes; old tokens expire within 1 hour.
// Uses the AWS SDK that comes with the Node.js Lambda runtime: no dependencies to install.
const crypto = require('crypto');
const {
  SecretsManagerClient, DescribeSecretCommand, GetSecretValueCommand, PutSecretValueCommand,
  UpdateSecretVersionStageCommand
} = require('@aws-sdk/client-secrets-manager');

const sm = new SecretsManagerClient({});
const MIN_LENGTH = 64;

async function stagesOf(secretId) {
  const d = await sm.send(new DescribeSecretCommand({ SecretId: secretId }));
  return { versions: d.VersionIdsToStages || {}, enabled: d.RotationEnabled };
}

async function createSecret(secretId, token) {
  // Skip only if a real key is already stored for this version (a retried step). On AWS the pending
  // version has no value yet; Floci 2.5.0 creates it with an empty string. Both cases need a new key.
  try {
    const v = await sm.send(new GetSecretValueCommand({ SecretId: secretId, VersionId: token, VersionStage: 'AWSPENDING' }));
    if (v.SecretString && v.SecretString.length >= MIN_LENGTH) return 'pending key already stored';
  } catch (error) {
    if (error.name !== 'ResourceNotFoundException') throw error;
  }
  await sm.send(new PutSecretValueCommand({
    SecretId: secretId,
    ClientRequestToken: token,
    SecretString: crypto.randomBytes(48).toString('hex'),
    VersionStages: ['AWSPENDING']
  }));
  return 'new key stored as AWSPENDING';
}

async function testSecret(secretId, token) {
  const v = await sm.send(new GetSecretValueCommand({ SecretId: secretId, VersionId: token, VersionStage: 'AWSPENDING' }));
  if (!v.SecretString || v.SecretString.length < MIN_LENGTH) throw new Error('Pending key is too short.');
  return 'pending key checked';
}

async function finishSecret(secretId, token) {
  const { versions } = await stagesOf(secretId);
  const current = Object.keys(versions).find((id) => versions[id].includes('AWSCURRENT'));
  if (current === token) return 'already current';
  await sm.send(new UpdateSecretVersionStageCommand({
    SecretId: secretId, VersionStage: 'AWSCURRENT', MoveToVersionId: token, RemoveFromVersionId: current
  }));
  // AWS drops the AWSPENDING label after a successful rotation; Floci 2.5.0 leaves it, which blocks the
  // next rotation ("A previous rotation isn't complete"). Removing it here is harmless on AWS.
  await sm.send(new UpdateSecretVersionStageCommand({
    SecretId: secretId, VersionStage: 'AWSPENDING', RemoveFromVersionId: token
  }));
  return `AWSCURRENT moved from ${current} to ${token}`;
}

exports.handler = async (event) => {
  const { SecretId: secretId, ClientRequestToken: token, Step: step } = event;
  const { versions } = await stagesOf(secretId);
  if (!versions[token]) throw new Error(`Version ${token} is not part of ${secretId}.`);
  let result;
  if (step === 'createSecret') result = await createSecret(secretId, token);
  else if (step === 'setSecret') result = 'nothing to set (key used only by our own services)';
  else if (step === 'testSecret') result = await testSecret(secretId, token);
  else if (step === 'finishSecret') result = await finishSecret(secretId, token);
  else throw new Error(`Unknown rotation step ${step}.`);
  // Never log the key itself: only the step and the version id.
  console.log(JSON.stringify({ event: 'JWT_SECRET_ROTATION', step, versionId: token, result }));
  return { step, result };
};
