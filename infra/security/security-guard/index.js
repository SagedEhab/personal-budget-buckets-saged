// Security guard (ENHANCEMENTS 5o, Saged): finds security settings that drifted and puts them back.
// EventBridge Scheduler runs it every 5 minutes (infra/security/setup-guard.sh). Each run:
//   G1  private S3 buckets: all 4 Block Public Access settings on          -> turned back on
//   G2  private S3 buckets: no bucket-policy statement that Allows "*"      -> those statements removed
//   G3  private S3 buckets: no ACL grant to AllUsers / AuthenticatedUsers   -> ACL reset to private
//   G4  private S3 buckets: default encryption on                           -> AES256 put back if missing;
//       buckets marked ":kms" must keep their KMS key                       -> alert if downgraded
//   G5  pb-* Lambda roles: no "*" actions, no admin policies attached       -> alert only (see below)
//   G6  JWT signing secret: automatic rotation still on                     -> alert only
// Everything it finds or fixes is logged (SECURITY_DRIFT_FIXED / SECURITY_DRIFT_FOUND) and sent as one
// alert to the SNS topic pb-ops-alarms. The alert holds resource names only, never data or secrets.
//
// Why G5/G6 only alert: rewriting IAM or rotation settings automatically could break the app or hide an
// attacker's change; a person must look. The guard's own role can read IAM but not change it.
// Uses the AWS SDK of the Node.js Lambda runtime (nothing to install). The pure functions at the top
// have no AWS calls and are unit-tested in tests/security-guard.test.js.

// "name" or "name:kms" (= this bucket must stay encrypted with a customer-managed KMS key).
const parseBuckets = (s) => s.split(',').map((x) => x.trim()).filter(Boolean)
  .map((x) => { const [name, want] = x.split(':'); return { name, kms: want === 'kms' }; });
const PRIVATE_BUCKETS = parseBuckets(process.env.PRIVATE_BUCKETS || 'pb-receipts-244694:kms,pb-reports-244694:kms,pb-audit-logs-244694');
const ROLE_PREFIX = process.env.ROLE_PREFIX || 'pb-';
const JWT_SECRET_ID = process.env.JWT_SECRET_ID || 'pb/jwt-secret';
const TOPIC_ARN = process.env.OPS_TOPIC_ARN || '';
const PUBLIC_GROUPS = ['http://acs.amazonaws.com/groups/global/AllUsers', 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'];
const ADMIN_POLICIES = ['AdministratorAccess', 'PowerUserAccess', 'IAMFullAccess'];
const BPA_ON = { BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true };

// ---------- pure checks ----------
const asList = (x) => (x === undefined ? [] : Array.isArray(x) ? x : [x]);

function bpaMissing(config) {
  const c = config || {};
  return Object.keys(BPA_ON).filter((k) => c[k] !== true);
}

// A statement is public when it ALLOWS everyone ("*" or {"AWS":"*"}). Deny statements with "*"
// (like our HTTPS-only rule) are protective and are kept.
function isPublicAllow(statement) {
  if (!statement || statement.Effect !== 'Allow') return false;
  const p = statement.Principal;
  if (p === '*') return true;
  if (p && typeof p === 'object') return asList(p.AWS).includes('*');
  return false;
}

// Returns { publicSids, fixed } where fixed is the policy without the public statements (null = delete).
function stripPublicStatements(policy) {
  const statements = asList(policy && policy.Statement);
  const bad = statements.filter(isPublicAllow);
  const keep = statements.filter((s) => !isPublicAllow(s));
  return {
    publicSids: bad.map((s, i) => s.Sid || `statement-${i + 1}`),
    fixed: bad.length === 0 ? policy : keep.length === 0 ? null : { ...policy, Statement: keep }
  };
}

function publicAclGrants(acl) {
  return asList(acl && acl.Grants).filter((g) => g.Grantee && PUBLIC_GROUPS.includes(g.Grantee.URI))
    .map((g) => `${g.Grantee.URI.split('/').pop()}:${g.Permission}`);
}

// Over-broad permissions in a role policy document: Action "*" or "<service>:*", or NotAction (allow
// everything except), on any statement that Allows.
function wildcardProblems(document) {
  const problems = [];
  for (const s of asList(document && document.Statement)) {
    if (s.Effect !== 'Allow') continue;
    if (s.NotAction) problems.push('NotAction (allows everything except a list)');
    for (const a of asList(s.Action)) {
      if (a === '*' || /^[a-z0-9-]+:\*$/i.test(a)) problems.push(`Action ${a}`);
    }
  }
  return problems;
}

// G4: what is wrong with a bucket's default encryption (null = fine).
function encryptionProblem(config, wantKms) {
  const rule = asList(config && config.Rules)[0];
  const algo = rule && rule.ApplyServerSideEncryptionByDefault && rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm;
  if (!algo) return 'missing';
  if (wantKms && !/^aws:kms/.test(algo)) return `downgraded to ${algo} (should use its KMS key)`;
  return null;
}

function summarise(findings) {
  const fixed = findings.filter((f) => f.fixed);
  const open = findings.filter((f) => !f.fixed);
  return { fixed: fixed.length, needsPerson: open.length, findings };
}

// ---------- AWS checks ----------
async function checkBuckets(s3, cmd, findings) {
  for (const { name: Bucket, kms } of PRIVATE_BUCKETS) {
    // G1 Block Public Access
    let bpa = null;
    try { bpa = (await s3.send(new cmd.GetPublicAccessBlockCommand({ Bucket }))).PublicAccessBlockConfiguration; }
    catch (e) { if (!/NoSuchPublicAccessBlockConfiguration/.test(e.name || e.message)) throw e; }
    const missing = bpaMissing(bpa);
    if (missing.length) {
      await s3.send(new cmd.PutPublicAccessBlockCommand({ Bucket, PublicAccessBlockConfiguration: BPA_ON }));
      findings.push({ check: 'G1', resource: Bucket, problem: `Block Public Access off: ${missing.join(', ')}`, fixed: true, action: 'all 4 settings turned back on' });
    }
    // G2 public bucket policy
    let policy = null;
    try { policy = JSON.parse((await s3.send(new cmd.GetBucketPolicyCommand({ Bucket }))).Policy); }
    catch (e) { if (!/NoSuchBucketPolicy/.test(e.name || e.message)) throw e; }
    if (policy) {
      const { publicSids, fixed } = stripPublicStatements(policy);
      if (publicSids.length) {
        if (fixed) await s3.send(new cmd.PutBucketPolicyCommand({ Bucket, Policy: JSON.stringify(fixed) }));
        else await s3.send(new cmd.DeleteBucketPolicyCommand({ Bucket }));
        findings.push({ check: 'G2', resource: Bucket, problem: `bucket policy allows everyone (${publicSids.join(', ')})`, fixed: true,
          action: fixed ? 'public statements removed, the rest kept' : 'policy deleted (it only had public statements)' });
      }
    }
    // G3 public ACL
    const grants = publicAclGrants(await s3.send(new cmd.GetBucketAclCommand({ Bucket })));
    if (grants.length) {
      await s3.send(new cmd.PutBucketAclCommand({ Bucket, ACL: 'private' }));
      findings.push({ check: 'G3', resource: Bucket, problem: `public ACL grants: ${grants.join(', ')}`, fixed: true, action: 'ACL reset to private' });
    }
    // G4 default encryption
    let enc = null;
    try { enc = (await s3.send(new cmd.GetBucketEncryptionCommand({ Bucket }))).ServerSideEncryptionConfiguration; }
    catch (e) { if (!/ServerSideEncryptionConfigurationNotFound/.test(e.name || e.message)) throw e; }
    const encProblem = encryptionProblem(enc, kms);
    if (encProblem === 'missing') {
      await s3.send(new cmd.PutBucketEncryptionCommand({ Bucket, ServerSideEncryptionConfiguration: {
        Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] } }));
      findings.push({ check: 'G4', resource: Bucket, problem: 'default encryption missing', fixed: true, action: 'AES256 default encryption put back' });
    } else if (encProblem) {
      // Which KMS key a bucket uses is its owner's choice, so the guard does not pick one: it alerts.
      findings.push({ check: 'G4', resource: Bucket, problem: `default encryption ${encProblem}`, fixed: false, action: "alert: the owner must put the bucket's KMS key back" });
    }
  }
}

async function checkRoles(iam, cmd, findings) {
  const roles = [];
  let Marker;
  do {
    const r = await iam.send(new cmd.ListRolesCommand({ Marker }));
    roles.push(...(r.Roles || []).filter((x) => x.RoleName.startsWith(ROLE_PREFIX)));
    Marker = r.IsTruncated ? r.Marker : undefined;
  } while (Marker);
  for (const { RoleName } of roles) {
    const names = (await iam.send(new cmd.ListRolePoliciesCommand({ RoleName }))).PolicyNames || [];
    for (const PolicyName of names) {
      const doc = (await iam.send(new cmd.GetRolePolicyCommand({ RoleName, PolicyName }))).PolicyDocument;
      const parsed = typeof doc === 'string' ? JSON.parse(decodeURIComponent(doc)) : doc;
      const problems = wildcardProblems(parsed);
      if (problems.length) findings.push({ check: 'G5', resource: `${RoleName}/${PolicyName}`, problem: `over-broad permissions: ${problems.join(', ')}`, fixed: false, action: 'alert: a person must review this IAM change' });
    }
    const attached = (await iam.send(new cmd.ListAttachedRolePoliciesCommand({ RoleName }))).AttachedPolicies || [];
    const admin = attached.filter((p) => ADMIN_POLICIES.includes(p.PolicyName));
    if (admin.length) findings.push({ check: 'G5', resource: RoleName, problem: `admin policy attached: ${admin.map((p) => p.PolicyName).join(', ')}`, fixed: false, action: 'alert: a person must review this IAM change' });
  }
  return roles.length;
}

async function checkRotation(sm, cmd, findings) {
  const d = await sm.send(new cmd.DescribeSecretCommand({ SecretId: JWT_SECRET_ID }));
  if (!d.RotationEnabled) findings.push({ check: 'G6', resource: JWT_SECRET_ID, problem: 'automatic key rotation is off', fixed: false, action: 'alert: run infra/security/setup-rotation.sh' });
}

const log = (level, event, fields) => console.log(JSON.stringify({ ts: new Date().toISOString(), level, service: 'security-guard', event, ...fields }));

exports.handler = async (event = {}) => {
  const s3m = require('@aws-sdk/client-s3');
  const iamm = require('@aws-sdk/client-iam');
  const smm = require('@aws-sdk/client-secrets-manager');
  const snsm = require('@aws-sdk/client-sns');
  const findings = [];
  const errors = [];
  let rolesChecked = 0;
  const step = async (name, fn) => { try { await fn(); } catch (e) { errors.push(`${name}: ${e.name || e.message}`); log('error', 'GUARD_CHECK_FAILED', { check: name, error: e.name || e.message }); } };
  await step('buckets', () => checkBuckets(new s3m.S3Client({ forcePathStyle: true }), s3m, findings));
  await step('roles', async () => { rolesChecked = await checkRoles(new iamm.IAMClient({}), iamm, findings); });
  await step('rotation', () => checkRotation(new smm.SecretsManagerClient({}), smm, findings));

  for (const f of findings) log(f.fixed ? 'warn' : 'error', f.fixed ? 'SECURITY_DRIFT_FIXED' : 'SECURITY_DRIFT_FOUND', f);
  const result = { ...summarise(findings), bucketsChecked: PRIVATE_BUCKETS.length, rolesChecked, errors, trigger: event.source || event.trigger || 'manual' };
  log(findings.length || errors.length ? 'warn' : 'info', 'GUARD_RUN', { fixed: result.fixed, needsPerson: result.needsPerson, bucketsChecked: result.bucketsChecked, rolesChecked, errors: errors.length, trigger: result.trigger });

  if ((findings.length || errors.length) && TOPIC_ARN) {
    const lines = findings.map((f) => `- [${f.check}] ${f.resource}: ${f.problem} -> ${f.fixed ? 'FIXED: ' : ''}${f.action}`);
    if (errors.length) lines.push(`- guard could not finish: ${errors.join('; ')}`);
    try {
      await new snsm.SNSClient({}).send(new snsm.PublishCommand({
        TopicArn: TOPIC_ARN,
        Subject: `Security guard: ${result.fixed} fixed, ${result.needsPerson} need a person`,
        Message: `The security guard found settings that drifted from the secure baseline.\n${lines.join('\n')}\nDetails: CloudWatch Logs /aws/lambda/pb-security-guard`
      }));
      log('info', 'GUARD_ALERT_SENT', { findings: findings.length });
    } catch (e) { log('error', 'GUARD_ALERT_FAILED', { error: e.name || e.message }); }
  }
  return result;
};

exports._test = { parseBuckets, bpaMissing, isPublicAllow, stripPublicStatements, publicAclGrants, encryptionProblem, wildcardProblems, summarise };
