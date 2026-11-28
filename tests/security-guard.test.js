// Security guard (ENHANCEMENTS 5o, Saged): the checks that decide what counts as drift.
// The AWS calls themselves are proved live on Floci by `bash infra/security/setup-guard.sh --prove`.
const test = require('node:test');
const assert = require('node:assert/strict');
const { _test: g } = require('../infra/security/security-guard/index.js');

test('SG-01 Block Public Access: every setting that is off or missing is reported', () => {
  assert.deepEqual(g.bpaMissing({ BlockPublicAcls: true, IgnorePublicAcls: true, BlockPublicPolicy: true, RestrictPublicBuckets: true }), []);
  assert.deepEqual(g.bpaMissing({ BlockPublicAcls: true, IgnorePublicAcls: false, BlockPublicPolicy: true }), ['IgnorePublicAcls', 'RestrictPublicBuckets']);
  assert.equal(g.bpaMissing(null).length, 4);
});

test('SG-02 a policy statement is public only when it ALLOWS everyone', () => {
  assert.equal(g.isPublicAllow({ Effect: 'Allow', Principal: '*', Action: 's3:GetObject' }), true);
  assert.equal(g.isPublicAllow({ Effect: 'Allow', Principal: { AWS: '*' } }), true);
  assert.equal(g.isPublicAllow({ Effect: 'Allow', Principal: { AWS: ['arn:aws:iam::1:root', '*'] } }), true);
  // our HTTPS-only rule: Deny for everyone is protective, never removed
  assert.equal(g.isPublicAllow({ Effect: 'Deny', Principal: '*', Action: 's3:*' }), false);
  assert.equal(g.isPublicAllow({ Effect: 'Allow', Principal: { Service: 'cloudtrail.amazonaws.com' } }), false);
});

test('SG-03 removing public statements keeps the protective and service statements', () => {
  const policy = { Version: '2012-10-17', Statement: [
    { Sid: 'TrailWrite', Effect: 'Allow', Principal: { Service: 'cloudtrail.amazonaws.com' }, Action: 's3:PutObject' },
    { Sid: 'Oops', Effect: 'Allow', Principal: '*', Action: 's3:GetObject' },
    { Sid: 'HttpsOnly', Effect: 'Deny', Principal: '*', Action: 's3:*' }] };
  const r = g.stripPublicStatements(policy);
  assert.deepEqual(r.publicSids, ['Oops']);
  assert.deepEqual(r.fixed.Statement.map((s) => s.Sid), ['TrailWrite', 'HttpsOnly']);
  // a policy made only of public statements is deleted (fixed = null); a clean one is left as it is
  assert.equal(g.stripPublicStatements({ Statement: [{ Effect: 'Allow', Principal: '*' }] }).fixed, null);
  const clean = { Statement: [{ Sid: 'HttpsOnly', Effect: 'Deny', Principal: '*' }] };
  assert.equal(g.stripPublicStatements(clean).fixed, clean);
});

test('SG-04 ACL grants to AllUsers or AuthenticatedUsers are public; the owner grant is not', () => {
  const acl = { Grants: [
    { Grantee: { Type: 'CanonicalUser', ID: 'owner' }, Permission: 'FULL_CONTROL' },
    { Grantee: { Type: 'Group', URI: 'http://acs.amazonaws.com/groups/global/AllUsers' }, Permission: 'READ' },
    { Grantee: { Type: 'Group', URI: 'http://acs.amazonaws.com/groups/global/AuthenticatedUsers' }, Permission: 'WRITE' }] };
  assert.deepEqual(g.publicAclGrants(acl), ['AllUsers:READ', 'AuthenticatedUsers:WRITE']);
  assert.deepEqual(g.publicAclGrants({ Grants: [acl.Grants[0]] }), []);
});

test('SG-05 IAM: "*" and "service:*" actions and NotAction are over-broad; named actions are fine', () => {
  assert.deepEqual(g.wildcardProblems({ Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] }), ['Action *']);
  assert.deepEqual(g.wildcardProblems({ Statement: [{ Effect: 'Allow', Action: ['dynamodb:GetItem', 's3:*'] }] }), ['Action s3:*']);
  assert.deepEqual(g.wildcardProblems({ Statement: [{ Effect: 'Allow', NotAction: 'iam:*' }] }), ['NotAction (allows everything except a list)']);
  // the real Buckets policy shape: named actions on named resources, and a Deny is never a problem
  assert.deepEqual(g.wildcardProblems({ Statement: [
    { Effect: 'Allow', Action: ['dynamodb:GetItem', 'dynamodb:Query'], Resource: 'arn:aws:dynamodb:us-east-1:0:table/PBBuckets' },
    { Effect: 'Allow', Action: 'sns:Publish', Resource: 'arn:aws:sns:us-east-1:0:pb-budget-alerts' },
    { Effect: 'Deny', Action: '*', Resource: '*' }] }), []);
});

test('SG-07 encryption: missing is fixed; a KMS bucket downgraded to AES256 is flagged', () => {
  const kmsRule = { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms', KMSMasterKeyID: 'k' } }] };
  const aesRule = { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }] };
  assert.equal(g.encryptionProblem(null, false), 'missing');
  assert.equal(g.encryptionProblem(aesRule, false), null);
  assert.equal(g.encryptionProblem(kmsRule, true), null);
  assert.match(g.encryptionProblem(aesRule, true), /downgraded to AES256/);
  assert.deepEqual(g.parseBuckets('a:kms, b'), [{ name: 'a', kms: true }, { name: 'b', kms: false }]);
});

test('SG-06 the summary separates what was fixed from what needs a person', () => {
  const s = g.summarise([{ check: 'G1', fixed: true }, { check: 'G5', fixed: false }, { check: 'G2', fixed: true }]);
  assert.equal(s.fixed, 2);
  assert.equal(s.needsPerson, 1);
});
