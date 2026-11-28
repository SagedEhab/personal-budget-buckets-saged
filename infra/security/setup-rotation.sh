#!/usr/bin/env bash
# Automatic rotation of the JWT signing key (report sections 6 and 8).
#   bash infra/security/setup-rotation.sh          set up rotation every 30 days (also run by deploy-floci.sh)
#   bash infra/security/setup-rotation.sh --now        also rotate once now and prove logged-in users stay logged in
#   bash infra/security/setup-rotation.sh --emergency  the key leaked: replace it and reject every old token at once
#
# A leaked signing key lets an attacker make their own valid tokens (become any user, even admin).
# Rotating it every 30 days limits how long a leaked key is useful. The rotation Lambda
# (infra/security/jwt-rotator) makes a new random key; the services sign with the new key and still
# accept the old one, so nobody is logged out (pb-common/lib/secrets.js, auth.js).
# Switch-over: each Lambda caches the keys for up to 10 minutes, so for up to 10 minutes after a rotation
# some new logins are still signed with the previous key. That is safe (every service accepts it) and was
# measured on Floci: right after the drill's rotation, a new login was still signed with the previous key.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 1
ACCOUNT=000000000000
REGION=us-east-1
SECRET_ID=pb/jwt-secret
FN=pb-jwt-rotator
ROLE=pb-jwt-rotator-role
DAYS=30
TAR=/c/Windows/System32/tar.exe; [ -x "$TAR" ] || TAR=bsdtar

echo "Rotation Lambda $FN (least privilege: only this one secret)"
aws iam get-role --role-name $ROLE > /dev/null 2>&1 || \
  aws iam create-role --role-name $ROLE --assume-role-policy-document file://infra/iam/trust-policy.json > /dev/null
aws iam put-role-policy --role-name $ROLE --policy-name rotate-jwt-secret --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
 {\"Effect\":\"Allow\",\"Action\":[\"secretsmanager:DescribeSecret\",\"secretsmanager:GetSecretValue\",\"secretsmanager:PutSecretValue\",\"secretsmanager:UpdateSecretVersionStage\"],
  \"Resource\":\"arn:aws:secretsmanager:$REGION:$ACCOUNT:secret:$SECRET_ID*\"},
 {\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\",\"kms:GenerateDataKey\"],\"Resource\":\"arn:aws:kms:$REGION:$ACCOUNT:key/*\",
  \"Condition\":{\"StringEquals\":{\"kms:ViaService\":\"secretsmanager.$REGION.amazonaws.com\"}}},
 {\"Effect\":\"Allow\",\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],
  \"Resource\":\"arn:aws:logs:$REGION:$ACCOUNT:log-group:/aws/lambda/$FN:*\"}]}"
ZIP=infra/security/jwt-rotator/rotator.zip
rm -f "$ZIP"; (cd infra/security/jwt-rotator && "$TAR" -a -c -f rotator.zip index.js) || exit 1
if aws lambda get-function --function-name $FN > /dev/null 2>&1; then
  aws lambda update-function-code --function-name $FN --zip-file fileb://$ZIP > /dev/null
  aws lambda wait function-updated-v2 --function-name $FN
else
  aws lambda create-function --function-name $FN --runtime nodejs24.x --handler index.handler \
    --role arn:aws:iam::$ACCOUNT:role/$ROLE --zip-file fileb://$ZIP --timeout 30 --memory-size 128 \
    --tags Project=personal-budget-buckets,Owner=saged-ehab-244694 > /dev/null || exit 1
  aws lambda wait function-active-v2 --function-name $FN
  # Only Secrets Manager, for this one secret, may call the rotator
  aws lambda add-permission --function-name $FN --statement-id secretsmanager-rotation \
    --action lambda:InvokeFunction --principal secretsmanager.amazonaws.com \
    --source-arn "arn:aws:secretsmanager:$REGION:$ACCOUNT:secret:$SECRET_ID*" > /dev/null
fi
rm -f "$ZIP"
echo "  $FN ready"

echo "Rotation schedule: every $DAYS days"
aws secretsmanager rotate-secret --secret-id $SECRET_ID \
  --rotation-lambda-arn arn:aws:lambda:$REGION:$ACCOUNT:function:$FN \
  --rotation-rules AutomaticallyAfterDays=$DAYS --no-rotate-immediately > /dev/null || exit 1
echo "  $SECRET_ID rotation enabled: $(aws secretsmanager describe-secret --secret-id $SECRET_ID \
  --query '[RotationEnabled, RotationRules.AutomaticallyAfterDays]' --output text)"

# Restart every service Lambda so no copy keeps a cached key: changing an environment variable
# (KEY_EPOCH) makes Lambda start fresh containers, which load the keys again.
recycle_services() {
  for S in auth buckets transactions insights; do
    F=pb-$S-api
    ENV=$(aws lambda get-function-configuration --function-name $F --query Environment.Variables --output json \
      | node -pe "JSON.stringify({Variables:{...JSON.parse(require('fs').readFileSync(0)),KEY_EPOCH:'$(date +%s)'}})")
    aws lambda update-function-configuration --function-name $F --environment "$ENV" > /dev/null
    aws lambda wait function-updated-v2 --function-name $F
  done
}
# stage_of <label>: the version id that has this label (empty if none)
stage_of() {
  aws secretsmanager describe-secret --secret-id $SECRET_ID --query 'VersionIdsToStages' --output json \
    | node -pe "const v=JSON.parse(require('fs').readFileSync(0));Object.keys(v).find(k=>v[k].includes('$1'))||''"
}
# Rotate once and wait until it is finished: AWSCURRENT moved and no AWSPENDING label left.
rotate_once() {
  local before; before=$(stage_of AWSCURRENT)
  aws secretsmanager rotate-secret --secret-id $SECRET_ID --rotate-immediately > /dev/null || return 1
  for i in $(seq 1 30); do
    [ "$(stage_of AWSCURRENT)" != "$before" ] && [ -z "$(stage_of AWSPENDING)" ] && return 0
    sleep 2
  done
  return 1
}

# Emergency (the key has leaked): rotate twice so the leaked key is no longer even the "previous" key,
# then restart the services so it is rejected at once instead of after the 10-minute cache.
if [ "$1" = --emergency ]; then
  echo "EMERGENCY key replacement"
  API_ID=$(aws apigatewayv2 get-apis --query "Items[?Name=='pb-http-api'].ApiId | [0]" --output text)
  API=http://$API_ID.execute-api.localhost.floci.io:4566
  EMAIL="leak$(date +%s)@example.com"; PASS=LeakedPass2026
  curl -s -m 60 -X POST "$API/api/auth/register" -H 'content-type: application/json' \
    -d "{\"name\":\"Leak Drill\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" > /dev/null
  LEAKED=$(curl -s -m 60 -X POST "$API/api/auth/login" -H 'content-type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | node -pe 'JSON.parse(require("fs").readFileSync(0)).token')
  code() { curl -s -m 60 -w '
%{http_code}' "$API/api/buckets" -H "authorization: Bearer $1" | tail -n 1; }
  C0=$(code "$LEAKED")
  echo "  1. token signed with the key we pretend leaked: /api/buckets -> $C0 (should be 200)"
  [ "$C0" = 200 ] || { echo "  the token did not work before the rotation, so the drill proves nothing: RESULT FAIL"; exit 1; }
  rotate_once && rotate_once || { echo "  rotation failed: RESULT FAIL"; exit 1; }
  echo "  2. rotated twice: the leaked key is neither current nor previous"
  recycle_services
  echo "  3. restarted the 4 service Lambdas (no cached keys left)"
  C=$(code "$LEAKED")
  echo "  4. same token now: /api/buckets -> $C (should be 401)"
  [ "$C" = 401 ] && echo "RESULT: PASS (everyone must log in again, which is right after a leak)" || { echo "RESULT: FAIL"; exit 1; }
  exit 0
fi

[ "$1" = --now ] || exit 0

echo "Rotation drill: a logged-in user keeps working across a key change"
API_ID=$(aws apigatewayv2 get-apis --query "Items[?Name=='pb-http-api'].ApiId | [0]" --output text)
API=http://$API_ID.execute-api.localhost.floci.io:4566
EMAIL="rotation$(date +%s)@example.com"; PASS=RotatePass2026
curl -s -m 60 -X POST "$API/api/auth/register" -H 'content-type: application/json' \
  -d "{\"name\":\"Rotation Drill\",\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" > /dev/null
login() { curl -s -m 60 -X POST "$API/api/auth/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" | node -pe 'JSON.parse(require("fs").readFileSync(0)).token'; }
code() { curl -s -m 60 -w '
%{http_code}' "$API/api/buckets" -H "authorization: Bearer $1" | tail -n 1; }
version() { aws secretsmanager describe-secret --secret-id $SECRET_ID \
  --query 'VersionIdsToStages' --output json | node -pe 'const v=JSON.parse(require("fs").readFileSync(0));Object.keys(v).find(k=>v[k].includes("AWSCURRENT"))'; }
OLD_TOKEN=$(login); BEFORE=$(version); C_BASE=$(code "$OLD_TOKEN")
echo "  1. logged in with key version $BEFORE: /api/buckets -> $C_BASE (should be 200)"
[ "$C_BASE" = 200 ] || { echo "  the token did not work before the rotation, so the drill proves nothing: RESULT FAIL"; exit 1; }
rotate_once; AFTER=$(version)
if [ "$AFTER" = "$BEFORE" ]; then
  echo "  2. key did NOT change (still $AFTER): RESULT FAIL. Check: aws logs tail /aws/lambda/$FN"; exit 1
fi
PREV=$(aws secretsmanager describe-secret --secret-id $SECRET_ID --query 'VersionIdsToStages' --output json \
  | node -pe 'const v=JSON.parse(require("fs").readFileSync(0));Object.keys(v).find(k=>v[k].includes("AWSPREVIOUS"))')
echo "  2. rotated: AWSCURRENT is now $AFTER, AWSPREVIOUS is $PREV"
# The services cache the keys for up to 10 minutes; a token signed with a key they have not loaded yet
# makes them reload once (pb-common/lib/auth.js), so no waiting is needed.
C_OLD=$(code "$OLD_TOKEN")
echo "  3. token signed with the OLD key: /api/buckets -> $C_OLD (should be 200: still accepted, expires within 1 h)"
NEW_TOKEN=$(login)
C_NEW=$(code "$NEW_TOKEN")
# Which key signed the new token? Checked here without ever printing a key.
SIGNED_BY=$(TOK="$NEW_TOKEN" \
  CUR="$(aws secretsmanager get-secret-value --secret-id $SECRET_ID --version-stage AWSCURRENT --query SecretString --output text)" \
  PRE="$(aws secretsmanager get-secret-value --secret-id $SECRET_ID --version-stage AWSPREVIOUS --query SecretString --output text)" \
  node -e 'const c=require("crypto");const [h,p,s]=process.env.TOK.split(".");const m=k=>c.createHmac("sha256",k).update(h+"."+p).digest("base64url")===s;
           console.log(m(process.env.CUR)?"the NEW key":m(process.env.PRE)?"the previous key (Auth switches within its 10-minute key cache)":"an unknown key")')
echo "  4. new login: /api/buckets -> $C_NEW, token signed with $SIGNED_BY"
FAKE="${OLD_TOKEN%.*}.$(printf 'forged' | base64 | tr '+/' '-_' | tr -d '=')"
C_FAKE=$(code "$FAKE")
echo "  5. token with a forged signature: /api/buckets -> $C_FAKE (should be 401)"
case "$SIGNED_BY" in *unknown*) echo "  (a service still has a key from an earlier rotation cached: run with --emergency, or wait 10 min)";; esac
[ "$C_OLD" = 200 ] && [ "$C_NEW" = 200 ] && [ "$C_FAKE" = 401 ] && [ "${SIGNED_BY#*unknown}" = "$SIGNED_BY" ] \
  && echo "RESULT: PASS" || { echo "RESULT: FAIL"; exit 1; }
