#!/usr/bin/env bash
# Security guard: finds security settings that drifted and puts them back (ENHANCEMENTS 5o, report §8, §11, §15).
#   bash infra/security/setup-guard.sh           deploy the guard Lambda + run it every 5 minutes (also run by deploy-floci.sh)
#   bash infra/security/setup-guard.sh --prove   break the reports bucket on purpose, run the guard, check it was
#                                                repaired and that the team was alerted (evidence/security-guard-proof.txt)
#
# The guard (infra/security/security-guard/index.js) checks the private S3 buckets (Block Public Access,
# public policy, public ACL, default encryption) and fixes them; it checks the pb-* Lambda roles for "*"
# permissions or admin policies and the JWT key rotation, and only alerts on those (a person must look).
# Findings go to CloudWatch Logs and, as one message, to the SNS topic pb-ops-alarms.
# Least privilege: the guard may change only the 3 private buckets' public-access, policy, ACL and encryption
# settings; it can READ IAM roles but not change them; it can publish only to pb-ops-alarms.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 1
ACCOUNT=000000000000
REGION=us-east-1
FN=pb-security-guard
ROLE=pb-security-guard-role
SCHED_ROLE=pb-security-guard-scheduler-role
SCHEDULE=pb-security-guard-every-5-min
# ":kms" = must keep its customer-managed KMS key (setup-kms.sh); the guard alerts if it is downgraded
BUCKETS="pb-receipts-244694:kms pb-reports-244694:kms pb-audit-logs-244694"
TOPIC_ARN=$(aws sns create-topic --name pb-ops-alarms --query TopicArn --output text)
FN_ARN=arn:aws:lambda:$REGION:$ACCOUNT:function:$FN
TAR=/c/Windows/System32/tar.exe; [ -x "$TAR" ] || TAR=bsdtar

B_ARNS=$(for B in $BUCKETS; do printf '"arn:aws:s3:::%s",' "${B%%:*}"; done); B_ARNS="[${B_ARNS%,}]"

echo "Guard role $ROLE (least privilege)"
aws iam get-role --role-name $ROLE > /dev/null 2>&1 || \
  aws iam create-role --role-name $ROLE --assume-role-policy-document file://infra/iam/trust-policy.json > /dev/null
aws iam put-role-policy --role-name $ROLE --policy-name security-guard --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[
 {\"Sid\":\"RepairPrivateBuckets\",\"Effect\":\"Allow\",\"Action\":[\"s3:GetBucketPublicAccessBlock\",\"s3:PutBucketPublicAccessBlock\",
   \"s3:GetBucketPolicy\",\"s3:PutBucketPolicy\",\"s3:DeleteBucketPolicy\",\"s3:GetBucketAcl\",\"s3:PutBucketAcl\",
   \"s3:GetEncryptionConfiguration\",\"s3:PutEncryptionConfiguration\"],\"Resource\":$B_ARNS},
 {\"Sid\":\"ListRolesOnly\",\"Effect\":\"Allow\",\"Action\":\"iam:ListRoles\",\"Resource\":\"*\"},
 {\"Sid\":\"ReadTeamRoles\",\"Effect\":\"Allow\",\"Action\":[\"iam:ListRolePolicies\",\"iam:GetRolePolicy\",\"iam:ListAttachedRolePolicies\"],
   \"Resource\":\"arn:aws:iam::$ACCOUNT:role/pb-*\"},
 {\"Sid\":\"RotationStatus\",\"Effect\":\"Allow\",\"Action\":\"secretsmanager:DescribeSecret\",
   \"Resource\":\"arn:aws:secretsmanager:$REGION:$ACCOUNT:secret:pb/jwt-secret*\"},
 {\"Sid\":\"AlertTeam\",\"Effect\":\"Allow\",\"Action\":\"sns:Publish\",\"Resource\":\"$TOPIC_ARN\"},
 {\"Sid\":\"EncryptedTopic\",\"Effect\":\"Allow\",\"Action\":[\"kms:Decrypt\",\"kms:GenerateDataKey\"],\"Resource\":\"arn:aws:kms:$REGION:$ACCOUNT:key/*\",
   \"Condition\":{\"StringEquals\":{\"kms:ViaService\":\"sns.$REGION.amazonaws.com\"}}},
 {\"Sid\":\"OwnLogs\",\"Effect\":\"Allow\",\"Action\":[\"logs:CreateLogGroup\",\"logs:CreateLogStream\",\"logs:PutLogEvents\"],
   \"Resource\":\"arn:aws:logs:$REGION:$ACCOUNT:log-group:/aws/lambda/$FN:*\"}]}" || exit 1

ENV="{\"Variables\":{\"OPS_TOPIC_ARN\":\"$TOPIC_ARN\",\"PRIVATE_BUCKETS\":\"$(echo $BUCKETS | tr ' ' ',')\",\"JWT_SECRET_ID\":\"pb/jwt-secret\",\"ROLE_PREFIX\":\"pb-\"}}"
ZIP=infra/security/security-guard/guard.zip
rm -f "$ZIP"; (cd infra/security/security-guard && "$TAR" -a -c -f guard.zip index.js) || exit 1
if aws lambda get-function --function-name $FN > /dev/null 2>&1; then
  aws lambda update-function-code --function-name $FN --zip-file fileb://$ZIP > /dev/null
  aws lambda wait function-updated-v2 --function-name $FN
  aws lambda update-function-configuration --function-name $FN --environment "$ENV" > /dev/null
  aws lambda wait function-updated-v2 --function-name $FN
else
  aws lambda create-function --function-name $FN --runtime nodejs24.x --handler index.handler \
    --role arn:aws:iam::$ACCOUNT:role/$ROLE --zip-file fileb://$ZIP --timeout 60 --memory-size 128 \
    --environment "$ENV" --tags Project=personal-budget-buckets,Owner=saged-ehab-244694 > /dev/null || exit 1
  aws lambda wait function-active-v2 --function-name $FN
fi
rm -f "$ZIP"
echo "  $FN ready"

echo "Schedule: EventBridge Scheduler runs the guard every 5 minutes"
aws iam get-role --role-name $SCHED_ROLE > /dev/null 2>&1 || aws iam create-role --role-name $SCHED_ROLE \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"scheduler.amazonaws.com"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:SourceAccount":"'$ACCOUNT'"}}}]}' > /dev/null
aws iam put-role-policy --role-name $SCHED_ROLE --policy-name invoke-guard --policy-document \
  "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"lambda:InvokeFunction\",\"Resource\":\"$FN_ARN\"}]}"
TARGET="{\"Arn\":\"$FN_ARN\",\"RoleArn\":\"arn:aws:iam::$ACCOUNT:role/$SCHED_ROLE\",\"Input\":\"{\\\"source\\\":\\\"scheduler\\\"}\"}"
if aws scheduler get-schedule --name $SCHEDULE > /dev/null 2>&1; then
  aws scheduler update-schedule --name $SCHEDULE --schedule-expression "rate(5 minutes)" --flexible-time-window Mode=OFF --target "$TARGET" > /dev/null
else
  aws scheduler create-schedule --name $SCHEDULE --schedule-expression "rate(5 minutes)" --flexible-time-window Mode=OFF --target "$TARGET" > /dev/null || exit 1
fi
echo "  $SCHEDULE: $(aws scheduler get-schedule --name $SCHEDULE --query '[ScheduleExpression,State]' --output text)"

[ "$1" = --prove ] || exit 0

# ---------------------------------------------------------------- proof
B=pb-reports-244694
OUT=evidence/security-guard-proof.txt
run() { echo "$@" | tee -a $OUT; }
: > $OUT
run "Security guard proof ($(date -u +%Y-%m-%dT%H:%M:%SZ)) on Floci. Target: $B (private reports bucket)"
ORIG_ENC=$(aws s3api get-bucket-encryption --bucket $B --query ServerSideEncryptionConfiguration --output json)

# Listen on the ops topic with a test queue (in place of the team's e-mail)
Q_URL=$(aws sqs create-queue --queue-name pb-guard-proof --query QueueUrl --output text)
Q_ARN=$(aws sqs get-queue-attributes --queue-url "$Q_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)
SUB=$(aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol sqs --notification-endpoint "$Q_ARN" --query SubscriptionArn --output text)

state() {
  echo "  Block Public Access: $(aws s3api get-public-access-block --bucket $B --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text 2>&1 | tr '\t' '/')"
  echo "  bucket policy:       $(aws s3api get-bucket-policy --bucket $B --query Policy --output text 2>/dev/null || echo none)"
  echo "  public ACL grants:   $(aws s3api get-bucket-acl --bucket $B --query "Grants[?Grantee.URI!=null].[Grantee.URI,Permission]" --output text | tr '\t\n' ': ' | sed 's#http://acs.amazonaws.com/groups/global/##g')"
  echo "  default encryption:  $(aws s3api get-bucket-encryption --bucket $B --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo none)"
}
run "1. Before: the secure baseline"; state | tee -a $OUT
run "2. Simulated misconfiguration (what a careless change or an attacker would do):"
run "  - delete Block Public Access"; aws s3api delete-public-access-block --bucket $B
run "  - add a policy that lets anyone read every file"
aws s3api put-bucket-policy --bucket $B --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"MadePublic\",\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"s3:GetObject\",\"Resource\":\"arn:aws:s3:::$B/*\"}]}"
ACL_TRY=$(aws s3api put-bucket-acl --bucket $B --acl public-read 2>&1)
case "$ACL_TRY" in *AccessControlListNotSupported*) run "  - try a public-read ACL: refused by S3 (ACLs are disabled on this bucket), so G3 cannot drift here; G3 is covered by unit test SG-04";;
  *) run "  - set a public-read ACL";; esac
run "  - remove the KMS default encryption (S3 falls back to AES256)"; aws s3api delete-bucket-encryption --bucket $B
state | tee -a $OUT
run "3. The guard runs (the same code the 5-minute schedule runs; invoked now so we do not wait):"
GOUT=infra/security/security-guard/out.json
aws lambda invoke --function-name $FN --payload '{"source":"prove"}' --cli-binary-format raw-in-base64-out $GOUT > /dev/null
node -e "const r=require('./$GOUT');console.log('  result: fixed '+r.fixed+', need a person '+r.needsPerson+', buckets checked '+r.bucketsChecked+', roles checked '+r.rolesChecked+', errors '+r.errors.length);r.findings.forEach(f=>console.log('   ['+f.check+'] '+f.resource+': '+f.problem+' -> '+(f.fixed?'FIXED: ':'')+f.action))" | tee -a $OUT
G4_FLAGGED=$(node -pe "require('./$GOUT').findings.some(f=>f.check==='G4'&&f.resource==='$B'&&/downgraded/.test(f.problem))")
rm -f $GOUT
run "4. After the guard run"; state | tee -a $OUT
run "5. Team alerted on pb-ops-alarms:"
MSG=$(aws sqs receive-message --queue-url "$Q_URL" --wait-time-seconds 10 --max-number-of-messages 5 --query 'Messages[].Body' --output text)
SUBJ=$(printf '%s' "$MSG" | node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const m=s.match(/\"Subject\"\s*:\s*\"([^\"]+)\"/);console.log(m?m[1]:'(no alert received)')})")
run "  subject: $SUBJ"

AFTER_BPA=$(aws s3api get-public-access-block --bucket $B --query 'PublicAccessBlockConfiguration.[BlockPublicAcls,IgnorePublicAcls,BlockPublicPolicy,RestrictPublicBuckets]' --output text | tr -s '\t' ' ')
AFTER_POL=$(aws s3api get-bucket-policy --bucket $B --query Policy --output text 2>/dev/null || echo none)
AFTER_ACL=$(aws s3api get-bucket-acl --bucket $B --query "length(Grants[?Grantee.URI!=null])" --output text)

# The owner's step from the alert: put the bucket's own KMS key back
aws s3api put-bucket-encryption --bucket $B --server-side-encryption-configuration "$ORIG_ENC"
run "6. Owner's follow-up from the alert: KMS default encryption put back -> $(aws s3api get-bucket-encryption --bucket $B --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text)"
aws sns unsubscribe --subscription-arn "$SUB"; aws sqs delete-queue --queue-url "$Q_URL"

if [ "$AFTER_BPA" = "True True True True" ] && [ "$AFTER_POL" = none ] && [ "$AFTER_ACL" = 0 ] && [ "$G4_FLAGGED" = true ] && [ "${SUBJ#Security guard}" != "$SUBJ" ]; then
  run "RESULT: PASS (Block Public Access and the public policy repaired automatically, the KMS downgrade flagged, alert delivered)"
else
  run "RESULT: FAIL (bpa=$AFTER_BPA policy=$AFTER_POL publicGrants=$AFTER_ACL kmsDowngradeFlagged=$G4_FLAGGED alert=$SUBJ)"; exit 1
fi
