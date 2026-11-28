#!/usr/bin/env bash
# Customer-managed encryption key (report sections 6 and 8).
#   bash infra/security/setup-kms.sh        (also run by infra/deploy-floci.sh)
#
# Before: every table, bucket and the secret were encrypted with keys AWS owns and manages for us.
# Now: keys that WE own. Two keys, so one compromised or disabled key does not expose or lock everything:
#   alias/pb-transactions (Salma, services/transactions-service/infra/setup-kms.sh):
#     - the PBTransactions table and the receipts bucket (the most sensitive: amounts and receipt photos)
#   alias/pb-data-key (this script, Saged): everything else
#     - the PBUsers, PBBuckets and PBReports tables   - the reports S3 bucket (with an S3 Bucket Key)
#     - the JWT signing secret   - the two SNS topics   - the Lambda log groups
# This script never touches the Transactions table or the receipts bucket (it used to, which overwrote
# Salma's key: fixed 27 Nov).
# Why it is better:
#   - Automatic yearly rotation of the key material, old data still decrypts.
#   - Every use of the key is a CloudTrail event (who decrypted what, when).
#   - We can switch the key off: all data becomes unreadable at once (incident "kill switch").
#   - The key policy decides who may use it, on top of IAM (two locks instead of one).
#   - The Lambda roles may only use it through DynamoDB, S3, Secrets Manager and SNS (kms:ViaService),
#     never to decrypt arbitrary data directly (infra/iam/*-policy.json).
# Safe to run again. Tested on Floci 2.5.0: key, rotation and all re-encryptions accepted.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 1
ACCOUNT=000000000000
REGION=us-east-1
ALIAS=alias/pb-data-key
SUFFIX=244694
TABLES="PBUsers PBBuckets PBReports"          # PBTransactions: Salma's alias/pb-transactions
BUCKETS="pb-reports-$SUFFIX"                  # pb-receipts-$SUFFIX: Salma's alias/pb-transactions
TOPICS="pb-budget-alerts pb-ops-alarms"
FUNCTIONS="auth buckets transactions insights"

# Key policy: the account administrators manage the key; CloudWatch Logs may use it for our log groups.
# Everyone else needs an IAM permission as well (the Lambda policies grant use via the services only).
POLICY="{\"Version\":\"2012-10-17\",\"Statement\":[
 {\"Sid\":\"AccountAdmins\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::$ACCOUNT:root\"},\"Action\":\"kms:*\",\"Resource\":\"*\"},
 {\"Sid\":\"CloudWatchLogs\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"logs.$REGION.amazonaws.com\"},
  \"Action\":[\"kms:Encrypt*\",\"kms:Decrypt*\",\"kms:ReEncrypt*\",\"kms:GenerateDataKey*\",\"kms:Describe*\"],\"Resource\":\"*\",
  \"Condition\":{\"ArnLike\":{\"kms:EncryptionContext:aws:logs:arn\":\"arn:aws:logs:$REGION:$ACCOUNT:log-group:/aws/lambda/pb-*\"}}},
 {\"Sid\":\"AlarmsAndEventsPublishToEncryptedTopics\",\"Effect\":\"Allow\",
  \"Principal\":{\"Service\":[\"cloudwatch.amazonaws.com\",\"events.amazonaws.com\"]},
  \"Action\":[\"kms:GenerateDataKey*\",\"kms:Decrypt\"],\"Resource\":\"*\",
  \"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"$ACCOUNT\"}}}]}"

echo "Customer-managed KMS key $ALIAS (yearly automatic rotation)"
KEY_ID=$(aws kms describe-key --key-id $ALIAS --query KeyMetadata.KeyId --output text 2>/dev/null)
if [ -z "$KEY_ID" ] || [ "$KEY_ID" = None ]; then
  KEY_ID=$(aws kms create-key --description "Personal Budget Buckets data key" --policy "$POLICY" \
    --tags TagKey=Project,TagValue=personal-budget-buckets TagKey=Owner,TagValue=saged-ehab-244694 \
    --query KeyMetadata.KeyId --output text) || exit 1
  aws kms create-alias --alias-name $ALIAS --target-key-id "$KEY_ID"
fi
aws kms put-key-policy --key-id "$KEY_ID" --policy-name default --policy "$POLICY" || exit 1
aws kms enable-key-rotation --key-id "$KEY_ID"
KEY_ARN=$(aws kms describe-key --key-id "$KEY_ID" --query KeyMetadata.Arn --output text)
echo "  key $KEY_ID, rotation: $(aws kms get-key-rotation-status --key-id "$KEY_ID" --query KeyRotationEnabled --output text)"

echo "DynamoDB tables"
for T in $TABLES; do
  CUR=$(aws dynamodb describe-table --table-name $T --query Table.SSEDescription.KMSMasterKeyArn --output text 2>/dev/null)
  case "$CUR" in *"$KEY_ID"*) ;; *)
    aws dynamodb update-table --table-name $T \
      --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId="$KEY_ARN" > /dev/null ;; esac
  echo "  $T: $(aws dynamodb describe-table --table-name $T --query 'Table.SSEDescription.[SSEType,Status]' --output text)"
done

echo "S3 buckets (SSE-KMS with S3 Bucket Keys, which cut KMS requests and cost by about 99%)"
for B in $BUCKETS; do
  aws s3api put-bucket-encryption --bucket $B --server-side-encryption-configuration \
    "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$KEY_ARN\"},\"BucketKeyEnabled\":true}]}"
  echo "  $B: $(aws s3api get-bucket-encryption --bucket $B \
    --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text)"
done

echo "Secrets Manager: JWT signing secret"
aws secretsmanager update-secret --secret-id pb/jwt-secret --kms-key-id "$KEY_ARN" > /dev/null
echo "  pb/jwt-secret: $(aws secretsmanager describe-secret --secret-id pb/jwt-secret --query KmsKeyId --output text)"

echo "SNS topics"
for N in $TOPICS; do
  ARN=$(aws sns create-topic --name $N --query TopicArn --output text)
  aws sns set-topic-attributes --topic-arn "$ARN" --attribute-name KmsMasterKeyId --attribute-value $ALIAS
  echo "  $N: $(aws sns get-topic-attributes --topic-arn "$ARN" --query Attributes.KmsMasterKeyId --output text)"
done

echo "Lambda log groups"
for S in $FUNCTIONS; do
  aws logs associate-kms-key --log-group-name /aws/lambda/pb-$S-api --kms-key-id "$KEY_ARN" 2>/dev/null \
    && echo "  /aws/lambda/pb-$S-api: encrypted" || echo "  /aws/lambda/pb-$S-api: (not accepted by this Floci version)"
done
echo "KMS encryption configured."
