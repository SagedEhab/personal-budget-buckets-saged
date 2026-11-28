#!/usr/bin/env bash
# Audit and threat detection (ENHANCEMENTS 5h, report sections 11 and 16).
#   bash infra/security/setup-audit.sh        (also run by infra/deploy-floci.sh)
#
# 1. CloudTrail: records every AWS API call (who, what, when, from where) into a private, versioned
#    S3 bucket with log-file validation, so changes to the account can be traced and the log cannot
#    be edited without it showing.
# 2. GuardDuty: watches CloudTrail, DNS and network logs for attacks (stolen keys, crypto-mining, scans).
# 3. Security Hub: one page that collects findings and scores the account against AWS best practices.
# 4. AWS Config: records the settings of every resource and checks them against rules (no public S3,
#    encryption on, point-in-time recovery on, CloudTrail on), flagging anything that drifts.
# Safe to run again.
# Floci 2.5.0 (26 Nov 2026): every call above is accepted and the trail, detector, hub, recorder and 5 rules
# exist, but Floci does not produce events: lookup-events is empty, no log files arrive in the bucket and
# the rules stay INSUFFICIENT_DATA. On real AWS the same script gives working audit logs (report section 16).
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 1
ACCOUNT=000000000000
REGION=us-east-1
BUCKET=pb-audit-logs-244694
TRAIL=pb-trail
CONFIG_ROLE=pb-config-role
TAGS='Project=personal-budget-buckets,Owner=saged-ehab-244694,Environment=dev'

echo "Audit log bucket (private, encrypted, versioned)"
aws s3api head-bucket --bucket $BUCKET > /dev/null 2>&1 || aws s3 mb s3://$BUCKET > /dev/null
aws s3api put-public-access-block --bucket $BUCKET --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
aws s3api put-bucket-encryption --bucket $BUCKET --server-side-encryption-configuration \
  '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-bucket-versioning --bucket $BUCKET --versioning-configuration Status=Enabled
aws s3api put-bucket-policy --bucket $BUCKET --policy "{\"Version\":\"2012-10-17\",\"Statement\":[
 {\"Sid\":\"TrailAclCheck\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"cloudtrail.amazonaws.com\",\"config.amazonaws.com\"]},\"Action\":\"s3:GetBucketAcl\",\"Resource\":\"arn:aws:s3:::$BUCKET\"},
 {\"Sid\":\"TrailWrite\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"cloudtrail.amazonaws.com\",\"config.amazonaws.com\"]},\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::$BUCKET/*\",\"Condition\":{\"StringEquals\":{\"s3:x-amz-acl\":\"bucket-owner-full-control\"}}},
 {\"Sid\":\"HttpsOnly\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::$BUCKET\",\"arn:aws:s3:::$BUCKET/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}" \
  2>/dev/null || echo "  (bucket policy not accepted by this Floci version)"
echo "  s3://$BUCKET"

# Object Lock (WORM: write once, read many): a log file cannot be deleted or changed until its retention
# date, even by an administrator, so an attacker cannot hide their tracks by erasing CloudTrail logs.
#   laptop (default): GOVERNANCE, 1 day: blocks deletes, but an admin can still clean up Floci on purpose
#   SCALE=aws:        COMPLIANCE, 365 days: nobody, including the root user, can delete it before then
# Tested on Floci 2.5.0: deleting a locked version returned AccessDenied in both modes.
if [ "${SCALE:-laptop}" = aws ]; then LOCK_MODE=COMPLIANCE; LOCK_DAYS=365; else LOCK_MODE=GOVERNANCE; LOCK_DAYS=1; fi
aws s3api put-object-lock-configuration --bucket $BUCKET --object-lock-configuration \
  "{\"ObjectLockEnabled\":\"Enabled\",\"Rule\":{\"DefaultRetention\":{\"Mode\":\"$LOCK_MODE\",\"Days\":$LOCK_DAYS}}}" || exit 1
echo "  Object Lock: $LOCK_MODE, $LOCK_DAYS day(s) per log file"
if [ "$1" = --prove ]; then
  KEY=lock-test/proof.txt
  echo "test log line $(date -u +%FT%TZ)" | aws s3 cp - s3://$BUCKET/$KEY > /dev/null
  VER=$(aws s3api list-object-versions --bucket $BUCKET --prefix $KEY --query 'Versions[0].VersionId' --output text)
  OUT=$(aws s3api delete-object --bucket $BUCKET --key $KEY --version-id "$VER" 2>&1)
  case "$OUT" in *AccessDenied*) echo "  proof: deleting a locked log file -> AccessDenied (PASS)";;
                 *) echo "  proof: delete was NOT blocked (FAIL): $OUT";; esac
fi

echo "CloudTrail: all regions, management events, log-file validation"
aws cloudtrail describe-trails --trail-name-list $TRAIL --query 'trailList[0].Name' --output text 2>/dev/null | grep -q $TRAIL || \
  aws cloudtrail create-trail --name $TRAIL --s3-bucket-name $BUCKET --s3-key-prefix cloudtrail \
    --is-multi-region-trail --enable-log-file-validation \
    --tags-list Key=Project,Value=personal-budget-buckets Key=Owner,Value=saged-ehab-244694 > /dev/null
aws cloudtrail start-logging --name $TRAIL
echo "  $TRAIL logging: $(aws cloudtrail get-trail-status --name $TRAIL --query IsLogging --output text)"

echo "GuardDuty: threat detection"
DETECTOR=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
if [ -z "$DETECTOR" ] || [ "$DETECTOR" = None ]; then
  DETECTOR=$(aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES \
    --tags Project=personal-budget-buckets,Owner=saged-ehab-244694 --query DetectorId --output text)
fi
echo "  detector $DETECTOR: $(aws guardduty get-detector --detector-id "$DETECTOR" --query Status --output text)"

echo "Security Hub: findings in one place, AWS Foundational Security Best Practices"
aws securityhub describe-hub > /dev/null 2>&1 || \
  aws securityhub enable-security-hub --enable-default-standards --tags "$TAGS" > /dev/null
echo "  hub: $(aws securityhub describe-hub --query HubArn --output text)"

echo "AWS Config: record every resource, check it against rules"
aws iam get-role --role-name $CONFIG_ROLE > /dev/null 2>&1 || \
  aws iam create-role --role-name $CONFIG_ROLE --assume-role-policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"config.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > /dev/null
aws iam attach-role-policy --role-name $CONFIG_ROLE \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWS_ConfigRole 2>/dev/null
aws configservice put-configuration-recorder --configuration-recorder \
  "name=default,roleARN=arn:aws:iam::$ACCOUNT:role/$CONFIG_ROLE" \
  --recording-group allSupported=true,includeGlobalResourceTypes=true
aws configservice put-delivery-channel --delivery-channel "name=default,s3BucketName=$BUCKET,s3KeyPrefix=config"
aws configservice start-configuration-recorder --configuration-recorder-name default
for RULE in S3_BUCKET_PUBLIC_READ_PROHIBITED S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED \
            DYNAMODB_PITR_ENABLED CLOUD_TRAIL_ENABLED LAMBDA_FUNCTION_PUBLIC_ACCESS_PROHIBITED; do
  NAME=pb-$(echo $RULE | tr 'A-Z_' 'a-z-')
  aws configservice put-config-rule --config-rule \
    "{\"ConfigRuleName\":\"$NAME\",\"Source\":{\"Owner\":\"AWS\",\"SourceIdentifier\":\"$RULE\"}}" \
    2>/dev/null && echo "  rule $NAME" || echo "  rule $NAME (not accepted by this Floci version)"
done
echo "  recorder: $(aws configservice describe-configuration-recorder-status \
  --query 'ConfigurationRecordersStatus[0].recording' --output text)"
echo "Audit and threat detection configured."
