#!/usr/bin/env bash
# Deploys Personal Budget Buckets to Floci (extends Lab 7's setup-lab7.sh from 1 to 4 Lambdas).
#   docker compose -f infra/floci/docker-compose.yml up -d
#   bash infra/deploy-floci.sh
#   bash infra/check-floci.sh
# Safe to run again: existing resources are reused, code and settings are updated.
#
# AI-ASSISTED DRAFT: written by Claude, NOT yet run against Floci (no Docker/AWS CLI on the
# machine where it was written). Run it, fix what your Floci version rejects, and keep the output
# as deployment evidence.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.." || exit 1
REGION=us-east-1
ACCOUNT=000000000000
SUFFIX=244694
WEB_BUCKET=pb-web
RECEIPTS_BUCKET=pb-receipts-$SUFFIX
REPORTS_BUCKET=pb-reports-$SUFFIX
TOPIC=pb-budget-alerts
SECRET_ID=pb/jwt-secret
ORIGIN=http://localhost:4566
SERVICES="auth buckets transactions insights"
TMP=out/.deploy; mkdir -p "$TMP"

if ! curl -s -o /dev/null http://localhost:4566/_floci/health; then
  echo "Floci is not running. Start Docker Desktop, then:"
  echo "  docker compose -f infra/floci/docker-compose.yml up -d"; exit 1
fi

table_for() { case $1 in auth) echo PBUsers;; buckets) echo PBBuckets;; transactions) echo PBTransactions;; insights) echo PBReports;; esac; }

echo "1/8 DynamoDB tables (pk + sk, on-demand, encrypted)"
for S in $SERVICES; do
  T=$(table_for $S)
  if ! aws dynamodb describe-table --table-name $T > /dev/null 2>&1; then
    aws dynamodb create-table --table-name $T \
      --attribute-definitions AttributeName=pk,AttributeType=S AttributeName=sk,AttributeType=S \
      --key-schema AttributeName=pk,KeyType=HASH AttributeName=sk,KeyType=RANGE \
      --billing-mode PAY_PER_REQUEST --sse-specification Enabled=true > /dev/null
    aws dynamodb wait table-exists --table-name $T
  fi
  echo "  $T"
done

echo "2/8 Secrets Manager: JWT signing key (random, never printed, never in git)"
if ! aws secretsmanager describe-secret --secret-id $SECRET_ID > /dev/null 2>&1; then
  aws secretsmanager create-secret --name $SECRET_ID \
    --secret-string "$(node -e "console.log(require('crypto').randomBytes(48).toString('hex'))")" > /dev/null
fi

echo "3/8 SNS topic for budget alerts"
TOPIC_ARN=$(aws sns create-topic --name $TOPIC --query TopicArn --output text)

echo "4/8 Private S3 buckets for receipts and reports (Block Public Access + encryption)"
for B in $RECEIPTS_BUCKET $REPORTS_BUCKET; do
  aws s3api head-bucket --bucket $B > /dev/null 2>&1 || aws s3 mb s3://$B > /dev/null
  aws s3api put-public-access-block --bucket $B --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-encryption --bucket $B --server-side-encryption-configuration \
    '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  aws s3api put-bucket-versioning --bucket $B --versioning-configuration Status=Enabled
done
aws s3api put-bucket-lifecycle-configuration --bucket $REPORTS_BUCKET --lifecycle-configuration \
  '{"Rules":[{"ID":"expire-reports","Status":"Enabled","Filter":{"Prefix":"reports/"},"Expiration":{"Days":30}}]}' 2>/dev/null \
  || echo "  (lifecycle rule not supported by this Floci version: note it as a limitation)"

echo "5/8 One least-privilege IAM role per Lambda"
for S in $SERVICES; do
  ROLE=pb-$S-role
  aws iam get-role --role-name $ROLE > /dev/null 2>&1 || \
    aws iam create-role --role-name $ROLE --assume-role-policy-document file://infra/iam/trust-policy.json > /dev/null
  sed -e "s/__REGION__/$REGION/g" -e "s/__ACCOUNT__/$ACCOUNT/g" -e "s/__SUFFIX__/$SUFFIX/g" \
    infra/iam/$S-policy.json > "$TMP/$S-policy.json"
  aws iam put-role-policy --role-name $ROLE --policy-name pb-$S-access --policy-document "file://$TMP/$S-policy.json"
  echo "  $ROLE"
done

echo "6/8 Lambda functions (zip without .env)"
COMMON="NODE_ENV=production,JWT_SECRET_ID=$SECRET_ID,CORS_ORIGINS=$ORIGIN,SERVICE_TRANSPORT=lambda,AUTH_FUNCTION=pb-auth-api,BUCKETS_FUNCTION=pb-buckets-api,TRANSACTIONS_FUNCTION=pb-transactions-api,INSIGHTS_FUNCTION=pb-insights-api,S3_FORCE_PATH_STYLE=true,S3_PUBLIC_ENDPOINT=$ORIGIN"
for S in $SERVICES; do
  FN=pb-$S-api
  case $S in
    auth) EXTRA="USERS_TABLE=PBUsers";;
    buckets) EXTRA="BUCKETS_TABLE=PBBuckets,ALERTS_TOPIC_ARN=$TOPIC_ARN";;
    transactions) EXTRA="TRANSACTIONS_TABLE=PBTransactions,RECEIPTS_BUCKET=$RECEIPTS_BUCKET";;
    insights) EXTRA="REPORTS_TABLE=PBReports,REPORTS_BUCKET=$REPORTS_BUCKET";;
  esac
  (cd services/$S-service && npm install --no-audit --no-fund --loglevel=error && npm run zip --silent) || exit 1
  ENV_VARS="Variables={$COMMON,$EXTRA}"
  if aws lambda get-function --function-name $FN > /dev/null 2>&1; then
    aws lambda update-function-code --function-name $FN --zip-file fileb://services/$S-service/lambda.zip > /dev/null
    aws lambda wait function-updated-v2 --function-name $FN
    aws lambda update-function-configuration --function-name $FN --handler lambda.handler \
      --timeout 15 --memory-size 256 --environment "$ENV_VARS" > /dev/null
    aws lambda wait function-updated-v2 --function-name $FN
  else
    aws lambda create-function --function-name $FN --runtime nodejs24.x --handler lambda.handler \
      --role arn:aws:iam::$ACCOUNT:role/pb-$S-role --zip-file fileb://services/$S-service/lambda.zip \
      --timeout 15 --memory-size 256 --environment "$ENV_VARS" > /dev/null
    aws lambda wait function-active-v2 --function-name $FN
  fi
  aws logs create-log-group --log-group-name /aws/lambda/$FN > /dev/null 2>&1
  aws logs put-retention-policy --log-group-name /aws/lambda/$FN --retention-in-days 14 > /dev/null 2>&1
  echo "  $FN"
done

echo "7/8 API Gateway HTTP API: one integration per service, stage throttling"
API_ID=$(aws apigatewayv2 get-apis --query "Items[?Name=='pb-http-api'].ApiId | [0]" --output text)
if [ -z "$API_ID" ] || [ "$API_ID" = "None" ]; then
  API_ID=$(aws apigatewayv2 create-api --name pb-http-api --protocol-type HTTP --query ApiId --output text)
  for S in $SERVICES; do
    INT=$(aws apigatewayv2 create-integration --api-id $API_ID --integration-type AWS_PROXY \
      --payload-format-version 2.0 --integration-uri arn:aws:lambda:$REGION:$ACCOUNT:function:pb-$S-api \
      --query IntegrationId --output text)
    for KEY in "ANY /api/$S" "ANY /api/$S/{proxy+}"; do
      aws apigatewayv2 create-route --api-id $API_ID --route-key "$KEY" --target integrations/$INT > /dev/null
    done
  done
  aws apigatewayv2 create-stage --api-id $API_ID --stage-name '$default' --auto-deploy \
    --default-route-settings ThrottlingBurstLimit=20,ThrottlingRateLimit=10 > /dev/null
fi
for S in $SERVICES; do
  aws lambda add-permission --function-name pb-$S-api --statement-id apigw-invoke \
    --action lambda:InvokeFunction --principal apigateway.amazonaws.com \
    --source-arn "arn:aws:execute-api:$REGION:$ACCOUNT:$API_ID/*" > /dev/null 2>&1
done
API_URL=http://$API_ID.execute-api.localhost.floci.io:4566

echo "Tags: Project / Owner / Environment on every resource (governance and cost tracking, Lecture 8)"
owner_of() { case $1 in auth) echo team-04;; buckets) echo saged-ehab-244694;; transactions) echo salma-amir;; insights) echo omar-mohamed;; esac; }
tag_note() { echo "  (tagging $1 not supported by this Floci version: note it in the report)"; }
for S in $SERVICES; do
  O=$(owner_of $S); T=$(table_for $S)
  aws dynamodb tag-resource --resource-arn arn:aws:dynamodb:$REGION:$ACCOUNT:table/$T \
    --tags Key=Project,Value=personal-budget-buckets Key=Owner,Value=$O Key=Environment,Value=floci-dev > /dev/null 2>&1 || tag_note "table $T"
  aws lambda tag-resource --resource arn:aws:lambda:$REGION:$ACCOUNT:function:pb-$S-api \
    --tags Project=personal-budget-buckets,Owner=$O,Environment=floci-dev > /dev/null 2>&1 || tag_note "function pb-$S-api"
  aws iam tag-role --role-name pb-$S-role \
    --tags Key=Project,Value=personal-budget-buckets Key=Owner,Value=$O > /dev/null 2>&1 || tag_note "role pb-$S-role"
done
for B in $RECEIPTS_BUCKET:salma-amir $REPORTS_BUCKET:omar-mohamed; do
  aws s3api put-bucket-tagging --bucket ${B%%:*} --tagging \
    "TagSet=[{Key=Project,Value=personal-budget-buckets},{Key=Owner,Value=${B##*:}},{Key=Environment,Value=floci-dev}]" > /dev/null 2>&1 || tag_note "bucket ${B%%:*}"
done
aws sns tag-resource --resource-arn "$TOPIC_ARN" \
  --tags Key=Project,Value=personal-budget-buckets Key=Owner,Value=saged-ehab-244694 > /dev/null 2>&1 || tag_note "topic $TOPIC"
echo "  check with: aws resourcegroupstaggingapi get-resources --tag-filters Key=Project,Values=personal-budget-buckets"

echo "8/8 Website on S3 + monitoring"
sed -i "s#^const FLOCI_API = .*#const FLOCI_API = '$API_URL';#" frontend/js/config.js
aws s3 mb s3://$WEB_BUCKET > /dev/null 2>&1
aws s3 sync frontend s3://$WEB_BUCKET > /dev/null
aws s3 cp frontend/css s3://$WEB_BUCKET/css --recursive --content-type text/css > /dev/null
aws s3 cp frontend/js s3://$WEB_BUCKET/js --recursive --content-type text/javascript > /dev/null
bash infra/monitoring/setup-monitoring.sh || echo "  (some monitoring commands not supported: record which)"
rm -rf "$TMP"

echo
echo "API:     $API_URL/api/auth/health"
echo "Website: http://localhost:4566/$WEB_BUCKET/index.html"
echo "Next:    seed the admin (README), then bash infra/check-floci.sh"
