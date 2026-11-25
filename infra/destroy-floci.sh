#!/usr/bin/env bash
# Removes everything deploy-floci.sh created (Floci only). Data in the tables is LOST:
# export it first:  aws dynamodb scan --table-name PBBuckets > backup/PBBuckets.json
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
read -r -p "Delete the Personal Budget Buckets deployment on Floci? (yes/no) " OK
[ "$OK" = "yes" ] || exit 0
API_ID=$(aws apigatewayv2 get-apis --query "Items[?Name=='pb-http-api'].ApiId | [0]" --output text)
[ -n "$API_ID" ] && [ "$API_ID" != "None" ] && aws apigatewayv2 delete-api --api-id "$API_ID"
for S in auth buckets transactions insights; do
  aws lambda delete-function --function-name pb-$S-api 2>/dev/null
  aws iam delete-role-policy --role-name pb-$S-role --policy-name pb-$S-access 2>/dev/null
  aws iam delete-role --role-name pb-$S-role 2>/dev/null
done
for T in PBUsers PBBuckets PBTransactions PBReports; do aws dynamodb delete-table --table-name $T > /dev/null 2>&1; done
for B in pb-web pb-receipts-244694 pb-reports-244694; do aws s3 rb s3://$B --force 2>/dev/null; done
echo "Deleted. The JWT secret and SNS topics are kept; delete them in Floci Dash if needed."
