#!/usr/bin/env bash
# Smoke test of the Floci deployment (like Lab 7 check-lab7.sh). AI-assisted draft, not yet run on Floci.
#   bash infra/check-floci.sh
# Prints PASS/FAIL lines: copy the output into the report as deployment evidence.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.." || exit 1
API_ID=$(aws apigatewayv2 get-apis --query "Items[?Name=='pb-http-api'].ApiId | [0]" --output text)
[ -z "$API_ID" ] || [ "$API_ID" = "None" ] && { echo "FAIL no API pb-http-api (run infra/deploy-floci.sh)"; exit 1; }
API=http://$API_ID.execute-api.localhost.floci.io:4566
PASS=0; FAIL=0
check() { if [ "$2" = "$3" ]; then echo "PASS $1 ($2)"; PASS=$((PASS+1)); else echo "FAIL $1: got $2, expected $3"; FAIL=$((FAIL+1)); fi; }
code() { curl -s -o out.check.body -w '%{http_code}' --max-time 30 "$@"; }

for S in auth buckets transactions insights; do
  # The first call starts a Lambda container on Floci (cold start, can exceed 30 s): retry up to 3 times.
  for TRY in 1 2 3; do R=$(code "$API/api/$S/health"); [ "$R" = 200 ] && break; echo "     $S: cold start (got $R), retrying"; done
  check "GET /api/$S/health on Lambda" "$R" 200
  grep -q '"runtime":"lambda"' out.check.body || echo "     note: $S did not report runtime lambda"
done
EMAIL="check$(date +%s)@example.com"
check "POST register" "$(code -X POST "$API/api/auth/register" -H 'Content-Type: application/json' \
  -d "{\"name\":\"Checker\",\"email\":\"$EMAIL\",\"password\":\"CheckPass123\"}")" 201
TOKEN=$(sed -n 's/.*"token":"\([^"]*\)".*/\1/p' out.check.body)
check "GET buckets without token -> 401" "$(code "$API/api/buckets")" 401
check "POST bucket" "$(code -X POST "$API/api/buckets" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"Check bucket","monthlyLimit":100}')" 201
BID=$(sed -n 's/.*"id":"\([^"]*\)".*/\1/p' out.check.body | head -1)
check "POST expense (Transactions -> Buckets via Lambda Invoke)" "$(code -X POST "$API/api/transactions" -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -d "{\"type\":\"expense\",\"amount\":90,\"date\":\"$(date +%F)\",\"bucketId\":\"$BID\",\"paymentMethod\":\"cash\"}")" 201
check "GET dashboard (Insights -> Transactions + Buckets)" "$(code "$API/api/insights/dashboard" -H "Authorization: Bearer $TOKEN")" 200
check "GET admin users as normal user -> 403" "$(code "$API/api/auth/users" -H "Authorization: Bearer $TOKEN")" 403
check "Website index.html" "$(code http://localhost:4566/pb-web/index.html)" 200
rm -f out.check.body
echo; echo "Result: $PASS passed, $FAIL failed"
