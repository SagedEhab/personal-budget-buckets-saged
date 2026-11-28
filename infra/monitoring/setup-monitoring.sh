#!/usr/bin/env bash
# CloudWatch metric filters + alarms on the structured JSON logs (AI-assisted draft, not yet run on Floci).
#   FailedLogins   <- event LOGIN_FAILED / ACCOUNT_LOCKED in /aws/lambda/pb-auth-api
#   AccessDenied   <- status 403 in every service log group
#   ServerErrors   <- status >= 500 in every service log group
#   OwnershipProbes <- *_NOT_FOUND_OR_NOT_OWNED in buckets, transactions, insights (IDOR probing)
# bash infra/monitoring/setup-monitoring.sh --prove   a test user probes another user's ids; checks the
#   pb-ownership-probe alarm fires and reaches pb-ops-alarms (evidence/ownership-probe-alarm-proof.txt)
# Alarms fire when the sum over 5 minutes passes the threshold; they publish to the SNS topic.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
TOPIC_ARN=$(aws sns create-topic --name pb-ops-alarms --query TopicArn --output text)

aws logs put-metric-filter --log-group-name /aws/lambda/pb-auth-api --filter-name pb-failed-logins \
  --filter-pattern '{ ($.event = "LOGIN_FAILED") || ($.event = "ACCOUNT_LOCKED") }' \
  --metric-transformations metricName=FailedLogins,metricNamespace=PersonalBudget,metricValue=1,defaultValue=0

for S in auth buckets transactions insights; do
  aws logs put-metric-filter --log-group-name /aws/lambda/pb-$S-api --filter-name pb-$S-403 \
    --filter-pattern '{ $.status = 403 }' \
    --metric-transformations metricName=AccessDenied,metricNamespace=PersonalBudget,metricValue=1,defaultValue=0
  aws logs put-metric-filter --log-group-name /aws/lambda/pb-$S-api --filter-name pb-$S-5xx \
    --filter-pattern '{ $.status >= 500 }' \
    --metric-transformations metricName=ServerErrors,metricNamespace=PersonalBudget,metricValue=1,defaultValue=0
done

# OwnershipProbes (ENHANCEMENTS 5p, Saged): someone asking for buckets, transactions or reports that are not
# theirs. One wrong id is normal (an old link); many in a few minutes means someone is guessing other
# users' ids (IDOR probing), even though every one of those requests is refused with 404.
probe_filter() {
  aws logs put-metric-filter --log-group-name /aws/lambda/pb-$1-api --filter-name pb-$1-ownership-probe \
    --filter-pattern "{ \$.event = \"$2\" }" \
    --metric-transformations metricName=OwnershipProbes,metricNamespace=PersonalBudget,metricValue=1,defaultValue=0
}
probe_filter buckets BUCKET_NOT_FOUND_OR_NOT_OWNED
probe_filter transactions TXN_NOT_FOUND_OR_NOT_OWNED
probe_filter insights REPORT_NOT_FOUND_OR_NOT_OWNED
aws cloudwatch put-metric-alarm --alarm-name pb-ownership-probe --namespace PersonalBudget \
  --alarm-description "5+ requests for other users' (or missing) records in 5 minutes: possible IDOR probing. Check the userId in the *_NOT_FOUND_OR_NOT_OWNED log lines; disable the account if it is deliberate." \
  --metric-name OwnershipProbes --statistic Sum --period 300 --threshold 5 --treat-missing-data notBreaching \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions "$TOPIC_ARN" --ok-actions "$TOPIC_ARN"

aws cloudwatch put-metric-alarm --alarm-name pb-failed-logins-spike --namespace PersonalBudget \
  --metric-name FailedLogins --statistic Sum --period 300 --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions "$TOPIC_ARN"
aws cloudwatch put-metric-alarm --alarm-name pb-access-denied-spike --namespace PersonalBudget \
  --metric-name AccessDenied --statistic Sum --period 300 --threshold 10 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions "$TOPIC_ARN"
aws cloudwatch put-metric-alarm --alarm-name pb-server-errors-spike --namespace PersonalBudget \
  --metric-name ServerErrors --statistic Sum --period 300 --threshold 5 \
  --comparison-operator GreaterThanOrEqualToThreshold --evaluation-periods 1 --alarm-actions "$TOPIC_ARN"
echo "Monitoring configured."

[ "$1" = --prove ] || exit 0

# ---------------------------------------------------------------- proof: IDOR probing raises an alarm
cd "$(dirname "$0")/../.." || exit 1
OUT=evidence/ownership-probe-alarm-proof.txt
run() { echo "$@" | tee -a $OUT; }
: > $OUT
API_ID=$(aws apigatewayv2 get-apis --query "Items[?Name=='pb-http-api'].ApiId | [0]" --output text)
API=http://$API_ID.execute-api.localhost.floci.io:4566
run "Ownership-probe alarm proof ($(date -u +%Y-%m-%dT%H:%M:%SZ)) on Floci, API $API"
Q_URL=$(aws sqs create-queue --queue-name pb-probe-proof --query QueueUrl --output text)
Q_ARN=$(aws sqs get-queue-attributes --queue-url "$Q_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)
SUB=$(aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol sqs --notification-endpoint "$Q_ARN" --query SubscriptionArn --output text)
run "1. Alarm before: $(aws cloudwatch describe-alarms --alarm-names pb-ownership-probe --query 'MetricAlarms[0].StateValue' --output text)"
# Two throw-away users; B tries A's bucket id and made-up transaction/report ids. Passwords are random and
# stay in memory; both users are deleted at the end.
API="$API" node -e '
const api = process.env.API, crypto = require("crypto");
const call = async (m, p, t, b) => { const r = await fetch(api + p, { method: m, headers: { "content-type": "application/json", ...(t ? { authorization: "Bearer " + t } : {}) }, body: b ? JSON.stringify(b) : undefined }); return { status: r.status, data: await r.json().catch(() => null) }; };
(async () => {
  const users = [];
  for (const n of ["Probe Victim", "Probe Attacker"]) {
    const u = { email: `probe.${crypto.randomBytes(4).toString("hex")}@example.com`, password: `Prb-${crypto.randomBytes(6).toString("hex")}-9` };
    u.token = (await call("POST", "/api/auth/register", null, { name: n, ...u })).data.token; users.push(u);
  }
  const [A, B] = users;
  const bucket = (await call("POST", "/api/buckets", A.token, { name: "Rent", monthlyLimit: 900 })).data;
  const tries = [];
  for (let i = 0; i < 4; i++) tries.push(["GET", `/api/buckets/${bucket.id}`]);
  tries.push(["PATCH", `/api/buckets/${bucket.id}`, { monthlyLimit: 1 }], ["DELETE", `/api/buckets/${bucket.id}`]);
  for (let i = 0; i < 2; i++) tries.push(["GET", `/api/transactions/${crypto.randomBytes(10).toString("hex")}`]);
  const codes = [];
  for (const [m, p, b] of tries) codes.push((await call(m, p, B.token, b)).status);
  console.log(`2. Attacker B sent ${tries.length} requests for the victim bucket and guessed transaction ids: ${codes.join(", ")}`);
  const still = (await call("GET", `/api/buckets/${bucket.id}`, A.token)).data;
  console.log(`   the victim bucket unchanged: monthlyLimit ${still.monthlyLimit}`);
  require("fs").writeFileSync("evidence/.probe-users.json", JSON.stringify(users.map(({ token, password }) => ({ token, password }))));
})();' | tee -a $OUT

STATE=; for i in $(seq 1 24); do
  STATE=$(aws cloudwatch describe-alarms --alarm-names pb-ownership-probe --query 'MetricAlarms[0].StateValue' --output text)
  [ "$STATE" = ALARM ] && break; sleep 10
done
run "3. Alarm after $((i * 10)) s: $STATE ($(aws cloudwatch describe-alarms --alarm-names pb-ownership-probe --query 'MetricAlarms[0].StateReason' --output text))"
MSG=$(aws sqs receive-message --queue-url "$Q_URL" --wait-time-seconds 10 --max-number-of-messages 5 --query 'Messages[].Body' --output text)
case "$MSG" in *pb-ownership-probe*) GOT=yes;; *) GOT=no;; esac
run "4. Alarm notification delivered on pb-ops-alarms: $GOT"
run "5. Who did it (the log line an on-call person reads; user id only, no e-mail):"
START=$(( ($(date +%s) - 600) * 1000 ))
aws logs filter-log-events --log-group-name /aws/lambda/pb-buckets-api --start-time $START \
  --filter-pattern '{ $.event = "BUCKET_NOT_FOUND_OR_NOT_OWNED" }' --query 'events[-1].message' --output text | tee -a $OUT

# Clean up: delete both users through "delete my account", remove the test queue
API="$API" node -e '
const api = process.env.API; const users = JSON.parse(require("fs").readFileSync("evidence/.probe-users.json"));
(async () => { const out = []; for (const u of users) { const r = await fetch(api + "/api/auth/me", { method: "DELETE", headers: { "content-type": "application/json", authorization: "Bearer " + u.token }, body: JSON.stringify({ confirm: true, password: u.password }) }); out.push(r.status); } console.log("6. Test users deleted: " + out.join(", ")); })();' | tee -a $OUT
rm -f evidence/.probe-users.json
aws sns unsubscribe --subscription-arn "$SUB"; aws sqs delete-queue --queue-url "$Q_URL"
[ "$STATE" = ALARM ] && [ "$GOT" = yes ] && run "RESULT: PASS" || { run "RESULT: FAIL"; exit 1; }
