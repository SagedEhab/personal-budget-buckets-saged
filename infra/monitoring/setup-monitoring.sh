#!/usr/bin/env bash
# CloudWatch metric filters + alarms on the structured JSON logs (AI-assisted draft, not yet run on Floci).
#   FailedLogins   <- event LOGIN_FAILED / ACCOUNT_LOCKED in /aws/lambda/pb-auth-api
#   AccessDenied   <- status 403 in every service log group
#   ServerErrors   <- status >= 500 in every service log group
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
