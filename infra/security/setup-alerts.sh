#!/usr/bin/env bash
# Security alerts by e-mail (report sections 11 and 16).
#   ALERT_EMAIL=you@example.com bash infra/security/setup-alerts.sh   subscribe an e-mail (confirm the link AWS sends)
#   bash infra/security/setup-alerts.sh                               rules only (also run by deploy-floci.sh)
#   bash infra/security/setup-alerts.sh --prove                       check every rule against a sample event and
#                                                                     deliver a test alert to a queue
#
# Amazon EventBridge watches the account's security events and sends the dangerous ones to the SNS topic
# pb-ops-alarms (the same topic as the CloudWatch alarms), so the team hears about them in minutes:
#   pb-guardduty-finding     GuardDuty finding of medium severity or higher (severity >= 4)
#   pb-securityhub-critical  Security Hub finding labelled HIGH or CRITICAL
#   pb-root-login            someone signed in to the console as the root user
#   pb-iam-change            IAM users, roles, policies or access keys created, changed or deleted
#   pb-audit-tamper          someone tries to switch off the evidence: stop or delete the CloudTrail trail,
#                            disable or delete the KMS key, stop AWS Config, disable GuardDuty
# The IAM, root and tamper rules work from CloudTrail events, so they need the trail from setup-audit.sh.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 1
ACCOUNT=000000000000
REGION=us-east-1
TOPIC_ARN=$(aws sns create-topic --name pb-ops-alarms --query TopicArn --output text)

echo "SNS topic pb-ops-alarms: allow CloudWatch alarms and EventBridge (this account only) to publish"
aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy --attribute-value "{\"Version\":\"2012-10-17\",\"Statement\":[
 {\"Sid\":\"Owner\",\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::$ACCOUNT:root\"},\"Action\":[\"sns:Publish\",\"sns:Subscribe\",\"sns:GetTopicAttributes\",\"sns:SetTopicAttributes\",\"sns:ListSubscriptionsByTopic\"],\"Resource\":\"$TOPIC_ARN\"},
 {\"Sid\":\"AlarmsAndEvents\",\"Effect\":\"Allow\",\"Principal\":{\"Service\":[\"cloudwatch.amazonaws.com\",\"events.amazonaws.com\"]},\"Action\":\"sns:Publish\",\"Resource\":\"$TOPIC_ARN\",
  \"Condition\":{\"StringEquals\":{\"aws:SourceAccount\":\"$ACCOUNT\"}}},
 {\"Sid\":\"HttpsOnly\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"sns:Publish\",\"Resource\":\"$TOPIC_ARN\",\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}" \
  || echo "  (topic policy not accepted by this Floci version)"
if [ -n "$ALERT_EMAIL" ]; then
  aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol email --notification-endpoint "$ALERT_EMAIL" > /dev/null
  echo "  e-mail subscription requested: confirm the link AWS sends to that address"
fi

# name | description | event pattern
RULES=(
"pb-guardduty-finding|GuardDuty finding, severity medium or higher|{\"source\":[\"aws.guardduty\"],\"detail-type\":[\"GuardDuty Finding\"],\"detail\":{\"severity\":[{\"numeric\":[\">=\",4]}]}}"
"pb-securityhub-critical|Security Hub finding HIGH or CRITICAL|{\"source\":[\"aws.securityhub\"],\"detail-type\":[\"Security Hub Findings - Imported\"],\"detail\":{\"findings\":{\"Severity\":{\"Label\":[\"HIGH\",\"CRITICAL\"]}}}}"
"pb-root-login|Console sign-in as the root user|{\"detail-type\":[\"AWS Console Sign In via CloudTrail\"],\"detail\":{\"userIdentity\":{\"type\":[\"Root\"]}}}"
"pb-iam-change|IAM users, roles, policies or keys changed|{\"source\":[\"aws.iam\"],\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventName\":[\"CreateUser\",\"DeleteUser\",\"CreateAccessKey\",\"CreateRole\",\"DeleteRole\",\"UpdateAssumeRolePolicy\",\"PutRolePolicy\",\"PutUserPolicy\",\"DeleteRolePolicy\",\"DeleteUserPolicy\",\"AttachRolePolicy\",\"AttachUserPolicy\",\"DetachRolePolicy\",\"DetachUserPolicy\",\"CreatePolicyVersion\",\"AddUserToGroup\",\"CreateLoginProfile\",\"UpdateLoginProfile\",\"DeactivateMFADevice\"]}}"
"pb-audit-tamper|Attempt to switch off logging, the key, Config or GuardDuty|{\"detail-type\":[\"AWS API Call via CloudTrail\"],\"detail\":{\"eventName\":[\"StopLogging\",\"DeleteTrail\",\"UpdateTrail\",\"PutEventSelectors\",\"DisableKey\",\"ScheduleKeyDeletion\",\"StopConfigurationRecorder\",\"DeleteConfigurationRecorder\",\"DeleteDeliveryChannel\",\"DeleteDetector\",\"UpdateDetector\",\"DisableSecurityHub\",\"PutBucketObjectLockConfiguration\",\"DeleteBucketPolicy\"]}}"
)

echo "EventBridge rules -> SNS pb-ops-alarms"
for R in "${RULES[@]}"; do
  IFS='|' read -r NAME DESC PATTERN <<< "$R"
  aws events put-rule --name "$NAME" --description "$DESC" --event-pattern "$PATTERN" --state ENABLED \
    --tags Key=Project,Value=personal-budget-buckets Key=Owner,Value=saged-ehab-244694 > /dev/null || exit 1
  aws events put-targets --rule "$NAME" --targets "Id=ops-alarms,Arn=$TOPIC_ARN" > /dev/null || exit 1
  echo "  $NAME: $DESC"
done

[ "$1" = --prove ] || exit 0

echo "Proof 1: each rule matches a realistic sample event (EventBridge test-event-pattern)"
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
event() {  # source detail-type detail-json
  echo "{\"id\":\"$(node -e 'console.log(require("crypto").randomUUID())')\",\"version\":\"0\",\"account\":\"$ACCOUNT\",\"region\":\"$REGION\",\"time\":\"$NOW\",\"resources\":[],\"source\":\"$1\",\"detail-type\":\"$2\",\"detail\":$3}"
}
SAMPLES=(
"pb-guardduty-finding|$(event aws.guardduty 'GuardDuty Finding' '{"severity":8,"type":"UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"}')|$(event aws.guardduty 'GuardDuty Finding' '{"severity":2,"type":"Recon:EC2/Portscan"}')"
"pb-securityhub-critical|$(event aws.securityhub 'Security Hub Findings - Imported' '{"findings":[{"Severity":{"Label":"CRITICAL"},"Title":"S3 bucket allows public read"}]}')|$(event aws.securityhub 'Security Hub Findings - Imported' '{"findings":[{"Severity":{"Label":"LOW"}}]}')"
"pb-root-login|$(event aws.signin 'AWS Console Sign In via CloudTrail' '{"userIdentity":{"type":"Root"},"eventName":"ConsoleLogin"}')|$(event aws.signin 'AWS Console Sign In via CloudTrail' '{"userIdentity":{"type":"IAMUser"},"eventName":"ConsoleLogin"}')"
"pb-iam-change|$(event aws.iam 'AWS API Call via CloudTrail' '{"eventName":"CreateAccessKey","userIdentity":{"type":"IAMUser"}}')|$(event aws.iam 'AWS API Call via CloudTrail' '{"eventName":"ListUsers"}')"
"pb-audit-tamper|$(event aws.cloudtrail 'AWS API Call via CloudTrail' '{"eventName":"StopLogging","eventSource":"cloudtrail.amazonaws.com"}')|$(event aws.cloudtrail 'AWS API Call via CloudTrail' '{"eventName":"LookupEvents"}')"
)
for S in "${SAMPLES[@]}"; do
  IFS='|' read -r NAME BAD HARMLESS <<< "$S"
  PATTERN=$(aws events describe-rule --name "$NAME" --query EventPattern --output text)
  M1=$(aws events test-event-pattern --event-pattern "$PATTERN" --event "$BAD" --query Result --output text)
  M2=$(aws events test-event-pattern --event-pattern "$PATTERN" --event "$HARMLESS" --query Result --output text)
  [ "$M1" = True ] && [ "$M2" = False ] && R=PASS || R=FAIL
  echo "  $NAME: dangerous event matched=$M1, harmless event matched=$M2 -> $R"
done

echo "Proof 2: an alert published to the topic is delivered (test queue subscribed in place of e-mail)"
Q_URL=$(aws sqs create-queue --queue-name pb-alerts-proof --query QueueUrl --output text)
Q_ARN=$(aws sqs get-queue-attributes --queue-url "$Q_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)
SUB=$(aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol sqs --notification-endpoint "$Q_ARN" --query SubscriptionArn --output text)
aws sns publish --topic-arn "$TOPIC_ARN" --subject "TEST security alert" \
  --message "$(event aws.guardduty 'GuardDuty Finding' '{"severity":8,"type":"TEST finding from setup-alerts.sh --prove"}')" > /dev/null
GOT=$(aws sqs receive-message --queue-url "$Q_URL" --wait-time-seconds 5 --query 'Messages[0].Body' --output text)
case "$GOT" in *"TEST finding"*) echo "  alert delivered through pb-ops-alarms (PASS)";; *) echo "  alert NOT delivered (FAIL)";; esac
aws sns unsubscribe --subscription-arn "$SUB"; aws sqs delete-queue --queue-url "$Q_URL"
