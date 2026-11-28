#!/usr/bin/env bash
# Backups and recovery (ENHANCEMENTS 5j, report section 15).
#   bash infra/security/setup-backups.sh        (also run by infra/deploy-floci.sh)
#
# 1. Point-in-time recovery (PITR) on every table: any table can be rewound to any second of the
#    last 35 days (tested on Floci 2.5.0: a deleted record came back, see infra/restore-drill.sh).
# 2. AWS Backup: a vault and a daily plan that keeps copies for 35 days. The plan selects resources by
#    the Project tag, so new tables are included automatically. The backup role is separate from the
#    Lambda roles, so an attacker who takes over the app cannot delete the backups.
# Safe to run again.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/../.." || exit 1
ACCOUNT=000000000000
TABLES="PBUsers PBBuckets PBTransactions PBReports"
VAULT=pb-backup-vault
PLAN=pb-daily-backups
ROLE=pb-backup-role

echo "Point-in-time recovery on every table"
for T in $TABLES; do
  S=$(aws dynamodb update-continuous-backups --table-name $T \
        --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true \
        --query "ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus" --output text)
  echo "  $T: PITR $S"
done

echo "AWS Backup: vault, role and daily plan (35-day retention)"
aws backup describe-backup-vault --backup-vault-name $VAULT > /dev/null 2>&1 || \
  aws backup create-backup-vault --backup-vault-name $VAULT \
    --backup-vault-tags Project=personal-budget-buckets,Owner=saged-ehab-244694 > /dev/null
echo "  vault $VAULT"

aws iam get-role --role-name $ROLE > /dev/null 2>&1 || \
  aws iam create-role --role-name $ROLE --assume-role-policy-document \
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"backup.amazonaws.com"},"Action":"sts:AssumeRole"}]}' > /dev/null
aws iam attach-role-policy --role-name $ROLE \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup 2>/dev/null \
  || echo "  (managed backup policy not available on this Floci version: note it in the report)"
echo "  role $ROLE"

PLAN_ID=$(aws backup list-backup-plans --query "BackupPlansList[?BackupPlanName=='$PLAN'].BackupPlanId | [0]" --output text)
if [ -z "$PLAN_ID" ] || [ "$PLAN_ID" = "None" ]; then
  PLAN_ID=$(aws backup create-backup-plan --backup-plan \
    "{\"BackupPlanName\":\"$PLAN\",\"Rules\":[{\"RuleName\":\"daily-0300-utc\",\"TargetBackupVaultName\":\"$VAULT\",\"ScheduleExpression\":\"cron(0 3 * * ? *)\",\"Lifecycle\":{\"DeleteAfterDays\":35}}]}" \
    --query BackupPlanId --output text)
  aws backup create-backup-selection --backup-plan-id "$PLAN_ID" --backup-selection \
    "{\"SelectionName\":\"project-tag\",\"IamRoleArn\":\"arn:aws:iam::$ACCOUNT:role/$ROLE\",\"ListOfTags\":[{\"ConditionType\":\"STRINGEQUALS\",\"ConditionKey\":\"Project\",\"ConditionValue\":\"personal-budget-buckets\"}]}" > /dev/null
fi
echo "  plan $PLAN ($PLAN_ID): every day 03:00 UTC, kept 35 days, all resources tagged Project=personal-budget-buckets"
echo "Backups configured. Run bash infra/restore-drill.sh to prove a restore works."
