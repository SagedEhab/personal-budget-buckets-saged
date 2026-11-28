#!/usr/bin/env bash
# Restore drill (ENHANCEMENTS 5j, report section 15): proves that deleted data can be recovered.
#   bash infra/restore-drill.sh                         drill with a test record in PBBuckets
#   bash infra/restore-drill.sh recover <TABLE> <TIME>  real recovery: rewind TABLE to TIME
#                                                       (e.g. 2026-11-26T18:30:00Z) into <TABLE>-restored
# The drill never touches real user records: it writes its own marker, deletes it, rewinds the table
# to a copy, checks the marker is back, copies it into the live table and removes the copy.
export AWS_PROFILE="${AWS_PROFILE:-floci}" AWS_PAGER="" MSYS_NO_PATHCONV=1
cd "$(dirname "$0")/.." || exit 1

if [ "$1" = recover ]; then
  TABLE=$2; TIME=$3
  [ -z "$TABLE" ] || [ -z "$TIME" ] && { echo "usage: bash infra/restore-drill.sh recover <TABLE> <ISO time>"; exit 1; }
  aws dynamodb restore-table-to-point-in-time --source-table-name "$TABLE" --target-table-name "$TABLE-restored" \
    --restore-date-time "$TIME" > /dev/null || exit 1
  aws dynamodb wait table-exists --table-name "$TABLE-restored"
  echo "Restored $TABLE as it was at $TIME into $TABLE-restored ($(aws dynamodb scan --table-name "$TABLE-restored" --select COUNT --query Count) items)."
  echo "Check it, then copy the needed items back with aws dynamodb put-item, and delete $TABLE-restored."
  exit 0
fi

TABLE=PBBuckets
KEY='{"pk":{"S":"DRILL#restore"},"sk":{"S":"MARKER"}}'
COPY="$TABLE-drill-$(date +%s)"
step() { echo "[$(date -u +%H:%M:%S)] $*"; }
get_note() { aws dynamodb get-item --table-name "$1" --key "$KEY" --query Item.note.S --output text 2>/dev/null; }

step "Restore drill on $TABLE (point-in-time recovery: $(aws dynamodb describe-continuous-backups --table-name $TABLE \
  --query ContinuousBackupsDescription.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus --output text))"
aws dynamodb put-item --table-name $TABLE --item \
  '{"pk":{"S":"DRILL#restore"},"sk":{"S":"MARKER"},"note":{"S":"restore drill record"}}'
step "1. Wrote a test record: \"$(get_note $TABLE)\""
sleep 2; BEFORE=$(date -u +%Y-%m-%dT%H:%M:%SZ); sleep 2
aws dynamodb delete-item --table-name $TABLE --key "$KEY"
step "2. Deleted it by 'accident'. Live table now returns: $(get_note $TABLE)"
aws dynamodb restore-table-to-point-in-time --source-table-name $TABLE --target-table-name "$COPY" \
  --restore-date-time "$BEFORE" > /dev/null
aws dynamodb wait table-exists --table-name "$COPY"
FOUND=$(get_note "$COPY")
step "3. Rewound $TABLE to $BEFORE into $COPY: record is $([ "$FOUND" = None ] && echo MISSING || echo "back: \"$FOUND\"")"
aws dynamodb put-item --table-name $TABLE --item \
  "$(aws dynamodb get-item --table-name "$COPY" --key "$KEY" --query Item --output json)"
step "4. Copied it back into the live table: \"$(get_note $TABLE)\""
aws dynamodb delete-item --table-name $TABLE --key "$KEY"
aws dynamodb delete-table --table-name "$COPY" > /dev/null
step "5. Cleaned up (test record and the restored copy removed)."
[ "$FOUND" != None ] && echo "RESULT: PASS, deleted data recovered with point-in-time recovery." \
                     || { echo "RESULT: FAIL"; exit 1; }
