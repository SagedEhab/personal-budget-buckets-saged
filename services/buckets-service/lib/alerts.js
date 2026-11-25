// Near-limit / over-limit alerts.
//   - stored in the PBBuckets table (pk USER#<id>, sk ALERT#<id>) so the user sees them in the app
//   - de-duplicated: at most one alert per bucket, month and level (marker item ALERTKEY#...)
//   - published to an Amazon SNS topic (ALERTS_TOPIC_ARN) so e-mail/SMS/queue subscribers
//     can be notified without this service knowing about them (loose coupling)
//   - counted as the CloudWatch custom metric PersonalBudget/BudgetAlertsRaised
const crypto = require('crypto');

function newAlertId() {
  return `${Date.now().toString(36).padStart(9, '0')}${crypto.randomBytes(4).toString('hex')}`;
}

let snsClient = null;
async function publish(topicArn, message) {
  const { SNSClient, PublishCommand } = require('@aws-sdk/client-sns');
  if (!snsClient) snsClient = new SNSClient({});
  await snsClient.send(new PublishCommand({
    TopicArn: topicArn,
    Subject: `Budget alert: ${message.level}`,
    Message: JSON.stringify(message),
    MessageAttributes: { level: { DataType: 'String', StringValue: message.level } }
  }));
}

function createAlerts(store, logger) {
  async function raiseIfNeeded(userId, bucket, status, requestId) {
    if (status.state === 'OK') return null;
    const level = status.state; // NEAR_LIMIT or OVER_LIMIT
    const marker = { pk: `USER#${userId}`, sk: `ALERTKEY#${status.month}#${bucket.id}#${level}` };
    const isNew = await store.put(marker, { ifNotExists: true });
    if (!isNew) return null;

    const id = newAlertId();
    const alert = {
      pk: `USER#${userId}`, sk: `ALERT#${id}`, id, bucketId: bucket.id, bucketName: bucket.name,
      month: status.month, level, percentUsed: status.percentUsed, effectiveLimit: status.effectiveLimit,
      spent: status.spent, acknowledged: false, createdAt: new Date().toISOString()
    };
    await store.put(alert);
    logger.info('BUDGET_ALERT_RAISED', { requestId, userId, bucketId: bucket.id, level, month: status.month, percentUsed: status.percentUsed });
    logger.metric('BudgetAlertsRaised', 1, { Level: level });

    if (process.env.ALERTS_TOPIC_ARN) {
      try {
        // No e-mail addresses or names in the message: only ids and the budget numbers.
        await publish(process.env.ALERTS_TOPIC_ARN, {
          userId, bucketId: bucket.id, level, month: status.month, percentUsed: status.percentUsed
        });
        logger.info('BUDGET_ALERT_PUBLISHED', { requestId, alertId: id });
      } catch (error) {
        logger.error('BUDGET_ALERT_PUBLISH_FAILED', { requestId, alertId: id, message: error.message });
      }
    }
    return alert;
  }

  return { raiseIfNeeded };
}

module.exports = { createAlerts };
