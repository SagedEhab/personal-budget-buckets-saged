// Structured JSON logging. Every line is one JSON object, so CloudWatch Logs Insights
// (and the local log-report script) can filter on fields such as event, status or userId.
// Security rule: values whose key looks sensitive are replaced with "[REDACTED]" and
// request bodies are never logged.
const fs = require('fs');

const SENSITIVE = /pass(word)?|token|authorization|secret|cookie|apikey|api_key/i;

function redact(value, depth = 0) {
  if (value === null || typeof value !== 'object' || depth > 4) return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1));
  const out = {};
  for (const [key, val] of Object.entries(value)) {
    out[key] = SENSITIVE.test(key) ? '[REDACTED]' : redact(val, depth + 1);
  }
  return out;
}

function write(level, service, event, fields = {}) {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    service,
    event,
    ...redact(fields)
  });
  // process.stdout.write (not console.log): the Lambda runtime adds a "timestamp requestId INFO"
  // prefix to console.log lines, which would stop CloudWatch JSON metric filters from matching.
  (level === 'error' ? process.stderr : process.stdout).write(`${line}\n`);
  // Local runs only: also append to a file so the monitoring script can analyse it.
  if (process.env.LOG_FILE) {
    try { fs.appendFileSync(process.env.LOG_FILE, `${line}\n`); } catch { /* ignore */ }
  }
}

// CloudWatch Embedded Metric Format: on AWS this log line becomes a custom metric
// automatically (namespace PersonalBudget). On Floci/locally it is just a log line.
function metric(service, name, value = 1, dimensions = {}) {
  const dimKeys = Object.keys({ Service: service, ...dimensions });
  const line = {
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [{
        Namespace: 'PersonalBudget',
        Dimensions: [dimKeys],
        Metrics: [{ Name: name, Unit: 'Count' }]
      }]
    },
    Service: service,
    ...dimensions,
    [name]: value,
    event: 'METRIC'
  };
  process.stdout.write(`${JSON.stringify(line)}\n`);
  if (process.env.LOG_FILE) {
    try { fs.appendFileSync(process.env.LOG_FILE, `${JSON.stringify(line)}\n`); } catch { /* ignore */ }
  }
}

function createLogger(service) {
  return {
    info: (event, fields) => write('info', service, event, fields),
    warn: (event, fields) => write('warn', service, event, fields),
    error: (event, fields) => write('error', service, event, fields),
    metric: (name, value, dimensions) => metric(service, name, value, dimensions)
  };
}

module.exports = { createLogger, redact };
