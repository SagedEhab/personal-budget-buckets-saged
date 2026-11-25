// Service-to-service calls (how the three services work together).
// The caller FORWARDS the user's own Authorization header, so the called service applies
// the same authentication, role and ownership checks: no shared "god" credential exists.
//
//   SERVICE_TRANSPORT=lambda  (Floci/AWS): invoke the other service's Lambda function directly
//       with the AWS SDK. The caller's IAM role may only lambda:InvokeFunction on the named
//       functions it needs (least privilege). The payload is an API Gateway v2 event, so the
//       called Express app (serverless-http) handles it exactly like a browser request.
//   otherwise (local): HTTP request to INTERNAL_API_URL (the local gateway, default :3000).
const { errors } = require('./errors');

const FUNCTION_ENV = {
  auth: 'AUTH_FUNCTION',
  buckets: 'BUCKETS_FUNCTION',
  transactions: 'TRANSACTIONS_FUNCTION',
  insights: 'INSIGHTS_FUNCTION'
};

let customInvoker = null; // tests can replace the Lambda invoker
function setInvoker(fn) { customInvoker = fn; }

function buildQuery(query = {}) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== '') params.set(k, String(v));
  }
  return params.toString();
}

function toApiGatewayEvent({ method, path, query, body, headers }) {
  const rawQueryString = buildQuery(query);
  return {
    version: '2.0',
    routeKey: '$default',
    rawPath: path,
    rawQueryString,
    headers: { 'content-type': 'application/json', ...headers },
    requestContext: {
      http: { method, path, protocol: 'HTTP/1.1', sourceIp: '127.0.0.1', userAgent: 'pb-service-client' },
      requestId: headers['x-request-id'] || `internal-${Date.now()}`,
      stage: '$default'
    },
    body: body === undefined ? undefined : JSON.stringify(body),
    isBase64Encoded: false
  };
}

async function invokeLambda(target, event) {
  const functionName = process.env[FUNCTION_ENV[target]];
  if (!functionName) throw new Error(`${FUNCTION_ENV[target]} is not configured.`);
  if (customInvoker) return customInvoker(functionName, event);
  const { LambdaClient, InvokeCommand } = require('@aws-sdk/client-lambda');
  const client = new LambdaClient({});
  const result = await client.send(new InvokeCommand({
    FunctionName: functionName,
    Payload: Buffer.from(JSON.stringify(event))
  }));
  return JSON.parse(Buffer.from(result.Payload).toString('utf8'));
}

async function callService(target, { method = 'GET', path, query, body, authHeader, requestId }) {
  const headers = {};
  if (authHeader) headers.authorization = authHeader;
  if (requestId) headers['x-request-id'] = requestId;

  try {
    if (process.env.SERVICE_TRANSPORT === 'lambda') {
      const response = await invokeLambda(target, toApiGatewayEvent({ method, path, query, body, headers }));
      let parsed = null;
      if (response && response.body) {
        const text = response.isBase64Encoded ? Buffer.from(response.body, 'base64').toString('utf8') : response.body;
        try { parsed = JSON.parse(text); } catch { parsed = text; }
      }
      return { status: response.statusCode, body: parsed };
    }

    const base = (process.env.INTERNAL_API_URL || 'http://localhost:3000').replace(/\/$/, '');
    const qs = buildQuery(query);
    const res = await fetch(`${base}${path}${qs ? `?${qs}` : ''}`, {
      method,
      headers: { 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(Number(process.env.SERVICE_TIMEOUT_MS) || 8000)
    });
    const text = await res.text();
    let parsed = null;
    try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
    return { status: res.status, body: parsed };
  } catch (error) {
    throw errors.unavailable('DEPENDENCY_UNAVAILABLE', `The ${target} service is not reachable right now.`);
  }
}

module.exports = { callService, setInvoker, toApiGatewayEvent };
