// Frontend configuration (Lab 7 pattern). Nothing here is secret: every visitor can read it.
// infra/deploy-floci.sh writes the real API Gateway URL into FLOCI_API automatically.
const FLOCI_API = 'http://YOUR-API-ID.execute-api.localhost.floci.io:4566';
const AWS_API = 'https://YOUR-AWS-API-ID.execute-api.us-east-1.amazonaws.com';

// Picks the API from the address the page was loaded from:
//   port 4566 -> Floci (website in the Floci S3 bucket)   amazonaws.com -> real AWS
//   anything else -> the local gateway on your PC (node infra/local-gateway.js)
const { hostname, port } = window.location;
let API_ROOT;
if (port === '4566') API_ROOT = FLOCI_API;
else if (hostname.endsWith('amazonaws.com')) API_ROOT = AWS_API;
else API_ROOT = 'http://localhost:3000';
