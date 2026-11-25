// LOCAL ONLY: serves the frontend folder on http://localhost:8080 (plays the S3 website).
// Usage (from the project folder):  node infra/local-frontend.js
const http = require('http');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..', 'frontend');
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.png': 'image/png', '.svg': 'image/svg+xml' };
const port = Number(process.env.FRONTEND_PORT) || 8080;

http.createServer((req, res) => {
  const urlPath = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  const file = path.normalize(path.join(root, urlPath === '/' ? 'index.html' : urlPath));
  if (!file.startsWith(root)) { res.writeHead(403); res.end(); return; } // no path traversal
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); res.end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff' });
    res.end(data);
  });
}).listen(port, () => console.log(`Frontend on http://localhost:${port}`));
