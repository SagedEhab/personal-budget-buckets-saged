// Dependency vulnerability scan (DevSecOps, Lecture 9): runs `npm audit` in every service and
// writes evidence/npm-audit.md. Exit code 1 if any HIGH or CRITICAL issue is found in production packages.
//   npm run audit
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const rows = [];
let blocking = 0;
for (const svc of fs.readdirSync(path.join(root, 'services'))) {
  const dir = path.join(root, 'services', svc);
  if (!fs.existsSync(path.join(dir, 'package-lock.json'))) continue;
  let out;
  try {
    out = execSync('npm audit --omit=dev --json', { cwd: dir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    out = e.stdout; // npm audit exits 1 when it finds anything; the JSON is still on stdout
  }
  let v;
  try { v = JSON.parse(out).metadata.vulnerabilities; } catch {
    rows.push(`| ${svc} | audit could not run (no network?) | | | | |`);
    continue;
  }
  blocking += (v.high || 0) + (v.critical || 0);
  rows.push(`| ${svc} | ${v.critical || 0} | ${v.high || 0} | ${v.moderate || 0} | ${v.low || 0} | ${v.total || 0} |`);
}
const md = `# npm audit (production dependencies)\n\nRun ${new Date().toISOString()} with Node ${process.version}.\n\n`
  + '| Service | Critical | High | Moderate | Low | Total |\n|---|---|---|---|---|---|\n' + rows.join('\n') + '\n';
fs.mkdirSync(path.join(root, 'evidence'), { recursive: true });
fs.writeFileSync(path.join(root, 'evidence', 'npm-audit.md'), md);
console.log(md);
process.exit(blocking > 0 ? 1 : 0);
