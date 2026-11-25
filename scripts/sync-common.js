// Copies packages/pb-common into each service's node_modules after the shared module changes
// (npm installs it as a copy because of install-links=true, so Lambda zips are self-contained).
//   node scripts/sync-common.js
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const source = path.join(root, 'packages', 'pb-common');
for (const service of fs.readdirSync(path.join(root, 'services'))) {
  const target = path.join(root, 'services', service, 'node_modules', 'pb-common');
  if (!fs.existsSync(path.dirname(target))) continue;
  for (const item of ['index.js', 'package.json', 'lib']) {
    fs.cpSync(path.join(source, item), path.join(target, item), { recursive: true });
  }
  console.log(`synced pb-common -> services/${service}`);
}
