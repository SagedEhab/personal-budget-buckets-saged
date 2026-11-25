// Buckets & Budgets service Express app (owner: Student 244694).
try { require('dotenv').config({ quiet: true }); } catch { /* dotenv is optional */ }
const { createApp, createLogger } = require('pb-common');
const { createBucketRoutes } = require('./routes/buckets');

const logger = createLogger('buckets');

module.exports = createApp({
  service: 'buckets',
  logger,
  mount: (app) => app.use('/api/buckets', createBucketRoutes(logger))
});
