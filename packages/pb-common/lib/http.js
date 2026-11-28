// Builds the Express app shared structure for every service (same pattern as Lab 7 app.js):
// request id + access log, CORS allow-list, security headers, JSON body limit, Lab 7 body fix,
// health check, the service's routes, 404 and the central error handler.
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const { ApiError } = require('./errors');

function createApp({ service, logger, mount }) {
  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', true);

  // Request id + one structured access-log line per request (no bodies, no tokens)
  app.use((req, res, next) => {
    const incoming = req.get('x-request-id');
    req.requestId = incoming && /^[A-Za-z0-9-]{6,64}$/.test(incoming) ? incoming : crypto.randomUUID();
    res.set('x-request-id', req.requestId);
    const started = Date.now();
    res.on('finish', () => {
      const fields = {
        requestId: req.requestId, method: req.method, path: req.path, status: res.statusCode,
        ms: Date.now() - started, userId: req.user ? req.user.id : undefined, ip: req.ip
      };
      if (res.statusCode >= 500) logger.error('REQUEST', fields);
      else if (res.statusCode >= 400) logger.warn('REQUEST', fields);
      else logger.info('REQUEST', fields);
    });
    next();
  });

  // Security headers for an API that only returns JSON
  app.use((req, res, next) => {
    res.set({
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
      'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
    });
    next();
  });

  // CORS: only the frontend origins listed in CORS_ORIGINS may call the API from a browser
  const allowedOrigins = (process.env.CORS_ORIGINS || 'http://localhost:8080')
    .split(',').map((o) => o.trim()).filter(Boolean);
  app.use(cors({
    origin: allowedOrigins,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-Id'],
    maxAge: 600
  }));

  // JSON bodies only, max 20 KB (protects the Lambda from oversized payloads)
  app.use(express.json({ limit: '20kb' }));

  // Lab 7 fix: some API Gateway emulators give Lambda the body as a Buffer or base64 text.
  // On Lambda, serverless-http has already read the body, so express.json above skips it: the 20 KB
  // limit and the JSON-only rule must be applied here too (found by Salma's test ST-11 on Floci:
  // a 30 KB body was accepted and text/plain got 400 instead of 415).
  app.use((req, res, next) => {
    if (Buffer.isBuffer(req.body) || typeof req.body === 'string') {
      const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.from(req.body);
      if (raw.length && !req.is('application/json')) {
        return next(new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json.'));
      }
      const text = raw.toString('utf8').trim();
      const decoded = /^[A-Za-z0-9+/=\s]+$/.test(text) && !text.startsWith('{')
        ? Buffer.from(text, 'base64').toString('utf8') : text;
      if (Buffer.byteLength(decoded) > 20 * 1024) {
        return next(new ApiError(413, 'PAYLOAD_TOO_LARGE', 'Request body is too large.'));
      }
      try {
        req.body = decoded ? JSON.parse(decoded) : {};
      } catch {
        return next(new ApiError(400, 'VALIDATION_ERROR', 'Request body is not valid JSON.'));
      }
    }
    if (req.body === undefined || req.body === null) req.body = {};
    next();
  });

  // Write requests must be JSON (415 otherwise)
  app.use((req, res, next) => {
    const hasBody = ['POST', 'PUT', 'PATCH'].includes(req.method) && Number(req.get('content-length') || 0) > 0;
    if (hasBody && !req.is('application/json')) {
      return next(new ApiError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Content-Type must be application/json.'));
    }
    next();
  });

  app.get(`/api/${service}/health`, (req, res) => {
    res.status(200).json({
      status: 'ok',
      service,
      runtime: process.env.AWS_LAMBDA_FUNCTION_NAME ? 'lambda' : 'pc',
      environment: process.env.NODE_ENV || 'development'
    });
  });

  mount(app);

  app.use((req, res) => {
    res.status(404).json({ error: { code: 'ROUTE_NOT_FOUND', message: 'Route not found.' } });
  });

  // Central error handler: known errors -> their status; anything else -> 500 without internals
  // eslint-disable-next-line no-unused-vars
  app.use((error, req, res, next) => {
    if (error.type === 'entity.parse.failed') {
      return res.status(400).json({ error: { code: 'VALIDATION_ERROR', message: 'Request body is not valid JSON.' } });
    }
    if (error.type === 'entity.too.large') {
      return res.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large.' } });
    }
    if (error instanceof ApiError) {
      const body = { error: { code: error.code, message: error.message } };
      if (error.details) body.error.details = error.details;
      return res.status(error.status).json(body);
    }
    logger.error('UNHANDLED_ERROR', { requestId: req.requestId, path: req.path, message: error.message, name: error.name });
    res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: 'An unexpected server error occurred.' } });
  });

  return app;
}

// Wraps async route handlers so thrown errors reach the central error handler
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

module.exports = { createApp, wrap };
