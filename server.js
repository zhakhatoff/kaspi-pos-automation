import express from 'express';
import path from 'path';
import { PORT, ROOT_DIR } from './src/config.js';
import authRoutes from './src/routes/auth.js';
import invoiceRoutes from './src/routes/invoice.js';
import qrRoutes from './src/routes/qr.js';
import historyRoutes from './src/routes/history.js';
import refundRoutes from './src/routes/refund.js';
import sessionRoutes from './src/routes/session.js';
import reconcileRoutes from './src/routes/reconcile.js';
import { startPolling } from './src/polling.js';
import { parseCookieHeader } from './src/cookies.js';
import 'dotenv/config';

const app = express();

// Baseline security headers on every response. img-src allows
// api.qrserver.com because generateQrSvg in public/app.js still uses the
// external QR-render endpoint; migrating to a bundled QR generator would
// let us drop this exception.
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https://api.qrserver.com; object-src 'none'; " +
      "base-uri 'self'; frame-ancestors 'none'",
  );
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(express.json());
app.use((req, _res, next) => {
  req.cookies = parseCookieHeader(req.headers.cookie || '');
  next();
});
app.use(express.static(path.join(ROOT_DIR, 'public')));

app.get('/health', (req, res) => res.json({ status: 'ok' }));

// Optional shared-secret guard on /api/*. Enable by exporting API_TOKEN
// in .env before exposing the service on a public URL — without it any
// client on the internet can trigger /api/auth/init and burn SMS quota
// under the deviceId of the owner.
const API_TOKEN = process.env.API_TOKEN;
if (API_TOKEN) {
  app.use('/api', (req, res, next) => {
    const provided =
      req.headers['x-api-token'] ||
      (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);
    if (provided !== API_TOKEN) return res.status(401).json({ error: 'unauthorized' });
    next();
  });
  console.log('  🔒 API_TOKEN guard enabled on /api/*');
}

app.use('/api/auth', authRoutes);
app.use('/api/invoice', invoiceRoutes);
app.use('/api/qr', qrRoutes);
app.use('/api/history', historyRoutes);
app.use('/api/refund', refundRoutes);
app.use('/api/session', sessionRoutes);
app.use('/api/reconcile', reconcileRoutes);

process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err?.stack || err);
});
process.on('uncaughtException', (err) => {
  console.error('[uncaughtException]', err?.stack || err);
});

app.listen(PORT, () => {
  console.log(`\n  🟢 Kaspi Pay App running at http://localhost:${PORT}\n`);
  startPolling();
});
