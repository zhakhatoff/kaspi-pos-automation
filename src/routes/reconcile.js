import { Router } from 'express';
import { requireAuth } from '../authMiddleware.js';
import {
  trackPayment,
  getTrackedPayment,
  getTrackedPayments,
  fetchKaspiStatus,
  classifyStatus,
  buildPayload,
  sendWebhooks,
} from '../polling.js';
import { getWebhooksByEvent } from '../webhookStore.js';

const router = Router();

router.use(requireAuth);

const ALLOWED_EVENTS = new Set([
  'payment.success',
  'payment.failed',
  'payment.expired',
  'payment.unknown',
]);

const normalizeOperationId = (raw) => {
  if (raw === undefined || raw === null || raw === '') return null;
  if (typeof raw !== 'string' && typeof raw !== 'number') return null;
  return String(raw);
};

const sessionHeadersFromReq = (req) => ({
  tokenSN: req.session.tokenSN,
  vtokenSecret: req.session.vtokenSecret,
  profileId: req.session.profileId,
});

// Strip sensitive fields (sessionHeaders holds encrypted vtokenSecret,
// meta may include qrToken) before returning entries to the caller.
const sanitizeEntry = (entry) => ({
  paymentId: entry.paymentId,
  type: entry.type,
  status: entry.status,
  retryCount: entry.retryCount || 0,
  fetchRetry: entry.fetchRetry || 0,
  sessionRetry: entry.sessionRetry || 0,
  createdAt: entry.createdAt,
});

// ─── POST /api/reconcile ───
//
// Manual sync for a single operationId. If already tracked in memory,
// return the current entry without hitting Kaspi. Otherwise fetch status
// once, classify, and either return the terminal event or start tracking.
router.post('/', async (req, res) => {
  const operationId = normalizeOperationId(req.body?.operationId);
  if (!operationId) return res.status(400).json({ error: 'operationId required' });
  const type = req.body?.type === 'invoice' ? 'invoice' : 'qr';

  const existing = getTrackedPayment(operationId);
  if (existing) {
    return res.json({
      tracked: true,
      source: 'memory',
      entry: { ...sanitizeEntry(existing), meta: existing.meta || {} },
    });
  }

  const sessionHeaders = sessionHeadersFromReq(req);
  const result = await fetchKaspiStatus({ paymentId: operationId, type, sessionHeaders });
  if (result && result.error === 'session_expired') {
    return res.status(401).json({ error: 'session_expired' });
  }
  if (!result || !result.Data) {
    return res.status(502).json({ error: 'kaspi_unavailable' });
  }

  const newStatus = result.Data.Status;
  const cls = classifyStatus(type, newStatus);

  if (cls.terminal) {
    const payload = buildPayload(
      cls.event,
      { paymentId: operationId, type, status: newStatus, meta: {} },
      result.Data,
    );
    return res.json({
      tracked: false,
      terminal: true,
      status: newStatus,
      event: cls.event,
      payload,
    });
  }

  // intermediate or unknown → start tracking
  trackPayment(operationId, type, sessionHeaders, {
    amount: result.Data.Amount,
    receiptUrl: result.Data.ReceiptUrl,
    orderNumber: result.Data.OrderNumber,
  });
  return res.json({
    tracked: true,
    terminal: false,
    status: newStatus,
    event: null,
    source: 'reconcile',
  });
});

// ─── POST /api/reconcile/webhook-replay ───
//
// Re-send a webhook for a payment whose current Kaspi status still maps
// to the requested event. Guards against firing payment.success on a
// payment that has since transitioned.
router.post('/webhook-replay', async (req, res) => {
  const operationId = normalizeOperationId(req.body?.operationId);
  if (!operationId) return res.status(400).json({ error: 'operationId required' });
  const event = req.body?.event;
  if (!event || !ALLOWED_EVENTS.has(event)) {
    return res.status(400).json({ error: 'invalid event' });
  }

  const tracked = getTrackedPayment(operationId);
  const type = req.body?.type === 'invoice' ? 'invoice' : tracked?.type || 'qr';

  const sessionHeaders = sessionHeadersFromReq(req);
  const result = await fetchKaspiStatus({ paymentId: operationId, type, sessionHeaders });
  if (result && result.error === 'session_expired') {
    return res.status(401).json({ error: 'session_expired' });
  }
  if (!result || !result.Data) {
    return res.status(502).json({ error: 'kaspi_unavailable' });
  }

  const currentStatus = result.Data.Status;
  const cls = classifyStatus(type, currentStatus);
  const currentEvent = cls.event ?? (cls.unknown ? 'payment.unknown' : null);

  if (event !== currentEvent) {
    return res.status(409).json({
      error: 'event_mismatch',
      currentEvent,
      currentStatus,
    });
  }

  const payload = buildPayload(
    event,
    { paymentId: operationId, type, status: currentStatus, meta: {} },
    result.Data,
  );
  sendWebhooks(event, payload);

  return res.json({
    replayed: true,
    event,
    hooks: getWebhooksByEvent(event).length,
  });
});

// ─── GET /api/reconcile/tracked ───
router.get('/tracked', (_req, res) => {
  const all = getTrackedPayments();
  const list = Object.values(all).map(sanitizeEntry);
  res.json(list);
});

export default router;
