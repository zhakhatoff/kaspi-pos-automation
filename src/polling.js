import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import fetch from 'node-fetch';
import { fileURLToPath } from 'url';
import { DATA_DIR, KASPI_QRPAY_URL } from './config.js';
import { signedQrPayHeaders } from './helpers.js';
import { decryptSecret } from './crypto.js';
import { getWebhooksByEvent } from './webhookStore.js';
import { logger } from './logger.js';
import { runWithConcurrency } from './concurrency.js';

const POLL_CONCURRENCY = Number(process.env.KASPI_POLL_CONCURRENCY) || 8;
const POLL_TIMEOUT_MS = Number(process.env.KASPI_POLL_TIMEOUT_MS) || 8000;

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TRACKED_FILE = path.join(DATA_DIR, 'tracked-payments.json');

// ─── Tracked payments ───

const trackedPayments = new Map();

// ─── Persistence ───

const saveTracked = () => {
  try {
    const data = Object.fromEntries(trackedPayments);
    fs.writeFileSync(TRACKED_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    logger.error('POLLING', 'Failed to save tracked payments', err.message);
  }
};

const loadTracked = () => {
  try {
    if (!fs.existsSync(TRACKED_FILE)) return;
    const raw = fs.readFileSync(TRACKED_FILE, 'utf8');
    const data = JSON.parse(raw);
    for (const [id, entry] of Object.entries(data)) {
      trackedPayments.set(id, entry);
    }
    if (trackedPayments.size > 0) {
      logger.info('POLLING', `Restored ${trackedPayments.size} tracked payments from file`);
    }
  } catch (err) {
    logger.error('POLLING', 'Failed to load tracked payments', err.message);
  }
};

// ─── Pending retries (persisted) ───

const RETRY_FILE = path.join(DATA_DIR, 'webhook-retries.json');
let pendingRetries = [];

const saveRetries = () => {
  try {
    fs.writeFileSync(RETRY_FILE, JSON.stringify(pendingRetries, null, 2));
  } catch (err) {
    logger.error('WEBHOOK', 'Failed to save retries', err.message);
  }
};

const loadRetries = () => {
  try {
    if (!fs.existsSync(RETRY_FILE)) return;
    const raw = fs.readFileSync(RETRY_FILE, 'utf8');
    pendingRetries = JSON.parse(raw);
    if (pendingRetries.length > 0) {
      logger.info('WEBHOOK', `Restored ${pendingRetries.length} pending retries from file`);
    }
  } catch (err) {
    logger.error('WEBHOOK', 'Failed to load retries', err.message);
    pendingRetries = [];
  }
};

// ─── Status → event mapping ───

const QR_FINAL_STATUSES = {
  Processed: 'payment.success',
  CancelledByUser: 'payment.failed',
  NotConfirmedByUser: 'payment.failed',
  CancelledByExternalSource: 'payment.failed',
  ProcessingFailed: 'payment.failed',
  Rejected: 'payment.failed',
  InsufficientFunds: 'payment.failed',
  InsufficientFundsError: 'payment.failed',
  Error: 'payment.failed',
  IrisSrcBlockCode1: 'payment.failed',
  IrisSrcBlockCode3: 'payment.failed',
  IrisSrcBlockCode9: 'payment.failed',
  IrisDestBlockCode3: 'payment.failed',
  IrisDestBlockCode5: 'payment.failed',
  IrisDestBlockCode7: 'payment.failed',
  IrisDestBlockCode10: 'payment.failed',
  QrTokenDiscarded: 'payment.expired',
  Expired: 'payment.expired',
};

const INVOICE_FINAL_STATUSES = {
  Processed: 'payment.success',
  RemotePaymentCanceled: 'payment.failed',
  RemotePaymentRejected: 'payment.failed',
  Expired: 'payment.expired',
};

// Kaspi mid-2026 merged remote-invoice into the QR pipeline: operations
// now come back with QrOperationId (we track them as type='qr') but their
// status flow still steps through 'RemotePaymentCreated' (push delivered
// to the recipient, awaiting their tap on "Оплатить"). The old QR set
// only covered the bare QR-token states, so RemotePaymentCreated fell
// through resolveEvent's default and emitted payment.failed almost
// immediately after invoice/create — every push died at "first status
// change" before the customer ever saw the prompt.
//
// Treat any not-yet-final state as intermediate. The polling loop just
// keeps watching until a real terminal status (Processed / Canceled* /
// Expired / etc.) actually arrives.
const QR_INTERMEDIATE = new Set([
  'QrTokenCreated',
  'Wait',
  'WaitForRemotePayment',
  'WaitingForPayment',
  'RemotePaymentCreated',
]);
const INVOICE_INTERMEDIATE = new Set([
  'RemotePaymentCreated',
  'QrTokenCreated',
  'Wait',
  'WaitForRemotePayment',
  'WaitingForPayment',
]);

// ─── Track a payment ───

export const trackPayment = (paymentId, type, sessionHeaders, meta = {}) => {
  trackedPayments.set(String(paymentId), {
    paymentId: String(paymentId),
    type,
    status: type === 'qr' ? 'QrTokenCreated' : 'RemotePaymentCreated',
    sessionHeaders,
    meta,
    createdAt: Date.now(),
    retryCount: 0,
  });
  saveTracked();
  logger.info('POLLING', `Tracking ${type} payment ${paymentId}`);
};

// ─── Fetch status from Kaspi (quiet — no loggedFetch) ───
//
// Exported for reconcile-only use. Do not call from other routes — a
// stray call spawns a shadow-poll cycle that races the primary loop.
export const fetchKaspiStatus = async (entry) => {
  const { paymentId, type, sessionHeaders } = entry;

  let decryptedSecret;
  try {
    decryptedSecret = decryptSecret(sessionHeaders.vtokenSecret);
  } catch {
    logger.error('POLLING', `Failed to decrypt session for payment ${paymentId} — session may have expired`);
    return { error: 'session_expired' };
  }

  const session = {
    tokenSN: sessionHeaders.tokenSN,
    decryptedSecret,
    profileId: sessionHeaders.profileId,
  };

  let url;
  if (type === 'qr') {
    url = `${KASPI_QRPAY_URL}/v02/kaspi-qr/status?qrOperationId=${paymentId}`;
  } else {
    url = `${KASPI_QRPAY_URL}/v02/remote/details?operationId=${paymentId}`;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), POLL_TIMEOUT_MS);
  try {
    const resp = await fetch(url, {
      headers: signedQrPayHeaders(url, session),
      signal: controller.signal,
    });
    if (resp.status === 401 || resp.status === 403) {
      logger.warn('POLLING', `Kaspi returned ${resp.status} for payment ${paymentId} — treating as session_expired`);
      return { error: 'session_expired' };
    }
    return await resp.json();
  } catch (err) {
    logger.error('POLLING', `Error fetching status for ${paymentId}:`, err.message);
    return null;
  } finally {
    clearTimeout(timer);
  }
};

// ─── Send webhooks ───

const fetchWithTimeout = async (url, options, timeoutMs = 10000) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timer);
    return resp;
  } catch (err) {
    clearTimeout(timer);
    throw err;
  }
};

const dropPendingRetry = (hook, payload) => {
  pendingRetries = pendingRetries.filter(
    (r) => !(r.hook.url === hook.url && r.payload.paymentId === payload.paymentId && r.payload.event === payload.event),
  );
  saveRetries();
};

const scheduleWebhookRetry = (hook, payload, attempt, reason) => {
  logger.error('WEBHOOK', `→ ${hook.url} | attempt ${attempt} FAILED: ${reason}`);
  if (attempt < 3) {
    pendingRetries.push({
      hook,
      payload,
      attempt: attempt + 1,
      executeAfter: Date.now() + (attempt === 1 ? 5000 : 30000),
    });
    saveRetries();
  } else {
    logger.error('WEBHOOK', `→ ${hook.url} | FAILED after 3 retries`);
    dropPendingRetry(hook, payload);
  }
};

const sendWebhook = async (hook, payload, attempt = 1) => {
  const body = JSON.stringify(payload);
  const headers = { 'Content-Type': 'application/json' };
  // Signature MUST NOT be sent when there is no secret — an HMAC over the
  // empty key would give receivers a false sense of authenticity.
  if (hook.secret) {
    headers['X-Webhook-Signature'] =
      'sha256=' + crypto.createHmac('sha256', hook.secret).update(body).digest('hex');
  }

  try {
    const resp = await fetchWithTimeout(hook.url, { method: 'POST', headers, body });
    if (!resp.ok) {
      scheduleWebhookRetry(hook, payload, attempt, `HTTP ${resp.status} ${resp.statusText}`);
      return;
    }
    logger.info('WEBHOOK', `→ ${hook.url} | ${resp.status} ${resp.statusText}`);
    dropPendingRetry(hook, payload);
  } catch (err) {
    scheduleWebhookRetry(hook, payload, attempt, err.message);
  }
};

// Exported for reconcile-only use. Do not wire into other routes.
export const sendWebhooks = (event, payload) => {
  const hooks = getWebhooksByEvent(event);
  for (const hook of hooks) {
    sendWebhook(hook, payload);
  }
};

// ─── Process pending retries ───

const processRetries = async () => {
  const now = Date.now();
  const due = pendingRetries.filter((r) => r.executeAfter <= now);
  // Remove due items from list before executing (they'll be re-added on failure)
  pendingRetries = pendingRetries.filter((r) => r.executeAfter > now);
  saveRetries();

  for (const r of due) {
    await sendWebhook(r.hook, r.payload, r.attempt);
  }
};

// ─── Resolve event from status ───

// Pure classifier: no side effects, no logging. Safe for unit tests.
// Returns { event, terminal, intermediate, unknown }:
//   terminal     — mapped to a payment.* event, polling should stop
//   intermediate — known non-terminal state, keep polling
//   unknown      — status string is not in either set (log at caller)
export const classifyStatus = (type, status) => {
  if (type === 'qr') {
    if (QR_INTERMEDIATE.has(status)) {
      return { event: null, terminal: false, intermediate: true, unknown: false };
    }
    const mapped = QR_FINAL_STATUSES[status];
    if (mapped) {
      return { event: mapped, terminal: true, intermediate: false, unknown: false };
    }
  } else {
    if (INVOICE_INTERMEDIATE.has(status)) {
      return { event: null, terminal: false, intermediate: true, unknown: false };
    }
    const mapped = INVOICE_FINAL_STATUSES[status];
    if (mapped) {
      return { event: mapped, terminal: true, intermediate: false, unknown: false };
    }
  }
  return { event: null, terminal: false, intermediate: false, unknown: true };
};

export const resolveEvent = (type, status) => {
  const cls = classifyStatus(type, status);
  if (cls.terminal) return cls.event;
  if (cls.unknown) {
    // Kaspi occasionally introduces new intermediate states (the
    // RemotePaymentCreated incident was caused by exactly this default).
    logger.warn(
      'POLLING',
      `Unknown ${type} status '${status}' — keeping polling instead of emitting failure`,
    );
  }
  return null;
};

// ─── Poll cycle ───

// Absolute lifetime cap for any tracked payment. Applies as a fallback
// when Kaspi keeps returning an unknown/intermediate status forever
// (e.g. invoice entries have no expireDate; new terminal statuses may
// slip through resolveEvent) so the Map and tracked-payments.json can't
// grow unboundedly.
const MAX_TRACKED_LIFETIME_MS = Number(process.env.KASPI_MAX_TRACKED_LIFETIME_MS) || 24 * 60 * 60 * 1000;

const processEntry = async (id, entry) => {
  // Absolute lifetime fallback — hard delete with payment.unknown so
  // downstream consumers can reconcile via /invoice/details manually.
  if (entry.createdAt && Date.now() - entry.createdAt > MAX_TRACKED_LIFETIME_MS) {
    logger.warn('POLLING', `Payment ${id} exceeded lifetime cap — emitting payment.unknown`);
    sendWebhooks(
      'payment.unknown',
      buildPayload('payment.unknown', entry, {
        Status: entry.status || 'Unknown',
        StatusDesc: 'Превышен лимит времени наблюдения за платежом. Проверьте статус вручную.',
      }),
    );
    trackedPayments.delete(id);
    return true;
  }

  const result = await fetchKaspiStatus(entry);

  // Handle session expiration (local decrypt failure or Kaspi 401/403).
  // Do NOT emit payment.failed — this is a service-side issue, not a
  // payment outcome. A false payment.failed on a Processed payment
  // triggers order cancellation downstream.
  if (result && result.error === 'session_expired') {
    entry.sessionRetry = (entry.sessionRetry || 0) + 1;
    if (entry.sessionRetry === 1 || entry.sessionRetry % 20 === 0) {
      logger.warn(
        'POLLING',
        `Payment ${id} — session_expired (attempt ${entry.sessionRetry}). Refresh /auth/refresh or restart with matching TOKEN_SECRET_KEY.`,
      );
    }
    // Keep the entry; lifetime cap above will eventually reap it.
    return false;
  }

  if (!result || !result.Data) {
    entry.fetchRetry = (entry.fetchRetry || 0) + 1;
    if (entry.fetchRetry > 10) {
      logger.warn('POLLING', `Payment ${id} — 11 failed fetches, emitting payment.unknown`);
      sendWebhooks(
        'payment.unknown',
        buildPayload('payment.unknown', entry, {
          Status: entry.status || 'Unknown',
          StatusDesc: 'Не удалось получить статус платежа от Kaspi. Проверьте статус вручную.',
        }),
      );
      trackedPayments.delete(id);
      return true;
    }
    return false;
  }

  // Reset error counters on successful fetch
  entry.fetchRetry = 0;
  entry.sessionRetry = 0;

  const newStatus = result.Data.Status;

  // TTL by expireDate — apply only when Kaspi itself still reports an
  // intermediate status. Running the check before fetchStatus would
  // race a same-second Processed transition and fire payment.expired
  // over a successful payment.
  if (entry.meta.expireDate && Date.now() > new Date(entry.meta.expireDate).getTime()) {
    const isIntermediate = resolveEvent(entry.type, newStatus) === null;
    if (isIntermediate) {
      logger.info('POLLING', `Payment ${id} expired (TTL, Kaspi status still ${newStatus})`);
      sendWebhooks(
        'payment.expired',
        buildPayload('payment.expired', entry, { Status: 'Expired', StatusDesc: 'Время оплаты истекло' }),
      );
      trackedPayments.delete(id);
      return true;
    }
    // fall through — Kaspi reports a terminal status, emit it below
  }

  if (newStatus === entry.status) return false;

  logger.info('POLLING', `Payment ${id}: ${entry.status} → ${newStatus}`);
  entry.status = newStatus;

  const event = resolveEvent(entry.type, newStatus);
  if (event) {
    sendWebhooks(event, buildPayload(event, entry, result.Data));
    trackedPayments.delete(id);
  }
  return true;
};

const pollOnce = async () => {
  // Snapshot the Map so concurrent delete() inside processEntry does not
  // affect iteration order, and workers process independent entries.
  const snapshot = Array.from(trackedPayments.entries());
  if (snapshot.length === 0) return;

  const results = new Array(snapshot.length);
  await runWithConcurrency(snapshot, POLL_CONCURRENCY, async ([id, entry], idx) => {
    try {
      results[idx] = await processEntry(id, entry);
    } catch (err) {
      logger.error('POLLING', `Unexpected error processing ${id}:`, err.message);
      results[idx] = false;
    }
  });

  if (results.some(Boolean)) {
    saveTracked();
  }
};

export const buildPayload = (event, entry, data) => ({
  event,
  paymentId: entry.paymentId,
  type: entry.type,
  status: data.Status || entry.status,
  statusDesc: data.StatusDesc || '',
  amount: entry.meta.amount || data.Amount || null,
  qrToken: entry.meta.qrToken || null,
  receiptUrl: entry.meta.receiptUrl || data.ReceiptUrl || null,
  orderNumber: entry.meta.orderNumber || data.OrderNumber || null,
  data,
  timestamp: new Date().toISOString(),
});

// ─── Polling loop (setTimeout-based, no overlap) ───

let pollActive = false;
let pollTimer = null;
const POLL_MS = 3000;

const scheduleNext = () => {
  if (!pollActive) return;
  pollTimer = setTimeout(async () => {
    try {
      if (trackedPayments.size > 0) {
        await pollOnce();
      }
      // Process pending webhook retries
      if (pendingRetries.length > 0) {
        await processRetries();
      }
    } catch (err) {
      logger.error('POLLING', 'Unexpected error:', err.message);
    }
    scheduleNext();
  }, POLL_MS);
};

export const startPolling = () => {
  if (pollActive) return;

  // Load persisted state
  loadTracked();
  loadRetries();

  pollActive = true;
  scheduleNext();
  logger.info('POLLING', 'Started (interval: 3s, persistence: enabled)');
};

export const stopPolling = () => {
  pollActive = false;
  if (pollTimer) {
    clearTimeout(pollTimer);
    pollTimer = null;
  }
  saveTracked();
  saveRetries();
  logger.info('POLLING', 'Stopped');
};

export const getTrackedPayments = () => Object.fromEntries(trackedPayments);

// Returns a shallow copy of a tracked entry (or null). We copy so callers
// cannot mutate the internal Map — the polling loop still owns it.
export const getTrackedPayment = (id) => {
  const entry = trackedPayments.get(String(id));
  return entry ? { ...entry } : null;
};
