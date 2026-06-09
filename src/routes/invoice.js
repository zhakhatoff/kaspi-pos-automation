import { Router } from 'express';
import { KASPI_QRPAY_URL } from '../config.js';
import { loggedFetch, signedQrPayHeaders } from '../helpers.js';
import { decryptSecret } from '../crypto.js';
import { trackPayment } from '../polling.js';

const router = Router();

// Extract session from request headers
const extractSession = (req) => ({
  tokenSN: req.headers['x-token-sn'] || null,
  profileId: req.headers['x-profile-id'] || null,
  vtokenSecret: req.headers['x-vtoken-secret'] || null,
});

const requireAuth = (req, res, next) => {
  const session = extractSession(req);
  if (!session.tokenSN) return res.status(401).json({ error: 'Missing X-Token-SN header.' });
  if (!session.vtokenSecret) return res.status(401).json({ error: 'Missing X-Vtoken-Secret header.' });
  try {
    session.decryptedSecret = decryptSecret(session.vtokenSecret);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired vtokenSecret. Re-authenticate.' });
  }
  req.session = session;
  next();
};

router.use(requireAuth);

// ─── Client info ───

router.get('/client-info', async (req, res) => {
  const { phoneNumber } = req.query;
  if (!phoneNumber) return res.status(400).json({ error: 'phoneNumber required' });

  try {
    const url = `${KASPI_QRPAY_URL}/v01/remote/client-info?phoneNumber=${phoneNumber}`;
    const resp = await loggedFetch(url, { headers: signedQrPayHeaders(url, req.session) });
    res.json(await resp.json());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Create invoice ───

router.post('/create', async (req, res) => {
  const { phoneNumber, amount, comment } = req.body;
  if (!phoneNumber || !amount) return res.status(400).json({ error: 'phoneNumber and amount required' });

  try {
    const url = `${KASPI_QRPAY_URL}/v01/remote/create`;
    const headers = { ...signedQrPayHeaders(url, req.session), 'Content-Type': 'application/json' };
    const resp = await loggedFetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ PhoneNumber: phoneNumber, Amount: Number(amount), Comment: comment || '' }),
    });
    const kaspiResponse = await resp.json();
    const d = kaspiResponse.Data || {};
    // Kaspi changed the response shape mid-2026: instead of returning
    // {Id, Status: 'RemotePaymentCreated', Amount, ...} the remote/create
    // endpoint now returns {QrOperationId} only. The old condition
    // (d.Id && d.Status === 'RemotePaymentCreated') silently skipped
    // trackPayment for every new push-invoice, so polling never started
    // and downstream consumers never got the payment.success webhook.
    //
    // Accept both shapes: take whichever ID field exists, infer the
    // polling type from which field came back (QrOperationId → QR status
    // endpoint /v02/kaspi-qr/status, legacy Id → /v02/remote/details).
    const operationId = d.Id || d.QrOperationId || d.OperationId;
    if (operationId) {
      const pollType = (d.Id && !d.QrOperationId) ? 'invoice' : 'qr';
      trackPayment(
        operationId,
        pollType,
        {
          tokenSN: req.session.tokenSN,
          vtokenSecret: req.headers['x-vtoken-secret'],
          profileId: req.session.profileId,
        },
        {
          amount: d.Amount || Number(amount),
          clientMobile: d.ClientMobile || phoneNumber,
          receiptUrl: d.ReceiptUrl,
          orderNumber: d.OrderNumber,
        },
      );
    } else {
      console.warn(
        '[invoice] Kaspi response had no operation id; nothing to poll:',
        JSON.stringify(kaspiResponse).slice(0, 300),
      );
    }
    res.json(kaspiResponse);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Invoice details ───

router.get('/details', async (req, res) => {
  const { operationId } = req.query;
  if (!operationId) return res.status(400).json({ error: 'operationId required' });

  try {
    const url = `${KASPI_QRPAY_URL}/v02/remote/details?operationId=${operationId}`;
    const resp = await loggedFetch(url, { headers: signedQrPayHeaders(url, req.session) });
    res.json(await resp.json());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Cancel invoice ───

router.post('/cancel', async (req, res) => {
  const { operationId } = req.body;
  if (!operationId) return res.status(400).json({ error: 'operationId required' });

  try {
    const url = `${KASPI_QRPAY_URL}/v01/remote/cancel`;
    const headers = { ...signedQrPayHeaders(url, req.session), 'Content-Type': 'application/json' };
    const resp = await loggedFetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ qrOperationId: Number(operationId) }),
    });
    res.json(await resp.json());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Invoice history ───

router.post('/history', async (req, res) => {
  try {
    const url = `${KASPI_QRPAY_URL}/v01/remote/history`;
    const headers = { ...signedQrPayHeaders(url, req.session), 'Content-Type': 'application/json' };
    const resp = await loggedFetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({ MaxResult: 20 }),
    });
    res.json(await resp.json());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

export default router;
