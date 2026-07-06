import { Router } from 'express';
import { KASPI_QRPAY_URL } from '../config.js';
import { loggedFetch, signedQrPayHeaders } from '../helpers.js';
import { decryptSecret } from '../crypto.js';
import { readSession } from '../authMiddleware.js';

const router = Router();

// ─── Check session validity ───

router.get('/check', async (req, res) => {
  const session = readSession(req);

  // 1. Check required creds present (cookie or legacy headers)
  if (!session.tokenSN) return res.status(401).json({ active: false, error: 'No session.' });
  if (!session.vtokenSecret) return res.status(401).json({ active: false, error: 'No session secret.' });

  // 2. Try to decrypt vtokenSecret
  try {
    session.decryptedSecret = decryptSecret(session.vtokenSecret);
  } catch {
    return res.status(401).json({ active: false, error: 'Invalid or expired vtokenSecret. Re-authenticate.' });
  }

  // 3. Ping Kaspi API to verify the token is still accepted
  try {
    const url = `${KASPI_QRPAY_URL}/v02/history/operations`;
    const headers = { ...signedQrPayHeaders(url, session), 'Content-Type': 'application/json' };
    const resp = await loggedFetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        EndDate: new Date().toISOString().slice(0, 10),
        LastTransactionDate: '',
        StatementPeriodCode: 0,
      }),
    });

    const body = await resp.json().catch(() => ({}));

    // Kaspi may return HTTP 200 but with error StatusCode in body
    if (resp.ok && (!body.StatusCode || body.StatusCode === 0)) {
      return res.json({ active: true });
    }

    return res.status(resp.ok ? 401 : resp.status).json({
      active: false,
      error: body.Message || body.message || 'Session rejected by Kaspi API.',
      code: body.StatusCode || body.Code,
      details: body,
    });
  } catch (err) {
    return res.status(500).json({ active: false, error: err.message });
  }
});

export default router;
