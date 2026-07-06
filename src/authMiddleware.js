import { decryptSecret } from './crypto.js';
import { parseCookieHeader, parseSessionCookie, SESSION_COOKIE_NAME } from './cookies.js';

export { SESSION_COOKIE_NAME };

// Read session credentials from either the HttpOnly cookie or the legacy
// X-Token-SN / X-Vtoken-Secret / X-Profile-Id headers.
//
// TODO(remove-legacy-headers, target 2026-Q4): the header fallback exists only
// for curl-scripts and the previous localStorage-based UI. Once callers are
// migrated to cookie-based auth, delete the header branch and stop accepting
// credentials outside the cookie.
export function readSession(req) {
  // Cookie path (preferred). If a middleware already parsed cookies onto
  // req.cookies, use that; otherwise parse the header directly.
  const cookies = req.cookies || parseCookieHeader(req.headers.cookie || '');
  const blob = cookies[SESSION_COOKIE_NAME];
  if (blob) {
    const parsed = parseSessionCookie(blob);
    if (parsed && parsed.tokenSN && parsed.vtokenSecret) {
      return {
        tokenSN: parsed.tokenSN,
        vtokenSecret: parsed.vtokenSecret,
        profileId: parsed.profileId,
        source: 'cookie',
      };
    }
  }
  // Legacy header fallback.
  const headerToken = req.headers['x-token-sn'];
  const headerSecret = req.headers['x-vtoken-secret'];
  if (headerToken || headerSecret) {
    return {
      tokenSN: headerToken || null,
      vtokenSecret: headerSecret || null,
      profileId: req.headers['x-profile-id'] || null,
      source: 'header',
    };
  }
  return { tokenSN: null, vtokenSecret: null, profileId: null, source: null };
}

export function requireAuth(req, res, next) {
  const session = readSession(req);
  if (!session.tokenSN) {
    return res.status(401).json({ error: 'Missing session (tokenSN).' });
  }
  if (!session.vtokenSecret) {
    return res.status(401).json({ error: 'Missing session (vtokenSecret).' });
  }
  try {
    session.decryptedSecret = decryptSecret(session.vtokenSecret);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired vtokenSecret. Re-authenticate.' });
  }
  req.session = session;
  next();
}
