// Cookie helpers for HttpOnly session storage.
//
// The session blob contains {tokenSN, vtokenSecret, profileId}. vtokenSecret is
// already AES-256-GCM ciphertext (see src/crypto.js), tokenSN by itself is
// useless without the ECDH-derived secret, and profileId is not sensitive —
// so the blob is not additionally signed. Confidentiality/integrity of
// vtokenSecret is provided by ENCRYPTION_KEY on the server side.

export const SESSION_COOKIE_NAME = 'kaspi_session';

// Parse a Cookie header value into a plain object. First occurrence wins on
// duplicate keys (mirrors what browsers send and what most parsers do).
export function parseCookieHeader(header) {
  const out = {};
  if (!header || typeof header !== 'string') return out;
  const pairs = header.split(';');
  for (const raw of pairs) {
    const idx = raw.indexOf('=');
    if (idx < 0) continue;
    const name = raw.slice(0, idx).trim();
    if (!name) continue;
    if (Object.prototype.hasOwnProperty.call(out, name)) continue;
    let value = raw.slice(idx + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1);
    }
    try {
      out[name] = decodeURIComponent(value);
    } catch {
      out[name] = value;
    }
  }
  return out;
}

// Serialize a single Set-Cookie value. opts supports:
//   httpOnly, secure, sameSite ('Strict'|'Lax'|'None'), path, maxAge (seconds),
//   domain, expires (Date).
export function serializeCookie(name, value, opts = {}) {
  const parts = [`${name}=${encodeURIComponent(value)}`];
  if (opts.maxAge != null) parts.push(`Max-Age=${Math.floor(opts.maxAge)}`);
  if (opts.domain) parts.push(`Domain=${opts.domain}`);
  if (opts.path) parts.push(`Path=${opts.path}`);
  if (opts.expires instanceof Date) parts.push(`Expires=${opts.expires.toUTCString()}`);
  if (opts.httpOnly) parts.push('HttpOnly');
  if (opts.secure) parts.push('Secure');
  if (opts.sameSite) parts.push(`SameSite=${opts.sameSite}`);
  return parts.join('; ');
}

export function buildSessionCookie({ tokenSN, vtokenSecret, profileId }) {
  const payload = JSON.stringify({
    tokenSN: tokenSN || null,
    vtokenSecret: vtokenSecret || null,
    profileId: profileId != null ? String(profileId) : null,
  });
  return Buffer.from(payload, 'utf8').toString('base64url');
}

export function parseSessionCookie(blob) {
  if (!blob || typeof blob !== 'string') return null;
  try {
    const json = Buffer.from(blob, 'base64url').toString('utf8');
    const obj = JSON.parse(json);
    if (!obj || typeof obj !== 'object') return null;
    return {
      tokenSN: obj.tokenSN || null,
      vtokenSecret: obj.vtokenSecret || null,
      profileId: obj.profileId != null ? String(obj.profileId) : null,
    };
  } catch {
    return null;
  }
}

// Whether cookies should be flagged Secure. Production defaults on; anything
// else requires COOKIE_SECURE=1 to opt in (localhost over HTTP won't accept
// Secure cookies).
export function cookieSecureFlag() {
  return process.env.NODE_ENV === 'production' || process.env.COOKIE_SECURE === '1';
}

// Standard options for the session cookie.
export function sessionCookieOptions({ maxAge = 60 * 60 * 24 * 30 } = {}) {
  return {
    httpOnly: true,
    secure: cookieSecureFlag(),
    sameSite: 'Strict',
    path: '/',
    maxAge,
  };
}
