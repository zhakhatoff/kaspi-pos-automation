import crypto from 'crypto';
import fetch from 'node-fetch';
import { DEVICE, APP, UA_NATIVE } from './config.js';
import { computeTokenSnMac, computeXSign } from './crypto.js';

// ─── Utilities ───

export const generateUUID = () => crypto.randomUUID().toUpperCase();

export const nowISO = () => {
  const d = new Date();
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? '+' : '-';
  const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, '0');
  const mm = String(Math.abs(off) % 60).padStart(2, '0');
  return (
    d
      .toISOString()
      .replace('Z', '')
      .replace(/\.\d{3}/, `.${String(d.getMilliseconds()).padStart(3, '0')}`) +
    sign +
    hh +
    mm
  );
};

// ─── Cookie builder ───

export const entranceCookie = (extraUserToken) => {
  let c = `deviceId=${DEVICE.deviceId}; installId=${DEVICE.installId}; is_mobile_app=true; locale=${APP.locale}; ma_bld=${APP.build}; ma_platform_type=${APP.platform}; ma_platform_ver=${APP.platformVer}; ma_ver=${APP.version}; pk=${DEVICE.pk}; pkTag=${DEVICE.pkTag}; xs=R:0|E:0|RH:0|N:0`;
  if (extraUserToken) c += `; user_token=${extraUserToken}`;
  return c;
};

// ─── Extract user_token from set-cookie ───

export const extractUserToken = (resp) => {
  const raw = resp.headers.raw()['set-cookie'] || [];
  for (const c of raw) {
    const m = c.match(/user_token=([^;]+)/);
    if (m) return m[1];
  }
  return null;
};

// ─── Logged fetch wrapper ───

const KASPI_FETCH_TIMEOUT_MS = Number(process.env.KASPI_FETCH_TIMEOUT_MS) || 25000;
const VERBOSE = process.env.KASPI_VERBOSE_LOGS === '1' || process.env.NODE_ENV !== 'production';

const SENSITIVE_HEADERS = new Set([
  'cookie',
  'x-sign',
  'x-kb-tokensn',
  'x-kb-tokensnmac',
  'x-su',
  'authorization',
]);

const SENSITIVE_BODY_KEYS = new Set([
  'userOtp',
  'phoneNumber',
  'PhoneNumber',
  'pinHash',
  'x509',
  'X509',
  'vtokenSecret',
  'tokenSN',
  'TokenSn',
  'sign',
]);

const maskString = (s) => {
  if (typeof s !== 'string' || s.length <= 4) return '***';
  return s.slice(0, 2) + '***' + s.slice(-2);
};

const maskHeaders = (headers) => {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE_HEADERS.has(k.toLowerCase()) && typeof v === 'string' ? maskString(v) : v;
  }
  return out;
};

const maskBody = (value) => {
  if (Array.isArray(value)) return value.map(maskBody);
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_BODY_KEYS.has(k)) {
        out[k] = typeof v === 'string' ? maskString(v) : '***';
      } else {
        out[k] = maskBody(v);
      }
    }
    return out;
  }
  return value;
};

// node-fetch 2 has no default timeout and its .clone() teed body dead-locks
// on responses larger than the internal PassThrough highWaterMark (~16 KB).
// Read the body once via .text() and JSON.parse to avoid both.
export const loggedFetch = async (url, options = {}) => {
  const method = (options.method || 'GET').toUpperCase();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), KASPI_FETCH_TIMEOUT_MS);
  const finalOptions = { ...options, signal: options.signal || controller.signal };

  if (VERBOSE) {
    console.log(`\n>>> ${method} ${url}`);
    if (options.headers) console.log('>>> Headers:', JSON.stringify(maskHeaders(options.headers), null, 2));
    if (options.body) {
      try {
        console.log('>>> Body:', maskBody(JSON.parse(options.body)));
      } catch {
        console.log('>>> Body:', '[non-json body]');
      }
    }
  }

  let resp;
  try {
    resp = await fetch(url, finalOptions);
  } catch (err) {
    clearTimeout(timer);
    if (err.name === 'AbortError') throw new Error(`kaspi_timeout: ${method} ${url} exceeded ${KASPI_FETCH_TIMEOUT_MS}ms`);
    throw err;
  }

  let text;
  try {
    text = await resp.text();
  } finally {
    clearTimeout(timer);
  }

  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }

  if (VERBOSE) {
    console.log(`<<< ${resp.status} ${resp.statusText}`);
    console.log(
      '<<< Response:',
      typeof parsed === 'object' ? JSON.stringify(maskBody(parsed), null, 2) : String(parsed).slice(0, 500),
    );
  }

  // Preserve the resp.json()/resp.text() contract for existing callers.
  resp.json = async () => (typeof parsed === 'object' && parsed !== null ? parsed : JSON.parse(text));
  resp.text = async () => text;
  return resp;
};

// ─── Signed QR-pay headers (session passed as parameter) ───

export const signedQrPayHeaders = (url, session) => {
  const xsh =
    'url,X-Request-ID,X-Device-ID,X-Platform-Ver,X-App-Bld,X-Time,X-Kb-TokenSn,X-App-Ver,X-Kb-TokenSnMac,X-Call,X-PI,X-Install-ID,X-Platform-Type,X-Locale,X-SV';
  const headers = {
    'X-Kb-TokenSn': session.tokenSN,
    'X-Kb-TokenSnMac': computeTokenSnMac(session.tokenSN, session.decryptedSecret),
    'X-PI': session.profileId != null ? String(session.profileId) : '',
    'X-Install-ID': DEVICE.installId,
    'X-Device-ID': DEVICE.deviceId,
    'X-App-Ver': APP.version,
    'X-App-Bld': APP.build,
    'X-Platform-Type': APP.platform,
    'X-Platform-Ver': APP.platformVer,
    'X-Locale': APP.locale,
    'X-Time': nowISO(),
    'X-Request-ID': generateUUID(),
    'X-Call': 'notConnected',
    'X-SV': '2',
    'X-SH': xsh,
    'User-Agent': UA_NATIVE,
    Accept: '*/*',
    'Accept-Language': 'ru',
    'Accept-Encoding': 'gzip, deflate, br',
  };
  headers['X-Sign'] = computeXSign(url, headers, xsh);
  return headers;
};
