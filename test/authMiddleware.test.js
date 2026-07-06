import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { encryptSecret } = await import('../src/crypto.js');
const { requireAuth, readSession } = await import('../src/authMiddleware.js');
const { buildSessionCookie } = await import('../src/cookies.js');

const validSecret = encryptSecret(Buffer.from('raw-secret'));

function makeReq({ cookieHeader, headers = {} } = {}) {
  return {
    headers: { ...(cookieHeader ? { cookie: cookieHeader } : {}), ...headers },
  };
}

function makeRes() {
  return {
    statusCode: 200,
    body: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(obj) {
      this.body = obj;
      return this;
    },
  };
}

describe('readSession', () => {
  it('prefers cookie over legacy headers', () => {
    const blob = buildSessionCookie({ tokenSN: 'cookieTS', vtokenSecret: validSecret, profileId: 7 });
    const req = makeReq({
      cookieHeader: `kaspi_session=${blob}`,
      headers: { 'x-token-sn': 'headerTS', 'x-vtoken-secret': 'other' },
    });
    const s = readSession(req);
    assert.equal(s.source, 'cookie');
    assert.equal(s.tokenSN, 'cookieTS');
    assert.equal(s.vtokenSecret, validSecret);
    assert.equal(s.profileId, '7');
  });

  it('falls back to legacy headers when cookie missing', () => {
    const req = makeReq({
      headers: { 'x-token-sn': 'TS', 'x-vtoken-secret': 'VS', 'x-profile-id': '9' },
    });
    const s = readSession(req);
    assert.equal(s.source, 'header');
    assert.equal(s.tokenSN, 'TS');
    assert.equal(s.vtokenSecret, 'VS');
    assert.equal(s.profileId, '9');
  });

  it('returns nulls when nothing present', () => {
    const s = readSession(makeReq());
    assert.equal(s.tokenSN, null);
    assert.equal(s.vtokenSecret, null);
    assert.equal(s.source, null);
  });
});

describe('requireAuth', () => {
  it('401 when no session at all', () => {
    const req = makeReq();
    const res = makeRes();
    let nextCalled = false;
    requireAuth(req, res, () => (nextCalled = true));
    assert.equal(res.statusCode, 401);
    assert.equal(nextCalled, false);
  });

  it('401 when vtokenSecret cannot be decrypted', () => {
    const req = makeReq({ headers: { 'x-token-sn': 'TS', 'x-vtoken-secret': 'not-valid' } });
    const res = makeRes();
    let nextCalled = false;
    requireAuth(req, res, () => (nextCalled = true));
    assert.equal(res.statusCode, 401);
    assert.equal(nextCalled, false);
    assert.match(res.body.error, /vtokenSecret/);
  });

  it('passes and populates req.session on valid cookie', () => {
    const blob = buildSessionCookie({ tokenSN: 'TS', vtokenSecret: validSecret, profileId: 1 });
    const req = makeReq({ cookieHeader: `kaspi_session=${blob}` });
    const res = makeRes();
    let nextCalled = false;
    requireAuth(req, res, () => (nextCalled = true));
    assert.equal(nextCalled, true);
    assert.equal(req.session.tokenSN, 'TS');
    assert.ok(Buffer.isBuffer(req.session.decryptedSecret));
    assert.equal(req.session.decryptedSecret.toString(), 'raw-secret');
  });

  it('passes with legacy headers (backward compat)', () => {
    const req = makeReq({
      headers: { 'x-token-sn': 'TS', 'x-vtoken-secret': validSecret, 'x-profile-id': '3' },
    });
    const res = makeRes();
    let nextCalled = false;
    requireAuth(req, res, () => (nextCalled = true));
    assert.equal(nextCalled, true);
    assert.equal(req.session.profileId, '3');
    assert.equal(req.session.decryptedSecret.toString(), 'raw-secret');
  });
});
