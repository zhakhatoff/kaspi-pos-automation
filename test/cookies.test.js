import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseCookieHeader,
  serializeCookie,
  buildSessionCookie,
  parseSessionCookie,
  SESSION_COOKIE_NAME,
} from '../src/cookies.js';

describe('parseCookieHeader', () => {
  it('parses a simple header', () => {
    assert.deepEqual(parseCookieHeader('a=1; b=2'), { a: '1', b: '2' });
  });

  it('returns first value on duplicate keys', () => {
    assert.deepEqual(parseCookieHeader('a=1; b=2; a=3'), { a: '1', b: '2' });
  });

  it('URL-decodes values', () => {
    assert.deepEqual(parseCookieHeader('x=%7Bhi%7D'), { x: '{hi}' });
  });

  it('handles empty / missing header', () => {
    assert.deepEqual(parseCookieHeader(''), {});
    assert.deepEqual(parseCookieHeader(undefined), {});
  });

  it('strips surrounding quotes', () => {
    assert.deepEqual(parseCookieHeader('x="hi"'), { x: 'hi' });
  });
});

describe('serializeCookie', () => {
  it('emits standard flags', () => {
    const s = serializeCookie('kaspi_session', 'X', {
      httpOnly: true,
      secure: true,
      sameSite: 'Strict',
      path: '/',
      maxAge: 60,
    });
    assert.match(s, /^kaspi_session=X/);
    assert.match(s, /HttpOnly/);
    assert.match(s, /Secure/);
    assert.match(s, /SameSite=Strict/);
    assert.match(s, /Path=\//);
    assert.match(s, /Max-Age=60/);
  });

  it('URL-encodes value', () => {
    const s = serializeCookie('n', 'a b', {});
    assert.match(s, /^n=a%20b/);
  });

  it('omits flags that are not set', () => {
    const s = serializeCookie('n', 'v', {});
    assert.doesNotMatch(s, /HttpOnly/);
    assert.doesNotMatch(s, /Secure/);
    assert.doesNotMatch(s, /SameSite/);
  });
});

describe('buildSessionCookie / parseSessionCookie', () => {
  it('round-trips fields', () => {
    const blob = buildSessionCookie({ tokenSN: 'T', vtokenSecret: 'V', profileId: 42 });
    const parsed = parseSessionCookie(blob);
    assert.equal(parsed.tokenSN, 'T');
    assert.equal(parsed.vtokenSecret, 'V');
    assert.equal(parsed.profileId, '42');
  });

  it('returns null for garbage input', () => {
    assert.equal(parseSessionCookie('not-base64url-json'), null);
    assert.equal(parseSessionCookie(''), null);
    assert.equal(parseSessionCookie(null), null);
  });

  it('exports a stable cookie name', () => {
    assert.equal(SESSION_COOKIE_NAME, 'kaspi_session');
  });
});
