import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

process.env.TOKEN_SECRET_KEY = 'a'.repeat(64);

const { classifyStatus, buildPayload } = await import('../src/polling.js');

describe('classifyStatus — QR', () => {
  it('maps Processed to payment.success (terminal)', () => {
    const cls = classifyStatus('qr', 'Processed');
    assert.equal(cls.event, 'payment.success');
    assert.equal(cls.terminal, true);
    assert.equal(cls.intermediate, false);
    assert.equal(cls.unknown, false);
  });

  it('maps Rejected to payment.failed (terminal)', () => {
    const cls = classifyStatus('qr', 'Rejected');
    assert.equal(cls.event, 'payment.failed');
    assert.equal(cls.terminal, true);
  });

  it('maps Expired to payment.expired (terminal)', () => {
    const cls = classifyStatus('qr', 'Expired');
    assert.equal(cls.event, 'payment.expired');
    assert.equal(cls.terminal, true);
  });

  it('treats RemotePaymentCreated as intermediate', () => {
    const cls = classifyStatus('qr', 'RemotePaymentCreated');
    assert.equal(cls.event, null);
    assert.equal(cls.intermediate, true);
    assert.equal(cls.terminal, false);
    assert.equal(cls.unknown, false);
  });

  it('treats QrTokenCreated as intermediate', () => {
    const cls = classifyStatus('qr', 'QrTokenCreated');
    assert.equal(cls.event, null);
    assert.equal(cls.intermediate, true);
  });

  it('flags a novel status as unknown, no event', () => {
    const cls = classifyStatus('qr', 'SomeFutureStatus');
    assert.equal(cls.event, null);
    assert.equal(cls.unknown, true);
    assert.equal(cls.terminal, false);
    assert.equal(cls.intermediate, false);
  });
});

describe('classifyStatus — invoice', () => {
  it('maps Processed to payment.success', () => {
    assert.equal(classifyStatus('invoice', 'Processed').event, 'payment.success');
  });

  it('maps RemotePaymentCanceled to payment.failed', () => {
    assert.equal(classifyStatus('invoice', 'RemotePaymentCanceled').event, 'payment.failed');
  });

  it('maps Expired to payment.expired', () => {
    assert.equal(classifyStatus('invoice', 'Expired').event, 'payment.expired');
  });

  it('treats RemotePaymentCreated as intermediate', () => {
    const cls = classifyStatus('invoice', 'RemotePaymentCreated');
    assert.equal(cls.event, null);
    assert.equal(cls.intermediate, true);
  });
});

describe('buildPayload', () => {
  it('assembles the standard payload envelope', () => {
    const entry = { paymentId: '42', type: 'qr', status: 'Processed', meta: {} };
    const data = { Status: 'Processed', StatusDesc: 'ok', Amount: 100 };
    const payload = buildPayload('payment.success', entry, data);
    assert.equal(payload.event, 'payment.success');
    assert.equal(payload.paymentId, '42');
    assert.equal(payload.status, 'Processed');
    assert.equal(payload.data, data);
    assert.ok(payload.timestamp);
  });
});
