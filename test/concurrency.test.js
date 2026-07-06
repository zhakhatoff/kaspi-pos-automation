import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runWithConcurrency } from '../src/concurrency.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('runWithConcurrency caps in-flight workers at limit', async () => {
  const items = Array.from({ length: 20 }, (_, i) => i);
  const processed = [];
  let running = 0;
  let maxRunning = 0;

  await runWithConcurrency(items, 4, async (item) => {
    running++;
    if (running > maxRunning) maxRunning = running;
    await sleep(20);
    processed.push(item);
    running--;
  });

  assert.ok(maxRunning <= 4, `maxRunning was ${maxRunning}`);
  assert.equal(processed.length, 20);
  assert.deepEqual([...processed].sort((a, b) => a - b), items);
});

test('runWithConcurrency does not spawn more workers than items', async () => {
  const items = [1, 2];
  let running = 0;
  let maxRunning = 0;

  await runWithConcurrency(items, 8, async () => {
    running++;
    if (running > maxRunning) maxRunning = running;
    await sleep(15);
    running--;
  });

  assert.ok(maxRunning <= 2, `maxRunning was ${maxRunning}`);
});

test('runWithConcurrency swallows worker errors and keeps going', async () => {
  const items = [0, 1, 2, 3, 4];
  const processed = [];

  await runWithConcurrency(items, 2, async (item) => {
    await sleep(5);
    if (item === 2) throw new Error('boom');
    processed.push(item);
  });

  assert.deepEqual([...processed].sort((a, b) => a - b), [0, 1, 3, 4]);
});

test('runWithConcurrency handles empty items', async () => {
  await runWithConcurrency([], 4, async () => {
    throw new Error('should not run');
  });
});
