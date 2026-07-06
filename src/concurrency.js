// ─── Bounded concurrency helper ───
//
// Runs `worker(item, idx)` over `items` with at most `limit` in-flight
// promises. Errors thrown by a worker are swallowed so a single failing
// task cannot poison the whole pool — workers are expected to log their
// own failures. Resolves once every item has been processed.

export const runWithConcurrency = async (items, limit, worker) => {
  if (!Array.isArray(items) || items.length === 0) return;
  let i = 0;
  const n = Math.min(Math.max(1, limit | 0), items.length);
  const run = async () => {
    while (i < items.length) {
      const idx = i++;
      try {
        await worker(items[idx], idx);
      } catch {
        // Swallow — workers must log their own errors.
      }
    }
  };
  await Promise.all(Array.from({ length: n }, run));
};
