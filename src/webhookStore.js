import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { DATA_DIR } from './config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WEBHOOKS_FILE_DATA = path.join(DATA_DIR, 'webhooks.json');
const WEBHOOKS_FILE_ROOT = path.join(__dirname, '..', 'webhooks.json');

/**
 * Builds the default webhook subscription from env vars when no
 * webhooks.json is found. This lets containerised deployments avoid
 * committing secrets and avoids the need for a writable file.
 *
 * Env vars:
 *   BOT_WEBHOOK_URL — target URL to POST events to
 *   KASPI_WEBHOOK_SECRET — HMAC secret shared with the target
 *   BOT_WEBHOOK_EVENTS — comma-separated; defaults to all three
 */
const envWebhook = () => {
  const url = process.env.BOT_WEBHOOK_URL;
  const secret = process.env.KASPI_WEBHOOK_SECRET;
  if (!url) return null;
  const events = (process.env.BOT_WEBHOOK_EVENTS || 'payment.success,payment.failed,payment.expired')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  return { url, events, secret };
};

/**
 * Читает webhooks.json и возвращает массив вебхуков.
 * Tries DATA_DIR first, then repo root, then env vars.
 * При ошибке чтения/парсинга возвращает [].
 */
export const loadWebhooks = () => {
  for (const file of [WEBHOOKS_FILE_DATA, WEBHOOKS_FILE_ROOT]) {
    try {
      const raw = fs.readFileSync(file, 'utf8');
      const hooks = JSON.parse(raw);
      if (Array.isArray(hooks) && hooks.length > 0) return hooks;
    } catch (err) {
      if (err.code !== 'ENOENT') {
        console.error(`[WEBHOOK STORE] Error reading ${file}:`, err.message);
      }
    }
  }
  const fromEnv = envWebhook();
  return fromEnv ? [fromEnv] : [];
};

/**
 * Возвращает вебхуки, подписанные на указанное событие.
 */
export const getWebhooksByEvent = (event) => {
  return loadWebhooks().filter((hook) => hook.url && Array.isArray(hook.events) && hook.events.includes(event));
};
