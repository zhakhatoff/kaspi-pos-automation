# Changelog

Все заметные изменения в проекте документируются в этом файле.

Формат основан на [Keep a Changelog](https://keepachangelog.com/ru/1.0.0/),
проект придерживается [Semantic Versioning](https://semver.org/lang/ru/).

## [Unreleased]

### Изменено

- Серверная сессия перенесена из `localStorage` в HttpOnly Secure `SameSite=Strict` cookie `kaspi_session`. Веб-UI больше не хранит `tokenSN` и `vtokenSecret` в браузерном хранилище. Существующие пользователи будут разлогинены при обновлении и должны войти заново.
- Добавлены заголовки `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. `img-src` разрешает `api.qrserver.com` для внешнего QR-рендера.
- HTML-экранирование добавлено в рендер истории, продаж и деталей операций.
- Заголовки `X-Token-SN` / `X-Vtoken-Secret` / `X-Profile-Id` пока принимаются как fallback для curl-скриптов и будут удалены в следующем релизе.
- Переменная `COOKIE_SECURE=1` включает флаг `Secure` вне `NODE_ENV=production`.
- Эндпоинт `POST /api/auth/session` удалён — используйте `GET /api/session/check`.

## [1.0.0] - 2025-05-09

### Добавлено

- Серверное приложение на Express для автоматизации Kaspi Pay POS.
- 3-шаговая SMS-авторизация (init → send-phone → verify-otp).
- Создание счетов и генерация QR-кодов.
- Просмотр истории транзакций.
- Оформление возвратов.
- Веб-интерфейс (SPA) в `public/`.
- ECDH/ECDSA криптография и TOTP-генерация.
- AES-256-GCM шифрование `vtokenSecret`.
- Поллинг статусов платежей с вебхук-уведомлениями.
- Скрипты ротации ключей (`regen:keypair`, `regen:device`).
- Файловое и консольное логирование.
- Подготовка к open source: SECURITY.md, CONTRIBUTING.md, LICENSE (MIT), GitHub-шаблоны, ESLint, Prettier, EditorConfig, CI.
