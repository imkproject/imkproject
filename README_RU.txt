РАЗВЁРТЫВАНИЕ IMKPROJECT НА CLOUDFLARE
======================================

Комплект:
- public/index.html — сайт с соцсетями и формами регистрации/входа;
- functions/ — серверные API Cloudflare Pages Functions;
- schema.sql — структура базы D1;
- wrangler.toml — конфигурация проекта.

1) Создайте Cloudflare Pages project и разверните папку public как статическую часть проекта, вместе с папкой functions.
2) Создайте D1 database (например imkproject-db).
3) Выполните schema.sql в D1: Dashboard → D1 → ваша база → Console.
4) В wrangler.toml замените REPLACE_WITH_YOUR_D1_DATABASE_ID на ID вашей базы и настройте binding DB для Pages Functions.
5) В Cloudflare Turnstile создайте виджет для домена сайта.
6) В public/index.html замените REPLACE_WITH_TURNSTILE_SITE_KEY на публичный Site Key.
7) В Pages → Settings → Variables and Secrets добавьте TURNSTILE_SECRET_KEY как Secret (не обычную переменную).
8) Повторно разверните сайт.

CLI-пример:
  npx wrangler d1 create imkproject-db
  npx wrangler d1 execute imkproject-db --file=./schema.sql
  npx wrangler pages deploy ./public

ВАЖНО: при деплое Pages Functions должны попасть в корень проекта рядом с папкой public (не внутрь public). Для Git-интеграции используйте этот проект целиком и настройте output directory public.

Безопасность:
- Пароли: PBKDF2-SHA256, 310 000 итераций, индивидуальная соль.
- Сессии: случайный токен, в D1 хранится только SHA-256 токена.
- Cookie: HttpOnly, Secure, SameSite=Lax, срок 7 дней.
- CAPTCHA проверяется сервером через Cloudflare Siteverify.
- Ограничения: пароль 8–128 символов; логин 3–24 символа латиницей, цифрами и _.
- Подтверждение email и восстановление пароля пока не реализованы.
- Не помещайте TURNSTILE_SECRET_KEY в HTML или Git. Используйте только Cloudflare Secret.
- Перед публичным запуском включите резервное копирование D1 и протестируйте API на своём домене.
