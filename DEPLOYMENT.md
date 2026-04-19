# Deploying Cafe Ordering on Railway

## Prerequisites

- GitHub repository pushed to the `prod-upgrade` branch.
- Railway account.
- Stripe account for paid checkout.
- SendGrid or SMTP credentials for receipt emails.

## 1. Create the Railway project

1. In Railway, choose **New Project**.
2. Select **Deploy from GitHub repo**.
3. Pick `k89293676-creator/Cafe-ordering` and the `prod-upgrade` branch.
4. Add a PostgreSQL database service to the project.

## 2. Configure environment variables

Required:

- `DATABASE_URL` - provided by Railway PostgreSQL.
- `SECRET_KEY` - random session/CSRF secret.
- `ADMIN_SECRET_KEY` - random secret for `/admin/login`.

Stripe:

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_PUBLISHABLE_KEY`
- `STRIPE_CURRENCY` - optional, defaults to `inr`.

Email:

- `SENDGRID_API_KEY` or SMTP variables.
- `MAIL_SERVER`
- `MAIL_PORT`
- `MAIL_USE_TLS`
- `MAIL_USERNAME`
- `MAIL_PASSWORD`
- `MAIL_DEFAULT_SENDER`

Optional:

- `REDIS_URL`
- `GEMINI_API_KEY`
- `FLASK_ENV=production`

## 3. Start command

Railway can use the included Dockerfile. If you deploy with Nixpacks, use:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT --worker-class gevent --workers 1 --threads 4
```

## 4. Stripe webhook

Create a Stripe webhook endpoint:

```text
https://YOUR_RAILWAY_DOMAIN/stripe/webhook
```

Subscribe to:

- `checkout.session.completed`
- `payment_intent.succeeded`

Copy the webhook signing secret into `STRIPE_WEBHOOK_SECRET`.

## 5. First-time setup

1. Open `/owner/signup` on the deployed domain.
2. Create an owner account.
3. Add tables and menu items.
4. Configure logo/color in `/owner/profile`.
5. Share table QR codes with customers.

## Notes

The app uses PostgreSQL when `DATABASE_URL` is set and SQLite otherwise. Legacy JSON files are imported into the database on first startup if the owner table is empty.
