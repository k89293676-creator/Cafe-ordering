# Cafe Ordering System

Production-ready Flask cafe ordering SaaS with owner accounts, QR table ordering, Stripe payments, email confirmations, analytics, and per-cafe branding.

## Features

- Owner signup/login with Flask-Login sessions, bcrypt password hashing, CSRF protection, and remember-me tokens.
- SQLAlchemy data layer with Flask-Migrate and automatic SQLite fallback when `DATABASE_URL` is not set.
- PostgreSQL support for Railway production deployments.
- QR table management, menu editing, live order dashboard, customer cancellation window, and feedback.
- Stripe Checkout with webhook support and stored payment intent IDs.
- Flask-Mail order confirmations via SendGrid API key or standard SMTP credentials.
- Owner analytics for revenue, top items, order status, and peak order hours with Chart.js.
- Cafe branding settings for logo URL and brand color.
- Dockerfile and docker-compose setup for local production-style runs.

## Local Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env  # optional, if you create one locally
python app.py
```

Open `http://127.0.0.1:5000/owner/signup` to create your first owner account. Without `DATABASE_URL`, the app uses local SQLite at `instance/cafe_ordering.sqlite3`.

## Docker Compose

```bash
docker compose up --build
```

The app will run at `http://127.0.0.1:8000` with PostgreSQL available in the `db` service.

## Railway Deployment

1. Create a new Railway project from this GitHub repository and branch.
2. Add a Railway PostgreSQL database service.
3. Set the app service start command to use the Dockerfile, or use:

   ```bash
   gunicorn --bind 0.0.0.0:$PORT --worker-class gevent --workers 1 --threads 4 app:app
   ```

4. Add the required environment variables below.
5. Deploy the service.
6. In Stripe, create a webhook endpoint pointing to `https://YOUR_DOMAIN/stripe/webhook` and subscribe to `checkout.session.completed` and `payment_intent.succeeded`.
7. Open `/owner/signup`, create an owner account, configure branding in Profile, then create tables and menu items.

## Environment Variables

### Required for production

- `DATABASE_URL` - Railway PostgreSQL connection string. If omitted, SQLite is used.
- `SECRET_KEY` - Flask session/CSRF secret.
- `ADMIN_SECRET_KEY` - secret key for super-admin routes.

### Stripe

- `STRIPE_SECRET_KEY` - Stripe secret API key.
- `STRIPE_WEBHOOK_SECRET` - Stripe webhook signing secret.
- `STRIPE_PUBLISHABLE_KEY` - publishable key exposed to the browser.
- `STRIPE_CURRENCY` - optional, defaults to `inr`.

### Email

Use either SendGrid or SMTP settings:

- `SENDGRID_API_KEY` - optional SendGrid key. When set, the app uses SendGrid SMTP defaults.
- `MAIL_SERVER` - SMTP host, defaults to `smtp.sendgrid.net` when SendGrid is set.
- `MAIL_PORT` - SMTP port, usually `587`.
- `MAIL_USE_TLS` - `true` or `false`.
- `MAIL_USERNAME` - SMTP username, usually `apikey` for SendGrid.
- `MAIL_PASSWORD` - SMTP password or SendGrid API key.
- `MAIL_DEFAULT_SENDER` - sender email address for order confirmations.

### Optional

- `REDIS_URL` - enables shared rate-limit storage.
- `GEMINI_API_KEY` - enables AI menu helper features if configured.
- `FLASK_ENV` - set to `development` locally for debug mode.
- `DATA_DIR` - optional path for legacy JSON seed files.

## Database Migrations

The app initializes tables automatically on startup and includes additive column creation for upgraded deployments. For explicit migrations, run:

```bash
flask --app app db init
flask --app app db migrate -m "initial schema"
flask --app app db upgrade
```

## Owner Portal

1. Open `/owner/signup` to create an owner account.
2. Sign in at `/owner/login`.
3. Add tables and menu items.
4. Share table QR codes with customers.
5. Monitor and update orders from the dashboard.

## Super Admin

Set `ADMIN_SECRET_KEY`, then use `/admin/login` with that key to access operational dashboards.

## Notes

Legacy JSON files are imported into the SQLAlchemy database on first startup if the owners table is empty. After migration, database storage is the source of truth.
