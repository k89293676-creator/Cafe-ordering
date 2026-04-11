# Deploying Cafe 11:11 on Railway

## Prerequisites
- GitHub account with the repo pushed (already done)
- Railway account — free at https://railway.app

---

## Step 1 — Create a Railway project from GitHub

1. Go to https://railway.app → **New Project**
2. Choose **Deploy from GitHub repo**
3. Select **k89293676-creator/Cafe-ordering**
4. Railway auto-detects Python / Nixpacks — click **Deploy Now**

---

## Step 2 — Set environment variables

In the Railway service dashboard go to **Variables** and add:

| Key | Value | Notes |
|---|---|---|
| `SECRET_KEY` | (random 32-char string) | **Required** — app won't start without it |
| `FLASK_ENV` | `production` | Enables HTTPS cookies, HSTS, etc. |

Generate a secure key:
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

---

## Step 3 — Add PostgreSQL (recommended)

Using PostgreSQL means your data persists across redeploys:

1. In your Railway project → **New** → **Database** → **PostgreSQL**
2. Railway automatically injects `DATABASE_URL` into your service
3. The app detects `DATABASE_URL` and switches from JSON files to Postgres
4. Tables, indexes, and constraints are created automatically on first start

---

## Step 4 — Alternative: Persistent volume (if not using PostgreSQL)

Without PostgreSQL or a volume, every redeploy wipes orders, menu, and owner accounts.

1. In the Railway service → **Volumes** tab → **Add Volume**
2. Set **Mount Path** to `/data`
3. Add env var `DATA_DIR=/data` in the Variables tab
4. Railway auto-restarts the service with the volume attached

---

## Step 5 — Verify the deployment

Railway config (`railway.json`) already sets:
- **Start**: `gunicorn --bind 0.0.0.0:$PORT --worker-class gthread --workers 2 --threads 4 --timeout 120`
- **Health check**: `GET /health` — returns `{"status":"ok"}` when ready

Watch the **Build Logs** tab. A successful deploy ends with:
```
[INFO] Listening at: http://0.0.0.0:XXXX
```

---

## Step 6 — First-time setup

1. Open your Railway URL (e.g. `https://web-production-xxxx.up.railway.app`)
2. Go to `/owner/signup` and create your owner account
3. Add your menu in the dashboard
4. Create tables — each gets a QR code
5. Download and print the QR codes for each table

---

## Step 7 — Custom domain (optional)

1. Railway service → **Settings** → **Custom Domain**
2. Enter your domain, Railway gives you a CNAME record
3. Add the CNAME in your DNS provider (propagates in minutes)

---

## Redeploying after a GitHub push

Railway automatically redeploys when you push to `main`.
Or trigger manually: **Railway dashboard → Deployments → Redeploy**.

---

## Environment variable reference

| Key | Default | Description |
|---|---|---|
| `SECRET_KEY` | (none) | Flask session signing key — **required** |
| `FLASK_ENV` | `development` | Set to `production` on Railway |
| `DATABASE_URL` | (none) | PostgreSQL URL — auto-set if you add a Railway Postgres plugin |
| `DATA_DIR` | (project root) | Directory for JSON data files (set to `/data` with a volume) |
| `GEMINI_API_KEY` | (none) | Google Gemini API key for AI menu extraction from images |
| `PORT` | `5000` | Injected by Railway automatically — do not set manually |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Build fails | Check logs — usually a missing system package or pip dependency |
| App starts but crashes | Ensure `SECRET_KEY` is set in Variables |
| Orders lost on redeploy | Add a PostgreSQL plugin or mount a volume at `/data` |
| 502 / Bad Gateway | Health check failed — check app logs for startup errors |
| CSRF errors on forms | Make sure `FLASK_ENV=production` and `SECRET_KEY` are set |
| SSE stream drops | Normal on free tier (60s timeout) — the dashboard auto-reconnects |
