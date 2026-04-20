# Cafe Ordering System

A web-based cafe ordering system built with Python and Flask.

## Overview

Customers can browse the cafe menu and place orders from their table via QR codes or online. The app includes an Owner Portal for managing menus, tracking orders, importing menus, and generating table-specific QR codes.

## Tech Stack

- **Backend:** Python 3.12 with Flask
- **Frontend:** HTML, CSS, Vanilla JavaScript with Jinja2 templating
- **Primary storage:** JSON files with portalocker-backed atomic reads/writes
- **Optional storage:** PostgreSQL when `DATABASE_URL` is set
- **Auth:** Session-based with Werkzeug password hashing and CSRF protection
- **Deployment:** Railway-ready Gunicorn + gevent configuration
- **Security:** Flask-WTF CSRF, Flask-Talisman security headers in production, upload validation, rate limiting, compressed responses

## Project Layout

```
app.py                 # Main Flask application with all routes and data access
migrate_json_to_db.py  # Imports JSON data into PostgreSQL when DATABASE_URL is set
requirements.txt       # Python dependencies
railway.json           # Railway build and deployment configuration
Procfile               # Gunicorn process command
.env.example           # Required and optional environment variables
menu.json              # Menu data fallback
orders.json            # Order records fallback
owners.json            # Owner account storage fallback
tables.json            # Table metadata fallback
static/                # CSS and JavaScript
templates/             # Jinja2 templates
```

## Environment Variables

- `SECRET_KEY` — Flask session secret key; required in production
- `IS_PRODUCTION` — set to `true` to enable production-only safeguards
- `PORT` — port provided by the host
- `FLASK_ENV` — set to `production` or `development`
- `DATA_DIR` — optional directory for JSON fallback files
- `DATABASE_URL` — optional PostgreSQL connection string
- `REDIS_URL` — optional Redis backend for rate limiting
- `GEMINI_API_KEY` — optional AI image menu extraction key
- `LOG_FILE` — optional production JSON log file path

## Running the App

```bash
python app.py
```

For production-like local testing:

```bash
gunicorn app:app --bind 0.0.0.0:$PORT --worker-class gevent --workers 1
```

## Deployment

Railway uses `railway.json` and `Procfile` to install dependencies, start Gunicorn, and health-check `/health`.

## Key Features

- Menu browsing with categories and item tags
- Cart and checkout for online and table orders
- Table-based ordering via QR codes
- Owner portal with menu, table, order, and profile management
- JSON fallback mode for local/free-tier development
- Optional PostgreSQL mode with JSON-to-database import script
- Production-grade file locking, atomic writes, cache invalidation, security headers, CSRF, logging, and rate limiting
