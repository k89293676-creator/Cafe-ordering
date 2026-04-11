# Cafe Ordering System

A web-based cafe ordering system built with Python and Flask.

## Overview

Customers can browse the cafe menu and place orders from their table (via QR codes) or online. The app includes an Owner Portal for managing menus, tracking orders, and generating table-specific QR codes.

## Tech Stack

- **Backend:** Python 3.12 with Flask
- **Frontend:** HTML, CSS, Vanilla JavaScript with Jinja2 templating
- **Database:** Flat JSON files (menu.json, orders.json, owners.json, tables.json)
- **Auth:** Session-based with Werkzeug password hashing
- **QR Codes:** `qrcode[pil]` library

## Project Layout

```
app.py              # Main Flask application with all routes
requirements.txt    # Python dependencies
menu.json           # Menu data (categories and items)
orders.json         # Order records
owners.json         # Owner account credentials (hashed)
tables.json         # Table metadata
static/
  css/styles.css    # Main stylesheet
  js/app.js         # Cart and checkout logic
  js/table.js       # Table-specific ordering logic
templates/
  index.html        # Landing/ordering page
  table_order.html  # Table-specific ordering page
  owner_login.html  # Owner login
  owner_signup.html # Owner signup (only when no owners exist)
  owner_dashboard.html # Owner management console
```

## Environment Variables

- `SECRET_KEY` — Flask session secret key (required, set as env var)
- `PORT` — Port to run the server on (default: 5000)
- `FLASK_ENV` — Set to "development" to enable Flask debug mode

## Running the App

```bash
python app.py
```

The app runs on `0.0.0.0:5000` (all interfaces).

## Deployment

Configured for `vm` deployment target using gunicorn:
```
gunicorn --bind=0.0.0.0:5000 --reuse-port app:app
```

Uses `vm` (always-running) because data is stored in local JSON files that require persistent state.

## Key Features

- Menu browsing with categories and item tags
- Cart and checkout for online orders
- Table-based ordering via QR codes
- Owner portal with:
  - Menu management (add/edit/delete categories and items)
  - Table management and QR code generation
  - Order tracking (pending/completed)
  - Menu import/export via JSON
