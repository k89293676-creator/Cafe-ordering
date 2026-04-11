# Cafe Ordering System

A simple cafe ordering system built with Python and Flask.

## Features

- Browse a customizable cafe menu with coffee, tea, pastries, and sandwiches
- Owner portal with QR table management, menu editing, and order tracking
- Add items to a cart, update quantities, and preview totals
- Table-specific ordering pages generated from QR codes
- Searchable menu, JSON import/export, and category/item management
- Responsive browser UI with live cart summary

## Getting Started

1. Create and activate a Python virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the app:

   ```bash
   python app.py
   ```

4. Open your browser at `http://127.0.0.1:8000`

## Project Structure

- `app.py` - Flask backend with menu and checkout APIs
- `menu.json` - Cafe menu data
- `templates/index.html` - Single-page UI
- `static/css/styles.css` - UI styles
- `static/js/app.js` - Cart and checkout interactions
- `static/js/table.js` - Table-specific ordering behavior
- `owners.json` - Owner account storage
- `tables.json` - Table and QR code metadata
- `docs/` - Static GitHub Pages landing content
- `.github/workflows/pages.yml` - GitHub Pages deploy workflow
- `.gitignore` - Local excludes
## Owner Menu Management

Cafe owners can now update the menu directly from the owner dashboard using:
- a raw `menu.json` editor
- JSON file upload
- current menu download
## GitHub Pages

This repo includes a simple static landing page under `docs/index.html`. GitHub Pages can host that page, but it cannot host the Flask backend.

To make the app live:

1. Deploy the Flask app to a Python-capable host.
2. Use the deployed app URL and navigate to `/owner/signup`.
3. Use GitHub Pages only for a static landing page or redirect.

## Owner Portal

1. Open `http://127.0.0.1:8000/owner/signup` if you do not yet have an owner account.
2. Sign in at `http://127.0.0.1:8000/owner/login`.
3. Create tables in the dashboard to generate table-specific QR codes.
4. Place orders from any table QR page, then manage pending orders from the dashboard.

## Notes

- Orders are stored locally in `orders.json`
- The app is intended as a starting point for a cafe ordering workflow
