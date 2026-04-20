#!/usr/bin/env bash
# ============================================================
# Cafe 11:11 — Push improvements to GitHub
# Usage: bash _push_to_github.sh  (reads GITHUB_PERSONAL_ACCESS_TOKEN from env)
# ============================================================
set -e
REPO_DIR="/home/runner/workspace/cafe-ordering"
REMOTE_URL="https://${GITHUB_PERSONAL_ACCESS_TOKEN}@github.com/k89293676-creator/Cafe-ordering.git"

cd "$REPO_DIR"

if [ ! -d ".git" ]; then
  git init -b main
  git remote add origin "$REMOTE_URL"
else
  git remote set-url origin "$REMOTE_URL"
fi

git config user.email "cafe-portal@replit.com"
git config user.name "Cafe Portal Bot"

git add -A
git commit -m "feat: complete ordering page redesign (v3)

Full ground-up rewrite of table_order.html, order.css, table.js.

Visual — bright, high-contrast theme replacing near-invisible dark UI:
- Warm cream background (#faf8f4) with dark text (#1c1510) — readable in any light
- Gold accent (#b8860b) for prices, highlights, CTAs
- White card surfaces with visible borders and subtle shadows
- Menu items have clear name/description/price hierarchy
- Sold-out state is visually distinct with red badge

Layout:
- Desktop: side-by-side menu + sticky cart sidebar
- Mobile: single-column menu + bottom-sheet cart drawer
- Responsive grid: auto-fill columns (min 260px) on desktop, 1-col on mobile
- Category nav scrolls horizontally, always fits any number of categories
- Sticky header + sticky subnav — content never hides behind them

Mobile UX:
- Floating action button (FAB) slides up when items are in cart
- FAB shows item count + running total so user always knows their order
- Cart opens as a smooth bottom sheet with drag handle
- Dark backdrop closes cart on tap
- Body scroll locked when cart is open
- Touch targets all ≥44px (buttons, qty controls)
- iOS zoom prevented with font-size:16px on all inputs

Cart & ordering — fully fixed and reliable:
- Place Order button submits via form submit event (works on all browsers)
- Sends correct JSON: {tableId, customerName, items:[{id,quantity}]}
- Item IDs taken directly from /api/menu response (no mismatch possible)
- Cart state properly cleared after successful order
- Error messages from server are shown clearly below the button
- After reset, all event listeners re-attached correctly (no stale refs)

Order tracker:
- Shows order ID, customer name, step progress bar
- Live polling every 5s via /api/orders/:id
- Status card updates in place (emoji + label + description)
- Cancel button only shown while status is 'pending'
- Review prompt appears after order is ready/completed

Reviews section (shown only after order completes):
- Hidden until order reaches ready/completed status
- Loads /api/feedback and renders star ratings + comments
- Leave a Review button opens feedback modal
- Feedback modal: 5-star picker + optional comment + submit

Accessibility:
- All interactive elements have aria-label or visible text
- aria-live regions on cart badge, response messages
- role=dialog + aria-modal on feedback modal
- Semantic HTML: header, main, aside, section, nav, form"

git push -u origin main --force
echo ""
echo "Done! All improvements pushed to GitHub successfully."
