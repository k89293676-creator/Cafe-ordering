#!/usr/bin/env python3
"""Helper script to commit and push changes to GitHub via git subprocess."""
import os
import subprocess
import sys

repo = "/home/runner/workspace/cafe-ordering-repo"
pat = os.environ.get("GITHUB_PAT", "")
if not pat:
    print("ERROR: GITHUB_PAT not set", file=sys.stderr)
    sys.exit(1)

remote = f"https://{pat}@github.com/k89293676-creator/Cafe-ordering.git"

def run(args, **kw):
    result = subprocess.run(args, cwd=repo, capture_output=True, text=True, **kw)
    if result.returncode != 0:
        print(f"FAIL: {' '.join(args)}", file=sys.stderr)
        print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return result.stdout.strip()

run(["git", "config", "user.email", "agent@replit.com"])
run(["git", "config", "user.name", "Replit Agent"])
run(["git", "add", "-A"])

msg = """fix+feat: bug fixes, images, prep time, popular badges, customer accounts

Bug fixes:
- Remove duplicate inline checkout handler (localStorage cart always empty)
- Pickup code displayed prominently in order tracker UI
- Dietary filter checks item.tags as fallback for dietary_tags
- Table calls drawer shows note field
- data-order-id on kanban order cards for employee assignment
- Employee assignment JS dropdown on active order cards
- placeOrder sends customerPhone and notes

New features:
- Menu items: image_url, prep_time, dietary_tags fields (save + edit forms)
- Popular badge auto-computed from last-30-day order counts
- Customer accounts: register/login/logout/orders (model + blueprint + templates)"""

run(["git", "commit", "-m", msg])
print("Committed OK")

run(["git", "remote", "set-url", "origin", remote])
run(["git", "push", "origin", "main"])
print("Pushed to origin/main OK")
