#!/usr/bin/env python3
"""Helper script to commit and push changes to GitHub via git subprocess.

Usage:
    python .push_changes.py "your commit message"
    python .push_changes.py            # uses a default message

Requires GITHUB_PAT in the environment (already provided as a Replit secret).
Run this from the Replit Shell tab — the agent cannot run git commands directly.
"""
import os
import subprocess
import sys

REPO = "/home/runner/workspace"
REPO_URL = "github.com/k89293676-creator/Cafe-ordering.git"

pat = os.environ.get("GITHUB_PAT", "")
if not pat:
    print("ERROR: GITHUB_PAT not set", file=sys.stderr)
    sys.exit(1)

remote_url = f"https://x-access-token:{pat}@{REPO_URL}"


def run(args, check=True, capture=True):
    result = subprocess.run(
        args, cwd=REPO, capture_output=capture, text=True
    )
    if check and result.returncode != 0:
        print(f"FAIL: {' '.join(args)}", file=sys.stderr)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return result


# Clear any stale lock files
for lock in (".git/config.lock", ".git/index.lock"):
    p = os.path.join(REPO, lock)
    if os.path.exists(p):
        try:
            os.remove(p)
        except OSError:
            pass

run(["git", "config", "user.email", "agent@replit.com"])
run(["git", "config", "user.name", "Replit Agent"])

# Ensure 'origin' points to GitHub repo with PAT
existing = run(["git", "remote"], check=False).stdout.split()
if "origin" in existing:
    run(["git", "remote", "set-url", "origin", remote_url])
else:
    run(["git", "remote", "add", "origin", remote_url])

run(["git", "add", "-A"])

# Stash any uncommitted changes so we can rebase cleanly on top of origin/main.
status = run(["git", "status", "--porcelain"]).stdout.strip()
stashed = False
if status:
    msg = sys.argv[1] if len(sys.argv) > 1 else "chore: automated update from Replit"
    # Commit locally first; rebasing a real commit is more reliable than stashing.
    run(["git", "commit", "-m", msg])
    print(f"Committed locally: {msg}")
else:
    print("Nothing new to commit; will sync and push current HEAD.")

# Fetch and rebase onto origin/main so we never get rejected for non-fast-forward.
run(["git", "fetch", "origin", "main"], check=False)
rebase = run(["git", "rebase", "origin/main"], check=False)
if rebase.returncode != 0:
    print("Rebase hit conflicts — aborting and falling back to a merge.", file=sys.stderr)
    run(["git", "rebase", "--abort"], check=False)
    merge = run(
        ["git", "-c", "user.email=agent@replit.com",
         "-c", "user.name=Replit Agent",
         "merge", "--no-edit", "--strategy-option=theirs", "origin/main"],
        check=False,
    )
    if merge.returncode != 0:
        print(merge.stderr, file=sys.stderr)
        print("\nCould not auto-merge with origin/main. Resolve conflicts in the Shell, then re-run.",
              file=sys.stderr)
        sys.exit(merge.returncode)

# Push current branch to main on GitHub
push = run(
    ["git", "push", "-u", "origin", "HEAD:main"],
    check=False,
)
if push.returncode != 0:
    print(push.stderr, file=sys.stderr)
    print("\nPush still rejected. As a last resort you can force-push from the Shell with:")
    print("  git push -f origin HEAD:main")
    sys.exit(push.returncode)

print("Pushed to origin/main OK")
