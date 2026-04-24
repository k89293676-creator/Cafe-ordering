# Disaster Recovery Runbook

This document is the single source of truth for "the production
database is gone — what do I do?" Print it, link it from your on-call
rotation, and review it every quarter so the steps still match
reality.

## Recovery objectives

| Objective | Target | How we hit it |
| --- | --- | --- |
| **RPO** (max data loss tolerated) | 24 hours | Daily encrypted backup via `scripts/backup_db.sh`. Set ≤ 5 min by attaching Railway's Postgres PITR add-on. |
| **RTO** (max downtime) | 1 hour | Restore from latest backup directly to a new Railway Postgres instance, then point `DATABASE_URL` at it. |

## Backup inventory

| Backup | Frequency | Retention | Stored where |
| --- | --- | --- | --- |
| `scripts/backup_db.sh` (encrypted custom-format dump) | Daily 02:00 UTC | 14 days local + indefinite on the upload URL | `BACKUP_UPLOAD_URL` (S3-compatible) |
| Railway Postgres snapshots (managed) | Hourly | 7 days (Hobby), 30 days (Pro) | Railway-managed |
| Railway PITR (optional add-on) | Continuous WAL | 7 days | Railway-managed |

If only one of these exists, the answer is "make the other one exist
this week."

## Required environment for restoring

```
DATABASE_URL=postgres://USER:PASS@HOST:PORT/DB     # the NEW instance
BACKUP_GPG_PASSPHRASE=...                          # same value used during backup
BACKUP_UPLOAD_URL=https://...                      # S3-compatible source of the file
BACKUP_UPLOAD_AUTH_HEADER="Authorization: Bearer ..."  # if private bucket
```

`BACKUP_GPG_PASSPHRASE` lives in your password manager — **not** in
Railway env vars (because if you've lost Railway, you've lost those
too). If the passphrase is gone, the encrypted dumps are useless.

## Restore procedure (under 30 minutes)

1. **Triage.** Confirm the database is actually unrecoverable. Check
   Railway's status page; check `pg_isready` against `DATABASE_URL`.
   90% of "outages" are network blips that resolve in five minutes.

2. **Provision a fresh Postgres.** In Railway: create a new Postgres
   service in the same project. Copy the new `DATABASE_URL`.

3. **Pull the latest dump.**

   ```bash
   curl -fL -H "${BACKUP_UPLOAD_AUTH_HEADER}" \
        "${BACKUP_UPLOAD_URL%/}/cafe_LATEST.dump.gpg" \
        -o cafe_restore.dump.gpg
   ```

4. **Decrypt.**

   ```bash
   gpg --batch --pinentry-mode loopback \
       --passphrase "${BACKUP_GPG_PASSPHRASE}" \
       --decrypt cafe_restore.dump.gpg > cafe_restore.dump
   ```

5. **Restore.**

   ```bash
   pg_restore --no-owner --no-privileges --clean --if-exists \
              --dbname="${DATABASE_URL}" cafe_restore.dump
   ```

   `--clean --if-exists` drops anything in the target before recreating
   it, so this is safe to re-run if it crashes mid-way.

6. **Validate.** Run the application's read-only health checks against
   the new database **before** flipping any traffic:

   ```bash
   psql "${DATABASE_URL}" -c "SELECT count(*) FROM owners;"
   psql "${DATABASE_URL}" -c "SELECT count(*) FROM orders;"
   psql "${DATABASE_URL}" -c "SELECT max(created_at) FROM orders;"
   ```

   The `max(created_at)` value tells you exactly how much data was
   lost (RPO actual).

7. **Cut over.** Update `DATABASE_URL` on the application service in
   Railway. Redeploy. The post-deploy GitHub Actions workflow will
   verify `/healthz` + `/readyz` + per-section health automatically.

8. **Post-mortem.** File a written incident report within 24 hours
   covering: trigger, RPO actual, RTO actual, customer-visible
   impact, what we'll change. Drop it in `docs/incidents/`.

## Pre-incident checklist (do this monthly)

- [ ] Run `scripts/backup_db.sh` manually and confirm the file appears
      in object storage.
- [ ] Pick a recent dump and run steps 4–6 against a throw-away
      database (Railway lets you spin one up for free). Time it. If
      it took longer than your RTO target, the dump is too big and
      you need PITR.
- [ ] Confirm `BACKUP_GPG_PASSPHRASE` is in two password managers
      (yours + a co-founder's). One is a single point of failure.
- [ ] Rotate the passphrase yearly. Old encrypted dumps stay readable
      with the old passphrase — keep the previous one archived.

## Known limitations

- **Object storage credentials.** If the same vendor hosts both the
  app and the backup bucket and they disappear together (rare but
  possible), the backup is useless. Consider mirroring to a
  second-vendor bucket weekly.
- **Schema drift.** A backup taken before a destructive migration
  cannot be restored after the migration without manual fix-up. If
  you ship a `db/migrations/` change that drops a column, take a
  manual backup *immediately before* the deploy.
