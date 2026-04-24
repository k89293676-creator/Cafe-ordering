#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Encrypted PostgreSQL backup with optional S3-compatible upload.
#
# Designed for two deployment shapes:
#
#   1. Railway "scheduled job" service running this script daily.
#   2. GitHub Actions cron (.github/workflows/backup-db.yml) for
#      operators who don't want a 24/7 backup container.
#
# What it does:
#   * Runs pg_dump against $DATABASE_URL (custom format = -Fc, allows
#     selective restore of individual tables via pg_restore -t).
#   * Encrypts with gpg using $BACKUP_GPG_PASSPHRASE (symmetric AES-256).
#     Encryption is REQUIRED — the script refuses to run without it
#     because storing customer PII in plaintext on object storage is
#     a regulatory landmine.
#   * Uploads to ${BACKUP_UPLOAD_URL} (S3-compatible PUT URL) when set,
#     otherwise leaves the file in ${BACKUP_DIR:-./backups} for
#     out-of-band collection.
#   * Keeps the last $BACKUP_RETENTION_DAYS local files (default 14).
#
# What it does NOT do:
#   * Continuous WAL archiving (use Railway's PITR add-on or a managed
#     Postgres provider — see scripts/disaster_recovery.md for the
#     full picture).
#
# Exit codes:
#   0  success
#   1  config/validation error
#   2  pg_dump failed
#   3  encryption failed
#   4  upload failed
# ---------------------------------------------------------------------------

set -euo pipefail

# ---- Config ---------------------------------------------------------------

: "${DATABASE_URL:?DATABASE_URL is required}"
: "${BACKUP_GPG_PASSPHRASE:?BACKUP_GPG_PASSPHRASE is required (32+ random chars)}"

BACKUP_DIR="${BACKUP_DIR:-./backups}"
BACKUP_RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
BACKUP_UPLOAD_URL="${BACKUP_UPLOAD_URL:-}"
BACKUP_UPLOAD_AUTH_HEADER="${BACKUP_UPLOAD_AUTH_HEADER:-}"
BACKUP_LABEL="${BACKUP_LABEL:-cafe}"

mkdir -p "${BACKUP_DIR}"

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
basename_="${BACKUP_LABEL}_${stamp}"
dump_path="${BACKUP_DIR}/${basename_}.dump"
enc_path="${dump_path}.gpg"

# ---- Pre-flight -----------------------------------------------------------

for bin in pg_dump gpg; do
  if ! command -v "${bin}" >/dev/null 2>&1; then
    echo "ERROR: ${bin} not found in PATH" >&2
    exit 1
  fi
done

if [[ "${#BACKUP_GPG_PASSPHRASE}" -lt 16 ]]; then
  echo "ERROR: BACKUP_GPG_PASSPHRASE must be at least 16 chars" >&2
  exit 1
fi

# ---- Dump -----------------------------------------------------------------

echo "[$(date -u +%FT%TZ)] pg_dump → ${dump_path}"
if ! pg_dump --format=custom --compress=9 --no-owner --no-privileges \
    --file="${dump_path}" "${DATABASE_URL}"; then
  echo "ERROR: pg_dump failed" >&2
  exit 2
fi
dump_size_bytes=$(stat -c%s "${dump_path}" 2>/dev/null || stat -f%z "${dump_path}")
echo "[$(date -u +%FT%TZ)] dump complete (${dump_size_bytes} bytes)"

# ---- Encrypt --------------------------------------------------------------

echo "[$(date -u +%FT%TZ)] encrypt → ${enc_path}"
# --batch + --yes + passphrase via fd 0 keeps the secret off argv
if ! gpg --batch --yes --pinentry-mode loopback \
       --symmetric --cipher-algo AES256 --s2k-mode 3 --s2k-count 65011712 \
       --passphrase-fd 0 -o "${enc_path}" "${dump_path}" \
       <<<"${BACKUP_GPG_PASSPHRASE}"; then
  echo "ERROR: gpg encryption failed" >&2
  exit 3
fi
# Shred the plaintext on disk — even on a tmpfs we don't want a
# crashed process leaving readable PII behind.
rm -f -- "${dump_path}"

enc_size_bytes=$(stat -c%s "${enc_path}" 2>/dev/null || stat -f%z "${enc_path}")
echo "[$(date -u +%FT%TZ)] encrypted (${enc_size_bytes} bytes)"

# ---- Upload (optional) ----------------------------------------------------

if [[ -n "${BACKUP_UPLOAD_URL}" ]]; then
  echo "[$(date -u +%FT%TZ)] uploading to ${BACKUP_UPLOAD_URL}"
  curl_args=(--silent --show-error --fail --max-time 600
             --upload-file "${enc_path}"
             "${BACKUP_UPLOAD_URL%/}/${basename_}.dump.gpg")
  if [[ -n "${BACKUP_UPLOAD_AUTH_HEADER}" ]]; then
    curl_args=(-H "${BACKUP_UPLOAD_AUTH_HEADER}" "${curl_args[@]}")
  fi
  if ! curl "${curl_args[@]}"; then
    echo "ERROR: upload failed" >&2
    exit 4
  fi
  echo "[$(date -u +%FT%TZ)] upload complete"
fi

# ---- Local retention -----------------------------------------------------

echo "[$(date -u +%FT%TZ)] pruning local backups older than ${BACKUP_RETENTION_DAYS} days"
find "${BACKUP_DIR}" -maxdepth 1 -name "${BACKUP_LABEL}_*.dump.gpg" \
     -type f -mtime "+${BACKUP_RETENTION_DAYS}" -print -delete || true

echo "[$(date -u +%FT%TZ)] backup OK (${enc_path})"
