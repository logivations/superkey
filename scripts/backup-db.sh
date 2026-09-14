#!/bin/bash
#
# Daily SQLite backup of the Superkey database ON THE SUPERKEY HOST.
#
# Uses SQLite's online backup API via the running app container (the host has
# no sqlite3 CLI), so the copy is consistent even while the app is writing.
# Keeps the last $KEEP_DAYS daily snapshots in $BACKUP_DIR.
#
# --install: idempotently install a root cron entry running this daily at 03:15.
#            Called from auto-update.sh so the cron self-installs.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONTAINER="${SUPERKEY_CONTAINER:-superkey-superkey-1}"
BACKUP_DIR="${SUPERKEY_BACKUP_DIR:-$PROJECT_DIR/data/backups}"
KEEP_DAYS="${SUPERKEY_BACKUP_KEEP_DAYS:-30}"
CRON_FILE="/etc/cron.d/superkey-backup"

if [ "${1:-}" = "--install" ]; then
    [ "$(id -u)" -eq 0 ] || { echo "Run as root to install cron"; exit 1; }
    LINE="15 3 * * * root $SCRIPT_DIR/backup-db.sh >> $PROJECT_DIR/backup.log 2>&1"
    if [ ! -f "$CRON_FILE" ] || ! grep -qF "$LINE" "$CRON_FILE"; then
        printf '# Daily Superkey DB backup (installed by scripts/backup-db.sh --install)\n%s\n' "$LINE" > "$CRON_FILE"
        chmod 644 "$CRON_FILE"
        echo "Installed $CRON_FILE"
    fi
    exit 0
fi

mkdir -p "$BACKUP_DIR"
STAMP="$(date +%Y%m%d-%H%M%S)"
TMP="/data/backups/.superkey-$STAMP.db.tmp"   # path inside the container (data/ is bind-mounted at /data)
OUT="$BACKUP_DIR/superkey-$STAMP.db"

docker exec "$CONTAINER" node -e "
  const D = require('better-sqlite3');
  new D('/data/superkey.db', { readonly: true }).backup('$TMP').then(() => process.exit(0), e => { console.error(e); process.exit(1); });
"
mv "$BACKUP_DIR/.superkey-$STAMP.db.tmp" "$OUT"
gzip -f "$OUT"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backup written: $OUT.gz ($(du -h "$OUT.gz" | cut -f1))"

find "$BACKUP_DIR" -name 'superkey-*.db.gz' -mtime +"$KEEP_DAYS" -print -delete | sed 's/^/  pruned: /'
