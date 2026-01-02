#!/bin/bash
# Auto-update script for Superkey
# Checks for new commits on main branch and redeploys if updates found
# Also pulls hostnames repo periodically

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="${PROJECT_DIR}/auto-update.log"
BRANCH="main"
HOSTNAMES_DIR="/home/logi/hostnames"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Update Superkey repo
cd "$PROJECT_DIR"

git fetch origin "$BRANCH" --quiet

LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse "origin/$BRANCH")

if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
    log "Superkey: No updates found (at commit ${LOCAL_COMMIT:0:7})"
else
    log "Superkey update detected: ${LOCAL_COMMIT:0:7} -> ${REMOTE_COMMIT:0:7}"

    log "Pulling latest changes..."
    git pull origin "$BRANCH"

    log "Rebuilding and restarting Docker container..."
    docker-compose down
    docker-compose build --no-cache
    docker-compose up -d

    log "Superkey update complete! Now running commit ${REMOTE_COMMIT:0:7}"
fi

# Update hostnames repo
if [ -d "$HOSTNAMES_DIR" ]; then
    cd "$HOSTNAMES_DIR"

    git fetch origin --quiet 2>/dev/null || {
        log "Hostnames: Failed to fetch"
        exit 0
    }

    HOSTNAMES_LOCAL=$(git rev-parse HEAD)
    HOSTNAMES_REMOTE=$(git rev-parse "origin/$(git rev-parse --abbrev-ref HEAD)")

    if [ "$HOSTNAMES_LOCAL" != "$HOSTNAMES_REMOTE" ]; then
        log "Hostnames update detected: ${HOSTNAMES_LOCAL:0:7} -> ${HOSTNAMES_REMOTE:0:7}"
        git pull --quiet
        log "Hostnames repo updated to ${HOSTNAMES_REMOTE:0:7}"
    else
        log "Hostnames: Up to date (at commit ${HOSTNAMES_LOCAL:0:7})"
    fi
else
    log "Warning: Hostnames directory not found at $HOSTNAMES_DIR"
fi
