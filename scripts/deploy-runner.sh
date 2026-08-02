#!/bin/bash
#
# Superkey deploy runner — executed by superkey-deploy.timer on the
# superkey host (installed by setup-deploy-runner.sh).
#
# Polls the API for servers whose deployed keys differ from what superkey
# would deploy now, and runs deploy.sh --stale to bring only those up to
# date. With --full, deploys to every enrolled server (daily reconcile,
# catches out-of-band drift the hash can't see).
#
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"

# Pull only the keys we need out of .env (values may contain spaces, so
# sourcing the whole file is not safe).
env_get() {
    grep "^$1=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d= -f2-
}

export SUPERKEY_URL="${SUPERKEY_URL:-http://127.0.0.1:3000}"
export DEPLOY_SSH_KEY="${DEPLOY_SSH_KEY:-/root/superkey-deploy-key}"
export DEPLOY_API_TOKEN="${DEPLOY_API_TOKEN:-$(env_get DEPLOY_API_TOKEN)}"

if [ -z "$DEPLOY_API_TOKEN" ]; then
    echo "DEPLOY_API_TOKEN not set — run setup-deploy-runner.sh first"
    exit 1
fi
if [ ! -f "$DEPLOY_SSH_KEY" ]; then
    echo "Deploy key $DEPLOY_SSH_KEY not found — run setup-deploy-runner.sh first"
    exit 1
fi

MODE="--stale"
if [ "${1:-}" = "--full" ]; then
    MODE=""
fi

# One runner at a time (timer ticks can outpace a slow fleet-wide deploy).
exec 9>/run/superkey-deploy.lock
if ! flock -n 9; then
    echo "Another deploy is running; skipping."
    exit 0
fi

# Always exit 0: individual host failures (offline robots etc.) are normal
# and land in the journal; the timer should not flap into a failed state.
"$SCRIPT_DIR/deploy.sh" $MODE || echo "deploy.sh reported failures (see output above)"
exit 0
