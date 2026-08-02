#!/bin/bash
#
# Migration to the machine deploy key.
#
# Historically every superkey admin's personal key was installed on the
# superkey-deploy user of each server. This script brings hosts onto the
# machine deploy key (fetched from the Superkey API):
#
#   default    ADD the machine key to superkey-deploy's authorized_keys,
#              keeping existing (admin) keys — safe, reversible first step.
#   --replace  replace authorized_keys with ONLY the machine key — final
#              cutover that removes admin access to superkey-deploy.
#
# Run from an admin machine whose key currently works for
# superkey-deploy@<host>.
#
# Usage:
#   ./scripts/migrate-deploy-key.sh host1 host2 ...
#   ./scripts/migrate-deploy-key.sh --from-file hosts.txt   # one hostname per line
#
set -u

SUPERKEY_URL="${SUPERKEY_URL:-https://superkey.ops.logivations.com}"
DEPLOY_USER="${DEPLOY_USER:-superkey-deploy}"
MAX_JOBS="${MAX_JOBS:-20}"
REPLACE=false

HOSTS=()
while [[ $# -gt 0 ]]; do
    case $1 in
        --from-file)
            while IFS= read -r line; do
                line="${line%%#*}"; line="$(echo "$line" | xargs)"
                [ -n "$line" ] && HOSTS+=("$line")
            done < "$2"
            shift 2
            ;;
        --superkey-url)
            SUPERKEY_URL="$2"; shift 2
            ;;
        --replace)
            REPLACE=true; shift
            ;;
        -*)
            echo "Unknown option: $1"; exit 1
            ;;
        *)
            HOSTS+=("$1"); shift
            ;;
    esac
done

if [ ${#HOSTS[@]} -eq 0 ]; then
    echo "Usage: $0 [--replace] [--superkey-url URL] <host>... | --from-file hosts.txt"
    exit 1
fi

echo "Fetching machine deploy key from ${SUPERKEY_URL}/api/deploy-key..."
KEY_DATA=$(curl -sfL "${SUPERKEY_URL}/api/deploy-key") || {
    echo "Error: could not fetch deploy key. Is the deploy runner set up on the superkey host?"
    exit 1
}
MACHINE_KEY=$(echo "$KEY_DATA" | jq -r '.public_key')
if [ -z "$MACHINE_KEY" ] || [ "$MACHINE_KEY" = "null" ]; then
    echo "Error: API returned no deploy key: $KEY_DATA"
    exit 1
fi
echo "Machine key: $(echo "$MACHINE_KEY" | awk '{print $1, substr($2,1,20) "...", $3}')"
if [ "$REPLACE" = true ]; then
    echo "Mode: REPLACE (authorized_keys becomes the machine key ONLY)"
else
    echo "Mode: add (machine key appended, existing keys kept)"
fi
echo ""

# The key data (type + base64) without the comment — comments may differ,
# presence is decided on the actual key material.
KEY_MATERIAL=$(echo "$MACHINE_KEY" | awk '{print $1, $2}')

migrate_host() {
    local HOST="$1"
    if [ "$REPLACE" = true ]; then
        ssh -o ConnectTimeout=8 -o BatchMode=yes "$DEPLOY_USER@$HOST" \
            "printf '%s\n' '$MACHINE_KEY' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'replaced'"
    else
        ssh -o ConnectTimeout=8 -o BatchMode=yes "$DEPLOY_USER@$HOST" \
            "if grep -qF '$KEY_MATERIAL' ~/.ssh/authorized_keys 2>/dev/null; then echo 'already present'; else printf '%s\n' '$MACHINE_KEY' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo 'added'; fi"
    fi
}

STATUS_DIR=$(mktemp -d)
trap 'rm -rf "$STATUS_DIR"' EXIT

wait_for_slot() {
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_JOBS" ]; do
        wait -n 2>/dev/null || true
    done
}

for HOST in "${HOSTS[@]}"; do
    wait_for_slot
    (
        if OUT=$(migrate_host "$HOST" 2>/dev/null); then
            echo "OK $OUT" > "$STATUS_DIR/$HOST"
        else
            echo "FAILED" > "$STATUS_DIR/$HOST"
        fi
    ) &
done
wait

OK=0
FAILED=()
for HOST in "${HOSTS[@]}"; do
    RESULT=$(cat "$STATUS_DIR/$HOST" 2>/dev/null || echo "FAILED")
    printf '%-40s %s\n' "$HOST" "$RESULT"
    if [ "$RESULT" = "FAILED" ]; then
        FAILED+=("$HOST")
    else
        OK=$((OK+1))
    fi
done

echo ""
echo "Done: $OK ok, ${#FAILED[@]} failed."
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "Failed hosts (no access or connection error):"
    printf '  %s\n' "${FAILED[@]}"
    exit 1
fi
