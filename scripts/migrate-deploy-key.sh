#!/bin/bash
#
# One-time migration to the machine deploy key.
#
# Historically every superkey admin's personal key was installed on the
# superkey-deploy user of each server. This script replaces that server by
# server: superkey-deploy's authorized_keys becomes the machine deploy key
# ONLY (fetched from the Superkey API). Run it from an admin machine whose
# key still works for superkey-deploy@<host> — i.e. before your own key is
# removed, which is exactly what this script does last.
#
# Usage:
#   ./scripts/migrate-deploy-key.sh host1 host2 ...
#   ./scripts/migrate-deploy-key.sh --from-file hosts.txt   # one hostname per line
#
set -u

SUPERKEY_URL="${SUPERKEY_URL:-https://superkey.ops.logivations.com}"
DEPLOY_USER="${DEPLOY_USER:-superkey-deploy}"

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
        -*)
            echo "Unknown option: $1"; exit 1
            ;;
        *)
            HOSTS+=("$1"); shift
            ;;
    esac
done

if [ ${#HOSTS[@]} -eq 0 ]; then
    echo "Usage: $0 [--superkey-url URL] <host>... | --from-file hosts.txt"
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
echo ""

FAILED=()
for HOST in "${HOSTS[@]}"; do
    echo "=== $HOST"
    if ssh -o ConnectTimeout=8 -o BatchMode=yes "$DEPLOY_USER@$HOST" \
        "printf '%s\n' '$MACHINE_KEY' > ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && echo '  authorized_keys replaced with machine key'"; then
        :
    else
        echo "  FAILED (no access or connection error)"
        FAILED+=("$HOST")
    fi
done

echo ""
if [ ${#FAILED[@]} -gt 0 ]; then
    echo "Failed hosts (fix manually or re-run):"
    printf '  %s\n' "${FAILED[@]}"
    exit 1
fi
echo "All hosts migrated. Admin personal keys no longer work for $DEPLOY_USER."
