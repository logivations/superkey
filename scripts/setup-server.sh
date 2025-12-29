#!/bin/bash
#
# Superkey Server Setup Script
#
# Run this once on each server to set up the superkey-deploy user.
# Fetches public keys from all superkey_admins group members and adds them
# to the deploy user's authorized_keys.
#
# Usage: ./setup-server.sh <server-hostname> [--superkey-url URL]
#
# Example:
#   ./setup-server.sh muc-amr.cs
#   ./setup-server.sh muc-amr.cs --superkey-url http://superkey.internal:3000
#

set -e

SUPERKEY_URL="${SUPERKEY_URL:-http://localhost:3000}"
SERVER=""
DEPLOY_USER="superkey-deploy"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --superkey-url)
            SUPERKEY_URL="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Usage: $0 <server-hostname> [--superkey-url URL]"
            exit 1
            ;;
        *)
            SERVER="$1"
            shift
            ;;
    esac
done

if [ -z "$SERVER" ]; then
    echo "Superkey Server Setup Script"
    echo ""
    echo "Usage: $0 <server-hostname> [--superkey-url URL]"
    echo ""
    echo "This script sets up the superkey-deploy user on a target server and adds"
    echo "SSH public keys from all members of the superkey_admins group."
    echo ""
    echo "Options:"
    echo "  --superkey-url URL    Superkey API URL (default: \$SUPERKEY_URL or http://localhost:3000)"
    echo ""
    echo "Examples:"
    echo "  $0 muc-amr.cs"
    echo "  $0 muc-amr.cs --superkey-url http://superkey.internal:3000"
    echo "  SUPERKEY_URL=http://superkey:3000 $0 muc-amr.cs"
    exit 1
fi

echo "Superkey Server Setup Script"
echo "============================"
echo ""
echo "Server:      $SERVER"
echo "Superkey:    $SUPERKEY_URL"
echo "Deploy user: $DEPLOY_USER"
echo ""

# Fetch admin public keys from Superkey API
echo "Fetching admin public keys from Superkey API..."
ADMIN_DATA=$(curl -sf "${SUPERKEY_URL}/api/admin-keys" 2>/dev/null) || {
    echo "Error: Could not connect to Superkey API at ${SUPERKEY_URL}"
    echo "Make sure Superkey is running and accessible."
    exit 1
}

# Check for errors
if echo "$ADMIN_DATA" | jq -e '.error' &>/dev/null; then
    echo "Error: $(echo "$ADMIN_DATA" | jq -r '.error')"
    exit 1
fi

# Get users and their public keys
KEY_COUNT=$(echo "$ADMIN_DATA" | jq '.users | length')

if [ "$KEY_COUNT" -eq 0 ]; then
    echo ""
    echo "Error: No admin users have public keys configured"
    echo "At least one superkey_admins member must have uploaded their SSH public key."
    exit 1
fi

echo "Found $KEY_COUNT admin(s) with public keys:"
echo "$ADMIN_DATA" | jq -r '.users[] | "  - \(.email)"'

# Collect all public keys
PUBLIC_KEYS=$(echo "$ADMIN_DATA" | jq -r '.users[].public_key')

echo ""

# Prompt for sudo password
echo -n "Enter sudo password for $SERVER: "
read -rs SUDO_PASS
echo ""

if [ -z "$SUDO_PASS" ]; then
    echo "Error: Sudo password required"
    exit 1
fi

# Escape single quotes in password for safe embedding
SUDO_PASS_ESCAPED=$(printf '%s' "$SUDO_PASS" | sed "s/'/'\\\\''/g")

# Create a temporary file with all public keys (one per line, no empty lines)
KEYS_CONTENT=$(echo "$PUBLIC_KEYS" | grep -v '^$' | sort -u)

echo ""
echo "Setting up $DEPLOY_USER on $SERVER..."

# Run setup on remote server
ssh "$SERVER" bash << REMOTE_EOF
set -e

DEPLOY_USER='$DEPLOY_USER'
SUDO_PASS='$SUDO_PASS_ESCAPED'

echo "Creating user \$DEPLOY_USER..."
if ! id "\$DEPLOY_USER" &>/dev/null; then
    echo "\$SUDO_PASS" | sudo -S useradd -m -s /bin/bash -c "Superkey Deploy User" "\$DEPLOY_USER" 2>&1 | grep -v "^\[sudo\]" || true
    echo "  User created"
else
    echo "  User already exists"
fi

echo "Setting up SSH keys..."
DEPLOY_HOME=\$(getent passwd "\$DEPLOY_USER" | cut -d: -f6)
SSH_DIR="\$DEPLOY_HOME/.ssh"
AUTH_KEYS="\$SSH_DIR/authorized_keys"

echo "\$SUDO_PASS" | sudo -S mkdir -p "\$SSH_DIR" 2>&1 | grep -v "^\[sudo\]" || true
echo "\$SUDO_PASS" | sudo -S chmod 700 "\$SSH_DIR" 2>&1 | grep -v "^\[sudo\]" || true

# Write all admin public keys (replace existing to ensure clean state)
echo "\$SUDO_PASS" | sudo -S bash -c "cat > '\$AUTH_KEYS'" << 'KEYS_EOF'
$KEYS_CONTENT
KEYS_EOF

echo "\$SUDO_PASS" | sudo -S chmod 600 "\$AUTH_KEYS" 2>&1 | grep -v "^\[sudo\]" || true
echo "\$SUDO_PASS" | sudo -S chown -R "\$DEPLOY_USER:\$DEPLOY_USER" "\$SSH_DIR" 2>&1 | grep -v "^\[sudo\]" || true

KEY_COUNT=\$(echo "\$SUDO_PASS" | sudo -S wc -l < "\$AUTH_KEYS" 2>/dev/null | tr -d ' ')
echo "  Added \$KEY_COUNT key(s) to authorized_keys"

echo "Configuring passwordless sudo..."
SUDOERS_FILE="/etc/sudoers.d/\$DEPLOY_USER"

# Remove old sudoers file if exists (might be corrupted)
echo "\$SUDO_PASS" | sudo -S rm -f "\$SUDOERS_FILE" 2>&1 | grep -v "^\[sudo\]" || true

# Create new sudoers file (allow all commands - simpler and works across distros)
SUDOERS_LINE="\$DEPLOY_USER ALL=(ALL) NOPASSWD: ALL"
echo "\$SUDO_PASS" | sudo -S bash -c "echo '\$SUDOERS_LINE' > '\$SUDOERS_FILE'" 2>&1 | grep -v "^\[sudo\]" || true
echo "\$SUDO_PASS" | sudo -S chmod 440 "\$SUDOERS_FILE" 2>&1 | grep -v "^\[sudo\]" || true

# Validate sudoers syntax
if echo "\$SUDO_PASS" | sudo -S visudo -c -f "\$SUDOERS_FILE" 2>&1 | grep -q "parsed OK"; then
    echo "  Sudoers configured OK"
else
    echo "  ERROR: Invalid sudoers syntax!"
    echo "\$SUDO_PASS" | sudo -S rm -f "\$SUDOERS_FILE" 2>&1 | grep -v "^\[sudo\]" || true
    exit 1
fi

echo ""
echo "Setup complete for \$DEPLOY_USER on \$(hostname)"
REMOTE_EOF

echo ""
echo "Done! Testing connection as $DEPLOY_USER..."
if ssh -o BatchMode=yes -o ConnectTimeout=5 "$DEPLOY_USER@$SERVER" "echo 'SSH OK' && sudo -n true && echo 'Sudo OK'" 2>/dev/null; then
    echo ""
    echo "SUCCESS: $SERVER is ready for deployment"
    echo ""
    echo "All superkey_admins members with public keys can now SSH as $DEPLOY_USER"
else
    echo ""
    echo "WARNING: Could not verify $DEPLOY_USER access"
    echo "Make sure your SSH key is in your agent: ssh-add ~/.ssh/id_rsa"
fi
