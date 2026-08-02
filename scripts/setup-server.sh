#!/bin/bash
#
# Superkey Server Setup Script
#
# Run this once on each server to set up the superkey-deploy user.
# Installs the superkey MACHINE deploy key (fetched from the Superkey API)
# as the only authorized key of the deploy user — deploys then run
# automatically from the superkey host. Admin personal keys are NOT
# installed; admins reach servers through their own provisioned accounts.
#
# Usage: ./setup-server.sh <server-hostname> [--superkey-url URL] [--ssh-user USER]
#
# Example:
#   ./setup-server.sh muc-amr.cs
#   ./setup-server.sh fleetbot --ssh-user root
#

set -e

SUPERKEY_URL="${SUPERKEY_URL:-https://superkey.ops.logivations.com}"
SERVER=""
DEPLOY_USER="superkey-deploy"
SSH_USER=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --superkey-url)
            SUPERKEY_URL="$2"
            shift 2
            ;;
        --ssh-user)
            SSH_USER="$2"
            shift 2
            ;;
        -*)
            echo "Unknown option: $1"
            echo "Usage: $0 <server-hostname> [--superkey-url URL] [--ssh-user USER]"
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
    echo "Usage: $0 <server-hostname> [--superkey-url URL] [--ssh-user USER]"
    echo ""
    echo "Sets up the superkey-deploy user on a target server with the superkey"
    echo "machine deploy key. After this, the superkey host deploys user access"
    echo "to the server automatically."
    echo ""
    echo "Options:"
    echo "  --superkey-url URL    Superkey API URL (default: \$SUPERKEY_URL or https://superkey.ops.logivations.com)"
    echo "  --ssh-user USER       SSH as USER on the target (default: current user). Use 'root' for fresh servers."
    echo ""
    echo "Examples:"
    echo "  $0 muc-amr.cs"
    echo "  $0 fleetbot --ssh-user root"
    exit 1
fi

SSH_TARGET="${SSH_USER:+$SSH_USER@}$SERVER"

echo "Superkey Server Setup Script"
echo "============================"
echo ""
echo "Server:      $SERVER"
echo "Superkey:    $SUPERKEY_URL"
echo "Deploy user: $DEPLOY_USER"
echo ""

# Fetch the machine deploy public key from the Superkey API
echo "Fetching machine deploy key from Superkey API..."
KEY_DATA=$(curl -sfL "${SUPERKEY_URL}/api/deploy-key" 2>/dev/null) || {
    echo "Error: Could not fetch the deploy key from ${SUPERKEY_URL}/api/deploy-key"
    echo "Make sure Superkey is running and the deploy runner is set up"
    echo "(scripts/setup-deploy-runner.sh on the superkey host)."
    exit 1
}

if echo "$KEY_DATA" | jq -e '.error' &>/dev/null; then
    echo "Error: $(echo "$KEY_DATA" | jq -r '.error')"
    exit 1
fi

KEYS_CONTENT=$(echo "$KEY_DATA" | jq -r '.public_key')
if [ -z "$KEYS_CONTENT" ] || [ "$KEYS_CONTENT" = "null" ]; then
    echo "Error: API returned no deploy key"
    exit 1
fi

echo "Deploy key: $(echo "$KEYS_CONTENT" | awk '{print $1, substr($2, 1, 20) "...", $3}')"
echo ""

# Prompt for sudo password (not needed when SSHing as root)
if [ "$SSH_USER" = "root" ]; then
    SUDO_PASS=""
else
    echo -n "Enter sudo password for $SSH_TARGET: "
    read -rs SUDO_PASS
    echo ""

    if [ -z "$SUDO_PASS" ]; then
        echo "Error: Sudo password required"
        exit 1
    fi
fi

# Escape single quotes in password for safe embedding
SUDO_PASS_ESCAPED=$(printf '%s' "$SUDO_PASS" | sed "s/'/'\\\\''/g")

echo ""
echo "Setting up $DEPLOY_USER on $SERVER..."

# Run setup on remote server
ssh "$SSH_TARGET" bash << REMOTE_EOF
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

# Write the machine deploy key (replace existing to ensure clean state)
echo "\$SUDO_PASS" | sudo -S bash -c "cat > '\$AUTH_KEYS'" << 'KEYS_EOF'
$KEYS_CONTENT
KEYS_EOF

echo "\$SUDO_PASS" | sudo -S chmod 600 "\$AUTH_KEYS" 2>&1 | grep -v "^\[sudo\]" || true
echo "\$SUDO_PASS" | sudo -S chown -R "\$DEPLOY_USER:\$DEPLOY_USER" "\$SSH_DIR" 2>&1 | grep -v "^\[sudo\]" || true

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
echo "Done! The superkey host can now deploy to $SERVER."
echo "Add the server in the Superkey UI (with labels) if it isn't there yet —"
echo "the deploy runner picks it up automatically within a minute."
