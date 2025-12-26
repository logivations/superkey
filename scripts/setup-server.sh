#!/bin/bash
#
# Superkey Server Setup Script
#
# Run this once on each server to set up the superkey-deploy user
# Usage: ./setup-server.sh <server-hostname> [public-key-file]
#
# Example:
#   ./setup-server.sh muc-amr.cs ~/.ssh/superkey_deploy.pub
#   ./setup-server.sh muc-amr.cs  # will prompt for key
#

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <server-hostname> [public-key-file]"
    echo ""
    echo "Examples:"
    echo "  $0 muc-amr.cs ~/.ssh/superkey_deploy.pub"
    echo "  $0 muc-amr.cs  # will prompt for key"
    exit 1
fi

SERVER="$1"
KEY_FILE="$2"
DEPLOY_USER="superkey-deploy"

# Get the public key
if [ -n "$KEY_FILE" ]; then
    if [ ! -f "$KEY_FILE" ]; then
        echo "Error: Key file not found: $KEY_FILE"
        exit 1
    fi
    PUBLIC_KEY=$(cat "$KEY_FILE")
else
    echo "Enter the public SSH key for $DEPLOY_USER (paste and press Enter):"
    read -r PUBLIC_KEY
fi

if [ -z "$PUBLIC_KEY" ]; then
    echo "Error: No public key provided"
    exit 1
fi

echo ""
echo "Setting up $DEPLOY_USER on $SERVER..."
echo "Using key: ${PUBLIC_KEY:0:50}..."
echo ""

# Prompt for sudo password
echo -n "Enter sudo password for $SERVER: "
read -rs SUDO_PASS
echo ""

if [ -z "$SUDO_PASS" ]; then
    echo "Error: Sudo password required"
    exit 1
fi

# Escape single quotes in password and public key for safe embedding
SUDO_PASS_ESCAPED=$(printf '%s' "$SUDO_PASS" | sed "s/'/'\\\\''/g")
PUBLIC_KEY_ESCAPED=$(printf '%s' "$PUBLIC_KEY" | sed "s/'/'\\\\''/g")

# Run setup on remote server
ssh "$SERVER" bash << REMOTE_EOF
set -e

DEPLOY_USER='$DEPLOY_USER'
PUBLIC_KEY='$PUBLIC_KEY_ESCAPED'
SUDO_PASS='$SUDO_PASS_ESCAPED'

echo "Creating user \$DEPLOY_USER..."
if ! id "\$DEPLOY_USER" &>/dev/null; then
    echo "\$SUDO_PASS" | sudo -S useradd -m -s /bin/bash -c "Superkey Deploy User" "\$DEPLOY_USER" 2>&1 | grep -v "^\[sudo\]" || true
    echo "  User created"
else
    echo "  User already exists"
fi

echo "Setting up SSH key..."
DEPLOY_HOME=\$(getent passwd "\$DEPLOY_USER" | cut -d: -f6)
SSH_DIR="\$DEPLOY_HOME/.ssh"
AUTH_KEYS="\$SSH_DIR/authorized_keys"

echo "\$SUDO_PASS" | sudo -S mkdir -p "\$SSH_DIR" 2>&1 | grep -v "^\[sudo\]" || true
echo "\$SUDO_PASS" | sudo -S chmod 700 "\$SSH_DIR" 2>&1 | grep -v "^\[sudo\]" || true

# Always write the key (will create file if needed, or append if exists)
if echo "\$SUDO_PASS" | sudo -S test -f "\$AUTH_KEYS" 2>/dev/null; then
    # File exists, check if key is present
    if echo "\$SUDO_PASS" | sudo -S grep -qF "\$PUBLIC_KEY" "\$AUTH_KEYS" 2>/dev/null; then
        echo "  Key already present"
    else
        echo "\$PUBLIC_KEY" | echo "\$SUDO_PASS" | sudo -S tee -a "\$AUTH_KEYS" > /dev/null 2>&1
        echo "  Key added"
    fi
else
    # File doesn't exist, create it
    echo "\$SUDO_PASS" | sudo -S bash -c "echo '\$PUBLIC_KEY' > '\$AUTH_KEYS'" 2>&1 | grep -v "^\[sudo\]" || true
    echo "  Key added"
fi

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
echo "Done! Testing connection as $DEPLOY_USER..."
if ssh -o BatchMode=yes -o ConnectTimeout=5 "$DEPLOY_USER@$SERVER" "echo 'SSH OK' && sudo -n true && echo 'Sudo OK'" 2>/dev/null; then
    echo ""
    echo "SUCCESS: $SERVER is ready for deployment"
else
    echo ""
    echo "WARNING: Could not verify $DEPLOY_USER access"
    echo "You may need to add the private key to your SSH agent:"
    echo "  ssh-add ~/.ssh/id_rsa"
fi
