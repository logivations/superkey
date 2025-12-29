#!/bin/bash
#
# Superkey Deployment Script
#
# This script connects to each server configured in Superkey and:
# - Creates system users for authorized users
# - Adds their public SSH keys
# - Adds users to the 'superkey' group (marker) and 'logi' group (access)
# - Revokes access for users no longer authorized (removes from superkey group members)
#
# Usage: ./scripts/deploy.sh [--dry-run] [--server hostname]
#

set -e

SUPERKEY_URL="${SUPERKEY_URL:-http://localhost:3000}"
DEPLOY_USER="${DEPLOY_USER:-superkey-deploy}"
DRY_RUN=false
TARGET_SERVER=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --server)
            TARGET_SERVER="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dry-run] [--server hostname]"
            exit 1
            ;;
    esac
done

echo "Superkey Deployment Script"
echo "=========================="
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "** DRY RUN MODE - No changes will be made **"
    echo ""
fi

# Get all servers with access configuration
echo "Fetching server access data from Superkey..."
SERVERS_DATA=$(curl -s "${SUPERKEY_URL}/api/deploy-data")

if [ -z "$SERVERS_DATA" ] || [ "$SERVERS_DATA" = "null" ]; then
    echo "Error: Could not fetch data from Superkey API"
    exit 1
fi

# Parse JSON and process each server
echo "$SERVERS_DATA" | jq -c '.servers[]' | while read -r server; do
    HOSTNAME=$(echo "$server" | jq -r '.hostname')
    DESCRIPTION=$(echo "$server" | jq -r '.description // ""')

    # Skip if targeting a specific server and this isn't it
    if [ -n "$TARGET_SERVER" ] && [ "$HOSTNAME" != "$TARGET_SERVER" ]; then
        continue
    fi

    echo ""
    echo "Processing server: $HOSTNAME"
    [ -n "$DESCRIPTION" ] && echo "  Description: $DESCRIPTION"

    # Check if any users are configured for this server
    USER_COUNT=$(echo "$server" | jq '.users | length')
    if [ "$USER_COUNT" -eq 0 ] || [ -z "$USER_COUNT" ]; then
        echo "  No users configured for this server, skipping..."
        continue
    fi

    # Build list of authorized usernames for this server
    AUTHORIZED_USERS=$(echo "$server" | jq -r '.users[] | .email' | while read -r email; do
        echo "$email" | cut -d'@' -f1 | tr '.' '_'
    done | sort -u | tr '\n' ' ')

    # Test SSH connection (use DEPLOY_USER)
    SSH_TARGET="$DEPLOY_USER@$HOSTNAME"
    echo "  Testing SSH connection to $SSH_TARGET..."
    if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "$SSH_TARGET" "echo 'SSH OK'" 2>/dev/null; then
        echo "  ERROR: Cannot connect to $SSH_TARGET via SSH, skipping..."
        echo "  Run: ./scripts/setup-server.sh $HOSTNAME to configure"
        continue
    fi

    echo "  SSH connection successful"

    # First, revoke access for users no longer authorized
    echo "  Checking for revoked users..."

    REVOKE_SCRIPT=$(cat <<'REVOKE_EOF'
#!/bin/bash
AUTHORIZED_USERS="$1"

# Check if superkey group exists
if ! getent group superkey &>/dev/null; then
    echo "    No superkey group yet, skipping revocation check"
    exit 0
fi

# Get all users in superkey group
SUPERKEY_MEMBERS=$(getent group superkey | cut -d: -f4 | tr ',' ' ')

for MEMBER in $SUPERKEY_MEMBERS; do
    # Check if this member is still authorized
    if ! echo " $AUTHORIZED_USERS " | grep -q " $MEMBER "; then
        echo "    Revoking access for $MEMBER..."

        # Remove from superkey and logi groups
        sudo -n gpasswd -d "$MEMBER" superkey 2>/dev/null || true
        sudo -n gpasswd -d "$MEMBER" logi 2>/dev/null || true

        # Remove SSH authorized_keys
        USER_HOME=$(getent passwd "$MEMBER" | cut -d: -f6)
        if [ -n "$USER_HOME" ] && [ -f "$USER_HOME/.ssh/authorized_keys" ]; then
            sudo -n rm -f "$USER_HOME/.ssh/authorized_keys"
            echo "      Removed SSH keys"
        fi

        # Lock the account (optional - prevents any login)
        sudo -n usermod -L "$MEMBER" 2>/dev/null || true
        echo "      Account locked"
    fi
done
REVOKE_EOF
)

    if [ "$DRY_RUN" = true ]; then
        echo "    [DRY RUN] Would check and revoke unauthorized users"
    else
        echo "$REVOKE_SCRIPT" | ssh "$SSH_TARGET" "bash -s '$AUTHORIZED_USERS'"
    fi

    # Process each user
    echo "$server" | jq -c '.users[]' | while read -r user; do
        EMAIL=$(echo "$user" | jq -r '.email')
        PUBLIC_KEY=$(echo "$user" | jq -r '.public_key // ""')
        NAME=$(echo "$user" | jq -r '.name // ""')

        # Extract username from email (part before @)
        USERNAME=$(echo "$EMAIL" | cut -d'@' -f1 | tr '.' '_')

        if [ -z "$PUBLIC_KEY" ]; then
            echo "    User $EMAIL has no public key, skipping..."
            continue
        fi

        echo "    Setting up user: $USERNAME ($EMAIL)"

        if [ "$DRY_RUN" = true ]; then
            echo "      [DRY RUN] Would create user $USERNAME"
            echo "      [DRY RUN] Would add to groups: superkey, logi"
            echo "      [DRY RUN] Would set up SSH key"
        else
            # Create the user management script to run on remote server
            # Uses sudo -n (non-interactive) - requires NOPASSWD sudo access
            REMOTE_SCRIPT=$(cat <<EOF
#!/bin/bash

USERNAME="$USERNAME"
PUBLIC_KEY="$PUBLIC_KEY"
FULL_NAME="$NAME"

# Check if we have passwordless sudo
if ! sudo -n true 2>/dev/null; then
    echo "      ERROR: Passwordless sudo not available"
    exit 1
fi

# Ensure superkey group exists (marker for managed users)
if ! getent group superkey &>/dev/null; then
    sudo -n groupadd superkey 2>/dev/null || true
fi

# Ensure logi group exists (access group)
if ! getent group logi &>/dev/null; then
    sudo -n groupadd logi 2>/dev/null || true
fi

# Ensure docker group exists
if ! getent group docker &>/dev/null; then
    sudo -n groupadd docker 2>/dev/null || true
fi

# Create user if doesn't exist
if ! id "\$USERNAME" &>/dev/null; then
    echo "      Creating user \$USERNAME..."
    if ! sudo -n useradd -m -s /bin/bash -c "\$FULL_NAME" "\$USERNAME" 2>&1; then
        echo "      ERROR: Failed to create user"
        exit 1
    fi
else
    echo "      User \$USERNAME already exists"
    # Unlock account if it was previously locked
    sudo -n usermod -U "\$USERNAME" 2>/dev/null || true
fi

# Add user to superkey group (marker)
if ! id -nG "\$USERNAME" | grep -qw "superkey"; then
    echo "      Adding \$USERNAME to superkey group..."
    sudo -n usermod -aG superkey "\$USERNAME" || echo "      Warning: Could not add to superkey group"
fi

# Add user to logi group (access)
if ! id -nG "\$USERNAME" | grep -qw "logi"; then
    echo "      Adding \$USERNAME to logi group..."
    sudo -n usermod -aG logi "\$USERNAME" || echo "      Warning: Could not add to logi group"
fi

# Add user to docker group (allows docker without sudo)
if ! id -nG "\$USERNAME" | grep -qw "docker"; then
    echo "      Adding \$USERNAME to docker group..."
    sudo -n usermod -aG docker "\$USERNAME" || echo "      Warning: Could not add to docker group"
fi

# Set up SSH directory and authorized_keys
USER_HOME=\$(getent passwd "\$USERNAME" | cut -d: -f6)
if [ -z "\$USER_HOME" ]; then
    echo "      ERROR: Could not determine home directory"
    exit 1
fi

SSH_DIR="\$USER_HOME/.ssh"
AUTH_KEYS="\$SSH_DIR/authorized_keys"

sudo -n mkdir -p "\$SSH_DIR"
sudo -n chmod 700 "\$SSH_DIR"

# Replace authorized_keys with current key (ensures old keys are removed)
echo "\$PUBLIC_KEY" | sudo -n tee "\$AUTH_KEYS" > /dev/null
sudo -n chmod 600 "\$AUTH_KEYS"
sudo -n chown -R "\$USERNAME:\$USERNAME" "\$SSH_DIR"

# Add source line to .bashrc if not already present
BASHRC="\$USER_HOME/.bashrc"
SOURCE_LINE="source /home/logi/deploy/linux/setup.bash"
if sudo -n test -f "/home/logi/deploy/linux/setup.bash"; then
    if ! sudo -n grep -qF "\$SOURCE_LINE" "\$BASHRC" 2>/dev/null; then
        echo "      Adding setup.bash to .bashrc..."
        echo "\$SOURCE_LINE" | sudo -n tee -a "\$BASHRC" > /dev/null
        sudo -n chown "\$USERNAME:\$USERNAME" "\$BASHRC"
    fi
fi

echo "      Done setting up \$USERNAME"
EOF
)
            # Execute the script on the remote server
            echo "$REMOTE_SCRIPT" | ssh "$SSH_TARGET" "bash -s"
        fi
    done

    echo "  Completed processing $HOSTNAME"

    # Report deployment status to API
    if [ "$DRY_RUN" = false ]; then
        # Use the expected hash from the API (computed server-side for consistency)
        KEYS_HASH=$(echo "$server" | jq -r '.expected_keys_hash')

        echo "  Reporting deployment status to API (hash: $KEYS_HASH)..."
        REPORT_RESULT=$(curl -s -X POST "${SUPERKEY_URL}/api/servers/${HOSTNAME}/deployed" \
            -H "Content-Type: application/json" \
            -d "{\"keys_hash\": \"$KEYS_HASH\"}")

        if echo "$REPORT_RESULT" | jq -e '.success' &>/dev/null; then
            echo "  Deployment status recorded successfully"
        else
            echo "  Warning: Failed to record deployment status: $REPORT_RESULT"
        fi
    fi
done

echo ""
echo "Deployment complete!"
