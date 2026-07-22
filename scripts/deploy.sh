#!/bin/bash
#
# Superkey Deployment Script
#
# This script connects to each server configured in Superkey and:
# - Creates system users for authorized users
# - Adds their public SSH keys
# - Adds users to the 'superkey' group (marker) and 'logi' group (access)
# - Provisions per-user bot accounts (<user>_<bot>): a separate, unprivileged
#   account (superkey + adm/systemd-journal for read-only logs, no logi/docker)
#   with a hardened bot key
# - Revokes access for users no longer authorized (removes from superkey group members)
#
# Servers are processed in parallel. Output from each server is prefixed
# with its hostname. Cap concurrency with MAX_JOBS (default 8), or force
# sequential mode with --serial.
#
# Usage: ./scripts/deploy.sh [--dry-run] [--server hostname] [--serial] [--jobs N]
#

SUPERKEY_URL="${SUPERKEY_URL:-http://localhost:3000}"
DEPLOY_USER="${DEPLOY_USER:-superkey-deploy}"
MAX_JOBS="${MAX_JOBS:-50}"
DRY_RUN=false
TARGET_SERVER=""
SERIAL=false

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
        --serial)
            SERIAL=true
            shift
            ;;
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dry-run] [--server hostname] [--serial] [--jobs N]"
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

if [ "$SERIAL" = true ]; then
    echo "Running serially (one server at a time)"
else
    echo "Running in parallel (max ${MAX_JOBS} concurrent)"
fi
echo ""

# Get all servers with access configuration
echo "Fetching server access data from Superkey..."
SERVERS_DATA=$(curl -s "${SUPERKEY_URL}/api/deploy-data")

if [ -z "$SERVERS_DATA" ] || [ "$SERVERS_DATA" = "null" ]; then
    echo "Error: Could not fetch data from Superkey API"
    exit 1
fi

# Process a single server. All output goes to stdout/stderr; the caller
# is responsible for prefixing with the hostname.
# Returns 0 on success, non-zero on any failure.
process_server() {
    local server="$1"
    local HOSTNAME
    local DESCRIPTION
    HOSTNAME=$(echo "$server" | jq -r '.hostname')
    DESCRIPTION=$(echo "$server" | jq -r '.description // ""')

    echo "Processing server: $HOSTNAME"
    [ -n "$DESCRIPTION" ] && echo "  Description: $DESCRIPTION"

    # Check if any users are configured for this server
    local USER_COUNT
    USER_COUNT=$(echo "$server" | jq '.users | length')
    if [ "$USER_COUNT" -eq 0 ] || [ -z "$USER_COUNT" ]; then
        echo "  No users configured for this server, skipping..."
        return 0
    fi

    # Build list of authorized usernames for this server: human accounts
    # (derived from email) plus their bot accounts (computed server-side).
    # The revoke pass below locks anything in the superkey group that isn't
    # in this list, so both kinds must be present here.
    local AUTHORIZED_USERS
    AUTHORIZED_USERS=$( {
        echo "$server" | jq -r '.users[] | .email' | while read -r email; do
            echo "$email" | cut -d'@' -f1 | tr '.' '_'
        done
        echo "$server" | jq -r '.users[].bots[]?.account'
    } | sort -u | tr '\n' ' ')

    # Test SSH connection (use DEPLOY_USER)
    local SSH_TARGET="$DEPLOY_USER@$HOSTNAME"
    echo "  Testing SSH connection to $SSH_TARGET..."
    if ! ssh -n -o ConnectTimeout=5 -o BatchMode=yes "$SSH_TARGET" "echo 'SSH OK'" 2>/dev/null; then
        echo "  ERROR: Cannot connect to $SSH_TARGET via SSH, skipping..."
        echo "  Run: ./scripts/setup-server.sh $HOSTNAME to configure"
        return 1
    fi

    echo "  SSH connection successful"

    # Build per-user setup invocations (shell-safe quoting via %q). Each human
    # gets setup_user; each of their bots gets setup_bot as a separate,
    # unprivileged account. Bots are deployed independently of the human's own
    # key (a user may have bots but no personal key on this host).
    local USER_CALLS=""
    while read -r user; do
        local EMAIL PUBLIC_KEY NAME USERNAME
        EMAIL=$(echo "$user" | jq -r '.email')
        PUBLIC_KEY=$(echo "$user" | jq -r '.public_key // ""')
        NAME=$(echo "$user" | jq -r '.name // ""')
        USERNAME=$(echo "$EMAIL" | cut -d'@' -f1 | tr '.' '_')

        if [ -n "$PUBLIC_KEY" ]; then
            if [ "$DRY_RUN" = true ]; then
                echo "    [DRY RUN] Would set up user $USERNAME ($EMAIL)"
            else
                USER_CALLS+=$(printf 'setup_user %q %q %q || OVERALL_STATUS=1\n' \
                    "$USERNAME" "$NAME" "$PUBLIC_KEY")
                USER_CALLS+=$'\n'
            fi
        else
            echo "    User $EMAIL has no public key, skipping user account..."
        fi

        # Bot accounts owned by this user
        while read -r bot; do
            [ -z "$bot" ] && continue
            local BACCT BKEY BOPTS BNAME
            BACCT=$(echo "$bot" | jq -r '.account')
            BKEY=$(echo "$bot" | jq -r '.public_key // ""')
            BOPTS=$(echo "$bot" | jq -r '.key_options // "restrict,pty"')
            BNAME=$(echo "$bot" | jq -r '.name')

            if [ -z "$BKEY" ]; then
                continue
            fi

            if [ "$DRY_RUN" = true ]; then
                echo "    [DRY RUN] Would set up bot $BACCT ($EMAIL / $BNAME)"
                continue
            fi

            USER_CALLS+=$(printf 'setup_bot %q %q %q %q || OVERALL_STATUS=1\n' \
                "$BACCT" "$BNAME" "$BKEY" "$BOPTS")
            USER_CALLS+=$'\n'
        done < <(echo "$user" | jq -c '.bots[]?')
    done < <(echo "$server" | jq -c '.users[]')

    local user_failed=0
    if [ "$DRY_RUN" = true ]; then
        echo "  [DRY RUN] Would revoke unauthorized users"
    else
        # Single SSH connection: revoke + all user setups in one remote session
        local REMOTE_BODY
        REMOTE_BODY=$(cat <<'REMOTE_EOF'
if ! sudo -n true 2>/dev/null; then
    echo "  ERROR: Passwordless sudo not available"
    exit 1
fi

# Ensure required groups exist
for g in superkey logi docker; do
    if ! getent group "$g" &>/dev/null; then
        sudo -n groupadd "$g" 2>/dev/null || true
    fi
done

# Ensure /data exists and is writable by superkey users
# Mode 2775: setgid so new files inherit the superkey group, group-writable
if [ ! -d /data ]; then
    sudo -n mkdir -p /data
fi
sudo -n chgrp superkey /data
sudo -n chmod 2775 /data

# W2MO hosts: whdb containers run as the logi user (deploy/linux/
# update_w2mo.sh), and every logi-group member must be able to back up /
# restore / prune the DB folders without root. Re-own anything root-mode
# containers left behind; setgid dirs keep the logi group on new subfolders.
# The find probe keeps this a no-op on already-migrated hosts.
if id logi &>/dev/null && [ -d /data/mysql_data ]; then
    for d in /data/mysql_data /data/mysql_backup; do
        [ -d "$d" ] || continue
        if [ -n "$(sudo -n find "$d" ! -user logi -print -quit 2>/dev/null)" ] \
           || [ "$(stat -c %a "$d" 2>/dev/null)" != "2775" ]; then
            echo "  Migrating $d to logi ownership (group-writable)..."
            sudo -n chown -R logi:logi "$d"
            sudo -n chmod -R u+rwX,g+rwX "$d"
            sudo -n find "$d" -type d -exec chmod g+s {} +
            sudo -n chmod 2775 "$d"
        fi
    done

    # rollback/autoupdate state + config: group-writable so the update and
    # rollback scripts need no sudo for them either
    sudo -n mkdir -p /data/w2mo_autoupdate
    sudo -n chown -R logi:logi /data/w2mo_autoupdate
    sudo -n chmod -R g+rwX /data/w2mo_autoupdate
    sudo -n chmod 2775 /data/w2mo_autoupdate
    if [ -d /data/appconfig_static ]; then
        # top level only -- certs/ and the rest stay untouched
        sudo -n chgrp logi /data/appconfig_static 2>/dev/null || true
        sudo -n chmod g+rwxs /data/appconfig_static 2>/dev/null || true
        for f in /data/appconfig_static/w2mo_autoupdate.conf /data/appconfig_static/server.settings; do
            if [ -f "$f" ]; then
                sudo -n chown logi:logi "$f"
                sudo -n chmod g+rw "$f"
            fi
        done
    fi
fi

# Grant the logi group scoped passwordless sudo for host troubleshooting
# (reboots, service management, reading system logs). Managed accounts are
# otherwise unprivileged; this replaces the implicit docker-based root path
# with explicit, audited sudo. Paths are resolved per-host (distros differ)
# and the file is validated with visudo before install.
LOGI_SUDO_CMDS=""
add_sudo_cmd() {
    for p in "$@"; do
        if [ -x "$p" ]; then
            [ -n "$LOGI_SUDO_CMDS" ] && LOGI_SUDO_CMDS+=", "
            LOGI_SUDO_CMDS+="$p"
            return
        fi
    done
}
add_sudo_cmd /usr/bin/systemctl /bin/systemctl
add_sudo_cmd /usr/bin/journalctl /bin/journalctl
add_sudo_cmd /usr/bin/dmesg /bin/dmesg
add_sudo_cmd /usr/sbin/reboot /sbin/reboot
add_sudo_cmd /usr/sbin/shutdown /sbin/shutdown

if [ -n "$LOGI_SUDO_CMDS" ]; then
    LOGI_SUDOERS="/etc/sudoers.d/logi"
    LOGI_SUDOERS_LINE="%logi ALL=(ALL) NOPASSWD: $LOGI_SUDO_CMDS"
    if [ "$(sudo -n cat "$LOGI_SUDOERS" 2>/dev/null)" != "$LOGI_SUDOERS_LINE" ]; then
        echo "  Configuring scoped sudo for logi group..."
        LOGI_TMP=$(mktemp)
        printf '%s\n' "$LOGI_SUDOERS_LINE" > "$LOGI_TMP"
        if sudo -n visudo -cf "$LOGI_TMP" >/dev/null 2>&1; then
            sudo -n cp "$LOGI_TMP" "$LOGI_SUDOERS"
            sudo -n chmod 440 "$LOGI_SUDOERS"
            echo "    Installed: $LOGI_SUDOERS_LINE"
        else
            echo "    ERROR: logi sudoers failed visudo validation, not installing"
        fi
        rm -f "$LOGI_TMP"
    fi
fi

# Revoke users currently in superkey group but no longer authorized
if getent group superkey &>/dev/null; then
    SUPERKEY_MEMBERS=$(getent group superkey | cut -d: -f4 | tr ',' ' ')
    for MEMBER in $SUPERKEY_MEMBERS; do
        if ! echo " $AUTHORIZED_USERS " | grep -q " $MEMBER "; then
            echo "    Revoking access for $MEMBER..."
            for g in superkey logi docker adm systemd-journal; do
                sudo -n gpasswd -d "$MEMBER" "$g" 2>/dev/null || true
            done
            REV_HOME=$(getent passwd "$MEMBER" | cut -d: -f6)
            if [ -n "$REV_HOME" ] && [ -f "$REV_HOME/.ssh/authorized_keys" ]; then
                sudo -n rm -f "$REV_HOME/.ssh/authorized_keys"
                echo "      Removed SSH keys"
            fi
            sudo -n usermod -L "$MEMBER" 2>/dev/null || true
            echo "      Account locked"
        fi
    done
fi

setup_user() {
    local USERNAME="$1"
    local FULL_NAME="$2"
    local PUBLIC_KEY="$3"

    echo "    Setting up user: $USERNAME"

    if ! id "$USERNAME" &>/dev/null; then
        echo "      Creating user $USERNAME..."
        if ! sudo -n useradd -m -s /bin/bash -c "$FULL_NAME" "$USERNAME" 2>&1; then
            echo "      ERROR: Failed to create user"
            return 1
        fi
    else
        echo "      User $USERNAME already exists"
        sudo -n usermod -U "$USERNAME" 2>/dev/null || true
    fi

    # superkey/logi/docker are created above if missing; adm/systemd-journal
    # are standard system groups (for reading system logs) and are only joined
    # if they already exist on the host.
    for g in superkey logi docker adm systemd-journal; do
        if ! getent group "$g" &>/dev/null; then
            continue
        fi
        if ! id -nG "$USERNAME" | grep -qw "$g"; then
            echo "      Adding $USERNAME to $g group..."
            sudo -n usermod -aG "$g" "$USERNAME" || echo "      Warning: Could not add to $g group"
        fi
    done

    local USER_HOME SSH_DIR AUTH_KEYS
    USER_HOME=$(getent passwd "$USERNAME" | cut -d: -f6)
    if [ -z "$USER_HOME" ]; then
        echo "      ERROR: Could not determine home directory"
        return 1
    fi
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    sudo -n mkdir -p "$SSH_DIR"
    sudo -n chmod 700 "$SSH_DIR"
    echo "$PUBLIC_KEY" | sudo -n tee "$AUTH_KEYS" > /dev/null
    sudo -n chmod 600 "$AUTH_KEYS"
    sudo -n chown -R "$USERNAME:$USERNAME" "$SSH_DIR"

    local BASHRC="$USER_HOME/.bashrc"
    local SOURCE_LINE="source /home/logi/deploy/linux/setup.bash"
    if sudo -n test -f "/home/logi/deploy/linux/setup.bash"; then
        if ! sudo -n grep -qF "$SOURCE_LINE" "$BASHRC" 2>/dev/null; then
            echo "      Adding setup.bash to .bashrc..."
            echo "$SOURCE_LINE" | sudo -n tee -a "$BASHRC" > /dev/null
            sudo -n chown "$USERNAME:$USERNAME" "$BASHRC"
        fi
    fi

    echo "      Done setting up $USERNAME"
}

setup_bot() {
    local ACCT="$1"
    local BOT_NAME="$2"
    local PUBLIC_KEY="$3"
    local KEY_OPTS="$4"

    echo "    Setting up bot account: $ACCT"

    if ! id "$ACCT" &>/dev/null; then
        echo "      Creating bot account $ACCT..."
        if ! sudo -n useradd -m -s /bin/bash -c "superkey bot $BOT_NAME" "$ACCT" 2>&1; then
            echo "      ERROR: Failed to create bot account"
            return 1
        fi
    else
        echo "      Bot account $ACCT already exists"
        sudo -n usermod -U "$ACCT" 2>/dev/null || true
    fi

    # Bots join the superkey marker group (managed + revocable by superkey,
    # access to the shared /data dir) plus adm/systemd-journal for READ-ONLY
    # access to the full system journal. They are deliberately NOT in
    # logi/docker, so they get no scoped sudo and no docker=root: a bot is
    # meant to be less privileged than its human owner. adm/systemd-journal are
    # standard system groups, joined only if they already exist on the host.
    for g in superkey adm systemd-journal; do
        if ! getent group "$g" &>/dev/null; then
            continue
        fi
        if ! id -nG "$ACCT" | grep -qw "$g"; then
            echo "      Adding $ACCT to $g group..."
            sudo -n usermod -aG "$g" "$ACCT" || echo "      Warning: Could not add to $g group"
        fi
    done

    local USER_HOME SSH_DIR AUTH_KEYS
    USER_HOME=$(getent passwd "$ACCT" | cut -d: -f6)
    if [ -z "$USER_HOME" ]; then
        echo "      ERROR: Could not determine home directory"
        return 1
    fi
    SSH_DIR="$USER_HOME/.ssh"
    AUTH_KEYS="$SSH_DIR/authorized_keys"

    sudo -n mkdir -p "$SSH_DIR"
    sudo -n chmod 700 "$SSH_DIR"
    # KEY_OPTS is computed and validated server-side (restrict,pty[,from=...]).
    printf '%s %s\n' "$KEY_OPTS" "$PUBLIC_KEY" | sudo -n tee "$AUTH_KEYS" > /dev/null
    sudo -n chmod 600 "$AUTH_KEYS"
    sudo -n chown -R "$ACCT:$ACCT" "$SSH_DIR"

    echo "      Done setting up bot $ACCT"
}

OVERALL_STATUS=0
REMOTE_EOF
)

        local REMOTE_SCRIPT
        REMOTE_SCRIPT="AUTHORIZED_USERS=$(printf '%q' "$AUTHORIZED_USERS")
${REMOTE_BODY}
${USER_CALLS}
exit \$OVERALL_STATUS"

        if ! ssh "$SSH_TARGET" "bash -s" <<< "$REMOTE_SCRIPT"; then
            echo "  ERROR: Remote setup failed on $HOSTNAME"
            user_failed=1
        fi
    fi

    echo "  Completed processing $HOSTNAME"

    # Report deployment status to API
    if [ "$DRY_RUN" = false ] && [ "$user_failed" -eq 0 ]; then
        # Use the expected hash from the API (computed server-side for consistency)
        local KEYS_HASH REPORT_RESULT
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

    return "$user_failed"
}

# Block until a background job slot is free.
wait_for_slot() {
    while [ "$(jobs -rp | wc -l)" -ge "$MAX_JOBS" ]; do
        wait -n 2>/dev/null || true
    done
}

# Track per-host exit status via temp files (set -e would abort the whole
# run on the first server failure, which we explicitly do not want).
STATUS_DIR=$(mktemp -d)
trap 'rm -rf "$STATUS_DIR"' EXIT

HOSTS_SEEN=()

while read -r server; do
    HOSTNAME=$(echo "$server" | jq -r '.hostname')

    # Skip if targeting a specific server and this isn't it
    if [ -n "$TARGET_SERVER" ] && [ "$HOSTNAME" != "$TARGET_SERVER" ]; then
        continue
    fi

    HOSTS_SEEN+=("$HOSTNAME")

    if [ "$SERIAL" = true ]; then
        echo ""
        if process_server "$server" 2>&1 | sed "s/^/[$HOSTNAME] /"; then
            echo "0" > "$STATUS_DIR/$HOSTNAME"
        else
            # PIPESTATUS[0] is process_server's exit code before sed
            echo "${PIPESTATUS[0]}" > "$STATUS_DIR/$HOSTNAME"
        fi
    else
        wait_for_slot
        (
            if process_server "$server" 2>&1 | sed "s/^/[$HOSTNAME] /"; then
                echo "0" > "$STATUS_DIR/$HOSTNAME"
            else
                echo "${PIPESTATUS[0]}" > "$STATUS_DIR/$HOSTNAME"
            fi
        ) &
    fi
done < <(echo "$SERVERS_DATA" | jq -c '.servers[]')

# Wait for any remaining background jobs
if [ "$SERIAL" != true ]; then
    wait
fi

# Summarize results
echo ""
echo "Deployment complete!"

FAILED_HOSTS=()
for host in "${HOSTS_SEEN[@]}"; do
    status_file="$STATUS_DIR/$host"
    if [ ! -f "$status_file" ] || [ "$(cat "$status_file")" != "0" ]; then
        FAILED_HOSTS+=("$host")
    fi
done

if [ "${#FAILED_HOSTS[@]}" -gt 0 ]; then
    echo ""
    echo "The following hosts reported errors:"
    for host in "${FAILED_HOSTS[@]}"; do
        echo "  - $host"
    done
    exit 1
fi
