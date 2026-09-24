#!/bin/bash
#
# Superkey Deployment Script
#
# This script connects to each server configured in Superkey and:
# - Creates system users for authorized users
# - Adds their public SSH keys
# - Adds users to the 'superkey' group (marker), 'logi' group (access) and
#   'superkey_ops' group (scoped NOPASSWD sudo for host troubleshooting,
#   /etc/sudoers.d/superkey-ops; humans only)
# - Provisions per-user bot accounts (<user>_<bot>): a separate, unprivileged
#   account (superkey + adm/systemd-journal for read-only logs, no logi/docker)
#   with a hardened bot key
# - Provisions team-agent accounts (agent_<name>): the same hardened account
#   plus the docker and superkey_agents groups — the latter carries a NOPASSWD
#   run-as rule for the host's deploy user (/etc/sudoers.d/superkey-agents)
# - Revokes access for users no longer authorized (removes from superkey group members)
#
# Servers are processed in parallel. Output from each server is prefixed
# with its hostname. Cap concurrency with MAX_JOBS (default 8), or force
# sequential mode with --serial.
#
# The deploy API requires DEPLOY_API_TOKEN (see .env on the superkey host).
# SSH uses DEPLOY_SSH_KEY if set (the machine deploy key), otherwise
# whatever your agent offers.
#
# Usage: ./scripts/deploy.sh [--dry-run] [--server hostname] [--stale] [--serial] [--jobs N]
#

SUPERKEY_URL="${SUPERKEY_URL:-http://localhost:3000}"
DEPLOY_USER="${DEPLOY_USER:-superkey-deploy}"
MAX_JOBS="${MAX_JOBS:-50}"
DRY_RUN=false
TARGET_SERVER=""
SERIAL=false
STALE_ONLY=false

# Extra ssh options; use the machine deploy key when configured.
# accept-new: trust host keys on first contact (the runner starts with an
# empty known_hosts); a CHANGED key still fails loudly.
SSH_EXTRA_OPTS=(-o StrictHostKeyChecking=accept-new)
if [ -n "$DEPLOY_SSH_KEY" ]; then
    SSH_EXTRA_OPTS+=(-i "$DEPLOY_SSH_KEY" -o IdentitiesOnly=yes)
fi

api_curl() {
    curl -s ${DEPLOY_API_TOKEN:+-H "Authorization: Bearer $DEPLOY_API_TOKEN"} "$@"
}

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
        --stale)
            STALE_ONLY=true
            shift
            ;;
        --jobs)
            MAX_JOBS="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--dry-run] [--server hostname] [--stale] [--serial] [--jobs N]"
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
SERVERS_DATA=$(api_curl "${SUPERKEY_URL}/api/deploy-data")

if [ -z "$SERVERS_DATA" ] || [ "$SERVERS_DATA" = "null" ]; then
    echo "Error: Could not fetch data from Superkey API"
    exit 1
fi
if echo "$SERVERS_DATA" | jq -e '.error' &>/dev/null; then
    echo "Error from Superkey API: $(echo "$SERVERS_DATA" | jq -r '.error')"
    echo "(Is DEPLOY_API_TOKEN set and correct?)"
    exit 1
fi

# In --stale mode only touch servers whose deployed keys hash differs from
# what superkey would deploy now.
STALE_LIST=""
if [ "$STALE_ONLY" = true ]; then
    STALE_JSON=$(api_curl "${SUPERKEY_URL}/api/stale-servers")
    if ! echo "$STALE_JSON" | jq -e '.servers' &>/dev/null; then
        echo "Error: Could not fetch stale servers: $STALE_JSON"
        exit 1
    fi
    STALE_LIST=" $(echo "$STALE_JSON" | jq -r '.servers[]' | tr '\n' ' ') "
    STALE_COUNT=$(echo "$STALE_JSON" | jq '.servers | length')
    echo "Stale servers: ${STALE_COUNT}"
    if [ "$STALE_COUNT" -eq 0 ]; then
        echo "Nothing to deploy."
        exit 0
    fi
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

    # Servers with nothing to deploy that were never deployed are simply not
    # enrolled — skip them. A previously deployed server that is now empty
    # still gets processed so the revoke pass locks remaining accounts.
    local USER_COUNT AGENT_COUNT EVER_DEPLOYED
    USER_COUNT=$(echo "$server" | jq '.users | length')
    AGENT_COUNT=$(echo "$server" | jq '.agents // [] | length')
    EVER_DEPLOYED=$(echo "$server" | jq -r '.ever_deployed // false')
    if [ "${USER_COUNT:-0}" -eq 0 ] && [ "${AGENT_COUNT:-0}" -eq 0 ] && [ "$EVER_DEPLOYED" != "true" ]; then
        echo "  No users or agents configured for this server, skipping..."
        return 0
    fi

    # Build list of authorized usernames for this server: human accounts
    # (derived from email), their personal-agent accounts, and team-agent
    # accounts (both computed server-side). The revoke pass below locks
    # anything in the superkey group that isn't in this list, so all three
    # kinds must be present here.
    local AUTHORIZED_USERS
    AUTHORIZED_USERS=$( {
        echo "$server" | jq -r '.users[] | .email' | while read -r email; do
            echo "$email" | cut -d'@' -f1 | tr '.' '_'
        done
        echo "$server" | jq -r '.users[].bots[]?.account'
        echo "$server" | jq -r '.agents[]?.account'
    } | sort -u | tr '\n' ' ')

    # Test SSH connection (use DEPLOY_USER)
    local SSH_TARGET="$DEPLOY_USER@$HOSTNAME"
    echo "  Testing SSH connection to $SSH_TARGET..."
    if ! ssh -n "${SSH_EXTRA_OPTS[@]}" -o ConnectTimeout=5 -o BatchMode=yes "$SSH_TARGET" "echo 'SSH OK'" 2>/dev/null; then
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

            USER_CALLS+=$(printf 'setup_bot %q %q %q %q %q || OVERALL_STATUS=1\n' \
                "$BACCT" "$BNAME" "$BKEY" "$BOPTS" "")
            USER_CALLS+=$'\n'
        done < <(echo "$user" | jq -c '.bots[]?')
    done < <(echo "$server" | jq -c '.users[]')

    # Team agents (label-granted, no owning user) — provisioned exactly like
    # bot accounts: unprivileged, hardened key, superkey/adm/systemd-journal.
    while read -r agent; do
        [ -z "$agent" ] && continue
        local AACCT AKEY AOPTS ANAME
        AACCT=$(echo "$agent" | jq -r '.account')
        AKEY=$(echo "$agent" | jq -r '.public_key // ""')
        AOPTS=$(echo "$agent" | jq -r '.key_options // "restrict,pty"')
        ANAME=$(echo "$agent" | jq -r '.name')

        if [ -z "$AKEY" ]; then
            continue
        fi

        if [ "$DRY_RUN" = true ]; then
            echo "    [DRY RUN] Would set up team agent $AACCT ($ANAME)"
            continue
        fi

        USER_CALLS+=$(printf 'setup_bot %q %q %q %q %q || OVERALL_STATUS=1\n' \
            "$AACCT" "$ANAME" "$AKEY" "$AOPTS" "docker superkey_agents")
        USER_CALLS+=$'\n'
    done < <(echo "$server" | jq -c '.agents[]?')

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

# Set once, first: every failed step below turns it into the host's exit status.
OVERALL_STATUS=0

# Ensure required groups exist
for g in superkey logi docker superkey_agents superkey_ops; do
    if ! getent group "$g" &>/dev/null; then
        sudo -n groupadd "$g" 2>/dev/null || true
    fi
done

# Ensure /data exists and is writable by superkey users
# Mode 3775: setgid so new files inherit the superkey group, group-writable,
# and STICKY: a member may add entries but not rename or unlink entries it does
# not own. Without the sticky bit any managed account -- personal bots
# included -- could move /data/monitoring aside and replace it, and the
# deploy tooling runs that tree as root (RTDTK-967 review).
if [ ! -d /data ]; then
    sudo -n mkdir -p /data
fi
sudo -n chgrp superkey /data
sudo -n chmod 3775 /data

# Grant human operators scoped passwordless sudo for host troubleshooting
# (reboots, service management, reading system logs) through a group of their
# own: only setup_user joins superkey_ops, bots and agents never do, and the
# deploy account is not in it. The rule lives in a file superkey owns. The
# deploy account's own rule belongs to the deploy repo
# (/etc/sudoers.d/deploy-<user>, linux/utilities/ensure_deploy_sudoers.sh) and
# is never written here -- RTDTK-967. Paths are resolved per-host (distros
# differ) and the file is validated with visudo before install.
OPS_SUDO_CMDS=""
add_sudo_cmd() {
    for p in "$@"; do
        if [ -x "$p" ]; then
            [ -n "$OPS_SUDO_CMDS" ] && OPS_SUDO_CMDS+=", "
            OPS_SUDO_CMDS+="$p"
            return
        fi
    done
}
add_sudo_cmd /usr/bin/systemctl /bin/systemctl
add_sudo_cmd /usr/bin/journalctl /bin/journalctl
add_sudo_cmd /usr/bin/dmesg /bin/dmesg
add_sudo_cmd /usr/sbin/reboot /sbin/reboot
add_sudo_cmd /usr/sbin/shutdown /sbin/shutdown

# install_sudoers_file <file> <rule>: idempotent, validated with visudo, and
# atomic -- the candidate is written next to the target under a dotted name
# (sudo skips names containing a dot) and renamed into place, so sudo never
# sees a truncated or half-written file.
install_sudoers_file() {
    local file="$1" rule="$2" candidate
    if [ "$(sudo -n cat "$file" 2>/dev/null)" = "$rule" ]; then
        return 0
    fi
    echo "  Installing $file..."
    candidate=$(sudo -n mktemp "$(dirname "$file")/.$(basename "$file").XXXXXX")
    printf '%s\n' "$rule" | sudo -n tee "$candidate" > /dev/null
    sudo -n chmod 440 "$candidate"
    if sudo -n visudo -cf "$candidate" >/dev/null 2>&1; then
        sudo -n mv -f "$candidate" "$file"
        echo "    Installed: $rule"
    else
        sudo -n rm -f "$candidate"
        echo "    ERROR: $file failed visudo validation, not installing"
        return 1
    fi
}

if [ -n "$OPS_SUDO_CMDS" ]; then
    install_sudoers_file /etc/sudoers.d/superkey-ops \
        "%superkey_ops ALL=(ALL) NOPASSWD: $OPS_SUDO_CMDS" || OVERALL_STATUS=1
fi

# Let TEAM agents run commands as the host's deploy account (the user that owns
# the ~/deploy checkout). Rationale: the deploy tooling is only correct when run
# as that user -- run_docker.sh mounts the INVOKING user's home into the
# container (deploy#345), so an agent starting deep_cv under its own account
# silently drops the ssh config mount on AMRs. Team agents already hold the
# docker group, which is root-equivalent, so this adds no privilege tier: it
# replaces hand-rolled docker calls with the supported path and puts every
# action in sudo's log. It does NOT grant the deploy user's own
# password-gated sudo. PERSONAL bots are deliberately excluded (they get
# neither docker nor this group) so they stay less privileged than their owner.
AGENT_RUNAS=""
AGENT_RUNAS_FALLBACK=""
for u in logi administrator ubuntu; do
    if id "$u" &>/dev/null; then
        U_HOME=$(getent passwd "$u" | cut -d: -f6)
        if [ -n "$U_HOME" ] && [ -d "$U_HOME/deploy" ]; then
            AGENT_RUNAS="$u"
            break
        fi
        # Remember the first existing candidate as a fallback when no host has
        # a deploy checkout (fresh machine, or a repo in a non-default place).
        [ -z "$AGENT_RUNAS_FALLBACK" ] && AGENT_RUNAS_FALLBACK="$u"
    fi
done
: "${AGENT_RUNAS:=$AGENT_RUNAS_FALLBACK}"

# Until 2026-09 the scoped rule above was written as "%logi ..." to
# /etc/sudoers.d/logi -- the file the deploy repo used for the deploy account's
# own "NOPASSWD: ALL" rule. On a host with a logi deploy account that replaced
# the deploy rule with the scoped list and silently broke unattended updates
# (RTDTK-967). Superkey is the only writer of "%logi ALL=(ALL) NOPASSWD:" lines,
# so a legacy file consisting of one such line is superkey's and is removed
# (the command paths in it may predate an OS upgrade, hence the prefix match).
# Whether the deploy account has sudo of its own is the deploy repo's business;
# it is only reported here so the operator knows what to run.
LEGACY_LOGI_SUDOERS="/etc/sudoers.d/logi"
LEGACY_LOGI_SUDOERS_CONTENT=$(sudo -n cat "$LEGACY_LOGI_SUDOERS" 2>/dev/null || true)
if [ -n "$LEGACY_LOGI_SUDOERS_CONTENT" ] \
    && [ "$(printf '%s\n' "$LEGACY_LOGI_SUDOERS_CONTENT" | wc -l)" -eq 1 ] \
    && [[ "$LEGACY_LOGI_SUDOERS_CONTENT" == "%logi ALL=(ALL) NOPASSWD: "* ]]; then
    sudo -n rm -f "$LEGACY_LOGI_SUDOERS"
    echo "  Removed legacy $LEGACY_LOGI_SUDOERS (replaced by /etc/sudoers.d/superkey-ops)"
fi
if [ -n "$AGENT_RUNAS" ] && ! sudo -n -u "$AGENT_RUNAS" -- sudo -k -n true 2>/dev/null; then
    echo "  NOTE: deploy account $AGENT_RUNAS has no passwordless sudo on this host. If its unattended"
    echo "        updates need it (cameras, AMRs), provision the deploy repo's rule:"
    echo "        sudo bash ~$AGENT_RUNAS/deploy/linux/utilities/ensure_deploy_sudoers.sh $AGENT_RUNAS (RTDTK-967)"
fi

if [ -n "$AGENT_RUNAS" ]; then
    install_sudoers_file /etc/sudoers.d/superkey-agents \
        "%superkey_agents ALL=($AGENT_RUNAS) NOPASSWD: ALL" || OVERALL_STATUS=1
else
    echo "  No deploy account (logi/administrator/ubuntu) on this host;"
    echo "  skipping the superkey_agents run-as sudoers rule."
fi

# Revoke users currently in superkey group but no longer authorized
if getent group superkey &>/dev/null; then
    SUPERKEY_MEMBERS=$(getent group superkey | cut -d: -f4 | tr ',' ' ')
    for MEMBER in $SUPERKEY_MEMBERS; do
        if ! echo " $AUTHORIZED_USERS " | grep -q " $MEMBER "; then
            echo "    Revoking access for $MEMBER..."
            for g in superkey logi docker superkey_agents superkey_ops adm systemd-journal; do
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

    # superkey/logi/docker/superkey_ops are created above if missing;
    # adm/systemd-journal are standard system groups (for reading system logs)
    # and are only joined if they already exist on the host. superkey_ops is
    # the humans' scoped sudo (see above): bots and agents are never in it.
    for g in superkey logi docker superkey_ops adm systemd-journal; do
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
    local EXTRA_GROUPS="$5"

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
    # access to the full system journal. PERSONAL bots are deliberately NOT
    # in logi/docker (no scoped sudo, no docker=root: less privileged than
    # their owner). TEAM agents additionally get docker and superkey_agents
    # via EXTRA_GROUPS — the latter carries the run-as-deploy-user sudoers rule
    # installed above, so they can drive the deploy tooling (checkout_*,
    # update_w2mo, run_docker.sh) the way a human would instead of hand-rolling
    # docker commands. Their access is granted per label, on restricted servers
    # only by allowed_users. adm/systemd-journal are standard system groups,
    # joined only if they already exist on the host.
    for g in superkey adm systemd-journal $EXTRA_GROUPS; do
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

REMOTE_EOF
)

        local REMOTE_SCRIPT
        REMOTE_SCRIPT="AUTHORIZED_USERS=$(printf '%q' "$AUTHORIZED_USERS")
${REMOTE_BODY}
${USER_CALLS}
exit \$OVERALL_STATUS"

        if ! ssh "${SSH_EXTRA_OPTS[@]}" -o BatchMode=yes "$SSH_TARGET" "bash -s" <<< "$REMOTE_SCRIPT"; then
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
        REPORT_RESULT=$(api_curl -X POST "${SUPERKEY_URL}/api/servers/${HOSTNAME}/deployed" \
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

    # In --stale mode, skip servers that are already up to date
    if [ "$STALE_ONLY" = true ] && ! echo "$STALE_LIST" | grep -q " $HOSTNAME "; then
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
