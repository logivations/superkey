#!/bin/bash
#
# One-time (idempotent) setup of the automated deploy runner ON THE
# SUPERKEY HOST. Run as root. Called automatically from auto-update.sh, so
# a fresh checkout self-installs on the next update cycle.
#
# - Generates the machine deploy keypair (/root/superkey-deploy-key)
# - Writes DEPLOY_API_TOKEN and DEPLOY_PUBKEY into the project .env
#   (used by docker-compose; the app serves the pubkey at /api/deploy-key)
# - Installs + enables systemd units:
#     superkey-deploy.timer       every minute, deploys stale servers only
#     superkey-deploy-full.timer  daily full reconcile
# - Recreates the app container if .env changed
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="$PROJECT_DIR/.env"
KEY_FILE="${DEPLOY_SSH_KEY:-/root/superkey-deploy-key}"

if [ "$(id -u)" -ne 0 ]; then
    echo "Run as root (needs $KEY_FILE and systemd units)"
    exit 1
fi

CHANGED=false

# --- Machine deploy keypair -------------------------------------------------
if [ ! -f "$KEY_FILE" ]; then
    echo "Generating machine deploy keypair at $KEY_FILE..."
    ssh-keygen -t ed25519 -N "" -C "superkey-deploy@$(hostname)" -f "$KEY_FILE"
    CHANGED=true
fi
PUBKEY=$(cat "$KEY_FILE.pub")

# --- .env entries -------------------------------------------------------------
touch "$ENV_FILE"

# set_env KEY VALUE — add or replace KEY= line in .env
set_env() {
    local key="$1" value="$2"
    if grep -q "^${key}=" "$ENV_FILE"; then
        if [ "$(grep "^${key}=" "$ENV_FILE")" != "${key}=${value}" ]; then
            sed -i "s|^${key}=.*|${key}=${value}|" "$ENV_FILE"
            CHANGED=true
        fi
    else
        echo "${key}=${value}" >> "$ENV_FILE"
        CHANGED=true
    fi
}

if ! grep -q '^DEPLOY_API_TOKEN=..*' "$ENV_FILE"; then
    echo "Generating DEPLOY_API_TOKEN..."
    set_env DEPLOY_API_TOKEN "$(openssl rand -hex 32)"
fi
set_env DEPLOY_PUBKEY "$PUBKEY"

# --- ssh client config ----------------------------------------------------
# Fleet hostnames (muc-amr.cs, ...) resolve via the ssh-configs in the
# hostnames repo, same as on admin laptops. accept-new host keys: first
# contact is trusted (TOFU), changed keys still fail loudly.
mkdir -p /root/.ssh && chmod 700 /root/.ssh
SSH_INCLUDE="Include /root/hostnames/ssh-configs/*.config"
if ! grep -qxF "$SSH_INCLUDE" /root/.ssh/config 2>/dev/null; then
    echo "Adding hostnames ssh-config include to /root/.ssh/config..."
    printf '%s\n%s' "$SSH_INCLUDE" "$(cat /root/.ssh/config 2>/dev/null)" > /root/.ssh/config
    chmod 600 /root/.ssh/config
fi

# --- systemd units ------------------------------------------------------------
write_unit() {
    local path="$1" content="$2"
    if [ ! -f "$path" ] || [ "$(cat "$path")" != "$content" ]; then
        printf '%s\n' "$content" > "$path"
        CHANGED=true
        UNITS_CHANGED=true
    fi
}

UNITS_CHANGED=false

write_unit /etc/systemd/system/superkey-deploy.service "[Unit]
Description=Superkey: deploy SSH access to stale servers
After=docker.service

[Service]
Type=oneshot
ExecStart=$PROJECT_DIR/scripts/deploy-runner.sh
TimeoutStartSec=30min"

write_unit /etc/systemd/system/superkey-deploy.timer "[Unit]
Description=Superkey: check for stale servers every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min

[Install]
WantedBy=timers.target"

write_unit /etc/systemd/system/superkey-deploy-full.service "[Unit]
Description=Superkey: full deploy reconcile to all enrolled servers
After=docker.service

[Service]
Type=oneshot
ExecStart=$PROJECT_DIR/scripts/deploy-runner.sh --full
TimeoutStartSec=2h"

write_unit /etc/systemd/system/superkey-deploy-full.timer "[Unit]
Description=Superkey: daily full deploy reconcile

[Timer]
OnCalendar=*-*-* 05:00:00
Persistent=true

[Install]
WantedBy=timers.target"

if [ "$UNITS_CHANGED" = true ]; then
    systemctl daemon-reload
    # Enable only when units were (re)installed — an admin's manual
    # `systemctl disable` of the timers must survive later runs.
    systemctl enable --now superkey-deploy.timer superkey-deploy-full.timer >/dev/null 2>&1
fi

# --- apply .env changes to the running container -------------------------------
if [ "$CHANGED" = true ]; then
    echo "Configuration changed — recreating app container with new env..."
    # docker-compose v1 crashes with KeyError 'ContainerConfig' when it
    # recreates a running container, so remove it first and create fresh.
    (cd "$PROJECT_DIR" && docker-compose rm -sf superkey && docker-compose up -d) \
        || echo "WARNING: docker-compose up failed; run it manually"
fi

echo "Deploy runner set up."
echo "  Machine key:  $KEY_FILE (BACK THIS UP somewhere offline!)"
echo "  Public key:   $PUBKEY"
echo "  Timers:       superkey-deploy.timer (stale, 1min), superkey-deploy-full.timer (daily 05:00)"
