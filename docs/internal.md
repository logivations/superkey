# Superkey - Internal Documentation

**Superkey** is an SSH public key management tool that automates server access provisioning using Google Workspace as the source of truth for users and groups.

---

## Table of Contents

1. [What is Superkey?](#what-is-superkey)
2. [Architecture Overview](#architecture-overview)
3. [Access Model](#access-model)
4. [Agents](#bot-keys-per-user-automation)
5. [Technology Stack](#technology-stack)
6. [Getting Started](#getting-started)
7. [Configuration](#configuration)
8. [Server Deployment](#server-deployment)
9. [Database Backups](#database-backups)
10. [API Reference](#api-reference)
11. [Troubleshooting](#troubleshooting)

---

## What is Superkey?

Superkey solves the problem of managing SSH access across many servers. Instead of manually adding/removing SSH keys on each server, Superkey:

1. **Authenticates users** via Google SSO
2. **Syncs users and groups** from Google Workspace
3. **Lets users upload** their SSH public keys
4. **Maps groups to server labels** (e.g., "dev-team" group → "staging" servers)
5. **Automatically deploys** SSH keys to authorized servers
6. **Revokes access** when users leave groups or the organization

This means when someone joins a team in Google Workspace, they automatically get SSH access to the right servers. When they leave, access is revoked automatically.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SUPERKEY SERVER                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────────┐  │
│  │   Express    │    │   SQLite     │    │   Google APIs        │  │
│  │   Web App    │◄──►│   Database   │    │   (Admin SDK)        │  │
│  │   (Port 3000)│    │              │    │                      │  │
│  └──────────────┘    └──────────────┘    └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                │ SSH (superkey-deploy user)
                                ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        TARGET SERVERS                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐                 │
│  │  Server A   │  │  Server B   │  │  Server C   │  ...            │
│  │  (staging)  │  │  (prod)     │  │  (dev)      │                 │
│  └─────────────┘  └─────────────┘  └─────────────┘                 │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. Users log in via Google SSO
2. Superkey syncs their group memberships from Google Workspace
3. Users upload their SSH public keys via the web UI
4. Admins assign Google groups to server labels
5. The deploy runner on the superkey host pushes keys to servers whose
   deployed state is out of date (checked every minute)

---

## Access Model

Access is determined by a chain of relationships:

```
Users ──► Groups ──► Labels ──► Servers
```

| Entity   | Description                                                              | Source                      |
|----------|--------------------------------------------------------------------------|----------------------------|
| Users    | People who need SSH access                                               | Google Workspace (synced)   |
| Groups   | Logical groupings of users (e.g., "dev-team", "ops")                    | Google Workspace (synced)   |
| Labels   | Tags for servers (e.g., "production", "staging", "munich-office")       | Created manually in Superkey|
| Servers  | Target machines                                                          | Imported from SSH config or added manually |

### Example Access Flow

1. Alice is a member of the `engineering` group in Google Workspace
2. An admin assigns the `engineering` group to the `staging` label in Superkey
3. The `staging` label is applied to servers `staging-web-1` and `staging-db-1`
4. **Result**: Alice can SSH into `staging-web-1` and `staging-db-1`

Servers matched by `restricted-servers.json` (in git) override this chain:
only the listed groups/users are ever deployed there. See the Readme's
*Restricted servers* section.
Servers in its `unprivileged_servers` section are deployed with no
privileged groups and forced-command keys — see *Unprivileged servers*.

### Admin Access

Admins are members of the `superkey_admins` Google Workspace group. They can:

- Manage servers and labels
- View all users and their access permissions
- Assign groups to labels
- Trigger full user/group sync from Google Workspace
- Run deployments

---

## Bot Keys (per-user automation)

Users can register **bot keys** for automation agents (e.g. `nemo`) that act on
their behalf. The design goal is to let a bot work "the same way" a user does
over SSH, without ever handing it the user's personal key or more access than
the user already has.

**Model**

- A bot is a child of a user (`bot_keys` table): a `name`, a dedicated
  `public_key`, and an optional `source_cidr` restriction.
- It is deployed as a **separate Linux account** named `<username>_<bot>`
  (e.g. `johannes_plapp_nemo`) on **exactly the servers the owning user can
  already reach** — access is derived from the owner's group membership, so a
  user can never grant a bot more than they have. Self-service is therefore
  safe: the user's own scope is the hard ceiling.
- Optionally **label-scoped** (`bot_keys.label_scoped` + `bot_labels`): the
  owner picks labels under **Access** in My agents (only labels of devices
  they reach, `/api/me/reachable-labels` — admins included),
  and the bot then lands only on the owner's servers carrying one of them —
  none attached means nowhere. Unscoped (the default, and every bot created
  before this existed) follows the owner everywhere. `serverUserBots()` is
  the single filter behind deploy-data, the keys hash and the access views.
- The bot account joins the **`superkey`** marker group (managed/revocable by
  superkey, access to the shared `/data` dir) plus **`adm`/`systemd-journal`**
  for **read-only** access to the full system journal. It is **not** in
  `logi`, so it has **no scoped sudo**. It joins **`docker`** (root-equivalent)
  and **`superkey_agents`** (NOPASSWD run-as the deploy user, e.g.
  `sudo -u logi` for `~logi/deploy` — the same as team agents) only when the
  owner enables **Root access** per bot under **Access** (`bot_keys.docker`,
  sent as `extra_groups` in deploy-data); switching it off removes the bot
  from both on the next deploy.
- The key is installed with hardened `authorized_keys` options:
  `restrict,pty` plus `from="<cidr>"` when a source restriction is set — so a
  leaked bot key is useless off its host.

**Lifecycle**

- Register/rotate/revoke from the **My agents** tab (self-service, no admin).
  Re-submitting the same bot name rotates its key.
- Revocation is automatic: deleting a bot removes it from the per-server
  authorized list, so the next deploy locks the account and removes its key
  (the same revoke path used for departed users).
- Public keys are validated server-side (single line, must start with a real
  key type) to prevent `authorized_keys` option/line injection. The base64
  blob must also decode to that same key type: sshd silently skips a line it
  can't parse, so a copy/paste slip would otherwise save fine and never work.

## Team Agents (shared nemo agents)

- A team agent (`team_agents` table) has **no owner**. The nemo dispatcher
  registers it through the machine API (`POST /api/agents/register`, bearer
  `AGENT_API_TOKEN`); re-registering the same name rotates its key.
- It starts with **no access**. Signed-in users attach **labels** to it in the
  **Team agents** tab (`agent_labels`), and it reaches the servers carrying
  those labels as `agent_<name>`. Users can only attach labels they hold via
  their groups (`/api/me/labels`); admins can attach any label.
- **Maintainers** (`agent_maintainers`): the dispatcher may send
  `maintainers: [emails]` on registration (owner + shared_with); a sent list
  replaces the stored one (`[]` clears it), an absent one leaves it. If an
  agent has maintainers, label changes need admin OR (label held AND email in
  maintainers); without maintainers the label rule alone applies. Enforced in
  `grantAgentLabel` / `revokeAgentLabel`, shared by the HTTP routes and the
  MCP tools. `GET /api/agents` and MCP `list_agents`/`deploy_status` return
  `maintainers` and the caller's `can_manage`.
- Restricted servers withhold team agents unless their rule sets
  `allow_agents`. When a rule sets `allowed_users`, only those users may
  attach or detach labels that touch the server.
- Accounts always join `superkey`, `adm`, `systemd-journal`, `docker` and
  `superkey_agents` (see the group table below).
- Deleting an agent (admin in the UI, or the dispatcher via
  `DELETE /api/agents/register/<name>`) locks its accounts on the next deploy.

## Technology Stack

| Component          | Technology                                         |
|--------------------|----------------------------------------------------|
| Backend            | Node.js + Express                                  |
| Database           | SQLite (better-sqlite3)                            |
| Authentication     | Passport.js with Google OAuth 2.0; OAuth 2.1 authorization server for `/mcp` (`src/oauth.js`) |
| MCP                | `@modelcontextprotocol/sdk`, Streamable HTTP at `/mcp` (`src/mcp.js`) |
| Session Storage    | SQLite-backed sessions                             |
| Google Integration | Google Admin SDK (Directory API)                   |
| Frontend           | Static HTML/JS served from `public/`               |
| Deployment         | Bash scripts using SSH                             |

### Database Schema

Key tables:
- `users` - User accounts (synced from Google)
- `groups` - Google Workspace groups
- `user_groups` - Many-to-many: which users belong to which groups
- `servers` - Target servers with hostname and description
- `labels` - Server labels/tags
- `server_labels` - Many-to-many: which labels are applied to which servers
- `label_groups` - Many-to-many: which groups have access to which labels
- `bot_keys` - Personal agents (owner, key, `source_cidr`, `label_scoped`,
  `docker` = Root access)
- `bot_labels` - Labels a label-scoped personal agent is limited to
- `team_agents` - Shared nemo agents (no owner)
- `agent_labels` - Labels granting a team agent access
- `agent_maintainers` - Emails allowed to change a team agent's labels
- `oauth_clients`, `oauth_requests`, `oauth_codes`, `oauth_grants`,
  `oauth_tokens` - MCP OAuth: registered clients, pending authorizations,
  codes, grants (= connected apps) and hashed access/refresh tokens

`servers.deployed_keys_hash` / `last_deployed_at` record what was last
deployed; the runner compares that hash with what superkey would deploy now.

---

## Getting Started

### Prerequisites

- Node.js 18+
- A Google Workspace organization
- SSH access to target servers

### Local Development

```bash
# Clone and install
git clone <repo-url>
cd superkey
npm install

# Configure environment
cp .env.example .env
# Edit .env with your Google OAuth credentials

# Run
npm start
# Visit http://localhost:3000
```

---

## Configuration

### Environment Variables

| Variable                    | Required | Description                                              |
|-----------------------------|----------|----------------------------------------------------------|
| `GOOGLE_CLIENT_ID`          | Yes      | OAuth 2.0 client ID from Google Cloud Console            |
| `GOOGLE_CLIENT_SECRET`      | Yes      | OAuth 2.0 client secret                                  |
| `GOOGLE_CALLBACK_URL`       | Yes      | OAuth callback URL (e.g., `http://localhost:3000/auth/google/callback`) |
| `GOOGLE_SERVICE_ACCOUNT_KEY`| No*      | Path to service account JSON key file                    |
| `GOOGLE_ADMIN_EMAIL`        | No*      | Admin email for service account impersonation            |
| `SESSION_SECRET`            | Yes      | Random string for session encryption                     |
| `PORT`                      | No       | Server port (default: 3000)                              |
| `NODE_ENV`                  | No       | Environment: `development` or `production`               |
| `DB_PATH`                   | No       | SQLite database path (default: `./superkey.db`; `/data/superkey.db` in the container) |
| `AGENT_API_TOKEN`           | No       | Bearer token for the team-agent registration API. Unset = agent API disabled |
| `DEPLOY_API_TOKEN`          | No**     | Bearer token for `/api/deploy-data`, `/api/stale-servers`, `/api/servers/:hostname/deployed`. Unset = deploy API disabled |
| `DEPLOY_PUBKEY`             | No**     | Machine deploy public key served at `/api/deploy-key` |
| `SSH_CONFIGS_REPO`          | No       | Checkout of the hostnames repo (default: `~/hostnames`) |
| `SSH_CONFIGS_PATH`          | No       | Path to SSH config files for import (default: `$SSH_CONFIGS_REPO/ssh-configs`) |
| `SERVER_IMPORT_INTERVAL_MS` | No       | How often servers are re-imported from the hostnames repo (default: 5 min) |
| `GROUP_SYNC_INTERVAL_MS`    | No       | How often groups are synced from Google, with a service account (default: 1 h) |
| `RESTRICTED_SERVERS_PATH`   | No       | Path to the restricted-servers policy (default: `restricted-servers.json` in the repo) |
| `PUBLIC_URL`                | No***    | External base URL (e.g. `https://superkey.ops.logivations.com`); OAuth issuer and `/mcp` resource are built from it |

*Service account is optional but strongly recommended for complete group sync.
**Written into `.env` automatically by `scripts/setup-deploy-runner.sh` on the superkey host.
***Falls back to the origin of `GOOGLE_CALLBACK_URL`. Must be https (or localhost) or /mcp is disabled.

### Google Cloud Setup

#### 1. OAuth Credentials (Required)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Navigate to APIs & Services → Credentials
4. Create OAuth 2.0 Client ID (Web application)
5. Add authorized redirect URI: `http://localhost:3000/auth/google/callback`
6. Copy Client ID and Secret to `.env`

#### 2. Service Account (Recommended)

Without a service account, group sync is limited to what the logged-in user's OAuth token can see. With a service account, Superkey can sync ALL users and groups from the domain.

1. Create a service account in Google Cloud Console
2. Enable **domain-wide delegation**
3. Download the JSON key file
4. In Google Workspace Admin Console, authorize the service account with these scopes:
   - `https://www.googleapis.com/auth/admin.directory.user.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.readonly`
   - `https://www.googleapis.com/auth/admin.directory.group.member.readonly`
5. Set `GOOGLE_SERVICE_ACCOUNT_KEY` and `GOOGLE_ADMIN_EMAIL` in `.env`

---

## Server Deployment

Deploys run automatically from the superkey host with a dedicated machine
key (`/root/superkey-deploy-key`). Admin personal keys are never installed on
the `superkey-deploy` account.

### Step 1: One-Time Server Setup

Each target server needs a `superkey-deploy` user with passwordless sudo that
the deploy runner can SSH into. Any admin with sudo on the target enrolls it:

```bash
./scripts/setup-server.sh <hostname>                 # uses your sudo on the target
./scripts/setup-server.sh <hostname> --ssh-user root # fresh hosts
```

The setup script:
1. Creates the `superkey-deploy` user
2. Installs the machine deploy key (fetched from `/api/deploy-key`) as its only
   authorized key
3. Configures passwordless sudo for it

Then add the server with labels in the UI (or let the hostnames-repo import
pick it up). The runner deploys to it within a minute.

### Step 2: Automatic Deploys

On the superkey host, `scripts/setup-deploy-runner.sh` (run by
`auto-update.sh`) generates the machine keypair, writes `DEPLOY_API_TOKEN` /
`DEPLOY_PUBKEY` into `.env` and installs two systemd timers:

- `superkey-deploy.timer`: every minute, `deploy-runner.sh` asks
  `/api/stale-servers` for servers whose `deployed_keys_hash` differs from what
  superkey would deploy now, and deploys only to those.
- `superkey-deploy-full.timer`: a daily full run over every enrolled server,
  catching drift the hash can't see.

After a successful deploy the script reports the new hash via
`POST /api/servers/:hostname/deployed`. **Back up `/root/superkey-deploy-key`**:
it is the only deploy credential.

Manual runs (need `DEPLOY_API_TOKEN`, and off the superkey host `DEPLOY_SSH_KEY`):

```bash
npm run deploy:dry-run                 # preview what would change
npm run deploy                         # all servers
./scripts/deploy.sh --stale            # only out-of-date servers
./scripts/deploy.sh --server muc-amr.cs
```

### What the Deploy Script Does

For each server, the deploy script:

1. **Fetches access data** from `/api/deploy-data`
2. **Connects via SSH** as `superkey-deploy`
3. **Revokes access** for users who are no longer authorized:
   - Removes them from the `superkey`, `logi`, `docker`, `superkey_agents`,
     `superkey_ops`, `adm` and `systemd-journal` groups
   - Deletes their `authorized_keys`
   - Locks their account
   (the same path applies to revoked personal and team agents)
4. **Creates/updates users** who are authorized:
   - Creates system user (username from email: `john.doe@example.com` → `john_doe`)
   - Adds to `superkey` group (marker for Superkey-managed accounts)
   - Adds to `logi` group (shared permissions, e.g. `/data`)
   - Adds to `superkey_ops` group (scoped sudo, see below)
   - Adds to `docker` group (container management)
   - Adds to `adm` and `systemd-journal` groups, when present (read system logs)
   - Sets up SSH authorized_keys with their public key
5. **Creates/updates agent accounts**: personal agents (`<user>_<bot>`) and
   team agents (`agent_<name>`), with the groups described under
   [System Groups on Servers](#system-groups-on-servers)

It also installs `/etc/sudoers.d/superkey-ops`, granting the `superkey_ops`
group **scoped passwordless sudo** for host troubleshooting (`systemctl`,
`journalctl`, `dmesg`, `reboot`, `shutdown`). Only human accounts join that
group. Command paths are resolved per-host and the file is validated with
`visudo` before install. Managed accounts have a locked password and no general
sudo, so this is the only sudo they get. Note that unrestricted `systemctl`
and the `docker` group are root-equivalent in practice; the scope limits what
is *convenient*, not what a determined operator can do.

**Sudoers ownership.** Superkey only ever writes files named
`/etc/sudoers.d/superkey-*`. The deploy account's own rule (`logi` on cameras
and AMRs: `NOPASSWD: ALL`, needed by the unattended update path) is the deploy
repo's, in `/etc/sudoers.d/deploy-<user>`, provisioned by
`linux/utilities/ensure_deploy_sudoers.sh`. Until 2026-09 superkey wrote its
rule as `%logi …` into `/etc/sudoers.d/logi`, the deploy repo's file, which
replaced the deploy rule and silently broke every unattended update on such
hosts ([RTDTK-967](https://lvserv01.logivations.com/browse/RTDTK-967)).
The deploy script removes that legacy file when it holds a single line superkey
wrote (`%logi ALL=(ALL) NOPASSWD: …`) and, on every run, prints a note when the
host's deploy account has no passwordless sudo of its own, naming the deploy
repo's command to provision it:
`sudo bash ~logi/deploy/linux/utilities/ensure_deploy_sudoers.sh logi`.

`/data` is `3775` (setgid, group-writable, sticky): managed accounts may add
entries but not rename or unlink what they do not own, because the deploy
tooling runs `/data/monitoring` as root.

It also installs `/etc/sudoers.d/superkey-agents`
(`%superkey_agents ALL=(<deploy user>) NOPASSWD: ALL`, also `visudo`-validated)
and puts team agents, plus personal agents whose owner enabled **Root
access**, in `superkey_agents`. See the group table below for why; in short, the
deploy tooling is only correct when run as the deploy user, those agents
already have `docker`, and going through `sudo -u` makes every action auditable
(`journalctl _COMM=sudo`). Hosts without a `logi`/`administrator`/`ubuntu`
account skip the rule with a message.

### System Groups on Servers

| Group      | Purpose                                                                   |
|------------|---------------------------------------------------------------------------|
| `superkey` | Marker group. All Superkey-managed users are in this group. Used to identify which accounts can be safely managed (revoked) by Superkey without affecting other system users. |
| `logi`     | Access group. Used for shared permissions like access to certain directories (`/data`). Carries no sudo rule of its own: the `logi` *user* is the deploy account, with its own rule owned by the deploy repo. |
| `docker`   | Humans and team agents always; personal agents only with **Root access**. Root-equivalent in practice. |
| `superkey_ops` | **Humans only.** Carries `/etc/sudoers.d/superkey-ops`: scoped NOPASSWD sudo (`systemctl`, `journalctl`, `dmesg`, `reboot`, `shutdown`) for host troubleshooting. Bots, agents and the deploy account are never in it. |
| `adm` / `systemd-journal` | Standard system groups. Managed users are added to these (when present) so they can read full system/kernel logs via `journalctl`. |
| `superkey_agents` | **Team agents, and personal agents with Root access.** Carries `/etc/sudoers.d/superkey-agents`: `%superkey_agents ALL=(<deploy user>) NOPASSWD: ALL`, where the deploy user is the first of `logi`/`administrator`/`ubuntu` that exists and owns a `~/deploy` checkout. It lets an agent drive the deploy tooling (`checkout_release_deepcv`, `checkout_master`, `update_w2mo`, `run_docker.sh`) as that user — which is the only way those scripts are correct, since `run_docker.sh` mounts the invoking user's home into the container. Running as the deploy user, an agent inherits whatever sudo that account has (on cameras and AMRs: `NOPASSWD: ALL`, from the deploy repo's rule). Every member also holds `docker` (root-equivalent), so this is no new privilege tier; it is the supported path plus a sudo audit trail. Personal agents join it (together with `docker`) only when their owner enables **Root access** under My agents > Access, and leave both on the next deploy when it is switched off. |

---

## Database Backups

`scripts/backup-db.sh` snapshots the SQLite database daily at 03:15. It uses
SQLite's online backup API inside the running app container (the host has no
`sqlite3` CLI), so the copy stays consistent while the app writes. Snapshots
land in `data/backups/superkey-<stamp>.db.gz` on the superkey host; anything
older than 30 days is pruned (`SUPERKEY_BACKUP_DIR`,
`SUPERKEY_BACKUP_KEEP_DAYS`). `auto-update.sh` installs the cron entry
(`/etc/cron.d/superkey-backup`) itself, and logs go to `backup.log`.

To recover data, `zcat` a snapshot and read it with better-sqlite3 via
`docker exec superkey-superkey-1 node -e …`. Match users by email, not id:
a Google resync can recreate users with new ids. Don't copy files into the
host's checkout outside `data/`: an untracked file there silently blocks
auto-update's `git pull`.

---

## API Reference

All endpoints require authentication via Google SSO session unless noted.
OAuth access tokens issued for the MCP endpoint (`sk_oat_...`, see
[MCP](#mcp)) are **not** accepted on `/api/*`: such requests get 401 and never
touch the session, so a cookie sent along is ignored too.

### Authentication

| Endpoint                  | Method | Description                          |
|---------------------------|--------|--------------------------------------|
| `/auth/google`            | GET    | Initiate Google OAuth login          |
| `/auth/google/callback`   | GET    | OAuth callback (handled by Passport) |
| `/auth/logout`            | GET    | Log out                              |

### User Endpoints

| Endpoint                  | Method | Auth    | Description                          |
|---------------------------|--------|---------|--------------------------------------|
| `/api/me`                 | GET    | User    | Get current user info                |
| `/api/me/public-key`      | PUT    | User    | Update current user's SSH public key |
| `/api/me/bots`            | GET    | User    | List the current user's bot keys     |
| `/api/me/bots`            | POST   | User    | Create/rotate a bot key (`name`, `publicKey`, optional `sourceCidr`) |
| `/api/me/bots/:id`        | DELETE | User    | Revoke one of the current user's bots |
| `/api/me/bots/:id/access` | PUT    | User    | Set `labelScoped` and/or `docker` (Root access) on an own bot |
| `/api/me/reachable-labels`| GET    | User    | Labels of devices the user reaches (the bot label picker) |
| `/api/me/bots/:id/labels/:labelId` | POST/DELETE | User | Attach/detach a scoping label on an own bot |
| `/api/me/labels`          | GET    | User    | Labels the user may grant to team agents (all for admins) |
| `/api/users`              | GET    | Admin   | List all users (incl. `bot_count`)   |
| `/api/users/:id`          | GET    | Admin   | Get specific user                    |

### Team Agent Endpoints

| Endpoint                          | Method | Auth    | Description                          |
|-----------------------------------|--------|---------|--------------------------------------|
| `/api/agents/register`            | POST   | Agent API* | Register/rotate a team agent (`name`, `publicKey`, optional `sourceCidr`, `description`, `maintainers` = emails; sent replaces, absent keeps) |
| `/api/agents/register/:name`      | DELETE | Agent API* | Deregister a team agent            |
| `/api/agents`                     | GET    | User    | List team agents with labels, `maintainers` and the caller's `can_manage` |
| `/api/agents/:agentId/labels/:labelId` | POST/DELETE | User | Attach/detach a label (only labels the user holds, and only as a maintainer if the agent has any; admins any) |
| `/api/agents/:id`                 | DELETE | Admin   | Delete a team agent                  |

*`Authorization: Bearer $AGENT_API_TOKEN`; the API is disabled when the token is unset.

### Server Endpoints

| Endpoint                  | Method | Auth    | Description                          |
|---------------------------|--------|---------|--------------------------------------|
| `/api/servers`            | GET    | User    | List all servers                     |
| `/api/servers`            | POST   | Admin   | Create a new server                  |
| `/api/servers/:id`        | PUT    | Admin   | Update a server                      |
| `/api/servers/:id`        | DELETE | Admin   | Delete a server                      |
| `/api/servers/:serverId/labels/:labelId` | POST/DELETE | Admin | Apply/remove a label on a server |
| `/api/servers/:id/download-setup` | GET | Admin | Manual setup package for a server (same policy as deploy-data) |
| `/api/import-servers`     | POST   | Admin   | Import servers from SSH config files (also runs every 5 min) |
| `/api/ssh-configs-commit-date` | GET | Admin  | Last commit date of the hostnames repo |

### Label Endpoints

| Endpoint                      | Method | Auth    | Description                          |
|-------------------------------|--------|---------|--------------------------------------|
| `/api/labels`                 | GET    | User    | List all labels                      |
| `/api/labels`                 | POST   | Admin   | Create a new label                   |
| `/api/labels/:id`             | DELETE | Admin   | Delete a label                       |
| `/api/labels/:id/groups`      | GET    | User    | Get groups assigned to a label       |
| `/api/labels/:id/groups/:gid` | POST   | Admin   | Assign a group to a label            |
| `/api/labels/:id/groups/:gid` | DELETE | Admin   | Remove a group from a label          |

### Group Endpoints

| Endpoint                  | Method | Auth    | Description                          |
|---------------------------|--------|---------|--------------------------------------|
| `/api/groups`             | GET    | User    | List all groups                      |
| `/api/groups`             | POST   | Admin   | Create a manual group                |
| `/api/groups/:id`         | PUT    | Admin   | Update a group                       |
| `/api/groups/:id`         | DELETE | Admin   | Delete a group (cannot delete superkey_admins) |
| `/api/groups/:id/users`   | GET    | User    | Get users in a group                 |

### Sync & Admin Endpoints

| Endpoint                     | Method | Auth    | Description                          |
|------------------------------|--------|---------|--------------------------------------|
| `/api/sync-groups`           | POST   | User    | Sync current user's groups           |
| `/api/sync-all-groups`       | POST   | Admin   | Full sync of all users/groups from Google |
| `/api/service-account-status`| GET    | Admin   | Check if service account is configured |

### Access View Endpoints

| Endpoint                  | Method | Auth    | Description                          |
|---------------------------|--------|---------|--------------------------------------|
| `/api/my-servers`         | GET    | User    | Servers the current user can access  |
| `/api/user-servers/:id`   | GET    | Admin   | Servers a specific user can access   |
| `/api/bot-servers/:id`    | GET    | Admin   | Servers a personal agent reaches     |
| `/api/agent-servers/:id`  | GET    | Admin   | Servers a team agent reaches         |
| `/api/server-access/:id`  | GET    | Admin   | Users who can access a specific server |

### Deployment

| Endpoint                  | Method | Auth    | Description                          |
|---------------------------|--------|---------|--------------------------------------|
| `/api/deploy-data`        | GET    | Deploy API* | All servers with authorized users, their bots and team agents |
| `/api/stale-servers`      | GET    | Deploy API* | Hostnames whose deployed keys hash is out of date |
| `/api/servers/:hostname/deployed` | POST | Deploy API* | Record a successful deploy (`keys_hash`) |
| `/api/deploy-key`         | GET    | None    | The machine deploy public key (`DEPLOY_PUBKEY`), used by `setup-server.sh` |

*`Authorization: Bearer $DEPLOY_API_TOKEN`; the API is disabled when the token is unset.

### MCP

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/mcp`   | POST   | OAuth bearer | MCP Streamable HTTP, stateless, JSON responses; GET/DELETE answer 405 |
| `/.well-known/oauth-protected-resource[/mcp]` | GET | None | RFC 9728 metadata (resource = `<PUBLIC_URL>/mcp`) |
| `/.well-known/oauth-authorization-server` | GET | None | RFC 8414 metadata |
| `/register` | POST | None | RFC 7591 dynamic client registration (public clients; redirect URIs `https://` or loopback `http://` only; 20/h per IP) |
| `/authorize` | GET/POST | Session | Code + PKCE S256; resource must be `/mcp`; parks the request and redirects to the consent page (via Google login) |
| `/oauth/consent` | GET/POST | Session | Consent page; approval needs the CSRF token stored in the same session |
| `/token` | POST | Client id | `authorization_code` (PKCE) and `refresh_token` (rotating) grants |
| `/revoke` | POST | Client id | RFC 7009; revoking any token of a grant ends the grant |
| `/api/me/oauth-grants` | GET | Session | Own connected apps (client name, redirect host, created, last used) |
| `/api/me/oauth-grants/:id` | DELETE | Session | Disconnect one |

The authorization server (`src/oauth.js`) is built on the SDK's
`mcpAuthRouter` / `requireBearerAuth` with a SQLite-backed provider. Issuer
and resource URLs come from `PUBLIC_URL` (fallback: origin of
`GOOGLE_CALLBACK_URL`, then `http://localhost:$PORT`); an http issuer other
than localhost disables /mcp (503) instead of failing startup. Flow:
`/authorize` stores the request (10 min) → Google login if needed
(`returnTo` survives the login via `keepSessionInfo`) → consent page shows
client name (self-asserted), redirect host and what is granted, as whom →
Approve issues a 5-minute single-use code (replay revokes its grant) →
`/token` checks PKCE, redirect URI and resource and creates the grant.
Access tokens: 1 h, opaque, sha256-stored, bound to the `/mcp` resource.
Refresh tokens: rotated on every use, 30-day sliding expiry; presenting an
already-rotated one revokes the grant (both parties lose it). The user row is
re-read on every request, so a user removed by the Google sync loses access
at once. Client ID Metadata Documents are not supported (the SDK has no
server-side support; DCR covers Claude Code).

Each POST builds a fresh MCP server bound to the user who approved the
connection. Tools:
`whoami`, `search_servers {query?, label?, limit?}`, `list_grantable_labels`,
`list_agents {query?}`, `grant_label {agent, label}`,
`revoke_label {agent, label}`, `deploy_status {agent?, label?}`,
`list_my_bots`. Their names and arguments are a contract (the nemo
team-agent skill calls them). Grant/revoke go through the same
`grantAgentLabel` / `revokeAgentLabel` functions as the HTTP routes, so the
"only labels you hold" rule and the restricted-servers checks are shared.
`deploy_status` compares each server's `deployed_keys_hash` with the hash
superkey would deploy now (`deployed`), else `pending` (deployed before) or
`never-deployed`.

---

## Troubleshooting

### "Service account not configured" warning

The service account is optional but recommended. Without it:
- User/group sync only works for logged-in users
- Admin "Sync All" button won't work
- Groups may be incomplete

**Fix**: Follow the [Service Account setup](#2-service-account-recommended) instructions.

### Deploy script can't connect to a server

```
ERROR: Cannot connect to superkey-deploy@hostname via SSH, skipping...
```

**Causes**:
- Server not enrolled (`superkey-deploy` missing or without the machine key) → Run `./scripts/setup-server.sh <hostname>`
- Manual run off the superkey host without the machine key → Set `DEPLOY_SSH_KEY`
- Network/firewall issue → Check SSH access manually

Runner logs: `journalctl -u superkey-deploy.service` on the superkey host.

### User has no access but should

Check the access chain:
1. Is the user synced? (`/api/users` should list them)
2. Is their group synced? (`/api/groups/:id/users` should show them)
3. Is the group assigned to a label? (`/api/labels/:id/groups`)
4. Is the server tagged with that label? (`/api/servers`)

### User still has access after removal

Access is revoked on the next deploy, which the runner starts within a
minute of the change. To force it:
```bash
./scripts/deploy.sh --server <hostname>
```

The deploy script will:
1. Check who should have access
2. Lock accounts and remove keys for unauthorized users

### Agent lacks new groups after a change

Group changes (e.g. switching Root access on) only take effect in new login
sessions. Reconnect the agent after the next deploy.

---

## File Structure

```
superkey/
├── src/
│   ├── server.js      # Main Express application
│   ├── database.js    # SQLite database setup and migrations
│   ├── restricted.js  # restricted-servers.json policy
│   ├── oauth.js       # OAuth 2.1 authorization server for /mcp
│   └── mcp.js         # MCP endpoint (/mcp) and its tools
├── test/              # node:test suite (npm test), temp SQLite DB
├── public/            # Frontend static files
├── scripts/
│   ├── setup-server.sh         # One-time server enrollment
│   ├── deploy.sh               # Deploy keys/accounts to servers
│   ├── deploy-runner.sh        # Timer entry point (stale / --full)
│   ├── setup-deploy-runner.sh  # Machine key, tokens, systemd timers
│   ├── auto-update.sh          # Pull main + redeploy the app (root cron)
│   ├── backup-db.sh            # Daily SQLite snapshot
│   └── migrate-deploy-key.sh   # Move old servers to the machine key
├── restricted-servers.json  # Restricted-server policy (change via commit)
├── docker-compose.yml # App + Caddy
├── .env.example       # Environment variable template
├── package.json
└── docs/
    └── internal.md    # This file
```