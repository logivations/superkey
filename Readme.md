# Superkey

SSH public key management tool with Google Workspace integration.

## Features

- **Google SSO** - Users authenticate with Google accounts
- **SSH Key Management** - Users upload their public SSH keys
- **Server Management** - Servers tagged with labels, import from SSH config files
- **Group Sync** - Users and groups synced from Google Workspace
- **Access Control** - Assign groups to labels to control server access
- **Admin Views** - See who has access to what
- **Deployment** - Automated user provisioning on remote servers
- **Agents** - Personal and team automation accounts with hardened keys
- **MCP endpoint** - OAuth-connected MCP server for Claude Code / agents

Details (deploy internals, server groups, sudoers, API): [docs/internal.md](docs/internal.md).

## Setup

1. Copy `.env.example` to `.env` and configure:
   - Google OAuth credentials
   - Service account for Workspace sync (optional but recommended)

2. Install and run:
   ```bash
   npm install
   npm start
   ```

3. Access at `http://localhost:3000`

## Deployment to Servers

Deploys run **automatically from the superkey host** with a dedicated
machine key (`/root/superkey-deploy-key`) — admin personal keys are never
installed on the `superkey-deploy` account. A systemd timer checks every
minute for servers whose keys are out of date (`/api/stale-servers`) and
deploys only to those; a daily full run reconciles drift.

Enrolling a new server (one-time, any admin with sudo on the target):
```bash
./scripts/setup-server.sh <hostname>              # or --ssh-user root for fresh hosts
```
This installs the machine deploy key (fetched from `/api/deploy-key`) for
the `superkey-deploy` user. Add the server with labels in the UI and the
runner picks it up within a minute.

On the superkey host itself, `scripts/setup-deploy-runner.sh` (run
automatically by `auto-update.sh`) generates the machine keypair, writes
`DEPLOY_API_TOKEN`/`DEPLOY_PUBKEY` into `.env` and installs the
`superkey-deploy.timer` / `superkey-deploy-full.timer` systemd units.
**Back up `/root/superkey-deploy-key`** — it is the only deploy credential.

Migrating servers enrolled under the old scheme (admin keys on
`superkey-deploy`): run `./scripts/migrate-deploy-key.sh --from-file
hosts.txt` from an admin machine — by default it ADDS the machine key to
`superkey-deploy`'s authorized_keys (admin keys keep working); with
`--replace` it swaps authorized_keys to the machine key only (final
cutover).

Manual runs are still possible:
```bash
npm run deploy          # deploy to all servers
npm run deploy:dry-run  # preview changes
./scripts/deploy.sh --stale   # only out-of-date servers
```
(Requires `DEPLOY_API_TOKEN` and, off the superkey host, `DEPLOY_SSH_KEY`.)

## Docker

```bash
docker-compose up -d
```

On the superkey host, a root cron runs `scripts/auto-update.sh`: it pulls
`main` and rebuilds the app when there are new commits, so pushing to `main`
deploys superkey itself. It also keeps the deploy runner and the daily
database backup (`scripts/backup-db.sh`, snapshots in `data/backups/`, 30
days) installed.

## Access Model

- Users belong to **groups** (synced from Google Workspace)
- Servers are tagged with **labels**
- Groups are assigned to labels
- Users get access to servers via their group memberships
- Admins are members of the `superkey_admins` group

### Restricted servers

Servers matching a rule in **`restricted-servers.json`** are restricted:
only members of the rule's `allowed_groups` are ever deployed there, no
matter what labels/groups are wired up in the UI, and team agents are
blocked unless `allow_agents` is set. The file lives in git on purpose —
any admin can change label/group assignments through the API without a
trace, but widening access to a restricted server requires a commit.

```json
{
  "restricted_servers": [
    { "match": "prod-*", "allowed_groups": ["infra_core"], "allow_agents": false },
    { "match": "mcpservers", "allowed_users": ["johannes.plapp@lvairo.com"], "allow_agents": true }
  ]
}
```

`match` is a hostname glob (`*`/`?`). `allowed_groups` members still need
the usual label wiring; `allowed_users` emails are granted directly by the
file (no label needed — group grants on such servers are refused). When
`allowed_users` is set, ONLY those users may attach/detach agent labels
touching the server — superkey admins are not exempt. Multiple matching
rules merge (union of lists, agents allowed if any rule allows). The
policy is enforced in `/api/deploy-data` (authoritative), the access
views, the manual setup download, and the UI actions that would
contradict it.

## Agents

Two kinds of automation identities, both deployed as separate Linux
accounts (hardened `restrict,pty` keys, optional `from=` source
restriction). Personal bots get groups `superkey, adm, systemd-journal`
(read-only logs, no sudo), plus `docker` and `superkey_agents` (run-as the
deploy user) when the owner enables **Root access** per agent under
**Access** (the owner is in docker/logi on those hosts anyway); team
agents always join both:

- **Personal agents** ("My agents" tab): owned by a user, log in as
  `<user>_<name>`, and reach the devices the owner can — access is
  inherited and capped, revocable by the owner any time. Under **Access**
  the owner can limit an agent to devices carrying chosen labels (only
  labels of devices they reach; no labels = no access), the same model as team agents
  but still never beyond the owner's own reach. Unlimited is the default.
- **Team agents** ("Team agents" tab): shared nemo agents with no owner.
  The nemo dispatcher registers them automatically via
  `POST /api/agents/register` (machine auth: `AGENT_API_TOKEN` bearer
  token); they start with **no access**. Signed-in users attach **labels**
  to an agent — it can then reach the devices carrying those labels, as
  `agent_<name>`. Users can only attach labels they hold themselves
  (admins: any label). The dispatcher also sends the agent's
  **maintainers** (its nemo owner + whoever it is shared with); when an
  agent has maintainers, only they (and admins) may change its labels —
  agents without any keep the "anyone holding the label" rule. Deleting a team agent (admin in the UI, or the
  dispatcher via `DELETE /api/agents/register/<name>` when the nemo agent
  is deleted) locks its accounts on the next deploy.

Both kinds are subjects in the admin **Who can reach what** lens, alongside
people, groups and labels: pick an agent to light up the devices it reaches.
A team agent stays dark on restricted servers without `allow_agents` —
exactly the hosts it is never deployed to. The per-device panel lists the
agents that reach that device and why.

## MCP / Connected apps

Superkey has an **MCP endpoint** at `https://superkey.ops.logivations.com/mcp`
(Streamable HTTP, stateless) for Claude Code and other MCP clients. It uses
**OAuth 2.1** with Superkey as its own authorization server (MCP
authorization spec 2025-11-25): no tokens to copy around.

```bash
claude mcp add --transport http superkey https://superkey.ops.logivations.com/mcp
```

Then in Claude Code: `/mcp` → **superkey** → **Authenticate**. The browser
opens Superkey (Google sign-in if needed) and shows a **consent page** —
which app, where the authorization goes (`localhost` for Claude Code), and
what it may do — Approve, and Claude Code is connected. Approved apps are
listed under **Connected apps** in the web UI, where you can disconnect them.

What a connection can do is the MCP tools below, as you, through the same
permission checks as the web UI: read, and attach/detach team-agent labels
you hold. OAuth tokens are only accepted at `/mcp` — never on `/api/*` — so
a connection can't touch your SSH key, your agents or admin settings.
Access tokens live 1 h; refresh tokens rotate (30 days sliding) and a
replayed one revokes the connection.

Tools (each runs as the user who approved the connection):

| Tool | Arguments | What it does |
|------|-----------|--------------|
| `whoami` | — | Email, Linux username, admin flag, groups |
| `search_servers` | `query?`, `label?`, `limit?` | Servers (whole fleet, as in the UI) with labels, restricted flag, whether you reach them, deploy state |
| `list_grantable_labels` | — | Labels you may attach to team agents, with server counts, holding groups and whether a restricted server blocks the grant |
| `list_agents` | `query?` | Team agents with account (`agent_<name>`), description and labels |
| `grant_label` | `agent`, `label` | Attach a label to a team agent (only labels you hold; admins any; restricted servers enforced). Idempotent |
| `revoke_label` | `agent`, `label` | Detach it. Idempotent |
| `deploy_status` | `agent?`, `label?` | Per server whether the agent's key / the current key set is deployed: deployed / pending / never-deployed |
| `list_my_bots` | — | Your personal agents (read-only) |

`agent` and `label` take a name (agents also their account `agent_<name>`)
or a numeric id. Deploys are automatic: the runner deploys out-of-date
servers every minute, so `pending` normally clears within 1-2 minutes;
offline robots stay pending until they are back.
