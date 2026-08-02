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
hosts.txt` from an admin machine — it replaces `superkey-deploy`'s
authorized_keys with the machine key on each host.

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
    { "match": "prod-*", "allowed_groups": ["infra_core"], "allow_agents": false }
  ]
}
```

`match` is a hostname glob (`*`/`?`). Multiple matching rules merge
(union of groups, agents allowed if any rule allows). The policy is
enforced in `/api/deploy-data` (authoritative), the access views, the
manual setup download, and the UI actions that would contradict it.

## Agents

Two kinds of automation identities, both deployed as separate, unprivileged
Linux accounts (groups `superkey, adm, systemd-journal`; hardened
`restrict,pty` keys, optional `from=` source restriction):

- **Personal agents** ("My Agents" tab): owned by a user, log in as
  `<user>_<name>`, and reach exactly the devices the owner can — access is
  inherited and capped, revocable by the owner any time.
- **Team agents** ("Team Agents" tab): shared nemo agents with no owner.
  The nemo dispatcher registers them automatically via
  `POST /api/agents/register` (machine auth: `AGENT_API_TOKEN` bearer
  token); they start with **no access**. Signed-in users attach **labels**
  to an agent — it can then reach the devices carrying those labels, as
  `agent_<name>`. Users can only attach labels they hold themselves
  (admins: any label). Deleting a team agent (admin) locks its accounts on
  the next deploy.
