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

Set up the deploy user on each server (one-time):
```bash
./scripts/setup-server.sh <hostname> ~/.ssh/id_rsa.pub
```

Deploy SSH keys to all configured servers:
```bash
npm run deploy          # deploy to all servers
npm run deploy:dry-run  # preview changes
```

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
