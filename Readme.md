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
