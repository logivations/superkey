# Superkey - Internal Documentation

**Superkey** is an SSH public key management tool that automates server access provisioning using Google Workspace as the source of truth for users and groups.

---

## Table of Contents

1. [What is Superkey?](#what-is-superkey)
2. [Architecture Overview](#architecture-overview)
3. [Access Model](#access-model)
4. [Technology Stack](#technology-stack)
5. [Getting Started](#getting-started)
6. [Configuration](#configuration)
7. [Server Deployment](#server-deployment)
8. [API Reference](#api-reference)
9. [Troubleshooting](#troubleshooting)

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
5. Deploy script pushes SSH keys to authorized servers

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

### Admin Access

Admins are members of the `superkey_admins` Google Workspace group. They can:

- Manage servers and labels
- View all users and their access permissions
- Assign groups to labels
- Trigger full user/group sync from Google Workspace
- Run deployments

---

## Technology Stack

| Component          | Technology                                         |
|--------------------|----------------------------------------------------|
| Backend            | Node.js + Express                                  |
| Database           | SQLite (better-sqlite3)                            |
| Authentication     | Passport.js with Google OAuth 2.0                  |
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
| `DB_PATH`                   | No       | SQLite database path (default: `./superkey.db`)          |
| `SSH_CONFIGS_PATH`          | No       | Path to SSH config files for import (default: `~/hostnames/ssh-configs`) |

*Service account is optional but strongly recommended for complete group sync.

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

Deployment is a two-step process:

### Step 1: One-Time Server Setup

Each target server needs a `superkey-deploy` user that the deploy script can SSH into. This user has passwordless sudo access for managing system users.

```bash
# Generate a dedicated keypair for deployments (if you haven't already)
ssh-keygen -t ed25519 -f ~/.ssh/superkey_deploy -C "superkey-deploy"

# Run setup on each server (requires your personal sudo access)
./scripts/setup-server.sh <hostname> ~/.ssh/superkey_deploy.pub

# Example
./scripts/setup-server.sh muc-amr.cs ~/.ssh/superkey_deploy.pub
```

The setup script:
1. Creates the `superkey-deploy` user
2. Adds the public key to its authorized_keys
3. Configures passwordless sudo for user management commands

### Step 2: Deploy SSH Keys

Once servers are prepared, deploy user access:

```bash
# Preview what would change
npm run deploy:dry-run

# Deploy to all servers
npm run deploy

# Deploy to a specific server
SUPERKEY_URL=http://localhost:3000 ./scripts/deploy.sh --server muc-amr.cs
```

### What the Deploy Script Does

For each server, the deploy script:

1. **Fetches access data** from `/api/deploy-data`
2. **Connects via SSH** as `superkey-deploy`
3. **Revokes access** for users who are no longer authorized:
   - Removes them from `superkey` and `logi` groups
   - Deletes their `authorized_keys`
   - Locks their account
4. **Creates/updates users** who are authorized:
   - Creates system user (username from email: `john.doe@example.com` → `john_doe`)
   - Adds to `superkey` group (marker for Superkey-managed accounts)
   - Adds to `logi` group (for shared permissions)
   - Sets up SSH authorized_keys with their public key

### System Groups on Servers

| Group      | Purpose                                                                   |
|------------|---------------------------------------------------------------------------|
| `superkey` | Marker group. All Superkey-managed users are in this group. Used to identify which accounts can be safely managed (revoked) by Superkey without affecting other system users. |
| `logi`     | Access group. Used for shared permissions like access to certain directories, sudo rules, etc. Configure your server permissions based on membership in this group. |

---

## API Reference

All endpoints require authentication via Google SSO session unless noted.

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
| `/api/users`              | GET    | Admin   | List all users                       |
| `/api/users/:id`          | GET    | Admin   | Get specific user                    |

### Server Endpoints

| Endpoint                  | Method | Auth    | Description                          |
|---------------------------|--------|---------|--------------------------------------|
| `/api/servers`            | GET    | User    | List all servers                     |
| `/api/servers`            | POST   | Admin   | Create a new server                  |
| `/api/servers/:id`        | PUT    | Admin   | Update a server                      |
| `/api/servers/:id`        | DELETE | Admin   | Delete a server                      |
| `/api/import-servers`     | POST   | Admin   | Import servers from SSH config files |

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
| `/api/server-access/:id`  | GET    | Admin   | Users who can access a specific server |

### Deployment

| Endpoint                  | Method | Auth    | Description                          |
|---------------------------|--------|---------|--------------------------------------|
| `/api/deploy-data`        | GET    | None*   | Get all servers with authorized users (used by deploy script) |

*Note: `/api/deploy-data` has no auth for simplicity. In production, consider adding API key auth or network-level protection.

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
ERROR: Cannot connect to superkey-deploy@hostname via SSH
```

**Causes**:
- `superkey-deploy` user doesn't exist → Run `./scripts/setup-server.sh`
- SSH key not in agent → Run `ssh-add ~/.ssh/superkey_deploy`
- Network/firewall issue → Check SSH access manually

### User has no access but should

Check the access chain:
1. Is the user synced? (`/api/users` should list them)
2. Is their group synced? (`/api/groups/:id/users` should show them)
3. Is the group assigned to a label? (`/api/labels/:id/groups`)
4. Is the server tagged with that label? (`/api/servers`)

### User still has access after removal

Access is only revoked on the next deploy run. Run:
```bash
npm run deploy
```

The deploy script will:
1. Check who should have access
2. Lock accounts and remove keys for unauthorized users

---

## File Structure

```
superkey/
├── src/
│   ├── server.js      # Main Express application
│   └── database.js    # SQLite database setup
├── public/            # Frontend static files
├── scripts/
│   ├── setup-server.sh  # One-time server preparation
│   └── deploy.sh        # Deploy SSH keys to servers
├── .env.example       # Environment variable template
├── package.json
└── docs/
    └── internal.md    # This file
```