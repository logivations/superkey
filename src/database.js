const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(process.env.DB_PATH || path.join(__dirname, '..', 'superkey.db'));

// Initialize database schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    google_id TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    name TEXT,
    public_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    google_group_email TEXT UNIQUE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS user_groups (
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS servers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT UNIQUE NOT NULL,
    description TEXT,
    last_deployed_at DATETIME,
    deployed_keys_hash TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS server_labels (
    server_id INTEGER NOT NULL,
    label_id INTEGER NOT NULL,
    PRIMARY KEY (server_id, label_id),
    FOREIGN KEY (server_id) REFERENCES servers(id) ON DELETE CASCADE,
    FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS label_groups (
    label_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    PRIMARY KEY (label_id, group_id),
    FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
  );

  -- Per-user bot keys (a user's PERSONAL agent, e.g. their "nemo").
  -- Each is deployed as a separate, unprivileged Linux account
  -- (<user>_<name>) on exactly the servers the owning user can already
  -- reach. Access is derived from the owner, so a user can never grant a
  -- personal agent more than they have themselves.
  CREATE TABLE IF NOT EXISTS bot_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    source_cidr TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE (user_id, name)
  );

  -- TEAM agents (nemo agents): not owned by a user, registered by the
  -- nemo dispatcher through the machine API with no access at all.
  -- Access is granted per label (agent_labels), like groups get labels —
  -- an agent reaches exactly the servers carrying its labels, as the
  -- account agent_<name> (groups superkey/adm/systemd-journal + docker +
  -- superkey_agents, the latter granting NOPASSWD run-as of the host's deploy
  -- user so the deploy tooling can be driven correctly; personal bots get
  -- docker + superkey_agents only when their owner enabled Root access).
  CREATE TABLE IF NOT EXISTS team_agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    public_key TEXT NOT NULL,
    source_cidr TEXT,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS agent_labels (
    agent_id INTEGER NOT NULL,
    label_id INTEGER NOT NULL,
    PRIMARY KEY (agent_id, label_id),
    FOREIGN KEY (agent_id) REFERENCES team_agents(id) ON DELETE CASCADE,
    FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE
  );

  -- Labels a label-scoped PERSONAL agent is limited to (bot_keys.label_scoped).
  -- Narrowing only: the agent still never lands where its owner can't go.
  CREATE TABLE IF NOT EXISTS bot_labels (
    bot_id INTEGER NOT NULL,
    label_id INTEGER NOT NULL,
    PRIMARY KEY (bot_id, label_id),
    FOREIGN KEY (bot_id) REFERENCES bot_keys(id) ON DELETE CASCADE,
    FOREIGN KEY (label_id) REFERENCES labels(id) ON DELETE CASCADE
  );
`);

// Migrations for existing databases
try {
  db.exec(`ALTER TABLE servers ADD COLUMN last_deployed_at DATETIME`);
} catch (e) { /* Column already exists */ }
try {
  db.exec(`ALTER TABLE servers ADD COLUMN deployed_keys_hash TEXT`);
} catch (e) { /* Column already exists */ }
// 0 = the personal agent follows its owner onto every device (the original
// behaviour, kept for existing agents); 1 = only devices carrying one of its
// bot_labels.
try {
  db.exec(`ALTER TABLE bot_keys ADD COLUMN label_scoped INTEGER NOT NULL DEFAULT 0`);
} catch (e) { /* Column already exists */ }
// 1 = the personal agent also joins docker (root-equivalent on the host; its
// owner is in docker there anyway). Opt-in per agent.
try {
  db.exec(`ALTER TABLE bot_keys ADD COLUMN docker INTEGER NOT NULL DEFAULT 0`);
} catch (e) { /* Column already exists */ }

// Last run of the deploy runner, one row per mode ('stale' = the per-minute
// timer, 'full' = the daily reconcile). The runner POSTs after every run so
// the UI can show it's alive even when there was nothing to deploy.
db.exec(`
  CREATE TABLE IF NOT EXISTS deploy_runs (
    mode TEXT PRIMARY KEY,
    started_at DATETIME,
    finished_at DATETIME NOT NULL,
    exit_code INTEGER NOT NULL
  );
`);

// OAuth 2.1 authorization server for the MCP endpoint (src/oauth.js).
// Clients self-register (RFC 7591) and are public (no secret). A user's
// approval on the consent page yields a short-lived code, exchanged (with
// PKCE) for a grant: one row per connected app, listed under Connected
// apps. Tokens are stored only as sha256; expiries are unix seconds.
db.exec(`
  CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    metadata TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Authorization requests waiting for the user (Google login + consent).
  CREATE TABLE IF NOT EXISTS oauth_requests (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    state TEXT,
    scopes TEXT,
    expires_at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    scopes TEXT,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    grant_id INTEGER
  );

  CREATE TABLE IF NOT EXISTS oauth_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    client_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    scopes TEXT,
    redirect_uri TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    revoked_at DATETIME,
    revoked_reason TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
  CREATE INDEX IF NOT EXISTS idx_oauth_grants_user ON oauth_grants(user_id);

  -- kind: 'access' | 'refresh'. A rotated refresh token keeps its row
  -- (rotated_at set) until it expires, so a replay can be detected.
  CREATE TABLE IF NOT EXISTS oauth_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    rotated_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX IF NOT EXISTS idx_oauth_tokens_grant ON oauth_tokens(grant_id);
`);

// Ensure superkey_admins group exists
db.prepare(`INSERT OR IGNORE INTO groups (name) VALUES ('superkey_admins')`).run();

module.exports = db;
