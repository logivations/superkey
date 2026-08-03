require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SqliteStore = require('better-sqlite3-session-store')(session);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { google } = require('googleapis');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const archiver = require('archiver');
const db = require('./database');
const restricted = require('./restricted');

// Derive the Linux username superkey provisions for an email
// (matches deploy.sh: local-part, dots -> underscores).
function emailToUsername(email) {
  return email.split('@')[0].replace(/\./g, '_');
}

// Linux caps usernames at 32 chars; useradd rejects longer ones outright,
// which would wedge every deploy that includes the account. Over-long names
// are shortened deterministically: keep the recognizable prefix, replace the
// tail with a short hash of the full name so distinct names stay distinct.
const LINUX_USERNAME_MAX = 32;
function fitLinuxUsername(name) {
  if (name.length <= LINUX_USERNAME_MAX) return name;
  const hash = crypto.createHash('sha256').update(name).digest('hex').slice(0, 4);
  return `${name.slice(0, LINUX_USERNAME_MAX - 5)}_${hash}`;
}

// The dedicated, unprivileged Linux account a user's personal agent logs in as.
function botAccount(email, botName) {
  return fitLinuxUsername(`${emailToUsername(email)}_${botName}`);
}

// The Linux account a TEAM agent logs in as. Team agents have no owning
// user; the fixed prefix keeps them recognizable on a host and apart from
// <user>_<bot> personal-agent accounts.
function agentAccount(name) {
  return fitLinuxUsername(`agent_${name}`);
}

// authorized_keys option prefix for a bot key. Bots are non-interactive
// automation, so we lock the key down: `restrict` disables all forwarding
// and `pty` is re-enabled (agents commonly need a tty). An optional source
// restriction (`from=`) means a leaked key is useless off the bot's host.
function botKeyOptions(sourceCidr) {
  let opts = 'restrict,pty';
  if (sourceCidr) opts += `,from="${sourceCidr}"`;
  return opts;
}

// Allowed SSH public-key types (first token of an authorized_keys line).
const SSH_KEY_TYPES = new Set([
  'ssh-ed25519', 'ssh-rsa', 'ssh-dss',
  'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
  'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com'
]);

// Validate a single public key. Rejects multi-line input and anything whose
// first token is not a real key type, so a user can't smuggle authorized_keys
// options (command=, from=, a second key, ...) into the file we deploy.
function isValidPublicKey(key) {
  if (typeof key !== 'string') return false;
  const k = key.trim();
  if (!k || /[\r\n]/.test(k)) return false;
  const parts = k.split(/\s+/);
  if (parts.length < 2) return false;
  if (!SSH_KEY_TYPES.has(parts[0])) return false;
  return /^[A-Za-z0-9+/]+={0,3}$/.test(parts[1]);
}

// Bot names become part of a Linux username, so keep them strict.
function sanitizeBotName(name) {
  if (typeof name !== 'string') return null;
  const n = name.trim().toLowerCase();
  return /^[a-z][a-z0-9_]{0,19}$/.test(n) ? n : null;
}

// Optional `from=` value: comma-separated IPs/CIDRs only, no quotes/newlines.
function isValidSourceList(s) {
  if (s == null || s === '') return true;
  if (typeof s !== 'string' || s.length > 200) return false;
  return /^[0-9a-fA-F:.\/]+(,[0-9a-fA-F:.\/]+)*$/.test(s);
}

const MAX_BOTS_PER_USER = 10;

// Users that will actually be DEPLOYED on a server. This is the single
// source of truth shared by deploy-data, the keys hash, the access views
// and the manual-setup download, so they can never disagree. For servers
// matching restricted-servers.json, label wiring alone is not enough —
// the user must also be in one of the policy's allowed groups.
function serverAuthorizedUsers(server) {
  const policy = restricted.policyFor(server.hostname);
  if (!policy) {
    return db.prepare(`
      SELECT DISTINCT u.id, u.email, u.name, u.public_key FROM users u
      JOIN user_groups ug ON u.id = ug.user_id
      JOIN label_groups lg ON ug.group_id = lg.group_id
      JOIN server_labels sl ON lg.label_id = sl.label_id
      WHERE sl.server_id = ?
      ORDER BY u.email
    `).all(server.id);
  }
  const byId = new Map();
  // Group path: label wiring as usual, but only allowed groups count.
  if (policy.allowed_groups.length > 0) {
    const placeholders = policy.allowed_groups.map(() => '?').join(',');
    for (const u of db.prepare(`
      SELECT DISTINCT u.id, u.email, u.name, u.public_key FROM users u
      JOIN user_groups ug ON u.id = ug.user_id
      JOIN groups g ON g.id = ug.group_id
      JOIN label_groups lg ON ug.group_id = lg.group_id
      JOIN server_labels sl ON lg.label_id = sl.label_id
      WHERE sl.server_id = ? AND g.name IN (${placeholders})
    `).all(server.id, ...policy.allowed_groups)) byId.set(u.id, u);
  }
  // Direct path: emails listed in restricted-servers.json are authorized
  // by the file itself — no label/group wiring needed (or possible: for
  // user-restricted servers, group grants are refused).
  for (const email of policy.allowed_users) {
    const u = db.prepare(
      'SELECT id, email, name, public_key FROM users WHERE lower(email) = ?'
    ).get(email);
    if (u) byId.set(u.id, u);
  }
  return [...byId.values()].sort((a, b) => a.email.localeCompare(b.email));
}

// Team agents to deploy on a server (shared with /api/deploy-data and the
// admin access view). Restricted servers get no team agents unless the
// policy explicitly sets allow_agents.
function serverTeamAgents(server) {
  const policy = restricted.policyFor(server.hostname);
  if (policy && !policy.allow_agents) return [];
  return db.prepare(`
    SELECT DISTINCT a.name, a.public_key, a.source_cidr FROM team_agents a
    JOIN agent_labels al ON a.id = al.agent_id
    JOIN server_labels sl ON al.label_id = sl.label_id
    WHERE sl.server_id = ?
    ORDER BY a.name
  `).all(server.id).map(a => ({
    name: a.name,
    account: agentAccount(a.name),
    public_key: a.public_key,
    source_cidr: a.source_cidr,
    key_options: botKeyOptions(a.source_cidr)
  }));
}

// Personal agents (bots) an admin view attributes to a user. The account
// name is what actually appears on the host, so it is computed here rather
// than reassembled in the browser.
function userBots(user) {
  return db.prepare('SELECT id, name FROM bot_keys WHERE user_id = ? ORDER BY name')
    .all(user.id)
    .map(b => ({ id: b.id, name: b.name, account: botAccount(user.email, b.name) }));
}

// Compute hash of users/keys for a server to detect if deployment is
// up-to-date. Built from the same filtered views deploy-data serves, so a
// restricted server is "up to date" exactly when the FILTERED set is on it.
function computeServerKeysHash(server) {
  const users = serverAuthorizedUsers(server);
  const botsStmt = db.prepare(
    'SELECT name, public_key, source_cidr FROM bot_keys WHERE user_id = ? ORDER BY name'
  );
  const agents = serverTeamAgents(server);
  const data = [
    ...users.filter(u => u.public_key).map(u => `${u.email}:${u.public_key}`),
    ...users.flatMap(u => botsStmt.all(u.id).map(b => `${u.email}/${b.name}:${b.public_key}:${b.source_cidr || ''}`)),
    ...agents.map(a => `agent/${a.name}:${a.public_key}:${a.source_cidr || ''}`)
  ].join('\n');
  return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
}

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Use SQLite for session storage (persists across restarts)
app.use(session({
  store: new SqliteStore({
    client: db,
    expired: {
      clear: true,
      intervalMs: 900000 // 15 min
    }
  }),
  secret: process.env.SESSION_SECRET || 'superkey-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

app.use(passport.initialize());
app.use(passport.session());

// Service account auth for domain-wide group sync
let serviceAccountAuth = null;

function initServiceAccount() {
  const keyPath = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  const adminEmail = process.env.GOOGLE_ADMIN_EMAIL;

  if (keyPath && adminEmail && fs.existsSync(keyPath)) {
    try {
      const key = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
      serviceAccountAuth = new google.auth.JWT({
        email: key.client_email,
        key: key.private_key,
        scopes: [
          'https://www.googleapis.com/auth/admin.directory.user.readonly',
          'https://www.googleapis.com/auth/admin.directory.group.readonly',
          'https://www.googleapis.com/auth/admin.directory.group.member.readonly'
        ],
        subject: adminEmail // Impersonate admin user
      });
      console.log('Service account configured for group sync');
      return true;
    } catch (err) {
      console.error('Failed to load service account:', err.message);
    }
  }
  return false;
}

// Initialize service account on startup
initServiceAccount();

// Sync ALL users and groups from Google Workspace
async function syncAllUsersGroups() {
  if (!serviceAccountAuth) {
    throw new Error('Service account not configured. Set GOOGLE_SERVICE_ACCOUNT_KEY and GOOGLE_ADMIN_EMAIL');
  }

  const admin = google.admin({ version: 'directory_v1', auth: serviceAccountAuth });

  // Step 1: Fetch ALL users from Google Workspace
  console.log('Fetching all users from Google Workspace...');
  let allGoogleUsers = [];
  let pageToken = null;

  do {
    try {
      const response = await admin.users.list({
        customer: 'my_customer',
        maxResults: 500,
        pageToken: pageToken,
        showDeleted: 'false'
      });

      if (response.data.users) {
        allGoogleUsers = allGoogleUsers.concat(response.data.users);
      }
      pageToken = response.data.nextPageToken;
    } catch (err) {
      console.error('Error fetching users:', err.message);
      break;
    }
  } while (pageToken);

  console.log(`Found ${allGoogleUsers.length} users in Google Workspace`);

  // Get active users from Google
  const activeGoogleUsers = allGoogleUsers.filter(u => !u.suspended);
  const activeEmails = new Set(activeGoogleUsers.map(u => u.primaryEmail));

  // Remove users that no longer exist or are suspended in Google
  const localUsers = db.prepare('SELECT * FROM users').all();
  let removedUsers = 0;
  for (const localUser of localUsers) {
    if (!activeEmails.has(localUser.email)) {
      console.log(`  Removing inactive/deleted user: ${localUser.email}`);
      db.prepare('DELETE FROM user_groups WHERE user_id = ?').run(localUser.id);
      db.prepare('DELETE FROM users WHERE id = ?').run(localUser.id);
      removedUsers++;
    }
  }

  // Create users from Google that don't exist locally
  let createdUsers = 0;
  for (const gUser of activeGoogleUsers) {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(gUser.primaryEmail);
    if (!existing) {
      const fullName = gUser.name ? `${gUser.name.givenName || ''} ${gUser.name.familyName || ''}`.trim() : gUser.primaryEmail.split('@')[0];
      db.prepare('INSERT INTO users (google_id, email, name) VALUES (?, ?, ?)').run(gUser.id, gUser.primaryEmail, fullName);
      console.log(`  Created user: ${fullName} (${gUser.primaryEmail})`);
      createdUsers++;
    }
  }

  // Step 2: Fetch ALL groups from Google Workspace
  console.log('Fetching all groups from Google Workspace...');
  let allGoogleGroups = [];
  pageToken = null;

  do {
    try {
      const response = await admin.groups.list({
        customer: 'my_customer',
        maxResults: 200,
        pageToken: pageToken
      });

      if (response.data.groups) {
        allGoogleGroups = allGoogleGroups.concat(response.data.groups);
      }
      pageToken = response.data.nextPageToken;
    } catch (err) {
      console.error('Error fetching groups:', err.message);
      break;
    }
  } while (pageToken);

  console.log(`Found ${allGoogleGroups.length} groups in Google Workspace`);

  // Get Google group emails
  const googleGroupEmails = new Set(allGoogleGroups.map(g => g.email));

  // Remove groups that no longer exist in Google (except those without google_group_email)
  const localGroups = db.prepare("SELECT * FROM groups WHERE google_group_email IS NOT NULL AND google_group_email != ''").all();
  let removedGroups = 0;
  for (const localGroup of localGroups) {
    if (!googleGroupEmails.has(localGroup.google_group_email)) {
      console.log(`  Removing deleted group: ${localGroup.name} (${localGroup.google_group_email})`);
      db.prepare('DELETE FROM user_groups WHERE group_id = ?').run(localGroup.id);
      db.prepare('DELETE FROM label_groups WHERE group_id = ?').run(localGroup.id);
      db.prepare('DELETE FROM groups WHERE id = ?').run(localGroup.id);
      removedGroups++;
    }
  }

  // Create/update groups in local database
  let createdGroups = 0;
  for (const gGroup of allGoogleGroups) {
    const existingByEmail = db.prepare('SELECT id FROM groups WHERE google_group_email = ?').get(gGroup.email);
    const displayName = gGroup.name || gGroup.email.split('@')[0];

    if (!existingByEmail) {
      // Check if group with same name exists (update its email) or create new
      const existingByName = db.prepare('SELECT id FROM groups WHERE name = ?').get(displayName);
      if (existingByName) {
        db.prepare('UPDATE groups SET google_group_email = ? WHERE id = ?').run(gGroup.email, existingByName.id);
        console.log(`  Updated group: ${displayName} (${gGroup.email})`);
      } else {
        db.prepare('INSERT INTO groups (name, google_group_email) VALUES (?, ?)').run(displayName, gGroup.email);
        console.log(`  Created group: ${displayName} (${gGroup.email})`);
        createdGroups++;
      }
    }
  }

  // Step 3: Sync user-group memberships (fetch members per group - much faster)
  const groupsWithEmail = db.prepare("SELECT * FROM groups WHERE google_group_email IS NOT NULL AND google_group_email != ''").all();
  const users = db.prepare('SELECT * FROM users').all();
  const userEmailToId = new Map(users.map(u => [u.email.toLowerCase(), u.id]));

  console.log(`Syncing memberships for ${groupsWithEmail.length} groups...`);

  // Clear all user_groups and rebuild
  db.prepare('DELETE FROM user_groups').run();

  let syncCount = 0;
  for (const group of groupsWithEmail) {
    try {
      // Fetch all members of this group at once
      let allMembers = [];
      let pageToken = null;

      do {
        const response = await admin.members.list({
          groupKey: group.google_group_email,
          maxResults: 200,
          pageToken: pageToken
        });

        if (response.data.members) {
          allMembers = allMembers.concat(response.data.members);
        }
        pageToken = response.data.nextPageToken;
      } while (pageToken);

      console.log(`  ${group.name}: ${allMembers.length} members`);

      // Match members to local users
      for (const member of allMembers) {
        const userId = userEmailToId.get(member.email.toLowerCase());
        if (userId) {
          db.prepare('INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)').run(userId, group.id);
          syncCount++;
        }
      }
    } catch (err) {
      console.log(`  Error fetching members for ${group.google_group_email}: ${err.message}`);
    }
  }

  console.log(`Sync complete: ${syncCount} memberships found`);
  return {
    googleUsers: allGoogleUsers.length,
    googleGroups: allGoogleGroups.length,
    users: users.length,
    groups: groupsWithEmail.length,
    memberships: syncCount,
    removedUsers,
    createdUsers,
    removedGroups,
    createdGroups
  };
}

// Sync single user's groups (using service account if available, else OAuth token)
async function syncUserGroups(userId, userEmail, accessToken) {
  try {
    let auth;
    if (serviceAccountAuth) {
      auth = serviceAccountAuth;
    } else if (accessToken) {
      const oauth2Client = new google.auth.OAuth2();
      oauth2Client.setCredentials({ access_token: accessToken });
      auth = oauth2Client;
    } else {
      console.log('No auth available for group sync');
      return;
    }

    const admin = google.admin({ version: 'directory_v1', auth });
    const groupsWithEmail = db.prepare("SELECT * FROM groups WHERE google_group_email IS NOT NULL AND google_group_email != ''").all();

    // Clear existing group memberships for this user
    db.prepare('DELETE FROM user_groups WHERE user_id = ?').run(userId);

    for (const group of groupsWithEmail) {
      try {
        const response = await admin.members.hasMember({
          groupKey: group.google_group_email,
          memberKey: userEmail
        });

        if (response.data.isMember) {
          db.prepare('INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)').run(userId, group.id);
          console.log(`User ${userEmail} is member of ${group.google_group_email}`);
        }
      } catch (err) {
        if (err.code !== 404) {
          console.log(`Could not check membership for ${group.google_group_email}: ${err.message}`);
        }
      }
    }
  } catch (err) {
    console.error('Error syncing groups:', err.message);
  }
}

// Passport Google OAuth setup
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value;
      const googleId = profile.id;
      const name = profile.displayName;

      let user = db.prepare('SELECT * FROM users WHERE google_id = ?').get(googleId);

      if (!user) {
        const result = db.prepare('INSERT INTO users (google_id, email, name) VALUES (?, ?, ?)').run(googleId, email, name);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      } else {
        db.prepare('UPDATE users SET email = ?, name = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(email, name, user.id);
      }

      // Sync Google Groups membership
      await syncUserGroups(user.id, email, accessToken);

      // Store access token in user object for session
      user.accessToken = accessToken;

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, { id: user.id, accessToken: user.accessToken });
});

passport.deserializeUser((data, done) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(data.id);
  if (user) {
    user.accessToken = data.accessToken;
  }
  done(null, user);
});

// Auth middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Not authenticated' });
}

function isAdmin(req, res, next) {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Not authenticated' });

  const adminGroup = db.prepare(`
    SELECT g.id FROM groups g
    JOIN user_groups ug ON g.id = ug.group_id
    WHERE g.name = 'superkey_admins' AND ug.user_id = ?
  `).get(req.user.id);

  if (adminGroup) return next();
  res.status(403).json({ error: 'Admin access required' });
}

function isAdminUser(userId) {
  return !!db.prepare(`
    SELECT g.id FROM groups g
    JOIN user_groups ug ON g.id = ug.group_id
    WHERE g.name = 'superkey_admins' AND ug.user_id = ?
  `).get(userId);
}

// Whether a user has access to a label's servers themselves (via any of
// their groups). Users may only grant team agents labels they hold — the
// same "you can't hand out more than you have" rule personal agents get
// by inheritance. Admins bypass this.
function userHasLabel(userId, labelId) {
  return !!db.prepare(`
    SELECT 1 FROM label_groups lg
    JOIN user_groups ug ON lg.group_id = ug.group_id
    WHERE lg.label_id = ? AND ug.user_id = ?
  `).get(labelId, userId);
}

// Machine auth: a single bearer token from the environment; no session,
// no user. Used for the nemo dispatcher (AGENT_API_TOKEN) and the deploy
// runner (DEPLOY_API_TOKEN).
function bearerTokenAuth(envName) {
  return (req, res, next) => {
    const token = process.env[envName];
    if (!token) return res.status(503).json({ error: `API not configured (${envName} unset)` });
    const header = req.headers.authorization || '';
    const provided = header.startsWith('Bearer ') ? header.slice(7) : '';
    const a = Buffer.from(provided);
    const b = Buffer.from(token);
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return next();
    res.status(401).json({ error: 'Bad API token' });
  };
}

const isAgentApi = bearerTokenAuth('AGENT_API_TOKEN');

// The deploy runner on the superkey host is the only legitimate caller of
// the deploy endpoints; they enumerate every user, key and server, so they
// are not public.
const isDeployApi = bearerTokenAuth('DEPLOY_API_TOKEN');

// Auth routes
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
  accessType: 'offline',
  prompt: 'consent'
}));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/')
);

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/api/me', isAuthenticated, (req, res) => {
  const adminGroup = db.prepare(`
    SELECT g.id FROM groups g
    JOIN user_groups ug ON g.id = ug.group_id
    WHERE g.name = 'superkey_admins' AND ug.user_id = ?
  `).get(req.user.id);

  const userGroups = db.prepare(`
    SELECT g.name FROM groups g
    JOIN user_groups ug ON g.id = ug.group_id
    WHERE ug.user_id = ?
  `).all(req.user.id);

  res.json({
    ...req.user,
    accessToken: undefined,
    isAdmin: !!adminGroup,
    groups: userGroups.map(g => g.name)
  });
});

// Sync all users' groups (admin only)
app.post('/api/sync-all-groups', isAdmin, async (req, res) => {
  try {
    const result = await syncAllUsersGroups();
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Sync current user's groups
app.post('/api/sync-groups', isAuthenticated, async (req, res) => {
  try {
    await syncUserGroups(req.user.id, req.user.email, req.user.accessToken);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Service account status
app.get('/api/service-account-status', isAdmin, (req, res) => {
  res.json({
    configured: !!serviceAccountAuth,
    keyPath: process.env.GOOGLE_SERVICE_ACCOUNT_KEY || null,
    adminEmail: process.env.GOOGLE_ADMIN_EMAIL || null
  });
});

// User routes
app.put('/api/me/public-key', isAuthenticated, (req, res) => {
  const { publicKey } = req.body;
  const key = typeof publicKey === 'string' ? publicKey.trim() : '';
  // Allow clearing the key, but reject anything that isn't a clean single key.
  if (key !== '' && !isValidPublicKey(key)) {
    return res.status(400).json({ error: 'Invalid SSH public key (expected a single line like "ssh-ed25519 AAAA...").' });
  }
  db.prepare('UPDATE users SET public_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(key, req.user.id);
  res.json({ success: true });
});

// Bot keys (self-service): a user manages automation keys (e.g. "nemo") that
// are deployed as separate, unprivileged accounts on the servers the user can
// already reach. A user only ever sees/edits their own bots.
app.get('/api/me/bots', isAuthenticated, (req, res) => {
  const bots = db.prepare(
    'SELECT id, name, public_key, source_cidr, created_at FROM bot_keys WHERE user_id = ? ORDER BY name'
  ).all(req.user.id);
  res.json(bots.map(b => ({ ...b, account: botAccount(req.user.email, b.name) })));
});

app.post('/api/me/bots', isAuthenticated, (req, res) => {
  const name = sanitizeBotName(req.body.name);
  const publicKey = typeof req.body.publicKey === 'string' ? req.body.publicKey.trim() : '';
  const sourceCidr = (req.body.sourceCidr || '').trim();

  if (!name) {
    return res.status(400).json({ error: 'Invalid bot name (use 1-20 chars: a-z, 0-9, _, starting with a letter).' });
  }
  if (!isValidPublicKey(publicKey)) {
    return res.status(400).json({ error: 'Invalid SSH public key (expected a single line like "ssh-ed25519 AAAA...").' });
  }
  if (!isValidSourceList(sourceCidr)) {
    return res.status(400).json({ error: 'Invalid source restriction (use comma-separated IPs/CIDRs).' });
  }

  const count = db.prepare('SELECT COUNT(*) AS n FROM bot_keys WHERE user_id = ?').get(req.user.id).n;
  const exists = db.prepare('SELECT 1 FROM bot_keys WHERE user_id = ? AND name = ?').get(req.user.id, name);
  if (!exists && count >= MAX_BOTS_PER_USER) {
    return res.status(400).json({ error: `Bot limit reached (max ${MAX_BOTS_PER_USER}).` });
  }

  // Upsert by (user, name) so re-submitting rotates the key.
  db.prepare(`
    INSERT INTO bot_keys (user_id, name, public_key, source_cidr)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (user_id, name) DO UPDATE SET public_key = excluded.public_key, source_cidr = excluded.source_cidr
  `).run(req.user.id, name, publicKey, sourceCidr || null);

  const bot = db.prepare('SELECT id, name, public_key, source_cidr, created_at FROM bot_keys WHERE user_id = ? AND name = ?').get(req.user.id, name);
  res.json({ ...bot, account: botAccount(req.user.email, bot.name) });
});

app.delete('/api/me/bots/:id', isAuthenticated, (req, res) => {
  const result = db.prepare('DELETE FROM bot_keys WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Bot not found' });
  res.json({ success: true });
});

// ---- Team agents ----------------------------------------------------------
// Registered by the nemo dispatcher (machine token), never by a user. A
// fresh registration has NO access; signed-in users then attach labels.

// Machine registration/rotation. Upsert by name so re-registering with a
// new key rotates it; labels are never touched here.
app.post('/api/agents/register', isAgentApi, (req, res) => {
  const name = sanitizeBotName(req.body.name);
  const publicKey = typeof req.body.publicKey === 'string' ? req.body.publicKey.trim() : '';
  const sourceCidr = (req.body.sourceCidr || '').trim();
  const description = typeof req.body.description === 'string' ? req.body.description.slice(0, 200) : null;

  if (!name) {
    return res.status(400).json({ error: 'Invalid agent name (use 1-20 chars: a-z, 0-9, _, starting with a letter).' });
  }
  if (!isValidPublicKey(publicKey)) {
    return res.status(400).json({ error: 'Invalid SSH public key (expected a single line like "ssh-ed25519 AAAA...").' });
  }
  if (!isValidSourceList(sourceCidr)) {
    return res.status(400).json({ error: 'Invalid source restriction (use comma-separated IPs/CIDRs).' });
  }

  db.prepare(`
    INSERT INTO team_agents (name, public_key, source_cidr, description)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (name) DO UPDATE SET
      public_key = excluded.public_key,
      source_cidr = excluded.source_cidr,
      description = COALESCE(excluded.description, description),
      updated_at = CURRENT_TIMESTAMP
  `).run(name, publicKey, sourceCidr || null, description);

  const agent = db.prepare('SELECT id, name, created_at FROM team_agents WHERE name = ?').get(name);
  res.json({ ...agent, account: agentAccount(agent.name) });
});

app.get('/api/agents', isAuthenticated, (req, res) => {
  const agents = db.prepare(`
    SELECT a.id, a.name, a.public_key, a.source_cidr, a.description, a.created_at
    FROM team_agents a ORDER BY a.name
  `).all();
  const labelsFor = db.prepare(`
    SELECT l.id, l.name FROM labels l
    JOIN agent_labels al ON l.id = al.label_id
    WHERE al.agent_id = ? ORDER BY l.name
  `);
  res.json(agents.map(a => ({
    ...a,
    account: agentAccount(a.name),
    labels: labelsFor.all(a.id)
  })));
});

// Labels the current user may grant to agents: the ones they hold via
// their groups (all labels for admins).
app.get('/api/me/labels', isAuthenticated, (req, res) => {
  if (isAdminUser(req.user.id)) {
    return res.json(db.prepare('SELECT * FROM labels ORDER BY name').all());
  }
  const labels = db.prepare(`
    SELECT DISTINCT l.* FROM labels l
    JOIN label_groups lg ON l.id = lg.label_id
    JOIN user_groups ug ON lg.group_id = ug.group_id
    WHERE ug.user_id = ? ORDER BY l.name
  `).all(req.user.id);
  res.json(labels);
});

app.post('/api/agents/:agentId/labels/:labelId', isAuthenticated, (req, res) => {
  if (!isAdminUser(req.user.id) && !userHasLabel(req.user.id, req.params.labelId)) {
    return res.status(403).json({ error: 'You can only grant labels you have access to yourself.' });
  }
  const agent = db.prepare('SELECT id FROM team_agents WHERE id = ?').get(req.params.agentId);
  const label = db.prepare('SELECT id FROM labels WHERE id = ?').get(req.params.labelId);
  if (!agent || !label) return res.status(404).json({ error: 'Agent or label not found' });
  const blocked = restrictedServersWithLabel(label.id)
    .filter(x => !restricted.userMayManageAgents(x.policy, req.user.email));
  if (blocked.length > 0) {
    return res.status(403).json({
      error: `Label is attached to restricted server(s) ${blocked.map(x => x.server.hostname).join(', ')} ` +
        `where you may not manage agent access (see restricted-servers.json: allow_agents / allowed_users).`
    });
  }
  db.prepare('INSERT OR IGNORE INTO agent_labels (agent_id, label_id) VALUES (?, ?)').run(agent.id, label.id);
  res.json({ success: true });
});

app.delete('/api/agents/:agentId/labels/:labelId', isAuthenticated, (req, res) => {
  if (!isAdminUser(req.user.id) && !userHasLabel(req.user.id, req.params.labelId)) {
    return res.status(403).json({ error: 'You can only remove labels you have access to yourself.' });
  }
  // Removing is narrowing, so only the allowed_users exclusivity applies
  // (cleanup on allow_agents=false servers must stay possible).
  const blocked = restrictedServersWithLabel(req.params.labelId)
    .filter(x => x.policy.allowed_users.length > 0
      && !x.policy.allowed_users.includes((req.user.email || '').toLowerCase()));
  if (blocked.length > 0) {
    return res.status(403).json({
      error: `Label is attached to restricted server(s) ${blocked.map(x => x.server.hostname).join(', ')} ` +
        `where only allowed_users (restricted-servers.json) may manage agent access.`
    });
  }
  db.prepare('DELETE FROM agent_labels WHERE agent_id = ? AND label_id = ?').run(req.params.agentId, req.params.labelId);
  res.json({ success: true });
});

app.delete('/api/agents/:id', isAdmin, (req, res) => {
  const result = db.prepare('DELETE FROM team_agents WHERE id = ?').run(req.params.id);
  if (result.changes === 0) return res.status(404).json({ error: 'Agent not found' });
  res.json({ success: true });
});

app.get('/api/users', isAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.email, u.name, u.public_key, u.created_at,
           (SELECT COUNT(*) FROM bot_keys bk WHERE bk.user_id = u.id) AS bot_count
    FROM users u ORDER BY u.name COLLATE NOCASE
  `).all();
  // Group names inline so the access views can show how someone got their
  // access without a request per user.
  const rows = db.prepare(`
    SELECT ug.user_id, g.name FROM user_groups ug
    JOIN groups g ON g.id = ug.group_id
    ORDER BY g.name COLLATE NOCASE
  `).all();
  const byUser = new Map();
  for (const r of rows) {
    if (!byUser.has(r.user_id)) byUser.set(r.user_id, []);
    byUser.get(r.user_id).push(r.name);
  }
  // Bots inline for the same reason: the access views show a user's personal
  // agents next to the user, and they reach whatever the user reaches.
  res.json(users.map(u => ({ ...u, group_names: byUser.get(u.id) || [], bots: userBots(u) })));
});

app.get('/api/users/:id', isAdmin, (req, res) => {
  const user = db.prepare('SELECT id, email, name, public_key, created_at FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// Import servers from SSH config files
const SSH_CONFIGS_REPO = process.env.SSH_CONFIGS_REPO || path.join(process.env.HOME, 'hostnames');
const SSH_CONFIGS_PATH = process.env.SSH_CONFIGS_PATH || path.join(SSH_CONFIGS_REPO, 'ssh-configs');

function parseSSHConfig(content, configName) {
  const servers = [];
  const lines = content.split('\n');
  let currentHost = null;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('Host ') && !trimmed.includes('*')) {
      if (currentHost) {
        currentHost.description = currentHost.ip ? `${currentHost.ip} (${configName})` : configName;
        servers.push(currentHost);
      }
      currentHost = {
        hostname: trimmed.substring(5).trim(),
        label: configName,
        ip: null
      };
    } else if (currentHost && trimmed.startsWith('HostName ')) {
      currentHost.ip = trimmed.substring(9).trim();
    }
  }

  if (currentHost) {
    currentHost.description = currentHost.ip ? `${currentHost.ip} (${configName})` : configName;
    servers.push(currentHost);
  }

  return servers;
}

// Sync the servers table with the hostnames repo (ssh-configs/*.config).
// Runs on a timer at startup (the repo itself is pulled by auto-update.sh),
// and on demand via POST /api/import-servers.
function importServersFromConfigs() {
  if (!fs.existsSync(SSH_CONFIGS_PATH)) {
    throw new Error(`SSH configs directory not found: ${SSH_CONFIGS_PATH}`);
  }

  const configFiles = fs.readdirSync(SSH_CONFIGS_PATH).filter(f => f.endsWith('.config'));
  let imported = 0;
  let updated = 0;
  const hostnamesInRepo = new Set();

  for (const configFile of configFiles) {
    const configName = configFile.replace('.config', '');
    const content = fs.readFileSync(path.join(SSH_CONFIGS_PATH, configFile), 'utf8');
    const servers = parseSSHConfig(content, configName);

    for (const server of servers) {
      hostnamesInRepo.add(server.hostname);

      // Check if server already exists
      const existing = db.prepare('SELECT id, description FROM servers WHERE hostname = ?').get(server.hostname);
      if (existing) {
        // Update description if it changed (e.g. IP address changed)
        if (existing.description !== server.description) {
          db.prepare('UPDATE servers SET description = ? WHERE id = ?').run(server.description, existing.id);
          updated++;
        }
        continue;
      }

      // Create the server
      const result = db.prepare('INSERT INTO servers (hostname, description) VALUES (?, ?)').run(server.hostname, server.description);
      const serverId = result.lastInsertRowid;

      // Create or get the label
      let label = db.prepare('SELECT id FROM labels WHERE name = ?').get(server.label);
      if (!label) {
        const labelResult = db.prepare('INSERT INTO labels (name) VALUES (?)').run(server.label);
        label = { id: labelResult.lastInsertRowid };
      }

      // Link server to label
      db.prepare('INSERT OR IGNORE INTO server_labels (server_id, label_id) VALUES (?, ?)').run(serverId, label.id);
      imported++;
    }
  }

  // Remove servers that no longer exist in the hostnames repo
  const allDbServers = db.prepare('SELECT id, hostname FROM servers').all();
  let removed = 0;
  for (const dbServer of allDbServers) {
    if (!hostnamesInRepo.has(dbServer.hostname)) {
      // Delete server_labels associations first
      db.prepare('DELETE FROM server_labels WHERE server_id = ?').run(dbServer.id);
      // Delete the server
      db.prepare('DELETE FROM servers WHERE id = ?').run(dbServer.id);
      removed++;
    }
  }

  return { imported, updated, removed, configFiles: configFiles.length };
}

app.post('/api/import-servers', isAdmin, (req, res) => {
  try {
    res.json({ success: true, ...importServersFromConfigs() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get last git commit date from SSH configs directory
app.get('/api/ssh-configs-commit-date', isAdmin, (req, res) => {
  try {
    if (!fs.existsSync(SSH_CONFIGS_REPO)) {
      return res.json({ date: null, error: 'SSH configs repo not found' });
    }
    const { execSync } = require('child_process');
    const gitDate = execSync('git log -1 --format=%ci', {
      cwd: SSH_CONFIGS_REPO,
      encoding: 'utf8'
    }).trim();
    res.json({ date: gitDate });
  } catch (err) {
    res.json({ date: null, error: err.message });
  }
});

// Server routes
app.get('/api/servers', isAuthenticated, (req, res) => {
  const servers = db.prepare(`
    SELECT s.*, GROUP_CONCAT(l.name) as labels
    FROM servers s
    LEFT JOIN server_labels sl ON s.id = sl.server_id
    LEFT JOIN labels l ON sl.label_id = l.id
    GROUP BY s.id
  `).all();
  res.json(servers.map(s => {
    const expectedHash = computeServerKeysHash(s);
    const isUpToDate = s.deployed_keys_hash === expectedHash;
    return {
      ...s,
      labels: s.labels ? s.labels.split(',') : [],
      expected_keys_hash: expectedHash,
      is_up_to_date: isUpToDate,
      restricted: !!restricted.policyFor(s.hostname)
    };
  }));
});

app.post('/api/servers', isAdmin, (req, res) => {
  const { hostname, description, labels } = req.body;
  try {
    const result = db.prepare('INSERT INTO servers (hostname, description) VALUES (?, ?)').run(hostname, description);
    const serverId = result.lastInsertRowid;

    if (labels && labels.length) {
      for (const labelName of labels) {
        let label = db.prepare('SELECT id FROM labels WHERE name = ?').get(labelName);
        if (!label) {
          const labelResult = db.prepare('INSERT INTO labels (name) VALUES (?)').run(labelName);
          label = { id: labelResult.lastInsertRowid };
        }
        db.prepare('INSERT OR IGNORE INTO server_labels (server_id, label_id) VALUES (?, ?)').run(serverId, label.id);
      }
    }

    res.json({ id: serverId, hostname, description, labels: labels || [] });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/servers/:id', isAdmin, (req, res) => {
  const { hostname, description, labels } = req.body;
  const serverId = req.params.id;

  db.prepare('UPDATE servers SET hostname = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(hostname, description, serverId);
  db.prepare('DELETE FROM server_labels WHERE server_id = ?').run(serverId);

  if (labels && labels.length) {
    for (const labelName of labels) {
      let label = db.prepare('SELECT id FROM labels WHERE name = ?').get(labelName);
      if (!label) {
        const labelResult = db.prepare('INSERT INTO labels (name) VALUES (?)').run(labelName);
        label = { id: labelResult.lastInsertRowid };
      }
      db.prepare('INSERT OR IGNORE INTO server_labels (server_id, label_id) VALUES (?, ?)').run(serverId, label.id);
    }
  }

  res.json({ success: true });
});

app.delete('/api/servers/:id', isAdmin, (req, res) => {
  db.prepare('DELETE FROM servers WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Add label to server
app.post('/api/servers/:serverId/labels/:labelId', isAdmin, (req, res) => {
  try {
    db.prepare('INSERT OR IGNORE INTO server_labels (server_id, label_id) VALUES (?, ?)').run(req.params.serverId, req.params.labelId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Remove label from server
app.delete('/api/servers/:serverId/labels/:labelId', isAdmin, (req, res) => {
  try {
    db.prepare('DELETE FROM server_labels WHERE server_id = ? AND label_id = ?').run(req.params.serverId, req.params.labelId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Report deployment status (called by deploy script)
app.post('/api/servers/:hostname/deployed', isDeployApi, (req, res) => {
  const { keys_hash } = req.body;
  const { hostname } = req.params;
  try {
    const result = db.prepare(`
      UPDATE servers
      SET last_deployed_at = datetime('now'), deployed_keys_hash = ?
      WHERE hostname = ?
    `).run(keys_hash, hostname);
    if (result.changes === 0) {
      res.status(404).json({ error: 'Server not found' });
    } else {
      res.json({ success: true });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Label routes
// Labels carry their group grants inline: the UI renders "who can reach this
// label" in a list, and fetching that per row was one request per label.
app.get('/api/labels', isAuthenticated, (req, res) => {
  const labels = db.prepare('SELECT * FROM labels ORDER BY name COLLATE NOCASE').all();
  const grants = db.prepare(`
    SELECT lg.label_id, g.id, g.name FROM label_groups lg
    JOIN groups g ON g.id = lg.group_id
    ORDER BY g.name COLLATE NOCASE
  `).all();
  const byLabel = new Map();
  for (const r of grants) {
    if (!byLabel.has(r.label_id)) byLabel.set(r.label_id, []);
    byLabel.get(r.label_id).push({ id: r.id, name: r.name });
  }
  res.json(labels.map(l => ({ ...l, groups: byLabel.get(l.id) || [] })));
});

app.post('/api/labels', isAdmin, (req, res) => {
  const { name } = req.body;
  try {
    const result = db.prepare('INSERT INTO labels (name) VALUES (?)').run(name);
    res.json({ id: result.lastInsertRowid, name });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/labels/:id', isAdmin, (req, res) => {
  db.prepare('DELETE FROM labels WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// Group routes
app.get('/api/groups', isAuthenticated, (req, res) => {
  const groups = db.prepare(`
    SELECT g.*, (SELECT COUNT(*) FROM user_groups ug WHERE ug.group_id = g.id) AS member_count
    FROM groups g ORDER BY g.name COLLATE NOCASE
  `).all();
  res.json(groups);
});

app.post('/api/groups', isAdmin, (req, res) => {
  const { name, google_group_email } = req.body;
  try {
    const result = db.prepare('INSERT INTO groups (name, google_group_email) VALUES (?, ?)').run(name, google_group_email);
    res.json({ id: result.lastInsertRowid, name, google_group_email });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/groups/:id', isAdmin, (req, res) => {
  const { name, google_group_email } = req.body;
  try {
    db.prepare('UPDATE groups SET name = ?, google_group_email = ? WHERE id = ?').run(name, google_group_email, req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/groups/:id', isAdmin, (req, res) => {
  const group = db.prepare('SELECT name FROM groups WHERE id = ?').get(req.params.id);
  if (group && group.name === 'superkey_admins') {
    return res.status(400).json({ error: 'Cannot delete superkey_admins group' });
  }
  db.prepare('DELETE FROM groups WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// User-Group management (read-only, synced from Google)
app.get('/api/groups/:groupId/users', isAuthenticated, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.email, u.name FROM users u
    JOIN user_groups ug ON u.id = ug.user_id
    WHERE ug.group_id = ?
  `).all(req.params.groupId);
  res.json(users);
});

// Restricted servers carrying this label. Used to refuse UI actions that
// look like they grant access the deploy would silently filter out anyway.
function restrictedServersWithLabel(labelId) {
  return db.prepare(`
    SELECT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    WHERE sl.label_id = ?
  `).all(labelId)
    .map(s => ({ server: s, policy: restricted.policyFor(s.hostname) }))
    .filter(x => x.policy);
}

// Label-Group access management
app.post('/api/labels/:labelId/groups/:groupId', isAdmin, (req, res) => {
  try {
    const group = db.prepare('SELECT name FROM groups WHERE id = ?').get(req.params.groupId);
    if (!group) return res.status(404).json({ error: 'Group not found' });
    const blocked = restrictedServersWithLabel(req.params.labelId)
      .filter(x => !x.policy.allowed_groups.includes(group.name));
    if (blocked.length > 0) {
      return res.status(403).json({
        error: `Label is attached to restricted server(s) ${blocked.map(x => x.server.hostname).join(', ')} ` +
          `and group "${group.name}" is not in their allowed_groups. ` +
          `Widening access to restricted servers requires a commit to restricted-servers.json ` +
          `(or use a separate label for the unrestricted servers).`
      });
    }
    db.prepare('INSERT OR IGNORE INTO label_groups (label_id, group_id) VALUES (?, ?)').run(req.params.labelId, req.params.groupId);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/labels/:labelId/groups/:groupId', isAdmin, (req, res) => {
  db.prepare('DELETE FROM label_groups WHERE label_id = ? AND group_id = ?').run(req.params.labelId, req.params.groupId);
  res.json({ success: true });
});

app.get('/api/labels/:labelId/groups', isAuthenticated, (req, res) => {
  const groups = db.prepare(`
    SELECT g.* FROM groups g
    JOIN label_groups lg ON g.id = lg.group_id
    WHERE lg.label_id = ?
  `).all(req.params.labelId);
  res.json(groups);
});

// Shared shaping for the "which servers can this user reach" views.
// Restricted servers where the user's groups aren't in the policy's
// allowed_groups are dropped: label wiring says yes, but they would never
// be deployed there, so showing the server would be a lie.
function serversVisibleToUser(servers, userId) {
  const groupNames = db.prepare(`
    SELECT g.name FROM groups g
    JOIN user_groups ug ON g.id = ug.group_id
    WHERE ug.user_id = ?
  `).all(userId).map(r => r.name);
  const user = db.prepare('SELECT email FROM users WHERE id = ?').get(userId);
  const email = (user?.email || '').toLowerCase();

  const kept = servers.filter(s => {
    const policy = restricted.policyFor(s.hostname);
    return !policy
      || policy.allowed_groups.some(g => groupNames.includes(g))
      || policy.allowed_users.includes(email);
  });

  // Servers granted directly via allowed_users have no label path and are
  // missing from the label-based query — add them.
  const seen = new Set(kept.map(s => s.id));
  for (const s of db.prepare('SELECT * FROM servers ORDER BY hostname COLLATE NOCASE').all()) {
    if (seen.has(s.id)) continue;
    const policy = restricted.policyFor(s.hostname);
    if (policy && policy.allowed_users.includes(email)) kept.push(s);
  }
  kept.sort((a, b) => a.hostname.localeCompare(b.hostname, undefined, { sensitivity: 'base' }));

  return kept.map(withDeployState);
}

// The extra fields every access view adds on top of a raw server row.
function withDeployState(s) {
  const expectedHash = computeServerKeysHash(s);
  return {
    ...s,
    expected_keys_hash: expectedHash,
    is_up_to_date: s.deployed_keys_hash === expectedHash,
    restricted: !!restricted.policyFor(s.hostname)
  };
}

// Access views
app.get('/api/my-servers', isAuthenticated, (req, res) => {
  const servers = db.prepare(`
    SELECT DISTINCT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    JOIN labels l ON sl.label_id = l.id
    JOIN label_groups lg ON l.id = lg.label_id
    JOIN user_groups ug ON lg.group_id = ug.group_id
    WHERE ug.user_id = ?
    ORDER BY s.hostname COLLATE NOCASE
  `).all(req.user.id);
  res.json(serversVisibleToUser(servers, req.user.id));
});

app.get('/api/user-servers/:userId', isAdmin, (req, res) => {
  const servers = db.prepare(`
    SELECT DISTINCT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    JOIN labels l ON sl.label_id = l.id
    JOIN label_groups lg ON l.id = lg.label_id
    JOIN user_groups ug ON lg.group_id = ug.group_id
    WHERE ug.user_id = ?
    ORDER BY s.hostname COLLATE NOCASE
  `).all(req.params.userId);
  res.json(serversVisibleToUser(servers, req.params.userId));
});

// Devices a TEAM agent reaches: those carrying one of its labels, minus
// restricted servers whose policy withholds agents — the same filter
// serverTeamAgents applies at deploy time, so the view cannot promise more
// than the deploy delivers. A personal agent has no view of its own: it
// reaches exactly its owner's devices (/api/user-servers/:userId).
app.get('/api/agent-servers/:id', isAdmin, (req, res) => {
  const agent = db.prepare('SELECT id, name FROM team_agents WHERE id = ?').get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'Agent not found' });
  const servers = db.prepare(`
    SELECT DISTINCT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    JOIN agent_labels al ON al.label_id = sl.label_id
    WHERE al.agent_id = ?
    ORDER BY s.hostname COLLATE NOCASE
  `).all(agent.id).filter(s => {
    const policy = restricted.policyFor(s.hostname);
    return !policy || policy.allow_agents;
  });
  res.json(servers.map(withDeployState));
});

app.get('/api/server-access/:serverId', isAdmin, (req, res) => {
  const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.serverId);
  if (!server) return res.status(404).json({ error: 'Server not found' });
  const policy = restricted.policyFor(server.hostname);

  let rows = db.prepare(`
    SELECT DISTINCT u.id, u.email, u.name, u.public_key, g.name as group_name FROM users u
    JOIN user_groups ug ON u.id = ug.user_id
    JOIN groups g ON ug.group_id = g.id
    JOIN label_groups lg ON g.id = lg.group_id
    JOIN server_labels sl ON lg.label_id = sl.label_id
    WHERE sl.server_id = ?
    ORDER BY g.name COLLATE NOCASE
  `).all(req.params.serverId);
  // On a restricted server only memberships in allowed groups grant access,
  // so only those are shown. Users granted directly via allowed_users are
  // appended below.
  if (policy) rows = rows.filter(r => policy.allowed_groups.includes(r.group_name));
  if (policy) {
    for (const email of policy.allowed_users) {
      const u = db.prepare('SELECT id, email, name, public_key FROM users WHERE lower(email) = ?').get(email);
      if (u) rows.push({ ...u, group_name: 'restricted-servers.json' });
    }
  }

  const byUser = new Map();
  for (const r of rows) {
    const existing = byUser.get(r.id);
    if (existing) {
      existing.group_names.push(r.group_name);
    } else {
      byUser.set(r.id, {
        id: r.id,
        email: r.email,
        name: r.name,
        public_key: r.public_key,
        group_names: [r.group_name],
        // A personal agent lands on every device its owner reaches, so
        // whoever is listed here brings their bots with them.
        bots: userBots(r)
      });
    }
  }
  const users = [...byUser.values()].sort((a, b) =>
    (a.name || a.email).localeCompare(b.name || b.email, undefined, { sensitivity: 'base' })
  );

  res.json({
    users,
    agents: serverTeamAgents(server),
    restricted: !!policy,
    restricted_policy: policy
  });
});

// Download manual setup package for a server (for unreachable/air-gapped servers)
app.get('/api/servers/:id/download-setup', isAdmin, (req, res) => {
  try {
    const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }

    // Same filtered view the automated deploy uses (restricted-servers
    // policy applied), so the manual package can't hand out more.
    const users = serverAuthorizedUsers(server);

    if (users.length === 0) {
      return res.status(400).json({ error: 'No users have access to this server. Assign groups to this server\'s labels first.' });
    }

    // Filter to users with public keys
    const usersWithKeys = users.filter(u => u.public_key && u.public_key.trim());
    if (usersWithKeys.length === 0) {
      return res.status(400).json({ error: 'No authorized users have SSH public keys configured.' });
    }

    // Generate authorized_keys content
    const authorizedKeys = usersWithKeys
      .map(u => u.public_key.trim())
      .join('\n') + '\n';

    // Generate README
    const timestamp = new Date().toISOString();
    const userList = usersWithKeys
      .map(u => `  - ${u.name || u.email} (${u.email})`)
      .join('\n');

    const readme = `# Superkey Manual Setup for ${server.hostname}

Generated: ${timestamp}

## Overview

This package contains the authorized_keys file for users who have access to
the server "${server.hostname}".

Use this when the server cannot be reached from the Superkey server
(e.g., air-gapped networks, firewalls, VPNs).

## Authorized Users (${usersWithKeys.length})

${userList}

## Setup Instructions

1. Copy this package to the target server

2. Extract the archive:
   \`\`\`bash
   tar -xzf superkey-setup-${server.hostname}.tar.gz
   \`\`\`

3. Copy the authorized_keys file to your shared user's SSH directory:
   \`\`\`bash
   # Replace <username> with your shared user (e.g., logi, ubuntu, deploy)
   sudo cp authorized_keys /home/<username>/.ssh/authorized_keys
   sudo chmod 600 /home/<username>/.ssh/authorized_keys
   sudo chown <username>:<username> /home/<username>/.ssh/authorized_keys
   \`\`\`

   Or append to existing keys:
   \`\`\`bash
   sudo cat authorized_keys >> /home/<username>/.ssh/authorized_keys
   \`\`\`

## Updating Access

When user access changes in Superkey, download a new package and replace
the authorized_keys file on the server.

## Notes

- This file contains ${usersWithKeys.length} public key(s)
- ${users.length - usersWithKeys.length} authorized user(s) have not uploaded their SSH public key
`;

    // Create tarball
    const folderName = `superkey-setup-${server.hostname}`;
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', `attachment; filename="${folderName}.tar.gz"`);

    const archive = archiver('tar', { gzip: true });
    archive.on('error', (err) => {
      console.error('Archive error:', err);
      res.status(500).end();
    });
    archive.pipe(res);

    archive.append(authorizedKeys, { name: `${folderName}/authorized_keys`, mode: 0o644 });
    archive.append(readme, { name: `${folderName}/README.md`, mode: 0o644 });

    archive.finalize();

  } catch (err) {
    console.error('Error generating setup package:', err);
    res.status(500).json({ error: err.message });
  }
});

// The machine public key deploys run with. Served without auth (it is a
// public key) so the admin enrolling a new server can fetch it via
// setup-server.sh. Set by setup-deploy-runner.sh on the superkey host.
app.get('/api/deploy-key', (req, res) => {
  const key = (process.env.DEPLOY_PUBKEY || '').trim();
  if (!key) {
    return res.status(404).json({
      error: 'Deploy key not configured (DEPLOY_PUBKEY unset). Run scripts/setup-deploy-runner.sh on the superkey host.'
    });
  }
  res.json({ public_key: key });
});

// Deployment data - returns all servers with their authorized users.
// Used by the deploy runner to set up user access on remote servers.
app.get('/api/deploy-data', isDeployApi, (req, res) => {
  try {
    const servers = db.prepare('SELECT * FROM servers').all();
    const result = {
      servers: servers.map(server => {
        const users = serverAuthorizedUsers(server);
        return {
          hostname: server.hostname,
          description: server.description,
          restricted: !!restricted.policyFor(server.hostname),
          ever_deployed: !!server.last_deployed_at,
          expected_keys_hash: computeServerKeysHash(server),
          users: users.map(u => ({
            email: u.email,
            name: u.name,
            public_key: u.public_key,
            bots: db.prepare('SELECT name, public_key, source_cidr FROM bot_keys WHERE user_id = ?').all(u.id).map(b => ({
              name: b.name,
              account: botAccount(u.email, b.name),
              public_key: b.public_key,
              key_options: botKeyOptions(b.source_cidr)
            }))
          })),
          agents: serverTeamAgents(server)
        };
      })
    };
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Servers whose deployed keys don't match what superkey would deploy now.
// The deploy runner polls this and only touches stale hosts.
app.get('/api/stale-servers', isDeployApi, (req, res) => {
  try {
    const servers = db.prepare('SELECT * FROM servers').all();
    const stale = servers
      .filter(s => {
        if (s.deployed_keys_hash === computeServerKeysHash(s)) return false;
        // Never deployed and nothing to deploy: not an enrolled server,
        // don't make the runner knock on its door forever.
        if (!s.last_deployed_at
            && serverAuthorizedUsers(s).length === 0
            && serverTeamAgents(s).length === 0) return false;
        return true;
      })
      .map(s => s.hostname);
    res.json({ servers: stale });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve the SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

const GROUP_SYNC_INTERVAL_MS = parseInt(process.env.GROUP_SYNC_INTERVAL_MS, 10) || 60 * 60 * 1000;
const SERVER_IMPORT_INTERVAL_MS = parseInt(process.env.SERVER_IMPORT_INTERVAL_MS, 10) || 5 * 60 * 1000;

// Keep the servers table in sync with the hostnames repo without anyone
// having to open the admin UI: a pushed hostname is enrolled and (if its
// label already maps to groups) deployed by the runner within minutes.
function scheduledServerImport() {
  try {
    const r = importServersFromConfigs();
    if (r.imported || r.updated || r.removed) {
      console.log(`Server import: ${r.imported} added, ${r.updated} updated, ${r.removed} removed (${r.configFiles} config files)`);
    }
  } catch (err) {
    console.error('Server import failed:', err.message);
  }
}

app.listen(PORT, async () => {
  console.log(`Superkey server running on port ${PORT}`);

  scheduledServerImport();
  setInterval(scheduledServerImport, SERVER_IMPORT_INTERVAL_MS);
  console.log(`Scheduled hostnames-repo server import every ${Math.round(SERVER_IMPORT_INTERVAL_MS / 60000)} min`);
  if (serviceAccountAuth) {
    console.log('Google Workspace group sync enabled via service account');

    // Auto-sync on first startup if no groups exist or no memberships
    const groupCount = db.prepare('SELECT COUNT(*) as count FROM groups').get().count;
    const membershipCount = db.prepare('SELECT COUNT(*) as count FROM user_groups').get().count;
    if (groupCount === 0 || membershipCount === 0) {
      console.log('No groups or memberships found - running initial sync from Google Workspace...');
      try {
        const result = await syncAllUsersGroups();
        console.log(`Initial sync complete: ${result.users} users, ${result.groups} groups, ${result.memberships} memberships`);
      } catch (err) {
        console.error('Initial sync failed:', err.message);
      }
    }

    let syncInFlight = false;
    setInterval(async () => {
      if (syncInFlight) return;
      syncInFlight = true;
      try {
        const result = await syncAllUsersGroups();
        console.log(`Scheduled sync complete: ${result.users} users, ${result.groups} groups, ${result.memberships} memberships`);
      } catch (err) {
        console.error('Scheduled sync failed:', err.message);
      } finally {
        syncInFlight = false;
      }
    }, GROUP_SYNC_INTERVAL_MS);
    console.log(`Scheduled Google group sync every ${Math.round(GROUP_SYNC_INTERVAL_MS / 60000)} min`);
  } else {
    console.log('Note: Set GOOGLE_SERVICE_ACCOUNT_KEY and GOOGLE_ADMIN_EMAIL for full group sync');
  }
});
