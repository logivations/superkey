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

// Compute hash of users/keys for a server to detect if deployment is up-to-date
function computeServerKeysHash(serverId) {
  const users = db.prepare(`
    SELECT DISTINCT u.email, u.public_key FROM users u
    JOIN user_groups ug ON u.id = ug.user_id
    JOIN label_groups lg ON ug.group_id = lg.group_id
    JOIN server_labels sl ON lg.label_id = sl.label_id
    WHERE sl.server_id = ? AND u.public_key IS NOT NULL AND u.public_key != ''
    ORDER BY u.email
  `).all(serverId);
  const data = users.map(u => `${u.email}:${u.public_key}`).join('\n');
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
  db.prepare('UPDATE users SET public_key = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?').run(publicKey, req.user.id);
  res.json({ success: true });
});

app.get('/api/users', isAdmin, (req, res) => {
  const users = db.prepare('SELECT id, email, name, public_key, created_at FROM users').all();
  res.json(users);
});

app.get('/api/users/:id', isAdmin, (req, res) => {
  const user = db.prepare('SELECT id, email, name, public_key, created_at FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

// Import servers from SSH config files
const SSH_CONFIGS_PATH = process.env.SSH_CONFIGS_PATH || path.join(process.env.HOME, 'hostnames', 'ssh-configs');

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

app.post('/api/import-servers', isAdmin, (req, res) => {
  try {
    if (!fs.existsSync(SSH_CONFIGS_PATH)) {
      return res.status(400).json({ error: `SSH configs directory not found: ${SSH_CONFIGS_PATH}` });
    }

    const configFiles = fs.readdirSync(SSH_CONFIGS_PATH).filter(f => f.endsWith('.config'));
    let imported = 0;
    let skipped = 0;

    for (const configFile of configFiles) {
      const configName = configFile.replace('.config', '');
      const content = fs.readFileSync(path.join(SSH_CONFIGS_PATH, configFile), 'utf8');
      const servers = parseSSHConfig(content, configName);

      for (const server of servers) {
        // Check if server already exists
        const existing = db.prepare('SELECT id FROM servers WHERE hostname = ?').get(server.hostname);
        if (existing) {
          skipped++;
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

    res.json({
      success: true,
      imported,
      skipped,
      configFiles: configFiles.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get last git commit date from SSH configs directory
app.get('/api/ssh-configs-commit-date', isAdmin, (req, res) => {
  try {
    if (!fs.existsSync(SSH_CONFIGS_PATH)) {
      return res.json({ date: null, error: 'SSH configs directory not found' });
    }
    const { execSync } = require('child_process');
    const gitDate = execSync('git log -1 --format=%ci', {
      cwd: SSH_CONFIGS_PATH,
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
    const expectedHash = computeServerKeysHash(s.id);
    const isUpToDate = s.deployed_keys_hash === expectedHash;
    return {
      ...s,
      labels: s.labels ? s.labels.split(',') : [],
      expected_keys_hash: expectedHash,
      is_up_to_date: isUpToDate
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
app.post('/api/servers/:hostname/deployed', (req, res) => {
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
app.get('/api/labels', isAuthenticated, (req, res) => {
  const labels = db.prepare('SELECT * FROM labels').all();
  res.json(labels);
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
  const groups = db.prepare('SELECT * FROM groups').all();
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

// Label-Group access management
app.post('/api/labels/:labelId/groups/:groupId', isAdmin, (req, res) => {
  try {
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

// Access views
app.get('/api/my-servers', isAuthenticated, (req, res) => {
  const servers = db.prepare(`
    SELECT DISTINCT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    JOIN labels l ON sl.label_id = l.id
    JOIN label_groups lg ON l.id = lg.label_id
    JOIN user_groups ug ON lg.group_id = ug.group_id
    WHERE ug.user_id = ?
  `).all(req.user.id);
  res.json(servers.map(s => {
    const expectedHash = computeServerKeysHash(s.id);
    const isUpToDate = s.deployed_keys_hash === expectedHash;
    return {
      ...s,
      expected_keys_hash: expectedHash,
      is_up_to_date: isUpToDate
    };
  }));
});

app.get('/api/user-servers/:userId', isAdmin, (req, res) => {
  const servers = db.prepare(`
    SELECT DISTINCT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    JOIN labels l ON sl.label_id = l.id
    JOIN label_groups lg ON l.id = lg.label_id
    JOIN user_groups ug ON lg.group_id = ug.group_id
    WHERE ug.user_id = ?
  `).all(req.params.userId);
  res.json(servers.map(s => {
    const expectedHash = computeServerKeysHash(s.id);
    const isUpToDate = s.deployed_keys_hash === expectedHash;
    return {
      ...s,
      expected_keys_hash: expectedHash,
      is_up_to_date: isUpToDate
    };
  }));
});

app.get('/api/server-access/:serverId', isAdmin, (req, res) => {
  const users = db.prepare(`
    SELECT DISTINCT u.id, u.email, u.name, u.public_key, g.name as group_name FROM users u
    JOIN user_groups ug ON u.id = ug.user_id
    JOIN groups g ON ug.group_id = g.id
    JOIN label_groups lg ON g.id = lg.group_id
    JOIN server_labels sl ON lg.label_id = sl.label_id
    WHERE sl.server_id = ?
  `).all(req.params.serverId);

  res.json({ users });
});

// Download manual setup package for a server (for unreachable/air-gapped servers)
app.get('/api/servers/:id/download-setup', isAdmin, (req, res) => {
  try {
    const server = db.prepare('SELECT * FROM servers WHERE id = ?').get(req.params.id);
    if (!server) {
      return res.status(404).json({ error: 'Server not found' });
    }

    // Get all users with access to this server via group membership
    const users = db.prepare(`
      SELECT DISTINCT u.id, u.email, u.name, u.public_key FROM users u
      JOIN user_groups ug ON u.id = ug.user_id
      JOIN label_groups lg ON ug.group_id = lg.group_id
      JOIN server_labels sl ON lg.label_id = sl.label_id
      WHERE sl.server_id = ?
    `).all(req.params.id);

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

// Get admin public keys for setup script (no auth required)
// Returns public keys of all users in superkey_admins group
app.get('/api/admin-keys', (req, res) => {
  try {
    const adminGroup = db.prepare("SELECT id FROM groups WHERE name = 'superkey_admins'").get();
    if (!adminGroup) {
      return res.status(404).json({ error: 'superkey_admins group not found' });
    }

    const users = db.prepare(`
      SELECT u.email, u.name, u.public_key FROM users u
      JOIN user_groups ug ON u.id = ug.user_id
      WHERE ug.group_id = ? AND u.public_key IS NOT NULL AND u.public_key != ''
    `).all(adminGroup.id);

    res.json({
      group: 'superkey_admins',
      users: users.map(u => ({
        email: u.email,
        name: u.name,
        public_key: u.public_key
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Deployment data - returns all servers with their authorized users
// Used by the deploy.sh script to set up user access on remote servers
app.get('/api/deploy-data', (req, res) => {
  try {
    const servers = db.prepare('SELECT * FROM servers').all();
    const result = {
      servers: servers.map(server => {
        // Get all users with access to this server via group membership
        const users = db.prepare(`
          SELECT DISTINCT u.id, u.email, u.name, u.public_key FROM users u
          JOIN user_groups ug ON u.id = ug.user_id
          JOIN label_groups lg ON ug.group_id = lg.group_id
          JOIN server_labels sl ON lg.label_id = sl.label_id
          WHERE sl.server_id = ?
        `).all(server.id);

        return {
          hostname: server.hostname,
          description: server.description,
          expected_keys_hash: computeServerKeysHash(server.id),
          users: users.map(u => ({
            email: u.email,
            name: u.name,
            public_key: u.public_key
          }))
        };
      })
    };
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve the SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, async () => {
  console.log(`Superkey server running on port ${PORT}`);
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
  } else {
    console.log('Note: Set GOOGLE_SERVICE_ACCOUNT_KEY and GOOGLE_ADMIN_EMAIL for full group sync');
  }
});
