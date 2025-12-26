require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { google } = require('googleapis');
const path = require('path');
const fs = require('fs');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;
const EXPORT_PATH = process.env.EXPORT_PATH || path.join(process.env.HOME, 'hostnames', 'keys');

app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'superkey-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(passport.initialize());
app.use(passport.session());

// Sync user's Google Groups to local database
async function syncUserGroups(userId, userEmail, accessToken) {
  try {
    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({ access_token: accessToken });

    const people = google.people({ version: 'v1', auth: oauth2Client });

    // Get user's memberships using Cloud Identity or check against configured groups
    // Since we can't list all groups user belongs to without admin access,
    // we'll check membership against each configured group

    const groupsWithEmail = db.prepare('SELECT * FROM groups WHERE google_group_email IS NOT NULL').all();

    // Clear existing group memberships for this user
    db.prepare('DELETE FROM user_groups WHERE user_id = ?').run(userId);

    // For each group with a google_group_email, check if user is a member
    for (const group of groupsWithEmail) {
      try {
        const admin = google.admin({ version: 'directory_v1', auth: oauth2Client });
        const response = await admin.members.hasMember({
          groupKey: group.google_group_email,
          memberKey: userEmail
        });

        if (response.data.isMember) {
          db.prepare('INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)').run(userId, group.id);
          console.log(`User ${userEmail} is member of ${group.google_group_email}`);
        }
      } catch (err) {
        // If we get a 403, user doesn't have permission to check this group
        // If 404, user is not a member
        if (err.code === 404) {
          // Not a member, that's fine
        } else {
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
  scope: [
    'profile',
    'email',
    'https://www.googleapis.com/auth/admin.directory.group.member.readonly'
  ],
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
    accessToken: undefined, // Don't expose token
    isAdmin: !!adminGroup,
    groups: userGroups.map(g => g.name)
  });
});

// Manual group sync endpoint
app.post('/api/sync-groups', isAuthenticated, async (req, res) => {
  try {
    await syncUserGroups(req.user.id, req.user.email, req.user.accessToken);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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

// Server routes
app.get('/api/servers', isAuthenticated, (req, res) => {
  const servers = db.prepare(`
    SELECT s.*, GROUP_CONCAT(l.name) as labels
    FROM servers s
    LEFT JOIN server_labels sl ON s.id = sl.server_id
    LEFT JOIN labels l ON sl.label_id = l.id
    GROUP BY s.id
  `).all();
  res.json(servers.map(s => ({ ...s, labels: s.labels ? s.labels.split(',') : [] })));
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

// User-Group management (read-only for Google-synced groups)
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

// Label-User direct access management
app.post('/api/labels/:labelId/users/:userId', isAdmin, (req, res) => {
  try {
    db.prepare('INSERT OR IGNORE INTO label_users (label_id, user_id) VALUES (?, ?)').run(req.params.labelId, req.params.userId);
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/labels/:labelId/users/:userId', isAdmin, (req, res) => {
  db.prepare('DELETE FROM label_users WHERE label_id = ? AND user_id = ?').run(req.params.labelId, req.params.userId);
  res.json({ success: true });
});

app.get('/api/labels/:labelId/users', isAuthenticated, (req, res) => {
  const users = db.prepare(`
    SELECT u.id, u.email, u.name FROM users u
    JOIN label_users lu ON u.id = lu.user_id
    WHERE lu.label_id = ?
  `).all(req.params.labelId);
  res.json(users);
});

// Access views
app.get('/api/my-servers', isAuthenticated, (req, res) => {
  const servers = db.prepare(`
    SELECT DISTINCT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    JOIN labels l ON sl.label_id = l.id
    LEFT JOIN label_groups lg ON l.id = lg.label_id
    LEFT JOIN user_groups ug ON lg.group_id = ug.group_id
    LEFT JOIN label_users lu ON l.id = lu.label_id
    WHERE ug.user_id = ? OR lu.user_id = ?
  `).all(req.user.id, req.user.id);
  res.json(servers);
});

app.get('/api/user-servers/:userId', isAdmin, (req, res) => {
  const servers = db.prepare(`
    SELECT DISTINCT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    JOIN labels l ON sl.label_id = l.id
    LEFT JOIN label_groups lg ON l.id = lg.label_id
    LEFT JOIN user_groups ug ON lg.group_id = ug.group_id
    LEFT JOIN label_users lu ON l.id = lu.label_id
    WHERE ug.user_id = ? OR lu.user_id = ?
  `).all(req.params.userId, req.params.userId);
  res.json(servers);
});

app.get('/api/server-access/:serverId', isAdmin, (req, res) => {
  const byGroup = db.prepare(`
    SELECT DISTINCT u.id, u.email, u.name, u.public_key, g.name as group_name FROM users u
    JOIN user_groups ug ON u.id = ug.user_id
    JOIN groups g ON ug.group_id = g.id
    JOIN label_groups lg ON g.id = lg.group_id
    JOIN server_labels sl ON lg.label_id = sl.label_id
    WHERE sl.server_id = ?
  `).all(req.params.serverId);

  const byUser = db.prepare(`
    SELECT DISTINCT u.id, u.email, u.name, u.public_key FROM users u
    JOIN label_users lu ON u.id = lu.user_id
    JOIN server_labels sl ON lu.label_id = sl.label_id
    WHERE sl.server_id = ?
  `).all(req.params.serverId);

  res.json({ byGroup, byUser });
});

// Export keys
app.post('/api/export', isAdmin, (req, res) => {
  try {
    const servers = db.prepare('SELECT * FROM servers').all();

    // Create export directory if it doesn't exist
    fs.mkdirSync(EXPORT_PATH, { recursive: true });

    for (const server of servers) {
      const serverPath = path.join(EXPORT_PATH, server.hostname);
      fs.mkdirSync(serverPath, { recursive: true });

      // Get all users with access to this server
      const users = db.prepare(`
        SELECT DISTINCT u.email, u.public_key FROM users u
        LEFT JOIN user_groups ug ON u.id = ug.user_id
        LEFT JOIN label_groups lg ON ug.group_id = lg.group_id
        LEFT JOIN label_users lu ON u.id = lu.user_id
        JOIN server_labels sl ON (lg.label_id = sl.label_id OR lu.label_id = sl.label_id)
        WHERE sl.server_id = ? AND u.public_key IS NOT NULL AND u.public_key != ''
      `).all(server.id);

      // Clear existing keys
      const existingFiles = fs.readdirSync(serverPath);
      for (const file of existingFiles) {
        fs.unlinkSync(path.join(serverPath, file));
      }

      // Write each user's public key
      for (const user of users) {
        const keyFilename = user.email.replace(/[^a-zA-Z0-9]/g, '_') + '.pub';
        fs.writeFileSync(path.join(serverPath, keyFilename), user.public_key);
      }
    }

    res.json({ success: true, path: EXPORT_PATH, serverCount: servers.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Serve the SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Superkey server running on port ${PORT}`);
});
