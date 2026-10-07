// Test harness: a throwaway SQLite database and restricted-servers policy,
// environment set BEFORE src/ is required (database.js and restricted.js
// read it at load time). Each test file runs in its own process
// (node --test), so every file gets a fresh database.

const fs = require('fs');
const os = require('os');
const path = require('path');

const SESSION_SECRET = 'test-session-secret';
const AGENT_API_TOKEN = 'a'.repeat(64);
const DEPLOY_API_TOKEN = 'd'.repeat(64);

function setupEnv() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'superkey-test-'));
  const policyPath = path.join(dir, 'restricted-servers.json');
  fs.writeFileSync(policyPath, JSON.stringify({
    restricted_servers: [
      { match: 'mcpservers', allowed_users: ['carol@example.com'], allow_agents: true },
      { match: 'prod-*', allowed_groups: ['infra_core'], allow_agents: false }
    ]
  }));
  Object.assign(process.env, {
    DB_PATH: path.join(dir, 'superkey.db'),
    RESTRICTED_SERVERS_PATH: policyPath,
    GOOGLE_CLIENT_ID: 'test-client-id',
    GOOGLE_CLIENT_SECRET: 'test-client-secret',
    SESSION_SECRET,
    AGENT_API_TOKEN,
    DEPLOY_API_TOKEN,
    HOME: dir
  });
  delete process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  // The session store starts a cleanup setInterval it never unrefs, which
  // would keep the test process alive forever.
  const realSetInterval = global.setInterval;
  global.setInterval = (...args) => {
    const t = realSetInterval(...args);
    if (t && t.unref) t.unref();
    return t;
  };
  return dir;
}

// Fixture builders (straight into the DB; the app reads the same module).
function fixtures(db) {
  const ids = {};
  const user = (key, email, name) => {
    ids[key] = db.prepare('INSERT INTO users (google_id, email, name) VALUES (?, ?, ?)')
      .run(`g-${key}`, email, name).lastInsertRowid;
    return ids[key];
  };
  const group = name => {
    db.prepare('INSERT OR IGNORE INTO groups (name) VALUES (?)').run(name);
    return db.prepare('SELECT id FROM groups WHERE name = ?').get(name).id;
  };
  const label = name => {
    db.prepare('INSERT OR IGNORE INTO labels (name) VALUES (?)').run(name);
    return db.prepare('SELECT id FROM labels WHERE name = ?').get(name).id;
  };
  const member = (userId, groupName) =>
    db.prepare('INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)').run(userId, group(groupName));
  const grantGroup = (labelName, groupName) =>
    db.prepare('INSERT OR IGNORE INTO label_groups (label_id, group_id) VALUES (?, ?)').run(label(labelName), group(groupName));
  const server = (hostname, labels) => {
    const id = db.prepare('INSERT INTO servers (hostname, description) VALUES (?, ?)')
      .run(hostname, `10.0.0.${Object.keys(ids).length} (${labels[0]})`).lastInsertRowid;
    for (const l of labels) db.prepare('INSERT INTO server_labels (server_id, label_id) VALUES (?, ?)').run(id, label(l));
    return id;
  };
  return { ids, user, group, label, member, grantGroup, server };
}

// Forge a browser session for a user, exactly what passport stores after a
// Google login, and return the signed connect.sid cookie for it.
function sessionCookie(db, userId) {
  const signature = require('cookie-signature');
  const sid = `test-${userId}-${Math.random().toString(36).slice(2)}`;
  const sess = {
    cookie: { originalMaxAge: 3600000, expires: new Date(Date.now() + 3600000).toISOString(), httpOnly: true, path: '/' },
    passport: { user: { id: userId } }
  };
  db.prepare('INSERT INTO sessions (sid, sess, expire) VALUES (?, ?, ?)')
    .run(sid, JSON.stringify(sess), new Date(Date.now() + 3600000).toISOString());
  return 'connect.sid=' + encodeURIComponent('s:' + signature.sign(sid, SESSION_SECRET));
}

// Start the express app on an ephemeral port.
async function listen(app) {
  const server = await new Promise(resolve => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, base };
}

module.exports = { setupEnv, fixtures, sessionCookie, listen, AGENT_API_TOKEN, DEPLOY_API_TOKEN };
