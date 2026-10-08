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

// The OAuth issuer/resource URLs are fixed at startup from PUBLIC_URL, so
// the port has to be known before the app is required.
async function freePort() {
  const net = require('net');
  return new Promise(resolve => {
    const srv = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

function setupEnv(port) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'superkey-test-'));
  const policyPath = path.join(dir, 'restricted-servers.json');
  fs.writeFileSync(policyPath, JSON.stringify({
    restricted_servers: [
      { match: 'mcpservers', allowed_users: ['carol@example.com'], allow_agents: true },
      { match: 'prod-*', allowed_groups: ['infra_core'], allow_agents: false }
    ],
    unprivileged_servers: [
      { match: 'nemo', forced_command: 'sudo -n /usr/local/sbin/nemo-enter' }
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
    PUBLIC_URL: `http://127.0.0.1:${port}`,
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

// Start the express app on the port given to setupEnv.
async function listen(app, port) {
  const server = await new Promise(resolve => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, base };
}

// ---- OAuth (src/oauth.js) test client ------------------------------------

const crypto = require('crypto');

function pkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

// fetch that never follows redirects and returns { status, location, json, text, headers }.
async function req(base, method, path, { cookie, json, form, auth, headers = {} } = {}) {
  const h = { ...headers };
  if (cookie) h.Cookie = cookie;
  if (auth) h.Authorization = auth;
  let body;
  if (json) { h['Content-Type'] = 'application/json'; body = JSON.stringify(json); }
  if (form) { h['Content-Type'] = 'application/x-www-form-urlencoded'; body = new URLSearchParams(form).toString(); }
  const res = await fetch(base + path, { method, headers: h, body, redirect: 'manual' });
  const text = await res.text();
  let parsed = null;
  try { parsed = JSON.parse(text); } catch (e) { /* not JSON */ }
  return { status: res.status, location: res.headers.get('location'), json: parsed, text, headers: res.headers };
}

const REDIRECT = 'http://127.0.0.1:33418/callback';

async function registerClient(base, { redirect = REDIRECT, name = 'Test client' } = {}) {
  const r = await req(base, 'POST', '/register', {
    json: { client_name: name, redirect_uris: [redirect], token_endpoint_auth_method: 'none' }
  });
  if (r.status !== 201) throw new Error(`register failed: ${r.status} ${r.text}`);
  return r.json;
}

function authorizePath(base, client, { challenge, redirect = REDIRECT, resource = `${base}/mcp`, state = 'st4te' }) {
  const q = new URLSearchParams({
    response_type: 'code', client_id: client.client_id, redirect_uri: redirect,
    code_challenge: challenge, code_challenge_method: 'S256', state
  });
  if (resource) q.set('resource', resource);
  return '/authorize?' + q;
}

// Load the consent page (signed in via `cookie`) and submit a decision.
// Returns the final redirect (to the client's redirect_uri).
async function consent(base, consentLocation, cookie, decision = 'approve') {
  const page = await req(base, 'GET', consentLocation, { cookie });
  if (page.status !== 200) throw new Error(`consent page: ${page.status} ${page.text}`);
  const field = n => (page.text.match(new RegExp(`name="${n}" value="([^"]+)"`)) || [])[1];
  return req(base, 'POST', '/oauth/consent', {
    cookie, form: { request: field('request'), csrf: field('csrf'), decision }
  });
}

async function exchangeCode(base, client, code, verifier, extra = {}) {
  return req(base, 'POST', '/token', {
    form: { grant_type: 'authorization_code', client_id: client.client_id, code, code_verifier: verifier,
      redirect_uri: REDIRECT, resource: `${base}/mcp`, ...extra }
  });
}

async function refresh(base, client, refreshToken) {
  return req(base, 'POST', '/token', {
    form: { grant_type: 'refresh_token', client_id: client.client_id, refresh_token: refreshToken, resource: `${base}/mcp` }
  });
}

// The whole browser dance for a signed-in user: register, authorize,
// approve, exchange. Returns { client, tokens }.
async function oauthLogin(base, cookie, opts = {}) {
  const client = opts.client || await registerClient(base);
  const { verifier, challenge } = pkce();
  const a = await req(base, 'GET', authorizePath(base, client, { challenge }), { cookie });
  if (a.status !== 302 || !a.location.startsWith('/oauth/consent')) throw new Error(`authorize: ${a.status} ${a.location} ${a.text}`);
  const back = await consent(base, a.location, cookie);
  const code = new URL(back.location).searchParams.get('code');
  const t = await exchangeCode(base, client, code, verifier);
  if (t.status !== 200) throw new Error(`token: ${t.status} ${t.text}`);
  return { client, tokens: t.json };
}

module.exports = { pkce, req, REDIRECT, registerClient, authorizePath, consent, exchangeCode, refresh, oauthLogin,
  freePort, setupEnv, fixtures, sessionCookie, listen, AGENT_API_TOKEN, DEPLOY_API_TOKEN };
