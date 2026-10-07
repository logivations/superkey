// OAuth 2.1 authorization server for /mcp (src/oauth.js), end to end
// against the real app: discovery metadata, dynamic client registration,
// authorize via the Google session (forged) + consent, PKCE, resource
// binding, refresh rotation and reuse detection, revocation, and that
// OAuth tokens are worthless outside /mcp.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./helpers');

let db, base, httpServer, Client, StreamableHTTPClientTransport, UnauthorizedError;
let alice, bob, aliceCookie, bobCookie;
// One client for the failure cases: /register is rate-limited (20/h per IP).
let shared;

before(async () => {
  const port = await H.freePort();
  H.setupEnv(port);
  db = require('../src/database');
  const { app } = require('../src/server');
  ({ Client } = require('@modelcontextprotocol/sdk/client/index.js'));
  ({ StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js'));
  ({ UnauthorizedError } = require('@modelcontextprotocol/sdk/client/auth.js'));
  const f = H.fixtures(db);
  alice = f.user('alice', 'alice@example.com', 'Alice');
  bob = f.user('bob', 'bob@example.com', 'Bob');
  f.member(bob, 'superkey_admins');
  ({ server: httpServer, base } = await H.listen(app, port));
  aliceCookie = H.sessionCookie(db, alice);
  bobCookie = H.sessionCookie(db, bob);
  shared = await H.registerClient(base);
});
after(() => httpServer.close());

const req = (...a) => H.req(base, ...a);

async function mcpListTools(accessToken) {
  const client = new Client({ name: 'oauth-test', version: '0' });
  const transport = new StreamableHTTPClientTransport(new URL(base + '/mcp'), {
    requestInit: { headers: { Authorization: `Bearer ${accessToken}` } }
  });
  await client.connect(transport);
  const { tools } = await client.listTools();
  await client.close();
  return tools.map(t => t.name);
}

const mcpStatus = async token =>
  (await req('POST', '/mcp', {
    auth: `Bearer ${token}`,
    headers: { Accept: 'application/json, text/event-stream' },
    json: { jsonrpc: '2.0', id: 1, method: 'tools/list' }
  })).status;

// ---- discovery ---------------------------------------------------------------

test('protected resource + authorization server metadata, built from PUBLIC_URL', async () => {
  for (const p of ['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp']) {
    const r = await req('GET', p);
    assert.equal(r.status, 200, p);
    assert.equal(r.json.resource, `${base}/mcp`);
    assert.deepEqual(r.json.authorization_servers, [`${base}/`]);
  }
  const as = await req('GET', '/.well-known/oauth-authorization-server');
  assert.equal(as.json.issuer, `${base}/`);
  assert.equal(as.json.authorization_endpoint, `${base}/authorize`);
  assert.equal(as.json.token_endpoint, `${base}/token`);
  assert.equal(as.json.registration_endpoint, `${base}/register`);
  assert.deepEqual(as.json.code_challenge_methods_supported, ['S256']);
  assert.deepEqual(as.json.response_types_supported, ['code']);
});

test('/mcp without a token: 401 pointing at the metadata and at claude mcp add', async () => {
  const r = await req('POST', '/mcp', { json: { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} } });
  assert.equal(r.status, 401);
  assert.equal(r.headers.get('www-authenticate'),
    `Bearer resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`);
  assert.match(r.json.error_description, /claude mcp add --transport http superkey http:\/\/127\.0\.0\.1:\d+\/mcp/);
  assert.match(r.json.error_description, /Authenticate/);
  // A browser session is not an MCP credential.
  assert.equal((await req('POST', '/mcp', { cookie: bobCookie, json: {} })).status, 401);
  assert.equal((await req('POST', '/mcp', { auth: `Bearer ${H.AGENT_API_TOKEN}`, json: {} })).status, 401);
  assert.equal((await req('POST', '/mcp', { auth: 'Bearer sk_oat_nope', json: {} })).status, 401);
});

// ---- registration -------------------------------------------------------------

test('DCR: loopback http (any port) and https redirect URIs only; clients are public', async () => {
  const ok = await H.registerClient(base, { redirect: 'http://localhost:4567/callback' });
  assert.equal(ok.token_endpoint_auth_method, 'none');
  assert.equal(ok.client_secret, undefined);
  assert.ok(await H.registerClient(base, { redirect: 'https://claude.ai/api/mcp/auth_callback' }));
  for (const bad of ['http://evil.example/cb', 'myapp://cb', 'https://x.example/cb#frag', 'http://user:pw@localhost/cb']) {
    const r = await req('POST', '/register', { json: { redirect_uris: [bad] } });
    assert.equal(r.status, 400, bad);
    assert.equal(r.json.error, 'invalid_client_metadata');
  }
  // A confidential registration request is turned into a public client: no secret stored.
  const conf = await req('POST', '/register', {
    json: { redirect_uris: [H.REDIRECT], token_endpoint_auth_method: 'client_secret_post' }
  });
  assert.equal(conf.json.token_endpoint_auth_method, 'none');
  assert.equal(conf.json.client_secret, undefined);
  assert.ok(!db.prepare('SELECT metadata FROM oauth_clients WHERE client_id = ?').get(conf.json.client_id).metadata.includes('secret'));
});

// ---- the full flow ---------------------------------------------------------------

test('full flow: authorize without session -> Google login -> consent -> code -> token -> /mcp -> refresh rotation -> reuse revokes', async () => {
  const client = await H.registerClient(base, { name: 'Claude Code (superkey)' });
  const { verifier, challenge } = H.pkce();

  // 1. No session: sent through Google login, with the way back remembered.
  const a = await req('GET', H.authorizePath(base, client, { challenge }));
  assert.equal(a.status, 302);
  assert.equal(a.location, '/auth/google');
  const cookie = a.headers.get('set-cookie').split(';')[0];
  const sid = decodeURIComponent(cookie.split('=')[1]).slice(2).split('.')[0];
  const sess = JSON.parse(db.prepare('SELECT sess FROM sessions WHERE sid = ?').get(sid).sess);
  assert.match(sess.returnTo, /^\/oauth\/consent\?request=/);

  // 2. "Google login" (passport would do this) — then follow returnTo.
  sess.passport = { user: { id: alice } };
  db.prepare('UPDATE sessions SET sess = ? WHERE sid = ?').run(JSON.stringify(sess), sid);
  const page = await req('GET', sess.returnTo, { cookie });
  assert.equal(page.status, 200);
  assert.match(page.text, /Claude Code \(superkey\)/);
  assert.match(page.text, /alice@example\.com/);
  assert.match(page.text, /127\.0\.0\.1:33418/, 'shows where the code goes');
  assert.match(page.text, /grant and revoke team-agent labels/);
  assert.equal(page.headers.get('x-frame-options'), 'DENY');

  // 3. Approve -> code at the registered redirect URI, with state and iss.
  const back = await H.consent(base, sess.returnTo, cookie, 'approve');
  assert.equal(back.status, 302);
  const cb = new URL(back.location);
  assert.equal(cb.origin + cb.pathname, H.REDIRECT);
  assert.equal(cb.searchParams.get('state'), 'st4te');
  assert.equal(cb.searchParams.get('iss'), `${base}/`);
  const code = cb.searchParams.get('code');

  // 4. Code + PKCE verifier -> tokens.
  const t = await H.exchangeCode(base, client, code, verifier);
  assert.equal(t.status, 200);
  assert.match(t.json.access_token, /^sk_oat_/);
  assert.match(t.json.refresh_token, /^sk_ort_/);
  assert.equal(t.json.token_type, 'Bearer');
  assert.equal(t.json.expires_in, 3600);
  assert.ok(!db.prepare('SELECT 1 FROM oauth_tokens WHERE token_hash = ?').get(t.json.access_token), 'only hashes stored');

  // 5. The token works at /mcp.
  assert.ok((await mcpListTools(t.json.access_token)).includes('grant_label'));

  // 6. Refresh rotates: new pair, old refresh token spent.
  const r1 = await H.refresh(base, client, t.json.refresh_token);
  assert.equal(r1.status, 200);
  assert.notEqual(r1.json.refresh_token, t.json.refresh_token);
  assert.notEqual(r1.json.access_token, t.json.access_token);
  assert.equal(await mcpStatus(r1.json.access_token), 200);

  // 7. Replaying the old refresh token revokes the whole grant.
  const replay = await H.refresh(base, client, t.json.refresh_token);
  assert.equal(replay.status, 400);
  assert.equal(replay.json.error, 'invalid_grant');
  assert.equal(await mcpStatus(r1.json.access_token), 401, 'access tokens of the grant die with it');
  assert.equal((await H.refresh(base, client, r1.json.refresh_token)).status, 400, 'and so does the current refresh token');
  const g = db.prepare('SELECT revoked_reason FROM oauth_grants ORDER BY id DESC LIMIT 1').get();
  assert.equal(g.revoked_reason, 'refresh token reuse');
});

test('the SDK client (what Claude Code uses) completes discovery, DCR, PKCE and token exchange on its own', async () => {
  const provider = {
    _client: undefined, _tokens: undefined, _verifier: undefined, authUrl: undefined,
    get redirectUrl() { return H.REDIRECT; },
    get clientMetadata() {
      return { client_name: 'sdk client', redirect_uris: [H.REDIRECT], grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'], token_endpoint_auth_method: 'none' };
    },
    clientInformation() { return this._client; },
    saveClientInformation(c) { this._client = c; },
    tokens() { return this._tokens; },
    saveTokens(t) { this._tokens = t; },
    redirectToAuthorization(url) { this.authUrl = url; },
    saveCodeVerifier(v) { this._verifier = v; },
    codeVerifier() { return this._verifier; }
  };
  const url = new URL(base + '/mcp');
  const first = new StreamableHTTPClientTransport(url, { authProvider: provider });
  await assert.rejects(new Client({ name: 'sdk', version: '0' }).connect(first), UnauthorizedError);
  assert.ok(provider._client.client_id, 'registered itself');
  assert.equal(provider.authUrl.searchParams.get('resource'), `${base}/mcp`);
  assert.equal(provider.authUrl.searchParams.get('code_challenge_method'), 'S256');

  // The "browser": signed-in user approves.
  const a = await req('GET', provider.authUrl.pathname + provider.authUrl.search, { cookie: aliceCookie });
  const back = await H.consent(base, a.location, aliceCookie, 'approve');
  await first.finishAuth(new URL(back.location).searchParams.get('code'));
  assert.match(provider._tokens.access_token, /^sk_oat_/);

  const client = new Client({ name: 'sdk', version: '0' });
  await client.connect(new StreamableHTTPClientTransport(url, { authProvider: provider }));
  const r = await client.callTool({ name: 'whoami', arguments: {} });
  assert.equal(JSON.parse(r.content[0].text).email, 'alice@example.com');
  await client.close();
});

// ---- failures --------------------------------------------------------------------

async function codeFor(cookie, client, opts = {}) {
  const { verifier, challenge } = H.pkce();
  const a = await req('GET', H.authorizePath(base, client, { challenge, ...opts }), { cookie });
  assert.equal(a.status, 302, a.text);
  const back = await H.consent(base, a.location, cookie, 'approve');
  return { code: new URL(back.location).searchParams.get('code'), verifier };
}

test('PKCE: a wrong code_verifier gets no token', async () => {
  const client = shared;
  const { code } = await codeFor(aliceCookie, client);
  const r = await H.exchangeCode(base, client, code, H.pkce().verifier);
  assert.equal(r.status, 400);
  assert.equal(r.json.error, 'invalid_grant');
});

test('PKCE: plain or missing challenges are refused at /authorize', async () => {
  const client = shared;
  const q = new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: H.REDIRECT,
    code_challenge: 'abc', code_challenge_method: 'plain' });
  const r = await req('GET', '/authorize?' + q, { cookie: aliceCookie });
  assert.equal(r.status, 302);
  assert.equal(new URL(r.location).searchParams.get('error'), 'invalid_request');
});

test('redirect_uri: unregistered at /authorize is a 400 (never redirected); mismatched at /token is refused', async () => {
  const client = shared;
  const { challenge } = H.pkce();
  for (const redirect of ['http://127.0.0.1:33418/other', 'https://evil.example/callback']) {
    const r = await req('GET', H.authorizePath(base, client, { challenge, redirect }), { cookie: aliceCookie });
    assert.equal(r.status, 400, redirect);
    assert.equal(r.location, null);
  }
  // Loopback: any port is fine (RFC 8252), path must match exactly.
  const okPort = await req('GET', H.authorizePath(base, client, { challenge, redirect: 'http://127.0.0.1:1/callback' }), { cookie: aliceCookie });
  assert.equal(okPort.status, 302);

  const { code, verifier } = await codeFor(aliceCookie, client);
  const r = await H.exchangeCode(base, client, code, verifier, { redirect_uri: 'http://127.0.0.1:33418/elsewhere' });
  assert.equal(r.status, 400);
  assert.equal(r.json.error, 'invalid_grant');
});

test('resource indicator: other resources are refused at /authorize and /token', async () => {
  const client = shared;
  const { challenge } = H.pkce();
  const r = await req('GET', H.authorizePath(base, client, { challenge, resource: 'https://other.example/mcp' }), { cookie: aliceCookie });
  assert.equal(r.status, 302);
  const err = new URL(r.location);
  assert.equal(err.searchParams.get('error'), 'invalid_target');
  assert.equal(err.searchParams.get('state'), 'st4te');

  const { code, verifier } = await codeFor(aliceCookie, client);
  const t = await H.exchangeCode(base, client, code, verifier, { resource: 'https://other.example/mcp' });
  assert.equal(t.status, 400);
  assert.equal(t.json.error, 'invalid_target');
});

test('authorization codes are single-use; a replay revokes the grant it produced', async () => {
  const client = shared;
  const { code, verifier } = await codeFor(aliceCookie, client);
  const t = await H.exchangeCode(base, client, code, verifier);
  assert.equal(t.status, 200);
  const again = await H.exchangeCode(base, client, code, verifier);
  assert.equal(again.json.error, 'invalid_grant');
  assert.equal(await mcpStatus(t.json.access_token), 401);
});

test('consent deny: access_denied back to the client, no code', async () => {
  const client = shared;
  const { challenge } = H.pkce();
  const a = await req('GET', H.authorizePath(base, client, { challenge }), { cookie: aliceCookie });
  const back = await H.consent(base, a.location, aliceCookie, 'deny');
  const u = new URL(back.location);
  assert.equal(u.searchParams.get('error'), 'access_denied');
  assert.equal(u.searchParams.get('state'), 'st4te');
  assert.equal(u.searchParams.get('code'), null);
  // The request is spent either way.
  assert.equal((await req('GET', a.location, { cookie: aliceCookie })).status, 400);
});

test('consent CSRF: the approval must come from the page shown in the same browser session', async () => {
  const client = shared;
  const { challenge } = H.pkce();
  const a = await req('GET', H.authorizePath(base, client, { challenge }), { cookie: aliceCookie });
  const page = await req('GET', a.location, { cookie: aliceCookie });
  const request = page.text.match(/name="request" value="([^"]+)"/)[1];
  const csrf = page.text.match(/name="csrf" value="([^"]+)"/)[1];
  // Someone else's browser (bob's session) replaying alice's form.
  const forged = await req('POST', '/oauth/consent', { cookie: bobCookie, form: { request, csrf, decision: 'approve' } });
  assert.equal(forged.status, 403);
  // No/incorrect csrf in alice's own session.
  assert.equal((await req('POST', '/oauth/consent', { cookie: aliceCookie, form: { request, csrf: 'x', decision: 'approve' } })).status, 403);
  // Signed out: refused.
  assert.equal((await req('POST', '/oauth/consent', { form: { request, csrf, decision: 'approve' } })).status, 401);
});

test('OAuth tokens are rejected on /api/* (401) and never fall back to the cookie', async () => {
  const { tokens } = await H.oauthLogin(base, bobCookie, { client: shared });
  for (const path of ['/api/me', '/API/me', '/api/me/', '/api/users', '/api/servers']) {
    const r = await req('GET', path, { auth: `Bearer ${tokens.access_token}`, cookie: bobCookie });
    assert.equal(r.status, 401, path);
    assert.equal(r.headers.get('set-cookie'), null);
  }
  assert.equal((await req('GET', '/api/me', { auth: `bearer ${tokens.access_token}`, cookie: bobCookie })).status, 401);
  assert.equal((await req('GET', '/api/me', { auth: `Bearer ${tokens.refresh_token}`, cookie: bobCookie })).status, 401);
  // The cookie alone still works, as on origin/main.
  assert.equal((await req('GET', '/api/me', { cookie: bobCookie })).status, 200);
});

test('Connected apps: list own grants, revoke one (token dies), not someone else\'s', async () => {
  const { tokens } = await H.oauthLogin(base, aliceCookie, { client: await H.registerClient(base, { name: 'Laptop' }) });
  const list = await req('GET', '/api/me/oauth-grants', { cookie: aliceCookie });
  const grant = list.json.find(g => g.client_name === 'Laptop');
  assert.equal(grant.redirect_host, '127.0.0.1:33418');
  assert.ok(grant.created_at);
  assert.equal(await mcpStatus(tokens.access_token), 200);
  assert.ok(list.json.length >= 1);

  assert.equal((await req('DELETE', `/api/me/oauth-grants/${grant.id}`, { cookie: bobCookie })).status, 404);
  assert.equal((await req('DELETE', `/api/me/oauth-grants/${grant.id}`, { cookie: aliceCookie })).status, 200);
  assert.equal(await mcpStatus(tokens.access_token), 401);
  assert.equal((await H.refresh(base, { client_id: db.prepare('SELECT client_id FROM oauth_grants WHERE id = ?').get(grant.id).client_id }, tokens.refresh_token)).status, 400);
  assert.ok(!(await req('GET', '/api/me/oauth-grants', { cookie: aliceCookie })).json.some(g => g.id === grant.id));
});

test('expired access token: 401; a user deleted by the Google sync: 401 and no refresh', async () => {
  const f = H.fixtures(db);
  const carol = f.user('carol', 'carol@example.com', 'Carol');
  const carolCookie = H.sessionCookie(db, carol);
  const { client, tokens } = await H.oauthLogin(base, carolCookie, { client: shared });
  assert.equal(await mcpStatus(tokens.access_token), 200);

  db.prepare("UPDATE oauth_tokens SET expires_at = 1 WHERE kind = 'access' AND grant_id = (SELECT MAX(id) FROM oauth_grants)").run();
  assert.equal(await mcpStatus(tokens.access_token), 401);
  const fresh = await H.refresh(base, client, tokens.refresh_token);
  assert.equal(fresh.status, 200);
  assert.equal(await mcpStatus(fresh.json.access_token), 200);

  db.prepare('DELETE FROM users WHERE id = ?').run(carol);
  assert.equal(await mcpStatus(fresh.json.access_token), 401);
  assert.equal((await H.refresh(base, client, fresh.json.refresh_token)).json.error, 'invalid_grant');
});

test('revocation endpoint (RFC 7009) ends the grant', async () => {
  const { client, tokens } = await H.oauthLogin(base, aliceCookie, { client: shared });
  const r = await req('POST', '/revoke', { form: { client_id: client.client_id, token: tokens.refresh_token } });
  assert.equal(r.status, 200);
  assert.equal(await mcpStatus(tokens.access_token), 401);
});

test('consent page without a session goes through Google login', async () => {
  const client = shared;
  const { challenge } = H.pkce();
  const a = await req('GET', H.authorizePath(base, client, { challenge }), { cookie: aliceCookie });
  const r = await req('GET', a.location);
  assert.equal(r.status, 302);
  assert.equal(r.location, '/auth/google');
});
