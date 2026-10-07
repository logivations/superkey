// End to end against the real express app on an ephemeral port: PAT auth
// in the existing middleware, token management (session-only), machine
// tokens still working, and the MCP endpoint with its permission checks.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { setupEnv, fixtures, sessionCookie, listen, AGENT_API_TOKEN, DEPLOY_API_TOKEN } = require('./helpers');

setupEnv();
const db = require('../src/database');
const tokens = require('../src/tokens');
const { app } = require('../src/server');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js');

const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

// alice: non-admin, holds "brummer" via brummer_team.
// bob:   superkey admin (holds every label for granting), NOT in mcpservers' allowed_users.
// carol: non-admin, holds "infra" via ops, and IS mcpservers' allowed user.
const f = fixtures(db);
const alice = f.user('alice', 'alice.smith@example.com', 'Alice');
const bob = f.user('bob', 'bob@example.com', 'Bob');
const carol = f.user('carol', 'carol@example.com', 'Carol');
f.member(alice, 'brummer_team');
f.member(carol, 'brummer_team');
f.member(bob, 'superkey_admins');
f.member(carol, 'ops');
f.grantGroup('brummer', 'brummer_team');
f.grantGroup('infra', 'ops');
f.label('kaufland');
f.server('br-amr1', ['brummer']);
f.server('br-amr2', ['brummer']);
f.server('br-amr3', ['brummer']);
f.server('kl-1', ['kaufland']);
f.server('mcpservers', ['infra']);
f.server('ops-1', ['infra']);
f.server('prod-db', ['legacy']);
db.prepare('UPDATE users SET public_key = ? WHERE id IN (?, ?, ?)').run(KEY, alice, bob, carol);
db.prepare("INSERT INTO bot_keys (user_id, name, public_key, source_cidr) VALUES (?, 'nemo', ?, '10.0.0.5')").run(alice, KEY);

const pat = {};
let base;
let httpServer;

before(async () => {
  ({ server: httpServer, base } = await listen(app));
  for (const [name, id] of Object.entries({ alice, bob, carol })) pat[name] = tokens.createToken(id, 'test').token;
});
after(() => httpServer.close());

async function call(method, path, { token, cookie, body, auth } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  if (auth) headers.Authorization = auth;
  if (cookie) headers.Cookie = cookie;
  const res = await fetch(base + path, { method, headers, body: body && JSON.stringify(body) });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch (e) { /* not JSON */ }
  return { status: res.status, json, headers: res.headers };
}

async function mcpClient(token) {
  const client = new Client({ name: 'superkey-test', version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(base + '/mcp'), {
    requestInit: { headers: { Authorization: `Bearer ${token}` } }
  });
  await client.connect(transport);
  return client;
}

async function tool(client, name, args = {}) {
  const r = await client.callTool({ name, arguments: args });
  return { isError: !!r.isError, data: JSON.parse(r.content[0].text) };
}

// ---- machine tokens --------------------------------------------------------

test('AGENT_API_TOKEN still registers team agents; a PAT does not', async () => {
  const ok = await call('POST', '/api/agents/register', {
    auth: `Bearer ${AGENT_API_TOKEN}`, body: { name: 'opsbot', publicKey: KEY, description: 'ops helper' }
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.account, 'agent_opsbot');
  const viaPat = await call('POST', '/api/agents/register', {
    token: pat.bob, body: { name: 'evil', publicKey: KEY }
  });
  assert.equal(viaPat.status, 403); // outside the PAT scope, before isAgentApi even looks
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM team_agents WHERE name = 'evil'").get().n, 0);
});

test('DEPLOY_API_TOKEN still reads deploy data; a PAT (even an admin\'s) does not', async () => {
  assert.equal((await call('GET', '/api/stale-servers', { auth: `Bearer ${DEPLOY_API_TOKEN}` })).status, 200);
  assert.equal((await call('GET', '/api/deploy-data', { token: pat.bob })).status, 401);
});

// ---- PAT -> req.user -------------------------------------------------------

test('a PAT authenticates as its owner on existing session routes', async () => {
  const me = await call('GET', '/api/me', { token: pat.alice });
  assert.equal(me.status, 200);
  assert.equal(me.json.email, 'alice.smith@example.com');
  assert.equal(me.json.isAdmin, false);
  assert.deepEqual(me.json.groups, ['brummer_team']);
  assert.equal(me.json.accessToken, undefined);

  const mine = await call('GET', '/api/my-servers', { token: pat.alice });
  assert.deepEqual(mine.json.map(s => s.hostname), ['br-amr1', 'br-amr2', 'br-amr3']);
});

test('isAdmin works with PATs: admin owner 200, non-admin owner 403', async () => {
  assert.equal((await call('GET', '/api/users', { token: pat.bob })).status, 200);
  assert.equal((await call('GET', '/api/users', { token: pat.alice })).status, 403);
});

// ---- PAT scope: read + agent-label only ------------------------------------

test('PAT scope: SSH key and personal-agent changes need a browser session', async () => {
  const before = db.prepare('SELECT public_key FROM users WHERE id = ?').get(alice).public_key;
  const put = await call('PUT', '/api/me/public-key', { token: pat.alice, body: { publicKey: KEY + ' planted' } });
  assert.equal(put.status, 403);
  assert.match(put.json.error, /requires a browser session: API tokens are read \+ agent-label only/);
  assert.equal(db.prepare('SELECT public_key FROM users WHERE id = ?').get(alice).public_key, before);

  const bot = await call('POST', '/api/me/bots', { token: pat.alice, body: { name: 'planted', publicKey: KEY, docker: true } });
  assert.equal(bot.status, 403);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM bot_keys WHERE name = 'planted'").get().n, 0);
  const nemo = db.prepare("SELECT id FROM bot_keys WHERE name = 'nemo'").get().id;
  assert.equal((await call('DELETE', `/api/me/bots/${nemo}`, { token: pat.alice })).status, 403);
  assert.equal((await call('PUT', `/api/me/bots/${nemo}/access`, { token: pat.alice, body: { docker: true } })).status, 403);
  assert.equal((await call('POST', '/api/sync-groups', { token: pat.alice })).status, 403);
  // Case/slash variants are the same route to Express, and the same refusal.
  assert.equal((await call('PUT', '/API/Me/Public-Key/', { token: pat.alice, body: { publicKey: KEY } })).status, 403);
  // The same calls still work from a session.
  assert.equal((await call('PUT', '/api/me/public-key', { cookie: sessionCookie(db, alice), body: { publicKey: KEY } })).status, 200);
});

test('PAT scope: an admin\'s PAT cannot mutate admin resources, but can read them', async () => {
  const labels = () => db.prepare('SELECT COUNT(*) AS n FROM labels').get().n;
  const n = labels();
  const r = await call('POST', '/api/labels', { token: pat.bob, body: { name: 'planted' } });
  assert.equal(r.status, 403);
  assert.equal(labels(), n);
  const brummer = f.label('brummer');
  const team = f.group('brummer_team');
  assert.equal((await call('DELETE', `/api/labels/${brummer}/groups/${team}`, { token: pat.bob })).status, 403);
  assert.equal((await call('POST', '/api/sync-all-groups', { token: pat.bob })).status, 403);
  assert.equal((await call('GET', '/api/users', { token: pat.bob })).status, 200);
  // From a session the admin still can.
  assert.equal((await call('POST', '/api/labels', { cookie: sessionCookie(db, bob), body: { name: 'from-session' } })).status, 200);
});

test('PAT scope: GETs are allowed (whole-fleet server list)', async () => {
  const r = await call('GET', '/api/servers', { token: pat.alice });
  assert.equal(r.status, 200);
  assert.ok(r.json.some(s => s.hostname === 'kl-1'));
});

test('a session and a PAT resolve to the same user object', async () => {
  const viaCookie = await call('GET', '/api/me', { cookie: sessionCookie(db, alice) });
  const viaPat = await call('GET', '/api/me', { token: pat.alice });
  assert.equal(viaCookie.status, 200);
  assert.deepEqual(viaPat.json, viaCookie.json);
});

test('a bad PAT is a hard 401, never a fallback to the cookie it came with', async () => {
  const r = await call('GET', '/api/me', { token: 'sk_pat_nope', cookie: sessionCookie(db, bob) });
  assert.equal(r.status, 401);
  assert.match(r.headers.get('www-authenticate'), /invalid_token/);
});

test('a cookie riding along with a PAT cannot change who the request runs as', async () => {
  const r = await call('GET', '/api/me', { token: pat.alice, cookie: sessionCookie(db, bob) });
  assert.equal(r.json.email, 'alice.smith@example.com');
  assert.equal(r.json.isAdmin, false);
  assert.equal((await call('GET', '/api/users', { token: pat.alice, cookie: sessionCookie(db, bob) })).status, 403);
  assert.equal(r.headers.get('set-cookie'), null, 'PAT requests never get a session cookie');
});

test('PAT detection matches Express routing: path case, trailing slash and scheme case cannot fall back to the cookie', async () => {
  const cookie = sessionCookie(db, bob);
  // Bad PAT on case/slash variants of a route: hard 401, not bob's session.
  for (const path of ['/API/me', '/Api/Me/', '/api/me/']) {
    assert.equal((await call('GET', path, { token: 'sk_pat_nope', cookie })).status, 401, path);
  }
  assert.equal((await call('GET', '/api/me', { auth: 'bearer sk_pat_nope', cookie })).status, 401);
  // A valid PAT on such variants is the PAT's owner, and still cannot manage tokens.
  const r = await call('GET', '/API/me', { auth: `bearer ${pat.alice}`, cookie });
  assert.equal(r.json.email, 'alice.smith@example.com');
  assert.equal((await call('POST', '/API/me/tokens', { token: pat.alice, cookie, body: { name: 'x' } })).status, 403);
  assert.equal((await call('GET', '/api/me/tokens/', { token: pat.alice, cookie })).status, 403);
  // /mcp/ (Express matches it to /mcp) takes the PAT too.
  const res = await fetch(base + '/mcp/', {
    method: 'POST',
    headers: { Authorization: `Bearer ${pat.alice}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '0' } } })
  });
  assert.equal(res.status, 200);
});

test('no credentials: 401 as before', async () => {
  assert.equal((await call('GET', '/api/me')).status, 401);
});

test('revoked PAT stops working immediately', async () => {
  const t = tokens.createToken(alice, 'short-lived');
  assert.equal((await call('GET', '/api/me', { token: t.token })).status, 200);
  tokens.revokeToken(alice, t.id);
  assert.equal((await call('GET', '/api/me', { token: t.token })).status, 401);
});

// ---- token management ------------------------------------------------------

test('session users create, list and revoke their tokens', async () => {
  const cookie = sessionCookie(db, carol);
  const created = await call('POST', '/api/me/tokens', { cookie, body: { name: 'claude code', expiresInDays: 90 } });
  assert.equal(created.status, 200);
  assert.match(created.json.token, /^sk_pat_/);
  assert.ok(created.json.expires_at);

  const list = await call('GET', '/api/me/tokens', { cookie });
  const row = list.json.find(t => t.id === created.json.id);
  assert.equal(row.name, 'claude code');
  assert.equal(row.token, undefined);
  assert.equal(row.token_hash, undefined);

  assert.equal((await call('GET', '/api/me', { token: created.json.token })).json.email, 'carol@example.com');
  // Someone else's session cannot revoke it.
  assert.equal((await call('DELETE', `/api/me/tokens/${created.json.id}`, { cookie: sessionCookie(db, bob) })).status, 404);
  assert.equal((await call('DELETE', `/api/me/tokens/${created.json.id}`, { cookie })).status, 200);
  assert.equal((await call('GET', '/api/me', { token: created.json.token })).status, 401);
});

test('PATs cannot mint, list or revoke PATs', async () => {
  const mint = await call('POST', '/api/me/tokens', { token: pat.bob, body: { name: 'successor' } });
  assert.equal(mint.status, 403);
  assert.match(mint.json.error, /requires a browser session/);
  const list = await call('GET', '/api/me/tokens', { token: pat.bob });
  assert.match(list.json.error, /cannot manage API tokens/);
  assert.equal((await call('GET', '/api/me/tokens', { token: pat.bob })).status, 403);
  const own = tokens.listTokens(bob)[0];
  assert.equal((await call('DELETE', `/api/me/tokens/${own.id}`, { token: pat.bob })).status, 403);
  // Even with a valid session cookie alongside: the PAT decides, and it may not.
  assert.equal((await call('POST', '/api/me/tokens', {
    token: pat.bob, cookie: sessionCookie(db, bob), body: { name: 'successor' }
  })).status, 403);
  assert.equal(tokens.listTokens(bob).length, 1);
});

test('token management without any auth: 401', async () => {
  assert.equal((await call('POST', '/api/me/tokens', { body: { name: 'x' } })).status, 401);
});

// ---- HTTP grant route (refactored onto the shared logic) -------------------

test('HTTP: non-admin cannot grant a label they do not hold, can grant one they do', async () => {
  const agent = db.prepare("SELECT id FROM team_agents WHERE name = 'opsbot'").get().id;
  const kaufland = f.label('kaufland');
  const brummer = f.label('brummer');
  const denied = await call('POST', `/api/agents/${agent}/labels/${kaufland}`, { token: pat.alice });
  assert.equal(denied.status, 403);
  assert.match(denied.json.error, /only grant labels you have access to/);
  assert.equal((await call('POST', `/api/agents/${agent}/labels/${brummer}`, { token: pat.alice })).status, 200);
  assert.equal((await call('DELETE', `/api/agents/${agent}/labels/${brummer}`, { token: pat.alice })).status, 200);
  assert.equal((await call('POST', `/api/agents/9999/labels/${brummer}`, { token: pat.alice })).status, 404);
});

// ---- MCP ------------------------------------------------------------------

test('MCP: 401 with a helpful message without a PAT, session cookies do not count', async () => {
  const init = { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} };
  const none = await call('POST', '/mcp', { body: init });
  assert.equal(none.status, 401);
  assert.match(none.json.error.message, /personal access token/);
  assert.equal((await call('POST', '/mcp', { body: init, cookie: sessionCookie(db, bob) })).status, 401);
  assert.equal((await call('POST', '/mcp', { body: init, auth: `Bearer ${AGENT_API_TOKEN}` })).status, 401);
  assert.equal((await call('POST', '/mcp', { body: init, token: 'sk_pat_wrong' })).status, 401);
  assert.equal((await call('GET', '/mcp', { token: pat.alice })).status, 405);
  assert.equal((await call('GET', '/.well-known/oauth-protected-resource/mcp')).status, 404);
});

test('MCP: initialize + tools/list exposes exactly the contracted tools', async () => {
  const client = await mcpClient(pat.alice);
  const { tools } = await client.listTools();
  assert.deepEqual(tools.map(t => t.name).sort(), [
    'deploy_status', 'grant_label', 'list_agents', 'list_grantable_labels',
    'list_my_bots', 'revoke_label', 'search_servers', 'whoami'
  ]);
  for (const t of tools) assert.ok(t.description.length > 40, `${t.name} has a real description`);
  const grant = tools.find(t => t.name === 'grant_label');
  assert.deepEqual(grant.inputSchema.required.sort(), ['agent', 'label']);
  await client.close();
});

test('MCP whoami runs as the token owner', async () => {
  const client = await mcpClient(pat.alice);
  const { data } = await tool(client, 'whoami');
  assert.equal(data.email, 'alice.smith@example.com');
  assert.equal(data.linux_username, 'alice_smith');
  assert.equal(data.isAdmin, false);
  assert.deepEqual(data.groups, ['brummer_team']);
  await client.close();
  const admin = await mcpClient(pat.bob);
  assert.equal((await tool(admin, 'whoami')).data.isAdmin, true);
  await admin.close();
});

test('MCP grant_label: a non-admin cannot grant a label they do not hold', async () => {
  const client = await mcpClient(pat.alice);
  const r = await tool(client, 'grant_label', { agent: 'opsbot', label: 'kaufland' });
  assert.equal(r.isError, true);
  assert.match(r.data.error, /only grant labels you have access to/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM agent_labels').get().n, 0);
  await client.close();
});

test('MCP grant_label / revoke_label: by name or account, idempotent', async () => {
  const client = await mcpClient(pat.alice);
  let r = await tool(client, 'grant_label', { agent: 'agent_opsbot', label: 'brummer' });
  assert.equal(r.isError, false);
  assert.equal(r.data.changed, true);
  assert.equal(r.data.servers_with_label, 3);
  r = await tool(client, 'grant_label', { agent: 'opsbot', label: 'Brummer' });
  assert.equal(r.data.changed, false, 'second grant is a no-op');

  r = await tool(client, 'revoke_label', { agent: 'opsbot', label: 'brummer' });
  assert.equal(r.data.changed, true);
  r = await tool(client, 'revoke_label', { agent: 'opsbot', label: 'brummer' });
  assert.equal(r.data.changed, false);

  const agentId = db.prepare("SELECT id FROM team_agents WHERE name = 'opsbot'").get().id;
  r = await tool(client, 'grant_label', { agent: agentId, label: f.label('brummer') });
  assert.equal(r.data.changed, true, 'numeric ids work too');

  r = await tool(client, 'grant_label', { agent: 'nosuchagent', label: 'brummer' });
  assert.equal(r.isError, true);
  assert.match(r.data.error, /list_agents/);
  await client.close();
});

test('MCP grant_label: restricted servers block even admins; allowed_users may', async () => {
  const admin = await mcpClient(pat.bob);
  let r = await tool(admin, 'grant_label', { agent: 'opsbot', label: 'infra' });
  assert.equal(r.isError, true);
  assert.match(r.data.error, /restricted server\(s\) mcpservers/);

  // Admin can grant labels they do not hold via a group (no restricted servers on it).
  r = await tool(admin, 'grant_label', { agent: 'opsbot', label: 'kaufland' });
  assert.equal(r.data.changed, true);
  await tool(admin, 'revoke_label', { agent: 'opsbot', label: 'kaufland' });

  const labels = (await tool(admin, 'list_grantable_labels')).data;
  const infra = labels.find(l => l.name === 'infra');
  assert.equal(infra.can_grant, false);
  assert.deepEqual(infra.blocked_by, ['mcpservers']);
  await admin.close();

  // carol holds infra and is mcpservers' allowed user.
  const client = await mcpClient(pat.carol);
  r = await tool(client, 'grant_label', { agent: 'opsbot', label: 'infra' });
  assert.equal(r.isError, false);
  assert.equal(r.data.changed, true);
  // ...and bob may not even take it away again (allowed_users is exclusive).
  const admin2 = await mcpClient(pat.bob);
  r = await tool(admin2, 'revoke_label', { agent: 'opsbot', label: 'infra' });
  assert.equal(r.isError, true);
  await admin2.close();
  r = await tool(client, 'revoke_label', { agent: 'opsbot', label: 'infra' });
  assert.equal(r.data.changed, true);
  await client.close();
});

test('MCP list_grantable_labels mirrors /api/me/labels', async () => {
  const client = await mcpClient(pat.alice);
  const { data } = await tool(client, 'list_grantable_labels');
  const http = await call('GET', '/api/me/labels', { token: pat.alice });
  assert.deepEqual(data.map(l => l.name), http.json.map(l => l.name));
  assert.deepEqual(data, [{
    id: f.label('brummer'), name: 'brummer', server_count: 3, groups: ['brummer_team'],
    held_by_any_group: true, restricted_servers: [], can_grant: true
  }]);
  await client.close();
});

test('MCP search_servers: query, label, limit, reachability', async () => {
  const client = await mcpClient(pat.alice);
  let { data } = await tool(client, 'search_servers', { query: 'br-amr' });
  assert.equal(data.total_matches, 3);
  assert.ok(data.servers.every(s => s.reachable_by_me && s.labels.includes('brummer')));
  ({ data } = await tool(client, 'search_servers', { label: 'kaufland' }));
  assert.deepEqual(data.servers.map(s => [s.hostname, s.reachable_by_me]), [['kl-1', false]]);
  ({ data } = await tool(client, 'search_servers', { query: 'br-amr', limit: 1 }));
  assert.equal(data.returned, 1);
  assert.equal(data.total_matches, 3);
  ({ data } = await tool(client, 'search_servers', {}));
  assert.equal(data.total_matches, 7, 'the whole fleet, as GET /api/servers shows it');
  const mcp = data.servers.find(s => s.hostname === 'mcpservers');
  assert.equal(mcp.restricted, true);
  assert.equal(mcp.deploy.state, 'never-deployed');
  await client.close();
});

test('MCP list_agents and list_my_bots', async () => {
  const client = await mcpClient(pat.alice);
  const agents = (await tool(client, 'list_agents', { query: 'ops' })).data;
  assert.equal(agents.length, 1);
  assert.equal(agents[0].account, 'agent_opsbot');
  assert.equal(agents[0].description, 'ops helper');
  assert.deepEqual(agents[0].labels, ['brummer']);
  assert.deepEqual((await tool(client, 'list_agents', { query: 'zzz' })).data, []);

  const bots = (await tool(client, 'list_my_bots')).data;
  assert.equal(bots.length, 1);
  assert.equal(bots[0].account, 'alice_smith_nemo');
  assert.equal(bots[0].device_count, 3);
  assert.equal(bots[0].key_type, 'ssh-ed25519');
  // Only one's own bots.
  const other = await mcpClient(pat.carol);
  assert.deepEqual((await tool(other, 'list_my_bots')).data, []);
  await other.close();
  await client.close();
});

test('MCP deploy_status: deployed / pending / never-deployed per agent and label', async () => {
  // opsbot holds brummer (from the grant test). Simulate the runner: br-amr1
  // got the current key set, br-amr2 an older one, br-amr3 was never reached.
  const servers = (await call('GET', '/api/servers', { token: pat.bob })).json;
  const expected = Object.fromEntries(servers.map(s => [s.hostname, s.expected_keys_hash]));
  const report = (host, hash) => call('POST', `/api/servers/${host}/deployed`, {
    auth: `Bearer ${DEPLOY_API_TOKEN}`, body: { keys_hash: hash }
  });
  assert.equal((await report('br-amr1', expected['br-amr1'])).status, 200);
  assert.equal((await report('br-amr2', '0123456789abcdef')).status, 200);

  // A legacy grant on a restricted no-agents server (made before the
  // policy existed): excluded, never counted.
  const agentId = db.prepare("SELECT id FROM team_agents WHERE name = 'opsbot'").get().id;
  db.prepare('INSERT INTO agent_labels (agent_id, label_id) VALUES (?, ?)').run(agentId, f.label('legacy'));

  const client = await mcpClient(pat.alice);
  let { data } = await tool(client, 'deploy_status', { agent: 'opsbot' });
  assert.deepEqual(data.summary, { servers: 3, deployed: 1, pending: 1, never_deployed: 1 });
  assert.deepEqual(data.servers.map(s => [s.hostname, s.state, s.agent_key_deployed]), [
    ['br-amr2', 'pending', false],
    ['br-amr3', 'never-deployed', false],
    ['br-amr1', 'deployed', true]
  ]);
  assert.ok(data.servers.find(s => s.hostname === 'br-amr1').last_deployed_at.endsWith('Z'));
  assert.deepEqual(data.excluded.map(e => e.hostname), ['prod-db']);
  assert.deepEqual(data.agent_labels, ['brummer', 'legacy']);
  assert.match(data.note, /1-2 minutes/);

  ({ data } = await tool(client, 'deploy_status', { label: 'brummer' }));
  assert.deepEqual(data.summary, { servers: 3, deployed: 1, pending: 1, never_deployed: 1 });
  assert.deepEqual(data.agents_with_label, ['opsbot']);

  ({ data } = await tool(client, 'deploy_status', { agent: 'opsbot', label: 'kaufland' }));
  assert.equal(data.summary.servers, 0, 'the agent is not expected on kaufland servers');
  assert.equal(data.servers[0].agent_expected, false);
  assert.match(data.warning, /does not hold label "kaufland"/);

  const none = await tool(client, 'deploy_status', {});
  assert.equal(none.isError, true);
  await client.close();
});
