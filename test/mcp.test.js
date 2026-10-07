// MCP tools end to end: the real express app on a local port, an OAuth
// access token obtained through the full flow (src/oauth.js), and the SDK
// client. Covers every tool and its permission checks, plus the shared
// HTTP grant route and the machine tokens.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./helpers');

const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

let db, f, base, httpServer, Client, StreamableHTTPClientTransport;
let alice, bob, carol;
const tok = {};
const cookie = {};

// alice: non-admin, holds "brummer" via brummer_team.
// bob:   superkey admin (holds every label for granting), NOT in mcpservers' allowed_users.
// carol: non-admin, holds "infra" via ops, and IS mcpservers' allowed user.
before(async () => {
  const port = await H.freePort();
  H.setupEnv(port);
  db = require('../src/database');
  const { app } = require('../src/server');
  ({ Client } = require('@modelcontextprotocol/sdk/client/index.js'));
  ({ StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js'));

  f = H.fixtures(db);
  alice = f.user('alice', 'alice.smith@example.com', 'Alice');
  bob = f.user('bob', 'bob@example.com', 'Bob');
  carol = f.user('carol', 'carol@example.com', 'Carol');
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

  ({ server: httpServer, base } = await H.listen(app, port));
  const client = await H.registerClient(base);
  for (const [name, id] of Object.entries({ alice, bob, carol })) {
    cookie[name] = H.sessionCookie(db, id);
    tok[name] = (await H.oauthLogin(base, cookie[name], { client })).tokens.access_token;
  }
});
after(() => httpServer.close());

async function call(method, path, { token, cookie: c, body, auth } = {}) {
  return H.req(base, method, path, { cookie: c, json: body, auth: auth || (token && `Bearer ${token}`) });
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

test('AGENT_API_TOKEN still registers team agents; an OAuth token does not', async () => {
  const ok = await call('POST', '/api/agents/register', {
    auth: `Bearer ${H.AGENT_API_TOKEN}`, body: { name: 'opsbot', publicKey: KEY, description: 'ops helper' }
  });
  assert.equal(ok.status, 200);
  assert.equal(ok.json.account, 'agent_opsbot');
  const viaOAuth = await call('POST', '/api/agents/register', { token: tok.bob, body: { name: 'evil', publicKey: KEY } });
  assert.equal(viaOAuth.status, 401);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM team_agents WHERE name = 'evil'").get().n, 0);
});

test('DEPLOY_API_TOKEN still reads deploy data; an OAuth token (even an admin\'s) does not', async () => {
  assert.equal((await call('GET', '/api/stale-servers', { auth: `Bearer ${H.DEPLOY_API_TOKEN}` })).status, 200);
  assert.equal((await call('GET', '/api/deploy-data', { token: tok.bob })).status, 401);
});

// ---- HTTP grant route (shared logic with grant_label) ----------------------

test('HTTP: non-admin cannot grant a label they do not hold, can grant one they do', async () => {
  const agent = db.prepare("SELECT id FROM team_agents WHERE name = 'opsbot'").get().id;
  const kaufland = f.label('kaufland');
  const brummer = f.label('brummer');
  const denied = await call('POST', `/api/agents/${agent}/labels/${kaufland}`, { cookie: cookie.alice });
  assert.equal(denied.status, 403);
  assert.match(denied.json.error, /only grant labels you have access to/);
  assert.equal((await call('POST', `/api/agents/${agent}/labels/${brummer}`, { cookie: cookie.alice })).status, 200);
  assert.equal((await call('DELETE', `/api/agents/${agent}/labels/${brummer}`, { cookie: cookie.alice })).status, 200);
  assert.equal((await call('POST', `/api/agents/9999/labels/${brummer}`, { cookie: cookie.alice })).status, 404);
});

// ---- MCP ------------------------------------------------------------------

test('MCP: GET is 405 (stateless server)', async () => {
  assert.equal((await call('GET', '/mcp', { token: tok.alice })).status, 405);
});

test('MCP: initialize + tools/list exposes exactly the contracted tools', async () => {
  const client = await mcpClient(tok.alice);
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

test('MCP whoami runs as the user who connected the app', async () => {
  const client = await mcpClient(tok.alice);
  const { data } = await tool(client, 'whoami');
  assert.equal(data.email, 'alice.smith@example.com');
  assert.equal(data.linux_username, 'alice_smith');
  assert.equal(data.isAdmin, false);
  assert.deepEqual(data.groups, ['brummer_team']);
  assert.equal(data.connection.client, 'Test client');
  await client.close();
  const admin = await mcpClient(tok.bob);
  assert.equal((await tool(admin, 'whoami')).data.isAdmin, true);
  await admin.close();
});

test('MCP grant_label: a non-admin cannot grant a label they do not hold', async () => {
  const client = await mcpClient(tok.alice);
  const r = await tool(client, 'grant_label', { agent: 'opsbot', label: 'kaufland' });
  assert.equal(r.isError, true);
  assert.match(r.data.error, /only grant labels you have access to/);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM agent_labels').get().n, 0);
  await client.close();
});

test('MCP grant_label / revoke_label: by name or account, idempotent', async () => {
  const client = await mcpClient(tok.alice);
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
  const admin = await mcpClient(tok.bob);
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
  const client = await mcpClient(tok.carol);
  r = await tool(client, 'grant_label', { agent: 'opsbot', label: 'infra' });
  assert.equal(r.isError, false);
  assert.equal(r.data.changed, true);
  // ...and bob may not even take it away again (allowed_users is exclusive).
  const admin2 = await mcpClient(tok.bob);
  r = await tool(admin2, 'revoke_label', { agent: 'opsbot', label: 'infra' });
  assert.equal(r.isError, true);
  await admin2.close();
  r = await tool(client, 'revoke_label', { agent: 'opsbot', label: 'infra' });
  assert.equal(r.data.changed, true);
  await client.close();
});

test('MCP list_grantable_labels mirrors /api/me/labels', async () => {
  const client = await mcpClient(tok.alice);
  const { data } = await tool(client, 'list_grantable_labels');
  const http = await call('GET', '/api/me/labels', { cookie: cookie.alice });
  assert.deepEqual(data.map(l => l.name), http.json.map(l => l.name));
  assert.deepEqual(data, [{
    id: f.label('brummer'), name: 'brummer', server_count: 3, groups: ['brummer_team'],
    held_by_any_group: true, restricted_servers: [], can_grant: true
  }]);
  await client.close();
});

test('MCP search_servers: query, label, limit, reachability', async () => {
  const client = await mcpClient(tok.alice);
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
  const client = await mcpClient(tok.alice);
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
  const other = await mcpClient(tok.carol);
  assert.deepEqual((await tool(other, 'list_my_bots')).data, []);
  await other.close();
  await client.close();
});

test('MCP deploy_status: deployed / pending / never-deployed per agent and label', async () => {
  // opsbot holds brummer (from the grant test). Simulate the runner: br-amr1
  // got the current key set, br-amr2 an older one, br-amr3 was never reached.
  const servers = (await call('GET', '/api/servers', { cookie: cookie.bob })).json;
  const expected = Object.fromEntries(servers.map(s => [s.hostname, s.expected_keys_hash]));
  const report = (host, hash) => call('POST', `/api/servers/${host}/deployed`, {
    auth: `Bearer ${H.DEPLOY_API_TOKEN}`, body: { keys_hash: hash }
  });
  assert.equal((await report('br-amr1', expected['br-amr1'])).status, 200);
  assert.equal((await report('br-amr2', '0123456789abcdef')).status, 200);

  // A legacy grant on a restricted no-agents server (made before the
  // policy existed): excluded, never counted.
  const agentId = db.prepare("SELECT id FROM team_agents WHERE name = 'opsbot'").get().id;
  db.prepare('INSERT INTO agent_labels (agent_id, label_id) VALUES (?, ?)').run(agentId, f.label('legacy'));

  const client = await mcpClient(tok.alice);
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
