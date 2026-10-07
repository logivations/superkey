// Team-agent maintainers: registration API contract and the grant/revoke
// rule (admin OR (holds the label AND (no maintainers OR is a maintainer))),
// through both the HTTP routes and the MCP tools (same shared function).

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const H = require('./helpers');

const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';

let db, f, base, httpServer, Client, StreamableHTTPClientTransport;
const cookie = {};
const tok = {};

before(async () => {
  const port = await H.freePort();
  H.setupEnv(port);
  db = require('../src/database');
  const { app } = require('../src/server');
  ({ Client } = require('@modelcontextprotocol/sdk/client/index.js'));
  ({ StreamableHTTPClientTransport } = require('@modelcontextprotocol/sdk/client/streamableHttp.js'));
  f = H.fixtures(db);
  // owner + mate maintain "shared"; outsider holds the same label but is not
  // a maintainer; admin is a superkey admin holding nothing via groups.
  const users = {
    owner: f.user('owner', 'Owner@Example.com', 'Owner'),
    mate: f.user('mate', 'mate@example.com', 'Mate'),
    outsider: f.user('outsider', 'outsider@example.com', 'Outsider'),
    admin: f.user('admin', 'admin@example.com', 'Admin')
  };
  for (const k of ['owner', 'mate', 'outsider']) f.member(users[k], 'brummer_team');
  f.member(users.admin, 'superkey_admins');
  f.grantGroup('brummer', 'brummer_team');
  f.label('kaufland');
  f.server('br-amr1', ['brummer']);
  f.server('kl-1', ['kaufland']);
  ({ server: httpServer, base } = await H.listen(app, port));
  const client = await H.registerClient(base);
  for (const [k, id] of Object.entries(users)) {
    cookie[k] = H.sessionCookie(db, id);
    tok[k] = (await H.oauthLogin(base, cookie[k], { client })).tokens.access_token;
  }
});
after(() => httpServer.close());

const register = body => H.req(base, 'POST', '/api/agents/register', {
  auth: `Bearer ${H.AGENT_API_TOKEN}`, json: { publicKey: KEY, ...body }
});
const agentId = name => db.prepare('SELECT id FROM team_agents WHERE name = ?').get(name).id;
const labelId = name => f.label(name);
const grant = (who, agent, label) => H.req(base, 'POST', `/api/agents/${agentId(agent)}/labels/${labelId(label)}`, { cookie: cookie[who] });
const revoke = (who, agent, label) => H.req(base, 'DELETE', `/api/agents/${agentId(agent)}/labels/${labelId(label)}`, { cookie: cookie[who] });
const agents = async who => (await H.req(base, 'GET', '/api/agents', { cookie: cookie[who] })).json;

async function mcpTool(who, name, args) {
  const client = new Client({ name: 't', version: '0' });
  await client.connect(new StreamableHTTPClientTransport(new URL(base + '/mcp'), {
    requestInit: { headers: { Authorization: `Bearer ${tok[who]}` } }
  }));
  const r = await client.callTool({ name, arguments: args });
  await client.close();
  return { isError: !!r.isError, data: JSON.parse(r.content[0].text) };
}

test('register: maintainers are lowercased, deduplicated, validated, and returned', async () => {
  const r = await register({ name: 'shared', maintainers: ['owner@example.com', 'MATE@example.com', 'mate@example.com'] });
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.maintainers, ['mate@example.com', 'owner@example.com']);
  for (const bad of ['not-an-email', 'a@b', 42, 'x@example.com, y@example.com']) {
    const b = await register({ name: 'shared', maintainers: [bad] });
    assert.equal(b.status, 400, String(bad));
  }
  assert.equal((await register({ name: 'shared', maintainers: 'owner@example.com' })).status, 400);
  // Nothing changed by the rejected calls.
  assert.deepEqual((await agents('owner')).find(a => a.name === 'shared').maintainers, ['mate@example.com', 'owner@example.com']);
});

test('register without maintainers leaves the stored list; a new list replaces it', async () => {
  await register({ name: 'shared' });
  assert.deepEqual((await agents('owner')).find(a => a.name === 'shared').maintainers, ['mate@example.com', 'owner@example.com']);
  await register({ name: 'shared', maintainers: ['owner@example.com'] });
  assert.deepEqual((await agents('owner')).find(a => a.name === 'shared').maintainers, ['owner@example.com']);
  await register({ name: 'shared', maintainers: ['owner@example.com', 'mate@example.com'] });
});

test('a maintainer holding the label can grant and revoke', async () => {
  assert.equal((await grant('mate', 'shared', 'brummer')).status, 200);
  assert.equal((await revoke('owner', 'shared', 'brummer')).status, 200);
});

test('a non-maintainer holding the label cannot grant or revoke, with a clear message', async () => {
  const g = await grant('outsider', 'shared', 'brummer');
  assert.equal(g.status, 403);
  assert.match(g.json.error, /Only the maintainers of team agent "shared" \(mate@example\.com, owner@example\.com\) or a Superkey admin/);
  await grant('owner', 'shared', 'brummer');
  assert.equal((await revoke('outsider', 'shared', 'brummer')).status, 403);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM agent_labels WHERE agent_id = ?').get(agentId('shared')).n, 1);
});

test('a maintainer still needs to hold the label', async () => {
  const g = await grant('owner', 'shared', 'kaufland');
  assert.equal(g.status, 403);
  assert.match(g.json.error, /only grant labels you have access to/);
});

test('an admin can manage any agent, maintainer or not', async () => {
  assert.equal((await grant('admin', 'shared', 'kaufland')).status, 200);
  assert.equal((await revoke('admin', 'shared', 'kaufland')).status, 200);
});

test('legacy agent without maintainers: anyone holding the label (old behaviour)', async () => {
  await register({ name: 'legacy' });
  assert.deepEqual((await agents('outsider')).find(a => a.name === 'legacy').maintainers, []);
  assert.equal((await grant('outsider', 'legacy', 'brummer')).status, 200);
  assert.equal((await revoke('outsider', 'legacy', 'brummer')).status, 200);
  // An empty list clears maintainers back to that behaviour.
  await register({ name: 'cleared', maintainers: ['owner@example.com'] });
  await register({ name: 'cleared', maintainers: [] });
  assert.equal((await grant('outsider', 'cleared', 'brummer')).status, 200);
});

test('GET /api/agents: maintainers and can_manage for the caller', async () => {
  const shared = who => agents(who).then(list => list.find(a => a.name === 'shared'));
  assert.equal((await shared('owner')).can_manage, true);
  assert.equal((await shared('outsider')).can_manage, false);
  assert.equal((await shared('admin')).can_manage, true);
  assert.equal((await agents('outsider')).find(a => a.name === 'legacy').can_manage, true);
});

test('MCP: grant_label/revoke_label apply the same rule; list_agents and deploy_status show maintainers', async () => {
  let r = await mcpTool('outsider', 'grant_label', { agent: 'shared', label: 'brummer' });
  assert.equal(r.isError, true);
  assert.match(r.data.error, /Only the maintainers of team agent "shared"/);
  r = await mcpTool('outsider', 'revoke_label', { agent: 'agent_shared', label: 'brummer' });
  assert.equal(r.isError, true);
  r = await mcpTool('mate', 'grant_label', { agent: 'shared', label: 'brummer' });
  assert.equal(r.isError, false);

  const listed = (await mcpTool('outsider', 'list_agents', { query: 'shared' })).data[0];
  assert.deepEqual(listed.maintainers, ['mate@example.com', 'owner@example.com']);
  assert.equal(listed.can_manage, false);
  const status = (await mcpTool('owner', 'deploy_status', { agent: 'shared' })).data;
  assert.deepEqual(status.maintainers, ['mate@example.com', 'owner@example.com']);
  assert.equal(status.can_manage, true, 'owner@example.com matches Owner@Example.com case-insensitively');
});

test('deregistering an agent drops its maintainers', async () => {
  const id = agentId('cleared');
  await register({ name: 'cleared', maintainers: ['owner@example.com'] });
  const del = await H.req(base, 'DELETE', '/api/agents/register/cleared', { auth: `Bearer ${H.AGENT_API_TOKEN}` });
  assert.equal(del.status, 200);
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM agent_maintainers WHERE agent_id = ?').get(id).n, 0);
});
