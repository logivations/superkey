// Unprivileged servers (restricted-servers.json `unprivileged_servers`):
// /api/deploy-data marks the server, gives humans forced-command keys and
// drops every privileged extra group from bots and team agents, while
// ordinary servers deploy exactly as before.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const H = require('./helpers');

const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl';
const FORCED = 'restrict,pty,command="sudo -n /usr/local/sbin/nemo-enter"';

let db, base, httpServer;

before(async () => {
  const port = await H.freePort();
  H.setupEnv(port);
  db = require('../src/database');
  const { app } = require('../src/server');
  const f = H.fixtures(db);
  const alice = f.user('alice', 'alice.smith@example.com', 'Alice');
  db.prepare('UPDATE users SET public_key = ? WHERE id = ?').run(KEY, alice);
  f.member(alice, 'staff');
  f.grantGroup('everyone', 'staff');
  f.server('nemo', ['everyone']);
  f.server('plain', ['everyone']);
  db.prepare('INSERT INTO bot_keys (user_id, name, public_key, source_cidr, docker) VALUES (?, ?, ?, ?, 1)')
    .run(alice, 'helper', KEY, '10.1.2.3/32');
  const agent = db.prepare('INSERT INTO team_agents (name, public_key) VALUES (?, ?)').run('ops', KEY).lastInsertRowid;
  db.prepare('INSERT INTO agent_labels (agent_id, label_id) VALUES (?, ?)').run(agent, f.label('everyone'));
  ({ server: httpServer, base } = await H.listen(app, port));
});
after(() => httpServer.close());

async function deployData() {
  const r = await H.req(base, 'GET', '/api/deploy-data', { auth: `Bearer ${H.DEPLOY_API_TOKEN}` });
  assert.equal(r.status, 200);
  return Object.fromEntries(r.json.servers.map(s => [s.hostname, s]));
}

test('unprivileged server: forced-command keys, no privileged groups', async () => {
  const { nemo } = await deployData();
  assert.equal(nemo.unprivileged, true);
  const [user] = nemo.users;
  assert.equal(user.key_options, FORCED);
  assert.deepEqual(user.bots.map(b => [b.key_options, b.extra_groups]), [
    ['restrict,pty,from="10.1.2.3/32",command="sudo -n /usr/local/sbin/nemo-enter"', '']
  ]);
  assert.deepEqual(nemo.agents.map(a => [a.account, a.key_options, a.extra_groups]), [
    ['agent_ops', FORCED, '']
  ]);
});

test('ordinary server deploys as before', async () => {
  const { plain } = await deployData();
  assert.equal(plain.unprivileged, false);
  const [user] = plain.users;
  assert.equal(user.key_options, '');
  assert.deepEqual(user.bots.map(b => [b.key_options, b.extra_groups]), [
    ['restrict,pty,from="10.1.2.3/32"', 'docker superkey_agents']
  ]);
  assert.deepEqual(plain.agents.map(a => [a.key_options, a.extra_groups]), [
    ['restrict,pty', 'docker superkey_agents']
  ]);
});

test('becoming unprivileged changes the keys hash (deploy runner redeploys)', async () => {
  const { nemo, plain } = await deployData();
  assert.notEqual(nemo.expected_keys_hash, plain.expected_keys_hash);
});

test('a forced_command that could break out of command="..." refuses to load', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'superkey-policy-'));
  const load = cmd => {
    const p = path.join(dir, `${Math.random()}.json`);
    fs.writeFileSync(p, JSON.stringify({ unprivileged_servers: [{ match: 'x', forced_command: cmd }] }));
    return spawnSync(process.execPath, ['-e', "require('./src/restricted')"], {
      cwd: path.join(__dirname, '..'), env: { ...process.env, RESTRICTED_SERVERS_PATH: p }, encoding: 'utf8'
    });
  };
  assert.equal(load('sudo -n /usr/local/sbin/nemo-enter').status, 0);
  for (const bad of ['x" ,no-pty', 'a\nb', 'echo $(id)', '']) {
    const r = load(bad);
    assert.notEqual(r.status, 0, bad);
    assert.match(r.stderr, /unprivileged_servers/);
  }
});
