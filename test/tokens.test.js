// Personal access tokens: creation, storage, verification, revocation,
// expiry (src/tokens.js against a temp database).

const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const { setupEnv, fixtures } = require('./helpers');

setupEnv();
const db = require('../src/database');
const tokens = require('../src/tokens');

const f = fixtures(db);
const alice = f.user('alice', 'alice@example.com', 'Alice');
const bob = f.user('bob', 'bob@example.com', 'Bob');

test('create: sk_pat_ + 32 random bytes, shown once, only the sha256 stored', () => {
  const t = tokens.createToken(alice, 'laptop', 30);
  assert.match(t.token, /^sk_pat_[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(t.token.slice(7), 'base64url').length, 32);
  assert.equal(t.prefix, t.token.slice(0, 13));
  assert.equal(t.name, 'laptop');

  const row = db.prepare('SELECT * FROM api_tokens WHERE id = ?').get(t.id);
  assert.equal(row.token_hash, crypto.createHash('sha256').update(t.token).digest('hex'));
  assert.ok(!Object.values(row).includes(t.token), 'plaintext token must not be stored');

  const listed = tokens.listTokens(alice);
  assert.deepEqual(listed.map(x => x.id), [t.id]);
  assert.equal(listed[0].token, undefined);
  assert.equal(listed[0].token_hash, undefined);
  assert.equal(tokens.listTokens(bob).length, 0);
});

test('two tokens never collide', () => {
  const a = tokens.createToken(bob, 'a');
  const b = tokens.createToken(bob, 'b');
  assert.notEqual(a.token, b.token);
  tokens.revokeToken(bob, a.id);
  tokens.revokeToken(bob, b.id);
});

test('resolve: the owner\'s users row; unknown / malformed tokens resolve to nothing', () => {
  const t = tokens.createToken(alice, 'resolve');
  const r = tokens.resolveToken(t.token);
  assert.equal(r.user.id, alice);
  assert.equal(r.user.email, 'alice@example.com');
  assert.equal(r.token.id, t.id);

  assert.equal(tokens.resolveToken(t.token + 'x'), null);
  assert.equal(tokens.resolveToken('sk_pat_' + 'A'.repeat(43)), null);
  assert.equal(tokens.resolveToken(t.token.slice(7)), null, 'the prefix is required');
  assert.equal(tokens.resolveToken(''), null);
  assert.equal(tokens.resolveToken(undefined), null);
});

test('resolve bumps last_used_at', () => {
  const t = tokens.createToken(alice, 'usage');
  assert.equal(db.prepare('SELECT last_used_at FROM api_tokens WHERE id = ?').get(t.id).last_used_at, null);
  tokens.resolveToken(t.token);
  assert.ok(db.prepare('SELECT last_used_at FROM api_tokens WHERE id = ?').get(t.id).last_used_at);
});

test('revoke: only the owner, only once; a revoked token stops working', () => {
  const t = tokens.createToken(alice, 'revoke-me');
  assert.equal(tokens.revokeToken(bob, t.id), false, 'someone else cannot revoke it');
  assert.ok(tokens.resolveToken(t.token));
  assert.equal(tokens.revokeToken(alice, t.id), true);
  assert.equal(tokens.resolveToken(t.token), null);
  assert.equal(tokens.revokeToken(alice, t.id), false);
  assert.ok(!tokens.listTokens(alice).some(x => x.id === t.id), 'revoked tokens are not listed');
  // The row stays for the record.
  assert.equal(db.prepare('SELECT revoked FROM api_tokens WHERE id = ?').get(t.id).revoked, 1);
});

test('expiry: expiresInDays sets expires_at; an expired token stops working', () => {
  const t = tokens.createToken(alice, 'short', 1);
  const days = (new Date(t.expires_at.replace(' ', 'T') + 'Z') - Date.now()) / 86400000;
  assert.ok(days > 0.99 && days <= 1.01, `expires in ~1 day, got ${days}`);
  assert.ok(tokens.resolveToken(t.token));

  db.prepare("UPDATE api_tokens SET expires_at = datetime('now', '-1 minute') WHERE id = ?").run(t.id);
  assert.equal(tokens.resolveToken(t.token), null);
  assert.equal(tokens.listTokens(alice).find(x => x.id === t.id).expired, true);

  const forever = tokens.createToken(alice, 'forever');
  assert.equal(forever.expires_at, null);
  assert.equal(forever.expired, false);
});

test('validation: bad names and expiry values are rejected with 400', () => {
  for (const days of [0, -1, 1.5, 366, 'abc']) {
    assert.throws(() => tokens.createToken(alice, 'x', days), e => e.status === 400, `expiresInDays=${days}`);
  }
  for (const name of ['', '   ', 'x'.repeat(61), 'a\nb', 42, undefined]) {
    assert.throws(() => tokens.createToken(alice, name), e => e.status === 400, `name=${JSON.stringify(name)}`);
  }
});

test('a deleted user (e.g. removed by the Google sync) takes their tokens down', () => {
  const carol = f.user('carol', 'carol@example.com', 'Carol');
  const t = tokens.createToken(carol, 'gone');
  assert.ok(tokens.resolveToken(t.token));
  db.prepare('DELETE FROM users WHERE id = ?').run(carol);
  assert.equal(tokens.resolveToken(t.token), null);
});

test('per-user limit on active tokens', () => {
  const dave = f.user('dave', 'dave@example.com', 'Dave');
  for (let i = 0; i < tokens.MAX_TOKENS_PER_USER; i++) tokens.createToken(dave, `t${i}`);
  assert.throws(() => tokens.createToken(dave, 'one too many'), e => e.status === 400);
  tokens.revokeToken(dave, tokens.listTokens(dave)[0].id);
  assert.ok(tokens.createToken(dave, 'room again'));
});

test('isPatRequest: only sk_pat_ bearers on /api/* and /mcp', () => {
  const req = (p, auth) => ({ path: p, headers: auth ? { authorization: auth } : {} });
  assert.equal(tokens.isPatRequest(req('/api/me', 'Bearer sk_pat_abc')), true);
  assert.equal(tokens.isPatRequest(req('/mcp', 'Bearer sk_pat_abc')), true);
  assert.equal(tokens.isPatRequest(req('/api/me', 'Bearer ' + 'a'.repeat(64))), false, 'machine tokens are not PATs');
  assert.equal(tokens.isPatRequest(req('/api/me')), false);
  assert.equal(tokens.isPatRequest(req('/auth/google', 'Bearer sk_pat_abc')), false, 'login flow stays session-only');
});
