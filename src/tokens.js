// Personal access tokens (PATs).
//
// A PAT is a bearer token a signed-in user creates for scripts and for the
// MCP endpoint. It authenticates AS that user: req.user is the same users
// row a session would give, admin status and group membership are read
// from the database on every request exactly like for a session, and a user
// removed by the Google sync takes their tokens down with them. A PAT never
// grants anything of its own.
//
// Format: "sk_pat_" + 32 random bytes, base64url. The prefix keeps PATs
// apart from the machine tokens (AGENT_API_TOKEN, DEPLOY_API_TOKEN), which
// are plain hex. The token is shown once at creation; only its sha256 is
// stored, so a database leak does not leak usable tokens.

const crypto = require('crypto');
const db = require('./database');

const PAT_PREFIX = 'sk_pat_';
const DISPLAY_PREFIX_LEN = PAT_PREFIX.length + 6;
const MAX_TOKENS_PER_USER = 20;
const MAX_EXPIRY_DAYS = 365;

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function generateToken() {
  return PAT_PREFIX + crypto.randomBytes(32).toString('base64url');
}

// The bearer value of a request, or '' if it has none.
// The auth scheme is case-insensitive (RFC 7235), so "bearer sk_pat_..." is
// a PAT too and must not slip past patAuth to the session cookie.
function bearerOf(req) {
  const m = /^bearer\s+(.*)$/i.exec(req.headers.authorization || '');
  return m ? m[1].trim() : '';
}

// PAT auth only covers the API and the MCP endpoint. The /auth/* login flow
// stays purely session-based whatever headers a client sends.
// Express routing is case-insensitive and ignores a trailing slash, so
// match the same way: otherwise "/API/me/tokens" or "/mcp/" would reach the
// route with the session (cookie) instead of the token deciding identity.
function isPatRequest(req) {
  const p = req.path.toLowerCase().replace(/\/+$/, '');
  return (p.startsWith('/api/') || p === '/mcp')
    && bearerOf(req).startsWith(PAT_PREFIX);
}

// Token names are free text for the owner's benefit; keep them printable
// and short.
function sanitizeTokenName(name) {
  if (typeof name !== 'string') return null;
  const n = name.trim();
  return n.length >= 1 && n.length <= 60 && !/[\u0000-\u001f\u007f]/.test(n) ? n : null;
}

// Rows the owner sees: never the hash. `expired` is computed here so the UI
// and API don't have to compare SQLite timestamps.
function publicRow(t) {
  return {
    id: t.id,
    name: t.name,
    prefix: t.prefix,
    created_at: t.created_at,
    last_used_at: t.last_used_at,
    expires_at: t.expires_at,
    expired: !!t.expired
  };
}

const SELECT_PUBLIC = `
  SELECT id, name, prefix, created_at, last_used_at, expires_at,
         (expires_at IS NOT NULL AND expires_at <= datetime('now')) AS expired
  FROM api_tokens`;

function listTokens(userId) {
  return db.prepare(`${SELECT_PUBLIC} WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC, id DESC`)
    .all(userId).map(publicRow);
}

// Create a token for a user. expiresInDays: positive integer up to
// MAX_EXPIRY_DAYS, or null/undefined for a token that never expires.
// Returns the public row plus the plaintext token — the only time it exists.
function createToken(userId, name, expiresInDays) {
  const clean = sanitizeTokenName(name);
  if (!clean) throw httpError(400, 'Invalid token name (1-60 printable characters).');
  let days = null;
  if (expiresInDays !== undefined && expiresInDays !== null && expiresInDays !== '') {
    days = Number(expiresInDays);
    if (!Number.isInteger(days) || days < 1 || days > MAX_EXPIRY_DAYS) {
      throw httpError(400, `expiresInDays must be a whole number of days between 1 and ${MAX_EXPIRY_DAYS} (omit it for no expiry).`);
    }
  }
  const active = db.prepare(`
    SELECT COUNT(*) AS n FROM api_tokens
    WHERE user_id = ? AND revoked = 0 AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(userId).n;
  if (active >= MAX_TOKENS_PER_USER) {
    throw httpError(400, `Token limit reached (max ${MAX_TOKENS_PER_USER} active). Revoke one first.`);
  }

  const token = generateToken();
  const result = db.prepare(`
    INSERT INTO api_tokens (user_id, name, token_hash, prefix, expires_at)
    VALUES (?, ?, ?, ?, CASE WHEN ? IS NULL THEN NULL ELSE datetime('now', ?) END)
  `).run(userId, clean, hashToken(token), token.slice(0, DISPLAY_PREFIX_LEN), days, days && `+${days} days`);
  const row = db.prepare(`${SELECT_PUBLIC} WHERE id = ?`).get(result.lastInsertRowid);
  return { ...publicRow(row), token };
}

// Revoke one of the user's own tokens. False if there is no such (active)
// token of theirs.
function revokeToken(userId, tokenId) {
  const result = db.prepare('UPDATE api_tokens SET revoked = 1 WHERE id = ? AND user_id = ? AND revoked = 0')
    .run(tokenId, userId);
  return result.changes > 0;
}

// Resolve a plaintext token to { token, user }, or null when it is unknown,
// revoked, expired, or its owner no longer exists. Bumps last_used_at (at
// most once a minute, to keep a busy client from writing on every call).
function resolveToken(plain) {
  if (typeof plain !== 'string' || !plain.startsWith(PAT_PREFIX)) return null;
  const t = db.prepare(`
    SELECT * FROM api_tokens
    WHERE token_hash = ? AND revoked = 0
      AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).get(hashToken(plain));
  if (!t) return null;
  // The same lookup passport's deserializeUser does for a session.
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(t.user_id);
  if (!user) return null;
  db.prepare(`
    UPDATE api_tokens SET last_used_at = datetime('now')
    WHERE id = ? AND (last_used_at IS NULL OR last_used_at < datetime('now', '-60 seconds'))
  `).run(t.id);
  return { token: { id: t.id, name: t.name, prefix: t.prefix, expires_at: t.expires_at }, user };
}

// Express middleware: for requests carrying "Authorization: Bearer sk_pat_…"
// (on /api/* and /mcp) the token alone decides who the caller is. Such
// requests skip the session middleware entirely (see server.js), so a
// cookie riding along can neither add to nor replace the token's identity,
// and a bad token is a hard 401 — never a fallback to the cookie.
function patAuth(req, res, next) {
  if (!isPatRequest(req)) return next();
  const resolved = resolveToken(bearerOf(req));
  if (!resolved) {
    res.set('WWW-Authenticate', 'Bearer realm="superkey", error="invalid_token"');
    return res.status(401).json({
      error: 'Invalid, expired or revoked API token. Create a new one in Superkey under "API tokens".'
    });
  }
  req.user = resolved.user;
  req.pat = resolved.token;
  req.authMethod = 'pat';
  next();
}

module.exports = {
  PAT_PREFIX,
  MAX_TOKENS_PER_USER,
  MAX_EXPIRY_DAYS,
  hashToken,
  isPatRequest,
  listTokens,
  createToken,
  revokeToken,
  resolveToken,
  patAuth
};
