// OAuth 2.1 authorization server for Superkey's own MCP endpoint (/mcp),
// following the MCP authorization spec (2025-11-25) with the
// @modelcontextprotocol/sdk server helpers:
//
//   /.well-known/oauth-protected-resource[/mcp]  RFC 9728, points at us
//   /.well-known/oauth-authorization-server      RFC 8414
//   /register                                    RFC 7591 dynamic client registration
//   /authorize                                   code + PKCE S256 only
//   /token                                       code exchange, refresh rotation
//   /revoke                                      RFC 7009
//
// Login is delegated to the existing Google SSO session: /authorize sends a
// signed-out user through /auth/google and back, then shows a consent page.
// Consent is required every time — dynamic registration means anyone can
// register a client with any name, so the user must see where the code
// goes (the redirect host) and approve it.
//
// Tokens are opaque random strings, stored only as sha256. Access tokens
// live 1 h and are bound (RFC 8707) to the /mcp resource; refresh tokens
// rotate on every use with a 30-day sliding expiry, and replaying an
// already-rotated refresh token revokes the whole grant. The user row is
// re-read on every request: a user removed by the Google sync loses access
// immediately.
//
// OAuth tokens are accepted ONLY at /mcp. /api/* stays session (or the
// AGENT/DEPLOY machine tokens) exactly as before; see rejectOAuthOutsideMcp.

const crypto = require('crypto');
const express = require('express');
const { mcpAuthRouter, createOAuthMetadata, getOAuthProtectedResourceMetadataUrl } =
  require('@modelcontextprotocol/sdk/server/auth/router.js');
const { requireBearerAuth } = require('@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js');
const {
  InvalidClientMetadataError, InvalidGrantError, InvalidTargetError, InvalidTokenError, InvalidRequestError
} = require('@modelcontextprotocol/sdk/server/auth/errors.js');
const db = require('./database');

const ACCESS_TOKEN_TTL_S = 60 * 60;
const REFRESH_TOKEN_TTL_S = 30 * 24 * 60 * 60;
const AUTH_CODE_TTL_S = 5 * 60;
const AUTH_REQUEST_TTL_S = 10 * 60;
// Unused registrations (no grant) are dropped after this long.
const STALE_CLIENT_S = 7 * 24 * 60 * 60;

// Token prefixes: recognizable in logs and kept apart from the plain-hex
// machine tokens, so a request carrying one can be routed without a lookup.
const ACCESS_PREFIX = 'sk_oat_';
const REFRESH_PREFIX = 'sk_ort_';
const OAUTH_TOKEN_RE = /^sk_o(at|rt)_/;

const now = () => Math.floor(Date.now() / 1000);
const hash = v => crypto.createHash('sha256').update(String(v)).digest('hex');
const random = (prefix = '') => prefix + crypto.randomBytes(32).toString('base64url');

// ---- public URLs ------------------------------------------------------------

// The externally visible base URL. Issuer, resource and metadata URLs are
// built from it, never from request headers. PUBLIC_URL wins; otherwise
// the origin of the Google callback URL (configured for prod anyway);
// otherwise localhost for development.
function publicBaseUrl() {
  if (process.env.PUBLIC_URL) return new URL(new URL(process.env.PUBLIC_URL).origin + '/');
  const cb = process.env.GOOGLE_CALLBACK_URL;
  if (cb && /^https?:\/\//.test(cb)) return new URL(new URL(cb).origin + '/');
  return new URL(`http://localhost:${process.env.PORT || 3000}/`);
}

// ---- request helpers --------------------------------------------------------

function bearerOf(req) {
  const m = /^bearer\s+(\S+)\s*$/i.exec(req.headers.authorization || '');
  return m ? m[1] : '';
}

// A request presenting one of our OAuth tokens. These never touch the
// session (server.js skips the session middleware for them), so a cookie
// sent along cannot stand in for, or add to, the token.
function isOAuthBearer(req) {
  return OAUTH_TOKEN_RE.test(bearerOf(req));
}

// OAuth tokens are for /mcp only. On /api/* answer 401 explicitly rather
// than relying on the (skipped) session to fail. Express routes paths
// case-insensitively, so compare the same way.
function rejectOAuthOutsideMcp(req, res, next) {
  if (isOAuthBearer(req) && req.path.toLowerCase().startsWith('/api/')) {
    return res.status(401).json({
      error: 'OAuth access tokens are only accepted at /mcp. The Superkey API needs a browser session.'
    });
  }
  next();
}

// ---- clients (RFC 7591) -----------------------------------------------------

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

// Redirect URIs a client may register: loopback http (any port — native
// apps like Claude Code pick one per login) or https. No fragments, no
// credentials, no custom schemes.
function validRedirectUri(uri) {
  let u;
  try { u = new URL(uri); } catch (e) { return false; }
  if (u.hash || u.username || u.password) return false;
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && LOOPBACK.has(u.hostname);
}

function cleanClientName(name) {
  const n = typeof name === 'string' ? name.replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, 100) : '';
  return n || 'Unnamed client';
}

const clientsStore = {
  getClient(clientId) {
    const row = db.prepare('SELECT metadata FROM oauth_clients WHERE client_id = ?').get(String(clientId));
    return row ? JSON.parse(row.metadata) : undefined;
  },

  // Every client is public (token_endpoint_auth_method "none"): a secret
  // handed to a self-registered native app protects nothing — PKCE, the
  // exact redirect URI and the consent page do. So no secrets are stored.
  registerClient(client) {
    const uris = client.redirect_uris || [];
    if (uris.length === 0 || uris.length > 10 || !uris.every(validRedirectUri)) {
      throw new InvalidClientMetadataError(
        'redirect_uris must be 1-10 URLs, each https:// or http://localhost / 127.0.0.1 / [::1] (any port)');
    }
    const grants = client.grant_types || ['authorization_code', 'refresh_token'];
    if (!grants.every(g => g === 'authorization_code' || g === 'refresh_token')) {
      throw new InvalidClientMetadataError('Only the authorization_code and refresh_token grant types are supported');
    }
    if (client.response_types && !client.response_types.every(t => t === 'code')) {
      throw new InvalidClientMetadataError('Only the "code" response type is supported');
    }
    const full = {
      client_id: client.client_id,
      client_id_issued_at: client.client_id_issued_at,
      client_name: cleanClientName(client.client_name),
      redirect_uris: uris,
      grant_types: grants,
      response_types: ['code'],
      token_endpoint_auth_method: 'none'
    };
    if (client.client_uri) full.client_uri = client.client_uri;
    db.prepare('INSERT INTO oauth_clients (client_id, client_name, metadata) VALUES (?, ?, ?)')
      .run(full.client_id, full.client_name, JSON.stringify(full));
    return full;
  }
};

// ---- storage helpers --------------------------------------------------------

function cleanup() {
  const t = now();
  db.prepare('DELETE FROM oauth_requests WHERE expires_at < ?').run(t);
  db.prepare('DELETE FROM oauth_codes WHERE expires_at < ?').run(t - 3600);
  db.prepare('DELETE FROM oauth_tokens WHERE expires_at < ?').run(t);
  db.prepare(`
    DELETE FROM oauth_clients
    WHERE created_at < datetime('now', ?)
      AND NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_id = oauth_clients.client_id)
  `).run(`-${STALE_CLIENT_S} seconds`);
}

function revokeGrant(grantId, reason) {
  db.prepare(`
    UPDATE oauth_grants SET revoked_at = datetime('now'), revoked_reason = ?
    WHERE id = ? AND revoked_at IS NULL
  `).run(reason, grantId);
  db.prepare('DELETE FROM oauth_tokens WHERE grant_id = ?').run(grantId);
}

// Issue an access + refresh token pair for a grant.
function issueTokens(grantId) {
  const access = random(ACCESS_PREFIX);
  const refresh = random(REFRESH_PREFIX);
  const t = now();
  const insert = db.prepare('INSERT INTO oauth_tokens (token_hash, grant_id, kind, expires_at) VALUES (?, ?, ?, ?)');
  insert.run(hash(access), grantId, 'access', t + ACCESS_TOKEN_TTL_S);
  insert.run(hash(refresh), grantId, 'refresh', t + REFRESH_TOKEN_TTL_S);
  return { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TOKEN_TTL_S, refresh_token: refresh };
}

function userExists(userId) {
  return !!db.prepare('SELECT 1 FROM users WHERE id = ?').get(userId);
}

// ---- the provider -----------------------------------------------------------

function createProvider(resourceUrl) {
  const resource = resourceUrl.href;
  const sameResource = r => !r || String(r).replace(/\/$/, '') === resource.replace(/\/$/, '');

  return {
    clientsStore,

    // Called by the SDK after it validated client_id, redirect_uri (exact,
    // loopback port relaxed), response_type=code and PKCE S256. Park the
    // request and hand the browser to the consent page (via Google login
    // when there is no session).
    async authorize(client, params, res) {
      if (!sameResource(params.resource)) {
        throw new InvalidTargetError(`This authorization server only issues tokens for ${resource}`);
      }
      cleanup();
      const id = random();
      db.prepare(`
        INSERT INTO oauth_requests (id, client_id, redirect_uri, code_challenge, state, scopes, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).run(id, client.client_id, params.redirectUri, params.codeChallenge, params.state ?? null,
        (params.scopes || []).join(' '), now() + AUTH_REQUEST_TTL_S);
      const consent = `/oauth/consent?request=${encodeURIComponent(id)}`;
      const req = res.req;
      if (!req.session) throw new InvalidRequestError('Open this URL in a browser');
      if (req.isAuthenticated && req.isAuthenticated()) return res.redirect(consent);
      req.session.returnTo = consent;
      req.session.save(() => res.redirect('/auth/google'));
    },

    async challengeForAuthorizationCode(client, code) {
      const row = db.prepare('SELECT * FROM oauth_codes WHERE code_hash = ?').get(hash(code));
      if (!row || row.client_id !== client.client_id || row.expires_at < now()) {
        throw new InvalidGrantError('Invalid or expired authorization code');
      }
      return row.code_challenge;
    },

    async exchangeAuthorizationCode(client, code, _verifier, redirectUri, reqResource) {
      const row = db.prepare('SELECT * FROM oauth_codes WHERE code_hash = ?').get(hash(code));
      if (!row || row.client_id !== client.client_id || row.expires_at < now()) {
        throw new InvalidGrantError('Invalid or expired authorization code');
      }
      if (row.used) {
        // A replayed code means it leaked: kill what it produced (RFC 6749 4.1.2).
        if (row.grant_id) revokeGrant(row.grant_id, 'authorization code reuse');
        throw new InvalidGrantError('Authorization code already used');
      }
      if (redirectUri !== undefined && redirectUri !== row.redirect_uri) {
        throw new InvalidGrantError('redirect_uri does not match the authorization request');
      }
      if (!sameResource(reqResource)) throw new InvalidTargetError(`Tokens are only issued for ${resource}`);
      if (!userExists(row.user_id)) throw new InvalidGrantError('User no longer exists');

      return db.transaction(() => {
        const grantId = db.prepare(`
          INSERT INTO oauth_grants (user_id, client_id, resource, scopes, redirect_uri) VALUES (?, ?, ?, ?, ?)
        `).run(row.user_id, client.client_id, resource, row.scopes || '', row.redirect_uri).lastInsertRowid;
        db.prepare('UPDATE oauth_codes SET used = 1, grant_id = ? WHERE code_hash = ?').run(grantId, row.code_hash);
        return issueTokens(grantId);
      })();
    },

    async exchangeRefreshToken(client, refreshToken, _scopes, reqResource) {
      const row = db.prepare(`
        SELECT t.*, g.client_id, g.user_id, g.revoked_at FROM oauth_tokens t
        JOIN oauth_grants g ON g.id = t.grant_id
        WHERE t.token_hash = ? AND t.kind = 'refresh'
      `).get(hash(refreshToken));
      if (!row || row.revoked_at || row.client_id !== client.client_id || row.expires_at < now()) {
        throw new InvalidGrantError('Invalid or expired refresh token');
      }
      if (row.rotated_at) {
        // Rotated tokens are never valid again; seeing one means two
        // parties hold the grant's tokens. Revoke it for everyone.
        revokeGrant(row.grant_id, 'refresh token reuse');
        throw new InvalidGrantError('Refresh token already used; the grant has been revoked');
      }
      if (!sameResource(reqResource)) throw new InvalidTargetError(`Tokens are only issued for ${resource}`);
      if (!userExists(row.user_id)) {
        revokeGrant(row.grant_id, 'user removed');
        throw new InvalidGrantError('User no longer exists');
      }
      return db.transaction(() => {
        db.prepare("UPDATE oauth_tokens SET rotated_at = datetime('now') WHERE token_hash = ?").run(row.token_hash);
        // The rotated token row is kept until its old expiry so reuse is detectable.
        return issueTokens(row.grant_id);
      })();
    },

    async verifyAccessToken(token) {
      const row = db.prepare(`
        SELECT t.expires_at, t.grant_id, g.user_id, g.client_id, g.resource, g.scopes, g.revoked_at
        FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
        WHERE t.token_hash = ? AND t.kind = 'access'
      `).get(hash(token));
      if (!row || row.revoked_at || row.expires_at < now()) throw new InvalidTokenError('Invalid or expired access token');
      // Same lookup a session does: a user deleted by the Google sync is out.
      if (!userExists(row.user_id)) throw new InvalidTokenError('User no longer exists');
      db.prepare(`
        UPDATE oauth_grants SET last_used_at = datetime('now')
        WHERE id = ? AND (last_used_at IS NULL OR last_used_at < datetime('now', '-60 seconds'))
      `).run(row.grant_id);
      return {
        token,
        clientId: row.client_id,
        scopes: row.scopes ? row.scopes.split(' ') : [],
        expiresAt: row.expires_at,
        resource: new URL(row.resource),
        extra: { userId: row.user_id, grantId: row.grant_id }
      };
    },

    // RFC 7009: revoking either token of a grant ends the grant.
    async revokeToken(client, request) {
      const row = db.prepare(`
        SELECT t.grant_id, g.client_id FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
        WHERE t.token_hash = ?
      `).get(hash(request.token));
      if (row && row.client_id === client.client_id) revokeGrant(row.grant_id, 'revoked by client');
    }
  };
}

// ---- consent page ------------------------------------------------------------

const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g,
  c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// Where the code goes, in words a user can judge.
function describeRedirect(uri) {
  const u = new URL(uri);
  if (u.protocol === 'http:') return { host: u.host, local: true };
  return { host: u.host, local: false };
}

function page(title, body) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} — Superkey</title>
<style>
  :root { --paper:#F2F3EF; --panel:#FFFFFF; --ink:#16202A; --ink-2:#5A6670; --rule:#C7CEC7;
    --blueprint:#0B5E8A; --revision:#B4331F;
    --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, "Liberation Mono", monospace;
    --sans: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", sans-serif; }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--paper); color: var(--ink); font-family: var(--sans); font-size: 14px;
    line-height: 1.45; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px;
    background-image: linear-gradient(to right, rgba(11,94,138,.045) 1px, transparent 1px),
      linear-gradient(to bottom, rgba(11,94,138,.045) 1px, transparent 1px); background-size: 32px 32px; }
  .box { background: var(--panel); border: 2px solid var(--ink); width: 560px; max-width: 100%; }
  .head { background: var(--ink); color: var(--paper); padding: 12px 18px; font-family: var(--mono);
    font-size: 12px; letter-spacing: .16em; text-transform: uppercase; font-weight: 700; }
  .body { padding: 20px 22px; }
  h1 { font-family: var(--mono); font-size: 15px; margin: 0 0 14px; letter-spacing: .04em; }
  .k { font-family: var(--mono); font-size: 10.5px; letter-spacing: .1em; text-transform: uppercase;
    color: var(--ink-2); font-weight: 600; margin: 14px 0 4px; }
  .v { font-family: var(--mono); font-size: 13px; word-break: break-all; }
  ul { margin: 6px 0 0; padding-left: 18px; } li { margin: 3px 0; }
  .warn { border: 1px solid var(--revision); border-left: 3px solid var(--revision); padding: 10px 12px;
    font-size: 12.5px; margin-top: 16px; }
  .actions { display: flex; gap: 10px; margin-top: 20px; }
  .btn { appearance: none; cursor: pointer; font-family: var(--mono); font-size: 11px; letter-spacing: .1em;
    text-transform: uppercase; font-weight: 600; padding: 9px 16px; border: 1px solid var(--blueprint);
    background: var(--panel); color: var(--blueprint); }
  .btn.solid { background: var(--blueprint); color: #fff; }
  .btn:hover { background: var(--ink); border-color: var(--ink); color: #fff; }
  .muted { color: var(--ink-2); font-size: 12.5px; }
</style>
</head>
<body><div class="box"><div class="head">Superkey</div><div class="body">${body}</div></div></body>
</html>`;
}

function consentPage({ client, redirect, email, request, csrf }) {
  const where = redirect.local
    ? `an app on <b>this computer</b> (<span class="v">${esc(redirect.host)}</span>)`
    : `<b class="v">${esc(redirect.host)}</b>`;
  return page('Authorize access', `
    <h1>Allow “${esc(client.client_name)}” to use Superkey as you?</h1>
    <div class="k">Signed in as</div><div class="v">${esc(email)}</div>
    <div class="k">The authorization goes to</div><div>${where}</div>
    <div class="k">It will be able to</div>
    <ul>
      <li>read servers, labels, team agents, your personal agents and deploy state</li>
      <li>grant and revoke team-agent labels — only labels you hold yourself, on agents you may manage</li>
    </ul>
    <p class="muted">It acts as <b>${esc(email)}</b> through Superkey's MCP endpoint only — it cannot change your
      SSH key, your agents or any admin settings. You can disconnect it any time under <b>Connected apps</b>.</p>
    ${redirect.local ? '' : `<div class="warn">The name “${esc(client.client_name)}” is chosen by the app itself.
      Only approve if you started this from an app you trust at ${esc(redirect.host)}.</div>`}
    <form method="post" action="/oauth/consent" class="actions">
      <input type="hidden" name="request" value="${esc(request)}">
      <input type="hidden" name="csrf" value="${esc(csrf)}">
      <button class="btn solid" name="decision" value="approve" type="submit">Approve</button>
      <button class="btn" name="decision" value="deny" type="submit">Deny</button>
    </form>`);
}

function errorPage(res, status, message) {
  res.status(status).type('html').send(page('Authorization failed', `
    <h1>Authorization failed</h1><p>${esc(message)}</p>
    <p class="muted">Start the connection again from your app (for Claude Code: <code>/mcp</code> → Authenticate).</p>`));
}

function redirectWith(res, redirectUri, params) {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) u.searchParams.set(k, v);
  res.redirect(302, u.href);
}

function loadRequest(id) {
  const row = db.prepare('SELECT * FROM oauth_requests WHERE id = ? AND expires_at >= ?').get(String(id || ''), now());
  if (!row) return null;
  const client = clientsStore.getClient(row.client_id);
  return client ? { row, client } : null;
}

// ---- grants of a user (Connected apps) ------------------------------------------

function listGrants(userId) {
  return db.prepare(`
    SELECT g.id, g.client_id, g.redirect_uri, g.created_at, g.last_used_at, c.client_name
    FROM oauth_grants g LEFT JOIN oauth_clients c ON c.client_id = g.client_id
    WHERE g.user_id = ? AND g.revoked_at IS NULL
    ORDER BY g.created_at DESC, g.id DESC
  `).all(userId).map(g => ({
    id: g.id,
    client_name: g.client_name || 'Unknown client',
    redirect_host: (() => { try { return new URL(g.redirect_uri).host; } catch (e) { return null; } })(),
    created_at: g.created_at,
    last_used_at: g.last_used_at
  }));
}

function revokeUserGrant(userId, grantId) {
  const g = db.prepare('SELECT id FROM oauth_grants WHERE id = ? AND user_id = ? AND revoked_at IS NULL').get(grantId, userId);
  if (!g) return false;
  revokeGrant(g.id, 'revoked by user');
  return true;
}

// ---- wiring --------------------------------------------------------------------

// Mount the authorization server on the app (after the session middleware:
// /authorize and the consent page need the Google session). Returns the
// middleware that protects /mcp, or null when the configured base URL is
// unusable as an issuer (then /mcp is unavailable, the rest of Superkey
// runs normally).
function mount(app, { isAuthenticated }) {
  const base = publicBaseUrl();
  const resourceUrl = new URL('/mcp', base);
  const provider = createProvider(resourceUrl);
  let router;
  try {
    router = mcpAuthRouter({
      provider,
      issuerUrl: base,
      resourceServerUrl: resourceUrl,
      resourceName: 'Superkey',
    });
  } catch (err) {
    console.error(`MCP OAuth disabled: ${err.message} (set PUBLIC_URL to the https URL of this Superkey)`);
    return null;
  }
  app.use(router);

  // RFC 9728 also allows clients to probe the root variant; serve the same
  // document there as at /.well-known/oauth-protected-resource/mcp.
  const metadataUrl = getOAuthProtectedResourceMetadataUrl(resourceUrl);
  const asMetadata = createOAuthMetadata({ provider, issuerUrl: base });
  app.get('/.well-known/oauth-protected-resource', (req, res) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.json({
      resource: resourceUrl.href,
      authorization_servers: [asMetadata.issuer],
      resource_name: 'Superkey'
    });
  });

  app.get('/oauth/consent', (req, res) => {
    res.set('Cache-Control', 'no-store');
    res.set('X-Frame-Options', 'DENY');
    res.set('Content-Security-Policy', "frame-ancestors 'none'");
    const found = loadRequest(req.query.request);
    if (!found) return errorPage(res, 400, 'This authorization request is unknown or has expired.');
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      req.session.returnTo = `/oauth/consent?request=${encodeURIComponent(found.row.id)}`;
      return req.session.save(() => res.redirect('/auth/google'));
    }
    // The CSRF token lives in THIS browser's session: whoever started the
    // authorization (possibly an attacker who knows the request id) cannot
    // make someone else's browser approve it.
    const csrf = random();
    req.session.oauthConsent = { request: found.row.id, csrf };
    req.session.save(() => res.type('html').send(consentPage({
      client: found.client,
      redirect: describeRedirect(found.row.redirect_uri),
      email: req.user.email,
      request: found.row.id,
      csrf
    })));
  });

  app.post('/oauth/consent', express.urlencoded({ extended: false }), (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!req.isAuthenticated || !req.isAuthenticated()) return errorPage(res, 401, 'You are not signed in.');
    const { request, csrf, decision } = req.body || {};
    const expected = req.session.oauthConsent;
    const ok = expected && expected.request === request && typeof csrf === 'string'
      && csrf.length === expected.csrf.length
      && crypto.timingSafeEqual(Buffer.from(csrf), Buffer.from(expected.csrf));
    if (!ok) return errorPage(res, 403, 'This approval did not come from the consent page shown to you.');
    const found = loadRequest(request);
    delete req.session.oauthConsent;
    if (!found) return errorPage(res, 400, 'This authorization request is unknown or has expired.');
    // Single use, whatever the decision.
    db.prepare('DELETE FROM oauth_requests WHERE id = ?').run(found.row.id);
    const { row } = found;
    const iss = asMetadata.issuer;

    if (decision !== 'approve') {
      return redirectWith(res, row.redirect_uri, {
        error: 'access_denied', error_description: 'The user denied access', state: row.state, iss
      });
    }
    const code = random();
    db.prepare(`
      INSERT INTO oauth_codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scopes, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(hash(code), row.client_id, req.user.id, row.redirect_uri, row.code_challenge, row.scopes,
      now() + AUTH_CODE_TTL_S);
    redirectWith(res, row.redirect_uri, { code, state: row.state, iss });
  });

  // Connected apps (session only, like every /api route).
  app.get('/api/me/oauth-grants', isAuthenticated, (req, res) => res.json(listGrants(req.user.id)));
  app.delete('/api/me/oauth-grants/:id', isAuthenticated, (req, res) => {
    if (!revokeUserGrant(req.user.id, req.params.id)) return res.status(404).json({ error: 'Connected app not found' });
    res.json({ success: true });
  });

  const bearer = requireBearerAuth({ verifier: provider, resourceMetadataUrl: metadataUrl, expectedResource: resourceUrl });
  const help = `Superkey MCP uses OAuth: run "claude mcp add --transport http superkey ${resourceUrl.href}", ` +
    'then /mcp in Claude Code → superkey → Authenticate.';
  // /mcp guard: no token → 401 pointing at the metadata (that is what
  // starts an MCP client's OAuth flow) and at the human instructions.
  return function requireMcpAuth(req, res, next) {
    if (!req.headers.authorization) {
      res.set('WWW-Authenticate', `Bearer resource_metadata="${metadataUrl}"`);
      return res.status(401).json({ error: 'invalid_token', error_description: help });
    }
    bearer(req, res, next);
  };
}

module.exports = {
  mount,
  isOAuthBearer,
  rejectOAuthOutsideMcp,
  publicBaseUrl,
  ACCESS_TOKEN_TTL_S,
  REFRESH_TOKEN_TTL_S,
  _test: { validRedirectUri }
};
