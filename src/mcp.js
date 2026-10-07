// MCP endpoint (/mcp): Superkey for LLM clients (Claude Code, nemo agents).
//
// Streamable HTTP, stateless: every POST gets a fresh McpServer bound to the
// caller, so there is no session state to leak between users. Auth is an
// OAuth access token issued by Superkey itself (src/oauth.js, which also
// verifies it and re-checks the user); every tool runs as the user who
// approved the connection, through the same functions the
// HTTP routes use, so the permission rules (users only grant labels they
// hold, restricted-servers.json, admin-only operations) cannot drift apart.
//
// Tool names and input schemas are a contract — other components (the
// nemo-team-agent skill) call them by name. Add, don't rename.

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const db = require('./database');
const restricted = require('./restricted');

const SEARCH_DEFAULT_LIMIT = 50;
const SEARCH_MAX_LIMIT = 500;

// What a client is told about deploy timing. The runner on the superkey host
// deploys stale servers every minute (superkey-deploy.timer).
const DEPLOY_NOTE = 'Superkey deploys out-of-date servers automatically every minute, so "pending" ' +
  'usually clears within 1-2 minutes. A server that stays pending is normally offline or ' +
  'unreachable (many robots are switched off most of the time) and is deployed when it comes back. ' +
  '"never-deployed" means Superkey has never reached the server.';

const INSTRUCTIONS = `Superkey manages SSH access to the Logivations / Pixel Robotics fleet.
Servers carry labels (by default the site/config they come from, e.g. "brummer", "kaufland").
People get access through Google groups wired to labels; TEAM agents (shared nemo agents,
Linux account agent_<name>) get access when a label is attached to them.
You act as the user who connected this app: you can only attach labels that user holds
(admins: any), and restricted servers (restricted-servers.json) may refuse agent access entirely.
Typical flow: list_agents -> list_grantable_labels -> grant_label -> deploy_status.
${DEPLOY_NOTE}`;

function httpError(status, message) {
  return Object.assign(new Error(message), { status });
}

function json(value) {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}

// Run a tool body, turning thrown errors (httpError from the shared logic,
// or anything unexpected) into an MCP tool error the model can read.
async function run(fn) {
  try {
    return json(await fn());
  } catch (err) {
    if (!err.status) console.error('MCP tool failed:', err);
    return { ...json({ error: err.message }), isError: true };
  }
}

// deployed: the server has exactly the key set Superkey would deploy now.
// pending: it was deployed before but is out of date. never-deployed: no
// successful deploy on record.
function deployState(server) {
  if (server.is_up_to_date) return 'deployed';
  return server.last_deployed_at ? 'pending' : 'never-deployed';
}

const STATE_ORDER = { pending: 0, 'never-deployed': 1, deployed: 2 };

function summarize(hosts) {
  const summary = { servers: hosts.length, deployed: 0, pending: 0, never_deployed: 0 };
  for (const h of hosts) {
    if (h.state === 'deployed') summary.deployed++;
    else if (h.state === 'pending') summary.pending++;
    else summary.never_deployed++;
  }
  return summary;
}

// Interesting hosts (not yet deployed) first, then by name.
function byStateThenName(a, b) {
  return STATE_ORDER[a.state] - STATE_ORDER[b.state]
    || a.hostname.localeCompare(b.hostname, undefined, { sensitivity: 'base' });
}

function labelServers(labelId) {
  return db.prepare(`
    SELECT s.* FROM servers s
    JOIN server_labels sl ON s.id = sl.server_id
    WHERE sl.label_id = ?
    ORDER BY s.hostname COLLATE NOCASE
  `).all(labelId);
}

// Look up a team agent by name, Linux account (agent_<name>) or id.
function resolveAgent(ref, agentAccount) {
  const s = String(ref ?? '').trim();
  if (!s) throw httpError(400, 'agent is required (name, account agent_<name>, or id).');
  const agents = db.prepare('SELECT id, name FROM team_agents').all();
  const hit = agents.find(a => a.name === s.toLowerCase())
    || agents.find(a => agentAccount(a.name) === s.toLowerCase())
    || (/^\d+$/.test(s) && agents.find(a => a.id === Number(s)));
  if (!hit) throw httpError(404, `No team agent "${s}". Use list_agents to see the registered agents.`);
  return hit;
}

// Look up a label by name (exact, then case-insensitive) or id.
function resolveLabel(ref) {
  const s = String(ref ?? '').trim();
  if (!s) throw httpError(400, 'label is required (label name or id).');
  const labels = db.prepare('SELECT id, name FROM labels').all();
  const ci = labels.filter(l => l.name.toLowerCase() === s.toLowerCase());
  const hit = labels.find(l => l.name === s)
    || (ci.length === 1 && ci[0])
    || (/^\d+$/.test(s) && labels.find(l => l.id === Number(s)));
  if (!hit) throw httpError(404, `No label "${s}". Use list_grantable_labels to see the labels you can grant.`);
  return hit;
}

const nameOrId = z.union([z.string(), z.number()]);

function buildServer(user, auth, core) {
  const server = new McpServer(
    { name: 'superkey', version: '1.0.0' },
    { instructions: INSTRUCTIONS }
  );
  const readOnly = { readOnlyHint: true, openWorldHint: false };

  server.registerTool('whoami', {
    title: 'Who am I',
    description: 'The Superkey user this connection acts as: email, Linux username on the servers, ' +
      'whether they are a Superkey admin, and their Google groups (which decide what they can reach and grant).',
    inputSchema: {},
    annotations: readOnly
  }, () => run(() => ({
    email: user.email,
    name: user.name,
    linux_username: core.emailToUsername(user.email),
    isAdmin: core.isAdminUser(user.id),
    groups: core.userGroupNames(user.id),
    connection: {
      client: (db.prepare('SELECT client_name FROM oauth_clients WHERE client_id = ?').get(auth.clientId) || {}).client_name || null,
      access_token_expires_at: new Date(auth.expiresAt * 1000).toISOString()
    }
  })));

  server.registerTool('search_servers', {
    title: 'Search servers',
    description: 'Search the servers Superkey manages (every signed-in user can see the whole fleet, as in the web UI). ' +
      'Filter by a free-text query (space-separated terms, all must match the hostname or description; the description ' +
      'holds the IP and the site config) and/or an exact label. Returns hostname, labels, whether the server is restricted, ' +
      'whether YOU can reach it, and its deploy state: "deployed" (its authorized_keys match what Superkey would deploy now), ' +
      '"pending" (out of date, the runner retries every minute — offline robots stay pending) or "never-deployed". ' +
      'Superkey has no live online check; a long-pending server is usually offline.',
    inputSchema: {
      query: z.string().optional().describe('Free-text filter, e.g. "brummer amr" or an IP. Case-insensitive.'),
      label: z.string().optional().describe('Only servers carrying this label (label name, e.g. "brummer").'),
      limit: z.number().int().min(1).max(SEARCH_MAX_LIMIT).optional()
        .describe(`Maximum number of servers to return (default ${SEARCH_DEFAULT_LIMIT}).`)
    },
    annotations: readOnly
  }, ({ query, label, limit }) => run(() => {
    const terms = String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
    const labelName = label ? resolveLabel(label).name : null;
    const reachable = new Set(core.userServers(user.id).map(s => s.id));
    const matches = core.allServersWithDeployState()
      .filter(s => !labelName || s.labels.includes(labelName))
      .filter(s => {
        const hay = `${s.hostname} ${s.description || ''}`.toLowerCase();
        return terms.every(t => hay.includes(t));
      })
      .sort((a, b) => a.hostname.localeCompare(b.hostname, undefined, { sensitivity: 'base' }));
    const max = limit || SEARCH_DEFAULT_LIMIT;
    return {
      total_matches: matches.length,
      returned: Math.min(matches.length, max),
      servers: matches.slice(0, max).map(s => ({
        hostname: s.hostname,
        description: s.description,
        labels: s.labels,
        restricted: s.restricted,
        reachable_by_me: reachable.has(s.id),
        deploy: {
          state: deployState(s),
          up_to_date: s.is_up_to_date,
          last_deployed_at: core.sqlUtc(s.last_deployed_at)
        }
      }))
    };
  }));

  server.registerTool('list_grantable_labels', {
    title: 'Labels I can grant',
    description: 'Labels you may attach to team agents: the labels your groups hold (admins: all labels). ' +
      'For each: how many servers carry it, which groups hold it, the restricted servers it touches, and can_grant — ' +
      'false when a restricted server carrying the label refuses agent access for you (grant_label would fail).',
    inputSchema: {},
    annotations: readOnly
  }, () => run(() => {
    const serverCount = db.prepare('SELECT COUNT(*) AS n FROM server_labels WHERE label_id = ?');
    const groupsOf = db.prepare(`
      SELECT g.name FROM groups g JOIN label_groups lg ON g.id = lg.group_id
      WHERE lg.label_id = ? ORDER BY g.name COLLATE NOCASE
    `);
    return core.grantableLabels(user.id).map(l => {
      const groups = groupsOf.all(l.id).map(g => g.name);
      const blocked = core.grantBlockedBy(user, l.id).map(x => x.server.hostname);
      return {
        id: l.id,
        name: l.name,
        server_count: serverCount.get(l.id).n,
        groups,
        held_by_any_group: groups.length > 0,
        restricted_servers: core.restrictedServersWithLabel(l.id).map(x => x.server.hostname),
        can_grant: blocked.length === 0,
        ...(blocked.length ? { blocked_by: blocked } : {})
      };
    });
  }));

  server.registerTool('list_agents', {
    title: 'List team agents',
    description: 'Team agents (shared nemo agents) registered in Superkey, with their Linux account (agent_<name>), ' +
      'description and attached labels. An agent reaches exactly the servers carrying one of its labels ' +
      '(minus restricted servers that refuse agents).',
    inputSchema: {
      query: z.string().optional().describe('Case-insensitive filter on agent name, account or description.')
    },
    annotations: readOnly
  }, ({ query }) => run(() => {
    const q = String(query || '').trim().toLowerCase();
    return core.teamAgentsWithLabels()
      .filter(a => !q || `${a.name} ${a.account} ${a.description || ''}`.toLowerCase().includes(q))
      .map(a => ({
        id: a.id,
        name: a.name,
        account: a.account,
        description: a.description,
        labels: a.labels.map(l => l.name),
        source_cidr: a.source_cidr,
        created_at: core.sqlUtc(a.created_at)
      }));
  }));

  const agentLabelInput = {
    agent: nameOrId.describe('Team agent: name (e.g. "brummer_ops"), account ("agent_brummer_ops") or numeric id.'),
    label: nameOrId.describe('Label: name (e.g. "brummer") or numeric id.')
  };

  server.registerTool('grant_label', {
    title: 'Grant a label to a team agent',
    description: 'Attach a label to a team agent, giving its account SSH access to every server carrying the label. ' +
      'Same rules as the web UI: you can only grant labels you hold yourself (admins: any), and labels touching ' +
      'restricted servers that refuse agent access for you are rejected. Idempotent (granting an attached label ' +
      'changes nothing). The keys are deployed within ~1-2 minutes; check with deploy_status.',
    inputSchema: agentLabelInput,
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false }
  }, ({ agent, label }) => run(() => {
    const a = resolveAgent(agent, core.agentAccount);
    const l = resolveLabel(label);
    const { changed } = core.grantAgentLabel(user, a.id, l.id);
    const covered = labelServers(l.id).filter(s => {
      const policy = restricted.policyFor(s.hostname);
      return !policy || policy.allow_agents;
    });
    return {
      ok: true,
      changed,
      agent: a.name,
      account: core.agentAccount(a.name),
      label: l.name,
      servers_with_label: covered.length,
      message: changed
        ? `Label "${l.name}" attached to ${a.name}. ${core.agentAccount(a.name)} is deployed to ${covered.length} server(s) within ~1-2 min.`
        : `${a.name} already had label "${l.name}"; nothing changed.`,
      next: `Call deploy_status with agent "${a.name}" to watch the rollout.`
    };
  }));

  server.registerTool('revoke_label', {
    title: 'Revoke a label from a team agent',
    description: 'Detach a label from a team agent; its account is removed from the servers it no longer reaches on ' +
      'the next deploy (~1-2 minutes, offline servers when they come back). Same rules as the web UI: you can only ' +
      'remove labels you hold yourself (admins: any); restricted servers with allowed_users only let those users ' +
      'manage agent access. Idempotent.',
    inputSchema: agentLabelInput,
    annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: true, openWorldHint: false }
  }, ({ agent, label }) => run(() => {
    const a = resolveAgent(agent, core.agentAccount);
    const l = resolveLabel(label);
    const { changed } = core.revokeAgentLabel(user, a.id, l.id);
    return {
      ok: true,
      changed,
      agent: a.name,
      account: core.agentAccount(a.name),
      label: l.name,
      message: changed
        ? `Label "${l.name}" removed from ${a.name}; its access there goes away on the next deploy.`
        : `${a.name} did not have label "${l.name}"; nothing changed.`
    };
  }));

  server.registerTool('deploy_status', {
    title: 'Deploy status',
    description: 'Whether Superkey has rolled out access for a team agent and/or a label. With agent: the servers its ' +
      'labels cover, and per server whether the agent\'s key is deployed (the server\'s deployed key set equals what ' +
      'Superkey would deploy now, which includes the agent). With label: the servers carrying it. With both: the ' +
      'label\'s servers, marking whether the agent is expected there. Returns a summary (deployed / pending / ' +
      'never-deployed), not-yet-deployed servers first, and restricted servers excluded for agents. ' + DEPLOY_NOTE,
    inputSchema: {
      agent: nameOrId.optional().describe('Team agent: name, account (agent_<name>) or id.'),
      label: nameOrId.optional().describe('Label name or id.')
    },
    annotations: readOnly
  }, ({ agent, label }) => run(() => {
    if (agent === undefined && label === undefined) throw httpError(400, 'Pass agent and/or label.');
    const a = agent !== undefined ? resolveAgent(agent, core.agentAccount) : null;
    const l = label !== undefined ? resolveLabel(label) : null;
    const host = (s, extra) => {
      const d = core.withDeployState(s);
      return {
        hostname: s.hostname,
        state: deployState(d),
        last_deployed_at: core.sqlUtc(s.last_deployed_at),
        restricted: d.restricted,
        ...extra
      };
    };

    if (!a) {
      const hosts = labelServers(l.id).map(s => host(s)).sort(byStateThenName);
      const agents = db.prepare(`
        SELECT a.name FROM team_agents a JOIN agent_labels al ON a.id = al.agent_id
        WHERE al.label_id = ? ORDER BY a.name
      `).all(l.id).map(r => r.name);
      return { label: l.name, agents_with_label: agents, summary: summarize(hosts), servers: hosts, note: DEPLOY_NOTE };
    }

    const agentLabels = db.prepare(`
      SELECT l.id, l.name FROM labels l JOIN agent_labels al ON l.id = al.label_id
      WHERE al.agent_id = ? ORDER BY l.name
    `).all(a.id);
    const expected = new Set(core.teamAgentServers(a.id).map(s => s.id));
    // Candidate servers: the label's (if given), else every server carrying
    // one of the agent's labels. Restricted servers refusing agents are
    // reported apart: the agent is never deployed there.
    const candidates = l
      ? labelServers(l.id)
      : db.prepare(`
          SELECT DISTINCT s.* FROM servers s
          JOIN server_labels sl ON s.id = sl.server_id
          JOIN agent_labels al ON al.label_id = sl.label_id
          WHERE al.agent_id = ?
          ORDER BY s.hostname COLLATE NOCASE
        `).all(a.id);
    const excluded = [];
    const hosts = [];
    for (const s of candidates) {
      const policy = restricted.policyFor(s.hostname);
      if (policy && !policy.allow_agents) {
        excluded.push({ hostname: s.hostname, reason: 'restricted server without allow_agents (restricted-servers.json)' });
        continue;
      }
      const isExpected = expected.has(s.id);
      const h = host(s, { agent_expected: isExpected });
      if (isExpected) h.agent_key_deployed = h.state === 'deployed';
      hosts.push(h);
    }
    hosts.sort(byStateThenName);
    const relevant = hosts.filter(h => h.agent_expected);
    const result = {
      agent: a.name,
      account: core.agentAccount(a.name),
      agent_labels: agentLabels.map(x => x.name),
      ...(l ? { label: l.name } : {}),
      summary: summarize(relevant),
      servers: hosts,
      excluded,
      note: DEPLOY_NOTE
    };
    if (l && !agentLabels.some(x => x.id === l.id)) {
      result.warning = `${a.name} does not hold label "${l.name}", so its account is not deployed to these servers ` +
        '(unless another of its labels covers them). Use grant_label to attach it.';
    }
    if (!l && agentLabels.length === 0) {
      result.warning = `${a.name} has no labels and therefore no access anywhere. Use grant_label to attach one.`;
    }
    return result;
  }));

  server.registerTool('list_my_bots', {
    title: 'List my personal agents',
    description: 'Your PERSONAL agents (bots that run as you, account <you>_<name>): whether they follow you onto ' +
      'all your devices or only labelled ones, root access (docker), source restriction and how many devices they ' +
      'reach. Read-only; manage them in the web UI (My agents). Team agents are listed by list_agents.',
    inputSchema: {},
    annotations: readOnly
  }, () => run(() => core.ownBotsDetailed(user).map(b => ({
    id: b.id,
    name: b.name,
    account: b.account,
    key_type: String(b.public_key || '').trim().split(/\s+/)[0] || null,
    source_cidr: b.source_cidr,
    scope: b.label_scoped ? 'labels' : 'all my devices',
    labels: b.labels.map(l => l.name),
    root_access: b.docker,
    device_count: b.device_count,
    created_at: core.sqlUtc(b.created_at)
  }))));

  return server;
}

function sendJsonRpcError(res, status, code, message) {
  res.status(status).json({ jsonrpc: '2.0', error: { code, message }, id: null });
}

// Mount /mcp on the app. `requireAuth` is the OAuth bearer guard from
// src/oauth.js (null when OAuth could not be configured); `core` is the
// shared logic from server.js.
function mount(app, requireAuth, core) {
  if (!requireAuth) {
    app.all('/mcp', (req, res) => sendJsonRpcError(res, 503, -32000,
      'MCP is disabled on this Superkey: its OAuth issuer URL is not configured (PUBLIC_URL).'));
    return;
  }

  app.all('/mcp', requireAuth, async (req, res) => {
    if (req.method !== 'POST') {
      // Stateless server: no standalone SSE stream (GET) and no session to
      // delete (DELETE).
      res.set('Allow', 'POST');
      return sendJsonRpcError(res, 405, -32000, 'Method not allowed: this MCP server is stateless, use POST.');
    }
    // requireAuth verified the token and that the user exists; load the
    // same users row a session would carry.
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.auth.extra.userId);
    if (!user) return sendJsonRpcError(res, 401, -32001, 'User no longer exists');

    const server = buildServer(user, req.auth, core);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => {
      transport.close();
      server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error('MCP request failed:', err);
      if (!res.headersSent) sendJsonRpcError(res, 500, -32603, 'Internal server error');
    }
  });
}

module.exports = { mount, deployState, summarize };
