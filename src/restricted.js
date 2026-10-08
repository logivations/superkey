// Restricted-servers policy.
//
// The policy lives in restricted-servers.json IN THE GIT REPO, not in the
// database, on purpose: any admin can edit the database through the API
// without leaving a trace, but widening access to a restricted server this
// way requires a commit (git history + review). The file is authoritative
// at deploy time — label/group wiring in the DB that contradicts it is
// simply never deployed.
//
// Format:
//   {
//     "restricted_servers": [
//       {
//         "match": "prod-*",              // hostname glob (* and ?)
//         "allowed_groups": ["infra"],    // groups whose members are deployed (needs label wiring too)
//         "allowed_users": ["a@b.com"],   // emails deployed DIRECTLY by this file (no label needed);
//                                         // if non-empty, ONLY these users may manage agent access
//                                         // to matching servers — superkey admins are NOT exempt
//         "allow_agents": false           // team agents deployable? (default false)
//       }
//     ]
//   }
//
// At least one of allowed_groups / allowed_users must be present. If
// several entries match a hostname, the lists are unioned and allow_agents
// is true if any entry allows it.
//
// A second, independent section makes servers UNPRIVILEGED: who is deployed
// is still decided by label wiring (and restricted_servers, if a host is in
// both), but every account superkey deploys there -- humans, personal bots
// and team agents alike -- gets only the `superkey` marker group (no docker,
// logi, superkey_ops, superkey_agents, adm, systemd-journal) and, when
// forced_command is set, a `restrict,pty,command="..."` key, so a login can
// do nothing but run that command. For hosts no superkey admin should be
// able to administer through superkey accounts (e.g. a host holding other
// people's data). Like the restricted list, loosening it takes a commit.
//
//   {
//     "unprivileged_servers": [
//       { "match": "nemo", "forced_command": "sudo -n /usr/local/sbin/nemo-enter" }
//     ]
//   }
//
// If several entries match, the first one wins.

const fs = require('fs');
const path = require('path');

const POLICY_PATH = process.env.RESTRICTED_SERVERS_PATH
  || path.join(__dirname, '..', 'restricted-servers.json');

let entries = [];
let unprivilegedEntries = [];

// forced_command goes verbatim into authorized_keys as command="...", so
// anything that could break out of that quoted option is refused.
const FORCED_COMMAND_RE = /^[A-Za-z0-9 _.,:=\/+-]{1,200}$/;

function globToRegex(glob) {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

function loadPolicy() {
  entries = [];
  unprivilegedEntries = [];
  if (!fs.existsSync(POLICY_PATH)) {
    console.log(`Restricted-servers policy: no file at ${POLICY_PATH}, no servers restricted`);
    return;
  }
  const raw = JSON.parse(fs.readFileSync(POLICY_PATH, 'utf8'));
  const list = raw.restricted_servers || [];
  for (const e of list) {
    const groups = e.allowed_groups;
    const users = e.allowed_users;
    if (!e.match || (!Array.isArray(groups) && !Array.isArray(users))) {
      throw new Error(`restricted-servers.json: every entry needs "match" and allowed_groups and/or allowed_users (bad entry: ${JSON.stringify(e)})`);
    }
    entries.push({
      regex: globToRegex(e.match),
      match: e.match,
      allowed_groups: Array.isArray(groups) ? groups : [],
      allowed_users: (Array.isArray(users) ? users : []).map(u => String(u).toLowerCase()),
      allow_agents: !!e.allow_agents
    });
  }
  for (const e of raw.unprivileged_servers || []) {
    if (!e.match || (e.forced_command !== undefined
        && (typeof e.forced_command !== 'string' || !FORCED_COMMAND_RE.test(e.forced_command)))) {
      throw new Error(`restricted-servers.json: unprivileged_servers entries need "match" and an optional plain forced_command (bad entry: ${JSON.stringify(e)})`);
    }
    unprivilegedEntries.push({
      regex: globToRegex(e.match),
      match: e.match,
      forced_command: e.forced_command || null
    });
  }
  console.log(`Restricted-servers policy: ${entries.length} restricted, ${unprivilegedEntries.length} unprivileged rule(s) loaded from ${POLICY_PATH}`);
}

// Policy for a hostname: null if unrestricted, otherwise the merged
// { allowed_groups, allowed_users, allow_agents } of all matching rules.
function policyFor(hostname) {
  const matching = entries.filter(e => e.regex.test(hostname));
  if (matching.length === 0) return null;
  return {
    allowed_groups: [...new Set(matching.flatMap(e => e.allowed_groups))],
    allowed_users: [...new Set(matching.flatMap(e => e.allowed_users))],
    allow_agents: matching.some(e => e.allow_agents)
  };
}

// Unprivileged policy for a hostname: null, or { forced_command } (null
// command = unprivileged shell) of the first matching rule.
function unprivilegedFor(hostname) {
  const e = unprivilegedEntries.find(x => x.regex.test(hostname));
  return e ? { forced_command: e.forced_command } : null;
}

// Whether this user may manage agent access on a server with this policy.
// allowed_users, when set, is exclusive — being a superkey admin does not
// bypass it (that is the whole point of the list living in git).
function userMayManageAgents(policy, email) {
  if (!policy.allow_agents) return false;
  if (policy.allowed_users.length === 0) return true;
  return policy.allowed_users.includes(String(email || '').toLowerCase());
}

// Fail fast on a broken policy file: better to refuse startup than to run
// with restrictions silently dropped.
loadPolicy();

module.exports = { policyFor, unprivilegedFor, userMayManageAgents, POLICY_PATH };
