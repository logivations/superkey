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

const fs = require('fs');
const path = require('path');

const POLICY_PATH = process.env.RESTRICTED_SERVERS_PATH
  || path.join(__dirname, '..', 'restricted-servers.json');

let entries = [];

function globToRegex(glob) {
  const escaped = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}$`, 'i');
}

function loadPolicy() {
  entries = [];
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
  console.log(`Restricted-servers policy: ${entries.length} rule(s) loaded from ${POLICY_PATH}`);
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

module.exports = { policyFor, userMayManageAgents, POLICY_PATH };
