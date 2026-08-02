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
//         "allowed_groups": ["infra"],    // only these groups' members are deployed
//         "allow_agents": false           // team agents allowed? (default false)
//       }
//     ]
//   }
//
// If several entries match a hostname, allowed_groups are the union and
// allow_agents is true if any entry allows it.

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
    if (!e.match || !Array.isArray(e.allowed_groups)) {
      throw new Error(`restricted-servers.json: every entry needs "match" and "allowed_groups" (bad entry: ${JSON.stringify(e)})`);
    }
    entries.push({
      regex: globToRegex(e.match),
      match: e.match,
      allowed_groups: e.allowed_groups,
      allow_agents: !!e.allow_agents
    });
  }
  console.log(`Restricted-servers policy: ${entries.length} rule(s) loaded from ${POLICY_PATH}`);
}

// Policy for a hostname: null if unrestricted, otherwise the merged
// { allowed_groups, allow_agents } of all matching rules.
function policyFor(hostname) {
  const matching = entries.filter(e => e.regex.test(hostname));
  if (matching.length === 0) return null;
  return {
    allowed_groups: [...new Set(matching.flatMap(e => e.allowed_groups))],
    allow_agents: matching.some(e => e.allow_agents)
  };
}

// Fail fast on a broken policy file: better to refuse startup than to run
// with restrictions silently dropped.
loadPolicy();

module.exports = { policyFor, POLICY_PATH };
