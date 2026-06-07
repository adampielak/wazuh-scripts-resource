#!/usr/bin/env bash
# wazuh-agent-health-check.sh
# Queries Wazuh API and prints agent status summary per group.
# Usage: ./wazuh-agent-health-check.sh <manager_url> <user> <password>
# Example: ./wazuh-agent-health-check.sh https://localhost:55000 wazuh-wui MyPass

set -euo pipefail

MANAGER_URL="${1:-https://localhost:55000}"
API_USER="${2:-wazuh-wui}"
API_PASS="${3:-}"

if [[ -z "$API_PASS" ]]; then
    read -rsp "Password for ${API_USER}: " API_PASS
    echo
fi

TOKEN=$(curl -s -k -u "${API_USER}:${API_PASS}" \
    -X GET "${MANAGER_URL}/security/user/authenticate?raw=true")

if [[ -z "$TOKEN" || "$TOKEN" == *"error"* ]]; then
    echo "ERROR: Failed to authenticate" >&2
    exit 1
fi

AUTH=(-H "Authorization: Bearer ${TOKEN}")

PAGE_SIZE=500

fetch_agents() {
    local offset=0
    local total=1
    while (( offset < total )); do
        local result
        result=$(curl -s -k "${AUTH[@]}" \
            "${MANAGER_URL}/agents?limit=${PAGE_SIZE}&offset=${offset}&select=id,name,status,group,os.platform")
        local count
        count=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['total_affected_items'])" 2>/dev/null || echo 0)
        total=$count
        echo "$result" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for a in d['data']['affected_items']:
    grp = ','.join(a.get('group', ['default'])) if isinstance(a.get('group'), list) else a.get('group', 'default')
    print(a['id'], a['name'], a['status'], grp)
" 2>/dev/null
        (( offset += PAGE_SIZE ))
    done
}

echo "=== Wazuh Agent Health Check — $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
echo

fetch_agents | python3 - <<'PYEOF'
import sys
from collections import defaultdict

totals = defaultdict(lambda: defaultdict(int))
all_agents = []

for line in sys.stdin:
    parts = line.strip().split(' ', 3)
    if len(parts) < 4:
        continue
    aid, name, status, group = parts
    if aid == '000':
        continue
    all_agents.append((aid, name, status, group))
    for g in group.split(','):
        totals[g.strip()][status] += 1
    totals['__ALL__'][status] += 1

statuses = ['active', 'disconnected', 'never_connected', 'pending']

# Header
print(f"{'Group':<30} {'Active':>8} {'Disconn':>8} {'NeverConn':>10} {'Pending':>8} {'Total':>7} {'Active%':>8}")
print('-' * 85)

for group in sorted(totals.keys()):
    if group == '__ALL__':
        continue
    row = totals[group]
    total = sum(row.values())
    active_pct = 100 * row.get('active', 0) / total if total else 0
    flag = ' !' if row.get('disconnected', 0) > 0 or row.get('never_connected', 0) > 0 else ''
    print(f"{group:<30} {row.get('active',0):>8} {row.get('disconnected',0):>8} {row.get('never_connected',0):>10} {row.get('pending',0):>8} {total:>7} {active_pct:>7.1f}%{flag}")

print('-' * 85)
row = totals['__ALL__']
total = sum(row.values())
active_pct = 100 * row.get('active', 0) / total if total else 0
print(f"{'TOTAL':<30} {row.get('active',0):>8} {row.get('disconnected',0):>8} {row.get('never_connected',0):>10} {row.get('pending',0):>8} {total:>7} {active_pct:>7.1f}%")

print()
disconnected = [(aid, name, grp) for aid, name, status, grp in all_agents if status == 'disconnected']
if disconnected:
    print(f"Disconnected agents ({len(disconnected)}):")
    for aid, name, grp in disconnected:
        print(f"  [{aid}] {name}  (group: {grp})")
PYEOF
