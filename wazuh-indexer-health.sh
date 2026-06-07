#!/usr/bin/env bash
# wazuh-indexer-health.sh
# Checks OpenSearch cluster health, shard status, and disk usage.
# Exits non-zero if cluster is red or any node disk usage > threshold.
# Usage: ./wazuh-indexer-health.sh [url] [user] [password] [disk_threshold_%]

set -euo pipefail

OS_URL="${1:-https://localhost:9200}"
OS_USER="${2:-admin}"
OS_PASS="${3:-}"
DISK_WARN="${4:-80}"

if [[ -z "$OS_PASS" ]]; then
    read -rsp "Password for ${OS_USER}@${OS_URL}: " OS_PASS
    echo
fi

CURL=(curl -s -k -u "${OS_USER}:${OS_PASS}")

echo "=== Wazuh Indexer Health — $(date -u '+%Y-%m-%d %H:%M:%S UTC') ==="
echo "URL: ${OS_URL}"
echo

# Cluster health
HEALTH=$("${CURL[@]}" "${OS_URL}/_cluster/health?pretty")
STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
ACTIVE=$(echo "$HEALTH" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['active_shards'])")
UNASSIGNED=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['unassigned_shards'])")
NODES=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['number_of_nodes'])")
DATA_NODES=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin)['number_of_data_nodes'])")

STATUS_ICON="OK"
[[ "$STATUS" == "yellow" ]] && STATUS_ICON="WARN"
[[ "$STATUS" == "red" ]] && STATUS_ICON="CRIT"

echo "Cluster status : [${STATUS_ICON}] ${STATUS}"
echo "Nodes          : ${NODES} total, ${DATA_NODES} data"
echo "Active shards  : ${ACTIVE}"
echo "Unassigned     : ${UNASSIGNED}"
echo

# Node disk usage
echo "--- Node disk usage ---"
DISK_ALERT=0
"${CURL[@]}" "${OS_URL}/_cat/nodes?h=name,diskUsed,diskTotal,diskUsedPercent,heapPercent,cpu&v" | \
while IFS= read -r line; do
    echo "$line"
    if [[ "$line" =~ ^[^n] ]]; then
        pct=$(echo "$line" | awk '{print $4}' | tr -d '%')
        if [[ -n "$pct" ]] && (( $(echo "$pct > $DISK_WARN" | bc -l) )); then
            echo "  ^^^ DISK USAGE ${pct}% EXCEEDS THRESHOLD ${DISK_WARN}%"
            DISK_ALERT=1
        fi
    fi
done
echo

# Index status summary — wazuh-alerts indices only
echo "--- wazuh-alerts index summary (last 7 days) ---"
"${CURL[@]}" "${OS_URL}/_cat/indices/wazuh-alerts-*?h=index,health,status,pri,rep,docs.count,store.size&s=index:desc&v" | head -n 20
echo

# Red shards detail
if [[ "$STATUS" == "red" || "$UNASSIGNED" -gt 0 ]]; then
    echo "--- Unassigned shards ---"
    "${CURL[@]}" "${OS_URL}/_cat/shards?h=index,shard,prirep,state,unassigned.reason&v" | grep -v STARTED | head -n 30
    echo
fi

EXIT_CODE=0
if [[ "$STATUS" == "red" ]]; then
    echo "ALERT: cluster status RED"
    EXIT_CODE=2
elif [[ "$STATUS" == "yellow" ]]; then
    echo "WARN: cluster status YELLOW"
    EXIT_CODE=1
fi

if [[ "$DISK_ALERT" -eq 1 ]]; then
    echo "ALERT: disk usage threshold exceeded on one or more nodes"
    EXIT_CODE=2
fi

exit $EXIT_CODE
