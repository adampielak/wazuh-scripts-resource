#!/usr/bin/env bash
# Auto-refreshes all OpenSearch Dashboards index patterns.
# Triggered by systemd after wazuh-manager restart.
set -euo pipefail

DASH_URL="https://127.0.0.1:443"
DASH_USER="admin"
PASS_FILE="/etc/wazuh-dashboard/.refresh_token"

if [[ ! -f "${PASS_FILE}" ]]; then
  echo "ERROR: ${PASS_FILE} missing — run the Ansible playbook with --tags install_systemd" >&2
  exit 1
fi
DASH_PASS="$(cat "${PASS_FILE}")"

# Wait up to 90s for dashboard to be up
for i in $(seq 1 18); do
  curl -sk -o /dev/null -w "%{http_code}" \
    -u "${DASH_USER}:${DASH_PASS}" \
    "${DASH_URL}/api/status" | grep -q "200" && break
  sleep 5
done

PATTERNS=$(curl -sk \
  -u "${DASH_USER}:${DASH_PASS}" \
  -H "osd-xsrf: true" \
  "${DASH_URL}/api/saved_objects/_find?type=index-pattern&per_page=100" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print('\n'.join(o['id'] for o in d.get('saved_objects',[])))")

COUNT=0
while IFS= read -r ID; do
  [[ -z "${ID}" ]] && continue
  curl -sk -X POST \
    -u "${DASH_USER}:${DASH_PASS}" \
    -H "osd-xsrf: true" \
    -H "Content-Type: application/json" \
    "${DASH_URL}/api/index_patterns/index_pattern/${ID}/fields/refresh" > /dev/null
  COUNT=$((COUNT + 1))
done <<< "${PATTERNS}"

logger -t wazuh-refresh-patterns "Refreshed ${COUNT} index pattern(s)"
echo "Refreshed ${COUNT} index pattern(s)"
