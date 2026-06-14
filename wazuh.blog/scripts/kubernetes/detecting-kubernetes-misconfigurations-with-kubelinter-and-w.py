<!-- Source: https://wazuh.com/blog/detecting-kubernetes-with-kubelinter-and-wazuh/ | Article: Detecting Kubernetes misconfigurations with KubeLinter and Wazuh -->
#!/usr/bin/env bash
# KubeLinter scan script for Wazuh integration
set -euo pipefail

# The script runs KubeLinter against this path. Update this path if your manifests are stored elsewhere.
MANIFEST_DIR="/etc/kubernetes/manifests"

# Wazuh monitors this log file and ingests each JSON line as a separate event.
LOG_FILE="/var/log/kubelinter.log"

TMP_FILE="$(mktemp)"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

RESULTS=$(kube-linter lint "$MANIFEST_DIR" --format json 2>/dev/null || true)

if [[ -n "$RESULTS" ]]; then
  echo "$RESULTS" | python3 -c "
import sys, json

data = json.load(sys.stdin)
reports = data.get('Reports', [])

for r in reports:
    flat = {
        'integration':    'kubelinter',
        'check':          r.get('Check', ''),
        'remediation':    r.get('Remediation', ''),
        'message':        r.get('Diagnostic', {}).get('Message', ''),
        'kind':           r.get('Object', {}).get('K8sObject', {}).get('GroupVersionKind', {}).get('Kind', ''),
        'name':           r.get('Object', {}).get('K8sObject', {}).get('Name', ''),
        'namespace':      r.get('Object', {}).get('K8sObject', {}).get('Namespace', ''),
        'file':           r.get('Object', {}).get('Metadata', {}).get('FilePath', ''),
        'scan_timestamp': sys.argv[1]
    }
    print(json.dumps(flat))
" "$TIMESTAMP" > "$TMP_FILE"

  mv "$TMP_FILE" "$LOG_FILE"
  chmod 0644 "$LOG_FILE"
else
  : > "$LOG_FILE"
fi