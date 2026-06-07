# Wazuh Scripts Resource

Collection of custom Wazuh scripts, integrations, active responses, and utilities to enhance monitoring capabilities.

**Author:** Adam Pielak (tick) — tick@linuxmafia.pl

---

## Contents

### Agent management

| File | Description |
|------|-------------|
| `add-agent-to-group.sh` | Assign agents to groups based on OS detection |
| `wazuh-agent-health-check.sh` | Per-group agent status table (active/disconnected/never_connected) with pagination |

### Health & monitoring

| File | Description |
|------|-------------|
| `wazuh-indexer-health.sh` | OpenSearch cluster health, disk usage per node, unassigned shards; exits non-zero for red/disk threshold breach — cron-friendly |

### Configuration

| File | Description |
|------|-------------|
| `linux-wazuh-agent-local_internal_options.sh` | Set agent `local_internal_options.conf` on Linux and restart |
| `windows-wazuh-agent-local_internal_options.ps1` | Set agent `local_internal_options.conf` on Windows and restart |
| `windows-enable-PSLogging.ps1` | Enable PowerShell script block and module logging |
| `wazuh-manager-local_internal_options.conf` | Reference `local_internal_options.conf` for manager |
| `sync-wazuh-conf.sh` | Sync `ossec.conf` from master to all workers via cluster_control |

### Integrations (`wazuh-manager/integrations/`)

| File | Description |
|------|-------------|
| `custom-keep.py` | Wazuh → Keep (alert management) integration; queries OpenSearch for document ID, sends structured alert to Keep webhook |

### Active responses (`wazuh-manager/active-response/`)

| File | Description |
|------|-------------|
| `suricata_ja3.py` | Active response stub for processing Suricata JA3 data |

### Wodles (`wazuh-manager/wodles/`)

| File | Description |
|------|-------------|
| `esquery.py` | Periodic Elasticsearch/OpenSearch query wodle; sends event count to Wazuh socket |

### OpenSearch / Indexer

| File | Description |
|------|-------------|
| `wazuh-index_hot_warm_delete-policy.json` | ISM policy: hot (14d) → warm (replica 0) → delete (102d) |
| `wazuh-indexer/opensearch.yml` | 4-node cluster config template |
| `wazuh_flag_scripted_fields.txt` | OpenSearch Dashboard scripted field mapping country name → flag emoji |

### Dashboard (`wazuh-dashboard/`)

Custom dashboards and visualizations.

### CVE-2025-24016

Wazuh unsafe deserialization RCE — detection and PoC material.

| File | Description |
|------|-------------|
| `CVE-2025-24016-exploit.py` | Simple PoC: unhandled_exc deserialization payload for arbitrary command execution |
| `CVE-2025-24016-exploit2.py` | Extended PoC with banner and argument parsing |
| `CVE-2025-24016-POC.py` | `__reduce__` payload variant |
| `CVE-2025-24016-POC.curl` | Raw curl PoC for manual testing |
| `CVE-2025-24016.snort` | Snort + YARA rules for Mirai IOC detection |
| `nuclei-CVE-2025-24016.yaml` | Nuclei template for safe detection (triggers NameError, no exploitation) |

### Misc

| File | Description |
|------|-------------|
| `debug-wazuh..txt` | tcpdump one-liners for monitoring Wazuh agent traffic (port 1514) |
| `mikrotik2wazuh.txt` | MikroTik → Wazuh log forwarding notes |
| `filebeat/` | Filebeat config snippets |

---

## Usage — health scripts

```bash
# Agent health (prompts for password if not supplied)
./wazuh-agent-health-check.sh https://localhost:55000 wazuh-wui <password>

# Indexer health (default threshold 80%)
./wazuh-indexer-health.sh https://localhost:9200 admin <password>
# Custom disk threshold
./wazuh-indexer-health.sh https://localhost:9200 admin <password> 75
```

Exit codes for `wazuh-indexer-health.sh`: `0` = green, `1` = yellow, `2` = red or disk threshold exceeded.

---

## Keep integration — ossec.conf snippet

```xml
<ossec_config>
  <!-- Keep integration -->
  <integration>
    <name>custom-keep</name>
    <hook_url>http://KEEP_IP_ADDRESS:8080/alerts/event</hook_url>
    <api_key>KEEP_API_KEY</api_key>
    <level>3</level>
    <alert_format>json</alert_format>
  </integration>
</ossec_config>
```
