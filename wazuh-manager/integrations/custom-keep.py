#!/usr/bin/python3
#
# Wazuh & Keep integration by Adam Pielak tick@linuxmafia.pl
#
# ADD THIS TO ossec.conf configuration:
#  <ossec_config>
#    <!-- Keep integration -->
#    <integration>
#      <name>custom-keep</name>
#      <hook_url>http://<KEEP_IP_ADDRESS>:8080/alerts/event</hook_url>
#      <api_key><KEEP_API_KEY></api_key>
#      <level>3</level>
#      <alert_format>json</alert_format>
#    </integration>
#  </ossec_config>

import json
import os
import sys
from datetime import datetime, timezone
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    import requests
except Exception:
    print("No module 'requests' found. Install: pip install requests")
    sys.exit(1)

# Hardcode your environment value here
environment = "Wazuh.Blog"
url = "https://wazuh.blog/app/endpoints-summary#/agents?tab=welcome&agent="
imageUrl = "https://wazuh.com/uploads/2022/05/WAZUH.png"
ticket_url = "https://jira.wazuh.blog"
opensearch_url = "https://10.10.10.10:9200"
opensearch_index_prefix = "wazuh-alerts-"
opensearch_auth = ("admin", "*")  # change if needed

# Global vars
debug_enabled = False
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}
json_options = {}

# Log path
LOG_FILE = f"{pwd}/logs/integrations.log"

# Constants
ALERT_INDEX = 1
API_KEY_INDEX = 2
WEBHOOK_INDEX = 3

def main(args):
    global debug_enabled
    try:
        bad_arguments = False
        if len(args) >= 4:
            msg = " ".join(args[1:6])
            debug_enabled = len(args) > 4 and args[4] == "debug"
        else:
            msg = "# ERROR: Wrong arguments"
            bad_arguments = True

        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")

        if bad_arguments:
            debug("# ERROR: Exiting, bad arguments. Inputted: %s" % args)
            sys.exit(2)

        process_args(args)

    except Exception as e:
        debug(str(e))
        raise

def process_args(args):
    debug("# Running Custom Keep script")

    alert_file_location = args[ALERT_INDEX]
    webhook = args[WEBHOOK_INDEX]
    api_key = args[API_KEY_INDEX]
    options_file_location = ""

    for idx in range(4, len(args)):
        if args[idx].endswith("options"):
            options_file_location = args[idx]
            break

    json_options = get_json_options(options_file_location)
    debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    debug("# Generating message")
    msg = generate_msg(json_alert, json_options)

    if not msg:
        debug("# ERROR: Empty message")
        raise Exception

    debug(f"# Sending message {json.dumps(msg, indent=2)} to Keep server")
    send_msg(msg, webhook, api_key)

def debug(msg):
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, "a") as f:
            f.write(msg + "\n")

# Helper to extract agent.ip, agent.srcip, agent_ip for ip_address field
def get_ip_address(alert):
    agent = alert.get("agent", {})
    data = alert.get("data", {})
    if "ip" in agent:
        return agent["ip"]
    if "srcip" in agent:
        return agent["srcip"]
    if "agent_ip" in data:
        return data["agent_ip"]
    if "srcip" in data:
        return data["srcip"]
    if "ip" in data:
        return data["ip"]
    return "unknown"

def generate_msg(alert, options):
    level = alert.get("rule", {}).get("level", 0)
    title = alert.get("rule", {}).get("description", "N/A")
    rule_id = alert.get("rule", {}).get("id", "N/A")
    agent = alert.get("agent", {})
    agent_id = agent.get("id", "N/A")
    agent_name = agent.get("name", "N/A")
    full_log = alert.get("full_log", "N/A")

    severity = "low"
    if level > 14:
        severity = "critical"
    elif level > 11:
        severity = "high"
    elif level > 6:
        severity = "info"

    created_at = alert.get("timestamp", datetime.now(timezone.utc).astimezone().isoformat())
    fingerprint = f"{agent_id}-{rule_id}"

    labels = alert.get("data", {}).copy()
    labels.update({
        "agent_id": agent_id,
        "agent_name": agent_name,
        "rule_id": rule_id
    })

    agent_ip = get_ip_address(alert)
    document_id = get_document_id(alert)

    result = {
        "id": f"{fingerprint}-{int(datetime.now().timestamp())}",
        "name": title,
        "status": "firing",
        "created_at": created_at,
        "lastReceived": created_at,
        "environment": environment,
        "service": agent_name,
        "source": ["wazuh"],
        "note": f"Rule ID {rule_id}\nLevel {level}\nAgent ID {agent_id}\nAgent Name {agent_name}\n\nFull Log:\n{full_log}",
        "message": title,
        "description": f"Rule ID {rule_id}\nLevel {level}\nAgent ID {agent_id}\nAgent Name {agent_name}\n\nFull Log:\n{full_log}",
        "severity": severity,
        "host_name": agent_name,
        "hostname": agent_name,
        "ip_address": agent_ip,
        "host_ip": agent_ip,
        "pushed": True,
        "url": f"{url}/app/discover#/doc/{opensearch_index_prefix}*/{opensearch_index_prefix}{created_at[:10].replace('-', '.')}?id={document_id}" if document_id else url,
#        "url": f"{url}{agent_id}",
        "imageUrl": imageUrl,
        "labels": labels,
        "ticket_url": ticket_url,
        "fingerprint": fingerprint
    }
    return result

def get_document_id(alert):
    try:
        timestamp = alert.get("timestamp")
        if not timestamp:
            return None

        date_index = timestamp.split("T")[0].replace("-", ".")
        search_index = f"{opensearch_index_prefix}{date_index}"

        search_query = {
            "query": {
                "bool": {
                    "must": [
                        {"match": {"agent.id": alert.get("agent", {}).get("id", "")}},
                        {"match": {"rule.id": alert.get("rule", {}).get("id", "")}},
                        {"match": {"timestamp": alert.get("timestamp", "")}}
                    ]
                }
            },
            "sort": [{"timestamp": {"order": "desc"}}],
            "size": 1
        }

        res = requests.post(
            f"{opensearch_url}/{search_index}/_search",
            auth=opensearch_auth,
            headers={"Content-Type": "application/json"},
            json=search_query,
            verify=False
        )

        if res.status_code == 200:
            hits = res.json().get("hits", {}).get("hits", [])
            if hits:
                return hits[0].get("_id")
        debug(f"# OpenSearch query failed or no hits: {res.text}")
    except Exception as e:
        debug(f"# Failed querying OpenSearch: {e}")
    return None

def send_msg(msg, url, api_key):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-API-KEY": api_key,
    }
    try:
        res = requests.post(url, json=msg, headers=headers, timeout=10, verify=False)
        debug(f"# Response received: {res.status_code} {res.text}")
    except Exception as e:
        debug(f"# Error sending message: {e}")

def get_json_alert(file_location):
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug(f"# JSON file for alert {file_location} doesn't exist")
        sys.exit(6)
    except json.decoder.JSONDecodeError as e:
        debug(f"Failed getting JSON alert. Error: {e}")
        sys.exit(7)

def get_json_options(file_location):
    if not file_location:
        return {}
    try:
        with open(file_location) as options_file:
            return json.load(options_file)
    except FileNotFoundError:
        debug(f"# JSON file for options {file_location} doesn't exist")
        return {}
    except Exception as e:
        debug(f"Failed getting JSON options. Error: {e}")
        sys.exit(7)

if __name__ == "__main__":
    main(sys.argv)
