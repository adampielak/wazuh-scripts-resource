<!-- Source: https://wazuh.com/blog/incident-management-with-wazuh-and-rootly/ | Article: Incident management with Wazuh and Rootly -->
#!/var/ossec/framework/python/bin/python3.10
# Wazuh → Rootly integration script

import json
import sys
import time
import os

try:
    import requests
except ImportError:
    print("Module 'requests' not found. Install with: pip install requests")
    sys.exit(1)

# === CONFIGURATION ===
ROOTLY_WEBHOOK_URL = "<ROOTLY_WEBHOOK_URL>"  

debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = f"{pwd}/logs/integrations-rootly.log"
if not os.path.exists(log_file):
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    with open(log_file, "w") as f:
        f.write("=== Rootly Integration Log Start ===\n")

now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

def main(args):
    debug("# Wazuh → Rootly script started")

    alert_file = args[1]
    debug(f"# Reading alert from: {alert_file}")

    with open(alert_file, 'rb') as f:
        last_line = f.read().decode('utf-8').splitlines()[-1]
        if last_line.strip():
            alert = json.loads(last_line)
        else:
            debug("Alert file is empty.")
            return

    payload = build_payload(alert)
    debug("# Sending payload to Rootly")
    debug(payload)

    send_to_rootly(payload)

def debug(msg):
    if debug_enabled:
        msg = f"{now}: {msg}\n"
        print(msg)
        with open(log_file, "a") as f:
            f.write(msg)

def build_payload(alert):
    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    description = rule.get("description")
    level = str(rule.get("level"))
    agent_name = agent.get("name", "Unknown")
    agent_ip = agent.get("ip", "Unknown")
    location = alert.get("location", "N/A")
    timestamp = alert.get("timestamp", "N/A")
    full_log = alert.get('full_log')
    computer = (
    alert.get('data', {}).get('win', {}).get('system', {}).get('computer')
    or alert.get('agent', {}).get('name')
    or "N/A"
)
  
    severity = map_severity(level)

    return {
        "title": f"Wazuh Alert: {description}",
        "Timestamp": timestamp,
        "Agent_IP": agent_ip,
        "Computer": computer,
        "summary": f"""
Timestamp: {timestamp}
Agent_Name: {agent_name}
Agent_IP: {agent_ip}
Computer: {computer}
Location: {location}
Log: {full_log}
Level: {level}
""",
        "source": "Wazuh",
        "severity": severity
    }

def map_severity(level):
    try:
        level = int(level)
        if level >= 12:
            return "SEV0" # High
        elif level >= 8:
            return "SEV1" #Medium
        else:
            return "SEV2" #Low

    except:
        return "unknown"

def send_to_rootly(payload):
    try:
        response = requests.post(
            ROOTLY_WEBHOOK_URL,
            headers={"Content-Type": "application/json"},
            json=payload
        )
        debug(f"Rootly response: {response.status_code} - {response.text}")
    except Exception as e:
        debug(f"Error sending to Rootly: {e}")

if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as e:
        debug(f"Unhandled exception: {e}")