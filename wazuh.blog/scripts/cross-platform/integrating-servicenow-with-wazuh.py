<!-- Source: https://wazuh.com/blog/integrating-servicenow-with-wazuh/ | Article: Integrating ServiceNow with Wazuh -->
#!/var/ossec/framework/python/bin/python3.10
# Wazuh -> ServiceNow integration script

import json
import sys
import time
import os

try:
    import requests
    from requests.auth import HTTPBasicAuth
    from dotenv import load_dotenv
except Exception as e:
    print("Required modules not found. Install with: pip install requests python-dotenv")
    sys.exit(1)

# Load environment variables from .env file in the same directory as this script
script_dir = os.path.dirname(os.path.realpath(__file__))
dotenv_path = os.path.join(script_dir, '.env')
load_dotenv(dotenv_path)

SN_INSTANCE = os.getenv('SERVICENOW_INSTANCE')
SN_USER = os.getenv('SERVICENOW_USER')
SN_PASS = os.getenv('SERVICENOW_PASS')
SN_TABLE_URL = f"https://{SN_INSTANCE}/api/now/table/incident"

debug_enabled = True  # Set to True for logs
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
log_file = '{0}/logs/integrations.log'.format(pwd)

def main(args):
    debug("# Starting")

    if not SN_INSTANCE or not SN_USER or not SN_PASS:
        debug("Missing ServiceNow configuration in environment variables.")
        sys.exit(1)

    # Read alert file location
    alert_file_location = args[1]

    debug("# File location")
    debug(alert_file_location)

    # Load alert JSON
    with open(alert_file_location, 'rb') as alert_file:
        last_line = alert_file.read().decode('utf-8').splitlines()[-1]
        if last_line.split():
            json_alert = json.loads(last_line)

    debug("# Processing alert")
    debug(json_alert)

    # Build ServiceNow payload
    msg = generate_payload(json_alert)
    debug("# Payload to ServiceNow")
    debug(msg)

    # Send to ServiceNow
    send_msg(msg)

def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        with open(log_file, "a") as f:
            f.write(msg)

def generate_payload(alert):
    title = alert['rule'].get('description', "No Description")
    alert_level = str(alert['rule'].get('level', "N/A"))
    agentname = alert['agent'].get('name', "No Name")
    agentip = alert['agent'].get('ip', "No IP")
    location = alert.get('location', "No Location")
    timestamp = alert.get('timestamp', "No Timestamp")
    full_log = alert.get('full_log', "No Log")

    payload = {
        "short_description": f"Wazuh Alert: {title}",
        "description": f"""
Wazuh Alert Details:
Timestamp: {timestamp}
Agent Name: {agentname}
Agent IP: {agentip}
Alert Level: {alert_level}
Location: {location}
Log: {full_log}
""",
        "urgency": "1",  # High
        "impact": "1",
        "category": "Security"
    }

    return payload

def send_msg(payload):
    try:
        response = requests.post(
            SN_TABLE_URL,
            auth=HTTPBasicAuth(SN_USER, SN_PASS),
            headers={"Content-Type": "application/json"},
            json=payload
        )
        debug(f"ServiceNow response: {response.status_code} {response.text}")
    except Exception as e:
        debug(f"Error sending to ServiceNow: {e}")

if __name__ == "__main__":
    try:
        if len(sys.argv) >= 2:
            msg = '{0} {1}'.format(now, sys.argv[1])
        else:
            msg = '{0} Wrong arguments'.format(now)
            with open(log_file, 'a') as f:
                f.write(msg + '\n')
            debug("# Exiting: Bad arguments.")
            sys.exit(1)

        with open(log_file, 'a') as f:
            f.write(msg + '\n')

        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise