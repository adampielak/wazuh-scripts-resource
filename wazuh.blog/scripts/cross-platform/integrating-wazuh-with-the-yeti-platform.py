<!-- Source: https://wazuh.com/blog/integrating-wazuh-with-yeti-platform/ | Article: Integrating Wazuh with the Yeti platform -->
#!/var/ossec/framework/python/bin/python3
import json
import os
import re
import sys
import requests
import ipaddress
from requests.exceptions import Timeout
from socket import AF_UNIX, SOCK_DGRAM, socket

# Exit error codes
ERR_NO_REQUEST_MODULE = 1
ERR_BAD_ARGUMENTS = 2
ERR_BAD_MD5_SUM = 3
ERR_NO_RESPONSE_YETI = 4
ERR_SOCKET_OPERATION = 5
ERR_FILE_NOT_FOUND = 6
ERR_INVALID_JSON = 7

# Global vars
debug_enabled = True
timeout = 10
retries = 3
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
json_alert = {}


# Log and socket path
LOG_FILE = f'{pwd}/logs/integrations.log'
SOCKET_ADDR = f'{pwd}/queue/sockets/queue'

# Constants
ALERT_INDEX = 1
APIKEY_INDEX = 2
TIMEOUT_INDEX = 6
RETRIES_INDEX = 7
YETI_INSTANCE = 'http://<YETI_IP_ADDRESS>'

def debug(msg: str) -> None:
    """Log the message in the log file with the timestamp, if debug flag
    is enabled."""
    if debug_enabled:
        print(msg)
        with open(LOG_FILE, 'a') as f:
            f.write(msg + '\n')

def main(args):
    global debug_enabled
    global timeout
    global retries
    try:
        # Read arguments
        bad_arguments: bool = False
        msg = ''
        if len(args) >= 4:
            debug_enabled = len(args) > 4 and args[4] == 'debug'
            if len(args) > TIMEOUT_INDEX:
                timeout = int(args[TIMEOUT_INDEX])
            if len(args) > RETRIES_INDEX:
                retries = int(args[RETRIES_INDEX])
        else:
            msg = '# Error: Wrong arguments\n'
            bad_arguments = True

        # Logging the call
        with open(LOG_FILE, 'a') as f:
            f.write(msg)

        if bad_arguments:
            debug('# Error: Exiting, bad arguments. Inputted: %s' % args)
            sys.exit(ERR_BAD_ARGUMENTS)

        # Read args
        apikey: str = args[APIKEY_INDEX]

        # Obtain the access token
        access_token = getAccessToken(apikey)

        # Core function
        process_args(args, access_token)


    except Exception as e:
        debug(str(e))
        raise

def getAccessToken(apikey):
    """Exchange API key for a JWT access token."""

    url = f"{YETI_INSTANCE}/api/v2/auth/api-token"
    headers = {"x-yeti-apikey": apikey}
    try:
        response = requests.post(url, headers=headers)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if not access_token:
            raise ValueError("Access token missing in the response.")
        return access_token
    except requests.exceptions.RequestException as e:
        debug(f"Error obtaining access token from API: {e}")
        sys.exit(1)

def process_args(args, access_token: str) -> None:
    """This is the core function, creates a message with all valid fields
    and overwrite or add with the optional fields."""
    debug('# Running Yeti script')

    # Read args
    alert_file_location: str = args[ALERT_INDEX]

    # Load alert. Parse JSON object.
    json_alert = get_json_alert(alert_file_location)
    debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

    # Determine the type of alert and process accordingly
    if 'data' in json_alert and ('sshd' in json_alert or 'srcip' in json_alert['data']):
        debug('# Detected an SSH-related alert')
        wazuh_info = json_alert['data']['srcip']
        msg: any = request_ssh_info(json_alert, access_token, wazuh_info)

    elif 'syscheck' in json_alert or 'md5_after' in json_alert['syscheck']:
        debug('# Detected a file integrity alert (md5 check)')
        wazuh_info = json_alert['syscheck']['md5_after']
        msg: any = request_md5_info(json_alert, access_token, wazuh_info)

    else:
        debug('# Alert does not match known types (SSH or MD5). Skipping processing.')
        return None

    # If a valid message is generated, send it
    if msg:
        send_msg(msg, json_alert['agent'])
    else:
        debug('# No valid message generated. Skipping sending.')

def request_md5_info(alert: any, access_token: str, wazuh_info: str):
    """Generate the JSON object with the message to be send."""
    alert_output = {'yeti': {}, 'integration': 'yeti'}

    # Validate md5 hash
    # if not isinstance(alert['syscheck']['md5_after'], str) or len(re.findall(r'\b([a-f\d]{32}|[A-F\d]{32})\b', alert['syscheck']['md5_after'])) != 1:
    #     debug(f"# Invalid md5_after value: '{alert['syscheck']['md5_after']}'")
    #     return None

    # Request info using Yeti API
    yeti_response_data = request_info_from_api(alert_output, access_token, wazuh_info)

    if not yeti_response_data:
        debug("No data returned from the Yeti API.")
        return None
   
    alert_output['yeti']['source'] = {
        'alert_id': alert['id'],
        'file': alert['syscheck']['path'],
        'md5': alert['syscheck']['md5_after'],
        'sha1': alert['syscheck']['sha1_after'],
    }

    # Check Yeti info about the hash

    if any("source" in ctx and ctx["source"].strip() for ctx in yeti_response_data.get("context", [])):
    # The source field is present and not empty
        alert_output['yeti'].update(
            {
            'info': {
                'name' : yeti_response_data.get('tags', [{}])[0].get("name"),
                'last_seen' : yeti_response_data.get('tags', [{}])[0].get("last_seen"),
                'Created' : yeti_response_data.get("created"),
                'type' : yeti_response_data.get("type"),    
                'source' : yeti_response_data.get('context', [{}])[0].get("source"),
            }})
        return alert_output
   
    else:
    # The source field is missing or empty
        alert_output['yeti'].update(
        {
        'info': {
            'name' : yeti_response_data.get('tags', [{}])[0].get("name"),
            'last_seen' : yeti_response_data.get('tags', [{}])[0].get("last_seen"),
            'Created' : yeti_response_data.get("created"),
            'type' : yeti_response_data.get("type"),
            'source' : "AbuseCHMalwareBazaaar",
        } })
        return alert_output

def is_valid_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)

        # Reject private, loopback, or reserved addresses
        if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_multicast:
            debug(f"# IP address '{ip_str}' is private, loopback, or reserved.")
            return False

        return True
    except ValueError:
        debug(f"# IP address '{ip_str}' is not valid.")
        return False
   
def request_ssh_info(alert: any, access_token: str, wazuh_info):
    """Generate the JSON object with the message to be send."""
    alert_output = {'yeti': {}, 'integration': 'yeti'}

    # Inline validation of the source IP
    if not is_valid_ip(wazuh_info):
        return None

    # Request info using Yeti API
    yeti_response_data = request_info_from_api(alert_output, access_token, wazuh_info)

    if not yeti_response_data:
        debug("No data returned from the Yeti API.")
        return None
   
    alert_output['yeti']['source'] = {
        'alert_id': alert['id'],
        'src_ip': alert['data']['srcip'],
        'src_port': alert['data']['srcport'],
        'dst_user': alert['data']['dstuser'],
    }

    # Check Yeti  info about the source IP

    if any("source" in ctx and ctx["source"].strip() for ctx in yeti_response_data.get("context", [])):
        # The source field is present and not empty
        alert_output['yeti'].update({
            'info': {
                'country_code': yeti_response_data.get('context', [{}])[0].get("country"),
                'threat':  yeti_response_data.get('context', [{}])[0].get("threat"),
                'reliability': yeti_response_data.get('context', [{}])[0].get("reliability"),
                'risk':  yeti_response_data.get('context', [{}])[0].get("risk"),
                'name': yeti_response_data.get('tags', [{}])[0].get("name"),
                'source': yeti_response_data.get('context', [{}])[0].get("source"),
                'created': yeti_response_data.get("created"),
                'type' : yeti_response_data.get("type"),
            }    
            })
        return alert_output
   
    else:
        # The source field is missing or empty
        alert_output['yeti'].update({
            'info': {
                'country_code': yeti_response_data.get('context', [{}])[0].get("country"),
                'threat':  yeti_response_data.get('context', [{}])[0].get("threat"),
                'reliability': yeti_response_data.get('context', [{}])[0].get("reliability"),
                'risk':  yeti_response_data.get('context', [{}])[0].get("risk"),
                'name': yeti_response_data.get('tags', [{}])[0].get("name"),
                'source': "AlienVaultIPReputation",
                'created': yeti_response_data.get("created"),
                'type' : yeti_response_data.get("type"),
            }    
            })
        return alert_output

def request_info_from_api(alert_output, access_token, wazuh_info):
    """Request information from Yeti API."""
    for attempt in range(retries + 1):
        try:
            yeti_response_data = query_api(access_token, wazuh_info)
            return yeti_response_data
        except Timeout:
            debug('# Error: Request timed out. Remaining retries: %s' % (retries - attempt))
            continue
        except Exception as e:
            debug(str(e))
            sys.exit(ERR_NO_RESPONSE_YETI)

    debug('# Error: Request timed out and maximum number of retries was exceeded')
    alert_output['yeti']['error'] = 408
    alert_output['yeti']['description'] = 'Error: API request timed out'
    send_msg(alert_output)
    sys.exit(ERR_NO_RESPONSE_YETI)

def query_api(access_token: str, wazuh_info: str) -> any:
    """Query the API for observables."""
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }
    debug('# Querying Yeti API')
    response = requests.get(
        f'{YETI_INSTANCE}/api/v2/observables/?value={wazuh_info}', headers=headers, timeout=timeout
    )
    if response.status_code == 200:
        return response.json()
    else:
        handle_api_error(response.status_code)

def handle_api_error(status_code):
    """Handle errors from the Yeti API."""
    alert_output = {}
    alert_output['yeti'] = {}
    alert_output['integration'] = 'yeti'

    if status_code == 401:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: Unauthorized. Check your API key.'
        send_msg(alert_output)
        raise Exception('# Error: Yeti credentials, required privileges error')
    elif status_code == 404:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: Resource not found.'
    elif status_code == 500:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: Internal server error.'
    else:
        alert_output['yeti']['error'] = status_code
        alert_output['yeti']['description'] = 'Error: API request failed.'

    send_msg(alert_output)
    raise Exception(f'# Error: Yeti API request failed with status code {status_code}')

def send_msg(msg: any, agent: any = None) -> None:
    if not agent or agent['id'] == '000':
        string = '1:yeti:{0}'.format(json.dumps(msg))
    else:
        location = '[{0}] ({1}) {2}'.format(agent['id'], agent['name'], agent['ip'] if 'ip' in agent else 'any')
        location = location.replace('|', '||').replace(':', '|:')
        string = '1:{0}->yeti:{1}'.format(location, json.dumps(msg))

    debug('# Request result from Yeti server: %s' % string)
    try:
        sock = socket(AF_UNIX, SOCK_DGRAM)
        sock.connect(SOCKET_ADDR)
        sock.send(string.encode())
        sock.close()
    except FileNotFoundError:
        debug('# Error: Unable to open socket connection at %s' % SOCKET_ADDR)
        sys.exit(ERR_SOCKET_OPERATION)

def get_json_alert(file_location: str) -> any:
    """Read JSON alert object from file."""
    try:
        with open(file_location) as alert_file:
            return json.load(alert_file)
    except FileNotFoundError:
        debug("# JSON file for alert %s doesn't exist" % file_location)
        sys.exit(ERR_FILE_NOT_FOUND)
    except json.decoder.JSONDecodeError as e:
        debug('Failed getting JSON alert. Error: %s' % e)
        sys.exit(ERR_INVALID_JSON)

if __name__ == '__main__':
    main(sys.argv)