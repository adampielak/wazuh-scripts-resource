#!/var/ossec/framework/python/bin/python3
import os
import sys
import json
import time
import requests
from os.path import dirname, abspath
from socket import socket, AF_UNIX, SOCK_DGRAM

wazuh_path = os.path.abspath(os.path.join(__file__, "../../.."))
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
ar_log_file = '{0}/logs/active-responses.log'.format(wazuh_path)

def ar_log():
        msg = '{0} {1} {2}'.format(now, os.path.realpath(__file__), 'Post JSON Alert')
        f = open(ar_log_file, 'a')
        f.write(msg +'\n')
        f.close()

def run_command():

	json_data = json.load(sys.stdin)
	json_dump = json.dumps(json_data)



ar_log()
run_command()
