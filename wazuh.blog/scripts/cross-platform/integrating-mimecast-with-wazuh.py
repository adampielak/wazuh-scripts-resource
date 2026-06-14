<!-- Source: https://wazuh.com/blog/integrating-mimecast/ | Article: Integrating Mimecast with Wazuh -->
#!/usr/bin/env python
# -*- coding: utf-8 -*-
#Mimecast SIEM logs download
import logging.handlers
import json
import os
import requests
import base64
import uuid
import datetime
import hashlib
import shutil
import hmac
import time
from zipfile import ZipFile
import io
from logging.handlers import RotatingFileHandler
 
# Set up variables
APP_ID = "<APPLICATION_ID>"
APP_KEY = "<APPLICATION_KEY>"
ACCESS_KEY = '<ACCESS_KEY>'
SECRET_KEY = '<SECRET_KEY>'
base_url = "<BASE_URL>"
LOG_FILE_PATH = "/var/log/mimecast/log"
CHK_POINT_DIR = '/var/log/mimecast'
URI = "/api/audit/get-siem-logs"
 
# delete files after fetching
delete_files = False
# Set threshold in number of files in log file directory
log_file_threshold = 105

# Set up logging
log = logging.getLogger(__name__)
log.root.setLevel(logging.DEBUG)
log_formatter = logging.Formatter('%(levelname)s %(message)s')
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_formatter)
log.addHandler(log_handler)

# Supporting methods
def rotate_file_if_needed(file_path, max_size_bytes):
    if os.path.exists(file_path):
        file_size = os.path.getsize(file_path)
        if file_size >= max_size_bytes:
            base_dir = os.path.dirname(file_path)
            base_name = os.path.basename(file_path)
            file_name, file_ext = os.path.splitext(base_name)
            new_file_name = f"{file_name}_1{file_ext}"
            new_file_path = os.path.join(base_dir, new_file_name)
            shutil.move(file_path, new_file_path)
            log.info(f"Rotated file: {file_path} -> {new_file_path}")
    else:
        log.warning(f"File not found: {file_path}")

def get_hdr_date():
    return datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S UTC")

def read_file(file_name):
    try:
        with open(file_name, 'r') as f:
            data = f.read()
        return data
    except Exception as e:
        log.error('Error reading file ' + file_name + '. Cannot continue. Exception: ' + str(e))
        quit()

def write_file(file_name, data_to_write):
    if '.zip' in file_name:
        try:
            byte_content = io.BytesIO(data_to_write)
            zip_file = ZipFile(byte_content)
            zip_file.extractall(LOG_FILE_PATH)
        except Exception as e:
            log.error('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))
            quit()
    else:
        try:
            with open(file_name, 'w') as f:
                f.write(data_to_write)
        except Exception as e:
            log.error('Error writing file ' + file_name + '. Cannot continue. Exception: ' + str(e))
            quit()

def post_request(base_url, uri, post_body, access_key, secret_key):
    request_id = str(uuid.uuid4())
    request_date = get_hdr_date()

    unsigned_auth_header = '{date}:{req_id}:{uri}:{app_key}'.format(
        date=request_date,
        req_id=request_id,
        uri=uri,
        app_key=APP_KEY
    )
    hmac_sha1 = hmac.new(
        base64.b64decode(secret_key),
        unsigned_auth_header.encode(),
        digestmod=hashlib.sha1).digest()
    sig = base64.encodebytes(hmac_sha1).rstrip()
    headers = {
        'Authorization': 'MC ' + access_key + ':' + sig.decode(),
        'x-mc-app-id': APP_ID,
        'x-mc-date': request_date,
        'x-mc-req-id': request_id,
        'Content-Type': 'application/json'
    }

    try:
        log.debug('Sending request to ' + base_url + uri + ' with request Id: ' + request_id)
        r = requests.post(url=base_url + uri, data=json.dumps(post_body), headers=headers)

        if r.status_code == 429:
            log.warning('Rate limit hit. Sleeping for ' + str(r.headers['X-RateLimit-Reset'] * 1000))
            time.sleep(r.headers['X-RateLimit-Reset'] * 1000)
            r = requests.post(url=base_url + uri, data=json.dumps(post_body), headers=headers)

    except Exception as e:
        log.error('Unexpected error connecting to API. Exception: ' + str(e))
        return 'error'

    if r.status_code != 200:
        log.error('Request to ' + uri + ' with , request id: ' + request_id + ' returned with status code: ' +
                  str(r.status_code) + ', response body: ' + r.text)
        return 'error'

    return r.content, r.headers

def get_mta_siem_logs(checkpoint_dir, base_url, access_key, secret_key, now):
    uri = "/api/audit/get-siem-logs"
    checkpoint_filename = os.path.join(checkpoint_dir, 'get_mta_siem_logs_checkpoint')
    post_body = dict()
    post_body['data'] = [{}]
    post_body['data'][0]['type'] = 'MTA'
    post_body['data'][0]['compress'] = True
    if os.path.exists(checkpoint_filename):
        post_body['data'][0]['token'] = read_file(checkpoint_filename)

    resp = post_request(base_url, uri, post_body, access_key, secret_key)

    if resp != 'error':
        resp_body = resp[0]
        resp_headers = resp[1]
        content_type = resp_headers['Content-Type']

        if content_type == 'application/json':
            log.info('No more logs available')
            return False
        elif content_type == 'application/octet-stream':
            file_name = resp_headers['Content-Disposition'].split('=\"')
            file_name = file_name[1][:-1]

            write_file(os.path.join(LOG_FILE_PATH, file_name), resp_body)
            write_file(checkpoint_filename, resp_headers['mc-siem-token'])

            return True
        else:
            log.error('Unexpected response')
            for header in resp_headers:
                log.error(header)
            return False

def run_script():
    try:
        log.info('Getting MTA log data')

        # Rotate merged log file if needed before downloading new logs
        rotate_file_if_needed(os.path.join(LOG_FILE_PATH, 'mimecast.log'), 5242880)

        get_mta_siem_logs(checkpoint_dir=CHK_POINT_DIR, base_url=base_url, access_key=ACCESS_KEY,
                          secret_key=SECRET_KEY, now=time.time())
    except Exception as e:
        log.error('Unexpected error getting MTA logs ' + str(e))

    files = [os.path.join(LOG_FILE_PATH, f) for f in os.listdir(LOG_FILE_PATH)]
    files.sort(key=os.path.getctime)

    if delete_files or len(files) >= log_file_threshold:
        num_files_to_delete = len(files) - log_file_threshold
        for i in range(num_files_to_delete):
            try:
                os.unlink(files[i])
            except Exception as e:
                log.error('Failed to delete file {}. Reason: {}'.format(files[i], e))
                continue

    merged_file_path = os.path.join(LOG_FILE_PATH, 'mimecast.log')
    with open(merged_file_path, 'a') as merged_file:
        for filename in os.listdir(LOG_FILE_PATH):
            if filename.endswith('.siem') and filename != 'mimecast.log':
                file_path = os.path.join(LOG_FILE_PATH, filename)
                try:
                    with open(file_path, 'r') as log_file:
                        for line in log_file:
                            merged_file.write(line)
                except Exception as e:
                    log.error('Failed to merge log file {}. Reason: {}'.format(file_path, e))

                os.remove(file_path)

run_script()