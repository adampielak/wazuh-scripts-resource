<!-- Source: https://wazuh.com/blog/integrating-eset-protect-hub-with-wazuh/ | Article: Integrating ESET PROTECT Hub with Wazuh -->
import json
import logging
import os
import time
import tzlocal  # pip install tzlocal
import requests
import yaml
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dateutil.parser import isoparse
from dateutil import parser
from dotenv import load_dotenv

# === Configuration ===

load_dotenv()
USERNAME = os.getenv("USERNAME_INTEGRATION")
PASSWORD = os.getenv("PASSWORD_INTEGRATION")
INSTANCE_REGION = os.getenv("INSTANCE_REGION").lower()
IAM_URL = f"https://{INSTANCE_REGION}.business-account.iam.eset.systems/oauth/token"
API_BASE = f"https://{INSTANCE_REGION}.incident-management.eset.systems"
OUTPUT_FILE = "/var/log/eset_integration.log"
INTERVAL = int(os.getenv("INTERVAL", "3"))  # in minutes
LAST_TIME_FILE = "/opt/eset_integration/last_detection_time.yml"
DATA_SOURCE = "EP"  # Event type key

# === Last Time Handling ===

def load_last_detection_time() -> str:
    try:
        with open(LAST_TIME_FILE, "rb") as f:
            ldt = yaml.safe_load(f)
            if ldt is None:
                ldt = {}
    except FileNotFoundError:
        ldt = {}

    last_time = ldt.get(DATA_SOURCE)
    if not last_time:
        return (
            datetime.now(timezone.utc) - timedelta(minutes=30)
        ).isoformat(timespec='milliseconds').replace("+00:00", "Z")
    return last_time

def save_last_detection_time(new_time: str) -> None:
    try:
        with open(LAST_TIME_FILE, "rb") as f:
            ldt = yaml.safe_load(f)
            if ldt is None:
                ldt = {}
    except FileNotFoundError:
        ldt = {}

    # Parse the UTC time string
    utc_dt = parser.isoparse(new_time)

    # Convert to local system time zone
    local_tz = tzlocal.get_localzone()
    local_dt = utc_dt.astimezone(local_tz)

    # Format back to ISO 8601 with 'Z' removed, because it's no longer UTC
    formatted_local_time = local_dt.isoformat(timespec='milliseconds')

    ldt[DATA_SOURCE] = formatted_local_time
    with open(LAST_TIME_FILE, "w") as f:
        yaml.safe_dump(ldt, f)
# === Main Logic ===

def fetch_and_save_detections():
    try:
        # 1. Get Access Token
        token_data = {
            "grant_type": "password",
            "username": USERNAME,
            "password": PASSWORD,
            "refresh_token": ""
        }
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        logging.info("Requesting access token...")
        response = requests.post(IAM_URL, data=token_data, headers=headers)
        response.raise_for_status()
        access_token = response.json().get("access_token")
        if not access_token:
            raise Exception("Failed to obtain access token")

        # 2. Fetch Detections
        start_time = load_last_detection_time()
        api_headers = {"Authorization": f"Bearer {access_token}"}
        detections_url = f"{API_BASE}/v1/detections"
        params = {"startTime": start_time}
        logging.info(f"Fetching detections from {start_time}...")

        detections_resp = requests.get(detections_url, headers=api_headers, params=params)

        if detections_resp.status_code != 200:
            logging.error(f"API response: {detections_resp.status_code} - {detections_resp.text}")
        detections_resp.raise_for_status()

        detections = detections_resp.json().get("detections", [])
        if not detections:
            logging.info("No new detections found.")
            return

        # 3. Save each detection to the log file
        with open(OUTPUT_FILE, "a") as f:
            for detection in detections:
                detection["providerName"] = "ESET"
                wrapped = {"eset": detection}
                f.write(json.dumps(wrapped) + "\n")

        logging.info(f"{len(detections)} detections saved.")

        # 4. Update last detection time
        detect_times = [isoparse(d["occurTime"]) for d in detections if d.get("occurTime")]
        if detect_times:
            newest_time = (max(detect_times) + timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
            save_last_detection_time(newest_time)
            logging.info(f"Updated last detection time to {newest_time}.")
        else:
            logging.warning("No valid occurTime found in detections.")

    except Exception as e:
        logging.error(f"Error: {e}", exc_info=True)


# === Runner ===

def main_loop():
    logging.basicConfig(
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    logging.info("Starting ESET event fetcher.")
    while True:
        fetch_and_save_detections()
        time.sleep(INTERVAL * 60)

if __name__ == "__main__":
    main_loop()