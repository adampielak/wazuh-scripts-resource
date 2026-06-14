<!-- Source: https://wazuh.com/blog/detecting-compromised-accounts-with-hibp-and-wazuh/ | Article: Detecting compromised accounts with HIBP and Wazuh -->
import requests
import time
import json
import os
from datetime import datetime, timedelta

# Configuration
API_KEY = "<YOUR_HIBP_API_KEY>"  # Replace with your HIBP API key
EMAIL_LIST_FILE = "/home/wazuh-user/email_list.txt"  # File containing email addresses (one per line)
OUTPUT_LOG_FILE = "/var/log/hibp_breach_checks.log"  # Log file path
CACHE_FILE = "hibp_cache.json"  # To store recently checked emails and avoid redundant checks
BREACH_DETAILS_CACHE_FILE = "breach_details_cache.json"  # Cache for breach descriptions
RATE_LIMIT_DELAY = 60  # Seconds to wait between API calls to respect rate limits
CACHE_EXPIRATION_DAYS = 6  # How long to consider cached results valid

# Ensure the output log file directory exists
os.makedirs(os.path.dirname(OUTPUT_LOG_FILE), exist_ok=True)

# Load cache (if exists and valid)
if os.path.exists(CACHE_FILE):
    try:
        with open(CACHE_FILE, "r") as f:
            cache = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print("Cache file is empty or corrupted. Initializing empty cache.")
        cache = {}
else:
    cache = {}

# Load breach details cache (if exists and valid)
if os.path.exists(BREACH_DETAILS_CACHE_FILE):
    try:
        with open(BREACH_DETAILS_CACHE_FILE, "r") as f:
            breach_details_cache = json.load(f)
    except (json.JSONDecodeError, ValueError):
        print("Breach details cache file is empty or corrupted. Initializing empty cache.")
        breach_details_cache = {}
else:
    breach_details_cache = {}

def save_cache():
    """Save the email check cache to a file."""
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f)

def save_breach_details_cache():
    """Save the breach details cache to a file."""
    with open(BREACH_DETAILS_CACHE_FILE, "w") as f:
        json.dump(breach_details_cache, f)

def is_recently_checked(email):
    """Check if an email has been checked recently."""
    if email in cache:
        last_checked = datetime.strptime(cache[email]["last_checked"], "%Y-%m-%dT%H:%M:%S")
        if datetime.now() - last_checked < timedelta(days=CACHE_EXPIRATION_DAYS):
            return True
    return False

def get_breach_details(breach_name):
    """Fetch detailed information about a breach, using cache if available."""
    if breach_name in breach_details_cache:
        return breach_details_cache[breach_name]

    url = f"https://haveibeenpwned.com/api/v3/breach/{breach_name}"
    headers = {"hibp-api-key": API_KEY, "User-Agent": "HIBP-Wazuh-Integration"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        breach_data = response.json()
        description = breach_data.get("Description", "No description available")
        breach_details_cache[breach_name] = description
        save_breach_details_cache()
        return description
    else:
        return "No description available"

def log_breach_info(email, breach, description):
    """Log each breach separately with its description to a file."""
    log_entry = {
        "email": email,
        "breaches": {breach: description},
        "last_checked": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "Source": "hibpwned"
    }
    with open(OUTPUT_LOG_FILE, "a") as log_file:
        log_file.write(json.dumps(log_entry) + "\n")

def check_email_breaches(email):
    """Check if an email has been breached using the HIBP API."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"hibp-api-key": API_KEY, "User-Agent": "HIBP-Wazuh-Integration"}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        breaches = response.json()
        breach_names = [breach['Name'] for breach in breaches]  # Extract breach names
        cache[email] = {"breaches": breach_names, "last_checked": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}

        for breach in breach_names:
            description = get_breach_details(breach)
            log_breach_info(email, breach, description)

        print(f"{email} found in breaches: {breach_names}")
    elif response.status_code == 404:
        print(f"{email} not found in any breaches.")
        cache[email] = {"breaches": [], "last_checked": datetime.now().strftime("%Y-%m-%dT%H:%M:%S")}
    else:
        print(f"Error checking {email}: {response.status_code} - {response.text}")

def main():
    """Main function to read emails and check breaches."""
    with open(EMAIL_LIST_FILE, "r") as f:
        emails = [line.strip() for line in f.readlines()]

    for email in emails:
        if is_recently_checked(email):
            print(f"Skipping recently checked email: {email}")
            continue

        check_email_breaches(email)
        save_cache()
        time.sleep(RATE_LIMIT_DELAY)

if __name__ == "__main__":
    main()