<!-- Source: https://wazuh.com/blog/monitoring-mongodb-atlas-with-wazuh/ | Article: Monitoring MongoDB Atlas with Wazuh -->
#!/usr/bin/env python3

import base64
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import os

import requests
from dotenv import load_dotenv


# LOAD ENV
load_dotenv()

# CONFIG
ATLAS_BASE_URL = "https://cloud.mongodb.com/api/atlas/v2"
OAUTH_TOKEN_URL = "https://cloud.mongodb.com/api/oauth/token"

ORG_ID = os.getenv("MONGODB_ATLAS_ORG_ID")

CLIENT_ID = os.getenv("MONGODB_ATLAS_CLIENT_ID")
CLIENT_SECRET = os.getenv("MONGODB_ATLAS_CLIENT_SECRET")

OUTPUT_FILE = Path("/var/log/mongodb_atlas/atlas_events.json")

PAGE_SIZE = 500

# VALIDATION
required = {
    "MONGODB_ATLAS_ORG_ID": ORG_ID,
    "MONGODB_ATLAS_CLIENT_ID": CLIENT_ID,
    "MONGODB_ATLAS_CLIENT_SECRET": CLIENT_SECRET,
}

missing = [k for k, v in required.items() if not v]

if missing:
    raise ValueError(
        f"Missing environment variables: {', '.join(missing)}"
    )


# OAUTH TOKEN MANAGER
class OAuthTokenManager:
    def __init__(self, client_id, client_secret):
        self.client_id = client_id
        self.client_secret = client_secret

        self.access_token = None
        self.expires_at = 0

    def get_access_token(self):
        now = time.time()

        # Reuse token until close to expiry
        if self.access_token and now < (self.expires_at - 60):
            return self.access_token

        print("Refreshing OAuth token...")

        credentials = f"{self.client_id}:{self.client_secret}"

        base64_auth = base64.b64encode(
            credentials.encode()
        ).decode()

        response = requests.post(
            OAUTH_TOKEN_URL,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-cache",
                "Authorization": f"Basic {base64_auth}",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            data="grant_type=client_credentials",
            timeout=30,
        )

        if response.status_code != 200:
            raise Exception(
                f"OAuth token request failed "
                f"{response.status_code}: {response.text}"
            )

        data = response.json()

        self.access_token = data["access_token"]

        expires_in = data.get("expires_in", 3600)

        self.expires_at = now + expires_in

        return self.access_token


token_manager = OAuthTokenManager(
    CLIENT_ID,
    CLIENT_SECRET,
)

# CHECKPOINT HANDLING
def load_checkpoint(checkpoint_file):
    if not checkpoint_file.exists():
        return {
            "last_created": "1970-01-01T00:00:00Z",
            "last_event_id": None,
        }

    with open(checkpoint_file, "r") as f:
        return json.load(f)


def save_checkpoint(checkpoint_file, created, event_id):
    checkpoint_file.parent.mkdir(parents=True, exist_ok=True)

    checkpoint = {
        "last_created": created,
        "last_event_id": event_id,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    with open(checkpoint_file, "w") as f:
        json.dump(checkpoint, f, indent=2)

# API REQUEST
def atlas_get(url, params=None):
    token = token_manager.get_access_token()

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.atlas.2025-02-19+json",
    }

    response = requests.get(
        url,
        headers=headers,
        params=params,
        timeout=60,
    )

    # Retry once if token expired unexpectedly
    if response.status_code == 401:
        print("Token expired unexpectedly. Refreshing and retrying...")

        token_manager.access_token = None

        token = token_manager.get_access_token()

        headers["Authorization"] = f"Bearer {token}"

        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=60,
        )

    if response.status_code != 200:
        raise Exception(
            f"Atlas API Error {response.status_code}: {response.text}"
        )

    return response.json()


# FETCH ALL PROJECTS
def get_all_projects():
    url = f"{ATLAS_BASE_URL}/groups"

    projects = []
    page_num = 1

    while True:
        params = {
            "itemsPerPage": PAGE_SIZE,
            "pageNum": page_num,
        }

        data = atlas_get(url, params=params)

        results = data.get("results", [])

        if not results:
            break

        projects.extend(results)

        if len(results) < PAGE_SIZE:
            break

        page_num += 1

    return projects


# FETCH EVENTS FOR A SCOPE
def fetch_events_for_scope(scope_name, url, checkpoint_file):
    checkpoint = load_checkpoint(checkpoint_file)

    last_created = checkpoint["last_created"]
    last_event_id = checkpoint["last_event_id"]

    total_written = 0
    page_num = 1

    newest_created = last_created
    newest_event_id = last_event_id

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "a", encoding="utf-8") as out_f:

        while True:
            params = {
                "itemsPerPage": PAGE_SIZE,
                "pageNum": page_num,
                "includeCount": "false",
                "minDate": last_created,
            }

            data = atlas_get(url, params=params)

            results = data.get("results", [])

            if not results:
                break

            # Stable ordering
            results.sort(
                key=lambda x: (
                    x.get("created", ""),
                    x.get("id", ""),
                )
            )

            wrote_new_data = False

            for event in results:
                event_created = event.get("created")
                event_id = event.get("id")

                # Skip already processed event
                if (
                    event_created < last_created
                    or (
                        event_created == last_created
                        and event_id == last_event_id
                    )
                ):
                    continue

                enriched_event = {
                    "scope": scope_name,
                    **event,
                }

                out_f.write(
                    json.dumps(
                        enriched_event,
                        ensure_ascii=False,
                    ) + "\n"
                )

                newest_created = event_created
                newest_event_id = event_id

                total_written += 1
                wrote_new_data = True

            out_f.flush()

            if wrote_new_data:
                save_checkpoint(
                    checkpoint_file,
                    newest_created,
                    newest_event_id,
                )

            # Last page
            if len(results) < PAGE_SIZE:
                break

            page_num += 1

            time.sleep(0.25)

    print(f"{scope_name}: downloaded {total_written} new events")


# MAIN ENTRYPOINT
def fetch_events():

    print("Starting MongoDB Atlas event collection...")

    # ORG EVENTS
    
    org_url = f"{ATLAS_BASE_URL}/orgs/{ORG_ID}/events"

    fetch_events_for_scope(
        scope_name=f"org:{ORG_ID}",
        url=org_url,
        checkpoint_file=Path("/etc/mongodb_atlas/state/org_checkpoint.json"),
    )

    # PROJECT EVENTS

    projects = get_all_projects()

    print(f"Found {len(projects)} projects")

    for project in projects:
        group_id = project["id"]
        project_name = project.get("name", group_id)

        print(f"Fetching project events: {project_name}")

        project_url = (
            f"{ATLAS_BASE_URL}/groups/{group_id}/events"
        )

        checkpoint_file = Path(
            f"/etc/mongodb_atlas/state/project_{group_id}_checkpoint.json"
        )

        fetch_events_for_scope(
            scope_name=f"project:{project_name}",
            url=project_url,
            checkpoint_file=checkpoint_file,
        )

    print("Finished fetching all events.")

if __name__ == "__main__":
    fetch_events()