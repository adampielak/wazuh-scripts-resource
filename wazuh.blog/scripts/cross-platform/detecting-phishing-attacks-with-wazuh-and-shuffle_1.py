<!-- Source: https://wazuh.com/blog/detecting-phishing-attacks-with-wazuh-and-shuffle/ | Article: Detecting phishing attacks with Wazuh and Shuffle -->
#!/usr/bin/env python3
import json, sys, time, requests, urllib3
from base64 import b64encode

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

NODE1   = r"""$get_ioc.message"""
HOST    = "<WAZUH_IP_ADDRESS>"
PORT    = 55000
USER    = "<WAZUH_API_USERNAME>"
PASSWD  = "<WAZUH_API_PASSWORD>"
BASE    = f"https://{HOST}:{PORT}"
BATCH   = 100
RETRIES = 3

# ── Debug flag ──────────────────────────────────────────────────────────────
DEBUG_LOG = []  
DEBUG = False #Set to True if necessary

def debug_log(label, payload):
    if not DEBUG:
        return
    if isinstance(payload, str):
        try:
            entry = {"label": label, "data": json.loads(payload)}
        except:
            entry = {"label": label, "data": payload}
    elif isinstance(payload, list):
        parsed = []
        for item in payload:
            try:
                parsed.append(json.loads(item) if isinstance(item, str) else item)
            except:
                parsed.append(str(item))
        entry = {"label": label, "data": parsed}
    else:
        entry = {"label": label, "data": payload}
    DEBUG_LOG.append(entry)

def auth():
    r = requests.post(f"{BASE}/security/user/authenticate",
        headers={"Authorization":f"Basic {b64encode(f'{USER}:{PASSWD}'.encode()).decode()}"},
        verify=False, timeout=15)
    r.raise_for_status()
    t = r.json().get("data",{}).get("token")
    if not t: sys.exit("Wazuh auth: no token")
    return t

def parse(raw):
    if isinstance(raw, list): return raw
    if isinstance(raw, dict): return [raw]
    if isinstance(raw, str) and raw.strip() and not raw.strip().startswith("$"):
        try:
            p = json.loads(raw)
            return p if isinstance(p,list) else [p]
        except: pass
    return []

def build(emails):
    events = []
    for e in emails:
        if not isinstance(e,dict): continue
        base = {k:e.get(k) for k in ["message_id","subject","body_preview","received_datetime",
            "sent_datetime","is_read","parent_folder_id","sender_email","sender_name",
            "recipient_emails","attachment_count"]}
        base["integration"] = "shuffle-office365"
        base["attachment_count"] = len(e.get("attachments",[]))
        for ioc in (e.get("iocs") or []):
            if not isinstance(ioc,dict): continue
            d, t = (ioc.get("data") or "").strip(), ioc.get("data_type")
            if not d or not t: continue
            if t == "email":
                continue
            ev = {**base,"data":d,"data_type":t}
            if t == "md5":
                ev["file_name"] = ioc.get("file_name")
                ev["file_size"] = ioc.get("file_size")
                ev["file_type"] = ioc.get("file_type")
            events.append(json.dumps(ev, separators=(",",":"), default=str))
    debug_log(f"Built {len(events)} event(s) from {len(emails)} email(s)", events)
    return events

def send(events, token):
    hdrs = {"Content-Type":"application/json","Authorization":f"Bearer {token}"}
    sent = failed = 0
    for i in range(0, len(events), BATCH):
        batch = events[i:i+BATCH]
        batch_num = i // BATCH + 1
        ok = False
                # ── Log the exact payload being sent ──────────────────────────────
        debug_log(f"Sending batch {batch_num} ({len(batch)} events)", {"events": batch})
        for attempt in range(1, RETRIES+1):
            try:
                r = requests.post(f"{BASE}/events", headers=hdrs,
                    data=json.dumps({"events":batch}), verify=False, timeout=30)
                # ── Log the response ───────────────────────────────────────
                debug_log(f"Batch {batch_num} response (attempt {attempt})", {
                    "status_code": r.status_code,
                    "response_body": r.text[:500]  # cap at 500 chars
                })
                if r.status_code == 401:
                    token = auth(); hdrs["Authorization"] = f"Bearer {token}"; continue
                r.raise_for_status(); sent += len(batch); ok = True; break
            except Exception as e:
                if attempt < RETRIES: time.sleep(2**attempt)
        if not ok: failed += len(batch)
    result = {"sent":sent,"failed":failed,"total":len(events)}
    if DEBUG:
        result["debug"] = DEBUG_LOG
    print(json.dumps(result))

def main():
    emails = parse(NODE1)
    if not emails: print(json.dumps({"status":"no_input"})); return
    events = build(emails)
    if not events: print(json.dumps({"status":"no_events"})); return
    send(events, auth())

main()