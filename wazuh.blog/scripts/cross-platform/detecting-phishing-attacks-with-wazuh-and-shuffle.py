<!-- Source: https://wazuh.com/blog/detecting-phishing-attacks-with-wazuh-and-shuffle/ | Article: Detecting phishing attacks with Wazuh and Shuffle -->
import json, re, base64, hashlib, html
from urllib.parse import urlparse

nodevalue         = r"""$get_emails.body"""
attachments_value = r"""$get_attachments.body"""
whitelist_raw     = r"""$shuffle_cache.ds_whitelist.value"""
sender_skip_raw   = r"""$shuffle_cache.ds_skip.value"""

SCANNED = "Shuffle-Scanned"

def load_list(raw):
    if isinstance(raw, list): return raw
    if isinstance(raw, str) and raw.strip() and not raw.strip().startswith("$"):
        try:
            p = json.loads(raw.strip())
            if isinstance(p, list): return p
        except: pass
    return []

WL   = load_list(whitelist_raw)
SKIP = load_list(sender_skip_raw)

PRIVATE = ("10.","192.168.","127.","0.","255.","169.254.","172.16.","172.17.",
    "172.18.","172.19.","172.20.","172.21.","172.22.","172.23.","172.24.",
    "172.25.","172.26.","172.27.","172.28.","172.29.","172.30.","172.31.")

def is_wl(d):
    d = d.lower().rstrip(".")
    return any(d == w or d.endswith("."+w) for w in WL)

def is_priv(ip): return any(ip.startswith(p) for p in PRIVATE)

def parse(raw):
    if isinstance(raw, (dict,list)): return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s or s.startswith("$"): return None
        try: return json.loads(s)
        except: return None

def get_email(raw):
    d = parse(raw)
    if d is None: return None
    if isinstance(d, dict):
        if "id" in d: return d
        if "value" in d and d["value"]: return d["value"][0]
        if "body" in d: return get_email(d["body"])
    if isinstance(d, list) and d: return d[0] if isinstance(d[0],dict) else None

def get_attachments(raw):
    d = parse(raw)
    if d is None: return []
    if isinstance(d, list):
        for item in d:
            if isinstance(item, dict) and item.get("status") == 200:
                body = item.get("body", {})
                if isinstance(body, str):
                    try: body = json.loads(body)
                    except: continue
                if isinstance(body, dict) and "value" in body:
                    return [a for a in body["value"] if isinstance(a, dict)]
        return []
    if isinstance(d, dict):
        if "status" in d and "body" in d:
            body = d["body"]
            if isinstance(body, dict) and "value" in body:
                return [a for a in body["value"] if isinstance(a, dict)]
        if "value" in d: return [a for a in d["value"] if isinstance(a, dict)]
        if "id" in d: return [d]
    return []

def md5s(atts):
    out = []
    for a in atts:
        b = a.get("contentBytes")
        if not b: continue
        try:
            dec = base64.b64decode(b)
            out.append({"name":a.get("name"),"md5":hashlib.md5(dec).hexdigest(),
                        "size":a.get("size"),"content_type":a.get("contentType")})
        except: pass
    return out

RE_SRC  = re.compile(r'originalsrc=["\']([^"\'>\s]+)["\']', re.I)
RE_TAG  = re.compile(r"<[^>]+>", re.I)
RE_WS   = re.compile(r"[ \t]+")
RE_URL  = re.compile(r"https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", re.I)
RE_IP   = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b")
RE_MAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
RE_DOM  = re.compile(r"(?<![a-zA-Z0-9\-_@/])(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,10}(?![a-zA-Z0-9\-_])")
RE_256  = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_MD5  = re.compile(r"\b[a-fA-F0-9]{32}\b")

def src(h): return list(set(html.unescape(m.group(1)) for m in RE_SRC.finditer(h) if not m.group(1).startswith("$")))
def clean(h): return RE_WS.sub(" ", html.unescape(RE_TAG.sub(" ", h))).strip()
def refang(t):
    t = re.sub(r"\[\.?\]|\(\.\)",".",t); t = re.sub(r"\[:\]|\(:\)",":",t)
    t = re.sub(r"\bhxxps?\b",lambda m:m.group().replace("xx","tt"),t,flags=re.I)
    t = re.sub(r"(https?://)\s+",r"\1",t,flags=re.I)
    t = re.sub(r"\[at\]|\(at\)","@",t,flags=re.I)
    t = re.sub(r"\[dot\]|\(dot\)",".",t,flags=re.I)
    return t

def extract(text, pre):
    seen, iocs, hosts = set(), [], set()
    def add(v, t, extra=None):
        v = v.strip().rstrip(".,;:")
        k = (v.lower(), t)
        if v and k not in seen:
            seen.add(k); e = {"data":v,"data_type":t}
            if extra: e.update(extra)
            iocs.append(e)
    for u in pre:
        u = u.rstrip(".,;:'\")>]}")
        try:
            h = urlparse(u).hostname or ""
            if h and not is_wl(h) and not is_priv(h): add(u,"url"); hosts.add(h.lower())
        except: pass
    for m in RE_URL.finditer(text):
        u = m.group().rstrip(".,;:'\")>]}")
        try:
            h = urlparse(u).hostname or ""
            if h and not is_wl(h) and not is_priv(h): add(u,"url"); hosts.add(h.lower())
        except: pass
    for m in RE_IP.finditer(text):
        if not is_priv(m.group()): add(m.group(),"ip")
    for m in RE_MAIL.finditer(text): add(m.group().lower(),"email")
    for m in RE_DOM.finditer(text):
        d = m.group().lower().rstrip(".")
        if "." not in d or d[0].isdigit() or is_wl(d): continue
        if not any(d.endswith("."+h) for h in hosts): add(d,"domain")
    used = set()
    for m in RE_256.finditer(text): add(m.group().lower(),"sha256"); used.update(range(m.start(),m.end()))
    for m in RE_SHA1.finditer(text):
        if not set(range(m.start(),m.end()))&used: add(m.group().lower(),"sha1"); used.update(range(m.start(),m.end()))
    for m in RE_MD5.finditer(text):
        if not set(range(m.start(),m.end()))&used: add(m.group().lower(),"md5")
    return iocs

def main():
    email = get_email(nodevalue)
    if not email: print(json.dumps({"error":"parse_failed"})); return
    mid  = email.get("id","")
    subj = email.get("subject","") or ""
    rcpts = [r.get("emailAddress",{}).get("address") for r in (email.get("toRecipients") or []) if isinstance(r,dict)]
   
    if SCANNED in email.get("categories",[]): print(json.dumps({"skipped":"already_scanned"})); return
    sobj    = email.get("sender",{}).get("emailAddress",{})
    saddr   = (sobj.get("address") or "").lower()
    sdomain = saddr.split("@")[-1] if "@" in saddr else ""
    if sdomain in SKIP: print(json.dumps({"skipped":"system_sender","message_id":mid,"recipient_emails":rcpts})); return
    body  = email.get("body",{})
    braw  = body.get("content","") or ""
    btype = (body.get("contentType","text") or "text").lower()
    pre   = src(braw) if btype=="html" else []
    btext = clean(braw) if btype=="html" else braw
    iocs  = extract(refang(subj+"\n"+btext), pre)
    if saddr and not any(i["data"]==saddr and i["data_type"]=="email" for i in iocs):
        iocs.insert(0,{"data":saddr,"data_type":"email","role":"sender"})
    atts = get_attachments(attachments_value)
    m5s  = md5s(atts)
    for a in m5s:
        if a.get("md5"):
            iocs.append({"data":a["md5"],"data_type":"md5","file_name":a.get("name"),
                         "file_size":a.get("size"),"file_type":a.get("content_type")})
    if not iocs: print(json.dumps({"skipped":"no_iocs","message_id":mid,"recipient_emails":rcpts})); return
    summ  = {t+"s":len([i for i in iocs if i["data_type"]==t]) for t in ["url","domain","ip","email","md5","sha1","sha256"]}
    print(json.dumps({
        "message_id":mid,"subject":subj,"body_preview":email.get("bodyPreview"),
        "received_datetime":email.get("receivedDateTime"),"sent_datetime":email.get("sentDateTime"),
        "is_read":email.get("isRead"),"parent_folder_id":email.get("parentFolderId"),
        "sender_email":saddr,"sender_name":sobj.get("name"),"recipient_emails":rcpts,
        "iocs":iocs,"attachments":m5s,"existing_categories":email.get("categories",[]),
        "ioc_count":len(iocs),"ioc_summary":summ
    }, default=str))

main()