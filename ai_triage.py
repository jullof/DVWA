#!/usr/bin/env python3
# ai_triage.py (Gemini-only, stronger prompt, English only)

import os, sys, json, time, hashlib, urllib.request, urllib.error, re
from collections import defaultdict

REPORT_DIR = os.environ.get("REPORT_DIR", "reports")
IN_PATH    = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_PATH   = os.path.join(REPORT_DIR, "ai_findings.json")
BODIES_OUT = os.path.join(REPORT_DIR, "ai_bodies.json")

# Gemini config
GEMINI_API_KEY = (os.environ.get("GEMINI_API_KEY") or "").strip()
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash").strip()
GEMINI_BASE    = os.environ.get("GEMINI_BASE", "https://generativelanguage.googleapis.com/v1beta/models").strip()

# AI knobs
AI_ONLY_SEVERITIES = set([s.strip().lower() for s in (os.environ.get("AI_ONLY_SEVERITIES","low,medium,high,critical").split(",")) if s.strip()])
AI_MAX_FINDINGS    = int(os.environ.get("AI_MAX_FINDINGS","150"))
AI_BATCH_SIZE      = int(os.environ.get("AI_BATCH_SIZE","25"))
AI_SLEEP_BETWEEN   = float(os.environ.get("AI_SLEEP_BETWEEN","1.0"))

CTRL_CHARS_RGX = re.compile(r'[\x00-\x1f\x7f]')

def clean_text(s: str) -> str:
    if not isinstance(s, str):
        s = str(s or "")
    s = CTRL_CHARS_RGX.sub(' ', s).strip()
    if s.startswith("```"):
        s = s.strip("`")
        if s.startswith("json"):
            s = s[4:].lstrip()
    return s.strip()

def extract_json_block(s: str) -> str:
    s = clean_text(s)
    start, end = s.find('{'), s.rfind('}')
    if start != -1 and end != -1 and end > start:
        return s[start:end+1]
    return s

def safe_json_loads(s: str):
    s = extract_json_block(s)
    try:
        return json.loads(s)
    except Exception:
        return {}

def _lower(s): return (s or "").lower()
def digest(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update((_lower(str(p))).encode("utf-8","ignore"))
    return h.hexdigest()[:12]

# Plugin classification maps
PLUGIN_XSS   = {"40012","40014","40016","40017","40026"}
PLUGIN_SQLI  = {"40018","40019","40020","40021","40022","40024","40027"}
PLUGIN_RCE   = {"90020","20018"}
PLUGIN_CSP   = {"10038"}
PLUGIN_INFO  = {"90022","10095","10099"}
PLUGIN_XSLT  = {"90017"}
PLUGIN_OPENR = {"30006"}

def classify(name, pluginId, cwe):
    n = _lower(name); p = str(pluginId or "")
    if ("xss" in n or "cross site scripting" in n) or p in PLUGIN_XSS: return "xss"
    if "sql injection" in n or p in PLUGIN_SQLI: return "sqli"
    if any(k in n for k in ["remote code execution","os command","command injection","code injection"]) or p in PLUGIN_RCE: return "rce"
    if "content security policy" in n or "csp" in n or p in PLUGIN_CSP: return "csp"
    if "open redirect" in n or p in PLUGIN_OPENR: return "open_redirect"
    if "directory listing" in n or "index of /" in n: return "dir_listing"
    if "authorization" in n or "access control" in n or "privilege" in n: return "authz"
    if "xslt" in n or p in PLUGIN_XSLT: return "xslt_injection"
    if "leak" in n or "disclosure" in n or p in PLUGIN_INFO: return "info_leak"
    return "other"

def norm_sev(s):
    s = _lower(s)
    if s in ("0","info","informational"): return "info"
    if s in ("1","low"): return "low"
    if s in ("2","medium","moderate"): return "medium"
    if s in ("3","high"): return "high"
    if s in ("4","critical","urgent"): return "critical"
    return "unknown"

# ---------- Load raw ----------
try:
    with open(IN_PATH,"r",encoding="utf-8") as fh:
        raw = json.load(fh)
except FileNotFoundError:
    print(f"[AI] skipped: {IN_PATH} not found.")
    sys.exit(0)

items = raw["findings"] if isinstance(raw, dict) and "findings" in raw else (raw if isinstance(raw, list) else [])

# ---------- Normalize ----------
norm = []
for it in items:
    f = dict(it or {})
    loc  = f.get("location") or {}
    src  = f.get("source") or f.get("scanner") or "unknown"
    sev  = norm_sev(f.get("severity") or f.get("risk") or "")
    url  = clean_text(f.get("url") or f.get("target") or loc.get("url") or "")
    name = clean_text(f.get("name") or f.get("title") or f.get("rule") or "Finding")
    plug = f.get("pluginId") or f.get("id") or ""
    param= clean_text(f.get("param") or loc.get("param") or "")
    cwe  = f.get("cwe") or ""
    ev   = clean_text(f.get("evidence") or "")
    klass= classify(name, plug, cwe)
    fid  = f.get("id") or f"{src}-{plug}-{digest(url,name,param or ev)}"
    norm.append({
        "id": fid, "source": src, "severity": sev, "title": name,
        "url": url, "param": param, "pluginId": str(plug), "cwe": str(cwe),
        "evidence": ev, "class": klass
    })

# Dedup
seen, dedup = set(), []
for f in norm:
    if f["id"] in seen: continue
    seen.add(f["id"]); dedup.append(f)

# Throttle
if AI_ONLY_SEVERITIES:
    dedup = [x for x in dedup if x.get("severity","").lower() in AI_ONLY_SEVERITIES]
if AI_MAX_FINDINGS and len(dedup) > AI_MAX_FINDINGS:
    dedup = dedup[:AI_MAX_FINDINGS]

# ---------- Gemini call ----------
def call_gemini(batch):
    payload_items = []
    for x in batch:
        desc = {
            "id": x["id"], "title": x["title"], "severity": x["severity"],
            "url": x.get("url",""), "param": x.get("param",""),
            "pluginId": x.get("pluginId",""), "cwe": x.get("cwe",""),
            "evidence": x.get("evidence",""), "class": x.get("class","other")
        }
        payload_items.append(desc)

    sys_prompt = (
        "You are a senior security triage assistant. "
        "For each finding id, respond ONLY with a valid JSON object. "
        "Keys per id: "
        "ai_priority (P0-P4), ai_suspected_fp (true/false), "
        "why_opened (<=2 sentences, clear risk statement), "
        "remediation (4-6 numbered, detailed technical steps, actionable), "
        "references (array of 2-3 authoritative URLs like OWASP, CWE, NIST). "
        "Language: English only. "
        "Be specific (e.g., for CSP header missing → recommend concrete headers; for SQLi → parameterized queries). "
        "Return strictly JSON, no extra text."
    )

    user_payload = json.dumps({"findings": payload_items}, ensure_ascii=False)

    url = f"{GEMINI_BASE}/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    body = {
        "contents": [
            {"role":"user","parts":[{"text": sys_prompt + "\n\n" + user_payload}]}
        ],
        "generationConfig": {"temperature":0.0,"maxOutputTokens":1500,"responseMimeType":"application/json"}
    }
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 method="POST", headers={"Content-Type":"application/json"})

    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read().decode("utf-8"))
        text = (data.get("candidates",[{}])[0].get("content",{}).get("parts",[{}])[0].get("text",""))
        return safe_json_loads(text)
    except Exception as e:
        print(f"[AI] Gemini call error: {e}")
        return {}

# ---------- Short-circuit ----------
if not GEMINI_API_KEY:
    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(OUT_PATH,"w",encoding="utf-8") as fh: json.dump(dedup, fh, indent=2)
    with open(BODIES_OUT,"w",encoding="utf-8") as fh: json.dump({}, fh)
    print("[AI] skipped: no key.")
    sys.exit(0)

# ---------- Run batches ----------
ai_results = {}
for i in range(0, len(dedup), AI_BATCH_SIZE):
    batch = dedup[i:i+AI_BATCH_SIZE]
    res = call_gemini(batch)
    if isinstance(res, dict): ai_results.update(res)
    time.sleep(AI_SLEEP_BETWEEN)

# ---------- Merge ----------
def default_refs(): return [
    "https://owasp.org/www-project-top-ten/",
    "https://cwe.mitre.org/"
]

enriched = []
for f in dedup:
    aid = f["id"]
    ai  = ai_results.get(aid, {}) or {}
    enriched.append({
        **f,
        "ai_priority": ai.get("ai_priority","P3"),
        "ai_suspected_fp": bool(ai.get("ai_suspected_fp", False)),
        "why_opened": ai.get("why_opened","Manual review recommended."),
        "remediation": ai.get("remediation","1) Review and validate 2) Apply fix 3) Retest 4) Deploy"),
        "references": ai.get("references") or default_refs(),
        "provenance": {"pluginId": f.get("pluginId"), "urls": [f.get("url")]}
    })

groups = defaultdict(list)
for f in enriched: groups[f["class"]].append(f)

# ---------- Write ----------
os.makedirs(REPORT_DIR, exist_ok=True)
with open(OUT_PATH,"w",encoding="utf-8") as fh: json.dump(enriched, fh, indent=2)
with open(BODIES_OUT,"w",encoding="utf-8") as fh: json.dump({k:{"count":len(v)} for k,v in groups.items()}, fh)

print(f"[AI] refined -> {OUT_PATH}; total={len(enriched)}")
print(f"[AI] class groups -> {BODIES_OUT}; keys={list(groups.keys())}")
