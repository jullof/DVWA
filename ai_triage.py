#!/usr/bin/env python3
# ai_triage.py (hardened)
# - Robustly groups findings into XSS / SQLi / RCE / Other
# - Always writes non-empty ai_bodies.json (so 'Create issues' stage has content)
# - Optional AI FP triage with safe fallback (env OPENAI_API_KEY optional)
# - Adds 'class' and 'fp_suspect' fields to ai_findings.json

import os, json, re, hashlib, time, urllib.request
from collections import defaultdict, Counter

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
IN_PATH    = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_PATH   = os.path.join(REPORT_DIR, "ai_findings.json")
BODIES_OUT = os.path.join(REPORT_DIR, "ai_bodies.json")

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY","").strip()
OPENAI_MODEL   = os.environ.get("OPENAI_MODEL","gpt-4o-mini")
OPENAI_BASE    = os.environ.get("OPENAI_BASE","https://api.openai.com/v1/chat/completions")

def _lower(s): 
    return (s or "").lower()

def classify(f):
    """Heuristic mapping to classes."""
    name = _lower(f.get("name") or f.get("title"))
    plugin = str(f.get("pluginId", ""))
    cwe = str(f.get("cwe", ""))
    # XSS
    if any(k in name for k in ["cross site scripting", "xss"]) or plugin in {"40012","40014","40016","40017","40026"}:
        return "xss"
    # SQLi
    if "sql injection" in name or any(p in plugin for p in ["40018","40019","40020","40021","40022","40024","40027"]):
        return "sqli"
    # RCE / Command injection
    if any(k in name for k in ["remote code execution","os command","command injection","code injection"]) or plugin in {"90020","20018"}:
        return "rce"
    return "other"

def normalize_severity(s):
    s = _lower(s)
    if s in ("0","info","informational"): return "info"
    if s in ("1","low"): return "low"
    if s in ("2","medium","moderate"): return "medium"
    if s in ("3","high"): return "high"
    if s in ("4","critical","very high","urgent"): return "critical"
    return "unknown"

def digest(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update((_lower(str(p))).encode("utf-8", "ignore"))
    return h.hexdigest()[:12]

# --- Load raw findings ---
with open(IN_PATH,"r",encoding="utf-8") as fh:
    raw = json.load(fh)

# Accept either list or dict with 'findings'
if isinstance(raw, dict) and "findings" in raw:
    items = raw["findings"]
elif isinstance(raw, list):
    items = raw
else:
    items = []

# Ensure dict structure
norm = []
for it in items:
    f = dict(it or {})
    src = f.get("source") or f.get("scanner") or "unknown"
    sev = normalize_severity(f.get("severity") or f.get("risk") or f.get("level") or "")
    url = f.get("url") or f.get("target") or f.get("endpoint") or ""
    name = f.get("name") or f.get("title") or f.get("rule") or "Finding"
    pluginId = f.get("pluginId") or f.get("id") or ""
    evidence = f.get("evidence") or f.get("param") or f.get("evidenceSnippet") or ""
    cwe = f.get("cwe") or f.get("cweId") or ""
    klass = classify({"name": name, "pluginId": pluginId, "cwe": cwe})
    f.update({
        "source": src,
        "severity": sev,
        "url": url,
        "name": name,
        "pluginId": pluginId,
        "evidence": evidence,
        "cwe": cwe,
        "class": klass,
        "id": f.get("id") or f.get("fingerprint") or f"{src}-{pluginId}-{digest(url,name,evidence)}"
    })
    norm.append(f)

# Deduplicate (by id)
seen = set()
deduped = []
for f in norm:
    if f["id"] in seen:
        continue
    seen.add(f["id"])
    deduped.append(f)

# --- Optional AI-based FP flagging (batched & safe) ---
def call_openai_batch(samples):
    if not OPENAI_API_KEY: 
        return {}
    # Keep prompt deterministic and bounded
    prompt = {
        "role": "system",
        "content": (
            "You are a security triage assistant. For each item, decide if it is VERY LIKELY a false positive.\n"
            "Return *ONLY* a compact JSON object mapping each 'id' to true/false.\n"
            "Be conservative: if unsure, return false.\n"
        )
    }
    user = {
        "role": "user",
        "content": json.dumps(
            [{"id": f["id"], "name": f["name"], "severity": f["severity"], "url": f["url"], "source": f["source"]} for f in samples],
            ensure_ascii=False
        )
    }
    req = json.dumps({
        "model": OPENAI_MODEL,
        "messages": [prompt, user],
        "temperature": 0.0,
        "response_format": {"type": "json_object"},
        "max_tokens": 400
    }).encode("utf-8")
    try:
        req_obj = urllib.request.Request(
            OPENAI_BASE, data=req, method="POST",
            headers={
                "Authorization": f"Bearer {OPENAI_API_KEY}",
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req_obj, timeout=60) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        mapping = json.loads(content) if content.strip().startswith("{") else {}
        return mapping if isinstance(mapping, dict) else {}
    except Exception:
        return {}

# Batch and flag (but do not drop them yet)
fp_map = {}
if OPENAI_API_KEY:
    batch = []
    for f in deduped:
        # Only ask AI for medium+ to save tokens; everything else default false
        if f["severity"] in {"medium","high","critical"}:
            batch.append(f)
            if len(batch) == 25:
                fp_map.update(call_openai_batch(batch))
                batch = []
    if batch:
        fp_map.update(call_openai_batch(batch))

for f in deduped:
    f["fp_suspect"] = bool(fp_map.get(f["id"], False))

# --- Group and write outputs ---
groups = defaultdict(list)
for f in deduped:
    groups[f["class"]].append(f)

# Helper: make compact markdown table
def md_table(rows, headers):
    # rows: list of tuples
    out = []
    out.append("| " + " | ".join(headers) + " |")
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for r in rows:
        out.append("| " + " | ".join((str(x) if x is not None else "")[:160] for x in r) + " |")
    return "\n".join(out)

bodies = {}
now = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.gmtime())
for klass in ("xss","sqli","rce","other"):
    items = groups.get(klass, [])
    total = len(items)
    if total == 0:
        body = f"**{klass.upper()}**: No findings.\nGenerated: {now}"
    else:
        from collections import Counter
        sev_counts = Counter(f["severity"] for f in items)
        fp_counts  = Counter("fp" if f.get("fp_suspect") else "tp" for f in items)
        top_rows = []
        # Top 15 unique (pluginId,url)
        seen_keys = set()
        for f in items:
            k = (f.get("pluginId"), f.get("url"))
            if k in seen_keys: 
                continue
            seen_keys.add(k)
            top_rows.append((f.get("severity"), f.get("name"), f.get("url"), f.get("source")))
            if len(top_rows) >= 15:
                break
        body_lines = []
        body_lines.append(f"**Total:** {total} | **Severity:** " +
                          ", ".join(f"{k}:{sev_counts[k]}" for k in ("critical","high","medium","low","info","unknown") if k in sev_counts))
        if fp_counts:
            body_lines.append(f"**AI-suspected FP:** {fp_counts.get('fp',0)} / {total}")
        body_lines.append("")
        body_lines.append(md_table(top_rows, headers=["Severity","Title","URL","Source"]))
        # Collapsible details (limited)
        details = []
        for f in items[:100]:
            details.append(f"- `{f.get('severity','')}` **{f.get('name','')}** → {f.get('url','')} (src: {f.get('source','')}, id: `{f.get('id','')}`)")
        body_lines.append("\n<details><summary>Details (first 100)</summary>\n\n" + "\n".join(details) + "\n\n</details>")
        body_lines.append(f"\nGenerated: {now}")
        body = "\n".join(body_lines)
    bodies[klass] = {"body": body}

# Save outputs
os.makedirs(REPORT_DIR, exist_ok=True)
with open(OUT_PATH, "w", encoding="utf-8") as fh:
    json.dump(deduped, fh, ensure_ascii=False, indent=2)
with open(BODIES_OUT, "w", encoding="utf-8") as fh:
    json.dump(bodies, fh, ensure_ascii=False, indent=2)

print(f"[AI] refined -> {OUT_PATH}; total={len(deduped)}")
print(f"[AI] class bodies -> {BODIES_OUT}; keys={list(bodies.keys())}")
