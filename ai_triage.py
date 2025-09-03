#!/usr/bin/env python3
# ai_triage.py (OPTIMIZED VERSION)
import os, sys, json, re, time, hashlib, urllib.request, urllib.error
from collections import defaultdict, Counter

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
IN_PATH    = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_PATH   = os.path.join(REPORT_DIR, "ai_findings.json")
BODIES_OUT = os.path.join(REPORT_DIR, "ai_bodies.json")

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY","").strip()
OPENAI_MODEL   = os.environ.get("OPENAI_MODEL","gpt-4o")
OPENAI_BASE    = os.environ.get("OPENAI_BASE","https://api.openai.com/v1/chat/completions")

if not OPENAI_API_KEY:
    for p in (OUT_PATH, BODIES_OUT):
        try:
            if os.path.exists(p): os.remove(p)
        except Exception:
            pass
    print("[AI] skipped: OPENAI_API_KEY not set -> no triage, no outputs.")
    sys.exit(0)

# ---------- helpers ----------
def _lower(s): return (s or "").lower()
def digest(*parts):
    h = hashlib.sha1()
    for p in parts:
        h.update((_lower(str(p))).encode("utf-8","ignore"))
    return h.hexdigest()[:12]

PLUGIN_XSS  = {"40012","40014","40016","40017","40026"}
PLUGIN_SQLI = {"40018","40019","40020","40021","40022","40024","40027"}
PLUGIN_RCE  = {"90020","20018"}

def classify(name, pluginId, cwe):
    n = _lower(name); p = str(pluginId or "")
    if ("xss" in n or "cross site scripting" in n) or p in PLUGIN_XSS:  return "xss"
    if "sql injection" in n or p in PLUGIN_SQLI:                        return "sqli"
    if any(k in n for k in ["remote code execution","os command","command injection","code injection"]) or p in PLUGIN_RCE:
        return "rce"
    return "other"

def norm_sev(s):
    s = _lower(s)
    if s in ("0","info","informational"): return "info"
    if s in ("1","low"): return "low"
    if s in ("2","medium","moderate"): return "medium"
    if s in ("3","high"): return "high"
    if s in ("4","critical","very high","urgent"): return "critical"
    return "unknown"

with open(IN_PATH,"r",encoding="utf-8") as fh:
    raw = json.load(fh)

items = raw["findings"] if isinstance(raw, dict) and "findings" in raw else (raw if isinstance(raw, list) else [])

norm = []
for it in items:
    f = dict(it or {})
    src  = f.get("source") or f.get("scanner") or f.get("tool") or "unknown"
    sev  = norm_sev(f.get("severity") or f.get("risk") or f.get("level") or "")
    url  = f.get("url") or f.get("target") or f.get("endpoint") or ""
    name = f.get("name") or f.get("title") or f.get("rule") or "Finding"
    plug = f.get("pluginId") or f.get("pluginid") or f.get("rule_id") or f.get("id") or ""
    param = f.get("param") or ""
    cwe = f.get("cwe") or f.get("cweId") or ""
    ev  = f.get("evidence") or f.get("evidenceSnippet") or ""
    klass = classify(name, plug, cwe)
    fid = f.get("id") or f.get("fingerprint") or f"{src}-{plug}-{digest(url,name,param or ev)}"
    norm.append({
        "id": fid,
        "source": src,
        "scanner": f.get("scanner") or src,
        "severity": sev,
        "name": name,
        "title": f.get("title") or name,
        "url": url,
        "param": param,
        "pluginId": str(plug),
        "cwe": str(cwe),
        "evidence": ev,
        "class": klass
    })

seen, dedup = set(), []
for f in norm:
    if f["id"] in seen: continue
    seen.add(f["id"]); dedup.append(f)

# ---------- AI enrichment ----------
def call_openai(batch):
    # Prepare simplified input for AI
    payload_items = []
    for x in batch:
        # Create a concise description for the AI
        description = f"{x['title']}. Severity: {x['severity']}. Target: {x['url'] or 'N/A'}. Evidence: {x.get('evidence', '')[:200]}"
        payload_items.append({
            "id": x["id"],
            "description": description
        })

    sys_prompt = """You are a security expert analyzing vulnerability findings. For each finding provided, return a JSON object with the following structure for each finding ID:

{
  "ai_priority": "P0/P1/P2/P3/P4",
  "ai_suspected_fp": true/false,
  "why_opened": "2-4 sentence explanation of impact and exploitability",
  "remediation": "3-6 actionable remediation steps as a single string with numbered steps",
  "references": ["URL1", "URL2", "URL3"] (2-5 reputable security references)
}

PRIORITY GUIDE:
- P0: Critical severity, actively exploited, immediate action required
- P1: High severity, easily exploitable, important to fix
- P2: Medium severity, requires specific conditions to exploit
- P3: Low severity, limited impact or difficult to exploit
- P4: Informational findings with no direct security impact

FALSE POSITIVE GUIDANCE: Only mark as true if you're highly confident it's a false positive.

Return ONLY valid JSON with finding IDs as keys."""

    user_payload = json.dumps({"findings": payload_items}, ensure_ascii=False, indent=2)
    
    req_body = json.dumps({
        "model": OPENAI_MODEL,
        "messages": [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_payload}
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
        "max_tokens": 4000
    }).encode("utf-8")

    req = urllib.request.Request(
        OPENAI_BASE, data=req_body, method="POST",
        headers={
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
    )
    
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = json.loads(r.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        
        # Parse AI response
        ai_response = json.loads(content.strip())
        return ai_response
        
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} - {e.reason}")
        print(f"Response: {e.read().decode()}")
        return {}
    except json.JSONDecodeError as e:
        print(f"JSON Parse Error: {e}")
        print(f"Raw response: {content}")
        return {}
    except Exception as e:
        print(f"Unexpected error: {e}")
        return {}

# Process findings in smaller batches for better reliability
ai_results = {}
BATCH_SIZE = 10

for i in range(0, len(dedup), BATCH_SIZE):
    batch = dedup[i:i+BATCH_SIZE]
    print(f"Processing batch {i//BATCH_SIZE + 1}/{(len(dedup)-1)//BATCH_SIZE + 1}")
    
    batch_results = call_openai(batch)
    ai_results.update(batch_results)
    
    # Be gentle with the API
    time.sleep(1.5)

# ---------- merge & write ----------
enriched = []
for f in dedup:
    finding_id = f["id"]
    ai_data = ai_results.get(finding_id, {})
    
    # Ensure we have proper fallback values for all required fields
    remediation = ai_data.get("remediation", "Review the finding manually for appropriate remediation steps.")
    references = ai_data.get("references", [])
    
    # If remediation is empty, provide a default
    if not remediation.strip():
        remediation = "1. Review the vulnerability\n2. Implement appropriate security controls\n3. Test the fix\n4. Deploy the solution"
    
    # Ensure we have at least some references
    if not references:
        references = [
            "https://owasp.org/www-project-top-ten/",
            "https://cwe.mitre.org/",
            "https://cheatsheetseries.owasp.org/"
        ]
    
    # Create provenance information from original finding
    prov = {
        "source": f["source"],
        "scanner": f["scanner"],
        "rule_or_plugin": f.get("pluginId") or f.get("cwe") or "",
        "urls": [u for u in {f.get("url")} if u],
        "params": [p for p in {f.get("param")} if p],
        "evidence": [e for e in {f.get("evidence")} if e]
    }
    
    enriched.append({
        **f,
        "ai_priority": ai_data.get("ai_priority", "P3"),
        "ai_suspected_fp": bool(ai_data.get("ai_suspected_fp", False)),
        "why_opened": ai_data.get("why_opened", "Needs manual review for accurate assessment."),
        "remediation": remediation,
        "references": references,
        "provenance": prov
    })

# Create grouped bodies for issue creation
groups = defaultdict(list)
for f in enriched: 
    groups[f["class"]].append(f)

def table(rows, headers):
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join((str(x) if x is not None else "")[:180] for x in r) + " |")
    return "\n".join(out)

now = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.gmtime())
bodies = {}
for klass in ("xss","sqli","rce","other"):
    items = groups.get(klass, [])
    if not items:
        bodies[klass] = {"body": f"**{klass.upper()}**: No findings.\nGenerated: {now}"}
        continue
        
    # Create summary table
    uniq, rows = set(), []
    for x in items:
        key = (x.get("pluginId"), x.get("url"))
        if key in uniq: continue
        uniq.add(key)
        rows.append((x["severity"], x["title"], x.get("url",""), x.get("ai_priority","P3")))
        if len(rows) >= 15: break
            
    # Create detailed findings section
    details = []
    for x in items[:80]:
        prov = x.get("provenance") or {}
        urls = ", ".join(prov.get("urls") or ([x.get("url")] if x.get("url") else []))
        refs = "".join(f"\n  - {r}" for r in (x.get("references") or [])[:6])
        
        details.append(
f"""- **{x.get('title','')}** (`{x.get('severity','')}`, {x.get('ai_priority','P3')})
  - **Why:** {x.get('why_opened','')}
  - **Where:** {urls}
  - **Rule/Plugin:** {prov.get('rule_or_plugin','')}
  - **Evidence:** {", ".join((prov.get("evidence") or [])[:2])}
  - **Remediation:** {x.get('remediation','')}
  - **References:**{refs}
""".rstrip()
        )
    
    body = f"{table(rows, ['Severity','Title','URL','Priority'])}\n\n<details><summary>Details (first 80)</summary>\n\n" + "\n\n".join(details) + f"\n\n</details>\n\nGenerated: {now}"
    bodies[klass] = {"body": body}

# Write outputs
os.makedirs(REPORT_DIR, exist_ok=True)
with open(OUT_PATH,"w",encoding="utf-8") as fh: 
    json.dump(enriched, fh, ensure_ascii=False, indent=2)
with open(BODIES_OUT,"w",encoding="utf-8") as fh: 
    json.dump(bodies, fh, ensure_ascii=False, indent=2)

print(f"[AI] refined -> {OUT_PATH}; total={len(enriched)}")
print(f"[AI] class bodies -> {BODIES_OUT}; keys={list(bodies.keys())}")