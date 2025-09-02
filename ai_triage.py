#!/usr/bin/env python3
# ai_triage.py (NO-OP V)
import os, sys, json, re, time, hashlib, urllib.request, urllib.error
from collections import defaultdict, Counter

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
IN_PATH    = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_PATH   = os.path.join(REPORT_DIR, "ai_findings.json")
BODIES_OUT = os.path.join(REPORT_DIR, "ai_bodies.json")

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY","").strip()
OPENAI_MODEL   = os.environ.get("OPENAI_MODEL","gpt-5")
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

# ---------- AI enrichment (required because key exists) ----------
def call_openai(batch):
    payload_items = [{
        "id": x["id"], "title": x["title"], "severity": x["severity"],
        "url": x["url"], "param": x.get("param"), "class": x["class"],
        "source": x["source"], "scanner": x["scanner"],
        "rule_or_plugin": x.get("pluginId") or x.get("cwe") or "",
        "evidence": (x.get("evidence") or "")[:800]
    } for x in batch]

    sys_prompt = (
        "You are an application security triage assistant. "
        "Given a list of web security findings (ZAP/Snyk/Semgrep), "
        "produce a STRICT JSON with key 'items' (array). "
        "For EACH input item, return an object containing:\n"
        "- id (same as input)\n"
        "- ai_priority: one of P0,P1,P2,P3,P4 (P0 highest)\n"
        "- ai_suspected_fp: boolean (true only if VERY LIKELY a false positive)\n"
        "- why_opened: concise 2-4 sentence rationale referencing impact & exploitability\n"
        "- remediation: 3-6 actionable steps (numbered)\n"
        "- references: array of 2-5 short reputable refs (OWASP/MDN/NIST/CWE/CVE)\n"
        "- provenance: {source, scanner, rule_or_plugin, urls[], params[], evidence[]}\n"
        "Be conservative in fp flagging; if unsure set false. Return ONLY JSON."
    )

    user_payload = json.dumps({"items": payload_items}, ensure_ascii=False)
    req_body = json.dumps({
        "model": OPENAI_MODEL,
        "messages": [
            {"role":"system","content":sys_prompt},
            {"role":"user","content":user_payload}
        ],
        "temperature": 0.0,
        "response_format": {"type":"json_object"},
        "max_tokens": 1200
    }).encode("utf-8")

    req = urllib.request.Request(
        OPENAI_BASE, data=req_body, method="POST",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}",
                 "Content-Type":"application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            data = json.loads(r.read().decode("utf-8"))
        content = data["choices"][0]["message"]["content"]
        obj = json.loads(content) if content.strip().startswith("{") else {}
        items = obj.get("items") or []
        # normalize to dict by id
        m = {}
        if isinstance(items, list):
            for it in items:
                if isinstance(it, dict) and "id" in it:
                    m[it["id"]] = it
        elif isinstance(items, dict):
            for k,v in items.items():
                if isinstance(v, dict):
                    v["id"] = v.get("id", k)
                    m[v["id"]] = v
        return m
    except Exception:
        return {}

ai_map = {}
B = 40
for i in range(0, len(dedup), B):
    ai_map.update(call_openai(dedup[i:i+B]))
    time.sleep(0.4)

# ---------- merge & write ----------
enriched = []
for f in dedup:
    extra = ai_map.get(f["id"], {})
    prov = extra.get("provenance") or {
        "source": f["source"], "scanner": f["scanner"],
        "rule_or_plugin": f.get("pluginId") or f.get("cwe") or "",
        "urls": [u for u in {f.get("url")} if u],
        "params": [p for p in {f.get("param")} if p],
        "evidence": [e for e in {f.get("evidence")} if e]
    }
    enriched.append({
        **f,
        "ai_priority": extra.get("ai_priority","P3"),
        "ai_suspected_fp": bool(extra.get("ai_suspected_fp", False)),
        "why_opened": extra.get("why_opened",""),
        "remediation": extra.get("remediation",""),
        "references": extra.get("references") or [],
        "provenance": prov
    })

# grouped bodies
groups = defaultdict(list)
for f in enriched: groups[f["class"]].append(f)

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
    # top rows
    uniq, rows = set(), []
    for x in items:
        key = (x.get("pluginId"), x.get("url"))
        if key in uniq: continue
        uniq.add(key)
        rows.append((x["severity"], x["title"], x.get("url",""), x.get("ai_priority","P3")))
        if len(rows) >= 15: break
    # details
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

os.makedirs(REPORT_DIR, exist_ok=True)
with open(OUT_PATH,"w",encoding="utf-8") as fh: json.dump(enriched, fh, ensure_ascii=False, indent=2)
with open(BODIES_OUT,"w",encoding="utf-8") as fh: json.dump(bodies, fh, ensure_ascii=False, indent=2)

print(f"[AI] refined -> {OUT_PATH}; total={len(enriched)}")
print(f"[AI] class bodies -> {BODIES_OUT}; keys={list(bodies.keys())}")
