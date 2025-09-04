#!/usr/bin/env python3
# ai_triage.py (GEMINI-ONLY, cost-optimized)
import os, sys, json, time, hashlib, urllib.request, urllib.error
from collections import defaultdict

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
IN_PATH    = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_PATH   = os.path.join(REPORT_DIR, "ai_findings.json")
BODIES_OUT = os.path.join(REPORT_DIR, "ai_bodies.json")

# ------------ Gemini config ------------
GEMINI_API_KEY = (os.environ.get("GEMINI_API_KEY") or "").strip()
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL","gemini-1.5-flash").strip()
GEMINI_BASE    = os.environ.get("GEMINI_BASE","https://generativelanguage.googleapis.com/v1beta/models").strip()

# Cost/limit knobs
AI_ONLY_SEVERITIES = set([s.strip().lower() for s in (os.environ.get("AI_ONLY_SEVERITIES","low,medium,high,critical,info").split(",")) if s.strip()])
AI_MAX_FINDINGS    = int(os.environ.get("AI_MAX_FINDINGS","200"))
AI_BATCH_SIZE      = int(os.environ.get("AI_BATCH_SIZE","25"))
AI_SLEEP_BETWEEN   = float(os.environ.get("AI_SLEEP_BETWEEN","1.0"))

# ---------- helpers ----------

import re


CTRL_CHARS_RGX = re.compile(r'[\x00-\x1f\x7f]')

def clean_text(s: str) -> str:
    if not isinstance(s, str):
        s = str(s or "")
    # kontrol karakterleri ve NULL'lar
    s = CTRL_CHARS_RGX.sub(' ', s)
    # kimi modeller ```json ... ``` ile çitliyor
    s = s.strip()
    if s.startswith("```"):
        s = s.strip("`")
        # ilk satır "json" yazıyorsa at
        if s.startswith("json"):
            s = s[4:].lstrip()
    return s.strip()

def extract_json_block(s: str) -> str:
    """Metin içinden en geniş { ... } bloğunu kaba kuvvetle çıkar."""
    s = clean_text(s)
    start = s.find('{')
    end   = s.rfind('}')
    if start != -1 and end != -1 and end > start:
        return s[start:end+1]
    return s

def safe_json_loads(s: str):
    s = extract_json_block(s)
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # Çok kaba kurtarma: sonuna } ekleme denemesi
        s2 = s.rstrip()
        if not s2.endswith('}'):
            s2 += '}'
            try:
                return json.loads(s2)
            except Exception:
                pass
        # tamamen başarısızsa boş obje dön
        return {}


def _lower(s): return (s or "").lower()
def digest(*parts):
    h = hashlib.sha1()
    for p in parts: h.update((_lower(str(p))).encode("utf-8","ignore"))
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

# ---------- load raw ----------
try:
    with open(IN_PATH,"r",encoding="utf-8") as fh:
        raw = json.load(fh)
except FileNotFoundError:
    print(f"[AI] skipped: {IN_PATH} not found.")
    sys.exit(0)

items = raw["findings"] if isinstance(raw, dict) and "findings" in raw else (raw if isinstance(raw, list) else [])

# ---------- normalize ----------
norm = []
for it in items:
    f = dict(it or {})
    src  = f.get("source") or f.get("scanner") or f.get("tool") or "unknown"
    sev  = norm_sev(f.get("severity") or f.get("risk") or f.get("level") or "")
    url  = clean_text(f.get("url") or f.get("target") or f.get("endpoint") or "")
    name = clean_text(f.get("name") or f.get("title") or f.get("rule") or "Finding")
    plug = f.get("pluginId") or f.get("pluginid") or f.get("rule_id") or f.get("id") or ""
    param = clean_text(f.get("param") or "")
    cwe = f.get("cwe") or f.get("cweId") or ""
    ev  = clean_text(f.get("evidence") or f.get("evidenceSnippet") or "")
    klass = classify(name, plug, cwe)
    fid = f.get("id") or f.get("fingerprint") or f"{src}-{plug}-{digest(url,name,param or ev)}"
    norm.append({
        "id": fid,
        "source": src,
        "scanner": f.get("scanner") or src,
        "severity": sev,
        "name": name,
        "title": name,
        "url": url,
        "param": param,
        "pluginId": str(plug),
        "cwe": str(cwe),
        "evidence": ev,
        "class": klass
    })


# dedup
seen, dedup = set(), []
for f in norm:
    if f["id"] in seen: continue
    seen.add(f["id"]); dedup.append(f)

# ---------- throttle by severity / cap count ----------
if AI_ONLY_SEVERITIES:
    dedup = [x for x in dedup if (x.get("severity","").lower() in AI_ONLY_SEVERITIES)]
if AI_MAX_FINDINGS and len(dedup) > AI_MAX_FINDINGS:
    buckets = defaultdict(list)
    for x in dedup:
        key = (x["severity"], x["class"])
        if len(buckets[key]) < 50:
            buckets[key].append(x)
    pooled = []
    for _, arr in buckets.items():
        pooled.extend(arr)
    dedup = pooled[:AI_MAX_FINDINGS]

# ---------- Gemini call ----------
def call_gemini(batch):
    payload_items = []
    for x in batch:
        ev = clean_text((x.get("evidence","") or ""))[:160].replace("\n"," ")
        title = clean_text(x.get("title",""))
        url = (x.get("url") or "N/A")
        desc = f"{title} | sev={x['severity']} | url={url} | ev={ev}"
        payload_items.append({"id": x["id"], "d": desc})

    sys_prompt = (
        "You are a security triage assistant. For each finding id, return a JSON object keyed by id "
        "with fields: ai_priority (P0..P4), ai_suspected_fp (boolean), why_opened ('<=2 sentences'), "
        "remediation ('<=4 numbered steps'), references (array with up to 2 reputable URLs). "
        "Return ONLY a JSON object and nothing else."
    )
    user_payload = json.dumps({"findings": payload_items}, ensure_ascii=False)

    url = f"{GEMINI_BASE}/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    body = {
        "contents": [
            {"role":"user", "parts":[{"text": sys_prompt + "\n\n" + user_payload}]}
        ],
        "generationConfig": {
            "temperature": 0.0,
            "maxOutputTokens": 1200,
            "responseMimeType": "application/json"
        }
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={"Content-Type":"application/json"}
    )

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = json.loads(r.read().decode("utf-8"))
            text = (
                data.get("candidates",[{}])[0]
                    .get("content",{}).get("parts",[{}])[0]
                    .get("text","")
            )
            text = clean_text(text)
            if not text:
                return {}
            return safe_json_loads(text)
        except urllib.error.HTTPError as e:
            body = e.read().decode(errors="ignore")
            print(f"HTTP Error (Gemini): {e.code} - {e.reason}\nResponse: {body}")
            if e.code == 429 or "quota" in body.lower() or "insufficient" in body.lower():
                return "__ABORT_ALL__"
            if e.code >= 500:
                time.sleep(1.5 + attempt)
                continue
            return {}

        except Exception as e:
            print(f"Unexpected error (Gemini): {e}")
            time.sleep(1.0 + 0.5*attempt)
            continue
    return {}


# ---------- short-circuit if no key ----------
if not GEMINI_API_KEY:
    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(OUT_PATH,"w",encoding="utf-8") as fh: json.dump(dedup, fh, ensure_ascii=False, indent=2)
    with open(BODIES_OUT,"w",encoding="utf-8") as fh: json.dump(
        {k:{"body":f"**{k.upper()}**: No AI triage (no GEMINI_API_KEY)."} for k in ("xss","sqli","rce","other")},
        fh, ensure_ascii=False, indent=2
    )
    print("[AI] skipped: GEMINI_API_KEY not set -> wrote pass-through outputs.")
    sys.exit(0)

# ---------- triage (batched) ----------
ai_results = {}
if dedup:
    total_batches = (len(dedup)-1)//AI_BATCH_SIZE + 1
    for i in range(0, len(dedup), AI_BATCH_SIZE):
        batch = dedup[i:i+AI_BATCH_SIZE]
        print(f"Processing batch {i//AI_BATCH_SIZE + 1}/{total_batches} via gemini")
        res = call_gemini(batch)
        if res == "__ABORT_ALL__":
            print("[AI] No quota — skipping remaining batches, falling back to defaults.")
            ai_results = {}
            break
        if isinstance(res, dict):
            ai_results.update(res)
        time.sleep(AI_SLEEP_BETWEEN)
else:
    print("[AI] nothing to triage after filtering/grouping.")

# ---------- merge & write ----------
def default_refs():
    return [
        "https://owasp.org/www-project-top-ten/",
        "https://cwe.mitre.org/",
        "https://cheatsheetseries.owasp.org/"
    ]

enriched = []
for f in dedup:
    finding_id = f["id"]
    ai = ai_results.get(finding_id, {}) or {}
    remediation = (ai.get("remediation") or "").strip() or "1) İnceleyin  2) Uygun düzeltmeleri yapın  3) Test edin  4) Yayına alın"
    refs = ai.get("references")
    if isinstance(refs, str):
        refs = [refs]
    if not refs:
        refs = default_refs()


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
        "ai_priority": ai.get("ai_priority","P3"),
        "ai_suspected_fp": bool(ai.get("ai_suspected_fp", False)),
        "why_opened": ai.get("why_opened","Manual review recommended."),
        "remediation": remediation,
        "references": refs,
        "provenance": prov
    })

groups = defaultdict(list)
for f in enriched: groups[f["class"]].append(f)

def _cell(x, limit=120):
    s = clean_text(str(x if x is not None else ""))
    s = s.replace("|", "\\|")
    return s[:limit]

def table(rows, headers):
    out = ["| " + " | ".join(_cell(h) for h in headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for r in rows:
        out.append("| " + " | ".join(_cell(x) for x in r) + " |")
    return "\n".join(out)


now = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.gmtime())
bodies = {}
for klass in ("xss", "sqli", "rce", "other"):
    items = groups.get(klass, [])
    if not items:
        bodies[klass] = {"body": f"**{klass.upper()}**: No findings.\nGenerated: {now}"}
        continue

    uniq, rows = set(), []
    for x in items:
        key = (x.get("pluginId"), x.get("url"))
        if key in uniq:
            continue
        uniq.add(key)
        rows.append((x["severity"], x["title"], x.get("url", ""), x.get("ai_priority", "P3")))
        if len(rows) >= 15:
            break

    details = []
    for x in items[:80]:
        prov = x.get("provenance") or {}
        urls = ", ".join(prov.get("urls") or ([x.get("url")] if x.get("url") else []))

        raw_refs = x.get("references") or []
        if isinstance(raw_refs, str):
            raw_refs = [raw_refs]
        refs_list = [clean_text(r) for r in raw_refs[:6]]
        refs_md = "".join(f"\n  - {r}" for r in refs_list)

        title_safe = clean_text(x.get("title", ""))
        why_safe   = clean_text(x.get("why_opened", ""))
        rem_safe   = clean_text(x.get("remediation", ""))

        details.append(
f"""- **{title_safe}** (`{x.get('severity','')}`, {x.get('ai_priority','P3')})
  - **Why:** {why_safe}
  - **Where:** {urls}
  - **Rule/Plugin:** {prov.get('rule_or_plugin','')}
  - **Evidence:** {", ".join((prov.get("evidence") or [])[:2])}
  - **Remediation:** {rem_safe}
  - **References:**{refs_md}"""
        )

    body = (
        f"{table(rows, ['Severity','Title','URL','Priority'])}\n\n"
        f"<details><summary>Details (first 80)</summary>\n\n"
        + "\n\n".join(details)
        + f"\n\n</details>\n\nGenerated: {now}"
    )
    bodies[klass] = {"body": body}



os.makedirs(REPORT_DIR, exist_ok=True)
with open(OUT_PATH,"w",encoding="utf-8") as fh: json.dump(enriched, fh, ensure_ascii=False, indent=2)
with open(BODIES_OUT,"w",encoding="utf-8") as fh: json.dump(bodies, fh, ensure_ascii=False, indent=2)

print(f"[AI] refined -> {OUT_PATH}; total={len(enriched)}")
print(f"[AI] class bodies -> {BODIES_OUT}; keys={list(bodies.keys())}")
