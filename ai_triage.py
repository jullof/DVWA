#!/usr/bin/env python3
# ai_triage.py — LLM-driven triage (Gemini ONLY, strong schema prompt)

import os, json, time, hashlib, re, urllib.request, urllib.error
from collections import defaultdict

REPORT_DIR   = os.environ.get("REPORT_DIR", "reports")
IN_PATH      = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_ITEMS    = os.path.join(REPORT_DIR, "ai_findings.json")
OUT_GROUPS   = os.path.join(REPORT_DIR, "ai_bodies.json")

# ==== Gemini Config ====
GEMINI_API_KEY = (os.environ.get("GEMINI_API_KEY") or "").strip()
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
BATCH_SIZE     = int(os.environ.get("AI_TRIAGE_BATCH", "25"))
TIMEOUT_S      = int(os.environ.get("AI_HTTP_TIMEOUT", "75"))

if not GEMINI_API_KEY:
    print("[AI] GEMINI_API_KEY missing — will use short per-item fallback.")

CLASS_ENUM = [
    "xss","sqli","rce","open_redirect","xslt_injection","csp",
    "csrf","auth","info_leak","misconfig","other"
]

# ==== Helpers ====
def load_raw_findings(path):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, dict) and "findings" in data:
        return data["findings"]
    if isinstance(data, list):
        return data
    return []

def chunked(seq, n):
    buf = []
    for x in seq:
        buf.append(x)
        if len(buf) >= n:
            yield buf
            buf = []
    if buf:
        yield buf

def sev_to_priority(sev):
    sev = (sev or "").lower()
    return {"critical":"P0","high":"P1","medium":"P3","low":"P4"}.get(sev, "P3")

def minimal_item(it):
    """Short fallback."""
    title = (it.get("title") or it.get("name") or "Finding").strip()
    where = (it.get("url") or it.get("where") or it.get("path") or "").strip()
    ev    = (it.get("evidence") or it.get("proof") or "").strip()
    sev   = (it.get("severity") or "medium").lower()
    if sev not in ("low","medium","high","critical"): sev = "medium"
    iid   = hashlib.sha1((title + where + ev).encode("utf-8")).hexdigest()[:12]
    return {
        "id": iid,
        "title": title,
        "class": "other",
        "severity": sev,
        "priority": sev_to_priority(sev),
        "where": where,
        "evidence": ev,
        "root_cause": "AI unavailable.",
        "recommended_remediation": ["Manual review required."],
        "references": []
    }

def coerce_item_schema(d, fallback_seed=None):
    """Normalize"""
    base = minimal_item(fallback_seed or {})
    out = {
        "id": str(d.get("id") or base["id"])[:32],
        "title": str(d.get("title") or base["title"]).strip(),
        "class": str(d.get("class") or "other").strip().lower(),
        "severity": str(d.get("severity") or base["severity"]).strip().lower(),
        "priority": str(d.get("priority") or sev_to_priority(d.get("severity")) or base["priority"]).strip().upper(),
        "where": str(d.get("where") or base["where"]).strip(),
        "evidence": str(d.get("evidence") or base["evidence"]).strip(),
        "root_cause": str(d.get("root_cause") or base["root_cause"]).strip(),
        "recommended_remediation": d.get("recommended_remediation") or base["recommended_remediation"],
        "references": d.get("references") or []
    }
    if out["class"] not in CLASS_ENUM:
        out["class"] = "other"
    if out["severity"] not in ("low","medium","high","critical"):
        out["severity"] = "medium"
    if out["priority"] not in ("P0","P1","P3","P4"):
        out["priority"] = sev_to_priority(out["severity"])
    # normalize arrays
    if not isinstance(out["recommended_remediation"], list):
        out["recommended_remediation"] = [str(out["recommended_remediation"])]
    out["recommended_remediation"] = [str(x).strip() for x in out["recommended_remediation"] if str(x).strip()]
    if not isinstance(out["references"], list):
        out["references"] = [str(out["references"])]
    out["references"] = [str(x).strip() for x in out["references"] if str(x).strip()]
    return out

def extract_json(text):
    """Parse security"""
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        m = re.search(r"\{.*\}\s*$", text, flags=re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                return None
        return None

# ==== Gemini Call ====
def call_gemini(prompt, retries=3, backoff=2.0):
    if not GEMINI_API_KEY:
        return ""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={GEMINI_API_KEY}"
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2,
            "topK": 40,
            "topP": 0.95,
            "maxOutputTokens": 2048,
            "response_mime_type": "application/json"  
        },
        "safetySettings": [
            {"category":"HARM_CATEGORY_HATE_SPEECH","threshold":"BLOCK_NONE"},
            {"category":"HARM_CATEGORY_DANGEROUS_CONTENT","threshold":"BLOCK_NONE"},
            {"category":"HARM_CATEGORY_HARASSMENT","threshold":"BLOCK_NONE"},
            {"category":"HARM_CATEGORY_SEXUALLY_EXPLICIT","threshold":"BLOCK_NONE"}
        ]
    }
    data = json.dumps(payload).encode("utf-8")
    for i in range(retries):
        try:
            req = urllib.request.Request(url, data=data, headers={"Content-Type":"application/json"})
            with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
                raw = resp.read().decode("utf-8")
            obj = json.loads(raw)
            # text çıkar
            text = ""
            try:
                text = obj["candidates"][0]["content"]["parts"][0]["text"]
            except Exception:
                text = ""
            if text.strip():
                return text
        except Exception as e:
            if i < retries-1:
                time.sleep(backoff ** i)
            else:
                return ""
    return ""

# ==== Strong Prompt ====
INSTRUCTIONS = """
You are a senior Application Security triage assistant for a CI/CD pipeline that ingests dynamic (DAST) and mixed findings.
You MUST return STRICT JSON ONLY, with the exact top-level shape: {"items":[ ... ]}. Do not include prose, markdown, or code fences.

For EACH input finding, produce ONE output object with EXACTLY these fields:

- id (string): Keep the provided id if present; otherwise derive a short stable hash based on title+where+evidence (we already supply an id seed).
- title (string): Clear and short. No severity tags here.
- class (string): ONE of:
  xss, sqli, rce, open_redirect, xslt_injection, csp, csrf, auth, info_leak, misconfig, other
  Choose the closest category; if uncertain, use "other".
- severity (string): ONE of: low, medium, high, critical.
- priority (string): Map severity → priority using:
  critical→P0, high→P1, medium→P3, low→P4. Always output P0/P1/P3/P4.
- where (string): URL or path of the affected location. Keep it short.
- evidence (string): A brief, concrete snippet that justifies the finding (≤ 200 chars).
- root_cause (string): 2-3 concise technical sentences explaining WHY the issue occurs (dataflow, missing controls, sink).
- recommended_remediation (array of strings): 2-6 short, actionable bullets (framework-agnostic). Avoid generic fluff; propose concrete controls/configs.
- references (array of strings): 1-4 URLs, preferably OWASP/CWE/MDN docs relevant to THIS class.

STRICT Requirements:
- Output VALID JSON ONLY. No extra keys. No nulls; use empty arrays where needed.
- Keep text crisp and professional; avoid verbosity.
- If the input is ambiguous or lacks sufficient context, set class="other" and root_cause="Needs manual review." Keep remediation minimal but actionable.
- Do NOT invent URLs. Use generic OWASP/CWE links when unsure.

You will receive JSON with a field "findings": an array of items (title, where/url/path, evidence, severity, id seed).
Return ONLY:
{"items":[{id,title,class,severity,priority,where,evidence,root_cause,recommended_remediation,references}, ...]}
"""

def build_user_payload(batch):
    items = []
    for it in batch:
        title = it.get("title") or it.get("name") or "Finding"
        where = it.get("url") or it.get("where") or it.get("path") or ""
        ev    = it.get("evidence") or it.get("proof") or ""
        sev   = (it.get("severity") or "medium")
        seed  = minimal_item(it)  
        items.append({
            "id": seed["id"],
            "title": title,
            "where": where,
            "evidence": ev,
            "severity": sev
        })
    return json.dumps({"findings": items}, ensure_ascii=False)

# ==== Main ====
raw = load_raw_findings(IN_PATH)
if not raw:
    print(f"[AI] input missing or empty: {IN_PATH}")
    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(OUT_ITEMS, "w", encoding="utf-8") as f: json.dump([], f, indent=2, ensure_ascii=False)
    with open(OUT_GROUPS, "w", encoding="utf-8") as f: json.dump({}, f, indent=2, ensure_ascii=False)
    raise SystemExit(0)

all_items = []
for batch in chunked(raw, BATCH_SIZE):
    if GEMINI_API_KEY:
        prompt = INSTRUCTIONS + "\n\nINPUT JSON:\n" + build_user_payload(batch)
        text = call_gemini(prompt)
        data = extract_json(text)
        if data and isinstance(data.get("items"), list) and data["items"]:
            for src, out in zip(batch, data["items"]):
                all_items.append(coerce_item_schema(out, fallback_seed=src))
            continue  

    all_items.extend([ minimal_item(it) for it in batch ])

# ==== Write ai_findings.json ====
os.makedirs(REPORT_DIR, exist_ok=True)
with open(OUT_ITEMS, "w", encoding="utf-8") as f:
    json.dump(all_items, f, indent=2, ensure_ascii=False)

# ==== Build grouped markdown bodies (ai_bodies.json) ====
groups = defaultdict(list)
for it in all_items:
    groups[it["class"]].append(it)

group_bodies = {}
for g, items in groups.items():
    lines = []
    lines.append(f"# AI triage summary — {g.upper()}\n")
    lines.append(f"Total items: **{len(items)}**\n")
    for idx, it in enumerate(items, 1):
        lines.append(f"## {idx}. {it['title']}  *(severity:{it['severity']}, priority:{it['priority']})*")
        if it.get("where"):
            lines.append(f"- **Where:** {it['where']}")
        if it.get("evidence"):
            ev = it['evidence']
            ev = (ev[:200] + "…") if len(ev) > 200 else ev
            lines.append(f"- **Evidence:** `{ev}`")
        if it.get("root_cause"):
            lines.append(f"- **Root cause:** {it['root_cause']}")
        rem = it.get("recommended_remediation") or []
        if rem:
            lines.append("- **Proposed remediation:**")
            for step in rem:
                lines.append(f"  - {step}")
        refs = it.get("references") or []
        if refs:
            lines.append("- **References:**")
            for r in refs:
                lines.append(f"  - {r}")
        lines.append("")  # spacer
    group_bodies[g] = "\n".join(lines)

with open(OUT_GROUPS, "w", encoding="utf-8") as f:
    json.dump(group_bodies, f, indent=2, ensure_ascii=False)

print(f"[AI] refined -> {OUT_ITEMS}; total={len(all_items)}")
print(f"[AI] class groups -> {OUT_GROUPS}; keys={list(group_bodies.keys())}")
