#!/usr/bin/env python3
# ai_triage_patched.py — deterministic triage + compact grouping (AI optional)
# Drop-in replacement for ai_triage.py

import os, json, time, hashlib, re, urllib.request, urllib.error
from collections import defaultdict, Counter

REPORT_DIR   = os.environ.get("REPORT_DIR", "reports")
IN_PATH      = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_ITEMS    = os.path.join(REPORT_DIR, "ai_findings.json")   # normalized per-item JSON
OUT_GROUPS   = os.path.join(REPORT_DIR, "ai_bodies.json")     # grouped markdown bodies
OUT_GROUPMETA= os.path.join(REPORT_DIR, "ai_groupmeta.json")  # meta for labels/titles per group

# ==== AI Config (Gemini) ====
GEMINI_API_KEY = (os.environ.get("GEMINI_API_KEY") or "").strip()
GEMINI_MODEL   = os.environ.get("GEMINI_MODEL", "gemini-1.5-flash")
BATCH_SIZE     = int(os.environ.get("AI_TRIAGE_BATCH", "25"))
TIMEOUT_S      = int(os.environ.get("AI_HTTP_TIMEOUT", "75"))

# ==== Output Controls ====
MAX_ITEMS_PER_GROUP_ISSUE = int(os.environ.get("MAX_ITEMS_PER_GROUP_ISSUE", "120"))
MAX_EVIDENCE_CHARS        = int(os.environ.get("MAX_EVIDENCE_CHARS", "200"))
MIN_TRUNCATE_CLASS_COUNT  = int(os.environ.get("MIN_TRUNCATE_CLASS_COUNT", "10"))

CLASS_ENUM = [
    "xss","sqli","rce","open_redirect","xslt_injection","csp",
    "csrf","auth","info_leak","misconfig","other"
]

# Label mapping for downstream "Create Issues" stage
CLASS_LABELS = {
    "xss": ["security","xss","ai-triage"],
    "sqli": ["security","sql_injection","ai-triage"],
    "rce": ["security","rce","ai-triage"],
    "open_redirect": ["security","open_redirect","ai-triage"],
    "xslt_injection": ["security","xslt_injection","ai-triage"],
    "csp": ["security","csp","ai-triage"],
    "csrf": ["security","csrf","ai-triage"],
    "auth": ["security","auth","ai-triage"],
    "info_leak": ["security","info_leak","ai-triage"],
    "misconfig": ["security","misconfig","ai-triage"],
    "other": ["security","other","ai-triage"],
}

# Deterministic remediation/reference fallbacks
REMEDIATION_MAP = {
    "xss": [
        "Encode user output (htmlspecialchars/htmlentities).",
        "Prefer templating with auto-escaping.",
        "Validate and sanitize inputs server-side.",
        "Set strong CSP (script-src 'self' with nonces)."
    ],
    "sqli": [
        "Use parameterized queries / prepared statements (PDO).",
        "Avoid string concatenation for SQL.",
        "Apply least-privilege DB user permissions.",
        "Centralize query building in a vetted DAL."
    ],
    "rce": [
        "Avoid dynamic command execution; use safe library APIs.",
        "If execution is required, strictly validate/whitelist args.",
        "Disable shell expansion, quote and escape inputs.",
        "Run service with least privileges; enable AppArmor/SELinux."
    ],
    "open_redirect": [
        "Validate and whitelist redirect targets.",
        "Reject external/absolute URLs unless explicitly allowed.",
        "Use server-side routing identifiers instead of raw URLs."
    ],
    "csp": [
        "Add strict Content-Security-Policy with nonces for scripts.",
        "Disallow 'unsafe-inline' and wildcards for script-src.",
        "Gradually harden using CSP report-only first."
    ],
    "csrf": [
        "Require anti-CSRF tokens and validate per request.",
        "Use SameSite=Lax cookies and enforce origin checks."
    ],
    "auth": [
        "Enforce authentication for sensitive endpoints.",
        "Use secure session management and rotate tokens on login.",
        "Rate-limit and lockout on repeated failures."
    ],
    "info_leak": [
        "Disable directory listing and verbose error pages.",
        "Restrict access to /backup and config endpoints.",
        "Avoid exposing version banners and stack traces."
    ],
    "misconfig": [
        "Harden server defaults; remove debug endpoints.",
        "Apply least-privilege on files and folders.",
        "Review container/base image packages; patch regularly."
    ],
    "other": [
        "Review logic and inputs; add validation and least privilege."
    ]
}

REFS_MAP = {
    "xss": ["https://owasp.org/www-community/attacks/xss/","https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    "sqli": ["https://owasp.org/www-community/attacks/SQL_Injection","https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"],
    "rce": ["https://cwe.mitre.org/data/definitions/78.html","https://owasp.org/Top10/A03_2021-Injection/"],
    "open_redirect": ["https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards/"],
    "csp": ["https://developer.mozilla.org/docs/Web/HTTP/CSP","https://owasp.org/www-project-secure-headers/"],
    "csrf": ["https://owasp.org/www-community/attacks/csrf"],
    "auth": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"],
    "info_leak": ["https://owasp.org/www-community/Improper_Error_Handling","https://cwe.mitre.org/data/definitions/200.html"],
    "misconfig": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
    "other": ["https://owasp.org/"],
}

# ---- Helpers ----
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
    """Short fallback for a raw finding."""
    title = (it.get("title") or it.get("name") or "Finding").strip()
    where = (it.get("url") or it.get("where") or it.get("path") or "").strip()
    ev    = (it.get("evidence") or it.get("proof") or "").strip()
    sev   = (it.get("severity") or "medium").lower()
    if sev not in ("low","medium","high","critical"): sev = "medium"
    iid   = hashlib.sha1((title + where + ev).encode("utf-8")).hexdigest()[:12]
    klass = classify_fallback(title, where, ev)
    return {
        "id": iid,
        "title": title,
        "class": klass,
        "severity": sev,
        "priority": sev_to_priority(sev),
        "where": where,
        "evidence": ev[:MAX_EVIDENCE_CHARS],
        "root_cause": root_cause_fallback(klass),
        "recommended_remediation": REMEDIATION_MAP.get(klass, REMEDIATION_MAP["other"]),
        "references": REFS_MAP.get(klass, REFS_MAP["other"]),
    }

# Deterministic classifier (regex/keyword based) for AI-unavailable path
RX = {
    "xss": re.compile(r"\bxss\b|cross[- ]site|<script>|javascript:", re.I),
    "sqli": re.compile(r"\bsql(\s|_|-)?inj|select\s+.+\s+from|\bunion\b\s+select", re.I),
    "rce": re.compile(r"\brce\b|command\s+execution|exec\(|system\(|shell_exec\(", re.I),
    "open_redirect": re.compile(r"open\s*redirect|redirect\s*to|location\s*header", re.I),
    "xslt_injection": re.compile(r"xslt|xsl:|xml\s+stylesheet", re.I),
    "csp": re.compile(r"content\s*security\s*policy|csp\s+header", re.I),
    "csrf": re.compile(r"\bcsrf\b|cross[- ]site\s+request", re.I),
    "auth": re.compile(r"authenticat|authorization|weak\s*password|login\b", re.I),
    "info_leak": re.compile(r"info(?:rmation)?\s*exposure|path\s*disclosure|stack\s*trace|backup\s*file|\.bak\b|\.old\b|\.swp\b", re.I),
    "misconfig": re.compile(r"misconfig|directory\s+listing|debug\s+mode|insecure\s+headers", re.I),
}

def classify_fallback(title, where, evidence):
    text = " ".join([title or "", where or "", evidence or ""])
    for k, rx in RX.items():
        if rx.search(text):
            return k
    return "other"

def root_cause_fallback(klass):
    return {
        "xss": "User-controlled data is rendered without proper output encoding and CSP is permissive.",
        "sqli": "Untrusted input flows into SQL queries without parameterization or proper sanitization.",
        "rce": "User input influences OS command execution via shell/system APIs without strict whitelisting.",
        "open_redirect": "Redirect target is derived from user input without validation/allow‑list.",
        "xslt_injection": "Untrusted XSLT sources are processed, allowing attacker-controlled templates.",
        "csp": "CSP header is missing or too permissive, permitting inline/remote scripts.",
        "csrf": "State-changing endpoints lack anti-CSRF tokens and origin checks.",
        "auth": "Sensitive endpoints permit unauthenticated or weakly authenticated access.",
        "info_leak": "Verbose responses or backup/config endpoints expose internal data.",
        "misconfig": "Insecure defaults or debug features are exposed in production."
    }.get(klass, "Needs manual review.")
    
def coerce_item_schema(d, fallback_seed=None):
    """Normalize AI output to our schema and fill safe defaults."""
    base = minimal_item(fallback_seed or {})
    out = {
        "id": str(d.get("id") or base["id"])[:32],
        "title": (d.get("title") or base["title"]).strip(),
        "class": (d.get("class") or base["class"]).strip().lower(),
        "severity": (d.get("severity") or base["severity"]).strip().lower(),
        "priority": (d.get("priority") or sev_to_priority(d.get("severity")) or base["priority"]).strip().upper(),
        "where": (d.get("where") or base["where"]).strip(),
        "evidence": (d.get("evidence") or base["evidence"]).strip()[:MAX_EVIDENCE_CHARS],
        "root_cause": (d.get("root_cause") or base["root_cause"]).strip(),
        "recommended_remediation": d.get("recommended_remediation") or base["recommended_remediation"],
        "references": d.get("references") or base["references"]
    }
    if out["class"] not in CLASS_ENUM:
        out["class"] = classify_fallback(out["title"], out["where"], out["evidence"])
    if out["severity"] not in ("low","medium","high","critical"):
        out["severity"] = "medium"
    if out["priority"] not in ("P0","P1","P3","P4"):
        out["priority"] = sev_to_priority(out["severity"])
    if not isinstance(out["recommended_remediation"], list):
        out["recommended_remediation"] = [str(out["recommended_remediation"])]
    out["recommended_remediation"] = [str(x).strip() for x in out["recommended_remediation"] if str(x).strip()]
    if not isinstance(out["references"], list):
        out["references"] = [str(out["references"])]
    out["references"] = [str(x).strip() for x in out["references"] if str(x).strip()]
    if not out["recommended_remediation"]:
        out["recommended_remediation"] = REMEDIATION_MAP.get(out["class"], REMEDIATION_MAP["other"])
    if not out["references"]:
        out["references"] = REFS_MAP.get(out["class"], REFS_MAP["other"])
    return out

def extract_json(text):
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
            text = ""
            try:
                text = obj["candidates"][0]["content"]["parts"][0]["text"]
            except Exception:
                text = ""
            if text.strip():
                return text
        except Exception:
            if i < retries-1:
                time.sleep(backoff ** i)
            else:
                return ""
    return ""

INSTRUCTIONS = """
You are a senior AppSec triage assistant. Return STRICT JSON ONLY with this shape: {"items":[ ... ]}
For each input, output: id,title,class (xss|sqli|rce|open_redirect|xslt_injection|csp|csrf|auth|info_leak|misconfig|other),
severity (low|medium|high|critical), priority (P0|P1|P3|P4 via severity map), where, evidence (<=200 chars),
root_cause, recommended_remediation (2-6 bullet strings), references (1-4 URLs). No prose.
If unsure, class="other" and root_cause="Needs manual review." Use generic OWASP/CWE links when unsure.
"""

def build_user_payload(batch):
    items = []
    for it in batch:
        title = it.get("title") or it.get("name") or "Finding"
        where = it.get("url") or it.get("where") or it.get("path") or ""
        ev    = it.get("evidence") or it.get("proof") or ""
        sev   = (it.get("severity") or "medium")
        seed  = minimal_item(it)  # to generate id stable
        items.append({
            "id": seed["id"],
            "title": title,
            "where": where,
            "evidence": ev[:MAX_EVIDENCE_CHARS],
            "severity": sev
        })
    return json.dumps({"findings": items}, ensure_ascii=False)

# ---- Pipeline ----
raw = load_raw_findings(IN_PATH)
os.makedirs(REPORT_DIR, exist_ok=True)
if not raw:
    # Write empty outputs to keep pipeline happy
    with open(OUT_ITEMS, "w", encoding="utf-8") as f: json.dump([], f, indent=2, ensure_ascii=False)
    with open(OUT_GROUPS, "w", encoding="utf-8") as f: json.dump({}, f, indent=2, ensure_ascii=False)
    with open(OUT_GROUPMETA, "w", encoding="utf-8") as f: json.dump({}, f, indent=2, ensure_ascii=False)
    raise SystemExit(0)

# 1) AI-enhanced or deterministic fallback normalization
normalized = []
for batch in chunked(raw, BATCH_SIZE):
    used_ai = False
    if GEMINI_API_KEY:
        prompt = INSTRUCTIONS + "\n\nINPUT JSON:\n" + build_user_payload(batch)
        text = call_gemini(prompt)
        data = extract_json(text)
        if data and isinstance(data.get("items"), list) and data["items"]:
            for src, out in zip(batch, data["items"]):
                normalized.append(coerce_item_schema(out, fallback_seed=src))
            used_ai = True
    if not used_ai:
        normalized.extend([ minimal_item(it) for it in batch ])

# 2) Deduplicate by signature (class+where+title) -> keep highest severity; merge evidence samples
order = {"low":0,"medium":1,"high":2,"critical":3}
dedup = {}
ev_agg = defaultdict(list)
for it in normalized:
    sig = f"{it['class']}|{(it['where'] or '').strip()}|{it['title'].strip()}"
    if sig not in dedup or order[it["severity"]] > order[dedup[sig]["severity"]]:
        dedup[sig] = it
    # collect up to 3 unique evidence snippets
    ev = (it.get("evidence") or "").strip()
    if ev and ev not in ev_agg[sig]:
        ev_agg[sig].append(ev[:MAX_EVIDENCE_CHARS])
        ev_agg[sig] = ev_agg[sig][:3]
for sig, it in dedup.items():
    if ev_agg[sig]:
        it["evidence"] = " | ".join(ev_agg[sig])

all_items = list(dedup.values())

# 3) Write normalized items
with open(OUT_ITEMS, "w", encoding="utf-8") as f:
    json.dump(all_items, f, indent=2, ensure_ascii=False)

# 4) Build compact grouped bodies and metadata for issue creation
groups = defaultdict(list)
for it in all_items:
    groups[it["class"]].append(it)

group_bodies = {}
group_meta   = {}
for g, items in groups.items():
    # Sort by severity then title for a stable reading order
    items.sort(key=lambda x: ({"critical":0,"high":1,"medium":2,"low":3}.get(x["severity"],2), x["title"]))
    total = len(items)

    # pagination / truncation to avoid 65k limit explosions
    chunks = [items[i:i+MAX_ITEMS_PER_GROUP_ISSUE] for i in range(0, total, MAX_ITEMS_PER_GROUP_ISSUE)]
    for part_idx, chunk in enumerate(chunks, 1):
        title_suffix = "" if len(chunks)==1 else f" — Part {part_idx}/{len(chunks)}"
        body_lines = []
        body_lines.append(f"# AI triage summary — {g.upper()}{title_suffix}\n")
        body_lines.append(f"Total items in this part: **{len(chunk)}**")
        if len(chunks) > 1:
            body_lines.append(f"All items in class: **{total}** (split to avoid size limits)")
        body_lines.append("")

        for idx, it in enumerate(chunk, 1):
            body_lines.append(f"## {idx}. {it['title']} *(severity:{it['severity']}, priority:{it['priority']})*")
            if it.get("where"):
                body_lines.append(f"- **Where:** {it['where']}")
            if it.get("evidence"):
                ev = (it['evidence'][:MAX_EVIDENCE_CHARS] + '…') if len(it['evidence'])>MAX_EVIDENCE_CHARS else it['evidence']
                body_lines.append(f"- **Evidence:** `{ev}`")
            if it.get("root_cause"):
                body_lines.append(f"- **Root cause:** {it['root_cause']}")
            rem = it.get("recommended_remediation") or []
            if rem:
                body_lines.append("- **Proposed remediation:**")
                for step in rem[:6]:
                    body_lines.append(f"  - {step}")
            refs = it.get("references") or []
            if refs:
                body_lines.append("- **References:**")
                for r in refs[:4]:
                    body_lines.append(f"  - {r}")
            body_lines.append("")  # spacer

        key = g if len(chunks)==1 else f"{g}__part{part_idx}"
        group_bodies[key] = "\n".join(body_lines)
        group_meta[key] = {
            "class": g,
            "part": part_idx,
            "parts_total": len(chunks),
            "labels": CLASS_LABELS.get(g, CLASS_LABELS["other"]),
            "issue_title": f"[Security][{g.upper()}] AI triage summary{title_suffix} ({len(chunk)} items)"
        }

with open(OUT_GROUPS, "w", encoding="utf-8") as f:
    json.dump(group_bodies, f, indent=2, ensure_ascii=False)
with open(OUT_GROUPMETA, "w", encoding="utf-8") as f:
    json.dump(group_meta, f, indent=2, ensure_ascii=False)

print(f"[AI] normalized items -> {OUT_ITEMS}; total={len(all_items)}")
print(f"[AI] grouped bodies   -> {OUT_GROUPS}; keys={list(group_bodies.keys())}")
print(f"[AI] group meta       -> {OUT_GROUPMETA}; keys={list(group_meta.keys())}")
