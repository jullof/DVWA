#!/usr/bin/env python3
# ai_triage.py 
import os, json, subprocess, time, urllib.request

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
IN_PATH    = os.path.join(REPORT_DIR, "findings_raw.json")
OUT_PATH   = os.path.join(REPORT_DIR, "ai_findings.json")
BODIES_OUT = os.path.join(REPORT_DIR, "ai_bodies.json")

OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
OPENAI_MODEL   = os.environ.get("OPENAI_MODEL","gpt-5")
OPENAI_BASE    = os.environ.get("OPENAI_BASE","https://api.openai.com/v1/chat/completions")

TARGET_URL = os.environ.get("TARGET_URL","http://127.0.0.1:8080")
APP_HOST   = os.environ.get("APP_HOST","")
VERIFY_URL = f"http://{APP_HOST}:8080" if APP_HOST else TARGET_URL

AI_THRESHOLD = float(os.environ.get("AI_THRESHOLD","0.6") or 0.6)
BUILD_NO     = os.environ.get("BUILD_NUMBER","")
BUILD_URL    = os.environ.get("BUILD_URL","")

NEEDS_HEADER = { "10020":"X-Frame-Options","10021":"X-Content-Type-Options","10038":"Content-Security-Policy","10063":"Permissions-Policy" }
QUICK_FP_DAST = set(["90004"])  # Spectre

def curl_head(url:str)->str:
    try:
        out = subprocess.check_output(["curl","-sS","-I","-L",url], timeout=10)
        return out.decode("utf-8","ignore")
    except Exception:
        return ""

def header_present(head:str, name:str)->bool:
    name_l = name.lower()
    for line in head.splitlines():
        if ":" in line:
            k,v = line.split(":",1)
            if k.strip().lower()==name_l:
                return True
    return False

SYS_PROMPT = (
  "You are an AppSec triage assistant. Be conservative; if uncertain, mark as FP or lower confidence. "
  "Use live header checks when provided. Return ONLY valid JSON for every answer."
)

def _openai_chat(messages, max_tokens=800, temperature=0.1):
    body = {"model": OPENAI_MODEL, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
    req = urllib.request.Request(
      OPENAI_BASE, data=json.dumps(body).encode(),
      headers={"Content-Type":"application/json","Authorization":f"Bearer {OPENAI_API_KEY}"}
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        data = json.load(resp)
    return data["choices"][0]["message"]["content"]

def build_item_payload(item):
    schema = {
      "is_fp":"boolean",
      "confidence":"0.0-1.0",
      "why":"short justification",
      "attack_class":"xss|sqli|rce|other",
      "recom":"minimal stack-aware fix or empty",
      "references":"IDs only (e.g., CWE-79, OWASP-ASVS-5.x)"
    }
    guard = {
      "allowed_headers":["Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Permissions-Policy","Strict-Transport-Security","Referrer-Policy"],
      "apache_steps":["a2enmod headers","Header always set <Name> \"<Value>\"","ServerTokens Prod","ServerSignature Off"],
      "php_session":["session.cookie_samesite","session.cookie_httponly","session.cookie_secure","session_set_cookie_params","@ini_set"],
      "rules":"If live_check.header_missing_confirmed=false, prefer FP with rationale. Map 'command injection' to 'rce'."
    }
    ctx = { "App":"DVWA","Runtime":"PHP 8.2 + Apache","TargetBase": VERIFY_URL }
    return json.dumps({"Context":ctx,"Finding":item,"Schema":schema,"Guardrails":guard}, ensure_ascii=False)

def triage_one(item):
    try:
        content = _openai_chat(
            [{"role":"system","content":SYS_PROMPT},
             {"role":"user","content": build_item_payload(item)}],
            max_tokens=600, temperature=0.1
        )
        out = json.loads(content.strip())
        return {
          "is_fp": bool(out.get("is_fp",False)),
          "confidence": float(out.get("confidence",0.0) or 0.0),
          "why": str(out.get("why","")),
          "attack_class": str(out.get("attack_class","other")),
          "recom": str(out.get("recom","")),
          "references": out.get("references") or []
        }
    except Exception as e:
        return {"is_fp":False,"confidence":0.0,"why":f"llm_error:{e}","attack_class":"other","recom":"","references":[]}

raw = json.load(open(IN_PATH,"r",encoding="utf-8"))
refined = []

for f in raw.get("findings",[]):
    live = {"checked":False,"header_missing_confirmed":False,"header_name":""}
    if f.get("source")=="ZAP" and f.get("rule_id") in NEEDS_HEADER:
        url = (f.get("location") or {}).get("url") or VERIFY_URL
        head = curl_head(url)
        live["checked"] = True
        live["header_name"] = NEEDS_HEADER[f["rule_id"]]
        live["header_missing_confirmed"] = not header_present(head, live["header_name"])

    item = {
      "source": f.get("source"),
      "type": f.get("type"),
      "rule_id": f.get("rule_id"),
      "title": f.get("title"),
      "severity": f.get("severity"),
      "location": f.get("location"),
      "description": f.get("description",""),
      "evidence": f.get("evidence",""),
      "cwe": f.get("cwe") or [],
      "class_hint": f.get("class_hint","other"),
      "changed_in_diff": bool(f.get("changed_in_diff")),
      "live_check": live
    }

    tri = triage_one(item)

    if live["checked"] and live["header_missing_confirmed"] is False:
        tri["is_fp"] = True
        tri["confidence"] = max(tri["confidence"], 0.8)
        tri["why"] = (tri.get("why","") + " | live_check: header present").strip(" |")

    if f.get("source")=="ZAP" and f.get("rule_id") in QUICK_FP_DAST and not tri["is_fp"]:
        tri["confidence"] = min(tri["confidence"], 0.5)
        tri["why"] = (tri.get("why","") + " | quick_hint: likely benign").strip(" |")

    f["ai"] = tri
    refined.append(f)
    time.sleep(0.25)

json.dump({"findings":refined}, open(OUT_PATH,"w",encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"[AI] refined -> {OUT_PATH}; total={len(refined)}")

def build_issue_template():
    return (
"""You will craft final GitHub issue bodies per class (XSS, SQLi, RCE, Other) in a strict Markdown template.
Use ONLY the provided normalized items. Do not invent URLs/files. Keep it concise.

### REQUIRED MARKDOWN TEMPLATE (use literally):
# <Class Title> — AI-refined Security Findings

**Build:** #<BUILD_NUMBER>  <BUILD_URL>  
**Generated:** <UTC-ISO>  
**Scope:** ZAP (DAST) + Semgrep (SAST) + Snyk (SCA)  
**Policy:** Only AI-refined True Positives (confidence ≥ <AI_THRESHOLD>)

---

## Summary
- Total: <N>  |  High: <H>  |  Medium: <M>  |  Low: <L>  |  Info: <I>
- Top risks: <top 3 titles or '—'>

---

## Findings (sorted by severity desc, confidence desc)

### <Index>. [<Severity>] <Title>
- **Source/Type:** <ZAP|Semgrep|Snyk> / <dast|sast|sca>  
- **Location:** <URL | file:line | package | N/A>  
- **AI:** confidence=<0.00-1.00>  
- **Why:** <short justification>  
- **Suggested fix (AI):**  
  <one-paragraph minimal, stack-aware fix or '—'>  
- **References:** <CWE/ASVS ids or '—'>

(repeat for all findings)

---

## Notes
- False positives and low-confidence findings are excluded by policy.
- Header-related DAST rules were live-checked (curl -I).
"""
)

def class_title_map():
    return {
      "xss":"Security: XSS findings (AI-refined)",
      "sqli":"Security: SQLi findings (AI-refined)",
      "rce":"Security: RCE findings (AI-refined)",
      "other":"Security: Other findings (AI-refined)"
    }

def summarize_counts(items):
    sev = [ (i.get("severity","informational") or "").lower() for i in items ]
    h = sum(s=="high" for s in sev)
    m = sum(s=="medium" for s in sev)
    l = sum(s=="low" for s in sev)
    i = sum(s=="informational" for s in sev)
    return {"total":len(items),"high":h,"medium":m,"low":l,"info":i}

buckets = {"xss":[],"sqli":[],"rce":[],"other":[]}
for f in refined:
    ai = f.get("ai",{})
    if ai.get("is_fp"): 
        continue
    if float(ai.get("confidence",0.0) or 0.0) < AI_THRESHOLD:
        continue
    cls = (ai.get("attack_class") or f.get("class_hint","other"))
    if cls not in buckets: cls="other"
    # Location string
    loc = f.get("location") or {}
    where = loc.get("url") or (f"{loc.get('file')}:{loc.get('line')}" if loc.get('file') else None) or loc.get("package") or "N/A"
    buckets[cls].append({
        "severity": f.get("severity","informational"),
        "title": f.get("title",""),
        "source": f.get("source"),
        "type": f.get("type"),
        "where": where,
        "confidence": float(ai.get("confidence",0.0) or 0.0),
        "why": (ai.get("why") or ""),
        "recom": (ai.get("recom") or ""),
        "references": ai.get("references") or []
    })

payload = {
  "build": {"number": BUILD_NO, "url": BUILD_URL, "threshold": AI_THRESHOLD},
  "template": build_issue_template(),
  "classes": [],
}
titles = class_title_map()
for cls, items in buckets.items():
    payload["classes"].append({
      "key": cls, "title": titles[cls],
      "summary": summarize_counts(items),
      "items": sorted(items, key=lambda x:({"high":3,"medium":2,"low":1,"informational":0}[x["severity"].lower()], x["confidence"]), reverse=True)
    })

ai_bodies = {}
try:
    content = _openai_chat(
      [
        {"role":"system","content": "You are a meticulous technical writer for AppSec reports. Output JSON only."},
        {"role":"user","content": json.dumps({
          "instruction":"For each class, render the REQUIRED MARKDOWN TEMPLATE fully populated. Keep exactly the headings and bullet labels.",
          "data": payload
        }, ensure_ascii=False)}
      ],
      max_tokens=3500, temperature=0.1
    )
    parsed = json.loads(content.strip())
    # beklenen format: { "xss": {"body":"..."}, "sqli":{"body":"..."}, "rce":{"body":"..."}, "other":{"body":"..."} }
    if isinstance(parsed, dict):
        for k in ("xss","sqli","rce","other"):
            v = parsed.get(k)
            if isinstance(v, dict) and isinstance(v.get("body"), str) and v["body"].strip():
                ai_bodies[k] = v
except Exception as e:
    ai_bodies = {}

json.dump(ai_bodies, open(BODIES_OUT,"w",encoding="utf-8"), ensure_ascii=False, indent=2)
print(f"[AI] class bodies -> {BODIES_OUT}; keys={list(ai_bodies.keys())}")
