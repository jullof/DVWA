#!/usr/bin/env python3
# collector_normalize.py
import os, json, subprocess, re

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
ZAP_JSON   = os.path.join(REPORT_DIR, os.environ.get("REPORT_JSON","zap_report.json"))
SG_JSON    = os.path.join(REPORT_DIR, "semgrep.json")
SNYK_SCA   = os.path.join(REPORT_DIR, "snyk_sca.json")
SNYK_CONT  = os.path.join(REPORT_DIR, "snyk_container.json")
OUT_PATH   = os.path.join(REPORT_DIR, "findings_raw.json")

def slurp_json(path):
    if not os.path.exists(path): return None
    txt = open(path, "r", encoding="utf-8", errors="ignore").read().strip()
    if not txt: return None
    if txt.startswith("{"):
        try: return json.loads(txt)
        except: pass
    objs=[]
    for line in txt.splitlines():
        line=line.strip()
        if not line: continue
        try: objs.append(json.loads(line))
        except: pass
    return objs if objs else None

def sev_norm(s):
    s = (s or "").lower()
    if s in ("informational","info"): return "informational"
    if s in ("low",): return "low"
    if s in ("warning","medium"): return "medium"
    if s in ("error","high","critical"): return "high"
    return "low"

def class_hint(title, desc):
    t = f"{title} {desc}".lower()
    if re.search(r'\b(xss|cross[- ]?site[- ]?scripting)\b', t): return "xss"
    if re.search(r'\b(sqli|sql[- ]?injection)\b', t): return "sqli"
    if re.search(r'\b(rce|remote code execution|command injection|code execution)\b', t): return "rce"
    return "other"

def changed_files():
    base = os.environ.get("GIT_PREVIOUS_SUCCESSFUL_COMMIT") or ""
    head = os.environ.get("GIT_COMMIT") or "HEAD"
    if not base: return set()
    try:
        out = subprocess.check_output(["git","diff","--name-only",f"{base}..{head}"], stderr=subprocess.DEVNULL)
        return set(out.decode().split())
    except:
        return set()

changed = changed_files()
all_findings = []

# DAST (ZAP)
z = slurp_json(ZAP_JSON)
if z:
    sites = z.get("site",[])
    if isinstance(sites, dict): sites=[sites]
    for site in sites:
        for a in site.get("alerts",[]) or []:
            inst = a.get("instances") or []
            url = next((i.get("uri") or i.get("url") for i in inst if (i.get("uri") or i.get("url"))), "N/A")
            title = a.get("alert","")
            desc  = (a.get("desc") or "").strip()
            sev   = sev_norm(a.get("risk") or a.get("riskdesc","").split(" ")[0])
            rid   = str(a.get("pluginid") or "")
            all_findings.append({
                "source":"ZAP","type":"dast",
                "rule_id":rid,"title":title,"severity":sev,
                "location":{"url":url},
                "description":desc,
                "evidence":a.get("otherinfo","") or "",
                "cwe": [],
                "class_hint": class_hint(title, desc),
                "changed_in_diff": False
            })

# SAST (Semgrep)
sg = slurp_json(SG_JSON)
if sg and isinstance(sg, dict):
    for r in sg.get("results",[]):
        path = (r.get("path") or "").strip()
        line = r.get("start",{}).get("line")
        title= r.get("check_id") or (r.get("extra",{}).get("message") or "Semgrep finding")
        desc = r.get("extra",{}).get("message") or ""
        sev  = sev_norm(r.get("extra",{}).get("severity"))
        cwe  = r.get("extra",{}).get("metadata",{}).get("cwe") or []
        all_findings.append({
            "source":"Semgrep","type":"sast",
            "rule_id": r.get("check_id"),
            "title": title,"severity": sev,
            "location":{"file":path,"line": line},
            "description": desc,
            "evidence": "",
            "cwe": cwe,
            "class_hint": class_hint(title, desc),
            "changed_in_diff": bool(path and path in changed)
        })

# SCA (Snyk app deps)
sca = slurp_json(SNYK_SCA)
def iter_snyk(obj):
    if not obj: return
    if isinstance(obj, list):
        for o in obj: yield from iter_snyk(o)
    elif isinstance(obj, dict) and "vulnerabilities" in obj:
        for v in obj["vulnerabilities"]: yield v

for v in iter_snyk(sca):
    sev  = sev_norm(v.get("severity"))
    title= v.get("title") or v.get("id") or "Snyk vuln"
    desc = v.get("description") or ""
    pkg  = v.get("package") or ""
    cwe  = (v.get("identifiers",{}) or {}).get("CWE") or []
    all_findings.append({
        "source":"Snyk","type":"sca",
        "rule_id": v.get("id"),
        "title": f"{title} ({pkg})" if pkg else title,
        "severity": sev,
        "location":{"package":pkg},
        "description": desc,
        "evidence": "",
        "cwe": cwe,
        "class_hint": class_hint(title, desc),
        "changed_in_diff": False
    })

# SCA (Snyk container)
cont = slurp_json(SNYK_CONT)
for v in iter_snyk(cont):
    sev  = sev_norm(v.get("severity"))
    title= v.get("title") or v.get("id") or "Image vuln"
    desc = v.get("description") or ""
    pkg  = v.get("package") or (v.get("name") or "")
    cwe  = (v.get("identifiers",{}) or {}).get("CWE") or []
    all_findings.append({
        "source":"Snyk","type":"sca",
        "rule_id": v.get("id"),
        "title": f"{title} ({pkg})" if pkg else title,
        "severity": sev,
        "location":{"package":pkg},
        "description": desc,
        "evidence": "",
        "cwe": cwe,
        "class_hint": class_hint(title, desc),
        "changed_in_diff": False
    })

os.makedirs(REPORT_DIR, exist_ok=True)
with open(OUT_PATH,"w",encoding="utf-8") as f:
    json.dump({"findings": all_findings}, f, ensure_ascii=False, indent=2)
print(f"[COLLECTOR] normalized -> {OUT_PATH}; total={len(all_findings)}")
