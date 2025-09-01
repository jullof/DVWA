#!/usr/bin/env python3
# create_issues_grouped.py — AI body prefer / fallback deterministic
import os, json, subprocess
from datetime import datetime
from collections import Counter

repo        = os.environ["GITHUB_REPO"]
reportdir   = os.environ.get("REPORT_DIR","reports")
findings_p  = os.path.join(reportdir, "ai_findings.json")
bodies_p    = os.path.join(reportdir, "ai_bodies.json")  # <- YENİ
show_recom  = os.environ.get("SHOW_RECOM","true").lower() == "true"
threshold   = float(os.environ.get("AI_THRESHOLD","0.6"))
fail_on     = os.environ.get("FAIL_ON_RISK","none").lower()
build_no    = os.environ.get("BUILD_NUMBER","")
build_url   = os.environ.get("BUILD_URL","")

BUCKETS = {
  "xss":  {"title":"Security: XSS findings (AI-refined)",  "label":"class:xss"},
  "sqli": {"title":"Security: SQLi findings (AI-refined)", "label":"class:sqli"},
  "rce":  {"title":"Security: RCE findings (AI-refined)",  "label":"class:rce"},
  "other":{"title":"Security: Other findings (AI-refined)","label":"class:other"}
}
SEV_ORDER = {"high":3, "medium":2, "low":1, "informational":0}
def risk_level(s): return SEV_ORDER.get((s or "").lower(), 0)

def upsert_label(name):
    subprocess.run(["gh","label","create",name,"-R",repo,"-c","CCCCCC","--force"], check=False)

def find_issue_by_title(title):
    out = subprocess.run(["gh","issue","list","-R",repo,"--search",f'title:"{title}" state:open','--json','number','--limit','1'],
                         capture_output=True, text=True, check=False)
    try:
        arr = json.loads(out.stdout or "[]")
        return arr[0]["number"] if arr else None
    except: return None

def update_or_create(title, label, body):
    for L in ["ZAP","Semgrep","Snyk","ai:tp",label]:
        upsert_label(L)
    n = find_issue_by_title(title)
    if n:
        subprocess.run(["gh","issue","edit",str(n),"-R",repo,"-b",body], check=True)
        print(f"Updated issue #{n} ({title})")
    else:
        cmd = ["gh","issue","create","-R",repo,"-t",title,"-b",body,"-l","ai:tp","-l",label]
        subprocess.run(cmd, check=True)
        print(f"Created issue ({title})")

def summarize(items):
    cnt = Counter((e["risk"] or "Informational").capitalize() for e in items)
    H = cnt.get("High",0); M = cnt.get("Medium",0); L = cnt.get("Low",0); I = cnt.get("Informational",0)
    total = len(items)
    return total, H, M, L, I

def body_for_class(cls_title, items):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    total, H, M, L, I = summarize(items)
    top3 = [e["title"] for e in sorted(items, key=lambda x:(-risk_level(x["risk"]), -x["confidence"]))[:3]]
    topline = ", ".join(top3) if top3 else "—"

    header = (
f"# {cls_title}\n\n"
f"**Build:** #{build_no}  {build_url}\n"
f"**Generated:** {now}\n"
f"**Scope:** ZAP (DAST) + Semgrep (SAST) + Snyk (SCA)\n"
f"**Policy:** Only AI-refined True Positives (confidence ≥ {threshold})\n\n"
"---\n\n"
"## Summary\n"
f"- Total: {total}  |  High: {H}  |  Medium: {M}  |  Low: {L}  |  Info: {I}\n"
f"- Top risks: {topline}\n\n"
"---\n\n"
"## Findings (sorted by severity desc, confidence desc)\n\n"
    )

    if not items:
        return header + "✅ No actionable findings in this class.\n\n---\n\n## Notes\n- False positives and low-confidence findings are excluded by policy.\n- Header-related DAST rules were live-checked (curl -I).\n"

    lines = []
    items_sorted = sorted(items, key=lambda x:(-risk_level(x["risk"]), -x["confidence"]))
    for i, e in enumerate(items_sorted, 1):
        recom = (e['recom'].strip() if e.get('recom') else "")
        ref = e.get('references') or []
        ref_str = ", ".join(ref) if ref else "—"
        if not show_recom or not recom:
            recom = "—"
        lines.append(
f"### {i}. [{e['risk']}] {e['title']}\n"
f"- **Source/Type:** {e['source']} / {e['type']}\n"
f"- **Location:** {e['where']}\n"
f"- **AI:** confidence={e['confidence']:.2f}\n"
f"- **Why:** {e['why']}\n"
f"- **Suggested fix (AI):**\n  {recom}\n"
f"- **References:** {ref_str}\n"
        )
    tail = "\n---\n\n## Notes\n- False positives and low-confidence findings are excluded by policy.\n- Header-related DAST rules were live-checked (curl -I).\n"
    return header + "\n".join(lines) + tail

# ---- load data ----
data = json.load(open(findings_p,"r",encoding="utf-8"))
try:
    ai_bodies = json.load(open(bodies_p,"r",encoding="utf-8"))
except Exception:
    ai_bodies = {}

SEV_ORDER = {"high":3,"medium":2,"low":1,"informational":0}
max_seen = 0

bucket_items = {k: [] for k in BUCKETS}

for it in data.get("findings",[]):
    ai = it.get("ai",{}) or {}
    if ai.get("is_fp"): continue
    conf = float(ai.get("confidence",0.0) or 0.0)
    if conf < threshold: continue

    sev = (it.get("severity") or "informational").lower()
    max_seen = max(max_seen, SEV_ORDER.get(sev,0))
    cls = (ai.get("attack_class") or it.get("class_hint","other"))
    if cls not in bucket_items: cls = "other"

    loc = it.get("location") or {}
    where = loc.get("url") or (f"{loc.get('file')}:{loc.get('line')}" if loc.get('file') else None) or loc.get("package") or "N/A"

    bucket_items[cls].append({
      "risk": sev.capitalize(),
      "source": it.get("source"),
      "type": it.get("type"),
      "title": it.get("title",""),
      "where": where,
      "why": (ai.get("why","") or "").strip(),
      "recom": (ai.get("recom","") or "").strip(),
      "confidence": conf,
      "references": ai.get("references") or []
    })

for cls, meta in BUCKETS.items():
    title = meta["title"]; label = meta["label"]
    ai_body = ""
    if isinstance(ai_bodies.get(cls), dict):
        ai_body = ai_bodies.get(cls,{}).get("body","") or ""
    if ai_body.strip():
        body = ai_body
    else:
        body = body_for_class(title, bucket_items[cls])
    update_or_create(title, label, body)

# risk gate
gate = {"none":99, "medium":2, "high":3}.get(fail_on, 99)
if max_seen >= gate:
    raise SystemExit(2)
