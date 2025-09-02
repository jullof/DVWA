#!/usr/bin/env python3
# create_issues_grouped.py (v2)
import os, json, subprocess, re, sys, urllib.request

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
BODIES     = os.path.join(REPORT_DIR, "ai_bodies.json")
FALLBACK   = os.path.join(REPORT_DIR, "ai_findings.json")

OWNER = os.environ.get("GITHUB_OWNER","")
REPO  = os.environ.get("GITHUB_REPO","")
GH_TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

def infer_repo():
    if OWNER and REPO:
        return OWNER, REPO
    try:
        url = subprocess.check_output(["git","config","--get","remote.origin.url"], text=True).strip()
        m = re.search(r'[:/]([^/]+)/([^/]+?)(?:\.git)?$', url)
        if m: return m.group(1), m.group(2)
    except Exception:
        pass
    return None, None

def post_issue(owner, repo, title, body, labels=None):
    assert GH_TOKEN, "GH_TOKEN/GITHUB_TOKEN not set"
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    data = {"title": title, "body": body, "labels": labels or ["security","automated"]}
    req = urllib.request.Request(url, data=json.dumps(data).encode("utf-8"), method="POST",
                                 headers={"Authorization": f"Bearer {GH_TOKEN}",
                                          "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        obj = json.load(resp)
    print(obj.get("html_url","(no url)"))
    return obj

def load_json(path):
    if not os.path.exists(path): return None
    with open(path,"r",encoding="utf-8") as fh:
        return json.load(fh)

def synthesize_bodies_from_findings(items):
    def block(klass, picks):
        if not picks:
            return f"**{klass.upper()}**: No findings."
        lines = []
        lines.append(f"**{klass.upper()}** findings: {len(picks)}")
        for p in picks[:50]:
            lines.append(f"- `{p.get('severity','')}` **{p.get('title','')}** → {p.get('url','')}")
        return "\n".join(lines)
    out = {}
    for k in ("xss","sqli","rce","other"):
        out[k] = block(k,[i for i in items if i.get("class")==k])
    return out

def mk_labels(sev_counts, prio_counts, base=None):
    labels = set(base or [])
    labels.update({"security","dast","auto"})
    if sev_counts:
        top_sev = max(sev_counts, key=lambda k: sev_counts[k])
        labels.add(f"sev:{top_sev}")
    if prio_counts:
        top_pr = max(prio_counts, key=lambda k: prio_counts[k])
        labels.add(f"prio:{top_pr}")
    return sorted(labels)

def main():
    owner, repo = infer_repo()
    if not (owner and repo):
        print("Could not infer repo (set GITHUB_OWNER/GITHUB_REPO or configure git remote).", file=sys.stderr)
        sys.exit(2)

    bodies_json = load_json(BODIES)
    findings = load_json(FALLBACK) or []

    if not bodies_json:
        # fallback bodies
        groups = synthesize_bodies_from_findings(findings)
        bodies_json = {k: {"body": v} for k,v in groups.items()}

    titles = {
        "xss":   "Security: XSS findings (AI-refined)",
        "sqli":  "Security: SQLi findings (AI-refined)",
        "rce":   "Security: RCE findings (AI-refined)",
        "other": "Security: Other findings (AI-refined)",
    }

    by_class = {"xss":[], "sqli":[], "rce":[], "other":[]}
    for f in findings:
        by_class.get(f.get("class","other"), by_class["other"]).append(f)

    for klass in ("xss","sqli","rce","other"):
        base_body = (bodies_json.get(klass) or {}).get("body") or f"No {klass} findings."
        picks = by_class.get(klass, [])[:10]
        if picks:
            base_body += "\n\n---\n\n### Top 10 detailed items\n"
            for x in picks:
                prov = x.get("provenance") or {}
                urls = ", ".join(prov.get("urls") or ([x.get("url")] if x.get("url") else []))
                refs = "".join(f"\n  - {r}" for r in (x.get("references") or [])[:6])
                base_body += f"""
**{x.get('title','')}**  
- **Severity:** {x.get('severity','')} | **Priority:** {x.get('ai_priority','P3')} | **FP?** {x.get('ai_suspected_fp', False)}
- **Why opened:** {x.get('why_opened','')}
- **Where:** {urls}
- **Rule/Plugin:** {prov.get('rule_or_plugin','')}
- **Evidence:** {", ".join((prov.get("evidence") or [])[:2])}
- **Remediation:** {x.get('remediation','')}
- **References:**{refs}
"""
        sev_counts  = {}
        prio_counts = {}
        for x in by_class.get(klass, []):
            sev_counts[x.get("severity","unknown")] = sev_counts.get(x.get("severity","unknown"),0)+1
            prio_counts[x.get("ai_priority","P3")] = prio_counts.get(x.get("ai_priority","P3"),0)+1

        labels = mk_labels(sev_counts, prio_counts, base=["security","dast","auto"])
        post_issue(owner, repo, titles[klass], base_body.strip(), labels=labels)

if __name__ == "__main__":
    main()
