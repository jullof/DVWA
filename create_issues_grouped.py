#!/usr/bin/env python3
import os, json, subprocess, re, sys, urllib.request

REPORT_DIR = os.environ.get("REPORT_DIR","reports")
BODIES = os.path.join(REPORT_DIR, "ai_bodies.json")
FALLBACK = os.path.join(REPORT_DIR, "ai_findings.json")

OWNER = os.environ.get("GITHUB_OWNER","")
REPO  = os.environ.get("GITHUB_REPO","")
GH_TOKEN = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")

def infer_repo():
    if OWNER and REPO:
        return OWNER, REPO
    # try git remote
    try:
        url = subprocess.check_output(["git","config","--get","remote.origin.url"], text=True).strip()
        # normalize
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
                                 headers={"Authorization": f"Bearer {GH_TOKEN}", "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        obj = json.load(resp)
    print(obj.get("html_url","(no url)"))
    return obj

def load_bodies():
    if os.path.exists(BODIES):
        with open(BODIES,"r",encoding="utf-8") as fh: 
            data = json.load(fh)
        # Some earlier versions produced {"xss":{"body":""},...}
        return {k:(v.get("body") if isinstance(v,dict) else str(v)) for k,v in data.items()}
    return {}

def fallback_bodies():
    if not os.path.exists(FALLBACK):
        return {}
    with open(FALLBACK,"r",encoding="utf-8") as fh:
        items = json.load(fh)
    def synth(klass):
        picks = [i for i in items if i.get("class")==klass]
        if not picks:
            return f"**{klass.upper()}**: No findings."
        head = "\n".join(f"- `{p.get('severity','')}` **{p.get('name','')}** → {p.get('url','')}" for p in picks[:50])
        return f"Auto-generated from ai_findings.json (no AI body).\n\n{head}"
    return {k: synth(k) for k in ("xss","sqli","rce","other")}

def main():
    owner, repo = infer_repo()
    if not (owner and repo):
        print("Could not infer repo (set GITHUB_OWNER/GITHUB_REPO or configure git remote).", file=sys.stderr)
        sys.exit(2)

    bodies = load_bodies()
    if not bodies or all(not (bodies.get(k) or '').strip() for k in bodies):
        bodies = fallback_bodies()

    titles = {
        "xss":   "Security: XSS findings (AI-refined)",
        "sqli":  "Security: SQLi findings (AI-refined)",
        "rce":   "Security: RCE findings (AI-refined)",
        "other": "Security: Other findings (AI-refined)",
    }

    for k in ("xss","sqli","rce","other"):
        body = bodies.get(k) or f"No {k} findings."
        post_issue(owner, repo, titles[k], body, labels=["security","dast","auto"])

if __name__ == "__main__":
    main()
