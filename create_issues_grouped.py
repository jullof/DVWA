#!/usr/bin/env python3
"""
Create grouped GitHub issues from AI-enriched findings.
Groups: xss, sqli, rce, other
Env:
  GH_TOKEN (required), GITHUB_REPO (owner/repo), REPORT_DIR (default: reports)
"""
import os, sys, json, urllib.request, urllib.error, base64, time

REPORT_DIR   = os.environ.get("REPORT_DIR","reports")
AI_PATH      = os.path.join(REPORT_DIR, "ai_findings.json")
BODIES_PATH  = os.path.join(REPORT_DIR, "ai_bodies.json")  # optional, not required
GH_TOKEN     = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
REPO         = os.environ.get("GITHUB_REPO","")

API_BASE = "https://api.github.com"

def die(msg, code=1):
    print(msg, file=sys.stderr); sys.exit(code)

if not GH_TOKEN: die("GH_TOKEN/GITHUB_TOKEN is not set.")
if not REPO or "/" not in REPO: die("GITHUB_REPO must be like 'owner/repo'.")

try:
    with open(AI_PATH,"r",encoding="utf-8") as fh:
        findings = json.load(fh)
except FileNotFoundError:
    die(f"{AI_PATH} not found.", 0)

groups = {"xss":[], "sqli":[], "rce":[], "other":[]}
for f in findings:
    groups.get(f.get("class","other"), groups["other"]).append(f)

def post_issue(title, body):
    url = f"{API_BASE}/repos/{REPO}/issues"
    data = {"title": title, "body": body}
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"token {GH_TOKEN}",
            "Accept": "application/vnd.github+json",
            "Content-Type":"application/json",
            "User-Agent":"security-pipeline-bot"
        }
    )
    with urllib.request.urlopen(req, timeout=60) as r:
        resp = json.loads(r.read().decode("utf-8"))
    return resp.get("html_url","")

def hdr(txt): return f"## {txt}\n"
def code(s): return f"`{s}`" if s else ""

def as_table_rows(items, limit=15):
    rows = ["| Severity | Title | Where | Priority |",
            "| --- | --- | --- | --- |"]
    for x in items[:limit]:
        rows.append(f"| {code(x.get('severity',''))} | {x.get('title','')} | {code(x.get('where',''))} | {code(x.get('ai_priority','P3'))} |")
    return "\n".join(rows)

def as_details(items, limit=80):
    chunks = []
    for x in items[:limit]:
        refs = x.get("references") or []
        if isinstance(refs, str): refs = [refs]
        refs_md = "\n".join([f"- {r}" for r in refs[:6]])

        prov = x.get("provenance") or {}
        evidence = ", ".join((prov.get("evidence") or [])[:2])

        chunk = (
f"""- **{x.get('title','')}** ({code(x.get('severity',''))}, {code(x.get('ai_priority','P3'))})
  - **Why:** {x.get('why_opened','')}
  - **Where:** {code(x.get('where',''))}
  - **Rule/Plugin:** {code(prov.get('rule_or_plugin',''))}
  - **Evidence:** {evidence}
  - **Recommended remediation:** {x.get('remediation','')}
  - **References:**
{refs_md}"""
        )
        chunks.append(chunk)
    return "\n\n".join(chunks)

def build_issue_body(group_name, items):
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    intro = f"Grouped findings for **{group_name.upper()}** (generated {ts}).\n"
    table = as_table_rows(items)
    details = as_details(items)
    return intro + "\n" + table + "\n\n<details><summary>Details (first 80)</summary>\n\n" + details + "\n\n</details>"

order = ["xss","sqli","rce","other"]
created = []
for g in order:
    items = groups.get(g, [])
    if not items: continue
    title = f"[Security][{g.upper()}] AI triage summary ({len(items)} items)"
    body  = build_issue_body(g, items)
    try:
        url = post_issue(title, body)
        print(url)
        created.append(url)
    except urllib.error.HTTPError as e:
        print(f"GitHub API error {e.code}: {e.read().decode(errors='ignore')}", file=sys.stderr)
    except Exception as e:
        print(f"Error creating issue: {e}", file=sys.stderr)

if not created:
    print("No issues created (no findings).")
