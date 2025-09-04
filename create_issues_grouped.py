#!/usr/bin/env python3
# create_issues_grouped.py — English-only, rich Markdown, grouped by class

import os, sys, json, time, html, hashlib, urllib.request, urllib.error

REPORT_DIR = os.environ.get("REPORT_DIR", "reports")
IN_PATH    = os.path.join(REPORT_DIR, "ai_findings.json")

GH_TOKEN   = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
REPO_FULL  = os.environ.get("GITHUB_REPO", "").strip()  # e.g. "owner/repo"

API_ROOT   = "https://api.github.com"

BADGE_COLORS = {
    "critical": "d73a4a",  # red
    "high":     "d73a4a",
    "medium":   "dbab09",  # yellow-ish
    "low":      "0e8a16",  # green
    "info":     "6a737d",  # gray
    "unknown":  "6a737d",
}

# -------- helpers --------

def esc(s: str) -> str:
    if s is None: return ""
    # escape pipes so tables/inline code don’t break
    return str(s).replace("|", "\\|").strip()

def mk_badge(text: str, color: str) -> str:
    # shields.io static badge
    t = urllib.parse.quote(str(text))
    c = urllib.parse.quote(color)
    return f"![](https://img.shields.io/badge/{t}-{c}.svg)"

def sev_badge(sev: str) -> str:
    color = BADGE_COLORS.get((sev or "").lower(), BADGE_COLORS["unknown"])
    return mk_badge(f"severity:{sev.lower() or 'unknown'}", color)

def prio_badge(p: str) -> str:
    # P0–P4
    p = (p or "P3").upper()
    color = {
        "P0": "d73a4a", "P1": "d73a4a",
        "P2": "dbab09",
        "P3": "0e8a16",
        "P4": "6a737d"
    }.get(p, "6a737d")
    return mk_badge(f"priority:{p}", color)

def trim(s: str, n=500):
    s = (s or "").strip()
    return (s if len(s) <= n else (s[:n-3] + "..."))

def split_remediation(rem: str):
    """Turn '1) ..., 2) ...' or '1. ...' or lines into a numbered list."""
    rem = (rem or "").strip()
    if not rem:
        return []
    # Try to split on numbered bullets
    import re
    parts = re.split(r"(?:^|\s)(?:\d+[\)\.]\s+)", rem)
    parts = [p.strip(" \n\r\t-•") for p in parts if p and p.strip(" \n\r\t-•")]
    if len(parts) >= 2:
        return parts
    # Fallback: split lines
    lines = [l.strip(" -•") for l in rem.splitlines() if l.strip(" -•")]
    if lines: return lines
    # Last fallback: single item
    return [rem]

def uniq_keep_order(seq):
    seen = set(); out = []
    for x in seq:
        if x in seen: continue
        seen.add(x); out.append(x)
    return out

def http_post_json(url, payload, headers):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers=headers)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read().decode("utf-8")), r.getcode()

def create_issue(owner_repo: str, title: str, body: str, labels=None):
    if not GH_TOKEN or not owner_repo or "/" not in owner_repo:
        raise RuntimeError("Missing GH_TOKEN or invalid GITHUB_REPO (expected owner/repo)")
    url = f"{API_ROOT}/repos/{owner_repo}/issues"
    headers = {
        "Authorization": f"token {GH_TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "User-Agent": "ai-triage-bot",
    }
    payload = {"title": title, "body": body, "labels": labels or ["security", "ai-triage"]}
    return http_post_json(url, payload, headers)

# -------- load --------

try:
    with open(IN_PATH, "r", encoding="utf-8") as fh:
        findings = json.load(fh)
except FileNotFoundError:
    print(f"[ISSUES] {IN_PATH} not found, nothing to publish.")
    sys.exit(0)
except Exception as e:
    print(f"[ISSUES] Failed to read {IN_PATH}: {e}")
    sys.exit(1)

if not isinstance(findings, list) or not findings:
    print("[ISSUES] No findings to publish.")
    sys.exit(0)

# -------- group by class --------

from collections import defaultdict
groups = defaultdict(list)
for f in findings:
    groups[(f.get("class") or "other").lower()].append(f)

stamp = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime())

# -------- body builder per group --------

def render_finding_block(f):
    sev = (f.get("severity") or "unknown").lower()
    pr  = (f.get("ai_priority") or "P3").upper()

    # url(s)
    urls = []
    prov = f.get("provenance") or {}
    purls = prov.get("urls") or []
    if not purls and f.get("url"):
        purls = [f.get("url")]
    for u in purls:
        if u:
            urls.append(f"[{esc(u)}]({esc(u)})")
    where_line = ", ".join(uniq_keep_order(urls)) if urls else "_n/a_"

    # rule / cwe
    rule = esc(prov.get("rule_or_plugin") or f.get("pluginId") or "")
    cwe  = esc(f.get("cwe") or "")
    rule_line = rule if rule else "_n/a_"
    if cwe:
        rule_line = f"{rule_line} (CWE: {cwe})" if rule_line != "_n/a_" else f"CWE: {cwe}"

    # evidence (trim)
    ev = trim(f.get("evidence") or (", ".join(prov.get("evidence") or []) if prov else ""), 500)
    ev_md = f"\n```\n{ev}\n```" if ev else ""

    # remediation → numbered list
    rem_items = split_remediation(f.get("remediation") or "")
    if rem_items:
        rem_md = "\n".join([f"   {i+1}. {esc(it)}" for i, it in enumerate(rem_items)])
    else:
        rem_md = "   1. Review and validate\n   2. Apply fix\n   3. Retest\n   4. Deploy"

    # references (2–6 links)
    refs = f.get("references") or []
    if isinstance(refs, str):
        refs = [refs]
    refs = [r for r in refs if isinstance(r, str) and r.strip()]
    refs = uniq_keep_order(refs)[:6]
    refs_md = "\n".join([f"- {esc(r)}" for r in refs]) if refs else "- https://owasp.org/www-project-top-ten/\n- https://cwe.mitre.org/"

    title = esc(f.get("title") or f.get("name") or "Finding")
    sev_b = sev_badge(sev)
    pr_b  = prio_badge(pr)

    block = []
    block.append(f"**{title}** {sev_b} {pr_b}")
    why = esc(f.get("why_opened") or "Potential risk identified; manual review recommended.")
    block.append(f"- **Why:** {why}")
    block.append(f"- **Where:** {where_line}")
    block.append(f"- **Rule/Plugin:** {rule_line}")
    if ev_md:
        block.append(f"- **Evidence:**{ev_md}")
    block.append(f"- **Recommended remediation:**\n{rem_md}")
    block.append(f"- **References:**\n{refs_md}")
    return "\n".join(block)

def build_issue_body(group_name: str, items):
    # Header
    header = [
        f"# AI triage summary — **{group_name.upper()}**",
        "",
        f"_Generated: {stamp}_",
        "",
        f"Total items: **{len(items)}**",
        ""
    ]

    # Sort: critical/high first, then by priority, then title
    sev_order = {"critical":0,"high":1,"medium":2,"low":3,"info":4,"unknown":5}
    prio_order = {"P0":0,"P1":1,"P2":2,"P3":3,"P4":4}
    items_sorted = sorted(items, key=lambda x: (
        sev_order.get((x.get('severity') or 'unknown').lower(), 5),
        prio_order.get((x.get('ai_priority') or 'P3').upper(), 3),
        (x.get('title') or '')
    ))

    blocks = []
    for f in items_sorted:
        blocks.append(render_finding_block(f))
        blocks.append("")  # spacer

    return "\n".join(header + blocks).strip()

# -------- create issues --------

created = []
for klass, items in groups.items():
    title = f"[Security][{klass.upper()}] AI triage summary ({len(items)} items)"
    body  = build_issue_body(klass, items)
    labels = ["security", "ai-triage", klass.lower()]
    try:
        res, code = create_issue(REPO_FULL, title, body, labels)
        url = res.get("html_url", "")
        print(url or f"[{klass}] created (status {code})")
        created.append(url or title)
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8", errors="ignore")
        print(f"[ISSUES] GitHub error ({e.code}): {err}")
    except Exception as e:
        print(f"[ISSUES] Failed to create issue for {klass}: {e}")

if not created:
    print("[ISSUES] No issues created.")
