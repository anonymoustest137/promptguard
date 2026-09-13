"""HTML report generation, with an optional diff against a previous JSON run.

Keeps the zero-runtime-dependency promise: pure string templating, no
Jinja/etc. Output is a single self-contained HTML file (inline CSS, no
external assets) so it can be uploaded as a CI artifact and opened as-is.
"""
import html
import json
from datetime import datetime, timezone

_CSS = """
:root {
  --bg: #0b0f14; --panel: #121822; --text: #e6edf3; --muted: #8b96a5;
  --ok: #2ea043; --breach: #f85149; --border: #263140; --accent: #58a6ff;
}
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--text); font-family: -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 0; padding: 2rem; }
h1 { margin-top: 0; }
.meta { color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }
.summary { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
.card { background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
        padding: 1rem 1.5rem; min-width: 140px; }
.card .value { font-size: 2rem; font-weight: 700; }
.card .label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.04em; }
.risk-low { color: var(--ok); } .risk-mid { color: #d29922; } .risk-high { color: var(--breach); }
table { width: 100%; border-collapse: collapse; background: var(--panel); border: 1px solid var(--border);
        border-radius: 10px; overflow: hidden; }
th, td { padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }
th { color: var(--muted); text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.04em; }
tr:last-child td { border-bottom: none; }
.badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
.badge-breach { background: rgba(248,81,73,0.15); color: var(--breach); }
.badge-ok { background: rgba(46,160,67,0.15); color: var(--ok); }
.sev-critical { color: #ff6b6b; font-weight: 700; }
.sev-high { color: #f0883e; } .sev-medium { color: #d29922; } .sev-low { color: var(--muted); }
.diff-new { color: var(--breach); font-weight: 600; }
.diff-fixed { color: var(--ok); font-weight: 600; }
.response { color: var(--muted); font-size: 0.8rem; max-width: 480px; white-space: pre-wrap; }
.section-title { margin-top: 2.5rem; margin-bottom: 0.75rem; }
footer { color: var(--muted); font-size: 0.8rem; margin-top: 3rem; }
"""


def _risk_class(score):
    if score < 20:
        return "risk-low"
    if score < 50:
        return "risk-mid"
    return "risk-high"


def _diff(previous_results, current_results):
    """Compare two result lists by probe id. Returns dict with newly_breached
    (regressions), newly_fixed, and unchanged id lists."""
    prev_by_id = {r["id"]: r for r in (previous_results or [])}
    cur_by_id = {r["id"]: r for r in current_results}
    newly_breached, newly_fixed, unchanged = [], [], []
    for pid, cur in cur_by_id.items():
        prev = prev_by_id.get(pid)
        if prev is None:
            continue
        if cur["breached"] and not prev["breached"]:
            newly_breached.append(pid)
        elif not cur["breached"] and prev["breached"]:
            newly_fixed.append(pid)
        else:
            unchanged.append(pid)
    return {"newly_breached": newly_breached, "newly_fixed": newly_fixed, "unchanged": unchanged}


def render_html(results, summary, previous=None, title="promptguard report"):
    """previous: optional (results, summary) tuple from a prior JSON report,
    used to render a regression diff section."""
    generated_at = datetime.now(timezone.utc).isoformat()
    rows = []
    prev_by_id = {r["id"]: r for r in (previous[0] if previous else [])}
    for r in results:
        badge = ('<span class="badge badge-breach">BREACH</span>' if r["breached"]
                 else '<span class="badge badge-ok">ok</span>')
        change = ""
        if previous:
            prev = prev_by_id.get(r["id"])
            if prev is not None:
                if r["breached"] and not prev["breached"]:
                    change = '<span class="diff-new">NEW REGRESSION</span>'
                elif not r["breached"] and prev["breached"]:
                    change = '<span class="diff-fixed">FIXED</span>'
        resp = html.escape((r.get("response") or "")[:200])
        rows.append(f"""
        <tr>
          <td>{html.escape(r["id"])}</td>
          <td>{html.escape(r["category"])}</td>
          <td class="sev-{html.escape(r["severity"])}">{html.escape(r["severity"])}</td>
          <td>{badge}</td>
          <td>{change}</td>
          <td class="response">{resp}</td>
        </tr>""")

    diff_section = ""
    if previous:
        d = _diff(previous[0], results)
        diff_section = f"""
        <h2 class="section-title">Regression diff vs previous run</h2>
        <div class="summary">
          <div class="card"><div class="value diff-new">{len(d['newly_breached'])}</div><div class="label">New breaches</div></div>
          <div class="card"><div class="value diff-fixed">{len(d['newly_fixed'])}</div><div class="label">Newly fixed</div></div>
          <div class="card"><div class="value">{len(d['unchanged'])}</div><div class="label">Unchanged</div></div>
        </div>
        """

    risk_cls = _risk_class(summary["risk_score"])
    by_cat_rows = "".join(
        f"<tr><td>{html.escape(cat)}</td><td>{v['breached']}/{v['total']}</td></tr>"
        for cat, v in sorted(summary.get("by_category", {}).items())
    )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<div class="meta">Generated {generated_at}</div>

<div class="summary">
  <div class="card"><div class="value">{summary['probes_run']}</div><div class="label">Probes run</div></div>
  <div class="card"><div class="value">{summary['breaches']}</div><div class="label">Breaches</div></div>
  <div class="card"><div class="value">{summary['pass_rate']}%</div><div class="label">Pass rate</div></div>
  <div class="card"><div class="value {risk_cls}">{summary['risk_score']}/100</div><div class="label">Risk score</div></div>
</div>

{diff_section}

<h2 class="section-title">Results by category</h2>
<table>
<thead><tr><th>Category</th><th>Breached / Total</th></tr></thead>
<tbody>{by_cat_rows}</tbody>
</table>

<h2 class="section-title">Probe results</h2>
<table>
<thead><tr><th>ID</th><th>Category</th><th>Severity</th><th>Result</th><th>Change</th><th>Response (truncated)</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>

<footer>promptguard - test only systems you own or are authorized to assess.</footer>
</body>
</html>"""


def load_previous_report(path):
    """Load a JSON report previously written by --json, for diffing.
    Returns (results, summary) or None if the file doesn't exist/parse."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("results", []), data.get("summary", {})
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def write_html_report(path, results, summary, previous_json_path=None, title="promptguard report"):
    previous = load_previous_report(previous_json_path) if previous_json_path else None
    html_doc = render_html(results, summary, previous=previous, title=title)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    return path
