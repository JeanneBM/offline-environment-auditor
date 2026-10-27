"""Self-contained local reports: no scripts, external assets or clickable input URLs."""
from collections import Counter
import html
import json
from pathlib import Path


def render_html(report):
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    for finding in report["findings"]:
        rows.append("<tr>" + "".join("<td>" + esc(finding[key]) + "</td>" for key in
                    ("severity", "resource", "title", "evidence", "recommendation", "owner")) + "</tr>")
    limitations = "".join("<li>" + esc(x) + "</li>" for x in report["coverage"]["limitations"])
    counts = dict(Counter(f["severity"] for f in report["findings"]))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Offline environment audit</title>
<style>body{font:16px system-ui,sans-serif;margin:2rem;color:#172033;background:#f5f7fa}main{max-width:1500px;margin:auto}h1{margin-bottom:.4rem}.card{background:white;padding:1.2rem;border:1px solid #dbe2ea;border-radius:8px;margin:1rem 0}.scroll{overflow:auto}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:.8rem;text-align:left;border-bottom:1px solid #ddd;vertical-align:top}td{overflow-wrap:anywhere;max-width:26rem}th{background:#eef2f7}code{white-space:pre-wrap}li{margin:.5rem 0}</style></head><body><main>
<h1>Offline environment audit</h1><p>Evidence-based review items, not a security certification.</p>
<section class="card"><strong>Assessment: """ + esc(report["assessment"]) + "</strong><p>Coverage: " + esc(report["coverage"]["status"]) + "</p><p>Generated: " + esc(report["generated_at"]) + "</p><p>Findings by severity: " + esc(counts) + "</p></section>" + \
        '<section class="card"><h2>Coverage and limitations</h2><ul>' + limitations + "</ul></section>" + \
        '<section class="card scroll"><h2>Findings</h2><table><thead><tr>' + \
        "".join("<th>" + x + "</th>" for x in ("Severity", "Resource", "Finding", "Evidence", "Recommended review", "Owner")) + \
        "</tr></thead><tbody>" + ("".join(rows) or '<tr><td colspan="6">No findings in the checked scope. Review coverage limitations.</td></tr>') + \
        "</tbody></table></section></main></body></html>"


def write_report(directory, report):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    (directory / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (directory / "report.html").write_text(render_html(report), encoding="utf-8")


def write_existing(directory, report):
    """Only for an exclusively created scan run directory owned by this operation."""
    directory = Path(directory)
    with (directory / "report.json").open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    with (directory / "report.html").open("x", encoding="utf-8") as stream:
        stream.write(render_html(report))
