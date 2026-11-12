"""Run the detector on a log file and build a SIEM-style HTML dashboard.

Usage: python dashboard.py logs/sample_auth.log
Outputs: reports/alerts.json and reports/dashboard.html
"""
import html
import json
import os
import sys

from detector import detect, parse_log, summarize

COLORS = {"CRITICAL": "#b71c1c", "HIGH": "#e65100", "MEDIUM": "#f9a825"}


def build_html(summary, alerts, source):
    esc = html.escape
    cards = "".join(
        f'<div class="card"><div class="num" style="color:{COLORS[s]}">{n}</div>'
        f'<div class="lbl">{s}</div></div>'
        for s, n in summary["severity"].items()
    )
    top = max((n for _, n in summary["top_ips"]), default=1)
    bars = "".join(
        f'<div class="bar-row"><span class="ip">{esc(ip)}</span>'
        f'<span class="bar" style="width:{int(n / top * 100)}%"></span>'
        f'<span class="n">{n}</span></div>'
        for ip, n in summary["top_ips"]
    )
    rows = "".join(
        f'<tr><td>{esc(a["time"])}</td>'
        f'<td><span class="badge" style="background:{COLORS[a["severity"]]}">{a["severity"]}</span></td>'
        f'<td>{esc(a["rule"])}</td><td>{esc(a["ip"])}</td><td>{esc(a["user"])}</td>'
        f'<td>{esc(a["detail"])}</td></tr>'
        for a in sorted(alerts, key=lambda a: a["time"])
    )
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Security Monitoring Dashboard</title>
<style>
body{{font-family:Arial,sans-serif;margin:24px;background:#f4f6f8;color:#1f2933}}
h1{{margin:0 0 4px}} .sub{{color:#6b7785;margin-bottom:20px}}
.cards{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px}}
.card{{background:#fff;border-radius:8px;padding:14px 22px;box-shadow:0 1px 3px #0002}}
.num{{font-size:30px;font-weight:bold}} .lbl{{font-size:12px;color:#6b7785}}
.panel{{background:#fff;border-radius:8px;padding:16px;margin-bottom:20px;box-shadow:0 1px 3px #0002}}
.bar-row{{display:flex;align-items:center;gap:8px;margin:6px 0}}
.ip{{width:120px;font-family:monospace}} .bar{{background:#1f3864;height:14px;border-radius:3px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
th,td{{text-align:left;padding:8px;border-bottom:1px solid #e4e7eb}} th{{background:#eef1f5}}
.badge{{color:#fff;padding:2px 8px;border-radius:10px;font-size:11px}}
</style></head><body>
<h1>Security Monitoring Dashboard</h1>
<div class="sub">Source: {esc(source)} &middot; {summary["total"]} events &middot; {summary["failed"]} failed logins</div>
<div class="cards">{cards}</div>
<div class="panel"><h3>Top source IPs by failed logins</h3>{bars}</div>
<div class="panel"><h3>Alerts</h3>
<table><tr><th>Time</th><th>Severity</th><th>Rule</th><th>IP</th><th>User</th><th>Detail</th></tr>{rows}</table></div>
</body></html>"""


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "logs/sample_auth.log"
    events = parse_log(path)
    alerts = detect(events)
    summary = summarize(events, alerts)

    os.makedirs("reports", exist_ok=True)
    with open("reports/alerts.json", "w") as f:
        json.dump(alerts, f, indent=2)
    with open("reports/dashboard.html", "w") as f:
        f.write(build_html(summary, alerts, path))

    print(f"Parsed {summary['total']} events, {summary['failed']} failed logins")
    for a in sorted(alerts, key=lambda a: a["time"]):
        print(f"[{a['severity']:<8}] {a['time']}  {a['rule']:<24} {a['ip']:<15} {a['detail']}")
    print("Wrote reports/alerts.json and reports/dashboard.html")


if __name__ == "__main__":
    main()
