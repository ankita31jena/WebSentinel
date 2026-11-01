from db import alerts_col
from datetime import datetime

def generate_report():
    all_alerts = list(alerts_col.find({}, {"_id": 0}))
    total = len(all_alerts)

    risk_count = {}
    scan_type_count = {}
    for a in all_alerts:
        r = a.get("risk", "Unknown")
        st = a.get("scan_type", "general") or "general"
        risk_count[r] = risk_count.get(r, 0) + 1
        scan_type_count[st] = scan_type_count.get(st, 0) + 1

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html><head><title>OWASP ZAP Consolidated Report</title>
<style>
body{{font-family:Arial;background:#0f172a;color:#e2e8f0;padding:30px}}
h1{{color:#60a5fa}} h2{{color:#93c5fd;border-bottom:1px solid #334155;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;margin:15px 0}}
th{{background:#1F5C99;color:#fff;padding:10px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #334155}}
.stat{{display:inline-block;background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin:10px;min-width:150px;text-align:center}}
.stat .num{{font-size:32px;font-weight:bold;color:#60a5fa}}
</style></head><body>
<h1>OWASP ZAP — Consolidated Vulnerability Report</h1>
<p>Generated: {ts} | Target: DVWA (http://127.0.0.1/dvwa) | Project: Padmanathan — Infotact Solutions</p>

<h2>Overall Summary</h2>
<div class="stat"><div class="num">{total}</div>Total Alerts</div>
<div class="stat"><div class="num">{risk_count.get('High',0)}</div>High Risk</div>
<div class="stat"><div class="num">{risk_count.get('Medium',0)}</div>Medium Risk</div>
<div class="stat"><div class="num">{risk_count.get('Low',0)}</div>Low Risk</div>

<h2>Alerts by Scan Type</h2>
<table><tr><th>Scan Type</th><th>Count</th></tr>
{''.join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in scan_type_count.items())}
</table>

<h2>Alerts by Risk Level</h2>
<table><tr><th>Risk</th><th>Count</th></tr>
{''.join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k,v in risk_count.items())}
</table>

<h2>Full Alert Listing</h2>
<table><tr><th>#</th><th>Name</th><th>Risk</th><th>Scan Type</th><th>URL</th></tr>
{''.join(f"<tr><td>{i+1}</td><td>{a.get('name','')}</td><td>{a.get('risk','')}</td><td>{a.get('scan_type','general') or 'general'}</td><td>{a.get('url','')[:70]}</td></tr>" for i,a in enumerate(all_alerts))}
</table>
</body></html>"""

    with open("/home/kali/zap_project/reports/consolidated_report.html", "w") as f:
        f.write(html)
    print(f"[✓] Consolidated report generated: {total} alerts")
    print(f"[✓] Saved to ~/zap_project/reports/consolidated_report.html")

if __name__ == "__main__":
    generate_report()
