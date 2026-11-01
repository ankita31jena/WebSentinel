from flask import Flask, render_template, jsonify, request, send_file
from db import (get_all_scans, get_alerts_by_scan, get_alerts_by_risk,
                count_by_risk, alerts_col, scans_col, get_top_alerts)
from zapv2 import ZAPv2
from dotenv import load_dotenv
import os, time, threading, io

load_dotenv()
app = Flask(__name__)

ZAP_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")
TARGET  = os.getenv("TARGET_URL")
zap = ZAPv2(apikey=ZAP_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

scan_status = {"running": False, "progress": 0, "message": "Idle"}

@app.route("/")
def dashboard():
    risk_data    = count_by_risk()
    risk_summary = {r["_id"]: r["count"] for r in risk_data}
    scans        = get_all_scans()
    total_alerts = sum(risk_summary.values())
    top_alerts   = get_top_alerts(10)
    return render_template("dashboard.html",
        risk_summary=risk_summary,
        scans=scans,
        total_alerts=total_alerts,
        top_alerts=top_alerts
    )

@app.route("/alerts")
def alerts():
    risk_filter = request.args.get("risk", "All")
    scan_filter = request.args.get("scan", "All")
    page = int(request.args.get("page", 1))
    per_page = 50

    query = {}
    if risk_filter != "All":
        query["risk"] = risk_filter
    if scan_filter != "All":
        query["scan_type"] = scan_filter

    total = alerts_col.count_documents(query)
    total_pages = (total + per_page - 1) // per_page
    skip = (page - 1) * per_page

    all_alerts = list(alerts_col.find(query, {"_id": 0}).skip(skip).limit(per_page))
    scan_types = alerts_col.distinct("scan_type")

    return render_template("alerts.html",
        alerts=all_alerts,
        risk_filter=risk_filter,
        scan_filter=scan_filter,
        scan_types=scan_types,
        total=total,
        page=page,
        total_pages=total_pages
    )


@app.route("/alert/<int:idx>")
def alert_detail(idx):
    try:
        alert = list(alerts_col.find({}, {"_id": 0}).skip(idx).limit(1))[0]
    except:
        alert = None
    return render_template("alert_detail.html", alert=alert, idx=idx)

@app.route("/scans")
def scans():
    all_scans = get_all_scans()
    return render_template("scans.html", scans=all_scans)

@app.route("/scan/trigger", methods=["POST"])
def trigger_scan():
    global scan_status
    if scan_status["running"]:
        return jsonify({"status": "already_running"})
    def run_scan():
        global scan_status
        scan_status = {"running": True, "progress": 0, "message": "Spider running..."}
        try:
            sid = zap.spider.scan(TARGET, apikey=ZAP_KEY)
            while int(zap.spider.status(sid)) < 100:
                scan_status["progress"] = int(int(zap.spider.status(sid)) * 0.3)
                time.sleep(3)
            scan_status["message"] = "Active scan running..."
            asid = zap.ascan.scan(TARGET, apikey=ZAP_KEY)
            while int(zap.ascan.status(asid)) < 100:
                scan_status["progress"] = 30 + int(int(zap.ascan.status(asid)) * 0.7)
                time.sleep(10)
            scan_status["message"] = "Saving to MongoDB..."
            from datetime import datetime
            from db import save_scan, save_alerts
            raw = zap.core.alerts(baseurl=TARGET)
            ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_scan({"scan_id": str(asid), "target": TARGET,
                       "timestamp": ts, "urls_found": len(zap.spider.results(sid)),
                       "status": "completed"})
            save_alerts([{
                "scan_id": str(asid), "timestamp": ts,
                "name": a.get("name",""), "risk": a.get("risk",""),
                "confidence": a.get("confidence",""), "url": a.get("url",""),
                "description": a.get("description",""), "solution": a.get("solution",""),
                "reference": a.get("reference","")
            } for a in raw])
            scan_status = {"running": False, "progress": 100, "message": "Scan complete!"}
        except Exception as e:
            scan_status = {"running": False, "progress": 0, "message": f"Error: {str(e)}"}
    threading.Thread(target=run_scan, daemon=True).start()
    return jsonify({"status": "started"})

@app.route("/scan/status")
def scan_status_api():
    return jsonify(scan_status)

@app.route("/report/download")
def download_report():
    try:
        report = zap.core.htmlreport(apikey=ZAP_KEY)
        buf = io.BytesIO(report.encode("utf-8"))
        buf.seek(0)
        return send_file(buf, mimetype="text/html",
                         as_attachment=True,
                         download_name="zap_report.html")
    except Exception as e:
        return f"Error generating report: {e}", 500

@app.route("/api/risk-summary")
def api_risk_summary():
    return jsonify({r["_id"]: r["count"] for r in count_by_risk()})

@app.route("/api/alerts")
def api_alerts():
    return jsonify(list(alerts_col.find({}, {"_id": 0})))


@app.route("/summary")
def summary():
    pipeline = [
        {"$group": {
            "_id": {"scan_type": "$scan_type", "risk": "$risk"},
            "count": {"$sum": 1}
        }}
    ]
    raw = list(alerts_col.aggregate(pipeline))

    summary_data = {}
    for r in raw:
        st = r["_id"].get("scan_type") or "general"
        risk = r["_id"].get("risk", "Unknown")
        summary_data.setdefault(st, {})[risk] = r["count"]

    total_by_type = {st: sum(v.values()) for st, v in summary_data.items()}

    return render_template("summary.html",
        summary_data=summary_data,
        total_by_type=total_by_type)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
