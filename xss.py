from zapv2 import ZAPv2
from db import alerts_col
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")
XSS_TARGET = "http://127.0.0.1/dvwa/vulnerabilities/xss_r/?name=test"

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

def spider_xss_page():
    print("[*] Spidering XSS page...")
    sid = zap.spider.scan(XSS_TARGET, apikey=API_KEY)
    time.sleep(2)
    while int(zap.spider.status(sid)) < 100:
        print(f"    Spider: {zap.spider.status(sid)}%")
        time.sleep(3)
    print(f"[+] Spider done. URLs: {len(zap.spider.results(sid))}")

def run_xss_scan():
    print("[*] Starting XSS targeted active scan...")
    scan_id = zap.ascan.scan(XSS_TARGET, apikey=API_KEY)
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"    XSS Scan: {zap.ascan.status(scan_id)}%")
        time.sleep(8)
    print("[+] XSS Scan complete!")
    return scan_id

def collect_xss_alerts(scan_id):
    all_alerts = zap.core.alerts(
        baseurl="http://127.0.0.1/dvwa/vulnerabilities/xss_r"
    )
    xss_alerts = [a for a in all_alerts if
                  "xss" in a.get("name","").lower() or
                  "cross-site" in a.get("name","").lower() or
                  "script" in a.get("name","").lower()]

    print(f"\n[+] XSS alerts found: {len(xss_alerts)}")
    print(f"[+] Total alerts on XSS page: {len(all_alerts)}")
    print("-" * 60)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    docs = []
    for a in all_alerts:
        docs.append({
            "scan_id":     f"xss_{scan_id}",
            "scan_type":   "targeted_xss",
            "timestamp":   ts,
            "name":        a.get("name",""),
            "risk":        a.get("risk",""),
            "confidence":  a.get("confidence",""),
            "url":         a.get("url",""),
            "param":       a.get("param",""),
            "attack":      a.get("attack",""),
            "description": a.get("description",""),
            "solution":    a.get("solution",""),
        })
        print(f"  [{a.get('risk','?'):13}] {a.get('name','')}")
        if a.get("attack"):
            print(f"              Attack: {a.get('attack','')[:60]}")

    if docs:
        alerts_col.insert_many(docs)
        print(f"\n[✓] {len(docs)} alerts saved to MongoDB (scan_type: targeted_xss)")
    return docs

if __name__ == "__main__":
    spider_xss_page()
    scan_id = run_xss_scan()
    collect_xss_alerts(scan_id)
    print("\n[✓] Day 6 XSS scan complete!")
