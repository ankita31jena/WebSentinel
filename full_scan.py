from zapv2 import ZAPv2
from db import alerts_col
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

# DVWA pages not yet targeted in earlier scans
TARGETS = [
    "http://127.0.0.1/dvwa/vulnerabilities/brute/",
    "http://127.0.0.1/dvwa/vulnerabilities/csrf/",
    "http://127.0.0.1/dvwa/vulnerabilities/upload/",
    "http://127.0.0.1/dvwa/vulnerabilities/captcha/",
    "http://127.0.0.1/dvwa/vulnerabilities/sqli_blind/",
    "http://127.0.0.1/dvwa/vulnerabilities/weak_id/",
]

def login_and_browse():
    print("[*] Logging into DVWA...")
    session = requests.Session()
    session.proxies = {"http": ZAP_URL, "https": ZAP_URL}
    session.verify = False
    session.get("http://127.0.0.1/dvwa/login.php")
    session.post("http://127.0.0.1/dvwa/login.php", data={
        "username": "admin", "password": "password", "Login": "Login"
    })
    session.post("http://127.0.0.1/dvwa/security.php",
                 data={"security": "low", "seclev_submit": "Submit"})
    print("[+] Logged in — security set to low")

    print("[*] Browsing all target pages to register in ZAP Sites tree...")
    for url in TARGETS:
        try:
            r = session.get(url, timeout=10)
            print(f"    {url.split('/')[-2]:20} -> HTTP {r.status_code}")
        except Exception as e:
            print(f"    Error: {url} -> {e}")
        time.sleep(0.5)
    print("[+] All target pages registered in ZAP")
    return session

def run_full_scan():
    print("\n[*] Running full active scan on all DVWA pages...")
    base = "http://127.0.0.1/dvwa"
    scan_id = zap.ascan.scan(base, recurse=True, apikey=API_KEY)
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        pct = zap.ascan.status(scan_id)
        print(f"    Full Scan: {pct}%")
        time.sleep(10)
    print("[+] Full scan complete!")
    return scan_id

def collect_and_save(scan_id):
    print("\n[*] Collecting and saving alerts...")
    all_alerts = zap.core.alerts(baseurl="http://127.0.0.1/dvwa")
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Only save alerts from pages not previously scanned
    already_covered = [
        "/vulnerabilities/sqli?",
        "/vulnerabilities/xss_r",
        "/vulnerabilities/fi/",
        "/vulnerabilities/exec/",
    ]
    new_alerts = [a for a in all_alerts
                  if not any(p in a.get("url","") for p in already_covered)]

    docs = [{
        "scan_id":     f"full_{scan_id}",
        "scan_type":   "full_scan",
        "timestamp":   ts,
        "name":        a.get("name",""),
        "risk":        a.get("risk",""),
        "confidence":  a.get("confidence",""),
        "url":         a.get("url",""),
        "param":       a.get("param",""),
        "attack":      a.get("attack",""),
        "description": a.get("description",""),
        "solution":    a.get("solution",""),
    } for a in new_alerts]

    risk_count = {}
    for a in new_alerts:
        r = a.get("risk","?")
        risk_count[r] = risk_count.get(r, 0) + 1

    print(f"\n[+] New alerts from uncovered pages: {len(new_alerts)}")
    print(f"[+] Total alerts from full scan: {len(all_alerts)}")
    print("\n[+] Risk Summary:")
    for r, c in sorted(risk_count.items()):
        print(f"    {r:15} : {c}")

    if docs:
        alerts_col.insert_many(docs)
        print(f"\n[✓] {len(docs)} new alerts saved (scan_type: full_scan)")
    return docs

if __name__ == "__main__":
    login_and_browse()
    scan_id = run_full_scan()
    collect_and_save(scan_id)
    print("\n[✓] Day 10 full scan complete!")
