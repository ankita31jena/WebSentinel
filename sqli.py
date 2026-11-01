from zapv2 import ZAPv2
from db import alerts_col
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")
TARGET  = "http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

def login_dvwa():
    print("[*] Logging into DVWA...")
    session = requests.Session()
    session.proxies = {"http": ZAP_URL, "https": ZAP_URL}
    session.verify = False
    r = session.get("http://127.0.0.1/dvwa/login.php")
    session.post("http://127.0.0.1/dvwa/login.php", data={
        "username": "admin", "password": "password",
        "Login": "Login", "user_token": ""
    })
    session.post("http://127.0.0.1/dvwa/security.php",
                 data={"security": "low", "seclev_submit": "Submit"})
    print("[+] Logged in successfully")
    return session.cookies.get_dict()

def run_sqli_scan():
    print("[*] Starting SQLi targeted active scan on DVWA...")
    scan_id = zap.ascan.scan(
        TARGET,
        scanpolicyname=None,
        apikey=API_KEY
    )
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        pct = zap.ascan.status(scan_id)
        print(f"    SQLi Scan: {pct}%")
        time.sleep(8)
    print("[+] SQLi Scan complete!")
    return scan_id

def collect_sqli_alerts(scan_id):
    all_alerts = zap.core.alerts(baseurl="http://127.0.0.1/dvwa/vulnerabilities/sqli")
    sqli_alerts = [a for a in all_alerts if
                   "sql" in a.get("name","").lower() or
                   "injection" in a.get("name","").lower()]

    print(f"\n[+] SQL Injection alerts found: {len(sqli_alerts)}")
    print(f"[+] Total alerts on SQLi page: {len(all_alerts)}")
    print("-" * 60)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    docs = []
    for a in all_alerts:
        docs.append({
            "scan_id":     f"sqli_{scan_id}",
            "scan_type":   "targeted_sqli",
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
        if a.get("param"):
            print(f"              Param : {a.get('param','')}")
        if a.get("attack"):
            print(f"              Attack: {a.get('attack','')[:60]}")

    if docs:
        alerts_col.insert_many(docs)
        print(f"\n[✓] {len(docs)} alerts saved to MongoDB (scan_type: targeted_sqli)")
    return docs

if __name__ == "__main__":
    login_dvwa()
    scan_id = run_sqli_scan()
    collect_sqli_alerts(scan_id)
    print("\n[✓] Day 6 SQLi scan complete!")
