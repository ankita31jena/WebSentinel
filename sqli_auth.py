from zapv2 import ZAPv2
from db import alerts_col
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")
SQLI_URL = "http://127.0.0.1/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit"

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

def login_and_browse():
    """Login via plain requests.Session through ZAP proxy, then browse
    the SQLi page so ZAP records it in its Sites tree with cookies attached."""
    print("[*] Logging into DVWA via session...")
    session = requests.Session()
    session.proxies = {"http": ZAP_URL, "https": ZAP_URL}
    session.verify = False

    session.get("http://127.0.0.1/dvwa/login.php")
    session.post("http://127.0.0.1/dvwa/login.php", data={
        "username": "admin", "password": "password", "Login": "Login"
    })
    session.post("http://127.0.0.1/dvwa/security.php",
                 data={"security": "low", "seclev_submit": "Submit"})
    print("[+] Logged in, security set to low")

    # Browse the SQLi page a few times with different IDs so ZAP
    # records it as a known URL with valid session cookies attached
    print("[*] Browsing SQLi page to register it in ZAP Sites tree...")
    for test_id in ["1", "2", "3"]:
        r = session.get(
            f"http://127.0.0.1/dvwa/vulnerabilities/sqli/?id={test_id}&Submit=Submit",
            timeout=10)
        print(f"    Browsed id={test_id} -> HTTP {r.status_code}")
        time.sleep(0.5)

    print("[+] SQLi page now in ZAP Sites tree with valid session")
    return session

def run_sqli_scan():
    """Run a plain (non-forced-user) active scan on the now-known URL.
    Since ZAP already has cookies from the browsed requests in its
    session store, this avoids the repeated re-authentication that
    triggers the Insights auto-shutdown."""
    print("\n[*] Running SQLi active scan (no auth context needed)...")
    scan_id = zap.ascan.scan(SQLI_URL, apikey=API_KEY)
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        pct = zap.ascan.status(scan_id)
        print(f"    SQLi Scan: {pct}%")
        time.sleep(8)
    print("[+] SQLi Scan complete!")
    return scan_id

def collect_and_save(scan_id):
    print("\n[*] Collecting alerts...")
    alerts = zap.core.alerts(
        baseurl="http://127.0.0.1/dvwa/vulnerabilities/sqli")

    sqli_specific = [a for a in alerts if
                      "sql" in a.get("name","").lower() or
                      "injection" in a.get("name","").lower()]

    print(f"[+] SQL Injection-specific alerts: {len(sqli_specific)}")
    print(f"[+] Total alerts on SQLi page: {len(alerts)}")
    print("-" * 60)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    docs = []
    for a in alerts:
        docs.append({
            "scan_id":     f"sqli_v2_{scan_id}",
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
            print(f"               Param : {a.get('param','')}")

    if docs:
        alerts_col.insert_many(docs)
        print(f"\n[\u2713] {len(docs)} alerts saved to MongoDB (scan_type: targeted_sqli)")
    return docs

if __name__ == "__main__":
    login_and_browse()
    scan_id = run_sqli_scan()
    collect_and_save(scan_id)
    print("\n[\u2713] Day 9 SQLi scan complete \u2014 no ZAP crash!")
