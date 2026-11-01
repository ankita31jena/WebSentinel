from zapv2 import ZAPv2
from db import save_scan, save_alerts
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os

load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
TARGET  = os.getenv("TARGET_URL")
ZAP_URL = os.getenv("ZAP_URL")

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

def login_dvwa():
    print("[*] Logging into DVWA...")
    session = requests.Session()
    session.proxies = {"http": ZAP_URL, "https": ZAP_URL}

    # Get login page to grab CSRF token
    login_url = "http://127.0.0.1/dvwa/login.php"
    r = session.get(login_url, verify=False)

    # Login POST
    data = {
        "username": "admin",
        "password": "password",
        "Login":    "Login",
        "user_token": ""
    }
    r = session.post(login_url, data=data, verify=False)

    # Set security to low
    session.get("http://127.0.0.1/dvwa/security.php", verify=False)
    session.post("http://127.0.0.1/dvwa/security.php",
                 data={"security": "low", "seclev_submit": "Submit"}, verify=False)

    cookies = session.cookies.get_dict()
    print(f"[+] Logged in. Session cookies: {list(cookies.keys())}")
    return cookies

def run_spider(cookies):
    print("[*] Running authenticated Spider...")
    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
    zap.core.set_option_single_cookie_request_header(True, apikey=API_KEY)

    scan_id = zap.spider.scan(TARGET, apikey=API_KEY)
    time.sleep(2)
    while int(zap.spider.status(scan_id)) < 100:
        print(f"    Spider: {zap.spider.status(scan_id)}%")
        time.sleep(3)

    urls = zap.spider.results(scan_id)
    print(f"[+] Spider found {len(urls)} URLs")
    return urls

def run_active_scan():
    print("[*] Running Active Scan...")
    scan_id = zap.ascan.scan(TARGET, apikey=API_KEY)
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        pct = zap.ascan.status(scan_id)
        print(f"    Active Scan: {pct}%")
        time.sleep(10)
    print("[+] Active Scan complete!")
    return scan_id

def collect_and_save(scan_id, urls):
    print("[*] Collecting alerts and saving to MongoDB...")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    scan_doc = {
        "scan_id":   str(scan_id),
        "target":    TARGET,
        "timestamp": timestamp,
        "urls_found": len(urls),
        "status":    "completed"
    }
    save_scan(scan_doc)

    raw_alerts = zap.core.alerts(baseurl=TARGET)
    alerts_to_save = []
    for a in raw_alerts:
        alerts_to_save.append({
            "scan_id":     str(scan_id),
            "timestamp":   timestamp,
            "name":        a.get("name", ""),
            "risk":        a.get("risk", ""),
            "confidence":  a.get("confidence", ""),
            "url":         a.get("url", ""),
            "description": a.get("description", ""),
            "solution":    a.get("solution", ""),
            "reference":   a.get("reference", ""),
        })

    save_alerts(alerts_to_save)
    print(f"[+] Saved {len(alerts_to_save)} alerts to MongoDB")

    # Risk summary
    risk_count = {}
    for a in alerts_to_save:
        r = a["risk"]
        risk_count[r] = risk_count.get(r, 0) + 1

    print("\n[+] Risk Summary:")
    for risk, count in sorted(risk_count.items()):
        print(f"    {risk:15} : {count}")

    return alerts_to_save

if __name__ == "__main__":
    cookies = login_dvwa()
    urls    = run_spider(cookies)
    scan_id = run_active_scan()
    alerts  = collect_and_save(scan_id, urls)
    print("\n[✓] Day 3 Complete — Scan saved to MongoDB!")
