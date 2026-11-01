from zapv2 import ZAPv2
from db import alerts_col
from dotenv import load_dotenv
from datetime import datetime
import requests, time, os, urllib3

urllib3.disable_warnings()
load_dotenv()

API_KEY = os.getenv("ZAP_API_KEY")
ZAP_URL = os.getenv("ZAP_URL")
TARGET  = "http://127.0.0.1/dvwa"

zap = ZAPv2(apikey=API_KEY, proxies={"http": ZAP_URL, "https": ZAP_URL})
zap.forcedUser.set_forced_user_mode_enabled(False, apikey=API_KEY)

def setup_auth_context():
    print("[*] Setting up ZAP authentication context...")

    # Create context
    ctx_id = zap.context.new_context("dvwa_auth", apikey=API_KEY)
    print(f"[+] Context ID: {ctx_id}")

    # Include DVWA in context
    zap.context.include_in_context("dvwa_auth",
        "http://127.0.0.1/dvwa.*", apikey=API_KEY)

    # Set form-based authentication
    zap.authentication.set_authentication_method(
        ctx_id,
        "formBasedAuthentication",
        "loginUrl=http://127.0.0.1/dvwa/login.php"
        "&loginRequestData=username%3D{%25username%25}"
        "%26password%3D{%25password%25}%26Login%3DLogin",
        apikey=API_KEY
    )

    # Set logged-in indicator
    zap.authentication.set_logged_in_indicator(
        ctx_id, "logout.php", apikey=API_KEY)

    # Set logged-out indicator
    zap.authentication.set_logged_out_indicator(
        ctx_id, "login.php", apikey=API_KEY)

    # Create user
    user_id = zap.users.new_user(ctx_id, "admin", apikey=API_KEY)
    zap.users.set_authentication_credentials(
        ctx_id, user_id,
        "username=admin&password=password",
        apikey=API_KEY
    )
    zap.users.set_user_enabled(ctx_id, user_id, True, apikey=API_KEY)

    # Force user
    zap.forcedUser.set_forced_user(ctx_id, user_id, apikey=API_KEY)
    zap.forcedUser.set_forced_user_mode_enabled(True, apikey=API_KEY)

    print(f"[+] Auth context ready — User ID: {user_id}")
    return ctx_id, user_id

def run_auth_spider(ctx_id, user_id):
    print("[*] Running authenticated spider...")
    sid = zap.spider.scan_as_user(
        ctx_id, user_id, TARGET, apikey=API_KEY)
    time.sleep(2)
    while int(zap.spider.status(sid)) < 100:
        print(f"    Auth Spider: {zap.spider.status(sid)}%")
        time.sleep(3)
    urls = zap.spider.results(sid)
    print(f"[+] Auth Spider found {len(urls)} URLs")
    for u in urls:
        print(f"    {u}")
    return urls

def run_sqli_auth_scan(ctx_id, user_id):
    print("\n[*] Spidering SQLi page first (required before scan_as_user)...")
    sqli_url = "http://127.0.0.1/dvwa/vulnerabilities/sqli/"
    sid = zap.spider.scan_as_user(ctx_id, user_id, sqli_url, apikey=API_KEY)
    time.sleep(2)
    while int(zap.spider.status(sid)) < 100:
        print(f"    Pre-scan Spider: {zap.spider.status(sid)}%")
        time.sleep(2)
    print("[+] SQLi page now in Sites tree")

    print("\n[*] Running authenticated SQLi scan...")
    scan_id = zap.ascan.scan_as_user(
        sqli_url, ctx_id, user_id,
        recurse=True, apikey=API_KEY)
    time.sleep(2)
    while int(zap.ascan.status(scan_id)) < 100:
        print(f"    SQLi Auth Scan: {zap.ascan.status(scan_id)}%")
        time.sleep(8)
    print("[+] Authenticated SQLi scan complete!")

    alerts = zap.core.alerts(baseurl=sqli_url)
    sqli = [a for a in alerts if "sql" in a.get("name","").lower()
            or "injection" in a.get("name","").lower()]

    print(f"\n[+] SQLi alerts: {len(sqli)}")
    print(f"[+] Total alerts on page: {len(alerts)}")

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    docs = [{
        "scan_id": f"sqli_auth_{scan_id}",
        "scan_type": "targeted_sqli_auth",
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
        if a.get("attack"):
            print(f"               Attack: {a.get('attack','')[:50]}")

    print(f"\n[✓] {len(docs)} alerts saved (scan_type: targeted_sqli_auth)")
    return docs

if __name__ == "__main__":
    ctx_id, user_id = setup_auth_context()
    run_auth_spider(ctx_id, user_id)
    run_sqli_auth_scan(ctx_id, user_id)
    print("\n[✓] Day 7 Auth Context + SQLi complete!")
