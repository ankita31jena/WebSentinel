from zapv2 import ZAPv2 

API_KEY = 'zapkey123'
ZAP_URL = 'http://127.0.0.1:8080'

zap = ZAPv2(apikey=API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})

alerts = zap.core.alerts()
print(f"[+] Total passive alerts found: {len(alerts)}")
print("-" * 50)
for a in alerts:
    print(f"  Risk: {a['risk']:10} | Name: {a['name']}")

