from zapv2 import ZAPv2
import time

API_KEY='zapkey123'
TARGET='http://127.0.0.1/dvwa'
ZAP_URL='http://127.0.0.1:8080'

zap =ZAPv2(apikey=API_KEY, proxies={'http':ZAP_URL,'https':ZAP_URL})

print("[*] Starting spider on ",TARGET)
scan_id = zap.spider.scan(TARGET, apikey=API_KEY)
time.sleep(2)

while int(zap.spider.status(scan_id))<100:
    pct = zap.spider.status(scan_id)
    print(f" spider progress: {pct}%")
    time.sleep(3)

print("[+] Spider complete!")
print(f"[+] URLs found: {len(zap.spider.results(scan_id))}")
for url in zap.spider.results(scan_id):
    print(" ",url)











