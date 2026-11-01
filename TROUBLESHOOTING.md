# OWASP ZAP Project — Troubleshooting Guide

## Issue 1: ZAP daemon dies a few seconds/minutes after starting
**Cause:** Linux OOM (Out of Memory) killer terminates the Java process when system RAM is exhausted.
**Check:** `free -h` -- if "available" is under 1GB, this is likely the cause.
**Fix:**
sudo systemctl stop elasticsearch kibana
sudo systemctl disable elasticsearch kibana
Launch ZAP with a capped heap: `-Xmx1024m`

## Issue 2: ZAP shuts down mid-scan with "Shutting down ZAP due to High Level Insight: EXCEEDED_HIGH : insight.auth.failure"
**Cause:** ZAP's built-in Insights safety feature auto-terminates the daemon after 100+ repeated authentication attempts. This happens with form-based auth contexts that re-authenticate on every spider/scan request.
**Fix:** Launch ZAP with `-config insights.enabled=false`
**Better fix:** Avoid auth contexts entirely for simple cases -- use a requests.Session() with manual login + cookie reuse instead of ZAP's built-in authentication context system (see Day 9 approach).

## Issue 3: "Connection refused" port 8080 errors in Python scripts
**Cause:** ZAP isn't running (crashed or never started) when the script tries to connect.
**Fix:** Always verify before running scripts:
curl http://127.0.0.1:8080/JSON/core/view/version/?apikey=zapkey123
Should return version JSON -- if not, restart ZAP first.

## Issue 4: scan_as_user fails with URL_NOT_FOUND
**Cause:** The target URL must already exist in ZAP's Sites tree (via spider or manual browse) before ascan.scan_as_user can scan it.
**Fix:** Run spider.scan_as_user on the target URL first, then ascan.scan_as_user. Note: this can still trigger Issue 2 if repeated too many times.

## Standard ZAP Startup Sequence (use every day)
sudo systemctl start apache2 mariadb mongodb
pkill -f zap
sleep 2
rm -f ~/.ZAP/zap.lock
cd ~/zap_project
source venv/bin/activate
zaproxy -daemon -port 8080 -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true -config api.key=zapkey123 -config insights.enabled=false -Xmx1024m &
sleep 30
curl http://127.0.0.1:8080/JSON/core/view/version/?apikey=zapkey123
