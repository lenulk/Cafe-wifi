#!/bin/bash
# lab_e2e_register.sh -- ทดสอบครบวงจรบน Pi จริงด้วยลูกค้าจำลอง (ต้องมี tools/lab_client.sh ที่ /root/cafe-client-test/client.sh)
# ลูกค้าขอใช้งาน -> อนุมัติผ่าน /requests ตัวจริง -> ndsctl auth -> ออกเน็ต · ใช้: sudo bash lab_e2e_register.sh [4ตัวท้ายที่พนักงานพิมพ์]
set -u
NS=cte; MAC=02:ca:fe:00:00:2a; UA="Mozilla/5.0 (Linux; Android 14; SM-A546E) AppleWebKit/537.36 Chrome/126 Mobile"; NATID=1101700000010; LAST4=${1:-0010}
cd /root/cafe-client-test
./client.sh down $NS >/dev/null 2>&1; ndsctl deauth $MAC >/dev/null 2>&1
./client.sh up $NS $MAC
CJ=/tmp/cj-$NS; rm -f $CJ
X="ip netns exec $NS curl -s -m 15 -b $CJ -c $CJ"
loc=$($X -o /dev/null -w '%{redirect_url}' http://example.com/)
echo "1 captive -> ${loc:0:50}"
nonce=$($X -L "$loc" | grep -o 'name="nonce" value="[^"]*"' | sed 's/.*value="//;s/"//')
base=$(echo "$loc" | sed 's#\(http://[^/]*\)/.*#\1#')
echo "2 register POST -> $($X -o /dev/null -w '%{http_code} %{redirect_url}' --data-urlencode "nonce=$nonce" --data-urlencode "natid=$NATID" --data-urlencode consent=on -A "$UA" "$base/login")"
code=$($X "$base/request" | grep -oE '>[A-Z0-9]{4}</div>' | head -1 | tr -d '<>/div')
echo "3 waiting page code=$code"

cat > /tmp/approve.py <<PY
import re, sys
from admin.app import app
c = app.test_client(); H = {"X-Real-IP": "127.0.0.1"}
with c.session_transaction() as s:
    s.update(staff_id=1, username="admin", role="admin", csrf_token="t" * 43, pw_at="")
html = c.get("/requests", headers=H).get_data(as_text=True)
print("4 admin sees code:", "$code" in html, "| full natid hidden:", "$NATID" not in html)
m = re.search(r'/requests/(\d+)/approve"[^>]*>(?:(?!</form>).)*', html, re.S)
rid = re.findall(r'/requests/(\d+)/approve', html)[-1]
r = c.post(f"/requests/{rid}/approve", headers=H,
           data=dict(csrf_token="t" * 43, last4="$LAST4", hours="1", devices="1", quota_mb=""))
html = c.get("/requests", headers=H).get_data(as_text=True)
print("5 approve ->", r.status_code, re.findall(r'class="msg (?:ok|err)">([^<]+)', html)[:1])
PY
(cd /opt/cafe-wifi && env $(grep -v '^#' /etc/cafe-wifi/secrets.env | xargs) PYTHONPATH=/opt/cafe-wifi ./venv/bin/python /tmp/approve.py 2>&1 | grep -v '^\[')
t0=$(date +%s)
for i in $(seq 1 30); do
  st=$($X "$base/request" | grep -oE 'ใช้อินเทอร์เน็ตได้แล้ว|กำลังเปิดอินเทอร์เน็ต|ไม่สำเร็จ|รหัสนี้ให้พนักงาน' | head -1)
  [ "$st" = "ใช้อินเทอร์เน็ตได้แล้ว" ] && break; sleep 1
done
echo "6 waiting page -> '$st' after $(( $(date +%s)-t0 ))s"
echo "7 internet -> $($X -o /dev/null -w '%{http_code}' http://example.com/)"
mysql cafewifi -t -e "SELECT ar.code, ar.hostname, ar.os_label, ps.hostname AS ps_host, ps.os_label AS ps_os FROM access_request ar LEFT JOIN portal_session ps ON ps.id=ar.portal_session_id ORDER BY ar.id DESC LIMIT 1"
mysql cafewifi -t -e "SELECT ar.code, ar.status, ar.natid_hash IS NULL AS pii_cleared, ar.auth_sent_at IS NOT NULL AS authed, ps.state, v.username, v.max_devices FROM access_request ar LEFT JOIN portal_session ps ON ps.id=ar.portal_session_id LEFT JOIN voucher v ON v.id=ar.voucher_id ORDER BY ar.id DESC LIMIT 1"
ndsctl json $MAC 2>/dev/null | python3 -c 'import json,sys,datetime as d; c=json.load(sys.stdin); print("openNDS:", c.get("state"), "ends", d.datetime.fromtimestamp(int(c["session_end"])).strftime("%H:%M") if c.get("session_end","null")!="null" else "-")' 2>/dev/null
