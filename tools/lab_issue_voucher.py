"""ออก voucher ทดสอบผ่าน /issue ตัวจริงของ Admin -- ใช้ในแล็บเท่านั้น พิมพ์ "code password"

ใช้ Flask test client + session ของ staff_id=1 (ข้ามแค่ขั้นพิมพ์รหัสพนักงาน ส่วนตรวจเลขบัตร, CSRF,
บันทึก audit และหน้าแสดงรหัสครั้งเดียวทำงานจริงทั้งหมด) · ต้องรันบน Pi เป็น root:
    set -a; . /etc/cafe-wifi/secrets.env; set +a
    cd /opt/cafe-wifi && PYTHONPATH=/opt/cafe-wifi venv/bin/python tools/lab_issue_voucher.py 1101700000010 1 1 20
ใช้เลขบัตรทดสอบที่ checksum ถูกแต่ไม่ใช่ของคนจริง (เช่น 1101700000010)
"""
import re, sys
from admin.app import app
natid, hours, devices, quota = sys.argv[1], sys.argv[2], sys.argv[3], (sys.argv[4] if len(sys.argv) > 4 else "")
c = app.test_client()
with c.session_transaction() as s:
    s.update(staff_id=1, username="admin", role="admin", csrf_token="t" * 43)
r = c.post("/issue", data=dict(csrf_token="t" * 43, natid=natid, hours=hours, devices=devices,
                               quota_mb=quota, consent="on"), headers={"X-Real-IP": "127.0.0.1"})
if r.status_code != 302:
    print("ISSUE_FAILED", r.status_code, re.findall(r'class="msg err[^"]*">([^<]+)', r.get_data(as_text=True))); sys.exit(1)
html = c.get("/issue/result", headers={"X-Real-IP": "127.0.0.1"}).get_data(as_text=True)
code, pw = re.findall(r'<div class="cred">([^<]+)</div>', html)[:2]
print(code.strip(), pw.strip())
