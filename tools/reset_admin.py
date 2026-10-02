"""
tools/reset_admin.py — รีเซ็ตรหัสผ่านผู้ดูแลระบบจากบรรทัดคำสั่งบนเครื่อง gateway
(ใช้เมื่อลืมรหัสผ่าน — ต้องมีสิทธิ์ root บนเครื่องอยู่แล้ว)

    sudo bash -c 'set -a; . /etc/cafe-wifi/secrets.env; set +a;       cd /opt/cafe-wifi && PYTHONPATH=/opt/cafe-wifi venv/bin/python -m tools.reset_admin <username>'

หมายเหตุ: ต้องโหลด secrets.env ก่อนเสมอ เพราะเครื่องมือนี้ต้องใช้รหัสฐานข้อมูลจากไฟล์นั้น
`sudo -E` อย่างเดียวใช้ไม่ได้ (env ของผู้ใช้ทั่วไปไม่มี DB_PASS) -- แก้คำอธิบายนี้หลังเจอ
ปัญหาจริงตอนผู้ดูแลลืมรหัสบน Pi 2026-09-20
"""
from __future__ import annotations

import getpass
import sys

from common import crypto
from common.db import execute, query_one


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    username = sys.argv[1]
    row = query_one("SELECT id, role FROM staff WHERE username = %s", (username,))
    if not row:
        print(f"ไม่พบผู้ใช้ '{username}'")
        return 1

    pw1 = getpass.getpass("รหัสผ่านใหม่: ")
    problems = crypto.check_admin_password(pw1)
    if problems:
        print("รหัสผ่านไม่ผ่านเกณฑ์:")
        for p in problems:
            print("  -", p)
        return 1
    if pw1 != getpass.getpass("ยืนยันรหัสผ่านใหม่: "):
        print("รหัสผ่านไม่ตรงกัน")
        return 1

    # password_changed_at = NOW(): session ที่ login ค้างไว้ด้วยรหัสเก่าหลุดทันที (admin/app.py gate())
    execute("UPDATE staff SET password_hash = %s, is_active = 1, must_change_password = 0, "
            "password_changed_at = NOW() WHERE id = %s",
            (crypto.hash_password(pw1), row["id"]))
    print(f"รีเซ็ตรหัสผ่านของ '{username}' (role={row['role']}) เรียบร้อย")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
