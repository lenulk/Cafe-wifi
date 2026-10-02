"""common/audit.py — บันทึกร่องรอยการใช้งานที่มีผลทางกฎหมาย/PDPA"""
from __future__ import annotations

from . import db

# หมายเหตุ: import โมดูล `db` ทั้งก้อนแล้วเรียก db.execute(...) แบบ dynamic ตอนใช้งานจริง
# (ไม่ใช่ `from .db import execute` ที่ import ครั้งเดียวแล้วผูกชื่อตายตัว) เพราะถ้ามีการ
# สลับ implementation ของ db.execute ในภายหลัง (เช่น ห่อ retry logic, หรือใน unit test ที่
# monkeypatch แทนที่ด้วย fake) โค้ดจุดนี้ต้องเห็นเวอร์ชันล่าสุดเสมอ ไม่งั้น audit trail จะ
# เงียบ ๆ เขียนไปที่ implementation เก่าโดยไม่มีใครรู้ตัว — สำคัญมากเพราะนี่คือกลไกพิสูจน์
# การเข้าถึงข้อมูลอ่อนไหวตาม PDPA

# การกระทำที่ "ต้อง" บันทึกเสมอ
REVEAL_NATID = "reveal_natid"
ISSUE_VOUCHER = "issue_voucher"
REVOKE_VOUCHER = "revoke_voucher"
EXPORT_LOG = "export_log"
LOGIN_OK = "login_ok"
LOGIN_FAIL = "login_fail"
LOGOUT = "logout"  # N38 -- ต้องรู้เวลาจบ session ของแอดมิน ไม่ใช่แค่เวลาเริ่ม
SETUP_ADMIN = "setup_admin"
DISK_ALERT = "disk_alert"  # N1 (CODING_BRIEF.md) -- ดิสก์เต็ม = log หยุดเขียน = ผิด ม.26
ERASE_REFUSED = "erase_refused"  # N33 -- ปฏิเสธคำขอลบเพราะยังอยู่ในช่วงเก็บบังคับตาม ม.26
ERASE_CUSTOMER = "erase_customer"  # N6 (CODING_BRIEF.md) -- DSR: ลบข้อมูลรายบุคคลตามคำขอ (PDPA §6.2 ข้อ 6)
SEARCH_LOG = "search_log"  # N9 (CODING_BRIEF.md) -- ค้น conn_log/dns_log ใน Admin ต้องมีร่องรอยทุกครั้งตาม PDPA
BYPASS_DETECTED = "bypass_detected"  # N10 (CODING_BRIEF.md) -- T17: ตรวจพบอุปกรณ์แปลกปลอมในวง uplink
LOG_GAP = "log_gap"  # N31 -- เหตุการณ์จราจรบางส่วนถูกทิ้ง (ENOBUFS/DB ล่ม) หลักฐานช่วงนั้นไม่ครบ
INTEGRITY_FAILED = "integrity_failed"  # N21 -- hash chain ของ log ไม่ตรง = หลักฐานถูกแก้ไขย้อนหลัง
CSRF_REJECT = "csrf_reject"  # R2-09 -- POST ไม่มี/ผิด CSRF token = อาจมีหน้าอื่นพยายามสั่งงานแทนพนักงาน
# หน้า /staff -- ใครสร้าง/ปิด/รีเซ็ตบัญชีใคร ต้องตรวจย้อนหลังได้ (บัญชีรายคนแทนบัญชีร่วม เพื่อ PDPA)
STAFF_CREATE = "staff_create"
STAFF_DISABLE = "staff_disable"
STAFF_ENABLE = "staff_enable"
STAFF_ROLE = "staff_role"
STAFF_RESET_PASSWORD = "staff_reset_password"
PASSWORD_CHANGE = "password_change"


def log(action: str, staff_id: int | None = None, target: str = "",
        client_ip: str = "", detail: str = "") -> None:
    """ล้มเหลวเงียบ ๆ ไม่ได้ — แต่ก็ต้องไม่ทำให้ request หลักพัง"""
    try:
        db.execute(
            "INSERT INTO audit_log (staff_id, action, target, client_ip, detail) "
            "VALUES (%s, %s, %s, %s, %s)",
            (staff_id, action[:64], target[:128], client_ip[:45], detail),
        )
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger(__name__).error("เขียน audit_log ไม่สำเร็จ: %s", exc)


def log_required(action: str, staff_id: int | None = None, target: str = "",
                 client_ip: str = "", detail: str = "", cursor=None) -> None:
    """สำหรับงานที่ห้ามแสดงข้อมูล/commit หาก audit ล้มเหลว."""
    sql = ("INSERT INTO audit_log (staff_id, action, target, client_ip, detail) "
           "VALUES (%s,%s,%s,%s,%s)")
    args = (staff_id, action[:64], target[:128], client_ip[:45], detail)
    if cursor is not None:
        cursor.execute(sql, args)
    else:
        db.execute(sql, args)
