"""
common/access.py — คำขอใช้งานของลูกค้า + การจองสิทธิ์อุปกรณ์ (ใช้ร่วมกันระหว่าง FAS กับ Admin)

ลำดับ (แทนสลิปรหัสผ่านเดิม -- ดู sql/010_access_request.sql):
  FAS  : ลูกค้ากรอกเลขบัตร + ยินยอม -> create_request() -> ได้รหัสคำขอ 4 ตัว
  Admin: พนักงานตรวจบัตร พิมพ์ 4 ตัวท้ายเทียบ -> อนุมัติ -> reserve_pending_session()
  root : tools/reconcile_pending.py สั่ง `ndsctl auth <mac>` แล้วยืนยัน session กับ openNDS ตามเดิม
"""
from __future__ import annotations

import secrets

from . import crypto

REQUEST_TTL_MIN = 15        # คำขอที่ไม่มีใครกดอนุมัติภายในนี้หมดอายุ (ลูกค้ายืนรอหน้าเคาน์เตอร์)
MAX_PENDING_REQUESTS = 50   # กันคนสร้างคำขอปลอมท่วมหน้าอนุมัติ
PENDING_SECONDS = 180       # เวลาที่ portal_session รอ openNDS ยืนยัน (เท่าเดิมของ FAS)


def gen_request_code(cur) -> str:
    """รหัสคำขอ 4 ตัวจากตัวอักษรที่ไม่กำกวม ไม่ซ้ำกับคำขอที่ยังรออยู่ (27^4 = 531,441 แบบ)"""
    for _ in range(50):
        code = "".join(secrets.choice(crypto._ALPHABET) for _ in range(4))
        cur.execute("SELECT id FROM access_request WHERE code=%s AND status='pending' "
                    "AND expires_at > NOW()", (code,))
        if not cur.fetchone():
            return code
    raise RuntimeError("สุ่มรหัสคำขอไม่ซ้ำไม่ได้")


def reserve_pending_session(cur, voucher: dict, mac: str, ip: str, hostname: str | None = None,
                            os_label: str | None = None) -> tuple[str | None, int | None]:
    """จอง MAC + โควตาจำนวนเครื่องของ voucher แล้วสร้าง portal_session แบบ pending

    คืน (None, portal_session_id) ถ้าสำเร็จ หรือ (ข้อความที่ต้องบอกผู้ใช้, None) ถ้าปฏิเสธ -- ผู้เรียกต้อง rollback เอง (R2-01: ถ้าออกจาก get_conn() ปกติจะ commit แถว
    pending_mac_claim ที่ไม่มี session ค้างไว้ แล้ว MAC นั้นใช้งานไม่ได้อีกเลย)
    """
    cur.execute("SELECT id FROM voucher WHERE id=%s FOR UPDATE", (voucher["id"],))
    cur.fetchone()
    cur.execute("SELECT id FROM portal_session WHERE mac=%s AND state='pending' FOR UPDATE", (mac,))
    if cur.fetchone():
        return "อุปกรณ์นี้กำลังรอเปิดสิทธิ์อยู่แล้ว รอสักครู่", None
    cur.execute("INSERT IGNORE INTO pending_mac_claim (mac) VALUES (%s)", (mac,))
    if cur.rowcount != 1:
        return "อุปกรณ์นี้กำลังรอเปิดสิทธิ์อยู่แล้ว รอสักครู่", None
    cur.execute("SELECT COUNT(*) AS n FROM ("
                "SELECT mac FROM device WHERE voucher_id=%s UNION "
                "SELECT mac FROM portal_session WHERE voucher_id=%s AND state='pending' "
                "AND pending_until > NOW()) AS reserved",
                (voucher["id"], voucher["id"]))
    reserved = int(cur.fetchone()["n"])
    cur.execute("SELECT 1 FROM device WHERE voucher_id=%s AND mac=%s UNION "
                "SELECT 1 FROM portal_session WHERE voucher_id=%s AND mac=%s "
                "AND state='pending' AND pending_until > NOW() LIMIT 1",
                (voucher["id"], mac, voucher["id"], mac))
    if not cur.fetchone() and reserved >= voucher["max_devices"]:
        return (f"สิทธิ์นี้ใช้ครบ {voucher['max_devices']} เครื่องแล้ว "
                "ต้องปิดสิทธิ์เครื่องเดิมหรือหมดเวลาก่อน"), None
    cur.execute("INSERT INTO portal_session "
                "(voucher_id, mac, ip, hostname, os_label, started_at, pending_until, state) "
                f"VALUES (%s,%s,%s,%s,%s,NOW(),DATE_ADD(NOW(), INTERVAL {PENDING_SECONDS} SECOND),'pending')",
                (voucher["id"], mac, ip, hostname, os_label))
    session_id = cur.lastrowid
    cur.execute("UPDATE pending_mac_claim SET portal_session_id=%s WHERE mac=%s", (session_id, mac))
    return None, session_id
