"""
common/customer.py — ตรรกะเกี่ยวกับข้อมูลลูกค้าที่ทั้งฝั่งเว็บ (app/) และงานบำรุงรักษา (tools/)
ต้องใช้ร่วมกัน (ตามแบบที่ common/traffic.py ทำไว้แล้วกับ sum_session_traffic_bytes() -- กัน
การ import ข้ามชั้นผิดทิศทางจาก app/ ไป tools/ ที่เคยเป็นปัญหาจริงมาก่อน ดู Work Log ตรวจทานรอบ 4
ใน PROJECT_PLAN.md)
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta

PURGED_MARK = "PURGED"  # ค่า natid_masked ที่แปลว่า "ถูกล้างข้อมูลระบุตัวตนไปแล้ว"


def anonymize_customer(execute_fn, customer_id: int) -> int:
    """
    ล้างข้อมูลระบุตัวตนของลูกค้า 1 คน (natid_hash/natid_enc/natid_masked) แต่**คงแถวไว้**
    -- ห้าม DELETE เพราะ fk_voucher_customer เป็น RESTRICT ปริยาย และลูกค้าทุกรายมี voucher
    อย่างน้อย 1 ใบเสมอ (ดู D20 ใน PROJECT_PLAN.md, บั๊กจริง C2 ที่เคย DELETE ตรง ๆ แล้วชน FK
    จนทำให้ cafe-maintenance.service ทั้งหน่วยหยุดกลางคัน) แถวที่เหลือยังใช้เป็นหลักฐานจำนวน
    ครั้ง/อุปกรณ์ตาม พ.ร.บ.คอมพิวเตอร์ ม.26 ได้ต่อ แม้ตัวตนจะถูกลบไปแล้ว

    ใช้ร่วมกันทั้ง 2 เส้นทางที่ต้องล้าง PII ของลูกค้า -- ตรรกะต้องเป็นชุดเดียวกันเป๊ะเสมอ
    ไม่แยกเขียนซ้ำที่ไหนอีก:
      (1) purge อัตโนมัติตามอายุ (tools/purge_old_data.py::purge_stale_customers, T11)
      (2) ลบตามคำขอเจ้าของข้อมูล -- DSR (N6, CODING_BRIEF.md, admin/app.py POST
          /customers/<id>/erase, §6.2 ข้อ 6 ของนโยบายความเป็นส่วนตัว)

    execute_fn(sql, args) -> จำนวนแถวที่ถูกกระทบ (rowcount) -- คืนค่านี้ตรง ๆ ให้ผู้เรียกเช็คว่า
    id ที่ส่งมามีแถวอยู่จริงไหม (0 = ไม่พบแถว)
    """
    n = execute_fn(
        "UPDATE customer SET natid_hash = CONCAT('PURGED-', id), "
        "natid_enc = '', natid_masked = 'PURGED' WHERE id = %s",
        (customer_id,),
    )
    if n:
        # ชื่อเครื่องอาจมีชื่อจริงของลูกค้า (เช่น "ASUS-Laptop-Somchai") -- ล้างไปพร้อมเลขบัตร
        # (sql/011_device_info.sql) · os_label ไม่ระบุตัวบุคคล เก็บไว้ได้
        execute_fn("UPDATE portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
                   "SET ps.hostname = NULL WHERE v.customer_id = %s", (customer_id,))
        execute_fn("UPDATE access_request ar JOIN voucher v ON v.id = ar.voucher_id "
                   "SET ar.hostname = NULL, ar.user_agent = NULL WHERE v.customer_id = %s",
                   (customer_id,))
    return n


def retention_hold_until(query_one_fn, customer_id: int,
                         retention_days: int | None = None,
                         now: datetime | None = None) -> datetime | None:
    """
    N33: คืนวันที่ที่ "ยังลบตัวตนไม่ได้" ถึง หรือ None ถ้าพ้นกำหนดเก็บแล้ว

    พ.ร.บ.คอมพิวเตอร์ ม.26 บังคับให้ผู้ให้บริการเก็บ **ข้อมูลผู้ใช้บริการ** (ไม่ใช่แค่ข้อมูล
    จราจร) ไว้อย่างน้อย 90 วัน ถ้าลบตัวตนทิ้งทันทีตามคำขอ ข้อมูลจราจรที่เหลือจะชี้กลับไปหา
    บุคคลไม่ได้อีก = ผิด ม.26 ทั้งที่ยังอยู่ในช่วงเก็บ

    ฝั่ง PDPA เองก็เปิดช่องไว้: สิทธิ์ขอลบใช้ไม่ได้กับข้อมูลที่ต้องเก็บตามกฎหมายอื่น สิทธิ์ของ
    เจ้าของข้อมูลจึงไม่ได้หายไป แค่เลื่อนไปจนพ้นกำหนด -- และ tools/purge_old_data.py ลบให้
    อัตโนมัติเมื่อพ้นกำหนดอยู่แล้ว (T11) ไม่ต้องรอให้ใครมาขอซ้ำ

    นับจากกิจกรรมล่าสุดจริง ๆ ของลูกค้า = ทีหลังสุดระหว่าง customer.last_seen (อัปเดตตอนออก
    voucher) กับ portal_session.started_at ล่าสุดของ voucher ทุกใบของเขา เพราะลูกค้าที่รับ
    voucher วันนี้อาจใช้งานต่ออีกหลายชั่วโมง/หลายวันหลังจากนั้น
    """
    if retention_days is None:
        retention_days = max(int(os.environ.get("LOG_RETENTION_DAYS", "180")),
                             int(os.environ.get("CUSTOMER_RETENTION_DAYS", "0")))
    row = query_one_fn(
        "SELECT GREATEST("
        " COALESCE(c.last_seen, c.first_seen),"
        " COALESCE((SELECT MAX(COALESCE(ps.ended_at,"
        " CASE WHEN ps.state='authenticated' THEN NOW() ELSE ps.authenticated_at END,"
        " ps.started_at))"
        " FROM portal_session ps JOIN voucher v ON v.id=ps.voucher_id"
        " WHERE v.customer_id=c.id), c.first_seen),"
        " COALESCE((SELECT MAX(cl.ts) FROM conn_log cl"
        " JOIN portal_session ps ON ps.mac=cl.mac AND ps.ip=cl.src_ip"
        " AND ps.authenticated_at<=COALESCE(cl.started_at, cl.ts)"
        " AND (ps.ended_at IS NULL OR COALESCE(cl.started_at, cl.ts)<=ps.ended_at)"
        " JOIN voucher v ON v.id=ps.voucher_id WHERE v.customer_id=c.id), c.first_seen),"
        " COALESCE((SELECT MAX(dl.ts) FROM dns_log dl"
        " JOIN portal_session ps ON ps.mac=dl.mac AND ps.ip=dl.client_ip"
        " AND ps.authenticated_at<=dl.ts AND (ps.ended_at IS NULL OR dl.ts<=ps.ended_at)"
        " JOIN voucher v ON v.id=ps.voucher_id WHERE v.customer_id=c.id), c.first_seen)"
        " ) AS last_activity FROM customer c WHERE c.id = %s", (customer_id,))
    if not row or not row.get("last_activity"):
        return None
    hold_until = row["last_activity"] + timedelta(days=retention_days)
    return hold_until if hold_until > (now or datetime.now()) else None
