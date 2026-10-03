"""
common/ratelimit.py — นับความพยายามที่ล้มเหลว (เดารหัส login, กรอกเลขบัตรผิดซ้ำ) แล้วบล็อกชั่วคราว

เดิมนับไว้ในหน่วยความจำของแต่ละ service -- รีสตาร์ท service (หรือทำให้มัน crash) ตัวนับกลับเป็นศูนย์
หลังเปิดหน้าแอดมินให้วงลูกค้า (2026-10-02) จุดนี้สำคัญขึ้น จึงเก็บในฐานข้อมูลแทน (ตาราง rate_attempt,
sql/013_rate_attempt.sql) ใช้ร่วมกันทั้ง Admin และ portal ของลูกค้า

RATE_LIMIT_BACKEND=memory ใช้ตัวนับในหน่วยความจำแบบเดิม (เทสต์ตั้งไว้ใน tests/conftest.py เพราะ DB จำลอง
ของแต่ละไฟล์เทสต์ไม่รู้จักตารางนี้) · ฐานข้อมูลล่มระหว่างนับ = ถอยไปใช้หน่วยความจำ ไม่ทำให้หน้า login พัง
"""
from __future__ import annotations

import logging
import os
import time

log = logging.getLogger("cafe-wifi.ratelimit")


def _backend() -> str:
    return os.environ.get("RATE_LIMIT_BACKEND", "db")


def _memory_hits(memory: dict, bucket: str, window: int) -> int:
    now = time.time()
    hits = [t for t in memory.get(bucket, []) if now - t < window]
    memory[bucket] = hits
    return len(hits)


def limited(bucket: str, limit: int, window: int, memory: dict) -> bool:
    bucket = bucket[:128]
    if _backend() == "db":
        try:
            from common import db
            row = db.query_one("SELECT COUNT(*) AS n FROM rate_attempt WHERE bucket=%s "
                               "AND ts > NOW() - INTERVAL %s SECOND", (bucket, window))
            return int(row["n"]) >= limit
        except Exception:  # noqa: BLE001 -- นับไม่ได้ต้องไม่ทำให้ login พัง ถอยไปใช้หน่วยความจำ
            log.exception("อ่านตัวนับจากฐานข้อมูลไม่สำเร็จ -- ใช้ตัวนับในหน่วยความจำแทนชั่วคราว")
    return _memory_hits(memory, bucket, window) >= limit


def hit(bucket: str, window: int, memory: dict) -> None:
    bucket = bucket[:128]
    if _backend() == "db":
        try:
            from common import db
            db.execute("INSERT INTO rate_attempt (bucket) VALUES (%s)", (bucket,))
            # ล้างของเก่าของ bucket นี้ไปด้วย ตารางไม่โตเรื่อย ๆ (มี index (bucket, ts))
            db.execute("DELETE FROM rate_attempt WHERE bucket=%s AND ts < NOW() - INTERVAL %s SECOND",
                       (bucket, window))
            return
        except Exception:  # noqa: BLE001
            log.exception("บันทึกตัวนับลงฐานข้อมูลไม่สำเร็จ -- ใช้ตัวนับในหน่วยความจำแทนชั่วคราว")
    memory.setdefault(bucket, []).append(time.time())
