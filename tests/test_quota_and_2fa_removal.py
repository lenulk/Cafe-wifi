"""
T-N8 — งานตัดสินใจฟีเจอร์ครึ่งใบ 2 ตัว (N8, CODING_BRIEF.md)

เจ้าของโครงงานตัดสินใจแล้ว (2026-08-26): **quota_mb ทำให้จบ** (back-end พร้อมอยู่แล้ว แค่ขาด
ช่องกรอกใน /issue) · **2FA ถอดออก** (pyotp ค้างใน requirements.txt โดยไม่มีไฟล์ไหน import
เลยสักบรรทัด, staff.totp_secret ไม่เคยถูกใช้ -- ดู PROJECT_PLAN.md R8 ที่บอกไว้เองแล้วว่าตัด
Phase 5/2FA ได้)

ไฟล์นี้แบ่ง 2 ส่วน: (1) เทสต์ว่า quota_mb ใช้งานได้จริงครบสาย -- กรอกได้ ส่งเข้า INSERT จริง
โชว์ในหน้าผลลัพธ์ ลง audit_log (2) เทสต์ว่าถอด 2FA scaffold ออกสะอาดจริง -- ไม่มี pyotp ค้าง
ใน requirements.txt (ส่วนการลบคอลัมน์ staff.totp_secret ยืนยันด้วย sql/006_drop_totp.sql +
`bash -n install.sh` ตามธรรมเนียมโปรเจกต์ที่ไม่เขียน pytest ตรวจไฟล์ .sql/.sh โดยตรง)
"""
from __future__ import annotations

import contextlib
import pathlib
from datetime import datetime

import pytest

from common import crypto

GOOD_PW = "CafeWifi2026Secure"
_NOW = datetime(2026, 8, 26, 12, 0, 0)

STAFF = [{"id": 1, "username": "admin1", "password_hash": crypto.hash_password(GOOD_PW),
         "display_name": "Admin", "role": "admin", "is_active": 1}]
CUSTOMERS: dict[int, dict] = {}
VOUCHERS: dict[int, dict] = {}
AUDIT: list[tuple] = []
REVEALS: dict[str, dict] = {}
_ids = {"customer": 0, "voucher": 0}


def _reset():
    CUSTOMERS.clear()
    VOUCHERS.clear()
    AUDIT.clear()
    REVEALS.clear()
    _ids.update(customer=0, voucher=0)


class FakeCursor:
    def __init__(self):
        self.lastrowid = None
        self.rowcount = 0
        self._rows = []

    def execute(self, sql, args=()):
        s = " ".join(sql.split()).lower()
        if s.startswith("select count(*) as n from staff"):
            self._rows = [{"n": len(STAFF)}]
        elif s.startswith("select role, is_active"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("select id, is_blocked from customer where natid_hash"):
            self._rows = [c for c in CUSTOMERS.values() if c["natid_hash"] == args[0]]
        elif s.startswith("update customer set last_seen"):
            pass
        elif s.startswith("insert into customer"):
            _ids["customer"] += 1
            cid = _ids["customer"]
            CUSTOMERS[cid] = dict(id=cid, natid_hash=args[0], natid_enc=args[1], natid_masked=args[2])
            self.lastrowid = cid
        elif s.startswith("insert into voucher ("):
            _ids["voucher"] += 1
            vid = _ids["voucher"]
            # ลำดับคอลัมน์: customer_id, username, password_hash, issued_by, valid_from,
            # valid_until, max_devices, quota_mb (N8 -- คอลัมน์ใหม่ที่เพิ่งต่อสาย)
            VOUCHERS[vid] = dict(id=vid, customer_id=args[0], username=args[1],
                                 max_devices=args[6], quota_mb=args[7])
            self.lastrowid = vid
        elif s.startswith("insert into voucher_reveal"):
            token, staff_id, payload, expires_at = args
            REVEALS[token] = dict(payload=payload, staff_id=staff_id,
                                  expires_at=expires_at, consumed_at=None)
            self.rowcount = 1
        elif s.startswith("select payload, expires_at, consumed_at, staff_id from voucher_reveal"):
            self._rows = [REVEALS[args[0]]] if args[0] in REVEALS else []
        elif s.startswith("update voucher_reveal set consumed_at"):
            REVEALS[args[0]]["consumed_at"] = datetime.now()
            self.rowcount = 1
        elif s.startswith("insert into audit_log"):
            AUDIT.append(args)
            self.rowcount = 1
        elif s.startswith("select count(*) as n from access_request"):
            self._rows = [{"n": 0}]  # ตัวเลขคำขอที่รออนุมัติบนเมนู
        else:
            raise AssertionError(f"FakeCursor ไม่รู้จัก SQL: {s[:80]}")

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    def cursor(self):
        return FakeCursor()


@pytest.fixture
def client(monkeypatch):
    _reset()
    import common.db as db
    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(FakeConn()))

    def _run(sql, args=()):
        cur = FakeCursor()
        cur.execute(sql, args)
        return cur

    monkeypatch.setattr(db, "query_one", lambda s, a=(): _run(s, a).fetchone())
    monkeypatch.setattr(db, "query_all", lambda s, a=(): _run(s, a).fetchall())
    monkeypatch.setattr(db, "execute", lambda s, a=(): _run(s, a).rowcount)

    import importlib
    admin_app = importlib.import_module("admin.app")
    importlib.reload(admin_app)
    admin_app.app.config.update(SESSION_COOKIE_SECURE=False, TESTING=True,
                                CSRF_ENABLED=False)  # R2-09: CSRF ทดสอบแยกท้าย test_setup_flow.py
    admin_app._attempts.clear()
    c = admin_app.app.test_client()
    with c.session_transaction() as sess:
        sess["staff_id"] = 1
        sess["username"] = "admin1"
        sess["role"] = "admin"
    return c


NID = "1101700207366"  # เลขบัตรตัวอย่างที่ checksum ผ่าน (ใช้ซ้ำจาก test_thai_id.py ได้)


# ================================================================== ส่วนที่ 1: quota_mb


def test_requirements_txt_does_not_pin_pyotp():
    req = pathlib.Path(__file__).resolve().parents[1] / "app" / "requirements.txt"
    text = req.read_text(encoding="utf-8").lower()
    assert "pyotp" not in text, "2FA ตัดสินใจถอดออกแล้ว (N8) -- ต้องไม่มี pyotp ค้างใน requirements.txt"


def test_no_source_file_imports_pyotp():
    """กันไม่ให้มีใครลืมไฟล์ที่ import pyotp ค้างไว้ (ต้องถอดให้สะอาดจริง ไม่ใช่แค่ requirements.txt)"""
    root = pathlib.Path(__file__).resolve().parents[1]
    hits = []
    for py_file in (root / "app").rglob("*.py"):
        if "pyotp" in py_file.read_text(encoding="utf-8"):
            hits.append(str(py_file))
    for py_file in (root / "tools").rglob("*.py"):
        if "pyotp" in py_file.read_text(encoding="utf-8"):
            hits.append(str(py_file))
    assert not hits, f"เจอ pyotp ค้างอยู่ใน: {hits}"


def test_drop_totp_migration_file_exists_and_targets_right_column():
    sql_path = pathlib.Path(__file__).resolve().parents[1] / "sql" / "006_drop_totp.sql"
    assert sql_path.exists(), "N8 ต้องมี migration ใหม่ลบ staff.totp_secret (ห้ามแก้ 001_schema.sql เดิม)"
    text = sql_path.read_text(encoding="utf-8").upper()
    assert "DROP COLUMN" in text
    assert "TOTP_SECRET" in text
    assert "ALTER TABLE STAFF" in text
