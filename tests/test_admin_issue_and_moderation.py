"""
T-Admin — /issue (M6: POST-Redirect-GET), /vouchers/<id>/revoke และ
/customers/<id>/block (M2: เดินสายฟีเจอร์ที่เคยตายในสคีมา) และการ validate hours/devices
(บั๊กเดิมที่แก้ไปแล้ว: int() พังถ้ากรอกไม่ใช่ตัวเลข)

ใช้ฐานข้อมูลจำลองในหน่วยความจำแบบเดียวกับ test_setup_flow.py แต่มี staff ที่ล็อกอินแล้ว
"""
import contextlib
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
        elif s.startswith("select id, username, password_hash"):
            self._rows = [r for r in STAFF if r["username"] == args[0]]
        elif s.startswith("select id, role from staff"):
            self._rows = [r for r in STAFF if r["username"] == args[0]]
        elif s.startswith("select id, is_blocked from customer where natid_hash"):
            hit = [c for c in CUSTOMERS.values() if c["natid_hash"] == args[0]]
            self._rows = hit
        elif s.startswith("update customer set last_seen"):
            pass
        elif s.startswith("insert into customer"):
            _ids["customer"] += 1
            cid = _ids["customer"]
            CUSTOMERS[cid] = dict(id=cid, natid_hash=args[0], natid_enc=args[1],
                                  natid_masked=args[2], is_blocked=False,
                                  first_seen="now", last_seen="now", visit_count=1)
            self.lastrowid = cid
        elif s.startswith("insert into voucher ("):
            _ids["voucher"] += 1
            vid = _ids["voucher"]
            VOUCHERS[vid] = dict(id=vid, customer_id=args[0], username=args[1],
                                 status="active")
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
        elif s.startswith("update voucher set status='revoked'"):
            vid = args[0]
            v = VOUCHERS.get(vid)
            if v and v["status"] == "active":
                v["status"] = "revoked"
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif s.startswith("select is_blocked from customer where id"):
            c = CUSTOMERS.get(args[0])
            self._rows = [{"is_blocked": c["is_blocked"]}] if c else []
        elif s.startswith("update customer set is_blocked"):
            c = CUSTOMERS.get(args[1])
            if c:
                c["is_blocked"] = bool(args[0])
                self.rowcount = 1
        elif s.startswith("insert into audit_log"):
            AUDIT.append(args)
            self.lastrowid = None
            self.rowcount = 1
        elif s.startswith("select v.id, v.username, v.issued_at"):
            self._rows = [dict(id=v["id"], username=v["username"], issued_at=_NOW,
                               valid_until=_NOW, status=v["status"],
                               natid_masked=CUSTOMERS[v["customer_id"]]["natid_masked"],
                               issued_by="admin1")
                         for v in sorted(VOUCHERS.values(), key=lambda v: -v["id"])]
        elif s.startswith("select id, natid_masked, first_seen"):
            self._rows = [dict(id=c["id"], natid_masked=c["natid_masked"],
                               first_seen=_NOW, last_seen=_NOW,
                               visit_count=c["visit_count"], is_blocked=c["is_blocked"])
                         for c in CUSTOMERS.values()]
        elif s.startswith("select"):
            self._rows = []
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

    def _execute(s, a=()):
        cur = _run(s, a)
        return cur.rowcount

    monkeypatch.setattr(db, "execute", _execute)

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


def _seed_voucher():
    """ลูกค้า 1 คน + voucher ที่ใช้ได้ 1 ใบ (เดิมสร้างผ่าน /issue ซึ่งเลิกใช้แล้ว -- คำขอ+อนุมัติแทน)"""
    _ids["customer"] += 1
    cid = _ids["customer"]
    CUSTOMERS[cid] = dict(id=cid, natid_hash=crypto.natid_hash(NID), natid_enc=crypto.natid_encrypt(NID),
                          natid_masked=crypto.mask_natid(NID), is_blocked=False,
                          first_seen="now", last_seen="now", visit_count=1)
    _ids["voucher"] += 1
    VOUCHERS[_ids["voucher"]] = dict(id=_ids["voucher"], customer_id=cid, username="CAFE-SEED1",
                                     status="active")


def test_revoke_voucher_sets_status_and_is_idempotent_safe(client):
    _seed_voucher()
    vid = next(iter(VOUCHERS))
    assert VOUCHERS[vid]["status"] == "active"

    r = client.post(f"/vouchers/{vid}/revoke")
    assert r.status_code == 302
    assert VOUCHERS[vid]["status"] == "revoked"
    assert any("revoke_voucher" in str(a) for a in AUDIT)

    # revoke ซ้ำ (ใบเดียวกัน, ไม่ active แล้ว) ต้องได้ 404 ไม่ใช่ทำซ้ำเงียบ ๆ
    r2 = client.post(f"/vouchers/{vid}/revoke")
    assert r2.status_code == 404


def test_toggle_block_customer_requires_admin_and_toggles(client):
    _seed_voucher()
    cid = next(iter(CUSTOMERS))
    assert CUSTOMERS[cid]["is_blocked"] is False

    r = client.post(f"/customers/{cid}/block")
    assert r.status_code == 302
    assert CUSTOMERS[cid]["is_blocked"] is True

    r2 = client.post(f"/customers/{cid}/block")
    assert r2.status_code == 302
    assert CUSTOMERS[cid]["is_blocked"] is False, "เรียกซ้ำต้องสลับกลับ (toggle)"


def test_dashboard_renders_with_revoke_button_for_active_voucher(client):
    """สโมคเทสต์: dashboard.html ต้อง render ได้จริงกับ v.id คอลัมน์ใหม่ (ไม่ใช่แค่ backend)"""
    _seed_voucher()
    html = client.get("/").get_data(as_text=True)
    assert "ปิดสิทธิ์" in html
    vid = next(iter(VOUCHERS))
    assert f"/vouchers/{vid}/revoke" in html


def test_customers_page_renders_block_button_for_admin(client):
    """สโมคเทสต์: customers.html ต้อง render ปุ่มระงับ/ยกเลิกระงับได้จริง"""
    _seed_voucher()
    html = client.get("/customers").get_data(as_text=True)
    cid = next(iter(CUSTOMERS))
    assert f"/customers/{cid}/block" in html
    assert "ระงับ" in html


def test_toggle_block_customer_rejected_for_non_admin_staff(client, monkeypatch):
    monkeypatch.setitem(STAFF[0], "role", "staff")
    with client.session_transaction() as sess:
        sess["role"] = "staff"
    _seed_voucher()
    cid = next(iter(CUSTOMERS))
    r = client.post(f"/customers/{cid}/block")
    assert r.status_code == 403
