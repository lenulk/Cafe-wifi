"""
T-IssueQR — QR code + สลิปพิมพ์ได้ในหน้า /issue/result (N7, CODING_BRIEF.md)

KPI §14: ออก voucher 1 ใบ ≤ 30 วินาที -- ถ้าพนักงานต้องอ่านรหัส 8 ตัวให้ลูกค้าฟังทีละตัวแล้ว
พิมพ์เองบนมือถือ จะเกินแน่นอน เพิ่ม QR (ฝัง SVG ฝั่งเซิร์ฟเวอร์ ห้าม CDN) ให้สแกนแทน

แบ่ง 2 ส่วน: (1) เทสต์ตรงของ common/qr.py::voucher_qr_svg() (2) เทสต์ว่าหน้า /issue/result
ฝัง SVG ลงจริง ไม่ใช่ลิงก์ภายนอก/CDN
"""
from __future__ import annotations

import contextlib
from datetime import datetime

import pytest

from common import crypto
from common.qr import voucher_qr_svg

# ================================================================== ส่วนที่ 1: common/qr.py ตรง ๆ


def test_voucher_qr_svg_starts_with_svg_tag_no_xml_prolog():
    svg = voucher_qr_svg("User: CAFE-8F3K2\nPass: aB3dEfGh")
    assert svg.startswith("<svg"), "ต้องเริ่มด้วย <svg ตรง ๆ ไม่มี <?xml ...?> prolog ปนมา"
    assert svg.rstrip().endswith("</svg>")
    assert "<?xml" not in svg


def test_voucher_qr_svg_has_no_external_references():
    """ห้ามใช้ CDN -- ต้องไม่มี URL ที่ทำให้เบราว์เซอร์ยิง request ออกไปนอกเครื่อง
    (xmlns="http://www.w3.org/2000/svg" ไม่นับ -- เป็นแค่ตัวระบุ namespace ของ XML ไม่มีการ
    fetch จริง เบราว์เซอร์ไม่เคยเรียก URL นั้นเลย)"""
    svg = voucher_qr_svg("User: CAFE-8F3K2\nPass: aB3dEfGh")
    assert "src=" not in svg
    assert "href=" not in svg
    assert "cdn." not in svg


def test_voucher_qr_svg_differs_by_input_text():
    a = voucher_qr_svg("User: CAFE-AAAAA\nPass: aaaaaaaa")
    b = voucher_qr_svg("User: CAFE-ZZZZZ\nPass: zzzzzzzz")
    assert a != b


def test_voucher_qr_svg_is_valid_enough_xml_to_parse():
    import xml.etree.ElementTree as ET

    svg = voucher_qr_svg("hello world")
    root = ET.fromstring(svg)  # ต้อง parse ผ่านโดยไม่ throw -- ยืนยันว่าเป็น well-formed markup
    assert root.tag.endswith("svg")


# ================================================================== ส่วนที่ 2: หน้า /issue/result ผ่าน Flask


GOOD_PW = "CafeWifi2026Secure"
_NOW = datetime(2026, 8, 26, 12, 0, 0)

STAFF = [{"id": 1, "username": "admin1", "password_hash": crypto.hash_password(GOOD_PW),
         "display_name": "Admin", "role": "admin", "is_active": 1}]
CUSTOMERS: dict[int, dict] = {}
VOUCHERS: dict[int, dict] = {}
REVEALS: dict[str, dict] = {}
_ids = {"customer": 0, "voucher": 0}


def _reset():
    CUSTOMERS.clear()
    VOUCHERS.clear()
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
            CUSTOMERS[cid] = dict(id=cid, natid_hash=args[0], natid_enc=args[1],
                                  natid_masked=args[2])
            self.lastrowid = cid
        elif s.startswith("insert into voucher ("):
            _ids["voucher"] += 1
            vid = _ids["voucher"]
            VOUCHERS[vid] = dict(id=vid, customer_id=args[0], username=args[1])
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
            self.rowcount = 1
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


def test_issue_result_embeds_inline_svg_qr(client):
    r = client.post("/issue", data=dict(natid=NID, hours="4", devices="2", consent="on"))
    assert r.status_code == 302

    html = client.get("/issue/result").get_data(as_text=True)
    assert "<svg" in html, "ต้องฝัง SVG ตรง ๆ ในหน้า ไม่ใช่ <img src=...> หรือโหลดจากที่อื่น"
    assert "<?xml" not in html


def test_issue_result_has_no_cdn_or_external_references(client):
    """ทั้งโปรเจกต์ห้ามใช้ CDN (asset local ล้วน) -- ต้องไม่มีแท็กที่โหลดทรัพยากรจากนอกเครื่อง
    (xmlns ของ SVG ไม่นับ -- ดูเหตุผลใน test_voucher_qr_svg_has_no_external_references)"""
    client.post("/issue", data=dict(natid=NID, hours="4", devices="2", consent="on"))
    html = client.get("/issue/result").get_data(as_text=True)
    assert 'src="http' not in html
    assert 'href="http' not in html


def test_issue_result_has_print_button_and_noprint_banner(client):
    """ปุ่มพิมพ์สลิป + banner เตือน 'แสดงครั้งเดียว' ต้องซ่อนตอนพิมพ์ (.noprint)"""
    client.post("/issue", data=dict(natid=NID, hours="4", devices="2", consent="on"))
    html = client.get("/issue/result").get_data(as_text=True)
    assert "window.print()" in html
    assert 'class="msg warn noprint"' in html


def test_requirements_txt_pins_qrcode():
    import pathlib

    req = pathlib.Path(__file__).resolve().parents[1] / "app" / "requirements.txt"
    text = req.read_text(encoding="utf-8")
    assert "qrcode" in text.lower()
