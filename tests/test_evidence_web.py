"""หน้า /evidence -- ส่งออกหลักฐานจากหน้าแอดมิน (ใช้ตรรกะชุดเดียวกับ tools/export_evidence.py)

คิวรี่ SQL ของการส่งออกทดสอบแล้วใน test_purge_and_export.py -- ที่นี่ทดสอบสิ่งที่หน้าเว็บเพิ่มเข้ามา:
สิทธิ์, การตรวจค่าที่กรอก, เนื้อหา ZIP + manifest + SHA-256, และ audit ที่ห้ามมีเลขบัตรเต็ม
"""
import hashlib
import io
import json
import sys
import zipfile
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_logs_search as base  # noqa: E402  ใช้ DB จำลอง + ผู้ใช้ชุดเดียวกัน

NATID = base.NATID_A
CONN = [dict(ts=datetime(2026, 8, 1, 10, 0), started_at=datetime(2026, 8, 1, 9, 59), mac="AA:BB:CC:DD:EE:01",
             src_ip="10.10.0.105", src_port=51322, dst_ip="93.184.216.34", dst_port=443, proto="tcp",
             bytes_out=1400, bytes_in=8200, voucher_username="CAFE-8F3K2", natid_masked="1-2345-XXXXX-XX-3",
             device_hostname="Somchais-iPhone", device_os="iPhone · iOS 17.5")]
DNS = [dict(ts=datetime(2026, 8, 1, 9, 59), event_kind="query", client_ip="10.10.0.105", mac="AA:BB:CC:DD:EE:01",
            qname="www.example.com", qtype="A", answer=None, voucher_username="CAFE-8F3K2",
            natid_masked="1-2345-XXXXX-XX-3", device_hostname="Somchais-iPhone", device_os="iPhone · iOS 17.5")]


@pytest.fixture
def client(monkeypatch):
    c = base.make_client(monkeypatch)
    from tools import export_evidence as ev
    seen = {}
    monkeypatch.setattr(ev, "build_conn_query", lambda s, e, mac=None, ip=None, customer_id=None:
                        ("EV_CONN", (s, e, mac, customer_id)))
    monkeypatch.setattr(ev, "build_dns_query", lambda s, e, mac=None, ip=None, customer_id=None:
                        ("EV_DNS", (s, e, mac, customer_id)))
    import admin.app as admin_app
    real_all, real_one = admin_app.query_all, admin_app.query_one

    def q_all(sql, args=()):
        if sql == "EV_CONN":
            seen["conn"] = args
            return list(CONN)
        if sql == "EV_DNS":
            return list(DNS)
        if "FROM portal_session ps JOIN voucher v" in sql and "DISTINCT" in sql:
            return [dict(mac="AA:BB:CC:DD:EE:01", ip="10.10.0.105")]
        if "FROM audit_log a" in sql:
            return [dict(ts=datetime(2026, 10, 3, 14, 0), username="admin", target=a[2],
                         detail=a[4]) for a in base.AUDIT if a[1] == "export_log"]
        return real_all(sql, args)

    def q_one(sql, args=()):
        if sql.startswith("SELECT id, natid_masked FROM customer WHERE natid_hash"):
            return next(({"id": c["id"], "natid_masked": c["natid_masked"]}
                         for c in base.CUSTOMERS if c["natid_hash"] == args[0]), None)
        return real_one(sql, args)
    monkeypatch.setattr(admin_app, "query_all", q_all)
    monkeypatch.setattr(admin_app, "query_one", q_one)
    c.seen = seen
    return c


def _post(c, **kw):
    data = dict(who="natid", natid=NATID, start="2026-08-01", end="2026-08-01",
                reason="หนังสือ สภ.เมือง ที่ 1234/2569")
    data.update(kw)
    return c.post("/evidence", data=data)


def test_staff_cannot_open_evidence_page(client):
    base._login_as(client, "staff")
    assert client.get("/evidence").status_code == 403
    assert _post(client).status_code == 403


def test_export_by_natid_returns_zip_with_verifiable_hashes(client):
    base._login_as(client, "admin")
    assert "ส่งออกหลักฐานให้เจ้าหน้าที่" in client.get("/evidence").get_data(as_text=True)
    r = _post(client)
    assert r.status_code == 200 and r.headers["Content-Type"] == "application/zip"
    data = r.get_data()
    assert r.headers["X-Evidence-SHA256"] == hashlib.sha256(data).hexdigest()
    z = zipfile.ZipFile(io.BytesIO(data))
    names = z.namelist()
    assert "manifest.json" in names and "README.txt" in names
    manifest = json.loads(z.read("manifest.json"))
    assert manifest["criteria"]["natid_masked"] == "1-2345-XXXXX-XX-3"
    assert manifest["criteria"]["reason"].startswith("หนังสือ")
    for f in manifest["files"]:
        body = z.read(f["filename"]).decode("utf-8").lstrip("﻿")
        assert hashlib.sha256(body.encode("utf-8")).hexdigest() == f["sha256"], "ตรวจ hash ได้จริง"
    conn_csv = z.read(next(n for n in names if n.startswith("conn_log"))).decode("utf-8")
    assert "93.184.216.34" in conn_csv and "Somchais-iPhone" in conn_csv
    # ทั้งวันที่ 1 ส.ค. (ถึง 23:59:59)
    s, e = client.seen["conn"][0], client.seen["conn"][1]
    assert (s.hour, e.hour, e.minute) == (0, 23, 59)


def test_export_is_audited_without_full_natid(client):
    base._login_as(client, "admin")
    data = _post(client).get_data()
    (a,) = [a for a in base.AUDIT if a[1] == "export_log"]
    assert a[2].startswith("evidence:customer:1")
    assert hashlib.sha256(data).hexdigest() in a[4] and "สภ.เมือง" in a[4]
    assert all(NATID not in str(x) for x in base.AUDIT)
    assert "สภ.เมือง" in client.get("/evidence").get_data(as_text=True), "ประวัติการส่งออก"


@pytest.mark.parametrize("kw,msg", [
    (dict(reason="สั้น"), "อย่างน้อย 10"),
    (dict(natid="1234567890123"), "ไม่ถูกต้อง"),
    (dict(natid="1101700000028"), "ไม่พบลูกค้า"),
    (dict(end="2026-07-01"), "ไม่ก่อนวันที่เริ่มต้น"),
    (dict(who="mac", mac="zz"), "MAC"),
    (dict(who="all", end="2026-08-20"), "ไม่เกิน 7 วัน"),
])
def test_bad_input_rejected_and_not_audited(client, kw, msg):
    base._login_as(client, "admin")
    r = _post(client, **kw)
    assert r.status_code == 400 and msg in r.get_data(as_text=True)
    assert not [a for a in base.AUDIT if a[1] == "export_log"]


def test_export_by_mac(client):
    base._login_as(client, "admin")
    r = _post(client, who="mac", mac="aa-bb-cc-dd-ee-01")
    assert r.status_code == 200 and "aabbccddee01" in r.headers["Content-Disposition"].lower()
    assert client.seen["conn"][2] == "AA:BB:CC:DD:EE:01"
