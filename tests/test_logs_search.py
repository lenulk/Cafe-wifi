"""
T-LogsSearch — หน้าเว็บค้น log ใน Admin (N9, CODING_BRIEF.md) ⭐ ช่องว่างที่ใหญ่ที่สุด

DoD ของ Phase 4 เขียนว่า "ค้นย้อนกลับใน Admin เจอครบ" และ T10 ทดสอบไม่ได้เลยถ้าไม่มีหน้านี้
(เดิมมีแค่ export ผ่าน command line ใน tools/export_evidence.py)

FakeCursor ในไฟล์นี้จำลอง JOIN/filter ของคิวรี่จริงใน admin/app.py::search_logs() ด้วย Python
ล้วน ๆ (ไม่ใช้ SQLite) เพราะ SQL ที่ประกอบขึ้นมีเงื่อนไข AND แบบไดนามิกตามฟิลเตอร์ที่กรอก --
ตรวจจับด้วย substring ของ SQL ที่ normalize แล้วว่ามีเงื่อนไขไหนบ้าง แล้วดึงพารามิเตอร์ตาม
ลำดับที่โค้ดจริง append (start, end, [mac], [ip, ip], limit, offset เสมอ) ตรงกับพฤติกรรมจริง
เป๊ะเพราะเราคุมทั้ง route และเทสต์เอง
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timedelta

import pytest

from common import crypto

GOOD_PW = "CafeWifi2026Secure"

STAFF = [
    {"id": 1, "username": "admin1", "password_hash": crypto.hash_password(GOOD_PW),
     "display_name": "Admin", "role": "admin", "is_active": 1},
    {"id": 2, "username": "staff1", "password_hash": crypto.hash_password(GOOD_PW),
     "display_name": "Staff", "role": "staff", "is_active": 1},
]

# ---------------------------------------------------------------- ข้อมูลจำลอง
CUSTOMERS = [
    {"id": 1, "natid_masked": "1-2345-XXXXX-XX-3"},
]
VOUCHERS = [
    {"id": 1, "customer_id": 1, "username": "CAFE-8F3K2",
     "valid_from": datetime(2026, 8, 1, 0, 0), "valid_until": datetime(2026, 8, 3, 0, 0)},
]
DEVICES = [
    {"mac": "AA:BB:CC:DD:EE:01", "voucher_id": 1},
]
SESSIONS = [
    {"mac": "AA:BB:CC:DD:EE:01", "ip": "10.10.0.105", "voucher_id": 1,
     "authenticated_at": datetime(2026, 8, 1, 0, 0),
     "ended_at": datetime(2026, 8, 3, 0, 0)},
]
CONN_LOGS: list[dict] = []
DNS_LOGS: list[dict] = []
AUDIT: list[tuple] = []


def _reset():
    CONN_LOGS.clear()
    DNS_LOGS.clear()
    AUDIT.clear()
    del SESSIONS[1:]


def _lookup_mapping(mac: str, ip: str, ts: datetime) -> tuple[str | None, str | None]:
    candidates = [s for s in SESSIONS if s["mac"] == mac and s["ip"] == ip
                  and s["authenticated_at"] <= ts
                  and (s["ended_at"] is None or ts <= s["ended_at"])]
    if len(candidates) != 1:
        return None, None
    v = next((v for v in VOUCHERS if v["id"] == candidates[0]["voucher_id"]), None)
    if v:
        c = next((c for c in CUSTOMERS if c["id"] == v["customer_id"]), None)
        return v["username"], (c["natid_masked"] if c else None)
    return None, None


def _norm(sql: str) -> str:
    return " ".join(sql.split()).lower()


class FakeCursor:
    def __init__(self):
        self.lastrowid = None
        self.rowcount = 0
        self._rows = []

    def execute(self, sql, args=()):
        s = _norm(sql)
        if s.startswith("select count(*) as n from staff"):
            self._rows = [{"n": len(STAFF)}]
        elif s.startswith("select role, is_active"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("insert into audit_log"):
            AUDIT.append(args)
            self.rowcount = 1
        elif "from conn_log cl" in s:
            assert "portal_session" in s
            self._rows = self._search_conn(s, args)
        elif "from dns_log dl" in s:
            assert "portal_session" in s
            self._rows = self._search_dns(s, args)
        elif s.startswith("select count(*) as n from access_request"):
            self._rows = [{"n": 0}]  # ตัวเลขคำขอที่รออนุมัติบนเมนู
        else:
            raise AssertionError(f"FakeCursor ไม่รู้จัก SQL: {s[:120]}")

    def _search_conn(self, s, args):
        idx = 2
        mac_val = ip_val = None
        if "and cl.mac = %s" in s:
            mac_val = args[idx]; idx += 1
        if "and (cl.src_ip = %s or cl.dst_ip = %s)" in s:
            ip_val = args[idx]; idx += 2
        start, end = args[0], args[1]
        limit, offset = args[idx], args[idx + 1]

        rows = [r for r in CONN_LOGS if start <= r["ts"] <= end
               and (not mac_val or r["mac"] == mac_val)
               and (not ip_val or ip_val in (r["src_ip"], r["dst_ip"]))]
        rows.sort(key=lambda r: r["ts"], reverse=True)
        out = []
        for r in rows[offset:offset + limit]:
            vu, nm = _lookup_mapping(r["mac"], r["src_ip"], r["ts"])
            out.append(dict(r, voucher_username=vu, natid_masked=nm))
        return out

    def _search_dns(self, s, args):
        idx = 2
        mac_val = domain_val = None
        if "and dl.mac = %s" in s:
            mac_val = args[idx]; idx += 1
        if "and dl.qname like %s" in s:
            domain_val = args[idx].strip("%"); idx += 1
        start, end = args[0], args[1]
        limit, offset = args[idx], args[idx + 1]

        rows = [r for r in DNS_LOGS if start <= r["ts"] <= end
               and (not mac_val or r["mac"] == mac_val)
               and (not domain_val or domain_val in r["qname"])]
        rows.sort(key=lambda r: r["ts"], reverse=True)
        out = []
        for r in rows[offset:offset + limit]:
            vu, nm = _lookup_mapping(r["mac"], r["client_ip"], r["ts"])
            out.append(dict(r, event_kind=r.get("event_kind", "query"),
                            voucher_username=vu, natid_masked=nm))
        return out

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
    return admin_app.app.test_client()


def _login_as(client, role):
    staff = next(s for s in STAFF if s["role"] == role)
    with client.session_transaction() as sess:
        sess["staff_id"] = staff["id"]
        sess["username"] = staff["username"]
        sess["role"] = staff["role"]


# ---------------------------------------------------------------- สิทธิ์เข้าถึงพื้นฐาน
def test_search_requires_login(client):
    r = client.get("/logs")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_staff_role_can_access_not_admin_only(client):
    """ต่างจาก /reveal, /logs/verify -- หน้านี้ @login_required เฉย ๆ ไม่ต้อง admin"""
    _login_as(client, "staff")
    r = client.get("/logs", query_string={"start": "2026-08-01T00:00", "end": "2026-08-02T00:00"})
    assert r.status_code == 200


# ---------------------------------------------------------------- ปฏิเสธถ้าไม่กรอกช่วงเวลา
def test_missing_time_range_is_rejected(client):
    _login_as(client, "admin")
    r = client.get("/logs")
    assert r.status_code == 400
    assert "ช่วงเวลา" in r.get_data(as_text=True)
    assert len(AUDIT) == 0, "ไม่ควรลง audit_log เพราะยังไม่มีการค้นเกิดขึ้นจริง"


def test_end_before_start_is_rejected(client):
    _login_as(client, "admin")
    r = client.get("/logs", query_string={"start": "2026-08-05T00:00", "end": "2026-08-01T00:00"})
    assert r.status_code == 400


# ---------------------------------------------------------------- ค้นด้วย MAC เจอ (conn_log)
def test_search_by_mac_finds_conn_log_rows_and_maps_customer(client):
    _login_as(client, "admin")
    CONN_LOGS.append(dict(ts=datetime(2026, 8, 1, 10, 0), mac="AA:BB:CC:DD:EE:01",
                          src_ip="10.10.0.105", src_port=51322, dst_ip="93.184.216.34",
                          dst_port=443, proto="tcp", bytes_out=1400, bytes_in=8200))
    # แถวของ mac อื่นที่ไม่ควรติดมาด้วย
    CONN_LOGS.append(dict(ts=datetime(2026, 8, 1, 10, 5), mac="11:22:33:44:55:66",
                          src_ip="10.10.0.200", src_port=1234, dst_ip="1.1.1.1",
                          dst_port=53, proto="udp", bytes_out=60, bytes_in=90))

    r = client.get("/logs", query_string={"log_type": "conn", "start": "2026-08-01T00:00",
                                          "end": "2026-08-02T00:00", "mac": "AA:BB:CC:DD:EE:01"})
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "AA:BB:CC:DD:EE:01" in html
    assert "93.184.216.34" in html
    assert "11:22:33:44:55:66" not in html  # กรองตาม mac ถูกต้อง ไม่ปนแถวอื่น
    assert "1-2345-XXXXX-XX-3" in html  # mapping ย้อนกลับถึงลูกค้า (masked)
    assert "CAFE-8F3K2" in html


def test_overlapping_sessions_do_not_claim_a_person_twice(client):
    _login_as(client, "admin")
    CONN_LOGS.append(dict(ts=datetime(2026, 8, 1, 10, 0), mac="AA:BB:CC:DD:EE:01",
                          src_ip="10.10.0.105", src_port=51322, dst_ip="93.184.216.34",
                          dst_port=443, proto="tcp", bytes_out=1400, bytes_in=8200))
    SESSIONS.append(dict(mac="AA:BB:CC:DD:EE:01", ip="10.10.0.105", voucher_id=2,
                         authenticated_at=datetime(2026, 8, 1, 9, 0), ended_at=None))
    r = client.get("/logs", query_string={"start": "2026-08-01T00:00", "end": "2026-08-02T00:00"})
    html = r.get_data(as_text=True)
    assert html.count("93.184.216.34") == 1
    assert "ระบุตัวไม่แน่นอน" in html
    assert "1-2345-XXXXX-XX-3" not in html


# ---------------------------------------------------------------- ค้นด้วยโดเมนเจอ (dns_log)
def test_search_by_domain_finds_dns_log_rows(client):
    _login_as(client, "admin")
    DNS_LOGS.append(dict(ts=datetime(2026, 8, 1, 9, 0), client_ip="10.10.0.105",
                        mac="AA:BB:CC:DD:EE:01", qname="www.example.com", qtype="A",
                        answer="93.184.216.34"))
    DNS_LOGS.append(dict(ts=datetime(2026, 8, 1, 9, 1), client_ip="10.10.0.105",
                        mac="AA:BB:CC:DD:EE:01", qname="ads.tracker.net", qtype="A",
                        answer="203.0.113.5"))

    r = client.get("/logs", query_string={"log_type": "dns", "start": "2026-08-01T00:00",
                                          "end": "2026-08-02T00:00", "domain": "example"})
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "www.example.com" in html
    assert "ads.tracker.net" not in html  # ไม่ตรง "example" ต้องไม่ติดมา


# ---------------------------------------------------------------- pagination
def test_pagination_limits_rows_per_page_and_has_next(client):
    _login_as(client, "admin")
    for i in range(55):  # เกิน LOGS_PAGE_SIZE (50) ไป 5 แถว
        CONN_LOGS.append(dict(ts=datetime(2026, 8, 1, 0, 0) + timedelta(minutes=i),
                              mac="AA:BB:CC:DD:EE:01", src_ip="10.10.0.105", src_port=1000 + i,
                              dst_ip="1.1.1.1", dst_port=443, proto="tcp", bytes_out=10, bytes_in=10))

    r1 = client.get("/logs", query_string={"start": "2026-08-01T00:00", "end": "2026-08-02T00:00"})
    assert r1.status_code == 200
    html1 = r1.get_data(as_text=True)
    assert "ถัดไป" in html1  # มีหน้าถัดไปเพราะเกิน 50 แถว
    assert "ก่อนหน้า" not in html1  # หน้าแรกไม่มีก่อนหน้า

    r2 = client.get("/logs", query_string={"start": "2026-08-01T00:00", "end": "2026-08-02T00:00",
                                           "page": "2"})
    assert r2.status_code == 200
    html2 = r2.get_data(as_text=True)
    assert "ก่อนหน้า" in html2
    assert "ถัดไป" not in html2  # หน้า 2 มีแค่ 5 แถวที่เหลือ ไม่มีหน้าถัดไปอีก


# ---------------------------------------------------------------- audit_log ทุกครั้งที่ค้น
def test_every_successful_search_writes_audit_log(client):
    _login_as(client, "admin")
    client.get("/logs", query_string={"start": "2026-08-01T00:00", "end": "2026-08-02T00:00",
                                      "mac": "AA:BB:CC:DD:EE:01"})
    assert len(AUDIT) == 1
    assert AUDIT[0][1] == "search_log"
    detail = AUDIT[0][4]
    assert "mac=AA:BB:CC:DD:EE:01" in detail
    assert "start=2026-08-01" in detail


# ---------------------------------------------------------------- staff เห็น masked ไม่ใช่เลขเต็ม
def test_staff_sees_masked_natid_not_full_number(client):
    _login_as(client, "staff")
    CONN_LOGS.append(dict(ts=datetime(2026, 8, 1, 10, 0), mac="AA:BB:CC:DD:EE:01",
                          src_ip="10.10.0.105", src_port=1, dst_ip="1.1.1.1", dst_port=443,
                          proto="tcp", bytes_out=1, bytes_in=1))
    html = client.get("/logs", query_string={"start": "2026-08-01T00:00",
                                             "end": "2026-08-02T00:00"}).get_data(as_text=True)
    assert "1-2345-XXXXX-XX-3" in html  # masked เท่านั้น -- คิวรี่ไม่เคย SELECT natid_enc/natid_hash เลย


def test_conn_log_maps_owner_by_start_time_not_destroy_time(client):
    """R2-02: conn_log.ts คือเวลา DESTROY ซึ่งเลยช่วง session ของเจ้าของไปได้ -- การจับคู่
    กับ portal_session ต้องใช้เวลาเริ่ม (started_at) ถ้ามี"""
    _login_as(client, "admin")
    captured = []
    orig = FakeCursor._search_conn

    def spy(self, s, args):
        captured.append(s)
        return orig(self, s, args)

    FakeCursor._search_conn = spy
    try:
        client.get("/logs", query_string={"log_type": "conn", "start": "2026-08-01T00:00",
                                          "end": "2026-08-02T00:00"})
    finally:
        FakeCursor._search_conn = orig
    assert "s.authenticated_at <= coalesce(cl.started_at, cl.ts)" in captured[0]
    assert "coalesce(cl.started_at, cl.ts) <= s.ended_at" in captured[0]
