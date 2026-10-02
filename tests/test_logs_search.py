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
NATID_A = "1101700000010"   # เลขทดสอบ checksum ถูก
CUSTOMERS = [
    {"id": 1, "natid_masked": "1-2345-XXXXX-XX-3", "natid_hash": crypto.natid_hash(NATID_A)},
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
    if len(VOUCHERS) > 1:
        del VOUCHERS[1:]


def _lookup_mapping(mac, ip, ts):
    """จำลอง common/log_mapping.py: session เดียวเท่านั้นที่ครอบเวลานี้ -> (voucher, masked, customer_id)"""
    candidates = [s for s in SESSIONS if s["mac"] == mac and s["ip"] == ip
                  and s["authenticated_at"] <= ts
                  and (s["ended_at"] is None or ts <= s["ended_at"])]
    if len(candidates) != 1:
        return None, None, None
    v = next((v for v in VOUCHERS if v["id"] == candidates[0]["voucher_id"]), None)
    if v:
        c = next((c for c in CUSTOMERS if c["id"] == v["customer_id"]), None)
        return v["username"], (c["natid_masked"] if c else None), (c["id"] if c else None)
    return None, None, None


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
        elif s.startswith("select id from customer where natid_hash"):
            self._rows = [c for c in CUSTOMERS if c["natid_hash"] == args[0]]
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

    def _filters(self, s, args, alias):
        """อ่านเงื่อนไขตามลำดับที่ admin/app.py::search_logs() ต่อจริง แล้วคืน (predicate, limit, offset)"""
        start, end = args[0], args[1]
        idx = 2
        preds = [lambda r, m: start <= r["ts"] <= end]
        if "and c.id = %s" in s:
            cid = args[idx]; idx += 1
            preds.append(lambda r, m: m[2] == cid)
        if "and v.username = %s" in s:
            vu = args[idx]; idx += 1
            preds.append(lambda r, m: m[0] == vu)
        if f"and {alias}.mac = %s" in s:
            mac = args[idx]; idx += 1
            preds.append(lambda r, m: r["mac"] == mac)
        if "and (cl.src_ip = %s or cl.dst_ip = %s)" in s:
            ip = args[idx]; idx += 2
            preds.append(lambda r, m: ip in (r["src_ip"], r["dst_ip"]))
        if "and (dl.client_ip = %s or dl.answer = %s)" in s:
            ip = args[idx]; idx += 2
            preds.append(lambda r, m: ip in (r["client_ip"], r.get("answer")))
        if "and dl.qname like %s" in s:
            dom = args[idx].strip("%"); idx += 1
            preds.append(lambda r, m: dom in r["qname"])
        if "and cl.dst_ip in (select d2.answer from dns_log d2" in s:
            dom, w0, w1 = args[idx].strip("%"), args[idx + 1], args[idx + 2]; idx += 3
            ips = {d.get("answer") for d in DNS_LOGS if dom in d["qname"]
                   and d.get("event_kind") == "answer" and w0 <= d["ts"] <= w1}
            preds.append(lambda r, m: r["dst_ip"] in ips)
        if "and v.id is not null" in s:
            preds.append(lambda r, m: m[0] is not None)
        if "and dl.event_kind = 'query'" in s:
            preds.append(lambda r, m: r.get("event_kind", "query") == "query")
        return (lambda r, m: all(p(r, m) for p in preds)), args[idx], args[idx + 1]

    def _search(self, s, args, table, alias, ipfield):
        pred, limit, offset = self._filters(s, args, alias)
        out = []
        for r in sorted(table, key=lambda r: r["ts"], reverse=True):
            m = _lookup_mapping(r["mac"], r[ipfield], r.get("started_at") or r["ts"])
            if pred(r, m):
                out.append(dict(r, event_kind=r.get("event_kind", "query"),
                                started_at=r.get("started_at"),
                                voucher_username=m[0], natid_masked=m[1]))
        return out[offset:offset + limit]

    def _search_conn(self, s, args):
        return self._search(s, args, CONN_LOGS, "cl", "src_ip")

    def _search_dns(self, s, args):
        return self._search(s, args, DNS_LOGS, "dl", "client_ip")

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
    r = client.get("/logs", query_string=AUG1)
    assert r.status_code == 200


AUG1 = {"range": "custom", "start": "2026-08-01T00:00", "end": "2026-08-02T00:00"}


def _q(**over):
    return dict(AUG1, **over)


def _conn(minute=0, mac="AA:BB:CC:DD:EE:01", src="10.10.0.105", dst="93.184.216.34", **kw):
    row = dict(ts=datetime(2026, 8, 1, 10, minute), mac=mac, src_ip=src, src_port=51322,
               dst_ip=dst, dst_port=443, proto="tcp", bytes_out=1400, bytes_in=8_200_000)
    row.update(kw)
    CONN_LOGS.append(row)


# ---------------------------------------------------------------- เปิดหน้า / ช่วงเวลา
def test_first_visit_shows_form_without_searching(client):
    _login_as(client, "admin")
    r = client.get("/logs")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'name="q"' in html and "วันนี้" in html and "1 ชม.ล่าสุด" in html
    assert len(AUDIT) == 0, "ยังไม่ได้ค้น = ไม่ลง audit"


def test_preset_range_searches_today(client):
    _login_as(client, "admin")
    now = datetime.now()
    CONN_LOGS.append(dict(ts=now - timedelta(minutes=1), mac="AA:BB:CC:DD:EE:01", src_ip="10.10.0.9",
                          src_port=1, dst_ip="8.8.4.4", dst_port=443, proto="tcp",
                          bytes_out=1, bytes_in=1))
    html = client.get("/logs", query_string={"range": "1h"}).get_data(as_text=True)
    assert "8.8.4.4" in html
    assert AUDIT and AUDIT[0][1] == "search_log"


def test_custom_range_validation(client):
    _login_as(client, "admin")
    assert client.get("/logs", query_string={"range": "custom"}).status_code == 400
    assert client.get("/logs", query_string=_q(start="2026-08-05T00:00", end="2026-08-01T00:00")).status_code == 400
    assert client.get("/logs", query_string=_q(end="2026-09-15T00:00")).status_code == 400, "เกิน 31 วัน"
    assert len(AUDIT) == 0


# ---------------------------------------------------------------- ช่องค้นหาเดียว เดาชนิดเอง
def test_search_by_mac_any_format_finds_rows_and_maps_customer(client):
    _login_as(client, "admin")
    _conn(0)
    _conn(5, mac="11:22:33:44:55:66", src="10.10.0.200", dst="1.1.1.1")
    for typed in ("AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-01", "aabbccddee01"):
        html = client.get("/logs", query_string=_q(q=typed)).get_data(as_text=True)
        assert "93.184.216.34" in html and "1.1.1.1" not in html, typed
        assert "1-2345-XXXXX-XX-3" in html and "CAFE-8F3K2" in html
        assert "8.2 MB" in html, "ขนาดต้องอ่านง่าย ไม่ใช่ bytes ดิบ"


def test_search_by_natid_and_voucher_code(client):
    _login_as(client, "staff")
    _conn(0)
    _conn(5, mac="11:22:33:44:55:66", src="10.10.0.200", dst="1.1.1.1")
    for typed in (NATID_A, "1-1017-00000-01-0", "cafe-8f3k2"):
        html = client.get("/logs", query_string=_q(q=typed)).get_data(as_text=True)
        assert "93.184.216.34" in html and "1.1.1.1" not in html, typed
    assert all(NATID_A not in str(a) for a in AUDIT), "ห้ามลงเลขบัตรเต็มใน audit"
    assert "kind=natid" in AUDIT[0][4]


def test_unknown_customer_natid_says_not_found(client):
    _login_as(client, "admin")
    html = client.get("/logs", query_string=_q(q="1101700000028")).get_data(as_text=True)
    assert "ไม่พบลูกค้า" in html


def test_bad_query_formats_rejected(client):
    _login_as(client, "admin")
    assert client.get("/logs", query_string=_q(q="1234567890123")).status_code == 400  # checksum ผิด
    assert client.get("/logs", query_string=_q(q="<script>")).status_code == 400


def test_search_by_ip_matches_source_or_destination(client):
    _login_as(client, "admin")
    _conn(0)
    _conn(5, mac="11:22:33:44:55:66", src="10.10.0.200", dst="1.1.1.1")
    html = client.get("/logs", query_string=_q(q="1.1.1.1")).get_data(as_text=True)
    assert "10.10.0.200" in html and "93.184.216.34" not in html


def test_overlapping_sessions_do_not_claim_a_person_twice(client):
    _login_as(client, "admin")
    _conn(0)
    SESSIONS.append(dict(mac="AA:BB:CC:DD:EE:01", ip="10.10.0.105", voucher_id=2,
                         authenticated_at=datetime(2026, 8, 1, 9, 0), ended_at=None))
    html = client.get("/logs", query_string=AUG1).get_data(as_text=True)
    assert html.count(">93.184.216.34<") == 1, "แถวเดียว ไม่ซ้ำ"
    assert "ยังไม่ระบุตัว" in html and "1-2345-XXXXX-XX-3" not in html
    html = client.get("/logs", query_string=_q(identified="1")).get_data(as_text=True)
    assert "93.184.216.34" not in html, "ติ๊ก 'เฉพาะที่ระบุตัวได้' ต้องซ่อนแถวที่ไม่รู้เจ้าของ"


# ---------------------------------------------------------------- DNS / ชื่อเว็บ
def _dns(minute, qname, answer, kind="query", client_ip="10.10.0.105"):
    DNS_LOGS.append(dict(ts=datetime(2026, 8, 1, 9, minute), client_ip=client_ip if kind == "query" else None,
                         mac="AA:BB:CC:DD:EE:01" if kind == "query" else None, qname=qname,
                         qtype="A" if kind == "query" else None, answer=answer, event_kind=kind))


def test_search_by_domain_finds_dns_rows_and_hides_answers_by_default(client):
    _login_as(client, "admin")
    _dns(0, "www.example.com", None)
    _dns(0, "www.example.com", "93.184.216.34", kind="answer")
    _dns(1, "ads.tracker.net", None)
    html = client.get("/logs", query_string=_q(log_type="dns", q="example")).get_data(as_text=True)
    assert "www.example.com" in html and "ads.tracker.net" not in html
    assert "93.184.216.34" not in html, "คำตอบ DNS ซ่อนเป็นค่าเริ่มต้น"
    html = client.get("/logs", query_string=_q(log_type="dns", q="example", answers="1")).get_data(as_text=True)
    assert "93.184.216.34" in html


def test_domain_search_in_connection_tab_uses_dns_answers(client):
    """ใครเชื่อมต่อไปเว็บนี้: conn_log ไม่มีชื่อเว็บ -- ใช้ IP ที่ DNS ตอบสำหรับเว็บนั้น"""
    _login_as(client, "admin")
    _dns(0, "www.example.com", "93.184.216.34", kind="answer")
    _conn(0)
    _conn(5, mac="11:22:33:44:55:66", src="10.10.0.200", dst="1.1.1.1")
    html = client.get("/logs", query_string=_q(q="example.com")).get_data(as_text=True)
    assert "93.184.216.34" in html and "1.1.1.1" not in html
    assert "ประมาณจาก IP" in html


# ---------------------------------------------------------------- pagination / ลิงก์ค้นต่อ
def test_pagination_keeps_filters(client):
    _login_as(client, "admin")
    for i in range(55):  # เกิน LOGS_PAGE_SIZE (50) ไป 5 แถว
        CONN_LOGS.append(dict(ts=datetime(2026, 8, 1, 0, 0) + timedelta(minutes=i),
                              mac="AA:BB:CC:DD:EE:01", src_ip="10.10.0.105", src_port=1000 + i,
                              dst_ip="1.1.1.1", dst_port=443, proto="tcp", bytes_out=10, bytes_in=10))
    html1 = client.get("/logs", query_string=_q(q="aabbccddee01")).get_data(as_text=True)
    assert "เก่ากว่า" in html1 and "ใหม่กว่า" not in html1
    assert "page=2" in html1 and "q=aabbccddee01" in html1, "หน้าถัดไปต้องค้นด้วยเงื่อนไขเดิม"
    html2 = client.get("/logs", query_string=_q(q="aabbccddee01", page="2")).get_data(as_text=True)
    assert "ใหม่กว่า" in html2 and "เก่ากว่า" not in html2


def test_values_in_results_link_to_new_search(client):
    _login_as(client, "admin")
    _conn(0)
    html = client.get("/logs", query_string=AUG1).get_data(as_text=True)
    assert "q=CAFE-8F3K2" in html and "q=93.184.216.34" in html


# ---------------------------------------------------------------- audit / สิทธิ์ / CSV
def test_every_successful_search_writes_audit_log(client):
    _login_as(client, "admin")
    client.get("/logs", query_string=_q(q="AA:BB:CC:DD:EE:01"))
    assert len(AUDIT) == 1 and AUDIT[0][1] == "search_log"
    detail = AUDIT[0][4]
    assert "q=AA:BB:CC:DD:EE:01" in detail and "kind=mac" in detail and "start=2026-08-01" in detail


def test_staff_sees_masked_natid_not_full_number(client):
    _login_as(client, "staff")
    _conn(0)
    html = client.get("/logs", query_string=AUG1).get_data(as_text=True)
    assert "1-2345-XXXXX-XX-3" in html  # masked เท่านั้น -- คิวรี่ไม่เคย SELECT natid_enc/natid_hash เลย
    assert "ดาวน์โหลด CSV" not in html


def test_csv_download_admin_only_and_audited(client):
    _login_as(client, "staff")
    _conn(0)
    assert client.get("/logs", query_string=_q(format="csv")).status_code == 403
    _login_as(client, "admin")
    r = client.get("/logs", query_string=_q(format="csv"))
    assert r.status_code == 200 and r.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in r.headers["Content-Disposition"]
    body = r.get_data(as_text=True)
    assert "93.184.216.34" in body and "CAFE-8F3K2" in body
    assert AUDIT[-1][1] == "export_log" and "rows=1" in AUDIT[-1][4]


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
        client.get("/logs", query_string=_q(log_type="conn"))
    finally:
        FakeCursor._search_conn = orig
    assert "s.authenticated_at <= coalesce(cl.started_at, cl.ts)" in captured[0]
    assert "coalesce(cl.started_at, cl.ts) <= s.ended_at" in captured[0]
