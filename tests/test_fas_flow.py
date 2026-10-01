"""
T-FAS — Captive Portal end-to-end (mock openNDS gateway + DB จำลอง)

จำลองฝั่ง openNDS เองด้วย encrypt_fas_payload (เราคุมทั้งสองฝั่ง เพราะไม่มี
openNDS binary จริงในสภาพแวดล้อมนี้ — ดูคำเตือนใน opennds_proto.py และ PROJECT_PLAN.md §17)
"""
import contextlib
import copy
from datetime import datetime, timedelta

import pytest

from common import crypto
from fas.opennds_proto import encrypt_fas_payload, auth_token

FASKEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # ตรงกับที่จะตั้งใน env ตอนเทสต์
GW_PARAMS = dict(clientip="10.10.0.105", clientmac="AA:BB:CC:DD:EE:01",
                 gatewayname="Cafe-Guest", client_hid="hid-0001",
                 # openNDS จริงส่งพร้อมพอร์ต (ดู test_opennds_proto.py) -- อย่าใช้ IP เปล่า ไม่งั้นจับบั๊กพอร์ตไม่ได้
                 gatewayaddress="10.10.0.1:2050", authdir="opennds_auth",
                 originurl="http://example.com/", clientif="eth1")

VOUCHERS: dict[str, dict] = {}
CUSTOMERS: dict[int, dict] = {}
DEVICES: list[dict] = []
SESSIONS: list[dict] = []
AUDIT: list[tuple] = []
FAS_CONTEXTS: dict[str, dict] = {}
CLAIMS: dict[str, int | None] = {}
ARP = {"mac": GW_PARAMS["clientmac"]}
_ids = {"customer": 0, "device": 0, "session": 0}


def _reset():
    VOUCHERS.clear(); CUSTOMERS.clear(); DEVICES.clear(); SESSIONS.clear(); AUDIT.clear(); FAS_CONTEXTS.clear(); CLAIMS.clear()
    ARP["mac"] = GW_PARAMS["clientmac"]
    _ids.update(customer=0, device=0, session=0)


def _make_voucher(code="CAFE-TEST1", hours=4, max_devices=2, blocked=False, status="active"):
    _ids["customer"] += 1
    cid = _ids["customer"]
    CUSTOMERS[cid] = dict(id=cid, is_blocked=blocked)
    now = datetime.now()
    VOUCHERS[code] = dict(
        id=len(VOUCHERS) + 1, username=code,
        password_hash=crypto.hash_password("TESTPASS"),
        valid_from=now - timedelta(minutes=1), valid_until=now + timedelta(hours=hours),
        status=status, max_devices=max_devices, customer_id=cid,
    )
    return code, "TESTPASS"


class FakeCursor:
    def __init__(self):
        self.lastrowid = None
        self._rows = []
        self.rowcount = 0

    def execute(self, sql, args=()):
        s = " ".join(sql.split()).lower()
        if s.startswith("select v.id, v.password_hash"):
            code = args[0]
            v = VOUCHERS.get(code)
            if not v:
                self._rows = []
            else:
                c = CUSTOMERS[v["customer_id"]]
                self._rows = [{**v, "is_blocked": c["is_blocked"]}]
        elif s.startswith("insert into fas_context"):
            key, payload, ip, expiry = args
            FAS_CONTEXTS[key] = dict(payload=payload, request_ip=ip, expires_at=expiry,
                                     consumed_at=None)
            self.rowcount = 1
        elif s.startswith("select payload, request_ip"):
            row = FAS_CONTEXTS.get(args[0])
            self._rows = [row] if row else []
        elif s.startswith("select id from voucher where id=%s for update"):
            self._rows = [{"id": args[0]}]
        elif s.startswith("select id from portal_session where mac=%s and state='pending' for update"):
            self._rows = [{"id": sess["id"]} for sess in SESSIONS
                          if sess["mac"] == args[0] and sess["state"] == "pending"]
        elif s.startswith("insert ignore into pending_mac_claim"):
            self.rowcount = int(args[0] not in CLAIMS)
            if self.rowcount:
                CLAIMS[args[0]] = None
        elif s.startswith("update pending_mac_claim set portal_session_id"):
            CLAIMS[args[1]] = args[0]
            self.rowcount = 1
        elif s.startswith("select count(*) as n from ("):
            vid = args[0]
            macs = {d["mac"] for d in DEVICES if d["voucher_id"] == vid}
            macs.update(sess["mac"] for sess in SESSIONS
                        if sess["voucher_id"] == vid and sess["state"] == "pending"
                        and sess["ended_at"] is None)
            self._rows = [{"n": len(macs)}]
        elif s.startswith("select 1 from device"):
            vid, mac, _, _ = args
            exists = any(d["voucher_id"] == vid and d["mac"] == mac for d in DEVICES)
            exists |= any(sess["voucher_id"] == vid and sess["mac"] == mac
                          and sess["state"] == "pending" and sess["ended_at"] is None
                          for sess in SESSIONS)
            self._rows = [{"1": 1}] if exists else []
        elif s.startswith("update fas_context set consumed_at=now()"):
            row = FAS_CONTEXTS.get(args[0])
            self.rowcount = int(bool(row and not row["consumed_at"]))
            if self.rowcount:
                row["consumed_at"] = datetime.now()
        elif s.startswith("update portal_session set state='closed'"):
            for sess in SESSIONS:
                if sess["mac"] == args[0] and sess["state"] == "pending":
                    sess["state"] = "closed"; sess["ended_at"] = "now"
        elif s.startswith("insert into portal_session"):
            vid, mac, ip = args
            _ids["session"] += 1
            SESSIONS.append(dict(id=_ids["session"], voucher_id=vid, mac=mac, ip=ip,
                                 started_at=f"t{_ids['session']}", ended_at=None,
                                 state="pending", bytes_out=0, bytes_in=0))
            self.lastrowid = _ids["session"]
        elif s.startswith("insert into audit_log"):
            AUDIT.append(args)
            self.lastrowid = len(AUDIT)
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
    """snapshot ตารางที่ POST /login เขียนตอนเปิด connection เพื่อให้ rollback() ย้อนได้จริง
    (R2-01: เดิมไม่มี rollback เทสต์จึงไม่เห็นว่า claim ค้างหลังถูกปฏิเสธ)"""

    def __init__(self):
        self._snapshot = copy.deepcopy((CLAIMS, SESSIONS, FAS_CONTEXTS))

    def cursor(self):
        return FakeCursor()

    def rollback(self):
        claims, sessions, contexts = copy.deepcopy(self._snapshot)
        CLAIMS.clear(); CLAIMS.update(claims)
        SESSIONS[:] = sessions
        FAS_CONTEXTS.clear(); FAS_CONTEXTS.update(contexts)


@pytest.fixture
def client(monkeypatch):
    _reset()
    monkeypatch.setenv("FAS_KEY", FASKEY)
    monkeypatch.setenv("GATEWAY_NAME", "Cafe-Guest-Test")

    import common.db as db
    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(FakeConn()))

    def _run(sql, args=()):
        cur = FakeCursor(); cur.execute(sql, args); return cur

    monkeypatch.setattr(db, "query_one", lambda s, a=(): _run(s, a).fetchone())
    monkeypatch.setattr(db, "query_all", lambda s, a=(): _run(s, a).fetchall())
    monkeypatch.setattr(db, "execute", lambda s, a=(): _run(s, a).rowcount)

    import importlib
    fas_app = importlib.import_module("fas.app")
    importlib.reload(fas_app)
    fas_app.FAS_KEY = FASKEY
    fas_app.GATEWAY_NAME = "Cafe-Guest-Test"
    fas_app.client_ip = lambda: GW_PARAMS["clientip"]
    fas_app.resolve_mac = lambda ip: ARP["mac"] if ip == GW_PARAMS["clientip"] else None
    fas_app.app.config.update(TESTING=True)
    fas_app._attempts.clear()
    c = fas_app.app.test_client()
    c.module = fas_app
    return c


def _gw_url(mac="AA:BB:CC:DD:EE:01"):
    """
    จำลอง URL ที่ openNDS gateway จะ redirect ลูกค้ามา — ต้อง urlencode ค่า fas/iv เอง
    เพราะ base64 มี '+' '/' '=' ซึ่งมีความหมายพิเศษใน query string (เช่น '+' = เว้นวรรค)
    """
    from urllib.parse import quote
    ARP["mac"] = mac
    p = dict(GW_PARAMS, clientmac=mac)
    fas_b64, iv = encrypt_fas_payload(p, FASKEY)
    return f"/login?fas={quote(fas_b64, safe='')}&iv={quote(iv, safe='')}"


def _extract_hidden(html: str, field: str) -> str:
    import re
    m = re.search(rf'name="{field}" value="([^"]*)"', html)
    return m.group(1) if m else ""


def _post_login(client, html, username, password):
    data = {"nonce": _extract_hidden(html, "nonce")}
    data["username"] = username
    data["password"] = password
    return client.post("/login", data=data)


# ---------------------------------------------------------------- GET /login
def test_manual_page_without_fas_params(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "cafe.wifi" in r.get_data(as_text=True)


def test_get_login_decodes_gateway_payload(client):
    r = client.get(_gw_url())
    html = r.get_data(as_text=True)
    assert r.status_code == 200
    assert _extract_hidden(html, "nonce")
    assert "ctx_clientmac" not in html


def test_get_login_wrong_faskey_shows_error(client):
    bad_b64, iv = encrypt_fas_payload(GW_PARAMS, "b" * 32)  # เข้ารหัสด้วยกุญแจอื่น
    r = client.get(f"/login?fas={bad_b64}&iv={iv}")
    assert r.status_code == 400


def test_service_unavailable_when_faskey_missing(client, monkeypatch):
    monkeypatch.setattr(client.module, "FAS_KEY", "")
    r = client.get("/login")
    assert r.status_code == 503


# ---------------------------------------------------------------- POST /login สำเร็จ
def test_successful_login_redirects_to_gateway_auth_url(client):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, code, pw)
    assert r.status_code == 302
    loc = r.headers["Location"]
    assert loc.startswith("http://10.10.0.1:2050/opennds_auth/?tok=")
    assert auth_token("hid-0001", FASKEY) in loc
    assert len(SESSIONS) == 1 and SESSIONS[0]["ended_at"] is None
    assert len(DEVICES) == 0
    assert SESSIONS[0]["state"] == "pending"
    assert any("login_pending" in str(a) for a in AUDIT)


def test_arp_missing_after_ping_rejects_without_session(client, monkeypatch):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    ARP["mac"] = None
    pings = []
    monkeypatch.setattr(client.module.subprocess, "run", lambda *args, **kwargs: pings.append((args, kwargs)))

    r = _post_login(client, html, code, pw)

    assert r.status_code == 400
    assert "ลองอีกครั้ง" in r.get_data(as_text=True)
    assert len(pings) == 1
    assert pings[0][0][0][-1] == GW_PARAMS["clientip"]
    assert SESSIONS == [] and CLAIMS == {}
    assert all(row["consumed_at"] is None for row in FAS_CONTEXTS.values())


def test_arp_found_after_ping_allows_login(client, monkeypatch):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    macs = iter((None, GW_PARAMS["clientmac"].lower()))
    monkeypatch.setattr(client.module, "resolve_mac", lambda ip: next(macs))
    pings = []
    monkeypatch.setattr(client.module.subprocess, "run", lambda *args, **kwargs: pings.append((args, kwargs)))

    r = _post_login(client, html, code, pw)

    assert r.status_code == 302
    assert len(pings) == 1
    assert SESSIONS[0]["mac"] == GW_PARAMS["clientmac"]


def test_arp_mac_mismatch_rejects_without_ping_or_session(client, monkeypatch):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    ARP["mac"] = "AA:BB:CC:DD:EE:99"
    monkeypatch.setattr(client.module.subprocess, "run", lambda *args, **kwargs: pytest.fail("ไม่ควร ping เมื่อมี ARP"))

    r = _post_login(client, html, code, pw)

    assert r.status_code == 400
    assert SESSIONS == [] and CLAIMS == {}


def test_username_is_case_insensitive(client):
    code, pw = _make_voucher(code="CAFE-ABCDE")
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, "cafe-abcde", pw)
    assert r.status_code == 302


def test_second_login_waits_for_pending_confirmation(client):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    _post_login(client, html, code, pw)
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, code, pw)
    assert r.status_code == 409
    open_sessions = [s for s in SESSIONS if s["ended_at"] is None]
    assert len(open_sessions) == 1, "ต้องมี session เปิดอยู่แค่ 1 อันต่อ mac เท่านั้น"


def test_existing_pending_session_cannot_be_replaced(client):
    """
    บั๊กเดิม (พบตอนตรวจทานรอบ 4): ถ้าบังเอิญมี session ค้างเปิดพร้อมกันมากกว่า 1 อันของ mac
    เดียวกัน (เช่น เกิดจาก race condition) เดิม fetchone() ดึง started_at มาแค่แถวเดียวแล้วเอา
    ไป UPDATE "ทุกแถว" ที่ mac ตรงกัน -- ต้องปิดทีละแถวแยกกันด้วย id ของตัวเอง ไม่ใช่ mac ร่วม
    """
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)

    # จำลอง session ค้างเปิดพร้อมกัน 2 อันของ mac เดียวกัน (ปกติไม่เกิดจาก flow ปกติ แต่ต้อง
    # ทนได้ถ้าเกิดจริง) ก่อน login ครั้งใหม่
    _ids["session"] += 1
    SESSIONS.append(dict(id=_ids["session"], voucher_id=1, mac="AA:BB:CC:DD:EE:01",
                         ip="10.10.0.50", started_at="t-old-1", ended_at=None,
                         state="pending", bytes_out=0, bytes_in=0))
    _ids["session"] += 1
    SESSIONS.append(dict(id=_ids["session"], voucher_id=1, mac="AA:BB:CC:DD:EE:01",
                         ip="10.10.0.51", started_at="t-old-2", ended_at=None,
                         state="pending", bytes_out=0, bytes_in=0))

    r = _post_login(client, html, code, pw)
    assert r.status_code == 409

    still_open = [s for s in SESSIONS if s["mac"] == "AA:BB:CC:DD:EE:01" and s["ended_at"] is None]
    assert len(still_open) == 2


# ---------------------------------------------------------------- ปฏิเสธ
def test_wrong_password_rejected(client):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, code, "WRONGPASS")
    assert r.status_code == 401
    assert len(SESSIONS) == 0
    assert any("login_fail" in str(a) for a in AUDIT)


def test_unknown_voucher_rejected(client):
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, "CAFE-NOPE1", "whatever")
    assert r.status_code == 401


def test_expired_voucher_rejected(client):
    code, pw = _make_voucher(hours=-1)  # หมดอายุไปแล้ว
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, code, pw)
    assert r.status_code == 401
    assert "หมดอายุ" in r.get_data(as_text=True)


def test_blocked_customer_rejected(client):
    code, pw = _make_voucher(blocked=True)
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, code, pw)
    assert r.status_code == 401
    assert "ระงับ" in r.get_data(as_text=True)


def test_revoked_voucher_rejected(client):
    code, pw = _make_voucher(status="revoked")
    html = client.get(_gw_url()).get_data(as_text=True)
    r = _post_login(client, html, code, pw)
    assert r.status_code == 401


# ---------------------------------------------------------------- จำกัดอุปกรณ์
def test_device_limit_enforced(client):
    code, pw = _make_voucher(max_devices=2)
    for i, mac in enumerate(["AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:02"]):
        html = client.get(_gw_url(mac=mac)).get_data(as_text=True)
        assert _post_login(client, html, code, pw).status_code == 302

    html = client.get(_gw_url(mac="AA:BB:CC:DD:EE:03")).get_data(as_text=True)
    r = _post_login(client, html, code, pw)
    assert r.status_code == 403
    assert "ครบ" in r.get_data(as_text=True)
    assert "AA:BB:CC:DD:EE:03" not in CLAIMS, "ถูกปฏิเสธแล้วต้องไม่มี claim ค้าง"


def test_device_rejected_at_limit_can_use_new_voucher(client):
    """R2-01: เครื่องที่ชนเพดานของรหัสเดิม ต้องใช้รหัสใหม่ที่พนักงานออกให้ได้ทันที"""
    code, pw = _make_voucher(code="CAFE-OLD01", max_devices=1)
    html = client.get(_gw_url(mac="AA:BB:CC:DD:EE:01")).get_data(as_text=True)
    assert _post_login(client, html, code, pw).status_code == 302

    html = client.get(_gw_url(mac="AA:BB:CC:DD:EE:03")).get_data(as_text=True)
    assert _post_login(client, html, code, pw).status_code == 403

    code2, pw2 = _make_voucher(code="CAFE-NEW01", max_devices=2)
    html = client.get(_gw_url(mac="AA:BB:CC:DD:EE:03")).get_data(as_text=True)
    r = _post_login(client, html, code2, pw2)
    assert r.status_code == 302
    assert CLAIMS["AA:BB:CC:DD:EE:03"] == SESSIONS[-1]["id"]


def test_consumed_nonce_rejection_leaves_no_claim(client, monkeypatch):
    """R2-01: ทาง nonce ถูกใช้ไปแล้ว (400) ก็ต้อง rollback claim เช่นกัน -- จำลองกดส่งซ้อน
    ที่อีก request ใช้ nonce ไปก่อนระหว่างผ่าน _load_context กับ UPDATE fas_context"""
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    real_execute = FakeCursor.execute

    def racing_execute(self, sql, args=()):
        real_execute(self, sql, args)
        if " ".join(sql.split()).lower().startswith("update fas_context set consumed_at"):
            self.rowcount = 0

    monkeypatch.setattr(FakeCursor, "execute", racing_execute)
    r = _post_login(client, html, code, pw)
    assert r.status_code == 400
    assert "AA:BB:CC:DD:EE:01" not in CLAIMS
    assert SESSIONS == []


def test_same_device_can_relogin_even_at_limit(client):
    code, pw = _make_voucher(max_devices=1)
    html = client.get(_gw_url(mac="AA:BB:CC:DD:EE:01")).get_data(as_text=True)
    assert _post_login(client, html, code, pw).status_code == 302
    # เครื่องเดิม login ซ้ำ ต้องไม่โดนนับว่าเกินโควตา
    html2 = client.get(_gw_url(mac="AA:BB:CC:DD:EE:01")).get_data(as_text=True)
    assert _post_login(client, html2, code, pw).status_code == 409
    assert len(DEVICES) == 0


# ---------------------------------------------------------------- rate limit / เซสชันหมดอายุ
def test_rate_limit_after_repeated_failures(client):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    for _ in range(5):
        _post_login(client, html, code, "WRONGPASS")
    r = _post_login(client, html, code, "WRONGPASS")
    assert r.status_code == 429


def test_tampered_hidden_fields_rejected(client):
    r = client.post("/login", data=dict(ctx_clientmac="not-a-mac", username="X", password="Y"))
    assert r.status_code == 400


def test_hidden_context_is_ignored_and_nonce_is_single_use(client):
    code, pw = _make_voucher()
    html = client.get(_gw_url()).get_data(as_text=True)
    nonce = _extract_hidden(html, "nonce")
    r = client.post("/login", data=dict(nonce=nonce, username=code, password=pw,
                                         ctx_clientmac="AA:BB:CC:DD:EE:99",
                                         ctx_gatewayaddress="evil.example"))
    assert r.status_code == 302
    assert r.headers["Location"].startswith("http://10.10.0.1:2050/opennds_auth/")
    assert SESSIONS[-1]["mac"] == "AA:BB:CC:DD:EE:01"
    replay = client.post("/login", data=dict(nonce=nonce, username=code, password=pw))
    assert replay.status_code == 400


def test_missing_context_rejected(client):
    r = client.post("/login", data=dict(username="X", password="Y"))
    assert r.status_code == 400


@pytest.mark.parametrize("address,ok", [
    ("10.10.0.1:2050", True),    # รูปแบบที่ openNDS 10.1.3 ตัวจริงส่งมา
    ("10.10.0.1", True),         # เผื่อรุ่นที่ไม่ใส่พอร์ต
    ("10.10.0.1:8080", False),   # พอร์ตไม่ใช่ของ openNDS
    ("10.10.0.99:2050", False),  # gateway อื่น
    ("evil.example:2050", False),
])
def test_valid_gateway_accepts_ip_with_nds_port(client, address, ok):
    from fas.opennds_proto import ClientContext
    ctx = ClientContext(clientmac="AA:BB:CC:DD:EE:01", hid="h", gatewayaddress=address,
                        authdir="opennds_auth")
    assert client.module._valid_gateway(ctx) is ok


def test_real_opennds_gateway_address_passes_validation(client):
    """payload จริงจาก openNDS 10.1.3 (ชุดเดียวกับ test_opennds_proto.py) ต้องผ่านการตรวจ gateway --
    เดิมเทียบ "10.10.0.1:2050" == "10.10.0.1" ตรง ๆ ลูกค้าจริงทุกคน login ไม่ได้"""
    from fas.opennds_proto import decrypt_fas_payload
    from test_opennds_proto import REAL_FAS_B64, REAL_FASKEY, REAL_IV
    ctx = decrypt_fas_payload(REAL_FAS_B64, REAL_IV, REAL_FASKEY)
    assert ctx.gatewayaddress == "10.10.0.1:2050"
    assert client.module._valid_gateway(ctx)
