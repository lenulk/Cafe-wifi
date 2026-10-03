"""
T-Register — ลูกค้าขอใช้งานบน portal แล้วพนักงานอนุมัติ (แทนสลิปรหัสผ่าน CAFE-XXXXX)

  FAS   : GET /login (payload openNDS) -> ฟอร์ม · POST /login -> access_request + รหัส 4 ตัว · GET /request
  Admin : GET /requests · POST /requests/<id>/approve (เทียบ 4 ตัวท้ายจากบัตร) · /reject
  (ส่วน ndsctl auth อยู่ใน test_reconcile_pending.py)

ฐานข้อมูลจำลองในหน่วยความจำชุดเดียวให้ทั้งสองแอป จึงเดินได้ครบวงจร: ลูกค้าขอ -> พนักงานอนุมัติ ->
portal_session pending -> หน้ารอของลูกค้าเห็นผล · ไม่ต้องมี MariaDB
"""
import contextlib
import copy
import re
from datetime import datetime, timedelta

import pytest

from common import crypto
from fas.opennds_proto import encrypt_fas_payload

FASKEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
GW_PARAMS = dict(clientip="10.10.0.105", clientmac="AA:BB:CC:DD:EE:01",
                 gatewayname="Cafe-Guest", client_hid="hid-0001",
                 # openNDS จริงส่งพร้อมพอร์ต (ดู test_opennds_proto.py) -- อย่าใช้ IP เปล่า
                 gatewayaddress="10.10.0.1:2050", authdir="opennds_auth",
                 originurl="http://example.com/", clientif="eth1")
NATID = "1101700000010"          # เลขทดสอบ checksum ถูก ไม่ใช่ของคนจริง
NATID2 = "1101700000028"

DB: dict = {}
ARP = {"mac": GW_PARAMS["clientmac"]}


def _reset():
    DB.clear()
    DB.update(fas_context={}, access_request=[], customer=[], voucher=[], portal_session=[],
              device=[], claims={}, audit=[], staff=[dict(id=1, username="admin", role="admin",
                                                          is_active=1, must_change_password=0,
                                                          password_changed_at=None)])
    ARP["mac"] = GW_PARAMS["clientmac"]


def _now():
    return datetime.now()


def _live_pending(r):
    return r["status"] == "pending" and r["expires_at"] > _now()


class FakeCursor:
    def __init__(self):
        self.lastrowid = None
        self.rowcount = 0
        self._rows = []

    def execute(self, sql, args=()):  # noqa: C901 -- ตัวจำลอง SQL ตรง ๆ อ่านง่ายกว่าแยกฟังก์ชัน
        s = " ".join(sql.split()).lower()
        self._rows, self.rowcount = [], 0
        ar, cust, vou, ps = DB["access_request"], DB["customer"], DB["voucher"], DB["portal_session"]
        # ---- FAS context
        if s.startswith("insert into fas_context"):
            key, payload, ip, expiry = args
            DB["fas_context"][key] = dict(payload=payload, request_ip=ip, expires_at=expiry,
                                          consumed_at=None)
        elif s.startswith("select payload, request_ip"):
            row = DB["fas_context"].get(args[0])
            self._rows = [row] if row else []
        elif s.startswith("update fas_context set consumed_at=now()"):
            row = DB["fas_context"].get(args[0])
            self.rowcount = int(bool(row and not row["consumed_at"]))
            if self.rowcount:
                row["consumed_at"] = _now()
        # ---- access_request
        elif s.startswith("select id from access_request where mac=%s and status='pending'"):
            self._rows = [r for r in ar if r["mac"] == args[0] and _live_pending(r)]
        elif s.startswith("select count(*) as n from access_request where status='pending'"):
            self._rows = [{"n": sum(_live_pending(r) for r in ar)}]
        elif s.startswith("select id from access_request where code=%s"):
            self._rows = [r for r in ar if r["code"] == args[0] and _live_pending(r)]
        elif s.startswith("insert into access_request"):
            code, mac, ip, host, os_label, ua, h, enc, masked = args
            ar.append(dict(id=len(ar) + 1, code=code, mac=mac, ip=ip, hostname=host, os_label=os_label,
                           user_agent=ua, natid_hash=h, natid_enc=enc,
                           natid_masked=masked, consent_at=_now(), status="pending",
                           created_at=_now(), expires_at=_now() + timedelta(minutes=15),
                           decided_at=None, decided_by=None, decision_note=None, voucher_id=None,
                           portal_session_id=None, auth_sent_at=None))
            self.lastrowid = len(ar)
        elif s.startswith("select ar.code, ar.status, ar.expires_at"):
            mine = [r for r in ar if r["mac"] == args[0]]
            if mine:
                r = mine[-1]
                sess = next((x for x in ps if x["id"] == r["portal_session_id"]), None)
                v = next((x for x in vou if x["id"] == r["voucher_id"]), None)
                self._rows = [dict(r, session_state=sess and sess["state"],
                                   authenticated_at=sess and sess.get("authenticated_at"),
                                   terminate_cause=sess and sess.get("terminate_cause"),
                                   valid_until=v and v["valid_until"], quota_mb=v and v["quota_mb"],
                                   used_mb=v and v["used_mb"], voucher_status=v and v["status"])]
        elif s.startswith("select state as session_state, authenticated_at, terminate_cause from portal_session"):
            mine = [x for x in ps if x["mac"] == args[0] and x["voucher_id"] == args[1]]
            self._rows = [dict(session_state=x["state"], authenticated_at=x.get("authenticated_at"),
                               terminate_cause=x.get("terminate_cause")) for x in mine[-1:]]
        elif s.startswith("select mac, authenticated_at from portal_session where voucher_id"):
            self._rows = [dict(mac=x["mac"], authenticated_at=x.get("authenticated_at") or x["started_at"])
                          for x in ps if x["voucher_id"] == args[0] and x["state"] == "authenticated"
                          and not x.get("ended_at")]
        elif s.startswith("select id, code, mac, hostname, os_label, natid_hash, natid_masked, created_at"):
            self._rows = [r for r in ar if _live_pending(r)]
        elif s.startswith("select ar.code, ar.natid_masked, ar.hostname, ar.os_label, ar.status"):
            self._rows = [dict(r, decided_by="admin") for r in ar
                          if r["status"] in ("approved", "rejected")]
        elif s.startswith("select id, code, mac, ip, hostname, os_label, natid_hash, natid_enc"):
            self._rows = [r for r in ar if r["id"] == args[0]]
        elif s.startswith("select code, natid_masked from access_request"):
            self._rows = [r for r in ar if r["id"] == args[0] and r["status"] == "pending"]
        elif s.startswith("update access_request set status='approved'"):
            staff, vid, sid, rid = args
            ar[rid - 1].update(status="approved", decided_at=_now(), decided_by=staff, voucher_id=vid,
                               portal_session_id=sid, natid_hash=None, natid_enc=None)
        elif s.startswith("update access_request set status='rejected'"):
            staff, note, rid = args
            ar[rid - 1].update(status="rejected", decided_at=_now(), decided_by=staff,
                               decision_note=note, natid_hash=None, natid_enc=None)
        # ---- customer
        elif s.startswith("select is_blocked from customer where natid_hash"):
            self._rows = [c for c in cust if c["natid_hash"] == args[0]]
        elif s.startswith("select id, is_blocked"):
            self._rows = [c for c in cust if c["natid_hash"] == args[0]]
        elif s.startswith("update customer set last_seen"):
            c = next(c for c in cust if c["id"] == args[0])
            c["visit_count"] += 1
        elif s.startswith("insert into customer"):
            cust.append(dict(id=len(cust) + 1, natid_hash=args[0], natid_enc=args[1],
                             natid_masked=args[2], is_blocked=0, visit_count=1))
            self.lastrowid = len(cust)
        # ---- voucher
        elif s.startswith("select id, username, max_devices, valid_until"):
            self._rows = sorted([v for v in vou if v["customer_id"] == args[0]
                                 and v["status"] == "active" and v["valid_until"] > _now()],
                                key=lambda v: v["valid_until"], reverse=True)[:1]
        elif s.startswith("insert into voucher"):
            cid, code, ph, staff, vf, vu, dev, quota = args
            vou.append(dict(id=len(vou) + 1, customer_id=cid, username=code, password_hash=ph,
                            issued_by=staff, valid_from=vf, valid_until=vu, max_devices=dev,
                            quota_mb=quota, used_mb=0, status="active"))
            self.lastrowid = len(vou)
        elif s.startswith("select id, username, max_devices, status, valid_until from voucher"):
            self._rows = [v for v in vou if v["id"] == args[0]]
        elif s.startswith("select id, status, valid_until from voucher where id=%s for update"):
            self._rows = [v for v in vou if v["id"] == args[0]]
        elif s.startswith("update voucher set valid_until=%s, auth_sync_needed=1"):
            v = next(v for v in vou if v["id"] == args[1])
            v.update(valid_until=args[0], auth_sync_needed=1)
        elif s.startswith("update voucher set max_devices"):
            next(v for v in vou if v["id"] == args[1])["max_devices"] = args[0]
        elif s.startswith("select count(*) as n from device where voucher_id"):
            self._rows = [{"n": sum(d["voucher_id"] == args[0] for d in DB["device"])}]
        # ---- common/access.reserve_pending_session
        elif s.startswith("select id from voucher where id=%s for update"):
            self._rows = [{"id": args[0]}]
        elif s.startswith("select id from portal_session where mac=%s and state='pending'"):
            self._rows = [x for x in ps if x["mac"] == args[0] and x["state"] == "pending"]
        elif s.startswith("insert ignore into pending_mac_claim"):
            self.rowcount = int(args[0] not in DB["claims"])
            if self.rowcount:
                DB["claims"][args[0]] = None
        elif s.startswith("update pending_mac_claim set portal_session_id"):
            DB["claims"][args[1]] = args[0]
        elif s.startswith("select count(*) as n from ("):
            vid = args[0]
            macs = {d["mac"] for d in DB["device"] if d["voucher_id"] == vid}
            macs |= {x["mac"] for x in ps if x["voucher_id"] == vid and x["state"] == "pending"}
            self._rows = [{"n": len(macs)}]
        elif s.startswith("select 1 from device"):
            vid, mac = args[0], args[1]
            hit = any(d["voucher_id"] == vid and d["mac"] == mac for d in DB["device"])
            hit |= any(x["voucher_id"] == vid and x["mac"] == mac and x["state"] == "pending" for x in ps)
            self._rows = [{"1": 1}] if hit else []
        elif s.startswith("insert into portal_session"):
            vid, mac, ip, host, os_label = args
            ps.append(dict(id=len(ps) + 1, voucher_id=vid, mac=mac, ip=ip, hostname=host,
                           os_label=os_label, state="pending",
                           started_at=_now()))
            self.lastrowid = len(ps)
        # ---- staff / audit
        elif s.startswith("select role, is_active"):
            self._rows = [x for x in DB["staff"] if x["id"] == args[0]]
        elif s.startswith("insert into audit_log"):
            DB["audit"].append(args)
        elif s.startswith("select count(*) as n from staff"):
            self._rows = [{"n": len(DB["staff"])}]
        # ---- dashboard
        elif s.startswith("select (select count(*) from voucher"):
            self._rows = [dict(active_vouchers=0, customers=len(cust), issued_today=0, online_now=0)]
        elif s.startswith(("select v.id as k, ps.mac, ps.state", "select v.customer_id as k, ps.mac, ps.state")):
            key = "id" if s.startswith("select v.id as k") else "customer_id"
            self._rows = [dict(k=v[key], mac=x["mac"], state=x["state"], ended_at=x.get("ended_at"),
                               authenticated_at=x.get("authenticated_at") or x["started_at"],
                               bytes_in=x.get("bytes_in", 0), bytes_out=x.get("bytes_out", 0))
                          for x in ps for v in vou if v["id"] == x["voucher_id"] and v[key] in args
                          and x["state"] != "pending"]
        elif s.startswith("select coalesce(sum(bytes_out),0) as bo"):
            mac = args[0]
            self._rows = [dict(bo=sum(c["out"] for c in DB.get("conn", []) if c["mac"] == mac),
                               bi=sum(c["in"] for c in DB.get("conn", []) if c["mac"] == mac))]
        elif s.startswith(("select v.id as k", "select v.customer_id as k")):
            key = "id" if s.startswith("select v.id as k") else "customer_id"
            self._rows = [dict(k=v[key], mac=x["mac"], hostname=x.get("hostname"),
                               os_label=x.get("os_label"), state=x["state"], ended_at=x.get("ended_at"))
                          for x in reversed(ps) for v in vou if v["id"] == x["voucher_id"] and v[key] in args]
        # ---- dashboard: อุปกรณ์บนเครือข่าย
        elif s.startswith("select ps.mac, ps.ip, ps.hostname, ps.os_label, ps.authenticated_at, c.natid_masked"):
            self._rows = [dict(mac=x["mac"], ip=x["ip"], hostname=x.get("hostname"), os_label=x.get("os_label"),
                               authenticated_at=x.get("authenticated_at") or x["started_at"],
                               natid_masked=next(c["natid_masked"] for v in vou if v["id"] == x["voucher_id"]
                                                 for c in cust if c["id"] == v["customer_id"]))
                          for x in ps if x["state"] == "authenticated" and not x.get("ended_at")]
        elif s.startswith("select mac, code, os_label from access_request"):
            self._rows = [r for r in ar if _live_pending(r)]
        elif s.startswith("select ps.mac, ps.hostname, ps.os_label, c.natid_masked from portal_session"):
            self._rows = []  # เคยใช้สิทธิ์ของใคร -- เทสต์ชุดนี้ไม่มีประวัติ
        elif s.startswith("select v.id, v.username, v.issued_at"):
            self._rows = [dict(v, issued_at=v["valid_from"], issued_by="admin",
                               natid_masked=next(c["natid_masked"] for c in cust if c["id"] == v["customer_id"]))
                          for v in reversed(vou)]
        elif s.startswith("select id, natid_masked, first_seen"):
            self._rows = [dict(c, first_seen=_now(), last_seen=_now()) for c in cust]
        else:
            raise AssertionError(f"FakeCursor ไม่รู้จัก SQL: {s[:90]}")
        if self._rows and not self.rowcount:
            self.rowcount = len(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    """snapshot ตอนเปิด connection -- rollback() ย้อนได้จริง (R2-01: ทุกทางที่ปฏิเสธต้องไม่เหลือ claim ค้าง)"""

    def __init__(self):
        self._snap = copy.deepcopy(DB)

    def cursor(self):
        return FakeCursor()

    def rollback(self):
        snap = copy.deepcopy(self._snap)
        DB.clear()
        DB.update(snap)


def _patch_db(monkeypatch):
    import common.db as db
    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(FakeConn()))

    def _run(sql, args=()):
        cur = FakeCursor()
        cur.execute(sql, args)
        return cur

    monkeypatch.setattr(db, "query_one", lambda s, a=(): _run(s, a).fetchone())
    monkeypatch.setattr(db, "query_all", lambda s, a=(): _run(s, a).fetchall())
    monkeypatch.setattr(db, "execute", lambda s, a=(): _run(s, a).rowcount)


@pytest.fixture
def fas(monkeypatch, tmp_path):
    _reset()
    monkeypatch.setenv("FAS_KEY", FASKEY)
    _patch_db(monkeypatch)
    from common import device_info
    lease = tmp_path / "dnsmasq.leases"
    lease.write_text("1790946321 aa:bb:cc:dd:ee:01 10.10.0.105 Somchais-iPhone 01:aa:bb:cc:dd:ee:01\n"
                     "1790946214 aa:bb:cc:dd:ee:02 10.10.0.105 * 01:aa:bb:cc:dd:ee:02\n")
    monkeypatch.setattr(device_info, "LEASE_FILE", str(lease))
    import importlib
    mod = importlib.reload(importlib.import_module("fas.app"))
    mod.FAS_KEY = FASKEY
    mod.client_ip = lambda: GW_PARAMS["clientip"]
    mod.resolve_mac = lambda ip: ARP["mac"] if ip == GW_PARAMS["clientip"] else None
    monkeypatch.setattr(mod.subprocess, "run", lambda *a, **k: None)  # ping กระตุ้น ARP
    mod.app.config.update(TESTING=True)
    mod._attempts.clear()
    c = mod.app.test_client()
    c.module = mod
    return c


@pytest.fixture
def admin(monkeypatch, tmp_path, fas):
    """Admin ใช้ DB จำลองชุดเดียวกับ FAS (ต้องสร้าง fas ก่อน -- fixture นี้พึ่ง fas)"""
    import importlib
    mod = importlib.reload(importlib.import_module("admin.app"))
    mod.SETUP_TOKEN_FILE = tmp_path / "setup.token"
    mod.app.config.update(TESTING=True, SESSION_COOKIE_SECURE=False, CSRF_ENABLED=False)
    c = mod.app.test_client()
    with c.session_transaction() as s:
        s.update(staff_id=1, username="admin", role="admin", pw_at="")
    return c


def _gw_url(mac="AA:BB:CC:DD:EE:01"):
    from urllib.parse import quote
    ARP["mac"] = mac
    fas_b64, iv = encrypt_fas_payload(dict(GW_PARAMS, clientmac=mac), FASKEY)
    return f"/login?fas={quote(fas_b64, safe='')}&iv={quote(iv, safe='')}"


def _nonce(html):
    m = re.search(r'name="nonce" value="([^"]*)"', html)
    return m.group(1) if m else ""


IPHONE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 "
             "(KHTML, like Gecko) Mobile/15E148")


def _register(fas, natid=NATID, consent=True, mac="AA:BB:CC:DD:EE:01", ua=IPHONE_UA):
    html = fas.get(_gw_url(mac)).get_data(as_text=True)
    data = dict(nonce=_nonce(html), natid=natid)
    if consent:
        data["consent"] = "on"
    return fas.post("/login", data=data, headers={"User-Agent": ua})


def _approve(admin, rid=1, last4=NATID[-4:], **package):
    return admin.post(f"/requests/{rid}/approve", data=dict(last4=last4, **package))


# ================================================================ FAS: ฟอร์ม + ส่งคำขอ
def test_manual_page_without_fas_params(fas):
    r = fas.get("/login")
    assert r.status_code == 200 and "cafe.wifi" in r.get_data(as_text=True)


def test_gateway_payload_shows_registration_form(fas):
    html = fas.get(_gw_url()).get_data(as_text=True)
    assert _nonce(html)
    assert 'name="natid"' in html and 'type="password"' in html, "ช่องเลขบัตรต้องซ่อนตัวเลข"
    assert 'name="consent"' in html
    assert 'name="password"' not in html, "เลิกใช้รหัสผ่านแล้ว"


def test_wrong_faskey_or_missing_key(fas, monkeypatch):
    bad_b64, iv = encrypt_fas_payload(GW_PARAMS, "b" * 32)
    assert fas.get(f"/login?fas={bad_b64}&iv={iv}").status_code == 400
    monkeypatch.setattr(fas.module, "FAS_KEY", "")
    assert fas.get(_gw_url()).status_code == 503


def test_register_creates_request_and_redirects_to_waiting_page(fas):
    r = _register(fas)
    assert r.status_code == 303 and r.headers["Location"].endswith("/request")
    (req,) = DB["access_request"]
    assert req["status"] == "pending" and req["mac"] == "AA:BB:CC:DD:EE:01"
    assert re.fullmatch(r"[A-Z0-9]{4}", req["code"])
    assert req["natid_masked"] == crypto.mask_natid(NATID)
    assert NATID not in repr(req), "ห้ามเก็บเลขบัตรแบบอ่านออก"
    assert crypto.natid_decrypt(req["natid_enc"]) == NATID
    page = fas.get("/request").get_data(as_text=True)
    assert req["code"] in page and 'http-equiv="refresh"' in page


def test_natid_never_appears_in_audit_or_responses(fas):
    r = _register(fas)
    assert NATID not in r.get_data(as_text=True)
    assert NATID not in fas.get("/request").get_data(as_text=True)
    assert all(NATID not in str(a) for a in DB["audit"])


def test_invalid_natid_and_missing_consent_rejected(fas):
    assert _register(fas, natid="1234567890123").status_code == 400
    assert _register(fas, consent=False).status_code == 400
    assert DB["access_request"] == []


def test_resubmit_reuses_pending_request(fas):
    _register(fas)
    r = _register(fas)
    assert r.status_code == 303
    assert len(DB["access_request"]) == 1


def test_blocked_customer_cannot_request(fas):
    DB["customer"].append(dict(id=1, natid_hash=crypto.natid_hash(NATID), natid_enc=b"",
                               natid_masked="x", is_blocked=1, visit_count=3))
    r = _register(fas)
    assert r.status_code == 403 and "ติดต่อพนักงาน" in r.get_data(as_text=True)
    assert DB["access_request"] == []


def test_rate_limit_on_bad_natid(fas):
    codes = [_register(fas, natid="1234567890123").status_code for _ in range(7)]
    assert codes[-1] == 429


def test_queue_cap(fas, monkeypatch):
    monkeypatch.setattr(fas.module.access, "MAX_PENDING_REQUESTS", 1)
    assert _register(fas, mac="AA:BB:CC:DD:EE:01").status_code == 303
    assert _register(fas, natid=NATID2, mac="AA:BB:CC:DD:EE:02").status_code == 503


def test_nonce_is_single_use(fas):
    html = fas.get(_gw_url()).get_data(as_text=True)
    data = dict(nonce=_nonce(html), natid=NATID, consent="on")
    assert fas.post("/login", data=data).status_code == 303
    DB["access_request"][0]["status"] = "rejected"  # ไม่ให้เข้าทาง "ใช้คำขอเดิม"
    assert fas.post("/login", data=data).status_code == 400


def test_arp_mismatch_or_missing_rejected(fas, monkeypatch):
    html = fas.get(_gw_url()).get_data(as_text=True)
    ARP["mac"] = "AA:BB:CC:DD:EE:99"
    r = fas.post("/login", data=dict(nonce=_nonce(html), natid=NATID, consent="on"))
    assert r.status_code == 400
    monkeypatch.setattr(fas.module, "resolve_mac", lambda ip: None)
    r = fas.post("/login", data=dict(nonce=_nonce(html), natid=NATID, consent="on"))
    assert r.status_code == 400
    assert DB["access_request"] == []


def test_waiting_page_without_request(fas):
    assert "ไม่พบคำขอ" in fas.get("/request").get_data(as_text=True)


# ================================================================ Admin: อนุมัติ/ปฏิเสธ
def test_requests_page_lists_pending_without_full_natid(fas, admin):
    _register(fas)
    html = admin.get("/requests").get_data(as_text=True)
    code = DB["access_request"][0]["code"]
    assert code in html and crypto.mask_natid(NATID) in html
    assert NATID not in html, "พนักงานต้องไม่เห็นเลขบัตรเต็ม (§6.2)"
    assert "ลูกค้าใหม่" in html
    assert f'<b class="badge err">1</b>' in admin.get("/").get_data(as_text=True)


def test_approve_new_customer_creates_voucher_and_pending_session(fas, admin):
    _register(fas)
    r = _approve(admin, hours="2", devices="1", quota_mb="500")
    assert r.status_code == 302
    req = DB["access_request"][0]
    assert req["status"] == "approved" and req["natid_enc"] is None and req["natid_hash"] is None
    (c,) = DB["customer"]
    assert crypto.natid_decrypt(c["natid_enc"]) == NATID
    (v,) = DB["voucher"]
    assert (v["max_devices"], v["quota_mb"]) == (1, 500)
    assert timedelta(hours=1, minutes=59) < v["valid_until"] - datetime.now() <= timedelta(hours=2)
    (s,) = DB["portal_session"]
    assert (s["mac"], s["state"], s["voucher_id"]) == ("AA:BB:CC:DD:EE:01", "pending", v["id"])
    assert req["portal_session_id"] == s["id"] and req["voucher_id"] == v["id"]
    assert "request_approve" in [a[1] for a in DB["audit"]]
    # ฝั่งลูกค้า: หน้ารอเปลี่ยนเป็น "กำลังเปิด" แล้วเป็น "ใช้ได้แล้ว" เมื่อ reconcile ยืนยัน
    assert "กำลังเปิดอินเทอร์เน็ต" in fas.get("/request").get_data(as_text=True)
    s["state"] = "authenticated"
    assert "ใช้อินเทอร์เน็ตได้แล้ว" in fas.get("/request").get_data(as_text=True)


def test_last4_mismatch_blocks_approval_and_is_audited(fas, admin):
    _register(fas)
    r = _approve(admin, last4="9999")
    assert r.status_code == 302
    assert DB["access_request"][0]["status"] == "pending"
    assert DB["voucher"] == [] and DB["portal_session"] == [] and DB["claims"] == {}
    assert "request_mismatch" in [a[1] for a in DB["audit"]]


def test_second_device_joins_existing_voucher(fas, admin):
    _register(fas, mac="AA:BB:CC:DD:EE:01")
    _approve(admin, rid=1, devices="2")
    DB["portal_session"][0]["state"] = "authenticated"
    DB["device"].append(dict(voucher_id=1, mac="AA:BB:CC:DD:EE:01"))
    DB["claims"].clear()
    _register(fas, mac="AA:BB:CC:DD:EE:02")
    assert "มีสิทธิ์อยู่แล้ว" in admin.get("/requests").get_data(as_text=True)
    _approve(admin, rid=2, hours="24")  # แพ็กเกจใหม่ถูกเพิกเฉย ใช้ของเดิม
    assert len(DB["voucher"]) == 1
    assert DB["portal_session"][1]["voucher_id"] == 1
    assert DB["customer"][0]["visit_count"] == 2


def test_device_limit_on_existing_voucher(fas, admin):
    _register(fas, mac="AA:BB:CC:DD:EE:01")
    _approve(admin, rid=1, devices="1")
    DB["portal_session"][0]["state"] = "authenticated"
    DB["device"].append(dict(voucher_id=1, mac="AA:BB:CC:DD:EE:01"))
    DB["claims"].clear()
    _register(fas, mac="AA:BB:CC:DD:EE:02")
    r = _approve(admin, rid=2)
    assert r.status_code == 302
    assert DB["access_request"][1]["status"] == "pending", "ครบจำนวนเครื่อง = ไม่อนุมัติ"
    assert len(DB["portal_session"]) == 1 and "AA:BB:CC:DD:EE:02" not in DB["claims"]


def test_blocked_customer_cannot_be_approved(fas, admin):
    _register(fas)
    DB["customer"].append(dict(id=1, natid_hash=crypto.natid_hash(NATID), natid_enc=b"",
                               natid_masked="x", is_blocked=1, visit_count=1))
    assert "ลูกค้าถูกระงับ" in admin.get("/requests").get_data(as_text=True)
    _approve(admin)
    assert DB["access_request"][0]["status"] == "pending" and DB["voucher"] == []


def test_expired_request_cannot_be_approved(fas, admin):
    _register(fas)
    DB["access_request"][0]["expires_at"] = datetime.now() - timedelta(seconds=1)
    _approve(admin)
    assert DB["voucher"] == []
    assert "หมดอายุ" in fas.get("/request").get_data(as_text=True)


def test_reject_clears_pii_and_shows_reason_to_customer(fas, admin):
    _register(fas)
    r = admin.post("/requests/1/reject", data=dict(reason="ไม่มีบัตรมาแสดง"))
    assert r.status_code == 302
    req = DB["access_request"][0]
    assert req["status"] == "rejected" and req["natid_enc"] is None
    assert "ไม่มีบัตรมาแสดง" in fas.get("/request").get_data(as_text=True)
    assert "request_reject" in [a[1] for a in DB["audit"]]
    assert admin.post("/requests/1/reject").status_code == 302  # ซ้ำ = ไม่พัง


def test_bad_package_values_rejected(fas, admin):
    _register(fas)
    _approve(admin, hours="abc")
    _approve(admin, quota_mb="-5")
    assert DB["voucher"] == [] and DB["access_request"][0]["status"] == "pending"


def test_staff_role_can_approve(fas, admin):
    DB["staff"].append(dict(id=2, username="barista", role="staff", is_active=1,
                            must_change_password=0, password_changed_at=None))
    with admin.session_transaction() as s:
        s.update(staff_id=2, username="barista", role="staff", pw_at="")
    _register(fas)
    _approve(admin)
    assert DB["access_request"][0]["status"] == "approved"


def test_csrf_required_on_approve(fas, admin):
    admin.application.config.update(CSRF_ENABLED=True)
    _register(fas)
    assert _approve(admin).status_code == 400
    assert DB["access_request"][0]["status"] == "pending"


def _full_voucher(fas, admin):
    """ลูกค้ามีสิทธิ์ 1 เครื่องและใช้ไปแล้ว แล้วมาขอเครื่องที่ 2 (ภาพจากหน้าจอจริง 2 ต.ค.)"""
    _register(fas, mac="AA:BB:CC:DD:EE:01")
    _approve(admin, rid=1, devices="1")
    DB["portal_session"][0]["state"] = "authenticated"
    DB["device"].append(dict(voucher_id=1, mac="AA:BB:CC:DD:EE:01"))
    DB["claims"].clear()
    _register(fas, mac="AA:BB:CC:DD:EE:02")


def test_full_voucher_shows_warning_and_device_editor(fas, admin):
    _full_voucher(fas, admin)
    html = admin.get("/requests").get_data(as_text=True)
    assert "ใช้ 1/1 เครื่อง" in html and "ใช้ครบแล้ว" in html
    assert 'action="/vouchers/1/devices"' in html
    assert re.search(r'id="vdev-2"[^>]*value="2"', html, re.S), "ครบแล้ว = เสนอเพิ่มเป็น 2 ไว้ให้"


def test_raise_device_limit_then_approve_second_device(fas, admin):
    _full_voucher(fas, admin)
    r = admin.post("/vouchers/1/devices", data=dict(devices="2", next="/requests"))
    assert r.status_code == 302 and r.headers["Location"].endswith("/requests")
    assert DB["voucher"][0]["max_devices"] == 2
    assert "voucher_devices" in [a[1] for a in DB["audit"]]
    _approve(admin, rid=2)
    assert DB["access_request"][1]["status"] == "approved"
    assert DB["portal_session"][1]["voucher_id"] == 1


def test_device_limit_cannot_drop_below_bound_devices_or_out_of_range(fas, admin):
    _full_voucher(fas, admin)
    DB["voucher"][0]["max_devices"] = 3
    DB["device"].append(dict(voucher_id=1, mac="AA:BB:CC:DD:EE:03"))
    for bad in ("1", "0", "6", "abc"):
        admin.post("/vouchers/1/devices", data=dict(devices=bad))
        assert DB["voucher"][0]["max_devices"] == 3, bad
    admin.post("/vouchers/1/devices", data=dict(devices="2"))
    assert DB["voucher"][0]["max_devices"] == 2


def test_device_edit_rejects_expired_voucher_and_unsafe_next(fas, admin):
    _full_voucher(fas, admin)
    DB["voucher"][0]["valid_until"] = datetime.now() - timedelta(minutes=1)
    r = admin.post("/vouchers/1/devices", data=dict(devices="3", next="//evil.example/"))
    assert DB["voucher"][0]["max_devices"] == 1
    assert r.headers["Location"].endswith("/requests"), "ห้าม open redirect ผ่าน next"


def test_register_page_has_show_hide_toggle(fas):
    html = fas.get(_gw_url()).get_data(as_text=True)
    assert 'id="natid-toggle"' in html and 'type="button"' in html
    assert 'type="password" id="natid"' in html, "ค่าเริ่มต้นต้องซ่อน"


def test_old_issue_page_is_gone(admin):
    assert admin.get("/issue").status_code == 404


# ================================================================ gateway validation (เดิมใน test_fas_flow)
@pytest.mark.parametrize("address,ok", [
    ("10.10.0.1:2050", True), ("10.10.0.1", True), ("10.10.0.1:8080", False),
    ("10.10.0.99:2050", False), ("evil.example:2050", False),
])
def test_valid_gateway_accepts_ip_with_nds_port(fas, address, ok):
    from fas.opennds_proto import ClientContext
    ctx = ClientContext(clientmac="AA:BB:CC:DD:EE:01", hid="h", gatewayaddress=address,
                        authdir="opennds_auth")
    assert fas.module._valid_gateway(ctx) is ok


def test_real_opennds_gateway_address_passes_validation(fas):
    from fas.opennds_proto import decrypt_fas_payload
    from test_opennds_proto import REAL_FAS_B64, REAL_FASKEY, REAL_IV
    ctx = decrypt_fas_payload(REAL_FAS_B64, REAL_IV, REAL_FASKEY)
    assert ctx.gatewayaddress == "10.10.0.1:2050"
    assert fas.module._valid_gateway(ctx)


# ================================================================ ชื่อเครื่อง + ระบบปฏิบัติการ
def test_register_records_hostname_and_os(fas):
    _register(fas)
    (req,) = DB["access_request"]
    assert req["hostname"] == "Somchais-iPhone", "ชื่อเครื่องมาจาก lease ของ dnsmasq"
    assert req["os_label"] == "iPhone · iOS 17.5"
    assert req["user_agent"] == IPHONE_UA


def test_register_without_hostname_or_user_agent_still_works(fas):
    r = _register(fas, mac="AA:BB:CC:DD:EE:02", ua="")
    assert r.status_code == 303
    (req,) = DB["access_request"]
    assert req["hostname"] is None and req["os_label"] is None and req["user_agent"] is None


def test_requests_page_shows_device_and_approval_copies_it_to_session(fas, admin):
    _register(fas)
    html = admin.get("/requests").get_data(as_text=True)
    assert "iPhone · iOS 17.5" in html and "Somchais-iPhone" in html
    _approve(admin)
    (s,) = DB["portal_session"]
    assert s["hostname"] == "Somchais-iPhone" and s["os_label"] == "iPhone · iOS 17.5"


def test_dashboard_and_recent_requests_show_device_names(fas, admin):
    _register(fas)
    _approve(admin)
    DB["portal_session"][0]["state"] = "authenticated"
    html = admin.get("/requests").get_data(as_text=True)
    assert html.count("Somchais-iPhone") >= 1, "รายการล่าสุดแสดงชื่อเครื่อง"
    # แดชบอร์ด: ใช้ fake แบบย่อ -- เรียก helper ตรง ๆ ว่าจัดกลุ่ม/ออนไลน์ถูก
    from admin.views.overview import _devices_by
    devs = _devices_by("id", [1])
    assert devs[1][0]["hostname"] == "Somchais-iPhone" and devs[1][0]["online"] is True


# ================================================================ แดชบอร์ด: อุปกรณ์บนเครือข่าย
def test_dashboard_network_overview_counts_and_lists_devices(fas, admin, tmp_path, monkeypatch):
    from common import device_info
    lease = tmp_path / "net.leases"
    lease.write_text("0 aa:bb:cc:dd:ee:01 10.10.0.105 Somchais-iPhone *\n"     # ได้รับสิทธิ์
                     "0 aa:bb:cc:dd:ee:02 10.10.0.106 * *\n"                     # รออนุมัติ
                     "0 aa:bb:cc:dd:ee:03 10.10.0.107 DESKTOP-7KQ2L *\n"         # ยังไม่ระบุตัว
                     "1000 aa:bb:cc:dd:ee:04 10.10.0.108 Old-Phone *\n")         # lease หมดอายุแล้ว
    conf = tmp_path / "dnsmasq.conf"
    conf.write_text("dhcp-range=10.10.0.100,10.10.0.250,255.255.255.0,4h\n")
    monkeypatch.setattr(device_info, "LEASE_FILE", str(lease))
    monkeypatch.setattr(device_info, "DNSMASQ_CONF", str(conf))
    _register(fas)
    _approve(admin)
    DB["portal_session"][0]["state"] = "authenticated"
    _register(fas, natid=NATID2, mac="AA:BB:CC:DD:EE:02")
    html = admin.get("/").get_data(as_text=True)
    assert "อุปกรณ์บนเครือข่ายตอนนี้" in html
    assert re.search(r"แจก IP ไปแล้ว <b[^>]*>3</b>\s*จาก 151", html)
    for n, label in ((1, "ระบุตัวแล้ว"), (1, "รออนุมัติ"), (1, "ยังไม่ระบุตัว"), (148, "IP ว่าง")):
        assert re.search(rf"<b>{n}</b> {label}", html), label
    assert "DESKTOP-7KQ2L" in html and "Old-Phone" not in html



def test_dashboard_and_customers_show_data_usage(fas, admin, tmp_path, monkeypatch):
    from common import device_info
    lease = tmp_path / "u.leases"
    lease.write_text("0 aa:bb:cc:dd:ee:01 10.10.0.105 Somchais-iPhone *\n")
    _register(fas)
    monkeypatch.setattr(device_info, "LEASE_FILE", str(lease))
    _approve(admin, quota_mb="1000")
    DB["portal_session"][0]["state"] = "authenticated"
    DB["conn"] = [dict(mac="AA:BB:CC:DD:EE:01", out=4_000_000, **{"in": 816_000_000})]
    html = admin.get("/").get_data(as_text=True)
    assert "820.0 MB" in html and "/ 1.0 GB" in html, "ใช้ไป/โควตา บนแดชบอร์ด"
    assert "↓ 816.0 MB · ↑ 4.0 MB" in html
    assert "var(--warn)" in html, "ใช้ 82% ของโควตา = แถบสีเหลือง"
    assert "ใช้เน็ตรวม <b" in html and html.count("820.0 MB") >= 2, "ทั้งรายการเครื่องออนไลน์และสิทธิ์ล่าสุด"
    html = admin.get("/customers").get_data(as_text=True)
    assert "820.0 MB" in html


def test_portal_has_staff_login_button(fas):
    """ร้านจริง: พนักงานได้ IP วงลูกค้า -- หน้า portal ต้องมีทางไปหน้าแอดมิน"""
    html = fas.get(_gw_url()).get_data(as_text=True)
    assert "เข้าสู่ระบบสำหรับแอดมินและพนักงาน" in html
    assert 'href="https://cafe.wifi:8443/login"' in html
    assert "เข้าสู่ระบบสำหรับแอดมินและพนักงาน" in fas.get("/login").get_data(as_text=True), "หน้าแนะนำ cafe.wifi ด้วย"



# ================================================================ ลูกค้าดูเวลา/เน็ตที่เหลือ
def _online(fas, admin, quota_mb=""):
    _register(fas)
    _approve(admin, hours="2", quota_mb=quota_mb)
    sess = DB["portal_session"][0]
    sess.update(state="authenticated", authenticated_at=_now())
    return sess


def test_online_page_shows_time_and_data_left(fas, admin):
    _online(fas, admin, quota_mb="1000")
    DB["voucher"][0]["used_mb"] = 300
    DB["conn"] = [dict(mac="AA:BB:CC:DD:EE:01", out=10_000_000, **{"in": 390_000_000})]
    html = fas.get("/request").get_data(as_text=True)
    assert "เวลาที่เหลือ" in html and "1 ชม. 59 นาที" in html
    assert "ใช้เน็ตไป <b>700.0 MB</b>" in html and "จาก 1.0 GB" in html, "300 MB ที่ปิดบัญชีแล้ว + 400 MB สด"
    assert "เหลือ 300.0 MB" in html and "var(--warn)" in html, "70% = แถบเหลือง"
    assert 'http-equiv="refresh" content="60"' in html


def test_online_page_unlimited_quota(fas, admin):
    _online(fas, admin)
    html = fas.get("/request").get_data(as_text=True)
    assert "ไม่จำกัด" in html and "เหลือ" in html


def test_cafe_wifi_root_redirects_to_status(fas):
    r = fas.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/request")


@pytest.mark.parametrize("cause,expect", [
    ("voucher_expired", "หมดเวลาใช้งานแล้ว"),
    ("quota_exceeded", "ใช้เน็ตครบโควตาแล้ว"),
    ("voucher_revoked", "ถูกปิดโดยพนักงาน"),
    ("disconnected", "หลุดการเชื่อมต่อ"),
])
def test_ended_session_explains_why_instead_of_failed(fas, admin, cause, expect):
    """บั๊กเดิม: ใช้ครบเวลาตามปกติแล้วขึ้น 'เปิดอินเทอร์เน็ตไม่สำเร็จ'"""
    sess = _online(fas, admin)
    sess.update(state="closed", ended_at=_now(), terminate_cause=cause)
    if cause == "voucher_expired":
        DB["voucher"][0]["valid_until"] = _now() - timedelta(minutes=1)
    html = fas.get("/request").get_data(as_text=True)
    assert expect in html and "ไม่สำเร็จ" not in html


def test_reconnected_device_uses_latest_session(fas, admin):
    """หลุดแล้วกลับมาได้ session ใหม่ในสิทธิ์เดิม -- ต้องขึ้นออนไลน์ ไม่ใช่ 'หลุด'"""
    sess = _online(fas, admin)
    sess.update(state="closed", ended_at=_now(), terminate_cause="reauth")
    DB["portal_session"].append(dict(sess, id=2, state="authenticated", ended_at=None, terminate_cause=None))
    html = fas.get("/request").get_data(as_text=True)
    assert "เวลาที่เหลือ" in html and "หลุด" not in html



# ================================================================ ปุ่มต่อเวลา
def test_extend_voucher_adds_time_flags_gateway_sync_and_audits(fas, admin):
    _register(fas)
    _approve(admin, hours="1")
    v = DB["voucher"][0]
    before = v["valid_until"]
    r = admin.post(f"/vouchers/{v['id']}/extend", data=dict(minutes="60"))
    assert r.status_code == 302
    assert v["valid_until"] - before == timedelta(minutes=60) and v["auth_sync_needed"] == 1
    assert any(a[1] == "voucher_extend" and "+60min" in a[4] for a in DB["audit"])


def test_extend_rejects_bad_minutes_and_dead_vouchers(fas, admin):
    _register(fas)
    _approve(admin, hours="1")
    v = DB["voucher"][0]
    assert admin.post(f"/vouchers/{v['id']}/extend", data=dict(minutes="999")).status_code == 400
    v["status"] = "revoked"
    before = v["valid_until"]
    admin.post(f"/vouchers/{v['id']}/extend", data=dict(minutes="60"))
    assert v["valid_until"] == before and not v.get("auth_sync_needed")


# ================================================================ เลขบัตร: ตัวเลข 13 หลักเท่านั้น
@pytest.mark.parametrize("bad", ["1-1017-00000-01-0", "1101 7000 0001 0", "110170000001", "11017000000100",
                                 "110170000001a", " "])
def test_natid_must_be_exactly_13_digits(fas, bad):
    r = _register(fas, natid=bad)
    assert r.status_code == 400 and DB["access_request"] == []
    assert "ตัวเลข 13 หลักเท่านั้น" in r.get_data(as_text=True)


def test_natid_field_restricts_input_in_browser(fas):
    html = fas.get(_gw_url()).get_data(as_text=True)
    assert 'pattern="[0-9]{13}"' in html and 'maxlength="13"' in html and 'minlength="13"' in html
    assert "replace(/\D/g, '')" in html and "0/13" in html
