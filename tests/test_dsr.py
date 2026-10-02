"""
T-DSR — สิทธิ์ขอให้ลบข้อมูลรายบุคคล (N6, CODING_BRIEF.md)

§6.2 ข้อ 6 ของนโยบายความเป็นส่วนตัวประกาศสิทธิ์นี้ไว้แล้ว แต่ก่อนหน้านี้มีแค่ /reveal กับ
/block -- purge_old_data.py ลบตามอายุอัตโนมัติเท่านั้น ลบรายคนตามคำขอไม่ได้เลย

ไฟล์นี้แบ่งเป็น 2 ส่วน: (1) เทสต์ตรงของ common/customer.py::anonymize_customer() (2) เทสต์
ชั้น route/permission ผ่าน Flask test client ของ POST /customers/<id>/erase เหมือน
tests/test_logs_verify.py (N2) รวมผลข้างเคียงที่ /reveal ต้องปฏิเสธลูกค้าที่ถูกลบไปแล้วด้วย
"""
from __future__ import annotations

import contextlib
from datetime import datetime, timedelta

import pytest

from common import crypto
from common.customer import PURGED_MARK, anonymize_customer, retention_hold_until

# ================================================================== ส่วนที่ 1: common/customer.py ตรง ๆ


def test_anonymize_customer_writes_expected_sql_and_returns_rowcount():
    calls = []

    def fake_exec(sql, args=()):
        calls.append((" ".join(sql.split()), args))
        return 1

    n = anonymize_customer(fake_exec, 42)
    assert n == 1
    assert [c[0].split()[1] for c in calls[1:]] == ["portal_session", "access_request"],         "ชื่อเครื่องอาจมีชื่อจริง -- ต้องล้างพร้อมเลขบัตร"
    assert all("hostname = NULL" in c[0] and c[1] == (42,) for c in calls[1:])
    sql, args = calls[0]
    assert sql.upper().startswith("UPDATE CUSTOMER SET NATID_HASH")
    assert "NATID_MASKED = 'PURGED'" in sql.upper()
    assert args == (42,), "ต้องส่งแค่ customer_id เป็นพารามิเตอร์ (ตรงกับที่ purge_old_data.py เดิมใช้)"


def test_anonymize_customer_passes_through_zero_rowcount_when_not_found():
    calls = []
    n = anonymize_customer(lambda sql, args=(): calls.append(sql) or 0, 999)
    assert n == 0 and len(calls) == 1, "ไม่พบลูกค้า = ไม่ต้องไปแตะตารางอื่น"


# ================================================================== ส่วนที่ 2: route /customers/<id>/erase ผ่าน Flask


GOOD_PW = "CafeWifi2026Secure"
STAFF = [
    {"id": 1, "username": "admin1", "password_hash": crypto.hash_password(GOOD_PW),
     "display_name": "Admin", "role": "admin", "is_active": 1},
    {"id": 2, "username": "staff1", "password_hash": crypto.hash_password(GOOD_PW),
     "display_name": "Staff", "role": "staff", "is_active": 1},
]
CUSTOMERS: list[dict] = []
AUDIT: list[tuple] = []
HOSTNAME_CLEARED: list = []


def _reset():
    LAST_ACTIVITY[0] = datetime.now() - timedelta(days=400)
    CUSTOMERS.clear()
    CUSTOMERS.append({
        "id": 1, "natid_hash": "hash-of-real-id", "natid_enc": b"x" * 40,
        "natid_masked": "1-2345-XXXXX-XX-3", "first_seen": datetime(2026, 1, 1),
        "last_seen": datetime(2026, 8, 1), "visit_count": 3, "is_blocked": 0,
    })
    CUSTOMERS.append({
        "id": 2, "natid_hash": "PURGED-2", "natid_enc": b"",
        "natid_masked": PURGED_MARK, "first_seen": datetime(2026, 1, 1),
        "last_seen": datetime(2026, 7, 1), "visit_count": 1, "is_blocked": 0,
    })
    AUDIT.clear()
    HOSTNAME_CLEARED.clear()


LAST_ACTIVITY = [datetime.now() - timedelta(days=400)]  # N33: ค่าเริ่มต้น = พ้นระยะเก็บแล้ว


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
        elif s.startswith("select id, natid_masked from customer where id"):
            match = next((c for c in CUSTOMERS if c["id"] == args[0]), None)
            self._rows = [dict(id=match["id"], natid_masked=match["natid_masked"])] if match else []
        elif s.startswith("select natid_enc, natid_masked from customer where id"):
            match = next((c for c in CUSTOMERS if c["id"] == args[0]), None)
            self._rows = [dict(natid_enc=match["natid_enc"], natid_masked=match["natid_masked"])] if match else []
        elif s.startswith("select id, natid_masked, first_seen, last_seen, visit_count, is_blocked "
                          "from customer order by last_seen"):
            self._rows = list(CUSTOMERS)
        elif s.startswith("select v.customer_id as k"):
            self._rows = []  # เครื่องที่ลูกค้าเคยใช้ (หน้า /customers)
        elif s.startswith("update customer set natid_hash"):
            cid = args[0]
            match = next((c for c in CUSTOMERS if c["id"] == cid), None)
            if match:
                match["natid_hash"] = f"PURGED-{cid}"
                match["natid_enc"] = b""
                match["natid_masked"] = PURGED_MARK
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif s.startswith(("update portal_session ps join voucher", "update access_request ar join voucher")):
            HOSTNAME_CLEARED.append(args[0])  # ชื่อเครื่องอาจมีชื่อจริง -- ล้างพร้อมเลขบัตร
        elif s.startswith("select greatest("):
            # N33: กิจกรรมล่าสุดของลูกค้า -- ค่าเริ่มต้นตั้งให้เก่ากว่าระยะเก็บ (ลบได้) เทสต์ที่
            # ต้องการกรณี "ยังลบไม่ได้" จะเซ็ต LAST_ACTIVITY ให้เป็นวันที่ใกล้ ๆ เอง
            self._rows = [{"last_activity": LAST_ACTIVITY[0]}]
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
    return admin_app.app.test_client()


def _login_as(client, role):
    staff = next(s for s in STAFF if s["role"] == role)
    with client.session_transaction() as sess:
        sess["staff_id"] = staff["id"]
        sess["username"] = staff["username"]
        sess["role"] = staff["role"]


# ---------------------------------------------------------------- สิทธิ์
def test_erase_requires_login(client):
    r = client.post("/customers/1/erase", data={"reason": "ลูกค้าขอใช้สิทธิ์ตาม PDPA"})
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_staff_role_gets_403_not_admin(client):
    _login_as(client, "staff")
    r = client.post("/customers/1/erase", data={"reason": "ลูกค้าขอใช้สิทธิ์ตาม PDPA"})
    assert r.status_code == 403
    assert len(AUDIT) == 0


def test_erase_rejects_short_reason(client):
    _login_as(client, "admin")
    r = client.post("/customers/1/erase", data={"reason": "สั้นไป"})
    assert r.status_code == 400
    assert len(AUDIT) == 0
    # ยังไม่ถูกล้าง
    assert CUSTOMERS[0]["natid_masked"] != PURGED_MARK


def test_erase_rejects_missing_reason(client):
    _login_as(client, "admin")
    r = client.post("/customers/1/erase", data={})
    assert r.status_code == 400
    assert len(AUDIT) == 0


def test_erase_unknown_customer_404(client):
    _login_as(client, "admin")
    r = client.post("/customers/999/erase", data={"reason": "ลูกค้าขอใช้สิทธิ์ตาม PDPA"})
    assert r.status_code == 404
    assert len(AUDIT) == 0


# ---------------------------------------------------------------- กรณีหลัก: ลบสำเร็จ
def test_erase_success_anonymizes_and_logs_audit(client):
    _login_as(client, "admin")
    reason = "ลูกค้าโทรมาขอใช้สิทธิ์ลบข้อมูลตาม PDPA วันที่ 26/08"
    r = client.post("/customers/1/erase", data={"reason": reason}, follow_redirects=False)
    assert r.status_code == 302
    assert "/customers" in r.headers["Location"]

    # แถวยังอยู่ (ไม่ใช่ DELETE) แต่ข้อมูลระบุตัวตนถูกล้างแล้ว -- ห้าม DELETE เพราะชน
    # fk_voucher_customer (D20)
    row = CUSTOMERS[0]
    assert row["natid_masked"] == PURGED_MARK
    assert row["natid_enc"] == b""
    assert row["natid_hash"] == "PURGED-1"

    assert HOSTNAME_CLEARED == [1, 1], "ต้องล้างชื่อเครื่องทั้งใน portal_session และ access_request"
    assert len(AUDIT) == 1
    assert AUDIT[0][1] == "erase_customer"
    assert AUDIT[0][2] == "customer:1"
    assert AUDIT[0][4] == reason


def test_erase_already_purged_customer_is_a_noop_no_duplicate_audit(client):
    """ลูกค้า id=2 ถูกลบไปแล้วตั้งแต่ fixture -- กดซ้ำต้องไม่ throw และไม่ลง audit_log ซ้ำ"""
    _login_as(client, "admin")
    r = client.post("/customers/2/erase", data={"reason": "กดซ้ำโดยไม่ตั้งใจ"}, follow_redirects=False)
    assert r.status_code == 302
    assert len(AUDIT) == 0


# ---------------------------------------------------------------- ผลข้างเคียงที่ /customers และ /reveal
def test_customers_page_shows_erased_badge_instead_of_buttons(client):
    _login_as(client, "admin")
    html = client.get("/customers").get_data(as_text=True)
    assert "ลบข้อมูลแล้ว" in html


def test_reveal_on_purged_customer_returns_410_not_crash(client):
    """natid_enc ว่างเปล่าหลังลบ -- ต้องปฏิเสธชัดเจน ไม่ปล่อยให้ natid_decrypt() throw ValueError
    หลุดออกไปเป็น 500 ทั่วไปที่อ่านไม่ออก"""
    _login_as(client, "admin")
    r = client.post("/customers/2/reveal", data={"reason": "ลองเปิดเผยหลังลบไปแล้ว"})
    assert r.status_code == 410
    html = r.get_data(as_text=True)
    assert "ถูกลบข้อมูล" in html
    assert len(AUDIT) == 0, "ไม่ควรลง audit_log เปิดเผย เพราะไม่มีอะไรให้เปิดเผยจริง"


def test_reveal_does_not_disclose_when_audit_write_fails(client, monkeypatch):
    import common.db as db
    _login_as(client, "admin")
    monkeypatch.setattr(db, "execute", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("audit down")))
    with pytest.raises(RuntimeError, match="audit down"):
        client.post("/customers/1/reveal", data={"reason": "ทดสอบ audit ล้มเหลว"})


# ============ N33: ม.26 บังคับเก็บข้อมูลผู้ใช้บริการ -- ลบตามคำขอก่อนครบกำหนดไม่ได้
def test_retention_hold_blocks_while_inside_window():
    now = datetime(2026, 9, 20, 12, 0, 0)
    q = lambda sql, args=(): {"last_activity": datetime(2026, 9, 1, 10, 0, 0)}

    hold = retention_hold_until(q, 1, retention_days=90, now=now)

    assert hold == datetime(2026, 11, 30, 10, 0, 0)


def test_retention_hold_is_none_after_window():
    now = datetime(2026, 9, 20, 12, 0, 0)
    q = lambda sql, args=(): {"last_activity": datetime(2026, 1, 1, 10, 0, 0)}

    assert retention_hold_until(q, 1, retention_days=90, now=now) is None


def test_retention_hold_is_none_when_customer_has_no_activity():
    assert retention_hold_until(lambda sql, args=(): None, 1, retention_days=90) is None


def test_erase_is_refused_while_customer_data_must_be_kept(client):
    """สิทธิ์ขอลบตาม PDPA ใช้ไม่ได้กับข้อมูลที่กฎหมายอื่นบังคับให้เก็บ -- ต้องปฏิเสธ แต่ต้อง
    บันทึกคำขอไว้เป็นหลักฐานว่าได้รับเรื่องแล้ว (ไม่ใช่เงียบหาย)"""
    LAST_ACTIVITY[0] = datetime.now() - timedelta(days=3)
    _login_as(client, "admin")

    r = client.post("/customers/1/erase", data={"reason": "ลูกค้าขอใช้สิทธิ์ลบข้อมูลตาม PDPA"},
                    follow_redirects=False)

    assert r.status_code == 302
    assert CUSTOMERS[0]["natid_masked"] != PURGED_MARK, "ห้ามลบระหว่างช่วงเก็บบังคับ"
    assert len(AUDIT) == 1
    assert AUDIT[0][1] == "erase_refused"
    assert "ยังอยู่ในช่วงเก็บบังคับถึง" in AUDIT[0][4]
