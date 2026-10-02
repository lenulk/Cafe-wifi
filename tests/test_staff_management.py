"""
T-Staff — บัญชีพนักงานรายคน (หน้า /staff + /account/password)

ฐานข้อมูลจำลองในหน่วยความจำ รันได้โดยไม่ต้องมี MariaDB · ครอบคลุม: admin สร้างบัญชีด้วยรหัสชั่วคราว,
บังคับเปลี่ยนรหัสตอนเข้าใช้ครั้งแรก, เปลี่ยน/รีเซ็ตรหัสแล้ว session เดิมหลุด, ปิดบัญชี/เปลี่ยน role,
กันไม่ให้ระบบเหลือ admin 0 คน, staff เข้าหน้านี้ไม่ได้, ทุกการกระทำลง audit_log
"""
import contextlib
import re
from datetime import datetime, timedelta

import pytest

from common import crypto

ADMIN_PW = "CafeWifi2026Secure"
NEW_PW = "Barista2026Strong"

STAFF: list[dict] = []
AUDIT: list[tuple] = []
CLOCK = {"t": datetime(2026, 10, 2, 9, 0, 0)}


def _now():
    # NOW() ของ DB จำลอง เดินทีละวินาที -- ค่า password_changed_at แต่ละครั้งจึงไม่ซ้ำกัน
    CLOCK["t"] += timedelta(seconds=1)
    return CLOCK["t"]


def _by_id(sid):
    return next((r for r in STAFF if r["id"] == sid), None)


class FakeCursor:
    def __init__(self):
        self.lastrowid = None
        self.rowcount = 0
        self._rows: list[dict] = []

    def execute(self, sql, args=()):
        s = " ".join(sql.split()).lower()
        self._rows = []
        if s.startswith("select count(*) as n from staff"):
            self._rows = [{"n": len(STAFF)}]
        elif s.startswith("select role, is_active"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("select id, username, password_hash"):
            self._rows = [r for r in STAFF if r["username"] == args[0]]
        elif s.startswith("select id, username, display_name"):
            self._rows = sorted(STAFF, key=lambda r: (not r["is_active"], r["username"]))
        elif s.startswith("select id from staff where username"):
            self._rows = [r for r in STAFF if r["username"] == args[0]]
        elif s.startswith("select id, username, role, is_active from staff where id"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("select id from staff where role='admin'"):
            self._rows = [r for r in STAFF if r["role"] == "admin" and r["is_active"]
                          and r["id"] != args[0]]
        elif s.startswith("select must_change_password from staff"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("select password_hash from staff"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("select password_changed_at from staff"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("insert into staff"):
            STAFF.append(dict(id=len(STAFF) + 1, username=args[0], password_hash=args[1],
                              display_name=args[2], role=args[3], is_active=1,
                              must_change_password=1, password_changed_at=_now(),
                              created_at=CLOCK["t"], last_login_at=None))
            self.lastrowid = STAFF[-1]["id"]
        elif s.startswith("update staff set last_login_at"):
            _by_id(args[0])["last_login_at"] = CLOCK["t"]
        elif s.startswith("update staff set is_active"):
            _by_id(args[1])["is_active"] = args[0]
        elif s.startswith("update staff set role"):
            _by_id(args[1])["role"] = args[0]
        elif s.startswith("update staff set password_hash = %s, must_change_password = 1"):
            _by_id(args[1]).update(password_hash=args[0], must_change_password=1,
                                   password_changed_at=_now())
        elif s.startswith("update staff set password_hash = %s, must_change_password = 0"):
            _by_id(args[1]).update(password_hash=args[0], must_change_password=0,
                                   password_changed_at=_now())
        elif s.startswith("insert into audit_log"):
            AUDIT.append(args)
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
    def cursor(self):
        return FakeCursor()


@pytest.fixture
def app_mod(tmp_path, monkeypatch):
    STAFF.clear()
    AUDIT.clear()
    STAFF.append(dict(id=1, username="owner", password_hash=crypto.hash_password(ADMIN_PW),
                      display_name="เจ้าของร้าน", role="admin", is_active=1,
                      must_change_password=0, password_changed_at=None,
                      created_at=CLOCK["t"], last_login_at=None))
    monkeypatch.setenv("ETC_DIR", str(tmp_path))

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
    admin_app.SETUP_TOKEN_FILE = tmp_path / "setup.token"  # ไม่มีไฟล์ = setup เสร็จแล้ว
    admin_app.app.config.update(SESSION_COOKIE_SECURE=False, TESTING=True, CSRF_ENABLED=False)
    admin_app._attempts.clear()
    return admin_app


def _client(app_mod):
    return app_mod.app.test_client()


def _login(c, username, password):
    return c.post("/login", data=dict(username=username, password=password))


def _create(c, username="somchai", role="staff"):
    r = c.post("/staff", data=dict(username=username, display_name="สมชาย", role=role))
    m = re.findall(r'<div class="cred">([^<]+)</div>', r.get_data(as_text=True))
    return r, (m[1].strip() if len(m) > 1 else None)


def _actions():
    return [a[1] for a in AUDIT]


# ---------------------------------------------------------------- สร้างบัญชี
def test_admin_creates_staff_with_temp_password_shown_once(app_mod):
    c = _client(app_mod)
    assert _login(c, "owner", ADMIN_PW).status_code == 302
    r, temp = _create(c)
    assert r.status_code == 200
    assert r.headers["Cache-Control"] == "no-store"
    assert temp and not crypto.check_admin_password(temp), "รหัสชั่วคราวต้องผ่านนโยบายรหัสผ่าน"
    new = STAFF[-1]
    assert (new["username"], new["role"], new["must_change_password"]) == ("somchai", "staff", 1)
    assert crypto.verify_password(new["password_hash"], temp)
    assert temp not in new["password_hash"], "เก็บแค่ hash"
    assert "staff_create" in _actions()


def test_duplicate_and_invalid_username_rejected(app_mod):
    c = _client(app_mod)
    _login(c, "owner", ADMIN_PW)
    assert _create(c, username="owner")[0].status_code == 409
    assert _create(c, username="ไทย")[0].status_code == 400
    assert _create(c, username="a b")[0].status_code == 400
    assert len(STAFF) == 1


def test_staff_role_cannot_open_staff_pages(app_mod):
    c = _client(app_mod)
    _login(c, "owner", ADMIN_PW)
    _, temp = _create(c)
    s = _client(app_mod)
    _login(s, "somchai", temp)
    s.post("/account/password", data=dict(current_password=temp, password=NEW_PW,
                                          password_confirm=NEW_PW))
    assert s.get("/staff").status_code == 403
    assert s.post("/staff", data=dict(username="evil", role="admin")).status_code == 403
    assert s.post("/staff/1/active").status_code == 403
    assert len(STAFF) == 2


# ---------------------------------------------------------------- บังคับเปลี่ยนรหัส
def test_temp_password_forces_change_before_anything_else(app_mod):
    c = _client(app_mod)
    _login(c, "owner", ADMIN_PW)
    _, temp = _create(c)

    s = _client(app_mod)
    r = _login(s, "somchai", temp)
    assert r.status_code == 302 and r.headers["Location"].endswith("/account/password")
    for path in ("/", "/issue", "/customers", "/logs"):
        r = s.get(path)
        assert r.status_code == 302 and r.headers["Location"].endswith("/account/password"), path
    assert "ตั้งรหัสผ่านของคุณ" in s.get("/account/password").get_data(as_text=True)

    r = s.post("/account/password", data=dict(current_password=temp, password=NEW_PW,
                                              password_confirm=NEW_PW))
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    assert STAFF[-1]["must_change_password"] == 0
    assert s.get("/issue").status_code == 200, "ตั้งรหัสแล้ว session เดิมใช้ต่อได้"
    assert "password_change" in _actions()


def test_change_password_validations(app_mod):
    c = _client(app_mod)
    _login(c, "owner", ADMIN_PW)
    bad = [
        dict(current_password="wrong", password=NEW_PW, password_confirm=NEW_PW),
        dict(current_password=ADMIN_PW, password=NEW_PW, password_confirm=NEW_PW + "x"),
        dict(current_password=ADMIN_PW, password="short1A", password_confirm="short1A"),
        dict(current_password=ADMIN_PW, password=ADMIN_PW, password_confirm=ADMIN_PW),
    ]
    for data in bad:
        assert c.post("/account/password", data=data).status_code == 400, data
    assert crypto.verify_password(STAFF[0]["password_hash"], ADMIN_PW), "รหัสเดิมต้องไม่ถูกเปลี่ยน"


def test_change_password_rate_limited(app_mod):
    c = _client(app_mod)
    _login(c, "owner", ADMIN_PW)
    codes = [c.post("/account/password", data=dict(current_password="wrong", password=NEW_PW,
                                                    password_confirm=NEW_PW)).status_code
             for _ in range(8)]
    assert codes[-1] == 429


# ---------------------------------------------------------------- session หลุดเมื่อรหัสเปลี่ยน
def test_own_password_change_logs_out_other_devices(app_mod):
    phone, laptop = _client(app_mod), _client(app_mod)
    _login(phone, "owner", ADMIN_PW)
    _login(laptop, "owner", ADMIN_PW)
    assert laptop.get("/issue").status_code == 200
    phone.post("/account/password", data=dict(current_password=ADMIN_PW, password=NEW_PW,
                                              password_confirm=NEW_PW))
    assert phone.get("/issue").status_code == 200
    r = laptop.get("/issue")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_reset_password_kicks_existing_session_and_old_password_stops_working(app_mod):
    a = _client(app_mod)
    _login(a, "owner", ADMIN_PW)
    _, temp = _create(a)
    s = _client(app_mod)
    _login(s, "somchai", temp)
    s.post("/account/password", data=dict(current_password=temp, password=NEW_PW,
                                          password_confirm=NEW_PW))
    assert s.get("/issue").status_code == 200

    r = a.post(f"/staff/{STAFF[-1]['id']}/reset-password")
    new_temp = re.findall(r'<div class="cred">([^<]+)</div>', r.get_data(as_text=True))[1].strip()
    assert new_temp != temp
    r = s.get("/issue")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert _login(_client(app_mod), "somchai", NEW_PW).status_code == 401
    assert STAFF[-1]["must_change_password"] == 1
    assert "staff_reset_password" in _actions()


# ---------------------------------------------------------------- ปิดบัญชี / role
def test_disable_kicks_session_and_blocks_login(app_mod):
    a = _client(app_mod)
    _login(a, "owner", ADMIN_PW)
    _, temp = _create(a)
    s = _client(app_mod)
    _login(s, "somchai", temp)
    sid = STAFF[-1]["id"]

    assert a.post(f"/staff/{sid}/active").status_code == 302
    assert STAFF[-1]["is_active"] == 0
    r = s.get("/account/password")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert _login(_client(app_mod), "somchai", temp).status_code == 401

    a.post(f"/staff/{sid}/active")
    assert STAFF[-1]["is_active"] == 1
    assert {"staff_disable", "staff_enable"} <= set(_actions())


def test_cannot_disable_or_demote_self(app_mod):
    a = _client(app_mod)
    _login(a, "owner", ADMIN_PW)
    assert a.post("/staff/1/active").status_code == 400
    assert a.post("/staff/1/role", data=dict(role="staff")).status_code == 400
    assert a.post("/staff/1/reset-password").status_code == 400
    assert STAFF[0]["is_active"] == 1 and STAFF[0]["role"] == "admin"


def test_last_active_admin_is_protected(app_mod):
    a = _client(app_mod)
    _login(a, "owner", ADMIN_PW)
    _, temp = _create(a, username="manager", role="admin")
    m = _client(app_mod)
    _login(m, "manager", temp)
    m.post("/account/password", data=dict(current_password=temp, password=NEW_PW,
                                          password_confirm=NEW_PW))
    # admin 2 คน: manager ปิด owner ได้ เพราะยังเหลือตัวเองเป็น admin
    assert m.post("/staff/1/active").status_code == 302
    assert STAFF[0]["is_active"] == 0
    # เหลือ admin คนเดียว -- ตัวนับต้องเห็นว่าถ้าปิด/ลด manager จะไม่เหลือใคร (กันกรณี admin 2 คน
    # กดปิดกันเองพร้อมกัน: request ที่สองจะเจอแถวที่ล็อกไว้และนับได้ 0)
    cur = FakeCursor()
    assert app_mod._other_active_admins(cur, STAFF[-1]["id"]) == 0
    assert app_mod._other_active_admins(cur, 1) == 1


def test_role_change_takes_effect_on_live_session(app_mod):
    a = _client(app_mod)
    _login(a, "owner", ADMIN_PW)
    _, temp = _create(a, username="manager", role="admin")
    m = _client(app_mod)
    _login(m, "manager", temp)
    m.post("/account/password", data=dict(current_password=temp, password=NEW_PW,
                                          password_confirm=NEW_PW))
    assert m.get("/staff").status_code == 200
    assert a.post(f"/staff/{STAFF[-1]['id']}/role", data=dict(role="staff")).status_code == 302
    r = m.get("/staff")
    assert r.status_code == 302 and "/login" in r.headers["Location"], "role เปลี่ยน = ต้อง login ใหม่ (R2-L03)"
    assert "staff_role" in _actions()


def test_staff_page_lists_accounts_and_nav_link_only_for_admin(app_mod):
    a = _client(app_mod)
    _login(a, "owner", ADMIN_PW)
    _create(a)
    html = a.get("/staff").get_data(as_text=True)
    assert "somchai" in html and "รอตั้งรหัสใหม่" in html
    assert 'href="/staff"' in a.get("/issue").get_data(as_text=True)


def test_csrf_required_on_staff_actions(app_mod):
    app_mod.app.config.update(CSRF_ENABLED=True)
    a = _client(app_mod)
    with a.session_transaction() as s:
        s.update(staff_id=1, username="owner", role="admin", pw_at="")
    assert a.post("/staff", data=dict(username="sneaky", role="admin")).status_code == 400
    assert len(STAFF) == 1


def test_temp_password_generator_always_meets_policy():
    for _ in range(200):
        pw = crypto.gen_temp_staff_password()
        assert not crypto.check_admin_password(pw), pw
        assert re.fullmatch(r"[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}", pw)
