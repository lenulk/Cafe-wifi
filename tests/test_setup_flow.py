"""
T-Setup — First-run Setup Wizard (สร้างบัญชีผู้ดูแลระบบหลักผ่านหน้าเว็บ)

ใช้ฐานข้อมูลจำลองในหน่วยความจำ จึงรันได้โดยไม่ต้องมี MariaDB
"""
import contextlib
import os
import pathlib

import pytest

TOKEN = "b8f2c1d9e4a7361f0c5b2d8e93a41f6072ce5b1d4a8f3927"
GOOD_PW = "CafeWifi2026Secure"

STAFF: list[dict] = []
AUDIT: list[tuple] = []


class FakeCursor:
    def __init__(self):
        self.lastrowid = None
        self._rows: list[dict] = []

    def execute(self, sql, args=()):
        s = " ".join(sql.split()).lower()
        if s.startswith("select count(*) as n from staff"):
            self._rows = [{"n": len(STAFF)}]
        elif s.startswith("select role, is_active"):
            self._rows = [r for r in STAFF if r["id"] == args[0]]
        elif s.startswith("insert into staff"):
            STAFF.append({"id": len(STAFF) + 1, "username": args[0],
                          "password_hash": args[1], "display_name": args[2],
                          "role": "admin", "is_active": 1})
            self.lastrowid = STAFF[-1]["id"]
        elif s.startswith("insert into audit_log"):
            AUDIT.append(args)
            self.lastrowid = len(AUDIT)
        elif s.startswith("select id, username, password_hash"):
            self._rows = [r for r in STAFF if r["username"] == args[0]]
        else:
            self._rows = []

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
def client(tmp_path, monkeypatch):
    STAFF.clear()
    AUDIT.clear()
    monkeypatch.setenv("ETC_DIR", str(tmp_path))
    (tmp_path / "setup.token").write_text(TOKEN + "\n", encoding="utf-8")

    import common.db as db
    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(FakeConn()))

    def _run(sql, args=()):
        cur = FakeCursor()
        cur.execute(sql, args)
        return cur

    monkeypatch.setattr(db, "query_one", lambda s, a=(): _run(s, a).fetchone())
    monkeypatch.setattr(db, "query_all", lambda s, a=(): _run(s, a).fetchall())
    monkeypatch.setattr(db, "execute", lambda s, a=(): _run(s, a).lastrowid)

    import importlib
    admin_app = importlib.import_module("admin.app")
    importlib.reload(admin_app)
    admin_app.SETUP_TOKEN_FILE = tmp_path / "setup.token"
    admin_app.app.config.update(SESSION_COOKIE_SECURE=False, TESTING=True,
                                CSRF_ENABLED=False)  # R2-09: CSRF ทดสอบแยกท้าย test_setup_flow.py
    c = admin_app.app.test_client()
    c.token_file = tmp_path / "setup.token"
    return c


def _post(c, **over):
    data = dict(token=TOKEN, username="admin", display_name="ผู้ดูแลระบบ",
                password=GOOD_PW, password_confirm=GOOD_PW)
    data.update(over)
    return c.post("/setup", data=data)


def test_all_pages_redirect_to_setup_before_first_account(client):
    for path in ("/", "/customers", "/issue"):
        r = client.get(path)
        assert r.status_code == 302 and "/setup" in r.headers["Location"], path


def test_setup_page_renders_form(client):
    html = client.get("/setup").get_data(as_text=True)
    assert 'name="token"' in html
    assert "ปิดตัวเองถาวร" in html


def test_wrong_token_creates_nothing(client):
    r = _post(client, token="wrong-token")
    assert r.status_code == 400
    assert "Setup Token ไม่ถูกต้อง" in r.get_data(as_text=True)
    assert STAFF == []


def test_weak_password_rejected(client):
    r = _post(client, password="admin123", password_confirm="admin123")
    assert r.status_code == 400
    assert STAFF == []


def test_mismatched_password_rejected(client):
    r = _post(client, password_confirm=GOOD_PW + "x")
    assert r.status_code == 400
    assert STAFF == []


def test_invalid_username_rejected(client):
    assert _post(client, username="ad min!").status_code == 400
    assert STAFF == []


def test_successful_setup(client):
    r = _post(client)
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    assert len(STAFF) == 1
    assert STAFF[0]["role"] == "admin"
    assert GOOD_PW not in STAFF[0]["password_hash"], "ต้องเก็บเป็น hash เท่านั้น"
    assert not client.token_file.exists(), "ต้องลบ setup.token ทิ้งอัตโนมัติ"
    assert any("setup_admin" in str(a) for a in AUDIT)


def test_setup_closes_permanently(client):
    _post(client)
    assert client.get("/setup").status_code == 410
    r = _post(client, username="attacker")
    assert r.status_code == 410
    assert len(STAFF) == 1, "ห้ามสร้างบัญชีที่สองผ่านหน้า setup"


def test_login_with_new_account(client):
    _post(client)
    assert client.post("/login", data=dict(username="admin", password=GOOD_PW)).status_code == 302
    assert client.post("/login", data=dict(username="admin", password="wrong-pass-123")).status_code == 401


def _login_admin(client):
    _post(client)
    response = client.post("/login", data=dict(username="admin", password=GOOD_PW))
    assert response.status_code == 302


def test_active_staff_session_stays_valid(client):
    _login_admin(client)
    assert client.get("/setup").status_code == 410
    with client.session_transaction() as sess:
        assert sess["staff_id"] == STAFF[0]["id"]
        assert sess["role"] == "admin"


def test_deactivated_staff_is_logged_out_on_next_request(client):
    _login_admin(client)
    STAFF[0]["is_active"] = 0
    response = client.get("/setup")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert "staff_id" not in sess
        assert "role" not in sess


def test_deactivated_staff_post_is_stopped_before_route(client):
    _login_admin(client)
    STAFF[0]["is_active"] = 0
    prior_audit_count = len(AUDIT)
    response = client.post("/setup", data={"token": TOKEN})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    assert len(AUDIT) == prior_audit_count


def test_demoted_admin_must_log_in_again_as_staff(client):
    _login_admin(client)
    STAFF[0]["role"] = "staff"
    response = client.get("/setup")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert "staff_id" not in sess

    assert client.post("/login", data=dict(username="admin", password=GOOD_PW)).status_code == 302
    with client.session_transaction() as sess:
        assert sess["role"] == "staff"
    assert client.post("/customers/1/block").status_code == 403


def test_deleted_staff_is_logged_out_on_next_request(client):
    _login_admin(client)
    STAFF.clear()
    response = client.get("/setup")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    with client.session_transaction() as sess:
        assert "staff_id" not in sess


def _login_next(client, nxt):
    _post(client)
    r = client.post("/login", query_string={"next": nxt},
                    data=dict(username="admin", password=GOOD_PW))
    assert r.status_code == 302
    return r.headers["Location"]


def test_login_redirects_to_internal_next(client):
    # R2-04: path ภายในยังพากลับไปหน้าที่ตั้งใจไว้ได้ตามเดิม
    assert _login_next(client, "/logs?page=2").endswith("/logs?page=2")


@pytest.mark.parametrize("nxt", [
    "//evil.example/", "/\\evil.example/", "/\t/evil.example/", "/\n/evil.example/",
    "https://evil.example/", "javascript:alert(1)", "evil.example",
])
def test_login_rejects_open_redirect(client, nxt):
    # R2-04: ปลายทางที่ browser ตีความเป็นโดเมนอื่นต้องตกไปหน้า dashboard แทน
    loc = _login_next(client, nxt)
    assert "evil" not in loc and "javascript" not in loc
    assert loc in ("/", "http://localhost/")


# ---------------------------------------------------------------- R2-09: CSRF token
import re  # noqa: E402

_TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


@pytest.fixture
def csrf_client(client):
    """client เดิมแต่เปิดการตรวจ CSRF (ค่าจริงตอนใช้งาน)"""
    client.application.config["CSRF_ENABLED"] = True
    return client


def _form_token(c, path):
    m = _TOKEN_RE.search(c.get(path).get_data(as_text=True))
    assert m, f"หน้า {path} ต้องมี hidden field csrf_token"
    return m.group(1)


def _setup_and_login(c):
    _post(c, csrf_token=_form_token(c, "/setup"))
    r = c.post("/login", data=dict(username="admin", password=GOOD_PW,
                                   csrf_token=_form_token(c, "/login")))
    assert r.status_code == 302


def test_csrf_setup_without_token_rejected(csrf_client):
    r = _post(csrf_client)
    assert r.status_code == 400
    assert STAFF == [], "ไม่มี token ต้องไม่สร้างบัญชี"
    assert any("csrf_reject" in str(a) for a in AUDIT)


def test_csrf_setup_with_token_works(csrf_client):
    r = _post(csrf_client, csrf_token=_form_token(csrf_client, "/setup"))
    assert r.status_code == 302 and len(STAFF) == 1


def test_csrf_login_without_token_rejected(csrf_client):
    # กัน login CSRF: หน้าอื่นบังคับ browser พนักงานให้ login เป็นบัญชีของผู้โจมตี
    _post(csrf_client, csrf_token=_form_token(csrf_client, "/setup"))
    r = csrf_client.post("/login", data=dict(username="admin", password=GOOD_PW))
    assert r.status_code == 400
    with csrf_client.session_transaction() as sess:
        assert "staff_id" not in sess


def test_deactivated_staff_post_redirects_before_csrf_check(csrf_client):
    _setup_and_login(csrf_client)
    STAFF[0]["is_active"] = 0
    response = csrf_client.post("/setup", data={"token": TOKEN})
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]
    with csrf_client.session_transaction() as sess:
        assert "staff_id" not in sess


@pytest.mark.parametrize("bad", ["", "wrong-token"])
def test_csrf_logged_in_post_with_bad_token_rejected(csrf_client, bad):
    _setup_and_login(csrf_client)
    r = csrf_client.post("/logout", data=dict(csrf_token=bad))
    assert r.status_code == 400
    with csrf_client.session_transaction() as sess:
        assert "staff_id" in sess, "POST ที่ไม่ผ่าน CSRF ต้องไม่มีผลใด ๆ"


def test_csrf_token_rotates_on_login(csrf_client):
    # token ที่ได้ก่อน login (ผู้โจมตีอาจรู้ได้ถ้าฝัง session ไว้) ต้องใช้หลัง login ไม่ได้
    _post(csrf_client, csrf_token=_form_token(csrf_client, "/setup"))
    pre = _form_token(csrf_client, "/login")
    csrf_client.post("/login", data=dict(username="admin", password=GOOD_PW, csrf_token=pre))
    assert csrf_client.post("/logout", data=dict(csrf_token=pre)).status_code == 400
    post = _form_token(csrf_client, "/")
    assert post != pre
    assert csrf_client.post("/logout", data=dict(csrf_token=post)).status_code == 302


def test_csrf_header_accepted(csrf_client):
    _setup_and_login(csrf_client)
    tok = _form_token(csrf_client, "/")
    r = csrf_client.post("/logout", headers={"X-CSRF-Token": tok})
    assert r.status_code == 302


def test_every_admin_post_form_has_csrf_field():
    """กันลืมใส่ hidden field เวลาเพิ่มฟอร์มใหม่"""
    tpl_dir = pathlib.Path(__file__).resolve().parents[1] / "app" / "admin" / "templates"
    for tpl in tpl_dir.glob("*.html"):
        html = tpl.read_text(encoding="utf-8")
        for m in re.finditer(r'<form[^>]*method="post"[^>]*>(.*?)</form>', html, re.S | re.I):
            assert 'name="csrf_token"' in m.group(1), f"{tpl.name}: ฟอร์ม POST ไม่มี csrf_token"
