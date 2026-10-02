"""
T-LogsVerify — /logs/verify (N2, CODING_BRIEF.md)

ต่อปุ่ม "ตรวจสอบความถูกต้องของ log" เข้ากับ logger/integrity.py::verify_chain() ที่มีอยู่แล้ว
และมีเทสต์ของตัวเองผ่านแล้ว (T12) -- ไฟล์นี้เทสต์แค่ชั้น route/permission/audit ไม่เทสต์
ตรรกะ hash chain ซ้ำ (นั่นเป็นหน้าที่ของ tests/test_logger.py)
"""
import contextlib

import pytest

from common import crypto
from logger.integrity import sha256_file

GOOD_PW = "CafeWifi2026Secure"

STAFF = [
    {"id": 1, "username": "admin1", "password_hash": crypto.hash_password(GOOD_PW),
     "display_name": "Admin", "role": "admin", "is_active": 1},
    {"id": 2, "username": "staff1", "password_hash": crypto.hash_password(GOOD_PW),
     "display_name": "Staff", "role": "staff", "is_active": 1},
]
MANIFEST: list[dict] = []
AUDIT: list[tuple] = []


def _reset():
    MANIFEST.clear()
    AUDIT.clear()


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
        elif s.startswith("select filename, sha256, prev_sha256, size_bytes, deletion_state, sealed_at from log_manifest order by id asc"):
            self._rows = list(MANIFEST)
        elif s.startswith("select (select count(*) from voucher"):  # dashboard stats
            self._rows = [{"active_vouchers": 0, "customers": 0, "issued_today": 0, "online_now": 0}]
        elif s.startswith("select v.id, v.username, v.issued_at"):  # dashboard recent vouchers
            self._rows = []
        elif s.startswith("insert into audit_log"):
            AUDIT.append(args)
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
def client(tmp_path, monkeypatch):
    _reset()
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    monkeypatch.setenv("LOG_DIR", str(tmp_path))

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
    importlib.reload(admin_app)  # ให้ LOG_DIR (module-level constant) อ่านค่า env ใหม่
    admin_app.app.config.update(SESSION_COOKIE_SECURE=False, TESTING=True,
                                CSRF_ENABLED=False)  # R2-09: CSRF ทดสอบแยกท้าย test_setup_flow.py
    c = admin_app.app.test_client()
    c.archive_dir = archive_dir
    c.module = admin_app
    return c


def _login_as(client, role):
    staff = next(s for s in STAFF if s["role"] == role)
    with client.session_transaction() as sess:
        sess["staff_id"] = staff["id"]
        sess["username"] = staff["username"]
        sess["role"] = staff["role"]


def _seal_one_file(archive_dir, filename: str, content: bytes) -> None:
    """จำลองไฟล์ log ที่ผนึกไว้แล้ว (เหมือนที่ seal_directory() ทำจริง) โดยเขียนแถว manifest
    ตรง ๆ ในหน่วยความจำ -- ไม่ต้องเรียก seal_directory() จริงเพราะไฟล์นี้เทสต์แค่ verify_chain()"""
    path = archive_dir / filename
    path.write_bytes(content)
    digest = sha256_file(path)
    MANIFEST.append(dict(filename=filename, sha256=digest, prev_sha256=None, size_bytes=len(content)))


# ---------------------------------------------------------------- กรณีที่ 1: chain สมบูรณ์
def test_verify_shows_no_issues_when_chain_is_intact(client):
    _login_as(client, "admin")
    _seal_one_file(client.archive_dir, "conn_log.log-2026-08-25", b"day 1 content, untouched")

    r = client.post("/logs/verify")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "ผ่านทั้งหมด" in html

    assert len(AUDIT) == 1, "ต้องลง audit_log ทุกครั้งที่กด ไม่ว่าผลจะเป็นอย่างไร"
    assert AUDIT[0][1] == "verify_integrity"
    assert "สมบูรณ์" in AUDIT[0][4]


# ---------------------------------------------------------------- กรณีที่ 2: chain ถูกแก้
def test_verify_detects_a_file_tampered_after_sealing(client):
    """สาธิตจริงตามที่ CODING_BRIEF.md บอก: แก้ไฟล์ log ที่ผนึกแล้ว 1 ตัวอักษร -> ต้องจับได้"""
    _login_as(client, "admin")
    path_name = "dns_log.log-2026-08-25"
    _seal_one_file(client.archive_dir, path_name, b"original content, sealed")

    # แก้ไฟล์ 1 ตัวอักษรหลังผนึกไปแล้ว (จำลองการปลอมแปลงหลักฐาน)
    tampered = client.archive_dir / path_name
    tampered.write_bytes(b"0riginal content, sealed")

    r = client.post("/logs/verify")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "พบ 1 ปัญหา" in html
    assert path_name in html
    assert "ถูกแก้ไข" in html  # แปลจาก kind='hash_mismatch' ในเทมเพลต

    assert len(AUDIT) == 1
    assert "พบ 1 ปัญหา" in AUDIT[0][4]


def test_verify_detects_missing_file(client):
    _login_as(client, "admin")
    _seal_one_file(client.archive_dir, "portal-access.log-2026-08-20", b"content")
    (client.archive_dir / "portal-access.log-2026-08-20").unlink()  # ลบไฟล์ทิ้งนอกกระบวนการปกติ

    r = client.post("/logs/verify")
    html = r.get_data(as_text=True)
    assert "พบ 1 ปัญหา" in html
    assert "ไฟล์หายไป" in html


# ---------------------------------------------------------------- สิทธิ์: staff ธรรมดากดไม่ได้
def test_staff_role_gets_403_not_admin(client):
    _login_as(client, "staff")
    r = client.post("/logs/verify")
    assert r.status_code == 403
    assert len(AUDIT) == 0, "ถูกบล็อกก่อนถึงชั้น audit -- ต้องไม่มีแถวเกิดขึ้น"


def test_not_logged_in_redirects_to_login(client):
    r = client.post("/logs/verify")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_dashboard_shows_button_for_admin_and_hint_for_staff(client):
    _login_as(client, "admin")
    html = client.get("/").get_data(as_text=True)
    assert "ตรวจสอบความถูกต้องของ log" in html

    _login_as(client, "staff")
    html = client.get("/").get_data(as_text=True)
    assert "เฉพาะ admin" in html
