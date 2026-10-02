"""
T-Status — หน้า System Health `/status` (N5, CODING_BRIEF.md)

ตรรกะการอ่าน/คำนวณอยู่ใน `common/health.py` (แยกจาก route เพื่อทดสอบได้บน Windows โดยไม่ต้อง
มี systemd/chronyd/MariaDB จริง — ไฟล์นี้แบ่งเป็น 2 ส่วน: (1) เทสต์ตรงของฟังก์ชันใน
common/health.py ทีละตัว (2) เทสต์ชั้น route/permission ผ่าน Flask test client เหมือน
tests/test_logs_verify.py (N2) -- `/health` เดิมที่คืน JSON ต้องยังทำงานเหมือนเดิมทุกประการ
(มีเทสต์อ้างอิงอยู่แล้วที่อื่น แต่กันพลาดซ้ำอีกชั้นตรงนี้ด้วยเพราะเป็นเงื่อนไขที่ CODING_BRIEF.md
เขียนไว้ชัดเจนว่าห้ามแตะ)
"""
from __future__ import annotations

import contextlib
from collections import namedtuple
from datetime import datetime

import pytest

from common import crypto
from common.health import (
    ChronyStatus,
    _parse_chrony_line,
    build_status,
    chrony_status,
    db_status,
    latest_alert,
    service_statuses,
)

# ================================================================== ส่วนที่ 1: common/health.py ตรง ๆ


# ---------------------------------------------------------------- chrony (T13)
def test_parse_chrony_line_extracts_offset_in_ms():
    ts, ms, raw = _parse_chrony_line(
        "2026-08-26T10:00:00+07:00  0.003210000 seconds slow of NTP time"
    )
    assert ts == "2026-08-26T10:00:00+07:00"
    assert ms == pytest.approx(3.21, abs=1e-3)
    assert "slow of NTP time" in raw


def test_parse_chrony_line_unknown():
    ts, ms, raw = _parse_chrony_line("2026-08-26T10:00:00+07:00  unknown")
    assert ts == "2026-08-26T10:00:00+07:00"
    assert ms is None
    assert raw == "unknown"


def test_chrony_status_missing_file_reports_not_available(tmp_path):
    status = chrony_status(tmp_path)
    assert status.available is False
    assert status.offset_ms is None
    assert status.ok is False


def test_chrony_status_within_threshold_is_ok(tmp_path):
    (tmp_path / "time-accuracy.log").write_text(
        "2026-08-26T03:30:00+07:00  0.000500000 seconds fast of NTP time\n", encoding="utf-8"
    )
    status = chrony_status(tmp_path)
    assert status.available is True
    assert status.offset_ms == pytest.approx(0.5, abs=1e-3)
    assert status.ok is True


def test_chrony_status_exceeds_threshold_is_not_ok(tmp_path):
    # อ่านเฉพาะบรรทัดสุดท้ายเสมอ (ค่าล่าสุด) แม้มีประวัติเก่าหลายบรรทัดอยู่ก่อนแล้ว
    log_file = tmp_path / "time-accuracy.log"
    log_file.write_text(
        "2026-08-26T03:00:00+07:00  0.000100000 seconds slow of NTP time\n"
        "2026-08-26T03:30:00+07:00  0.050000000 seconds slow of NTP time\n",
        encoding="utf-8",
    )
    status = chrony_status(tmp_path)
    assert status.offset_ms == pytest.approx(50.0, abs=1e-3)
    assert status.ok is False


def test_chrony_status_unreadable_value_is_unknown(tmp_path):
    (tmp_path / "time-accuracy.log").write_text(
        "2026-08-26T03:30:00+07:00  unknown\n", encoding="utf-8"
    )
    status = chrony_status(tmp_path)
    assert status.available is True
    assert status.offset_ms is None
    assert status.ok is False


# ---------------------------------------------------------------- service ขึ้น/ลง
def test_service_statuses_uses_injected_runner():
    fake_states = {"cafe-admin": "active", "cafe-fas": "active", "cafe-logger": "failed",
                   "mariadb": "active", "nginx": "active", "opennds": "inactive"}
    result = service_statuses(runner=lambda name: fake_states[name])
    assert result == fake_states


def test_service_statuses_runner_unknown_when_systemctl_missing():
    # จำลองเครื่องที่ไม่มี systemctl เลย (เช่นเครื่อง dev บน Windows) -- ต้องไม่ throw
    result = service_statuses(names=("cafe-admin",), runner=lambda name: "unknown")
    assert result == {"cafe-admin": "unknown"}


# ---------------------------------------------------------------- alert ล่าสุดจาก N1
def test_latest_alert_missing_file_returns_none(tmp_path):
    assert latest_alert(tmp_path) is None


def test_latest_alert_returns_last_line(tmp_path):
    (tmp_path / "alert.log").write_text(
        "2026-08-25T10:00:00  WARNING  /var/log/cafe-wifi  82.0% used, 1200 MB เหลือ\n"
        "2026-08-26T03:30:00  CRITICAL  /  91.0% used, 400 MB เหลือ\n",
        encoding="utf-8",
    )
    assert latest_alert(tmp_path) == "2026-08-26T03:30:00  CRITICAL  /  91.0% used, 400 MB เหลือ"


# ---------------------------------------------------------------- ฐานข้อมูล
def test_db_status_success(monkeypatch):
    import common.db as db

    row = dict(active_sessions=3, conn_log_today=120, dns_log_today=340,
              last_sealed_at=datetime(2026, 8, 26, 3, 30, 5))
    monkeypatch.setattr(db, "query_one", lambda sql, args=(): row)

    result = db_status()
    assert result["error"] is None
    assert result["active_sessions"] == 3
    assert result["log_rows_today"] == 120 + 340
    assert result["last_sealed_at"] == row["last_sealed_at"]


def test_db_status_reports_error_instead_of_crashing(monkeypatch):
    import common.db as db

    def _boom(sql, args=()):
        raise RuntimeError("MariaDB ต่อไม่ได้ (จำลอง)")

    monkeypatch.setattr(db, "query_one", _boom)

    result = db_status()
    assert result["error"] == "MariaDB ต่อไม่ได้ (จำลอง)"
    assert result["active_sessions"] is None
    assert result["log_rows_today"] is None


# ---------------------------------------------------------------- ประกอบทั้งหมด (build_status)
def test_build_status_composes_all_sections(tmp_path, monkeypatch):
    import common.db as db

    (tmp_path / "time-accuracy.log").write_text(
        "2026-08-26T03:30:00+07:00  0.000500000 seconds fast of NTP time\n", encoding="utf-8"
    )
    (tmp_path / "alert.log").write_text("2026-08-26T03:30:00  WARNING  x\n", encoding="utf-8")

    row = dict(active_sessions=1, conn_log_today=10, dns_log_today=5, last_sealed_at=None)
    monkeypatch.setattr(db, "query_one", lambda sql, args=(): row)

    _Usage = namedtuple("_Usage", "total used free")

    def fake_disk_usage(path):
        return _Usage(total=100, used=50, free=50)  # 50% ทุก path -- อยู่ในเกณฑ์ 'ok' (< 80%)

    data = build_status(
        str(tmp_path),
        disk_usage_fn=fake_disk_usage,
        service_runner=lambda name: "active",
    )

    assert isinstance(data["generated_at"], datetime)
    assert len(data["disks"]) == 2  # LOG_DIR + "/"
    assert all(d.level == "ok" for d in data["disks"])
    assert isinstance(data["chrony"], ChronyStatus) and data["chrony"].ok
    assert data["services"] == {name: "active" for name in
                                ("cafe-admin", "cafe-fas", "cafe-logger", "mariadb", "nginx", "opennds")}
    assert data["db"]["log_rows_today"] == 15
    assert data["latest_alert"] == "2026-08-26T03:30:00  WARNING  x"


# ================================================================== ส่วนที่ 2: route /status ผ่าน Flask


GOOD_PW = "CafeWifi2026Secure"
STAFF = [{"id": 1, "username": "staff1", "password_hash": crypto.hash_password(GOOD_PW),
         "display_name": "Staff", "role": "staff", "is_active": 1}]


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
        elif s.startswith("select (select count(*) from portal_session"):
            self._rows = [{"active_sessions": 2, "conn_log_today": 7, "dns_log_today": 9,
                          "last_sealed_at": datetime(2026, 8, 26, 3, 30, 5)}]
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    (tmp_path / "time-accuracy.log").write_text(
        "2026-08-26T03:30:00+07:00  0.000500000 seconds fast of NTP time\n", encoding="utf-8"
    )
    (tmp_path / "alert.log").write_text(
        "2026-08-26T03:30:00  WARNING  /var/log/cafe-wifi  82.0% used, 900 MB เหลือ\n", encoding="utf-8"
    )

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
    return admin_app.app.test_client()


def _login(client):
    with client.session_transaction() as sess:
        sess["staff_id"] = STAFF[0]["id"]
        sess["username"] = STAFF[0]["username"]
        sess["role"] = STAFF[0]["role"]


def test_status_requires_login(client):
    r = client.get("/status")
    assert r.status_code == 302
    assert "/login" in r.headers["Location"]


def test_status_page_renders_all_sections(client, monkeypatch):
    # ไม่มี systemctl จริงบนเครื่องทดสอบนี้ (Windows) -- ต้องไม่ 500 แต่โชว์ "ไม่ทราบ" แทน
    _login(client)
    r = client.get("/status")
    assert r.status_code == 200
    html = r.get_data(as_text=True)

    assert "พื้นที่ดิสก์" in html
    assert "ความแม่นยำของนาฬิกา" in html
    assert "0.500" in html  # offset ms ที่ parse ได้จากไฟล์ปลอม
    assert "cafe-admin" in html and "mariadb" in html
    assert "<b>2</b>" in html  # session ที่ active
    assert "<b>16</b>" in html  # log rows วันนี้ = conn(7) + dns(9)
    assert "82.0% used" in html  # alert ล่าสุดจาก N1


def test_status_link_visible_in_nav_when_logged_in(client):
    _login(client)
    html = client.get("/status").get_data(as_text=True)
    assert "สถานะระบบ" in html


def test_health_json_endpoint_unchanged(client):
    """CODING_BRIEF.md N5: '/health เดิมที่คืน JSON ไว้ด้วย (มีเทสต์อ้างอิงอยู่)' -- กันพลาดซ้ำ"""
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"
