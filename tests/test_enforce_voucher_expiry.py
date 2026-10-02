"""T-Enforce — tools/enforce_voucher_expiry.py (แก้บั๊ก H3/M1/M2 พร้อมกัน)"""
import contextlib
from datetime import datetime, timedelta

import pytest

from tools import enforce_voucher_expiry as ev


def test_expire_stale_vouchers_calls_correct_sql():
    calls = []

    def fake_exec(sql, args=()):
        calls.append(" ".join(sql.split()))
        return 3

    n = ev.expire_stale_vouchers(fake_exec)
    assert n == 3
    assert "UPDATE voucher SET status='expired'" in calls[0]
    assert "status='active'" in calls[0]
    assert "valid_until < NOW()" in calls[0]


def test_mark_used_up_vouchers_only_touches_vouchers_with_quota():
    calls = []

    def fake_exec(sql, args=()):
        calls.append(" ".join(sql.split()))
        return 1

    ev.mark_used_up_vouchers(fake_exec)
    assert "quota_mb IS NOT NULL" in calls[0]
    assert "used_mb >= quota_mb" in calls[0]


def test_sum_session_traffic_bytes_sums_conn_log():
    def fake_query_one(sql, args=()):
        assert args[0] == "AA:BB:CC:DD:EE:01"
        return {"bo": 12345, "bi": 67890}

    bo, bi = ev.sum_session_traffic_bytes(fake_query_one, "AA:BB:CC:DD:EE:01", datetime.now())
    assert (bo, bi) == (12345, 67890)


def test_sum_session_traffic_bytes_handles_no_rows():
    bo, bi = ev.sum_session_traffic_bytes(lambda *a: None, "AA:BB:CC:DD:EE:01", datetime.now())
    assert (bo, bi) == (0, 0)


def test_close_session_writes_bytes_and_bumps_used_mb():
    calls = []

    def fake_exec(sql, args=()):
        calls.append((" ".join(sql.split()), args))
        return 1

    ev.close_session(fake_exec, session_id=42, voucher_id=7,
                     bytes_out=3_000_000, bytes_in=2_000_000)
    assert len(calls) == 2
    assert calls[0][0].startswith("UPDATE portal_session SET state='closed', ended_at=NOW()")
    assert calls[0][1] == ("voucher_expired", 3_000_000, 2_000_000, 42)  # default voucher_status="expired"
    assert calls[1][0].startswith("UPDATE voucher SET used_mb = used_mb +")
    assert calls[1][1] == (5, 7)  # (3MB+2MB) รวม 5MB


def test_close_session_maps_terminate_cause_from_voucher_status():
    """
    บั๊กเดิม (พบตอนตรวจทานรอบ 2): terminate_cause เคยตั้งเป็น 'voucher_expired' ตายตัว
    แม้ voucher จะถูกพนักงานยกเลิก (revoked) หรือใช้ครบโควต้า (used_up) -- ระบุสาเหตุผิด
    ในหลักฐานตาม ม.26 ต้องแมปจาก voucher.status จริง
    """
    calls = []

    def fake_exec(sql, args=()):
        calls.append((" ".join(sql.split()), args))
        return 1

    ev.close_session(fake_exec, session_id=1, voucher_id=1,
                     bytes_out=0, bytes_in=0, voucher_status="revoked")
    assert calls[0][1][0] == "voucher_revoked"

    calls.clear()
    ev.close_session(fake_exec, session_id=1, voucher_id=1,
                     bytes_out=0, bytes_in=0, voucher_status="used_up")
    assert calls[0][1][0] == "quota_exceeded"


def _sessions_to_close_on_sqlite(customers, vouchers, sessions):
    """รันคิวรีจริงของ find_sessions_to_close() บน sqlite (ใช้แค่ JOIN/CASE มาตรฐาน) เพื่อตรวจ
    ความหมายของ WHERE ไม่ใช่แค่ว่ามีคำไหนอยู่ในสตริง"""
    import sqlite3
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE customer (id INTEGER PRIMARY KEY, is_blocked BOOLEAN NOT NULL);
        CREATE TABLE voucher (id INTEGER PRIMARY KEY, customer_id INTEGER, status TEXT);
        CREATE TABLE portal_session (id INTEGER PRIMARY KEY, mac TEXT, voucher_id INTEGER,
                                     started_at TEXT, authenticated_at TEXT,
                                     state TEXT, ended_at TEXT);
    """)
    db.executemany("INSERT INTO customer VALUES (?,?)", customers)
    db.executemany("INSERT INTO voucher VALUES (?,?,?)", vouchers)
    db.executemany("INSERT INTO portal_session VALUES (?,?,?,?,?,?,?)",
                   [(sid, mac, voucher_id, started_at, started_at, state, ended_at)
                    for sid, mac, voucher_id, started_at, state, ended_at in sessions])

    def q(sql, args=()):
        return [dict(r) for r in db.execute(sql, args).fetchall()]

    return {r["id"]: r["voucher_status"] for r in ev.find_sessions_to_close(q)}


def test_find_sessions_to_close_includes_blocked_customer_with_active_voucher():
    """
    R2-05: ระงับลูกค้าแล้ว เครื่องที่ออนไลน์อยู่ต้องถูกตัดรอบถัดไป ไม่ใช่ใช้ต่อได้จนรหัสหมดอายุ
    ส่วนลูกค้าปกติที่ voucher ยัง active ต้องไม่โดน
    """
    got = _sessions_to_close_on_sqlite(
        customers=[(1, True), (2, False)],
        vouchers=[(10, 1, "active"), (20, 2, "active"), (21, 2, "expired")],
        sessions=[
            (100, "AA", 10, "t", "authenticated", None),   # ถูกระงับ -> ตัด
            (101, "BB", 20, "t", "authenticated", None),   # ปกติ -> ไม่ตัด
            (102, "CC", 21, "t", "authenticated", None),   # หมดอายุ -> ตัดตามเดิม
            (103, "DD", 10, "t", "closed", "t"),           # ปิดไปแล้ว -> ไม่แตะ
            (104, "EE", 10, "t", "pending", None),         # ยังไม่ auth -> ไม่แตะ
        ])
    assert got == {100: "blocked", 102: "expired"}


def test_find_sessions_to_close_prefers_voucher_status_when_both_apply():
    got = _sessions_to_close_on_sqlite(
        customers=[(1, True)],
        vouchers=[(10, 1, "revoked")],
        sessions=[(100, "AA", 10, "t", "authenticated", None)])
    assert got == {100: "revoked"}


def test_close_session_records_customer_blocked_cause():
    calls = []

    def fake_exec(sql, args=()):
        calls.append(args)
        return 1

    ev.close_session(fake_exec, session_id=1, voucher_id=1,
                     bytes_out=0, bytes_in=0, voucher_status="blocked")
    assert calls[0][0] == "customer_blocked"


def test_close_session_skips_voucher_update_when_zero_bytes():
    calls = []

    def fake_exec(sql, args=()):
        calls.append(sql)
        return 1

    ev.close_session(fake_exec, session_id=1, voucher_id=1, bytes_out=0, bytes_in=0)
    assert len(calls) == 1, "ไม่ต้องยิง UPDATE voucher ถ้าไม่มีทราฟฟิกเพิ่ม (delta=0)"


def test_close_session_reauth_bumps_old_voucher_once():
    calls = []
    ended = datetime(2026, 9, 30, 12, 0)
    updated = [1, 0]

    def fake_exec(sql, args=()):
        calls.append((" ".join(sql.split()), args))
        if sql.startswith("UPDATE portal_session"):
            return updated.pop(0)
        return 1

    results = [ev.close_session(fake_exec, session_id=42, voucher_id=7,
                                bytes_out=3_000_000, bytes_in=2_000_000,
                                voucher_status="reauth", ended_at=ended)
               for _ in range(2)]

    closes = [(sql, args) for sql, args in calls if sql.startswith("UPDATE portal_session")]
    bumps = [(sql, args) for sql, args in calls if sql.startswith("UPDATE voucher SET used_mb")]
    assert len(closes) == 2
    assert closes[0][1] == (ended, "reauth", 3_000_000, 2_000_000, 42)
    assert "state='authenticated' AND ended_at IS NULL" in closes[0][0]
    assert len(bumps) == 1 and bumps[0][1] == (5, 7)
    assert results == [True, False]


def test_deauth_mac_returns_false_when_ndsctl_missing(monkeypatch):
    monkeypatch.setattr(ev.shutil, "which", lambda _: None)
    assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is False


def test_deauth_mac_returns_true_on_success(monkeypatch):
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")

    class FakeResult:
        returncode = 0
        stderr = b""

    monkeypatch.setattr(ev.subprocess, "run", lambda *a, **kw: FakeResult())
    assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is True


def test_deauth_mac_returns_false_on_nonzero_exit(monkeypatch):
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")

    class FakeResult:
        returncode = 1
        stderr = b"no such client"

    monkeypatch.setattr(ev.subprocess, "run", lambda *a, **kw: FakeResult())
    assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is False


# ---------------------------------------------------------------- run() end-to-end
class _FakeCursor:
    def __init__(self, state):
        self.state = state
        self.rowcount = 0
        self._result = None

    def execute(self, sql, args=()):
        s = " ".join(sql.split())
        if s.startswith("SELECT v.id AS voucher_id, v.quota_mb"):
            self._result = self.state.get("quota_rows", [])
        elif s.startswith("UPDATE voucher SET status='used_up' WHERE id="):
            self.rowcount = 1
        elif s.startswith("UPDATE voucher SET status='expired'"):
            self.rowcount = self.state["expire_count"]
        elif s.startswith("SELECT ps.id, ps.mac"):
            self._result = self.state["to_close"]
        elif s.startswith("SELECT COALESCE(SUM(bytes_out)"):
            self._result = {"bo": 1_000_000, "bi": 1_000_000}
        elif s.startswith("UPDATE portal_session SET state='closed'"):
            self.state["closed"].append(args)
            self.rowcount = 1
        elif s.startswith("UPDATE voucher SET used_mb"):
            self.state["used_mb_bumped"].append(args)
            self.rowcount = 1
        elif s.startswith("UPDATE voucher SET status='used_up'"):
            self.rowcount = self.state["used_up_count"]
        else:
            raise AssertionError(f"ไม่รู้จัก SQL: {s[:80]}")

    def fetchone(self):
        return self._result

    def fetchall(self):
        return self._result

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_run_end_to_end_closes_expired_sessions_and_skips_deauth_when_disabled(monkeypatch):
    state = dict(
        expire_count=2,
        to_close=[{"id": 1, "mac": "AA:BB:CC:DD:EE:01", "voucher_id": 10,
                  "started_at": datetime.now() - timedelta(hours=1),
                  "authenticated_at": datetime.now() - timedelta(hours=1),
                  "voucher_status": "expired"}],
        closed=[], used_mb_bumped=[], used_up_count=0,
    )

    class FakeConn:
        def cursor(self):
            return _FakeCursor(state)

    import common.db as db
    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(FakeConn()))

    summary = ev.run(deauth=False)
    assert summary.expired_vouchers == 2
    assert summary.sessions_closed == 1
    assert summary.deauth_ok == 0 and summary.deauth_failed == 0, \
        "deauth=False ต้องไม่เรียก ndsctl เลย"
    assert len(state["closed"]) == 1
    assert len(state["used_mb_bumped"]) == 1


# ============== N22: ndsctl ต้องรันด้วยสิทธิ์ root ไม่งั้นเพิกถอน voucher แล้วตัดคนไม่ออกจริง
def _fake_run(captured, returncode=0):
    class FakeResult:
        pass
    FakeResult.returncode = returncode
    FakeResult.stderr = b""

    def run(cmd, **kw):
        captured.append(cmd)
        return FakeResult()
    return run


def test_deauth_mac_runs_ndsctl_directly_when_already_root(monkeypatch):
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)
    captured = []
    monkeypatch.setattr(ev.subprocess, "run", _fake_run(captured))

    assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is True
    assert captured == [["ndsctl", "deauth", "aa:bb:cc:dd:ee:01"]],         "openNDS เทียบ MAC แบบ case-sensitive และใช้ตัวพิมพ์เล็กเสมอ"


def test_deauth_mac_adds_sudo_when_not_root(monkeypatch):
    """รันเป็น cafewifi ตรง ๆ จะอ่าน /etc/config/opennds ไม่ได้และต่อ /tmp/ndsctl.sock ไม่ได้
    (ยืนยันบน Pi จริง 2026-09-16: exit 3 ทุกครั้ง) จึงต้องยกสิทธิ์ก่อนเสมอ"""
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: False)
    captured = []
    monkeypatch.setattr(ev.subprocess, "run", _fake_run(captured))

    assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is True
    assert captured == [["sudo", "-n", "ndsctl", "deauth", "aa:bb:cc:dd:ee:01"]]


def test_deauth_failure_is_logged_as_error_not_warning(monkeypatch, caplog):
    """deauth ล้มเหลว = ลูกค้าที่ถูกตัดสิทธิ์ยังใช้เน็ตได้จริง ไม่ใช่แค่ตัวเลขใน DB เพี้ยน
    ระดับ log จึงต้องเป็น ERROR ให้เห็นชัด (ของเดิมเป็น warning เลยถูกมองข้าม)"""
    import logging
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)
    monkeypatch.setattr(ev.subprocess, "run", _fake_run([], returncode=3))

    with caplog.at_level(logging.DEBUG):
        assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is False

    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, "ต้อง log ระดับ ERROR อย่างน้อยหนึ่งรายการ"
    assert "ยังออกเน็ตได้อยู่" in errors[0].getMessage()


def _run_with_fake_db(monkeypatch, deauth_succeeds: bool):
    state = dict(
        expire_count=0,
        to_close=[{"id": 1, "mac": "AA:BB:CC:DD:EE:01", "voucher_id": 10,
                  "started_at": datetime.now() - timedelta(hours=1),
                  "authenticated_at": datetime.now() - timedelta(hours=1),
                  "voucher_status": "revoked"}],
        closed=[], used_mb_bumped=[], used_up_count=0,
    )

    class FakeConn:
        def cursor(self):
            return _FakeCursor(state)

    import common.db as db
    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(FakeConn()))
    monkeypatch.setattr(ev, "deauth_mac", lambda mac: deauth_succeeds)
    return ev.run(deauth=True), state


def test_run_keeps_session_open_when_deauth_fails_so_next_run_retries(monkeypatch):
    """ถ้าตัดที่ openNDS ไม่สำเร็จ ลูกค้ายังต่อเน็ตอยู่จริง ห้ามปิดแถวในฐานข้อมูล ไม่งั้น
    คิวรีรอบถัดไป (หาเฉพาะ ended_at IS NULL) จะมองไม่เห็นแถวนี้อีกเลย = ใช้เน็ตต่อได้ตลอดไป
    โดยไม่มีการลองตัดซ้ำ -- พบจากการทดสอบบน Pi จริง 2026-09-16"""
    summary, state = _run_with_fake_db(monkeypatch, deauth_succeeds=False)

    assert summary.deauth_failed == 1
    assert summary.sessions_closed == 0, "นับเฉพาะที่ปิดจริง ไม่ใช่จำนวนที่ตั้งใจจะปิด"
    assert state["closed"] == [], "ห้ามปิด session ที่ยังตัดไม่ออกจริง"


def test_run_closes_session_when_deauth_succeeds(monkeypatch):
    summary, state = _run_with_fake_db(monkeypatch, deauth_succeeds=True)

    assert summary.deauth_ok == 1
    assert summary.sessions_closed == 1
    assert len(state["closed"]) == 1


# ============== N28: ลูกค้าไม่อยู่ใน openNDS แล้ว (เดินออกไป / idle timeout) ต้องนับว่าตัดสำเร็จ
def test_deauth_counts_client_already_gone_as_success(monkeypatch):
    """ยืนยันบน Pi จริง: `ndsctl deauth <mac>` ของเครื่องที่ไม่อยู่แล้วได้ stdout
    "Client ... not found." exit 1 -- ถ้านับเป็นล้มเหลว N22 จะเว้น session ไว้ตลอดกาล"""
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)

    class FakeResult:
        returncode = 1
        stdout = b"Client aa:bb:cc:dd:ee:01 not found."
        stderr = b""

    monkeypatch.setattr(ev.subprocess, "run", lambda *a, **kw: FakeResult())
    assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is True


def test_deauth_other_failures_still_count_as_failure(monkeypatch):
    """ต้องไม่กลืนความล้มเหลวจริง เช่น permission denied แบบที่เจอใน N22"""
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)

    class FakeResult:
        returncode = 3
        stdout = b""
        stderr = b"cat: /etc/config/opennds: Permission denied"

    monkeypatch.setattr(ev.subprocess, "run", lambda *a, **kw: FakeResult())
    assert ev.deauth_mac("AA:BB:CC:DD:EE:01") is False


# =================== N29: โควตาต้องถูกบังคับใช้ระหว่างที่ลูกค้ายังออนไลน์ ไม่ใช่รอตอนปิด session
def _quota_rows(*rows):
    def query_all(sql, args=()):
        assert "quota_mb IS NOT NULL" in sql
        assert "ps.state = 'authenticated'" in sql
        return [{**r, "authenticated_at": r.get("authenticated_at") or r["started_at"]}
                for r in rows]
    return query_all


def _traffic(bytes_out, bytes_in):
    return lambda sql, args=(): {"bo": bytes_out, "bi": bytes_in}


def test_quota_counts_traffic_of_sessions_that_are_still_open():
    """เดิม used_mb อัปเดตตอนปิด session เท่านั้น และ session ปิดเมื่อ voucher ไม่ active แล้ว
    = วงกลม โควตาจึงไม่มีวันถูกบังคับใช้ระหว่างลูกค้าใช้งานอยู่ (พบบน Pi จริง 2026-09-20)"""
    rows = _quota_rows({"voucher_id": 3, "quota_mb": 500, "used_mb": 0,
                        "mac": "AA:BB:CC:DD:EE:01", "started_at": datetime.now()})
    hits = ev.find_quota_exceeded_vouchers(rows, _traffic(300 * ev.BYTES_PER_MB, 250 * ev.BYTES_PER_MB))

    assert len(hits) == 1
    assert hits[0]["voucher_id"] == 3 and hits[0]["total_mb"] == 550


def test_quota_not_exceeded_yet_is_left_alone():
    rows = _quota_rows({"voucher_id": 3, "quota_mb": 500, "used_mb": 0,
                        "mac": "AA:BB:CC:DD:EE:01", "started_at": datetime.now()})
    assert ev.find_quota_exceeded_vouchers(rows, _traffic(100 * ev.BYTES_PER_MB, 10 * ev.BYTES_PER_MB)) == []


def test_quota_sums_every_device_of_the_same_voucher():
    """โควตาผูกกับ voucher ไม่ใช่ผูกกับเครื่อง -- 2 เครื่องเครื่องละ 300 MB = เกิน 500 MB"""
    now = datetime.now()
    rows = _quota_rows(
        {"voucher_id": 3, "quota_mb": 500, "used_mb": 0, "mac": "AA:BB:CC:DD:EE:01", "started_at": now},
        {"voucher_id": 3, "quota_mb": 500, "used_mb": 0, "mac": "AA:BB:CC:DD:EE:02", "started_at": now},
    )
    hits = ev.find_quota_exceeded_vouchers(rows, _traffic(300 * ev.BYTES_PER_MB, 0))

    assert len(hits) == 1 and hits[0]["total_mb"] == 600


def test_quota_adds_usage_recorded_from_previous_sessions():
    rows = _quota_rows({"voucher_id": 3, "quota_mb": 500, "used_mb": 480,
                        "mac": "AA:BB:CC:DD:EE:01", "started_at": datetime.now()})
    hits = ev.find_quota_exceeded_vouchers(rows, _traffic(20 * ev.BYTES_PER_MB, 0))

    assert len(hits) == 1 and hits[0]["total_mb"] == 500


def test_quota_ignores_pending_session_rows():
    import sqlite3

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE voucher (id INTEGER, quota_mb INTEGER, used_mb INTEGER, status TEXT);
        CREATE TABLE portal_session (voucher_id INTEGER, mac TEXT, started_at TEXT,
                                     authenticated_at TEXT, state TEXT, ended_at TEXT);
    """)
    db.execute("INSERT INTO voucher VALUES (3, 500, 0, 'active')")
    db.executemany("INSERT INTO portal_session VALUES (3, ?, ?, ?, ?, NULL)", [
        ("AA", "2026-09-30 12:00:00", "2026-09-30 12:01:00", "authenticated"),
        ("BB", "2026-09-30 12:02:00", None, "pending"),
    ])

    def query_all(sql, args=()):
        return [dict(row) for row in db.execute(sql, args).fetchall()]

    queried_macs = []

    def query_one(sql, args=()):
        queried_macs.append(args[0])
        return {"bo": 100 * ev.BYTES_PER_MB, "bi": 0}

    assert ev.find_quota_exceeded_vouchers(query_all, query_one) == []
    assert queried_macs == ["AA"]
    db.close()


def test_mark_quota_exceeded_only_touches_active_vouchers():
    calls = []
    ev.mark_quota_exceeded(lambda sql, args=(): calls.append((sql, args)) or 1,
                          [{"voucher_id": 3, "total_mb": 550, "quota_mb": 500}])

    assert len(calls) == 1
    sql, args = calls[0]
    assert "status='used_up'" in " ".join(sql.split())
    assert "status='active'" in " ".join(sql.split()), "กันไม่ให้ทับ voucher ที่ถูกยกเลิก/หมดอายุไปแล้ว"
    assert args == (3,)


# =================== N30: ปิด session ที่ openNDS ไม่มีเครื่องนั้นแล้ว (session ผี + ลูกค้าเดินออก)
def _json_run(payload, returncode=0):
    class R:
        pass
    R.returncode = returncode
    R.stdout = payload.encode("utf-8")
    R.stderr = b""
    return lambda *a, **kw: R()


def test_authenticated_macs_returns_only_authenticated(monkeypatch):
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)
    monkeypatch.setattr(ev.subprocess, "run", _json_run(
        '{"clients":{"aa:bb:cc:dd:ee:01":{"state":"Authenticated"},'
        '"aa:bb:cc:dd:ee:02":{"state":"Preauthenticated"}}}'))

    assert ev.authenticated_macs() == {"AA:BB:CC:DD:EE:01"}


def test_authenticated_macs_returns_none_when_ndsctl_fails(monkeypatch):
    """อ่านไม่ได้ = ไม่รู้ความจริง ต้องไม่ใช่ 'ไม่มีใครออนไลน์' ไม่งั้นจะไปปิด session ของลูกค้าที่
    กำลังใช้งานอยู่ทั้งร้านตอน openNDS ล่มชั่วคราว"""
    monkeypatch.setattr(ev.shutil, "which", lambda _: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)
    monkeypatch.setattr(ev.subprocess, "run", _json_run("", returncode=1))
    assert ev.authenticated_macs() is None

    monkeypatch.setattr(ev.subprocess, "run", _json_run("ไม่ใช่ json"))
    assert ev.authenticated_macs() is None


def test_authenticated_macs_returns_none_without_ndsctl(monkeypatch):
    monkeypatch.setattr(ev.shutil, "which", lambda _: None)
    assert ev.authenticated_macs() is None


def test_find_sessions_gone_picks_only_macs_not_in_opennds():
    rows = [{"id": 1, "mac": "AA:BB:CC:DD:EE:01", "voucher_id": 3, "started_at": datetime.now()},
            {"id": 2, "mac": "AA:BB:CC:DD:EE:02", "voucher_id": 3, "started_at": datetime.now()}]
    seen = []

    def query_all(sql, args=()):
        seen.append((sql, args))
        return rows

    gone = ev.find_sessions_gone(query_all, {"AA:BB:CC:DD:EE:01"})

    assert [g["id"] for g in gone] == [2]
    assert "ended_at IS NULL" in seen[0][0]
    assert seen[0][1] == (ev.GONE_GRACE_SECONDS,), "ต้องเว้นช่วงผ่อนผันให้คนที่เพิ่งกด login"


def test_find_sessions_gone_is_case_insensitive():
    rows = [{"id": 1, "mac": "AA:BB:CC:DD:EE:01", "voucher_id": 3, "started_at": datetime.now()}]
    assert ev.find_sessions_gone(lambda sql, args=(): rows, {"aa:bb:cc:dd:ee:01".upper()}) == []


def test_ndsctl_busy_is_retried_until_success(monkeypatch):
    """openNDS ตอบ busy (exit 4) เมื่อมี ndsctl อีกตัวถืออยู่ (cafe-reconcile ทุก 5 วิ) -- ต้องลองใหม่
    ไม่ใช่ปล่อยให้ลูกค้าที่ถูกยกเลิกใช้เน็ตต่อ (พบบน Pi จริง 2026-10-02)"""
    codes = iter([4, 4, 0])
    calls = []

    class R:
        def __init__(self, rc):
            self.returncode, self.stdout, self.stderr = rc, b"", b""

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return R(next(codes))

    monkeypatch.setattr(ev.subprocess, "run", fake_run)
    monkeypatch.setattr(ev.time, "sleep", lambda s: None)
    monkeypatch.setattr(ev.shutil, "which", lambda b: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)
    assert ev.deauth_mac("AA:BB:CC:DD:EE:FF") is True
    assert len(calls) == 3


def test_ndsctl_busy_forever_gives_up(monkeypatch):
    class R:
        returncode, stdout, stderr = 4, b"", b"ndsctl thread is busy"

    monkeypatch.setattr(ev.subprocess, "run", lambda cmd, **kw: R())
    monkeypatch.setattr(ev.time, "sleep", lambda s: None)
    monkeypatch.setattr(ev.shutil, "which", lambda b: "/usr/bin/ndsctl")
    monkeypatch.setattr(ev, "_running_as_root", lambda: True)
    assert ev.deauth_mac("AA:BB:CC:DD:EE:FF") is False
    assert ev.authenticated_macs() is None
