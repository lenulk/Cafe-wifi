"""common/ratelimit.py -- ตัวนับการเดารหัสเก็บในฐานข้อมูล (รีสตาร์ทแล้วไม่หาย) + ถอยไปหน่วยความจำเมื่อ DB ล่ม"""
from datetime import datetime, timedelta

import pytest

from common import ratelimit


class FakeDB:
    def __init__(self):
        self.rows = []      # (bucket, ts)
        self.down = False

    def _check(self):
        if self.down:
            raise ConnectionError("db down")

    def query_one(self, sql, args=()):
        self._check()
        bucket, window = args
        cutoff = datetime.now() - timedelta(seconds=window)
        return {"n": sum(1 for b, t in self.rows if b == bucket and t > cutoff)}

    def execute(self, sql, args=()):
        self._check()
        if sql.startswith("INSERT INTO rate_attempt"):
            self.rows.append((args[0], datetime.now()))
            return 1
        if sql.startswith("DELETE FROM rate_attempt WHERE bucket"):
            cutoff = datetime.now() - timedelta(seconds=args[1])
            before = len(self.rows)
            self.rows = [(b, t) for b, t in self.rows if not (b == args[0] and t < cutoff)]
            return before - len(self.rows)
        raise AssertionError(sql)


@pytest.fixture
def fake(monkeypatch):
    monkeypatch.setenv("RATE_LIMIT_BACKEND", "db")
    import common.db as db
    f = FakeDB()
    monkeypatch.setattr(db, "query_one", f.query_one)
    monkeypatch.setattr(db, "execute", f.execute)
    return f


def test_db_backend_counts_and_survives_restart(fake):
    mem = {}
    for _ in range(5):
        assert not ratelimit.limited("login:10.10.0.9", 5, 600, mem)
        ratelimit.hit("login:10.10.0.9", 600, mem)
    assert ratelimit.limited("login:10.10.0.9", 5, 600, mem)
    assert mem == {}, "ไม่ได้นับในหน่วยความจำ"
    # รีสตาร์ท service = หน่วยความจำใหม่ แต่ยังโดนบล็อกอยู่
    assert ratelimit.limited("login:10.10.0.9", 5, 600, {})
    assert not ratelimit.limited("login:10.10.0.10", 5, 600, {}), "bucket อื่นไม่เกี่ยว"


def test_old_attempts_expire_and_are_cleaned(fake):
    fake.rows = [("login-user:admin", datetime.now() - timedelta(seconds=700))] * 9
    assert not ratelimit.limited("login-user:admin", 5, 600, {})
    ratelimit.hit("login-user:admin", 600, {})
    assert len(fake.rows) == 1, "แถวที่เกินช่วงเวลาถูกลบตอนนับครั้งใหม่"


def test_falls_back_to_memory_when_db_down(fake):
    fake.down = True
    mem = {}
    for _ in range(3):
        ratelimit.hit("register:AA", 600, mem)
    assert ratelimit.limited("register:AA", 3, 600, mem), "DB ล่มยังต้องกันการเดาได้"
    assert len(mem["register:AA"]) == 3


def test_long_bucket_truncated(fake):
    ratelimit.hit("x" * 500, 600, {})
    assert len(fake.rows[0][0]) == 128
