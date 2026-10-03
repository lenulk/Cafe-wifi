"""หน้า /reports -- สรุปลูกค้า/เน็ต/ช่วงเวลา/การอนุมัติ (ตัวเลขรวมเท่านั้น)"""
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))
import test_logs_search as base  # noqa: E402

TODAY = datetime.now().date()
YDAY = TODAY - timedelta(days=1)


@pytest.fixture
def client(monkeypatch):
    c = base.make_client(monkeypatch)
    import admin.app as admin_app
    admin_app._report_cache.clear()
    real_all, real_one = admin_app.query_all, admin_app.query_one
    c.queries = []

    def q_all(sql, args=()):
        c.queries.append(sql)
        if "COUNT(DISTINCT v.customer_id) AS customers, COUNT(*) AS sessions, COUNT(DISTINCT ps.mac)" in sql:
            return [dict(d=YDAY, customers=3, sessions=5, devices=4), dict(d=TODAY, customers=7, sessions=9, devices=8)]
        if "FROM customer WHERE first_seen" in sql:
            return [dict(d=TODAY, n=2)]
        if "FROM conn_log WHERE ts" in sql:
            return [dict(d=YDAY, b=250_000_000), dict(d=TODAY, b=1_250_000_000)]
        if "DATE(decided_at)" in sql:
            return [dict(d=TODAY, n=6)]
        if "HOUR(authenticated_at)" in sql:
            return [dict(h=9, n=2), dict(h=14, n=8), dict(h=15, n=4)]
        if "JOIN staff s ON s.id = ar.decided_by" in sql:
            return [dict(username="somchai", display_name="สมชาย", n=5), dict(username="admin", display_name=None, n=1)]
        return real_all(sql, args)

    def q_one(sql, args=()):
        if "COUNT(DISTINCT v.customer_id) AS customers, COUNT(*) AS sessions FROM portal_session" in sql:
            return dict(customers=9, sessions=14)
        return real_one(sql, args)
    monkeypatch.setattr(admin_app, "query_all", q_all)
    monkeypatch.setattr(admin_app, "query_one", q_one)
    return c


def test_report_shows_totals_charts_and_highlights(client):
    base._login_as(client, "staff")  # พนักงานดูได้ (ไม่มีข้อมูลรายบุคคล)
    html = client.get("/reports").get_data(as_text=True)
    assert "รายงานสรุป" in html
    assert "<b>9</b><span>ลูกค้า (ไม่นับซ้ำ)" in html and "<b>2</b><span>ลูกค้าใหม่" in html
    assert "<b>14</b>" in html and "1.5 GB" in html
    assert "ช่วงที่แน่นที่สุด: <b>14:00–15:00 น.</b>" in html
    assert "(7 คน)" in html, "วันที่คนมากที่สุด = วันนี้"
    assert html.count('class="col"') == 7 + 7 + 24, "7 วัน x 2 กราฟ + 24 ชั่วโมง"
    assert "height:100.0%" in html and "สมชาย" in html


def test_report_30_days_and_cache(client):
    base._login_as(client, "admin")
    html = client.get("/reports?range=30").get_data(as_text=True)
    assert html.count('class="col"') == 30 + 30 + 24
    n = len(client.queries)
    client.get("/reports?range=30")
    assert len(client.queries) == n, "ภายใน 5 นาทีใช้ผลเดิม ไม่คิวรี่ซ้ำ"
    client.get("/reports?range=30&refresh=1")
    assert len(client.queries) > n


def test_report_requires_login(client):
    assert client.get("/reports").status_code == 302
