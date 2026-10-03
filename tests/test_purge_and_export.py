"""T-Purge/Export — tools/purge_old_data.py และ tools/export_evidence.py"""
import contextlib
import hashlib
import json
import os
import stat
from datetime import datetime, timedelta

import pytest

from tools import export_evidence, purge_old_data


# ---------------------------------------------------------------- purge: ตรรกะวันที่ล้วน ๆ
def test_log_cutoff_rejects_below_legal_minimum():
    with pytest.raises(ValueError, match="90"):
        purge_old_data.compute_log_cutoff(89)


def test_log_cutoff_accepts_legal_minimum():
    now = datetime(2026, 8, 22)
    cutoff = purge_old_data.compute_log_cutoff(90, now=now)
    assert cutoff == now - timedelta(days=90)


def test_log_cutoff_default_180_days():
    now = datetime(2026, 8, 22)
    assert purge_old_data.compute_log_cutoff(180, now=now) == now - timedelta(days=180)


def test_customer_cutoff_is_plain_subtraction():
    now = datetime(2026, 8, 22)
    assert purge_old_data.compute_customer_cutoff(180, now=now) == now - timedelta(days=180)


# ---------------------------------------------------------------- purge: DB จำลอง (fake executor)
def test_purge_conn_and_dns_logs_calls_correct_sql():
    calls = []

    def fake_exec(sql, args=()):
        calls.append((" ".join(sql.split()), args))
        return 42

    cutoff = datetime(2026, 1, 1)
    n_conn, n_dns = purge_old_data.purge_conn_and_dns_logs(fake_exec, cutoff)
    assert n_conn == 42 and n_dns == 42
    assert calls[0] == ("DELETE FROM conn_log WHERE ts < %s", (cutoff,))
    assert calls[1] == ("DELETE FROM dns_log WHERE ts < %s", (cutoff,))


def test_purge_stale_customers_anonymizes_only_those_without_active_voucher():
    """
    บั๊กเดิม (C2): เคยเป็น DELETE FROM customer ตรง ๆ ซึ่งชน fk_voucher_customer
    แตกจริงบนเครื่อง (ลูกค้าทุกรายมี voucher เสมอ) -- ตอนนี้เปลี่ยนเป็น UPDATE
    เพื่อล้าง PII แต่ยังคงแถวไว้รักษาสาย FK
    """
    stale_rows = [{"id": 7}, {"id": 9}]
    anonymized = []

    def fake_query_all(sql, args=()):
        return stale_rows

    def fake_exec(sql, args=()):
        if not sql.strip().upper().startswith("UPDATE CUSTOMER"):
            assert sql.strip().upper().startswith("UPDATE "), "ล้างชื่อเครื่องต้อง UPDATE ไม่ใช่ DELETE"
            return 1
        assert sql.strip().upper().startswith("UPDATE CUSTOMER"), \
            "ต้อง UPDATE (anonymize) ไม่ใช่ DELETE -- DELETE จะชน FK ของ voucher"
        anonymized.append(args[0])
        return 1

    n = purge_old_data.purge_stale_customers(
        fake_query_all, lambda *a: {"last_activity": datetime(2025, 1, 1)},
        fake_exec, datetime(2026, 1, 1), retention_days=180,
        now=datetime(2026, 8, 1))
    assert n == 2
    assert anonymized == [7, 9]


def test_purge_stale_customers_none_found():
    n = purge_old_data.purge_stale_customers(
        lambda *a: [], lambda *a: None, lambda *a: 0, datetime.now(), 180)
    assert n == 0


# ---------------------------------------------------------------- purge: end-to-end ผ่าน run()
class _FakeCursor:
    def __init__(self, anonymized_log, stale_customers):
        self._anonymized_log = anonymized_log
        self._stale = stale_customers
        self.rowcount = 0
        self._select_result = []

    def execute(self, sql, args=()):
        s = " ".join(sql.split()).lower()
        if s.startswith("delete from conn_log"):
            self.rowcount = 5
        elif s.startswith("delete from dns_log"):
            self.rowcount = 8
        elif s.startswith("delete from voucher_reveal"):
            self.rowcount = 0
        elif s.startswith("delete from access_request where created_at < %s"):
            self.rowcount = 4
        elif s.startswith("delete from rate_attempt where ts <"):
            self.rowcount = 0
        elif s.startswith(("update portal_session ps join voucher", "update access_request ar join voucher")):
            self.rowcount = 1
        elif s.startswith("select c.id from customer"):
            self._select_result = self._stale
        elif s.startswith("select greatest("):
            self._select_result = {"last_activity": datetime.now() - timedelta(days=400)}
        elif s.startswith("update customer set natid_hash"):
            self._anonymized_log.append(args[0])
            self.rowcount = 1
        elif s.startswith("insert into audit_log"):
            self.rowcount = 1
        else:
            raise AssertionError(f"ไม่รู้จัก SQL: {s[:60]}")

    def fetchall(self):
        return self._select_result

    def fetchone(self):
        return self._select_result

    def __enter__(self): return self
    def __exit__(self, *a): return False


def test_run_end_to_end_with_fake_db(monkeypatch):
    anonymized_customers = []
    stale = [{"id": 1}, {"id": 2}, {"id": 3}]

    class FakeConn:
        def cursor(self):
            return _FakeCursor(anonymized_customers, stale)

    import common.db as db
    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(FakeConn()))
    audit_calls = []
    # audit.py เรียก db.execute(...) แบบ dynamic (ดูเหตุผลใน common/audit.py) จึง patch
    # ที่ common.db.execute ตรง ๆ ไม่ใช่ผ่านชื่อที่เคย import เข้าไปใน common.audit
    monkeypatch.setattr(db, "execute", lambda sql, args=(): audit_calls.append(args))

    summary = purge_old_data.run(retention_days=180, customer_retention_days=180)
    assert summary.conn_log_deleted == 5
    assert summary.dns_log_deleted == 8
    assert summary.customers_deleted == 3
    assert anonymized_customers == [1, 2, 3]
    assert len(audit_calls) == 1
    assert "access_request=-4" in str(audit_calls[0]), "คำขอใช้งานเก่าต้องถูกลบตามอายุ log"


def test_run_refuses_below_legal_minimum(monkeypatch):
    with pytest.raises(ValueError):
        purge_old_data.run(retention_days=30)


# ---------------------------------------------------------------- export_evidence
SAMPLE_CONN = [
    dict(ts="2026-08-01 10:00:00", mac="AA:BB:CC:DD:EE:01", src_ip="10.10.0.105",
        src_port=51322, dst_ip="93.184.216.34", dst_port=443, proto="tcp",
        bytes_out=1400, bytes_in=8200),
]
SAMPLE_DNS = [
    dict(ts="2026-08-01 10:00:00", client_ip="10.10.0.105", mac="AA:BB:CC:DD:EE:01",
        qname="example.com", qtype="A", answer="93.184.216.34"),
]


def test_rows_to_csv_text_has_header_and_row():
    text = export_evidence.rows_to_csv_text(SAMPLE_CONN, export_evidence.CONN_FIELDS)
    lines = text.strip().splitlines()
    assert lines[0].split(",") == export_evidence.CONN_FIELDS
    assert "AA:BB:CC:DD:EE:01" in lines[1]


def test_rows_to_csv_text_ignores_extra_fields():
    rows = [dict(SAMPLE_CONN[0], unexpected_field="should not appear")]
    text = export_evidence.rows_to_csv_text(rows, export_evidence.CONN_FIELDS)
    assert "unexpected_field" not in text
    assert "should not appear" not in text


def test_write_export_file_matches_sha256(tmp_path):
    ef = export_evidence.write_export_file(SAMPLE_CONN, export_evidence.CONN_FIELDS,
                                           tmp_path / "conn.csv")
    on_disk = (tmp_path / "conn.csv").read_bytes()
    assert ef.sha256 == hashlib.sha256(on_disk).hexdigest()
    assert ef.row_count == 1


def test_export_end_to_end_writes_csv_and_manifest(tmp_path):
    audit_calls = []
    import common.db as db_mod
    orig = db_mod.execute
    db_mod.execute = lambda sql, args=(): audit_calls.append(args)
    try:
        result = export_evidence.export(
            mac="AA:BB:CC:DD:EE:01", start=datetime(2026, 8, 1), end=datetime(2026, 8, 22),
            out_dir=tmp_path, query_conn_fn=lambda *a: SAMPLE_CONN,
            query_dns_fn=lambda *a: SAMPLE_DNS, staff_id=1)
    finally:
        db_mod.execute = orig

    assert result["conn_file"].path.exists()
    assert result["dns_file"].path.exists()
    # ต้องระบุ encoding="utf-8" ชัดเจน (ไฟล์เขียนด้วย utf-8 เสมอใน build_manifest แต่
    # read_text() แบบไม่ระบุ encoding จะใช้ locale ของเครื่อง -- พังจริงถ้า locale ไม่ใช่ UTF-8
    # เช่น cp1252 บน Windows หรือ C locale บน container Linux แบบ minimal)
    manifest = json.loads(result["manifest_path"].read_text(encoding="utf-8"))
    assert manifest["criteria"]["mac"] == "AA:BB:CC:DD:EE:01"
    assert len(manifest["files"]) == 2
    for f in manifest["files"]:
        actual = hashlib.sha256((tmp_path / f["filename"]).read_bytes()).hexdigest()
        assert actual == f["sha256"], f"sha256 ใน manifest ต้องตรงกับไฟล์จริงเสมอ ({f['filename']})"
    assert len(audit_calls) == 1, "ต้องบันทึก audit_log ทุกครั้งที่ export"


def test_export_rejects_invalid_date_range(tmp_path):
    with pytest.raises(ValueError):
        export_evidence.export(None, datetime(2026, 8, 22), datetime(2026, 8, 1), tmp_path,
                               lambda *a: [], lambda *a: [])


def test_export_writes_no_files_when_audit_fails(tmp_path, monkeypatch):
    from common import audit
    monkeypatch.setattr(audit, "log_required",
                        lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("audit down")))
    with pytest.raises(RuntimeError, match="audit down"):
        export_evidence.export(None, datetime(2026, 8, 1), datetime(2026, 8, 2), tmp_path,
                               lambda *a: [], lambda *a: [])
    assert list(tmp_path.iterdir()) == []


# ============ N32: วันสิ้นสุดของช่วงส่งออกหลักฐานต้องหมายถึงสิ้นวัน ไม่ใช่เที่ยงคืนต้นวัน
def test_range_end_date_only_means_end_of_day():
    """ของเดิม --to 2026-09-20 = 00:00:00 ทำให้ข้อมูลทั้งวันที่ 20 หายไปจากไฟล์หลักฐานเงียบ ๆ"""
    end = export_evidence.parse_range_end("2026-09-20")
    assert (end.hour, end.minute, end.second) == (23, 59, 59)
    assert end.date().isoformat() == "2026-09-20"


def test_range_end_with_explicit_time_is_untouched():
    end = export_evidence.parse_range_end("2026-09-20T08:30:00")
    assert (end.hour, end.minute, end.second) == (8, 30, 0)


def test_single_day_export_range_is_valid():
    """คำขอที่พบบ่อยที่สุดจากเจ้าหน้าที่คือ 'ขอข้อมูลวันที่ X' -- ต้องไม่ถูกปฏิเสธ"""
    from datetime import datetime as _dt
    start = _dt.fromisoformat("2026-09-20")
    assert export_evidence.parse_range_end("2026-09-20") > start


# ============ R2-10: ไฟล์ส่งออกหลักฐานต้องโยงถึงตัวบุคคลได้ และ --natid ต้องใช้ได้จริง
def test_cli_accepts_natid_documented_in_docstring():
    """docstring บอกว่าใช้ --natid ได้ แต่ argparse เดิมไม่มีตัวเลือกนี้ (รันแล้ว error)"""
    args = export_evidence.build_parser().parse_args(
        ["--natid", "1234567890121", "--from", "2026-08-01", "--to", "2026-08-22"])
    assert args.natid == "1234567890121" and args.mac is None


def test_cli_rejects_mac_and_natid_together():
    with pytest.raises(SystemExit):
        export_evidence.build_parser().parse_args(
            ["--mac", "AA:BB:CC:DD:EE:01", "--natid", "1234567890121",
             "--from", "2026-08-01", "--to", "2026-08-22"])


def test_csv_fields_include_identity_columns():
    for fields in (export_evidence.CONN_FIELDS, export_evidence.DNS_FIELDS):
        assert "voucher_username" in fields and "natid_masked" in fields


def test_queries_use_same_mapping_join_as_logs_page():
    from common.log_mapping import conn_mapping_join, dns_mapping_join
    conn_sql, _ = export_evidence.build_conn_query(datetime(2026, 8, 1), datetime(2026, 8, 2))
    dns_sql, _ = export_evidence.build_dns_query(datetime(2026, 8, 1), datetime(2026, 8, 2))
    assert conn_mapping_join() in conn_sql
    assert dns_mapping_join() in dns_sql
    for sql in (conn_sql, dns_sql):
        assert "natid_enc" not in sql and "natid_hash" not in sql, "ห้ามดึงเลขบัตรเต็มหรือ hash"


def test_customer_query_filters_by_session_mac_ip_and_customer():
    s, e = datetime(2026, 8, 1), datetime(2026, 8, 2)
    sql, params = export_evidence.build_conn_query(s, e, mac="AA:BB:CC:DD:EE:01",
                                                   ip="10.10.0.105", customer_id=7)
    assert "cl.mac = %s" in sql and "cl.src_ip = %s" in sql and "c.id = %s" in sql
    assert params == (s, e, "AA:BB:CC:DD:EE:01", "10.10.0.105", 7)


def test_query_customer_rows_merges_every_session_pair_sorted():
    calls = []
    pairs = [{"mac": "AA:BB:CC:DD:EE:01", "ip": "10.10.0.105"},
             {"mac": "AA:BB:CC:DD:EE:02", "ip": "10.10.0.77"}]
    per_pair = {
        "AA:BB:CC:DD:EE:01": [{"ts": datetime(2026, 8, 1, 12)}],
        "AA:BB:CC:DD:EE:02": [{"ts": datetime(2026, 8, 1, 9)}],
    }

    def fake_query_all(sql, params):
        calls.append((sql, params))
        if "DISTINCT ps.mac" in sql:
            assert params[0] == 7
            return pairs
        return per_pair[params[2]]

    rows = export_evidence.query_customer_rows(export_evidence.build_dns_query, 7,
                                               datetime(2026, 8, 1), datetime(2026, 8, 2),
                                               fake_query_all)
    assert [r["ts"].hour for r in rows] == [9, 12]
    assert all(p[-1] == 7 for _, p in calls[1:]), "ทุกคิวรี่ต้องกรอง c.id ของลูกค้ารายนี้"


def test_find_customer_uses_hash_and_rejects_bad_checksum():
    from common import crypto
    seen = []
    row = export_evidence.find_customer(
        "0-0000-00000-00-1", lambda sql, p: seen.append(p) or {"id": 3, "natid_masked": "x"})
    assert row["id"] == 3
    assert seen == [(crypto.natid_hash("0000000000001"),)]
    with pytest.raises(ValueError):
        export_evidence.find_customer("1234567890123", lambda *a: None)


def test_mac_is_normalized_to_uppercase():
    """DB เก็บ MAC ตัวใหญ่ -- เดิมใส่ aa:bb:… แล้วได้ 0 แถวเงียบ ๆ"""
    assert export_evidence.normalize_mac(" aa-bb-cc-dd-ee-01 ") == "AA:BB:CC:DD:EE:01"
    assert export_evidence.normalize_mac(None) is None
    with pytest.raises(ValueError):
        export_evidence.normalize_mac("not-a-mac")


def test_export_passes_normalized_mac_and_records_customer(tmp_path, monkeypatch):
    from common import audit
    audit_targets = []
    monkeypatch.setattr(audit, "log_required", lambda *a, **kw: audit_targets.append(kw["target"]))
    seen_mac = []
    result = export_evidence.export(
        "aa:bb:cc:dd:ee:01", datetime(2026, 8, 1), datetime(2026, 8, 2), tmp_path,
        lambda mac, s, e: seen_mac.append(mac) or [], lambda *a: [])
    assert seen_mac == ["AA:BB:CC:DD:EE:01"]

    result = export_evidence.export(
        None, datetime(2026, 8, 1), datetime(2026, 8, 2), tmp_path, lambda *a: [], lambda *a: [],
        customer={"id": 7, "natid_masked": "1-2345-XXXXX-XX-3"})
    manifest = json.loads(result["manifest_path"].read_text(encoding="utf-8"))
    assert manifest["criteria"]["customer_id"] == 7
    assert manifest["criteria"]["natid_masked"] == "1-2345-XXXXX-XX-3"
    assert audit_targets == ["AA:BB:CC:DD:EE:01", "customer:7"]


@pytest.mark.skipif(os.name != "posix", reason="สิทธิ์ไฟล์แบบ POSIX")
def test_exported_files_are_private(tmp_path, monkeypatch):
    from common import audit
    monkeypatch.setattr(audit, "log_required", lambda *a, **kw: None)
    old = os.umask(0o022)
    try:
        result = export_evidence.export(None, datetime(2026, 8, 1), datetime(2026, 8, 2),
                                        tmp_path / "exports", lambda *a: SAMPLE_CONN,
                                        lambda *a: SAMPLE_DNS)
    finally:
        os.umask(old)
    for path in (result["conn_file"].path, result["dns_file"].path, result["manifest_path"]):
        assert stat.S_IMODE(path.stat().st_mode) == 0o600, path.name
    assert stat.S_IMODE((tmp_path / "exports").stat().st_mode) == 0o700
