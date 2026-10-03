"""T-Logger — conn_collector / dns_collector / integrity (เฉพาะส่วนที่ทดสอบได้โดยไม่ต้องมีฮาร์ดแวร์จริง)"""
import gzip
import ipaddress
from datetime import datetime

import pytest

from logger import conn_collector
from logger import dns_collector
from logger.conn_collector import ConnRecord, flush_buffer, parse_conntrack_line
from logger.dns_collector import DnsCorrelator, parse_dnsmasq_line, parse_syslog_timestamp
from logger import integrity
from logger.integrity import (MemoryManifestStore, sha256_file, seal_directory,
                              verify_chain, prune_archives, ManifestEntry)
from logger.netutil import MacCache, resolve_mac

# ---------------------------------------------------------------- conntrack
# หมายเหตุ (แก้บั๊ก 2026-08-28): ตัวอย่างเหล่านี้เคยไม่มี "ipv4     2 " นำหน้าชื่อโปรโตคอล
# ซึ่งไม่ตรงกับ `conntrack -E -o timestamp,extended` ตัวจริงเลย (มี address family ขึ้นก่อน
# ชื่อโปรโตคอลเสมอ) ทำให้เทสต์ผ่านหมดทั้งที่โค้ดจริงตีความ proto ผิด 100% เวลาเจอ conntrack
# จริง (ยืนยันจาก VM lab: conn_log ทุกแถวเป็น "other" หมด) แก้ตัวอย่างให้ตรงกับที่ conntrack
# จริงส่งมาแล้ว (ดู test_destroy_event_from_live_conntrack ด้านล่างที่ใช้บรรทัดจริงที่จับได้)
NEW_LINE = ("[1692702000.1] [NEW] ipv4     2 tcp      6 120 SYN_SENT "
           "src=10.10.0.105 dst=93.184.216.34 "
           "sport=51322 dport=443 [UNREPLIED] src=93.184.216.34 dst=10.10.0.105 "
           "sport=443 dport=51322")
DESTROY_TCP = ("[1692702005.9] [DESTROY] ipv4     2 tcp      6 TIME_WAIT "
              "src=10.10.0.105 dst=93.184.216.34 "
              "sport=51322 dport=443 packets=12 bytes=1400 src=93.184.216.34 "
              "dst=10.10.0.105 sport=443 dport=51322 packets=9 bytes=8200 [ASSURED]")
DESTROY_UDP = ("[1692702010.0] [DESTROY] ipv4     2 udp      17 "
              "src=10.10.0.108 dst=8.8.8.8 "
              "sport=54000 dport=53 packets=1 bytes=60 src=8.8.8.8 dst=10.10.0.108 "
              "sport=53 dport=54000 packets=1 bytes=120")
# บรรทัดจริง 100% ที่จับได้จาก `conntrack -E -o timestamp,extended -e DESTROY` บน VM lab
# (2026-08-28) ตอนที่มี client จริง (macvlan+netns จำลอง) กำลังคุยผ่าน openNDS จริงอยู่
DESTROY_TCP_REAL_CAPTURE = (
    "[1787853886.670856]\t[DESTROY] ipv4     2 tcp      6 TIME_WAIT "
    "src=10.10.0.222 dst=34.223.124.45 sport=44256 dport=80 "
    "src=10.10.0.1 dst=10.10.0.222 sport=2050 dport=44256 [ASSURED]"
)


def test_new_event_is_ignored():
    assert parse_conntrack_line(NEW_LINE) is None, "เก็บเฉพาะ DESTROY (connection จบแล้ว) เท่านั้น"


def test_destroy_tcp_parsed_correctly():
    r = parse_conntrack_line(DESTROY_TCP)
    assert r == ConnRecord(ts=1692702005.9, proto="tcp", src_ip="10.10.0.105",
                           src_port=51322, dst_ip="93.184.216.34", dst_port=443,
                           bytes_out=1400, bytes_in=8200)


def test_uses_original_direction_not_reply_direction():
    r = parse_conntrack_line(DESTROY_TCP)
    # ต้องเป็น IP/port ของ "ต้นทาง" (บล็อกแรก) ไม่ใช่ของทิศทางย้อนกลับ (บล็อกที่สอง)
    assert r.src_ip == "10.10.0.105" and r.dst_ip == "93.184.216.34"


def test_udp_and_no_ports_for_icmp():
    r = parse_conntrack_line(DESTROY_UDP)
    assert r.proto == "udp" and r.src_port == 54000


def test_garbage_and_empty_lines_ignored():
    assert parse_conntrack_line("") is None
    assert parse_conntrack_line("not conntrack output at all") is None


def test_bytes_default_to_zero_without_extended_accounting():
    line = "[1.0] [DESTROY] ipv4     2 tcp      6 src=1.2.3.4 dst=5.6.7.8 sport=1 dport=2"
    r = parse_conntrack_line(line)
    assert r.bytes_out == 0 and r.bytes_in == 0


def test_destroy_event_from_live_conntrack():
    """
    Regression test — กันบั๊ก "ipv4 prefix ทำให้ proto เป็น other เสมอ" กลับมาแบบเงียบๆ อีก
    (2026-08-28) โค้ดเดิมเข้าใจว่า token แรกที่ไม่ใช่ตัวเลข/key=value คือชื่อโปรโตคอล แต่
    conntrack ตัวจริงขึ้นต้นด้วย address family ("ipv4"/"ipv6") ก่อนชื่อโปรโตคอลเสมอ ทำให้
    ทุกแถวถูกจัดเป็น "other" หมด 100% ทั้งที่มี TCP/UDP จริงปนอยู่ (ยืนยันจาก conn_log จริง
    บน VM lab ก่อนแก้: 16/16 แถวเป็น "other") บรรทัดด้านล่างจับมาจาก conntrack ตัวจริง
    ห้ามแก้เป็นค่าที่สร้างเอง
    """
    r = parse_conntrack_line(DESTROY_TCP_REAL_CAPTURE)
    assert r.proto == "tcp", "ต้องอ่าน 'tcp' ที่อยู่หลัง 'ipv4     2' ได้ ไม่ใช่ตีความ 'ipv4' เป็นโปรโตคอล"
    assert r.src_ip == "10.10.0.222" and r.dst_ip == "34.223.124.45"
    assert r.src_port == 44256 and r.dst_port == 80


# ---------------------------------------------------------------- dnsmasq
NOW = datetime(2026, 8, 22, 12, 0, 0)


def test_parse_query_line():
    ev = parse_dnsmasq_line("Aug 22 10:15:32 dnsmasq[1234]: query[A] example.com from 10.10.0.105", NOW)
    assert ev.__class__.__name__ == "DnsQueryEvent"
    assert ev.qname == "example.com" and ev.client_ip == "10.10.0.105" and ev.qtype == "A"


def test_parse_reply_and_cached_lines():
    r1 = parse_dnsmasq_line("Aug 22 10:15:33 dnsmasq[1234]: reply example.com is 93.184.216.34", NOW)
    r2 = parse_dnsmasq_line("Aug 22 10:15:33 dnsmasq[1234]: cached example.com is 93.184.216.34", NOW)
    assert r1.answer == "93.184.216.34" and r2.answer == "93.184.216.34"


def test_forwarded_line_is_ignored():
    assert parse_dnsmasq_line("Aug 22 10:15:32 dnsmasq[1234]: forwarded example.com to 1.1.1.1", NOW) is None


def test_year_rollback_for_old_timestamps():
    # สถานการณ์จริง: อ่าน log เก่าตอนต้นปีใหม่ (now = 2 ม.ค. 2026) ที่มีบรรทัดของ
    # "31 ธ.ค." (ปี 2025) ค้างอยู่ — ถ้าเดาว่าเป็นปีปัจจุบัน (2026) จะกลายเป็นอนาคต ต้องถอยปีให้
    early_jan = datetime(2026, 1, 2, 8, 0, 0)
    ts = parse_syslog_timestamp("Dec 31 23:59:00", early_jan)
    assert ts.year == 2025, "31 ธ.ค. ที่ดูเหมือนอยู่ในอนาคตเมื่อเทียบกับ now ต้องถูกตีความเป็นปีก่อน"


def test_dns_query_and_reply_are_independent_events():
    c = DnsCorrelator()
    query = c.feed_line("Aug 22 10:15:32 dnsmasq[1234]: query[A] example.com from 10.10.0.105", NOW)
    answer = c.feed_line("Aug 22 10:15:33 dnsmasq[1234]: reply example.com is 93.184.216.34", NOW)
    assert query == dict(ts=NOW.replace(hour=10, minute=15, second=32), client_ip="10.10.0.105",
                         qname="example.com", qtype="A", answer=None, event_kind="query")
    assert answer == dict(ts=NOW.replace(hour=10, minute=15, second=33), client_ip=None,
                          qname="example.com", qtype=None, answer="93.184.216.34", event_kind="answer")


def test_dns_orphan_reply_is_retained_without_client():
    c = DnsCorrelator()
    row = c.feed_line("Aug 22 10:15:50 dnsmasq[1234]: reply orphan.com is 1.2.3.4", NOW)
    assert row["event_kind"] == "answer" and row["client_ip"] is None


def test_dns_same_name_from_two_clients_stays_separate():
    c = DnsCorrelator()
    a = c.feed_line("Aug 22 10:15:01 dnsmasq[1]: query[A] same.test from 10.0.0.1", NOW)
    b = c.feed_line("Aug 22 10:15:02 dnsmasq[1]: query[A] same.test from 10.0.0.2", NOW)
    assert a["client_ip"] == "10.0.0.1" and b["client_ip"] == "10.0.0.2"


# ---------------------------------------------------------------- integrity / hash chain
def test_sha256_file_plain_and_gz_match_same_content(tmp_path):
    content = b"log content for testing\n" * 100
    plain = tmp_path / "a.log"
    plain.write_bytes(content)
    gz = tmp_path / "a.log.gz"
    with gzip.open(gz, "wb") as f:
        f.write(content)
    assert sha256_file(plain) == sha256_file(gz), "hash เนื้อหาต้องเหมือนกันไม่ว่าจะบีบอัดหรือไม่"


def test_seal_directory_builds_chain(tmp_path):
    (tmp_path / "day1.log").write_bytes(b"day 1 content")
    (tmp_path / "day2.log").write_bytes(b"day 2 content")
    store = MemoryManifestStore()

    sealed = seal_directory(tmp_path, store, patterns=("*.log",))
    assert len(sealed) == 2
    assert sealed[0].prev_sha256 is None, "ไฟล์แรกสุดไม่มี prev"
    assert sealed[1].prev_sha256 == sealed[0].sha256, "ไฟล์ถัดไปต้องอ้าง hash ไฟล์ก่อนหน้า"


def test_seal_directory_matches_real_logrotate_dateext_filenames(tmp_path):
    """
    บั๊กเดิม (C1): pattern default ("*.log.gz", "*.log") ไม่ตรงกับไฟล์ที่ install.sh
    logrotate สร้างจริงเลยสักไฟล์ เพราะตั้ง `dateext` + `dateformat -%Y-%m-%d` ไว้
    ชื่อไฟล์จริงจึงเป็น "dnsmasq.log-2026-08-25.gz" (delaycompress ทำให้รอบแรกยังไม่ .gz)
    ไม่ใช่ "dnsmasq.log.gz" แบบที่เทสต์เดิมสมมติ -- เทสต์นี้ใช้ชื่อไฟล์แบบจริงและไม่ระบุ
    patterns เอง (ใช้ default) เพื่อจับบั๊กนี้ไว้ไม่ให้กลับมาอีก
    """
    with gzip.open(tmp_path / "dnsmasq.log-2026-08-24.gz", "wb") as f:
        f.write(b"day 1 already compressed")
    (tmp_path / "dnsmasq.log-2026-08-25").write_bytes(b"day 2 not compressed yet (delaycompress)")
    store = MemoryManifestStore()

    sealed = seal_directory(tmp_path, store)  # ไม่ระบุ patterns -- ต้องใช้ default ได้ตรง
    assert len(sealed) == 2, "ต้องผนึกไฟล์แบบ dateext ของจริงได้ทั้งคู่ด้วย pattern default"


def test_seal_directory_is_idempotent(tmp_path):
    (tmp_path / "day1.log").write_bytes(b"content")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store, patterns=("*.log",))
    sealed_again = seal_directory(tmp_path, store, patterns=("*.log",))
    assert sealed_again == [], "ไฟล์ที่ผนึกแล้วต้องไม่ถูกผนึกซ้ำ"
    assert len(store.all_entries()) == 1


def test_verify_chain_passes_on_untouched_files(tmp_path):
    (tmp_path / "day1.log").write_bytes(b"content 1")
    (tmp_path / "day2.log").write_bytes(b"content 2")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store, patterns=("*.log",))
    assert verify_chain(store, tmp_path) == []


def test_verify_chain_detects_tampered_file(tmp_path):
    (tmp_path / "day1.log").write_bytes(b"original content")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store, patterns=("*.log",))

    (tmp_path / "day1.log").write_bytes(b"TAMPERED content")  # แก้ไขย้อนหลัง
    issues = verify_chain(store, tmp_path)
    assert len(issues) == 1 and issues[0].kind == "hash_mismatch"


def test_verify_chain_detects_deleted_file(tmp_path):
    (tmp_path / "day1.log").write_bytes(b"content")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store, patterns=("*.log",))
    (tmp_path / "day1.log").unlink()

    issues = verify_chain(store, tmp_path)
    assert len(issues) == 1 and issues[0].kind == "missing_file"


def test_verify_chain_detects_broken_link():
    """จำลอง manifest ที่ถูกแก้ prev_sha256 ตรง ๆ (เช่นมีคนไปแก้ DB โดยตรง)"""
    from logger.integrity import ManifestEntry
    store = MemoryManifestStore()
    store.add(ManifestEntry(filename="a.log", sha256="a" * 64, prev_sha256=None, size_bytes=1))
    store.add(ManifestEntry(filename="b.log", sha256="b" * 64, prev_sha256="WRONG", size_bytes=1))
    issues = verify_chain(store, store and __import__("pathlib").Path("/nonexistent"))
    kinds = {i.kind for i in issues}
    assert "chain_broken" in kinds


def test_retention_delete_is_recorded_without_false_missing_file(tmp_path, monkeypatch):
    from common import audit
    archive = tmp_path / "dnsmasq.log-2026-01-01"
    archive.write_bytes(b"old raw log")
    store = MemoryManifestStore()
    store.add(ManifestEntry(filename=archive.name, sha256=sha256_file(archive),
                            prev_sha256=None, size_bytes=archive.stat().st_size,
                            sealed_at=datetime(2026, 1, 2)))
    monkeypatch.setattr(audit, "log_required", lambda *a, **kw: None)
    assert prune_archives(store, tmp_path, 90, now=datetime(2026, 9, 29)) == 1
    assert not archive.exists()
    assert verify_chain(store, tmp_path) == []


def test_pending_retention_delete_is_an_issue(tmp_path):
    store = MemoryManifestStore()
    store.add(ManifestEntry(filename="dnsmasq.log-2026-01-01", sha256="a" * 64,
                            prev_sha256=None, size_bytes=1))
    store.set_deletion("dnsmasq.log-2026-01-01", "pending")
    assert {i.kind for i in verify_chain(store, tmp_path)} == {"pending_delete", "missing_file"}


# ============ R2-07: issue ของไฟล์หนึ่งต้องไม่บล็อกการลบทั้งหมด และ pending ต้องทำต่อได้
def _old_archive(directory, name, content=b"old raw log"):
    path = directory / name
    path.write_bytes(content)
    return path


def _add_sealed(store, path, prev=None):
    entry = ManifestEntry(filename=path.name, sha256=sha256_file(path), prev_sha256=prev,
                          size_bytes=path.stat().st_size, sealed_at=datetime(2026, 1, 2))
    store.add(entry)
    return entry.sha256


def test_prune_finishes_pending_whose_file_is_already_gone(tmp_path):
    """unlink สำเร็จแต่ set_deletion('deleted') ล้ม -> รอบถัดไปต้องปิดรายการได้ ไม่ค้างถาวร"""
    path = _old_archive(tmp_path, "dnsmasq.log-2026-01-01")
    _add_sealed(store := MemoryManifestStore(), path)
    store.set_deletion(path.name, "pending")
    path.unlink()

    assert prune_archives(store, tmp_path, 90, now=datetime(2026, 9, 29)) == 1
    assert store.all_entries()[0].deletion_state == "deleted"
    assert verify_chain(store, tmp_path) == []


def test_prune_finishes_pending_whose_file_still_exists(tmp_path):
    path = _old_archive(tmp_path, "dnsmasq.log-2026-01-01")
    _add_sealed(store := MemoryManifestStore(), path)
    store.set_deletion(path.name, "pending")   # unlink ล้มในรอบก่อน

    assert prune_archives(store, tmp_path, 90, now=datetime(2026, 9, 29)) == 1
    assert not path.exists()
    assert store.all_entries()[0].deletion_state == "deleted"


def test_prune_keeps_pending_file_whose_hash_changed(tmp_path):
    path = _old_archive(tmp_path, "dnsmasq.log-2026-01-01")
    _add_sealed(store := MemoryManifestStore(), path)
    store.set_deletion(path.name, "pending")
    path.write_bytes(b"TAMPERED")

    assert prune_archives(store, tmp_path, 90, now=datetime(2026, 9, 29)) == 0
    assert path.exists(), "ไฟล์ที่ถูกแก้ต้องเก็บไว้เป็นหลักฐาน"
    assert store.all_entries()[0].deletion_state == "pending"


def test_prune_skips_held_files_but_deletes_the_rest(tmp_path, monkeypatch):
    from common import audit
    monkeypatch.setattr(audit, "log_required", lambda *a, **kw: None)
    a = _old_archive(tmp_path, "dnsmasq.log-2026-01-01", b"a")
    b = _old_archive(tmp_path, "dnsmasq.log-2026-01-02", b"b")
    store = MemoryManifestStore()
    _add_sealed(store, b, _add_sealed(store, a))

    assert prune_archives(store, tmp_path, 90, now=datetime(2026, 9, 29), hold={a.name}) == 1
    assert a.exists() and not b.exists()


def test_prune_continues_after_one_unlink_fails(tmp_path, monkeypatch):
    from common import audit
    monkeypatch.setattr(audit, "log_required", lambda *a, **kw: None)
    a = _old_archive(tmp_path, "dnsmasq.log-2026-01-01", b"a")
    b = _old_archive(tmp_path, "dnsmasq.log-2026-01-02", b"b")
    store = MemoryManifestStore()
    _add_sealed(store, b, _add_sealed(store, a))
    real_unlink = type(a).unlink

    def flaky_unlink(self, *args, **kw):
        if self.name == a.name:
            raise PermissionError("Operation not permitted")
        return real_unlink(self, *args, **kw)
    monkeypatch.setattr(type(a), "unlink", flaky_unlink)

    assert prune_archives(store, tmp_path, 90, now=datetime(2026, 9, 29)) == 1
    states = {e.filename: e.deletion_state for e in store.all_entries()}
    assert states == {a.name: "pending", b.name: "deleted"}

    monkeypatch.setattr(type(a), "unlink", real_unlink)
    assert prune_archives(store, tmp_path, 90, now=datetime(2026, 9, 29)) == 1, "รอบถัดไปทำต่อได้"
    assert verify_chain(store, tmp_path) == []


# ---------------------------------------------------------------- netutil
PROC_NET_ARP_SAMPLE = """IP address       HW type     Flags       HW address            Mask     Device
10.10.0.105      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth1
10.10.0.108      0x1         0x2         11:22:33:44:55:66     *        eth1
10.10.0.199      0x1         0x0         00:00:00:00:00:00     *        eth1
"""


def test_resolve_mac_from_arp_table(tmp_path):
    arp_file = tmp_path / "arp"
    arp_file.write_text(PROC_NET_ARP_SAMPLE)
    assert resolve_mac("10.10.0.105", arp_file) == "AA:BB:CC:DD:EE:FF"
    assert resolve_mac("10.10.0.999", arp_file) is None
    assert resolve_mac("10.10.0.199", arp_file) is None, "MAC ทั้งหมดเป็น 0 แปลว่ายังไม่ resolve จริง"


def test_mac_cache_reuses_within_ttl(tmp_path, monkeypatch):
    arp_file = tmp_path / "arp"
    arp_file.write_text(PROC_NET_ARP_SAMPLE)
    calls = {"n": 0}
    import logger.netutil as netutil
    real_resolve = netutil.resolve_mac

    def counting_resolve(ip, path):
        calls["n"] += 1
        return real_resolve(ip, path)

    monkeypatch.setattr(netutil, "resolve_mac", counting_resolve)
    cache = MacCache(ttl_seconds=10, arp_path=arp_file)
    cache.get("10.10.0.105", now=100.0)
    cache.get("10.10.0.105", now=105.0)  # ยังอยู่ใน TTL -> ไม่ควรอ่านไฟล์ซ้ำ
    cache.get("10.10.0.105", now=115.0)  # เกิน TTL -> อ่านใหม่
    assert calls["n"] == 2


# =================================== N21: ตรวจพบ log ถูกแก้ ต้องทิ้งหลักฐานไว้ในฐานข้อมูลด้วย
@pytest.fixture
def sealed_archive(tmp_path, monkeypatch):
    """ไดเรกทอรี archive ที่ผนึกเรียบร้อยแล้ว + ผูก main() เข้ากับ store ในหน่วยความจำ"""
    archive = tmp_path / "archive"
    archive.mkdir()
    (archive / "portal-access.log-2026-09-16").write_text("บรรทัดของจริง\n", encoding="utf-8")
    store = MemoryManifestStore()
    monkeypatch.setattr(integrity, "SqlManifestStore", lambda: store)
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    assert integrity.main() == 0, "รอบแรกต้องผนึกแล้วผ่าน"
    return archive


def test_main_writes_audit_row_when_log_was_tampered(sealed_archive, monkeypatch):
    """ถ้าคนร้ายแก้ไฟล์ log ได้ ก็ย่อมลบบรรทัด ERROR ในไฟล์ log ทิ้งได้ด้วย -- หลักฐานว่า
    'ตรวจพบการแก้ไข' จึงต้องถูกบันทึกไว้คนละที่กับสิ่งที่ถูกแก้ (audit_log ในฐานข้อมูล)"""
    (sealed_archive / "portal-access.log-2026-09-16").write_text("โดนแก้แล้ว\n", encoding="utf-8")

    logged = []
    import common.audit as audit
    monkeypatch.setattr(audit, "log", lambda action, **kw: logged.append((action, kw)))

    assert integrity.main() == 1, "ตรวจเจอความผิดปกติต้องคืน exit code 1"
    assert len(logged) == 1
    action, kw = logged[0]
    assert action == "integrity_failed"
    assert kw["target"] == "portal-access.log-2026-09-16"
    assert "hash_mismatch" in kw["detail"]


def test_main_writes_audit_row_when_sealed_log_was_deleted(sealed_archive, monkeypatch):
    (sealed_archive / "portal-access.log-2026-09-16").unlink()

    logged = []
    import common.audit as audit
    monkeypatch.setattr(audit, "log", lambda action, **kw: logged.append((action, kw)))

    assert integrity.main() == 1
    assert logged[0][0] == "integrity_failed"
    assert "missing_file" in logged[0][1]["detail"]


def test_main_writes_no_audit_row_when_chain_is_clean(sealed_archive, monkeypatch):
    logged = []
    import common.audit as audit
    monkeypatch.setattr(audit, "log", lambda action, **kw: logged.append((action, kw)))

    assert integrity.main() == 0
    assert logged == [], "ผ่านปกติต้องไม่ถมแถวลง audit_log"


def test_main_still_reports_when_audit_write_fails(sealed_archive, monkeypatch):
    """DB ล่มไม่ควรทำให้ตัวตรวจ crash จนไม่เหลือรายงานอะไรเลย -- ยังต้องคืน 1 ตามเดิม"""
    (sealed_archive / "portal-access.log-2026-09-16").write_text("โดนแก้แล้ว\n", encoding="utf-8")

    import common.audit as audit
    def boom(*a, **kw):
        raise RuntimeError("DB ล่ม")
    monkeypatch.setattr(audit, "log", boom)

    assert integrity.main() == 1


def test_main_still_prunes_other_files_when_one_file_was_tampered(tmp_path, monkeypatch):
    """R2-07: เดิม return 1 ก่อนถึง prune -- ไฟล์เดียวที่ถูกแก้ทำให้ไม่มีอะไรถูกลบตามอายุอีกเลย"""
    archive = tmp_path / "archive"
    archive.mkdir()
    tampered = _old_archive(archive, "dnsmasq.log-2026-01-01", b"a")
    expired = _old_archive(archive, "dnsmasq.log-2026-01-02", b"b")
    store = MemoryManifestStore()
    _add_sealed(store, expired, _add_sealed(store, tampered))
    tampered.write_bytes(b"TAMPERED")

    import common.audit as audit
    logged = []
    monkeypatch.setattr(audit, "log", lambda action, **kw: logged.append((action, kw)))
    monkeypatch.setattr(audit, "log_required", lambda *a, **kw: None)
    monkeypatch.setattr(integrity, "SqlManifestStore", lambda: store)
    monkeypatch.setenv("LOG_DIR", str(tmp_path))
    monkeypatch.setenv("LOG_RETENTION_DAYS", "90")

    assert integrity.main() == 1, "ยังต้องคืน 1 เพราะมีไฟล์ถูกแก้"
    assert tampered.exists(), "ไฟล์ที่ถูกแก้ต้องเก็บไว้เป็นหลักฐาน"
    assert not expired.exists(), "ไฟล์อื่นที่ครบอายุและ hash ตรงต้องถูกลบตามปกติ"
    assert [kw["target"] for _, kw in logged] == [tampered.name]


def test_main_resolves_stuck_pending_delete_and_exits_clean(tmp_path, monkeypatch):
    """R2-07 deadlock: pending_delete เคยเป็น issue -> prune ไม่รัน -> ค้างถาวร"""
    archive = tmp_path / "archive"
    archive.mkdir()
    stuck = _old_archive(archive, "dnsmasq.log-2026-01-01")
    store = MemoryManifestStore()
    _add_sealed(store, stuck)
    store.set_deletion(stuck.name, "pending")
    stuck.unlink()

    import common.audit as audit
    logged = []
    monkeypatch.setattr(audit, "log", lambda action, **kw: logged.append((action, kw)))
    monkeypatch.setattr(integrity, "SqlManifestStore", lambda: store)
    monkeypatch.setenv("LOG_DIR", str(tmp_path))

    assert integrity.main() == 0
    assert logged == [], "pending ที่ทำต่อจนเสร็จแล้วไม่ต้องฟ้องเป็น integrity_failed"
    assert store.all_entries()[0].deletion_state == "deleted"


# ===================== N25: logrotate (delaycompress) บีบอัดไฟล์ที่ผนึกแล้วเป็น .gz ในรอบถัดไป
def _compress_like_logrotate(path):
    """จำลอง logrotate รอบที่สอง: บีบอัด X เป็น X.gz แล้วลบ X ทิ้ง"""
    gz = path.with_name(path.name + ".gz")
    with open(path, "rb") as src, gzip.open(gz, "wb") as dst:
        dst.write(src.read())
    path.unlink()
    return gz


def test_verify_follows_file_renamed_to_gz_by_logrotate(tmp_path):
    """พบจริงบน Pi 2026-09-19: ทุกไฟล์ที่ผนึกถูกฟ้อง missing_file หลัง logrotate รอบที่สอง
    ทั้งที่เนื้อหาไม่เปลี่ยนเลย แค่ถูกบีบอัดเปลี่ยนชื่อเป็น .gz"""
    f = tmp_path / "dnsmasq.log-2026-09-16"
    f.write_text("query 1\nquery 2\n", encoding="utf-8")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store)
    _compress_like_logrotate(f)

    assert verify_chain(store, tmp_path) == []


def test_verify_still_catches_tampering_inside_the_gz(tmp_path):
    f = tmp_path / "dnsmasq.log-2026-09-16"
    f.write_text("query 1\n", encoding="utf-8")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store)
    f.write_text("query 1\nแทรกย้อนหลัง\n", encoding="utf-8")
    _compress_like_logrotate(f)

    issues = verify_chain(store, tmp_path)
    assert [i.kind for i in issues] == ["hash_mismatch"]


def test_verify_reports_missing_when_neither_file_nor_gz_exists(tmp_path):
    f = tmp_path / "dnsmasq.log-2026-09-16"
    f.write_text("x", encoding="utf-8")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store)
    f.unlink()

    assert [i.kind for i in verify_chain(store, tmp_path)] == ["missing_file"]


def test_seal_does_not_reseal_gz_of_unchanged_file(tmp_path):
    """เดิมผนึก .gz ซ้ำเป็นรายการใหม่ทุกไฟล์ (manifest บน Pi มีแถวซ้ำ 6 คู่ hash เดียวกัน)"""
    f = tmp_path / "dnsmasq.log-2026-09-16"
    f.write_text("query 1\n", encoding="utf-8")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store)
    _compress_like_logrotate(f)

    assert seal_directory(tmp_path, store) == []
    assert len(store.all_entries()) == 1


def test_seal_records_gz_whose_content_differs_from_the_sealed_original(tmp_path):
    f = tmp_path / "dnsmasq.log-2026-09-16"
    f.write_text("query 1\n", encoding="utf-8")
    store = MemoryManifestStore()
    seal_directory(tmp_path, store)
    f.write_text("query 1\nเพิ่มหลังผนึก\n", encoding="utf-8")
    _compress_like_logrotate(f)

    sealed = seal_directory(tmp_path, store)
    assert [e.filename for e in sealed] == ["dnsmasq.log-2026-09-16.gz"]


# ================== N31: เหตุการณ์จราจรหายตอนทราฟฟิกหนัก (ENOBUFS) และหายตอน DB สะดุด
def _rec(port=1234):
    return ConnRecord(ts=1789000000.0, src_ip="10.10.0.5", src_port=port, dst_ip="1.1.1.1",
                     dst_port=443, proto="tcp", bytes_out=100, bytes_in=200)


class _Cache:
    def get(self, ip, now=None):
        return "AA:BB:CC:DD:EE:01"


def test_flush_keeps_records_when_db_fails(monkeypatch):
    """คอมเมนต์เดิมบอกว่า 'จะลองใหม่รอบถัดไป' แต่โค้ดเดิม clear() ทิ้งทันที -- DB สะดุดครู่เดียว
    (MariaDB ถูกรีสตาร์ทตอนติดตั้ง) ข้อมูลจราจรช่วงนั้นหายถาวร"""
    monkeypatch.setattr(conn_collector, "insert_conn_records",
                       lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("DB ล่ม")))
    buf = [_rec(1), _rec(2)]

    assert flush_buffer(buf, _Cache()) == 0
    assert len(buf) == 2, "ต้องเก็บไว้ลองใหม่ ไม่ใช่ทิ้ง"


def test_flush_clears_only_after_success(monkeypatch):
    monkeypatch.setattr(conn_collector, "insert_conn_records", lambda recs, cache: len(recs))
    buf = [_rec(1), _rec(2)]

    assert flush_buffer(buf, _Cache()) == 2
    assert buf == []


def test_flush_drops_oldest_when_db_down_too_long(monkeypatch):
    """DB ล่มยาวต้องไม่ทำให้หน่วยความจำบวมไม่มีที่สิ้นสุด แต่การทิ้งต้องถูกบันทึกไว้"""
    monkeypatch.setattr(conn_collector, "insert_conn_records",
                       lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("DB ล่ม")))
    buf = [_rec(i) for i in range(10)]

    flush_buffer(buf, _Cache(), max_pending=6)

    assert len(buf) == 6
    assert buf[0].src_port == 4, "ต้องทิ้งของเก่าสุดก่อน เก็บของใหม่ไว้"


def test_dns_flush_retries_without_losing_buffer(monkeypatch):
    row = dict(ts=NOW, client_ip="10.10.0.5", qname="example.test",
               qtype="A", answer=None, event_kind="query")
    buffer = [row]
    monkeypatch.setattr(dns_collector, "insert_dns_rows",
                        lambda *a: (_ for _ in ()).throw(RuntimeError("DB down")))
    assert dns_collector.flush_buffer(buffer, _Cache()) == 0
    assert buffer == [row]
    monkeypatch.setattr(dns_collector, "insert_dns_rows", lambda rows, cache: len(rows))
    assert dns_collector.flush_buffer(buffer, _Cache()) == 1
    assert buffer == []


def test_dns_collector_reopens_rotated_file_from_start(tmp_path, monkeypatch):
    path = tmp_path / "dnsmasq.log"
    path.write_text("", encoding="utf-8")
    seen = []
    monkeypatch.setattr(dns_collector, "insert_dns_rows",
                        lambda rows, cache, **kw: seen.extend(rows) or len(rows))
    calls = [0]

    class StopCollector(Exception):
        pass

    def rotate_then_stop(_seconds):
        calls[0] += 1
        if calls[0] == 1:
            path.rename(tmp_path / "dnsmasq.log-2026-08-22")
            path.write_text(
                "Aug 22 10:15:32 dnsmasq[1]: query[A] example.test from 10.10.0.5\n"
                "Aug 22 10:15:33 dnsmasq[1]: reply example.test is 192.0.2.1\n",
                encoding="utf-8")
        if calls[0] > 3:
            raise StopCollector

    class Stop:  # R2-06: ลูปรอด้วย stop_event.wait() แทน time.sleep() เพื่อหยุดได้ทันที
        def is_set(self): return False
        def wait(self, seconds): rotate_then_stop(seconds)

    with pytest.raises(StopCollector):
        dns_collector.run_forever(str(path), batch_size=1, flush_interval=0, stop_event=Stop())
    assert [r["event_kind"] for r in seen] == ["query", "answer"]


def test_conn_event_with_unknown_mac_is_inserted(monkeypatch):
    import contextlib
    import common.db as db
    inserted = []

    class Cursor:
        def executemany(self, sql, rows):
            inserted.extend(rows)
        def __enter__(self): return self
        def __exit__(self, *args): return False

    class Conn:
        def cursor(self): return Cursor()

    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(Conn()))

    class MissingMac:
        def get(self, ip): return None

    assert conn_collector.insert_conn_records([_rec()], MissingMac()) == 1
    assert inserted[0][2] is None  # (ts, started_at, mac, ...)


# ---------------------------------------------------------------- R2-02 ผูก MAC ตอน NEW
NEW_WITH_ID = ("[1789000000.0] [NEW] ipv4     2 tcp      6 120 SYN_SENT "
               "src=10.10.0.50 dst=93.184.216.34 sport=40000 dport=443 [UNREPLIED] "
               "src=93.184.216.34 dst=10.10.0.50 sport=443 dport=40000 id=3141592")
DESTROY_WITH_ID = ("[1789000900.0] [DESTROY] ipv4     2 tcp      6 "
                   "src=10.10.0.50 dst=93.184.216.34 sport=40000 dport=443 packets=10 bytes=900 "
                   "src=93.184.216.34 dst=10.10.0.50 sport=443 dport=40000 packets=8 bytes=7000 "
                   "[ASSURED] delta-time=900 id=3141592")


class _SwitchableArp:
    """ARP ที่เปลี่ยนเจ้าของ IP ได้ -- จำลอง DHCP แจก IP เดิมให้ลูกค้าคนใหม่"""
    def __init__(self, mac):
        self.mac = mac
    def get(self, ip, now=None):
        return self.mac


def test_parse_event_reads_id_and_kernel_delta_time():
    ev, rec = conn_collector.parse_conntrack_event(DESTROY_WITH_ID)
    assert ev == "DESTROY" and rec.ct_id == "3141592"
    assert rec.started_at == 1789000000.0, "เวลาเริ่ม = เวลา DESTROY - delta-time"
    assert rec.bytes_out == 900 and rec.bytes_in == 7000


def test_parse_line_still_returns_only_destroy():
    assert parse_conntrack_line(NEW_WITH_ID) is None
    assert parse_conntrack_line(DESTROY_WITH_ID).ct_id == "3141592"


def test_client_filter_keeps_both_events_for_original_client_source():
    client_iface = ipaddress.IPv4Interface("10.10.0.1/24")
    tracker = conn_collector.ConnTracker(_SwitchableArp("AA:AA:AA:AA:AA:01"))
    new = conn_collector.parse_client_conntrack_event(NEW_WITH_ID, client_iface)
    destroy = conn_collector.parse_client_conntrack_event(DESTROY_WITH_ID, client_iface)

    assert new[0] == "NEW" and destroy[0] == "DESTROY"
    assert tracker.feed(*new) is None
    assert len(tracker) == 1
    assert tracker.feed(*destroy).mac == "AA:AA:AA:AA:AA:01"
    assert len(tracker) == 0


def test_client_filter_excludes_pi_gateway_uplink_and_outside_sources():
    client_iface = ipaddress.IPv4Interface("10.10.0.1/24")
    for src in ("10.10.0.1", "192.168.1.2", "192.168.1.20", "10.10.1.50", "2001:db8::1"):
        for original in (NEW_WITH_ID, DESTROY_WITH_ID):
            line = original.replace("src=10.10.0.50", f"src={src}", 1)
            assert conn_collector.parse_client_conntrack_event(line, client_iface) is None


def test_conn_collector_requires_client_cidr(monkeypatch):
    monkeypatch.delenv("CLIENT_CIDR", raising=False)
    with pytest.raises(RuntimeError, match="CLIENT_CIDR"):
        conn_collector.run_forever()
    monkeypatch.setenv("CLIENT_CIDR", "not-a-network")
    with pytest.raises(RuntimeError, match="CLIENT_CIDR"):
        conn_collector.run_forever()


def test_ip_reassigned_between_new_and_destroy_keeps_original_mac():
    """R2-02: IP เดียวกันเปลี่ยน MAC ระหว่าง NEW กับ DESTROY -- record ต้องได้ MAC ของคนที่เปิด
    connection ไม่ใช่ของผู้ถือ IP ณ ตอน DESTROY"""
    arp = _SwitchableArp("AA:AA:AA:AA:AA:01")
    tracker = conn_collector.ConnTracker(arp)
    assert tracker.feed(*conn_collector.parse_conntrack_event(NEW_WITH_ID)) is None

    arp.mac = "BB:BB:BB:BB:BB:02"  # ลูกค้าคนเก่าออกไป DHCP แจก 10.10.0.50 ให้คนใหม่
    rec = tracker.feed(*conn_collector.parse_conntrack_event(DESTROY_WITH_ID))

    assert rec.mac == "AA:AA:AA:AA:AA:01"
    assert rec.started_at == 1789000000.0 and rec.ts == 1789000900.0
    assert len(tracker) == 0, "DESTROY แล้วต้องลืม connection นั้น"


def test_destroy_without_new_does_not_guess_from_current_arp():
    """collector เพิ่งเริ่ม (ไม่เห็น NEW) -- ห้ามใช้ ARP ปัจจุบันเพราะอาจเป็นคนใหม่"""
    tracker = conn_collector.ConnTracker(_SwitchableArp("BB:BB:BB:BB:BB:02"))
    rec = tracker.feed(*conn_collector.parse_conntrack_event(DESTROY_WITH_ID))
    assert rec.mac is None and rec.started_at == 1789000000.0


def test_tracker_evicts_oldest_when_full():
    tracker = conn_collector.ConnTracker(_SwitchableArp("AA:AA:AA:AA:AA:01"), max_open=2)
    for i in range(3):
        tracker.feed("NEW", conn_collector.replace(_rec(i), ct_id=str(i)))
    assert len(tracker) == 2 and tracker.evicted == 1
    assert tracker.feed("DESTROY", conn_collector.replace(_rec(0), ct_id="0")).mac is None
    assert tracker.feed("DESTROY", conn_collector.replace(_rec(2), ct_id="2")).mac == "AA:AA:AA:AA:AA:01"


def _fake_db(monkeypatch, session_macs):
    import contextlib
    import common.db as db
    state = dict(inserted=[], lookups=[])

    class Cursor:
        def execute(self, sql, params):
            state["lookups"].append(params)
        def fetchall(self):
            return [dict(mac=m) for m in session_macs]
        def executemany(self, sql, rows):
            state["sql"] = sql
            state["inserted"].extend(rows)
        def __enter__(self): return self
        def __exit__(self, *args): return False

    class Conn:
        def cursor(self): return Cursor()

    monkeypatch.setattr(db, "get_conn", lambda: contextlib.nullcontext(Conn()))
    return state


def test_insert_uses_captured_mac_and_started_at(monkeypatch):
    state = _fake_db(monkeypatch, [])
    rec = conn_collector.replace(_rec(), mac="AA:AA:AA:AA:AA:01", started_at=1788999000.0)
    assert conn_collector.insert_conn_records([rec]) == 1
    row = state["inserted"][0]
    assert "started_at" in state["sql"]
    assert row[1] == datetime.fromtimestamp(1788999000.0) and row[2] == "AA:AA:AA:AA:AA:01"
    assert state["lookups"] == [], "มี MAC จากตอน NEW แล้ว ไม่ต้องค้นประวัติ"


def test_insert_falls_back_to_session_history_at_start_time(monkeypatch):
    state = _fake_db(monkeypatch, ["AA:AA:AA:AA:AA:01"])
    rec = conn_collector.replace(_rec(), started_at=1788999000.0)
    conn_collector.insert_conn_records([rec])
    assert state["lookups"][0][1] == datetime.fromtimestamp(1788999000.0), \
        "ต้องค้นด้วยเวลาเริ่ม ไม่ใช่เวลา DESTROY"
    assert state["inserted"][0][2] == "AA:AA:AA:AA:AA:01"


def test_insert_leaves_mac_empty_when_history_is_ambiguous(monkeypatch):
    state = _fake_db(monkeypatch, ["AA:AA:AA:AA:AA:01", "BB:BB:BB:BB:BB:02"])
    conn_collector.insert_conn_records([conn_collector.replace(_rec(), started_at=1788999000.0)])
    assert state["inserted"][0][2] is None


def test_logger_process_exits_nonzero_if_collector_stops(monkeypatch):
    from logger import run_all

    class DeadThread:
        def __init__(self, *args, **kwargs):
            self.name = kwargs["name"]
        def start(self): pass
        def is_alive(self): return False
        def join(self, timeout=None): pass

    import threading
    monkeypatch.setattr(run_all.threading, "Thread", DeadThread)
    monkeypatch.setattr(run_all.signal, "signal", lambda *a: None)
    monkeypatch.setattr(run_all, "_stop", threading.Event())
    assert run_all.main() == 1


def test_stderr_drain_flags_enobufs_as_evidence_loss():
    """ENOBUFS = เคอร์เนลทิ้งเหตุการณ์ = หลักฐานไม่ครบ ต้องดังพอให้เห็น ไม่ใช่เงียบแบบเดิม
    (ของเดิมไม่เคยอ่าน stderr เลย ถ้าท่อเต็ม conntrack ก็ค้างไปทั้งระบบ)"""
    seen = []
    conn_collector._drain_stderr(
        iter(["WARNING: We have hit ENOBUFS! We are losing events.", "", "NOTICE: buffer set"]),
        on_event_loss=seen.append)

    assert len(seen) == 1 and "ENOBUFS" in seen[0]


def test_parse_kernel_start_bracket_takes_precedence(monkeypatch):
    """R2-02: รูปแบบ `[start=<ctime>]` จาก nf_conntrack_timestamp (conntrack -o ktimestamp)"""
    import time as _time
    start = _time.mktime(_time.strptime("Tue Sep 29 10:00:00 2026", "%a %b %d %H:%M:%S %Y"))
    line = ("[1790000000.0] [DESTROY] ipv4     2 udp      17 src=10.10.0.9 dst=8.8.8.8 "
            "sport=5000 dport=53 src=8.8.8.8 dst=10.10.0.9 sport=53 dport=5000 "
            "[start=Tue Sep 29 10:00:00 2026] [stop=Tue Sep 29 10:03:00 2026] delta-time=5 id=7")
    ev, rec = conn_collector.parse_conntrack_event(line)
    assert ev == "DESTROY" and rec.started_at == start and rec.ct_id == "7"
    assert rec.proto == "udp" and rec.dst_port == 53


def test_conntrack_cmd_filters_client_network_in_kernel():
    """N43: ทิ้งเหตุการณ์ที่ไม่ใช่ของวงลูกค้าตั้งแต่ในเคอร์เนล ไม่ให้กินบัฟเฟอร์จน ENOBUFS"""
    import ipaddress
    from logger.conn_collector import build_conntrack_cmd
    cmd = build_conntrack_cmd(ipaddress.IPv4Interface("10.10.0.1/24").network)
    assert cmd[:2] == ["conntrack", "-E"]
    assert cmd[cmd.index("-s") + 1] == "10.10.0.0/24"
    assert "NEW,DESTROY" in cmd and "--buffer-size" in cmd
