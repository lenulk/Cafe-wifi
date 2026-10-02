"""
tools/export_evidence.py — ส่งออกข้อมูลจราจร (conn_log/dns_log) เป็นหลักฐานตามคำสั่งเจ้าหน้าที่

ใช้งาน:
    python -m tools.export_evidence --mac AA:BB:CC:DD:EE:FF --from 2026-08-01 --to 2026-08-22
    python -m tools.export_evidence --natid 1234567890123 --from 2026-08-01 --to 2026-08-22

--natid หา customer จาก natid_hash แล้วส่งออกเฉพาะแถวที่โยงกลับไปหาลูกค้ารายนั้นได้แบบไม่กำกวม
(mac + ip + ช่วงเวลาของ portal_session ด้วย JOIN ชุดเดียวกับหน้า /logs) แถวที่เข้าได้หลาย session
จะไม่ถูกเดาใส่ให้ใคร -- ใช้ --mac ค้นต่อเองถ้าต้องการ

ทุกครั้งที่ export จะ:
  1. เขียนไฟล์ CSV (conn_log และ dns_log แยกไฟล์) พร้อมคอลัมน์ voucher_username และ
     natid_masked (ไม่มีเลขบัตรเต็มในไฟล์) สิทธิ์ไฟล์ 0600 เพราะเป็นข้อมูลจราจรจำนวนมาก
  2. คำนวณ SHA-256 ของแต่ละไฟล์ แล้วเขียน manifest .json คู่กัน (พิสูจน์ทีหลังว่าไฟล์ไม่ถูกแก้)
  3. บันทึก audit_log ว่าใคร export อะไร เมื่อไหร่ (สำคัญมากตาม PDPA — นี่คือการเข้าถึง
     ข้อมูลผู้ใช้จำนวนมากในครั้งเดียว ต้องมีร่องรอยเสมอ)
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from common.log_mapping import conn_mapping_join, dns_mapping_join

log = logging.getLogger("cafe-wifi.export")

CONN_FIELDS = ["ts", "started_at", "mac", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
               "bytes_out", "bytes_in", "voucher_username", "natid_masked",
               "device_hostname", "device_os"]
DNS_FIELDS = ["ts", "event_kind", "client_ip", "mac", "qname", "qtype", "answer",
              "voucher_username", "natid_masked", "device_hostname", "device_os"]

_MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")


@dataclass(frozen=True)
class ExportedFile:
    path: Path
    sha256: str
    row_count: int


def rows_to_csv_text(rows: list[dict], fieldnames: list[str]) -> str:
    """แปลง list ของ dict เป็นข้อความ CSV — แยกจาก I/O เพื่อทดสอบง่าย"""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize_mac(mac: str | None) -> str | None:
    """
    R2-10: DB เก็บ MAC เป็นตัวพิมพ์ใหญ่คั่นด้วย ':' เสมอ -- เดิมใส่ `aa:bb:…` แล้วได้ 0 แถวแบบ
    เงียบ ๆ (ไฟล์หลักฐานว่างทั้งที่มีข้อมูลจริง) จึงแปลงให้ และปฏิเสธรูปแบบที่ผิดแทนการคืน 0 แถว
    """
    if mac is None or not mac.strip():
        return None
    norm = mac.strip().upper().replace("-", ":")
    if not _MAC_RE.match(norm):
        raise ValueError(f"รูปแบบ MAC ไม่ถูกต้อง: {mac!r} (ต้องเป็น AA:BB:CC:DD:EE:FF)")
    return norm


def _write_private(path: Path, text: str) -> None:
    """
    R2-10: เขียนไฟล์สิทธิ์ 0600 ตั้งแต่ตอนสร้าง (ไม่ใช่ chmod ทีหลัง ซึ่งมีช่วงที่ไฟล์เป็น 0644
    ตาม umask ปริยาย) ไฟล์ส่งออกคือข้อมูลจราจรจำนวนมากที่โยงถึงตัวบุคคลได้
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as f:
        if hasattr(os, "fchmod"):
            os.fchmod(f.fileno(), 0o600)  # เผื่อไฟล์มีอยู่ก่อนด้วยสิทธิ์อื่น
        f.write(text)


def write_export_file(rows: list[dict], fieldnames: list[str], out_path: Path) -> ExportedFile:
    text = rows_to_csv_text(rows, fieldnames)
    out_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_private(out_path, text)
    return ExportedFile(path=out_path, sha256=sha256_text(text), row_count=len(rows))


def build_manifest(files: list[ExportedFile], criteria: dict) -> dict:
    return {
        "generated_at": datetime.now().isoformat(),
        "criteria": criteria,
        "files": [{"filename": f.path.name, "sha256": f.sha256, "row_count": f.row_count}
                 for f in files],
        "note": "ตรวจสอบไฟล์ไม่ถูกแก้ไข: sha256sum <ชื่อไฟล์> แล้วเทียบกับค่าในนี้",
    }


def parse_range_end(value: str) -> datetime:
    """
    N32 (พบตอนทดสอบส่งออกหลักฐานบน Pi จริง 2026-09-20): ถ้าผู้ใช้ระบุวันสิ้นสุดเป็นวันที่เปล่า ๆ
    (YYYY-MM-DD) ให้หมายถึง **สิ้นวันนั้น** ไม่ใช่เที่ยงคืนต้นวัน

    ของเดิม `--to 2026-09-20` = 2026-09-20 00:00:00 ทำให้ข้อมูลของวันที่ 20 ทั้งวันไม่ติดมาใน
    ไฟล์หลักฐานเลย (เงียบ ๆ ไม่มี error) และขอข้อมูลวันเดียว (--from กับ --to วันเดียวกัน) ก็ถูก
    ปฏิเสธด้วย "วันที่สิ้นสุดต้องอยู่หลังวันที่เริ่มต้น" ทั้งที่เป็นคำขอที่พบบ่อยที่สุดจากเจ้าหน้าที่
    ถ้าระบุเวลามาด้วยจะใช้ตามที่ระบุ ไม่ไปยุ่ง
    """
    dt = datetime.fromisoformat(value)
    if len(value.strip()) == 10:  # "YYYY-MM-DD" ไม่มีส่วนเวลา
        dt = dt.replace(hour=23, minute=59, second=59, microsecond=999999)
    return dt


def build_conn_query(start: datetime, end: datetime, mac: str | None = None,
                     ip: str | None = None, customer_id: int | None = None) -> tuple[str, tuple]:
    """กรองช่วงด้วย ts (ตรงกับหน้า /logs และ partition) แล้วโยงตัวบุคคลด้วย JOIN ชุดเดียวกับ /logs"""
    sql = ("SELECT cl.ts, cl.started_at, cl.mac, cl.src_ip, cl.src_port, cl.dst_ip, cl.dst_port, "
           "cl.proto, cl.bytes_out, cl.bytes_in, v.username AS voucher_username, c.natid_masked, "
           "ps.hostname AS device_hostname, ps.os_label AS device_os "
           "FROM conn_log cl" + conn_mapping_join() + " WHERE cl.ts BETWEEN %s AND %s")
    params: list = [start, end]
    if mac:
        sql += " AND cl.mac = %s"; params.append(mac)
    if ip:
        sql += " AND cl.src_ip = %s"; params.append(ip)
    if customer_id is not None:
        sql += " AND c.id = %s"; params.append(customer_id)
    return sql + " ORDER BY cl.ts", tuple(params)


def build_dns_query(start: datetime, end: datetime, mac: str | None = None,
                    ip: str | None = None, customer_id: int | None = None) -> tuple[str, tuple]:
    sql = ("SELECT dl.ts, dl.event_kind, dl.client_ip, dl.mac, dl.qname, dl.qtype, dl.answer, "
           "v.username AS voucher_username, c.natid_masked, "
           "ps.hostname AS device_hostname, ps.os_label AS device_os "
           "FROM dns_log dl" + dns_mapping_join() + " WHERE dl.ts BETWEEN %s AND %s")
    params: list = [start, end]
    if mac:
        sql += " AND dl.mac = %s"; params.append(mac)
    if ip:
        sql += " AND dl.client_ip = %s"; params.append(ip)
    if customer_id is not None:
        sql += " AND c.id = %s"; params.append(customer_id)
    return sql + " ORDER BY dl.ts", tuple(params)


def find_customer(natid: str, query_one_fn) -> dict | None:
    """หา customer ด้วย natid_hash -- คืนแค่ id กับค่า mask ไม่แตะ natid_enc"""
    from common import crypto
    nid = crypto.normalize_natid(natid)
    if not crypto.valid_thai_id(nid):
        raise ValueError("เลขประจำตัวประชาชนไม่ถูกต้อง (ตรวจ checksum ไม่ผ่าน)")
    return query_one_fn("SELECT id, natid_masked FROM customer WHERE natid_hash = %s",
                        (crypto.natid_hash(nid),))


# คู่ (mac, ip) ทุกคู่ที่ลูกค้าเคยได้รับสิทธิ์ก่อนสิ้นสุดช่วง -- ไม่ตัดด้วย ended_at >= start
# เพราะ connection ที่เริ่มใน session เก่าอาจจบ (ts) ภายในช่วงที่ขอ ตัวกรองจริงคือ c.id ใน
# JOIN ส่วนนี้แค่จำกัดให้แต่ละคิวรี่ใช้ index (mac, ts) ได้
_CUSTOMER_PAIRS_SQL = (
    "SELECT DISTINCT ps.mac, ps.ip FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id"
    " WHERE v.customer_id = %s AND ps.authenticated_at IS NOT NULL AND ps.authenticated_at <= %s")


def query_customer_rows(build_query_fn, customer_id: int, start: datetime, end: datetime,
                        query_all_fn) -> list[dict]:
    """
    R2-10 --natid: ส่งออกตาม mac + ip + ช่วงเวลาของแต่ละ session ของลูกค้า คู่ (mac, ip) ต่างกัน
    ให้แถวไม่ซ้ำกันเสมอ จึงรวมผลได้ตรง ๆ แล้วเรียงตามเวลาอีกรอบ
    """
    rows: list[dict] = []
    for pair in query_all_fn(_CUSTOMER_PAIRS_SQL, (customer_id, end)):
        sql, params = build_query_fn(start, end, mac=pair["mac"], ip=pair["ip"],
                                     customer_id=customer_id)
        rows.extend(query_all_fn(sql, params))
    rows.sort(key=lambda r: r["ts"])
    return rows


def export(mac: str | None, start: datetime, end: datetime, out_dir: Path,
          query_conn_fn, query_dns_fn, staff_id: int | None = None,
          customer: dict | None = None) -> dict:
    """
    customer = {"id", "natid_masked"} เมื่อส่งออกตามเลขบัตร (--natid) -- ไม่รับเลขบัตรเต็มเข้ามา
    เลย เพื่อไม่ให้หลุดไปอยู่ใน audit_log, ชื่อไฟล์ หรือ manifest
    """
    if end <= start:
        raise ValueError("วันที่สิ้นสุดต้องอยู่หลังวันที่เริ่มต้น")
    mac = normalize_mac(mac)

    if customer is not None:
        target = f"customer:{customer['id']}"
        tag = f"customer{customer['id']}"
    else:
        target = mac or "ALL"
        tag = (mac or "all").replace(":", "")

    from common import audit
    audit.log_required(audit.EXPORT_LOG, staff_id=staff_id, target=target,
                       detail=f"requested range={start}..{end}")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    conn_rows = query_conn_fn(mac, start, end)
    dns_rows = query_dns_fn(mac, start, end)

    conn_file = write_export_file(conn_rows, CONN_FIELDS, out_dir / f"conn_log_{tag}_{stamp}.csv")
    dns_file = write_export_file(dns_rows, DNS_FIELDS, out_dir / f"dns_log_{tag}_{stamp}.csv")

    criteria = dict(mac=mac, start=start.isoformat(), end=end.isoformat())
    if customer is not None:
        criteria.update(customer_id=customer["id"], natid_masked=customer["natid_masked"])
    manifest = build_manifest([conn_file, dns_file], criteria)
    manifest_path = out_dir / f"manifest_{tag}_{stamp}.json"
    _write_private(manifest_path, json.dumps(manifest, ensure_ascii=False, indent=2))

    return {"manifest_path": manifest_path, "conn_file": conn_file, "dns_file": dns_file}


def build_parser():
    import argparse

    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    who = p.add_mutually_exclusive_group()
    who.add_argument("--mac", help="กรองเฉพาะ MAC นี้ (ไม่ใส่ทั้งคู่ = ทุกเครื่อง)")
    who.add_argument("--natid", help="เลขประจำตัวประชาชน 13 หลัก -- ส่งออกเฉพาะข้อมูลของลูกค้ารายนี้")
    p.add_argument("--from", dest="start", required=True, help="YYYY-MM-DD")
    p.add_argument("--to", dest="end", required=True,
                  help="YYYY-MM-DD (นับถึงสิ้นวันนั้น) หรือระบุเวลาเองเป็น YYYY-MM-DDTHH:MM:SS")
    p.add_argument("--out", default="/var/log/cafe-wifi/exports")
    return p


def _cli() -> int:  # pragma: no cover
    from common.db import query_all, query_one

    p = build_parser()
    args = p.parse_args()

    start = datetime.fromisoformat(args.start)
    end = parse_range_end(args.end)

    customer = None
    if args.natid:
        try:
            customer = find_customer(args.natid, query_one)
        except ValueError as e:
            p.error(str(e))
        if customer is None:
            print("ไม่พบลูกค้าที่มีเลขประจำตัวประชาชนนี้")
            return 1

    def q_conn(mac, s, e):
        if customer is not None:
            return query_customer_rows(build_conn_query, customer["id"], s, e, query_all)
        return query_all(*build_conn_query(s, e, mac=mac))

    def q_dns(mac, s, e):
        if customer is not None:
            return query_customer_rows(build_dns_query, customer["id"], s, e, query_all)
        return query_all(*build_dns_query(s, e, mac=mac))

    logging.basicConfig(level=logging.INFO)
    try:
        result = export(args.mac, start, end, Path(args.out), q_conn, q_dns, customer=customer)
    except ValueError as e:
        p.error(str(e))
    print(f"ส่งออกสำเร็จ: {result['manifest_path']}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_cli())
