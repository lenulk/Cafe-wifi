"""
logger/conn_collector.py — เก็บข้อมูลจราจร (metadata เท่านั้น, D5) จาก `conntrack -E`

รันจริงต้องใช้สิทธิ์ CAP_NET_ADMIN/CAP_NET_RAW (systemd unit cafe-logger.service ให้ไว้แล้ว)
และต้องเปิด accounting ของเคอร์เนลก่อนจึงจะได้ตัวเลข bytes:
    sysctl -w net.netfilter.nf_conntrack_acct=1
และ (R2-02) เปิด timestamp ของ connection เพื่อให้ DESTROY บอกได้ว่า connection เริ่มเมื่อไร:
    sysctl -w net.netfilter.nf_conntrack_timestamp=1

ไฟล์นี้แยกส่วน "แปลงข้อความ 1 บรรทัดเป็นข้อมูล" (parse_conntrack_line, ทดสอบได้ล้วน ๆ
ไม่ต้องมี conntrack จริง) ออกจากส่วน "รันจริงแบบ stream ต่อเนื่อง" (run_forever)
เพื่อให้ตรรกะหลักตรวจสอบได้โดยไม่ต้องพึ่งฮาร์ดแวร์/สิทธิ์ root
"""
from __future__ import annotations

import ipaddress
import logging
import os
import queue
import re
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace

from .netutil import MacCache
from .telemetry import CollectorTelemetry

log = logging.getLogger("cafe-wifi.conn_collector")

# N31 (พบบน Pi จริง 2026-09-20 ขณะทดสอบโควตาด้วยการโหลดไฟล์ 100 MB หลายรอบ):
# `conntrack -E` พ่น "WARNING: We have hit ENOBUFS! We are losing events." ออก stderr
# แปลว่าเคอร์เนลทิ้งเหตุการณ์เพราะบัฟเฟอร์ netlink เต็ม -> conn_log ขาดหายจริง (วัดได้: โหลด
# 5 ไฟล์ บันทึกได้ 2) ซึ่งร้ายแรงมากสำหรับหลักฐานตาม ม.26 เพราะช่วงที่ร้านคนเยอะคือช่วงที่
# log ต้องครบที่สุด · ของเดิมยังไม่เคยอ่าน stderr เลย คำเตือนจึงไม่มีใครเห็น และถ้าท่อ stderr
# เต็ม (64 KB) conntrack จะค้าง = หยุดเก็บ log ทั้งระบบแบบเงียบ ๆ
# 2026-09-20 รอบสอง: 8 MB ยังไม่พอ -- ยังเจอ ENOBUFS ตอนโหลดไฟล์ต่อเนื่อง (เห็นช้าเพราะ
# stderr ของ conntrack ถูกพักในบัฟเฟอร์ก่อนไหลออกมา ทำให้ตอนเช็คทันทีหลังทดสอบยังไม่เห็น)
# เคอร์เนลจะคูณสองให้อีกที และ conntrack ใช้ SO_RCVBUFFORCE จึงข้ามเพดาน net.core.rmem_max ได้
NETLINK_BUFFER_BYTES = 32 * 1024 * 1024
# คิวกันการอ่านช้าเพราะรอเขียน DB -- ตัวอ่านต้องว่างตลอดเพื่อไม่ให้ท่อจากเคอร์เนลตัน
EVENT_QUEUE_MAX = 20000
# เพดานเรคคอร์ดที่ค้างรอเขียนตอน DB ล่ม (กันหน่วยความจำบวมไม่มีที่สิ้นสุด)
MAX_PENDING_RECORDS = 20000
# R2-02: เพดานจำนวน connection ที่เปิดค้างอยู่ซึ่งเราจำ MAC ไว้ (ต่อรายการ ~200 ไบต์ -> ~25 MB)
MAX_OPEN_CONNS = 131072
PIPE_BUFFER_BYTES = 1024 * 1024  # N39 -- ท่อปริยาย 64 KB เต็มได้ในชุดเดียวตอน conntrack เก็บกวาด
F_SETPIPE_SZ = 1031              # ค่าคงที่ของ Linux (ไม่มีใน fcntl ของ Python)

_BRACKET_RE = re.compile(r"\[([^\]]*)\]")
_KV_RE = re.compile(r"(\w+)=(\S+)")
_TS_RE = re.compile(r"^\[(\d+\.\d+)\]")
_DELTA_RE = re.compile(r"\bdelta-time=(\d+)")

# บันทึกลง conn_log เฉพาะ DESTROY เพราะเป็น event เดียวที่มีตัวเลข bytes สุดท้าย
# R2-02: แต่ต้องฟัง NEW ด้วยเพื่อจับ MAC + เวลาเริ่ม ณ ตอนที่ connection เปิดจริง -- ถ้าไปหา
# MAC ตอน DESTROY (ซึ่งช้ากว่าได้ตั้งแต่ 2 นาทีถึง 5 วัน) IP นั้นอาจถูก DHCP แจกให้คนอื่นไปแล้ว
# UPDATE ไม่สนใจ
INTERESTING_EVENTS = {"NEW", "DESTROY"}


@dataclass(frozen=True)
class ConnRecord:
    ts: float
    proto: str
    src_ip: str
    src_port: int | None
    dst_ip: str
    dst_port: int | None
    bytes_out: int
    bytes_in: int
    # R2-02: id จาก `-o id` ใช้จับคู่ NEW กับ DESTROY ของ connection เดียวกัน
    ct_id: str | None = None
    # R2-02: เวลาที่ connection เริ่ม (ts คือเวลาจบ = DESTROY) -- None ถ้าไม่รู้
    started_at: float | None = None
    # R2-02: MAC ที่จับไว้ตอน NEW (ไม่ใช่ตอนเขียน DB)
    mac: str | None = None


def _proto_norm(p: str) -> str:
    p = p.lower()
    return p if p in {"tcp", "udp", "icmp"} else "other"


def _parse_kernel_start(brackets: list[str], ts: float, body: str) -> float | None:
    """R2-02: เวลาเริ่ม connection จาก nf_conntrack_timestamp -- `[start=<ctime>]` ถ้ามี
    ไม่งั้นใช้ `delta-time=<วินาที>` (ระยะเวลาทั้งหมดของ connection) ย้อนจากเวลา DESTROY"""
    for b in brackets:
        if b.startswith("start="):
            try:
                return time.mktime(time.strptime(b[len("start="):].strip(), "%a %b %d %H:%M:%S %Y"))
            except ValueError:
                pass
    m = _DELTA_RE.search(body)
    if m:
        return ts - int(m.group(1))
    return None


def parse_conntrack_event(line: str, now: float | None = None) -> tuple[str, ConnRecord] | None:
    """
    แปลงบรรทัดหนึ่งจาก `conntrack -E -o timestamp,extended,id -e NEW,DESTROY`
    เป็น (ชื่อ event, record) -- คืน None ถ้าไม่ใช่ event ที่สนใจ หรือ parse ไม่ได้ (บันทึก
    warning แล้วข้าม ไม่ throw เพื่อไม่ให้ 1 บรรทัดเสียทำให้ collector ทั้งตัวตายทั้งกระบวนการ)
    """
    line = line.strip()
    if not line:
        return None

    ts = now if now is not None else time.time()
    m = _TS_RE.match(line)
    if m:
        try:
            ts = float(m.group(1))
        except ValueError:
            pass
        line = _TS_RE.sub("", line, count=1).strip()

    brackets = _BRACKET_RE.findall(line)
    event = brackets[0].upper() if brackets else ""
    if INTERESTING_EVENTS and event not in INTERESTING_EVENTS:
        return None

    started_at = _parse_kernel_start(brackets, ts, line) if event == "DESTROY" else None
    body = _BRACKET_RE.sub(" ", _DELTA_RE.sub(" ", line))
    tokens = body.split()
    proto = "other"
    # *** แก้บั๊ก (พบจาก conntrack ตัวจริงบน VM lab, 2026-08-28) *** — เดิมเข้าใจว่า token
    # ที่ไม่ใช่ตัวเลข/key=value ตัวแรกคือชื่อโปรโตคอล แต่ผลจริงจาก `conntrack -E -o
    # timestamp,extended` ขึ้นต้นด้วย address family ("ipv4"/"ipv6") ก่อนเสมอ เช่น
    # "ipv4     2 tcp      6 72 TIME_WAIT src=... dst=..." -- โค้ดเดิมเจอ "ipv4" เป็น
    # token แรกที่เข้าเงื่อนไข แล้ว _proto_norm("ipv4") คืน "other" ทันทีแบบไม่ทันได้
    # เห็น "tcp" ที่ตามมาเลย -- ผลคือ proto เป็น "other" 100% ของทุกแถวเสมอ (ยืนยันจาก
    # conn_log จริงบน VM lab: 16/16 แถวเป็น "other" หมด ทั้งที่มี TCP/UDP จริงปนอยู่)
    # ต้องข้าม "ipv4"/"ipv6" ไปก่อนถึงจะเจอ token ที่เป็นชื่อโปรโตคอลจริง
    for tok in tokens:
        if tok.lower() in ("ipv4", "ipv6"):
            continue
        if "=" not in tok and not tok.isdigit():
            proto = _proto_norm(tok)
            break

    kv_first: dict[str, str] = {}
    byte_values: list[int] = []
    for k, v in _KV_RE.findall(body):
        if k == "bytes":
            try:
                byte_values.append(int(v))
            except ValueError:
                pass
            continue
        kv_first.setdefault(k, v)  # การเกิดครั้งแรก = ทิศทาง original (client -> server)

    src_ip = kv_first.get("src")
    dst_ip = kv_first.get("dst")
    if not src_ip or not dst_ip:
        log.warning("conntrack line ไม่มี src/dst ครบ ข้ามบรรทัดนี้: %r", line[:200])
        return None

    def _to_port(v: str | None) -> int | None:
        try:
            return int(v) if v is not None else None
        except ValueError:
            return None

    bytes_out = byte_values[0] if len(byte_values) >= 1 else 0
    bytes_in = byte_values[1] if len(byte_values) >= 2 else 0

    return event, ConnRecord(
        ts=ts, proto=proto, src_ip=src_ip, src_port=_to_port(kv_first.get("sport")),
        dst_ip=dst_ip, dst_port=_to_port(kv_first.get("dport")),
        bytes_out=bytes_out, bytes_in=bytes_in,
        ct_id=kv_first.get("id"), started_at=started_at,
    )


def parse_conntrack_line(line: str, now: float | None = None) -> ConnRecord | None:
    """เหมือน parse_conntrack_event แต่คืนเฉพาะ record ของ DESTROY (ที่จะลง conn_log)"""
    parsed = parse_conntrack_event(line, now)
    if parsed and parsed[0] == "DESTROY":
        return parsed[1]
    return None


def parse_client_conntrack_event(
    line: str, client_iface: ipaddress.IPv4Interface,
) -> tuple[str, ConnRecord] | None:
    """รับเฉพาะ original source ของลูกค้า; gateway ของ Pi อยู่ใน subnet เดียวกัน."""
    parsed = parse_conntrack_event(line)
    if parsed is None:
        return None
    try:
        src = ipaddress.IPv4Address(parsed[1].src_ip)
    except ipaddress.AddressValueError:
        log.warning("conntrack original src ไม่ใช่ IPv4: %r", parsed[1].src_ip)
        return None
    if src == client_iface.ip or src not in client_iface.network:
        return None
    return parsed


class ConnTracker:
    """
    R2-02: จำ MAC + เวลาเริ่มของแต่ละ connection ตั้งแต่ event NEW แล้วแปะให้ record ตอน DESTROY

    ของเดิมหา MAC จาก ARP ตอนเขียน DB ซึ่งช้ากว่าตอนเปิด connection ได้มาก (TIME_WAIT ~2 นาที,
    TCP ที่ลูกค้าหายไปเฉย ๆ ค้างได้ถึง 5 วัน) ระหว่างนั้น IP อาจถูก DHCP แจกให้ลูกค้าคนใหม่ ->
    ทราฟฟิกของคนเก่าถูกบันทึกเป็นของคนใหม่ ซึ่งเป็นหลักฐานผิดคนตาม ม.26
    """

    def __init__(self, mac_cache: MacCache, max_open: int = MAX_OPEN_CONNS):
        self.mac_cache = mac_cache
        self.max_open = max_open
        self._open: dict[str, tuple[str | None, float]] = {}
        self.evicted = 0

    def __len__(self) -> int:
        return len(self._open)

    def feed(self, event: str, rec: ConnRecord) -> ConnRecord | None:
        """คืน record ที่พร้อมบันทึก (เฉพาะ DESTROY) หรือ None"""
        if event == "NEW":
            if rec.ct_id is None:
                return None
            if len(self._open) >= self.max_open:
                # dict เรียงตามลำดับที่ใส่ -- ทิ้งรายการเก่าสุด DESTROY ของมันจะไปพึ่ง fallback
                self._open.pop(next(iter(self._open)))
                self.evicted += 1
            self._open[rec.ct_id] = (self.mac_cache.get(rec.src_ip), rec.ts)
            return None
        opened = self._open.pop(rec.ct_id, None) if rec.ct_id is not None else None
        if opened is None:
            # ไม่เห็น NEW (collector เพิ่งเริ่ม / event หายตอน ENOBUFS) -- ห้ามเดาจาก ARP ปัจจุบัน
            # ปล่อย mac ว่างให้ insert_conn_records หาจากประวัติ portal_session ตามเวลาเริ่มแทน
            return rec
        mac, started_at = opened
        return replace(rec, mac=mac, started_at=started_at)


# R2-02: fallback เมื่อไม่มี MAC จากตอน NEW -- หาจาก portal_session ที่ IP นี้ authenticated อยู่
# ณ เวลาที่ connection เริ่ม ต้องเจอ MAC เดียวเท่านั้น ถ้าคลุมเครือให้เว้นว่างดีกว่าชี้ผิดคน
_SESSION_MAC_SQL = (
    "SELECT DISTINCT mac FROM portal_session WHERE ip=%s"
    " AND authenticated_at IS NOT NULL AND authenticated_at <= %s"
    " AND (ended_at IS NULL OR %s <= ended_at) LIMIT 2"
)


def _mac_from_session_history(cur, ip: str, at) -> str | None:
    cur.execute(_SESSION_MAC_SQL, (ip, at, at))
    rows = cur.fetchall()
    if len(rows) != 1:
        return None
    row = rows[0]
    return row["mac"] if isinstance(row, dict) else row[0]


def insert_conn_records(records: list[ConnRecord], mac_cache: MacCache | None = None,
                        on_unmapped=None) -> int:
    """เขียนกลุ่ม record ลง conn_log เป็น batch — คืนจำนวนแถวที่เขียนสำเร็จ

    R2-02: ใช้ MAC ที่จับไว้ใน record (ตอน NEW) เท่านั้น ไม่อ่าน ARP ณ ตอนเขียน DB อีกแล้ว
    (`mac_cache` เหลือไว้เพื่อความเข้ากันได้ของ signature เดิม)"""
    from datetime import datetime

    from common.db import get_conn

    if not records:
        return 0
    rows = []
    unmapped = 0
    with get_conn() as conn, conn.cursor() as cur:
        for r in records:
            mac = r.mac
            started = datetime.fromtimestamp(r.started_at) if r.started_at is not None else None
            if not mac and started is not None:
                mac = _mac_from_session_history(cur, r.src_ip, started)
            if not mac:
                log.warning("ไม่พบ MAC ของ %s — เก็บ conn_log โดยไม่ระบุตัวอุปกรณ์", r.src_ip)
                unmapped += 1
            rows.append((datetime.fromtimestamp(r.ts), started, mac, r.src_ip, r.src_port,
                         r.dst_ip, r.dst_port, r.proto, r.bytes_out, r.bytes_in))
        cur.executemany(
            "INSERT INTO conn_log (ts, started_at, mac, src_ip, src_port, dst_ip, dst_port, "
            "proto, bytes_out, bytes_in) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", rows)
    if on_unmapped and unmapped:
        on_unmapped(unmapped)
    return len(rows)


def flush_buffer(buffer: list[ConnRecord], mac_cache: MacCache,
                 max_pending: int = MAX_PENDING_RECORDS,
                 telemetry: CollectorTelemetry | None = None) -> int:
    """
    พยายามเขียน buffer ลง DB -- คืนจำนวนแถวที่เขียนสำเร็จ (0 ถ้าล้มเหลว)

    N31: ของเดิมเรียก insert แล้ว `buffer.clear()` นอก try ทั้งที่คอมเมนต์เขียนว่า "จะลองใหม่
    รอบถัดไป" -> DB สะดุดแค่ครู่เดียว (เช่น MariaDB ถูกรีสตาร์ทตอนติดตั้ง ซึ่งเกิดขึ้นจริงเมื่อ
    2026-09-19) ข้อมูลจราจรช่วงนั้นหายถาวรโดยไม่มีใครรู้ ตอนนี้เก็บไว้ลองใหม่จริง ๆ และถ้า DB
    ล่มยาวจนเกินเพดาน จะทิ้งของเก่าสุดพร้อม **บันทึกไว้ว่าทิ้งไปกี่รายการ** ไม่ใช่หายเงียบ
    """
    if not buffer:
        return 0
    try:
        if telemetry:
            n = insert_conn_records(buffer, mac_cache, on_unmapped=telemetry.missing_mac)
        else:
            n = insert_conn_records(buffer, mac_cache)
    except Exception:
        log.exception("เขียน conn_log ไม่สำเร็จ — เก็บ %d รายการไว้ลองใหม่รอบถัดไป", len(buffer))
        if telemetry:
            telemetry.error("เขียน conn_log ไม่สำเร็จ")
        if len(buffer) > max_pending:
            dropped = len(buffer) - max_pending
            del buffer[:dropped]
            log.error("DB ล่มนานจนคิวเกิน %d รายการ — ทิ้งรายการเก่าสุด %d รายการ "
                     "(หลักฐานช่วงนั้นจะไม่ครบ)", max_pending, dropped)
            if telemetry:
                telemetry.drop(dropped)
        return 0
    buffer.clear()
    if telemetry:
        telemetry.write(n)
    return n


def _drain_stderr(stream, on_event_loss=None) -> None:  # pragma: no cover (thread I/O)
    """
    N31: อ่าน stderr ของ conntrack ตลอดเวลา 2 เหตุผล: (1) ถ้าไม่อ่าน ท่อจะเต็มแล้ว conntrack
    ค้าง = หยุดเก็บ log ทั้งระบบ (2) ข้อความ ENOBUFS คือสัญญาณว่าหลักฐานขาดหาย ต้องดังให้ได้ยิน
    """
    for line in stream:
        line = line.strip()
        if not line:
            continue
        if "ENOBUFS" in line:
            log.error("conntrack: %s -- เหตุการณ์บางส่วนถูกทิ้ง conn_log ช่วงนี้ไม่ครบ", line)
            if on_event_loss:
                on_event_loss(line)
        else:
            log.warning("conntrack: %s", line)


def build_conntrack_cmd(client_network) -> list[str]:
    """
    R2-02: `id` ใช้จับคู่ NEW กับ DESTROY · ฟัง NEW ด้วยเพื่อจับ MAC ตอนเปิด connection

    N43 (2026-10-03): `-s <วงลูกค้า>` ให้ conntrack ติดตัวกรอง BPF ที่ socket ในเคอร์เนล -- เหตุการณ์ที่
    ไม่ได้เริ่มจากวงลูกค้า (DNS ขาออกของ dnsmasq ไป 1.1.1.1 ทุกครั้งที่ลูกค้าถาม, chrony, apt, ทดสอบ
    ความเร็ว ฯลฯ) ถูกทิ้งตั้งแต่ในเคอร์เนล ไม่กินบัฟเฟอร์ netlink ที่ล้นจนเกิด ENOBUFS · วัดบน Pi
    ได้ราวครึ่งหนึ่งของเหตุการณ์ทั้งหมด ซึ่ง parse_client_conntrack_event ทิ้งทีหลังอยู่แล้ว
    (ทราฟฟิกลูกค้าที่ถูก NAT ยังมี original src เป็น 10.10.0.x จึงผ่านตัวกรองครบ)
    """
    return ["conntrack", "-E", "-o", "timestamp,extended,id", "-e", "NEW,DESTROY",
            "-s", str(client_network), "--buffer-size", str(NETLINK_BUFFER_BYTES)]


def _record_event_loss(detail: str, cooldown_seconds: int = 300,
                       _last: list[float] = []) -> None:  # pragma: no cover (ต้องมี DB)
    """บันทึกลง audit_log ว่ามีช่วงที่เก็บ log ได้ไม่ครบ -- หลักฐานความซื่อสัตย์ของระบบเอง
    ตาม ม.26 ดีกว่าปล่อยให้ข้อมูลขาดไปเงียบ ๆ · จำกัดความถี่กันถม audit_log"""
    now = time.time()
    if _last and now - _last[-1] < cooldown_seconds:
        return
    _last.append(now)
    try:
        from common import audit
        audit.log(audit.LOG_GAP, target="conn_log", detail=detail[:200])
    except Exception:
        log.exception("บันทึก audit_log เรื่องเหตุการณ์ที่หายไม่สำเร็จ")


def _enlarge_pipe(stream, target: int = PIPE_BUFFER_BYTES) -> int:  # pragma: no cover (ขึ้นกับ OS)
    """
    N39: ขยายท่อระหว่าง conntrack กับตัวเรา (ปริยาย 64 KB ซึ่งเต็มได้ในชุดเดียว)
    ถ้าเคอร์เนลไม่ยอม (เกิน `/proc/sys/fs/pipe-max-size`) ให้ทำงานต่อด้วยขนาดเดิม
    ไม่ใช่ล้มทั้งบริการ -- เป็นการปรับให้ทนทานขึ้น ไม่ใช่เงื่อนไขที่ขาดไม่ได้
    """
    try:
        import fcntl
        return fcntl.fcntl(stream.fileno(), F_SETPIPE_SZ, target)
    except Exception as exc:
        log.warning("ขยายบัฟเฟอร์ท่อเป็น %d ไบต์ไม่สำเร็จ (%s) — ใช้ขนาดปริยายต่อไป", target, exc)
        return 0


def _record_restart_gap(since: str) -> None:  # pragma: no cover (ต้องมี DB)
    """R2-06: `conntrack -E` เห็นแค่เหตุการณ์สด connection ที่ปิดระหว่าง logger ดับจึงหายแน่นอน
    แก้ไม่ได้ แต่ต้องมีร่องรอยว่าช่วงไหนไม่ครบ ไม่ใช่ให้ดูเหมือนไม่มีทราฟฟิก"""
    detail = f"conn_collector เริ่มใหม่ — ไม่ได้ฟัง conntrack ตั้งแต่ heartbeat ล่าสุด {since}"
    log.warning("log_gap conn_log: %s", detail)
    try:
        from common import audit
        audit.log(audit.LOG_GAP, target="conn_log", detail=detail[:200])
    except Exception:
        log.exception("บันทึก audit_log เรื่อง conn_log ขาดช่วงไม่สำเร็จ")


def run_forever(batch_size: int = 100, flush_interval: float = 5.0,
                stop_event: threading.Event | None = None) -> None:  # pragma: no cover
    """
    รันจริงบน gateway: เปิด `conntrack -E` เป็น subprocess แล้วแยกเป็น 3 ส่วนที่ไม่บล็อกกัน
    (N31) -- เดิมอ่านและเขียน DB อยู่ในลูปเดียวกัน ระหว่างที่รอ DB ท่อจากเคอร์เนลจะตันจนเกิด
    ENOBUFS และเหตุการณ์ถูกทิ้ง:
      1. เธรดอ่าน stdout  -> โยนเข้าคิว (ต้องว่างตลอด)
      2. เธรดอ่าน stderr  -> log คำเตือน ENOBUFS + บันทึกลง audit_log
      3. ลูปหลัก          -> ดึงจากคิวมาเขียน DB เป็น batch

    R2-06: เมื่อ `stop_event` ถูกตั้ง (SIGTERM) ให้ปิด conntrack แล้วดูดเหตุการณ์ที่ค้างในท่อ/คิว
    มาเขียนให้หมดก่อน return -- เดิมเธรดนี้เป็น daemon ที่ถูกฆ่าตอน interpreter ปิด บล็อก
    finally ไม่ได้ทำงาน record ใน buffer และคิวหายทุกครั้งที่ restart/reboot
    """
    stop_event = stop_event or threading.Event()
    client_cidr = os.environ.get("CLIENT_CIDR", "")
    try:
        client_iface = ipaddress.IPv4Interface(client_cidr)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
        raise RuntimeError("CLIENT_CIDR ต้องเป็น IPv4/prefix ของ gateway ฝั่งลูกค้าใน secrets.env") from exc
    mac_cache = MacCache()
    tracker = ConnTracker(mac_cache)
    reported_evicted = 0
    telemetry = CollectorTelemetry("conn")
    last_seen = telemetry.previous_heartbeat()
    if last_seen:
        _record_restart_gap(last_seen)
    buffer: list[ConnRecord] = []
    events: queue.Queue = queue.Queue(maxsize=EVENT_QUEUE_MAX)
    overflow = [0]
    last_flush = time.time()

    cmd = build_conntrack_cmd(client_iface.network)
    log.info("เริ่ม conn_collector: %s", " ".join(cmd))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    _enlarge_pipe(proc.stdout)

    def _read_stdout() -> None:
        # N39: เธรดนี้ต้อง "โง่และเร็วที่สุด" -- หน้าที่เดียวคือดูดข้อมูลออกจากท่อ
        # ของเคอร์เนลให้ทัน ของเดิมแปลงบรรทัดเป็น record ตรงนี้ด้วย ซึ่งช้าพอที่จะทำให้
        # ท่อตันตอนที่ conntrack ปล่อยเหตุการณ์มาเป็นชุดใหญ่พร้อมกัน (เกิดจากการเก็บกวาด
        # รายการหมดอายุ ซึ่งปล่อยทีละหลายร้อยรายการในมิลลิวินาทีเดียว) -> ENOBUFS -> หลักฐานหาย
        # วัดจริงแล้วหาย 17 จาก 300 การเชื่อมต่อ (5.7%) เทียบกับตัวอ้างอิงที่รันคู่ขนาน
        for line in proc.stdout:  # type: ignore[union-attr]
            try:
                events.put_nowait(line)
            except queue.Full:
                overflow[0] += 1

    stdout_thread = threading.Thread(target=_read_stdout, daemon=True, name="conntrack-stdout")
    stderr_thread = threading.Thread(target=_drain_stderr, args=(proc.stderr, _record_event_loss),
                                     daemon=True, name="conntrack-stderr")
    stdout_thread.start()
    stderr_thread.start()

    try:
        reported_overflow = 0
        while proc.poll() is None and not stop_event.is_set():
            telemetry.heartbeat()
            if not stdout_thread.is_alive() or not stderr_thread.is_alive():
                raise RuntimeError("conntrack reader thread หยุดทำงาน")
            try:
                # N39: แปลงบรรทัดเป็น record ตรงนี้ (ลูปหลัก) แทนที่จะทำในเธรดอ่าน
                parsed = parse_client_conntrack_event(
                    events.get(timeout=min(flush_interval, 1.0)), client_iface)
                rec = tracker.feed(*parsed) if parsed else None
                if rec:
                    buffer.append(rec)
                    telemetry.event()
            except queue.Empty:
                pass
            if tracker.evicted != reported_evicted:
                log.warning("connection ที่เปิดค้างเกิน %d รายการ — ลืม MAC ตอนเปิดไป %d รายการ "
                            "(จะหาจาก portal_session แทน)", tracker.max_open,
                            tracker.evicted - reported_evicted)
                reported_evicted = tracker.evicted
            if overflow[0] != reported_overflow:
                lost = overflow[0] - reported_overflow
                reported_overflow = overflow[0]
                log.error("log_gap conn_log: stdout queue เต็ม ทิ้ง %d เหตุการณ์", lost)
                telemetry.drop(lost)
                _record_event_loss(f"conntrack stdout queue full, dropped={lost}")
            now = time.time()
            if len(buffer) >= batch_size or (buffer and now - last_flush >= flush_interval):
                n = flush_buffer(buffer, mac_cache, telemetry=telemetry)
                log.debug("บันทึก conn_log %d แถว", n)
                last_flush = now
        if stop_event.is_set():
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            stdout_thread.join(timeout=5)  # อ่านท่อจนเจอ EOF ก่อน แล้วค่อยดูดคิว
            drained = 0
            while True:
                try:
                    parsed = parse_client_conntrack_event(events.get_nowait(), client_iface)
                except queue.Empty:
                    break
                rec = tracker.feed(*parsed) if parsed else None
                if rec:
                    buffer.append(rec)
                    telemetry.event()
                    drained += 1
            log.info("ปิด conn_collector: เก็บเหตุการณ์ที่ค้างในคิวอีก %d รายการ", drained)
            return
        log.error("conntrack หยุดทำงาน (exit %s) — cafe-logger จะถูก systemd รีสตาร์ทให้",
                 proc.returncode)
        raise RuntimeError(f"conntrack หยุดทำงาน (exit {proc.returncode})")
    finally:
        flush_buffer(buffer, mac_cache, telemetry=telemetry)
        if buffer:
            log.error("log_gap conn_log: ปิดตัวทั้งที่ยังเขียน %d รายการไม่สำเร็จ", len(buffer))
            telemetry.drop(len(buffer))
        telemetry.heartbeat(force=True)
        proc.terminate()


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    run_forever()
