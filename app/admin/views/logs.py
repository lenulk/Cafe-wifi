"""
admin/views/logs.py — ค้นหา log ย้อนหลัง + CSV + ตรวจความถูกต้องของ log

แยกออกจาก admin/app.py (2026-10-03) -- ตัวช่วยกลางและการเชื่อมฐานข้อมูลเรียกผ่าน core.* ตอนรันเสมอ
(เทสต์ reload admin.app แล้วสลับฐานข้อมูลจำลอง ถ้า import query_all มาตรง ๆ จะค้างตัวเก่า)
"""
from __future__ import annotations

import ipaddress
import io
import re
from datetime import datetime, timedelta
from flask import abort, g, render_template, request, session
from common import audit, crypto
from common.log_mapping import conn_mapping_join, dns_mapping_join
from logger.integrity import SqlManifestStore, verify_chain

from admin import app as core
from admin.routes import Routes

routes = Routes()


# N9 (CODING_BRIEF.md) ⭐ ช่องว่างที่ใหญ่ที่สุด -- DoD ของ Phase 4 เขียนว่า "ค้นย้อนกลับใน
# Admin เจอครบ" และ T10 ทดสอบไม่ได้เลยถ้าไม่มีหน้านี้ (เดิมมีแค่ export ผ่าน command line
# ใน tools/export_evidence.py) -- หน้านี้ค้น conn_log/dns_log ผ่านเว็บได้จริง
LOGS_PAGE_SIZE = 50


@routes.get("/logs")
@core.login_required
def search_logs():
    """ค้น log ย้อนหลัง -- ช่องค้นหาเดียวเดาชนิดให้เอง (เลขบัตร/CAFE-/MAC/IP/เว็บ) + ช่วงเวลาสำเร็จรูป

    ยังบังคับช่วงเวลาเสมอเหมือนเดิม (ตาราง log โตเร็วตาม ม.26 ห้ามกวาดทั้งตาราง) แต่ค่าเริ่มต้นคือ
    "วันนี้" -- เปิดหน้าครั้งแรกจึงไม่ค้นอะไร (ไม่ลง audit) แค่แสดงฟอร์มพร้อมใช้ แทน 400 แบบเดิม
    """
    log_type = request.args.get("log_type", "conn")
    if log_type not in ("conn", "dns"):
        log_type = "conn"
    q = (request.args.get("q") or "").strip()[:100]
    rng = request.args.get("range", "today")
    if rng not in LOG_RANGES:
        rng = "today"
    start_raw = (request.args.get("start") or "").strip()
    end_raw = (request.args.get("end") or "").strip()
    identified_only = request.args.get("identified") == "1"
    show_answers = request.args.get("answers") == "1"
    want_csv = request.args.get("format") == "csv"
    try:
        page = max(1, int(request.args.get("page") or 1))
    except ValueError:
        page = 1

    params = dict(log_type=log_type, q=q, range=rng, start=start_raw, end=end_raw,
                  identified="1" if identified_only else "", answers="1" if show_answers else "")
    ctx = dict(params=params, ranges=LOG_RANGES, rows=[], page=page, has_next=False,
               has_prev=page > 1, searched=False, kind=None, note=None)

    # เปิดหน้าครั้งแรก (ยังไม่กดค้นหา) -- แสดงฟอร์ม ไม่แตะ DB
    if "range" not in request.args and not q:
        return render_template("logs_search.html", error=None, **ctx)

    start, end, error = _resolve_log_range(rng, start_raw, end_raw)
    if error:
        return render_template("logs_search.html", error=error, **ctx), 400
    kind, value, error = _classify_log_query(q)
    if error:
        return render_template("logs_search.html", error=error, **ctx), 400
    ctx.update(kind=kind, start_dt=start, end_dt=end)

    where: list[str] = []
    args: list = [start, end]
    a = "dl" if log_type == "dns" else "cl"
    if kind == "natid":
        cust = core.query_one("SELECT id FROM customer WHERE natid_hash = %s", (value,))
        if not cust:
            ctx.update(searched=True, note="ไม่พบลูกค้าที่ใช้เลขบัตรนี้")
            return render_template("logs_search.html", error=None, **ctx)
        where.append("c.id = %s"); args.append(cust["id"])
    elif kind == "voucher":
        where.append("v.username = %s"); args.append(value)
    elif kind == "mac":
        where.append(f"{a}.mac = %s"); args.append(value)
    elif kind == "ip":
        if log_type == "dns":
            where.append("(dl.client_ip = %s OR dl.answer = %s)")
        else:
            where.append("(cl.src_ip = %s OR cl.dst_ip = %s)")
        args += [value, value]
    elif kind in ("domain", "name"):
        # "name" = คำไม่มีจุด เช่น "DESKTOP-7KQ2L" หรือ "facebook" -- อาจเป็นชื่อเครื่องลูกค้าหรือชื่อเว็บก็ได้
        # จึงค้นทั้งสองอย่าง ("domain" มีจุด = ชื่อเว็บแน่นอน ไม่ต้องค้นชื่อเครื่อง)
        conds: list[str] = []
        if kind == "name":
            conds.append("ps.hostname LIKE %s"); args.append(f"%{value}%")
        if log_type == "dns":
            conds.append("dl.qname LIKE %s"); args.append(f"%{value}%")
        else:
            # "ใครเข้าเว็บนี้" ในตารางการเชื่อมต่อ: conn_log มีแต่ IP -- ใช้ IP ที่ DNS ตอบสำหรับโดเมนนี้
            # ในช่วงเดียวกัน (ย้อน 1 ชม. เผื่อแคช DNS ของเครื่อง) · เป็นค่าประมาณ: หลายเว็บใช้ IP ร่วมกัน (CDN)
            conds.append("cl.dst_ip IN (SELECT d2.answer FROM dns_log d2 WHERE d2.qname LIKE %s "
                         "AND d2.event_kind = 'answer' AND d2.ts BETWEEN %s AND %s)")
            args += [f"%{value}%", start - timedelta(hours=1), end]
            ctx["note"] = ("ค้นชื่อเว็บในตารางการเชื่อมต่อ = ประมาณจาก IP ที่ DNS ตอบสำหรับเว็บนั้น "
                           "(เว็บที่ใช้ CDN ร่วมกันอาจติดมาด้วย)")
        if kind == "name":
            ctx["note"] = ("ค้นทั้งชื่อเครื่องลูกค้าและชื่อเว็บ" +
                           (" · " + ctx["note"] if ctx["note"] else ""))
        where.append("(" + " OR ".join(conds) + ")")
    if identified_only:
        where.append("v.id IS NOT NULL")
    if log_type == "dns" and not show_answers:
        where.append("dl.event_kind = 'query'")

    if log_type == "dns":
        sql = ("SELECT dl.ts, dl.client_ip, dl.mac, dl.qname, dl.qtype, dl.answer, dl.event_kind, "
               "v.username AS voucher_username, c.natid_masked, "
               "ps.hostname AS device_hostname, ps.os_label AS device_os "
               "FROM dns_log dl" + dns_mapping_join() + " WHERE dl.ts BETWEEN %s AND %s")
    else:
        sql = ("SELECT cl.ts, cl.started_at, cl.mac, cl.src_ip, cl.src_port, cl.dst_ip, cl.dst_port, "
               "cl.proto, cl.bytes_out, cl.bytes_in, v.username AS voucher_username, c.natid_masked, "
               "ps.hostname AS device_hostname, ps.os_label AS device_os "
               "FROM conn_log cl" + conn_mapping_join() + " WHERE cl.ts BETWEEN %s AND %s")
    sql += "".join(f" AND {w}" for w in where) + f" ORDER BY {a}.ts DESC LIMIT %s OFFSET %s"

    # audit ห้ามมีเลขบัตรเต็ม -- ลงแค่ชนิดที่ค้น (เลขบัตรแทนด้วย masked)
    shown_q = crypto.mask_natid(re.sub(r"\D", "", q)) if kind == "natid" else (q or "-")
    detail = (f"log_type={log_type} start={start.isoformat()} end={end.isoformat()} "
              f"q={shown_q} kind={kind or '-'} identified={int(identified_only)} page={page}")

    if want_csv:
        if session.get("role") != "admin":
            abort(403, "ดาวน์โหลด CSV ได้เฉพาะผู้ดูแลระบบ (admin)")
        rows = core.query_all(sql, tuple(args + [LOGS_CSV_MAX, 0]))
        audit.log_required(audit.EXPORT_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                           target="web-csv", detail=f"{detail} rows={len(rows)}")
        return _logs_csv(log_type, rows)

    audit.log_required(audit.SEARCH_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                       detail=detail)
    rows = core.query_all(sql, tuple(args + [LOGS_PAGE_SIZE + 1, (page - 1) * LOGS_PAGE_SIZE]))
    has_next = len(rows) > LOGS_PAGE_SIZE
    rows = rows[:LOGS_PAGE_SIZE]
    _add_unidentified_hints(rows)
    ctx.update(rows=rows, has_next=has_next, searched=True)
    return render_template("logs_search.html", error=None, **ctx)


def _add_unidentified_hints(rows) -> None:
    """แถวที่ "ยังไม่ระบุตัว" (เครื่องไม่ได้รับสิทธิ์ตอนนั้น เช่น ก่อนอนุมัติ หรือหลังถูกปิดสิทธิ์) ใส่ r["hint"]
    บอกว่าเครื่อง (MAC) นี้เคยใช้/ต่อมาได้สิทธิ์ของใคร -- **แสดงประกอบบนเว็บเท่านั้น** ไม่ผูกแถวนั้นกับ
    ลูกค้าจริง (ไม่ลง CSV/ไฟล์หลักฐาน) เพราะตอนเกิดแถวนั้นเครื่องไม่ได้ใช้สิทธิ์ของใครเลย"""
    pending = [r for r in rows if not r.get("natid_masked") and r.get("mac")]
    macs = sorted({r["mac"] for r in pending})
    if not macs:
        return
    sessions = core.query_all(
        "SELECT ps.mac, ps.authenticated_at, ps.ended_at, ps.hostname, ps.os_label, c.natid_masked "
        "FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
        "LEFT JOIN customer c ON c.id = v.customer_id "
        f"WHERE ps.mac IN ({', '.join(['%s'] * len(macs))}) AND ps.authenticated_at IS NOT NULL "
        "ORDER BY ps.authenticated_at DESC", tuple(macs))
    for r in pending:
        t = r.get("started_at") or r["ts"]
        mine = [s for s in sessions if s["mac"] == r["mac"]]
        if any(s["authenticated_at"] <= t and (s["ended_at"] is None or t <= s["ended_at"]) for s in mine):
            continue  # มี session ครอบเวลานี้แต่จับคู่ไม่ได้แน่ชัด (ซ้อนกัน/IP ไม่ตรง) -- ไม่ชี้นำว่าเป็นของใคร
        before = next((s for s in mine if s["authenticated_at"] <= t), None)   # ใหม่สุดก่อนแถวนี้
        after = next((s for s in reversed(mine) if s["authenticated_at"] > t), None)  # แรกสุดหลังแถวนี้
        s, when = (before, "เคยใช้สิทธิ์ของ") if before else (after, "ต่อมาได้รับสิทธิ์ของ")
        if s:
            r["hint"] = dict(hostname=s["hostname"], os_label=s["os_label"],
                             natid_masked=s["natid_masked"], when=when)


LOGS_CSV_MAX = 5000


LOG_MAX_SPAN = timedelta(days=31)


LOG_RANGES = {"1h": "1 ชม.ล่าสุด", "today": "วันนี้", "yesterday": "เมื่อวาน",
              "7d": "7 วันล่าสุด", "custom": "กำหนดเอง"}


def _resolve_log_range(rng: str, start_raw: str, end_raw: str):
    """คืน (start, end, error) -- ช่วงสำเร็จรูปคำนวณจากเวลาปัจจุบัน, กำหนดเองไม่เกิน 31 วัน"""
    now = datetime.now().replace(microsecond=0)
    midnight = now.replace(hour=0, minute=0, second=0)
    if rng == "1h":
        return now - timedelta(hours=1), now, None
    if rng == "today":
        return midnight, now, None
    if rng == "yesterday":
        return midnight - timedelta(days=1), midnight - timedelta(seconds=1), None
    if rng == "7d":
        return now - timedelta(days=7), now, None
    if not start_raw or not end_raw:
        return None, None, "เลือก 'กำหนดเอง' แล้วต้องระบุทั้งเวลาเริ่มต้นและสิ้นสุด"
    try:
        start, end = datetime.fromisoformat(start_raw), datetime.fromisoformat(end_raw)
    except ValueError:
        return None, None, "รูปแบบวันเวลาไม่ถูกต้อง"
    if end <= start:
        return None, None, "เวลาสิ้นสุดต้องอยู่หลังเวลาเริ่มต้น"
    if end - start > LOG_MAX_SPAN:
        return None, None, "ค้นได้ครั้งละไม่เกิน 31 วัน (กันเครื่องช้า) — แบ่งค้นเป็นช่วง"
    return start, end, None


_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$")


_DOMAIN_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def _classify_log_query(q: str):
    """เดาว่าพิมพ์อะไรมา -- คืน (kind, value, error) · kind: natid/voucher/mac/ip/domain/name หรือ None
    (name = คำไม่มีจุด อาจเป็นชื่อเครื่องหรือชื่อเว็บ)"""
    if not q:
        return None, None, None
    digits = re.sub(r"[\s-]", "", q)
    if digits.isdigit() and len(digits) == 13:
        if not crypto.valid_thai_id(digits):
            return None, None, "เลขบัตรประชาชนไม่ถูกต้อง (ตรวจ checksum ไม่ผ่าน)"
        return "natid", crypto.natid_hash(digits), None
    if re.fullmatch(r"(?i)CAFE-[A-Z0-9]{5}", q):
        return "voucher", q.upper(), None
    if _MAC_RE.match(q):
        hexes = re.sub(r"[:-]", "", q).upper()
        return "mac", ":".join(hexes[i:i + 2] for i in range(0, 12, 2)), None
    try:
        return "ip", str(ipaddress.ip_address(q)), None
    except ValueError:
        pass
    if _DOMAIN_RE.match(q) and any(ch.isalpha() for ch in q):
        return ("domain" if "." in q.strip(".") else "name"), q.lower(), None
    return None, None, ("ไม่รู้จักรูปแบบนี้ — พิมพ์เลขบัตร 13 หลัก, เลขอ้างอิง CAFE-xxxxx, MAC, IP, "
                        "ชื่อเครื่อง หรือชื่อเว็บ")


def _logs_csv(log_type: str, rows):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    if log_type == "dns":
        w.writerow(["ts", "client_ip", "mac", "qname", "qtype", "answer", "event_kind",
                    "voucher", "customer_masked", "device_hostname", "device_os"])
        for r in rows:
            w.writerow([r["ts"], r["client_ip"], r["mac"], r["qname"], r["qtype"], r["answer"],
                        r["event_kind"], r["voucher_username"], r["natid_masked"],
                        r.get("device_hostname"), r.get("device_os")])
    else:
        w.writerow(["started_at", "ts", "mac", "src_ip", "src_port", "dst_ip", "dst_port", "proto",
                    "bytes_out", "bytes_in", "voucher", "customer_masked", "device_hostname", "device_os"])
        for r in rows:
            w.writerow([r["started_at"], r["ts"], r["mac"], r["src_ip"], r["src_port"], r["dst_ip"],
                        r["dst_port"], r["proto"], r["bytes_out"], r["bytes_in"],
                        r["voucher_username"], r["natid_masked"],
                        r.get("device_hostname"), r.get("device_os")])
    resp = core.app.make_response("﻿" + buf.getvalue())  # BOM ให้ Excel อ่านภาษาไทยถูก
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = (
        f"attachment; filename={log_type}_log_{datetime.now():%Y%m%d-%H%M%S}.csv")
    resp.headers["Cache-Control"] = "no-store"
    return resp


# N2 (CODING_BRIEF.md): logger/integrity.py มี verify_chain() พร้อมใช้และมีเทสต์ผ่านแล้ว
# แต่ไม่เคยมีปุ่มไหนต่อเรียกมันในหน้าเว็บเลย -- ปุ่มนี้คือ T12 ที่สาธิตสดได้ใน 20 วินาที
# (แก้ไฟล์ log ที่ผนึกแล้ว 1 ตัวอักษร -> กดปุ่ม -> เจอ hash_mismatch ทันที)
@routes.post("/logs/verify")
@core.login_required
@core.admin_required
def verify_log_integrity():
    archive_dir = core.LOG_DIR / "archive"
    issues = verify_chain(SqlManifestStore(), archive_dir)
    audit.log("verify_integrity", staff_id=session["staff_id"], client_ip=g.client_ip,
              detail=(f"พบ {len(issues)} ปัญหา" if issues else "chain สมบูรณ์ ไม่พบปัญหา"))
    return render_template("logs_verify.html", issues=issues, archive_dir=str(archive_dir))
