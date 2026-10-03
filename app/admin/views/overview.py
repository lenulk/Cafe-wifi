"""
admin/views/overview.py — แดชบอร์ด, สถานะระบบ, รายงานสรุป

แยกออกจาก admin/app.py (2026-10-03) -- ตัวช่วยกลางและการเชื่อมฐานข้อมูลเรียกผ่าน core.* ตอนรันเสมอ
(เทสต์ reload admin.app แล้วสลับฐานข้อมูลจำลอง ถ้า import query_all มาตรง ๆ จะค้างตัวเก่า)
"""
from __future__ import annotations

import os
import time
from datetime import datetime, timedelta
from flask import g, jsonify, render_template, request, session
from common import audit, device_info, sysinfo, traffic

from admin import app as core
from admin.routes import Routes

routes = Routes()


# N5 (CODING_BRIEF.md): /health เดิมด้านบนคืนแค่ JSON ไว้ให้ monitoring ภายนอก/เทสต์เดิม
# อ้างอิงต่อไป -- ไม่แตะ -- หน้านี้คือหน้าเว็บจริงแยกต่างหากที่ /status ตามที่สั่ง แสดง disk %,
# chrony offset (T13), service ขึ้น/ลง, session active, log rows วันนี้, seal ล่าสุด, alert ล่าสุด
# (N1) ตรรกะทั้งหมดอยู่ใน common/health.py (แยกจาก route เพื่อให้ทดสอบได้บน Windows)
@routes.get("/status")
@core.login_required
def status_page():
    from common.health import build_status
    data = build_status(str(core.LOG_DIR))
    from tools import backup_db
    backup = backup_db.read_status(backup_db.status_path()) or {}
    backup["usb_present"] = os.path.exists("/dev/disk/by-label/CAFEBACKUP")
    return render_template("status.html", res=sysinfo.resources(), inet=sysinfo.internet_status(),
                           speed=sysinfo.last_speed_test(), backup=backup, **data)


@routes.get("/status/live")
@core.login_required
def status_live():
    """CPU/RAM/อุณหภูมิ/เน็ต สำหรับหน้า /status รีเฟรชเองทุก 10 วินาที (ไม่ต้องโหลดทั้งหน้า)"""
    return jsonify(res=sysinfo.resources(), inet=sysinfo.internet_status())


@routes.post("/status/speedtest")
@core.login_required
def status_speedtest():
    result = sysinfo.run_speed_test()
    if result.get("ok"):
        audit.log("speed_test", staff_id=session["staff_id"], client_ip=g.client_ip,
                  detail=f"ping={result['ping_ms']}ms down={result['down_mbps']} up={result['up_mbps']} Mbps")
    return jsonify(result), (200 if result.get("ok") else 429 if result.get("retry_in") else 502)


# ---------------------------------------------------------------- dashboard
@routes.get("/")
@core.login_required
def dashboard():
    stats = core.query_one("""
        SELECT
          (SELECT COUNT(*) FROM voucher WHERE status='active' AND valid_until > NOW()) AS active_vouchers,
          (SELECT COUNT(*) FROM customer)                                              AS customers,
          (SELECT COUNT(*) FROM voucher WHERE DATE(issued_at) = CURDATE())             AS issued_today,
          (SELECT COUNT(*) FROM portal_session WHERE state='authenticated' AND ended_at IS NULL) AS online_now
    """) or {}
    recent = core.query_all("""
        SELECT v.id, v.username, v.issued_at, v.valid_until, v.status, v.max_devices, v.quota_mb,
               c.natid_masked, s.username AS issued_by
        FROM voucher v
        JOIN customer c ON c.id = v.customer_id
        JOIN staff s    ON s.id = v.issued_by
        ORDER BY v.issued_at DESC LIMIT 15
    """)
    devices = _devices_by("id", [r["id"] for r in recent])
    usage = _usage_by("id", [r["id"] for r in recent])
    for r in recent:
        r["devices"] = devices.get(r["id"], [])
        r["usage"] = usage.get(r["id"], dict(down=0, up=0, total=0))
    return render_template("dashboard.html", stats=stats, recent=recent, now=datetime.now(),
                           net=_network_overview())


def _network_overview() -> dict:
    """อุปกรณ์บนเครือข่ายลูกค้าตอนนี้ แบ่งจาก lease ของ dnsmasq (= IP ที่แจกไปแล้ว):
    identified = มี session ที่ได้รับสิทธิ์อยู่ · pending = มีคำขอรออนุมัติ · unknown = ต่อ Wi-Fi แต่ยังไม่ได้รับสิทธิ์"""
    leases = device_info.read_leases()
    pool = device_info.dhcp_pool_size()
    online = {r["mac"]: r for r in core.query_all(
        "SELECT ps.mac, ps.ip, ps.hostname, ps.os_label, ps.authenticated_at, c.natid_masked "
        "FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
        "LEFT JOIN customer c ON c.id = v.customer_id "
        "WHERE ps.state = 'authenticated' AND ps.ended_at IS NULL")}
    for on in online.values():  # ใช้ไปเท่าไหร่ในรอบนี้ (ตั้งแต่ได้รับสิทธิ์)
        up, down = traffic.sum_session_traffic_bytes(core.query_one, on["mac"], on["authenticated_at"])
        on["usage"] = dict(down=down, up=up, total=down + up)
    pending = {r["mac"]: r for r in core.query_all(
        "SELECT mac, code, os_label FROM access_request WHERE status = 'pending' AND expires_at > NOW()")}
    devices = []
    seen = set()
    for l in leases:
        seen.add(l["mac"])
        on, pe = online.get(l["mac"]), pending.get(l["mac"])
        kind = "identified" if on else "pending" if pe else "unknown"
        devices.append(dict(mac=l["mac"], ip=l["ip"], kind=kind,
                            hostname=l["hostname"] or (on or {}).get("hostname"),
                            os_label=(on or pe or {}).get("os_label"),
                            natid_masked=(on or {}).get("natid_masked"), code=(pe or {}).get("code"),
                            usage=(on or {}).get("usage")))
    for mac, on in online.items():  # ได้รับสิทธิ์แต่ไม่อยู่ใน lease (lease เพิ่งหมด/ตั้ง IP เอง) -- ยังนับ
        if mac not in seen:
            devices.append(dict(mac=mac, ip=on["ip"], kind="identified", hostname=on["hostname"],
                                os_label=on["os_label"], natid_masked=on["natid_masked"], code=None,
                                usage=on["usage"]))
    # ยังไม่ระบุตัว: บอกว่าเครื่องนี้เคยใช้สิทธิ์ของใคร (คำใบ้เหมือนหน้าค้นหา log)
    unknown = [d["mac"] for d in devices if d["kind"] == "unknown"]
    if unknown:
        for r in core.query_all(
                "SELECT ps.mac, ps.hostname, ps.os_label, c.natid_masked FROM portal_session ps "
                "JOIN voucher v ON v.id = ps.voucher_id LEFT JOIN customer c ON c.id = v.customer_id "
                f"WHERE ps.mac IN ({', '.join(['%s'] * len(unknown))}) AND ps.authenticated_at IS NOT NULL "
                "ORDER BY ps.authenticated_at DESC", tuple(unknown)):
            d = next(d for d in devices if d["mac"] == r["mac"])
            if "past_owner" not in d:
                d["past_owner"] = r["natid_masked"]
                d["hostname"] = d["hostname"] or r["hostname"]
                d["os_label"] = d["os_label"] or r["os_label"]
    order = {"identified": 0, "pending": 1, "unknown": 2}
    devices.sort(key=lambda d: (order[d["kind"]], [int(x) for x in d["ip"].split(".")] if "." in d["ip"] else [0]))
    counts = {k: sum(d["kind"] == k for d in devices) for k in order}
    used = len(leases)
    total_usage = sum((d["usage"] or {}).get("total", 0) for d in devices if d.get("usage"))
    return dict(devices=devices, counts=counts, leased=used, pool=pool, total_usage=total_usage,
                free=(max(pool - used, 0) if pool else None))


def _usage_by(column: str, ids: list) -> dict:
    """ปริมาณเน็ตที่ใช้ไป รวมตาม voucher.id ("id") หรือ voucher.customer_id ("customer_id")
    -> {key: {down, up, total}} (bytes) · session ที่จบแล้วใช้ยอดที่ cafe-enforce ปิดบัญชีไว้
    (portal_session.bytes_in/out) ส่วนที่ยังออนไลน์รวมสด ๆ จาก conn_log (นับเมื่อ connection จบ
    -- ดาวน์โหลดยาว ๆ ที่ยังไม่จบจะยังไม่ขึ้นจนกว่าจะเสร็จ)"""
    if not ids:
        return {}
    assert column in ("id", "customer_id")
    rows = core.query_all(
        f"SELECT v.{column} AS k, ps.mac, ps.state, ps.authenticated_at, ps.ended_at, "
        "ps.bytes_in, ps.bytes_out FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
        f"WHERE v.{column} IN ({', '.join(['%s'] * len(ids))}) AND ps.authenticated_at IS NOT NULL",
        tuple(ids))
    out: dict = {}
    for r in rows:
        if r["state"] == "authenticated" and r["ended_at"] is None:
            up, down = traffic.sum_session_traffic_bytes(core.query_one, r["mac"], r["authenticated_at"])
        else:
            up, down = int(r["bytes_out"] or 0), int(r["bytes_in"] or 0)
        u = out.setdefault(r["k"], dict(down=0, up=0, total=0))
        u["down"] += down; u["up"] += up; u["total"] += down + up
    return out


def _devices_by(column: str, ids: list, per_key: int = 5) -> dict:
    """เครื่องที่เคยใช้สิทธิ์ จัดกลุ่มตาม voucher.id ("id") หรือ voucher.customer_id ("customer_id")
    -- ชื่อเครื่อง/OS อ่านง่ายกว่าเลขสิทธิ์ CAFE-xxxxx ที่สุ่มมา · เครื่องเดียวกัน (MAC) นับครั้งเดียว ใหม่สุดก่อน"""
    if not ids:
        return {}
    assert column in ("id", "customer_id")
    rows = core.query_all(
        f"SELECT v.{column} AS k, ps.mac, ps.hostname, ps.os_label, ps.state, ps.ended_at "
        "FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
        f"WHERE v.{column} IN ({', '.join(['%s'] * len(ids))}) ORDER BY ps.id DESC", tuple(ids))
    out: dict = {}
    for r in rows:
        lst = out.setdefault(r["k"], [])
        online = r["state"] == "authenticated" and r["ended_at"] is None
        same = next((d for d in lst if d["mac"] == r["mac"]), None)
        if same:
            same["online"] = same["online"] or online
            same["hostname"] = same["hostname"] or r["hostname"]
            same["os_label"] = same["os_label"] or r["os_label"]
        elif len(lst) < per_key:
            lst.append(dict(mac=r["mac"], hostname=r["hostname"], os_label=r["os_label"], online=online))
    return out


# ---------------------------------------------------------------- รายงานสรุป
# ใช้ทั้งในร้าน (วันไหน/ช่วงไหนคนแน่น) และเป็นผลลัพธ์ในเล่ม · ไม่มีข้อมูลรายบุคคล มีแต่ตัวเลขรวม
REPORT_RANGES = {"7": "7 วันล่าสุด", "30": "30 วันล่าสุด"}


_report_cache: dict = {}


REPORT_CACHE_SEC = 300  # SUM(conn_log) 30 วันบนร้านจริงอาจหลายวินาที -- คำนวณซ้ำทุก 5 นาทีพอ


def _build_report(days: int) -> dict:
    start = (datetime.now() - timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
    per_day = {(start + timedelta(days=i)).date(): dict(customers=0, sessions=0, devices=0, new=0, bytes=0,
                                                         approvals=0)
               for i in range(days)}
    for r in core.query_all(
            "SELECT DATE(ps.authenticated_at) AS d, COUNT(DISTINCT v.customer_id) AS customers, "
            "COUNT(*) AS sessions, COUNT(DISTINCT ps.mac) AS devices FROM portal_session ps "
            "JOIN voucher v ON v.id = ps.voucher_id WHERE ps.authenticated_at >= %s GROUP BY d", (start,)):
        if r["d"] in per_day:
            per_day[r["d"]].update(customers=r["customers"], sessions=r["sessions"], devices=r["devices"])
    for r in core.query_all("SELECT DATE(first_seen) AS d, COUNT(*) AS n FROM customer "
                       "WHERE first_seen >= %s GROUP BY d", (start,)):
        if r["d"] in per_day:
            per_day[r["d"]]["new"] = r["n"]
    for r in core.query_all("SELECT DATE(ts) AS d, SUM(bytes_in + bytes_out) AS b FROM conn_log "
                       "WHERE ts >= %s GROUP BY d", (start,)):
        if r["d"] in per_day:
            per_day[r["d"]]["bytes"] = int(r["b"] or 0)
    for r in core.query_all("SELECT DATE(decided_at) AS d, COUNT(*) AS n FROM access_request "
                       "WHERE status = 'approved' AND decided_at >= %s GROUP BY d", (start,)):
        if r["d"] in per_day:
            per_day[r["d"]]["approvals"] = r["n"]
    hours = [0] * 24
    for r in core.query_all("SELECT HOUR(authenticated_at) AS h, COUNT(*) AS n FROM portal_session "
                       "WHERE authenticated_at >= %s GROUP BY h", (start,)):
        hours[int(r["h"])] = int(r["n"])
    staff_rows = core.query_all(
        "SELECT s.username, s.display_name, COUNT(*) AS n FROM access_request ar "
        "JOIN staff s ON s.id = ar.decided_by WHERE ar.status = 'approved' AND ar.decided_at >= %s "
        "GROUP BY s.id, s.username, s.display_name ORDER BY n DESC", (start,))
    totals = core.query_one(
        "SELECT COUNT(DISTINCT v.customer_id) AS customers, COUNT(*) AS sessions FROM portal_session ps "
        "JOIN voucher v ON v.id = ps.voucher_id WHERE ps.authenticated_at >= %s", (start,)) or {}
    days_list = [dict(date=d, **v) for d, v in sorted(per_day.items())]
    return dict(
        start=start, days=days_list, hours=hours, staff=staff_rows,
        total_customers=int(totals.get("customers") or 0), total_sessions=int(totals.get("sessions") or 0),
        total_new=sum(d["new"] for d in days_list), total_bytes=sum(d["bytes"] for d in days_list),
        max_customers=max([d["customers"] for d in days_list] + [1]),
        max_bytes=max([d["bytes"] for d in days_list] + [1]), max_hour=max(hours + [1]),
        peak_hour=(hours.index(max(hours)) if any(hours) else None),
        busiest=(max(days_list, key=lambda d: d["customers"]) if any(d["customers"] for d in days_list) else None),
        generated_at=datetime.now())


@routes.get("/reports")
@core.login_required
def reports():
    rng = request.args.get("range", "7")
    if rng not in REPORT_RANGES:
        rng = "7"
    cached = _report_cache.get(rng)
    if not cached or time.time() - cached[0] > REPORT_CACHE_SEC or request.args.get("refresh") == "1":
        cached = (time.time(), _build_report(int(rng)))
        _report_cache[rng] = cached
    return render_template("reports.html", r=cached[1], rng=rng, ranges=REPORT_RANGES)
