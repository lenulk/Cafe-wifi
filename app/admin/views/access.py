"""
admin/views/access.py — คำขอใช้งาน (อนุมัติ/ปฏิเสธ) + จัดการสิทธิ์ (ต่อเวลา/จำนวนเครื่อง/ยกเลิก)

แยกออกจาก admin/app.py (2026-10-03) -- ตัวช่วยกลางและการเชื่อมฐานข้อมูลเรียกผ่าน core.* ตอนรันเสมอ
(เทสต์ reload admin.app แล้วสลับฐานข้อมูลจำลอง ถ้า import query_all มาตรง ๆ จะค้างตัวเก่า)
"""
from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta
from flask import abort, flash, g, redirect, render_template, request, session, url_for
from common import access, audit, crypto

from admin import app as core
from admin.routes import Routes

routes = Routes()


# ---------------------------------------------------------------- คำขอใช้งาน (แทนการออกรหัส)
# 2026-10-02 เลิกใช้สลิป CAFE-XXXXX + รหัสผ่าน: ลูกค้ากรอกเลขบัตรบน portal เอง ได้รหัสคำขอ 4 ตัว
# พนักงานตรวจบัตรจริงแล้วอนุมัติที่นี่ -- cafe-reconcile (root) สั่ง ndsctl auth เปิดสิทธิ์ให้เครื่องนั้น
# พนักงานไม่เห็นเลขบัตรเต็มบนจอ (§6.2): เห็นแบบ masked และต้องพิมพ์ 4 ตัวท้ายจากบัตรจริง ระบบเทียบ
# กับที่ลูกค้ากรอกให้ -- ยืนยันว่าบัตรที่ถืออยู่ตรงกับคำขอ และกันกดอนุมัติผิดคำขอ
PACKAGE_HOURS = (1, 2, 3, 4, 8, 12, 24)


def _parse_package():
    """ชั่วโมง/จำนวนเครื่อง/โควตาของสิทธิ์ใหม่ -- คืน (hours, devices, quota_mb) หรือ None ถ้าค่าไม่ถูก"""
    quota_raw = (request.form.get("quota_mb") or "").strip()
    try:
        hours = max(1, min(24, int(request.form.get("hours") or 4)))
        devices = max(1, min(5, int(request.form.get("devices") or 2)))
        quota_mb: int | None = int(quota_raw) if quota_raw else None
        if quota_mb is not None and quota_mb <= 0:
            raise ValueError
    except ValueError:
        return None
    return hours, devices, quota_mb


def _active_voucher(cur, customer_id: int, lock: bool = False):
    cur.execute("SELECT id, username, max_devices, valid_until, quota_mb, used_mb FROM voucher "
                "WHERE customer_id=%s AND status='active' AND valid_until > NOW() "
                "ORDER BY valid_until DESC LIMIT 1" + (" FOR UPDATE" if lock else ""), (customer_id,))
    return cur.fetchone()


@routes.get("/requests")
@core.login_required
def requests_page():
    rows = core.query_all("SELECT id, code, mac, hostname, os_label, natid_hash, natid_masked, created_at, expires_at "
                     "FROM access_request WHERE status='pending' AND expires_at > NOW() ORDER BY id")
    pending = []
    with core.get_conn() as conn, conn.cursor() as cur:
        for r in rows:
            cur.execute("SELECT id, is_blocked, visit_count FROM customer WHERE natid_hash=%s",
                        (r["natid_hash"],))
            cust = cur.fetchone()
            voucher = _active_voucher(cur, cust["id"]) if cust else None
            used = 0
            if voucher:
                cur.execute("SELECT COUNT(*) AS n FROM device WHERE voucher_id=%s", (voucher["id"],))
                used = int((cur.fetchone() or {}).get("n", 0))
            # natid_hash ไม่ส่งต่อไปถึง template
            pending.append(dict(id=r["id"], code=r["code"], mac_tail=r["mac"][-5:],
                                hostname=r["hostname"], os_label=r["os_label"],
                                natid_masked=r["natid_masked"], created_at=r["created_at"],
                                expires_at=r["expires_at"], customer=cust, voucher=voucher,
                                devices_used=used))
    recent = core.query_all(
        "SELECT ar.code, ar.natid_masked, ar.hostname, ar.os_label, ar.status, ar.decided_at, ar.decision_note, "
        "s.username AS decided_by FROM access_request ar LEFT JOIN staff s ON s.id = ar.decided_by "
        "WHERE ar.status IN ('approved','rejected') ORDER BY ar.decided_at DESC LIMIT 10")
    return render_template("requests.html", pending=pending, recent=recent,
                           hours_choices=PACKAGE_HOURS)


@routes.post("/requests/<int:rid>/approve")
@core.login_required
def approve_request(rid: int):
    last4 = re.sub(r"\D", "", request.form.get("last4", ""))
    package = _parse_package()
    if package is None:
        flash("ชั่วโมง/จำนวนเครื่อง/โควตาต้องเป็นตัวเลข", "err")
        return redirect(url_for("requests_page"))
    hours, devices, quota_mb = package

    with core.get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, code, mac, ip, hostname, os_label, natid_hash, natid_enc, natid_masked, "
                    "status, expires_at FROM access_request WHERE id=%s FOR UPDATE", (rid,))
        req = cur.fetchone()
        if not req or req["status"] != "pending" or req["expires_at"] <= datetime.now():
            flash("คำขอนี้หมดอายุหรือถูกจัดการไปแล้ว", "err")
            return redirect(url_for("requests_page"))
        nid = crypto.natid_decrypt(req["natid_enc"])
        if len(last4) != 4 or not secrets.compare_digest(last4, nid[-4:]):
            audit.log_required(audit.REQUEST_MISMATCH, staff_id=session["staff_id"],
                               target=req["code"], client_ip=g.client_ip,
                               detail=f"customer={req['natid_masked']}", cursor=cur)
            flash(f"คำขอ {req['code']}: เลข 4 ตัวท้ายบนบัตรไม่ตรงกับที่ลูกค้ากรอก — "
                  "ตรวจบัตรอีกครั้ง หรือให้ลูกค้าขอใหม่", "err")
            return redirect(url_for("requests_page"))

        cur.execute("SELECT id, is_blocked FROM customer WHERE natid_hash=%s FOR UPDATE",
                    (req["natid_hash"],))
        cust = cur.fetchone()
        if cust and cust["is_blocked"]:
            flash(f"คำขอ {req['code']}: ลูกค้ารายนี้ถูกระงับการใช้งาน", "err")
            return redirect(url_for("requests_page"))
        if cust:
            cust_id = cust["id"]
            cur.execute("UPDATE customer SET last_seen = NOW(), visit_count = visit_count + 1 "
                        "WHERE id = %s", (cust_id,))
        else:
            cur.execute("INSERT INTO customer (natid_hash, natid_enc, natid_masked, last_seen, "
                        "visit_count) VALUES (%s, %s, %s, NOW(), 1)",
                        (req["natid_hash"], req["natid_enc"], req["natid_masked"]))
            cust_id = cur.lastrowid

        # มีสิทธิ์ที่ยังใช้ได้อยู่ = เครื่องนี้เข้าสิทธิ์เดิม (เวลา/โควตา/จำนวนเครื่องร่วมกัน) ไม่ออกใบใหม่ซ้อน
        voucher = _active_voucher(cur, cust_id, lock=True)
        reused = voucher is not None
        if not reused:
            now = datetime.now()
            code = crypto.gen_voucher_code()
            # ไม่มีทาง login ด้วยรหัสผ่านแล้ว แต่คอลัมน์บังคับ NOT NULL -- ใส่ hash ของค่าสุ่มที่ไม่มีใครรู้
            cur.execute(
                "INSERT INTO voucher (customer_id, username, password_hash, issued_by, "
                "valid_from, valid_until, max_devices, quota_mb, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'active')",
                (cust_id, code, crypto.hash_password(secrets.token_urlsafe(32)),
                 session["staff_id"], now, now + timedelta(hours=hours), devices, quota_mb))
            voucher = dict(id=cur.lastrowid, username=code, max_devices=devices)

        error, session_id = access.reserve_pending_session(cur, voucher, req["mac"], req["ip"],
                                                           req["hostname"], req["os_label"])
        if error:
            conn.rollback()
            flash(f"คำขอ {req['code']}: {error}", "err")
            return redirect(url_for("requests_page"))

        # เลขบัตรย้ายไปอยู่ใน customer แล้ว -- สำเนาในคำขอไม่จำเป็นอีก ล้างทิ้งทันที
        cur.execute("UPDATE access_request SET status='approved', decided_at=NOW(), decided_by=%s, "
                    "voucher_id=%s, portal_session_id=%s, natid_hash=NULL, natid_enc=NULL "
                    "WHERE id=%s", (session["staff_id"], voucher["id"], session_id, rid))
        package_note = ("เข้าสิทธิ์เดิม" if reused else
                        f"hours={hours} devices={devices} quota_mb={quota_mb or 'unlimited'}")
        audit.log_required(audit.REQUEST_APPROVE, staff_id=session["staff_id"],
                           target=voucher["username"], client_ip=g.client_ip,
                           detail=f"request={req['code']} mac={req['mac']} "
                                  f"customer={req['natid_masked']} {package_note}", cursor=cur)

    flash(f"อนุมัติคำขอ {req['code']} แล้ว — เครื่องของลูกค้าจะใช้งานได้ภายในไม่กี่วินาที"
          + (" (เข้าสิทธิ์เดิมที่ยังเหลืออยู่)" if reused else ""), "success")
    return redirect(url_for("requests_page"))


MAX_DEVICES_PER_VOUCHER = 5


EXTEND_CHOICES_MIN = (30, 60, 120)


@routes.post("/vouchers/<int:vid>/extend")
@core.login_required
def extend_voucher(vid: int):
    """ต่อเวลาสิทธิ์ที่ยังใช้ได้ -- ลูกค้าขอนั่งต่อ ไม่ต้องขอใช้งานใหม่ · เครื่องที่ออนไลน์อยู่ได้เวลาใหม่ที่
    openNDS ภายใน ~5 วินาที (cafe-reconcile เห็น auth_sync_needed แล้วสั่ง deauth+auth ด้วยนาทีใหม่)"""
    try:
        minutes = int(request.form.get("minutes", "60"))
    except ValueError:
        minutes = 0
    if minutes not in EXTEND_CHOICES_MIN:
        abort(400, "ต่อเวลาได้ 30, 60 หรือ 120 นาที")
    with core.get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, status, valid_until FROM voucher WHERE id=%s FOR UPDATE", (vid,))
        v = cur.fetchone()
        if not v or v["status"] != "active" or v["valid_until"] <= datetime.now():
            flash("ต่อเวลาได้เฉพาะสิทธิ์ที่ยังใช้งานได้ — สิทธิ์ที่หมดแล้วให้ลูกค้าขอใช้งานใหม่", "err")
            return redirect(core.safe_next(request.form.get("next")) or url_for("dashboard"))
        new_until = v["valid_until"] + timedelta(minutes=minutes)
        cur.execute("UPDATE voucher SET valid_until=%s, auth_sync_needed=1 WHERE id=%s", (new_until, vid))
        audit.log_required(audit.VOUCHER_EXTEND, staff_id=session["staff_id"], target=f"voucher:{vid}",
                           client_ip=g.client_ip,
                           detail=f"+{minutes}min {v['valid_until']:%H:%M}->{new_until:%H:%M}", cursor=cur)
    flash(f"ต่อเวลาแล้ว +{minutes} นาที — ใช้ได้ถึง {new_until:%H:%M} น.", "success")
    return redirect(core.safe_next(request.form.get("next")) or url_for("dashboard"))


@routes.post("/vouchers/<int:vid>/devices")
@core.login_required
def set_voucher_devices(vid: int):
    """แก้จำนวนเครื่องของสิทธิ์ที่ยังใช้ได้ -- เช่น ลูกค้ามาขอเครื่องที่ 2 แต่สิทธิ์เดิมให้ไว้ 1 เครื่อง
    ลดได้แต่ไม่ต่ำกว่าจำนวนเครื่องที่ผูกกับสิทธิ์นี้แล้ว (เครื่องที่ใช้อยู่ต้องไม่หลุดเพราะตัวเลขนี้)"""
    back = core.safe_next(request.form.get("next", "")) or url_for("requests_page")
    try:
        n = int(request.form.get("devices", ""))
    except ValueError:
        n = 0
    if not 1 <= n <= MAX_DEVICES_PER_VOUCHER:
        flash(f"จำนวนเครื่องต้องอยู่ระหว่าง 1-{MAX_DEVICES_PER_VOUCHER}", "err")
        return redirect(back)
    with core.get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, username, max_devices, status, valid_until FROM voucher "
                    "WHERE id=%s FOR UPDATE", (vid,))
        v = cur.fetchone()
        if not v or v["status"] != "active" or v["valid_until"] <= datetime.now():
            flash("สิทธิ์นี้หมดอายุหรือถูกยกเลิกแล้ว", "err")
            return redirect(back)
        cur.execute("SELECT COUNT(*) AS n FROM device WHERE voucher_id=%s", (vid,))
        used = int((cur.fetchone() or {}).get("n") or 0)
        if n < used:
            flash(f"สิทธิ์นี้ผูกกับ {used} เครื่องแล้ว ลดต่ำกว่านั้นไม่ได้", "err")
            return redirect(back)
        if n == v["max_devices"]:
            return redirect(back)
        cur.execute("UPDATE voucher SET max_devices=%s WHERE id=%s", (n, vid))
        audit.log_required(audit.VOUCHER_DEVICES, staff_id=session["staff_id"], target=v["username"],
                           client_ip=g.client_ip, detail=f"{v['max_devices']}->{n}", cursor=cur)
    flash(f"แก้จำนวนเครื่องของ {v['username']} เป็น {n} เครื่องแล้ว", "success")
    return redirect(back)


@routes.post("/requests/<int:rid>/reject")
@core.login_required
def reject_request(rid: int):
    note = (request.form.get("reason") or "").strip()[:255] or None
    with core.get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT code, natid_masked FROM access_request WHERE id=%s AND status='pending' "
                    "FOR UPDATE", (rid,))
        req = cur.fetchone()
        if not req:
            flash("คำขอนี้ถูกจัดการไปแล้ว", "err")
            return redirect(url_for("requests_page"))
        cur.execute("UPDATE access_request SET status='rejected', decided_at=NOW(), decided_by=%s, "
                    "decision_note=%s, natid_hash=NULL, natid_enc=NULL WHERE id=%s",
                    (session["staff_id"], note, rid))
        audit.log_required(audit.REQUEST_REJECT, staff_id=session["staff_id"], target=req["code"],
                           client_ip=g.client_ip,
                           detail=f"customer={req['natid_masked']} reason={note or '-'}", cursor=cur)
    flash(f"ปฏิเสธคำขอ {req['code']} แล้ว", "success")
    return redirect(url_for("requests_page"))


# แก้บั๊ก M2: voucher.status='revoked' และ audit.REVOKE_VOUCHER ถูกประกาศไว้ในสคีมา/
# common/audit.py มาตั้งแต่แรก แต่ไม่มี endpoint ไหนเรียกใช้จริงเลย -- ค่า 'revoked' จึง
# ไม่มีทางเกิดขึ้นได้จริงในฐานข้อมูล เพิ่ม endpoint นี้ให้ใช้งานได้จริงตามที่ schema ตั้งใจไว้
@routes.post("/vouchers/<int:vid>/revoke")
@core.login_required
def revoke_voucher(vid: int):
    """ยกเลิก voucher ก่อนหมดอายุ (เช่น ออกผิด/ลูกค้าขอยกเลิก) -- ยกเลิกได้เฉพาะใบที่ยัง active"""
    with core.get_conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE voucher SET status='revoked' WHERE id=%s AND status='active'", (vid,))
        if not cur.rowcount:
            abort(404, "ไม่พบสิทธิ์นี้ หรือถูกปิด/หมดอายุไปแล้ว")
        audit.log_required(audit.REVOKE_VOUCHER, staff_id=session["staff_id"],
                           target=f"voucher:{vid}", client_ip=g.client_ip, cursor=cur)
    flash("ปิดสิทธิ์แล้ว — เครื่องที่ออนไลน์อยู่จะหลุดภายใน 5 นาที", "success")
    return redirect(url_for("dashboard"))
