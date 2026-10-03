"""
admin/views/staff.py — บัญชีพนักงาน + เปลี่ยนรหัสผ่านของตัวเอง

แยกออกจาก admin/app.py (2026-10-03) -- ตัวช่วยกลางและการเชื่อมฐานข้อมูลเรียกผ่าน core.* ตอนรันเสมอ
(เทสต์ reload admin.app แล้วสลับฐานข้อมูลจำลอง ถ้า import query_all มาตรง ๆ จะค้างตัวเก่า)
"""
from __future__ import annotations

from flask import abort, flash, g, redirect, render_template, request, session, url_for
from common import audit, crypto

from admin import app as core
from admin.routes import Routes

routes = Routes()


# ---------------------------------------------------------------- บัญชีพนักงาน
# เดิมมีแค่บัญชี admin ตัวแรกจาก /setup ร้านจริงจะใช้บัญชีร่วมกันทุกคน แล้ว audit_log บอกไม่ได้ว่า
# "ใคร" เปิดดูเลขบัตร/ออกรหัส (PDPA ต้องระบุตัวผู้เข้าถึงได้) -- admin สร้างบัญชีรายคนด้วยรหัสชั่วคราว
# ที่ระบบสุ่มให้ (แสดงครั้งเดียว) และพนักงานต้องตั้งรหัสเองตอน login ครั้งแรก admin จึงไม่รู้รหัสจริง
USERNAME_HINT = "ชื่อผู้ใช้ต้องยาว 3-64 ตัว ใช้ได้เฉพาะ a-z A-Z 0-9 . _"


def _valid_username(username: str) -> bool:
    return (3 <= len(username) <= 64 and username.isascii()
            and username.replace("_", "").replace(".", "").isalnum())


def _other_active_admins(cur, staff_id: int) -> int:
    """จำนวน admin ที่ใช้งานได้นอกจากบัญชีนี้ -- ต้องเหลืออย่างน้อย 1 เสมอ ไม่งั้นไม่มีใครจัดการระบบได้
    (เรียกใน transaction เดียวกับการแก้และล็อกแถวไว้ กัน admin 2 คนปิดกันเองพร้อมกัน)"""
    cur.execute("SELECT id FROM staff WHERE role='admin' AND is_active=1 AND id<>%s FOR UPDATE",
                (staff_id,))
    return len(cur.fetchall())


def _staff_page(**ctx):
    rows = core.query_all("SELECT id, username, display_name, role, is_active, must_change_password, "
                     "created_at, last_login_at FROM staff ORDER BY is_active DESC, username")
    return render_template("staff.html", rows=rows, **ctx)


def _show_temp_password(username: str, temp_pw: str, created: bool):
    # render ตรงจาก POST ไม่ใช่ PRG ผ่าน flash -- flash เก็บใน cookie ที่แค่เซ็นไม่ได้เข้ารหัส รหัสชั่วคราว
    # จะค้างอยู่ใน cookie แบบอ่านออก · no-store กันเบราว์เซอร์เก็บหน้านี้ไว้ใน cache
    resp = core.app.make_response(render_template("staff_temp_password.html", username=username,
                                             temp_password=temp_pw, created=created))
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _load_staff(cur, sid: int) -> dict:
    cur.execute("SELECT id, username, role, is_active FROM staff WHERE id = %s FOR UPDATE", (sid,))
    row = cur.fetchone()
    if not row:
        abort(404, "ไม่พบบัญชีพนักงานนี้")
    return row


@routes.get("/staff")
@core.login_required
@core.admin_required
def staff_list():
    return _staff_page()


@routes.post("/staff")
@core.login_required
@core.admin_required
def staff_create():
    username = (request.form.get("username") or "").strip()
    display = (request.form.get("display_name") or "").strip()[:128] or username
    role = request.form.get("role", "staff")
    if role not in ("admin", "staff"):
        abort(400, "role ไม่ถูกต้อง")
    if not _valid_username(username):
        return _staff_page(error=USERNAME_HINT, username=username, display_name=display), 400
    temp_pw = crypto.gen_temp_staff_password()
    with core.get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT id FROM staff WHERE username = %s", (username,))
        if cur.fetchone():
            return _staff_page(error=f"มีชื่อผู้ใช้ '{username}' อยู่แล้ว",
                               username=username, display_name=display), 409
        cur.execute(
            "INSERT INTO staff (username, password_hash, display_name, role, is_active, "
            "must_change_password, password_changed_at) VALUES (%s, %s, %s, %s, 1, 1, NOW())",
            (username, crypto.hash_password(temp_pw), display, role))
        audit.log_required(audit.STAFF_CREATE, staff_id=session["staff_id"], target=username,
                           client_ip=g.client_ip, detail=f"role={role}", cursor=cur)
    return _show_temp_password(username, temp_pw, created=True)


@routes.post("/staff/<int:sid>/active")
@core.login_required
@core.admin_required
def staff_toggle_active(sid: int):
    if sid == session["staff_id"]:
        abort(400, "ปิดบัญชีของตัวเองไม่ได้ — ให้ admin คนอื่นปิดให้")
    with core.get_conn() as conn, conn.cursor() as cur:
        row = _load_staff(cur, sid)
        activate = not row["is_active"]
        if not activate and row["role"] == "admin" and _other_active_admins(cur, sid) == 0:
            abort(400, "ต้องเหลือ admin ที่ใช้งานได้อย่างน้อย 1 บัญชี")
        cur.execute("UPDATE staff SET is_active = %s WHERE id = %s", (1 if activate else 0, sid))
        audit.log_required(audit.STAFF_ENABLE if activate else audit.STAFF_DISABLE,
                           staff_id=session["staff_id"], target=row["username"],
                           client_ip=g.client_ip, cursor=cur)
    # ปิดแล้ว gate() เตะ session ของบัญชีนั้นออกเองใน request ถัดไป (R2-L03)
    flash(f"{'เปิด' if activate else 'ปิด'}บัญชี '{row['username']}' แล้ว", "success")
    return redirect(url_for("staff_list"))


@routes.post("/staff/<int:sid>/role")
@core.login_required
@core.admin_required
def staff_set_role(sid: int):
    role = request.form.get("role", "")
    if role not in ("admin", "staff"):
        abort(400, "role ไม่ถูกต้อง")
    if sid == session["staff_id"]:
        abort(400, "เปลี่ยน role ของตัวเองไม่ได้ — ให้ admin คนอื่นเปลี่ยนให้")
    with core.get_conn() as conn, conn.cursor() as cur:
        row = _load_staff(cur, sid)
        if row["role"] == role:
            return redirect(url_for("staff_list"))
        if row["role"] == "admin" and row["is_active"] and _other_active_admins(cur, sid) == 0:
            abort(400, "ต้องเหลือ admin ที่ใช้งานได้อย่างน้อย 1 บัญชี")
        cur.execute("UPDATE staff SET role = %s WHERE id = %s", (role, sid))
        audit.log_required(audit.STAFF_ROLE, staff_id=session["staff_id"], target=row["username"],
                           client_ip=g.client_ip, detail=f"{row['role']}->{role}", cursor=cur)
    flash(f"เปลี่ยน '{row['username']}' เป็น {role} แล้ว", "success")
    return redirect(url_for("staff_list"))


@routes.post("/staff/<int:sid>/reset-password")
@core.login_required
@core.admin_required
def staff_reset_password(sid: int):
    if sid == session["staff_id"]:
        abort(400, "รีเซ็ตรหัสของตัวเองไม่ได้ — ใช้หน้า 'เปลี่ยนรหัสผ่าน'")
    temp_pw = crypto.gen_temp_staff_password()
    with core.get_conn() as conn, conn.cursor() as cur:
        row = _load_staff(cur, sid)
        # password_changed_at = NOW() -> session ของบัญชีนี้ทุกเครื่องหลุดทันที (gate())
        cur.execute("UPDATE staff SET password_hash = %s, must_change_password = 1, "
                    "password_changed_at = NOW() WHERE id = %s",
                    (crypto.hash_password(temp_pw), sid))
        audit.log_required(audit.STAFF_RESET_PASSWORD, staff_id=session["staff_id"],
                           target=row["username"], client_ip=g.client_ip, cursor=cur)
    return _show_temp_password(row["username"], temp_pw, created=False)


@routes.route("/account/password", methods=["GET", "POST"])
@core.login_required
def change_password():
    forced = bool((core.query_one("SELECT must_change_password FROM staff WHERE id = %s",
                             (session["staff_id"],)) or {}).get("must_change_password"))
    if request.method == "GET":
        return render_template("account_password.html", forced=forced)

    bucket = f"pwchange:{session['staff_id']}"
    if core.rate_limited(bucket):
        return render_template("account_password.html", forced=forced,
                               errors=["ลองผิดหลายครั้งเกินไป รอ 10 นาทีแล้วลองใหม่"]), 429
    current = request.form.get("current_password") or ""
    pw1 = request.form.get("password") or ""
    pw2 = request.form.get("password_confirm") or ""
    row = core.query_one("SELECT password_hash FROM staff WHERE id = %s", (session["staff_id"],))
    errors: list[str] = []
    if not row or not crypto.verify_password(row["password_hash"], current):
        core.record_attempt(bucket)
        errors.append("รหัสผ่านปัจจุบันไม่ถูกต้อง")
    if pw1 != pw2:
        errors.append("รหัสผ่านใหม่ทั้งสองช่องไม่ตรงกัน")
    if pw1 and pw1 == current:
        errors.append("รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสเดิม")
    errors.extend(crypto.check_admin_password(pw1))
    if errors:
        return render_template("account_password.html", forced=forced, errors=errors), 400

    with core.get_conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE staff SET password_hash = %s, must_change_password = 0, "
                    "password_changed_at = NOW() WHERE id = %s",
                    (crypto.hash_password(pw1), session["staff_id"]))
        cur.execute("SELECT password_changed_at FROM staff WHERE id = %s", (session["staff_id"],))
        stamp = (cur.fetchone() or {}).get("password_changed_at")
        audit.log_required(audit.PASSWORD_CHANGE, staff_id=session["staff_id"],
                           target=session.get("username", ""), client_ip=g.client_ip, cursor=cur)
    # session นี้อยู่ต่อ ส่วน session อื่นของบัญชีเดียวกัน (ค่า stamp เก่า) หลุดใน request ถัดไป
    session["pw_at"] = core._pw_stamp(stamp)
    flash("เปลี่ยนรหัสผ่านแล้ว อุปกรณ์อื่นที่ login บัญชีนี้ค้างไว้ถูกออกจากระบบแล้ว", "success")
    return redirect(url_for("dashboard"))
