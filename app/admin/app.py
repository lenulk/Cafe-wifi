"""
admin/app.py — Admin Panel สำหรับพนักงาน

จุดสำคัญ: First-run Setup Wizard
  - ตอนติดตั้ง install.sh สร้าง /etc/cafe-wifi/setup.token ไว้ (สุ่ม 24 ไบต์)
  - ตราบใดที่ตาราง staff ยังว่าง ทุก request จะถูกบังคับไปที่ /setup
  - /setup ต้องกรอก token ให้ตรง จึงจะสร้างบัญชีผู้ดูแลระบบหลักได้
  - สร้างสำเร็จ -> ลบไฟล์ token ทิ้ง -> /setup ปิดตัวเองถาวร
"""
from __future__ import annotations

import ipaddress
import hashlib
import io
import json
import os
import re
import secrets
import time
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)

from common import access, audit, crypto, device_info, sysinfo, traffic
from common.customer import PURGED_MARK, anonymize_customer, retention_hold_until
from common.db import execute, get_conn, query_all, query_one
from common.log_mapping import conn_mapping_join, dns_mapping_join
from logger.integrity import SqlManifestStore, verify_chain

ETC_DIR = Path(os.environ.get("ETC_DIR", "/etc/cafe-wifi"))
SETUP_TOKEN_FILE = ETC_DIR / "setup.token"
LOG_DIR = Path(os.environ.get("LOG_DIR", "/var/log/cafe-wifi"))  # N2 (CODING_BRIEF.md)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32).hex()),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True,          # ผ่าน nginx TLS เท่านั้น
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    CSRF_ENABLED=True,                   # R2-09 -- ปิดได้เฉพาะในเทสต์ที่ไม่ได้ทดสอบ CSRF โดยตรง
)


@app.after_request
def no_cache_sensitive(response):
    if request.path.endswith("/reveal") or request.path == "/requests":
        response.headers["Cache-Control"] = "no-store"
    return response
if not os.environ.get("SECRET_KEY"):
    # แก้บั๊ก (พบตอนตรวจทานรอบ 2): เดิม fallback เป็นค่าสุ่มเงียบ ๆ ไม่มี log อะไรเลย --
    # ตรงข้ามกับ FAS_KEY ที่ตั้งใจ fail ดัง ๆ (503) ถ้าไม่มีค่า สองไฟล์นี้ทำคนละมาตรฐาน
    # ค่าสุ่มที่สร้างตอน import จะเปลี่ยนทุกครั้งที่ service restart -- session/cookie เดิม
    # ของพนักงานทุกคนจะใช้ไม่ได้ทันที (ต้อง login ใหม่หมด) โดยไม่มีสัญญาณเตือนอะไรเลยว่า
    # secrets.env โหลดไม่สำเร็จ -- อย่างน้อยต้อง log ให้เห็นชัดเจนใน journal/error log
    app.logger.error(
        "ไม่พบ SECRET_KEY ใน environment — ใช้ค่าสุ่มชั่วคราวแทน (จะเปลี่ยนทุกครั้งที่ "
        "restart service ทำให้ทุกคน login ค้างอยู่หลุดหมด) ตรวจสอบว่า EnvironmentFile "
        "โหลด /etc/cafe-wifi/secrets.env สำเร็จหรือไม่"
    )

# rate limit แบบง่ายในหน่วยความจำ (พอสำหรับ 1 เครื่อง; ถ้าขยายหลาย worker ให้ย้ายไป DB)
_attempts: dict[str, list[float]] = {}
MAX_ATTEMPTS = 5
WINDOW_SEC = 600
# หน้าแอดมินเปิดให้วงลูกค้าเข้าได้ (เจ้าของโครงงานเลือก 2026-10-02: ร้านจริงมีแค่เราเตอร์ + Pi เครื่อง
# พนักงานได้ IP วงลูกค้าเหมือนทุกคน) -- ลูกค้าขอ IP ใหม่/ปลอม MAC ได้เรื่อย ๆ การจำกัดต่อ IP อย่างเดียว
# จึงไม่พอ ต้องจำกัดต่อ "ชื่อผู้ใช้" ด้วย (สูงกว่าต่อ IP หน่อย กันลูกค้าแกล้งล็อกบัญชีพนักงานง่ายเกินไป)
MAX_USER_ATTEMPTS = 10


# ---------------------------------------------------------------- helpers
def client_ip() -> str:
    # แก้บั๊ก C3: เดิมหยิบ X-Forwarded-For ตัวแรกซึ่งไคลเอนต์ปลอมได้ตรง ๆ (nginx เดิมต่อท้าย
    # ค่าที่ไคลเอนต์ส่งมาด้วย $proxy_add_x_forwarded_for ไม่ได้เขียนทับ) -- ใช้ X-Real-IP
    # ก่อนเสมอ เพราะ nginx เขียนทับ header นี้ด้วย $remote_addr ทุกครั้งไม่ว่าไคลเอนต์จะส่ง
    # อะไรมา (ดู install.sh configure_nginx) จึงปลอมไม่ได้ -- fallback ไป X-Forwarded-For/
    # remote_addr เฉพาะกรณี dev/ต่อตรงไม่ผ่าน nginx (เช่นรัน flask dev server ตรง ๆ)
    real_ip = request.headers.get("X-Real-IP", "").strip()
    if not real_ip:
        fwd = request.headers.get("X-Forwarded-For", "")
        real_ip = fwd.split(",")[0].strip() if fwd else (request.remote_addr or "")
    try:
        ipaddress.ip_address(real_ip)
    except ValueError:
        return ""
    return real_ip


def rate_limited(bucket: str, limit: int = MAX_ATTEMPTS) -> bool:
    now = time.time()
    hits = [t for t in _attempts.get(bucket, []) if now - t < WINDOW_SEC]
    _attempts[bucket] = hits
    return len(hits) >= limit


def record_attempt(bucket: str) -> None:
    _attempts.setdefault(bucket, []).append(time.time())


def staff_count() -> int:
    row = query_one("SELECT COUNT(*) AS n FROM staff")
    return int(row["n"]) if row else 0


def setup_done() -> bool:
    """ติดตั้งเสร็จแล้วเมื่อ: มีบัญชีอย่างน้อย 1 และไฟล์ token ถูกลบไปแล้ว"""
    return staff_count() > 0 and not SETUP_TOKEN_FILE.exists()


def login_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if "staff_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapper


def safe_next(nxt: str) -> str | None:
    """R2-04: รับเฉพาะ path ภายในเว็บนี้ -- กัน open redirect หลัง login
    `//evil.example/` และ `/\\evil.example/` ขึ้นต้นด้วย `/` แต่ browser ตีความเป็นโดเมนอื่น
    ส่วน tab/newline browser จะตัดทิ้งก่อน (`/<TAB>/evil` กลายเป็น `//evil`) จึงปฏิเสธ control char ทั้งหมด"""
    if not nxt or not nxt.startswith("/") or nxt.startswith("//"):
        return None
    if "\\" in nxt or any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in nxt):
        return None
    parts = urlsplit(nxt)
    if parts.scheme or parts.netloc:
        return None
    return nxt


CSRF_FIELD = "csrf_token"


def csrf_token() -> str:
    """R2-09: token สุ่มผูกกับ session (synchronizer token pattern) ใช้ใน hidden field ทุกฟอร์ม POST
    สร้างใหม่เมื่อ session ถูกล้าง (login/logout) -- token เก่าก่อน login จึงใช้ต่อหลัง login ไม่ได้"""
    tok = session.get(CSRF_FIELD)
    if not tok:
        tok = session[CSRF_FIELD] = secrets.token_urlsafe(32)
    return tok


def csrf_ok() -> bool:
    expected = session.get(CSRF_FIELD)
    sent = request.form.get(CSRF_FIELD) or request.headers.get("X-CSRF-Token") or ""
    return bool(expected) and secrets.compare_digest(sent.encode(), expected.encode())


def admin_required(view):
    @wraps(view)
    def wrapper(*a, **kw):
        if session.get("role") != "admin":
            abort(403, "ต้องเป็นผู้ดูแลระบบ (admin) เท่านั้น")
        return view(*a, **kw)
    return wrapper


# ระหว่างถูกบังคับเปลี่ยนรหัส (รหัสชั่วคราว) เข้าได้แค่หน้าเหล่านี้
PASSWORD_CHANGE_ALLOWED = {"change_password", "logout", "health", "static"}


def _pw_stamp(value) -> str:
    """ค่า staff.password_changed_at ในรูปที่เก็บลง session ได้ ("" = ยังไม่เคยเปลี่ยนผ่านหน้าเว็บ)"""
    return str(value) if value else ""


@app.before_request
def gate():
    g.client_ip = client_ip()
    if request.path.startswith("/static"):
        return None
    # R2-L03: session เก็บ role ไว้ใน cookie แต่สิทธิ์จริงอาจเปลี่ยนระหว่างที่ login ค้างอยู่
    if "staff_id" in session:
        staff = query_one("SELECT role, is_active, must_change_password, password_changed_at "
                          "FROM staff WHERE id = %s", (session["staff_id"],))
        if not staff or not staff["is_active"] or staff["role"] != session.get("role"):
            session.clear()
            return redirect(url_for("login"))
        # เปลี่ยน/รีเซ็ตรหัสแล้ว session ที่ login ไว้ก่อนหน้า (เครื่องอื่น หรือคนที่รู้รหัสเก่า) หลุดทันที
        if _pw_stamp(staff.get("password_changed_at")) != session.get("pw_at", ""):
            session.clear()
            return redirect(url_for("login"))
        # รหัสชั่วคราวจาก /staff ใช้ได้แค่เพื่อตั้งรหัสใหม่เท่านั้น
        if staff.get("must_change_password") and request.endpoint not in PASSWORD_CHANGE_ALLOWED:
            return redirect(url_for("change_password"))
    # R2-09: SameSite=Lax อย่างเดียวไม่กันคำขอจากหน้าอื่นใน "site" เดียวกัน (host/IP เดียวกันคนละ port)
    # ตรวจ token ทุก POST รวม /login และ /setup ด้วย (กัน login CSRF -- ถูกจับ login เป็นบัญชีคนอื่น)
    if request.method == "POST" and app.config["CSRF_ENABLED"] and not csrf_ok():
        audit.log(audit.CSRF_REJECT, staff_id=session.get("staff_id"), target=request.path,
                  client_ip=g.client_ip)
        abort(400, "แบบฟอร์มหมดอายุหรือไม่ได้ส่งมาจากหน้านี้ กรุณาโหลดหน้าใหม่แล้วลองอีกครั้ง")
    # ยังไม่มีบัญชีผู้ดูแล -> บังคับไปหน้า setup
    if staff_count() == 0 and request.endpoint not in {"setup", "health"}:
        return redirect(url_for("setup"))
    return None


@app.context_processor
def inject_globals():
    return {
        "gateway_name": os.environ.get("GATEWAY_NAME", "Cafe-Guest"),
        "current_user": session.get("username"),
        "current_role": session.get("role"),
        "now": datetime.now(),
        "csrf_token": csrf_token,
        "pending_requests": _pending_request_count,
    }


def _pending_request_count() -> int:
    """จำนวนคำขอที่รออนุมัติ แสดงเป็นตัวเลขบนเมนู (เรียกจาก template เฉพาะหน้าที่ login แล้ว)"""
    row = query_one("SELECT COUNT(*) AS n FROM access_request WHERE status='pending' "
                    "AND expires_at > NOW()")
    return int((row or {}).get("n") or 0)


@app.get("/health")
def health():
    return {"status": "ok", "setup_done": setup_done()}


# ---------------------------------------------------------------- setup wizard
@app.route("/setup", methods=["GET", "POST"])
def setup():
    # ปิดตัวเองถาวรเมื่อมีบัญชีแล้ว
    if staff_count() > 0:
        return render_template("setup_closed.html"), 410

    if not SETUP_TOKEN_FILE.exists():
        return render_template(
            "error.html",
            title="ยังตั้งค่าไม่ได้",
            message=f"ไม่พบไฟล์ {SETUP_TOKEN_FILE} — รัน install.sh ใหม่ "
                    "หรือสร้างไฟล์นี้เองด้วย openssl rand -hex 24",
        ), 503

    if request.method == "GET":
        return render_template("setup.html")

    ip = g.client_ip or "unknown"
    if rate_limited(f"setup:{ip}"):
        return render_template(
            "error.html", title="พยายามมากเกินไป",
            message="กรอก Setup Token ผิดหลายครั้ง กรุณารอ 10 นาทีแล้วลองใหม่",
        ), 429

    token_in = request.form.get("token", "")
    username = (request.form.get("username") or "").strip()
    display = (request.form.get("display_name") or "").strip() or username
    pw1 = request.form.get("password") or ""
    pw2 = request.form.get("password_confirm") or ""

    expected = SETUP_TOKEN_FILE.read_text(encoding="utf-8")
    errors: list[str] = []

    if not crypto.constant_time_eq(token_in, expected):
        record_attempt(f"setup:{ip}")
        errors.append("Setup Token ไม่ถูกต้อง")
    if not (3 <= len(username) <= 64) or not username.replace("_", "").replace(".", "").isalnum():
        errors.append("ชื่อผู้ใช้ต้องยาว 3-64 ตัว ใช้ได้เฉพาะ a-z A-Z 0-9 . _")
    if pw1 != pw2:
        errors.append("รหัสผ่านทั้งสองช่องไม่ตรงกัน")
    errors.extend(crypto.check_admin_password(pw1))

    if errors:
        return render_template("setup.html", errors=errors,
                               username=username, display_name=display), 400

    with get_conn() as conn, conn.cursor() as cur:
        # กันการแข่งกันสร้างพร้อมกัน 2 request
        cur.execute("SELECT COUNT(*) AS n FROM staff FOR UPDATE")
        if int(cur.fetchone()["n"]) > 0:
            return redirect(url_for("login"))
        cur.execute(
            "INSERT INTO staff (username, password_hash, display_name, role, is_active) "
            "VALUES (%s, %s, %s, 'admin', 1)",
            (username, crypto.hash_password(pw1), display),
        )
        new_id = cur.lastrowid

    # ทำลาย token ทันที -> /setup ปิดถาวร
    try:
        SETUP_TOKEN_FILE.unlink()
    except OSError:
        app.logger.error("ลบ %s ไม่สำเร็จ — ลบด้วยมือทันที", SETUP_TOKEN_FILE)

    audit.log(audit.SETUP_ADMIN, staff_id=new_id, target=username,
              client_ip=ip, detail="สร้างบัญชีผู้ดูแลระบบหลักผ่านหน้า /setup")

    flash(f"สร้างบัญชีผู้ดูแลระบบ '{username}' เรียบร้อย — เข้าสู่ระบบได้เลย", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------- auth
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template("login.html")

    ip = g.client_ip or "unknown"
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    user_bucket = f"login-user:{username.lower()[:64]}"
    if rate_limited(f"login:{ip}") or rate_limited(user_bucket, MAX_USER_ATTEMPTS):
        audit.log(audit.LOGIN_FAIL, target="rate-limited", client_ip=ip, detail=f"user={username[:64]}")
        return render_template("login.html",
                               error="พยายามเข้าสู่ระบบมากเกินไป รอ 10 นาทีแล้วลองใหม่"), 429

    row = query_one(
        "SELECT id, username, password_hash, display_name, role, is_active, "
        "must_change_password, password_changed_at "
        "FROM staff WHERE username = %s", (username,))

    if not row or not row["is_active"] or not crypto.verify_password(row["password_hash"], password):
        record_attempt(f"login:{ip}")
        record_attempt(user_bucket)
        audit.log(audit.LOGIN_FAIL, target=username, client_ip=ip)
        # ข้อความเดียวกันทุกกรณี ไม่บอกใบ้ว่าชื่อผู้ใช้มีจริงไหม
        return render_template("login.html", error="ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง"), 401

    if crypto.needs_rehash(row["password_hash"]):
        execute("UPDATE staff SET password_hash = %s WHERE id = %s",
                (crypto.hash_password(password), row["id"]))

    session.clear()
    session.permanent = True
    session.update(staff_id=row["id"], username=row["username"], role=row["role"],
                   pw_at=_pw_stamp(row.get("password_changed_at")))
    execute("UPDATE staff SET last_login_at = NOW() WHERE id = %s", (row["id"],))
    audit.log(audit.LOGIN_OK, staff_id=row["id"], target=username, client_ip=ip)

    if row.get("must_change_password"):
        flash("กรุณาตั้งรหัสผ่านใหม่ของคุณเองก่อนเริ่มใช้งาน (รหัสที่ได้รับเป็นรหัสชั่วคราว)", "warn")
        return redirect(url_for("change_password"))
    return redirect(safe_next(request.args.get("next", "")) or url_for("dashboard"))


@app.post("/logout")
@login_required
def logout():
    # N38: เดิมออกจากระบบแล้วไม่มีร่องรอยเลย ทั้งที่การเข้าสู่ระบบถูกบันทึกไว้ -- ตรวจสอบย้อนหลัง
    # ไม่ได้ว่าแอดมินคนไหนใช้งานอยู่ในช่วงเวลาใด (ต้องรู้ทั้งเวลาเริ่มและเวลาจบ session)
    audit.log(audit.LOGOUT, staff_id=session.get("staff_id"),
              target=session.get("username", ""), client_ip=g.client_ip)
    session.clear()
    return redirect(url_for("login"))


# JOIN ย้อนกลับ log -> voucher/customer อยู่ใน common/log_mapping.py (R2-10: ใช้ร่วมกับ
# tools/export_evidence.py เพื่อให้หน้าเว็บกับไฟล์หลักฐานจับคู่ตัวบุคคลแบบเดียวกันเป๊ะ)


@app.template_filter("human_bytes")
def human_bytes(n) -> str:
    n = int(n or 0)
    for unit, size in (("GB", 1_000_000_000), ("MB", 1_000_000), ("KB", 1_000)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


@app.errorhandler(400)
def e400(e):
    return render_template("error.html", title="คำขอไม่ถูกต้อง", message=e.description), 400


@app.errorhandler(403)
def e403(e):
    return render_template("error.html", title="ไม่มีสิทธิ์", message=str(e)), 403


@app.errorhandler(404)
def e404(e):
    return render_template("error.html", title="ไม่พบหน้านี้", message=str(e)), 404


@app.errorhandler(500)
def e500(e):
    # แก้บั๊ก (ผลข้างเคียงของ M6): ไฟล์นี้ไม่มี handler 500 มาก่อนเลย ต่างจาก fas/app.py
    # ทำให้ error ที่ไม่คาดคิดโผล่เป็นหน้า Werkzeug ดิบ ๆ แทนหน้า error.html ที่สอดคล้องกัน
    app.logger.exception("unhandled error")
    return render_template("error.html", title="เกิดข้อผิดพลาด",
                           message="กรุณาลองใหม่อีกครั้ง หรือแจ้งผู้ดูแลระบบ"), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("ADMIN_PORT", 18443)), debug=False)


# ---------------------------------------------------------------- ผูกหน้าต่าง ๆ จาก admin/views/
# import ไว้ท้ายไฟล์ (ไฟล์เหล่านั้น import admin.app กลับมาใช้ตัวช่วย) · register ทุกครั้งที่ไฟล์นี้ทำงาน
from admin.views import access, customers, logs, overview, staff  # noqa: E402

for _views in (overview, staff, access, customers, logs):
    _views.routes.register(app)

# เทสต์เดิมอ้างถึงผ่าน admin.app
_other_active_admins = staff._other_active_admins
_report_cache = overview._report_cache
