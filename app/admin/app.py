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


# N5 (CODING_BRIEF.md): /health เดิมด้านบนคืนแค่ JSON ไว้ให้ monitoring ภายนอก/เทสต์เดิม
# อ้างอิงต่อไป -- ไม่แตะ -- หน้านี้คือหน้าเว็บจริงแยกต่างหากที่ /status ตามที่สั่ง แสดง disk %,
# chrony offset (T13), service ขึ้น/ลง, session active, log rows วันนี้, seal ล่าสุด, alert ล่าสุด
# (N1) ตรรกะทั้งหมดอยู่ใน common/health.py (แยกจาก route เพื่อให้ทดสอบได้บน Windows)
@app.get("/status")
@login_required
def status_page():
    from common.health import build_status
    data = build_status(str(LOG_DIR))
    from tools import backup_db
    backup = backup_db.read_status(backup_db.status_path()) or {}
    backup["usb_present"] = os.path.exists("/dev/disk/by-label/CAFEBACKUP")
    return render_template("status.html", res=sysinfo.resources(), inet=sysinfo.internet_status(),
                           speed=sysinfo.last_speed_test(), backup=backup, **data)


@app.get("/status/live")
@login_required
def status_live():
    """CPU/RAM/อุณหภูมิ/เน็ต สำหรับหน้า /status รีเฟรชเองทุก 10 วินาที (ไม่ต้องโหลดทั้งหน้า)"""
    return jsonify(res=sysinfo.resources(), inet=sysinfo.internet_status())


@app.post("/status/speedtest")
@login_required
def status_speedtest():
    result = sysinfo.run_speed_test()
    if result.get("ok"):
        audit.log("speed_test", staff_id=session["staff_id"], client_ip=g.client_ip,
                  detail=f"ping={result['ping_ms']}ms down={result['down_mbps']} up={result['up_mbps']} Mbps")
    return jsonify(result), (200 if result.get("ok") else 429 if result.get("retry_in") else 502)


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
    rows = query_all("SELECT id, username, display_name, role, is_active, must_change_password, "
                     "created_at, last_login_at FROM staff ORDER BY is_active DESC, username")
    return render_template("staff.html", rows=rows, **ctx)


def _show_temp_password(username: str, temp_pw: str, created: bool):
    # render ตรงจาก POST ไม่ใช่ PRG ผ่าน flash -- flash เก็บใน cookie ที่แค่เซ็นไม่ได้เข้ารหัส รหัสชั่วคราว
    # จะค้างอยู่ใน cookie แบบอ่านออก · no-store กันเบราว์เซอร์เก็บหน้านี้ไว้ใน cache
    resp = app.make_response(render_template("staff_temp_password.html", username=username,
                                             temp_password=temp_pw, created=created))
    resp.headers["Cache-Control"] = "no-store"
    return resp


def _load_staff(cur, sid: int) -> dict:
    cur.execute("SELECT id, username, role, is_active FROM staff WHERE id = %s FOR UPDATE", (sid,))
    row = cur.fetchone()
    if not row:
        abort(404, "ไม่พบบัญชีพนักงานนี้")
    return row


@app.get("/staff")
@login_required
@admin_required
def staff_list():
    return _staff_page()


@app.post("/staff")
@login_required
@admin_required
def staff_create():
    username = (request.form.get("username") or "").strip()
    display = (request.form.get("display_name") or "").strip()[:128] or username
    role = request.form.get("role", "staff")
    if role not in ("admin", "staff"):
        abort(400, "role ไม่ถูกต้อง")
    if not _valid_username(username):
        return _staff_page(error=USERNAME_HINT, username=username, display_name=display), 400
    temp_pw = crypto.gen_temp_staff_password()
    with get_conn() as conn, conn.cursor() as cur:
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


@app.post("/staff/<int:sid>/active")
@login_required
@admin_required
def staff_toggle_active(sid: int):
    if sid == session["staff_id"]:
        abort(400, "ปิดบัญชีของตัวเองไม่ได้ — ให้ admin คนอื่นปิดให้")
    with get_conn() as conn, conn.cursor() as cur:
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


@app.post("/staff/<int:sid>/role")
@login_required
@admin_required
def staff_set_role(sid: int):
    role = request.form.get("role", "")
    if role not in ("admin", "staff"):
        abort(400, "role ไม่ถูกต้อง")
    if sid == session["staff_id"]:
        abort(400, "เปลี่ยน role ของตัวเองไม่ได้ — ให้ admin คนอื่นเปลี่ยนให้")
    with get_conn() as conn, conn.cursor() as cur:
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


@app.post("/staff/<int:sid>/reset-password")
@login_required
@admin_required
def staff_reset_password(sid: int):
    if sid == session["staff_id"]:
        abort(400, "รีเซ็ตรหัสของตัวเองไม่ได้ — ใช้หน้า 'เปลี่ยนรหัสผ่าน'")
    temp_pw = crypto.gen_temp_staff_password()
    with get_conn() as conn, conn.cursor() as cur:
        row = _load_staff(cur, sid)
        # password_changed_at = NOW() -> session ของบัญชีนี้ทุกเครื่องหลุดทันที (gate())
        cur.execute("UPDATE staff SET password_hash = %s, must_change_password = 1, "
                    "password_changed_at = NOW() WHERE id = %s",
                    (crypto.hash_password(temp_pw), sid))
        audit.log_required(audit.STAFF_RESET_PASSWORD, staff_id=session["staff_id"],
                           target=row["username"], client_ip=g.client_ip, cursor=cur)
    return _show_temp_password(row["username"], temp_pw, created=False)


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    forced = bool((query_one("SELECT must_change_password FROM staff WHERE id = %s",
                             (session["staff_id"],)) or {}).get("must_change_password"))
    if request.method == "GET":
        return render_template("account_password.html", forced=forced)

    bucket = f"pwchange:{session['staff_id']}"
    if rate_limited(bucket):
        return render_template("account_password.html", forced=forced,
                               errors=["ลองผิดหลายครั้งเกินไป รอ 10 นาทีแล้วลองใหม่"]), 429
    current = request.form.get("current_password") or ""
    pw1 = request.form.get("password") or ""
    pw2 = request.form.get("password_confirm") or ""
    row = query_one("SELECT password_hash FROM staff WHERE id = %s", (session["staff_id"],))
    errors: list[str] = []
    if not row or not crypto.verify_password(row["password_hash"], current):
        record_attempt(bucket)
        errors.append("รหัสผ่านปัจจุบันไม่ถูกต้อง")
    if pw1 != pw2:
        errors.append("รหัสผ่านใหม่ทั้งสองช่องไม่ตรงกัน")
    if pw1 and pw1 == current:
        errors.append("รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสเดิม")
    errors.extend(crypto.check_admin_password(pw1))
    if errors:
        return render_template("account_password.html", forced=forced, errors=errors), 400

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE staff SET password_hash = %s, must_change_password = 0, "
                    "password_changed_at = NOW() WHERE id = %s",
                    (crypto.hash_password(pw1), session["staff_id"]))
        cur.execute("SELECT password_changed_at FROM staff WHERE id = %s", (session["staff_id"],))
        stamp = (cur.fetchone() or {}).get("password_changed_at")
        audit.log_required(audit.PASSWORD_CHANGE, staff_id=session["staff_id"],
                           target=session.get("username", ""), client_ip=g.client_ip, cursor=cur)
    # session นี้อยู่ต่อ ส่วน session อื่นของบัญชีเดียวกัน (ค่า stamp เก่า) หลุดใน request ถัดไป
    session["pw_at"] = _pw_stamp(stamp)
    flash("เปลี่ยนรหัสผ่านแล้ว อุปกรณ์อื่นที่ login บัญชีนี้ค้างไว้ถูกออกจากระบบแล้ว", "success")
    return redirect(url_for("dashboard"))


# ---------------------------------------------------------------- dashboard
@app.get("/")
@login_required
def dashboard():
    stats = query_one("""
        SELECT
          (SELECT COUNT(*) FROM voucher WHERE status='active' AND valid_until > NOW()) AS active_vouchers,
          (SELECT COUNT(*) FROM customer)                                              AS customers,
          (SELECT COUNT(*) FROM voucher WHERE DATE(issued_at) = CURDATE())             AS issued_today,
          (SELECT COUNT(*) FROM portal_session WHERE state='authenticated' AND ended_at IS NULL) AS online_now
    """) or {}
    recent = query_all("""
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
    online = {r["mac"]: r for r in query_all(
        "SELECT ps.mac, ps.ip, ps.hostname, ps.os_label, ps.authenticated_at, c.natid_masked "
        "FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
        "LEFT JOIN customer c ON c.id = v.customer_id "
        "WHERE ps.state = 'authenticated' AND ps.ended_at IS NULL")}
    for on in online.values():  # ใช้ไปเท่าไหร่ในรอบนี้ (ตั้งแต่ได้รับสิทธิ์)
        up, down = traffic.sum_session_traffic_bytes(query_one, on["mac"], on["authenticated_at"])
        on["usage"] = dict(down=down, up=up, total=down + up)
    pending = {r["mac"]: r for r in query_all(
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
        for r in query_all(
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
    rows = query_all(
        f"SELECT v.{column} AS k, ps.mac, ps.state, ps.authenticated_at, ps.ended_at, "
        "ps.bytes_in, ps.bytes_out FROM portal_session ps JOIN voucher v ON v.id = ps.voucher_id "
        f"WHERE v.{column} IN ({', '.join(['%s'] * len(ids))}) AND ps.authenticated_at IS NOT NULL",
        tuple(ids))
    out: dict = {}
    for r in rows:
        if r["state"] == "authenticated" and r["ended_at"] is None:
            up, down = traffic.sum_session_traffic_bytes(query_one, r["mac"], r["authenticated_at"])
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
    rows = query_all(
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


@app.get("/requests")
@login_required
def requests_page():
    rows = query_all("SELECT id, code, mac, hostname, os_label, natid_hash, natid_masked, created_at, expires_at "
                     "FROM access_request WHERE status='pending' AND expires_at > NOW() ORDER BY id")
    pending = []
    with get_conn() as conn, conn.cursor() as cur:
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
    recent = query_all(
        "SELECT ar.code, ar.natid_masked, ar.hostname, ar.os_label, ar.status, ar.decided_at, ar.decision_note, "
        "s.username AS decided_by FROM access_request ar LEFT JOIN staff s ON s.id = ar.decided_by "
        "WHERE ar.status IN ('approved','rejected') ORDER BY ar.decided_at DESC LIMIT 10")
    return render_template("requests.html", pending=pending, recent=recent,
                           hours_choices=PACKAGE_HOURS)


@app.post("/requests/<int:rid>/approve")
@login_required
def approve_request(rid: int):
    last4 = re.sub(r"\D", "", request.form.get("last4", ""))
    package = _parse_package()
    if package is None:
        flash("ชั่วโมง/จำนวนเครื่อง/โควตาต้องเป็นตัวเลข", "err")
        return redirect(url_for("requests_page"))
    hours, devices, quota_mb = package

    with get_conn() as conn, conn.cursor() as cur:
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


@app.post("/vouchers/<int:vid>/devices")
@login_required
def set_voucher_devices(vid: int):
    """แก้จำนวนเครื่องของสิทธิ์ที่ยังใช้ได้ -- เช่น ลูกค้ามาขอเครื่องที่ 2 แต่สิทธิ์เดิมให้ไว้ 1 เครื่อง
    ลดได้แต่ไม่ต่ำกว่าจำนวนเครื่องที่ผูกกับสิทธิ์นี้แล้ว (เครื่องที่ใช้อยู่ต้องไม่หลุดเพราะตัวเลขนี้)"""
    back = safe_next(request.form.get("next", "")) or url_for("requests_page")
    try:
        n = int(request.form.get("devices", ""))
    except ValueError:
        n = 0
    if not 1 <= n <= MAX_DEVICES_PER_VOUCHER:
        flash(f"จำนวนเครื่องต้องอยู่ระหว่าง 1-{MAX_DEVICES_PER_VOUCHER}", "err")
        return redirect(back)
    with get_conn() as conn, conn.cursor() as cur:
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


@app.post("/requests/<int:rid>/reject")
@login_required
def reject_request(rid: int):
    note = (request.form.get("reason") or "").strip()[:255] or None
    with get_conn() as conn, conn.cursor() as cur:
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


# ---------------------------------------------------------------- ลูกค้า
@app.get("/customers")
@login_required
def customers():
    q = (request.args.get("q") or "").strip()
    if q and crypto.valid_thai_id(q):
        rows = query_all(
            "SELECT id, natid_masked, first_seen, last_seen, visit_count, is_blocked "
            "FROM customer WHERE natid_hash = %s", (crypto.natid_hash(q),))
    else:
        rows = query_all(
            "SELECT id, natid_masked, first_seen, last_seen, visit_count, is_blocked "
            "FROM customer ORDER BY last_seen DESC LIMIT 100")
    devices = _devices_by("customer_id", [r["id"] for r in rows], per_key=3)
    usage = _usage_by("customer_id", [r["id"] for r in rows])
    for r in rows:
        r["devices"] = devices.get(r["id"], [])
        r["usage"] = usage.get(r["id"], dict(down=0, up=0, total=0))
    return render_template("customers.html", rows=rows, q=q)


@app.post("/customers/<int:cid>/reveal")
@login_required
@admin_required
def reveal(cid: int):
    """
    เปิดเผยเลขบัตรประชาชนเต็ม — เฉพาะ role admin และต้องระบุเหตุผล
    ทุกครั้งจะถูกบันทึกลง audit_log (หลักฐานตาม PDPA)
    """
    reason = (request.form.get("reason") or "").strip()
    if len(reason) < 10:
        abort(400, "ต้องระบุเหตุผลอย่างน้อย 10 ตัวอักษร")

    row = query_one("SELECT natid_enc, natid_masked FROM customer WHERE id = %s", (cid,))
    if not row:
        abort(404)
    # N6 (CODING_BRIEF.md): หลัง DSR erase natid_enc จะว่างเปล่า -- ถอดรหัสไม่ได้ (natid_decrypt
    # จะ raise ValueError) ปฏิเสธชัดเจนแทนที่จะปล่อยให้หลุดไปเป็น 500 ทั่วไปที่อ่านไม่ออก
    # (ไม่ใช้ abort() เพราะ 410 ไม่มี errorhandler ลงทะเบียนไว้ -- render_template ตรง ๆ
    # แบบเดียวกับที่ setup() ทำตอน token ถูกใช้ไปแล้ว เพื่อให้หน้าตาสอดคล้องกันทั้งแอป)
    if row["natid_masked"] == PURGED_MARK:
        return render_template(
            "error.html", title="ลบข้อมูลไปแล้ว",
            message="ลูกค้ารายนี้ถูกลบข้อมูลระบุตัวตนไปแล้วตามคำขอ (DSR) — ไม่มีเลขบัตรให้เปิดเผยอีกต่อไป",
        ), 410

    audit.log_required(audit.REVEAL_NATID, staff_id=session["staff_id"],
                       target=f"customer:{cid}", client_ip=g.client_ip, detail=reason)
    return render_template("reveal.html", natid=crypto.natid_decrypt(row["natid_enc"]),
                           masked=row["natid_masked"], cid=cid, reason=reason)


# แก้บั๊ก M2: voucher.status='revoked' และ audit.REVOKE_VOUCHER ถูกประกาศไว้ในสคีมา/
# common/audit.py มาตั้งแต่แรก แต่ไม่มี endpoint ไหนเรียกใช้จริงเลย -- ค่า 'revoked' จึง
# ไม่มีทางเกิดขึ้นได้จริงในฐานข้อมูล เพิ่ม endpoint นี้ให้ใช้งานได้จริงตามที่ schema ตั้งใจไว้
@app.post("/vouchers/<int:vid>/revoke")
@login_required
def revoke_voucher(vid: int):
    """ยกเลิก voucher ก่อนหมดอายุ (เช่น ออกผิด/ลูกค้าขอยกเลิก) -- ยกเลิกได้เฉพาะใบที่ยัง active"""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("UPDATE voucher SET status='revoked' WHERE id=%s AND status='active'", (vid,))
        if not cur.rowcount:
            abort(404, "ไม่พบสิทธิ์นี้ หรือถูกปิด/หมดอายุไปแล้ว")
        audit.log_required(audit.REVOKE_VOUCHER, staff_id=session["staff_id"],
                           target=f"voucher:{vid}", client_ip=g.client_ip, cursor=cur)
    flash("ปิดสิทธิ์แล้ว — เครื่องที่ออนไลน์อยู่จะหลุดภายใน 5 นาที", "success")
    return redirect(url_for("dashboard"))


# แก้บั๊ก M2: customer.is_blocked ถูกอ่านใน /issue และ /login ของ fas มาตั้งแต่แรก (บล็อก
# ลูกค้าไม่ให้ออก voucher ใหม่/ล็อกอินได้) แต่ไม่มีหน้าจอไหนตั้งค่านี้เป็น true ได้เลย
@app.post("/customers/<int:cid>/block")
@login_required
@admin_required
def toggle_block_customer(cid: int):
    row = query_one("SELECT is_blocked FROM customer WHERE id=%s", (cid,))
    if not row:
        abort(404)
    new_state = not row["is_blocked"]
    execute("UPDATE customer SET is_blocked=%s WHERE id=%s", (new_state, cid))
    audit.log("block_customer" if new_state else "unblock_customer",
              staff_id=session["staff_id"], target=f"customer:{cid}", client_ip=g.client_ip)
    # R2-05: เครื่องที่ออนไลน์อยู่ถูกตัดโดย cafe-enforce.timer รอบถัดไป (ทุก 5 นาที) -- แอปนี้
    # รันเป็น cafewifi สั่ง ndsctl deauth เองไม่ได้
    flash("ระงับลูกค้ารายนี้แล้ว อุปกรณ์ที่ออนไลน์อยู่จะถูกตัดภายใน 5 นาที" if new_state
          else "ยกเลิกการระงับแล้ว", "success")
    return redirect(url_for("customers"))


# N6 (CODING_BRIEF.md): DSR -- §6.2 ข้อ 6 ของนโยบายความเป็นส่วนตัวประกาศสิทธิ์นี้ไว้แล้ว
# แต่ก่อนหน้านี้มีแค่ /reveal กับ /block ลบรายคนตามคำขอไม่ได้เลย -- ใช้ตรรกะ anonymize
# เดียวกับที่ tools/purge_old_data.py ใช้ล้างลูกค้าเก่าอัตโนมัติ (ผ่าน common/customer.py
# ตัวเดียวกัน ไม่เขียนซ้ำ) ล้าง natid_hash/natid_enc/natid_masked แต่**คงแถวไว้เสมอ** --
# ห้าม DELETE เพราะชน fk_voucher_customer (D20 ในแผน, บั๊กจริง C2 ที่เคยเจอมาก่อน)
@app.post("/customers/<int:cid>/erase")
@login_required
@admin_required
def erase_customer(cid: int):
    reason = (request.form.get("reason") or "").strip()
    if len(reason) < 10:
        abort(400, "ต้องระบุเหตุผล/คำขอของเจ้าของข้อมูลอย่างน้อย 10 ตัวอักษร")

    row = query_one("SELECT id, natid_masked FROM customer WHERE id = %s", (cid,))
    if not row:
        abort(404)
    if row["natid_masked"] == PURGED_MARK:
        flash("ลูกค้ารายนี้ถูกลบข้อมูลระบุตัวตนไปแล้ว", "warn")
        return redirect(url_for("customers"))

    # N33: ม.26 บังคับให้เก็บข้อมูลผู้ใช้บริการไว้ตามกำหนด ลบก่อนครบ = log ที่เหลือชี้กลับไปหา
    # บุคคลไม่ได้ ซึ่งผิดกฎหมาย -- PDPA เองยกเว้นสิทธิ์ขอลบไว้ในกรณีที่มีกฎหมายอื่นบังคับให้เก็บ
    # สิทธิ์ของเจ้าของข้อมูลไม่ได้หายไป แค่เลื่อน และ purge_old_data จะลบให้เองเมื่อพ้นกำหนด
    hold_until = retention_hold_until(query_one, cid)
    if hold_until:
        audit.log(audit.ERASE_REFUSED, staff_id=session["staff_id"], target=f"customer:{cid}",
                  client_ip=g.client_ip,
                  detail=f"ยังอยู่ในช่วงเก็บบังคับถึง {hold_until:%Y-%m-%d} — คำขอ: {reason}")
        flash(f"ยังลบข้อมูลระบุตัวตนไม่ได้ ต้องเก็บไว้ถึง {hold_until:%d/%m/%Y} "
              "ตาม พ.ร.บ.คอมพิวเตอร์ ม.26 (ระบบจะลบให้อัตโนมัติเมื่อพ้นกำหนด) "
              "คำขอของเจ้าของข้อมูลถูกบันทึกไว้แล้ว", "warn")
        return redirect(url_for("customers"))

    n = anonymize_customer(execute, cid)
    if not n:
        abort(404)

    audit.log(audit.ERASE_CUSTOMER, staff_id=session["staff_id"], target=f"customer:{cid}",
              client_ip=g.client_ip, detail=reason)
    flash("ลบข้อมูลระบุตัวตนของลูกค้ารายนี้แล้วตามคำขอ", "success")
    return redirect(url_for("customers"))


# N9 (CODING_BRIEF.md) ⭐ ช่องว่างที่ใหญ่ที่สุด -- DoD ของ Phase 4 เขียนว่า "ค้นย้อนกลับใน
# Admin เจอครบ" และ T10 ทดสอบไม่ได้เลยถ้าไม่มีหน้านี้ (เดิมมีแค่ export ผ่าน command line
# ใน tools/export_evidence.py) -- หน้านี้ค้น conn_log/dns_log ผ่านเว็บได้จริง
LOGS_PAGE_SIZE = 50

# JOIN ย้อนกลับ log -> voucher/customer อยู่ใน common/log_mapping.py (R2-10: ใช้ร่วมกับ
# tools/export_evidence.py เพื่อให้หน้าเว็บกับไฟล์หลักฐานจับคู่ตัวบุคคลแบบเดียวกันเป๊ะ)


@app.get("/logs")
@login_required
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
        cust = query_one("SELECT id FROM customer WHERE natid_hash = %s", (value,))
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
        rows = query_all(sql, tuple(args + [LOGS_CSV_MAX, 0]))
        audit.log_required(audit.EXPORT_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                           target="web-csv", detail=f"{detail} rows={len(rows)}")
        return _logs_csv(log_type, rows)

    audit.log_required(audit.SEARCH_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                       detail=detail)
    rows = query_all(sql, tuple(args + [LOGS_PAGE_SIZE + 1, (page - 1) * LOGS_PAGE_SIZE]))
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
    sessions = query_all(
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


# ---------------------------------------------------------------- ส่งออกหลักฐาน (ม.26 / คำสั่งเจ้าหน้าที่)
# เดิมต้อง SSH เข้าไปรัน tools/export_evidence.py -- เจ้าของร้านทำเองไม่ได้ และ SSH เข้าจากวงลูกค้าไม่ได้
# หน้านี้ใช้ตรรกะชุดเดียวกับเครื่องมือนั้นเป๊ะ (คิวรี่/JOIN/manifest) ไฟล์บนเว็บกับไฟล์จาก CLI จึงตรงกันเสมอ
EVIDENCE_MAX_DAYS_PERSON = 186   # รายคน/รายเครื่อง: ครอบระยะเก็บ 180 วันได้ทั้งหมด
EVIDENCE_MAX_DAYS_ALL = 7        # ทุกเครื่อง: ข้อมูลเยอะมาก จำกัดไว้กันเครื่องค้าง


@app.route("/evidence", methods=["GET", "POST"])
@login_required
@admin_required
def evidence():
    from tools import export_evidence as ev

    history = query_all(
        "SELECT a.ts, s.username, a.target, a.detail FROM audit_log a "
        "LEFT JOIN staff s ON s.id = a.staff_id WHERE a.action = %s AND a.target LIKE 'evidence%%' "
        "ORDER BY a.id DESC LIMIT 20", (audit.EXPORT_LOG,))
    today = datetime.now().date()
    form = dict(who=request.form.get("who", "natid"), start=request.form.get("start") or str(today),
                end=request.form.get("end") or str(today), reason=request.form.get("reason", ""),
                mac=request.form.get("mac", ""))
    if request.method == "GET":
        return render_template("evidence.html", form=form, history=history, error=None)

    def fail(msg):
        return render_template("evidence.html", form=form, history=history, error=msg), 400

    reason = form["reason"].strip()
    if len(reason) < 10:
        return fail("ระบุเลขที่หนังสือ/คำสั่งของเจ้าหน้าที่ หรือเหตุผล อย่างน้อย 10 ตัวอักษร (บันทึกใน audit)")
    try:
        start = datetime.fromisoformat(form["start"])
        end = ev.parse_range_end(form["end"])
    except ValueError:
        return fail("รูปแบบวันที่ไม่ถูกต้อง")
    if end <= start:
        return fail("วันที่สิ้นสุดต้องไม่ก่อนวันที่เริ่มต้น")

    customer, mac = None, None
    if form["who"] == "natid":
        try:
            customer = ev.find_customer(request.form.get("natid", ""), query_one)
        except ValueError as exc:
            return fail(str(exc))
        if not customer:
            return fail("ไม่พบลูกค้าที่ใช้เลขบัตรนี้")
        limit = EVIDENCE_MAX_DAYS_PERSON
    elif form["who"] == "mac":
        try:
            mac = ev.normalize_mac(form["mac"])
        except ValueError as exc:
            return fail(str(exc))
        if not mac:
            return fail("กรอก MAC ของเครื่อง")
        limit = EVIDENCE_MAX_DAYS_PERSON
    else:
        limit = EVIDENCE_MAX_DAYS_ALL
    if end - start > timedelta(days=limit):
        return fail(f"ส่งออกได้ครั้งละไม่เกิน {limit} วันสำหรับแบบที่เลือก — แบ่งเป็นหลายครั้ง")

    def rows(build):
        if customer is not None:
            return ev.query_customer_rows(build, customer["id"], start, end, query_all)
        return query_all(*build(start, end, mac=mac))

    conn_rows, dns_rows = rows(ev.build_conn_query), rows(ev.build_dns_query)
    tag = f"customer{customer['id']}" if customer else (mac.replace(":", "") if mac else "all")
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    conn_csv = ev.rows_to_csv_text(conn_rows, ev.CONN_FIELDS)
    dns_csv = ev.rows_to_csv_text(dns_rows, ev.DNS_FIELDS)
    conn_name, dns_name = f"conn_log_{tag}_{stamp}.csv", f"dns_log_{tag}_{stamp}.csv"
    criteria = dict(mac=mac, start=start.isoformat(), end=end.isoformat(), reason=reason,
                    exported_by=session.get("username"))
    if customer:
        criteria.update(customer_id=customer["id"], natid_masked=customer["natid_masked"])
    manifest = ev.build_manifest(
        [ev.ExportedFile(path=Path(conn_name), sha256=ev.sha256_text(conn_csv), row_count=len(conn_rows)),
         ev.ExportedFile(path=Path(dns_name), sha256=ev.sha256_text(dns_csv), row_count=len(dns_rows))],
        criteria)
    readme = ("ไฟล์หลักฐานข้อมูลจราจรทางคอมพิวเตอร์ (พ.ร.บ.คอมพิวเตอร์ มาตรา 26)\n"
              f"ส่งออกเมื่อ {manifest['generated_at']} โดย {session.get('username')}\n"
              f"ช่วงเวลา {start} ถึง {end}\nเหตุผล/เลขที่หนังสือ: {reason}\n\n"
              "ตรวจว่าไฟล์ไม่ถูกแก้ไข: คำนวณ SHA-256 ของไฟล์ .csv แต่ละไฟล์ (เช่น sha256sum <ไฟล์> หรือ\n"
              "certutil -hashfile <ไฟล์> SHA256 บน Windows) แล้วเทียบกับค่าใน manifest.json\n"
              "เลขบัตรประชาชนแสดงแบบปิดบางหลัก (natid_masked) ขอเลขเต็มได้จากผู้ดูแลระบบตามขั้นตอน\n")

    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(conn_name, "\ufeff" + conn_csv)  # BOM ให้ Excel อ่านภาษาไทยถูก (hash คิดจากเนื้อหาไม่รวม BOM)
        z.writestr(dns_name, "\ufeff" + dns_csv)
        z.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        z.writestr("README.txt", readme)
    data = buf.getvalue()
    zip_sha = hashlib.sha256(data).hexdigest()
    target = f"evidence:customer:{customer['id']}" if customer else f"evidence:{mac or 'ALL'}"
    audit.log_required(audit.EXPORT_LOG, staff_id=session["staff_id"], client_ip=g.client_ip,
                       target=target,
                       detail=(f"range={start:%Y-%m-%d %H:%M}..{end:%Y-%m-%d %H:%M} conn={len(conn_rows)} "
                               f"dns={len(dns_rows)} zip_sha256={zip_sha} reason={reason[:200]}"))
    resp = app.make_response(data)
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = f"attachment; filename=evidence_{tag}_{stamp}.zip"
    resp.headers["X-Evidence-SHA256"] = zip_sha
    resp.headers["Cache-Control"] = "no-store"
    return resp


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
    resp = app.make_response("﻿" + buf.getvalue())  # BOM ให้ Excel อ่านภาษาไทยถูก
    resp.headers["Content-Type"] = "text/csv; charset=utf-8"
    resp.headers["Content-Disposition"] = (
        f"attachment; filename={log_type}_log_{datetime.now():%Y%m%d-%H%M%S}.csv")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.template_filter("human_bytes")
def human_bytes(n) -> str:
    n = int(n or 0)
    for unit, size in (("GB", 1_000_000_000), ("MB", 1_000_000), ("KB", 1_000)):
        if n >= size:
            return f"{n / size:.1f} {unit}"
    return f"{n} B"


# N2 (CODING_BRIEF.md): logger/integrity.py มี verify_chain() พร้อมใช้และมีเทสต์ผ่านแล้ว
# แต่ไม่เคยมีปุ่มไหนต่อเรียกมันในหน้าเว็บเลย -- ปุ่มนี้คือ T12 ที่สาธิตสดได้ใน 20 วินาที
# (แก้ไฟล์ log ที่ผนึกแล้ว 1 ตัวอักษร -> กดปุ่ม -> เจอ hash_mismatch ทันที)
@app.post("/logs/verify")
@login_required
@admin_required
def verify_log_integrity():
    archive_dir = LOG_DIR / "archive"
    issues = verify_chain(SqlManifestStore(), archive_dir)
    audit.log("verify_integrity", staff_id=session["staff_id"], client_ip=g.client_ip,
              detail=(f"พบ {len(issues)} ปัญหา" if issues else "chain สมบูรณ์ ไม่พบปัญหา"))
    return render_template("logs_verify.html", issues=issues, archive_dir=str(archive_dir))


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
