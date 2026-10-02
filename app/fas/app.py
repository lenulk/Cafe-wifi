"""
fas/app.py — Captive Portal (Forwarding Authentication Service, FAS level 2)

ลำดับการทำงาน (ดู §3.3 ใน PROJECT_PLAN.md):
  1. ลูกค้าต่อ Wi-Fi -> openNDS redirect มาที่ GET /login?fas=..&iv=..
  2. ถอดรหัส payload ได้ ClientContext (mac, hid, gatewayaddress, originurl, ...)
  3. แสดงฟอร์มขอใช้งาน: เลขบัตรประชาชน + ยินยอมตามนโยบายความเป็นส่วนตัว (context เก็บฝั่ง server
     ผูกกับ nonce ใน fas_context)
  4. POST /login -> ยืนยัน MAC จาก ARP, สร้าง access_request พร้อมรหัสคำขอ 4 ตัว
  5. GET /request -> หน้ารอ: ลูกค้าโชว์รหัสให้พนักงาน พนักงานตรวจบัตรแล้วอนุมัติใน Admin
  6. tools/reconcile_pending.py (root) สั่ง `ndsctl auth <mac>` เปิดสิทธิ์ให้เครื่องนี้โดยตรง
     แล้วยืนยัน session กับ openNDS -- ลูกค้าไม่ต้องพิมพ์ username/password ใด ๆ

(2026-10-02 เลิกใช้สลิป CAFE-XXXXX + รหัสผ่าน -- ดู sql/010_access_request.sql)
"""
from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import re
import secrets
import subprocess
import time
from datetime import datetime, timedelta

from flask import Flask, abort, redirect, render_template, request

from common import access, audit, crypto, device_info
from common.db import execute, get_conn, query_one
from logger.netutil import resolve_mac
from .opennds_proto import ClientContext, FasProtocolError, decrypt_fas_payload

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32).hex()),
    MAX_CONTENT_LENGTH=256 * 1024,
)
if not os.environ.get("SECRET_KEY"):
    # แก้บั๊ก (พบตอนตรวจทานรอบ 2): ดูรายละเอียดเดียวกันใน admin/app.py -- ไฟล์นี้ไม่ได้ใช้
    # Flask session/flash เอง (ใช้ hidden form field แทน) ผลกระทบจึงต่ำกว่า admin/app.py
    # มาก แต่ log ไว้เผื่ออนาคตมีคนเพิ่มโค้ดที่พึ่ง session เข้ามาโดยไม่รู้ตัวว่า SECRET_KEY หาย
    app.logger.error(
        "ไม่พบ SECRET_KEY ใน environment — ใช้ค่าสุ่มชั่วคราวแทน ตรวจสอบว่า EnvironmentFile "
        "โหลด /etc/cafe-wifi/secrets.env สำเร็จหรือไม่"
    )

FAS_KEY = os.environ.get("FAS_KEY", "")
GATEWAY_NAME = os.environ.get("GATEWAY_NAME", "Cafe-Guest")
GATEWAY_IP = os.environ.get("GATEWAY_IP", "10.10.0.1")
GATEWAY_AUTHDIR = os.environ.get("GATEWAY_AUTHDIR", "opennds_auth")
NDS_PORT = os.environ.get("NDS_PORT", "2050")
# พนักงานต่อ Wi-Fi ร้านได้ IP วงลูกค้าเหมือนทุกคน (ร้านจริงมีแค่เราเตอร์ + Pi) -- หน้า portal จึงมีปุ่มไปหน้าแอดมิน
ADMIN_URL = os.environ.get("ADMIN_URL", "https://cafe.wifi:8443/login")
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")

_attempts: dict[str, list[float]] = {}
MAX_ATTEMPTS = 5
WINDOW_SEC = 600


def rate_limited(bucket: str) -> bool:
    now = time.time()
    hits = [t for t in _attempts.get(bucket, []) if now - t < WINDOW_SEC]
    _attempts[bucket] = hits
    return len(hits) >= MAX_ATTEMPTS


def record_attempt(bucket: str) -> None:
    _attempts.setdefault(bucket, []).append(time.time())


def client_ip() -> str:
    # แก้บั๊ก C3: ใช้ X-Real-IP ก่อนเสมอ (nginx เขียนทับด้วย $remote_addr ทุกครั้ง ปลอมไม่ได้)
    # ดูรายละเอียดเดียวกันใน admin/app.py::client_ip()
    real_ip = request.headers.get("X-Real-IP", "").strip()
    if not real_ip:
        fwd = request.headers.get("X-Forwarded-For", "")
        real_ip = fwd.split(",")[0].strip() if fwd else (request.remote_addr or "")
    try:
        ipaddress.ip_address(real_ip)
    except ValueError:
        return ""
    return real_ip


def normalize_mac(mac: str) -> str:
    return (mac or "").strip().upper()


def _nonce_hash(nonce: str) -> str:
    return hashlib.sha256(nonce.encode("ascii")).hexdigest()


def _save_context(ctx: ClientContext, ip: str) -> str:
    nonce = secrets.token_urlsafe(32)
    execute("INSERT INTO fas_context (nonce_hash, payload, request_ip, expires_at) "
            "VALUES (%s,%s,%s,%s)",
            (_nonce_hash(nonce), json.dumps(ctx.__dict__), ip,
             datetime.now() + timedelta(minutes=10)))
    return nonce


def _load_context(nonce: str, ip: str) -> ClientContext | None:
    if len(nonce) < 32 or len(nonce) > 128 or not ip:
        return None
    row = query_one("SELECT payload, request_ip, expires_at, consumed_at FROM fas_context "
                    "WHERE nonce_hash=%s", (_nonce_hash(nonce),))
    if not row or row["request_ip"] != ip or row["consumed_at"] or row["expires_at"] <= datetime.now():
        return None
    return ClientContext.from_dict(json.loads(row["payload"]))


def _valid_gateway(ctx: ClientContext) -> bool:
    # openNDS 10.1.3 ตัวจริงส่ง gatewayaddress เป็น "ip:port" (เช่น "10.10.0.1:2050" -- ดู payload จริง
    # ใน tests/test_opennds_proto.py) ไม่ใช่ IP เปล่า -- เดิมเทียบทั้งสตริงกับ GATEWAY_IP ตรง ๆ
    # ลูกค้าทุกคนบนเครื่องจริงจึงเจอ "หน้านี้หมดอายุแล้ว" ทั้งที่เทสต์ (ใช้ค่าที่สร้างเองไม่มีพอร์ต) ผ่าน
    host, sep, port = ctx.gatewayaddress.partition(":")
    if sep and port != NDS_PORT:
        return False
    return host == GATEWAY_IP and ctx.authdir.strip("/") == GATEWAY_AUTHDIR


@app.context_processor
def inject_globals():
    return {"gateway_name": GATEWAY_NAME, "admin_url": ADMIN_URL}


@app.get("/health")
def health():
    return {"status": "ok", "service": "cafe-wifi-fas"}


# ---------------------------------------------------------------- หน้าล็อกอิน
@app.route("/login", methods=["GET", "POST"])
def login():
    if not FAS_KEY:
        app.logger.error("ไม่พบ FAS_KEY ใน environment — service โหลด secrets.env หรือยัง?")
        return render_template("error.html", title="ระบบยังตั้งค่าไม่ครบ",
                               message="ผู้ดูแลระบบต้องตรวจสอบการตั้งค่าเซิร์ฟเวอร์"), 503

    if request.method == "GET":
        fas_b64 = request.args.get("fas", "")
        iv = request.args.get("iv", "")

        # เข้าเว็บตรง ๆ ผ่าน http://cafe.wifi (ไม่มี fas/iv) เช่น ลูกค้าพิมพ์เองเพราะ
        # captive detection ไม่เด้ง -> อธิบายวิธีต่อใหม่แทนที่จะ error
        if not fas_b64 or not iv:
            return render_template("manual.html")

        try:
            ctx = decrypt_fas_payload(fas_b64, iv, FAS_KEY)
        except FasProtocolError as exc:
            app.logger.warning("ถอดรหัส FAS payload ไม่สำเร็จ: %s", exc)
            # N35: ลูกค้าเจอกรณีนี้บ่อยที่สุดเวลาเปิดหน้า login ค้างไว้นานแล้วค่อยกด (openNDS
            # ตัด session ที่ไม่มีความเคลื่อนไหวเกิน 10 นาที ลิงก์ในหน้าเก่าจึงใช้ไม่ได้) --
            # ต้องบอกสิ่งที่ต้องทำ ไม่ใช่บอกแค่ว่าผิดพลาด
            return render_template("error.html", title="หน้านี้หมดอายุแล้ว",
                                   message="ปิดหน้านี้แล้วเปิดเว็บใดก็ได้ใหม่อีกครั้ง ระบบจะพาไปหน้าเข้าใช้งานเอง หากยังไม่ขึ้น ให้ปิด-เปิด Wi-Fi ใหม่"), 400
        if not ctx.is_complete() or not _valid_gateway(ctx):
            return render_template("error.html", title="หน้านี้หมดอายุแล้ว",
                                   message="ปิดหน้านี้แล้วเปิดเว็บใดก็ได้ใหม่อีกครั้ง ระบบจะพาไปหน้าเข้าใช้งานเอง หากยังไม่ขึ้น ให้ปิด-เปิด Wi-Fi ใหม่"), 400
        if not MAC_RE.match(ctx.clientmac):
            return render_template("error.html", title="ข้อมูลอุปกรณ์ไม่ถูกต้อง",
                                   message="ไม่รู้จักที่อยู่อุปกรณ์ กรุณาต่อ Wi-Fi ใหม่"), 400

        real_ip = client_ip()
        if not real_ip or real_ip != ctx.clientip:
            return render_template("error.html", title="ข้อมูลเครือข่ายไม่ตรงกัน",
                                   message="กรุณาต่อ Wi-Fi ใหม่อีกครั้ง"), 400
        nonce = _save_context(ctx, real_ip)
        return render_template("register.html", nonce=nonce)

    # ---- POST: ส่งคำขอใช้งาน ----
    nonce = request.form.get("nonce", "")
    real_ip = client_ip()
    ctx = _load_context(nonce, real_ip)
    if not ctx or not ctx.is_complete() or not _valid_gateway(ctx) or not MAC_RE.match(ctx.clientmac):
        return render_template("error.html", title="หน้านี้หมดอายุแล้ว",
                               message="ปิดหน้านี้แล้วเปิดเว็บใดก็ได้ใหม่อีกครั้ง ระบบจะพาไปหน้าเข้าใช้งานเอง หากยังไม่ขึ้น ให้ปิด-เปิด Wi-Fi ใหม่"), 400

    # บั๊กเดิม: ใช้ ctx.clientip (มาจาก hidden field ที่ POST เข้ามา -- ผู้ใช้ปลอมค่าได้ตรง ๆ
    # ผ่าน devtools/curl) ไปเขียนลง audit_log/device/portal_session ซึ่งเป็นหลักฐานตาม PDPA
    # ต้องใช้ IP จริงของ request (client_ip() ที่นิยามไว้แล้วแต่ไม่เคยถูกเรียก) แทน
    if real_ip != ctx.clientip:
        return render_template("error.html", title="ข้อมูลเครือข่ายไม่ตรงกัน",
                               message="กรุณาต่อ Wi-Fi ใหม่อีกครั้ง"), 400

    arp_mac = _verified_mac(real_ip)
    if not arp_mac:
        app.logger.warning("ไม่พบ MAC ใน ARP หลังลองอีกครั้ง: ip=%s", real_ip)
        return render_template("error.html", title="ยืนยันอุปกรณ์ไม่สำเร็จ",
                               message="ไม่พบอุปกรณ์บนเครือข่าย กรุณาเปิดหน้าเข้าใช้งานแล้วลองอีกครั้ง"), 400
    if arp_mac != normalize_mac(ctx.clientmac):
        app.logger.warning("MAC ไม่ตรงกับ ARP: form=%s arp=%s ip=%s", ctx.clientmac, arp_mac, real_ip)
        return render_template("error.html", title="ข้อมูลอุปกรณ์ไม่ตรงกัน",
                               message="กรุณาต่อ Wi-Fi ใหม่อีกครั้ง"), 400
    mac = arp_mac

    bucket = f"register:{mac}"
    if rate_limited(bucket):
        return render_template("register.html", nonce=nonce,
                               error="ลองหลายครั้งเกินไป กรุณารอ 10 นาที หรือแจ้งพนักงาน"), 429

    if request.form.get("consent") != "on":
        return render_template("register.html", nonce=nonce,
                               error="ต้องอ่านและยอมรับนโยบายความเป็นส่วนตัวก่อนขอใช้งาน"), 400
    # เลขบัตรเต็มเดินทางมาบน HTTP (ความเสี่ยงที่เจ้าของโครงงานยอมรับ -- sql/010) ฝั่งนี้จึงห้ามมีร่องรอย
    # เลขเต็มที่ไหนอีก: ไม่ลง log/audit ไม่ส่งกลับไปในหน้า error ไม่เก็บแบบอ่านออก
    nid = crypto.normalize_natid(request.form.get("natid", ""))
    if not crypto.valid_thai_id(nid):
        record_attempt(bucket)
        return render_template("register.html", nonce=nonce,
                               error="เลขบัตรประชาชนไม่ถูกต้อง กรุณาตรวจอีกครั้ง"), 400
    nid_hash = crypto.natid_hash(nid)
    masked = crypto.mask_natid(nid)

    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("SELECT is_blocked FROM customer WHERE natid_hash=%s", (nid_hash,))
        cust = cur.fetchone()
        if cust and cust["is_blocked"]:
            record_attempt(bucket)
            return render_template("register.html", nonce=nonce,
                                   error="ขอใช้งานไม่ได้ กรุณาติดต่อพนักงาน"), 403
        # กดส่งซ้ำ/ย้อนกลับมาหน้าเดิม = ใช้คำขอที่รออยู่ ไม่สร้างใหม่ให้รกหน้าอนุมัติ
        cur.execute("SELECT id FROM access_request WHERE mac=%s AND status='pending' "
                    "AND expires_at > NOW() FOR UPDATE", (mac,))
        if cur.fetchone():
            return redirect("/request", code=303)
        cur.execute("SELECT COUNT(*) AS n FROM access_request WHERE status='pending' "
                    "AND expires_at > NOW()")
        if int(cur.fetchone()["n"]) >= access.MAX_PENDING_REQUESTS:
            app.logger.error("คำขอที่รออนุมัติเต็ม %d รายการ", access.MAX_PENDING_REQUESTS)
            return render_template("register.html", nonce=nonce,
                                   error="ขณะนี้มีคำขอรออยู่มาก กรุณาติดต่อพนักงานโดยตรง"), 503
        cur.execute("UPDATE fas_context SET consumed_at=NOW() WHERE nonce_hash=%s "
                    "AND consumed_at IS NULL AND expires_at > NOW()", (_nonce_hash(nonce),))
        if cur.rowcount != 1:
            conn.rollback()
            return render_template("error.html", title="หน้านี้หมดอายุแล้ว",
                                   message="กรุณาเปิดหน้าเข้าใช้งานใหม่"), 400
        code = access.gen_request_code(cur)
        # ชื่อเครื่อง/OS ช่วยพนักงานถามลูกค้าว่า "ใช่เครื่องนี้ไหม" -- เครื่องบอกเอง ปลอมได้ ใช้ประกอบเท่านั้น
        ua = request.headers.get("User-Agent", "")[:device_info.UA_MAX]
        cur.execute(
            "INSERT INTO access_request (code, mac, ip, hostname, os_label, user_agent, natid_hash, "
            "natid_enc, natid_masked, consent_at, expires_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,NOW(),"
            f"DATE_ADD(NOW(), INTERVAL {access.REQUEST_TTL_MIN} MINUTE))",
            (code, mac, real_ip, device_info.lease_hostname(mac, real_ip),
             device_info.os_from_user_agent(ua), ua or None,
             nid_hash, crypto.natid_encrypt(nid), masked))

    audit.log(audit.ACCESS_REQUEST, target=code, client_ip=real_ip,
              detail=f"mac={mac} customer={masked}")
    return redirect("/request", code=303)


def _verified_mac(ip: str) -> str | None:
    """MAC ของ IP นี้จากตาราง ARP ของเคอร์เนล (ไม่ใช่ค่าจากฟอร์ม) -- R2-L01: ถ้า cache ว่างให้กระตุ้น
    ARP หนึ่งครั้งแล้วอ่านใหม่ แม้ ping ไม่ได้รับ ICMP reply ก็อาจได้ ARP reply"""
    mac = resolve_mac(ip)
    if not mac:
        try:
            subprocess.run(["ping", "-4", "-n", "-c", "1", "-W", "1", ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=2, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            app.logger.warning("กระตุ้น ARP ไม่สำเร็จ: ip=%s error=%s", ip, exc)
        mac = resolve_mac(ip)
    return normalize_mac(mac) if mac else None


# ---------------------------------------------------------------- หน้ารออนุมัติ
@app.get("/request")
def request_status():
    """สถานะคำขอล่าสุดของ "เครื่องนี้" -- ระบุเครื่องจาก IP จริง + ARP ไม่ต้องมี token ในลิงก์
    (ลิงก์นี้ส่งต่อให้เครื่องอื่นดูแทนไม่ได้ เพราะเครื่องอื่นมี MAC ของตัวเอง)"""
    ip = client_ip()
    mac = _verified_mac(ip) if ip else None
    if not mac:
        return render_template("error.html", title="ไม่พบอุปกรณ์",
                               message="เปิดหน้านี้จากเครื่องที่ต่อ Wi-Fi ของร้านเท่านั้น"), 400
    row = query_one(
        "SELECT ar.code, ar.status, ar.expires_at, ar.decision_note, ps.state AS session_state, "
        "v.valid_until FROM access_request ar "
        "LEFT JOIN portal_session ps ON ps.id = ar.portal_session_id "
        "LEFT JOIN voucher v ON v.id = ar.voucher_id "
        "WHERE ar.mac = %s AND ar.created_at > NOW() - INTERVAL 1 DAY "
        "ORDER BY ar.id DESC LIMIT 1", (mac,))
    if not row:
        return render_template("request_status.html", state="none")
    state = row["status"]
    if state == "pending" and row["expires_at"] <= datetime.now():
        state = "expired"
    elif state == "approved":
        state = {"authenticated": "online", "closed": "failed"}.get(row["session_state"], "opening")
    resp = app.make_response(render_template("request_status.html", state=state, row=row))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/policy")
def policy():
    return render_template("policy.html")


@app.errorhandler(404)
def e404(e):
    # N35: ลูกค้าที่เปิด URL ของ portal ตรง ๆ หรือกดจากหน้าที่ค้างไว้จะมาถึงตรงนี้ -- ข้อความ
    # เดิม "ไม่พบหน้านี้ / กรุณาต่อ Wi-Fi ใหม่" ชวนสับสน เพราะเขาต่อ Wi-Fi อยู่แล้ว
    return render_template("error.html", title="หน้านี้หมดอายุหรือไม่มีอยู่",
                           message="ปิดหน้านี้แล้วเปิดเว็บใดก็ได้ใหม่อีกครั้ง ระบบจะพาไปหน้าเข้าใช้งานเอง หากยังไม่ขึ้น ให้ปิด-เปิด Wi-Fi ใหม่"), 404


@app.errorhandler(500)
def e500(e):
    app.logger.exception("unhandled error")
    return render_template("error.html", title="เกิดข้อผิดพลาด",
                           message="กรุณาลองใหม่อีกครั้ง หรือแจ้งพนักงาน"), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("FAS_PORT", 18080)), debug=False)
