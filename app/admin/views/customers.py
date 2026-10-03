"""
admin/views/customers.py — ลูกค้า (เปิดเผยเลขบัตร/ระงับ/ลบตามคำขอ) + ส่งออกหลักฐาน

แยกออกจาก admin/app.py (2026-10-03) -- ตัวช่วยกลางและการเชื่อมฐานข้อมูลเรียกผ่าน core.* ตอนรันเสมอ
(เทสต์ reload admin.app แล้วสลับฐานข้อมูลจำลอง ถ้า import query_all มาตรง ๆ จะค้างตัวเก่า)
"""
from __future__ import annotations

import hashlib
import io
import json
from datetime import datetime, timedelta
from pathlib import Path
from flask import abort, flash, g, redirect, render_template, request, session, url_for
from common import audit, crypto
from common.customer import PURGED_MARK, anonymize_customer, retention_hold_until

from admin import app as core
from admin.routes import Routes
from admin.views.overview import _devices_by, _usage_by

routes = Routes()


# ---------------------------------------------------------------- ลูกค้า
@routes.get("/customers")
@core.login_required
def customers():
    q = (request.args.get("q") or "").strip()
    error = None
    if q and not crypto.valid_thai_id(q):
        error = "เลขบัตรประชาชนไม่ถูกต้อง (ต้องเป็นตัวเลข 13 หลัก และ checksum ถูก) — แสดงลูกค้าทั้งหมดแทน"
    if q and not error:
        rows = core.query_all(
            "SELECT id, natid_masked, first_seen, last_seen, visit_count, is_blocked "
            "FROM customer WHERE natid_hash = %s", (crypto.natid_hash(q),))
    else:
        rows = core.query_all(
            "SELECT id, natid_masked, first_seen, last_seen, visit_count, is_blocked "
            "FROM customer ORDER BY last_seen DESC LIMIT 100")
    devices = _devices_by("customer_id", [r["id"] for r in rows], per_key=3)
    usage = _usage_by("customer_id", [r["id"] for r in rows])
    for r in rows:
        r["devices"] = devices.get(r["id"], [])
        r["usage"] = usage.get(r["id"], dict(down=0, up=0, total=0))
        r["online"] = any(d.get("online") for d in r["devices"])
        r["state"] = ("purged" if r["natid_masked"] == PURGED_MARK else "blocked" if r["is_blocked"]
                      else "online" if r["online"] else "normal")
    counts = {k: sum(r["state"] == k for r in rows) for k in ("online", "blocked", "normal", "purged")}
    return render_template("customers.html", rows=rows, q=q if not error else "", error=error,
                           counts=counts, now=datetime.now())


@routes.post("/customers/<int:cid>/reveal")
@core.login_required
@core.admin_required
def reveal(cid: int):
    """
    เปิดเผยเลขบัตรประชาชนเต็ม — เฉพาะ role admin และต้องระบุเหตุผล
    ทุกครั้งจะถูกบันทึกลง audit_log (หลักฐานตาม PDPA)
    """
    reason = (request.form.get("reason") or "").strip()
    if len(reason) < 10:
        abort(400, "ต้องระบุเหตุผลอย่างน้อย 10 ตัวอักษร")

    row = core.query_one("SELECT natid_enc, natid_masked FROM customer WHERE id = %s", (cid,))
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


# แก้บั๊ก M2: customer.is_blocked ถูกอ่านใน /issue และ /login ของ fas มาตั้งแต่แรก (บล็อก
# ลูกค้าไม่ให้ออก voucher ใหม่/ล็อกอินได้) แต่ไม่มีหน้าจอไหนตั้งค่านี้เป็น true ได้เลย
@routes.post("/customers/<int:cid>/block")
@core.login_required
@core.admin_required
def toggle_block_customer(cid: int):
    row = core.query_one("SELECT is_blocked FROM customer WHERE id=%s", (cid,))
    if not row:
        abort(404)
    new_state = not row["is_blocked"]
    core.execute("UPDATE customer SET is_blocked=%s WHERE id=%s", (new_state, cid))
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
@routes.post("/customers/<int:cid>/erase")
@core.login_required
@core.admin_required
def erase_customer(cid: int):
    reason = (request.form.get("reason") or "").strip()
    if len(reason) < 10:
        abort(400, "ต้องระบุเหตุผล/คำขอของเจ้าของข้อมูลอย่างน้อย 10 ตัวอักษร")

    row = core.query_one("SELECT id, natid_masked FROM customer WHERE id = %s", (cid,))
    if not row:
        abort(404)
    if row["natid_masked"] == PURGED_MARK:
        flash("ลูกค้ารายนี้ถูกลบข้อมูลระบุตัวตนไปแล้ว", "warn")
        return redirect(url_for("customers"))

    # N33: ม.26 บังคับให้เก็บข้อมูลผู้ใช้บริการไว้ตามกำหนด ลบก่อนครบ = log ที่เหลือชี้กลับไปหา
    # บุคคลไม่ได้ ซึ่งผิดกฎหมาย -- PDPA เองยกเว้นสิทธิ์ขอลบไว้ในกรณีที่มีกฎหมายอื่นบังคับให้เก็บ
    # สิทธิ์ของเจ้าของข้อมูลไม่ได้หายไป แค่เลื่อน และ purge_old_data จะลบให้เองเมื่อพ้นกำหนด
    hold_until = retention_hold_until(core.query_one, cid)
    if hold_until:
        audit.log(audit.ERASE_REFUSED, staff_id=session["staff_id"], target=f"customer:{cid}",
                  client_ip=g.client_ip,
                  detail=f"ยังอยู่ในช่วงเก็บบังคับถึง {hold_until:%Y-%m-%d} — คำขอ: {reason}")
        flash(f"ยังลบข้อมูลระบุตัวตนไม่ได้ ต้องเก็บไว้ถึง {hold_until:%d/%m/%Y} "
              "ตาม พ.ร.บ.คอมพิวเตอร์ ม.26 (ระบบจะลบให้อัตโนมัติเมื่อพ้นกำหนด) "
              "คำขอของเจ้าของข้อมูลถูกบันทึกไว้แล้ว", "warn")
        return redirect(url_for("customers"))

    n = anonymize_customer(core.execute, cid)
    if not n:
        abort(404)

    audit.log(audit.ERASE_CUSTOMER, staff_id=session["staff_id"], target=f"customer:{cid}",
              client_ip=g.client_ip, detail=reason)
    flash("ลบข้อมูลระบุตัวตนของลูกค้ารายนี้แล้วตามคำขอ", "success")
    return redirect(url_for("customers"))


# ---------------------------------------------------------------- ส่งออกหลักฐาน (ม.26 / คำสั่งเจ้าหน้าที่)
# เดิมต้อง SSH เข้าไปรัน tools/export_evidence.py -- เจ้าของร้านทำเองไม่ได้ และ SSH เข้าจากวงลูกค้าไม่ได้
# หน้านี้ใช้ตรรกะชุดเดียวกับเครื่องมือนั้นเป๊ะ (คิวรี่/JOIN/manifest) ไฟล์บนเว็บกับไฟล์จาก CLI จึงตรงกันเสมอ
EVIDENCE_MAX_DAYS_PERSON = 186   # รายคน/รายเครื่อง: ครอบระยะเก็บ 180 วันได้ทั้งหมด


EVIDENCE_MAX_DAYS_ALL = 7        # ทุกเครื่อง: ข้อมูลเยอะมาก จำกัดไว้กันเครื่องค้าง


@routes.route("/evidence", methods=["GET", "POST"])
@core.login_required
@core.admin_required
def evidence():
    from tools import export_evidence as ev

    history = core.query_all(
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
            customer = ev.find_customer(request.form.get("natid", ""), core.query_one)
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
            return ev.query_customer_rows(build, customer["id"], start, end, core.query_all)
        return core.query_all(*build(start, end, mac=mac))

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
    resp = core.app.make_response(data)
    resp.headers["Content-Type"] = "application/zip"
    resp.headers["Content-Disposition"] = f"attachment; filename=evidence_{tag}_{stamp}.zip"
    resp.headers["X-Evidence-SHA256"] = zip_sha
    resp.headers["Cache-Control"] = "no-store"
    return resp
