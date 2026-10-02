"""ยืนยัน pending FAS sessions กับ openNDS ก่อนนับว่าออนไลน์จริง."""
from __future__ import annotations

import json
import logging
import subprocess
from datetime import datetime

from common import audit
from common.db import get_conn

log = logging.getLogger("cafe-wifi.reconcile_pending")


def gateway_clients() -> dict | None:
    try:
        from tools.enforce_voucher_expiry import run_ndsctl
        result = run_ndsctl(["ndsctl", "json"])  # ลองใหม่เองเมื่อ openNDS ตอบ busy (exit 4)
        if result.returncode != 0:
            raise subprocess.CalledProcessError(result.returncode, "ndsctl json")
        return (json.loads(result.stdout.decode(errors="replace")) or {}).get("clients", {})
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        log.error("อ่านสถานะ openNDS ไม่ได้: %s", exc)
        return None


def confirmed_at(client: dict | None, ip: str, started_at: datetime) -> datetime | None:
    """คืนเวลาที่ openNDS เปิดสิทธิ์จริง (session_start) ถ้ายืนยันได้ ไม่งั้นคืน None

    MAC อย่างเดียวไม่พอ: ต้องเป็น IP เดิมและ gateway session ที่เริ่มหลัง pending
    """
    if not client or not str(client.get("state", "")).lower().startswith("auth"):
        return None
    if str(client.get("ip") or client.get("clientip") or "") != ip:
        return None
    try:
        gateway_start = datetime.fromtimestamp(int(client["session_start"]))
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return None
    return gateway_start if gateway_start >= started_at else None


def purge_orphan_claims() -> int:
    """R2-01: ลบ claim ที่ portal_session_id=NULL ซึ่งหลุด commit มาจาก /login รุ่นก่อนแก้

    แถวแบบนี้ไม่มี session ให้ผูก ลูปหลักจึงไม่เคยลบ และทำให้ MAC นั้นได้ 409 ตลอดไป
    แยก transaction จากลูปหลักและแตะแค่ตารางนี้ เพื่อไม่ให้ลำดับ lock ชนกับ /login
    (claim ของ /login ที่ยังไม่ commit จะผูก portal_session_id ก่อน commit เสมอ จึงไม่ถูกลบ)
    """
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM pending_mac_claim WHERE portal_session_id IS NULL")
        purged = cur.rowcount
    if purged:
        log.warning("ลบ pending_mac_claim ที่ค้างอยู่ %d รายการ", purged)
    return purged


def run() -> tuple[int, int]:
    clients = gateway_clients()
    promoted = expired = 0
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute("DELETE FROM fas_context WHERE expires_at < "
                    "DATE_SUB(NOW(), INTERVAL 1 DAY)")
        cur.execute("SELECT ps.id, ps.voucher_id, ps.mac, ps.ip, ps.started_at, "
                    "ps.pending_until, v.status, v.valid_until "
                    "FROM portal_session ps JOIN voucher v ON v.id=ps.voucher_id "
                    "WHERE ps.state='pending' ORDER BY ps.id FOR UPDATE")
        pending = cur.fetchall()
        # อ่าน ndsctl ไม่ได้ (openNDS กำลังรีสตาร์ท หรือ ndsctl ตอบ busy เพราะ cafe-enforce/คนดูแล
        # เรียกพร้อมกัน -- เจอจริงบน Pi 2026-10-02 exit 4) = ไม่รู้ว่าใครได้สิทธิ์แล้ว ต้องข้ามทั้งรอบ
        # เดิมยังตัด pending ที่เลยกำหนดทิ้งเป็น auth_timeout ทั้งที่ลูกค้าอาจออนไลน์แล้วจริง
        if clients is None:
            pending = []
        for row in pending:
            # R2-08: ตรวจการยืนยันจาก openNDS ก่อน timeout -- ลูกค้าที่กดตาม redirect ใกล้
            # วินาทีสุดท้ายของ pending ถูกเปิดสิทธิ์ไปแล้ว ต้องไม่ถูกตัดทิ้งว่า auth_timeout
            gateway_start = None
            if clients is not None:
                client = clients.get(row["mac"].lower()) or clients.get(row["mac"].upper())
                gateway_start = confirmed_at(client, row["ip"], row["started_at"])
            if gateway_start is None and row["pending_until"] <= datetime.now():
                from tools.enforce_voucher_expiry import deauth_mac
                if not deauth_mac(row["mac"]):
                    log.error("pending %s หมดเวลาแต่ตัดสิทธิ์ที่ gateway ไม่สำเร็จ", row["id"])
                    continue
                cur.execute("UPDATE portal_session SET state='closed', ended_at=NOW(), "
                            "terminate_cause='auth_timeout' WHERE id=%s AND state='pending'",
                            (row["id"],))
                cur.execute("DELETE FROM pending_mac_claim WHERE mac=%s AND portal_session_id=%s",
                            (row["mac"], row["id"]))
                expired += 1
                continue
            if gateway_start is None:
                continue
            if row["status"] != "active" or row["valid_until"] <= datetime.now():
                from tools.enforce_voucher_expiry import deauth_mac
                if not deauth_mac(row["mac"]):
                    log.error("voucher ไม่ active แต่ตัด MAC %s ไม่สำเร็จ", row["mac"])
                    continue
                cur.execute("UPDATE portal_session SET state='closed', ended_at=NOW(), "
                            "terminate_cause='voucher_invalid' WHERE id=%s", (row["id"],))
                cur.execute("DELETE FROM pending_mac_claim WHERE mac=%s AND portal_session_id=%s",
                            (row["mac"], row["id"]))
                continue
            cur.execute("SELECT id, voucher_id, started_at, authenticated_at FROM portal_session WHERE mac=%s "
                        "AND state='authenticated' AND ended_at IS NULL FOR UPDATE",
                        (row["mac"],))
            for old in cur.fetchall():
                from common.traffic import sum_session_traffic_bytes
                from tools.enforce_voucher_expiry import close_session

                def lookup(sql, args=()):
                    cur.execute(sql, args)
                    return cur.fetchone()

                def execute(sql, args=()):
                    cur.execute(sql, args)
                    return cur.rowcount

                bo, bi = sum_session_traffic_bytes(
                    lookup, row["mac"], old["authenticated_at"] or old["started_at"], gateway_start)
                close_session(execute, old["id"], old["voucher_id"], bo, bi,
                              "reauth", ended_at=gateway_start)
            cur.execute("INSERT INTO device (voucher_id, mac, last_ip) VALUES (%s,%s,%s) "
                        "ON DUPLICATE KEY UPDATE last_ip=VALUES(last_ip)",
                        (row["voucher_id"], row["mac"], row["ip"]))
            # R2-08: ใช้เวลาที่ openNDS เปิดสิทธิ์จริง ไม่ใช่เวลาที่ timer มาเจอ (ช้ากว่าได้หลายวินาที)
            # ไม่งั้น DNS query ชุดแรกหลังเปิดสิทธิ์จะมี ts < authenticated_at และโยงหาลูกค้าไม่ได้
            cur.execute("UPDATE portal_session SET state='authenticated', authenticated_at=%s "
                        "WHERE id=%s AND state='pending'", (gateway_start, row["id"]))
            cur.execute("DELETE FROM pending_mac_claim WHERE mac=%s AND portal_session_id=%s",
                        (row["mac"], row["id"]))
            promoted += 1
    purge_orphan_claims()
    if promoted:
        audit.log(audit.LOGIN_OK, detail=f"confirmed={promoted}")
    if expired:
        log.warning("pending session หมดเวลา %d รายการ", expired)
    return promoted, expired


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
