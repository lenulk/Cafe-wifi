"""
common/device_info.py — ชื่อเครื่อง (hostname) + ระบบปฏิบัติการของเครื่องลูกค้า

ใช้ช่วยพนักงานดูว่าคำขอ/แถว log เป็นของเครื่องไหน ("iPhone · iOS 17.5", "DESKTOP-7KQ2L") -- ค่าทั้งคู่
**เครื่องลูกค้าบอกเอง ปลอมได้** ใช้เป็นข้อมูลประกอบเท่านั้น หลักฐานหลักยังเป็น MAC (ยืนยันจาก ARP) + เวลา

  * hostname: DHCP option 12 ที่ dnsmasq จดไว้ใน lease file (คอลัมน์ที่ 4, "*" = เครื่องไม่ส่งมา)
    Android รุ่นใหม่มักไม่ส่ง/ส่งชื่อกลาง ๆ -- ว่างได้เป็นเรื่องปกติ
  * OS: User-Agent ของเบราว์เซอร์ตอนลูกค้ากดขอใช้งานบน portal

hostname อาจมีชื่อจริงของลูกค้า (เช่น "ASUS-Laptop-Somchai") = ข้อมูลส่วนบุคคล -- ล้างพร้อม PII อื่นใน
common/customer.py::anonymize_customer() และแจ้งไว้ในนโยบายความเป็นส่วนตัว (fas/templates/policy.html)
"""
from __future__ import annotations

import re

LEASE_FILE = "/var/lib/misc/dnsmasq.leases"  # ชื่อตายตัว ดูเหตุผลใน install.sh (openNDS dhcp_check)
HOSTNAME_MAX = 63
UA_MAX = 255

_HOST_BAD = re.compile(r"[^A-Za-z0-9._-]")


def clean_hostname(name: str | None) -> str | None:
    """เหลือเฉพาะอักขระของชื่อ DNS + ตัดความยาว -- ค่ามาจากเครื่องลูกค้า ห้ามเชื่อ"""
    name = _HOST_BAD.sub("", (name or "").strip())[:HOSTNAME_MAX].strip(".-")
    return name or None


def lease_hostname(mac: str, ip: str | None = None, path: str | None = None) -> str | None:
    """hostname ของ MAC นี้จาก lease ของ dnsmasq (ถ้าส่ง ip มา ต้องตรงด้วย) -- อ่านไม่ได้ = None เงียบ ๆ"""
    mac = (mac or "").lower()
    try:
        with open(path or LEASE_FILE, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[1].lower() == mac and (ip is None or parts[2] == ip):
            return None if parts[3] == "*" else clean_hostname(parts[3])
    return None


def _ver(raw: str) -> str:
    return raw.replace("_", ".")


def os_from_user_agent(ua: str | None) -> str | None:
    """User-Agent -> ข้อความสั้นที่พนักงานอ่านรู้เรื่อง เช่น "iPhone · iOS 17.5", "Android 14 · SM-A546E" """
    ua = ua or ""
    if not ua:
        return None
    m = re.search(r"\((iPhone|iPad|iPod)[^)]*?OS (\d+(?:_\d+)*)", ua)
    if m:
        dev, ver = m.group(1), _ver(m.group(2))
        return f"{dev} · {'iPadOS' if dev == 'iPad' else 'iOS'} {ver}"
    m = re.search(r"Android (\d+(?:\.\d+)*)(?:; ([^;)]+))?", ua)
    if m:
        model = (m.group(2) or "").strip()
        model = re.sub(r"\s*Build/.*$", "", model)
        # Chrome ลดข้อมูลใน UA แล้วใส่รุ่นเป็น "K" -- ไม่มีประโยชน์ ไม่ต้องแสดง
        if model and model != "K" and not model.startswith(("wv", "Linux")):
            return f"Android {m.group(1)} · {model[:40]}"
        return f"Android {m.group(1)}"
    m = re.search(r"Windows NT (\d+\.\d+)", ua)
    if m:
        # Windows 11 ยังส่ง "NT 10.0" เหมือน Windows 10 -- แยกจาก UA ไม่ได้
        return {"10.0": "Windows 10/11", "6.3": "Windows 8.1", "6.2": "Windows 8",
                "6.1": "Windows 7"}.get(m.group(1), f"Windows NT {m.group(1)}")
    if "CrOS" in ua:
        return "ChromeOS"
    if "Mac OS X" in ua:
        return "macOS"  # Safari/Chrome ตรึงเลขรุ่นไว้ที่ 10.15.7 มานานแล้ว -- เลขไม่น่าเชื่อ ไม่แสดง
    if "Linux" in ua:
        return "Linux"
    return None
