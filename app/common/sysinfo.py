"""
common/sysinfo.py — CPU / RAM / อุณหภูมิ / การเชื่อมต่ออินเทอร์เน็ต / ทดสอบความเร็ว สำหรับหน้า /status

อ่านจาก /proc และ /sys ตรง ๆ (ไม่ต้องลง psutil เพิ่ม) -- ทุกฟังก์ชันรับ path/ฟังก์ชันฉีดได้เพื่อเทสต์บน
Windows ได้ และอ่านไม่ได้ = คืน None (หน้าเว็บต้องไม่พังเพราะเครื่องไม่มีไฟล์ใดไฟล์หนึ่ง)

ทดสอบความเร็วใช้ speed.cloudflare.com (ไม่ต้องลงโปรแกรมเพิ่ม) -- วัดความเร็วของ "สายเน็ตร้าน" ที่ Pi
ต่ออยู่ ขณะทดสอบจะแย่ง bandwidth ลูกค้าชั่วครู่ จึงจำกัดขนาด/เวลา และให้กดได้ครั้งเดียวต่อ SPEEDTEST_COOLDOWN
"""
from __future__ import annotations

import socket
import threading
import time
import urllib.request
from datetime import datetime


# ---------------------------------------------------------------- CPU / RAM / อุณหภูมิ
def _cpu_times(path: str = "/proc/stat") -> tuple[int, int] | None:
    try:
        with open(path) as fh:
            parts = fh.readline().split()
    except OSError:
        return None
    if not parts or parts[0] != "cpu":
        return None
    vals = [int(x) for x in parts[1:]]
    idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle + iowait
    return sum(vals), idle


def cpu_percent(sample_sec: float = 0.3, read=_cpu_times, sleep=time.sleep) -> float | None:
    a = read()
    sleep(sample_sec)
    b = read()
    if not a or not b or b[0] <= a[0]:
        return None
    total, idle = b[0] - a[0], b[1] - a[1]
    return round(100.0 * (total - idle) / total, 1)


def memory(path: str = "/proc/meminfo") -> dict | None:
    info = {}
    try:
        with open(path) as fh:
            for line in fh:
                k, _, v = line.partition(":")
                info[k] = int(v.split()[0]) * 1024  # kB -> bytes
    except (OSError, ValueError, IndexError):
        return None
    total, avail = info.get("MemTotal"), info.get("MemAvailable")
    if not total or avail is None:
        return None
    used = total - avail
    return dict(total=total, used=used, percent=round(100.0 * used / total, 1))


def cpu_temp(path: str = "/sys/class/thermal/thermal_zone0/temp") -> float | None:
    try:
        with open(path) as fh:
            return round(int(fh.read().strip()) / 1000, 1)
    except (OSError, ValueError):
        return None


def uptime_seconds(path: str = "/proc/uptime") -> int | None:
    try:
        with open(path) as fh:
            return int(float(fh.read().split()[0]))
    except (OSError, ValueError, IndexError):
        return None


def load_average(path: str = "/proc/loadavg") -> tuple[float, float, float] | None:
    try:
        with open(path) as fh:
            a, b, c = fh.read().split()[:3]
        return float(a), float(b), float(c)
    except (OSError, ValueError):
        return None


def cpu_count() -> int:
    import os
    return os.cpu_count() or 1


def resources() -> dict:
    return dict(cpu=cpu_percent(), cores=cpu_count(), load=load_average(), mem=memory(),
                temp=cpu_temp(), uptime=uptime_seconds())


# ---------------------------------------------------------------- อินเทอร์เน็ต
CHECK_URL = "http://connectivitycheck.gstatic.com/generate_204"  # ตอบ 204 ว่าง ๆ -- เบาและเร็ว
DNS_TEST_NAME = "www.google.com"


def default_gateway(path: str = "/proc/net/route") -> dict | None:
    """เส้นทางออกเน็ตหลักของ Pi (metric ต่ำสุด) -> {iface, gateway}"""
    best = None
    try:
        with open(path) as fh:
            next(fh)
            for line in fh:
                f = line.split()
                if len(f) >= 7 and f[1] == "00000000":  # destination 0.0.0.0 = default route
                    gw = socket.inet_ntoa(bytes.fromhex(f[2])[::-1])
                    metric = int(f[6])
                    if best is None or metric < best[0]:
                        best = (metric, dict(iface=f[0], gateway=gw))
    except (OSError, ValueError, StopIteration):
        return None
    return best[1] if best else None


def internet_status(timeout: float = 3.0, opener=urllib.request.urlopen,
                    resolver=socket.getaddrinfo) -> dict:
    """ต่อเน็ตได้ไหม + เร็วแค่ไหน (latency ของ HTTP เล็ก ๆ หนึ่งครั้ง) + DNS ใช้ได้ไหม"""
    out = dict(online=False, latency_ms=None, dns_ok=False, dns_ms=None, error=None,
               route=default_gateway())
    t = time.monotonic()
    try:
        resolver(DNS_TEST_NAME, 443)
        out.update(dns_ok=True, dns_ms=round((time.monotonic() - t) * 1000))
    except OSError as exc:
        out["error"] = f"DNS ใช้ไม่ได้: {exc}"
    t = time.monotonic()
    try:
        with opener(CHECK_URL, timeout=timeout) as r:
            if r.status in (200, 204):
                out.update(online=True, latency_ms=round((time.monotonic() - t) * 1000))
    except OSError as exc:
        out["error"] = out["error"] or f"ออกเน็ตไม่ได้: {getattr(exc, 'reason', exc)}"
    return out


# ---------------------------------------------------------------- ทดสอบความเร็ว
SPEED_DOWN_URL = "https://speed.cloudflare.com/__down?bytes={n}"
SPEED_UP_URL = "https://speed.cloudflare.com/__up"
SPEED_DOWN_BYTES = 25_000_000
SPEED_UP_BYTES = 8_000_000
SPEED_MAX_SEC = 8.0           # ต่อขา -- รวมทั้งหมดไม่เกิน ~20 วิ (gunicorn --timeout 60)
SPEEDTEST_COOLDOWN = 60       # วินาที -- กันกดรัวจนแย่งเน็ตลูกค้า

# speed.cloudflare.com ตอบ 403 กับ User-Agent ปริยายของ Python ("Python-urllib/3.x") -- พบบน Pi จริง
SPEED_HEADERS = {"User-Agent": "Mozilla/5.0 (cafe-wifi speed test)"}

_speed_lock = threading.Lock()
_last_speed: dict = {}


def _mbps(nbytes: int, sec: float) -> float:
    return round(nbytes * 8 / sec / 1_000_000, 1) if sec > 0 else 0.0


def _measure_download(opener) -> tuple[float, int]:
    t = time.monotonic()
    got = 0
    req = urllib.request.Request(SPEED_DOWN_URL.format(n=SPEED_DOWN_BYTES), headers=SPEED_HEADERS)
    with opener(req, timeout=10) as r:
        while time.monotonic() - t < SPEED_MAX_SEC:
            chunk = r.read(64 * 1024)
            if not chunk:
                break
            got += len(chunk)
    return _mbps(got, time.monotonic() - t), got


def _measure_upload(opener) -> tuple[float, int]:
    data = b"0" * SPEED_UP_BYTES
    req = urllib.request.Request(SPEED_UP_URL, data=data, method="POST",
                                 headers=dict(SPEED_HEADERS, **{"Content-Type": "application/octet-stream"}))
    t = time.monotonic()
    with opener(req, timeout=SPEED_MAX_SEC + 5) as r:
        r.read()
    return _mbps(len(data), time.monotonic() - t), len(data)


SPEED_HOST = "speed.cloudflare.com"
_connect = socket.create_connection  # เทสต์แทนที่ได้


def _measure_ping(opener=None, tries: int = 3) -> float | None:
    """เวลาเปิดการเชื่อมต่อ TCP (ดีที่สุดใน 3 ครั้ง) -- ใกล้เคียง ping จริงกว่าการจับเวลา HTTPS ทั้งก้อน
    ที่รวมการแลกกุญแจ TLS ด้วย (ลองบน Pi: HTTPS 134 ms) · opener ไม่ได้ใช้ คงไว้ให้รูปแบบเหมือนตัวอื่น"""
    best = None
    for _ in range(tries):
        t = time.monotonic()
        try:
            _connect((SPEED_HOST, 443), timeout=5).close()
        except OSError:
            continue
        ms = (time.monotonic() - t) * 1000
        best = ms if best is None else min(best, ms)
    return round(best) if best is not None else None


def last_speed_test() -> dict:
    return dict(_last_speed)


def run_speed_test(opener=urllib.request.urlopen, now=time.time) -> dict:
    """คืน {ok, ping_ms, down_mbps, up_mbps, at} หรือ {ok: False, error, retry_in} -- รันทีละครั้งเท่านั้น"""
    if _last_speed.get("ts") and now() - _last_speed["ts"] < SPEEDTEST_COOLDOWN:
        wait = int(SPEEDTEST_COOLDOWN - (now() - _last_speed["ts"]))
        return dict(ok=False, error=f"เพิ่งทดสอบไป รออีก {wait} วินาที", retry_in=wait)
    if not _speed_lock.acquire(blocking=False):
        return dict(ok=False, error="กำลังทดสอบอยู่ (มีคนกดก่อนหน้า) รอสักครู่", retry_in=10)
    try:
        result = dict(ok=True, ping_ms=_measure_ping(opener), down_mbps=None, up_mbps=None)
        try:
            result["down_mbps"], _ = _measure_download(opener)
            result["up_mbps"], _ = _measure_upload(opener)
        except OSError as exc:
            result.update(ok=result["down_mbps"] is not None,
                          error=f"ทดสอบไม่สำเร็จ: {getattr(exc, 'reason', exc)}")
        result["at"] = datetime.now().strftime("%d/%m %H:%M:%S")
        if result["ok"]:  # ล้มเหลว = ไม่ต้องรอ cooldown ให้ลองใหม่ได้ทันที
            _last_speed.clear()
            _last_speed.update(result, ts=now())
        return result
    finally:
        _speed_lock.release()
