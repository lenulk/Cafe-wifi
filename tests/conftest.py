"""ค่าตั้งต้นสำหรับการทดสอบ — ใช้กุญแจปลอม ไม่แตะ secrets.env ของจริง"""
import os
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "app"))
sys.path.insert(0, str(ROOT))  # ให้ import `tools.xxx` (อยู่ที่รากรีโป ไม่ใช่ใต้ app/) ได้ด้วย

os.environ.setdefault("NATID_PEPPER", "aa" * 32)
os.environ.setdefault("NATID_DEK", "bb" * 32)
os.environ.setdefault("SECRET_KEY", "cc" * 32)
os.environ.setdefault("GATEWAY_NAME", "Cafe-Guest-Test")
# DB จำลองของแต่ละไฟล์เทสต์ไม่รู้จักตาราง rate_attempt -- ใช้ตัวนับในหน่วยความจำ (ตัวนับแบบ DB มีเทสต์แยก)
os.environ.setdefault("RATE_LIMIT_BACKEND", "memory")
