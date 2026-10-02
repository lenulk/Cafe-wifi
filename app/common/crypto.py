"""
common/crypto.py — ฟังก์ชันความปลอดภัยหลักของระบบ

หลักการ (ดู D6 และ §6.2 ใน PROJECT_PLAN.md):
  * เลขบัตรประชาชน 13 หลัก ห้ามเก็บเป็น plaintext
  * เก็บ 3 รูปแบบ:
      - natid_hash   HMAC-SHA256(natid, PEPPER)  -> ใช้ค้นหา / กันซ้ำ (deterministic)
      - natid_enc    AES-256-GCM(natid, DEK)     -> ถอดกลับได้เมื่อมีหมายศาล
      - natid_masked '1-2345-XXXXX-XX-X'         -> ใช้แสดงผลบนหน้าจอ
  * PEPPER และ DEK อยู่ใน /etc/cafe-wifi/secrets.env เท่านั้น (chmod 0640)
"""
from __future__ import annotations

import hmac
import os
import re
import secrets
import hashlib
from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------- Argon2id
# ค่าเหล่านี้ตั้งให้พอเหมาะกับ Raspberry Pi 4/5 (ประมาณ 100-200 ms ต่อครั้ง)
_ph: Final = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

# ตัวอักษรสำหรับสุ่มรหัสผ่าน ตัดตัวที่อ่านสับสน 0/O, 1/I/l, 2/Z, 5/S ออก
_ALPHABET: Final = "ABCDEFGHJKMNPQRTUVWXY346789"


class SecretsMissingError(RuntimeError):
    """ไม่พบกุญแจใน environment — ปกติแปลว่าไม่ได้โหลด secrets.env"""


def _key(name: str) -> bytes:
    raw = os.environ.get(name, "")
    if not raw:
        raise SecretsMissingError(
            f"ไม่พบตัวแปร {name} — ตรวจสอบว่า service โหลด /etc/cafe-wifi/secrets.env แล้ว"
        )
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise SecretsMissingError(f"{name} ต้องเป็น hex string") from exc
    if len(key) != 32:
        raise SecretsMissingError(f"{name} ต้องยาว 32 ไบต์ (64 hex chars) แต่ได้ {len(key)}")
    return key


# ---------------------------------------------------------------- เลขบัตรประชาชน
def valid_thai_id(nid: str) -> bool:
    """
    ตรวจ checksum เลขประจำตัวประชาชนไทย 13 หลัก (mod-11)
        sum = Σ d[i] * (13 - i)   สำหรับ i = 0..11
        check = (11 - sum % 11) % 10   ต้องเท่ากับ d[12]
    """
    nid = normalize_natid(nid)
    if not (len(nid) == 13 and nid.isdigit()):
        return False
    total = sum(int(nid[i]) * (13 - i) for i in range(12))
    return (11 - total % 11) % 10 == int(nid[12])


def normalize_natid(nid: str) -> str:
    """ลบขีด เว้นวรรค และอักขระอื่นที่ไม่ใช่ตัวเลขออก"""
    return re.sub(r"\D", "", nid or "")


def mask_natid(nid: str) -> str:
    """1234567890123 -> '1-2345-XXXXX-XX-3'  (เปิดเผยเท่าที่จำเป็นต่อการยืนยันด้วยตา)"""
    nid = normalize_natid(nid)
    if len(nid) != 13:
        return "X-XXXX-XXXXX-XX-X"
    return f"{nid[0]}-{nid[1:5]}-XXXXX-XX-{nid[12]}"


def natid_hash(nid: str) -> str:
    """HMAC-SHA256 พร้อม pepper — deterministic จึงใช้เป็น unique key ค้นหาได้"""
    nid = normalize_natid(nid)
    return hmac.new(_key("NATID_PEPPER"), nid.encode("utf-8"), hashlib.sha256).hexdigest()


def natid_encrypt(nid: str) -> bytes:
    """AES-256-GCM -> nonce(12) || ciphertext || tag(16)"""
    nid = normalize_natid(nid)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_key("NATID_DEK")).encrypt(nonce, nid.encode("utf-8"), None)
    return nonce + ct


def natid_decrypt(blob: bytes) -> str:
    """ถอดรหัสเลขบัตร — ทุกครั้งที่เรียกต้องเขียน audit_log ด้วย (ดู admin/views)"""
    if len(blob) < 29:
        raise ValueError("ciphertext สั้นเกินไป")
    return AESGCM(_key("NATID_DEK")).decrypt(blob[:12], blob[12:], None).decode("utf-8")


# ---------------------------------------------------------------- รหัสผ่าน
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        _ph.verify(stored_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(stored_hash)
    except InvalidHashError:
        return True


def gen_voucher_code(prefix: str = "CAFE") -> str:
    return f"{prefix}-{''.join(secrets.choice(_ALPHABET) for _ in range(5))}"


def gen_temp_staff_password() -> str:
    """รหัสชั่วคราวของพนักงาน (หน้า /staff) -- ผ่าน check_admin_password เสมอ และอ่านบอกกันได้

    รูปแบบ xxxx-xxxx-xxxx (14 ตัว) จาก _ALPHABET ที่ไม่มีตัวกำกวม บังคับให้มีพิมพ์ใหญ่/เล็ก/ตัวเลขครบ
    ใช้ได้ครั้งเดียว: login แล้วถูกบังคับเปลี่ยนทันที (staff.must_change_password)
    """
    while True:
        pw = "-".join("".join(secrets.choice(_ALPHABET + _ALPHABET.lower()) for _ in range(4))
                      for _ in range(3))
        if not check_admin_password(pw):
            return pw


def check_admin_password(password: str) -> list[str]:
    """
    นโยบายรหัสผ่านผู้ดูแลระบบ คืน list ของปัญหา (ว่าง = ผ่าน)
    """
    problems: list[str] = []
    if len(password) < 12:
        problems.append("ต้องยาวอย่างน้อย 12 ตัวอักษร")
    if not re.search(r"[a-z]", password):
        problems.append("ต้องมีตัวพิมพ์เล็กอย่างน้อย 1 ตัว")
    if not re.search(r"[A-Z]", password):
        problems.append("ต้องมีตัวพิมพ์ใหญ่อย่างน้อย 1 ตัว")
    if not re.search(r"\d", password):
        problems.append("ต้องมีตัวเลขอย่างน้อย 1 ตัว")
    if password.lower() in {"password1234", "administrator", "adminadmin1", "cafewifi1234"}:
        problems.append("รหัสผ่านนี้เดาง่ายเกินไป")
    return problems


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest((a or "").strip(), (b or "").strip())
