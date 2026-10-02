"""T2 — การเข้ารหัส/แฮชเลขบัตรประชาชน และนโยบายรหัสผ่าน"""
import os

import pytest

from common import crypto

SAMPLE = "0000000000001"   # เลขทดสอบสังเคราะห์: ผ่าน checksum แต่ขึ้นต้นด้วย 0
                          # จึงไม่มีทางตรงกับเลขบัตรจริงของใคร (ของจริงขึ้นต้น 1-8)
SAMPLE2 = "0000000000019"  # เลขทดสอบสังเคราะห์อีกชุด


def test_encrypt_decrypt_roundtrip():
    assert crypto.natid_decrypt(crypto.natid_encrypt(SAMPLE)) == SAMPLE


def test_ciphertext_never_repeats():
    blobs = {bytes(crypto.natid_encrypt(SAMPLE)) for _ in range(100)}
    assert len(blobs) == 100, "nonce ต้องสุ่มใหม่ทุกครั้ง"


def test_plaintext_not_present_in_ciphertext():
    assert SAMPLE.encode() not in crypto.natid_encrypt(SAMPLE)


def test_tampered_ciphertext_is_rejected():
    blob = bytearray(crypto.natid_encrypt(SAMPLE))
    blob[-1] ^= 0xFF
    with pytest.raises(Exception):
        crypto.natid_decrypt(bytes(blob))


def test_hash_is_deterministic_and_unique():
    assert crypto.natid_hash(SAMPLE) == crypto.natid_hash(SAMPLE)
    assert crypto.natid_hash(SAMPLE) != crypto.natid_hash(SAMPLE2)
    assert len(crypto.natid_hash(SAMPLE)) == 64


def test_password_hash_roundtrip():
    h = crypto.hash_password("CafeWifi2026Secure")
    assert "CafeWifi2026Secure" not in h
    assert crypto.verify_password(h, "CafeWifi2026Secure")
    assert not crypto.verify_password(h, "CafeWifi2026Secur3")


@pytest.mark.parametrize("pw,ok", [
    ("CafeWifi2026Secure", True),
    ("short1A", False),
    ("alllowercase123", False),
    ("ALLUPPERCASE123", False),
    ("NoDigitsHereAtAll", False),
])
def test_admin_password_policy(pw, ok):
    assert (crypto.check_admin_password(pw) == []) is ok


def test_missing_key_raises_clear_error(monkeypatch):
    monkeypatch.delenv("NATID_DEK", raising=False)
    with pytest.raises(crypto.SecretsMissingError):
        crypto.natid_encrypt(SAMPLE)
