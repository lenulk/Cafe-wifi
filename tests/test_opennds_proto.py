"""
ทดสอบ fas/opennds_proto.py — โปรโตคอลคุยกับ openNDS (fas_secure_enabled = 2)

ส่วนใหญ่ยืนยันด้วยตัวเองว่า encrypt<->decrypt สมมาตรกัน (เราคุมทั้งสองฝั่งของการทดสอบนี้เอง
เพราะไม่มี openNDS binary จริงในสภาพแวดล้อมที่รัน pytest นี้) ยกเว้น
test_decrypt_real_capture_from_live_opennds() ที่ใช้ payload จริงจาก openNDS 10.1.3 ตัวเป็นๆ
(จับมาจาก VM lab, 2026-08-28) — เขียนเพิ่มหลังพบว่าการ round-trip กับตัวเองแบบข้างต้น
"หลอก" ให้เทสต์ผ่านได้ทั้งที่ไม่ตรงกับ openNDS จริงเลย (บั๊ก double-base64 encoding
ดูรายละเอียดที่ docstring ของเทสต์นั้น)
"""
import pytest

from fas.opennds_proto import (ClientContext, FasProtocolError,
                               auth_token, build_auth_action_url,
                               build_kv_string, decrypt_fas_payload,
                               encrypt_fas_payload, parse_kv_string)

FASKEY = "a1b2c3d4e5f60718293a4b5c6d7e8f90"  # 32 ตัวอักษร เหมือนที่ install.sh สุ่มให้
PARAMS = dict(clientip="10.10.0.105", clientmac="AA:BB:CC:DD:EE:FF",
             gatewayname="Cafe-Guest", client_hid="9f8e7d6c5b4a3f2e1d0c",
             gatewayaddress="10.10.0.1", authdir="opennds_auth",
             originurl="http://example.com/", clientif="eth1")


def test_kv_string_roundtrip():
    s = build_kv_string(PARAMS)
    assert parse_kv_string(s)["clientmac"] == "AA:BB:CC:DD:EE:FF"


def test_parse_kv_string_tolerates_messy_spacing():
    d = parse_kv_string("a=1,  b=2 ,c=3,, d=")
    assert d == {"a": "1", "b": "2", "c": "3", "d": ""}


def test_encrypt_decrypt_roundtrip():
    fas_b64, iv = encrypt_fas_payload(PARAMS, FASKEY)
    ctx = decrypt_fas_payload(fas_b64, iv, FASKEY)
    assert ctx.clientmac == "AA:BB:CC:DD:EE:FF"
    assert ctx.hid == "9f8e7d6c5b4a3f2e1d0c", "client_hid ต้อง map เป็น ctx.hid"
    assert ctx.gatewayaddress == "10.10.0.1"
    assert ctx.is_complete()


# ค่าจับจาก openNDS 10.1.3 ตัวจริง (VM lab, 2026-08-28) -- ห้ามแก้เป็นค่าที่สร้างเอง ดู
# test_decrypt_real_capture_from_live_opennds; test_fas_flow.py ใช้ชุดเดียวกันตรวจ _valid_gateway
REAL_FAS_B64 = (
    "NHo0ZzNWR0lrYjNraVk3Q3V3cGpuc1JwVkhvb095MFphV3FWZms3MlVEVlkreUt0dXNWSjZwWmxt"
    "aENpcUdxdDBjWHZGZjJzZjNUcjBoZitaWDhJRC9Gc08rdnhwOXFtZFBsWWpISWFET1Rhb1RCU2Rk"
    "TUswVnp2SW9jakJrMlYzMktoaEJ5TjdNUW1WL0R5dUo4RGdubWNuTjhPUFV2SmpQYnFVdWI1UFBy"
    "RmF2Z1J1Ni9TdUQrMUZvU0JjS2xVblFrVEV2SHAvWTM5Wm5zblpwTFNXUDEwYmpLallWR1QzZTZ2"
    "SW42N2dBOWRTcFRVYUR4Vi9yaEtxMXZkV2N1YktDSURZZGJ2eHUySWtvbFJtQk0rdmFwOHd4UzBU"
    "bGtwb08zdFkwTDM5Zmo3RWttQnhsUkdiNGxsVEYzWjhBYnRCaXV6aVBHdVdZZ09FUEppZG9JMzZV"
    "T0JUVlNlcG9yTWRWN1ZEd2dFSU0xejBFc0REelBLUHpyTW14aWZIeWszK3pVK1JKNFd2YWF2Zi9Q"
    "a1NmcjFXd1VEOFB6U1JKUHdQdE5wdkMvbXdyZE9QSW1xYTJPYzRKNmNubVpTRFVxcVpldXpDaFNp"
    "Wk5kb1hHRGF6V2FCcmtncVpCL2haSURXZmkxZmk2OS9vSmlLanFlbWtRUkdpU0YzMWNIeUd4OFBx"
    "dWJXdzBqZ0NwYzh3NnhyeENIbnJ6eUFwS1VZY0lyMDdlcEZOemRLZ2cyZGorbHRVc0Mrblp5eXN0"
    "a2RXVzdK"
)
REAL_IV = "ca6c3800c66deebc"
REAL_FASKEY = "205c091caa29eb5393173febfc660e60"


def test_decrypt_real_capture_from_live_opennds():
    """
    Regression test — กันบั๊ก double-base64 encoding กลับมาแบบเงียบๆ อีก (2026-08-28)

    ทุกเคสอื่นในไฟล์นี้ round-trip กับ encrypt_fas_payload()/decrypt_fas_payload() ของเราเอง
    ทั้งคู่ ซึ่ง "หลอก" เราได้แนบเนียนมาก่อนแล้วจริงๆ: openNDS จริง (PHP reference ใน
    src/http_microhttpd.c) เรียก openssl_encrypt($string,$cipher,$key,0,$iv) โดย
    $options=0 (ไม่ใส่ OPENSSL_RAW_DATA) ซึ่งทำให้ผลลัพธ์ถูก base64 encode มาให้เองอยู่แล้ว
    ในตัว แล้วโค้ดยัง base64_encode() ครอบซ้ำอีกชั้น -- พารามิเตอร์ fas จริงคือ
    base64(base64(ciphertext)) ไม่ใช่ base64(ciphertext) ชั้นเดียว โค้ดเดิม decode
    ชั้นเดียวเลย "Invalid padding bytes." ทุกครั้งตอนเจอ openNDS จริง (ยืนยันบน VM lab
    บน Debian 13 + openNDS 10.1.3 ตัวจริง ไม่ใช่ mock) ทั้งที่เทสต์ 14 เคสอื่นผ่านหมด

    ค่าด้านล่างจับมาจาก openNDS จริงตัวเป็นๆ (VM lab, 2026-08-28) ห้ามแก้เป็นค่าที่สร้างเอง
    เด็ดขาด — ต้องเป็นค่าจริงจาก binary เท่านั้นถึงจะจับบั๊กสายนี้ได้
    """
    ctx = decrypt_fas_payload(REAL_FAS_B64, REAL_IV, REAL_FASKEY)

    assert ctx.clientip == "10.10.0.222"
    assert ctx.clientmac == "aa:bb:db:36:03:d1"
    assert ctx.gatewayaddress == "10.10.0.1:2050"
    assert ctx.authdir == "opennds_auth"
    assert ctx.clientif == "cafe-wifi-cli0"
    assert ctx.is_complete()


def test_iv_is_random_each_time():
    _, iv1 = encrypt_fas_payload(PARAMS, FASKEY)
    _, iv2 = encrypt_fas_payload(PARAMS, FASKEY)
    assert iv1 != iv2


def test_ciphertext_does_not_contain_plaintext():
    fas_b64, _ = encrypt_fas_payload(PARAMS, FASKEY)
    assert "AA:BB:CC:DD:EE:FF" not in fas_b64


def test_wrong_faskey_raises():
    fas_b64, iv = encrypt_fas_payload(PARAMS, FASKEY)
    with pytest.raises(FasProtocolError):
        decrypt_fas_payload(fas_b64, iv, "b" * 32)


def test_empty_payload_raises():
    with pytest.raises(FasProtocolError):
        decrypt_fas_payload("", "", FASKEY)


def test_malformed_base64_raises():
    _, iv = encrypt_fas_payload(PARAMS, FASKEY)
    with pytest.raises(FasProtocolError):
        decrypt_fas_payload("not-valid-base64!!!", iv, FASKEY)


def test_short_faskey_rejected_at_encrypt():
    with pytest.raises(FasProtocolError):
        encrypt_fas_payload(PARAMS, "too-short")


def test_wrong_iv_length_rejected():
    fas_b64, _ = encrypt_fas_payload(PARAMS, FASKEY)
    with pytest.raises(FasProtocolError):
        decrypt_fas_payload(fas_b64, "short", FASKEY)


def test_cbc_has_no_integrity_check_known_limitation():
    """
    บันทึกไว้เป็นเอกสาร (ไม่ใช่บั๊กของเรา): AES-256-CBC ตามที่ openNDS level 2 กำหนด
    ไม่มี MAC/authentication tag ผูกกับ ciphertext — การปลอม iv ทำให้ "บล็อกแรก" ของ
    plaintext เพี้ยน แต่บล็อกถัดไปยังถอดได้ตามปกติและ padding ท้ายสุดยังผ่าน จึง "ไม่ error"
    ทั้งที่ข้อมูลถูกดัดแปลง — เป็นข้อจำกัดของโปรโตคอล openNDS เอง ต้องเขียนอธิบายไว้ในเล่ม
    (บทวิเคราะห์ความปลอดภัย) ไม่ใช่ความผิดพลาดของโค้ดนี้
    """
    fas_b64, iv = encrypt_fas_payload(PARAMS, FASKEY)
    tampered_iv = ("0" * 16)
    ctx = decrypt_fas_payload(fas_b64, tampered_iv, FASKEY)  # ไม่ throw
    assert ctx.clientip != PARAMS["clientip"], "บล็อกแรก (clientip) ต้องเพี้ยนเมื่อ iv ผิด"
    assert ctx.gatewayaddress == PARAMS["gatewayaddress"], "บล็อกหลังยังถอดได้ปกติ (คุณสมบัติของ CBC)"


def test_auth_token_deterministic():
    assert auth_token("hid123", FASKEY) == auth_token("hid123", FASKEY)
    assert auth_token("hid123", FASKEY) != auth_token("hid456", FASKEY)
    assert len(auth_token("hid123", FASKEY)) == 64


def test_build_auth_action_url():
    ctx = ClientContext.from_dict(PARAMS)
    url = build_auth_action_url(ctx, FASKEY, redir="http://example.com/page")
    assert url.startswith("http://10.10.0.1/opennds_auth/?tok=")
    assert auth_token(ctx.hid, FASKEY) in url
    assert "redir=" in url


def test_build_auth_action_url_requires_complete_context():
    incomplete = ClientContext(clientmac="", hid="x", gatewayaddress="1.2.3.4", authdir="a")
    with pytest.raises(FasProtocolError):
        build_auth_action_url(incomplete, FASKEY)


def test_client_hid_alias_mapping():
    ctx = ClientContext.from_dict({"client_hid": "xyz", "clientmac": "AA:BB:CC:DD:EE:FF"})
    assert ctx.hid == "xyz"
