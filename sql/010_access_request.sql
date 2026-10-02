-- ============================================================================
--  010_access_request.sql — ลูกค้าขอใช้งานเองบน portal แล้วพนักงานอนุมัติ
--  MariaDB 10.6+ / 11.x
-- ============================================================================
-- แทนการออกรหัส CAFE-XXXXX + รหัสผ่านบนสลิป (เลิกใช้ 2026-10-02 ตามการตัดสินใจของเจ้าของโครงงาน):
--   1. ลูกค้ากรอกเลขบัตร 13 หลัก + ยินยอม บนหน้า portal -> ได้รหัสคำขอ 4 ตัว (code)
--   2. พนักงานเปิดคำขอใน Admin ตรวจบัตรจริง พิมพ์ 4 ตัวท้ายจากบัตรเพื่อเทียบ แล้วอนุมัติ
--   3. cafe-reconcile (root) สั่ง `ndsctl auth <mac>` เปิดสิทธิ์ให้เครื่องที่ลูกค้าใช้อยู่เลย
--
-- ความเสี่ยงที่เจ้าของโครงงานยอมรับ: หน้า portal เป็น HTTP เลขบัตรเต็มวิ่งผ่าน Wi-Fi แบบอ่านออก
-- (ดู memory/customer-self-registration-decision.md) -- ฝั่งเก็บข้อมูลทำเท่าที่ทำได้:
--   * เก็บเลขบัตรแบบเดียวกับตาราง customer (hash + AES-GCM + masked) ไม่มี plaintext
--   * ล้าง natid_hash/natid_enc ทันทีที่อนุมัติ/ปฏิเสธ/หมดเวลา (ข้อมูลจริงย้ายไปอยู่ใน customer แล้ว)
--     เหลือแค่ natid_masked ไว้เป็นร่องรอยว่าคำขอนี้ของใคร
--
-- รันซ้ำได้เสมอ
CREATE TABLE IF NOT EXISTS access_request (
  id                BIGINT AUTO_INCREMENT PRIMARY KEY,
  code              CHAR(4)        NOT NULL,          -- รหัสที่ลูกค้าโชว์พนักงาน (ไม่ซ้ำในคำขอที่รออยู่)
  mac               CHAR(17)       NOT NULL,          -- ยืนยันจาก ARP แล้ว ไม่ใช่ค่าจากฟอร์ม
  ip                VARCHAR(45)    NOT NULL,
  natid_hash        CHAR(64)       NULL,              -- NULL = ล้างแล้วหลังตัดสินใจ
  natid_enc         VARBINARY(255) NULL,
  natid_masked      CHAR(20)       NOT NULL,
  consent_at        DATETIME       NOT NULL,
  status            ENUM('pending','approved','rejected','expired') NOT NULL DEFAULT 'pending',
  created_at        DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at        DATETIME       NOT NULL,
  decided_at        DATETIME       NULL,
  decided_by        INT            NULL,
  decision_note     VARCHAR(255)   NULL,
  voucher_id        BIGINT         NULL,
  portal_session_id BIGINT         NULL,
  auth_sent_at      DATETIME       NULL,              -- cafe-reconcile สั่ง ndsctl auth แล้ว
  INDEX idx_status (status, expires_at),
  INDEX idx_mac (mac, created_at)
) ENGINE=InnoDB;
