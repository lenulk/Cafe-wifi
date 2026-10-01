-- ============================================================================
--  008_pending_sessions_and_log_columns.sql — ยกคอลัมน์/ตารางของรีวิวรอบ 2 ขึ้นเครื่องที่ติดตั้งไว้แล้ว
--  MariaDB 10.6+ / 11.x
-- ============================================================================
-- งานรอบ R2 (pending session, FAS nonce, voucher reveal, dns answer, การลบ archive ตามอายุ) แก้
-- 001_schema.sql ตรง ๆ แต่ไฟล์นั้นใช้ CREATE TABLE IF NOT EXISTS -- เครื่องที่เคยติดตั้งแล้ว (Pi จริง)
-- จะไม่ได้คอลัมน์ใหม่เลย แล้ว FAS พังตอน login (ไม่มี portal_session.state) และ cafe-logger เขียน
-- dns_log ไม่ได้ทุก batch (ไม่มี event_kind) = หลักฐาน ม.26 หาย -- ไฟล์นี้ทำให้สองทางเท่ากัน
--
-- รันซ้ำได้เสมอ: ทุกคำสั่งใช้ IF NOT EXISTS / MODIFY (MariaDB extension) และ UPDATE แตะเฉพาะแถวเก่า
-- เครื่องใหม่ที่สร้างจาก 001 ฉบับใหม่แล้ว ไฟล์นี้ไม่เปลี่ยนอะไร

-- ---------------------------------------------------------------- portal_session
ALTER TABLE portal_session ADD COLUMN IF NOT EXISTS authenticated_at DATETIME NULL AFTER started_at;
ALTER TABLE portal_session ADD COLUMN IF NOT EXISTS pending_until DATETIME NULL AFTER authenticated_at;
-- ระวัง: ห้ามเพิ่มด้วย DEFAULT 'pending' ตรง ๆ -- แถวเก่าทั้งหมดจะกลายเป็น pending ที่ pending_until
-- เป็น NULL แล้ว tools/reconcile_pending.py จะพัง (เทียบ None <= datetime) หรือสั่ง deauth ลูกค้า
-- ที่ออนไลน์อยู่ทั้งร้าน -- เพิ่มเป็น 'closed' ก่อน (มีผลเฉพาะตอนสร้างคอลัมน์ครั้งแรก) แล้วค่อยเปลี่ยน
-- default ให้ตรงกับ 001 ด้านล่าง
ALTER TABLE portal_session ADD COLUMN IF NOT EXISTS
  state ENUM('pending','authenticated','closed') NOT NULL DEFAULT 'closed' AFTER pending_until;
ALTER TABLE portal_session ALTER COLUMN state SET DEFAULT 'pending';
CREATE INDEX IF NOT EXISTS idx_pending ON portal_session (state, pending_until);

-- แถวเก่าที่ยังเปิดอยู่ = ลูกค้าที่ออนไลน์อยู่จริงตอนอัปเกรด (โค้ดเดิมบันทึกหลัง login ผ่านทันที)
-- โค้ดใหม่ปิด session ทุกทางพร้อม ended_at เสมอ แถว closed ที่ ended_at ว่างจึงมีได้แค่แถวเก่า
UPDATE portal_session SET state='authenticated'
 WHERE state='closed' AND ended_at IS NULL;

-- common/log_mapping.py และ retention_hold_until() จับคู่ log กับลูกค้าด้วย authenticated_at --
-- ถ้าแถวเก่าว่าง log ย้อนหลังทั้งหมดก่อนอัปเกรดจะโยงหาตัวบุคคลไม่ได้ (หลักฐานเดิมใช้ไม่ได้)
-- ใช้ started_at แทนตามความหมายของโค้ดเดิม -- ยกเว้นสองสาเหตุที่โค้ดใหม่ใช้กับ session ที่ไม่เคย
-- ได้รับสิทธิ์จริง ซึ่งต้องคง NULL ไว้ (กันรันซ้ำแล้วไปโยง log ให้ session ที่ไม่เคยออนไลน์)
UPDATE portal_session SET authenticated_at=started_at
 WHERE authenticated_at IS NULL AND state IN ('authenticated','closed')
   AND (terminate_cause IS NULL OR terminate_cause NOT IN ('auth_timeout','voucher_invalid'));

-- ---------------------------------------------------------------- ตารางใหม่ (เหมือน 001)
CREATE TABLE IF NOT EXISTS pending_mac_claim (
  mac CHAR(17) PRIMARY KEY,
  portal_session_id BIGINT NULL UNIQUE,
  CONSTRAINT fk_pending_session FOREIGN KEY (portal_session_id) REFERENCES portal_session(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS fas_context (
  nonce_hash CHAR(64) PRIMARY KEY,
  payload TEXT NOT NULL,
  request_ip VARCHAR(45) NOT NULL,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL,
  INDEX idx_expiry (expires_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS voucher_reveal (
  token_hash CHAR(64) PRIMARY KEY,
  staff_id INT NOT NULL,
  payload BLOB NOT NULL,
  expires_at DATETIME NOT NULL,
  consumed_at DATETIME NULL,
  INDEX idx_expiry (expires_at)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------- log
-- conn_log.mac ว่างได้ (หา MAC ไม่ได้ก็ยังต้องเก็บแถว ไม่ใช่ทิ้งหลักฐาน)
ALTER TABLE conn_log MODIFY COLUMN mac CHAR(17) NULL;
-- dns_log: แถว answer ไม่มี client_ip (dnsmasq log บรรทัด reply ไม่บอกผู้ถาม)
ALTER TABLE dns_log MODIFY COLUMN client_ip VARCHAR(45) NULL;
ALTER TABLE dns_log ADD COLUMN IF NOT EXISTS
  event_kind ENUM('query','answer') NOT NULL DEFAULT 'query' AFTER answer;

-- log_manifest: การลบ archive ตามอายุแบบสองขั้น (logger/integrity.py prune_archives)
ALTER TABLE log_manifest ADD COLUMN IF NOT EXISTS
  deletion_state ENUM('active','pending','deleted') NOT NULL DEFAULT 'active' AFTER sealed_at;
ALTER TABLE log_manifest ADD COLUMN IF NOT EXISTS deleted_at DATETIME NULL AFTER deletion_state;
