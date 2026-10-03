-- ============================================================================
--  013_rate_attempt.sql — ตัวนับความพยายามที่ล้มเหลว (เดารหัส / กรอกเลขบัตรผิดซ้ำ)
--  MariaDB 10.6+ / 11.x
-- ============================================================================
-- เดิมนับในหน่วยความจำของ service -- รีสตาร์ทแล้วกลับเป็นศูนย์ (ดู app/common/ratelimit.py)
-- bucket เช่น "login:10.10.0.177", "login-user:admin", "register:AA:BB:..." -- ไม่มีรหัสผ่านหรือเลขบัตร
-- แถวเก่าถูกลบเองทุกครั้งที่ bucket เดิมถูกนับ (เกินช่วงเวลานับ) และ purge_old_data ลบที่เกิน 1 วัน
--
-- รันซ้ำได้เสมอ
CREATE TABLE IF NOT EXISTS rate_attempt (
  id     BIGINT AUTO_INCREMENT PRIMARY KEY,
  bucket VARCHAR(128) NOT NULL,
  ts     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_bucket_ts (bucket, ts),
  INDEX idx_ts (ts)
) ENGINE=InnoDB;
