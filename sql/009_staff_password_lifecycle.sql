-- ============================================================================
--  009_staff_password_lifecycle.sql — บัญชีพนักงานหลายคน (หน้า /staff)
--  MariaDB 10.6+ / 11.x
-- ============================================================================
-- เดิมมีแค่บัญชี admin ตัวแรกจาก /setup ร้านจึงต้องใช้บัญชีร่วมกันทุกคน audit_log บอกไม่ได้ว่า
-- "ใคร" เปิดดูเลขบัตร (ขัด PDPA) -- หน้า /staff ให้ admin สร้างบัญชีรายคนด้วยรหัสชั่วคราว
--
-- must_change_password: รหัสชั่วคราวที่ admin เห็นตอนสร้าง/รีเซ็ต ต้องถูกเปลี่ยนตอน login ครั้งแรก
--   (admin จึงไม่รู้รหัสจริงของพนักงานคนไหนเลย)
-- password_changed_at: เปลี่ยน/รีเซ็ตรหัสแล้ว session เดิมทุกเครื่องหลุดทันที (gate() เทียบกับค่าที่
--   เก็บใน session ตอน login) -- R2-L03 ตรวจแค่ role/is_active ไม่ครอบคลุมกรณีรหัสรั่ว
--
-- 001_schema.sql apply ไปแล้วแก้ตรง ๆ ไม่ได้ (§5) -- เพิ่มผ่าน migration · รันซ้ำได้เสมอ
ALTER TABLE staff ADD COLUMN IF NOT EXISTS
  must_change_password BOOLEAN NOT NULL DEFAULT FALSE AFTER is_active;
ALTER TABLE staff ADD COLUMN IF NOT EXISTS
  password_changed_at DATETIME NULL AFTER must_change_password;
