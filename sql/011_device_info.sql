-- ============================================================================
--  011_device_info.sql — ชื่อเครื่อง (hostname) + ระบบปฏิบัติการของเครื่องลูกค้า
--  MariaDB 10.6+ / 11.x
-- ============================================================================
-- เก็บตอนลูกค้ากดขอใช้งานบน portal (ดู app/common/device_info.py) แล้วคัดลอกไปที่ portal_session
-- ตอนอนุมัติ -- หน้า /logs จึงแสดงชื่อเครื่อง/OS ของแถว log ได้ผ่าน JOIN เดิม (common/log_mapping.py)
-- โดยไม่ต้องเพิ่มคอลัมน์ในตาราง log ที่โตเร็ว
--
-- เครื่องลูกค้าบอกค่าเหล่านี้เอง ปลอมได้ -- ใช้ประกอบ ไม่ใช่หลักฐานยืนยันตัวตน
-- hostname อาจมีชื่อจริง = ข้อมูลส่วนบุคคล: ล้างพร้อมเลขบัตรใน anonymize_customer()
--
-- รันซ้ำได้เสมอ
ALTER TABLE access_request ADD COLUMN IF NOT EXISTS hostname   VARCHAR(63)  NULL AFTER ip;
ALTER TABLE access_request ADD COLUMN IF NOT EXISTS os_label   VARCHAR(64)  NULL AFTER hostname;
ALTER TABLE access_request ADD COLUMN IF NOT EXISTS user_agent VARCHAR(255) NULL AFTER os_label;

ALTER TABLE portal_session ADD COLUMN IF NOT EXISTS hostname   VARCHAR(63)  NULL AFTER ip;
ALTER TABLE portal_session ADD COLUMN IF NOT EXISTS os_label   VARCHAR(64)  NULL AFTER hostname;
