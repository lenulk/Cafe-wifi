-- ============================================================================
--  Partition รายสัปดาห์สำหรับ conn_log และ dns_log (Phase 4 — เสริมประสิทธิภาพ)
-- ----------------------------------------------------------------------------
--  ทำไมต้อง partition: purge_old_data.py ใช้ `DELETE FROM conn_log WHERE ts < ?`
--  ซึ่งพอข้อมูลเป็นสิบล้านแถวจะช้าและกิน I/O มาก (ต้องสแกน+ล็อกทีละแถว)
--  ถ้าแบ่งเป็น partition รายสัปดาห์ การ "ลบข้อมูลเก่า" จะกลายเป็นแค่
--  `ALTER TABLE ... DROP PARTITION` ซึ่งเป็นการลบทั้งไฟล์ ไม่ใช่ลบทีละแถว เร็วกว่ามาก
--
--  หมายเหตุ: ไฟล์นี้ optional — ถ้าไม่รัน ระบบยังทำงานถูกต้องปกติ เพียงแต่
--  purge_old_data.py จะลบทีละแถวแทน (ก็ยังถูกต้อง แค่ช้ากว่าเมื่อข้อมูลเยอะมาก ๆ)
--  รันครั้งเดียวตอนติดตั้ง (หรือใส่ในขั้นตอน setup_database ของ install.sh เพิ่มเองได้):
--      mysql cafewifi < sql/003_partitions.sql
-- ============================================================================

DELIMITER $$

-- แปลงตารางที่มีอยู่แล้วให้เป็น partition ตาม "สัปดาห์ ISO" ของ ts
-- (ปลอดภัยต่อการรันซ้ำ: เช็คก่อนว่ายัง partition หรือยัง)
DROP PROCEDURE IF EXISTS cafewifi_init_partitions $$
DROP PROCEDURE IF EXISTS cafewifi_partition_table $$
-- แก้บั๊ก (ทดสอบกับ MariaDB 11.8 จริง 2026-10-02): เดิมเขียน
-- `PARTITION p_start VALUES LESS THAN (TO_DAYS(CURDATE()))` ตรง ๆ ใน ALTER TABLE ซึ่ง MariaDB ไม่รับ
-- ("Constant, random or timezone-dependent expressions in (sub)partitioning function are not allowed")
-- --enable-partitions จึงล้มทุกครั้งตั้งแต่แรก -- คำนวณขอบเป็นตัวเลขก่อนแล้วประกอบคำสั่งแบบเดียวกับ
-- cafewifi_ensure_future_partition ด้านล่าง
CREATE PROCEDURE cafewifi_partition_table(IN tbl VARCHAR(64))
BEGIN
    DECLARE already_partitioned INT DEFAULT 0;

    SELECT COUNT(*) INTO already_partitioned
    FROM information_schema.PARTITIONS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND PARTITION_NAME IS NOT NULL;

    IF already_partitioned = 0 THEN
        SET @sql = CONCAT(
            'ALTER TABLE ', tbl, ' PARTITION BY RANGE (TO_DAYS(ts)) (',
            'PARTITION p_start VALUES LESS THAN (', TO_DAYS(CURDATE()), '), ',
            'PARTITION p_future VALUES LESS THAN MAXVALUE)'
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END $$

CREATE PROCEDURE cafewifi_init_partitions()
BEGIN
    CALL cafewifi_partition_table('conn_log');
    CALL cafewifi_partition_table('dns_log');
END $$

-- แยก p_future ออกเป็น partition ของสัปดาห์ถัดไป + p_future ใหม่ (REORGANIZE)
-- เรียกทุกวันจาก event scheduler ด้านล่าง — ถ้าของสัปดาห์นั้นมีอยู่แล้วจะข้ามไปเงียบ ๆ
DROP PROCEDURE IF EXISTS cafewifi_ensure_future_partition $$
CREATE PROCEDURE cafewifi_ensure_future_partition(IN tbl VARCHAR(64))
BEGIN
    DECLARE next_boundary INT;
    DECLARE part_name VARCHAR(32);
    DECLARE existing INT DEFAULT 0;

    SET next_boundary = TO_DAYS(DATE_ADD(CURDATE(), INTERVAL 14 DAY));
    SET part_name = CONCAT('p', DATE_FORMAT(DATE_ADD(CURDATE(), INTERVAL 14 DAY), '%Y%m%d'));

    SELECT COUNT(*) INTO existing
    FROM information_schema.PARTITIONS
    WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl AND PARTITION_NAME = part_name;

    IF existing = 0 THEN
        SET @sql = CONCAT(
            'ALTER TABLE ', tbl, ' REORGANIZE PARTITION p_future INTO (',
            'PARTITION ', part_name, ' VALUES LESS THAN (', next_boundary, '), ',
            'PARTITION p_future VALUES LESS THAN MAXVALUE)'
        );
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END IF;
END $$

-- ทิ้ง partition ที่เก่ากว่า retention_days ทั้งก้อน (เร็วกว่า DELETE ทีละแถวมาก)
DROP PROCEDURE IF EXISTS cafewifi_drop_old_partitions $$
CREATE PROCEDURE cafewifi_drop_old_partitions(IN tbl VARCHAR(64), IN retention_days INT)
BEGIN
    DECLARE done INT DEFAULT 0;
    DECLARE pname VARCHAR(64);
    DECLARE cutoff_days INT;
    DECLARE cur CURSOR FOR
        SELECT PARTITION_NAME FROM information_schema.PARTITIONS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = tbl
          AND PARTITION_NAME NOT IN ('p_start', 'p_future')
          AND PARTITION_DESCRIPTION < cutoff_days
        ORDER BY PARTITION_ORDINAL_POSITION;
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = 1;

    IF retention_days < 90 THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'ปฏิเสธ: retention_days ต่ำกว่า 90 วันตามที่ พ.ร.บ.คอมพิวเตอร์ ม.26 กำหนด';
    END IF;

    SET cutoff_days = TO_DAYS(DATE_SUB(CURDATE(), INTERVAL retention_days DAY));

    OPEN cur;
    read_loop: LOOP
        FETCH cur INTO pname;
        IF done THEN
            LEAVE read_loop;
        END IF;
        SET @sql = CONCAT('ALTER TABLE ', tbl, ' DROP PARTITION ', pname);
        PREPARE stmt FROM @sql;
        EXECUTE stmt;
        DEALLOCATE PREPARE stmt;
    END LOOP;
    CLOSE cur;
END $$

-- เรียกทั้งหมดในรอบเดียว ให้ event scheduler เรียกฟังก์ชันนี้ฟังก์ชันเดียวพอ
DROP PROCEDURE IF EXISTS cafewifi_partition_maintenance $$
CREATE PROCEDURE cafewifi_partition_maintenance(IN retention_days INT)
BEGIN
    CALL cafewifi_ensure_future_partition('conn_log');
    CALL cafewifi_ensure_future_partition('dns_log');
    CALL cafewifi_drop_old_partitions('conn_log', retention_days);
    CALL cafewifi_drop_old_partitions('dns_log', retention_days);
END $$

DELIMITER ;

-- รันครั้งแรกตอนติดตั้ง
CALL cafewifi_init_partitions();
CALL cafewifi_ensure_future_partition('conn_log');
CALL cafewifi_ensure_future_partition('dns_log');

-- ตั้ง event scheduler ให้รันทุกคืน (ต้องเปิด event_scheduler=ON ในระดับ server ด้วย
-- -- install.sh ยังไม่ได้เปิดให้อัตโนมัติ ต้องเพิ่มเอง: SET GLOBAL event_scheduler = ON;
-- หรือใส่ event_scheduler=ON ใน my.cnf แล้ว restart mariadb)
DROP EVENT IF EXISTS cafewifi_daily_partition_maintenance;
CREATE EVENT cafewifi_daily_partition_maintenance
    ON SCHEDULE EVERY 1 DAY STARTS (CURRENT_DATE + INTERVAL 1 DAY + INTERVAL 3 HOUR)
    DO CALL cafewifi_partition_maintenance(180);  -- ปรับตัวเลขให้ตรงกับ LOG_RETENTION_DAYS ใน secrets.env
