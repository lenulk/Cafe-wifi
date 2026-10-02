---
name: single-pi-single-cable-constraint
description: "Hard design constraint — one Raspberry Pi, one LAN cable into the café Wi-Fi router, plug-and-play; no separate management network"
metadata:
  node_type: memory
  pinned: false
  originSessionId: 4ec482b1-787a-40f3-9cbf-67b87d7eee75
  modified: 2026-09-29T16:27:16.590Z
---

The user requires that the Cafe-wifi product is a single Raspberry Pi that works by plugging one LAN cable from the café's Wi-Fi router into it — nothing else. Because of this, the management path (SSH, Admin Panel) cannot be moved to a separate interface, VLAN, or L2 segment; customers and the admin always share the same L2 as the Pi. The user rejected "separate the management interface from the customer L2" as a fix for review finding R2-03 (2026-09-29).

When proposing security fixes, do not suggest extra hardware, a second NIC/interface, or VLAN separation. Work within one shared L2: host firewall rules (e.g. dropping IPv6 input), strong authentication (the user plans to switch SSH to key-only with `PasswordAuthentication no` later), rate limiting, or cryptographic overlays such as WireGuard that run over the same cable. Note that IP/MAC allowlists on a shared L2 can be spoofed by customers, so present them as hurdles, not real separation.

**2026-10-02 ทดสอบสายเดียวจริง (wlan0 ปิด):** เจอ N40 — Pi ไม่มี DNS ของตัวเองเลย (เคยได้จาก DHCP ของ
wlan0) → chrony หาเซิร์ฟเวอร์เวลาไม่เจอหลังรีบูต · แก้ด้วย `configure_host_dns()`/`--host-dns` ใน install.sh
แล้ว รีบูตแบบสายเดียวผ่านครบ · **โน้ตบุ๊กมีสาย LAN อยู่วง 172.20.18.0/24 ด้วย** (Ethernet 4 = 172.20.18.53)
SSH เข้า Pi ทาง eth0 ได้ที่ `ras@172.20.18.128` — ใช้ทดสอบโหมดสายเดียวได้โดยไม่ต้องพึ่ง wlan0
