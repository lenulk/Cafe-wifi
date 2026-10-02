---
name: admin-access-from-customer-lan
description: Admin panel is reachable from the customer subnet (user chose option B 2026-10-02); openNDS users_to_router must list ADMIN_PORT or it rejects it
metadata:
  type: project
---

Real shop = router + Pi only. After the router's DHCP is turned off, staff phones/laptops get customer IPs (10.10.0.x), so the old T8 rule (block :8443 from CLIENT_NET) locked staff out entirely. On 2026-10-02 the user chose **option B: open the Admin panel to the customer subnet** (rejected staff-MAC allowlist and WireGuard), plus a "เข้าสู่ระบบสำหรับแอดมินและพนักงาน" button on every portal page linking to `https://cafe.wifi:${ADMIN_PORT}/login` (FAS reads `ADMIN_URL` from secrets.env).

**Two layers must both allow it:** our nftables input chain AND openNDS's own `ndsRTR` chain (users_to_router), which rejects every port except udp 53/67, tcp 22/443 + gateway/FAS ports. Setting `list users_to_router` in /etc/config/opennds REPLACES the defaults, so install.sh lists them all again plus ADMIN_PORT (N42). SSH stays blocked from customers by our nftables.

Compensating controls: per-person passwords, login rate limit per IP (5/10min) AND per username (10/10min, because customers can rotate IPs), HTTPS, audit of every failed login.

**How to apply:** never re-add a CLIENT_NET→ADMIN_PORT drop; when changing openNDS config keep the full users_to_router list. Verified on the Pi with a preauthenticated lab client (docs/hardware-test-log.md §3.9). Related: [[single-pi-single-cable-constraint]].
