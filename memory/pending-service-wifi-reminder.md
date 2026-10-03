---
name: pending-service-wifi-reminder
description: "REMIND THE USER — deferred 2026-10-03: \"service Wi-Fi\" for technicians on the Pi's wlan0 + SSH hardening before shop handover"
metadata:
  node_type: memory
  type: project
  originSessionId: 668bce67-4ec1-453a-add8-59fc42ac7deb
  modified: 2026-10-03T06:20:55.658Z
---

The user asked to be reminded later (2026-10-03, "พับไว้ก่อน เตือนผมตอนหลังด้วย"). Bring it up at a natural point: before any production install or shop handover, or when the user asks what is left.

Agreed direction: keep the Pi's wlan0 enabled as a technician/installer access path (normal operation runs on eth0 only, verified 2026-10-02). Proposed but not built:
- `install.sh --service-wifi "SSID:PASS"`: the Pi auto-joins only the technician hotspot (default name `cafe-service`).
- **Refuse** if the SSID equals the shop's customer SSID: wlan0 would get a 10.10.0.x lease from the Pi itself, overlap `cafe-wifi-cli0` and break routing.
- Restrict SSH to the eth0 uplink subnet + the hotspot subnet. Today nftables accepts SSH from any non-customer source.
- Show service Wi-Fi connected/not on the status page.

**Must happen before handover regardless:**
- The user changes the `ras` password from `1234` themselves, or switches SSH to key-only. Claude must not set passwords for the user; give them the commands.
- Delete the lab "NetworkLab" Wi-Fi profile.

Related: [[single-pi-single-cable-constraint]], [[admin-access-from-customer-lan]].
