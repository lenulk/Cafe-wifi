---
name: customer-self-registration-decision
description: "2026-10-02 user decision — customers self-register on the portal with full 13-digit ID, staff approves in Admin, device is authorized directly; voucher username/password login is retired"
metadata:
  node_type: memory
  type: project
  originSessionId: 668bce67-4ec1-453a-add8-59fc42ac7deb
  modified: 2026-10-02T04:55:11.386Z
---

User decisions 2026-10-02 (replacing the CAFE-XXXXX code + password slip flow):

1. Customer connects → portal form: full 13-digit national ID + PDPA consent → gets a short request code
   shown on screen.
2. Staff opens "pending requests" in Admin (HTTPS), checks the physical ID card, approves → system
   authorizes the device the customer is already using (no username/password typed by anyone).
3. Username/password login (incl. the just-built "last 4 digits + random password" variant) is retired —
   approval-only. The last-4 work was never committed.
4. A second device for a customer with a still-valid entitlement is approved into the existing voucher
   (shared hours/device limit).

**Accepted risk (user chose it explicitly after being warned):** the portal is plain HTTP on :8080, so
the full national ID crosses the café Wi-Fi unencrypted (plan risk R3 "critical"). HTTPS on the portal
isn't practical (no real domain → cert warnings, captive portal breaks). Must be written into the thesis
as an accepted risk; recommend OWE/WPA2 on the SSID. Mitigations chosen by Claude: masked input,
never logged, encrypted/hashed at rest, request PII purged after decision/expiry, rate limits.

Design choice by Claude: staff never sees the full ID — request list shows natid_masked and staff
types the last 4 digits from the physical card; approval only succeeds if they match (verifies card ↔
request and blocks approving the wrong person).

Implementation (2026-10-02, branch `feature/self-registration` on top of `feature/staff-accounts`, local
only): sql/010_access_request.sql, app/common/access.py (shared reserve_pending_session), FAS POST /login =
registration + GET /request waiting page (meta refresh, identifies device by IP+ARP, no token), Admin
/requests (+ nav badge) with approve/reject, tools/reconcile_pending.py authorize_approved() runs
`ndsctl auth <mac> <minutes left>` (root) + expire_requests(). Removed /issue, slips, QR (qrcode dep),
one-time reveal crypto. `ndsctl auth mac minutes` verified on openNDS 10.1.3: works, session_end exact.
Pi e2e (tools/lab_e2e_register.sh): wrong last4 blocked; approve → online in 5 s. 368 tests pass.

**Why:** user wants a smoother counter flow than reading out codes/passwords.
**How to apply:** don't re-propose password slips; keep the accepted-risk note in docs; related
[[lenilk-fork]], [[single-pi-single-cable-constraint]].
