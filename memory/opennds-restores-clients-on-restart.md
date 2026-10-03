---
name: opennds-restores-clients-on-restart
description: openNDS 10.1.3 re-authenticates every client it remembers when it restarts, ignoring our DB; cafe-enforce must sweep openNDS→DB orphans (N44)
metadata:
  type: project
---

openNDS keeps `/tmp/ndslog/authlog.log` (base64 MAC + session_end). After any restart (install.sh re-run, reboot, crash) it runs `ndsctl auth` for each of those clients. binauthlog shows `shutdown_deauth` immediately followed by `ndsctl_auth`.

It does not consult our database. A device whose voucher was revoked or expired can therefore come back online for free, with unattributed logs, which is a Section 26 problem. Found 2026-10-03: a revoked ASUS laptop was online with session_end the next day.

**Fix (N44):**
- `tools/enforce_voucher_expiry.find_orphan_macs()` deauths any openNDS Authenticated MAC that has no DB session in state authenticated (open) or pending (not yet expired), and audits it as `orphan_deauth`.
- Drop-in `opennds.service.d/cafe-wifi-orphan-sweep.conf` uses systemd-run to start cafe-enforce 45 s after openNDS starts.
- Measured on the Pi: orphans were cut about 75 s after the restart.

**How to apply:**
- Every reachability check must go both ways (DB→openNDS and openNDS→DB).
- Never treat "openNDS says Authenticated" as entitlement.
- Pending sessions must not be cut: openNDS opens a device before reconcile confirms it.

Related: [[admin-access-from-customer-lan]]
