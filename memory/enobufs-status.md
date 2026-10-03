---
name: enobufs-status
description: State of the conntrack ENOBUFS (log_gap) investigation as of 2026-10-03 — what was fixed, what was verified, what is still unexplained
metadata:
  type: project
---

conn_log can lose events when `conntrack -E` hits ENOBUFS. History:
- **N31/N39:** reader threads and a bigger pipe.
- **N41:** the bypass detector's ping sweep was notracked.
- **N43 (2026-10-03):**
  - nftables `iif/oif lo notrack`: MariaDB loopback connections were 122/281 tracked entries.
  - `conntrack -E -s <client net>`: a BPF filter in the kernel drops the Pi's own traffic.

**Verified on the Pi:**
- `strace` shows `SO_RCVBUFFORCE 33554432` succeeds, and the kernel doubles it to 64 MB.
- `/proc/net/netlink` Rmem stays 0, so the buffer is not filling.
- Completeness test: 323/323.

**Still open:** ENOBUFS still occurred 3× in ~75 min after N43.
- Two coincided with install.sh re-runs: openNDS restarts and flushes conntrack, and the collector shows ~182 drops in its first minute.
- One, at 14:05, is unexplained.
- Unconfirmed hypothesis: the kernel's atomic allocation fails during event bursts.

**How to apply:**
- Don't claim ENOBUFS is fixed. Count `log_gap` rows with ENOBUFS over a day of normal operation, with no reinstalls, before concluding.
- Re-installs cause restart-time drops by design, and the `log_gap` audit row records them.

Related: [[pi-dhcp-and-portal-milestone]]
