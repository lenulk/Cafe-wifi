---
name: lenilk-fork
description: "Collaborator fork github.com/Lenilk/Cafe-wifi (not our origin lenulk/Cafe-wifi) — helper's ChatGPT+Claude fixes land there first"
metadata:
  node_type: memory
  type: reference
  originSessionId: 668bce67-4ec1-453a-add8-59fc42ac7deb
  modified: 2026-10-02T03:45:58.964Z
---

- Our origin: https://github.com/lenulk/Cafe-wifi
- Collaborator "Lenilk" fork: https://github.com/Lenilk/Cafe-wifi (note spelling: Len**i**lk vs len**u**lk)
- The helper works with ChatGPT + Claude; commits authored as "test".
- As of 2026-10-02 the fork was 33 commits ahead of our master a2d2510 (fast-forwardable, no divergence):
  round-2 code review (R2-01..R2-10, R2-L03/L05) fixes in FAS/logger/admin/nftables/export/reconcile,
  Docker Compose test env, review/ reports, sql/007, new memory single-pi-single-cable-constraint.
- Review 2026-10-02 (helper never tested on real hardware) found 2 merge blockers:
  1. FAS `_valid_gateway()` compares `ctx.gatewayaddress == GATEWAY_IP` ("10.10.0.1") but real
     openNDS 10.1.3 sends "10.10.0.1:2050" (port included; see real payload in
     tests/test_opennds_proto.py) → every real customer login rejected. Helper's tests used a fake "10.10.0.1".
  2. New columns added by editing sql/001_schema.sql (CREATE TABLE IF NOT EXISTS) with no migration →
     an already-installed Pi never gets portal_session.state/pending_until/authenticated_at,
     dns_log.event_kind, nullable conn_log.mac / dns_log.client_ip, log_manifest.deletion_state → FAS 500s and
     dns_log inserts fail (evidence loss). A migration must also backfill old rows' state
     (DEFAULT 'pending' + NULL pending_until would make reconcile_pending crash/deauth everyone).
  Both fixed 2026-10-02 on local branch `fix/lenilk-review` (on top of `lenilk`): c1faaf3 (host/port
  split + NDS_PORT check, real-payload tests; shared REAL_FAS_B64 constants in test_opennds_proto.py) and
  9a8655d (sql/008_pending_sessions_and_log_columns.sql, called by install.sh after 007). 362/362 on Linux.
  008 verified 2026-10-02 on real MariaDB 11.8.8 in Kali WSL (installed for this; `wsl -u root`,
  `service mariadb start`): old master schema + data → new 001/005/006/007/008 → re-run = 33/34 checks pass
  (legacy open session stays authenticated, legacy logs still map to the customer, re-run is a no-op);
  reconcile_pending + enforce ran against it with a fake ndsctl: pending promoted, nobody deauthed.
  The 1 failure is a pre-existing master bug: sql/003_partitions.sql (opt-in) errors on MariaDB 11.8
  ("Constant ... expressions in partitioning function are not allowed", TO_DAYS(CURDATE()) bound) — never worked.
  Also verify on Pi: `ndsctl json` really has `session_start` (reconcile depends on it, else every login
  times out after 180 s and is deauthed); reconcile timer spawns python every 5 s (CPU on Pi 4B).
- **MERGED 2026-10-02** after full Pi testing: master fast-forwarded to `fix/lenilk-review` (8b7c691 =
  Lenilk's 33 commits + 11 of ours) and pushed to origin lenulk/Cafe-wifi with the user's go-ahead.
  Future Lenilk work: fetch by URL again, review, and test on the Pi before merging (same process).
- Pi test 2026-10-02 (lab, Aruba): backup at Pi `/root/pre-r2-20261002/` (DB dump + /etc + /opt), old source
  at `~/cafe-wifi.bak-20261002`. install.sh re-run OK, 008 migrated the real DB (20 old sessions → closed,
  authenticated_at filled). Found pre-existing bug: install.sh re-run never restarted cafe-fas/admin/logger
  (`enable --now` only starts stopped units) → Admin 500 "'csrf_token' is undefined" (old code + new
  templates). Fixed in commit on fix/lenilk-review (restart those 3, not opennds) and restarted on the Pi.
  Pi SSH now uses laptop key ~/.ssh/id_ed25519 (BatchMode works) + temporary `/etc/sudoers.d/90-ras-lab`
  NOPASSWD — remind user to remove it after testing. Pi clock was 16 Sep (dead home route blocked NTP)
  until default route pointed at 172.20.18.1.
- Real customer login on Pi 2026-10-02 09:20 (phone via AP-515, voucher issued in Admin with CSRF): PASSED.
  Real `ndsctl json` (openNDS 10.1.3) DOES have `session_start` (epoch string, "0" when preauth), `ip`,
  `state":"Authenticated"`, keys = lowercase MAC, gatewayaddress "10.10.0.1:2050" → reconcile promoted
  pending→authenticated in ~17 s, authenticated_at = openNDS session_start, phone kept internet.
  `ndsctl json` returns exit 4 when called concurrently (busy) / while openNDS restarts → fixed reconcile to
  skip the round instead of timing out pending (commit 20c6a65, deployed to Pi /opt + ~/cafe-wifi).
- Same day: revoke in Admin → enforce deauth failed 3× with exit 4. Cause: openNDS serves one ndsctl at a
  time ("ndsctl thread is busy, please try later." exit 4); with reconcile's `ndsctl json` every 5 s ~11% of
  calls hit busy (regression from Lenilk's timer). Fixed 998b3fe: run_ndsctl() retries exit 4 (20×0.25 s),
  used by deauth_mac/authenticated_macs/reconcile. After fix: revoke → deauth OK, session closed
  voucher_revoked with bytes, used_mb charged. Logs map to customer only after authenticated_at (pre-login
  portal traffic correctly unmapped). Reboot test: everything came back (services, eth0 172.20.18.128,
  sysctls, nft rules). Pre-existing: no RTC + chrony → every boot starts at 2026-09-16 14:20
  (/var/lib/systemd/timesync/clock mtime) until NTP syncs; 8 conn_log rows today got the wrong date
  (spun off as separate task).
- Later 2026-10-02: fixed sql/003_partitions (e137a73, dynamic SQL; tested MariaDB 11.8) and added
  fake-hwclock to install.sh (83efc8c; N23 chrony-wait/time-sync drop-ins already existed). Re-ran install.sh
  on Pi: services got new PIDs (restart fix proven). Pi-verified: maintenance (purge/backup/integrity; the
  2026-09-16 cafe-fas-access hash_mismatch is the known N26 evidence), logger restart loses no DNS
  (16/16), export_evidence --mac maps rows to the right voucher by time + manifest sha256, --natid rejects bad
  checksum, block customer → enforce cuts (customer_blocked), issue to blocked customer → 403, login while
  blocked → login_fail. OPEN (pre-existing, also 2026-09-20 every 5–10 min): conntrack "ENOBUFS" log_gap
  even at ~100 events/min; bypass ping-sweep ruled out as cause; root cause unknown.
  Then (same day) emulated clients on the Pi: tools/lab_client.sh (netns + macvlan bridge on eth0, busybox
  udhcpc, curl through portal) + tools/lab_issue_voucher.py (real /issue via Flask test client, staff_id=1);
  test natid 1101700000010 (customer id 3 on Pi). Verified quota→used_up, device limit 403, auth_timeout at
  180 s, expiry, DoT 853 drop counter, IPv6 drop, all admin pages 200. Found + fixed 6ef63ad: `ndsctl json`
  costs ~0.27 s + 1.1 s per client (30 clients ≈ 34 s > 10 s timeout → everyone stuck pending); reconcile
  now queries `ndsctl json <mac>` only for pending MACs (~1.4 s), none when idle; enforce json timeout 180 s.
  Results written to docs/hardware-test-log.md §3.5 (8b7c691). Branch now 11 commits on top of lenilk;
  368 tests pass. Still NOT merged/pushed.
  Note: user confused Dashboard "ยกเลิก" (revoke voucher) with Customers "ระงับ" (block) — name the page.
- Running tests: on Windows, 7 admin issue-result tests fail on master too (Thai strftime / locale) and
  4–5 logger rotation/restart tests fail only on Windows (file locking). Use Kali WSL instead:
  venv at /tmp/cafevenv (`pip install -r app/requirements.txt pytest`) → fork passed 356/356 there.
- Compare with: `git fetch https://github.com/Lenilk/Cafe-wifi master` then `git log HEAD..FETCH_HEAD`.
