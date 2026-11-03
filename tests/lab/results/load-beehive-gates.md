# Load gates: plan 12c ruling 7 applied to run 7

Written by hand, as the lead's application of plan 12c ruling 7 to the two harness notes. The
harness notes are never edited; every figure below names the note and cell it comes from.
`load-beehive.md` is the real-disk note and `load-beehive-ram.md` the RAM one.

- **Commit both runs were built from:** 15e77241 (both notes record it as `15e77241...+dirty`: the
  worktree held the two uncommitted notes themselves).
- **Host:** beehive (SER8), AMD Ryzen 7 8745HS, 16 cores, 30818 MB RAM, kernel 7.0.0-38-generic.
- **Fleet:** 10000 devices, 50 machine principals, 450 people (both notes).
- **Real-disk run** (`load-beehive.md`): session etcd, accounting spool and run directory on a
  CT1000P3PSSD8 (DRAM-less QLC), ext4. TestLoad FAIL: cells a, b, c, e2 and f FAIL, d and e PASS.
- **RAM run** (`load-beehive-ram.md`): the session etcd's data and the accounting spool under
  /dev/shm, the directory etcds on disk. Every cell PASSes. This is port49's own ceiling, not a
  deployable shape.

## Ryan's ruling, 2026-11-03

No datacenter disk is available. Task 7 closes on the real-disk FAIL plus the labelled RAM
ceiling, and every sized default below is **provisional on the beta GCP pass** (n2-standard-16,
pd-ssd). The disk run misses design section 5's targets on this drive (gate 8); under ruling 7 that
stops the plan, and Ryan's ruling is how it closes.

## Task 6 and 6b benchmarks (fleet size, SER8, one run each)

From the ledger lines for Task 6 and Task 6b in `progress.md` and the two reports; a number that is
not there is not stated.

- **Task 6** (64705949, before the fix): ClassAges 22.7 s, Compare 271 s (254 GB), inventory-only
  refresh 341 s. After fix round 1 (2ff5fe63): ParseFleet 68.2 s, InventoryReloadFleet 65.5 s,
  broker RefreshInventoryOnly 53 ms. Task 6 complete at 1bd57ed0.
- **Task 6b** (e9af0b60 to eca7ae4b, `task-6b-report.md`): Parse 68.5 s to 0.036 s, varied fleet
  91.8 s to 0.60 s, PolicyEditLoad 394.7 s to 1.36 s, ClassAges 23.5 s to 0.004 s, Compare 282.5 s
  to 2.99 s, MFARequirements 30.6 s to 0.13 s. Follow-up (66a1c998, e6c378a0): named-scope fleets
  55.4 s to 8.19 s. The other rows were not re-measured after the follow-up.

## Gate rulings

1. **TLS session tickets stay off** (`session_ticket_lifetime: 0s`). The RAM cell b (TLS, full
   handshake, 170/s) has `step_p99_ms_command_permitted` 1.56 ms, under the 5 ms target
   (`load-beehive-ram.md`, cell b). The disk cell b has 23.64 ms (`load-beehive.md`, cell b); that
   is the drive, since tickets do not change a store read. Provisional on the GCP pass.
2. **Accounting group commit is already built** (Task 8, 6cf27fc6); `Offer` stays as it is. Spool
   capacity against twice the sustained rate (2 x 170 = 340/s): RAM cell c `capacity_per_s` 1291
   (`load-beehive-ram.md`). Disk cell c `capacity_per_s` 0, with `step_1_account_p99_ms` 152.10 at
   170/s, over the 50 ms gate, because of the drive (`load-beehive.md`, cell c).
3. **`LimitNOFILE=65536` stands.** The connection cap sized from it is 65536 - 1024 reserved
   = 64512 (`connectionCap`, `internal/port49d/fdlimit.go`); a quarter is 16128. The peak
   `port49_connections` is 209 on disk (cell e2) and 73 in RAM (cell c); both are under 16128.
4. **`autoscaling.averageConnections` goes from 500 to 50.** The target-rate cells are a and b with
   one replica. The peak is 62 on disk (cell b) and 8 in RAM (cell b). Half of 62 is 31, which rounds
   to 50, the nearest multiple of 50. RAM's half, 4, would round to 0, and a target of 0 is no
   target, so the disk figure is taken. Provisional on the GCP pass. `TestHPAAverageConnections`
   (`tests/helm/static_test.go`) holds the value.
5. **The timeouts stand:** `stores.session.etcd.call_timeout` (500 ms), `bulk_timeout` (30 s) and
   `packet_deadline` (2 s). The store call p99 at target is under a fifth of 500 ms (100 ms): on
   disk cells a and b `daemon_store_call_p99_ms` and `broker_store_call_p99_ms` are at most 50 ms
   (`load-beehive.md`), and in RAM at most 2.50 ms (`load-beehive-ram.md`).
6. **`stores.directory.etcd.call_timeout` guidance** is in `deploy/examples/stores/README.md`: at
   least four times the cross-region round trip. The lab injects 20 ms of egress delay on each
   region's link (`tests/lab/regions_test.go`, `regionDelay`), so the injected round trip is 80 ms
   and four times that is 320 ms; the 500 ms in the example covers an injected round trip up to
   125 ms. Cell f passes at that delay in RAM (`load-beehive-ram.md`, cell f). The figure is the
   injected delay, not a measured round trip.
7. **The reload settle is inside its bound.** `port49d_reload_seconds` is 10.4 on disk and 9.3 in
   RAM (cell d, both notes); `port49_broker_reload_seconds` is 7.3 and 7.9. The bound is
   `max(30 s, 2 x policy.watch_interval + 5 s)`; `policy.watch_interval` defaults to 5 s
   (`internal/config/config.go`), so the bound is 30 s and all four are under it.
8. **Design section 5 targets.**
   - **Met in RAM:** 170 authentications per second sustained in cells a and b (`errors` 0, `late`
     0), per-command p99 under 5 ms (0.71 ms cell a, 1.56 ms cell b), the spool capacity above.
   - **Missed on this drive** (`load-beehive.md`): per-command p99 under 5 ms is missed in every
     cell that has a per-command figure: `step_p99_ms_command_permitted` is 17.77 ms (a), 23.64 ms
     (b), 59.40 ms (d), 78.43 ms (e), 69.91 ms (e2) and 82.58 ms (f). The spool cannot sustain 340/s:
     capacity 0, account p99 152.10 ms at 170/s (cell c). Cells a, b, c, e2 and f FAIL. The 170/s
     rate itself was held in a and b (`errors` 0, `late` 0).
   - This stops the plan under ruling 7, and Ryan's 2026-11-03 ruling above is how it closes, with
     the GCP pass in beta.
