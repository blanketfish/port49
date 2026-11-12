# L94 — cisco_nxos

- **Date measured:** 2026-11-12
- **Platform:** cisco_nxos (containerlab node `nx1`)
- **Image version:** Nexus 9300v 10.6(2)F (`vrnetlab/cisco_n9kv:9300v64-10.6.2.F`)
- **Topology:** `tests/lab/topologies/nxos106.clab.yml`
- **Transport:** TACACS+ over TLS (RFC 9887), port 300; both modes: single-connect offered by port49 (`offered`) and configured on the device (`single`)
- **Run:** `PORT49_LAB_PLATFORMS=nxos106 go test -tags lab ./tests/lab/ -run '^TestL94$' -count=1 -v -timeout 300m`, with `PORT49_L94_ARM=baseline` (port49d before decision 59) and `PORT49_L94_ARM=fixed` for cells c1, c2, c3 and c5, then `PORT49_L94_ARM=fixed PORT49_L94_CELLS=c4`, which runs the lab-only `port49_lab_acct_hold` build
- **Evidence:** `tests/lab/evidence/L94-cisco_nxos/{baseline,fixed}/{offered,single}/` — per cell, the summary (`<cell>-summary.txt`), port49's decision records, the typed commands, the device's TACACS+ debug counts, and the cell's TLS connections (`<cell>.tls.json`, built from the cell's capture). Committed as 4481bbd8 (baseline), 5131998b (fixed) and f57c3f75 (c4).
- **Capture:** the raw captures are git-ignored (they hold lab credentials). The c4 run's are kept under `tests/lab/captures/L94-cisco_nxos-c4/`. The c1–c3 and c5 runs' raw captures were replaced by later runs before they were copied; each cell's `<cell>.tls.json` is the record taken from them.

## Claim

Spec §15 L94: whether NX-OS takes replies to the sessions of one single-connect connection sent out of request order, and how long a command waits behind failing logins on that connection (decision 59, provisional on L94).

## Observation

Every cell ran on exactly one TLS connection (c5 on two: one before port49d's restart and one after), in both modes and on both arms.

| Cell | Baseline arm | Fixed arm |
|---|---|---|
| c1, two sessions interleaving commands | pass: every command asked once, denies held, START and STOP arrived, no server-dead mark | the same |
| c2, a FAIL held in its 2 s failure delay ahead of another session's commands | pass | pass: the later session's commands answered within the delay; the FAIL reported as an authentication failure |
| c3, three concurrent FAILs while a command runs every 250 ms | commands waited behind the FAILs: 1.0–16.4 s (`offered`), 1.0–15.7 s (`single`); the device marked the server dead 7 times and fell back once, and opened a second connection | every command answered in 0.75–1.00 s, port49 decided each within 24 ms of the device asking, 0 server-dead marks, one connection |
| c4, accounting replies held 1.5 s so later authorization replies leave first | not run (needs the fixed arm) | pass: c1's conditions held with replies out of request order; 0 server-dead marks, no `ssl_read` error |
| c5, port49d restarted while a session is in its failure delay | the device reconnected; no command ran unasked | the same |

c5's one `ssl_read` failure and two server-dead marks are the restart itself (both arms show them); the device reconnected on its own.

## Result

NX-OS 10.6(2)F takes out-of-order replies on one single-connect TLS connection, in both modes. With decision 59, a command no longer waits behind other sessions' failing logins (c3: from up to 16.4 s to under 1 s), and the device stops marking the server dead under that load. L94 closes for cisco_nxos; the row stays open for the platforms its Status names.
