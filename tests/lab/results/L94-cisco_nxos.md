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

Every cell ran on one TLS connection, in both modes, except c5 on both arms (one before port49d's restart and one after) and baseline c3, where the device opened a second.

| Cell | Baseline arm | Fixed arm |
|---|---|---|
| c1, two sessions interleaving commands | pass: every command asked once, denies held, START and STOP arrived, no server-dead mark | the same |
| c2, a FAIL held in its 2 s failure delay ahead of another session's commands | pass | pass: the later session's commands answered within the delay; the FAIL reported as an authentication failure |
| c3, three concurrent FAILs while a command runs every 250 ms | commands waited behind the FAILs: only 2 ran, the second in 7.26 s (`offered`) and 6.51 s (`single`), past vEOS's 5.0 s reply timeout (L13); the three FAILed logins themselves took 15.0–16.4 s (`offered`) and 13.4–15.7 s (`single`); the device marked the server dead 7 times and fell back once, and opened a second connection | 8 commands ran, each answered in 0.75–1.00 s; port49 decided each within 24 ms of the device asking; the FAILed logins took 5.0–5.1 s; 0 server-dead marks, one connection |
| c4, accounting replies held 1.5 s so later authorization replies leave first | not run (needs the fixed arm) | pass: c1's conditions held; 0 server-dead marks, no `ssl_read` error. Replies left out of request order, by inference from the records (which carry read time): in `single`, two `account` requests were read at 07:58:37.723 and .739, so their held replies could not leave before about 07:58:39.22, while session 1's `show version` authorization was read at 37.892 and the device finished that command by 38.63, all on one TLS connection (port 55154). Its reply therefore left before the earlier accounting replies. `offered` shows the same order (account read 48.371, authorization 48.541). |
| c5, port49d restarted while a session is in its failure delay | the device reconnected; no command ran unasked | the same |

c5's one `ssl_read` failure and two server-dead marks are the restart itself (both arms show them); the device reconnected on its own.

c4 on NX-OS (f57c3f75) ran the hold build from before the hold was switched on at the cell's clean point (e4a7abd7): every accounting reply from daemon start was held 1.5 s, so its summary has no `accounting hold:` line. The hold therefore covered every accounting reply in the cell, and the cell passed with it.

## Result

NX-OS 10.6(2)F takes out-of-order replies on one single-connect TLS connection, in both modes. With decision 59, a command no longer waits behind other sessions' failing logins (c3: from up to 7.3 s to under 1 s), and the device stops marking the server dead under that load. L94 is measured on cisco_nxos; the row stays open for the platforms its Status names.
