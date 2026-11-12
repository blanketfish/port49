# L94 — juniper_vjunos-router

- **Date measured:** 2026-11-12
- **Platform:** juniper_vjunos-router (containerlab node `srx1`)
- **Image version:** vJunos-router 26.2R1.7 (`vrnetlab/juniper_vjunos-router:26.2R1.7`)
- **Topology:** `tests/lab/topologies/vjunos26.clab.yml`
- **Transport:** TACACS+ over TLS (RFC 9887), port 300, with `single-connection` configured on the device (`single`)
- **Run:** `PORT49_LAB_PLATFORMS=vjunos26 go test -tags lab ./tests/lab/ -run '^TestL94$' -count=1 -v -timeout 300m`, with `PORT49_L94_ARM=baseline` (port49d before decision 59) and `PORT49_L94_ARM=fixed` for cells c1, c2, c3 and c5, then `PORT49_L94_ARM=fixed PORT49_L94_CELLS=c4`, which runs the lab-only `port49_lab_acct_hold` build
- **Evidence:** `tests/lab/evidence/L94-juniper_vjunos-router/{baseline,fixed}/single/` — per cell, the summary (`<cell>-summary.txt`), port49's decision records, the typed commands, the device's TACACS+ log lines and the cell's TLS connections (`<cell>.tls.json`, built from the cell's capture). Committed as b4a2d9bd (baseline), aec97a04 (fixed) and c3f34dd7 with a4858992 (c4).
- **Capture:** the raw captures are git-ignored (they hold lab credentials). The c4 run's are kept under `tests/lab/captures/L94-juniper_vjunos-router-c4-r3/`. The baseline and fixed c1–c3 and c5 runs' raw captures were replaced by later runs before they were copied; each cell's `<cell>.tls.json` is the record taken from them.

## Claim

Spec §15 L94: whether Junos takes replies to the sessions of one single-connect connection sent out of request order, and how long a command waits behind failing logins on that connection (decision 59, provisional on L94).

## Observation

Both arms pass every cell, and the two arms behave the same: the same connection counts, the same command times (0.25–1.50 s in c1, 0.25–1.00 s in c3) and the same suspect-line count in the device log.

| Cell | Both arms |
|---|---|
| c1, two sessions interleaving commands | 3 TLS connections, at most 1 open at once; every command asked once; denies held; START and STOP arrived |
| c2, a FAIL held in its 2 s failure delay ahead of another session's commands | 5 TLS connections, at most 2–3 open at once: one per login |
| c3, three concurrent FAILs while a command runs every 250 ms | 9 TLS connections, at most 4–5 open at once: one per login; every command answered in 1 s or less |
| c4, accounting replies held 1.5 s (fixed arm) | 3 TLS connections, at most 1 open at once; the hold applied to all 38 accounting replies and every record arrived; no connection was lost |
| c5, port49d restarted while a session is in its failure delay | the device reconnected; no command ran unasked |

What Junos does not do, and therefore what this platform does not exercise:

- **A connection per login.** With `single-connection` configured, vJunos 26.2R1.7 still opens a new TLS connection for each login and for its accounting, so in c1–c3 two sessions' requests never wait on one connection.
- **No per-command authorization.** Junos asked port49 for no `authorize_command` in any cell: it authorizes commands locally from the attributes it received at login, and its denies (`show system users`) are its own.
- **No pipelining behind accounting.** In c4 the device sent each accounting record only after the reply to the one before (one per 1.5 s), so no reply could leave out of request order.

## Result

vJunos 26.2R1.7 takes port49's replies on both arms, and nothing in the device's behaviour changed with decision 59. Out-of-order replies on one connection were not exercised on this platform, because Junos never puts two outstanding requests on one connection. L94 stays open for Junos: vSRX is not measurable in this harness (no RFC 9887 dialect), and a Junos configuration that pipelines requests has not been found.
