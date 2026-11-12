# L94 — arista_ceos

- **Date measured:** 2026-11-12
- **Platform:** arista_eos (containerlab node `leaf1`)
- **Image version:** cEOS-lab 4.36.3M (`ceos:4.36.3M`)
- **Topology:** `tests/lab/topologies/ceos436.clab.yml`
- **Transport:** TACACS+ over TLS (RFC 9887), port 300, with `single-connection` configured on the device (`single`)
- **Run:** `PORT49_LAB_PLATFORMS=ceos436 go test -tags lab ./tests/lab/ -run '^TestL94$' -count=1 -v -timeout 300m`, with `PORT49_L94_ARM=baseline` (port49d before decision 59) and `PORT49_L94_ARM=fixed`, cells c1, c2, c3 and c5
- **Evidence:** `tests/lab/evidence/L94-arista_ceos/{baseline,fixed}/single/` — per cell, the summary (`<cell>-summary.txt`), port49's decision records, the typed commands and the cell's TLS connections (`<cell>.tls.json`, built from the cell's capture). Committed as f6a0c919 (baseline) and d3f7ff9e (fixed).
- **Capture:** the raw captures are git-ignored (they hold lab credentials) and are kept under `tests/lab/captures/L94-arista_ceos-baseline-r2/` and `tests/lab/captures/L94-arista_ceos-fixed/`.

## Claim

Spec §15 L94: whether EOS takes replies to the sessions of one single-connect connection sent out of request order, and how long a command waits behind failing logins on that connection (decision 59, provisional on L94).

## Observation

Both arms pass every cell, and the two arms behave the same.

| Cell | Both arms |
|---|---|
| c1, two sessions interleaving commands | one TLS connection; every command asked once and answered in 0.25 s; denies held; START and STOP arrived |
| c2, a FAIL held in its 2 s failure delay ahead of another session's commands | 3 TLS connections, at most 2 open at once: the device opened a connection per login, so the FAIL and the other session's commands did not share a connection; the commands answered in 0.25 s |
| c3, three concurrent FAILs while a command runs every 250 ms | 5 TLS connections, at most 4 open at once, one per login; every command answered in 0.25 s |
| c5, port49d restarted while a session is in its failure delay | the device reconnected; no command ran unasked |

c4 (accounting replies held so a later authorization reply leaves first) was not run on EOS; the spec runs it where a device pipelines requests behind accounting on one connection (NX-OS, Junos).

Findings, not failures:

- **A connection per login.** With `single-connection` configured, EOS 4.36.3M still opens a new TLS connection for each login while another is busy. Its c2 and c3 therefore never put two sessions' requests on one connection, and those cells do not exercise decision 59's out-of-order replies on this platform; c1, where they did share one, passes on both arms.
- **A stale connection.** In c3 on both arms, the device sent a packet on the connection it had opened in c2, which port49d's stop between cells had closed from the server side; the server reset it and the device carried on. The harness reports this as a finding (`tests/lab/l94_cells.go`, `l94OlderThanCapture`), and the cell graded normally.

## Result

EOS 4.36.3M takes port49's replies on one single-connect connection on both arms, and no command waits behind a failing login. That is because the device spreads concurrent logins over separate connections, not because of decision 59: L94's head-of-line cells are not exercised here. The row stays open for the platforms its Status names.
