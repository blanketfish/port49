# L35 — juniper_vsrx

- **Date measured:** 2026-11-06
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L35-juniper_vsrx.pcap` — 482 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L35-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestStoreOutageEndToEnd$`

## Claim

When port49d's store hangs (etcd cut off from port49d), port49d answers a command FAIL store_unavailable and a login ERROR store_unavailable within packet_deadline (2s), before the device's own TACACS+ timeout, and the device acts as on L4's store outage, never as on a silent server; once port49d closes its listeners on losing the store (its health checks, decision 37), the device acts as with port49d stopped and break-glass logs in; and once the store returns and port49d listens again, an open session's next command is answered from the context the store kept (plan 7d; spec §13 decisions 35 and 37).

## Observation

| step | observed |
|---|---|
| 0. the keyspace before the first process starts | `0 keys under /port49/` |
| 1. baseline, `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1'` |
| 2. port49d's start lines | nothing |
| 2. after the restart, the open session's `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1'; record , ctx_id (before: )` |
| 2. a token minted before the port49d restart | `redeemed: token_redeemed` |
| 3. store hung, a token login (attempt 1) | `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain` |
| 3. the token login, attempt 1 (hung 6s), validity | `port49d closed its listeners during this cell: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable:…` |
| 3. the token login, attempt 1 (hung 6s) | `valid, port49d went dark during it: every verdict before dark was ERROR in time (AUTHEN seq 3 ERROR(7) in 500ms; AUTHEN seq 3 ERROR(7) in 501ms); the rest of th…` |
| 3. store hung, break-glass and `show version` (attempt 1) | `login err <nil>; printed 'Hostname: srx1' (compare tests/lab/results/L4-error-juniper_vsrx.md)` |
| 3. records | `authorize_command []; redeem [deny store_unavailable deny store_unavailable deny store_unavailable]; authorize_session []; accounting []` |
| 3. the token login, attempt 1 (hung 6s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 500ms; AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms; ACCT seq 1 -> SUCCESS in 500ms; ACCT seq 1 unanswered` |
| 3. break-glass, attempt 1 (hung 1s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms` |
| 4. port49d's line | `4.8s after the hang: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method / health checks failed at 4.8s, listeners closed at 4.8s` |
| 4. listeners closed, the open session's `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1' (no quarantine note for this image)` |
| 4. listeners closed, break-glass and `show version` | `login err <nil> in 200ms; printed 'Hostname: srx1'` |
| 5. port49d's start lines | `listening 5s after the store returned:` |
| 5. store back, the open session's `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1'; record , ctx_id` |

