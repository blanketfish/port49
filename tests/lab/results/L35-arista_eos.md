# L35 — arista_eos

- **Date measured:** 2026-11-06
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L35-arista_eos.pcap` — 540 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L35-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestStoreOutageEndToEnd$`

## Claim

When port49d's store hangs (etcd cut off from port49d), port49d answers a command FAIL store_unavailable and a login ERROR store_unavailable within packet_deadline (2s), before the device's own TACACS+ timeout, and the device acts as on L4's store outage, never as on a silent server; once port49d closes its listeners on losing the store (its health checks, decision 37), the device acts as with port49d stopped and break-glass logs in; and once the store returns and port49d listens again, an open session's next command is answered from the context the store kept (plan 7d; spec §13 decisions 35 and 37).

## Observation

| step | observed |
|---|---|
| 0. the keyspace before the first process starts | `0 keys under /port49/` |
| 1. baseline, `show version` | `printed its output in 100ms: 'Arista vEOS-lab'` |
| 2. port49d's start lines | nothing |
| 2. after the restart, the open session's `show version` | `printed its output in 100ms: 'Arista vEOS-lab'; record permit permit_dominates, ctx_id DD6KLSE2I6FAY52C (before: DD6KLSE2I6FAY52C)` |
| 2. a token minted before the port49d restart | `redeemed: token_redeemed` |
| 3. store hung, the open session's `show version` (attempt 1) | `refused in 600ms: '% Authorization denied for command 'show version': port49: authorization store unavailable'` |
| 3. store hung, a token login (attempt 1) | `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain` |
| 3. store hung, break-glass and `show version` (attempt 1) | `login err <nil>; printed 'Authorization denied: port49: authorization store unavailable' (compare tests/lab/results/L4-error-arista_eos.md)` |
| 3. records | `authorize_command [deny store_unavailable]; redeem [deny store_unavailable deny store_unavailable]; authorize_session [deny store_unavailable]; accounting []` |
| 3. the open session's command, attempt 1 (hung 1s), request-to-reply from the capture | `AUTHOR seq 1 -> FAIL in 502ms; ACCT seq 1 -> SUCCESS in 500ms` |
| 3. the token login, attempt 1 (hung 1s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms` |
| 3. break-glass, attempt 1 (hung 1s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms; ACCT seq 1 -> SUCCESS in 501ms; AUTHOR seq 1 -> FAIL in 501ms` |
| 4. port49d's line | `4.8s after the hang: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method / health checks failed at 4.8s, listeners closed at 4.8s` |
| 4. listeners closed, the open session's `show version` | `printed its output in 100ms: 'Arista vEOS-lab' (compare tests/lab/results/quarantine-arista_eos.md)` |
| 4. listeners closed, break-glass and `show version` | `login err <nil> in 100ms; printed 'Arista vEOS-lab'` |
| 5. port49d's start lines | `listening 5s after the store returned:` |
| 5. store back, the open session's `show version` | `printed its output in 100ms: 'Arista vEOS-lab'; record permit permit_dominates, ctx_id DD6KLSE2I6FAY52C` |

