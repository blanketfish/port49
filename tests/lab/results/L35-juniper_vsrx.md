# L35 — juniper_vsrx

- **Date measured:** 2026-10-03
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L35-juniper_vsrx.pcap` — 528 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L35-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

When port49d's store hangs (etcd cut off from port49d), port49d answers a command FAIL store_unavailable and a login ERROR store_unavailable within store.packet_deadline (2s), before the device's own TACACS+ timeout, and the device acts as on L4's store outage, never as on a silent server; once port49d closes its listeners on losing the store (store.etcd.hold_ttl), the device acts as with port49d stopped and break-glass logs in; and once the store returns and port49d listens again, an open session's next command is answered from the context the store kept (plan 7d; spec §13 decision 35).

## Observation

| step | observed |
|---|---|
| 0. the keyspace before port49d's first start | `0 keys under /port49/ (err <nil>)` |
| 1. baseline, `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1'` |
| 2. port49d's start lines | `port49d: store: purged 153 unspent token(s) from before this start (run 'port49 token' again) / port49d: store: 1 live context(s) carried onto the policy in force (bundle sha256:3d7dd9dfe022f76f8bdb36a30a5790a783cccdb303682bbc3d12a5b826b29b43) before serving` |
| 2. after the restart, the open session's `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1'; record , ctx_id (before: )` |
| 2. a token minted before the restart | `refused token_not_found` |
| 3. store hung, a token login (attempt 1) | `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain` |
| 3. store hung, break-glass and `show version` (attempt 1) | `login err <nil>; printed 'Hostname: srx1' (compare tests/lab/results/L4-error-juniper_vsrx.md)` |
| 3. records | `authorize_command []; redeem [deny store_unavailable deny store_unavailable deny store_unavailable]; authorize_session []; accounting []` |
| 3. the token login, attempt 1 (hung 6s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms; AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 500ms` |
| 3. break-glass, attempt 1 (hung 1s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms` |
| 4. port49d's line | `14s after the hang: port49d: store: lost this port49d's hold on keyspace /port49/ (its lock key is gone, or etcd stopped answering with half its lease or less left); closing every listener so that devices use their local method` |
| 4. listeners closed, the open session's `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1' (no quarantine note for this image)` |
| 4. listeners closed, break-glass and `show version` | `login err <nil> in 100ms; printed 'Hostname: srx1'` |
| 5. port49d's start lines | `listening 53s after the store returned: port49d: store: purged 152 unspent token(s) from before this start (run 'port49 token' again) / port49d: store: 1 live context(s) carried onto the policy in force (bundle sha256:3d7dd9dfe022f76f8bdb36a30a5790a783cccdb303682bbc3d12a5b826b29b43) before serving` |
| 5. store back, the open session's `show version` | `printed its output, read 3s after the prompt its echo carried: 'Hostname: srx1'; record , ctx_id` |

