# L35 — cisco_iosxe

- **Date measured:** 2026-10-03
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L35-cisco_iosxe.pcap` — 729 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L35-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

When port49d's store hangs (etcd cut off from port49d), port49d answers a command FAIL store_unavailable and a login ERROR store_unavailable within store.packet_deadline (2s), before the device's own TACACS+ timeout, and the device acts as on L4's store outage, never as on a silent server; once port49d closes its listeners on losing the store (store.etcd.hold_ttl), the device acts as with port49d stopped and break-glass logs in; and once the store returns and port49d listens again, an open session's next command is answered from the context the store kept (plan 7d; spec §13 decision 35).

## Observation

| step | observed |
|---|---|
| 0. the keyspace before port49d's first start | `0 keys under /port49/ (err <nil>)` |
| 1. baseline, `show version` | `printed its output in 300ms: 'Cisco IOS XE Software, Version 17.13.01a'` |
| 2. port49d's start lines | `port49d: store: purged 153 unspent token(s) from before this start (run 'port49 token' again) / port49d: store: 1 live context(s) carried onto the policy in force (bundle sha256:3d7dd9dfe022f76f8bdb36a30a5790a783cccdb303682bbc3d12a5b826b29b43) before serving` |
| 2. after the restart, the open session's `show version` | `printed its output in 300ms: 'Cisco IOS XE Software, Version 17.13.01a'; record permit permit_dominates, ctx_id HLJJJZXIXACOCYOQ (before: HLJJJZXIXACOCYOQ)` |
| 2. a token minted before the restart | `refused token_not_found` |
| 3. store hung, the open session's `show version` (attempt 1) | `refused silently, no output: printed something in 800ms, without "Cisco IOS XE Software": 'show version'; nothing more 3s later` |
| 3. store hung, a token login (attempt 1) | `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain` |
| 3. store hung, break-glass and `show version` (attempt 1) | `login err ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; printed nothi…` |
| 3. records | `authorize_command [deny store_unavailable]; redeem [deny store_unavailable deny store_unavailable deny store_unavailable deny store_unavailable]; authorize_session []; accounting []` |
| 3. the open session's command, attempt 1 (hung 4s), request-to-reply from the capture | `AUTHOR seq 1 -> FAIL in 501ms` |
| 3. the token login, attempt 1 (hung 5s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms; AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms` |
| 3. break-glass, attempt 1 (hung 5s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms; AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms` |
| 4. port49d's line | `20s after the hang: port49d: store: lost this port49d's hold on keyspace /port49/ (its lock key is gone, or etcd stopped answering with half its lease or less left); closing every listener so that devices use their local method` |
| 4. listeners closed, the open session's `show version` | `refused in 100ms: '% Authorization failed.' (compare tests/lab/results/quarantine-cisco_iosxe.md)` |
| 4. listeners closed, break-glass and `show version` | `login err <nil> in 800ms; printed 'Cisco IOS XE Software, Version 17.13.01a'` |
| 5. port49d's start lines | `listening 1m27s after the store returned: port49d: store: purged 152 unspent token(s) from before this start (run 'port49 token' again) / port49d: store: 1 live context(s) carried onto the policy in force (bundle sha256:3d7dd9dfe022f76f8bdb36a30a5790a783cccdb303682bbc3d12a5b826b29b43) before serving` |
| 5. store back, the open session's `show version` | `printed its output in 300ms: 'Cisco IOS XE Software, Version 17.13.01a'; record permit permit_dominates, ctx_id HLJJJZXIXACOCYOQ` |

