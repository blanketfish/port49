# L41 — cisco_nxos

- **Date measured:** 2026-10-05
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L41-cisco_nxos.pcap` — 352 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L41-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

On the compose deployment (plan 7f; port49d, port49-broker and three etcd members as containers), an idle port49d whose store hangs closes its TACACS+ listener within close_after × interval + call_timeout (5.5s at the defaults; the bound allows 5s more for the poll), and break-glass then logs in; an open session's next command once it is closed is recorded beside the same command with port49d stopped; once the store returns, port49d says its open_after passes before it listens again, and the session's next command the device sends it is answered from the context the store kept (policy engine spec §13 decision 37).

## Observation

| cell | observed |
|---|---|
| 1. login through the compose port49d, `show version` | `printed its output in 810ms: 'Cisco Nexus Operating System (NX-OS) Software'; record permit permit_dominates, ctx_id FHVENMXVEBDGXKXJ / AUTHOR seq 1 -> PASS_ADD from 172.30.49.6 in 1ms; AUTHOR seq 1 -> PASS_ADD from 172.30.49.6 in 1ms / connections: +0.01s to 172.100.100.1: accepted after 0s; +0.01s to 172.30.49.6: accepted after 0s` |
| 2. the store hangs (the three members paused), no device asking: port49d closes its listener | `5s after the hang (bound 10.5s); the line: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method` |
| 3. listener closed: the open session's `show version` | `1128 bytes in 800ms, first line 'Cisco Nexus Operating System (NX-OS) Software' / no request in the capture / connections: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.30.49.6: refused after 0s` |
| 4. listener closed: break-glass and `show version` | `login err <nil> in 1s; printed 'Cisco Nexus Operating System (NX-OS) Software' / no request in the capture / connections: +0.12s to 172.100.100.1: refused after 0s; +0.12s to 172.30.49.6: refused after 0s; +0.26s to 172.100.100.1: refused after 0s; +0.26s to 172.30.49.6: refused after 0s; +0.27s to 172.100.100.1: refused after 0s; +0.27s to 172.30.49.6: refused after 0s; +0.99s to 172.100.100.1: refused after 0s; +0.99s to 172.30.49.6: refused after 0s; +1.00s to 172.100.100.1: refused after 0s; +1.00s to 172.30.49.6: refused after 0s` |
| 5. the store returns: the passes said, then listening | `passes said 3.5s, listening 3.5s after the release` |
| 6. the open session's `show version` until port49d is asked again | `asked 800ms after listening; record permit permit_dominates, ctx_id FHVENMXVEBDGXKXJ (before: FHVENMXVEBDGXKXJ) / AUTHOR seq 1 -> PASS_ADD from 172.30.49.6 in 16ms; AUTHOR seq 1 -> PASS_ADD from 172.30.49.6 in 16ms / connections: +0.01s to 172.100.100.1: accepted after 0s; +0.01s to 172.30.49.6: accepted after 0s` |
| 7. port49d stopped: the open session's `show version` | `1128 bytes in 700ms, first line 'Cisco Nexus Operating System (NX-OS) Software' / no request in the capture / connections: +0.01s to 172.100.100.1: refused after 0s` |
| 7. port49d stopped: break-glass | `login err <nil> in 1s; printed 'Cisco Nexus Operating System (NX-OS) Software'` |
| 3 beside 7 | `closed on its checks: 1128 bytes in 800ms, first line 'Cisco Nexus Operating System (NX-OS) Software'; stopped: 1128 bytes in 700ms, first line 'Cisco Nexus Operating System (NX-OS) Software'` |

