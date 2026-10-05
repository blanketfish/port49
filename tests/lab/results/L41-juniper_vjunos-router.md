# L41 — juniper_vjunos-router

- **Date measured:** 2026-10-05
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L41-juniper_vjunos-router.pcap` — 368 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L41-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

On the compose deployment (plan 7f; port49d, port49-broker and three etcd members as containers), an idle port49d whose store hangs closes its TACACS+ listener within close_after × interval + call_timeout (5.5s at the defaults; the bound allows 5s more for the poll), and break-glass then logs in; an open session's next command once it is closed is recorded beside the same command with port49d stopped; once the store returns, port49d says its open_after passes before it listens again, and the session's next command the device sends it is answered from the context the store kept (policy engine spec §13 decision 37).

## Observation

| cell | observed |
|---|---|
| 1. login through the compose port49d, `show version` | `printed its output in 200ms: 'Junos: 23.4R2-S2.1'; record , ctx_id / ACCT seq 1 -> SUCCESS from 172.30.49.5 in 12ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 12ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 4ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 4ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 4ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 4ms / connections: +0.39s to 172.100.100.1: accepted after 0s; +0.39s to 172.30.49.5: accepted after 0s; +0.41s to 172.100.100.1: accepted after 0s; +0.41s to 172.30.49.5: accepted after 0s; +0.41s to 172.100.100.1: accepted after 0s; +0.41s to 172.30.49.5: accepted after 0s` |
| 2. the store hangs (the three members paused), no device asking: port49d closes its listener | `5s after the hang (bound 10.5s); the line: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method` |
| 3. listener closed: the open session's `show version` | `6010 bytes in 200ms, first line 'Hostname: srx1' / no request in the capture / connections: the device opened no connection` |
| 4. listener closed: break-glass and `show version` | `login err <nil> in 200ms; printed 'Hostname: srx1' / no request in the capture / connections: +0.02s to 172.100.100.1: refused after 0s; +0.02s to 172.30.49.5: refused after 0s` |
| 5. the store returns: the passes said, then listening | `passes said 3.5s, listening 3.5s after the release` |
| 6. Junos: a fresh login after the return (an open session's command sends no TACACS+) | `err <nil>, 300ms after listening / AUTHEN seq 1 -> GETPASS(5) from 172.30.49.5 in 0s; AUTHEN seq 3 -> PASS(1) from 172.30.49.5 in 37ms; AUTHEN seq 1 -> GETPASS(5) from 172.30.49.5 in 0s; AUTHEN seq 3 -> PASS(1) from 172.30.49.5 in 37ms; AUTHOR seq 1 -> PASS_ADD from 172.30.49.5 in 14ms; AUTHOR seq 1 -> PASS_ADD from 172.30.49.5 in 14ms / connections: +0.10s to 172.100.100.1: accepted after 0s; +0.10s to 172.30.49.5: accepted after 0s; +0.13s to 172.100.100.1: accepted after 0s; +0.13s to 172.30.49.5: accepted after 0s` |
| 7. port49d stopped: the open session's `show version` | `6010 bytes in 200ms, first line 'Hostname: srx1' / no request in the capture / connections: the device opened no connection` |
| 7. port49d stopped: break-glass | `login err <nil> in 200ms; printed 'Hostname: srx1'` |
| 3 beside 7 | `closed on its checks: 6010 bytes in 200ms, first line 'Hostname: srx1'; stopped: 6010 bytes in 200ms, first line 'Hostname: srx1'` |

