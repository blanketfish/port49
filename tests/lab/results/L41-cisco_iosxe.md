# L41 — cisco_iosxe

- **Date measured:** 2026-11-06
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L41-cisco_iosxe.pcap` — 588 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L41-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL41GoDarkMidSession$`

## Claim

On the compose deployment (plan 7f; port49d, port49-broker and three etcd members as containers), an idle port49d whose store hangs closes its TACACS+ listener within close_after × interval + call_timeout (5.5s at the defaults; the bound allows 5s more for the poll), and break-glass then logs in; an open session's next command once it is closed is recorded beside the same command with port49d stopped; once the store returns, port49d says its open_after passes before it listens again, and the session's next command the device sends it is answered from the context the store kept (policy engine spec §13 decision 37).

## Observation

Each connection and reply below appears once per bridge leg (the device to 172.100.100.1, then to port49d's container at 172.30.49.x) while the container exists, and once after it is stopped.

| cell | observed |
|---|---|
| 1. login through the compose port49d, `show version` | `printed its output in 300ms: 'Cisco IOS XE Software, Version 17.13.01a'; record permit permit_dominates, ctx_id SA6RG2OENMTCG2RM / AUTHOR seq 1 -> PASS_ADD from 172.30.49.5 in 2ms; AUTHOR seq 1 -> PASS_ADD from 172.30.49.5 in 2ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 5ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 5ms / connections: +0.01s to 172.100.100.1: accepted after 0s; +0.01s to 172.30.49.5: accepted after 0s; +0.21s to 172.100.100.1: accepted after 0s; +0.21s to 172.30.49.5: accepted after 0s` |
| 2. the store hangs (the three members paused), no device asking: port49d closes its listener | `5s after the hang (bound 10.5s); the line: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method` |
| 3. listener closed: the open session's `show version` | `23 bytes in 100ms, first line '% Authorization failed.' / no request in the capture / connections: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.30.49.5: refused after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.30.49.5: refused after 0s` |
| 4. listener closed: break-glass and `show version` | `login err <nil> in 800ms; printed 'Cisco IOS XE Software, Version 17.13.01a' / no request in the capture / connections: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.30.49.5: refused after 0s; +0.02s to 172.100.100.1: refused after 0s; +0.02s to 172.30.49.5: refused after 0s; +0.02s to 172.100.100.1: refused after 0s; +0.02s to 172.30.49.5: refused after 0s; +0.28s to 172.100.100.1: refused after 0s; +0.28s to 172.30.49.5: refused after 0s; +0.28s to 172.100.100.1: refused after 0s; +0.28s to 172.30.49.5: refused after 0s; +0.53s to 172.100.100.1: refused after 0s; +0.53s to 172.30.49.5: refused after 0s; +0.53s to 172.100.100.1: refused after 0s; +0.53s to 172.30.49.5: refused after 0s` |
| 5. the store returns: the passes said, then listening | `passes said 3.5s, listening 3.5s after the release` |
| 6. the open session's `show version` until port49d is asked again | `asked 300ms after listening; record permit permit_dominates, ctx_id SA6RG2OENMTCG2RM (before: SA6RG2OENMTCG2RM) / AUTHOR seq 1 -> PASS_ADD from 172.30.49.5 in 15ms; AUTHOR seq 1 -> PASS_ADD from 172.30.49.5 in 15ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 9ms; ACCT seq 1 -> SUCCESS from 172.30.49.5 in 9ms / connections: +0.00s to 172.100.100.1: accepted after 0s; +0.00s to 172.30.49.5: accepted after 0s; +0.21s to 172.100.100.1: accepted after 0s; +0.21s to 172.30.49.5: accepted after 0s` |
| 7. port49d stopped: the open session's `show version` | `23 bytes in 100ms, first line '% Authorization failed.' / no request in the capture / connections: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.1: refused after 0s` |
| 7. port49d stopped: break-glass | `login err <nil> in 800ms; printed 'Cisco IOS XE Software, Version 17.13.01a'` |
| 3 beside 7 | `closed on its checks: 23 bytes in 100ms, first line '% Authorization failed.'; stopped: 23 bytes in 100ms, first line '% Authorization failed.'` |

