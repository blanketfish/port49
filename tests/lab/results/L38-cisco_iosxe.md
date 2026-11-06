# L38 — cisco_iosxe

- **Date measured:** 2026-11-06
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L38-cisco_iosxe.pcap` — 1084 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L38-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=iosxe`, `-run ^TestIOSXEOpenSessionUnreachable$`

## Claim

On IOS-XE, an open session's `show privilege` and `show version`, typed once both port49d replicas are unreachable, are answered as L4's reading 3 says (the device's local method) whether or not the session's last command was answered FAIL store_unavailable, and the device sends port49 nothing (plan 7e; compare quarantine-cisco_iosxe.md).

## Observation

| cell | typed first in its session | typed second in its session |
|---|---|---|
| 0. the device's TACACS+ servers, read back after the push | `aaa group server tacacs+ port49 server name port49-host server name port49-host2 ip vrf forwarding clab-mgmt ip tacacs source-interface GigabitEthernet1 tacacs server port49-host address ipv4 172.100.100.1 key <removed> timeout 5 tacacs server port49-host2 address ipv4 172.100.100.2 key <removed> timeout 5 / /` |
| (the daemons stopped after a permit (the harness's `terminal length 0`), attempt 1) | | |
| (a separate session's `show privilege` while every process answers) | `29 bytes in 300ms, first line 'Current privilege level is 15'` | |
| `show privilege`, the daemons stopped after a permit (the harness's `terminal length 0`) | `session 1: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.00s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` | `session 2: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.00s to 172.100.100.1: refused after 0s; +0.00s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` |
| `show version`, the daemons stopped after a permit (the harness's `terminal length 0`) | `session 2: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` | `session 1: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` |
| (the daemons stopped after a FAIL store_unavailable on the session's last command, attempt 1) | | |
| (a separate session's `show privilege` while every process answers) | `29 bytes in 300ms, first line 'Current privilege level is 15'` | |
| (the FAIL, session 1: `show clock` with the store hung) | `39 bytes in 800ms, first line 'port49: authorization store unavailable'` | |
| (the FAIL, session 2: `show clock` with the store hung) | `39 bytes in 800ms, first line 'port49: authorization store unavailable'` | |
| (the FAIL's proof) | 2 deny store_unavailable record(s) on A; 2 AUTHOR FAIL(s) on the wire: `AUTHOR seq 1 -> FAIL from 172.100.100.1 in 500ms; AUTHOR seq 1 -> FAIL from 172.100.100.1 in 501ms` | |
| `show privilege`, the daemons stopped after a FAIL store_unavailable on the session's last command | `session 1: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.00s to 172.100.100.1: refused after 0s; +0.00s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` | `session 2: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` |
| `show version`, the daemons stopped after a FAIL store_unavailable on the session's last command | `session 2: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` | `session 1: 23 bytes in 100ms, first line '% Authorization failed.'; the device sent port49 3 connection(s) and 0 packet(s) with a payload: +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: refused after 0s` |

The harness's first command in every session, `terminal length 0`, was permitted by port49 before the daemons stopped, so the first column is "after a permit", not "after nothing".

