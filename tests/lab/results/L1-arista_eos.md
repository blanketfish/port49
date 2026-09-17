# L1 — arista_eos

- **Date measured:** 2026-09-17
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L1-arista_eos.pcap` — 148 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L1-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

What the `port` field contains, per platform and per transport — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session and stable for its life.

## Observation

Two overlapping SSH sessions, each holding an interactive shell open, produced these `port` values on the authentication START:

| session | user | `port` |
|---|---|---|
| 1 | alice02 | `ssh` |
| 2 | alice03 | `ssh` |

**The two concurrent sessions reported the SAME `port` value.** The login context key `(nas, port)` therefore does not distinguish them: the second login overwrites the first login's context, and the receipt key `(nas, port, username)` collides for repeated logins by one user.

All 2 `port` values seen in this test: ["ssh" "ssh"].

Stability for the life of a session: stable. Across 2 sessions and 4 records carrying a ctx_id, every record for a session reported the same `port` as that session's authentication START.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here (eAPI and NX-API are plan 3), so L1 is not answered for those transports.
