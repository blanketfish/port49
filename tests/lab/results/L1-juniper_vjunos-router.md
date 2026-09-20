# L1 — juniper_vjunos-router

- **Date measured:** 2026-09-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/captures/L1-juniper_vjunos-router.pcap` — 208 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L1-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

What the `port` field contains, per platform and per transport — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session and stable for its life.

## Observation

Two overlapping SSH sessions, each holding an interactive shell open, produced these `port` values on the authentication START:

| session | user | `port` |
|---|---|---|
| 1 | alice02 | `` |
| 2 | alice03 | `` |

**The two concurrent sessions reported the SAME `port` value.** The login context key `(nas, port)` therefore does not distinguish them: the second login overwrites the first login's context, and the receipt key `(nas, port, username)` collides for repeated logins by one user.

All 2 `port` values seen in this test: ["" ""].

Stability for the life of a session: stable. Across 2 sessions and 4 records carrying a ctx_id, every record for a session reported the same `port` as that session's authentication START.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here (eAPI and NX-API are plan 3), so L1 is not answered for those transports.
