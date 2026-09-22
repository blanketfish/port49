# L1 — juniper_vsrx

- **Date measured:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L1-juniper_vsrx.pcap` — 268 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L1-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What the `port` field contains, per platform and per transport — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session and stable for its life.

## Observation

Two overlapping SSH sessions, each holding an interactive shell open, produced these `port` values on the authentication START:

| session | user | `port` |
|---|---|---|
| 1 | alice02 | `` |
| 2 | alice03 | `` |

**The two concurrent sessions reported the SAME `port` value.** The login context key `(nas, port)` that plan 1 shipped therefore does not distinguish them: the second login overwrites the first login's context, and the receipt key `(nas, port, username)` collides for repeated logins by one user. This measurement is why neither key survived. The context key is now `(nas, username)` and the receipt key `(nas, username, kind, credential_sha256)`, so a repeat of one credential finds its own receipt, a different credential misses it, and an enable cannot be answered out of a login receipt (spec §13, decision 15).

All 2 `port` values seen in this test: ["" ""].

Stability for the life of a session: stable. Across 2 sessions and 4 records carrying a ctx_id, every record for a session reported the same `port` as that session's authentication START.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here (eAPI and NX-API are plan 3), so L1 is not answered for those transports.
