# L10 — juniper_vjunos-router

- **Date measured:** 2026-09-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/captures/L10-juniper_vjunos-router.pcap` — 44 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L10-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter.

## Observation

One SSH login running `show version` produced 1 authorization request(s).

`service` arrived as `junos-exec` (1 requests).

Attribute names seen, exactly as spelled on the wire: `service`.

Every AV pair, per request:

```
authorize_session (deny/service_unsupported):
  service=junos-exec
```

Only this platform's own spellings are measured here; a shipped adapter is `VERIFIED` only for the platform its note names.
