# L10 — juniper_vsrx

- **Date measured:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/captures/L10-juniper_vsrx.pcap` — 44 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L10-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`
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
