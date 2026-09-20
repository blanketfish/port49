# L10 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L10-arista_eos.pcap` — 124 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L10-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter.

## Observation

One SSH login running `show version` produced 2 authorization request(s).

`service` arrived as `shell` (2 requests).

Attribute names seen, exactly as spelled on the wire: `cmd`, `cmd-arg`, `service`.

Every AV pair, per request:

```
authorize_session (permit/context_matched):
  service=shell
  cmd*

authorize_command (permit/permit_dominates):
  service=shell
  cmd=show
  cmd-arg=version
  cmd-arg=<cr>
```

Only this platform's own spellings are measured here; a shipped adapter is `VERIFIED` only for the platform its note names.
