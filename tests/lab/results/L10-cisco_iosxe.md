# L10 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/captures/L10-cisco_iosxe.pcap` — 124 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L10-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`
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
