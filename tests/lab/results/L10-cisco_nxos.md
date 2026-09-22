# L10 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L10-cisco_nxos.pcap` — 120 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L10-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter.

## Observation

One SSH login running `show version` produced 3 authorization request(s).

`service` arrived as `shell` (3 requests).

Attribute names seen, exactly as spelled on the wire: `cisco-av-pair`, `cmd`, `cmd-arg`, `service`, `shell:roles`.

Every AV pair, per request:

```
authorize_session (permit/context_matched):
  service=shell
  cmd=
  cisco-av-pair*
  shell:roles*

authorize_command (permit/permit_dominates):
  service=shell
  cmd=show
  cmd-arg=version
  cmd-arg=<cr>

authorize_command (permit/permit_dominates):
  service=shell
  cmd=end
  cmd-arg=<cr>
```

Only this platform's own spellings are measured here; a shipped adapter is `VERIFIED` only for the platform its note names.
