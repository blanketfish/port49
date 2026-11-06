# L10 — arista_eos

- **Date measured:** 2026-11-05
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L10-arista_eos.pcap` — 124 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L10-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `5ed06f5ff587893a8740a7fd30042d3c53eb0bb0`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL10ServiceAndAttributeSpellings$`

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
