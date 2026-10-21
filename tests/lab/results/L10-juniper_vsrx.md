# L10 — juniper_vsrx

- **Date measured:** 2026-10-19
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L10-juniper_vsrx.pcap` — 44 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L10-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `2c680dbfad8fed41de8176383c9e67e2f871d2eb`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL10ServiceAndAttributeSpellings$`

## Claim

Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter.

## Observation

One SSH login running `show version` produced 1 authorization request(s).

`service` arrived as `junos-exec` (1 requests).

Attribute names seen, exactly as spelled on the wire: `service`.

Every AV pair, per request:

```
authorize_session (permit/context_matched):
  service=junos-exec
```

Only this platform's own spellings are measured here; a shipped adapter is `VERIFIED` only for the platform its note names.
