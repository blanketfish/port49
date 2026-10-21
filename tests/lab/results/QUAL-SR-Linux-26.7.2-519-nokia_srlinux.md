# QUAL-SR-Linux-26.7.2-519 — nokia_srlinux

- **Date measured:** 2026-10-21
- **Platform:** nokia_srlinux (containerlab node `srl1`, 172.100.100.71)
- **Image version:** SR Linux 26.7.2-519 (`ghcr.io/nokia/srlinux:26.7.2-519`)
- **Topology:** `tests/lab/topologies/srlinux.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux.pcap` — 302 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `ae02c4babfd208586f8d8c58819ba5d1434b9787`, `PORT49_LAB_PLATFORMS=srlinux`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (832 bytes of output).
- `command_permitted` (re-measures L10, L21): **not_applicable**. L76: SR Linux sends no per-command authorization; the session reply's role bounds the session
- `command_denied` (re-measures L21): **not_applicable**. L76: SR Linux sends no per-command authorization; the session reply's role bounds the session
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused, and port49d denied its redeem.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 56ms.
- `single_connection` (re-measures L15, L73): **not_run**. the image's `?` offers no single-connection form
- `tls_token_login` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_denied_command` (re-measures L80): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_store_unavailable` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_unknown_ca` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_single_connection` (re-measures L15, L73): **not_run**. this image carries no RFC 9887 client (L71)

## Operator requirements on SR Linux

- **port49 must render priv-lvl.** platform_set 1.3.0 has no `nokia_srlinux` adapter, so the generic adapter serves it and renders no attribute, and SR Linux then refuses every login: port49 permits the session and the device refuses the SSH login (QUAL-SR-Linux-26.7.2-519-nokia_srlinux-no-priv-lvl.md). This run passes with `platforms: nokia_srlinux` in tests/qual/qual-policy.yaml; L76 cells (a) and (h) measured the device reading `priv-lvl` 15 and 1 as p49-admin and p49-read. Add to the policy file:

```yaml
platforms:
  nokia_srlinux:
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
```

- **operator is read-only on SR Linux until a level between 1 and 15 is measured.** Port49 command permit and deny rules never apply on SR Linux, because the device sends no per-command authorization (L76 cell b): the session role, chosen by `priv-lvl`, is the only bound. At 15 an operator would be device admin with nothing to narrow it, so operator renders level 1 (p49-read), as readonly does.
- **Set `priv-lvl-authorization true` on the device.** Its default is false, and then port49 is never asked to authorize (L76 cell i: 0 authorization requests); the YANG says the session then gets full admin access (srl_nokia-aaa.yang:254; YANG-stated, not measured).


Evidence: `tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux/` (whitelisted decision records, connection headers and run.json).
