# QUAL-SR-Linux-26.7.2-519 — nokia_srlinux

- **Date measured:** 2026-10-20
- **Platform:** nokia_srlinux (containerlab node `srl1`, 172.100.100.71)
- **Image version:** SR Linux 26.7.2-519 (`ghcr.io/nokia/srlinux:26.7.2-519`)
- **Topology:** `tests/lab/topologies/srlinux.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux.pcap` — 304 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `85e6ecdd0fb3a8d6f3dd1366695e43c04a9abd5f`, `PORT49_LAB_PLATFORMS=srlinux`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (832 bytes of output).
- `command_permitted` (re-measures L10, L21): **not_applicable**. L76: SR Linux sends no per-command authorization; the session reply's role bounds the session
- `command_denied` (re-measures L21): **not_applicable**. L76: SR Linux sends no per-command authorization; the session reply's role bounds the session
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 61ms.
- `single_connection` (re-measures L15, L73): **not_run**. the image's `?` offers no single-connection form
- `tls_token_login` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_store_unavailable` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_unknown_ca` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)

Authorization on this platform. platform_set 1.3.0 ships no `nokia_srlinux` adapter (nor one for `cisco_iosxr`), so port49 serves it with the generic adapter, which renders no attribute. SR Linux then refuses every login: the same cell, run without the block below, ended with the device refusing the SSH login after port49 permitted the session with no attribute (`tests/lab/results/QUAL-SR-Linux-26.7.2-519-nokia_srlinux-no-priv-lvl.md`). An operator must therefore add this to the policy file, which the spec lets an operator define without any upstream change (§8, `platforms:`); L76 cells (a) and (h) measured the device's reading of `priv-lvl` 15 and 1 as p49-admin and p49-read:

```yaml
platforms:
  nokia_srlinux:
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=15"]
      admin:    ["priv-lvl=15"]
```

This suite's tests/qual/qual-policy.yaml carries exactly that block, so the golden's authorization (`priv-lvl=15`) is its output, not an adapter's. The device must also run `priv-lvl-authorization true` (as tests/lab/configs/srlinux-startup.cli sets it). Its default is false, and then port49 is never asked to authorize: L76 cell (i) measured 0 authorization requests and an empty Role column, and the YANG (srl_nokia-aaa.yang:254) says authorization is skipped, which is full admin access (YANG-stated, not measured). Port49 command rules (permit and deny lists) are never consulted for SR Linux, because the device sends no per-command authorization (L76 cell b); the session's role, chosen by `priv-lvl`, is the only bound.

Evidence: `tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux/` (whitelisted decision records, connection headers and run.json).
