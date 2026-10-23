# L80 — cisco_nxos

- **Date measured:** 2026-10-22
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.6(2)F (`vrnetlab/cisco_n9kv:9300v64-10.6.2.F`)
- **Topology:** `tests/lab/topologies/nxos106.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos.pcap` — 1230 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `5f9a2d84c6da759100dc05a7222e8e3309201e2d`, `PORT49_LAB_PLATFORMS=nxos106`, `-run ^TestQualify$`

## Claim

Whether a command port49's policy denies runs on NX-OS 10.6 over per-request TLS (RFC 9887) when port49 offers the device single-connect (policy engine spec §15 L80; decision 50 ruling 20), measured by TestQualify's `tls_token_login` cell under tests/qual/qual-policy.yaml: a login typing `show version` and the denied command, graded from port49's authorize_command records.

## Observation

- `tls_token_login` (re-measures L73): **pass**. per-request (the device default): a token login over RFC 9887; `show version` permitted and `show users` denied by port49 (authorize_command records); the stop record arrived.
- `tls_denied_command` (re-measures L80): **not_run**. per-request TLS sent port49 command authorization (tls_token_login), so port49 decided the denied command there

Evidence: `tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos/` (the cells' whitelisted records in decisions.jsonl; the login's connections in tls_token_login.tls.json). Before the fix the device sent command authorization for some commands only, so commands ran with no authorize_command record (the baseline evidence below); with the offer it asks about every command and port49's deny holds (this cell, and the fixed arm below).

Under spec §13 decision 50 ruling 20 this build offers the device single-connect over per-request TLS (platform.TLSServerSingleConnect), so a request NX-OS writes behind an accounting record is read and decided on the same connection. The before-the-fix evidence, the same sequences on the build before the fix, is committed under `tests/lab/evidence/L80-cisco_nxos/baseline/` (make lab-l80 ARM=baseline); the fixed arm's idle-boundary and concurrent-sessions cells beside it, under `tests/lab/evidence/L80-cisco_nxos/fixed/` (make lab-l80 ARM=fixed).
