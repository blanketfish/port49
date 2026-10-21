# L80 — cisco_nxos

- **Date measured:** 2026-10-21
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.6(2)F (`vrnetlab/cisco_n9kv:9300v64-10.6.2.F`)
- **Topology:** `tests/lab/topologies/nxos106.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos.pcap` — 1196 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `069d98f9c24de2a49439143a16608c263e2550d5`, `PORT49_LAB_PLATFORMS=nxos106`, `-run ^TestQualify$`

## Claim

Whether a command port49's policy denies runs over per-request TLS (RFC 9887 with no single-connection, the device default) when the device sends port49 no command authorization (policy engine spec §15 L80), measured by TestQualify's `tls_denied_command` cell under tests/qual/qual-policy.yaml: one login typing only the denied command, graded from its first output line and port49's records.

## Observation

- `tls_token_login` (re-measures L73): **pass**. per-request (the device default): login only: a token login over RFC 9887 and its stop record arrived; command authorization not sent: port49 received no authorize_command for `show version` or `show users` (a device fact, as L73 cell a; not a pass for command authorization over TLS); `show version` said "Cisco Nexus Operating System (NX-OS) Software"; `show users` said "NAME LINE TIME IDLE PID COMMENT".
- `tls_denied_command` (re-measures L80): **observed**. per-request (the device default): **denied command ran; port49 never asked (the device's local method, presumed)**: `show users` ran with no authorization request for it reaching port49, so the qual policy's deny was not enforced over per-request TLS (first line "NAME LINE TIME IDLE PID COMMENT"; 0 authorize_command records for `show users`, 1 for other commands).

Evidence: `tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos/` (the cells' whitelisted records in decisions.jsonl; the denied-command login's connections in tls_denied_command.tls.json).
