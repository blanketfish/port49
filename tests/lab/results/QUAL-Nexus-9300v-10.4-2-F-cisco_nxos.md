# QUAL-Nexus-9300v-10.4-2-F — cisco_nxos

- **Date measured:** 2026-10-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-Nexus-9300v-10.4-2-F-cisco_nxos.pcap` — 770 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-Nexus-9300v-10.4-2-F-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `fd181ad5c7c71f21368e37a08d36a1f56274aec4`, `PORT49_LAB_PLATFORMS=nxos`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (1131 bytes of output).
- `command_permitted` (re-measures L10, L21): **pass**. an authorize_command record permits `show version`.
- `command_denied` (re-measures L21): **pass**. `show users` was refused with no_permit_dominates_deny.
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 142ms.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `tacacs-server host 172.100.100.1 key 0 <key> single-connection`.
- `tls_token_login` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_store_unavailable` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_unknown_ca` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)

Evidence: `tests/lab/evidence/QUAL-Nexus-9300v-10.4-2-F-cisco_nxos/` (whitelisted decision records, connection headers and run.json).
