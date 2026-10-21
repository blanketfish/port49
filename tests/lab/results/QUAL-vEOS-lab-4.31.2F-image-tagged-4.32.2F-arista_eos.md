# QUAL-vEOS-lab-4.31.2F-image-tagged-4.32.2F — arista_eos

- **Date measured:** 2026-10-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-vEOS-lab-4.31.2F-image-tagged-4.32.2F-arista_eos.pcap` — 722 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-vEOS-lab-4.31.2F-image-tagged-4.32.2F-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a6ac502fd078e3e44cf3d374997a2b460048ab4b`, `PORT49_LAB_PLATFORMS=eos`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (399 bytes of output).
- `command_permitted` (re-measures L10, L21): **pass**. an authorize_command record permits `show version`.
- `command_denied` (re-measures L21): **pass**. `show users` was refused with no_permit_dominates_deny.
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 30ms.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `tacacs-server host 172.100.100.1 single-connection`.
- `tls_token_login` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_store_unavailable` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_unknown_ca` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)

Evidence: `tests/lab/evidence/QUAL-vEOS-lab-4.31.2F-image-tagged-4.32.2F-arista_eos/` (whitelisted decision records, connection headers and run.json).
