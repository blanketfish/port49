# QUAL-vSRX3-21.4R3.15 — juniper_vsrx

- **Date measured:** 2026-10-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-vSRX3-21.4R3.15-juniper_vsrx.pcap` — 916 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-vSRX3-21.4R3.15-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `aafd557bb282ab795410db970b71e9075d33a4d1`, `PORT49_LAB_PLATFORMS=vsrx`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (2912 bytes of output).
- `command_permitted` (re-measures L10, L21): **not_applicable**. L18: Junos sends no per-command authorization; the deny is enforced by the session reply's deny-commands
- `command_denied` (re-measures L21): **not_applicable**. L18: Junos sends no per-command authorization; the deny is enforced by the session reply's deny-commands
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 17ms.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`.
- `tls_token_login` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_store_unavailable` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_unknown_ca` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)

Evidence: `tests/lab/evidence/QUAL-vSRX3-21.4R3.15-juniper_vsrx/` (whitelisted decision records, connection headers and run.json).
