# QUAL-vJunos-router-23.4R2-S2.1 — juniper_vjunos-router

- **Date measured:** 2026-10-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-vJunos-router-23.4R2-S2.1-juniper_vjunos-router.pcap` — 596 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-vJunos-router-23.4R2-S2.1-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `73f7a5df43fd80f66f6d1508c22d4d08bd2798f4`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (6011 bytes of output).
- `command_permitted` (re-measures L10, L21): **not_applicable**. L18: Junos sends no per-command authorization; the deny is enforced by the session reply's deny-commands
- `command_denied` (re-measures L21): **not_applicable**. L18: Junos sends no per-command authorization; the deny is enforced by the session reply's deny-commands
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 30ms.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`.
- `tls_token_login` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_store_unavailable` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)
- `tls_unknown_ca` (re-measures L73): **not_run**. this image carries no RFC 9887 client (L71)

Evidence: `tests/lab/evidence/QUAL-vJunos-router-23.4R2-S2.1-juniper_vjunos-router/` (whitelisted decision records, connection headers and run.json).
