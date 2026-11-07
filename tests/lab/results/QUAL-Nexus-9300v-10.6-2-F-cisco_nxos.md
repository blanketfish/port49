# QUAL-Nexus-9300v-10.6-2-F — cisco_nxos

- **Date measured:** 2026-11-07
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.6(2)F (`vrnetlab/cisco_n9kv:9300v64-10.6.2.F`)
- **Topology:** `tests/lab/topologies/nxos106.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos.pcap` — 1201 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `8c93afade21ffa7250e59ecedbb271157fb28bc9-dirty`, `PORT49_LAB_PLATFORMS=nxos106`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (1115 bytes of output).
- `command_permitted` (re-measures L10, L21): **pass**. an authorize_command record permits `show version`.
- `command_denied` (re-measures L21): **pass**. `show users` was refused with no_permit_dominates_deny.
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused, and port49d denied its redeem.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 157ms.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `tacacs-server host 172.100.100.1 key 0 <key> single-connection`.
- `tls_token_login` (re-measures L73): **pass**. per-request (the device default): a token login over RFC 9887; `show version` permitted and `show users` denied by port49 (authorize_command records); the stop record arrived.
- `tls_denied_command` (re-measures L80): **not_run**. per-request TLS sent port49 command authorization (tls_token_login), so port49 decided the denied command there
- `tls_store_unavailable` (re-measures L73): **pass**. the token login was refused over TLS; break-glass logged in true after 8.188s.
- `tls_unknown_ca` (re-measures L73): **pass**. the handshake was refused as unknown_ca and no token was redeemed.
- `tls_single_connection` (re-measures L15, L73): **pass**. single-connection on: a token login over RFC 9887; `show version` permitted and `show users` denied by port49 (authorize_command records); the stop record arrived.
- TLS handshake facts: PKI: ecdsa (root, a device intermediate, an untrusted CA); port49d's server certificate subject "CN=port49 L73", issuer "CN=L73 Lab Root", dNSName [tacacs.l73.example], iPAddress [172.100.100.1], EKU [serverAuth], key ECDSA-P-256, valid 2026-11-07T09:21:07Z to 2026-11-08T10:21:07Z; the device's request (`crypto ca enroll l73-dev`): subject "CN=nx1", dNSName [nx1], iPAddress [172.100.100.31], email [], key RSA-2048, requested extensions [2.5.29.17], requested EKU []; the lab intermediate issued subject "CN=nx1", issuer "CN=L73 Lab Device Intermediate", dNSName [nx1], iPAddress [172.100.100.31], EKU [clientAuth], key RSA-2048, valid 2026-11-07T09:21:20Z to 2026-11-08T10:21:20Z

Evidence: `tests/lab/evidence/QUAL-Nexus-9300v-10.6-2-F-cisco_nxos/` (whitelisted decision records, connection headers and run.json).
