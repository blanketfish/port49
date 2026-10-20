# QUAL-cEOS-lab-4.36.3M — arista_ceos

- **Date measured:** 2026-10-20
- **Platform:** arista_ceos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** cEOS-lab 4.36.3M (`ceos:4.36.3M`)
- **Topology:** `tests/lab/topologies/ceos436.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-cEOS-lab-4.36.3M-arista_ceos.pcap` — 1221 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-cEOS-lab-4.36.3M-arista_ceos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `3f4ecc03c96db750652ab1a5157e7ee5c64f2391`, `PORT49_LAB_PLATFORMS=ceos436`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (502 bytes of output).
- `command_permitted` (re-measures L10, L21): **pass**. an authorize_command record permits `show version`.
- `command_denied` (re-measures L21): **pass**. `show users` was refused with no_permit_dominates_deny.
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in true after 2.7s.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `tacacs-server host 172.100.100.1 single-connection`.
- `tls_token_login` (re-measures L73): **pass**. a token login over RFC 9887, show version, the denied command, and the stop record.
- `tls_store_unavailable` (re-measures L73): **pass**. the token login was refused over TLS; break-glass logged in true after 2.7s.
- `tls_unknown_ca` (re-measures L73): **pass**. the handshake was refused as unknown_ca and no token was redeemed.
- TLS handshake facts: PKI: ecdsa (root, a device intermediate, an untrusted CA); port49d's server certificate subject "CN=port49 L73", issuer "CN=L73 Lab Root", dNSName [tacacs.l73.example], iPAddress [172.100.100.1], EKU [serverAuth], key ECDSA-P-256, valid 2026-10-20T19:30:30Z to 2026-10-21T20:30:30Z; the device's request (`security pki certificate generate signing-request key l73-dev.key parameters common-name leaf1`): subject "CN=leaf1", dNSName [], iPAddress [], email [], key RSA-2048, requested extensions [], requested EKU []; the lab intermediate issued subject "CN=leaf1", issuer "CN=L73 Lab Device Intermediate", dNSName [leaf1], iPAddress [172.100.100.11], EKU [clientAuth], key RSA-2048, valid 2026-10-20T19:30:35Z to 2026-10-21T20:30:35Z (the request named neither a dNSName nor an iPAddress, so the lab CA added the inventory's)

Evidence: `tests/lab/evidence/QUAL-cEOS-lab-4.36.3M-arista_ceos/` (whitelisted decision records, connection headers and run.json).
