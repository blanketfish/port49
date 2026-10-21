# QUAL-XRd-control-plane-26.1.1 — cisco_xrd

- **Date measured:** 2026-10-21
- **Platform:** cisco_xrd (containerlab node `xrd1`, 172.100.100.61)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd.pcap` — 886 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `c756f2ad039e41cb6a9fe47f10f6fed3ba2d29de`, `PORT49_LAB_PLATFORMS=xrd261`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (494 bytes of output).
- `command_permitted` (re-measures L10, L21): **pass**. an authorize_command record permits `show version`.
- `command_denied` (re-measures L21): **pass**. `show users` was refused with no_permit_dominates_deny.
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused, and port49d denied its redeem.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in false after 2.03s.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `tacacs-server host 172.100.100.1 single-connection`, committed; after port49d restarted the device refused 2 login(s) over 21s before it reached port49d (no record of them).
- `tls_token_login` (re-measures L73): **pass**. a token login over RFC 9887, show version, the denied command, and the stop record.
- `tls_store_unavailable` (re-measures L73): **pass**. the token login was refused over TLS; break-glass logged in false after 1.629s.
- `tls_unknown_ca` (re-measures L73): **pass**. the handshake was refused as unknown_ca and no token was redeemed.
- TLS handshake facts: PKI: ecdsa (root, a device intermediate, an untrusted CA); port49d's server certificate subject "CN=port49 L73", issuer "CN=L73 Lab Root", dNSName [tacacs.l73.example], iPAddress [172.100.100.1], EKU [serverAuth], key ECDSA-P-256, valid 2026-10-21T03:26:23Z to 2026-10-22T04:26:23Z; the device's request (`do crypto ca enroll l73-dev`): subject "CN=xrd1,1.2.840.113549.1.9.2=#1314787264312e6c61622e706f727434392e74657374", dNSName [], iPAddress [], email [], key RSA-3072, requested extensions [2.5.29.15 2.5.29.37 2.5.29.19], requested EKU [serverAuth clientAuth]; the lab intermediate issued subject "CN=xrd1", issuer "CN=L73 Lab Device Intermediate", dNSName [xrd1], iPAddress [172.100.100.61], EKU [clientAuth], key RSA-3072, valid 2026-10-21T03:26:41Z to 2026-10-22T04:26:41Z (the request named neither a dNSName nor an iPAddress, so the lab CA added the inventory's)

Evidence: `tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd/` (whitelisted decision records, connection headers and run.json).
