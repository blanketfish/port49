# QUAL-Catalyst-8000V-17.18.02 — cisco_iosxe

- **Date measured:** 2026-10-22
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.18.02 (`vrnetlab/cisco_c8000v:17.18.02`)
- **Topology:** `tests/lab/topologies/iosxe1718.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-Catalyst-8000V-17.18.02-cisco_iosxe.pcap` — 1176 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-Catalyst-8000V-17.18.02-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `3b0983b5e8ca8786332d445e6f9caf768f9aceeb`, `PORT49_LAB_PLATFORMS=iosxe1718`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (2522 bytes of output).
- `command_permitted` (re-measures L10, L21): **pass**. an authorize_command record permits `show version`.
- `command_denied` (re-measures L21): **pass**. `show users` was refused with no_permit_dominates_deny.
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused, and port49d denied its redeem.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in false after 4.025s.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `single-connection` under `tacacs server port49-host`.
- `tls_token_login` (re-measures L73): **pass**. per-request (the device default): a token login over RFC 9887; `show version` permitted and `show users` denied by port49 (authorize_command records); the stop record arrived.
- `tls_denied_command` (re-measures L80): **not_run**. per-request TLS sent port49 command authorization (tls_token_login), so port49 decided the denied command there
- `tls_store_unavailable` (re-measures L73): **pass**. the token login was refused over TLS; break-glass logged in false after 4.071s.
- `tls_unknown_ca` (re-measures L73): **pass**. the handshake was refused as unknown_ca and no token was redeemed.
- `tls_single_connection` (re-measures L15, L73): **pass**. single-connection on: a token login over RFC 9887; `show version` permitted and `show users` denied by port49 (authorize_command records); the stop record arrived.
- TLS handshake facts: PKI: ecdsa (root, a device intermediate, an untrusted CA); port49d's server certificate subject "CN=port49 L73", issuer "CN=L73 Lab Root", dNSName [tacacs.l73.example], iPAddress [172.100.100.1], EKU [serverAuth], key ECDSA-P-256, valid 2026-10-22T17:07:21Z to 2026-10-23T18:07:21Z; the device's request (`crypto pki enroll l73-dev`): subject "CN=xe1,1.2.840.113549.1.9.2=#130f7865312e6578616d706c652e636f6d", dNSName [], iPAddress [], email [], key ECDSA-P-256, requested extensions [2.5.29.15], requested EKU []; the lab intermediate issued subject "CN=xe1", issuer "CN=L73 Lab Device Intermediate", dNSName [xe1], iPAddress [172.100.100.41], EKU [clientAuth], key ECDSA-P-256, valid 2026-10-22T17:07:44Z to 2026-10-23T18:07:44Z (the request named neither a dNSName nor an iPAddress, so the lab CA added the inventory's); IOS XE `show running-config | section tacacs`, typed right after the `address ipv4` line of server object 1, with port49-host already removed: `aaa group server tacacs+ port49 /  ip vrf forwarding clab-mgmt /  ip tacacs source-interface GigabitEthernet1 / tacacs server l73-tls /  address ipv4 172.100.100.1`; with port49-host removed from the device, a break-glass login ok false in 5.588s ()

Evidence: `tests/lab/evidence/QUAL-Catalyst-8000V-17.18.02-cisco_iosxe/` (whitelisted decision records, connection headers and run.json).
