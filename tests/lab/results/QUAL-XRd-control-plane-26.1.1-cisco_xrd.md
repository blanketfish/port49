# QUAL-XRd-control-plane-26.1.1 — cisco_xrd

- **Date measured:** 2026-10-23
- **Platform:** cisco_xrd (containerlab node `xrd1`, 172.100.100.61)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd.pcap` — 929 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `e2b618f6422b6e48175ebcaac685205f664be9c8`, `PORT49_LAB_PLATFORMS=xrd261`, `-run ^TestQualify$`

## Claim

The conformance cells of plan 11b under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with tokens the broker minted. Each cell re-measures the register rows it cites and closes none.

## Observation

Every cell's verdict, with the rows it re-measures:

- `token_login` (re-measures L1, L15, L19): **pass**. a broker-minted token logged in over SSH and ran `show version` (494 bytes of output).
- `command_permitted` (re-measures L10, L21): **pass**. an authorize_command record permits `show version`.
- `command_denied` (re-measures L21): **pass**. `show users` was refused with no_permit_dominates_deny.
- `accounting` (re-measures L6): **pass**. the login's start and stop records arrived.
- `wrong_credential` (re-measures L13): **pass**. a random string as password was refused, and port49d denied its redeem.
- `store_unavailable` (re-measures L4, L28): **pass**. the token login was refused; break-glass logged in false after 2.036s.
- `single_connection` (re-measures L15, L73): **pass**. single-connection on: on: `tacacs-server host 172.100.100.1 single-connection`, committed; after port49d restarted the device refused 2 login(s) over 21s before it reached port49d (no record of them).
- `tls_token_login` (re-measures L73): **pass**. per-request (the device default): a token login over RFC 9887; `show version` permitted and `show users` denied by port49 (authorize_command records); the stop record arrived.
- `tls_denied_command` (re-measures L80): **not_run**. per-request TLS sent port49 command authorization (tls_token_login), so port49 decided the denied command there
- `tls_store_unavailable` (re-measures L73): **pass**. the token login was refused over TLS; break-glass logged in false after 1.641s.
- `tls_unknown_ca` (re-measures L73): **pass**. the handshake was refused as unknown_ca and no token was redeemed.
- `tls_single_connection` (re-measures L15, L73): **pass**. single-connection on: a token login over RFC 9887; `show version` permitted and `show users` denied by port49 (authorize_command records); the stop record arrived.
- TLS handshake facts: operator fact (XR, seen during development, not measured by a committed run): `crypto ca enroll` fails with "Failed to enroll: ... Domain name is not configured" until `domain name` is configured, so tests/lab/configs/xrd-startup.cfg sets one; the committed help for `domain name` is in evidence/L73-cisco_xrd/l71-probe.txt; operator fact (XR, seen during development, not measured by a committed run): a commit that removes a group member, removes and re-adds the host and moves its port fails with "Cannot delete this server as it is still referenced in one of the server groups and is the only server with the given IP address" (read with `show configuration failed`), so the member is removed in its own commit first; PKI: ecdsa (root, a device intermediate, an untrusted CA); port49d's server certificate subject "CN=port49 L73", issuer "CN=L73 Lab Root", dNSName [tacacs.l73.example], iPAddress [172.100.100.1], EKU [serverAuth], key ECDSA-P-256, valid 2026-10-23T02:21:15Z to 2026-10-24T03:21:15Z; the device's request (`do crypto ca enroll l73-dev`): subject "CN=xrd1,1.2.840.113549.1.9.2=#1314787264312e6c61622e706f727434392e74657374", dNSName [], iPAddress [], email [], key RSA-3072, requested extensions [2.5.29.15 2.5.29.37 2.5.29.19], requested EKU [serverAuth clientAuth]; the lab intermediate issued subject "CN=xrd1", issuer "CN=L73 Lab Device Intermediate", dNSName [xrd1], iPAddress [172.100.100.61], EKU [clientAuth], key RSA-3072, valid 2026-10-23T02:21:39Z to 2026-10-24T03:21:39Z (the request named neither a dNSName nor an iPAddress, so the lab CA added the inventory's)

## Operator requirements on XR

- **port49 must render priv-lvl.** This run passes with `platforms: cisco_iosxr` in tests/qual/qual-policy.yaml, which renders `priv-lvl=15` for the admin role. Without it (platform_set 1.3.0 has no cisco_iosxr adapter, so the generic adapter renders no attribute) XRd logs the token user in and then refuses every command locally with `% This command is not authorized`, asking port49 about none (QUAL-XRd-control-plane-26.1.1-cisco_xrd-no-priv-lvl.md). That case fails safe: commands are refused, not allowed. `priv-lvl=15` alone was enough; no other attribute was tried. Add to the policy file:

```yaml
platforms:
  cisco_iosxr:
    privilege:
      readonly: ["priv-lvl=1"]
      operator: ["priv-lvl=1"]
      admin: ["priv-lvl=15"]
```

- **Command authorization must be configured on the device**: `aaa authorization commands default group <port49 group> local`, as tests/lab/configs/xrd-startup.cfg has it. Without that line XR never asks port49 about a command, so no role rule applies and `priv-lvl` is the only bound (admin's 15 is whatever XR grants level 15, unmeasured).
- **Only level 15 was shown.** Level 1 (readonly, operator) was not measured. That it grants no more than the role says is reasoning, not measurement, and holds only with command authorization configured: XR then either refuses locally (fails safe) or asks port49, whose role bounds the command.
- **Break-glass fails when port49 answers ERROR** (its store is unavailable), over TCP and TLS: the cells `store_unavailable` and `tls_store_unavailable` record break-glass logged in false (L73 cell i: ok false in 860 ms), as on IOS XE 17.18.02. With the store down nobody logs in to this device by SSH; keep a path that does not depend on port49 answering.
- In this run `command_denied` passes through port49: `show users` has an authorize_command record denied with no_permit_dominates_deny.


Evidence: `tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd/` (whitelisted decision records, connection headers and run.json).
