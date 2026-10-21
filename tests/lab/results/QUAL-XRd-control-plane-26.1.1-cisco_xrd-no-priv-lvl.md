# QUAL-XRd-control-plane-26.1.1 without a priv-lvl block — cisco_xrd

- **Date measured:** 2026-10-21
- **Platform:** cisco_xrd (containerlab node `xrd1`, 172.100.100.61)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd-no-priv-lvl.pcap` — 846 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/QUAL-XRd-control-plane-26.1.1-cisco_xrd-no-priv-lvl.pcap -n | wc -l`; credential bytes overwritten with `x`, everything else byte-identical (`make evidence`).
- **Transport:** SSH, then RFC 9887 TLS
- **Run:** `make lab-qualify P=xrd261` on the branch's tests at 0d985aaf, with tests/qual/qual-policy.yaml minus its `platforms: cisco_iosxr` block (removed for this run only and restored after it).

## Claim

What XRd 26.1.1, served by the platform-set 1.3.0 generic adapter (which renders no attribute), does when port49's session authorization reply carries no attribute.

## Observation

The device logs the token user in and then refuses every command locally. The run's printed failures:

- `token_login`: logged in, but `show version` did not run (the first line of its output was `% This command is not authorized`).
- `command_permitted`: `show version` and `show users` each said `% This command is not authorized`; port49d logged no `authorize_command` record for either.
- `single_connection` and `tls_token_login`: no `authorize_command` record at all.

port49d's records for the token login, in order: `redeem` (permit, token_redeemed), `authorize_session` (permit, context_matched) with a null reply, then the `account` records. Across the whole run port49d logged no `authorize_command` record (0), over TCP or TLS. So with an empty reply XR asks port49 about no command, and nothing is allowed: the case fails safe. `accounting`, `wrong_credential`, `store_unavailable`, `tls_store_unavailable` and `tls_unknown_ca` still pass.

With only `priv-lvl=15` rendered (the block in tests/qual/qual-policy.yaml) the same cells all pass, `authorize_command` arrives, and port49d's permit and deny apply: `show version` is permitted and `show users` is denied with `no_permit_dominates_deny` (QUAL-XRd-control-plane-26.1.1-cisco_xrd.md). That run is the only evidence of which attribute made the difference; no other attribute was tried, because `priv-lvl=15` alone was enough.

This measures one image, one level (15) and the startup configuration of tests/lab/configs/xrd-startup.cfg (`aaa authorization exec` and `commands` through group `port49`, local fallback). The levels readonly and operator render `priv-lvl=1` in the qual policy; no run showed what XR does with level 1.

The harness wrote its usual evidence directory for this failing run over the passing run's; the passing run's committed evidence was restored from git, and only this pcap and note are kept from the failing one.
