# QUAL-SR-Linux-26.7.2-519 without a priv-lvl block — nokia_srlinux

- **Date measured:** 2026-10-20
- **Platform:** nokia_srlinux (containerlab node `srl1`, 172.100.100.71)
- **Image version:** SR Linux 26.7.2-519 (`ghcr.io/nokia/srlinux:26.7.2-519`)
- **Topology:** `tests/lab/topologies/srlinux.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux-no-priv-lvl.pcap` — 60 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux-no-priv-lvl.pcap -n | wc -l`; credential bytes overwritten with `x`, everything else byte-identical (`make evidence`).
- **Transport:** SSH
- **Run:** `make lab-qualify P=srlinux` on the branch's tests, with tests/qual/qual-policy.yaml as committed in 2e43cea9 minus its `platforms: nokia_srlinux` block (the block was removed for this run only and restored after it).

## Claim

Whether SR Linux, served by the platform-set 1.3.0 generic adapter (which renders no attribute), logs a person in when port49's session authorization reply carries no `priv-lvl`.

## Observation

`token_login` stopped the run as INVALID: the broker-minted token login failed with `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain`.

port49d's decision records for that login, in order: `blob`, `mint` (permit, grants_matched), `redeem` (permit, token_redeemed, user `qual01`, port `ssh`), `authorize_session` (permit, context_matched). The `authorize_session` record's reply is null: port49 answered permit with no attribute. The device refused the login anyway. With the block in place (priv-lvl=15) the same cell passes (QUAL-SR-Linux-26.7.2-519-nokia_srlinux.md).

This run stopped as INVALID before the harness wrote its evidence, so it wrote no run.json. The record is the pcap and `decisions.jsonl` beside it; the latter was produced afterwards from the run's own daemon log with the harness's `qualRecords`, the same whitelist and gate.

This measures one image and the device configuration of tests/lab/configs/srlinux-startup.cli (`priv-lvl-authorization true`). It does not measure a login with `priv-lvl-authorization false`; that is L76 cell (i): no authorization request is sent at all.
