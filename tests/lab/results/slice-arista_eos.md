# slice — arista_eos

- **Date measured:** 2026-09-23
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/slice-arista_eos.pcap` — 288 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/slice-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH, with tokens minted by the broker over a held mTLS connection (`port49 login`, `port49 token`)

## Claim

The vertical slice end to end: an operator's client certificate, validated by the broker against one trust anchor, mints a device token over a held mTLS connection (`port49 login`, `port49 token`); the token logs into the device; every authorization is answered from the compiled blob the mint wrote; and a second `port49 token` mints a fresh token rather than handing back the first.

## Observation

Two `port49 token leaf1` calls over one `port49 login` session minted two different tokens for principal `user:alice@slice.port49.test`, username `slice01`, each on its own `mint` record naming blob `sha256:0a2f7063497603e199be3811160b65d706ac85aa115aa09a38d9db1df3433fd5`. The `blob` event carried it:

```json
{"attributes":["priv-lvl=15"],"deny":["show hostname"],"permit":["**"],"platform":"arista_eos","privilege":15}
```

Every record for `slice01` in the run, in order (tokens appear as the hash the log carries):

| event | verdict | reason | ctx_id | port | credential_sha256 / vector |
|---|---|---|---|---|---|
| redeem | permit | token_redeemed | `AYYDCHWLFO42ILQR` | `ssh` | `afd34242d710…` |
| account |  |  | `AYYDCHWLFO42ILQR` | `ssh` |  |
| authorize_session | permit | context_matched | `AYYDCHWLFO42ILQR` | `ssh` |  |
| authorize_command | permit | permit_dominates | `AYYDCHWLFO42ILQR` | `ssh` | `show version` |
| account |  |  | `AYYDCHWLFO42ILQR` | `ssh` |  |
| authorize_session | permit | context_matched | `AYYDCHWLFO42ILQR` | `ssh` |  |
| authorize_command | deny | no_permit_dominates_deny | `AYYDCHWLFO42ILQR` | `ssh` | `show hostname` |
| account |  |  | `AYYDCHWLFO42ILQR` | `ssh` |  |
| redeem | permit | token_redeemed | `AYYDCHWLFO42ILQR` | `ssh` | `fce133545f57…` |
| account |  |  | `AYYDCHWLFO42ILQR` | `ssh` |  |
| authorize_session | permit | context_matched | `AYYDCHWLFO42ILQR` | `ssh` |  |
| authorize_command | permit | permit_dominates | `AYYDCHWLFO42ILQR` | `ssh` | `show version` |
| account |  |  | `AYYDCHWLFO42ILQR` | `ssh` |  |

Both logins redeemed into ctx_id `AYYDCHWLFO42ILQR`: the second window joined the first's context (spec §5.6).

The device's reply to `show hostname`, which only the blob denies (`tests/lab/slice/policy.yaml`); the decision record's server_msg was `port49: denied by policy; see 'port49 explain'`:

```
> show hostname
% Authorization denied for command 'show hostname': port49: denied by policy; see 'port49 explain' at line 1
```

