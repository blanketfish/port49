# slice — cisco_nxos

- **Date measured:** 2026-09-24
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/slice-cisco_nxos.pcap` — 320 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/slice-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH, with tokens minted by the broker over a held mTLS connection (`port49 login`, `port49 token`)

## Claim

The vertical slice end to end: an operator's client certificate, validated by the broker against one trust anchor, mints a device token over a held mTLS connection (`port49 login`, `port49 token`); the token logs into the device; every authorization is answered from the compiled blob the mint wrote; and a second `port49 token` mints a fresh token rather than handing back the first.

## Observation

Two `port49 token nx1` calls over one `port49 login` session minted two different tokens for principal `user:alice@slice.port49.test`, username `slice01`, each on its own `mint` record naming blob `sha256:f2ebc5c0e3f768dfa897459337929afe68dfd8b1cb313d1f7bbf4ca641651afe`. The `blob` event carried it:

```json
{"attributes":["shell:roles*network-admin"],"bundle":"sha256:7dab7395f0b92032bb037eda78b4acf24108412deb1ea390657fdd46e094bb0b","classes":{},"normalize":{"expands_abbreviations":true,"pipe_authorized":false,"pipe_token":"|","strip_cr":true},"pipe":["begin **","count","exclude **","include **","json","no-more","section **"],"platform":"cisco_nxos","privilege":"admin","rules":[{"role":"slice_denies","rule":"show hostname","verdict":"deny"},{"role":"slice_denies","rule":"show users","verdict":"deny"},{"role":"network_admin","rule":"**","verdict":"permit"}],"version":2}
```

Every record for `slice01` in the run, in order (tokens appear as the hash the log carries):

| event | verdict | reason | ctx_id | port | credential_sha256 / vector |
|---|---|---|---|---|---|
| redeem | permit | token_redeemed | `2TQL64M4LXQKHIHX` | `0` | `daaa4d72054f…` |
| authorize_session | permit | context_matched | `2TQL64M4LXQKHIHX` | `0` |  |
| authorize_command | permit | permit_dominates | `2TQL64M4LXQKHIHX` | `` | `show version` |
| account |  |  | `2TQL64M4LXQKHIHX` | `0` |  |
| authorize_command | permit | permit_dominates | `2TQL64M4LXQKHIHX` | `` | `end` |
| account |  |  | `2TQL64M4LXQKHIHX` | `0` |  |
| account |  |  | `2TQL64M4LXQKHIHX` | `0` |  |
| authorize_command | deny | no_permit_dominates_deny | `2TQL64M4LXQKHIHX` | `` | `show hostname` |
| authorize_command | permit | permit_dominates | `2TQL64M4LXQKHIHX` | `` | `end` |
| account |  |  | `2TQL64M4LXQKHIHX` | `0` |  |
| redeem | permit | token_redeemed | `2TQL64M4LXQKHIHX` | `0` | `451334e91328…` |
| authorize_session | permit | context_matched | `2TQL64M4LXQKHIHX` | `0` |  |
| account |  |  | `2TQL64M4LXQKHIHX` | `0` |  |
| authorize_command | permit | permit_dominates | `2TQL64M4LXQKHIHX` | `` | `show version` |
| authorize_command | permit | permit_dominates | `2TQL64M4LXQKHIHX` | `` | `end` |
| account |  |  | `2TQL64M4LXQKHIHX` | `0` |  |

Both logins redeemed into ctx_id `2TQL64M4LXQKHIHX`: the second window joined the first's context (spec §5.6).

The device's reply to `show hostname`, which only the blob denies (`tests/lab/slice/policy.yaml`); the decision record's server_msg was `port49: denied by slice_denies (show hostname) - see 'port49 explain'`:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)

Cmd exec error.
```

