# slice — cisco_iosxe

- **Date measured:** 2026-09-24
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/slice-cisco_iosxe.pcap` — 358 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/slice-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH, with tokens minted by the broker over a held mTLS connection (`port49 login`, `port49 token`)

## Claim

The vertical slice end to end: an operator's client certificate, validated by the broker against one trust anchor, mints a device token over a held mTLS connection (`port49 login`, `port49 token`); the token logs into the device; every authorization is answered from the compiled blob the mint wrote; and a second `port49 token` mints a fresh token rather than handing back the first.

## Observation

Two `port49 token xe1` calls over one `port49 login` session minted two different tokens for principal `user:alice@slice.port49.test`, username `slice01`, each on its own `mint` record naming blob `sha256:82009bdced98843da58ebebcc8437e28646463275c901d136e70bb5a5c1b31a6`. The `blob` event carried it:

```json
{"accepted_attributes":["priv-lvl"],"attributes":["priv-lvl=15"],"bundle":"sha256:7dab7395f0b92032bb037eda78b4acf24108412deb1ea390657fdd46e094bb0b","classes":{},"normalize":{"expands_abbreviations":true,"pipe_authorized":false,"pipe_token":"|","splits_interface_names":true,"strip_cr":true},"pipe":["begin **","count","exclude **","include **","json","no-more","section **"],"platform":"cisco_iosxe","privilege":"admin","rules":[{"role":"slice_denies","rule":"show hostname","verdict":"deny"},{"role":"slice_denies","rule":"show users","verdict":"deny"},{"role":"network_admin","rule":"**","verdict":"permit"}],"version":2}
```

Every record for `slice01` in the run, in order (tokens appear as the hash the log carries):

| event | verdict | reason | ctx_id | port | credential_sha256 / vector |
|---|---|---|---|---|---|
| redeem | permit | token_redeemed | `LJD2AYKR277IYM6H` | `tty434` | `a8fba67e33ec…` |
| authorize_session | permit | context_matched | `LJD2AYKR277IYM6H` | `tty434` |  |
| account |  |  | `LJD2AYKR277IYM6H` | `tty434` |  |
| authorize_command | permit | permit_dominates | `LJD2AYKR277IYM6H` | `tty434` | `terminal length 0` |
| account |  |  | `LJD2AYKR277IYM6H` | `tty434` |  |
| authorize_command | permit | permit_dominates | `LJD2AYKR277IYM6H` | `tty434` | `show version` |
| account |  |  | `LJD2AYKR277IYM6H` | `tty434` |  |
| authorize_command | deny | no_permit_dominates_deny | `LJD2AYKR277IYM6H` | `tty434` | `show users` |
| account |  |  | `LJD2AYKR277IYM6H` | `tty434` |  |
| redeem | permit | token_redeemed | `LJD2AYKR277IYM6H` | `tty435` | `42bab6522221…` |
| authorize_session | permit | context_matched | `LJD2AYKR277IYM6H` | `tty435` |  |
| account |  |  | `LJD2AYKR277IYM6H` | `tty435` |  |
| authorize_command | permit | permit_dominates | `LJD2AYKR277IYM6H` | `tty435` | `terminal length 0` |
| account |  |  | `LJD2AYKR277IYM6H` | `tty435` |  |
| authorize_command | permit | permit_dominates | `LJD2AYKR277IYM6H` | `tty435` | `show version` |
| account |  |  | `LJD2AYKR277IYM6H` | `tty435` |  |

Both logins redeemed into ctx_id `LJD2AYKR277IYM6H`: the second window joined the first's context (spec §5.6).

The device's reply to `show users`, which only the blob denies (`tests/lab/slice/policy.yaml`); the decision record's server_msg was `port49: denied by slice_denies (show users) - see 'port49 explain'`:

```
port49: denied by slice_denies (show users) - see 'port49 explain'
```

