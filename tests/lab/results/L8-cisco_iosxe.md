# L8 — cisco_iosxe

- **Date measured:** 2026-11-05
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L8-cisco_iosxe.pcap` — 968 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L8-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL8PasswordLength$`

## Claim

The maximum password length each platform accepts at an interactive prompt.

## Observation

Each probe is a password of the given length typed under a username that holds no token, so port49 refuses it `token_not_found` and logs `auth.credential_sha256` — the SHA-256 of exactly the bytes the device sent. "Characters that arrived" is the length of the one prefix of the probe whose hash equals that field; `all N` means the password reached port49 byte for byte. No record at all means the device refused the password locally and sent nothing. The probe is `abcdefghij` repeated and cut to length.

| length | reached port49 | method | characters that arrived | SSH result |
|---|---|---|---|---|
| 30 | yes (2 record(s)) | `ascii`, `ascii` | all 30, all 30 | rejected |
| 31 | yes (2 record(s)) | `ascii`, `ascii` | all 31, all 31 | rejected |
| 32 | yes (2 record(s)) | `ascii`, `ascii` | all 32, all 32 | rejected |
| 63 | yes (2 record(s)) | `ascii`, `ascii` | all 63, all 63 | rejected |
| 64 | yes (2 record(s)) | `ascii`, `ascii` | all 64, all 64 | rejected |
| 65 | yes (2 record(s)) | `ascii`, `ascii` | all 65, all 65 | rejected |
| 127 | yes (2 record(s)) | `ascii`, `ascii` | all 127, all 127 | rejected |
| 128 | yes (2 record(s)) | `ascii`, `ascii` | all 128, all 128 | rejected |
| 129 | yes (2 record(s)) | `ascii`, `ascii` | all 129, all 129 | rejected |
| 138 | yes (2 record(s)) | `ascii`, `ascii` | all 138, all 138 | rejected |
| 255 | yes (2 record(s)) | `ascii`, `ascii` | all 255, all 255 | rejected |
| 256 | yes (2 record(s)) | `ascii`, `ascii` | all 256, all 256 | rejected |
| 257 | yes (2 record(s)) | `ascii`, `ascii` | all 257, all 257 | rejected |
| 512 | yes (2 record(s)) | `ascii`, `ascii` | all 512, all 512 | rejected |
| 1024 | yes (2 record(s)) | `ascii`, `ascii` | all 1024, all 1024 | rejected |

**Every length tried arrived intact, up to 1024 characters; no limit was found below that.**

### The design's 30-character handle

A token port49d minted for this run (30 characters; not quoted, it is a credential) was typed under `alice01`. port49 answered `permit` `token_redeemed` over `ascii`; the credential hash it logged equals the hash of the token; SSH logged in. The 30-character handle on this platform: **works**.

### Every length that did not arrive intact

None: every length tried arrived intact.

The device's reply to an intact probe, for comparison (length 30, which port49 received and refused):

```
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[keyboard-interactive prompt]
name="" instruction="port49: authentication failed, mint a new token with `port49 token`" questions=[]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

### Device log

Read with port49d stopped, over the break-glass account:

```
show logging | include l8len
xe1#
```

The `method` column is what the device chose, not this test. No exchange from this platform arrived as PAP, so this note says nothing about a PAP limit; it measures the interactive SSH prompt only.
