# L8 — cisco_nxos

- **Date measured:** 2026-11-05
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L8-cisco_nxos.pcap` — 714 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L8-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL8PasswordLength$`

## Claim

The maximum password length each platform accepts at an interactive prompt.

## Observation

Each probe is a password of the given length typed under a username that holds no token, so port49 refuses it `token_not_found` and logs `auth.credential_sha256` — the SHA-256 of exactly the bytes the device sent. "Characters that arrived" is the length of the one prefix of the probe whose hash equals that field; `all N` means the password reached port49 byte for byte. No record at all means the device refused the password locally and sent nothing. The probe is `abcdefghij` repeated and cut to length.

| length | reached port49 | method | characters that arrived | SSH result |
|---|---|---|---|---|
| 30 | yes (2 record(s)) | `pap`, `pap` | all 30, all 30 | rejected |
| 31 | yes (2 record(s)) | `pap`, `pap` | all 31, all 31 | rejected |
| 32 | yes (2 record(s)) | `pap`, `pap` | all 32, all 32 | rejected |
| 63 | yes (2 record(s)) | `pap`, `pap` | all 63, all 63 | rejected |
| 64 | yes (2 record(s)) | `pap`, `pap` | all 64, all 64 | rejected |
| 65 | yes (2 record(s)) | `pap`, `pap` | all 65, all 65 | rejected |
| 127 | yes (2 record(s)) | `pap`, `pap` | all 127, all 127 | rejected |
| 128 | no | — | — | rejected |
| 129 | no | — | — | rejected |
| 138 | no | — | — | rejected |
| 255 | no | — | — | rejected |
| 256 | no | — | — | rejected |
| 257 | no | — | — | rejected |
| 512 | no | — | — | rejected |
| 1024 | no | — | — | rejected |

**Longest password that arrived intact: 127 characters.** 128 characters did not.

### The design's 30-character handle

A token port49d minted for this run (30 characters; not quoted, it is a credential) was typed under `alice01`. port49 answered `permit` `token_redeemed` over `pap`; the credential hash it logged equals the hash of the token; SSH logged in. The 30-character handle on this platform: **works**.

### Every length that did not arrive intact

**Length 128, username `l8len128`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefgh
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**Length 129, username `l8len129`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghi
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**Length 138, username `l8len138`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefgh
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**Length 255, username `l8len255`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcde
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**Length 256, username `l8len256`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdef
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**Length 257, username `l8len257`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefg
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**Length 512, username `l8len512`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijab
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

**Length 1024, username `l8len1024`.** Sent at the SSH password prompt (and again at the keyboard-interactive prompt if the device offered one):

```
abcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcdefghijabcd
```

What port49 received: nothing — no redeem record for this username reached the decision log, so the device never asked.

The device replied:

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

The device's reply to an intact probe, for comparison (length 30, which port49 received and refused):

```
[SSH banner]
User Access Verification
[keyboard-interactive prompt]
name="" instruction="" questions=["Password: "]
[SSH authentication result]
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

The two replies are identical. An operator who types a password of 128 characters or more sees exactly what a wrong password produces, and port49 never hears of the attempt.

### Device log

Read with port49d stopped, over the break-glass account:

```
show logging logfile | include l8len
nx1#
```

The `method` column is what the device chose, not this test: this platform carries a password typed at the interactive SSH prompt to port49 as a PAP START. So the limit above is also this platform's PAP limit **for SSH logins**; whether a PAP client on another path (the console, PPP) is bounded the same way is not measured here.
