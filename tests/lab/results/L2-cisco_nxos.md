# L2 — cisco_nxos

- **Date measured:** 2026-10-01
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Image ID:** `sha256:d8297de1c034164cc3d9ceaee7b1352153302b0b60dbbeefdbdddc4fa62fb9cb`
- **Run:** at commit 4bd3100, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=nxos go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L2-cisco_nxos.pcap` — 995 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L2-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates.

## Observation

Each length on a port49d of its own, started on the standing lab config with `lab.deny_message_length: N`. A seeded login typed `show clock`, which the lab denies. The message is `port49: denied by lab_deny (show clock); see 'port49 explain'`, a space, and `0123456789` repeated to N bytes, so the last digit shown says where the device cut.

| N (bytes) | The record | Longest prefix shown | Where it ends, and what follows | What the device printed |
|---|---|---|---|---|
| 64 | authorize_command deny, 64-byte server_msg | 0 | — | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| 128 | authorize_command deny, 128-byte server_msg | 0 | — | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| 200 | authorize_command deny, 200-byte server_msg | 0 | — | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| 255 | authorize_command deny, 255-byte server_msg | 0 | — | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| 256 | authorize_command deny, 256-byte server_msg | 0 | — | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| 512 | authorize_command deny, 512-byte server_msg | 0 | — | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| 1000 | authorize_command deny, 1000-byte server_msg | 0 | — | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |

**Not displayed** at any length: the device printed no 16-byte prefix of the message, so its truncation length cannot be read.

### Output modifiers (the earlier note's "Truncation length", kept)

Not measured, and the reason is itself an observation. The operator typed a 171-character line, but the device did not send that line for authorization, so port49 never built a long `server_msg` to truncate. What the device actually asked port49 to authorize:

```
"show clock"
"end"
```

The device printed:

```
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)

Cmd exec error.
```

port49d, port49 and port49-inventory built from `4bd3100` (`make build`).

