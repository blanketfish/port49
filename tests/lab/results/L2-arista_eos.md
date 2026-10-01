# L2 — arista_eos

- **Date measured:** 2026-10-01
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Image ID:** `sha256:8ef33020ece8871b19ddfdddf7f3585b04d2ac3672845b0db88debe8e96ff9c9`
- **Run:** at commit ec50053, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L2-arista_eos.pcap` — 1006 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L2-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates.

## Observation

Each length on a port49d of its own, started on the standing lab config with `lab.deny_message_length: N`. A seeded login typed `show clock`, which the lab denies. The message is `port49: denied by lab_deny (show clock); see 'port49 explain'`, a space, and `0123456789` repeated to N bytes, so the last digit shown says where the device cut.

| N (bytes) | The record | Longest prefix shown | Where it ends, and what follows | What the device printed |
|---|---|---|---|---|
| 64 | authorize_command deny, 64-byte server_msg | 64 (all of it) | …`see 'port49 explain' 01`, then nothing | `% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' 01` |
| 128 | authorize_command deny, 128-byte server_msg | 128 (all of it) | …`234567890123456789012345`, then nothing | `% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' 0123456789012345678901234567890123456789012345678…` |
| 200 | authorize_command deny, 200-byte server_msg | 200 (all of it) | …`456789012345678901234567`, then nothing | `% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' 0123456789012345678901234567890123456789012345678…` |
| 255 | authorize_command deny, 255-byte server_msg | 255 (all of it) | …`901234567890123456789012`, then nothing | `% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' 0123456789012345678901234567890123456789012345678…` |
| 256 | authorize_command deny, 256-byte server_msg | 256 (all of it) | …`012345678901234567890123`, then nothing | `% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' 0123456789012345678901234567890123456789012345678…` |
| 512 | authorize_command deny, 512-byte server_msg | 512 (all of it) | …`678901234567890123456789`, then nothing | `% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' 0123456789012345678901234567890123456789012345678…` |
| 1000 | authorize_command deny, 1000-byte server_msg | 1000 (all of it) | …`456789012345678901234567`, then nothing | `% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' 0123456789012345678901234567890123456789012345678…` |

**Displayed in full** at every length measured, up to 1000 bytes: no truncation at or below 1000 bytes.

### Output modifiers (the earlier note's "Truncation length", kept)

Not measured, and the reason is itself an observation. The operator typed a 171-character line, but the device did not send that line for authorization, so port49 never built a long `server_msg` to truncate. What the device actually asked port49 to authorize:

```
"show clock"
```

The device printed:

```

```

port49d, port49 and port49-inventory built from `ec50053` (`make build`).

