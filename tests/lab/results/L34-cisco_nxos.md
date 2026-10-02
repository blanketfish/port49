# L34 — cisco_nxos

- **Date measured:** 2026-10-01
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Image ID:** `sha256:d8297de1c034164cc3d9ceaee7b1352153302b0b60dbbeefdbdddc4fa62fb9cb`
- **Run:** at commit 4bd3100, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=nxos go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/session-cisco_nxos.pcap` — 240 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/session-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — the session reply at login, and a per-command reply — and still treats the reply as a permit: the command's output appears and the session goes on.

## Observation

Run at a 6m `max_session_age` with `session.ceiling_warning: 2m`; the login and the command below came 4m10s after `port49 login`, inside the warning.

| What | The device | The record |
|---|---|---|
| `port49 token` inside the warning | stderr: `port49: your session on nx1 ends at 2026-10-01T21:14:26Z (in 2m); run 'port49 refresh'` | — |
| login as `slice01` (the session reply) | reached a prompt; **the warning was not observed** before it (the text before the prompt: `Cisco NX-OS Software Copyright (c) 2002-2023, Cisco Systems, Inc. All rights reserved. Nexus 9000v software ("Nexus 9000v Software") and related documentation, …`) | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| `show version` inside the warning (a per-command reply) | its output appeared in 700ms; port49's text: no port49 text and no refusal | permit permit_dominates, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| `port49 refresh` | exit 0 | 1 refresh record(s) |
| `show version` after the refresh | its output appeared in 700ms; port49's text: no port49 text and no refusal | permit permit_dominates, server_msg `(none)` |

**Session reply:** the warning **not observed**; the login reached a prompt, so the reply was still a permit.

**Per-command reply:** the warning **not observed**; still a permit: the output appeared and the session went on.

The warning's text (`port49: session ends in`) appears 0 time(s) anywhere in the session's whole transcript, from login to its last command. The transcript includes the reply to the paging command the harness types after the first prompt (`terminal length 0`, or `set cli screen-length 0` on Junos), which a per-command platform authorizes like any other command.

The refresh's output:

```
refreshed at 2026-10-01T21:12:37Z; this login lasts until 2026-10-02T09:12:37Z
  nx1 (slice01)  extended to 2026-10-01T21:18:37Z
```

