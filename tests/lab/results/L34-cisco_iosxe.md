# L34 — cisco_iosxe

- **Date measured:** 2026-10-01
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Image ID:** `sha256:ec5b86bf54286ef3bfecee6ec4ba576289ec2da78c301a007a091d694a6c414b`
- **Run:** at commit ec50053, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=iosxe go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/session-cisco_iosxe.pcap` — 318 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/session-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — the session reply at login, and a per-command reply — and still treats the reply as a permit: the command's output appears and the session goes on.

## Observation

Run at a 6m `max_session_age` with `session.ceiling_warning: 2m`; the login and the command below came 4m10s after `port49 login`, inside the warning.

| What | The device | The record |
|---|---|---|
| `port49 token` inside the warning | stderr: `port49: your session on xe1 ends at 2026-10-01T23:10:50Z (in 2m); run 'port49 refresh'` | — |
| login as `slice01` (the session reply) | reached a prompt; before it the device showed `port49: session ends in 2m - run 'port49 refresh'` | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| `show version` inside the warning (a per-command reply) | its output appeared in 300ms; port49's text: `port49: session ends in 2m - run 'port49 refresh'` | permit permit_dominates, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| `port49 refresh` | exit 0 | 1 refresh record(s) |
| `show version` after the refresh | its output appeared in 300ms; port49's text: no port49 text and no refusal | permit permit_dominates, server_msg `(none)` |

**Session reply:** the warning shown; the login reached a prompt, so the reply was still a permit.

**Per-command reply:** the warning shown; still a permit: the output appeared and the session went on.

The warning's text (`port49: session ends in`) appears 3 time(s) anywhere in the session's whole transcript, from login to its last command. The transcript includes the reply to the paging command the harness types after the first prompt (`terminal length 0`, or `set cli screen-length 0` on Junos), which a per-command platform authorizes like any other command.

The refresh's output:

```
refreshed at 2026-10-01T23:09:01Z; this login lasts until 2026-10-02T11:09:01Z
  xe1 (slice01)  extended to 2026-10-01T23:15:01Z
```

