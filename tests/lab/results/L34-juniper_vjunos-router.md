# L34 — juniper_vjunos-router

- **Date measured:** 2026-10-01
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Image ID:** `sha256:9e62ec961b57369bb35379a404503cf13baf788af70fdba9a6d49c3f4e7a203c`
- **Run:** at commit 6dece62, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run 'TestSessionLifetime|TestL2Truncation' -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/session-juniper_vjunos-router.pcap` — 244 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/session-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — the session reply at login, and a per-command reply — and still treats the reply as a permit: the command's output appears and the session goes on.

## Observation

Run at a 6m `max_session_age` with `session.ceiling_warning: 2m`; the login and the command below came 4m10s after `port49 login`, inside the warning.

| What | The device | The record |
|---|---|---|
| `port49 token` inside the warning | stderr: `port49: your session on srx1 ends at 2026-10-01T22:00:14Z (in 2m); run 'port49 refresh'` | — |
| login as `slice01` (the session reply) | reached a prompt; **the warning was not observed** before it (the text before the prompt: `--- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil slice01@`) | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| `show version` inside the warning (a per-command reply) | its output appeared in 200ms; port49's text: no port49 text and no refusal | port49 was not asked (decision 21) |
| `port49 refresh` | exit 0 | 1 refresh record(s) |
| `show version` after the refresh | its output appeared in 200ms; port49's text: no port49 text and no refusal | port49 was not asked (decision 21) |

**Session reply:** the warning **not observed**; the login reached a prompt, so the reply was still a permit.

**Per-command reply:** not measurable on Junos: no per-command reply is ever sent (decision 21).

The warning's text (`port49: session ends in`) appears 0 time(s) anywhere in the session's whole transcript, from login to its last command.

The refresh's output:

```
refreshed at 2026-10-01T21:58:24Z; this login lasts until 2026-10-02T09:58:24Z
  srx1 (slice01)  extended to 2026-10-01T22:04:24Z, not reached: the device keeps its own session
```


On Junos the session reply at login is the one `server_msg` the device is ever sent (decision 21): Junos authorizes no command with port49, so the command rows say only whether `show version` ran, and the ceiling and the grace window are read off the refresh's answer and the records.

