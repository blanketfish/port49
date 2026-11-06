# L34 — juniper_vsrx

- **Date measured:** 2026-11-06
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/session-juniper_vsrx.pcap` — 444 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/session-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestSessionLifetime$`

## Claim

Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — the session reply at login, and a per-command reply — and still treats the reply as a permit: the command's output appears and the session goes on.

## Observation

Run at a 6m `max_session_age` with `session.ceiling_warning: 2m`; the login and the command below came 4m10s after `port49 login`, inside the warning.

| What | The device | The record |
|---|---|---|
| `port49 token` inside the warning | stderr: `port49: your session on vsrx1 ends at 2026-11-06T02:31:14Z (in 2m); run 'port49 refresh'` | — |
| login as `slice01` (the session reply) | reached a prompt; **the warning was not observed** before it (the text before the prompt: `--- JUNOS 21.4R3.15 Kernel 64-bit XEN JNPR-12.1-20220817.43c4e23_buil slice01@`) | permit context_matched, server_msg `port49: session ends in 2m - run 'port49 refresh'` |
| `show version` inside the warning (a per-command reply) | its output appeared in 100ms; port49's text: no port49 text and no refusal | port49 was not asked (decision 21) |
| `port49 refresh` | exit 0 | 1 refresh record(s) |
| `show version` after the refresh | its output appeared in 100ms; port49's text: no port49 text and no refusal | port49 was not asked (decision 21) |

**Session reply:** the warning **not observed**; the login reached a prompt, so the reply was still a permit.

**Per-command reply:** not measurable on Junos: no per-command reply is ever sent (decision 21).

The warning's text (`port49: session ends in`) appears 0 time(s) anywhere in the session's whole transcript, from login to its last command. The transcript includes the reply to the paging command the harness types after the first prompt (`terminal length 0`, or `set cli screen-length 0` on Junos), which a per-command platform authorizes like any other command.

The refresh's output:

```
refreshed at 2026-11-06T02:29:24Z; this login lasts until 2026-11-06T14:29:24Z
  vsrx1 (slice01)  extended to 2026-11-06T02:35:24Z, not reached: the device keeps its own session
```


On Junos the session reply at login is the one `server_msg` the device is ever sent (decision 21): Junos authorizes no command with port49, so the command rows say only whether `show version` ran, and the ceiling and the grace window are read off the refresh's answer and the records.

