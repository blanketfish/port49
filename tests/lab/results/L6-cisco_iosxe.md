# L6 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L6-cisco_iosxe.pcap` — 126 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L6-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next.

## Observation

One SSH login that ran `show version` and disconnected. Login began 2026-09-20T19:20:26.436222608Z UTC; the connection closed 2026-09-20T19:20:26.757445796Z UTC.

- Exec **START**: arrived 18ms after the login began.
- Exec **STOP**: arrived -99ms after the session closed.

Accounting records in the window: start=1, stop=2 (an exec record is one that carries no command at all, as on EOS, or carries only `login` or `logout`, as on Junos; anything else is a per-command record).

All accounting AV pairs, in arrival order:

```
2026-09-20T19:20:26.454Z flags=start attribution=resolved raw=[task_id=4041 timezone=UTC service=shell]
2026-09-20T19:20:26.657Z flags=stop attribution=resolved raw=[task_id=4041 timezone=UTC service=shell priv-lvl=1 cmd=show version <cr>]
2026-09-20T19:20:26.658Z flags=stop attribution=resolved raw=[task_id=4041 timezone=UTC service=shell disc-cause=1 disc-cause-ext=9 pre-session-time=0 elapsed_time=0 stop_time=1789932026]
```

Retry-to-the-next-server behavior is not measured here: this lab has a single TACACS+ server, so nothing in this run shows what the device does when one is unreachable.
