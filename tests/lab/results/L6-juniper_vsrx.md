# L6 — juniper_vsrx

- **Date measured:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/captures/L6-juniper_vsrx.pcap` — 104 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L6-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH
- **Caveat:** could not confirm the startup config was applied: breakglass never logged in within 8m54.675033002s (last error: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain)

## Claim

How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next.

## Observation

One SSH login that ran `show version` and disconnected. Login began 2026-09-20T07:54:35.217438082Z UTC; the connection closed 2026-09-20T07:54:35.361338951Z UTC.

- Exec **START**: arrived 4.156s after the login began.
- Exec **STOP**: arrived 4.013s after the session closed.

Accounting records in the window: start=1, stop=2 (an exec record is one that carries no command at all, as on EOS, or carries only `login` or `logout`, as on Junos; anything else is a per-command record).

All accounting AV pairs, in arrival order:

```
2026-09-20T07:54:39.373Z flags=start attribution=unattributed raw=[task_id=1 service=shell session_pid = 29374 cmd=login]
2026-09-20T07:54:39.373Z flags=stop attribution=unattributed raw=[task_id=2 service=shell session_pid = 29374 cmd=show version <cr>]
2026-09-20T07:54:39.374Z flags=stop attribution=unattributed raw=[task_id=1 service=shell session_pid = 29374 elapsed_time=0 cmd=logout]
```

Retry-to-the-next-server behavior is not measured here: this lab has a single TACACS+ server, so nothing in this run shows what the device does when one is unreachable.
