# L53 — cisco_nxos

- **Date measured:** 2026-10-09
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-cisco_nxos.pcap` — 864 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0a5e9d30b6e6962340b6ca26d0085f0b9dd68211`, `PORT49_LAB_PLATFORMS=nxos`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (20:01:30-20:01:30 UTC) read a `ssh-rsa` key, SHA256:MBgr/2WujsUjlTnLLf286CeYNMSIGs4IcKTuSHWR4cg. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show ssh key`: base64 key.

```
show ssh key
**************************************
rsa Keys generated:Fri Oct  9 20:00:36 2026

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOOK2AB+aULSJGchDd6iT1aGFPPCxrMLYkJJrH3TWhG/NuaK0Gwm2ou7pZxvhEX1nR0d8hZsxCy0RhOyX0xphudrtojE85WaCyR8IPEQz+WzQ0B7Q61ljkv6uc/4mLCijJnjS7V7qryWrvpcIqARnyCpVcZph4V3NJ1xkr5W5NkyO5tmtzDqBlq8Z2/EVNimODNEWx4QdtiK2BfTgY0p2p5etBXPTXb3cWxWQFu/UTIbJeHdf8vNaE7s1ptPnRSJUIRJ4H6lkxsLtdhl0xrorSsOBNFD2ZxBNn4pTU7QoHnekX9nfooI02zWdKEO7e48fK7SPHEl7g+TXJbZxQn6ih

bitcount:2048
fingerprint:
SHA256:MBgr/2WujsUjlTnLLf286CeYNMSIGs4IcKTuSHWR4cg
**************************************
could not retrieve dsa key information
**************************************
could not retrieve ecdsa key information
**************************************
nx1# 
```

Before the reload, `show version` says: ["Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 25 second(s)\r"].

`show logging logfile`: 5 lines it has now that it did not before the scan. Host windows (UTC): scan 20:01:30-20:01:30, control login 20:01:41-20:01:42.

The control, a refused login as `l53-control` (host 20:01:41-20:01:42), is in the log as the line matching `PAM: Authentication failure for illegal user` nearest its window, stamped 20:01:42 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    2026 Oct  9 20:01:42 nx1 %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user ***** from 172.100.100.1 - dcos_sshd[14668]

By step: scan 0, control 4, before the scan 0, between the scan and the control 0, after the control 1, no time 0. No line names the break-glass login that read the log.

No line is stamped inside the scan's window.

The last 30 lines, each with its step:

```
[control] 2026 Oct  9 20:01:40 nx1 %TACACS-3-TACACS_ERROR_MESSAGE: All servers failed to respond (message repeated 6 times)
[control] 2026 Oct  9 20:01:40 nx1 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 172.100.100.1 - dcos_sshd[14668]
[control] 2026 Oct  9 20:01:42 nx1 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 172.100.100.1 - dcos_sshd[14677]
[control] 2026 Oct  9 20:01:42 nx1 %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user ***** from 172.100.100.1 - dcos_sshd[14668]
[after the control] 2026 Oct  9 20:01:47 nx1 %TACACS-3-TACACS_ERROR_MESSAGE: All servers failed to respond
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

With `aaa authentication rejected 2 in 60 ban 60` set (and 70s waited, so the harness's own failed probe logins after the daemon's restart were out of its window): three scans, then a login with a fresh token: it succeeded. The control, two refused logins as `slice01`, the user the login uses, and then a login with a fresh token: it was refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain).

The reload command was sent at 20:04:59; the device was seen down (no SSH banner on two connections in a row) at 20:05:15, and was serving SSH authentication again no later than 1m12s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show version` says: ["Kernel uptime is 0 day(s), 0 hour(s), 1 minute(s), 10 second(s)\r"].

The device rebooted: true (uptime 3m25s, then 1m10s after 4m40s).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:MBgr/2WujsUjlTnLLf286CeYNMSIGs4IcKTuSHWR4cg).
