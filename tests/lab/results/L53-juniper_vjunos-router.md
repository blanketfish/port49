# L53 — juniper_vjunos-router

- **Date measured:** 2026-11-06
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vjunos-router.pcap` — 1562 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL53HostKeyScan$`

## Claim

The SSH host key the device presents to a scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (06:35:32-06:35:32 UTC) read a `ssh-rsa` key, SHA256:H/tC8Mxxy6L2pnATScoGGMZJ46uhDq3QWbBuEzLFFE4. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`file show /etc/ssh/ssh_host_ed25519_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ed25519_key.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPLRhgIe6UG+rzdWxFm6dcQpiQpqKNSVUPuBA+kqK9UN root@

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_ecdsa_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ecdsa_key.pub 
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEiDZX5Kli9u/lanRgYMTZ459v5JHvAFj+9OmldXE4Qzo0th190598GBHfELc3zARJhH9sOyy4TjRA7+AIQF79A= root@

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_rsa_key.pub`: base64 key.

```
file show /etc/ssh/ssh_host_rsa_key.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3nLeVczFB9EGrQxKfWEyG933vaI5P2jPwSo+BUFGKQz68bklBTgnae+9Sxei6Cewyt9xalNC1o0fICXyjIl5Wz7bTbPRV8Gw2TRiUF4EtPPhAHUA06UZp5gCTeWZirbRWldWPVYFL/hwXYgyjpLfq2S9UGNI3GpIOFfr3QlfDdnjdhhrwWLgWeDIDuV/fpAuPL5aYi8LB5VIgn6132CgjyNTJCmnH75sOvfoVywM8VJNKOE5ZnBFAZeX47kripcAOQLehc8NZidhutu2Ej4N5tF4BJH4512Ft9nQhR9e7ftEgQz07czHC79E9E+0o+JheISQoZf1RP1kHFngMnODx root@

breakglass@srx1> 
```

Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-11-06 06:34:02 UTC (00:01:52 ago)\r"].

`show log messages`: 17 lines it has now that it did not before the scan. Host windows (UTC): scan 06:35:32-06:35:32, control login 06:35:42-06:35:49.

The control, a refused login as `l53-control` (host 06:35:42-06:35:49), is in the log as the line matching `l53-control` nearest its window, stamped 06:35:47 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    Nov  6 06:35:47  srx1 sshd[14492]: Connection closed by authenticating user l53-control 172.100.100.1 port 37678

By step: scan 3, control 6, before the scan 5, between the scan and the control 0, after the control 3, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Nov  6 06:35:31  srx1 sshd[14489]: Connection closed by 172.100.100.1 port 49818 [preauth]
Nov  6 06:35:31  srx1 sshd[14490]: Connection closed by 172.100.100.1 port 49818
Nov  6 06:35:31  srx1 inetd[14107]: /usr/sbin/sshd[14489]: exited, status 255
```

The last 30 lines, each with its step:

```
[before the scan] Nov  6 06:35:14  srx1 chassisd[14100]: CHASSISD_SNMP_TRAP7: SNMP trap generated: FRU insertion (jnxFruContentsIndex 7, jnxFruL1Index 1, jnxFruL2Index 0, jnxFruL3Index 0, jnxFruName FPC: Virtual FPC @ 0/*/*, jnxFruType 3, jnxFruSlot 0)
[before the scan] Nov  6 06:35:14  srx1 chassisd[14100]: CHASSISD_SNMP_TRAP10: SNMP trap generated: FRU power on (jnxFruContentsIndex 7, jnxFruL1Index 1, jnxFruL2Index 0, jnxFruL3Index 0, jnxFruName FPC: Virtual FPC @ 0/*/*, jnxFruType 3, jnxFruSlot 0, jnxFruOfflineReason 2, jnxFruLastPowerOff 0, jnxFruLastPowerOn 7144)
[before the scan] Nov  6 06:35:29  srx1 rpd[14289]: RPD_RT_HWM_NOTICE: New RIB highwatermark for unique destinations: 16 [2026-11-06 06:34:59]
[before the scan] Nov  6 06:35:29  srx1 rpd[14289]: RPD_RT_HWM_NOTICE: New RIB highwatermark for routes: 17 [2026-11-06 06:34:59]
[before the scan] Nov  6 06:35:30  srx1 rpd[14289]: RPD_RT_HWM_NOTICE: New FIB highwatermark for routes: 2 [2026-11-06 06:34:59]
[scan] Nov  6 06:35:31  srx1 sshd[14489]: Connection closed by 172.100.100.1 port 49818 [preauth]
[scan] Nov  6 06:35:31  srx1 sshd[14490]: Connection closed by 172.100.100.1 port 49818
[scan] Nov  6 06:35:31  srx1 inetd[14107]: /usr/sbin/sshd[14489]: exited, status 255
[control] Nov  6 06:35:41  srx1 sshd[14491]: Failed password for l53-control from 172.100.100.1 port 37678 ssh2
[control] Nov  6 06:35:41  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Nov  6 06:35:42  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Nov  6 06:35:47  srx1 sshd[14492]: Connection closed by authenticating user l53-control 172.100.100.1 port 37678
[control] Nov  6 06:35:47  srx1 sshd[14491]: Connection closed by authenticating user l53-control 172.100.100.1 port 37678 [preauth]
[control] Nov  6 06:35:47  srx1 inetd[14107]: /usr/sbin/sshd[14491]: exited, status 255
[after the control] Nov  6 06:35:52  srx1 sshd: PAM_TACPLUS_SEND_AUTHEN_FAIL: Failed in sending authentication with error connect: Connection refused.
[after the control] Nov  6 06:35:52  srx1 sshd[14495]: Accepted password for breakglass from 172.100.100.1 port 58228 ssh2
[after the control] Nov  6 06:35:54  srx1 auditd[14309]: AUDITD_TACPLUS_FAIL: TACACS+ failure: TACACS+ server returned status as 'error' in the accounting reply
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

The reload command was sent at 06:35:56; the device was seen down (no SSH banner on two connections in a row) at 06:36:00, and was serving SSH authentication again no later than 1m27s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-11-06 06:36:29 UTC (00:00:58 ago)\r"].

The device rebooted: true (System booted 2026-11-06 06:34:02 UTC, then 2026-11-06 06:36:29 UTC).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:H/tC8Mxxy6L2pnATScoGGMZJ46uhDq3QWbBuEzLFFE4).
