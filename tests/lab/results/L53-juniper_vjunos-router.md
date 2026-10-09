# L53 — juniper_vjunos-router

- **Date measured:** 2026-10-09
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vjunos-router.pcap` — 2260 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0a5e9d30b6e6962340b6ca26d0085f0b9dd68211`, `PORT49_LAB_PLATFORMS=vjunos`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (19:52:10-19:52:10 UTC) read a `ssh-rsa` key, SHA256:H/tC8Mxxy6L2pnATScoGGMZJ46uhDq3QWbBuEzLFFE4. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

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

Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 19:50:49 UTC (00:01:43 ago)\r"].

`show log messages`: 33 lines it has now that it did not before the scan. Host windows (UTC): scan 19:52:10-19:52:10, control login 19:52:21-19:52:27.

The control, a refused login as `l53-control` (host 19:52:21-19:52:27), is in the log as the line matching `l53-control` nearest its window, stamped 19:52:26 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    Oct  9 19:52:26  srx1 sshd[14492]: Connection closed by authenticating user l53-control 172.100.100.1 port 59008

By step: scan 3, control 6, before the scan 19, between the scan and the control 3, after the control 2, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Oct  9 19:52:09  srx1 sshd[14489]: Connection closed by 172.100.100.1 port 58448 [preauth]
Oct  9 19:52:09  srx1 sshd[14490]: Connection closed by 172.100.100.1 port 58448
Oct  9 19:52:09  srx1 inetd[14107]: /usr/sbin/sshd[14489]: exited, status 255
```

The last 30 lines, each with its step:

```
[before the scan] Oct  9 19:51:48  srx1 mosquitto[14229]: New client connected from 128.0.0.4 as client-1-re0-NA_periodic_subscriber-re0 (c1, k0).
[before the scan] Oct  9 19:51:48  srx1 mosquitto[14229]: New client connected from 128.0.0.4 as client-2-re0-NA_event_subscriber-re0 (c1, k0).
[before the scan] Oct  9 19:51:48  srx1 mosquitto[14229]: New client connected from 128.0.0.4 as client-2-re0-NA_periodic_subscriber-re0 (c1, k0).
[before the scan] Oct  9 19:51:49  srx1 mgd[14357]: UI_EPHEMERAL_COMMIT: User 'root' has requested commit on 'junos-analytics' ephemeral database
[before the scan] Oct  9 19:51:49  srx1 mgd[14357]: UI_EPHEMERAL_COMMIT_COMPLETED: commit complete on 'junos-analytics' ephemeral database
[before the scan] Oct  9 19:51:49  srx1 mosquitto[14229]: New connection from 128.0.0.4 on port 51883.
[before the scan] Oct  9 19:51:49  srx1 mosquitto[14229]: New client connected from 128.0.0.4 as eventd_telemetry_publisher (c1, k6000).
[before the scan] Oct  9 19:51:49  srx1 pfed: LIBJSNMP_SA_IPC_REG_ROWS: ns_subagent_register_mibs: registering 2 rows
[before the scan] Oct  9 19:51:49  srx1 transportd[14338]: LIBJSNMP_SA_IPC_REG_ROWS: ns_subagent_register_mibs: registering 42 rows
[before the scan] Oct  9 19:51:50  srx1 jlaunchd[14086]: commit-batch (PID 14327) exited with status=0 Normal Exit
[before the scan] Oct  9 19:51:50  srx1 mgd[14378]: UI_EPHEMERAL_COMMIT: User 'root' has requested commit on 'junos-analytics' ephemeral database
[before the scan] Oct  9 19:51:50  srx1 mosquitto[14229]: New connection from 128.0.0.4 on port 51883.
[before the scan] Oct  9 19:51:50  srx1 mosquitto[14229]: New client connected from 128.0.0.4 as chassisd_telemetry_publisher (c1, k6000).
[before the scan] Oct  9 19:51:50  srx1 mgd[14378]: UI_EPHEMERAL_COMMIT_COMPLETED: commit complete on 'junos-analytics' ephemeral database
[before the scan] Oct  9 19:51:53  srx1 chassisd[14100]: CHASSISD_SNMP_TRAP7: SNMP trap generated: FRU insertion (jnxFruContentsIndex 7, jnxFruL1Index 1, jnxFruL2Index 0, jnxFruL3Index 0, jnxFruName FPC: Virtual FPC @ 0/*/*, jnxFruType 3, jnxFruSlot 0)
[before the scan] Oct  9 19:51:53  srx1 chassisd[14100]: CHASSISD_SNMP_TRAP10: SNMP trap generated: FRU power on (jnxFruContentsIndex 7, jnxFruL1Index 1, jnxFruL2Index 0, jnxFruL3Index 0, jnxFruName FPC: Virtual FPC @ 0/*/*, jnxFruType 3, jnxFruSlot 0, jnxFruOfflineReason 2, jnxFruLastPowerOff 0, jnxFruLastPowerOn 6472)
[scan] Oct  9 19:52:09  srx1 sshd[14489]: Connection closed by 172.100.100.1 port 58448 [preauth]
[scan] Oct  9 19:52:09  srx1 sshd[14490]: Connection closed by 172.100.100.1 port 58448
[scan] Oct  9 19:52:09  srx1 inetd[14107]: /usr/sbin/sshd[14489]: exited, status 255
[between the scan and the control] Oct  9 19:52:14  srx1 rpd[14297]: RPD_RT_HWM_NOTICE: New RIB highwatermark for unique destinations: 16 [2026-10-09 19:51:44]
[between the scan and the control] Oct  9 19:52:14  srx1 rpd[14297]: RPD_RT_HWM_NOTICE: New RIB highwatermark for routes: 17 [2026-10-09 19:51:44]
[between the scan and the control] Oct  9 19:52:14  srx1 rpd[14297]: RPD_RT_HWM_NOTICE: New FIB highwatermark for routes: 2 [2026-10-09 19:51:44]
[control] Oct  9 19:52:20  srx1 sshd[14491]: Failed password for l53-control from 172.100.100.1 port 59008 ssh2
[control] Oct  9 19:52:20  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Oct  9 19:52:21  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Oct  9 19:52:26  srx1 sshd[14492]: Connection closed by authenticating user l53-control 172.100.100.1 port 59008
[control] Oct  9 19:52:26  srx1 sshd[14491]: Connection closed by authenticating user l53-control 172.100.100.1 port 59008 [preauth]
[control] Oct  9 19:52:26  srx1 inetd[14107]: /usr/sbin/sshd[14491]: exited, status 255
[after the control] Oct  9 19:52:31  srx1 sshd: PAM_TACPLUS_SEND_AUTHEN_FAIL: Failed in sending authentication with error connect: Connection refused.
[
... (truncated for this note; the full answer is in the test log)
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

The reload command was sent at 19:52:56; the device was seen down (no SSH banner on two connections in a row) at 19:53:00, and was serving SSH authentication again no later than 1m28s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 19:53:27 UTC (00:01:00 ago)\r"].

The device rebooted: true (System booted 2026-10-09 19:50:49 UTC, then 2026-10-09 19:53:27 UTC).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:H/tC8Mxxy6L2pnATScoGGMZJ46uhDq3QWbBuEzLFFE4).

## History of attempts

This note is from one run on harness commit `0a5e9d3`, which passed first try. On the earlier harness commit `74ec202` (a previous run set whose notes this one replaces) the first vJunos-router run failed: the VM was not serving SSH 8 minutes after its reboot (`i/o timeout`); its rerun on the same commit passed. The cause was not investigated. Runs since on `eb7de28` and `0a5e9d3` passed first try.
