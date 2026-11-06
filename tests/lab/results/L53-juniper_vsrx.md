# L53 — juniper_vsrx

- **Date measured:** 2026-11-06
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vsrx.pcap` — 623 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL53HostKeyScan$`

## Claim

The SSH host key the device presents to a scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (06:39:07-06:39:07 UTC) read a `ssh-rsa` key, SHA256:6aNIAFL+RsPsvfL3Lc5Hwzsox0Wqv4eaOBeItMcX790. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`file show /etc/ssh/ssh_host_ed25519_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ed25519_key.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICFGGWIfbQxsePJlSaqzlU7hExAxMFlnJUtPy9qIV4qF root@srx1

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_ecdsa_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ecdsa_key.pub 
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPvKVofNNMYtJqooevclXciHa//O2bPyt7BiCh+K0z2XlZrso8Ya5fUdamOxYOvaJSrHX/FmB3f2i4821QwpDVY= root@srx1

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_rsa_key.pub`: base64 key.

```
file show /etc/ssh/ssh_host_rsa_key.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCoBtp163i3m9DE3EQHzoN7m1DopxZ4MmFIbD9xSk2Mze1Aiuk40mLkcBrend1aHgNWi0dnZIufzQSBOXtOCxLhmTzPcKIPeuP2tIdaz+Fsuqh7wXHnT2M+m8J7iuhp17GL+VNzeyv+p2zoeI7iggBK6gZ4DddoyakUvtIeK8pKhAzAwQ3+De5SnkqQcd+qKoj5SGZN16Jl+TTzGWG4Vgjtz6ut1TI25p2x9ejRQoPxwUUnBQtBlpSfIut8A77SjVbkAJVAbCEGH2WyKmuYmn4LG4AFpnsiAyFwKJuZPCIRZNTLcb6bU2UL+F4vY22/D8nHcR/BNjC+bvGDZAB76lU1 root@srx1

breakglass@srx1> 
```

Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-11-06 06:37:46 UTC (00:01:43 ago)\r"].

`show log messages`: 126 lines it has now that it did not before the scan. Host windows (UTC): scan 06:39:07-06:39:07, control login 06:39:18-06:39:24.

The control, a refused login as `l53-control` (host 06:39:18-06:39:24), is in the log as the line matching `l53-control` nearest its window, stamped 06:39:23 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    Nov  6 06:39:23  srx1 sshd[28676]: Connection closed by authenticating user l53-control 172.100.100.1 port 40894

By step: scan 3, control 25, before the scan 62, between the scan and the control 31, after the control 5, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Nov  6 06:39:06  srx1 sshd[28667]: Connection closed by 172.100.100.1 port 47172 [preauth]
Nov  6 06:39:06  srx1 sshd[28668]: Connection closed by 172.100.100.1 port 47172
Nov  6 06:39:06  srx1 inetd[27930]: /usr/sbin/sshd[28667]: exited, status 255
```

The last 30 lines, each with its step:

```
[control] Nov  6 06:39:17  srx1 sshd[28675]: Failed password for l53-control from 172.100.100.1 port 40894 ssh2
[control] Nov  6 06:39:17  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Nov  6 06:39:17  srx1 chassisd[27905]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Nov  6 06:39:17  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[control] Nov  6 06:39:17  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Nov  6 06:39:18  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Nov  6 06:39:19  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_NOTICE: create_pics: created interface device for mt-0/0/0
[control] Nov  6 06:39:19  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_NOTICE: create_pics: created interface device for lt-0/0/0
[control] Nov  6 06:39:19  srx1 chassisd[27905]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Nov  6 06:39:19  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[control] Nov  6 06:39:19  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Nov  6 06:39:19  srx1 Node for service control ifl 71, is already present
[control] Nov  6 06:39:20  srx1 mib2d[27927]: SNMP_TRAP_LINK_UP: ifIndex 513, ifAdminStatus up(1), ifOperStatus up(1), ifName mt-0/0/0
[control] Nov  6 06:39:21  srx1 chassisd[27905]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Nov  6 06:39:21  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Nov  6 06:39:21  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[control] Nov  6 06:39:23  srx1 sshd[28676]: Connection closed by authenticating user l53-control 172.100.100.1 port 40894
[control] Nov  6 06:39:23  srx1 sshd[28675]: Connection closed by authenticating user l53-control 172.100.100.1 port 40894 [preauth]
[control] Nov  6 06:39:23  srx1 inetd[27930]: /usr/sbin/sshd[28675]: exited, status 255
[control] Nov  6 06:39:24  srx1 chassisd[27905]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Nov  6 06:39:24  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Nov  6 06:39:24  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[control] Nov  6 06:39:26  srx1 chassisd[27905]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Nov  6 06:39:26  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Nov  6 06:39:26  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[after the control] Nov  6 06:39:28  srx1 chassisd[27905]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[after the control] Nov  6 06:39:28  srx1 chassisd[27905]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[after the control] Nov  6 06:39:28  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[after the control] Nov  6 06:39:28  srx1 sshd: PAM_TACPLUS_SEND_AUTHEN_FAIL: Failed in sending authentication with error connect: Connection refused.
[after the control] Nov  6 06:39:28  srx1 sshd[28684]: Accepted password for breakglass from 172.100.100.1 port 51016 ssh2
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

The reload command was sent at 06:39:32; the device was seen down (no SSH banner on two connections in a row) at 06:39:36, and was serving SSH authentication again no later than 1m12s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-11-06 06:40:04 UTC (00:00:44 ago)\r"].

The device rebooted: true (System booted 2026-11-06 06:37:46 UTC, then 2026-11-06 06:40:04 UTC).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:6aNIAFL+RsPsvfL3Lc5Hwzsox0Wqv4eaOBeItMcX790).
