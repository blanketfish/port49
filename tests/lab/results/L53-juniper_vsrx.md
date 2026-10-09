# L53 — juniper_vsrx

- **Date measured:** 2026-10-09
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-juniper_vsrx.pcap` — 672 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0a5e9d30b6e6962340b6ca26d0085f0b9dd68211`, `PORT49_LAB_PLATFORMS=vsrx`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (19:56:11-19:56:11 UTC) read a `ssh-rsa` key, SHA256:v4Y99+lvEyVbYJxTLH6HED58nFIUQpxkuJ6sZ2HTnkg. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`file show /etc/ssh/ssh_host_ed25519_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ed25519_key.pub 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMIET9zOTYakc2Md78g7EbzJC2YaLsUz0z87Hc9zf0wf root@srx1

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_ecdsa_key.pub`: not this key.

```
file show /etc/ssh/ssh_host_ecdsa_key.pub 
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMQzt+faWKc4PFvbtKGx92i4aV98z28AaSQk6/GS5RMx9afJ4tWr7UkNVPhE3eahTAgbhnUL/m+VfGznS9KBH98= root@srx1

breakglass@srx1> 
```

`file show /etc/ssh/ssh_host_rsa_key.pub`: base64 key.

```
file show /etc/ssh/ssh_host_rsa_key.pub 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCPuVI79L+WnMuOcKQuZvoD2URX8AZXc0slTijG6Viyvyn8HmUwNOc+evkifMfHuVmOm+o2HVj1NMhqRbci3SpHM+ptn6owpL8M+M4hqZ1+Ccwqtjw9OA7K7+xakr7v/a5psKhPhuba4yO8IowRIphFiTsXA1Uu1IlfoLd+7K9En4RYM0kNpBOnVYvei1pB4g2KctlhuRGDKnLoqyagBwuq/kjc5K2jXr6Sj2URGJhw/yTmApA3s0maA5VKZIEgWHnaMLV9S8pgDTW0VcHshCzsuLaeXSicO1fRZqOVr8+pR/PtUUcflOkEWKrj/OUagYVILt2KkUjKbHrubsayunxj root@srx1

breakglass@srx1> 
```

Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 19:54:46 UTC (00:01:48 ago)\r"].

`show log messages`: 150 lines it has now that it did not before the scan. Host windows (UTC): scan 19:56:11-19:56:11, control login 19:56:21-19:56:28.

The control, a refused login as `l53-control` (host 19:56:21-19:56:28), is in the log as the line matching `l53-control` nearest its window, stamped 19:56:23 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    Oct  9 19:56:23  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'

By step: scan 31, control 28, before the scan 71, between the scan and the control 7, after the control 13, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Oct  9 19:56:11  srx1 cmfwdd_fpc_action:
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_SNMP_TRAP3: ENTITY trap generated: entStateOperEnabled (entPhysicalIndex 20, entStateAdmin 4, entStateAlarm 6)
Oct  9 19:56:11  srx1 Error requesting CMFWDD SET INTEGER, illegal setting 100032
Oct  9 19:56:11  srx1 sshd[28674]: Connection closed by 172.100.100.1 port 45616 [preauth]
Oct  9 19:56:11  srx1 sshd[28675]: Connection closed by 172.100.100.1 port 45616
Oct  9 19:56:11  srx1 inetd[27928]: /usr/sbin/sshd[28674]: exited, status 255
Oct  9 19:56:11  srx1 CM_FWDD: cmfwdd_get_pic_i2c_id_from_fpc_i2c_id fpcid 1919 pic_dcard_id 0
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_SNMP_TRAP10: SNMP trap generated: FRU power on (jnxFruContentsIndex 8, jnxFruL1Index 1, jnxFruL2Index 1, jnxFruL3Index 0, jnxFruName PIC:  @ 0/0/*, jnxFruType 11, jnxFruSlot 0, jnxFruOfflineReason 2, jnxFruLastPowerOff 0, jnxFruLastPowerOn 4096)
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_SNMP_TRAP3: ENTITY trap generated: entStateOperEnabled (entPhysicalIndex 27, entStateAdmin 4, entStateAlarm 0)
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_SNMP_TRAP0: ENTITY trap generated: entConfigChanged
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_NOTICE: create_pics: created interface device for sp-0/0/0
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_NOTICE: create_pics: created interface device for gr-0/0/0
Oct  9 19:56:11  srx1 kernel: if_pfe_multiservice_ifdconfig_tlv: pfc_milisec_detection_interval 1000 if_pfe_multiservice_ifdconfig_tlv: pause_frame_threshold 10000 if_pfe_multiservice_ifdconfig_tlv: dump_via_mailbox 0 if_pfe_multiservice_ifdconfig_tlv: jb_scratch_pad_debug_flag 1
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_NOTICE: create_pics: created interface device for ip-0/0/0
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_NOTICE: create_pics: created interface device for lsq-0/0/0
Oct  9 19:56:11  srx1 chassisd[27912]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
Oct  9 19:56:11  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
Oct  9 19:56:11  srx1 kernel: if_pfe_multiservice_ifdconfig_tlv: pfc_milisec_detection_interval 1000 if_pfe_multiservice_ifdconfig_tlv: pause_frame_threshold 10000 if_pfe_multiservice_ifdconfig_tlv: dump_via_mailbox 0 if_pfe_multiservice_ifdconfig_tlv: jb_scratch_pad_debug_flag 1
Oct  9 19:56:11  srx1 fwdd_ifd_set_eff_bandwidth: can't find outq ifd entry for ifd sp-0/0/0
Oct  9 19:56:11  srx1 cosman_compute_install_sched_params: Failed to get subunit b/w for sp-0/0/0
Oct  9 19:56:11  srx1 COSMAN_FWDD: cosman_update_sched_policy_for_ifd:2929 updation of sched policy failed for ifd 135 (sp-0/0/0)
Oct  9 19:56:11  srx1 COSMAN: policy update failed
Oct  9 19:56:11  srx1 fwdd_ifd_set_eff_bandwidth: can't find outq ifd entry for ifd sp-0/0/0
Oct  9 19:56:11  srx1 cosman_compute_install_sched_params: Failed to get subunit b/w for sp-0/0/0
Oct  9 19:56:11  srx1 COSMAN_FWDD: cosman_update_sched_policy_for_ifd:2929 updation of sched policy failed for ifd 135 (sp-0/0/0)
Oct  9 19:56:11  srx1 COSMAN: media speed change cos policy update failed
Oct  9 19:56:11  srx1 mib2d[27925]: SNMP_TRAP_LINK_UP: ifIndex 501, ifAdminStatus up(1), ifOperStatus up(1), ifName pp0
Oct  9 19:56:11  srx1 mib2d[27925]: SNMP_TRAP_LINK_UP: ifIndex 502, ifAdminStatus up(1), ifOperStatus up(1), ifName irb
Oct  9 19:56:11  srx1 mib2d[27925]: SNMP_TRAP_LINK_UP: ifIndex 504, ifAdminStatus up(1), ifOperStatus up(1), ifName ppd0
Oct  9 19:56:11  srx1 mib2d[27925]: SNMP_TRAP_LINK_UP: ifIndex 505, ifAdminStatus up(1), ifOperStatus up(1), ifName ppe0
Oct  9 19:56:12  srx1 mib2d[27925]: SNMP_TRAP_LINK_UP: ifIndex 508, ifAdminStatus up(1), ifOperStatus up(1), ifName sp-0/0/0
```

The last 30 lines, each with its step:

```
[control] Oct  9 19:56:22  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Oct  9 19:56:23  srx1 sshd: SSHD_LOGIN_FAILED: Login failed for user 'l53-control' from host '172.100.100.1'
[control] Oct  9 19:56:24  srx1 chassisd[27912]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Oct  9 19:56:24  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Oct  9 19:56:24  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[control] Oct  9 19:56:26  srx1 chassisd[27912]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Oct  9 19:56:26  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Oct  9 19:56:26  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[control] Oct  9 19:56:28  srx1 sshd[28683]: Connection closed by authenticating user l53-control 172.100.100.1 port 51230
[control] Oct  9 19:56:28  srx1 sshd[28682]: Connection closed by authenticating user l53-control 172.100.100.1 port 51230 [preauth]
[control] Oct  9 19:56:28  srx1 inetd[27928]: /usr/sbin/sshd[28682]: exited, status 255
[control] Oct  9 19:56:28  srx1 chassisd[27912]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Oct  9 19:56:28  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Oct  9 19:56:28  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[control] Oct  9 19:56:30  srx1 chassisd[27912]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[control] Oct  9 19:56:30  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[control] Oct  9 19:56:30  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[after the control] Oct  9 19:56:32  srx1 craftd[27922]:  Minor alarm set, License for feature Virtual Appliance(119) is about to expire
[after the control] Oct  9 19:56:32  srx1 alarmd[27919]: Alarm set: License id=0, color=YELLOW, class=CHASSIS, reason=License for feature Virtual Appliance(119) is about to expire
[after the control] Oct  9 19:56:32  srx1 craftd[27922]:  Minor alarm set, License for feature VCPU Scale(292) is about to expire
[after the control] Oct  9 19:56:32  srx1 alarmd[27919]: Alarm set: License id=0, color=YELLOW, class=CHASSIS, reason=License for feature VCPU Scale(292) is about to expire
[after the control] Oct  9 19:56:32  srx1 mib2d[27925]: SNMP_TRAP_LINK_UP: ifIndex 514, ifAdminStatus up(1), ifOperStatus up(1), ifName lt-0/0/0
[after the control] Oct  9 19:56:32  srx1 chassisd[27912]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[after the control] Oct  9 19:56:32  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink port attributes - nic 0, pic 0
[after the control] Oct  9 19:56:32  srx1 chassisd[27912]: CHASSISD_IFDEV_CREATE_FAILURE: create_pics: unable to create interface device for lsq-0/0/0 (Invalid argument)
[after the control] Oct  9 19:56:33  srx1 sshd: PAM_TACPLUS_SEND_AUTHEN_FAIL: Failed in sending authentication with error connect: Connection refused.
[after the control] Oct  9 19:56:33  srx1 sshd[28695]: Accepted password for breakglass from 172.100.100.1 port 40926 ssh2
[after the control] Oct  9 19:56:35  srx1 chassisd[27912]: CHASSISD_IFDEV_RTSLIB_FAILURE: ifdev_create: rtslib_ifdm_add failed (Invalid argument)
[after the control] Oct  9 19:56:35  srx1 kernel: if_pfe_ml_mlppp_ifd_add: Could not get the multilink 
... (truncated for this note; the full answer is in the test log)
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

The reload command was sent at 19:56:56; the device was seen down (no SSH banner on two connections in a row) at 19:57:00, and was serving SSH authentication again no later than 1m6s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-09 19:57:27 UTC (00:00:39 ago)\r"].

The device rebooted: true (System booted 2026-10-09 19:54:46 UTC, then 2026-10-09 19:57:27 UTC).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:v4Y99+lvEyVbYJxTLH6HED58nFIUQpxkuJ6sZ2HTnkg).
