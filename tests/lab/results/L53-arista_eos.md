# L53 — arista_eos

- **Date measured:** 2026-10-09
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-arista_eos.pcap` — 525 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `99b8abd2ab85e4c5468c9d5ffa0116ccd9c706a6`, `PORT49_LAB_PLATFORMS=eos`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (18:50:23-18:50:23 UTC) read a `ssh-rsa` key, SHA256:OpFHD49hIfDGt5+POILJ6wkqzS8OmGi6UuShow0YPBk. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show management ssh hostkey ed25519 public`: not this key.

```
show management ssh hostkey ed25519 public
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICNpbkEYEsZVDXVIIdu5u4k2PAMK7OchTBjNbjDpovbU  chassisAddr=0c:00:d6:2d:d3:bf
leaf1#
```

`show management ssh hostkey ecdsa-nistp256 public`: not this key.

```
show management ssh hostkey ecdsa-nistp256 public
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBYXp5iWe04Ee7j1fBetksGUjfYZYRd44r/NgJHupAhZlLyQcpcMv+G8gNusvaUL4M+U8rC9Hu8hMqTlPcUMWqI=  chassisAddr=0c:00:d6:2d:d3:bf
leaf1#
```

`show management ssh hostkey rsa public`: base64 key.

```
show management ssh hostkey rsa public
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDKsj2TVUi29eSOZNgJRdH5l1x2xPpLOAU6nMLrsmXhag4bQjjcPJcsAr2lZtRRctRGpUcDU43k8Lk6OOTGuaUIazjALmNCV+0/67oiWEKqKpHqqF/DCVYQxasCuDzHISgPYrD7yuRCGmKA9IJgvmgWgr1fMFVoYpsBeWWBbL+JEYY9WCI7a1WPR5kjdx56PkGZn1dH+bHSk8LHXVDJttpv2zF6oBViHs5HWebfPuORKCCAZp/5goOqFbCiAz9Y/uz59CoIMgSiYFtaifnHZKIHyd+VB5WrtMHYqpdS36XK4G3+NCZ2BPdVO018Efceau+4Ptz2iXXAISKOOH1u+K1V  chassisAddr=0c:00:d6:2d:d3:bf keySize=2048
leaf1#
```

Before the reload, `show version` says: ["Uptime: 1 minute\r"].

`show logging`: 19 lines it has now that it did not before the scan. Host windows (UTC): scan 18:50:23-18:50:23, control login 18:50:33-18:50:34.

**The control, a refused login as `l53-control`, is not in this log**: it records no failed login, so its silence about the scan means nothing, and **the log clause is UNMEASURED here**.

By step: scan 1, control 17, before the scan 1, between the scan and the control 0, after the control 0, no time 0. The break-glass login that read the log is among the lines. The last 30 lines, each with its step:

```
[before the scan] Oct  9 18:50:12 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[scan] Oct  9 18:50:23 leaf1 Stp: %SPANTREE-6-STABLE_CHANGE: Stp state is now stable
[control] Oct  9 18:50:33 leaf1 Aaa: %AAA-4-AUTHN_FALLBACK: Authentication method 'group port49' is currently unavailable; falling back to next method for service 'sshd' for user breakglass.
[control] Oct  9 18:50:33 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[control] Oct  9 18:50:33 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[control] Oct  9 18:50:33 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:33 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:34 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:35 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:35 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:35 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[control] Oct  9 18:50:35 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
```

**The log clause is UNMEASURED on arista_eos**: no log read showed the control login, so none of them can show that the scan left no line. L53 stays open on this clause.

The reload command was sent at 18:50:58; the device was seen down (no SSH banner on two connections in a row) at 18:51:02, and was serving SSH authentication again no later than 46s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show version` says: ["Uptime: 0 minutes\r"].

The device rebooted: true (uptime 1m0s, then 0s after 1m14s).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:OpFHD49hIfDGt5+POILJ6wkqzS8OmGi6UuShow0YPBk).
