# L53 — arista_eos

- **Date measured:** 2026-10-09
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-arista_eos.pcap` — 548 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0a5e9d30b6e6962340b6ca26d0085f0b9dd68211`, `PORT49_LAB_PLATFORMS=eos`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (19:48:37-19:48:37 UTC) read a `ssh-rsa` key, SHA256:DrTtiAowLaH9LTcKZX77dv7QDdpDkOZIVG1taF0bqbk. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show management ssh hostkey ed25519 public`: not this key.

```
show management ssh hostkey ed25519 public
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFEaN1MPia93qwjyFUNnYwJ0sJlIlXjEpOiZrafMr9y9  chassisAddr=0c:00:67:20:4b:ca
leaf1#
```

`show management ssh hostkey ecdsa-nistp256 public`: not this key.

```
show management ssh hostkey ecdsa-nistp256 public
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEowjh6sgt3o53P6ydxt3nCcEIBMdam6ibQNa+73QYB7eITAULcDgere9dK5QLsid0lSUcfHYJ2Ho5rDVDvnWwU=  chassisAddr=0c:00:67:20:4b:ca
leaf1#
```

`show management ssh hostkey rsa public`: base64 key.

```
show management ssh hostkey rsa public
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDXZiUa9uSnKyix8EWXlWCfg9piOV8Tz/vO1ta94KB0aF+umhMkOAAZmAqVq7EmTtvQP6k5Wi/SYkkjK9yMtC06Q3fXM7zkXzTA1IN23bQFNjNFKx7Z3wDBqsE//rtaxhvDv/jD41NyF9kXZrJxMpDI2IuTybo+QXnPRvIl6jHaJi5FlE4oYVS8dSotSHHeYH+AJv3Q+Nap0gAGfpCtC10y9q+Gm9LhY6PJ3jaFo/Yy2QqTQzyItJwqQjv7bQ73P+h5n3XhlQ3QaeEXepvZUD/DYiDp+8WjBTV3VkcbrKBx0NRM0+OPmhDOCFniWrhmzxsARcNlIF6/aX4fehapZ45t  chassisAddr=0c:00:67:20:4b:ca keySize=2048
leaf1#
```

Before the reload, `show version` says: ["Uptime: 1 minute\r"].

`show logging`: 21 lines it has now that it did not before the scan. Host windows (UTC): scan 19:48:37-19:48:37, control login 19:48:47-19:48:47.

**The control, a refused login as `l53-control`, is not in this log** (no line matching `l53-control` within 10s of its window): it records no failed login, so its silence about the scan means nothing, and **the log clause is UNMEASURED here**.

By step: scan 1, control 0, before the scan 3, between the scan and the control 0, after the control 17, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Oct  9 19:48:36 leaf1 Stp: %SPANTREE-6-STABLE_CHANGE: Stp state is now stable
```

The last 30 lines, each with its step:

```
[before the scan] Oct  9 19:48:26 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[before the scan] Oct  9 19:48:26 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[before the scan] Oct  9 19:48:26 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[scan] Oct  9 19:48:36 leaf1 Stp: %SPANTREE-6-STABLE_CHANGE: Stp state is now stable
[after the control] Oct  9 19:48:52 leaf1 Aaa: %AAA-4-AUTHN_FALLBACK: Authentication method 'group port49' is currently unavailable; falling back to next method for service 'sshd' for user breakglass.
[after the control] Oct  9 19:48:52 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[after the control] Oct  9 19:48:52 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:53 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:54 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:54 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:54 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:54 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:54 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Oct  9 19:48:54 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port4
... (truncated for this note; the full answer is in the test log)
```

`bash sudo cat /var/log/secure`: 12 lines it has now that it did not before the scan. Host windows (UTC): scan 19:48:37-19:48:37, control login 19:48:47-19:48:47.

The control, a refused login as `l53-control` (host 19:48:47-19:48:47), is in the log as the line matching `l53-control` nearest its window, stamped 19:48:47 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    Oct  9 19:48:47 leaf1 sshd[2773]: Connection closed by authenticating user l53-control 172.100.100.1 port 36030 [preauth]

By step: scan 1, control 1, before the scan 3, between the scan and the control 0, after the control 7, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Oct  9 19:48:36 leaf1 sshd[2768]: Connection closed by 172.100.100.1 port 56954 [preauth]
```

The last 30 lines, each with its step:

```
[before the scan] Oct  9 19:48:26 leaf1 sudo: pam_unix(sudo:session): session closed for user root
[before the scan] Oct  9 19:48:26 leaf1 sshd[2687]: pam_unix(sshd:session): session closed for user breakglass
[before the scan] Oct  9 19:48:31 leaf1 sshd[2767]: Did not receive identification string from 172.100.100.1 port 57068
[scan] Oct  9 19:48:36 leaf1 sshd[2768]: Connection closed by 172.100.100.1 port 56954 [preauth]
[control] Oct  9 19:48:47 leaf1 sshd[2773]: Connection closed by authenticating user l53-control 172.100.100.1 port 36030 [preauth]
[after the control] Oct  9 19:48:52 leaf1 sshd[2784]: Accepted keyboard-interactive/pam for breakglass from 172.100.100.1 port 50796 ssh2
[after the control] Oct  9 19:48:52 leaf1 sshd[2784]: pam_unix(sshd:session): session opened for user breakglass by (uid=0)
[after the control] Oct  9 19:48:54 leaf1 sudo: breakglass : TTY=pts/5 ; PWD=/home/breakglass ; USER=root ; COMMAND=/usr/bin/ssh-keygen -lf /persist/secure/ssh_host_rsa_key.pub
[after the control] Oct  9 19:48:54 leaf1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
[after the control] Oct  9 19:48:54 leaf1 sudo: pam_unix(sudo:session): session closed for user root
[after the control] Oct  9 19:48:54 leaf1 sudo: breakglass : TTY=pts/5 ; PWD=/home/breakglass ; USER=root ; COMMAND=/usr/bin/cat /var/log/secure
[after the control] Oct  9 19:48:54 leaf1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

The reload command was sent at 19:49:17; the device was seen down (no SSH banner on two connections in a row) at 19:49:21, and was serving SSH authentication again no later than 59s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show version` says: ["Uptime: 0 minutes\r"].

The device rebooted: true (uptime 1m0s, then 0s after 1m26s).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:DrTtiAowLaH9LTcKZX77dv7QDdpDkOZIVG1taF0bqbk).
