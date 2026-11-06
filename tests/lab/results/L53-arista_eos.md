# L53 — arista_eos

- **Date measured:** 2026-11-06
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-arista_eos.pcap` — 425 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL53HostKeyScan$`

## Claim

The SSH host key the device presents to a scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (06:32:09-06:32:09 UTC) read a `ssh-rsa` key, SHA256:6X283nBLz9fIahOaLTpSOMgIGO1LNcCL0H+ZIqNuAPY. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show management ssh hostkey ed25519 public`: not this key.

```
show management ssh hostkey ed25519 public
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKBGNxdCnkTcwVWACrG/huSJ3P1FxJ4s+xOkSxCM67F9 chassisAddr=0c:00:e6:ae:f4:89
leaf1#
```

`show management ssh hostkey ecdsa-nistp256 public`: not this key.

```
show management ssh hostkey ecdsa-nistp256 public
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGCzfpfztzd48QXjfLVDxGILD4N21+vN3e5nQzXWgKynDcYINpSMTg1HGEwpPKFo1ciSlwk3ZtEV2Z++GsPFx2M= chassisAddr=0c:00:e6:ae:f4:89
leaf1#
```

`show management ssh hostkey rsa public`: base64 key.

```
show management ssh hostkey rsa public
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvPoyTsjatT5bylGlHQHeD1vEi/hMTT4Jp4behNnv7I60nE5GXU+hHAw9/1D19HGlb+hFCiqXbDtlk+t0qn0GOSmGifHlbjnToJnWwpLmnzINqdta+855shSgf8FsDkuPafMSgiNmjmRyQ7QwBxISlHOD6twNTDkYcHK3HoNRtpKzRTW0tTQLJSGPIgnDq0EklCg9UopINzFvTtzsakTTrnrboyoiW6pHsG7kfWhsO6zgBA+vOFYQqu0f/xv0DotR6NlqsqmXReByj825MGRbJOq9O8oak9A//eLryeOnu7KzTgPzzyYoQSRtpFJdKMrN+IWHuSOV64wNwiRfWawXX chassisAddr=0c:00:e6:ae:f4:89 keySize=2048
leaf1#
```

Before the reload, `show version` says: ["Uptime: 1 minute\r"].

`show logging`: 19 lines it has now that it did not before the scan. Host windows (UTC): scan 06:32:09-06:32:09, control login 06:32:19-06:32:20.

**The control, a refused login as `l53-control`, is not in this log** (no line matching `l53-control` within 10s of its window): it records no failed login, so its silence about the scan means nothing, and **the log clause is UNMEASURED here**.

By step: scan 1, control 0, before the scan 1, between the scan and the control 0, after the control 17, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Nov  6 06:32:09 leaf1 Stp: %SPANTREE-6-STABLE_CHANGE: Stp state is now stable
```

The last 30 lines, each with its step:

```
[before the scan] Nov  6 06:31:58 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[scan] Nov  6 06:32:09 leaf1 Stp: %SPANTREE-6-STABLE_CHANGE: Stp state is now stable
[after the control] Nov  6 06:32:24 leaf1 Aaa: %AAA-4-AUTHN_FALLBACK: Authentication method 'group port49' is currently unavailable; falling back to next method for service 'sshd' for user breakglass.
[after the control] Nov  6 06:32:24 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[after the control] Nov  6 06:32:24 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'exec' for user breakglass.
[after the control] Nov  6 06:32:24 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:24 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:25 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:26 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:26 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:26 leaf1 Aaa: %AAA-4-AUTHZ_FALLBACK: Authorization method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
[after the control] Nov  6 06:32:26 leaf1 Aaa: %AAA-4-ACCT_FALLBACK: Accounting method 'group port49' is currently unavailable; falling back to next method for action 'command15' for user breakglass.
```

`bash sudo cat /var/log/secure`: 13 lines it has now that it did not before the scan. Host windows (UTC): scan 06:32:09-06:32:09, control login 06:32:19-06:32:20.

The control, a refused login as `l53-control` (host 06:32:19-06:32:20), is in the log as the line matching `l53-control` nearest its window, stamped 06:32:19 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    Nov  6 06:32:19 leaf1 sshd[2871]: Connection closed by authenticating user l53-control 172.100.100.1 port 55524 [preauth]

By step: scan 1, control 1, before the scan 4, between the scan and the control 0, after the control 7, no time 0. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
Nov  6 06:32:08 leaf1 sshd[2866]: Connection closed by 172.100.100.1 port 37798 [preauth]
```

The last 30 lines, each with its step:

```
[before the scan] Nov  6 06:31:58 leaf1 sudo: pam_unix(sudo:session): session closed for user root
[before the scan] Nov  6 06:31:58 leaf1 sshd[2772]: pam_unix(sshd:session): session closed for user breakglass
[before the scan] Nov  6 06:32:00 leaf1 sshd[2852]: Did not receive identification string from 172.100.100.1 port 32900
[before the scan] Nov  6 06:32:03 leaf1 sshd[2865]: Did not receive identification string from 172.100.100.1 port 38186
[scan] Nov  6 06:32:08 leaf1 sshd[2866]: Connection closed by 172.100.100.1 port 37798 [preauth]
[control] Nov  6 06:32:19 leaf1 sshd[2871]: Connection closed by authenticating user l53-control 172.100.100.1 port 55524 [preauth]
[after the control] Nov  6 06:32:24 leaf1 sshd[2882]: Accepted keyboard-interactive/pam for breakglass from 172.100.100.1 port 55534 ssh2
[after the control] Nov  6 06:32:24 leaf1 sshd[2882]: pam_unix(sshd:session): session opened for user breakglass by (uid=0)
[after the control] Nov  6 06:32:25 leaf1 sudo: breakglass : TTY=pts/5 ; PWD=/home/breakglass ; USER=root ; COMMAND=/usr/bin/ssh-keygen -lf /persist/secure/ssh_host_rsa_key.pub
[after the control] Nov  6 06:32:25 leaf1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
[after the control] Nov  6 06:32:25 leaf1 sudo: pam_unix(sudo:session): session closed for user root
[after the control] Nov  6 06:32:26 leaf1 sudo: breakglass : TTY=pts/5 ; PWD=/home/breakglass ; USER=root ; COMMAND=/usr/bin/cat /var/log/secure
[after the control] Nov  6 06:32:26 leaf1 sudo: pam_unix(sudo:session): session opened for user root by (uid=0)
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

The reload command was sent at 06:32:28; the device was seen down (no SSH banner on two connections in a row) at 06:32:32, and was serving SSH authentication again no later than 58s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show version` says: ["Uptime: 0 minutes\r"].

The device rebooted: true (uptime 1m0s, then 0s after 1m5s).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:6X283nBLz9fIahOaLTpSOMgIGO1LNcCL0H+ZIqNuAPY).
