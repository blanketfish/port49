# L53 — cisco_nxos

- **Date measured:** 2026-11-06
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-cisco_nxos.pcap` — 744 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL53HostKeyScan$`

## Claim

The SSH host key the device presents to a scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (06:44:24-06:44:24 UTC) read a `ssh-rsa` key, SHA256:0m22Srf8XqjyOpeDGGZszPcEb6M+Ci5JSL9yeTVkvRs. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show ssh key`: base64 key.

```
show ssh key
**************************************
rsa Keys generated:Fri Nov  6 06:43:28 2026

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDhSn4cN9I2rQS3etZhuGU6vhSggDZ02bKelM8AXXtEeqHzx8VVCVbNWZL0NFyEba5WlX+BkTqWJ+8v6IfdSntMphpaMR94Wkq6+cHN+sNKiNdfslco3OkWSXwSKIY7OestrHLkqp+kV2KZyk7FRRcJyaJCIzXyQsxWGrd0WhYdR/q92awcnmV7yJlhcJjvEILdZ9WLLi1v85fP2mDg1ZbaG91cUAdevmUcZiSV9bfvELBNUn9Mm7qHydWVM1MZOe8P6gjfd7qQiqTpVdxySbrUmx7CgHpBRbTSRNFU4kzhA1RSSdLZ3+QzIrDSZEQsNB8Za2N7G6UVNCwJ4aYQgTM5

bitcount:2048
fingerprint:
SHA256:0m22Srf8XqjyOpeDGGZszPcEb6M+Ci5JSL9yeTVkvRs
**************************************
could not retrieve dsa key information
**************************************
could not retrieve ecdsa key information
**************************************
nx1# 
```

Before the reload, `show version` says: ["Kernel uptime is 0 day(s), 0 hour(s), 3 minute(s), 36 second(s)\r"].

`show logging logfile`: 5 lines it has now that it did not before the scan. Host windows (UTC): scan 06:44:24-06:44:24, control login 06:44:34-06:44:36.

The control, a refused login as `l53-control` (host 06:44:34-06:44:36), is in the log as the line matching `PAM: Authentication failure for illegal user` nearest its window, stamped 06:44:34 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    2026 Nov  6 06:44:34 nx1 %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user ***** from 172.100.100.1 - dcos_sshd[14741]

By step: scan 0, control 4, before the scan 0, between the scan and the control 0, after the control 1, no time 0. No line names the break-glass login that read the log.

No line is stamped inside the scan's window.

The last 30 lines, each with its step:

```
[control] 2026 Nov  6 06:44:33 nx1 %TACACS-3-TACACS_ERROR_MESSAGE: All servers failed to respond (message repeated 6 times)
[control] 2026 Nov  6 06:44:33 nx1 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 172.100.100.1 - dcos_sshd[14741]
[control] 2026 Nov  6 06:44:34 nx1 %AUTHPRIV-3-SYSTEM_MSG: pam_aaa:Authentication failed from 172.100.100.1 - dcos_sshd[14743]
[control] 2026 Nov  6 06:44:34 nx1 %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user ***** from 172.100.100.1 - dcos_sshd[14741]
[after the control] 2026 Nov  6 06:44:40 nx1 %TACACS-3-TACACS_ERROR_MESSAGE: All servers failed to respond
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

With `aaa authentication rejected 2 in 60 ban 60` set (and 70s waited, so the harness's own failed probe logins after the daemon's restart were out of its window): three scans, then a login with a fresh token: it succeeded. The control, two refused logins as `slice01`, the user the login uses, and then a login with a fresh token: it was refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain).

The reload command was sent at 06:47:31; the device was seen down (no SSH banner on two connections in a row) at 06:47:47, and was serving SSH authentication again no later than 1m12s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show version` says: ["Kernel uptime is 0 day(s), 0 hour(s), 1 minute(s), 10 second(s)\r"].

The device rebooted: true (uptime 3m36s, then 1m10s after 4m19s).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:0m22Srf8XqjyOpeDGGZszPcEb6M+Ci5JSL9yeTVkvRs).
