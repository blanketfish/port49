# L53 — cisco_iosxe

- **Date measured:** 2026-11-06
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-cisco_iosxe.pcap` — 910 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,vsrx,nxos,iosxe`, `-run ^TestL53HostKeyScan$`

## Claim

The SSH host key the device presents to a scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (06:51:10-06:51:10 UTC) read a `ssh-rsa` key, SHA256:IhGkfXEk1RB5i8WoSpgYeVcSeUlbhfIG7KkeHjhVRDI. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

Within 10s of the scan: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

`show ip ssh`: base64 key.

```
show ip ssh
SSH Enabled - version 2.0
Authentication methods:publickey,keyboard-interactive,password
Authentication Publickey Algorithms:ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-ed25519,x509v3-ecdsa-sha2-nistp256,x509v3-ecdsa-sha2-nistp384,x509v3-ecdsa-sha2-nistp521,rsa-sha2-256,rsa-sha2-512,x509v3-rsa2048-sha256
Hostkey Algorithms:rsa-sha2-512,rsa-sha2-256,ssh-rsa
Encryption Algorithms:chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-gcm,aes256-gcm,aes128-ctr,aes192-ctr,aes256-ctr
MAC Algorithms:hmac-sha2-512
KEX Algorithms:curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512
Authentication timeout: 120 secs; Authentication retries: 3
Minimum expected Diffie Hellman key size : 2048 bits
IOS Keys in SECSH format(ssh-rsa, base64 encoded): xe1.example.com
Modulus Size : 2048 bits
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCL8yqXIMK4ox6E5CEe2gsohN4qq/qZn8c/sOjLR5pD
GF71W/t8WWUsaSiAb3M2UWGK7Cdnqs61AxJbip+GUi6FIZ84YhzM+2OyltSkAo1cmqkCWCuCd9O0nQsj
g/qKtnS/tIB9gdGsE9aAkUNww0XUQgwRmY9E4JT9p+yI0+SledZBgfHUzkd4cn+hfJp3PkrPwXxZM0Bp
LTpU0WLTNNj9CcOWdnwarPvvg6GyulK4uzULZ3Zbiy3GYbth4bI05Io+3KbLxQTSWL1Bb4d8E/79LA4U
f/6j8gEvL9KIHD3fZm/xMuVinPHXXcvJPSKu3KG/lJd8X1YqJErbrm69uusL                    
xe1#
```

`show crypto key mypubkey rsa`: hex DER key.

```
show crypto key mypubkey rsa
% Key pair was generated at: 06:50:25 UTC Nov 6 2026
Key name: xe1.example.com
Key type: RSA KEYS      2048 bits
 Storage Device: private-config
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101 
  008BF32A 9720C2B8 A31E84E4 211EDA0B 2884DE2A ABFA999F C73FB0E8 CB479A43 
  185EF55B FB7C5965 2C692880 6F733651 618AEC27 67AACEB5 03125B8A 9F86522E 
  85219F38 621CCCFB 63B296D4 A4028D5C 9AA90258 2B8277D3 B49D0B23 83FA8AB6 
  74BFB480 7D81D1AC 13D68091 4370C345 D4420C11 998F44E0 94FDA7EC 88D3E4A5 
  79D64181 F1D4CE47 78727FA1 7C9A773E 4ACFC17C 59334069 2D3A54D1 62D334D8 
  FD09C396 767C1AAC FBEF83A1 B2BA52B8 BB350B67 765B8B2D C661BB61 E1B234E4 
  8A3EDCA6 CBC504D2 58BD416F 877C13FE FD2C0E14 7FFEA3F2 012F2FD2 881C3DDF 
  666FF132 E5629CF1 D75DCBC9 3D22AEDC A1BF9497 7C5F562A 244ADBAE 6EBDBAEB 
  0B020301 0001
% Key pair was generated at: 06:50:28 UTC Nov 6 2026
Key name: xe1.example.com.server
Key type: RSA KEYS      2176 bits
Temporary key
 Usage: Encryption Key
 Key is not exportable.
 Key Data:
  30820132 300D0609 2A864886 F70D0101 01050003 82011F00 3082011A 02820111 
  008F77EF 9D84F779 4CF9E02B E8A7C3AB DF33ED4F DAFD3810 D90F0CB1 39F4EB3A 
  DC07484C AA68FB95 AE5A9AF3 EBDC8C94 3AD88993 8A39DCC9 D419ECE9 5DC9AFED 
  895AEDB9 1E370F6A D57C703A 8B8DB637 EA0EA42F F644B7FB 67C7C096 4B56D618 
  73DEE183 F1C8F2BD A1A383C5 5D772FC6 680B9AA6 0A1E112A C0A1E848 30487FDC 
  CB0BE3CD CC0CE5C8 8206D176 F296A860 EA9B6B86 B187306F AF38739C CCCAB6A2 
  BA944222 684EDAA4 8E5AE304 AA9AFABD F38BF9D4 56F8F751 1C2DB422 B10FF08A 
  10115D7E F6A3E6BF 2C7B2946 758BE65B 11D63DB0 C3AC025A B4709240 F7840BC4 
  8551422B C77C3F75 B18B2441 BAD471E8 AC58FC4E BAFE8F26 E5ABB3CA E9D24D6E 
  D068FEEC 06A5C0EE 03AA9B38 F142B4C1 73020301 0001
% Key pair was generated at: 06:50:42 UTC Nov 6 2026
Key name: TP-self-signed-214562003
Key type: RSA KEYS      2048 bits
 Storage Device: private-config
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101 
  00BCF03F C2834AE3 24B56CB5 F3BA5D82 24537A8F 25BC2272 1B2C8476 271A106B 
  A2C4D70F EB427CE9 F84868DE F6128FDF 7B128A63 8B761B86 CA4A038F 14637DC4 
  BB7AE613 0689DAEC 87FF7036 DFCB8E4D 38E03E80 60A6378B 950B6612 782E14F5 
  CFF51A38 D8B42403 12BDCE75 7FB50238 952CB6F4 09B14B30 889C60E2 1B51C7F7 
  8E7A289E 6EF096B7 E22D01B7 7E76A5DE 8880EC11 8FF9D363 EED8F96D 6868D018 
  70796DE4 13471333 D719A8BA 28A98FDA 6D9C971F 481F3400 72B9F9AB D1D98F0E 
  DC9A1B96 5D4F4CEF A774C65B B389489E D854D028 A088919E B8A1F64F 2B156FE0 
  A8BCE558 507B3D6C 8A75A1D9 5D40C71C 49A2A396 810B302B 9D708436 5B16EACD 
  61020301 0001
xe1#
```

Before the reload, `show version` says: ["xe1 uptime is 1 minute\r" "Uptime for this control processor is 2 minutes\r"].

`show logging`: 26 lines it has now that it did not before the scan. Host windows (UTC): scan 06:51:10-06:51:10, control login 06:51:20-06:51:26.

The control, a refused login as `l53-control` (host 06:51:20-06:51:26), is in the log as the line matching `SSH2_USERAUTH: User '' .*Failed` nearest its window, stamped 06:51:26.015 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    *Nov  6 06:51:26.015: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed

By step: scan 3, control 3, before the scan 13, between the scan and the control 0, after the control 4, no time 3. The break-glass login that read the log is among the lines.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
*Nov  6 06:51:10.281: %SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived. Terminating the connection from 172.100.100.1
*Nov  6 06:51:10.281: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
*Nov  6 06:51:10.281: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
```

The last 30 lines, each with its step:

```
[no time] Console logging: level debugging, 138 messages logged, xml disabled,
[no time] Buffer logging:  level debugging, 138 messages logged, xml disabled,
[no time] Trap logging: level informational, 141 message lines logged
[before the scan] *Nov  6 06:50:53.323: %SSH-5-SSH2_USERAUTH: User 'breakglass' authentication for SSH2 Session from 172.100.100.1 (tty = 1) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[before the scan] *Nov  6 06:50:54.077: %SYS-6-LOGOUT: User breakglass has exited tty session 435(172.100.100.1)
[before the scan] *Nov  6 06:50:54.077: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 1) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[before the scan] *Nov  6 06:50:54.345: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[before the scan] *Nov  6 06:50:54.500: %PKI-6-TRUSTPOINT_CREATE: Trustpoint: SLA-TrustPoint created succesfully
[before the scan] *Nov  6 06:50:54.501: %PKI-6-CONFIGAUTOSAVE: Running configuration saved to NVRAM
[before the scan] *Nov  6 06:50:55.329: %SYS-6-PRIVCFG_ENCRYPT_SUCCESS: Successfully encrypted private config file
[before the scan] *Nov  6 06:50:57.208: %DMI-5-NACM_INIT: R0/0: dmiauthd: NACM configuration has been set to its initial configuration.
[before the scan] *Nov  6 06:50:58.940: %DMI-5-SYNC_NEEDED: R0/0: dmiauthd: Configuration change requiring running configuration sync detected - 'Initial sync'. The running configuration will be synchronized  to the NETCONF running data store.
[before the scan] *Nov  6 06:50:59.058: %DMI-5-SYNC_START: R0/0: dmiauthd: Synchronization of the running configuration to the NETCONF running data store has started.
[before the scan] *Nov  6 06:50:59.907: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
[before the scan] *Nov  6 06:50:59.907: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[before the scan] *Nov  6 06:51:00.196: %DMI-5-SYNC_COMPLETE: R0/0: dmiauthd: The running configuration has been synchronized to the NETCONF running data store.
[scan] *Nov  6 06:51:10.281: %SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived. Terminating the connection from 172.100.100.1
[scan] *Nov  6 06:51:10.281: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
[scan] *Nov  6 06:51:10.281: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[control] *Nov  6 06:51:20.506: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[control] *Nov  6 06:51:26.015: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
[control] *Nov  6 06:51:26.015: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[after the control] *Nov  6 06:51:31.053: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[after the control] *Nov  6 06:51:31.064: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: breakglass] [Source: 172.100.100.1] [localport: 22] at 06:51:31 UTC Fri Nov 6 2026
[after the control] *Nov  6 06:51:31.064: %SSH-5-SSH2_USERAUTH: User 'breakglass' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[after t
... (truncated for this note; the full answer is in the test log)
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

With `login block-for 60 attempts 2 within 60` set (and 70s waited, so the harness's own failed probe logins after the daemon's restart were out of its window): three scans, then a login with a fresh token: it succeeded. The control, two refused logins as `slice01`, the user the login uses, and then a login with a fresh token: it was refused (ssh: handshake failed: read tcp 172.100.100.1:50526->172.100.100.41:22: read: connection reset by peer).

The reload command was sent at 06:55:23; the device was seen down (no SSH banner on two connections in a row) at 06:55:35, and was serving SSH authentication again no later than 1m38s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show version` says: ["xe1 uptime is 0 minutes\r" "Uptime for this control processor is 1 minute\r"].

The device rebooted: true (uptime 1m0s, then 0s after 5m42s).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:IhGkfXEk1RB5i8WoSpgYeVcSeUlbhfIG7KkeHjhVRDI).
