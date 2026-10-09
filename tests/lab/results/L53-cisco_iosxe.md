# L53 — cisco_iosxe

- **Date measured:** 2026-10-09
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-cisco_iosxe.pcap` — 1057 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0a5e9d30b6e6962340b6ca26d0085f0b9dd68211`, `PORT49_LAB_PLATFORMS=iosxe`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan (20:08:38-20:08:38 UTC) read a `ssh-rsa` key, SHA256:MgVxK/hSaREdYgPmTjUy1QzTQI8QdNpUlJ/VXTJdWQE. The host-key algorithm the device signed with when offered what the scan offers: `rsa-sha2-256`.

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
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCs0hQoWDU/phyeOqMbPii0r8Jgo0zTGLtAuYhQxjYM
VjiVX2wAxh7gEjn0eluXJd/ht84ajbnP4xZldIkczE/M1oBC/OR8ylJo9O0uLf2BVvA56mwDDJFaxA0q
QGJYIizMIsGr9isX+B71miXwY8g3qGAEe3F7197/ehiGe+MvWmtrnXgXVdyAAtTaaPLYNRRZ515m1oky
bWWZYIANetFIfq4EhA0uw0Osrc8aKyXyGSjmoacbMFpkHGTJ46m2W369of/WtuFYBno42iH+HlWxedPO
nEM4yqoI0K8f0q+YvXFwwlpTB7I9zMGOx7eiM5SlWQ+lk91jx41W90GR94NJ                    
xe1#
```

`show crypto key mypubkey rsa`: hex DER key.

```
show crypto key mypubkey rsa
% Key pair was generated at: 20:07:49 UTC Oct 9 2026
Key name: xe1.example.com
Key type: RSA KEYS      2048 bits
 Storage Device: private-config
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101 
  00ACD214 2858353F A61C9E3A A31B3E28 B4AFC260 A34CD318 BB40B988 50C6360C 
  5638955F 6C00C61E E01239F4 7A5B9725 DFE1B7CE 1A8DB9CF E3166574 891CCC4F 
  CCD68042 FCE47CCA 5268F4ED 2E2DFD81 56F039EA 6C030C91 5AC40D2A 40625822 
  2CCC22C1 ABF62B17 F81EF59A 25F063C8 37A86004 7B717BD7 DEFF7A18 867BE32F 
  5A6B6B9D 781755DC 8002D4DA 68F2D835 1459E75E 66D68932 6D659960 800D7AD1 
  487EAE04 840D2EC3 43ACADCF 1A2B25F2 1928E6A1 A71B305A 641C64C9 E3A9B65B 
  7EBDA1FF D6B6E158 067A38DA 21FE1E55 B179D3CE 9C4338CA AA08D0AF 1FD2AF98 
  BD7170C2 5A5307B2 3DCCC18E C7B7A233 94A5590F A593DD63 C78D56F7 4191F783 
  49020301 0001
% Key pair was generated at: 20:07:52 UTC Oct 9 2026
Key name: xe1.example.com.server
Key type: RSA KEYS      2176 bits
Temporary key
 Usage: Encryption Key
 Key is not exportable.
 Key Data:
  30820132 300D0609 2A864886 F70D0101 01050003 82011F00 3082011A 02820111 
  00D8A453 D598B1C7 08D24513 30A8DFCF 8B6C1128 EDA25767 3516B1D8 BF6FF59D 
  9047390E B4A299D7 F2494C5E 84EC6967 F2125E5B A890D140 386A4115 A207E4E8 
  67B1A249 05C2B1F7 5DEBFB52 B248153B C01CF6CE EB24F445 852160B7 6F1D11BD 
  EFE051A3 4DB208AA 168481E6 CF419E44 48E22311 67D72767 7C1C585F 7E46F6A0 
  765A3265 89E38A4A 1B6E6865 7169241D 43D6D829 BF065E7C E5289462 FAB9908B 
  FBD9CA26 863F37D1 DB3E1C30 9C4152D4 BF280823 3C8948DE DD0FA83A CC4A4068 
  D6239D3A 53BD5F00 2AAFFECC B1ADB0F4 225C259C CF81786A BCA131D2 35393896 
  79507715 1773488A 29815E41 F939EEB5 10BF2149 1ECECA22 7F514CF8 D198408C 
  4CD8C68F 58188A77 08D7227B 5AE8D6EA A5020301 0001
% Key pair was generated at: 20:08:07 UTC Oct 9 2026
Key name: TP-self-signed-214562003
Key type: RSA KEYS      2048 bits
 Storage Device: private-config
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101 
  009B0271 4CA04C33 4B7C77CA 43AC471D 4FE99F4E 3750A95B 8B8D67D1 45C641A4 
  8AA2E229 93742C82 FA4B5512 03F6F36B EA264AFD 8C0CB831 F82CDCD9 052EB238 
  7A67C1D3 1771EAD2 442485B1 E98F6E22 FEAA0C2F 67971367 322D4FFF 24A6134D 
  5243BBA0 4E5E3DD9 76BC2B35 C1FFE232 528042B7 10A0592F 0171A048 049E9B9C 
  FA1AE7B8 3ABCB4B7 D8C35A5B 549B07AD 041FA140 ACD5CEB1 4CC2945E 809BC356 
  9D0893A6 AB9CD857 C1869B32 54EE5DAD AC3CBA10 57B93703 4EBBB144 8598C2B2 
  B4D71A8B 52DFD055 9445C44F 69CC9125 E33667E4 EA0DF0B0 0271202D D2524569 
  07096CB1 CAB0C1B6 16A4F64C 247AF4F4 E3E18950 03E578D7 94AD2901 2C7A39F3 
  B3020301 0001
xe1#
```

Before the reload, `show version` says: ["xe1 uptime is 1 minute\r" "Uptime for this control processor is 2 minutes\r"].

`show logging`: 23 lines it has now that it did not before the scan. Host windows (UTC): scan 20:08:38-20:08:38, control login 20:08:48-20:08:53.

The control, a refused login as `l53-control` (host 20:08:48-20:08:53), is in the log as the line matching `SSH2_USERAUTH: User '' .*Failed` nearest its window, stamped 20:08:53.790 (the device's clock agrees with the host's to within 2s), so this log records a failed login:

    *Oct  9 20:08:53.790: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed

By step: scan 3, control 3, before the scan 9, between the scan and the control 0, after the control 5, no time 3. The break-glass login that read the log is among the lines. The lines tagged `[before the scan]` (20:08:22–27) are the harness's readiness probe.

Every line stamped inside the scan's window (a line there is the scan's only if it is about an SSH connection from the scanning address; the rest is the device's own):

```
*Oct  9 20:08:38.056: %SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived. Terminating the connection from 172.100.100.1
*Oct  9 20:08:38.056: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
*Oct  9 20:08:38.056: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
```

The last 30 lines, each with its step:

```
[no time] Console logging: level debugging, 139 messages logged, xml disabled,
[no time] Buffer logging:  level debugging, 139 messages logged, xml disabled,
[no time] Trap logging: level informational, 142 message lines logged
[before the scan] *Oct  9 20:08:21.162: %SSH-5-SSH2_USERAUTH: User 'breakglass' authentication for SSH2 Session from 172.100.100.1 (tty = 1) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[before the scan] *Oct  9 20:08:21.093: %DMI-5-SYNC_NEEDED: R0/0: dmiauthd: Configuration change requiring running configuration sync detected - 'Initial sync'. The running configuration will be synchronized  to the NETCONF running data store.
[before the scan] *Oct  9 20:08:21.237: %DMI-5-SYNC_START: R0/0: dmiauthd: Synchronization of the running configuration to the NETCONF running data store has started.
[before the scan] *Oct  9 20:08:21.916: %SYS-6-LOGOUT: User breakglass has exited tty session 435(172.100.100.1)
[before the scan] *Oct  9 20:08:21.916: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 1) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[before the scan] *Oct  9 20:08:22.182: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[before the scan] *Oct  9 20:08:22.371: %DMI-5-SYNC_COMPLETE: R0/0: dmiauthd: The running configuration has been synchronized to the NETCONF running data store.
[before the scan] *Oct  9 20:08:27.692: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
[before the scan] *Oct  9 20:08:27.692: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[scan] *Oct  9 20:08:38.056: %SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived. Terminating the connection from 172.100.100.1
[scan] *Oct  9 20:08:38.056: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
[scan] *Oct  9 20:08:38.056: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[control] *Oct  9 20:08:48.282: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[control] *Oct  9 20:08:53.790: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
[control] *Oct  9 20:08:53.790: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
[after the control] *Oct  9 20:08:58.829: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[after the control] *Oct  9 20:08:58.839: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: breakglass] [Source: 172.100.100.1] [localport: 22] at 20:08:58 UTC Fri Oct 9 2026
[after the control] *Oct  9 20:08:58.840: %SSH-5-SSH2_USERAUTH: User 'breakglass' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
[after the control] *Oct  9 20:08:58.842: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
[after the control] *Oct  9 20:08:58.975: %SMART_LIC-3-COMM_FAILED: Communications failure with the Cisco Smart License Utility (CSLU) : Unable to resolve server hostname/domain name
```

The log clause is measured here: the control login is in the log, so what the log holds for the scan's window is what the scan wrote.

With `login block-for 60 attempts 2 within 60` set (and 70s waited, so the harness's own failed probe logins after the daemon's restart were out of its window): three scans, then a login with a fresh token: it succeeded. The control, two refused logins as `slice01`, the user the login uses, and then a login with a fresh token: it was refused (ssh: handshake failed: read tcp 172.100.100.1:54508->172.100.100.41:22: read: connection reset by peer).

The reload command was sent at 20:13:12; the device was seen down (no SSH banner on two connections in a row) at 20:13:24, and was serving SSH authentication again no later than 1m38s after that: an upper bound, since it is read after the admin helper's daemon restart (which on IOS-XE includes a probe login) and after the readiness wait.

After the reload, `show version` says: ["xe1 uptime is 0 minutes\r" "Uptime for this control processor is 1 minute\r"].

The device rebooted: true (uptime 1m0s, then 0s after 6m3s).

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:MgVxK/hSaREdYgPmTjUy1QzTQI8QdNpUlJ/VXTJdWQE).
