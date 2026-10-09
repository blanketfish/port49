# L53 — cisco_iosxe

- **Date measured:** 2026-10-09
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L53L54-cisco_iosxe.pcap` — 998 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L53L54-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `74ec20276ee4c41b6e2e2e420864a47a41229e59`, `PORT49_LAB_PLATFORMS=iosxe`, `-run TestL53L54PortSSH`

## Claim

The SSH host key the device presents to port49 devices trust's scan, the console's view of it, whether it survives a reload, and what the scan leaves (policy engine spec §15, L53).

## Observation

The window of 10s before the scan, its baseline: 0 decision records, and 0 TACACS+ packets to or from the device in the capture.

The scan read a `ssh-rsa` key, SHA256:fSKEhew9YpJnJjhYP3tXXcfe9VOplfXVGiJX4JE1BRY.

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
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCQIvG+KJ6I4hWvFibtPXlqf8hRBtzlUoSbzNUs2mtn
ADZGk+OLx8MxYfiqTXk2g6kQFFNAPXdXhJeD56n+r9Ex9asgACXY3VkslWfwKf1XqctSPSnjVmCAWv4M
j9moNr6nNdo42NAaGpgwbJ3AVoknvYu+kIvyO21es9mbcoEBvgqKaAps0NCVa055VFGhyZhWgQMEcEt4
ut9M47K0mTxSowy9Rq4guRmIKYpHnCsV4tOsFb9QzXD7y6Dhh/e9C5id8kwK98siPrZL8NEDRlBNMFQY
Y/F93w4JxwYIZeOpEHenGwDNyhw7TZQGkmuvNlvFqneKndYOw/b7gdZtE+bP                    
xe1#
```

`show crypto key mypubkey rsa`: hex DER key.

```
show crypto key mypubkey rsa
% Key pair was generated at: 18:12:59 UTC Oct 9 2026
Key name: xe1.example.com
Key type: RSA KEYS      2048 bits
 Storage Device: private-config
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101 
  009022F1 BE289E88 E215AF16 26ED3D79 6A7FC851 06DCE552 849BCCD5 2CDA6B67 
  00364693 E38BC7C3 3161F8AA 4D793683 A9101453 403D7757 849783E7 A9FEAFD1 
  31F5AB20 0025D8DD 592C9567 F029FD57 A9CB523D 29E35660 805AFE0C 8FD9A836 
  BEA735DA 38D8D01A 1A98306C 9DC05689 27BD8BBE 908BF23B 6D5EB3D9 9B728101 
  BE0A8A68 0A6CD0D0 956B4E79 5451A1C9 98568103 04704B78 BADF4CE3 B2B4993C 
  52A30CBD 46AE20B9 1988298A 479C2B15 E2D3AC15 BF50CD70 FBCBA0E1 87F7BD0B 
  989DF24C 0AF7CB22 3EB64BF0 D1034650 4D305418 63F17DDF 0E09C706 0865E3A9 
  1077A71B 00CDCA1C 3B4D9406 926BAF36 5BC5AA77 8A9DD60E C3F6FB81 D66D13E6 
  CF020301 0001
% Key pair was generated at: 18:13:02 UTC Oct 9 2026
Key name: xe1.example.com.server
Key type: RSA KEYS      2176 bits
Temporary key
 Usage: Encryption Key
 Key is not exportable.
 Key Data:
  30820132 300D0609 2A864886 F70D0101 01050003 82011F00 3082011A 02820111 
  00AE7EC6 3941C9D6 660CBA8C 99F50D23 BD18AA28 337CB6E9 02DDB228 3C98B51A 
  10BCDE27 C314ECFD CD157456 B7BB8CCE B824E84E 7B8DE4AD 67909860 92BD2D29 
  E280FFCB 6065AAA9 AB6894A2 5E3C927B 8ADDE570 1741AF1E 89A8CEF2 2C92CB18 
  CF0ACA9D C2E42D3C 22087857 7018A20E 0C6631BD EBD180DA 8F4DE046 4A385E6C 
  323CDDAD 760123DF 1ED77B87 52A83CDD 0F592C34 A996D34D AF086F19 849333D9 
  C486615D DAC38B67 ECA6A847 B9525F84 5B129CB0 C24A5CF1 E04412F3 B0E58902 
  B4C524B6 00EDF7A9 4C15401E 59227828 2BFBC9A9 1E8037EC 69A5289C 57521831 
  7827D733 8740C0EB 4FE2564B 032077CF 9114DE14 EC43AC90 608E7B76 1FC701CD 
  1AA39C4C 226E872D 1CB68AB9 C35C29C1 F9020301 0001
% Key pair was generated at: 18:13:16 UTC Oct 9 2026
Key name: TP-self-signed-214562003
Key type: RSA KEYS      2048 bits
 Storage Device: private-config
 Usage: General Purpose Key
 Key is not exportable. Redundancy enabled.
 Key Data:
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101 
  00EBEBBC 938CAA9A 8174BF76 95D11FAC 0660F69B 871BC204 C96B3BA0 10D5DBFA 
  1A6FDEF2 2AFCAE7D 99DCCB88 6CF66090 9E018EC2 E9AE0DCE D0DC9717 BDCEE08F 
  5B7683E1 873000A6 C15B80CC 0F65FE0F A77D7C1D 1650CFB5 FBE8CB7E 9AD2FF89 
  AB6FB2B8 229A2207 B7CFB4F5 C45A937F 0943038E 293E44E8 6493B14B AEDBF081 
  91CE91A9 47DFD815 69BD104C B16116B9 BA3E681D DEC4AC36 E77A6446 06FCF04E 
  6FE98AAA 8E6D1430 4D5671B3 57C47511 FEAF30D5 B75506BC 7A760484 0C72B590 
  0894F436 F5F5F3C2 1CB0847E 82D0FF06 A98B92F2 607A7131 51E6E87A C5C7FCAD 
  098D46BB B0CD7469 8A37EDD8 9FD54CCA CC386656 820126BA BADDD8CA C017C497 
  AD020301 0001
xe1#
```

Before the reload, `show version` says: ["xe1 uptime is 1 minute\r" "Uptime for this control processor is 2 minutes\r"].

`show logging`: 18 lines it has now that it did not before the scan (the break-glass login that read it is among them), the last 30:

```
Console logging: level debugging, 132 messages logged, xml disabled,
Buffer logging:  level debugging, 132 messages logged, xml disabled,
Trap logging: level informational, 135 message lines logged
*Oct  9 18:13:30.423: %DMI-5-SYNC_NEEDED: R0/0: dmiauthd: Configuration change requiring running configuration sync detected - 'Initial sync'. The running configuration will be synchronized  to the NETCONF running data store.
*Oct  9 18:13:30.556: %DMI-5-SYNC_START: R0/0: dmiauthd: Synchronization of the running configuration to the NETCONF running data store has started.
*Oct  9 18:13:31.232: %SYS-6-LOGOUT: User breakglass has exited tty session 434(172.100.100.1)
*Oct  9 18:13:31.232: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
*Oct  9 18:13:31.496: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
*Oct  9 18:13:31.671: %DMI-5-SYNC_COMPLETE: R0/0: dmiauthd: The running configuration has been synchronized to the NETCONF running data store.
*Oct  9 18:13:37.004: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
*Oct  9 18:13:37.004: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
*Oct  9 18:13:47.370: %SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived. Terminating the connection from 172.100.100.1
*Oct  9 18:13:47.370: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
*Oct  9 18:13:47.370: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
*Oct  9 18:13:57.633: %SSH-5-SSH2_SESSION: SSH2 Session request from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
*Oct  9 18:13:57.644: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: breakglass] [Source: 172.100.100.1] [localport: 22] at 18:13:57 UTC Fri Oct 9 2026
*Oct  9 18:13:57.644: %SSH-5-SSH2_USERAUTH: User 'breakglass' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Succeeded
*Oct  9 18:13:57.647: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
```

With `login block-for 60 attempts 2 within 60` set (and 70s waited, so the harness's own failed probe logins after the daemon's restart were out of its window): three scans, then a login with a fresh token: it succeeded. The control, two refused logins as `slice01`, the user the login uses, and then a login with a fresh token: it was refused (ssh: handshake failed: read tcp 172.100.100.1:47152->172.100.100.41:22: read: connection reset by peer).

The reload command was sent at 18:18:10; the device was seen down (no SSH banner on two connections in a row) at 18:18:22, and serving SSH authentication again 1m38s later.

After the reload, `show version` says: ["xe1 uptime is 0 minutes\r" "Uptime for this control processor is 1 minute\r"].

After a reload with the configuration saved, the device seen down and back, the key is the same (SHA256:fSKEhew9YpJnJjhYP3tXXcfe9VOplfXVGiJX4JE1BRY).
