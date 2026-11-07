# L64 — juniper_vsrx

- **Date measured:** 2026-11-07
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-juniper_vsrx.pcap` — 1560 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `08a6f6e8db258b255baf8613fcc6d42eafb00bd6`, `PORT49_LAB_PLATFORMS=vsrx`, `-run ^TestL64L65$`

## Claim

`port49 ssh` under OpenSSH's accept-new against juniper_vsrx (policy engine spec §15, L64): (a) a first contact, (b) after a reload, (c) a replaced key of the filed type, (d) a key of another type only.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 08a6f6e8db258b255baf8613fcc6d42eafb00bd6 into the shared lab venv.

The 10s before the first cell: 7 decision records and 140 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L64a | PASS | 6.5s |
| L64b | PASS | 1m35.7s |
| L64c | PASS | 16.5s |
| L64d | PASS | 16.6s |

### L64a: PASS

`port49 ssh -v vsrx1 -- show version` with an empty known_hosts: exit 0; 51 lines of output; ssh tried [keyboard-interactive], authenticated by `keyboard-interactive`; 1 askpass asks (the keyboard-interactive and password methods tried); 1 redeem records; 164 TACACS+ packets in the window (the positive control: it must be above 0); records: blob x1, mint x1, redeem x1, authorize_session x1, account x6. ssh: accepted. After the login `ssh-keygen -F vsrx1` finds 1 line(s), of key types [ssh-ed25519] (a read error: <nil>); the file holds 1 line(s).

```
Warning: Permanently added 'vsrx1' (ED25519) to the list of known hosts.
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.22 ([172.100.100.22]:22) using "keyboard-interactive".
```

### L64b: PASS

The device rebooted: true (System booted 2026-11-07 10:28:59 UTC, then 2026-11-07 10:30:51 UTC). The scan's key is the same after the reload (SHA256:Wp169NS6nGjWgf2I5NTpO+C/Z92q/z7DwPk04c06bVc).

The filed lines (type and key, compared with the host field left out) before the reload: 1; after: 2; added by the login: ecdsa-sha2-nistp256; gone after it: none.

```
reload step "request system reboot": err <nil>; the device said:
request system reboot 
Reboot the system ? [yes,no] (no) 
after the answer "yes", the device said:
yes 

                                                                               
*** FINAL System shutdown message from breakglass@srx1 ***                   

System going down IMMEDIATELY                                                  

                                                                               
Shutdown NOW!
[pid 28955]

breakglass@srx1> 
The reload command was sent at 10:30:19; the device was seen down (no SSH banner on two connections in a row) at 10:30:23, and was serving SSH authentication again no later than 1m22s after that.
Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-11-07 10:28:59 UTC (00:01:19 ago)\r"]. After: ["show system uptime \r" "System booted: 2026-11-07 10:30:51 UTC (00:00:54 ago)\r"].
```

The 10s before the first cell: 7 decision records and 140 TACACS+ packets to or from the device.

After it, `port49 ssh -v vsrx1 -- show version`: exit 0; 51 lines of output; 164 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account account account account account account]; ssh: clean; the warning banner is present: false.

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.22 ([172.100.100.22]:22) using "keyboard-interactive".
debug1: client_input_hostkeys: searching /tmp/p49l64home4183616505/.ssh/known_hosts for vsrx1 / (none)
Learned new hostkey: ECDSA SHA256:yvHmUvytA30gn7FJx83V+ExFs/p8sjONTwvEshpPIzs
```

### L64c: PASS

`port49 ssh` against an entry replaced by a fresh `ssh-ed25519` key: exit 255; ssh: changed (filed type "ED25519", sent type "ED25519"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the ED25519 key sent by the remote host is
Offending ED25519 key in /tmp/p49l64home4183616505/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home4183616505/.ssh/known_hosts' -R 'vsrx1'
Host key for vsrx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before vsrx1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under vsrx1 is not the one 172.100.100.22 presents: either the device's key changed, or the address inventory gives for vsrx1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home4183616505/.ssh/known_hosts -R vsrx1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

### L64d: PASS

`port49 ssh` against an entry replaced by a `ssh-rsa` key, a type other than the filed `ssh-ed25519`: exit 255; ssh: changed (filed type "RSA", sent type "RSA"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the RSA key sent by the remote host is
Offending RSA key in /tmp/p49l64home4183616505/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home4183616505/.ssh/known_hosts' -R 'vsrx1'
Host key for vsrx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before vsrx1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under vsrx1 is not the one 172.100.100.22 presents: either the device's key changed, or the address inventory gives for vsrx1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home4183616505/.ssh/known_hosts -R vsrx1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

