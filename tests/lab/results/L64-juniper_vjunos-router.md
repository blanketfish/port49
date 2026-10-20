# L64 — juniper_vjunos-router

- **Date measured:** 2026-10-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-juniper_vjunos-router.pcap` — 2346 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `30728fa3429a1beea98251be87a16837056daa55`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestL64L65$`

## Claim

`port49 ssh` under OpenSSH's accept-new against juniper_vjunos-router (policy engine spec §15, L64): (a) a first contact, (b) after a reload, (c) a replaced key of the filed type, (d) a key of another type only.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 30728fa3429a1beea98251be87a16837056daa55 into the shared lab venv.

The 10s before the first cell: 0 decision records and 0 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L64a | PASS | 6.5s |
| L64b | PASS | 1m41.2s |
| L64c | PASS | 16.5s |
| L64d | PASS | 16.5s |

### L64a: PASS

`port49 ssh -v srx1 -- show version` with an empty known_hosts: exit 0; 91 lines of output; ssh tried [keyboard-interactive], authenticated by `keyboard-interactive`; 1 askpass asks (the keyboard-interactive and password methods tried); 1 redeem records; 104 TACACS+ packets in the window (the positive control: it must be above 0); records: blob x1, mint x1, redeem x1, authorize_session x1, account x3. ssh: accepted. After the login `ssh-keygen -F srx1` finds 1 line(s), of key types [ssh-ed25519] (a read error: <nil>); the file holds 1 line(s).

```
Warning: Permanently added 'srx1' (ED25519) to the list of known hosts.
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.21 ([172.100.100.21]:22) using "keyboard-interactive".
```

### L64b: PASS

The device rebooted: true (System booted 2026-10-20 11:40:37 UTC, then 2026-10-20 11:42:46 UTC). The scan's key is the same after the reload (SHA256:H/tC8Mxxy6L2pnATScoGGMZJ46uhDq3QWbBuEzLFFE4).

The filed lines (type and key, compared with the host field left out) before the reload: 1; after: 4; added by the login: ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521; gone after it: none.

```
reload step "request system reboot": err <nil>; the device said:
request system reboot 
Reboot the system ? [yes,no] (no) 
after the answer "yes", the device said:
yes 

                                                                               
*** FINAL System shutdown message from breakglass@srx1 ***                   

System going down IMMEDIATELY                                                  

                                                                               
Shutdown NOW!
[pid 14933]

breakglass@srx1> 
The reload command was sent at 11:42:14; the device was seen down (no SSH banner on two connections in a row) at 11:42:18, and was serving SSH authentication again no later than 1m28s after that.
Before the reload, `show system uptime` says: ["show system uptime \r" "System booted: 2026-10-20 11:40:37 UTC (00:01:35 ago)\r"]. After: ["show system uptime \r" "System booted: 2026-10-20 11:42:46 UTC (00:00:59 ago)\r"].
```

The 10s before the first cell: 0 decision records and 0 TACACS+ packets to or from the device.

After it, `port49 ssh -v srx1 -- show version`: exit 0; 91 lines of output; 624 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account account account account account account account account account account account account account account account account account account account account account account account account account account account account account]; ssh: clean; the warning banner is present: false.

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.21 ([172.100.100.21]:22) using "keyboard-interactive".
debug1: client_input_hostkeys: searching /tmp/p49l64home316647081/.ssh/known_hosts for srx1 / (none)
Learned new hostkey: ECDSA SHA256:nkmJy0ygYhdKpYOz9P2E0QXa/2+XYSf2mTq6t52ZNig
Learned new hostkey: ECDSA SHA256:qMyY0hXuejsmToBhRtUv6Rwd4W+5cSN6VdXoYVp5cNg
Learned new hostkey: ECDSA SHA256:0E3Qg1PEERghWq3gDAx2OSGPvBrYQyHARg9Uft3R+04
```

### L64c: PASS

`port49 ssh` against an entry replaced by a fresh `ssh-ed25519` key: exit 255; ssh: changed (filed type "ED25519", sent type "ED25519"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the ED25519 key sent by the remote host is
Offending ED25519 key in /tmp/p49l64home316647081/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home316647081/.ssh/known_hosts' -R 'srx1'
Host key for srx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before srx1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under srx1 is not the one 172.100.100.21 presents: either the device's key changed, or the address inventory gives for srx1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home316647081/.ssh/known_hosts -R srx1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

### L64d: PASS

`port49 ssh` against an entry replaced by a `ssh-rsa` key, a type other than the filed `ssh-ed25519`: exit 255; ssh: changed (filed type "RSA", sent type "RSA"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the RSA key sent by the remote host is
Offending RSA key in /tmp/p49l64home316647081/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home316647081/.ssh/known_hosts' -R 'srx1'
Host key for srx1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before srx1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under srx1 is not the one 172.100.100.21 presents: either the device's key changed, or the address inventory gives for srx1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home316647081/.ssh/known_hosts -R srx1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

