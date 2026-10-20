# L64 — arista_eos

- **Date measured:** 2026-10-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-arista_eos.pcap` — 1280 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `30728fa3429a1beea98251be87a16837056daa55`, `PORT49_LAB_PLATFORMS=eos`, `-run ^TestL64L65$`

## Claim

`port49 ssh` under OpenSSH's accept-new against arista_eos (policy engine spec §15, L64): (a) a first contact, (b) after a reload, (c) a replaced key of the filed type, (d) a key of another type only.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 30728fa3429a1beea98251be87a16837056daa55 into the shared lab venv.

The 10s before the first cell: 0 decision records and 0 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L64a | PASS | 6.7s |
| L64b | PASS | 1m13.3s |
| L64c | PASS | 16.5s |
| L64d | PASS | 16.6s |

### L64a: PASS

`port49 ssh -v leaf1 -- show version` with an empty known_hosts: exit 0; 14 lines of output; ssh tried [keyboard-interactive], authenticated by `keyboard-interactive`; 1 askpass asks (the keyboard-interactive and password methods tried); 1 redeem records; 124 TACACS+ packets in the window (the positive control: it must be above 0); records: blob x1, mint x1, redeem x1, account x3, authorize_session x1, authorize_command x1. ssh: accepted. After the login `ssh-keygen -F leaf1` finds 1 line(s), of key types [ssh-ed25519] (a read error: <nil>); the file holds 1 line(s).

```
Warning: Permanently added 'leaf1' (ED25519) to the list of known hosts.
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.11 ([172.100.100.11]:22) using "keyboard-interactive".
```

### L64b: PASS

The device rebooted: true (uptime 1m0s, then 0s after 1m5s). The scan's key is the same after the reload (SHA256:LpMGxK3w8Gyt44VbNW8ckZE7Po4cWe2qeHGkJjt0vZg).

The filed lines (type and key, compared with the host field left out) before the reload: 1; after: 2; added by the login: ecdsa-sha2-nistp521; gone after it: none.

```
reload step "write memory": err <nil>; the device said:
write memory
Copy completed successfully.
leaf1#
reload step "reload now": sent, no prompt waited for
The reload command was sent at 11:36:52; the device was seen down (no SSH banner on two connections in a row) at 11:36:56, and was serving SSH authentication again no later than 59s after that.
Before the reload, `show version` says: ["Uptime: 1 minute\r"]. After: ["Uptime: 0 minutes\r"].
```

The 10s before the first cell: 0 decision records and 0 TACACS+ packets to or from the device.

After it, `port49 ssh -v leaf1 -- show version`: exit 0; 14 lines of output; 124 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem account authorize_session authorize_command account account]; ssh: clean; the warning banner is present: false.

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.11 ([172.100.100.11]:22) using "keyboard-interactive".
debug1: client_input_hostkeys: searching /tmp/p49l64home3135331141/.ssh/known_hosts for leaf1 / (none)
Learned new hostkey: ECDSA SHA256:uRt8MZs0ytce/IL2G02pv8sld4itBpIQxsyWD3pHbS4
```

### L64c: PASS

`port49 ssh` against an entry replaced by a fresh `ssh-ed25519` key: exit 255; ssh: changed (filed type "ED25519", sent type "ED25519"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the ED25519 key sent by the remote host is
Offending ED25519 key in /tmp/p49l64home3135331141/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home3135331141/.ssh/known_hosts' -R 'leaf1'
Host key for leaf1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before leaf1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under leaf1 is not the one 172.100.100.11 presents: either the device's key changed, or the address inventory gives for leaf1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home3135331141/.ssh/known_hosts -R leaf1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

### L64d: PASS

`port49 ssh` against an entry replaced by a `ssh-rsa` key, a type other than the filed `ssh-ed25519`: exit 255; ssh: changed (filed type "RSA", sent type "RSA"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the RSA key sent by the remote host is
Offending RSA key in /tmp/p49l64home3135331141/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home3135331141/.ssh/known_hosts' -R 'leaf1'
Host key for leaf1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before leaf1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under leaf1 is not the one 172.100.100.11 presents: either the device's key changed, or the address inventory gives for leaf1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home3135331141/.ssh/known_hosts -R leaf1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

