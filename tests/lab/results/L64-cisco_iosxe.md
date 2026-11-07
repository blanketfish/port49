# L64 — cisco_iosxe

- **Date measured:** 2026-11-07
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-cisco_iosxe.pcap` — 1382 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `4b5838f04d2c30826169b280fb32bd4f15c080b3`, `PORT49_LAB_PLATFORMS=iosxe`, `-run ^TestL64L65$`

## Claim

`port49 ssh` under OpenSSH's accept-new against cisco_iosxe (policy engine spec §15, L64): (a) a first contact, (b) after a reload, (c) a replaced key of the filed type, (d) a key of another type only.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 4b5838f04d2c30826169b280fb32bd4f15c080b3 into the shared lab venv.

The 10s before the first cell: 1 decision records and 20 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L64a | PASS | 6.6s |
| L64b | PASS | 2m16.8s |
| L64c | PASS | 16.5s |
| L64d | PASS | 16.5s |

### L64a: PASS

`port49 ssh -v xe1 -- show version` with an empty known_hosts: exit 0; 48 lines of output; ssh tried [keyboard-interactive], authenticated by `keyboard-interactive`; 1 askpass asks (the keyboard-interactive and password methods tried); 1 redeem records; 122 TACACS+ packets in the window (the positive control: it must be above 0); records: blob x1, mint x1, redeem x1, authorize_session x1, account x3, authorize_command x1. ssh: accepted. After the login `ssh-keygen -F xe1` finds 1 line(s), of key types [ssh-rsa] (a read error: <nil>); the file holds 1 line(s).

```
Warning: Permanently added 'xe1' (RSA) to the list of known hosts.
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.41 ([172.100.100.41]:22) using "keyboard-interactive".
```

### L64b: PASS

The device rebooted: true (uptime 1m0s, then 0s after 2m3s). The scan's key is the same after the reload (SHA256:4tEDXH7L9+j5eB4dY8O9lA7YmdtKl8yUK7FvQ9CexZk).

The filed lines (type and key, compared with the host field left out) before the reload: 1; after: 1; added by the login: none; gone after it: none.

```
reload step "write memory": err <nil>; the device said:
write memory
Building configuration...
[OK]
xe1#
reload step "reload": err <nil>; the device said:
reload
Proceed with reload? [confirm]
after the answer "", the device said:

The reload command was sent at 10:12:51; the device was seen down (no SSH banner on two connections in a row) at 10:13:03, and was serving SSH authentication again no later than 1m43s after that.
Before the reload, `show version` says: ["xe1 uptime is 1 minute\r" "Uptime for this control processor is 2 minutes\r"]. After: ["xe1 uptime is 0 minutes\r" "Uptime for this control processor is 1 minute\r"].
```

The 10s before the first cell: 1 decision records and 20 TACACS+ packets to or from the device.

After it, `port49 ssh -v xe1 -- show version`: exit 0; 48 lines of output; 126 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account authorize_command account account]; ssh: clean; the warning banner is present: false.

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.41 ([172.100.100.41]:22) using "keyboard-interactive".
```

### L64c: PASS

`port49 ssh` against an entry replaced by a fresh `ssh-rsa` key: exit 255; ssh: changed (filed type "RSA", sent type "RSA"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the RSA key sent by the remote host is
Offending RSA key in /tmp/p49l64home1459925485/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home1459925485/.ssh/known_hosts' -R 'xe1'
Host key for xe1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before xe1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under xe1 is not the one 172.100.100.41 presents: either the device's key changed, or the address inventory gives for xe1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home1459925485/.ssh/known_hosts -R xe1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

### L64d: PASS

`port49 ssh` against an entry replaced by a `ssh-ed25519` key, a type other than the filed `ssh-rsa`: exit 255; ssh: other_type (filed type "ED25519", sent type "RSA"); 0 TACACS+ packets; records: mint x1; names `ssh-keygen -R`: true. 

```
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
The fingerprint for the RSA key sent by the remote host is
Offending ED25519 key in /tmp/p49l64home1459925485/.ssh/known_hosts:1
  ssh-keygen -f '/tmp/p49l64home1459925485/.ssh/known_hosts' -R 'xe1'
Host key for xe1 has changed and you have requested strict checking.
Host key verification failed.
port49 ssh: ssh stopped before xe1 asked for the token, so it was never sent (ssh exit 255, its message is above). If it says Host key verification failed, the key your known_hosts files under xe1 is not the one 172.100.100.41 presents: either the device's key changed, or the address inventory gives for xe1 is not the device. Verify the key on its console, then run ssh-keygen -f /tmp/p49l64home1459925485/.ssh/known_hosts -R xe1 and connect again
``` a window of 10s with no decision record and no TACACS+ packet preceded it.

