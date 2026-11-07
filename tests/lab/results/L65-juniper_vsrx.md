# L65 — juniper_vsrx

- **Date measured:** 2026-11-07
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-juniper_vsrx.pcap` — 1560 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `08a6f6e8db258b255baf8613fcc6d42eafb00bd6-dirty`, `PORT49_LAB_PLATFORMS=vsrx`, `-run ^TestL64L65$`

## Claim

The Python client (`port49.netmiko.connect`) against juniper_vsrx (policy engine spec §15, L65): (a) a first contact, (b) a second connection, (c) and (d) a replaced key, (e) the entries each client filed, (f) an `@revoked` key.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 08a6f6e8db258b255baf8613fcc6d42eafb00bd6 into the shared lab venv.

The 10s before the first cell: 7 decision records and 140 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L65e1 | PASS | 6.9s |
| L65a | PASS | 6.8s |
| L65b | PASS | 6.8s |
| L65c | PASS | 16.7s |
| L65d | PASS | 16.7s |
| L65e2 | PASS | 6.5s |
| L65f1 | PASS | 16.6s |
| L65f2 | PASS | 16.6s |

### L65e1: PASS

`connect(vsrx1)` against the entry `port49 ssh` filed: outcome `connected`, 51 lines of output, the device's key `ssh-ed25519`; the file held 1 line(s) before and 1 after; 184 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account account account account account account account]. Driver stderr: 

### L65a: PASS

`connect(vsrx1)` from an empty known_hosts, with `HashKnownHosts yes`: outcome `connected`, 51 lines of output, the device's key `ssh-ed25519`; the file holds 1 line(s); `ssh-keygen -F vsrx1` finds 1, of key types [ssh-ed25519], hashed: true (read error: <nil>); the key Paramiko accepted: `ssh-ed25519`; 184 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account account account account account account account]. Driver stderr: port49: permanently added 'vsrx1' (ssh-ed25519) to /tmp/p49l64home4183616505/.ssh/known_hosts

### L65b: PASS

A second `connect(vsrx1)`: outcome `connected`, 51 lines of output, the device's key `ssh-ed25519`; the file held 1 line(s) before and 1 after; 184 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account account account account account account account].

### L65c: PASS

`connect(vsrx1)` against an entry replaced by a fresh `ssh-ed25519` key: outcome `port49_error`, `HostKeyError`, code `host_key_changed`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65d: PASS

`connect(vsrx1)` against an entry replaced by a `ssh-rsa` key, a type other than the filed `ssh-ed25519`: outcome `port49_error`, `HostKeyError`, code `host_key_changed`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65e2: PASS

`port49 ssh -v vsrx1 -- show version` against the entry Python filed (`ssh-ed25519`): exit 0; ssh: clean; the file held 1 line(s) before and 2 after, of key types ssh-ed25519, ecdsa-sha2-nistp256 (UpdateHostKeys is on; types it adds after authentication are an observation, the negotiated key's line must be unchanged; read error: <nil>); 104 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account account account]. 

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.22 ([172.100.100.22]:22) using "keyboard-interactive".
debug1: client_input_hostkeys: searching /tmp/p49l64home4183616505/.ssh/known_hosts for vsrx1 / (none)
Learned new hostkey: ECDSA SHA256:yvHmUvytA30gn7FJx83V+ExFs/p8sjONTwvEshpPIzs
```

Observed: ssh filed further key types after authentication (UpdateHostKeys): ecdsa-sha2-nistp256.

### L65f1: PASS

`connect(vsrx1)` with an `@revoked` line naming the key Python filed (`ssh-ed25519`) beside the filed entry: outcome `port49_error`, `HostKeyError`, code `host_key_revoked`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65f2: PASS

`connect(vsrx1)` from a known_hosts holding only that `@revoked` line, at first contact: outcome `port49_error`, `HostKeyError`, code `host_key_revoked`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: []; the file held 1 key line(s) after, and is unchanged: true.  a window of 10s with no decision record and no TACACS+ packet preceded it.

