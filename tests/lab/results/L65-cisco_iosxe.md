# L65 — cisco_iosxe

- **Date measured:** 2026-10-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-cisco_iosxe.pcap` — 1386 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `2c680dbfad8fed41de8176383c9e67e2f871d2eb`, `PORT49_LAB_PLATFORMS=iosxe`, `-run ^TestL64L65$`

## Claim

The Python client (`port49.netmiko.connect`) against cisco_iosxe (policy engine spec §15, L65): (a) a first contact, (b) a second connection, (c) and (d) a replaced key, (e) the entries each client filed, (f) an `@revoked` key.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 2c680dbfad8fed41de8176383c9e67e2f871d2eb into the shared lab venv.

The 10s before the first cell: 1 decision records and 20 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L65e1 | PASS | 7.3s |
| L65a | PASS | 7.3s |
| L65b | PASS | 7.3s |
| L65c | PASS | 16.6s |
| L65d | PASS | 16.6s |
| L65e2 | PASS | 6.6s |
| L65f1 | PASS | 16.6s |
| L65f2 | PASS | 16.6s |

### L65e1: PASS

`connect(xe1)` against the entry `port49 ssh` filed: outcome `connected`, 64 lines of output, the device's key `ssh-rsa`; the file held 1 line(s) before and 1 after; 210 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account authorize_command account authorize_command account authorize_command account account]. Driver stderr: 

### L65a: PASS

`connect(xe1)` from an empty known_hosts, with `HashKnownHosts yes`: outcome `connected`, 64 lines of output, the device's key `ssh-rsa`; the file holds 1 line(s); `ssh-keygen -F xe1` finds 1, of key types [ssh-rsa], hashed: true (read error: <nil>); the key Paramiko accepted: `ssh-rsa`; 210 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account authorize_command account authorize_command account authorize_command account account]. Driver stderr: port49: permanently added 'xe1' (ssh-rsa) to /tmp/p49l64home3797359969/.ssh/known_hosts

### L65b: PASS

A second `connect(xe1)`: outcome `connected`, 64 lines of output, the device's key `ssh-rsa`; the file held 1 line(s) before and 1 after; 210 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account authorize_command account authorize_command account authorize_command account account].

### L65c: PASS

`connect(xe1)` against an entry replaced by a fresh `ssh-rsa` key: outcome `port49_error`, `HostKeyError`, code `host_key_changed`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65d: PASS

`connect(xe1)` against an entry replaced by a `ssh-ed25519` key, a type other than the filed `ssh-rsa`: outcome `port49_error`, `HostKeyError`, code `host_key_changed`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65e2: PASS

`port49 ssh -v xe1 -- show version` against the entry Python filed (`ssh-rsa`): exit 0; ssh: clean; the file held 1 line(s) before and 1 after, of key types ssh-rsa (UpdateHostKeys is on; types it adds after authentication are an observation, the negotiated key's line must be unchanged; read error: <nil>); 126 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem authorize_session account authorize_command account account]. 

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.41 ([172.100.100.41]:22) using "keyboard-interactive".
```

### L65f1: PASS

`connect(xe1)` with an `@revoked` line naming the key Python filed (`ssh-rsa`) beside the filed entry: outcome `port49_error`, `HostKeyError`, code `host_key_revoked`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65f2: PASS

`connect(xe1)` from a known_hosts holding only that `@revoked` line, at first contact: outcome `port49_error`, `HostKeyError`, code `host_key_revoked`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: []; the file held 1 key line(s) after, and is unchanged: true.  a window of 10s with no decision record and no TACACS+ packet preceded it.

