# L65 — arista_eos

- **Date measured:** 2026-10-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-arista_eos.pcap` — 1280 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `2c680dbfad8fed41de8176383c9e67e2f871d2eb`, `PORT49_LAB_PLATFORMS=eos`, `-run ^TestL64L65$`

## Claim

The Python client (`port49.netmiko.connect`) against arista_eos (policy engine spec §15, L65): (a) a first contact, (b) a second connection, (c) and (d) a replaced key, (e) the entries each client filed, (f) an `@revoked` key.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit 2c680dbfad8fed41de8176383c9e67e2f871d2eb into the shared lab venv.

The 10s before the first cell: 0 decision records and 0 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L65e1 | PASS | 6.8s |
| L65a | PASS | 6.7s |
| L65b | PASS | 6.7s |
| L65c | PASS | 16.7s |
| L65d | PASS | 16.7s |
| L65e2 | PASS | 6.4s |
| L65f1 | PASS | 16.7s |
| L65f2 | PASS | 16.6s |

### L65e1: PASS

`connect(leaf1)` against the entry `port49 ssh` filed: outcome `connected`, 16 lines of output, the device's key `ssh-ed25519`; the file held 1 line(s) before and 1 after; 204 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem account authorize_session authorize_command account authorize_command account authorize_command account account]. Driver stderr: 

### L65a: PASS

`connect(leaf1)` from an empty known_hosts, with `HashKnownHosts yes`: outcome `connected`, 16 lines of output, the device's key `ssh-ed25519`; the file holds 1 line(s); `ssh-keygen -F leaf1` finds 1, of key types [ssh-ed25519], hashed: true (read error: <nil>); the key Paramiko accepted: `ssh-ed25519`; 224 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem account authorize_session authorize_command account authorize_command account authorize_command account account account]. Driver stderr: port49: permanently added 'leaf1' (ssh-ed25519) to /tmp/p49l64home3135331141/.ssh/known_hosts

### L65b: PASS

A second `connect(leaf1)`: outcome `connected`, 16 lines of output, the device's key `ssh-ed25519`; the file held 1 line(s) before and 1 after; 224 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem account authorize_session authorize_command account authorize_command account authorize_command account account account].

### L65c: PASS

`connect(leaf1)` against an entry replaced by a fresh `ssh-ed25519` key: outcome `port49_error`, `HostKeyError`, code `host_key_changed`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65d: PASS

`connect(leaf1)` against an entry replaced by a `ssh-rsa` key, a type other than the filed `ssh-ed25519`: outcome `port49_error`, `HostKeyError`, code `host_key_changed`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65e2: PASS

`port49 ssh -v leaf1 -- show version` against the entry Python filed (`ssh-ed25519`): exit 0; ssh: clean; the file held 1 line(s) before and 2 after, of key types ssh-ed25519, ecdsa-sha2-nistp521 (UpdateHostKeys is on; types it adds after authentication are an observation, the negotiated key's line must be unchanged; read error: <nil>); 124 TACACS+ packets, 1 redeem records, records other than mint and blob: [redeem account authorize_session authorize_command account account]. 

```
debug1: Next authentication method: keyboard-interactive
Authenticated to 172.100.100.11 ([172.100.100.11]:22) using "keyboard-interactive".
debug1: client_input_hostkeys: searching /tmp/p49l64home3135331141/.ssh/known_hosts for leaf1 / (none)
Learned new hostkey: ECDSA SHA256:uRt8MZs0ytce/IL2G02pv8sld4itBpIQxsyWD3pHbS4
```

Observed: ssh filed further key types after authentication (UpdateHostKeys): ecdsa-sha2-nistp521.

### L65f1: PASS

`connect(leaf1)` with an `@revoked` line naming the key Python filed (`ssh-ed25519`) beside the filed entry: outcome `port49_error`, `HostKeyError`, code `host_key_revoked`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].  a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65f2: PASS

`connect(leaf1)` from a known_hosts holding only that `@revoked` line, at first contact: outcome `port49_error`, `HostKeyError`, code `host_key_revoked`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: []; the file held 1 key line(s) after, and is unchanged: true.  a window of 10s with no decision record and no TACACS+ packet preceded it.

