# L65 — juniper_vsrx

- **Date measured:** 2026-11-06
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L64L65-juniper_vsrx.pcap` — 888 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L64L65-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vsrx`, `-run ^TestL64L65$`

## Claim

The Python client (`port49.netmiko.connect`) against juniper_vsrx (policy engine spec §15, L65): (a) a first contact, (b) a second connection, (c) and (d) a replaced key, (e) the entries each client filed, (f) an `@revoked` key.

## Observation

Client versions in this run: Python 3.14.4 netmiko 4.8.0 paramiko 5.1.0 port49 0.1.0; OpenSSH_10.2p1 Ubuntu-2ubuntu3.8, OpenSSL 3.5.5 27 Jan 2026; installed from clients/python at commit a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2 into the shared lab venv.

The 10s before the first cell: 7 decision records and 140 TACACS+ packets to or from the device.

| cell | outcome | elapsed |
|---|---|---|
| L65e1 | FAIL | 6.3s |
| L65a | FAIL | 6.3s |
| L65b | FAIL | 6.3s |
| L65c | FAIL | 16.5s |
| L65d | FAIL | 16.5s |
| L65e2 | FAIL | 0s |
| L65f1 | FAIL | 0s |
| L65f2 | FAIL | 0s |

### L65e1: FAIL

`connect(vsrx1)` against the entry `port49 ssh` filed: outcome `error`, `TypeError`; the file held 1 line(s) before and 1 after; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: []. Driver stderr: 

### L65a: FAIL

`connect(vsrx1)` from an empty known_hosts, with `HashKnownHosts yes`: outcome `error`, `TypeError`; the file holds 0 line(s); `ssh-keygen -F vsrx1` finds 0, of key types [], hashed: false (read error: <nil>); the key Paramiko accepted: ``; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: []. Driver stderr: 

### L65b: FAIL

A second `connect(vsrx1)`: outcome `error`, `TypeError`; the file held 0 line(s) before and 0 after; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: [].

### L65c: FAIL

`connect(vsrx1)` against an entry replaced by a fresh `ssh-ed25519` key: outcome `error`, `TypeError`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: []. outcome error TypeError, not a HostKeyError a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65d: FAIL

`connect(vsrx1)` against an entry replaced by a `ssh-rsa` key, a type other than the filed `ssh-ed25519`: outcome `error`, `TypeError`; 0 TACACS+ packets, 0 redeem records, records other than mint and blob: []. outcome error TypeError, not a HostKeyError a window of 10s with no decision record and no TACACS+ packet preceded it.

### L65e2: FAIL

no entry was filed by L65a, so there is nothing to verify

### L65f1: FAIL

L65a recorded no line for the key Python negotiated, so no @revoked line can name the device's own

### L65f2: FAIL

L65a recorded no line for the key Python negotiated, so no @revoked line can name the device's own

