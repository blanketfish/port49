# L31 — arista_eos

- **Date measured:** 2026-09-30
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L31-quarantined-arista_eos.pcap` — 192 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-quarantined-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What break-glass costs on IOS-XE and NX-OS with single-connection on when port49d declines the device (removed from the inventory, refused admission, or quarantined), now that the first connection is reset at once and the source's next connections are refused at Accept for a short window: break-glass login plus three commands, against port49d stopped and a key miss (the rekeyed control), and whether the device's retries are refused at Accept before it writes (spec §15 L31).

## Observation

port49d, port49 and port49-inventory built from `b998ae9` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 370ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 2.16s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `tacacs-server host 172.100.100.1 single-connection`.

**Reading the records and the captures.** port49d records the first packet of a connection it declines (`unadmitted_source`, `admission_refused` or `device_quarantined`; `no_known_key_matches` in the rekeyed control) and resets it at once. A connection from the same source inside the window that close opened is reset at Accept, before the device sends anything, and is not recorded: the capture's per-connection table reads it as "reset before the device sent on it (refused at Accept)". The single-connect count reads the flag byte of each TACACS+ header the device sent (0x04 is single-connection on), and no body byte, on the connections the device opened after the change. The bar holds each declined phase's break-glass to the rekeyed control's time plus 1.5 s, and never 5 s or more: no AAA exchange waited out the device's timeout. The refusals at Accept the verdict rests on are counted inside the break-glass session's own interval, since the token login before it retries too; a phase in which the device opened no connection to port 49 during break-glass is not a measurement, because the device went to local without asking. A break-glass whose commands the device answered with its refusal text did not run them. IOS-XE retries about 100–200 ms after a reset, against a first window of 100 ms, so one or two of its first retries may land after the window and be recorded before the doubling catches up. The control has the same dynamics. The stopped control is measured before this test sets single-connection, as in L29. With nothing listening, the SYN itself is refused, so the flag plays no part there.

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: port49d's broker.policy_file given `- {match: {name: leaf1}, key_ref: lab_key2}`, a key the device does not hold (L29's rekeyed phase: a key miss)

port49d said the change was in force by 23:24:24.783Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 2.44s |
| break-glass login plus three `show version` | logged in and ran them in 340ms |

Break-glass ran from 23:24:27.222Z to 23:24:27.564Z (host UTC); the device opened 15 connection(s) to port 49 in that interval, and port49d refused 12 of them at Accept (13 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 5, clear on 0.

Records from the device since just before the change: `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2; `event=unvalidated diagnosis=no_known_key_matches type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 37542 | 23:24:23.013Z | true | (not observed) | (not observed) | not reset by port49d |
| 37554 | 23:24:24.807Z | false | 23:24:24.807Z | 23:24:24.807Z | reset at its first packet after the change |
| 37560 | 23:24:27.247Z | false | 23:24:27.248Z | 23:24:27.248Z | reset at its first packet after the change |
| 37566 | 23:24:27.268Z | false | (not observed) | 23:24:27.268Z | reset before the device sent on it (refused at Accept) |
| 37570 | 23:24:27.269Z | false | (not observed) | 23:24:27.269Z | reset before the device sent on it (refused at Accept) |
| 37572 | 23:24:27.303Z | false | (not observed) | 23:24:27.303Z | reset before the device sent on it (refused at Accept) |
| 37578 | 23:24:27.347Z | false | (not observed) | 23:24:27.347Z | reset before the device sent on it (refused at Accept) |
| 37580 | 23:24:27.349Z | false | (not observed) | 23:24:27.350Z | reset before the device sent on it (refused at Accept) |
| 37582 | 23:24:27.350Z | false | 23:24:27.350Z | 23:24:27.350Z | reset |
| 37584 | 23:24:27.399Z | false | (not observed) | 23:24:27.399Z | reset before the device sent on it (refused at Accept) |
| 37592 | 23:24:27.449Z | false | 23:24:27.449Z | 23:24:27.450Z | reset at its first packet after the change |
| 37596 | 23:24:27.452Z | false | (not observed) | 23:24:27.452Z | reset before the device sent on it (refused at Accept) |
| 37610 | 23:24:27.452Z | false | (not observed) | 23:24:27.452Z | reset before the device sent on it (refused at Accept) |
| 37612 | 23:24:27.503Z | false | (not observed) | 23:24:27.503Z | reset before the device sent on it (refused at Accept) |
| 37614 | 23:24:27.545Z | false | (not observed) | 23:24:27.545Z | reset before the device sent on it (refused at Accept) |
| 37620 | 23:24:27.547Z | false | (not observed) | 23:24:27.547Z | reset before the device sent on it (refused at Accept) |
| 37626 | 23:24:27.548Z | false | (not observed) | 23:24:27.548Z | reset before the device sent on it (refused at Accept) |
| 37630 | 23:24:27.567Z | false | 23:24:27.567Z | 23:24:27.567Z | reset |
| 37634 | 23:24:27.567Z | false | (not observed) | 23:24:27.567Z | reset before the device sent on it (refused at Accept) |

The change began at 23:24:24.783Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-rekeyed-arista_eos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-rekeyed-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:0754c64f0d1fc80a7defafe9c2909daafd80b92c38e1ecf0169c54dd6c68b070): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:0754c64f0d1fc80a7defafe9c2909daafd80b92c38e1ecf0169c54dd6c68b070: +0 device(s), -1, 0 changed; 0 quarantined
  device removed leaf1 (arista_eos)
  scope all_devices: leaf1 left
```

port49d said the change was in force by 23:24:43.906Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 2.19s |
| break-glass login plus three `show version` | logged in and ran them in 330ms |

Break-glass ran from 23:24:46.095Z to 23:24:46.420Z (host UTC); the device opened 15 connection(s) to port 49 in that interval, and port49d refused 11 of them at Accept (13 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 5, clear on 0.

Records from the device since just before the change: `event=unvalidated diagnosis=unadmitted_source type=authen` ×2; `event=unvalidated diagnosis=unadmitted_source type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 60302 | 23:24:39.133Z | true | (not observed) | (not observed) | not reset by port49d |
| 60308 | 23:24:43.933Z | false | 23:24:43.933Z | 23:24:43.933Z | reset at its first packet after the change |
| 60316 | 23:24:46.120Z | false | 23:24:46.121Z | 23:24:46.121Z | reset at its first packet after the change |
| 60332 | 23:24:46.138Z | false | 23:24:46.138Z | 23:24:46.138Z | reset |
| 60348 | 23:24:46.139Z | false | 23:24:46.139Z | 23:24:46.139Z | reset |
| 60356 | 23:24:46.174Z | false | (not observed) | 23:24:46.174Z | reset before the device sent on it (refused at Accept) |
| 60368 | 23:24:46.217Z | false | (not observed) | 23:24:46.217Z | reset before the device sent on it (refused at Accept) |
| 60376 | 23:24:46.219Z | false | (not observed) | 23:24:46.219Z | reset before the device sent on it (refused at Accept) |
| 60388 | 23:24:46.220Z | false | (not observed) | 23:24:46.220Z | reset before the device sent on it (refused at Accept) |
| 60404 | 23:24:46.266Z | false | (not observed) | 23:24:46.266Z | reset before the device sent on it (refused at Accept) |
| 60416 | 23:24:46.310Z | false | (not observed) | 23:24:46.310Z | reset before the device sent on it (refused at Accept) |
| 60422 | 23:24:46.312Z | false | (not observed) | 23:24:46.313Z | reset before the device sent on it (refused at Accept) |
| 60436 | 23:24:46.313Z | false | (not observed) | 23:24:46.313Z | reset before the device sent on it (refused at Accept) |
| 60442 | 23:24:46.359Z | false | 23:24:46.360Z | 23:24:46.360Z | reset at its first packet after the change |
| 60448 | 23:24:46.402Z | false | (not observed) | 23:24:46.402Z | reset before the device sent on it (refused at Accept) |
| 60460 | 23:24:46.403Z | false | (not observed) | 23:24:46.403Z | reset before the device sent on it (refused at Accept) |
| 60464 | 23:24:46.404Z | false | (not observed) | 23:24:46.404Z | reset before the device sent on it (refused at Accept) |
| 60466 | 23:24:46.424Z | false | (not observed) | 23:24:46.424Z | reset before the device sent on it (refused at Accept) |
| 60482 | 23:24:46.424Z | false | (not observed) | 23:24:46.424Z | reset before the device sent on it (refused at Accept) |

The change began at 23:24:43.906Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-removed-arista_eos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-removed-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: `port49 inventory sync`:

```
published bundle 4 (sha256:2a02bd5a21ec83b40fd4f1deb3e4c5fcdfdaed445128061deaf4fb6e4bfe303b): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:2a02bd5a21ec83b40fd4f1deb3e4c5fcdfdaed445128061deaf4fb6e4bfe303b: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed leaf1: admitted → refused
```

port49d said the change was in force by 23:25:02.760Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 2.66s |
| break-glass login plus three `show version` | logged in and ran them in 320ms |

Break-glass ran from 23:25:05.415Z to 23:25:05.738Z (host UTC); the device opened 15 connection(s) to port 49 in that interval, and port49d refused 10 of them at Accept (12 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 6, clear on 0.

Records from the device since just before the change: `event=unvalidated diagnosis=admission_refused device=leaf1 type=authen` ×2; `event=unvalidated diagnosis=admission_refused device=leaf1 type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 34420 | 23:24:57.993Z | true | (not observed) | (not observed) | not reset by port49d |
| 34432 | 23:25:02.783Z | false | 23:25:02.783Z | 23:25:02.783Z | reset at its first packet after the change |
| 34434 | 23:25:05.438Z | false | 23:25:05.438Z | 23:25:05.438Z | reset at its first packet after the change |
| 34438 | 23:25:05.449Z | false | 23:25:05.449Z | 23:25:05.449Z | reset |
| 34454 | 23:25:05.450Z | false | (not observed) | 23:25:05.450Z | reset before the device sent on it (refused at Accept) |
| 34464 | 23:25:05.484Z | false | (not observed) | 23:25:05.485Z | reset before the device sent on it (refused at Accept) |
| 34480 | 23:25:05.528Z | false | (not observed) | 23:25:05.528Z | reset before the device sent on it (refused at Accept) |
| 34494 | 23:25:05.530Z | false | (not observed) | 23:25:05.530Z | reset before the device sent on it (refused at Accept) |
| 34502 | 23:25:05.531Z | false | 23:25:05.531Z | 23:25:05.531Z | reset |
| 34504 | 23:25:05.578Z | false | (not observed) | 23:25:05.578Z | reset before the device sent on it (refused at Accept) |
| 34510 | 23:25:05.623Z | false | (not observed) | 23:25:05.624Z | reset before the device sent on it (refused at Accept) |
| 34524 | 23:25:05.626Z | false | (not observed) | 23:25:05.626Z | reset before the device sent on it (refused at Accept) |
| 34534 | 23:25:05.626Z | false | (not observed) | 23:25:05.626Z | reset before the device sent on it (refused at Accept) |
| 34538 | 23:25:05.674Z | false | 23:25:05.674Z | 23:25:05.674Z | reset at its first packet after the change |
| 34544 | 23:25:05.718Z | false | 23:25:05.718Z | 23:25:05.718Z | reset |
| 34548 | 23:25:05.720Z | false | (not observed) | 23:25:05.720Z | reset before the device sent on it (refused at Accept) |
| 34562 | 23:25:05.720Z | false | (not observed) | 23:25:05.720Z | reset before the device sent on it (refused at Accept) |
| 34574 | 23:25:05.740Z | false | (not observed) | 23:25:05.741Z | reset before the device sent on it (refused at Accept) |
| 34584 | 23:25:05.741Z | false | (not observed) | 23:25:05.741Z | reset before the device sent on it (refused at Accept) |

The change began at 23:25:02.760Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-refused-arista_eos.pcap` — 204 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-refused-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: quarantined

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: port49d's broker.policy_file replaced by `tests/lab/quarantine-sync/policy.yaml`, whose probe grants quarantine leaf1; the service's copy unchanged

port49d said the change was in force by 23:25:19.082Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 1.66s |
| break-glass login plus three `show version` | logged in and ran them in 320ms |

Break-glass ran from 23:25:20.739Z to 23:25:21.060Z (host UTC); the device opened 15 connection(s) to port 49 in that interval, and port49d refused 13 of them at Accept (15 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 3, clear on 0.

Records from the device since just before the change: `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=leaf1 type=authen` ×2; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=leaf1 type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 37948 | 23:25:17.313Z | true | (not observed) | (not observed) | not reset by port49d |
| 51752 | 23:25:19.105Z | false | 23:25:19.105Z | 23:25:19.105Z | reset at its first packet after the change |
| 51758 | 23:25:20.761Z | false | 23:25:20.762Z | 23:25:20.762Z | reset at its first packet after the change |
| 51766 | 23:25:20.773Z | false | (not observed) | 23:25:20.773Z | reset before the device sent on it (refused at Accept) |
| 51772 | 23:25:20.774Z | false | (not observed) | 23:25:20.774Z | reset before the device sent on it (refused at Accept) |
| 51774 | 23:25:20.808Z | false | (not observed) | 23:25:20.809Z | reset before the device sent on it (refused at Accept) |
| 51784 | 23:25:20.852Z | false | (not observed) | 23:25:20.852Z | reset before the device sent on it (refused at Accept) |
| 51786 | 23:25:20.853Z | false | (not observed) | 23:25:20.853Z | reset before the device sent on it (refused at Accept) |
| 51792 | 23:25:20.853Z | false | (not observed) | 23:25:20.854Z | reset before the device sent on it (refused at Accept) |
| 51794 | 23:25:20.902Z | false | (not observed) | 23:25:20.902Z | reset before the device sent on it (refused at Accept) |
| 51798 | 23:25:20.947Z | false | (not observed) | 23:25:20.947Z | reset before the device sent on it (refused at Accept) |
| 51806 | 23:25:20.948Z | false | (not observed) | 23:25:20.949Z | reset before the device sent on it (refused at Accept) |
| 51820 | 23:25:20.949Z | false | (not observed) | 23:25:20.949Z | reset before the device sent on it (refused at Accept) |
| 51828 | 23:25:20.998Z | false | 23:25:20.999Z | 23:25:20.999Z | reset at its first packet after the change |
| 51844 | 23:25:21.042Z | false | (not observed) | 23:25:21.042Z | reset before the device sent on it (refused at Accept) |
| 51856 | 23:25:21.044Z | false | (not observed) | 23:25:21.044Z | reset before the device sent on it (refused at Accept) |
| 51858 | 23:25:21.045Z | false | (not observed) | 23:25:21.045Z | reset before the device sent on it (refused at Accept) |
| 51864 | 23:25:21.063Z | false | (not observed) | 23:25:21.063Z | reset before the device sent on it (refused at Accept) |
| 51878 | 23:25:21.064Z | false | (not observed) | 23:25:21.064Z | reset before the device sent on it (refused at Accept) |

The change began at 23:25:19.082Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-quarantined-arista_eos.pcap` — 192 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-quarantined-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Summary

| phase | break-glass login plus three `show version` | bar | connections refused at Accept during break-glass | refused at Accept since the change | records from the device since just before the change |
|---|---|---|---|---|---|
| rekeyed | logged in and ran them in 340ms | (the control) | 12 | 13 | `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2; `event=unvalidated diagnosis=no_known_key_matches type=author` ×1 |
| removed | logged in and ran them in 330ms | 1.84s | 11 | 13 | `event=unvalidated diagnosis=unadmitted_source type=authen` ×2; `event=unvalidated diagnosis=unadmitted_source type=author` ×1 |
| refused | logged in and ran them in 320ms | 1.84s | 10 | 12 | `event=unvalidated diagnosis=admission_refused device=leaf1 type=authen` ×2; `event=unvalidated diagnosis=admission_refused device=leaf1 type=author` ×1 |
| quarantined | logged in and ran them in 320ms | 1.84s | 13 | 15 | `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=leaf1 type=authen` ×2; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=leaf1 type=author` ×1 |


