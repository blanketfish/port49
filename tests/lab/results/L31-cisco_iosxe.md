# L31 — cisco_iosxe

- **Date measured:** 2026-09-30
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L31-quarantined-cisco_iosxe.pcap` — 166 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-quarantined-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What break-glass costs on IOS-XE and NX-OS with single-connection on when port49d declines the device (removed from the inventory, refused admission, or quarantined), now that the first connection is reset at once and the source's next connections are refused at Accept for a short window: break-glass login plus three commands, against port49d stopped and a key miss (the rekeyed control), and whether the device's retries are refused at Accept before it writes (spec §15 L31).

## Observation

port49d, port49 and port49-inventory built from `b998ae9` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 110ms |
| break-glass login plus three `show version` | ran | 1.31s |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.02s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `single-connection` under `tacacs server port49-host`.

**Reading the records and the captures.** port49d records the first packet of a connection it declines (`unadmitted_source`, `admission_refused` or `device_quarantined`; `no_known_key_matches` in the rekeyed control) and resets it at once. A connection from the same source inside the window that close opened is reset at Accept, before the device sends anything, and is not recorded: the capture's per-connection table reads it as "reset before the device sent on it (refused at Accept)". The single-connect count reads the flag byte of each TACACS+ header the device sent (0x04 is single-connection on), and no body byte, on the connections the device opened after the change. The bar holds each declined phase's break-glass to the rekeyed control's time plus 1.5 s, and never 5 s or more: no AAA exchange waited out the device's timeout. The refusals at Accept the verdict rests on are counted inside the break-glass session's own interval, since the token login before it retries too; a phase in which the device opened no connection to port 49 during break-glass is not a measurement, because the device went to local without asking. A break-glass whose commands the device answered with its refusal text did not run them. IOS-XE retries about 100–200 ms after a reset, against a first window of 100 ms, so one or two of its first retries may land after the window and be recorded before the doubling catches up. The control has the same dynamics. The stopped control is measured before this test sets single-connection, as in L29. With nothing listening, the SYN itself is refused, so the flag plays no part there.

### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (30s).

The change: port49d's broker.policy_file given `- {match: {name: xe1}, key_ref: lab_key2}`, a key the device does not hold (L29's rekeyed phase: a key miss)

port49d said the change was in force by 23:20:54.568Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.01s |
| break-glass login plus three `show version` | logged in and ran them in 1.28s |

Break-glass ran from 23:20:58.583Z to 23:20:59.861Z (host UTC); the device opened 8 connection(s) to port 49 in that interval, and port49d refused 5 of them at Accept (5 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 4, clear on 0.

Records from the device since the change: `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2; `event=unvalidated diagnosis=no_known_key_matches type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=authen` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 58608 | 23:20:47.826Z | true | 23:20:54.580Z | 23:20:54.580Z | **reset mid-connection**: open across the change |
| 58618 | 23:20:56.581Z | false | 23:20:56.582Z | 23:20:56.582Z | reset at its first packet after the change |
| 51656 | 23:20:58.595Z | false | 23:20:58.596Z | 23:20:58.596Z | reset at its first packet after the change |
| 51672 | 23:20:58.607Z | false | (not observed) | 23:20:58.607Z | reset before the device sent on it (refused at Accept) |
| 51684 | 23:20:58.963Z | false | 23:20:58.964Z | 23:20:58.964Z | reset at its first packet after the change |
| 51700 | 23:20:59.063Z | false | (not observed) | 23:20:59.063Z | reset before the device sent on it (refused at Accept) |
| 51714 | 23:20:59.213Z | false | (not observed) | 23:20:59.213Z | reset before the device sent on it (refused at Accept) |
| 51716 | 23:20:59.462Z | false | 23:20:59.464Z | 23:20:59.464Z | reset at its first packet after the change |
| 51724 | 23:20:59.562Z | false | (not observed) | 23:20:59.562Z | reset before the device sent on it (refused at Accept) |
| 51730 | 23:20:59.714Z | false | (not observed) | 23:20:59.714Z | reset before the device sent on it (refused at Accept) |

The change began at 23:20:54.568Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-rekeyed-cisco_iosxe.pcap` — 142 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-rekeyed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:d9d970b1e2181507aa59563b60dbd830dafc1739c629f44c050167c96cce27a6): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:d9d970b1e2181507aa59563b60dbd830dafc1739c629f44c050167c96cce27a6: +0 device(s), -1, 0 changed; 0 quarantined
  device removed xe1 (cisco_iosxe)
  scope all_devices: xe1 left
```

port49d said the change was in force by 23:21:21.178Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.01s |
| break-glass login plus three `show version` | logged in and ran them in 1.28s |

Break-glass ran from 23:21:25.192Z to 23:21:26.468Z (host UTC); the device opened 9 connection(s) to port 49 in that interval, and port49d refused 6 of them at Accept (6 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 4, clear on 0.

Records from the device since the change: `event=unvalidated diagnosis=unadmitted_source type=authen` ×2; `event=unvalidated diagnosis=unadmitted_source type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=xe1 type=authen` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 37366 | 23:21:11.411Z | true | 23:21:21.189Z | 23:21:21.190Z | **reset mid-connection**: open across the change |
| 35936 | 23:21:23.191Z | false | 23:21:23.192Z | 23:21:23.192Z | reset at its first packet after the change |
| 35948 | 23:21:25.204Z | false | 23:21:25.204Z | 23:21:25.205Z | reset at its first packet after the change |
| 35962 | 23:21:25.216Z | false | (not observed) | 23:21:25.216Z | reset before the device sent on it (refused at Accept) |
| 35964 | 23:21:25.571Z | false | 23:21:25.572Z | 23:21:25.572Z | reset at its first packet after the change |
| 35972 | 23:21:25.671Z | false | (not observed) | 23:21:25.671Z | reset before the device sent on it (refused at Accept) |
| 35986 | 23:21:25.821Z | false | (not observed) | 23:21:25.822Z | reset before the device sent on it (refused at Accept) |
| 35994 | 23:21:26.072Z | false | 23:21:26.073Z | 23:21:26.073Z | reset at its first packet after the change |
| 35998 | 23:21:26.171Z | false | (not observed) | 23:21:26.172Z | reset before the device sent on it (refused at Accept) |
| 36006 | 23:21:26.321Z | false | (not observed) | 23:21:26.321Z | reset before the device sent on it (refused at Accept) |
| 36010 | 23:21:26.421Z | false | (not observed) | 23:21:26.421Z | reset before the device sent on it (refused at Accept) |

The change began at 23:21:21.178Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-removed-cisco_iosxe.pcap` — 150 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-removed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

The change: `port49 inventory sync`:

```
published bundle 4 (sha256:27b8bd5f3047adfb87ce2ed1a94c58593c1dabd6803863a5f1d4b12c0bcf6348): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:27b8bd5f3047adfb87ce2ed1a94c58593c1dabd6803863a5f1d4b12c0bcf6348: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed xe1: admitted → refused
```

port49d said the change was in force by 23:21:47.805Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.01s |
| break-glass login plus three `show version` | logged in and ran them in 1.78s |

Break-glass ran from 23:21:51.820Z to 23:21:53.598Z (host UTC); the device opened 13 connection(s) to port 49 in that interval, and port49d refused 10 of them at Accept (10 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 4, clear on 0.

Records from the device since the change: `event=unvalidated diagnosis=admission_refused device=xe1 type=authen` ×2; `event=unvalidated diagnosis=admission_refused device=xe1 type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=xe1 type=authen` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 34462 | 23:21:38.039Z | true | 23:21:47.817Z | 23:21:47.817Z | **reset mid-connection**: open across the change |
| 43122 | 23:21:49.818Z | false | 23:21:49.819Z | 23:21:49.819Z | reset at its first packet after the change |
| 43132 | 23:21:51.832Z | false | 23:21:51.832Z | 23:21:51.833Z | reset at its first packet after the change |
| 43144 | 23:21:51.844Z | false | (not observed) | 23:21:51.844Z | reset before the device sent on it (refused at Accept) |
| 43152 | 23:21:52.198Z | false | (not observed) | 23:21:52.198Z | reset before the device sent on it (refused at Accept) |
| 43166 | 23:21:52.298Z | false | 23:21:52.398Z | 23:21:52.398Z | reset at its first packet after the change |
| 43170 | 23:21:52.498Z | false | (not observed) | 23:21:52.498Z | reset before the device sent on it (refused at Accept) |
| 43184 | 23:21:52.598Z | false | (not observed) | 23:21:52.598Z | reset before the device sent on it (refused at Accept) |
| 43186 | 23:21:52.698Z | false | (not observed) | 23:21:52.698Z | reset before the device sent on it (refused at Accept) |
| 43194 | 23:21:52.798Z | false | (not observed) | 23:21:52.799Z | reset before the device sent on it (refused at Accept) |
| 43202 | 23:21:52.951Z | false | (not observed) | 23:21:52.952Z | reset before the device sent on it (refused at Accept) |
| 43216 | 23:21:53.200Z | false | 23:21:53.201Z | 23:21:53.201Z | reset at its first packet after the change |
| 43230 | 23:21:53.300Z | false | (not observed) | 23:21:53.300Z | reset before the device sent on it (refused at Accept) |
| 43246 | 23:21:53.451Z | false | (not observed) | 23:21:53.451Z | reset before the device sent on it (refused at Accept) |
| 43250 | 23:21:53.551Z | false | (not observed) | 23:21:53.551Z | reset before the device sent on it (refused at Accept) |

The change began at 23:21:47.805Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-refused-cisco_iosxe.pcap` — 182 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-refused-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: quarantined

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

The change: port49d's broker.policy_file replaced by `tests/lab/quarantine-sync/policy.yaml`, whose probe grants quarantine xe1; the service's copy unchanged

port49d said the change was in force by 23:22:11.927Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.01s |
| break-glass login plus three `show version` | logged in and ran them in 1.78s |

Break-glass ran from 23:22:15.940Z to 23:22:17.719Z (host UTC); the device opened 11 connection(s) to port 49 in that interval, and port49d refused 8 of them at Accept (8 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 4, clear on 0.

Records from the device since the change: `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=xe1 type=authen` ×3; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=xe1 type=author` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 39064 | 23:22:05.158Z | true | 23:22:11.938Z | 23:22:11.939Z | **reset mid-connection**: open across the change |
| 44704 | 23:22:13.939Z | false | 23:22:13.940Z | 23:22:13.940Z | reset at its first packet after the change |
| 44720 | 23:22:15.952Z | false | 23:22:15.952Z | 23:22:15.953Z | reset at its first packet after the change |
| 44736 | 23:22:15.964Z | false | (not observed) | 23:22:15.964Z | reset before the device sent on it (refused at Accept) |
| 44742 | 23:22:16.320Z | false | (not observed) | 23:22:16.320Z | reset before the device sent on it (refused at Accept) |
| 44750 | 23:22:16.419Z | false | 23:22:16.520Z | 23:22:16.520Z | reset at its first packet after the change |
| 44752 | 23:22:16.620Z | false | (not observed) | 23:22:16.620Z | reset before the device sent on it (refused at Accept) |
| 44758 | 23:22:16.720Z | false | (not observed) | 23:22:16.720Z | reset before the device sent on it (refused at Accept) |
| 44760 | 23:22:16.820Z | false | (not observed) | 23:22:16.820Z | reset before the device sent on it (refused at Accept) |
| 44774 | 23:22:17.070Z | false | (not observed) | 23:22:17.071Z | reset before the device sent on it (refused at Accept) |
| 44786 | 23:22:17.320Z | false | 23:22:17.322Z | 23:22:17.322Z | reset at its first packet after the change |
| 44800 | 23:22:17.421Z | false | (not observed) | 23:22:17.421Z | reset before the device sent on it (refused at Accept) |
| 44816 | 23:22:17.573Z | false | (not observed) | 23:22:17.573Z | reset before the device sent on it (refused at Accept) |

The change began at 23:22:11.927Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-quarantined-cisco_iosxe.pcap` — 166 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-quarantined-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Summary

| phase | break-glass login plus three `show version` | bar | connections refused at Accept during break-glass | refused at Accept since the change | records from the device |
|---|---|---|---|---|---|
| rekeyed | logged in and ran them in 1.28s | (the control) | 5 | 5 | `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2; `event=unvalidated diagnosis=no_known_key_matches type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=authen` ×1 |
| removed | logged in and ran them in 1.28s | 2.78s | 6 | 6 | `event=unvalidated diagnosis=unadmitted_source type=authen` ×2; `event=unvalidated diagnosis=unadmitted_source type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=xe1 type=authen` ×1 |
| refused | logged in and ran them in 1.78s | 2.78s | 10 | 10 | `event=unvalidated diagnosis=admission_refused device=xe1 type=authen` ×2; `event=unvalidated diagnosis=admission_refused device=xe1 type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=xe1 type=authen` ×1 |
| quarantined | logged in and ran them in 1.78s | 2.78s | 8 | 8 | `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=xe1 type=authen` ×3; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=xe1 type=author` ×2 |


