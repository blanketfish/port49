# L31 — cisco_nxos

- **Date measured:** 2026-09-30
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L31-quarantined-cisco_nxos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-quarantined-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What break-glass costs on IOS-XE and NX-OS with single-connection on when port49d declines the device (removed from the inventory, refused admission, or quarantined), now that the first connection is reset at once and the source's next connections are refused at Accept for a short window: break-glass login plus three commands, against port49d stopped and a key miss (the rekeyed control), and whether the device's retries are refused at Accept before it writes (spec §15 L31).

## Observation

port49d, port49 and port49-inventory built from `b998ae9` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 130ms |
| break-glass login plus three `show version` | ran | 2.66s |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 6.23s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `tacacs-server host 172.100.100.1 key 0 <key> single-connection`.

**Reading the records and the captures.** port49d records the first packet of a connection it declines (`unadmitted_source`, `admission_refused` or `device_quarantined`; `no_known_key_matches` in the rekeyed control) and resets it at once. A connection from the same source inside the window that close opened is reset at Accept, before the device sends anything, and is not recorded: the capture's per-connection table reads it as "reset before the device sent on it (refused at Accept)". The single-connect count reads the flag byte of each TACACS+ header the device sent (0x04 is single-connection on), and no body byte, on the connections the device opened after the change. The bar holds each declined phase's break-glass to the rekeyed control's time plus 1.5 s, and never 5 s or more: no AAA exchange waited out the device's timeout. The refusals at Accept the verdict rests on are counted inside the break-glass session's own interval, since the token login before it retries too; a phase in which the device opened no connection to port 49 during break-glass is not a measurement, because the device went to local without asking. A break-glass whose commands the device answered with its refusal text did not run them. IOS-XE retries about 100–200 ms after a reset, against a first window of 100 ms, so one or two of its first retries may land after the window and be recorded before the doubling catches up. The control has the same dynamics. The stopped control is measured before this test sets single-connection, as in L29. With nothing listening, the SYN itself is refused, so the flag plays no part there.

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: port49d's broker.policy_file given `- {match: {name: nx1}, key_ref: lab_key2}`, a key the device does not hold (L29's rekeyed phase: a key miss)

port49d said the change was in force by 23:15:37.892Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.91s |
| break-glass login plus three `show version` | logged in and ran them in 2.61s |

Break-glass ran from 23:15:43.799Z to 23:15:46.413Z (host UTC); the device opened 14 connection(s) to port 49 in that interval, and port49d refused 11 of them at Accept (11 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 5, clear on 0.

Records from the device since the change: `event=account` ×1; `event=unvalidated diagnosis=no_known_key_matches type=acct` ×2; `event=unvalidated diagnosis=no_known_key_matches type=authen` ×1; `event=unvalidated diagnosis=no_known_key_matches type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=nx1 type=authen` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 57534 | 23:15:34.226Z | true | 23:15:38.010Z | 23:15:38.010Z | **reset mid-connection**: open across the change |
| 60362 | 23:15:40.221Z | false | 23:15:40.222Z | 23:15:40.222Z | reset at its first packet after the change |
| 60374 | 23:15:42.055Z | false | 23:15:42.056Z | 23:15:42.056Z | reset at its first packet after the change |
| 60380 | 23:15:43.809Z | false | 23:15:43.810Z | 23:15:43.810Z | reset at its first packet after the change |
| 60382 | 23:15:43.912Z | false | (not observed) | 23:15:43.912Z | reset before the device sent on it (refused at Accept) |
| 60394 | 23:15:44.042Z | false | (not observed) | 23:15:44.042Z | reset before the device sent on it (refused at Accept) |
| 60402 | 23:15:44.053Z | false | (not observed) | 23:15:44.053Z | reset before the device sent on it (refused at Accept) |
| 60414 | 23:15:44.741Z | false | 23:15:44.742Z | 23:15:44.742Z | reset at its first packet after the change |
| 60430 | 23:15:44.755Z | false | (not observed) | 23:15:44.755Z | reset before the device sent on it (refused at Accept) |
| 60438 | 23:15:44.864Z | false | (not observed) | 23:15:44.864Z | reset before the device sent on it (refused at Accept) |
| 60448 | 23:15:44.875Z | false | (not observed) | 23:15:44.875Z | reset before the device sent on it (refused at Accept) |
| 60460 | 23:15:45.569Z | false | 23:15:45.570Z | 23:15:45.570Z | reset at its first packet after the change |
| 60468 | 23:15:45.582Z | false | (not observed) | 23:15:45.582Z | reset before the device sent on it (refused at Accept) |
| 60472 | 23:15:45.690Z | false | (not observed) | 23:15:45.691Z | reset before the device sent on it (refused at Accept) |
| 60478 | 23:15:45.702Z | false | (not observed) | 23:15:45.702Z | reset before the device sent on it (refused at Accept) |
| 60494 | 23:15:46.396Z | false | (not observed) | 23:15:46.396Z | reset before the device sent on it (refused at Accept) |
| 60506 | 23:15:46.408Z | false | (not observed) | 23:15:46.409Z | reset before the device sent on it (refused at Accept) |

The change began at 23:15:37.892Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-rekeyed-cisco_nxos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-rekeyed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:a0b9ec4f6a8bba4f07fb6893cad2c7dc469ae24848114e13498c74715175e238): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:a0b9ec4f6a8bba4f07fb6893cad2c7dc469ae24848114e13498c74715175e238: +0 device(s), -1, 0 changed; 0 quarantined
  device removed nx1 (cisco_nxos)
  scope all_devices: nx1 left
```

port49d said the change was in force by 23:16:02.748Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.3s |
| break-glass login plus three `show version` | logged in and ran them in 2.62s |

Break-glass ran from 23:16:08.047Z to 23:16:10.667Z (host UTC); the device opened 14 connection(s) to port 49 in that interval, and port49d refused 11 of them at Accept (11 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 5, clear on 0.

Records from the device since the change: `event=account` ×1; `event=unvalidated diagnosis=unadmitted_source type=acct` ×2; `event=unvalidated diagnosis=unadmitted_source type=authen` ×1; `event=unvalidated diagnosis=unadmitted_source type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=nx1 type=authen` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 33452 | 23:15:58.076Z | true | 23:16:02.864Z | 23:16:02.865Z | **reset mid-connection**: open across the change |
| 33464 | 23:16:04.836Z | false | 23:16:04.836Z | 23:16:04.836Z | reset at its first packet after the change |
| 33474 | 23:16:06.342Z | false | 23:16:06.343Z | 23:16:06.343Z | reset at its first packet after the change |
| 42732 | 23:16:08.057Z | false | 23:16:08.058Z | 23:16:08.058Z | reset at its first packet after the change |
| 42742 | 23:16:08.160Z | false | (not observed) | 23:16:08.160Z | reset before the device sent on it (refused at Accept) |
| 42758 | 23:16:08.290Z | false | (not observed) | 23:16:08.290Z | reset before the device sent on it (refused at Accept) |
| 42772 | 23:16:08.301Z | false | (not observed) | 23:16:08.301Z | reset before the device sent on it (refused at Accept) |
| 42776 | 23:16:08.994Z | false | 23:16:08.995Z | 23:16:08.995Z | reset at its first packet after the change |
| 42790 | 23:16:09.007Z | false | (not observed) | 23:16:09.008Z | reset before the device sent on it (refused at Accept) |
| 42806 | 23:16:09.118Z | false | (not observed) | 23:16:09.118Z | reset before the device sent on it (refused at Accept) |
| 42820 | 23:16:09.129Z | false | (not observed) | 23:16:09.129Z | reset before the device sent on it (refused at Accept) |
| 42822 | 23:16:09.826Z | false | 23:16:09.827Z | 23:16:09.827Z | reset at its first packet after the change |
| 42830 | 23:16:09.840Z | false | (not observed) | 23:16:09.840Z | reset before the device sent on it (refused at Accept) |
| 42836 | 23:16:09.951Z | false | (not observed) | 23:16:09.951Z | reset before the device sent on it (refused at Accept) |
| 42840 | 23:16:09.962Z | false | (not observed) | 23:16:09.962Z | reset before the device sent on it (refused at Accept) |
| 42842 | 23:16:10.649Z | false | (not observed) | 23:16:10.649Z | reset before the device sent on it (refused at Accept) |
| 42852 | 23:16:10.662Z | false | (not observed) | 23:16:10.662Z | reset before the device sent on it (refused at Accept) |

The change began at 23:16:02.748Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-removed-cisco_nxos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-removed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: `port49 inventory sync`:

```
published bundle 4 (sha256:9ba22fe7d0e49432bf71a007605d2f6b421f40f7832615309d3a77905555e0df): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:9ba22fe7d0e49432bf71a007605d2f6b421f40f7832615309d3a77905555e0df: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed nx1: admitted → refused
```

port49d said the change was in force by 23:16:27.016Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 7s |
| break-glass login plus three `show version` | logged in and ran them in 2.58s |

Break-glass ran from 23:16:34.016Z to 23:16:36.598Z (host UTC); the device opened 14 connection(s) to port 49 in that interval, and port49d refused 11 of them at Accept (11 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 5, clear on 0.

Records from the device since the change: `event=account` ×1; `event=unvalidated diagnosis=admission_refused device=nx1 type=acct` ×2; `event=unvalidated diagnosis=admission_refused device=nx1 type=authen` ×1; `event=unvalidated diagnosis=admission_refused device=nx1 type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=nx1 type=authen` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 60746 | 23:16:22.344Z | true | 23:16:27.138Z | 23:16:27.139Z | **reset mid-connection**: open across the change |
| 39200 | 23:16:29.604Z | false | 23:16:29.605Z | 23:16:29.605Z | reset at its first packet after the change |
| 39210 | 23:16:31.873Z | false | 23:16:31.874Z | 23:16:31.875Z | reset at its first packet after the change |
| 39216 | 23:16:34.026Z | false | 23:16:34.026Z | 23:16:34.026Z | reset at its first packet after the change |
| 39220 | 23:16:34.133Z | false | (not observed) | 23:16:34.133Z | reset before the device sent on it (refused at Accept) |
| 39230 | 23:16:34.260Z | false | (not observed) | 23:16:34.260Z | reset before the device sent on it (refused at Accept) |
| 39236 | 23:16:34.271Z | false | (not observed) | 23:16:34.271Z | reset before the device sent on it (refused at Accept) |
| 39244 | 23:16:34.957Z | false | 23:16:34.958Z | 23:16:34.958Z | reset at its first packet after the change |
| 39250 | 23:16:34.971Z | false | (not observed) | 23:16:34.971Z | reset before the device sent on it (refused at Accept) |
| 39258 | 23:16:35.077Z | false | (not observed) | 23:16:35.078Z | reset before the device sent on it (refused at Accept) |
| 39268 | 23:16:35.088Z | false | (not observed) | 23:16:35.088Z | reset before the device sent on it (refused at Accept) |
| 39282 | 23:16:35.776Z | false | (not observed) | 23:16:35.776Z | reset before the device sent on it (refused at Accept) |
| 39298 | 23:16:35.789Z | false | (not observed) | 23:16:35.790Z | reset before the device sent on it (refused at Accept) |
| 39314 | 23:16:35.897Z | false | (not observed) | 23:16:35.897Z | reset before the device sent on it (refused at Accept) |
| 39318 | 23:16:35.908Z | false | (not observed) | 23:16:35.908Z | reset before the device sent on it (refused at Accept) |
| 39324 | 23:16:36.581Z | false | 23:16:36.581Z | 23:16:36.582Z | reset at its first packet after the change |
| 39328 | 23:16:36.593Z | false | (not observed) | 23:16:36.594Z | reset before the device sent on it (refused at Accept) |

The change began at 23:16:27.016Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-refused-cisco_nxos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-refused-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: quarantined

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: port49d's broker.policy_file replaced by `tests/lab/quarantine-sync/policy.yaml`, whose probe grants quarantine nx1; the service's copy unchanged

port49d said the change was in force by 23:16:51.935Z (host UTC).

| step | outcome |
|---|---|
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.45s |
| break-glass login plus three `show version` | logged in and ran them in 2.61s |

Break-glass ran from 23:16:57.384Z to 23:16:59.990Z (host UTC); the device opened 14 connection(s) to port 49 in that interval, and port49d refused 11 of them at Accept (11 since the change).

TACACS+ headers the device sent after the change: single-connect flag (0x04) set on 5, clear on 0.

Records from the device since the change: `event=account` ×1; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=acct` ×2; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=authen` ×2; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=author` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 59086 | 23:16:48.271Z | true | 23:16:52.051Z | 23:16:52.051Z | **reset mid-connection**: open across the change |
| 59090 | 23:16:53.946Z | false | 23:16:53.946Z | 23:16:53.946Z | reset at its first packet after the change |
| 59100 | 23:16:55.086Z | false | 23:16:55.086Z | 23:16:55.086Z | reset at its first packet after the change |
| 59108 | 23:16:57.394Z | false | 23:16:57.395Z | 23:16:57.395Z | reset at its first packet after the change |
| 59118 | 23:16:57.502Z | false | (not observed) | 23:16:57.502Z | reset before the device sent on it (refused at Accept) |
| 59122 | 23:16:57.631Z | false | (not observed) | 23:16:57.631Z | reset before the device sent on it (refused at Accept) |
| 59132 | 23:16:57.642Z | false | (not observed) | 23:16:57.642Z | reset before the device sent on it (refused at Accept) |
| 43402 | 23:16:58.328Z | false | 23:16:58.328Z | 23:16:58.329Z | reset at its first packet after the change |
| 43408 | 23:16:58.341Z | false | (not observed) | 23:16:58.341Z | reset before the device sent on it (refused at Accept) |
| 43420 | 23:16:58.453Z | false | (not observed) | 23:16:58.454Z | reset before the device sent on it (refused at Accept) |
| 43424 | 23:16:58.465Z | false | (not observed) | 23:16:58.465Z | reset before the device sent on it (refused at Accept) |
| 43430 | 23:16:59.150Z | false | (not observed) | 23:16:59.150Z | reset before the device sent on it (refused at Accept) |
| 43440 | 23:16:59.163Z | false | (not observed) | 23:16:59.163Z | reset before the device sent on it (refused at Accept) |
| 43448 | 23:16:59.275Z | false | (not observed) | 23:16:59.275Z | reset before the device sent on it (refused at Accept) |
| 43460 | 23:16:59.286Z | false | (not observed) | 23:16:59.286Z | reset before the device sent on it (refused at Accept) |
| 43468 | 23:16:59.971Z | false | 23:16:59.972Z | 23:16:59.972Z | reset at its first packet after the change |
| 43470 | 23:16:59.984Z | false | (not observed) | 23:16:59.984Z | reset before the device sent on it (refused at Accept) |

The change began at 23:16:51.935Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L31-quarantined-cisco_nxos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L31-quarantined-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Summary

| phase | break-glass login plus three `show version` | bar | connections refused at Accept during break-glass | refused at Accept since the change | records from the device |
|---|---|---|---|---|---|
| rekeyed | logged in and ran them in 2.61s | (the control) | 11 | 11 | `event=account` ×1; `event=unvalidated diagnosis=no_known_key_matches type=acct` ×2; `event=unvalidated diagnosis=no_known_key_matches type=authen` ×1; `event=unvalidated diagnosis=no_known_key_matches type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=nx1 type=authen` ×1 |
| removed | logged in and ran them in 2.62s | 4.11s | 11 | 11 | `event=account` ×1; `event=unvalidated diagnosis=unadmitted_source type=acct` ×2; `event=unvalidated diagnosis=unadmitted_source type=authen` ×1; `event=unvalidated diagnosis=unadmitted_source type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=nx1 type=authen` ×1 |
| refused | logged in and ran them in 2.58s | 4.11s | 11 | 11 | `event=account` ×1; `event=unvalidated diagnosis=admission_refused device=nx1 type=acct` ×2; `event=unvalidated diagnosis=admission_refused device=nx1 type=authen` ×1; `event=unvalidated diagnosis=admission_refused device=nx1 type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=nx1 type=authen` ×1 |
| quarantined | logged in and ran them in 2.61s | 4.11s | 11 | 11 | `event=account` ×1; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=acct` ×2; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=authen` ×2; `event=unvalidated reason=device_quarantined diagnosis=device_quarantined device=nx1 type=author` ×2 |


