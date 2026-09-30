# L29-reload — arista_eos

- **Date measured:** 2026-09-30
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L29-reload-rekeyed-arista_eos.pcap` — 284 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What a device does when port49d resets an open connection at its first packet after a reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29).

## Observation

port49d, port49 and port49-inventory built from `adc5746` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 380ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 2.14s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `tacacs-server host 172.100.100.1 single-connection`.

Device clock, `show clock` over break-glass with port49d stopped: `Wed Sep 30 20:33:27 2026; Timezone: UTC; Clock source: local`; host clock 20:33:28.382Z before, 20:33:28.634Z after. The host clock is the reference: port49d reads it, and every time here is the host's.

**Reading the records and the captures.** port49d writes one record for a packet on a connection it admitted before the change and no longer admits: `event=unvalidated reason=device_unknown`, naming the device the connection was admitted as, then resets that connection (`admission_withdrawn` for a rename, re-key or re-platform; `unadmitted_source` for a removal; `admission_refused` for a refusal). A packet opening a new connection is recorded without `reason=device_unknown`: `unadmitted_source` with no device, `admission_refused` naming it, or `no_known_key_matches` for a key it does not hold; a source inside the backoff a key miss earned is reset at Accept with no record at all. So the records say whether port49d reset a connection that was open across the change; they cannot say which of the device's connections carried the command in flight (an unvalidated record carries the source address, not its port), nor what the device did with the reset. The first comes from the capture: the per-connection table below reads each connection's 4-tuple, whether the device sent on it before the change, and when port49d reset it. The second comes from the device's own output in the open session. A phase with no such record, or whose capture holds no connection reset mid-connection, measured L28's first-packet case and fails.

Each phase has a capture of its own, named in its section; the header's is the last phase's.

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:0754c64f0d1fc80a7defafe9c2909daafd80b92c38e1ecf0169c54dd6c68b070): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:0754c64f0d1fc80a7defafe9c2909daafd80b92c38e1ecf0169c54dd6c68b070: +0 device(s), -1, 0 changed; 0 quarantined
  device removed leaf1 (arista_eos)
  scope all_devices: leaf1 left
```

Times are the host's, UTC: the change began 20:33:31.509Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:33:35.052Z; the command in flight was sent at 20:33:35.052Z.

| step | outcome |
|---|---|
| token session (`alice02`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 200ms: `% Authorization denied for command 'show version': Unknown role` |
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 2.67s |
| break-glass login plus three `show version` | logged in and ran them in 2.09s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×2; `event=unvalidated diagnosis=unadmitted_source type=author` ×1; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=leaf1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×3; `event=unvalidated diagnosis=unadmitted_source type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 36800 | 20:33:30.206Z | true | (not observed) | (not observed) | not reset by port49d |
| 36806 | 20:33:30.734Z | true | 20:33:35.055Z | 20:33:35.055Z | **reset mid-connection**: open across the change |
| 36810 | 20:33:35.155Z | false | 20:33:35.156Z | 20:33:35.257Z | reset at its first packet after the change |
| 36824 | 20:33:35.363Z | false | 20:33:35.363Z | 20:33:35.564Z | reset at its first packet after the change |
| 36826 | 20:33:35.565Z | false | 20:33:35.566Z | 20:33:35.967Z | reset at its first packet after the change |
| 37520 | 20:33:45.393Z | false | 20:33:45.393Z | 20:33:46.194Z | reset at its first packet after the change |
| 57216 | 20:33:48.064Z | false | 20:33:48.064Z | 20:33:49.665Z | reset at its first packet after the change |
| 57230 | 20:33:49.846Z | false | 20:33:49.846Z | 20:33:53.047Z | reset at its first packet after the change |
| 57232 | 20:33:49.883Z | false | (not observed) | 20:33:49.883Z | reset before the device sent on it (refused at Accept) |
| 57248 | 20:33:49.925Z | false | (not observed) | 20:33:49.925Z | reset before the device sent on it (refused at Accept) |
| 57264 | 20:33:49.975Z | false | (not observed) | 20:33:49.976Z | reset before the device sent on it (refused at Accept) |
| 57280 | 20:33:50.020Z | false | (not observed) | 20:33:50.020Z | reset before the device sent on it (refused at Accept) |
| 57292 | 20:33:50.070Z | false | 20:33:50.070Z | 20:33:50.070Z | reset |
| 57300 | 20:33:50.112Z | false | (not observed) | 20:33:50.113Z | reset before the device sent on it (refused at Accept) |
| 57312 | 20:33:53.048Z | false | 20:33:53.048Z | 20:33:58.049Z | reset at its first packet after the change |
| 34010 | 20:33:58.050Z | false | 20:33:58.051Z | (not observed) | not reset by port49d |

The change began at 20:33:31.509Z (host UTC); 1 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-removed-arista_eos.pcap` — 242 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-removed-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: renamed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: `port49 inventory sync`:

```
published bundle 4 (sha256:7cedb6a6e6f234a05699dc527f767f1336d1dc357c74eb671ffda002ad3b722e): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:7cedb6a6e6f234a05699dc527f767f1336d1dc357c74eb671ffda002ad3b722e: +1 device(s), -1, 0 changed; 0 quarantined
  device removed leaf1 (arista_eos)
! device added leaf1-b (arista_eos): admitted
  scope all_devices: leaf1 left
  scope all_devices: leaf1-b joined
```

Times are the host's, UTC: the change began 20:34:03.225Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:34:06.760Z; the command in flight was sent at 20:34:06.760Z.

| step | outcome |
|---|---|
| token session (`alice04`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 100ms: `% Authorization denied for command 'show version': port49: this session was not authenticated by port49` |
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 530ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 530ms |

Records from the device since the change, before the next logins: `event=account` ×1; `event=authorize_command reason=context_missing` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=leaf1 type=author` ×1

Records from the device during the next logins: `event=redeem reason=device_mismatch` ×1; `event=redeem reason=token_not_found` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 34010 | 20:34:01.640Z | false | (not observed) | 20:34:01.640Z | reset before the change |
| 34014 | 20:34:01.642Z | false | (not observed) | 20:34:01.642Z | reset before the change |
| 34026 | 20:34:01.642Z | false | (not observed) | 20:34:01.642Z | reset before the change |
| 34028 | 20:34:01.643Z | false | (not observed) | 20:34:01.643Z | reset before the change |
| 34042 | 20:34:01.644Z | false | (not observed) | 20:34:01.644Z | reset before the change |
| 34058 | 20:34:01.645Z | false | (not observed) | 20:34:01.645Z | reset before the change |
| 34066 | 20:34:01.645Z | false | (not observed) | 20:34:01.645Z | reset before the change |
| 34072 | 20:34:01.646Z | false | (not observed) | 20:34:01.646Z | reset before the change |
| 34074 | 20:34:01.920Z | true | (not observed) | (not observed) | not reset by port49d |
| 34082 | 20:34:02.453Z | true | 20:34:06.762Z | 20:34:06.762Z | **reset mid-connection**: open across the change |
| 34092 | 20:34:06.864Z | false | 20:34:06.864Z | (not observed) | not reset by port49d |
| 57634 | 20:34:17.529Z | false | 20:34:17.529Z | (not observed) | not reset by port49d |

The change began at 20:34:03.225Z (host UTC); 1 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-renamed-arista_eos.pcap` — 190 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-renamed-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: replatformed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: `port49 inventory sync`:

```
published bundle 6 (sha256:6e06fa58349ff351995cfc4d907194da2340e2ca117ae70e561024b67784cc64): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:6e06fa58349ff351995cfc4d907194da2340e2ca117ae70e561024b67784cc64: +0 device(s), -0, 1 changed; 0 quarantined
  platform_changed leaf1: arista_eos → cisco_nxos
```

Times are the host's, UTC: the change began 20:34:31.147Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:34:34.681Z; the command in flight was sent at 20:34:34.681Z.

| step | outcome |
|---|---|
| token session (`alice06`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 100ms |
| next token login (`alice07`) | logged in in 190ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 530ms |

Records from the device since the change, before the next logins: `event=account` ×2; `event=authorize_command reason=permit_dominates` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=leaf1 type=author` ×1

Records from the device during the next logins: `event=account` ×2; `event=redeem reason=token_not_found` ×1; `event=redeem reason=token_redeemed` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 50700 | 20:34:29.837Z | true | (not observed) | (not observed) | not reset by port49d |
| 50704 | 20:34:30.372Z | true | 20:34:34.684Z | 20:34:34.684Z | **reset mid-connection**: open across the change |
| 50718 | 20:34:34.785Z | false | 20:34:34.785Z | (not observed) | not reset by port49d |

The change began at 20:34:31.147Z (host UTC); 1 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-replatformed-arista_eos.pcap` — 160 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-replatformed-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: `port49 inventory sync`:

```
published bundle 8 (sha256:2a02bd5a21ec83b40fd4f1deb3e4c5fcdfdaed445128061deaf4fb6e4bfe303b): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:2a02bd5a21ec83b40fd4f1deb3e4c5fcdfdaed445128061deaf4fb6e4bfe303b: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed leaf1: admitted → refused
```

Times are the host's, UTC: the change began 20:34:58.701Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:35:02.234Z; the command in flight was sent at 20:35:02.234Z.

| step | outcome |
|---|---|
| token session (`alice08`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` |
| next token login (`alice09`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 2.09s |
| break-glass login plus three `show version` | logged in and ran them in 320ms |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=admission_refused device=leaf1 type=acct` ×2; `event=unvalidated diagnosis=admission_refused device=leaf1 type=author` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=leaf1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=admission_refused device=leaf1 type=acct` ×10; `event=unvalidated diagnosis=admission_refused device=leaf1 type=authen` ×2; `event=unvalidated diagnosis=admission_refused device=leaf1 type=author` ×6

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 43914 | 20:34:57.402Z | true | (not observed) | (not observed) | not reset by port49d |
| 59736 | 20:34:57.928Z | true | 20:35:02.238Z | 20:35:02.238Z | **reset mid-connection**: open across the change |
| 59744 | 20:35:02.339Z | false | 20:35:02.339Z | 20:35:02.340Z | reset at its first packet after the change |
| 59754 | 20:35:02.442Z | false | 20:35:02.442Z | 20:35:02.442Z | reset at its first packet after the change |
| 59770 | 20:35:02.443Z | false | 20:35:02.443Z | 20:35:02.443Z | reset at its first packet after the change |
| 38494 | 20:35:12.480Z | false | 20:35:12.480Z | 20:35:12.480Z | reset at its first packet after the change |
| 38498 | 20:35:14.560Z | false | 20:35:14.560Z | 20:35:14.561Z | reset at its first packet after the change |
| 38502 | 20:35:14.573Z | false | 20:35:14.573Z | 20:35:14.573Z | reset at its first packet after the change |
| 38504 | 20:35:14.573Z | false | 20:35:14.573Z | 20:35:14.573Z | reset at its first packet after the change |
| 38506 | 20:35:14.608Z | false | 20:35:14.608Z | 20:35:14.609Z | reset at its first packet after the change |
| 38510 | 20:35:14.651Z | false | 20:35:14.651Z | 20:35:14.651Z | reset at its first packet after the change |
| 38516 | 20:35:14.652Z | false | 20:35:14.653Z | 20:35:14.653Z | reset at its first packet after the change |
| 38518 | 20:35:14.653Z | false | 20:35:14.653Z | 20:35:14.653Z | reset at its first packet after the change |
| 38522 | 20:35:14.700Z | false | 20:35:14.701Z | 20:35:14.701Z | reset at its first packet after the change |
| 38528 | 20:35:14.744Z | false | 20:35:14.744Z | 20:35:14.744Z | reset at its first packet after the change |
| 38530 | 20:35:14.746Z | false | 20:35:14.746Z | 20:35:14.746Z | reset at its first packet after the change |
| 38546 | 20:35:14.747Z | false | 20:35:14.747Z | 20:35:14.747Z | reset at its first packet after the change |
| 38562 | 20:35:14.793Z | false | 20:35:14.794Z | 20:35:14.794Z | reset at its first packet after the change |
| 38572 | 20:35:14.837Z | false | 20:35:14.837Z | 20:35:14.837Z | reset at its first packet after the change |
| 38584 | 20:35:14.839Z | false | 20:35:14.839Z | 20:35:14.839Z | reset at its first packet after the change |
| 38592 | 20:35:14.840Z | false | 20:35:14.840Z | 20:35:14.840Z | reset at its first packet after the change |
| 38606 | 20:35:14.859Z | false | 20:35:14.859Z | 20:35:14.859Z | reset at its first packet after the change |
| 38620 | 20:35:14.859Z | false | 20:35:14.859Z | 20:35:14.859Z | reset at its first packet after the change |

The change began at 20:34:58.701Z (host UTC); 1 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-refused-arista_eos.pcap` — 348 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-refused-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: port49d's broker.policy_file given `- {match: {name: leaf1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the change began 20:35:27.941Z; port49d said `port49d: policy reloaded` by 20:35:29.445Z; the command in flight was sent at 20:35:29.445Z.

| step | outcome |
|---|---|
| token session (`alice10`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` |
| next token login (`alice11`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 1.45s |
| break-glass login plus three `show version` | logged in and ran them in 320ms |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1; `event=unvalidated diagnosis=no_known_key_matches type=author` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=leaf1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 45970 | 20:35:26.634Z | true | (not observed) | (not observed) | not reset by port49d |
| 45982 | 20:35:27.165Z | true | 20:35:29.448Z | 20:35:29.448Z | **reset mid-connection**: open across the change |
| 50748 | 20:35:29.550Z | false | 20:35:29.550Z | 20:35:29.550Z | reset at its first packet after the change |
| 50750 | 20:35:29.652Z | false | 20:35:29.652Z | 20:35:29.653Z | reset at its first packet after the change |
| 50760 | 20:35:29.653Z | false | (not observed) | 20:35:29.653Z | reset before the device sent on it (refused at Accept) |
| 43184 | 20:35:39.687Z | false | 20:35:39.687Z | 20:35:39.687Z | reset at its first packet after the change |
| 43196 | 20:35:41.136Z | false | 20:35:41.137Z | 20:35:41.137Z | reset at its first packet after the change |
| 43198 | 20:35:41.148Z | false | (not observed) | 20:35:41.148Z | reset before the device sent on it (refused at Accept) |
| 43210 | 20:35:41.148Z | false | (not observed) | 20:35:41.149Z | reset before the device sent on it (refused at Accept) |
| 43224 | 20:35:41.185Z | false | (not observed) | 20:35:41.185Z | reset before the device sent on it (refused at Accept) |
| 43230 | 20:35:41.229Z | false | (not observed) | 20:35:41.229Z | reset before the device sent on it (refused at Accept) |
| 43244 | 20:35:41.231Z | false | (not observed) | 20:35:41.231Z | reset before the device sent on it (refused at Accept) |
| 43252 | 20:35:41.231Z | false | (not observed) | 20:35:41.231Z | reset before the device sent on it (refused at Accept) |
| 43268 | 20:35:41.280Z | false | (not observed) | 20:35:41.281Z | reset before the device sent on it (refused at Accept) |
| 43270 | 20:35:41.324Z | false | (not observed) | 20:35:41.324Z | reset before the device sent on it (refused at Accept) |
| 43286 | 20:35:41.326Z | false | (not observed) | 20:35:41.327Z | reset before the device sent on it (refused at Accept) |
| 43298 | 20:35:41.327Z | false | (not observed) | 20:35:41.327Z | reset before the device sent on it (refused at Accept) |
| 43310 | 20:35:41.377Z | false | (not observed) | 20:35:41.377Z | reset before the device sent on it (refused at Accept) |
| 43322 | 20:35:41.421Z | false | (not observed) | 20:35:41.421Z | reset before the device sent on it (refused at Accept) |
| 43324 | 20:35:41.423Z | false | (not observed) | 20:35:41.423Z | reset before the device sent on it (refused at Accept) |
| 43336 | 20:35:41.424Z | false | (not observed) | 20:35:41.424Z | reset before the device sent on it (refused at Accept) |
| 43346 | 20:35:41.442Z | false | 20:35:41.442Z | 20:35:41.442Z | reset |
| 43348 | 20:35:41.443Z | false | (not observed) | 20:35:41.443Z | reset before the device sent on it (refused at Accept) |

The change began at 20:35:27.941Z (host UTC); 1 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-rekeyed-arista_eos.pcap` — 284 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


