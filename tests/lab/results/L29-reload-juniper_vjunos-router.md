**THIS RUN FAILED ITS PREMISE CHECKS: NOT A MEASUREMENT.** It is re-run, never read as an answer (plan 6b Task 19). Failed checks:

- renamed: no connection open across the change was reset (no reason=device_unknown record with diagnosis admission_withdrawn from the device): this phase measured L28's first-packet case, not L29's
- renamed: the capture holds no connection the device sent on before the change and port49d reset after it: no reset mid-connection was captured
- replatformed: no connection open across the change was reset (no reason=device_unknown record with diagnosis admission_withdrawn from the device): this phase measured L28's first-packet case, not L29's
- replatformed: the capture holds no connection the device sent on before the change and port49d reset after it: no reset mid-connection was captured
- refused: the capture holds no connection the device sent on before the change and port49d reset after it: no reset mid-connection was captured
- rekeyed: no connection open across the change was reset (no reason=device_unknown record with diagnosis admission_withdrawn from the device): this phase measured L28's first-packet case, not L29's
- rekeyed: the capture holds no connection the device sent on before the change and port49d reset after it: no reset mid-connection was captured

# L29-reload — juniper_vjunos-router

- **Date measured:** 2026-09-30
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 250 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What a device does when port49d resets an open connection at its first packet after a reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29).

## Observation

port49d, port49 and port49-inventory built from `adc5746` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 500ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.08s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`.

Device clock, `show system uptime` over break-glass with port49d stopped: `Current time: 2026-09-30 20:49:40 UTC`; host clock 20:49:42.703Z before, 20:49:42.954Z after. The host clock is the reference: port49d reads it, and every time here is the host's.

**Reading the records and the captures.** port49d writes one record for a packet on a connection it admitted before the change and no longer admits: `event=unvalidated reason=device_unknown`, naming the device the connection was admitted as, then resets that connection (`admission_withdrawn` for a rename, re-key or re-platform; `unadmitted_source` for a removal; `admission_refused` for a refusal). A packet opening a new connection is recorded without `reason=device_unknown`: `unadmitted_source` with no device, `admission_refused` naming it, or `no_known_key_matches` for a key it does not hold; a source inside the backoff a key miss earned is reset at Accept with no record at all. So the records say whether port49d reset a connection that was open across the change; they cannot say which of the device's connections carried the command in flight (an unvalidated record carries the source address, not its port), nor what the device did with the reset. The first comes from the capture: the per-connection table below reads each connection's 4-tuple, whether the device sent on it before the change, and when port49d reset it. The second comes from the device's own output in the open session. A phase with no such record, or whose capture holds no connection reset mid-connection, measured L28's first-packet case and fails.

Each phase has a capture of its own, named in its section; the header's is the last phase's.

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:8f7111515f455add6e75977daadf12c37d2f66dda9452d1268242f354f963d2c): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:8f7111515f455add6e75977daadf12c37d2f66dda9452d1268242f354f963d2c: +0 device(s), -1, 0 changed; 0 quarantined
  device removed srx1 (juniper_junos)
  scope all_devices: srx1 left
```

Times are the host's, UTC: the change began 20:49:51.809Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:49:54.340Z; the command in flight was sent at 20:49:54.341Z.

| step | outcome |
|---|---|
| token session (`alice02`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 9.69s |
| break-glass login plus three `show version` | logged in and ran them in 3.47s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×4; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×1; `event=unvalidated diagnosis=unadmitted_source type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 45612 | 20:49:44.523Z | true | (not observed) | (not observed) | not reset by port49d |
| 45620 | 20:49:45.047Z | true | (not observed) | (not observed) | not reset by port49d |
| 45626 | 20:49:46.173Z | true | 20:49:56.187Z | 20:49:56.187Z | **reset mid-connection**: open across the change |
| 43394 | 20:49:51.101Z | true | (not observed) | (not observed) | not reset by port49d |
| 43404 | 20:49:56.188Z | false | 20:49:56.188Z | 20:49:56.289Z | reset at its first packet after the change |
| 43414 | 20:49:56.290Z | false | 20:49:56.291Z | 20:49:56.492Z | reset at its first packet after the change |
| 43428 | 20:49:56.493Z | false | 20:49:56.493Z | 20:49:56.894Z | reset at its first packet after the change |
| 43434 | 20:49:56.895Z | false | 20:49:56.896Z | 20:49:57.697Z | reset at its first packet after the change |
| 33922 | 20:50:04.786Z | false | 20:50:04.787Z | 20:50:06.388Z | reset at its first packet after the change |
| 33930 | 20:50:06.411Z | false | 20:50:06.412Z | 20:50:09.612Z | reset at its first packet after the change |
| 44518 | 20:50:14.473Z | false | 20:50:14.473Z | 20:50:19.474Z | reset at its first packet after the change |
| 44524 | 20:50:17.706Z | false | (not observed) | 20:50:17.707Z | reset before the device sent on it (refused at Accept) |
| 44532 | 20:50:17.707Z | false | (not observed) | 20:50:17.707Z | reset before the device sent on it (refused at Accept) |
| 44548 | 20:50:17.707Z | false | (not observed) | 20:50:17.707Z | reset before the device sent on it (refused at Accept) |
| 44552 | 20:50:17.708Z | false | (not observed) | 20:50:17.708Z | reset before the device sent on it (refused at Accept) |
| 44568 | 20:50:17.708Z | false | (not observed) | 20:50:17.708Z | reset before the device sent on it (refused at Accept) |
| 44238 | 20:50:22.719Z | false | 20:50:22.720Z | 20:50:27.721Z | reset at its first packet after the change |
| 44250 | 20:50:25.729Z | false | (not observed) | 20:50:25.729Z | reset before the device sent on it (refused at Accept) |
| 44260 | 20:50:25.731Z | false | (not observed) | 20:50:25.731Z | reset before the device sent on it (refused at Accept) |
| 44272 | 20:50:25.732Z | false | (not observed) | 20:50:25.732Z | reset before the device sent on it (refused at Accept) |

The change began at 20:49:51.809Z (host UTC); 1 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap` — 308 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: renamed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 4 (sha256:61209118683d65694cccefa9cf84ad8fa55e1dd4d14c4b23cc6ce7a7e8edfe39): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:61209118683d65694cccefa9cf84ad8fa55e1dd4d14c4b23cc6ce7a7e8edfe39: +1 device(s), -1, 0 changed; 0 quarantined
  device removed srx1 (juniper_junos)
! device added srx1-b (juniper_junos): admitted
  scope all_devices: srx1 left
  scope all_devices: srx1-b joined
```

Times are the host's, UTC: the change began 20:50:37.000Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:50:39.529Z; the command in flight was sent at 20:50:39.529Z.

| step | outcome |
|---|---|
| token session (`alice04`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 6.57s |
| break-glass login plus three `show version` | logged in and ran them in 960ms |

Records from the device since the change, before the next logins: `event=account` ×6

Records from the device during the next logins: `event=account` ×9; `event=redeem reason=device_mismatch` ×2; `event=redeem reason=token_not_found` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 42786 | 20:50:29.703Z | true | (not observed) | (not observed) | not reset by port49d |
| 42796 | 20:50:30.228Z | true | (not observed) | (not observed) | not reset by port49d |
| 42806 | 20:50:36.290Z | true | (not observed) | (not observed) | not reset by port49d |
| 45582 | 20:50:40.742Z | false | 20:50:40.743Z | (not observed) | not reset by port49d |
| 53992 | 20:50:49.976Z | false | 20:50:49.977Z | (not observed) | not reset by port49d |
| 54000 | 20:50:50.498Z | false | 20:50:50.498Z | (not observed) | not reset by port49d |
| 54016 | 20:50:56.547Z | false | 20:50:56.548Z | (not observed) | not reset by port49d |

The change began at 20:50:37.000Z (host UTC); 0 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap` — 248 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: replatformed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 6 (sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4: +0 device(s), -0, 1 changed; 0 quarantined
  platform_changed srx1: juniper_junos → arista_eos
```

Times are the host's, UTC: the change began 20:51:16.545Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:51:19.078Z; the command in flight was sent at 20:51:19.078Z.

| step | outcome |
|---|---|
| token session (`alice06`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice07`) | logged in in 30ms |
| break-glass login plus three `show version` | logged in and ran them in 960ms |

Records from the device since the change, before the next logins: `event=account` ×5

Records from the device during the next logins: `event=account` ×9; `event=authorize_session reason=service_unsupported` ×1; `event=redeem reason=token_not_found` ×1; `event=redeem reason=token_redeemed` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 45582 | 20:51:08.972Z | false | 20:51:20.792Z | 20:51:20.792Z | reset at its first packet after the change |
| 46216 | 20:51:09.252Z | true | (not observed) | (not observed) | not reset by port49d |
| 46228 | 20:51:09.779Z | true | (not observed) | (not observed) | not reset by port49d |
| 46244 | 20:51:15.837Z | true | (not observed) | (not observed) | not reset by port49d |
| 46436 | 20:51:20.793Z | false | 20:51:20.794Z | (not observed) | not reset by port49d |
| 59174 | 20:51:29.523Z | false | 20:51:29.523Z | (not observed) | not reset by port49d |
| 59186 | 20:51:29.549Z | false | 20:51:29.549Z | (not observed) | not reset by port49d |

The change began at 20:51:16.545Z (host UTC); 0 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap` — 224 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 8 (sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed srx1: admitted → refused
```

Times are the host's, UTC: the change began 20:51:49.657Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:51:52.189Z; the command in flight was sent at 20:51:52.189Z.

| step | outcome |
|---|---|
| token session (`alice08`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice09`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s |
| break-glass login plus three `show version` | logged in and ran them in 480ms |

Records from the device since the change, before the next logins: `event=account` ×2; `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×9; `event=unvalidated diagnosis=admission_refused device=srx1 type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 46436 | 20:51:42.092Z | false | 20:51:50.824Z | 20:51:50.824Z | reset at its first packet after the change |
| 53884 | 20:51:42.374Z | true | (not observed) | (not observed) | not reset by port49d |
| 53900 | 20:51:42.898Z | true | (not observed) | (not observed) | not reset by port49d |
| 50042 | 20:51:48.949Z | true | (not observed) | (not observed) | not reset by port49d |
| 50056 | 20:51:50.825Z | false | 20:51:50.825Z | 20:51:55.834Z | reset at its first packet after the change |
| 50066 | 20:51:55.835Z | false | 20:51:55.835Z | 20:51:55.835Z | reset at its first packet after the change |
| 50080 | 20:51:55.836Z | false | 20:51:55.836Z | 20:51:55.836Z | reset at its first packet after the change |
| 40666 | 20:52:02.631Z | false | 20:52:02.632Z | 20:52:02.632Z | reset at its first packet after the change |
| 40672 | 20:52:02.652Z | false | 20:52:02.652Z | 20:52:02.652Z | reset at its first packet after the change |
| 40688 | 20:52:07.708Z | false | 20:52:07.708Z | 20:52:07.708Z | reset at its first packet after the change |
| 53414 | 20:52:10.851Z | false | 20:52:10.852Z | 20:52:10.852Z | reset at its first packet after the change |
| 53416 | 20:52:10.852Z | false | 20:52:10.853Z | 20:52:10.853Z | reset at its first packet after the change |
| 53418 | 20:52:10.853Z | false | 20:52:10.854Z | 20:52:10.854Z | reset at its first packet after the change |
| 53420 | 20:52:10.854Z | false | 20:52:10.854Z | 20:52:10.854Z | reset at its first packet after the change |
| 53432 | 20:52:10.855Z | false | 20:52:10.855Z | 20:52:10.855Z | reset at its first packet after the change |
| 53436 | 20:52:10.855Z | false | 20:52:10.856Z | 20:52:10.856Z | reset at its first packet after the change |
| 53440 | 20:52:10.856Z | false | 20:52:10.856Z | 20:52:10.856Z | reset at its first packet after the change |
| 53456 | 20:52:10.857Z | false | 20:52:10.857Z | 20:52:10.857Z | reset at its first packet after the change |
| 53460 | 20:52:10.857Z | false | 20:52:10.857Z | 20:52:10.857Z | reset at its first packet after the change |

The change began at 20:51:49.657Z (host UTC); 0 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap` — 290 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: srx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the change began 20:52:27.238Z; port49d said `port49d: policy reloaded` by 20:52:28.742Z; the command in flight was sent at 20:52:28.742Z.

| step | outcome |
|---|---|
| token session (`alice10`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice11`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.06s |
| break-glass login plus three `show version` | logged in and ran them in 460ms |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1; `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 43354 | 20:52:19.949Z | true | (not observed) | (not observed) | not reset by port49d |
| 43362 | 20:52:20.473Z | true | (not observed) | (not observed) | not reset by port49d |
| 43370 | 20:52:26.531Z | true | (not observed) | (not observed) | not reset by port49d |
| 38838 | 20:52:30.875Z | false | 20:52:30.875Z | 20:52:30.876Z | reset at its first packet after the change |
| 38852 | 20:52:30.876Z | false | (not observed) | 20:52:30.876Z | reset before the device sent on it (refused at Accept) |
| 38864 | 20:52:30.877Z | false | (not observed) | 20:52:30.877Z | reset before the device sent on it (refused at Accept) |
| 38866 | 20:52:30.877Z | false | (not observed) | 20:52:30.877Z | reset before the device sent on it (refused at Accept) |
| 38872 | 20:52:30.878Z | false | (not observed) | 20:52:30.878Z | reset before the device sent on it (refused at Accept) |
| 38882 | 20:52:30.878Z | false | (not observed) | 20:52:30.879Z | reset before the device sent on it (refused at Accept) |
| 58810 | 20:52:39.186Z | false | 20:52:39.187Z | 20:52:39.187Z | reset at its first packet after the change |
| 58826 | 20:52:39.204Z | false | (not observed) | 20:52:39.204Z | reset before the device sent on it (refused at Accept) |
| 58838 | 20:52:44.251Z | false | 20:52:44.251Z | 20:52:44.251Z | reset at its first packet after the change |
| 58840 | 20:52:45.895Z | false | 20:52:45.896Z | 20:52:45.896Z | reset at its first packet after the change |
| 58850 | 20:52:45.897Z | false | (not observed) | 20:52:45.897Z | reset before the device sent on it (refused at Accept) |
| 58852 | 20:52:45.898Z | false | (not observed) | 20:52:45.898Z | reset before the device sent on it (refused at Accept) |
| 58854 | 20:52:45.899Z | false | (not observed) | 20:52:45.899Z | reset before the device sent on it (refused at Accept) |
| 58864 | 20:52:45.899Z | false | (not observed) | 20:52:45.899Z | reset before the device sent on it (refused at Accept) |
| 58870 | 20:52:45.900Z | false | (not observed) | 20:52:45.900Z | reset before the device sent on it (refused at Accept) |
| 58880 | 20:52:45.901Z | false | (not observed) | 20:52:45.901Z | reset before the device sent on it (refused at Accept) |
| 58892 | 20:52:45.901Z | false | (not observed) | 20:52:45.902Z | reset before the device sent on it (refused at Accept) |
| 58908 | 20:52:45.902Z | false | (not observed) | 20:52:45.902Z | reset before the device sent on it (refused at Accept) |

The change began at 20:52:27.238Z (host UTC); 0 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 250 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


