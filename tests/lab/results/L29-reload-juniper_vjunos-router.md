**THIS RUN FAILED ITS PREMISE CHECKS: NOT A MEASUREMENT.** It is re-run, never read as an answer (plan 6b Task 19). Failed checks:

- renamed: the capture holds no connection open across the change that port49d reset after it: no reset of an open connection was captured
- refused: no connection open across the change was reset (no reason=device_unknown record with diagnosis admission_refused from the device): this phase measured L28's first-packet case, not L29's
- refused: the capture holds no connection open across the change that port49d reset after it: no reset of an open connection was captured
- rekeyed: the capture holds no connection open across the change that port49d reset after it: no reset of an open connection was captured

# L29-reload — juniper_vjunos-router

- **Date measured:** 2026-09-30
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 246 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What a device does when port49d resets an open connection at its first packet after a reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29).

## Observation

port49d, port49 and port49-inventory built from `088f18a` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 510ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.07s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`.

Device clock, `show system uptime` over break-glass with port49d stopped: `Current time: 2026-09-30 21:10:44 UTC`; host clock 21:10:46.572Z before, 21:10:46.822Z after. The host clock is the reference: port49d reads it, and every time here is the host's.

**Reading the records and the captures.** port49d writes one record for a packet on a connection it admitted before the change and no longer admits: `event=unvalidated reason=device_unknown`, naming the device the connection was admitted as, then resets that connection (`admission_withdrawn` for a rename, re-key or re-platform; `unadmitted_source` for a removal; `admission_refused` for a refusal). A packet opening a new connection is recorded without `reason=device_unknown`: `unadmitted_source` with no device, `admission_refused` naming it, or `no_known_key_matches` for a key it does not hold; a source inside the backoff a key miss earned is reset at Accept with no record at all. So the records say whether port49d reset a connection that was open across the change; they cannot say which of the device's connections carried the command in flight (an unvalidated record carries the source address, not its port), nor what the device did with the reset. The first comes from the capture: the per-connection table below reads each connection's 4-tuple, whether the device sent on it before the change, and when port49d reset it. The second comes from the device's own output in the open session. A phase with no such record, or whose capture holds no connection reset mid-connection, measured L28's first-packet case and fails. A connection open before the change with nothing sent on it, and reset at its first packet after it, is a reset of an open connection too, and counts when port49d's device_unknown record names it so.

Each phase has a capture of its own, named in its section; the header's is the last phase's.

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:8f7111515f455add6e75977daadf12c37d2f66dda9452d1268242f354f963d2c): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:8f7111515f455add6e75977daadf12c37d2f66dda9452d1268242f354f963d2c: +0 device(s), -1, 0 changed; 0 quarantined
  device removed srx1 (juniper_junos)
  scope all_devices: srx1 left
```

Times are the host's, UTC: the change began 21:10:55.678Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:10:58.208Z; the command in flight was sent at 21:10:58.208Z.

| step | outcome |
|---|---|
| token session (`alice02`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 8.07s |
| break-glass login plus three `show version` | logged in and ran them in 3.46s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×5; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×1; `event=unvalidated diagnosis=unadmitted_source type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 39858 | 21:10:48.389Z | true | (not observed) | (not observed) | not reset by port49d |
| 39870 | 21:10:48.914Z | true | (not observed) | (not observed) | not reset by port49d |
| 39880 | 21:10:49.443Z | true | 21:10:59.455Z | 21:10:59.456Z | **reset mid-connection**: open across the change |
| 39892 | 21:10:54.968Z | true | (not observed) | (not observed) | not reset by port49d |
| 40552 | 21:10:59.456Z | false | 21:10:59.457Z | 21:10:59.557Z | reset at its first packet after the change |
| 40556 | 21:10:59.558Z | false | 21:10:59.559Z | 21:10:59.760Z | reset at its first packet after the change |
| 40564 | 21:10:59.760Z | false | 21:10:59.761Z | 21:11:00.161Z | reset at its first packet after the change |
| 40578 | 21:11:00.162Z | false | 21:11:00.163Z | 21:11:00.963Z | reset at its first packet after the change |
| 40586 | 21:11:00.964Z | false | 21:11:00.965Z | 21:11:02.565Z | reset at its first packet after the change |
| 44498 | 21:11:08.650Z | false | 21:11:08.650Z | 21:11:11.850Z | reset at its first packet after the change |
| 44512 | 21:11:11.673Z | false | (not observed) | 21:11:11.673Z | reset before the device sent on it (refused at Accept) |
| 44516 | 21:11:16.721Z | false | 21:11:16.722Z | 21:11:21.722Z | reset at its first packet after the change |
| 43904 | 21:11:22.598Z | false | 21:11:22.599Z | 21:11:27.600Z | reset at its first packet after the change |
| 43920 | 21:11:25.608Z | false | (not observed) | 21:11:25.608Z | reset before the device sent on it (refused at Accept) |
| 43930 | 21:11:25.609Z | false | (not observed) | 21:11:25.609Z | reset before the device sent on it (refused at Accept) |
| 43946 | 21:11:25.610Z | false | (not observed) | 21:11:25.610Z | reset before the device sent on it (refused at Accept) |
| 43954 | 21:11:25.611Z | false | (not observed) | 21:11:25.611Z | reset before the device sent on it (refused at Accept) |
| 43966 | 21:11:25.611Z | false | (not observed) | 21:11:25.611Z | reset before the device sent on it (refused at Accept) |
| 43972 | 21:11:25.612Z | false | (not observed) | 21:11:25.612Z | reset before the device sent on it (refused at Accept) |
| 43982 | 21:11:25.612Z | false | (not observed) | 21:11:25.613Z | reset before the device sent on it (refused at Accept) |
| 43998 | 21:11:25.613Z | false | (not observed) | 21:11:25.613Z | reset before the device sent on it (refused at Accept) |

The change began at 21:10:55.678Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap` — 322 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

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

Times are the host's, UTC: the change began 21:11:39.237Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:11:41.763Z; the command in flight was sent at 21:11:41.763Z.

| step | outcome |
|---|---|
| token session (`alice04`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 6.58s |
| break-glass login plus three `show version` | logged in and ran them in 960ms |

Records from the device since the change, before the next logins: `event=account` ×5; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=srx1 type=acct` ×1

Records from the device during the next logins: `event=account` ×9; `event=redeem reason=device_mismatch` ×2; `event=redeem reason=token_not_found` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 52720 | 21:11:31.947Z | true | (not observed) | (not observed) | not reset by port49d |
| 52730 | 21:11:32.474Z | true | (not observed) | (not observed) | not reset by port49d |
| 57596 | 21:11:38.527Z | true | (not observed) | (not observed) | not reset by port49d |
| 57608 | 21:11:40.625Z | false | 21:11:40.626Z | 21:11:45.632Z | reset at its first packet after the change |
| 57618 | 21:11:45.633Z | false | 21:11:45.633Z | (not observed) | not reset by port49d |
| 54072 | 21:11:52.211Z | false | 21:11:52.212Z | (not observed) | not reset by port49d |
| 54076 | 21:11:52.738Z | false | 21:11:52.738Z | (not observed) | not reset by port49d |
| 44866 | 21:11:58.792Z | false | 21:11:58.792Z | (not observed) | not reset by port49d |

The change began at 21:11:39.237Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap` — 256 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: replatformed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 6 (sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4: +0 device(s), -0, 1 changed; 0 quarantined
  platform_changed srx1: juniper_junos → arista_eos
```

Times are the host's, UTC: the change began 21:12:18.895Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:12:21.426Z; the command in flight was sent at 21:12:21.426Z.

| step | outcome |
|---|---|
| token session (`alice06`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice07`) | logged in in 30ms |
| break-glass login plus three `show version` | logged in and ran them in 970ms |

Records from the device since the change, before the next logins: `event=account` ×4; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=srx1 type=acct` ×1

Records from the device during the next logins: `event=account` ×9; `event=authorize_session reason=service_unsupported` ×1; `event=redeem reason=token_not_found` ×1; `event=redeem reason=token_redeemed` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 57618 | 21:12:11.329Z | false | 21:12:20.671Z | 21:12:20.671Z | **open (idle) before the change, reset at its first packet** |
| 49944 | 21:12:11.609Z | true | (not observed) | (not observed) | not reset by port49d |
| 49948 | 21:12:12.132Z | true | (not observed) | (not observed) | not reset by port49d |
| 56050 | 21:12:18.185Z | true | (not observed) | (not observed) | not reset by port49d |
| 56064 | 21:12:20.672Z | false | 21:12:20.672Z | 21:12:25.683Z | reset at its first packet after the change |
| 56080 | 21:12:25.684Z | false | 21:12:25.684Z | (not observed) | not reset by port49d |
| 40864 | 21:12:31.870Z | false | 21:12:31.871Z | (not observed) | not reset by port49d |
| 40880 | 21:12:31.893Z | false | 21:12:31.893Z | (not observed) | not reset by port49d |

The change began at 21:12:18.895Z (host UTC); 0 connection(s) read as reset mid-connection, 1 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap` — 236 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 8 (sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed srx1: admitted → refused
```

**Observation: the device held no connection open across this change.** port49d wrote no device_unknown record, and the capture holds no connection open before the change that port49d reset after it; what the device sent after the change went on connections it opened after it (records: `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×5).

Times are the host's, UTC: the change began 21:12:52.014Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:12:54.545Z; the command in flight was sent at 21:12:54.545Z.

| step | outcome |
|---|---|
| token session (`alice08`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice09`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s |
| break-glass login plus three `show version` | logged in and ran them in 460ms |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×5

Records from the device during the next logins: `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×9; `event=unvalidated diagnosis=admission_refused device=srx1 type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 56080 | 21:12:44.442Z | false | 21:12:55.726Z | 21:12:55.726Z | **open (idle) before the change, reset at its first packet** |
| 41652 | 21:12:44.723Z | true | (not observed) | (not observed) | not reset by port49d |
| 41654 | 21:12:45.248Z | true | (not observed) | (not observed) | not reset by port49d |
| 56862 | 21:12:51.304Z | true | (not observed) | (not observed) | not reset by port49d |
| 56866 | 21:12:55.726Z | false | 21:12:55.727Z | 21:12:55.727Z | reset at its first packet after the change |
| 56868 | 21:12:55.728Z | false | 21:12:55.728Z | 21:12:55.728Z | reset at its first packet after the change |
| 56878 | 21:12:55.729Z | false | 21:12:55.729Z | 21:12:55.729Z | reset at its first packet after the change |
| 56894 | 21:12:55.729Z | false | 21:12:55.730Z | 21:12:55.730Z | reset at its first packet after the change |
| 56908 | 21:12:55.730Z | false | 21:12:55.730Z | 21:12:55.730Z | reset at its first packet after the change |
| 33836 | 21:13:04.993Z | false | 21:13:04.993Z | 21:13:04.993Z | reset at its first packet after the change |
| 33842 | 21:13:05.012Z | false | 21:13:05.012Z | 21:13:05.012Z | reset at its first packet after the change |
| 50178 | 21:13:10.064Z | false | 21:13:10.064Z | 21:13:10.064Z | reset at its first packet after the change |
| 50182 | 21:13:10.759Z | false | 21:13:10.759Z | 21:13:10.760Z | reset at its first packet after the change |
| 50188 | 21:13:10.760Z | false | 21:13:10.760Z | 21:13:10.760Z | reset at its first packet after the change |
| 50190 | 21:13:10.761Z | false | 21:13:10.761Z | 21:13:10.761Z | reset at its first packet after the change |
| 50196 | 21:13:10.761Z | false | 21:13:10.761Z | 21:13:10.762Z | reset at its first packet after the change |
| 50208 | 21:13:10.762Z | false | 21:13:10.762Z | 21:13:10.762Z | reset at its first packet after the change |
| 50214 | 21:13:10.762Z | false | 21:13:10.763Z | 21:13:10.763Z | reset at its first packet after the change |
| 50216 | 21:13:10.763Z | false | 21:13:10.763Z | 21:13:10.763Z | reset at its first packet after the change |
| 50230 | 21:13:10.764Z | false | 21:13:10.764Z | 21:13:10.764Z | reset at its first packet after the change |
| 50238 | 21:13:10.764Z | false | 21:13:10.764Z | 21:13:10.764Z | reset at its first packet after the change |

The change began at 21:12:52.014Z (host UTC); 0 connection(s) read as reset mid-connection, 1 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap` — 302 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: srx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the change began 21:13:29.575Z; port49d said `port49d: policy reloaded` by 21:13:31.078Z; the command in flight was sent at 21:13:31.078Z.

| step | outcome |
|---|---|
| token session (`alice10`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice11`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.11s |
| break-glass login plus three `show version` | logged in and ran them in 450ms |

Records from the device since the change, before the next logins: `event=account` ×3; `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1; `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 47762 | 21:13:22.287Z | true | (not observed) | (not observed) | not reset by port49d |
| 47764 | 21:13:22.812Z | true | (not observed) | (not observed) | not reset by port49d |
| 44688 | 21:13:28.869Z | true | (not observed) | (not observed) | not reset by port49d |
| 44690 | 21:13:30.774Z | false | 21:13:30.775Z | 21:13:35.784Z | reset at its first packet after the change |
| 44704 | 21:13:35.785Z | false | 21:13:35.785Z | 21:13:35.785Z | reset at its first packet after the change |
| 44714 | 21:13:35.786Z | false | (not observed) | 21:13:35.786Z | reset before the device sent on it (refused at Accept) |
| 59592 | 21:13:41.537Z | false | 21:13:41.538Z | 21:13:41.540Z | reset at its first packet after the change |
| 59608 | 21:13:41.569Z | false | 21:13:41.570Z | (not observed) | not reset by port49d |
| 59614 | 21:13:46.634Z | false | 21:13:46.634Z | 21:13:46.634Z | reset at its first packet after the change |
| 51464 | 21:13:50.807Z | false | 21:13:50.808Z | 21:13:50.808Z | reset at its first packet after the change |
| 51476 | 21:13:50.808Z | false | (not observed) | 21:13:50.809Z | reset before the device sent on it (refused at Accept) |
| 51480 | 21:13:50.809Z | false | (not observed) | 21:13:50.809Z | reset before the device sent on it (refused at Accept) |
| 51494 | 21:13:50.810Z | false | (not observed) | 21:13:50.810Z | reset before the device sent on it (refused at Accept) |
| 51500 | 21:13:50.811Z | false | (not observed) | 21:13:50.811Z | reset before the device sent on it (refused at Accept) |
| 51516 | 21:13:50.812Z | false | (not observed) | 21:13:50.812Z | reset before the device sent on it (refused at Accept) |
| 51518 | 21:13:50.812Z | false | (not observed) | 21:13:50.812Z | reset before the device sent on it (refused at Accept) |
| 51530 | 21:13:50.813Z | false | (not observed) | 21:13:50.813Z | reset before the device sent on it (refused at Accept) |
| 51534 | 21:13:50.813Z | false | (not observed) | 21:13:50.813Z | reset before the device sent on it (refused at Accept) |

The change began at 21:13:29.575Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 246 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


