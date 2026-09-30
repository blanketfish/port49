**THIS RUN FAILED ITS PREMISE CHECKS: NOT A MEASUREMENT.** It is re-run, never read as an answer (plan 6b Task 19). Failed checks:

- renamed: no connection open across the change was reset (no reason=device_unknown record with diagnosis admission_withdrawn from the device): this phase measured L28's first-packet case, not L29's
- renamed: the capture holds no connection open across the change that port49d reset after it: no reset of an open connection was captured
- replatformed: no connection open across the change was reset (no reason=device_unknown record with diagnosis admission_withdrawn from the device): this phase measured L28's first-packet case, not L29's
- replatformed: the capture holds no connection open across the change that port49d reset after it: no reset of an open connection was captured
- rekeyed: no connection open across the change was reset (no reason=device_unknown record with diagnosis admission_withdrawn from the device): this phase measured L28's first-packet case, not L29's
- rekeyed: the capture holds no connection open across the change that port49d reset after it: no reset of an open connection was captured

# L29-reload — juniper_vjunos-router

- **Date measured:** 2026-09-30
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 254 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What a device does when port49d resets an open connection at its first packet after a reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29).

## Observation

port49d, port49 and port49-inventory built from `6fcce47` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 460ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.06s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`.

Device clock, `show system uptime` over break-glass with port49d stopped: `Current time: 2026-09-30 21:45:25 UTC`; host clock 21:45:26.513Z before, 21:45:26.764Z after. The host clock is the reference: port49d reads it, and every time here is the host's.

**Reading the records and the captures.** port49d writes one record for a packet on a connection it admitted before the change and no longer admits: `event=unvalidated reason=device_unknown`, naming the device the connection was admitted as, then resets that connection (`admission_withdrawn` for a rename, re-key or re-platform; `unadmitted_source` for a removal; `admission_refused` for a refusal). A packet opening a new connection is recorded without `reason=device_unknown`: `unadmitted_source` with no device, `admission_refused` naming it, or `no_known_key_matches` for a key it does not hold; a source inside the backoff a key miss earned is reset at Accept with no record at all. So the records say whether port49d reset a connection that was open across the change; they cannot say which of the device's connections carried the command in flight (an unvalidated record carries the source address, not its port), nor what the device did with the reset. The first comes from the capture: the per-connection table below reads each connection's 4-tuple, whether the device sent on it before the change, and when port49d reset it. The second comes from the device's own output in the open session. A phase with no such record, or whose capture holds no connection reset mid-connection, measured L28's first-packet case and fails. A connection open before the change with nothing sent on it, and reset at its first packet after it, is a reset of an open connection too, and counts when port49d's device_unknown record names it so. "The change" in the capture tables is the instant port49d applied the reload (its reload line, read to within 25ms), not the sync's start: port49d resets a connection only once it has applied the change.

Each phase has a capture of its own, named in its section; the header's is the last phase's.

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:8f7111515f455add6e75977daadf12c37d2f66dda9452d1268242f354f963d2c): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:8f7111515f455add6e75977daadf12c37d2f66dda9452d1268242f354f963d2c: +0 device(s), -1, 0 changed; 0 quarantined
  device removed srx1 (juniper_junos)
  scope all_devices: srx1 left
```

Times are the host's, UTC: the sync (or policy edit) began 21:45:35.624Z; port49d applied the reload, saying `port49d: inventory reloaded (inventory service, bundle`, between 21:45:38.071Z and 21:45:38.097Z, and the change instant the capture is read against is 21:45:38.071Z; the command in flight was sent at 21:45:38.097Z.

| step | outcome |
|---|---|
| token session (`alice02`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 6.27s |
| break-glass login plus three `show version` | logged in and ran them in 2.06s |

Records from the device since the change, before the next logins: `event=account` ×3; `event=unvalidated diagnosis=unadmitted_source type=acct` ×2; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×1; `event=unvalidated diagnosis=unadmitted_source type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 42872 | 21:45:28.335Z | true | (not observed) | (not observed) | not reset by port49d |
| 42876 | 21:45:28.861Z | true | (not observed) | (not observed) | not reset by port49d |
| 60990 | 21:45:30.937Z | true | (not observed) | 21:45:30.937Z | reset before the change |
| 42892 | 21:45:30.938Z | true | 21:45:40.954Z | 21:45:40.955Z | **reset mid-connection**: open across the change |
| 42900 | 21:45:34.915Z | true | (not observed) | (not observed) | not reset by port49d |
| 60562 | 21:45:40.955Z | false | 21:45:40.956Z | 21:45:41.056Z | reset at its first packet after the change |
| 60574 | 21:45:41.057Z | false | 21:45:41.058Z | 21:45:41.258Z | reset at its first packet after the change |
| 36874 | 21:45:48.543Z | false | 21:45:48.543Z | 21:45:48.943Z | reset at its first packet after the change |
| 36884 | 21:45:48.962Z | false | 21:45:48.962Z | 21:45:49.762Z | reset at its first packet after the change |
| 36892 | 21:45:54.812Z | false | 21:45:54.812Z | 21:45:56.414Z | reset at its first packet after the change |
| 52140 | 21:46:01.267Z | false | 21:46:01.268Z | 21:46:04.468Z | reset at its first packet after the change |
| 52154 | 21:46:04.276Z | false | (not observed) | 21:46:04.276Z | reset before the device sent on it (refused at Accept) |
| 52158 | 21:46:04.277Z | false | (not observed) | 21:46:04.277Z | reset before the device sent on it (refused at Accept) |
| 52168 | 21:46:04.277Z | false | (not observed) | 21:46:04.278Z | reset before the device sent on it (refused at Accept) |
| 52170 | 21:46:04.278Z | false | (not observed) | 21:46:04.278Z | reset before the device sent on it (refused at Accept) |
| 52174 | 21:46:04.279Z | false | (not observed) | 21:46:04.279Z | reset before the device sent on it (refused at Accept) |
| 52182 | 21:46:04.280Z | false | (not observed) | 21:46:04.280Z | reset before the device sent on it (refused at Accept) |
| 52196 | 21:46:04.280Z | false | (not observed) | 21:46:04.280Z | reset before the device sent on it (refused at Accept) |
| 52202 | 21:46:04.281Z | false | (not observed) | 21:46:04.281Z | reset before the device sent on it (refused at Accept) |

The change began at 21:45:38.071Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap` — 279 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

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

**Observation: the device held no connection open across this change.** port49d wrote no device_unknown record, and the capture holds no connection open before the change that port49d reset after it; what the device sent after the change went on connections it opened after it (records: `event=account` ×6).

Times are the host's, UTC: the sync (or policy edit) began 21:46:15.936Z; port49d applied the reload, saying `port49d: inventory reloaded (inventory service, bundle`, between 21:46:18.385Z and 21:46:18.410Z, and the change instant the capture is read against is 21:46:18.385Z; the command in flight was sent at 21:46:18.410Z.

| step | outcome |
|---|---|
| token session (`alice04`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 6.59s |
| break-glass login plus three `show version` | logged in and ran them in 960ms |

Records from the device since the change, before the next logins: `event=account` ×6

Records from the device during the next logins: `event=account` ×9; `event=redeem reason=device_mismatch` ×2; `event=redeem reason=token_not_found` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 45844 | 21:46:08.645Z | true | (not observed) | (not observed) | not reset by port49d |
| 45858 | 21:46:09.169Z | true | (not observed) | (not observed) | not reset by port49d |
| 45870 | 21:46:15.226Z | true | (not observed) | (not observed) | not reset by port49d |
| 45676 | 21:46:19.298Z | false | 21:46:19.299Z | (not observed) | not reset by port49d |
| 37214 | 21:46:28.859Z | false | 21:46:28.859Z | (not observed) | not reset by port49d |
| 37218 | 21:46:29.386Z | false | 21:46:29.387Z | (not observed) | not reset by port49d |
| 37222 | 21:46:35.447Z | false | 21:46:35.448Z | (not observed) | not reset by port49d |

The change began at 21:46:18.385Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap` — 248 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: replatformed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 6 (sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4: +0 device(s), -0, 1 changed; 0 quarantined
  platform_changed srx1: juniper_junos → arista_eos
```

**Observation: the record and the capture disagree.** The capture holds 1 connection(s) open (idle) before the change and reset at its first packet after it, but port49d wrote no device_unknown record for any (records: `event=account` ×5).

Times are the host's, UTC: the sync (or policy edit) began 21:46:55.461Z; port49d applied the reload, saying `port49d: inventory reloaded (inventory service, bundle`, between 21:46:57.914Z and 21:46:57.939Z, and the change instant the capture is read against is 21:46:57.914Z; the command in flight was sent at 21:46:57.940Z.

| step | outcome |
|---|---|
| token session (`alice06`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice07`) | logged in in 30ms |
| break-glass login plus three `show version` | logged in and ran them in 980ms |

Records from the device since the change, before the next logins: `event=account` ×5

Records from the device during the next logins: `event=account` ×9; `event=authorize_session reason=service_unsupported` ×1; `event=redeem reason=token_not_found` ×1; `event=redeem reason=token_redeemed` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 45676 | 21:46:47.892Z | false | 21:46:59.347Z | 21:46:59.347Z | **open (idle) before the change, reset at its first packet** |
| 56124 | 21:46:48.171Z | true | (not observed) | (not observed) | not reset by port49d |
| 56132 | 21:46:48.694Z | true | (not observed) | (not observed) | not reset by port49d |
| 56138 | 21:46:54.752Z | true | (not observed) | (not observed) | not reset by port49d |
| 46606 | 21:46:59.348Z | false | 21:46:59.348Z | (not observed) | not reset by port49d |
| 60522 | 21:47:08.385Z | false | 21:47:08.385Z | (not observed) | not reset by port49d |
| 60534 | 21:47:08.407Z | false | 21:47:08.408Z | (not observed) | not reset by port49d |

The change began at 21:46:57.914Z (host UTC); 0 connection(s) read as reset mid-connection, 1 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap` — 226 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 8 (sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed srx1: admitted → refused
```

Times are the host's, UTC: the sync (or policy edit) began 21:47:28.447Z; port49d applied the reload, saying `port49d: inventory reloaded (inventory service, bundle`, between 21:47:30.901Z and 21:47:30.927Z, and the change instant the capture is read against is 21:47:30.901Z; the command in flight was sent at 21:47:30.927Z.

| step | outcome |
|---|---|
| token session (`alice08`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice09`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s |
| break-glass login plus three `show version` | logged in and ran them in 450ms |

Records from the device since the change, before the next logins: `event=account` ×2; `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×9; `event=unvalidated diagnosis=admission_refused device=srx1 type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 46606 | 21:47:20.882Z | true | (not observed) | 21:47:29.385Z | reset before the change |
| 55194 | 21:47:21.161Z | true | (not observed) | (not observed) | not reset by port49d |
| 55200 | 21:47:21.686Z | true | (not observed) | (not observed) | not reset by port49d |
| 55208 | 21:47:27.738Z | true | (not observed) | (not observed) | not reset by port49d |
| 58580 | 21:47:29.385Z | true | 21:47:34.395Z | 21:47:34.395Z | **reset mid-connection**: open across the change |
| 58596 | 21:47:34.396Z | false | 21:47:34.396Z | 21:47:34.396Z | reset at its first packet after the change |
| 58612 | 21:47:34.397Z | false | 21:47:34.397Z | 21:47:34.397Z | reset at its first packet after the change |
| 55922 | 21:47:41.374Z | false | 21:47:41.375Z | 21:47:41.375Z | reset at its first packet after the change |
| 55928 | 21:47:41.396Z | false | 21:47:41.397Z | 21:47:41.397Z | reset at its first packet after the change |
| 55938 | 21:47:46.446Z | false | 21:47:46.447Z | 21:47:46.447Z | reset at its first packet after the change |
| 53674 | 21:47:49.420Z | false | 21:47:49.420Z | 21:47:49.421Z | reset at its first packet after the change |
| 53680 | 21:47:49.421Z | false | 21:47:49.422Z | 21:47:49.422Z | reset at its first packet after the change |
| 53694 | 21:47:49.422Z | false | 21:47:49.422Z | 21:47:49.422Z | reset at its first packet after the change |
| 53708 | 21:47:49.423Z | false | 21:47:49.423Z | 21:47:49.423Z | reset at its first packet after the change |
| 53710 | 21:47:49.423Z | false | 21:47:49.424Z | 21:47:49.424Z | reset at its first packet after the change |
| 53726 | 21:47:49.424Z | false | 21:47:49.424Z | 21:47:49.424Z | reset at its first packet after the change |
| 53728 | 21:47:49.425Z | false | 21:47:49.425Z | 21:47:49.425Z | reset at its first packet after the change |
| 53730 | 21:47:49.425Z | false | 21:47:49.426Z | 21:47:49.426Z | reset at its first packet after the change |
| 53740 | 21:47:49.426Z | false | 21:47:49.426Z | 21:47:49.426Z | reset at its first packet after the change |

The change began at 21:47:30.901Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap` — 290 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: srx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

**Observation: the device held no connection open across this change.** port49d wrote no device_unknown record, and the capture holds no connection open before the change that port49d reset after it; what the device sent after the change went on connections it opened after it (records: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1).

Times are the host's, UTC: the sync (or policy edit) began 21:48:05.950Z; port49d applied the reload, saying `port49d: policy reloaded`, between 21:48:07.412Z and 21:48:07.438Z, and the change instant the capture is read against is 21:48:07.412Z; the command in flight was sent at 21:48:07.438Z.

| step | outcome |
|---|---|
| token session (`alice10`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice11`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s |
| break-glass login plus three `show version` | logged in and ran them in 450ms |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1; `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 52646 | 21:47:58.665Z | true | (not observed) | (not observed) | not reset by port49d |
| 52658 | 21:47:59.188Z | true | (not observed) | (not observed) | not reset by port49d |
| 52670 | 21:48:05.243Z | true | (not observed) | (not observed) | not reset by port49d |
| 41966 | 21:48:09.438Z | false | 21:48:09.438Z | 21:48:09.438Z | reset at its first packet after the change |
| 41980 | 21:48:09.439Z | false | (not observed) | 21:48:09.439Z | reset before the device sent on it (refused at Accept) |
| 41992 | 21:48:09.439Z | false | (not observed) | 21:48:09.439Z | reset before the device sent on it (refused at Accept) |
| 41994 | 21:48:09.440Z | false | (not observed) | 21:48:09.440Z | reset before the device sent on it (refused at Accept) |
| 42008 | 21:48:09.440Z | false | 21:48:09.440Z | 21:48:09.440Z | reset |
| 42010 | 21:48:09.440Z | false | (not observed) | 21:48:09.441Z | reset before the device sent on it (refused at Accept) |
| 43980 | 21:48:17.882Z | false | 21:48:17.882Z | 21:48:17.882Z | reset at its first packet after the change |
| 43994 | 21:48:17.902Z | false | (not observed) | 21:48:17.902Z | reset before the device sent on it (refused at Accept) |
| 44008 | 21:48:22.953Z | false | 21:48:22.954Z | 21:48:22.954Z | reset at its first packet after the change |
| 44024 | 21:48:24.458Z | false | 21:48:24.458Z | 21:48:24.458Z | reset at its first packet after the change |
| 44028 | 21:48:24.459Z | false | (not observed) | 21:48:24.459Z | reset before the device sent on it (refused at Accept) |
| 44036 | 21:48:24.460Z | false | (not observed) | 21:48:24.460Z | reset before the device sent on it (refused at Accept) |
| 44044 | 21:48:24.461Z | false | (not observed) | 21:48:24.461Z | reset before the device sent on it (refused at Accept) |
| 44056 | 21:48:24.461Z | false | (not observed) | 21:48:24.461Z | reset before the device sent on it (refused at Accept) |
| 44068 | 21:48:24.462Z | false | (not observed) | 21:48:24.462Z | reset before the device sent on it (refused at Accept) |
| 44080 | 21:48:24.462Z | false | (not observed) | 21:48:24.462Z | reset before the device sent on it (refused at Accept) |
| 44086 | 21:48:24.463Z | false | (not observed) | 21:48:24.463Z | reset before the device sent on it (refused at Accept) |
| 44096 | 21:48:24.463Z | false | (not observed) | 21:48:24.464Z | reset before the device sent on it (refused at Accept) |

The change began at 21:48:07.412Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 254 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


