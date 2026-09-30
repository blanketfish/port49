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
- **Capture:** `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 250 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What a device does when port49d resets an open connection at its first packet after a reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29).

## Observation

port49d, port49 and port49-inventory built from `2f9ff4b` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 450ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.07s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`.

Device clock, `show system uptime` over break-glass with port49d stopped: `Current time: 2026-09-30 21:36:10 UTC`; host clock 21:36:12.447Z before, 21:36:12.698Z after. The host clock is the reference: port49d reads it, and every time here is the host's.

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

Times are the host's, UTC: the change began 21:36:21.562Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:36:24.094Z; the command in flight was sent at 21:36:24.094Z.

| step | outcome |
|---|---|
| token session (`alice02`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 6.28s |
| break-glass login plus three `show version` | logged in and ran them in 2.07s |

Records from the device since the change, before the next logins: `event=account` ×3; `event=unvalidated diagnosis=unadmitted_source type=acct` ×2; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×1; `event=unvalidated diagnosis=unadmitted_source type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 59254 | 21:36:14.273Z | true | (not observed) | (not observed) | not reset by port49d |
| 59266 | 21:36:14.798Z | true | (not observed) | (not observed) | not reset by port49d |
| 59234 | 21:36:16.767Z | true | (not observed) | 21:36:16.767Z | reset before the change |
| 59278 | 21:36:16.767Z | true | 21:36:21.771Z | 21:36:26.783Z | **reset mid-connection**: open across the change |
| 54474 | 21:36:20.853Z | true | (not observed) | (not observed) | not reset by port49d |
| 54482 | 21:36:26.784Z | false | 21:36:26.784Z | 21:36:26.885Z | reset at its first packet after the change |
| 54484 | 21:36:26.886Z | false | 21:36:26.886Z | 21:36:27.088Z | reset at its first packet after the change |
| 49132 | 21:36:34.538Z | false | 21:36:34.539Z | 21:36:34.940Z | reset at its first packet after the change |
| 49138 | 21:36:34.962Z | false | 21:36:34.962Z | 21:36:35.764Z | reset at its first packet after the change |
| 37322 | 21:36:40.822Z | false | 21:36:40.822Z | 21:36:42.422Z | reset at its first packet after the change |
| 37326 | 21:36:47.113Z | false | 21:36:47.114Z | 21:36:50.315Z | reset at its first packet after the change |
| 32830 | 21:36:50.123Z | false | (not observed) | 21:36:50.124Z | reset before the device sent on it (refused at Accept) |
| 32840 | 21:36:50.125Z | false | (not observed) | 21:36:50.125Z | reset before the device sent on it (refused at Accept) |
| 32856 | 21:36:50.125Z | false | (not observed) | 21:36:50.125Z | reset before the device sent on it (refused at Accept) |
| 32864 | 21:36:50.126Z | false | (not observed) | 21:36:50.126Z | reset before the device sent on it (refused at Accept) |
| 32876 | 21:36:50.126Z | false | (not observed) | 21:36:50.127Z | reset before the device sent on it (refused at Accept) |
| 32880 | 21:36:50.127Z | false | (not observed) | 21:36:50.127Z | reset before the device sent on it (refused at Accept) |
| 32896 | 21:36:50.128Z | false | (not observed) | 21:36:50.128Z | reset before the device sent on it (refused at Accept) |
| 32900 | 21:36:50.128Z | false | (not observed) | 21:36:50.128Z | reset before the device sent on it (refused at Accept) |

The change began at 21:36:21.562Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap` — 278 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-removed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

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

Times are the host's, UTC: the change began 21:37:01.944Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:37:04.474Z; the command in flight was sent at 21:37:04.474Z.

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
| 32912 | 21:36:54.655Z | true | (not observed) | (not observed) | not reset by port49d |
| 32926 | 21:36:55.179Z | true | (not observed) | (not observed) | not reset by port49d |
| 55952 | 21:37:01.238Z | true | (not observed) | (not observed) | not reset by port49d |
| 55958 | 21:37:05.135Z | false | 21:37:05.135Z | (not observed) | not reset by port49d |
| 56150 | 21:37:14.922Z | false | 21:37:14.923Z | (not observed) | not reset by port49d |
| 56158 | 21:37:15.449Z | false | 21:37:15.450Z | (not observed) | not reset by port49d |
| 47578 | 21:37:21.510Z | false | 21:37:21.511Z | (not observed) | not reset by port49d |

The change began at 21:37:01.944Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap` — 248 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-renamed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: replatformed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 6 (sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:c3fce70591176f45bc1bbb5469e12e9ab5a4a34313c3464a0716d696f5964eb4: +0 device(s), -0, 1 changed; 0 quarantined
  platform_changed srx1: juniper_junos → arista_eos
```

**Observation: the record and the capture disagree.** The capture holds 1 connection(s) open (idle) before the change and reset at its first packet after it, but port49d wrote no device_unknown record for any (records: `event=account` ×5).

Times are the host's, UTC: the change began 21:37:41.523Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:37:44.054Z; the command in flight was sent at 21:37:44.054Z.

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
| 55958 | 21:37:33.954Z | false | 21:37:45.158Z | 21:37:45.158Z | **open (idle) before the change, reset at its first packet** |
| 56218 | 21:37:34.237Z | true | (not observed) | (not observed) | not reset by port49d |
| 56222 | 21:37:34.762Z | true | (not observed) | (not observed) | not reset by port49d |
| 40442 | 21:37:40.815Z | true | (not observed) | (not observed) | not reset by port49d |
| 40446 | 21:37:45.158Z | false | 21:37:45.158Z | (not observed) | not reset by port49d |
| 33468 | 21:37:54.501Z | false | 21:37:54.502Z | (not observed) | not reset by port49d |
| 33480 | 21:37:54.525Z | false | 21:37:54.526Z | (not observed) | not reset by port49d |

The change began at 21:37:41.523Z (host UTC); 0 connection(s) read as reset mid-connection, 1 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap` — 228 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-replatformed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: `port49 inventory sync`:

```
published bundle 8 (sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:3c9eaf0be9cb9c0a8bb903df6c4fe37a89210b33e33f3d48531703911b6e1345: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed srx1: admitted → refused
```

Times are the host's, UTC: the change began 21:38:14.551Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:38:17.080Z; the command in flight was sent at 21:38:17.080Z.

| step | outcome |
|---|---|
| token session (`alice08`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice09`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s |
| break-glass login plus three `show version` | logged in and ran them in 460ms |

Records from the device since the change, before the next logins: `event=account` ×2; `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=admission_refused device=srx1 type=acct` ×9; `event=unvalidated diagnosis=admission_refused device=srx1 type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 40446 | 21:38:06.976Z | false | 21:38:15.195Z | 21:38:15.195Z | **open (idle) before the change, reset at its first packet** |
| 50618 | 21:38:07.257Z | true | (not observed) | (not observed) | not reset by port49d |
| 39806 | 21:38:07.783Z | true | (not observed) | (not observed) | not reset by port49d |
| 39810 | 21:38:13.841Z | true | (not observed) | (not observed) | not reset by port49d |
| 39816 | 21:38:15.196Z | false | 21:38:15.196Z | 21:38:20.198Z | reset at its first packet after the change |
| 37550 | 21:38:20.199Z | false | 21:38:20.200Z | 21:38:20.200Z | reset at its first packet after the change |
| 37558 | 21:38:20.200Z | false | 21:38:20.200Z | 21:38:20.201Z | reset at its first packet after the change |
| 37566 | 21:38:27.526Z | false | 21:38:27.527Z | 21:38:27.527Z | reset at its first packet after the change |
| 37580 | 21:38:27.545Z | false | 21:38:27.545Z | 21:38:27.545Z | reset at its first packet after the change |
| 40086 | 21:38:32.599Z | false | 21:38:32.599Z | 21:38:32.599Z | reset at its first packet after the change |
| 40100 | 21:38:35.213Z | false | 21:38:35.214Z | 21:38:35.214Z | reset at its first packet after the change |
| 40108 | 21:38:35.214Z | false | 21:38:35.215Z | 21:38:35.215Z | reset at its first packet after the change |
| 40112 | 21:38:35.215Z | false | 21:38:35.215Z | 21:38:35.215Z | reset at its first packet after the change |
| 40120 | 21:38:35.216Z | false | 21:38:35.216Z | 21:38:35.216Z | reset at its first packet after the change |
| 40126 | 21:38:35.216Z | false | 21:38:35.217Z | 21:38:35.217Z | reset at its first packet after the change |
| 40128 | 21:38:35.217Z | false | 21:38:35.217Z | 21:38:35.217Z | reset at its first packet after the change |
| 40138 | 21:38:35.217Z | false | 21:38:35.218Z | 21:38:35.218Z | reset at its first packet after the change |
| 40152 | 21:38:35.218Z | false | 21:38:35.218Z | 21:38:35.218Z | reset at its first packet after the change |
| 40166 | 21:38:35.219Z | false | 21:38:35.219Z | 21:38:35.219Z | reset at its first packet after the change |

The change began at 21:38:14.551Z (host UTC); 0 connection(s) read as reset mid-connection, 1 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap` — 290 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-refused-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: srx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

**Observation: the device held no connection open across this change.** port49d wrote no device_unknown record, and the capture holds no connection open before the change that port49d reset after it; what the device sent after the change went on connections it opened after it (records: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1).

Times are the host's, UTC: the change began 21:38:52.098Z; port49d said `port49d: policy reloaded` by 21:38:53.602Z; the command in flight was sent at 21:38:53.602Z.

| step | outcome |
|---|---|
| token session (`alice10`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice11`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s |
| break-glass login plus three `show version` | logged in and ran them in 460ms |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1; `event=unvalidated diagnosis=no_known_key_matches type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 35924 | 21:38:44.810Z | true | (not observed) | (not observed) | not reset by port49d |
| 35926 | 21:38:45.335Z | true | (not observed) | (not observed) | not reset by port49d |
| 55912 | 21:38:51.389Z | true | (not observed) | (not observed) | not reset by port49d |
| 55914 | 21:38:55.228Z | false | 21:38:55.229Z | 21:38:55.229Z | reset at its first packet after the change |
| 55926 | 21:38:55.230Z | false | (not observed) | 21:38:55.230Z | reset before the device sent on it (refused at Accept) |
| 55942 | 21:38:55.231Z | false | (not observed) | 21:38:55.231Z | reset before the device sent on it (refused at Accept) |
| 55946 | 21:38:55.231Z | false | (not observed) | 21:38:55.231Z | reset before the device sent on it (refused at Accept) |
| 55956 | 21:38:55.232Z | false | (not observed) | 21:38:55.232Z | reset before the device sent on it (refused at Accept) |
| 55966 | 21:38:55.233Z | false | (not observed) | 21:38:55.233Z | reset before the device sent on it (refused at Accept) |
| 36874 | 21:39:04.050Z | false | 21:39:04.050Z | 21:39:04.050Z | reset at its first packet after the change |
| 36890 | 21:39:04.067Z | false | (not observed) | 21:39:04.067Z | reset before the device sent on it (refused at Accept) |
| 33422 | 21:39:09.116Z | false | 21:39:09.117Z | 21:39:09.117Z | reset at its first packet after the change |
| 33430 | 21:39:10.242Z | false | 21:39:10.243Z | 21:39:10.243Z | reset at its first packet after the change |
| 33438 | 21:39:10.244Z | false | (not observed) | 21:39:10.244Z | reset before the device sent on it (refused at Accept) |
| 33446 | 21:39:10.244Z | false | (not observed) | 21:39:10.245Z | reset before the device sent on it (refused at Accept) |
| 33454 | 21:39:10.245Z | false | (not observed) | 21:39:10.245Z | reset before the device sent on it (refused at Accept) |
| 33462 | 21:39:10.246Z | false | (not observed) | 21:39:10.246Z | reset before the device sent on it (refused at Accept) |
| 33474 | 21:39:10.246Z | false | (not observed) | 21:39:10.246Z | reset before the device sent on it (refused at Accept) |
| 33476 | 21:39:10.247Z | false | (not observed) | 21:39:10.247Z | reset before the device sent on it (refused at Accept) |
| 33488 | 21:39:10.247Z | false | (not observed) | 21:39:10.247Z | reset before the device sent on it (refused at Accept) |
| 33494 | 21:39:10.248Z | false | (not observed) | 21:39:10.248Z | reset before the device sent on it (refused at Accept) |

The change began at 21:38:52.098Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap` — 250 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


