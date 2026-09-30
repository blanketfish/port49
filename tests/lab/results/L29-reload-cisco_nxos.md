# L29-reload — cisco_nxos

- **Date measured:** 2026-09-30
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L29-reload-rekeyed-cisco_nxos.pcap` — 264 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What a device does when port49d resets an open connection at its first packet after a reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29).

## Observation

port49d, port49 and port49-inventory built from `2f9ff4b` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 140ms |
| break-glass login plus three `show version` | ran | 2.62s |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.82s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `tacacs-server host 172.100.100.1 key 0 <key> single-connection`.

Device clock, `show clock` over break-glass with port49d stopped: `Warning: No NTP peer/server configured. Time may be out of sync.; 21:28:01.201 UTC Wed Sep 30 2026; Time source is NTP`; host clock 21:28:02.326Z before, 21:28:02.577Z after. The host clock is the reference: port49d reads it, and every time here is the host's.

**Reading the records and the captures.** port49d writes one record for a packet on a connection it admitted before the change and no longer admits: `event=unvalidated reason=device_unknown`, naming the device the connection was admitted as, then resets that connection (`admission_withdrawn` for a rename, re-key or re-platform; `unadmitted_source` for a removal; `admission_refused` for a refusal). A packet opening a new connection is recorded without `reason=device_unknown`: `unadmitted_source` with no device, `admission_refused` naming it, or `no_known_key_matches` for a key it does not hold; a source inside the backoff a key miss earned is reset at Accept with no record at all. So the records say whether port49d reset a connection that was open across the change; they cannot say which of the device's connections carried the command in flight (an unvalidated record carries the source address, not its port), nor what the device did with the reset. The first comes from the capture: the per-connection table below reads each connection's 4-tuple, whether the device sent on it before the change, and when port49d reset it. The second comes from the device's own output in the open session. A phase with no such record, or whose capture holds no connection reset mid-connection, measured L28's first-packet case and fails. A connection open before the change with nothing sent on it, and reset at its first packet after it, is a reset of an open connection too, and counts when port49d's device_unknown record names it so.

Each phase has a capture of its own, named in its section; the header's is the last phase's.

### Phase: removed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:a0b9ec4f6a8bba4f07fb6893cad2c7dc469ae24848114e13498c74715175e238): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:a0b9ec4f6a8bba4f07fb6893cad2c7dc469ae24848114e13498c74715175e238: +0 device(s), -1, 0 changed; 0 quarantined
  device removed nx1 (cisco_nxos)
  scope all_devices: nx1 left
```

Times are the host's, UTC: the change began 21:28:07.410Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:28:08.936Z; the command in flight was sent at 21:28:08.936Z.

| step | outcome |
|---|---|
| token session (`alice02`), `show version` before the change | ran in 700ms |
| first `show version` after the change, same session | printed its output in 800ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 900ms |
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 9.85s |
| break-glass login plus three `show version` | logged in and ran them in 40.89s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×1; `event=unvalidated diagnosis=unadmitted_source type=author` ×1; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=nx1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=unadmitted_source type=acct` ×6; `event=unvalidated diagnosis=unadmitted_source type=authen` ×1; `event=unvalidated diagnosis=unadmitted_source type=author` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 42708 | 21:28:04.240Z | true | 21:28:08.949Z | 21:28:08.950Z | **reset mid-connection**: open across the change |
| 54506 | 21:28:09.754Z | false | 21:28:09.755Z | 21:28:09.856Z | reset at its first packet after the change |
| 54520 | 21:28:10.657Z | false | 21:28:10.658Z | 21:28:10.859Z | reset at its first packet after the change |
| 48924 | 21:28:20.782Z | false | 21:28:20.783Z | 21:28:21.184Z | reset at its first packet after the change |
| 48938 | 21:28:23.036Z | false | 21:28:23.036Z | 21:28:23.837Z | reset at its first packet after the change |
| 40330 | 21:28:30.518Z | false | 21:28:30.519Z | 21:28:32.120Z | reset at its first packet after the change |
| 40820 | 21:28:39.062Z | false | 21:28:39.073Z | 21:28:42.273Z | reset at its first packet after the change |
| 40834 | 21:28:44.962Z | false | 21:28:44.963Z | 21:28:49.963Z | reset at its first packet after the change |
| 42074 | 21:28:49.978Z | false | 21:28:49.979Z | 21:28:54.979Z | reset at its first packet after the change |
| 42088 | 21:28:55.665Z | false | 21:28:55.665Z | 21:29:00.665Z | reset at its first packet after the change |
| 39842 | 21:29:00.680Z | false | 21:29:00.681Z | 21:29:05.681Z | reset at its first packet after the change |
| 39854 | 21:29:06.372Z | false | 21:29:06.373Z | 21:29:11.373Z | reset at its first packet after the change |
| 54552 | 21:29:11.388Z | false | 21:29:11.389Z | 21:29:16.390Z | reset at its first packet after the change |

The change began at 21:28:07.410Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-removed-cisco_nxos.pcap` — 260 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-removed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: renamed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: `port49 inventory sync`:

```
published bundle 4 (sha256:147806cc8c70e2c363eb2246cb90d85ac7b27f05208f06e645ba8acd1341677f): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:147806cc8c70e2c363eb2246cb90d85ac7b27f05208f06e645ba8acd1341677f: +1 device(s), -1, 0 changed; 0 quarantined
  device removed nx1 (cisco_nxos)
! device added nx1-b (cisco_nxos): admitted
  scope all_devices: nx1 left
  scope all_devices: nx1-b joined
```

Times are the host's, UTC: the change began 21:29:26.475Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:29:28.002Z; the command in flight was sent at 21:29:28.002Z.

| step | outcome |
|---|---|
| token session (`alice04`), `show version` before the change | ran in 700ms |
| first `show version` after the change, same session | printed its output in 700ms (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 100ms: `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 1.89s |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 1.65s |

Records from the device since the change, before the next logins: `event=account` ×1; `event=authorize_command reason=context_missing` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=nx1 type=author` ×1

Records from the device during the next logins: `event=account` ×4; `event=redeem reason=device_mismatch` ×2; `event=redeem reason=token_not_found` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 37840 | 21:29:23.283Z | true | 21:29:28.017Z | 21:29:28.017Z | **reset mid-connection**: open across the change |
| 45408 | 21:29:28.719Z | false | 21:29:28.720Z | (not observed) | not reset by port49d |

The change began at 21:29:26.475Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-renamed-cisco_nxos.pcap` — 168 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-renamed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: replatformed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: `port49 inventory sync`:

```
published bundle 6 (sha256:4a75d286baabc0d394caeffe07e08848b051f97ca34d63fb4ea145a0d8ddb4db): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:4a75d286baabc0d394caeffe07e08848b051f97ca34d63fb4ea145a0d8ddb4db: +0 device(s), -0, 1 changed; 0 quarantined
  platform_changed nx1: cisco_nxos → arista_eos
```

Times are the host's, UTC: the change began 21:29:57.499Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:29:59.029Z; the command in flight was sent at 21:29:59.029Z.

| step | outcome |
|---|---|
| token session (`alice06`), `show version` before the change | ran in 800ms |
| first `show version` after the change, same session | printed its output in 700ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 700ms |
| next token login (`alice07`) | logged in in 220ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 1.65s |

Records from the device since the change, before the next logins: `event=account` ×1; `event=authorize_command reason=permit_dominates` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=nx1 type=author` ×1

Records from the device during the next logins: `event=account` ×2; `event=authorize_session reason=context_matched` ×1; `event=redeem reason=token_not_found` ×2; `event=redeem reason=token_redeemed` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 45408 | 21:29:53.882Z | false | (not observed) | (not observed) | not reset by port49d |
| 49228 | 21:29:54.256Z | true | 21:29:59.044Z | 21:29:59.045Z | **reset mid-connection**: open across the change |
| 44914 | 21:29:59.746Z | false | 21:29:59.748Z | (not observed) | not reset by port49d |

The change began at 21:29:57.499Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-replatformed-cisco_nxos.pcap` — 154 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-replatformed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: `port49 inventory sync`:

```
published bundle 8 (sha256:9ba22fe7d0e49432bf71a007605d2f6b421f40f7832615309d3a77905555e0df): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:9ba22fe7d0e49432bf71a007605d2f6b421f40f7832615309d3a77905555e0df: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed nx1: admitted → refused
```

Times are the host's, UTC: the change began 21:30:27.449Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 21:30:28.979Z; the command in flight was sent at 21:30:28.979Z.

| step | outcome |
|---|---|
| token session (`alice08`), `show version` before the change | ran in 800ms |
| first `show version` after the change, same session | printed its output in 700ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 700ms |
| next token login (`alice09`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 3.46s |
| break-glass login plus three `show version` | logged in and ran them in 17.63s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=admission_refused device=nx1 type=acct` ×1; `event=unvalidated diagnosis=admission_refused device=nx1 type=author` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=nx1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=admission_refused device=nx1 type=acct` ×8; `event=unvalidated diagnosis=admission_refused device=nx1 type=authen` ×3; `event=unvalidated diagnosis=admission_refused device=nx1 type=author` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 44914 | 21:30:23.825Z | false | (not observed) | (not observed) | not reset by port49d |
| 39804 | 21:30:24.200Z | true | 21:30:28.993Z | 21:30:28.993Z | **reset mid-connection**: open across the change |
| 33840 | 21:30:29.695Z | false | 21:30:29.696Z | 21:30:29.696Z | reset at its first packet after the change |
| 33846 | 21:30:30.398Z | false | 21:30:30.398Z | 21:30:30.399Z | reset at its first packet after the change |
| 42536 | 21:30:40.522Z | false | 21:30:40.523Z | 21:30:40.523Z | reset at its first packet after the change |
| 42544 | 21:30:42.320Z | false | 21:30:42.321Z | 21:30:42.321Z | reset at its first packet after the change |
| 42558 | 21:30:42.464Z | false | 21:30:42.465Z | 21:30:42.466Z | reset at its first packet after the change |
| 42572 | 21:30:43.869Z | false | 21:30:43.870Z | 21:30:43.871Z | reset at its first packet after the change |
| 42578 | 21:30:43.982Z | false | 21:30:43.983Z | 21:30:43.983Z | reset at its first packet after the change |
| 42594 | 21:30:44.121Z | false | 21:30:44.131Z | 21:30:44.131Z | reset at its first packet after the change |
| 46088 | 21:30:49.823Z | false | 21:30:49.823Z | 21:30:49.824Z | reset at its first packet after the change |
| 46100 | 21:30:49.835Z | false | 21:30:49.836Z | 21:30:49.836Z | reset at its first packet after the change |
| 46108 | 21:30:49.947Z | false | 21:30:49.959Z | 21:30:49.959Z | reset at its first packet after the change |
| 46116 | 21:30:55.650Z | false | 21:30:55.651Z | 21:30:55.651Z | reset at its first packet after the change |
| 46132 | 21:30:55.664Z | false | 21:30:55.664Z | 21:30:55.664Z | reset at its first packet after the change |
| 46148 | 21:30:55.771Z | false | 21:30:55.782Z | 21:30:55.782Z | reset at its first packet after the change |
| 42480 | 21:31:01.473Z | false | 21:31:01.474Z | 21:31:01.474Z | reset at its first packet after the change |
| 42490 | 21:31:01.486Z | false | 21:31:01.487Z | 21:31:01.487Z | reset at its first packet after the change |

The change began at 21:30:27.449Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-refused-cisco_nxos.pcap` — 286 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-refused-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: port49d's broker.policy_file given `- {match: {name: nx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the change began 21:31:16.612Z; port49d said `port49d: policy reloaded` by 21:31:18.116Z; the command in flight was sent at 21:31:18.116Z.

| step | outcome |
|---|---|
| token session (`alice10`), `show version` before the change | ran in 800ms |
| first `show version` after the change, same session | printed its output in 700ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 700ms |
| next token login (`alice11`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.54s |
| break-glass login plus three `show version` | logged in and ran them in 2.6s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×1; `event=unvalidated diagnosis=no_known_key_matches type=author` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=nx1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=no_known_key_matches type=acct` ×2; `event=unvalidated diagnosis=no_known_key_matches type=authen` ×1; `event=unvalidated diagnosis=no_known_key_matches type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 47642 | 21:31:13.369Z | true | 21:31:18.129Z | 21:31:18.129Z | **reset mid-connection**: open across the change |
| 46818 | 21:31:18.832Z | false | 21:31:18.833Z | 21:31:18.833Z | reset at its first packet after the change |
| 46830 | 21:31:19.534Z | false | 21:31:19.535Z | 21:31:19.535Z | reset at its first packet after the change |
| 58514 | 21:31:29.662Z | false | 21:31:29.663Z | 21:31:29.663Z | reset at its first packet after the change |
| 58522 | 21:31:31.715Z | false | 21:31:31.715Z | 21:31:31.716Z | reset at its first packet after the change |
| 58526 | 21:31:31.766Z | false | (not observed) | 21:31:31.766Z | reset before the device sent on it (refused at Accept) |
| 58538 | 21:31:34.095Z | false | 21:31:34.096Z | 21:31:34.096Z | reset at its first packet after the change |
| 58552 | 21:31:34.203Z | false | (not observed) | 21:31:34.203Z | reset before the device sent on it (refused at Accept) |
| 58556 | 21:31:34.346Z | false | (not observed) | 21:31:34.346Z | reset before the device sent on it (refused at Accept) |
| 58558 | 21:31:34.358Z | false | (not observed) | 21:31:34.359Z | reset before the device sent on it (refused at Accept) |
| 58562 | 21:31:35.049Z | false | (not observed) | 21:31:35.049Z | reset before the device sent on it (refused at Accept) |
| 58576 | 21:31:35.061Z | false | (not observed) | 21:31:35.061Z | reset before the device sent on it (refused at Accept) |
| 58586 | 21:31:35.169Z | false | (not observed) | 21:31:35.169Z | reset before the device sent on it (refused at Accept) |
| 58588 | 21:31:35.180Z | false | (not observed) | 21:31:35.180Z | reset before the device sent on it (refused at Accept) |
| 58594 | 21:31:35.861Z | false | 21:31:35.862Z | 21:31:35.862Z | reset at its first packet after the change |
| 58600 | 21:31:35.874Z | false | (not observed) | 21:31:35.874Z | reset before the device sent on it (refused at Accept) |
| 58612 | 21:31:35.981Z | false | (not observed) | 21:31:35.981Z | reset before the device sent on it (refused at Accept) |
| 58622 | 21:31:35.992Z | false | (not observed) | 21:31:35.992Z | reset before the device sent on it (refused at Accept) |
| 58630 | 21:31:36.666Z | false | (not observed) | 21:31:36.666Z | reset before the device sent on it (refused at Accept) |
| 58634 | 21:31:36.679Z | false | (not observed) | 21:31:36.679Z | reset before the device sent on it (refused at Accept) |

The change began at 21:31:16.612Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L29-reload-rekeyed-cisco_nxos.pcap` — 264 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


