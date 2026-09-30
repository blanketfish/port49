# L29-reload — cisco_iosxe

- **Date measured:** 2026-09-30
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L29-reload-rekeyed-cisco_iosxe.pcap` — 250 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What a device does when port49d resets an open connection at its first packet after a reload removed, renamed, re-platformed, refused or re-keyed its device, each reload but the re-key a sync through the inventory service: the command in flight, the next token login and break-glass (spec §15 L29).

## Observation

port49d, port49 and port49-inventory built from `adc5746` (`make build`).

**Control, port49d stopped** (L28's `stopped` phase):

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 20ms |
| break-glass login plus three `show version` | ran | 1.28s |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.02s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Single-connection: on: `single-connection` under `tacacs server port49-host`.

Device clock, `show clock` over break-glass with port49d stopped: `*20:40:00.118 UTC Wed Sep 30 2026`; host clock 20:40:00.026Z before, 20:40:00.276Z after. The host clock is the reference: port49d reads it, and every time here is the host's.

**Reading the records and the captures.** port49d writes one record for a packet on a connection it admitted before the change and no longer admits: `event=unvalidated reason=device_unknown`, naming the device the connection was admitted as, then resets that connection (`admission_withdrawn` for a rename, re-key or re-platform; `unadmitted_source` for a removal; `admission_refused` for a refusal). A packet opening a new connection is recorded without `reason=device_unknown`: `unadmitted_source` with no device, `admission_refused` naming it, or `no_known_key_matches` for a key it does not hold; a source inside the backoff a key miss earned is reset at Accept with no record at all. So the records say whether port49d reset a connection that was open across the change; they cannot say which of the device's connections carried the command in flight (an unvalidated record carries the source address, not its port), nor what the device did with the reset. The first comes from the capture: the per-connection table below reads each connection's 4-tuple, whether the device sent on it before the change, and when port49d reset it. The second comes from the device's own output in the open session. A phase with no such record, or whose capture holds no connection reset mid-connection, measured L28's first-packet case and fails.

Each phase has a capture of its own, named in its section; the header's is the last phase's.

### Phase: removed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (30s).

The change: `port49 inventory sync`:

```
published bundle 2 (sha256:d9d970b1e2181507aa59563b60dbd830dafc1739c629f44c050167c96cce27a6): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:d9d970b1e2181507aa59563b60dbd830dafc1739c629f44c050167c96cce27a6: +0 device(s), -1, 0 changed; 0 quarantined
  device removed xe1 (cisco_iosxe)
  scope all_devices: xe1 left
```

Times are the host's, UTC: the change began 20:40:32.186Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:40:36.714Z; the command in flight was sent at 20:40:36.714Z.

| step | outcome |
|---|---|
| token session (`alice02`), `show version` before the change | ran in 300ms |
| first `show version` after the change, same session | refused in 5.01s: `% Authorization failed.` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 5.01s: `% Authorization failed.` |
| next token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 14.01s |
| break-glass login plus three `show version` | logged in and ran them in 30.06s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=unadmitted_source type=author` ×7; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=xe1 type=acct` ×1; `event=unvalidated reason=device_unknown diagnosis=unadmitted_source device=xe1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=unadmitted_source type=authen` ×3; `event=unvalidated diagnosis=unadmitted_source type=author` ×5

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 50752 | 20:40:25.862Z | true | 20:40:46.742Z | 20:40:46.742Z | **reset mid-connection**: open across the change |
| 42956 | 20:40:31.739Z | true | 20:40:36.819Z | 20:40:36.819Z | **reset mid-connection**: open across the change |
| 42958 | 20:40:36.920Z | false | 20:40:37.019Z | 20:40:37.120Z | reset at its first packet after the change |
| 42970 | 20:40:37.219Z | false | 20:40:37.319Z | 20:40:37.520Z | reset at its first packet after the change |
| 42974 | 20:40:37.619Z | false | 20:40:37.719Z | 20:40:38.119Z | reset at its first packet after the change |
| 35194 | 20:40:38.120Z | false | 20:40:38.219Z | 20:40:39.021Z | reset at its first packet after the change |
| 35204 | 20:40:39.119Z | false | 20:40:39.219Z | 20:40:40.819Z | reset at its first packet after the change |
| 35208 | 20:40:40.919Z | false | 20:40:41.019Z | 20:40:44.219Z | reset at its first packet after the change |
| 35222 | 20:40:44.231Z | false | 20:40:44.331Z | 20:40:49.331Z | reset at its first packet after the change |
| 41722 | 20:40:56.769Z | false | 20:40:56.770Z | 20:41:01.770Z | reset at its first packet after the change |
| 38094 | 20:41:03.769Z | false | 20:41:03.771Z | 20:41:08.772Z | reset at its first packet after the change |
| 48622 | 20:41:10.782Z | false | 20:41:10.783Z | 20:41:15.784Z | reset at its first packet after the change |
| 48626 | 20:41:15.793Z | false | 20:41:15.794Z | 20:41:20.794Z | reset at its first packet after the change |
| 46382 | 20:41:20.906Z | false | 20:41:21.005Z | 20:41:26.006Z | reset at its first packet after the change |
| 46392 | 20:41:26.013Z | false | 20:41:26.113Z | 20:41:31.114Z | reset at its first packet after the change |
| 49436 | 20:41:31.120Z | false | 20:41:31.220Z | 20:41:36.221Z | reset at its first packet after the change |
| 49442 | 20:41:36.229Z | false | 20:41:36.329Z | 20:41:41.331Z | reset at its first packet after the change |

The change began at 20:40:32.186Z (host UTC); 2 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-removed-cisco_iosxe.pcap` — 306 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-removed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: renamed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 3; why is not established (54s).

The change: `port49 inventory sync`:

```
published bundle 4 (sha256:f3db979b8a3b3ca909a41e98b0c06e7dbf518287be91e956d2bf453afd75ba33): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:f3db979b8a3b3ca909a41e98b0c06e7dbf518287be91e956d2bf453afd75ba33: +1 device(s), -1, 0 changed; 0 quarantined
  device removed xe1 (cisco_iosxe)
! device added xe1-b (cisco_iosxe): admitted
  scope all_devices: xe1 left
  scope all_devices: xe1-b joined
```

Times are the host's, UTC: the change began 20:42:47.248Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:42:47.520Z; the command in flight was sent at 20:42:47.520Z.

| step | outcome |
|---|---|
| token session (`alice04`), `show version` before the change | ran in 300ms |
| first `show version` after the change, same session | printed its output in 500ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 300ms |
| next token login (`alice05`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.52s |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.52s |

Records from the device since the change, before the next logins: `event=authorize_command reason=context_missing` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=acct` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=author` ×1

Records from the device during the next logins: `event=redeem reason=device_mismatch` ×2; `event=redeem reason=token_not_found` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 36818 | 20:42:40.673Z | true | 20:42:48.325Z | 20:42:48.325Z | **reset mid-connection**: open across the change |
| 36820 | 20:42:46.549Z | true | 20:42:47.625Z | 20:42:47.625Z | **reset mid-connection**: open across the change |
| 36822 | 20:42:47.725Z | false | 20:42:47.825Z | (not observed) | not reset by port49d |
| 49358 | 20:42:58.353Z | false | 20:42:58.354Z | (not observed) | not reset by port49d |

The change began at 20:42:47.248Z (host UTC); 2 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-renamed-cisco_iosxe.pcap` — 208 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-renamed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: replatformed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

The change: `port49 inventory sync`:

```
published bundle 6 (sha256:a32efb497d50628e5d73d2793777d3e4fa7c755c7cbf611d6d54eaeec49ae080): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:a32efb497d50628e5d73d2793777d3e4fa7c755c7cbf611d6d54eaeec49ae080: +0 device(s), -0, 1 changed; 0 quarantined
  platform_changed xe1: cisco_iosxe → arista_eos
```

Times are the host's, UTC: the change began 20:43:27.705Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:43:30.983Z; the command in flight was sent at 20:43:30.983Z.

| step | outcome |
|---|---|
| token session (`alice06`), `show version` before the change | ran in 300ms |
| first `show version` after the change, same session | printed its output in 500ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 300ms |
| next token login (`alice07`) | logged in in 10ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.52s |

Records from the device since the change, before the next logins: `event=account` ×2; `event=authorize_command reason=permit_dominates` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=acct` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=author` ×1

Records from the device during the next logins: `event=redeem reason=token_not_found` ×2; `event=redeem reason=token_redeemed` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 49358 | 20:43:20.865Z | false | (not observed) | (not observed) | not reset by port49d |
| 36822 | 20:43:20.865Z | true | (not observed) | 20:43:27.006Z | reset before the change |
| 35662 | 20:43:21.131Z | true | 20:43:31.386Z | 20:43:31.387Z | **reset mid-connection**: open across the change |
| 35670 | 20:43:27.006Z | true | 20:43:31.087Z | 20:43:31.087Z | **reset mid-connection**: open across the change |
| 37712 | 20:43:31.186Z | false | 20:43:31.287Z | (not observed) | not reset by port49d |
| 37724 | 20:43:31.690Z | false | 20:43:31.693Z | (not observed) | not reset by port49d |

The change began at 20:43:27.705Z (host UTC); 2 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-replatformed-cisco_iosxe.pcap` — 206 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-replatformed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: refused

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

The change: `port49 inventory sync`:

```
published bundle 8 (sha256:27b8bd5f3047adfb87ce2ed1a94c58593c1dabd6803863a5f1d4b12c0bcf6348): bundle sha256:e535674e09e1c7f6aa8fbee9f8918a42c117871956a2300b7b9764c9e9ef71ee → sha256:27b8bd5f3047adfb87ce2ed1a94c58593c1dabd6803863a5f1d4b12c0bcf6348: +0 device(s), -0, 1 changed; 0 quarantined
  admission_changed xe1: admitted → refused
```

Times are the host's, UTC: the change began 20:44:05.767Z; port49d said `port49d: inventory reloaded (inventory service, bundle` by 20:44:09.044Z; the command in flight was sent at 20:44:09.044Z.

| step | outcome |
|---|---|
| token session (`alice08`), `show version` before the change | ran in 300ms |
| first `show version` after the change, same session | refused in 5.01s: `% Authorization failed.` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 5.01s: `% Authorization failed.` |
| next token login (`alice09`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.02s |
| break-glass login plus three `show version` | logged in and ran them in 20.56s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=admission_refused device=xe1 type=author` ×48; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=xe1 type=acct` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_refused device=xe1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=admission_refused device=xe1 type=acct` ×6; `event=unvalidated diagnosis=admission_refused device=xe1 type=authen` ×3; `event=unvalidated diagnosis=admission_refused device=xe1 type=author` ×99

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 37724 | 20:43:58.927Z | false | (not observed) | (not observed) | not reset by port49d |
| 37712 | 20:43:58.927Z | true | (not observed) | 20:44:05.067Z | reset before the change |
| 56660 | 20:43:59.194Z | true | 20:44:19.068Z | 20:44:19.069Z | **reset mid-connection**: open across the change |
| 56670 | 20:44:05.068Z | true | 20:44:09.149Z | 20:44:09.149Z | **reset mid-connection**: open across the change |
| 56944 | 20:44:09.250Z | false | 20:44:09.350Z | 20:44:09.350Z | reset at its first packet after the change |
| 56946 | 20:44:09.450Z | false | 20:44:09.550Z | 20:44:09.550Z | reset at its first packet after the change |
| 56952 | 20:44:09.649Z | false | 20:44:09.750Z | 20:44:09.750Z | reset at its first packet after the change |
| 56968 | 20:44:09.849Z | false | 20:44:09.950Z | 20:44:09.950Z | reset at its first packet after the change |
| 56974 | 20:44:10.050Z | false | 20:44:10.150Z | 20:44:10.150Z | reset at its first packet after the change |
| 56976 | 20:44:10.250Z | false | 20:44:10.349Z | 20:44:10.349Z | reset at its first packet after the change |
| 56988 | 20:44:10.450Z | false | 20:44:10.549Z | 20:44:10.549Z | reset at its first packet after the change |
| 56990 | 20:44:10.650Z | false | 20:44:10.750Z | 20:44:10.750Z | reset at its first packet after the change |
| 56996 | 20:44:10.850Z | false | 20:44:10.950Z | 20:44:10.950Z | reset at its first packet after the change |
| 57004 | 20:44:11.050Z | false | 20:44:11.149Z | 20:44:11.150Z | reset at its first packet after the change |
| 57008 | 20:44:11.250Z | false | 20:44:11.350Z | 20:44:11.350Z | reset at its first packet after the change |
| 57014 | 20:44:11.450Z | false | 20:44:11.549Z | 20:44:11.549Z | reset at its first packet after the change |
| 57028 | 20:44:11.649Z | false | 20:44:11.749Z | 20:44:11.750Z | reset at its first packet after the change |
| 57030 | 20:44:11.850Z | false | 20:44:11.949Z | 20:44:11.949Z | reset at its first packet after the change |
| 57040 | 20:44:12.050Z | false | 20:44:12.150Z | 20:44:12.150Z | reset at its first packet after the change |
| 57056 | 20:44:12.249Z | false | 20:44:12.350Z | 20:44:12.350Z | reset at its first packet after the change |
| 57064 | 20:44:12.450Z | false | 20:44:12.549Z | 20:44:12.549Z | reset at its first packet after the change |
| 57072 | 20:44:12.650Z | false | 20:44:12.749Z | 20:44:12.749Z | reset at its first packet after the change |
| 57076 | 20:44:12.850Z | false | 20:44:12.950Z | 20:44:12.950Z | reset at its first packet after the change |
| 57092 | 20:44:13.050Z | false | 20:44:13.150Z | 20:44:13.150Z | reset at its first packet after the change |
| 57104 | 20:44:13.250Z | false | 20:44:13.349Z | 20:44:13.350Z | reset at its first packet after the change |
| 57114 | 20:44:13.450Z | false | 20:44:13.549Z | 20:44:13.550Z | reset at its first packet after the change |
| 57120 | 20:44:13.650Z | false | 20:44:13.750Z | 20:44:13.750Z | reset at its first packet after the change |
| 57126 | 20:44:13.850Z | false | 20:44:13.949Z | 20:44:13.950Z | reset at its first packet after the change |
| 57136 | 20:44:14.160Z | false | 20:44:14.260Z | 20:44:14.260Z | reset at its first packet after the change |
| 57152 | 20:44:14.360Z | false | 20:44:14.459Z | 20:44:14.460Z | reset at its first packet after the change |
| 57154 | 20:44:14.559Z | false | 20:44:14.659Z | 20:44:14.660Z | reset at its first packet after the change |
| 57166 | 20:44:14.760Z | false | 20:44:14.859Z | 20:44:14.859Z | reset at its first packet after the change |
| 57182 | 20:44:14.960Z | false | 20:44:15.059Z | 20:44:15.059Z | reset at its first packet after the change |
| 57186 | 20:44:15.159Z | false | 20:44:15.260Z | 20:44:15.260Z | reset at its first packet after the change |
| 57190 | 20:44:15.360Z | false | 20:44:15.460Z | 20:44:15.460Z | reset at its first packet after the change |
| 57194 | 20:44:15.560Z | false | 20:44:15.659Z | 20:44:15.660Z | reset at its first packet after the change |
| 57206 | 20:44:15.760Z | false | 20:44:15.860Z | 20:44:15.860Z | reset at its first packet after the change |
| 57220 | 20:44:15.960Z | false | 20:44:16.060Z | 20:44:16.060Z | reset at its first packet after the change |
| 57222 | 20:44:16.159Z | false | 20:44:16.260Z | 20:44:16.260Z | reset at its first packet after the change |
| 57226 | 20:44:16.359Z | false | 20:44:16.460Z | 20:44:16.460Z | reset at its first packet after the change |
| … | 123 more connection(s) not listed | | | | |

The change began at 20:44:05.767Z (host UTC); 2 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-refused-cisco_iosxe.pcap` — 2032 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-refused-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

The change: port49d's broker.policy_file given `- {match: {name: xe1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the change began 20:45:11.762Z; port49d said `port49d: policy reloaded` by 20:45:13.265Z; the command in flight was sent at 20:45:13.265Z.

| step | outcome |
|---|---|
| token session (`alice10`), `show version` before the change | ran in 300ms |
| first `show version` after the change, same session | refused in 500ms: `% Authorization failed.` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 300ms: `% Authorization failed.` |
| next token login (`alice11`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.02s |
| break-glass login plus three `show version` | logged in and ran them in 1.53s |

Records from the device since the change, before the next logins: `event=unvalidated diagnosis=no_known_key_matches type=author` ×2; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=acct` ×1; `event=unvalidated reason=device_unknown diagnosis=admission_withdrawn device=xe1 type=author` ×1

Records from the device during the next logins: `event=unvalidated diagnosis=no_known_key_matches type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 52322 | 20:45:05.440Z | true | 20:45:14.070Z | 20:45:14.070Z | **reset mid-connection**: open across the change |
| 57346 | 20:45:11.316Z | true | 20:45:13.370Z | 20:45:13.370Z | **reset mid-connection**: open across the change |
| 57350 | 20:45:13.469Z | false | 20:45:13.570Z | 20:45:13.570Z | reset at its first packet after the change |
| 57362 | 20:45:13.670Z | false | (not observed) | 20:45:13.670Z | reset before the device sent on it (refused at Accept) |
| 57368 | 20:45:13.874Z | false | 20:45:13.875Z | 20:45:13.875Z | reset at its first packet after the change |
| 57372 | 20:45:13.974Z | false | (not observed) | 20:45:13.974Z | reset before the device sent on it (refused at Accept) |
| 50106 | 20:45:24.097Z | false | 20:45:24.098Z | 20:45:24.098Z | reset at its first packet after the change |
| 50118 | 20:45:26.099Z | false | 20:45:26.100Z | 20:45:26.100Z | reset at its first packet after the change |
| 60500 | 20:45:28.113Z | false | 20:45:28.114Z | 20:45:28.114Z | reset at its first packet after the change |
| 60510 | 20:45:28.125Z | false | (not observed) | 20:45:28.125Z | reset before the device sent on it (refused at Accept) |
| 60526 | 20:45:28.482Z | false | (not observed) | 20:45:28.482Z | reset before the device sent on it (refused at Accept) |
| 60536 | 20:45:28.730Z | false | (not observed) | 20:45:28.730Z | reset before the device sent on it (refused at Accept) |
| 60550 | 20:45:28.830Z | false | (not observed) | 20:45:28.831Z | reset before the device sent on it (refused at Accept) |
| 60566 | 20:45:28.980Z | false | (not observed) | 20:45:28.980Z | reset before the device sent on it (refused at Accept) |
| 60574 | 20:45:29.232Z | false | (not observed) | 20:45:29.232Z | reset before the device sent on it (refused at Accept) |
| 60590 | 20:45:29.332Z | false | (not observed) | 20:45:29.333Z | reset before the device sent on it (refused at Accept) |
| 60606 | 20:45:29.433Z | false | (not observed) | 20:45:29.433Z | reset before the device sent on it (refused at Accept) |

The change began at 20:45:11.762Z (host UTC); 2 connection(s) read as reset mid-connection.

Capture: `tests/lab/evidence/L29-reload-rekeyed-cisco_iosxe.pcap` — 250 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L29-reload-rekeyed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


