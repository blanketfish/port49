# L88: the reference AAA configuration on Nexus 9300v 10.6(2)F

Platform: cisco_nxos. Image: Nexus 9300v 10.6(2)F. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_nxos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 2.07s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +2s |
| b | PASS | break-glass login with port49d stopped: ok true in 210ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [deny store_unavailable deny store_unavailable], accounting []; tries: try at +0s took 2s: logged in, `show version` printed "'Error: AAA authorization failed <LONG>(0x10)'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 1.25s, `show version` output "'Cisco Nexus Operating System (NX-OS) Software'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 3 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 1; port49 authorized one command and denied the other; command output: [0] TAC support: http://www.cisco.com/tac Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html Copyright (c) 2002-2025, Cisco... [1] Cmd exec error.  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 1.24s; connections the first server reset: 5; port49 redeemed the credential: true; tries 1, the login reached port49 after 1s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 key 0 <key> single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 800ms; first `show version` after the change, same session: printed its output in 800ms (the reset's packet: `type=author`); second `show version`, same session: printed its output in 800ms; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 30.43s; break-glass login plus three `show version`: logged in and ran them in 2.94s |
| h | NOT MEASURED | the harness does not run cell h yet |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=0
  event=account verdict= reason= flags=stop user= port=0
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=0
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=0
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=0
  event=account verdict= reason= flags=start user=alice01 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=
  event=account verdict= reason= flags=stop user=alice01 port=0
  event=account verdict= reason= flags=start user=alice01 port=0
  event=authorize_command verdict=deny reason=no_permit_dominates_deny flags= user=alice01 port=
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=0
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=0
  event=account verdict= reason= flags=start user=alice02 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
the wire during the login (headers only):
11 connections from the device in the window: 11 with a SYN, 11 answered SYN-ACK, 5 with an RST
+100ms 172.100.100.1 sport 42668: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.2 sport 49400: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+200ms 172.100.100.2 sport 49408: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+400ms 172.100.100.1 sport 42676: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+400ms 172.100.100.1 sport 42686: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+400ms 172.100.100.2 sport 49422: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+400ms 172.100.100.2 sport 49430: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+1.2s 172.100.100.1 sport 42690: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+1.2s 172.100.100.2 sport 49446: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+1.2s 172.100.100.1 sport 42698: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+1.3s 172.100.100.2 sport 49460: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: port49d's broker.policy_file given `- {match: {name: nx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 01:40:00.294Z; port49d applied the reload, saying `port49d: policy reloaded`, between 01:40:01.691Z and 01:40:01.717Z, and the change instant the capture is read against is 01:40:01.691Z; the command in flight was sent at 01:40:01.717Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 800ms |
| first `show version` after the change, same session | printed its output in 800ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 800ms |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 30.43s |
| break-glass login plus three `show version` | logged in and ran them in 2.94s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×1; `event=unvalidated reason=device_unknown <LONG> device=nx1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×2; `event=unvalidated <LONG> type=authen` ×1; `event=unvalidated <LONG> type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 35886 | 01:39:57.063Z | true | 01:40:01.741Z | 01:40:01.741Z | **reset mid-connection**: open across the change |
| 35892 | 01:40:02.547Z | false | 01:40:02.548Z | 01:40:02.548Z | reset at its first packet after the change |
| 35906 | 01:40:03.350Z | false | 01:40:03.350Z | 01:40:03.350Z | reset at its first packet after the change |
| 41912 | 01:40:13.503Z | false | 01:40:13.504Z | 01:40:13.504Z | reset at its first packet after the change |
| 41826 | 01:40:26.175Z | false | 01:40:26.197Z | 01:40:26.197Z | reset at its first packet after the change |
| 41418 | 01:40:30.918Z | false | (not observed) | 01:40:30.918Z | reset before the device sent on it (refused at Accept) |
| 45956 | 01:40:43.809Z | false | 01:40:43.810Z | 01:40:43.810Z | reset at its first packet after the change |
| 45970 | 01:40:43.927Z | false | (not observed) | 01:40:43.927Z | reset before the device sent on it (refused at Accept) |
| 45980 | 01:40:44.087Z | false | (not observed) | 01:40:44.087Z | reset before the device sent on it (refused at Accept) |
| 45984 | 01:40:44.109Z | false | (not observed) | 01:40:44.109Z | reset before the device sent on it (refused at Accept) |
| 42714 | 01:40:44.116Z | false | (not observed) | 01:40:44.116Z | reset before the device sent on it (refused at Accept) |
| 45992 | 01:40:44.881Z | false | (not observed) | 01:40:44.882Z | reset before the device sent on it (refused at Accept) |
| 45996 | 01:40:44.906Z | false | (not observed) | 01:40:44.906Z | reset before the device sent on it (refused at Accept) |
| 42720 | 01:40:44.912Z | false | (not observed) | 01:40:44.913Z | reset before the device sent on it (refused at Accept) |
| 46008 | 01:40:45.005Z | false | (not observed) | 01:40:45.005Z | reset before the device sent on it (refused at Accept) |
| 46010 | 01:40:45.027Z | false | (not observed) | 01:40:45.027Z | reset before the device sent on it (refused at Accept) |
| 46020 | 01:40:45.795Z | false | 01:40:45.796Z | 01:40:45.796Z | reset at its first packet after the change |
| 46034 | 01:40:45.819Z | false | (not observed) | 01:40:45.820Z | reset before the device sent on it (refused at Accept) |
| 42724 | 01:40:45.826Z | false | (not observed) | 01:40:45.826Z | reset before the device sent on it (refused at Accept) |
| 46050 | 01:40:45.915Z | false | (not observed) | 01:40:45.916Z | reset before the device sent on it (refused at Accept) |
| 46056 | 01:40:45.938Z | false | (not observed) | 01:40:45.938Z | reset before the device sent on it (refused at Accept) |
| 46068 | 01:40:46.714Z | false | (not observed) | 01:40:46.715Z | reset before the device sent on it (refused at Accept) |
| 46084 | 01:40:46.739Z | false | (not observed) | 01:40:46.739Z | reset before the device sent on it (refused at Accept) |

The change began at 01:40:01.691Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 272 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
