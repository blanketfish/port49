# L88: the reference AAA configuration on Nexus 9300v 10.6(2)F

Platform: cisco_nxos. Image: Nexus 9300v 10.6(2)F. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_nxos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-nxos106-cisco_nxos.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 2.086s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +2s |
| b | PASS | break-glass login with port49d stopped: ok true in 190ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [deny store_unavailable deny store_unavailable], accounting []; tries: try at +0s took 2.4s: logged in, `show version` printed "'Error: AAA authorization failed <LONG>(0x10)'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 1.2s, `show version` output "'Cisco Nexus Operating System (NX-OS) Software'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 3 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 1; port49 authorized one command and denied the other; command output: [0] TAC support: http://www.cisco.com/tac Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html Copyright (c) 2002-2025, Cisco... [1] Cmd exec error.  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 1.21s; connections the first server reset: 5; port49 redeemed the credential: true; tries 1, the login reached port49 after 1s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 key 0 <key> single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 810ms; first `show version` after the change, same session: printed its output in 810ms (the reset's packet: `type=author`); second `show version`, same session: printed its output in 810ms; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 28.61s; break-glass login plus three `show version`: logged in and ran them in 2.96s |

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
+100ms 172.100.100.1 sport 47076: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.2 sport 41462: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+200ms 172.100.100.2 sport 41474: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+400ms 172.100.100.1 sport 47084: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+400ms 172.100.100.1 sport 47100: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+400ms 172.100.100.2 sport 41478: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+400ms 172.100.100.2 sport 41486: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+1.2s 172.100.100.1 sport 47104: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+1.2s 172.100.100.2 sport 41500: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+1.2s 172.100.100.1 sport 47106: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+1.2s 172.100.100.2 sport 41516: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (2s).

The change: port49d's broker.policy_file given `- {match: {name: nx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 08:31:28.438Z; port49d applied the reload, saying `port49d: policy reloaded`, between 08:31:29.937Z and 08:31:29.962Z, and the change instant the capture is read against is 08:31:29.937Z; the command in flight was sent at 08:31:29.962Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 810ms |
| first `show version` after the change, same session | printed its output in 810ms (the reset's packet: `type=author`) |
| second `show version`, same session | printed its output in 810ms |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 28.61s |
| break-glass login plus three `show version` | logged in and ran them in 2.96s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×1; `event=unvalidated reason=device_unknown <LONG> device=nx1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×2; `event=unvalidated <LONG> type=authen` ×1; `event=unvalidated <LONG> type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 47246 | 08:31:25.296Z | true | 08:31:29.987Z | 08:31:29.987Z | **reset mid-connection**: open across the change |
| 41546 | 08:31:30.794Z | false | 08:31:30.795Z | 08:31:30.795Z | reset at its first packet after the change |
| 41550 | 08:31:31.598Z | false | 08:31:31.599Z | 08:31:31.599Z | reset at its first packet after the change |
| 36888 | 08:31:41.748Z | false | 08:31:41.750Z | 08:31:41.750Z | reset at its first packet after the change |
| 52086 | 08:31:53.703Z | false | 08:31:53.726Z | 08:31:53.726Z | reset at its first packet after the change |
| 47984 | 08:31:57.738Z | false | (not observed) | 08:31:57.738Z | reset before the device sent on it (refused at Accept) |
| 44460 | 08:32:10.236Z | false | 08:32:10.237Z | 08:32:10.237Z | reset at its first packet after the change |
| 44464 | 08:32:10.350Z | false | (not observed) | 08:32:10.351Z | reset before the device sent on it (refused at Accept) |
| 44474 | 08:32:10.502Z | false | (not observed) | 08:32:10.502Z | reset before the device sent on it (refused at Accept) |
| 44484 | 08:32:10.525Z | false | (not observed) | 08:32:10.525Z | reset before the device sent on it (refused at Accept) |
| 57208 | 08:32:10.531Z | false | (not observed) | 08:32:10.531Z | reset before the device sent on it (refused at Accept) |
| 44488 | 08:32:11.311Z | false | (not observed) | 08:32:11.311Z | reset before the device sent on it (refused at Accept) |
| 57210 | 08:32:11.318Z | false | (not observed) | 08:32:11.318Z | reset before the device sent on it (refused at Accept) |
| 44500 | 08:32:11.342Z | false | (not observed) | 08:32:11.342Z | reset before the device sent on it (refused at Accept) |
| 57216 | 08:32:11.349Z | false | (not observed) | 08:32:11.349Z | reset before the device sent on it (refused at Accept) |
| 44508 | 08:32:11.440Z | false | (not observed) | 08:32:11.440Z | reset before the device sent on it (refused at Accept) |
| 44516 | 08:32:11.464Z | false | (not observed) | 08:32:11.464Z | reset before the device sent on it (refused at Accept) |
| 44532 | 08:32:12.234Z | false | 08:32:12.235Z | 08:32:12.235Z | reset at its first packet after the change |
| 44546 | 08:32:12.258Z | false | (not observed) | 08:32:12.259Z | reset before the device sent on it (refused at Accept) |
| 57222 | 08:32:12.266Z | false | (not observed) | 08:32:12.266Z | reset before the device sent on it (refused at Accept) |
| 44556 | 08:32:12.354Z | false | (not observed) | 08:32:12.354Z | reset before the device sent on it (refused at Accept) |
| 44560 | 08:32:12.376Z | false | (not observed) | 08:32:12.376Z | reset before the device sent on it (refused at Accept) |
| 44576 | 08:32:13.153Z | false | (not observed) | 08:32:13.153Z | reset before the device sent on it (refused at Accept) |
| 57228 | 08:32:13.160Z | false | (not observed) | 08:32:13.160Z | reset before the device sent on it (refused at Accept) |
| 44586 | 08:32:13.185Z | false | (not observed) | 08:32:13.185Z | reset before the device sent on it (refused at Accept) |
| 57238 | 08:32:13.192Z | false | (not observed) | 08:32:13.192Z | reset before the device sent on it (refused at Accept) |

The change began at 08:31:29.937Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L88-g-nxos106-rekeyed-cisco_nxos.pcap` — 280 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L88-g-nxos106-rekeyed-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
