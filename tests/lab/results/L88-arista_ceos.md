# L88: the reference AAA configuration on cEOS-lab 4.36.3M

Platform: arista_ceos. Image: cEOS-lab 4.36.3M. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/arista_eos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-ceos436-arista_ceos.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 893ms (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +1s |
| b | PASS | break-glass login with port49d stopped: ok true in 2.37s (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [deny store_unavailable], authorize_command [], accounting []; tries: try at +0s took 3s: logged in, `show version` printed "'Authorization denied: port49: authorization store unavailable'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 2.54s, `show version` output "'Arista cEOSLab'" |
| e | PASS | login with a one-time credential (login attempt 1, 2s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 1; port49 authorized one command and denied the other; command output: [0] Hardware version: Serial number: 76CD1C5C8DFE62E9C4FAF36AE23A97CA Hardware MAC address: 001c.73dd.78d9 System MAC address: 001c.73dd.78d9 Software image version... [1] > show clock % Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' at line 1  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 2.12s; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 2s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`); second `show version`, same session: refused in 100ms: `% Authorization denied for command 'show version': Unknown role`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 3.88s; break-glass login plus three `show version`: logged in and ran them in 2.74s |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=ssh
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=ssh
  event=account verdict= reason= flags=start user=alice01 port=ssh
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=ssh
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=ssh
  event=account verdict= reason= flags=stop user=alice01 port=ssh
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=ssh
  event=authorize_command verdict=deny reason=no_permit_dominates_deny flags= user=alice01 port=ssh
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=ssh
  event=account verdict= reason= flags=start user=alice02 port=ssh
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=ssh
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=ssh
  event=account verdict= reason= flags=stop user=alice02 port=ssh
the wire during the login (headers only):
7 connections from the device in the window: 7 with a SYN, 7 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 43699: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 53779: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+2s 172.100.100.2 sport 40953: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.1s 172.100.100.2 sport 47559: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.1s 172.100.100.2 sport 44923: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.1s 172.100.100.2 sport 42237: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.1s 172.100.100.2 sport 58225: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: port49d's broker.policy_file given `- {match: {name: leaf1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 08:34:28.015Z; port49d applied the reload, saying `port49d: policy reloaded`, between 08:34:29.450Z and 08:34:29.476Z, and the change instant the capture is read against is 08:34:29.450Z; the command in flight was sent at 08:34:29.476Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 3.88s |
| break-glass login plus three `show version` | logged in and ran them in 2.74s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×1; `event=unvalidated reason=device_unknown <LONG> device=leaf1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 52001 | 08:34:24.704Z | true | (not observed) | (not observed) | not reset by port49d |
| 36063 | 08:34:25.417Z | true | 08:34:29.478Z | 08:34:29.478Z | **reset mid-connection**: open across the change |
| 56091 | 08:34:29.478Z | false | (not observed) | 08:34:29.479Z | reset before the device sent on it (refused at Accept) |
| 58291 | 08:34:29.579Z | false | 08:34:29.579Z | 08:34:29.579Z | reset at its first packet after the change |
| 55159 | 08:34:29.579Z | false | (not observed) | 08:34:29.579Z | reset before the device sent on it (refused at Accept) |
| 36945 | 08:34:29.681Z | false | 08:34:29.681Z | 08:34:29.682Z | reset at its first packet after the change |
| 41715 | 08:34:29.682Z | false | (not observed) | 08:34:29.682Z | reset before the device sent on it (refused at Accept) |
| 53911 | 08:34:39.741Z | false | 08:34:39.741Z | 08:34:39.742Z | reset at its first packet after the change |
| 39325 | 08:34:39.742Z | false | (not observed) | 08:34:39.742Z | reset before the device sent on it (refused at Accept) |
| 60349 | 08:34:43.627Z | false | 08:34:43.628Z | 08:34:43.628Z | reset at its first packet after the change |
| 55663 | 08:34:43.628Z | false | (not observed) | 08:34:43.628Z | reset before the device sent on it (refused at Accept) |
| 42941 | 08:34:45.978Z | false | 08:34:45.979Z | 08:34:45.979Z | reset at its first packet after the change |
| 34443 | 08:34:45.979Z | false | (not observed) | 08:34:45.979Z | reset before the device sent on it (refused at Accept) |
| 36483 | 08:34:46.064Z | false | (not observed) | 08:34:46.064Z | reset before the device sent on it (refused at Accept) |
| 57683 | 08:34:46.064Z | false | (not observed) | 08:34:46.064Z | reset before the device sent on it (refused at Accept) |
| 32915 | 08:34:46.108Z | false | (not observed) | 08:34:46.109Z | reset before the device sent on it (refused at Accept) |
| 52543 | 08:34:46.109Z | false | (not observed) | 08:34:46.109Z | reset before the device sent on it (refused at Accept) |
| 38971 | 08:34:46.111Z | false | (not observed) | 08:34:46.111Z | reset before the device sent on it (refused at Accept) |
| 56493 | 08:34:46.112Z | false | (not observed) | 08:34:46.112Z | reset before the device sent on it (refused at Accept) |
| 37437 | 08:34:46.172Z | false | (not observed) | 08:34:46.172Z | reset before the device sent on it (refused at Accept) |
| 33421 | 08:34:46.173Z | false | (not observed) | 08:34:46.173Z | reset before the device sent on it (refused at Accept) |
| 33095 | 08:34:46.215Z | false | (not observed) | 08:34:46.216Z | reset before the device sent on it (refused at Accept) |
| 55233 | 08:34:46.216Z | false | (not observed) | 08:34:46.216Z | reset before the device sent on it (refused at Accept) |
| 56189 | 08:34:46.217Z | false | (not observed) | 08:34:46.217Z | reset before the device sent on it (refused at Accept) |
| 52003 | 08:34:46.218Z | false | (not observed) | 08:34:46.218Z | reset before the device sent on it (refused at Accept) |
| 54973 | 08:34:46.276Z | false | (not observed) | 08:34:46.276Z | reset before the device sent on it (refused at Accept) |
| 60097 | 08:34:46.320Z | false | (not observed) | 08:34:46.320Z | reset before the device sent on it (refused at Accept) |
| 36717 | 08:34:46.321Z | false | (not observed) | 08:34:46.321Z | reset before the device sent on it (refused at Accept) |
| 54463 | 08:34:46.322Z | false | (not observed) | 08:34:46.322Z | reset before the device sent on it (refused at Accept) |
| 58205 | 08:34:46.323Z | false | (not observed) | 08:34:46.323Z | reset before the device sent on it (refused at Accept) |
| 57647 | 08:34:46.344Z | false | (not observed) | 08:34:46.344Z | reset before the device sent on it (refused at Accept) |
| 35783 | 08:34:46.345Z | false | (not observed) | 08:34:46.345Z | reset before the device sent on it (refused at Accept) |

The change began at 08:34:29.450Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L88-g-ceos436-rekeyed-arista_ceos.pcap` — 300 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L88-g-ceos436-rekeyed-arista_ceos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
