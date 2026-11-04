# L88: the reference AAA configuration on cEOS-lab 4.36.3M

Platform: arista_ceos. Image: cEOS-lab 4.36.3M. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/arista_eos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 602ms (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +1s |
| b | PASS | break-glass login with port49d stopped: ok true in 1.56s (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [deny store_unavailable], authorize_command [], accounting []; tries: try at +0s took 3.7s: logged in, `show version` printed "'Authorization denied: port49: authorization store unavailable'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 1.72s, `show version` output "'Arista cEOSLab'" |
| e | PASS | login with a one-time credential (login attempt 1, 2s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 1; port49 authorized one command and denied the other; command output: [0] Hardware version: Serial number: 0A3387FE82C43CDFF4AD09916EB43403 Hardware MAC address: 001c.737a.ec99 System MAC address: 001c.737a.ec99 Software image version... [1] > show clock % Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' at line 1  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 2.38s; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 2s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`); second `show version`, same session: refused in 100ms: `% Authorization denied for command 'show version': Unknown role`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 6.07s; break-glass login plus three `show version`: logged in and ran them in 1.92s |
| h | SEE NOTE | measured in the separate RFC 9887 pass (cells a, b, d, e, f), `tests/lab/results/L88-arista_ceos-tls.md`; this row was a placeholder when this plain pass ran |

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
6 connections from the device in the window: 6 with a SYN, 6 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 60515: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 52001: SYN true SYN-ACK true; device packets 22, server packets 22; FIN dev true srv true; RST dev false srv false
+2.2s 172.100.100.2 sport 43233: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.3s 172.100.100.2 sport 53169: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.4s 172.100.100.2 sport 55831: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.4s 172.100.100.2 sport 41099: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

The change: port49d's broker.policy_file given `- {match: {name: leaf1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 01:47:38.185Z; port49d applied the reload, saying `port49d: policy reloaded`, between 01:47:40.002Z and 01:47:40.027Z, and the change instant the capture is read against is 01:47:40.002Z; the command in flight was sent at 01:47:40.027Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 100ms: `% Authorization denied for command 'show version': Unknown role` |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain in 6.07s |
| break-glass login plus three `show version` | logged in and ran them in 1.92s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×1; `event=unvalidated reason=device_unknown <LONG> device=leaf1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 54513 | 01:47:34.256Z | true | (not observed) | (not observed) | not reset by port49d |
| 59297 | 01:47:35.258Z | true | 01:47:40.030Z | 01:47:40.030Z | **reset mid-connection**: open across the change |
| 34341 | 01:47:40.030Z | false | (not observed) | 01:47:40.030Z | reset before the device sent on it (refused at Accept) |
| 53011 | 01:47:40.130Z | false | 01:47:40.131Z | 01:47:40.131Z | reset at its first packet after the change |
| 41249 | 01:47:40.131Z | false | (not observed) | 01:47:40.131Z | reset before the device sent on it (refused at Accept) |
| 54401 | 01:47:40.232Z | false | 01:47:40.232Z | 01:47:40.232Z | reset at its first packet after the change |
| 33397 | 01:47:40.233Z | false | (not observed) | 01:47:40.233Z | reset before the device sent on it (refused at Accept) |
| 57923 | 01:47:50.295Z | false | 01:47:50.295Z | 01:47:50.295Z | reset at its first packet after the change |
| 41247 | 01:47:50.296Z | false | (not observed) | 01:47:50.296Z | reset before the device sent on it (refused at Accept) |
| 48185 | 01:47:56.355Z | false | 01:47:56.355Z | 01:47:56.356Z | reset at its first packet after the change |
| 46147 | 01:47:56.356Z | false | (not observed) | 01:47:56.356Z | reset before the device sent on it (refused at Accept) |
| 37167 | 01:47:57.892Z | false | 01:47:57.892Z | 01:47:57.892Z | reset at its first packet after the change |
| 48371 | 01:47:57.892Z | false | (not observed) | 01:47:57.892Z | reset before the device sent on it (refused at Accept) |
| 48773 | 01:47:57.978Z | false | (not observed) | 01:47:57.978Z | reset before the device sent on it (refused at Accept) |
| 37539 | 01:47:57.978Z | false | (not observed) | 01:47:57.978Z | reset before the device sent on it (refused at Accept) |
| 47043 | 01:47:58.021Z | false | (not observed) | 01:47:58.022Z | reset before the device sent on it (refused at Accept) |
| 57293 | 01:47:58.022Z | false | (not observed) | 01:47:58.022Z | reset before the device sent on it (refused at Accept) |
| 47259 | 01:47:58.023Z | false | (not observed) | 01:47:58.023Z | reset before the device sent on it (refused at Accept) |
| 60151 | 01:47:58.024Z | false | (not observed) | 01:47:58.024Z | reset before the device sent on it (refused at Accept) |
| 34035 | 01:47:58.081Z | false | (not observed) | 01:47:58.081Z | reset before the device sent on it (refused at Accept) |
| 56577 | 01:47:58.081Z | false | (not observed) | 01:47:58.081Z | reset before the device sent on it (refused at Accept) |
| 52001 | 01:47:58.123Z | false | (not observed) | 01:47:58.123Z | reset before the device sent on it (refused at Accept) |
| 49559 | 01:47:58.124Z | false | (not observed) | 01:47:58.124Z | reset before the device sent on it (refused at Accept) |
| 54287 | 01:47:58.125Z | false | (not observed) | 01:47:58.125Z | reset before the device sent on it (refused at Accept) |
| 57355 | 01:47:58.126Z | false | (not observed) | 01:47:58.126Z | reset before the device sent on it (refused at Accept) |
| 59983 | 01:47:58.184Z | false | (not observed) | 01:47:58.184Z | reset before the device sent on it (refused at Accept) |
| 54327 | 01:47:58.229Z | false | (not observed) | 01:47:58.229Z | reset before the device sent on it (refused at Accept) |
| 39257 | 01:47:58.230Z | false | (not observed) | 01:47:58.230Z | reset before the device sent on it (refused at Accept) |
| 36475 | 01:47:58.231Z | false | (not observed) | 01:47:58.231Z | reset before the device sent on it (refused at Accept) |
| 57559 | 01:47:58.232Z | false | (not observed) | 01:47:58.232Z | reset before the device sent on it (refused at Accept) |
| 38549 | 01:47:58.251Z | false | (not observed) | 01:47:58.251Z | reset before the device sent on it (refused at Accept) |
| 34231 | 01:47:58.251Z | false | (not observed) | 01:47:58.251Z | reset before the device sent on it (refused at Accept) |

The change began at 01:47:40.002Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 300 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
