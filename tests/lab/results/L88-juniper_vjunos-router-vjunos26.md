# L88: the reference AAA configuration on vJunos-router 26.2R1.7

Platform: juniper_vjunos-router. Image: vJunos-router 26.2R1.7. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/juniper_junos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `show configuration system authentication-order | display set`: set system authentication-order tacplus
- `show interfaces terse | match fxp0`: fxp0 up up fxp0.0 up up inet 10.0.0.15/24

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 6.625s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +7s |
| b | PASS | break-glass login with port49d stopped: ok true in 40ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 800ms: logged in, `show version` printed "'Hostname: srx1'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 190ms, `show version` output "'Hostname: srx1'" |
| e | PASS | login with a one-time credential (login attempt 1, 3s after the first) no error: 0 command authorizations permitted, 0 denied by port49; accounting START 2, STOP 4; judged on the device output: Junos authorizes a command by the login class and asks port49 for none; command output: [0] Model: vmx Family: junos Junos: 26.2R1.7 JUNOS OS Kernel 64-bit [20260518.25fe30f_builder_bsd15_262] JUNOS OS libs [20260518.25fe30f_builder_bsd15_262] JUNOS mo... [1] error: unknown command: clear  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 180ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 0s; first command output:  |
| g | OBSERVED | the device held no connection open across the reload that port49d reset (single-connection was on; what it sent after the reload went on connections it opened after it); single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 200ms; first `show version` after the change, same session: printed its output in 200ms; second `show version`, same session: printed its output in 200ms; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.05s; break-glass login plus three `show version`: logged in and ran them in 450ms |
| h | NOT MEASURED | the harness does not run cell h yet |
| i | MEASURED | the largest `idle-timeout` the commit accepts is 4294967295 (the next value up was refused: set system login class l88i idle-timeout 4294967296 ^ Value 4294967296 is not within range (0..4294967295) at '4294967296' [edit] breakglass@srx1#) |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=
  event=account verdict= reason= flags=start user=alice01 port=non-tty
  event=account verdict= reason= flags=stop user=alice01 port=non-tty
  event=account verdict= reason= flags=stop user=alice01 port=non-tty
  event=account verdict= reason= flags=start user=alice01 port=non-tty
  event=account verdict= reason= flags=stop user=alice01 port=non-tty
  event=account verdict= reason= flags=stop user=alice01 port=non-tty
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=
the wire during the login (headers only):
3 connections from the device in the window: 3 with a SYN, 3 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 42382: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 56054: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 56062: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: srx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

**Observation: the device held no connection open across this change.** port49d wrote no device_unknown record, and the capture holds no connection open before the change that port49d reset after it; what the device sent after the change went on connections it opened after it (records: `event=unvalidated <LONG> type=acct` ×1).

Times are the host's, UTC: the sync (or policy edit) began 01:44:38.802Z; port49d applied the reload, saying `port49d: policy reloaded`, between 01:44:39.916Z and 01:44:39.942Z, and the change instant the capture is read against is 01:44:39.916Z; the command in flight was sent at 01:44:39.943Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.05s |
| break-glass login plus three `show version` | logged in and ran them in 450ms |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 46506 | 01:44:30.914Z | false | (not observed) | 01:44:30.914Z | reset before the change |
| 48796 | 01:44:30.914Z | false | (not observed) | 01:44:30.914Z | reset before the change |
| 46518 | 01:44:30.915Z | false | (not observed) | 01:44:30.915Z | reset before the change |
| 48804 | 01:44:30.915Z | false | (not observed) | 01:44:30.915Z | reset before the change |
| 46524 | 01:44:30.916Z | false | (not observed) | 01:44:30.916Z | reset before the change |
| 48808 | 01:44:30.916Z | false | (not observed) | 01:44:30.916Z | reset before the change |
| 46532 | 01:44:30.916Z | false | (not observed) | 01:44:30.916Z | reset before the change |
| 48812 | 01:44:30.917Z | false | (not observed) | 01:44:30.917Z | reset before the change |
| 46534 | 01:44:30.917Z | false | (not observed) | 01:44:30.917Z | reset before the change |
| 48824 | 01:44:30.917Z | false | (not observed) | 01:44:30.917Z | reset before the change |
| 46550 | 01:44:30.918Z | false | (not observed) | 01:44:30.918Z | reset before the change |
| 48840 | 01:44:30.918Z | false | (not observed) | 01:44:30.918Z | reset before the change |
| 46560 | 01:44:30.918Z | false | (not observed) | 01:44:30.918Z | reset before the change |
| 48850 | 01:44:30.919Z | false | (not observed) | 01:44:30.919Z | reset before the change |
| 46566 | 01:44:30.919Z | false | (not observed) | 01:44:30.919Z | reset before the change |
| 48860 | 01:44:30.919Z | false | (not observed) | 01:44:30.919Z | reset before the change |
| 46580 | 01:44:30.919Z | false | (not observed) | 01:44:30.919Z | reset before the change |
| 48870 | 01:44:30.920Z | false | (not observed) | 01:44:30.920Z | reset before the change |
| 46584 | 01:44:30.920Z | false | (not observed) | 01:44:30.920Z | reset before the change |
| 48882 | 01:44:30.920Z | false | (not observed) | 01:44:30.920Z | reset before the change |
| 46590 | 01:44:30.921Z | false | (not observed) | 01:44:30.921Z | reset before the change |
| 48892 | 01:44:30.921Z | false | (not observed) | 01:44:30.921Z | reset before the change |
| 46596 | 01:44:31.167Z | true | (not observed) | (not observed) | not reset by port49d |
| 46606 | 01:44:32.038Z | true | (not observed) | (not observed) | not reset by port49d |
| 36172 | 01:44:38.088Z | true | (not observed) | (not observed) | not reset by port49d |
| 36180 | 01:44:40.956Z | false | 01:44:40.957Z | 01:44:40.957Z | reset at its first packet after the change |
| 40528 | 01:44:40.958Z | false | (not observed) | 01:44:40.958Z | reset before the device sent on it (refused at Accept) |
| 36186 | 01:44:40.959Z | false | (not observed) | 01:44:40.959Z | reset before the device sent on it (refused at Accept) |
| 40530 | 01:44:40.960Z | false | (not observed) | 01:44:40.960Z | reset before the device sent on it (refused at Accept) |
| 36192 | 01:44:40.960Z | false | (not observed) | 01:44:40.961Z | reset before the device sent on it (refused at Accept) |
| 40546 | 01:44:40.962Z | false | (not observed) | 01:44:40.962Z | reset before the device sent on it (refused at Accept) |
| 36204 | 01:44:40.962Z | false | (not observed) | 01:44:40.962Z | reset before the device sent on it (refused at Accept) |
| 40548 | 01:44:40.963Z | false | (not observed) | 01:44:40.963Z | reset before the device sent on it (refused at Accept) |
| 36214 | 01:44:40.963Z | false | (not observed) | 01:44:40.964Z | reset before the device sent on it (refused at Accept) |
| 40550 | 01:44:40.965Z | false | (not observed) | 01:44:40.965Z | reset before the device sent on it (refused at Accept) |
| 36230 | 01:44:40.965Z | false | (not observed) | 01:44:40.965Z | reset before the device sent on it (refused at Accept) |
| 40564 | 01:44:40.966Z | false | (not observed) | 01:44:40.966Z | reset before the device sent on it (refused at Accept) |
| 36242 | 01:44:40.966Z | false | (not observed) | 01:44:40.967Z | reset before the device sent on it (refused at Accept) |
| 40580 | 01:44:40.967Z | false | (not observed) | 01:44:40.967Z | reset before the device sent on it (refused at Accept) |
| 36252 | 01:44:40.968Z | false | (not observed) | 01:44:40.968Z | reset before the device sent on it (refused at Accept) |
| … | 53 more connection(s) not listed | | | | |

The change began at 01:44:39.916Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 610 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
