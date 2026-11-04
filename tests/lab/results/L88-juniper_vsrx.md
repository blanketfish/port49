# L88: the reference AAA configuration on vSRX3 21.4R3.15

Platform: juniper_vsrx. Image: vSRX3 21.4R3.15. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/juniper_junos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `show configuration system authentication-order | display set`: set system authentication-order tacplus
- `show interfaces terse | match fxp0`: fxp0 up up fxp0.0 up up inet 10.0.0.15/24

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 6.528s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +7s |
| b | PASS | break-glass login with port49d stopped: ok true in 20ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +7s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 6s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +7s took 200ms: logged in, `show version` printed "'Hostname: srx1'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 160ms, `show version` output "'Hostname: srx1'" |
| e | PASS | login with a one-time credential (login attempt 1, 2s after the first) no error: 0 command authorizations permitted, 0 denied by port49; accounting START 2, STOP 4; judged on the device output: Junos authorizes a command by the login class and asks port49 for none; command output: [0] Model: vSRX Junos: 21.4R3.15 JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214] JUNOS OS libs [20220817.43c4e23_builder_stable_12_214] JUNOS OS... [1] error: unknown command: clear  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 160ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 0s; first command output:  |
| g | OBSERVED | single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: printed its output in 100ms (the reset's packet: `type=acct`); second `show version`, same session: printed its output in 100ms; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.05s; break-glass login plus three `show version`: logged in and ran them in 450ms |
| i | MEASURED | the largest `idle-timeout` the commit accepts is 4294967295 (the next value up was refused: set system login class l88i idle-timeout 4294967296 ^ Value 4294967296 is not within range (0..4294967295) at '4294967296' [edit] breakglass@srx1#) |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
  event=account verdict= reason= flags=start user=root port=non-tty
  event=account verdict= reason= flags=stop user=root port=non-tty
  event=account verdict= reason= flags=stop user=root port=non-tty
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
+0s 172.100.100.1 sport 33464: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 46276: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 46292: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: vsrx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 01:19:51.171Z; port49d applied the reload, saying `port49d: policy reloaded`, between 01:19:52.789Z and 01:19:52.814Z, and the change instant the capture is read against is 01:19:52.789Z; the command in flight was sent at 01:19:52.814Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | printed its output in 100ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 100ms |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.05s |
| break-glass login plus three `show version` | logged in and ran them in 450ms |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated reason=device_unknown <LONG> device=vsrx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 55558 | 01:19:44.038Z | true | (not observed) | (not observed) | not reset by port49d |
| 55574 | 01:19:44.542Z | true | (not observed) | (not observed) | not reset by port49d |
| 55576 | 01:19:44.822Z | true | 01:19:54.829Z | 01:19:54.830Z | **reset mid-connection**: open across the change |
| 58226 | 01:19:50.562Z | true | (not observed) | (not observed) | not reset by port49d |
| 40982 | 01:19:54.830Z | false | (not observed) | 01:19:54.830Z | reset before the device sent on it (refused at Accept) |
| 58236 | 01:19:54.830Z | false | 01:19:54.831Z | 01:19:54.831Z | reset at its first packet after the change |
| 40988 | 01:19:54.831Z | false | (not observed) | 01:19:54.831Z | reset before the device sent on it (refused at Accept) |
| 58248 | 01:19:54.831Z | false | (not observed) | 01:19:54.831Z | reset before the device sent on it (refused at Accept) |
| 40996 | 01:19:54.831Z | false | (not observed) | 01:19:54.831Z | reset before the device sent on it (refused at Accept) |
| 58258 | 01:19:54.831Z | false | 01:19:54.831Z | 01:19:54.831Z | reset at its first packet after the change |
| 41008 | 01:19:54.831Z | false | (not observed) | 01:19:54.831Z | reset before the device sent on it (refused at Accept) |
| 58274 | 01:19:54.831Z | false | 01:19:54.831Z | 01:19:54.831Z | reset at its first packet after the change |
| 41012 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 58282 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 41028 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 58296 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 41044 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 58300 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 41046 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 58312 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 41056 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 58324 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 41060 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 58332 | 01:19:54.832Z | false | (not observed) | 01:19:54.832Z | reset before the device sent on it (refused at Accept) |
| 41066 | 01:19:54.833Z | false | (not observed) | 01:19:54.833Z | reset before the device sent on it (refused at Accept) |
| 58334 | 01:19:54.833Z | false | (not observed) | 01:19:54.833Z | reset before the device sent on it (refused at Accept) |
| 53846 | 01:20:03.063Z | false | 01:20:03.063Z | 01:20:03.063Z | reset at its first packet after the change |
| 43578 | 01:20:03.063Z | false | (not observed) | 01:20:03.063Z | reset before the device sent on it (refused at Accept) |
| 53848 | 01:20:03.063Z | false | 01:20:03.063Z | 01:20:03.063Z | reset |
| 53856 | 01:20:03.081Z | false | (not observed) | 01:20:03.081Z | reset before the device sent on it (refused at Accept) |
| 43592 | 01:20:03.081Z | false | (not observed) | 01:20:03.081Z | reset before the device sent on it (refused at Accept) |
| 53858 | 01:20:03.081Z | false | (not observed) | 01:20:03.081Z | reset before the device sent on it (refused at Accept) |
| 51888 | 01:20:08.116Z | false | 01:20:08.116Z | 01:20:08.116Z | reset at its first packet after the change |
| 33144 | 01:20:08.117Z | false | (not observed) | 01:20:08.117Z | reset before the device sent on it (refused at Accept) |
| 51896 | 01:20:08.117Z | false | 01:20:08.117Z | 01:20:08.117Z | reset at its first packet after the change |
| 33148 | 01:20:09.840Z | false | (not observed) | 01:20:09.840Z | reset before the device sent on it (refused at Accept) |
| 51900 | 01:20:09.841Z | false | 01:20:09.841Z | 01:20:09.841Z | reset at its first packet after the change |
| 33158 | 01:20:09.841Z | false | (not observed) | 01:20:09.841Z | reset before the device sent on it (refused at Accept) |
| 51916 | 01:20:09.842Z | false | 01:20:09.842Z | 01:20:09.842Z | reset |
| 33172 | 01:20:09.842Z | false | (not observed) | 01:20:09.842Z | reset before the device sent on it (refused at Accept) |
| … | 31 more connection(s) not listed | | | | |

The change began at 01:19:52.789Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 618 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
