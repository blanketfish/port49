# L88: the reference AAA configuration on vSRX3 21.4R3.15

Platform: juniper_vsrx. Image: vSRX3 21.4R3.15. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/juniper_junos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `show configuration system authentication-order | display set`: set system authentication-order tacplus
- `show interfaces terse | match fxp0`: fxp0 up up fxp0.0 up up inet 10.0.0.15/24

Capture: `tests/lab/evidence/L88-f-juniper_vsrx.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 6.532s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +7s |
| b | PASS | break-glass login with port49d stopped: ok true in 20ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +7s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 6s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +7s took 200ms: logged in, `show version` printed "'Hostname: srx1'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 160ms, `show version` output "'Hostname: srx1'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 0 command authorizations permitted, 0 denied by port49; accounting START 2, STOP 4; judged on the device output: Junos authorizes a command by the login class and asks port49 for none; command output: [0] Model: vSRX Junos: 21.4R3.15 JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214] JUNOS OS libs [20220817.43c4e23_builder_stable_12_214] JUNOS OS... [1] error: unknown command: clear  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 160ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 0s; first command output:  |
| g | OBSERVED | single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: printed its output in 100ms (the reset's packet: `type=acct`); second `show version`, same session: printed its output in 100ms; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.06s; break-glass login plus three `show version`: logged in and ran them in 440ms |
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
  event=account verdict= reason= flags=start user=alice01 port=non-tty
  event=account verdict= reason= flags=stop user=alice01 port=non-tty
  event=account verdict= reason= flags=stop user=alice01 port=non-tty
  event=account verdict= reason= flags=stop user=alice01 port=non-tty
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=
the wire during the login (headers only):
3 connections from the device in the window: 3 with a SYN, 3 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 43826: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 43760: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 43764: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: vsrx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 08:02:27.431Z; port49d applied the reload, saying `port49d: policy reloaded`, between 08:02:29.051Z and 08:02:29.077Z, and the change instant the capture is read against is 08:02:29.051Z; the command in flight was sent at 08:02:29.077Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | printed its output in 100ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 100ms |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.06s |
| break-glass login plus three `show version` | logged in and ran them in 440ms |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated reason=device_unknown <LONG> device=vsrx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 48068 | 08:02:20.295Z | true | (not observed) | (not observed) | not reset by port49d |
| 48074 | 08:02:20.798Z | true | (not observed) | (not observed) | not reset by port49d |
| 48084 | 08:02:20.981Z | true | 08:02:30.987Z | 08:02:30.988Z | **reset mid-connection**: open across the change |
| 39556 | 08:02:26.821Z | true | (not observed) | (not observed) | not reset by port49d |
| 36270 | 08:02:30.988Z | false | (not observed) | 08:02:30.988Z | reset before the device sent on it (refused at Accept) |
| 39570 | 08:02:30.988Z | false | 08:02:30.988Z | 08:02:30.989Z | reset at its first packet after the change |
| 36272 | 08:02:30.989Z | false | (not observed) | 08:02:30.989Z | reset before the device sent on it (refused at Accept) |
| 39578 | 08:02:30.989Z | false | 08:02:30.989Z | 08:02:30.989Z | reset at its first packet after the change |
| 36274 | 08:02:30.989Z | false | (not observed) | 08:02:30.989Z | reset before the device sent on it (refused at Accept) |
| 39594 | 08:02:30.989Z | false | (not observed) | 08:02:30.989Z | reset before the device sent on it (refused at Accept) |
| 36280 | 08:02:30.989Z | false | (not observed) | 08:02:30.989Z | reset before the device sent on it (refused at Accept) |
| 39602 | 08:02:30.989Z | false | (not observed) | 08:02:30.989Z | reset before the device sent on it (refused at Accept) |
| 36286 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 39612 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 36296 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 39620 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 36298 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 39630 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 36308 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 39640 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 36312 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 39652 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 36318 | 08:02:30.990Z | false | (not observed) | 08:02:30.990Z | reset before the device sent on it (refused at Accept) |
| 39664 | 08:02:30.991Z | false | (not observed) | 08:02:30.991Z | reset before the device sent on it (refused at Accept) |
| 36326 | 08:02:30.991Z | false | (not observed) | 08:02:30.991Z | reset before the device sent on it (refused at Accept) |
| 39668 | 08:02:30.991Z | false | (not observed) | 08:02:30.991Z | reset before the device sent on it (refused at Accept) |
| 49438 | 08:02:39.326Z | false | 08:02:39.326Z | 08:02:39.326Z | reset at its first packet after the change |
| 52566 | 08:02:39.326Z | false | (not observed) | 08:02:39.326Z | reset before the device sent on it (refused at Accept) |
| 49444 | 08:02:39.326Z | false | 08:02:39.326Z | 08:02:39.326Z | reset at its first packet after the change |
| 49448 | 08:02:39.348Z | false | 08:02:39.348Z | 08:02:39.348Z | reset at its first packet after the change |
| 52576 | 08:02:39.348Z | false | (not observed) | 08:02:39.348Z | reset before the device sent on it (refused at Accept) |
| 49452 | 08:02:39.348Z | false | 08:02:39.348Z | 08:02:39.348Z | reset at its first packet after the change |
| 49464 | 08:02:44.387Z | false | 08:02:44.388Z | 08:02:44.388Z | reset at its first packet after the change |
| 52580 | 08:02:44.388Z | false | (not observed) | 08:02:44.388Z | reset before the device sent on it (refused at Accept) |
| 49478 | 08:02:44.388Z | false | 08:02:44.388Z | 08:02:44.388Z | reset at its first packet after the change |
| 52588 | 08:02:45.995Z | false | (not observed) | 08:02:45.995Z | reset before the device sent on it (refused at Accept) |
| 49492 | 08:02:45.995Z | false | 08:02:45.996Z | 08:02:45.996Z | reset at its first packet after the change |
| 52598 | 08:02:45.996Z | false | (not observed) | 08:02:45.996Z | reset before the device sent on it (refused at Accept) |
| 49498 | 08:02:45.996Z | false | (not observed) | 08:02:45.996Z | reset before the device sent on it (refused at Accept) |
| 52608 | 08:02:45.997Z | false | (not observed) | 08:02:45.997Z | reset before the device sent on it (refused at Accept) |
| … | 31 more connection(s) not listed | | | | |

The change began at 08:02:29.051Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L88-g-rekeyed-juniper_vsrx.pcap` — 610 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L88-g-rekeyed-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
