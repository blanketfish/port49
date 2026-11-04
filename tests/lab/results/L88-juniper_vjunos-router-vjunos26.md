# L88: the reference AAA configuration on vJunos-router 26.2R1.7

Platform: juniper_vjunos-router. Image: vJunos-router 26.2R1.7. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/juniper_junos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `show configuration system authentication-order | display set`: set system authentication-order tacplus
- `show interfaces terse | match fxp0`: fxp0 up up fxp0.0 up up inet 10.0.0.15/24

Capture: `tests/lab/evidence/L88-f-vjunos26-juniper_vjunos-router.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 6.909s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +7s |
| b | PASS | break-glass login with port49d stopped: ok true in 40ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 1.1s: logged in, `show version` printed "'Hostname: srx1'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 190ms, `show version` output "'Hostname: srx1'" |
| e | PASS | login with a one-time credential (login attempt 1, 3s after the first) no error: 0 command authorizations permitted, 0 denied by port49; accounting START 2, STOP 4; judged on the device output: Junos authorizes a command by the login class and asks port49 for none; command output: [0] Model: vmx Family: junos Junos: 26.2R1.7 JUNOS OS Kernel 64-bit [20260518.25fe30f_builder_bsd15_262] JUNOS OS libs [20260518.25fe30f_builder_bsd15_262] JUNOS mo... [1] error: unknown command: clear  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 180ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 0s; first command output:  |
| g | OBSERVED | single-connection: on: `set system tacplus-server 172.100.100.1 single-connection`; on: `set system accounting destination tacplus server 172.100.100.1 single-connection`; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 200ms; first `show version` after the change, same session: printed its output in 200ms (the reset's packet: `type=acct`); second `show version`, same session: printed its output in 200ms; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s; break-glass login plus three `show version`: logged in and ran them in 470ms |
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
+0s 172.100.100.1 sport 44254: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 53682: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 53688: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: the first probe login reached port49 (7s).

The change: port49d's broker.policy_file given `- {match: {name: srx1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 08:18:05.865Z; port49d applied the reload, saying `port49d: policy reloaded`, between 08:18:06.905Z and 08:18:06.930Z, and the change instant the capture is read against is 08:18:06.905Z; the command in flight was sent at 08:18:06.930Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 200ms |
| first `show version` after the change, same session | printed its output in 200ms (the reset's packet: `type=acct`) |
| second `show version`, same session | printed its output in 200ms |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.07s |
| break-glass login plus three `show version` | logged in and ran them in 470ms |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated reason=device_unknown <LONG> device=srx1 type=acct` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=authen` ×2

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 57164 | 08:17:58.030Z | true | 08:18:08.091Z | 08:18:08.091Z | **reset mid-connection**: open across the change |
| 57172 | 08:17:58.171Z | true | (not observed) | (not observed) | not reset by port49d |
| 57180 | 08:17:59.093Z | true | (not observed) | (not observed) | not reset by port49d |
| 57188 | 08:18:05.145Z | true | (not observed) | (not observed) | not reset by port49d |
| 37036 | 08:18:08.093Z | false | (not observed) | 08:18:08.093Z | reset before the device sent on it (refused at Accept) |
| 56030 | 08:18:08.093Z | false | 08:18:08.094Z | 08:18:08.094Z | reset at its first packet after the change |
| 37042 | 08:18:08.094Z | false | (not observed) | 08:18:08.094Z | reset before the device sent on it (refused at Accept) |
| 56046 | 08:18:08.095Z | false | (not observed) | 08:18:08.095Z | reset before the device sent on it (refused at Accept) |
| 37048 | 08:18:08.096Z | false | (not observed) | 08:18:08.096Z | reset before the device sent on it (refused at Accept) |
| 56058 | 08:18:08.096Z | false | (not observed) | 08:18:08.096Z | reset before the device sent on it (refused at Accept) |
| 37064 | 08:18:08.098Z | false | (not observed) | 08:18:08.098Z | reset before the device sent on it (refused at Accept) |
| 56064 | 08:18:08.098Z | false | (not observed) | 08:18:08.098Z | reset before the device sent on it (refused at Accept) |
| 37074 | 08:18:08.099Z | false | (not observed) | 08:18:08.099Z | reset before the device sent on it (refused at Accept) |
| 56066 | 08:18:08.100Z | false | (not observed) | 08:18:08.100Z | reset before the device sent on it (refused at Accept) |
| 37076 | 08:18:08.101Z | false | (not observed) | 08:18:08.101Z | reset before the device sent on it (refused at Accept) |
| 56076 | 08:18:08.101Z | false | (not observed) | 08:18:08.101Z | reset before the device sent on it (refused at Accept) |
| 37078 | 08:18:08.102Z | false | (not observed) | 08:18:08.102Z | reset before the device sent on it (refused at Accept) |
| 56084 | 08:18:08.103Z | false | (not observed) | 08:18:08.103Z | reset before the device sent on it (refused at Accept) |
| 37088 | 08:18:08.103Z | false | (not observed) | 08:18:08.103Z | reset before the device sent on it (refused at Accept) |
| 56086 | 08:18:08.104Z | false | (not observed) | 08:18:08.104Z | reset before the device sent on it (refused at Accept) |
| 37096 | 08:18:08.104Z | false | (not observed) | 08:18:08.104Z | reset before the device sent on it (refused at Accept) |
| 56096 | 08:18:08.105Z | false | (not observed) | 08:18:08.105Z | reset before the device sent on it (refused at Accept) |
| 37102 | 08:18:08.106Z | false | (not observed) | 08:18:08.106Z | reset before the device sent on it (refused at Accept) |
| 56102 | 08:18:08.106Z | false | (not observed) | 08:18:08.106Z | reset before the device sent on it (refused at Accept) |
| 37108 | 08:18:08.107Z | false | (not observed) | 08:18:08.107Z | reset before the device sent on it (refused at Accept) |
| 56112 | 08:18:08.107Z | false | (not observed) | 08:18:08.107Z | reset before the device sent on it (refused at Accept) |
| 48604 | 08:18:17.399Z | false | 08:18:17.400Z | 08:18:17.400Z | reset at its first packet after the change |
| 45542 | 08:18:17.401Z | false | (not observed) | 08:18:17.401Z | reset before the device sent on it (refused at Accept) |
| 48610 | 08:18:17.402Z | false | (not observed) | 08:18:17.402Z | reset before the device sent on it (refused at Accept) |
| 48612 | 08:18:17.411Z | false | (not observed) | 08:18:17.411Z | reset before the device sent on it (refused at Accept) |
| 45550 | 08:18:17.412Z | false | (not observed) | 08:18:17.412Z | reset before the device sent on it (refused at Accept) |
| 48624 | 08:18:17.412Z | false | (not observed) | 08:18:17.413Z | reset before the device sent on it (refused at Accept) |
| 48632 | 08:18:22.464Z | false | 08:18:22.465Z | 08:18:22.465Z | reset at its first packet after the change |
| 45554 | 08:18:22.466Z | false | (not observed) | 08:18:22.466Z | reset before the device sent on it (refused at Accept) |
| 48644 | 08:18:22.466Z | false | (not observed) | 08:18:22.466Z | reset before the device sent on it (refused at Accept) |
| 45564 | 08:18:23.167Z | false | (not observed) | 08:18:23.167Z | reset before the device sent on it (refused at Accept) |
| 48658 | 08:18:23.168Z | false | 08:18:23.168Z | 08:18:23.168Z | reset at its first packet after the change |
| 45566 | 08:18:23.169Z | false | (not observed) | 08:18:23.169Z | reset before the device sent on it (refused at Accept) |
| 48668 | 08:18:23.169Z | false | (not observed) | 08:18:23.169Z | reset before the device sent on it (refused at Accept) |
| 45578 | 08:18:23.170Z | false | (not observed) | 08:18:23.170Z | reset before the device sent on it (refused at Accept) |
| … | 31 more connection(s) not listed | | | | |

The change began at 08:18:06.905Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L88-g-vjunos26-rekeyed-juniper_vjunos-router.pcap` — 579 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L88-g-vjunos26-rekeyed-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
