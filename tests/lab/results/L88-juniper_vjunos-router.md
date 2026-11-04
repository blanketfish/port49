# L88: the reference AAA configuration on vJunos-router 23.4R2-S2.1

Platform: juniper_vjunos-router. Image: vJunos-router 23.4R2-S2.1. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/juniper_junos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `show configuration system authentication-order | display set`: set system authentication-order tacplus
- `show interfaces terse | match fxp0`: fxp0 up up fxp0.0 up up inet 10.0.0.15/24

Capture: `tests/lab/evidence/L88-f-juniper_vjunos-router.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 6.539s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +7s |
| b | PASS | break-glass login with port49d stopped: ok true in 30ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +7s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 6s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +7s took 200ms: logged in, `show version` printed "'Hostname: srx1'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 180ms, `show version` output "'Hostname: srx1'" |
| e | PASS | login with a one-time credential (login attempt 1, 2s after the first) no error: 0 command authorizations permitted, 0 denied by port49; accounting START 2, STOP 4; judged on the device output: Junos authorizes a command by the login class and asks port49 for none; command output: [0] Model: vmx Junos: 23.4R2-S2.1 JUNOS OS Kernel 64-bit [20240604.39c9257_builder_stable_12_234] JUNOS OS libs [20240604.39c9257_builder_stable_12_234] JUNOS OS ru... [1] error: unknown command: clear  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 180ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 0s; first command output:  |
| i | MEASURED | the largest `idle-timeout` the commit accepts is 4294967295 (the next value up was refused: set system login class l88i idle-timeout 4294967296 ^ Value 4294967296 is not within range (0..4294967295) at '4294967296' [edit] breakglass@srx1#) |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=start user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=account verdict= reason= flags=stop user=breakglass port=0
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
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
+0s 172.100.100.1 sport 57630: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 33084: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 33096: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```
