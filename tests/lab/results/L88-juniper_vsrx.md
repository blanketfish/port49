# L88: the reference AAA configuration on vSRX3 21.4R3.15

Platform: juniper_vsrx. Image: vSRX3 21.4R3.15. Transport: tcp. Measured 2026-11-03 by TestL88.

- the reference loaded: `deploy/device-aaa/juniper_junos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `show configuration system authentication-order | display set`: set system authentication-order tacplus
- `show interfaces terse | match fxp0`: fxp0 up up fxp0.0 up up inet 10.0.0.15/24

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local password): logged in true (no error). With port49d answering: logged in false after 6.531s (); port49 decision for the attempt: verdict="deny" reason="token_not_found" |
| b | PASS | break-glass login with port49d stopped: ok true in 20ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +7s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 6s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +7s took 200ms: logged in, `show version` printed "'Hostname: srx1'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 160ms, `show version` output "'Hostname: srx1'" |
| e | PASS | token login (login attempt 1, 2s after the first) no error: 0 command authorizations permitted, 0 denied by port49; accounting START 2, STOP 4; judged on the device output: Junos authorizes a command by the login class and asks port49 for none; command output: [0] Model: vSRX Junos: 21.4R3.15 JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214] JUNOS OS libs [20220817.43c4e23_builder_stable_12_214] JUNOS OS... [1] error: unknown command: clear  |
| f | PASS | token login with the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 160ms; connections the first server reset: 1; port49 redeemed the token: true; first command output:  |
| g | NOT MEASURED | the harness does not run cell g yet |
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
```
