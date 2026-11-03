# L88: the reference AAA configuration on Nexus 9300v 10.4(2)F

Platform: cisco_nxos. Image: Nexus 9300v 10.4(2)F. Transport: tcp. Measured 2026-11-03 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_nxos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local password): logged in true (no error). With port49d answering: logged in false after 1.971s (); port49 decision for the attempt: verdict="deny" reason="token_not_found" |
| b | PASS | break-glass login with port49d stopped: ok true in 140ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held), break-glass login no error in 2.25s, `show version` output "'Error: AAA authorization failed <LONG>(0x10)'"; port49d records: authorize_session [], authorize_command [deny store_unavailable deny store_unavailable], accounting []; port49d's log shows no listener closing during the login |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 1.08s, `show version` output "'Cisco Nexus Operating System (NX-OS) Software'" |
| e | PASS | token login (login attempt 1, 1s after the first) no error: 3 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 1; port49 authorized one command and denied the other; command output: [0] TAC support: http://www.cisco.com/tac Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html Copyright (c) 2002-2023, Cisco... [1] Cmd exec error.  |
| f | PASS | token login with the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 1.29s; connections the first server reset: 5; port49 redeemed the token: true; first command output:  |

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
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=account verdict= reason= flags=start user=alice02 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=account verdict= reason= flags=stop user=alice02 port=0
```
