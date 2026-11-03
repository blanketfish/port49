# L88: the reference AAA configuration on Catalyst 8000V 17.13.01a

Platform: cisco_iosxe. Image: Catalyst 8000V 17.13.01a. Transport: tcp. Measured 2026-11-03 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local password): logged in true (no error). With port49d answering: logged in false after 5.523s (); port49 decision for the attempt: verdict="deny" reason="token_not_found" |
| b | PASS | break-glass login with port49d stopped: ok true in 20ms (no error) |
| c | NOT MEASURED | the harness does not run cell c yet |
| d | NOT MEASURED | the harness does not run cell d yet |
| e | PASS | token login (login attempt 2, 55s after the first) no error: 2 command authorizations permitted, 1 denied; accounting START 1, STOP 2; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.com/techsupport Copyright (c) 1986-2023 by Cisco Systems, Inc. Compiled Wed 13-Dec-23 21:43 by mcpre Cisco IOS-XE software, Copyright (c) 2005-2023 by cisco Systems, Inc. All rights reserved. Certain components of Cisco IOS-XE software are licensed under the GNU General Public License... |
| f | PASS | token login with the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 770ms; connections the first server reset: 1; port49 redeemed the token: true; first command output:  |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=tty434
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=tty434
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=tty434
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=tty434
  event=account verdict= reason= flags=start user=alice01 port=tty434
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=tty434
  event=account verdict= reason= flags=stop user=alice01 port=tty434
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=tty434
  event=account verdict= reason= flags=stop user=alice01 port=tty434
  event=authorize_command verdict=deny reason=no_permit_dominates_deny flags= user=alice01 port=tty434
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=tty434
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=tty434
  event=account verdict= reason= flags=start user=alice02 port=tty434
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=tty434
  event=account verdict= reason= flags=stop user=alice02 port=tty434
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=tty434
  event=account verdict= reason= flags=stop user=alice02 port=tty434
```
