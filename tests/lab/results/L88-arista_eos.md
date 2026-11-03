# L88: the reference AAA configuration on vEOS-lab 4.31.2F (image tagged 4.32.2F)

Platform: arista_eos. Image: vEOS-lab 4.31.2F (image tagged 4.32.2F). Transport: tcp. Measured 2026-11-03 by TestL88.

- the reference loaded: `deploy/device-aaa/arista_eos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local password): logged in true (no error). With port49d answering: logged in false after 529ms (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain); port49 decision for the attempt: verdict="deny" reason="token_not_found" |
| b | PASS | break-glass login with port49d stopped: ok true in 40ms (no error) |
| c | NOT MEASURED | the harness does not run cell c yet |
| d | NOT MEASURED | the harness does not run cell d yet |
| e | PASS | token login no error: 1 command authorizations permitted, 1 denied; accounting START 1, STOP 1; command output: [0] Hardware version: Serial number: Hardware MAC address: 0c00.f7b1.4578 System MAC address: 0c00.f7b1.4578 Software image version: 4.31.2F Architecture: x86_64 Internal build version: 4.31.2F-35442176.4312F Internal build ID: 48bb2b78-5325-4a32-b124-dcd4e37fd3bc Image format version: 1.0 Image optimization: None Uptime: 1 minute Total memory: 1979668 kB Free memory: 619312 kB [1] > show clock % Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); ... |
| f | PASS | token login with the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 290ms; connections the first server reset: 1; port49 redeemed the token: true; first command output:  |

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
```
