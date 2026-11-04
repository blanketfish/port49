# L88: the reference AAA configuration on vEOS-lab 4.31.2F (image tagged 4.32.2F)

Platform: arista_eos. Image: vEOS-lab 4.31.2F (image tagged 4.32.2F). Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/arista_eos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-arista_eos.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 532ms (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +1s |
| b | PASS | break-glass login with port49d stopped: ok true in 60ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [deny store_unavailable], authorize_command [], accounting []; tries: try at +0s took 1.1s: logged in, `show version` printed "'Authorization denied: port49: authorization store unavailable'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 150ms, `show version` output "'Arista vEOS-lab'" |
| e | PASS | login with a one-time credential (login attempt 1, 0s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 1; port49 authorized one command and denied the other; command output: [0] Hardware version: Serial number: Hardware MAC address: 0c00.5178.8d5f System MAC address: 0c00.5178.8d5f Software image version: 4.31.2F Architecture: x86_64 In... [1] > show clock % Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' at line 1  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 300ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 0s; first command output:  |

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
7 connections from the device in the window: 7 with a SYN, 7 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 36408: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 46530: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+200ms 172.100.100.2 sport 46546: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+200ms 172.100.100.2 sport 46560: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.2 sport 46568: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.2 sport 46584: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.2 sport 46592: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```
