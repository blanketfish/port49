# L88: the reference AAA configuration on Nexus 9300v 10.4(2)F

Platform: cisco_nxos. Image: Nexus 9300v 10.4(2)F. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_nxos` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-cisco_nxos.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 1.784s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +2s |
| b | PASS | break-glass login with port49d stopped: ok true in 160ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [deny store_unavailable deny store_unavailable], accounting []; tries: try at +0s took 2.1s: logged in, `show version` printed "'Error: AAA authorization failed <LONG>(0x10)'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 1.08s, `show version` output "'Cisco Nexus Operating System (NX-OS) Software'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 3 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] TAC support: http://www.cisco.com/tac Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html Copyright (c) 2002-2023, Cisco... [1] Cmd exec error.  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 1.11s; connections the first server reset: 5; port49 redeemed the credential: true; tries 1, the login reached port49 after 1s; first command output:  |

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
  event=account verdict= reason= flags=stop user=alice01 port=0
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=0
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=account verdict= reason= flags=start user=alice02 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=account verdict= reason= flags=stop user=alice02 port=0
the wire during the login (headers only):
11 connections from the device in the window: 11 with a SYN, 11 answered SYN-ACK, 5 with an RST
+100ms 172.100.100.1 sport 51002: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+100ms 172.100.100.2 sport 56124: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+100ms 172.100.100.2 sport 56126: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.1 sport 51004: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+300ms 172.100.100.1 sport 51014: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+300ms 172.100.100.2 sport 56138: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.2 sport 56146: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+1.1s 172.100.100.1 sport 51022: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+1.1s 172.100.100.2 sport 56150: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+1.1s 172.100.100.1 sport 51024: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+1.1s 172.100.100.2 sport 56156: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

```
