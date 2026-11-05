# L88: the reference AAA configuration on Nexus 9300v 10.6(2)F

Platform: cisco_nxos. Image: Nexus 9300v 10.6(2)F. Transport: tls. Measured 2026-11-04 by TestL88.

- cells run over RFC 9887: a, b, d, e, f. c, g, i: not transport-dependent, measured on the plain pass (L88-cisco_nxos-nxos106.md)
- port49d's server certificate carries both server addresses (172.100.100.1, 172.100.100.2) as IP names, because cell f has the device dial the second one; with the first alone, a device that checks the dialled address would refuse the second server for the certificate, not for failover
- RFC 9887 enrolment by L73's machinery (its own PKI; the device's key and certificate id `l73-dev`, the root trusted as `port49-root`); port49d's tls_listener on 172.100.100.1:300. The reference TLS file was then applied over it unchanged.
- the reference loaded: `deploy/device-aaa/cisco_nxos` (tls), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-tls-nxos106-cisco_nxos.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 6.7s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +7s |
| b | PASS | break-glass login with port49d stopped: ok true in 6.7s (no error) |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 1.15s, `show version` output "'Cisco Nexus Operating System (NX-OS) Software'" |
| e | PASS | login with a one-time credential (login attempt 1, 6s after the first) no error: 3 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 1; port49 authorized one command and denied the other; command output: [0] TAC support: http://www.cisco.com/tac Documents: http://www.cisco.com/en/US/products/ps9372/tsd_products_support_series_home.html Copyright (c) 2002-2025, Cisco... [1] Cmd exec error.  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 6.23s; connections the first server reset: 5; port49 redeemed the credential: true; tries 1, the login reached port49 after 6s; first command output:  |

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
  event=account verdict= reason= flags=start user=alice02 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
the wire during the login (headers only):
6 connections from the device in the window: 6 with a SYN, 6 answered SYN-ACK, 5 with an RST
+100ms 172.100.100.1 sport 46782: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.2 sport 60110: SYN true SYN-ACK true; device packets 38, server packets 22; FIN dev false srv false; RST dev false srv false
+5.4s 172.100.100.1 sport 48256: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+5.4s 172.100.100.1 sport 48264: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+6.2s 172.100.100.1 sport 48266: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+6.2s 172.100.100.1 sport 48274: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true

```
