# L88: the reference AAA configuration on vJunos-router 26.2R1.7

Platform: juniper_vjunos-router. Image: vJunos-router 26.2R1.7. Transport: tls. Measured 2026-11-04 by TestL88.

- cells run over RFC 9887: a, b, d, e, f. c, g, i: not transport-dependent, measured on the plain pass (L88-juniper_vjunos-router-vjunos26.md)
- port49d's server certificate carries both server addresses (172.100.100.1, 172.100.100.2) as IP names, because cell f has the device dial the second one; with the first alone, a device that checks the dialled address would refuse the second server for the certificate, not for failover
- RFC 9887 enrolment by L73's machinery (its own PKI; the device's key and certificate id `l73-dev`, the root trusted as `port49-root`); port49d's tls_listener on 172.100.100.1:300. The reference TLS file was then applied over it unchanged.
- the reference loaded: `deploy/device-aaa/juniper_junos` (tls), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `show configuration system authentication-order | display set`: set system authentication-order tacplus
- `show interfaces terse | match fxp0`: fxp0 up up fxp0.0 up up inet 10.0.0.15/24

Capture: `tests/lab/evidence/L88-f-tls-vjunos26-juniper_vjunos-router.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 7.069s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +7s |
| b | PASS | break-glass login with port49d stopped: ok true in 40ms (no error) |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 190ms, `show version` output "'Hostname: srx1'" |
| e | PASS | login with a one-time credential (login attempt 1, 2s after the first) no error: 0 command authorizations permitted, 0 denied by port49; accounting START 2, STOP 4; judged on the device output: Junos authorizes a command by the login class and asks port49 for none; command output: [0] Model: vmx Family: junos Junos: 26.2R1.7 JUNOS OS Kernel 64-bit [20260518.25fe30f_builder_bsd15_262] JUNOS OS libs [20260518.25fe30f_builder_bsd15_262] JUNOS mo... [1] error: unknown command: clear  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 190ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 0s; first command output:  |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=
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
2 connections from the device in the window: 2 with a SYN, 2 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 41328: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 42406: SYN true SYN-ACK true; device packets 20, server packets 20; FIN dev true srv true; RST dev false srv false

```
