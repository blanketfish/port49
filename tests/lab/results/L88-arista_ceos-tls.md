# L88: the reference AAA configuration on cEOS-lab 4.36.3M

Platform: arista_ceos. Image: cEOS-lab 4.36.3M. Transport: tls. Measured 2026-11-04 by TestL88.

- cells run over RFC 9887: a, b, d, e, f. c, g, i: not transport-dependent, measured on the plain pass (L88-arista_ceos.md)
- port49d's server certificate carries both server addresses (172.100.100.1, 172.100.100.2) as IP names, because cell f has the device dial the second one; with the first alone, a device that checks the dialled address would refuse the second server for the certificate, not for failover
- RFC 9887 enrolment by L73's machinery (its own PKI; the device's key and certificate id `l73-dev`, the root trusted as `port49-root`); port49d's tls_listener on 172.100.100.1:300. The reference TLS file was then applied over it unchanged.
- the reference loaded: `deploy/device-aaa/arista_eos` (tls), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 832ms (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +1s |
| b | PASS | break-glass login with port49d stopped: ok true in 1.83s (no error) |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 2s, `show version` output "'Arista cEOSLab'" |
| e | PASS | login with a one-time credential (login attempt 1, 2s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 1; port49 authorized one command and denied the other; command output: [0] Hardware version: Serial number: 1CBEA85094F628AABFCF3B015A90F05D Hardware MAC address: 001c.73b7.3c2d System MAC address: 001c.73b7.3c2d Software image version... [1] > show clock % Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain' at line 1  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 2.41s; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 2s; first command output:  |

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
0 connections from the device in the window: 0 with a SYN, 0 answered SYN-ACK, 0 with an RST

```
