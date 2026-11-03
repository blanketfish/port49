# L88: the reference AAA configuration on Catalyst 8000V 17.13.01a

Platform: cisco_iosxe. Image: Catalyst 8000V 17.13.01a. Transport: tcp. Measured 2026-11-03 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 5.526s (); port49 decision for the attempt: verdict="deny" reason="token_not_found" |
| b | PASS | break-glass login with port49d stopped: ok true in 30ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +6s; port49d's own close line appeared at +4.8s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 5s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +6s took 800ms: logged in, `show version` printed "'Cisco IOS XE Software, Version 17.13.01a'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 780ms, `show version` output "'Cisco IOS XE Software, Version 17.13.01a'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 2 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 2; port49 authorized one command and denied the other; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.... [1]   |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 2.77s; connections the first server reset: 2; port49 redeemed the credential: true; first command output:  |
| f2 | MEASURED | the first one-time-credential login that port49 answered came at +30s after port49d was back; the session was still open when the loop began and was closed at +0s; a break-glass login first succeeded at +0s |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=tty434
  event=account verdict= reason= flags=stop user=yang_mgmt_infra port=
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=tty434
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=tty435
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=tty435
  event=account verdict= reason= flags=start user=alice01 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=tty435
  event=account verdict= reason= flags=stop user=alice01 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=tty435
  event=account verdict= reason= flags=stop user=alice01 port=tty435
  event=authorize_command verdict=deny reason=no_permit_dominates_deny flags= user=alice01 port=tty435
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
`terminal length 0` after f:
terminal length 0
xe1#
`show tacacs` after f:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        235
             Socket closes:        235
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         33
        Total Packets Sent:         35
        Total Packets Recv:         34
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 49
              Socket opens:        219
             Socket closes:        219
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         32
        Total Packets Sent:          9
        Total Packets Recv:          8
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show tcp brief` after f:
show tcp brief
TCB       Local Address               Foreign Address             (state)
73678C02C570  10.0.0.15.40072            172.100.100.1.49            TIMEWAIT
73678C02D7A0  10.0.0.15.28306            172.100.100.2.49            CLOSING
73678BFDAEB0  10.0.0.15.22               172.100.100.1.33126         ESTAB
736792099B90  10.0.0.15.39671            172.100.100.2.49            CLOSING
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS` after f:
show processes | include TACACS
 374 Mwe 5A080173CFE5             0         11       0  21120/24000  0 TACACS+         
xe1#

```

### Cell f2 evidence

```
break-glass session ran 5 commands with port49d stopped; port49d was then started again as a new process (same config, same address) and the session stayed open for 60 s
+0s: one-time-credential login: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; break-glass login: no error
+15s: one-time-credential login: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; break-glass login: no error
+30s: one-time-credential login: no error; break-glass login: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain

port49d's own view of the window: 627 decision records; its stderr lines: port49d: <LONG> is 0s: no context ever goes context_stale, so a context the broker stopped refreshing keeps its last answer until its own session ends / port49d: at most 523264 TACACS+ connections at once (the open-file limit 524288, less what the spool, the store and the logs keep); past it each new connection is reset at Accept / port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 7 devices admitted / port49d: signal received, draining / port49d: accounting spool drained, exiting / port49d: LAB MODE: port49d.yaml has a lab: block, which enables 304 seed token(s) minted to <LONG>; the lab fallback authorizer, which answers a context with no blob from the lab's fixed attributes and deny prefixes instead of denying it; a lab: block must never be in production / port49d: metrics on 127.0.0.1:9049 / port49d lab: 304 login token(s) and 0 enable token(s) minted, credentials written to <LONG> / port49d: <LONG> is 0s: no context ever goes context_stale, so a context the broker stopped refreshing keeps its last answer until its own session ends / port49d: at most 523264 TACACS+ connections at once (the open-file limit 524288, less what the spool, the store and the logs keep); past it each new connection is reset at Accept / port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 7 devices admitted / 

  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=account verdict= reason= flags=start user=breakglass port=tty436
  event=authorize_command verdict=deny reason=context_missing flags= user=breakglass port=tty436
  event=authorize_command verdict=deny reason=context_missing flags= user=breakglass port=tty436
  event=account verdict= reason= flags=stop user=breakglass port=tty436
  event=account verdict= reason= flags=start user=breakglass port=tty436
  event=authorize_command verdict=deny reason=context_missing flags= user=breakglass port=tty436
  event=authorize_command verdict=deny reason=context_missing flags= user=breakglass port=tty436
  event=account verdict= reason= flags=stop user=breakglass port=tty436
  event=redeem verdict=permit reason=token_redeemed flags= user=alice03 port=tty435
  event=authorize_session verdict=permit reason=context_matched flags= user=alice03 port=tty435
  event=account verdict= reason= flags=start user=alice03 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice03 port=tty435
  event=account verdict= reason= flags=stop user=alice03 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice03 port=tty435
  event=account verdict= reason= flags=stop user=alice03 port=tty435
  event=account verdict= reason= flags=stop user=alice03 port=tty435
  event=redeem verdict=deny reason=token_not_found flags= user=breakglass port=tty436
  event=redeem verdict=deny reason=token_not_found flags= user=breakglass port=tty436
  event=account verdict= reason= flags=stop user=breakglass port=tty434
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
  event=mint verdict=permit reason=grants_matched flags=
`ss -tn` on port 49 before port49d restarted:
State     Recv-Q Send-Q Local Address:Port    Peer Address:Port 
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41724
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57024
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50932
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41696
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50934
TIME-WAIT 0      0      172.100.100.1:37082  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:37118  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41648
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41680
TIME-WAIT 0      0      172.100.100.1:58054  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:58082  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41682
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57032
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41704
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41712
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50956
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41672
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41732
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:32884
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:32880
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50950
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41660
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:32888
TIME-WAIT 0      0      172.100.100.1:48644  172.100.100.2:49   

mid-window:

after:
State     Recv-Q Send-Q Local Address:Port    Peer Address:Port 
LISTEN    0      4096   172.100.100.1:49           0.0.0.0:*    
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41724
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:50228
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57024
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35564
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35556
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50932
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35566
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41696
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50934
TIME-WAIT 0      0      172.100.100.1:37082  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:37118  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41648
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41680
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35500
TIME-WAIT 0      0      172.100.100.1:58054  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:58082  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:58102  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35532
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41682
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57032
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35544
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35518
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41704
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41786
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41712
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50956
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35504
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41672
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:50222
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:36236
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41732
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:50218
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:32884
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:32880
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:50950
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41660
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35528
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:36250
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:32888
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:36244
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:50208
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:36228
TIME-WAIT 0      0      172.100.100.1:48644  172.100.100.2:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35536

the wire (headers only):
18 connections from the device in the window: 18 with a SYN, 18 answered SYN-ACK, 0 with an RST
+4s 172.100.100.1 sport 36228: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+4.3s 172.100.100.1 sport 36236: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.5s 172.100.100.1 sport 36244: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.8s 172.100.100.1 sport 36250: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+18.9s 172.100.100.1 sport 50208: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+19.1s 172.100.100.1 sport 50218: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.4s 172.100.100.1 sport 50222: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.6s 172.100.100.1 sport 50228: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 35500: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 35504: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 35518: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.9s 172.100.100.1 sport 35528: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.1s 172.100.100.1 sport 35532: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.2s 172.100.100.1 sport 35536: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 35544: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.5s 172.100.100.1 sport 35556: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.5s 172.100.100.1 sport 35564: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false
+33s 172.100.100.1 sport 35566: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
xe1#
`show tacacs`:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        328
             Socket closes:        328
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         46
        Total Packets Sent:         57
        Total Packets Recv:         56
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 49
              Socket opens:        293
             Socket closes:        293
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         45
        Total Packets Sent:          9
        Total Packets Recv:          8
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show tcp brief`:
show tcp brief
TCB       Local Address               Foreign Address             (state)
73678C02C570  10.0.0.15.40072            172.100.100.1.49            TIMEWAIT
73678BFDAEB0  10.0.0.15.22               172.100.100.1.55490         ESTAB
73678C02D7A0  10.0.0.15.28306            172.100.100.2.49            TIMEWAIT
736792099B90  10.0.0.15.39671            172.100.100.2.49            TIMEWAIT
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS`:
show processes | include TACACS
 374 Mwe 5A080173CFE5             1         23      43  21120/24000  0 TACACS+         
xe1#
`show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next`:
show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next
991: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:20.992: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:09:20.994: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:20.994: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:20.995: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:20.996: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:20.997: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:20.998: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:20.999: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:21.000: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.239: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:21.240: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:09:21.242: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:21.243: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.244: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:21.245: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.246: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:21.247: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.248: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:21.249: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.495: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:21.496: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:09:21.505: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:21.506: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.506: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:21.507: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.508: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:21.509: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:21.510: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:21.511: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:23.026: TPLUS: Authentication start packet created for 4037(alice03)
*Nov  3 23:09:25.027: TPLUS: Authentication start packet created for 4037(alice03)
*Nov  3 23:09:27.028:  Socket I/O cleanup message sent to TACACS
*Nov  3 23:09:27.039: TPLUS: Authentication start packet created for 4038(breakglass)
*Nov  3 23:09:27.050: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:27.307: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:27.557: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:27.804:  Socket I/O cleanup message sent to TACACS
*Nov  3 23:09:37.863: TPLUS: Authentication start packet created for 4039(alice03)
*Nov  3 23:09:39.864: TPLUS: Authentication start packet created for 4039(alice03)
*Nov  3 23:09:41.866:  Socket I/O cleanup message sent to TACACS
*Nov  3 23:09:41.876: TPLUS: Authentication start packet created for 4040(breakglass)
*Nov  3 23:09:41.887: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:42.141: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:42.402: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:42.642:  Socket I/O cleanup message sent to TACACS
*Nov  3 23:09:52.700: TPLUS: Authentication start packet created for 4041(alice03)
*Nov  3 23:09:52.700: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:52.960: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:53.208: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:53.487:  Socket I/O cleanup message sent to TACACS
*Nov  3 23:09:53.494: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  3 23:09:53.494: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:55.998: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  3 23:09:55.998: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:59.004:  Socket I/O cleanup message sent to TACACS
*Nov  3 23:09:59.004: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:59.007:  Socket I/O cleanup message sent to TACACS
*Nov  3 23:09:59.230: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.230: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:59.231: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.231: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.232: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.232: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.233: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.233: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.234: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.234: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.235: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.235: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.236: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.236: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.237: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.237: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.238: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  3 23:09:59.248: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:59.249: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.250: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.251: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.252: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.253: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.254: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.255: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.256: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:59.257: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.258: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.259: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.260: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.261: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.262: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.263: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.264: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.265: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.266: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.267: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.506: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:59.507: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:09:59.508: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:59.509: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.510: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.511: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.512: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.513: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.514: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.515: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.756: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:09:59.757: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:09:59.758: TPLUS: Using server 172.100.100.1
*Nov  3 23:09:59.759: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.760: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.761: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.762: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.763: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:09:59.764: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:09:59.765: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.006: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:10:00.008: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:10:00.009: TPLUS: Using server 172.100.100.1
*Nov  3 23:10:00.011: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.012: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.013: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.014: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.015: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.016: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.017: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.261: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:10:00.262: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:10:00.267: TPLUS: Using server 172.100.100.1
*Nov  3 23:10:00.268: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.269: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.270: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.271: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.272: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.273: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.274: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.511: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 23:10:00.512: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 23:10:00.521: TPLUS: Using server 172.100.100.1
*Nov  3 23:10:00.522: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.523: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.524: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.525: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.526: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.527: TPLUS: Choosing next server 172.100.100.1
*Nov  3 23:10:00.528: TPLUS: Choosing next server 172.100.100.2
*Nov  3 23:10:00.776: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
xe1#

```
