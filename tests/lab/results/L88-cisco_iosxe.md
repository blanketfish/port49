# L88: the reference AAA configuration on Catalyst 8000V 17.13.01a

Platform: cisco_iosxe. Image: Catalyst 8000V 17.13.01a. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 5.521s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +6s |
| b | PASS | break-glass login with port49d stopped: ok true in 20ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +6s; port49d's own close line appeared at +4.8s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 5s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +6s took 800ms: logged in, `show version` printed "'Cisco IOS XE Software, Version 17.13.01a'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 780ms, `show version` output "'Cisco IOS XE Software, Version 17.13.01a'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 2 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 2; port49 authorized one command and denied the other; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.... [1]   |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 770ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 1s; first command output:  |
| f2 | MEASURED | the first one-time-credential login that port49 answered came at +30s after port49d was back; the session was still open when the loop began and was closed at +0s; a break-glass login first succeeded at +0s |
| f3 | MEASURED | the first one-time-credential login that reached the second server came at +39s; the break-glass session was never closed in the loop |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=tty434
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
the wire during the login (headers only):
9 connections from the device in the window: 9 with a SYN, 9 answered SYN-ACK, 1 with an RST
+0s 172.100.100.1 sport 59122: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 36388: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 36402: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 36406: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.2 sport 36422: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+500ms 172.100.100.2 sport 36430: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+500ms 172.100.100.2 sport 36440: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+700ms 172.100.100.2 sport 36450: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+800ms 172.100.100.2 sport 36460: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0` after f:
terminal length 0
xe1#
`show tacacs` after f:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        234
             Socket closes:        234
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         33
        Total Packets Sent:         34
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
        Total Packets Recv:          9
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show tcp brief` after f:
show tcp brief
TCB       Local Address               Foreign Address             (state)
7FC89CBEFFD0  10.0.0.15.18875            172.100.100.1.49            TIMEWAIT
7FC89CB21158  10.0.0.15.22               172.100.100.1.60372         ESTAB
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS` after f:
show processes | include TACACS
 374 Mwe 64ADCD8F3FE5             1         11      90  21120/24000  0 TACACS+         
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
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:58978
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36440
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59016
TIME-WAIT 0      0      172.100.100.1:41390  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41424  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36402
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59042
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59068
TIME-WAIT 0      0      172.100.100.1:59326  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:59348  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59028
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36406
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36430
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59058
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36450
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57450
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59038
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59000
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36460
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57454
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59050
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36422
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36388
TIME-WAIT 0      0      172.100.100.1:47028  172.100.100.2:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:58988

mid-window:

after:
State     Recv-Q Send-Q Local Address:Port    Peer Address:Port 
LISTEN    0      4096   172.100.100.1:49           0.0.0.0:*    
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35088
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35082
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:48316
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:58978
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:56020
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36440
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59016
TIME-WAIT 0      0      172.100.100.1:41390  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41424  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36402
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55988
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59042
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:56038
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59068
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:56004
TIME-WAIT 0      0      172.100.100.1:59326  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:59348  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:59378  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59028
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55986
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36406
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36430
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59058
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36450
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57450
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35092
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55976
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59038
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:48284
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:45068
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59000
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:56050
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36460
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57454
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:56002
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:59050
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:48288
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36422
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:48300
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:36388
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55962
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:56022
TIME-WAIT 0      0      172.100.100.1:47028  172.100.100.2:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:58988
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:54612

the wire (headers only):
18 connections from the device in the window: 18 with a SYN, 18 answered SYN-ACK, 0 with an RST
+4.1s 172.100.100.1 sport 54612: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+4.3s 172.100.100.1 sport 35082: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.6s 172.100.100.1 sport 35088: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.8s 172.100.100.1 sport 35092: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+18.9s 172.100.100.1 sport 48284: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+19.2s 172.100.100.1 sport 48288: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.4s 172.100.100.1 sport 48300: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.7s 172.100.100.1 sport 48316: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 55962: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 55976: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 55986: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.9s 172.100.100.1 sport 55988: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.1s 172.100.100.1 sport 56002: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.2s 172.100.100.1 sport 56004: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 56020: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 56022: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 56038: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false
+32.9s 172.100.100.1 sport 56050: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
xe1#
`show tacacs`:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        327
             Socket closes:        327
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         46
        Total Packets Sent:         56
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
        Total Packets Recv:          9
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show tcp brief`:
show tcp brief
TCB       Local Address               Foreign Address             (state)
7FC89CB21158  10.0.0.15.22               172.100.100.1.56344         ESTAB
7FC89CBEFFD0  10.0.0.15.18875            172.100.100.1.49            TIMEWAIT
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS`:
show processes | include TACACS
 374 Mwe 64ADCD8F3FE5             2         23      86  21120/24000  0 TACACS+         
xe1#
`show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next`:
show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next
*Nov  4 00:18:00.514: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:00.515: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:00.516: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:00.517: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:00.518: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:00.519: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:00.520: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:00.521: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:00.522: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:00.760: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:00.761: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:00.763: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:00.764: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:00.765: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:00.766: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:00.767: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:00.768: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:00.769: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:00.770: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:01.014: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:01.015: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:01.024: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:01.025: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:01.026: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:01.027: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:01.028: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:01.029: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:01.030: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:01.031: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:02.542: TPLUS: Authentication start packet created for 4037(alice03)
*Nov  4 00:18:04.543: TPLUS: Authentication start packet created for 4037(alice03)
*Nov  4 00:18:06.576:  Socket I/O cleanup message sent to TACACS
*Nov  4 00:18:06.587: TPLUS: Authentication start packet created for 4038(breakglass)
*Nov  4 00:18:06.598: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:06.854: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:07.105: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:07.352:  Socket I/O cleanup message sent to TACACS
*Nov  4 00:18:17.408: TPLUS: Authentication start packet created for 4039(alice03)
*Nov  4 00:18:19.409: TPLUS: Authentication start packet created for 4039(alice03)
*Nov  4 00:18:21.410:  Socket I/O cleanup message sent to TACACS
*Nov  4 00:18:21.421: TPLUS: Authentication start packet created for 4040(breakglass)
*Nov  4 00:18:21.432: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:21.687: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:21.939: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:22.186:  Socket I/O cleanup message sent to TACACS
*Nov  4 00:18:32.206: TPLUS: Authentication start packet created for 4041(alice03)
*Nov  4 00:18:32.206: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:32.469: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:32.718: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:32.969:  Socket I/O cleanup message sent to TACACS
*Nov  4 00:18:32.976: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 00:18:32.976: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:35.480: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 00:18:35.480: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:38.485:  Socket I/O cleanup message sent to TACACS
*Nov  4 00:18:38.485: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:38.487:  Socket I/O cleanup message sent to TACACS
*Nov  4 00:18:38.810: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.810: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:38.811: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.812: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.812: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.812: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.813: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.813: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.814: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.814: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.815: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.815: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.816: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.816: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.817: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.817: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.818: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 00:18:38.829: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:38.830: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.831: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.831: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.833: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.834: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.835: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.836: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.837: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:38.838: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.838: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.840: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.841: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.841: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.842: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.844: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.845: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.846: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:38.847: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:38.848: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.086: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:39.086: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:39.088: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:39.089: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.089: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.091: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.092: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.093: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.094: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.095: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.336: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:39.337: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:39.338: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:39.339: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.340: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.341: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.342: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.342: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.344: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.345: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.589: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:39.590: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:39.591: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:39.593: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.594: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.594: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.596: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.597: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.598: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.599: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.839: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:39.841: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:39.844: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:39.845: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.846: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.847: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.848: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.849: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:39.850: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:39.851: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:40.114: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 00:18:40.115: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 00:18:40.123: TPLUS: Using server 172.100.100.1
*Nov  4 00:18:40.125: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:40.126: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:40.127: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:40.128: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:40.129: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:40.130: TPLUS: Choosing next server 172.100.100.1
*Nov  4 00:18:40.131: TPLUS: Choosing next server 172.100.100.2
*Nov  4 00:18:40.357: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
xe1#

```

### Cell f3 evidence

```
break-glass session ran 5 commands with port49d stopped; port49d was then started on the second address (172.100.100.2) while the first (172.100.100.1) reset every connection; the session stayed open 60 s
+0s: one-time-credential login: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; port49 saw it: false
+20s: one-time-credential login: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; port49 saw it: false
+39s: one-time-credential login: no error; port49 saw it: true

device state at the first failed login (read over the still-open session):
`show tacacs`:
show tacacs
port49: this session was not authenticated by port49

xe1#
`show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next`:
show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next
xe1#


  event=authorize_command verdict=deny reason=context_missing flags= user=breakglass port=tty434
  event=authorize_command verdict=deny reason=context_missing flags= user=breakglass port=tty434
  event=redeem verdict=permit reason=token_redeemed flags= user=alice04 port=tty435
  event=authorize_session verdict=permit reason=context_matched flags= user=alice04 port=tty435
  event=account verdict= reason= flags=start user=alice04 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice04 port=tty435
  event=account verdict= reason= flags=stop user=alice04 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice04 port=tty435
  event=account verdict= reason= flags=stop user=alice04 port=tty435
  event=account verdict= reason= flags=stop user=breakglass port=tty434
  event=account verdict= reason= flags=stop user=alice04 port=tty435
the wire (headers only):
12 connections from the device in the window: 12 with a SYN, 12 answered SYN-ACK, 3 with an RST
+9s 172.100.100.1 sport 60466: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.1s 172.100.100.2 sport 49568: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+9.5s 172.100.100.1 sport 60470: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.5s 172.100.100.2 sport 49578: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+38.9s 172.100.100.1 sport 53094: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+38.9s 172.100.100.2 sport 42098: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+38.9s 172.100.100.2 sport 42110: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+38.9s 172.100.100.2 sport 42126: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+39.2s 172.100.100.2 sport 42138: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+39.4s 172.100.100.2 sport 42150: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+39.4s 172.100.100.2 sport 42154: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+39.6s 172.100.100.2 sport 42162: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

(the evidence session failed: port49d was stopped but something is still listening on 172.100.100.1:49 after 30s)

```
