# L88: the reference AAA configuration on Catalyst 8000V 17.18.02

Platform: cisco_iosxe. Image: Catalyst 8000V 17.18.02. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 5.536s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +6s |
| b | PASS | break-glass login with port49d stopped: ok true in 30ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +6s; port49d's own close line appeared at +4.8s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 5s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +6s took 800ms: logged in, `show version` printed "'Cisco IOS XE Software, Version 17.18.02'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 780ms, `show version` output "'Cisco IOS XE Software, Version 17.18.02'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 2 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 2; port49 authorized one command and denied the other; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.18.2, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.c... [1]   |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 770ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 1s; first command output:  |
| f2 | MEASURED | the first one-time-credential login that port49 answered came at +30s after port49d was back; the session was still open when the loop began and was closed at +0s; a break-glass login first succeeded at +0s |
| f3 | MEASURED | the first one-time-credential login that reached the second server came at +39s; the break-glass session was never closed in the loop |
| g | OBSERVED | the device held no connection open across the reload that port49d reset (single-connection was on; what it sent after the reload went on connections it opened after it); single-connection: on: `single-connection` under `tacacs server port49-host`; the re-keyed phase: token session (`alice05`), `show version` before the change: ran in 300ms; first `show version` after the change, same session: refused in 300ms: `% Authorization failed.`; second `show version`, same session: refused in 300ms: `% Authorization failed.`; next token login (`alice06`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.02s; break-glass login plus three `show version`: logged in and ran them in 1.28s |
| h | NOT MEASURED | the harness does not run cell h yet |

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
+0s 172.100.100.1 sport 57290: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 37720: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 37730: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 37736: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.2 sport 37748: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+500ms 172.100.100.2 sport 37764: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+500ms 172.100.100.2 sport 37780: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+700ms 172.100.100.2 sport 37794: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+800ms 172.100.100.2 sport 37800: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0` after f:
terminal length 0
xe1#
`show tacacs` after f:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:         78
             Socket closes:         78
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
              Socket opens:         62
             Socket closes:         62
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
77AD238CEE50  10.0.0.15.31494            172.100.100.2.49            CLOSING
77AD238CDDB8  10.0.0.15.29563            172.100.100.2.49            CLOSING
77AD2AE7D030  10.0.0.15.22               172.100.100.1.57884         ESTAB
77AD2AE92CA0  10.0.0.15.43261            172.100.100.1.49            TIMEWAIT
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS` after f:
show processes | include TACACS
 576 Mwe 557F6C6C80A5             0         11       0  20864/24000  0 TACACS+         
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
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57230
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37764
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38304
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57208
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57252
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38326
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37794
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57274
TIME-WAIT 0      0      172.100.100.1:37656  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:37676  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41634  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41680  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57268
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37748
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57198
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37730
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37800
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57220
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57182
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37720
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37780
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37736
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57246
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38320
TIME-WAIT 0      0      172.100.100.1:55348  172.100.100.2:49   

mid-window:

after:
State     Recv-Q Send-Q Local Address:Port    Peer Address:Port 
LISTEN    0      4096   172.100.100.1:49           0.0.0.0:*    
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57230
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41094
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37764
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38304
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57208
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57252
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38326
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37794
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57274
TIME-WAIT 0      0      172.100.100.1:37656  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:37676  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41254  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41634  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41680  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57268
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37748
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57198
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35762
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37730
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41072
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37800
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55650
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41074
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41044
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55660
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41078
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41050
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41098
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57220
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57182
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55654
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37720
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41062
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41104
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35770
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37780
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35760
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:55672
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41106
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37736
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:57246
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38320
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:35784
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:41120
TIME-WAIT 0      0      172.100.100.1:55348  172.100.100.2:49   

the wire (headers only):
18 connections from the device in the window: 18 with a SYN, 18 answered SYN-ACK, 0 with an RST
+4.1s 172.100.100.1 sport 55650: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+4.3s 172.100.100.1 sport 55654: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.6s 172.100.100.1 sport 55660: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.8s 172.100.100.1 sport 55672: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+18.9s 172.100.100.1 sport 35760: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+19.2s 172.100.100.1 sport 35762: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.4s 172.100.100.1 sport 35770: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.6s 172.100.100.1 sport 35784: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 41044: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 41050: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 41062: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.9s 172.100.100.1 sport 41072: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.1s 172.100.100.1 sport 41074: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.2s 172.100.100.1 sport 41078: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 41094: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.1 sport 41098: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.1 sport 41104: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false
+33.2s 172.100.100.1 sport 41106: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
xe1#
`show tacacs`:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        114
             Socket closes:        114
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
              Socket opens:         81
             Socket closes:         81
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
77AD238CEE50  10.0.0.15.31494            172.100.100.2.49            TIMEWAIT
77AD238CDDB8  10.0.0.15.29563            172.100.100.2.49            TIMEWAIT
77AD278F7580  10.0.0.15.24863            172.100.100.1.49            TIMEWAIT
77ACB4276DD8  10.0.0.15.19864            172.100.100.1.49            TIMEWAIT
77AD2A6F01D0  10.0.0.15.22               172.100.100.1.60274         ESTAB
77AD278F6520  10.0.0.15.13806            172.100.100.1.49            TIMEWAIT
77ACB4277D98  10.0.0.15.14455            172.100.100.1.49            TIMEWAIT
77AD2AE92CA0  10.0.0.15.43261            172.100.100.1.49            TIMEWAIT
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS`:
show processes | include TACACS
 576 Mwe 557F6C6C80A5             1         23      43  20864/24000  0 TACACS+         
xe1#
`show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next`:
show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next
*Nov  4 01:32:17.245: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:17.246: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:17.490: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:17.492: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:17.493: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:17.496: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:17.740: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:17.742: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:17.743: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:17.744: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:17.996: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:17.997: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:17.998: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:17.999: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:18.242: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:18.243: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:18.245: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:18.246: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:18.496: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:18.497: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:18.507: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:18.508: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:20.024: TPLUS: Authentication start packet created for 4036(alice03)
*Nov  4 01:32:22.046: TPLUS: Authentication start packet created for 4036(alice03)
*Nov  4 01:32:24.050:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:24.064: TPLUS: Authentication start packet created for 4037(breakglass)
*Nov  4 01:32:24.077: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:24.337: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:24.583: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:24.832:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:34.864: TPLUS: Authentication start packet created for 4038(alice03)
*Nov  4 01:32:36.866: TPLUS: Authentication start packet created for 4038(alice03)
*Nov  4 01:32:38.867:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:38.880: TPLUS: Authentication start packet created for 4039(breakglass)
*Nov  4 01:32:38.893: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:39.162: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:39.401: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:39.647:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:49.694: TPLUS: Authentication start packet created for 4040(alice03)
*Nov  4 01:32:49.694: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:49.957: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:50.251: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:50.709:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:50.718: TPLUS: Authentication start packet created for 4041(breakglass)
*Nov  4 01:32:50.718: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:53.222: TPLUS: Authentication start packet created for 4041(breakglass)
*Nov  4 01:32:53.222: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.228:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:56.228: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.230:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:56.456: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 01:32:56.456: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.456: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 01:32:56.456: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.457: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 01:32:56.469: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.470: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.472: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.472: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.729: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:56.729: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:56.731: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.731: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.981: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:56.981: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:56.982: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.983: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:57.231: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:57.232: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:57.234: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:57.235: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:57.482: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:57.482: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:57.492: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:57.493: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:57.736: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:57.737: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:57.748: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:57.749: TPLUS: Choosing next server 172.100.100.2
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
  event=account verdict= reason= flags=stop user=alice04 port=tty435
  event=account verdict= reason= flags=stop user=breakglass port=tty434
the wire (headers only):
13 connections from the device in the window: 13 with a SYN, 13 answered SYN-ACK, 4 with an RST
+9s 172.100.100.1 sport 39276: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9s 172.100.100.2 sport 60410: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+9.3s 172.100.100.1 sport 39288: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.3s 172.100.100.2 sport 60424: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+38.7s 172.100.100.1 sport 39840: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+40.7s 172.100.100.1 sport 39852: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+40.7s 172.100.100.2 sport 57296: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+40.7s 172.100.100.2 sport 57300: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+40.7s 172.100.100.2 sport 57310: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+41s 172.100.100.2 sport 57314: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+41.2s 172.100.100.2 sport 57324: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+41.2s 172.100.100.2 sport 57334: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+41.4s 172.100.100.2 sport 57344: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
xe1#
`show tacacs`:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        137
             Socket closes:        137
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         62
        Total Packets Sent:         59
        Total Packets Recv:         56
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 49
              Socket opens:        110
             Socket closes:        110
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         59
        Total Packets Sent:         21
        Total Packets Recv:         21
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show tcp brief`:
show tcp brief
TCB       Local Address               Foreign Address             (state)
77AD238CEE18  10.0.0.15.12018            172.100.100.2.49            TIMEWAIT
77AD2A6F01D0  10.0.0.15.22               172.100.100.1.50560         ESTAB
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS`:
show processes | include TACACS
 576 Mwe 557F6C6C80A5             2         32      62  20864/24000  0 TACACS+         
xe1#
`show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next`:
show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next
*Nov  4 01:32:24.077: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:24.337: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:24.583: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:24.832:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:34.864: TPLUS: Authentication start packet created for 4038(alice03)
*Nov  4 01:32:36.866: TPLUS: Authentication start packet created for 4038(alice03)
*Nov  4 01:32:38.867:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:38.880: TPLUS: Authentication start packet created for 4039(breakglass)
*Nov  4 01:32:38.893: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:39.162: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:39.401: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:39.647:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:49.694: TPLUS: Authentication start packet created for 4040(alice03)
*Nov  4 01:32:49.694: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:49.957: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:50.251: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:50.709:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:50.718: TPLUS: Authentication start packet created for 4041(breakglass)
*Nov  4 01:32:50.718: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:53.222: TPLUS: Authentication start packet created for 4041(breakglass)
*Nov  4 01:32:53.222: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.228:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:56.228: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.230:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:56.456: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 01:32:56.456: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.456: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 01:32:56.456: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.457: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 01:32:56.469: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.470: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.472: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.472: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.729: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:56.729: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:56.731: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.731: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:56.981: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:56.981: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:56.982: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:56.983: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:57.231: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:57.232: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:57.234: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:57.235: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:57.482: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:57.482: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:57.492: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:57.493: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:57.736: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:57.737: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:57.748: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:57.749: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:58.004: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:58.005: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:58.023: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:58.024: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:58.227: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:58.227: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:58.228: TPLUS: Choosing next server 172.100.100.1
*Nov  4 01:32:58.229: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:58.231:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:32:58.761: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 01:32:58.774: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:58.774: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:59.031: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:59.032: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:59.034: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:59.034: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:59.283: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:59.284: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:59.285: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:59.286: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:59.543: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:59.543: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:59.545: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:59.545: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:32:59.782: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:32:59.782: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:32:59.784: TPLUS: Using server 172.100.100.1
*Nov  4 01:32:59.786: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:33:00.035: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:33:00.035: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:00.037: TPLUS: Using server 172.100.100.1
*Nov  4 01:33:00.037: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:33:00.288: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:33:00.288: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:00.290: TPLUS: Using server 172.100.100.1
*Nov  4 01:33:00.290: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:33:00.536: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:33:00.581: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:00.583: TPLUS: Using server 172.100.100.1
*Nov  4 01:33:00.583: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:33:00.791: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:33:00.792: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:00.803: TPLUS: Using server 172.100.100.1
*Nov  4 01:33:00.803: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:33:02.327: TPLUS: Authentication start packet created for 4044(alice04)
*Nov  4 01:33:04.328: TPLUS: Authentication start packet created for 4044(alice04)
*Nov  4 01:33:06.330:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:33:11.353: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:33:11.354: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:11.623: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:33:11.623: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:21.908: TPLUS: Authentication start packet created for 4045(alice04)
*Nov  4 01:33:23.909: TPLUS: Authentication start packet created for 4045(alice04)
*Nov  4 01:33:25.911:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:33:40.998: TPLUS: Authentication start packet created for 4046(alice04)
*Nov  4 01:33:40.998: TPLUS: Using server 172.100.100.1
*Nov  4 01:33:43.001: TPLUS: Authentication start packet created for 4046(alice04)
*Nov  4 01:33:43.001: TPLUS: Using server 172.100.100.1
*Nov  4 01:33:43.002: TPLUS: Authentication start packet created for 4046(alice04)
*Nov  4 01:33:43.002: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:33:43.268: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:43.519: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:33:43.764: TPLUS: Using server 172.100.100.1
*Nov  4 01:33:43.765: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:33:43.765:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:33:43.767:  Socket I/O cleanup message sent to TACACS
*Nov  4 01:34:03.045: TPLUS: Authentication start packet created for 4047(breakglass)
*Nov  4 01:34:03.045: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:03.046: TPLUS: Authentication start packet created for 4047(breakglass)
*Nov  4 01:34:03.046: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:34:03.047: TPLUS: Authentication start packet created for 4047(breakglass)
*Nov  4 01:34:03.060: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:03.061: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:03.062: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:34:03.319: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:34:03.319: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:34:03.321: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:03.568: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:34:03.568: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:34:03.570: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:03.570: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:34:03.822: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:34:03.823: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:34:03.825: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:03.826: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:34:04.072: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:34:04.173: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:34:04.183: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:04.184: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:34:04.326: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 01:34:04.327: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 01:34:04.344: TPLUS: Using server 172.100.100.1
*Nov  4 01:34:04.345: TPLUS: Choosing next server 172.100.100.2
*Nov  4 01:34:04.593: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
xe1#
(the evidence session failed: something is already listening on 172.100.100.1:49, most likely a port49d left by an interrupted run. It would answer this device's AAA instead of the daemon this run starts. Find and stop it:
  sudo ss -lptn 'sport = :49'
  pkill -f 'port49d -config .*<LONG>')

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (30s).

The change: port49d's broker.policy_file given `- {match: {name: xe1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

**Observation: the device held no connection open across this change.** port49d wrote no device_unknown record, and the capture holds no connection open before the change that port49d reset after it; what the device sent after the change went on connections it opened after it (records: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×2).

Times are the host's, UTC: the sync (or policy edit) began 01:34:40.952Z; port49d applied the reload, saying `port49d: policy reloaded`, between 01:34:42.268Z and 01:34:42.294Z, and the change instant the capture is read against is 01:34:42.268Z; the command in flight was sent at 01:34:42.294Z.

| step | outcome |
|---|---|
| token session (`alice05`), `show version` before the change | ran in 300ms |
| first `show version` after the change, same session | refused in 300ms: `% Authorization failed.` |
| second `show version`, same session | refused in 300ms: `% Authorization failed.` |
| next token login (`alice06`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.02s |
| break-glass login plus three `show version` | logged in and ran them in 1.28s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×2

Records from the device during the next logins: `event=unvalidated <LONG> type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 53898 | 01:34:34.620Z | true | (not observed) | (not observed) | not reset by port49d |
| 40632 | 01:34:37.124Z | true | (not observed) | (not observed) | not reset by port49d |
| 40648 | 01:34:40.144Z | true | (not observed) | (not observed) | not reset by port49d |
| 40650 | 01:34:40.148Z | true | (not observed) | (not observed) | not reset by port49d |
| 40656 | 01:34:40.151Z | true | (not observed) | (not observed) | not reset by port49d |
| 40668 | 01:34:40.407Z | true | (not observed) | (not observed) | not reset by port49d |
| 40682 | 01:34:40.609Z | true | (not observed) | (not observed) | not reset by port49d |
| 40686 | 01:34:40.656Z | true | (not observed) | (not observed) | not reset by port49d |
| 40692 | 01:34:40.858Z | true | (not observed) | (not observed) | not reset by port49d |
| 40706 | 01:34:42.302Z | false | 01:34:42.402Z | 01:34:42.402Z | reset at its first packet after the change |
| 35122 | 01:34:42.502Z | false | (not observed) | 01:34:42.503Z | reset before the device sent on it (refused at Accept) |
| 40720 | 01:34:42.600Z | false | 01:34:42.701Z | 01:34:42.701Z | reset at its first packet after the change |
| 35136 | 01:34:42.801Z | false | (not observed) | 01:34:42.802Z | reset before the device sent on it (refused at Accept) |
| 40724 | 01:34:42.937Z | false | 01:34:42.938Z | 01:34:42.938Z | reset at its first packet after the change |
| 59080 | 01:34:52.946Z | false | 01:34:52.947Z | 01:34:52.947Z | reset at its first packet after the change |
| 59086 | 01:34:54.948Z | false | 01:34:54.950Z | 01:34:54.950Z | reset at its first packet after the change |
| 34306 | 01:34:56.966Z | false | 01:34:56.967Z | 01:34:56.967Z | reset at its first packet after the change |
| 34308 | 01:34:56.980Z | false | (not observed) | 01:34:56.980Z | reset before the device sent on it (refused at Accept) |
| 36358 | 01:34:56.981Z | false | (not observed) | 01:34:56.981Z | reset before the device sent on it (refused at Accept) |
| 34324 | 01:34:56.982Z | false | (not observed) | 01:34:56.982Z | reset before the device sent on it (refused at Accept) |
| 36364 | 01:34:56.983Z | false | (not observed) | 01:34:56.983Z | reset before the device sent on it (refused at Accept) |
| 34340 | 01:34:57.237Z | false | (not observed) | 01:34:57.237Z | reset before the device sent on it (refused at Accept) |
| 36370 | 01:34:57.238Z | false | (not observed) | 01:34:57.238Z | reset before the device sent on it (refused at Accept) |
| 34350 | 01:34:57.239Z | false | (not observed) | 01:34:57.239Z | reset before the device sent on it (refused at Accept) |
| 36378 | 01:34:57.240Z | false | (not observed) | 01:34:57.240Z | reset before the device sent on it (refused at Accept) |
| 34358 | 01:34:57.487Z | false | (not observed) | 01:34:57.487Z | reset before the device sent on it (refused at Accept) |
| 36392 | 01:34:57.489Z | false | (not observed) | 01:34:57.489Z | reset before the device sent on it (refused at Accept) |
| 34370 | 01:34:57.490Z | false | (not observed) | 01:34:57.490Z | reset before the device sent on it (refused at Accept) |
| 36404 | 01:34:57.493Z | false | (not observed) | 01:34:57.493Z | reset before the device sent on it (refused at Accept) |
| 34382 | 01:34:57.737Z | false | (not observed) | 01:34:57.737Z | reset before the device sent on it (refused at Accept) |
| 36412 | 01:34:57.738Z | false | (not observed) | 01:34:57.738Z | reset before the device sent on it (refused at Accept) |
| 34392 | 01:34:57.739Z | false | (not observed) | 01:34:57.739Z | reset before the device sent on it (refused at Accept) |
| 36428 | 01:34:57.742Z | false | (not observed) | 01:34:57.742Z | reset before the device sent on it (refused at Accept) |
| 34396 | 01:34:57.990Z | false | (not observed) | 01:34:57.990Z | reset before the device sent on it (refused at Accept) |
| 36438 | 01:34:57.991Z | false | (not observed) | 01:34:57.991Z | reset before the device sent on it (refused at Accept) |
| 34402 | 01:34:57.992Z | false | (not observed) | 01:34:57.992Z | reset before the device sent on it (refused at Accept) |
| 36446 | 01:34:57.994Z | false | (not observed) | 01:34:57.994Z | reset before the device sent on it (refused at Accept) |
| 34414 | 01:34:58.235Z | false | (not observed) | 01:34:58.235Z | reset before the device sent on it (refused at Accept) |
| 36462 | 01:34:58.236Z | false | (not observed) | 01:34:58.236Z | reset before the device sent on it (refused at Accept) |

The change began at 01:34:42.268Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 422 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
