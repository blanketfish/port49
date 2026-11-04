# L88: the reference AAA configuration on Catalyst 8000V 17.13.01a

Platform: cisco_iosxe. Image: Catalyst 8000V 17.13.01a. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-cisco_iosxe.pcap` (redacted copy of the run's capture)

Capture: `tests/lab/evidence/L88-f2-cisco_iosxe.pcap` (redacted copy of the run's capture)

Capture: `tests/lab/evidence/L88-f3-cisco_iosxe.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 5.522s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +6s |
| b | PASS | break-glass login with port49d stopped: ok true in 30ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +6s; port49d's own close line appeared at +5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 5s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +6s took 800ms: logged in, `show version` printed "'Cisco IOS XE Software, Version 17.13.01a'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 780ms, `show version` output "'Cisco IOS XE Software, Version 17.13.01a'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 2 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 2; port49 authorized one command and denied the other; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.... [1]   |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 2.78s; connections the first server reset: 2; port49 redeemed the credential: true; tries 1, the login reached port49 after 3s; first command output:  |
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
10 connections from the device in the window: 10 with a SYN, 10 answered SYN-ACK, 2 with an RST
+0s 172.100.100.1 sport 43450: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+2s 172.100.100.1 sport 43464: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+2s 172.100.100.2 sport 34290: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+2s 172.100.100.2 sport 34304: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2s 172.100.100.2 sport 34320: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.3s 172.100.100.2 sport 45320: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+2.5s 172.100.100.2 sport 45336: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.5s 172.100.100.2 sport 45344: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+2.7s 172.100.100.2 sport 45358: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+2.8s 172.100.100.2 sport 45370: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0` after f:
terminal length 0
xe1#
`show tacacs` after f:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        239
             Socket closes:        239
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         34
        Total Packets Sent:         35
        Total Packets Recv:         34
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 49
              Socket opens:        223
             Socket closes:        223
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         33
        Total Packets Sent:          9
        Total Packets Recv:          9
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show tcp brief` after f:
show tcp brief
TCB       Local Address               Foreign Address             (state)
7F7804950FA0  10.0.0.15.22               172.100.100.1.55272         ESTAB
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS` after f:
show processes | include TACACS
 374 Mwe 5E624309DFE5             1         11      90  21120/24000  0 TACACS+         
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
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43342
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45358
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43376
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43398
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:34320
TIME-WAIT 0      0      172.100.100.1:47384  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:47422  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43382
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:34290
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40812
TIME-WAIT 0      0      172.100.100.1:60950  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:60982  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40824
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43362
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43420
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:34304
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43406
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40800
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45336
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45320
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45344
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43358
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45370
TIME-WAIT 0      0      172.100.100.1:45952  172.100.100.2:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43348

mid-window:

after:
State     Recv-Q Send-Q Local Address:Port    Peer Address:Port 
LISTEN    0      4096   172.100.100.1:49           0.0.0.0:*    
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43342
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45358
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43376
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43398
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52866
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:60530
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52944
TIME-WAIT 0      0      172.100.100.1:32772  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52932
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52896
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:34320
TIME-WAIT 0      0      172.100.100.1:47384  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:47422  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40956
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:44444
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43382
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:34290
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40812
TIME-WAIT 0      0      172.100.100.1:60950  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:60982  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40824
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52872
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43362
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52900
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:60532
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40962
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43420
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:34304
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40946
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43406
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52922
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52882
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:60524
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:60548
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40800
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45336
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45320
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45344
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52906
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43358
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:45370
TIME-WAIT 0      0      172.100.100.1:45952  172.100.100.2:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:43348
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:40966
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:52942

the wire (headers only):
18 connections from the device in the window: 18 with a SYN, 18 answered SYN-ACK, 0 with an RST
+4s 172.100.100.1 sport 40946: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+4.3s 172.100.100.1 sport 40956: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.5s 172.100.100.1 sport 40962: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.8s 172.100.100.1 sport 40966: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+18.8s 172.100.100.1 sport 60524: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+19.1s 172.100.100.1 sport 60530: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.3s 172.100.100.1 sport 60532: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.6s 172.100.100.1 sport 60548: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.6s 172.100.100.1 sport 52866: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+29.6s 172.100.100.1 sport 52872: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 52882: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.9s 172.100.100.1 sport 52896: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.1s 172.100.100.1 sport 52900: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.2s 172.100.100.1 sport 52906: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 52922: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 52932: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 52942: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false
+32.9s 172.100.100.1 sport 52944: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
xe1#
`show tacacs`:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        332
             Socket closes:        332
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         47
        Total Packets Sent:         57
        Total Packets Recv:         56
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 49
              Socket opens:        297
             Socket closes:        297
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         46
        Total Packets Sent:          9
        Total Packets Recv:          9
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show tcp brief`:
show tcp brief
TCB       Local Address               Foreign Address             (state)
7F787098BB18  10.0.0.15.53467            172.100.100.1.49            TIMEWAIT
7F7804950FA0  10.0.0.15.22               172.100.100.1.48814         ESTAB
7F7804945000  10.0.0.15.48002            172.100.100.1.49            TIMEWAIT
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS`:
show processes | include TACACS
 374 Mwe 5E624309DFE5             1         23      43  21120/24000  0 TACACS+         
xe1#
`show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next`:
show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next
1: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:12:31.412: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:12:31.413: TPLUS: Using server 172.100.100.1
*Nov  4 08:12:31.414: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.415: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.416: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.417: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.418: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.419: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.420: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.621: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:12:31.622: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:12:31.624: TPLUS: Using server 172.100.100.1
*Nov  4 08:12:31.625: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.626: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.627: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.628: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.629: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.630: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.631: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.875: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:12:31.876: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:12:31.885: TPLUS: Using server 172.100.100.1
*Nov  4 08:12:31.886: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.887: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.888: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.889: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.890: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:31.891: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:12:31.892: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:12:33.407: TPLUS: Authentication start packet created for 4037(alice03)
*Nov  4 08:12:35.408: TPLUS: Authentication start packet created for 4037(alice03)
*Nov  4 08:12:37.409:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:12:37.420: TPLUS: Authentication start packet created for 4038(breakglass)
*Nov  4 08:12:37.431: TPLUS: Using server 172.100.100.1
*Nov  4 08:12:37.686: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:12:37.935: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:12:38.185:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:12:48.202: TPLUS: Authentication start packet created for 4039(alice03)
*Nov  4 08:12:50.203: TPLUS: Authentication start packet created for 4039(alice03)
*Nov  4 08:12:52.204:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:12:52.215: TPLUS: Authentication start packet created for 4040(breakglass)
*Nov  4 08:12:52.226: TPLUS: Using server 172.100.100.1
*Nov  4 08:12:52.483: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:12:52.733: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:12:52.981:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:13:03.039: TPLUS: Authentication start packet created for 4041(alice03)
*Nov  4 08:13:03.039: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:03.301: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:13:03.549: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:13:03.807:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:13:03.807: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 08:13:03.807: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:06.312: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 08:13:06.312: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:09.317:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:13:09.317: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:09.320:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:13:09.541: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.541: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:09.542: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.542: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.542: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.543: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.544: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.544: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.545: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.545: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.546: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.546: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.547: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.547: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.547: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.548: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.549: TPLUS: Authentication start packet created for 4043(breakglass)
*Nov  4 08:13:09.559: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:09.560: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.561: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.562: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.563: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.564: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.565: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.566: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.567: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:09.568: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.569: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.570: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.571: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.572: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.573: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.574: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.575: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.576: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.577: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.578: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.818: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:13:09.819: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:13:09.820: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:09.821: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.822: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.823: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.824: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.825: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:09.826: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:09.827: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.069: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:13:10.070: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:13:10.071: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:10.072: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.073: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.074: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.075: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.076: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.077: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.078: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.321: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:13:10.322: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:13:10.323: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:10.325: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.326: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.327: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.328: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.329: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.330: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.331: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.572: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:13:10.573: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:13:10.577: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:10.578: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.579: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.580: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.581: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.582: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.583: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.584: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.824: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:13:10.826: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:13:10.834: TPLUS: Using server 172.100.100.1
*Nov  4 08:13:10.836: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.837: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.838: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.839: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.840: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:10.841: TPLUS: Choosing next server 172.100.100.1
*Nov  4 08:13:10.842: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:13:11.086: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
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
12 connections from the device in the window: 12 with a SYN, 12 answered SYN-ACK, 3 with an RST
+9.1s 172.100.100.1 sport 36252: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.1s 172.100.100.2 sport 51270: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+9.3s 172.100.100.1 sport 36260: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.3s 172.100.100.2 sport 51272: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+38.7s 172.100.100.1 sport 37758: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+38.7s 172.100.100.2 sport 47786: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+38.7s 172.100.100.2 sport 47788: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+38.7s 172.100.100.2 sport 47802: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+39s 172.100.100.2 sport 47818: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+39.2s 172.100.100.2 sport 47832: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+39.2s 172.100.100.2 sport 47838: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+39.4s 172.100.100.2 sport 47842: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

(the evidence session failed: port49d was stopped but something is still listening on 172.100.100.1:49 after 30s)

```
