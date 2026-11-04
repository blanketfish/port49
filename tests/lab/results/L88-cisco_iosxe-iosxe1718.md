# L88: the reference AAA configuration on Catalyst 8000V 17.18.02

Platform: cisco_iosxe. Image: Catalyst 8000V 17.18.02. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

Capture: `tests/lab/evidence/L88-f-iosxe1718-cisco_iosxe.pcap` (redacted copy of the run's capture)

Capture: `tests/lab/evidence/L88-f2-iosxe1718-cisco_iosxe.pcap` (redacted copy of the run's capture)

Capture: `tests/lab/evidence/L88-f3-iosxe1718-cisco_iosxe.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 5.532s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +6s |
| b | PASS | break-glass login with port49d stopped: ok true in 30ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +6s; port49d's own close line appeared at +4.8s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 5s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +6s took 800ms: logged in, `show version` printed "'Cisco IOS XE Software, Version 17.18.02'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 780ms, `show version` output "'Cisco IOS XE Software, Version 17.18.02'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 2 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 2; port49 authorized one command and denied the other; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.18.2, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.c... [1]   |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 770ms; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 1s; first command output:  |
| f2 | MEASURED | the first one-time-credential login that port49 answered came at +30s after port49d was back; the session was still open when the loop began and was closed at +0s; a break-glass login first succeeded at +0s |
| f3 | MEASURED | the first one-time-credential login that reached the second server came at +39s; the break-glass session was never closed in the loop |
| g | OBSERVED | the device held no connection open across the reload that port49d reset (single-connection was on; what it sent after the reload went on connections it opened after it); single-connection: on: `single-connection` under `tacacs server port49-host`; the re-keyed phase: token session (`alice05`), `show version` before the change: ran in 300ms; first `show version` after the change, same session: refused in 300ms: `% Authorization failed.`; second `show version`, same session: refused in 300ms: `% Authorization failed.`; next token login (`alice06`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.02s; break-glass login plus three `show version`: logged in and ran them in 1.28s |

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
+0s 172.100.100.1 sport 38570: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 37368: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 37372: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+0s 172.100.100.2 sport 37378: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+300ms 172.100.100.2 sport 37394: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+500ms 172.100.100.2 sport 37400: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+500ms 172.100.100.2 sport 37406: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+700ms 172.100.100.2 sport 37408: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+800ms 172.100.100.2 sport 37422: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0` after f:
terminal length 0
xe1#
`show tacacs` after f:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:         79
             Socket closes:         79
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         34
        Total Packets Sent:         33
        Total Packets Recv:         33
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 49
              Socket opens:         64
             Socket closes:         64
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
777A68779BA8  10.0.0.15.43740            172.100.100.2.49            CLOSING
777ADAF96C20  10.0.0.15.41798            172.100.100.2.49            CLOSING
777A68830050  10.0.0.15.28709            172.100.100.2.49            CLOSING
777ADAF98CE0  10.0.0.15.31761            172.100.100.2.49            CLOSING
777ADAF96000  10.0.0.15.35816            172.100.100.1.49            TIMEWAIT
777A687F2BE0  10.0.0.15.30276            172.100.100.1.49            TIMEWAIT
777A686CF0A8  10.0.0.15.22               172.100.100.1.42688         ESTAB
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS` after f:
show processes | include TACACS
 576 Mwe 5C276B0F30A5             1         11      90  20864/24000  0 TACACS+         
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
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38512
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37372
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38542
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37394
TIME-WAIT 0      0      172.100.100.1:41096  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:41126  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:48024  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:48066  172.100.100.1:49   
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38496
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38538
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:33918
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:33900
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37368
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38482
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37400
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38504
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:33904
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37378
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38516
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38528
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37406
TIME-WAIT 0      0      172.100.100.1:49    172.100.100.41:38500
TIME-WAIT 0      0      172.100.100.1:53052  172.100.100.2:49   
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37408
TIME-WAIT 0      0      172.100.100.2:49    172.100.100.41:37422

mid-window:

after:
State      Recv-Q Send-Q Local Address:Port    Peer Address:Port 
LISTEN     0      4096   172.100.100.1:49           0.0.0.0:*    
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:50414
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:36126
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38512
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37372
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38542
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40768
FIN-WAIT-1 0      1      172.100.100.1:49    172.100.100.41:40836
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:50412
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40734
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37394
TIME-WAIT  0      0      172.100.100.1:41096  172.100.100.1:49   
TIME-WAIT  0      0      172.100.100.1:41126  172.100.100.1:49   
TIME-WAIT  0      0      172.100.100.1:48024  172.100.100.1:49   
TIME-WAIT  0      0      172.100.100.1:48066  172.100.100.1:49   
TIME-WAIT  0      0      172.100.100.1:49438  172.100.100.1:49   
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:36138
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40798
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:36116
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40824
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40758
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:50384
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38496
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38538
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:33918
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40744
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:33900
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37368
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38482
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37400
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40784
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38504
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:33904
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37378
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38516
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40814
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40820
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:50400
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38528
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:40766
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37406
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:38500
TIME-WAIT  0      0      172.100.100.1:49    172.100.100.41:36106
TIME-WAIT  0      0      172.100.100.1:53052  172.100.100.2:49   
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37408
TIME-WAIT  0      0      172.100.100.2:49    172.100.100.41:37422

the wire (headers only):
18 connections from the device in the window: 18 with a SYN, 18 answered SYN-ACK, 0 with an RST
+4.1s 172.100.100.1 sport 50384: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+4.3s 172.100.100.1 sport 50400: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.6s 172.100.100.1 sport 50412: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+4.8s 172.100.100.1 sport 50414: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+18.9s 172.100.100.1 sport 36106: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+19.2s 172.100.100.1 sport 36116: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.4s 172.100.100.1 sport 36126: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+19.6s 172.100.100.1 sport 36138: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 40734: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 40744: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+29.7s 172.100.100.1 sport 40758: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30s 172.100.100.1 sport 40766: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.2s 172.100.100.1 sport 40768: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.2s 172.100.100.1 sport 40784: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+30.4s 172.100.100.1 sport 40798: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.5s 172.100.100.1 sport 40814: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.5s 172.100.100.1 sport 40820: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false
+33s 172.100.100.1 sport 40824: SYN true SYN-ACK true; device packets 12, server packets 14; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
xe1#
`show tacacs`:
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        115
             Socket closes:        115
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         47
        Total Packets Sent:         55
        Total Packets Recv:         55
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0


Tacacs+ Server -  public  :
               Server name: port49-2
            Server address: 172.100.100.2
               Server port: 49
              Socket opens:         83
             Socket closes:         83
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
777A687E6DA8  10.0.0.15.12602            172.100.100.1.49            TIMEWAIT
777A68779BA8  10.0.0.15.43740            172.100.100.2.49            TIMEWAIT
777A6877C888  10.0.0.15.14986            172.100.100.1.49            TIMEWAIT
777ADAF96C20  10.0.0.15.41798            172.100.100.2.49            TIMEWAIT
777A687E5D08  10.0.0.15.17174            172.100.100.1.49            TIMEWAIT
777A68830050  10.0.0.15.28709            172.100.100.2.49            TIMEWAIT
777ADAF98CE0  10.0.0.15.31761            172.100.100.2.49            TIMEWAIT
777ADAF96000  10.0.0.15.35816            172.100.100.1.49            TIMEWAIT
777A686CF0A8  10.0.0.15.22               172.100.100.1.49710         ESTAB
777A687F2BE0  10.0.0.15.30276            172.100.100.1.49            TIMEWAIT
------------  0.0.0.0.22                 *.*                         LISTEN
------------  ::.22                      *.*                         LISTEN
xe1#
`show processes | include TACACS`:
show processes | include TACACS
 576 Mwe 5C276B0F30A5             1         23      43  20864/24000  0 TACACS+         
xe1#
`show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next`:
show logging | include Authentication start|Using server|Opening TCP|Socket I/O|Choosing next
*Nov  4 08:23:57.444: TPLUS: Using server 172.100.100.1
*Nov  4 08:23:57.445: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:23:57.681: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:23:57.682: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:23:57.683: TPLUS: Using server 172.100.100.1
*Nov  4 08:23:57.685: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:23:57.929: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:23:57.930: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:23:57.931: TPLUS: Using server 172.100.100.1
*Nov  4 08:23:57.932: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:23:58.185: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:23:58.186: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:23:58.187: TPLUS: Using server 172.100.100.1
*Nov  4 08:23:58.188: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:23:58.434: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:23:58.435: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:23:58.437: TPLUS: Using server 172.100.100.1
*Nov  4 08:23:58.438: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:23:58.690: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:23:58.691: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:23:58.701: TPLUS: Using server 172.100.100.1
*Nov  4 08:23:58.702: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:00.218: TPLUS: Authentication start packet created for 4036(alice03)
*Nov  4 08:24:02.219: TPLUS: Authentication start packet created for 4036(alice03)
*Nov  4 08:24:04.222:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:24:04.237: TPLUS: Authentication start packet created for 4037(breakglass)
*Nov  4 08:24:04.255: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:04.515: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:04.762: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:05.010:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:24:15.070: TPLUS: Authentication start packet created for 4038(alice03)
*Nov  4 08:24:17.071: TPLUS: Authentication start packet created for 4038(alice03)
*Nov  4 08:24:19.072:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:24:19.086: TPLUS: Authentication start packet created for 4039(breakglass)
*Nov  4 08:24:19.099: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:19.356: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:19.605: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:19.854:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:24:29.915: TPLUS: Authentication start packet created for 4040(alice03)
*Nov  4 08:24:29.915: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:30.176: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:30.427: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:30.679:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:24:30.688: TPLUS: Authentication start packet created for 4041(breakglass)
*Nov  4 08:24:30.688: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:33.192: TPLUS: Authentication start packet created for 4041(breakglass)
*Nov  4 08:24:33.192: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:36.199:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:24:36.200: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:36.202:  Socket I/O cleanup message sent to TACACS
*Nov  4 08:24:36.427: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 08:24:36.427: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:36.427: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 08:24:36.427: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:36.428: TPLUS: Authentication start packet created for 4042(breakglass)
*Nov  4 08:24:36.441: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:36.442: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:36.444: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:36.444: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:36.700: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:36.701: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:24:36.703: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:36.703: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:36.952: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:36.953: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:24:36.955: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:36.955: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:37.203: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:37.204: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:24:37.206: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:37.207: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:37.455: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:37.455: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:24:37.467: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:37.468: TPLUS: Choosing next server 172.100.100.2
*Nov  4 08:24:37.713: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  4 08:24:37.713: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  4 08:24:37.724: TPLUS: Using server 172.100.100.1
*Nov  4 08:24:37.725: TPLUS: Choosing next server 172.100.100.2
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
+9.1s 172.100.100.1 sport 46202: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.1s 172.100.100.2 sport 48502: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+9.4s 172.100.100.1 sport 46212: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.4s 172.100.100.2 sport 48514: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+38.7s 172.100.100.1 sport 42030: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+38.7s 172.100.100.2 sport 39840: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+38.7s 172.100.100.2 sport 39850: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+38.7s 172.100.100.2 sport 39856: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+39s 172.100.100.2 sport 39870: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+39.2s 172.100.100.2 sport 39874: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+39.2s 172.100.100.2 sport 39876: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev true srv true; RST dev false srv false
+39.4s 172.100.100.2 sport 39884: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

(the evidence session failed: port49d was stopped but something is still listening on 172.100.100.1:49 after 30s)

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (29s).

The change: port49d's broker.policy_file given `- {match: {name: xe1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

**Observation: the device held no connection open across this change.** port49d wrote no device_unknown record, and the capture holds no connection open before the change that port49d reset after it; what the device sent after the change went on connections it opened after it (records: `event=unvalidated <LONG> type=author` ×2).

Times are the host's, UTC: the sync (or policy edit) began 08:26:27.485Z; port49d applied the reload, saying `port49d: policy reloaded`, between 08:26:28.826Z and 08:26:28.852Z, and the change instant the capture is read against is 08:26:28.826Z; the command in flight was sent at 08:26:28.852Z.

| step | outcome |
|---|---|
| token session (`alice05`), `show version` before the change | ran in 300ms |
| first `show version` after the change, same session | refused in 300ms: `% Authorization failed.` |
| second `show version`, same session | refused in 300ms: `% Authorization failed.` |
| next token login (`alice06`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.02s |
| break-glass login plus three `show version` | logged in and ran them in 1.28s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=author` ×2

Records from the device during the next logins: `event=unvalidated <LONG> type=authen` ×3

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 59876 | 08:26:24.158Z | true | (not observed) | (not observed) | not reset by port49d |
| 59886 | 08:26:26.677Z | true | (not observed) | (not observed) | not reset by port49d |
| 59900 | 08:26:26.682Z | true | (not observed) | (not observed) | not reset by port49d |
| 59904 | 08:26:26.684Z | true | (not observed) | (not observed) | not reset by port49d |
| 40828 | 08:26:26.941Z | true | (not observed) | (not observed) | not reset by port49d |
| 40836 | 08:26:27.142Z | true | (not observed) | (not observed) | not reset by port49d |
| 40852 | 08:26:27.192Z | true | (not observed) | (not observed) | not reset by port49d |
| 40860 | 08:26:27.394Z | true | (not observed) | (not observed) | not reset by port49d |
| 40862 | 08:26:28.861Z | false | 08:26:28.962Z | 08:26:28.962Z | reset at its first packet after the change |
| 39136 | 08:26:29.062Z | false | (not observed) | 08:26:29.062Z | reset before the device sent on it (refused at Accept) |
| 40876 | 08:26:29.163Z | false | 08:26:29.264Z | 08:26:29.264Z | reset at its first packet after the change |
| 39146 | 08:26:29.364Z | false | (not observed) | 08:26:29.364Z | reset before the device sent on it (refused at Accept) |
| 40878 | 08:26:29.458Z | false | (not observed) | 08:26:29.458Z | reset before the device sent on it (refused at Accept) |
| 51674 | 08:26:39.503Z | false | 08:26:39.504Z | 08:26:39.504Z | reset at its first packet after the change |
| 51684 | 08:26:41.505Z | false | 08:26:41.506Z | 08:26:41.506Z | reset at its first packet after the change |
| 51688 | 08:26:43.523Z | false | 08:26:43.524Z | 08:26:43.524Z | reset at its first packet after the change |
| 51694 | 08:26:43.537Z | false | (not observed) | 08:26:43.537Z | reset before the device sent on it (refused at Accept) |
| 48812 | 08:26:43.538Z | false | (not observed) | 08:26:43.538Z | reset before the device sent on it (refused at Accept) |
| 51702 | 08:26:43.539Z | false | (not observed) | 08:26:43.539Z | reset before the device sent on it (refused at Accept) |
| 51716 | 08:26:43.796Z | false | (not observed) | 08:26:43.796Z | reset before the device sent on it (refused at Accept) |
| 48814 | 08:26:43.797Z | false | (not observed) | 08:26:43.797Z | reset before the device sent on it (refused at Accept) |
| 51720 | 08:26:43.798Z | false | (not observed) | 08:26:43.798Z | reset before the device sent on it (refused at Accept) |
| 51734 | 08:26:44.044Z | false | (not observed) | 08:26:44.044Z | reset before the device sent on it (refused at Accept) |
| 48820 | 08:26:44.046Z | false | (not observed) | 08:26:44.046Z | reset before the device sent on it (refused at Accept) |
| 51738 | 08:26:44.047Z | false | (not observed) | 08:26:44.047Z | reset before the device sent on it (refused at Accept) |
| 48826 | 08:26:44.050Z | false | (not observed) | 08:26:44.050Z | reset before the device sent on it (refused at Accept) |
| 51746 | 08:26:44.295Z | false | (not observed) | 08:26:44.295Z | reset before the device sent on it (refused at Accept) |
| 48830 | 08:26:44.296Z | false | (not observed) | 08:26:44.296Z | reset before the device sent on it (refused at Accept) |
| 51762 | 08:26:44.297Z | false | (not observed) | 08:26:44.297Z | reset before the device sent on it (refused at Accept) |
| 48840 | 08:26:44.299Z | false | (not observed) | 08:26:44.299Z | reset before the device sent on it (refused at Accept) |
| 51778 | 08:26:44.546Z | false | (not observed) | 08:26:44.546Z | reset before the device sent on it (refused at Accept) |
| 48854 | 08:26:44.647Z | false | (not observed) | 08:26:44.647Z | reset before the device sent on it (refused at Accept) |
| 51794 | 08:26:44.648Z | false | (not observed) | 08:26:44.649Z | reset before the device sent on it (refused at Accept) |
| 48864 | 08:26:44.650Z | false | (not observed) | 08:26:44.650Z | reset before the device sent on it (refused at Accept) |
| 51808 | 08:26:44.791Z | false | (not observed) | 08:26:44.791Z | reset before the device sent on it (refused at Accept) |

The change began at 08:26:28.826Z (host UTC); 0 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L88-g-iosxe1718-rekeyed-cisco_iosxe.pcap` — 380 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L88-g-iosxe1718-rekeyed-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
