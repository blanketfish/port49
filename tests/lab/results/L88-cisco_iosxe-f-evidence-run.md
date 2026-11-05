# L88: the reference AAA configuration on Catalyst 8000V 17.13.01a

Platform: cisco_iosxe. Image: Catalyst 8000V 17.13.01a. Transport: tcp. Measured 2026-11-03 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxe` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 5.52s (); port49 decision for the attempt: verdict="deny" reason="token_not_found" |
| b | PASS | break-glass login with port49d stopped: ok true in 30ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +6s; port49d's own close line appeared at +4.8s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 5s: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain; try at +6s took 800ms: logged in, `show version` printed "'Cisco IOS XE Software, Version 17.13.01a'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 780ms, `show version` output "'Cisco IOS XE Software, Version 17.13.01a'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 2 command authorizations permitted, 1 denied by port49; accounting START 1, STOP 2; port49 authorized one command and denied the other; command output: [0] Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3) Technical Support: http://www.cisco.... [1]   |
| f | FAIL | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 4.01s; connections the first server reset: 0; port49 redeemed the credential: false; first command output:  |

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
`show tacacs` 0s after the break-glass login (port49d stopped):
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
              Socket opens:        211
             Socket closes:        211
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         32
        Total Packets Sent:          0
        Total Packets Recv:          0
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`debug tacacs` on:
debug tacacs
TACACS access control debugging is on
xe1#
`show tacacs` after the login (port49d stopped):
show tacacs

Tacacs+ Server -  public  :
               Server name: port49-1
            Server address: 172.100.100.1
               Server port: 49
              Socket opens:        242
             Socket closes:        242
             Socket aborts:          0
             Socket errors:          0
           Socket Timeouts:          0
   Failed Connect Attempts:         35
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
   Failed Connect Attempts:         34
        Total Packets Sent:          0
        Total Packets Recv:          0
             Server Status: Alive
Continous Authc fail count:          0
Continous Authz fail count:          0

xe1#
`show logging` tacacs lines:
show logging | include TAC|tacacs|TPLUS|AAA
*Nov  3 22:10:06.268: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.269: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.269: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.270: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.270: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.270: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.270: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.271: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.271: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.272: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.272: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.272: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.272: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.273: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.273: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.274: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.274: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.275: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.275: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.279: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:06.279: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:27.384: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:27.384: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:27.633: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:28.137: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:29.946: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:30.949: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:31.953: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:31.953: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:32.202: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:32.453: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:32.707: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:32.707: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:32.960: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:32.960: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.215: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.215: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.466: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.466: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.715: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.715: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.967: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:33.967: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:34.219: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:34.219: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:34.469: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:34.469: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:36.222: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:36.222: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:45.343: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:10:45.344: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:11:15.343: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:11:15.343: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:11:15.343: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:11:15.343: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:11:30.691: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:11:30.692: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:00.691: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:00.691: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:00.692: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:00.692: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:28.043: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:28.044: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:58.043: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:58.043: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:58.044: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:12:58.044: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:13:26.197: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:13:26.198: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:13:27.202: TPLUS: Queuing AAA Accounting request 4034 for processing
*Nov  3 22:13:27.202: TPLUS: processing accounting request id 4034
*Nov  3 22:13:27.202: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.202: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.202: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.202: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.202: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.202: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.202: TPLUS: Using server 172.100.100.1
*Nov  3 22:13:27.202: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.202: TPLUS(00000FC2)/0/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.203: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:13:27.203: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.203: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.203: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.203: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.203: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.203: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.203: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.203: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:13:27.203: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.203: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.203: TPLUS(00000FC2)/7E27F4B12B40: releasing old socket 0
*Nov  3 22:13:27.203: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Socket 1 is in wait state
*Nov  3 22:13:27.204: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:13:27.204: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.204: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.204: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.204: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.204: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.204: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.204: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.204: TPLUS: Choosing next server 172.100.100.1
*Nov  3 22:13:27.204: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.204: TPLUS(00000FC2)/0/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.204: TPLUS(00000FC2)/7E27F4B12B40: releasing old socket 1
*Nov  3 22:13:27.204: TPLUS(00000FC2)/0/NB_WAIT/7E27F4B12B40: Socket 0 is in wait state
*Nov  3 22:13:27.205: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:13:27.205: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.205: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.205: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.205: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.205: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.205: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.205: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.205: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:13:27.205: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.205: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.205: TPLUS(00000FC2)/7E27F4B12B40: releasing old socket 0
*Nov  3 22:13:27.205: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Socket 1 is in wait state
*Nov  3 22:13:27.206: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:13:27.206: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.206: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.206: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.206: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.206: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.206: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.206: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.206: TPLUS: Choosing next server 172.100.100.1
*Nov  3 22:13:27.206: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.206: TPLUS(00000FC2)/0/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.206: TPLUS(00000FC2)/7E27F4B12B40: releasing old socket 1
*Nov  3 22:13:27.206: TPLUS(00000FC2)/0/NB_WAIT/7E27F4B12B40: Socket 0 is in wait state
*Nov  3 22:13:27.207: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:13:27.207: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.207: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.207: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.207: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.207: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.207: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.207: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.207: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:13:27.207: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.207: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.207: TPLUS(00000FC2)/7E27F4B12B40: releasing old socket 0
*Nov  3 22:13:27.207: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Socket 1 is in wait state
*Nov  3 22:13:27.208: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:13:27.208: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.208: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.208: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.208: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.208: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.208: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.208: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.208: TPLUS: Choosing next server 172.100.100.1
*Nov  3 22:13:27.208: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.208: TPLUS(00000FC2)/0/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.208: TPLUS(00000FC2)/7E27F4B12B40: releasing old socket 1
*Nov  3 22:13:27.208: TPLUS(00000FC2)/0/NB_WAIT/7E27F4B12B40: Socket 0 is in wait state
*Nov  3 22:13:27.209: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:13:27.209: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.209: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.209: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.209: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.209: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.209: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.209: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.209: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:13:27.209: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:13:27.209: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Started 5 sec timeout
*Nov  3 22:13:27.209: TPLUS(00000FC2)/7E27F4B12B40: releasing old socket 0
*Nov  3 22:13:27.209: TPLUS(00000FC2)/1/NB_WAIT/7E27F4B12B40: Socket 1 is in wait state
*Nov  3 22:13:27.210: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:13:27.210: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:13:27.210: TPLUS: Sending AV task_id=4079
*Nov  3 22:13:27.210: TPLUS: Sending AV timezone=UTC
*Nov  3 22:13:27.210: TPLUS: Sending AV service=shell
*Nov  3 22:13:27.210: TPLUS: Sending AV priv-lvl=15
*Nov  3 22:13:27.210: TPLUS: Sending AV cmd=debug tacacs <cr>
*Nov  3 22:13:27.210: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:13:27.210: TPLUS(00000FC2)/1/7E27F4B12B40: Processing the reply packet
*Nov  3 22:13:27.729: TPLUS: Queuing AAA Authentication request 4035 for processing
*Nov  3 22:13:27.729: TPLUS(00000FC3) login timer started 1020 sec timeout
*Nov  3 22:13:27.729: TPLUS: processing authentication start request id 4035
*Nov  3 22:13:27.729: TPLUS: Authentication start packet created for 4035(alice02)
*Nov  3 22:13:29.729: TPLUS: Queuing AAA Authentication request 4035 for processing
*Nov  3 22:13:29.729: TPLUS(00000FC3) login timer started 1020 sec timeout
*Nov  3 22:13:29.729: TPLUS: processing authentication start request id 4035
*Nov  3 22:13:29.729: TPLUS: Authentication start packet created for 4035(alice02)
*Nov  3 22:13:31.731:  Socket I/O cleanup message sent to TACACS
TPLUS Proc:SOCKET IO CLEANUP EVENT
*Nov  3 22:13:56.197: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:13:56.197: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:13:56.197: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:13:56.197: %AAA-6-METHOD_LIST_STATE: authen mlist  pvt_authen_0 of DOT1X service is marked for notifyingstate and its current state is : DEAD
*Nov  3 22:14:01.829: TAC+: Using default tacacs server-group "port49" list.
*Nov  3 22:14:01.829: % TAC+: Index :1 | Count : 0 
*Nov  3 22:14:01.829: % TAC+:server handle : D2000008 
*Nov  3 22:14:01.829: % TAC+:server name   : port49-1
*Nov  3 22:14:01.829: % TAC+:server addr   : 172.100.100.1 
*Nov  3 22:14:01.829: TAC+: Opening TCP/IP to 172.100.100.1/49 timeout=5
*Nov  3 22:14:01.830: TAC+: TCP/IP open to 172.100.100.1/49 failed -- Connection refused by remote host
*Nov  3 22:14:01.830: % TAC+: Index :2 | Count : 2 
*Nov  3 22:14:01.830: % TAC+:server handle : CE000009 
*Nov  3 22:14:01.830: % TAC+:server name   : port49-2
*Nov  3 22:14:01.830: % TAC+:server addr   : 172.100.100.2 
*Nov  3 22:14:01.830: TAC+: Opening TCP/IP to 172.100.100.2/49 timeout=5
*Nov  3 22:14:01.831: TAC+: TCP/IP open to 172.100.100.2/49 failed -- Connection refused by remote host
*Nov  3 22:14:01.832: TPLUS: Queuing AAA Accounting request 4034 for processing
*Nov  3 22:14:01.832: TPLUS: processing accounting request id 4034
*Nov  3 22:14:01.832: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.832: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.832: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.832: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.832: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.832: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.832: TPLUS: Using server 172.100.100.1
*Nov  3 22:14:01.832: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.832: TPLUS(00000FC2)/0/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.833: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:14:01.833: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.833: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.833: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.833: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.833: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.833: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.833: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.833: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:14:01.833: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.833: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.833: TPLUS(00000FC2)/7E27F25F0C68: releasing old socket 0
*Nov  3 22:14:01.833: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Socket 1 is in wait state
*Nov  3 22:14:01.834: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:14:01.834: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.834: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.834: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.834: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.834: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.834: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.834: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.834: TPLUS: Choosing next server 172.100.100.1
*Nov  3 22:14:01.834: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.834: TPLUS(00000FC2)/0/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.834: TPLUS(00000FC2)/7E27F25F0C68: releasing old socket 1
*Nov  3 22:14:01.834: TPLUS(00000FC2)/0/NB_WAIT/7E27F25F0C68: Socket 0 is in wait state
*Nov  3 22:14:01.835: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:14:01.835: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.835: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.835: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.835: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.835: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.835: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.835: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.835: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:14:01.835: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.835: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.835: TPLUS(00000FC2)/7E27F25F0C68: releasing old socket 0
*Nov  3 22:14:01.835: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Socket 1 is in wait state
*Nov  3 22:14:01.836: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:14:01.836: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.836: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.836: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.836: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.836: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.836: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.836: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.836: TPLUS: Choosing next server 172.100.100.1
*Nov  3 22:14:01.836: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.836: TPLUS(00000FC2)/0/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.836: TPLUS(00000FC2)/7E27F25F0C68: releasing old socket 1
*Nov  3 22:14:01.836: TPLUS(00000FC2)/0/NB_WAIT/7E27F25F0C68: Socket 0 is in wait state
*Nov  3 22:14:01.837: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:14:01.837: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.837: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.837: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.837: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.837: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.837: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.837: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.837: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:14:01.837: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.837: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.837: TPLUS(00000FC2)/7E27F25F0C68: releasing old socket 0
*Nov  3 22:14:01.837: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Socket 1 is in wait state
*Nov  3 22:14:01.838: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:14:01.838: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.838: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.838: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.838: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.838: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.838: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.838: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.838: TPLUS: Choosing next server 172.100.100.1
*Nov  3 22:14:01.838: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.839: TPLUS(00000FC2)/0/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.839: TPLUS(00000FC2)/7E27F25F0C68: releasing old socket 1
*Nov  3 22:14:01.839: TPLUS(00000FC2)/0/NB_WAIT/7E27F25F0C68: Socket 0 is in wait state
*Nov  3 22:14:01.839: TPLUS(00000FC2)/0/NB_WAIT: socket event 2
*Nov  3 22:14:01.839: TPLUS(00000FC2)/0/NB_WAIT: write to 172.100.100.1 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.839: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.839: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.839: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.839: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.839: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.839: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.839: TPLUS: Choosing next server 172.100.100.2
*Nov  3 22:14:01.839: TPLUS: Source IP selected is: 10.0.0.15
*Nov  3 22:14:01.839: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Started 5 sec timeout
*Nov  3 22:14:01.839: TPLUS(00000FC2)/7E27F25F0C68: releasing old socket 0
*Nov  3 22:14:01.839: TPLUS(00000FC2)/1/NB_WAIT/7E27F25F0C68: Socket 1 is in wait state
*Nov  3 22:14:01.840: TPLUS(00000FC2)/1/NB_WAIT: socket event 2
*Nov  3 22:14:01.840: TPLUS(00000FC2)/1/NB_WAIT: write to 172.100.100.2 failed with errno 257((ENOTCONN))
*Nov  3 22:14:01.840: TPLUS: Sending AV task_id=4080
*Nov  3 22:14:01.840: TPLUS: Sending AV timezone=UTC
*Nov  3 22:14:01.840: TPLUS: Sending AV service=shell
*Nov  3 22:14:01.840: TPLUS: Sending AV priv-lvl=1
*Nov  3 22:14:01.840: TPLUS: Sending AV cmd=show tacacs <cr>
*Nov  3 22:14:01.840: TPLUS: Accounting request created for 4034(breakglass)
*Nov  3 22:14:01.840: TPLUS(00000FC2)/1/7E27F25F0C68: Processing the reply packet
*Nov  3 22:14:02.085: TAC+: Using default tacacs server-group "port49" list.
*Nov  3 22:14:02.085: % TAC+: Index :1 | Count : 0 
*Nov  3 22:14:02.085: % TAC+:server handle : D2000008 
*Nov  3 22:14:02.085: % TAC+:server name   : port49-1
*Nov  3 22:14:02.085: % TAC+:server addr   : 172.100.100.1 
xe1#

(no records at all reached the decision log)
```
