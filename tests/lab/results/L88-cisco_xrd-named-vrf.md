# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-04 by TestL88.

- named-VRF pass: the management interface and the SSH server moved into vrf mgmt by the lab scaffolding (`vrf mgmt;  address-family ipv4 unicast; exit; exit; interface MgmtEth0/RP0/CPU0/0;  vrf mgmt;  ipv4 address 172.100.100.61 255.255.255.0; exit; ssh server vrf mgmt`)
- `show vrf all` after the move: Wed Nov 4 02:32:46.588 UTC VRF RD RT AFI SAFI mgmt not set
- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `terminal length 0`: Wed Nov 4 02:33:04.072 UTC
- `show running-config interface MgmtEth0/RP0/CPU0/0`: Wed Nov 4 02:33:04.324 UTC interface MgmtEth0/RP0/CPU0/0 vrf mgmt ipv4 address 172.100.100.61 255.255.255.0 !
- `show ipv4 vrf all interface brief`: Wed Nov 4 02:33:04.575 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up mgmt
- `show running-config router static`: Wed Nov 4 02:33:04.826 UTC % No such configuration item(s)
- `show running-config ssh`: Wed Nov 4 02:33:05.077 UTC ssh server v2 ssh server vrf mgmt
- `show vrf all`: Wed Nov 4 02:33:05.326 UTC VRF RD RT AFI SAFI mgmt not set
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 31s before port49 saw it
- teardown, `show ipv4 vrf all interface brief`: Wed Nov 4 02:40:32.463 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up default
- teardown, `show running-config ssh`: Wed Nov 4 02:40:32.714 UTC ssh server v2
- teardown: the undo push said "commit": neither the configuration prompt nor a question this dialogue knows within 180s; the read-back said <nil>

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 1.75s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 2, port49 first saw one at +24s |
| b | PASS | break-glass login with port49d stopped: ok true in 120ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 500ms: logged in, `show version` printed "'Wed Nov 4 02:33:45.506 UTC'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 5.59s, `show version` output "'Wed Nov 4 02:34:16.115 UTC'" |
| e | PASS | login with a one-time credential (login attempt 2, 51s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] Wed Nov 4 02:35:22.448 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 31.05s; connections the first server reset: 4; port49 redeemed the credential: true; tries 2, the login reached port49 after 31s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`, committed; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`); second `show version`, same session: refused in 5.13s: `% Command authorization failed`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.6s; break-glass login plus three `show version`: logged in and ran them in 16.42s |
| h | NOT MEASURED | the harness does not run cell h yet |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=/dev/pts/3
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=/dev/pts/3
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=/dev/pts/2
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=/dev/pts/2
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=/dev/pts/2
  event=account verdict= reason= flags=start user=alice01 port=/dev/pts/2
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=/dev/pts/2
  event=account verdict= reason= flags=stop user=alice01 port=/dev/pts/2
  event=account verdict= reason= flags=stop user=alice01 port=/dev/pts/2
  event=account verdict= reason= flags=start user=alice01 port=/dev/pts/3
  event=authorize_command verdict=deny reason=no_permit_dominates_deny flags= user=alice01 port=/dev/pts/3
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=/dev/pts/2
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=/dev/pts/2
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=/dev/pts/2
  event=account verdict= reason= flags=start user=alice02 port=/dev/pts/2
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=/dev/pts/2
the wire during the login (headers only):
13 connections from the device in the window: 13 with a SYN, 13 answered SYN-ACK, 4 with an RST
+200ms 172.100.100.1 sport 41459: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.1 sport 23038: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+3.8s 172.100.100.1 sport 27853: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.8s 172.100.100.2 sport 37433: SYN true SYN-ACK true; device packets 8, server packets 4; FIN dev true srv true; RST dev false srv false
+29s 172.100.100.1 sport 42442: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+30.5s 172.100.100.2 sport 22341: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+30.6s 172.100.100.2 sport 60187: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.6s 172.100.100.2 sport 28149: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 47500: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31s 172.100.100.2 sport 34311: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 51296: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 15700: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 56729: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
Wed Nov  4 02:36:02.473 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Wed Nov  4 02:36:02.723 UTC
RP/0/RP0/CPU0:Nov  4 02:28:44.621 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:29:09.349 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:29:29.405 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:29:47.042 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:32:51.879 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:32:51.881 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 02:33:02.613 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.267 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.515 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:33:07.607 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000019: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:33:22.677 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:33:45.760 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000025: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:34:05.824 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:34:20.866 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000029: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:34:40.930 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:35:33.051 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000047: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:35:33.915 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Wed Nov  4 02:36:02.979 UTC
RP/0/RP0/CPU0:Nov  4 02:28:44.621 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:29:09.349 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:29:29.405 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:29:47.042 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:32:51.879 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:32:51.881 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 02:33:02.613 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.266 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.271 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.512 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:33:07.516 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:33:07.607 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000019: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:33:22.677 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:33:45.760 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000025: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:34:05.824 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:34:20.866 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000029: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:34:40.930 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:35:33.051 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000047: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:35:33.915 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Wed Nov  4 02:36:03.230 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Wed Nov  4 02:36:03.483 UTC
RP/0/RP0/CPU0:xrd1#

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (22s).

The change: port49d's broker.policy_file given `- {match: {name: xrd1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 02:36:33.466Z; port49d applied the reload, saying `port49d: policy reloaded`, between 02:36:35.000Z and 02:36:35.026Z, and the change instant the capture is read against is 02:36:35.000Z; the command in flight was sent at 02:36:35.026Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 5.13s: `% Command authorization failed` |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.6s |
| break-glass login plus three `show version` | logged in and ran them in 16.42s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×2; `event=unvalidated reason=device_unknown <LONG> device=xrd1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×2; `event=unvalidated <LONG> type=authen` ×1; `event=unvalidated <LONG> type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 51931 | 02:36:18.311Z | false | (not observed) | (not observed) | not reset by port49d |
| 38916 | 02:36:26.754Z | false | (not observed) | 02:36:26.754Z | reset before the change |
| 38108 | 02:36:30.594Z | true | 02:36:35.030Z | 02:36:35.030Z | **reset mid-connection**: open across the change |
| 46592 | 02:36:35.082Z | false | 02:36:35.083Z | 02:36:35.083Z | reset at its first packet after the change |
| 18486 | 02:36:35.137Z | false | 02:36:35.138Z | 02:36:35.138Z | reset |
| 26463 | 02:36:35.190Z | false | 02:36:35.192Z | 02:36:35.192Z | reset at its first packet after the change |
| 22320 | 02:36:35.244Z | false | 02:36:35.246Z | 02:36:35.245Z | reset |
| 20597 | 02:36:35.298Z | false | (not observed) | 02:36:35.299Z | reset before the device sent on it (refused at Accept) |
| 46104 | 02:36:40.389Z | false | (not observed) | (not observed) | not reset by port49d |
| 36483 | 02:36:40.512Z | false | 02:36:40.514Z | 02:36:40.514Z | reset at its first packet after the change |
| 24567 | 02:36:40.566Z | false | 02:36:40.567Z | 02:36:40.567Z | reset |
| 60095 | 02:36:40.618Z | false | 02:36:40.619Z | 02:36:40.619Z | reset |
| 27581 | 02:36:40.671Z | false | 02:36:40.672Z | 02:36:40.672Z | reset |
| 20531 | 02:36:40.724Z | false | 02:36:40.725Z | 02:36:40.725Z | reset at its first packet after the change |
| 26798 | 02:36:40.778Z | false | (not observed) | 02:36:40.779Z | reset before the device sent on it (refused at Accept) |
| 15600 | 02:36:51.958Z | false | (not observed) | 02:36:51.958Z | reset before the device sent on it (refused at Accept) |
| 48916 | 02:36:55.649Z | false | (not observed) | (not observed) | not reset by port49d |
| 54692 | 02:36:55.756Z | false | 02:36:55.758Z | 02:36:55.758Z | reset at its first packet after the change |
| 16859 | 02:36:55.810Z | false | 02:36:55.811Z | 02:36:55.811Z | reset |
| 33472 | 02:36:55.862Z | false | 02:36:55.864Z | 02:36:55.864Z | reset |
| 25798 | 02:36:55.915Z | false | 02:36:55.917Z | 02:36:55.917Z | reset at its first packet after the change |
| 39899 | 02:36:55.969Z | false | 02:36:55.970Z | 02:36:55.970Z | reset |
| 38624 | 02:36:56.022Z | false | (not observed) | 02:36:56.023Z | reset before the device sent on it (refused at Accept) |
| 57322 | 02:37:01.249Z | false | (not observed) | (not observed) | not reset by port49d |
| 22531 | 02:37:01.354Z | false | 02:37:01.355Z | 02:37:01.355Z | reset at its first packet after the change |
| 37317 | 02:37:01.406Z | false | 02:37:01.407Z | 02:37:01.407Z | reset |
| 34037 | 02:37:01.458Z | false | 02:37:01.459Z | 02:37:01.459Z | reset |
| 52595 | 02:37:01.510Z | false | 02:37:01.511Z | 02:37:01.511Z | reset at its first packet after the change |
| 50234 | 02:37:01.562Z | false | 02:37:01.563Z | 02:37:01.563Z | reset at its first packet after the change |
| 55303 | 02:37:01.614Z | false | (not observed) | 02:37:01.615Z | reset before the device sent on it (refused at Accept) |
| 56644 | 02:37:06.672Z | false | (not observed) | (not observed) | not reset by port49d |
| 25384 | 02:37:06.771Z | false | 02:37:06.772Z | 02:37:06.772Z | reset at its first packet after the change |
| 49819 | 02:37:06.823Z | false | 02:37:06.824Z | 02:37:06.824Z | reset |
| 47718 | 02:37:06.875Z | false | 02:37:06.875Z | 02:37:06.875Z | reset |
| 47114 | 02:37:06.927Z | false | 02:37:06.928Z | 02:37:06.928Z | reset |
| 38372 | 02:37:06.979Z | false | 02:37:06.980Z | 02:37:06.980Z | reset |
| 36166 | 02:37:07.031Z | false | 02:37:07.033Z | 02:37:07.032Z | reset |
| 54731 | 02:37:07.084Z | false | 02:37:07.086Z | 02:37:07.085Z | reset |
| 35502 | 02:37:07.137Z | false | 02:37:07.139Z | 02:37:07.139Z | reset |
| 62969 | 02:37:07.191Z | false | 02:37:07.192Z | 02:37:07.192Z | reset |
| … | 13 more connection(s) not listed | | | | |

The change began at 02:36:35.000Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 756 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
