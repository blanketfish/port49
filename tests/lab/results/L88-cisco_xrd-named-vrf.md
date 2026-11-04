# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-04 by TestL88.

- named-VRF pass: the management interface and the SSH server moved into vrf mgmt by the lab scaffolding (`vrf mgmt;  address-family ipv4 unicast; exit; exit; interface MgmtEth0/RP0/CPU0/0;  vrf mgmt;  ipv4 address 172.100.100.61 255.255.255.0; exit; ssh server vrf mgmt`)
- `show vrf all` after the move: Wed Nov 4 06:20:26.259 UTC VRF RD RT AFI SAFI mgmt not set
- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `terminal length 0`: Wed Nov 4 06:20:43.746 UTC
- `show running-config interface MgmtEth0/RP0/CPU0/0`: Wed Nov 4 06:20:43.999 UTC interface MgmtEth0/RP0/CPU0/0 vrf mgmt ipv4 address 172.100.100.61 255.255.255.0 !
- `show ipv4 vrf all interface brief`: Wed Nov 4 06:20:44.250 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up mgmt
- `show running-config router static`: Wed Nov 4 06:20:44.501 UTC % No such configuration item(s)
- `show running-config ssh`: Wed Nov 4 06:20:44.752 UTC ssh server v2 ssh server vrf mgmt
- `show vrf all`: Wed Nov 4 06:20:45.002 UTC VRF RD RT AFI SAFI mgmt not set
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 31s before port49 saw it
- teardown, `show ipv4 vrf all interface brief`: Wed Nov 4 06:25:31.692 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up default
- teardown, `show running-config ssh`: Wed Nov 4 06:25:31.943 UTC ssh server v2
- teardown: the undo push said EOF; the read-back said <nil>

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 1.771s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 2, port49 first saw one at +24s |
| b | PASS | break-glass login with port49d stopped: ok true in 120ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's own close line appeared at +5.5s: port49d: store: 5 consecutive store health checks failed over 4s (the last: the context pool: store: unavailable: context deadline exceeded); closing every listener so that devices use their local method; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 700ms: logged in, `show version` printed "'Wed Nov 4 06:21:24.869 UTC'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 5.58s, `show version` output "'Wed Nov 4 06:21:55.482 UTC'" |
| e | PASS | login with a one-time credential (login attempt 2, 51s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] Wed Nov 4 06:23:01.734 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 31.08s; connections the first server reset: 4; port49 redeemed the credential: true; tries 2, the login reached port49 after 31s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`, committed; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`); second `show version`, same session: refused in 5.13s: `% Command authorization failed`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.8s; break-glass login plus three `show version`: logged in and ran them in 16.37s |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=/dev/pts/3
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=/dev/pts/3
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=/dev/pts/3
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=/dev/pts/3
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=/dev/pts/3
  event=account verdict= reason= flags=start user=alice01 port=/dev/pts/3
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=/dev/pts/3
  event=account verdict= reason= flags=stop user=alice01 port=/dev/pts/3
  event=account verdict= reason= flags=stop user=alice01 port=/dev/pts/3
  event=account verdict= reason= flags=start user=alice01 port=/dev/pts/4
  event=authorize_command verdict=deny reason=no_permit_dominates_deny flags= user=alice01 port=/dev/pts/4
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=/dev/pts/3
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=/dev/pts/3
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=/dev/pts/3
  event=account verdict= reason= flags=start user=alice02 port=/dev/pts/3
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=/dev/pts/3
the wire during the login (headers only):
13 connections from the device in the window: 13 with a SYN, 13 answered SYN-ACK, 4 with an RST
+200ms 172.100.100.1 sport 25444: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.1 sport 16394: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+3.8s 172.100.100.1 sport 52749: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.8s 172.100.100.2 sport 18611: SYN true SYN-ACK true; device packets 8, server packets 4; FIN dev true srv true; RST dev false srv false
+29s 172.100.100.1 sport 31071: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+30.5s 172.100.100.2 sport 37302: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+30.5s 172.100.100.2 sport 37684: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 29649: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 65286: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31s 172.100.100.2 sport 53671: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 45881: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 15244: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 42493: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
Wed Nov  4 06:23:41.734 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Wed Nov  4 06:23:41.985 UTC
RP/0/RP0/CPU0:Nov  4 06:19:03.626 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 06:19:29.081 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:19:49.136 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:20:07.051 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:20:31.556 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 06:20:31.558 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 06:20:42.268 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000009: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 06:20:47.254 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000011: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:21:02.323 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:21:25.359 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:21:45.421 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:22:00.218 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000021: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:22:20.273 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:23:12.308 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000039: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:23:13.227 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Wed Nov  4 06:23:42.239 UTC
RP/0/RP0/CPU0:Nov  4 06:19:03.626 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 06:19:29.081 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:19:49.136 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:20:07.051 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:20:31.556 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 06:20:31.558 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 06:20:42.268 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000009: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:46.936 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:46.939 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:47.183 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 06:20:47.189 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 06:20:47.254 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000011: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:21:02.323 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:21:25.359 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:21:45.421 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:22:00.218 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000021: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:22:20.273 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 06:23:12.308 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000039: Connection timed out 
RP/0/RP0/CPU0:Nov  4 06:23:13.227 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Wed Nov  4 06:23:42.494 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Wed Nov  4 06:23:42.742 UTC
RP/0/RP0/CPU0:xrd1#

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (22s).

The change: port49d's broker.policy_file given `- {match: {name: xrd1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 06:24:12.687Z; port49d applied the reload, saying `port49d: policy reloaded`, between 06:24:14.254Z and 06:24:14.280Z, and the change instant the capture is read against is 06:24:14.254Z; the command in flight was sent at 06:24:14.280Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 5.13s: `% Command authorization failed` |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.8s |
| break-glass login plus three `show version` | logged in and ran them in 16.37s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×2; `event=unvalidated reason=device_unknown <LONG> device=xrd1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×2; `event=unvalidated <LONG> type=authen` ×1; `event=unvalidated <LONG> type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 62639 | 06:23:57.442Z | false | (not observed) | (not observed) | not reset by port49d |
| 62144 | 06:24:05.368Z | true | 06:24:14.283Z | 06:24:14.283Z | **reset mid-connection**: open across the change |
| 62003 | 06:24:05.941Z | false | (not observed) | 06:24:05.941Z | reset before the change |
| 58565 | 06:24:14.335Z | false | 06:24:14.336Z | 06:24:14.336Z | reset at its first packet after the change |
| 44636 | 06:24:14.388Z | false | 06:24:14.389Z | 06:24:14.388Z | reset |
| 54255 | 06:24:14.440Z | false | 06:24:14.440Z | 06:24:14.440Z | reset at its first packet after the change |
| 51713 | 06:24:14.492Z | false | 06:24:14.492Z | 06:24:14.492Z | reset |
| 53750 | 06:24:14.544Z | false | (not observed) | 06:24:14.545Z | reset before the device sent on it (refused at Accept) |
| 29839 | 06:24:19.639Z | false | (not observed) | (not observed) | not reset by port49d |
| 25187 | 06:24:19.766Z | false | 06:24:19.767Z | 06:24:19.767Z | reset at its first packet after the change |
| 15988 | 06:24:19.818Z | false | 06:24:19.819Z | 06:24:19.819Z | reset |
| 25178 | 06:24:19.871Z | false | 06:24:19.872Z | 06:24:19.872Z | reset |
| 41628 | 06:24:19.923Z | false | 06:24:19.924Z | 06:24:19.924Z | reset |
| 51998 | 06:24:19.975Z | false | 06:24:19.976Z | 06:24:19.976Z | reset |
| 34762 | 06:24:20.027Z | false | (not observed) | 06:24:20.028Z | reset before the device sent on it (refused at Accept) |
| 62600 | 06:24:31.027Z | false | (not observed) | 06:24:31.027Z | reset before the device sent on it (refused at Accept) |
| 40295 | 06:24:34.912Z | false | (not observed) | (not observed) | not reset by port49d |
| 30166 | 06:24:35.017Z | false | 06:24:35.017Z | 06:24:35.018Z | reset at its first packet after the change |
| 16058 | 06:24:35.069Z | false | 06:24:35.070Z | 06:24:35.070Z | reset at its first packet after the change |
| 64790 | 06:24:35.121Z | false | 06:24:35.122Z | 06:24:35.122Z | reset |
| 43859 | 06:24:35.174Z | false | 06:24:35.175Z | 06:24:35.175Z | reset |
| 53596 | 06:24:35.226Z | false | 06:24:35.227Z | 06:24:35.227Z | reset at its first packet after the change |
| 62845 | 06:24:35.279Z | false | (not observed) | 06:24:35.280Z | reset before the device sent on it (refused at Accept) |
| 16221 | 06:24:40.708Z | false | (not observed) | (not observed) | not reset by port49d |
| 63578 | 06:24:40.819Z | false | 06:24:40.821Z | 06:24:40.821Z | reset at its first packet after the change |
| 35406 | 06:24:40.874Z | false | 06:24:40.876Z | 06:24:40.875Z | reset |
| 58833 | 06:24:40.927Z | false | 06:24:40.929Z | 06:24:40.929Z | reset |
| 35986 | 06:24:40.981Z | false | 06:24:40.983Z | 06:24:40.983Z | reset |
| 30894 | 06:24:41.035Z | false | 06:24:41.036Z | 06:24:41.036Z | reset |
| 23187 | 06:24:41.088Z | false | (not observed) | 06:24:41.090Z | reset before the device sent on it (refused at Accept) |
| 19731 | 06:24:46.147Z | false | (not observed) | (not observed) | not reset by port49d |
| 16785 | 06:24:46.247Z | false | 06:24:46.247Z | 06:24:46.247Z | reset at its first packet after the change |
| 53319 | 06:24:46.299Z | false | 06:24:46.300Z | 06:24:46.300Z | reset at its first packet after the change |
| 20066 | 06:24:46.351Z | false | 06:24:46.351Z | 06:24:46.351Z | reset |
| 39418 | 06:24:46.403Z | false | 06:24:46.403Z | 06:24:46.403Z | reset |
| 19056 | 06:24:46.454Z | false | 06:24:46.454Z | 06:24:46.454Z | reset |
| 35063 | 06:24:46.506Z | false | 06:24:46.507Z | 06:24:46.506Z | reset |
| 37807 | 06:24:46.558Z | false | 06:24:46.559Z | 06:24:46.558Z | reset |
| 19985 | 06:24:46.610Z | false | 06:24:46.611Z | 06:24:46.611Z | reset |
| 16767 | 06:24:46.662Z | false | 06:24:46.663Z | 06:24:46.663Z | reset |
| … | 12 more connection(s) not listed | | | | |

The change began at 06:24:14.254Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 756 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
