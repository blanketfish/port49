# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-04 by TestL88.

- named-VRF pass: the management interface and the SSH server moved into vrf mgmt by the lab scaffolding (`vrf mgmt;  address-family ipv4 unicast; exit; exit; interface MgmtEth0/RP0/CPU0/0;  vrf mgmt;  ipv4 address 172.100.100.61 255.255.255.0; exit; ssh server vrf mgmt`)
- `show vrf all` after the move: Wed Nov 4 02:17:07.111 UTC VRF RD RT AFI SAFI mgmt not set
- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `terminal length 0`: Wed Nov 4 02:17:24.590 UTC
- `show running-config interface MgmtEth0/RP0/CPU0/0`: Wed Nov 4 02:17:24.843 UTC interface MgmtEth0/RP0/CPU0/0 vrf mgmt ipv4 address 172.100.100.61 255.255.255.0 !
- `show ipv4 vrf all interface brief`: Wed Nov 4 02:17:25.112 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up mgmt
- `show running-config router static`: Wed Nov 4 02:17:25.345 UTC % No such configuration item(s)
- `show running-config ssh`: Wed Nov 4 02:17:25.593 UTC ssh server v2 ssh server vrf mgmt
- `show vrf all`: Wed Nov 4 02:17:25.844 UTC VRF RD RT AFI SAFI mgmt not set
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 31s before port49 saw it

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 2.145s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 2, port49 first saw one at +24s |
| b | PASS | break-glass login with port49d stopped: ok true in 110ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 500ms: logged in, `show version` printed "'Wed Nov 4 02:18:06.691 UTC'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 5.58s, `show version` output "'Wed Nov 4 02:18:37.280 UTC'" |
| e | PASS | login with a one-time credential (login attempt 2, 51s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] Wed Nov 4 02:19:43.573 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 31.11s; connections the first server reset: 4; port49 redeemed the credential: true; tries 2, the login reached port49 after 31s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`, committed; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`); second `show version`, same session: refused in 5.13s: `% Command authorization failed`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.8s; break-glass login plus three `show version`: logged in and ran them in 16.37s |
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
+200ms 172.100.100.1 sport 65043: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.1 sport 27535: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+3.8s 172.100.100.1 sport 32187: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.2s 172.100.100.2 sport 55691: SYN true SYN-ACK true; device packets 8, server packets 4; FIN dev true srv true; RST dev false srv false
+29s 172.100.100.1 sport 28773: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+30.5s 172.100.100.2 sport 58598: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+30.6s 172.100.100.2 sport 51231: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 52559: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.8s 172.100.100.2 sport 40801: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 49356: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 48075: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.2s 172.100.100.2 sport 30363: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.2s 172.100.100.2 sport 34944: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
Wed Nov  4 02:20:23.594 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Wed Nov  4 02:20:23.848 UTC
RP/0/RP0/CPU0:Nov  4 02:12:54.608 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:13:29.863 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:13:49.927 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:14:07.562 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:17:12.403 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:17:12.404 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 02:17:23.121 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:27.788 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:17:28.128 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000019: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:17:43.185 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:18:06.428 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000025: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:18:26.491 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:18:42.046 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000029: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:19:02.101 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:19:54.167 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000047: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:19:54.373 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Wed Nov  4 02:20:24.102 UTC
RP/0/RP0/CPU0:Nov  4 02:12:54.608 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:13:29.863 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:13:49.927 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:14:07.562 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:17:12.403 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:17:12.404 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 02:17:23.121 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:27.787 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:27.792 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:28.035 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:17:28.039 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:17:28.128 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000019: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:17:43.185 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:18:06.428 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000025: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:18:26.491 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:18:42.046 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000029: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:19:02.101 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:19:54.167 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000047: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:19:54.373 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Wed Nov  4 02:20:24.356 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Wed Nov  4 02:20:24.606 UTC
RP/0/RP0/CPU0:xrd1#

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (22s).

The change: port49d's broker.policy_file given `- {match: {name: xrd1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 02:20:54.782Z; port49d applied the reload, saying `port49d: policy reloaded`, between 02:20:56.167Z and 02:20:56.193Z, and the change instant the capture is read against is 02:20:56.167Z; the command in flight was sent at 02:20:56.193Z.

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
| 33008 | 02:20:39.441Z | false | (not observed) | (not observed) | not reset by port49d |
| 59150 | 02:20:47.878Z | false | (not observed) | 02:20:47.878Z | reset before the change |
| 32014 | 02:20:51.722Z | true | 02:20:56.198Z | 02:20:56.198Z | **reset mid-connection**: open across the change |
| 30486 | 02:20:56.250Z | false | 02:20:56.252Z | 02:20:56.252Z | reset at its first packet after the change |
| 52325 | 02:20:56.304Z | false | 02:20:56.306Z | 02:20:56.306Z | reset |
| 38311 | 02:20:56.359Z | false | 02:20:56.360Z | 02:20:56.361Z | reset at its first packet after the change |
| 50920 | 02:20:56.413Z | false | 02:20:56.414Z | 02:20:56.414Z | reset |
| 53447 | 02:20:56.466Z | false | (not observed) | 02:20:56.467Z | reset before the device sent on it (refused at Accept) |
| 21920 | 02:21:01.553Z | false | (not observed) | (not observed) | not reset by port49d |
| 62939 | 02:21:01.684Z | false | 02:21:01.686Z | 02:21:01.686Z | reset at its first packet after the change |
| 56756 | 02:21:01.737Z | false | 02:21:01.739Z | 02:21:01.738Z | reset |
| 36860 | 02:21:01.790Z | false | 02:21:01.792Z | 02:21:01.792Z | reset |
| 20430 | 02:21:01.844Z | false | 02:21:01.845Z | 02:21:01.845Z | reset |
| 32584 | 02:21:01.898Z | false | 02:21:01.899Z | 02:21:01.899Z | reset |
| 37999 | 02:21:01.952Z | false | (not observed) | 02:21:01.953Z | reset before the device sent on it (refused at Accept) |
| 28985 | 02:21:13.097Z | false | (not observed) | 02:21:13.098Z | reset before the device sent on it (refused at Accept) |
| 49895 | 02:21:16.829Z | false | (not observed) | (not observed) | not reset by port49d |
| 58451 | 02:21:16.934Z | false | 02:21:16.936Z | 02:21:16.936Z | reset at its first packet after the change |
| 25146 | 02:21:16.988Z | false | 02:21:16.989Z | 02:21:16.989Z | reset at its first packet after the change |
| 48734 | 02:21:17.041Z | false | 02:21:17.043Z | 02:21:17.043Z | reset |
| 57890 | 02:21:17.095Z | false | 02:21:17.096Z | 02:21:17.096Z | reset at its first packet after the change |
| 62205 | 02:21:17.148Z | false | 02:21:17.150Z | 02:21:17.150Z | reset |
| 23520 | 02:21:17.201Z | false | (not observed) | 02:21:17.202Z | reset before the device sent on it (refused at Accept) |
| 33246 | 02:21:22.631Z | false | (not observed) | (not observed) | not reset by port49d |
| 46397 | 02:21:22.740Z | false | 02:21:22.742Z | 02:21:22.742Z | reset at its first packet after the change |
| 26771 | 02:21:22.794Z | false | 02:21:22.796Z | 02:21:22.796Z | reset |
| 16216 | 02:21:22.849Z | false | 02:21:22.850Z | 02:21:22.850Z | reset |
| 28436 | 02:21:22.903Z | false | 02:21:22.904Z | 02:21:22.904Z | reset |
| 44426 | 02:21:22.956Z | false | 02:21:22.958Z | 02:21:22.958Z | reset at its first packet after the change |
| 17710 | 02:21:23.011Z | false | (not observed) | 02:21:23.012Z | reset before the device sent on it (refused at Accept) |
| 17513 | 02:21:28.070Z | false | (not observed) | (not observed) | not reset by port49d |
| 49427 | 02:21:28.169Z | false | 02:21:28.170Z | 02:21:28.170Z | reset at its first packet after the change |
| 55256 | 02:21:28.221Z | false | 02:21:28.222Z | 02:21:28.222Z | reset |
| 22166 | 02:21:28.273Z | false | 02:21:28.274Z | 02:21:28.274Z | reset |
| 23269 | 02:21:28.326Z | false | 02:21:28.327Z | 02:21:28.327Z | reset |
| 33818 | 02:21:28.378Z | false | 02:21:28.379Z | 02:21:28.379Z | reset |
| 32634 | 02:21:28.430Z | false | 02:21:28.431Z | 02:21:28.431Z | reset |
| 51832 | 02:21:28.482Z | false | 02:21:28.483Z | 02:21:28.483Z | reset |
| 65198 | 02:21:28.535Z | false | 02:21:28.536Z | 02:21:28.536Z | reset |
| 55240 | 02:21:28.587Z | false | 02:21:28.588Z | 02:21:28.588Z | reset |
| … | 13 more connection(s) not listed | | | | |

The change began at 02:20:56.167Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 754 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
