# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-03 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 31s before port49 saw it

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 2.043s (); port49 decision for the attempt: verdict="deny" reason="token_not_found" |
| b | PASS | break-glass login with port49d stopped: ok true in 120ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 500ms: logged in, `show version` printed "'Tue Nov 3 23:44:56.024 UTC'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 5.57s, `show version` output "'Tue Nov 3 23:45:26.605 UTC'" |
| e | PASS | login with a one-time credential (login attempt 2, 51s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] Tue Nov 3 23:46:32.896 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 31.02s; connections the first server reset: 4; port49 redeemed the credential: true; first command output:  |
| g | NOT MEASURED | the harness does not run cell g yet |
| h | NOT MEASURED | the harness does not run cell h yet |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=/dev/pts/2
  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=/dev/pts/2
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
+200ms 172.100.100.1 sport 58340: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.1 sport 48620: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+3.8s 172.100.100.1 sport 48646: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+12.2s 172.100.100.2 sport 34266: SYN true SYN-ACK true; device packets 8, server packets 4; FIN dev true srv true; RST dev false srv false
+29s 172.100.100.1 sport 65171: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+30.5s 172.100.100.2 sport 33379: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+30.5s 172.100.100.2 sport 35901: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.6s 172.100.100.2 sport 18298: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 25164: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31s 172.100.100.2 sport 31487: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31s 172.100.100.2 sport 42370: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 52926: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 22405: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
Tue Nov  3 23:47:12.921 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Tue Nov  3 23:47:13.173 UTC
RP/0/RP0/CPU0:Nov  3 23:42:55.021 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  3 23:43:28.162 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:43:48.226 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:44:04.916 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  3 23:44:04.917 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  3 23:44:15.649 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  3 23:44:20.646 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:44:35.704 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:44:56.121 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000016: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:45:16.176 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:45:31.364 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:45:51.428 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:46:43.493 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000038: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:46:46.784 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Tue Nov  3 23:47:13.427 UTC
RP/0/RP0/CPU0:Nov  3 23:42:55.021 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  3 23:43:28.162 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:43:48.226 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:44:04.916 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  3 23:44:04.917 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  3 23:44:15.649 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.604 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.608 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.849 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  3 23:44:17.855 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  3 23:44:20.646 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:44:35.704 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:44:56.121 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000016: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:45:16.176 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:45:31.364 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:45:51.428 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  3 23:46:43.493 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000038: Connection timed out 
RP/0/RP0/CPU0:Nov  3 23:46:46.784 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Tue Nov  3 23:47:13.680 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Tue Nov  3 23:47:13.930 UTC
RP/0/RP0/CPU0:xrd1#

```
