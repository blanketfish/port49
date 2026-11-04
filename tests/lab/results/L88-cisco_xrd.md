# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `terminal length 0`: Wed Nov 4 02:08:12.082 UTC
- `show running-config interface MgmtEth0/RP0/CPU0/0`: Wed Nov 4 02:08:12.333 UTC interface MgmtEth0/RP0/CPU0/0 ipv4 address 172.100.100.61 255.255.255.0 !
- `show ipv4 vrf all interface brief`: Wed Nov 4 02:08:12.584 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up default
- `show running-config router static`: Wed Nov 4 02:08:12.833 UTC % No such configuration item(s)
- `show running-config ssh`: Wed Nov 4 02:08:13.087 UTC ssh server v2
- `show vrf all`: Wed Nov 4 02:08:13.333 UTC
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 31s before port49 saw it

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 2.308s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 2, port49 first saw one at +24s |
| b | PASS | break-glass login with port49d stopped: ok true in 110ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 500ms: logged in, `show version` printed "'Wed Nov 4 02:08:53.940 UTC'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 5.56s, `show version` output "'Wed Nov 4 02:09:24.519 UTC'" |
| e | PASS | login with a one-time credential (login attempt 2, 51s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] Wed Nov 4 02:10:30.850 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 31.04s; connections the first server reset: 4; port49 redeemed the credential: true; tries 2, the login reached port49 after 31s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`, committed; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`); second `show version`, same session: refused in 5.13s: `% Command authorization failed`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.69s; break-glass login plus three `show version`: logged in and ran them in 16.57s |
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
+200ms 172.100.100.1 sport 60705: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.1 sport 57134: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+3.8s 172.100.100.1 sport 23297: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.2s 172.100.100.2 sport 54954: SYN true SYN-ACK true; device packets 8, server packets 4; FIN dev true srv true; RST dev false srv false
+29s 172.100.100.1 sport 50820: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+30.5s 172.100.100.2 sport 49980: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+30.6s 172.100.100.2 sport 22110: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.6s 172.100.100.2 sport 51208: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 60469: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31s 172.100.100.2 sport 65424: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 23078: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 32043: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 48050: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
Wed Nov  4 02:11:10.864 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Wed Nov  4 02:11:11.115 UTC
RP/0/RP0/CPU0:Nov  4 02:06:57.797 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:07:23.414 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:07:43.479 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:07:59.901 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:07:59.902 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 02:08:10.596 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 02:08:15.615 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:08:30.653 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:08:54.065 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000016: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:09:14.129 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:09:29.280 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:09:49.344 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:10:41.404 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000038: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:10:41.713 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Wed Nov  4 02:11:11.370 UTC
RP/0/RP0/CPU0:Nov  4 02:06:57.797 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:07:23.414 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:07:43.479 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:07:59.901 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 02:07:59.902 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 02:08:10.596 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.273 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.277 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.520 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 02:08:15.525 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 02:08:15.615 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:08:30.653 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:08:54.065 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000016: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:09:14.129 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:09:29.280 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:09:49.344 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 02:10:41.404 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000038: Connection timed out 
RP/0/RP0/CPU0:Nov  4 02:10:41.713 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Wed Nov  4 02:11:11.622 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Wed Nov  4 02:11:11.874 UTC
RP/0/RP0/CPU0:xrd1#

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (22s).

The change: port49d's broker.policy_file given `- {match: {name: xrd1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 02:11:41.910Z; port49d applied the reload, saying `port49d: policy reloaded`, between 02:11:43.421Z and 02:11:43.447Z, and the change instant the capture is read against is 02:11:43.421Z; the command in flight was sent at 02:11:43.447Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 5.13s: `% Command authorization failed` |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.69s |
| break-glass login plus three `show version` | logged in and ran them in 16.57s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×2; `event=unvalidated reason=device_unknown <LONG> device=xrd1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×2; `event=unvalidated <LONG> type=authen` ×1; `event=unvalidated <LONG> type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 62809 | 02:11:26.650Z | false | (not observed) | (not observed) | not reset by port49d |
| 27292 | 02:11:35.135Z | false | (not observed) | 02:11:35.135Z | reset before the change |
| 33094 | 02:11:39.001Z | true | 02:11:43.451Z | 02:11:43.451Z | **reset mid-connection**: open across the change |
| 18656 | 02:11:43.503Z | false | 02:11:43.504Z | 02:11:43.504Z | reset at its first packet after the change |
| 24599 | 02:11:43.556Z | false | 02:11:43.557Z | 02:11:43.557Z | reset |
| 35035 | 02:11:43.610Z | false | 02:11:43.611Z | 02:11:43.611Z | reset at its first packet after the change |
| 29257 | 02:11:43.663Z | false | 02:11:43.664Z | 02:11:43.664Z | reset |
| 17541 | 02:11:43.716Z | false | (not observed) | 02:11:43.717Z | reset before the device sent on it (refused at Accept) |
| 46339 | 02:11:48.806Z | false | (not observed) | (not observed) | not reset by port49d |
| 42404 | 02:11:48.935Z | false | 02:11:48.936Z | 02:11:48.936Z | reset at its first packet after the change |
| 60913 | 02:11:48.988Z | false | 02:11:48.989Z | 02:11:48.989Z | reset at its first packet after the change |
| 37643 | 02:11:49.042Z | false | 02:11:49.043Z | 02:11:49.043Z | reset |
| 57196 | 02:11:49.095Z | false | 02:11:49.096Z | 02:11:49.096Z | reset |
| 37840 | 02:11:49.149Z | false | 02:11:49.150Z | 02:11:49.150Z | reset |
| 40813 | 02:11:49.202Z | false | (not observed) | 02:11:49.204Z | reset before the device sent on it (refused at Accept) |
| 58389 | 02:12:00.358Z | false | (not observed) | 02:12:00.358Z | reset before the device sent on it (refused at Accept) |
| 24063 | 02:12:04.084Z | false | (not observed) | (not observed) | not reset by port49d |
| 50439 | 02:12:04.192Z | false | 02:12:04.194Z | 02:12:04.194Z | reset at its first packet after the change |
| 33048 | 02:12:04.246Z | false | 02:12:04.247Z | 02:12:04.247Z | reset |
| 19014 | 02:12:04.299Z | false | 02:12:04.301Z | 02:12:04.301Z | reset |
| 48595 | 02:12:04.354Z | false | 02:12:04.355Z | 02:12:04.355Z | reset |
| 22497 | 02:12:04.407Z | false | 02:12:04.408Z | 02:12:04.408Z | reset at its first packet after the change |
| 58248 | 02:12:04.460Z | false | (not observed) | 02:12:04.461Z | reset before the device sent on it (refused at Accept) |
| 25803 | 02:12:09.778Z | false | (not observed) | (not observed) | not reset by port49d |
| 50129 | 02:12:09.889Z | false | 02:12:09.891Z | 02:12:09.891Z | reset at its first packet after the change |
| 62011 | 02:12:09.943Z | false | 02:12:09.945Z | 02:12:09.945Z | reset |
| 19336 | 02:12:09.997Z | false | 02:12:09.998Z | 02:12:09.998Z | reset at its first packet after the change |
| 17374 | 02:12:10.050Z | false | 02:12:10.052Z | 02:12:10.051Z | reset |
| 65092 | 02:12:10.104Z | false | 02:12:10.105Z | 02:12:10.105Z | reset |
| 22532 | 02:12:10.158Z | false | (not observed) | 02:12:10.160Z | reset before the device sent on it (refused at Accept) |
| 56215 | 02:12:15.219Z | false | (not observed) | (not observed) | not reset by port49d |
| 34273 | 02:12:15.317Z | false | 02:12:15.318Z | 02:12:15.318Z | reset at its first packet after the change |
| 49483 | 02:12:15.369Z | false | 02:12:15.370Z | 02:12:15.370Z | reset |
| 64398 | 02:12:15.422Z | false | 02:12:15.422Z | 02:12:15.422Z | reset |
| 46853 | 02:12:15.473Z | false | 02:12:15.474Z | 02:12:15.474Z | reset |
| 39607 | 02:12:15.526Z | false | 02:12:15.526Z | 02:12:15.526Z | reset |
| 34702 | 02:12:20.476Z | false | (not observed) | (not observed) | not reset by port49d |
| 24846 | 02:12:20.574Z | false | 02:12:20.575Z | 02:12:20.575Z | reset at its first packet after the change |
| 21630 | 02:12:20.626Z | false | 02:12:20.627Z | 02:12:20.627Z | reset |
| 46616 | 02:12:20.678Z | false | 02:12:20.679Z | 02:12:20.679Z | reset |
| … | 11 more connection(s) not listed | | | | |

The change began at 02:11:43.421Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `<LONG>` — 730 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r <LONG> -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
