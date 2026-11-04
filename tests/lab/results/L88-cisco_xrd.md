# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-04 by TestL88.

- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `terminal length 0`: Wed Nov 4 08:36:29.891 UTC
- `show running-config interface MgmtEth0/RP0/CPU0/0`: Wed Nov 4 08:36:30.143 UTC interface MgmtEth0/RP0/CPU0/0 ipv4 address 172.100.100.61 255.255.255.0 !
- `show ipv4 vrf all interface brief`: Wed Nov 4 08:36:30.393 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up default
- `show running-config router static`: Wed Nov 4 08:36:30.644 UTC % No such configuration item(s)
- `show running-config ssh`: Wed Nov 4 08:36:30.895 UTC ssh server v2
- `show vrf all`: Wed Nov 4 08:36:31.145 UTC
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 36s before port49 saw it

Capture: `tests/lab/evidence/L88-f-xrd261-cisco_xrd.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 1.961s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 2, port49 first saw one at +24s |
| b | PASS | break-glass login with port49d stopped: ok true in 120ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 500ms: logged in, `show version` printed "'Wed Nov 4 08:37:11.395 UTC'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 5.58s, `show version` output "'Wed Nov 4 08:37:41.988 UTC'" |
| e | PASS | login with a one-time credential (login attempt 2, 51s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] Wed Nov 4 08:38:48.363 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 36.18s; connections the first server reset: 7; port49 redeemed the credential: true; tries 2, the login reached port49 after 36s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`, committed; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`); second `show version`, same session: refused in 5.14s: `% Command authorization failed`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.72s; break-glass login plus three `show version`: logged in and ran them in 16.37s |

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
16 connections from the device in the window: 16 with a SYN, 16 answered SYN-ACK, 7 with an RST
+200ms 172.100.100.1 sport 18881: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.1 sport 32601: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+3.8s 172.100.100.1 sport 57223: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.8s 172.100.100.2 sport 24678: SYN true SYN-ACK true; device packets 8, server packets 4; FIN dev true srv true; RST dev false srv false
+29s 172.100.100.1 sport 33636: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+30.5s 172.100.100.1 sport 39183: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+30.6s 172.100.100.1 sport 55841: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+35.6s 172.100.100.1 sport 25012: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+35.7s 172.100.100.2 sport 21712: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+35.7s 172.100.100.2 sport 40665: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+35.8s 172.100.100.2 sport 23414: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+35.8s 172.100.100.2 sport 47319: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+36.1s 172.100.100.2 sport 15249: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+36.2s 172.100.100.2 sport 43386: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+36.2s 172.100.100.2 sport 45847: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+36.2s 172.100.100.2 sport 58310: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
Wed Nov  4 08:39:32.690 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Wed Nov  4 08:39:32.942 UTC
RP/0/RP0/CPU0:Nov  4 08:35:16.433 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:35:41.250 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:36:01.305 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:36:17.703 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:36:17.705 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 08:36:28.439 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.334 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:36:33.339 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:36:33.339 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:36:33.442 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:36:48.503 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:37:11.567 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000016: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:37:31.631 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:37:46.750 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:38:06.812 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:38:58.976 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000038: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:38:59.782 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:39:19.031 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:39:30.728 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000043: Connection timed out 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Wed Nov  4 08:39:33.210 UTC
RP/0/RP0/CPU0:Nov  4 08:35:16.433 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:35:41.250 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:36:01.305 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:36:17.703 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:36:17.705 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 08:36:28.439 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.087 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.091 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.335 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:36:33.340 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:36:33.442 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:36:48.503 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:37:11.567 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000016: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:37:31.631 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:37:46.750 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:38:06.812 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:38:58.976 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000038: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:38:59.782 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:39:19.031 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:39:30.728 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000043: Connection timed out 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Wed Nov  4 08:39:33.446 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Wed Nov  4 08:39:33.696 UTC
RP/0/RP0/CPU0:xrd1#

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (22s).

The change: port49d's broker.policy_file given `- {match: {name: xrd1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 08:40:03.864Z; port49d applied the reload, saying `port49d: policy reloaded`, between 08:40:05.249Z and 08:40:05.275Z, and the change instant the capture is read against is 08:40:05.249Z; the command in flight was sent at 08:40:05.275Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 5.14s: `% Command authorization failed` |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.72s |
| break-glass login plus three `show version` | logged in and ran them in 16.37s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×2; `event=unvalidated reason=device_unknown <LONG> device=xrd1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×2; `event=unvalidated <LONG> type=authen` ×1; `event=unvalidated <LONG> type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 46605 | 08:39:50.781Z | false | (not observed) | (not observed) | not reset by port49d |
| 64304 | 08:39:56.987Z | false | (not observed) | 08:39:56.987Z | reset before the change |
| 38824 | 08:40:00.825Z | true | 08:40:05.281Z | 08:40:05.281Z | **reset mid-connection**: open across the change |
| 47746 | 08:40:05.333Z | false | 08:40:05.334Z | 08:40:05.335Z | reset at its first packet after the change |
| 43107 | 08:40:05.387Z | false | 08:40:05.388Z | 08:40:05.388Z | reset at its first packet after the change |
| 23738 | 08:40:05.440Z | false | 08:40:05.442Z | 08:40:05.442Z | reset at its first packet after the change |
| 24785 | 08:40:05.494Z | false | 08:40:05.495Z | 08:40:05.495Z | reset at its first packet after the change |
| 60405 | 08:40:05.548Z | false | (not observed) | 08:40:05.549Z | reset before the device sent on it (refused at Accept) |
| 56963 | 08:40:10.636Z | false | (not observed) | (not observed) | not reset by port49d |
| 60153 | 08:40:10.769Z | false | 08:40:10.770Z | 08:40:10.770Z | reset at its first packet after the change |
| 38628 | 08:40:10.822Z | false | 08:40:10.822Z | 08:40:10.822Z | reset at its first packet after the change |
| 15478 | 08:40:10.875Z | false | 08:40:10.876Z | 08:40:10.876Z | reset |
| 45645 | 08:40:10.928Z | false | 08:40:10.930Z | 08:40:10.930Z | reset at its first packet after the change |
| 34225 | 08:40:10.982Z | false | 08:40:10.983Z | 08:40:10.983Z | reset at its first packet after the change |
| 50252 | 08:40:11.035Z | false | (not observed) | 08:40:11.036Z | reset before the device sent on it (refused at Accept) |
| 56844 | 08:40:22.228Z | false | (not observed) | 08:40:22.228Z | reset before the device sent on it (refused at Accept) |
| 56755 | 08:40:25.906Z | false | (not observed) | (not observed) | not reset by port49d |
| 35582 | 08:40:26.010Z | false | 08:40:26.011Z | 08:40:26.012Z | reset at its first packet after the change |
| 32026 | 08:40:26.064Z | false | 08:40:26.066Z | 08:40:26.066Z | reset |
| 48534 | 08:40:26.118Z | false | 08:40:26.119Z | 08:40:26.119Z | reset at its first packet after the change |
| 55344 | 08:40:26.172Z | false | 08:40:26.173Z | 08:40:26.173Z | reset |
| 15244 | 08:40:26.225Z | false | 08:40:26.227Z | 08:40:26.227Z | reset |
| 34950 | 08:40:26.279Z | false | (not observed) | 08:40:26.280Z | reset before the device sent on it (refused at Accept) |
| 60867 | 08:40:31.629Z | false | (not observed) | (not observed) | not reset by port49d |
| 19416 | 08:40:31.736Z | false | 08:40:31.738Z | 08:40:31.738Z | reset at its first packet after the change |
| 23004 | 08:40:31.791Z | false | 08:40:31.792Z | 08:40:31.792Z | reset |
| 46450 | 08:40:31.844Z | false | 08:40:31.846Z | 08:40:31.846Z | reset |
| 27003 | 08:40:31.898Z | false | 08:40:31.900Z | 08:40:31.899Z | reset |
| 63776 | 08:40:31.951Z | false | 08:40:31.953Z | 08:40:31.952Z | reset |
| 50879 | 08:40:32.005Z | false | (not observed) | 08:40:32.006Z | reset before the device sent on it (refused at Accept) |
| 18051 | 08:40:37.065Z | false | (not observed) | (not observed) | not reset by port49d |
| 62275 | 08:40:37.164Z | false | 08:40:37.165Z | 08:40:37.165Z | reset at its first packet after the change |
| 49867 | 08:40:37.216Z | false | 08:40:37.217Z | 08:40:37.217Z | reset at its first packet after the change |
| 41232 | 08:40:37.269Z | false | 08:40:37.270Z | 08:40:37.270Z | reset |
| 61466 | 08:40:37.322Z | false | 08:40:37.323Z | 08:40:37.323Z | reset |
| 47148 | 08:40:37.374Z | false | 08:40:37.375Z | 08:40:37.375Z | reset |
| 31999 | 08:40:37.426Z | false | 08:40:37.427Z | 08:40:37.427Z | reset |
| 55146 | 08:40:37.480Z | false | 08:40:37.481Z | 08:40:37.481Z | reset |
| 54532 | 08:40:37.534Z | false | 08:40:37.535Z | 08:40:37.535Z | reset |
| 40325 | 08:40:37.587Z | false | 08:40:37.589Z | 08:40:37.588Z | reset |
| … | 12 more connection(s) not listed | | | | |

The change began at 08:40:05.249Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L88-g-xrd261-rekeyed-cisco_xrd.pcap` — 740 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L88-g-xrd261-rekeyed-cisco_xrd.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
