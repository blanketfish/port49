# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tcp. Measured 2026-11-04 by TestL88.

- named-VRF pass: the management interface and the SSH server moved into vrf mgmt by the lab scaffolding (`vrf mgmt;  address-family ipv4 unicast; exit; exit; interface MgmtEth0/RP0/CPU0/0;  vrf mgmt;  ipv4 address 172.100.100.61 255.255.255.0; exit; ssh server vrf mgmt`)
- `show vrf all` after the move: Wed Nov 4 08:43:52.200 UTC VRF RD RT AFI SAFI mgmt not set
- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tcp), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `terminal length 0`: Wed Nov 4 08:44:09.673 UTC
- `show running-config interface MgmtEth0/RP0/CPU0/0`: Wed Nov 4 08:44:09.934 UTC interface MgmtEth0/RP0/CPU0/0 vrf mgmt ipv4 address 172.100.100.61 255.255.255.0 !
- `show ipv4 vrf all interface brief`: Wed Nov 4 08:44:10.175 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up mgmt
- `show running-config router static`: Wed Nov 4 08:44:10.428 UTC % No such configuration item(s)
- `show running-config ssh`: Wed Nov 4 08:44:10.677 UTC ssh server v2 ssh server vrf mgmt
- `show vrf all`: Wed Nov 4 08:44:10.930 UTC VRF RD RT AFI SAFI mgmt not set
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 31s before port49 saw it
- teardown, `show ipv4 vrf all interface brief`: Wed Nov 4 08:48:57.977 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up default
- teardown, `show running-config ssh`: Wed Nov 4 08:48:58.228 UTC ssh server v2
- teardown: the undo push said EOF; the read-back said <nil>

Capture: `tests/lab/evidence/L88-f-vrf-xrd261-cisco_xrd.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 1.942s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 2, port49 first saw one at +24s |
| b | PASS | break-glass login with port49d stopped: ok true in 120ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 500ms: logged in, `show version` printed "'Wed Nov 4 08:44:51.224 UTC'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 5.58s, `show version` output "'Wed Nov 4 08:45:21.810 UTC'" |
| e | PASS | login with a one-time credential (login attempt 2, 51s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 2; port49 authorized one command and denied the other; command output: [0] Wed Nov 4 08:46:28.103 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 31.1s; connections the first server reset: 4; port49 redeemed the credential: true; tries 2, the login reached port49 after 31s; first command output:  |
| g | OBSERVED | single-connection: on: `tacacs-server host 172.100.100.1 single-connection`, committed; the re-keyed phase: token session (`alice03`), `show version` before the change: ran in 100ms; first `show version` after the change, same session: refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`); second `show version`, same session: refused in 5.14s: `% Command authorization failed`; next token login (`alice04`): refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.66s; break-glass login plus three `show version`: logged in and ran them in 16.39s |

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
+200ms 172.100.100.1 sport 50012: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+200ms 172.100.100.1 sport 31779: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+3.8s 172.100.100.1 sport 63605: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+9.7s 172.100.100.2 sport 35984: SYN true SYN-ACK true; device packets 8, server packets 4; FIN dev true srv true; RST dev false srv false
+29s 172.100.100.1 sport 64086: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+30.5s 172.100.100.2 sport 43229: SYN true SYN-ACK true; device packets 12, server packets 12; FIN dev true srv true; RST dev false srv false
+30.6s 172.100.100.2 sport 54576: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 50119: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+30.7s 172.100.100.2 sport 39289: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 29729: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 44045: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.1s 172.100.100.2 sport 41743: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false
+31.2s 172.100.100.2 sport 21478: SYN true SYN-ACK true; device packets 10, server packets 10; FIN dev true srv true; RST dev false srv false

`terminal length 0`:
terminal length 0
Wed Nov  4 08:47:08.141 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Wed Nov  4 08:47:08.394 UTC
RP/0/RP0/CPU0:Nov  4 08:42:29.114 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:42:54.812 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:43:14.867 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:43:32.751 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:43:57.487 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:43:57.489 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 08:44:08.244 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000009: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: CHECK_LIMIT current: 0 (qsize:1)
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000001
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Selected server - 172.100.100.1/49
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:49]
RP/0/RP0/CPU0:Nov  4 08:44:13.114 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:49] tls disabled
RP/0/RP0/CPU0:Nov  4 08:44:13.115 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:44:13.115 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:13.115 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:13.115 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 08:44:13.227 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000011: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:44:28.298 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:44:51.310 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:45:11.363 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:45:26.575 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000021: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:45:46.629 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:46:38.711 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000039: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:46:39.512 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Wed Nov  4 08:47:08.648 UTC
RP/0/RP0/CPU0:Nov  4 08:42:29.114 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:42:54.812 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:43:14.867 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:43:32.751 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000006: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:43:57.487 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 08:43:57.489 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.2/49' 
RP/0/RP0/CPU0:Nov  4 08:44:08.244 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000009: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:12.863 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:12.867 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:13.110 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:13.115 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 08:44:13.115 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 08:44:13.115 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 08:44:13.227 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000011: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:44:28.298 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:44:51.310 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000017: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:45:11.363 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:45:26.575 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000021: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:45:46.629 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:Nov  4 08:46:38.711 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000001, server-private: No]- Socket 1000039: Connection timed out 
RP/0/RP0/CPU0:Nov  4 08:46:39.512 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/49 is UP [vrf: 0x60000001, server-private: No] 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Wed Nov  4 08:47:08.901 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Wed Nov  4 08:47:09.154 UTC
RP/0/RP0/CPU0:xrd1#

```

### Cell g evidence

```
### Phase: rekeyed

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (22s).

The change: port49d's broker.policy_file given `- {match: {name: xrd1}, key_ref: lab_key2}` (a reviewed pin onto the rotation key, which the device does not hold); the service's copy unchanged

Times are the host's, UTC: the sync (or policy edit) began 08:47:39.139Z; port49d applied the reload, saying `port49d: policy reloaded`, between 08:47:40.677Z and 08:47:40.703Z, and the change instant the capture is read against is 08:47:40.677Z; the command in flight was sent at 08:47:40.703Z.

| step | outcome |
|---|---|
| token session (`alice03`), `show version` before the change | ran in 100ms |
| first `show version` after the change, same session | refused in 300ms: `% Command authorization failed` (the reset's packet: `type=author`) |
| second `show version`, same session | refused in 5.14s: `% Command authorization failed` |
| next token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain in 5.66s |
| break-glass login plus three `show version` | logged in and ran them in 16.39s |

Records from the device since the change, before the next logins: `event=unvalidated <LONG> type=acct` ×1; `event=unvalidated <LONG> type=author` ×2; `event=unvalidated reason=device_unknown <LONG> device=xrd1 type=author` ×1

Records from the device during the next logins: `event=unvalidated <LONG> type=acct` ×2; `event=unvalidated <LONG> type=authen` ×1; `event=unvalidated <LONG> type=author` ×1

Connections between the device and port 49 in this phase's capture:

| device port | first seen | device sent before the change | device first sent after it | port49d reset it | reading |
|---|---|---|---|---|---|
| 54205 | 08:47:23.986Z | false | (not observed) | (not observed) | not reset by port49d |
| 58229 | 08:47:31.365Z | true | 08:47:40.707Z | 08:47:40.707Z | **reset mid-connection**: open across the change |
| 42524 | 08:47:32.433Z | false | (not observed) | 08:47:32.433Z | reset before the change |
| 45896 | 08:47:40.759Z | false | 08:47:40.760Z | 08:47:40.760Z | reset at its first packet after the change |
| 56111 | 08:47:40.813Z | false | 08:47:40.815Z | 08:47:40.815Z | reset |
| 64472 | 08:47:40.868Z | false | 08:47:40.869Z | 08:47:40.869Z | reset at its first packet after the change |
| 54171 | 08:47:40.922Z | false | 08:47:40.924Z | 08:47:40.924Z | reset |
| 56463 | 08:47:40.975Z | false | (not observed) | 08:47:40.977Z | reset before the device sent on it (refused at Accept) |
| 29552 | 08:47:46.064Z | false | (not observed) | (not observed) | not reset by port49d |
| 63310 | 08:47:46.196Z | false | 08:47:46.197Z | 08:47:46.197Z | reset at its first packet after the change |
| 29998 | 08:47:46.249Z | false | 08:47:46.251Z | 08:47:46.251Z | reset |
| 23815 | 08:47:46.303Z | false | 08:47:46.305Z | 08:47:46.305Z | reset |
| 54484 | 08:47:46.358Z | false | 08:47:46.359Z | 08:47:46.359Z | reset |
| 61412 | 08:47:46.411Z | false | 08:47:46.413Z | 08:47:46.413Z | reset |
| 25011 | 08:47:46.465Z | false | (not observed) | 08:47:46.467Z | reset before the device sent on it (refused at Accept) |
| 30894 | 08:47:57.673Z | false | (not observed) | 08:47:57.673Z | reset before the device sent on it (refused at Accept) |
| 59964 | 08:48:01.340Z | false | (not observed) | (not observed) | not reset by port49d |
| 50069 | 08:48:01.448Z | false | 08:48:01.449Z | 08:48:01.450Z | reset at its first packet after the change |
| 41536 | 08:48:01.503Z | false | 08:48:01.504Z | 08:48:01.504Z | reset |
| 26579 | 08:48:01.557Z | false | 08:48:01.558Z | 08:48:01.558Z | reset |
| 49235 | 08:48:01.611Z | false | 08:48:01.612Z | 08:48:01.612Z | reset |
| 15386 | 08:48:01.665Z | false | 08:48:01.666Z | 08:48:01.666Z | reset |
| 21448 | 08:48:01.719Z | false | (not observed) | 08:48:01.720Z | reset before the device sent on it (refused at Accept) |
| 58927 | 08:48:06.998Z | false | (not observed) | (not observed) | not reset by port49d |
| 20052 | 08:48:07.108Z | false | 08:48:07.110Z | 08:48:07.111Z | reset at its first packet after the change |
| 57836 | 08:48:07.163Z | false | 08:48:07.164Z | 08:48:07.164Z | reset |
| 48174 | 08:48:07.216Z | false | 08:48:07.218Z | 08:48:07.218Z | reset |
| 33304 | 08:48:07.270Z | false | 08:48:07.272Z | 08:48:07.272Z | reset |
| 50194 | 08:48:07.324Z | false | 08:48:07.325Z | 08:48:07.325Z | reset |
| 30237 | 08:48:07.377Z | false | (not observed) | 08:48:07.379Z | reset before the device sent on it (refused at Accept) |
| 57003 | 08:48:12.438Z | false | (not observed) | (not observed) | not reset by port49d |
| 31552 | 08:48:12.537Z | false | 08:48:12.538Z | 08:48:12.538Z | reset at its first packet after the change |
| 24982 | 08:48:12.589Z | false | 08:48:12.590Z | 08:48:12.590Z | reset |
| 48884 | 08:48:12.642Z | false | 08:48:12.642Z | 08:48:12.642Z | reset |
| 54614 | 08:48:12.694Z | false | 08:48:12.694Z | 08:48:12.694Z | reset |
| 19228 | 08:48:12.746Z | false | 08:48:12.747Z | 08:48:12.747Z | reset |
| 28063 | 08:48:12.800Z | false | 08:48:12.801Z | 08:48:12.801Z | reset at its first packet after the change |
| 40256 | 08:48:12.854Z | false | 08:48:12.855Z | 08:48:12.855Z | reset |
| 34303 | 08:48:12.908Z | false | 08:48:12.909Z | 08:48:12.909Z | reset |
| 54999 | 08:48:12.962Z | false | 08:48:12.963Z | 08:48:12.963Z | reset at its first packet after the change |
| … | 12 more connection(s) not listed | | | | |

The change began at 08:47:40.677Z (host UTC); 1 connection(s) read as reset mid-connection, 0 as open (idle) before the change and reset at its first packet.

Capture: `tests/lab/evidence/L88-g-vrf-xrd261-rekeyed-cisco_xrd.pcap` — 760 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L88-g-vrf-xrd261-rekeyed-cisco_xrd.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).


```
