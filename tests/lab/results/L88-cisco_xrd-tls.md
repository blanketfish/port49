# L88: the reference AAA configuration on XRd control plane 26.1.1

Platform: cisco_xrd. Image: XRd control plane 26.1.1. Transport: tls. Measured 2026-11-04 by TestL88.

- cells run over RFC 9887: a, b, d, e, f. c, g, i: not transport-dependent, measured on the plain pass (L88-cisco_xrd.md)
- port49d's server certificate carries both server addresses (172.100.100.1, 172.100.100.2) as IP names, because cell f has the device dial the second one; with the first alone, a device that checks the dialled address would refuse the second server for the certificate, not for failover
- RFC 9887 enrolment by L73's machinery (its own PKI; the device's key and certificate id `l73-dev`, the root trusted as `port49-root`); port49d's tls_listener on 172.100.100.1:300. The reference TLS file was then applied over it unchanged.
- the reference loaded: `deploy/device-aaa/cisco_iosxr` (tls), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- `terminal length 0`: Wed Nov 4 09:06:28.380 UTC
- `show running-config interface MgmtEth0/RP0/CPU0/0`: Wed Nov 4 09:06:28.635 UTC interface MgmtEth0/RP0/CPU0/0 ipv4 address 172.100.100.61 255.255.255.0 !
- `show ipv4 vrf all interface brief`: Wed Nov 4 09:06:28.885 UTC Interface IP-Address Status Protocol Vrf-Name MgmtEth0/RP0/CPU0/0 172.100.100.61 Up Up default
- `show running-config router static`: Wed Nov 4 09:06:29.136 UTC % No such configuration item(s)
- `show running-config ssh`: Wed Nov 4 09:06:29.402 UTC ssh server v2
- `show vrf all`: Wed Nov 4 09:06:29.637 UTC
- device debug on from before cell a: debug tacacs, debug aaa authentication
- cell a: before an attempt reached port49 the denied user was tried 1 times: +12s logged in true without port49 seeing it
- cell f: the login took 2 tries over 26s before port49 saw it

Capture: `tests/lab/evidence/L88-f-tls-xrd261-cisco_xrd.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 1.962s (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 2, port49 first saw one at +24s |
| b | PASS | break-glass login with port49d stopped: ok true in 120ms (no error) |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 470ms, `show version` output "'Wed Nov 4 09:07:10.634 UTC'" |
| e | PASS | login with a one-time credential (login attempt 1, 1s after the first) no error: 1 command authorizations permitted, 1 denied by port49; accounting START 2, STOP 3; port49 authorized one command and denied the other; command output: [0] Wed Nov 4 09:07:26.838 UTC Cisco IOS XR Software, Version 26.1.1 LNT Copyright (c) 2013-2026 by Cisco Systems, Inc. Build Information: Built By : cisco Built On... [1] % Command authorization failed  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 26s; connections the first server reset: 1; port49 redeemed the credential: true; tries 2, the login reached port49 after 26s; first command output:  |

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
  event=account verdict= reason= flags=stop user=alice01 port=/dev/pts/3
```

### Cell f evidence

```

  event=unvalidated verdict= reason= flags= unvalidated_diagnosis=tls_refused
  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=/dev/pts/2
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=/dev/pts/2
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=/dev/pts/2
  event=account verdict= reason= flags=start user=alice02 port=/dev/pts/2
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=/dev/pts/2
  event=account verdict= reason= flags=stop user=alice02 port=/dev/pts/2
  event=account verdict= reason= flags=stop user=alice02 port=/dev/pts/2
the wire during the login (headers only):
3 connections from the device in the window: 3 with a SYN, 3 answered SYN-ACK, 2 with an RST
+14.1s 172.100.100.2 sport 25569: SYN true SYN-ACK true; device packets 6, server packets 4; FIN dev true srv false; RST dev false srv true
+24.1s 172.100.100.1 sport 22897: SYN true SYN-ACK true; device packets 4, server packets 4; FIN dev false srv false; RST dev false srv true
+25.3s 172.100.100.2 sport 43644: SYN true SYN-ACK true; device packets 32, server packets 26; FIN dev false srv false; RST dev false srv false

`terminal length 0`:
terminal length 0
Wed Nov  4 09:07:56.688 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include tacacs`:
show logging | include tacacs
Wed Nov  4 09:07:56.942 UTC
RP/0/RP0/CPU0:Nov  4 09:05:00.165 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 09:05:25.332 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:05:45.398 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:06:26.762 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:06:26.828 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.2/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Message type : 5
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Dispatching Message type : 5
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Invoke api for Message type : 5
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: author Options send : 64
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Option : 64
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: CHECK_LIMIT current: 2 (qsize:1)
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: CHECK_LIMIT current: 2 (qsize:1)
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 09:06:31.763 UTC: tacacsd[1139]: Errno set as :Success
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: CHECK_LIMIT current: 2 (qsize:1)
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [msg_call_back] Message recieved from client : tacacs  
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Dispatching Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Invoke api for Message type : 7
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: ACCT Options send : 131
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Enter enque function
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Option : 131
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_req_enqueue] Enqueuing request cnt: 0 : CHECK_LIMIT 
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: CHECK_LIMIT current: 2 (qsize:1)
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Using server group # 3001, vrf_id=0x60000000
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Checking server 172.100.100.1 ...
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: New server selected [up: 1][del: 0]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Selected server - 172.100.100.1/300
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Selected next server : 172.100.100.2/0
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Look for server [port : 0][private:0][port org:300]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: [tacacs_get_next_server] Selected server [private:0][port org:300] tls disabled
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Delete session_id entry in timer_db
RP/0/RP0/CPU0:Nov  4 09:06:31.905 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:06:31.977 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:06:51.970 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:06:58.208 UTC: tacacsd[1139]: %SECURITY-PKI-6-LOG_INFO : Certificate verified successfully 
RP/0/RP0/CPU0:Nov  4 09:06:58.208 UTC: tacacsd[1139]: %<LONG> : SSL Certificate verification: Peer certificate verified successfully 
RP/0/RP0/CPU0:Nov  4 09:06:59.944 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:07:05.134 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000015: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:07:25.190 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:07:27.225 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:07:32.463 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:07:42.517 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/300 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:07:55.784 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.2/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:xrd1#

`show logging | include TACACS`:
show logging | include TACACS
Wed Nov  4 09:07:57.195 UTC
RP/0/RP0/CPU0:Nov  4 09:05:00.165 UTC: tacacsd[1139]: %<LONG> : Key is configured or updated for server '172.100.100.1/49' 
RP/0/RP0/CPU0:Nov  4 09:05:25.332 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000001: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:05:45.398 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/49 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:06:26.762 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:06:26.828 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.2/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt64]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.582 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.586 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.827 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Connection ready status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848][opt131]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Failed to send request status : 'TACACS' detected the 'fatal' condition 'No server available to send the request'[-1572558848]
RP/0/RP0/CPU0:Nov  4 09:06:31.831 UTC: tacacsd[1139]: Sending error message to client - 'TACACS' detected the 'fatal' condition 'No server available to send the request'
RP/0/RP0/CPU0:Nov  4 09:06:31.905 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000008: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:06:31.977 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000010: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:06:51.970 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:06:59.944 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:07:05.134 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000015: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:07:25.190 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:07:27.225 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:Nov  4 09:07:32.463 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.1/300 is DOWN [vrf: 0x60000000, server-private: No]- Socket 1000020: Connection timed out 
RP/0/RP0/CPU0:Nov  4 09:07:42.517 UTC: tacacsd[1139]: %<LONG> : TACACS+ server 172.100.100.2/300 is UP [vrf: 0x60000000, server-private: No] 
RP/0/RP0/CPU0:Nov  4 09:07:55.784 UTC: tacacsd[1139]: %<LONG> : Connection to TACACS+ server 172.100.100.2/300 failed [server-private: No], SSL Error:System call error. 
RP/0/RP0/CPU0:xrd1#

`show logging | include AAA`:
show logging | include AAA
Wed Nov  4 09:07:57.449 UTC
RP/0/RP0/CPU0:xrd1#

`show logging | include aaa`:
show logging | include aaa
Wed Nov  4 09:07:57.699 UTC
RP/0/RP0/CPU0:xrd1#

```
