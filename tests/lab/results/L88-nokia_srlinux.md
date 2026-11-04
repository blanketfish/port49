# L88: the reference AAA configuration on SR Linux 26.7.2-519

Platform: nokia_srlinux. Image: SR Linux 26.7.2-519. Transport: tcp. Measured 2026-11-04 by TestL88.

- `info from state interface mgmt0 subinterface 0 ipv4`: admin-state enable <LONG> false address 172.100.100.71/24 { origin dhcp status preferred } unnumbered { admin-state disable } dhcp-client { } arp { <LONG> true timeout 14400 learn-unsolicited false proxy-arp false neighbor 172.100.100.1 { link-layer-address 6A:C3:83:8D:D6:8F origin dynamic expiration-time "2026-11-04T12:41:11.027Z (3 hours from now)" group-based-policy-tag 0 datapath-programming { status success } } }
- `info from state network-instance mgmt interface`: Parsing error: While parsing 'interface': Missing value for 'name' (exit status 1)
- `info from running network-instance mgmt`: type ip-vrf admin-state enable description "Management network instance" interface mgmt0.0 { } protocols { linux { import-routes true export-routes true export-neighbors true } }
- the lab scaffolding configured `172.100.100.71/24` statically on mgmt0.0 in place of the DHCP client (the address is DHCP-learned; the commit of a source-address needs a configured one)
- the reference loaded: `deploy/device-aaa/nokia_srlinux` (tcp, then tls-profile and port 300 added by the harness), values: servers 172.100.100.1, 172.100.100.2; the second is an address on the bridge where nothing listens
- teardown, `info from running interface mgmt0 subinterface 0 ipv4`: admin-state enable dhcp-client { }
- teardown: the static management address was removed and mgmt0 is back on the DHCP client (read back)

Capture: `tests/lab/evidence/L88-f-srlinux-nokia_srlinux.pcap` (redacted copy of the run's capture)

| Cell | Verdict | Observation |
|---|---|---|
| a | PASS | control (port49d stopped, the local account): logged in true (no error). With port49d answering: logged in false after 757ms (); port49 decision for the attempt: verdict="deny" reason="token_not_found"; attempts 1, port49 first saw one at +1s |
| b | PASS | break-glass login with port49d stopped: ok true in 50ms (no error) |
| c | OBSERVED | the store hung (the proxy to etcd held); break-glass first logged in at +0s; port49d's log showed no listener close within the window; port49d records: authorize_session [], authorize_command [], accounting []; tries: try at +0s took 2.9s: logged in, `show version` printed "'Hostname : srl1'" |
| d | PASS | port49d dark (its log shows it closed its listeners: true): break-glass login no error in 2.36s, `show version` output "'Hostname : srl1'" |
| e | OBSERVED | login with a one-time credential (login attempt 1, 3s after the first) no error: port49 received 0 command authorizations (SR Linux asks for none, L76); the command port49's policy denies on other platforms (`show clock`) ran and printed output, so no command denial through port49 exists on SR Linux; accounting START 2, STOP 2; command output: [0] Chassis Type : 7220 IXR-D2L Part Number : Sim Part No. Serial Number : Sim Serial No. System HW MAC Address: 1A:21:00:FF:00:00 OS : SR Linux Software Version : ... [1] [0m--{ + running }--[ ]--[0m [0mA:alice01@srl1# echo l88-end[28D[28C[?7h[0m[?12l[?25h[?25l[?7l[2A[28D[0m[J[0m [0m--{ + running }--[ ]--[0m [0...  |
| f | PASS | login with a one-time credential, the first server (172.100.100.1) resetting every connection at Accept and port49d on the second (172.100.100.2): no error in 2.33s; connections the first server reset: 1; port49 redeemed the credential: true; tries 1, the login reached port49 after 2s; first command output:  |
| g | OBSERVED | SR Linux has no single-connection setting, so a key-retiring reload has no open shared connection to reset. `tree flat system aaa server-group`, read from the device: system aaa server-group system aaa server-group type system aaa server-group timeout system aaa server-group health-check system aaa server-group tacacs system aaa server-group tacacs priv-lvl-authorization system aaa server-group tacacs service-request system aaa server-group tacacs service-request <LONG> system aaa server-group tacacs service-request <LONG> system aaa server-group tacacs service-request <LONG> system aaa server-group tacacs service-request <LONG> system aaa server-group server system aaa server-group server name system aaa server-group server network-instance system aaa server-group server tls-profile system aaa server-group server timeout system aaa server-group server tacacs system aaa server-group server tacacs port system aaa server-group server tacacs secret-key system aaa server-group server tacacs source-address system aaa server-group server radius system aaa server-group server radius auth-port system aaa server-group server radius acct-port system aaa server-group server radius secret-key system aaa server-group server radius source-address system aaa server-group server radius retransmit-attempts |

### Cell a evidence

```

  event=redeem verdict=deny reason=token_not_found flags= user=l88deny port=ssh
```

### Cell e evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=ssh
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=ssh
  event=account verdict= reason= flags=start user=alice01 port=unknown
  event=account verdict= reason= flags=stop user=alice01 port=unknown
  event=account verdict= reason= flags=start user=alice01 port=unknown
  event=account verdict= reason= flags=stop user=alice01 port=unknown
```

### Cell f evidence

```

  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=ssh
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=ssh
  event=account verdict= reason= flags=start user=alice02 port=unknown
  event=account verdict= reason= flags=stop user=alice02 port=unknown
the wire during the login (headers only):
5 connections from the device in the window: 5 with a SYN, 5 answered SYN-ACK, 5 with an RST
+0s 172.100.100.1 sport 35421: SYN true SYN-ACK true; device packets 6, server packets 6; FIN dev false srv false; RST dev false srv true
+0s 172.100.100.2 sport 48951: SYN true SYN-ACK true; device packets 12, server packets 10; FIN dev false srv true; RST dev true srv false
+0s 172.100.100.2 sport 44885: SYN true SYN-ACK true; device packets 10, server packets 8; FIN dev false srv true; RST dev true srv false
+1.9s 172.100.100.2 sport 47731: SYN true SYN-ACK true; device packets 10, server packets 8; FIN dev false srv true; RST dev true srv false
+2.1s 172.100.100.2 sport 58219: SYN true SYN-ACK true; device packets 10, server packets 8; FIN dev false srv true; RST dev true srv false

```
