# L3 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/captures/L3-cisco_iosxe.pcap` — 196 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L3-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. Also, because the login-context key now rests on it: what **username** the device puts on an enable START, and whether two concurrent enables are distinguishable.

## Observation

### Before anything was measured

The device's authorization configuration was left exactly as `tests/lab/configs` deploys it: `aaa authorization exec` and `aaa authorization commands` were in force throughout, and the token sessions below passed them.

Two overlapping sessions, each logged in with its own token and each holding at the enable password prompt until the other had reached it, then both answering at once. `disable` precedes `enable` because the seeded session is `priv-lvl=15`: a login lands in enable mode already and typing `enable` there authenticates nothing.

### What the device said

**alice02**:

```
could not open a CLI: none of ["Username:" "Password:" "xe1#" "xe1>"] appeared on the serial console (172.100.100.41:5000) as alice02, after SSH failed (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain) within 1m30s; what it said was:

*Sep 20 19:11:31.643: %SSH-5-SSH2_USERAUTH: User '' authentication for SSH2 Session from 172.100.100.1 (tty = 0) using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' Failed
*Sep 20 19:11:31.643: %SSH-5-SSH2_CLOSE: SSH2 Session from 172.100.100.1 (tty = 0) for user '' using crypto cipher 'aes128-gcm@openssh.com', hmac 'hmac-sha2-512' closed
*Sep 20 19:11:34.220: %SMART_LIC-3-COMM_FAILED: Communications failure with the Cisco Smart License Utility (CSLU) : Unable to resolve server hostname/domain name 
```

**alice03**:

```
xe1>enable
Password: 
% Password:  timeout expired!
% Error in authentication.

xe1>p49_labenable01
% Bad IP address or host name% Unknown command or computer name, or unable to find computer address
p49_labenable01 % Bad IP address or host name% Unknown command or computer name, or unable to find computer address xe1>
```

### The enable authentication, in the decision log

**No authentication record arrived under a username other than the two the harness logged in as.** Either the device sent the operator's own username on the enable START — which the wire table below settles — or it never asked port49 about the enable at all. Every record in the window:
  event=redeem verdict=permit reason=token_redeemed flags= user=alice03 port=tty435
  event=authorize_session verdict=permit reason=context_matched flags= user=alice03 port=tty435
  event=account verdict= reason= flags=start user=alice03 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice03 port=tty435
  event=account verdict= reason= flags=stop user=alice03 port=tty435
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice03 port=tty435
  event=account verdict= reason= flags=stop user=alice03 port=tty435
  event=account verdict= reason= flags=stop user=alice03 port=tty435


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.41:59924 → | `0x97a63dc5` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="tty435" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.41:59924 → | `0x97a63dc5` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x97a63dc5` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x97a63dc5` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.41:59928 → | `0x8a037355` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="tty435" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x8a037355` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15] |
| 172.100.100.41:59930 → | `0x7a2d689e` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice03" port="tty435" rem_addr="172.100.100.1" args=[task_id=4017 timezone=UTC service=shell] |
| 172.100.100.1:49 ← | `0x7a2d689e` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:43208 → | `0x9f139439` | 1 | clear | AUTHOR REQUEST authen_method=none(1) authen_type=ascii(1) service=none(0) priv_lvl=1 user="alice03" port="tty435" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x9f139439` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.41:43218 → | `0x6b899844` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice03" port="tty435" rem_addr="172.100.100.1" args=[task_id=4017 timezone=UTC service=shell priv-lvl=1 cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0x6b899844` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:43228 → | `0x13e1266d` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice03" port="tty435" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.1:49 ← | `0x13e1266d` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.41:58510 → | `0x41d08fc2` | 1 | clear | AUTHOR REQUEST authen_method=none(1) authen_type=ascii(1) service=none(0) priv_lvl=1 user="alice03" port="tty435" rem_addr="172.100.100.1" args=[service=shell cmd=connect cmd-arg=p49_labenable01 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x41d08fc2` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.41:58522 → | `0x95954a88` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="tty435" rem_addr="172.100.100.1" args=[task_id=4019 timezone=UTC service=shell priv-lvl=1 cmd=connect p49_labenable01 <cr>] |
| 172.100.100.1:49 ← | `0x95954a88` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:58524 → | `0xc04432b7` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="tty435" rem_addr="172.100.100.1" args=[task_id=4017 timezone=UTC service=shell disc-cause=1 disc-cause-ext=9 pre-session-time=0 elapsed_time=95 stop_time=1789931582] |
| 172.100.100.1:49 ← | `0xc04432b7` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 9, carrying 9 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 10 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 4 connection(s), AUTHEN on 2 connection(s), AUTHOR on 3 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Read the `service=` field in that table: a login START is `login(1)` and an enable START is `enable(2)`. `priv_lvl` on the enable START is the level being asked for, which is what decides whether the username is `$enab15$` or something else on a device that spells it that way.

### When the enable is allowed

Not measured: phase one produced no enable authentication record, so there was no username to seed a token under.

### Not measured

- Two operators from two different client addresses. Both sessions here come from the harness at the bridge's `.1`, so `rem_addr` not distinguishing them is measured only for the shared-bastion case.
- Privilege levels other than the one `enable` with no argument asks for.
- `enable` over any transport but the interactive SSH CLI.
- IOS-XE, which is the platform the `$enab{level}$` spelling comes from and the one this row most needs.
- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question asked of the enable method list rather than the login one.

