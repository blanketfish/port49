# L1 — cisco_iosxe

- **Date measured:** 2026-09-20
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/captures/L1-cisco_iosxe.pcap` — 168 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L1-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

What the `port` field contains, per platform and per transport — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session, stable for its life, and **the same value at authentication and at authorization time**.

## Observation

Two overlapping SSH sessions, each holding an interactive shell open, produced these `port` values on the authentication START:

| session | user | `port` |
|---|---|---|
| 1 | alice04 | `tty434` |
| 2 | alice05 | `tty435` |

**The two concurrent sessions reported DIFFERENT `port` values** on this run. Nothing rests on that either way: the login context is keyed `(nas, username)` (spec §13, decision 15). Recorded because the value is what L1 asks for.

All 2 `port` values seen at a `redeem` in this test: ["tty434" "tty435"].

### Stability for the life of a session

Every record naming either login, in arrival order, with the `port` it carried. Grouped by username rather than by `ctx_id`: a `ctx_id` is only written when the context lookup succeeded, so grouping by it hides exactly the sessions whose `port` moved.

| user | records, `event`=`port` |
|---|---|
| `alice04` | `redeem`=tty434, `authorize_session`=tty434, `account`=tty434, `account`=tty434 |
| `alice05` | `redeem`=tty435, `authorize_session`=tty435, `account`=tty435, `account`=tty435 |

**Stable.** Across 2 session(s), every record for a session reported the same `port` as that session's authentication START.


### What the two sessions were actually told

What each login was told when the device asked to authorize its session, and the `port` the device put on that request — which is not the `port` it authenticated under.

| user | `port` at authorization | verdict | reason | `ctx_id` |
|---|---|---|---|---|
| `alice04` | `tty434` | permit | `context_matched` | `HBQAFC74PL5SB6BA` |
| `alice05` | `tty435` | permit | `context_matched` | `QEHEVPKDEOTJ3U44` |

2 permitted, 0 denied. **Both concurrent sessions matched their own context and were authorized**, across 2 distinct `ctx_id`(s) — neither login disturbed the other, and the `port` changing between the authentication and this request did not cost either of them anything.

### What the header carried

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.41:48394 → | `0x3496eeb7` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="tty434" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.41:48394 → | `0x3496eeb7` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x3496eeb7` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x3496eeb7` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.41:48396 → | `0x725ca9ce` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="tty434" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x725ca9ce` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15] |
| 172.100.100.41:48404 → | `0xb5f588b1` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice04" port="tty434" rem_addr="172.100.100.1" args=[task_id=4033 timezone=UTC service=shell] |
| 172.100.100.1:49 ← | `0xb5f588b1` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:48418 → | `0xc2964e6a` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="tty435" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.41:48418 → | `0xc2964e6a` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xc2964e6a` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xc2964e6a` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.41:48430 → | `0x193998f7` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="tty435" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x193998f7` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15] |
| 172.100.100.41:48434 → | `0x33af9fe0` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice05" port="tty435" rem_addr="172.100.100.1" args=[task_id=4034 timezone=UTC service=shell] |
| 172.100.100.1:49 ← | `0x33af9fe0` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:47726 → | `0x50fcd5bc` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="tty435" rem_addr="172.100.100.1" args=[task_id=4034 timezone=UTC service=shell disc-cause=1 disc-cause-ext=9 pre-session-time=0 elapsed_time=15 stop_time=1789931792] |
| 172.100.100.1:49 ← | `0x50fcd5bc` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:47730 → | `0x1ccfc64d` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="tty434" rem_addr="172.100.100.1" args=[task_id=4033 timezone=UTC service=shell disc-cause=1 disc-cause-ext=9 pre-session-time=0 elapsed_time=20 stop_time=1789931795] |
| 172.100.100.1:49 ← | `0x1ccfc64d` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 8, carrying 8 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 10 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 4 connection(s), AUTHEN on 2 connection(s), AUTHOR on 2 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here, so L1 is not answered for those transports.
