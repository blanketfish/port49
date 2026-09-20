# L1 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L1-arista_eos.pcap` — 148 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L1-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

What the `port` field contains, per platform and per transport — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session, stable for its life, and **the same value at authentication and at authorization time**.

## Observation

Two overlapping SSH sessions, each holding an interactive shell open, produced these `port` values on the authentication START:

| session | user | `port` |
|---|---|---|
| 1 | alice04 | `ssh` |
| 2 | alice05 | `ssh` |

**The two concurrent sessions reported the SAME `port` value.** The login context key `(nas, port)` therefore does not distinguish them: the second login overwrites the first login's context, and the receipt key `(nas, port, username)` collides for repeated logins by one user.

All 2 `port` values seen at a `redeem` in this test: ["ssh" "ssh"].

### Stability for the life of a session

Every record naming either login, in arrival order, with the `port` it carried. Grouped by username rather than by `ctx_id`: a `ctx_id` is only written when the context lookup succeeded, so grouping by it hides exactly the sessions whose `port` moved.

| user | records, `event`=`port` |
|---|---|
| `alice04` | `redeem`=ssh, `account`=ssh, `authorize_session`=vty4 |
| `alice05` | `redeem`=ssh, `account`=ssh, `authorize_session`=vty4, `account`=vty4 |

**NOT stable**: 2 of 2 session(s) reported more than one `port` value over their life (alice04, alice05). A login context keyed on `(nas, port)` is written under one value and looked up under another, so the authorization misses and the session is denied for a reason that has nothing to do with policy.


### What the header carried

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.11:57614 → | `0xa5e6b2a1` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:57614 → | `0xa5e6b2a1` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:57614 → | `0xa5e6b2a1` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.11:57614 → | `0xa5e6b2a1` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xa5e6b2a1` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xa5e6b2a1` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xa5e6b2a1` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.1:49 ← | `0xa5e6b2a1` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:57618 → | `0xd9fa52a1` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="ssh" rem_addr="172.100.100.1" args=[task_id=21 service=shell start_time=1789922179 timezone=UTC] |
| 172.100.100.11:57618 → | `0xd9fa52a1` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="ssh" rem_addr="172.100.100.1" args=[task_id=21 service=shell start_time=1789922179 timezone=UTC] |
| 172.100.100.1:49 ← | `0xd9fa52a1` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0xd9fa52a1` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:57632 → | `0xaa4b221e` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.11:57632 → | `0xaa4b221e` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice04" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0xaa4b221e` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.1:49 ← | `0xaa4b221e` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.11:57638 → | `0xf4ee07eb` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:57638 → | `0xf4ee07eb` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:57638 → | `0xf4ee07eb` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.11:57638 → | `0xf4ee07eb` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xf4ee07eb` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xf4ee07eb` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xf4ee07eb` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.1:49 ← | `0xf4ee07eb` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:57648 → | `0x68afdff3` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="ssh" rem_addr="172.100.100.1" args=[task_id=22 service=shell start_time=1789922181 timezone=UTC] |
| 172.100.100.11:57648 → | `0x68afdff3` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="ssh" rem_addr="172.100.100.1" args=[task_id=22 service=shell start_time=1789922181 timezone=UTC] |
| 172.100.100.1:49 ← | `0x68afdff3` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0x68afdff3` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:57664 → | `0xc365d2b2` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.11:57664 → | `0xc365d2b2` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0xc365d2b2` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.1:49 ← | `0xc365d2b2` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.11:34864 → | `0xe9eff019` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="vty4" rem_addr="172.100.100.1" args=[task_id=22 service=shell start_time=1789922181 timezone=UTC elapsed_time=16] |
| 172.100.100.11:34864 → | `0xe9eff019` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="vty4" rem_addr="172.100.100.1" args=[task_id=22 service=shell start_time=1789922181 timezone=UTC elapsed_time=16] |
| 172.100.100.1:49 ← | `0xe9eff019` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0xe9eff019` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 7, carrying 7 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 18 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 3 connection(s), AUTHEN on 2 connection(s), AUTHOR on 2 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here, so L1 is not answered for those transports.
