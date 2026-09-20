# L3 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L3-arista_eos.pcap` — 168 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L3-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. Also, because the login-context key now rests on it: what **username** the device puts on an enable START, and whether two concurrent enables are distinguishable.

## Observation

Two overlapping sessions, each logged in with its own token and each holding at the enable password prompt until the other had reached it, then both answering at once. `disable` precedes `enable` because the seeded session is `priv-lvl=15`: a login lands in enable mode already and typing `enable` there authenticates nothing.

### What the device said

**alice02**:

```
could not open a CLI: none of ["leaf1#" "leaf1>"] appeared on the SSH CLI as alice02 within 45s; what it said was:
Authorization denied: port49: this session was not authenticated by port49
```

**alice03**:

```
could not open a CLI: none of ["leaf1#" "leaf1>"] appeared on the SSH CLI as alice03 within 45s; what it said was:
Authorization denied: port49: this session was not authenticated by port49
```

### The enable authentication, in the decision log

**No authentication record arrived under a username other than the two the harness logged in as.** Either the device sent the operator's own username on the enable START — which the wire table below settles — or it never asked port49 about the enable at all. Every record in the window:
  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=ssh
  event=redeem verdict=permit reason=token_redeemed flags= user=alice03 port=ssh
  event=account verdict= reason= flags=start user=alice02 port=ssh
  event=account verdict= reason= flags=start user=alice03 port=ssh
  event=authorize_session verdict=deny reason=context_missing flags= user=alice02 port=vty5
  event=authorize_session verdict=deny reason=context_missing flags= user=alice03 port=vty4
  event=account verdict= reason= flags=stop user=alice03 port=vty4
  event=account verdict= reason= flags=stop user=alice02 port=vty5


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.11:34126 → | `0x497f3c54` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:34126 → | `0x497f3c54` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:34126 → | `0x497f3c54` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.11:34126 → | `0x497f3c54` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x497f3c54` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x497f3c54` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x497f3c54` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.1:49 ← | `0x497f3c54` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:34134 → | `0x22676e72` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:34134 → | `0x22676e72` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:34134 → | `0x22676e72` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.11:34134 → | `0x22676e72` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x22676e72` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x22676e72` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x22676e72` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.1:49 ← | `0x22676e72` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:34146 → | `0x190c95b8` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789922071 timezone=UTC] |
| 172.100.100.11:34146 → | `0x190c95b8` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789922071 timezone=UTC] |
| 172.100.100.1:49 ← | `0x190c95b8` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0x190c95b8` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:34158 → | `0xfa7aa1c2` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="ssh" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789922071 timezone=UTC] |
| 172.100.100.11:34158 → | `0xfa7aa1c2` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="ssh" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789922071 timezone=UTC] |
| 172.100.100.1:49 ← | `0xfa7aa1c2` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0xfa7aa1c2` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:34162 → | `0x46b2aa9d` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.11:34162 → | `0x46b2aa9d` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x46b2aa9d` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.1:49 ← | `0x46b2aa9d` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.11:34178 → | `0xb327df01` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.11:34178 → | `0xb327df01` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0xb327df01` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.1:49 ← | `0xb327df01` | 2 | clear | AUTHOR RESPONSE status=0x10 server_msg="port49: this session was not authenticated by port49" args=[] |
| 172.100.100.11:44540 → | `0x296691e7` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty4" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789922071 timezone=UTC elapsed_time=46] |
| 172.100.100.11:44540 → | `0x296691e7` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty4" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789922071 timezone=UTC elapsed_time=46] |
| 172.100.100.1:49 ← | `0x296691e7` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0x296691e7` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:44546 → | `0xf1901831` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789922071 timezone=UTC elapsed_time=46] |
| 172.100.100.11:44546 → | `0xf1901831` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789922071 timezone=UTC elapsed_time=46] |
| 172.100.100.1:49 ← | `0xf1901831` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0xf1901831` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 8, carrying 8 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 20 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 4 connection(s), AUTHEN on 2 connection(s), AUTHOR on 2 connection(s).
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

