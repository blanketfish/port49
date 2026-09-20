# L3 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L3-arista_eos.pcap` — 316 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L3-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. Also, because the login-context key now rests on it: what **username** the device puts on an enable START, and whether two concurrent enables are distinguishable.

## Observation

### Before anything was measured

**The device's authorization configuration was changed for this test, and the reason is a finding of its own.** The first attempt measured nothing: both token sessions logged in, both were denied their exec authorization, and vEOS killed them with `Authorization denied: port49: this session was not authenticated by port49`. The decision log for that moment reads `redeem permit … port=ssh` and then `authorize_session deny context_missing … port=vty5`. port49 writes the login context under `(nas, port)` at the authentication, where this image says `ssh`, and reads it at the authorization, where the same image says `vty5`. **On vEOS 4.32.2F no interactive session that gets a vty allocated can pass authorization through port49 today.**

So for the duration of this test, and only for it, the device was set to:

```
aaa authorization exec default local
aaa authorization commands all default local
```

and put back to:

```
aaa authorization exec default group port49 local
aaa authorization commands all default group port49 local
```

afterwards. The enable exchange is authenticated by `aaa authentication enable default`, which was **not** touched, so nothing measured below depends on the change.

Two overlapping sessions, each logged in with its own token and each holding at the enable password prompt until the other had reached it, then both answering at once. `disable` precedes `enable` because the seeded session is `priv-lvl=15`: a login lands in enable mode already and typing `enable` there authenticates nothing.

### What the device said

**alice01**:

```
could not open a CLI: none of ["leaf1#" "leaf1>"] appeared on the SSH CLI as alice01 within 45s; what it said was:
Authorization denied: Unknown user
```

**alice02**:

```
could not open a CLI: none of ["leaf1#" "leaf1>"] appeared on the SSH CLI as alice02 within 45s; what it said was:
Authorization denied: Unknown user
```

### The enable authentication, in the decision log

**No authentication record arrived under a username other than the two the harness logged in as.** Either the device sent the operator's own username on the enable START — which the wire table below settles — or it never asked port49 about the enable at all. Every record in the window:
  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=ssh
  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=ssh
  event=account verdict= reason= flags=start user=alice01 port=ssh
  event=account verdict= reason= flags=start user=alice02 port=ssh
  event=account verdict= reason= flags=stop user=alice01 port=vty4
  event=account verdict= reason= flags=stop user=alice02 port=vty5


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.11:40384 → | `0x2b4bd62d` | 1 | clear | ACCT REQUEST flags=stop authen_method=local(5) authen_type=ascii(1) service=login(1) priv_lvl=1 user="breakglass" port="vty4" rem_addr="172.100.100.1" args=[task_id=10 service=shell start_time=1789922641 timezone=UTC elapsed_time=2] |
| 172.100.100.1:49 ← | `0x2b4bd62d` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40610 → | `0xe3d448a4` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:40610 → | `0xe3d448a4` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xe3d448a4` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xe3d448a4` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:40620 → | `0x35dc978e` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:40620 → | `0x35dc978e` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x35dc978e` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x35dc978e` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:40636 → | `0xc52a90d5` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="ssh" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789922645 timezone=UTC] |
| 172.100.100.1:49 ← | `0xc52a90d5` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40646 → | `0x0cc8b13c` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789922645 timezone=UTC] |
| 172.100.100.1:49 ← | `0x0cc8b13c` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:54834 → | `0x1b454a6e` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789922645 timezone=UTC elapsed_time=46] |
| 172.100.100.1:49 ← | `0x1b454a6e` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:54848 → | `0x841b8ebb` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789922645 timezone=UTC elapsed_time=46] |
| 172.100.100.1:49 ← | `0x841b8ebb` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 7, carrying 7 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 9 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 5 connection(s), AUTHEN on 2 connection(s).
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

