# L3 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L3-arista_eos.pcap` — 682 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L3-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. Also, because the login-context key now rests on it: what **username** the device puts on an enable START, and whether two concurrent enables are distinguishable.

## Observation

### Before anything was measured

**The device's authorization configuration was removed for this test, and the reason is a finding of its own.**

The first attempt measured nothing: both token sessions logged in, both were denied their exec authorization, and vEOS killed them with `Authorization denied: port49: this session was not authenticated by port49`. The decision log for that moment reads `redeem permit … port=ssh` and then `authorize_session deny context_missing … port=vty5`. port49 writes the login context under `(nas, port)` at the authentication, where this image says `ssh`, and reads it at the authorization, where the same image says `vty5`. **On vEOS 4.32.2F no interactive session that gets a vty allocated can pass authorization through port49 today.**

The second attempt pointed the same statements at `local` and measured nothing for a second reason worth writing down: vEOS answered **`Authorization denied: Unknown user`**. A token user has no local account — that is the entire point of port49 — so `local` exec authorization has nobody to authorize. The two together say that on this image a port49-authenticated operator reaches a prompt only if the `(nas, port)` lookup succeeds, and it does not.

So for the duration of this test, and only for it, these lines were removed:

```
no aaa authorization exec default group port49 local
no aaa authorization commands all default group port49 local
```

and put back afterwards:

```
aaa authorization exec default group port49 local
aaa authorization commands all default group port49 local
```

The enable exchange is authenticated by `aaa authentication enable default`, which was **not** touched, so nothing measured below depends on the change.

Two overlapping sessions, each logged in with its own token and each holding at the enable password prompt until the other had reached it, then both answering at once. `disable` precedes `enable` because the seeded session is `priv-lvl=15`: a login lands in enable mode already and typing `enable` there authenticates nothing.

### What the device said

**alice01**:

```
leaf1>enable
Password: 
% Error in authentication
% Error in authentication leaf1>
```

**alice02**:

```
leaf1>enable
Password: 
% Error in authentication
% Error in authentication leaf1>
```

### The enable authentication, in the decision log

| wire username | verdict | reason | `port` | `rem_addr` |
|---|---|---|---|---|
| `alice02` | deny | `token_not_found` | vty5 | 172.100.100.1 |
| `alice01` | deny | `token_not_found` | vty4 | 172.100.100.1 |

**The two concurrent enables arrived under different usernames**, so the device puts the operator's own identity on the enable START and `(nas, username)` keeps them apart.

Distinct `port` values across the two: 2. Distinct `rem_addr` values: 1. A field with one distinct value across two concurrent enables cannot tell them apart.


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.11:59496 → | `0x2e863935` | 1 | clear | ACCT REQUEST flags=stop authen_method=local(5) authen_type=ascii(1) service=login(1) priv_lvl=1 user="breakglass" port="vty4" rem_addr="172.100.100.1" args=[task_id=10 service=shell start_time=1789923293 timezone=UTC elapsed_time=2] |
| 172.100.100.1:49 ← | `0x2e863935` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:59682 → | `0x508d6901` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:59682 → | `0x508d6901` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x508d6901` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x508d6901` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:59692 → | `0x443864e9` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:59692 → | `0x443864e9` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x443864e9` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x443864e9` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:59698 → | `0x27e8a507` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="ssh" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789923297 timezone=UTC] |
| 172.100.100.1:49 ← | `0x27e8a507` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40804 → | `0x7063a443` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789923297 timezone=UTC] |
| 172.100.100.1:49 ← | `0x7063a443` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40814 → | `0xe206c0e8` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=3 service=shell priv-lvl=1 start_time=1789923297 timezone=UTC cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0xe206c0e8` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40830 → | `0xd277c8d2` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[task_id=4 service=shell priv-lvl=1 start_time=1789923297 timezone=UTC cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0xd277c8d2` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40844 → | `0x16d27d41` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[task_id=5 service=shell priv-lvl=1 start_time=1789923297 timezone=UTC cmd=disable <cr>] |
| 172.100.100.1:49 ← | `0x16d27d41` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40846 → | `0xe7df7dca` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=6 service=shell priv-lvl=1 start_time=1789923297 timezone=UTC cmd=disable <cr>] |
| 172.100.100.1:49 ← | `0xe7df7dca` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40860 → | `0x55d8da57` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[task_id=7 service=shell priv-lvl=1 start_time=1789923297 timezone=UTC cmd=enable <cr>] |
| 172.100.100.1:49 ← | `0x55d8da57` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40862 → | `0xb47e62b4` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice02" port="vty5" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:40862 → | `0xb47e62b4` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xb47e62b4` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xb47e62b4` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.11:40872 → | `0x8f336acf` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice01" port="vty4" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:40872 → | `0x8f336acf` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x8f336acf` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x8f336acf` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.11:40882 → | `0x443864e9` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=1 service=shell priv-lvl=1 start_time=1789923297 timezone=UTC cmd=enable <cr>] |
| 172.100.100.1:49 ← | `0x443864e9` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40894 → | `0x27e8a507` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=1 service=shell start_time=1789923297 timezone=UTC elapsed_time=2] |
| 172.100.100.1:49 ← | `0x27e8a507` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:40908 → | `0x7063a443` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty5" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1789923297 timezone=UTC elapsed_time=2] |
| 172.100.100.1:49 ← | `0x7063a443` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 15, carrying 12 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 19 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 11 connection(s), AUTHEN on 4 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Read the `service=` field in that table: a login START is `login(1)` and an enable START is `enable(2)`. `priv_lvl` on the enable START is the level being asked for, which is what decides whether the username is `$enab15$` or something else on a device that spells it that way.

### When the enable is allowed

phase one measured that this device puts **the operator's own username** on the enable START. port49d was therefore restarted on a config seeding one token under `alice03`, and the same keystrokes were repeated as `alice03`. Nothing else changed.

What the device said:

```
leaf1>enable
Password: 
leaf1#show clock
Sun Sep 20 16:55:10 2026
Timezone: UTC
Clock source: local
```

Every record in that window:

```
2026-09-20T16:55:09.849Z event=redeem verdict=permit reason=token_redeemed user="alice03" port="ssh" rem_addr="172.100.100.1"
2026-09-20T16:55:10.013Z event=account verdict= reason= user="alice03" port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=8
    accounting AV: service=shell
    accounting AV: start_time=1789923309
    accounting AV: timezone=UTC
2026-09-20T16:55:10.274Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=9
    accounting AV: service=shell
    accounting AV: priv-lvl=1
    accounting AV: start_time=1789923309
    accounting AV: timezone=UTC
    accounting AV: cmd=terminal length 0 <cr>
2026-09-20T16:55:10.524Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=10
    accounting AV: service=shell
    accounting AV: priv-lvl=1
    accounting AV: start_time=1789923309
    accounting AV: timezone=UTC
    accounting AV: cmd=disable <cr>
2026-09-20T16:55:10.773Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=11
    accounting AV: service=shell
    accounting AV: priv-lvl=1
    accounting AV: start_time=1789923310
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-20T16:55:11.023Z event=redeem verdict=permit reason=token_redeemed user="alice03" port="vty4" rem_addr="172.100.100.1"
2026-09-20T16:55:11.276Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=21
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789923310
    accounting AV: timezone=UTC
    accounting AV: cmd=show clock <cr>
2026-09-20T16:55:11.529Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=8
    accounting AV: service=shell
    accounting AV: start_time=1789923309
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=2
```

### Not measured

- Two operators from two different client addresses. Both sessions here come from the harness at the bridge's `.1`, so `rem_addr` not distinguishing them is measured only for the shared-bastion case.
- Privilege levels other than the one `enable` with no argument asks for.
- `enable` over any transport but the interactive SSH CLI.
- IOS-XE, which is the platform the `$enab{level}$` spelling comes from and the one this row most needs.
- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question asked of the enable method list rather than the login one.

