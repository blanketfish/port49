# L3 — cisco_iosxe

- **Date measured:** 2026-11-05
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L3-cisco_iosxe.pcap` — 528 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L3-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,nxos,iosxe`, `-run ^TestL3Enable$`

## Claim

Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. Also, because the login-context key now rests on it: what **username** the device puts on an enable START, and whether two concurrent enables are distinguishable.

## Observation

### Before anything was measured

The device's authorization configuration was left exactly as `tests/lab/configs` deploys it: `aaa authorization exec` and `aaa authorization commands` were in force throughout, and the token sessions below passed them.

Two overlapping sessions, each logged in with its own token and each holding at the enable password prompt until the other had reached it, then both answering at once. `disable` precedes `enable` because the seeded session is `priv-lvl=15`: a login lands in enable mode already and typing `enable` there authenticates nothing.

### What the device said

**alice01**:

```
xe1>enable
Password: 
port49: authentication failed, mint a new token with `port49 token`
port49: authentication failed, mint a new token with `port49 token` xe1>
```

**alice02**:

```
xe1>enable
Password: 
port49: authentication failed, mint a new token with `port49 token`
port49: authentication failed, mint a new token with `port49 token` xe1>
```

### The enable authentication, in the decision log

| wire username | verdict | reason | `port` | `rem_addr` |
|---|---|---|---|---|
| `alice02` | deny | `token_not_found` | tty435 | 172.100.100.1 |
| `alice01` | deny | `token_not_found` | tty434 | 172.100.100.1 |

**The two concurrent enables arrived under different usernames**, so the device puts the operator's own identity on the enable START and `(nas, username)` keeps them apart.

Distinct `port` values across the two: 2. Distinct `rem_addr` values: 1. A field with one distinct value across two concurrent enables cannot tell them apart.


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.41:41732 → | `0x04fa408d` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="tty434" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.41:41732 → | `0x04fa408d` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=30 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x04fa408d` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x04fa408d` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.41:41746 → | `0x7edb476f` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="tty434" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x7edb476f` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15] |
| 172.100.100.41:41748 → | `0xcb78d58b` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice01" port="tty434" rem_addr="172.100.100.1" args=[task_id=4005 timezone=UTC service=shell] |
| 172.100.100.1:49 ← | `0xcb78d58b` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:41750 → | `0x3e6d5dbb` | 1 | clear | AUTHOR REQUEST authen_method=none(1) authen_type=ascii(1) service=none(0) priv_lvl=1 user="alice01" port="tty434" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x3e6d5dbb` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.41:41752 → | `0x64af7403` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice01" port="tty434" rem_addr="172.100.100.1" args=[task_id=4005 timezone=UTC service=shell priv-lvl=1 cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0x64af7403` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:41764 → | `0x838a1017` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice01" port="tty434" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.41:41764 → | `0x838a1017` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x838a1017` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x838a1017` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.41:41768 → | `0x5248e0f6` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="tty435" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.41:41768 → | `0x5248e0f6` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=30 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x5248e0f6` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x5248e0f6` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.41:41776 → | `0xaea3bb8d` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="tty435" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0xaea3bb8d` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15] |
| 172.100.100.41:41790 → | `0x2bee49f1` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="tty435" rem_addr="172.100.100.1" args=[task_id=4007 timezone=UTC service=shell] |
| 172.100.100.1:49 ← | `0x2bee49f1` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:41794 → | `0x496a96a8` | 1 | clear | AUTHOR REQUEST authen_method=none(1) authen_type=ascii(1) service=none(0) priv_lvl=1 user="alice02" port="tty435" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x496a96a8` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.41:41806 → | `0x65a6b991` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="tty435" rem_addr="172.100.100.1" args=[task_id=4007 timezone=UTC service=shell priv-lvl=1 cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0x65a6b991` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:41818 → | `0x2bc4a6dc` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice02" port="tty435" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.41:41818 → | `0x2bc4a6dc` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x2bc4a6dc` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x2bc4a6dc` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.41:41830 → | `0x473c2c09` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="tty434" rem_addr="172.100.100.1" args=[task_id=4005 timezone=UTC service=shell disc-cause=1 disc-cause-ext=9 pre-session-time=0 elapsed_time=6 stop_time=1793914033] |
| 172.100.100.41:41846 → | `0xa99586eb` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="tty435" rem_addr="172.100.100.1" args=[task_id=4007 timezone=UTC service=shell disc-cause=1 disc-cause-ext=9 pre-session-time=0 elapsed_time=1 stop_time=1793914033] |
| 172.100.100.1:49 ← | `0x473c2c09` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0xa99586eb` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.41:42200 → | `0x190af4f1` | 1 | clear | ACCT REQUEST flags=stop authen_method=none(1) authen_type=not-set(0) service=none(0) priv_lvl=1 user="yang_mgmt_infra" port="" rem_addr="" args=[task_id=4001 timezone=UTC service=shell priv-lvl=15 cmd=show running-config yang <cr>] |
| 172.100.100.1:49 ← | `0x190af4f1` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 15, carrying 15 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 19 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 7 connection(s), AUTHEN on 4 connection(s), AUTHOR on 4 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Read the `service=` field in that table: a login START is `login(1)` and an enable START is `enable(2)`. `priv_lvl` on the enable START is the level being asked for, which is what decides whether the username is `$enab15$` or something else on a device that spells it that way.

### When the enable is allowed

phase one measured that this device puts **the operator's own username** on the enable START. port49d was therefore restarted on a config seeding one token under `alice03`, and the same keystrokes were repeated as `alice03`. Nothing else changed.

What the device said:

```
xe1>enable
Password: 
xe1#show clock
port49: denied by lab_deny (show clock); see 'port49 explain'
```

Every record in that window:

```
2026-11-05T21:27:24.317Z event=redeem verdict=permit reason=token_redeemed user="alice03" port="tty434" rem_addr="172.100.100.1"
2026-11-05T21:27:24.320Z event=authorize_session verdict=permit reason=context_matched user="alice03" port="tty434" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-11-05T21:27:24.322Z event=account verdict= reason= user="alice03" port="tty434" rem_addr="172.100.100.1"
    accounting AV: task_id=4011
    accounting AV: timezone=UTC
    accounting AV: service=shell
2026-11-05T21:27:24.676Z event=authorize_command verdict=permit reason=permit_dominates user="alice03" port="tty434" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=terminal
    request AV: cmd-arg=length
    request AV: cmd-arg=0
    request AV: cmd-arg=<cr>
2026-11-05T21:27:24.776Z event=account verdict= reason= user="alice03" port="tty434" rem_addr="172.100.100.1"
    accounting AV: task_id=4011
    accounting AV: timezone=UTC
    accounting AV: service=shell
    accounting AV: priv-lvl=1
    accounting AV: cmd=terminal length 0 <cr>
2026-11-05T21:27:25.430Z event=escalate verdict=permit reason=escalation_granted user="alice03" port="tty434" rem_addr="172.100.100.1"
2026-11-05T21:27:25.677Z event=authorize_command verdict=deny reason=no_permit_dominates_deny user="alice03" port="tty434" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=clock
    request AV: cmd-arg=<cr>
2026-11-05T21:27:25.824Z event=account verdict= reason= user="alice03" port="tty434" rem_addr="172.100.100.1"
    accounting AV: task_id=4011
    accounting AV: timezone=UTC
    accounting AV: service=shell
    accounting AV: disc-cause=1
    accounting AV: disc-cause-ext=9
    accounting AV: pre-session-time=0
    accounting AV: elapsed_time=1
    accounting AV: stop_time=1793914045
```

### Not measured

- Two operators from two different client addresses. Both sessions here come from the harness at the bridge's `.1`, so `rem_addr` not distinguishing them is measured only for the shared-bastion case.
- Privilege levels other than the one `enable` with no argument asks for.
- `enable` over any transport but the interactive SSH CLI.
- Any cisco_iosxe release but the one named above, and every platform family this lab does not deploy. The families it does are `arista_eos`, `juniper_vjunos-router`, `juniper_vsrx`, `cisco_nxos`, each in its own L3 note where that platform has an enable exchange at all.
- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question asked of the enable method list rather than the login one.

