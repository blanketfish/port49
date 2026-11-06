# L3 — arista_eos

- **Date measured:** 2026-11-05
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L3-arista_eos.pcap` — 734 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L3-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
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
| `alice01` | deny | `token_not_found` | vty4 | 172.100.100.1 |
| `alice02` | deny | `token_not_found` | vty6 | 172.100.100.1 |

**The two concurrent enables arrived under different usernames**, so the device puts the operator's own identity on the enable START and `(nas, username)` keeps them apart.

Distinct `port` values across the two: 2. Distinct `rem_addr` values: 1. A field with one distinct value across two concurrent enables cannot tell them apart.


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.11:51300 → | `0x541cdacb` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:51300 → | `0x541cdacb` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=30 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x541cdacb` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x541cdacb` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:51310 → | `0xa62e49bf` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="ssh" rem_addr="172.100.100.1" args=[task_id=10 service=shell start_time=1793913625 timezone=UTC] |
| 172.100.100.1:49 ← | `0xa62e49bf` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:51324 → | `0x8418fd52` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x8418fd52` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.11:51340 → | `0x5c1ed2c5` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x5c1ed2c5` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:51350 → | `0x1c8ac99d` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=11 service=shell priv-lvl=15 start_time=1793913625 timezone=UTC cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0x1c8ac99d` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:41608 → | `0xa38ea6b6` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd=disable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0xa38ea6b6` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:41620 → | `0x9edb3a39` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=12 service=shell priv-lvl=15 start_time=1793913626 timezone=UTC cmd=disable <cr>] |
| 172.100.100.1:49 ← | `0x9edb3a39` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:41626 → | `0x39d76b3d` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd=enable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x39d76b3d` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:41636 → | `0x02798960` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice01" port="vty4" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:41636 → | `0x02798960` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.11:41650 → | `0xbe6d8d09` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=1 service=shell priv-lvl=1 start_time=1793913626 timezone=UTC cmd=enable <cr>] |
| 172.100.100.1:49 ← | `0x02798960` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x02798960` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.1:49 ← | `0xbe6d8d09` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:41654 → | `0x86ae36e2` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:41654 → | `0x86ae36e2` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=30 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x86ae36e2` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x86ae36e2` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:41656 → | `0xbe2dcf58` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1793913630 timezone=UTC] |
| 172.100.100.1:49 ← | `0xbe2dcf58` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:41672 → | `0x7bd50ab3` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x7bd50ab3` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.11:41682 → | `0xac4d136a` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0xac4d136a` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:41698 → | `0x15571df2` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[task_id=3 service=shell priv-lvl=15 start_time=1793913631 timezone=UTC cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0x15571df2` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:41700 → | `0x0488c187` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd=disable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x0488c187` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:41706 → | `0x86834b9c` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[task_id=4 service=shell priv-lvl=15 start_time=1793913631 timezone=UTC cmd=disable <cr>] |
| 172.100.100.1:49 ← | `0x86834b9c` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:41722 → | `0xe8e78bfb` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd=enable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0xe8e78bfb` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:41738 → | `0xc43cbe86` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice02" port="vty6" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:41738 → | `0xc43cbe86` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.11:41752 → | `0x78f45e15` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[task_id=1 service=shell priv-lvl=1 start_time=1793913631 timezone=UTC cmd=enable <cr>] |
| 172.100.100.1:49 ← | `0x78f45e15` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.1:49 ← | `0xc43cbe86` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xc43cbe86` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.11:41768 → | `0x8907fd30` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty6" rem_addr="172.100.100.1" args=[task_id=2 service=shell start_time=1793913630 timezone=UTC elapsed_time=2] |
| 172.100.100.1:49 ← | `0x8907fd30` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:41774 → | `0x2b259230` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice01" port="vty4" rem_addr="172.100.100.1" args=[task_id=10 service=shell start_time=1793913625 timezone=UTC elapsed_time=7] |
| 172.100.100.1:49 ← | `0x2b259230` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 22, carrying 22 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 26 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 10 connection(s), AUTHEN on 4 connection(s), AUTHOR on 8 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Read the `service=` field in that table: a login START is `login(1)` and an enable START is `enable(2)`. `priv_lvl` on the enable START is the level being asked for, which is what decides whether the username is `$enab15$` or something else on a device that spells it that way.

### When the enable is allowed

phase one measured that this device puts **the operator's own username** on the enable START. port49d was therefore restarted on a config seeding one token under `alice03`, and the same keystrokes were repeated as `alice03`. Nothing else changed.

What the device said:

```
leaf1>enable
Password: 
leaf1#show clock
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
```

Every record in that window:

```
2026-11-05T21:20:43.429Z event=redeem verdict=permit reason=token_redeemed user="alice03" port="ssh" rem_addr="172.100.100.1"
2026-11-05T21:20:43.592Z event=account verdict= reason= user="alice03" port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=5
    accounting AV: service=shell
    accounting AV: start_time=1793913642
    accounting AV: timezone=UTC
2026-11-05T21:20:43.631Z event=authorize_session verdict=permit reason=context_matched user="alice03" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-11-05T21:20:43.852Z event=authorize_command verdict=permit reason=permit_dominates user="alice03" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=terminal
    request AV: cmd-arg=length
    request AV: cmd-arg=0
    request AV: cmd-arg=<cr>
2026-11-05T21:20:43.855Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=6
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1793913643
    accounting AV: timezone=UTC
    accounting AV: cmd=terminal length 0 <cr>
2026-11-05T21:20:44.101Z event=authorize_command verdict=permit reason=permit_dominates user="alice03" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=disable
    request AV: cmd-arg=<cr>
2026-11-05T21:20:44.104Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=7
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1793913643
    accounting AV: timezone=UTC
    accounting AV: cmd=disable <cr>
2026-11-05T21:20:44.352Z event=authorize_command verdict=permit reason=permit_dominates user="alice03" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-11-05T21:20:44.355Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=8
    accounting AV: service=shell
    accounting AV: priv-lvl=1
    accounting AV: start_time=1793913643
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-11-05T21:20:44.601Z event=escalate verdict=permit reason=escalation_granted user="alice03" port="vty4" rem_addr="172.100.100.1"
2026-11-05T21:20:44.855Z event=authorize_command verdict=deny reason=no_permit_dominates_deny user="alice03" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=clock
    request AV: cmd-arg=<cr>
2026-11-05T21:20:45.106Z event=account verdict= reason= user="alice03" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=5
    accounting AV: service=shell
    accounting AV: start_time=1793913642
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=2
```

### Not measured

- Two operators from two different client addresses. Both sessions here come from the harness at the bridge's `.1`, so `rem_addr` not distinguishing them is measured only for the shared-bastion case.
- Privilege levels other than the one `enable` with no argument asks for.
- `enable` over any transport but the interactive SSH CLI.
- Any arista_eos release but the one named above, and every platform family this lab does not deploy. The families it does are `juniper_vjunos-router`, `juniper_vsrx`, `cisco_nxos`, `cisco_iosxe`, each in its own L3 note where that platform has an enable exchange at all.
- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question asked of the enable method list rather than the login one.

