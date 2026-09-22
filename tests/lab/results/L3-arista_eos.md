# L3 — arista_eos

- **Date measured:** 2026-09-22
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L3-arista_eos.pcap` — 735 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L3-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
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
leaf1>enable
Password: 
% Error in authentication
% Error in authentication leaf1>
```

**alice03**:

```
leaf1>enable
Password: 
% Error in authentication
% Error in authentication leaf1>
```

### The enable authentication, in the decision log

| wire username | verdict | reason | `port` | `rem_addr` |
|---|---|---|---|---|
| `alice03` | deny | `token_not_found` | vty6 | 172.100.100.1 |
| `alice02` | deny | `token_not_found` | vty4 | 172.100.100.1 |

**The two concurrent enables arrived under different usernames**, so the device puts the operator's own identity on the enable START and `(nas, username)` keeps them apart.

Distinct `port` values across the two: 2. Distinct `rem_addr` values: 1. A field with one distinct value across two concurrent enables cannot tell them apart.


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.11:52766 → | `0xbe79bd59` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:52766 → | `0xbe79bd59` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=30 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xbe79bd59` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xbe79bd59` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:52774 → | `0xf6fca241` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="ssh" rem_addr="172.100.100.1" args=[task_id=12 service=shell start_time=1790092668 timezone=UTC] |
| 172.100.100.1:49 ← | `0xf6fca241` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52784 → | `0x23885016` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x23885016` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.11:52800 → | `0x7da587ed` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x7da587ed` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:52812 → | `0x37a84683` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[task_id=13 service=shell priv-lvl=15 start_time=1790092668 timezone=UTC cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0x37a84683` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52824 → | `0x95ed8c8c` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd=disable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x95ed8c8c` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:52826 → | `0xab5cc789` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[task_id=14 service=shell priv-lvl=15 start_time=1790092669 timezone=UTC cmd=disable <cr>] |
| 172.100.100.1:49 ← | `0xab5cc789` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52840 → | `0xa6ad3e02` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd=enable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0xa6ad3e02` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:52854 → | `0x64ff0e11` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[task_id=15 service=shell priv-lvl=1 start_time=1790092669 timezone=UTC cmd=enable <cr>] |
| 172.100.100.1:49 ← | `0x64ff0e11` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52860 → | `0xdd59a754` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice02" port="vty4" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:52860 → | `0xdd59a754` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xdd59a754` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xdd59a754` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.11:52874 → | `0xff3041b1` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:52874 → | `0xff3041b1` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=30 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xff3041b1` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xff3041b1` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:52880 → | `0x5a3ead25` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="ssh" rem_addr="172.100.100.1" args=[task_id=16 service=shell start_time=1790092673 timezone=UTC] |
| 172.100.100.1:49 ← | `0x5a3ead25` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52882 → | `0xddc1d054` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0xddc1d054` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.11:52884 → | `0xc2a8ba89` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0xc2a8ba89` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:52890 → | `0x6e15deda` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[task_id=17 service=shell priv-lvl=15 start_time=1790092673 timezone=UTC cmd=terminal length 0 <cr>] |
| 172.100.100.1:49 ← | `0x6e15deda` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52906 → | `0x219a3dc9` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd=disable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x219a3dc9` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:52914 → | `0x5f6c2356` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=15 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[task_id=18 service=shell priv-lvl=15 start_time=1790092674 timezone=UTC cmd=disable <cr>] |
| 172.100.100.1:49 ← | `0x5f6c2356` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52918 → | `0xc84644a6` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd=enable cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0xc84644a6` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.11:52930 → | `0x9438fcaf` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[task_id=19 service=shell priv-lvl=1 start_time=1790092674 timezone=UTC cmd=enable <cr>] |
| 172.100.100.1:49 ← | `0x9438fcaf` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52940 → | `0xa885afe7` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15 user="alice03" port="vty6" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:52940 → | `0xa885afe7` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=15 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0xa885afe7` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0xa885afe7` | 4 | clear | AUTHEN REPLY status=FAIL(2) flags=0x00 server_msg="port49: authentication failed, mint a new token with `port49 token`" data=0 bytes |
| 172.100.100.11:52942 → | `0xaecb9c37` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice03" port="vty6" rem_addr="172.100.100.1" args=[task_id=16 service=shell start_time=1790092673 timezone=UTC elapsed_time=2] |
| 172.100.100.1:49 ← | `0xaecb9c37` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:52944 → | `0x7fcb5efc` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice02" port="vty4" rem_addr="172.100.100.1" args=[task_id=12 service=shell start_time=1790092668 timezone=UTC elapsed_time=7] |
| 172.100.100.1:49 ← | `0x7fcb5efc` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 22, carrying 22 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 26 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 10 connection(s), AUTHEN on 4 connection(s), AUTHOR on 8 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Read the `service=` field in that table: a login START is `login(1)` and an enable START is `enable(2)`. `priv_lvl` on the enable START is the level being asked for, which is what decides whether the username is `$enab15$` or something else on a device that spells it that way.

### When the enable is allowed

phase one measured that this device puts **the operator's own username** on the enable START. port49d was therefore restarted on a config seeding one token under `alice04`, and the same keystrokes were repeated as `alice04`. Nothing else changed.

What the device said:

```
leaf1>enable
Password: 
leaf1#show clock
% Authorization denied for command 'show clock': port49: denied by lab_deny (show clock); see 'port49 explain'
```

Every record in that window:

```
2026-09-22T15:58:06.070Z event=redeem verdict=permit reason=token_redeemed user="alice04" port="ssh" rem_addr="172.100.100.1"
2026-09-22T15:58:06.232Z event=account verdict= reason= user="alice04" port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: start_time=1790092685
    accounting AV: timezone=UTC
2026-09-22T15:58:06.271Z event=authorize_session verdict=permit reason=context_matched user="alice04" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-22T15:58:06.493Z event=authorize_command verdict=permit reason=permit_dominates user="alice04" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=terminal
    request AV: cmd-arg=length
    request AV: cmd-arg=0
    request AV: cmd-arg=<cr>
2026-09-22T15:58:06.496Z event=account verdict= reason= user="alice04" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=2
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1790092686
    accounting AV: timezone=UTC
    accounting AV: cmd=terminal length 0 <cr>
2026-09-22T15:58:06.741Z event=authorize_command verdict=permit reason=permit_dominates user="alice04" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=disable
    request AV: cmd-arg=<cr>
2026-09-22T15:58:06.743Z event=account verdict= reason= user="alice04" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=3
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1790092686
    accounting AV: timezone=UTC
    accounting AV: cmd=disable <cr>
2026-09-22T15:58:06.992Z event=authorize_command verdict=permit reason=permit_dominates user="alice04" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-09-22T15:58:06.994Z event=account verdict= reason= user="alice04" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=4
    accounting AV: service=shell
    accounting AV: priv-lvl=1
    accounting AV: start_time=1790092686
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-22T15:58:07.242Z event=escalate verdict=permit reason=escalation_granted user="alice04" port="vty4" rem_addr="172.100.100.1"
2026-09-22T15:58:07.494Z event=authorize_command verdict=deny reason=no_permit_dominates_deny user="alice04" port="vty4" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=clock
    request AV: cmd-arg=<cr>
2026-09-22T15:58:07.748Z event=account verdict= reason= user="alice04" port="vty4" rem_addr="172.100.100.1"
    accounting AV: task_id=1
    accounting AV: service=shell
    accounting AV: start_time=1790092685
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=2
```

### Not measured

- Two operators from two different client addresses. Both sessions here come from the harness at the bridge's `.1`, so `rem_addr` not distinguishing them is measured only for the shared-bastion case.
- Privilege levels other than the one `enable` with no argument asks for.
- `enable` over any transport but the interactive SSH CLI.
- Any arista_eos release but the one named above, and every platform family this lab does not deploy. The families it does are `juniper_vjunos-router`, `juniper_vsrx`, `cisco_nxos`, `cisco_iosxe`, each in its own L3 note where that platform has an enable exchange at all.
- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question asked of the enable method list rather than the login one.

