# L3 — cisco_nxos

- **Date measured:** 2026-11-05
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L3-cisco_nxos.pcap` — 240 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L3-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
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
THIS PLATFORM HAS NO ENABLE COMMAND. The device rejected it outright:
^
% Invalid command at '^' marker.
```

**alice02**:

```
THIS PLATFORM HAS NO ENABLE COMMAND. The device rejected it outright:
^
% Invalid command at '^' marker.
```

### The enable authentication, in the decision log

**No authentication record arrived under a username other than the two the harness logged in as.** Either the device sent the operator's own username on the enable START — which the wire table below settles — or it never asked port49 about the enable at all. Every record in the window:
  event=redeem verdict=permit reason=token_redeemed flags= user=alice01 port=0
  event=authorize_session verdict=permit reason=context_matched flags= user=alice01 port=0
  event=account verdict= reason= flags=start user=alice01 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice01 port=
  event=account verdict= reason= flags=stop user=alice01 port=0
  event=account verdict= reason= flags=stop user=alice01 port=0
  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=0
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=0
  event=account verdict= reason= flags=start user=alice02 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=account verdict= reason= flags=stop user=alice02 port=0
  event=account verdict= reason= flags=stop user=alice02 port=0


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.31:54366 → | `0x1b827ebe` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice01" port="0" rem_addr="172.100.100.1" data=30 bytes |
| 172.100.100.1:49 ← | `0x1b827ebe` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.31:54370 → | `0x352f7a0a` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice01" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.1:49 ← | `0x352f7a0a` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.31:54382 → | `0x4dd88150` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice01" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1793913860 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x4dd88150` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:54384 → | `0x7a0c8dc8` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=none(0) priv_lvl=1 user="alice01" port="" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x7a0c8dc8` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.31:54392 → | `0x06242647` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice01" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1793913861 timezone=UTC cmd=terminal length 0 (SUCCESS) service=none] |
| 172.100.100.1:49 ← | `0x06242647` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:54404 → | `0x24a7fe91` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice01" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1793913861 timezone=UTC stop_time=1793913861 service=none] |
| 172.100.100.1:49 ← | `0x24a7fe91` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:51502 → | `0x40957e13` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice02" port="0" rem_addr="172.100.100.1" data=30 bytes |
| 172.100.100.1:49 ← | `0x40957e13` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.31:51504 → | `0x3ed280a3` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice02" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.1:49 ← | `0x3ed280a3` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.31:51512 → | `0x5de2b2f4` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice02" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1793913865 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x5de2b2f4` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:51526 → | `0x48890524` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=none(0) priv_lvl=1 user="alice02" port="" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x48890524` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.31:51540 → | `0x7df2c539` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice02" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1793913866 timezone=UTC cmd=terminal length 0 (SUCCESS) service=none] |
| 172.100.100.1:49 ← | `0x7df2c539` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:51556 → | `0x78bb8320` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice02" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1793913866 timezone=UTC stop_time=1793913866 service=none] |
| 172.100.100.1:49 ← | `0x78bb8320` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 12, carrying 12 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 12 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 6 connection(s), AUTHEN on 2 connection(s), AUTHOR on 4 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Read the `service=` field in that table: a login START is `login(1)` and an enable START is `enable(2)`. `priv_lvl` on the enable START is the level being asked for, which is what decides whether the username is `$enab15$` or something else on a device that spells it that way.

### When the enable is allowed

Not measured: phase one produced no enable authentication record, so there was no username to seed a token under.

### Not measured

- Two operators from two different client addresses. Both sessions here come from the harness at the bridge's `.1`, so `rem_addr` not distinguishing them is measured only for the shared-bastion case.
- Privilege levels other than the one `enable` with no argument asks for.
- `enable` over any transport but the interactive SSH CLI.
- Any cisco_nxos release but the one named above, and every platform family this lab does not deploy. The families it does are `arista_eos`, `juniper_vjunos-router`, `juniper_vsrx`, `cisco_iosxe`, each in its own L3 note where that platform has an enable exchange at all.
- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question asked of the enable method list rather than the login one.

