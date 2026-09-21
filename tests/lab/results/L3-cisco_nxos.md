# L3 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L3-cisco_nxos.pcap` — 240 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L3-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
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
THIS PLATFORM HAS NO ENABLE COMMAND. The device rejected it outright:
^
% Invalid command at '^' marker.
```

**alice03**:

```
THIS PLATFORM HAS NO ENABLE COMMAND. The device rejected it outright:
^
% Invalid command at '^' marker.
```

### The enable authentication, in the decision log

**No authentication record arrived under a username other than the two the harness logged in as.** Either the device sent the operator's own username on the enable START — which the wire table below settles — or it never asked port49 about the enable at all. Every record in the window:
  event=redeem verdict=permit reason=token_redeemed flags= user=alice02 port=0
  event=redeem verdict=permit reason=token_redeemed flags= user=alice03 port=0
  event=authorize_session verdict=permit reason=context_matched flags= user=alice02 port=0
  event=authorize_session verdict=permit reason=context_matched flags= user=alice03 port=0
  event=account verdict= reason= flags=start user=alice02 port=0
  event=account verdict= reason= flags=start user=alice03 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice02 port=
  event=account verdict= reason= flags=stop user=alice02 port=0
  event=authorize_command verdict=permit reason=permit_dominates flags= user=alice03 port=
  event=account verdict= reason= flags=stop user=alice03 port=0
  event=account verdict= reason= flags=stop user=alice02 port=0
  event=account verdict= reason= flags=stop user=alice03 port=0


### The enable exchange on the wire

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.31:46648 → | `0x0703e74e` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice02" port="0" rem_addr="172.100.100.1" data=14 bytes |
| 172.100.100.31:46664 → | `0x538b591d` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice03" port="0" rem_addr="172.100.100.1" data=14 bytes |
| 172.100.100.1:49 ← | `0x0703e74e` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.1:49 ← | `0x538b591d` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.31:46666 → | `0x5b4f601f` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice02" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.31:46676 → | `0x2fa5b79a` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice03" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.1:49 ← | `0x5b4f601f` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.1:49 ← | `0x2fa5b79a` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.31:46686 → | `0x78b610f4` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice02" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1789928310 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x78b610f4` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:46700 → | `0x31f4f859` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice03" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/4 start_time=1789928310 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x31f4f859` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:46712 → | `0x45ddcfee` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=none(0) priv_lvl=1 user="alice02" port="" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x45ddcfee` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.31:46726 → | `0x542cc593` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice02" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1789928311 timezone=UTC cmd=terminal length 0 (SUCCESS) service=none] |
| 172.100.100.1:49 ← | `0x542cc593` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:46738 → | `0x3feceffc` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=none(0) priv_lvl=1 user="alice03" port="" rem_addr="172.100.100.1" args=[service=shell cmd=terminal cmd-arg=length cmd-arg=0 cmd-arg=<cr>] |
| 172.100.100.1:49 ← | `0x3feceffc` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[] |
| 172.100.100.31:46752 → | `0x5bc94aee` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice03" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/4 start_time=1789928311 timezone=UTC cmd=terminal length 0 (SUCCESS) service=none] |
| 172.100.100.1:49 ← | `0x5bc94aee` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:46754 → | `0x2244e112` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice02" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1789928311 timezone=UTC stop_time=1789928311 service=none] |
| 172.100.100.1:49 ← | `0x2244e112` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:46766 → | `0x5d32fbef` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice03" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/4 start_time=1789928311 timezone=UTC stop_time=1789928311 service=none] |
| 172.100.100.1:49 ← | `0x5d32fbef` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

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
- IOS-XE, which is the platform the `$enab{level}$` spelling comes from and the one this row most needs.
- Whether a device that is refused an enable falls back to a local enable secret, which is L4's question asked of the enable method list rather than the login one.

