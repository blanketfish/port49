# Role ceiling — cisco_iosxe

- **Date measured:** 2026-09-24
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Captures** (by hand, no loopback probes, all packets to or from the lab subnet):
  `tests/lab/evidence/ceiling-priv1-cisco_iosxe.pcap` (254), `ceiling-priv7-cisco_iosxe.pcap`
  (254), `ceiling-priv15-cisco_iosxe.pcap` (338), `ceiling-priv7cfg-cisco_iosxe.pcap` (314, the
  device change below), `ceiling-priv7b-cisco_iosxe.pcap` (254)
- **Transport:** SSH, one seeded-token session per level
- **Method:** by hand. port49d restarted per level on a derivation of `tests/lab/port49d-lab.yaml`
  whose `session_attributes` is `["priv-lvl=N"]` alone (IOS-XE refuses any other attribute, L18),
  and whose authorizer permits every command (no deny prefix matched any command typed). Device:
  `tests/lab/configs/iosxe-startup.cfg` plus `aaa authorization commands 7 default group port49
  local`, `aaa accounting commands 7 default start-stop group port49`, and `router bgp 65000 /
  neighbor 192.0.2.2 remote-as 65001` so that `clear ip bgp *` has something to clear.

There is no register row for this; it is recorded for plan 5's adapter levels. Propose a row
before closing anything on it.

## Question

At each privilege level port49 could deliver, with port49 answering PERMIT to every command,
does the **device itself** allow `clear counters`, `clear ip bgp *` and `configure terminal`? The
owner's intended ladder: readonly = show only; operator = non-disruptive state changes and no
configuration (`clear counters` yes, `clear bgp *` no); admin = everything.

## Answer

| delivered | `clear counters` | `clear ip bgp *` | `configure terminal` |
|---|---|---|---|
| `priv-lvl=1` | refused by the device | refused by the device | refused by the device |
| `priv-lvl=7`, stock config | refused by the device | refused by the device | refused by the device |
| `priv-lvl=7`, with `privilege exec level 7 clear counters` | **allowed** | refused by the device | refused by the device |
| `priv-lvl=15` | allowed | allowed | allowed |

"Refused by the device" means the parser rejected the command and **port49 was never asked** — no
`authorize_command` record exists for it. So on IOS-XE the ladder's middle rung does not exist out
of the box: level 7 is level 1 until the device is told what level 7 may run, and one line of
device configuration (`privilege exec level 7 clear counters`) gives exactly the operator rung.

## Observation

`priv-lvl=1`:

```
xe1>show privilege
Current privilege level is 1
xe1>clear counters
            ^
% Invalid input detected at '^' marker.

xe1>clear ip bgp *
            ^
% Invalid input detected at '^' marker.

xe1>configure terminal
       ^
% Invalid input detected at '^' marker.
```

Decision log for the session: the redeem, the session authorization (`permit context_matched`),
and command authorizations for `terminal length 0`, `show privilege` and — see the note below —
`connect end`; nothing for the three commands under test.

`priv-lvl=7`, stock: the same three refusals, word for word, at `Current privilege level is 7`
with the prompt `xe1#`.

`priv-lvl=15`:

```
xe1#show privilege
Current privilege level is 15
xe1#clear counters
Clear "show interface" counters on all interfaces [confirm]

xe1#clear ip bgp *
xe1#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
xe1(config)#end
```

with `authorize_command permit` for `clear counters` (`priv-lvl` 15 on the request), `clear ip bgp
*` (15) and `configure terminal` (15).

Then, as a level-15 token user: `privilege exec level 7 clear counters` (read back as two lines,
`privilege exec level 7 clear counters` and `privilege exec level 7 clear`). `priv-lvl=7` again:

```
xe1#show privilege
Current privilege level is 7
xe1#clear counters
Clear "show interface" counters on all interfaces [confirm]

xe1#clear ip bgp *
            ^
% Invalid input detected at '^' marker.

xe1#configure terminal
       ^
% Invalid input detected at '^' marker.
```

`clear counters` was authorized by port49 with `priv-lvl=7` on the request; the other two never
reached it.

A side effect worth knowing: at levels 1 and 7 the harness's trailing `end` — not a command at
those levels — was parsed as a Telnet host name and **sent to port49 for authorization as
`cmd=connect cmd-arg=end`**, which the lab authorizer permitted; the device then printed `% Bad IP
address or host name% Unknown command or computer name, or unable to find computer address`. An
unknown word at the exec prompt is an outbound connection attempt on IOS-XE.

## Reading

- IOS-XE enforces its own ceiling below port49: a level the device has given no commands refuses
  them in the parser, with no request to port49 and no record in port49's log. The decision log
  cannot show these refusals.
- An adapter that maps `operator` to a middle level on IOS-XE depends on device configuration
  (`privilege exec level N ...`) that port49 does not deliver. Without it, operator is readonly.
- The request carries the command's level, not the session's: `clear counters` arrived with
  `priv-lvl=15` in the level-15 session and `priv-lvl=7` once it was moved to level 7, while
  `show privilege` arrived with `priv-lvl=1` in both. This run configured `aaa authorization
  commands 7 ...`; what the device does at level 7 without that list is unmeasured.

*Unmeasured:* `clear ip bgp *` against an established session (the neighbour here never came up);
levels other than 1, 7 and 15; `privilege exec` assignments of `configure terminal`.
