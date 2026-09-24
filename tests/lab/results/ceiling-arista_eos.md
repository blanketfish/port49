# Role ceiling — arista_eos

- **Date measured:** 2026-09-24
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Captures** (by hand, no loopback probes, all packets to or from the lab subnet):
  `tests/lab/evidence/ceiling-op15-arista_eos.pcap` (406), `ceiling-priv1-arista_eos.pcap` (226),
  `ceiling-priv15-arista_eos.pcap` (406)
- **Transport:** SSH, one seeded-token session per variant
- **Method:** by hand. port49d restarted per variant on a derivation of
  `tests/lab/port49d-lab.yaml` with the `session_attributes` below; its authorizer permits every
  command typed. Device: `tests/lab/configs/eos-startup.cfg` as shipped (`aaa authorization exec
  default group port49 local`, `aaa authorization commands all default group port49 local`).

No register row; recorded for plan 5's adapter levels, beside L16.

## Question

As for `ceiling-cisco_iosxe.md`: with port49 answering PERMIT to every command, what does the
device itself allow at each role or level port49 could deliver?

## Answer

| delivered | role shown by `show users detail` | `clear counters` | `clear ip bgp *` | `configure terminal` |
|---|---|---|---|---|
| `roles=network-operator`, `priv-lvl=15` | `network-operator` | **allowed** | parsed and allowed; `% BGP inactive` | **allowed** |
| `priv-lvl=1` | not readable: `show users detail` refused | refused by the device | refused by the device | refused by the device |
| `priv-lvl=15` | `<unknown>` | allowed | parsed and allowed; `% BGP inactive` | allowed |

At level 1 every command under test is refused by the device with `% Invalid input (privileged
mode required)` and never reaches port49. At level 15, `network-operator` is not a ceiling while
port49 is in the command path: port49's permit is the only check, as L16 found for `configure`
(`tests/lab/results/L16-arista_eos.md`).

BGP could not be configured on this image — `router bgp 65000` answers `% Unavailable command (not
supported on this hardware platform)`, as does `ip routing` — so `clear ip bgp *` was authorized
by port49 and answered `% BGP inactive`; whether the role would have stopped a real BGP clear is
not measurable here.

## Observation

`["priv-lvl=15", "roles=network-operator"]`:

```
leaf1#show privilege
Current privilege level is 15
leaf1#show users detail
Session       Username       Roles                  TTY        State       Duration       Auth               Remote Host
------------- -------------- ---------------------- ---------- ----------- -------------- ------------------ -------------
1             admin          network-admin          con0       E           0:07:25        local
34            u001           network-operator       vty4       E           0:00:01        group port49       172.100.100.1
leaf1#clear counters
leaf1#
leaf1#clear ip bgp *
% BGP inactive
leaf1#configure terminal
leaf1(config)#end
```

each of `clear counters`, `clear ip bgp *` and `configure terminal` with an `authorize_command
permit` record at `priv-lvl` 15.

`["priv-lvl=1"]`:

```
leaf1>show privilege
Current privilege level is 1
leaf1>show users detail
% Invalid input (privileged mode required)
leaf1>clear counters
% Invalid input (privileged mode required)
leaf1>
leaf1>clear ip bgp *
% Invalid input (privileged mode required)
leaf1>configure terminal
% Invalid input (privileged mode required)
```

and no `authorize_command` record for any of them.

`["priv-lvl=15"]`: the same transcript as the first, with the role column `<unknown>`.

## Reading

- On vEOS the device's own ceiling is the privilege level: level 1 is show-only by the parser,
  level 15 is everything port49 permits. A role delivered beside level 15 does not narrow it while
  command authorization points at port49 — so the owner's `operator` rung (clear counters yes,
  clear bgp no, no config) has to be port49's per-command policy on this platform; the device will
  not enforce it.
- Whether `network-operator` changes a configuration once in `configure terminal` was not typed
  here (only the mode was entered); on the N9Kv it does (`ceiling-cisco_nxos.md`).

*Unmeasured:* a real BGP clear; `roles=network-operator` with `priv-lvl=1`; any level between 1
and 15; the same under `aaa authorization commands all default local`, where L16 found the role
binding.
