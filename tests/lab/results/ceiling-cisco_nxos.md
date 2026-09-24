# Role ceiling — cisco_nxos

- **Date measured:** 2026-09-24
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Captures** (by hand, no loopback probes, all packets to or from the lab subnet):
  `tests/lab/evidence/ceiling-network-operator-cisco_nxos.pcap` (260),
  `ceiling-vdc-operator-cisco_nxos.pcap` (254), `ceiling-network-admin-cisco_nxos.pcap` (260),
  `ceiling-network-operator-cfg-cisco_nxos.pcap` (380)
- **Transport:** SSH, one seeded-token session per role
- **Method:** by hand. port49d restarted per role on a derivation of `tests/lab/port49d-lab.yaml`
  with `session_attributes: ["shell:roles*<role>"]` and no `priv-lvl` (plan 5: the role decides on
  NX-OS and `priv-lvl` beside it is inert, L16); its authorizer permits every command typed.
  Device: `tests/lab/configs/nxos-startup.cfg` (`aaa authorization commands default group port49
  local`, `aaa authorization config-commands default group port49 local`) plus `feature bgp`,
  `router bgp 65000`, `neighbor 192.0.2.2`, `remote-as 65001`.

No register row; recorded for plan 5's adapter levels, beside L16.

## Question

As for `ceiling-cisco_iosxe.md`: with port49 answering PERMIT to every command, what does the
device itself allow at each role port49 could deliver?

## Answer

| delivered role (`show user-account u001`) | `clear counters` | `clear ip bgp *` | `configure terminal` | a configuration change |
|---|---|---|---|---|
| `network-operator` | **allowed** | **allowed** | **allowed** | **applied** |
| `vdc-operator` | allowed | allowed | allowed | not typed |
| `network-admin` | allowed | allowed | allowed | not typed |

**No role narrows anything while command authorization points at port49.** A `network-operator`
session — NX-OS's read-only role — entered configuration mode and set an interface description,
and the running configuration showed it. Every command reached port49 and was permitted there, so
the per-command answer is the whole ceiling on this platform. That is L16's finding ("a delivered
role's own rules do not bind while `aaa authorization commands` points at TACACS+") shown with the
disruptive commands.

## Observation

The three roles gave the same transcript except for the role line:

```
nx1# show user-account u001
user:u001
        roles:network-operator
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# clear counters
error: clearing pfstat counters
nx1# clear ip bgp *
nx1# configure terminal
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# end
```

`clear counters` took about two minutes to return and printed `error: clearing pfstat counters`
for every role, including `network-admin`: it ran, and part of it failed on this virtual
platform. Each session has `authorize_command permit` records for `clear counters`, `clear ip bgp
*`, `configure terminal` and `end`.

The configuration change, `network-operator`:

```
nx1# configure terminal
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# interface e1/1
nx1(config-if)# description p49-ceiling
nx1(config-if)# show running-config interface e1/1
...
interface Ethernet1/1
  description p49-ceiling

nx1(config-if)# no description
nx1(config-if)# end
```

with accounting `configure terminal ; interface Ethernet1/1 ; description p49-ceiling (SUCCESS)`
under `u001`.

## Reading

- Delivering `network-operator` gives an operator nothing narrower than port49's policy. If the
  owner's readonly and operator rungs are to hold on NX-OS while port49 is up, port49's
  per-command rules must enforce them; the role matters only when the device authorizes locally —
  which on an ERROR it does, under `group port49 local` (`L4-error-cisco_nxos.md`).
- The first run of this measurement mis-read its own transcript because `clear counters` outlasted
  the harness's 60s command timeout; the table above is the second run, with a 400s timeout.

*Unmeasured:* a custom role; `clear ip bgp *` against an established session; configuration
changes under `vdc-operator` and `network-admin`.
