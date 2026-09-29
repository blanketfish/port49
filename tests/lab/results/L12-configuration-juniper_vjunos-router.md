# L12-configuration — juniper_vjunos-router

- **Date measured:** 2026-09-25
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L12-configuration-juniper_vjunos-router.pcap` — 1798 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L12-configuration-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Over TACACS+ on `junos-exec`: whether a wire `deny-commands` reaches a statement typed in configuration mode, isolated: one class holding system-control, with and without a deny naming only `set system host-name`, and a sibling statement under the deny (spec §15 L12; it replaces the wire test's configuration-mode cell, whose class could not modify [system]).

## Observation

The admin CLI that configured the class: SSH CLI as breakglass. The class was committed: commit complete.

```
set system login class p49-l12-sys permissions [ configure view view-configuration system system-control ]
set system login user p49-l12-sys class p49-l12-sys
```

| session | reply | why | priv_lvl on the request |
|---|---|---|---|
| same class, no deny | `["local-user-name=p49-l12-sys"]` | the control: the class holds system-control, so the statement must run | 1 |
| same class, deny host-name | `["local-user-name=p49-l12-sys", "deny-commands=^set system host-name( .*)?$"]` | the same class with a deny naming only the host-name statement | 1 |

| probe | same class, no deny | same class, deny host-name |
|---|---|---|
| `configure` | ran | ran |
| `set system host-name srx1` | ran | ran |
| `set system services netconf ssh` | ran | ran |
| `run show system uptime` | ran | ran |
| `exit configuration-mode` | ran | ran |

### Read off the table

- deny-commands in configuration mode: not reached: the statement ran under a deny-commands naming it

### same class, no deny

Reply `["local-user-name=p49-l12-sys"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-sys' login: 'alice01' class 'p49-l12-sys'
Permissions:
    configure   -- Can enter configuration mode
    system      -- Can view system configuration
    system-control-- Can modify system configuration
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

`configure`:

```
 
Entering configuration mode

[edit]
alice01@srx1# 
```

`set system host-name srx1`:

```
 

[edit]
alice01@srx1# 
```

`set system services netconf ssh`:

```
 

[edit]
alice01@srx1# 
```

`run show system uptime`:

```
 
Current time: 2026-09-25 03:20:49 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 03:19:46 UTC (00:01:03 ago)
Protocols started: 2026-09-25 03:20:40 UTC (00:00:09 ago)
Last configured: 2026-09-25 03:20:46 UTC (00:00:03 ago) by breakglass
 3:20AM  up 1 min, 1 users, load averages: 1.88, 0.61, 0.23

[edit]
alice01@srx1# 
```

`exit configuration-mode`:

```
 
Exiting configuration mode

alice01@srx1> 
```

### same class, deny host-name

Reply `["local-user-name=p49-l12-sys", "deny-commands=^set system host-name( .*)?$"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-sys' login: 'alice02' class 'p49-l12-sys'
Permissions:
    configure   -- Can enter configuration mode
    system      -- Can view system configuration
    system-control-- Can modify system configuration
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^set system host-name( .*)?$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice02@srx1> 
```

`configure`:

```
 
Entering configuration mode

[edit]
alice02@srx1# 
```

`set system host-name srx1`:

```
 

[edit]
alice02@srx1# 
```

`set system services netconf ssh`:

```
 

[edit]
alice02@srx1# 
```

`run show system uptime`:

```
 
Current time: 2026-09-25 03:21:01 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 03:19:46 UTC (00:01:15 ago)
Protocols started: 2026-09-25 03:20:40 UTC (00:00:21 ago)
Last configured: 2026-09-25 03:20:46 UTC (00:00:15 ago) by breakglass
 3:21AM  up 1 min, 1 users, load averages: 1.74, 0.62, 0.24

[edit]
alice02@srx1# 
```

`exit configuration-mode`:

```
 
Exiting configuration mode

alice02@srx1> 
```

