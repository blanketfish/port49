# L12-configuration — juniper_vjunos-router

- **Date measured:** 2026-11-05
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L12-configuration-juniper_vjunos-router.pcap` — 1481 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L12-configuration-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL12JunosConfiguration$`

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
 
Current time: 2026-11-05 22:10:57 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:09:42 UTC (00:01:15 ago)
Protocols started: 2026-11-05 22:10:38 UTC (00:00:19 ago)
Last configured: 2026-11-05 22:10:52 UTC (00:00:05 ago) by breakglass
10:10PM  up 1 min, 1 users, load averages: 2.19, 0.78, 0.30

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
 
Current time: 2026-11-05 22:11:15 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:09:42 UTC (00:01:33 ago)
Protocols started: 2026-11-05 22:10:38 UTC (00:00:37 ago)
Last configured: 2026-11-05 22:10:52 UTC (00:00:23 ago) by breakglass
10:11PM  up 2 mins, 1 users, load averages: 1.81, 0.78, 0.31

[edit]
alice02@srx1# 
```

`exit configuration-mode`:

```
 
Exiting configuration mode

alice02@srx1> 
```

