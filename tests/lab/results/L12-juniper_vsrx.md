# L12 — juniper_vsrx

- **Date measured:** 2026-11-05
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L12-juniper_vsrx.pcap` — 5397 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L12-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL12JunosWire$`

## Claim

Over TACACS+ on `junos-exec`: whether `user-permissions` is applied over a bitless template, replacing or merging, per session, and two bits in one value; whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits, and what it does to the commands a class with no bits runs; whether deny-commands reaches a statement typed in configuration mode, and `run`; whether `deny-commands-regexps` beats `allow-commands-regexps`; whether `allow-commands2` is an attribute of its own; whether a template user commits with no uid, and whether it can be logged into locally (spec §8, §13 decision 22, §15 L12).

## Observation

The templates were committed without a uid (commit complete).

| variant | reply | why | priv_lvl on the request |
|---|---|---|---|
| control | `["local-user-name=p49-l12-all"]` | every bit and no regex: what the device runs at all | 1 |
| bitless | `["local-user-name=p49-l12-none"]` | a template with no bits: the baseline every session has | 1 |
| bitless + user-permissions | `["local-user-name=p49-l12-none", "user-permissions=view"]` | L12: is user-permissions applied over a bitless template | 1 |
| bitless + two bits | `["local-user-name=p49-l12-none", "user-permissions=view clear"]` | L12: two bits in one value, space-separated, as the generator writes them | 1 |
| remote + user-permissions | `["user-permissions=view"]` | L12: over remote's view view-configuration, does it replace (view alone) or merge | 1 |
| narrow | `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^(show version\|show interfaces( .*)?)$"]` | L12: deny .* and one allow alternation yield exactly the permits, and what .* does to the baseline | 1 |
| deny unanchored word | `["local-user-name=p49-l12-all", "deny-commands=version"]` | L9: is a deny regex matched anywhere in the line | 1 |
| deny prefix | `["local-user-name=p49-l12-all", "deny-commands=show ver"]` | L9: is it matched as a prefix | 1 |
| deny anchored | `["local-user-name=p49-l12-all", "deny-commands=^show version( *\\\|.*)?$"]` | L9: explicit anchors with the pipe tail the generator writes; and the case and abbreviation of `show version` | 1 |
| deny argument | `["local-user-name=p49-l12-all", "deny-commands=^show interfaces fxp0( .*)?$"]` | L9: an argument's case and an abbreviated command against a deny | 1 |
| deny malformed | `["local-user-name=p49-l12-all", "deny-commands=^(show$"]` | L9: a regex the dialect rejects: refused session, ignored, or applied | 1 |
| configuration mode | `["local-user-name=p49-l12-cfg", "deny-commands=^(set system host-name.*\|show version)$"]` | L12: does deny-commands reach a statement typed in configuration mode, and `run` | 1 |
| regexps family | `["local-user-name=p49-l12-view", "deny-commands-regexps=^show version$", "allow-commands-regexps=^show version$"]` | L12: does the -regexps family's deny beat its allow over the wire | 1 |
| numbered name | `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^show version$", "allow-commands2=^show system uptime$"]` | L12: is allow-commands2 an attribute of its own | 1 |

| probe | control | bitless | bitless + user-permissions | bitless + two bits | remote + user-permissions | narrow | deny unanchored word | deny prefix | deny anchored | deny argument | deny malformed | configuration mode | regexps family | numbered name |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `show version` | ran | refused | ran | ran | ran | ran | refused | refused | refused | ran | refused | refused | refused | ran |
| `show version \| no-more` | ran | refused | ran | ran | ran | ran | refused | refused | refused | ran | refused | refused | refused | ran |
| `show system uptime` | ran | refused | ran | ran | ran | refused | ran | ran | ran | ran | refused | ran | ran | ran |
| `show interfaces terse` | ran | refused | ran | ran | ran | ran | ran | ran | ran | ran | refused | ran | ran | refused |
| `show interfaces fxp0 terse` | ran | refused | ran | ran | ran | ran | ran | ran | ran | ran | refused | ran | ran | refused |
| `show configuration system host-name` | ran | refused | refused | refused | ran | refused | ran | ran | ran | ran | refused | ran | refused | refused |
| `clear interfaces statistics fxp0` | ran | refused | refused | ran | refused | refused | ran | ran | ran | ran | refused | refused | refused | refused |
| `ping 127.0.0.1 count 1 rapid` | ran | refused | refused | refused | refused | refused | ran | ran | ran | ran | refused | refused | refused | refused |
| `SHOW VERSION` | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) |
| `show interfaces FXP0 terse` | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) | not comparable (the control did not run it) |
| `sh ver` | ran | refused | ran | ran | ran | ran | refused | refused | refused | ran | refused | refused | refused | ran |
| `sh int fxp0 terse` | ran | refused | ran | ran | ran | ran | ran | ran | ran | ran | refused | ran | ran | refused |
| `set cli screen-width 200` | ran | ran | ran | ran | ran | refused | ran | ran | ran | ran | ran | ran | ran | refused |
| `file list /var/tmp` | ran | ran | ran | ran | ran | refused | ran | ran | ran | ran | ran | ran | ran | refused |
| `request system reboot` | completes | absent | absent | absent | absent | absent | completes | completes | completes | completes | absent | absent | absent | absent |
| `restart routing` | completes | absent | absent | absent | absent | absent | completes | completes | completes | completes | absent | absent | absent | absent |
| `configure` | ran | — | — | — | — | — | — | — | — | — | — | ran | — | — |
| `set system host-name srx1` | ran | — | — | — | — | — | — | — | — | — | — | refused | — | — |
| `run show version` | ran | — | — | — | — | — | — | — | — | — | — | refused | — | — |
| `run show system uptime` | ran | — | — | — | — | — | — | — | — | — | — | ran | — | — |
| `exit configuration-mode` | ran | — | — | — | — | — | — | — | — | — | — | ran | — | — |

### Read off the table

- explicit anchors with the pipe tail: true: `^show version( *\|.*)?$` refused `show version` (true) and `show version | no-more` (true), and ran `show system uptime` (true)
- unanchored: `version` refused `show version` (true); `show ver` refused `show version` (true)
- JunosFacts.CaseSensitive = false: false only where every other-case spelling was refused by the CLI in the control or by the deny
- JunosFacts.DenyMatchesExpanded = false: true only where the control ran both abbreviations and each deny refused them
- a malformed deny `^(show$`: the session opened true; the device refused the login false (no error); `show version` ran false
- narrow shape exact: true: ran `show version` true and `show interfaces terse` true; refused `show system uptime` true, `clear interfaces statistics fxp0` true, `ping` true, the configuration true
- under deny .*, the commands a class with no bits runs: `set cli screen-width 200` bitless true, narrow false; `file list /var/tmp` bitless true, narrow false
- user-permissions over a bitless template applied: true; both bits of a two-bit value applied: true (bit_delivery: user_permissions only if both are true, and per session below)
- user-permissions over remote: `show cli authorization` lists view-configuration: true (true: merged or ignored; false: replaced)
- a statement typed in configuration mode under a deny-commands naming it: refused; `run show version` under a deny naming `show version`: refused
- -regexps: `show version` refused with both deny and allow naming it: true
- allow-commands2 an attribute of its own: `show system uptime` ran: true
- per session: A before `show cli authorization Current user: 'p49-l12-none' login: 'alice15' class 'p49-l12-none' Permissions: view -- Can view current values and statistics Individual command authorization: Allow regular expression: none Deny regular expression: none Allow configuration regular expression: none Deny configuration regular expression: none alice15@srx1>`, B `show ^ unknown command. alice16@srx1> show cli ^ unknown command. alice16@srx1> showcli authorization ^ unknown command. alice16@srx1>`, A after B `show cli authorization Current user: 'p49-l12-none' login: 'alice15' class 'p49-l12-none' Permissions: view -- Can view current values and statistics Individual command authorization: Allow regular expression: none Deny regular expression: none Allow configuration regular expression: none Deny configuration regular expression: none alice15@srx1>`

- a template user with no authentication, locally: empty password refused, `x` refused
- `authentication encrypted-password "*"` commits: true (commit complete)
- that template, locally: empty password refused, `*` refused


### control

Reply `["local-user-name=p49-l12-all"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-all' login: 'alice01' class 'p49-l12-all'
Permissions:
    access      -- Can view access configuration
    access-control-- Can modify access configuration
    admin       -- Can view user accounts
    admin-control-- Can modify user accounts
    clear       -- Can clear learned network info
    configure   -- Can enter configuration mode
    control     -- Can modify any config
    edit        -- Can edit full files
    field       -- Can use field debug commands
    firewall    -- Can view firewall configuration
    firewall-control-- Can modify firewall configuration
    floppy      -- Can read and write the floppy
    interface   -- Can view interface configuration
    interface-control-- Can modify interface configuration
    maintenance -- Can become the super-user
    network     -- Can access the network
    reset       -- Can reset/restart interfaces and daemons
    rollback    -- Can rollback to previous configurations
    routing     -- Can view routing configuration
    routing-control-- Can modify routing configuration
    secret      -- Can view secret statements
    secret-control-- Can modify secret statements
    security    -- Can view security configuration
    security-control-- Can modify security configuration
    shell       -- Can start a local shell
    snmp        -- Can view SNMP configuration
    snmp-control-- Can modify SNMP configuration
    storage     -- Can view fibre channel storage protocol configuration
    storage-control-- Can modify fibre channel storage protocol configuration
    system      -- Can view system configuration
    system-control-- Can modify system configuration
    trace       -- Can view trace file settings
    trace-control-- Can modify trace file settings
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
    all-control -- Can modify any configuration
    flow-tap    -- Can view flow-tap configuration
    flow-tap-control-- Can modify flow-tap configuration
    flow-tap-operation-- Can tap flows
    idp-profiler-operation-- Can Profiler data
    pgcp-session-mirroring-- Can view pgcp session mirroring configuration
    pgcp-session-mirroring-control-- Can modify pgcp session mirroring configuration
    unified-edge-- Can view unified edge configuration
    unified-edge-control-- Can modify unified edge configuration
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice01@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice01@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:28:52 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:00:58 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:00:13 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:00:04 ago) by breakglass
10:28PM  up 57 secs, 1 users, load averages: 2.07, 0.69, 0.26

alice01@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
dsc                     up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
tap                     up    up

alice01@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice01@srx1> 
```

`show configuration system host-name`:

```
 
host-name srx1;

alice01@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice01@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
 
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: sendto: Can't assign requested address
.
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

alice01@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice01@srx1> SHOW   VERSION
              ^
unknown command.

alice01@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice01@srx1> 
```

`sh ver`:

```
show version 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice01@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice01@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice01@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice01@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  decrypt              Decrypt a $8$ or $9$-encrypted password
  download             Manage downloads
  firmware             Upgrade or downgrade firmware
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
  set-encryption-key   Set EEPROM stored encryption key
  snapshot             Create a normal Junos or a recovery snapshot
  software             Perform system software extension or upgrade
  storage              Request operation on system storage
  yang                 Perform YANG schema operations
  zeroize              Erase all data, including configuration and log files
alice01@srx1> request system    
```

`restart routing`:

```
alice01@srx1>                  restart ?
Possible completions:
> SDN-Telemetry        agent for all the telemetry sensors
> advanced-anti-malware  Advanced Anti-Malware daemon
> analytics-agent      Analytics agent
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> application-security  Application security daemon
> audit-process        Audit process
> autoinstallation     Autoinstallation process
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> cloudagent           Cloudagent process
> cloudham-service     Cloud HA Management Daemon
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
  ddns                 Restart the dynamic DNS client
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> dialer-services      Dialer services process
> diameter-service     Diameter process
> dynamic-filtering    Dynamic Filtering Daemon
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fipsd                FIPS daemon
> firewall             Firewall process
> firewall-authentication-service  Firewall authentication daemon
> forwarding           Forwarding Daemon
> general-authentication-service  General authentication process
> gprs-process         gprs daemon
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group key member daemon
> group-key-server     Group key server daemon
> gstatd               geom-device performance monitoring daemon
> idp-policy           IDP policy daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> interface-control    Interface control process
> ipmi                 Intelligent platform management interface daemon
> ipsec-key-management  IPSec Key Management daemon
> jnu-management       Junos node unifier process
> jnx-wmicd-service    wmicd service process
> jsd                  JET Services Daemon
> jsrp-service         Juniper Stateful Redundancy Protocol Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> local-log-management  Local Log Management Daemon
> logical-system-service  Logical System Daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
  named-service        DNS server process
> netproxy             netproxy service
> network-security     Network security daemon
> network-security-trace  Network security trace daemon
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ntpd-service         Network Time Protocol Service
> peer-selection-service  Peer selection service process
> pgm                  Pragmatic General Multicast process
> phone-home-client    Phone home client daemon
> pki-service          PKI service daemon
> ppp                  PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> profilerd            Profiler Daemon
> redundancy-interface-process  Redundancy interface management process
> remote-operations    Remote operations process
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpcbind-service      Service for rpc requests
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> security-intelligence  IPF daemon
> security-log         Security Log Daemon
> service-deployment   Service Deployment Client
> simple-mail-client-service  Simple Mail Transfer Protocol Client process
> slaacd               SLAAC process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> sysctl-relay-process  Sysctl Relaying Process
> system-health-management  System Health Management Daemon
> system-log-vital     System Log Vital Daemon
> tunnel-oamd          Tunnel OAM process
> uac-service          Unified access control daemon
> ui-pubd              Mosquitto pub client process
> user-ad-authentication  user id daemon
> vrrp                 Virtual Router Redundancy Protocol process
  web-management       Web management process
> webapi-service       webapi service process
> wireless-wan-service  Wireless WAN process
> xmlproxyd            XMLPROXY Daemon
alice01@srx1> restart    
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

`run show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

[edit]
alice01@srx1# 
```

`run show system uptime`:

```
 
Current time: 2026-11-05 22:29:13 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:01:19 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:00:34 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:00:25 ago) by breakglass
10:29PM  up 1 min, 1 users, load averages: 2.13, 0.79, 0.31

[edit]
alice01@srx1# 
```

`exit configuration-mode`:

```
 
Exiting configuration mode

alice01@srx1> 
```

### bitless

Reply `["local-user-name=p49-l12-none"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice02@srx1> show   cli
              ^
unknown command.
alice02@srx1> showcli   authorization
              ^
unknown command.

alice02@srx1> 
```

`show version`:

```
show
              ^
unknown command.
alice02@srx1> show   version
              ^
unknown command.

alice02@srx1> 
```

`show version | no-more`:

```
show
              ^
unknown command.
alice02@srx1> show   version
              ^
unknown command.
alice02@srx1> showversion   |
              ^
unknown command.
alice02@srx1> showversion|   no-more
              ^
unknown command.

alice02@srx1> 
```

`show system uptime`:

```
show
              ^
unknown command.
alice02@srx1> show   system
              ^
unknown command.
alice02@srx1> showsystem   uptime
              ^
unknown command.

alice02@srx1> 
```

`show interfaces terse`:

```
show
              ^
unknown command.
alice02@srx1> show   interfaces
              ^
unknown command.
alice02@srx1> showinterfaces   terse
              ^
unknown command.

alice02@srx1> 
```

`show interfaces fxp0 terse`:

```
show
              ^
unknown command.
alice02@srx1> show   interfaces
              ^
unknown command.
alice02@srx1> showinterfaces   fxp0
              ^
unknown command.
alice02@srx1> showinterfacesfxp0   terse
              ^
unknown command.

alice02@srx1> 
```

`show configuration system host-name`:

```
show
              ^
unknown command.
alice02@srx1> show   configuration
              ^
unknown command.
alice02@srx1> showconfiguration   system
              ^
unknown command.
alice02@srx1> showconfigurationsystem   host-name
              ^
unknown command.

alice02@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice02@srx1> clear   interfaces
              ^
unknown command.
alice02@srx1> clearinterfaces   statistics
              ^
unknown command.
alice02@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice02@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice02@srx1> ping   127.0.0.1
              ^
unknown command.
alice02@srx1> ping127.0.0.1   count
              ^
unknown command.
alice02@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice02@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice02@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice02@srx1> SHOW   VERSION
              ^
unknown command.

alice02@srx1> 
```

`show interfaces FXP0 terse`:

```
show
              ^
unknown command.
alice02@srx1> show   interfaces
              ^
unknown command.
alice02@srx1> showinterfaces   FXP0
              ^
unknown command.
alice02@srx1> showinterfacesFXP0   terse
              ^
unknown command.

alice02@srx1> 
```

`sh ver`:

```
sh
              ^
unknown command.
alice02@srx1> sh   ver
              ^
unknown command.

alice02@srx1> 
```

`sh int fxp0 terse`:

```
sh
              ^
unknown command.
alice02@srx1> sh   int
              ^
unknown command.
alice02@srx1> shint   fxp0
              ^
unknown command.
alice02@srx1> shintfxp0   terse
              ^
unknown command.

alice02@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice02@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice02@srx1> 
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice02@srx1> request system   ?
No valid completions
alice02@srx1> request system   
```

`restart routing`:

```
alice02@srx1>                 restart
              ^
unknown command.
alice02@srx1> restart   ?
No valid completions
alice02@srx1> restart   
```

### bitless + user-permissions

Reply `["local-user-name=p49-l12-none", "user-permissions=view"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-none' login: 'alice03' class 'p49-l12-none'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice03@srx1> 
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice03@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice03@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:29:58 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:02:04 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:01:19 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:01:10 ago) by breakglass
10:29PM  up 2 mins, 1 users, load averages: 1.71, 0.87, 0.36

alice03@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice03@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice03@srx1> 
```

`show configuration system host-name`:

```
show configuration system
                                 ^
syntax error.
alice03@srx1> show configuration system   host-name
                                 ^
syntax error.

alice03@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice03@srx1> clear   interfaces
              ^
unknown command.
alice03@srx1> clearinterfaces   statistics
              ^
unknown command.
alice03@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice03@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice03@srx1> ping   127.0.0.1
              ^
unknown command.
alice03@srx1> ping127.0.0.1   count
              ^
unknown command.
alice03@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice03@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice03@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice03@srx1> SHOW   VERSION
              ^
unknown command.

alice03@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice03@srx1> 
```

`sh ver`:

```
show version 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice03@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice03@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice03@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice03@srx1> 
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice03@srx1> request system   ?
No valid completions
alice03@srx1> request system   
```

`restart routing`:

```
alice03@srx1>                 restart
              ^
unknown command.
alice03@srx1> restart   ?
No valid completions
alice03@srx1> restart   
```

### bitless + two bits

Reply `["local-user-name=p49-l12-none", "user-permissions=view clear"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-none' login: 'alice04' class 'p49-l12-none'
Permissions:
    clear       -- Can clear learned network info
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice04@srx1> 
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice04@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice04@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:30:27 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:02:33 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:01:48 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:01:39 ago) by breakglass
10:30PM  up 3 mins, 1 users, load averages: 1.61, 0.91, 0.39

alice04@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice04@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice04@srx1> 
```

`show configuration system host-name`:

```
show configuration system
                                 ^
syntax error.
alice04@srx1> show configuration system   host-name
                                 ^
syntax error.

alice04@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice04@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice04@srx1> ping   127.0.0.1
              ^
unknown command.
alice04@srx1> ping127.0.0.1   count
              ^
unknown command.
alice04@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice04@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice04@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice04@srx1> SHOW   VERSION
              ^
unknown command.

alice04@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice04@srx1> 
```

`sh ver`:

```
show version 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice04@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice04@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice04@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice04@srx1> 
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice04@srx1> request system   ?
No valid completions
alice04@srx1> request system   
```

`restart routing`:

```
alice04@srx1>                 restart
              ^
unknown command.
alice04@srx1> restart   ?
No valid completions
alice04@srx1> restart   
```

### remote + user-permissions

Reply `["user-permissions=view"]`. `show cli authorization`:

```
 
Current user: 'remote' login: 'alice05' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice05@srx1> 
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice05@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice05@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:30:56 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:03:02 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:02:17 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:02:08 ago) by breakglass
10:30PM  up 3 mins, 1 users, load averages: 1.37, 0.92, 0.41

alice05@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice05@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice05@srx1> 
```

`show configuration system host-name`:

```
 
host-name srx1;

alice05@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice05@srx1> clear   interfaces
              ^
unknown command.
alice05@srx1> clearinterfaces   statistics
              ^
unknown command.
alice05@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice05@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice05@srx1> ping   127.0.0.1
              ^
unknown command.
alice05@srx1> ping127.0.0.1   count
              ^
unknown command.
alice05@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice05@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice05@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice05@srx1> SHOW   VERSION
              ^
unknown command.

alice05@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice05@srx1> 
```

`sh ver`:

```
show version 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice05@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice05@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice05@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice05@srx1> 
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice05@srx1> request system   ?
No valid completions
alice05@srx1> request system   
```

`restart routing`:

```
alice05@srx1>                 restart
              ^
unknown command.
alice05@srx1> restart   ?
No valid completions
alice05@srx1> restart   
```

### narrow

Reply `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^(show version|show interfaces( .*)?)$"]`. `show cli authorization`:

```
show cli
                   ^
syntax error, expecting <command>.
alice06@srx1> show cli   authorization
                   ^
syntax error, expecting <command>.

alice06@srx1> 
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice06@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice06@srx1> 
```

`show system uptime`:

```
show system
                   ^
syntax error, expecting <command>.
alice06@srx1> show system   uptime
                   ^
syntax error, expecting <command>.

alice06@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice06@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice06@srx1> 
```

`show configuration system host-name`:

```
show configuration
                   ^
syntax error, expecting <command>.
alice06@srx1> show configuration   system
                   ^
syntax error, expecting <command>.
alice06@srx1> show configurationsystem   host-name
                   ^
syntax error, expecting <command>.

alice06@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice06@srx1> clear   interfaces
              ^
unknown command.
alice06@srx1> clearinterfaces   statistics
              ^
unknown command.
alice06@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice06@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice06@srx1> ping   127.0.0.1
              ^
unknown command.
alice06@srx1> ping127.0.0.1   count
              ^
unknown command.
alice06@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice06@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice06@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice06@srx1> SHOW   VERSION
              ^
unknown command.

alice06@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice06@srx1> 
```

`sh ver`:

```
show version 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice06@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice06@srx1> 
```

`set cli screen-width 200`:

```
set
              ^
unknown command.
alice06@srx1> set   cli
              ^
unknown command.
alice06@srx1> setcli   screen-width
              ^
unknown command.
alice06@srx1> setcliscreen-width   200
              ^
unknown command.

alice06@srx1> 
```

`file list /var/tmp`:

```
file
              ^
unknown command.
alice06@srx1> file   list
              ^
unknown command.
alice06@srx1> filelist   /var/tmp
              ^
unknown command.

alice06@srx1> 
```

`request system reboot`:

```
request
              ^
unknown command.
alice06@srx1> request   system
              ^
unknown command.
alice06@srx1> requestsystem   ?
No valid completions
alice06@srx1> requestsystem   
```

`restart routing`:

```
alice06@srx1>                restart
              ^
unknown command.
alice06@srx1> restart   ?
No valid completions
alice06@srx1> restart   
```

### deny unanchored word

Reply `["local-user-name=p49-l12-all", "deny-commands=version"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-all' login: 'alice07' class 'p49-l12-all'
Permissions:
    access      -- Can view access configuration
    access-control-- Can modify access configuration
    admin       -- Can view user accounts
    admin-control-- Can modify user accounts
    clear       -- Can clear learned network info
    configure   -- Can enter configuration mode
    control     -- Can modify any config
    edit        -- Can edit full files
    field       -- Can use field debug commands
    firewall    -- Can view firewall configuration
    firewall-control-- Can modify firewall configuration
    floppy      -- Can read and write the floppy
    interface   -- Can view interface configuration
    interface-control-- Can modify interface configuration
    maintenance -- Can become the super-user
    network     -- Can access the network
    reset       -- Can reset/restart interfaces and daemons
    rollback    -- Can rollback to previous configurations
    routing     -- Can view routing configuration
    routing-control-- Can modify routing configuration
    secret      -- Can view secret statements
    secret-control-- Can modify secret statements
    security    -- Can view security configuration
    security-control-- Can modify security configuration
    shell       -- Can start a local shell
    snmp        -- Can view SNMP configuration
    snmp-control-- Can modify SNMP configuration
    storage     -- Can view fibre channel storage protocol configuration
    storage-control-- Can modify fibre channel storage protocol configuration
    system      -- Can view system configuration
    system-control-- Can modify system configuration
    trace       -- Can view trace file settings
    trace-control-- Can modify trace file settings
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
    all-control -- Can modify any configuration
    flow-tap    -- Can view flow-tap configuration
    flow-tap-control-- Can modify flow-tap configuration
    flow-tap-operation-- Can tap flows
    idp-profiler-operation-- Can Profiler data
    pgcp-session-mirroring-- Can view pgcp session mirroring configuration
    pgcp-session-mirroring-control-- Can modify pgcp session mirroring configuration
    unified-edge-- Can view unified edge configuration
    unified-edge-control-- Can modify unified edge configuration
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (version)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice07@srx1> 
```

`show version`:

```
                   ^
syntax error, expecting <command>.

alice07@srx1> 
```

`show version | no-more`:

```
show version
                   ^
syntax error, expecting <command>.
alice07@srx1> show version   |
                   ^
permission denied.
alice07@srx1> show version|   no-more
                   ^
permission denied.

alice07@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:31:54 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:04:00 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:03:15 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:03:06 ago) by breakglass
10:31PM  up 4 mins, 1 users, load averages: 1.35, 1.00, 0.47

alice07@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice07@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice07@srx1> 
```

`show configuration system host-name`:

```
 
host-name srx1;

alice07@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice07@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
 
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: sendto: Can't assign requested address
.
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

alice07@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice07@srx1> SHOW   VERSION
              ^
unknown command.

alice07@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice07@srx1> 
```

`sh ver`:

```
show ver
                   ^
syntax error, expecting <command>.

alice07@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice07@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice07@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice07@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  decrypt              Decrypt a $8$ or $9$-encrypted password
  download             Manage downloads
  firmware             Upgrade or downgrade firmware
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
  set-encryption-key   Set EEPROM stored encryption key
  snapshot             Create a normal Junos or a recovery snapshot
  software             Perform system software extension or upgrade
  storage              Request operation on system storage
  yang                 Perform YANG schema operations
  zeroize              Erase all data, including configuration and log files
alice07@srx1> request system    
```

`restart routing`:

```
alice07@srx1>                  restart ?
Possible completions:
> SDN-Telemetry        agent for all the telemetry sensors
> advanced-anti-malware  Advanced Anti-Malware daemon
> analytics-agent      Analytics agent
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> application-security  Application security daemon
> audit-process        Audit process
> autoinstallation     Autoinstallation process
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> cloudagent           Cloudagent process
> cloudham-service     Cloud HA Management Daemon
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
  ddns                 Restart the dynamic DNS client
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> dialer-services      Dialer services process
> diameter-service     Diameter process
> dynamic-filtering    Dynamic Filtering Daemon
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fipsd                FIPS daemon
> firewall             Firewall process
> firewall-authentication-service  Firewall authentication daemon
> forwarding           Forwarding Daemon
> general-authentication-service  General authentication process
> gprs-process         gprs daemon
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group key member daemon
> group-key-server     Group key server daemon
> gstatd               geom-device performance monitoring daemon
> idp-policy           IDP policy daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> interface-control    Interface control process
> ipmi                 Intelligent platform management interface daemon
> ipsec-key-management  IPSec Key Management daemon
> jnu-management       Junos node unifier process
> jnx-wmicd-service    wmicd service process
> jsd                  JET Services Daemon
> jsrp-service         Juniper Stateful Redundancy Protocol Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> local-log-management  Local Log Management Daemon
> logical-system-service  Logical System Daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
  named-service        DNS server process
> netproxy             netproxy service
> network-security     Network security daemon
> network-security-trace  Network security trace daemon
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ntpd-service         Network Time Protocol Service
> peer-selection-service  Peer selection service process
> pgm                  Pragmatic General Multicast process
> phone-home-client    Phone home client daemon
> pki-service          PKI service daemon
> ppp                  PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> profilerd            Profiler Daemon
> redundancy-interface-process  Redundancy interface management process
> remote-operations    Remote operations process
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpcbind-service      Service for rpc requests
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> security-intelligence  IPF daemon
> security-log         Security Log Daemon
> service-deployment   Service Deployment Client
> simple-mail-client-service  Simple Mail Transfer Protocol Client process
> slaacd               SLAAC process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> sysctl-relay-process  Sysctl Relaying Process
> system-health-management  System Health Management Daemon
> system-log-vital     System Log Vital Daemon
> tunnel-oamd          Tunnel OAM process
> uac-service          Unified access control daemon
> ui-pubd              Mosquitto pub client process
> user-ad-authentication  user id daemon
> vrrp                 Virtual Router Redundancy Protocol process
  web-management       Web management process
> webapi-service       webapi service process
> wireless-wan-service  Wireless WAN process
> xmlproxyd            XMLPROXY Daemon
alice07@srx1> restart    
```

### deny prefix

Reply `["local-user-name=p49-l12-all", "deny-commands=show ver"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-all' login: 'alice08' class 'p49-l12-all'
Permissions:
    access      -- Can view access configuration
    access-control-- Can modify access configuration
    admin       -- Can view user accounts
    admin-control-- Can modify user accounts
    clear       -- Can clear learned network info
    configure   -- Can enter configuration mode
    control     -- Can modify any config
    edit        -- Can edit full files
    field       -- Can use field debug commands
    firewall    -- Can view firewall configuration
    firewall-control-- Can modify firewall configuration
    floppy      -- Can read and write the floppy
    interface   -- Can view interface configuration
    interface-control-- Can modify interface configuration
    maintenance -- Can become the super-user
    network     -- Can access the network
    reset       -- Can reset/restart interfaces and daemons
    rollback    -- Can rollback to previous configurations
    routing     -- Can view routing configuration
    routing-control-- Can modify routing configuration
    secret      -- Can view secret statements
    secret-control-- Can modify secret statements
    security    -- Can view security configuration
    security-control-- Can modify security configuration
    shell       -- Can start a local shell
    snmp        -- Can view SNMP configuration
    snmp-control-- Can modify SNMP configuration
    storage     -- Can view fibre channel storage protocol configuration
    storage-control-- Can modify fibre channel storage protocol configuration
    system      -- Can view system configuration
    system-control-- Can modify system configuration
    trace       -- Can view trace file settings
    trace-control-- Can modify trace file settings
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
    all-control -- Can modify any configuration
    flow-tap    -- Can view flow-tap configuration
    flow-tap-control-- Can modify flow-tap configuration
    flow-tap-operation-- Can tap flows
    idp-profiler-operation-- Can Profiler data
    pgcp-session-mirroring-- Can view pgcp session mirroring configuration
    pgcp-session-mirroring-control-- Can modify pgcp session mirroring configuration
    unified-edge-- Can view unified edge configuration
    unified-edge-control-- Can modify unified edge configuration
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (show ver)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice08@srx1> 
```

`show version`:

```
                   ^
syntax error, expecting <command>.

alice08@srx1> 
```

`show version | no-more`:

```
show version
                   ^
syntax error, expecting <command>.
alice08@srx1> show version   |
                   ^
permission denied.
alice08@srx1> show version|   no-more
                   ^
permission denied.

alice08@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:32:24 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:04:30 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:03:45 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:03:36 ago) by breakglass
10:32PM  up 4 mins, 1 users, load averages: 1.80, 1.14, 0.54

alice08@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice08@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice08@srx1> 
```

`show configuration system host-name`:

```
 
host-name srx1;

alice08@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice08@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
 
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: sendto: Can't assign requested address
.
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

alice08@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice08@srx1> SHOW   VERSION
              ^
unknown command.

alice08@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice08@srx1> 
```

`sh ver`:

```
show ver
                   ^
syntax error, expecting <command>.

alice08@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice08@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice08@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice08@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  decrypt              Decrypt a $8$ or $9$-encrypted password
  download             Manage downloads
  firmware             Upgrade or downgrade firmware
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
  set-encryption-key   Set EEPROM stored encryption key
  snapshot             Create a normal Junos or a recovery snapshot
  software             Perform system software extension or upgrade
  storage              Request operation on system storage
  yang                 Perform YANG schema operations
  zeroize              Erase all data, including configuration and log files
alice08@srx1> request system    
```

`restart routing`:

```
alice08@srx1>                  restart ?
Possible completions:
> SDN-Telemetry        agent for all the telemetry sensors
> advanced-anti-malware  Advanced Anti-Malware daemon
> analytics-agent      Analytics agent
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> application-security  Application security daemon
> audit-process        Audit process
> autoinstallation     Autoinstallation process
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> cloudagent           Cloudagent process
> cloudham-service     Cloud HA Management Daemon
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
  ddns                 Restart the dynamic DNS client
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> dialer-services      Dialer services process
> diameter-service     Diameter process
> dynamic-filtering    Dynamic Filtering Daemon
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fipsd                FIPS daemon
> firewall             Firewall process
> firewall-authentication-service  Firewall authentication daemon
> forwarding           Forwarding Daemon
> general-authentication-service  General authentication process
> gprs-process         gprs daemon
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group key member daemon
> group-key-server     Group key server daemon
> gstatd               geom-device performance monitoring daemon
> idp-policy           IDP policy daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> interface-control    Interface control process
> ipmi                 Intelligent platform management interface daemon
> ipsec-key-management  IPSec Key Management daemon
> jnu-management       Junos node unifier process
> jnx-wmicd-service    wmicd service process
> jsd                  JET Services Daemon
> jsrp-service         Juniper Stateful Redundancy Protocol Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> local-log-management  Local Log Management Daemon
> logical-system-service  Logical System Daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
  named-service        DNS server process
> netproxy             netproxy service
> network-security     Network security daemon
> network-security-trace  Network security trace daemon
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ntpd-service         Network Time Protocol Service
> peer-selection-service  Peer selection service process
> pgm                  Pragmatic General Multicast process
> phone-home-client    Phone home client daemon
> pki-service          PKI service daemon
> ppp                  PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> profilerd            Profiler Daemon
> redundancy-interface-process  Redundancy interface management process
> remote-operations    Remote operations process
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpcbind-service      Service for rpc requests
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> security-intelligence  IPF daemon
> security-log         Security Log Daemon
> service-deployment   Service Deployment Client
> simple-mail-client-service  Simple Mail Transfer Protocol Client process
> slaacd               SLAAC process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> sysctl-relay-process  Sysctl Relaying Process
> system-health-management  System Health Management Daemon
> system-log-vital     System Log Vital Daemon
> tunnel-oamd          Tunnel OAM process
> uac-service          Unified access control daemon
> ui-pubd              Mosquitto pub client process
> user-ad-authentication  user id daemon
> vrrp                 Virtual Router Redundancy Protocol process
  web-management       Web management process
> webapi-service       webapi service process
> wireless-wan-service  Wireless WAN process
> xmlproxyd            XMLPROXY Daemon
alice08@srx1> restart    
```

### deny anchored

Reply `["local-user-name=p49-l12-all", "deny-commands=^show version( *\\|.*)?$"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-all' login: 'alice09' class 'p49-l12-all'
Permissions:
    access      -- Can view access configuration
    access-control-- Can modify access configuration
    admin       -- Can view user accounts
    admin-control-- Can modify user accounts
    clear       -- Can clear learned network info
    configure   -- Can enter configuration mode
    control     -- Can modify any config
    edit        -- Can edit full files
    field       -- Can use field debug commands
    firewall    -- Can view firewall configuration
    firewall-control-- Can modify firewall configuration
    floppy      -- Can read and write the floppy
    interface   -- Can view interface configuration
    interface-control-- Can modify interface configuration
    maintenance -- Can become the super-user
    network     -- Can access the network
    reset       -- Can reset/restart interfaces and daemons
    rollback    -- Can rollback to previous configurations
    routing     -- Can view routing configuration
    routing-control-- Can modify routing configuration
    secret      -- Can view secret statements
    secret-control-- Can modify secret statements
    security    -- Can view security configuration
    security-control-- Can modify security configuration
    shell       -- Can start a local shell
    snmp        -- Can view SNMP configuration
    snmp-control-- Can modify SNMP configuration
    storage     -- Can view fibre channel storage protocol configuration
    storage-control-- Can modify fibre channel storage protocol configuration
    system      -- Can view system configuration
    system-control-- Can modify system configuration
    trace       -- Can view trace file settings
    trace-control-- Can modify trace file settings
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
    all-control -- Can modify any configuration
    flow-tap    -- Can view flow-tap configuration
    flow-tap-control-- Can modify flow-tap configuration
    flow-tap-operation-- Can tap flows
    idp-profiler-operation-- Can Profiler data
    pgcp-session-mirroring-- Can view pgcp session mirroring configuration
    pgcp-session-mirroring-control-- Can modify pgcp session mirroring configuration
    unified-edge-- Can view unified edge configuration
    unified-edge-control-- Can modify unified edge configuration
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^show version( *\|.*)?$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice09@srx1> 
```

`show version`:

```
 
                           ^
missing argument.

alice09@srx1> 
```

`show version | no-more`:

```
show version |
                           ^
syntax error, expecting <command>.
alice09@srx1> show version |   no-more
                           ^
syntax error, expecting <command>.

alice09@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:32:53 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:04:59 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:04:14 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:04:05 ago) by breakglass
10:32PM  up 5 mins, 1 users, load averages: 1.56, 1.15, 0.56

alice09@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice09@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice09@srx1> 
```

`show configuration system host-name`:

```
 
host-name srx1;

alice09@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice09@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
 
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: sendto: Can't assign requested address
.
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

alice09@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice09@srx1> SHOW   VERSION
              ^
unknown command.

alice09@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice09@srx1> 
```

`sh ver`:

```
show version 
                           ^
missing argument.

alice09@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice09@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice09@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice09@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  decrypt              Decrypt a $8$ or $9$-encrypted password
  download             Manage downloads
  firmware             Upgrade or downgrade firmware
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
  set-encryption-key   Set EEPROM stored encryption key
  snapshot             Create a normal Junos or a recovery snapshot
  software             Perform system software extension or upgrade
  storage              Request operation on system storage
  yang                 Perform YANG schema operations
  zeroize              Erase all data, including configuration and log files
alice09@srx1> request system    
```

`restart routing`:

```
alice09@srx1>                  restart ?
Possible completions:
> SDN-Telemetry        agent for all the telemetry sensors
> advanced-anti-malware  Advanced Anti-Malware daemon
> analytics-agent      Analytics agent
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> application-security  Application security daemon
> audit-process        Audit process
> autoinstallation     Autoinstallation process
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> cloudagent           Cloudagent process
> cloudham-service     Cloud HA Management Daemon
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
  ddns                 Restart the dynamic DNS client
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> dialer-services      Dialer services process
> diameter-service     Diameter process
> dynamic-filtering    Dynamic Filtering Daemon
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fipsd                FIPS daemon
> firewall             Firewall process
> firewall-authentication-service  Firewall authentication daemon
> forwarding           Forwarding Daemon
> general-authentication-service  General authentication process
> gprs-process         gprs daemon
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group key member daemon
> group-key-server     Group key server daemon
> gstatd               geom-device performance monitoring daemon
> idp-policy           IDP policy daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> interface-control    Interface control process
> ipmi                 Intelligent platform management interface daemon
> ipsec-key-management  IPSec Key Management daemon
> jnu-management       Junos node unifier process
> jnx-wmicd-service    wmicd service process
> jsd                  JET Services Daemon
> jsrp-service         Juniper Stateful Redundancy Protocol Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> local-log-management  Local Log Management Daemon
> logical-system-service  Logical System Daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
  named-service        DNS server process
> netproxy             netproxy service
> network-security     Network security daemon
> network-security-trace  Network security trace daemon
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ntpd-service         Network Time Protocol Service
> peer-selection-service  Peer selection service process
> pgm                  Pragmatic General Multicast process
> phone-home-client    Phone home client daemon
> pki-service          PKI service daemon
> ppp                  PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> profilerd            Profiler Daemon
> redundancy-interface-process  Redundancy interface management process
> remote-operations    Remote operations process
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpcbind-service      Service for rpc requests
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> security-intelligence  IPF daemon
> security-log         Security Log Daemon
> service-deployment   Service Deployment Client
> simple-mail-client-service  Simple Mail Transfer Protocol Client process
> slaacd               SLAAC process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> sysctl-relay-process  Sysctl Relaying Process
> system-health-management  System Health Management Daemon
> system-log-vital     System Log Vital Daemon
> tunnel-oamd          Tunnel OAM process
> uac-service          Unified access control daemon
> ui-pubd              Mosquitto pub client process
> user-ad-authentication  user id daemon
> vrrp                 Virtual Router Redundancy Protocol process
  web-management       Web management process
> webapi-service       webapi service process
> wireless-wan-service  Wireless WAN process
> xmlproxyd            XMLPROXY Daemon
alice09@srx1> restart    
```

### deny argument

Reply `["local-user-name=p49-l12-all", "deny-commands=^show interfaces fxp0( .*)?$"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-all' login: 'alice10' class 'p49-l12-all'
Permissions:
    access      -- Can view access configuration
    access-control-- Can modify access configuration
    admin       -- Can view user accounts
    admin-control-- Can modify user accounts
    clear       -- Can clear learned network info
    configure   -- Can enter configuration mode
    control     -- Can modify any config
    edit        -- Can edit full files
    field       -- Can use field debug commands
    firewall    -- Can view firewall configuration
    firewall-control-- Can modify firewall configuration
    floppy      -- Can read and write the floppy
    interface   -- Can view interface configuration
    interface-control-- Can modify interface configuration
    maintenance -- Can become the super-user
    network     -- Can access the network
    reset       -- Can reset/restart interfaces and daemons
    rollback    -- Can rollback to previous configurations
    routing     -- Can view routing configuration
    routing-control-- Can modify routing configuration
    secret      -- Can view secret statements
    secret-control-- Can modify secret statements
    security    -- Can view security configuration
    security-control-- Can modify security configuration
    shell       -- Can start a local shell
    snmp        -- Can view SNMP configuration
    snmp-control-- Can modify SNMP configuration
    storage     -- Can view fibre channel storage protocol configuration
    storage-control-- Can modify fibre channel storage protocol configuration
    system      -- Can view system configuration
    system-control-- Can modify system configuration
    trace       -- Can view trace file settings
    trace-control-- Can modify trace file settings
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
    all-control -- Can modify any configuration
    flow-tap    -- Can view flow-tap configuration
    flow-tap-control-- Can modify flow-tap configuration
    flow-tap-operation-- Can tap flows
    idp-profiler-operation-- Can Profiler data
    pgcp-session-mirroring-- Can view pgcp session mirroring configuration
    pgcp-session-mirroring-control-- Can modify pgcp session mirroring configuration
    unified-edge-- Can view unified edge configuration
    unified-edge-control-- Can modify unified edge configuration
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^show interfaces fxp0( .*)?$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice10@srx1> 
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice10@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice10@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:33:23 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:05:29 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:04:44 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:04:35 ago) by breakglass
10:33PM  up 5 mins, 1 users, load averages: 1.56, 1.18, 0.59

alice10@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice10@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice10@srx1> 
```

`show configuration system host-name`:

```
 
host-name srx1;

alice10@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice10@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
 
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: sendto: Can't assign requested address
.
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

alice10@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice10@srx1> SHOW   VERSION
              ^
unknown command.

alice10@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice10@srx1> 
```

`sh ver`:

```
show version 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice10@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice10@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice10@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice10@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  decrypt              Decrypt a $8$ or $9$-encrypted password
  download             Manage downloads
  firmware             Upgrade or downgrade firmware
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
  set-encryption-key   Set EEPROM stored encryption key
  snapshot             Create a normal Junos or a recovery snapshot
  software             Perform system software extension or upgrade
  storage              Request operation on system storage
  yang                 Perform YANG schema operations
  zeroize              Erase all data, including configuration and log files
alice10@srx1> request system    
```

`restart routing`:

```
alice10@srx1>                  restart ?
Possible completions:
> SDN-Telemetry        agent for all the telemetry sensors
> advanced-anti-malware  Advanced Anti-Malware daemon
> analytics-agent      Analytics agent
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> application-security  Application security daemon
> audit-process        Audit process
> autoinstallation     Autoinstallation process
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> cloudagent           Cloudagent process
> cloudham-service     Cloud HA Management Daemon
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
  ddns                 Restart the dynamic DNS client
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> dialer-services      Dialer services process
> diameter-service     Diameter process
> dynamic-filtering    Dynamic Filtering Daemon
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fipsd                FIPS daemon
> firewall             Firewall process
> firewall-authentication-service  Firewall authentication daemon
> forwarding           Forwarding Daemon
> general-authentication-service  General authentication process
> gprs-process         gprs daemon
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group key member daemon
> group-key-server     Group key server daemon
> gstatd               geom-device performance monitoring daemon
> idp-policy           IDP policy daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> interface-control    Interface control process
> ipmi                 Intelligent platform management interface daemon
> ipsec-key-management  IPSec Key Management daemon
> jnu-management       Junos node unifier process
> jnx-wmicd-service    wmicd service process
> jsd                  JET Services Daemon
> jsrp-service         Juniper Stateful Redundancy Protocol Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> local-log-management  Local Log Management Daemon
> logical-system-service  Logical System Daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
  named-service        DNS server process
> netproxy             netproxy service
> network-security     Network security daemon
> network-security-trace  Network security trace daemon
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ntpd-service         Network Time Protocol Service
> peer-selection-service  Peer selection service process
> pgm                  Pragmatic General Multicast process
> phone-home-client    Phone home client daemon
> pki-service          PKI service daemon
> ppp                  PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> profilerd            Profiler Daemon
> redundancy-interface-process  Redundancy interface management process
> remote-operations    Remote operations process
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpcbind-service      Service for rpc requests
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> security-intelligence  IPF daemon
> security-log         Security Log Daemon
> service-deployment   Service Deployment Client
> simple-mail-client-service  Simple Mail Transfer Protocol Client process
> slaacd               SLAAC process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> sysctl-relay-process  Sysctl Relaying Process
> system-health-management  System Health Management Daemon
> system-log-vital     System Log Vital Daemon
> tunnel-oamd          Tunnel OAM process
> uac-service          Unified access control daemon
> ui-pubd              Mosquitto pub client process
> user-ad-authentication  user id daemon
> vrrp                 Virtual Router Redundancy Protocol process
  web-management       Web management process
> webapi-service       webapi service process
> wireless-wan-service  Wireless WAN process
> xmlproxyd            XMLPROXY Daemon
alice10@srx1> restart    
```

### deny malformed

Reply `["local-user-name=p49-l12-all", "deny-commands=^(show$"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice11@srx1> show   cli
              ^
unknown command.
alice11@srx1> showcli   authorization
              ^
unknown command.

alice11@srx1> 
```

`show version`:

```
show
              ^
unknown command.
alice11@srx1> show   version
              ^
unknown command.

alice11@srx1> 
```

`show version | no-more`:

```
show
              ^
unknown command.
alice11@srx1> show   version
              ^
unknown command.
alice11@srx1> showversion   |
              ^
unknown command.
alice11@srx1> showversion|   no-more
              ^
unknown command.

alice11@srx1> 
```

`show system uptime`:

```
show
              ^
unknown command.
alice11@srx1> show   system
              ^
unknown command.
alice11@srx1> showsystem   uptime
              ^
unknown command.

alice11@srx1> 
```

`show interfaces terse`:

```
show
              ^
unknown command.
alice11@srx1> show   interfaces
              ^
unknown command.
alice11@srx1> showinterfaces   terse
              ^
unknown command.

alice11@srx1> 
```

`show interfaces fxp0 terse`:

```
show
              ^
unknown command.
alice11@srx1> show   interfaces
              ^
unknown command.
alice11@srx1> showinterfaces   fxp0
              ^
unknown command.
alice11@srx1> showinterfacesfxp0   terse
              ^
unknown command.

alice11@srx1> 
```

`show configuration system host-name`:

```
show
              ^
unknown command.
alice11@srx1> show   configuration
              ^
unknown command.
alice11@srx1> showconfiguration   system
              ^
unknown command.
alice11@srx1> showconfigurationsystem   host-name
              ^
unknown command.

alice11@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice11@srx1> clear   interfaces
              ^
unknown command.
alice11@srx1> clearinterfaces   statistics
              ^
unknown command.
alice11@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice11@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice11@srx1> ping   127.0.0.1
              ^
unknown command.
alice11@srx1> ping127.0.0.1   count
              ^
unknown command.
alice11@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice11@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice11@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice11@srx1> SHOW   VERSION
              ^
unknown command.

alice11@srx1> 
```

`show interfaces FXP0 terse`:

```
show
              ^
unknown command.
alice11@srx1> show   interfaces
              ^
unknown command.
alice11@srx1> showinterfaces   FXP0
              ^
unknown command.
alice11@srx1> showinterfacesFXP0   terse
              ^
unknown command.

alice11@srx1> 
```

`sh ver`:

```
sh
              ^
unknown command.
alice11@srx1> sh   ver
              ^
unknown command.

alice11@srx1> 
```

`sh int fxp0 terse`:

```
sh
              ^
unknown command.
alice11@srx1> sh   int
              ^
unknown command.
alice11@srx1> shint   fxp0
              ^
unknown command.
alice11@srx1> shintfxp0   terse
              ^
unknown command.

alice11@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice11@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice11@srx1> 
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice11@srx1> request system   ?
No valid completions
alice11@srx1> request system   
```

`restart routing`:

```
alice11@srx1>                 restart
              ^
unknown command.
alice11@srx1> restart   ?
No valid completions
alice11@srx1> restart   
```

### configuration mode

Reply `["local-user-name=p49-l12-cfg", "deny-commands=^(set system host-name.*|show version)$"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-cfg' login: 'alice12' class 'p49-l12-cfg'
Permissions:
    configure   -- Can enter configuration mode
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^(set system host-name.*|show version)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice12@srx1> 
```

`show version`:

```
 
                           ^
missing argument.

alice12@srx1> 
```

`show version | no-more`:

```
show version |
                           ^
syntax error, expecting <command>.
alice12@srx1> show version |   no-more
                           ^
syntax error, expecting <command>.

alice12@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:34:22 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:06:28 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:05:43 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:05:34 ago) by breakglass
10:34PM  up 6 mins, 1 users, load averages: 1.36, 1.19, 0.63

alice12@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice12@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice12@srx1> 
```

`show configuration system host-name`:

```
 
host-name srx1;

alice12@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear interfaces
                    ^
syntax error, expecting <command>.
alice12@srx1> clear interfaces   statistics
                    ^
syntax error, expecting <command>.
alice12@srx1> clear interfacesstatistics   fxp0
                    ^
syntax error, expecting <command>.

alice12@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice12@srx1> ping   127.0.0.1
              ^
unknown command.
alice12@srx1> ping127.0.0.1   count
              ^
unknown command.
alice12@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice12@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice12@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice12@srx1> SHOW   VERSION
              ^
unknown command.

alice12@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice12@srx1> 
```

`sh ver`:

```
show version 
                           ^
missing argument.

alice12@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice12@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice12@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice12@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  malware-scan         Scan for malware
  set-encryption-key   Set EEPROM stored encryption key
alice12@srx1> request system    
```

`restart routing`:

```
alice12@srx1>                  restart
              ^
unknown command.
alice12@srx1> restart   ?
No valid completions
alice12@srx1> restart   
```

`configure`:

```
 
Entering configuration mode

[edit]
alice12@srx1# 
```

`set system host-name srx1`:

```
set system
                  ^
syntax error.
alice12@srx1# set system   host-name
                  ^
syntax error.
alice12@srx1# set systemhost-name   srx1
                  ^
syntax error.

[edit]
alice12@srx1# 
```

`run show version`:

```
 
                               ^
missing argument.

[edit]
alice12@srx1# 
```

`run show system uptime`:

```
 
Current time: 2026-11-05 22:34:41 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:06:47 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:06:02 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:05:53 ago) by breakglass
10:34PM  up 7 mins, 1 users, load averages: 1.42, 1.21, 0.65

[edit]
alice12@srx1# 
```

`exit configuration-mode`:

```
 
Exiting configuration mode

alice12@srx1> 
```

### regexps family

Reply `["local-user-name=p49-l12-view", "deny-commands-regexps=^show version$", "allow-commands-regexps=^show version$"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-view' login: 'alice13' class 'p49-l12-view'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: "^show version$"
    Deny regular expression: "^show version$"
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice13@srx1> 
```

`show version`:

```
                   ^
syntax error, expecting <command>.

alice13@srx1> 
```

`show version | no-more`:

```
show version
                   ^
syntax error, expecting <command>.
alice13@srx1> show version   |
                   ^
permission denied.
alice13@srx1> show version|   no-more
                   ^
permission denied.

alice13@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:34:57 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:07:03 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:06:18 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:06:09 ago) by breakglass
10:34PM  up 7 mins, 1 users, load averages: 1.48, 1.23, 0.67

alice13@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
gr-0/0/0                up    up
ip-0/0/0                up    up
lt-0/0/0                up    up
mt-0/0/0                up    up
sp-0/0/0                up    up
sp-0/0/0.0              up    up   inet    
                                   inet6   
sp-0/0/0.16383          up    up   inet    
dsc                     up    up
fti0                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64
gre                     up    up
ipip                    up    up
irb                     up    up
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet     10.0.0.1            --> 0/0
                                            10.0.0.16           --> 0/0
                                            128.0.0.1           --> 0/0
                                            128.0.0.4           --> 0/0
                                            128.0.1.16          --> 0/0
lo0.32768               up    up  
lsi                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pp0                     up    up
ppd0                    up    up
ppe0                    up    up
st0                     up    up
tap                     up    up
vlan                    up    down

alice13@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice13@srx1> 
```

`show configuration system host-name`:

```
show configuration system
                                 ^
syntax error.
alice13@srx1> show configuration system   host-name
                                 ^
syntax error.

alice13@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear interfaces
                    ^
syntax error, expecting <command>.
alice13@srx1> clear interfaces   statistics
                    ^
syntax error, expecting <command>.
alice13@srx1> clear interfacesstatistics   fxp0
                    ^
syntax error, expecting <command>.

alice13@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice13@srx1> ping   127.0.0.1
              ^
unknown command.
alice13@srx1> ping127.0.0.1   count
              ^
unknown command.
alice13@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice13@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice13@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice13@srx1> SHOW   VERSION
              ^
unknown command.

alice13@srx1> 
```

`show interfaces FXP0 terse`:

```
 
error: device FXP0 not found

alice13@srx1> 
```

`sh ver`:

```
show ver
                   ^
syntax error, expecting <command>.

alice13@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:d2ff:fe83:f200/64

alice13@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice13@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice13@srx1> 
```

`request system reboot`:

```
request system ?
No valid completions
alice13@srx1> request system    
```

`restart routing`:

```
alice13@srx1>                  restart
              ^
unknown command.
alice13@srx1> restart   ?
No valid completions
alice13@srx1> restart   
```

### numbered name

Reply `["local-user-name=p49-l12-view", "deny-commands=^.*$", "allow-commands=^show version$", "allow-commands2=^show system uptime$"]`. `show cli authorization`:

```
show cli
                   ^
syntax error, expecting <command>.
alice14@srx1> show cli   authorization
                   ^
syntax error, expecting <command>.

alice14@srx1> 
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice14@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice14@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 22:35:26 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 22:27:54 UTC (00:07:32 ago)
Protocols started: 2026-11-05 22:28:39 UTC (00:06:47 ago)
Last configured: 2026-11-05 22:28:48 UTC (00:06:38 ago) by breakglass
10:35PM  up 8 mins, 1 users, load averages: 1.55, 1.27, 0.70

alice14@srx1> 
```

`show interfaces terse`:

```
show interfaces
                   ^
syntax error, expecting <command>.
alice14@srx1> show interfaces   terse
                   ^
syntax error, expecting <command>.

alice14@srx1> 
```

`show interfaces fxp0 terse`:

```
show interfaces
                   ^
syntax error, expecting <command>.
alice14@srx1> show interfaces   fxp0
                   ^
syntax error, expecting <command>.
alice14@srx1> show interfacesfxp0   terse
                   ^
syntax error, expecting <command>.

alice14@srx1> 
```

`show configuration system host-name`:

```
show configuration
                   ^
syntax error, expecting <command>.
alice14@srx1> show configuration   system
                   ^
syntax error, expecting <command>.
alice14@srx1> show configurationsystem   host-name
                   ^
syntax error, expecting <command>.

alice14@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice14@srx1> clear   interfaces
              ^
unknown command.
alice14@srx1> clearinterfaces   statistics
              ^
unknown command.
alice14@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice14@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice14@srx1> ping   127.0.0.1
              ^
unknown command.
alice14@srx1> ping127.0.0.1   count
              ^
unknown command.
alice14@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice14@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice14@srx1> 
```

`SHOW VERSION`:

```
SHOW
              ^
unknown command.
alice14@srx1> SHOW   VERSION
              ^
unknown command.

alice14@srx1> 
```

`show interfaces FXP0 terse`:

```
show interfaces
                   ^
syntax error, expecting <command>.
alice14@srx1> show interfaces   FXP0
                   ^
syntax error, expecting <command>.
alice14@srx1> show interfacesFXP0   terse
                   ^
syntax error, expecting <command>.

alice14@srx1> 
```

`sh ver`:

```
show version 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice14@srx1> 
```

`sh int fxp0 terse`:

```
show int
                   ^
syntax error, expecting <command>.
alice14@srx1> show int   fxp0
                   ^
syntax error, expecting <command>.
alice14@srx1> show intfxp0   terse
                   ^
syntax error, expecting <command>.

alice14@srx1> 
```

`set cli screen-width 200`:

```
set
              ^
unknown command.
alice14@srx1> set   cli
              ^
unknown command.
alice14@srx1> setcli   screen-width
              ^
unknown command.
alice14@srx1> setcliscreen-width   200
              ^
unknown command.

alice14@srx1> 
```

`file list /var/tmp`:

```
file
              ^
unknown command.
alice14@srx1> file   list
              ^
unknown command.
alice14@srx1> filelist   /var/tmp
              ^
unknown command.

alice14@srx1> 
```

`request system reboot`:

```
request
              ^
unknown command.
alice14@srx1> request   system
              ^
unknown command.
alice14@srx1> requestsystem   ?
No valid completions
alice14@srx1> requestsystem   
```

`restart routing`:

```
alice14@srx1>                restart
              ^
unknown command.
alice14@srx1> restart   ?
No valid completions
alice14@srx1> restart   
```

