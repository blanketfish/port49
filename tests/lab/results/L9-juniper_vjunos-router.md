# L9 — juniper_vjunos-router

- **Date measured:** 2026-09-25
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L12-juniper_vjunos-router.pcap` — 5849 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L12-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Over TACACS+ on `junos-exec`: whether a `deny-commands` regex is matched anywhere in the line, as a prefix, or only as anchored; whether explicit `^` and `$` are taken with the pipe tail `( *\|.*)?`; whether it reads a command in the case typed (`SHOW VERSION`, an argument `FXP0`), the abbreviation typed (`sh ver`) and the pipe typed (`| no-more`), or as the CLI expands it; what a malformed regex does; and whether a value with spaces is taken raw (spec §8, §15 L9). The `JunosFacts` lines below are what internal/projection reads.

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
- a malformed deny `^(show$`: the session opened true (no error); `show version` ran false
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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice01@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice01@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 02:40:48 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:01:05 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:00:11 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:00:02 ago) by breakglass
 2:40AM  up 1 min, 1 users, load averages: 2.07, 0.67, 0.25

alice01@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice01@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice01@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

alice01@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  convert-json-configuration  Convert the given JSON configuration file as per Junos
  debug-info           Collect debug information of the system
  decrypt              Decrypt a $8$ or $9$-encrypted password
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  power-on             Power on the system
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
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
> aaad                 AAAD process - Authentication, authorization and accounting
> aaasd                AAA Service Daemon
> adaptive-services    Adaptive services process
> alarm-management     Alarm management process
> analytics-agent      Analytics agent
> ancpd-service        Access Node Control Protocol Process
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> audit-process        Audit process
> bbe-cpcdd-dbng       Captive-portal-content-delivery process for dBNG
> bbe-mib-daemon       Enhanced Session Management MIB Daemon process
> bbe-stats-daemon     Enhanced Session Management Statistics Daemon process
> captive-portal-content-delivery  Captive-portal-content-delivery process
> charged              Local persistent storage for CDR backup
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> clksyncd-service     Ethernet Clock Synchronization Process
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
> ddos-protection      Distributed Denial of Service Protection
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> diameter-service     Diameter process
> disk-monitoring      Disk monitoring process
> dot1x-protocol       Port based Network Access Control
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fib-streaming        FIB Telemetry Streaming Daemon
> firewall             Firewall process
> fwa-service          Fixed Wireless Access Daemon Process
> general-authentication-service  General authentication process
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group Key Member daemon
> grpc-tunnel          GRPC Tunnel Daemon
> gstatd               geom-device performance monitoring daemon
> gtp-proxy-service    User Plane GTP Protocol Proxy
> health-mon           Health Monitoring and correlation for all platforms
> iccp-service         Inter-Chassis Communication Protocol daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> inline-monitoring    Inline Packet Monitoring Process
> interface-control    Interface control process
> ipsec-key-management  IPSec Key Management daemon
> jflow-service        Jflow process for embedded junos
> jnu-management       Junos node unifier process
> jsd                  JET Services Daemon
> jsqlsync             Juniper SQL Sync Daemon
> kernel-debug-streaming  Junos Kernel Debug streaming Daemon
> kernel-health-monitoring  Junos Kernel Health Monitoring Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> l2tp-universal-edge  Universal edge Layer 2 Tunneling Protocol daemon
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> link-management      Link management process
> mac-validation       MAC SA Validation
> mc-ae-config-check-service  MC-LAG Configuration Consistency Check daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mobiled              Mobility process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> mspd                 Multiservice Daemon
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
> nas                  Non-Access Stratum Server Daemon
> net-monitord         Traffic director service monitor process
> netproxy             netproxy service
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ngap                 AGF Next Generation Application Protocol process
> nginx                Reverse proxy for grpc
> ngx-auth-meta-service  Authentication and metadata service for NGINX
> ngx-client-cache-service  Client cache service for nginx
> ngx-client-monitor-service  Client monitor service for nginx
> ngx-jnx-login-service  JNX Login service for NGINX
> ngx-login-service    Login service for NGINX
> pccd-service         Path Computation Client Daemon
> peer-selection-service  Peer selection service process
> pfcp-proxy-service   User Plane PFCP Protocol Proxy
> pgm                  Pragmatic General Multicast process
> pic-services-logging  PIC services logging process
> pki-service          PKI service daemon
> ppp                  PPP process
> ppp-service          Universal edge PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> redundancy-interface-process  Redundancy interface management process
> remote-device-management  Remote Device Management Daemon
> remote-operations    Remote operations process
> replication-client-service  Replication Client Process
> replication-server-service  Replication Server Process
> resource-management  Resource Management and Packet Steering
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpd-telemetry-daemon  RPD Telemetry Applications
> sae-gateway-user-plane-agent-daemon  SAE gateway user plane agent daemon
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> satellite-control-plane-process  Satellite Control Plane Process
> satellite-discovery-provisioning-process  Satellite Discovery and Provisioning Process
> satellite-platform-management-process  Satellite Platform Management Process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> service-deployment   Service Deployment System (SDX) process
> sflow-service        Flow Sampling (Sflow) Daemon
> slaacd               SLAAC process
> smg-service          Enhanced Session Management process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> srd                  Services Redundancy daemon
> static-subscribers   Static Subscriber Client
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-helper-service  Enhanced BBE helper user plane process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> subscriber-statistics-service  Statistics Services Daemon for dBNG
> sysd                 Telemetry System Daemon
> system-monitor       System monitoring and heuristic process
> tcp-forwarding       TCP Forwarding Daemon
> traffic-dird         Traffic director process
> transport-control    Transport control process
> tunnel-oamd          Tunnel OAM process
> ui-pubd              Mosquitto pub client process
> up-smg-service       Enhanced Session Management user plane process
> upm-service          User Plane Manager for dBNG
> url-filterd          URL Filtering process
> video-monitoring     Video Monitoring Process
> virtual-node-fabric  Virtual Node Fabric Protocol
> virtual-node-provisioning  Virtual Node Provisioning Protocol
> vrrp                 Virtual Router Redundancy Protocol process
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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

[edit]
alice01@srx1# 
```

`run show system uptime`:

```
 
Current time: 2026-09-25 02:40:54 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:01:11 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:00:17 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:00:08 ago) by breakglass
 2:40AM  up 1 min, 1 users, load averages: 1.90, 0.66, 0.25

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice03@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice03@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 02:41:21 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:01:38 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:00:44 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:00:35 ago) by breakglass
 2:41AM  up 2 mins, 1 users, load averages: 1.45, 0.67, 0.27

alice03@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice03@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice03@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice04@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice04@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 02:41:36 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:01:53 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:00:59 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:00:50 ago) by breakglass
 2:41AM  up 2 mins, 1 users, load averages: 1.22, 0.65, 0.27

alice04@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice04@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice04@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice05@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice05@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 02:41:51 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:02:08 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:01:14 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:01:05 ago) by breakglass
 2:41AM  up 2 mins, 1 users, load averages: 1.03, 0.63, 0.27

alice05@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice05@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice05@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice06@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

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
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice06@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice06@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
 
Current time: 2026-09-25 02:42:21 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:02:38 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:01:44 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:01:35 ago) by breakglass
 2:42AM  up 3 mins, 1 users, load averages: 0.70, 0.59, 0.26

alice07@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice07@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

alice07@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  convert-json-configuration  Convert the given JSON configuration file as per Junos
  debug-info           Collect debug information of the system
  decrypt              Decrypt a $8$ or $9$-encrypted password
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  power-on             Power on the system
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
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
> aaad                 AAAD process - Authentication, authorization and accounting
> aaasd                AAA Service Daemon
> adaptive-services    Adaptive services process
> alarm-management     Alarm management process
> analytics-agent      Analytics agent
> ancpd-service        Access Node Control Protocol Process
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> audit-process        Audit process
> bbe-cpcdd-dbng       Captive-portal-content-delivery process for dBNG
> bbe-mib-daemon       Enhanced Session Management MIB Daemon process
> bbe-stats-daemon     Enhanced Session Management Statistics Daemon process
> captive-portal-content-delivery  Captive-portal-content-delivery process
> charged              Local persistent storage for CDR backup
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> clksyncd-service     Ethernet Clock Synchronization Process
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
> ddos-protection      Distributed Denial of Service Protection
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> diameter-service     Diameter process
> disk-monitoring      Disk monitoring process
> dot1x-protocol       Port based Network Access Control
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fib-streaming        FIB Telemetry Streaming Daemon
> firewall             Firewall process
> fwa-service          Fixed Wireless Access Daemon Process
> general-authentication-service  General authentication process
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group Key Member daemon
> grpc-tunnel          GRPC Tunnel Daemon
> gstatd               geom-device performance monitoring daemon
> gtp-proxy-service    User Plane GTP Protocol Proxy
> health-mon           Health Monitoring and correlation for all platforms
> iccp-service         Inter-Chassis Communication Protocol daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> inline-monitoring    Inline Packet Monitoring Process
> interface-control    Interface control process
> ipsec-key-management  IPSec Key Management daemon
> jflow-service        Jflow process for embedded junos
> jnu-management       Junos node unifier process
> jsd                  JET Services Daemon
> jsqlsync             Juniper SQL Sync Daemon
> kernel-debug-streaming  Junos Kernel Debug streaming Daemon
> kernel-health-monitoring  Junos Kernel Health Monitoring Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> l2tp-universal-edge  Universal edge Layer 2 Tunneling Protocol daemon
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> link-management      Link management process
> mac-validation       MAC SA Validation
> mc-ae-config-check-service  MC-LAG Configuration Consistency Check daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mobiled              Mobility process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> mspd                 Multiservice Daemon
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
> nas                  Non-Access Stratum Server Daemon
> net-monitord         Traffic director service monitor process
> netproxy             netproxy service
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ngap                 AGF Next Generation Application Protocol process
> nginx                Reverse proxy for grpc
> ngx-auth-meta-service  Authentication and metadata service for NGINX
> ngx-client-cache-service  Client cache service for nginx
> ngx-client-monitor-service  Client monitor service for nginx
> ngx-jnx-login-service  JNX Login service for NGINX
> ngx-login-service    Login service for NGINX
> pccd-service         Path Computation Client Daemon
> peer-selection-service  Peer selection service process
> pfcp-proxy-service   User Plane PFCP Protocol Proxy
> pgm                  Pragmatic General Multicast process
> pic-services-logging  PIC services logging process
> pki-service          PKI service daemon
> ppp                  PPP process
> ppp-service          Universal edge PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> redundancy-interface-process  Redundancy interface management process
> remote-device-management  Remote Device Management Daemon
> remote-operations    Remote operations process
> replication-client-service  Replication Client Process
> replication-server-service  Replication Server Process
> resource-management  Resource Management and Packet Steering
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpd-telemetry-daemon  RPD Telemetry Applications
> sae-gateway-user-plane-agent-daemon  SAE gateway user plane agent daemon
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> satellite-control-plane-process  Satellite Control Plane Process
> satellite-discovery-provisioning-process  Satellite Discovery and Provisioning Process
> satellite-platform-management-process  Satellite Platform Management Process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> service-deployment   Service Deployment System (SDX) process
> sflow-service        Flow Sampling (Sflow) Daemon
> slaacd               SLAAC process
> smg-service          Enhanced Session Management process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> srd                  Services Redundancy daemon
> static-subscribers   Static Subscriber Client
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-helper-service  Enhanced BBE helper user plane process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> subscriber-statistics-service  Statistics Services Daemon for dBNG
> sysd                 Telemetry System Daemon
> system-monitor       System monitoring and heuristic process
> tcp-forwarding       TCP Forwarding Daemon
> traffic-dird         Traffic director process
> transport-control    Transport control process
> tunnel-oamd          Tunnel OAM process
> ui-pubd              Mosquitto pub client process
> up-smg-service       Enhanced Session Management user plane process
> upm-service          User Plane Manager for dBNG
> url-filterd          URL Filtering process
> video-monitoring     Video Monitoring Process
> virtual-node-fabric  Virtual Node Fabric Protocol
> virtual-node-provisioning  Virtual Node Provisioning Protocol
> vrrp                 Virtual Router Redundancy Protocol process
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
 
Current time: 2026-09-25 02:42:37 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:02:54 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:02:00 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:01:51 ago) by breakglass
 2:42AM  up 3 mins, 1 users, load averages: 0.78, 0.61, 0.28

alice08@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice08@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

alice08@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  convert-json-configuration  Convert the given JSON configuration file as per Junos
  debug-info           Collect debug information of the system
  decrypt              Decrypt a $8$ or $9$-encrypted password
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  power-on             Power on the system
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
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
> aaad                 AAAD process - Authentication, authorization and accounting
> aaasd                AAA Service Daemon
> adaptive-services    Adaptive services process
> alarm-management     Alarm management process
> analytics-agent      Analytics agent
> ancpd-service        Access Node Control Protocol Process
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> audit-process        Audit process
> bbe-cpcdd-dbng       Captive-portal-content-delivery process for dBNG
> bbe-mib-daemon       Enhanced Session Management MIB Daemon process
> bbe-stats-daemon     Enhanced Session Management Statistics Daemon process
> captive-portal-content-delivery  Captive-portal-content-delivery process
> charged              Local persistent storage for CDR backup
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> clksyncd-service     Ethernet Clock Synchronization Process
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
> ddos-protection      Distributed Denial of Service Protection
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> diameter-service     Diameter process
> disk-monitoring      Disk monitoring process
> dot1x-protocol       Port based Network Access Control
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fib-streaming        FIB Telemetry Streaming Daemon
> firewall             Firewall process
> fwa-service          Fixed Wireless Access Daemon Process
> general-authentication-service  General authentication process
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group Key Member daemon
> grpc-tunnel          GRPC Tunnel Daemon
> gstatd               geom-device performance monitoring daemon
> gtp-proxy-service    User Plane GTP Protocol Proxy
> health-mon           Health Monitoring and correlation for all platforms
> iccp-service         Inter-Chassis Communication Protocol daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> inline-monitoring    Inline Packet Monitoring Process
> interface-control    Interface control process
> ipsec-key-management  IPSec Key Management daemon
> jflow-service        Jflow process for embedded junos
> jnu-management       Junos node unifier process
> jsd                  JET Services Daemon
> jsqlsync             Juniper SQL Sync Daemon
> kernel-debug-streaming  Junos Kernel Debug streaming Daemon
> kernel-health-monitoring  Junos Kernel Health Monitoring Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> l2tp-universal-edge  Universal edge Layer 2 Tunneling Protocol daemon
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> link-management      Link management process
> mac-validation       MAC SA Validation
> mc-ae-config-check-service  MC-LAG Configuration Consistency Check daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mobiled              Mobility process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> mspd                 Multiservice Daemon
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
> nas                  Non-Access Stratum Server Daemon
> net-monitord         Traffic director service monitor process
> netproxy             netproxy service
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ngap                 AGF Next Generation Application Protocol process
> nginx                Reverse proxy for grpc
> ngx-auth-meta-service  Authentication and metadata service for NGINX
> ngx-client-cache-service  Client cache service for nginx
> ngx-client-monitor-service  Client monitor service for nginx
> ngx-jnx-login-service  JNX Login service for NGINX
> ngx-login-service    Login service for NGINX
> pccd-service         Path Computation Client Daemon
> peer-selection-service  Peer selection service process
> pfcp-proxy-service   User Plane PFCP Protocol Proxy
> pgm                  Pragmatic General Multicast process
> pic-services-logging  PIC services logging process
> pki-service          PKI service daemon
> ppp                  PPP process
> ppp-service          Universal edge PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> redundancy-interface-process  Redundancy interface management process
> remote-device-management  Remote Device Management Daemon
> remote-operations    Remote operations process
> replication-client-service  Replication Client Process
> replication-server-service  Replication Server Process
> resource-management  Resource Management and Packet Steering
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpd-telemetry-daemon  RPD Telemetry Applications
> sae-gateway-user-plane-agent-daemon  SAE gateway user plane agent daemon
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> satellite-control-plane-process  Satellite Control Plane Process
> satellite-discovery-provisioning-process  Satellite Discovery and Provisioning Process
> satellite-platform-management-process  Satellite Platform Management Process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> service-deployment   Service Deployment System (SDX) process
> sflow-service        Flow Sampling (Sflow) Daemon
> slaacd               SLAAC process
> smg-service          Enhanced Session Management process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> srd                  Services Redundancy daemon
> static-subscribers   Static Subscriber Client
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-helper-service  Enhanced BBE helper user plane process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> subscriber-statistics-service  Statistics Services Daemon for dBNG
> sysd                 Telemetry System Daemon
> system-monitor       System monitoring and heuristic process
> tcp-forwarding       TCP Forwarding Daemon
> traffic-dird         Traffic director process
> transport-control    Transport control process
> tunnel-oamd          Tunnel OAM process
> ui-pubd              Mosquitto pub client process
> up-smg-service       Enhanced Session Management user plane process
> upm-service          User Plane Manager for dBNG
> url-filterd          URL Filtering process
> video-monitoring     Video Monitoring Process
> virtual-node-fabric  Virtual Node Fabric Protocol
> virtual-node-provisioning  Virtual Node Provisioning Protocol
> vrrp                 Virtual Router Redundancy Protocol process
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
 
Current time: 2026-09-25 02:42:53 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:03:10 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:02:16 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:02:07 ago) by breakglass
 2:42AM  up 3 mins, 1 users, load averages: 0.89, 0.65, 0.29

alice09@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice09@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

alice09@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  convert-json-configuration  Convert the given JSON configuration file as per Junos
  debug-info           Collect debug information of the system
  decrypt              Decrypt a $8$ or $9$-encrypted password
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  power-on             Power on the system
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
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
> aaad                 AAAD process - Authentication, authorization and accounting
> aaasd                AAA Service Daemon
> adaptive-services    Adaptive services process
> alarm-management     Alarm management process
> analytics-agent      Analytics agent
> ancpd-service        Access Node Control Protocol Process
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> audit-process        Audit process
> bbe-cpcdd-dbng       Captive-portal-content-delivery process for dBNG
> bbe-mib-daemon       Enhanced Session Management MIB Daemon process
> bbe-stats-daemon     Enhanced Session Management Statistics Daemon process
> captive-portal-content-delivery  Captive-portal-content-delivery process
> charged              Local persistent storage for CDR backup
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> clksyncd-service     Ethernet Clock Synchronization Process
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
> ddos-protection      Distributed Denial of Service Protection
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> diameter-service     Diameter process
> disk-monitoring      Disk monitoring process
> dot1x-protocol       Port based Network Access Control
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fib-streaming        FIB Telemetry Streaming Daemon
> firewall             Firewall process
> fwa-service          Fixed Wireless Access Daemon Process
> general-authentication-service  General authentication process
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group Key Member daemon
> grpc-tunnel          GRPC Tunnel Daemon
> gstatd               geom-device performance monitoring daemon
> gtp-proxy-service    User Plane GTP Protocol Proxy
> health-mon           Health Monitoring and correlation for all platforms
> iccp-service         Inter-Chassis Communication Protocol daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> inline-monitoring    Inline Packet Monitoring Process
> interface-control    Interface control process
> ipsec-key-management  IPSec Key Management daemon
> jflow-service        Jflow process for embedded junos
> jnu-management       Junos node unifier process
> jsd                  JET Services Daemon
> jsqlsync             Juniper SQL Sync Daemon
> kernel-debug-streaming  Junos Kernel Debug streaming Daemon
> kernel-health-monitoring  Junos Kernel Health Monitoring Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> l2tp-universal-edge  Universal edge Layer 2 Tunneling Protocol daemon
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> link-management      Link management process
> mac-validation       MAC SA Validation
> mc-ae-config-check-service  MC-LAG Configuration Consistency Check daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mobiled              Mobility process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> mspd                 Multiservice Daemon
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
> nas                  Non-Access Stratum Server Daemon
> net-monitord         Traffic director service monitor process
> netproxy             netproxy service
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ngap                 AGF Next Generation Application Protocol process
> nginx                Reverse proxy for grpc
> ngx-auth-meta-service  Authentication and metadata service for NGINX
> ngx-client-cache-service  Client cache service for nginx
> ngx-client-monitor-service  Client monitor service for nginx
> ngx-jnx-login-service  JNX Login service for NGINX
> ngx-login-service    Login service for NGINX
> pccd-service         Path Computation Client Daemon
> peer-selection-service  Peer selection service process
> pfcp-proxy-service   User Plane PFCP Protocol Proxy
> pgm                  Pragmatic General Multicast process
> pic-services-logging  PIC services logging process
> pki-service          PKI service daemon
> ppp                  PPP process
> ppp-service          Universal edge PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> redundancy-interface-process  Redundancy interface management process
> remote-device-management  Remote Device Management Daemon
> remote-operations    Remote operations process
> replication-client-service  Replication Client Process
> replication-server-service  Replication Server Process
> resource-management  Resource Management and Packet Steering
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpd-telemetry-daemon  RPD Telemetry Applications
> sae-gateway-user-plane-agent-daemon  SAE gateway user plane agent daemon
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> satellite-control-plane-process  Satellite Control Plane Process
> satellite-discovery-provisioning-process  Satellite Discovery and Provisioning Process
> satellite-platform-management-process  Satellite Platform Management Process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> service-deployment   Service Deployment System (SDX) process
> sflow-service        Flow Sampling (Sflow) Daemon
> slaacd               SLAAC process
> smg-service          Enhanced Session Management process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> srd                  Services Redundancy daemon
> static-subscribers   Static Subscriber Client
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-helper-service  Enhanced BBE helper user plane process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> subscriber-statistics-service  Statistics Services Daemon for dBNG
> sysd                 Telemetry System Daemon
> system-monitor       System monitoring and heuristic process
> tcp-forwarding       TCP Forwarding Daemon
> traffic-dird         Traffic director process
> transport-control    Transport control process
> tunnel-oamd          Tunnel OAM process
> ui-pubd              Mosquitto pub client process
> up-smg-service       Enhanced Session Management user plane process
> upm-service          User Plane Manager for dBNG
> url-filterd          URL Filtering process
> video-monitoring     Video Monitoring Process
> virtual-node-fabric  Virtual Node Fabric Protocol
> virtual-node-provisioning  Virtual Node Provisioning Protocol
> vrrp                 Virtual Router Redundancy Protocol process
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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice10@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice10@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 02:43:08 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:03:25 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:02:31 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:02:22 ago) by breakglass
 2:43AM  up 3 mins, 1 users, load averages: 0.77, 0.63, 0.29

alice10@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice10@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice10@srx1> 
```

`sh int fxp0 terse`:

```
show interfaces fxp0 terse 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

alice10@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  convert-json-configuration  Convert the given JSON configuration file as per Junos
  debug-info           Collect debug information of the system
  decrypt              Decrypt a $8$ or $9$-encrypted password
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  power-on             Power on the system
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
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
> aaad                 AAAD process - Authentication, authorization and accounting
> aaasd                AAA Service Daemon
> adaptive-services    Adaptive services process
> alarm-management     Alarm management process
> analytics-agent      Analytics agent
> ancpd-service        Access Node Control Protocol Process
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> audit-process        Audit process
> bbe-cpcdd-dbng       Captive-portal-content-delivery process for dBNG
> bbe-mib-daemon       Enhanced Session Management MIB Daemon process
> bbe-stats-daemon     Enhanced Session Management Statistics Daemon process
> captive-portal-content-delivery  Captive-portal-content-delivery process
> charged              Local persistent storage for CDR backup
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> clksyncd-service     Ethernet Clock Synchronization Process
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
> ddos-protection      Distributed Denial of Service Protection
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> diameter-service     Diameter process
> disk-monitoring      Disk monitoring process
> dot1x-protocol       Port based Network Access Control
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fib-streaming        FIB Telemetry Streaming Daemon
> firewall             Firewall process
> fwa-service          Fixed Wireless Access Daemon Process
> general-authentication-service  General authentication process
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group Key Member daemon
> grpc-tunnel          GRPC Tunnel Daemon
> gstatd               geom-device performance monitoring daemon
> gtp-proxy-service    User Plane GTP Protocol Proxy
> health-mon           Health Monitoring and correlation for all platforms
> iccp-service         Inter-Chassis Communication Protocol daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> inline-monitoring    Inline Packet Monitoring Process
> interface-control    Interface control process
> ipsec-key-management  IPSec Key Management daemon
> jflow-service        Jflow process for embedded junos
> jnu-management       Junos node unifier process
> jsd                  JET Services Daemon
> jsqlsync             Juniper SQL Sync Daemon
> kernel-debug-streaming  Junos Kernel Debug streaming Daemon
> kernel-health-monitoring  Junos Kernel Health Monitoring Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> l2tp-universal-edge  Universal edge Layer 2 Tunneling Protocol daemon
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> link-management      Link management process
> mac-validation       MAC SA Validation
> mc-ae-config-check-service  MC-LAG Configuration Consistency Check daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mobiled              Mobility process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> mspd                 Multiservice Daemon
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
> nas                  Non-Access Stratum Server Daemon
> net-monitord         Traffic director service monitor process
> netproxy             netproxy service
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ngap                 AGF Next Generation Application Protocol process
> nginx                Reverse proxy for grpc
> ngx-auth-meta-service  Authentication and metadata service for NGINX
> ngx-client-cache-service  Client cache service for nginx
> ngx-client-monitor-service  Client monitor service for nginx
> ngx-jnx-login-service  JNX Login service for NGINX
> ngx-login-service    Login service for NGINX
> pccd-service         Path Computation Client Daemon
> peer-selection-service  Peer selection service process
> pfcp-proxy-service   User Plane PFCP Protocol Proxy
> pgm                  Pragmatic General Multicast process
> pic-services-logging  PIC services logging process
> pki-service          PKI service daemon
> ppp                  PPP process
> ppp-service          Universal edge PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> redundancy-interface-process  Redundancy interface management process
> remote-device-management  Remote Device Management Daemon
> remote-operations    Remote operations process
> replication-client-service  Replication Client Process
> replication-server-service  Replication Server Process
> resource-management  Resource Management and Packet Steering
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpd-telemetry-daemon  RPD Telemetry Applications
> sae-gateway-user-plane-agent-daemon  SAE gateway user plane agent daemon
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> satellite-control-plane-process  Satellite Control Plane Process
> satellite-discovery-provisioning-process  Satellite Discovery and Provisioning Process
> satellite-platform-management-process  Satellite Platform Management Process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> service-deployment   Service Deployment System (SDX) process
> sflow-service        Flow Sampling (Sflow) Daemon
> slaacd               SLAAC process
> smg-service          Enhanced Session Management process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> srd                  Services Redundancy daemon
> static-subscribers   Static Subscriber Client
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-helper-service  Enhanced BBE helper user plane process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> subscriber-statistics-service  Statistics Services Daemon for dBNG
> sysd                 Telemetry System Daemon
> system-monitor       System monitoring and heuristic process
> tcp-forwarding       TCP Forwarding Daemon
> traffic-dird         Traffic director process
> transport-control    Transport control process
> tunnel-oamd          Tunnel OAM process
> ui-pubd              Mosquitto pub client process
> up-smg-service       Enhanced Session Management user plane process
> upm-service          User Plane Manager for dBNG
> url-filterd          URL Filtering process
> video-monitoring     Video Monitoring Process
> virtual-node-fabric  Virtual Node Fabric Protocol
> virtual-node-provisioning  Virtual Node Provisioning Protocol
> vrrp                 Virtual Router Redundancy Protocol process
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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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
 
Current time: 2026-09-25 02:43:39 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:03:56 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:03:02 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:02:53 ago) by breakglass
 2:43AM  up 4 mins, 1 users, load averages: 0.46, 0.57, 0.28

alice12@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice12@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

alice12@srx1> 
```

`request system reboot`:

```
request system ?
Possible completions:
  malware-scan         Scan for malware
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
 
Current time: 2026-09-25 02:43:43 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:04:00 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:03:06 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:02:57 ago) by breakglass
 2:43AM  up 4 mins, 1 users, load averages: 0.43, 0.56, 0.28

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
 
Current time: 2026-09-25 02:43:55 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:04:12 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:03:18 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:03:09 ago) by breakglass
 2:43AM  up 4 mins, 1 users, load averages: 0.33, 0.53, 0.27

alice13@srx1> 
```

`show interfaces terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
cbp0                    up    up
demux0                  up    up
dsc                     up    up
em1                     up    up
em1.0                   up    up   inet     10.0.0.4/8      
                                            128.0.0.1/2     
                                            128.0.0.4/2     
                                   inet6    fe80::5254:ff:fe12:bdfe/64
                                            fec0::a:0:0:4/64
                                   tnp      0x4             
esi                     up    up
fti0                    up    up
fti1                    up    up
fti2                    up    up
fti3                    up    up
fti4                    up    up
fti5                    up    up
fti6                    up    up
fti7                    up    up
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64
gre                     up    up
ipip                    up    up
irb                     up    up
jsrv                    up    up
jsrv.1                  up    up   inet     128.0.0.127/2   
lo0                     up    up
lo0.16384               up    up   inet     127.0.0.1           --> 0/0
lo0.16385               up    up   inet    
lsi                     up    up
mif                     up    up
mtun                    up    up
pimd                    up    up
pime                    up    up
pip0                    up    up
pp0                     up    up
rbeb                    up    up
tap                     up    up
vtep                    up    up

alice13@srx1> 
```

`show interfaces fxp0 terse`:

```
 
Interface               Admin Link Proto    Local                 Remote
fxp0                    up    up
fxp0.0                  up    up   inet     10.0.0.15/24    
                                   inet6    2001:db8::2/64  
                                            fe80::e00:75ff:fe2a:da00/64

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
                                            fe80::e00:75ff:fe2a:da00/64

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

alice13@srx1> 
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice13@srx1> request system   ?
No valid completions
alice13@srx1> request system   
```

`restart routing`:

```
alice13@srx1>                 restart
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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice14@srx1> 
```

`show version | no-more`:

```
 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice14@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 02:44:10 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 02:39:43 UTC (00:04:27 ago)
Protocols started: 2026-09-25 02:40:37 UTC (00:03:33 ago)
Last configured: 2026-09-25 02:40:46 UTC (00:03:24 ago) by breakglass
 2:44AM  up 4 mins, 1 users, load averages: 0.64, 0.59, 0.30

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
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]
JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]
JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS libs compat32 [20240604.39c9257_builder_stable_12_234]
JUNOS OS 32-bit compatibility [20240604.39c9257_builder_stable_12_234]
JUNOS libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS Packet Forwarding Engine Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS sflow mx [20240821.090638_builder_junos_234_r2_s2]
JUNOS py extensions [20240821.090638_builder_junos_234_r2_s2]
JUNOS py base [20240821.090638_builder_junos_234_r2_s2]
JUNOS OS vmguest [20240604.39c9257_builder_stable_12_234]
JUNOS OS package [20240704.061808_builder_main]
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

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

