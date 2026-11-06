# L9-abbreviations — juniper_vjunos-router

- **Date measured:** 2026-11-05
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L9-abbreviations-juniper_vjunos-router.pcap` — 1038 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L9-abbreviations-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL9JunosAbbreviations$`

## Claim

Whether a keyword deny-commands refuses its command however the keywords are abbreviated, at several lengths and depths, piped, and ambiguous at one level: JunosFacts.DenyMatchesExpanded for keywords (spec §15 L9; decision 27).

## Observation

The class was committed: commit complete.

```
set system login class p49-l9-all permissions all
set system login user p49-l9-all class p49-l9-all
```

The deny: `deny-commands=^( *show +version *(\\\|.*)?\| *show +interfaces +terse *(\\\|.*)?\| *show +system +uptime *(\\\|.*)?\| *show +route +summary *(\\\|.*)?\| *show +chassis +hardware *(\\\|.*)?)$`.

A probe ran only where its output holds the denied command's own output (for `| count`, the lines the control's own run of the command held, more than one); `refused` is the CLI's refusal; `not run` is a device error, so the command did not execute, and the deny did not refuse it either; anything else is not observed and fails the test. A `not run` cell marked not isolated as an abbreviation still counts toward the fact (the lead's ruling of 2026-09-25): the denied command did not execute; leaving them out would not change the verdict, since a `not run` cell never makes it false.

| probe | control | under the deny | expanded, control / deny |
|---|---|---|---|
| "show version" | ran | refused | `Hostname: srx1` / `^` |
| "show version \| no-more" | ran | refused | `Hostname: srx1` / `show version \|` |
| "sh ver" | ran | refused | `show version` / `show version` |
| "sho vers" | ran | refused | `show version` / `show version` |
| "show versi" | ran | refused | `on` / `on` |
| "sh ver \| no-more" | ran | refused | `show version \| no-more` / `show version \|` |
| "show interfaces terse" | ran | refused | `Interface               Admin Link Proto    Local                 Remote` / `^` |
| "sh int ter" | ran | not run; not isolated as an abbreviation of `show interfaces terse`: it expanded otherwise under the deny | `show interfaces terse` / `show interfaces ter` |
| "sh interfaces te" | ran | not run; not isolated as an abbreviation of `show interfaces terse`: it expanded otherwise under the deny | `show interfaces terse` / `show interfaces te` |
| "show int terse" | ran | refused | `show interfaces terse` / `show interfaces terse` |
| "sh int ter \| count" | ran | not run; not isolated as an abbreviation of `show interfaces terse`: it expanded otherwise under the deny | `show interfaces terse \| count` / `show interfaces ter \| count` |
| "show system uptime" | ran | refused | `Current time: 2026-11-05 21:41:55 UTC` / `^` |
| "sh sys upt" | ran | refused | `show system uptime` / `show system uptime` |
| "sh system up" | ran | refused | `show system uptime` / `show system uptime` |
| "show sy uptime" | ran | refused | `show system uptime` / `show system uptime` |
| "show route summary" | ran | refused | `Highwater Mark (All time / Time averaged watermark)` / `^` |
| "sh rou sum" | ran | not counted: control not run — ambiguous on vSRX (completes to `rout`) (here: refused) | `show route summary` / `show route summary` |
| "sh route sum" | ran | refused | `show route summary` / `show route summary` |
| "sh route summ" | ran | refused | `show route summary` / `show route summary` |
| "show chassis hardware" | ran | refused | `Hardware inventory:` / `^` |
| "sh chas hard" | ran | refused | `show chassis hardware` / `show chassis hardware` |
| "sh chassis hardw" | ran | refused | `show chassis hardware` / `show chassis hardware` |
| "sh i terse" | ambiguous | not isolated (ambiguous) | `show i` / `show i` |
| "ſhow version" | refused | not isolated (refused) | `how` / `how` |
| "   show version" | ran | refused | `show version` / `show version` |
| "show version   " | ran | refused | `show version` / `show version` |
| "   sh int ter   " | ran | not run; not isolated as an abbreviation of `show interfaces terse`: it expanded otherwise under the deny | `show interfaces terse` / `show interfaces ter` |

### Read off the table

- the rendered deny shape (` *... *(\|.*)?`) enforced: true: every full form, plain and piped, refused under it and run by the control
- JunosFacts.DenyMatchesExpanded (keywords) = true: true only where the shape is enforced, no probe ran under the deny (each refused or not run) and the control ran every unambiguous one; set 1.1.0 takes true only where both images say true
- A keyword the deny hides from completion changes how an abbreviation resolves: under the deny an abbreviation of it may resolve as an argument instead (a probe marked "expanded otherwise").
- `ſhow version` shows that the CLI refuses a non-ASCII keystroke (it rings the bell, drops `ſ` and reads `how`), not whether `ſ` case-folds to `s` in a deny: the control refuses it too, so its deny cell isolates nothing.

### control

Reply `["local-user-name=p49-l9-all"]`. `show cli authorization`:

```
 
Current user: 'p49-l9-all' login: 'alice01' class 'p49-l9-all'
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

`sho vers`:

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

`show versi`:

```
on 
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

`sh ver | no-more`:

```
show version | no-more 
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
                                            fe80::e00:7eff:feaa:8700/64
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

`sh int ter`:

```
show interfaces terse 
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
                                            fe80::e00:7eff:feaa:8700/64
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

`sh interfaces te`:

```
show interfaces terse 
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
                                            fe80::e00:7eff:feaa:8700/64
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

`show int terse`:

```
show interfaces terse 
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
                                            fe80::e00:7eff:feaa:8700/64
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

`sh int ter | count`:

```
show interfaces terse | count 
Count: 42 lines

alice01@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 21:41:55 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 21:40:30 UTC (00:01:25 ago)
Protocols started: 2026-11-05 21:41:28 UTC (00:00:27 ago)
Last configured: 2026-11-05 21:41:39 UTC (00:00:16 ago) by breakglass
 9:41PM  up 1 min, 1 users, load averages: 1.94, 0.79, 0.31

alice01@srx1> 
```

`sh sys upt`:

```
show system uptime 
Current time: 2026-11-05 21:41:56 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 21:40:30 UTC (00:01:26 ago)
Protocols started: 2026-11-05 21:41:28 UTC (00:00:28 ago)
Last configured: 2026-11-05 21:41:39 UTC (00:00:17 ago) by breakglass
 9:41PM  up 1 min, 1 users, load averages: 1.94, 0.79, 0.31

alice01@srx1> 
```

`sh system up`:

```
show system uptime 
Current time: 2026-11-05 21:41:57 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 21:40:30 UTC (00:01:27 ago)
Protocols started: 2026-11-05 21:41:28 UTC (00:00:29 ago)
Last configured: 2026-11-05 21:41:39 UTC (00:00:18 ago) by breakglass
 9:41PM  up 1 min, 1 users, load averages: 1.94, 0.79, 0.31

alice01@srx1> 
```

`show sy uptime`:

```
show system uptime 
Current time: 2026-11-05 21:41:58 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 21:40:30 UTC (00:01:28 ago)
Protocols started: 2026-11-05 21:41:28 UTC (00:00:30 ago)
Last configured: 2026-11-05 21:41:39 UTC (00:00:19 ago) by breakglass
 9:41PM  up 1 min, 1 users, load averages: 1.78, 0.78, 0.31

alice01@srx1> 
```

`show route summary`:

```
 

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 16 at 2026-11-05 21:41:30 / 0
    RIB routes                   : 17 at 2026-11-05 21:41:30 / 0
    FIB routes                   : 2 at 2026-11-05 21:41:30 / 0
    VRF type routing instances   : 0 at 2026-11-05 21:41:28

mgmt_junos.inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      1 routes,      1 active
              Static:      1 routes,      1 active

mgmt_junos.inet6.0: 4 destinations, 4 routes (4 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      2 routes,      2 active
              Static:      1 routes,      1 active

alice01@srx1> 
```

`sh rou sum`:

```
show route summary 

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 16 at 2026-11-05 21:41:30 / 0
    RIB routes                   : 17 at 2026-11-05 21:41:30 / 0
    FIB routes                   : 2 at 2026-11-05 21:41:30 / 0
    VRF type routing instances   : 0 at 2026-11-05 21:41:28

mgmt_junos.inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      1 routes,      1 active
              Static:      1 routes,      1 active

mgmt_junos.inet6.0: 4 destinations, 4 routes (4 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      2 routes,      2 active
              Static:      1 routes,      1 active

alice01@srx1> 
```

`sh route sum`:

```
show route summary 

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 16 at 2026-11-05 21:41:30 / 0
    RIB routes                   : 17 at 2026-11-05 21:41:30 / 0
    FIB routes                   : 2 at 2026-11-05 21:41:30 / 0
    VRF type routing instances   : 0 at 2026-11-05 21:41:28

mgmt_junos.inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      1 routes,      1 active
              Static:      1 routes,      1 active

mgmt_junos.inet6.0: 4 destinations, 4 routes (4 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      2 routes,      2 active
              Static:      1 routes,      1 active

alice01@srx1> 
```

`sh route summ`:

```
show route summary 

Highwater Mark (All time / Time averaged watermark)
    RIB unique destination routes: 16 at 2026-11-05 21:41:30 / 0
    RIB routes                   : 17 at 2026-11-05 21:41:30 / 0
    FIB routes                   : 2 at 2026-11-05 21:41:30 / 0
    VRF type routing instances   : 0 at 2026-11-05 21:41:28

mgmt_junos.inet.0: 3 destinations, 3 routes (3 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      1 routes,      1 active
              Static:      1 routes,      1 active

mgmt_junos.inet6.0: 4 destinations, 4 routes (4 active, 0 holddown, 0 hidden)
              Direct:      1 routes,      1 active
               Local:      2 routes,      2 active
              Static:      1 routes,      1 active

alice01@srx1> 
```

`show chassis hardware`:

```
 
Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                VM6AECF8076B      VMX
Midplane        
Routing Engine 0                                         RE-VMX
CB 0                                                     VMX SCB
FPC 0                     BUILTIN      BUILTIN           Virtual FPC
  CPU           

alice01@srx1> 
```

`sh chas hard`:

```
show chassis hardware 
Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                VM6AECF8076B      VMX
Midplane        
Routing Engine 0                                         RE-VMX
CB 0                                                     VMX SCB
FPC 0                     BUILTIN      BUILTIN           Virtual FPC
  CPU           

alice01@srx1> 
```

`sh chassis hardw`:

```
show chassis hardware 
Hardware inventory:
Item             Version  Part number  Serial number     Description
Chassis                                VM6AECF8076B      VMX
Midplane        
Routing Engine 0                                         RE-VMX
CB 0                                                     VMX SCB
FPC 0                     BUILTIN      BUILTIN           Virtual FPC
  CPU           

alice01@srx1> 
```

`sh i terse`:

```
show i
                    ^
'i' is ambiguous.
Possible completions:
  iccp                 Show Inter Chassis Control Protocol information
  igmp                 Show Internet Group Management Protocol information
  igp-compute          Show IGP SPF compute operations
  ike                  Show Internet Key Exchange information
  ilmi                 Show interim local management interface information
  ingress-replication  Show Ingress-Replication tunnel information
  interfaces           Show interface information
  ipsec                Show IP Security information
  ipv6                 Show IP version 6 information
  isis                 Show Intermediate System-to-Intermediate System information
alice01@srx1> show i   terse
                   ^
syntax error, expecting <command>.

alice01@srx1> 
```

`ſhow version`:

```
how
              ^
unknown command.
alice01@srx1> how   version
              ^
unknown command.

alice01@srx1> 
```

`   show version`:

```
show version 
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

`show version   `:

```
show version 
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

`   sh int ter   `:

```
show interfaces terse 
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
                                            fe80::e00:7eff:feaa:8700/64
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

### deny

Reply `["local-user-name=p49-l9-all", "deny-commands=^( *show +version *(\\|.*)?| *show +interfaces +terse *(\\|.*)?| *show +system +uptime *(\\|.*)?| *show +route +summary *(\\|.*)?| *show +chassis +hardware *(\\|.*)?)$"]`. `show cli authorization`:

```
 
Current user: 'p49-l9-all' login: 'alice02' class 'p49-l9-all'
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
    Deny regular expression: (^( *show +version *(\|.*)?| *show +interfaces +terse *(\|.*)?| *show +system +uptime *(\|.*)?| *show +route +summary *(\|.*)?| *show +chassis +hardware *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice02@srx1> 
```

`show version`:

```
 
                           ^
missing argument.

alice02@srx1> 
```

`show version | no-more`:

```
show version |
                           ^
syntax error, expecting <command>.
alice02@srx1> show version |   no-more
                           ^
syntax error, expecting <command>.

alice02@srx1> 
```

`sh ver`:

```
show version 
                           ^
missing argument.

alice02@srx1> 
```

`sho vers`:

```
show version 
                           ^
missing argument.

alice02@srx1> 
```

`show versi`:

```
on 
                           ^
missing argument.

alice02@srx1> 
```

`sh ver | no-more`:

```
show version |
                           ^
syntax error, expecting <command>.
alice02@srx1> show version |   no-more
                           ^
syntax error, expecting <command>.

alice02@srx1> 
```

`show interfaces terse`:

```
 
                                    ^
permission denied.

alice02@srx1> 
```

`sh int ter`:

```
show interfaces ter 
error: device ter not found

alice02@srx1> 
```

`sh interfaces te`:

```
show interfaces te 
error: device te not found

alice02@srx1> 
```

`show int terse`:

```
show interfaces terse 
                                    ^
permission denied.

alice02@srx1> 
```

`sh int ter | count`:

```
show interfaces ter | count 
Count: 1 lines

alice02@srx1> 
```

`show system uptime`:

```
 
                                 ^
missing argument.

alice02@srx1> 
```

`sh sys upt`:

```
show system uptime 
                                 ^
missing argument.

alice02@srx1> 
```

`sh system up`:

```
show system uptime 
                                 ^
missing argument.

alice02@srx1> 
```

`show sy uptime`:

```
show system uptime 
                                 ^
missing argument.

alice02@srx1> 
```

`show route summary`:

```
 
                                 ^
missing argument.

alice02@srx1> 
```

`sh rou sum`:

```
show route summary 
                                 ^
missing argument.

alice02@srx1> 
```

`sh route sum`:

```
show route summary 
                                 ^
missing argument.

alice02@srx1> 
```

`sh route summ`:

```
show route summary 
                                 ^
missing argument.

alice02@srx1> 
```

`show chassis hardware`:

```
 
                                    ^
missing argument.

alice02@srx1> 
```

`sh chas hard`:

```
show chassis hardware 
                                    ^
missing argument.

alice02@srx1> 
```

`sh chassis hardw`:

```
show chassis hardware 
                                    ^
missing argument.

alice02@srx1> 
```

`sh i terse`:

```
show i
                    ^
'i' is ambiguous.
Possible completions:
  iccp                 Show Inter Chassis Control Protocol information
  igmp                 Show Internet Group Management Protocol information
  igp-compute          Show IGP SPF compute operations
  ike                  Show Internet Key Exchange information
  ilmi                 Show interim local management interface information
  ingress-replication  Show Ingress-Replication tunnel information
  interfaces           Show interface information
  ipsec                Show IP Security information
  ipv6                 Show IP version 6 information
  isis                 Show Intermediate System-to-Intermediate System information
alice02@srx1> show i   terse
                   ^
syntax error, expecting <command>.

alice02@srx1> 
```

`ſhow version`:

```
how
              ^
unknown command.
alice02@srx1> how   version
              ^
unknown command.

alice02@srx1> 
```

`   show version`:

```
show version 
                           ^
missing argument.

alice02@srx1> 
```

`show version   `:

```
show version 
                           ^
missing argument.

alice02@srx1> 
```

`   sh int ter   `:

```
show interfaces ter 
error: device ter not found

alice02@srx1> 
```

