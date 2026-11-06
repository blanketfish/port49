# L26b — juniper_vjunos-router

- **Date measured:** 2026-11-05
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L26b-juniper_vjunos-router.pcap` — 2664 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L26b-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL26bJunosKeywordDeny$`

## Claim

Junos keywords proven by deny-commands enforcement against a paired control: L26's unproven words after `show`, `exit`, `save` and `set cli`, and every `show configuration` hierarchy (spec §15 L26; decision 27).

## Observation

The class was committed: commit complete.

```
set system login class p49-l26b-all permissions all
set system login user p49-l26b-all class p49-l26b-all
```

A word is **proven** a keyword where the control (the class, no deny) ran the command with positive evidence and no refusal in its window (a `Count: N lines` line from `| count`; `Screen length set to 0`; for `exit`, the SSH session ending; never a match in the command's own echo), and the deny session refused it with the CLI's refusal, its caret under the word; **absent** only where the image does not offer the word and the control's CLI answered `unknown command`, typed in full as a hidden command would be (a deny naming it is vacuous there, and it is never an allow); anything else is **unproven**, and fails closed. Unproven is a result, not a test failure: the test fails on a harness failure and on a regression of the words the first run proved.

### Completion listings (break-glass)

| path | placeholder offered | words offered | words |
|---|---|---|---|
| `` | false | 22 | `clear`, `configure`, `file`, `help`, `load`, `monitor`, `mtrace`, `op`, `ping`, `probe`, `quit`, `request`, `restart`, `save`, `scp`, `set`, `show`, `ssh`, `start`, `telnet`, `test`, `traceroute` |
| `set` | false | 2 | `cli`, `date` |
| `show` | false | 129 | `access-cac`, `access-security`, `accounting`, `agent`, `amt`, `ancp`, `aps`, `arp`, `as-path`, `authentication-whitelist`, `auto-bandwidth`, `auto-configuration`, `backup-selection`, `bfd`, `bgp`, `bier`, `bridge`, `captive-portal`, `chassis`, `class-of-service`, `cli`, `configuration`, `congestion-protection`, `connections`, `database-replication`, `ddos-protection`, `dhcp`, `dhcp-security`, `dhcpv6`, `diameter`, `dot1x`, `dual-phase-bootup-status`, `dynamic-profile`, `dynamic-tunnels`, `ephemeral-configuration`, `esis`, `event-options`, `evpn`, `express-segments`, `extensible-subscriber-services`, `extension-provider`, `extension-service`, `fib-streaming`, `firewall`, `flexible-tunnels`, `flight-recorder`, `forwarding-options`, `helper`, `hfrr`, `host`, `iccp`, `igmp`, `igp-compute`, `ike`, `ilmi`, `ingress-replication`, `interfaces`, `ipsec`, `ipv6`, `isis`, `jdaf`, `l2-learning`, `l2circuit`, `l2cpd`, `l2pt`, `l2vpn`, `lacp`, `layer2-control`, `ldp`, `link-management`, `lldp`, `log`, `loop-detect`, `mac-rewrite`, `mac-vrf`, `mld`, `mpls`, `msdp`, `multi-chassis`, `multicast`, `mvpn`, `mvrp`, `network-access`, `network-agent`, `nonstop-routing`, `ntp`, `oam`, `ospf`, `ospf3`, `path-computation-client`, `performance-monitoring`, `pfe`, `pim`, `poe`, `policer`, `policy`, `ppp`, `pppoe`, `programmable-rpd`, `protection-group`, `remote-device-management`, `rip`, `ripng`, `route`, `rsvp`, `sap`, `security`, `services`, `sflow`, `shmlog`, `snmp`, `spanning-tree`, `spring-traffic-engineering`, `srv6`, `ssl-certificates`, `static-subscribers`, `subscribers`, `system`, `task`, `tcp-forwarding`, `ted`, `unified-edge`, `user-plane`, `v4ov6-tunnels`, `validation`, `version`, `virtual-chassis`, `vpls`, `vrrp` |
| `show configuration` | false | 32 | `access`, `access-profile`, `accounting-options`, `applications`, `apply-groups`, `bridge-domains`, `chassis`, `class-of-service`, `diameter`, `dynamic-profiles`, `event-options`, `firewall`, `forwarding-options`, `groups`, `interfaces`, `jsrc`, `jsrc-partition`, `logical-systems`, `multi-chassis`, `multicast-snooping-options`, `poe`, `policy-options`, `protocols`, `routing-instances`, `routing-options`, `security`, `services`, `snmp`, `switch-options`, `system`, `unified-edge`, `virtual-chassis` |

### Verdicts

| path | word | command | control | deny | verdict | deny session |
|---|---|---|---|---|---|---|
| `show` | `cli` | `show cli \| count` | ran | refused | **proven** | deny show words |
| `show` | `host` | `show host localhost \| count` | ran | refused | **proven** | deny show words |
| `show` | `ingress-replication` | `show ingress-replication mvpn \| count` | ran | refused | **proven** | deny show words |
| `show` | `policy` | `show policy \| count` | ran | refused | **proven** | deny show words |
| `show` | `task` | `show task memory \| count` | ran | refused | **proven** | deny show words |
| `set` | `cli` | `set cli screen-length 0` | ran | refused | **proven** | deny root and set words |
| `` | `save` | `save dhcp-security-snoop /var/tmp/p49-l26b.snoop \| count` | ran | refused | **proven** | deny root and set words |
| `show configuration` | `access` | `show configuration access \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `access-profile` | `show configuration access-profile \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `accounting-options` | `show configuration accounting-options \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `applications` | `show configuration applications \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `apply-groups` | `show configuration apply-groups \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `bridge-domains` | `show configuration bridge-domains \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `chassis` | `show configuration chassis \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `class-of-service` | `show configuration class-of-service \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `diameter` | `show configuration diameter \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `dynamic-profiles` | `show configuration dynamic-profiles \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `event-options` | `show configuration event-options \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `firewall` | `show configuration firewall \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `forwarding-options` | `show configuration forwarding-options \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `groups` | `show configuration groups \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `interfaces` | `show configuration interfaces \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `jsrc` | `show configuration jsrc \| count` | ran | ran | **unproven** | deny hierarchies 1 |
| `show configuration` | `jsrc-partition` | `show configuration jsrc-partition \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `logical-systems` | `show configuration logical-systems \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `multi-chassis` | `show configuration multi-chassis \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `multicast-snooping-options` | `show configuration multicast-snooping-options \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `poe` | `show configuration poe \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `policy-options` | `show configuration policy-options \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `protocols` | `show configuration protocols \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `routing-instances` | `show configuration routing-instances \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `routing-options` | `show configuration routing-options \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `schedulers` | `show configuration schedulers \| count` | refused | refused | **unproven** | deny hierarchies 2 |
| `show configuration` | `security` | `show configuration security \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `services` | `show configuration services \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `smtp` | `show configuration smtp \| count` | refused | refused | **unproven** | deny hierarchies 2 |
| `show configuration` | `snmp` | `show configuration snmp \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `switch-options` | `show configuration switch-options \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `system` | `show configuration system \| count` | ran | ran | **unproven** | deny hierarchies 2 |
| `show configuration` | `unified-edge` | `show configuration unified-edge \| count` | ran | ran | **unproven** | deny hierarchies 3 |
| `show configuration` | `vlans` | `show configuration vlans \| count` | ran | ran | **unproven** | deny hierarchies 3 |
| `show configuration` | `virtual-chassis` | `show configuration virtual-chassis \| count` | ran | ran | **unproven** | deny hierarchies 3 |
| `` | `exit` | `exit` | ran | refused | **proven** | deny root and set words |

### Hierarchies

**A deny naming a `show configuration` hierarchy is not enforced.** Every one of the 32 hierarchies this image offers ran under a deny naming it, as it did in the control; the same deny shape refused the `show` words above. Each hierarchy word stays unproven.

Each hierarchy deny session that does not name `system` also typed `show configuration system \| count`, a hierarchy with lines to count, under its deny:

| deny session | deny |
|---|---|
| deny hierarchies 1 | ran |
| deny hierarchies 3 | ran |

### The overlay

`tests/lab/results/L26b-keywords-juniper_vjunos-router.yaml`, in platform.ParseKeywords form: a node's words are those this run proves (and, for the parent chain, `set`, `show` and `configuration`, which L26 proves); its `argument` is the node once the overlay is laid over this image's L26 tree: true where a placeholder is offered there, or a word offered there is proven by neither. It was computed against `tests/lab/results/L26-keywords-juniper_vjunos-router.yaml`, sha256 `94791e17081c6d17351174914f858a6c29ab9329104cafe743b30edbbb4d5074`, and holds only against the tree that hashes to that.

```yaml
# computed against tests/lab/results/L26-keywords-juniper_vjunos-router.yaml sha256 94791e17081c6d17351174914f858a6c29ab9329104cafe743b30edbbb4d5074
platform: juniper_junos
nodes:
  "": {words: ["exit", "save", "set", "show"], argument: false}
  "set": {words: ["cli"], argument: true}
  "show": {words: ["cli", "configuration", "host", "ingress-replication", "policy", "task"], argument: false}
  "show configuration": {words: [], argument: true}
```

### Sessions

#### control, user `alice01`

```
 
Current user: 'p49-l26b-all' login: 'alice01' class 'p49-l26b-all'
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

#### deny show words, user `alice02`

`deny-commands=^( *show +(cli\|host\|ingress-replication\|policy\|task)( .*)? *(\\|.*)?)$`

```
show cli
                   ^
syntax error, expecting <command>.
alice02@srx1> show cli   authorization
                   ^
syntax error, expecting <command>.

alice02@srx1> 
```

#### deny root and set words, user `alice03`

`deny-commands=^( *exit( .*)? *(\\|.*)?\| *save( .*)? *(\\|.*)?\| *set +cli( .*)? *(\\|.*)?)$`

```
 
Current user: 'p49-l26b-all' login: 'alice03' class 'p49-l26b-all'
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
    Deny regular expression: (^( *exit( .*)? *(\|.*)?| *save( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice03@srx1> 
```

#### deny hierarchies 1, user `alice04`

`deny-commands=^( *show +configuration +(access\|access-profile\|accounting-options\|applications\|apply-groups\|bridge-domains\|chassis\|class-of-service\|diameter\|dynamic-profiles\|event-options\|firewall\|forwarding-options\|groups\|interfaces\|jsrc)( .*)? *(\\|.*)?)$`

```
 
Current user: 'p49-l26b-all' login: 'alice04' class 'p49-l26b-all'
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
    Deny regular expression: (^( *show +configuration +(access|access-profile|accounting-options|applications|apply-groups|bridge-domains|chassis|class-of-service|diameter|dynamic-profiles|event-options|firewall|forwarding-options|groups|interfaces|jsrc)( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice04@srx1> 
```

#### deny hierarchies 2, user `alice05`

`deny-commands=^( *show +configuration +(jsrc-partition\|logical-systems\|multi-chassis\|multicast-snooping-options\|poe\|policy-options\|protocols\|routing-instances\|routing-options\|schedulers\|security\|services\|smtp\|snmp\|switch-options\|system)( .*)? *(\\|.*)?)$`

```
 
Current user: 'p49-l26b-all' login: 'alice05' class 'p49-l26b-all'
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
    Deny regular expression: (^( *show +configuration +(jsrc-partition|logical-systems|multi-chassis|multicast-snooping-options|poe|policy-options|protocols|routing-instances|routing-options|schedulers|security|services|smtp|snmp|switch-options|system)( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice05@srx1> 
```

#### deny hierarchies 3, user `alice06`

`deny-commands=^( *show +configuration +(unified-edge\|vlans\|virtual-chassis)( .*)? *(\\|.*)?)$`

```
 
Current user: 'p49-l26b-all' login: 'alice06' class 'p49-l26b-all'
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
    Deny regular expression: (^( *show +configuration +(unified-edge|vlans|virtual-chassis)( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice06@srx1> 
```

### Outputs

#### `show cli | count`

control:

```
 
Count: 9 lines

alice01@srx1> 
```

deny:

```
show cli
                   ^
syntax error, expecting <command>.
alice02@srx1> show cli   |
                   ^
permission denied.
alice02@srx1> show cli|   count
                   ^
permission denied.

alice02@srx1> 
```

#### `show host localhost | count`

control:

```
 
Count: 1 lines

alice01@srx1> 
```

deny:

```
show host
                   ^
syntax error, expecting <command>.
alice02@srx1> show host   localhost
                   ^
syntax error, expecting <command>.
alice02@srx1> show hostlocalhost   |
                   ^
syntax error, expecting <command>.
alice02@srx1> show hostlocalhost|   count
                   ^
syntax error, expecting <command>.

alice02@srx1> 
```

#### `show ingress-replication mvpn | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
show ingress-replication
                   ^
syntax error, expecting <command>.
alice02@srx1> show ingress-replication   mvpn
                   ^
syntax error, expecting <command>.
alice02@srx1> show ingress-replicationmvpn   |
                   ^
syntax error, expecting <command>.
alice02@srx1> show ingress-replicationmvpn|   count
                   ^
syntax error, expecting <command>.

alice02@srx1> 
```

#### `show policy | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
show policy
                   ^
syntax error, expecting <command>.
alice02@srx1> show policy   |
                   ^
permission denied.
alice02@srx1> show policy|   count
                   ^
permission denied.

alice02@srx1> 
```

#### `show task memory | count`

control:

```
 
Count: 4 lines

alice01@srx1> 
```

deny:

```
show task
                   ^
syntax error, expecting <command>.
alice02@srx1> show task   memory
                   ^
syntax error, expecting <command>.
alice02@srx1> show taskmemory   |
                   ^
syntax error, expecting <command>.
alice02@srx1> show taskmemory|   count
                   ^
syntax error, expecting <command>.

alice02@srx1> 
```

#### `set cli screen-length 0`

control:

```
 
Screen length set to 0

alice01@srx1> 
```

deny:

```
set cli
                  ^
syntax error, expecting <command>.
alice03@srx1> set cli   screen-length
                  ^
syntax error, expecting <command>.
alice03@srx1> set cliscreen-length   0
                  ^
syntax error, expecting <command>.

alice03@srx1> 
```

#### `save dhcp-security-snoop /var/tmp/p49-l26b.snoop | count`

control:

```
 
Count: 1 lines

alice01@srx1> 
```

deny:

```
save
              ^
unknown command.
alice03@srx1> save   dhcp-security-snoop
              ^
unknown command.
alice03@srx1> savedhcp-security-snoop   /var/tmp/p49-l26b.snoop
              ^
unknown command.
alice03@srx1> savedhcp-security-snoop/var/tmp/p49-l26b.snoop   |
              ^
unknown command.
alice03@srx1> savedhcp-security-snoop/var/tmp/p49-l26b.snoop|   count
              ^
unknown command.

alice03@srx1> 
```

#### `show configuration access | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration access-profile | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration accounting-options | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration applications | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration apply-groups | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration bridge-domains | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration chassis | count`

control:

```
 
Count: 5 lines

alice01@srx1> 
```

deny:

```
 
Count: 5 lines

alice04@srx1> 
```

#### `show configuration class-of-service | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration diameter | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration dynamic-profiles | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration event-options | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration firewall | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration forwarding-options | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration groups | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration interfaces | count`

control:

```
 
Count: 10 lines

alice01@srx1> 
```

deny:

```
 
Count: 10 lines

alice04@srx1> 
```

#### `show configuration jsrc | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice04@srx1> 
```

#### `show configuration jsrc-partition | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration logical-systems | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration multi-chassis | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration multicast-snooping-options | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration poe | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration policy-options | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration protocols | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration routing-instances | count`

control:

```
 
Count: 12 lines

alice01@srx1> 
```

deny:

```
 
Count: 12 lines

alice05@srx1> 
```

#### `show configuration routing-options | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration schedulers | count`

control:

```
show configuration schedulers
                                 ^
syntax error.
alice01@srx1> show configuration schedulers   |
                                 ^
syntax error.
alice01@srx1> show configuration schedulers|   count
                                 ^
syntax error.

alice01@srx1> 
```

deny:

```
show configuration schedulers
                                 ^
syntax error.
alice05@srx1> show configuration schedulers   |
                                 ^
syntax error.
alice05@srx1> show configuration schedulers|   count
                                 ^
syntax error.

alice05@srx1> 
```

#### `show configuration security | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration services | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration smtp | count`

control:

```
show configuration smtp
                                 ^
syntax error.
alice01@srx1> show configuration smtp   |
                                 ^
syntax error.
alice01@srx1> show configuration smtp|   count
                                 ^
syntax error.

alice01@srx1> 
```

deny:

```
show configuration smtp
                                 ^
syntax error.
alice05@srx1> show configuration smtp   |
                                 ^
syntax error.
alice05@srx1> show configuration smtp|   count
                                 ^
syntax error.

alice05@srx1> 
```

#### `show configuration snmp | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration switch-options | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice05@srx1> 
```

#### `show configuration system | count`

control:

```
 
Count: 150 lines

alice01@srx1> 
```

deny:

```
 
Count: 150 lines

alice05@srx1> 
```

#### `show configuration unified-edge | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice06@srx1> 
```

#### `show configuration vlans | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice06@srx1> 
```

#### `show configuration virtual-chassis | count`

control:

```
 
Count: 0 lines

alice01@srx1> 
```

deny:

```
 
Count: 0 lines

alice06@srx1> 
```

#### `exit`

control:

```
exit 


```

deny:

```
exit
              ^
unknown command.

alice03@srx1> 
```

#### sentinel, deny hierarchies 1

deny:

```
 
Count: 150 lines

alice04@srx1> 
```

#### sentinel, deny hierarchies 3

deny:

```
 
Count: 150 lines

alice06@srx1> 
```

