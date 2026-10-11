# L58 — juniper_vsrx

- **Date measured:** 2026-10-11
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L58-juniper_vsrx.pcap` — 1534 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L58-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `8c0448ecf87b00fcf54f4a10cfedcb4beefae8a4`, `PORT49_LAB_PLATFORMS=vsrx`, `-run ^TestL58JunosBaselineWords$`

## Claim

Whether `save` is a keyword to deny-commands, and whether bare `xml-mode` and `xml-mode netconf` are refused, under set 1.2.0's factored deny naming `save` and `junoscript`, each against a control with the same class and no deny (spec §15 L58; decision 44 ruling 10).

## Observation

The class was committed: commit complete.

```
set system login class p49-l58-view permissions view
set system login user p49-l58-view class p49-l58-view
set system login class p49-l58-save permissions all
set system login user p49-l58-save class p49-l58-save
```

Completion over break-glass: `save ?`:  (placeholder false, err <nil>); `xml-mode ?`: attributes interactive netconf version (placeholder false, err <nil>).

| session | reply |
|---|---|
| control (`save`) | `["local-user-name=p49-l58-save"]` |
| deny (`save`) | `["local-user-name=p49-l58-save", "deny-commands=^ *(save\|junoscript)( .*)? *(\\\|.*)?$"]` |
| control (entries) | `["local-user-name=p49-l58-view"]` |
| deny (entries) | `["local-user-name=p49-l58-view", "deny-commands=^ *(save\|junoscript)( .*)? *(\\\|.*)?$"]` |

| probe | control | deny |
|---|---|---|
| `show version \| count` | ran | ran |
| `save dhcp-security-snoop /var/tmp/p49-l58.snoop \| count` | refused | refused |
| `save dhcp-security-snoop \| count` | not observed | refused |
| `xml-mode` | greeting | refused |
| `xml-mode netconf need-trailer` | greeting | refused |

### Gates

- **G3** `save`: **proven** (by `save dhcp-security-snoop /var/tmp/p49-l58.snoop \| count; the control's CLI took `save` and stopped after it`).
- **G4** `xml-mode` under the `junoscript` deny: bare refused, `netconf` refused: **closed**.

### Outputs

#### control, user `alice01`

```
 
Current user: 'p49-l58-save' login: 'alice01' class 'p49-l58-save'
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

`show version \| count`:

```
 
Count: 51 lines

alice01@srx1> 
```

`save dhcp-security-snoop /var/tmp/p49-l58.snoop \| count`:

```
save dhcp-security-snoop /var/tmp/p49-l58.snoop
                                       ^
syntax error, expecting <command>.
alice01@srx1> save dhcp-security-snoop /var/tmp/p49-l58.snoop   |
                                       ^
syntax error, expecting <command>.
alice01@srx1> save dhcp-security-snoop /var/tmp/p49-l58.snoop|   count
                                       ^
syntax error, expecting <command>.

alice01@srx1> 
```

`save dhcp-security-snoop \| count`:

```
 
error: command is not valid on the vsrx
error: command is not valid on the vsrx

alice01@srx1> 
```

`xml-mode`:

```
xml-mode 
<?xml version="1.0" encoding="us-ascii"?>
<junoscript xmlns="http://xml.juniper.net/xnm/1.1/xnm" xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" schemaLocation="http://xml.juniper.net/junos/21.4R0/junos junos/21.4R0/junos.xsd" os="JUNOS" release="21.4R3.15" hostname="srx1" version="1.0">
<!-- session start at 2026-10-11 20:33:39 UTC -->

```

`xml-mode netconf need-trailer`:

```
xml-mode netconf need-trailer 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-l58-view, class j-p49-l58-view -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:confirmed-commit:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:validate:1.0</capability>
    <capability>urn:ietf:params:netconf:capability:url:1.0?scheme=http,ftp,file</capability>
    <capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:candidate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:confirmed-commit:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:validate:1.0</capability>
    <capability>urn:ietf:params:xml:ns:netconf:capability:url:1.0?scheme=http,ftp,file</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability>
    <capability>http://xml.juniper.net/netconf/junos/1.0</capability>
    <capability>http://xml.juniper.net/dmi/system/1.0</capability>
  </capabilities>
  <session-id>29353</session-id>
</hello>
]]>]]>

```

#### deny, user `alice02`

```
 
Current user: 'p49-l58-save' login: 'alice02' class 'p49-l58-save'
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
    Deny regular expression: (^ *(save|junoscript)( .*)? *(\|.*)?$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice02@srx1> 
```

`show version \| count`:

```
 
Count: 51 lines

alice02@srx1> 
```

`save dhcp-security-snoop /var/tmp/p49-l58.snoop \| count`:

```
save
              ^
unknown command.
alice02@srx1> save   dhcp-security-snoop
              ^
unknown command.
alice02@srx1> savedhcp-security-snoop   /var/tmp/p49-l58.snoop
              ^
unknown command.
alice02@srx1> savedhcp-security-snoop/var/tmp/p49-l58.snoop   |
              ^
unknown command.
alice02@srx1> savedhcp-security-snoop/var/tmp/p49-l58.snoop|   count
              ^
unknown command.

alice02@srx1> 
```

`save dhcp-security-snoop \| count`:

```
save
              ^
unknown command.
alice02@srx1> save   dhcp-security-snoop
              ^
unknown command.
alice02@srx1> savedhcp-security-snoop   |
              ^
unknown command.
alice02@srx1> savedhcp-security-snoop|   count
              ^
unknown command.

alice02@srx1> 
```

`xml-mode`:

```
xml-mode
              ^
unknown command.

alice04@srx1> 
```

`xml-mode netconf need-trailer`:

```
xml-mode
              ^
unknown command.
alice06@srx1> xml-mode   netconf
              ^
unknown command.
alice06@srx1> xml-modenetconf   need-trailer
              ^
unknown command.

alice06@srx1> 
```

