# L68-netconf-operator — juniper_vjunos-router

- **Date measured:** 2026-10-16
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L68-netconf-operator-juniper_vjunos-router.pcap` — 854 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L68-netconf-operator-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `5fba3a804ab7115d7a37b93b2527dc71564a9ade`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestL68ViewConfigurationNetconfOperator$`

## Claim

Whether NETCONF (`xml-mode` from the CLI, port 830, the port-22 subsystem, the exec channel) reaches `<get-configuration/>` under a reply holding view-configuration with the entry denies beside view-configuration's other reach denied (O), against a control with the same bits and no deny (spec §15 L68; plan 9g Task 1, gate G1-operator).

## Observation

**Gate:** G1-operator: pass

The reference configuration and `netconf ssh` were committed: commit complete.

| probe | O | C |
|---|---|---|
| entry: xml-mode netconf need-trailer | refused | hello |
| xml-mode netconf need-trailer: get-configuration | — | result |
| port 830 | refused | hello |
| port 830: get-configuration | — | result |
| port 22 subsystem | refused | hello |
| port 22 subsystem: get-configuration | — | result |
| exec channel | refused | hello |
| exec channel: get-configuration | — | result |

### Verdict against the control

| probe | O |
|---|---|
| entry: xml-mode netconf need-trailer | deny |
| xml-mode netconf need-trailer: get-configuration | — |
| port 830 | deny |
| port 830: get-configuration | — |
| port 22 subsystem | deny |
| port 22 subsystem: get-configuration | — |
| exec channel | deny |
| exec channel: get-configuration | — |

### O

`entry: xml-mode netconf need-trailer`:

```
xml-mode
              ^
unknown command.
alice01@srx1> xml-mode   netconf
              ^
unknown command.
alice01@srx1> xml-modenetconf   need-trailer
              ^
unknown command.

alice01@srx1> 
```

`exec channel`:

```

error: unknown command: xml-mode

```

`port 22 subsystem`:

```
the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF
```

`port 830`:

```
the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice01' class 'p49-remote'
Permissions:
    clear       -- Can clear learned network info
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

### C

`entry: xml-mode netconf need-trailer`:

```
xml-mode netconf need-trailer 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user remote, class j-p49-remote -->
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
    <capability>urn:ietf:params:xml:ns:yang:ietf-yang-metadata?module=ietf-yang-metadata&amp;revision=2016-08-05</capability>
    <capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability>
    <capability>http://xml.juniper.net/netconf/junos/1.0</capability>
    <capability>http://xml.juniper.net/dmi/system/1.0</capability>
    <capability>http://yang.juniper.net/junos/jcmd?module=junos-configuration-metadata&amp;revision=2021-09-01</capability>
… (5 more lines)
```

`exec channel`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user remote, class j-p49-remote -->
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
… (25 more lines)
```

`port 22 subsystem`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user remote, class j-p49-remote -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (17 more lines)
```

`port 22 subsystem: get-configuration`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1792141150" junos:changed-localtime="2026-10-16 08:59:10 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
```

`port 830`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user remote, class j-p49-remote -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (17 more lines)
```

`port 830: get-configuration`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1792141150" junos:changed-localtime="2026-10-16 08:59:10 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice05' class 'p49-remote'
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

`xml-mode netconf need-trailer: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1792141150" junos:changed-localtime="2026-10-16 08:59:10 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
]]>]]>

```

