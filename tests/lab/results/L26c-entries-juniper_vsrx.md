# L26c-entries — juniper_vsrx

- **Date measured:** 2026-10-11
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L26c-entries-juniper_vsrx.pcap` — 1888 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L26c-entries-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `3cb39d236d76844923195c5b8a110e554ae95974`, `PORT49_LAB_PLATFORMS=vsrx`, `-run ^TestL26cEntryNetconf$`

## Claim

Whether `deny-commands "junoscript"`, sent by TACACS+ beside a deny of `show configuration` under `view view-configuration`, refuses NETCONF as an SSH subsystem on port 22 and over the SSH exec channel (`xml-mode netconf need-trailer`), as it refuses `xml-mode` from the CLI and port 830; with the same reply less the junoscript deny (the hole) and a control with the same bits and no deny (spec §15 L26c; plan 9b1 Task 3, cell a).

## Observation

The classes were committed: commit complete.

```
set system login class p49-ent-vc permissions view
set system login class p49-ent-vc permissions view-configuration
set system login user p49-ent-vc class p49-ent-vc
set system login class p49-ent-v permissions view
set system login user p49-ent-v class p49-ent-v
```

| class | reply | why |
|---|---|---|
| W | `["local-user-name=p49-ent-vc", "deny-commands=^( *show +configuration( .*)? *(\\\|.*)?\| *junoscript( .*)? *(\\\|.*)?)$"]` | view view-configuration; deny show configuration and junoscript (set 1.2.0's reply) |
| V | `["local-user-name=p49-ent-vc", "deny-commands=^ *show +configuration( .*)? *(\\\|.*)?$"]` | view view-configuration; deny show configuration only (the hole) |
| C | `["local-user-name=p49-ent-vc"]` | view view-configuration; no deny (the control) |

| probe | W | V | C |
|---|---|---|---|
| show configuration system host-name | refused | refused | ran |
| entry: xml-mode netconf need-trailer | refused | hello | hello |
| xml-mode netconf need-trailer: get-configuration | — | result | result |
| port 830 | refused | hello | hello |
| port 830: get-configuration | — | result | result |
| port 22 subsystem | refused | hello | hello |
| port 22 subsystem: get-configuration | — | result | result |
| exec channel | refused | hello | hello |
| exec channel: get-configuration | — | result | result |

### Verdict against the control

| probe | W | V |
|---|---|---|
| show configuration system host-name | deny | deny |
| entry: xml-mode netconf need-trailer | deny | reached |
| xml-mode netconf need-trailer: get-configuration | — | reached |
| port 830 | deny | reached |
| port 830: get-configuration | — | reached |
| port 22 subsystem | deny | reached |
| port 22 subsystem: get-configuration | — | reached |
| exec channel | deny | reached |
| exec channel: get-configuration | — | reached |

### W

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
 
Current user: 'p49-ent-vc' login: 'alice01' class 'p49-ent-vc'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +configuration( .*)? *(\|.*)?| *junoscript( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

`show configuration system host-name`:

```
show configuration
                                ^
syntax error.
alice01@srx1> show configuration   system
                   ^
syntax error, expecting <command>.
… (5 more lines)
```

### V

`entry: xml-mode netconf need-trailer`:

```
xml-mode netconf need-trailer 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
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
  <session-id>29119</session-id>
… (3 more lines)
```

`exec channel`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
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
… (23 more lines)
```

`port 22 subsystem`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (15 more lines)
```

`port 22 subsystem: get-configuration`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1791748055" junos:changed-localtime="2026-10-11 19:47:35 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
```

`port 830`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (15 more lines)
```

`port 830: get-configuration`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1791748055" junos:changed-localtime="2026-10-11 19:47:35 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
```

`show cli authorization`:

```
 
Current user: 'p49-ent-vc' login: 'alice05' class 'p49-ent-vc'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^ *show +configuration( .*)? *(\|.*)?$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice05@srx1> 
```

`show configuration system host-name`:

```
show configuration
                                ^
syntax error.
alice05@srx1> show configuration   system
                   ^
syntax error, expecting <command>.
… (5 more lines)
```

`xml-mode netconf need-trailer: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1791748055" junos:changed-localtime="2026-10-11 19:47:35 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
]]>]]>

```

### C

`entry: xml-mode netconf need-trailer`:

```
xml-mode netconf need-trailer 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
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
  <session-id>29146</session-id>
… (3 more lines)
```

`exec channel`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
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
… (23 more lines)
```

`port 22 subsystem`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (15 more lines)
```

`port 22 subsystem: get-configuration`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1791748055" junos:changed-localtime="2026-10-11 19:47:35 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
```

`port 830`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-ent-vc, class j-p49-ent-vc -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (15 more lines)
```

`port 830: get-configuration`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1791748055" junos:changed-localtime="2026-10-11 19:47:35 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
```

`show cli authorization`:

```
 
Current user: 'p49-ent-vc' login: 'alice09' class 'p49-ent-vc'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice09@srx1> 
```

`show configuration system host-name`:

```
show configuration system host-name 
host-name srx1;

alice09@srx1> 
```

`xml-mode netconf need-trailer: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1791748055" junos:changed-localtime="2026-10-11 19:47:35 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
]]>]]>

```

