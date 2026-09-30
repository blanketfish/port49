# L26c-junoscript — juniper_vjunos-router

- **Date measured:** 2026-09-30
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L26c-junoscript-juniper_vjunos-router.pcap` — 2632 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L26c-junoscript-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether `deny-commands "junoscript"`, sent by TACACS+ or set on the local class, refuses `xml-mode netconf` from a CLI session while `show version` still runs, and closes the NETCONF service on port 830 for that user; with a control of the same bits and no deny. Also: whether a deny naming `xml-mode` binds, and whether abbreviations of `xml-mode` and `junoscript` are refused under the `junoscript` deny (the owner's SRX report, results/L26c-operator-juniper_srx.md).

## Observation

The classes were committed: commit complete.

```
set system login class p49-jsd-view permissions view
set system login user p49-jsd-view class p49-jsd-view
set system login class p49-jsd-local permissions view
set system login class p49-jsd-local deny-commands junoscript
set system login user p49-jsd-local class p49-jsd-local
```

On the device afterwards:

```
show configuration system login | display set | match p49-jsd 
set system login class p49-jsd-local permissions view
set system login class p49-jsd-local deny-commands junoscript
set system login class p49-jsd-view permissions view
set system login user p49-jsd-local uid 2003
set system login user p49-jsd-local class p49-jsd-local
set system login user p49-jsd-view uid 2004
set system login user p49-jsd-view class p49-jsd-view

breakglass@srx1>
```

| class | reply | why |
|---|---|---|
| W | `["local-user-name=p49-jsd-view", "deny-commands=junoscript"]` | wire: view, and deny-commands junoscript sent by TACACS+ |
| L | `["local-user-name=p49-jsd-local"]` | local: view, and deny-commands junoscript on the template's class, none sent |
| X | `["local-user-name=p49-jsd-view", "deny-commands=xml-mode"]` | wire: view, and a deny naming xml-mode itself |
| C | `["local-user-name=p49-jsd-view"]` | the control: view, no deny |
| R | break-glass, local | every permission: shows each entry form runs at all |

Completion over break-glass: `xml-mode ?`: [attributes interactive netconf version], placeholder false, err <nil>; `junoscript ?`: [attributes interactive netconf version], placeholder false, err <nil>.

Only `<get-software-information/>` was sent in any NETCONF session. A cell is `hello` (a NETCONF hello came back), `refused` (the CLI's refusal words, or the channel closed after port49d permitted the session), `result` (the RPC's `<software-information>`), `—` (not typed: the class does not type it, or its entry was refused).

| probe | W | L | X | C | R |
|---|---|---|---|---|---|
| show version | ran | ran | ran | ran | ran |
| entry: xml-mode netconf | refused | refused | hello | hello | hello |
| xml-mode netconf: get-software-information | — | — | result | result | result |
| entry: xml-mod netconf | refused | refused | — | refused | refused |
| xml-mod netconf: get-software-information | — | — | — | — | — |
| entry: junoscript netconf | refused | refused | — | hello | hello |
| junoscript netconf: get-software-information | — | — | — | result | result |
| entry: junoscr netconf | refused | refused | — | refused | refused |
| junoscr netconf: get-software-information | — | — | — | — | — |
| port 830 | refused | refused | hello | hello | — |
| port 830: get-software-information | — | — | result | result | — |

### Accounting `cmd=` per class

W:

```
breakglass cmd=logout
alice01 cmd=login
alice01 cmd=set cli «redacted» «redacted» «redacted»
alice01 cmd=show cli «redacted» «redacted»
alice01 cmd=show version <cr>
alice01 cmd=logout
alice02 cmd=login
alice02 cmd=xml-mode <cr>
alice02 cmd=logout
```

L:

```
alice03 cmd=login
alice03 cmd=set cli «redacted» «redacted» «redacted»
alice03 cmd=show cli «redacted» «redacted»
alice03 cmd=show version <cr>
alice03 cmd=logout
alice04 cmd=login
alice04 cmd=xml-mode <cr>
alice04 cmd=logout
```

X:

```
alice05 cmd=login
alice05 cmd=set cli «redacted» «redacted» «redacted»
alice05 cmd=show cli «redacted» «redacted»
alice05 cmd=show version <cr>
alice05 cmd=xml-mode netconf <cr>
alice05 cmd=login
alice05 cmd=logout
alice05 cmd=get-software-information<cr>
alice05 cmd=logout
alice06 cmd=login
alice06 cmd=xml-mode netconf need-trailer <cr>
alice06 cmd=logout
alice06 cmd=login
alice06 cmd=get-software-information<cr>
alice06 cmd=logout
```

C:

```
alice07 cmd=login
alice07 cmd=set cli «redacted» «redacted» «redacted»
alice07 cmd=show cli «redacted» «redacted»
alice07 cmd=show version <cr>
alice07 cmd=xml-mode netconf <cr>
alice07 cmd=login
alice07 cmd=logout
alice07 cmd=get-software-information<cr>
alice07 cmd=logout
alice08 cmd=login
alice08 cmd=set cli «redacted» «redacted» «redacted»
alice08 cmd=show cli «redacted» «redacted»
alice08 cmd=junoscript netconf <cr>
alice08 cmd=logout
alice08 cmd=login
alice08 cmd=get-software-information<cr>
alice08 cmd=logout
alice09 cmd=login
alice09 cmd=set cli «redacted» «redacted» «redacted»
alice09 cmd=show cli «redacted» «redacted»
alice09 cmd=logout
alice10 cmd=login
alice10 cmd=xml-mode netconf need-trailer <cr>
alice10 cmd=logout
alice10 cmd=login
alice10 cmd=get-software-information<cr>
alice10 cmd=logout
```

### W

`entry: junoscr netconf`:

```
junoscr
              ^
unknown command.
alice01@srx1> junoscr   netconf
              ^
unknown command.

alice01@srx1> 
```

`entry: junoscript netconf`:

```
junoscript
              ^
unknown command.
alice01@srx1> junoscript   netconf
              ^
unknown command.

alice01@srx1> 
```

`entry: xml-mod netconf`:

```
xml-mod
              ^
unknown command.
alice01@srx1> xml-mod   netconf
              ^
unknown command.

alice01@srx1> 
```

`entry: xml-mode netconf`:

```
xml-mode
              ^
unknown command.
alice01@srx1> xml-mode   netconf
              ^
unknown command.

alice01@srx1> 
```

`port 830`:

```
the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF
```

`show cli authorization`:

```
 
Current user: 'p49-jsd-view' login: 'alice01' class 'p49-jsd-view'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (junoscript)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

`show version`:

```
show version 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
… (88 more lines)
```

### L

`entry: junoscr netconf`:

```
junoscr
              ^
unknown command.
alice03@srx1> junoscr   netconf
              ^
unknown command.

alice03@srx1> 
```

`entry: junoscript netconf`:

```
junoscript
              ^
unknown command.
alice03@srx1> junoscript   netconf
              ^
unknown command.

alice03@srx1> 
```

`entry: xml-mod netconf`:

```
xml-mod
              ^
unknown command.
alice03@srx1> xml-mod   netconf
              ^
unknown command.

alice03@srx1> 
```

`entry: xml-mode netconf`:

```
xml-mode
              ^
unknown command.
alice03@srx1> xml-mode   netconf
              ^
unknown command.

alice03@srx1> 
```

`port 830`:

```
the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF
```

`show cli authorization`:

```
 
Current user: 'p49-jsd-local' login: 'alice03' class 'p49-jsd-local'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: junoscript
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice03@srx1> 
```

`show version`:

```
show version 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
… (88 more lines)
```

### X

`entry: xml-mode netconf`:

```
xml-mode netconf 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-jsd-view, class j-p49-jsd-view -->
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
… (4 more lines)
```

`port 830`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-jsd-view, class j-p49-jsd-view -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (17 more lines)
```

`port 830: get-software-information`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<software-information>
<host-name>srx1</host-name>
<product-model>vmx</product-model>
<product-name>vmx</product-name>
<junos-version>23.4R2-S2.1</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-prd-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]</comment>
… (438 more lines)
```

`show cli authorization`:

```
 
Current user: 'p49-jsd-view' login: 'alice05' class 'p49-jsd-view'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (xml-mode)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice05@srx1> 
```

`show version`:

```
show version 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
… (88 more lines)
```

`xml-mode netconf: get-software-information`:

```
]]>]]>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<software-information>
<host-name>srx1</host-name>
<product-model>vmx</product-model>
<product-name>vmx</product-name>
<junos-version>23.4R2-S2.1</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-prd-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
… (439 more lines)
```

### C

`entry: junoscr netconf`:

```
junoscr
                     ^
syntax error.
alice09@srx1> junoscr   netconf
              ^
unknown command.

alice09@srx1> 
```

`entry: junoscript netconf`:

```
junoscript netconf 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-jsd-view, class j-p49-jsd-view -->
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
… (4 more lines)
```

`entry: xml-mod netconf`:

```
xml-mod
                     ^
syntax error.
alice08@srx1> xml-mod   netconf
              ^
unknown command.

alice08@srx1> 
```

`entry: xml-mode netconf`:

```
xml-mode netconf 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-jsd-view, class j-p49-jsd-view -->
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
… (4 more lines)
```

`junoscript netconf: get-software-information`:

```
]]>]]>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<software-information>
<host-name>srx1</host-name>
<product-model>vmx</product-model>
<product-name>vmx</product-name>
<junos-version>23.4R2-S2.1</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-prd-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
… (439 more lines)
```

`port 830`:

```
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-jsd-view, class j-p49-jsd-view -->
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  <capabilities>
    <capability>urn:ietf:params:netconf:base:1.0</capability>
… (17 more lines)
```

`port 830: get-software-information`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<software-information>
<host-name>srx1</host-name>
<product-model>vmx</product-model>
<product-name>vmx</product-name>
<junos-version>23.4R2-S2.1</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-prd-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]</comment>
… (438 more lines)
```

`show cli authorization`:

```
 
Current user: 'p49-jsd-view' login: 'alice07' class 'p49-jsd-view'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice07@srx1> 
```

`show version`:

```
show version 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
… (88 more lines)
```

`xml-mode netconf: get-software-information`:

```
]]>]]>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<software-information>
<host-name>srx1</host-name>
<product-model>vmx</product-model>
<product-name>vmx</product-name>
<junos-version>23.4R2-S2.1</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-prd-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
… (439 more lines)
```

### R

`entry: junoscr netconf`:

```
junoscr
                        ^
syntax error.
breakglass@srx1> junoscr   netconf
                 ^
unknown command.

breakglass@srx1> 
```

`entry: junoscript netconf`:

```
junoscript netconf 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user breakglass, class j-super-user -->
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
… (4 more lines)
```

`entry: xml-mod netconf`:

```
xml-mod
                        ^
syntax error.
breakglass@srx1> xml-mod   netconf
                 ^
unknown command.

breakglass@srx1> 
```

`entry: xml-mode netconf`:

```
xml-mode netconf 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user breakglass, class j-super-user -->
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
… (4 more lines)
```

`junoscript netconf: get-software-information`:

```
]]>]]>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<software-information>
<host-name>srx1</host-name>
<product-model>vmx</product-model>
<product-name>vmx</product-name>
<junos-version>23.4R2-S2.1</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-prd-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
… (439 more lines)
```

`show version`:

```
show version 
Hostname: srx1
Model: vmx
Junos: 23.4R2-S2.1
JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]
JUNOS OS libs [20240604.39c9257_builder_stable_12_234]
… (88 more lines)
```

`xml-mode netconf: get-software-information`:

```
]]>]]>
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<software-information>
<host-name>srx1</host-name>
<product-model>vmx</product-model>
<product-name>vmx</product-name>
<junos-version>23.4R2-S2.1</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-prd-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS Kernel 64-bit  [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
… (439 more lines)
```

