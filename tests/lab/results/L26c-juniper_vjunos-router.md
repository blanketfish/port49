# L26c — juniper_vjunos-router

- **Date measured:** 2026-09-25
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L26c-juniper_vjunos-router.pcap` — 3163 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L26c-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a projected Junos CLI session reaches an RPC past its denies: `xml-mode netconf need-trailer`, the NETCONF subsystem on port 22 with `netconf ssh` deleted, `op url`, and `start shell`, under a projected class, the fail-closed reply and a control (Task 13a review I1; gates Task 14's branch M).

## Observation

The class was committed: commit complete.

```
set system login class p49-l26c-view permissions view
set system login user p49-l26c-view class p49-l26c-view
```

| class | reply | why |
|---|---|---|
| P | `["local-user-name=p49-l26c-view", "deny-commands=^ *show +configuration( .*)? *(\\\|.*)?$"]` | projected: view, and a deny naming show configuration |
| F | `["local-user-name=p49-l26c-view", "deny-commands=^.*$"]` | the fail-closed reply over the same template |
| C | `["local-user-name=p49-l26c-view"]` | the control: view, no deny |
| R | break-glass, local | every permission: shows each probe runs at all |

xml-mode completion (break-glass): `xml-mode ?`: [attributes interactive netconf version], placeholder false, err <nil>; `xml-mode netconf ?`: [attributes interactive version], placeholder false, err <nil>. Entries tried: `xml-mode netconf need-trailer`, `xml-mode netconf`.

Port 22 was measured after `delete system services netconf` (commit: commit complete); the services then:

```
show configuration system services | display set 
set system services ssh root-login allow

breakglass@srx1> 
```

| probe | P | F | C | R |
|---|---|---|---|---|
| show version | ran | refused | ran | ran |
| show configuration | refused | refused | not observed | ran |
| op ? | 2 words, placeholder true | 0 words, placeholder false | 2 words, placeholder true | 2 words, placeholder true |
| op url | accepted | refused | accepted | accepted |
| start shell | refused | refused | refused | shell |
| port 22 | refused | refused | refused | refused |
| port 22: get-software-information | — | — | — | — |
| entry: xml-mode netconf need-trailer | hello | refused | hello | hello |
| xml-mode netconf need-trailer: get-software-information | result | — | result | result |
| xml-mode netconf need-trailer: get-configuration | not observed | — | not observed | result |
| xml-mode netconf need-trailer: command show configuration | refused | — | not observed | result |
| entry: xml-mode netconf | hello | refused | hello | hello |
| xml-mode netconf: get-software-information | result | — | result | result |
| xml-mode netconf: get-configuration | not observed | — | not observed | result |
| xml-mode netconf: command show configuration | refused | — | not observed | result |

### Read off the table

- RPC reachable from projected CLI: true
- every P and F refusal isolated: false
- reached: op url in P (accepted)
- start shell refused in P and C alike (the bits), reached in R
- start shell refused in F and C alike (the bits), reached in R
- port 22 runs nowhere: refused in R too (refused)
- port 22 runs nowhere: refused in R too (refused)
- reached: entry: xml-mode netconf need-trailer in P (hello)
- reached: xml-mode netconf need-trailer: get-software-information in P (result)
- not observed: xml-mode netconf need-trailer: get-configuration in P (not observed)
- xml-mode netconf need-trailer: command show configuration refused in P and C alike (the bits), reached in R
- reached: entry: xml-mode netconf in P (hello)
- reached: xml-mode netconf: get-software-information in P (result)
- not observed: xml-mode netconf: get-configuration in P (not observed)
- xml-mode netconf: command show configuration refused in P and C alike (the bits), reached in R

### P

`entry: xml-mode netconf`:

```
xml-mode netconf 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-l26c-view, class j-p49-l26c-view -->
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

`entry: xml-mode netconf need-trailer`:

```
xml-mode netconf need-trailer 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-l26c-view, class j-p49-l26c-view -->
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

`op ?`:

```
invoke-debugger url
```

`op url`:

```
op url /var/tmp/p49-none.slax 
error: cp: /var/tmp/p49-none.slax: No such file or directory
error: File copy operation failed

alice01@srx1> 
```

`port 22`:

```
request the netconf subsystem on port 22: ssh: subsystem request failed
```

`show cli authorization`:

```
 
Current user: 'p49-l26c-view' login: 'alice01' class 'p49-l26c-view'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^ *show +configuration( .*)? *(\|.*)?$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

`show configuration`:

```
show configuration
                                ^
syntax error.

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
… (74 more lines)
```

`start shell`:

```
start shell
                    ^
syntax error, expecting <command>.

alice01@srx1> 
```

`xml-mode netconf need-trailer: command show configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<rpc-error>
<error-type>protocol</error-type>
<error-tag>operation-failed</error-tag>
<error-severity>error</error-severity>
<error-message>permission denied</error-message>
<error-info>
<bad-element>configuration</bad-element>
</error-info>
</rpc-error>
</rpc-reply>
]]>]]>

```

`xml-mode netconf need-trailer: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790344645" junos:changed-localtime="2026-09-25 13:57:25 UTC">
</configuration>
</rpc-reply>
]]>]]>

```

`xml-mode netconf need-trailer: get-software-information`:

```
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
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS libs [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]</comment>
… (430 more lines)
```

`xml-mode netconf: command show configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<rpc-error>
<error-type>protocol</error-type>
<error-tag>operation-failed</error-tag>
<error-severity>error</error-severity>
<error-message>permission denied</error-message>
<error-info>
<bad-element>configuration</bad-element>
</error-info>
</rpc-error>
</rpc-reply>
]]>]]>

```

`xml-mode netconf: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790344645" junos:changed-localtime="2026-09-25 13:57:25 UTC">
</configuration>
</rpc-reply>
]]>]]>

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
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS libs [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
… (431 more lines)
```

### F

`entry: xml-mode netconf`:

```
xml-mode
              ^
unknown command.
alice04@srx1> xml-mode   netconf
              ^
unknown command.

alice04@srx1> 
```

`entry: xml-mode netconf need-trailer`:

```
xml-mode
              ^
unknown command.
alice03@srx1> xml-mode   netconf
              ^
unknown command.
alice03@srx1> xml-modenetconf   need-trailer
              ^
unknown command.

alice03@srx1> 
```

`op ?`:

```
(the device returned no output at all: zero bytes on the channel)
```

`op url`:

```
op
              ^
unknown command.
alice03@srx1> op   url
              ^
unknown command.
alice03@srx1> opurl   /var/tmp/p49-none.slax
              ^
unknown command.

alice03@srx1> 
```

`port 22`:

```
request the netconf subsystem on port 22: ssh: subsystem request failed
```

`show cli authorization`:

```
show
              ^
unknown command.
alice03@srx1> show   cli
              ^
unknown command.
alice03@srx1> showcli   authorization
              ^
unknown command.

alice03@srx1> 
```

`show configuration`:

```
show
              ^
unknown command.
alice03@srx1> show   configuration
              ^
unknown command.

alice03@srx1> 
```

`show version`:

```
show
              ^
unknown command.
alice03@srx1> show   version
              ^
unknown command.

alice03@srx1> 
```

`start shell`:

```
start
              ^
unknown command.
alice03@srx1> start   shell
              ^
unknown command.

alice03@srx1> 
```

### C

`entry: xml-mode netconf`:

```
xml-mode netconf 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-l26c-view, class j-p49-l26c-view -->
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

`entry: xml-mode netconf need-trailer`:

```
xml-mode netconf need-trailer 
<!-- No zombies were killed during the creation of this user interface -->
<!-- user p49-l26c-view, class j-p49-l26c-view -->
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

`op ?`:

```
invoke-debugger url
```

`op url`:

```
op url /var/tmp/p49-none.slax 
error: cp: /var/tmp/p49-none.slax: No such file or directory
error: File copy operation failed

alice05@srx1> 
```

`port 22`:

```
request the netconf subsystem on port 22: ssh: subsystem request failed
```

`show cli authorization`:

```
 
Current user: 'p49-l26c-view' login: 'alice05' class 'p49-l26c-view'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice05@srx1> 
```

`show configuration`:

```
show configuration 
## Last commit: 2026-09-25 13:57:25 UTC by breakglass
version /* ACCESS-DENIED */;
system { /* ACCESS-DENIED */ };
chassis { /* ACCESS-DENIED */ };
interfaces { /* ACCESS-DENIED */ };
routing-instances { /* ACCESS-DENIED */ };

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
… (74 more lines)
```

`start shell`:

```
start shell
                    ^
syntax error, expecting <command>.

alice05@srx1> 
```

`xml-mode netconf need-trailer: command show configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration-information>
<configuration-output>
## Last commit: 2026-09-25 13:57:25 UTC by breakglass
version /* ACCESS-DENIED */;
system { /* ACCESS-DENIED */ };
chassis { /* ACCESS-DENIED */ };
interfaces { /* ACCESS-DENIED */ };
routing-instances { /* ACCESS-DENIED */ };
</configuration-output>
</configuration-information>
</rpc-reply>
]]>]]>

```

`xml-mode netconf need-trailer: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790344645" junos:changed-localtime="2026-09-25 13:57:25 UTC">
</configuration>
</rpc-reply>
]]>]]>

```

`xml-mode netconf need-trailer: get-software-information`:

```
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
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS libs [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]</comment>
… (430 more lines)
```

`xml-mode netconf: command show configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration-information>
<configuration-output>
## Last commit: 2026-09-25 13:57:25 UTC by breakglass
version /* ACCESS-DENIED */;
system { /* ACCESS-DENIED */ };
chassis { /* ACCESS-DENIED */ };
interfaces { /* ACCESS-DENIED */ };
routing-instances { /* ACCESS-DENIED */ };
</configuration-output>
</configuration-information>
</rpc-reply>
]]>]]>

```

`xml-mode netconf: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790344645" junos:changed-localtime="2026-09-25 13:57:25 UTC">
</configuration>
</rpc-reply>
]]>]]>

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
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS libs [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
… (431 more lines)
```

### R

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

`entry: xml-mode netconf need-trailer`:

```
xml-mode netconf need-trailer 
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
… (5 more lines)
```

`op ?`:

```
invoke-debugger url
```

`op url`:

```
op url /var/tmp/p49-none.slax 
error: cp: /var/tmp/p49-none.slax: No such file or directory
error: File copy operation failed

breakglass@srx1> 
```

`port 22`:

```
request the netconf subsystem on port 22: ssh: subsystem request failed
```

`show configuration`:

```
show configuration 
## Last commit: 2026-09-25 13:57:25 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
    root-authentication {
        encrypted-password "«redacted»"; ## SECRET-DATA
    }
    login {
        class p49-l26c-view {
            permissions view;
        }
        class p49-readonly {
            permissions [ view view-configuration ];
        }
        user admin {
            uid 2000;
            class super-user;
            authentication {
                encrypted-password "«redacted»"; ## SECRET-DATA
… (158 more lines)
```

`show version`:

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
… (74 more lines)
```

`start shell`:

```
start shell 
% 
[exit typed]
exit
exit

breakglass@srx1> 
```

`xml-mode netconf need-trailer: command show configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration-information>
<configuration-output>
## Last commit: 2026-09-25 13:57:25 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
    root-authentication {
        encrypted-password "«redacted»"; ## SECRET-DATA
    }
    login {
        class p49-l26c-view {
            permissions view;
        }
        class p49-readonly {
            permissions [ view view-configuration ];
        }
        user admin {
            uid 2000;
            class super-user;
… (163 more lines)
```

`xml-mode netconf need-trailer: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790344645" junos:changed-localtime="2026-09-25 13:57:25 UTC">
    <version>23.4R2-S2.1</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>«redacted»</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-l26c-view</name>
                <permissions>view</permissions>
            </class>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
… (187 more lines)
```

`xml-mode netconf need-trailer: get-software-information`:

```
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
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS libs [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS runtime [20240604.39c9257_builder_stable_12_234]</comment>
… (430 more lines)
```

`xml-mode netconf: command show configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration-information>
<configuration-output>
## Last commit: 2026-09-25 13:57:25 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
    root-authentication {
        encrypted-password "«redacted»"; ## SECRET-DATA
    }
    login {
        class p49-l26c-view {
            permissions view;
        }
        class p49-readonly {
            permissions [ view view-configuration ];
        }
        user admin {
            uid 2000;
            class super-user;
… (163 more lines)
```

`xml-mode netconf: get-configuration`:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790344645" junos:changed-localtime="2026-09-25 13:57:25 UTC">
    <version>23.4R2-S2.1</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>«redacted»</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-l26c-view</name>
                <permissions>view</permissions>
            </class>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
… (187 more lines)
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
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS libs [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20240604.39c9257_builder_stable_12_234</package-name>
… (431 more lines)
```

