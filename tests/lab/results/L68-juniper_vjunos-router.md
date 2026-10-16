# L68 — juniper_vjunos-router

- **Date measured:** 2026-10-16
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L68-juniper_vjunos-router.pcap` — 4784 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L68-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `226b97ba894b84e03d7124f03e5bff92aedb4eb7`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestL68ViewConfigurationCLI$`

## Claim

Whether `user-permissions` holding view-configuration, with deny-commands covering `show security` and view-configuration's other reach, lets the session read the configuration and nothing the denies leave open, at the CLI and over the exec channel, for a readonly's reply and an operator's, against `view` alone and a control with the same bits and no deny (spec §15 L68; plan 9g Task 1, gates G1 and G1-operator).

## Observation

**Gate:** G1: STOP —    monitor   list: P took it past its deny;    monitor   list: H took it past its deny; G1-operator: STOP —    monitor   list: O took it past its deny

The reference configuration was committed: commit complete.

| row | reply | why | `show cli authorization` bits |
|---|---|---|---|
| P | `["user-permissions=view view-configuration", "deny-commands=^( *show +security( .*)? *(\\\|.*)?\| *(monitor\|help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\\|.*)?\| *set +cli( .*)? *(\\\|.*)?)$"]` | set 1.2.0's render of a readonly granted show ** less show security ** and monitor **: set 1.3.0's reply | view view-configuration |
| H | `["user-permissions=view view-configuration", "deny-commands=^( *show +security( .*)? *(\\\|.*)?\| *(monitor\|junoscript\|op)( .*)? *(\\\|.*)?\| *request +(mpls\|path-computation-client\|security\|unified-edge\|virtual-chassis)( .*)? *(\\\|.*)?\| *(load\|save) +dhcp-security-snoop( .*)? *(\\\|.*)?)$"]` | show security, view-configuration's other reach and the entry denies, nothing else | view view-configuration |
| O | `["user-permissions=clear view view-configuration", "deny-commands=^( *show +security( .*)? *(\\\|.*)?\| *(monitor\|help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\\|.*)?\| *set +cli( .*)? *(\\\|.*)?)$"]` | the operator granted show ** and clear ** less the same: set 1.3.0's operator reply | clear view view-configuration |
| V | `["user-permissions=view", "deny-commands=^( *show +security( .*)? *(\\\|.*)?\| *(monitor\|help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\\|.*)?\| *set +cli( .*)? *(\\\|.*)?)$"]` | view alone under P's deny: what the bit adds | view |
| Vc | `["user-permissions=view"]` | view alone, no deny: the completion baseline | view |
| C | `["user-permissions=view view-configuration"]` | the control | view view-configuration |

| probe | P | H | O | V | Vc | C |
|---|---|---|---|---|---|---|
| show configuration system host-name | ran | ran | ran | refused | refused | ran |
| sh conf sys host-name | ran | ran | ran | refused | refused | ran |
| show configuration system host-name \| display set | ran | ran | ran | refused | refused | ran |
| show security p49-none | refused | refused | refused | refused | past | past |
| sh sec p49-none | refused | refused | refused | refused | past | past |
| monitor p49-none | refused | refused | refused | refused | refused | past |
| mon p49-none | refused | refused | refused | refused | refused | past |
| monitor list | refused | refused | refused | refused | refused | past |
| monitor list \| no-more | refused | refused | refused | refused | refused | past |
|    monitor   list | past | past | past | past | past | past |
| MONITOR LIST | refused | refused | refused | refused | refused | refused |
| request mpls p49-none | refused | refused | refused | refused | refused | past |
| req mpls p49-none | refused | refused | refused | refused | refused | past |
| request mp p49-none | refused | refused | refused | refused | refused | past |
| request path-computation-client p49-none | refused | refused | refused | refused | refused | past |
| req path-computation-client p49-none | refused | refused | refused | refused | refused | past |
| request security p49-none | refused | refused | refused | refused | refused | past |
| req sec p49-none | refused | refused | refused | refused | refused | past |
| request unified-edge p49-none | refused | refused | refused | refused | refused | past |
| request virtual-chassis p49-none | refused | refused | refused | refused | refused | past |
| req vir p49-none | refused | refused | refused | refused | refused | past |
| load dhcp-security-snoop /var/tmp/p49-l68-none | refused | refused | refused | refused | refused | past |
| save dhcp-security-snoop \| count | refused | refused | refused | refused | refused | past |
| op url /var/tmp/p49-entry-op.slax | refused | refused | refused | refused | ran | ran |
| op ur /var/tmp/p49-entry-op.slax | refused | refused | refused | refused | ran | ran |
| configure | refused | refused | refused | refused | refused | refused |
| edit | refused | refused | refused | refused | refused | refused |
| configure private | refused | refused | refused | refused | refused | refused |
| show log messages \| count | ran | ran | ran | refused | refused | ran |
| show firewall \| no-more | past | past | past | refused | refused | past |
| show policer \| no-more | past | past | past | refused | refused | past |
| file list /config | refused | past | refused | refused | past | past |
| file show /config/juniper.conf.gz \| count | refused | ran | refused | refused | ran | ran |
| exec: show configuration system host-name | ran | ran | ran | — | — | ran |
| exec: monitor list | refused | refused | refused | — | — | past |
| exec: show security zones | refused | refused | refused | — | — | refused |
| pager s | no pager | no pager | no pager | no pager | no pager | no pager |
| scp /config/juniper.conf.gz | refused | — | — | refused | — | refused |

### Verdict against the control

| probe | P | H | O |
|---|---|---|---|
| show security p49-none | deny | deny | deny |
| sh sec p49-none | deny | deny | deny |
| monitor p49-none | deny | deny | deny |
| mon p49-none | deny | deny | deny |
| monitor list | deny | deny | deny |
| monitor list \| no-more | deny | deny | deny |
|    monitor   list | reached | reached | reached |
| request mpls p49-none | deny | deny | deny |
| req mpls p49-none | deny | deny | deny |
| request mp p49-none | deny | deny | deny |
| request path-computation-client p49-none | deny | deny | deny |
| req path-computation-client p49-none | deny | deny | deny |
| request security p49-none | deny | deny | deny |
| req sec p49-none | deny | deny | deny |
| request unified-edge p49-none | deny | deny | deny |
| request virtual-chassis p49-none | deny | deny | deny |
| req vir p49-none | deny | deny | deny |
| load dhcp-security-snoop /var/tmp/p49-l68-none | deny | deny | deny |
| save dhcp-security-snoop \| count | deny | deny | deny |
| op url /var/tmp/p49-entry-op.slax | deny | deny | deny |
| op ur /var/tmp/p49-entry-op.slax | deny | deny | deny |
| exec: monitor list | deny | deny | deny |
| exec: show security zones | runs nowhere | runs nowhere | runs nowhere |

### Completion: what view-configuration offers over `view` (C against Vc)

load dhcp-security-snoop, monitor, monitor ethernet, monitor interface, monitor label-switched-path, monitor list, monitor mpls, monitor start, monitor static-lsp, monitor stop, request mpls, request path-computation-client, request security, request unified-edge, request virtual-chassis, save dhcp-security-snoop, show firewall, show log, show policer

### Files under /var/tmp after the rows (`| save`, pager `s`)

```
file list /var/tmp/ breakglass@srx1> file list /var/tmp/    | match p49-l68 
p49-l68-pipe-C
p49-l68-pipe-H
p49-l68-pipe-O
p49-l68-pipe-P

breakglass@srx1> 
```

### P

`   monitor   list`:

```
monitor
              ^
unknown command.
alice01@srx1> monitor   
              ^
unknown command.
alice01@srx1> monitor   
              ^
unknown command.
alice01@srx1> monitor   list
              ^
unknown command.

alice01@srx1> 
```

`MONITOR LIST`:

```
MONITOR
              ^
unknown command.
alice01@srx1> MONITOR   LIST
              ^
unknown command.

alice01@srx1> 
```

`configure`:

```
configure
              ^
unknown command.

alice01@srx1> 
```

`configure private`:

```
configure
              ^
unknown command.
alice01@srx1> configure   private
              ^
unknown command.

alice01@srx1> 
```

`edit`:

```
edit
              ^
unknown command.

alice01@srx1> 
```

`exec: monitor list`:

```

error: unknown command: monitor

```

`exec: show configuration system host-name`:

```
host-name srx1;

```

`exec: show security zones`:

```

error: permission denied: security

```

`file list /config`:

```
file
              ^
unknown command.
alice01@srx1> file   list
              ^
unknown command.
alice01@srx1> filelist   /config
              ^
unknown command.

alice01@srx1> 
```

`file show /config/juniper.conf.gz | count`:

```
file
              ^
unknown command.
alice01@srx1> file   show
              ^
unknown command.
alice01@srx1> fileshow   /config/juniper.conf.gz
              ^
unknown command.
alice01@srx1> fileshow/config/juniper.conf.gz   |
              ^
unknown command.
alice01@srx1> fileshow/config/juniper.conf.gz|   count
              ^
unknown command.

alice01@srx1> 
```

`load dhcp-security-snoop /var/tmp/p49-l68-none`:

```
load
              ^
unknown command.
alice01@srx1> load   dhcp-security-snoop
              ^
unknown command.
alice01@srx1> loaddhcp-security-snoop   /var/tmp/p49-l68-none
              ^
unknown command.

alice01@srx1> 
```

`mon p49-none`:

```
mon
              ^
unknown command.
alice01@srx1> mon   p49-none
              ^
unknown command.

alice01@srx1> 
```

`monitor list`:

```
monitor
              ^
unknown command.
alice01@srx1> monitor   list
              ^
unknown command.

alice01@srx1> 
```

`monitor list | no-more`:

```
monitor
              ^
unknown command.
alice01@srx1> monitor   list
              ^
unknown command.
alice01@srx1> monitorlist   |
              ^
unknown command.
alice01@srx1> monitorlist|   no-more
              ^
unknown command.

alice01@srx1> 
```

`monitor p49-none`:

```
monitor
              ^
unknown command.
alice01@srx1> monitor   p49-none
              ^
unknown command.

alice01@srx1> 
```

`op ur /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice01@srx1> op   ur
              ^
unknown command.
alice01@srx1> opur   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice01@srx1> 
```

`op url /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice01@srx1> op   url
              ^
unknown command.
alice01@srx1> opurl   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice01@srx1> 
```

`pager s`:

```
set
              ^
unknown command.
alice01@srx1> set   cli
              ^
unknown command.
alice01@srx1> setcli   screen-length
              ^
unknown command.
alice01@srx1> setcliscreen-length   5
              ^
unknown command.

alice01@srx1> show configuration 
## Last commit: 2026-10-16 08:16:09 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
    root-authentication {
        encrypted-password /* SECRET-DATA */; ## SECRET-DATA
… (193 more lines)
```

`req mpls p49-none`:

```
req
              ^
unknown command.
alice01@srx1> req   mpls
              ^
unknown command.
alice01@srx1> reqmpls   p49-none
              ^
unknown command.

alice01@srx1> 
```

`req path-computation-client p49-none`:

```
req
              ^
unknown command.
alice01@srx1> req   path-computation-client
              ^
unknown command.
alice01@srx1> reqpath-computation-client   p49-none
              ^
unknown command.

alice01@srx1> 
```

`req sec p49-none`:

```
req
              ^
unknown command.
alice01@srx1> req   sec
              ^
unknown command.
alice01@srx1> reqsec   p49-none
              ^
unknown command.

alice01@srx1> 
```

`req vir p49-none`:

```
req
              ^
unknown command.
alice01@srx1> req   vir
              ^
unknown command.
alice01@srx1> reqvir   p49-none
              ^
unknown command.

alice01@srx1> 
```

`request mp p49-none`:

```
request
              ^
unknown command.
alice01@srx1> request   mp
              ^
unknown command.
alice01@srx1> requestmp   p49-none
              ^
unknown command.

alice01@srx1> 
```

`request mpls p49-none`:

```
request
              ^
unknown command.
alice01@srx1> request   mpls
              ^
unknown command.
alice01@srx1> requestmpls   p49-none
              ^
unknown command.

alice01@srx1> 
```

`request path-computation-client p49-none`:

```
request
              ^
unknown command.
alice01@srx1> request   path-computation-client
              ^
unknown command.
alice01@srx1> requestpath-computation-client   p49-none
              ^
unknown command.

alice01@srx1> 
```

`request security p49-none`:

```
request
              ^
unknown command.
alice01@srx1> request   security
              ^
unknown command.
alice01@srx1> requestsecurity   p49-none
              ^
unknown command.

alice01@srx1> 
```

`request unified-edge p49-none`:

```
request
              ^
unknown command.
alice01@srx1> request   unified-edge
              ^
unknown command.
alice01@srx1> requestunified-edge   p49-none
              ^
unknown command.

alice01@srx1> 
```

`request virtual-chassis p49-none`:

```
request
              ^
unknown command.
alice01@srx1> request   virtual-chassis
              ^
unknown command.
alice01@srx1> requestvirtual-chassis   p49-none
              ^
unknown command.

alice01@srx1> 
```

`save dhcp-security-snoop | count`:

```
save
              ^
unknown command.
alice01@srx1> save   dhcp-security-snoop
              ^
unknown command.
alice01@srx1> savedhcp-security-snoop   |
              ^
unknown command.
alice01@srx1> savedhcp-security-snoop|   count
              ^
unknown command.

alice01@srx1> 
```

`scp /config/juniper.conf.gz`:

```
0 bytes; err scp refused: scp: /config/juniper.conf.gz: Permission denied 
```

`sh conf sys host-name`:

```
show configuration system host-name 
host-name srx1;

alice01@srx1> 
```

`sh sec p49-none`:

```
show sec
                   ^
syntax error, expecting <command>.
alice01@srx1> show sec   p49-none
                   ^
syntax error, expecting <command>.

alice01@srx1> 
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice01' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice01@srx1> 
```

`show configuration system host-name`:

```
show configuration system host-name 
host-name srx1;

alice01@srx1> 
```

`show configuration system host-name | display set`:

```
show configuration system host-name | display set 
set system host-name srx1

alice01@srx1> 
```

`show firewall | no-more`:

```
show firewall | no-more 

Filter: __default_bpdu_filter__                                

alice01@srx1> 
```

`show log messages | count`:

```
show log messages | count 
Count: 1 lines

alice01@srx1> 
```

`show policer | no-more`:

```
show policer | no-more 
Policers:
Name                                                                            Bytes              Packets
__default_arp_policer__                                                             0                    0
__policer_tmpl__-term                                                               0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc4                                                                0                    0
… (23 more lines)
```

`show security p49-none`:

```
show security
                   ^
syntax error, expecting <command>.
alice01@srx1> show security   p49-none
                   ^
syntax error, expecting <command>.

alice01@srx1> 
```

`| save`:

```
show configuration system host-name | save /var/tmp/p49-l68-pipe-P 
Wrote 1 line of output to '/var/tmp/p49-l68-pipe-P'

alice01@srx1> 
```

### H

`   monitor   list`:

```
monitor
              ^
unknown command.
alice04@srx1> monitor   
              ^
unknown command.
alice04@srx1> monitor   
              ^
unknown command.
alice04@srx1> monitor   list
              ^
unknown command.

alice04@srx1> 
```

`MONITOR LIST`:

```
MONITOR
              ^
unknown command.
alice04@srx1> MONITOR   LIST
              ^
unknown command.

alice04@srx1> 
```

`configure`:

```
configure
              ^
unknown command.

alice04@srx1> 
```

`configure private`:

```
configure
              ^
unknown command.
alice04@srx1> configure   private
              ^
unknown command.

alice04@srx1> 
```

`edit`:

```
edit
              ^
unknown command.

alice04@srx1> 
```

`exec: monitor list`:

```

error: unknown command: monitor

```

`exec: show configuration system host-name`:

```
host-name srx1;

```

`exec: show security zones`:

```

error: permission denied: security

```

`file list /config`:

```
file list /config 

/config:
db_ext
juniper.conf.1.gz
juniper.conf.2.gz
juniper.conf.gz
license/
ssh_host_ec_p384_key
ssh_host_ec_p384_key.pub
ssh_host_ec_p521_key
ssh_host_ec_p521_key.pub
ssh_host_ecdsa_key
ssh_host_ecdsa_key.pub
ssh_host_ed25519_key
ssh_host_ed25519_key.pub
ssh_host_rsa_key
ssh_host_rsa_key.pub
vchassis/

… (1 more lines)
```

`file show /config/juniper.conf.gz | count`:

```
file show /config/juniper.conf.gz | count 
Count: 1 lines

alice04@srx1> 
```

`load dhcp-security-snoop /var/tmp/p49-l68-none`:

```
load dhcp-security-snoop
                   ^
syntax error, expecting <command>.
alice04@srx1> load dhcp-security-snoop   /var/tmp/p49-l68-none
                   ^
syntax error, expecting <command>.

alice04@srx1> 
```

`mon p49-none`:

```
mon
              ^
unknown command.
alice04@srx1> mon   p49-none
              ^
unknown command.

alice04@srx1> 
```

`monitor list`:

```
monitor
              ^
unknown command.
alice04@srx1> monitor   list
              ^
unknown command.

alice04@srx1> 
```

`monitor list | no-more`:

```
monitor
              ^
unknown command.
alice04@srx1> monitor   list
              ^
unknown command.
alice04@srx1> monitorlist   |
              ^
unknown command.
alice04@srx1> monitorlist|   no-more
              ^
unknown command.

alice04@srx1> 
```

`monitor p49-none`:

```
monitor
              ^
unknown command.
alice04@srx1> monitor   p49-none
              ^
unknown command.

alice04@srx1> 
```

`op ur /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice04@srx1> op   ur
              ^
unknown command.
alice04@srx1> opur   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice04@srx1> 
```

`op url /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice04@srx1> op   url
              ^
unknown command.
alice04@srx1> opurl   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice04@srx1> 
```

`pager s`:

```
set cli screen-length 5 
Screen length set to 5

alice04@srx1> show configuration 
## Last commit: 2026-10-16 08:16:09 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
---(more)---                                        Filename: et cli screen-length 0
Wrote 184 lines of output to 'et cli screen-length 0'
---(more 2%)---
```

`req mpls p49-none`:

```
request mpls
                      ^
syntax error, expecting <command>.
alice04@srx1> request mpls   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`req path-computation-client p49-none`:

```
request path-computation-client
                      ^
syntax error, expecting <command>.
alice04@srx1> request path-computation-client   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`req sec p49-none`:

```
request sec
                      ^
syntax error, expecting <command>.
alice04@srx1> request sec   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`req vir p49-none`:

```
request vir
                         ^
syntax error.
alice04@srx1> request vir   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`request mp p49-none`:

```
request mp
                      ^
syntax error, expecting <command>.
alice04@srx1> request mp   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`request mpls p49-none`:

```
request mpls
                      ^
syntax error, expecting <command>.
alice04@srx1> request mpls   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`request path-computation-client p49-none`:

```
request path-computation-client
                      ^
syntax error, expecting <command>.
alice04@srx1> request path-computation-client   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`request security p49-none`:

```
request security
                      ^
syntax error, expecting <command>.
alice04@srx1> request security   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`request unified-edge p49-none`:

```
request unified-edge
                      ^
syntax error, expecting <command>.
alice04@srx1> request unified-edge   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`request virtual-chassis p49-none`:

```
request virtual-chassis
                      ^
syntax error, expecting <command>.
alice04@srx1> request virtual-chassis   p49-none
                      ^
syntax error, expecting <command>.

alice04@srx1> 
```

`save dhcp-security-snoop | count`:

```
save dhcp-security-snoop
                   ^
syntax error, expecting <command>.
alice04@srx1> save dhcp-security-snoop   |
                   ^
permission denied.
alice04@srx1> save dhcp-security-snoop|   count
                   ^
permission denied.

alice04@srx1> 
```

`sh conf sys host-name`:

```
show configuration system host-name 
host-name srx1;

alice04@srx1> 
```

`sh sec p49-none`:

```
show sec
                   ^
syntax error, expecting <command>.
alice04@srx1> show sec   p49-none
                   ^
syntax error, expecting <command>.

alice04@srx1> 
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice04' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +security( .*)? *(\|.*)?| *(monitor|junoscript|op)( .*)? *(\|.*)?| *request +(mpls|path-computation-client|security|unified-edge|virtual-chassis)( .*)? *(\|.*)?| *(load|save) +dhcp-security-snoop( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice04@srx1> 
```

`show configuration system host-name`:

```
show configuration system host-name 
host-name srx1;

alice04@srx1> 
```

`show configuration system host-name | display set`:

```
show configuration system host-name | display set 
set system host-name srx1

alice04@srx1> 
```

`show firewall | no-more`:

```
show firewall | no-more 

Filter: __default_bpdu_filter__                                

alice04@srx1> 
```

`show log messages | count`:

```
show log messages | count 
Count: 1 lines

alice04@srx1> 
```

`show policer | no-more`:

```
show policer | no-more 
Policers:
Name                                                                            Bytes              Packets
__default_arp_policer__                                                             0                    0
__policer_tmpl__-term                                                               0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc4                                                                0                    0
… (23 more lines)
```

`show security p49-none`:

```
show security
                   ^
syntax error, expecting <command>.
alice04@srx1> show security   p49-none
                   ^
syntax error, expecting <command>.

alice04@srx1> 
```

`| save`:

```
show configuration system host-name | save /var/tmp/p49-l68-pipe-H 
Wrote 1 line of output to '/var/tmp/p49-l68-pipe-H'

alice04@srx1> 
```

### O

`   monitor   list`:

```
monitor
              ^
unknown command.
alice06@srx1> monitor   
              ^
unknown command.
alice06@srx1> monitor   
              ^
unknown command.
alice06@srx1> monitor   list
              ^
unknown command.

alice06@srx1> 
```

`MONITOR LIST`:

```
MONITOR
              ^
unknown command.
alice06@srx1> MONITOR   LIST
              ^
unknown command.

alice06@srx1> 
```

`configure`:

```
configure
              ^
unknown command.

alice06@srx1> 
```

`configure private`:

```
configure
              ^
unknown command.
alice06@srx1> configure   private
              ^
unknown command.

alice06@srx1> 
```

`edit`:

```
edit
              ^
unknown command.

alice06@srx1> 
```

`exec: monitor list`:

```

error: unknown command: monitor

```

`exec: show configuration system host-name`:

```
host-name srx1;

```

`exec: show security zones`:

```

error: permission denied: security

```

`file list /config`:

```
file
              ^
unknown command.
alice06@srx1> file   list
              ^
unknown command.
alice06@srx1> filelist   /config
              ^
unknown command.

alice06@srx1> 
```

`file show /config/juniper.conf.gz | count`:

```
file
              ^
unknown command.
alice06@srx1> file   show
              ^
unknown command.
alice06@srx1> fileshow   /config/juniper.conf.gz
              ^
unknown command.
alice06@srx1> fileshow/config/juniper.conf.gz   |
              ^
unknown command.
alice06@srx1> fileshow/config/juniper.conf.gz|   count
              ^
unknown command.

alice06@srx1> 
```

`load dhcp-security-snoop /var/tmp/p49-l68-none`:

```
load
              ^
unknown command.
alice06@srx1> load   dhcp-security-snoop
              ^
unknown command.
alice06@srx1> loaddhcp-security-snoop   /var/tmp/p49-l68-none
              ^
unknown command.

alice06@srx1> 
```

`mon p49-none`:

```
mon
              ^
unknown command.
alice06@srx1> mon   p49-none
              ^
unknown command.

alice06@srx1> 
```

`monitor list`:

```
monitor
              ^
unknown command.
alice06@srx1> monitor   list
              ^
unknown command.

alice06@srx1> 
```

`monitor list | no-more`:

```
monitor
              ^
unknown command.
alice06@srx1> monitor   list
              ^
unknown command.
alice06@srx1> monitorlist   |
              ^
unknown command.
alice06@srx1> monitorlist|   no-more
              ^
unknown command.

alice06@srx1> 
```

`monitor p49-none`:

```
monitor
              ^
unknown command.
alice06@srx1> monitor   p49-none
              ^
unknown command.

alice06@srx1> 
```

`op ur /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice06@srx1> op   ur
              ^
unknown command.
alice06@srx1> opur   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice06@srx1> 
```

`op url /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice06@srx1> op   url
              ^
unknown command.
alice06@srx1> opurl   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice06@srx1> 
```

`pager s`:

```
set
              ^
unknown command.
alice06@srx1> set   cli
              ^
unknown command.
alice06@srx1> setcli   screen-length
              ^
unknown command.
alice06@srx1> setcliscreen-length   5
              ^
unknown command.

alice06@srx1> show configuration 
## Last commit: 2026-10-16 08:16:09 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
    root-authentication {
        encrypted-password /* SECRET-DATA */; ## SECRET-DATA
… (193 more lines)
```

`req mpls p49-none`:

```
req
              ^
unknown command.
alice06@srx1> req   mpls
              ^
unknown command.
alice06@srx1> reqmpls   p49-none
              ^
unknown command.

alice06@srx1> 
```

`req path-computation-client p49-none`:

```
req
              ^
unknown command.
alice06@srx1> req   path-computation-client
              ^
unknown command.
alice06@srx1> reqpath-computation-client   p49-none
              ^
unknown command.

alice06@srx1> 
```

`req sec p49-none`:

```
req
              ^
unknown command.
alice06@srx1> req   sec
              ^
unknown command.
alice06@srx1> reqsec   p49-none
              ^
unknown command.

alice06@srx1> 
```

`req vir p49-none`:

```
req
              ^
unknown command.
alice06@srx1> req   vir
              ^
unknown command.
alice06@srx1> reqvir   p49-none
              ^
unknown command.

alice06@srx1> 
```

`request mp p49-none`:

```
request
              ^
unknown command.
alice06@srx1> request   mp
              ^
unknown command.
alice06@srx1> requestmp   p49-none
              ^
unknown command.

alice06@srx1> 
```

`request mpls p49-none`:

```
request
              ^
unknown command.
alice06@srx1> request   mpls
              ^
unknown command.
alice06@srx1> requestmpls   p49-none
              ^
unknown command.

alice06@srx1> 
```

`request path-computation-client p49-none`:

```
request
              ^
unknown command.
alice06@srx1> request   path-computation-client
              ^
unknown command.
alice06@srx1> requestpath-computation-client   p49-none
              ^
unknown command.

alice06@srx1> 
```

`request security p49-none`:

```
request
              ^
unknown command.
alice06@srx1> request   security
              ^
unknown command.
alice06@srx1> requestsecurity   p49-none
              ^
unknown command.

alice06@srx1> 
```

`request unified-edge p49-none`:

```
request
              ^
unknown command.
alice06@srx1> request   unified-edge
              ^
unknown command.
alice06@srx1> requestunified-edge   p49-none
              ^
unknown command.

alice06@srx1> 
```

`request virtual-chassis p49-none`:

```
request
              ^
unknown command.
alice06@srx1> request   virtual-chassis
              ^
unknown command.
alice06@srx1> requestvirtual-chassis   p49-none
              ^
unknown command.

alice06@srx1> 
```

`save dhcp-security-snoop | count`:

```
save
              ^
unknown command.
alice06@srx1> save   dhcp-security-snoop
              ^
unknown command.
alice06@srx1> savedhcp-security-snoop   |
              ^
unknown command.
alice06@srx1> savedhcp-security-snoop|   count
              ^
unknown command.

alice06@srx1> 
```

`sh conf sys host-name`:

```
show configuration system host-name 
host-name srx1;

alice06@srx1> 
```

`sh sec p49-none`:

```
show sec
                   ^
syntax error, expecting <command>.
alice06@srx1> show sec   p49-none
                   ^
syntax error, expecting <command>.

alice06@srx1> 
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice06' class 'p49-remote'
Permissions:
    clear       -- Can clear learned network info
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice06@srx1> 
```

`show configuration system host-name`:

```
show configuration system host-name 
host-name srx1;

alice06@srx1> 
```

`show configuration system host-name | display set`:

```
show configuration system host-name | display set 
set system host-name srx1

alice06@srx1> 
```

`show firewall | no-more`:

```
show firewall | no-more 

Filter: __default_bpdu_filter__                                

alice06@srx1> 
```

`show log messages | count`:

```
show log messages | count 
Count: 1 lines

alice06@srx1> 
```

`show policer | no-more`:

```
show policer | no-more 
Policers:
Name                                                                            Bytes              Packets
__default_arp_policer__                                                             0                    0
__policer_tmpl__-term                                                               0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc4                                                                0                    0
… (23 more lines)
```

`show security p49-none`:

```
show security
                   ^
syntax error, expecting <command>.
alice06@srx1> show security   p49-none
                   ^
syntax error, expecting <command>.

alice06@srx1> 
```

`| save`:

```
show configuration system host-name | save /var/tmp/p49-l68-pipe-O 
Wrote 1 line of output to '/var/tmp/p49-l68-pipe-O'

alice06@srx1> 
```

### V

`   monitor   list`:

```
monitor
              ^
unknown command.
alice08@srx1> monitor   
              ^
unknown command.
alice08@srx1> monitor   
              ^
unknown command.
alice08@srx1> monitor   list
              ^
unknown command.

alice08@srx1> 
```

`MONITOR LIST`:

```
MONITOR
              ^
unknown command.
alice08@srx1> MONITOR   LIST
              ^
unknown command.

alice08@srx1> 
```

`configure`:

```
configure
              ^
unknown command.

alice08@srx1> 
```

`configure private`:

```
configure
              ^
unknown command.
alice08@srx1> configure   private
              ^
unknown command.

alice08@srx1> 
```

`edit`:

```
edit
              ^
unknown command.

alice08@srx1> 
```

`file list /config`:

```
file
              ^
unknown command.
alice08@srx1> file   list
              ^
unknown command.
alice08@srx1> filelist   /config
              ^
unknown command.

alice08@srx1> 
```

`file show /config/juniper.conf.gz | count`:

```
file
              ^
unknown command.
alice08@srx1> file   show
              ^
unknown command.
alice08@srx1> fileshow   /config/juniper.conf.gz
              ^
unknown command.
alice08@srx1> fileshow/config/juniper.conf.gz   |
              ^
unknown command.
alice08@srx1> fileshow/config/juniper.conf.gz|   count
              ^
unknown command.

alice08@srx1> 
```

`load dhcp-security-snoop /var/tmp/p49-l68-none`:

```
load
              ^
unknown command.
alice08@srx1> load   dhcp-security-snoop
              ^
unknown command.
alice08@srx1> loaddhcp-security-snoop   /var/tmp/p49-l68-none
              ^
unknown command.

alice08@srx1> 
```

`mon p49-none`:

```
mon
              ^
unknown command.
alice08@srx1> mon   p49-none
              ^
unknown command.

alice08@srx1> 
```

`monitor list`:

```
monitor
              ^
unknown command.
alice08@srx1> monitor   list
              ^
unknown command.

alice08@srx1> 
```

`monitor list | no-more`:

```
monitor
              ^
unknown command.
alice08@srx1> monitor   list
              ^
unknown command.
alice08@srx1> monitorlist   |
              ^
unknown command.
alice08@srx1> monitorlist|   no-more
              ^
unknown command.

alice08@srx1> 
```

`monitor p49-none`:

```
monitor
              ^
unknown command.
alice08@srx1> monitor   p49-none
              ^
unknown command.

alice08@srx1> 
```

`op ur /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice08@srx1> op   ur
              ^
unknown command.
alice08@srx1> opur   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice08@srx1> 
```

`op url /var/tmp/p49-entry-op.slax`:

```
op
              ^
unknown command.
alice08@srx1> op   url
              ^
unknown command.
alice08@srx1> opurl   /var/tmp/p49-entry-op.slax
              ^
unknown command.

alice08@srx1> 
```

`pager s`:

```
set
              ^
unknown command.
alice08@srx1> set   cli
              ^
unknown command.
alice08@srx1> setcli   screen-length
              ^
unknown command.
alice08@srx1> setcliscreen-length   5
              ^
unknown command.

alice08@srx1> show configuration 
## Last commit: 2026-10-16 08:16:09 UTC by breakglass

alice08@srx1> set
              ^
unknown command.
alice08@srx1> set   cli
… (10 more lines)
```

`req mpls p49-none`:

```
req
              ^
unknown command.
alice08@srx1> req   mpls
              ^
unknown command.
alice08@srx1> reqmpls   p49-none
              ^
unknown command.

alice08@srx1> 
```

`req path-computation-client p49-none`:

```
req
              ^
unknown command.
alice08@srx1> req   path-computation-client
              ^
unknown command.
alice08@srx1> reqpath-computation-client   p49-none
              ^
unknown command.

alice08@srx1> 
```

`req sec p49-none`:

```
req
              ^
unknown command.
alice08@srx1> req   sec
              ^
unknown command.
alice08@srx1> reqsec   p49-none
              ^
unknown command.

alice08@srx1> 
```

`req vir p49-none`:

```
req
              ^
unknown command.
alice08@srx1> req   vir
              ^
unknown command.
alice08@srx1> reqvir   p49-none
              ^
unknown command.

alice08@srx1> 
```

`request mp p49-none`:

```
request
              ^
unknown command.
alice08@srx1> request   mp
              ^
unknown command.
alice08@srx1> requestmp   p49-none
              ^
unknown command.

alice08@srx1> 
```

`request mpls p49-none`:

```
request
              ^
unknown command.
alice08@srx1> request   mpls
              ^
unknown command.
alice08@srx1> requestmpls   p49-none
              ^
unknown command.

alice08@srx1> 
```

`request path-computation-client p49-none`:

```
request
              ^
unknown command.
alice08@srx1> request   path-computation-client
              ^
unknown command.
alice08@srx1> requestpath-computation-client   p49-none
              ^
unknown command.

alice08@srx1> 
```

`request security p49-none`:

```
request
              ^
unknown command.
alice08@srx1> request   security
              ^
unknown command.
alice08@srx1> requestsecurity   p49-none
              ^
unknown command.

alice08@srx1> 
```

`request unified-edge p49-none`:

```
request
              ^
unknown command.
alice08@srx1> request   unified-edge
              ^
unknown command.
alice08@srx1> requestunified-edge   p49-none
              ^
unknown command.

alice08@srx1> 
```

`request virtual-chassis p49-none`:

```
request
              ^
unknown command.
alice08@srx1> request   virtual-chassis
              ^
unknown command.
alice08@srx1> requestvirtual-chassis   p49-none
              ^
unknown command.

alice08@srx1> 
```

`save dhcp-security-snoop | count`:

```
save
              ^
unknown command.
alice08@srx1> save   dhcp-security-snoop
              ^
unknown command.
alice08@srx1> savedhcp-security-snoop   |
              ^
unknown command.
alice08@srx1> savedhcp-security-snoop|   count
              ^
unknown command.

alice08@srx1> 
```

`scp /config/juniper.conf.gz`:

```
0 bytes; err scp refused: scp: /config/juniper.conf.gz: Permission denied 
```

`sh conf sys host-name`:

```
show configuration sys
                                 ^
syntax error.
alice08@srx1> show configuration sys   host-name
                                 ^
syntax error.

alice08@srx1> 
```

`sh sec p49-none`:

```
show sec
                   ^
syntax error, expecting <command>.
alice08@srx1> show sec   p49-none
                   ^
syntax error, expecting <command>.

alice08@srx1> 
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice08' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice08@srx1> 
```

`show configuration system host-name`:

```
show configuration system
                                 ^
syntax error.
alice08@srx1> show configuration system   host-name
                                 ^
syntax error.

alice08@srx1> 
```

`show configuration system host-name | display set`:

```
show configuration system
                                 ^
syntax error.
alice08@srx1> show configuration system   host-name
                                 ^
syntax error.
alice08@srx1> show configuration systemhost-name   |
                                 ^
syntax error.
alice08@srx1> show configuration systemhost-name|   display
                                 ^
syntax error.
alice08@srx1> show configuration systemhost-name|display   set
                                 ^
syntax error.

alice08@srx1> 
```

`show firewall | no-more`:

```
show firewall
                           ^
syntax error.
alice08@srx1> show firewall   |
                   ^
permission denied.
alice08@srx1> show firewall|   no-more
                   ^
permission denied.

alice08@srx1> 
```

`show log messages | count`:

```
show log
                   ^
syntax error, expecting <command>.
alice08@srx1> show log   messages
                   ^
syntax error, expecting <command>.
alice08@srx1> show logmessages   |
                   ^
syntax error, expecting <command>.
alice08@srx1> show logmessages|   count
                   ^
syntax error, expecting <command>.

alice08@srx1> 
```

`show policer | no-more`:

```
show policer
                   ^
syntax error, expecting <command>.
alice08@srx1> show policer   |
                   ^
permission denied.
alice08@srx1> show policer|   no-more
                   ^
permission denied.

alice08@srx1> 
```

`show security p49-none`:

```
show security
                   ^
syntax error, expecting <command>.
alice08@srx1> show security   p49-none
                   ^
syntax error, expecting <command>.

alice08@srx1> 
```

`| save`:

```
show configuration system
                                 ^
syntax error.
alice08@srx1> show configuration system   host-name
                                 ^
syntax error.
alice08@srx1> show configuration systemhost-name   |
                                 ^
syntax error.
alice08@srx1> show configuration systemhost-name|   save
                                 ^
syntax error.
alice08@srx1> show configuration systemhost-name|save   /var/tmp/p49-l68-pipe-V
                                 ^
syntax error.

alice08@srx1> 
```

### Vc

`   monitor   list`:

```
monitor
              ^
unknown command.
alice10@srx1> monitor   
              ^
unknown command.
alice10@srx1> monitor   
              ^
unknown command.
alice10@srx1> monitor   list
              ^
unknown command.

alice10@srx1> 
```

`MONITOR LIST`:

```
MONITOR
              ^
unknown command.
alice10@srx1> MONITOR   LIST
              ^
unknown command.

alice10@srx1> 
```

`configure`:

```
configure
              ^
unknown command.

alice10@srx1> 
```

`configure private`:

```
configure
              ^
unknown command.
alice10@srx1> configure   private
              ^
unknown command.

alice10@srx1> 
```

`edit`:

```
edit
              ^
unknown command.

alice10@srx1> 
```

`file list /config`:

```
file list /config 

/config:
db_ext
juniper.conf.1.gz
juniper.conf.2.gz
juniper.conf.gz
license/
ssh_host_ec_p384_key
ssh_host_ec_p384_key.pub
ssh_host_ec_p521_key
ssh_host_ec_p521_key.pub
ssh_host_ecdsa_key
ssh_host_ecdsa_key.pub
ssh_host_ed25519_key
ssh_host_ed25519_key.pub
ssh_host_rsa_key
ssh_host_rsa_key.pub
vchassis/

… (1 more lines)
```

`file show /config/juniper.conf.gz | count`:

```
file show /config/juniper.conf.gz | count 
Count: 1 lines

alice10@srx1> 
```

`load dhcp-security-snoop /var/tmp/p49-l68-none`:

```
load dhcp-security-snoop
                   ^
syntax error, expecting <command>.
alice10@srx1> load dhcp-security-snoop   /var/tmp/p49-l68-none
                   ^
syntax error, expecting <command>.

alice10@srx1> 
```

`mon p49-none`:

```
mon
              ^
unknown command.
alice10@srx1> mon   p49-none
              ^
unknown command.

alice10@srx1> 
```

`monitor list`:

```
monitor
              ^
unknown command.
alice10@srx1> monitor   list
              ^
unknown command.

alice10@srx1> 
```

`monitor list | no-more`:

```
monitor
              ^
unknown command.
alice10@srx1> monitor   list
              ^
unknown command.
alice10@srx1> monitorlist   |
              ^
unknown command.
alice10@srx1> monitorlist|   no-more
              ^
unknown command.

alice10@srx1> 
```

`monitor p49-none`:

```
monitor
              ^
unknown command.
alice10@srx1> monitor   p49-none
              ^
unknown command.

alice10@srx1> 
```

`op ur /var/tmp/p49-entry-op.slax`:

```
op url /var/tmp/p49-entry-op.slax 
P49OP-VERSION srx1
P49OP-CONFIG 0

alice10@srx1> 
```

`op url /var/tmp/p49-entry-op.slax`:

```
op url /var/tmp/p49-entry-op.slax 
P49OP-VERSION srx1
P49OP-CONFIG 0

alice10@srx1> 
```

`pager s`:

```
set cli screen-length 5 
Screen length set to 5

alice10@srx1> show configuration 
## Last commit: 2026-10-16 08:16:09 UTC by breakglass
version /* ACCESS-DENIED */;
system { /* ACCESS-DENIED */ };
chassis { /* ACCESS-DENIED */ };
---(more)---                                        Filename: et cli screen-length 0
Wrote 6 lines of output to 'et cli screen-length 0'
---(more 66%)---
```

`req mpls p49-none`:

```
request mpls
                      ^
syntax error, expecting <command>.
alice10@srx1> request mpls   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`req path-computation-client p49-none`:

```
request path-computation-client
                      ^
syntax error, expecting <command>.
alice10@srx1> request path-computation-client   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`req sec p49-none`:

```
request sec
                      ^
syntax error, expecting <command>.
alice10@srx1> request sec   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`req vir p49-none`:

```
request vir
                         ^
syntax error.
alice10@srx1> request vir   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`request mp p49-none`:

```
request mp
                      ^
syntax error, expecting <command>.
alice10@srx1> request mp   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`request mpls p49-none`:

```
request mpls
                      ^
syntax error, expecting <command>.
alice10@srx1> request mpls   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`request path-computation-client p49-none`:

```
request path-computation-client
                      ^
syntax error, expecting <command>.
alice10@srx1> request path-computation-client   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`request security p49-none`:

```
request security
                      ^
syntax error, expecting <command>.
alice10@srx1> request security   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`request unified-edge p49-none`:

```
request unified-edge
                      ^
syntax error, expecting <command>.
alice10@srx1> request unified-edge   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`request virtual-chassis p49-none`:

```
request virtual-chassis
                      ^
syntax error, expecting <command>.
alice10@srx1> request virtual-chassis   p49-none
                      ^
syntax error, expecting <command>.

alice10@srx1> 
```

`save dhcp-security-snoop | count`:

```
save dhcp-security-snoop
                   ^
syntax error, expecting <command>.
alice10@srx1> save dhcp-security-snoop   |
                   ^
permission denied.
alice10@srx1> save dhcp-security-snoop|   count
                   ^
permission denied.

alice10@srx1> 
```

`sh conf sys host-name`:

```
show configuration sys
                                 ^
syntax error.
alice10@srx1> show configuration sys   host-name
                                 ^
syntax error.

alice10@srx1> 
```

`sh sec p49-none`:

```
show security p49-none
                            ^
syntax error, expecting <command>.

alice10@srx1> 
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice10' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice10@srx1> 
```

`show configuration system host-name`:

```
show configuration system
                                 ^
syntax error.
alice10@srx1> show configuration system   host-name
                                 ^
syntax error.

alice10@srx1> 
```

`show configuration system host-name | display set`:

```
show configuration system
                                 ^
syntax error.
alice10@srx1> show configuration system   host-name
                                 ^
syntax error.
alice10@srx1> show configuration systemhost-name   |
                                 ^
syntax error.
alice10@srx1> show configuration systemhost-name|   display
                                 ^
syntax error.
alice10@srx1> show configuration systemhost-name|display   set
                                 ^
syntax error.

alice10@srx1> 
```

`show firewall | no-more`:

```
show firewall
                           ^
syntax error.
alice10@srx1> show firewall   |
                   ^
permission denied.
alice10@srx1> show firewall|   no-more
                   ^
permission denied.

alice10@srx1> 
```

`show log messages | count`:

```
show log
                   ^
syntax error, expecting <command>.
alice10@srx1> show log   messages
                   ^
syntax error, expecting <command>.
alice10@srx1> show logmessages   |
                   ^
syntax error, expecting <command>.
alice10@srx1> show logmessages|   count
                   ^
syntax error, expecting <command>.

alice10@srx1> 
```

`show policer | no-more`:

```
show policer
                   ^
syntax error, expecting <command>.
alice10@srx1> show policer   |
                   ^
permission denied.
alice10@srx1> show policer|   no-more
                   ^
permission denied.

alice10@srx1> 
```

`show security p49-none`:

```
show security p49-none
                            ^
syntax error, expecting <command>.

alice10@srx1> 
```

`| save`:

```
alice10@srx1>        show configuration system
                                 ^
syntax error.
alice10@srx1> show configuration system   host-name
                                 ^
syntax error.
alice10@srx1> show configuration systemhost-name   |
                                 ^
syntax error.
alice10@srx1> show configuration systemhost-name|   save
                                 ^
syntax error.
alice10@srx1> show configuration systemhost-name|save   /var/tmp/p49-l68-pipe-Vc
                                 ^
syntax error.

alice10@srx1> 
```

### C

`   monitor   list`:

```
monitor list 
No monitored files

alice11@srx1> 
```

`MONITOR LIST`:

```
MONITOR
              ^
unknown command.
alice11@srx1> MONITOR   LIST
              ^
unknown command.

alice11@srx1> 
```

`configure`:

```
configure
              ^
unknown command.

alice11@srx1> 
```

`configure private`:

```
configure
              ^
unknown command.
alice11@srx1> configure   private
              ^
unknown command.

alice11@srx1> 
```

`edit`:

```
edit
              ^
unknown command.

alice11@srx1> 
```

`exec: monitor list`:

```
No monitored files

```

`exec: show configuration system host-name`:

```
host-name srx1;

```

`exec: show security zones`:

```

error: syntax error, expecting <command>: zones

```

`file list /config`:

```
file list /config 

/config:
db_ext
juniper.conf.1.gz
juniper.conf.2.gz
juniper.conf.gz
license/
ssh_host_ec_p384_key
ssh_host_ec_p384_key.pub
ssh_host_ec_p521_key
ssh_host_ec_p521_key.pub
ssh_host_ecdsa_key
ssh_host_ecdsa_key.pub
ssh_host_ed25519_key
ssh_host_ed25519_key.pub
ssh_host_rsa_key
ssh_host_rsa_key.pub
vchassis/

… (1 more lines)
```

`file show /config/juniper.conf.gz | count`:

```
file show /config/juniper.conf.gz | count 
Count: 1 lines

alice11@srx1> 
```

`load dhcp-security-snoop /var/tmp/p49-l68-none`:

```
load dhcp-security-snoop /var/tmp/p49-l68-none 
warning: dhcp-service subsystem not running - not needed by configuration.

alice11@srx1> 
```

`mon p49-none`:

```
monitor p49-none
                      ^
syntax error, expecting <command>.

alice11@srx1> 
```

`monitor list`:

```
monitor list 
No monitored files

alice11@srx1> 
```

`monitor list | no-more`:

```
monitor list | no-more 
No monitored files

alice11@srx1> 
```

`monitor p49-none`:

```
monitor p49-none
                      ^
syntax error, expecting <command>.

alice11@srx1> 
```

`op ur /var/tmp/p49-entry-op.slax`:

```
op url /var/tmp/p49-entry-op.slax 
P49OP-VERSION srx1
P49OP-CONFIG 1

alice11@srx1> 
```

`op url /var/tmp/p49-entry-op.slax`:

```
op url /var/tmp/p49-entry-op.slax 
P49OP-VERSION srx1
P49OP-CONFIG 1

alice11@srx1> 
```

`pager s`:

```
set cli screen-length 5 
Screen length set to 5

alice11@srx1> show configuration 
## Last commit: 2026-10-16 08:16:09 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
---(more)---                                        Filename: et cli screen-length 0
Wrote 186 lines of output to 'et cli screen-length 0'
---(more 2%)---
```

`req mpls p49-none`:

```
request mpls p49-none
                           ^
syntax error, expecting <command>.

alice11@srx1> 
```

`req path-computation-client p49-none`:

```
request path-computation-client p49-none
                                              ^
syntax error, expecting <command>.

alice11@srx1> 
```

`req sec p49-none`:

```
request security p49-none
                               ^
syntax error, expecting <command>.

alice11@srx1> 
```

`req vir p49-none`:

```
request virtual-chassis p49-none
                                      ^
syntax error, expecting <command>.

alice11@srx1> 
```

`request mp p49-none`:

```
request mpls p49-none
                           ^
syntax error, expecting <command>.

alice11@srx1> 
```

`request mpls p49-none`:

```
request mpls p49-none
                           ^
syntax error, expecting <command>.

alice11@srx1> 
```

`request path-computation-client p49-none`:

```
request path-computation-client p49-none
                                              ^
syntax error, expecting <command>.

alice11@srx1> 
```

`request security p49-none`:

```
request security p49-none
                               ^
syntax error, expecting <command>.

alice11@srx1> 
```

`request unified-edge p49-none`:

```
request unified-edge p49-none
                                   ^
syntax error, expecting <command>.

alice11@srx1> 
```

`request virtual-chassis p49-none`:

```
request virtual-chassis p49-none
                                      ^
syntax error, expecting <command>.

alice11@srx1> 
```

`save dhcp-security-snoop | count`:

```
save dhcp-security-snoop | count
                                         ^
syntax error.

alice11@srx1> 
```

`scp /config/juniper.conf.gz`:

```
0 bytes; err scp refused: scp: /config/juniper.conf.gz: Permission denied 
```

`sh conf sys host-name`:

```
show configuration system host-name 
host-name srx1;

alice11@srx1> 
```

`sh sec p49-none`:

```
show security p49-none
                            ^
syntax error, expecting <command>.

alice11@srx1> 
```

`show cli authorization`:

```
 
Current user: 'remote' login: 'alice11' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice11@srx1> 
```

`show configuration system host-name`:

```
show configuration system host-name 
host-name srx1;

alice11@srx1> 
```

`show configuration system host-name | display set`:

```
show configuration system host-name | display set 
set system host-name srx1

alice11@srx1> 
```

`show firewall | no-more`:

```
show firewall | no-more 

Filter: __default_bpdu_filter__                                

alice11@srx1> 
```

`show log messages | count`:

```
show log messages | count 
Count: 1 lines

alice11@srx1> 
```

`show policer | no-more`:

```
show policer | no-more 
Policers:
Name                                                                            Bytes              Packets
__default_arp_policer__                                                             0                    0
__policer_tmpl__-term                                                               0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc0                                                                0                    0
__policer_tmpl__-fc1                                                                0                    0
__policer_tmpl__-fc2                                                                0                    0
__policer_tmpl__-fc3                                                                0                    0
__policer_tmpl__-fc4                                                                0                    0
… (23 more lines)
```

`show security p49-none`:

```
show security p49-none
                            ^
syntax error, expecting <command>.

alice11@srx1> 
```

`| save`:

```
alice11@srx1>        show configuration system host-name | save /var/tmp/p49-l68-pipe-C 
Wrote 1 line of output to '/var/tmp/p49-l68-pipe-C'

alice11@srx1> 
```

