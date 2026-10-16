# L68-projected — juniper_vjunos-router

- **Date measured:** 2026-10-16
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L68-projected-juniper_vjunos-router.pcap` — 6869 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L68-projected-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `4aa55dea6f8524f71c1e198928e35bd2ce6c55a7`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestProjectionDifferential$`

## Claim

Set 1.3.0's projection end to end (plan 9g Task 6; L68): for each shape, the reply port49 renders, the readonly and the operator denying `show security` sent view-configuration with `monitor **` denied (decision 48), what the CLI runs and refuses, `show configuration` running where it is sent, and the XML entries and NETCONF under port49's rendered reply (spec §15 L68).

## Observation

The reference configuration applied, as `port49 platform export --classes` prints it for set 1.3.0 with a 12h max_session_age:

```
set system tacplus-options strict-authorization
delete system login class p49-remote
set system login class p49-remote idle-timeout 720
delete system login user remote
set system login user remote class p49-remote
```

The binary's JunosFacts: {CaseSensitive:false DenyMatchesExpanded:true DenyBindsRPCs:false AllowPastCarve:map[show configuration **:false show firewall **:true show log **:true show policer **:true]}.

### readonly denying show security

Reply `user-permissions=view view-configuration`, `deny-commands=^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$` (capability). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | permit | runs | runs | yes |
| `show interfaces terse` | `show interfaces terse` | permit | runs | runs | yes |
| `sh int ter` | `show interfaces terse` | permit | runs | runs | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | runs | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | runs | runs | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | runs | runs | yes |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | runs | runs | yes |
| `show configuration system host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `sh conf sys host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | runs | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | runs | runs | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | runs | runs | yes |
| `show route summary` | `show route summary` | permit | runs | runs | yes |
| `show route protocol static` | `show route protocol static` | permit | runs | runs | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `op url /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `op ur /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `show security zones | no-more` | `show security zones` | deny | refuses | refuses | yes |
| `show security policies | no-more` | `show security policies` | deny | refuses | refuses | yes |
| `show log messages | count` | `show log messages` | permit | runs | runs | yes |
| `show firewall | no-more` | `show firewall` | permit | runs | runs | yes |
| `show policer | no-more` | `show policer` | permit | runs | runs | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |
| `monitor list` | `monitor list` | deny | refuses | refuses | yes |
| `mon list` | `monitor list` | deny | refuses | refuses | yes |
| `monitor list | no-more` | `monitor list` | deny | refuses | refuses | yes |

reading: `SHOW INTERFACES TERSE`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW CONFIGURATION SYSTEM HOST-NAME`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW VERSION`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

| CLI entry | cell |
|---|---|
| `xml-mode` | refused |
| `xml-mode netconf need-trailer` | refused |

Rendered `deny-commands=` (the regex the `xml-mode` cells above are typed under): `^( *show +security( .*)? *(\\|.*)?\| *(monitor\|help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\|.*)?\| *set +cli( .*)? *(\\|.*)?)$`

NETCONF on port 830 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF`

NETCONF on port 22 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF`

### operator denying show security

Reply `user-permissions=clear view view-configuration`, `deny-commands=^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$` (capability). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
Permissions:
    clear       -- Can clear learned network info
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: (^( *show +security( .*)? *(\|.*)?| *(monitor|help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | permit | runs | runs | yes |
| `show interfaces terse` | `show interfaces terse` | permit | runs | runs | yes |
| `sh int ter` | `show interfaces terse` | permit | runs | runs | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | runs | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | runs | runs | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | runs | runs | yes |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | runs | runs | yes |
| `show configuration system host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `sh conf sys host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | runs | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | runs | runs | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | runs | runs | yes |
| `show route summary` | `show route summary` | permit | runs | runs | yes |
| `show route protocol static` | `show route protocol static` | permit | runs | runs | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | permit | runs | runs | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `op url /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `op ur /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `show security zones | no-more` | `show security zones` | deny | refuses | refuses | yes |
| `show security policies | no-more` | `show security policies` | deny | refuses | refuses | yes |
| `show log messages | count` | `show log messages` | permit | runs | runs | yes |
| `show firewall | no-more` | `show firewall` | permit | runs | runs | yes |
| `show policer | no-more` | `show policer` | permit | runs | runs | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |
| `monitor list` | `monitor list` | deny | refuses | refuses | yes |
| `mon list` | `monitor list` | deny | refuses | refuses | yes |
| `monitor list | no-more` | `monitor list` | deny | refuses | refuses | yes |

reading: `SHOW INTERFACES TERSE`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW CONFIGURATION SYSTEM HOST-NAME`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW VERSION`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

| CLI entry | cell |
|---|---|
| `xml-mode netconf need-trailer` | refused |

NETCONF on port 830 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF`

NETCONF on port 22 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF`

### readonly denying show configuration

Reply `user-permissions=view`, `deny-commands=^( *show +configuration( .*)? *(\|.*)?| *(help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$`, `allow-commands=^(show log( .*)?|show firewall( .*)?|show policer( .*)?)$` (capability). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: (^(show log( .*)?|show firewall( .*)?|show policer( .*)?)$)
    Deny regular expression: (^( *show +configuration( .*)? *(\|.*)?| *(help|quit|exit|file|load|op|request|save|scp|set|start|test|junoscript)( .*)? *(\|.*)?| *set +cli( .*)? *(\|.*)?)$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | permit | runs | runs | yes |
| `show interfaces terse` | `show interfaces terse` | permit | runs | runs | yes |
| `sh int ter` | `show interfaces terse` | permit | runs | runs | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | runs | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | runs | runs | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | runs | runs | yes |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | runs | runs | yes |
| `show configuration system host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `sh conf sys host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show configuration system host-name | display set` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show route summary` | `show route summary` | permit | runs | runs | yes |
| `show route protocol static` | `show route protocol static` | permit | runs | runs | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `op url /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `op ur /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `show security zones | no-more` | `show security zones` | permit | runs | refuses | no |
| `show security policies | no-more` | `show security policies` | permit | runs | refuses | no |
| `show log messages | count` | `show log messages` | permit | runs | runs | yes |
| `show firewall | no-more` | `show firewall` | permit | runs | runs | yes |
| `show policer | no-more` | `show policer` | permit | runs | runs | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |
| `monitor list` | `monitor list` | deny | refuses | refuses | yes |
| `mon list` | `monitor list` | deny | refuses | refuses | yes |
| `monitor list | no-more` | `monitor list` | deny | refuses | refuses | yes |

reading: `SHOW INTERFACES TERSE`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW VERSION`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `show security zones | no-more` did not run on this image (a refusal word, or the probe's evidence absent), and port49 permits it: the device is narrower than port49 (or lacks the command), recorded, not a failure.

reading: `show security policies | no-more` did not run on this image (a refusal word, or the probe's evidence absent), and port49 permits it: the device is narrower than port49 (or lacks the command), recorded, not a failure.

| CLI entry | cell |
|---|---|
| `xml-mode` | refused |
| `xml-mode netconf need-trailer` | refused |

Rendered `deny-commands=` (the regex the `xml-mode` cells above are typed under): `^( *show +configuration( .*)? *(\\|.*)?\| *(help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\|.*)?\| *set +cli( .*)? *(\\|.*)?)$`

NETCONF on port 830 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF`

NETCONF on port 22 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode"): the NETCONF channel closed: EOF`

### operator, all it reaches

Reply `user-permissions=clear network trace view view-configuration` (capability). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
Permissions:
    clear       -- Can clear learned network info
    network     -- Can access the network
    trace       -- Can view trace file settings
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | permit | runs | runs | yes |
| `show interfaces terse` | `show interfaces terse` | permit | runs | runs | yes |
| `sh int ter` | `show interfaces terse` | permit | runs | runs | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | runs | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | runs | runs | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | runs | runs | yes |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | runs | runs | yes |
| `show configuration system host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `sh conf sys host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | runs | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | runs | runs | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | runs | runs | yes |
| `show route summary` | `show route summary` | permit | runs | runs | yes |
| `show route protocol static` | `show route protocol static` | permit | runs | runs | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | permit | runs | runs | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | permit | runs | runs | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | permit | runs | runs | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | permit | runs | runs | yes |
| `op url /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | permit | runs | runs | yes |
| `op ur /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | permit | runs | runs | yes |
| `request system reboot` | `request system reboot` | permit | runs | refuses | no |
| `restart routing` | `restart routing` | permit | refuses | refuses | no |
| `show security zones | no-more` | `show security zones` | permit | runs | refuses | no |
| `show security policies | no-more` | `show security policies` | permit | runs | refuses | no |
| `show log messages | count` | `show log messages` | permit | runs | runs | yes |
| `show firewall | no-more` | `show firewall` | permit | runs | runs | yes |
| `show policer | no-more` | `show policer` | permit | runs | runs | yes |
| `configure` | `configure` | permit | refuses | refuses | no |
| `edit` | `edit` | permit | refuses | refuses | no |
| `monitor list` | `monitor list` | permit | runs | runs | yes |
| `mon list` | `monitor list` | permit | runs | runs | yes |
| `monitor list | no-more` | `monitor list` | permit | runs | runs | yes |

reading: `SHOW INTERFACES TERSE`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW CONFIGURATION SYSTEM HOST-NAME`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW VERSION`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `show security zones | no-more` did not run on this image (a refusal word, or the probe's evidence absent), and port49 permits it: the device is narrower than port49 (or lacks the command), recorded, not a failure.

reading: `show security policies | no-more` did not run on this image (a refusal word, or the probe's evidence absent), and port49 permits it: the device is narrower than port49 (or lacks the command), recorded, not a failure.

| CLI entry | cell |
|---|---|
| `xml-mode netconf need-trailer` | hello |

`get-configuration`: result

NETCONF on port 22 opened (control)

NETCONF on port 830 opened (control)

| NETCONF RPC | as the command | port49 | device |
|---|---|---|---|
| `<get-configuration/>` | `show configuration` | permit | ran |
| `<get-configuration><configuration><system/></configuration></get-configuration>` | `show configuration system` | permit | ran |
| `<command>show configuration</command>` | `show configuration` | permit | ran |
| `<get-software-information/>` | `show version` | permit | ran |

### readonly

Reply `user-permissions=view view-configuration`, `deny-commands=^.*$`, `allow-commands=^show( .*)?$` (narrow). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: (^show( .*)?$)
    Deny regular expression: (^.*$)
    Allow configuration regular expression: none
    Deny configuration regular expression: none

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | permit | runs | runs | yes |
| `show interfaces terse` | `show interfaces terse` | permit | runs | runs | yes |
| `sh int ter` | `show interfaces terse` | permit | runs | runs | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | runs | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | runs | runs | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | runs | runs | yes |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | runs | runs | yes |
| `show configuration system host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `sh conf sys host-name` | `show configuration system host-name` | permit | runs | runs | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | runs | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | runs | runs | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | runs | runs | yes |
| `show route summary` | `show route summary` | permit | runs | runs | yes |
| `show route protocol static` | `show route protocol static` | permit | runs | runs | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `op url /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `op ur /var/tmp/p49-entry-op.slax` | `op url /var/tmp/p49-entry-op.slax` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `show security zones | no-more` | `show security zones` | permit | runs | refuses | no |
| `show security policies | no-more` | `show security policies` | permit | runs | refuses | no |
| `show log messages | count` | `show log messages` | permit | runs | runs | yes |
| `show firewall | no-more` | `show firewall` | permit | runs | runs | yes |
| `show policer | no-more` | `show policer` | permit | runs | runs | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |
| `monitor list` | `monitor list` | deny | refuses | refuses | yes |
| `mon list` | `monitor list` | deny | refuses | refuses | yes |
| `monitor list | no-more` | `monitor list` | deny | refuses | refuses | yes |

reading: `SHOW INTERFACES TERSE`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW CONFIGURATION SYSTEM HOST-NAME`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `SHOW VERSION`: Junos's CLI is case-sensitive; the device refuses the uppercase form; recorded, not a failure; see L12-projection.

reading: `show security zones | no-more` did not run on this image (a refusal word, or the probe's evidence absent), and port49 permits it: the device is narrower than port49 (or lacks the command), recorded, not a failure.

reading: `show security policies | no-more` did not run on this image (a refusal word, or the probe's evidence absent), and port49 permits it: the device is narrower than port49 (or lacks the command), recorded, not a failure.

| CLI entry | cell |
|---|---|
| `xml-mode` | refused |
| `xml-mode netconf need-trailer` | refused |

NETCONF on port 830 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode\n\nerror: permission denied: netconf"): the NETCONF channel closed: EOF`

NETCONF on port 22 refused under the rendered reply: `the device sent no NETCONF hello (sent "error: unknown command: xml-mode\n\nerror: permission denied: netconf"): the NETCONF channel closed: EOF`

### the commit checker (L9)

| attribute | regex | commit | read back |
|---|---|---|---|
| `deny-commands` | `^( *show +security( .*)? *(\\|.*)?\| *(monitor\|help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\|.*)?\| *set +cli( .*)? *(\\|.*)?)$` | accepted | `set system login class p49-l9-commit deny-commands "^( *show +security( .*)? *(\\|.*)?\| *(monitor\|help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\|.*)?\| *set +cli( .*)? *(\\|.*)?)$"` |
| `deny-commands` | `^( *show +configuration( .*)? *(\\|.*)?\| *(help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\|.*)?\| *set +cli( .*)? *(\\|.*)?)$` | accepted | `set system login class p49-l9-commit deny-commands "^( *show +configuration( .*)? *(\\|.*)?\| *(help\|quit\|exit\|file\|load\|op\|request\|save\|scp\|set\|start\|test\|junoscript)( .*)? *(\\|.*)?\| *set +cli( .*)? *(\\|.*)?)$"` |
| `allow-commands` | `^(show log( .*)?\|show firewall( .*)?\|show policer( .*)?)$` | accepted | `set system login class p49-l9-commit allow-commands "^(show log( .*)?\|show firewall( .*)?\|show policer( .*)?)$"` |
| `deny-commands` | `^.*$` | accepted | `set system login class p49-l9-commit deny-commands "^.*$"` |
| `allow-commands` | `^show( .*)?$` | accepted | `set system login class p49-l9-commit allow-commands "^show( .*)?$"` |
| `deny-commands` | `^ *show +version *(\\|.*)?$` | accepted | `set system login class p49-l9-commit deny-commands "^ *show +version *(\\|.*)?$"` |
| `deny-commands` | `^( *restart( .*)? *(\\|.*)?\| *show +version *(\\|.*)?)$` | accepted | `set system login class p49-l9-commit deny-commands "^( *restart( .*)? *(\\|.*)?\| *show +version *(\\|.*)?)$"` |

