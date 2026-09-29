# L12-projection — juniper_vjunos-router

- **Date measured:** 2026-09-29
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/projection-juniper_vjunos-router.pcap` — 7858 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/projection-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Decisions 22 and 26's projection, differentially: for each rule shape the generator produces, what the device runs under the reply port49 renders, typed as an operator might type it — abbreviated, in upper case, piped — compared with port49's own decision on the command as the device expands it: never more; and, for a composition the projection cannot carry, that the subject gets the fail-closed reply and the device is not quarantined (spec §8, "Verification"; §13 decisions 22 and 26; §15 L9, L12).

## Observation

The reference configuration applied, as `port49 platform export --classes` prints it for set 1.1.0 with a 12h max_session_age:

```
set system tacplus-options strict-authorization
delete system login class p49-remote
set system login class p49-remote idle-timeout 720
delete system login user remote
set system login user remote class p49-remote
```

The binary's JunosFacts: {CaseSensitive:false DenyMatchesExpanded:true DenyBindsRPCs:false}.

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
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:52260->172.100.100.21:830: read: connection reset by peer`

### readonly, a deny aligned with a bit

Reply `deny-commands=^.*$` (fail_closed, refused_shape). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | permit | refuses | refuses | no |
| `sh int ter` | `show interfaces terse` | permit | refuses | refuses | no |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `sh conf sys host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show configuration system host-name | display set` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | permit | refuses | refuses | no |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:58372->172.100.100.21:830: read: connection reset by peer`

### a permit beneath a deny

Reply `deny-commands=^.*$` (fail_closed, refused_shape). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | permit | refuses | refuses | no |
| `sh int ter` | `show interfaces terse` | permit | refuses | refuses | no |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `sh conf sys host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | refuses | refuses | no |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | permit | refuses | refuses | no |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:45350->172.100.100.21:830: read: connection reset by peer`

### an exact deny

Reply `deny-commands=^.*$` (fail_closed, refused_shape). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | deny | refuses | refuses | yes |
| `sh int ter` | `show interfaces terse` | deny | refuses | refuses | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | deny | refuses | refuses | yes |
| `show interfaces terse | no-more` | `show interfaces terse` | deny | refuses | refuses | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `sh conf sys host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | refuses | refuses | no |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | permit | refuses | refuses | no |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:45188->172.100.100.21:830: read: connection reset by peer`

### narrow

Reply `user-permissions=view`, `deny-commands=^.*$`, `allow-commands=^(show interfaces( .*)?|show version)$` (narrow). `show cli authorization`:

```
show cli
                   ^
syntax error, expecting <command>.
slice01@srx1> show cli   authorization
                   ^
syntax error, expecting <command>.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | deny | refuses | refuses | yes |
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
| `show route summary` | `show route summary` | deny | refuses | refuses | yes |
| `show route protocol static` | `show route protocol static` | deny | refuses | refuses | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | deny | refuses | refuses | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:60726->172.100.100.21:830: read: connection reset by peer`

### a class term

Reply `deny-commands=^.*$` (fail_closed, argument_deny). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | permit | refuses | refuses | no |
| `sh int ter` | `show interfaces terse` | permit | refuses | refuses | no |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | deny | refuses | refuses | yes |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `sh conf sys host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | refuses | refuses | no |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | permit | refuses | refuses | no |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:45464->172.100.100.21:830: read: connection reset by peer`

### a permit beyond the bits

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
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | permit | refuses | refuses | no |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:48668->172.100.100.21:830: read: connection reset by peer`

### operator

Reply `user-permissions=clear network view view-configuration`, `deny-commands=^.*$`, `allow-commands=^(clear( .*)?|ping( .*)?|show( .*)?)$` (narrow). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
Permissions:
    clear       -- Can clear learned network info
    network     -- Can access the network
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: (^(clear( .*)?|ping( .*)?|show( .*)?)$)
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
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | permit | runs | runs | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | permit | runs | runs | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:54844->172.100.100.21:830: read: connection reset by peer`

### admin

Reply `user-permissions=all` (capability). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
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
| `request system reboot` | `request system reboot` | permit | runs | runs | yes |
| `restart routing` | `restart routing` | permit | runs | runs | yes |
| `configure` | `configure` | permit | runs | runs | yes |
| `edit` | `edit` | permit | runs | runs | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:58426->172.100.100.21:830: read: connection reset by peer`

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
| `request system reboot` | `request system reboot` | permit | runs | refuses | no |
| `restart routing` | `restart routing` | permit | refuses | refuses | no |
| `configure` | `configure` | permit | refuses | refuses | no |
| `edit` | `edit` | permit | refuses | refuses | no |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:58000->172.100.100.21:830: read: connection reset by peer`

### operator, a capability with a keyword deny

Reply `user-permissions=clear network trace view view-configuration`, `deny-commands=^ *restart( .*)? *(\|.*)?$` (capability). `show cli authorization`:

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
    Deny regular expression: (^ *restart( .*)? *(\|.*)?$)
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
| `request system reboot` | `request system reboot` | permit | runs | refuses | no |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | permit | refuses | refuses | no |
| `edit` | `edit` | permit | refuses | refuses | no |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:60610->172.100.100.21:830: read: connection reset by peer`

### operator, a capability with a keyword deny and allows

Reply `user-permissions=clear trace view view-configuration`, `deny-commands=^ *restart( .*)? *(\|.*)?$`, `allow-commands=^(mtrace( .*)?|ping( .*)?|ssh( .*)?|telnet( .*)?|traceroute( .*)?)$` (capability). `show cli authorization`:

```
 
Current user: 'remote' login: 'slice01' class 'p49-remote'
Permissions:
    clear       -- Can clear learned network info
    trace       -- Can view trace file settings
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: (^(mtrace( .*)?|ping( .*)?|ssh( .*)?|telnet( .*)?|traceroute( .*)?)$)
    Deny regular expression: (^ *restart( .*)? *(\|.*)?$)
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
| `request system reboot` | `request system reboot` | permit | runs | refuses | no |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:51568->172.100.100.21:830: read: connection reset by peer`

### operator, a capability with two keyword denies

Reply `user-permissions=clear network trace view view-configuration`, `deny-commands=^( *configure( .*)? *(\|.*)?| *restart( .*)? *(\|.*)?)$` (capability). `show cli authorization`:

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
    Deny regular expression: (^( *configure( .*)? *(\|.*)?| *restart( .*)? *(\|.*)?)$)
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
| `request system reboot` | `request system reboot` | permit | runs | refuses | no |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | permit | refuses | refuses | no |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:42728->172.100.100.21:830: read: connection reset by peer`

### admin with a deny

Reply `deny-commands=^.*$` (fail_closed, argument_deny). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | permit | refuses | refuses | no |
| `sh int ter` | `show interfaces terse` | permit | refuses | refuses | no |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `sh conf sys host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | refuses | refuses | no |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | permit | refuses | refuses | no |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | permit | refuses | refuses | no |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | permit | refuses | refuses | no |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | permit | refuses | refuses | no |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | permit | refuses | refuses | no |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | permit | refuses | refuses | no |
| `configure` | `configure` | permit | refuses | refuses | no |
| `edit` | `edit` | permit | refuses | refuses | no |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:56792->172.100.100.21:830: read: connection reset by peer`

### admin keeping a keyword deny

Reply `deny-commands=^.*$` (fail_closed, refused_shape). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | permit | refuses | refuses | no |
| `sh int ter` | `show interfaces terse` | permit | refuses | refuses | no |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `sh conf sys host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show configuration system host-name | display set` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | permit | refuses | refuses | no |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | permit | refuses | refuses | no |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | permit | refuses | refuses | no |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | permit | refuses | refuses | no |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | permit | refuses | refuses | no |
| `request system reboot` | `request system reboot` | permit | refuses | refuses | no |
| `restart routing` | `restart routing` | permit | refuses | refuses | no |
| `configure` | `configure` | permit | refuses | refuses | no |
| `edit` | `edit` | permit | refuses | refuses | no |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:60884->172.100.100.21:830: read: connection reset by peer`

### the refused shape

Reply `user-permissions=view`, `deny-commands=^.*$`, `allow-commands=^show version$` (fail_closed, refused_shape). `show cli authorization`:

```
show cli
                   ^
syntax error, expecting <command>.
slice01@srx1> show cli   authorization
                   ^
syntax error, expecting <command>.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | deny | refuses | refuses | yes |
| `show interfaces terse` | `show interfaces terse` | deny | refuses | refuses | yes |
| `sh int ter` | `show interfaces terse` | deny | refuses | refuses | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | deny | refuses | refuses | yes |
| `show interfaces terse | no-more` | `show interfaces terse` | deny | refuses | refuses | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `sh conf sys host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show configuration system host-name | display set` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show route summary` | `show route summary` | deny | refuses | refuses | yes |
| `show route protocol static` | `show route protocol static` | deny | refuses | refuses | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | deny | refuses | refuses | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:43132->172.100.100.21:830: read: connection reset by peer`

### a deny naming an argument

Reply `deny-commands=^.*$` (fail_closed, argument_deny). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | permit | refuses | refuses | no |
| `sh int ter` | `show interfaces terse` | permit | refuses | refuses | no |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | deny | refuses | refuses | yes |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `sh conf sys host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | refuses | refuses | no |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | permit | refuses | refuses | no |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:46022->172.100.100.21:830: read: connection reset by peer`

### an allow naming an argument

Reply `user-permissions=view`, `deny-commands=^.*$`, `allow-commands=^show version$` (narrow). `show cli authorization`:

```
show cli
                   ^
syntax error, expecting <command>.
slice01@srx1> show cli   authorization
                   ^
syntax error, expecting <command>.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | runs | runs | yes |
| `show system uptime` | `show system uptime` | deny | refuses | refuses | yes |
| `show interfaces terse` | `show interfaces terse` | deny | refuses | refuses | yes |
| `sh int ter` | `show interfaces terse` | deny | refuses | refuses | yes |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | deny | refuses | refuses | yes |
| `show interfaces terse | no-more` | `show interfaces terse` | deny | refuses | refuses | yes |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | deny | refuses | refuses | yes |
| `show configuration system host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `sh conf sys host-name` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show configuration system host-name | display set` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `   show configuration system host-name   ` | `show configuration system host-name` | deny | refuses | refuses | yes |
| `show route summary` | `show route summary` | deny | refuses | refuses | yes |
| `show route protocol static` | `show route protocol static` | deny | refuses | refuses | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | deny | refuses | refuses | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:44272->172.100.100.21:830: read: connection reset by peer`

### a deny naming an enumerated value

Reply `deny-commands=^.*$` (fail_closed, argument_deny). `show cli authorization`:

```
show
              ^
unknown command.
slice01@srx1> show   cli
              ^
unknown command.
slice01@srx1> showcli   authorization
              ^
unknown command.

slice01@srx1> 
```

| typed | port49 on | port49 | projection predicts | device | agrees |
|---|---|---|---|---|---|
| `show version` | `show version` | permit | refuses | refuses | no |
| `show system uptime` | `show system uptime` | permit | refuses | refuses | no |
| `show interfaces terse` | `show interfaces terse` | permit | refuses | refuses | no |
| `sh int ter` | `show interfaces terse` | permit | refuses | refuses | no |
| `SHOW INTERFACES TERSE` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces terse | no-more` | `show interfaces terse` | permit | refuses | refuses | no |
| `show interfaces fxp0 terse` | `show interfaces fxp0 terse` | permit | refuses | refuses | no |
| `show interfaces lo0 terse` | `show interfaces lo0 terse` | permit | refuses | refuses | no |
| `show configuration system host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `sh conf sys host-name` | `show configuration system host-name` | permit | refuses | refuses | no |
| `SHOW CONFIGURATION SYSTEM HOST-NAME` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show configuration system host-name | display set` | `show configuration system host-name` | permit | refuses | refuses | no |
| `   show configuration system host-name   ` | `show configuration system host-name` | permit | refuses | refuses | no |
| `show route summary` | `show route summary` | permit | refuses | refuses | no |
| `show route protocol static` | `show route protocol static` | deny | refuses | refuses | yes |
| `clear interfaces statistics fxp0` | `clear interfaces statistics fxp0` | deny | refuses | refuses | yes |
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | deny | refuses | refuses | yes |
| `sh ver` | `show version` | permit | refuses | refuses | no |
| `SHOW VERSION` | `show version` | permit | refuses | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | refuses | refuses | no |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:33924->172.100.100.21:830: read: connection reset by peer`

### a deny of a value under a command with no RPC

Reply `user-permissions=view view-configuration`, `deny-commands=^.*$`, `allow-commands=^show( .*)?$` (fail_closed, argument_deny). `show cli authorization`:

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
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:44116->172.100.100.21:830: read: connection reset by peer`

### a deny of a value under an incomplete command

Reply `user-permissions=view view-configuration`, `deny-commands=^.*$`, `allow-commands=^show( .*)?$` (fail_closed, argument_deny). `show cli authorization`:

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
| `ping 127.0.0.1 count 1 rapid` | `ping 127.0.0.1 count 1 rapid` | permit | refuses | refuses | no |
| `sh ver` | `show version` | permit | runs | runs | yes |
| `SHOW VERSION` | `show version` | permit | runs | refuses | no |
| `set cli screen-width 200` | `set cli screen-width 200` | deny | refuses | refuses | yes |
| `show cli` | `show cli` | permit | runs | runs | yes |
| `file list /var/tmp` | `file list /var/tmp` | deny | refuses | refuses | yes |
| `request system reboot` | `request system reboot` | deny | refuses | refuses | yes |
| `restart routing` | `restart routing` | deny | refuses | refuses | yes |
| `configure` | `configure` | deny | refuses | refuses | yes |
| `edit` | `edit` | deny | refuses | refuses | yes |

NETCONF is disabled, as set 1.1.0 requires: `SSH to the NETCONF port 830: ssh: handshake failed: read tcp 172.100.100.1:57140->172.100.100.21:830: read: connection reset by peer`

### the commit checker (L9)

| attribute | regex | commit | read back |
|---|---|---|---|
| `deny-commands` | `^.*$` | accepted | `set system login class p49-l9-commit deny-commands "^.*$"` |
| `allow-commands` | `^show( .*)?$` | accepted | `set system login class p49-l9-commit allow-commands "^show( .*)?$"` |
| `allow-commands` | `^(show interfaces( .*)?\|show version)$` | accepted | `set system login class p49-l9-commit allow-commands "^(show interfaces( .*)?\|show version)$"` |
| `allow-commands` | `^(clear( .*)?\|ping( .*)?\|show( .*)?)$` | accepted | `set system login class p49-l9-commit allow-commands "^(clear( .*)?\|ping( .*)?\|show( .*)?)$"` |
| `deny-commands` | `^ *restart( .*)? *(\\|.*)?$` | accepted | `set system login class p49-l9-commit deny-commands "^ *restart( .*)? *(\\|.*)?$"` |
| `allow-commands` | `^(mtrace( .*)?\|ping( .*)?\|ssh( .*)?\|telnet( .*)?\|traceroute( .*)?)$` | accepted | `set system login class p49-l9-commit allow-commands "^(mtrace( .*)?\|ping( .*)?\|ssh( .*)?\|telnet( .*)?\|traceroute( .*)?)$"` |
| `deny-commands` | `^( *configure( .*)? *(\\|.*)?\| *restart( .*)? *(\\|.*)?)$` | accepted | `set system login class p49-l9-commit deny-commands "^( *configure( .*)? *(\\|.*)?\| *restart( .*)? *(\\|.*)?)$"` |
| `allow-commands` | `^show version$` | accepted | `set system login class p49-l9-commit allow-commands "^show version$"` |
| `deny-commands` | `^ *show +version *(\\|.*)?$` | accepted | `set system login class p49-l9-commit deny-commands "^ *show +version *(\\|.*)?$"` |
| `deny-commands` | `^( *restart( .*)? *(\\|.*)?\| *show +version *(\\|.*)?)$` | accepted | `set system login class p49-l9-commit deny-commands "^( *restart( .*)? *(\\|.*)?\| *show +version *(\\|.*)?)$"` |

