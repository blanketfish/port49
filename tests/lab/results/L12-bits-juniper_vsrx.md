# L12-bits — juniper_vsrx

- **Date measured:** 2026-11-05
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L12-bits-juniper_vsrx.pcap` — 2418 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L12-bits-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL12JunosBits$`

## Claim

What each permission bit a built-in level's ceiling names reaches, alone in a template's class, over TACACS+ `local-user-name`: every command word, and every word one level under it, its completion offers that a class with no bits does not, held by the adapter's `bits:` reach as an upper bound; what a class with no bits runs (`baseline`); and that `view` alone does not show the configuration, the one carve-out the adapter declares (spec §8, §15 L12).

## Observation

Each row is a session whose template's class holds one bit and nothing else; `none` holds none and `all` every bit. A command word, or a word and the word under it, is the bit's where its completion offers it and `none`'s does not; `none`'s own are the baseline.

| bit | words beyond none | candidate reach | held |
|---|---|---|---|
| baseline | file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request jdaf, request lacp, request modem, request network-access, request protection-group, request services, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dot1x, test l2-learning, test security | `help **`, `quit **`, `exit **`, `set cli **`, `show cli **`, `file **`, `load **`, `op **`, `request **`, `save **`, `scp **`, `set **`, `start **`, `test **` | yes |
| clear | clear, clear amt, clear arp, clear auto-bandwidth, clear auto-configuration, clear bfd, clear bgp, clear captive-portal, clear class-of-service, clear cli, clear database-replication, clear dhcp, clear dhcp-security, clear dhcpv6, clear diameter, clear dot1x, clear dynamic-tunnels, clear error, clear esis, clear ethernet-switching, clear evpn, clear express-segments, clear firewall, clear helper, clear igmp, clear interfaces, clear ipv6, clear isis, clear l2-learning, clear l2circuit, clear ldp, clear lldp, clear loop-detect, clear mac-vrf, clear mld, clear monitor, clear mpls, clear msdp, clear multicast, clear network-access, clear oam, clear ospf, clear ospf3, clear performance-monitoring, clear pfe, clear pim, clear poe, clear ppp, clear pppoe, clear ptp, clear r2cp, clear resource-manager, clear rip, clear ripng, clear rsvp, clear snmp, clear spanning-tree, clear synchronous-ethernet, clear system, clear validation, clear vpls, clear vrrp, request mpls, set chassis | `clear **`, `request mpls **`, `set chassis **` | yes |
| network | mtrace, mtrace from-source, mtrace logical-system, mtrace monitor, mtrace routing-instance, mtrace to-gateway, ping, ping atm, ping bypass-routing, ping ce-ip, ping clns, ping count, ping detail, ping do-not-fragment, ping inet, ping inet6, ping interface, ping interval, ping logical-system, ping mac-address, ping mpls, ping no-resolve, ping overlay, ping pattern, ping rapid, ping record-route, ping routing-instance, ping size, ping source, ping srv6, ping strict, ping tenant, ping tos, ping ttl, ping verbose, ping vpls, ping wait, probe, probe by-address, probe by-index, probe by-name, probe by-remote-address, probe count, probe detail, probe inet, probe inet6, probe interface, probe interval, probe logical-system, probe routing-instance, probe source, probe tenant, probe tos, probe ttl, probe wait, request routing-engine, ssh, ssh bypass-routing, ssh extensive, ssh inet, ssh inet6, ssh interface, ssh logical-system, ssh routing-instance, ssh source, ssh tenant, ssh v2, ssh verbose, telnet, telnet bypass-routing, telnet inet, telnet inet6, telnet interface, telnet logical-system, telnet no-resolve, telnet port, telnet routing-instance, telnet source, telnet tenant, traceroute, traceroute as-number-lookup, traceroute bypass-routing, traceroute ce-ip, traceroute clns, traceroute extension, traceroute gateway, traceroute inet, traceroute inet6, traceroute interface, traceroute logical-system, traceroute monitor, traceroute mpls, traceroute next-hop, traceroute no-resolve, traceroute overlay, traceroute port, traceroute propagate-ttl, traceroute routing-instance, traceroute source, traceroute tenant, traceroute tos, traceroute ttl, traceroute wait | `ping **`, `traceroute **`, `ssh **`, `telnet **`, `mtrace **`, `probe **`, `request routing-engine **` | yes |
| trace | monitor, monitor interface, monitor label-switched-path, monitor list, monitor security, monitor start, monitor static-lsp, monitor stop | `monitor **` | yes |
| view | request flight-recorder, request pppoe, request snmp, request validation, show, show access-cac, show access-security, show accounting, show agent, show app-engine, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show connections, show database-replication, show dhcp, show dhcp-security, show dhcpv6, show dialer, show diameter, show dot1x, show dynamic-tunnels, show ephemeral-configuration, show esis, show ethernet-switching, show event-options, show evpn, show express-segments, show extension-service, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show iccp, show igmp, show ingress-replication, show interfaces, show ipv6, show isdn, show isis, show jdaf, show l2circuit, show l2cpd, show l2vpn, show lacp, show ldp, show lldp, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show modem, show monitor, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show performance-monitoring, show pfe, show pim, show policy, show ppp, show pppoe, show programmable-rpd, show r2cp, show resource-manager, show rip, show ripng, show route, show routing, show rsvp, show sap, show schedulers, show security, show services, show smtp, show snmp, show spanning-tree, show spring-traffic-engineering, show ssl-certificates, show subscribers, show system, show task, show ted, show v4ov6-tunnels, show validation, show version, show vlans, show vpls, show vrrp, test interface, test msdp, test policy, test rib-sharding | `show **`, `request flight-recorder **`, `request pppoe **`, `request snmp **`, `request validation **`, `test interface **`, `test msdp **`, `test policy **`, `test rib-sharding **`, `test services **` | yes |
| view-configuration | monitor, monitor interface, monitor label-switched-path, monitor list, monitor security, monitor start, monitor static-lsp, monitor stop, request mpls, request security | `show configuration **`, `monitor **`, `request mpls **`, `request path-computation-client **`, `request security **`, `request unified-edge **`, `request virtual-chassis **`, `load dhcp-security-snoop **`, `save dhcp-security-snoop **` | yes |

A top-level word is held whole (`request **`, `set **`), not word by word under it: `?` does not list Junos's hidden commands, so a per-word reach could under-report what the device runs. A per-word reach is a possible later refinement, and needs proof, not measured here, that no hidden command sits under each word.

Words `view view-configuration` is offered that `view`, `view-configuration` and `none` are not (a carve-out candidate for view-configuration, by completion only): show firewall, show log, show policer.

| hierarchy probe | `all` shows it | `view` alone: observed and refused | `view` alone shows it | `view-configuration` alone shows it | `view view-configuration` shows it | isolated |
|---|---|---|---|---|---|---|
| `show configuration system host-name` | true | true | false | false | true | yes |
| `show configuration routing-instances` | true | true | false | false | true | yes |
| `show configuration interfaces` | true | true | false | false | true | yes |

The adapter's carve-out `view-configuration: [show configuration **]` holds only if `view` alone shows none of them; it was measured on 3 hierarchies the `all` control shows. Bare `show configuration` under `view` alone: not probed.

| probe | none | all | clear | network | trace | view | view-configuration | view+view-configuration |
|---|---|---|---|---|---|---|---|---|
| `show version` | refused | ran | refused | refused | refused | ran | refused | ran |
| `show system uptime` | refused | ran | refused | refused | refused | ran | refused | ran |
| `clear interfaces statistics fxp0` | refused | ran | ran | refused | refused | refused | refused | refused |
| `ping 127.0.0.1 count 1 rapid` | refused | ran | refused | ran | refused | refused | refused | refused |
| `traceroute 127.0.0.1 ttl 1 wait 1` | refused | ran | refused | ran | refused | refused | refused | refused |
| `monitor interface` | absent | completes | absent | absent | completes | absent | completes | completes |
| `request system reboot` | absent | completes | absent | absent | absent | absent | absent | absent |
| `restart routing` | absent | completes | absent | absent | absent | absent | absent | absent |
| `show configuration system host-name` | refused | ran | refused | refused | refused | refused | refused | ran |
| `show configuration routing-instances` | refused | ran | refused | refused | refused | refused | refused | ran |
| `show configuration interfaces` | refused | ran | refused | refused | refused | refused | refused | ran |
| `help tip cli` | ran | ran | ran | ran | ran | ran | ran | ran |
| `show cli` | refused | ran | refused | refused | refused | ran | refused | ran |
| `set cli screen-width 200` | ran | ran | ran | ran | ran | ran | ran | ran |
| `file list /var/tmp` | ran | ran | ran | ran | ran | ran | ran | ran |
| `configure` | refused | ran | refused | refused | refused | refused | refused | refused |
| `exit configuration-mode` | refused | ran | refused | refused | refused | refused | refused | refused |

Classes other than `all` that entered configuration mode (`configure` ran): no class.

| baseline command | none | none + deny .* |
|---|---|---|
| `help tip cli` | ran | refused |
| `show cli` | refused | not comparable (the control did not run it) |
| `set cli screen-width 200` | ran | refused |
| `file list /var/tmp` | ran | refused |
| `quit` | closed the session | prompt back: ^ unknown command. alice10@srx1> |
| `exit` | closed the session | prompt back: ^ unknown command. alice10@srx1> |

The reach as measured, ready for `bits:` and `carve_outs:`:

```yaml
    bits:
      baseline: ["help **", "quit **", "exit **", "set cli **", "show cli **", "file **", "load **", "op **", "request **", "save **", "scp **", "set **", "start **", "test **"]
      clear: ["clear **", "request mpls **", "set chassis **"]
      network: ["ping **", "traceroute **", "ssh **", "telnet **", "mtrace **", "probe **", "request routing-engine **"]
      trace: ["monitor **"]
      view: ["show **", "request flight-recorder **", "request pppoe **", "request snmp **", "request validation **", "test interface **", "test msdp **", "test policy **", "test rib-sharding **", "test services **"]
      view-configuration: ["show configuration **", "monitor **", "request mpls **", "request path-computation-client **", "request security **", "request unified-edge **", "request virtual-chassis **", "load dhcp-security-snoop **", "save dhcp-security-snoop **"]
      all: ["**"]
    carve_outs:
      view-configuration: ["show configuration **"]
```

### none

Reply `["local-user-name=p49-l12-b-none"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice01@srx1> show   cli
              ^
unknown command.
alice01@srx1> showcli   authorization
              ^
unknown command.

alice01@srx1> 
```

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request jdaf, request lacp, request modem, request network-access, request protection-group, request services, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dot1x, test l2-learning, test security

Raw `?`:

```
?
Possible completions:
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  op                   Invoke an operation script
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  start                Start shell
  test                 Perform diagnostic debugging
alice01@srx1>    
```

Raw `request ?`:

```
alice01@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  network-access       Request network-access related information
  protection-group     Request protection group related operations
  services             Request service options
alice01@srx1> request    
```

Raw `test ?`:

```
alice01@srx1>         test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  l2-learning          Layer 2 forwarding commands
  security             Security related tests
alice01@srx1> test    
```

Raw `set ?`:

```
alice01@srx1>       set ?
Possible completions:
  cli                  Set CLI properties
alice01@srx1> set    
```

`show version`:

```
show
              ^
unknown command.
alice01@srx1> show   version
              ^
unknown command.

alice01@srx1> 
```

`show system uptime`:

```
show
              ^
unknown command.
alice01@srx1> show   system
              ^
unknown command.
alice01@srx1> showsystem   uptime
              ^
unknown command.

alice01@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice01@srx1> clear   interfaces
              ^
unknown command.
alice01@srx1> clearinterfaces   statistics
              ^
unknown command.
alice01@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice01@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice01@srx1> ping   127.0.0.1
              ^
unknown command.
alice01@srx1> ping127.0.0.1   count
              ^
unknown command.
alice01@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice01@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice01@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
traceroute
              ^
unknown command.
alice01@srx1> traceroute   127.0.0.1
              ^
unknown command.
alice01@srx1> traceroute127.0.0.1   ttl
              ^
unknown command.
alice01@srx1> traceroute127.0.0.1ttl   1
              ^
unknown command.
alice01@srx1> traceroute127.0.0.1ttl1   wait
              ^
unknown command.
alice01@srx1> traceroute127.0.0.1ttl1wait   1
              ^
unknown command.

alice01@srx1> 
```

`monitor interface`:

```
monitor
              ^
unknown command.
alice01@srx1> monitor   ?
No valid completions
alice01@srx1> monitor   
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice01@srx1> request system   ?
No valid completions
alice01@srx1> request system   
```

`restart routing`:

```
restart
              ^
unknown command.
alice01@srx1> restart   ?
No valid completions
alice01@srx1> restart   
```

`show configuration system host-name`:

```
show
              ^
unknown command.
alice01@srx1> show   configuration
              ^
unknown command.
alice01@srx1> showconfiguration   system
              ^
unknown command.
alice01@srx1> showconfigurationsystem   host-name
              ^
unknown command.

alice01@srx1> 
```

`show configuration routing-instances`:

```
show
              ^
unknown command.
alice01@srx1> show   configuration
              ^
unknown command.
alice01@srx1> showconfiguration   routing-instances
              ^
unknown command.

alice01@srx1> 
```

`show configuration interfaces`:

```
show
              ^
unknown command.
alice01@srx1> show   configuration
              ^
unknown command.
alice01@srx1> showconfiguration   interfaces
              ^
unknown command.

alice01@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
In configuration mode, use the 'copy' command to replicate
configuration statements.

alice01@srx1> 
```

`show cli`:

```
show
              ^
unknown command.
alice01@srx1> show   cli
              ^
unknown command.

alice01@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice01@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice01@srx1> 
```

`configure`:

```
              ^
unknown command.

alice01@srx1> 
```

`exit configuration-mode`:

```
                   ^
syntax error, expecting <command>.

alice01@srx1> 
```

`quit`: closed the session

### all

Reply `["local-user-name=p49-l12-b-all"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-b-all' login: 'alice02' class 'p49-l12-b-all'
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

alice02@srx1> 
```

Completion: clear, clear amt, clear arp, clear auto-bandwidth, clear auto-configuration, clear bfd, clear bgp, clear captive-portal, clear chassis, clear class-of-service, clear cli, clear database-replication, clear dhcp, clear dhcp-security, clear dhcpv6, clear diameter, clear dot1x, clear dynamic-tunnels, clear error, clear esis, clear ethernet-switching, clear evpn, clear express-segments, clear extension-service, clear firewall, clear helper, clear igmp, clear interfaces, clear ipv6, clear isdn, clear isis, clear l2-learning, clear l2circuit, clear lacp, clear ldp, clear lldp, clear log, clear loop-detect, clear mac-vrf, clear mld, clear monitor, clear mpls, clear msdp, clear multicast, clear network-access, clear oam, clear ospf, clear ospf3, clear passive-monitoring, clear performance-monitoring, clear pfe, clear pim, clear poe, clear ppp, clear pppoe, clear ptp, clear r2cp, clear resource-manager, clear rip, clear ripng, clear rsvp, clear security, clear services, clear snmp, clear spanning-tree, clear synchronous-ethernet, clear system, clear validation, clear vpls, clear vrrp, configure, configure batch, configure dynamic, configure exclusive, configure private, file, file archive, file change-owner, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, monitor, monitor interface, monitor label-switched-path, monitor list, monitor security, monitor start, monitor static-lsp, monitor stop, monitor traffic, mtrace, mtrace from-source, mtrace logical-system, mtrace monitor, mtrace routing-instance, mtrace to-gateway, op, op invoke-debugger, op url, ping, ping atm, ping bypass-routing, ping ce-ip, ping clns, ping count, ping detail, ping do-not-fragment, ping inet, ping inet6, ping interface, ping interval, ping logical-system, ping mac-address, ping mpls, ping no-resolve, ping overlay, ping pattern, ping rapid, ping record-route, ping routing-instance, ping size, ping source, ping srv6, ping strict, ping tenant, ping tos, ping ttl, ping verbose, ping vpls, ping wait, probe, probe by-address, probe by-index, probe by-name, probe by-remote-address, probe count, probe detail, probe inet, probe inet6, probe interface, probe interval, probe logical-system, probe routing-instance, probe source, probe tenant, probe tos, probe ttl, probe wait, quit, request, request access-security, request auto-configuration, request chassis, request debug, request dhcp, request dhcpv6, request extension-service, request flight-recorder, request interface, request jdaf, request jnu, request l2circuit-switchover, request lacp, request message, request modem, request mpls, request network-access, request pim, request pppoe, request protection-group, request routing-engine, request security, request services, request snmp, request support, request system, request validation, request vpls-switchover, restart, restart ddns, restart gracefully, restart immediately, restart kernel-replication, restart named-service, restart routing, restart soft, restart web-management, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set chassis, set cli, set date, show, show access-cac, show access-security, show accounting, show agent, show app-engine, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show connections, show database-replication, show dhcp, show dhcp-security, show dhcpv6, show dialer, show diameter, show dot1x, show dynamic-tunnels, show ephemeral-configuration, show esis, show ethernet-switching, show event-options, show evpn, show express-segments, show extension-service, show firewall, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show host, show iccp, show igmp, show ingress-replication, show interfaces, show ipv6, show isdn, show isis, show jdaf, show l2circuit, show l2cpd, show l2vpn, show lacp, show ldp, show lldp, show log, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show modem, show monitor, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show performance-monitoring, show pfe, show pim, show policer, show policy, show ppp, show pppoe, show programmable-rpd, show r2cp, show resource-manager, show rip, show ripng, show route, show routing, show rsvp, show sap, show schedulers, show security, show services, show smtp, show snmp, show spanning-tree, show spring-traffic-engineering, show ssl-certificates, show subscribers, show system, show task, show ted, show v4ov6-tunnels, show validation, show version, show vlans, show vpls, show vrrp, ssh, ssh bypass-routing, ssh extensive, ssh inet, ssh inet6, ssh interface, ssh logical-system, ssh routing-instance, ssh source, ssh tenant, ssh v2, ssh verbose, start, start shell, telnet, telnet bypass-routing, telnet inet, telnet inet6, telnet interface, telnet logical-system, telnet no-resolve, telnet port, telnet routing-instance, telnet source, telnet tenant, test, test aaa, test configuration, test dot1x, test interface, test l2-learning, test msdp, test policy, test rib-sharding, test security, test services, traceroute, traceroute as-number-lookup, traceroute bypass-routing, traceroute ce-ip, traceroute clns, traceroute extension, traceroute gateway, traceroute inet, traceroute inet6, traceroute interface, traceroute logical-system, traceroute monitor, traceroute mpls, traceroute next-hop, traceroute no-resolve, traceroute overlay, traceroute port, traceroute propagate-ttl, traceroute routing-instance, traceroute source, traceroute tenant, traceroute tos, traceroute ttl, traceroute wait

Raw `?`:

```
?
Possible completions:
  clear                Clear PPM related statistics information
  configure            Manipulate software configuration information
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  monitor              Show real-time debugging information
  mtrace               Trace multicast path from source to receiver
  op                   Invoke an operation script
  ping                 Ping remote target
  probe                Probe interfaces on remote target
  quit                 Exit the management session
  request              Make system-level requests
  restart              Restart software process
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  show                 Show system information
  ssh                  Start secure shell on another host
  start                Start shell
  telnet               Telnet to another host
  test                 Perform diagnostic debugging
  traceroute           Trace route to remote host
alice02@srx1>    
```

Raw `request ?`:

```
alice02@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  debug                Manageability Debugging
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  extension-service    Jet application
  flight-recorder      Flight recorder commands
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  jnu                  Perform JNU operations
  l2circuit-switchover  Perform l2circuit switchover
  lacp                 Request LACP actions
  message              Send text message to other users
  modem                
  mpls                 Perform Multiprotocol Label Switching operations
  network-access       Request network-access related information
  pim                  Perform PIM operations
  pppoe                Perform PPPoE specific operations
  protection-group     Request protection group related operations
  routing-engine       Routing Engine
  security             Request security operation
  services             Request service options
  snmp                 Request actions from the Simple Network Management Protocol daemon
  support              Perform JUNOS support tasks
  system               Perform system-level operations
  validation           Request route validation actions
  vpls-switchover      Perform LDP VPLS pseudowire switchover
alice02@srx1> request    
```

Raw `test ?`:

```
alice02@srx1>          test ?
Possible completions:
  aaa                  Test the aaa servers
  configuration        Check correctness of configuration file
  dot1x                Test dot1x functionality
  interface            Perform test on interface
  l2-learning          Layer 2 forwarding commands
  msdp                 Perform Multicast Source Discovery Protocol peer debugging
  policy               Import and export policy evaluation
  rib-sharding         Test sharding
  security             Security related tests
  services             Test service options
alice02@srx1> test    
```

Raw `set ?`:

```
alice02@srx1>       set ?
Possible completions:
  chassis              Set chassis properties
  cli                  Set CLI properties
  date                 Set system date and time
alice02@srx1> set    
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice02@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 21:56:44 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 21:54:17 UTC (00:02:27 ago)
Protocols started: 2026-11-05 21:55:06 UTC (00:01:38 ago)
Last configured: 2026-11-05 21:55:21 UTC (00:01:23 ago) by breakglass
 9:56PM  up 2 mins, 1 users, load averages: 1.88, 1.12, 0.48

alice02@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice02@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
 
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: sendto: Can't assign requested address
.
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

alice02@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
 
traceroute to 127.0.0.1 (127.0.0.1), 1 hops max, 52 byte packets
traceroute: sendto: Can't assign requested address
 1 traceroute: wrote 127.0.0.1 52 chars, ret=-1
 *traceroute: sendto: Can't assign requested address
traceroute: wrote 127.0.0.1 52 chars, ret=-1
 *traceroute: sendto: Can't assign requested address
traceroute: wrote 127.0.0.1 52 chars, ret=-1
 *

alice02@srx1> 
```

`monitor interface`:

```
monitor ?
Possible completions:
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  security             Monitor security information
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
  traffic              Show real-time network traffic information
alice02@srx1> monitor    
```

`request system reboot`:

```
request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  decrypt              Decrypt a $8$ or $9$-encrypted password
  download             Manage downloads
  firmware             Upgrade or downgrade firmware
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
  set-encryption-key   Set EEPROM stored encryption key
  snapshot             Create a normal Junos or a recovery snapshot
  software             Perform system software extension or upgrade
  storage              Request operation on system storage
  yang                 Perform YANG schema operations
  zeroize              Erase all data, including configuration and log files
alice02@srx1> request system    
```

`restart routing`:

```
restart ?
Possible completions:
> SDN-Telemetry        agent for all the telemetry sensors
> advanced-anti-malware  Advanced Anti-Malware daemon
> analytics-agent      Analytics agent
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> application-security  Application security daemon
> audit-process        Audit process
> autoinstallation     Autoinstallation process
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> cloudagent           Cloudagent process
> cloudham-service     Cloud HA Management Daemon
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
  ddns                 Restart the dynamic DNS client
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> dialer-services      Dialer services process
> diameter-service     Diameter process
> dynamic-filtering    Dynamic Filtering Daemon
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fipsd                FIPS daemon
> firewall             Firewall process
> firewall-authentication-service  Firewall authentication daemon
> forwarding           Forwarding Daemon
> general-authentication-service  General authentication process
> gprs-process         gprs daemon
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group key member daemon
> group-key-server     Group key server daemon
> gstatd               geom-device performance monitoring daemon
> idp-policy           IDP policy daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> interface-control    Interface control process
> ipmi                 Intelligent platform management interface daemon
> ipsec-key-management  IPSec Key Management daemon
> jnu-management       Junos node unifier process
> jnx-wmicd-service    wmicd service process
> jsd                  JET Services Daemon
> jsrp-service         Juniper Stateful Redundancy Protocol Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> local-log-management  Local Log Management Daemon
> logical-system-service  Logical System Daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
  named-service        DNS server process
> netproxy             netproxy service
> network-security     Network security daemon
> network-security-trace  Network security trace daemon
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ntpd-service         Network Time Protocol Service
> peer-selection-service  Peer selection service process
> pgm                  Pragmatic General Multicast process
> phone-home-client    Phone home client daemon
> pki-service          PKI service daemon
> ppp                  PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> profilerd            Profiler Daemon
> redundancy-interface-process  Redundancy interface management process
> remote-operations    Remote operations process
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpcbind-service      Service for rpc requests
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> security-intelligence  IPF daemon
> security-log         Security Log Daemon
> service-deployment   Service Deployment Client
> simple-mail-client-service  Simple Mail Transfer Protocol Client process
> slaacd               SLAAC process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> sysctl-relay-process  Sysctl Relaying Process
> system-health-management  System Health Management Daemon
> system-log-vital     System Log Vital Daemon
> tunnel-oamd          Tunnel OAM process
> uac-service          Unified access control daemon
> ui-pubd              Mosquitto pub client process
> user-ad-authentication  user id daemon
> vrrp                 Virtual Router Redundancy Protocol process
  web-management       Web management process
> webapi-service       webapi service process
> wireless-wan-service  Wireless WAN process
> xmlproxyd            XMLPROXY Daemon
alice02@srx1> restart    
```

`show configuration system host-name`:

```
 
host-name srx1;

alice02@srx1> 
```

`show configuration routing-instances`:

```
 
mgmt_junos {
    routing-options {
        rib mgmt_junos.inet6.0 {
            static {
                route ::/0 next-hop 2001:db8::1;
            }
        }
        static {
            route 0.0.0.0/0 next-hop 10.0.0.2;
        }
    }
}

alice02@srx1> 
```

`show configuration interfaces`:

```
 
fxp0 {
    unit 0 {
        family inet {
            address 10.0.0.15/24;
        }
        family inet6 {
            address 2001:db8::2/64;
        }
    }
}

alice02@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
Use 'commit check' to check configuration for correctness without
making it active.

alice02@srx1> 
```

`show cli`:

```
 
CLI complete-on-space set to on
CLI idle-timeout disabled
CLI restart-on-upgrade set to off
CLI screen-length set to 0
CLI screen-width set to 200
CLI terminal is 'vt100'
CLI is operating in enhanced mode
CLI timestamp disabled
CLI working directory is '/var/home/p49-l12-b-all'

alice02@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice02@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice02@srx1> 
```

`configure`:

```
 
Entering configuration mode

[edit]
alice02@srx1# 
```

`exit configuration-mode`:

```
 
Exiting configuration mode

alice02@srx1> 
```

### clear

Reply `["local-user-name=p49-l12-b-clear"]`. `show cli authorization`:

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

Completion: clear, clear amt, clear arp, clear auto-bandwidth, clear auto-configuration, clear bfd, clear bgp, clear captive-portal, clear class-of-service, clear cli, clear database-replication, clear dhcp, clear dhcp-security, clear dhcpv6, clear diameter, clear dot1x, clear dynamic-tunnels, clear error, clear esis, clear ethernet-switching, clear evpn, clear express-segments, clear firewall, clear helper, clear igmp, clear interfaces, clear ipv6, clear isis, clear l2-learning, clear l2circuit, clear ldp, clear lldp, clear loop-detect, clear mac-vrf, clear mld, clear monitor, clear mpls, clear msdp, clear multicast, clear network-access, clear oam, clear ospf, clear ospf3, clear performance-monitoring, clear pfe, clear pim, clear poe, clear ppp, clear pppoe, clear ptp, clear r2cp, clear resource-manager, clear rip, clear ripng, clear rsvp, clear snmp, clear spanning-tree, clear synchronous-ethernet, clear system, clear validation, clear vpls, clear vrrp, file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request jdaf, request lacp, request modem, request mpls, request network-access, request protection-group, request services, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set chassis, set cli, start, test, test aaa, test dot1x, test l2-learning, test security

Raw `?`:

```
?
Possible completions:
  clear                Clear PPM related statistics information
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  op                   Invoke an operation script
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  start                Start shell
  test                 Perform diagnostic debugging
alice03@srx1>    
```

Raw `request ?`:

```
alice03@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  mpls                 Perform Multiprotocol Label Switching operations
  network-access       Request network-access related information
  protection-group     Request protection group related operations
  services             Request service options
alice03@srx1> request    
```

Raw `test ?`:

```
alice03@srx1>         test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  l2-learning          Layer 2 forwarding commands
  security             Security related tests
alice03@srx1> test    
```

Raw `set ?`:

```
alice03@srx1>       set ?
Possible completions:
  chassis              Set chassis properties
  cli                  Set CLI properties
alice03@srx1> set    
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

`show system uptime`:

```
show
              ^
unknown command.
alice03@srx1> show   system
              ^
unknown command.
alice03@srx1> showsystem   uptime
              ^
unknown command.

alice03@srx1> 
```

`clear interfaces statistics fxp0`:

```
 

alice03@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice03@srx1> ping   127.0.0.1
              ^
unknown command.
alice03@srx1> ping127.0.0.1   count
              ^
unknown command.
alice03@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice03@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice03@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
traceroute
              ^
unknown command.
alice03@srx1> traceroute   127.0.0.1
              ^
unknown command.
alice03@srx1> traceroute127.0.0.1   ttl
              ^
unknown command.
alice03@srx1> traceroute127.0.0.1ttl   1
              ^
unknown command.
alice03@srx1> traceroute127.0.0.1ttl1   wait
              ^
unknown command.
alice03@srx1> traceroute127.0.0.1ttl1wait   1
              ^
unknown command.

alice03@srx1> 
```

`monitor interface`:

```
monitor
              ^
unknown command.
alice03@srx1> monitor   ?
No valid completions
alice03@srx1> monitor   
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice03@srx1> request system   ?
No valid completions
alice03@srx1> request system   
```

`restart routing`:

```
restart
              ^
unknown command.
alice03@srx1> restart   ?
No valid completions
alice03@srx1> restart   
```

`show configuration system host-name`:

```
show
              ^
unknown command.
alice03@srx1> show   configuration
              ^
unknown command.
alice03@srx1> showconfiguration   system
              ^
unknown command.
alice03@srx1> showconfigurationsystem   host-name
              ^
unknown command.

alice03@srx1> 
```

`show configuration routing-instances`:

```
show
              ^
unknown command.
alice03@srx1> show   configuration
              ^
unknown command.
alice03@srx1> showconfiguration   routing-instances
              ^
unknown command.

alice03@srx1> 
```

`show configuration interfaces`:

```
show
              ^
unknown command.
alice03@srx1> show   configuration
              ^
unknown command.
alice03@srx1> showconfiguration   interfaces
              ^
unknown command.

alice03@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
Use ESC-/ in the CLI to expand strings into matching words from the
command line history.

alice03@srx1> 
```

`show cli`:

```
show
              ^
unknown command.
alice03@srx1> show   cli
              ^
unknown command.

alice03@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice03@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice03@srx1> 
```

`configure`:

```
              ^
unknown command.

alice03@srx1> 
```

`exit configuration-mode`:

```
                   ^
syntax error, expecting <command>.

alice03@srx1> 
```

### network

Reply `["local-user-name=p49-l12-b-network"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice04@srx1> show   cli
              ^
unknown command.
alice04@srx1> showcli   authorization
              ^
unknown command.

alice04@srx1> 
```

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, mtrace, mtrace from-source, mtrace logical-system, mtrace monitor, mtrace routing-instance, mtrace to-gateway, op, op invoke-debugger, op url, ping, ping atm, ping bypass-routing, ping ce-ip, ping clns, ping count, ping detail, ping do-not-fragment, ping inet, ping inet6, ping interface, ping interval, ping logical-system, ping mac-address, ping mpls, ping no-resolve, ping overlay, ping pattern, ping rapid, ping record-route, ping routing-instance, ping size, ping source, ping srv6, ping strict, ping tenant, ping tos, ping ttl, ping verbose, ping vpls, ping wait, probe, probe by-address, probe by-index, probe by-name, probe by-remote-address, probe count, probe detail, probe inet, probe inet6, probe interface, probe interval, probe logical-system, probe routing-instance, probe source, probe tenant, probe tos, probe ttl, probe wait, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request jdaf, request lacp, request modem, request network-access, request protection-group, request routing-engine, request services, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, ssh, ssh bypass-routing, ssh extensive, ssh inet, ssh inet6, ssh interface, ssh logical-system, ssh routing-instance, ssh source, ssh tenant, ssh v2, ssh verbose, start, telnet, telnet bypass-routing, telnet inet, telnet inet6, telnet interface, telnet logical-system, telnet no-resolve, telnet port, telnet routing-instance, telnet source, telnet tenant, test, test aaa, test dot1x, test l2-learning, test security, traceroute, traceroute as-number-lookup, traceroute bypass-routing, traceroute ce-ip, traceroute clns, traceroute extension, traceroute gateway, traceroute inet, traceroute inet6, traceroute interface, traceroute logical-system, traceroute monitor, traceroute mpls, traceroute next-hop, traceroute no-resolve, traceroute overlay, traceroute port, traceroute propagate-ttl, traceroute routing-instance, traceroute source, traceroute tenant, traceroute tos, traceroute ttl, traceroute wait

Raw `?`:

```
?
Possible completions:
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  mtrace               Trace multicast path from source to receiver
  op                   Invoke an operation script
  ping                 Ping remote target
  probe                Probe interfaces on remote target
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  ssh                  Start secure shell on another host
  start                Start shell
  telnet               Telnet to another host
  test                 Perform diagnostic debugging
  traceroute           Trace route to remote host
alice04@srx1>    
```

Raw `request ?`:

```
alice04@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  network-access       Request network-access related information
  protection-group     Request protection group related operations
  routing-engine       Routing Engine
  services             Request service options
alice04@srx1> request    
```

Raw `test ?`:

```
alice04@srx1>          test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  l2-learning          Layer 2 forwarding commands
  security             Security related tests
alice04@srx1> test    
```

Raw `set ?`:

```
alice04@srx1>       set ?
Possible completions:
  cli                  Set CLI properties
alice04@srx1> set    
```

`show version`:

```
show
              ^
unknown command.
alice04@srx1> show   version
              ^
unknown command.

alice04@srx1> 
```

`show system uptime`:

```
show
              ^
unknown command.
alice04@srx1> show   system
              ^
unknown command.
alice04@srx1> showsystem   uptime
              ^
unknown command.

alice04@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice04@srx1> clear   interfaces
              ^
unknown command.
alice04@srx1> clearinterfaces   statistics
              ^
unknown command.
alice04@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice04@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
 
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: sendto: Can't assign requested address
.
--- 127.0.0.1 ping statistics ---
1 packets transmitted, 0 packets received, 100% packet loss

alice04@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
 
traceroute to 127.0.0.1 (127.0.0.1), 1 hops max, 52 byte packets
traceroute: sendto: Can't assign requested address
 1 traceroute: wrote 127.0.0.1 52 chars, ret=-1
 *traceroute: sendto: Can't assign requested address
traceroute: wrote 127.0.0.1 52 chars, ret=-1
 *traceroute: sendto: Can't assign requested address
traceroute: wrote 127.0.0.1 52 chars, ret=-1
 *

alice04@srx1> 
```

`monitor interface`:

```
monitor
              ^
unknown command.
alice04@srx1> monitor   ?
No valid completions
alice04@srx1> monitor   
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice04@srx1> request system   ?
No valid completions
alice04@srx1> request system   
```

`restart routing`:

```
restart
              ^
unknown command.
alice04@srx1> restart   ?
No valid completions
alice04@srx1> restart   
```

`show configuration system host-name`:

```
show
              ^
unknown command.
alice04@srx1> show   configuration
              ^
unknown command.
alice04@srx1> showconfiguration   system
              ^
unknown command.
alice04@srx1> showconfigurationsystem   host-name
              ^
unknown command.

alice04@srx1> 
```

`show configuration routing-instances`:

```
show
              ^
unknown command.
alice04@srx1> show   configuration
              ^
unknown command.
alice04@srx1> showconfiguration   routing-instances
              ^
unknown command.

alice04@srx1> 
```

`show configuration interfaces`:

```
show
              ^
unknown command.
alice04@srx1> show   configuration
              ^
unknown command.
alice04@srx1> showconfiguration   interfaces
              ^
unknown command.

alice04@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
Use a URL to save output using ftp.  For example,
'show route summary | save ftp://user:password@host/filename'.

alice04@srx1> 
```

`show cli`:

```
show
              ^
unknown command.
alice04@srx1> show   cli
              ^
unknown command.

alice04@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice04@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice04@srx1> 
```

`configure`:

```
              ^
unknown command.

alice04@srx1> 
```

`exit configuration-mode`:

```
                   ^
syntax error, expecting <command>.

alice04@srx1> 
```

### trace

Reply `["local-user-name=p49-l12-b-trace"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice05@srx1> show   cli
              ^
unknown command.
alice05@srx1> showcli   authorization
              ^
unknown command.

alice05@srx1> 
```

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, monitor, monitor interface, monitor label-switched-path, monitor list, monitor security, monitor start, monitor static-lsp, monitor stop, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request jdaf, request lacp, request modem, request network-access, request protection-group, request services, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dot1x, test l2-learning, test security

Raw `?`:

```
?
Possible completions:
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  monitor              Show real-time debugging information
  op                   Invoke an operation script
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  start                Start shell
  test                 Perform diagnostic debugging
alice05@srx1>    
```

Raw `request ?`:

```
alice05@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  network-access       Request network-access related information
  protection-group     Request protection group related operations
  services             Request service options
alice05@srx1> request    
```

Raw `test ?`:

```
alice05@srx1>         test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  l2-learning          Layer 2 forwarding commands
  security             Security related tests
alice05@srx1> test    
```

Raw `set ?`:

```
alice05@srx1>       set ?
Possible completions:
  cli                  Set CLI properties
alice05@srx1> set    
```

`show version`:

```
show
              ^
unknown command.
alice05@srx1> show   version
              ^
unknown command.

alice05@srx1> 
```

`show system uptime`:

```
show
              ^
unknown command.
alice05@srx1> show   system
              ^
unknown command.
alice05@srx1> showsystem   uptime
              ^
unknown command.

alice05@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice05@srx1> clear   interfaces
              ^
unknown command.
alice05@srx1> clearinterfaces   statistics
              ^
unknown command.
alice05@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice05@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice05@srx1> ping   127.0.0.1
              ^
unknown command.
alice05@srx1> ping127.0.0.1   count
              ^
unknown command.
alice05@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice05@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice05@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
traceroute
              ^
unknown command.
alice05@srx1> traceroute   127.0.0.1
              ^
unknown command.
alice05@srx1> traceroute127.0.0.1   ttl
              ^
unknown command.
alice05@srx1> traceroute127.0.0.1ttl   1
              ^
unknown command.
alice05@srx1> traceroute127.0.0.1ttl1   wait
              ^
unknown command.
alice05@srx1> traceroute127.0.0.1ttl1wait   1
              ^
unknown command.

alice05@srx1> 
```

`monitor interface`:

```
monitor ?
Possible completions:
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  security             Monitor security information
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
alice05@srx1> monitor    
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice05@srx1> request system   ?
No valid completions
alice05@srx1> request system   
```

`restart routing`:

```
restart
              ^
unknown command.
alice05@srx1> restart   ?
No valid completions
alice05@srx1> restart   
```

`show configuration system host-name`:

```
show
              ^
unknown command.
alice05@srx1> show   configuration
              ^
unknown command.
alice05@srx1> showconfiguration   system
              ^
unknown command.
alice05@srx1> showconfigurationsystem   host-name
              ^
unknown command.

alice05@srx1> 
```

`show configuration routing-instances`:

```
show
              ^
unknown command.
alice05@srx1> show   configuration
              ^
unknown command.
alice05@srx1> showconfiguration   routing-instances
              ^
unknown command.

alice05@srx1> 
```

`show configuration interfaces`:

```
show
              ^
unknown command.
alice05@srx1> show   configuration
              ^
unknown command.
alice05@srx1> showconfiguration   interfaces
              ^
unknown command.

alice05@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
Use a URL to load configuration using ftp.  For example,
'load merge ftp://user:password@host/filename'.

alice05@srx1> 
```

`show cli`:

```
show
              ^
unknown command.
alice05@srx1> show   cli
              ^
unknown command.

alice05@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice05@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice05@srx1> 
```

`configure`:

```
              ^
unknown command.

alice05@srx1> 
```

`exit configuration-mode`:

```
                   ^
syntax error, expecting <command>.

alice05@srx1> 
```

### view

Reply `["local-user-name=p49-l12-b-view"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-b-view' login: 'alice06' class 'p49-l12-b-view'
Permissions:
    view        -- Can view current values and statistics
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice06@srx1> 
```

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request flight-recorder, request interface, request jdaf, request lacp, request modem, request network-access, request pppoe, request protection-group, request services, request snmp, request validation, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, show, show access-cac, show access-security, show accounting, show agent, show app-engine, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show connections, show database-replication, show dhcp, show dhcp-security, show dhcpv6, show dialer, show diameter, show dot1x, show dynamic-tunnels, show ephemeral-configuration, show esis, show ethernet-switching, show event-options, show evpn, show express-segments, show extension-service, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show iccp, show igmp, show ingress-replication, show interfaces, show ipv6, show isdn, show isis, show jdaf, show l2circuit, show l2cpd, show l2vpn, show lacp, show ldp, show lldp, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show modem, show monitor, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show performance-monitoring, show pfe, show pim, show policy, show ppp, show pppoe, show programmable-rpd, show r2cp, show resource-manager, show rip, show ripng, show route, show routing, show rsvp, show sap, show schedulers, show security, show services, show smtp, show snmp, show spanning-tree, show spring-traffic-engineering, show ssl-certificates, show subscribers, show system, show task, show ted, show v4ov6-tunnels, show validation, show version, show vlans, show vpls, show vrrp, start, test, test aaa, test dot1x, test interface, test l2-learning, test msdp, test policy, test rib-sharding, test security

Raw `?`:

```
?
Possible completions:
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  op                   Invoke an operation script
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  show                 Show system information
  start                Start shell
  test                 Perform diagnostic debugging
alice06@srx1>    
```

Raw `request ?`:

```
alice06@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  flight-recorder      Flight recorder commands
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  network-access       Request network-access related information
  pppoe                Perform PPPoE specific operations
  protection-group     Request protection group related operations
  services             Request service options
  snmp                 Request actions from the Simple Network Management Protocol daemon
  validation           Request route validation actions
alice06@srx1> request    
```

Raw `test ?`:

```
alice06@srx1>         test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  interface            Perform test on interface
  l2-learning          Layer 2 forwarding commands
  msdp                 Perform Multicast Source Discovery Protocol peer debugging
  policy               Import and export policy evaluation
  rib-sharding         Test sharding
  security             Security related tests
alice06@srx1> test    
```

Raw `set ?`:

```
alice06@srx1>       set ?
Possible completions:
  cli                  Set CLI properties
alice06@srx1> set    
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice06@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 21:58:41 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 21:54:17 UTC (00:04:24 ago)
Protocols started: 2026-11-05 21:55:06 UTC (00:03:35 ago)
Last configured: 2026-11-05 21:55:21 UTC (00:03:20 ago) by breakglass
 9:58PM  up 4 mins, 1 users, load averages: 1.52, 1.27, 0.62

alice06@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice06@srx1> clear   interfaces
              ^
unknown command.
alice06@srx1> clearinterfaces   statistics
              ^
unknown command.
alice06@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice06@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice06@srx1> ping   127.0.0.1
              ^
unknown command.
alice06@srx1> ping127.0.0.1   count
              ^
unknown command.
alice06@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice06@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice06@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
traceroute
              ^
unknown command.
alice06@srx1> traceroute   127.0.0.1
              ^
unknown command.
alice06@srx1> traceroute127.0.0.1   ttl
              ^
unknown command.
alice06@srx1> traceroute127.0.0.1ttl   1
              ^
unknown command.
alice06@srx1> traceroute127.0.0.1ttl1   wait
              ^
unknown command.
alice06@srx1> traceroute127.0.0.1ttl1wait   1
              ^
unknown command.

alice06@srx1> 
```

`monitor interface`:

```
monitor
              ^
unknown command.
alice06@srx1> monitor   ?
No valid completions
alice06@srx1> monitor   
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice06@srx1> request system   ?
No valid completions
alice06@srx1> request system   
```

`restart routing`:

```
restart
              ^
unknown command.
alice06@srx1> restart   ?
No valid completions
alice06@srx1> restart   
```

`show configuration system host-name`:

```
show configuration system
                                 ^
syntax error.
alice06@srx1> show configuration system   host-name
                                 ^
syntax error.

alice06@srx1> 
```

`show configuration routing-instances`:

```
                                 ^
syntax error.

alice06@srx1> 
```

`show configuration interfaces`:

```
                                 ^
syntax error.

alice06@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
Use 'request system snapshot' to make a snapshot of the running system
on the hard disk drive.

alice06@srx1> 
```

`show cli`:

```
 
CLI complete-on-space set to on
CLI idle-timeout disabled
CLI restart-on-upgrade set to off
CLI screen-length set to 0
CLI screen-width set to 200
CLI terminal is 'vt100'
CLI is operating in enhanced mode
CLI timestamp disabled
CLI working directory is '/var/home/p49-l12-b-view'

alice06@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice06@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice06@srx1> 
```

`configure`:

```
              ^
unknown command.

alice06@srx1> 
```

`exit configuration-mode`:

```
                   ^
syntax error, expecting <command>.

alice06@srx1> 
```

### view-configuration

Reply `["local-user-name=p49-l12-b-view-configuration"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice07@srx1> show   cli
              ^
unknown command.
alice07@srx1> showcli   authorization
              ^
unknown command.

alice07@srx1> 
```

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, monitor, monitor interface, monitor label-switched-path, monitor list, monitor security, monitor start, monitor static-lsp, monitor stop, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request jdaf, request lacp, request modem, request mpls, request network-access, request protection-group, request security, request services, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dot1x, test l2-learning, test security

Raw `?`:

```
?
Possible completions:
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  monitor              Show real-time debugging information
  op                   Invoke an operation script
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  start                Start shell
  test                 Perform diagnostic debugging
alice07@srx1>    
```

Raw `request ?`:

```
alice07@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  mpls                 Perform Multiprotocol Label Switching operations
  network-access       Request network-access related information
  protection-group     Request protection group related operations
  security             Request security operation
  services             Request service options
alice07@srx1> request    
```

Raw `test ?`:

```
alice07@srx1>         test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  l2-learning          Layer 2 forwarding commands
  security             Security related tests
alice07@srx1> test    
```

Raw `set ?`:

```
alice07@srx1>       set ?
Possible completions:
  cli                  Set CLI properties
alice07@srx1> set    
```

`show version`:

```
show
              ^
unknown command.
alice07@srx1> show   version
              ^
unknown command.

alice07@srx1> 
```

`show system uptime`:

```
show
              ^
unknown command.
alice07@srx1> show   system
              ^
unknown command.
alice07@srx1> showsystem   uptime
              ^
unknown command.

alice07@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice07@srx1> clear   interfaces
              ^
unknown command.
alice07@srx1> clearinterfaces   statistics
              ^
unknown command.
alice07@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice07@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice07@srx1> ping   127.0.0.1
              ^
unknown command.
alice07@srx1> ping127.0.0.1   count
              ^
unknown command.
alice07@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice07@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice07@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
traceroute
              ^
unknown command.
alice07@srx1> traceroute   127.0.0.1
              ^
unknown command.
alice07@srx1> traceroute127.0.0.1   ttl
              ^
unknown command.
alice07@srx1> traceroute127.0.0.1ttl   1
              ^
unknown command.
alice07@srx1> traceroute127.0.0.1ttl1   wait
              ^
unknown command.
alice07@srx1> traceroute127.0.0.1ttl1wait   1
              ^
unknown command.

alice07@srx1> 
```

`monitor interface`:

```
monitor ?
Possible completions:
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  security             Monitor security information
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
alice07@srx1> monitor    
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice07@srx1> request system   ?
No valid completions
alice07@srx1> request system   
```

`restart routing`:

```
restart
              ^
unknown command.
alice07@srx1> restart   ?
No valid completions
alice07@srx1> restart   
```

`show configuration system host-name`:

```
show
              ^
unknown command.
alice07@srx1> show   configuration
              ^
unknown command.
alice07@srx1> showconfiguration   system
              ^
unknown command.
alice07@srx1> showconfigurationsystem   host-name
              ^
unknown command.

alice07@srx1> 
```

`show configuration routing-instances`:

```
show
              ^
unknown command.
alice07@srx1> show   configuration
              ^
unknown command.
alice07@srx1> showconfiguration   routing-instances
              ^
unknown command.

alice07@srx1> 
```

`show configuration interfaces`:

```
show
              ^
unknown command.
alice07@srx1> show   configuration
              ^
unknown command.
alice07@srx1> showconfiguration   interfaces
              ^
unknown command.

alice07@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
Use 'load merge <filename>' with 'relative' option to avoid having to
type the complete configuration hierarchy.

alice07@srx1> 
```

`show cli`:

```
show
              ^
unknown command.
alice07@srx1> show   cli
              ^
unknown command.

alice07@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice07@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice07@srx1> 
```

`configure`:

```
              ^
unknown command.

alice07@srx1> 
```

`exit configuration-mode`:

```
                   ^
syntax error, expecting <command>.

alice07@srx1> 
```

### view+view-configuration

Reply `["local-user-name=p49-l12-b-view-view-configuration"]`. `show cli authorization`:

```
 
Current user: 'p49-l12-b-view-view-configuration' login: 'alice08' class 'p49-l12-b-view-view-configuration'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice08@srx1> 
```

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, monitor, monitor interface, monitor label-switched-path, monitor list, monitor security, monitor start, monitor static-lsp, monitor stop, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request flight-recorder, request interface, request jdaf, request lacp, request modem, request mpls, request network-access, request pppoe, request protection-group, request security, request services, request snmp, request validation, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, show, show access-cac, show access-security, show accounting, show agent, show app-engine, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show connections, show database-replication, show dhcp, show dhcp-security, show dhcpv6, show dialer, show diameter, show dot1x, show dynamic-tunnels, show ephemeral-configuration, show esis, show ethernet-switching, show event-options, show evpn, show express-segments, show extension-service, show firewall, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show iccp, show igmp, show ingress-replication, show interfaces, show ipv6, show isdn, show isis, show jdaf, show l2circuit, show l2cpd, show l2vpn, show lacp, show ldp, show lldp, show log, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show modem, show monitor, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show performance-monitoring, show pfe, show pim, show policer, show policy, show ppp, show pppoe, show programmable-rpd, show r2cp, show resource-manager, show rip, show ripng, show route, show routing, show rsvp, show sap, show schedulers, show security, show services, show smtp, show snmp, show spanning-tree, show spring-traffic-engineering, show ssl-certificates, show subscribers, show system, show task, show ted, show v4ov6-tunnels, show validation, show version, show vlans, show vpls, show vrrp, start, test, test aaa, test dot1x, test interface, test l2-learning, test msdp, test policy, test rib-sharding, test security

Raw `?`:

```
?
Possible completions:
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  monitor              Show real-time debugging information
  op                   Invoke an operation script
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  show                 Show system information
  start                Start shell
  test                 Perform diagnostic debugging
alice08@srx1>    
```

Raw `request ?`:

```
alice08@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  flight-recorder      Flight recorder commands
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  mpls                 Perform Multiprotocol Label Switching operations
  network-access       Request network-access related information
  pppoe                Perform PPPoE specific operations
  protection-group     Request protection group related operations
  security             Request security operation
  services             Request service options
  snmp                 Request actions from the Simple Network Management Protocol daemon
  validation           Request route validation actions
alice08@srx1> request    
```

Raw `test ?`:

```
alice08@srx1>         test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  interface            Perform test on interface
  l2-learning          Layer 2 forwarding commands
  msdp                 Perform Multicast Source Discovery Protocol peer debugging
  policy               Import and export policy evaluation
  rib-sharding         Test sharding
  security             Security related tests
alice08@srx1> test    
```

Raw `set ?`:

```
alice08@srx1>       set ?
Possible completions:
  cli                  Set CLI properties
alice08@srx1> set    
```

`show version`:

```
 
Hostname: srx1
Model: vSRX
Junos: 21.4R3.15
JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]
JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]
JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]
JUNOS OS 32-bit compatibility [20220817.43c4e23_builder_stable_12_214]
JUNOS py extensions [20220903.052830_builder_junos_214_r3]
JUNOS py base [20220903.052830_builder_junos_214_r3]
JUNOS OS vmguest [20220817.43c4e23_builder_stable_12_214]
JUNOS OS crypto [20220817.43c4e23_builder_stable_12_214]
JUNOS OS boot-ve files [20220817.43c4e23_builder_stable_12_214]
JUNOS network stack and utilities [20220903.052830_builder_junos_214_r3]
JUNOS libs [20220903.052830_builder_junos_214_r3]
JUNOS libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS runtime [20220903.052830_builder_junos_214_r3]
JUNOS na telemetry [21.4R3.15]
JUNOS Web Management Platform Package [20220903.052830_builder_junos_214_r3]
JUNOS vsrx modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs compat32 [20220903.052830_builder_junos_214_r3]
JUNOS srx runtime [20220903.052830_builder_junos_214_r3]
JUNOS srx platform support [20220903.052830_builder_junos_214_r3]
JUNOS common platform support [20220903.052830_builder_junos_214_r3]
JUNOS vsrx runtime [20220903.052830_builder_junos_214_r3]
JUNOS Routing mpls-oam-basic [20220903.052830_builder_junos_214_r3]
JUNOS Routing lsys [20220903.052830_builder_junos_214_r3]
JUNOS Routing 32-bit Compatible Version [20220903.052830_builder_junos_214_r3]
JUNOS Routing aggregated [20220903.052830_builder_junos_214_r3]
JUNOS probe utility [20220903.052830_builder_junos_214_r3]
JUNOS pppoe [20220903.052830_builder_junos_214_r3]
JUNOS Openconfig [21.4R3.15]
JUNOS mtx network modules [20220903.052830_builder_junos_214_r3]
JUNOS modules [20220903.052830_builder_junos_214_r3]
JUNOS srx libs [20220903.052830_builder_junos_214_r3]
JUNOS L2 RSI Scripts [20220903.052830_builder_junos_214_r3]
JUNOS hsm [20220903.052830_builder_junos_214_r3]
JUNOS srx Data Plane Crypto Support [20220903.052830_builder_junos_214_r3]
JUNOS daemons [20220903.052830_builder_junos_214_r3]
JUNOS srx daemons [20220903.052830_builder_junos_214_r3]
JUNOS cloud libs [20220903.052830_builder_junos_214_r3]
JUNOS cloud init [20220903.052830_builder_junos_214_r3]
JUNOS SRX TVP AppQos Daemon [20220903.052830_builder_junos_214_r3]
JUNOS Extension Toolkit [20220903.052830_builder_junos_214_r3]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20220903.052830_builder_junos_214_r3]
JUNOS J-Insight [20220903.052830_builder_junos_214_r3]
JUNOS Online Documentation [20220903.052830_builder_junos_214_r3]
JUNOS jail runtime [20220817.43c4e23_builder_stable_12_214]
JUNOS FIPS mode utilities [20220903.052830_builder_junos_214_r3]
JUNOS dsa dsa [21.4R3.15]

alice08@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-11-05 21:59:36 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-11-05 21:54:17 UTC (00:05:19 ago)
Protocols started: 2026-11-05 21:55:06 UTC (00:04:30 ago)
Last configured: 2026-11-05 21:55:21 UTC (00:04:15 ago) by breakglass
 9:59PM  up 5 mins, 1 users, load averages: 1.50, 1.32, 0.68

alice08@srx1> 
```

`clear interfaces statistics fxp0`:

```
clear
              ^
unknown command.
alice08@srx1> clear   interfaces
              ^
unknown command.
alice08@srx1> clearinterfaces   statistics
              ^
unknown command.
alice08@srx1> clearinterfacesstatistics   fxp0
              ^
unknown command.

alice08@srx1> 
```

`ping 127.0.0.1 count 1 rapid`:

```
ping
              ^
unknown command.
alice08@srx1> ping   127.0.0.1
              ^
unknown command.
alice08@srx1> ping127.0.0.1   count
              ^
unknown command.
alice08@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice08@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice08@srx1> 
```

`traceroute 127.0.0.1 ttl 1 wait 1`:

```
traceroute
              ^
unknown command.
alice08@srx1> traceroute   127.0.0.1
              ^
unknown command.
alice08@srx1> traceroute127.0.0.1   ttl
              ^
unknown command.
alice08@srx1> traceroute127.0.0.1ttl   1
              ^
unknown command.
alice08@srx1> traceroute127.0.0.1ttl1   wait
              ^
unknown command.
alice08@srx1> traceroute127.0.0.1ttl1wait   1
              ^
unknown command.

alice08@srx1> 
```

`monitor interface`:

```
monitor ?
Possible completions:
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  security             Monitor security information
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
alice08@srx1> monitor    
```

`request system reboot`:

```
request system
                      ^
syntax error, expecting <command>.
alice08@srx1> request system   ?
No valid completions
alice08@srx1> request system   
```

`restart routing`:

```
restart
              ^
unknown command.
alice08@srx1> restart   ?
No valid completions
alice08@srx1> restart   
```

`show configuration system host-name`:

```
 
host-name srx1;

alice08@srx1> 
```

`show configuration routing-instances`:

```
 
mgmt_junos {
    routing-options {
        rib mgmt_junos.inet6.0 {
            static {
                route ::/0 next-hop 2001:db8::1;
            }
        }
        static {
            route 0.0.0.0/0 next-hop 10.0.0.2;
        }
    }
}

alice08@srx1> 
```

`show configuration interfaces`:

```
 
fxp0 {
    unit 0 {
        family inet {
            address 10.0.0.15/24;
        }
        family inet6 {
            address 2001:db8::2/64;
        }
    }
}

alice08@srx1> 
```

`help tip cli`:

```
 
JUNOS tip:
Use the 'apply-path' statement to define a prefix list containing
prefixes extracted from any configuration path.

alice08@srx1> 
```

`show cli`:

```
 
CLI complete-on-space set to on
CLI idle-timeout disabled
CLI restart-on-upgrade set to off
CLI screen-length set to 0
CLI screen-width set to 200
CLI terminal is 'vt100'
CLI is operating in enhanced mode
CLI timestamp disabled
CLI working directory is '/var/home/p49-l12-b-view-view-configuration'

alice08@srx1> 
```

`set cli screen-width 200`:

```
 
Screen width set to 200

alice08@srx1> 
```

`file list /var/tmp`:

```
 

/var/tmp:
appidd_cust_app_trace
appidd_trace_debug
eedebug_bin_file
kmdchk.log
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq
nsd_restart
pc /
pfe-limit
pfe_debug_commands
phone-home/
pics/
pkg_cleanup.log.err
policy_status
rtsdb/
sd-upgrade/
sec-download/

alice08@srx1> 
```

`configure`:

```
              ^
unknown command.

alice08@srx1> 
```

`exit configuration-mode`:

```
                   ^
syntax error, expecting <command>.

alice08@srx1> 
```

### none, exit

Reply `["local-user-name=p49-l12-b-none"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice09@srx1> show   cli
              ^
unknown command.
alice09@srx1> showcli   authorization
              ^
unknown command.

alice09@srx1> 
```

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load ssl-certificate, op, op invoke-debugger, op url, quit, request, request access-security, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request jdaf, request lacp, request modem, request network-access, request protection-group, request services, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dot1x, test l2-learning, test security

Raw `?`:

```
?
Possible completions:
  file                 Perform file operations
  help                 Provide help information
  load                 Load information from file
  op                   Invoke an operation script
  quit                 Exit the management session
  request              Make system-level requests
  scp                  Copy files via ssh
  set                  Set CLI properties, date/time, craft interface message
  start                Start shell
  test                 Perform diagnostic debugging
alice09@srx1>    
```

Raw `request ?`:

```
alice09@srx1>        request ?
Possible completions:
  access-security      Request access security feature
  auto-configuration   Request auto-configuration action
  chassis              Perform chassis-specific operations
  dhcp                 Perform DHCP operations
  dhcpv6               Perform DHCPv6 operations
  interface            Perform interface operations
  jdaf                 Request JDAF operation
  lacp                 Request LACP actions
  modem                
  network-access       Request network-access related information
  protection-group     Request protection group related operations
  services             Request service options
alice09@srx1> request    
```

Raw `test ?`:

```
alice09@srx1>         test ?
Possible completions:
  aaa                  Test the aaa servers
  dot1x                Test dot1x functionality
  l2-learning          Layer 2 forwarding commands
  security             Security related tests
alice09@srx1> test    
```

Raw `set ?`:

```
alice09@srx1>       set ?
Possible completions:
  cli                  Set CLI properties
alice09@srx1> set    
```

`exit`: closed the session

### none + deny .*

Reply `["local-user-name=p49-l12-b-none", "deny-commands=^.*$"]`. `show cli authorization`:

```
show
              ^
unknown command.
alice10@srx1> show   cli
              ^
unknown command.
alice10@srx1> showcli   authorization
              ^
unknown command.

alice10@srx1> 
```

Completion: 

Raw `?`:

```
?
No valid completions
alice10@srx1>    
```

`help tip cli`:

```
help
              ^
unknown command.
alice10@srx1> help   tip
              ^
unknown command.
alice10@srx1> helptip   cli
              ^
unknown command.

alice10@srx1> 
```

`show cli`:

```
show
              ^
unknown command.
alice10@srx1> show   cli
              ^
unknown command.

alice10@srx1> 
```

`set cli screen-width 200`:

```
set
              ^
unknown command.
alice10@srx1> set   cli
              ^
unknown command.
alice10@srx1> setcli   screen-width
              ^
unknown command.
alice10@srx1> setcliscreen-width   200
              ^
unknown command.

alice10@srx1> 
```

`file list /var/tmp`:

```
file
              ^
unknown command.
alice10@srx1> file   list
              ^
unknown command.
alice10@srx1> filelist   /var/tmp
              ^
unknown command.

alice10@srx1> 
```

`quit`: prompt back: ^ unknown command. alice10@srx1>

`exit`: prompt back: ^ unknown command. alice10@srx1>

