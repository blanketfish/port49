# L12-bits — juniper_vjunos-router

- **Date measured:** 2026-09-25
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L12-bits-juniper_vjunos-router.pcap` — 2234 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L12-bits-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What each permission bit a built-in level's ceiling names reaches, alone in a template's class, over TACACS+ `local-user-name`: every command word, and every word one level under it, its completion offers that a class with no bits does not, held by the adapter's `bits:` reach as an upper bound; what a class with no bits runs (`baseline`); and that `view` alone does not show the configuration, the one carve-out the adapter declares (spec §8, §15 L12).

## Observation

Each row is a session whose template's class holds one bit and nothing else; `none` holds none and `all` every bit. A command word, or a word and the word under it, is the bit's where its completion offers it and `none`'s does not; `none`'s own are the baseline.

| bit | words beyond none | candidate reach | held |
|---|---|---|---|
| baseline | file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request ipsec, request jdaf, request lacp, request network-access, request protection-group, request services, request session, save, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dhcp-security, test dhcp-service, test l2-learning, test rt-proxy, test unified-edge | `help **`, `quit **`, `exit **`, `set cli **`, `show cli **`, `file **`, `load **`, `op **`, `request **`, `save **`, `scp **`, `set **`, `start **`, `test **` | yes |
| clear | clear, clear amt, clear ancp, clear arp, clear auto-bandwidth, clear auto-configuration, clear bfd, clear bgp, clear bridge, clear captive-portal, clear cli, clear database-replication, clear ddos-protection, clear dhcp, clear dhcp-security, clear dhcpv6, clear diameter, clear dot1x, clear dynamic-tunnels, clear error, clear esis, clear evpn, clear express-segments, clear extensible-subscriber-services, clear firewall, clear forwarding-options, clear helper, clear igmp, clear ike, clear ilmi, clear interfaces, clear ipsec, clear ipv6, clear isis, clear l2-learning, clear l2circuit, clear ldp, clear lldp, clear loop-detect, clear mac-vrf, clear mld, clear mpls, clear msdp, clear multicast, clear mvrp, clear network-access, clear oam, clear ospf, clear ospf3, clear performance-monitoring, clear pfe, clear pim, clear poe, clear ppp, clear pppoe, clear protection-group, clear ptp, clear remote-device-management, clear rip, clear ripng, clear rsvp, clear sflow, clear shmlog, clear snmp, clear spanning-tree, clear synchronous-ethernet, clear system, clear tcp-forwarding, clear user-plane, clear validation, clear virtual-chassis, clear vpls, clear vrrp, request mpls | `clear **`, `request mpls **`, `set chassis **` | yes |
| network | mtrace, mtrace from-source, mtrace logical-system, mtrace monitor, mtrace routing-instance, mtrace to-gateway, ping, ping atm, ping bypass-routing, ping ce-ip, ping clns, ping count, ping detail, ping do-not-fragment, ping ethernet, ping gateway, ping inet, ping inet6, ping interface, ping interval, ping logical-system, ping mac-address, ping mpls, ping no-resolve, ping overlay, ping pattern, ping rapid, ping record-route, ping routing-instance, ping size, ping source, ping srv6, ping strict, ping tos, ping ttl, ping verbose, ping vpls, ping wait, probe, probe by-address, probe by-index, probe by-name, probe by-remote-address, probe count, probe detail, probe inet, probe inet6, probe interface, probe interval, probe logical-system, probe routing-instance, probe source, probe tos, probe ttl, probe wait, request routing-engine, ssh, ssh bypass-routing, ssh commands-to-execute, ssh extensive, ssh inet, ssh inet6, ssh interface, ssh logical-system, ssh routing-instance, ssh source, ssh v2, ssh verbose, telnet, telnet bypass-routing, telnet inet, telnet inet6, telnet interface, telnet logical-system, telnet no-resolve, telnet port, telnet routing-instance, telnet source, traceroute, traceroute as-number-lookup, traceroute bypass-routing, traceroute ce-ip, traceroute clns, traceroute ethernet, traceroute extension, traceroute gateway, traceroute inet, traceroute inet6, traceroute interface, traceroute logical-system, traceroute monitor, traceroute mpls, traceroute next-hop, traceroute no-resolve, traceroute overlay, traceroute port, traceroute propagate-ttl, traceroute routing-instance, traceroute source, traceroute srv6, traceroute tos, traceroute ttl, traceroute wait | `ping **`, `traceroute **`, `ssh **`, `telnet **`, `mtrace **`, `probe **`, `request routing-engine **` | yes |
| trace | monitor, monitor ethernet, monitor interface, monitor label-switched-path, monitor list, monitor mpls, monitor start, monitor static-lsp, monitor stop | `monitor **` | yes |
| view | request flight-recorder, request snmp, request validation, show, show access-cac, show access-security, show accounting, show agent, show amt, show ancp, show aps, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show bier, show bridge, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show congestion-protection, show connections, show database-replication, show ddos-protection, show dhcp, show dhcp-security, show dhcpv6, show diameter, show dot1x, show dual-phase-bootup-status, show dynamic-profile, show dynamic-tunnels, show ephemeral-configuration, show esis, show event-options, show evpn, show express-segments, show extensible-subscriber-services, show extension-provider, show extension-service, show fib-streaming, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show iccp, show igmp, show ike, show ilmi, show ingress-replication, show interfaces, show ipsec, show ipv6, show isis, show jdaf, show l2-learning, show l2circuit, show l2cpd, show l2pt, show l2vpn, show lacp, show layer2-control, show ldp, show link-management, show lldp, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show mvrp, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show path-computation-client, show performance-monitoring, show pfe, show pim, show poe, show policy, show ppp, show pppoe, show programmable-rpd, show protection-group, show remote-device-management, show rip, show ripng, show route, show rsvp, show sap, show security, show services, show sflow, show shmlog, show snmp, show spanning-tree, show spring-traffic-engineering, show srv6, show ssl-certificates, show static-subscribers, show subscribers, show system, show task, show tcp-forwarding, show ted, show unified-edge, show user-plane, show v4ov6-tunnels, show validation, show version, show virtual-chassis, show vpls, show vrrp, test interface, test msdp, test policy, test rib-sharding, test services | `show **`, `request flight-recorder **`, `request pppoe **`, `request snmp **`, `request validation **`, `test interface **`, `test msdp **`, `test policy **`, `test rib-sharding **`, `test services **` | yes |
| view-configuration | load dhcp-security-snoop, monitor, monitor ethernet, monitor interface, monitor label-switched-path, monitor list, monitor mpls, monitor start, monitor static-lsp, monitor stop, request mpls, request path-computation-client, request security, request unified-edge, request virtual-chassis, save dhcp-security-snoop | `show configuration **`, `monitor **`, `request mpls **`, `request path-computation-client **`, `request security **`, `request unified-edge **`, `request virtual-chassis **`, `load dhcp-security-snoop **`, `save dhcp-security-snoop **` | yes |

A top-level word is held whole (`request **`, `set **`), not word by word under it: `?` does not list Junos's hidden commands, so a per-word reach could under-report what the device runs. A per-word reach is a possible later refinement, and needs proof, not measured here, that no hidden command sits under each word.

| hierarchy probe | `all` shows it | `view` alone: observed | `view` alone shows it | `view-configuration` alone shows it | `view view-configuration` shows it | isolated |
|---|---|---|---|---|---|---|
| `show configuration system host-name` | true | true | false | false | true | yes |
| `show configuration routing-instances` | true | true | false | false | true | yes |
| `show configuration interfaces` | true | true | false | false | true | yes |

The adapter's carve-out `view-configuration: [show configuration **]` holds only if `view` alone shows none of them; it was measured on 3 hierarchies the `all` control shows.

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

Classes other than `all` that entered configuration mode (`configure` ran): none.

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

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request ipsec, request jdaf, request lacp, request network-access, request protection-group, request services, request session, save, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dhcp-security, test dhcp-service, test l2-learning, test rt-proxy, test unified-edge

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
alice01@srx1>          request system
                      ^
syntax error, expecting <command>.
alice01@srx1> request system   ?
No valid completions
alice01@srx1> request system   
```

`restart routing`:

```
alice01@srx1>                 restart
              ^
unknown command.
alice01@srx1> restart   ?
No valid completions
alice01@srx1> restart   
```

`show configuration system host-name`:

```
alice01@srx1>          show
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
Use the annotate command to add comments to your configuration.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: clear, clear amt, clear ancp, clear arp, clear auto-bandwidth, clear auto-configuration, clear bfd, clear bgp, clear bridge, clear captive-portal, clear chassis, clear cli, clear database-replication, clear ddos-protection, clear dhcp, clear dhcp-security, clear dhcpv6, clear diameter, clear dot1x, clear dynamic-tunnels, clear error, clear esis, clear evpn, clear express-segments, clear extensible-subscriber-services, clear extension-service, clear firewall, clear forwarding-options, clear helper, clear igmp, clear ike, clear ilmi, clear interfaces, clear ipsec, clear ipv6, clear isis, clear l2-learning, clear l2circuit, clear lacp, clear ldp, clear lldp, clear log, clear loop-detect, clear mac-vrf, clear mld, clear mpls, clear msdp, clear multicast, clear mvrp, clear network-access, clear oam, clear ospf, clear ospf3, clear passive-monitoring, clear path-computation-client, clear performance-monitoring, clear pfe, clear pim, clear poe, clear ppp, clear pppoe, clear protection-group, clear ptp, clear remote-device-management, clear rip, clear ripng, clear rsvp, clear security, clear services, clear sflow, clear shmlog, clear snmp, clear spanning-tree, clear synchronous-ethernet, clear system, clear tcp-forwarding, clear unified-edge, clear user-plane, clear validation, clear virtual-chassis, clear vpls, clear vrrp, configure, configure batch, configure dynamic, configure exclusive, configure private, file, file archive, file change-owner, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load dhcp-security-snoop, load ssl-certificate, monitor, monitor ethernet, monitor interface, monitor label-switched-path, monitor list, monitor mpls, monitor start, monitor static-lsp, monitor stop, monitor traffic, mtrace, mtrace from-source, mtrace logical-system, mtrace monitor, mtrace routing-instance, mtrace to-gateway, op, op invoke-debugger, op url, ping, ping atm, ping bypass-routing, ping ce-ip, ping clns, ping count, ping detail, ping do-not-fragment, ping ethernet, ping gateway, ping inet, ping inet6, ping interface, ping interval, ping logical-system, ping mac-address, ping mpls, ping no-resolve, ping overlay, ping pattern, ping rapid, ping record-route, ping routing-instance, ping size, ping source, ping srv6, ping strict, ping tos, ping ttl, ping verbose, ping vpls, ping wait, probe, probe by-address, probe by-index, probe by-name, probe by-remote-address, probe count, probe detail, probe inet, probe inet6, probe interface, probe interval, probe logical-system, probe routing-instance, probe source, probe tos, probe ttl, probe wait, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request debug, request dhcp, request dhcpv6, request extension-service, request flight-recorder, request interface, request ipsec, request jdaf, request jnu, request l2circuit-switchover, request lacp, request message, request mpls, request network-access, request path-computation-client, request pim, request protection-group, request routing-engine, request security, request services, request session, request snmp, request support, request system, request unified-edge, request validation, request virtual-chassis, request vpls-switchover, restart, restart gracefully, restart immediately, restart kernel-replication, restart routing, restart soft, save, save dhcp-security-snoop, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, set date, show, show access-cac, show access-security, show accounting, show agent, show amt, show ancp, show aps, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show bier, show bridge, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show congestion-protection, show connections, show database-replication, show ddos-protection, show dhcp, show dhcp-security, show dhcpv6, show diameter, show dot1x, show dual-phase-bootup-status, show dynamic-profile, show dynamic-tunnels, show ephemeral-configuration, show esis, show event-options, show evpn, show express-segments, show extensible-subscriber-services, show extension-provider, show extension-service, show fib-streaming, show firewall, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show host, show iccp, show igmp, show igp-compute, show ike, show ilmi, show ingress-replication, show interfaces, show ipsec, show ipv6, show isis, show jdaf, show l2-learning, show l2circuit, show l2cpd, show l2pt, show l2vpn, show lacp, show layer2-control, show ldp, show link-management, show lldp, show log, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show mvrp, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show path-computation-client, show performance-monitoring, show pfe, show pim, show poe, show policer, show policy, show ppp, show pppoe, show programmable-rpd, show protection-group, show remote-device-management, show rip, show ripng, show route, show rsvp, show sap, show security, show services, show sflow, show shmlog, show snmp, show spanning-tree, show spring-traffic-engineering, show srv6, show ssl-certificates, show static-subscribers, show subscribers, show system, show task, show tcp-forwarding, show ted, show unified-edge, show user-plane, show v4ov6-tunnels, show validation, show version, show virtual-chassis, show vpls, show vrrp, ssh, ssh bypass-routing, ssh commands-to-execute, ssh extensive, ssh inet, ssh inet6, ssh interface, ssh logical-system, ssh routing-instance, ssh source, ssh v2, ssh verbose, start, start shell, telnet, telnet bypass-routing, telnet inet, telnet inet6, telnet interface, telnet logical-system, telnet no-resolve, telnet port, telnet routing-instance, telnet source, test, test aaa, test configuration, test dhcp-security, test dhcp-service, test interface, test l2-learning, test msdp, test policy, test rib-sharding, test rt-proxy, test services, test unified-edge, traceroute, traceroute as-number-lookup, traceroute bypass-routing, traceroute ce-ip, traceroute clns, traceroute ethernet, traceroute extension, traceroute gateway, traceroute inet, traceroute inet6, traceroute interface, traceroute logical-system, traceroute monitor, traceroute mpls, traceroute next-hop, traceroute no-resolve, traceroute overlay, traceroute port, traceroute propagate-ttl, traceroute routing-instance, traceroute source, traceroute srv6, traceroute tos, traceroute ttl, traceroute wait

`show version`:

```
 
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
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice02@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 04:08:06 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 04:05:46 UTC (00:02:20 ago)
Protocols started: 2026-09-25 04:06:41 UTC (00:01:25 ago)
Last configured: 2026-09-25 04:07:01 UTC (00:01:05 ago) by breakglass
 4:08AM  up 2 mins, 1 users, load averages: 0.83, 0.63, 0.28

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
  ethernet             Start ethernet performance measurement
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  mpls                 Monitor MPLS LSPs
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
  traffic              Show real-time network traffic information
alice02@srx1> monitor    
```

`request system reboot`:

```
alice02@srx1>           request system ?
Possible completions:
  certificate          Manage X509 certificates
  commit               Perform commit related operations
  configuration        Request operation on system configuration
  convert-json-configuration  Convert the given JSON configuration file as per Junos
  debug-info           Collect debug information of the system
  decrypt              Decrypt a $8$ or $9$-encrypted password
  halt                 Halt the system
  license              Manage feature licenses
  logout               Forcibly end user's CLI login session
  malware-scan         Scan for malware
  personality-file     Execute commands related to personality of a device
  power-off            Power off the software on RE
  power-on             Power on the system
  process              Request operation on system process
  reboot               Reboot the system
  recover              Recover a specified volume
  scripts              Manage scripts (commit, op, event)
  snapshot             Create a normal Junos or a recovery snapshot
  software             Perform system software extension or upgrade
  storage              Request operation on system storage
  yang                 Perform YANG schema operations
  zeroize              Erase all data, including configuration and log files
alice02@srx1> request system    
```

`restart routing`:

```
alice02@srx1>                  restart ?
Possible completions:
> SDN-Telemetry        agent for all the telemetry sensors
> aaad                 AAAD process - Authentication, authorization and accounting
> aaasd                AAA Service Daemon
> adaptive-services    Adaptive services process
> alarm-management     Alarm management process
> analytics-agent      Analytics agent
> ancpd-service        Access Node Control Protocol Process
> app-engine-virtual-machine-management-service  App-engine virtual machine management process
> application-identification  Application-identification process
> audit-process        Audit process
> bbe-cpcdd-dbng       Captive-portal-content-delivery process for dBNG
> bbe-mib-daemon       Enhanced Session Management MIB Daemon process
> bbe-stats-daemon     Enhanced Session Management Statistics Daemon process
> captive-portal-content-delivery  Captive-portal-content-delivery process
> charged              Local persistent storage for CDR backup
> chassis-control      Chassis control process
> class-of-service     Class-of-service process
> clksyncd-service     Ethernet Clock Synchronization Process
> command-handler      Process container command handler
> cron                 Daemon to execute scheduled commands
> database-replication  Legacy (pre 17.2) Database Replication process
> datapath-trace-service  DATAPATH Trace process
> ddos-protection      Distributed Denial of Service Protection
> dhcp-service         Junos Dynamic Host Configuration Protocol process
> diameter-service     Diameter process
> disk-monitoring      Disk monitoring process
> dot1x-protocol       Port based Network Access Control
> dynamic-flow-capture  Dynamic flow capture service
> ethernet-connectivity-fault-management  Connectivity fault management process
> ethernet-link-fault-management  Ethernet OAM Link-Fault-Management process
> event-processing     Event processing process
> extensible-subscriber-services  Extensible Subscriber Services Manager Daemon
> fib-streaming        FIB Telemetry Streaming Daemon
> firewall             Firewall process
> fwa-service          Fixed Wireless Access Daemon Process
> general-authentication-service  General authentication process
  gracefully           Gracefully restart the process
> group-ipsec-key-management  Group Key Member daemon
> grpc-tunnel          GRPC Tunnel Daemon
> gstatd               geom-device performance monitoring daemon
> gtp-proxy-service    User Plane GTP Protocol Proxy
> health-mon           Health Monitoring and correlation for all platforms
> iccp-service         Inter-Chassis Communication Protocol daemon
> ilmi                 Integrated Local Management Interface process
  immediately          Immediately restart (SIGKILL) the process
> inline-monitoring    Inline Packet Monitoring Process
> interface-control    Interface control process
> ipsec-key-management  IPSec Key Management daemon
> jflow-service        Jflow process for embedded junos
> jnu-management       Junos node unifier process
> jsd                  JET Services Daemon
> jsqlsync             Juniper SQL Sync Daemon
> kernel-debug-streaming  Junos Kernel Debug streaming Daemon
> kernel-health-monitoring  Junos Kernel Health Monitoring Daemon
  kernel-replication   Kernel replication process
> l2-learning          Layer 2 address flooding and learning process
> l2cpd-service        Layer 2 Control Protocol process
> l2tp-universal-edge  Universal edge Layer 2 Tunneling Protocol daemon
> lacp                 Link Aggregation Control Protocol process
> license-service      Feature license management process
> link-management      Link management process
> mac-validation       MAC SA Validation
> mc-ae-config-check-service  MC-LAG Configuration Consistency Check daemon
> mgd-api              Management Daemon GRPC server
> mib-process          Management Information Base II process
> mobiled              Mobility process
> mosquitto            Mosquitto Broker for notification
> mountd-service       Service for NFS mounts requests
> mpls-traceroute      MPLS Periodic Traceroute process
> mspd                 Multiservice Daemon
> multicast-snooping   Multicast Snooping process
> na-grpc-server       Daemon providing gRPC interfaces
> na-mqttd             Message bus for telemetry
> nas                  Non-Access Stratum Server Daemon
> net-monitord         Traffic director service monitor process
> netproxy             netproxy service
> network-topology-export  Network Topology Abstraction Daemon
> nfsd-service         Remote NFS server
> ngap                 AGF Next Generation Application Protocol process
> nginx                Reverse proxy for grpc
> ngx-auth-meta-service  Authentication and metadata service for NGINX
> ngx-client-cache-service  Client cache service for nginx
> ngx-client-monitor-service  Client monitor service for nginx
> ngx-jnx-login-service  JNX Login service for NGINX
> ngx-login-service    Login service for NGINX
> pccd-service         Path Computation Client Daemon
> peer-selection-service  Peer selection service process
> pfcp-proxy-service   User Plane PFCP Protocol Proxy
> pgm                  Pragmatic General Multicast process
> pic-services-logging  PIC services logging process
> pki-service          PKI service daemon
> ppp                  PPP process
> ppp-service          Universal edge PPP process
> pppoe                Point-to-Point Protocol over Ethernet process
> redundancy-interface-process  Redundancy interface management process
> remote-device-management  Remote Device Management Daemon
> remote-operations    Remote operations process
> replication-client-service  Replication Client Process
> replication-server-service  Replication Server Process
> resource-management  Resource Management and Packet Steering
> rest-api             REST Application Programming Interface process
  routing              Routing protocol process
> rpd-telemetry-daemon  RPD Telemetry Applications
> sae-gateway-user-plane-agent-daemon  SAE gateway user plane agent daemon
> sampling             Traffic sampling control process
> sampling-route-record  Sampling route record process
> satellite-control-plane-process  Satellite Control Plane Process
> satellite-discovery-provisioning-process  Satellite Discovery and Provisioning Process
> satellite-platform-management-process  Satellite Platform Management Process
> scc-chassisd         SCC Chassisd Process
> secure-neighbor-discovery  Secure Neighbor Discovery Protocol process
> service-deployment   Service Deployment System (SDX) process
> sflow-service        Flow Sampling (Sflow) Daemon
> slaacd               SLAAC process
> smg-service          Enhanced Session Management process
> snmp                 Simple Network Management Protocol process
  soft                 Soft reset (SIGHUP) the process
> srd                  Services Redundancy daemon
> static-subscribers   Static Subscriber Client
> statistics-service   Packet Forwarding Engine statistics management process
> subscriber-helper-service  Enhanced BBE helper user plane process
> subscriber-management  Subscriber management process
> subscriber-management-helper  Subscriber management helper process
> subscriber-statistics-service  Statistics Services Daemon for dBNG
> sysd                 Telemetry System Daemon
> system-monitor       System monitoring and heuristic process
> tcp-forwarding       TCP Forwarding Daemon
> traffic-dird         Traffic director process
> transport-control    Transport control process
> tunnel-oamd          Tunnel OAM process
> ui-pubd              Mosquitto pub client process
> up-smg-service       Enhanced Session Management user plane process
> upm-service          User Plane Manager for dBNG
> url-filterd          URL Filtering process
> video-monitoring     Video Monitoring Process
> virtual-node-fabric  Virtual Node Fabric Protocol
> virtual-node-provisioning  Virtual Node Provisioning Protocol
> vrrp                 Virtual Router Redundancy Protocol process
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
Use 'request system snapshot' to make a snapshot of the running system
on the hard disk drive.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: clear, clear amt, clear ancp, clear arp, clear auto-bandwidth, clear auto-configuration, clear bfd, clear bgp, clear bridge, clear captive-portal, clear cli, clear database-replication, clear ddos-protection, clear dhcp, clear dhcp-security, clear dhcpv6, clear diameter, clear dot1x, clear dynamic-tunnels, clear error, clear esis, clear evpn, clear express-segments, clear extensible-subscriber-services, clear firewall, clear forwarding-options, clear helper, clear igmp, clear ike, clear ilmi, clear interfaces, clear ipsec, clear ipv6, clear isis, clear l2-learning, clear l2circuit, clear ldp, clear lldp, clear loop-detect, clear mac-vrf, clear mld, clear mpls, clear msdp, clear multicast, clear mvrp, clear network-access, clear oam, clear ospf, clear ospf3, clear performance-monitoring, clear pfe, clear pim, clear poe, clear ppp, clear pppoe, clear protection-group, clear ptp, clear remote-device-management, clear rip, clear ripng, clear rsvp, clear sflow, clear shmlog, clear snmp, clear spanning-tree, clear synchronous-ethernet, clear system, clear tcp-forwarding, clear user-plane, clear validation, clear virtual-chassis, clear vpls, clear vrrp, file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request ipsec, request jdaf, request lacp, request mpls, request network-access, request protection-group, request services, request session, save, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dhcp-security, test dhcp-service, test l2-learning, test rt-proxy, test unified-edge

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
alice03@srx1>          request system
                      ^
syntax error, expecting <command>.
alice03@srx1> request system   ?
No valid completions
alice03@srx1> request system   
```

`restart routing`:

```
alice03@srx1>                 restart
              ^
unknown command.
alice03@srx1> restart   ?
No valid completions
alice03@srx1> restart   
```

`show configuration system host-name`:

```
alice03@srx1>          show
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
Use re0: and re1: to save output to the other routing engine. For
example, 'show route summary | save re1:filename'.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, mtrace, mtrace from-source, mtrace logical-system, mtrace monitor, mtrace routing-instance, mtrace to-gateway, op, op invoke-debugger, op url, ping, ping atm, ping bypass-routing, ping ce-ip, ping clns, ping count, ping detail, ping do-not-fragment, ping ethernet, ping gateway, ping inet, ping inet6, ping interface, ping interval, ping logical-system, ping mac-address, ping mpls, ping no-resolve, ping overlay, ping pattern, ping rapid, ping record-route, ping routing-instance, ping size, ping source, ping srv6, ping strict, ping tos, ping ttl, ping verbose, ping vpls, ping wait, probe, probe by-address, probe by-index, probe by-name, probe by-remote-address, probe count, probe detail, probe inet, probe inet6, probe interface, probe interval, probe logical-system, probe routing-instance, probe source, probe tos, probe ttl, probe wait, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request ipsec, request jdaf, request lacp, request network-access, request protection-group, request routing-engine, request services, request session, save, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, ssh, ssh bypass-routing, ssh commands-to-execute, ssh extensive, ssh inet, ssh inet6, ssh interface, ssh logical-system, ssh routing-instance, ssh source, ssh v2, ssh verbose, start, telnet, telnet bypass-routing, telnet inet, telnet inet6, telnet interface, telnet logical-system, telnet no-resolve, telnet port, telnet routing-instance, telnet source, test, test aaa, test dhcp-security, test dhcp-service, test l2-learning, test rt-proxy, test unified-edge, traceroute, traceroute as-number-lookup, traceroute bypass-routing, traceroute ce-ip, traceroute clns, traceroute ethernet, traceroute extension, traceroute gateway, traceroute inet, traceroute inet6, traceroute interface, traceroute logical-system, traceroute monitor, traceroute mpls, traceroute next-hop, traceroute no-resolve, traceroute overlay, traceroute port, traceroute propagate-ttl, traceroute routing-instance, traceroute source, traceroute srv6, traceroute tos, traceroute ttl, traceroute wait

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
alice04@srx1>          request system
                      ^
syntax error, expecting <command>.
alice04@srx1> request system   ?
No valid completions
alice04@srx1> request system   
```

`restart routing`:

```
alice04@srx1>                 restart
              ^
unknown command.
alice04@srx1> restart   ?
No valid completions
alice04@srx1> restart   
```

`show configuration system host-name`:

```
alice04@srx1>          show
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
Use 'request system software validate' to validate the incoming software
against the current configuration without impacting the running system.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, monitor, monitor ethernet, monitor interface, monitor label-switched-path, monitor list, monitor mpls, monitor start, monitor static-lsp, monitor stop, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request ipsec, request jdaf, request lacp, request network-access, request protection-group, request services, request session, save, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dhcp-security, test dhcp-service, test l2-learning, test rt-proxy, test unified-edge

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
  ethernet             Start ethernet performance measurement
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  mpls                 Monitor MPLS LSPs
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
alice05@srx1> monitor    
```

`request system reboot`:

```
alice05@srx1>           request system
                      ^
syntax error, expecting <command>.
alice05@srx1> request system   ?
No valid completions
alice05@srx1> request system   
```

`restart routing`:

```
alice05@srx1>                 restart
              ^
unknown command.
alice05@srx1> restart   ?
No valid completions
alice05@srx1> restart   
```

`show configuration system host-name`:

```
alice05@srx1>          show
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
Use the 'help tip cli' to see more CLI tips.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request flight-recorder, request interface, request ipsec, request jdaf, request lacp, request network-access, request protection-group, request services, request session, request snmp, request validation, save, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, show, show access-cac, show access-security, show accounting, show agent, show amt, show ancp, show aps, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show bier, show bridge, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show congestion-protection, show connections, show database-replication, show ddos-protection, show dhcp, show dhcp-security, show dhcpv6, show diameter, show dot1x, show dual-phase-bootup-status, show dynamic-profile, show dynamic-tunnels, show ephemeral-configuration, show esis, show event-options, show evpn, show express-segments, show extensible-subscriber-services, show extension-provider, show extension-service, show fib-streaming, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show iccp, show igmp, show ike, show ilmi, show ingress-replication, show interfaces, show ipsec, show ipv6, show isis, show jdaf, show l2-learning, show l2circuit, show l2cpd, show l2pt, show l2vpn, show lacp, show layer2-control, show ldp, show link-management, show lldp, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show mvrp, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show path-computation-client, show performance-monitoring, show pfe, show pim, show poe, show policy, show ppp, show pppoe, show programmable-rpd, show protection-group, show remote-device-management, show rip, show ripng, show route, show rsvp, show sap, show security, show services, show sflow, show shmlog, show snmp, show spanning-tree, show spring-traffic-engineering, show srv6, show ssl-certificates, show static-subscribers, show subscribers, show system, show task, show tcp-forwarding, show ted, show unified-edge, show user-plane, show v4ov6-tunnels, show validation, show version, show virtual-chassis, show vpls, show vrrp, start, test, test aaa, test dhcp-security, test dhcp-service, test interface, test l2-learning, test msdp, test policy, test rib-sharding, test rt-proxy, test services, test unified-edge

`show version`:

```
 
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
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice06@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 04:08:54 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 04:05:46 UTC (00:03:08 ago)
Protocols started: 2026-09-25 04:06:41 UTC (00:02:13 ago)
Last configured: 2026-09-25 04:07:01 UTC (00:01:53 ago) by breakglass
 4:08AM  up 3 mins, 1 users, load averages: 0.81, 0.66, 0.31

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
alice06@srx1>          request system
                      ^
syntax error, expecting <command>.
alice06@srx1> request system   ?
No valid completions
alice06@srx1> request system   
```

`restart routing`:

```
alice06@srx1>                 restart
              ^
unknown command.
alice06@srx1> restart   ?
No valid completions
alice06@srx1> restart   
```

`show configuration system host-name`:

```
alice06@srx1>          show configuration system
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
Use the 'monitor' command to monitor system log files for changes.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load dhcp-security-snoop, monitor, monitor ethernet, monitor interface, monitor label-switched-path, monitor list, monitor mpls, monitor start, monitor static-lsp, monitor stop, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request ipsec, request jdaf, request lacp, request mpls, request network-access, request path-computation-client, request protection-group, request security, request services, request session, request unified-edge, request virtual-chassis, save, save dhcp-security-snoop, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dhcp-security, test dhcp-service, test l2-learning, test rt-proxy, test unified-edge

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
  ethernet             Start ethernet performance measurement
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  mpls                 Monitor MPLS LSPs
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
alice07@srx1> monitor    
```

`request system reboot`:

```
alice07@srx1>           request system
                      ^
syntax error, expecting <command>.
alice07@srx1> request system   ?
No valid completions
alice07@srx1> request system   
```

`restart routing`:

```
alice07@srx1>                 restart
              ^
unknown command.
alice07@srx1> restart   ?
No valid completions
alice07@srx1> restart   
```

`show configuration system host-name`:

```
alice07@srx1>          show
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
Use 'commit confirmed' to ensure that configuration changes do not
disconnect the router from the network.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, load dhcp-security-snoop, monitor, monitor ethernet, monitor interface, monitor label-switched-path, monitor list, monitor mpls, monitor start, monitor static-lsp, monitor stop, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request flight-recorder, request interface, request ipsec, request jdaf, request lacp, request mpls, request network-access, request path-computation-client, request protection-group, request security, request services, request session, request snmp, request unified-edge, request validation, request virtual-chassis, save, save dhcp-security-snoop, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, show, show access-cac, show access-security, show accounting, show agent, show amt, show ancp, show aps, show arp, show as-path, show authentication-whitelist, show auto-bandwidth, show auto-configuration, show backup-selection, show bfd, show bgp, show bier, show bridge, show captive-portal, show chassis, show class-of-service, show cli, show configuration, show congestion-protection, show connections, show database-replication, show ddos-protection, show dhcp, show dhcp-security, show dhcpv6, show diameter, show dot1x, show dual-phase-bootup-status, show dynamic-profile, show dynamic-tunnels, show ephemeral-configuration, show esis, show event-options, show evpn, show express-segments, show extensible-subscriber-services, show extension-provider, show extension-service, show fib-streaming, show firewall, show flexible-tunnels, show flight-recorder, show forwarding-options, show helper, show hfrr, show iccp, show igmp, show ike, show ilmi, show ingress-replication, show interfaces, show ipsec, show ipv6, show isis, show jdaf, show l2-learning, show l2circuit, show l2cpd, show l2pt, show l2vpn, show lacp, show layer2-control, show ldp, show link-management, show lldp, show log, show loop-detect, show mac-rewrite, show mac-vrf, show mld, show mpls, show msdp, show multi-chassis, show multicast, show mvpn, show mvrp, show network-access, show network-agent, show nonstop-routing, show ntp, show oam, show ospf, show ospf3, show path-computation-client, show performance-monitoring, show pfe, show pim, show poe, show policer, show policy, show ppp, show pppoe, show programmable-rpd, show protection-group, show remote-device-management, show rip, show ripng, show route, show rsvp, show sap, show security, show services, show sflow, show shmlog, show snmp, show spanning-tree, show spring-traffic-engineering, show srv6, show ssl-certificates, show static-subscribers, show subscribers, show system, show task, show tcp-forwarding, show ted, show unified-edge, show user-plane, show v4ov6-tunnels, show validation, show version, show virtual-chassis, show vpls, show vrrp, start, test, test aaa, test dhcp-security, test dhcp-service, test interface, test l2-learning, test msdp, test policy, test rib-sharding, test rt-proxy, test services, test unified-edge

`show version`:

```
 
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
JUNOS OS network modules [20240604.39c9257_builder_stable_12_234]
JUNOS OS crypto [20240604.39c9257_builder_stable_12_234]
JUNOS OS boot-ve files [20240604.39c9257_builder_stable_12_234]
JUNOS na telemetry [23.4R2-S2.1]
JUNOS vmguest  [20240821.090638_builder_junos_234_r2_s2]
JUNOS vmguest (NFX-3) [20240821.090638_builder_junos_234_r2_s2]
JUNOS full sysmond [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs compat32 [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx runtime [20240821.090638_builder_junos_234_r2_s2]
JUNOS RPD Telemetry Application [23.4R2-S2.1]
JUNOS python routing scripts for consistency check in RIB/FIB/PFE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-basic [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing mpls-oam-advanced [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing lsys [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-internal [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing controller-external [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing 32-bit Compatible Version [20240821.090638_builder_junos_234_r2_s2]
JUNOS Routing aggregated [20240821.090638_builder_junos_234_r2_s2]
Redis [20240821.090638_builder_junos_234_r2_s2]
JUNOS probe utility [20240821.090638_builder_junos_234_r2_s2]
JUNOS common platform support [20240821.090638_builder_junos_234_r2_s2]
JUNOS Openconfig [23.4R2-S2.1]
JUNOS mtx network modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx modules [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx libs [20240821.090638_builder_junos_234_r2_s2]
JUNOS L2 RSI Scripts [20240821.090638_builder_junos_234_r2_s2]
JUNOS SQL Sync Daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS mtx Data Plane Crypto Support [20240821.090638_builder_junos_234_r2_s2]
JUNOS daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS mx daemons [20240821.090638_builder_junos_234_r2_s2]
JUNOS Broadband Edge User Plane Apps [23.4R2-S2.1]
JUNOS appidd-mx application-identification daemon [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Linux Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Simulation Package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services URL Filter package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TLB Service PIC package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Telemetry [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services TCP-LOG [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SSL [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services SOFTWIRE [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Stateful Firewall [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RTCOM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services RPM [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services PCEF package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services NAT [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Mobile Subscriber Service Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services MobileNext Software package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Logging Report Framework package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services LL-PDF Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Jflow Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Deep Packet Inspection package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IPSec [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services IDS [20240821.090638_builder_junos_234_r2_s2]
JUNOS IDP Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services HTTP Content Management package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services DNS Filter package (i386) [20240821.090638_builder_junos_234_r2_s2] 
JUNOS Services Crypto [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Captive Portal and Content Delivery Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services COS [20240821.090638_builder_junos_234_r2_s2]
JUNOS AppId Services [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services Application Level Gateways [20240821.090638_builder_junos_234_r2_s2]
JUNOS Services AACL Container package [20240821.090638_builder_junos_234_r2_s2]
JUNOS Extension Toolkit [20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS Juniper Malware Removal Tool (JMRT) Test [1.0.0+20240821.090638_builder_junos_234_r2_s2]
JUNOS J-Insight [20240821.090638_builder_junos_234_r2_s2]
JUNOS Online Documentation [20240821.090638_builder_junos_234_r2_s2]
JUNOS jail runtime [20240604.39c9257_builder_stable_12_234]
JUNOS FIPS mode utilities [20240821.090638_builder_junos_234_r2_s2]
JUNOS dsa [20240821.090638_builder_junos_234_r2_s2]

alice08@srx1> 
```

`show system uptime`:

```
 
Current time: 2026-09-25 04:09:14 UTC
Time Source:  LOCAL CLOCK 
System booted: 2026-09-25 04:05:46 UTC (00:03:28 ago)
Protocols started: 2026-09-25 04:06:41 UTC (00:02:33 ago)
Last configured: 2026-09-25 04:07:01 UTC (00:02:13 ago) by breakglass
 4:09AM  up 3 mins, 1 users, load averages: 0.77, 0.66, 0.31

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
  ethernet             Start ethernet performance measurement
  interface            Show interface traffic
  label-switched-path  Show label-switched-path traffic
  list                 Show status of monitored files
  mpls                 Monitor MPLS LSPs
  start                Start showing log file in real time
  static-lsp           Show static label-switched-path traffic
  stop                 Stop showing log file in real time
alice08@srx1> monitor    
```

`request system reboot`:

```
alice08@srx1>           request system
                      ^
syntax error, expecting <command>.
alice08@srx1> request system   ?
No valid completions
alice08@srx1> request system   
```

`restart routing`:

```
alice08@srx1>                 restart
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
Use the 'help tip cli' to see more CLI tips.

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
LOCK_FILE
appidd_cust_app_trace
appidd_trace_debug
ex_autod_config
ex_autod_rollback_cfg
krt_rpf_filter.txt
mmcq_mmdb_rep_mmcq_ti0
mmcq_sdb_bbe_mmcq
pc /
pfe_debug_commands
pics/
pkg_cleanup.log.err
planeDb.log
rtsdb/
sd-upgrade/

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

Completion: file, file change-permission, file checksum, file compare, file compress, file copy, file delete, file delete-directory, file link, file list, file make-directory, file no-check-certificate, file no-stage, file rename, file routing-instance, file show, file source-address, file staging-directory, help, help apropos, help reference, help syslog, help tip, help topic, load, op, op invoke-debugger, op url, quit, request, request access-security, request ancp, request auto-configuration, request chassis, request dhcp, request dhcpv6, request interface, request ipsec, request jdaf, request lacp, request network-access, request protection-group, request services, request session, save, scp, scp extensive, scp recursive, scp routing-instance, scp source-address, set, set cli, start, test, test aaa, test dhcp-security, test dhcp-service, test l2-learning, test rt-proxy, test unified-edge

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


## Reading (controller, 2026-09-25; added by hand after the run, not generated)

- **Carve-out candidates beyond `show configuration`, by completion only.** The `view view-configuration` pair's `Completion:` line offers `show firewall`, `show log` and `show policer`. None of `view`, `view-configuration` or `none` offers them, and the same holds on both images. So view-configuration withholds them from `view` alone. This is completion evidence: no probe ran `show log`. Task 14 carries them as view-configuration carve-outs. Where a carve-out is unmeasured, the reach widens conservatively. A rerun of this test prints the pair's words beyond its parts.
- **Bare `show configuration` under `view` alone: not probed.** Under `view`, the caret falls on the hierarchy word (`system`, `routing-instances`, `interfaces`), not on `configuration`. What the bare command prints under `view` is unmeasured.
- **R-M2 line:** "(`configure` ran): none." means no class. A rerun prints "no class".
- **Refusals verified by hand:** each `view` carve-out cell above is `syntax error.`, and each `quit`/`exit` under `deny-commands=^.*$` is `^ unknown command.` with a prompt back. Neither verdict rests on an empty read. The test now requires a refusal marker for both (task-3 review I1).
- **Raw `?` listings:** this run recorded only the parsed words (`Completion:`). A rerun records the raw top-level, `request ?`, `test ?` and `set ?` listings for each class.
- **How the reach reads (lead's ruling):** the baseline's top-level words are held whole (`request **`), and a bit's rules under those words stay per sub-word. The union with the baseline makes the whole word reachable anyway.
