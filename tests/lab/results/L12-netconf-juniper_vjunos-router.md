# L12-netconf — juniper_vjunos-router

- **Date measured:** 2026-09-25
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L12-netconf-juniper_vjunos-router.pcap` — 1435 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L12-netconf-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Over TACACS+ on `junos-exec`: whether a wire deny-commands, and decision 26's fail-closed reply, bind a NETCONF RPC opened with the same token and reply, `<get-configuration>` and `<get-software-information>` beside `show configuration` and `show version` (spec §15 L12; decision 27).

## Observation

The classes were committed: commit complete.

```
set system login class p49-nc-ro permissions [ view view-configuration ]
set system login user p49-nc-ro class p49-nc-ro
set system login class p49-nc-none idle-timeout 60
set system login user p49-nc-none class p49-nc-none
```

| session | reply | why | <get-configuration/> | <get-configuration><configuration><system/></configuration></get-configuration> | <command>show configuration</command> | <get-software-information/> |
|---|---|---|---|---|---|---|
| control | `["local-user-name=p49-nc-ro"]` | view and view-configuration, no regex: every RPC runs | ran | ran | ran | ran |
| deny | `["local-user-name=p49-nc-ro", "deny-commands=^( *show +configuration( .*)? *(\\\|.*)?\| *show +version *(\\\|.*)?)$"]` | the same class under a deny naming both commands | ran | ran | refused | ran |
| fail-closed, local_user_name | `["deny-commands=^.*$"]` | decision 26's reply with no template: the session lands in remote's class | refused: the channel closed before hello | refused: the channel closed before hello | refused: the channel closed before hello | refused: the channel closed before hello |
| fail-closed, user_permissions | `["local-user-name=p49-nc-none", "user-permissions=view view-configuration", "deny-commands=^.*$"]` | decision 26's reply with bits over a bitless template | refused: the channel closed before hello | refused: the channel closed before hello | refused: the channel closed before hello | refused: the channel closed before hello |

### Read off the table

- deny-commands and the fail-closed reply bind NETCONF RPCs: false (true only where the control ran every RPC and every other session refused every one; set 1.1.0 takes it as bound only where both images say true)

### control

`<get-configuration/>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790312052" junos:changed-localtime="2026-09-25 04:54:12 UTC">
    <version>23.4R2-S2.1</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>/* SECRET-DATA */</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-nc-none</name>
                <idle-timeout>60</idle-timeout>
            </class>
            <class>
                <name>p49-nc-ro</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
                <uid>2000</uid>
                <class>super-user</class>
                <authentication>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
… (183 more lines)
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790312052" junos:changed-localtime="2026-09-25 04:54:12 UTC">
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>/* SECRET-DATA */</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-nc-none</name>
                <idle-timeout>60</idle-timeout>
            </class>
            <class>
                <name>p49-nc-ro</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
                <uid>2000</uid>
                <class>super-user</class>
                <authentication>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
            </user>
… (131 more lines)
```

`<command>show configuration</command>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
<configuration-information>
<configuration-output>
## Last commit: 2026-09-25 04:54:12 UTC by breakglass
version 23.4R2-S2.1;
system {
    host-name srx1;
    root-authentication {
        encrypted-password /* SECRET-DATA */; ## SECRET-DATA
    }
    login {
        class p49-nc-none {
            idle-timeout 60;
        }
        class p49-nc-ro {
            permissions [ view view-configuration ];
        }
        class p49-readonly {
            permissions [ view view-configuration ];
        }
        user admin {
            uid 2000;
            class super-user;
            authentication {
                encrypted-password /* SECRET-DATA */; ## SECRET-DATA
            }
        }
        user breakglass {
            uid 2002;
            class super-user;
… (158 more lines)
```

`<get-software-information/>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4">
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
</package-information>
<package-information>
<name>zoneinfo</name>
<package-name>os-zoneinfo-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>netstack</name>
<package-name>junos-net-prd-x86-64-20240821.090638_builder_junos_234_r2_s2</package-name>
<comment>JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]</comment>
… (418 more lines)
```

### deny

`<get-configuration/>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790312052" junos:changed-localtime="2026-09-25 04:54:12 UTC">
    <version>23.4R2-S2.1</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>/* SECRET-DATA */</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-nc-none</name>
                <idle-timeout>60</idle-timeout>
            </class>
            <class>
                <name>p49-nc-ro</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
                <uid>2000</uid>
                <class>super-user</class>
                <authentication>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
… (183 more lines)
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790312052" junos:changed-localtime="2026-09-25 04:54:12 UTC">
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password>/* SECRET-DATA */</encrypted-password>
        </root-authentication>
        <login>
            <class>
                <name>p49-nc-none</name>
                <idle-timeout>60</idle-timeout>
            </class>
            <class>
                <name>p49-nc-ro</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <user>
                <name>admin</name>
                <uid>2000</uid>
                <class>super-user</class>
                <authentication>
                    <encrypted-password>/* SECRET-DATA */</encrypted-password>
                </authentication>
            </user>
… (131 more lines)
```

`<command>show configuration</command>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
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
```

`<get-software-information/>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4">
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
</package-information>
<package-information>
<name>zoneinfo</name>
<package-name>os-zoneinfo-20240604.39c9257_builder_stable_12_234</package-name>
<comment>JUNOS OS time zone information [20240604.39c9257_builder_stable_12_234]</comment>
</package-information>
<package-information>
<name>netstack</name>
<package-name>junos-net-prd-x86-64-20240821.090638_builder_junos_234_r2_s2</package-name>
<comment>JUNOS network stack and utilities [20240821.090638_builder_junos_234_r2_s2]</comment>
… (418 more lines)
```

### fail-closed, local_user_name

`<get-configuration/>`:

```
no session: alice04: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1543 bytes)
paired control after (`[]`): hello (1543 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
no session: alice04: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1543 bytes)
paired control after (`[]`): hello (1543 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

`<command>show configuration</command>`:

```
no session: alice04: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1543 bytes)
paired control after (`[]`): hello (1543 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

`<get-software-information/>`:

```
no session: alice04: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1543 bytes)
paired control after (`[]`): hello (1543 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

### fail-closed, user_permissions

`<get-configuration/>`:

```
no session: alice07: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
no session: alice07: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

`<command>show configuration</command>`:

```
no session: alice07: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

`<get-software-information/>`:

```
no session: alice07: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)

the device's log:
show log messages | last 60 | no-more 
Aug 21 12:16:59   jlaunchd[29682]: process-monitor (PID 29847) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: smg-service (PID 29850) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: up-smg-service (PID 29854) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: application-identification (PID 29864) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: charged (PID 29868) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: kernel-health-monitoring (PID 29869) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: system-monitor (PID 29872) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: dot1x-protocol (PID 29881) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: bbe-stats-daemon (PID 29887) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-client-service (PID 29890) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: replication-server-service (PID 29894) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: license-service (PID 29900) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: aaasd (PID 29902) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: na-mqttd (PID 29908) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: mgd-api (PID 29911) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: jsqlsync (PID 29913) terminate signal 15 sent
Aug 21 12:16:59   jlaunchd[29682]: cron (PID 30751) terminate signal 15 sent
Aug 21 12:17:03   jlaunchd[29682]: cron (PID 30751) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: jsqlsync (PID 29913) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mgd-api (PID 29911) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: na-mqttd (PID 29908) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: aaasd (PID 29902) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: license-service (PID 29900) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: bbe-stats-daemon (PID 29887) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: dot1x-protocol (PID 29881) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: system-monitor (PID 29872) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: kernel-health-monitoring (PID 29869) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: charged (PID 29868) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: application-identification (PID 29864) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: up-smg-service (PID 29854) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: smg-service (PID 29850) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: process-monitor (PID 29847) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mountd-service (PID 29841) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-management (PID 29839) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: pmcd (PID 29828) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: rpcbind-service (PID 29825) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: SDN-Telemetry (PID 29816) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: transport-control (PID 29815) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: gstatd (PID 29814) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: shm-rtsdbd (PID 29810) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: stats-agent (PID 29809) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: subscriber-management (PID 29808) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: ethernet-link-fault-management (PID 29807) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: clksyncd-service (PID 29806) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: neighbor-liveness (PID 29805) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: internal-routing-service (PID 29802) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: firewall (PID 29792) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: periodic-packet-services (PID 29784) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: statistics-service (PID 29781) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntpsync (PID 29780) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: sntp (PID 29779) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: inet-process (PID 29773) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: mib-process (PID 29771) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: snmp (PID 29770) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: management (PID 29769) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: craft-control (PID 29768) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: alarm-control (PID 29767) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: interface-control (PID 29738) exited with status=0 Normal Exit
Aug 21 12:17:03   jlaunchd[29682]: tnp-process (PID 29737) exited with status=0 Normal Exit
---(more 100%)---                                        Aug 21 12:17:03   jlaunchd[29682]: bslockd (PID 29736) exited with status=0 Normal Exit

breakglass@srx1> 
```

