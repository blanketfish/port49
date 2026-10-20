# L12-netconf — juniper_vjunos-router

- **Date measured:** 2026-10-20
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L12-netconf-juniper_vjunos-router.pcap` — 1506 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L12-netconf-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `30728fa3429a1beea98251be87a16837056daa55`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL12JunosNetconf$`

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
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1792455039" junos:changed-localtime="2026-10-20 00:10:39 UTC">
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
… (202 more lines)
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1792455039" junos:changed-localtime="2026-10-20 00:10:39 UTC">
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
… (150 more lines)
```

`<command>show configuration</command>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
<configuration-information>
<configuration-output>
## Last commit: 2026-10-20 00:10:39 UTC by breakglass
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
… (170 more lines)
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
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1792455039" junos:changed-localtime="2026-10-20 00:10:39 UTC">
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
… (202 more lines)
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1792455039" junos:changed-localtime="2026-10-20 00:10:39 UTC">
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
… (150 more lines)
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

Every RPC:

```
no session: alice04: the device sent no NETCONF hello (sent "error: unknown command: xml-mode\n\nerror: permission denied: netconf"): the NETCONF channel closed: EOF (); port49d recorded [redeem permit token_redeemed authorize_session permit context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1543 bytes)
paired control after (`[]`): hello (1543 bytes)
```

### fail-closed, user_permissions

Every RPC:

```
no session: alice07: the device sent no NETCONF hello (sent "error: unknown command: xml-mode\n\nerror: permission denied: netconf"): the NETCONF channel closed: EOF (); port49d recorded [redeem permit token_redeemed authorize_session permit context_matched account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1547 bytes)
```

