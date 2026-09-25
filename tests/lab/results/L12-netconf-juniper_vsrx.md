# L12-netconf — juniper_vsrx

- **Date measured:** 2026-09-25
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L12-netconf-juniper_vsrx.pcap` — 1544 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L12-netconf-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
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
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790313128" junos:changed-localtime="2026-09-25 05:12:08 UTC">
    <version>21.4R3.15</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
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
                    <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
                </authentication>
… (174 more lines)
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790313128" junos:changed-localtime="2026-09-25 05:12:08 UTC">
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
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
                    <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
                </authentication>
            </user>
… (131 more lines)
```

`<command>show configuration</command>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
<configuration-information>
<configuration-output>
## Last commit: 2026-09-25 05:12:08 UTC by breakglass
version 21.4R3.15;
system {
    host-name srx1;
    root-authentication {
        plain-text-password-value /* SECRET-DATA */; ## SECRET-DATA
        ## Warning: missing mandatory statement(s): 'encrypted-password'
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
                plain-text-password-value /* SECRET-DATA */; ## SECRET-DATA
            }
        }
        user breakglass {
            uid 2002;
… (152 more lines)
```

`<get-software-information/>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4">
<software-information>
<host-name>srx1</host-name>
<product-model>vSRX</product-model>
<product-name>vsrx</product-name>
<junos-version>21.4R3.15</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-xen-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>zoneinfo</name>
<package-name>os-zoneinfo-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>os-libs-compat32</name>
<package-name>os-libs-compat32-12-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]</comment>
… (218 more lines)
```

### deny

`<get-configuration/>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790313128" junos:changed-localtime="2026-09-25 05:12:08 UTC">
    <version>21.4R3.15</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
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
                    <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
                </authentication>
… (174 more lines)
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="2">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790313128" junos:changed-localtime="2026-09-25 05:12:08 UTC">
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
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
                    <plain-text-password-value>/* SECRET-DATA */</plain-text-password-value>
                </authentication>
            </user>
… (131 more lines)
```

`<command>show configuration</command>`:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="3">
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
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R0/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="4">
<software-information>
<host-name>srx1</host-name>
<product-model>vSRX</product-model>
<product-name>vsrx</product-name>
<junos-version>21.4R3.15</junos-version>
<package-information>
<name>os-kernel</name>
<package-name>os-kernel-xen-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS Kernel 64-bit XEN [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>os-libs</name>
<package-name>os-libs-12-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS libs [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>os-runtime</name>
<package-name>os-runtime-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS runtime [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>zoneinfo</name>
<package-name>os-zoneinfo-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS time zone information [20220817.43c4e23_builder_stable_12_214]</comment>
</package-information>
<package-information>
<name>os-libs-compat32</name>
<package-name>os-libs-compat32-12-x86-64-20220817.43c4e23_builder_stable_12_214</package-name>
<comment>JUNOS OS libs compat32 [20220817.43c4e23_builder_stable_12_214]</comment>
… (218 more lines)
```

### fail-closed, local_user_name

`<get-configuration/>`:

```
no session: alice06: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1293 bytes)
paired control after (`[]`): hello (1293 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
no session: alice06: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1293 bytes)
paired control after (`[]`): hello (1293 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

`<command>show configuration</command>`:

```
no session: alice06: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1293 bytes)
paired control after (`[]`): hello (1293 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

`<get-software-information/>`:

```
no session: alice06: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account   account  ]
paired control before (`[]`): hello (1293 bytes)
paired control after (`[]`): hello (1293 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

### fail-closed, user_permissions

`<get-configuration/>`:

```
no session: alice09: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

`<get-configuration><configuration><system/></configuration></get-configuration>`:

```
no session: alice09: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

`<command>show configuration</command>`:

```
no session: alice09: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

`<get-software-information/>`:

```
no session: alice09: the device sent no NETCONF hello: the NETCONF channel closed: EOF (); port49d recorded [redeem  token_redeemed authorize_session  context_matched account   account   account   account   account   account   account   account  ]
paired control before (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)
paired control after (`["local-user-name=p49-nc-none", "user-permissions=view view-configuration"]`): hello (1297 bytes)

the device's log:
show log messages | last 60 | no-more 
error: could not resolve file: messages
---(more 100%)---                                        
breakglass@srx1> 
```

