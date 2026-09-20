# netconf — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/netconf-arista_eos.pcap` — 612 packets to or from the device, countable with `tcpdump -r tests/lab/captures/netconf-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** NETCONF over SSH (port 22)

## Claim

Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does, whether any authorization request is sent for the session or for an `<edit-config>` and with what `service`, `cmd` and `cmd-arg`, what `port` and `rem_addr` contain, what accounting arrives, and whether a second session with the same token re-authenticates.

## Observation

Transport measured: **NETCONF over SSH (port 22)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| session 1: open and `get-config running` | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 360ms |
| session 2: open again with the same token | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 160ms |
| session 3: `edit-config` and commit | `netconf02` | yes | 1 | 2 | 5 | start=2, stop=8 | 580ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `netconf01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication over this transport.

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, username, credential_sha256)` rather than out of the store — the same credential hashes to the same key, so a repeat finds its own receipt. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **`receipt_ttl`**: past it, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: `NETCONF`, `ssh`
- `rem_addr`: `172.100.100.1 56774 10.0.0.15 22`, `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`. Nothing keys on `port` any more (spec §13, decision 15), so a transport reporting the same constant as SSH no longer costs anything; what these values are still for is accounting annotation and the record an operator reads at 3am.

### How many TCP connections the device opened to port49d

**60** TCP connection(s) were opened toward port49d during this test, from source port(s) 41796, 41808, 41818, 41820, 41822, 41824, 51416, 51418, 51430, 51438, 51440, 51452, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/netconf-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**session 1: open and `get-config running`** (as `netconf01`)

```
2026-09-20T18:13:38.093Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T18:13:38.257Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=49
    accounting AV: service=shell
    accounting AV: start_time=1789928017
    accounting AV: timezone=UTC
2026-09-20T18:13:38.293Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:13:38.337Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T18:13:38.344Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=50
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928017
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T18:13:38.423Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=49
    accounting AV: service=shell
    accounting AV: start_time=1789928017
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T18:13:37.641518996Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapQos</type></cmapType><cmapType><type>mapControlPlane</type><cmap><name>copp-system-iplocking</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl0</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vxlan-encapsulation</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cvx</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3lpmoverflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmcmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bpdu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-glean</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipv6nd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-mba</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-ttl01</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-PimPtp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mac-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp-inspect</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mtu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mlag</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2forward-includes-cpu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cfm</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-nat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lacp</name><matchCondition>matchConditionAny</matchCondition></cmap><cma
... (truncated for this note; the full answer is in the test log)
```

**session 2: open again with the same token** (as `netconf01`)

```
2026-09-20T18:13:48.476Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T18:13:48.483Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=51
    accounting AV: service=shell
    accounting AV: start_time=1789928028
    accounting AV: timezone=UTC
2026-09-20T18:13:48.520Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:13:48.563Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T18:13:48.570Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=52
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928028
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T18:13:48.608Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=51
    accounting AV: service=shell
    accounting AV: start_time=1789928028
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T18:13:48.007171385Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapQos</type></cmapType><cmapType><type>mapControlPlane</type><cmap><name>copp-system-iplocking</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl0</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vxlan-encapsulation</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cvx</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3lpmoverflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmcmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bpdu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-glean</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipv6nd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-mba</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-ttl01</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-PimPtp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mac-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp-inspect</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mtu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mlag</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2forward-includes-cpu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cfm</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-nat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lacp</name><matchCondition>matchConditionAny</matchCondition></cmap><cma
... (truncated for this note; the full answer is in the test log)
```

**session 3: `edit-config` and commit** (as `netconf02`)

```
2026-09-20T18:13:58.654Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T18:13:58.816Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=53
    accounting AV: service=shell
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
2026-09-20T18:13:58.852Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:13:58.895Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T18:13:58.900Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=54
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T18:13:59.096Z event=account verdict= reason= flags=start port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    accounting AV: task_id=55
    accounting AV: service=shell
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
2026-09-20T18:13:59.106Z event=authorize_session verdict=permit reason=context_matched port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:13:59.111Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-09-20T18:13:59.112Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    accounting AV: task_id=56
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-20T18:13:59.113Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=session
    request AV: cmd-arg=session418242759302
    request AV: cmd-arg=<cr>
2026-09-20T18:13:59.115Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    accounting AV: task_id=5
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: cmd=configure session session418242759302 <cr>
2026-09-20T18:13:59.133Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=banner
    request AV: cmd-arg=login
    request AV: cmd-arg=<cr>
2026-09-20T18:13:59.135Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    accounting AV: task_id=6
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: cmd=banner login <cr>
2026-09-20T18:13:59.136Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    accounting AV: task_id=7
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: cmd=end <cr>
2026-09-20T18:13:59.138Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=session
    request AV: cmd-arg=session418242759302
    request AV: cmd-arg=commit
    request AV: cmd-arg=<cr>
2026-09-20T18:13:59.139Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    accounting AV: task_id=8
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: cmd=configure session session418242759302 commit <cr>
2026-09-20T18:13:59.199Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 56774 10.0.0.15 22"
    accounting AV: task_id=55
    accounting AV: service=shell
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
2026-09-20T18:13:59.203Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=53
    accounting AV: service=shell
    accounting AV: start_time=1789928038
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><ok></ok></rpc-reply>
```

### The requests that were sent

NETCONF over the SSH `netconf` subsystem on **port 22**, the token presented as the SSH password exactly as the interactive tests present one.

Read (sessions 1 and 2):

```xml
<get-config><source><running/></source></get-config>
```

Write (session 3), target `running`:

```xml
<system xmlns="http://openconfig.net/yang/system"><config><login-banner>port49-lab-netconf</login-banner></config></system>
```

**The write payload above is unverified.** It was written from model documentation and has never been sent to this image. If the reply is an `<rpc-error>`, that error — not the documentation — is what the payload should be rewritten from.

The device's NETCONF hello:

```xml
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability><capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability><capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability><capability>urn:ietf:params:netconf:capability:candidate:1.0</capability><capability>urn:ietf:params:netconf:capability:url:1.0?scheme=file,flash,ftp,http</capability><capability>http://arista.com/yang/openconfig/policy/augments?module=arista-rpol-augments&amp;revision=2023-08-21</capability><capability>http://arista.com/yang/cert/gnoi-cert?module=arista-gnoi-cert&amp;revision=2018-01-15</capability><capability>http://arista.com/yang/openconfig/spanning-tree/notsupported-deviations?module=arista-spanning-tree-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://arista.com/yang/experimental/eos/arista-ebra-vlan-tpid?module=arista-ebra-vlan-tpid&amp;revision=2021-10-20</capability><capability>http://arista.com/yang/experimental/eos/qos/config?module=arista-exp-eos-qos-config&amp;revision=2022-10-31</capability><capability>http://openconfig.net/yang/sampling?module=openconfig-sampling&amp;revision=2022-06-21</capability><capability>http://openconfig.net/yang/openflow/types?module=openconfig-openflow-types&amp;revision=2022-05-24</capability><capability>https://github.com/openconfig/gnsi/certz/yang?module=gnsi-certz&amp;revision=2023-08-24</capability><capability>http://arista.com/yang/openconfig/network-instance/vlan/augments?module=arista-vlan-augments&amp;revision=2020-11-30</capability><capability>http://openconfig.net/yang/vlan?module=openconfig-vlan&amp;revision=2023-02-07</capability><capability>http://openconfig.net/yang/aft?module=openconfig-aft&amp;revision=2023-09-26</capability><capability>http://arista.com/yang/openconfig/aft/augments?module=arista-aft-augments&amp;revision=2023-11-01</capability><capability>http://openconfig.net/yang/platform/linecard?module=openconfig-platform-linecard&amp;revision=2023-02-13</capability><capability>http://arista.com/yang/openconfig/relay-agent/deviations?module=arista-relay-agent-deviations&amp;revision=2020-11-30</capability><capability>http://arista.com/yang/experimental/eos/arista-interfaces-rates?module=arista-interfaces-rates&amp;revision=2023-09-15</capability><capability>http://openconfig.net/yang/openflow?module=openconfig-openflow&amp;revision=2018-11-21</capability><capability>http://openconfig.net/yang/programming-errors?module=openconfig-programming-errors&amp;revision=2022-10-11</capability><capability>http://arista.com/yang/experimental/isis-flex-algo?module=openconfig-isis-flex-algo&amp;revision=2021-09-30</capability><capability>http://openconfig.net/yang/bgp?module=openconfig-bgp&amp;revision=2023-11-01</capability><capability>http://arista.com/yang/experimental/eos/arista-ebra-vlan-tag?module=arista-ebra-vlan-tag&amp;revision=2021-10-20</capability><capability>https://github.com/openconfig/gnsi/authz/yang?module=gnsi-authz&amp;revision=2023-09-13</capability><capability>http://arista.com/yang/openconfig/bfd/augments?module=arista-bfd-augments&amp;revision=2022-05-26</capability><capability>http://openconfig.net/yang/platform/transceiver?module=openconfig-platform-transceiver&amp;revision=2023-08-30</capability><capability>http://openconfig.net/yang/platform-pipeline-counters?module=openconfig-platform-pipeline-counters&amp;revision=2023-09-26</capability><capability>http://arista.com/yang/openconfig/system/augments?module=arista-system-augments&amp;revision=2021-09-27</capability><capability>http://arista.com/yang/openconfig/interfaces/augments?module=arista-intf-augments&amp;revision=2023-07-20</capability><capability>http://openconfig.net/yang/hercules/qos?module=openconfig-hercules-qos&amp;revision=2018-06-01</capability><capability>http://
... (truncated for this note; the full answer is in the test log)
```


### Not measured

- base:1.1 chunked framing. This client advertises base:1.0 only.
- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, used once and closed.
- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and would not involve port49 at all.
- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare `<edit-config>`.
- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.

