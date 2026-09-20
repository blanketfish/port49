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
| session 1: open and `get-config running` | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 340ms |
| session 2: open again with the same token | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 150ms |
| session 3: `edit-config` and commit | `netconf02` | yes | 1 | 2 | 5 | start=2, stop=8 | 580ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `netconf01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication over this transport.

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, port, username)` rather than out of the store. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **`receipt_ttl`**: past it, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: `NETCONF`, `ssh`
- `rem_addr`: `172.100.100.1 60168 10.0.0.15 22`, `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**60** TCP connection(s) were opened toward port49d during this test, from source port(s) 36262, 36276, 36290, 36302, 36304, 36316, 36332, 36342, 36356, 36362, 36370, 36384, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/netconf-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**session 1: open and `get-config running`** (as `netconf01`)

```
2026-09-20T18:05:51.692Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T18:05:51.856Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=44
    accounting AV: service=shell
    accounting AV: start_time=1789927550
    accounting AV: timezone=UTC
2026-09-20T18:05:51.892Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:05:51.935Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T18:05:51.938Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=45
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927550
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T18:05:52.003Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=44
    accounting AV: service=shell
    accounting AV: start_time=1789927550
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T18:05:50.643320001Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapControlPlane</type><cmap><name>copp-system-linklocal</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-OspfIsis</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmcrsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mvrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lacp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-igmp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl1</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-egress-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-PimPtp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-mba</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-selfip-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mtu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-low-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mod</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp-inspect</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-vxlan</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3lpmoverflow</name><match
... (truncated for this note; the full answer is in the test log)
```

**session 2: open again with the same token** (as `netconf01`)

```
2026-09-20T18:06:02.044Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T18:06:02.050Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=46
    accounting AV: service=shell
    accounting AV: start_time=1789927561
    accounting AV: timezone=UTC
2026-09-20T18:06:02.086Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:06:02.130Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T18:06:02.134Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=47
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927561
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T18:06:02.170Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=46
    accounting AV: service=shell
    accounting AV: start_time=1789927561
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T18:06:00.995351005Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapControlPlane</type><cmap><name>copp-system-linklocal</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-OspfIsis</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmcrsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mvrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lacp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-igmp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl1</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-egress-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-PimPtp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-mba</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-selfip-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mtu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-low-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mod</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp-inspect</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-vxlan</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3lpmoverflow</name><match
... (truncated for this note; the full answer is in the test log)
```

**session 3: `edit-config` and commit** (as `netconf02`)

```
2026-09-20T18:06:12.207Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T18:06:12.369Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=48
    accounting AV: service=shell
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
2026-09-20T18:06:12.406Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:06:12.449Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T18:06:12.454Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=49
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T18:06:12.642Z event=account verdict= reason= flags=start port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    accounting AV: task_id=50
    accounting AV: service=shell
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
2026-09-20T18:06:12.655Z event=authorize_session verdict=permit reason=context_matched port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd*
2026-09-20T18:06:12.660Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-09-20T18:06:12.662Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    accounting AV: task_id=51
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-20T18:06:12.663Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=session
    request AV: cmd-arg=session418222211695
    request AV: cmd-arg=<cr>
2026-09-20T18:06:12.664Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    accounting AV: task_id=52
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
    accounting AV: cmd=configure session session418222211695 <cr>
2026-09-20T18:06:12.695Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=banner
    request AV: cmd-arg=login
    request AV: cmd-arg=<cr>
2026-09-20T18:06:12.697Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    accounting AV: task_id=53
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
    accounting AV: cmd=banner login <cr>
2026-09-20T18:06:12.698Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    accounting AV: task_id=54
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
    accounting AV: cmd=end <cr>
2026-09-20T18:06:12.699Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=session
    request AV: cmd-arg=session418222211695
    request AV: cmd-arg=commit
    request AV: cmd-arg=<cr>
2026-09-20T18:06:12.700Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    accounting AV: task_id=55
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
    accounting AV: cmd=configure session session418222211695 commit <cr>
2026-09-20T18:06:12.765Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 60168 10.0.0.15 22"
    accounting AV: task_id=50
    accounting AV: service=shell
    accounting AV: start_time=1789927571
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
2026-09-20T18:06:12.774Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=48
    accounting AV: service=shell
    accounting AV: start_time=1789927571
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
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability><capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability><capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability><capability>urn:ietf:params:netconf:capability:candidate:1.0</capability><capability>urn:ietf:params:netconf:capability:url:1.0?scheme=file,flash,ftp,http</capability><capability>urn:ietf:params:xml:ns:yang:ietf-yang-types?module=ietf-yang-types&amp;revision=2013-07-15</capability><capability>http://arista.com/yang/experimental/eos/arista-intf-intf?module=arista-intf-intf&amp;revision=2023-08-15</capability><capability>http://openconfig.net/yang/openflow?module=openconfig-openflow&amp;revision=2018-11-21</capability><capability>http://arista.com/yang/openconfig/platform/notsupported-deviations?module=arista-platform-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://openconfig.net/yang/segment-routing/srte-policy?module=openconfig-srte-policy&amp;revision=2021-07-28</capability><capability>http://arista.com/yang/openconfig/messages/notsupported-deviations?module=arista-messages-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://arista.com/yang/openconfig/defined-sets/notsupported-deviations?module=arista-defined-sets-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://arista.com/yang/experimental/eos/arista-ale-counters-open-config-hardware-drop-counters?module=arista-ale-counters-open-config-hardware-drop-counters&amp;revision=2023-01-01</capability><capability>http://openconfig.net/yang/rib/bgp-types?module=openconfig-rib-bgp-types&amp;revision=2019-03-14</capability><capability>http://openconfig.net/yang/mpls-types?module=openconfig-mpls-types&amp;revision=2021-12-01</capability><capability>http://openconfig.net/yang/system/terminal?module=openconfig-system-terminal&amp;revision=2018-11-21</capability><capability>http://arista.com/yang/openconfig/bgp/deviations?module=arista-bgp-deviations&amp;revision=2023-08-22</capability><capability>http://openconfig.net/yang/platform/port?module=openconfig-platform-port&amp;revision=2023-03-22</capability><capability>http://openconfig.net/yang/license?module=openconfig-license&amp;revision=2020-04-22</capability><capability>http://arista.com/yang/openconfig/network-instance/vlan/augments?module=arista-vlan-augments&amp;revision=2020-11-30</capability><capability>http://arista.com/yang/experimental/eos/arista-arnet-conn-tuple?module=arista-arnet-conn-tuple&amp;revision=2022-03-28</capability><capability>http://arista.com/yang/openconfig/policy-forwarding/augments?module=arista-srte-augments&amp;revision=2020-11-30</capability><capability>http://openconfig.net/yang/vlan?module=openconfig-vlan&amp;revision=2023-02-07</capability><capability>http://arista.com/yang/experimental/eos/arista-rcf-rcf-open-config?module=arista-rcf-rcf-open-config&amp;revision=2023-09-12</capability><capability>http://arista.com/yang/experimental/eos/arista-fhrp-fhrp-status?module=arista-fhrp-fhrp-status&amp;revision=2023-03-13</capability><capability>http://arista.com/yang/openconfig/policy/deviations?module=arista-rpol-deviations&amp;revision=2023-06-21</capability><capability>http://arista.com/yang/experimental/eos/arista-fhrp-fhrp-config?module=arista-fhrp-fhrp-config&amp;revision=2023-02-13</capability><capability>http://arista.com/yang/openconfig/telemetry/notsupported-deviations?module=arista-telemetry-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://openconfig.net/yang/platform/cpu?module=openconfig-platform-cpu&amp;revision=2018-11-21</capability><capability>http://arista.com/yang/openconfig/pim/augments?module=arista-pim-augments&amp;revision=2020-11-30</capability><capability>http://openconfig.ne
... (truncated for this note; the full answer is in the test log)
```


### Not measured

- base:1.1 chunked framing. This client advertises base:1.0 only.
- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, used once and closed.
- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and would not involve port49 at all.
- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare `<edit-config>`.
- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.

