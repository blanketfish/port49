# netconf — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/netconf-arista_eos.pcap` — 492 packets to or from the device, countable with `tcpdump -r tests/lab/captures/netconf-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** NETCONF over SSH (port 22)

## Claim

Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does, whether any authorization request is sent for the session or for an `<edit-config>` and with what `service`, `cmd` and `cmd-arg`, what `port` and `rem_addr` contain, what accounting arrives, and whether a second session with the same token re-authenticates.

## Observation

Transport measured: **NETCONF over SSH (port 22)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| session 1: open and `get-config running` | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 330ms |
| session 2: open again with the same token | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 150ms |
| session 3: `edit-config` and commit | `netconf02` | yes | 1 | 3 | 1 | start=3, stop=4 | 490ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `netconf01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication, so a single-use token is spent by the first call and every later call in the same script is denied. That is the failure mode decision 15 is provisional on: the operator sees one success and then a run of denials with a working credential in hand. The outcome of the second request was: `verdict=permit reason=receipt_replayed`

### `port` and `rem_addr` over this transport

- `port`: `NETCONF`, `ssh`
- `rem_addr`: `172.100.100.1 50148 10.0.0.15 22`, `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**48** TCP connection(s) were opened toward port49d during this test, from source port(s) 55908, 55922, 55928, 55938, 55940, 55950, 55966, 55968, 55972, 55978, 55988, 56004, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/netconf-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**session 1: open and `get-config running`** (as `netconf01`)

```
2026-09-20T16:41:09.822Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T16:41:09.985Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=45
    accounting AV: service=shell
    accounting AV: start_time=1789922468
    accounting AV: timezone=UTC
2026-09-20T16:41:10.022Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:41:10.065Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T16:41:10.069Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=46
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922469
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T16:41:10.130Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=45
    accounting AV: service=shell
    accounting AV: start_time=1789922468
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T16:41:08.806812278Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapControlPlane</type><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mvrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-glean</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-sflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-egress-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp-inspect</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc3to5</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-vxlan</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-exception</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cvx-heartbeat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-selfip</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-iplocking</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-ttl01</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-high-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vxlan-vtep-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-low-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3lpmoverflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-eapol-data</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><
... (truncated for this note; the full answer is in the test log)
```

**session 2: open again with the same token** (as `netconf01`)

```
2026-09-20T16:41:20.174Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T16:41:20.180Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=47
    accounting AV: service=shell
    accounting AV: start_time=1789922479
    accounting AV: timezone=UTC
2026-09-20T16:41:20.215Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:41:20.259Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T16:41:20.265Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=48
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922479
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T16:41:20.300Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=47
    accounting AV: service=shell
    accounting AV: start_time=1789922479
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T16:41:19.176918878Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapControlPlane</type><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mvrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-glean</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-sflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-egress-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp-inspect</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc3to5</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-vxlan</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-exception</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cvx-heartbeat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-selfip</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-iplocking</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-ttl01</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-high-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vxlan-vtep-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-low-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3lpmoverflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-eapol-data</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><
... (truncated for this note; the full answer is in the test log)
```

**session 3: `edit-config` and commit** (as `netconf02`)

```
2026-09-20T16:41:30.336Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T16:41:30.498Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=49
    accounting AV: service=shell
    accounting AV: start_time=1789922489
    accounting AV: timezone=UTC
2026-09-20T16:41:30.534Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:41:30.578Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T16:41:30.582Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=50
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922489
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T16:41:30.772Z event=account verdict= reason= flags=start port="NETCONF" rem_addr="172.100.100.1 50148 10.0.0.15 22"
    accounting AV: task_id=51
    accounting AV: service=shell
    accounting AV: start_time=1789922489
    accounting AV: timezone=UTC
2026-09-20T16:41:30.786Z event=authorize_session verdict=deny reason=context_missing port="NETCONF" rem_addr="172.100.100.1 50148 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:41:30.791Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 50148 10.0.0.15 22"
    accounting AV: task_id=51
    accounting AV: service=shell
    accounting AV: start_time=1789922489
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
2026-09-20T16:41:30.795Z event=account verdict= reason= flags=start port="NETCONF" rem_addr="172.100.100.1 50148 10.0.0.15 22"
    accounting AV: task_id=52
    accounting AV: service=shell
    accounting AV: start_time=1789922489
    accounting AV: timezone=UTC
2026-09-20T16:41:30.802Z event=authorize_session verdict=deny reason=context_missing port="NETCONF" rem_addr="172.100.100.1 50148 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:41:30.806Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 50148 10.0.0.15 22"
    accounting AV: task_id=52
    accounting AV: service=shell
    accounting AV: start_time=1789922489
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
2026-09-20T16:41:30.812Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=49
    accounting AV: service=shell
    accounting AV: start_time=1789922489
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><rpc-error><error-type>application</error-type><error-tag>operation-failed</error-tag><error-severity>error</error-severity><error-message>authorization denied</error-message></rpc-error></rpc-reply>
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
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability><capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability><capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability><capability>urn:ietf:params:netconf:capability:candidate:1.0</capability><capability>urn:ietf:params:netconf:capability:url:1.0?scheme=file,flash,ftp,http</capability><capability>http://arista.com/yang/openconfig/telemetry/augments?module=arista-telemetry-augments&amp;revision=2023-01-24</capability><capability>http://arista.com/yang/experimental/isis-flex-algo?module=openconfig-isis-flex-algo&amp;revision=2021-09-30</capability><capability>http://openconfig.net/yang/openconfig-ext?module=openconfig-extensions&amp;revision=2022-10-05</capability><capability>http://openconfig.net/yang/interfaces/ethernet?module=openconfig-if-ethernet&amp;revision=2023-03-10</capability><capability>http://openconfig.net/yang/rsvp?module=openconfig-mpls-rsvp&amp;revision=2023-02-06</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability><capability>http://openconfig.net/yang/telemetry?module=openconfig-telemetry&amp;revision=2018-11-21</capability><capability>http://openconfig.net/yang/mpls?module=openconfig-mpls&amp;revision=2023-07-25</capability><capability>http://arista.com/yang/openconfig/policy/augments?module=arista-rpol-augments&amp;revision=2023-08-21</capability><capability>http://openconfig.net/yang/network-instance-l3?module=openconfig-network-instance-l3&amp;revision=2022-11-08</capability><capability>http://openconfig.net/yang/isis-lsdb-types?module=openconfig-isis-lsdb-types&amp;revision=2018-11-21</capability><capability>http://arista.com/yang/openconfig/sflow/deviations?module=arista-sflow-deviations&amp;revision=2023-07-27</capability><capability>http://openconfig.net/yang/aft/ni?module=openconfig-aft-network-instance&amp;revision=2023-04-25</capability><capability>http://openconfig.net/yang/rib/bgp?module=openconfig-rib-bgp&amp;revision=2022-12-20</capability><capability>http://openconfig.net/yang/mpls-sr?module=openconfig-mpls-sr&amp;revision=2018-11-21</capability><capability>http://openconfig.net/yang/vlan-types?module=openconfig-vlan-types&amp;revision=2022-05-24</capability><capability>http://arista.com/yang/openconfig/lldp/augments?module=arista-lldp-augments&amp;revision=2020-11-30</capability><capability>http://openconfig.net/yang/openconfig-isis?module=openconfig-isis&amp;revision=2023-11-01</capability><capability>http://arista.com/yang/experimental/eos?module=arista-exp-eos&amp;revision=2016-11-09</capability><capability>http://arista.com/yang/openconfig/interfaces/deviations?module=arista-intf-deviations&amp;revision=2022-12-10</capability><capability>http://openconfig.net/yang/bgp-policy?module=openconfig-bgp-policy&amp;revision=2023-10-03</capability><capability>http://arista.com/yang/experimental/eos/arista-ale-counters-open-config-hardware-drop-counters?module=arista-ale-counters-open-config-hardware-drop-counters&amp;revision=2023-01-01</capability><capability>http://arista.com/yang/openconfig/policy/deviations?module=arista-rpol-deviations&amp;revision=2023-06-21</capability><capability>http://arista.com/yang/openconfig/bfd/notsupported-deviations?module=arista-bfd-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://arista.com/yang/openconfig/pim/augments?module=arista-pim-augments&amp;revision=2020-11-30</capability><capability>http://openconfig.net/yang/pim?module=openconfig-pim&amp;revision=2023-03-06</capability><capability>http://openconfig.net/yang/programming-errors?module=openconfig-programming-errors&amp;revision=2022-10-11</capability><capability>http://openconfig.net/yang/system?module=openco
... (truncated for this note; the full answer is in the test log)
```


### Not measured

- base:1.1 chunked framing. This client advertises base:1.0 only.
- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, used once and closed.
- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and would not involve port49 at all.
- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare `<edit-config>`.
- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.

