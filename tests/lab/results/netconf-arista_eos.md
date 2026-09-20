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
| session 1: open and `get-config running` | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 320ms |
| session 2: open again with the same token | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 160ms |
| session 3: `edit-config` and commit | `netconf02` | yes | 1 | 3 | 1 | start=3, stop=4 | 510ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `netconf01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication over this transport.

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, port, username)` rather than out of the store. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **`receipt_ttl`**: past it, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: `NETCONF`, `ssh`
- `rem_addr`: `172.100.100.1 52314 10.0.0.15 22`, `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**48** TCP connection(s) were opened toward port49d during this test, from source port(s) 32774, 32778, 32782, 32790, 39720, 39722, 39736, 39748, 39756, 39762, 40194, 40206, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/netconf-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**session 1: open and `get-config running`** (as `netconf01`)

```
2026-09-20T16:47:30.292Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T16:47:30.455Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=18
    accounting AV: service=shell
    accounting AV: start_time=1789922849
    accounting AV: timezone=UTC
2026-09-20T16:47:30.491Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:47:30.534Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T16:47:30.541Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=19
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922849
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T16:47:30.594Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=18
    accounting AV: service=shell
    accounting AV: start_time=1789922849
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T16:47:29.804511185Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapControlPlane</type><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lacp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2forward-includes-cpu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-low-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2broadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cfm-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vrrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmcmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc3to5</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-ttl01</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-mba</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl0</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-glean</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-high-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-PimPtp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mac-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-linklocal</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-sflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bgp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bpdu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmc</name><matchCondition>matchCon
... (truncated for this note; the full answer is in the test log)
```

**session 2: open again with the same token** (as `netconf01`)

```
2026-09-20T16:47:40.629Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T16:47:40.636Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=20
    accounting AV: service=shell
    accounting AV: start_time=1789922860
    accounting AV: timezone=UTC
2026-09-20T16:47:40.673Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:47:40.718Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T16:47:40.725Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=21
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922860
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T16:47:40.770Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=20
    accounting AV: service=shell
    accounting AV: start_time=1789922860
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-20T16:47:40.047421915Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapControlPlane</type><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lacp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2forward-includes-cpu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-low-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2broadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cfm-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vrrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmcmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc3to5</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-ttl01</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-mba</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-lldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipunicast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl0</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ldp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-glean</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3-high-pri</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-PimPtp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mac-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-linklocal</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-sflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bgp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bpdu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmc</name><matchCondition>matchCon
... (truncated for this note; the full answer is in the test log)
```

**session 3: `edit-config` and commit** (as `netconf02`)

```
2026-09-20T16:47:50.814Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-20T16:47:50.977Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=22
    accounting AV: service=shell
    accounting AV: start_time=1789922870
    accounting AV: timezone=UTC
2026-09-20T16:47:51.016Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:47:51.061Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-20T16:47:51.067Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=23
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922870
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-20T16:47:51.262Z event=account verdict= reason= flags=start port="NETCONF" rem_addr="172.100.100.1 52314 10.0.0.15 22"
    accounting AV: task_id=24
    accounting AV: service=shell
    accounting AV: start_time=1789922870
    accounting AV: timezone=UTC
2026-09-20T16:47:51.273Z event=authorize_session verdict=deny reason=context_missing port="NETCONF" rem_addr="172.100.100.1 52314 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:47:51.277Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 52314 10.0.0.15 22"
    accounting AV: task_id=24
    accounting AV: service=shell
    accounting AV: start_time=1789922870
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
2026-09-20T16:47:51.281Z event=account verdict= reason= flags=start port="NETCONF" rem_addr="172.100.100.1 52314 10.0.0.15 22"
    accounting AV: task_id=25
    accounting AV: service=shell
    accounting AV: start_time=1789922870
    accounting AV: timezone=UTC
2026-09-20T16:47:51.291Z event=authorize_session verdict=deny reason=context_missing port="NETCONF" rem_addr="172.100.100.1 52314 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:47:51.294Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 52314 10.0.0.15 22"
    accounting AV: task_id=25
    accounting AV: service=shell
    accounting AV: start_time=1789922870
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
2026-09-20T16:47:51.297Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=22
    accounting AV: service=shell
    accounting AV: start_time=1789922870
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
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability><capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability><capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability><capability>urn:ietf:params:netconf:capability:candidate:1.0</capability><capability>urn:ietf:params:netconf:capability:url:1.0?scheme=file,flash,ftp,http</capability><capability>http://openconfig.net/yang/platform/port?module=openconfig-platform-port&amp;revision=2023-03-22</capability><capability>http://arista.com/yang/experimental/multicast?module=arista-exp-eos-multicast&amp;revision=2017-10-20</capability><capability>http://openconfig.net/yang/header-fields?module=openconfig-packet-match&amp;revision=2023-03-01</capability><capability>http://openconfig.net/yang/routing-policy?module=openconfig-routing-policy&amp;revision=2023-11-01</capability><capability>http://openconfig.net/yang/spanning-tree?module=openconfig-spanning-tree&amp;revision=2019-11-28</capability><capability>http://openconfig.net/yang/interfaces/tunnel?module=openconfig-if-tunnel&amp;revision=2018-11-21</capability><capability>http://openconfig.net/yang/system-grpc?module=openconfig-system-grpc&amp;revision=2022-04-19</capability><capability>http://openconfig.net/yang/platform-types?module=openconfig-platform-types&amp;revision=2023-06-27</capability><capability>http://arista.com/yang/openconfig/mpls/deviations?module=arista-mpls-deviations&amp;revision=2021-02-15</capability><capability>http://arista.com/yang/openconfig/isis/augments?module=arista-isis-augments&amp;revision=2023-02-20</capability><capability>http://arista.com/yang/openconfig/bfd/deviations?module=arista-bfd-deviations&amp;revision=2020-11-30</capability><capability>http://openconfig.net/yang/mpls-types?module=openconfig-mpls-types&amp;revision=2021-12-01</capability><capability>http://openconfig.net/yang/telemetry?module=openconfig-telemetry&amp;revision=2018-11-21</capability><capability>http://arista.com/yang/openconfig/messages/notsupported-deviations?module=arista-messages-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://openconfig.net/yang/alarms?module=openconfig-alarms&amp;revision=2019-07-09</capability><capability>http://openconfig.net/yang/bgp?module=openconfig-bgp&amp;revision=2023-11-01</capability><capability>http://openconfig.net/yang/acl?module=openconfig-acl&amp;revision=2023-02-06</capability><capability>http://openconfig.net/yang/bfd?module=openconfig-bfd&amp;revision=2023-08-09</capability><capability>http://arista.com/yang/openconfig/keychain/notsupported-deviations?module=arista-keychain-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://arista.com/yang/openconfig/lldp/augments?module=arista-lldp-augments&amp;revision=2020-11-30</capability><capability>http://arista.com/yang/experimental/eos/qos?module=arista-exp-eos-qos&amp;revision=2017-09-26</capability><capability>http://arista.com/yang/openconfig/pim/augments?module=arista-pim-augments&amp;revision=2020-11-30</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability><capability>http://arista.com/yang/openconfig/macsec/notsupported-deviations?module=arista-macsec-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://openconfig.net/yang/alarms/types?module=openconfig-alarm-types&amp;revision=2018-11-21</capability><capability>http://openconfig.net/yang/bgp-types?module=openconfig-bgp-types&amp;revision=2023-09-06</capability><capability>http://openconfig.net/yang/pim/types?module=openconfig-pim-types&amp;revision=2018-11-21</capability><capability>http://arista.com/yang/experimental/eos/arista-ebra-vlan-tpid?module=arista-ebra-vlan-tpid&amp;revision=2021-
... (truncated for this note; the full answer is in the test log)
```


### Not measured

- base:1.1 chunked framing. This client advertises base:1.0 only.
- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, used once and closed.
- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and would not involve port49 at all.
- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare `<edit-config>`.
- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.

