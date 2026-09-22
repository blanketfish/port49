# netconf — arista_eos

- **Date measured:** 2026-09-21
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/netconf-arista_eos.pcap` — 616 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/netconf-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** NETCONF over SSH (port 22)

## Claim

Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does, whether any authorization request is sent for the session or for an `<edit-config>` and with what `service`, `cmd` and `cmd-arg`, what `port` and `rem_addr` contain, what accounting arrives, and whether a second session with the same token re-authenticates.

## Observation

Transport measured: **NETCONF over SSH (port 22)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| session 1: open and `get-config running` | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 340ms |
| session 2: open again with the same token | `netconf01` | yes | 1 | 1 | 1 | start=1, stop=2 | 180ms |
| session 3: `edit-config` and commit | `netconf02` | yes | 1 | 2 | 5 | start=2, stop=8 | 580ms |

### Does a second request with the same token re-authenticate?

**Yes, for a client shaped like this one.** The first request as `netconf01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. **This client sends HTTP Basic credentials on a fresh TCP connection every call** (`DisableKeepAlives`, no cookie jar), so what is measured here is that the device runs AAA for each such request — not that the transport cannot do better. The `/login` session-cookie flow and HTTP keep-alive are the obvious ways a real client avoids this, and both are separately measured (L7).

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, username, kind, credential_sha256)` rather than out of the store — the same credential hashes to the same key, so a repeat finds its own receipt. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **how long that receipt lives**: `receipt_idle_ttl` slides forward on every call the receipt answers, and `receipt_max_age` caps it from the first redemption and never slides. Past either, the next call in the same script is the first denial — `token_spent` — and nothing about the credential has changed (spec §13, decision 15).

### `port` and `rem_addr` over this transport

- `port`: `NETCONF`, `ssh`
- `rem_addr`: `172.100.100.1 54214 10.0.0.15 22`, `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`. Nothing keys on `port` any more (spec §13, decision 15), so a transport reporting the same constant as SSH no longer costs anything; what these values are still for is accounting annotation and the record an operator reads at 3am.

### How many TCP connections the device opened to port49d

**60** TCP connection(s) were opened toward port49d during this test, from source port(s) 33628, 33640, 33650, 33660, 33670, 33676, 33686, 33702, 33716, 33732, 33746, 33758, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/evidence/netconf-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**session 1: open and `get-config running`** (as `netconf01`)

```
2026-09-21T05:54:40.424Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-21T05:54:40.588Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=71
    accounting AV: service=shell
    accounting AV: start_time=1789970079
    accounting AV: timezone=UTC
2026-09-21T05:54:40.624Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-21T05:54:40.668Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-21T05:54:40.673Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=72
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970079
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-21T05:54:40.740Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=71
    accounting AV: service=shell
    accounting AV: start_time=1789970079
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-21T05:54:39.619210477Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapQos</type></cmapType><cmapType><type>mapControlPlane</type><cmap><name>copp-system-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cfm-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-OspfIsis</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vrrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-eapol-data</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl0</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipv6nd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog-sflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cvx-heartbeat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2forward-includes-cpu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-igmp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc3to5</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mac-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2ucast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vxlan-vtep-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmc</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-unicastarp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-nat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-protocol-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-iplocking</name><matchCondition>matchCond
... (truncated for this note; the full answer is in the test log)
```

**session 2: open again with the same token** (as `netconf01`)

```
2026-09-21T05:54:50.778Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-21T05:54:50.800Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=73
    accounting AV: service=shell
    accounting AV: start_time=1789970089
    accounting AV: timezone=UTC
2026-09-21T05:54:50.837Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-21T05:54:50.880Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-21T05:54:50.884Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=74
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970090
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-21T05:54:50.928Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=73
    accounting AV: service=shell
    accounting AV: start_time=1789970089
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1"><data xmlns:netconf="http://arista.com/yang/rpc/netconf" netconf:time-modified="2026-09-21T05:54:49.906968843Z"><acl xmlns="http://openconfig.net/yang/acl"></acl><arista xmlns="http://arista.com/yang/experimental/eos"><eos><bridging xmlns="http://arista.com/yang/experimental/igmpsnooping"><igmpsnooping><config></config></igmpsnooping></bridging><mlag xmlns="urn:aristanetworks:yang:experimental:eos"><config><dual-primary-action>action-none</dual-primary-action><reload-delay-mlag-configured>false</reload-delay-mlag-configured></config></mlag><qos xmlns="http://arista.com/yang/experimental/eos/qos"><acl xmlns="http://arista.com/yang/experimental/eos/qos/acl"><input><cli><cmapType><type>mapQos</type></cmapType><cmapType><type>mapControlPlane</type><cmap><name>copp-system-tc6to7</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cfm-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-OspfIsis</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vrrp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-dot1x-eapol-data</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3ttl0</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-arpresolver</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-label-miss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-bfd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipv6nd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipbroadcast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog-sflow</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-cvx-heartbeat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3destmiss</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-pim</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2forward-includes-cpu</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-acllog</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-igmp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l3rsvd</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-default-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mpls-arp-suppress</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-tc3to5</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-mac-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-l2ucast</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-vxlan-vtep-learn</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ptp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-ipmc</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-multicastsnoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-unicastarp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-nat</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-protocol-snoop</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-rsvp</name><matchCondition>matchConditionAny</matchCondition></cmap><cmap><name>copp-system-iplocking</name><matchCondition>matchCond
... (truncated for this note; the full answer is in the test log)
```

**session 3: `edit-config` and commit** (as `netconf02`)

```
2026-09-21T05:55:00.965Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="ssh" rem_addr="172.100.100.1"
2026-09-21T05:55:01.128Z event=account verdict= reason= flags=start port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=75
    accounting AV: service=shell
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
2026-09-21T05:55:01.163Z event=authorize_session verdict=permit reason=context_matched port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-21T05:55:01.206Z event=authorize_command verdict=permit reason=permit_dominates port="ssh" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=netconf
    request AV: cmd-arg=start-client
    request AV: cmd-arg=<cr>
2026-09-21T05:55:01.213Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=76
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
    accounting AV: cmd=netconf start-client <cr>
2026-09-21T05:55:01.404Z event=account verdict= reason= flags=start port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    accounting AV: task_id=77
    accounting AV: service=shell
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
2026-09-21T05:55:01.414Z event=authorize_session verdict=permit reason=context_matched port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd*
2026-09-21T05:55:01.419Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-09-21T05:55:01.422Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=session
    request AV: cmd-arg=session345140984722
    request AV: cmd-arg=<cr>
2026-09-21T05:55:01.422Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    accounting AV: task_id=78
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-21T05:55:01.424Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    accounting AV: task_id=142
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
    accounting AV: cmd=configure session session345140984722 <cr>
2026-09-21T05:55:01.451Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=banner
    request AV: cmd-arg=login
    request AV: cmd-arg=<cr>
2026-09-21T05:55:01.453Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    accounting AV: task_id=143
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
    accounting AV: cmd=banner login <cr>
2026-09-21T05:55:01.455Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    accounting AV: task_id=144
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
    accounting AV: cmd=end <cr>
2026-09-21T05:55:01.456Z event=authorize_command verdict=permit reason=permit_dominates port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=session
    request AV: cmd-arg=session345140984722
    request AV: cmd-arg=commit
    request AV: cmd-arg=<cr>
2026-09-21T05:55:01.457Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    accounting AV: task_id=145
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
    accounting AV: cmd=configure session session345140984722 commit <cr>
2026-09-21T05:55:01.519Z event=account verdict= reason= flags=stop port="NETCONF" rem_addr="172.100.100.1 54214 10.0.0.15 22"
    accounting AV: task_id=77
    accounting AV: service=shell
    accounting AV: start_time=1789970100
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
2026-09-21T05:55:01.524Z event=account verdict= reason= flags=stop port="ssh" rem_addr="172.100.100.1"
    accounting AV: task_id=75
    accounting AV: service=shell
    accounting AV: start_time=1789970100
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
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability><capability>urn:ietf:params:netconf:base:1.1</capability><capability>urn:ietf:params:xml:ns:netconf:base:1.0</capability><capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</capability><capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability><capability>urn:ietf:params:netconf:capability:candidate:1.0</capability><capability>urn:ietf:params:netconf:capability:url:1.0?scheme=file,flash,ftp,http</capability><capability>http://openconfig.net/yang/interfaces/ethernet?module=openconfig-if-ethernet&amp;revision=2023-03-10</capability><capability>http://openconfig.net/yang/pim?module=openconfig-pim&amp;revision=2023-03-06</capability><capability>http://arista.com/yang/openconfig/network-instance/notsupported-deviations?module=arista-network-instance-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://openconfig.net/yang/aaa?module=openconfig-aaa&amp;revision=2022-07-29</capability><capability>http://openconfig.net/yang/policy-forwarding?module=openconfig-policy-forwarding&amp;revision=2023-04-25</capability><capability>http://arista.com/yang/openconfig/policy/deviations?module=arista-rpol-deviations&amp;revision=2023-06-21</capability><capability>http://arista.com/yang/openconfig/lacp/notsupported-deviations?module=arista-lacp-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://openconfig.net/yang/system/terminal?module=openconfig-system-terminal&amp;revision=2018-11-21</capability><capability>http://arista.com/yang/experimental/eos/arista-acl-spec?module=arista-acl-spec&amp;revision=2022-03-28</capability><capability>http://openconfig.net/yang/rib/bgp?module=openconfig-rib-bgp&amp;revision=2022-12-20</capability><capability>http://arista.com/yang/openconfig/routing-policy/notsupported-deviations?module=arista-routing-policy-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://arista.com/yang/experimental/eos/arista-ebra-vlan-tag?module=arista-ebra-vlan-tag&amp;revision=2021-10-20</capability><capability>http://arista.com/yang/openconfig/pim/augments?module=arista-pim-augments&amp;revision=2020-11-30</capability><capability>http://arista.com/yang/openconfig/macsec/notsupported-deviations?module=arista-macsec-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://openconfig.net/yang/messages?module=openconfig-messages&amp;revision=2018-08-13</capability><capability>http://arista.com/yang/openconfig/lldp/deviations?module=arista-lldp-deviations&amp;revision=2022-01-17</capability><capability>http://arista.com/yang/experimental/eos/arista-arnet-ip?module=arista-arnet-ip&amp;revision=2022-03-28</capability><capability>http://openconfig.net/yang/system-controlplane?module=openconfig-system-controlplane&amp;revision=2023-03-03</capability><capability>http://arista.com/yang/openconfig/defined-sets/notsupported-deviations?module=arista-defined-sets-notsupported-deviations&amp;revision=2024-02-03</capability><capability>http://arista.com/yang/openconfig/network-instances/deviations?module=arista-netinst-deviations&amp;revision=2023-05-03</capability><capability>http://arista.com/yang/experimental/eos/arista-sand-hardware-drop-counters?module=arista-sand-hardware-drop-counters&amp;revision=2023-01-01</capability><capability>http://arista.com/yang/experimental/eos/l2protocolforwarding?module=arista-exp-eos-l2protocolforwarding&amp;revision=2022-08-18</capability><capability>http://arista.com/yang/experimental/eos/arista-interfaces-rates?module=arista-interfaces-rates&amp;revision=2023-09-15</capability><capability>http://arista.com/yang/experimental/multicast?module=arista-exp-eos-multicast&amp;revision=2017-10-20</capability><capability>http://openconfig.net/yang/platform/psu?module=openconfig-platform-psu&amp;revision=2018-11-21</capability><capability>http://openconfig.net/yang/oc-
... (truncated for this note; the full answer is in the test log)
```


### Not measured

- base:1.1 chunked framing. This client advertises base:1.0 only.
- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, used once and closed.
- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and would not involve port49 at all.
- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare `<edit-config>`.
- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.

