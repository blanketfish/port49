# netconf — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/captures/netconf-cisco_nxos.pcap` — 120 packets to or from the device, countable with `tcpdump -r tests/lab/captures/netconf-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** NETCONF over SSH (port 830)

## Claim

Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does, whether any authorization request is sent for the session or for an `<edit-config>` and with what `service`, `cmd` and `cmd-arg`, what `port` and `rem_addr` contain, what accounting arrives, and whether a second session with the same token re-authenticates.

## Observation

Transport measured: **NETCONF over SSH (port 830)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| session 1: open and `get-config running` | `netconf01` | **no**: the NETCONF channel closed: EOF | 1 | 1 | 0 | none | 330ms |
| session 2: open again with the same token | `netconf01` | **no**: the NETCONF channel closed: EOF | 1 | 1 | 0 | none | 260ms |
| session 3: `edit-config` and commit | `netconf02` | **no**: the NETCONF channel closed: EOF | 1 | 1 | 0 | none | 280ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `netconf01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication over this transport.

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, port, username)` rather than out of the store. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **`receipt_ttl`**: past it, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: `0`
- `rem_addr`: `172.100.100.1`
- `auth.method`: `pap`

These are the values this transport produced. Compare them with the SSH figures in `L1-cisco_nxos.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**12** TCP connection(s) were opened toward port49d during this test, from source port(s) 36060, 36064, 43662, 43664, 60708, 60724.

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/netconf-cisco_nxos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**session 1: open and `get-config running`** (as `netconf01`)

```
2026-09-20T17:33:31.035Z event=redeem verdict=permit reason=token_redeemed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-09-20T17:33:31.053Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
```

**session 2: open again with the same token** (as `netconf01`)

```
2026-09-20T17:33:41.380Z event=redeem verdict=permit reason=receipt_replayed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-09-20T17:33:41.398Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
```

**session 3: `edit-config` and commit** (as `netconf02`)

```
2026-09-20T17:33:51.662Z event=redeem verdict=permit reason=token_redeemed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-09-20T17:33:51.681Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
```

### The requests that were sent

NETCONF over the SSH `netconf` subsystem on **port 830**, the token presented as the SSH password exactly as the interactive tests present one.

Read (sessions 1 and 2):

```xml
<get-config><source><running/></source></get-config>
```

Write (session 3), target `running`:

```xml
<System xmlns="http://cisco.com/ns/yang/cisco-nx-os-device"><snmp-items><inst-items><locationstring>port49-lab-netconf</locationstring></inst-items></snmp-items></System>
```

**The write payload above is unverified.** It was written from model documentation and has never been sent to this image. If the reply is an `<rpc-error>`, that error — not the documentation — is what the payload should be rewritten from.

The device's NETCONF hello:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <capabilities>
        <capability>urn:ietf:params:netconf:base:1.0</capability>
        <capability>urn:ietf:params:netconf:base:1.1</capability>
        <capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>
        <capability>urn:ietf:params:netconf:capability:rollback-on-error:1.0</capability>
        <capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>
        <capability>urn:ietf:params:netconf:capability:validate:1.1</capability>
        <capability>urn:ietf:params:netconf:capability:confirmed-commit:1.1</capability>
        <capability>urn:ietf:params:netconf:capability:notification:1.0</capability>
        <capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>
        <capability>urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=report-all</capability>
        <capability>http://cisco.com/ns/yang/cisco-nx-os-device?revision=2023-12-13&amp;module=Cisco-NX-OS-device</capability>
    </capabilities>
    <session-id>1491389739</session-id>
</hello>
```


### Not measured

- base:1.1 chunked framing. This client advertises base:1.0 only.
- Whether a long-lived NETCONF session re-authenticates during its life; each session here is opened, used once and closed.
- Key-based SSH authentication to the NETCONF port, which is how automation would really connect and would not involve port49 at all.
- `<lock>`, `<validate>` and confirmed commit, any of which may authorize differently from a bare `<edit-config>`.
- Whether the `<edit-config>` payload above is even correct for this image; see the note under it.

