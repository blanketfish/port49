# L7 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/captures/L7-eapi-arista_eos.pcap` — 472 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L7-eapi-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** eAPI over HTTPS JSON-RPC

## Claim

Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests.

## Observation

Transport measured: **eAPI (HTTPS JSON-RPC `runCmds`)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| read `show version` | `eapi01` | yes | 1 | 1 | 1 | start=1, stop=2 | 190ms |
| read again, same token | `eapi01` | yes | 1 | 1 | 1 | start=1, stop=2 | 20ms |
| configure `snmp-server location` | `eapi02` | yes | 1 | 1 | 3 | start=1, stop=5 | 180ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `eapi01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication, so a single-use token is spent by the first call and every later call in the same script is denied. That is the failure mode decision 15 is provisional on: the operator sees one success and then a run of denials with a working credential in hand. The outcome of the second request was: `verdict=permit reason=receipt_replayed`

### `port` and `rem_addr` over this transport

- `port`: `command-api`
- `rem_addr`: `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**46** TCP connection(s) were opened toward port49d during this test, from source port(s) 40822, 40834, 40850, 40866, 40870, 40872, 42034, 42036, 42042, 42056, 42060, 42072, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/L7-eapi-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**read `show version`** (as `eapi01`)

```
2026-09-20T16:40:37.930Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-20T16:40:38.086Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:40:38.086Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=38
    accounting AV: service=shell
    accounting AV: start_time=1789922437
    accounting AV: timezone=UTC
2026-09-20T16:40:38.094Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-20T16:40:38.097Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=39
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922437
    accounting AV: timezone=UTC
    accounting AV: cmd=show version <cr>
2026-09-20T16:40:38.098Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=38
    accounting AV: service=shell
    accounting AV: start_time=1789922437
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
HTTP 200 OK
{"jsonrpc": "2.0", "id": "1", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:00:51:b4:24", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1789922000.2550652, "uptime": 436.85, "memTotal": 1979668, "memFree": 716916, "isIntlVersion": false}]}
```

**read again, same token** (as `eapi01`)

```
2026-09-20T16:40:48.119Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-20T16:40:48.121Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:40:48.121Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=40
    accounting AV: service=shell
    accounting AV: start_time=1789922447
    accounting AV: timezone=UTC
2026-09-20T16:40:48.127Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-20T16:40:48.129Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=41
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922447
    accounting AV: timezone=UTC
    accounting AV: cmd=show version <cr>
2026-09-20T16:40:48.130Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=40
    accounting AV: service=shell
    accounting AV: start_time=1789922447
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
HTTP 200 OK
{"jsonrpc": "2.0", "id": "1", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:00:51:b4:24", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1789922000.257242, "uptime": 446.88, "memTotal": 1979668, "memFree": 719008, "isIntlVersion": false}]}
```

**configure `snmp-server location`** (as `eapi02`)

```
2026-09-20T16:40:58.151Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-20T16:40:58.307Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=42
    accounting AV: service=shell
    accounting AV: start_time=1789922457
    accounting AV: timezone=UTC
2026-09-20T16:40:58.307Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:40:58.314Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-09-20T16:40:58.317Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=<cr>
2026-09-20T16:40:58.317Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=19
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922457
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-20T16:40:58.319Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=20
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922457
    accounting AV: timezone=UTC
    accounting AV: cmd=configure <cr>
2026-09-20T16:40:58.320Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=snmp-server
    request AV: cmd-arg=location
    request AV: cmd-arg=port49-lab-eapi
    request AV: cmd-arg=<cr>
2026-09-20T16:40:58.321Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=43
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922457
    accounting AV: timezone=UTC
    accounting AV: cmd=snmp-server location port49-lab-eapi <cr>
2026-09-20T16:40:58.323Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=44
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922457
    accounting AV: timezone=UTC
    accounting AV: cmd=end <cr>
2026-09-20T16:40:58.324Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=42
    accounting AV: service=shell
    accounting AV: start_time=1789922457
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
HTTP 200 OK
{"jsonrpc": "2.0", "id": "2", "result": [{}, {}, {}, {}]}
```

### The requests that were sent

Read (steps 1 and 2), POSTed to `https://172.100.100.11/command-api` with HTTP Basic authentication, the token as the password:

```json
{
  "id": "1",
  "jsonrpc": "2.0",
  "method": "runCmds",
  "params": {
    "cmds": [
      "show version"
    ],
    "format": "json",
    "version": 1
  }
}
```

Configuration (step 3):

```json
{
  "id": "2",
  "jsonrpc": "2.0",
  "method": "runCmds",
  "params": {
    "cmds": [
      "enable",
      "configure",
      "snmp-server location port49-lab-eapi",
      "end"
    ],
    "format": "json",
    "version": 1
  }
}
```


### Not measured

- The `/login` session-cookie flow. L7 names it explicitly, and this test does not use it: every request here carries HTTP Basic credentials. A cookie session is the obvious way a device would avoid re-authenticating, so if the table above shows an authentication per request, the cookie flow is the next thing to measure, not a conclusion to draw.
- HTTP keep-alive. Each step opens its own TCP connection (`DisableKeepAlives`), so nothing here says whether a second request on an already-open connection re-authenticates.
- `unix-socket` and HTTP (not HTTPS) eAPI transports.
- Whether eAPI accounting distinguishes the API from a shell session at all.

