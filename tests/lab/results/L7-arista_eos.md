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
| read `show version` | `eapi01` | yes | 1 | 1 | 1 | start=1, stop=2 | 200ms |
| read again, same token | `eapi01` | yes | 1 | 1 | 1 | start=1, stop=2 | 20ms |
| configure `snmp-server location` | `eapi02` | yes | 1 | 1 | 3 | start=1, stop=5 | 180ms |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `eapi01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication over this transport.

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, port, username)` rather than out of the store. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **`receipt_ttl`**: past it, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: `command-api`
- `rem_addr`: `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**46** TCP connection(s) were opened toward port49d during this test, from source port(s) 49410, 49426, 49434, 49448, 49456, 49472, 49476, 49484, 49498, 49514, 49526, 49676, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/L7-eapi-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**read `show version`** (as `eapi01`)

```
2026-09-20T16:46:58.382Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-20T16:46:58.539Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=14
    accounting AV: service=shell
    accounting AV: start_time=1789922817
    accounting AV: timezone=UTC
2026-09-20T16:46:58.541Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:46:58.550Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-20T16:46:58.552Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=21
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922817
    accounting AV: timezone=UTC
    accounting AV: cmd=show version <cr>
2026-09-20T16:46:58.553Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=14
    accounting AV: service=shell
    accounting AV: start_time=1789922817
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
HTTP 200 OK
{"jsonrpc": "2.0", "id": "1", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:f5:05:14:90", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1789922596.2616823, "uptime": 221.73, "memTotal": 1979668, "memFree": 674396, "isIntlVersion": false}]}
```

**read again, same token** (as `eapi01`)

```
2026-09-20T16:47:08.577Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-20T16:47:08.579Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:47:08.581Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=22
    accounting AV: service=shell
    accounting AV: start_time=1789922828
    accounting AV: timezone=UTC
2026-09-20T16:47:08.585Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-20T16:47:08.587Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=23
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922828
    accounting AV: timezone=UTC
    accounting AV: cmd=show version <cr>
2026-09-20T16:47:08.588Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=22
    accounting AV: service=shell
    accounting AV: start_time=1789922828
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
HTTP 200 OK
{"jsonrpc": "2.0", "id": "1", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:f5:05:14:90", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1789922596.2662501, "uptime": 231.76, "memTotal": 1979668, "memFree": 674260, "isIntlVersion": false}]}
```

**configure `snmp-server location`** (as `eapi02`)

```
2026-09-20T16:47:18.610Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-20T16:47:18.767Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=24
    accounting AV: service=shell
    accounting AV: start_time=1789922838
    accounting AV: timezone=UTC
2026-09-20T16:47:18.768Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-20T16:47:18.774Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-09-20T16:47:18.775Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=25
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922838
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-20T16:47:18.776Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=<cr>
2026-09-20T16:47:18.777Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=15
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922838
    accounting AV: timezone=UTC
    accounting AV: cmd=configure <cr>
2026-09-20T16:47:18.779Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=snmp-server
    request AV: cmd-arg=location
    request AV: cmd-arg=port49-lab-eapi
    request AV: cmd-arg=<cr>
2026-09-20T16:47:18.780Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=16
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922838
    accounting AV: timezone=UTC
    accounting AV: cmd=snmp-server location port49-lab-eapi <cr>
2026-09-20T16:47:18.781Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=17
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789922838
    accounting AV: timezone=UTC
    accounting AV: cmd=end <cr>
2026-09-20T16:47:18.783Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=24
    accounting AV: service=shell
    accounting AV: start_time=1789922838
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

