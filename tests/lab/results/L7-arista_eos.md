# L7 — arista_eos

- **Date measured:** 2026-09-21
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L7-eapi-arista_eos.pcap` — 472 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L7-eapi-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** eAPI over HTTPS JSON-RPC

## Claim

Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests.

## Observation

Transport measured: **eAPI (HTTPS JSON-RPC `runCmds`)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| read `show version` | `eapi01` | yes | 1 | 1 | 1 | start=1, stop=2 | 170ms |
| read again, same token | `eapi01` | yes | 1 | 1 | 1 | start=1, stop=2 | 20ms |
| configure `snmp-server location` | `eapi02` | yes | 1 | 1 | 3 | start=1, stop=5 | 180ms |

### Does a second request with the same token re-authenticate?

**Yes, for a client shaped like this one.** The first request as `eapi01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. **This client sends HTTP Basic credentials on a fresh TCP connection every call** (`DisableKeepAlives`, no cookie jar), so what is measured here is that the device runs AAA for each such request — not that the transport cannot do better. The `/login` session-cookie flow and HTTP keep-alive are the obvious ways a real client avoids this, and both are separately measured (L7).

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, username, kind, credential_sha256)` rather than out of the store — the same credential hashes to the same key, so a repeat finds its own receipt. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **how long that receipt lives**: `receipt_idle_ttl` slides forward on every call the receipt answers, and `receipt_max_age` caps it from the first redemption and never slides. Past either, the next call in the same script is the first denial — `token_spent` — and nothing about the credential has changed (spec §13, decision 15).

### `port` and `rem_addr` over this transport

- `port`: `command-api`
- `rem_addr`: `172.100.100.1`
- `auth.method`: `ascii`

These are the values this transport produced. Compare them with the SSH figures in `L1-arista_eos.md`. Nothing keys on `port` any more (spec §13, decision 15), so a transport reporting the same constant as SSH no longer costs anything; what these values are still for is accounting annotation and the record an operator reads at 3am.

### How many TCP connections the device opened to port49d

**46** TCP connection(s) were opened toward port49d during this test, from source port(s) 43620, 43636, 43650, 43658, 43670, 43684, 49522, 49526, 49530, 49542, 49556, 49566, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/evidence/L7-eapi-arista_eos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**read `show version`** (as `eapi01`)

```
2026-09-21T05:54:08.519Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-21T05:54:08.676Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=140
    accounting AV: service=shell
    accounting AV: start_time=1789970047
    accounting AV: timezone=UTC
2026-09-21T05:54:08.676Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-21T05:54:08.683Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-21T05:54:08.685Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=64
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970047
    accounting AV: timezone=UTC
    accounting AV: cmd=show version <cr>
2026-09-21T05:54:08.687Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=140
    accounting AV: service=shell
    accounting AV: start_time=1789970047
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
HTTP 200 OK
{"jsonrpc": "2.0", "id": "1", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:fc:ce:b8:ad", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1789969755.2609403, "uptime": 292.58, "memTotal": 1979668, "memFree": 723520, "isIntlVersion": false}]}
```

**read again, same token** (as `eapi01`)

```
2026-09-21T05:54:18.708Z event=redeem verdict=permit reason=receipt_replayed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-21T05:54:18.711Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-21T05:54:18.711Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=65
    accounting AV: service=shell
    accounting AV: start_time=1789970057
    accounting AV: timezone=UTC
2026-09-21T05:54:18.716Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-21T05:54:18.719Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=66
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970057
    accounting AV: timezone=UTC
    accounting AV: cmd=show version <cr>
2026-09-21T05:54:18.720Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=65
    accounting AV: service=shell
    accounting AV: start_time=1789970057
    accounting AV: timezone=UTC
    accounting AV: elapsed_time=1
```

What the device answered:

```
HTTP 200 OK
{"jsonrpc": "2.0", "id": "1", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:fc:ce:b8:ad", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1789969755.263465, "uptime": 302.61, "memTotal": 1979668, "memFree": 723520, "isIntlVersion": false}]}
```

**configure `snmp-server location`** (as `eapi02`)

```
2026-09-21T05:54:28.741Z event=redeem verdict=permit reason=token_redeemed auth.method=ascii port="command-api" rem_addr="172.100.100.1"
2026-09-21T05:54:28.898Z event=account verdict= reason= flags=start port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=67
    accounting AV: service=shell
    accounting AV: start_time=1789970068
    accounting AV: timezone=UTC
2026-09-21T05:54:28.900Z event=authorize_session verdict=permit reason=context_matched port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd*
2026-09-21T05:54:28.905Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=enable
    request AV: cmd-arg=<cr>
2026-09-21T05:54:28.906Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=68
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970068
    accounting AV: timezone=UTC
    accounting AV: cmd=enable <cr>
2026-09-21T05:54:28.907Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=<cr>
2026-09-21T05:54:28.909Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=141
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970068
    accounting AV: timezone=UTC
    accounting AV: cmd=configure <cr>
2026-09-21T05:54:28.910Z event=authorize_command verdict=permit reason=permit_dominates port="command-api" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=snmp-server
    request AV: cmd-arg=location
    request AV: cmd-arg=port49-lab-eapi
    request AV: cmd-arg=<cr>
2026-09-21T05:54:28.911Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=69
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970068
    accounting AV: timezone=UTC
    accounting AV: cmd=snmp-server location port49-lab-eapi <cr>
2026-09-21T05:54:28.913Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=70
    accounting AV: service=shell
    accounting AV: priv-lvl=15
    accounting AV: start_time=1789970068
    accounting AV: timezone=UTC
    accounting AV: cmd=end <cr>
2026-09-21T05:54:28.914Z event=account verdict= reason= flags=stop port="command-api" rem_addr="172.100.100.1"
    accounting AV: task_id=67
    accounting AV: service=shell
    accounting AV: start_time=1789970068
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

