# L7 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/captures/L7-nxapi-cisco_nxos.pcap` — 360 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L7-nxapi-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** NX-API over HTTPS `ins_api`

## Claim

Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests.

## Observation

Transport measured: **NX-API (HTTPS `ins_api`, `cli_show` and `cli_conf`)**. Each step below was a separate request or session; the decision log was read from a mark taken immediately before it, and drained for a further 10 seconds afterwards so that accounting arriving by way of the spool is counted in the step that produced it.

| step | user | device answered | authentications | session authz | command authz | accounting | elapsed |
|---|---|---|---|---|---|---|---|
| cli_show `show version` | `nxapi01` | yes | 1 | 1 | 2 | start=1, stop=1 | 5.82s |
| cli_show again, same token | `nxapi01` | yes | 1 | 1 | 2 | start=1, stop=1 | 5.79s |
| cli_conf `snmp-server location` | `nxapi02` | yes | 1 | 1 | 2 | start=1, stop=1 | 5.81s |

### Does a second request with the same token re-authenticate?

**Yes.** The first request as `nxapi01` cost 1 authentication exchange(s) and the second, with the same token, cost 1 more. Every request is a fresh authentication over this transport.

**And it was allowed anyway**: `verdict=permit reason=receipt_replayed`. The token was spent by the first call, and the second was answered out of the receipt port49 kept for `(nas, port, username)` rather than out of the store. So a script that makes forty calls with one token works — for as long as that receipt lives. What decision 15 rests on is therefore not "does it re-authenticate" but **`receipt_ttl`**: past it, the next call in the same script is the first denial, and nothing about the credential has changed.

### `port` and `rem_addr` over this transport

- `port`: (empty string), `0`
- `rem_addr`: (empty string), `172.100.100.1`
- `auth.method`: `pap`

These are the values this transport produced. Compare them with the SSH figures in `L1-cisco_nxos.md`: a transport that reports the same constant `port` as SSH gives the login context key `(nas, port)` nothing to tell an API call and a shell session apart.

### How many TCP connections the device opened to port49d

**36** TCP connection(s) were opened toward port49d during this test, from source port(s) 47410, 47412, 47428, 47442, 47448, 47452, 50314, 50322, 50336, 57240, 57252, 57254, ....

Read this against the step table above. One connection per authentication exchange means the device is not using single-connect; one connection carrying several exchanges means it is, or that it is holding the connection across requests. Count them yourself with `tcpdump -r tests/lab/captures/L7-nxapi-cisco_nxos.pcap -n 'tcp port 49 and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0'`.

### Every record, per step

**cli_show `show version`** (as `nxapi01`)

```
2026-09-20T17:22:30.271Z event=redeem verdict=permit reason=token_redeemed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-09-20T17:22:30.289Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
2026-09-20T17:22:30.431Z event=account verdict= reason= flags=start port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1789924945
    accounting AV: timezone=UTC
    accounting AV: service=none
2026-09-20T17:22:36.052Z event=authorize_command verdict=deny reason=context_missing port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-20T17:22:36.066Z event=authorize_command verdict=deny reason=context_missing port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=end
    request AV: cmd-arg=<cr>
2026-09-20T17:22:36.080Z event=account verdict= reason= flags=stop port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1789924951
    accounting AV: timezone=UTC
    accounting AV: stop_time=1789924951
    accounting AV: service=none
```

What the device answered:

```
HTTP 200 OK
{
	"ins_api":	{
		"type":	"cli_show",
		"version":	"1.0",
		"sid":	"eoc",
		"outputs":	{
			"output":	{
				"clierror":	"Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)\n",
				"input":	"show version",
				"msg":	"CLI execution error",
				"code":	"400"
			}
		}
	}
}
```

**cli_show again, same token** (as `nxapi01`)

```
2026-09-20T17:22:46.106Z event=redeem verdict=permit reason=receipt_replayed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-09-20T17:22:46.125Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
2026-09-20T17:22:46.239Z event=account verdict= reason= flags=start port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1789924961
    accounting AV: timezone=UTC
    accounting AV: service=none
2026-09-20T17:22:51.857Z event=authorize_command verdict=deny reason=context_missing port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=show
    request AV: cmd-arg=version
    request AV: cmd-arg=<cr>
2026-09-20T17:22:51.871Z event=authorize_command verdict=deny reason=context_missing port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=end
    request AV: cmd-arg=<cr>
2026-09-20T17:22:51.885Z event=account verdict= reason= flags=stop port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1789924966
    accounting AV: timezone=UTC
    accounting AV: stop_time=1789924966
    accounting AV: service=none
```

What the device answered:

```
HTTP 200 OK
{
	"ins_api":	{
		"type":	"cli_show",
		"version":	"1.0",
		"sid":	"eoc",
		"outputs":	{
			"output":	{
				"clierror":	"Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)\n",
				"input":	"show version",
				"msg":	"CLI execution error",
				"code":	"400"
			}
		}
	}
}
```

**cli_conf `snmp-server location`** (as `nxapi02`)

```
2026-09-20T17:23:01.909Z event=redeem verdict=permit reason=token_redeemed auth.method=pap port="0" rem_addr="172.100.100.1"
2026-09-20T17:23:01.927Z event=authorize_session verdict=permit reason=context_matched port="0" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=
    request AV: cisco-av-pair*
    request AV: shell:roles*
2026-09-20T17:23:02.067Z event=account verdict= reason= flags=start port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1789924977
    accounting AV: timezone=UTC
    accounting AV: service=none
2026-09-20T17:23:07.688Z event=authorize_command verdict=deny reason=context_missing port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=configure
    request AV: cmd-arg=terminal
    request AV: cmd-arg=<cr>
2026-09-20T17:23:07.701Z event=authorize_command verdict=deny reason=context_missing port="" rem_addr="172.100.100.1"
    request AV: service=shell
    request AV: cmd=end
    request AV: cmd-arg=<cr>
2026-09-20T17:23:07.715Z event=account verdict= reason= flags=stop port="0" rem_addr=""
    accounting AV: task_id=nginx
    accounting AV: start_time=1789924981
    accounting AV: timezone=UTC
    accounting AV: stop_time=1789924981
    accounting AV: service=none
```

What the device answered:

```
HTTP 200 OK
{
	"ins_api":	{
		"version":	"1.0",
		"sid":	"eoc",
		"type":	"cli_conf",
		"outputs":	{
			"output":	{
				"code":	"400",
				"clierror":	"Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)\n",
				"msg":	"CLI execution error"
			}
		}
	}
}
```

### The requests that were sent

Read (steps 1 and 2), POSTed to `https://172.100.100.31/ins` with HTTP Basic authentication, the token as the password:

```json
{
  "ins_api": {
    "chunk": "0",
    "input": "show version",
    "output_format": "json",
    "sid": "1",
    "type": "cli_show",
    "version": "1.0"
  }
}
```

Configuration (step 3):

```json
{
  "ins_api": {
    "chunk": "0",
    "input": "snmp-server location port49-lab-nxapi",
    "output_format": "json",
    "sid": "1",
    "type": "cli_conf",
    "version": "1.0"
  }
}
```


### Not measured

- The NX-API JSON-RPC dialect (`Content-Type: application/json-rpc`, `"method": "cli"`). Only the `ins_api` envelope is measured here, and the two are different code paths on the device.
- The NX-API sandbox and any cookie or session id the device may hand back in `sid`; every request here sends `sid: "1"` and carries HTTP Basic credentials.
- HTTP keep-alive: each step opens its own TCP connection.
- `aaa authentication login ascii-authentication` is left at the NX-OS default, so the `auth.method` reported above is whatever that default produces. The other setting is unmeasured.
- Whether `aaa authorization config-commands` changes what step 3 sends; this run has it configured and nothing to compare it against.

