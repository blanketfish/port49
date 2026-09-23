# L7-login — arista_eos

- **Date measured:** 2026-09-23
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L7-login-arista_eos.pcap` (3250 packets, 3250 of them device traffic; `-i any` records each packet twice, on the bridge and the veth. Most of it is the readiness wait below: 111 `breakglass` logins the device sent port49d between 06:35:09Z and 06:44:17Z. The eAPI run is 06:45:00Z–06:46:12Z, 10 TCP connections from the device.)
- **Transport:** eAPI over HTTPS, `/login` session cookie; token minted by the slice's broker
- **Method:** by hand, plan 3 Task 16; the commands are in that task verbatim

## Claim

Whether eAPI's `/login` session cookie changes how many TACACS+ authentications a sequence of API
requests costs (spec §15, L7, the eAPI half of the row's cookie clause; NX-API's `nxapi_auth`
cookie is not measured here).

## Observation

The daemon ran `tests/lab/port49d-lab.yaml` plus `tests/lab/slice/broker.yaml`; `port49 login`
opened a session for `user:alice@slice.port49.test` and `TOKEN=$(bin/port49 token leaf1)` minted the one
token this run used. `since` prints only records whose `session.username` is `slice01`. In the
replies below, the `Session=` cookie value is replaced with `<redacted>`; nothing else is edited.

**Readiness.** Task 16 Step 1's wait (`ssh breakglass@172.100.100.11 'show version | include Software'`)
never logged in: with port49d already running, every attempt reached port49d as a TACACS+ login for
`breakglass` and was refused `token_not_found` (111 records, the first at 06:35:09Z, 60s after
deploy), and EOS's `aaa authentication login default group port49 local` does not fall through to
`local` on a FAIL. The ssh client's last lines:

```
debug1: Authentications that can continue: publickey,keyboard-interactive
debug1: No more authentication methods to try.
breakglass@172.100.100.11: Permission denied (publickey,keyboard-interactive).
```

The device reaching port49d at all is the harness's own second readiness condition
(`waitDeviceReady`: its startup config is applied), and the run went on from there.

### 1. Does `POST /login` run a TACACS+ authentication?

Request:

```
printf '{"username":"slice01","password":"%s"}' "$TOKEN" |
  curl -sk -i -c "$JAR" -H 'Content-Type: application/json' --data-binary @- https://172.100.100.11/login
```

Reply:

```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 23 Sep 2026 06:45:00 GMT
Content-Type: application/json
Content-Length: 18
Connection: keep-alive
Cache-control: no-store
Cache-control: no-cache
Cache-control: must-revalidate
Cache-control: max-age=0
Cache-control: pre-check=0
Cache-control: post-check=0
Pragma: no-cache
Set-Cookie: Session=<redacted>;Expires=Thu, 24-Sep-2026 06:45:00 GMT;Path=/;HttpOnly
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000;includeSubDomains

{ "Login" : true }
```

`since`:

```
{"ts":"2026-09-23T06:45:00.443Z","event":"redeem","verdict":"permit","reason":"token_redeemed","port":"command-api","rem_addr":"172.100.100.1","method":"ascii","cred":"8942668dcc4e","vector":null}
{"ts":"2026-09-23T06:45:00.600Z","event":"authorize_session","verdict":"permit","reason":"context_matched","port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":null}
{"ts":"2026-09-23T06:45:00.600Z","event":"account","verdict":null,"reason":null,"port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":null}
```

### 2. Does a `POST /command-api` carrying the cookie authenticate again?

Three requests, 23s apart, each:

```
curl -sk -i -b "$JAR" -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"runCmds","params":{"version":1,"cmds":["show version"],"format":"json"},"id":"p49-'"$i"'"}' \
  https://172.100.100.11/command-api | head -20
```

Request `p49-1`, reply:

```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 23 Sep 2026 06:45:03 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-control: no-store
Cache-control: no-cache
Cache-control: must-revalidate
Cache-control: max-age=0
Cache-control: pre-check=0
Cache-control: post-check=0
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000;includeSubDomains

{"jsonrpc": "2.0", "id": "p49-1", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:ae:da:73:0c", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1790145256.2485206, "uptime": 647.19, "memTotal": 1979668, "memFree": 725568, "isIntlVersion": false}]}
```

`since`:

```
{"ts":"2026-09-23T06:45:03.634Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":["show","version"]}
{"ts":"2026-09-23T06:45:03.637Z","event":"account","verdict":null,"reason":null,"port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":null}
```

Request `p49-2`, reply:

```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 23 Sep 2026 06:45:26 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-control: no-store
Cache-control: no-cache
Cache-control: must-revalidate
Cache-control: max-age=0
Cache-control: pre-check=0
Cache-control: post-check=0
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000;includeSubDomains

{"jsonrpc": "2.0", "id": "p49-2", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:ae:da:73:0c", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1790145256.2543137, "uptime": 670.22, "memTotal": 1979668, "memFree": 725820, "isIntlVersion": false}]}
```

`since`:

```
{"ts":"2026-09-23T06:45:26.670Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":["show","version"]}
{"ts":"2026-09-23T06:45:26.672Z","event":"account","verdict":null,"reason":null,"port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":null}
```

Request `p49-3`, reply:

```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 23 Sep 2026 06:45:49 GMT
Content-Type: application/json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-control: no-store
Cache-control: no-cache
Cache-control: must-revalidate
Cache-control: max-age=0
Cache-control: pre-check=0
Cache-control: post-check=0
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000;includeSubDomains

{"jsonrpc": "2.0", "id": "p49-3", "result": [{"mfgName": "Arista", "modelName": "vEOS-lab", "hardwareRevision": "", "serialNumber": "", "systemMacAddress": "0c:00:ae:da:73:0c", "hwMacAddress": "00:00:00:00:00:00", "configMacAddress": "00:00:00:00:00:00", "version": "4.31.2F", "architecture": "x86_64", "internalVersion": "4.31.2F-35442176.4312F", "internalBuildId": "48bb2b78-5325-4a32-b124-dcd4e37fd3bc", "imageFormatVersion": "1.0", "imageOptimization": "None", "bootupTimestamp": 1790145256.2521653, "uptime": 693.26, "memTotal": 1979668, "memFree": 725820, "isIntlVersion": false}]}
```

`since`:

```
{"ts":"2026-09-23T06:45:49.708Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":["show","version"]}
{"ts":"2026-09-23T06:45:49.711Z","event":"account","verdict":null,"reason":null,"port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":null}
```

### 3. After `POST /logout`, is the cookie refused, and by whom?

Requests:

```
curl -sk -i -b "$JAR" -X POST https://172.100.100.11/logout
curl -sk -i -b "$JAR" -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"runCmds","params":{"version":1,"cmds":["show version"],"format":"json"},"id":"p49-after"}' \
  https://172.100.100.11/command-api | head -20
```

Reply to `/logout`:

```
HTTP/1.1 200 OK
Server: nginx
Date: Wed, 23 Sep 2026 06:46:12 GMT
Content-Type: application/json
Content-Length: 19
Connection: keep-alive
Cache-control: no-store
Cache-control: no-cache
Cache-control: must-revalidate
Cache-control: max-age=0
Cache-control: pre-check=0
Cache-control: post-check=0
Pragma: no-cache
Set-Cookie: Session=<redacted>;Expires=Wed, 23-Sep-2026 06:34:17 GMT;Path=/;HttpOnly
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000;includeSubDomains

{ "Logout" : true }
```

Reply to the `/command-api` request after it:

```
HTTP/1.1 401 Unauthorized
Server: nginx
Date: Wed, 23 Sep 2026 06:46:12 GMT
Content-Type: text/plain
Content-Length: 43
Connection: keep-alive
Cache-control: no-store
Cache-control: no-cache
Cache-control: must-revalidate
Cache-control: max-age=0
Cache-control: pre-check=0
Cache-control: post-check=0
Pragma: no-cache
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000;includeSubDomains

Unable to authenticate user: Bad session Id
```

`since` (both requests):

```
{"ts":"2026-09-23T06:46:12.742Z","event":"account","verdict":null,"reason":null,"port":"command-api","rem_addr":"172.100.100.1","method":null,"cred":"","vector":null}
```

The one record is the exec accounting `stop` for `task_id=1`, the task `/login` started
(`start_time=1790145900`, `elapsed_time=73`). The capture has one TACACS+ connection from the device
in this step (06:46:12.741Z, source port 52224) and none after it.

### Record counts

| request | redeem | authorize_session | authorize_command | account | port | rem_addr |
|---|---|---|---|---|---|---|
| `POST /login` | 1 | 1 | 0 | 1 (start, task_id 1) | `command-api` | `172.100.100.1` |
| `POST /command-api` `p49-1` | 0 | 0 | 1 | 1 (stop, task_id 9) | `command-api` | `172.100.100.1` |
| `POST /command-api` `p49-2` | 0 | 0 | 1 | 1 (stop, task_id 10) | `command-api` | `172.100.100.1` |
| `POST /command-api` `p49-3` | 0 | 0 | 1 | 1 (stop, task_id 11) | `command-api` | `172.100.100.1` |
| `POST /logout` | 0 | 0 | 0 | 1 (stop, task_id 1) | `command-api` | `172.100.100.1` |
| `POST /command-api` `p49-after` | 0 | 0 | 0 | 0 | — | — |

Every record carried `ctx_id` `L2MKOPAXNVS4PRBF` and principal `user:alice@slice.port49.test`.
`rem_addr` is the address the eAPI client connected from (the host, on the clab bridge), not the
device.

1. **Yes.** `POST /login` ran one TACACS+ authentication (`redeem` `token_redeemed`, `auth.method`
   `ascii`, `port` `command-api`, `rem_addr` `172.100.100.1`), then a session authorization and an
   exec accounting start.
2. **No.** A `/command-api` request carrying the cookie ran no authentication and no session
   authorization: one command authorization (`permit_dominates`) and one accounting stop each, the
   same for all three requests, 23s and 46s after the first.
3. **The device refuses it, and port49 never sees it.** After `/logout` (`{ "Logout" : true }`, and
   an expired `Set-Cookie`), the same cookie got `HTTP/1.1 401 Unauthorized`,
   `Unable to authenticate user: Bad session Id`, and sent port49d no packet: the only record in the
   step is `/logout`'s own accounting stop.

*Unmeasured:* a cookie used past `receipt_idle_ttl` (the last cookie request came 49s after `/login`, `/logout` 72s after it); a
cookie past its own `Expires` (24h); NX-API's `nxapi_auth` cookie; HTTP keep-alive without a
cookie; a denied command under a cookie session; two cookie sessions from one token.
