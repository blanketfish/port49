# L1-restconf — cisco_iosxe

- **Date measured:** 2026-09-23
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L1-restconf-cisco_iosxe.pcap` (132 packets, 132 of them device traffic; `-i any` records each packet twice, on the bridge and the veth: 6 TCP connections, 9 TACACS+ packets from the device)
- **Transport:** RESTCONF over HTTPS, HTTP Basic, seeded token
- **Method:** by hand, plan 3 Task 17; the commands are in that task verbatim

## Claim

What the `port` field contains on IOS-XE's RESTCONF transport, whether it is unique per concurrent
request and stable for the request's life (spec §15, L1).

## Observation

The daemon ran `tests/lab/port49d-lab.yaml` with `session_attributes: ["priv-lvl=15"]` and no
broker; the tokens are the seeded `alice01`–`alice03` for `xe1`. `since` prints every record whose
`device.name` is `xe1`.

**Order.** Step 2 was done before port49d started, not after as `tests/lab/README.md` "By hand" orders
it: `breakglass` is a local account, and with port49d running a TACACS+ FAIL does not fall through to
`local` under `aaa authentication login default group port49 local`, so an interactive `breakglass`
session is only available while port49d is down. `breakglass` logged in at 06:50:12Z, 1m39s after
`containerlab deploy`.

### Step 2: RESTCONF's AAA

The interactive session, as the device echoed it (`terminal length 0` added first):

```
xe1#terminal length 0
xe1#show running-config | include ^ip http|^restconf
ip http secure-server
restconf
xe1#configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
xe1(config)#ip http secure-server
xe1(config)#ip http authentication aaa login-authentication default
xe1(config)#ip http authentication aaa exec-authorization default
xe1(config)#restconf
xe1(config)#end
xe1#show running-config | include ^ip http|^restconf
ip http authentication aaa login-authentication default
ip http authentication aaa exec-authorization default
ip http secure-server
restconf
xe1#exit
```

No line was refused. The launcher had already set `ip http secure-server` and `restconf`; the final
`show` lists all four settings.

### Step 3: reachability

```
$ curl -sk -o /dev/null -w '%{http_code}\n' https://172.100.100.41/restconf
401
```

### Step 4: one request, its repeat, and two at once

Each request is

```
printf 'user = "%s:%s"\n' "$1" "$(tok "$1")" |
  curl -sk -i -K - -H 'Accept: application/yang-data+json' \
  https://172.100.100.41/restconf/data/Cisco-IOS-XE-native:native/hostname
```

with `$1` the seeded user; `curl -K -` reads the credential from stdin.

#### One request (`alice01`)

Reply:

```
HTTP/1.1 200 OK
Server: openresty
Date: Wed, 23 Sep 2026 06:51:23 GMT
Content-Type: application/yang-data+json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: private, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
Content-Security-Policy: default-src 'self'; block-all-mixed-content; base-uri 'self'; frame-ancestors 'none';
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

{
  "Cisco-IOS-XE-native:hostname": "xe1"
}
```

`since`:

```
{"ts":"2026-09-23T06:51:23.930Z","event":"redeem","verdict":"permit","reason":"token_redeemed","user":"alice01","port":"","rem_addr":"172.100.100.1","method":"ascii","vector":null}
{"ts":"2026-09-23T06:51:23.931Z","event":"authorize_session","verdict":"permit","reason":"context_matched","user":"alice01","port":"","rem_addr":"172.100.100.1","method":null,"vector":null}
```

#### The same credential again (`alice01`, 3s later)

Reply:

```
HTTP/1.1 200 OK
Server: openresty
Date: Wed, 23 Sep 2026 06:51:26 GMT
Content-Type: application/yang-data+json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: private, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
Content-Security-Policy: default-src 'self'; block-all-mixed-content; base-uri 'self'; frame-ancestors 'none';
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

{
  "Cisco-IOS-XE-native:hostname": "xe1"
}
```

`since` printed nothing: the decision log has no record between 06:51:23.931Z and 06:51:30.008Z,
and the capture has no TCP connection from the device in that interval (its connections open at
06:51:23.927Z and 06:51:23.931Z, then at 06:51:30.006Z).

#### Two at once (`alice02` and `alice03`, backgrounded together)

The two replies, in the order curl printed them:

```
HTTP/1.1 200 OK
Server: openresty
Date: Wed, 23 Sep 2026 06:51:30 GMT
Content-Type: application/yang-data+json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: private, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
Content-Security-Policy: default-src 'self'; block-all-mixed-content; base-uri 'self'; frame-ancestors 'none';
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

{
  "Cisco-IOS-XE-native:hostname": "xe1"
}
```

```
HTTP/1.1 200 OK
Server: openresty
Date: Wed, 23 Sep 2026 06:51:30 GMT
Content-Type: application/yang-data+json
Transfer-Encoding: chunked
Connection: keep-alive
Cache-Control: private, no-cache, must-revalidate, proxy-revalidate
Pragma: no-cache
Content-Security-Policy: default-src 'self'; block-all-mixed-content; base-uri 'self'; frame-ancestors 'none';
Strict-Transport-Security: max-age=15552000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block

{
  "Cisco-IOS-XE-native:hostname": "xe1"
}
```

`since`:

```
{"ts":"2026-09-23T06:51:30.008Z","event":"redeem","verdict":"permit","reason":"token_redeemed","user":"alice02","port":"","rem_addr":"172.100.100.1","method":"ascii","vector":null}
{"ts":"2026-09-23T06:51:30.008Z","event":"redeem","verdict":"permit","reason":"token_redeemed","user":"alice03","port":"","rem_addr":"172.100.100.1","method":"ascii","vector":null}
{"ts":"2026-09-23T06:51:30.010Z","event":"authorize_session","verdict":"permit","reason":"context_matched","user":"alice03","port":"","rem_addr":"172.100.100.1","method":null,"vector":null}
{"ts":"2026-09-23T06:51:30.010Z","event":"authorize_session","verdict":"permit","reason":"context_matched","user":"alice02","port":"","rem_addr":"172.100.100.1","method":null,"vector":null}
```

### Table

Each request that reached port49d cost two TCP connections: one authentication (an ASCII START of 40
bytes, then a CONTINUE of 47 carrying the password) and one authorization REQUEST of 59 bytes. The
START's 40 bytes are the 12-byte header, the 8 fixed body bytes, `alice0N` (7) and `172.100.100.1`
(13), which leaves 0 bytes for `port`; the REQUEST's 59 bytes leave 0 for it the same way. So the
empty `port` is what the device sent, not something port49d dropped. No accounting was sent for any
request.

| request | authentication `port` | authorization `port` | `rem_addr` | `auth.method` | exchanges |
|---|---|---|---|---|---|
| `alice01` | `""` (empty) | `""` (empty) | `172.100.100.1` | `ascii` | 2 (authen, author) |
| `alice01` again | — | — | — | — | 0 |
| `alice02` (concurrent) | `""` (empty) | `""` (empty) | `172.100.100.1` | `ascii` | 2 (authen, author) |
| `alice03` (concurrent) | `""` (empty) | `""` (empty) | `172.100.100.1` | `ascii` | 2 (authen, author) |

`rem_addr` is the address the RESTCONF client connected from (the host, on the clab bridge).

**Uniqueness.** Not unique: the two concurrent requests both carried an empty `port`, so
`(nas, port)` does not tell them apart; they differed only in username.
**Stability.** Stable in the trivial sense: `port` was empty at authentication and at authorization
for every request.
**The repeat.** Neither a receipt replay nor a new redeem: the device answered the second `alice01`
request with `200 OK` without sending port49d anything, so it keeps the credential for a while itself
(its HTTP AAA cache, whose lifetime this run did not measure). A spent seeded token kept working at
the device.

*Unmeasured:* NETCONF-YANG on IOS-XE; the console; how long IOS-XE keeps a RESTCONF credential
without re-authenticating, and whether a denied or changed credential is re-checked inside that
window; a RESTCONF write (command authorization for a config change); a request that port49d denies.
