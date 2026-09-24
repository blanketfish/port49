# L7-nxapi-cookie — cisco_nxos

- **Date measured:** 2026-09-24
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`); `show nxapi`: `NXAPI timeout 10`, `NXAPI cmd timeout 300`, `HTTPS Listen on port 443`
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L7-nxapi-cookie-cisco_nxos.pcap` — 4200 packets, all to or from the lab subnet; taken by hand, no loopback probes
- **Transport:** NX-API over HTTPS (`POST /ins`, `ins_api` JSON), HTTP Basic and the `nxapi_auth` cookie; seeded tokens
- **Method:** by hand. port49d ran a derivation of `tests/lab/port49d-lab.yaml` with
  `session_attributes: ["shell:roles*network-admin"]` and extra seeds for `nx1`; device
  configuration is `tests/lab/configs/nxos-startup.cfg` as shipped. Every curl request sent the
  credential or cookie on stdin (`curl -K -`), never on a command line. The decision log was read
  for 8s after each request, so accounting that arrives through the spool is counted with it.
  Cookie values, the `anticsrf` token bound to the cookie and the CSP nonces are shown as
  `<redacted>`; nothing else in the replies is edited. Every "`200`"
  below was also checked for the `ins_api` result code inside the body, because NX-API answers
  some refusals with HTTP 200 (see "Max sessions").

## Claim

Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies
change that, and whether API commands produce per-command authorization requests (spec §15, L7 —
this note is NX-API's `nxapi_auth` cookie, the half the row left open).

## Answer

- **The cookie is the session.** A request with Basic and no cookie authenticates (one PAP
  authentication, one session authorization) and the reply sets `nxapi_auth`. A request carrying
  that cookie runs **no authentication and no session authorization** — only its command
  authorizations. This is eAPI's `/login` shape (`L7-login-arista_eos.md`).
- **Every request is command-authorized**, cookie or not: a `cli_show` of one command sends two
  requests (the command, then `end`); a `cli_conf` sends `configure terminal`, the command, `end`.
- **A spent token without the cookie re-authenticates** and is permitted `receipt_replayed`.
- **A cookie beats a wrong password**: cookie plus a wrong Basic password got `200 Success` with no
  authentication at all.
- **Expiry is idle, 10 minutes** (`NXAPI timeout 10`): cookies left unused for 10m05s and 10m51s
  were refused `401`; a cookie used every 3 minutes still worked 12 minutes on.
- **`POST /logout` ends the cookie** (`401` afterwards); `POST /api/aaaLogout.json` does not.
  Neither sends port49 anything.
- **Clients differ by a factor of 21.** NAPALM `nxos` sent Basic on every request: 21
  authentications for `open()` plus five `get_facts()`. Ansible `cisco.nxos` over `httpapi` used the
  cookie: one authentication for five tasks.

## Observation

The request body for a `show` was
`{"ins_api":{"version":"1.0","type":"cli_show","chunk":"0","sid":"1","input":"show hostname","output_format":"json"}}`;
`cli_conf` for the configuration command.

### Basic, then the cookie

| # | sent | credential | request | reply | TACACS+ |
|---|---|---|---|---|---|
| 1 | 02:52:10.088Z | Basic `u001`, fresh token | `show hostname` | `200`, `Success`, `set-cookie: nxapi_auth=<redacted>; Secure; HttpOnly;`, 5.83s | `redeem permit token_redeemed`; `authorize_session permit context_matched`; accounting START `task_id=nginx`; `authorize_command` `show hostname`, `end` |
| 2 | 02:52:23.916Z | cookie only | `show hostname` | `200`, `Success`, 5.75s | accounting START; `authorize_command` `show hostname`, `end` — **no authentication** |
| 3 | 02:52:37.667Z | cookie only | `show version` | `200`, `Success` | accounting START; `authorize_command` `show version`, `end` |
| 4 | 02:52:52.285Z | cookie only | `cli_conf` `snmp-server location p49-l7` | `200`, `Success` | `authorize_command` `configure terminal`, `snmp-server location p49-l7`, `end`; accounting STOP `configure terminal ; snmp-server location p49-l7 (SUCCESS)` |
| 5 | 02:53:00.390Z | Basic `u001`, the **spent** token, no cookie | `show hostname` | `200`, `Success` | `redeem permit receipt_replayed`; `authorize_session permit`; `authorize_command` ×2 |
| 6 | 02:53:08.484Z | Basic `u001`, wrong password, no cookie | `show hostname` | `401` | `redeem deny device_mismatch`; accounting STOP `cmd=PAM: Authentication failed from nginx`, no user |
| 7 | 02:53:17.014Z | the cookie **and** a wrong Basic password | `show hostname` | `200`, `Success` | `authorize_command` ×2 — no authentication |
| 8 | 02:53:25.057Z | a made-up cookie | `show hostname` | `401` | none |

The reply to request 1, headers:

```
HTTP/2 200
server: nginx/1.24.0
date: Thu, 24 Sep 2026 02:52:15 GMT
content-type: text/json; charset=UTF-8
set-cookie: nxapi_auth=<redacted>; Secure; HttpOnly;
anticsrf: <redacted>
strict-transport-security: max-age=31536000; includeSubDomains
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
content-security-policy: block-all-mixed-content; base-uri 'self'; default-src 'self'; script-src 'self' 'nonce-<redacted>'; style-src 'self' 'nonce-<redacted>'; img-src 'self'; connect-src 'self'; font-src 'self'; object-src 'self'; media-src 'self'; form-action 'self'; frame-ancestors 'self';
cache-control: no-store, no-cache
```

and its body's `outputs.output`: `"input": "show hostname", "msg": "Success", "code": "200",
"body": {"hostname": "nx1"}`. Requests 1–3 took 5.5–6.6s and each sent an accounting START
with `task_id=nginx`; every request from 4 on took 0.01–0.1s. What the device was doing in those
seconds is not visible in a `tcp port 49` capture.

### Logout

Each path measured on a cookie of its own:

| user | step | reply | TACACS+ |
|---|---|---|---|
| `u002` | cookie, before | `200 Success` | `authorize_command` ×2 |
| `u002` | `POST /logout` with the cookie | `401`, `set-cookie: nxapi_auth=<redacted> ; expires=Thu, 01 Jan 1970 00:00:00 GMT ; Secure; HttpOnly;` | none |
| `u002` | cookie, after | **`401`** | none |
| `u003` | cookie, before | `200 Success` | `authorize_command` ×2 |
| `u003` | `POST /api/aaaLogout.json` with the cookie | `403`, `{"imdata":[{"error": {"attributes": {"code": "403","text": "Need a valid webtoken cookie (named APIC-Cookie) or a signed request with signature in the cookie APIC-Request-Signature for all REST API requests"}}}]}` | one accounting record |
| `u003` | cookie, after | `200 Success` | `authorize_command` ×2 |

### Expiry

Three cookies issued at 02:57:35Z (`u010`), 02:57:49Z (`u011`) and 02:58:02Z (`u012`); `u010`
and `u011` never used again until their single probe; `u012` probed every 3 minutes.

| cookie | last used | probed | idle | reply |
|---|---|---|---|---|
| `u010` | 02:57:35Z | 03:07:40.852Z | 10m05s | **`401`** |
| `u011` | 02:57:49Z | 03:08:40.852Z | 10m51s | **`401`** |
| `u012` | every 3 min from 03:01:10Z | 03:04:10Z, 03:07:10Z, 03:10:10Z | ≤ 3m | `200 Success` each time |

The device also closed idle sessions on its own schedule and told port49: accounting STOPs for
`u001` at 03:04:24Z (last successful use 02:53:45Z, 10m39s earlier) and for `u004`/`u005` at
03:07:22Z–03:07:24Z.

### Max sessions: a refusal inside a 200

`u012`'s own Basic request (02:58:02.772Z) and its first cookie probe (03:01:10.852Z) got HTTP
`200` with this body:

```
"outputs":	{
	"output":	{
		"clierror":	"",
		"input":	"show hostname",
		"msg":	"Max sessions reached. If you are a new user/client, please try again later.",
		"code":	"429"
	}
}
```

The Basic request was authenticated first — `redeem permit token_redeemed`,
`authorize_session permit` — and then refused by the device with no command authorization, and
the cookie it set worked once other sessions had idled out (03:04:10Z onwards). At that moment
the device held sessions for `u001`, `u003`, `u004` (NAPALM), `u005` (Ansible), `u010` and `u011`;
`u002`'s had been logged out. The limit itself was not measured.

### Real clients

| client | job | outcome | authentications | session authz | command authz | accounting |
|---|---|---|---|---|---|---|
| NAPALM 5.2.0 `nxos` (NX-API, `transport: https`) | `open()`, then 5 × `get_facts()` | `task 0..4 ok nx1` | **21**: 1 `token_redeemed`, 20 `receipt_replayed` | 21 | 63: 21 × (`configure terminal`, a `show`, `end`) | 4 |
| Ansible `cisco.nxos`, `ansible.netcommon.httpapi` | 5 × `nxos_command: show hostname` | `ok=5 ... failed=0` | **1** (`token_redeemed`) | 1 | 14 (`show hostname` ×5, `show version`, `show inventory`, `end` ×7) | 3 |

NAPALM's 20 repeats were all answered from the receipt, so the job worked; it would have failed
past `receipt_idle_ttl`/`receipt_max_age` (decision 15; `L15-clients-cisco_nxos.md` measured
that failure at 28 authentications).

## Reading

- NX-API with the cookie costs one authentication per session, like eAPI's `/login`. The row's
  NX-API cookie clause is answered.
- Revocation reaches a cookie session only at command authorization: the device never
  re-authenticates a cookie, so a revoked token keeps a live cookie working until the idle
  timeout or `/logout` — port49's per-command answer is the control there, and it is asked on
  every request.
- An operator who presents a cookie is not asked for a password even when one is sent; an
  NX-API client that falls back to Basic (NAPALM) spends one authentication per request.
- A `200` from NX-API is not success; the `ins_api` `code` is.

*Unmeasured:* NX-API over plain HTTP; JSON-RPC (`/ins` with `application/json-rpc`); the
configured `nxapi idle-timeout`; the session limit's value.
