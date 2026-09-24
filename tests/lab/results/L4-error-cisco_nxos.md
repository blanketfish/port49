# L4 (ERROR, closed, silent, deadtime) — cisco_nxos

- **Date measured:** 2026-09-24
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Captures** (taken by hand, no loopback probes; every packet is to or from the lab subnet):
  - `tests/lab/evidence/L4-error-cisco_nxos.pcap` — (a) and (b), 3360 packets
  - `tests/lab/evidence/L4-nonecheck-cisco_nxos.pcap` — whether the list keeps `none`, 320 packets
  - `tests/lab/evidence/L4-unreachable-cisco_nxos.pcap` — (c), 326 packets, 0 TACACS+ packets
  - `tests/lab/evidence/L4-retry-cisco_nxos.pcap` — (d) without deadtime, 132 packets
  - `tests/lab/evidence/L4-deadtime-cisco_nxos.pcap` — (d) with `deadtime 1`, 708 packets
- **Transport:** SSH (the N9Kv carries SSH logins as PAP, L19)
- **Method:** by hand, as `L4-error-cisco_iosxe.md` describes, with `session_attributes:
  ["shell:roles*network-admin"]`. Startup config: `tests/lab/configs/nxos-startup.cfg`
  (`aaa authentication login default group port49 local`, `aaa authorization commands default
  group port49 local`, `aaa authorization config-commands default group port49 local`; no exec
  authorization list, which NX-OS does not have).

## Claim

Spec §15 L4, the parts this run adds: authentication ERROR fall-through to break-glass;
per-command FAIL against ERROR; closed against silent; how long a returned server is skipped and
what `deadtime` does.

## Answer

| cell | outcome |
|---|---|
| (a) authentication ERROR, `group port49 local` | break-glass **logs in, and every command is refused** `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` |
| (a) authentication ERROR, `group port49` | the same: logs in, every command refused |
| (b) command FAIL, any list | refused, `...=16(0x10)` |
| (b) command ERROR, `group port49 local` | **falls through to `local`: the commands run** |
| (b) command ERROR, `group port49` | refused, `...=17(0x11)` |
| (b) `group port49 none` | not configurable: accepted at the prompt, not kept |
| (c) closed (RST) | break-glass logs in, 0.21s; commands instant |
| (c) silent | break-glass logs in, **5.21s**; **every command ~5s**, both sessions |
| (d) no deadtime, after the server returns | the next login asks it |
| (d) `deadtime 1`, silent | one timeout, then the server is skipped: break-glass 0.21s, commands instant — **and token logins are refused for about a minute after the server is back** |

## Observation

### (a) Authentication answered ERROR

`store_unavailable` in force, `breakglass` presenting its local password, logged in 0.21s after
the password:

```
terminal length 0
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1#
show user-account breakglass
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1#
show version | include NXOS
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1#
configure terminal
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
nx1#
end
Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)
```

Decision log (`group port49 local`):

```
{"ts":"2026-09-24T02:12:24.614Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"0","method":"pap"}
{"ts":"2026-09-24T02:12:24.827Z","event":"authorize_command","verdict":"deny","reason":"store_unavailable","user":"breakglass","vector":["terminal","length","0"]}
{"ts":"2026-09-24T02:12:24.907Z","event":"authorize_command","verdict":"deny","reason":"store_unavailable","user":"breakglass","vector":["show","user-account","breakglass"]}
{"ts":"2026-09-24T02:12:24.987Z","event":"authorize_command","verdict":"deny","reason":"store_unavailable","user":"breakglass","vector":["show","version"]}
{"ts":"2026-09-24T02:12:25.067Z","event":"authorize_command","verdict":"deny","reason":"store_unavailable","user":"breakglass","vector":["configure","terminal"]}
{"ts":"2026-09-24T02:12:25.149Z","event":"authorize_command","verdict":"deny","reason":"store_unavailable","user":"breakglass","vector":["end"]}
```

The ERROR fell through to `local` for authentication, under either list — so NX-OS treats an
authentication ERROR the way it treats an unreachable server (L4 reading 3) — and every command
the session then typed was sent to port49, answered FAIL `store_unavailable`, and refused. The
same with `aaa authentication login default group port49` (02:12:31Z).

### (b) Per-command authorization, FAIL against ERROR

The same list set for `commands` and `config-commands`. The prompt offers `local` only:

```
nx1(config)# aaa authorization commands default group port49 ?
  local  Use local RBACL based authorization
```

`none` is accepted when typed and not kept:

```
nx1(config)# aaa authorization commands default group port49 none
nx1(config)# show running-config aaa
...
aaa authorization commands default group port49
```

so the `none` cells measured `group port49` a second time.

| list | port49 answers | `show version \| include NXOS` | `show running-config \| include ^hostname` | `show user-account` |
|---|---|---|---|---|
| `group port49 local` | FAIL | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` | same | same |
| `group port49 local` | ERROR | **ran**: `NXOS: version 10.4(2) [Feature Release]` | **ran**: `hostname nx1` | **ran**, printing `Local login not possible` for each remote user |
| `group port49` | FAIL | `...=16(0x10)` | same | same |
| `group port49` | ERROR | `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=17(0x11)` | same | same |

`local` here is NX-OS's RBAC for the session's role (`network-admin`, delivered at login): on an
ERROR the device authorized the token user's commands itself.

### (c) Closed against silent

| condition | login | `terminal length 0` | `show user-account breakglass` | `show version \| include NXOS` | `configure terminal` | `end` |
|---|---|---|---|---|---|---|
| closed | logged in, 0.21s | 0.07s | 0.08s | 0.76s | 0.07s | 0.08s |
| closed, again | logged in, 0.21s | 0.07s | | | | |
| silent | logged in, **5.21s** | 5.07s | 5.08s | 5.73s | 4.07s | 5.07s |
| silent, again | logged in, 5.22s | 5.07s | | | | |

`breakglass` kept `roles:network-admin` and reached `nx1(config)#` in every session. 5s is
`show tacacs-server`'s `timeout value:5`.

### (d) A returned server, without and with `deadtime`

Without: port49d restarted at about 02:15:03Z, 6s after the silent sessions; a token login at
02:15:06.133Z reached it.

With `deadtime 1` in the server group (read back: `aaa group server tacacs+ port49 / server
172.100.100.1 / deadtime 1 / use-vrf management / source-interface mgmt0`), SYNs dropped from
02:15:28.871Z:

| time | login | result |
|---|---|---|
| 02:15:28.871Z | `breakglass` | logged in, 5.21s; `show tacacs-server` 0.09s |
| 02:15:36.580Z | `breakglass` again | logged in, **0.21s**; `show clock` 0.08s — the server is skipped |
| 02:15:39Z | the DROP rule removed; port49d answering throughout | |
| 02:15:39.307Z | token `u003` | **refused** in 2.74s, no decision record |
| 02:15:54.195Z | token `u004` | refused in 1.80s, no decision record |
| 02:16:08.950Z | token `u005` | refused in 1.86s, no decision record |
| 02:16:24.270Z | token `u006` | refused in 2.25s, no decision record |
| 02:16:40.624Z | token `u007` | logged in, `redeem permit token_redeemed` |

The server was marked dead at the first timeout (about 02:15:34Z) and was not asked again until
between 50s and 67s later — the configured minute. `deadtime` was removed afterwards (`no deadtime
1`, read back).

## Reading

- **A store outage leaves NX-OS break-glass logged in and useless.** Authentication falls through
  on ERROR, but every command goes to port49 first, and port49 answers FAIL when its store is down.
  The operator sees `AAA authorization failed` for every command including `configure terminal`.
- Had port49 answered those command authorizations ERROR instead, `group port49 local` would have
  let break-glass — and every token user whose role was already delivered — run anything their
  role allows. That is the trade the FAIL ruling makes on this platform.
- `deadtime` is the only knob on the five images that removes the silent-server penalty, and it
  costs every token user a lockout for the dead time after the server comes back; port49's log
  shows nothing of it.

*Unmeasured:* a second server; the console list; `tacacs-server deadtime` (the global form); NX-API.
