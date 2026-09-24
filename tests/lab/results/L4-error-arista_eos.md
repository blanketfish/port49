# L4 (ERROR, closed, silent) — arista_eos

- **Date measured:** 2026-09-24
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Captures** (taken by hand, no loopback probes; every packet is to or from the lab subnet):
  - `tests/lab/evidence/L4-error-arista_eos.pcap` — (a) and (b), 3516 packets
  - `tests/lab/evidence/L4-unreachable-arista_eos.pcap` — (c), 620 packets, 0 TACACS+ packets
  - `tests/lab/evidence/L4-retry-arista_eos.pcap` — (d), 434 packets
- **Transport:** SSH
- **Method:** by hand, as `L4-error-cisco_iosxe.md` describes: a derived port49d config with
  `session_attributes: ["priv-lvl=15"]` and the lab fault switch (`lab.fault_file`);
  `store_unavailable` makes authentication answer **ERROR** and authorization **FAIL**,
  `command_error` / `command_fail` answer every per-command authorization ERROR / FAIL. Lists were
  changed by a fresh token session with no fault in force and read back with `show
  running-config`. Startup config: `tests/lab/configs/eos-startup.cfg`.

## Claim

Spec §15 L4, the parts this run adds: authentication ERROR fall-through to break-glass;
per-command FAIL against ERROR under lists with and without `local` (and `none`, the nearest EOS
has to `if-authenticated`); closed against silent; how long a returned server is skipped.

## Answer

| cell | outcome |
|---|---|
| (a) authentication ERROR, `group port49 local` | break-glass **authenticates locally, then is thrown out**: `Authorization denied: port49: authorization store unavailable` |
| (a) authentication ERROR, `group port49` | break-glass refused |
| (b) command FAIL, any list | refused, port49's `server_msg` shown |
| (b) command ERROR, `group port49 local` | **refused** — no fall-through to `local` |
| (b) command ERROR, `group port49` | refused |
| (b) command ERROR, `group port49 none` | **refused** — not even `none` is reached |
| (c) closed (RST) | break-glass logs in, 0.65s; every command ~0.06s |
| (c) silent | break-glass logs in, **7.88s**; **every command 5.06s**, both sessions |
| (d) after the server returns | the next login asks it (3s after it came back) |
| dead-time setting | none offered for TACACS+ |

An authentication ERROR does fall through on vEOS — but the session authorization that follows is
sent to port49 too, and port49 answers it FAIL when its store is down, so break-glass is logged in
and immediately logged out. A per-command ERROR is final on every list tried.

## Observation

### (a) Authentication answered ERROR

`aaa authentication login default group port49 local`, `aaa authorization exec default group
port49 local`, `store_unavailable` in force, `breakglass` presenting its local password:

```
(breakglass@172.100.100.11) Password:
Last login: Thu Sep 24 02:02:59 2026 from 172.100.100.1
Authorization denied: port49: authorization store unavailable
```

and the channel closed. Decision log:

```
{"ts":"2026-09-24T02:04:13.350Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"ssh","priv":1,"method":"ascii"}
{"ts":"2026-09-24T02:04:13.362Z","event":"account","user":"breakglass","port":"ssh","flags":"start","raw":["task_id=82","service=shell","start_time=1790215452","timezone=UTC"]}
{"ts":"2026-09-24T02:04:13.402Z","event":"authorize_session","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"vty4","priv":1,"raw":["service=shell","cmd*"]}
{"ts":"2026-09-24T02:04:13.411Z","event":"account","user":"breakglass","port":"vty4","flags":"stop","raw":["task_id=82","service=shell","start_time=1790215452","timezone=UTC","elapsed_time=1"]}
```

The ERROR fell through to `local` (the password was accepted, `Last login:` printed, an exec
accounting START was sent), and then the exec authorization went to port49 first, got FAIL
`store_unavailable`, and the device did not go on to `local` for it.

With `aaa authentication login default group port49`:

```
(breakglass@172.100.100.11) Password:
breakglass@172.100.100.11: Permission denied (publickey,keyboard-interactive).
```

one `redeem deny store_unavailable` at 02:04:18.955Z.

### (b) Per-command authorization, FAIL against ERROR

A token session opened with no fault; the fault set after the prompt; three commands.

```
aaa authorization commands all default group port49 ?
  local  Use local database for authorization
  none   No authorization (always succeeds)
```

| list | port49 answers | each of `show version \| include Software`, `show running-config \| include ^hostname`, `show privilege` |
|---|---|---|
| `group port49 local` | FAIL | `% Authorization denied for command 'show version': port49: denied by lab fault command_fail` (and likewise) |
| `group port49 local` | ERROR | `% Authorization denied for command 'show version': port49: authorization store unavailable` (and likewise) |
| `group port49` | FAIL | as FAIL above |
| `group port49` | ERROR | as ERROR above |
| `group port49 none` | FAIL | as FAIL above |
| `group port49 none` | ERROR | as ERROR above |

Every command was refused in 0.06–0.08s, and every cell has one `authorize_command` record per
command with the verdict port49 gave. vEOS displays the `server_msg` of an ERROR as it does a
FAIL's, and treats the two identically.

### (c) Closed against silent

`breakglass`, the startup lists. Closed: port49d stopped, the host answers RST. Silent: `iptables
-I INPUT -s 172.100.100.11 -d 172.100.100.1 -p tcp --dport 49 -j DROP`.

| condition | login | `terminal length 0` | `show privilege` | `show version \| include Software` | `configure terminal` | `end` |
|---|---|---|---|---|---|---|
| closed | logged in, 0.65s | 0.06s | 0.06s | 0.09s | 0.07s | 0.06s |
| closed, again | logged in, 0.64s | 0.06s | 0.06s | | | |
| silent | logged in, **7.88s** | 5.06s | 5.06s | 5.07s | 5.06s | 0.06s |
| silent, again | logged in, 7.88s | 5.06s | 5.06s | | | |

`Current privilege level is 15` in every session; `configure terminal` reached `leaf1(config)#`.
The 5.06s is the TACACS+ timeout (EOS default, 5s): silent, each command waits it out before
`local` authorizes it, and the second session pays it again.

### (d) How long a returned server is skipped

port49d started at 02:06:42Z, 15s after the last silent-server session; a token login at
02:06:44.956Z reached it (`redeem permit token_redeemed`).

No dead-time exists to configure:

```
leaf1(config)#tacacs-server ?
  host      TACACS+ server configuration
  key       Set TACACS+ secret key
  policy    Set TACACS+ policy
  qos       Configure QoS parameters
  timeout   Time to wait for a TACACS+ server to respond
  username  Configure username parameters
```

## Reading

- **A store outage locks break-glass out of vEOS as it is configured here**, by a different route
  than IOS-XE: authentication falls through on ERROR, but `aaa authorization exec default group
  port49 local` sends the session authorization to port49, whose FAIL is final. port49 answering
  that FAIL is its ruled behaviour (plan 4, 2026-09-24), so the reference configuration, not
  port49, has to supply the way in — for example an exec authorization list that break-glass does
  not traverse. Which configuration does that on EOS is unmeasured.
- A per-command ERROR is never a fall-through on vEOS, so the FAIL-vs-ERROR choice at command
  authorization changes only the message the operator sees.
- Silent costs about 8s per login and 5s per command, every session.

*Unmeasured:* a second server; the console; eAPI; what `aaa authorization exec default local` (no
port49) does to a token user's role (L16 measured roles under `commands ... local` only).
