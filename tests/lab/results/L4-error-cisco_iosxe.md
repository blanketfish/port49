# L4 (ERROR, closed, silent) — cisco_iosxe

- **Date measured:** 2026-09-24
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Captures** (all taken by hand, no loopback probes; every packet is to or from the lab subnet):
  - `tests/lab/evidence/L4-error-cisco_iosxe.pcap` — (a) and (b), 3396 packets
  - `tests/lab/evidence/L4-unreachable-cisco_iosxe.pcap` — (c), 392 packets, 0 TACACS+ packets: every device connection is a SYN answered by RST or by nothing
  - `tests/lab/evidence/L4-retry-closed-cisco_iosxe.pcap`, `L4-retry-silent-cisco_iosxe.pcap` — (d)
  - `tests/lab/evidence/L4-deadtime-cfg-cisco_iosxe.pcap` — the session that asked the device for a dead-time setting
- **Transport:** SSH
- **Method:** by hand. port49d ran a derivation of `tests/lab/port49d-lab.yaml` with
  `session_attributes: ["priv-lvl=15"]`, extra seeds for `xe1`, and `lab.fault_file`, the lab
  fault switch added for this run (`author.LabFault`): `store_unavailable` fails the store reads
  every request handler starts with, so authentication answers **ERROR** `store_unavailable` and
  authorization answers **FAIL** `store_unavailable`, which is what port49 does today when its
  store is down; `command_error` and `command_fail` answer every per-command authorization ERROR
  or FAIL and leave the session authorization alone. Method lists were changed between cells by a
  fresh token session with no fault in force, and each change was read back with `show
  running-config`.

## Claim

Spec §15 L4, the parts this run adds: (a) whether the device falls through to its local
break-glass account when port49 answers authentication **ERROR**; (b) what the device does with a
per-command authorization FAIL against an ERROR, under lists with and without `local` and with
`if-authenticated`; (c) with port49d's listener closed (RST) against silent (SYNs dropped), the
time to fall through for authentication and for authorization, and whether break-glass logs in
and runs commands; (d) how long the device keeps skipping the server after it comes back, and
whether that is configurable.

## Answer

| cell | outcome |
|---|---|
| (a) authentication ERROR, `group port49 local` | **break-glass refused.** No fall-through: the ERROR ends the attempt |
| (a) authentication ERROR, `group port49` | break-glass refused |
| (b) command FAIL, any list | refused |
| (b) command ERROR, `group port49 local` | refused `% Authorization failed.` (the `local` method refuses a user it has no account for) |
| (b) command ERROR, `group port49` | refused `% Authorization failed.` |
| (b) command ERROR, `group port49 if-authenticated` | **every command runs** |
| (c) closed (RST) | break-glass logs in, 0.06s; every command 0.06s |
| (c) silent | break-glass logs in (0.06s on the first try, 5.06s on another run); **every command 5.06s** |
| (d) after a closed server returns | the next login asks it |
| (d) after a silent server returns | a login 2s later skipped it; one 25s later asked it |
| dead-time setting | none offered on this image |

So on this image **an ERROR is never a way to break-glass**: authentication ERROR refuses the
local account outright, and a per-command ERROR is a refusal unless the list ends in
`if-authenticated`, where it is a permit for everything. Break-glass works only when port49d is
unreachable — and while it is silent, every command costs the full 5s server timeout.

## Observation

### (a) Authentication answered ERROR

`breakglass` presented its local password with `store_unavailable` in force.

```
aaa authentication login default group port49 local
```

```
(breakglass@172.100.100.41) Password:
breakglass@172.100.100.41's password:
```

refused, 2.05s after the password was sent (the second prompt is ssh's next method; it was
refused the same way). Decision log:

```
{"ts":"2026-09-24T01:43:48.228Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"tty434","priv":1,"method":"ascii"}
{"ts":"2026-09-24T01:43:50.282Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"tty434","priv":1,"method":"ascii"}
```

port49 answered ERROR to both attempts, and the device refused the login rather than trying
`local`. With `aaa authentication login default group port49` the same, at 01:43:58.257Z and
01:44:00.311Z.

### (b) Per-command authorization, FAIL against ERROR

A token session (`priv-lvl=15`) opened with no fault; the fault was set after the prompt; then
three commands. The list was set identically for levels 1 and 15.

| list | port49 answers | `show version \| include Software` | `show running-config \| include ^hostname` | `show privilege` |
|---|---|---|---|---|
| `group port49 local` | FAIL | refused, no output | refused, no output | `port49: denied by lab fault command_fail` |
| `group port49 local` | ERROR | refused, no output | refused, no output | `% Authorization failed.` |
| `group port49` | FAIL | refused, no output | refused, no output | `port49: denied by lab fault command_fail` |
| `group port49` | ERROR | refused, no output | refused, no output | `% Authorization failed.` |
| `group port49 if-authenticated` | FAIL | refused, no output | refused, no output | `port49: denied by lab fault command_fail` |
| `group port49 if-authenticated` | ERROR | **ran** | **ran** | **ran** |

The `if-authenticated` / ERROR session, verbatim:

```
show version | include Software
Cisco IOS XE Software, Version 17.13.01a
Cisco IOS Software [IOSXE], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 17.13.1a, RELEASE SOFTWARE (fc3)
xe1#
show running-config | include ^hostname
hostname xe1
xe1#
show privilege
Current privilege level is 15
xe1#
```

and port49 had refused all three: `authorize_command verdict=deny reason=store_unavailable` for
`show version`, `show running-config`, `show privilege` (01:44:37.622Z, .890Z, 01:44:38.195Z).
Every cell has one `authorize_command` record per command, so each outcome is the device's answer
to port49's reply. A piped command that is refused prints nothing at all — no message — which is
L2's IOS-XE finding again.

### (c) Closed against silent

`breakglass`, `aaa authentication login default group port49 local`, `aaa authorization exec
default group port49 local`, command lists `group port49 local`. "Closed" is port49d stopped:
nothing listens on 172.100.100.1:49 and the host answers each SYN with RST. "Silent" is `iptables
-I INPUT -s 172.100.100.41 -d 172.100.100.1 -p tcp --dport 49 -j DROP`.

| condition | login | `terminal length 0` | `show privilege` | `show version \| include Software` | `configure terminal` | `end` |
|---|---|---|---|---|---|---|
| closed | logged in, 0.06s | 0.06s | 0.06s | 0.07s | 0.07s | 0.07s |
| closed, again | logged in, 0.06s | 0.06s | 0.06s | | | |
| silent | logged in, 0.06s | 5.06s | 5.06s | 5.06s | 5.06s | 0.05s |
| silent, again | logged in, 0.06s | 5.06s | 5.06s | | | |
| silent (run d3, not preceded by a closed server) | logged in, **5.06s** | 5.06s | 5.06s | | | |
| silent (run d3), again | logged in, 5.06s | 5.06s | 5.06s | | | |

Every command ran and the session was at level 15 (`Current privilege level is 15`). The 5.06s is
`tacacs server port49-host` / `timeout 5` from the startup config: silent, the device waits the
full timeout for each command's authorization before falling through to `local`, and it does not
learn — the second session pays it again. The capture shows the SYNs retransmitted and never
answered (the first silent login's at 01:45:27.227Z, then every second).

Why the first silent login took 0.06s and the d3 one 5.06s is not settled by this run: the first
came 3s after two closed-server logins, the second did not.

### (d) How long a returned server is skipped

- **After closed.** port49d stopped, `breakglass` logged in at 01:46:47.532Z (RST), port49d
  started; a token login at 01:47:00.600Z reached it (`redeem permit token_redeemed`). Again at
  01:51:56.116Z, 20s after the last closed-server login: reached it.
- **After silent.** The DROP rule was in place from 01:52:08.293Z to 01:52:58Z, with two
  `breakglass` logins in it. A token login at 01:52:58.366Z was **refused in 2.05s with no
  `redeem` record** — the device did not ask port49 and `local` has no such user — while the same
  connection window delivered the queued accounting for `breakglass`. A token login at
  01:53:21.562Z reached port49 and logged in.

So a timeout marks the server dead for authentication for a while — the device still skipped it
45s after the first timeout (01:52:13Z) and asked it again 68s after; a refused connection does
not mark it dead at all.

**No dead-time setting exists on this image.** Asked in configuration mode:

```
xe1(config)#aaa group server tacacs+ port49
xe1(config-sg-tacacs+)#deadtime 1
                         ^
% Invalid input detected at '^' marker.
xe1(config-sg-tacacs+)#?
TACACS+ Server-group commands:
  accounting        Accounting specific command
  cache             cached DB profile configuration
  default           Set a command to its defaults
  dns-alias-lookup  Enable IP Domain Name System Alias lookup for TACACS servers
  exit              Exit from TACACS+ server-group confguration mode
  host              Specify a TACACS server
  ip                Internet Protocol config commands
  ipv6              IPv6 config commands
  no                Negate a command or set its defaults
  pick-method       Method by which the next host will be picked
  server            Specify a TACACS server
  server-private    Define a private TACACS server (per group)
  timeout           Time to wait for a TACACS server to reply
xe1(config)#tacacs-server ?
  administration    Start tacacs+ deamon handling administrative messages
  attribute         Customize selected tacacs attributes
  cache             AAA auth cache default server group
  directed-request  Allow user to specify tacacs server to use with `@server'
  dns-alias-lookup  Enable IP Domain Name System Alias lookup for TACACS servers
  domain-stripping  Strip the domain from the username
  host              Specify a TACACS server
  key               Set TACACS+ encryption key.
  packet            Modify TACACS+ packet options
  timeout           Time to wait for a TACACS server to reply
xe1(config)#aaa dead-criteria ?
% Unrecognized command
```

## Reading

- **port49's `store_unavailable` answers are the right ones on this platform, and the reason is
  `if-authenticated`.** Authorization answers FAIL when the store cannot be read (plan 4, ruled
  2026-09-24). Had it been ERROR, every IOS-XE device whose command list ends in
  `if-authenticated` would authorize every command for every logged-in user for the length of a
  store outage.
- **A store outage locks out break-glass here.** Authentication ERROR does not fall through, so
  while port49d is up and cannot read its store, nobody logs in over SSH, local account included.
  The console's own `CONSOLE` list (`local`) is the only way in. That is the §5.6 3am case, and it
  is worse than "server unreachable", where break-glass gets in.
- Silent is the expensive failure: 5s per command, every command, every session.
- A piped command is refused silently (no message at all).
- A side observation: a `do show ...` typed in configuration mode is authorized as
  `cmd=do-exec` with the pipe and its pattern as arguments (`do-exec show running-config | section
  ^aaa gr...`), unlike the same command at the exec prompt, which drops the pipe.

*Unmeasured:* a second TACACS+ server; ERROR on the session (exec) authorization; `break-glass`
under a command ERROR (it cannot log in while port49d answers); the console under any of these;
`single-connection`.
