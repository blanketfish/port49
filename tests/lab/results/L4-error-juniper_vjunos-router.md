# L4 (ERROR, closed, silent) — juniper_vjunos-router

- **Date measured:** 2026-09-24
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`show version`: `Junos: 23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Captures** (taken by hand, no loopback probes; every packet is to or from the lab subnet):
  - `tests/lab/evidence/L4-error-juniper_vjunos-router.pcap` — (a), first run, 1596 packets; its `tacplus` cell did not take (below)
  - `tests/lab/evidence/L4-error2-juniper_vjunos-router.pcap` — (a), the `tacplus` cell, 566 packets
  - `tests/lab/evidence/L4-unreachable-juniper_vjunos-router.pcap` — (c) closed, 384 packets
  - `tests/lab/evidence/L4-silent-juniper_vjunos-router.pcap` — (c) silent from a healthy server, and (d), 1276 packets
- **Transport:** SSH
- **Method:** by hand, as `L4-error-cisco_iosxe.md` describes, with `session_attributes: []`.
  `system authentication-order` was changed as `breakglass` (which falls through to its local
  password on a FAIL when `password` is listed, L4 reading 1), with `delete system
  authentication-order` first, and read back with `show configuration system
  authentication-order`. Startup config: `tests/lab/configs/vjunos-startup.conf`. Junos sends no
  per-command authorization (decision 21), so (b) does not apply.

## Claim

Spec §15 L4, the parts this run adds: authentication ERROR fall-through to break-glass under
`authentication-order [ tacplus password ]` and `tacplus`; closed against silent; how long a
returned server is skipped, and whether a dead time is configurable.

## Answer

| cell | `[ tacplus password ]` | `tacplus` |
|---|---|---|
| (a) authentication ERROR | **local login**, 0.09s | **refused** |
| (c) closed (RST) | local login, 0.08s | local login, 0.08s |
| (c) silent, from a healthy server | local login, **0.08s** | local login, **0.08s** |
| (d) a token login right after the server answers again | reaches port49 | reaches port49 |

Junos treats an ERROR like a FAIL: final under `tacplus` alone, a fall-through when `password` is
listed. A silent server costs nothing: the login completes without waiting for the TCP handshake.
There is no dead-time setting.

## Observation

### (a) Authentication answered ERROR

`store_unavailable` in force. `authentication-order [ tacplus password ]`: `breakglass` logged in
0.09s after the password, `show version | match Junos:` answered `Junos: 23.4R2-S2.1`, and the
decision log holds the ERROR it fell through:

```
{"ts":"2026-09-24T02:33:15.145Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"","priv":1,"method":"ascii"}
```

`authentication-order tacplus` (read back `authentication-order tacplus;`):

```
(breakglass@172.100.100.21) Password:
breakglass@172.100.100.21's password:
```

refused, with two ERRORs answered:

```
{"ts":"2026-09-24T02:34:02.177Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"","priv":1,"method":"ascii"}
{"ts":"2026-09-24T02:34:02.232Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"","priv":1,"method":"ascii"}
```

The first run's `tacplus` cell (02:33:26Z, in `L4-error-juniper_vjunos-router.pcap`) logged in,
and is void: `set system authentication-order tacplus` on a list that already held `[ tacplus
password ]` added nothing, and the read-back showed `authentication-order [ tacplus password ];`.
The cell was re-run with `delete` first.

### (c) Closed against silent

Closed: port49d stopped. Silent: `iptables -I INPUT -s 172.100.100.21 -d 172.100.100.1 -p tcp
--dport 49 -j DROP`, inserted after a token login had just been answered (`u001`, 02:35:42.553Z
`redeem permit token_redeemed`), so the device had no reason to think the server down.

| order | condition | login | `show version \| match Junos:` |
|---|---|---|---|
| `[ tacplus password ]` | closed | local, 0.08s | 0.18s |
| `[ tacplus password ]` | silent | local, 0.08s | 0.18s |
| `[ tacplus password ]` | silent, again | local, 0.08s | 0.18s |
| `tacplus` | closed | local, 0.08s | 0.17s |
| `tacplus` | silent | local, 0.08s | 0.17s |
| `tacplus` | silent, again | local, 0.08s | 0.18s |

The silent logins are not the device skipping a server it knew was down. The capture has the
device's SYN for the first silent login at 02:35:45.004387Z, with retransmits at 02:35:46.005,
47.030, 48.053, 49.077, 50.101 and 52.149 — still being retried after the session was at its
prompt. The login did not wait for the connection.

### (d) A returned server, and dead time

A token login immediately after each DROP was removed reached port49: `u002` at 02:35:56.220Z,
`u004` at 02:36:41.444Z, both `redeem permit token_redeemed`.

```
breakglass@srx1# set system tacplus-server 172.100.100.1 ?
Possible completions:
  <[Enter]>            Execute this command
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
  port                 TACACS+ authentication server port number
  routing-instance     Routing instance
  secret               Shared secret with the authentication server
  single-connection    Optimize TCP connection attempts
  source-address       Use specified address as source address
  timeout              Request timeout period (1..90 seconds)
  |                    Pipe through a command
```

No dead-time setting. The order was restored to `[ tacplus password ]` at the end (read back).

## Reading

- **`authentication-order tacplus` is the one Junos shape where a store outage locks break-glass
  out:** port49 answers ERROR, Junos treats it as final. With `password` listed, break-glass gets
  in during a store outage — and, per L4 reading 1, also on any FAIL. There is no Junos order that
  is both "TACACS+ is final while it answers" and "local when the store is down".
- An unreachable or silent server costs a Junos login nothing measurable on this image.

*Unmeasured:* NETCONF; `single-connection`; a second server; the `timeout` leaf's effect on a
server that accepts the connection and never replies (L13 measured about 3s).
