# L4 (ERROR, closed, silent) — juniper_vsrx

- **Date measured:** 2026-09-24
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22; the device calls itself `srx1`)
- **Image version:** vSRX3 21.4R3.15 (`show version`: `Junos: 21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Captures** (taken by hand, no loopback probes; every packet is to or from the lab subnet):
  - `tests/lab/evidence/L4-error-juniper_vsrx.pcap` — (a), 980 packets
  - `tests/lab/evidence/L4-unreachable-juniper_vsrx.pcap` — (c) closed, 412 packets
  - `tests/lab/evidence/L4-silent-juniper_vsrx.pcap` — (c) silent from a healthy server, and (d), 1195 packets
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
| (a) authentication ERROR | **local login**, 0.13s | **refused** |
| (c) closed (RST) | local login, 0.13s | local login, 0.13s |
| (c) silent, from a healthy server | local login, **0.13s** | local login, **0.13s** |
| (d) a token login right after the server answers again | reaches port49 | reaches port49 |

Junos treats an ERROR like a FAIL: final under `tacplus` alone, a fall-through when `password` is
listed. A silent server costs nothing: the login completes without waiting for the TCP handshake.
There is no dead-time setting.

## Observation

### (a) Authentication answered ERROR

`store_unavailable` in force. `authentication-order [ tacplus password ]`: `breakglass` logged in
0.13s after the password, `show version | match Junos:` answered `Junos: 21.4R3.15`, and the
decision log holds the ERROR it fell through:

```
{"ts":"2026-09-24T02:38:37.427Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"","priv":1,"method":"ascii"}
```

`authentication-order tacplus` (read back `authentication-order tacplus;`):

```
(breakglass@172.100.100.22) Password:
breakglass@172.100.100.22's password:
```

refused, with two ERRORs answered:

```
{"ts":"2026-09-24T02:38:49.312Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"","priv":1,"method":"ascii"}
{"ts":"2026-09-24T02:38:49.366Z","event":"redeem","verdict":"deny","reason":"store_unavailable","user":"breakglass","port":"","priv":1,"method":"ascii"}
```

### (c) Closed against silent

Closed: port49d stopped. Silent: `iptables -I INPUT -s 172.100.100.22 -d 172.100.100.1 -p tcp
--dport 49 -j DROP`, inserted after a token login had just been answered (`u001`, 02:39:57.468Z
`redeem permit token_redeemed`; for `tacplus`, `u003` at 02:40:17.191Z).

| order | condition | login | `show version \| match Junos:` |
|---|---|---|---|
| `[ tacplus password ]` | closed | local, 0.13s | 0.11s |
| `[ tacplus password ]` | silent | local, 0.13s | 0.11s |
| `[ tacplus password ]` | silent, again | local, 0.13s | 0.11s |
| `tacplus` | closed | local, 0.13s | 0.11s |
| `tacplus` | silent | local, 0.13s | 0.12s |
| `tacplus` | silent, again | local, 0.13s | 0.11s |

The capture has the device's SYN for the first silent login at 02:39:59.901029Z, retransmitted
at 02:40:00.917, 01.941 and 02.965 after the session was already at its prompt: as on
vJunos-router, the login did not wait for the connection.

### (d) A returned server, and dead time

A token login immediately after each DROP was removed reached port49: `u002` at 02:40:11.051Z,
`u004` at 02:40:30.781Z, both `redeem permit token_redeemed`.

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
- Cell for cell the same as vJunos-router 23.4R2-S2.1 (`L4-error-juniper_vjunos-router.md`).

*Unmeasured:* NETCONF; `single-connection`; a second server; the `timeout` leaf's effect on a
server that accepts the connection and never replies (L13 measured about 3s).
