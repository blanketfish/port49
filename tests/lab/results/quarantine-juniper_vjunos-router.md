# Quarantine close — juniper_vjunos-router

- **Date measured:** 2026-09-24
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Captures** (by hand, no loopback probes; every packet to or from the lab subnet):
  `tests/lab/evidence/quarantine-juniper_vjunos-router.pcap` (846 packets: the session opened with port49d answering) and
  `tests/lab/evidence/quarantine-closed-juniper_vjunos-router.pcap` (240 packets: quarantined, then stopped). In the second,
  15 device connections end in a server RST after the device's first segment (the quarantine close) and 15
  in a RST answering the SYN (port49d stopped).
- **Transport:** SSH
- **Method:** by hand, with this branch's `port49d` (feature/policy-engine). "Quarantined" is the daemon
  restarted on a derivation of `tests/lab/port49d-lab.yaml` plus `tests/lab/quarantine/broker.yaml`, whose
  policy (`tests/lab/quarantine/policy.yaml`) quarantines every lab device; at start it said:

  ```
  port49d: broker: device srx1 (juniper_junos) is quarantined: subject "quarantine_probe": role "quarantines_all" names @loopback, which juniper_junos does not define
  ```

  A quarantined device's packet is answered by reading the 12-byte header and closing the connection with
  the body unread, which the kernel sends as a RST (`internal/daemon/server/conn.go`). "Stopped" is port49d
  not running: nothing listens on 172.100.100.1:49 and the host answers each SYN with RST. A seeded-token
  session (`u001`) was opened while port49d answered normally and held open across both changes. Device
  configuration: `tests/lab/configs/` as shipped.

No register row; recorded for spec §10 / §13 decision 20, whose close-on-quarantine assumes a closed
connection costs the device what "connection refused" does (`tests/lab/results/L4-error-*.md`).

## Answer

**The quarantine close behaves like connection refused on this image: no silent-server stall.** Junos sends
no per-command authorization (decision 21), so the connections row (2) records while quarantined are the
session's accounting, not command checks; the commands' timing is the same in all three states.

| step | quarantined (close after header) | port49d stopped (refused) |
|---|---|---|
| (1) break-glass login | logged in, 0.09s; again logged in, 0.08s | logged in, 0.08s; again logged in, 0.08s |
| (1) break-glass commands | `show version | match Junos:` 0.17s | `show version | match Junos:` 0.17s |
| (2) command in the already-open `u001` session | `show version | match Junos:` 0.18s; `show version | match Junos:` 0.19s; `show version | match Junos:` 0.18s | `show version | match Junos:` 0.17s; `show version | match Junos:` 0.19s; `show version | match Junos:` 0.17s |
| a new token login (`u002`) | refused, 0.07s: the device fell to `local`, which has no such user | — |

Before the change, with port49d answering: `show version | match Junos:` 0.35s; `show version | match Junos:` 0.52s.

Each command in the open session and each break-glass exchange while quarantined left one
`event=unvalidated reason=device_quarantined` record per connection and nothing else (3 for the
open session's commands) — so port49 logs that the device asked and was closed, and the device ran the
command on its local fall-through.

## Run log

Transcripts and decision records exactly as the run wrote them (passwords are never echoed by the device;
`unvalidated` records are shown by reason, diagnosis and source).

## juniper_vjunos-router


port49d started 04:10:19.726Z (no broker, no policy):
```
port49d lab: 172 login token(s) and 0 enable token(s) minted, credentials written to /tmp/port49-lab-tokens.jsonl
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
```

#### token session `u001` opened 04:10:21.904Z: logged in

#### (0) the open session, port49d answering

```
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
```
per line: `show version | match Junos:` 0.35s; `show version | match Junos:` 0.52s
decision log:
```
(no record)
```

port49d stopped 04:10:31.371Z: nothing listens on 172.100.100.1:49

port49d started 04:10:34.915Z (with the quarantine policy):
```
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
port49d: broker listening on 127.0.0.1:8449
```
```
port49d: broker: device srx1 (juniper_junos) is quarantined: subject "quarantine_probe": role "quarantines_all" names @loopback, which juniper_junos does not define
```

#### (2) the open session, device now quarantined

```
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
```
per line: `show version | match Junos:` 0.18s; `show version | match Junos:` 0.19s; `show version | match Junos:` 0.18s
decision log:
```
{"ts":"2026-09-24T04:10:35.357Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:35.358Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:35.358Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
```

#### (1) break-glass while quarantined

`breakglass` login started 04:10:37.461Z: **logged in**, 0.09s after the password was sent
```
show version | match Junos: 
Junos: 23.4R2-S2.1

breakglass@srx1> 
```
per line: `show version | match Junos:` 0.17s
decision log:
```
{"ts":"2026-09-24T04:10:37.545Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
```

#### (1) break-glass while quarantined, again

`breakglass` login started 04:10:39.984Z: **logged in**, 0.08s after the password was sent
```
show version | match Junos: 
Junos: 23.4R2-S2.1

breakglass@srx1> 
```
per line: `show version | match Junos:` 0.17s
decision log:
```
{"ts":"2026-09-24T04:10:40.063Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:40.361Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:40.362Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:40.362Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:40.363Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:40.364Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:40.364Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
```

#### token login `u002` while quarantined

`u002` login started 04:10:42.488Z: **refused**, 0.07s after the password was sent
device said:
```
(u002@172.100.100.21) Password:
u002@172.100.100.21's password:
```
decision log:
```
{"ts":"2026-09-24T04:10:42.568Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:42.696Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:45.372Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
{"ts":"2026-09-24T04:10:45.373Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.21"}
```

port49d stopped 04:10:51.317Z: nothing listens on 172.100.100.1:49

#### (3) the open session, port49d stopped

```
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
show version | match Junos: 
Junos: 23.4R2-S2.1

u001@srx1> 
```
per line: `show version | match Junos:` 0.17s; `show version | match Junos:` 0.19s; `show version | match Junos:` 0.17s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped

`breakglass` login started 04:10:53.855Z: **logged in**, 0.08s after the password was sent
```
show version | match Junos: 
Junos: 23.4R2-S2.1

breakglass@srx1> 
```
per line: `show version | match Junos:` 0.17s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped, again

`breakglass` login started 04:10:56.354Z: **logged in**, 0.08s after the password was sent
```
show version | match Junos: 
Junos: 23.4R2-S2.1

breakglass@srx1> 
```
per line: `show version | match Junos:` 0.17s
decision log:
```
(no record)
```
