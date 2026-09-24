# Quarantine close — arista_eos

- **Date measured:** 2026-09-24
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Captures** (by hand, no loopback probes; every packet to or from the lab subnet):
  `tests/lab/evidence/quarantine-arista_eos.pcap` (186 packets: the session opened with port49d answering) and
  `tests/lab/evidence/quarantine-closed-arista_eos.pcap` (508 packets: quarantined, then stopped). In the second,
  31 device connections end in a server RST after the device's first segment (the quarantine close) and 34
  in a RST answering the SYN (port49d stopped).
- **Transport:** SSH
- **Method:** by hand, with this branch's `port49d` (feature/policy-engine). "Quarantined" is the daemon
  restarted on a derivation of `tests/lab/port49d-lab.yaml` plus `tests/lab/quarantine/broker.yaml`, whose
  policy (`tests/lab/quarantine/policy.yaml`) quarantines every lab device; at start it said:

  ```
  port49d: broker: device leaf1 (arista_eos) is quarantined: subject "quarantine_probe": level operator has no rendering on arista_eos and no parent that has one (spec §6)
  ```

  A quarantined device's packet is answered by reading the 12-byte header and closing the connection with
  the body unread, which the kernel sends as a RST (`internal/daemon/server/conn.go`). "Stopped" is port49d
  not running: nothing listens on 172.100.100.1:49 and the host answers each SYN with RST. A seeded-token
  session (`u001`) was opened while port49d answered normally and held open across both changes. Device
  configuration: `tests/lab/configs/` as shipped.

No register row; recorded for spec §10 / §13 decision 20, whose close-on-quarantine assumes a closed
connection costs the device what "connection refused" does (`tests/lab/results/L4-error-*.md`).

## Answer

**The quarantine close behaves like connection refused on this image: no silent-server stall.**

| step | quarantined (close after header) | port49d stopped (refused) |
|---|---|---|
| (1) break-glass login | logged in, 0.65s; again logged in, 0.65s | logged in, 0.65s; again logged in, 0.65s |
| (1) break-glass commands | `show privilege` 0.08s; `configure terminal` 0.06s; `end` 0.06s | `show privilege` 0.07s; `configure terminal` 0.07s; `end` 0.06s |
| (2) command in the already-open `u001` session | `show privilege` 0.06s; `show privilege` 0.06s; `show privilege` 0.06s | `show privilege` 0.06s; `show privilege` 0.06s; `show privilege` 0.06s |
| a new token login (`u002`) | refused, 1.87s: the device fell to `local`, which has no such user | — |

Before the change, with port49d answering: `show privilege` 0.08s; `show privilege` 0.08s.

Each command in the open session and each break-glass exchange while quarantined left one
`event=unvalidated reason=device_quarantined` record per connection and nothing else (3 for the
open session's commands) — so port49 logs that the device asked and was closed, and the device ran the
command on its local fall-through.

## Run log

Transcripts and decision records exactly as the run wrote them (passwords are never echoed by the device;
`unvalidated` records are shown by reason, diagnosis and source).

## arista_eos


port49d started 04:01:53.767Z (no broker, no policy):
```
port49d lab: 172 login token(s) and 0 enable token(s) minted, credentials written to /tmp/port49-lab-tokens.jsonl
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
```

#### token session `u001` opened 04:01:56.643Z: logged in

#### (0) the open session, port49d answering

```
show privilege
Current privilege level is 15
leaf1#
show privilege
Current privilege level is 15
leaf1#
```
per line: `show privilege` 0.08s; `show privilege` 0.08s
decision log:
```
{"ts":"2026-09-24T04:01:56.779Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","user":"u001","port":"vty4","priv":15,"method":null,"vector":["show","privilege"],"raw":["service=shell","cmd=show","cmd-arg=privilege","cmd-arg=<cr>"]}
{"ts":"2026-09-24T04:01:56.782Z","event":"account","verdict":null,"reason":null,"user":"u001","port":"vty4","priv":15,"method":null,"vector":null,"flags":"stop","raw":["task_id=12","service=shell","priv-lvl=15","start_time=1790222515","timezone=UTC","cmd=show privilege <cr>"]}
{"ts":"2026-09-24T04:01:56.859Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","user":"u001","port":"vty4","priv":15,"method":null,"vector":["show","privilege"],"raw":["service=shell","cmd=show","cmd-arg=privilege","cmd-arg=<cr>"]}
{"ts":"2026-09-24T04:01:56.862Z","event":"account","verdict":null,"reason":null,"user":"u001","port":"vty4","priv":15,"method":null,"vector":null,"flags":"stop","raw":["task_id=13","service=shell","priv-lvl=15","start_time=1790222515","timezone=UTC","cmd=show privilege <cr>"]}
```

port49d stopped 04:02:05.548Z: nothing listens on 172.100.100.1:49

port49d started 04:02:09.094Z (with the quarantine policy):
```
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
port49d: broker listening on 127.0.0.1:8449
```
```
port49d: broker: device leaf1 (arista_eos) is quarantined: subject "quarantine_probe": level operator has no rendering on arista_eos and no parent that has one (spec §6)
```

#### (2) the open session, device now quarantined

```
show privilege
% Authorization denied for command 'show privilege': Unknown role
leaf1#
show privilege
% Authorization denied for command 'show privilege': Unknown role
leaf1#
show privilege
% Authorization denied for command 'show privilege': Unknown role
leaf1#
```
per line: `show privilege` 0.06s; `show privilege` 0.06s; `show privilege` 0.06s
decision log:
```
{"ts":"2026-09-24T04:02:09.151Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:09.211Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:09.270Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
```

#### (1) break-glass while quarantined

`breakglass` login started 04:02:11.274Z: **logged in**, 0.65s after the password was sent
```
show privilege
[?1h=Current privilege level is 15
[K[?1l>leaf1#
configure terminal
leaf1(config)#
end
leaf1#
```
per line: `show privilege` 0.08s; `configure terminal` 0.06s; `end` 0.06s
decision log:
```
{"ts":"2026-09-24T04:02:11.381Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:11.448Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:11.449Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:11.489Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.092Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.096Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.097Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.169Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.171Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.172Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.229Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.230Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.291Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.292Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.316Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:12.316Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
```

#### (1) break-glass while quarantined, again

`breakglass` login started 04:02:14.416Z: **logged in**, 0.65s after the password was sent
```
show privilege
[?1h=Current privilege level is 15
[K[?1l>leaf1#
```
per line: `show privilege` 0.07s
decision log:
```
{"ts":"2026-09-24T04:02:14.491Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:14.558Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:14.558Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:14.598Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:15.200Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:15.207Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:15.208Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:15.283Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:15.284Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:15.294Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
{"ts":"2026-09-24T04:02:15.294Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
```

#### token login `u002` while quarantined

`u002` login started 04:02:17.393Z: **refused**, 1.87s after the password was sent
device said:
```
(u002@172.100.100.11) Password: 
u002@172.100.100.11: Permission denied (publickey,keyboard-interactive).
```
decision log:
```
{"ts":"2026-09-24T04:02:17.469Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.11"}
```

port49d stopped 04:02:23.007Z: nothing listens on 172.100.100.1:49

#### (3) the open session, port49d stopped

```
show privilege
% Authorization denied for command 'show privilege': Unknown role
leaf1#
show privilege
% Authorization denied for command 'show privilege': Unknown role
leaf1#
show privilege
% Authorization denied for command 'show privilege': Unknown role
leaf1#
```
per line: `show privilege` 0.06s; `show privilege` 0.06s; `show privilege` 0.06s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped

`breakglass` login started 04:02:25.186Z: **logged in**, 0.65s after the password was sent
```
show privilege
[?1h=Current privilege level is 15
[K[?1l>leaf1#
configure terminal
leaf1(config)#
end
leaf1#
```
per line: `show privilege` 0.07s; `configure terminal` 0.07s; `end` 0.06s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped, again

`breakglass` login started 04:02:28.279Z: **logged in**, 0.65s after the password was sent
```
show privilege
[?1h=Current privilege level is 15
[K[?1l>leaf1#
```
per line: `show privilege` 0.07s
decision log:
```
(no record)
```
