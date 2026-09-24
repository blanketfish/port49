# Quarantine close — cisco_nxos

- **Date measured:** 2026-09-24
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Captures** (by hand, no loopback probes; every packet to or from the lab subnet):
  `tests/lab/evidence/quarantine-cisco_nxos.pcap` (160 packets: the session opened with port49d answering) and
  `tests/lab/evidence/quarantine-closed-cisco_nxos.pcap` (260 packets: quarantined, then stopped). In the second,
  17 device connections end in a server RST after the device's first segment (the quarantine close) and 14
  in a RST answering the SYN (port49d stopped).
- **Transport:** SSH
- **Method:** by hand, with this branch's `port49d` (feature/policy-engine). "Quarantined" is the daemon
  restarted on a derivation of `tests/lab/port49d-lab.yaml` plus `tests/lab/quarantine/broker.yaml`, whose
  policy (`tests/lab/quarantine/policy.yaml`) quarantines every lab device; at start it said:

  ```
  port49d: broker: device nx1 (cisco_nxos) is quarantined: subject "quarantine_probe": role "quarantines_all" names @loopback, which cisco_nxos does not define
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
| (1) break-glass login | logged in, 0.22s; again logged in, 0.22s | logged in, 0.21s; again logged in, 0.22s |
| (1) break-glass commands | `show hostname` 0.07s; `configure terminal` 0.07s; `end` 0.08s | `show hostname` 0.07s; `configure terminal` 0.08s; `end` 0.08s |
| (2) command in the already-open `u001` session | `show hostname` 0.07s; `show hostname` 0.08s; `show hostname` 0.08s | `show hostname` 0.07s; `show hostname` 0.08s; `show hostname` 0.08s |
| a new token login (`u002`) | refused, 1.59s: the device fell to `local`, which has no such user | — |

Before the change, with port49d answering: `show hostname` 0.08s; `show hostname` 0.08s.

Each command in the open session and each break-glass exchange while quarantined left one
`event=unvalidated reason=device_quarantined` record per connection and nothing else (3 for the
open session's commands) — so port49 logs that the device asked and was closed, and the device ran the
command on its local fall-through.

## Run log

Transcripts and decision records exactly as the run wrote them (passwords are never echoed by the device;
`unvalidated` records are shown by reason, diagnosis and source).

## cisco_nxos


port49d started 04:05:28.498Z (no broker, no policy):
```
port49d lab: 172 login token(s) and 0 enable token(s) minted, credentials written to /tmp/port49-lab-tokens.jsonl
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
```

#### token session `u001` opened 04:05:30.944Z: logged in

#### (0) the open session, port49d answering

```
show hostname
nx1 
nx1# 
show hostname
nx1 
nx1# 
```
per line: `show hostname` 0.08s; `show hostname` 0.08s
decision log:
```
{"ts":"2026-09-24T04:05:31.024Z","event":"account","verdict":null,"reason":null,"user":"u001","port":"0","priv":0,"method":null,"vector":null,"flags":"stop","raw":["task_id=172.100.100.1@pts/3","start_time=1790222729","timezone=UTC","cmd=terminal length 0 (SUCCESS)","service=none"]}
{"ts":"2026-09-24T04:05:31.089Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","user":"u001","port":"","priv":1,"method":null,"vector":["show","hostname"],"raw":["service=shell","cmd=show","cmd-arg=hostname","cmd-arg=<cr>"]}
{"ts":"2026-09-24T04:05:31.168Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","user":"u001","port":"","priv":1,"method":null,"vector":["show","hostname"],"raw":["service=shell","cmd=show","cmd-arg=hostname","cmd-arg=<cr>"]}
```

port49d stopped 04:05:39.761Z: nothing listens on 172.100.100.1:49

port49d started 04:05:43.301Z (with the quarantine policy):
```
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
port49d: broker listening on 127.0.0.1:8449
```
```
port49d: broker: device nx1 (cisco_nxos) is quarantined: subject "quarantine_probe": role "quarantines_all" names @loopback, which cisco_nxos does not define
```

#### (2) the open session, device now quarantined

```
show hostname
nx1 
nx1# 
show hostname
nx1 
nx1# 
show hostname
nx1 
nx1# 
```
per line: `show hostname` 0.07s; `show hostname` 0.08s; `show hostname` 0.08s
decision log:
```
{"ts":"2026-09-24T04:05:43.369Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:43.448Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:43.529Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
```

#### (1) break-glass while quarantined

`breakglass` login started 04:05:45.534Z: **logged in**, 0.22s after the password was sent
```
show hostname
nx1 
nx1# 
configure terminal
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
end
nx1# 
```
per line: `show hostname` 0.07s; `configure terminal` 0.07s; `end` 0.08s
decision log:
```
{"ts":"2026-09-24T04:05:45.758Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:45.886Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:45.973Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:46.052Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:46.132Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:46.215Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
```

#### (1) break-glass while quarantined, again

`breakglass` login started 04:05:48.321Z: **logged in**, 0.22s after the password was sent
```
show hostname
nx1 
nx1# 
```
per line: `show hostname` 0.07s
decision log:
```
{"ts":"2026-09-24T04:05:48.543Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:48.676Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:48.761Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:48.842Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
```

#### token login `u002` while quarantined

`u002` login started 04:05:50.953Z: **refused**, 1.59s after the password was sent
device said:
```
(u002@172.100.100.31) Password: 
u002@172.100.100.31's password:
```
decision log:
```
{"ts":"2026-09-24T04:05:51.175Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:52.713Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:52.768Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
{"ts":"2026-09-24T04:05:54.439Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.31"}
```

port49d stopped 04:05:59.232Z: nothing listens on 172.100.100.1:49

#### (3) the open session, port49d stopped

```
show hostname
nx1 
nx1# 
show hostname
nx1 
nx1# 
show hostname
nx1 
nx1# 
```
per line: `show hostname` 0.07s; `show hostname` 0.08s; `show hostname` 0.08s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped

`breakglass` login started 04:06:01.464Z: **logged in**, 0.21s after the password was sent
```
show hostname
nx1 
nx1# 
configure terminal
Enter configuration commands, one per line. End with CNTL/Z.
nx1(config)# 
end
nx1# 
```
per line: `show hostname` 0.07s; `configure terminal` 0.08s; `end` 0.08s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped, again

`breakglass` login started 04:06:04.245Z: **logged in**, 0.22s after the password was sent
```
show hostname
nx1 
nx1# 
```
per line: `show hostname` 0.07s
decision log:
```
(no record)
```
