# Quarantine close — cisco_iosxe

- **Date measured:** 2026-09-24
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Captures** (by hand, no loopback probes; every packet to or from the lab subnet):
  `tests/lab/evidence/quarantine-cisco_iosxe.pcap` (192 packets: the session opened with port49d answering) and
  `tests/lab/evidence/quarantine-closed-cisco_iosxe.pcap` (316 packets: quarantined, then stopped). In the second,
  20 device connections end in a server RST after the device's first segment (the quarantine close) and 19
  in a RST answering the SYN (port49d stopped).
- **Transport:** SSH
- **Method:** by hand, with this branch's `port49d` (feature/policy-engine). "Quarantined" is the daemon
  restarted on a derivation of `tests/lab/port49d-lab.yaml` plus `tests/lab/quarantine/broker.yaml`, whose
  policy (`tests/lab/quarantine/policy.yaml`) quarantines every lab device; at start it said:

  ```
  port49d: broker: device xe1 (cisco_iosxe) is quarantined: subject "quarantine_probe": role "quarantines_all" names @loopback, which cisco_iosxe does not define
  ```

  A quarantined device's packet is answered by reading the 12-byte header and closing the connection with
  the body unread, which the kernel sends as a RST (`internal/daemon/server/conn.go`). "Stopped" is port49d
  not running: nothing listens on 172.100.100.1:49 and the host answers each SYN with RST. A seeded-token
  session (`u001`) was opened while port49d answered normally and held open across both changes. Device
  configuration: `tests/lab/configs/` as shipped.

No register row; recorded for spec §10 / §13 decision 20, whose close-on-quarantine assumes a closed
connection costs the device what "connection refused" does (`tests/lab/results/L4-error-*.md`).

## Answer

**The quarantine close behaves like connection refused on this image: no silent-server stall.** One
difference: a command in the open session took 0.26–0.28s quarantined against 0.06s with port49d stopped —
the same 0.27s it took with port49d answering — so IOS-XE still makes its per-command attempt at the server
and is told no at once; the 5s timeout never comes into it.

| step | quarantined (close after header) | port49d stopped (refused) |
|---|---|---|
| (1) break-glass login | logged in, 0.06s; again logged in, 0.06s | logged in, 0.06s; again logged in, 0.06s |
| (1) break-glass commands | `show privilege` 0.26s; `configure terminal` 0.28s; `end` 0.07s | `show privilege` 0.06s; `configure terminal` 0.06s; `end` 0.06s |
| (2) command in the already-open `u001` session | `show privilege` 0.26s; `show privilege` 0.28s; `show privilege` 0.27s | `show privilege` 0.06s; `show privilege` 0.06s; `show privilege` 0.06s |
| a new token login (`u002`) | refused, 2.05s: the device fell to `local`, which has no such user | — |

Before the change, with port49d answering: `show privilege` 0.27s; `show privilege` 0.27s.

Each command in the open session and each break-glass exchange while quarantined left one
`event=unvalidated reason=device_quarantined` record per connection and nothing else (3 for the
open session's commands) — so port49 logs that the device asked and was closed, and the device ran the
command on its local fall-through.

## Run log

Transcripts and decision records exactly as the run wrote them (passwords are never echoed by the device;
`unvalidated` records are shown by reason, diagnosis and source).

## cisco_iosxe


port49d started 04:07:57.663Z (no broker, no policy):
```
port49d lab: 172 login token(s) and 0 enable token(s) minted, credentials written to /tmp/port49-lab-tokens.jsonl
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
```

#### token session `u001` opened 04:07:59.782Z: logged in

#### (0) the open session, port49d answering

```
show privilege
Current privilege level is 15
xe1#
show privilege
Current privilege level is 15
xe1#
```
per line: `show privilege` 0.27s; `show privilege` 0.27s
decision log:
```
{"ts":"2026-09-24T04:08:00.042Z","event":"account","verdict":null,"reason":null,"user":"u001","port":"tty434","priv":15,"method":null,"vector":null,"flags":"stop","raw":["task_id=4004","timezone=UTC","service=shell","priv-lvl=1","cmd=terminal length 0 <cr>"]}
{"ts":"2026-09-24T04:08:00.215Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","user":"u001","port":"tty434","priv":1,"method":null,"vector":["show","privilege"],"raw":["service=shell","cmd=show","cmd-arg=privilege","cmd-arg=<cr>"]}
{"ts":"2026-09-24T04:08:00.316Z","event":"account","verdict":null,"reason":null,"user":"u001","port":"tty434","priv":15,"method":null,"vector":null,"flags":"stop","raw":["task_id=4005","timezone=UTC","service=shell","priv-lvl=1","cmd=show privilege <cr>"]}
{"ts":"2026-09-24T04:08:00.483Z","event":"authorize_command","verdict":"permit","reason":"permit_dominates","user":"u001","port":"tty434","priv":1,"method":null,"vector":["show","privilege"],"raw":["service=shell","cmd=show","cmd-arg=privilege","cmd-arg=<cr>"]}
{"ts":"2026-09-24T04:08:00.584Z","event":"account","verdict":null,"reason":null,"user":"u001","port":"tty434","priv":15,"method":null,"vector":null,"flags":"stop","raw":["task_id=4006","timezone=UTC","service=shell","priv-lvl=1","cmd=show privilege <cr>"]}
```

port49d stopped 04:08:09.159Z: nothing listens on 172.100.100.1:49

port49d started 04:08:12.695Z (with the quarantine policy):
```
port49d: listening on 172.100.100.1:49, metrics on 127.0.0.1:9049, 5 devices admitted
port49d: broker listening on 127.0.0.1:8449
```
```
port49d: broker: device xe1 (cisco_iosxe) is quarantined: subject "quarantine_probe": role "quarantines_all" names @loopback, which cisco_iosxe does not define
```

#### (2) the open session, device now quarantined

```
show privilege
% Authorization failed.

xe1#
show privilege
% Authorization failed.

xe1#
show privilege
% Authorization failed.

xe1#
```
per line: `show privilege` 0.26s; `show privilege` 0.28s; `show privilege` 0.27s
decision log:
```
{"ts":"2026-09-24T04:08:12.853Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:13.129Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:13.402Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
```

#### (1) break-glass while quarantined

`breakglass` login started 04:08:15.503Z: **logged in**, 0.06s after the password was sent
```
show privilege
Current privilege level is 15
xe1#
configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
xe1(config)#
end
xe1#
```
per line: `show privilege` 0.26s; `configure terminal` 0.28s; `end` 0.07s
decision log:
```
{"ts":"2026-09-24T04:08:15.566Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:15.630Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:15.632Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:15.788Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:15.890Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:16.065Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:16.170Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:16.301Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
```

#### (1) break-glass while quarantined, again

`breakglass` login started 04:08:18.503Z: **logged in**, 0.06s after the password was sent
```
show privilege
Current privilege level is 15
xe1#
```
per line: `show privilege` 0.26s
decision log:
```
{"ts":"2026-09-24T04:08:18.565Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:18.628Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:18.630Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:18.786Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:18.887Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:18.956Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
```

#### token login `u002` while quarantined

`u002` login started 04:08:21.158Z: **refused**, 2.05s after the password was sent
device said:
```
(u002@172.100.100.41) Password: 
u002@172.100.100.41's password:
```
decision log:
```
{"ts":"2026-09-24T04:08:21.217Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
{"ts":"2026-09-24T04:08:23.321Z","event":"unvalidated","reason":"device_quarantined","diagnosis":"device_quarantined","source":"172.100.100.41"}
```

port49d stopped 04:08:28.937Z: nothing listens on 172.100.100.1:49

#### (3) the open session, port49d stopped

```
show privilege
% Authorization failed.

xe1#
show privilege
% Authorization failed.

xe1#
show privilege
% Authorization failed.

xe1#
```
per line: `show privilege` 0.06s; `show privilege` 0.06s; `show privilege` 0.06s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped

`breakglass` login started 04:08:31.114Z: **logged in**, 0.06s after the password was sent
```
show privilege
Current privilege level is 15
xe1#
configure terminal
Enter configuration commands, one per line.  End with CNTL/Z.
xe1(config)#
end
xe1#
```
per line: `show privilege` 0.06s; `configure terminal` 0.06s; `end` 0.06s
decision log:
```
(no record)
```

#### (3) break-glass, port49d stopped, again

`breakglass` login started 04:08:33.677Z: **logged in**, 0.06s after the password was sent
```
show privilege
Current privilege level is 15
xe1#
```
per line: `show privilege` 0.06s
decision log:
```
(no record)
```
