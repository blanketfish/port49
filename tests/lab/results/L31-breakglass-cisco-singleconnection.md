# L31 — break-glass on IOS-XE and NX-OS with single-connection, after a reset of a de-admitted device

- **Date observed:** 2026-09-30 (the runs); analysed the same day from their committed evidence. No
  new device run was made for this note.
- **Platforms:**
  - cisco_iosxe (containerlab node `xe1`, 172.100.100.41): Catalyst 8000V 17.13.01a
    (`vrnetlab/cisco_c8000v:17.13.01a`)
  - cisco_nxos (containerlab node `nx1`, 172.100.100.31): Nexus 9300v 10.4(2)F
    (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
  - For comparison, unaffected: vEOS-lab 4.31.2F and vJunos-router 23.4R2-S2.1, with single-connection
    on in the same runs (`L29-reload-arista_eos.md`, `L29-reload-juniper_vjunos-router.md`).
- **Runs analysed:** plan 6b Task 19's `TestL29Reload` and `TestQuarantineThroughASync`
  (`L29-reload-cisco_iosxe.md`, `L29-reload-cisco_nxos.md`, `quarantine-sync-cisco_iosxe.md`,
  `quarantine-sync-cisco_nxos.md`); the controls are L28 (`L28-cisco_iosxe.md`, `L28-cisco_nxos.md`)
  and the 2026-09-24 quarantine runs (`quarantine-cisco_iosxe.md`, `quarantine-cisco_nxos.md`).
- **Captures (evidence, redacted):**
  - `tests/lab/evidence/L29-reload-refused-cisco_nxos.pcap`, `L29-reload-refused-cisco_iosxe.pcap`
  - `tests/lab/evidence/L29-reload-removed-cisco_nxos.pcap`, `L29-reload-removed-cisco_iosxe.pcap`
  - `tests/lab/evidence/L29-reload-rekeyed-cisco_nxos.pcap`, `L29-reload-rekeyed-cisco_iosxe.pcap`
    (the controlled comparison)
  - `tests/lab/evidence/quarantine-sync-cisco_nxos.pcap`, `quarantine-sync-cisco_iosxe.pcap`
  - `tests/lab/evidence/L28-cisco_nxos.pcap`, `L28-cisco_iosxe.pcap`,
    `quarantine-closed-cisco_nxos.pcap` (single-connection off: header flags `0x00`)
- **Transport:** SSH
- **Read:** TCP flags and timestamps, and the TACACS+ 12-byte cleartext header only (type, seq, flags,
  length). No body byte was decoded or printed.
- **Status:** the pre-fix analysis, kept as history. L31 closed 2026-09-30 with
  `fix/breakglass-reset`: `L31-cisco_iosxe.md`, `L31-cisco_nxos.md` and `L31-arista_eos.md` measure
  break-glass at the key miss's time on every declined path.

## Claim

What break-glass costs on IOS-XE and NX-OS with single-connection on, when port49d resets a de-admitted
device's connection after the device has written its request: removed (unadmitted), refused admission,
and quarantined (spec §15, L31).

## Observation

Break-glass login plus three `show version`, from the notes:

| image | removed | refused | quarantined (through a sync) | re-keyed | port49d stopped |
|---|---|---|---|---|---|
| Catalyst 8000V 17.13.01a | 30.06 s | 20.56 s | 20.31 s | 1.53 s | 1.28 s |
| Nexus 9300v 10.4(2)F | 40.89 s | 17.63 s | 16.72 s | 2.6 s | 2.62 s |

vEOS (0.32–2.1 s) and vJunos-router (0.45–2.1 s) were not slowed in the same runs.

**Refused, NX-OS** (`L29-reload-refused-cisco_nxos.pcap`). Each connection is SYN, SYN/ACK, the
device's request, and port49d's RST 0.1–0.2 ms later. After each command's accounting the device is
silent on port 49 for about 5.7 s:

```
21:30:43.983538 42578 dev>49 [P.] tacacs type=authen seq=1 flags=0x04 len=47   <- break-glass login
21:30:43.983762 42578 49>dev [R.]
21:30:44.131376 42594 dev>49 [P.] tacacs type=acct   seq=1 flags=0x04 len=113
21:30:44.131550 42594 49>dev [R.]
            ... 5.69 s: nothing on :49 ...
21:30:49.823845 46088 dev>49 [P.] tacacs type=author seq=1 flags=0x04 len=53   <- show version #1
21:30:49.824004 46088 49>dev [R.]
            ... 5.69 s ...                                                      <- #2, #3 likewise
```

Four gaps of about 5 s give 17.63 s against 2.62 s stopped. The NX-OS quarantine-sync capture has the
same shape: RST at once, 16.72 s.

**Refused, IOS-XE** (`L29-reload-refused-cisco_iosxe.pcap`). After each RST the device reconnects about
every 200 ms and resends the same request for about 4.8 s, then falls to local. Each connection is reset
0.1–0.2 ms after its request:

```
20:44:33.118                      authen len=37   x1    <- break-glass login
20:44:33.488 .. 20:44:38.287      author len=102  x25 connections, ~200 ms apart, each RST
20:44:38.591 .. 20:44:43.191      author len=89   x24
20:44:43.499 .. 20:44:48.299      author len=89   x25
20:44:48.609 .. 20:44:53.209      author len=89   x24
20:44:53.664                      acct                  <- session end: 20.5 s (note: 20.56 s)
```

**Removed, both images** (`L29-reload-removed-cisco_*.pcap`). port49d accepts the connection, reads the
request, and holds it for the unadmitted strike's backoff before the RST. The hold doubles from 0.1 s to
the 5 s cap, and the device's retries are never refused at Accept:

```
21:28:09.755438 54506 dev>49 [P.] 92B    21:28:09.856349 49>dev [R.]   held 0.10 s
21:28:10.658205 54520 dev>49 [P.] 139B   21:28:10.859053 49>dev [R.]   held 0.20 s
21:28:20.783527 48924 dev>49 [P.] 71B    21:28:21.184160 49>dev [R.]   held 0.40 s
...                                                                    held 0.80, 1.60, 3.20 s
21:28:44.963068 40834 ...                21:28:49.963957 49>dev [R.]   held 5.00 s (and every one after)
```

On IOS-XE every authen and author connection in the removed phase is held exactly 5.0 s, then reset.
That, on top of the device's own timeout, gives 40.89 s on NX-OS and 30.06 s on IOS-XE.

## The controlled comparison: re-keyed

Same devices, same deploy, single-connection on. The re-key is a key miss (L28's path): one strike, an
RST at once, and the source's next connections reset at Accept, before the device writes anything.

**NX-OS** (`L29-reload-rekeyed-cisco_nxos.pcap`), 2.6 s:

```
21:31:35.862166 58594 dev>49 [P.] tacacs type=author flags=0x04   21:31:35.862264 49>dev [R.]  <- strike
21:31:35.874680 58600 dev>49 [S] -> [S.] -> [.]                   21:31:35.874802 49>dev [R.]  <- refused at Accept, no request
21:31:35.981480 58612 dev>49 [S] ...                              21:31:35.981625 49>dev [R.]
21:31:35.992513 58622 dev>49 [S] ...                              21:31:35.992665 49>dev [R.]
21:31:36.666530 58630 ...  next command, 0.67 s later (not 5.7 s)
```

**IOS-XE** (`L29-reload-rekeyed-cisco_iosxe.pcap`), 1.53 s. The retry comes 99 ms after the strike's
RST, is refused at Accept, and the device falls to local at once:

```
20:45:13.875188 57368 dev>49 [P.] tacacs type=author len=86   20:45:13.875327 49>dev [R.]
20:45:13.974006 57372 dev>49 [S]                              20:45:13.974135 49>dev [R.]  <- no request sent
```

An RST that comes before the device writes its request makes both images fall through at once. An RST
that comes after it, with single-connection on, is taken as transient, and the device waits out its
5 s timeout on every AAA exchange.

## The device-side variable: the single-connect header flag

The TACACS+ header's single-connect flag is **`0x04`** in every 2026-09-30 capture (`L29-*`,
`quarantine-sync-*`), where TestL29Reload had turned single-connection on. It is **`0x00`** in
`L28-cisco_nxos.pcap`, `L28-cisco_iosxe.pcap` and the 2026-09-24 `quarantine-closed-cisco_nxos.pcap`.
The 2026-09-24 quarantine close is the same code, with the same RST after the request. It cost 0.07 s
per command with flags `0x00`, and about 5 s per command with `0x04` on 2026-09-30.

## Root cause (port49d)

The unadmitted, refused and quarantined paths close a connection only after reading the device's
request, and none of them makes the source's next connections be refused at Accept:

- **Unadmitted:** `internal/daemon/server/conn.go:237-238`, `unvalidated(unadmitted_source)`, then
  `backoff` (`conn.go:154`). It holds the connection for the strike's backoff, 0.1 s doubling to 5 s,
  before the reset. The hold equals the `Holding` window (`internal/daemon/limits/limits.go:88`), so
  the window has expired by the time the device reconnects.
- **Refused:** `conn.go:233-234`, `refusedAdmission` (`conn.go:90`). An RST at once, with no strike and
  no Accept refusal.
- **Quarantined:** `conn.go:261-262`, `quarantine`. An RST at once, with no strike and no Accept
  refusal.
- Every close goes through `defer s.c.Close()` (`conn.go:205`) with the body unread, so the kernel
  sends an RST.

The key-miss path is different. `keyMiss` (`conn.go:181`) strikes and resets at once, and the retries
hit `Holding` at `internal/daemon/server/server.go:119`, where they are reset at Accept before the
device writes.

The mid-connection reset that L29 measures (`admissionWithdrawn` → `reset`, `conn.go:243`, `:171`)
works as designed. The slow part is the new connections that follow it.

## Regression or pre-existing

Pre-existing server behaviour, exposed by the 6b lab configuration:
- the unadmitted hold dates from `5463b89` (2026-09-16);
- the quarantine close from `6ebd032` (2026-09-24), unchanged since the fast 2026-09-24 measurement;
- the refused close from `2ea5d4c` (plan 6b), which copies the quarantine close.

L28 never exercised these paths with single-connection on, and never exercised the unadmitted path at
all: it measured a key miss from an admitted device.

## What an operator sees until the fix

On a Cisco device with single-connection on, a break-glass session takes 16–21 s when port49d refuses
or quarantines the device, and 30–41 s when the device has been removed from inventory. Break-glass
still logs in on every platform, and vEOS and vJunos-router are unaffected.

## Fix direction (`fix/breakglass-reset`, lab-gated)

Give the unadmitted, refused and quarantined paths L28's shape: record the first connection, reset it
at once, and refuse the source's next connections at Accept for a short window.
- **Unadmitted:** use a `keyMiss`-style close instead of `backoff`.
- **Refused and quarantined:** these take no strike by spec. They need a strike-free window, checked
  beside `Holding` and cleared at every reload.

This needs a lab run on IOS-XE and NX-OS with single-connection on, for the removed, refused and
quarantined phases, and that run closes L31.
