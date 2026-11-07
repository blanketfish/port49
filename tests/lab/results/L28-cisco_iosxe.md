# L28 — cisco_iosxe

- **Date measured:** 2026-11-07
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L28-rotation-cisco_iosxe.pcap` — 24 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L28-rotation-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`).
- **Transport:** SSH
- **Run:** commit `4d12e4350203f43ae51e2a5e3f2c839cbc056641-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,nxos,iosxe`, `-run ^TestL28KeyMiss$`

## Claim

What a device does when port49d cannot validate its key (unknown, and retired), and that a second accepted version and then the device's own key change carry it through a rotation (spec §15 L28).

## Observation

port49d built from `58e2d52a` (`make build`).

**Branch H.** port49d as first built held a key miss for the per-source backoff, and that stalled a break-glass session on every platform here (`tests/lab/results/L28-held-*.md`); closing it at once with a FIN still stalled the C8000V, which waits out its own timeout on a FIN (`tests/lab/results/L28-fin-cisco_iosxe.md`). So a first-packet key miss is now struck and closed at once with a reset, and any source inside the backoff its last strike earned — a key miss's, and equally a `malformed_after_validation`, `not_tacacs` or unadmitted source's — is refused at Accept with a reset for that backoff: no record, counted as `port49_connection_events_total{event="held_refused"}`. Each phase below compares with the `stopped` phase, the device's local fall-through with nothing listening.

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 1.28s |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.02s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

### Phase: unknown

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (30s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 20ms |
| break-glass login plus three `show version` | ran | 1.28s |
| token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.02s |

Unvalidated records by diagnosis/type: map[no_known_key_matches/authen:3 no_known_key_matches/author:2]. Validated records by key version: map[].

### Phase: retired

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
    retired: [{version: 1, secret_ref: env:PORT49_LAB_KEY}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 20ms |
| break-glass login plus three `show version` | ran | 1.28s |
| token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.02s |

Unvalidated records by diagnosis/type: map[matches_retired/authen:1 matches_retired/author:2]. Validated records by key version: map[].

### Phase: expired

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 2; why is not established (30s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_ref: env:PORT49_LAB_KEY, retire_after: 2026-11-06}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 20ms |
| break-glass login plus three `show version` | ran | 1.28s |
| token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.02s |

Unvalidated records by diagnosis/type: map[matches_retired/authen:3 matches_retired/author:2]. Validated records by key version: map[].

### Phase: accepted

Before this phase, with port49d validating the device's key: the first probe login reached port49 (6s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_ref: env:PORT49_LAB_KEY, retire_after: 2999-12-31}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.52s |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 8.02s |
| token login (`alice05`) | logged in | 20ms |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[v1:5].

Capture of the phases above: `tests/lab/evidence/L28-cisco_iosxe.pcap` — 932 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L28-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Rotation: the device given the new key

Before this phase, with port49d validating the device's key: no probe login reached port49 until probe attempt 3; why is not established (54s).

Token login (`alice06`) after the device's key changed, with port49d accepting v1 and v2: logged in; 1 record(s) carried `key_version` 2.

`port49 keys status` over the run's log:

```
KEY_REF      VERSION  STATE      DEVICES  LAST OLD-KEY USE
lab_key            2  current          1  —
                   1  accept           0  —
never seen in the log: leaf1, nx1, srl1, srx1, vsrx1, xrd1

UNVALIDATED SOURCES
SOURCE          DEVICE       KEY_REF      ATTEMPTS  LAST      DIAGNOSIS
172.100.100.41  xe1          lab_key             8  1m ago    matches retired v1
172.100.100.41  xe1          lab_key             5  2m ago    no known key matches
```

This capture is the note's Capture line: its bodies are obfuscated under the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`), not the lab key.

