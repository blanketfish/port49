# L28 — juniper_vjunos-router

- **Date measured:** 2026-09-30
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L28-rotation-juniper_vjunos-router.pcap` — 44 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-rotation-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`).
- **Transport:** SSH

## Claim

What a device does when port49d cannot validate its key (unknown, and retired), and that a second accepted version and then the device's own key change carry it through a rotation (spec §15 L28).

## Observation

port49d built from `a60d123` (`make build`).

**Branch H.** port49d as first built held a key miss for the per-source backoff, and that stalled a break-glass session on every platform here (`tests/lab/results/L28-held-*.md`); closing it at once with a FIN still stalled the C8000V, which waits out its own timeout on a FIN (`tests/lab/results/L28-fin-cisco_iosxe.md`). So a first-packet key miss is now struck and closed at once with a reset, and any source inside the backoff its last strike earned — a key miss's, and equally a `malformed_after_validation`, `not_tacacs` or unadmitted source's — is refused at Accept with a reset for that backoff: no record, counted as `port49_connection_events_total{event="held_refused"}`. Each phase below compares with the `stopped` phase, the device's local fall-through with nothing listening.

### Phase: stopped

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 20ms |
| break-glass login plus three `show version` | ran | 490ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.08s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Before this step, with port49d validating the device's key: The device was asking port49 at the first probe. (7s.)

### Phase: unknown

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 470ms |
| token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.07s |

Unvalidated records by diagnosis/type: map[no_known_key_matches/acct:1 no_known_key_matches/authen:2]. Validated records by key version: map[].

Before this step, with port49d validating the device's key: The device was asking port49 at the first probe. (7s.)

### Phase: retired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    retired: [{version: 1, secret_env: PORT49_LAB_KEY}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 460ms |
| token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.06s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:1 matches_retired/authen:2]. Validated records by key version: map[].

Before this step, with port49d validating the device's key: The device was asking port49 at the first probe. (7s.)

### Phase: expired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2026-09-29}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 450ms |
| token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.07s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:1 matches_retired/authen:2]. Validated records by key version: map[].

Before this step, with port49d validating the device's key: The device was asking port49 at the first probe. (7s.)

### Phase: accepted

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 530ms |
| break-glass login plus three `show version` | ran | 1.47s |
| token login (`alice05`) | logged in | 20ms |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[v1:13].

Before this step, with port49d validating the device's key: The device was asking port49 at the first probe. (7s.)

Capture of the phases above: `tests/lab/evidence/L28-juniper_vjunos-router.pcap` — 2488 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Rotation: the device given the new key

Before this step, with port49d validating the device's key: The device was asking port49 at the first probe. (7s.)

Token login (`alice06`) after the device's key changed, with port49d accepting v1 and v2: logged in; 2 record(s) carried `key_version` 2.

`port49 keys status` over the run's log:

```
KEY_REF      VERSION  STATE      DEVICES  LAST OLD-KEY USE
lab_key            2  current          1  —
                   1  accept           0  —
never seen in the log: leaf1, nx1, vsrx1, xe1

UNVALIDATED SOURCES
SOURCE          DEVICE       KEY_REF      ATTEMPTS  LAST      DIAGNOSIS
172.100.100.21  srx1         lab_key             6  54s ago   matches retired v1
172.100.100.21  srx1         lab_key             3  1m ago    no known key matches
```

This capture is the note's Capture line: its bodies are obfuscated under the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`), not the lab key.

