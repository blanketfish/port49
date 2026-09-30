# L28 (port49d closing a key miss at once with a FIN) — cisco_iosxe

- **Date measured:** 2026-09-30
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.13.01a (`vrnetlab/cisco_c8000v:17.13.01a`)
- **Topology:** `tests/lab/topologies/iosxe.clab.yml`
- **Capture:** `tests/lab/evidence/L28-rotation-fin-cisco_iosxe.pcap` — 24 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-rotation-fin-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`).
- **Transport:** SSH
- **port49d:** built from `51fb593`, before a60d123: a key miss closed at once with a FIN, and a held source refused at Accept. The capture shows the C8000V taking port49d's FIN at once and sending its own only 5 s later, at its timeout, before it falls to local. The current behaviour, with a reset, is in `tests/lab/results/L28-cisco_iosxe.md`.

## Claim

What a device does when port49d cannot validate its key (unknown, and retired), and that a second accepted version and then the device's own key change carry it through a rotation (spec §15 L28).

## Observation

port49d built from `51fb593` (`make build`).

### Phase: stopped

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 20ms |
| break-glass login plus three `show version` | ran | 1.28s |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.01s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

Before the phase above, with port49d validating the device's key: The device was asking port49 at the first probe. (6s.)

### Phase: unknown

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 5.02s |
| break-glass login plus three `show version` | ran | 11.03s |
| token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 9.02s |

Unvalidated records by diagnosis/type: map[no_known_key_matches/acct:2 no_known_key_matches/authen:3 no_known_key_matches/author:1]. Validated records by key version: map[].

Before the phase above, with port49d validating the device's key: No probe login reached port49 until probe attempt 2; why is not established. (30s.)

### Phase: retired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    retired: [{version: 1, secret_env: PORT49_LAB_KEY}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 5.02s |
| break-glass login plus three `show version` | ran | 1.27s |
| token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 4.02s |

Unvalidated records by diagnosis/type: map[matches_retired/authen:1 matches_retired/author:2]. Validated records by key version: map[].

Before the phase above, with port49d validating the device's key: The device was asking port49 at the first probe. (6s.)

### Phase: expired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2026-09-29}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 5.02s |
| break-glass login plus three `show version` | ran | 11.03s |
| token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 9.02s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:2 matches_retired/authen:3 matches_retired/author:1]. Validated records by key version: map[].

Before the phase above, with port49d validating the device's key: No probe login reached port49 until probe attempt 3; why is not established. (54s.)

### Phase: accepted

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.52s |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 8.02s |
| token login (`alice05`) | logged in | 10ms |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[v1:5].

Before the phase above, with port49d validating the device's key: The device was asking port49 at the first probe. (6s.)

Capture of the phases above: `tests/lab/evidence/L28-fin-cisco_iosxe.pcap` — 1080 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-fin-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Rotation: the device given the new key

Before this login, with port49d validating the device's key: The device was asking port49 at the first probe. (6s.)

Token login (`alice06`) after the device's key changed, with port49d accepting v1 and v2: logged in; 1 record(s) carried `key_version` 2.

`port49 keys status` over the run's log:

```
KEY_REF      VERSION  STATE      DEVICES  LAST OLD-KEY USE
lab_key            2  current          1  —
                   1  accept           0  —
never seen in the log: leaf1, nx1, srx1, vsrx1

UNVALIDATED SOURCES
SOURCE          DEVICE       KEY_REF      ATTEMPTS  LAST      DIAGNOSIS
172.100.100.41  xe1          lab_key             9  1m ago    matches retired v1
172.100.100.41  xe1          lab_key             6  3m ago    no known key matches
```

This capture is the note's Capture line: its bodies are obfuscated under the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`), not the lab key.

