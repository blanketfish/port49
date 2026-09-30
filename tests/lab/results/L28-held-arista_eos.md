# L28 (port49d holding a key miss) — arista_eos

- **Date measured:** 2026-09-30
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L28-rotation-held-arista_eos.pcap` — 64 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-rotation-held-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`).
- **Transport:** SSH
- **port49d:** built from `dea4a0b`, before 51fb593: a key miss held for the per-source backoff, then closed without a reply. This run predates the harness's liveness wait before each phase. The branch-H reading and the current behaviour are in `tests/lab/results/L28-arista_eos.md`.

## Claim

What a device does when port49d cannot validate its key (unknown, and retired), and that a second accepted version and then the device's own key change carry it through a rotation (spec §15 L28).

## Observation

### Phase: stopped

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 390ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 2.16s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

### Phase: unknown

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 240ms |
| break-glass login plus three `show version` | ran | 27.39s |
| token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 7.11s |

Unvalidated records by diagnosis/type: map[no_known_key_matches/acct:12 no_known_key_matches/authen:3 no_known_key_matches/author:6]. Validated records by key version: map[].

### Phase: retired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    retired: [{version: 1, secret_env: PORT49_LAB_KEY}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 240ms |
| break-glass login plus three `show version` | ran | 27.37s |
| token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 10.53s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:12 matches_retired/authen:3 matches_retired/author:6]. Validated records by key version: map[].

### Phase: expired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2026-09-29}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 250ms |
| break-glass login plus three `show version` | ran | 27.38s |
| token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 10.09s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:12 matches_retired/authen:3 matches_retired/author:6]. Validated records by key version: map[].

### Phase: accepted

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 530ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 1.03s |
| token login (`alice05`) | logged in | 190ms |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[v1:5].

Capture of the phases above: `tests/lab/evidence/L28-held-arista_eos.pcap` — 1346 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-held-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Rotation: the device given the new key

Token login (`alice06`) after the device's key changed, with port49d accepting v1 and v2: logged in; 3 record(s) carried `key_version` 2.

`port49 keys status` over the run's log:

```
KEY_REF      VERSION  STATE      DEVICES  LAST OLD-KEY USE
lab_key            2  current          1  —
                   1  accept           0  —
never seen in the log: nx1, srx1, vsrx1, xe1

UNVALIDATED SOURCES
SOURCE          DEVICE       KEY_REF      ATTEMPTS  LAST      DIAGNOSIS
172.100.100.11  leaf1        lab_key            42  29s ago   matches retired v1
172.100.100.11  leaf1        lab_key            21  2m ago    no known key matches
```

This capture is the note's Capture line: its bodies are obfuscated under the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`), not the lab key.

