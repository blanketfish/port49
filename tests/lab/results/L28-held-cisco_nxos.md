# L28 (port49d holding a key miss) — cisco_nxos

- **Date measured:** 2026-09-30
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L28-rotation-held-cisco_nxos.pcap` — 40 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-rotation-held-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`).
- **Transport:** SSH
- **port49d:** built from `dea4a0b`, before 51fb593: a key miss held for the per-source backoff, then closed without a reply. This run predates the harness's liveness wait before each phase. The branch-H reading and the current behaviour are in `tests/lab/results/L28-cisco_nxos.md`.

## Claim

What a device does when port49d cannot validate its key (unknown, and retired), and that a second accepted version and then the device's own key change carry it through a rotation (spec §15 L28).

## Observation

### Phase: stopped

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 140ms |
| break-glass login plus three `show version` | ran | 2.66s |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 6.53s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

### Phase: unknown

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 340ms |
| break-glass login plus three `show version` | ran | 25.18s |
| token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 20.29s |

Unvalidated records by diagnosis/type: map[no_known_key_matches/acct:8 no_known_key_matches/authen:4 no_known_key_matches/author:6]. Validated records by key version: map[].

### Phase: retired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    retired: [{version: 1, secret_env: PORT49_LAB_KEY}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 340ms |
| break-glass login plus three `show version` | ran | 25.13s |
| token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 18.52s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:8 matches_retired/authen:4 matches_retired/author:6]. Validated records by key version: map[].

### Phase: expired

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2026-09-29}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 340ms |
| break-glass login plus three `show version` | ran | 25.13s |
| token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 19.39s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:8 matches_retired/authen:4 matches_retired/author:6]. Validated records by key version: map[].

### Phase: accepted

```yaml
  lab_key:
    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 2.06s |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain | 5.81s |
| token login (`alice05`) | logged in | 230ms |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[v1:10].

Capture of the phases above: `tests/lab/evidence/L28-held-cisco_nxos.pcap` — 1278 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L28-held-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Rotation: the device given the new key

Token login (`alice06`) after the device's key changed, with port49d accepting v1 and v2: logged in; 2 record(s) carried `key_version` 2.

`port49 keys status` over the run's log:

```
KEY_REF      VERSION  STATE      DEVICES  LAST OLD-KEY USE
lab_key            2  current          1  —
                   1  accept           0  —
never seen in the log: leaf1, srx1, vsrx1, xe1

UNVALIDATED SOURCES
SOURCE          DEVICE       KEY_REF      ATTEMPTS  LAST      DIAGNOSIS
172.100.100.31  nx1          lab_key            36  42s ago   matches retired v1
172.100.100.31  nx1          lab_key            18  2m ago    no known key matches
```

This capture is the note's Capture line: its bodies are obfuscated under the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`), not the lab key.

