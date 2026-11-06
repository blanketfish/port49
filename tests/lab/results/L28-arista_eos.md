# L28 — arista_eos

- **Date measured:** 2026-11-06
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L28-rotation-arista_eos.pcap` — 64 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L28-rotation-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=eos,vjunos,nxos,iosxe`, `-run ^TestL28KeyMiss$`

## Claim

What a device does when port49d cannot validate its key (unknown, and retired), and that a second accepted version and then the device's own key change carry it through a rotation (spec §15 L28).

## Observation

port49d built from `a158aaf8` (`make build`).

**Branch H.** port49d as first built held a key miss for the per-source backoff, and that stalled a break-glass session on every platform here (`tests/lab/results/L28-held-*.md`); closing it at once with a FIN still stalled the C8000V, which waits out its own timeout on a FIN (`tests/lab/results/L28-fin-cisco_iosxe.md`). So a first-packet key miss is now struck and closed at once with a reset, and any source inside the backoff its last strike earned — a key miss's, and equally a `malformed_after_validation`, `not_tacacs` or unadmitted source's — is refused at Accept with a reset for that backoff: no record, counted as `port49_connection_events_total{event="held_refused"}`. Each phase below compares with the `stopped` phase, the device's local fall-through with nothing listening.

### Phase: stopped

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

```yaml
# port49d stopped: nothing listens on 172.100.100.1:49
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 30ms |
| break-glass login plus three `show version` | ran | 390ms |
| token login (`alice01`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 2.55s |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[].

### Phase: unknown

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 40ms |
| break-glass login plus three `show version` | ran | 330ms |
| token login (`alice02`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 1.8s |

Unvalidated records by diagnosis/type: map[no_known_key_matches/acct:1 no_known_key_matches/authen:1 no_known_key_matches/author:1]. Validated records by key version: map[].

### Phase: retired

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
    retired: [{version: 1, secret_ref: env:PORT49_LAB_KEY}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 50ms |
| break-glass login plus three `show version` | ran | 330ms |
| token login (`alice03`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 1.92s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:1 matches_retired/authen:1 matches_retired/author:1]. Validated records by key version: map[].

### Phase: expired

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_ref: env:PORT49_LAB_KEY, retire_after: 2026-11-05}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | logged in | 40ms |
| break-glass login plus three `show version` | ran | 340ms |
| token login (`alice04`) | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 2.18s |

Unvalidated records by diagnosis/type: map[matches_retired/acct:1 matches_retired/authen:1 matches_retired/author:1]. Validated records by key version: map[].

### Phase: accepted

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

```yaml
  lab_key:
    current: {version: 2, secret_ref: env:PORT49_L28_NEW_KEY}
    accept: [{version: 1, secret_ref: env:PORT49_LAB_KEY, retire_after: 2999-12-31}]
```

| step | outcome | took |
|---|---|---|
| break-glass login | refused: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 530ms |
| break-glass login plus three `show version` | not observed: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain | 1.03s |
| token login (`alice05`) | logged in | 180ms |

Unvalidated records by diagnosis/type: map[]. Validated records by key version: map[v1:5].

Capture of the phases above: `tests/lab/evidence/L28-arista_eos.pcap` — 1038 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L28-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).

### Rotation: the device given the new key

Before this phase, with port49d validating the device's key: the first probe login reached port49 (1s).

Token login (`alice06`) after the device's key changed, with port49d accepting v1 and v2: logged in; 3 record(s) carried `key_version` 2.

`port49 keys status` over the run's log:

```
flag provided but not defined: -config
Usage of port49 keys status:
  -inventory string
    	the inventory file the daemon admits from (inventory_file)
  -policy string
    	the policy file
  -since duration
    	read only the records within this long of the newest one (default: all)
(exit: exit status 2)
```

This capture is the note's Capture line: its bodies are obfuscated under the rotation key (`labcreds.RotationKey`, or `PORT49_L28_NEW_KEY`), not the lab key.

