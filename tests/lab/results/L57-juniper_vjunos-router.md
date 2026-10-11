# L57 — juniper_vjunos-router

- **Date measured:** 2026-10-11
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L57-juniper_vjunos-router.pcap` — 619 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L57-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `3ec6d64422b4a3c241116baa297dd9269400fdaa`, `PORT49_LAB_PLATFORMS=vjunos`, `-run ^TestL57JunosGroups$`

## Claim

What a Junos configuration capture carries for configuration groups that reach port49's template class p49-remote: a `<*>` and a `<p49-*>` group applied at the top, one kept off the class by `apply-groups-except`, one applied nowhere, one applied from inside another, and a group's idle-timeout beside the class's own; in both inherited set forms, plain set form and the inherited curly form; and what a session landing in `remote` holds (spec §15 L57; decision 44 ruling 7).

## Observation

Reference (set 1.1.0, 12h) applied, then the groups: commit complete. Nested: commit complete.

```
set groups p49g-tip system login class <*> login-tip
set groups p49g-perm system login class <p49-*> permissions view-configuration
set groups p49g-perm system login class <p49-*> allow-commands "^show version$"
set groups p49g-excepted system login class <*> permissions clear
set groups p49g-unapplied system login class <*> permissions all
set groups p49g-timeout system login class <*> idle-timeout 30
set system login class p49-l57own permissions view
set apply-groups p49g-tip
set apply-groups p49g-perm
set apply-groups p49g-excepted
set apply-groups p49g-timeout
set system login class p49-remote apply-groups-except p49g-excepted
set groups p49g-inner system login class <p49-*> permissions network
set groups p49g-outer apply-groups p49g-inner
set apply-groups p49g-outer
```

| capture | apply-groups lines | set groups lines | p49g-tip | p49g-perm | p49g-excepted | nested | own idle-timeout 720 | group permission beside own |
|---|---|---|---|---|---|---|---|---|
| `show configuration \| display set \| display inheritance \| no-more` | no | no | yes | yes | no | no | yes | yes |
| `show configuration \| display inheritance \| display set \| no-more` | no | no | yes | yes | no | no | yes | yes |
| `show configuration \| display set \| no-more` | yes | yes | no | no | no | no | yes | no |
| `show configuration system login \| display inheritance \| no-more` | no | no | no | no | no | no | no | no |

A token session with no reply attributes (lands in `remote`), `show cli authorization`:

```
show cli
                   ^
syntax error, expecting <command>.
alice01@srx1> show cli   authorization
                   ^
syntax error, expecting <command>.

alice01@srx1>
```

### `show configuration | display set | display inheritance | no-more` (p49-remote and the group lines)

```
set system login class p49-remote apply-groups-except p49g-excepted
set system login class p49-remote idle-timeout 720
set system login class p49-remote login-tip
set system login class p49-remote permissions view-configuration
set system login class p49-remote allow-commands "^show version$"
set system login user remote class p49-remote
```

### `show configuration | display inheritance | display set | no-more` (p49-remote and the group lines)

```
set system login class p49-remote apply-groups-except p49g-excepted
set system login class p49-remote idle-timeout 720
set system login class p49-remote login-tip
set system login class p49-remote permissions view-configuration
set system login class p49-remote allow-commands "^show version$"
set system login user remote class p49-remote
```

### `show configuration | display set | no-more` (p49-remote and the group lines)

```
set groups p49g-tip system login class <*> login-tip
set groups p49g-perm system login class <p49-*> permissions view-configuration
set groups p49g-perm system login class <p49-*> allow-commands "^show version$"
set groups p49g-excepted system login class <*> permissions clear
set groups p49g-unapplied system login class <*> permissions all
set groups p49g-timeout system login class <*> idle-timeout 30
set groups p49g-inner system login class <p49-*> permissions network
set groups p49g-outer apply-groups p49g-inner
set apply-groups p49g-tip
set apply-groups p49g-perm
set apply-groups p49g-excepted
set apply-groups p49g-timeout
set apply-groups p49g-outer
set system login class p49-remote apply-groups-except p49g-excepted
set system login class p49-remote idle-timeout 720
set system login user remote class p49-remote
```

### `show configuration system login | display inheritance | no-more` (p49-remote and the group lines)

```
    ## '30' was inherited from group 'p49g-timeout'
    ## 'login-tip' was inherited from group 'p49g-tip'
    ## 'view-configuration' was inherited from group 'p49g-perm'
    ## 'clear' was inherited from group 'p49g-excepted'
    ## '^show version$' was inherited from group 'p49g-perm'
    ## '30' was inherited from group 'p49g-timeout'
    ## 'login-tip' was inherited from group 'p49g-tip'
    ## 'clear' was inherited from group 'p49g-excepted'
    ## '^show version$' was inherited from group 'p49g-perm'
class p49-remote {
    apply-groups-except p49g-excepted;
    ## 'login-tip' was inherited from group 'p49g-tip'
    ## 'view-configuration' was inherited from group 'p49g-perm'
    ## '^show version$' was inherited from group 'p49g-perm'
    class p49-remote;
```

