# L57 — juniper_vsrx

- **Date measured:** 2026-11-05
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/L57-juniper_vsrx.pcap` — 1367 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L57-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL57JunosGroups$`

## Claim

What a Junos configuration capture carries for configuration groups that reach port49's template class p49-remote: a `<*>` and a `<p49-*>` group applied at the top, one kept off the class by `apply-groups-except`, one applied nowhere, one applied from inside another, one applied on the class itself, and a group's idle-timeout beside the class's own; in both inherited set forms, plain set form and the inherited curly form; and what a session landing in `remote` holds (spec §15 L57; decision 44 ruling 7).

## Observation

Reference (set 1.1.0, 12h) applied, then the groups: commit complete. Nested: commit complete. Class-level: commit complete.

```
set groups p49g-tip system login class <*> login-tip
set groups p49g-perm system login class <p49-*> permissions view-configuration
set groups p49g-perm system login class <p49-*> allow-commands "^show version$"
set groups p49g-excepted system login class <*> permissions clear
set groups p49g-unapplied system login class <*> permissions all
set groups p49g-timeout system login class <*> idle-timeout 30
set system login class p49-l57own permissions view
set system login user p49-l57own class p49-l57own
set apply-groups p49g-tip
set apply-groups p49g-perm
set apply-groups p49g-excepted
set apply-groups p49g-timeout
set system login class p49-remote apply-groups-except p49g-excepted
set groups p49g-inner system login class <p49-*> permissions network
set groups p49g-outer apply-groups p49g-inner
set apply-groups p49g-outer
set groups p49g-classlevel system login class <p49-*> login-alarms
set system login class p49-remote apply-groups p49g-classlevel
```

| capture | `apply-groups` word line (not -except) | set groups lines | p49g-tip | p49g-perm | p49g-excepted | nested | own idle-timeout 720 | group permission beside own | p49g-classlevel login-alarms |
|---|---|---|---|---|---|---|---|---|---|
| `show configuration \| display set \| display inheritance \| no-more` | no | no | yes | yes | no | no | yes | yes | yes |
| `show configuration \| display inheritance \| display set \| no-more` | no | no | yes | yes | no | no | yes | yes | yes |
| `show configuration \| display set \| no-more` | yes | yes | no | no | no | no | yes | no | no |
| `show configuration system login \| display inheritance \| no-more` | not parsed | not parsed | not parsed | not parsed | not parsed | not parsed | not parsed | not parsed | not parsed |

- class_level_apply_groups: `show configuration \| display set \| display inheritance \| no-more`: **stripped**; class_level_group_expanded (login-alarms under p49-remote): **yes**
- class_level_apply_groups: `show configuration \| display inheritance \| display set \| no-more`: **stripped**; class_level_group_expanded (login-alarms under p49-remote): **yes**
- class_level_apply_groups: `show configuration \| display set \| no-more`: **survives**; class_level_group_expanded (login-alarms under p49-remote): **no**
- class_level_apply_groups: `show configuration system login \| display inheritance \| no-more`: **not parsed**; class_level_group_expanded (login-alarms under p49-remote): **not parsed**

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

Nested group in a session: the inner group adds `permissions network` under `<p49-*>`. `show cli authorization` under p49-l57own (its own `view`; must print `Current user` and list `clear`, from p49g-excepted, and `view-configuration`, from p49g-perm, the controls that top-level inheritance reached this login):

```
Current user: 'p49-l57own' login: 'alice02' class 'p49-l57own'
Permissions:
    clear       -- Can clear learned network info
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: ^show version$
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

alice02@srx1>
```

Second reading, `ping 127.0.0.1 count 1 rapid` (runs only with `network`):

```
ping
              ^
unknown command.
alice02@srx1> ping   127.0.0.1
              ^
unknown command.
alice02@srx1> ping127.0.0.1   count
              ^
unknown command.
alice02@srx1> ping127.0.0.1count   1
              ^
unknown command.
alice02@srx1> ping127.0.0.1count1   rapid
              ^
unknown command.

alice02@srx1>
```

Nested-group session cell: **not applied**. The nested group is not applied in a session: `show cli authorization` ran and lists `clear` (top-level p49g-excepted) and `view-configuration` (top-level p49g-perm), so top-level inheritance reached the login, but not `network`, and `ping` was refused.

### `show configuration | display set | display inheritance | no-more` (p49-remote and the group lines)

```
set system login class p49-remote idle-timeout 720
set system login class p49-remote login-alarms
set system login class p49-remote login-tip
set system login class p49-remote permissions view-configuration
set system login class p49-remote allow-commands "^show version$"
set system login user remote class p49-remote
```

### `show configuration | display inheritance | display set | no-more` (p49-remote and the group lines)

```
set system login class p49-remote idle-timeout 720
set system login class p49-remote login-alarms
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
set groups p49g-classlevel system login class <p49-*> login-alarms
set apply-groups p49g-tip
set apply-groups p49g-perm
set apply-groups p49g-excepted
set apply-groups p49g-timeout
set apply-groups p49g-outer
set system login class p49-remote apply-groups p49g-classlevel
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
    ## 'login-alarms' was inherited from group 'p49g-classlevel'
    ## 'login-tip' was inherited from group 'p49g-tip'
    ## 'view-configuration' was inherited from group 'p49g-perm'
    ## '^show version$' was inherited from group 'p49g-perm'
    class p49-remote;
```

