# junos-session-service — juniper_vsrx

- **Date measured:** 2026-09-21
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Capture:** `tests/lab/evidence/junos-session-service-juniper_vsrx.pcap` — 1110 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/junos-session-service-juniper_vsrx.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether a Junos session authorization is permitted now that `junos-exec` is on the platform's `session_services` list (spec §5.2, §8); whether a device-renamed service (`set system tacplus-options service-name`) arrives on the authorization and on accounting; and what a deliberately DENIED session authorization costs the operator — which until 2026-09-21 was every Junos session port49 answered, and was inferred rather than measured.

## Observation


### Phase A — built-in default `junos-exec`, no attributes

**The login completed** and the operator reached an operational-mode prompt.

port49's own record:

```
event=authorize_session verdict=permit reason=context_matched
    request.service="junos-exec"
    request.raw=[service=junos-exec]
    port="" rem_addr="172.100.100.1" priv=1
```

What the device says the session may do:

```
show cli authorization
```

```
 
Current user: 'remote' login: 'alice02' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none
```

```
show system users | match .
```

```
 
 5:15AM  up 55 secs, 1 users, load averages: 2.99, 0.88, 0.33
USER     TTY      FROM                              LOGIN@  IDLE WHAT
alice02  pts/0    172.100.100.1                    5:15AM      - -cli (cli)    
```


### Phase B — device renamed to `junos-exec-fw`

**The login completed** and the operator reached an operational-mode prompt.

port49's own record:

```
event=authorize_session verdict=permit reason=context_matched
    request.service="junos-exec-fw"
    request.raw=[service=junos-exec-fw]
    port="" rem_addr="172.100.100.1" priv=1
```

What the device says the session may do:

```
show cli authorization
```

```
 
Current user: 'remote' login: 'alice03' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none
```

```
show system users | match .
```

```
 
 5:15AM  up 1 min, 1 users, load averages: 2.40, 0.85, 0.33
USER     TTY      FROM                              LOGIN@  IDLE WHAT
alice03  pts/0    172.100.100.1                    5:15AM      - -cli (cli)    
```

**Accounting** — the `service` AV pair on every record this phase produced:

```
account flags=stop service=shell
account flags=stop service=shell
account flags=start service=shell
account flags=stop service=shell
account flags=stop service=shell
account flags=stop service=shell
account flags=stop service=shell
```

The renamed service **does not** reach accounting: not one of the 7 records carries `service=junos-exec-fw`. The rename is an authorization-side setting only, so a reader correlating the two streams cannot use `service` as the join.


### Phase C — port49 denies the session authorization on purpose

**The login completed** and the operator reached an operational-mode prompt.

port49's own record:

```
event=authorize_session verdict=deny reason=service_unsupported
    request.service="junos-exec"
    request.raw=[service=junos-exec]
    port="" rem_addr="172.100.100.1" priv=1
```

What the device says the session may do:

```
show cli authorization
```

```
 
Current user: 'remote' login: 'alice04' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none
```

```
show system users | match .
```

```
 
 5:16AM  up 1 min, 1 users, load averages: 2.51, 0.98, 0.39
USER     TTY      FROM                              LOGIN@  IDLE WHAT
alice04  pts/0    172.100.100.1                    5:16AM      - -cli (cli)    
```


## The three phases side by side

| phase | authorize_session | request.service | login completed | `show cli authorization` |
|---|---|---|---|---|
| A — built-in default `junos-exec`, no attributes | permit context_matched | `junos-exec` | yes | see the phase above |
| B — device renamed to `junos-exec-fw` | permit context_matched | `junos-exec-fw` | yes | see the phase above |
| C — port49 denies the session authorization on purpose | deny service_unsupported | `junos-exec` | yes | see the phase above |

