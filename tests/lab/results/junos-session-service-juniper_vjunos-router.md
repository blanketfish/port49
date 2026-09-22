# junos-session-service — juniper_vjunos-router

- **Date measured:** 2026-09-21
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/junos-session-service-juniper_vjunos-router.pcap` — 2084 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/junos-session-service-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
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
 
Current user: 'remote' login: 'alice01' class 'p49-readonly'
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
 
 5:19AM  up 59 secs, 1 users, load averages: 1.80, 0.61, 0.23
USER     TTY      FROM                              LOGIN@  IDLE WHAT
alice01  pts/0    172.100.100.1                    5:19AM      - -cli (cli)    
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
 
 5:19AM  up 1 min, 1 users, load averages: 1.60, 0.60, 0.24
USER     TTY      FROM                              LOGIN@  IDLE WHAT
alice02  pts/0    172.100.100.1                    5:19AM      - -cli (cli)    
```

**Accounting.** Measured: renaming the authorization service does NOT rename it on accounting: not one of the 7 accounting records this phase produced carries `service=junos-exec-fw`, while the session authorization in the same phase carried it. `service` therefore cannot be used to join the authorization stream to the accounting stream on this platform.

Sent:

```
set system tacplus-options service-name junos-exec-fw
commit

(then one token SSH login, and every accounting record it produced)
```

The device replied:

```
account flags=stop service=shell
account flags=stop service=shell
account flags=start service=shell
account flags=stop service=shell
account flags=stop service=shell
account flags=stop service=shell
account flags=stop service=shell
```


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
 
 5:19AM  up 1 min, 1 users, load averages: 1.32, 0.59, 0.24
USER     TTY      FROM                              LOGIN@  IDLE WHAT
alice03  pts/0    172.100.100.1                    5:19AM      - -cli (cli)    
```


## The three phases side by side

| phase | authorize_session | request.service | login completed | `show cli authorization` |
|---|---|---|---|---|
| A — built-in default `junos-exec`, no attributes | permit context_matched | `junos-exec` | yes | see the phase above |
| B — device renamed to `junos-exec-fw` | permit context_matched | `junos-exec-fw` | yes | see the phase above |
| C — port49 denies the session authorization on purpose | deny service_unsupported | `junos-exec` | yes | see the phase above |

## What this settles

1. **A Junos session authorization is now permitted.** `service=junos-exec` is on the platform's `session_services` list and the record reads `permit context_matched`. Before 2026-09-21 this exchange was `deny service_unsupported` on every Junos login port49 had ever answered (§15, L10).

2. **A device-renamed service arrives on the authorization.** `set system tacplus-options service-name junos-exec-fw` and the request's `service` is `junos-exec-fw`, matched against the operator's configured list. It does not reach accounting — see phase B.

3. Measured: a session authorization denied `service_unsupported` does NOT stop a Junos login and does NOT change what the session may do. The operator logged in, reached an operational-mode prompt, and the device reported the same class and the same permissions as in the two phases port49 permitted.

Sent:

```
port49 answered the session authorization `deny service_unsupported`
(request.service=junos-exec, against a configured list of ["shell"]).
The operator then typed, in that session:

    show cli authorization
```

The device replied:

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

The class is the same one the permitted phases got (`p49-readonly`), which is the explanation as well as the observation: `tests/lab/configs/vjunos-startup.conf` defines

```
user remote {
    uid 2001;
    class p49-readonly;
}
```

and Junos applies that template to any user it authenticates who has no local account. The class comes from the device, not from port49, so denying the authorization removes nothing port49 was providing — **because port49 was providing nothing**. Phase A's permit carries no attributes either (decision 22's projection is plan 5, gated on L12), so phases A and C are indistinguishable to the operator and differ only in port49's own log.

**What that corrects.** The `<edit-config>` that returned `permission denied` in the 2026-09-20 NETCONF runs was read there as the session-authorization denial arriving. It was not: it is `p49-readonly` refusing a write, and it would have returned the same error with the authorization permitted. The denial and the read-only class are two separate facts that happened to produce one symptom.

**And what it means for plan 5.** On this image port49's session authorization is *advisory* under this configuration: the device authenticates through TACACS+ and then assigns privilege from its own `remote` template whatever port49 says. The projection is not a nicety on top of a working denial — until it lands, port49 does not constrain a Junos session at all, and the only thing standing between an authenticated operator and the device's capabilities is the class the device was configured with locally.


