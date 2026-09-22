# L17 — juniper_vjunos-router

- **Date measured:** 2026-09-21
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L17-juniper_vjunos-router.pcap` — 3808 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L17-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Which `system tacplus-options` statements change what a port49 answer means on Junos: whether `strict-authorization` makes a DENIED session authorization refuse the login (and what it does to break-glass when port49d is down, which is the 3am case), what AV pairs `enhanced-accounting` adds and to which record types, which accounting records carry a user that is not the logged-in operator and what port49 does with them today, and whether `authorization-time-interval` re-authorizes a live session so that a revocation can reach it.

## Observation

## 5. Every `tacplus-options` knob this image offers

Listed, not measured: this is the device's own completion help, verbatim, so that a reader can see which of the statements below exist on this release before reading what they did.

`set system tacplus-options ?`

```
set system tacplus-options ?
Possible completions:
+ apply-groups         Groups from which to inherit configuration data
+ apply-groups-except  Don't inherit configuration data from these groups
  authorization-time-interval  TACACS+ authorization refresh time interval (15..1440 minutes)
  enhanced-accounting  Include authentication method, remote port and user-privileges in 'login' accounting
  exclude-cmd-attribute  In start/stop requests, do not include 'cmd' attribute
  no-cmd-attribute-value  In start/stop requests, set 'cmd' attribute value to empty string
  no-strict-authorization  Don't deny login if authorization request fails
  service-name         TACACS+ service name
  strict-authorization  Deny login if authorization request fails
  timestamp-and-timezone  In start/stop accounting packets, include 'start-time', 'stop-time' and 'timezone' attributes
[edit]
breakglass@srx1# set system tacplus-options    
```

`set system tacplus-options authorization-time-interval ?`

```
set system tacplus-options authorization-time-interval ?
Possible completions:
  <authorization-time-interval>  TACACS+ authorization refresh time interval (15..1440 minutes)
[edit]
breakglass@srx1# set system tacplus-options authorization-time-interval    
```

## 1. `set system tacplus-options strict-authorization`

Applied for every attempt in this section:

```
set system tacplus-options strict-authorization
commit
```

The device said:

```
[edit]
commit complete

[edit]
```

`show configuration system tacplus-options | display set | no-more` then showed:

```
set system tacplus-options strict-authorization
```


### (a) port49 PERMITS the session authorization

#### (a) permit, strict-authorization committed

Committed on the device: `strict-authorization`. port49 was answering from `session_services: [junos-exec] (the built-in default)`.

**Outcome: logged in.**

What the device wrote on the channel:

```
--- JUNOS 23.4R2-S2.1 Kernel 64-bit  JNPR-12.1-20240604.39c9257_buil
jopt01@srx1> set cli screen-length 0 
Screen length set to 0

jopt01@srx1> show cli authorization 
Current user: 'remote' login: 'jopt01' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secret <redacted by the harness>
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none

jopt01@srx1> 
```

port49's own record:

```
event=authorize_session verdict=permit reason=context_matched
    request.service="junos-exec" request.raw=[service=junos-exec]
    port="" rem_addr="172.100.100.1"
```

What the device says the session may do:

```
show cli authorization
```

```
 
Current user: 'remote' login: 'jopt01' class 'p49-readonly'
Permissions:
    view        -- Can view current values and statistics
    view-configuration-- Can view all configuration (not including secrets)
Individual command authorization:
    Allow regular expression: none
    Deny regular expression: none
    Allow configuration regular expression: none
    Deny configuration regular expression: none
```

Accounting for this attempt (11 records):

| flags | `user` | `port` | `rem_addr` | `task_id` | `session_pid` | `service` | `cmd` | port49 `attribution` |
|---|---|---|---|---|---|---|---|---|
| stop | `breakglass` | `0` | `172.100.100.1` | `1` | `14487` | `shell` | `configure <cr>` | `unattributed` |
| stop | `breakglass` | `0` | `172.100.100.1` | `2` | `14487` | `shell` | `set: [system tacplus-options] unconfigured -- "strict-authorization"<cr>` | `unattributed` |
| stop | `breakglass` | `0` | `172.100.100.1` | `3` | `14487` | `shell` | `set system tacplus-options strict-authorization <cr>` | `unattributed` |
| stop | `breakglass` | `0` | `172.100.100.1` | `4` | `14487` | `shell` | `commit <cr>` | `unattributed` |
| stop | `breakglass` | `0` | `172.100.100.1` | `5` | `14487` | `shell` | `exit <cr>` | `unattributed` |
| stop | `breakglass` | `0` | `172.100.100.1` | `6` | `14487` | `shell` | `show configuration system tacplus-options / display set / no-more <cr>` | `unattributed` |
| stop | `breakglass` | `0` | `172.100.100.1` | `1` | `14487` | `shell` | `logout` | `unattributed` |
| start | `jopt01` | `0` | `172.100.100.1` | `1` | `14951` | `shell` | `login` | `resolved` |
| stop | `jopt01` | `0` | `172.100.100.1` | `2` | `14951` | `shell` | `set cli screen-length 0 <cr>` | `resolved` |
| stop | `jopt01` | `0` | `172.100.100.1` | `3` | `14951` | `shell` | `show cli authorization <cr>` | `resolved` |
| stop | `jopt01` | `0` | `172.100.100.1` | `1` | `14951` | `shell` | `logout` | `resolved` |


### (b) port49 DENIES the session authorization on purpose

port49 is configured to authorize `shell` alone, so a Junos `junos-exec` request is denied `service_unsupported` — the same condition that stood on every Junos login port49 answered before 2026-09-21 (§15 L10), and the condition the 2026-09-21 run measured to be **advisory** without `strict-authorization`.

#### (b) deny, strict-authorization committed

Committed on the device: `strict-authorization`. port49 was answering from `session_services: [shell] — every Junos session authorization denied`.

**Outcome: **SSH authentication refused**.**

The SSH client never got past authentication. This string is the **Go SSH client's**, not the device's — an operator at a terminal sees their own client's wording of the same event, and what the DEVICE said is in its own log below:

```
ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```

port49's own record:

```
event=authorize_session verdict=deny reason=service_unsupported
    request.service="junos-exec" request.raw=[service=junos-exec]
    port="" rem_addr="172.100.100.1"
```


**What the device itself logged for that attempt**, which is the operator's real answer to "why was I refused":

```
show log messages | match jopt02 | no-more
```

```
(nothing matching this login reached `messages` on this image, or the command did not return: <nil>)
```


### (a) against (b)

| | port49 answered | login | class the device gave |
|---|---|---|---|
| (a) permit, strict-authorization committed | permit context_matched | logged in | `p49-readonly` |
| (b) deny, strict-authorization committed | deny service_unsupported | **SSH authentication refused** | `` |

**`strict-authorization` makes a denied session authorization binding on this image.** The same denial that completed a login on 2026-09-21 now ends it at the SSH authentication refused step. That is the statement the reference configuration in `tests/lab/configs/vjunos-startup.conf` is missing, and without it port49's session authorization constrains nothing on Junos.

### (c) port49d stopped entirely — can break-glass still get in?

`strict-authorization` is committed for every cell below. The account is the local `breakglass` with its local password, over SSH, with port49d **not listening** — so the device sees the server as unreachable, which is the one condition L4 measured a local password being taken at all.

| `authentication-order` | port49d | `breakglass` over SSH | took |
|---|---|---|---|
| `authentication-order [ tacplus password ]` | not listening | **logged in** | 30ms |
| `authentication-order tacplus` | not listening | **logged in** | 30ms |


### (d) port49 answers the authentication and is gone before the authorization

**The session authorization arrives during SSH authentication on this image, not when the shell starts.** Ten seconds after the SSH client finished authenticating — and before it had asked for a session channel at all — port49 had already answered the `authorize_session`:

```
  event=redeem verdict=permit reason=token_redeemed flags= user=jopt03 port=
  event=authorize_session verdict=permit reason=context_matched flags= user=jopt03 port=
```

So the two exchanges cannot be separated from the client side, and this run does **not** produce the stranded-authorization state by stopping the daemon between them. A racing kill would win sometimes and lose sometimes, and a note that cannot say which happened for the attempt it is describing measures nothing.

What it does settle, and it is the more useful half: **a revocation has no window here.** Authentication and authorization are one event to the operator, so there is no point between them at which port49 could change its mind about a login already in flight. Whatever makes a Junos session stop has to reach an ALREADY ESTABLISHED session, which is what item 4 asks.

### (e) NETCONF on port 830, with `strict-authorization` committed

| port49 answered | NETCONF session | `<get-configuration>` |
|---|---|---|
| permit context_matched | opened | see below |
| deny service_unsupported | **refused** | — |

**port49 permits.**

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:changed-seconds="1790033124" junos:changed-localtime="2026-09-21 23:25:24 UTC">
    <system>
        <host-name>srx1</host-name>
    </system>
</configuration>
</rpc-reply>
```

**port49 denies `service_unsupported`.**

```
SSH to the NETCONF port 830: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
```


## 2. `set system tacplus-options enhanced-accounting`

The same session, twice: log in with a token, run `show version`, `show system uptime`, log out, and collect every accounting record. Once without the statement and once with it, nothing else changed.

### Without the statement — 6 records for `jopt06`

| flags | `user` | `port` | `rem_addr` | `task_id` | `session_pid` | `service` | `cmd` | port49 `attribution` |
|---|---|---|---|---|---|---|---|---|
| start | `jopt06` | `0` | `172.100.100.1` | `1` | `16356` | `shell` | `login` | `resolved` |
| stop | `jopt06` | `0` | `172.100.100.1` | `2` | `16356` | `shell` | `set cli screen-length 0 <cr>` | `resolved` |
| stop | `jopt06` | `0` | `172.100.100.1` | `3` | `16356` | `shell` | `show cli authorization <cr>` | `resolved` |
| stop | `jopt06` | `0` | `172.100.100.1` | `4` | `16356` | `shell` | `show version <cr>` | `resolved` |
| stop | `jopt06` | `0` | `172.100.100.1` | `5` | `16356` | `shell` | `show system uptime <cr>` | `resolved` |
| stop | `jopt06` | `0` | `172.100.100.1` | `1` | `16356` | `shell` | `logout` | `resolved` |

```
account flags=start user=jopt06
    task_id=1
    service=shell
    session_pid = 16356
    cmd=login
account flags=stop user=jopt06
    task_id=2
    service=shell
    session_pid = 16356
    cmd=set cli screen-length 0 <cr>
account flags=stop user=jopt06
    task_id=3
    service=shell
    session_pid = 16356
    cmd=show cli authorization <cr>
account flags=stop user=jopt06
    task_id=4
    service=shell
    session_pid = 16356
    cmd=show version <cr>
account flags=stop user=jopt06
    task_id=5
    service=shell
    session_pid = 16356
    cmd=show system uptime <cr>
account flags=stop user=jopt06
    task_id=1
    service=shell
    session_pid = 16356
    elapsed_time=2
    cmd=logout
```


```
set system tacplus-options enhanced-accounting
commit
```

The device said:

```
[edit]
commit complete

[edit]
```

`show configuration system tacplus-options | display set | no-more` then showed:

```
set system tacplus-options enhanced-accounting
```


### With `enhanced-accounting` — 6 records for `jopt07`

| flags | `user` | `port` | `rem_addr` | `task_id` | `session_pid` | `service` | `cmd` | port49 `attribution` |
|---|---|---|---|---|---|---|---|---|
| start | `jopt07` | `0` | `172.100.100.1` | `1` | `17028` | `shell` | `login` | `resolved` |
| stop | `jopt07` | `0` | `172.100.100.1` | `2` | `17028` | `shell` | `set cli screen-length 0 <cr>` | `resolved` |
| stop | `jopt07` | `0` | `172.100.100.1` | `3` | `17028` | `shell` | `show cli authorization <cr>` | `resolved` |
| stop | `jopt07` | `0` | `172.100.100.1` | `4` | `17028` | `shell` | `show version <cr>` | `resolved` |
| stop | `jopt07` | `0` | `172.100.100.1` | `5` | `17028` | `shell` | `show system uptime <cr>` | `resolved` |
| stop | `jopt07` | `0` | `172.100.100.1` | `1` | `17028` | `shell` | `logout` | `resolved` |

```
account flags=start user=jopt07
    task_id=1
    service=shell
    session_pid = 17028
    cmd=login
    Port=51164
    Authentication-Type=remote
    User_Perms=view view-configuration 
account flags=stop user=jopt07
    task_id=2
    service=shell
    session_pid = 17028
    cmd=set cli screen-length 0 <cr>
account flags=stop user=jopt07
    task_id=3
    service=shell
    session_pid = 17028
    cmd=show cli authorization <cr>
account flags=stop user=jopt07
    task_id=4
    service=shell
    session_pid = 17028
    cmd=show version <cr>
account flags=stop user=jopt07
    task_id=5
    service=shell
    session_pid = 17028
    cmd=show system uptime <cr>
account flags=stop user=jopt07
    task_id=1
    service=shell
    session_pid = 17028
    elapsed_time=1
    cmd=logout
```


### What `enhanced-accounting` added

| record (`flags`/kind) | AV pairs added | AV pairs no longer sent |
|---|---|---|
| `start/login` | `Authentication-Type`, `Port`, `User_Perms` | — |
| `stop/command` | — | — |
| `stop/logout` | — | — |

**Added, exactly as the device spells them:** `Authentication-Type`, `Port`, `User_Perms`.

Each one, with a value the device actually sent:

```
Authentication-Type  on flags=start/login: Authentication-Type=remote
Port                 on flags=start/login: Port=51164
User_Perms           on flags=start/login: User_Perms=view view-configuration
```

### Two concurrent sessions of the same user

Two sessions of `jopt08` were open at once (the second presented the same, spent, token and was permitted out of the receipt). Their accounting, 8 records:

| flags | `user` | `port` | `rem_addr` | `task_id` | `session_pid` | `service` | `cmd` | port49 `attribution` |
|---|---|---|---|---|---|---|---|---|
| start | `jopt08` | `0` | `172.100.100.1` | `1` | `17244` | `shell` | `login` | `resolved` |
| start | `jopt08` | `1` | `172.100.100.1` | `1` | `17246` | `shell` | `login` | `resolved` |
| stop | `jopt08` | `0` | `172.100.100.1` | `2` | `17244` | `shell` | `set cli screen-length 0 <cr>` | `resolved` |
| stop | `jopt08` | `0` | `172.100.100.1` | `3` | `17244` | `shell` | `show system users / match . <cr>` | `resolved` |
| stop | `jopt08` | `1` | `172.100.100.1` | `2` | `17246` | `shell` | `set cli screen-length 0 <cr>` | `resolved` |
| stop | `jopt08` | `1` | `172.100.100.1` | `3` | `17246` | `shell` | `show system users / match . <cr>` | `resolved` |
| stop | `jopt08` | `0` | `172.100.100.1` | `1` | `17244` | `shell` | `logout` | `resolved` |
| stop | `jopt08` | `1` | `172.100.100.1` | `1` | `17246` | `shell` | `logout` | `resolved` |

```
account flags=start user=jopt08
    task_id=1
    service=shell
    session_pid = 17244
    cmd=login
    Port=54496
    Authentication-Type=remote
    User_Perms=view view-configuration 
account flags=start user=jopt08
    task_id=1
    service=shell
    session_pid = 17246
    cmd=login
    Port=54504
    Authentication-Type=remote
    User_Perms=view view-configuration 
account flags=stop user=jopt08
    task_id=2
    service=shell
    session_pid = 17244
    cmd=set cli screen-length 0 <cr>
account flags=stop user=jopt08
    task_id=3
    service=shell
    session_pid = 17244
    cmd=show system users | match . <cr>
account flags=stop user=jopt08
    task_id=2
    service=shell
    session_pid = 17246
    cmd=set cli screen-length 0 <cr>
account flags=stop user=jopt08
    task_id=3
    service=shell
    session_pid = 17246
    cmd=show system users | match . <cr>
account flags=stop user=jopt08
    task_id=1
    service=shell
    session_pid = 17244
    elapsed_time=1
    cmd=logout
account flags=stop user=jopt08
    task_id=1
    service=shell
    session_pid = 17246
    elapsed_time=1
    cmd=logout
```


The two `cmd=login` records, field by field:

| field | distinct values across the two sessions | separates them |
|---|---|---|
| `Authentication-Type` | `remote` | no |
| `Port` | `54496`, `54504` | **yes** |
| `User_Perms` | `view view-configuration` | no |
| `cmd` | `login` | no |
| `ctx_id (port49's own)` | `M2WHXATLXEBLMRST` | no |
| `port (TACACS+ header)` | `0`, `1` | **yes** |
| `rem_addr (TACACS+ header)` | `172.100.100.1` | no |
| `service` | `shell` | no |
| `session_pid` | `17244`, `17246` | **yes** |
| `task_id` | `1` | no |

**`Port`, `port (TACACS+ header)`, `session_pid` separate the two sessions.** port49's own `ctx_id` does not — one context covers both, which is decision 15 behaving as specified — so anything that needs to tell two shells of one operator apart has to carry one of these forward from the record.

## 3. Which accounting records name a user who is not the operator

The production observation this item exists for: `show version` triggers an RPC that runs as root, so some records carry a user who is not the person who typed the command. `enhanced-accounting` is committed for this section.

The token operator is given a class that can commit for the duration of this item:

```
set system login class p49-rpc permissions all
set system login user remote class p49-rpc
commit
```

The lab's deployed template is `class p49-readonly` (`permissions [ view view-configuration ]`), under which `configure` is refused outright — so a commit could not be accounted for at all. The class is deleted again at the end of this test.

The operator was `jopt09` over SSH and `jopt10` over NETCONF. What the device accounted for under those two names, 17 of the 25 records in the window (the rest belong to the `breakglass` admin session this test used to swap the class, and are excluded):

| flags | `user` | `port` | `rem_addr` | `task_id` | `session_pid` | `service` | `cmd` | port49 `attribution` |
|---|---|---|---|---|---|---|---|---|
| start | `jopt09` | `0` | `172.100.100.1` | `1` | `17762` | `shell` | `login` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `2` | `17762` | `shell` | `set cli screen-length 0 <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `3` | `17762` | `shell` | `show cli authorization <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `4` | `17762` | `shell` | `show version <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `5` | `17762` | `shell` | `show chassis hardware <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `6` | `17762` | `shell` | `configure <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `7` | `17762` | `shell` | `set: [system location building] unconfigured -- "port49-lab-L17"<cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `8` | `17762` | `shell` | `set system location building port49-lab-L17 <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `9` | `17762` | `shell` | `commit <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `10` | `17762` | `shell` | `exit <cr>` | `resolved` |
| stop | `jopt09` | `0` | `172.100.100.1` | `1` | `17762` | `shell` | `logout` | `resolved` |
| start | `jopt10` | `non-tty` | `` | `1` | `18413` | `shell` | `login` | `resolved` |
| stop | `jopt10` | `non-tty` | `` | `2` | `18413` | `shell` | `xml-mode netconf need-trailer <cr>` | `resolved` |
| start | `jopt10` | `non-tty` | `` | `1` | `18412` | `shell` | `login` | `resolved` |
| stop | `jopt10` | `non-tty` | `172.100.100.1` | `1` | `18413` | `shell` | `logout` | `resolved` |
| stop | `jopt10` | `non-tty` | `` | `2` | `18412` | `shell` | `get-config<cr>` | `resolved` |
| stop | `jopt10` | `non-tty` | `172.100.100.1` | `1` | `18412` | `shell` | `logout` | `resolved` |

```
account flags=start user=jopt09
    task_id=1
    service=shell
    session_pid = 17762
    cmd=login
    Port=54334
    Authentication-Type=remote
    User_Perms=access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-<contd>
    User_Perms=control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session<contd>
    User_Perms=-mirroring-control unified-edge unified-edge-control 
account flags=stop user=jopt09
    task_id=2
    service=shell
    session_pid = 17762
    cmd=set cli screen-length 0 <cr>
account flags=stop user=jopt09
    task_id=3
    service=shell
    session_pid = 17762
    cmd=show cli authorization <cr>
account flags=stop user=jopt09
    task_id=4
    service=shell
    session_pid = 17762
    cmd=show version <cr>
account flags=stop user=jopt09
    task_id=5
    service=shell
    session_pid = 17762
    cmd=show chassis hardware <cr>
account flags=stop user=jopt09
    task_id=6
    service=shell
    session_pid = 17762
    cmd=configure <cr>
account flags=stop user=jopt09
    task_id=7
    service=shell
    session_pid = 17762
    cmd=set: [system location building] unconfigured -- "port49-lab-L17"<cr>
account flags=stop user=jopt09
    task_id=8
    service=shell
    session_pid = 17762
    cmd=set system location building port49-lab-L17 <cr>
account flags=stop user=jopt09
    task_id=9
    service=shell
    session_pid = 17762
    cmd=commit <cr>
account flags=stop user=jopt09
    task_id=10
    service=shell
    session_pid = 17762
    cmd=exit <cr>
account flags=stop user=jopt09
    task_id=1
    service=shell
    session_pid = 17762
    elapsed_time=3
    cmd=logout
account flags=start user=jopt10
    task_id=1
    service=shell
    session_pid = 18413
    cmd=login
    Port=48472
    Authentication-Type=remote
    User_Perms=access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-<contd>
    User_Perms=control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session<contd>
    User_Perms=-mirroring-control unified-edge unified-edge-control 
account flags=stop user=jopt10
    task_id=2
    service=shell
    session_pid = 18413
    cmd=xml-mode netconf need-trailer <cr>
account flags=start user=jopt10
    task_id=1
    service=shell
    session_pid = 18412
    cmd=login
    Port=48472
    Authentication-Type=remote
    User_Perms=access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-<contd>
    User_Perms=control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session<contd>
    User_Perms=-mirroring-control unified-edge unified-edge-control 
account flags=stop user=jopt10
    task_id=1
    service=shell
    session_pid = 18413
    elapsed_time=0
    cmd=logout
account flags=stop user=jopt10
    task_id=2
    service=shell
    session_pid = 18412
    cmd=get-config<cr>
account flags=stop user=jopt10
    task_id=1
    service=shell
    session_pid = 18412
    elapsed_time=0
    cmd=logout
```


```
configure
set system location building port49-lab-L17
commit
```

```
commit complete

[edit]
```

The NETCONF `<get-config>` returned 7960 bytes; its first lines:

```
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/23.4R2-S2.1/junos" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="1">
<data>
<configuration xmlns="http://xml.juniper.net/xnm/1.1/xnm" junos:commit-seconds="1790033212" junos:commit-localtime="2026-09-21 23:26:52 UTC" junos:commit-user="jopt09">
    <version>23.4R2-S2.1</version>
    <system>
        <host-name>srx1</host-name>
        <root-authentication>
            <encrypted-password <redacted by the harness>
        </root-authentication>
        <login>
            <class>
                <name>p49-readonly</name>
                <permissions>view</permissions>
                <permissions>view-configuration</permissions>
            </class>
            <class>
                <name>p49-rpc</name>
                <permissions>all</permissions>
            </class>
            <user>
                <name>admin</name>
                <uid>2000</uid>
                <class>super-user</class>
                <authentication>
                    <encrypted-password <redacted by the harness>
                </authentication>
            </user>
            <user>
                <name>breakglass</name>
                <uid>2002</uid>
                <class>super-user</class>
                <authentication>
                <junos:comment>/* This is a SHA-512 crypt hash of breakglassPassword <redacted by the harness>
                   tests/lab/harness_test.go -- that constant is the source of
                   truth for the plaintext, and this line is only its hash.
                   Regenerate with `openssl passwd -6 -salt p49labsalt` over
                   that same constant if it ever changes. Neither is a secret <redacted by the harness>
                   both are published lab constants in a public repository, and
                   the account exists only inside this containerlab topology.

                   It is a hash rather than plain-text-password <redacted by the harness>
                   that form does not produce a usable password <redacted by the harness>
                   21.4R3.15. Junos normally converts it to an
                   encrypted-password <redacted by the harness>
                   the account ended up with a disabled password <redacted by the harness>
                   /etc/master.passwd -- cannot authenticate with one -- so every
                   refused breakglass login there said nothing about
                   authentication-order, because there was nothing to fall
                   through TO. Measured 2026-09-20 off the console, in
                   tests/lab/results/juniper_vsrx-config-verified.md.

                   Verified after this change on BOTH images: breakglass logs
                   in over SSH with port49d not running. Do not go back to
                   plain-text-password <redacted by the harness>
                    <encrypted-password <redacted by the harness>
                </authentication>
            </user>
            <user>
                <name>remote</name>
                <uid>2001</uid>
                <class>p49-rpc</class>
            </user>
        </login>
        <junos:comment>/* NETCONF over SSH, for the transport tests in tests/lab/transport_test.go.
       Junos serves NETCONF on TCP 830 once this statement is committed and on
       nothing at all until then, so without this line the NETCONF tests fail on
       a connection refused that reads like a device fault rather than a missing
       statement. It is the only thing in this file that is not about TACACS+.

       On comment syntax, once more: never write a closing slash-star pair
       inside comment prose. The long note above authentication-order explains
       what that cost the first time. */</junos:comment>
        <services>
            <netconf>
                <ssh>
                </ssh>
            </netconf>
            <ssh>
                <root-login>allow</root-login>
            </ssh>
      
... (truncated for this note; the full answer is in the test log)
```

### The records that name somebody else

Measured: every accounting record this activity produced names the logged-in operator (`jopt09` or `jopt10`): NOT ONE carries `root` or any other user, on this image, under this accounting configuration (`events [ login change-log interactive-commands ]`), with `enhanced-accounting` committed.

Sent:

```
show version
show chassis hardware
configure; set system location building port49-lab-L17; commit
<get-config><source><running/></source></get-config>

(every accounting record port49 received in that window, excluding the
 breakglass admin session this test used to swap the login class)
```

The device replied:

```
```
account flags=start user=jopt09
    task_id=1
    service=shell
    session_pid = 17762
    cmd=login
    Port=54334
    Authentication-Type=remote
    User_Perms=access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-<contd>
    User_Perms=control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session<contd>
    User_Perms=-mirroring-control unified-edge unified-edge-control 
account flags=stop user=jopt09
    task_id=2
    service=shell
    session_pid = 17762
    cmd=set cli screen-length 0 <cr>
account flags=stop user=jopt09
    task_id=3
    service=shell
    session_pid = 17762
    cmd=show cli authorization <cr>
account flags=stop user=jopt09
    task_id=4
    service=shell
    session_pid = 17762
    cmd=show version <cr>
account flags=stop user=jopt09
    task_id=5
    service=shell
    session_pid = 17762
    cmd=show chassis hardware <cr>
account flags=stop user=jopt09
    task_id=6
    service=shell
    session_pid = 17762
    cmd=configure <cr>
account flags=stop user=jopt09
    task_id=7
    service=shell
    session_pid = 17762
    cmd=set: [system location building] unconfigured -- "port49-lab-L17"<cr>
account flags=stop user=jopt09
    task_id=8
    service=shell
    session_pid = 17762
    cmd=set system location building port49-lab-L17 <cr>
account flags=stop user=jopt09
    task_id=9
    service=shell
    session_pid = 17762
    cmd=commit <cr>
account flags=stop user=jopt09
    task_id=10
    service=shell
    session_pid = 17762
    cmd=exit <cr>
account flags=stop user=jopt09
    task_id=1
    service=shell
    session_pid = 17762
    elapsed_time=3
    cmd=logout
account flags=start user=jopt10
    task_id=1
    service=shell
    session_pid = 18413
    cmd=login
    Port=48472
    Authentication-Type=remote
    User_Perms=access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-<contd>
    User_Perms=control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session<contd>
    User_Perms=-mirroring-control unified-edge unified-edge-control 
account flags=stop user=jopt10
    task_id=2
    service=shell
    session_pid = 18413
    cmd=xml-mode netconf need-trailer <cr>
account flags=start user=jopt10
    task_id=1
    service=shell
    session_pid = 18412
    cmd=login
    Port=48472
    Authentication-Type=remote
    User_Perms=access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-<contd>
    User_Perms=control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session<contd>
    User_Perms=-mirroring-control unified-edge unified-edge-control 
account flags=stop user=jopt10
    task_id=1
    service=shell
    session_pid = 18413
    elapsed_time=0
    cmd=logout
account flags=stop user=jopt10
    task_id=2
    service=shell
    session_pid = 18412
    cmd=get-config<cr>
account flags=stop user=jopt10
    task_id=1
    service=shell
    session_pid = 18412
    elapsed_time=0
    cmd=logout
```
```

That is a finding about **this image under this accounting configuration**, not a contradiction of the production observation. The lab accounts for `events [ login change-log interactive-commands ]`; a fleet that also accounts for other event classes may well see records the lab's event list never asks the device to send. What it does settle is that the four activities named in the brief — `show version`, `show chassis hardware`, a `configure`/`commit` and a NETCONF `<get-config>` — do not by themselves produce a record under another name on this image.

## 4. `set system tacplus-options authorization-time-interval`

This is the revocation question. port49 can stop issuing tokens in an instant; what it cannot do is reach a session that is already open. If the device re-sends the session authorization on a timer, a denial on the second pass is a revocation that lands on a live session — and if it does not, nothing port49 decides after a login has begun can affect it.


```
set system tacplus-options authorization-time-interval 15
commit
```

The device said:

```
[edit]
commit complete

[edit]
```

`show configuration system tacplus-options | display set | no-more` then showed:

```
set system tacplus-options authorization-time-interval 15
set system tacplus-options enhanced-accounting
```

The image accepted `authorization-time-interval 15`. **The unit is not assumed here**: item 5's completion listing is the device's own statement of it, and this section reads the interval back off the wire — the gap between two `authorize_session` records for one live session is the measurement, whatever the statement's unit turns out to be.


### with `strict-authorization` committed

The session of `jopt11` was opened while port49 permitted, and port49 was switched to the denying configuration immediately afterwards — **with that session still open** — so the first re-authorization the device sends is refused.

The refusal arrives as `deny context_missing` rather than `deny service_unsupported`, and that is worth a sentence of its own. Switching port49's configuration restarts the daemon, and the login context store is in memory (`internal/store/memory`), so the context created by this session's own login does not survive the restart. **Every live Junos session's next re-authorization is denied `context_missing` after a port49d restart** — which under `strict-authorization` is the difference between restarting the daemon and cutting off every operator currently logged in, on a timer they cannot see. It is the same denial either way for the purposes of this measurement, and a more realistic one than a service-name mismatch.

**This image DOES re-authorize a live session, and port49 refused the re-authorization.** It arrived 15m0s after the login's own authorization — the statement is configured for 15m0s, and this is that interval measured off the wire rather than read off the configuration:

```
event=authorize_session verdict=deny reason=context_missing
    request.service="junos-exec" request.raw=[service=junos-exec]
    port="" rem_addr=""
```

The session that was already open was then probed, and it **was still listed by the device**:

A bare newline, to see whether the session is still there at all:

```
jopt11@srx1>
```

Then, twice, a command whose real output contains `Current time`:

```
show system uptime
```

```
show
             ^
unknown command.
jopt11@srx1> show   system
             ^
unknown command.
jopt11@srx1> showsystem   uptime
```

And the device's own answer, asked on a separate admin CLI while that session was still open:

```
show system users | no-more
```

```
11:42PM  up 19 mins, 2 users, load averages: 0.88, 0.62, 0.46
USER     TTY      FROM                              LOGIN@  IDLE WHAT
jopt11   pts/0    172.100.100.1                    11:27PM     - -cli (cli)    
breakglass pts/1  172.100.100.1                    11:42PM     - -cli (cli)
```

Measured: a DENIED re-authorization does not end a Junos session that is already open on this image, with `strict-authorization` committed: after port49 refused its re-authorization the session was still there — it answered its prompt, and the device still listed the login in `show system users | no-more`. Revocation does not reach a live session this way, and the re-authorization is an audit event rather than an enforcement point.

Sent:

```
port49 was switched to a configuration that denies every Junos session authorization,
with the session of jopt11 still open. The re-authorization that arrived 15m0s
later was answered `deny context_missing`. The operator then typed, in that same session:

    show system uptime
```

The device replied:

```
show
             ^
unknown command.
jopt11@srx1> show   system
             ^
unknown command.
jopt11@srx1> showsystem   uptime
```

### without `strict-authorization`

The session of `jopt12` was opened while port49 permitted, and port49 was switched to the denying configuration immediately afterwards — **with that session still open** — so the first re-authorization the device sends is refused.

The refusal arrives as `deny context_missing` rather than `deny service_unsupported`, and that is worth a sentence of its own. Switching port49's configuration restarts the daemon, and the login context store is in memory (`internal/store/memory`), so the context created by this session's own login does not survive the restart. **Every live Junos session's next re-authorization is denied `context_missing` after a port49d restart** — which under `strict-authorization` is the difference between restarting the daemon and cutting off every operator currently logged in, on a timer they cannot see. It is the same denial either way for the purposes of this measurement, and a more realistic one than a service-name mismatch.

**This image DOES re-authorize a live session, and port49 refused the re-authorization.** It arrived 15m0s after the login's own authorization — the statement is configured for 15m0s, and this is that interval measured off the wire rather than read off the configuration:

```
event=authorize_session verdict=deny reason=context_missing
    request.service="junos-exec" request.raw=[service=junos-exec]
    port="" rem_addr=""
```

The session that was already open was then probed, and it **was still listed by the device**:

A bare newline, to see whether the session is still there at all:

```
jopt12@srx1>
```

Then, twice, a command whose real output contains `Current time`:

```
show system uptime
```

```
show
             ^
unknown command.
jopt12@srx1> show   system
             ^
unknown command.
jopt12@srx1> showsystem   uptime
```

And the device's own answer, asked on a separate admin CLI while that session was still open:

```
show system users | no-more
```

```
11:57PM  up 34 mins, 2 users, load averages: 0.90, 0.67, 0.54
USER     TTY      FROM                              LOGIN@  IDLE WHAT
jopt12   pts/0    172.100.100.1                    11:42PM     - -cli (cli)    
breakglass pts/1  172.100.100.1                    11:57PM     - -cli (cli)
```

Measured: a DENIED re-authorization does not end a Junos session that is already open on this image, without `strict-authorization`: after port49 refused its re-authorization the session was still there — it answered its prompt, and the device still listed the login in `show system users | no-more`. Revocation does not reach a live session this way, and the re-authorization is an audit event rather than an enforcement point.

Sent:

```
port49 was switched to a configuration that denies every Junos session authorization,
with the session of jopt12 still open. The re-authorization that arrived 15m0s
later was answered `deny context_missing`. The operator then typed, in that same session:

    show system uptime
```

The device replied:

```
show
             ^
unknown command.
jopt12@srx1> show   system
             ^
unknown command.
jopt12@srx1> showsystem   uptime
```

## What this settles

1. **`strict-authorization` is the statement that makes a port49 denial bind on Junos.** With it committed, the denial that completed a login on 2026-09-21 refuses one. The reference configuration in `tests/lab/configs/vjunos-startup.conf` does not carry it, which is why the 2026-09-21 measurement found Junos authorization advisory: that was a property of the configuration, not of the vendor.

2. **Break-glass survives it.** With `strict-authorization` committed and port49d not listening, the local account logged in over SSH under every authentication order measured. The statement makes port49's answer binding without making port49 a single point of failure for the device.

3. **`enhanced-accounting` adds `Authentication-Type`, `Port`, `User_Perms`.** Section 2 says on which record types, and whether any of them tells two concurrent sessions of one user apart.

4. **No accounting record named a user other than the operator** under this lab's accounting event list. Section 3 carries the negative with the records behind it.

5. **Re-authorization:** with `strict-authorization` committed: re-authorizes after 15m0s, and a denial did NOT end the live session; without `strict-authorization`: re-authorizes after 15m0s, and a denial did NOT end the live session.

