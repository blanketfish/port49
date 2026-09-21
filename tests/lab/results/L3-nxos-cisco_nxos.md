# L3-nxos — cisco_nxos

- **Date measured:** 2026-09-21
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/L3-nxos-cisco_nxos.pcap` — 200 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L3-nxos-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether the Nexus 9300v has an exec `enable` at all, under the lab's own configuration and under `feature privilege`; what reply attributes put an NX-OS session below privilege 15; and what the wire exchange carries when an enable does happen — username form, `service`, `port`, `rem_addr`, `priv_lvl`. This supersedes `tests/lab/results/L3-cisco_nxos.md`, which asserted that no enable exists while quoting a reply to a command it did not name.

## Observation

Each command below is typed on its own and its reply is recorded beside it. The note this supersedes said `% Invalid command at '^' marker.` without saying which command was rejected; the test that wrote it types `disable` first, so that reply was very probably `disable`'s. Here `disable`, `enable` and `enable 15` are separate rows and each carries its own transcript.

## Phase 1 — as `tests/lab/configs/nxos-startup.cfg` leaves the device

`feature privilege` is not configured and there is no `enable secret`.

Reply attributes: `["priv-lvl=15", "shell:roles*network-admin"]`

The prompt the login produced: `nx1#`

`show user-account`:

```
user:admin
        this user account has no expiry date
        roles:network-admin 
user:breakglass
        this user account has no expiry date
        roles:network-admin 
user:alice01
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice02
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice03
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice04
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice05
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice06
        roles:network-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice07
        roles:vdc-operator 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
user:alice08
        roles:network-admin 
account created through REMOTE authentication
Credentials such as ssh server key will be cached temporarily only for this user account
Local login not possible
nx1# 
```

Typed:

```
disable
```

The device replied:

```
       ^
% Invalid command at '^' marker.
nx1# 
```

Typed:

```
enable
```

The device replied:

```
       ^
% Invalid command at '^' marker.
nx1# 
```

Typed:

```
enable 15
```

The device replied:

```
       ^
% Invalid command at '^' marker.
nx1# 
```

**No authentication record beyond the login reached port49 in this session**, so no enable exchange was put on the wire by any of the three commands.

Measured: the device rejects `enable` outright without `feature privilege`, so there is no enable exchange to measure on this platform under that configuration.

Sent:

```
enable
```

The device replied:

```
       ^
% Invalid command at '^' marker.
nx1# 

(and no authentication record beyond the login reached the decision log in this session's window)
```


## Phase 2 — with `feature privilege` and an `enable secret`

Measured: this image has no `feature privilege` at all, so the configuration NX-OS documents an exec `enable` under cannot be applied here and phase 2 cannot be run. Taken with phase 1, that is the complete answer for this platform: no enable, under any configuration this image can be put into.

Sent:

```
configure terminal
feature privilege
```

The device replied:

```
feature privilege
                         ^
% Invalid command at '^' marker.
nx1(config)#
```

