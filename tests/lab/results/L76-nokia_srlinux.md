# L76 — nokia_srlinux

- **Date measured:** 2026-10-18
- **Platform:** nokia_srlinux (containerlab node `srl1`, 172.100.100.71)
- **Image version:** SR Linux 26.7.2-519 (`ghcr.io/nokia/srlinux:26.7.2-519`)
- **Topology:** `tests/lab/topologies/srlinux.clab.yml`
- **Capture:** `tests/lab/evidence/L76-nokia_srlinux.pcap` — 2760 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L76-nokia_srlinux.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `c9312fda6b0d3cb403f919a3243d291fd24f3087`, `PORT49_LAB_PLATFORMS=srlinux`, `-run ^TestL76$`

## Claim

Nokia SR Linux against port49 over TACACS+ on port 49, server group `port49` then `local`, accounting to `port49`: (a) a user that exists only in port49 logs in over SSH; the session table names it, the port49 group and the priv-lvl; the authentication type on the wire; (b) the authorization requests the login sends with priv-lvl-authorization true: services and attributes; whether any per-command request follows; what the device does with priv-lvl=15 and the optional shell:roles; (c) the accounting records a CLI command sends: start and stop, their attributes; whether a session start or stop is sent; (d) a wrong password: port49's refusal, the time to the device's refusal, and whether a port49 deny falls through to local; (e) a wrong shared secret: port49's no_known_key_matches, and whether the break-glass account still logs in through local, and how fast; (f) port49 stopped: the break-glass login through local and its time; a port49 user refused; whether a CLI command still runs with accounting unreachable, and its time; (g) port49 restarted: the time until the device asks port49 again; the empty connections a quiet minute holds (health checks) and whether port49 logs them; (h) priv-lvl=1 in the reply: the roles the session gets (p49-read only) and the session table's priv-lvl; (i) priv-lvl-authorization false (the default): whether any authorization request is sent, and the roles the session gets; (j) service-request nokia-srl-authorization-role true: the services the device asks for, port49's answers, and whether the login survives them; (k) a priv-lvl 1 user's second exec channel on one SSH login: the session table's Role cell on the first and the second exec, and whether a documented harmless write that p49-read must not be allowed succeeds on either; (l) exit-on-reject true: whether the break-glass account still logs in through local, and how fast, when port49 denies it, with a wrong shared secret and with port49 stopped.

## Observation

### Schema and configuration

Version: `version v26.7.2-519-g94fbd638fa8`.

The configuration under test, as the device reports it (`info from running system aaa`, values masked):

```
    authentication {
        idle-timeout 7200
        authentication-method [
            port49
            local
        ]
        admin-user {
            ssh-key [
                "<ssh public key masked>"
                "<ssh public key masked>"
                "<ssh public key masked>"
            ]
        }
        linuxadmin-user {
            password <masked>
            ssh-key [
                "<ssh public key masked>"
                "<ssh public key masked>"
                "<ssh public key masked>"
            ]
        }
        user breakglass {
            password <masked>
            role [
                p49-admin
            ]
        }
    }
    authorization {
        role p49-admin {
            services [
                cli
            ]
            tacacs {
                priv-lvl 15
            }
        }
        role p49-read {
            services [
                cli
            ]
            tacacs {
                priv-lvl 1
            }
        }
    }
    accounting {
        accounting-method [
            port49
        ]
        event command {
            record start-stop
        }
    }
    server-group local {
        type local
    }
    server-group port49 {
        type tacacs
        tacacs {
            priv-lvl-authorization true
        }
        server 172.100.100.1 {
            network-instance mgmt
            tacacs {
                port 49
                secret-key <masked>
            }
        }
    }

```

What the image's own YANG says where Nokia's guide says otherwise or nothing:

- The accounting event is `event command` (base aaa_accounting_event_type); the guide's `event commands` is an authorization event type.
- A local server group must be named `local`; the guide's `LOCAL-GROUP` is refused.
- The SR Linux native schema has no TACACS+ authorization method: `aaa-authorization-methods-config` and `aaa-authorization-events-top` are defined in srl_nokia-aaa.yang and never used, so there is no per-command authorization (OpenConfig's openconfig-aaa.yang does use them; OpenConfig mode is not measured).
- A local role grants no service unless `services` lists one (leaf-list, no default; the guide: "By default, a role has no services configured"), and a user whose roles grant none of the service it connects with is refused and the session closed. Both lab roles list `cli`. L76 runs 1 to 4 failed on the lab's own role configuration, which listed no service, not on port49.
- `priv-lvl-authorization` false (the default) skips authorization and grants full admin.

The server group's state (`info from state system aaa server-group port49`):

```
    type tacacs
    timeout 10
    health-check 30
    oper-state up
    tacacs {
        priv-lvl-authorization true
        service-request {
            nokia-srl-authorization-role false
            nokia-srl-authorization-role-cli false
            nokia-srl-authorization-role-netconf false
            nokia-srl-configuration-role false
        }
    }
    server 172.100.100.1 {
        network-instance mgmt
        oper-state up
        tacacs {
            port 49
        }
        radius {
            auth-port 1812
            acct-port 1813
            retransmit-attempts 3
        }
        statistics {
            login-success 0
            login-connection-failures 1
            login-rejects 1
            accounting-success 4
            accounting-rejects 0
            accounting-connection-failures 1
            authorization-success 0
            authorization-rejects 0
            authorization-connection-failures 0
            invalid-vsas 0
            malformed-vsas 0
            unknown-vsas 0
            valid-vsas 0
        }
    }

```


### (a) a user that exists only in port49 logs in over SSH; the session table names it, the port49 group and the priv-lvl; the authentication type on the wire

`alice01` (a user with no local account) logged in over SSH in 1.261s. port49's redeem: permit/token_redeemed, auth.method `ascii`. The session table's row: id 16, service `srlinux-cli`, method `port49`, priv-lvl `15`, tty ``.

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |        Role         |
  <LONG>
  | 10 | breakglass | sshd         | local                 |          | ssh | 172.100.100.1 | mgmt             | 2026-10-18T18:54:58.033Z | p49-admin           |
  | 11 | breakglass | sshd         | local                 |          | ssh | 172.100.100.1 | mgmt             | 2026-10-18T18:54:58.346Z | p49-admin           |
  | 16 | alice01*   | srlinux-cli  | port49                | 15       |     | 172.100.100.1 | mgmt             | 2026-10-18T18:55:01.568Z | p49-admin, p49-read |
  <LONG>

```

Records:

```
redeem permit/token_redeemed method=ascii user=alice01
authorize_session permit/context_matched user=alice01 service=shell request=[service=shell cmd*] reply=[priv-lvl=15 shell:roles*network-admin]
account flags=start user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

**Unknown platform (spec §8).** The redeem's reason is `token_redeemed`. port49 raised no unknown-platform signal: no record has reason `platform_unknown`, and its log names no unknown platform. Spec §8's alarm was not observed; this is a question for Ryan, not a code change.

port49d's log, the lines naming `platform_unknown`, an unknown platform or `nokia_srlinux` (last 20):

```

```

Observation: each token login prints `Could not chdir to home directory /home/<user>: No such file or directory` before its command output. The user has no home directory on the device; the line is cosmetic and the commands ran.

### (b) the authorization requests the login sends with priv-lvl-authorization true: services and attributes; whether any per-command request follows; what the device does with priv-lvl=15 and the optional shell:roles

1 authorization request(s) for `alice01`: 1 `authorize_session`, 0 `authorize_command` (per-command). Services: map[shell:1]. port49's reply attributes (from its record): [priv-lvl=15 shell:roles*network-admin]. The session's roles (the Role column of this user's rows in `show system aaa authentication session`): [p49-admin p49-read]; priv-lvl in the table: `15`. `network-admin` does not appear in this user's rows.

```
authorize_session permit/context_matched user=alice01 service=shell request=[service=shell cmd*] reply=[priv-lvl=15 shell:roles*network-admin]
```

This user's rows in the session table, as the device printed them:

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |        Role         |
  <LONG>
  | 16 | alice01*   | srlinux-cli  | port49                | 15       |     | 172.100.100.1 | mgmt             | 2026-10-18T18:55:01.568Z | p49-admin, p49-read |
```

Probe (b1): port49 replied `["priv-lvl=15","shell:roles*network-admin"]`; `alice02` **logged in**. Nokia's SA#authorization-use-tacacsx-server says "Unknown optional VSAs are discarded": a login that is refused here contradicts it, one that succeeds confirms it.

```
redeem permit/token_redeemed method=ascii user=alice02
authorize_session permit/context_matched user=alice02 service=shell request=[service=shell cmd*] reply=[priv-lvl=15 shell:roles*network-admin]
account flags=start user=alice02 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice02 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice02 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice02 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

Probe (b2): port49 replied `["priv-lvl=15","p49-probe*x"]`; `alice03` **logged in**. Nokia's SA#authorization-use-tacacsx-server says "Unknown optional VSAs are discarded": a login that is refused here contradicts it, one that succeeds confirms it.

```
redeem permit/token_redeemed method=ascii user=alice03
authorize_session permit/context_matched user=alice03 service=shell request=[service=shell cmd*] reply=[priv-lvl=15 p49-probe*x]
account flags=start user=alice03 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice03 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice03 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice03 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

### (c) the accounting records a CLI command sends: start and stop, their attributes; whether a session start or stop is sent

4 accounting record(s) for `alice01`'s 2 commands, by flags map[start:2 stop:2]. Records with no `cmd` (a session start or stop): 0.

```
account flags=start user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice01 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

Accounted commands of this login, in order, from `evidence/L76-nokia_srlinux/decisions.jsonl`:

1. `show system aaa authentication «redacted»`: port `ssh`, priv-lvl 15
2. `info from state system information version`: port `unknown`, priv-lvl 15

The commands after the first are accounted on a different port or at a different priv-lvl than the first, while the reply granted priv-lvl 15. This line is only what the device sent port49; whether that channel runs with more authority is cell (k)'s question.

port49 redacts the word after `authentication` in the accounted `show system aaa authentication` command (the records carry `redacted: true` and the word is shown as `«redacted»`): its accounting redaction treats that word as a credential, so an operator reading SR Linux accounting sees the command without it. Input for the `nokia_srlinux` adapter: whether that rule should be platform-aware.

### (d) a wrong password: port49's refusal, the time to the device's refusal, and whether a port49 deny falls through to local

These break-glass results hold for `exit-on-reject` false, the default; cell (l) repeats them at true.

A wrong password for `alice04` was refused in 988ms. port49's records:

```
redeem deny/device_mismatch method=ascii user=alice04
redeem deny/token_not_found method=ascii user=breakglass
```

With port49 up, `breakglass` (local only; port49 denies it, having no token for it) logged in in 1.206s. So a port49 deny **falls** through to `local` with `exit-on-reject` at its default.

**Operator hazard:** with `exit-on-reject` at its default, a person whom port49 denies still gets in if the device has a local account for them. port49's deny is not final on this platform. Setting `exit-on-reject` true makes it final, at a cost cell (l) measures: with it true the break-glass account is refused while port49 is up and denies it. Plan 12's reference config sets `exit-on-reject` (Ruling 1) knowing that.

The AAA log's lines for both users:

```
2026-10-18T18:54:58.049402+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00000|EV|sessionOpened|N: Opened session 10 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.049422+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00001|EV|<LONG>|N: User breakglass on session 10 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.869720+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00000|EV|sessionOpened|N: Opened session 11 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.869741+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00001|EV|<LONG>|N: User breakglass on session 11 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:03.610742+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00000|EV|sessionOpened|N: Opened session 18 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:03.610760+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00001|EV|<LONG>|N: User breakglass on session 18 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:05.754301+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00000|EV|sessionOpened|N: Opened session 21 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:05.754320+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00001|EV|<LONG>|N: User breakglass on session 21 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:07.898160+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3176|00000|EV|sessionOpened|N: Opened session 24 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:07.898181+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3176|00001|EV|<LONG>|N: User breakglass on session 24 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:08.503154+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2540|3175|00000|EV|<LONG>|W: User alice04 authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.007980+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00004|EV|sessionOpened|N: Opened session 26 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.007998+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00005|EV|<LONG>|N: User breakglass on session 26 successfully authenticated from host 172.100.100.1 in network-instance mgmt
```

The wrong password is a random string shaped like a token, so port49's device-tag check refuses it as `device_mismatch` (a token cut for another device, internal/daemon/authen/authen.go). A mistyped human password is not token-shaped and would reach `token_not_found`, as the break-glass line shows.

### (e) a wrong shared secret: port49's no_known_key_matches, and whether the break-glass account still logs in through local, and how fast

These break-glass results hold for `exit-on-reject` false, the default; cell (l) repeats them at true.

port49d on a key the device does not have. `alice12` (port49 user): refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain) in 44ms. `breakglass` (local): logged in in 70ms. port49's diagnoses: map[no_known_key_matches:1] (1 unvalidated record(s), 0 redeem(s)).

```
unvalidated diagnosis=no_known_key_matches
```

The AAA log:

```
2026-10-18T18:54:58.049402+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00000|EV|sessionOpened|N: Opened session 10 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.049422+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00001|EV|<LONG>|N: User breakglass on session 10 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.869720+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00000|EV|sessionOpened|N: Opened session 11 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.869741+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00001|EV|<LONG>|N: User breakglass on session 11 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:03.610742+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00000|EV|sessionOpened|N: Opened session 18 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:03.610760+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00001|EV|<LONG>|N: User breakglass on session 18 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:05.754301+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00000|EV|sessionOpened|N: Opened session 21 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:05.754320+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00001|EV|<LONG>|N: User breakglass on session 21 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:07.898160+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3176|00000|EV|sessionOpened|N: Opened session 24 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:07.898181+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3176|00001|EV|<LONG>|N: User breakglass on session 24 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.007980+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00004|EV|sessionOpened|N: Opened session 26 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.007998+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00005|EV|<LONG>|N: User breakglass on session 26 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.994702+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00002|EV|sessionOpened|N: Opened session 27 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.994724+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00003|EV|<LONG>|N: User breakglass on session 27 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:13.147691+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00002|EV|sessionOpened|N: Opened session 30 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:13.147709+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00003|EV|<LONG>|N: User breakglass on session 30 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:19.813609+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00004|EV|sessionOpened|N: Opened session 43 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:19.813630+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00005|EV|<LONG>|N: User breakglass on session 43 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:25.303999+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00003|EV|sessionOpened|N: Opened session 51 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:25.304018+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00004|EV|<LONG>|N: User breakglass on session 51 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:28.512172+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2540|3174|00002|EV|<LONG>|W: User breakglass authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:29.018951+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00005|EV|sessionOpened|N: Opened session 57 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:29.018976+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00006|EV|<LONG>|N: User breakglass on session 57 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:39.133331+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00006|EV|sessionOpened|N: Opened session 58 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:39.133348+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00007|EV|<LONG>|N: User breakglass on session 58 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:39.957150+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2540|3181|00004|EV|<LONG>|W: User breakglass authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:41.160074+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2540|3179|00006|EV|<LONG>|W: User alice12 authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:41.216666+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3174|00003|EV|sessionOpened|N: Opened session 63 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:41.216683+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3174|00004|EV|<LONG>|N: User breakglass on session 63 successfully authenticated from host 172.100.100.1 in network-instance mgmt
```

### (f) port49 stopped: the break-glass login through local and its time; a port49 user refused; whether a CLI command still runs with accounting unreachable, and its time

These break-glass results hold for `exit-on-reject` false, the default; cell (l) repeats them at true.

port49d stopped. `breakglass`: logged in in 56ms. `alice13` (port49 user): refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain) in 44ms. A CLI command in a break-glass session with accounting unreachable ran; login and command took 478ms. The same command as the container's root (`sr_cli`) took 397ms (err <nil>).

The AAA log:

```
2026-10-18T18:54:58.049402+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00000|EV|sessionOpened|N: Opened session 10 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.049422+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00001|EV|<LONG>|N: User breakglass on session 10 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.869720+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00000|EV|sessionOpened|N: Opened session 11 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:54:58.869741+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00001|EV|<LONG>|N: User breakglass on session 11 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:03.610742+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00000|EV|sessionOpened|N: Opened session 18 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:03.610760+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00001|EV|<LONG>|N: User breakglass on session 18 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:05.754301+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00000|EV|sessionOpened|N: Opened session 21 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:05.754320+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00001|EV|<LONG>|N: User breakglass on session 21 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:07.898160+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3176|00000|EV|sessionOpened|N: Opened session 24 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:07.898181+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3176|00001|EV|<LONG>|N: User breakglass on session 24 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.007980+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00004|EV|sessionOpened|N: Opened session 26 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.007998+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00005|EV|<LONG>|N: User breakglass on session 26 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.994702+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00002|EV|sessionOpened|N: Opened session 27 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:10.994724+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00003|EV|<LONG>|N: User breakglass on session 27 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:13.147691+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00002|EV|sessionOpened|N: Opened session 30 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:13.147709+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00003|EV|<LONG>|N: User breakglass on session 30 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:19.813609+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00004|EV|sessionOpened|N: Opened session 43 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:19.813630+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3178|00005|EV|<LONG>|N: User breakglass on session 43 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:25.303999+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00003|EV|sessionOpened|N: Opened session 51 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:25.304018+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00004|EV|<LONG>|N: User breakglass on session 51 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:28.512172+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2540|3174|00002|EV|<LONG>|W: User breakglass authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:29.018951+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00005|EV|sessionOpened|N: Opened session 57 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:29.018976+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3175|00006|EV|<LONG>|N: User breakglass on session 57 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:39.133331+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00006|EV|sessionOpened|N: Opened session 58 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:39.133348+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3177|00007|EV|<LONG>|N: User breakglass on session 58 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:39.957150+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2540|3181|00004|EV|<LONG>|W: User breakglass authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:41.216666+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3174|00003|EV|sessionOpened|N: Opened session 63 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:41.216683+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3174|00004|EV|<LONG>|N: User breakglass on session 63 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.112212+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00002|EV|sessionOpened|N: Opened session 64 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.112231+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3172|00003|EV|<LONG>|N: User breakglass on session 64 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.229958+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00006|EV|sessionOpened|N: Opened session 65 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.229975+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3173|00007|EV|<LONG>|N: User breakglass on session 65 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.270075+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2540|3178|00006|EV|<LONG>|W: User alice13 authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.331061+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3180|00002|EV|sessionOpened|N: Opened session 67 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.331078+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3180|00003|EV|<LONG>|N: User breakglass on session 67 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T18:55:52.692316+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2540|3203|00055|EV|sessionClosed|N: Closed session 67 for user breakglass from host 172.100.100.1 in network-instance mgmt
```

### (g) port49 restarted: the time until the device asks port49 again; the empty connections a quiet minute holds (health checks) and whether port49 logs them

After a restart, the device asked port49 again 1s later (1 break-glass probe(s), each a login followed by up to 5 s waiting for its record, then 5 s apart, under the SSH rate-limit default of 20 unauthenticated sessions, srl_nokia-ssh.yang 479). The next port49 login as `alice14` logged in.

```
redeem permit/token_redeemed method=ascii user=alice14
authorize_session permit/context_matched user=alice14 service=shell request=[service=shell cmd*] reply=[priv-lvl=15 shell:roles*network-admin]
account flags=start user=alice14 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice14 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice14 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice14 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

In a quiet 1m10s with nobody logging in, the device opened 3 connection(s) to port49 and sent 0 packet(s) with a payload; port49 wrote 0 record(s).

### (h) priv-lvl=1 in the reply: the roles the session gets (p49-read only) and the session table's priv-lvl

With port49 replying `priv-lvl=1`, `alice05` logged in with roles [p49-read] and priv-lvl `1` in the session table.

```
redeem permit/token_redeemed method=ascii user=alice05
authorize_session permit/context_matched user=alice05 service=shell request=[service=shell cmd*] reply=[priv-lvl=1]
account flags=start user=alice05 record=[task_id=2 timezone=UTC service=shell priv-lvl=1 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice05 record=[task_id=2 timezone=UTC service=shell priv-lvl=1 cmd=show system aaa authentication «redacted»]
account flags=start user=alice05 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice05 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

This user's rows in the session table, as the device printed them:

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |   Role    |
  <LONG>
  | 28 | alice05*   | srlinux-cli  | port49                | 1        |     | 172.100.100.1 | mgmt             | 2026-10-18T18:55:11.093Z | p49-read  |
```

Accounted commands of this login, in order, from `evidence/L76-nokia_srlinux/decisions.jsonl`:

1. `show system aaa authentication «redacted»`: port `ssh`, priv-lvl 1
2. `info from state system information version`: port `unknown`, priv-lvl 15

The commands after the first are accounted on a different port or at a different priv-lvl than the first, while the reply granted priv-lvl 1. This line is only what the device sent port49; whether that channel runs with more authority is cell (k)'s question.

port49 redacts the word after `authentication` in the accounted `show system aaa authentication` command (the records carry `redacted: true` and the word is shown as `«redacted»`): its accounting redaction treats that word as a credential, so an operator reading SR Linux accounting sees the command without it. Input for the `nokia_srlinux` adapter: whether that rule should be platform-aware.

### (i) priv-lvl-authorization false (the default): whether any authorization request is sent, and the roles the session gets

With `priv-lvl-authorization false`, `alice06` logged in. Authorization requests: 0. Roles in the Role column of this user's rows: [].

```
redeem permit/token_redeemed method=ascii user=alice06
account flags=start user=alice06 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice06 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice06 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice06 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

This user's rows in the session table, as the device printed them:

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |   Role    |
  <LONG>
  | 33 | alice06*   | srlinux-cli  | port49                |          |     | 172.100.100.1 | mgmt             | 2026-10-18T18:55:14.054Z |           |
```

**Operator hazard:** with `priv-lvl-authorization` at its default (false) no authorization request reaches port49, so port49's privilege and role answer is never asked for: every user port49 authenticates gets whatever the device grants without it. The YANG says that is full admin access (srl_nokia-aaa.yang:254); this run measured only reads as that user, so the full-admin claim is YANG-stated and not measured. Plan 12's reference config sets `priv-lvl-authorization true`.

### (j) service-request nokia-srl-authorization-role true: the services the device asks for, port49's answers, and whether the login survives them

With `service-request nokia-srl-authorization-role true`, the login as `alice07` survived. Authorization requests: 2, services map[nokia-srl-authorization-role:1 shell:1]. Roles: [p49-admin p49-read].

```
redeem permit/token_redeemed method=ascii user=alice07
authorize_session deny/service_unsupported user=alice07 service=nokia-srl-authorization-role request=[service=nokia-srl-authorization-role superuser* services-cli* services-ftp* services-gnmi* services-gnoi* services-gnsi* services-gribi* services-grpc-reflection* services-json-rpc* services-netconf* services-p4rt*] reply=[]
authorize_session permit/context_matched user=alice07 service=shell request=[service=shell cmd*] reply=[priv-lvl=15 shell:roles*network-admin]
account flags=start user=alice07 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice07 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice07 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice07 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

This user's rows in the session table, as the device printed them:

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |        Role         |
  <LONG>
  | 39 | alice07*   | srlinux-cli  | port49                | 15       |     | 172.100.100.1 | mgmt             | 2026-10-18T18:55:16.953Z | p49-admin, p49-read |
```

### (k) a priv-lvl 1 user's second exec channel on one SSH login: the session table's Role cell on the first and the second exec, and whether a documented harmless write that p49-read must not be allowed succeeds on either

With port49 replying `priv-lvl=1`, `alice08` ran the session-table read as its first and as its second exec (error: <nil>). The Role cell: first exec [p49-read], second exec [p49-read].

The first exec's rows for this user:

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |   Role    |
  <LONG>
  | 44 | alice08*   | srlinux-cli  | port49                | 1        |     | 172.100.100.1 | mgmt             | 2026-10-18T18:55:19.908Z | p49-read  |
```

The second exec's rows for this user:

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |   Role    |
  <LONG>
  | 45 | alice08*   | srlinux-cli  | port49                | 1        |     | 172.100.100.1 | mgmt             | 2026-10-18T18:55:20.917Z | p49-read  |
```

Accounted commands of this login, in order, from `evidence/L76-nokia_srlinux/decisions.jsonl`:

1. `show system aaa authentication «redacted»`: port `ssh`, priv-lvl 1
2. `show system aaa authentication «redacted»`: port `unknown`, priv-lvl 15

The commands after the first are accounted on a different port or at a different priv-lvl than the first, while the reply granted priv-lvl 1. This line is only what the device sent port49; whether that channel runs with more authority is cell (k)'s question.

port49 redacts the word after `authentication` in the accounted `show system aaa authentication` command (the records carry `redacted: true` and the word is shown as `«redacted»`): its accounting redaction treats that word as a credential, so an operator reading SR Linux accounting sees the command without it. Input for the `nokia_srlinux` adapter: whether that rule should be platform-aware.

A checkpoint is a harmless write that the `p49-read` role (`rule / { action read }`) must not be allowed (CM#configuration-checkpoints). Whether it happened is read from the device's own state, root's clear afterwards; the make's output is evidence only. As the first exec of a priv-lvl 1 login it was refused (root found no checkpoint); as the second exec it was refused (root found no checkpoint).

The write was refused on both channels, so the second exec's priv-lvl 15 accounting is not shown to add authority for a write.

`l76-k-first`: make said "Error: No authorization to execute command: 'tools / system configuration generate-checkpoint name l76-k-first'"; root's clear said "Error in <LONG>[id=l76-k-first]: Checkpoint 'l76-k-first' does not exist Error: Tools command failed".

`l76-k-second`: make said "Could not chdir to home directory /home/alice09: No such file or directory Error: No authorization to execute command: 'tools / system configuration generate-checkpoint name l76-k-second'"; root's clear said "Error in <LONG>[id=l76-k-second]: Checkpoint 'l76-k-second' does not exist Error: Tools command failed".

### (l) exit-on-reject true: whether the break-glass account still logs in through local, and how fast, when port49 denies it, with a wrong shared secret and with port49 stopped

With `exit-on-reject` true (srl_nokia-aaa.yang:1165), a port49 user's token login: logged in.

**A port49 deny of the break-glass account (port49 up).** `breakglass` (local): refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain) in 1.203s.

```
redeem deny/token_not_found method=ascii user=breakglass
```

**A wrong shared secret.** `breakglass` (local): logged in in 57ms.

```
unvalidated diagnosis=no_known_key_matches
```

**port49 stopped.** `breakglass` (local): logged in in 53ms.

**Operator hazard:** with `exit-on-reject` true the break-glass account was locked out when: A port49 deny of the break-glass account (port49 up). That is the configuration plan 12 would ship, so these are what an operator meets at 3am.

The AAA log, per scenario, is in `l1-aaa-log.txt`, `l2-aaa-log.txt` and `l3-aaa-log.txt` under the evidence directory.

### Run

Dials retried after a failure before authentication (one retry each, 5 s later): none

Evidence: `tests/lab/evidence/L76-nokia_srlinux/` (device outputs, masked config, AAA log lines, the redacted decision log).

### Sources

- `show system aaa authentication session`: SA#display-user-session-information <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#display-user-session-information>
- `info from state system information version`: CM#configuration-datastores <https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html#configuration-datastores>; YANG srl_nokia-system-info.yang:108 (leaf version) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `info from running system aaa`: CM#configuration-datastores <https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html#configuration-datastores>
- `info from state system aaa server-group port49`: CM#configuration-datastores <https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html#configuration-datastores>; SA#configuring-aaa-server-group <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-aaa-server-group>
- `set / system aaa server-group port49 tacacs priv-lvl-authorization false`: CLAB#cli (flat form) <https://containerlab.dev/manual/kinds/srl/#cli>; SA#configuring-tacacsx-authorization <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-tacacsx-authorization>
- `set / system aaa server-group port49 tacacs priv-lvl-authorization true`: CLAB#cli (flat form) <https://containerlab.dev/manual/kinds/srl/#cli>; SA#configuring-tacacsx-authorization <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-tacacsx-authorization>
- `set / system aaa server-group port49 tacacs service-request nokia-srl-authorization-role true`: CLAB#cli (flat form) <https://containerlab.dev/manual/kinds/srl/#cli>; SA#configuring-tacacs-authorization-with-vsas <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-tacacs-authorization-with-vsas>
- `set / system aaa server-group port49 tacacs service-request nokia-srl-authorization-role false`: CLAB#cli (flat form) <https://containerlab.dev/manual/kinds/srl/#cli>; SA#configuring-tacacs-authorization-with-vsas <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-tacacs-authorization-with-vsas>
- `set / system aaa authentication exit-on-reject true`: CLAB#cli (flat form) <https://containerlab.dev/manual/kinds/srl/#cli>; YANG srl_nokia-aaa.yang:1165 (leaf exit-on-reject, in system aaa authentication) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `set / system aaa authentication exit-on-reject false`: CLAB#cli (flat form) <https://containerlab.dev/manual/kinds/srl/#cli>; YANG srl_nokia-aaa.yang:1165 (leaf exit-on-reject, in system aaa authentication) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `tools system configuration generate-checkpoint name <name>`: CM#configuration-checkpoints (Generating a checkpoint) <https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html#configuration-checkpoints>; YANG srl_nokia-tools-configuration.yang:150 (container generate-checkpoint, leaf name) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `tools system configuration checkpoint <name> clear`: CM#configuration-checkpoints (Clearing a checkpoint) <https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html#configuration-checkpoints>; YANG srl_nokia-tools-configuration.yang:120 (list checkpoint, key id, leaf clear) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `sr_cli -d <command>`: HELP (-d/--dumb-terminal, with a positional command run as one line) <sr_cli --help in ghcr.io/nokia/srlinux:26.7.2-519>
- `sr_cli --help`: HELP <sr_cli --help in ghcr.io/nokia/srlinux:26.7.2-519>
- `cat "$(find /opt/srlinux/models -name <model> | head -1)"`: YANG srl_nokia-aaa.yang </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>; YANG srl_nokia-aaa-types.yang (the image's own models) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `sr_cli -d --candidate-mode --commit-at-end -- <line>`: HELP (example: sr_cli --candidate-mode --commit-at-end -- <command>) <sr_cli --help in ghcr.io/nokia/srlinux:26.7.2-519>
- `enter candidate`: CM#configuration-modes <https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html#configuration-modes>
- `commit now`: CM#commit-configuration-in-candidate-mode <https://documentation.nokia.com/srlinux/26-7/books/config-basics/configuration-management.html#commit-configuration-in-candidate-mode>
- `tail -n 400 /var/log/srlinux/debug/sr_aaa_mgr.log`: SA#configuring-local-accounting <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-local-accounting>
- `authentication-method [ port49 local ]`: SA#configuring-authentication-local-users <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-authentication-local-users>
- `user breakglass { password ...; role [ p49-admin ] }`: SA#configuring-authentication-local-users <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-authentication-local-users>; SA#assign-roles-to-users <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#assign-roles-to-users>
- `authorization { role <n> { services [ cli ]; tacacs { priv-lvl <n> } } }`: SA#configuring-tacacsx-authorization <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-tacacsx-authorization>; SA#configuring-service-authorization <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-service-authorization>; SA#service-authorization-local-users <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#service-authorization-local-users>; YANG srl_nokia-aaa.yang:763 (leaf-list services, no default) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `accounting { accounting-method [ port49 ]; event command { record start-stop } }`: SA#configuring-account <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-account>; YANG srl_nokia-aaa-types.yang:77 (identity command, base aaa_accounting_event_type) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `server-group local { type local }`: SA#configuring-authentication-local-users <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-authentication-local-users>; YANG srl_nokia-aaa.yang:134 (the name must be local) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `server-group port49 { type tacacs; tacacs { priv-lvl-authorization true } }`: SA#configuring-aaa-server-group <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-aaa-server-group>; SA#configuring-tacacsx-authorization <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-tacacsx-authorization>
- `server 172.100.100.1 { network-instance mgmt; tacacs { port 49; secret-key ... } }`: SA#configuring-aaa-server-group <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-aaa-server-group>; YANG srl_nokia-aaa-tacacs.yang (port, default 49) </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `configuration { role <n> { rule / { action read|write } } }`: SA#configuring-role <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#configuring-role>
- `exit-on-reject: default false`: YANG srl_nokia-aaa.yang:1165 </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `priv-lvl-authorization false: authorization skipped, full admin`: YANG srl_nokia-aaa.yang:254 </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>
- `the TACACS+ health check: a TCP open and close every 30 s`: SA#aaa-server-group-configuration <https://documentation.nokia.com/srlinux/26-7/books/config-basics/secur-access.html#aaa-server-group-configuration>
- `ssh-server rate-limit: default 20 unauthenticated sessions`: YANG srl_nokia-ssh.yang:479 </opt/srlinux/models in ghcr.io/nokia/srlinux:26.7.2-519>

