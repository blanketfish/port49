# L76 — nokia_srlinux

- **Date measured:** 2026-10-18
- **Platform:** nokia_srlinux (containerlab node `srl1`, 172.100.100.71)
- **Image version:** SR Linux 26.7.2-519 (`ghcr.io/nokia/srlinux:26.7.2-519`)
- **Topology:** `tests/lab/topologies/srlinux.clab.yml`
- **Capture:** `tests/lab/evidence/L76-nokia_srlinux.pcap` — 1832 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L76-nokia_srlinux.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `44ad30639daf21936133716baff3deddcb045d2f`, `PORT49_LAB_PLATFORMS=srlinux`, `-run ^TestL76$`

## Claim

Nokia SR Linux against port49 over TACACS+ on port 49, server group `port49` then `local`, accounting to `port49`: (a) a user that exists only in port49 logs in over SSH; the session table names it, the port49 group and the priv-lvl; the authentication type on the wire; (b) the authorization requests the login sends with priv-lvl-authorization true: services and attributes; whether any per-command request follows; what the device does with priv-lvl=15 and the optional shell:roles; (c) the accounting records a CLI command sends: start and stop, their attributes; whether a session start or stop is sent; (d) a wrong password: port49's refusal, the time to the device's refusal, and whether a port49 deny falls through to local; (e) a wrong shared secret: port49's no_known_key_matches, and whether the break-glass account still logs in through local, and how fast; (f) port49 stopped: the break-glass login through local and its time; a port49 user refused; whether a CLI command still runs with accounting unreachable, and its time; (g) port49 restarted: the time until the device asks port49 again; the empty connections a quiet minute holds (health checks) and whether port49 logs them; (h) priv-lvl=1 in the reply: the roles the session gets (p49-read only) and the session table's priv-lvl; (i) priv-lvl-authorization false (the default): whether any authorization request is sent, and the roles the session gets; (j) service-request nokia-srl-authorization-role true: the services the device asks for, port49's answers, and whether the login survives them.

## Observation

### Schema and configuration

Version: `version <LONG>`.

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
    oper-state down
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

`alice01` (a user with no local account) logged in over SSH in 1.269s. port49's redeem: permit/token_redeemed, auth.method `ascii`. The session table's row: id 18, service `srlinux-cli`, method `port49`, priv-lvl `15`, tty ``.

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |        Role         |
  <LONG>
  | 12 | breakglass | sshd         | local                 |          | ssh | 172.100.100.1 | mgmt             | 2026-10-18T17:26:06.120Z | p49-admin           |
  | 13 | breakglass | sshd         | local                 |          | ssh | 172.100.100.1 | mgmt             | 2026-10-18T17:26:06.443Z | p49-admin           |
  | 18 | alice01*   | srlinux-cli  | port49                | 15       |     | 172.100.100.1 | mgmt             | 2026-10-18T17:26:10.091Z | p49-admin, p49-read |
  <LONG>

```

Records:

```
redeem permit/token_redeemed method=ascii user=alice01
authorize_session permit/context_matched user=alice01 service=shell request=[service=shell cmd*] reply=[priv-lvl=15]
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

1 authorization request(s) for `alice01`: 1 `authorize_session`, 0 `authorize_command` (per-command). Services: map[shell:1]. port49's reply attributes (from its record): [priv-lvl=15]. The session's roles (the Role column of this user's rows in `show system aaa authentication session`): [p49-admin p49-read]; priv-lvl in the table: `15`. `network-admin` does not appear in this user's rows.

```
authorize_session permit/context_matched user=alice01 service=shell request=[service=shell cmd*] reply=[priv-lvl=15]
```

This user's rows in the session table, as the device printed them:

```
  <LONG>
  | ID | User name  | Service name | Authentication method | Priv-lvl | TTY |  Remote host  | Network instance |        Login time        |        Role         |
  <LONG>
  | 18 | alice01*   | srlinux-cli  | port49                | 15       |     | 172.100.100.1 | mgmt             | 2026-10-18T17:26:10.091Z | p49-admin, p49-read |
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

### (d) a wrong password: port49's refusal, the time to the device's refusal, and whether a port49 deny falls through to local

A wrong password for `alice04` was refused in 852ms. port49's records:

```
redeem deny/device_mismatch method=ascii user=alice04
redeem deny/token_not_found method=ascii user=breakglass
```

With port49 up, `breakglass` (local only; port49 denies it, having no token for it) logged in in 2.079s. So a port49 deny **falls** through to `local` with `exit-on-reject` at its default.

**Operator hazard:** with `exit-on-reject` at its default, a person whom port49 denies still gets in if the device has a local account for them. port49's deny is not final on this platform. Plan 12's reference config sets `exit-on-reject` (Ruling 1).

The AAA log's lines for both users:

```
2026-10-18T17:26:06.136592+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00000|EV|sessionOpened|N: Opened session 12 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.136611+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00001|EV|<LONG>|N: User breakglass on session 12 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.966785+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00000|EV|sessionOpened|N: Opened session 13 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.966809+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00001|EV|<LONG>|N: User breakglass on session 13 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:12.141481+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00000|EV|sessionOpened|N: Opened session 20 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:12.141502+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00001|EV|<LONG>|N: User breakglass on session 20 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:14.713630+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00000|EV|sessionOpened|N: Opened session 23 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:14.713651+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00001|EV|<LONG>|N: User breakglass on session 23 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:17.282880+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3177|00000|EV|sessionOpened|N: Opened session 26 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:17.282897+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3177|00001|EV|<LONG>|N: User breakglass on session 26 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:18.322475+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2536|3175|00000|EV|<LONG>|W: User alice04 authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:19.696051+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00004|EV|sessionOpened|N: Opened session 28 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:19.696069+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00005|EV|<LONG>|N: User breakglass on session 28 successfully authenticated from host 172.100.100.1 in network-instance mgmt
```

### (e) a wrong shared secret: port49's no_known_key_matches, and whether the break-glass account still logs in through local, and how fast

port49d on a key the device does not have. `alice08` (port49 user): refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain) in 43ms. `breakglass` (local): logged in in 67ms. port49's diagnoses: map[no_known_key_matches:1] (1 unvalidated record(s), 0 redeem(s)).

```
unvalidated diagnosis=no_known_key_matches
```

The AAA log:

```
2026-10-18T17:26:06.136592+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00000|EV|sessionOpened|N: Opened session 12 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.136611+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00001|EV|<LONG>|N: User breakglass on session 12 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.966785+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00000|EV|sessionOpened|N: Opened session 13 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.966809+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00001|EV|<LONG>|N: User breakglass on session 13 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:12.141481+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00000|EV|sessionOpened|N: Opened session 20 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:12.141502+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00001|EV|<LONG>|N: User breakglass on session 20 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:14.713630+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00000|EV|sessionOpened|N: Opened session 23 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:14.713651+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00001|EV|<LONG>|N: User breakglass on session 23 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:17.282880+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3177|00000|EV|sessionOpened|N: Opened session 26 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:17.282897+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3177|00001|EV|<LONG>|N: User breakglass on session 26 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:19.696051+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00004|EV|sessionOpened|N: Opened session 28 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:19.696069+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00005|EV|<LONG>|N: User breakglass on session 28 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:21.560979+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00002|EV|sessionOpened|N: Opened session 29 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:21.560997+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00003|EV|<LONG>|N: User breakglass on session 29 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:24.136630+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00002|EV|sessionOpened|N: Opened session 32 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:24.136649+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00003|EV|<LONG>|N: User breakglass on session 32 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:30.689457+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2536|3183|00004|EV|<LONG>|W: User alice08 authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:30.744285+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3167|00000|EV|sessionOpened|N: Opened session 46 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:30.744304+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3167|00001|EV|<LONG>|N: User breakglass on session 46 successfully authenticated from host 172.100.100.1 in network-instance mgmt
```

### (f) port49 stopped: the break-glass login through local and its time; a port49 user refused; whether a CLI command still runs with accounting unreachable, and its time

port49d stopped. `breakglass`: logged in in 68ms. `alice09` (port49 user): refused (ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain) in 42ms. A CLI command in a break-glass session with accounting unreachable ran; login and command took 473ms. The same command as the container's root (`sr_cli`) took 394ms (err <nil>).

The AAA log:

```
2026-10-18T17:26:06.136592+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00000|EV|sessionOpened|N: Opened session 12 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.136611+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00001|EV|<LONG>|N: User breakglass on session 12 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.966785+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00000|EV|sessionOpened|N: Opened session 13 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:06.966809+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00001|EV|<LONG>|N: User breakglass on session 13 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:12.141481+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00000|EV|sessionOpened|N: Opened session 20 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:12.141502+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00001|EV|<LONG>|N: User breakglass on session 20 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:14.713630+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00000|EV|sessionOpened|N: Opened session 23 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:14.713651+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00001|EV|<LONG>|N: User breakglass on session 23 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:17.282880+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3177|00000|EV|sessionOpened|N: Opened session 26 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:17.282897+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3177|00001|EV|<LONG>|N: User breakglass on session 26 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:19.696051+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00004|EV|sessionOpened|N: Opened session 28 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:19.696069+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00005|EV|<LONG>|N: User breakglass on session 28 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:21.560979+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00002|EV|sessionOpened|N: Opened session 29 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:21.560997+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3181|00003|EV|<LONG>|N: User breakglass on session 29 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:24.136630+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00002|EV|sessionOpened|N: Opened session 32 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:24.136649+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3173|00003|EV|<LONG>|N: User breakglass on session 32 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:30.744285+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3167|00000|EV|sessionOpened|N: Opened session 46 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:30.744304+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3167|00001|EV|<LONG>|N: User breakglass on session 46 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:41.637537+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00004|EV|sessionOpened|N: Opened session 47 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:41.637556+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3165|00005|EV|<LONG>|N: User breakglass on session 47 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:42.188942+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00006|EV|sessionOpened|N: Opened session 48 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:42.188960+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3179|00007|EV|<LONG>|N: User breakglass on session 48 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:42.242426+00:00 srl1 local6|WARN sr_aaa_mgr: aaa|2536|3181|00004|EV|<LONG>|W: User alice09 authentication failed from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:42.296199+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3169|00000|EV|sessionOpened|N: Opened session 50 for user breakglass from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:42.296229+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3169|00001|EV|<LONG>|N: User breakglass on session 50 successfully authenticated from host 172.100.100.1 in network-instance mgmt
2026-10-18T17:26:42.661750+00:00 srl1 local6|NOTI sr_aaa_mgr: aaa|2536|3186|00045|EV|sessionClosed|N: Closed session 50 for user breakglass from host 172.100.100.1 in network-instance mgmt
```

### (g) port49 restarted: the time until the device asks port49 again; the empty connections a quiet minute holds (health checks) and whether port49 logs them

After a restart, the device asked port49 again 1s later (1 break-glass probe(s), each a login followed by up to 5 s waiting for its record, then 5 s apart, under the SSH rate-limit default of 20 unauthenticated sessions, srl_nokia-ssh.yang 479). The next port49 login as `alice10` logged in.

```
redeem permit/token_redeemed method=ascii user=alice10
authorize_session permit/context_matched user=alice10 service=shell request=[service=shell cmd*] reply=[priv-lvl=15]
account flags=start user=alice10 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=stop user=alice10 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=show system aaa authentication «redacted»]
account flags=start user=alice10 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
account flags=stop user=alice10 record=[task_id=2 timezone=UTC service=shell priv-lvl=15 cmd=info from state system information version]
```

In a quiet 1m10s with nobody logging in, the device opened 2 connection(s) to port49 and sent 0 packet(s) with a payload; port49 wrote 0 record(s).

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
  | 30 | alice05*   | srlinux-cli  | port49                | 1        |     | 172.100.100.1 | mgmt             | 2026-10-18T17:26:22.094Z | p49-read  |
```

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
  | 35 | alice06*   | srlinux-cli  | port49                |          |     | 172.100.100.1 | mgmt             | 2026-10-18T17:26:25.485Z |           |
```

### (j) service-request nokia-srl-authorization-role true: the services the device asks for, port49's answers, and whether the login survives them

With `service-request nokia-srl-authorization-role true`, the login as `alice07` survived. Authorization requests: 2, services map[nokia-srl-authorization-role:1 shell:1]. Roles: [p49-admin p49-read].

```
redeem permit/token_redeemed method=ascii user=alice07
authorize_session deny/service_unsupported user=alice07 service=nokia-srl-authorization-role request=[service=nokia-srl-authorization-role superuser* services-cli* services-ftp* services-gnmi* services-gnoi* services-gnsi* services-gribi* services-grpc-reflection* services-json-rpc* services-netconf* services-p4rt*] reply=[]
authorize_session permit/context_matched user=alice07 service=shell request=[service=shell cmd*] reply=[priv-lvl=15]
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
  | 41 | alice07*   | srlinux-cli  | port49                | 15       |     | 172.100.100.1 | mgmt             | 2026-10-18T17:26:28.350Z | p49-admin, p49-read |
```

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

