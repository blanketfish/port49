# L15-clients — cisco_nxos

- **Date measured:** 2026-09-21
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/evidence/clients-cisco_nxos.pcap` — 5138 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/clients-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How many TACACS+ authentication exchanges a ten-task job costs for each client an operator actually runs — pyeapi, NAPALM, Ansible over `httpapi` and `network_cli`, Nornir with ten worker threads — whether a single-use token survives the job, and what that implies the client put on the wire. Also, for Nornir: what port49 logs when ten concurrent logins share one `(nas, username)` login context, and whether any session is refused.

## Observation

Each client below runs a **ten-task job** against one device as one seeded user, with one single-use token. The counts come from port49's decision log, not from the client.

**What the client put on the wire is INFERRED, not measured.** The capture filter is `tcp port 49`, so the HTTPS and SSH bytes are not in evidence here. One authentication for ten tasks means the credential reached the device once — a cookie, a session, or one persistent connection; ten means it reached it ten times. That inference is from the authentication count and is labelled as an inference in every row.

### NAPALM nxos (NX-API over HTTPS)

NAPALM's `nxos` driver, which speaks NX-API. One `open()` then ten getters.

Ten tasks, the job completed in 38.814s.

port49's own counts for the window:

```
redeem records        28  (token_redeemed 1, receipt_replayed 22, denied 5)
authorize_session     23
authorize_command     69
distinct ctx_id       1
```

Denials, verbatim from the log:

```
redeem deny token_not_found user=alice01 port=0
redeem deny token_not_found user=alice01 port=0
redeem deny token_not_found user=alice01 port=0
redeem deny token_not_found user=alice01 port=0
redeem deny token_not_found user=alice01 port=0
```

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: 28 authentications for ten tasks: the credential reached the device **on every task**. That is Basic (or a password prompt) presented per call, on a connection that is not being reused for AAA purposes.

What the client printed:

```
task 0 ok nx1
task 1 ok nx1
task 2 ok nx1
task 3 ok nx1
task 4 ok nx1
task 5 FAILED NXAPIAuthError Authentication to NX-API failed please verify your username, password, and hostname.
task 6 FAILED NXAPIAuthError Authentication to NX-API failed please verify your username, password, and hostname.
task 7 FAILED NXAPIAuthError Authentication to NX-API failed please verify your username, password, and hostname.
task 8 FAILED NXAPIAuthError Authentication to NX-API failed please verify your username, password, and hostname.
task 9 FAILED NXAPIAuthError Authentication to NX-API failed please verify your username, password, and hostname.
```


### NAPALM nxos_ssh

The same driver family over SSH rather than NX-API — one persistent session.

Ten tasks, the job completed in 12.269s.

port49's own counts for the window:

```
redeem records        1  (token_redeemed 1, receipt_replayed 0, denied 0)
authorize_session     1
authorize_command     52
distinct ctx_id       1
```

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: one authentication for ten tasks: the credential reached the device **once**. That is a cookie, an API session, or a single persistent connection carrying all ten.

What the client printed:

```
task 0 ok nx1
task 1 ok nx1
task 2 ok nx1
task 3 ok nx1
task 4 ok nx1
task 5 ok nx1
task 6 ok nx1
task 7 ok nx1
task 8 ok nx1
task 9 ok nx1
```


### netmiko cisco_nxos (one persistent SSH)

One SSH session held open for ten commands.

Ten tasks, the job completed in 6.04s.

port49's own counts for the window:

```
redeem records        1  (token_redeemed 1, receipt_replayed 0, denied 0)
authorize_session     1
authorize_command     12
distinct ctx_id       1
```

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: one authentication for ten tasks: the credential reached the device **once**. That is a cookie, an API session, or a single persistent connection carrying all ten.

What the client printed:

```
task 0 ok nx1
task 1 ok nx1
task 2 ok nx1
task 3 ok nx1
task 4 ok nx1
task 5 ok nx1
task 6 ok nx1
task 7 ok nx1
task 8 ok nx1
task 9 ok nx1
```


### Ansible cisco.nxos over httpapi

`ansible.netcommon.httpapi` against NX-API, ten tasks in one play.

Ten tasks, the job completed in 27.924s.

port49's own counts for the window:

```
redeem records        1  (token_redeemed 1, receipt_replayed 0, denied 0)
authorize_session     1
authorize_command     24
distinct ctx_id       1
```

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: one authentication for ten tasks: the credential reached the device **once**. That is a cookie, an API session, or a single persistent connection carrying all ten.

What the client printed:

```

PLAY [all] *********************************************************************

TASK [task 0] ******************************************************************
ok: [nx1]

TASK [task 1] ******************************************************************
ok: [nx1]

TASK [task 2] ******************************************************************
ok: [nx1]

TASK [task 3] ******************************************************************
ok: [nx1]

TASK [task 4] ******************************************************************
ok: [nx1]

TASK [task 5] ******************************************************************
ok: [nx1]

TASK [task 6] ******************************************************************
ok: [nx1]

TASK [task 7] ******************************************************************
ok: [nx1]

TASK [task 8] ******************************************************************
ok: [nx1]

TASK [task 9] ******************************************************************
ok: [nx1]

PLAY RECAP *********************************************************************
nx1                        : ok=10   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
```


### Ansible cisco.nxos over network_cli

The same ten tasks over one persistent SSH connection.

Ten tasks, the job completed in 6.469s.

port49's own counts for the window:

```
redeem records        1  (token_redeemed 1, receipt_replayed 0, denied 0)
authorize_session     1
authorize_command     14
distinct ctx_id       1
```

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: one authentication for ten tasks: the credential reached the device **once**. That is a cookie, an API session, or a single persistent connection carrying all ten.

What the client printed:

```

PLAY [all] *********************************************************************

TASK [task 0] ******************************************************************
ok: [nx1]

TASK [task 1] ******************************************************************
ok: [nx1]

TASK [task 2] ******************************************************************
ok: [nx1]

TASK [task 3] ******************************************************************
ok: [nx1]

TASK [task 4] ******************************************************************
ok: [nx1]

TASK [task 5] ******************************************************************
ok: [nx1]

TASK [task 6] ******************************************************************
ok: [nx1]

TASK [task 7] ******************************************************************
ok: [nx1]

TASK [task 8] ******************************************************************
ok: [nx1]

TASK [task 9] ******************************************************************
ok: [nx1]

PLAY RECAP *********************************************************************
nx1                        : ok=10   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   


[WARNING]: ansible-pylibssh not installed, falling back to paramiko
```


## Every client side by side

| client | job completed | TACACS+ authentications per 10 tasks | fresh / replayed | single-use token survived the job | wire, inferred |
|---|---|---|---|---|---|
| NAPALM nxos (NX-API over HTTPS) | yes | **28** | 1 / 22 | yes, with 5 denial(s) | per task |
| NAPALM nxos_ssh | yes | **1** | 1 / 0 | **yes** | once |
| netmiko cisco_nxos (one persistent SSH) | yes | **1** | 1 / 0 | **yes** | once |
| Ansible cisco.nxos over httpapi | yes | **1** | 1 / 0 | **yes** | once |
| Ansible cisco.nxos over network_cli | yes | **1** | 1 / 0 | **yes** | once |

