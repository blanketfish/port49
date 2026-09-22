# L15-clients — arista_eos

- **Date measured:** 2026-09-21
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/clients-arista_eos.pcap` — 8464 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/clients-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

How many TACACS+ authentication exchanges a ten-task job costs for each client an operator actually runs — pyeapi, NAPALM, Ansible over `httpapi` and `network_cli`, Nornir with ten worker threads — whether a single-use token survives the job, and what that implies the client put on the wire. Also, for Nornir: what port49 logs when ten concurrent logins share one `(nas, username)` login context, and whether any session is refused.

## Observation

Each client below runs a **ten-task job** against one device as one seeded user, with one single-use token. The counts come from port49's decision log, not from the client.

**`receipt_ttl` below is the knob that was configured when this ran, and it no longer exists.** The receipt became a sliding window on 2026-09-22: `receipt_idle_ttl` (default 15m) slides forward on every presentation the receipt answers, `receipt_max_age` (default 2h) caps it from the first redemption and never slides, and `receipt_ttl` is now refused by name at config load (spec §13, decision 15). The measured counts and durations are unaffected — every job here finished far inside the 30s bound in force at the time — so the per-job sentences are left as they were measured.

**What the client put on the wire is INFERRED, not measured.** The capture filter is `tcp port 49`, so the HTTPS and SSH bytes are not in evidence here. One authentication for ten tasks means the credential reached the device once — a cookie, a session, or one persistent connection; ten means it reached it ten times. That inference is from the authentication count and is labelled as an inference in every row.

### pyeapi (eAPI over HTTPS)

Arista's own Python client. It builds one `requests`-style connection and reuses it, which is the shape `transport_test.go` deliberately does not drive.

Ten tasks in 391ms; the client exited 0. **10 task(s) succeeded and 0 failed**, counted from the client's own output — the exit status is not the measurement, because a script that catches its exceptions exits 0 with half its tasks refused.

port49's own counts for the window:

```
redeem records        10  (token_redeemed 1, receipt_replayed 9, denied 0)
authorize_session     10
authorize_command     20
distinct ctx_id       1
```

No call in this job was refused, so it did not reach the receipt boundary. The job took 391ms against a `receipt_ttl` of 30s.

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: 10 authentications for ten tasks: the credential reached the device **on every task**. That is Basic (or a password prompt) presented per call, on a connection that is not being reused for AAA purposes.

What the client printed:

```
task 0 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 1 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 2 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 3 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 4 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 5 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 6 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 7 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 8 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
task 9 ok [{'command': 'show hostname', 'result': {'hostname': 'leaf1', 'fqdn': 'leaf1'}, 
```


### NAPALM eos (eAPI)

NAPALM's `eos` driver, which sits on pyeapi. One `open()` then ten getters.

Ten tasks in 819ms; the client exited 0. **10 task(s) succeeded and 0 failed**, counted from the client's own output — the exit status is not the measurement, because a script that catches its exceptions exits 0 with half its tasks refused.

port49's own counts for the window:

```
redeem records        11  (token_redeemed 1, receipt_replayed 10, denied 0)
authorize_session     11
authorize_command     42
distinct ctx_id       1
```

No call in this job was refused, so it did not reach the receipt boundary. The job took 819ms against a `receipt_ttl` of 30s.

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: 11 authentications for ten tasks: the credential reached the device **on every task**. That is Basic (or a password prompt) presented per call, on a connection that is not being reused for AAA purposes.

What the client printed:

```
task 0 ok leaf1
task 1 ok leaf1
task 2 ok leaf1
task 3 ok leaf1
task 4 ok leaf1
task 5 ok leaf1
task 6 ok leaf1
task 7 ok leaf1
task 8 ok leaf1
task 9 ok leaf1
```


### netmiko arista_eos (one persistent SSH)

One SSH session held open for all ten commands — the shape an interactive operator has, and the one Nornir's netmiko plugin uses.

Ten tasks in 3.428s; the client exited 0. **10 task(s) succeeded and 0 failed**, counted from the client's own output — the exit status is not the measurement, because a script that catches its exceptions exits 0 with half its tasks refused.

port49's own counts for the window:

```
redeem records        1  (token_redeemed 1, receipt_replayed 0, denied 0)
authorize_session     1
authorize_command     12
distinct ctx_id       1
```

No call in this job was refused, so it did not reach the receipt boundary. The job took 3.428s against a `receipt_ttl` of 30s.

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: one authentication for ten tasks: the credential reached the device **once**. That is a cookie, an API session, or a single persistent connection carrying all ten.

What the client printed:

```
task 0 ok Hostname: leaf1
FQDN:     leaf1
task 1 ok Hostname: leaf1
FQDN:     leaf1
task 2 ok Hostname: leaf1
FQDN:     leaf1
task 3 ok Hostname: leaf1
FQDN:     leaf1
task 4 ok Hostname: leaf1
FQDN:     leaf1
task 5 ok Hostname: leaf1
FQDN:     leaf1
task 6 ok Hostname: leaf1
FQDN:     leaf1
task 7 ok Hostname: leaf1
FQDN:     leaf1
task 8 ok Hostname: leaf1
FQDN:     leaf1
task 9 ok Hostname: leaf1
FQDN:     leaf1
```


### Nornir + netmiko, 10 workers, one device, one user

Ten worker threads opening ten sessions to one device as one user **at the same time**. This is the `(nas, username)` login-context key under its accepted worst case: ten concurrent logins sharing one context (spec §13, decision 15). What port49 logs, and whether any session is refused, is the finding.

The inventory holds ten host entries that all point at the same device, and the job is ONE `nr.run` over them. The first version ran ten sequential `nr.run` calls against one host, and netmiko served them all from a single reused connection: one authentication, one ctx_id, 3.6 seconds and **no concurrency whatsoever**. It measured the opposite of what it claimed, and the count it produced looked perfectly reasonable, which is why it is called out here.

Ten tasks in 1.84s; the client exited 0. **10 task(s) succeeded and 0 failed**, counted from the client's own output — the exit status is not the measurement, because a script that catches its exceptions exits 0 with half its tasks refused.

port49's own counts for the window:

```
redeem records        10  (token_redeemed 1, receipt_replayed 9, denied 0)
authorize_session     10
authorize_command     30
distinct ctx_id       1
```

No call in this job was refused, so it did not reach the receipt boundary. The job took 1.84s against a `receipt_ttl` of 30s.

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: 10 authentications for ten tasks: the credential reached the device **on every task**. That is Basic (or a password prompt) presented per call, on a connection that is not being reused for AAA purposes.

What the client printed:

```
'/tmp/tmp6p9wh168/groups.yaml' is empty or contains only comments, defaulting to empty groups inventory.
task 0 leaf1-00 ok Hostname: leaf1
FQDN:     leaf1
task 1 leaf1-01 ok Hostname: leaf1
FQDN:     leaf1
task 2 leaf1-02 ok Hostname: leaf1
FQDN:     leaf1
task 3 leaf1-03 ok Hostname: leaf1
FQDN:     leaf1
task 4 leaf1-04 ok Hostname: leaf1
FQDN:     leaf1
task 5 leaf1-05 ok Hostname: leaf1
FQDN:     leaf1
task 6 leaf1-06 ok Hostname: leaf1
FQDN:     leaf1
task 7 leaf1-07 ok Hostname: leaf1
FQDN:     leaf1
task 8 leaf1-08 ok Hostname: leaf1
FQDN:     leaf1
task 9 leaf1-09 ok Hostname: leaf1
FQDN:     leaf1
```


### Ansible arista.eos over httpapi

`ansible.netcommon.httpapi` against eAPI, ten tasks in one play.

Ten tasks in 4.028s; the client exited 0. **10 task(s) succeeded and 0 failed**, counted from the client's own output — the exit status is not the measurement, because a script that catches its exceptions exits 0 with half its tasks refused.

port49's own counts for the window:

```
redeem records        13  (token_redeemed 1, receipt_replayed 12, denied 0)
authorize_session     13
authorize_command     13
distinct ctx_id       1
```

No call in this job was refused, so it did not reach the receipt boundary. The job took 4.028s against a `receipt_ttl` of 30s.

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: 13 authentications for ten tasks: the credential reached the device **on every task**. That is Basic (or a password prompt) presented per call, on a connection that is not being reused for AAA purposes.

What the client printed:

```

PLAY [all] *********************************************************************

TASK [task 0] ******************************************************************
ok: [leaf1]

TASK [task 1] ******************************************************************
ok: [leaf1]

TASK [task 2] ******************************************************************
ok: [leaf1]

TASK [task 3] ******************************************************************
ok: [leaf1]

TASK [task 4] ******************************************************************
ok: [leaf1]

TASK [task 5] ******************************************************************
ok: [leaf1]

TASK [task 6] ******************************************************************
ok: [leaf1]

TASK [task 7] ******************************************************************
ok: [leaf1]

TASK [task 8] ******************************************************************
ok: [leaf1]

TASK [task 9] ******************************************************************
ok: [leaf1]

PLAY RECAP *********************************************************************
leaf1                      : ok=10   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   
```


### Ansible arista.eos over network_cli

The same ten tasks over `ansible.netcommon.network_cli`, which holds one persistent SSH connection through a control-socket process.

Ten tasks in 774ms; **the client exited non-zero**. **0 task(s) succeeded and 1 failed**, counted from the client's own output — the exit status is not the measurement, because a script that catches its exceptions exits 0 with half its tasks refused.

port49's own counts for the window:

```
redeem records        0  (token_redeemed 0, receipt_replayed 0, denied 0)
authorize_session     0
authorize_command     0
distinct ctx_id       0
```

No call in this job was refused, so it did not reach the receipt boundary. The job took 774ms against a `receipt_ttl` of 30s.

**Inferred** from the authentication count, not measured — the capture holds no HTTPS or SSH bytes: no authentication reached port49 at all across ten tasks, so either the client never connected or it reached the device by a path that does not consult TACACS+ (a key-based SSH session, a cached session, or a failure before the first connection).

What the client printed:

```

PLAY [all] *********************************************************************

TASK [task 0] ******************************************************************
[ERROR]: Task failed: host key mismatch for 172.100.100.11
Origin: /tmp/tmpifcivepv/play.yml:4:7

2   gather_facts: false
3   tasks:
4     - name: task 0
        ^ column 7

fatal: [leaf1]: FAILED! => {"changed": false, "msg": "Task failed: host key mismatch for 172.100.100.11"}

PLAY RECAP *********************************************************************
leaf1                      : ok=0    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0   


[WARNING]: ansible-pylibssh not installed, falling back to paramiko



exit status 2
```


## Every client side by side

| client | tasks ok | TACACS+ authentications per 10 tasks | fresh / replayed / denied | single-use token survived the job | wire, inferred |
|---|---|---|---|---|---|
| pyeapi (eAPI over HTTPS) | 10/10 | **10** | 1 / 9 / 0 | **yes** | per task |
| NAPALM eos (eAPI) | 10/10 | **11** | 1 / 10 / 0 | **yes** | per task |
| netmiko arista_eos (one persistent SSH) | 10/10 | **1** | 1 / 0 / 0 | **yes** | once |
| Nornir + netmiko, 10 workers, one device, one user | 10/10 | **10** | 1 / 9 / 0 | **yes** | per task |
| Ansible arista.eos over httpapi | 10/10 | **13** | 1 / 12 / 0 | **yes** | per task |
| Ansible arista.eos over network_cli | 0/1 | **0** | 0 / 0 / 0 | **no** — 1 task(s) failed | never reached port49 |

