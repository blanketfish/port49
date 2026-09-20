# L1 — cisco_nxos

- **Date measured:** 2026-09-20
- **Platform:** cisco_nxos (containerlab node `nx1`, 172.100.100.31)
- **Image version:** Nexus 9300v 10.4(2)F (`vrnetlab/cisco_n9kv:9300v64-10.4.2.F`)
- **Topology:** `tests/lab/topologies/nxos.clab.yml`
- **Capture:** `tests/lab/captures/L1-cisco_nxos.pcap` — 160 packets to or from the device, countable with `tcpdump -r tests/lab/captures/L1-cisco_nxos.pcap -n 'net 172.100.100.0/24' | wc -l`
- **Transport:** SSH

## Claim

What the `port` field contains, per platform and per transport — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session, stable for its life, and **the same value at authentication and at authorization time**.

## Observation

Two overlapping SSH sessions, each holding an interactive shell open, produced these `port` values on the authentication START:

| session | user | `port` |
|---|---|---|
| 1 | alice04 | `0` |
| 2 | alice05 | `0` |

**The two concurrent sessions reported the SAME `port` value**, so `port` does not tell two simultaneous operators apart on this platform. That is now a fact about the device rather than a fact about port49: since 2026-09-20 the login context is keyed `(nas, username)` and the receipt `(nas, username, credential_sha256)`, so neither collides here (spec §13, decision 15). It is recorded because it is what a `port`-based key would have cost.

All 2 `port` values seen at a `redeem` in this test: ["0" "0"].

### Stability for the life of a session

Every record naming either login, in arrival order, with the `port` it carried. Grouped by username rather than by `ctx_id`: a `ctx_id` is only written when the context lookup succeeded, so grouping by it hides exactly the sessions whose `port` moved.

| user | records, `event`=`port` |
|---|---|
| `alice04` | `redeem`=0, `authorize_session`=0, `account`=0, `account`=0 |
| `alice05` | `redeem`=0, `authorize_session`=0, `account`=0, `account`=0 |

**Stable.** Across 2 session(s), every record for a session reported the same `port` as that session's authentication START.


### What the two sessions were actually told

What each login was told when the device asked to authorize its session, and the `port` the device put on that request — which is not the `port` it authenticated under.

| user | `port` at authorization | verdict | reason | `ctx_id` |
|---|---|---|---|---|
| `alice04` | `0` | permit | `context_matched` | `G3LIWOSOOQUO3JH5` |
| `alice05` | `0` | permit | `context_matched` | `F6GPWUD5IJGWGB3R` |

2 permitted, 0 denied. **Both concurrent sessions matched their own context and were authorized**, across 2 distinct `ctx_id`(s) — neither login disturbed the other, and the `port` changing between the authentication and this request did not cost either of them anything.

### What the header carried

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.31:52822 → | `0x5dd6aeee` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice04" port="0" rem_addr="172.100.100.1" data=14 bytes |
| 172.100.100.1:49 ← | `0x5dd6aeee` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.31:52836 → | `0x3dc7f796` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice04" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.1:49 ← | `0x3dc7f796` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.31:52842 → | `0x74d525c2` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice04" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1789928374 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x74d525c2` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:39592 → | `0x4643f73e` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice05" port="0" rem_addr="172.100.100.1" data=14 bytes |
| 172.100.100.1:49 ← | `0x4643f73e` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.31:39602 → | `0x62b1439e` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice05" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.1:49 ← | `0x62b1439e` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.31:39604 → | `0x064a6210` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice05" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/4 start_time=1789928376 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x064a6210` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:44614 → | `0x7736d53f` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice05" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/4 start_time=1789928391 timezone=UTC stop_time=1789928391 service=none] |
| 172.100.100.1:49 ← | `0x7736d53f` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:44630 → | `0x7f3f62f2` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice04" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1789928394 timezone=UTC stop_time=1789928394 service=none] |
| 172.100.100.1:49 ← | `0x7f3f62f2` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 8, carrying 8 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 8 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 4 connection(s), AUTHEN on 2 connection(s), AUTHOR on 2 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here, so L1 is not answered for those transports.
