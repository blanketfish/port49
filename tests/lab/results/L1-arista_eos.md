# L1 — arista_eos

- **Date measured:** 2026-09-20
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.32.2F (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L1-arista_eos.pcap` — 168 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L1-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

What the `port` field contains, per platform and per transport — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session, stable for its life, and **the same value at authentication and at authorization time**.

## Observation

Two overlapping SSH sessions, each holding an interactive shell open, produced these `port` values on the authentication START:

| session | user | `port` |
|---|---|---|
| 1 | alice05 | `ssh` |
| 2 | alice06 | `ssh` |

**The two concurrent sessions reported the SAME `port` value**, so `port` does not tell two simultaneous operators apart on this platform. That is now a fact about the device rather than a fact about port49: since 2026-09-20 the login context is keyed `(nas, username)` and the receipt `(nas, username, credential_sha256)`, so neither collides here (spec §13, decision 15). It is recorded because it is what a `port`-based key would have cost.

All 2 `port` values seen at a `redeem` in this test: ["ssh" "ssh"].

### Stability for the life of a session

Every record naming either login, in arrival order, with the `port` it carried. Grouped by username rather than by `ctx_id`: a `ctx_id` is only written when the context lookup succeeded, so grouping by it hides exactly the sessions whose `port` moved.

| user | records, `event`=`port` |
|---|---|
| `alice05` | `redeem`=ssh, `account`=ssh, `authorize_session`=vty4, `account`=vty4 |
| `alice06` | `redeem`=ssh, `account`=ssh, `authorize_session`=vty6, `account`=vty6 |

**NOT stable**: 2 of 2 session(s) reported more than one `port` value over their life (alice05, alice06). This is the measurement that re-cut the login-context key (spec §13, decision 15): a context keyed on `(nas, port)` is written under one value and looked up under another, so the authorization missed and the session was denied for a reason that had nothing to do with policy. Under `(nas, username)` the lookup does not read this field at all — the section below is that claim measured rather than asserted.


### What the two sessions were actually told

What each login was told when the device asked to authorize its session, and the `port` the device put on that request — which is not the `port` it authenticated under.

| user | `port` at authorization | verdict | reason | `ctx_id` |
|---|---|---|---|---|
| `alice05` | `vty4` | permit | `context_matched` | `CGLPCY4ZAWCHTMEO` |
| `alice06` | `vty6` | permit | `context_matched` | `VTVTBKEUPBTRRWZ6` |

2 permitted, 0 denied. **Both concurrent sessions matched their own context and were authorized**, across 2 distinct `ctx_id`(s) — neither login disturbed the other, and the `port` changing between the authentication and this request did not cost either of them anything.

### What the header carried

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.11:33446 → | `0x3df39a92` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:33446 → | `0x3df39a92` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x3df39a92` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x3df39a92` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:33452 → | `0x36a9ef42` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="ssh" rem_addr="172.100.100.1" args=[task_id=27 service=shell start_time=1789927728 timezone=UTC] |
| 172.100.100.1:49 ← | `0x36a9ef42` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:33462 → | `0x5bd09524` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="vty4" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0x5bd09524` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.11:33468 → | `0x1ca7c581` | 1 | clear | AUTHEN START action=login(1) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice06" port="ssh" rem_addr="172.100.100.1" data=0 bytes |
| 172.100.100.11:33468 → | `0x1ca7c581` | 3 | clear | AUTHEN CONTINUE flags=0x00 user_msg=14 bytes data=0 bytes |
| 172.100.100.1:49 ← | `0x1ca7c581` | 2 | clear | AUTHEN REPLY status=GETPASS(5) flags=0x01 server_msg="Password: " data=0 bytes |
| 172.100.100.1:49 ← | `0x1ca7c581` | 4 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.11:33474 → | `0x082157aa` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice06" port="ssh" rem_addr="172.100.100.1" args=[task_id=28 service=shell start_time=1789927730 timezone=UTC] |
| 172.100.100.1:49 ← | `0x082157aa` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:33480 → | `0xcfb63889` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice06" port="vty6" rem_addr="172.100.100.1" args=[service=shell cmd*] |
| 172.100.100.1:49 ← | `0xcfb63889` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15 shell:roles*network-admin] |
| 172.100.100.11:45800 → | `0x5436cd6f` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice06" port="vty6" rem_addr="172.100.100.1" args=[task_id=28 service=shell start_time=1789927730 timezone=UTC elapsed_time=16] |
| 172.100.100.1:49 ← | `0x5436cd6f` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.11:60766 → | `0x1d4ba202` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=login(1) priv_lvl=1 user="alice05" port="vty4" rem_addr="172.100.100.1" args=[task_id=27 service=shell start_time=1789927728 timezone=UTC elapsed_time=21] |
| 172.100.100.1:49 ← | `0x1d4ba202` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 8, carrying 8 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 10 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 4 connection(s), AUTHEN on 2 connection(s), AUTHOR on 2 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here, so L1 is not answered for those transports.
