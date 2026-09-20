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

**The two concurrent sessions reported the SAME `port` value.** The login context key `(nas, port)` therefore does not distinguish them: the second login overwrites the first login's context, and the receipt key `(nas, port, username)` collides for repeated logins by one user.

All 2 `port` values seen at a `redeem` in this test: ["0" "0"].

### Stability for the life of a session

Every record naming either login, in arrival order, with the `port` it carried. Grouped by username rather than by `ctx_id`: a `ctx_id` is only written when the context lookup succeeded, so grouping by it hides exactly the sessions whose `port` moved.

| user | records, `event`=`port` |
|---|---|
| `alice04` | `redeem`=0, `authorize_session`=0, `account`=0, `account`=0 |
| `alice05` | `redeem`=0, `authorize_session`=0, `account`=0, `account`=0 |

**Stable.** Across 2 session(s), every record for a session reported the same `port` as that session's authentication START, so a key built on `port` reads the same value at authorization time as it wrote at authentication time.


### What the header carried

Decoded from the capture with the daemon's own `internal/tacacs/wire` package and the lab shared key. Passwords are never rendered: an AUTHEN START's `data` and a CONTINUE's `user_msg` are reported as byte counts, which is where a PAP password and an ASCII one respectively live. `tcpdump -i any` sees each segment twice, on the bridge and on the veth, so the streams are reassembled by TCP sequence number and the duplicates dropped before anything below is counted.

| device connection | session_id | seq | single-connect | packet |
|---|---|---|---|---|
| 172.100.100.31:49716 → | `0x56212664` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice04" port="0" rem_addr="172.100.100.1" data=14 bytes |
| 172.100.100.1:49 ← | `0x56212664` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.31:49726 → | `0x4942f0c5` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice04" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.1:49 ← | `0x4942f0c5` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15] |
| 172.100.100.31:49738 → | `0x63b459ac` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice04" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1789924631 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x63b459ac` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:49748 → | `0x4912c981` | 1 | clear | AUTHEN START action=login(1) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice05" port="0" rem_addr="172.100.100.1" data=14 bytes |
| 172.100.100.1:49 ← | `0x4912c981` | 2 | clear | AUTHEN REPLY status=PASS(1) flags=0x00 server_msg="" data=0 bytes |
| 172.100.100.31:49760 → | `0x292ef038` | 1 | clear | AUTHOR REQUEST authen_method=tacacsplus(6) authen_type=pap(2) service=login(1) priv_lvl=1 user="alice05" port="0" rem_addr="172.100.100.1" args=[service=shell cmd= cisco-av-pair* shell:roles*] |
| 172.100.100.1:49 ← | `0x292ef038` | 2 | clear | AUTHOR RESPONSE status=0x01 server_msg="" args=[priv-lvl=15] |
| 172.100.100.31:49776 → | `0x30e81f92` | 1 | clear | ACCT REQUEST flags=start authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice05" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/4 start_time=1789924633 timezone=UTC service=none] |
| 172.100.100.1:49 ← | `0x30e81f92` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:56260 → | `0x15f23658` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice05" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/4 start_time=1789924648 timezone=UTC stop_time=1789924648 service=none] |
| 172.100.100.1:49 ← | `0x15f23658` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |
| 172.100.100.31:56276 → | `0x7ec3abc2` | 1 | clear | ACCT REQUEST flags=stop authen_method=tacacsplus(6) authen_type=ascii(1) service=none(0) priv_lvl=0 user="alice04" port="0" rem_addr="172.100.100.1" args=[task_id=172.100.100.1@pts/3 start_time=1789924651 timezone=UTC stop_time=1789924651 service=none] |
| 172.100.100.1:49 ← | `0x7ec3abc2` | 2 | clear | ACCT REPLY status=0x01 server_msg="" |

- **TCP connections the device opened:** 8, carrying 8 distinct `session_id`(s). The busiest connection carried **1** `session_id`(s).
  That is **one TCP connection per exchange**: the device tears the connection down and opens another for the next one, so nothing at the transport layer joins two exchanges either.
- **Single-connect flag:** set on 0 of 8 requests from the device. The device never asks to hold the connection open, whatever it then does with it.
- **Exchanges seen:** ACCT on 4 connection(s), AUTHEN on 2 connection(s), AUTHOR on 2 connection(s).
- **What `session_id` can join:** a `session_id` that appears on exactly one connection and under exactly one exchange links the packets *within* that exchange — a START and its CONTINUE, which is what makes an ASCII login work at all — and links nothing across exchanges. Read the table: if the authentication and the authorization for one login carry different `session_id`s, no field in the header joins them, and the login-context key cannot be built out of one.

Transport measured: SSH only. Console, eAPI, NX-API and NETCONF are not measured here, so L1 is not answered for those transports.
