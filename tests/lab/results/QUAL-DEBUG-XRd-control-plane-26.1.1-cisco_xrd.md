# QUAL-DEBUG-XRd-control-plane-26.1.1 — cisco_xrd

- **Date measured:** 2026-10-23
- **Platform:** cisco_xrd (containerlab node `xrd1`, 172.100.100.61)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-XRd-control-plane-26.1.1-cisco_xrd.pcap` — 968 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-XRd-control-plane-26.1.1-cisco_xrd.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0953fbf877a0ea7ba529a37718479380e08eb787`, `PORT49_LAB_PLATFORMS=xrd261`, `-run ^TestQualify$`

## Claim

What cisco_xrd's own TACACS+ debug says about the TLS cells of a qualification run on XRd control plane 26.1.1: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform cisco_xrd, image XRd control plane 26.1.1. Debug on: `terminal length 0`, `terminal width 512`, `clear logging`, `y`, `debug tacacs`, `debug aaa` (read with `show logging`; off with `undebug all`).

### What the filter kept

- `tls_token_login`: the device returned 1690 log lines and the filter kept 1177 (23 connection open/close, 3 request, 1151 other); the capture holds 11 TLS connection(s).
  Lines dropped by rule: facility=14 body_word=0 hex_view=500 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=12 closed=11 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=16:51:40.626 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 2: opened=16:51:40.958 closed=16:51:40.958 reason="" authen=0 author=0 acct=0.
  - debug connection 3: opened=before closed=16:51:41.295 reason="" authen=0 author=0 acct=0.
  - debug connection 4: opened=16:51:41.741 closed=16:51:42.078 reason="" authen=0 author=3 acct=0.
  - debug connection 5: opened=16:51:42.081 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 6: opened=16:51:42.414 closed=16:51:42.414 reason="" authen=0 author=0 acct=0.
  - debug connection 7: opened=before closed=16:51:42.746 reason="" authen=0 author=0 acct=0.
  - debug connection 8: opened=16:51:42.748 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 9: opened=16:51:42.768 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 10: opened=16:51:42.782 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 11: opened=16:51:43.071 closed=16:51:43.632 reason="" authen=0 author=0 acct=0.
  - debug connection 12: opened=before closed=16:51:43.633 reason="" authen=0 author=0 acct=0.
  - debug connection 13: opened=before closed=16:51:43.910 reason="" authen=0 author=0 acct=0.
  - debug connection 14: opened=before closed=16:51:43.911 reason="" authen=0 author=0 acct=0.
  - debug connection 15: opened=16:51:43.912 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 16: opened=16:51:43.921 closed=16:51:44.520 reason="" authen=0 author=0 acct=0.
  - debug connection 17: opened=before closed=16:51:44.521 reason="" authen=0 author=0 acct=0.
  - debug connection 18: opened=16:51:49.190 closed=open reason="" authen=0 author=0 acct=0.
  - capture: `conn port=17855 syn=16:51:40.677 hold=0.28s end=server-fin`
  - capture: `conn port=46902 syn=16:51:41.009 hold=0.29s end=server-fin`
  - capture: `conn port=60279 syn=16:51:41.791 hold=0.29s end=server-fin`
  - capture: `conn port=31655 syn=16:51:42.132 hold=0.28s end=server-fin`
  - capture: `conn port=35820 syn=16:51:42.464 hold=0.28s end=server-fin`
  - capture: `conn port=44662 syn=16:51:42.798 hold=0.27s end=server-fin`
  - capture: `conn port=25701 syn=16:51:42.818 hold=0.53s end=server-fin`
  - capture: `conn port=40417 syn=16:51:42.832 hold=0.80s end=server-fin`
  - capture: `conn port=52181 syn=16:51:43.122 hold=0.79s end=server-fin`
  - capture: `conn port=45164 syn=16:51:43.962 hold=0.28s end=server-fin`
  - capture: `conn port=30909 syn=16:51:43.972 hold=0.55s end=server-fin`
- `tls_unknown_ca`: the device returned 608 log lines and the filter kept 474 (5 connection open/close, 2 request, 467 other); the capture holds 3 TLS connection(s).
  Lines dropped by rule: facility=14 body_word=0 hex_view=121 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=3 closed=2 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=16:53:03.083 closed=16:53:03.416 reason="" authen=0 author=0 acct=0.
  - debug connection 2: opened=16:53:03.476 closed=16:53:03.538 reason="" authen=0 author=2 acct=0.
  - debug connection 3: opened=16:53:08.809 closed=open reason="" authen=0 author=0 acct=0.
  - capture: `conn port=19761 syn=16:53:03.134 hold=0.28s end=server-rst`
  - capture: `conn port=17896 syn=16:53:03.526 hold=0.00s end=server-rst`
  - capture: `conn port=41920 syn=16:53:03.589 hold=0.00s end=server-rst`

### Open questions

- **Which debug line marks a connection open?** `tls_token_login`: `RP/0/RP0/CPU0:Oct 23 16:51:40.626 UTC: tacacsd[1139]: Socket connected successfully` (12 in the cell); `tls_unknown_ca`: `RP/0/RP0/CPU0:Oct 23 16:53:03.083 UTC: tacacsd[1139]: Socket connected successfully` (3 in the cell).
- **tls_token_login: why does the device open a second connection?** The debug shows the second open at `RP/0/RP0/CPU0:Oct 23 16:51:40.958 UTC: tacacsd[1139]: Socket connected successfully`, after `RP/0/RP0/CPU0:Oct 23 16:51:40.958 UTC: tacacsd[1139]: Connection success!!`. That is the line that comes before it, not a stated cause.
- **How does a connection end?** `tls_unknown_ca`: close `RP/0/RP0/CPU0:Oct 23 16:53:03.416 UTC: tacacsd[1139]: closing the socket 1000084`, TLS failure `RP/0/RP0/CPU0:Oct 23 16:53:03.416 UTC: tacacsd[1139]: %<LONG> : SSL_write operation with TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error.`; `tls_token_login`: close `RP/0/RP0/CPU0:Oct 23 16:51:40.958 UTC: tacacsd[1139]: closing the socket 1000062`.
- **Do requests ride one connection together (pipelining)?** 1 of 18 debug connection(s) carried more than one request (3 request line(s)); first request line `RP/0/RP0/CPU0:Oct 23 16:51:41.741 UTC: tacacsd[1139]: [session 13] packet AUTHOR/START selected server 172.100.100.1/300 socket 1000064 TLS: Enabled`.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 37 shape(s), the first 30

- `show logging => _ tacacsd _ using server group _`
- `show logging => _ tacacsd _ socket connection _ tacacs _ server A _`
- `show logging => _ tacacsd _ socket created _ A _`
- `show logging => _ tacacsd _ connection _ status _ tacacs _ detected the _ server available _ send the request _`
- `show logging => _ tacacsd _ failed _ send request status _ tacacs _ detected the _ server available _ send the request _`
- `show logging => _ connection closed _ A port _`
- `show logging => _ tacacsd _ tacacsd _ server _ tacacs _ server A _ server _ socket _ connection _`
- `show logging => _ tacacsd _ A _ tacacs _`
- `show logging => _ tacacsd _ connect _ A _`
- `show logging => _ tacacsd _ tacacsd _ server _ tacacs _ server A _ server _`
- `show logging => _ tacacsd _ session _ packet _ start _ login _ server A _ socket _ tls _`
- `show logging => _ tacacsd _ timer for _ seconds _`
- `show logging => _ tacacsd _ tacacs _ with session _`
- `show logging => _ tacacsd _ tacacs _ connect _ for _ session _`
- `show logging => _ tacacsd _ tacacs _ connect _`
- `show logging => _ tacacsd _ session _`
- `show logging => _ tacacsd _ tacacs _`
- `show logging => _ tacacsd _ tacacs _ session _`
- `show logging => _ tacacsd _ tacacs _ for _ session _`
- `show logging => _ tacacsd _ packet _ start _ login _ session _ server A _`
- `show logging => _ tacacsd _ tacacs _ not _`
- `show logging => _ tacacsd _ reply _ session _ from server A _`
- `show logging => _ tacacsd _ and _ timer _`
- `show logging => _ tacacsd _ reply _ the _`
- `show logging => _ tacacsd _ session _ packet _ server A _ socket _ tls _`
- `show logging => _ tacacsd _ packet _ session _ server A _`
- `show logging => _ tacacsd _ session _ packet author _ start _ server A _ socket _ tls _`
- `show logging => _ tacacsd _ tacacs _ for _`
- `show logging => _ tacacsd _ socket _`
- `show logging => _ tacacsd _ packet author _ start _ session _ server A _`

`tls_unknown_ca`: 28 shape(s)

- `show logging => _ tacacsd _ using server group _`
- `show logging => _ tacacsd _ socket connection _ tacacs _ server A _`
- `show logging => _ tacacsd _ socket created _ A _`
- `show logging => _ tacacsd _ connection _ status _ tacacs _ detected the _ server available _ send the request _`
- `show logging => _ tacacsd _ failed _ send request status _ tacacs _ detected the _ server available _ send the request _`
- `show logging => _ connection closed _ A port _`
- `show logging => _ tacacsd _ tacacsd _ server _ tacacs _ server A _ server _ socket _ connection _`
- `show logging => _ tacacsd _ A _ tacacs _`
- `show logging => _ tacacsd _ connect _ A _`
- `show logging => _ tacacsd _ tacacsd _ server _ tacacs _ server A _ server _`
- `show logging => _ tacacsd _ session _ packet _ start _ login _ server A _ socket _ tls _`
- `show logging => _ tacacsd _ timer for _ seconds _`
- `show logging => _ tacacsd _ tacacs _ with session _`
- `show logging => _ tacacsd _ tacacs _ connect _ for _ session _`
- `show logging => _ tacacsd _ tacacs _ connect _`
- `show logging => _ tacacsd _ session _`
- `show logging => _ tacacsd _ tacacs _`
- `show logging => _ tacacsd _ tacacs _ session _`
- `show logging => _ tacacsd _ tacacs _ for _ session _`
- `show logging => _ tacacsd _ request _ start _ login _ tacacs _ detected the _ server _ not _`
- `show logging => _ tacacsd _ and _ timer _`
- `show logging => _ tacacsd _ tacacs _ for _`
- `show logging => _ tacacsd _ socket _`
- `show logging => _ tacacsd _ request _ author _ start _ tacacs _ detected the _ server _ not _`
- `show logging => _ tacacsd _ session _ packet author _ start _ server A _ socket _ tls _`
- `show logging => _ tacacsd _ tacacs _ connect _ failed _ error _ detected the _ invalid _`
- `show logging => _`
- `show logging => _ authentication for _ from A port _`

