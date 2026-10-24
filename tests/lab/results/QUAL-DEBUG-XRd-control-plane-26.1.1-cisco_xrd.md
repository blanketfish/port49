# QUAL-DEBUG-XRd-control-plane-26.1.1 — cisco_xrd

- **Date measured:** 2026-10-24
- **Platform:** cisco_xrd (containerlab node `xrd1`, 172.100.100.61)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-XRd-control-plane-26.1.1-cisco_xrd.pcap` — 972 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-XRd-control-plane-26.1.1-cisco_xrd.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `7fd3c9a27b8cc77c70cbdb325415691263314679`, `PORT49_LAB_PLATFORMS=xrd261`, `-run ^TestQualify$`

## Claim

What cisco_xrd's own TACACS+ debug says about the TLS cells of a qualification run on XRd control plane 26.1.1: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform cisco_xrd, image XRd control plane 26.1.1. Debug on: `terminal length 0`, `terminal width 512`, `clear logging`, `y`, `debug tacacs`, `debug aaa` (read with `show logging`; off with `undebug all`).

### What the filter kept

- `tls_token_login`: the device returned 1689 log lines and the filter kept 1184 (23 connection open/close, 1 request, 1160 other); the capture holds 11 TLS connection(s).
  Lines dropped by rule: facility=14 body_word=0 hex_view=492 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=12 closed=11 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=05:16:18.087 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 2: opened=05:16:18.422 closed=05:16:18.422 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 3: opened=before closed=05:16:18.755 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 4: opened=05:16:19.132 closed=05:16:19.462 reason="" authen=0 author=1 acct=0 requests=1.
  - debug connection 5: opened=05:16:19.465 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 6: opened=05:16:19.794 closed=05:16:19.794 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 7: opened=before closed=05:16:20.128 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 8: opened=05:16:20.129 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 9: opened=05:16:20.152 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 10: opened=05:16:20.167 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 11: opened=05:16:20.452 closed=05:16:21.007 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 12: opened=before closed=05:16:21.008 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 13: opened=before closed=05:16:21.284 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 14: opened=before closed=05:16:21.284 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 15: opened=05:16:21.286 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 16: opened=05:16:21.295 closed=05:16:21.891 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 17: opened=before closed=05:16:21.892 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 18: opened=05:16:26.573 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - capture: `conn port=45693 syn=05:16:18.138 hold=0.28s end=server-fin`
  - capture: `conn port=29934 syn=05:16:18.473 hold=0.28s end=server-fin`
  - capture: `conn port=25693 syn=05:16:19.183 hold=0.28s end=server-fin`
  - capture: `conn port=64687 syn=05:16:19.515 hold=0.28s end=server-fin`
  - capture: `conn port=19564 syn=05:16:19.844 hold=0.28s end=server-fin`
  - capture: `conn port=29840 syn=05:16:20.179 hold=0.27s end=server-fin`
  - capture: `conn port=57853 syn=05:16:20.203 hold=0.53s end=server-fin`
  - capture: `conn port=48508 syn=05:16:20.218 hold=0.79s end=server-fin`
  - capture: `conn port=38102 syn=05:16:20.502 hold=0.78s end=server-fin`
  - capture: `conn port=51893 syn=05:16:21.336 hold=0.28s end=server-fin`
  - capture: `conn port=58578 syn=05:16:21.345 hold=0.55s end=server-fin`
- `tls_unknown_ca`: the device returned 683 log lines and the filter kept 528 (7 connection open/close, 0 request, 521 other); the capture holds 5 TLS connection(s).
  Lines dropped by rule: facility=14 body_word=0 hex_view=142 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=4 closed=3 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=05:18:05.736 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 2: opened=05:18:06.071 closed=05:18:06.071 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 3: opened=before closed=05:18:11.171 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 4: opened=05:18:11.179 closed=05:18:11.240 reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 5: opened=05:18:16.503 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - capture: `conn port=56273 syn=05:18:05.787 hold=0.28s end=server-rst`
  - capture: `conn port=60828 syn=05:18:06.121 hold=0.00s end=server-rst`
  - capture: `conn port=21658 syn=05:18:11.123 hold=0.00s end=device-fin`
  - capture: `conn port=58329 syn=05:18:11.230 hold=0.00s end=server-rst`
  - capture: `conn port=47224 syn=05:18:11.291 hold=0.00s end=server-rst`

### Open questions

- **Which debug line marks a connection open?** `tls_token_login`: `RP/0/RP0/CPU0:Oct 24 05:16:18.087 UTC: tacacsd[1139]: Socket connected successfully` (12 in the cell); `tls_unknown_ca`: `RP/0/RP0/CPU0:Oct 24 05:18:05.736 UTC: tacacsd[1139]: Socket connected successfully` (4 in the cell).
- **tls_token_login: why does the device open a second connection?** The debug shows the second open at `RP/0/RP0/CPU0:Oct 24 05:16:18.422 UTC: tacacsd[1139]: Socket connected successfully`, after `RP/0/RP0/CPU0:Oct 24 05:16:18.422 UTC: tacacsd[1139]: Connection success!!`. That is the line that comes before it, not a stated cause.
- **How does a connection end?** `tls_unknown_ca`: close `RP/0/RP0/CPU0:Oct 24 05:18:06.071 UTC: tacacsd[1139]: closing the socket 1000085`, TLS failure `RP/0/RP0/CPU0:Oct 24 05:18:06.070 UTC: tacacsd[1139]: %<LONG> : SSL_read operation with TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error.`; `tls_token_login`: close `RP/0/RP0/CPU0:Oct 24 05:16:18.422 UTC: tacacsd[1139]: closing the socket 1000062`.
- **Do requests ride one connection together (pipelining)?** 0 of 12 debug connection(s) with a kept open carried more than one request (1 placed request line(s)); requests not placed on a connection: 0; first request line `RP/0/RP0/CPU0:Oct 24 05:16:19.461 UTC: tacacsd[1139]: Packet AUTHOR/START (session 13) to server 172.100.100.1/300`.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 35 shape(s), the first 30

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

`tls_unknown_ca`: 36 shape(s), the first 30

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
- `show logging => _ tacacsd _ thread _`
- `show logging => _ tacacsd _ tacacs _ connect _ error _ timer _`
- `show logging => _ tacacsd _ the request _ sent _`
- `show logging => _ tacacsd _ tacacs _ not _ for _ invalid _`
- `show logging => _ tacacsd _ tacacs _ timeout _`
- `show logging => _ tacacsd _ socket _`
- `show logging => _ tacacsd _ request _ start _ login _ server A _`
- `show logging => _ tacacsd _ and _ timer _`
- `show logging => _ tacacsd _ request _ start _ login _ tacacs _ detected the _ timer _`

