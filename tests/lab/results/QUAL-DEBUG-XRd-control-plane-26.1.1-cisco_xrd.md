# QUAL-DEBUG-XRd-control-plane-26.1.1 — cisco_xrd

- **Date measured:** 2026-10-23
- **Platform:** cisco_xrd (containerlab node `xrd1`, 172.100.100.61)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-XRd-control-plane-26.1.1-cisco_xrd.pcap` — 971 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-XRd-control-plane-26.1.1-cisco_xrd.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `da97eb6d37b539b5cfcedd50942c0b32df46c229`, `PORT49_LAB_PLATFORMS=xrd261`, `-run ^TestQualify$`

## Claim

What cisco_xrd's own TACACS+ debug says about the TLS cells of a qualification run on XRd control plane 26.1.1: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform cisco_xrd, image XRd control plane 26.1.1. Debug on: `terminal length 0`, `terminal width 512`, `clear logging`, `y`, `debug tacacs`, `debug aaa` (read with `show logging`; off with `undebug all`).

### What the filter kept

- `tls_token_login`: the device returned 1689 log lines and the filter kept 1178 (12 connection open/close, 5 request, 1161 other); the capture holds 11 TLS connection(s).
  Lines dropped by rule: facility=14 body_word=0 hex_view=498 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=12 closed=0 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=15:29:48.965 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 2: opened=15:29:49.302 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 3: opened=15:29:50.113 closed=open reason="" authen=0 author=3 acct=0.
  - debug connection 4: opened=15:29:50.450 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 5: opened=15:29:50.782 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 6: opened=15:29:51.119 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 7: opened=15:29:51.139 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 8: opened=15:29:51.154 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 9: opened=15:29:51.444 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 10: opened=15:29:52.276 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 11: opened=15:29:52.284 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 12: opened=15:29:57.551 closed=open reason="" authen=0 author=2 acct=0.
  - capture: `conn port=21249 syn=15:29:49.015 hold=0.29s end=server-fin`
  - capture: `conn port=18934 syn=15:29:49.353 hold=0.28s end=server-fin`
  - capture: `conn port=33661 syn=15:29:50.164 hold=0.28s end=server-fin`
  - capture: `conn port=29297 syn=15:29:50.501 hold=0.28s end=server-fin`
  - capture: `conn port=48417 syn=15:29:50.833 hold=0.28s end=server-fin`
  - capture: `conn port=47005 syn=15:29:51.170 hold=0.27s end=server-fin`
  - capture: `conn port=28720 syn=15:29:51.189 hold=0.53s end=server-fin`
  - capture: `conn port=34920 syn=15:29:51.204 hold=0.79s end=server-fin`
  - capture: `conn port=29681 syn=15:29:51.494 hold=0.78s end=server-fin`
  - capture: `conn port=24004 syn=15:29:52.326 hold=0.28s end=server-fin`
  - capture: `conn port=35045 syn=15:29:52.334 hold=0.55s end=server-fin`
- `tls_unknown_ca`: the device returned 608 log lines and the filter kept 474 (3 connection open/close, 2 request, 469 other); the capture holds 3 TLS connection(s).
  Lines dropped by rule: facility=14 body_word=0 hex_view=121 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=3 closed=0 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=15:31:11.860 closed=open reason="" authen=0 author=0 acct=0.
  - debug connection 2: opened=15:31:12.402 closed=open reason="" authen=0 author=2 acct=0.
  - debug connection 3: opened=15:31:17.726 closed=open reason="" authen=0 author=0 acct=0.
  - capture: `conn port=15689 syn=15:31:11.910 hold=0.28s end=server-rst`
  - capture: `conn port=31728 syn=15:31:12.452 hold=0.00s end=server-rst`
  - capture: `conn port=65066 syn=15:31:12.512 hold=0.00s end=server-rst`

### Open questions

- **Which debug line marks a connection open?** `tls_token_login`: `RP/0/RP0/CPU0:Oct 23 15:29:48.965 UTC: tacacsd[1139]: Socket connected successfully` (12 in the cell); `tls_unknown_ca`: `RP/0/RP0/CPU0:Oct 23 15:31:11.860 UTC: tacacsd[1139]: Socket connected successfully` (3 in the cell).
- **tls_token_login: why does the device open a second connection?** The debug shows the second open at `RP/0/RP0/CPU0:Oct 23 15:29:49.302 UTC: tacacsd[1139]: Socket connected successfully`, after `RP/0/RP0/CPU0:Oct 23 15:29:49.302 UTC: tacacsd[1139]: Connection success!!`. That is the line that comes before it, not a stated cause.
- **How does a connection end?** `tls_unknown_ca`: TLS failure `RP/0/RP0/CPU0:Oct 23 15:31:12.195 UTC: tacacsd[1139]: %<LONG> : SSL_write operation with TACACS+ server 172.100.100.1/300 failed [server-private: No], SSL Error:System call error.`.
- **Do requests ride one connection together (pipelining)?** 2 of 12 debug connection(s) carried more than one request (5 request line(s)); first request line `RP/0/RP0/CPU0:Oct 23 15:29:50.113 UTC: tacacsd[1139]: [session 13] packet AUTHOR/START selected server 172.100.100.1/300 socket 1000064 TLS: Enabled`.

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

