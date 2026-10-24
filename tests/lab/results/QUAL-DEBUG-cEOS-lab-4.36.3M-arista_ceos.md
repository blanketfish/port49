# QUAL-DEBUG-cEOS-lab-4.36.3M — arista_ceos

- **Date measured:** 2026-10-24
- **Platform:** arista_ceos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** cEOS-lab 4.36.3M (`ceos:4.36.3M`)
- **Topology:** `tests/lab/topologies/ceos436.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-cEOS-lab-4.36.3M-arista_ceos.pcap` — 1741 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-cEOS-lab-4.36.3M-arista_ceos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `9b765bc6d77d2354e968a5d3a62fecc258d0e2e6`, `PORT49_LAB_PLATFORMS=ceos436`, `-run ^TestQualify$`

## Claim

What arista_ceos's own TACACS+ debug says about the TLS cells of a qualification run on cEOS-lab 4.36.3M: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform arista_ceos, image cEOS-lab 4.36.3M. Debug on: `terminal length 0`, `terminal width 511`, `clear agent Aaa logs`, `configure`, `trace Aaa setting *`, `end` (read with `show agent Aaa logs`; off with `configure`, `no trace Aaa setting *`, `end`).

### What the filter kept

- `tls_token_login`: the device returned 864 log lines and the filter kept 152 (23 connection open/close, 11 request, 118 other); the capture holds 8 TLS connection(s).
  Lines dropped by rule: facility=698 body_word=1 hex_view=15 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=14 closed=9 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connections failed_opens=5.
  - debug connection 1: opened=06:14:34.105772 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 2: opened=06:14:34.106117 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 3: opened=06:14:35.755083 closed=06:14:36.263101 reason="" authen=0 author=0 acct=0 requests=2.
  - debug connection 4: opened=06:14:44.089321 closed=06:14:44.094707 reason="" authen=0 author=0 acct=0 requests=2.
  - debug connection 5: opened=06:14:45.750954 closed=06:14:45.753421 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 6: opened=06:14:45.838193 closed=06:14:45.840587 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 7: opened=06:14:45.884414 closed=06:14:45.886934 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 8: opened=06:14:45.888103 closed=06:14:45.889892 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 9: opened=06:14:45.946132 closed=06:14:45.949114 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 10: opened=06:14:45.993875 closed=06:14:45.996247 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 11: opened=06:14:46.019188 closed=06:14:46.021428 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 12: opened=06:14:51.327403 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 13: opened=06:14:51.329270 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 14: opened=06:14:51.329578 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - capture: `conn port=37646 syn=06:14:44.089 hold=0.01s end=server-fin`
  - capture: `conn port=37658 syn=06:14:45.751 hold=0.00s end=server-fin`
  - capture: `conn port=37670 syn=06:14:45.838 hold=0.00s end=server-fin`
  - capture: `conn port=37680 syn=06:14:45.884 hold=0.00s end=server-fin`
  - capture: `conn port=37696 syn=06:14:45.888 hold=0.00s end=server-fin`
  - capture: `conn port=37702 syn=06:14:45.946 hold=0.00s end=server-fin`
  - capture: `conn port=37706 syn=06:14:45.993 hold=0.00s end=server-fin`
  - capture: `conn port=37718 syn=06:14:46.019 hold=0.00s end=server-fin`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.
- `tls_unknown_ca`: the device returned 1777 log lines and the filter kept 280 (41 connection open/close, 15 request, 224 other); the capture holds 5 TLS connection(s).
  Lines dropped by rule: facility=1461 body_word=2 hex_view=36 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=29 closed=12 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connections failed_opens=17.
  - debug connection 1: opened=06:14:34.105772 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 2: opened=06:14:34.106117 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 3: opened=06:14:35.755083 closed=06:14:36.263101 reason="" authen=0 author=0 acct=0 requests=2.
  - debug connection 4: opened=06:14:44.089321 closed=06:14:44.094707 reason="" authen=0 author=0 acct=0 requests=2.
  - debug connection 5: opened=06:14:45.750954 closed=06:14:45.753421 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 6: opened=06:14:45.838193 closed=06:14:45.840587 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 7: opened=06:14:45.884414 closed=06:14:45.886934 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 8: opened=06:14:45.888103 closed=06:14:45.889892 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 9: opened=06:14:45.946132 closed=06:14:45.949114 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 10: opened=06:14:45.993875 closed=06:14:45.996247 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 11: opened=06:14:46.019188 closed=06:14:46.021428 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 12: opened=06:14:51.327403 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 13: opened=06:14:51.329270 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 14: opened=06:14:51.329578 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 15: opened=06:14:58.842085 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 16: opened=06:14:58.843420 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 17: opened=06:14:58.843723 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 18: opened=06:14:59.095079 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 19: opened=06:15:20.734064 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 20: opened=06:15:20.734656 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 21: opened=06:15:22.386659 closed=06:15:22.894222 reason="" authen=0 author=0 acct=0 requests=2.
  - debug connection 22: opened=06:15:30.962766 closed=06:15:30.965028 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 23: opened=06:15:32.977318 closed=06:15:32.979248 reason="" authen=0 author=0 acct=0 requests=1.
  - debug connection 24: opened=06:15:32.979457 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 25: opened=06:15:32.980502 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 26: opened=06:15:32.980964 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 27: opened=06:15:38.290349 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 28: opened=06:15:38.292256 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - debug connection 29: opened=06:15:38.292857 closed=open reason="" authen=0 author=0 acct=0 requests=0.
  - capture: `conn port=34734 syn=06:15:30.962 hold=0.00s end=device-fin`
  - capture: `conn port=34746 syn=06:15:32.977 hold=0.00s end=server-rst`
  - capture: `conn port=34762 syn=06:15:32.979 hold=0.00s end=server-rst`
  - capture: `conn port=34776 syn=06:15:32.980 hold=0.00s end=server-rst`
  - capture: `conn port=34788 syn=06:15:32.981 hold=0.00s end=server-rst`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.

### Open questions

- **Which debug line marks a connection open?** `tls_token_login`: `2026-10-24 06:14:34.105772  1006 TacacsLib            6 TACACS+ counter connOpens host 172.100.100.1:300/0/Tacacs+ TLS` (14 in the cell); `tls_unknown_ca`: `2026-10-24 06:14:34.105772  1006 TacacsLib            6 TACACS+ counter connOpens host 172.100.100.1:300/0/Tacacs+ TLS` (29 in the cell).
- **tls_token_login: why does the device open a second connection?** The debug shows the second open at `2026-10-24 06:14:34.106117  1006 TacacsLib            6 TACACS+ counter connOpens host 172.100.100.1:300/0/Tacacs+ TLS`, after `2026-10-24 06:14:34.106049  1006 Tacacs               0 tac_send_acct failed: connect: Connection refused`. That is the line that comes before it, not a stated cause.
- **How does a connection end?** `tls_unknown_ca`: close `2026-10-24 06:14:36.263101  5526 TacacsLib            6 TACACS+ counter connCloses host 172.100.100.1:300/0/Tacacs+ TLS`; `tls_token_login`: close `2026-10-24 06:14:36.263101  5526 TacacsLib            6 TACACS+ counter connCloses host 172.100.100.1:300/0/Tacacs+ TLS`.
- **Do requests ride one connection together (pipelining)?** 2 of 14 debug connection(s) with a kept open carried more than one request (11 placed request line(s)); requests not placed on a connection: 0; first request line `2026-10-24 06:14:35.757477  5526 TacacsLib            6 TACACS+ counter messagesSent host 172.100.100.1:300/0/Tacacs+ TLS`.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 32 shape(s), the first 30

- `show agent Aaa logs => _ session from _ tacacs _`
- `show agent Aaa logs => _ created socket _`
- `show agent Aaa logs => _ error _ connect _ connection _`
- `show agent Aaa logs => _ tacacs _ connect _ connection _`
- `show agent Aaa logs => _ session _ tacacs _`
- `show agent Aaa logs => _ accounting method _ group _ unavailable _ method for _ for _`
- `show agent Aaa logs => _ received _ request _ seconds _ was _ was _`
- `show agent Aaa logs => _ tls session _ for _ default _`
- `show agent Aaa logs => _ accounting _ exec _ exec _ start _`
- `show agent Aaa logs => _ for method group _ session _ status _ session _ type _ session _ start _`
- `show agent Aaa logs => _ accounting _`
- `show agent Aaa logs => _ tacacs _ status _ message _`
- `show agent Aaa logs => _ cmd _ failed _ failed authorization _`
- `show agent Aaa logs => _ accounting _ exec _ exec _`
- `show agent Aaa logs => _ for method group _ session _ type _ session _`
- `show agent Aaa logs => _ tacacs authorization error _ connect _ connection _`
- `show agent Aaa logs => _ authorization method _ group _ unavailable _ method for _ for _`
- `show agent Aaa logs => _`
- `show agent Aaa logs => _ open _`
- `show agent Aaa logs => _ fail _`
- `show agent Aaa logs => _ close _`
- `show agent Aaa logs => _ timeout _ timer expired _`
- `show agent Aaa logs => _ has _ timer _ timer timeout _`
- `show agent Aaa logs => _ state _`
- `show agent Aaa logs => _ default _`
- `show agent Aaa logs => _ sent _`
- `show agent Aaa logs => _ from _`
- `show agent Aaa logs => _ from _ failed _`
- `show agent Aaa logs => _ with _`
- `show agent Aaa logs => _ for method group _`

`tls_unknown_ca`: 48 shape(s), the first 30

- `show agent Aaa logs => _ session from _ tacacs _`
- `show agent Aaa logs => _ created socket _`
- `show agent Aaa logs => _ error _ connect _ connection _`
- `show agent Aaa logs => _ tacacs _ connect _ connection _`
- `show agent Aaa logs => _ session _ tacacs _`
- `show agent Aaa logs => _ accounting method _ group _ unavailable _ method for _ for _`
- `show agent Aaa logs => _ received _ request _ seconds _ was _ was _`
- `show agent Aaa logs => _ tls session _ for _ default _`
- `show agent Aaa logs => _ accounting _ exec _ exec _ start _`
- `show agent Aaa logs => _ for method group _ session _ status _ session _ type _ session _ start _`
- `show agent Aaa logs => _ accounting _`
- `show agent Aaa logs => _ tacacs _ status _ message _`
- `show agent Aaa logs => _ cmd _ failed _ failed authorization _`
- `show agent Aaa logs => _ accounting _ exec _ exec _`
- `show agent Aaa logs => _ for method group _ session _ type _ session _`
- `show agent Aaa logs => _ tacacs authorization error _ connect _ connection _`
- `show agent Aaa logs => _ authorization method _ group _ unavailable _ method for _ for _`
- `show agent Aaa logs => _ available server _ accounting _`
- `show agent Aaa logs => _ has _ request _`
- `show agent Aaa logs => _ request _`
- `show agent Aaa logs => _ error _ ssl _ failed _ error _ ssl _ ssl _ tls _`
- `show agent Aaa logs => _ tacacs _ tac _ send _ failed _ ssl _ failed _ error _ ssl _ ssl _ tls _`
- `show agent Aaa logs => _ tacacs _ ssl _ failed _ error _ ssl _ ssl _ tls _`
- `show agent Aaa logs => _ error _ ssl _ connect _ connection _ peer _`
- `show agent Aaa logs => _ tacacs _ ssl _ connect _ connection _ peer _`
- `show agent Aaa logs => _ accounting method _ group _ unavailable _ method for _ exec _ for _`
- `show agent Aaa logs => _`
- `show agent Aaa logs => _ open _`
- `show agent Aaa logs => _ fail _`
- `show agent Aaa logs => _ close _`

