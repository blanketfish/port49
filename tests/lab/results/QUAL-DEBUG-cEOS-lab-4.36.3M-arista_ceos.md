# QUAL-DEBUG-cEOS-lab-4.36.3M — arista_ceos

- **Date measured:** 2026-10-23
- **Platform:** arista_ceos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** cEOS-lab 4.36.3M (`ceos:4.36.3M`)
- **Topology:** `tests/lab/topologies/ceos436.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-cEOS-lab-4.36.3M-arista_ceos.pcap` — 1744 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-cEOS-lab-4.36.3M-arista_ceos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a060b4a5b24fc27bd2118c9f6b92ee454cf9ff2e`, `PORT49_LAB_PLATFORMS=ceos436`, `-run ^TestQualify$`

## Claim

What arista_ceos's own TACACS+ debug says about the TLS cells of a qualification run on cEOS-lab 4.36.3M: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform arista_ceos, image cEOS-lab 4.36.3M. Debug on: `terminal length 0`, `terminal width 511`, `clear agent Aaa logs`, `configure`, `trace Aaa setting *`, `end` (read with `show agent Aaa logs`; off with `configure`, `no trace Aaa setting *`, `end`).

### What the filter kept

- `tls_token_login`: the device returned 853 log lines and the filter kept 150 (23 connection open/close, 27 request, 100 other); the capture holds 8 TLS connection(s).
  Lines dropped by rule: facility=689 body_word=1 hex_view=15 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=14 closed=9 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=16:46:07.542887 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 2: opened=16:46:07.543426 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 3: opened=16:46:09.196767 closed=16:46:09.705099 reason="" authen=1 author=0 acct=0.
  - debug connection 4: opened=before closed=open reason="" authen=1 author=0 acct=0.
  - debug connection 5: opened=16:46:17.482890 closed=16:46:17.491149 reason="" authen=1 author=0 acct=0.
  - debug connection 6: opened=before closed=open reason="" authen=1 author=0 acct=0.
  - debug connection 7: opened=16:46:19.855568 closed=16:46:19.857941 reason="" authen=0 author=0 acct=0.
  - debug connection 8: opened=before closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 9: opened=16:46:19.943526 closed=16:46:19.946242 reason="" authen=0 author=0 acct=0.
  - debug connection 10: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 11: opened=16:46:19.990370 closed=16:46:19.993622 reason="" authen=0 author=0 acct=0.
  - debug connection 12: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 13: opened=16:46:19.994853 closed=16:46:19.996889 reason="" authen=0 author=0 acct=0.
  - debug connection 14: opened=before closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 15: opened=16:46:20.052191 closed=16:46:20.054478 reason="" authen=0 author=0 acct=0.
  - debug connection 16: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 17: opened=16:46:20.098855 closed=16:46:20.101358 reason="" authen=0 author=0 acct=0.
  - debug connection 18: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 19: opened=16:46:20.120947 closed=16:46:20.122824 reason="" authen=0 author=0 acct=0.
  - debug connection 20: opened=before closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 21: opened=16:46:25.414556 closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 22: opened=16:46:25.416532 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 23: opened=16:46:25.416836 closed=open reason="" authen=0 author=0 acct=1.
  - capture: `conn port=49452 syn=16:46:17.482 hold=0.01s end=server-fin`
  - capture: `conn port=49466 syn=16:46:19.855 hold=0.00s end=server-fin`
  - capture: `conn port=49476 syn=16:46:19.943 hold=0.00s end=server-fin`
  - capture: `conn port=49490 syn=16:46:19.990 hold=0.00s end=server-fin`
  - capture: `conn port=49502 syn=16:46:19.994 hold=0.00s end=server-fin`
  - capture: `conn port=49518 syn=16:46:20.052 hold=0.00s end=server-fin`
  - capture: `conn port=49528 syn=16:46:20.098 hold=0.00s end=server-fin`
  - capture: `conn port=49530 syn=16:46:20.121 hold=0.00s end=server-fin`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.
- `tls_unknown_ca`: the device returned 1777 log lines and the filter kept 281 (41 connection open/close, 46 request, 194 other); the capture holds 5 TLS connection(s).
  Lines dropped by rule: facility=1464 body_word=2 hex_view=32 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=30 closed=11 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=16:46:07.542887 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 2: opened=16:46:07.543426 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 3: opened=16:46:09.196767 closed=16:46:09.705099 reason="" authen=1 author=0 acct=0.
  - debug connection 4: opened=before closed=open reason="" authen=1 author=0 acct=0.
  - debug connection 5: opened=16:46:17.482890 closed=16:46:17.491149 reason="" authen=1 author=0 acct=0.
  - debug connection 6: opened=before closed=open reason="" authen=1 author=0 acct=0.
  - debug connection 7: opened=16:46:19.855568 closed=16:46:19.857941 reason="" authen=0 author=0 acct=0.
  - debug connection 8: opened=before closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 9: opened=16:46:19.943526 closed=16:46:19.946242 reason="" authen=0 author=0 acct=0.
  - debug connection 10: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 11: opened=16:46:19.990370 closed=16:46:19.993622 reason="" authen=0 author=0 acct=0.
  - debug connection 12: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 13: opened=16:46:19.994853 closed=16:46:19.996889 reason="" authen=0 author=0 acct=0.
  - debug connection 14: opened=before closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 15: opened=16:46:20.052191 closed=16:46:20.054478 reason="" authen=0 author=0 acct=0.
  - debug connection 16: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 17: opened=16:46:20.098855 closed=16:46:20.101358 reason="" authen=0 author=0 acct=0.
  - debug connection 18: opened=before closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 19: opened=16:46:20.120947 closed=16:46:20.122824 reason="" authen=0 author=0 acct=0.
  - debug connection 20: opened=before closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 21: opened=16:46:25.414556 closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 22: opened=16:46:25.416532 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 23: opened=16:46:25.416836 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 24: opened=16:46:26.691174 closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 25: opened=16:46:26.692888 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 26: opened=16:46:26.693200 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 27: opened=16:46:26.944831 closed=open reason="" authen=0 author=1 acct=1.
  - debug connection 28: opened=16:46:48.122208 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 29: opened=16:46:48.371953 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 30: opened=16:46:48.372563 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 31: opened=16:46:50.023475 closed=16:46:50.531524 reason="" authen=1 author=0 acct=0.
  - debug connection 32: opened=before closed=open reason="" authen=1 author=0 acct=0.
  - debug connection 33: opened=16:46:58.554026 closed=16:46:58.555894 reason="" authen=0 author=0 acct=0.
  - debug connection 34: opened=16:47:00.481359 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 35: opened=16:47:00.482290 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 36: opened=16:47:00.484793 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 37: opened=16:47:00.485521 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 38: opened=16:47:05.799797 closed=open reason="" authen=0 author=1 acct=0.
  - debug connection 39: opened=16:47:05.802564 closed=open reason="" authen=0 author=0 acct=1.
  - debug connection 40: opened=16:47:05.802936 closed=open reason="" authen=0 author=0 acct=0.
  - capture: `conn port=60728 syn=16:46:58.554 hold=0.00s end=device-fin`
  - capture: `conn port=60742 syn=16:47:00.481 hold=0.00s end=server-rst`
  - capture: `conn port=60756 syn=16:47:00.482 hold=0.00s end=server-rst`
  - capture: `conn port=60770 syn=16:47:00.484 hold=0.00s end=server-rst`
  - capture: `conn port=60786 syn=16:47:00.485 hold=0.00s end=server-rst`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.

### Open questions

- **Which debug line marks a connection open?** `tls_token_login`: `2026-10-23 16:46:07.542887  1031 TacacsLib            6 TACACS+ counter connOpens host 172.100.100.1:300/0/Tacacs+ TLS` (14 in the cell); `tls_unknown_ca`: `2026-10-23 16:46:07.542887  1031 TacacsLib            6 TACACS+ counter connOpens host 172.100.100.1:300/0/Tacacs+ TLS` (30 in the cell).
- **tls_token_login: why does the device open a second connection?** The debug shows the second open at `2026-10-23 16:46:07.543426  1031 TacacsLib            6 TACACS+ counter connOpens host 172.100.100.1:300/0/Tacacs+ TLS`, after `2026-10-23 16:46:07.543338  1031 Tacacs               0 tac_send_acct failed: connect: Connection refused`. That is the line that comes before it, not a stated cause.
- **How does a connection end?** `tls_unknown_ca`: close `2026-10-23 16:46:09.705099  5684 TacacsLib            6 TACACS+ counter connCloses host 172.100.100.1:300/0/Tacacs+ TLS`; `tls_token_login`: close `2026-10-23 16:46:09.705099  5684 TacacsLib            6 TACACS+ counter connCloses host 172.100.100.1:300/0/Tacacs+ TLS`.
- **Do requests ride one connection together (pipelining)?** 2 of 23 debug connection(s) carried more than one request (27 request line(s)); first request line `2026-10-23 16:46:07.543338  1031 Tacacs               0 tac_send_acct failed: connect: Connection refused`.

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
- `show agent Aaa logs => _ state _`
- `show agent Aaa logs => _ default _`
- `show agent Aaa logs => _ sent _`
- `show agent Aaa logs => _ from _`
- `show agent Aaa logs => _ from _ failed _`
- `show agent Aaa logs => _ with _`
- `show agent Aaa logs => _ timeout _ timer expired _`
- `show agent Aaa logs => _ has _ timer _ timer timeout _`
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
- `show agent Aaa logs => _ error _ ssl _ failed _ error _ ssl _ ssl _ tls _`
- `show agent Aaa logs => _ tacacs _ tac _ send _ failed _ ssl _ failed _ error _ ssl _ ssl _ tls _`
- `show agent Aaa logs => _ tacacs _ ssl _ failed _ error _ ssl _ ssl _ tls _`
- `show agent Aaa logs => _ error _ ssl _ connect _ connection _ peer _`
- `show agent Aaa logs => _ tacacs _ ssl _ connect _ connection _ peer _`
- `show agent Aaa logs => _ accounting method _ group _ unavailable _ method for _ exec _ for _`
- `show agent Aaa logs => _ has _ request _`
- `show agent Aaa logs => _ request _`
- `show agent Aaa logs => _`
- `show agent Aaa logs => _ open _`
- `show agent Aaa logs => _ fail _`
- `show agent Aaa logs => _ close _`

