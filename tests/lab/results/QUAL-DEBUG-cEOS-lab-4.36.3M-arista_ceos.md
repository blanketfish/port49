# QUAL-DEBUG-cEOS-lab-4.36.3M — arista_ceos

- **Date measured:** 2026-10-23
- **Platform:** arista_ceos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** cEOS-lab 4.36.3M (`ceos:4.36.3M`)
- **Topology:** `tests/lab/topologies/ceos436.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-cEOS-lab-4.36.3M-arista_ceos.pcap` — 1741 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-cEOS-lab-4.36.3M-arista_ceos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `d4f0de986717a120349fe63b776bc06f01d75ba7`, `PORT49_LAB_PLATFORMS=ceos436`, `-run ^TestQualify$`

## Claim

What arista_ceos's own TACACS+ debug says about the TLS cells of a qualification run on cEOS-lab 4.36.3M: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform arista_ceos, image cEOS-lab 4.36.3M. Debug on: `terminal length 0`, `terminal width 511`, `clear agent Aaa logs`, `configure`, `trace Aaa setting *`, `end` (read with `show agent Aaa logs`; off with `configure`, `no trace Aaa setting *`, `end`).

### What the filter kept

- `tls_token_login`: the device returned 866 log lines and the filter kept 152 (0 connection open/close, 16 request, 136 other); the capture holds 8 TLS connection(s).
  Lines dropped by rule: facility=700 body_word=1 hex_view=15 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=0 closed=0 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=before closed=open reason="" authen=4 author=5 acct=7.
  - capture: `conn port=35034 syn=15:52:57.197 hold=0.00s end=server-fin`
  - capture: `conn port=35042 syn=15:52:59.857 hold=0.00s end=server-fin`
  - capture: `conn port=35054 syn=15:52:59.942 hold=0.00s end=server-fin`
  - capture: `conn port=35060 syn=15:52:59.989 hold=0.00s end=server-fin`
  - capture: `conn port=35066 syn=15:52:59.993 hold=0.00s end=server-fin`
  - capture: `conn port=35072 syn=15:53:00.051 hold=0.00s end=server-fin`
  - capture: `conn port=35078 syn=15:53:00.097 hold=0.00s end=server-fin`
  - capture: `conn port=35080 syn=15:53:00.122 hold=0.00s end=server-fin`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.
- `tls_unknown_ca`: the device returned 1803 log lines and the filter kept 283 (0 connection open/close, 32 request, 251 other); the capture holds 5 TLS connection(s).
  Lines dropped by rule: facility=1486 body_word=2 hex_view=34 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=0 closed=0 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=before closed=open reason="" authen=6 author=8 acct=18.
  - capture: `conn port=55038 syn=15:53:38.009 hold=0.00s end=device-fin`
  - capture: `conn port=55052 syn=15:53:39.746 hold=0.00s end=server-rst`
  - capture: `conn port=55066 syn=15:53:39.747 hold=0.00s end=server-rst`
  - capture: `conn port=55080 syn=15:53:39.748 hold=0.00s end=server-rst`
  - capture: `conn port=55090 syn=15:53:39.749 hold=0.00s end=server-rst`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.

### Open questions

- **Which debug line marks a connection open?** Unmeasured: no kept line is a connection open.
- **tls_token_login: why does the device open a second connection?** Unmeasured: the capture holds 8 connections and the kept debug marks 0 open(s).
- **How does a connection end?** Unmeasured: no kept line is a close or a TLS failure.
- **Do requests ride one connection together (pipelining)?** Unmeasured: 16 request line(s) were kept but no connection open, so none can be assigned to a connection.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 33 shape(s), the first 30

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
- `show agent Aaa logs => _ for method group _`
- `show agent Aaa logs => _ status _`

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
- `show agent Aaa logs => _ has _ request _`
- `show agent Aaa logs => _ request _`
- `show agent Aaa logs => _ error _ ssl _ connect _ connection _ peer _`
- `show agent Aaa logs => _ tacacs _ ssl _ connect _ connection _ peer _`
- `show agent Aaa logs => _ accounting method _ group _ unavailable _ method for _ exec _ for _`
- `show agent Aaa logs => _`
- `show agent Aaa logs => _ open _`
- `show agent Aaa logs => _ fail _`
- `show agent Aaa logs => _ close _`

