# QUAL-DEBUG-Catalyst-8000V-17.18.02 — cisco_iosxe

- **Date measured:** 2026-10-23
- **Platform:** cisco_iosxe (containerlab node `xe1`, 172.100.100.41)
- **Image version:** Catalyst 8000V 17.18.02 (`vrnetlab/cisco_c8000v:17.18.02`)
- **Topology:** `tests/lab/topologies/iosxe1718.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-Catalyst-8000V-17.18.02-cisco_iosxe.pcap` — 1212 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-Catalyst-8000V-17.18.02-cisco_iosxe.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `04b232442ca2b55cc150af221adf0ed8e2138382`, `PORT49_LAB_PLATFORMS=iosxe1718`, `-run ^TestQualify$`

## Claim

What cisco_iosxe's own TACACS+ debug says about the TLS cells of a qualification run on Catalyst 8000V 17.18.02: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform cisco_iosxe, image Catalyst 8000V 17.18.02. Debug on: `terminal length 0`, `terminal width 511`, `clear logging`, `<enter>`, `debug tacacs`, `debug aaa authentication`, `debug aaa authorization`, `debug aaa accounting` (read with `show logging`; off with `undebug all`).

### What the filter kept

- `tls_token_login`: the device returned 716 log lines and the filter kept 281 (4 connection open/close, 27 request, 250 other); the capture holds 9 TLS connection(s).
  Lines dropped by rule: facility=297 body_word=0 hex_view=138 hex_message=0 evidence_marker=2 known_value_hex=0.
  - debug connections opened=2 closed=2 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=before closed=open reason="" authen=3 author=0 acct=14.
  - debug connection 2: opened=16:59:01.053 closed=16:59:01.557 reason="" authen=1 author=0 acct=0.
  - debug connection 3: opened=before closed=open reason="" authen=3 author=0 acct=0.
  - debug connection 4: opened=16:59:13.920 closed=16:59:13.922 reason="" authen=1 author=0 acct=0.
  - debug connection 5: opened=before closed=open reason="" authen=0 author=1 acct=4.
  - capture: `conn port=35884 syn=16:59:13.913 hold=0.02s end=server-fin`
  - capture: `conn port=35888 syn=16:59:13.940 hold=0.02s end=server-fin`
  - capture: `conn port=35902 syn=16:59:13.966 hold=0.02s end=server-fin`
  - capture: `conn port=35914 syn=16:59:14.300 hold=0.02s end=server-fin`
  - capture: `conn port=35924 syn=16:59:14.325 hold=0.07s end=server-fin`
  - capture: `conn port=35930 syn=16:59:14.550 hold=0.03s end=server-fin`
  - capture: `conn port=35940 syn=16:59:14.580 hold=0.02s end=server-fin`
  - capture: `conn port=35952 syn=16:59:14.800 hold=0.02s end=server-fin`
  - capture: `conn port=35958 syn=16:59:14.944 hold=0.03s end=server-fin`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 2.
- `tls_unknown_ca`: the device returned 492 log lines and the filter kept 199 (4 connection open/close, 21 request, 174 other); the capture holds 1 TLS connection(s).
  Lines dropped by rule: facility=197 body_word=0 hex_view=96 hex_message=0 evidence_marker=2 known_value_hex=0.
  - debug connections opened=2 closed=2 single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - debug connection 1: opened=before closed=open reason="" authen=3 author=0 acct=14.
  - debug connection 2: opened=17:00:26.309 closed=17:00:26.812 reason="" authen=1 author=0 acct=0.
  - debug connection 3: opened=before closed=open reason="" authen=3 author=0 acct=0.
  - debug connection 4: opened=17:00:39.469 closed=17:00:39.469 reason="" authen=0 author=0 acct=0.
  - capture: `conn port=51294 syn=17:00:39.421 hold=0.06s end=server-rst`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 2.

### Open questions

- **Which debug line marks a connection open?** `tls_token_login`: `*Oct 23 16:59:01.053: %<LONG>: TACACS SECURE connection established with peer 172.100.100.1` (2 in the cell); `tls_unknown_ca`: `*Oct 23 17:00:26.309: %<LONG>: TACACS SECURE connection established with peer 172.100.100.1` (2 in the cell).
- **tls_token_login: why does the device open a second connection?** The debug shows the second open at `*Oct 23 16:59:13.920: %<LONG>: TACACS SECURE connection established with peer 172.100.100.1`, after `*Oct 23 16:59:13.897: TPLUS: Source IP selected is: 10.0.0.15`. That is the line that comes before it, not a stated cause.
- **How does a connection end?** `tls_unknown_ca`: close `*Oct 23 17:00:26.812: %<LONG>: TACACS SECURE connection closed with peer 172.100.100.1`; `tls_token_login`: close `*Oct 23 16:59:01.557: %<LONG>: TACACS SECURE connection closed with peer 172.100.100.1`.
- **Do requests ride one connection together (pipelining)?** 3 of 5 debug connection(s) carried more than one request (27 request line(s)); first request line `*Oct 23 16:58:26.077: TPLUS: Accounting request created for 4034(breakglass)`.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 73 shape(s), the first 30

- `show logging => tls _`
- `show logging => _ tplus _ socket bind _ for secure transactions _`
- `show logging => _ tplus _ connected socket _`
- `show logging => _ tplus _ immediate connect _ new _`
- `show logging => _ tplus _ processing the reply packet _`
- `show logging => _ tac _ server handle _`
- `show logging => _ tac _ A _ author _ start queued _`
- `show logging => _ tac _ author _ start processed _`
- `show logging => _ author _ auth _ addr _ A _ list _ author _ type _`
- `show logging => _ author _ cmd _ port _ list _ service _ cmd _`
- `show logging => _ author _ cmd _`
- `show logging => _ author _ cmd _ send _ service _ shell _`
- `show logging => _ author _ cmd _ send _ cmd _ debug _`
- `show logging => _ author _ cmd _ send _ cmd _ arg _`
- `show logging => _ author _ cmd _ send _ cmd _ arg _ accounting _`
- `show logging => _ author _ cmd _ list _ default _`
- `show logging => _ author _ cmd _ method _ tacacs _`
- `show logging => _ author _ authorization status _ error _`
- `show logging => _ author _ cmd _ method _`
- `show logging => _ accounting method _ tacacs _`
- `show logging => _ session _ for cmd _`
- `show logging => _ cmd _ session _`
- `show logging => _ cmd _ reply fail _`
- `show logging => _ accounting method _ not _`
- `show logging => _ send _ accounting _`
- `show logging => _ session _ for _`
- `show logging => _ session _`
- `show logging => _ session _ for exec _`
- `show logging => _ exec _ accounting _ not sent _`
- `show logging => _ socket _ message sent _ tacacs _`

`tls_unknown_ca`: 61 shape(s), the first 30

- `show logging => tls _`
- `show logging => _ tplus _ socket bind _ for secure transactions _`
- `show logging => _ tplus _ connected socket _`
- `show logging => _ tplus _ immediate connect _ new _`
- `show logging => _ tplus _ processing the reply packet _`
- `show logging => _ tac _ server handle _`
- `show logging => _ tac _ A _ author _ start queued _`
- `show logging => _ tac _ author _ start processed _`
- `show logging => _ author _ auth _ addr _ A _ list _ author _ type _`
- `show logging => _ author _ cmd _ port _ list _ service _ cmd _`
- `show logging => _ author _ cmd _`
- `show logging => _ author _ cmd _ send _ service _ shell _`
- `show logging => _ author _ cmd _ send _ cmd _ debug _`
- `show logging => _ author _ cmd _ send _ cmd _ arg _`
- `show logging => _ author _ cmd _ send _ cmd _ arg _ accounting _`
- `show logging => _ author _ cmd _ list _ default _`
- `show logging => _ author _ cmd _ method _ tacacs _`
- `show logging => _ author _ authorization status _ error _`
- `show logging => _ author _ cmd _ method _`
- `show logging => _ session _ for cmd _`
- `show logging => _ cmd _ session _`
- `show logging => _ accounting method _ tacacs _`
- `show logging => _ cmd _ reply fail _`
- `show logging => _ accounting method _ not _`
- `show logging => _ send _ accounting _`
- `show logging => _ session _ for _`
- `show logging => _ session _`
- `show logging => _ session _ for exec _`
- `show logging => _ exec _ accounting _ not sent _`
- `show logging => _ socket _ message sent _ tacacs _`

