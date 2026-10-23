# QUAL-DEBUG-vJunos-router-26.2R1.7 — juniper_vjunos-router

- **Date measured:** 2026-10-23
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 26.2R1.7 (`vrnetlab/juniper_vjunos-router:26.2R1.7`)
- **Topology:** `tests/lab/topologies/vjunos26.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-vJunos-router-26.2R1.7-juniper_vjunos-router.pcap` — 1016 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-vJunos-router-26.2R1.7-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `657c057edf50ac8ead06911b8c18be230ab6cb9c`, `PORT49_LAB_PLATFORMS=vjunos26`, `-run ^TestQualify$`

## Claim

What juniper_vjunos-router's own TACACS+ debug says about the TLS cells of a qualification run on vJunos-router 26.2R1.7: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform juniper_vjunos-router, image vJunos-router 26.2R1.7. Debug on: `set cli screen-width 300`, `clear log p49-tacplus.log`, `clear log p49-auth.log`, `configure`, `set system processes general-authentication-service traceoptions file p49-tacplus.log`, `set system processes general-authentication-service traceoptions flag all`, `set system syslog file p49-auth.log any any`, `commit and-quit` (read with `show log p49-tacplus.log`, `show log p49-auth.log`; off with `configure`, `delete system processes general-authentication-service traceoptions`, `delete system syslog file p49-auth.log`, `commit and-quit`, `clear log p49-tacplus.log`, `clear log p49-auth.log`).

### What the filter kept

- `tls_token_login`: the device returned 441 log lines and the filter kept 200 (0 connection open/close, 0 request, 200 other); the capture holds 2 TLS connection(s).
  Lines dropped by rule: facility=247 body_word=0 hex_view=1 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=0 closed=unknown single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - capture: `conn port=36914 syn=15:49:08.343 hold=0.01s end=server-fin`
  - capture: `conn port=36928 syn=15:49:08.665 hold=open end=open`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.
- `tls_unknown_ca`: the device returned 249 log lines and the filter kept 41 (0 connection open/close, 0 request, 41 other); the capture holds 2 TLS connection(s).
  Lines dropped by rule: facility=214 body_word=0 hex_view=1 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=0 closed=unknown single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - capture: `conn port=46160 syn=15:49:56.062 hold=0.01s end=device-fin`
  - capture: `conn port=46172 syn=15:49:56.067 hold=0.00s end=server-rst`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.

This platform's two debug files are joined in order, not merged by time, so a request is attributed to the last connection opened in the trace, not necessarily the one it was sent on; and neither file has a close line.

### Open questions

- **Which debug line marks a connection open?** Unmeasured: no kept line is a connection open.
- **tls_token_login: why does the device open a second connection?** Unmeasured: the capture holds 2 connections and the kept debug marks 0 open(s).
- **How does a connection end?** Unmeasured: this platform's debug has no close line, and no kept line states a TLS failure.
- **Do requests ride one connection together (pipelining)?** Unmeasured: no kept line is a request.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 64 shape(s), the first 30

- `show log p49-tacplus.log => _ server _ name _`
- `show log p49-tacplus.log => _ accounting _`
- `show log p49-tacplus.log => _ authd _ server _ name _ server _`
- `show log p49-tacplus.log => _ connect fail _`
- `show log p49-tacplus.log => _ connect _`
- `show log p49-tacplus.log => _ connection state _`
- `show log p49-tacplus.log => _ authd _`
- `show log p49-tacplus.log => _ authd _ create _`
- `show log p49-tacplus.log => _ created authd _`
- `show log p49-tacplus.log => _`
- `show log p49-tacplus.log => _ created _`
- `show log p49-tacplus.log => _ auth _ create _`
- `show log p49-tacplus.log => _ start authd _`
- `show log p49-tacplus.log => _ timer _`
- `show log p49-tacplus.log => _ authd _ state _ timer _`
- `show log p49-tacplus.log => _ authd _ and new _`
- `show log p49-tacplus.log => _ host _ name _`
- `show log p49-tacplus.log => _ name _`
- `show log p49-tacplus.log => _ send _ not _`
- `show log p49-tacplus.log => _ default _`
- `show log p49-tacplus.log => _ for _ default _`
- `show log p49-tacplus.log => _ default _ default _`
- `show log p49-tacplus.log => _ authd _ auth _`
- `show log p49-tacplus.log => _ authd _ not _`
- `show log p49-tacplus.log => _ not _`
- `show log p49-tacplus.log => _ opened _`
- `show log p49-tacplus.log => _ address _`
- `show log p49-tacplus.log => _ state _`
- `show log p49-tacplus.log => _ sent _`
- `show log p49-tacplus.log => _ default _ default _ default _`

`tls_unknown_ca`: 54 shape(s), the first 30

- `show log p49-tacplus.log => _ server _ name _`
- `show log p49-tacplus.log => _ accounting _`
- `show log p49-tacplus.log => _ authd _ server _ name _ server _`
- `show log p49-tacplus.log => _ connect fail _`
- `show log p49-tacplus.log => _ connect _`
- `show log p49-tacplus.log => _ connection state _`
- `show log p49-tacplus.log => _`
- `show log p49-tacplus.log => _ authd _`
- `show log p49-tacplus.log => _ authd _ create _`
- `show log p49-tacplus.log => _ created authd _`
- `show log p49-tacplus.log => _ created _`
- `show log p49-tacplus.log => _ auth _ create _`
- `show log p49-tacplus.log => _ start authd _`
- `show log p49-tacplus.log => _ timer _`
- `show log p49-tacplus.log => _ authd _ state _ timer _`
- `show log p49-tacplus.log => _ authd _ and new _`
- `show log p49-tacplus.log => _ host _ name _`
- `show log p49-tacplus.log => _ name _`
- `show log p49-tacplus.log => _ send _ not _`
- `show log p49-tacplus.log => _ default _`
- `show log p49-tacplus.log => _ for _ default _`
- `show log p49-tacplus.log => _ for _`
- `show log p49-tacplus.log => _ default _ default _`
- `show log p49-tacplus.log => _ authd _ auth _`
- `show log p49-tacplus.log => _ authd _ not _`
- `show log p49-tacplus.log => _ not _`
- `show log p49-tacplus.log => _ opened _`
- `show log p49-tacplus.log => _ address _`
- `show log p49-tacplus.log => _ state _`
- `show log p49-tacplus.log => _ sent _`

