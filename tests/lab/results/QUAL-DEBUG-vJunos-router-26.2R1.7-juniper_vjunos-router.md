# QUAL-DEBUG-vJunos-router-26.2R1.7 — juniper_vjunos-router

- **Date measured:** 2026-10-24
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 26.2R1.7 (`vrnetlab/juniper_vjunos-router:26.2R1.7`)
- **Topology:** `tests/lab/topologies/vjunos26.clab.yml`
- **Capture:** `tests/lab/evidence/QUAL-DEBUG-vJunos-router-26.2R1.7-juniper_vjunos-router.pcap` — 1012 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/QUAL-DEBUG-vJunos-router-26.2R1.7-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `0d02d9036879632accfbcdbd3bb52abf9f6d1114`, `PORT49_LAB_PLATFORMS=vjunos26`, `-run ^TestQualify$`

## Claim

What juniper_vjunos-router's own TACACS+ debug says about the TLS cells of a qualification run on vJunos-router 26.2R1.7: which debug line marks a connection, how many requests ride one connection, and how a connection ends. Every line quoted is one the platform's debug filter kept: it carries the platform's TACACS+/AAA facility, and the run's secrets, reversible encodings and long runs were redacted or masked in it.

## Observation

Platform juniper_vjunos-router, image vJunos-router 26.2R1.7. Debug on: `set cli screen-width 300`, `clear log tacacs-traceoptions`, `clear log p49-auth.log`, `configure`, `set system processes general-authentication-service traceoptions flag ?`, `set system processes general-authentication-service traceoptions file tacacs-traceoptions`, `set system processes general-authentication-service traceoptions flag all`, `set system syslog file p49-auth.log any any`, `commit and-quit` (read with `show log tacacs-traceoptions`, `show log p49-auth.log`; off with `configure`, `delete system processes general-authentication-service traceoptions`, `delete system syslog file p49-auth.log`, `commit and-quit`, `clear log tacacs-traceoptions`, `clear log p49-auth.log`).

### What the filter kept

- `tls_token_login`: the device returned 450 log lines and the filter kept 314 (0 connection open/close, 5 request, 309 other); the capture holds 2 TLS connection(s).
  Lines dropped by rule: facility=135 body_word=0 hex_view=6 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=0 closed=unknown single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - traceoptions flag words the CLI offered: address-assignment all configuration framework gx-plus jsrc ldap lib-stats local-authentication nas-5g nasreq ocs-backup profile-db radius s6a saml session-db syntax user-access.
  - syslog process tags (counts only): mgd=60 jlaunchd=28 sshd=26 authd=6 auditd=5 rpd=4 kernel=3 alarmd=2 ppmd=2 nas5g=1 recovery=1 sdk-vmmd=1 sync-event=1 other=315.
  - debug connection 1: opened=before closed=unknown reason="" authen=0 author=0 acct=5.
  - capture: `conn port=56862 syn=04:01:57.178 hold=0.01s end=server-fin`
  - capture: `conn port=56870 syn=04:01:57.395 hold=open end=open`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.
- `tls_unknown_ca`: the device returned 246 log lines and the filter kept 157 (0 connection open/close, 2 request, 155 other); the capture holds 2 TLS connection(s).
  Lines dropped by rule: facility=88 body_word=0 hex_view=6 hex_message=0 evidence_marker=0 known_value_hex=0.
  - debug connections opened=0 closed=unknown single_connect_lines=0 server_dead_lines=0 fallback_lines=0.
  - traceoptions flag words the CLI offered: address-assignment all configuration framework gx-plus jsrc ldap lib-stats local-authentication nas-5g nasreq ocs-backup profile-db radius s6a saml session-db syntax user-access.
  - syslog process tags (counts only): mgd=38 sshd=35 jlaunchd=9 authd=5 auditd=2 clear-log=2 alarmd=1 kernel=1 nas5g=1 recovery=1 sync-event=1 other=155.
  - debug connection 1: opened=before closed=unknown reason="" authen=0 author=0 acct=2.
  - capture: `conn port=41408 syn=04:02:44.612 hold=0.01s end=server-rst`
  - capture: `conn port=41416 syn=04:02:44.618 hold=0.00s end=server-rst`
  - readiness probe connections after debug went on, before the cell (in the log, not in the cell's TLS connections): 1.

This platform's two debug files are joined in order, not merged by time, so a request is attributed to the last connection opened in the trace, not necessarily the one it was sent on; and neither file has a close line.

### Open questions

- **Which debug line marks a connection open?** Unmeasured: no kept line is a connection open.
- **tls_token_login: why does the device open a second connection?** Unmeasured: the capture holds 2 connections and the kept debug marks 0 open(s).
- **How does a connection end?** Unmeasured: this platform's debug has no close line, and no kept line states a TLS failure.
- **Do requests ride one connection together (pipelining)?** Unmeasured: 5 request line(s) were kept but no connection open, so none can be assigned to a connection.

### Shapes of the lines the filter dropped

Closed alphabet: a vocabulary word, `A` for an address and `_` for any other span; no value is in them.

`tls_token_login`: 64 shape(s), the first 30

- `show log tacacs-traceoptions => _ server _ name _`
- `show log tacacs-traceoptions => _ accounting _`
- `show log tacacs-traceoptions => _ authd _ server _ name _ server _`
- `show log tacacs-traceoptions => _ connect fail _`
- `show log tacacs-traceoptions => _ connect _`
- `show log tacacs-traceoptions => _ connection state _`
- `show log tacacs-traceoptions => _ authd _`
- `show log tacacs-traceoptions => _ authd _ create _`
- `show log tacacs-traceoptions => _ created authd _`
- `show log tacacs-traceoptions => _`
- `show log tacacs-traceoptions => _ created _`
- `show log tacacs-traceoptions => _ auth _ create _`
- `show log tacacs-traceoptions => _ start authd _`
- `show log tacacs-traceoptions => _ timer _`
- `show log tacacs-traceoptions => _ authd _ state _ timer _`
- `show log tacacs-traceoptions => _ authd _ and new _`
- `show log tacacs-traceoptions => _ host _ name _`
- `show log tacacs-traceoptions => _ name _`
- `show log tacacs-traceoptions => _ send _ not _`
- `show log tacacs-traceoptions => _ default _`
- `show log tacacs-traceoptions => _ for _ default _`
- `show log tacacs-traceoptions => _ default _ default _`
- `show log tacacs-traceoptions => _ authd _ auth _`
- `show log tacacs-traceoptions => _ authd _ not _`
- `show log tacacs-traceoptions => _ not _`
- `show log tacacs-traceoptions => _ opened _`
- `show log tacacs-traceoptions => _ address _`
- `show log tacacs-traceoptions => _ state _`
- `show log tacacs-traceoptions => _ sent _`
- `show log tacacs-traceoptions => _ default _ default _ default _`

`tls_unknown_ca`: 52 shape(s), the first 30

- `show log tacacs-traceoptions => _ server _ name _`
- `show log tacacs-traceoptions => _ accounting _`
- `show log tacacs-traceoptions => _ authd _ server _ name _ server _`
- `show log tacacs-traceoptions => _ connect fail _`
- `show log tacacs-traceoptions => _ connect _`
- `show log tacacs-traceoptions => _ connection state _`
- `show log tacacs-traceoptions => _`
- `show log tacacs-traceoptions => _ authd _`
- `show log tacacs-traceoptions => _ authd _ create _`
- `show log tacacs-traceoptions => _ created authd _`
- `show log tacacs-traceoptions => _ created _`
- `show log tacacs-traceoptions => _ auth _ create _`
- `show log tacacs-traceoptions => _ start authd _`
- `show log tacacs-traceoptions => _ timer _`
- `show log tacacs-traceoptions => _ authd _ state _ timer _`
- `show log tacacs-traceoptions => _ authd _ and new _`
- `show log tacacs-traceoptions => _ host _ name _`
- `show log tacacs-traceoptions => _ name _`
- `show log tacacs-traceoptions => _ send _ not _`
- `show log tacacs-traceoptions => _ default _`
- `show log tacacs-traceoptions => _ for _ default _`
- `show log tacacs-traceoptions => _ for _`
- `show log tacacs-traceoptions => _ default _ default _`
- `show log tacacs-traceoptions => _ authd _ auth _`
- `show log tacacs-traceoptions => _ authd _ not _`
- `show log tacacs-traceoptions => _ not _`
- `show log tacacs-traceoptions => _ opened _`
- `show log tacacs-traceoptions => _ address _`
- `show log tacacs-traceoptions => _ state _`
- `show log tacacs-traceoptions => _ sent _`

