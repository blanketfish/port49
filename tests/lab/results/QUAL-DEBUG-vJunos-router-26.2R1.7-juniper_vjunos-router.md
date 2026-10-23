# QUAL-DEBUG — juniper_vjunos-router (vjunos26, vJunos-router 26.2R1.7)

Device debug around tls_token_login and tls_unknown_ca of a re-vet (4 armed runs, 3 of them with a summary written, 2026-10-23).
The committed evidence came from the last run, built at test commit f6152a73: debug was turned on after port49d restarted
and the readiness probe ran (before aa0a1b73 moved debug-on first, which matters for the IOS XE and XR commands but not for
the Junos trace, which is a configuration commit), so its summaries lack the readiness-probe line later runs write.
Evidence: `tests/lab/evidence/QUAL-DEBUG-vJunos-router-26.2R1.7-juniper_vjunos-router/` (header-only; the filter kept no
device line). Raw captures are in the main checkout's `tests/lab/captures/QUAL-DEBUG-vJunos-router-26.2R1.7-juniper_vjunos-router.pcap`.

- Debug enable: `set system tacplus-options traceoptions ...` is a syntax error on this image. `set system processes
  general-authentication-service traceoptions file ... flag all` commits and writes a log, but the log holds authd
  start-up and configuration lines only (327 and 173 lines): no line about a TACACS+ server, request or connection.
- Second connection of tls_token_login: **unmeasured**. It was present in all three armed runs that wrote a summary (opened 0.46 s,
  0.21 s and 4.7 s after the first; the first ended server-fin after 0.01 s), so it is not capture noise, but the trace does not show why.
- tls_unknown_ca ends: **unmeasured**. Armed runs saw two or three connections within 0.6 s: device-fin then
  server-rst, server-rst then server-rst, and a third server-rst; the first connection's end is not stable.
- Pipelining over one connection: **unmeasured** (no request lines in the trace).
