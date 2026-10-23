# QUAL-DEBUG — cisco_iosxe (iosxe1718, Catalyst 8000V 17.18.02)

`debug tacacs` and `debug aaa authentication|authorization|accounting` (read with `show logging`) around tls_token_login and
tls_unknown_ca of a re-vet at port49 HEAD, 2026-10-23, in four armed runs. The first ran the debug commands after port49d
restarted, and the device sent them to port49d, which refused them ("this session was not ... by port49"); the later runs
turn debug on first (local session). Evidence: `tests/lab/evidence/QUAL-DEBUG-Catalyst-8000V-17.18.02-cisco_iosxe/` (the
lines the filter kept, header-only wire facts).

- The debug works. The filter kept 90 lines (tls_token_login) and 66 (tls_unknown_ca) of the form `TPLUS: Queuing AAA
  Accounting request N for processing`, `TPLUS: processing authentication start request id N`, `TPLUS: Using server <lab addr>`,
  `TPLUS(...)/N/...: Started 5 sec timeout`. It kept no connection-level line, and its counters read 0 connections.
- The lines it drops include the connection lifecycle: `... got immediate connect on new <n>`, `... a connected socket`,
  `TACACS+ secure message: ... message type ... / ... occurred ...`, `server handle / name / addr` blocks, and
  `... queued` / `... processed`. Those need allow-list shapes (an implementer's change with a security review) before the
  second-connection and end-of-connection questions can be answered from the device.
- tls_unknown_ca ends device-fin where it ended server-rst: **unmeasured**. Armed runs ended it server-rst (twice) and
  device-fin (once), so the end is not stable between runs of one image.
- tls_token_login: nine connections, each server-fin within 0.03 s (one per request, as in the re-vet). Pipelining over one
  connection: **unmeasured** (the kept lines name requests, not the connection each rode).
