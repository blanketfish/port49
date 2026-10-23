# QUAL-DEBUG — cisco_xrd (xrd261, XRd control plane 26.1.1)

`debug tacacs` and `debug aaa` (read with `show logging`) around tls_token_login and tls_unknown_ca of a re-vet at port49
HEAD, 2026-10-23. The first armed run failed in the enable (`clear logging` asks `[confirm] [y/n]` and XR rejects an empty
line; fixed to `y`); the second run (333 s) passed. Evidence: `tests/lab/evidence/QUAL-DEBUG-XRd-control-plane-26.1.1-cisco_xrd/`
(header-only; the filter kept no device line).

- The debug is on and works: 1692 and 611 log lines, many from `tacacsd[N]` (request received, server selected, socket
  connection to the TACACS+ server, "tls disabled" for a server, "server unavailable" errors). Each line begins
  `<node id> <Mon DD HH:MM:SS.mmm> <zone>: tacacsd[N]: <text>`. The filter's guessed shapes match none of them, so it kept
  0 lines (fails closed). An implementer must add the shapes with a security review.
- Pipelining over one connection: **unmeasured**. tls_token_login: 11 connections, each server-fin after 0.27 to 0.79 s,
  no connection reused (per-request, as in the re-vet), but the debug counts were not kept.
- tls_unknown_ca: three connections, all server-rst, which matches the re-vet (no change).
