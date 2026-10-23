# QUAL-DEBUG — cisco_iosxe (iosxe1718, Catalyst 8000V 17.18.02)

Device debug (`debug tacacs`, `debug aaa authentication|authorization|accounting`, read with `show logging`) around
tls_token_login and tls_unknown_ca of a re-vet at port49 HEAD, 2026-10-23, one armed run (405 s). Evidence:
`tests/lab/evidence/QUAL-DEBUG-Catalyst-8000V-17.18.02-cisco_iosxe/` (header-only; the filter kept no device line).

- The log (315 and 364 lines) is boot and syslog text in `*Mon DD HH:MM:SS.mmm: %FACILITY-SEV-MNEMONIC: text` form. The
  filter's guessed `TAC+:`-style shapes match none of it, and no line of a `debug tacacs` exchange was among the shapes
  listed (exchange-related lines first). Two syslog shapes do speak of the connection: `... connection established with
  peer <addr>` and `... connection closed with peer <addr>`; the filter has no shape for them and the timestamps do not tie
  them to a cell (the buffer was cleared once, before debug went on, but the lines are not dated to the cell).
  An implementer must decide whether those two shapes join the allow-list.
- tls_unknown_ca ends device-fin where it ended server-rst: **unmeasured**. This armed run ended it server-rst (one
  connection), the original value, so the end is not stable between runs of the same image.
- tls_token_login: nine connections, each server-fin within 0.03 s (the debug-on login ran the probe commands at
  one pty); pipelining over one connection: **unmeasured**.
