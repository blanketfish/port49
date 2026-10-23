# QUAL-DEBUG — arista_ceos (ceos436, cEOS-lab 4.36.3M)

One armed run, 2026-10-23, at port49 HEAD. `debug aaa` and `debug tacacs` are answered `% Invalid input` on this image (the
CLI has no such commands), and `show logging` lists only the facilities' logging levels; no TACACS+ line was in the 133 log
lines. The first armed run also sent the enable commands after port49d restarted, which refused two of them (fixed since;
the run was not repeated on EOS because the commands do not exist).

- Pipelining over one connection: **unmeasured**. tls_token_login: eight connections, each server-fin within 0.01 s (one per
  request, as in the re-vet). EOS's own tracing (`trace Aaa ...` into an agent log) is an implementer's step.
