# QUAL-DEBUG — arista_ceos (ceos436, cEOS-lab 4.36.3M)

One armed run, 2026-10-23, at port49 HEAD. `debug aaa` and `debug tacacs` are answered `% Invalid input` on this image (the
CLI has no such commands), and `show logging` lists only the facilities' logging levels; no TACACS+ line was in the 133 log
lines. The first armed run also sent the enable commands after port49d restarted, which refused two of them (fixed since;
the run was not repeated on EOS because the commands do not exist).

- Pipelining over one connection: **unmeasured**. tls_token_login: eight connections, each server-fin within 0.01 s (one per
  request, as in the re-vet). EOS's own tracing (`trace Aaa ...` into an agent log) is an implementer's step.

**Evidence and capture.** No `tests/lab/evidence/QUAL-DEBUG-*` directory is committed for this image: the run's directory was
removed in error before it was committed, and no further run was made because the debug commands do not exist. The facts
above (invalid input, 133 log lines, eight connections, server-fin within 0.01 s) are from that run's log, which is not kept.
The run's raw captures are in the main checkout under `tests/lab/captures/QUAL-DEBUG-ceos436/`.
