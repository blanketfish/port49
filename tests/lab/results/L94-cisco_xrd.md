# L94 — cisco_xrd

- **Date run:** 2026-11-12
- **Platform:** cisco_xrd (containerlab node `xrd1`)
- **Image version:** XRd control plane 26.1.1 (`port49lab/xrd-control-plane:26.1.1`)
- **Topology:** `tests/lab/topologies/xrd261.clab.yml`
- **Transport:** TACACS+ over TLS (RFC 9887), port 300, with `single-connection` configured on the device (`single`)
- **Run:** `PORT49_LAB_PLATFORMS=xrd261 go test -tags lab ./tests/lab/ -run '^TestL94$' -count=1 -v -timeout 300m`, with `PORT49_L94_ARM=baseline` and `PORT49_L94_ARM=fixed`
- **Evidence:** `tests/lab/evidence/L94-cisco_xrd/{baseline,fixed}/single/`, committed as a5671008 (baseline) and 4e06c91e (fixed)
- **Capture:** the fixed run's raw captures are kept, git-ignored, under `tests/lab/captures/L94-cisco_xrd-fixed/`; the baseline run's were replaced by the fixed run before they were copied

## Claim

Spec §15 L94 (decision 59, provisional on L94).

## Observation

**Not measured.** Both arms ended INVALID in c1 ("session 0 did not log in") before any cell was graded. The two arms are identical:

- port49 recorded no request from the device in the cell;
- the device logged `[tacacs_server_probe] 172.100.100.1/300: Probe thread failed in socket connect (errno=110) Connection timed out, sleeping for 20 seconds` as the cell began (baseline 11:07:36, fixed 11:14:51);
- about 20 s later the device opened one TLS connection and closed it itself within 10 ms (`end=device-fin` in `c1.tls.json`), with no request on it.

The cause is not established. A connect that times out, rather than being refused, means the device's SYNs went unanswered at that moment; whether that is the device's routing to port49's TLS address, the timing of port49d's start against the device's probe, or something else is not shown by this evidence. No request reached port49, so nothing here bears on reply order. Device debug of the TACACS+ TLS session is the next step.

## Result

L94 is not measured on XRd 26.1.1 and stays open for it.
