# L94 — cisco_iosxe

- **Date run:** 2026-11-12
- **Platform:** cisco_iosxe (containerlab node `xe1`)
- **Image version:** Catalyst 8000V 17.18.02 (`vrnetlab/cisco_c8000v:17.18.02`)
- **Topology:** `tests/lab/topologies/iosxe1718.clab.yml`
- **Transport:** TACACS+ over TLS (RFC 9887), port 300, with `single-connection` configured on the device (`single`)
- **Run:** `PORT49_LAB_PLATFORMS=iosxe1718 go test -tags lab ./tests/lab/ -run '^TestL94$' -count=1 -v -timeout 300m`, with `PORT49_L94_ARM=baseline` and `PORT49_L94_ARM=fixed`
- **Evidence:** `tests/lab/evidence/L94-cisco_iosxe/{baseline,fixed}/single/`, committed as c8883a32 (baseline) and fd017d24 (fixed)
- **Capture:** the fixed run's raw captures are kept, git-ignored, under `tests/lab/captures/L94-cisco_iosxe-fixed/`; the baseline run's were replaced by later runs before they were copied

## Claim

Spec §15 L94 (decision 59, provisional on L94).

## Observation

**Not measured.** Both arms ended INVALID in c1 ("session 0 did not log in") before any cell was graded. The two arms are identical:

- port49 recorded no request from the device in the cell;
- the device's TACACS+ debug shows 20 `TAC+: Handle TACACS+ Secure Message: ... Conn-Timeout` lines inside one second (baseline 10:04:21–10:04:22, fixed 11:01:04–11:01:05), as the test's logins started.

So the device gave up on its TLS connection to port49 before it sent a request, on the build before decision 59 as on the build with it. The cause is not established: it is somewhere in the device's TLS session to port49 in this harness, not in how port49 orders replies, because no request reached port49 to be answered. Device debug of the TLS session (not run here) is the next step before anything is said about IOS-XE's behaviour.

## Result

L94 is not measured on IOS-XE 17.18.02 and stays open for it.
