# L81 — reference clients

- **Date measured:** 2026-10-22
- **Platform:** reference clients on the lab host, no device (cell a only)
- **Image version:** OpenSSL 3.5.5 27 Jan 2026 (Library: OpenSSL 3.5.5 27 Jan 2026); Go go1.26.8
- **Capture:** tests/lab/evidence/L81-reference/
- **Run:** commit `399a9abdac9047bd7e5fe827f8c8f5d7430b5b52`, `PORT49_LAB_PLATFORMS=`, `-run ^TestL81IPv6ServerName$`

## Claim

spec §15 L81 (a). Cell (b), vJunos-router 26.2 over IPv6, is unmeasured here, so the row stays open.

## Observation

| cell | claim | observed | agrees with decision 50 |
|---|---|---|---|
| a | openssl s_client -servername <IPv6 literal> against a listener whose server_names lists it in another spelling: accepted. An unlisted one is refused with the alert (best-effort, recorded) and sni_mismatch, and the next connection inside the window is reset at Accept, with no strike and no second record. | server_names [tacacs.l72.example, 2001:db8::1]. openssl -servername 2001:0DB8:0:0::1: 1 ok handshakes, 0 sni_mismatch records; first line "Protocol version: TLSv1.3" (evidence/L81-reference/openssl-accepted.txt). -servername 2001:0DB8:0:0::2: 1 sni_mismatch records, detail names the spelling sent: true; record: {"ts":"2026-10-22T02:08:12.993Z","event":"unvalidated","device":{"nas":"127.0.0.1","name":"tls-dev","platform":"arista_eos","transport":"tls"},"unvalidated":{"source":"127.0.0.1","diagnosis":"tls_refused","type":0,"seq_no":0,"session_id":0,"length":0,"transport":"tls","tls_outcome":"sni_mismatch","detail":"asked for server name 2001:0DB8:0:0::2"}}; alert: 40D72BCB93750000:error:0A000438:SSL routines:ssl3_read_bytes:tlsv1 alert internal error:../ssl/record/rec_layer_s3.c:918:SSL alert number 80 (evidence/L81-reference/openssl-refused.txt). The next connection at once: declined_refused +1, held_refused +0; alert: (no alert line) (evidence/L81-reference/openssl-again.txt) | yes |
