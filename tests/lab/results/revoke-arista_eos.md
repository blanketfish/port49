# revoke — arista_eos

- **Date measured:** 2026-10-01
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Image ID:** `sha256:8ef33020ece8871b19ddfdddf7f3585b04d2ac3672845b0db88debe8e96ff9c9`
- **Run:** at commit 5ccd2ef, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run TestRevokeEndToEnd -count=1 -timeout 45m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/revoke-arista_eos.pcap` — 334 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/revoke-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`). The run's own count was 314: the last 20 packets are the TACACS+ accounting connection the device opened when the test closed the SSH session, which happened after the test had counted the capture and written this note (fix round 1 corrects the count; the evidence is unchanged).
- **Transport:** SSH

## Claim

A revocation by principal or by certificate (`port49 revoke` over the admin socket, plan 7a; spec §5.1.4) reaches a live SSH session and everything behind it: on a platform that authorizes each command the session's next command is refused and the session stays open; on Junos the open session keeps what it had at login (spec §13 decision 21), and the revocation names it as not reached; a token minted before the revocation and not yet spent is deleted, so its login is refused token_not_found; the revocation closes the agent's held broker connection; the agent's next mint, on a new connection, is answered 401 credential_revoked by the broker's listener as it binds, the agent ends on it, and a second `port49 token` finds no agent; and after a lift a new login works.

## Observation

| Step | What happened |
|---|---|
| `show version` before the revocation | printed its output in 100ms: `show version` |
| `port49 revoke --principal user:alice@slice.port49.test` | exit 0; report below |
| `show version` in the same session after it | refused in 100ms: `% Authorization denied for command 'show version': port49: this session was revoked - log in again` |
| a login with a token minted before it, unspent | refused, `token_not_found` |
| the agent's next mint | a 401 credential_revoked, which ended the agent's session: `port49 token: the session is over; run 'port49 login': this principal was revoked at 2026-10-01T15:35:11Z; nothing is minted for it until an operator lifts the …`; the agent exited; a second `port49 token`: `port49 token: no agent at /tmp/p49revoke736698148/a/agent.sock; run 'port49 login' (exit: exit status 1)` |
| `port49 revoke --lift`, then a new agent, a mint and a login | logged in and ran show version |
| `port49 revoke --cert` (the agent's certificate), then the agent's mint | a 401 credential_revoked, which ended the agent's session: `port49 token: the session is over; run 'port49 login': this certificate was revoked at 2026-10-01T15:35:12Z; nothing is minted for it until an operator lifts th…`; the agent exited; a second `port49 token`: `port49 token: no agent at /tmp/p49revoke3111907016/a/agent.sock; run 'port49 login' (exit: exit status 1)` |

Records: 2 revoke for the principal, 2 for the certificate, 1 authorize_command deny credential_revoked, 2 mint deny credential_revoked. port49d's stderr: 1 line(s) of the listener closing a revoked connection as it bound (at most one per 10 s; later ones are counted on the next).

The principal's revocation report, as `port49 revoke` printed it:

```
revoked user:alice@slice.port49.test at 2026-10-01T15:35:11Z: 1 live context(s) marked, the unspent tokens under 1 (device, username) key(s) deleted, 1 held broker connection(s) closed; every mint by user:alice@slice.port49.test is refused until `port49 revoke --lift --principal user:alice@slice.port49.test`
```

The certificate's:

```
port49 revoke: tests/lab/logs/slice-pki/client.pem: subject "CN=alice@slice.port49.test", issuer "CN=port49 lab slice CA", serial 272a542d5b99c552
revoked the certificate issuer="CN=port49 lab slice CA" serial=272a542d5b99c552 (as the broker compares it) at 2026-10-01T15:35:12Z: 1 live context(s) marked, the unspent tokens under 0 (device, username) key(s) deleted, 1 held broker connection(s) closed; every mint with this certificate is refused until `port49 revoke --lift --cert-issuer "CN=port49 lab slice CA" --cert-serial 272a542d5b99c552`
```

