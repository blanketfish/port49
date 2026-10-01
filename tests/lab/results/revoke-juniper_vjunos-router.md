# revoke — juniper_vjunos-router

- **Date measured:** 2026-10-01
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Image ID:** `sha256:9e62ec961b57369bb35379a404503cf13baf788af70fdba9a6d49c3f4e7a203c`
- **Run:** at commit e4326e6, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run TestRevokeEndToEnd -count=1 -timeout 45m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/revoke-juniper_vjunos-router.pcap` — 1684 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/revoke-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

A revocation by principal or by certificate (`port49 revoke` over the admin socket, plan 7a; spec §5.1.4) reaches a live SSH session and everything behind it: on a platform that authorizes each command the session's next command is refused and the session stays open; on Junos the open session keeps what it had at login (spec §13 decision 21), and the revocation names it as not reached; a token minted before the revocation and not yet spent is deleted, so its login is refused token_not_found; the revocation closes the agent's held broker connection; the agent's next mint, on a new connection, is answered 401 credential_revoked by the broker's listener as it binds, the agent ends on it, and a second `port49 token` finds no agent; and after a lift a new login works.

## Observation

| Step | What happened |
|---|---|
| `show version` before the revocation | printed its output in 200ms: `Junos: 23.4R2-S2.1` |
| `port49 revoke --principal user:alice@slice.port49.test` | exit 0; report below |
| `show version` in the same session after it | printed its output in 200ms: `Junos: 23.4R2-S2.1` |
| a login with a token minted before it, unspent | refused, `token_not_found` |
| the agent's next mint | a 401 credential_revoked, which ended the agent's session: `port49 token: the session is over; run 'port49 login': this principal was revoked at 2026-10-01T16:01:22Z; nothing is minted for it until an operator lifts the …`; the agent exited; a second `port49 token`: `port49 token: no agent at /tmp/p49revoke641538642/a/agent.sock; run 'port49 login' (exit: exit status 1)` |
| `port49 login` before the lift | refused: `port49 agent: the session is over; run 'port49 login': this principal was revoked at 2026-10-01T16:01:22Z; nothing is minted for it until an operator lifts the …` |
| `port49 revoke --lift`, then a new agent, a mint and a login | logged in and ran show version |
| `port49 revoke --cert` (the agent's certificate), then the agent's mint | a 401 credential_revoked, which ended the agent's session: `port49 token: the session is over; run 'port49 login': this certificate was revoked at 2026-10-01T16:01:29Z; nothing is minted for it until an operator lifts th…`; the agent exited; a second `port49 token`: `port49 token: no agent at /tmp/p49revoke1623496831/a/agent.sock; run 'port49 login' (exit: exit status 1)` |

Records: 2 revoke for the principal, 2 for the certificate, 0 authorize_command deny credential_revoked, 3 mint deny credential_revoked. port49d's stderr: 1 line(s) of the listener closing a revoked connection as it bound (at most one per 10 s; later ones are counted on the next).

The principal's revocation report, as `port49 revoke` printed it:

```
revoked user:alice@slice.port49.test at 2026-10-01T16:01:22Z: 1 live context(s) marked, the unspent tokens under 1 (device, username) key(s) deleted, 1 held broker connection(s) closed; every mint by user:alice@slice.port49.test is refused until `port49 revoke --lift --principal user:alice@slice.port49.test`
not reached, on a platform that never asks port49 about a command (close these on the device): srx1 (slice01)
```

The certificate's:

```
port49 revoke: tests/lab/logs/slice-pki/client.pem: subject "CN=alice@slice.port49.test", issuer "CN=port49 lab slice CA", serial 1085c7dbdfa563e3
revoked the certificate issuer="CN=port49 lab slice CA" serial=1085c7dbdfa563e3 (as the broker compares it) at 2026-10-01T16:01:29Z: 1 live context(s) marked, the unspent tokens under 0 (device, username) key(s) deleted, 1 held broker connection(s) closed; every mint with this certificate is refused until `port49 revoke --lift --cert-issuer "CN=port49 lab slice CA" --cert-serial 1085c7dbdfa563e3`
not reached, on a platform that never asks port49 about a command (close these on the device): srx1 (slice01)
```

