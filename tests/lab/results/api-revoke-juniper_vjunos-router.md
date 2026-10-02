# api-revoke — juniper_vjunos-router

- **Date measured:** 2026-10-02
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Image ID:** `sha256:9e62ec961b57369bb35379a404503cf13baf788af70fdba9a6d49c3f4e7a203c`
- **Run:** at commit 0529b92, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=vjunos go test -tags lab -run TestAPIRevokeEndToEnd -count=1 -timeout 60m -v ./tests/lab/` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/api-revoke-juniper_vjunos-router.pcap` — 568 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/api-revoke-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

The HTTP revocation (`POST /v1/tokens/revoke`, plan 7c; spec §5.1.4, §13 decision 34) reaches a live SSH session as the admin socket's does, under the caller's api: rights: a peer with no right who names the operator is refused 403 api_right_missing and the operator's next command still runs; the operator's `port49 revoke --mine` refuses the open session's next command on a platform that authorizes each command (Junos keeps what it had at login and the report names it), refuses the unspent token token_not_found, and leaves no mark, so a token minted after it logs in at once, and that login re-admits the session the revocation refused, whose next command runs again (decision 15's join; the report says to close such a session first); a peer's key revocation without the right is refused 403 as well; an on-call holding revoke_others ends the operator's session by (device, username) with no mark, and the operator logs in again at once; and the on-call's revocation of the principal is a standing mark with the on-call as its origin, which ends the operator's agent until a lift.

## Observation

| Step | What happened |
|---|---|
| carol (no right): `port49 revoke --via-agent --principal user:alice@slice.port49.test` | exit 1: `port49 revoke: refused: revoking another principal needs the api: revoke_others right, which your subject does not declare` |
| carol (no right): `--via-agent --device srx1 --username slice01` | exit 1: `port49 revoke: refused: ending a (device, username) whoever holds it needs the api: revoke_others right, which your subject does not declare; for your own sessi…` |
| alice's `show version` after both | printed its output in 200ms: `Junos: 23.4R2-S2.1` |
| alice: `port49 revoke --mine` | exit 0; report below |
| alice's `show version` in the same session after it | printed its output in 200ms: `Junos: 23.4R2-S2.1` |
| a login with a token minted before it, unspent | refused, `token_not_found` |
| a login with a token minted after it | logged in |
| the session `--mine` refused, after that login | printed its output in 200ms: `Junos: 23.4R2-S2.1` |
| bob (revoke_others): `--via-agent --device srx1 --username slice01` | exit 0; report below |
| a login after the key revocation | logged in and ran show version |
| bob: `--via-agent --principal user:alice@slice.port49.test` | exit 0; `--list` names `api user:bob@slice.port49.test` |
| alice's agent's next mint | a 401 credential_revoked, which ended the agent's session: `port49 token: the session is over: this principal was revoked at 2026-10-02T07:08:54Z; nothing is minted for it until an operator lifts the revocation (port49 r…`; the agent exited |
| a lift on the admin socket, a new agent, a mint and a login | logged in and ran show version |

Revoke records by `by` and reason: map[key api_right_missing:1 key credential_revoked:1 principal api_right_missing:1 principal credential_revoked:1 principal revocation_lifted:1 self credential_revoked:1].

`port49 revoke --mine` printed:

```
ended user:alice@slice.port49.test's sessions everywhere at 2026-10-02T07:08:35Z: 1 live context(s) marked, the unspent tokens under 1 (device, username) key(s) deleted; nothing stands against user:alice@slice.port49.test, so a new `port49 token` and login work at once
your next login on a device re-admits every session open there under your username: if anyone else used your token, close their session on the device (or ask an operator to revoke your principal) before you log in there again
not reached, on a platform that never asks port49 about a command (close these on the device): srx1 (slice01)
```

The key revocation:

```
target: user:alice@slice.port49.test (subject slice_operator)
ended the session on srx1 (slice01), user:alice@slice.port49.test's, at 2026-10-02T07:08:53Z: 1 live context(s) marked, the unspent tokens under 0 key(s) deleted; no revocation stands, so its owner can mint and log in again (to stop that, revoke the principal)
the owner's next login on srx1 re-admits any session still open on it under slice01; close it on the device
not reached, on a platform that never asks port49 about a command (close these on the device): srx1 (slice01)
```

The principal's:

```
target: user:alice@slice.port49.test (subject slice_operator)
revoked user:alice@slice.port49.test at 2026-10-02T07:08:54Z: 1 live context(s) marked, the unspent tokens under 0 (device, username) key(s) deleted, 1 held broker connection(s) closed; every mint by user:alice@slice.port49.test is refused until `port49 revoke --lift --principal user:alice@slice.port49.test`
the lift is made on port49d's admin socket (/home/rwendt/git/port49/.worktrees/lab-7c-t13/tests/lab/logs/api-revoke-admin.sock), by port49d's user or root
not reached, on a platform that never asks port49 about a command (close these on the device): srx1 (slice01)
```

