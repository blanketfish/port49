# L37 — arista_eos

- **Date measured:** 2026-10-04
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L37-arista_eos.pcap` — 496 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L37-arista_eos.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

On the split deployment (port49-broker and two port49d replicas on one etcd, the device listing both replicas as TACACS+ servers): a session opened through one replica has its next command answered by the other once the first stops; with the broker stopped an open session runs on and a token minted before the stop logs in; a revocation made on port49-broker denies the session's next command on either replica; and a port49d with no hold closes its listeners within `darkBound` (125.5s at the lab's `hold_ttl` 60s) of its store hanging, after which the device takes break-glass (plan 7e; spec §13 decision 36).

## Observation

| cell | observed |
|---|---|
| 0. the device's TACACS+ servers, read back after the push | `aaa group server tacacs+ port49 server 172.100.100.1 server 172.100.100.2 aaa authentication login default group port49 local aaa authentication enable default group port49 local aaa authorization exec default group port49 local aaa authorization commands all default group port49 local aaa accounting exec default start-stop group port49 aaa accounting commands all default start-stop group port49` |
| 1. mint through port49-broker, log in through A (B stopped, started after), `show version` | `printed its output in 100ms: 'Arista vEOS-lab'; A's record permit permit_dominates, ctx_id 2RMKU6XBPUU6YKOO / AUTHEN seq 1 -> GETPASS(5) from 172.100.100.1 in 0s; AUTHEN seq 3 -> PASS(1) from 172.100.100.1 in 5ms; ACCT seq 1 -> SUCCESS from 172.100.100.1 in 2ms; AUTHOR seq 1 -> PASS_ADD from 172.100.100.1 in 4ms; AUTHOR seq 1 -> PASS_ADD from 172.100.100.1 in 1ms; ACCT seq 1 -> SUCCESS from 172.100.100.1 in 0s; AUTHOR seq 1 -> PASS_ADD from 172.100.100.1 in 1ms; ACCT seq 1 -> SUCCESS from 172.100.100.1 in 1ms / connections: +0.02s to 172.100.100.1: accepted after 0s; +0.19s to 172.100.100.1: accepted after 0s; +0.23s to 172.100.100.1: accepted after 0s; +0.45s to 172.100.100.1: accepted after 0s; +0.45s to 172.100.100.1: accepted after 0s; +0.70s to 172.100.100.1: accepted after 0s; +0.70s to 172.100.100.1: accepted after 0s` |
| 2. A stopped, the open session's `show version` (attempt 1) | `printed its output in 100ms: 'Arista vEOS-lab'; B's record permit permit_dominates, ctx_id 2RMKU6XBPUU6YKOO (A's before: 2RMKU6XBPUU6YKOO) / AUTHOR seq 1 -> PASS_ADD from 172.100.100.2 in 3ms; ACCT seq 1 -> SUCCESS from 172.100.100.2 in 1ms / connections: +0.00s to 172.100.100.1: refused after 0s; +0.00s to 172.100.100.2: accepted after 0s; +0.01s to 172.100.100.1: refused after 0s; +0.01s to 172.100.100.2: accepted after 0s` |
| 3. A started, B stopped, the broker stopped: the open session's `show version`, then a login with a token minted before the stop | `printed its output in 100ms: 'Arista vEOS-lab'; record permit permit_dominates, ctx_id 2RMKU6XBPUU6YKOO (before: 2RMKU6XBPUU6YKOO); the login: err <nil>, redeem "token_redeemed" / AUTHOR seq 1 -> PASS_ADD from 172.100.100.1 in 2ms; ACCT seq 1 -> SUCCESS from 172.100.100.1 in 1ms; AUTHEN seq 1 -> GETPASS(5) from 172.100.100.1 in 0s; AUTHEN seq 3 -> PASS(1) from 172.100.100.1 in 4ms; ACCT seq 1 -> SUCCESS from 172.100.100.1 in 1ms; AUTHOR seq 1 -> PASS_ADD from 172.100.100.1 in 2ms; AUTHOR seq 1 -> PASS_ADD from 172.100.100.1 in 1ms; ACCT seq 1 -> SUCCESS from 172.100.100.1 in 1ms; ACCT seq 1 -> SUCCESS from 172.100.100.1 in 2ms / connections: +0.00s to 172.100.100.1: accepted after 0s; +0.01s to 172.100.100.1: accepted after 0s; +0.12s to 172.100.100.1: accepted after 0s; +0.14s to 172.100.100.1: accepted after 0s; +0.17s to 172.100.100.1: accepted after 0s; +0.23s to 172.100.100.1: accepted after 0s; +0.24s to 172.100.100.1: accepted after 0s; +0.25s to 172.100.100.1: accepted after 0s` |
| 4. `port49 revoke --principal` on the broker's socket | `revoked user:alice@slice.port49.test at 2026-10-04T20:13:22Z: 1 live context(s) marked, the unspent tokens under 0 (device, username) key(s) deleted, 0 held broker connection(s) closed; every mint by user:alice@slice.port49.test is refused until 'port49 revoke --lift --principal user:alice@slice.port49.test'` |
| 4. the session's next command on A | `refused in 100ms: '% Authorization denied for command 'show version': port49: this session was revoked - log in again'; records [deny credential_revoked] / AUTHOR seq 1 -> FAIL from 172.100.100.1 in 1ms / connections: +0.00s to 172.100.100.1: accepted after 0s` |
| 4. A stopped, the session's next command on B (attempt 1) | `refused in 100ms: '% Authorization denied for command 'show version': port49: this session was revoked - log in again'; records [deny credential_revoked] / AUTHOR seq 1 -> FAIL from 172.100.100.2 in 1ms / connections: +0.00s to 172.100.100.1: refused after 0s; +0.00s to 172.100.100.2: accepted after 0s` |
| 5. the store hangs: when each port49d's circuit opened and it closed its listeners | `A: circuit open at 50.4s, listeners closed at 2m0.4s (open to dark 1m10s); B: circuit open at 49.4s, listeners closed at 1m49.4s (open to dark 59.9s); bound 2m5.5s` |
| 5. both listeners closed, break-glass and `show version` | `login err <nil> in 100ms; printed 'Arista vEOS-lab' / no request in the capture / connections: +0.02s to 172.100.100.2: refused after 0s; +0.03s to 172.100.100.1: refused after 0s; +0.04s to 172.100.100.2: refused after 0s; +0.04s to 172.100.100.1: refused after 0s; +0.08s to 172.100.100.2: refused after 0s; +0.08s to 172.100.100.1: refused after 0s; +0.12s to 172.100.100.2: refused after 0s; +0.12s to 172.100.100.1: refused after 0s; +0.12s to 172.100.100.2: refused after 0s; +0.12s to 172.100.100.1: refused after 0s` |


## L35-recheck: step 3's cells and break-glass, on the device L37 left

Compared with L35-arista_eos.md, only step 3's cells are the same by design (reply times, the device's output text, break-glass); step 2's token (`token_redeemed`, not `token_not_found`), step 4's dark time and step 5's listening-again time differ on the split, and the daemon's start-line rows are the broker's. Row 0's readback shows no second server.

| step | observed |
|---|---|
| 0. the device's TACACS+ servers, read back before this run | `aaa group server tacacs+ port49 server 172.100.100.1 aaa authentication login default group port49 local aaa authentication enable default group port49 local aa…` |
| 0. the keyspace before the first process starts | `0 keys under /port49/` |
| 1. baseline, `show version` | `printed its output in 100ms: 'Arista vEOS-lab'` |
| 2. port49d's start lines | nothing |
| 2. after the restart, the open session's `show version` | `printed its output in 100ms: 'Arista vEOS-lab'; record permit permit_dominates, ctx_id VZJ5WKQPA5D7MOM3 (before: VZJ5WKQPA5D7MOM3)` |
| 2. a token minted before the port49d restart | `redeemed: token_redeemed` |
| 3. store hung, the open session's `show version` (attempt 1) | `refused in 600ms: '% Authorization denied for command 'show version': port49: authorization store unavailable'` |
| 3. store hung, a token login (attempt 1) | `ssh: handshake failed: ssh: unable to authenticate, attempted methods [none keyboard-interactive], no supported methods remain` |
| 3. store hung, break-glass and `show version` (attempt 1) | `login err <nil>; printed 'Authorization denied: port49: authorization store unavailable' (compare tests/lab/results/L4-error-arista_eos.md)` |
| 3. records | `authorize_command [deny store_unavailable]; redeem [deny store_unavailable deny store_unavailable]; authorize_session [deny store_unavailable]; accounting []` |
| 3. the open session's command, attempt 1 (hung 1s), request-to-reply from the capture | `ACCT seq 1 -> SUCCESS in 501ms; AUTHOR seq 1 -> FAIL in 500ms` |
| 3. the token login, attempt 1 (hung 1s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms` |
| 3. break-glass, attempt 1 (hung 1s), request-to-reply from the capture | `AUTHEN seq 1 -> GETPASS(5) in 0s; AUTHEN seq 3 -> ERROR(7) in 501ms; ACCT seq 1 -> SUCCESS in 502ms; AUTHOR seq 1 -> FAIL in 501ms` |
| 4. port49d's line | `1m52.8s after the hang: port49d: store: the daemon's context pool's circuit has been open for 1m0s (store: unavailable: no answer in 500ms); closing every listener so that devices use their local method / circuit open at 42.9s, listeners closed at 1m52.8s (open to dark 1m10s)` |
| 4. listeners closed, the open session's `show version` | `printed its output in 100ms: 'Arista vEOS-lab' (compare tests/lab/results/quarantine-arista_eos.md)` |
| 4. listeners closed, break-glass and `show version` | `login err <nil> in 100ms; printed 'Arista vEOS-lab'` |
| 5. port49d's start lines | `listening 2s after the store returned:` |
| 5. store back, the open session's `show version` | `printed its output in 100ms: 'Arista vEOS-lab'; record permit permit_dominates, ctx_id VZJ5WKQPA5D7MOM3` |

