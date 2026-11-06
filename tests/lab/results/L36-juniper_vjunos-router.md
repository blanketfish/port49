# L36 — juniper_vjunos-router

- **Date measured:** 2026-11-06
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L36-juniper_vjunos-router.pcap` — 282 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L36-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestJunosReauthorizationAfterRestart$`

## Claim

On Junos with `tacplus-options authorization-time-interval 15`, an open session is re-authorized by the device after the port49d replica it logged in through restarts on etcd, and after the principal is revoked the next re-authorization is denied; what the device does with the session on a denial is recorded (plan 7e; spec §13 decision 21).

## Observation

| step | observed |
|---|---|
| 0. the device's TACACS+ servers, read back after the push | `set system tacplus-server 172.100.100.1 routing-instance mgmt_junos set system tacplus-server 172.100.100.1 secret <removed> set system tacplus-server 172.100.100.2 routing-instance mgmt_junos set system tacplus-server 172.100.100.2 secret <removed> breakglass@srx1> set system accounting events login set system accounting events change-log set system accounting events interactive-commands set system accounting destination tacplus server 172.100.100.1 routing-instance mgmt_junos set system accounting destination tacplus server 172.100.100.1 secret <removed> set system accounting destination tacplus server 172.100.100.2 routing-instance mgmt_junos set system accounting destination tacplus server 172.100.100.2 secret <removed> breakglass@srx1>` |
| 1. `set system tacplus-options authorization-time-interval 15`, a login through A (B stopped) | `logged in; 'show version': 6010 bytes in 200ms, first line 'Hostname: srx1'` |
| 2. A restarted; the first re-authorization request | `15m0s after the login, 14m59s after the restart: AUTHOR seq 1 -> PASS_ADD from 172.100.100.1 in 4ms` |
| 2. port49d A's records since the restart | `authorize_session [permit context_matched]; accounting [<nil> <nil> <nil> <nil> <nil> <nil>]` |
| 2. the session after the re-authorization, `show version` | `6010 bytes in 200ms, first line 'Hostname: srx1'` |
| 3. a second session logged in through A, then `port49 revoke --principal` through the broker's API (the first closed) | `target: user:alice@slice.port49.test (subject slice_operator); login 1s before the revocation` |
| 3. the second session's first re-authorization request | `15m0s after its login, 14m59s after the revocation: AUTHOR seq 1 -> FAIL from 172.100.100.1 in 1ms` |
| 3. port49d A's records since the revocation | `authorize_session [permit context_matched deny credential_revoked]` |
| 3. the session after the denial | `still open 60s after the denial; 'show version': 83 bytes in 100ms, first line '^'` |

