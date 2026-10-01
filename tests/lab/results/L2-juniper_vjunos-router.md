# L2 — juniper_vjunos-router

- **Date measured:** 2026-10-01
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Image ID:** `sha256:9e62ec961b57369bb35379a404503cf13baf788af70fdba9a6d49c3f4e7a203c`
- **Run:** at commit ec50053, from a detached worktree pinned to it (`make build` there), on beehive: `PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run TestL2Truncation -count=1 -timeout 90m -v` (under `sg docker -c`)
- **Credentials:** no token, password or key appears in this note; tokens are named only by the decision log's `credential_sha256`, and the capture's credential fields are redacted
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L2-juniper_vjunos-router.pcap` — 2258 packets to or from the device, countable with `tcpdump -r tests/lab/evidence/L2-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH

## Claim

Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates.

## Observation

Each length on a port49d of its own, started on the standing lab config with `lab.deny_message_length: N` and `lab.deny_session: true`: Junos never authorizes a command (decision 21), so the session authorization itself fails with the padded message, and what the login printed is recorded. The message is `port49: denied by lab deny_session; see 'port49 explain'`, a space, and `0123456789` repeated to N bytes, so the last digit shown says where the device cut.

| N (bytes) | The record | Longest prefix shown | Where it ends, and what follows | What the device printed |
|---|---|---|---|---|
| 64 | authorize_session deny, 64-byte server_msg | 0 | — | `[shell, still open after 30 s] --- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil alice01@srx1>` |
| 128 | authorize_session deny, 128-byte server_msg | 0 | — | `[shell, still open after 30 s] --- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil alice01@srx1>` |
| 200 | authorize_session deny, 200-byte server_msg | 0 | — | `[shell, still open after 30 s] --- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil alice01@srx1>` |
| 255 | authorize_session deny, 255-byte server_msg | 0 | — | `[shell, still open after 30 s] --- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil alice01@srx1>` |
| 256 | authorize_session deny, 256-byte server_msg | 0 | — | `[shell, still open after 30 s] --- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil alice01@srx1>` |
| 512 | authorize_session deny, 512-byte server_msg | 0 | — | `[shell, still open after 30 s] --- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil alice01@srx1>` |
| 1000 | authorize_session deny, 1000-byte server_msg | 0 | — | `[shell, still open after 30 s] --- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil alice01@srx1>` |

**Not measurable: session-only (decision 21).** The session denial carried the padded message at every length, and the login printed none of it, so the device's display and its truncation length are not observed on this image. The login reached an operational-mode prompt (`@srx1>`) at 7 of 7 lengths all the same: the device does not refuse a login whose session authorization fails (`tests/lab/results/junos-session-service-juniper_vjunos-router.md`, phase C), so a session denial shows the operator nothing at all.

### Break-glass around long session denials

The owner's production prior: on Junos a reply over 255 bytes locked the user out. Break-glass was proved before each length over 255 and after the last, the run stopping at the first length that left it refused. This run sent a long *deny* `server_msg`, which Junos ignores (above); the prior concerns a long *permit* reply, which this run never sent. These rows show only that a long session denial did not lock break-glass out; they neither confirm nor refute the prior.

| When | Break-glass |
|---|---|
| before N=64 | logged in and ran them |
| before N=256 | logged in and ran them |
| before N=512 | logged in and ran them |
| before N=1000 | logged in and ran them |
| after N=1000 | logged in and ran them |

port49d, port49 and port49-inventory built from `ec50053` (`make build`).

