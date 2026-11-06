# L24 — juniper_vjunos-router

- **Date measured:** 2026-11-05
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Capture:** `tests/lab/evidence/L24-juniper_vjunos-router.pcap` — 462 packets to or from the device when this note was written (the finished file holds a few more: stopping the capture adds a probe pair), countable with `tcpdump -r tests/lab/evidence/L24-juniper_vjunos-router.pcap -n 'net 172.100.100.0/24' | wc -l`. A redacted copy of this run's capture: credential bytes overwritten with `x`, everything else byte-identical, decodable with the lab key (`tests/lab/README.md`).
- **Transport:** SSH
- **Run:** commit `a158aaf875a2e57e5d2f0a883e26f0db3fcae2b2-dirty`, `PORT49_LAB_PLATFORMS=vjunos,vsrx`, `-run ^TestL24JunosIdleTimeout$`

## Claim

A login class's `idle-timeout` ends an idle session a TACACS+ reply landed in that class, through `local-user-name` and through the `remote` template (spec §5.6; §13 decision 21).

## Observation

| path | reply | closed after the prompt | what the device said |
|---|---|---|---|
| local-user-name | `["local-user-name=p49-l24-idle"]` | 1m0s | `--- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil / alice01@srx1> Warning: session will be closed in 10 seconds if there is no activity / [H[JIdle timeout exceeded: closing session` |
| remote template | `[]` | 1m0s | `--- JUNOS 23.4R2-S2.1 Kernel 64-bit JNPR-12.1-20240604.39c9257_buil / alice02@srx1> Warning: session will be closed in 10 seconds if there is no activity / [H[JIdle timeout exceeded: closing session` |

