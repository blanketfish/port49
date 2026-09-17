# juniper_vjunos-router — nothing measured

This is not a results note. It is the record of two attempts that measured nothing, so that
the next person does not repeat them expecting a different answer. No register entry closes
on this file, and spec §15 keeps every Junos row open.

- **Date attempted:** 2026-09-17
- **Platform:** juniper_vjunos-router (containerlab node `srx1`, 172.100.100.21)
- **Image version:** vJunos-router 23.4R2-S2.1 (`vrnetlab/juniper_vjunos-router:23.4R2-S2.1`)
- **Topology:** `tests/lab/topologies/vjunos.clab.yml`
- **Entries attempted:** L1, L5, L6, L8, L10. L2 skips on this platform by design (session-only,
  spec decision 21).
- **Captures:** every one holds 4 packets, all of them the harness's own loopback liveness
  probes. Not one packet crossed the management bridge.
- **Decision log:** `tests/lab/logs/decisions-juniper_vjunos-router.jsonl`, 0 lines.

## What happened

The device never completed an SSH handshake, so no login ever happened, so it never sent
port49 a TACACS packet. Every failing test reports the same error:

```
ssh: handshake failed: read tcp 172.100.100.1:54228->172.100.100.21:22: i/o timeout
```

The TCP connection to port 22 succeeds immediately, because vrnetlab forwards that port into
the nested VM from the moment the container starts. It is not evidence that Junos is up, and
on this image it is misleading: the port answers for the whole boot.

## Why: this image does not finish booting in a reasonable window on this host

Measured from the container's console, on the second attempt:

| milestone | elapsed after `containerlab deploy` |
|---|---|
| FreeBSD kernel up, config disk attached | about 4 minutes |
| Junos 23.4R2-S2.1 userland starts | about 10 minutes |
| package mounting begins | about 9 minutes |
| `mount done` | 35 minutes 2 seconds |
| SSH serving a handshake | never observed |

The first attempt ran with a 20-minute budget capped to an 8-minute readiness gate and gave up
at 8m23s. The second ran with a 35-minute budget and the cap removed; it gave up at 35m07s,
five seconds after the VM logged `mount done`. Junos still had to start its daemons and load
the configuration after that, so the real time-to-SSH is longer than 35 minutes here, and how
much longer is unmeasured.

For contrast, on the same host and the same harness, vEOS answers a breakglass login 57
seconds after deploy.

## What this does and does not say

It says nothing about how Junos behaves over TACACS+. The device was never reachable, so the
startup configuration in `tests/lab/configs/vjunos-startup.conf` was never confirmed applied
and no claim in it has been tested. In particular, do not read this as evidence about
`authentication-order`, `tacplus-server`, or the management routing instance.

It does say that measuring Junos on this host needs one of these first, and choosing between
them is a decision, not a detail:

- A boot budget set from a completed measurement of time-to-SSH, taken by deploying the
  topology alone and watching until SSH answers, rather than inside a test run.
- More CPU or memory for the nested VM, or a host where KVM is not itself inside a VM. This
  host runs Docker under WSL2, so Junos is a VM inside a VM.
- The smaller vSRX image instead, if it serves the same register entries.

## Reproducing

```sh
PORT49_LAB_PLATFORMS=vjunos make lab
```

The run is in `tests/lab/logs/run-vjunos.log` and the device console in
`docker logs clab-port49-vjunos-srx1` while the topology is up.
