# juniper_vsrx — no local account on this image has a password

This note used to claim that vSRX 21.4R3.15 will not fall through
`authentication-order [ tacplus password ]` to a local password. **That conclusion was wrong,
and this note now records the measurement that overturns it.** The observation it rested on —
`breakglass`, `admin` and `root` all refused over SSH with port49d not listening — is real and
reproduced. The explanation was not: on this image none of those accounts has a password at
all, so no login by password could have succeeded whatever `authentication-order` did.

The original note reached the wrong conclusion because it read the configuration with
`| except SECRET`, which filtered out exactly the lines that would have shown whether a
password exists. `authentication { }` printed empty, and an empty block was read as "the
filter removed the password" rather than "look closer".

- **Date:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Config under test:** `tests/lab/configs/vjunos-startup.conf` (shared by both Junos topologies)
- **Capture pointer:** none. This is a console session, not device traffic; nothing on the
  wire to capture. It closes no register entry, so CLAUDE.md rule 3 does not apply.

## What was done

One deploy by hand. The serial console (`ttyu0`, the container's telnet port 5000) driven
non-interactively, port49d never started, so the TACACS+ server was unreachable throughout.

### 1. `breakglass` on the console, with the password from the startup config

```
login: breakglass
Password:            <- the prompt was offered
Login incorrect
```

The console is worth testing separately from SSH because `root` gets a shell on it with no
password, so it is the one path known to work on this image.

### 2. The configuration, read WITHOUT `| except SECRET`

```
> show configuration system login user breakglass | no-more
uid 2002;
class super-user;
authentication {
    plain-text-password-value <value withheld>; ## SECRET-DATA
}
```

**There is no `encrypted-password` line.** The statement from the startup config is present in
the committed configuration, in the plain-text input form it was written in. Junos normally
converts that form to `encrypted-password "<hash>"` at commit; here it did not.

### 3. The system password database — the decisive read

Classified, never printed: the password field of `/etc/master.passwd`.

| account | password field |
|---|---|
| `root` | empty |
| `admin` | `*` |
| `breakglass` | `*` |
| `remote` | `*` |

`*` in that field is FreeBSD for "this account has no password and cannot authenticate with
one". **Not one local account on this image has a usable password.**

## What this means

The three SSH refusals in the original note are explained without reference to
`authentication-order` at all. `breakglass` and `admin` have no password to check. `root` has
an empty one, which sshd refuses by policy. Fall-through could have been working perfectly and
the result would have been identical.

So this note is not evidence about Junos fall-through. It is a **lab configuration defect**:
`plain-text-password-value` in `tests/lab/configs/vjunos-startup.conf` does not produce a
usable password on vSRX 21.4R3.15.

**It says nothing about vJunos-router 23.4R2-S2.1.** There, `breakglass` logs in, and a
successful login needs both a password that materialized and a fall-through that happened. The
positive result stands on its own; only the vSRX negative is withdrawn.

## Register entry L4

L4 stays open and now has **one** data point instead of two: vJunos-router 23.4R2-S2.1 falls
through to the local password with the TACACS+ server unreachable. The vSRX half is withdrawn
— not measured, not measurable while the account has no password. Unmeasured: vSRX
fall-through, fall-through on a *denial* rather than on an unreachable server, `deadtime`, and
every non-Junos platform.

The design's reference AAA configuration still must not be written as though local
fall-through is available on Junos generally — one platform, one condition is not a general
rule — but the reason is now "barely measured", not "measured to fail".

## What to do about it (not done here)

Not changed in this pass: changing the lab's startup config needs a lab run to verify, and
this was a single deploy for a single question. For whoever picks it up:

- Set the account with `encrypted-password "<hash>"` and a pre-computed hash instead of
  `plain-text-password-value`, then confirm `/etc/master.passwd` shows a hash for
  `breakglass` on **both** Junos images before relying on it.
- Until then, `breakglassPassword` in `tests/lab/harness_test.go` is dead weight on vSRX, and
  the readiness gate's narrow signal (an authentication rejection) is the only one that fires
  there. The gate is correct as written; this only explains why.
- Re-run the vSRX fall-through question once the account actually has a password. That is the
  measurement L4 wanted and has never had.
