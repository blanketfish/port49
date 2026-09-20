# juniper_vsrx — the startup config was applied, and why every vSRX note says it was not

Every `L<N>-juniper_vsrx.md` in this directory carries this caveat:

> **Caveat:** could not confirm the startup config was applied: breakglass never logged in
> within 8m54s (last error: ssh: handshake failed: ssh: unable to authenticate ...)

That is a true statement about the harness and a misleading one about the device. The
configuration **was** applied, in full. This note is the evidence, so that the caveat is not
read as doubt about the measurements it sits above.

- **Date:** 2026-09-20
- **Platform:** juniper_vsrx (containerlab node `vsrx1`, 172.100.100.22)
- **Image version:** vSRX3 21.4R3.15 (`vrnetlab/juniper_vsrx:21.4R3.15`)
- **Topology:** `tests/lab/topologies/vsrx.clab.yml`
- **Config under test:** `tests/lab/configs/vjunos-startup.conf` (shared by both Junos topologies)

## Why the gate could not pass

`waitConfigApplied` proves the startup config reached the device by logging in as the local
`breakglass` account **before** port49d starts. That works only if Junos falls through
`authentication-order [ tacplus password ]` to the local password while the TACACS+ server is
not answering. vJunos-router 23.4R2-S2.1 does that. vSRX 21.4R3.15 does not.

With nothing listening on 172.100.100.1:49 — so the device's TACACS+ connection was refused
immediately, the clearest possible "server is not there" — every local account was refused
over SSH:

```
breakglass  (password from tests/lab/configs/vjunos-startup.conf) -> ssh: unable to authenticate
admin       (password from the vrnetlab image's /init.conf)       -> ssh: unable to authenticate
root        (password from the vrnetlab image's /init.conf)       -> ssh: unable to authenticate
```

Tried three times across a minute, roughly three minutes after vrnetlab reported
`Startup complete in: 0:00:57`.

## The configuration, read off the device while it was refusing those logins

Junos admits `root` on the serial console (`ttyu0`) without a password, so the console is a
path that does not depend on `authentication-order` at all. Over the container's console port:

```
> show configuration system authentication-order
authentication-order [ tacplus password ];

> show configuration system login | except SECRET
class p49-readonly { permissions [ view view-configuration ]; }
user admin      { uid 2000; class super-user; authentication { } }
user breakglass { uid 2002; class super-user; authentication { } }
user remote     { uid 2001; class p49-readonly; }

> show configuration system tacplus-server
172.100.100.1 {
    routing-instance mgmt_junos;
    secret "$9$GcUH..."; ## SECRET-DATA
}
```

Every statement is present: the authentication order with `password` second, the `breakglass`
account the gate was trying to use, the `remote` template user, and the TACACS+ server with
its management routing instance.

## What confirms it independently

Once the gate gave up and port49d started listening, the device authenticated over TACACS+ on
the first try — `TestLoginRoundTrip` passed with 44 packets between the device and port49d,
and all six register tests then measured. A device that had not applied this file could not
have done that: the `tacplus-server` statement it used is in this file.

So the device's authentication path was working the whole time. What it would not do was fall
back to a local password with the server unreachable.

## What this is and is not

This is not a results note and closes no register entry. The behavior it records is the first
evidence this project has on register entry **L4** — whether a Junos `authentication-order`
with `password` listed falls through to local — and L4 stays open: one platform, one
condition, and the other half of the question (fall-through on a *denial* rather than on an
unreachable server) unmeasured.

It does mean the reference AAA configuration in the design must not be written as though
local fall-through is available on Junos generally. On this image, with port49 down, only the
console gets in.
