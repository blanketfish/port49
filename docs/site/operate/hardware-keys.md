---
title: Hardware keys
description: Requiring a hardware key at sign-in and at each device login.
---

# Hardware keys

A person's session key can live on a YubiKey instead of in a file, and a device's policy can require a
touch on that key at login. This page is "set up your key": what the key is for, how
`port49 hwkey setup` and `port49 hwkey status` check it, and what can go wrong.

Only the client build of `port49` reads a YubiKey or a smartcard. The static build, which the server
package and the container image carry, cannot: `port49 hwkey` exits 2 there with a message saying it
was built without PKCS#11 support. [Install the clients](install/clients.md) says which build you
have and where to get the other, and how to find the PKCS#11 module (`libykcs11`) on Linux and macOS.

## Two keys on one token

A device that accepts `hardware_key_touch` needs two keys on the same YubiKey:

| Key | Slot | Policy | Config key |
|---|---|---|---|
| The session key, which signs the login and each refresh | `9a`, or `9e` where a site keeps it | PIN once, touch never | `issued_key` |
| The touch key, which signs a challenge from the broker for each device that asks | `9c` | touch always | `touch_key` |

The broker checks that both attestations chain to Yubico's roots and name the same device. A session
key in a file or in the TPM cannot satisfy it, and a policy that accepts only `hardware_key_touch`
locks that person out. The policy side is in the [`port49d` reference](../reference/config/port49d.md)
under `broker.identity.per_login_mfa`; the keys on the person's side are in the
[client reference](../reference/config/client.md).

## Check the key: `port49 hwkey status`

`status` reads the token and reports; it opens no key with the PIN and writes nothing to the token.

```sh
port49 hwkey status                 # human lines
port49 hwkey status --json          # one JSON object, for a script
port49 hwkey status --module <path-to>/libykcs11.so --token 1
```

Its first line says which attestation roots it will check against:

```text
roots: from broker broker.example.com:8443
module: <path-to>/libykcs11.so.2 (found)
token: <masked label>
ok    session_slot
...
ready
```

The roots are the broker's own, fetched over TLS and checked against the `broker_ca` in the person's
config, because a copy held by every user would drift from what the broker applies. They are public
certificates. The line is `roots: from broker <host>`, or `roots: --roots <file>` when `--roots FILE`
names a file instead; that is for offline use, and it wins over the broker. There is no config key
for roots. `--broker URL` names a different broker to ask.

Each line after is a check, `ok` or `FAIL` with a reason. The names are a closed set:
`session_slot`, `touch_slot`, `attestation_roots`, `session_attested`, `touch_attested`,
`touch_policy`, `same_token`, and, for `status` alone, `config_issued_key`, `config_touch_key`,
`issued_certificate`, `certificate_expiry` and `agent`. The attestation checks are the broker's own
code, so a key that passes here passes the broker's. A serial is never printed: every line, error
lines and `--json` reasons included, shows it masked.

`status` exits 0 when every check passes, 1 when something needs doing, and 2 on an error. The
[exit-code table](login.md#exit-codes) has the full list.

## Set it up: `port49 hwkey setup`

`setup` runs the same checks, and when all pass it writes `issued_key` and `touch_key` into the
person's own config file, and nothing else.

```sh
port49 hwkey setup
```

- **It changes only a file you own.** If `issued_key` or `touch_key` already names another key, it
  shows the old and new values and asks, at a terminal. With no terminal it changes nothing and exits 1.
  A key supplied by `/etc/port49/config.yaml` is reported, not edited: ask the administrator, or set
  the key in your own file.
- **When a check fails, it prints the commands to run.** The key is made with `ykman`, which asks for
  the management key; port49 never does, and never runs `ykman` itself:

  ```text
  # if 9a already holds a key, add its certificate (this replaces nothing):
  ykman piv certificates generate --subject "CN=port49 9a" 9a port49-9a.pub.pem
  # only if 9a holds no key, make one (this replaces any key already there):
  ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy NEVER 9a port49-9a.pub.pem
  ```

  That is what an empty session slot prints; slot `9c` prints the same with `--touch-policy ALWAYS`.
  port49 cannot tell an empty slot from a key that has no certificate, because `libykcs11` lists a
  slot's key only with a certificate in it, so it prints both lines, certificate first. Run the
  `keys generate` line only if the slot holds no key. No line names a serial, PIN, PUK or management
  key.

- **Which token and which module.** The module is found by `--module`, then the `module-path` of a key
  already in your config, then a probe of the system paths (not on macOS: pass `--module`). With more
  than one token present it lists them by number, model and masked label, exits 2, and wants
  `--token N`. A session key in the TPM, a file or the Secure Enclave is reported as not on a token.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | ready; for `setup`, the keys were written or already name this token |
| 1 | action needed: a check failed, no token is inserted, the session key is not on a token, or `setup` would replace a key and did not |
| 2 | an error, with a message: a bad flag, a config file that is refused, no roots, no module, a module that is refused, several tokens and no `--token`, a config write that fails |

The roots have their own messages, all exit 2, and each names the way out:

- `the broker <host> is unreachable, so the attestation roots could not be fetched: retry, or pass
  --roots FILE`: the broker did not answer. It is not a statement about the key.
- `the broker <host> did not present a certificate from the configured broker CA ...: check
  broker_ca, or pass --roots FILE`: a trust failure, not an outage. Do not work around it by
  pointing `--roots` at whatever file is to hand; find out why the certificate is not the broker's.
- `no attestation roots: the broker <host> serves none ...`: the broker does not verify
  `hardware_key_touch` at all, because `attestation_roots_file` is not set there.

## Logging in with the key

`port49 login` asks the key's PIN once, on the terminal, with echo off. The PIN goes to the agent on a
file descriptor and is zeroed after use. It is never on a command line, in the environment, or in a
log. A wrong PIN is sent once and never retried. The message says `fewer tries are left` after the
first wrong PIN and `one try is left before the key locks` after the second: the YubiKey measured
for this page reports the first as the token's low-tries flag and the second as its final-try flag.
A blocked PIN is unblocked with the PUK: `ykman piv access unblock-pin`.

When a device asks for a touch, `port49 token` and `port49 ssh` say `touch your key now`. The token
blinks. Touch it, or run the command again. On that YubiKey an untouched request ended after 14.4
seconds with `no touch within 15s; touch the key when it blinks and try again`, the key stayed
unlocked, no PIN try was spent, and a touch right after the timeout signed with no PIN.

### A wrong PIN typed anywhere on the machine logs the agent off the key

This is intended behaviour, not a fault to report. A mistyped PIN in another process, such as a
second terminal's `port49 login`, makes the token log the running agent's session off. The agent's
next refresh then says `your key needs its PIN: run port49 login`, and its status reads `locked`. This was seen with one
wrong PIN at a second `port49 login` on one YubiKey.

The instruction is to log in again with `port49 login`, which asks the PIN. A correct PIN typed in
another process did not do this. Until you have a reason to do otherwise, give each token to one
user at a time, and never let a script try a PIN on a token that an agent holds. A script that guesses
a wrong PIN on a timer logs the agent off every time and spends the token's tries. The second box
under "What has not been measured" lists what is still unknown about it.

## Two risks

**A lent key plus its PIN is the person's login.** The PIN is the only thing between whoever holds the
key and `port49 login` as that person, and the touch only proves that someone was at the key. A key that
was lent, lost or taken is the person's identity until it is revoked. Revoke the certificate or the
principal: see [Revocation](../concepts/revocation.md) and the runbook in
[Administer: revocation](../admin/revocation.md). Do not wait for the certificate to expire.

**A wrong attestation root checks the wrong thing.** `port49 hwkey` reports a key as ready against the
roots it was given, and `--roots FILE` replaces the broker's. A file with a root the broker does not
hold, or without one it does, makes `status` say ready for a key that the broker will refuse, or the
reverse. The broker applies its own roots whatever `status` said, so a wrong file cannot grant
anything; it can only waste an afternoon at the console. Use the broker's roots unless you are
offline, and when you are, take the file from the broker's administrator, not from the key.

## What has not been measured

!!! warning "Unmeasured"
    `port49 hwkey status` and `port49 hwkey setup` have not been run against a real YubiKey for this
    register entry: how they behave there, and whether `libykcs11` lists a slot's key when the slot
    holds no certificate, are unknown ([L91](../reference/lab-register.md#l91), open). The `ykman` lines above are what the commands
    print; treat them as a starting point and read `ykman piv info` before and after.

!!! warning "Unmeasured"
    The touch timeout, the low-tries flags and the wrong-PIN behaviour above were measured on one
    YubiKey 5C Nano FIPS, firmware 5.4.3, with libykcs11 2.7.2
    ([the lab note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L60-ser8.md)).
    Other tokens, other firmware and other libykcs11 versions are unknown ([L60](../reference/lab-register.md#l60), open). Also unknown:
    whether a `port49 login` to the running agent puts it back on the key after a wrong PIN typed in
    another process; whether `port49 token` still mints on the connection the agent already holds
    after it; and what other processes using the token do to the agent. Whether parallel forks, such
    as several Ansible workers sharing one agent, are asked for one touch or for several when a
    device requires `hardware_key_touch` is a question for [L60](../reference/lab-register.md#l60)'s next session. The agent sends one
    request to the broker at a time and batches the token requests queued behind it
    ([Identities](../concepts/identities.md)), but what the key does is not measured. A person runs `port49 ssh <device>` once for one such
    device before a play, as the Ansible collection's README says.

!!! warning "Unmeasured"
    On macOS, `port49` accepts a PKCS#11 module that the `admin` group can write, and no other group,
    because Homebrew's prefix is group-writable by `admin`. That exception's
    evidence is a CI run in which Homebrew's `libykcs11.dylib` was refused without the rule, and its
    hardware claims were measured on Linux. No register entry covers a YubiKey on a Mac, so whether
    a Homebrew Mac loads the module and signs in end to end is unknown.

!!! warning "Unmeasured"
    How the macOS Secure Enclave key store behaves on a Mac is unknown ([L63](../reference/lab-register.md#l63), open). It is experimental
    and opt-in.
