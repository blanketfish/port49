---
title: Hardware keys
description: Keep the session key on a YubiKey, check it with port49 hwkey, and meet a device's touch requirement.
---

# Hardware keys

A person's session key can live on a YubiKey instead of in a file, and a device's policy can require a
touch on that key at login. Only the client build of `port49` reads a YubiKey or a smartcard. The static
build exits 2 on `port49 hwkey` and says it was built without PKCS#11 support, so
[install the client](install-client.md) build and its PKCS#11 module (`libykcs11`) first.

## Two keys on one token

A device that accepts `hardware_key_touch` needs two keys on the same YubiKey:

| Key | Slot | Policy | Config key |
|---|---|---|---|
| The session key, which signs the login and each refresh | `9a`, or `9e` where a site keeps it | PIN once, touch never | `issued_key` |
| The touch key, which signs a challenge from the broker for each device that asks | `9c` | touch always | `touch_key` |

The broker checks that both attestations chain to Yubico's roots and name the same device. A session key in
a file or in the TPM cannot satisfy it, and a policy that accepts only `hardware_key_touch` locks that
person out. The policy side is under `broker.identity.per_login_mfa` in the
[`port49d` reference](../reference/config/port49d.md), and the person's keys are in the
[client reference](../reference/config/client.md).

## 1. Check the key

`port49 hwkey status` reads the token and reports. It opens no key with the PIN and writes nothing.

```sh
port49 hwkey status                 # human lines
port49 hwkey status --json          # one JSON object, for a script
port49 hwkey status --module <path-to>/libykcs11.so --token 1
```

To check, the output ends with `ready`. Its first line says which attestation roots it checks against:

```text
roots: from broker broker.example.com:8443
module: <path-to>/libykcs11.so.2 (found)
token: <masked label>
ok    session_slot
...
ready
```

The roots are the broker's own, fetched over TLS and checked against the `broker_ca` in your config. The
line is `roots: from broker <host>`, or `roots: --roots <file>` when `--roots FILE` names a file instead,
which is for offline use and wins over the broker. There is no config key for roots, and `--broker URL`
names a different broker to ask.

Each line after is a check, `ok` or `FAIL` with a reason: `session_slot`, `touch_slot`,
`attestation_roots`, `session_attested`, `touch_attested`, `touch_policy`, `same_token`, and, for `status`
alone, `config_issued_key`, `config_touch_key`, `issued_certificate`, `certificate_expiry` and `agent`.
The attestation checks are the broker's own code, so a key that passes here passes the broker's. A serial is
always shown masked. The exit codes are in [Client commands](../reference/client-commands.md#exit-codes).

The roots have their own messages, all exit 2, and each names the way out:

- `the broker <host> is unreachable, so the attestation roots could not be fetched: retry, or pass
  --roots FILE` means the broker did not answer. It says nothing about the key.
- `the broker <host> did not present a certificate from the configured broker CA ...: check broker_ca, or
  pass --roots FILE` is a trust failure, not an outage. Find out why the certificate is not the broker's
  before pointing `--roots` at any file.
- `no attestation roots: the broker <host> serves none ...` means the broker does not verify
  `hardware_key_touch`, because `attestation_roots_file` is not set there.

A wrong `--roots FILE` can make `status` say ready for a key the broker will refuse, or the reverse. It
cannot grant anything, because the broker applies its own roots. Take the file from the broker's
administrator, not from the key.

## 2. Set the key up

`port49 hwkey setup` runs the same checks, and when all pass it writes `issued_key` and `touch_key` into
your own config file and nothing else.

```sh
port49 hwkey setup
```

To check, run `port49 hwkey status` again and look for `ready`.

- If `issued_key` or `touch_key` already names another key, `setup` shows the old and new values and asks at
  a terminal. With no terminal it changes nothing and exits 1. A key supplied by `/etc/port49/config.yaml` is
  reported, not edited: ask the administrator, or set the key in your own file.
- When a check fails, it prints the commands to run. The key is made with `ykman`, which asks for the
  management key. port49 never asks for it and never runs `ykman` itself.

  ```text
  # if 9a already holds a key, add its certificate (this replaces nothing):
  ykman piv certificates generate --subject "CN=port49 9a" 9a port49-9a.pub.pem
  # only if 9a holds no key, make one (this replaces any key already there):
  ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy NEVER 9a port49-9a.pub.pem
  ```

  Slot `9c` prints the same with `--touch-policy ALWAYS`. `libykcs11` lists a slot's key only with a
  certificate in it, so port49 cannot tell an empty slot from a key with no certificate and prints both
  lines, certificate first. Run the `keys generate` line only if the slot holds no key.
- With more than one token present, `setup` lists them by number, model and masked label, exits 2, and wants
  `--token N`. A session key in the TPM, a file or the Secure Enclave is reported as not on a token.

## 3. Log in with the key

`port49 login` asks the key's PIN once, on the terminal, with echo off. The PIN goes to the agent on a file
descriptor and is zeroed after use. It is never on a command line, in the environment, or in a log. A wrong
PIN is sent once and never retried. The message says `fewer tries are left` after the first wrong PIN and
`one try is left before the key locks` after the second. A blocked PIN is unblocked with the PUK:
`ykman piv access unblock-pin`.

A reconnect to the broker is another use of the key, so the agent asks for the PIN or a touch again if its
connection drops. [The session](../concepts/tokens-receipts-contexts.md#the-session) says when that happens.

When a device asks for a touch, `port49 token` and `port49 ssh` say `touch your key now` and the token
blinks. Touch it, or run the command again. On the measured YubiKey an untouched request ended after 14.4
seconds with `no touch within 15s; touch the key when it blinks and try again`, the key stayed unlocked, no
PIN try was spent, and a touch right after the timeout signed with no PIN.

!!! warning "A wrong PIN typed anywhere on the machine logs the agent off the key"
    A mistyped PIN in another process, such as a second terminal's `port49 login`, makes the token log the
    running agent's session off. The agent's next refresh then says `your key needs its PIN: run port49
    login`, and its status reads `locked`. This is intended behaviour, so log in again with `port49 login`.
    Give each token to one user at a time, and never let a script try a PIN on a token that an agent holds,
    because a script that guesses a wrong PIN on a timer logs the agent off every time and spends the
    token's tries.

!!! warning "A lent key plus its PIN is the person's login"
    The PIN is the only thing between whoever holds the key and `port49 login` as that person, and the touch
    only proves that someone was at the key. Revoke the certificate or the principal as soon as a key is
    lent, lost or taken: see [Revocation](../concepts/revocation.md) and
    [Administer: revocation](../admin/revocation.md). Do not wait for the certificate to expire.

## What has not been measured

!!! warning "Unmeasured"
    `port49 hwkey status` and `port49 hwkey setup` have not been run against a real YubiKey for this
    register entry. How they behave there, and whether `libykcs11` lists a slot's key when the slot holds no
    certificate, are unknown ([L91](../reference/lab-register.md#l91), open). The `ykman` lines above are what
    the commands print. Treat them as a starting point and read `ykman piv info` before and after.

!!! warning "Unmeasured"
    The touch timeout, the low-tries flags and the wrong-PIN behaviour above were measured on one YubiKey 5C
    Nano FIPS, firmware 5.4.3, with libykcs11 2.7.2
    ([the lab note](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L60-ser8.md)). Other
    tokens, other firmware and other libykcs11 versions are unknown ([L60](../reference/lab-register.md#l60), open). Also unknown:
    whether a `port49 login` to the running agent puts it back on the key after a wrong PIN typed in another
    process; whether `port49 token` still mints on the connection the agent already holds after it; and what
    other processes using the token do to the agent. Whether parallel forks, such as several Ansible workers
    sharing one agent, are asked for one touch or for several when a device requires `hardware_key_touch` is
    a question for [L60](../reference/lab-register.md#l60)'s next session. The agent sends one request to the broker at a time and batches the
    token requests queued behind it ([Many devices at once](connect.md#many-devices-at-once)), but what the
    key does is not measured. A mint whose caller gave up after its batch was sent is still minted for the
    others' sake. That token goes unused, and the person can revoke it. A person runs `port49 ssh <device>`
    once for one such device before a play, as the Ansible collection's README says.

!!! warning "Unmeasured"
    On macOS, `port49` accepts a PKCS#11 module that the `admin` group can write, and no other group, because
    Homebrew's prefix is group-writable by `admin`. That exception's evidence is a CI run in which Homebrew's
    `libykcs11.dylib` was refused without the rule, and its hardware claims were measured on Linux. No
    register entry covers a YubiKey on a Mac, so whether a Homebrew Mac loads the module and signs in end to
    end is unknown.

!!! warning "Unmeasured"
    How the macOS Secure Enclave key store behaves on a Mac is unknown ([L63](../reference/lab-register.md#l63), open). It is experimental and
    opt-in.
