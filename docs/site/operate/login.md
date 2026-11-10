---
title: Signing in
description: How a person signs in to port49 and gets a token for a device login.
---

# Signing in

A person signs in once with `port49 login`, then asks for a token for each device with `port49 token`
or lets `port49 ssh` do both steps. This page is for the operator who has to explain what those
commands do, and what they return to a script. The pieces they talk to are on
[Broker and agent](broker-and-agent.md).

## `port49 login`

`port49 login` proves who the person is to the broker and starts the agent that keeps the result. It
takes one of three methods, each the same command with a different flag. The method can instead be
set once in the person's config file with `method:`, and every flag overrides its key; the keys are
in the [client configuration reference](../reference/config/client.md).

```sh
# A client certificate and key the person already holds
port49 login --broker https://broker.example.com:8443 --broker-ca <broker-ca.pem> \
  --cert <client-cert.pem> --key <client-key.pem>

# A sign-in at the identity provider; the broker issues the certificate
port49 login --oidc

# A directory name, password and authenticator code, asked at the terminal
port49 login --directory
```

What a successful login prints is `port49: logged in to <broker>; the session ends at <time>`, with
the agent's process id and the path of its log. A second `port49 login` while the agent runs
refreshes it instead of starting another one, and says `already logged in to <broker>; refreshing`.

- **`--oidc` and `--directory` hold the certificate the broker issues.** They sign in again only when
  that certificate has under a quarter of its life left, or when you pass `--sign-in`.
- **`--cert` and `--key` belong to the certificate method.** Combining them with `--oidc` or
  `--directory` is refused, as is naming both of those two together.
- **The key may be on a hardware token.** A `key` that starts `pkcs11:` is asked for its PIN once, on
  the terminal. See [Hardware keys](hardware-keys.md).
- **Where the broker and its CA come from.** Flags first, then the person's own config file, then
  `/etc/port49/config.yaml` key by key. The broker's CA is required; the system's roots are never
  trusted for the broker.

## `port49 token`

```sh
port49 token core-sw01            # prints the login token, and nothing else, on stdout
port49 token --ttl 30s core-sw01  # shorten the token's life below your token_ttl; never lengthens it
port49 token --json core-sw01     # the broker's whole answer as one JSON object
```

**A token's life is set by policy, not by you.** Each subject's `token_ttl` (`30s` to `900s`, on the
[policy reference](../reference/config/policy.md)) is how long its token stays usable before its one
login. `--ttl` can only ask for less: a value above `token_ttl` gets `token_ttl`. How long the session on
the device then lasts is the role's [`max_session_age`](../admin/roles-and-grants.md#max_session_age), a
separate setting ([The token](../concepts/tokens-receipts-contexts.md#the-token)).

The token is the one secret that port49 ever writes to standard output. Give it to the device where
the device asks for a password. It is single use, and short-lived by design: see
[Tokens, receipts and contexts](../concepts/tokens-receipts-contexts.md). Flags come before the
device name.

If the broker's store is not ready, `port49 token` retries by itself for up to 30 seconds, waiting
the broker's own hint between tries, and then fails with the last answer. It retries nothing else.

A device whose policy requires a second factor makes `port49 token` ask for it first: a touch on the
person's security key, or a sign-in at the identity provider. It prints which, and what to do.

### `--json`

With `--json`, standard output is exactly one JSON object whether the mint worked or not, so a
script reads one thing. Standard error carries the human words.

On success it is the broker's answer for that device. These are its keys:

| Key | Meaning |
|---|---|
| `device` | the device as the inventory names it |
| `verdict` | `permit` |
| `address`, `platform`, `username` | where to connect and as whom |
| `login` | the login token: `<token>` |
| `enable` | the enable token, present only with `--enable` |
| `expires_at` | when the token stops being redeemable |
| `session_expires_at` | when a login made with it stops being authorized; absent when the roles say never |

The object holds the tokens, so treat it as the secret it is: do not log it. The `--enable` flag
mints an enable token beside the login token; without `--json` only the login token is printed.

On a failure the command exits 1 and the object has `device` and one of these shapes:

- **A refusal by policy.** `verdict` is `deny` and `reason` is a code from
  [Reason codes](../reference/reason-codes.md), the same closed vocabulary the decision log uses, with
  `detail` as words. Nothing here is a code the table does not list.
- **A failure of the client or the broker.** `error` is one of the codes below and `detail` says more.
  These are the command's own and are never reason codes. For a device the broker could not decide,
  `error` is the broker's code for it instead.
- **A requirement to prove.** `error` is `per_login_mfa_required` and `per_login_mfa` lists `accept`
  (the methods that satisfy it), `reuse_for_seconds`, and where the reuse comes from. A challenge is
  never printed.

| `error` | What it means, and what to do |
|---|---|
| `no_agent` | nothing listens at the agent's socket: run `port49 login`, or check `XDG_RUNTIME_DIR` |
| `agent_too_old` | the agent was started by an older `port49`: run `port49 login` again |
| `session_over` | the session has ended: run `port49 login` |
| `credential_revoked` | the broker refuses this credential or session; a revocation is in force |
| `revocation_running` | a revocation of yours is still running on the broker; run the command again when it reports |
| `per_login_mfa_required` | prove the second factor, then run it again |
| `connection_changed` | the connection changed during a touch; nothing was sent: run it again |
| `broker_refused` | the broker refused the request or a proof, or its certificate was refused by the CRL check |
| `broker_unavailable` | the broker did not answer; try again when it does |
| `key_locked` | the hardware key needs its PIN: run `port49 login` ([Hardware keys](hardware-keys.md)) |
| `key_absent` | the hardware key is not inserted |
| `touch_timeout` | no touch arrived in time; run it again and touch when the key blinks |
| `no_token` | the broker said permit and gave no token; tell the broker's operator |
| `agent_error` | any other fault of the agent or the broker; the `detail` has the words |

A token near the end of the session's ceiling also prints a warning on standard error, never on
standard output, so `--json` stays one object.

## `port49 ssh`

`port49 ssh` does the mint and the connection together. It asks the agent for a token, runs your own
OpenSSH (8.5 or later) with the token ready for the device's password prompt, and exits with ssh's
status.

```sh
port49 ssh core-sw01                       # a shell
port49 ssh core-sw01 -- show version       # one command
port49 ssh --port 2222 --ttl 30s core-sw01   # --ttl shortens the token's life; never lengthens it
```

It takes `--ttl` (shorter than your `token_ttl` only, as for `port49 token`), `--port`, `--ssh PATH` for another OpenSSH, `--ssh-config FILE` for another
`ssh_config`, and `-v`. The device name may hold only letters, digits, `.`, `_` and `-`; for any
other, use `port49 token` and your own `ssh`.

What it passes to ssh is fixed so that a login costs one attempt: no public-key offers, one password
prompt, no connection sharing, no agent forwarding. The token goes only to the prompt of the device
it was minted for. A prompt from anything else on the way, such as a jump host that asks for its own
password, is not answered with it. If the device asks for the password a second time, `port49 ssh`
ends the connection so that no second or empty password is sent.

### Host keys

OpenSSH owns the device's host key. port49 does not pin one, keep a list, or add a trust step of its
own. `port49 ssh` runs ssh with `StrictHostKeyChecking=accept-new`: a device met for the first time is
accepted and filed in your `known_hosts`, and a device whose key has changed is refused. If your own
`ssh_config` says `StrictHostKeyChecking yes`, that stands, and the key must already be in
`known_hosts`. The keys are filed under the device's name, lowercased, unless your `ssh_config` sets a
`HostKeyAlias`.

Two consequences an operator should know:

- If ssh says `Host key verification failed`, the key filed under the device's name is not the one it
  presented. Verify the new key on the device's console, then remove the old one with
  `ssh-keygen -R <device>` (the failure message prints the exact command for your `known_hosts`) and
  connect again. Do not remove it first and accept whatever answers.
- Under `accept-new`, if your `ssh_config` points `UserKnownHostsFile` somewhere that cannot keep a
  key, such as `/dev/null`, `port49 ssh` refuses before sending anything, because every connection
  would be a first contact. With your own `StrictHostKeyChecking yes` that refusal does not apply.

### Telling port49's refusals from ssh's

A remote command can exit 1, and so can `port49 ssh`. The two are told apart by the line `port49 ssh:`
on standard error: when port49 itself refuses, it says so under that prefix and sent nothing to the
device. ssh's own messages have no such prefix. When ssh exits 255 after the device was sent the token,
`port49 ssh:` adds a line saying so, with `port49 explain --device <device>` as the next step.

## Exit codes

Read from the commands themselves.

| Command | Code | Meaning |
|---|---|---|
| `port49 login` | 0 | logged in, or an agent already running was refreshed |
| `port49 login` | 1 | the agent did not start, or did not answer within 15 seconds (the end of `agent.log` is printed); another broker's or another certificate's agent holds the socket, or `--sign-in` was given while one runs; refreshing the running agent failed; the agent socket's directory is not private; the sign-in failed at the identity provider or the directory; the broker did not answer; the broker refused the certificate it issued; a hardware key is absent, blocked or refused its PIN |
| `port49 login` | 2 | the command line or the config is refused: an unknown flag, flags that contradict each other, a config file that cannot be read or that others can write, a missing `--broker` or `--broker-ca`, or a key file that is readable by others |
| `port49 ssh` | 0 | ssh ended with 0 |
| `port49 ssh` | 1 | port49 refused before ssh ran: no OpenSSH, one older than 8.5, a mint that failed, no agent, a socket directory that is not private, an `ssh_config` that keeps no host keys under `accept-new`, or a config file refused while proving an `idp_mfa` device's sign-in. **Also ssh's own status when the remote command exits 1.** Read the `port49 ssh:` line |
| `port49 ssh` | 2 | a flag it does not accept, no device named, or a device name it does not accept |
| `port49 ssh` | 255 | ssh's own failure (connection, host key, authentication), or port49 ended ssh: the asker could not be verified, the token was asked for after it expired, or the device asked for the password again |
| `port49 revoke` | 0 | done; `--list` printed |
| `port49 revoke` | 1 | refused or unreachable: no agent, the right missing, the touch refused or not given, a declined confirmation (`nothing was revoked`), an unreadable `--cert` file. **Also when the broker did not answer, or answered without naming a revocation, and the revocation may be in force** (`it may be in force`, `it may have run`): run `port49 revoke --list` before you retry |
| `port49 revoke` | 2 | the flags are wrong: no target, two targets, or a flag that does not go with the form |
| `port49 revoke` | 3 | the revocation is in force but incomplete or not saved, or a lift step did not finish: run the same command again |
| `port49 hwkey` | 0 | ready; for `setup`, the keys are written, or already name this token |
| `port49 hwkey` | 1 | action needed: a check failed, no token is inserted, the session key is not on a token, or setup would change a key and was not allowed to |
| `port49 hwkey` | 2 | an error: a bad flag, no attestation roots, an unreachable or untrusted broker, a config file that is refused or cannot be written, no module found or one refused, several tokens with no `--token`, or the build has no hardware-key support |

Also, `port49 token` and `port49 refresh` exit 0 when they worked, 1 when they did not, and 2 for a
usage error. Under `--json`, `port49 token` writes its failure object before it exits 1.

**One refused config file, three commands.** A config file that others can write is refused. `port49
login` reads it first and exits 2. `port49 ssh` and `port49 token` read it only when a device asks for
an `idp_mfa` sign-in, and there the refusal ends the mint with exit 1. A script that tells the two
apart by the code alone will be wrong.

A command run by `cron` or a script should check the code and not the text: the words are meant for a
person and may change.
