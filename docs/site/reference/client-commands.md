---
title: Client commands
description: The JSON output and exit codes of the port49 client commands.
---

# Client commands

A script should check a command's exit code, not its text. The words are for a person and may change.

## port49 token --json

With `--json`, standard output is exactly one JSON object whether the mint worked or not, so a script
reads one thing. Standard error carries the human words. The object holds the tokens, so treat it as a
secret and do not log it.

On success it is the broker's answer for that device:

| Key | Meaning |
|---|---|
| `device` | the device as the inventory names it |
| `verdict` | `permit` |
| `address`, `platform`, `username` | where to connect and as whom |
| `login` | the login token: `<token>` |
| `enable` | the enable token, present only with `--enable` |
| `expires_at` | when the token stops being redeemable |
| `session_expires_at` | when a login made with it stops being authorized; absent when the roles say never |

On a failure the command exits 1 and the object has `device` and one of these forms:

- A refusal by policy. `verdict` is `deny`, and `detail` says why in words. `reason` is a code from
  [Reason codes](reason-codes.md), the same closed vocabulary the decision log uses. It is never a code
  that table does not list.
- A failure of the client or the broker. `error` is one of the codes below, and `detail` says more.
  These codes belong to the command and are never reason codes. The exception is a device the broker
  could not decide: then `error` is the broker's code for it.
- A requirement to prove. `error` is `per_login_mfa_required`, and `per_login_mfa` lists `accept` (the
  methods that satisfy it), `reuse_for_seconds`, and where the reuse comes from. A challenge is never
  printed.

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
| `key_locked` | the hardware key needs its PIN: run `port49 login` ([Hardware keys](../use/hardware-keys.md)) |
| `key_absent` | the hardware key is not inserted |
| `touch_timeout` | no touch arrived in time; run it again and touch when the key blinks |
| `no_token` | the broker said permit and gave no token; tell the broker's operator |
| `agent_error` | any other fault of the agent or the broker; the `detail` has the words |

A token near the end of the session's ceiling also prints a warning. It goes to standard error, so
`--json` stays one object.

## Exit codes

| Command | Code | Meaning |
|---|---|---|
| `port49 login` | 0 | logged in, or an agent already running was refreshed |
| `port49 login` | 1 | the agent did not start, or did not answer within 15 seconds (the end of `agent.log` is printed); another broker's or another certificate's agent holds the socket, or `--sign-in` was given while one runs; refreshing the running agent failed; the agent socket's directory is not private; the sign-in failed at the identity provider or the directory; the broker did not answer; the broker refused the certificate it issued; a hardware key is absent, blocked or refused its PIN |
| `port49 login` | 2 | the command line or the config is refused: an unknown flag, flags that contradict each other, a config file that cannot be read or that others can write, a missing `--broker` or `--broker-ca`, or a key file that is readable by others |
| `port49 ssh` | 0 | ssh ended with 0 |
| `port49 ssh` | 1 | port49 refused before ssh ran: no OpenSSH, one older than 8.5, a mint that failed, no agent, a socket directory that is not private, an `ssh_config` that keeps no host keys under `accept-new`, or a config file refused while proving an `idp_mfa` device's sign-in. It is also ssh's own status when the remote command exits 1, so read the `port49 ssh:` line |
| `port49 ssh` | 2 | a flag it does not accept, no device named, or a device name it does not accept |
| `port49 ssh` | 255 | ssh's own failure (connection, host key, authentication), or port49 ended ssh: the asker could not be verified, the token was asked for after it expired, or the device asked for the password again |

`port49 token` and `port49 refresh` exit 0 when they worked, 1 when they did not, and 2 for a usage
error. Under `--json`, `port49 token` writes its failure object before it exits 1.

A config file that others can write is refused, but not at the same moment by every command. `port49 login`
reads it first and exits 2. `port49 ssh` and `port49 token` read it only when a device asks for an
`idp_mfa` sign-in, and there the refusal ends the mint with exit 1. A script that reads the cause from
the exit code alone gets this case wrong.

## port49 hwkey

| Command | Code | Meaning |
|---|---|---|
| `port49 hwkey` | 0 | ready; for `setup`, the keys are written, or already name this token |
| `port49 hwkey` | 1 | action needed: a check failed, no token is inserted, the session key is not on a token, or `setup` would change a key and was not allowed to |
| `port49 hwkey` | 2 | an error: a bad flag, no attestation roots, an unreachable or untrusted broker, a config file that is refused or cannot be written, no module found or one refused, several tokens with no `--token`, or the build has no hardware-key support |

The attestation roots have their own messages, all exit 2, and each names the way out:

- `the broker <host> is unreachable, so the attestation roots could not be fetched: retry, or pass --roots FILE`.
  The broker did not answer. This says nothing about the key.
- `the broker <host> did not present a certificate from the configured broker CA ...: check broker_ca, or pass --roots FILE`.
  This is a trust failure, not an outage. Find out why the certificate is not the broker's before you
  point `--roots` at a file.
- `no attestation roots: the broker <host> serves none ...`. The broker does not verify
  `hardware_key_touch` at all, because `attestation_roots_file` is not set there.

## port49 store status

| Command | Code | Meaning |
|---|---|---|
| `port49 store status` | 0 | every store answers |
| `port49 store status` | 3 | a store does not answer, or the stores are not open yet |
| `port49 store status` | 1 | the metrics port did not answer, or a status is already running |

## port49 revoke

| Command | Code | Meaning |
|---|---|---|
| `port49 revoke` | 0 | done; `--list` printed |
| `port49 revoke` | 1 | nothing was revoked, or it is unknown whether it ran. Refused or unreachable: no agent, the right missing, the touch refused or not given, a declined confirmation (`nothing was revoked`), an unreadable or refused `--cert` file, or a broker refusal that says nothing was done. Unknown whether it ran: the broker did not answer (`the broker did not answer ...`), it answered with no revocation named (`the broker's answer named no revocation; it may be in force`), it answered `503 revocation_unconfirmed` (`the broker could not confirm it: ...`), or a revoke got `503 store_unavailable` (`the broker says: ...`) |
| `port49 revoke` | 2 | the flags are wrong: no target, two targets, or a flag that does not go with the form |
| `port49 revoke` | 3 | the revocation is in force but incomplete, or not saved to the revocations file, or a lift step did not finish: run the same command again, which repeats every step |

Exit 1 is two different things, so read the line. A refusal that says nothing was done means nothing
happened. `it may be in force` means it may have. For the first two unknown cases, run
`port49 revoke --list` and look at the decision log before you retry. Two broker answers look like
refusals and are not:

- `the broker could not confirm it` (`503 revocation_unconfirmed`): the revocation may have gone through,
  and so may a lift made meanwhile. Run `port49 revoke --list` to see what is in force, then repeat the
  command if the mark is not what you wanted.
- `the broker says: ...` on a revoke that got `503 store_unavailable`: the mark went to that one
  broker's own process only, so the credential is revoked on that broker and not, yet, on the others. Do
  what the broker's words say to make the mark everywhere, and run the revoke again once the store is
  back.

Exit 3 is never a failure to revoke. The mark stands and refuses every new mint, but until a run finishes,
unspent tokens may still log in (up to their TTL) and unmarked contexts keep authorizing.
`port49 revoke --lift` takes the same codes. An answer with no text exits 1 with `it may have run`.
