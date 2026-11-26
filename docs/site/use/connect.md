---
title: Connect to a device
description: Reach a network device with port49 ssh, or get a token from port49 token for your own tool.
---

# Connect to a device

You need to be [logged in](login.md). `port49 ssh` mints a token and connects in one command, and
`port49 token` prints the token for a tool of your own.

## 1. Connect with port49 ssh

```sh
port49 ssh core-sw01                          # a shell
port49 ssh core-sw01 -- show version          # one command
port49 ssh --port 2222 --ttl 30s core-sw01    # another port, a shorter token
```

`port49 ssh` asks the agent for a token, runs your own OpenSSH (8.5 or later) with the token ready for the
device's password prompt, and exits with ssh's status. To check, you get the device's prompt without typing
a password. Its other flags are `--ssh PATH` for another OpenSSH, `--ssh-config FILE` for another
`ssh_config`, and `-v`. Flags come before the device name, and the name may hold only letters, digits, `.`,
`_` and `-`. For any other name, use `port49 token` and your own `ssh`.

A login costs one attempt. The options `port49 ssh` passes to ssh are fixed: no public-key offers, one
password prompt, no connection sharing, no agent forwarding. The token goes only to the device it was minted
for. A prompt from anything else on the way, such as a jump host that asks for its own password, is not
answered with it, and if the device asks for the password a second time `port49 ssh` ends the connection.

### Host keys

OpenSSH owns the device's host key. port49 does not pin one, keep a list, or add a trust step of its own.
`port49 ssh` runs ssh with `StrictHostKeyChecking=accept-new`:

- A device met for the first time is accepted and filed in your `known_hosts`.
- A device whose key has changed is refused.
- If your own `ssh_config` says `StrictHostKeyChecking yes`, that stands, and the key must already be in
  `known_hosts`.

Keys are filed under the device's name, lowercased, unless your `ssh_config` sets a `HostKeyAlias`.

If ssh says `Host key verification failed`, the key filed under the device's name is not the one it
presented. Verify the new key on the device's console, then remove the old one with `ssh-keygen -R <device>`
(the message prints the exact command) and connect again. Do not remove it first and accept whatever
answers.

If your `ssh_config` points `UserKnownHostsFile` somewhere that cannot keep a key, such as `/dev/null`,
`port49 ssh` refuses under `accept-new` before sending anything, because every connection would be a first
contact. With your own `StrictHostKeyChecking yes` that refusal does not apply.

### Telling port49's refusals from ssh's

A remote command can exit 1, and so can `port49 ssh`. Look for a line that starts `port49 ssh:` on standard
error. If it is there, port49 refused and sent nothing to the device. If ssh's own messages have no such
prefix, ssh or the device failed. When ssh exits 255 after the device was sent the token, `port49 ssh:` adds
a line saying so, with `port49 explain --device <device>` as the next step. The codes are in
[Client commands](../reference/client-commands.md#exit-codes).

## 2. Get a token with port49 token

```sh
port49 token core-sw01            # prints the login token, and nothing else, on stdout
port49 token --ttl 30s core-sw01  # shorten the token's life below your token_ttl; never lengthens it
port49 token --json core-sw01     # the broker's whole answer as one JSON object
port49 token --enable core-sw01   # an enable token beside the login token
```

Give the token to the device where it asks for a password. The token is the one secret port49 writes to
standard output, and it is single use and short-lived. Policy sets its life: each subject's `token_ttl`
(`30s` to `900s`, in the [policy reference](../reference/config/policy.md)) is how long it stays usable
before its one login, and `--ttl` can only ask for less. How long the session on the device then lasts is the
role's [`max_session_age`](../admin/roles-and-grants.md#max_session_age).

If a device's policy requires a second factor, `port49 token` asks for it before the mint: a touch on your
security key, or a sign-in at the identity provider. It prints which one. If the broker's store is not ready,
the command retries by itself for up to 30 seconds, waiting the broker's own hint between tries, and then
fails with the last answer. Without `--json`, only the login token is printed.

`--json` makes standard output one JSON object whether the mint worked or not, and a script should check
the exit code, not the text. The keys, the error codes and the exit codes are in
[Client commands](../reference/client-commands.md), and the reason codes in
[Reason codes](../reference/reason-codes.md).

### Many devices at once

The agent's connection carries one request at a time. A run that asks for hundreds of devices at once, such
as Ansible with `forks: 20`, queues in the agent, which sends what is queued as one request of up to the
broker's `batch_max` devices and gives each caller its own token or its own refusal. The first mint goes
alone, and a mint that waits longer than 30 seconds for the connection fails with "busy" and nothing minted.
A mint that does not finish within about 85 seconds of being asked fails with the wait it was in.
