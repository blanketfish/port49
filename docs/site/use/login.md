---
title: Log in
description: Sign in with port49 login using a certificate, OIDC or a directory password, and what the agent it starts does.
---

# Log in

`port49 login` proves who you are to the broker and starts the agent that keeps the result. Your admin
tells you which method to use, and the [client installed](install-client.md) needs the broker's URL and CA
from them.

## 1. Sign in

=== "Certificate"

    Use a client certificate and key you already hold:

    ```sh
    port49 login --broker https://broker.example.com:8443 --broker-ca <broker-ca.pem> \
      --cert <client-cert.pem> --key <client-key.pem>
    ```

    The key may be on a hardware token. A `key` that starts `pkcs11:` is asked for its PIN once, on the
    terminal. See [Hardware keys](hardware-keys.md).

=== "OIDC"

    Sign in at your organization's identity provider. The broker then issues you a short-lived certificate:

    ```sh
    port49 login --oidc
    ```

=== "Directory password"

    Enter your directory name, password and an authenticator code at the terminal prompts:

    ```sh
    port49 login --directory
    ```

To check, the command prints `port49: logged in to <broker>; the session ends at <time>`, with the agent's
process id and the path of its log. `port49 identity` then shows who the broker thinks you are.

- Instead of a flag, set the method once in your config file with `method:`. A flag always overrides its
  config key. The keys are in the [client configuration reference](../reference/config/client.md).
- The broker and its CA come from flags first, then your own config file, then `/etc/port49/config.yaml`,
  key by key. The broker's CA is required, and the system's roots are never trusted for the broker.
- `--oidc` and `--directory` hold the certificate the broker issues. They sign in again only when that
  certificate has under a quarter of its life left, or when you pass `--sign-in`.
- `--cert` and `--key` belong to the certificate method. Combining them with `--oidc` or `--directory` is
  refused, as is naming both of those two together.

## The agent

The agent holds your session. Every other `port49` command (`token`, `ssh`, `refresh`, `identity`,
`revoke`) asks it over a socket, so a second terminal needs no second login.

- The socket is `$XDG_RUNTIME_DIR/port49/agent.sock`. With `XDG_RUNTIME_DIR` unset it is
  `port49-<uid>/agent.sock` under the system's temporary directory. The directory is created `0700`, and
  the agent refuses one that is not yours alone, because whoever can reach the socket can mint as you.
- Its log is `agent.log` in the same directory. `port49 login` prints its path and, when the agent exits
  at start, the last lines of it.
- No flag moves the socket. A command that says `no agent at <path>` is looking where its own
  `XDG_RUNTIME_DIR` points, so a `sudo`, a cron job or a container with a different value looks in the
  wrong place. Run `port49 login` in the shell that needs it, or give both shells the same
  `XDG_RUNTIME_DIR`.
- The agent marks itself non-dumpable where the platform allows, so a crash does not write your key to
  disk. It says so in its log if it could not.

## How long a session lasts

The agent exits at whichever comes first:

- The session's end, `max_session_age` counted from the sign-in. The log says
  `the session reached max_session_age`.
- The end of its certificate. For a certificate `port49` issued, the next `port49 login` signs you in
  again.
- The broker ending the session, for a revocation or a certificate it no longer trusts.
- `SIGTERM` or `SIGINT`.

When the agent is gone, every command says `no agent at <path>` and names `port49 login`. That is the whole
recovery, and a token already minted is single use and short-lived whether or not an agent runs.

`port49 refresh` re-authenticates the session and extends each live device session that policy still
grants. It prints `this login lasts until <time>`, which is when the agent exits next, and one line per
device. A dropped connection is redialed by itself, and a hardware key asks for its PIN or a touch again
when that happens. [The session](../concepts/tokens-receipts-contexts.md#the-session) explains why.

If the broker does not answer, `port49 login` says `the broker at <broker> did not answer`. Try again when
it does, because a new sign-in fails at the same place. A device login already in progress carries on, since
`port49d` answers it from the store.

## One agent, one identity

A second `port49 login` to a running agent refreshes it (`already logged in to <broker>; refreshing`), and only when the broker and the certificate are
the same ones. A login for another broker, or with another certificate, is refused with
`already holds the agent`, because refreshing would extend one identity's device sessions while you
believed you had switched. To switch, stop the first agent or let its session end.

Next, [connect to a device](connect.md).
