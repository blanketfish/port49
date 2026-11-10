---
title: Broker and agent
description: What the broker and the agent each do, and where each runs.
---

# Broker and agent

Two long-running pieces sit between a person and a device, and they run in different places. The
**broker** runs on your servers. The **agent** runs on the person's own machine. When a sign-in goes
wrong, the first question is which of the two you are looking at.

| | Broker | Agent |
|---|---|---|
| Binary | `port49-broker` | `port49`, started by `port49 login` |
| Runs on | your servers, next to `port49d` and the stores | the machine where the person works |
| One per | deployment (run several for availability) | person, per machine |
| Holds | the issuing key, the revocation marks, the policy | one mutual-TLS connection to the broker, and the key that proves it |
| Listens on | HTTPS, with the TLS certificate you gave it | a Unix socket that only that person can reach |
| Goes away when | you stop it | the session ends, or the person stops it |

## The broker

The broker is the HTTPS service that checks who a person is and decides what they may reach. On each
request it:

- resolves group membership from the directory at that moment
- evaluates policy
- mints the tokens `port49d` later redeems

It also issues the short-lived certificates for OIDC and directory sign-ins.
[Concepts](../concepts/index.md) follows one login through it. [Identities](../concepts/identities.md)
covers the three ways a person proves who they are.

You install it with the rest of the server, in the shape you chose: see [Install](install/index.md).
Its certificate and the CA the clients trust are on the [TLS](tls.md) page.

Its state directory, `broker.state_dir`, holds the revocation marks and must survive a restart. The
install page says what else must.

What an operator sees when the broker is down:

- **A person who is not logged in cannot log in.** For an OIDC or directory sign-in, `port49 login`
  says `the broker at <broker> did not answer`, and until when the certificate it holds is valid.
  Trying again when the broker answers is the whole remedy; a new sign-in would fail at the same
  place. A certificate login that cannot reach the broker ends by printing the end of `agent.log`.
- **A person who is logged in cannot mint.** `port49 token` fails because the broker is unavailable:
  the `broker_unavailable` code of `port49 token --json` (see [Signing in](login.md#port49-token)).
- **A device login already in progress carries on.** `port49d` answers it from the store, not the
  broker. How long it carries on is `session.staleness_ceiling`, on the
  [`port49d` reference](../reference/config/port49d.md).

## The agent

`port49 login` proves the person's identity to the broker once, and starts the agent to keep what
that produced. The agent holds the mutual-TLS connection open. If the key lives on a hardware token,
it also holds the token's unlocked session.

Every other `port49` command (`token`, `ssh`, `refresh`, `identity`, `revoke`) asks the agent over
its socket. None of them signs in again, so a second terminal needs no second login.

- **Where it is.** The socket is `$XDG_RUNTIME_DIR/port49/agent.sock`. With `XDG_RUNTIME_DIR` unset it
  is `port49-<uid>/agent.sock` under the system's temporary directory. The directory is created `0700`.
  The agent refuses to use one that is not that user's alone, because whoever can reach the socket
  can mint as that person.
- **Its log.** `agent.log`, in the same directory. `port49 login` prints its path and, when the agent
  exits at start, the last lines of it.
- **No flag moves it.** A command that says `no agent at <path>` is looking where its own
  `XDG_RUNTIME_DIR` points. If you logged in from a shell with a different `XDG_RUNTIME_DIR` (a
  `sudo`, a cron job, a container), the agent is somewhere else. Run `port49 login` in the shell that
  needs it, or give both shells the same `XDG_RUNTIME_DIR`.
- **It does not dump core.** The agent marks itself non-dumpable where the platform allows, so a
  crash does not write the key to disk. It says so on its log if it could not, and runs on.

### How long it lives

The agent ends itself. It exits at whichever comes first:

- the session's end, which is the broker's `max_session_age` counted from the sign-in (the log says
  `the session reached max_session_age`);
- the end of its certificate, after which the broker takes no request. For a certificate `port49`
  issued, the next `port49 login` signs the person in again;
- the broker ending the session, for a revocation or a certificate it no longer trusts (see
  [Revocation](../concepts/revocation.md));
- `SIGTERM` or `SIGINT`.

`port49 refresh` asks the agent to do two things: re-authenticate its session, and extend each live
device session that the policy in force still grants. It prints `this login lasts until <time>`,
which is when the agent will exit next, and one line per device.

When the agent is gone, every command says `no agent at <path>` and names `port49 login` as the next
step. That is the whole recovery. A token already minted is single use and short-lived whether or
not an agent is running.

### One agent, one identity

A second `port49 login` to a running agent does not start another. It refreshes the running one, and
only when the broker and the certificate are the same ones.

A login for another broker, or with another certificate, is refused with `already holds the agent`.
Refreshing would extend one identity's device sessions while the person believed they had switched.
To switch, stop the first agent, or let its session end.

A hardware key adds one more case: [Hardware keys](hardware-keys.md) covers what a locked or
absent key looks like and how to put the PIN back.

## Which side owns what

| Question | Look at |
|---|---|
| Can this person sign in at all? | the broker: its log, the [decision log](../reference/decision-log.md), [Identities](../concepts/identities.md) |
| Was the token refused? | the broker's decision log, with a code from [Reason codes](../reference/reason-codes.md) |
| `no agent at ...` | the person's machine: `XDG_RUNTIME_DIR`, then `port49 login` |
| The agent exited | `agent.log` on the person's machine |
| The device refused a token it was given | `port49d`'s decision log, not the broker's |
