---
title: Concepts
description: The ideas behind port49, in the order an operator meets them.
---

# Concepts

port49 puts a person's or a workload's identity in front of a network device that only speaks
TACACS+. The device is not changed. It is told that its TACACS+ server is port49d, and it
receives a short-lived token where it would receive a password.

## One login, end to end

Five parts take part in a login:

- The **person** (or a workload) wants a shell on a device.
- **`port49 login`** and the **agent** it starts run on the person's own host.
- The **broker** is port49's HTTPS service. It checks who the person is and hands out tokens.
- **port49d** is the TACACS+ server the device talks to.
- The **device** is unmodified.

A login goes through seven steps:

1. The person runs `port49 login`. It proves their identity to the broker in one of three ways (see
   [Identities](identities.md)): a client certificate, an OIDC sign-in, or a directory password with
   an authenticator code. The agent keeps the resulting mutual-TLS connection to the broker open.
   This held connection is the **session**. It lasts a working day, and the secret that proves it is
   never sent again.
2. The person, or a tool acting for them, asks for access to a device, for example with
   `port49 token`. The request travels over the agent's held connection. No second sign-in happens.
3. The broker decides. It resolves the person's groups from the directory at that moment (a group
   claimed by a credential is never believed), evaluates policy for that device, and refuses if the
   answer is no.
4. If the answer is yes, the broker mints a **token**: a short-lived, single-use secret stored for one
   device and one username. A login token and an enable token are minted as a pair. See
   [Tokens, receipts and contexts](tokens-receipts-contexts.md).
5. The person (or the tool) gives the token to the device in place of a password. The device sends it
   to port49d as an ordinary TACACS+ authentication.
6. port49d redeems the token in one atomic store operation, so it cannot be used twice. It records a
   **receipt** for a retransmission and a **login context** for the session, and answers PASS.
7. Every later authorization on that device, a session start or a command, is answered from the login
   context. The device asks, port49d looks up the context and applies the policy the broker compiled
   into it.

Two things follow from this shape.

- **The device never sees an identity credential.** It sees a token that is good for one device, once
  or for a short while.
- **The broker is needed to start work and to keep a context fresh, but not at every command.**
  port49d answers from the store, so a session in progress survives a broker outage for a while. The
  broker re-verifies live principals on a schedule. If it stays unreachable past
  `session.staleness_ceiling`, port49d denies `context_stale` until it recovers. The key is in the
  [port49d configuration reference](../reference/config/port49d.md).

When something goes wrong, the question is always: which step refused? Every refusal carries a reason
code in the decision log; see [Reason codes](../reference/reason-codes.md) and
[Decision log](../reference/decision-log.md).

## In this section

- [Tokens, receipts and contexts](tokens-receipts-contexts.md): what is stored, under which key, and
  for how long.
- [Identities](identities.md): how a person or a workload proves who it is.
- [Revocation](revocation.md): ending access already granted, and what it cannot reach.
- [Trust domains](trust-domains.md): why a workload can never act as a person.
