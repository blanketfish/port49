---
title: Concepts
description: What port49 is, the terms it uses and how one login to a device works.
---

# Concepts

port49 gives people and workloads their own identity on network devices that only speak TACACS+.
The device needs only standard TACACS+ configuration that names port49d as its server. At the password
prompt it receives a short-lived, single-use token instead of a shared password, and port49d checks that
token like any TACACS+ password.

## Terms

| Term | What it means |
|---|---|
| principal | The identity port49 derives from a credential: a person's `user:<email>`, or a workload's SPIFFE ID, Kubernetes service account or OIDC client id. |
| workload | A machine that logs in to devices, such as a CI job, rather than a person. |
| subject | Who, in policy: a directory group of people, a group of workloads, or named principals. |
| role | What may be done: command rules, a privilege level and a session length. |
| scope | Which devices: a selector over inventory attributes. |
| grant | Gives a subject some roles in a scope. |
| inventory | The devices port49 knows, with addresses and attributes, from a file, NetBox or Nautobot. |
| device (NAS) | A network device. port49d names it by looking up the connection's source address in the inventory. |
| agent | The background process `port49 login` starts on the person's host. It holds the session and asks the broker for tokens. |
| session | A person's sign-in, held by the agent until `max_session_age` (12 hours unless a role sets another). |
| broker | port49's HTTPS service. It checks who the person is, applies policy and mints tokens. |
| port49d | The TACACS+ server the devices talk to. |
| token | A single-use secret for one device and one username, good for 30 to 900 seconds, given to the device in place of a password. |
| mint, redeem | The broker mints a token. port49d redeems it when the device presents it. |
| receipt | port49d's record of a redeemed token, so a device that retransmits a login gets the same answer. |
| login context | The stored record of one person's login on one device. Later authorizations on that device are answered from it. |
| store | Where tokens, receipts and contexts live: etcd, or memory inside one process for a trial. |
| trust domain | Which verifier validated a credential. A workload's trust domain can never act as a person's. |
| revocation | Ending access already granted, before it would end on its own. |
| break-glass | A local account on the device, for when port49 cannot answer. |
| reason code | The word in the decision log that says why something was refused. |

## One login, end to end

| Part | Runs on |
|---|---|
| The person (or a workload), with `port49` and its agent | their own host |
| The broker | the broker host |
| port49d | the TACACS+ hosts |
| The device, unmodified | itself |

1. `port49 login` proves the person's identity to the broker with a client certificate, an OIDC sign-in,
   or a directory password and an authenticator code (see [Identities](identities.md)). The agent holds the
   resulting mutual-TLS connection while the network is up, and the secret that proves it is never sent
   again. See [the session](tokens-receipts-contexts.md#the-session).
2. The person, or a tool acting for them, asks for a device, for example with `port49 token`. The request
   travels over the agent's connection with no second sign-in.
3. The broker resolves the person's groups from the directory at that moment (a group claimed by a
   credential is never believed), evaluates policy for that device, and refuses if the answer is no.
4. If yes, the broker mints a token: short-lived, single-use, stored for one device and one username.
   A login token and an enable token are minted as a pair. See
   [Tokens, receipts and contexts](tokens-receipts-contexts.md).
5. The person gives the token to the device in place of a password. The device sends it to port49d as an
   ordinary TACACS+ authentication.
6. port49d redeems the token in one atomic store operation, so it cannot be used twice. It records a
   receipt for a retransmission and a login context, and answers PASS.
7. Every later authorization on that device, a session start or a command, is answered from the login
   context, with the policy the broker compiled into it.

Two things follow from how a login works.

- The device never sees an identity credential. It sees a token that is good for one device, once
  or for a short while.
- The broker is needed to start work and to keep a context fresh, but not at every command.
  port49d answers from the store, so a session in progress survives a broker outage for a while. If the
  broker stays unreachable past `session.staleness_ceiling`, port49d denies `context_stale` until it
  recovers ([port49d reference](../reference/config/port49d.md)).

When something goes wrong, ask which step refused. Every refusal carries a reason code in the decision
log; see [Reason codes](../reference/reason-codes.md) and [Decision log](../reference/decision-log.md).

## In this section

- [Tokens, receipts and contexts](tokens-receipts-contexts.md): what is stored, under which key, and
  for how long.
- [Identities](identities.md): how a person or a workload proves who it is.
- [Revocation](revocation.md): ending access already granted, and what it cannot reach.
- [Trust domains](trust-domains.md): why a workload can never act as a person.
