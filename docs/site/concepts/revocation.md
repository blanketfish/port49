---
title: Revocation
description: How port49 ends access that was already granted, and how quickly it takes effect.
---

# Revocation

A token can be short because expiry does most of the work. Revocation is for the other case: a stolen
laptop, an offboarding, a certificate that must stop now. port49 revokes through the broker's API, so
it needs no access to the store.

## What an operator runs

`port49 revoke` takes one target:

| You want to stop | Run | Leaves a standing mark |
|---|---|---|
| a person or workload, everywhere | `port49 revoke --principal <principal>` | yes |
| one certificate | `port49 revoke --cert <file>` (or `--cert-issuer` with `--cert-serial`) | yes |
| one OIDC session | `port49 revoke --sid <sid> --sid-issuer <issuer>` | no |
| whoever holds one device login | `port49 revoke --device <name> --username <user>` | no |
| your own sessions | `port49 revoke --mine` | no |

`port49 revoke --list` shows the marks in force, and `port49 revoke --lift` removes one. Revoking
another principal needs the `revoke_others` right and a press of the operator's security key; lifting needs
`lift_revocations` and a touch (both are rights in the [policy reference](../reference/config/policy.md)).
Without the right the call is refused and the refusal is logged. `port49 revoke --help` lists every
flag, and [Administer: revocation](../admin/revocation.md) is the runbook.

A **standing mark** is kept in the store and in the broker's revocations file, so a restart forgets
nothing. It does not expire, because the agent reconnects with the same key by itself and a mark that
a fresh handshake could outlive would be undone without anyone acting.

## What happens, in order

1. The mark is written first.
2. The broker closes the held connections it names.
3. Unspent tokens for the principal or certificate are deleted.
4. Every live login context under it is marked revoked, and its receipts are deleted.
5. The contexts are read and marked a second time, to catch a redemption that was in flight.

The next mint by that principal is refused `credential_revoked`. A person's agent sees that at its next
request, which ends its session. A login that arrives with a token minted *before* the revocation is
refused `credential_revoked` too, and its token is spent. Because the receipt was deleted, a device's
retransmission of an earlier login is answered `token_not_found` rather than replayed.

Each revocation is one `revoke` record in the [decision log](../reference/decision-log.md). It names
what it reached and which live contexts it could not.

## Other things that revoke

Revocation is not only an operator's act. Each of these marks the live context revoked, and its next
authorization is denied `credential_revoked`:

- a certificate appearing on a CRL or OCSP response;
- an OIDC back-channel logout, by `sid` or `sub`;
- the broker's periodic refresh finding that the principal now has no grant on the device
  (for example, a policy change withdrew them);
- the refresh finding that the directory no longer maps the principal: the entry is gone, ambiguous,
  or renamed to a username another entry holds;
- a subject's username changing, since the principal can no longer mint under the name the context is
  keyed by.

The `refresh` record before the denial says which of these it was.

A certificate that cannot be checked at all, such as a stale CRL, is not revocation: it is
`trust_domain_unresolved` at mint, and the broker setting `broker.certificate_status.on_unavailable`
decides whether that refuses.

## Workloads

A workload certificate renews under the same SPIFFE ID, so a mark on one certificate does not follow
the renewal. To stop a workload, revoke its principal (`port49 revoke --principal spiffe://…`), and
revoke the certificate at its CA so it cannot renew. `port49 revoke` says so when it sees the
workload anchor as the issuer.

## What revocation cannot do

!!! warning "port49 denies; it cannot disconnect"
    TACACS+ has no way for a server to close a device's session. Revocation takes effect at the
    *next authorization request*. The TCP session stays up, a candidate configuration stays intact, and
    an in-progress commit is untouched: the operator is told no, not cut off.

    A platform that asks port49 only at login asks nothing afterwards, so a revocation reaches a context
    nobody reads and the session lasts until the device ends it. Junos asks only at login unless its
    `authorization-time-interval` is set. With it set, Junos re-authorizes the open session once at the
    interval, and a revoked principal is denied `credential_revoked` there. Measured on vJunos-router
    23.4R2-S2.1 and vSRX3 21.4R3.15 with an interval of 15 minutes (L36, closed:
    [vJunos-router](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vjunos-router.md),
    [vSRX](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vsrx.md)).
    The denial does not end the session: it stayed open, and its next command printed an error.

    The decision log's `revoke` record lists the live contexts port49 could not reach, Junos contexts
    included, so you know which devices still need a manual disconnect. `port49 policy test` says so
    when a test names a platform that never asks about a command.

!!! warning "Unmeasured"
    Whether Junos re-authorizes more than once, so whether a revocation made after the first
    re-authorization ever reaches the session, is unknown (L40, open). Do not rely on a revocation
    reaching a Junos session before its device ends it.

Two other limits are worth knowing.

- **`--mine` and `--device` leave no mark.** If anyone else used your token, your next login on that
  device re-admits their session too. Close such a session on the device, or have an operator revoke
  the principal.
- **A key revocation is by principal or certificate only.** There is no finer cut, so deleting unspent
  tokens by certificate also deletes the same principal's tokens from other certificates under the same
  device and username. The error is toward denying.

Who may revoke is policy: see [Policy](../admin/policy.md).
