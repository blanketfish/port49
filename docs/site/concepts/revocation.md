---
title: Revocation
description: How port49 ends access that was already granted, and how quickly it takes effect.
---

# Revocation

Short tokens let expiry do most of the work. Revocation is for a stolen laptop, an offboarding or a
certificate that must stop now. It goes through the broker's API, so it needs no access to the store.
`port49 revoke` takes one target: a principal, a certificate, an OIDC session, one device login, or your own
sessions. Revoking another principal needs the `revoke_others` right and a press of the operator's security
key. The commands and rights are in [Administer: revoking access](../admin/revocation.md).

A principal or certificate revocation leaves a standing mark, which stays in force until someone lifts it.
It is kept in the store (with a copy in `broker.state_dir`), or, on the memory store, in
`broker.revocations_file`, so a restart forgets nothing. A mark does not expire, because the agent
reconnects with the same key by itself.

## What happens, in order

The mark is written first. The broker then closes the held connections it names, deletes unspent tokens for
the principal or certificate, marks every live login context under it revoked and deletes its receipts. It
reads and marks the contexts a second time to catch a redemption that was in flight.

The next mint by that principal is refused `credential_revoked`, which ends a person's agent session at its
next request. A login with a token minted before the revocation is refused `credential_revoked` too, and a
device's retransmission of an earlier login is answered `token_not_found`, because the receipt is gone. Each
revocation is one `revoke` record in the [decision log](../reference/decision-log.md), naming what it
reached and which live contexts it could not.

## Other things that revoke

Each of these marks the live context revoked, and its next authorization is denied `credential_revoked`. The
`refresh` record before the denial says which it was.

- a certificate appearing on a CRL or OCSP response;
- an OIDC back-channel logout, by `sid` or `sub`;
- the broker's periodic refresh finding that the principal has no grant on the device any more, or that the
  directory no longer maps the principal (the entry is gone, ambiguous, or renamed to a username another
  entry holds);
- a subject's username changing, since the principal can no longer mint under the name the context is keyed
  by.

A certificate that cannot be checked at all, such as a stale CRL, is not revocation. It is
`trust_domain_unresolved` at mint, and `broker.certificate_status.on_unavailable` decides whether that
refuses.

A workload certificate renews under the same SPIFFE ID, so a mark on one certificate does not follow the
renewal. Revoke the workload's principal (`port49 revoke --principal spiffe://…`) and revoke the
certificate at its CA so it cannot renew.

## What revocation cannot do

!!! warning "port49 denies; it cannot disconnect"
    TACACS+ has no way for a server to close a device's session. Revocation takes effect at the
    next authorization request. The TCP session stays up and an in-progress commit is untouched: the
    operator is told no, not cut off.

    A platform that asks port49 only at login never asks again, so the session lasts until the device ends
    it. Junos asks only at login unless its
    `authorization-time-interval` is set. With it set, Junos re-authorizes the open session at the
    interval (one re-authorization was measured), and a revoked principal is denied `credential_revoked` there. Measured on vJunos-router
    23.4R2-S2.1 and vSRX3 21.4R3.15 with an interval of 15 minutes ([L36](../reference/lab-register.md#l36), closed:
    [vJunos-router](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vjunos-router.md),
    [vSRX](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vsrx.md)).
    The denial does not end the session: it stayed open, and its next command printed an error.

    The `revoke` record lists the live contexts port49 could not reach, Junos included, so you know which
    devices still need a manual disconnect. `port49 policy test` warns when a test names a platform that
    never asks about a command.

!!! warning "Unmeasured"
    Whether Junos re-authorizes more than once, so whether a revocation made after the first
    re-authorization ever reaches the session, is unknown ([L40](../reference/lab-register.md#l40), open). Do not rely on a revocation
    reaching a Junos session before its device ends it.

Two other limits. `--mine` and `--device` leave no mark, so if anyone else used your token, your next login
on that device re-admits their session: close it on the device, or have an operator revoke the principal.
And a key revocation is by principal or certificate only, so deleting unspent tokens by certificate also
deletes the same principal's tokens from other certificates under the same device and username. The error is
toward denying.

Who may revoke is policy: see [Policy](../admin/policy.md).
