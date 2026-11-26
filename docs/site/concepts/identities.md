---
title: Identities
description: How port49 knows who is logging in, for people and for workloads.
---

# Identities

port49 does not keep users. It checks a credential that something else issued, and from there every path
looks the same: a principal, groups from the directory, and a session. The verifiers a broker trusts are
`broker.identity.humans` and `broker.identity.machines` in the
[port49d reference](../reference/config/port49d.md), and what a verifier accepts decides the principal's
[trust domain](trust-domains.md).

Groups never come from a credential. They are read from the directory when a token is minted, so an OIDC
deployment with no directory can name people in policy only by literal identity.

## People

There are three ways to sign in. They differ in how a person proves identity, and in nothing downstream.

### An x509 client certificate

`port49 login` presents a client certificate in a mutual-TLS handshake to the broker, which validates the
chain, expiry, revocation status and the client-authentication usage. The handshake is the proof that the
person holds the key, and the agent keeps that connection for
[the session](tokens-receipts-contexts.md#the-session).

The certificate must map to exactly one directory entry. Zero matches deny, and more than one denies loudly
rather than picking the first. `broker.directory.certificate_mapping` picks the kind. Strong kinds
(`issuer_serial`, `sid`) bind to a key. Weak kinds (`san_upn`, `san_email`, `subject_dn`, `cn`) bind to a
name, so they are refused at load without `allow_weak: true` and an issuer pin: any other trusted CA could
issue a certificate bearing the same name.

### OIDC, with a certificate port49 issues

This is the path for a company with no PKI. `port49 login --oidc` signs in at the identity provider with the
authorization-code flow (PKCE), and the broker validates the ID token against the provider's published keys.
It then issues a short-lived client certificate (12 hours by default) for a key generated on the person's
own host, and the agent holds no token.

The key lives where `issued_key_store` says ([client reference](../reference/config/client.md)). A key in
a file is copyable, and whoever copies it holds the session until the certificate ends. A key in a TPM or
hardware token is not. If the provider is down, people already holding a certificate keep working until it
ends.

### A directory password and an authenticator code

`port49 login --directory` is for a company with neither a PKI nor an identity provider. The person's
directory password and a TOTP code go to the broker over its TLS. The broker checks the code first, then
the password, by a single bind as the person's own directory entry (LDAPS or StartTLS), then issues the
same certificate as the OIDC path. The password is never stored, logged or given to a device. Attempts are
limited per person and per source address, counted before they are judged. A workload's directory entry is
refused.

Extending a session at its ceiling needs a fresh authentication event, which on the certificate paths is
the key's signature over a nonce, so nothing secret crosses the wire again.

## Machines

A workload cannot sign in interactively and has no directory password. Three mechanisms cover it,
and `port49 workload token` mints with no agent for any of them. [Workloads](../admin/workloads.md) sets each one up.

- Kubernetes service account tokens are the first choice inside a cluster. The broker validates a projected
  token with the audience `port49` against the cluster's published keys, and the principal is
  `system:serviceaccount:<namespace>:<name>`. There is no secret at rest.
- Workload certificates are for hosts outside a cluster. The `x509` machine verifier has its own trust
  anchor, and the principal is the certificate's one URI SAN, a SPIFFE ID.
- A machine OIDC client is for a workload that gets its token from your identity provider. The verifier
  lists the client ids it accepts, each pinned to its subject, and the principal is `app:<client_id>`.

A workload's access is its own identity subject's in policy. It can be mapped to a directory entry for group
membership, but only to a machine-scoped group.

A deleted service account's token stays valid until its own expiry or `broker.identity.max_token_age`,
whichever comes first. To stop it sooner, [revoke](revocation.md) the principal.

## Which one to use

With a PKI and hardware keys, use an x509 client certificate. With an identity provider and no PKI, use
OIDC (`port49 login --oidc`). With neither, use a directory password and TOTP (`port49 login --directory`).
For automation, use a service account token in Kubernetes, a workload certificate on static hosts, or a
machine OIDC client when your identity provider issues the token.
