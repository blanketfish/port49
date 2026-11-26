---
title: Identities
description: How port49 knows who is logging in, for people and for workloads.
---

# Identities

port49 does not keep users. It checks a credential that something else issued. From there on every
path looks the same: a principal (the identity port49 derived from the credential), groups from the
directory, and a session.

Which verifiers a broker trusts is configuration: `broker.identity.humans` and `broker.identity.machines`
in the [port49d reference](../reference/config/port49d.md). What a verifier accepts decides the principal's
[trust domain](trust-domains.md).

Groups never come from a credential. They are read from the directory when a token is minted, so an
OIDC deployment with no directory can name people in policy only by literal identity. That works for a
small team, and it is the point at which a directory earns its place.

## People

There are three ways to sign in. They differ in how a person proves identity, and in nothing
downstream.

### An x509 client certificate

`port49 login` presents a client certificate in a mutual-TLS handshake to the broker. The broker
validates the chain, expiry, revocation status and the client-authentication usage. The handshake itself
is the proof that the person holds the key. The agent keeps that connection for
[the session](tokens-receipts-contexts.md#the-session), and every token for the rest of the day is minted
over it.

The certificate must map to exactly one directory entry. Zero matches deny, and more than one denies loudly
rather than picking the first. The mapping kind is `broker.directory.certificate_mapping`:

- Strong kinds bind to a key: `issuer_serial`, `sid`.
- Weak kinds bind to a name: `san_upn`, `san_email`, `subject_dn`, `cn`. They are refused at load
  without `allow_weak: true` and an issuer pin, because any other trusted CA could otherwise issue a
  certificate bearing the same name.

### OIDC, with a certificate port49 issues

This is the path for a company with no PKI. `port49 login --oidc` signs in at the organization's identity
provider with the authorization-code flow (PKCE). The broker validates the ID token against the provider's
published keys. Then it issues the person a short-lived client certificate (12 hours by default) for a
key generated on their own host. From then on the person has the certificate path's session, and the agent
holds no token.

The key lives where `issued_key_store` in the client configuration says ([client
reference](../reference/config/client.md)). A key kept in a file is copyable, and whoever copies it holds
the session until the certificate ends. A key in a TPM or hardware token is not copyable.

If the provider is down, people already holding a certificate keep working until it ends.

### A directory password and an authenticator code

`port49 login --directory` is for a company with neither a PKI nor an identity provider. The person's
directory password and a TOTP code go to the broker over its TLS. The broker checks the code first, then
the password, by a single bind as the person's own directory entry (LDAPS or StartTLS). Then it issues the
same certificate as the OIDC path.

The password is never stored, logged or given to a device. Attempts are limited per person and per source
address, counted before they are judged. Service accounts do not sign in this way, and a workload's
directory entry is refused.

### Extending a session

Extending a session at its ceiling needs a fresh authentication event, not a replay of the old
one. On the certificate paths that is the key's signature over a nonce, so nothing secret crosses the
wire again.

## Machines

A workload cannot sign in interactively and has no directory password. Three mechanisms cover it,
and `port49 workload token` mints with no agent for any of them. [Workloads](../admin/workloads.md) sets each one up.

- Kubernetes service account tokens are the first choice inside a cluster. The kubelet rotates a projected
  token with the audience `port49`, the broker validates it against the cluster's published keys, and the
  principal is `system:serviceaccount:<namespace>:<name>`. There is no certificate to renew and no secret at rest.
- Workload certificates are for hosts outside a cluster. The `x509` machine verifier has its own
  trust anchor, separate from any person's, and the principal is the certificate's one URI SAN, a SPIFFE ID.
- A machine OIDC client is for a workload that gets its token from your identity provider. The verifier
  lists the client ids it accepts, each pinned to its subject, and the principal is `app:<client_id>`.

A workload's access is its own identity subject's in policy. A machine can be mapped to a directory entry
for group membership, but only to a machine-scoped group, never to a person's.

A deleted service account's token stays valid at port49 until its own expiry or the broker's
`broker.identity.max_token_age`, whichever comes first. To stop it sooner, revoke the principal; see
[Revocation](revocation.md).

## Which one to use

| If you have | Use |
|---|---|
| a PKI and hardware keys | an x509 client certificate |
| an identity provider and no PKI | OIDC (`port49 login --oidc`) |
| neither | a directory password and TOTP (`port49 login --directory`) |
| automation in Kubernetes | a service account token |
| automation on static hosts | a workload certificate |
| automation with a client at your identity provider | a machine OIDC client |
