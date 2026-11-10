---
title: Trust domains
description: What a trust domain is and what port49 trusts inside and outside one.
---

# Trust domains

A person and a workload must never be confusable. A workload that could present as a person, or
inherit a person's grants, would turn a leaked service credential into an operator's access. port49
makes the difference structural rather than checking a name.

## The rule

**A principal's trust domain is whichever verifier validated its credential.** Configuration declares
the verifiers in two lists, `broker.identity.humans` and `broker.identity.machines`
([port49d reference](../reference/config/port49d.md)), and nothing else classifies. A claim inside a
token, a naming convention or a group never decides.

```yaml
broker:
  identity:
    issuance: {}   # an OIDC person's ID token is taken to issue a certificate
    humans:
      - type: x509
        trust_anchor_file: <people-ca.pem>
      - type: oidc
        issuer: https://login.example.com
        client_id: <client_id>
        principal_claim: email
        principal_domains: [example.com]
    machines:
      - type: x509
        trust_anchor_file: <workload-ca.pem>
        spiffe_trust_domains: [example.org]
      - type: k8s
        issuer: https://kube.example.com
        cluster: us_east
        jwks: https://kube.example.com/openid/v1/jwks
        audience: port49
        namespaces: [netops]
```

The values are placeholders; the full key list is in the reference.

`issuance: {}` turns on certificate issuance with its defaults. The broker refuses an OIDC human verifier
without it. The one exception is an OIDC verifier that sits beside an x509 human verifier and serves only as
a per-login MFA proof.

## What follows from the rule

- **A credential no verifier accepts is refused at mint.** The reason is `trust_domain_unresolved`.
  The same reason covers a certificate whose revocation status cannot be established when
  `broker.certificate_status.on_unavailable` is `refuse`. See
  [Reason codes](../reference/reason-codes.md) for the full meaning.
- **A credential two verifiers accept is refused.** There is no tie-break. A person's delegated token is
  never a machine's, and two issuers never give one principal.
- **`principal_domains` bounds who a provider may name.** An OIDC human verifier lists the domains whose
  people it may name (`user:<name>@<domain>`), and has no default. Another provider cannot name someone
  in your domains, even with a claim that looks right. `principal_claim` likewise has no default: set it
  to a claim only your provider's administrators can write.
- **The same issuer may serve both lists with a different audience.** An identity provider that issues
  tokens to people and to applications uses one issuer for both. `client_id` names the public client
  whose ID token a person presents; `audience` names the API in the access token a service obtains.
  Both are checks on `aud`, and the list the token matched decides the domain.
- **Certificate anchors may not overlap.** The handshake verifies against both anchors, and the one the
  chain ends at is the domain. A chain that ends at both is refused at the TLS handshake. That leaves a
  line in the broker's log and a count of `identity_refused` handshake failures, not a decision record.
  Put the two anchors in unrelated hierarchies. The broker refuses to start if one anchor directly signs
  the other, and refuses at a request whose chain shows a deeper overlap.
- **A workload never authenticates with a directory password.** The password sign-in refuses a workload's
  entry, and the verifier's `filter` keeps a person-shaped service account out.
- **Directory groups reach a workload only as a machine group.** A workload can be mapped to a directory
  entry for membership, opt in per verifier, and the membership reaches only a `machine_group:` subject,
  never a person's. So a workload cannot inherit a person's grants by any route.

## What is trusted, and what is not

| Inside the domain | Outside it |
|---|---|
| the verifier's trust anchor, or the provider's published keys | any other CA or provider, even if it names the same user |
| the principal that verifier derived (a certificate's mapped entry, an OIDC principal claim, a SPIFFE ID, a service account name) | a group or role asserted by the credential |
| a directory entry the principal maps to exactly once | a name that matches more than one entry, which denies |

Policy identity strings carry the domain in their form, so a policy test can check the distinction in
CI without any credential in hand. See [Policy](../admin/policy.md).

## Your own trust domain

port49 is a relying party, not a certificate authority, with one exception: the short-lived
certificate it issues a person after an OIDC or directory-password sign-in. That is port49's own
trust domain. Only the broker that issued it reads it, no device ever sees it, and its CA lives in the
broker's state directory and rotates with overlap.
