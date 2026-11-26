---
title: OIDC sign-in
description: Register port49 with an OIDC provider, turn on certificate issuance and back-channel logout, and recover when a logout did not land.
---

# OIDC sign-in

People sign in at an OIDC provider such as Keycloak, Entra ID or Okta. The broker checks the sign-in and issues a
short-lived certificate. [Identities](../../concepts/identities.md) explains how that certificate becomes a login.

## Set it up

1. In the provider, register a public client for port49 and set its back-channel logout URL to
   `https://<broker>:<port>/v1/logout`, with backchannel logout session required on. The broker must reach the
   provider's discovery and JWKS URLs. Behind a proxy, set `HTTPS_PROXY` and `NO_PROXY` on the broker. The start line
   says how each issuer is fetched.

2. Add the verifier and turn on issuance in the broker config:

    ```yaml
    broker:
      identity:
        humans:
          - type: oidc
            issuer: https://idp.example.com/realms/corp
            client_id: port49
            principal_claim: preferred_username
            principal_domains: ["example.com"]
        issuance:
          certificate_lifetime: 12h
    ```

    `issuance: {}` turns it on with the defaults. `certificate_lifetime` is 12h by default and may be 1h to 24h. The
    config refuses an `oidc` human verifier with no `issuance`, unless an x509 verifier with `per_login_mfa.idp_mfa`
    sits beside it. An OIDC-only broker is valid.

3. Make the issuing CA once, on one broker: `port49-broker init-issuer`. Your deployment's install page has the step, and
   [key rotation](../key-rotation.md#the-issuing-ca) covers copying it to other brokers.

4. Restart the broker, then sign in from a test account. To check, run:

    ```sh
    port49 login --oidc
    ```

    Success prints `port49: logged in to <broker>; the session ends at <time>`.

!!! warning "Unmeasured"
    Hosted providers, Microsoft Entra ID and Okta, are unmeasured (lab register entry [L47](../../reference/lab-register.md#l47), open). Whether they send
    `email_verified`, what their tokens carry in `idtyp` and `scp`, and which `aud` their v2 tokens use are unknown
    until a run measures them. Keycloak is the measured provider. Check a hosted provider's token on a test account
    before relying on it.

## What a provider may name

`principal_claim` is required: `preferred_username`, `email` or `upn`. With `email` the provider must say
`email_verified: true`, and the value must be printable ASCII with an `@`. It is lower-cased into `user:<value>`.
`principal_domains` is required and bounds who the provider may name. A machine client's `sub` is read from the provider:
in Keycloak the client's "Service account roles" user id, in Entra ID the service principal's object id.

The broker keeps the provider's signing keys in `broker.state_dir` (`oidc-<hash>.json`) and refreshes them every
`jwks_refresh_interval` (1h). A fetch failure never changes `/readyz`. If the provider is unreachable, tokens signed by
the held keys keep verifying until `jwks_max_age` (24h by default, up to 720h). After that every token from it is refused
`identity_provider_unavailable`. At 3am with the provider down, certificate logins and live device sessions are
unaffected. To accept the held keys longer, raise `broker.identity.jwks_max_age` and restart. The broker says each state
once, for example:

```text
identity: <issuer>: no key refreshed within broker.identity.jwks_max_age (<jwks_max_age>; the last at <time>); every token from it is refused identity_provider_unavailable until a fetch succeeds; certificate logins and live device sessions are unaffected; to accept the held keys meanwhile, raise broker.identity.jwks_max_age (up to 720h) and restart <process>
```

## A person's ID token is not a bearer credential

The broker accepts a person's ID token in two places only: `POST /v1/certificate`, to exchange a fresh sign-in (at most 5
minutes old, bound to the request) for a certificate, which otherwise answers `sign_in_not_fresh`, `sign_in_not_bound` or
`sign_in_not_certifiable`; and as the proof of an `idp_mfa` per-login check (`POST /v1/mfa`). Anywhere else, including
`/v1/refresh`, it is refused 401 `trust_domain_unresolved`, so a stolen ID token cannot be replayed to act as the person.

Even at `POST /v1/certificate` the token's nonce must name the public key of the certificate request, and that key must
sign the request, or a thief gets `sign_in_not_bound`. A sign-in is exchanged once; a second exchange gets
`sign_in_spent`. `max_token_age` is 2h by default and `clock_skew` is 1m.

## Back-channel logout

When a person signs out at the provider, or an administrator ends their session there, the provider tells the broker and
the broker ends the person's port49 sessions. The body is form-encoded, at most 16 KiB.

A logout token that carries both `sid` and `sub` is handled as two logouts, so every session of that `sub` ends, not only
the one that signed out. This was measured: both sessions' ID tokens were refused `credential_revoked` (cells 6a to 6e of
the [Arista EOS end-to-end run](https://github.com/blanketfish/port49/blob/main/tests/lab/results/oidc-e2e-arista_eos.md);
the token forms and the no-retry result are in
[L45](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L45-keycloak.md); spec decision 39, ruling B).
A logout leaves no standing mark, so the person can sign in again after `clock_skew`. In the decision log the revoke has
origin `backchannel_logout <issuer>`.

The broker keeps the logout record for `max_token_age` plus twice `clock_skew` (on an issuing broker,
`max(max_token_age, 24h)` plus twice `clock_skew`). If it cannot write the record it answers 503 and the provider
retries. Keycloak does not retry a failed logout. The broker's log then spells out the recovery for the principal, in
one of two forms. Both end the principal's contexts with `port49 revoke --principal`, then lift with
`port49 revoke --lift`. When the decision log shows the `backchannel_logout` record, lift at once. When the logout
wrote nothing, lift only after the time the line prints, because lifting early lets the held token mint again. Both
steps need `revoke_others` and `lift_revocations`. The [3am index](../../operate/troubleshooting/index.md) has both
forms in full.
