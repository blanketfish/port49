---
title: OIDC sign-in
description: Register port49 with an OIDC provider, turn on certificate issuance and back-channel logout, and recover when a logout did not land.
---

# OIDC sign-in

People sign in at an OIDC provider such as Keycloak, Entra ID or Okta. The broker checks the sign-in and issues a
short-lived certificate. [Identities](../../concepts/identities.md) explains how that certificate becomes a login.

## Set it up

1. In the provider, register a public client for port49 and set its back-channel logout URL to
   `https://<broker>:<port>/v1/logout`, with **backchannel logout session required** on. The broker must reach the
   provider's discovery and JWKS URLs. Where egress goes through a proxy, set `HTTPS_PROXY` and `NO_PROXY` on the
   broker. The start line says how each issuer is fetched.

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
    sits beside it. An OIDC-only broker, with no x509 verifier, is valid.

3. Make the issuing CA once, on one broker, if you have not: `port49-broker init-issuer`. The install page for your
   deployment has the step, and [key rotation](../key-rotation.md#the-issuing-ca) covers copying it to other brokers.

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

- `principal_claim` is required: `preferred_username`, `email` or `upn`. With `email`, the provider must say
  `email_verified: true`, and the value must be printable ASCII with an `@`. It is lower-cased into `user:<value>`.
- `principal_domains` is required and bounds who the provider may name. It can only speak for the domains you list.
- Each machine client's `sub` is read from the provider: in Keycloak, the client's "Service account roles" user id;
  in Entra ID, the service principal's object id.
- Signing keys come from the discovery document. The broker keeps them in `broker.state_dir` (`oidc-<hash>.json`)
  and refreshes them every `jwks_refresh_interval` (1h). A fetch failure never changes `/readyz`.

If the provider is unreachable, tokens signed by the held keys keep verifying until `jwks_max_age` (24h by default,
up to 720h). After that, every token from it is refused `identity_provider_unavailable`.

At 3am with the provider down, certificate logins and live device sessions are unaffected. To accept the held keys
longer, raise `broker.identity.jwks_max_age` and restart. The broker says each state once, for example:

```text
identity: <issuer>: no key refreshed within broker.identity.jwks_max_age (<jwks_max_age>; the last at <time>); every token from it is refused identity_provider_unavailable until a fetch succeeds; certificate logins and live device sessions are unaffected; to accept the held keys meanwhile, raise broker.identity.jwks_max_age (up to 720h) and restart <process>
```

## A person's ID token is not a bearer credential

The broker accepts a person's ID token in two places only:

- `POST /v1/certificate`, to exchange a fresh sign-in for a certificate. The sign-in must be at most 5 minutes old and
  bound to the request, or the answer is `sign_in_not_fresh`, `sign_in_not_bound` or `sign_in_not_certifiable`.
- As the proof of an `idp_mfa` per-login check (`POST /v1/mfa`), where the provider's own second factor is the evidence.

Anywhere else, including `/v1/refresh`, it is refused 401 `trust_domain_unresolved`. A stolen ID token cannot be
replayed at the broker to act as the person.

Even at `POST /v1/certificate` the token's nonce must name the public key of the certificate request, and that key
must sign the request. A thief without the private key gets `sign_in_not_bound`. A sign-in is exchanged once; a
second exchange gets `sign_in_spent`. `max_token_age` is 2h by default and `clock_skew` is 1m.

## Back-channel logout

When a person signs out at the provider, or an administrator ends their session there, the provider tells the broker
and the broker ends the person's port49 sessions. The body is form-encoded, at most 16 KiB.

A logout token that carries both `sid` and `sub` is handled as two logouts, one for the `sid` and one for the
`sub`, so every session of that `sub` ends, not only the one that signed out. This was measured: both sessions' ID
tokens were refused `credential_revoked` (cells 6a to 6e of the
[Arista EOS end-to-end run](https://github.com/blanketfish/port49/blob/main/tests/lab/results/oidc-e2e-arista_eos.md);
the token forms and the no-retry result are in
[L45](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L45-keycloak.md); spec decision 39, ruling B).
A logout leaves no standing mark, so the person can sign in again after `clock_skew` (1m). In the decision log the
revoke has origin `backchannel_logout <issuer>`.

The broker keeps the logout record for `max_token_age` plus twice `clock_skew` (on an issuing broker,
`max(max_token_age, 24h)` plus twice `clock_skew`, since certificates live that long). If it cannot write the record
it answers 503 and the provider is the one to retry. Keycloak does not retry a failed logout.

### When a logout did not land

The provider's event log shows the 503, and the broker's log carries the recovery for the principal. It begins:

```text
logout: a logout token from <issuer> could not be applied: the store did not answer; answered 503 so the provider may retry; if it does not, once the store returns: <form>
```

Both forms run through your agent ([Revoking access](../revocation.md)) and need the `revoke_others` and
`lift_revocations` rights.

Form 1 means the logout wrote its record and a later step failed. It reads:

```text
if the decision log has a revoke record with origin backchannel_logout for <principal> just before this line, end its contexts with `port49 revoke --principal <principal>`, then `port49 revoke --lift --principal <principal>` so they may log in again; a lift can be lost across a <process> stop, so last check that `port49 revoke --list` shows no mark for <principal>
```

Form 2 means nothing was written, so no logout record refuses the person's held ID token or issued certificate.
The revoke is unconditional, and the lift waits for the time the line prints, when that token or certificate has
expired. Lifting early lets the held token mint again.

```text
end <principal>'s contexts with `port49 revoke --principal <principal>` (api: revoke_others), and lift it with `port49 revoke --lift --principal <principal>` (api: lift_revocations) only after <time>: no logout record refuses the session's held ID token or issued certificate until then; last check that `port49 revoke --list` shows no mark for <principal>
```

A token with `sid` and `sub` gets Form 1 when the logout wrote its record and Form 2 when it wrote nothing. Form 2 is
printed once per principal that the decision log's mint records name for that `sub`.

On an issuing broker the line adds a shorter path. Revoke each certificate issued to the principal with
`port49 revoke --cert-issuer <DN> --cert-serial <HEX>` (the DN and serial come from each broker's issue records), then
lift after `max_token_age` plus twice `clock_skew` instead of the printed time. This holds only if every broker's issue
records can be read. If any cannot, wait out the first time.

For a token that names only a `sid`, the line first offers `port49 revoke --sid <sid> --sid-issuer <issuer>`, which
needs `revoke_others` and a press of your security key. It ends that one session and leaves no mark to lift.
