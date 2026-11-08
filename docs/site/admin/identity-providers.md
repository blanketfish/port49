---
title: Identity providers
description: Connecting an OIDC provider, a directory or a directory password to port49, and ending a person's sessions when the provider signs them out.
---

# Identity providers

A person reaches a device with a **certificate** the broker issues them. This page covers the three things that can
stand behind that issuance: an OIDC provider (Keycloak, Entra ID, Okta and the like), a directory (LDAP, Active
Directory or Samba AD) that supplies groups and, if you have no provider, passwords, and a client certificate you
already have. The concepts are on [Identities](../concepts/identities.md) and
[Trust domains](../concepts/trust-domains.md); what a person types is on [Logging in](../operate/login.md).

## OIDC issuance

An OIDC human verifier sits under `broker.identity.humans`. It is paired with **issuance**, which turns a
verified sign-in into a short-lived certificate:

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
broker's issuing CA is made once, on one broker, with `port49-broker init-issuer`, which writes `issuing-ca.pem` and
`issuing-ca.key` into `broker.state_dir`; copying it to the other brokers and rotating it is on
[Key rotation](key-rotation.md#the-issuing-ca) and [Install](../operate/install/index.md).

The config **refuses** a human `oidc` verifier with no `issuance`, unless an x509 humans verifier with
`per_login_mfa.idp_mfa` sits beside it. The reason is the next section.

### A person's ID token is not a bearer credential

The person's ID token is accepted in exactly two places:

- `POST /v1/certificate`, to exchange a fresh sign-in for a certificate. The sign-in must be at most 5 minutes old and
  bound to the request, or the answer is `sign_in_not_fresh`, `sign_in_not_bound` or `sign_in_not_certifiable`.
- as the proof of an **`idp_mfa`** per-login check (`POST /v1/mfa`), where the provider's own second factor is the
  evidence.

Anywhere else, presenting it is refused **401 `trust_domain_unresolved`**, with a message saying that a person's ID
token is not accepted there, and `/v1/refresh` refuses it too. A stolen ID token therefore cannot be replayed at the
broker to act as the person. Even at `POST /v1/certificate` it is bound to the request: the token's nonce must name
the public key of the certificate request, and the request must be signed by that key, so a thief without the signer's
private key gets `sign_in_not_bound`. A sign-in is also exchanged once; a second exchange gets `sign_in_spent`.
(`max_token_age` is 2h by default; `clock_skew` is 1m.)

### What a provider may name

- `principal_claim` is required: `preferred_username`, `email` or `upn`. With `email`, the provider must say
  `email_verified: true`, and the value must be printable ASCII with an `@`. It is lower-cased into `user:<value>`.
- `principal_domains` is required, and bounds who this provider may name. A provider can only ever speak for the
  domains you list.
- The provider's signing keys are fetched from its discovery document, cached in `broker.state_dir`
  (`oidc-<hash>.json`) and refreshed every `jwks_refresh_interval` (1h). If the provider is unreachable, tokens signed
  by the held keys keep verifying until `jwks_max_age` (24h by default, up to 720h); then every token from it is
  refused `identity_provider_unavailable`. **At 3am**, with the provider down, certificate logins and live device
  sessions are unaffected; if you must accept the held keys longer, raise `broker.identity.jwks_max_age` and restart.
  The broker says each state once, for example:

  ```text
  identity: <issuer>: no key refreshed within broker.identity.jwks_max_age (<jwks_max_age>; the last at <time>); every token from it is refused identity_provider_unavailable until a fetch succeeds; certificate logins and live device sessions are unaffected; to accept the held keys meanwhile, raise broker.identity.jwks_max_age (up to 720h) and restart <process>
  ```

- `HTTPS_PROXY` and `NO_PROXY` are honoured for the provider's requests, and the start line says how each issuer is
  fetched.

!!! warning "Unmeasured"
    Hosted providers, Microsoft Entra ID and Okta, are unmeasured (lab register entry [L47](../reference/lab-register.md#l47), open): whether they send
    `email_verified`, what their tokens carry in `idtyp` and `scp`, and which `aud` their v2 tokens use are unknown
    until a run measures them. Keycloak is the measured provider. Check a hosted provider's token on a test account
    before relying on it.

## Back-channel logout

When a person signs out of the provider, or an administrator ends their session there, the provider can tell the
broker, and the broker ends the person's port49 sessions. Configure the client in the provider with the logout URL
`https://<broker>/v1/logout` and **backchannel logout session required** on. The body is form-encoded, at most
16 KiB.

A logout token that carries both `sid` and `sub` is handled as two logouts: the one for that `sid`, then the one for
that `sub`. **The consequence is that every session of that `sub` ends**, not just the one that signed out. This was
measured: one token revoked by `sid` and then by `sub`, and both sessions' ID tokens were refused
`credential_revoked` (cells 6a to 6e of the
[Arista EOS end-to-end run](https://github.com/blanketfish/port49/blob/main/tests/lab/results/oidc-e2e-arista_eos.md);
the token shapes and the no-retry result are in
[L45](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L45-keycloak.md); ruling B, spec decision 39).
A logout leaves no standing mark, so the person can sign in again after `clock_skew` (1m). In the decision log the
revoke has origin `backchannel_logout <issuer>`.

The broker keeps the logout record for `max_token_age` plus twice `clock_skew` (on an issuing broker,
`max(max_token_age, 24h)` plus twice `clock_skew`, since certificates live that long). If it cannot write the record
the answer is **503**, and the provider is the one to retry. **Keycloak does not retry a failed logout.**

### When a logout did not land

The provider's event log shows the 503, and the broker's log carries the recovery, spelled out for the principal. It
begins

```text
logout: a logout token from <issuer> could not be applied: the store did not answer; answered 503 so the provider may retry; if it does not, once the store returns: <form>
```

and goes on with one of two forms. Both are run through your agent ([Revocation](revocation.md)) and need the
`revoke_others` and `lift_revocations` rights.

**Form 1: the logout wrote its record** (a later step failed). The form reads "if the decision log holds"
a revoke record with origin `backchannel_logout`:

```text
if the decision log has a revoke record with origin backchannel_logout for <principal> just before this line, end its contexts with `port49 revoke --principal <principal>`, then `port49 revoke --lift --principal <principal>` so they may log in again; a lift can be lost across a <process> stop, so last check that `port49 revoke --list` shows no mark for <principal>
```

**Form 2: nothing was written**, so no logout record refuses the person's held ID token or issued certificate. The
revoke is unconditional, and **the lift waits for the time the line prints**, when that token or certificate has
expired (the line's `<time>` is the record's lifetime from now):

```text
end <principal>'s contexts with `port49 revoke --principal <principal>` (api: revoke_others), and lift it with `port49 revoke --lift --principal <principal>` (api: lift_revocations) only after <time>: no logout record refuses the session's held ID token or issued certificate until then; last check that `port49 revoke --list` shows no mark for <principal>
```

A token that carries `sid` and `sub` can get either form: Form 1 when the logout wrote its record, Form 2 when it
wrote nothing. Form 2 is printed once per principal the decision log's mint records name for that `sub`. Lifting
early lets the person's held token mint again. On an issuing broker the line adds a shorter path: revoke each
certificate issued to the principal with `port49 revoke --cert-issuer <DN> --cert-serial <HEX>` (the DN and serial
from each broker's issue records), and lift the mark after `max_token_age` plus twice `clock_skew` instead. The
shorter path holds only if every broker's issue records can be read: if any cannot, wait out the first time.

For a token that names only a `sid`, the line first offers `port49 revoke --sid <sid> --sid-issuer <issuer>` (needs
`revoke_others` and a press of your security key). It ends that one session, as a logout by `sid` does, and leaves
no mark to lift.

## The directory

A directory supplies groups for `group:` subjects and the `username_attribute` for device logins. It is configured
under `broker.directory`; every key is in the [port49d reference](../reference/config/port49d.md).

- `bind` is one of `external` (a client certificate), `gssapi` (Kerberos) or `simple`.
- `principal_attribute` and `username_attribute` must be **writable only by directory administrators**, and need a
  case-insensitive matching rule. Whoever can write them chooses who a person is.
- A principal is pinned to the entry's immutable id (`entryUUID` or `objectGUID`). A rename is followed; two entries
  claiming one principal are refused `identity_ambiguous`, and a username that two entries claim `username_collision`.
  `port49 directory forget <principal>` releases a pin.
- The staleness ceiling is 4h by default, `refresh_interval` 5m and `grace` 4h. See
  [Troubleshooting](../operate/troubleshooting/index.md) for what a stale cache looks like.

| Directory | Use | Notes |
|---|---|---|
| OpenLDAP | `external`, mapped by `olcAuthzRegexp`, with `nested_groups: recursive` | `in_chain` answers empty there, which fails closed |
| Samba AD | `simple` or `gssapi` | SASL EXTERNAL is refused (LDAP result 1); `gssapi` needs `ldap server require strong auth = allow_sasl_over_tls`; `in_chain` works |
| Windows AD | `external` over `ldap://` with `start_tls: true` | `ldaps://` gets result 7; result 49 means the certificate is unmapped or that DC's KDC is down; `gssapi` is refused under `LdapEnforceChannelBinding = 2` |

The Windows row is measured on Windows Server 2025 only
([L44](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L44-windows_ad.md)); older Windows Server
releases are unmeasured. OpenLDAP and Samba are in
[L42](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L42-openldap.md) and
[L43](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L43-samba_ad.md).

### Certificate mapping and `identity_unmapped`

With `external` on Windows AD, the directory finds a person's entry from the certificate through
`altSecurityIdentities`, so each entry holds the string for its certificate. port49 computes the same string Windows
does:

```text
X509:<I>DC=com,DC=corp,CN="corp, ""east"" CA"<SR>11AC0000000012
```

That is the value for an issuer `DC=com, DC=corp, CN=corp, "east" CA`: `<I>` is the issuer's RDNs, most significant first, and
`<SR>` the serial's bytes reversed in upper-case hex. A value is quoted the way Windows' CertNameToStr quotes it: a
value is quoted if it is empty, contains any of `,+="<>#;` or a newline, or has leading or trailing white space, and
an inner `"` is doubled. A backslash and a slash are not quoted. Of these, **a comma, a plus, an inner quote and a
leading space were measured**; an empty value, trailing white space, `=`, `<`, `>`, `#`, `;`, a newline and white
space other than a plain space are unmeasured, so a certificate whose issuer holds one is a case to test.

A **multi-valued** relative distinguished name in the issuer has no one string, so port49 does not guess one: the
mapping is empty and the certificate is refused `identity_unmapped`. That fails closed.

`identity_unmapped` is also what you get when no entry holds the string. The broker's detail reads
`directory: identity_unmapped: no entry under <BaseDN>`, and for a certificate from a CA that
`broker.directory.certificate_mapping.issuers` does not pin, `the certificate's issuer "<issuer>" is not one
broker.directory.certificate_mapping.issuers pins`. A certificate with several UPN SANs says
`the certificate carries <n> UPN SANs; exactly one maps`. **It does not print the value it searched for.** To find the
string to look for, compute it as above from the certificate's issuer and serial, or read it from the entry that
should hold it.

## Directory-password sign-in

For a site with no provider and no PKI. A person signs in with their directory password and a time-based
code from an authenticator app, over `POST /v1/sign-in` and `POST /v1/sign-in/confirm`, and the broker issues the
same certificate. The order is deliberate: the code is checked first and its step consumed, then **one bind as the
person's own entry**, then the certificate. A spray therefore never reaches the directory for someone with a code,
and port49 cannot lock an account. Service accounts and workload entries are refused.

The broker refuses a `directory_password` verifier whose `principal_domains` overlap an `oidc` verifier's: a password
beside a provider that enforces stronger sign-in is a downgrade an attacker would pick.

### Enrolling the authenticator

A person with no authenticator enrolls at a sign-in whose password is right, **only while a window is open for them**:

| Window | Opens when | Default |
|---|---|---|
| `enrollment.open_until` | a date you set, for the whole fleet (a rollout) | none |
| `enrollment.new_entries_for` | after the entry's creation (`whenCreated` or `createTimestamp`) | 336h |
| `enrollment.reopen_for` | after `port49 directory reset-second-factor <principal>` | 24h |

`port49 directory reset-second-factor --all` opens the reopen window for everyone. Outside every window the answer is
**403 `enrollment_closed`**. An entry with no creation time counts as outside its `new_entries_for` window, so a
directory that does not supply one fails closed.

**State the weakening plainly: inside a window, the directory password alone lets the first caller enrol their own
authenticator.** If that password is stolen, the thief enrolls first and the real person later finds a second factor
they never set up. Every enrollment is an `enroll` record you can alert on. Keep windows short, and close
`open_until` when a rollout ends.

The enrollments live in a sealed file in `broker.state_dir` (or in etcd). Create it once with
`port49-broker init-enrollments`; the broker never creates it, because a store that went missing must not reopen
enrollment for everyone. A missing or unreadable one refuses password sign-in with **503 `enrollment_store_lost`**,
and every other path keeps serving. Restore it from backup with `port49 directory import`, or run
`reset-second-factor --all`. `port49-broker export-enrollments` writes a copy ([backup and
restore](../operate/backup-and-restore.md)). Operator commands: `port49 directory forget`, `unlock` and
`reset-second-factor`, through your agent.

Limits are 5 failures per person and 50 per source in 15 minutes (`rate_limits`); over them the answer is
`429 sign_in_throttled`, and `port49 directory unlock <principal>` clears one person's count at 3am.
