# Plan 7h: OIDC and Trust Domains — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a person or a service authenticate to the broker with an OIDC token from the
organization's identity provider, assign every credential its trust domain by the verifier that
accepted it (decision 16), and let the provider end a person's live device sessions by
back-channel logout.

- **Trust domains (decision 16; design §7).**
  - The broker declares its verifiers in two lists, `broker.identity.humans` and
    `broker.identity.machines`.
  - A principal's domain is the list its verifier is in. Nothing in the credential is read to
    decide it.
  - 7h builds:
    - `x509` under `humans`: today's `broker.client_ca_file`, moved into the list;
    - `oidc` under `humans`: an ID token from a public client, keyed by `client_id`, for the
      `principal_domains` it is authoritative for;
    - `oidc` under `machines`: an access token from the client-credentials grant, keyed by
      `audience`, from a listed client whose `sub` is pinned. A person's delegated token for
      that client is refused.
  - `x509` under `machines` (workload certificates) and `k8s` are refused at load, naming plans
    8 and 10.
- **OIDC tokens, validated per request.**
  - A request carries `Authorization: Bearer <token>`.
  - Validation: a compact JWS whose `alg` is pinned per verifier (default `RS256`), and never
    `none` or an HMAC; a key from the provider's JWKS chosen by `kid`; then `iss`, `aud`,
    `azp`, `exp`, `nbf`, `iat`, `sub`, and a human's `auth_time`, within `clock_skew`.
  - **The principal.** A human's is `user:` plus the claim the deployment names
    (`preferred_username`, `email` with `email_verified`, or `upn`; required, no default), in
    one of the verifier's `principal_domains`. A machine's is `app:` plus `azp`, a client the
    verifier lists.
  - **Groups.** They come from the directory, through 7g's `Resolver`, never from the token.
- **Keys, with a 3am story.**
  - **Fetching.** Discovery and the JWKS are fetched over TLS, through `HTTPS_PROXY` when one is
    set, and refreshed hourly, and again on an unknown `kid` (at most once a minute).
  - **Persisting.** The keys are kept in the broker's state directory, so a restart during a
    provider outage keeps them.
  - **Staleness.** Keys not refreshed for `jwks_max_age` (24h) are no longer trusted. Every
    token is then refused 503 `identity_provider_unavailable`, and the agent retries.
  - **Device sessions.** A provider outage never touches one: the daemon never sees an OIDC
    token.
- **Session lifetime from the assertion (spec §5.6; decision 17).**
  - A human token's `auth_time` is the session clock.
  - **Refresh.** The broker issues a nonce at `POST /v1/refresh/challenge`. The agent sends it
    as the OIDC `nonce` of a `prompt=login` authentication. `POST /v1/refresh` accepts the new
    ID token only if its `nonce` is that challenge, unspent, and its `auth_time` is no earlier
    than the challenge. It then extends the person's live sessions from that `auth_time`.
- **Back-channel logout (OIDC Back-Channel Logout 1.0).**
  - **The endpoint.** `POST /v1/logout` validates the provider's logout token.
  - **What it reaches.** By `sid`, it ends the contexts that session authorized. By `sub`, it
    ends every context of the person, within the provider's `principal_domains`. It also
    deletes the person's unspent tokens and refuses every token of the dead session from then
    on.
  - **What it leaves.** No standing mark: the person may log in again at once.
  - **Over the API.** `POST /v1/tokens/revoke` takes a `sid` under `revoke_others`.
- **`amr` and `acr` are recorded**, in the context's sealed credential and in the decision log's
  `auth.oidc`, and consulted by nothing (decision 13).
- **`GET /v1/config`** names each human OIDC verifier's issuer, `client_id` and scopes, for the
  agent's public client (plan 9).
- **Lab (on beehive).** Keycloak in a container:
  - **L45:** the back-channel logout token Keycloak sends, and what it does when the broker does
    not answer 200;
  - **L46:** what `prompt=login` does to `auth_time`, `nonce` and `sid`, beside a refresh-token
    grant;
  - **L47:** both claims on hosted providers (Microsoft Entra ID, Okta). It opens and stays
    open.
  - An end-to-end run on the compose stack with vEOS: an OIDC login on the device, a logout at
    Keycloak, and the next command denied `credential_revoked`.

**Architecture:**
- **`internal/oidc`**, a new package, owns everything that reads a token:
  - `jws.go` and `jwk.go`: compact JWS and JWK, the standard library's crypto alone (OR-1),
    checked against the RFC examples, Project Wycheproof's vectors, an algorithm × key-type
    matrix and two fuzz targets;
  - `keyset.go`: one issuer's discovery and keys, refreshed, rate-limited, persisted and aged out;
  - `verify.go`: `Set`, the trust-domain lists, `Verify` (a bearer) and `Assertion`;
  - `logout.go`: `VerifyLogout`, a logout token per Back-Channel Logout 1.0 §2.6;
  - `config.go`: `Config`, which `internal/config` fills, as `directory.Config` is filled.

  It imports `store` (for `Credential`) and `metrics`, and nothing of `broker` or `policy`.
- **`store`** gains three small record families, each the broker's alone:
  - `Once`: put-if-absent with a TTL, and take-once. It holds a logout token's `jti` and a
    refresh challenge, and paces a principal's challenges.
  - The OIDC owner: `(issuer, sid)` and `(issuer, sub)` to every principal minting under them,
    so a logout finds the tokens to delete.
  - The logout record: what a logout refuses from then on.
- **`broker`**:
  - `authenticate` returns a `caller` (principal, credential, `auth_time`, assertion), from a
    client certificate or a bearer, never both.
  - The mint writes the owner records before its first token, and reads the logout records
    before anything else and again after its last token write, as it reads the marks (decision
    32).
  - `logout.go` holds `Broker.Logout` and the endpoint. `oidcrefresh.go` holds the OIDC
    challenge and refresh.
- **port49d and port49-broker** build the identity set from config, start each key set's
  refresh loop, and say what they trust at start.
  - port49d's daemon half never reads a token (design §7, decision 13).
  - Readiness never follows the provider.

**Tech Stack:**
- Go 1.26, module `github.com/blanketfish/port49`, no cgo.
- The standard library's `crypto/rsa`, `crypto/ecdsa`, `crypto/ed25519`, `encoding/json`,
  `net/http`. No new module (OR-1).
- etcd v3.6.15 as today.
- Lab: Keycloak (`quay.io/keycloak/keycloak:26.4`; each note records `kc.sh --version` and the
  image ID that ran), as a container on beehive (`sg docker -c`); containerlab with vEOS for the
  end-to-end run.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2: the principal table's OIDC rows, "The device-facing username", the `revoke_others` row,
    `/v1/logout` needing no right;
  - §5.1.4: the credential's `oidc` fields, `sid` and back-channel logout, revocation by `sid`
    or `sub` ("arrives with plan 7h");
  - §5.6: "Session lifetime", the refresh as a fresh authentication with `auth_time` from the
    assertion; the index by `sid`;
  - §5.7: the events (`revoke`), the reason codes (`trust_domain_unresolved`,
    `credential_revoked`, `identity_unmapped`, `session_expired`), and "Credentials never
    appear";
  - §13: decisions 8, 12, 13, 15, 16, 17, 32, 34 and 38 (read), and the new 39;
  - §14: the assertion "`/v1/logout` succeeds with a valid logout token and no caller rights";
  - §15: the register rules, and the new L45, L46 and L47.
- `docs/design/2026-08-21-port49-design.md`:
  - §7: human identity (OIDC), trust domain separation, the verifier lists;
  - §12: the failure model (a provider outage);
  - §17: the surface (`/v1/config`, `/v1/logout`, `/v1/tokens/revoke` by `sid`), the
    requirements (no API keys; `/v1/logout` authenticates by the provider's signature), the
    errors.
- Roadmap `docs/superpowers/plans/README.md`:
  - "Plan 7", the 7h bullet;
  - "Plan 7g — As built", "Carried, for later plans" (7h: OIDC principals through
    `Resolver.Verify`, `/v1/logout`).
- External: OpenID Connect Core 1.0 §2, §3.1.3.7, §15.1; OpenID Connect Discovery 1.0 §4; OpenID
  Connect Back-Channel Logout 1.0 §2.4–§2.8; RFC 7515, RFC 7517, RFC 7518, RFC 8037, RFC 8725
  (JWT best current practice), RFC 9068 (`at+jwt`).
- The merged plan 7g (`2026-10-05-07g-the-directory.md`), for house style. This plan is written
  against the code at `e6a6f5d`.

**Prerequisite:** plan 7g merged (PR #29, merge `e16f4bb`; `main` at `e6a6f5d`).

**Pre-flight:** `.superpowers/sdd/2026-10-06-07h-oidc-and-trust-domains/preflight-report.md`
(READY WITH FIXES: 2 Critical, 13 Important, 23 Minor) is applied in this text; `planfix-report.md`
beside it names each finding and where it landed. Rulings 21 to 24 are the pre-flight's.

## The carries: what 7h takes, and what it leaves

| Carry | Taken? | Where, or why not |
|---|---|---|
| The verifier lists `identity.humans` and `identity.machines` (decision 16; roadmap 7h) | **Taken**, as `broker.identity.humans` and `.machines` | Rulings 1, 2; Task 7 |
| OIDC ID and access tokens validated against the provider's JWKS (roadmap 7h; design §7) | **Taken**: ID tokens for humans, client-credentials access tokens for machines | Rulings 3–6; Tasks 3–5 |
| `/v1/config`'s issuer and client id (roadmap 7h; design §17) | **Taken** | Ruling 16; Task 10 |
| `prompt=login` refresh with `auth_time` from the assertion (roadmap 7h; spec §5.6; decision 17) | **Taken**, bound to a broker-issued nonce | Ruling 15; Task 11; L46 |
| `POST /v1/logout` back-channel by `sid` or `sub` (roadmap 7h; spec §5.1.4) | **Taken**: no standing mark, a bounded logout record | Rulings 12, 13; Task 12; L45 |
| `amr` and `acr` recorded (roadmap 7h; decision 13) | **Taken**: the context's credential and `auth.oidc` | Ruling 10; Tasks 2, 9 |
| OIDC principals resolve groups through `Resolver.Verify` (7g "Carried": `user:` + the claim the deployment names) | **Taken**, unchanged: `memberFor` reads `Resolver.Current` for any `user:` principal | Ruling 7; Task 9 |
| `/v1/tokens/revoke` by `sid` (spec §2's `revoke_others` row: "by `sid` with OIDC (plan 7h)") | **Taken** | Ruling 14; Task 13 |
| The agent's OIDC public client with PKCE (roadmap: "stays plan 9's") | **Left to plan 9** | The broker side is complete without it; the lab drives the flow from a test client |
| Workload certificates under `machines` (design §7 option 2) | **Left to plan 8** | Refused at load, naming plan 8 (Ruling 1) |
| The `k8s` verifier (design §7 option 1) | **Left to plan 10** | Refused at load, naming plan 10 (Ruling 1) |
| A broker-issued short-lived client certificate after OIDC (design §7: "not required for v1") | **Not taken** | Design §7 |
| L44 (Windows Server AD) | **Left unassigned** | 7g's, for the SER8 box |
| 7g's parked final-review items (the 24h membership record, `policy check --directory`) | **Left** to the pre-beta review | Not 7h's |

## What this plan does not do

- **No token reaches the daemon.** The daemon never sees an OIDC token (spec §5.1.4). A device
  login carries the port49 token the broker minted, exactly as on the certificate path.
- **No group from a token** (design §7). A `groups` claim, a `roles` claim and a `wids` claim
  are never read. Without a directory, an OIDC person matches identity subjects alone.
- **No username from a token** (Ruling 7). With a directory, the username is the directory's.
  Without one, it is the identity subject's declared `username:`.
- **No encrypted token** (JWE) and no HMAC-signed one. Each is refused before any key is
  looked up.
- **No header-named key.** A `jku`, `jwk`, `x5u` or `x5c` header is never fetched or trusted
  (RFC 8725 §3.10).
- **No standing mark from a logout.** A logout is the provider ending a session. The person may
  log in again at once, and only `port49 revoke` bans (decision 32).
- **No OIDC client in the agent** (plan 9). The lab and the unit tests present tokens directly.
- **No device behaviour changes.** Every reply port49d sends is one it sends today. A logged-out
  session's next command is denied `credential_revoked`, as a revoked one is.
- **No readiness change.** `/readyz` never follows the provider (design §12). A broker whose
  every key set is stale stays ready and serves the certificate path.
- **No hosted provider in the lab.** L45 and L46 measure Keycloak. L47 opens for Microsoft Entra
  ID and Okta and stays open (OR-3).

## Rulings where the design and spec are silent

Each takes the option that denies more, and is written into the tasks named. Spec §13 records
them as decision 39 (Task 1). Each says whether it rests on data (a measurement, an RFC) or on
reasoning. Ryan may override any. OR-1 to OR-3 below are the three that need his call.

1. **The verifier lists live at `broker.identity`** (reasoning: only a broker verifies).
   - **The lists.** `humans` and `machines`, each a list of verifiers, spec decision 16's
     `identity.humans` and `identity.machines`.
   - **`x509` under `humans`.** It takes `trust_anchor_file`: the one anchor, one certificate,
     as `broker.client_ca_file` is today (`LoadTLS`). At most one, since the listener verifies
     a chain against one anchor.
   - **`oidc` under `humans`.** It takes `issuer`, `client_id`, `principal_claim` (required,
     Ruling 23), `principal_domains` (required, Ruling 22), `scopes`, `algorithms` and
     `ca_file`.
   - **`oidc` under `machines`.** It takes `issuer`, `audience`, `clients` (required, Ruling
     21), `algorithms` and `ca_file`.
   - **Refused at load:** `x509` under `machines` ("workload certificates are plan 8's") and
     `k8s` ("plan 10's").
   - **The shorthand.** A broker with no `broker.identity` has `humans: [{type: x509,
     trust_anchor_file: <broker.client_ca_file>}]`, exactly today's behaviour. A start says so
     in one line.
     - With `broker.identity` set, `broker.client_ca_file` is refused: "moved to
       broker.identity.humans[].trust_anchor_file". One key means one anchor, and two would let
       them disagree.
     - `BrokerConfig.ClientCAFile` stays the resolved anchor, so the code reading it is
       unchanged.
   - **An OIDC-only broker** (no `x509` verifier) requests no client certificate at the
     handshake (`tls.NoClientCert`). Its `certificate_status` is refused if set: nothing would
     be checked. With an `x509` verifier, `certificate_status` is required as before (decision
     33).
   - **No verifier at all** is refused: a broker that accepts no one.
2. **A token is offered to every verifier for its issuer, and exactly one must accept it**
   (reasoning; design §7: "a claim in the token is not what tells them apart").
   - **Which verifiers.** The `iss` is read unverified only to pick the verifiers whose
     `issuer` equals it, byte for byte. Each verifies the token in full.
   - **One acceptance or none.** None is `trust_domain_unresolved`. Two (two machine verifiers
     at one issuer listing one client, a token whose `aud` names both audiences) is
     `trust_domain_unresolved` too, and never the first. A human and a machine domain never
     share a token: a human verifier requires `auth_time`, and a machine verifier refuses it.
   - **A human verifier** (OIDC Core §3.1.3.7):
     - `aud` holds `client_id`;
     - with more than one `aud`, `azp` is present;
     - `azp`, when present, equals `client_id`;
     - a `typ` header of `at+jwt` (an RFC 9068 access token) is refused.
   - **A machine verifier:** `aud` holds `audience`, and the token is a client-credentials token
     of a client the verifier lists, its `sub` the one pinned for that client (Ruling 21). A
     token carrying a person's session claim is refused. So a human and a machine verifier can
     never both accept one token; two machine verifiers at one issuer listing one client can,
     and are refused as above.
   - **A bearer carrying an `events` claim is refused.** A logout token is never a bearer (RFC
     8725 §2.8, cross-JWT confusion), and Ruling 12 refuses the reverse.
3. **The signature: a compact JWS, an algorithm pinned per verifier, a key chosen by `kid`**
   (data: RFC 7515, RFC 7518, RFC 8725 §3.1, §3.2, §3.10).
   - **The form.** Three dot-separated base64url parts with no padding. Five parts (JWE) are
     refused. A token over 16 KiB is refused unread.
   - **The algorithms.** `algorithms` per verifier, default `[RS256]` (the one OIDC Core §15.1
     requires a provider to offer). Allowed: `RS256`, `PS256`, `ES256`, `ES384`, `EdDSA`.
     `none` and every `HS*` are refused at load, and a token naming one is refused before any
     key is looked up.
   - **Algorithm and key agree.** RSA for `RS256` and `PS256`, P-256 for `ES256`, P-384 for
     `ES384`, Ed25519 for `EdDSA`. A JWK that declares `alg` must declare the token's.
   - **The headers.** A `crit` header is refused, since no extension is understood. `jku`,
     `jwk`, `x5u` and `x5c` are ignored for key selection: never fetched, never trusted.
   - **The key.** A `kid` must name exactly one key in the set. With no `kid`, the set must hold
     exactly one key of the algorithm's type; port49 never tries every key.
   - **Which JWKs are used.** A JWK whose `use` is present and not `sig`, or whose `key_ops`
     omit `verify`, is skipped. An RSA key under 2048 bits or over 8192 is skipped. A set of
     more than 100 keys is refused whole, as a failed fetch. A skip is said when the set of
     skips changes, not at every fetch (pre-flight M-3: Keycloak publishes an RSA-OAEP `enc` key
     by default).
   - **In-house, on the standard library** (OR-1). It is about 300 lines, tested against RFC
     7515's and RFC 8037's examples (fetched from rfc-editor.org, never retyped), Project
     Wycheproof's ECDSA P1363, RSA PKCS #1, RSA-PSS and Ed25519 vectors, every algorithm against
     every key type, and two fuzz targets (`FuzzParseCompact`, `FuzzParseJWKS`). `JWS.String`
     says nothing a token carries (pre-flight M-1).
4. **Keys: discovery and the JWKS, refreshed, rate-limited, persisted, and aged out** (data:
   OIDC Discovery 1.0 §4.3; reasoning for the timings, OR-2).
   - **Discovery.** `{issuer}/.well-known/openid-configuration`. The `issuer` it returns must
     equal the configured one exactly, and `jwks_uri` must be `https`.
   - **Fetching.** Over TLS with the verifier's `ca_file`, or the system roots when none is set
     (said at start). Through the environment's proxy (`HTTPS_PROXY`, `NO_PROXY`) when one is
     set, said at start with its credentials redacted: a site that reaches its provider only
     through an egress proxy would otherwise never fetch a key (pre-flight I-5). This is no
     SSRF surface: the targets are the configured issuer and the `jwks_uri` its own discovery
     names. No redirect is followed, a body is read up to 1 MiB, and a fetch times out at 10s.
   - **The `jwks_uri`** is said at the first fetch and whenever discovery changes it (pre-flight
     M-7). Its host is not constrained: whoever controls discovery controls the keys, and Google
     serves its keys from another host.
   - **A fetch that yields no usable key** (`{"keys":[]}`, every key skipped, or over 100 keys)
     is a failed fetch: the last good set stands until `jwks_max_age`, nothing is kept, and it
     is counted and said (pre-flight M-2). One bad publish never locks every person out, and a
     restart recovers.
   - **Refreshing.** Every `jwks_refresh_interval` (1h).
     - **An unknown `kid`** triggers one refetch, at most once a minute per issuer. A flood of
       forged `kid`s costs the provider one request a minute.
     - **A successful fetch replaces the set.** A key the provider dropped is dropped at once.
   - **A failed refresh keeps the last good set.** It is trusted until `jwks_max_age` (24h)
     after that set was fetched.
     - **Past it,** every token for the issuer is refused 503 `identity_provider_unavailable`,
       with `Retry-After: 30`.
     - **Why bound it.** A key the provider withdrew because it leaked would otherwise stay
       trusted for as long as the broker could not reach the provider.
   - **A `kid` the set does not hold:**
     - after a successful fetch within the last minute, the token is refused 401
       `trust_domain_unresolved`;
     - otherwise the refetch decides, and a refetch that fails answers 503;
     - a token arriving while a refetch runs waits for it.
   - **The refetch is the issuer's, not the caller's** (pre-flight I-3). It runs on a context
     detached from the request that started it, bounded by the 10s fetch timeout, and each
     caller waits for it under its own. A client that hangs up mid-fetch never stores
     `context canceled` as the issuer's last error, so it cannot block a key rotation for a
     minute at a time.
   - **Persisting.** Each successful fetch is written to the broker's state directory
     (`broker.state_dir`, or for port49d's in-process broker the directory of
     `broker.revocations_file`, as CRLs are kept; 7b). The file is `oidc-<sha256(issuer)[:16]>.json`,
     0600, through the same owner checks.
     - **A restart** restores the file if it is younger than `jwks_max_age`, so a broker
       restarted during a provider outage keeps validating the tokens people already hold.
     - **Who can write it.** A file another user wrote is refused, since it names the keys the
       broker trusts.
   - **A start never waits on the provider.** A key set with nothing restored and no fetch yet
     answers 503. The fetch is retried from 30s, doubling to 5m.
   - **The staleness gauge survives a restart** (pre-flight I-4). The last-success gauge exists
     from the key set's creation (0) and a restore sets it to the kept set's `fetched_at`, so
     the alert keeps firing for a broker restarted during an outage. The documented alert adds
     `or absent(...)`.
   - **An unwritable state directory** is said in one line at start, when an OIDC verifier is
     configured, not first at the first save (pre-flight M-21).
   - **Readiness never follows the provider.**
5. **The claims** (data: OIDC Core §2, §3.1.3.7; RFC 7519 §4.1; reasoning for `max_token_age`,
   OR-2).
   - **`iss`** equals the verifier's issuer exactly.
   - **`exp`** is required; now < `exp` + `clock_skew`.
   - **`nbf`,** when present: now ≥ `nbf` − `clock_skew`.
   - **`iat`** is required. It is not after now + `clock_skew`, and not older than
     `max_token_age` (2h), whatever `exp` says. That bounds how long a logout record must last
     (Ruling 13), and a provider configured for day-long tokens.
   - **`sub`** is required: a printable string of 1 to 255 bytes.
   - **A human's `auth_time`** is required, and not after now + `clock_skew`. Without it no
     session ceiling can be computed (spec §5.6), so the token is refused rather than
     defaulted to `iat`, which is later and would lengthen the session.
   - **`clock_skew`** is 60s, 0s to 5m.
   - **Claims are read by their exact names** (pre-flight M-4). `encoding/json` fills a struct
     field from a member whose name differs only in case, so `"ISS"` would be read as `iss`
     while the principal claim is read exactly. Every claim is taken from the payload's
     exact-name map, and a payload naming one claim twice in different case is refused.
   - **A date is a JSON number** (RFC 7519 §2, pre-flight M-5). An `exp`, `nbf`, `iat` or
     `auth_time` that is a JSON string is refused.
   - **The answer.** A token failing any check is 401 `trust_domain_unresolved`. The line names
     the check and the issuer the configuration knows, never a claim of a token that did not
     verify.
6. **The principal** (spec §2's OIDC rows; reasoning for the checks).
   - **A human's** is `user:` plus the value of `principal_claim`, lower-cased. The claim is
     required, with no default (Ruling 23), and is one of:
     - `preferred_username`;
     - `email`, which requires `email_verified: true` (an unverified address is anyone's to
       type);
     - `upn`.

     The value must be one string of printable ASCII with an `@`, the policy's `user:` form
     (`identityDomain`), and its domain (after the last `@`) must be one the verifier's
     `principal_domains` lists (Ruling 22). Otherwise the token is refused 401
     `identity_unmapped`: it verified, but names no principal this verifier may give.
   - **A machine's** is `app:` plus `azp`, else the `client_id` claim (RFC 9068), verbatim:
     client ids are case-sensitive. It must be printable ASCII, 1 to 255 bytes, and a client
     the verifier's `clients` lists, with that client's pinned `sub` (Ruling 21). With neither
     `azp` nor `client_id`, `identity_unmapped`; an unlisted client or another `sub`,
     `trust_domain_unresolved`.
   - **Where it is said.** The start line says the claim must be one only the provider's
     administrators can set, and names each verifier's domains and each machine client.
     Keycloak lets a user edit their own email unless verification is on, which is why
     `email` requires `email_verified`. A Keycloak realm brokering an external identity
     provider with "trust email" on lets that provider assert any address: turn it off (the
     operator notes say so).
   - **What a principal string is.** It is the same string a certificate maps to, so a person
     using both paths is one principal. Their marks, rights and subjects apply on both. Two
     OIDC issuers never give one principal: their `principal_domains` may not overlap (Ruling
     22).
7. **The username, and groups** (reasoning; resolves spec §2's OIDC row against decision 38's
   ruling 16).
   - **With a directory,** an OIDC `user:` principal resolves through `memberFor`, that is
     `Resolver.Current`, exactly as a mapped certificate's does (7g's carry). The username and
     the groups are the directory's.
   - **Without one,** the identity subject listing the principal declares `username:`, as
     decision 38 ruling 16 requires of every `user:` subject on a directory-less broker.
   - **The claim is never a username.** Spec §2's table ("OIDC: the `preferred_username`
     claim") and decision 8's "or the OIDC `preferred_username` claim" predate that ruling.
     They are amended (Task 1): one username source per deployment mode, reviewed policy over
     a runtime claim, and design §7's own last paragraph (an OIDC deployment with no directory
     addresses people through literal-identity subjects).
   - **Machines** declare `username:` as today.
8. **A bearer is validated on every request, and a request carries one credential** (reasoning;
   design §17's mint example).
   - **No session on the connection.** There is no held connection on the OIDC path (the
     agent's session is the provider's refresh token, design §7). The listener binds nothing,
     and the per-principal cap does not apply.
   - **The connection.** It is charged to its source while open, and closed once it goes idle
     after its request (`closeIdleWithoutCertificate`, unchanged). So
     `broker.max_pending_conns_per_source` (16) bounds concurrent OIDC requests per source
     address, said in the operator notes for a NAT'd office.
   - **One credential.** A request with a verified client certificate and an `Authorization`
     header is refused 400 `bad_request`, "one credential per request". An `Authorization`
     header that is not `Bearer`, or holds a second token, is refused 401
     `trust_domain_unresolved`.
   - **Marks.** A bearer caller's principal is checked against the standing marks on every
     request, as a certificate caller's is, so `port49 revoke user:alice@corp.example.com`
     refuses Alice's OIDC requests too.
9. **The session clock is the assertion's** (data: spec §5.6, decision 17).
   - **`auth_time`.** A human's `auth_time` is the request's. A machine's is `iat`: a
     client-credentials token is a fresh authentication each time. One ahead of the broker's
     clock, within `clock_skew`, is taken as now: a session clock never starts in the future
     (pre-flight M-18).
   - **The ceiling.** A request whose `auth_time` is older than
     `session.max_session_age_default` is refused 401 `session_expired`: "your identity provider
     last authenticated you at T; run `port49 login` (it asks the provider to authenticate you
     again)".
   - **Except the refresh's own two requests.** A challenge grants nothing but a nonce, and the
     refresh's token must be fresher than its challenge (Ruling 15). Refusing them past the
     ceiling would leave a person whose session reached it no way to refresh but two logins.
   - **Per device,** the ceiling is computed from that `auth_time`, as on the certificate path.
10. **The credential, and what is recorded** (data: spec §5.1.4, decision 13).
    - **`store.Credential`** is `{Method: "oidc", Iss, Sub, Sid, AMR, ACR}`.
    - **`Sid`** is `store.SidKey(iss, sid)`: issuer-qualified, so one issuer's logout never
      reaches a session another issuer authorized. It is what the daemon indexes contexts by
      (`contexts_by_sid`), unchanged code. Fingerprint, issuer and serial stay empty, and a
      blank certificate key is never indexed (spec §5.6).
    - **Every broker record** of a bearer caller carries `auth.oidc`: `{issuer, sub, sid, amr,
      acr, auth_time}`, with the provider's own `sid`. Nothing evaluates `amr` or `acr`.
    - **Never recorded:** the token, its signature, the nonce, a logout token, or any claim of a
      token that did not verify. A refused bearer's record names no principal and carries
      `auth: {method: oidc}` alone. That is the "unvalidated body is never logged" rule
      (CLAUDE.md).
11. **The owner records: a logout finds the tokens** (reasoning; the analogue of decision 32's
    token index).
    - **What they hold.** `(iss, sid)` and `(iss, sub)` each name every principal minting under
      them, each with its own expiry (Ruling 24). A rename (`alice@` to `alice2@` under one
      `sub`) adds a principal; it never replaces one, so a logout reaches both.
    - **When they are written.** Before the first token write of every human OIDC mint and every
      OIDC refresh. A write is skipped while the record holds this principal, written under an
      hour ago. A machine writes none: it has no session a provider logs out (pre-flight M-16).
    - **Their TTL.** `max(session.max_session_age_default, 24h)`, per principal.
    - **A failed write** refuses the mint `store_unavailable`, so no token exists that a logout
      cannot find.
    - **The residual.** A `sub` logout after the record lapsed (no mint for a day, a `never`
      ceiling) reaches no context. It still refuses every older token (Ruling 13), says so, and
      the operator notes say `port49 revoke` is the offboarding tool.
12. **`POST /v1/logout` validates the logout token per Back-Channel Logout 1.0 §2.6** (data: the
    BCL spec; L45 for Keycloak's shape).
    - **The request.** `application/x-www-form-urlencoded`, `logout_token=…`, a body up to 16
      KiB. It needs no client certificate and no `api:` right (spec §2): it authenticates by
      the provider's signature.
    - **Which verifiers.** Human OIDC verifiers alone, by `iss`, and `aud` and `azp` checked as
      for an ID token (BCL §2.6 step 3; pre-flight M-6): `aud` holds `client_id`, several
      audiences need an `azp`, and an `azp` is `client_id`. A machine has no session to end.
    - **The signature.** Ruling 3's checks.
    - **The claims:**
      - `iat` is required, not after now + `clock_skew`, and not older than 24h;
      - `exp`, when present, is honoured with `clock_skew`;
      - `jti` is required;
      - `events` holds the member `http://schemas.openid.net/event/backchannel-logout`, whose
        value is a JSON object;
      - `nonce` is absent;
      - `sub` or `sid` or both are present;
      - a `typ` header, when present, is `logout+jwt` or `JWT`.
    - **Replay.** The `jti` is remembered (`PutOnce`, keyed by issuer and `jti`) for 24h + 2 ×
      `clock_skew`. A token seen before is answered 200 and does nothing, so the provider's own
      retry is harmless. If the logout then fails in the store, the `jti` is taken back, so a
      retry applies it. If the take-back fails too, a retry would be answered 200 "replayed"
      and do nothing: that is said in one line naming the session and the manual ends, `POST
      /v1/tokens/revoke {"sid": …, "issuer": …}` and `port49 revoke` (pre-flight M-13).
    - **The answers:**
      - 200, applied, or nothing to apply;
      - 400 `{"error": "invalid_request"}`, a token that did not validate;
      - 503 with `Retry-After: 30`, the store did not answer, so the logout may not have
        applied: retry.

      Each carries `Cache-Control: no-store`. The 503 departs from BCL §2.8, which says 400 for
      any failure: a 400 tells the provider its token was bad. Whether Keycloak retries on
      either is L45's.
13. **A logout leaves no standing mark, and reaches tokens, then contexts twice** (reasoning;
    spec §5.1.4's order).
    - **The logout record**, first. A `sid` record refuses every token for that issuer and
      `sid` from then on. A `sub` record refuses every token for that issuer and `sub` issued
      at or before the logout token's `iat` plus `clock_skew`, so a new login after the logout
      is accepted.
      - **Its TTL** is `max_token_age` + 2 × `clock_skew`: past it, no token it refuses can pass
        Ruling 5's `iat` check anyway.
      - **A failed write** applies nothing, and is answered 503.
    - **Then the tokens.** The owner record names the principals (Ruling 24). Each one's unspent
      tokens are deleted one by one, its own only (`RevokeOwn`'s token step): all of them,
      every session's, since the token index holds no finer cut.
    - **Only principals in the provider's domains** (Ruling 22). A principal the owner record
      names whose domain is not one of the accepting verifier's `principal_domains` (a record
      left from before a configuration change) is skipped and said. A `sub` logout from one
      issuer never reaches a person another issuer authenticates.
    - **Then the contexts, twice:**
      - by `sid`, the contexts indexed under `SidKey(iss, sid)` (`session.Manager.RevokeBySid`);
      - by `sub` alone, every context of each principal (`ContextsByPrincipal`), by
        compare-and-set as a self revocation marks.

      A context is shared per (principal, device) and holds the last login's credential
      (decision 15), so a `sub` logout cannot tell a certificate login's context from an OIDC
      one's, and ends both. A `sid` logout ends a context another session joined, and a
      certificate-path context an OIDC refresh extended (the refresh indexes its `sid` there,
      Ruling 15; pre-flight M-17). Each fails closed. The person's next login, with a token
      minted after, lifts it (decision 15).
    - **Receipts** are deleted, as every revocation deletes them.
    - **The record.** One `revoke` record, `by: sid` or `by: sub`, origin `backchannel_logout
      <iss>`, naming the principal when the owner record named one. When it named several, the
      record's `principal` is the first in order and `revocation.principals` lists every one.
    - **The mint's side.** A mint reads the logout records before anything else and again after
      its last token write, and deletes what it wrote if one appeared (`revokedSince`, widened).
      Whichever of a mint and a logout reads the other's write, no token minted under a dead
      session survives.
    - **The residual window.** A redemption that removed its token before the delete, and writes
      its context after the second pass, writes it unrevoked. That window is one store round
      trip, as for a self revocation (spec §5.1.4): no mark stands for the daemon's login to
      check.
14. **`POST /v1/tokens/revoke` by `sid`** (spec §2's `revoke_others` row).
    - **The body.** `{"sid": "…", "issuer": "…"}`; `issuer` may be omitted when exactly one
      human OIDC verifier is configured.
    - **The right.** Under `revoke_others`; without it, 403 `api_right_missing`, recorded.
    - **What it does.** Exactly Ruling 13's `sid` logout (`Broker.RevokeSid`), origin `api
      <caller>`. The admin socket gains no form: `port49 revoke` revokes the principal.
15. **The OIDC refresh is bound to a broker-issued nonce** (data: spec §5.6, decision 17; L46
    for Keycloak).
    - **The challenge.** `POST /v1/refresh/challenge` with the current bearer answers a 32-byte
      nonce, base64url.
      - **Where it is held.** In the store (`PutOnce`, its SHA-256 the key, holding the
        principal, the issuer and the instant), for 5m, so any broker replica can take it.
      - **Pacing.** One per principal per 10s, by a `PutOnce` with a 10s TTL; a second is 429
        `refresh_too_soon`.
    - **The authentication.** The agent (plan 9) sends the nonce as the `nonce` of a
      `prompt=login` authorization request.
    - **The refresh.** `POST /v1/refresh` carries the new ID token as its bearer and an empty
      JSON body.
      - **The checks.** The token verifies (Rulings 2–6). Its `nonce` is taken once
        (`TakeOnce`), so a second use finds nothing. The challenge's principal and issuer are
        the token's. Its `auth_time` is no earlier than the challenge's instant less
        `clock_skew`.
      - **The refusals.** A missing or spent nonce is 401 `refresh_challenge_missing`. An
        `auth_time` from before the challenge is 401 `refresh_not_fresh`: "your identity
        provider did not authenticate you again (prompt=login was not honoured); the
        session was not extended".
    - **Then, as on the certificate path.** The marks, the logout records, the membership, and
      `RefreshSession` with `auth_time` as the new session clock.
    - **The new `sid`.** Each extended context is also indexed under it, and the old entry
      stays, so a logout of either session reaches it. `session.Manager.AddSid` adds an entry;
      it is not `Manager.Refresh`'s `ReindexSid`, which moves one
      (`TestRefreshMovesAuthTimeKeepsWindowReindexesSid`). A certificate-path context the
      refresh extends is indexed under the OIDC `sid` too, so that session's logout ends it:
      fail closed (pre-flight M-17).
    - **A logout during the refresh** (pre-flight I-2). The new `sid` is indexed before the
      context is extended, so a logout's `RevokeBySid` that runs after the index finds it. One
      that ran before is caught by the refresh's after-check: on a logout record it marks every
      context it extended (`RevokeBySid` on the new `sid`, then `revokeOwnContext` on each)
      before it answers 401. A logout never leaves an extended context alive to its new
      ceiling.
16. **`GET /v1/config` names the human OIDC verifiers** (design §17).
    - **What it says.** `methods` lists `x509` and `oidc` as configured. `oidc` lists `{issuer,
      client_id, scopes}` for each human verifier, the scopes being `openid` plus the
      configured ones.
    - **What it withholds.** Machine verifiers, which a client-credentials caller is configured
      with already. It is fleet-free discovery data.
17. **The metrics.** No label names a device or a principal. `issuer` is a configured issuer
    URL, a bounded set; an unknown `iss` is counted as `issuer="unknown"`.
    - `port49_oidc_tokens_total{issuer,outcome}`: `accepted`, `invalid`, `expired`,
      `unavailable`, `logged_out`, `unmapped`.
    - `port49_oidc_keys_last_success_timestamp_seconds{issuer}`: 0 from the key set's creation,
      the kept set's `fetched_at` after a restore. Alert on `time() - it > jwks_max_age / 2 or
      absent(it)`.
    - `port49_oidc_keys_fetch_failures_total{issuer}`.
    - `port49_oidc_logouts_total{outcome}`: `applied`, `nothing`, `replayed`, `invalid`,
      `unavailable`, `store_error`, `partial`.
18. **What is never logged.**
    - **Withheld:** a bearer token, a logout token, a signature, a refresh nonce, the
      `Authorization` header, and any claim of a token that did not verify.
    - **May be said:** a key id, an issuer from configuration, and the validated `sub`, `sid`
      and principal, each through `printsafe.Line`.
    - **Secret-bearing types** (`oidc.Assertion` holds the nonce) have a `String` that
      withholds it.
19. **`app:` principals can be revoked.** `normalPrincipal`'s prefixes gain `app:`, kept
    verbatim after the prefix (`user:` is still lower-cased), so `port49 revoke
    app:<client_id>` makes a mark the machine path honours.
20. **The lab is Keycloak** (reasoning: a container on beehive, and it implements Back-Channel
    Logout 1.0 with `sid`, `prompt=login` and `auth_time`).
    - **L45 and L46** measure it.
    - **L47** names the hosted providers, opens, and stays open (OR-3). Every ruling above that
      rests on a provider's behaviour is "provisional on L45/L46 (Keycloak) and L47 (hosted)".
      Those are 12's token shape, 15's `auth_time` and `nonce`, 13's `sid` and `sub` matching
      the ID token's, and 21's claim sets (which session claims a client-credentials token
      carries and a delegated one does).

The pre-flight's four rulings. Each narrows what a verifier accepts, so each takes the
anti-impersonation side of decision 16.

21. **A machine verifier takes listed clients, each with a pinned `sub`, and never a person's
    delegated token** (pre-flight C-1; data: RFC 9068 §2.2, a client-credentials token's `sub`
    is the client's own identity; OIDC Core §2 and §3.1.2.1, `auth_time`, `sid`, `nonce` and
    `amr` belong to an end-user's authentication; reasoning for the rest). It adds to spec §2's
    machine row ("`app:` + `azp`") a check the row does not name; it removes no form the spec
    allows a client-credentials token.
    - **The gap it closes.** With `aud ∋ audience` alone, a person who signs into a client that
      also allows interactive grants (a routine Entra or Keycloak misconfiguration) gets a
      delegated access token whose `aud` is the API and whose `azp` is the client. The machine
      verifier would make it `app:<client>`: a human crossed into the machine domain, acting
      as the service. Decision 16 exists to prevent exactly that.
    - **The config.** `clients: [{client_id, sub}]`, required, at least one. `sub` is the
      client's own identity at the provider: the Keycloak service-account user's id, the Entra
      service principal's object id. A person's `sub` never equals it. The start line names
      each client.
    - **The checks**, after the signature and before the principal:
      - a token carrying any of `auth_time`, `sid`, `nonce`, `scp` or `amr` is refused: each
        marks a person's session or a delegated grant;
      - an `idtyp` other than `app` (Entra's marker, when the tenant emits it) is refused;
      - `azp` and `client_id` both present and different is refused;
      - the client (`azp`, else `client_id`) must be listed, and the token's `sub` must be that
        client's pinned `sub`.
    - **The refusal** is `trust_domain_unresolved`: the token is no client-credentials token of
      a listed client. A token naming no client at all stays `identity_unmapped` (Ruling 6).
    - **Provisional** on L46 (which of these claims Keycloak's client-credentials and delegated
      access tokens carry) and L47 (Entra's `idtyp` and `scp`). A marker Keycloak puts on a
      client-credentials token is a lab result for Ryan, never a marker silently dropped.
22. **Each human OIDC verifier names the domains it is authoritative for** (pre-flight C-2;
    reasoning). It narrows spec §2's human row: the row names the claim, and this adds whose
    principals a verifier may give.
    - **The gap it closes.** The principal is `user:` plus a claim, from whichever human
      verifier accepted the token. A second issuer (a contractor realm, or a Keycloak realm
      brokering an external provider with "trust email" on) that issues `email:
      alice@corp.example.com` with `email_verified: true` would mint as Alice, with her
      subjects and rights, and its `sub` logout would end her certificate-path and
      first-issuer contexts. This is 7g C-2's class, moved from the directory to the provider.
    - **The config.** `principal_domains: [corp.example.com, …]` on each human `oidc` verifier,
      required, at least one: printable ASCII, no `@`, lower-cased at load, matched exactly
      (no subdomain is implied).
    - **The check.** The principal's domain, after its last `@`, must be listed; else 401
      `identity_unmapped`.
    - **At load.** Two human verifiers on different issuers whose domains overlap are refused:
      no two issuers can give one principal. An `x509` verifier takes no domains: a person on
      both paths is one principal by design (Ruling 6).
    - **Machines too** (Task 2 review; reasoning). `app:` + the client id carries no issuer,
      so two machine verifiers on different issuers that list one `client_id` are refused at
      load: else an administrator at the second issuer who creates a client by that name gets
      the first's grants.
    - **The logout.** A `sub` or `sid` logout reaches only principals in its verifier's
      domains (Ruling 13).
23. **`principal_claim` is required, with no default** (pre-flight I-6; data: OIDC Core §5.7,
    the RP "MUST NOT rely upon" `preferred_username` "being unique"; L46 records Keycloak's
    value). It amends spec §2's "`preferred_username` by default" (Task 1): all three claims
    stay, and none is chosen for the operator.
    - **Why.** Keycloak's documented default `preferred_username` is the bare username (L46
      measures it; the ruling does not wait on it), so the default would refuse every Keycloak
      person `identity_unmapped`. Where usernames are editable
      (Keycloak's `editUsernameAllowed`) or reassigned (an Entra UPN), the claim is not a
      stable identity. An operator who names the claim has read that.
    - **The refusal** names the three choices: `broker.identity.humans[1].principal_claim is
      required: one of preferred_username, email or upn`.
24. **An owner record holds every principal minting under it, and one issuer has one principal
    claim** (pre-flight I-1; reasoning, from the plan's own Global Constraint that a logout
    reaches more, never less).
    - **The record.** A set of `{principal, expires_at}` under `(iss, sid)` or `(iss, sub)`,
      merged by compare-and-set; an entry past its expiry is dropped at the next write.
      `Logout` ends every principal in it (Ruling 13).
    - **At load.** Two human verifiers on one issuer with different `principal_claim`s are
      refused: they would give one `sub` two principals at every mint.
    - **What remains.** A rename (`alice@` to `alice2@` under one `sub`) gives the record two
      entries, and a logout reaches both.

### Open for Ryan

Execution proceeds on each recommendation unless Ryan rules otherwise. Task 17 records the
answer.

**OR-1. JOSE in-house on the standard library, or `github.com/go-jose/go-jose/v4`.** Still
Ryan's call; the pre-flight recommends in-house, with the tests it asked for (M-1), now in Task 3.
- **In-house** is about 300 lines: compact parse, five algorithms, the JWK forms.
  - It brings no module.
  - Its whole surface is what Ruling 3 allows. There is no `none`, no HMAC and no header-named
    key to forget to disable.
  - **The pre-flight read Task 3 line by line against the known JOSE failure classes, and it
    avoids each:** the algorithm is pinned per verifier and checked before the key; `Fits`
    ties the algorithm to the key type and the curve, and a JWK's own `alg` must agree; `none`
    and every `HS*` are refused at load and at verify; `oct` keys are never parsed;
    `jku`/`jwk`/`x5u`/`x5c` are not even fields; `crit` is refused; ECDSA takes fixed-length
    `r‖s` only, and `ecdsa.Verify` rejects `r` or `s` of 0 or ≥ n; EC points are validated
    (`ParseUncompressedPublicKey`) at their exact size; PSS uses `SaltLengthEqualsHash`; RSA
    keys are 2048 to 8192 bits, with an odd exponent of at least 3; the base64url decoding is
    strict, with no padding; five-part (JWE) tokens are refused; the 16 KiB bound applies
    before parsing.
  - **The residual risk is a key-type or encoding bug the unit tests miss.** Task 3 now runs
    Project Wycheproof's ECDSA P1363, RSA PKCS #1 v1.5, RSA-PSS and Ed25519 vectors (JSON
    files, no module), every algorithm against every key type, and two fuzz targets. Wycheproof
    is the industry check for exactly that class.
  - It is also tested against the RFC 7515 and RFC 8037 vectors (fetched, never retyped) and
    against tokens Keycloak signs (L46).
- **go-jose v4** is widely used and maintained, and is one module.
  - It is general: JWE, HMAC and embedded keys exist, and are kept off by passing the
    algorithm list on every parse.
  - Its CVE history is in exactly that generality: algorithm confusion before v3's explicit
    list; CVE-2024-28180 (JWE decompression); CVE-2025-27144 (unbounded memory on a token with
    many dots, which `MaxToken` and the three-part split close here).
  - **It changes little.** It would replace only Task 3's ~150 lines of verification. go-oidc's
    `RemoteKeySet` has none of what Ruling 4 needs (persistence, `jwks_max_age`, a stale-set
    refusal), and with no `kid` it tries every key, which Ruling 3 forbids. Neither library
    does `auth_time`, the nonce challenge or back-channel logout. The claims layer, where the
    pre-flight's two Criticals were, is hand-written either way.
- **Recommended:** in-house, with Task 3's Wycheproof vectors, matrix test and fuzz targets.
  The code that decides who someone is should be no larger than what it accepts, and the
  standard library carries the cryptography.

**OR-2. The defaults: `clock_skew` 60s, `max_token_age` 2h, `jwks_refresh_interval` 1h,
`jwks_max_age` 24h; the refresh challenge 5m.**
- **Why they matter at 3am.**
  - **`jwks_max_age`.** When the broker cannot reach the provider for longer than this, every
    OIDC request is refused 503 `identity_provider_unavailable`, including tokens people hold.
    Certificate users and live device sessions are unaffected, and so is break-glass.
  - **`max_token_age`.** It refuses a token issued longer ago than itself even before its
    `exp`. Entra ID access tokens live 60 to 90 minutes, so 1h would refuse a machine's token
    in its last half hour; 2h does not.
- **Shorter `jwks_max_age` (4h):** a leaked key is trusted for less time in a partition; a
  provider outage of a long evening refuses everyone.
- **Longer (7d):** an outage never refuses; a withdrawn key stays trusted for a week in a
  partition.
- **Recommended:** 60s, 2h, 1h, 24h, 5m. Alert at half of `jwks_max_age` on
  `port49_oidc_keys_last_success_timestamp_seconds`, `or absent(...)`, which a restart during an
  outage no longer silences (pre-flight I-4).
- **The escape past `jwks_max_age`** (pre-flight M-20). Raise `broker.identity.jwks_max_age` (up
  to 30d) and restart: `Restore` judges the kept file against the new maximum. Restart
  port49-broker where there is one, since a port49d restart also restarts device AAA.
- **The pre-flight's reading:** safe, since each default fails closed.

**OR-3. Hosted providers are their own register row, L47, open until measured.**
- **What beehive can measure:** Keycloak, which runs in a container and implements every claim
  7h rests on.
- **What it cannot:** Microsoft Entra ID's and Okta's logout tokens (whether they send `sid`,
  `exp`, a `typ`), their `prompt=login` and `max_age=0` behaviour, and their access-token `azp`.
  For Entra also (pre-flight M-8, C-1): a v2 access token's `aud` is the application's GUID,
  not its `api://` URI; it sends no `email_verified`, so `principal_claim: email` refuses
  every Entra person; and its `idtyp` and `scp` claims, on which Ruling 21's delegated-token
  refusal rests there. Each needs a tenant, which Ryan holds or creates.
- **Recommended:** run L47 on an Entra ID free tenant and an Okta developer org before beta, as
  a register measurement. Until then the operator notes say measured on Keycloak only, and
  decision 39's provider bullets stay provisional on L47 for hosted providers.

**Worth reading before the merge** (rulings, not open questions):
- **Rulings 21 and 22** add two required config keys, `clients` on a machine verifier and
  `principal_domains` on a human one, so no person's token becomes a machine and no second
  issuer mints another's people. **Ruling 23** removes spec §2's `preferred_username` default.
- **Ruling 7.** The `preferred_username` claim is never a username. Spec §2 and decision 8 are
  amended to match decision 38.
- **Ruling 12.** `/v1/logout` answers 503, not 400, when the store failed, departing from BCL
  §2.8 so the provider is not told its token was bad.
- **Ruling 13.** A `sub` logout ends a person's certificate-path contexts too: decision 15
  shares one context per (principal, device).
- **Ruling 8.** OIDC requests are counted against the per-source cap while they run.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **A broker start with OIDC** (Task 14):

  ```
  port49-broker: identity: humans: x509 (trust anchor /etc/port49/broker/broker-ca.pem); oidc https://sso.corp.example.com/realms/corp (client_id port49-cli, principal from email in corp.example.com, email_verified required; algorithms RS256)
  port49-broker: identity: machines: oidc https://sso.corp.example.com/realms/corp (audience api://port49-svc; clients oxidized (sub 5f3c2d1e-0000-4000-8000-000000000049); principal app:<azp>; algorithms RS256)
  port49-broker: identity: the principal claim must be one only the identity provider's administrators can set: a person who can edit their own would choose whose principal they are; on a provider brokering another, turn off "trust email"
  port49-broker: identity: https://sso.corp.example.com/realms/corp is fetched through the proxy http://proxy.corp.example.com:3128 (HTTPS_PROXY)
  port49-broker: identity: keys refreshed every 1h0m0s; trusted without a refresh until 24h0m0s after the last (broker.identity.jwks_max_age); clock_skew 1m0s; max_token_age 2h0m0s
  port49-broker: identity: https://sso.corp.example.com/realms/corp: keys from https://sso.corp.example.com/realms/corp/protocol/openid-connect/certs
  ```

  Without a proxy the fourth line reads `… is fetched directly (no HTTPS_PROXY)`; a `ca_file`
  left out adds `… is trusted through the system's root certificates (no ca_file)`. A state
  directory the broker cannot keep keys in:

  ```
  port49-broker: identity: the state directory /var/lib/port49-broker cannot keep the providers' keys (…): a restart during a provider outage will refuse every OIDC token until a fetch succeeds
  ```

  With no `broker.identity`:

  ```
  port49-broker: identity: humans: x509 from broker.client_ca_file (no broker.identity is configured); no OIDC verifier
  ```

  A start during a provider outage, with keys restored:

  ```
  port49-broker: identity: https://sso.corp.example.com/realms/corp: restored 2 keys fetched 2026-10-06T07:00:00Z from /var/lib/port49-broker/oidc-5f1c0a3e9b7d2c41.json
  port49-broker: identity: https://sso.corp.example.com/realms/corp: keys not refreshed since 2026-10-06T07:00:00Z (the last error: GET https://sso.corp.example.com/realms/corp/.well-known/openid-configuration: dial tcp 10.0.0.30:443: connect: connection refused); tokens signed by the 2 keys held are accepted until 2026-10-07T07:00:00Z (broker.identity.jwks_max_age), then refused identity_provider_unavailable
  ```
- **The provider unreachable** (Task 4), once an hour while it lasts:

  ```
  port49-broker: identity: https://sso.corp.example.com/realms/corp: keys not refreshed since 2026-10-06T09:00:00Z (the last error: GET https://sso.corp.example.com/realms/corp/protocol/openid-connect/certs: 503 Service Unavailable); tokens signed by the 2 keys held are accepted until 2026-10-07T09:00:00Z (broker.identity.jwks_max_age), then refused identity_provider_unavailable
  ```

  and past it:

  ```
  port49-broker: identity: https://sso.corp.example.com/realms/corp: no key refreshed within broker.identity.jwks_max_age (24h0m0s; the last at 2026-10-06T09:00:00Z); every token from it is refused identity_provider_unavailable until a fetch succeeds; certificate logins and live device sessions are unaffected; to accept the held keys meanwhile, raise broker.identity.jwks_max_age (up to 720h) and restart port49-broker
  ```

  A JWKS with no usable key, as a failed fetch (the last good set stands):

  ```
  port49-broker: identity: https://sso.corp.example.com/realms/corp: keys not refreshed since 2026-10-06T09:00:00Z (the last error: the JWKS holds no key port49 can verify with (1 skipped)); tokens signed by the 2 keys held are accepted until 2026-10-07T09:00:00Z (broker.identity.jwks_max_age), then refused identity_provider_unavailable
  ```

  A provider outage is recorded `trust_domain_unresolved` in the decision log (the record has
  no field for an API code); the line above, the 503's `identity_provider_unavailable` and
  `port49_oidc_tokens_total{outcome="unavailable"}` tell it from a flood of bad tokens
  (pre-flight M-14).
- **A refused token** (Task 9), once per reason per 10s:

  ```
  port49-broker: identity: a bearer token was refused (trust_domain_unresolved): its signature does not verify under the keys of https://sso.corp.example.com/realms/corp
  port49-broker: identity: a bearer token was refused (trust_domain_unresolved): no configured verifier accepts its issuer
  port49-broker: identity: a bearer token was refused (trust_domain_unresolved): issued 2h4m ago, past broker.identity.max_token_age (2h0m0s)
  ```
- **A back-channel logout** (Task 12):

  ```
  port49-broker: logout: https://sso.corp.example.com/realms/corp ended session sid 3c1f… of user:alice@corp.example.com: 2 contexts marked (leaf1/alice, core1/alice), tokens on 1 key deleted
  port49-broker: logout: https://sso.corp.example.com/realms/corp ended every session of sub 8b2e…: no principal is on record for it (no mint in the last 24h0m0s); tokens it issued before 2026-10-06T10:12:00Z are refused from now on; to end a person's sessions at once use port49 revoke
  port49-broker: logout: a logout token from https://sso.corp.example.com/realms/corp could not be applied: the store did not answer; answered 503 so the provider may retry; if it does not, revoke the principal with port49 revoke once the store returns
  port49-broker: logout: the logout of sid 3c1f… from https://sso.corp.example.com/realms/corp could not be given back for a retry (…): the provider's retry will be answered 200 and do nothing; end it by hand with POST /v1/tokens/revoke {"sid": "3c1f…", "issuer": "https://sso.corp.example.com/realms/corp"} or port49 revoke <principal>
  port49-broker: logout: https://sso.corp.example.com/realms/corp: the owner record names user:alice@other.example.org, outside this verifier's principal_domains (corp.example.com); it is not reached
  ```
- **A refresh the provider did not re-authenticate** (Task 11), as the agent's error:

  ```
  refresh_not_fresh: your identity provider did not authenticate you again (prompt=login was not honoured); the session was not extended
  ```
- **New config refusals** (Task 7):
  - `broker.identity.machines[0]: type x509 (workload certificates) is plan 8's; remove it`;
  - `broker.identity.machines[1]: type k8s is plan 10's; remove it`;
  - `broker.identity.humans[1].algorithms: HS256 is refused: a shared-secret signature lets anyone holding the secret sign as the provider (RFC 8725 §3.2)`;
  - `broker.client_ca_file: moved to broker.identity.humans[].trust_anchor_file; set one or the other`;
  - `broker.identity.humans: at most one x509 verifier (the broker verifies a chain against one anchor)`;
  - `broker.identity.humans[1].principal_claim groups: one of preferred_username, email or upn`;
  - `broker.identity.humans[1].principal_claim is required: one of preferred_username, email or upn`;
  - `broker.identity.humans[1].principal_domains is required: the domains whose people this verifier may name (user:<name>@<domain>)`;
  - `broker.identity.humans[2].principal_domains: corp.example.com is also broker.identity.humans[1]'s, at another issuer: two issuers would give one principal`;
  - `broker.identity.humans[2].principal_claim upn differs from broker.identity.humans[1]'s (email) at one issuer: one sub would be two principals`;
  - `broker.identity.machines[0].clients is required: each client_id that may be a machine principal, with its sub at the provider`.
- **New metrics:** Ruling 17.

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, **no cgo**, **no new
  module** (OR-1).
- snake_case everywhere it is data: YAML keys, JSON log keys, config, metric names.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). **This plan
  adds none.** It widens `trust_domain_unresolved`, `identity_unmapped`, `credential_revoked`
  and `session_expired`, in the spec table first (Task 1). The API error codes
  `identity_provider_unavailable` and `refresh_not_fresh` are API codes (design §17's error
  table), not reasons.
- The log never contains a token, password, challenge or response. Credentials appear only as
  `credential_sha256`. **An unvalidated body is never logged.**
  - **7h's credentials:** a bearer token, a logout token, a JWS signature and a refresh nonce are
    never formatted into any line, record, error or metric label.
  - **A claim of a token that did not verify is unvalidated input.** It is never said,
    including its `iss`, `kid` and `sub`.
  - `oidc.Assertion` and `oidc.LogoutToken` have `String` methods that withhold the nonce and
    the `jti`.
- No device identity and no principal in metric labels.
- **Fail closed, never widen:**
  - two verifiers accepting one token is a refusal;
  - a person's token is never a machine's, and a machine verifier names its clients (Ruling 21);
  - an issuer gives only principals in its own `principal_domains`, and no two issuers share
    one (Ruling 22);
  - a stale key set refuses;
  - a logout reaches more than its session where the store cannot cut finer, never less;
  - an unknown claim form is a refusal.
- The daemon never reads a token. Nothing on the TACACS+ path waits on the provider.
- Verify with `make test && make vet` and report the real output. Every test that speaks to a
  real provider is a lab test (`//go:build lab`, Tasks 15 and 16, `make lab-oidc`, on beehive),
  so `go test ./...` needs no provider: the unit tests run on `oidctest.Issuer`, an
  `httptest.NewTLSServer`.
- **Deployment is not prescriptive.** Nothing requires OIDC. Without `broker.identity`, 7g's
  behaviour is unchanged (Ruling 1's shorthand).
- **Readiness never follows the provider** (design §12). No task adds a provider or key-set
  condition to `/readyz`; Task 14 pins it.
- The lab register rules (CLAUDE.md 1–4).
  - L45, L46 and L47 open in Task 1.
  - L45 and L46 close in Task 16 on Keycloak, the platform they name, only if their notes exist
    with platform, image version, observation and a capture pointer.
  - L47 (hosted providers) stays open.
- Conventional Commits; commit messages end with
  `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>` and
  `Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc`.

## Review Focus

The eight inputs or conditions no task's tests exercise by accident and most likely to bite a
person, with the test that pins each:

1. **A token that names its own trust, or a key the verifier mishandles.**
   - **The inputs:** an `alg` of `none`; an `HS256` token whose HMAC key is the provider's RSA
     public key; a `jku` or `jwk` header pointing at an attacker's key; a `crit` header; a token
     under a key of another type; Wycheproof's malformed signatures.
   - **Expected:** each refused before any key is used, or by the signature check.
   - **Pinned by** Task 3's `TestNoneAndHMACAreRefusedBeforeAnyKey`,
     `TestAHeaderNamedKeyIsNeverUsed`, `TestACritHeaderIsRefused`,
     `TestTheAlgorithmKeyTypeMatrix`, `TestWycheproof` and `FuzzParseCompact`.
2. **A key rotation, and a provider gone.**
   - **Rotation.** A new `kid` appears while the cache is warm. The operator expects the token
     accepted after one refetch, even when the client that triggered it hung up, and a dropped
     key refused once the provider stops listing it.
   - **Unreachable.** Tokens under a held key are accepted until `jwks_max_age`, then refused
     503. A JWKS with no usable key is a failed fetch, never an empty set.
   - **Pinned by** Task 4's `TestANewKidIsFetchedOnceAMinute`,
     `TestACallerHangingUpDoesNotPoisonTheRefetch`, `TestADroppedKeyIsRefusedAtOnce`,
     `TestAStaleSetRefusesAfterMaxAge` and `TestAJWKSWithNoUsableKeyKeepsTheLastGoodSet`.
3. **A broker restarted while the provider is down.**
   - **Expected:** tokens people hold still validate from the persisted keys, the staleness
     gauge carries the kept set's age, and a persisted file another user wrote is refused.
   - **Pinned by** Task 4's `TestARestoredSetServesUntilMaxAge` and
     `TestTheLastSuccessGaugeSurvivesARestart`, and Task 14's
     `TestAKeyFileTheBrokerDidNotWriteIsRefused`.
4. **One issuer serving both people and services.**
   - **The inputs:** an ID token for another client of the same provider; an access token
     presented where an ID token is expected; a person's delegated access token for a machine
     client (`aud` the API, `azp` the client, with `sid`, `auth_time` or `scp`); a
     client-credentials token of an unlisted client, or with another `sub`; a token two
     machine verifiers accept.
   - **Expected:** none becomes a principal in the other domain, and no person becomes `app:`.
   - **Pinned by** Task 5's `TestATokenTwoVerifiersAcceptIsRefused`,
     `TestAnotherClientsIDTokenIsRefused`, `TestAnAccessTokenIsNotAHumansToken`,
     `TestADelegatedTokenIsNotAMachine` and `TestAMachineSubIsPinned`.
5. **A logout the provider sends twice, late, or while the store is down.**
   - **Expected:** the second is a no-op answered 200; a logout for a session port49 never saw
     still refuses that session's tokens; a store outage answers 503 and the retry applies.
   - **Pinned by** Task 12's `TestALogoutReplayedIsANoOp`,
     `TestALogoutForAnUnseenSessionStillRefusesItsTokens`,
     `TestALogoutTheStoreFailedIsRetriable` and `TestALogoutWhoseJTICannotBeGivenBackSaysSo`.
6. **A clock a few minutes off between broker and provider.**
   - **Expected:** a token accepted within `clock_skew`, refused beyond it with a line naming
     the skew. A refresh whose `auth_time` is a second before the challenge, within skew, is
     accepted.
   - **Pinned by** Task 5's `TestClockSkewIsAllowedAndNoMore` and Task 11's
     `TestARefreshWithinSkewOfTheChallengeIsFresh`.
7. **A mint or a refresh racing a logout.**
   - **Expected:** no token minted under the dead session survives, and no context a refresh
     extended outlives a logout that landed during it. A rename under one `sub` leaves no
     principal a logout misses.
   - **Pinned by** Task 9's `TestAMintRacingALogoutLeavesNoToken`, Task 11's
     `TestALogoutDuringARefreshMarksTheExtendedContext`, Task 8's `OIDCOwnerKeepsEveryPrincipal`
     and Task 12's `TestALogoutFindsTokensMintedBeforeIt` and
     `TestALogoutReachesEveryPrincipalOfTheSub`.
8. **Two identity providers, one naming the other's people** (Ruling 22).
   - **The inputs:** a second issuer whose token says `email: alice@corp.example.com`,
     `email_verified: true`; its `sub` logout; an owner record that names a principal outside
     the issuer's domains.
   - **Expected:** the token is refused `identity_unmapped`; the logout reaches no context and
     no token of Alice's.
   - **Pinned by** Task 5's `TestAnIssuerNamesOnlyItsOwnDomains`, Task 7's
     `TestIdentityRefusals` ("domains overlap across issuers") and Task 12's
     `TestAnotherIssuersSubLogoutReachesNoneOfAlices`.

## Conflict scan: where tasks share a file or an interface

- `internal/broker/broker.go`:
  - Task 9 changes `authenticate`'s return to `caller` and every caller of it in the same
    commit;
  - Task 10 changes `config` and `Server`'s `tls.Config`;
  - Task 13 reads `revokedSince`.
  - In that order.
- `internal/broker/sessionrefresh.go`: Task 11 alone. It calls Task 9's `bearerCaller`.
- `internal/broker/revoke_api.go`: Task 9 (the `caller`) and Task 13 (`sid`). Task 13 builds on
  Task 12's `RevokeSid`.
- `internal/store/store.go`, `memory/memory.go`, `crypt/crypt.go`, `etcd/*`, `guard/guard.go`,
  `storetest/*`: Task 8 alone.
- `internal/decision/log.go`: Task 2 alone.
- `internal/broker/api/*.go`: Task 2 alone. Tasks 10 and 13 read the types.
- `internal/config/config.go`: Task 7 alone. The identity block lives in a new
  `internal/config/identity.go`.
- `internal/daemon/metrics/metrics.go`: Task 4 (keys), Task 5 (tokens) and Task 12 (logouts).
- `internal/port49d/main.go`, `brokerd.go`: Task 14 alone.
- `internal/oidc/oidctest`: Task 4 creates it. Tasks 5, 6, 9 to 13 use it.
- `internal/oidc/verify.go`: Task 5 writes it, Task 6 shares its signature and audience checks.
  `oidc.VerifierConfig`'s `Clients` and `PrincipalDomains` (Task 5) are what Task 7 fills and
  Tasks 9, 12 and 14 read.
- `internal/broker/member_test.go`: Task 9 converts its `revokedSince` call (pre-flight I-13).
- `internal/testpki/testpki.go`: Task 16 alone (the lab broker certificate's DNS name).
- Spec §5.7, §13, §15: Task 1 writes them; Task 16 closes the rows (a docs commit in that task).

## Running the lab (Tasks 15 and 16)

- On beehive, from a pinned worktree of the branch at the commit under test. Copy any raw
  captures to `main`'s `tests/lab/captures/` before removing the worktree (the labpcap audit).
- Run a background stall watchdog during each run, and re-arm it on wake.
- Before a run: `df -h` and `sg docker -c 'docker compose version'` (≥ v2.24.4).
- Docker is reached as `sg docker -c '…'` on beehive. The lab's Go tests call `docker` through
  the `dockerCmd` helper that prefixes it.
- Keycloak takes up to 90s to import its realm at first start. The harness waits on
  `/realms/port49-lab/.well-known/openid-configuration`, not on the container's state.

## File Structure

**Create:**
- `internal/oidc/doc.go`: the package comment (what reads a token, and what never does).
- `internal/oidc/jws.go` (+ `jws_test.go`): `Alg`, `ParseAlgs`, `ParseCompact`, `JWS.Verify`.
- `internal/oidc/jwk.go` (+ `jwk_test.go`): `Key`, `ParseJWKS`.
- `internal/oidc/wycheproof_test.go`, `fuzz_test.go`, `export_test.go`, and
  `internal/oidc/testdata/wycheproof/`: Project Wycheproof's vectors and the fuzz targets.
- `internal/oidc/keyset.go` (+ `keyset_test.go`): `KeySet`, discovery, refresh, persistence,
  aging.
- `internal/oidc/config.go`: `Config`, `Verifier` config, `Timing`, the defaults.
- `internal/oidc/verify.go` (+ `verify_test.go`): `Set`, `Verify`, `Assertion`, the errors.
- `internal/oidc/logout.go` (+ `logout_test.go`): `LogoutToken`, `VerifyLogout`.
- `internal/oidc/oidctest/sign.go`, `issuer.go`: keys, signed tokens, and `Issuer`, a TLS test
  provider publishing discovery and a JWKS.
- `internal/config/identity.go` (+ `identity_test.go`): `broker.identity`.
- `internal/store/storetest/oidc.go`: the new properties.
- `internal/store/etcd/oidc.go`: `on/`, `oo/`, `lo/`.
- `internal/broker/oidc.go` (+ `oidc_test.go`): `caller`, `bearerCaller`, the owner and logout
  checks.
- `internal/broker/logout.go` (+ `logout_test.go`): `Broker.Logout`, `Broker.RevokeSid`,
  `POST /v1/logout`.
- `internal/broker/oidcrefresh.go` (+ `oidcrefresh_test.go`): the OIDC challenge and refresh.
- `internal/broker/oidcserver_test.go`: the OIDC-only server, `/v1/config`, a bearer through the
  listener.
- `internal/port49d/identity.go` (+ `identity_test.go`): building the set, the start lines, the
  key-set loops, the key files.
- `tests/lab/oidc/keycloak/` (`realm.json`, `README.md`), `tests/lab/oidc/compose.yaml`: the
  provider.
- `tests/lab/compose/oidc.yaml`: the compose overlay for the end-to-end run.
- `tests/lab/oidc_test.go`, `oidcflow_test.go`, `l45_test.go`, `l46_test.go`,
  `oidc_e2e_test.go`: `//go:build lab`.
- `internal/port49d/identity_linux_test.go`: the kept key file's owner checks, and the two
  tests that write a key file (`ownedHere` is Linux's).

**Modify:**
- `internal/decision/log.go`: `Auth.OIDC`, `Revocation.OIDCIssuer`, `Sid`, `Sub`.
- `internal/broker/api/api.go`, `identity.go`, `revoke.go`: `Config.OIDC`, `Identity.OIDC`,
  `RevokeRequest.Issuer`.
- `internal/store/store.go`, `memory/memory.go`, `crypt/crypt.go`, `etcd/keys.go`,
  `etcd/roles.go`, `etcd/roles_test.go`, `guard/guard.go`, `storetest/storetest.go`.
- `internal/session/session.go`: `AddSid`.
- `internal/config/config.go`: `Broker.Identity`, the shorthand, the `client_ca_file` and
  `certificate_status` rules.
- `internal/broker/broker.go`, `identity_api.go`, `explain_api.go`, `revoke_api.go`,
  `revoke.go`, `server.go`, `sessionrefresh.go`, `member_test.go`.
- `internal/testpki/testpki.go` (+ `testpki_test.go`): the lab broker certificate names
  `port49-broker`.
- `internal/daemon/metrics/metrics.go`.
- `internal/port49d/main.go`, `brokerd.go`, `statedir_linux.go`, `statedir_other.go`
  (`readOwnerOnly`).
- `internal/token/minter.go`: `Request.OIDC` onto the permit record.
- `internal/daemon/authen/authen_test.go`: `noStore` gains the six store methods.
- `deploy/compose/config/port49-broker.yaml`, `deploy/compose/README.md`.
- `Makefile`: `lab-oidc`.
- `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`.
- `tests/lab/README.md`.
- `docs/superpowers/plans/README.md`.

---

### Task 1: The spec and the design say what 7h builds, and L45, L46 and L47 open

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §2, §5.1.4, §5.6, §5.7 (events, reason
  table, record fields), §13 (decisions 8, 39), §14, §15 (L45, L46, L47)
- Modify: `docs/design/2026-08-21-port49-design.md`: §7, §12, §17

**Interfaces:**
- Consumes: Rulings 1–24 above.
- Produces: decision 39 (every later task cites it), the widened reason rows (Tasks 5, 9, 11,
  12 cite them), `auth.oidc` and the `revoke` record's `oidc_issuer`, `sid`, `sub` (Task 2
  builds them), register rows L45 and L46 (Task 16 closes them) and L47 (stays open).

- [ ] **Step 1: §2, the principal table, the username table, and the rights**

In §2's principal table, replace the two OIDC rows with:

```markdown
| human OIDC | `user:` + the claim `broker.identity.humans[].principal_claim` names (required, no default: `preferred_username`, `email` only with `email_verified: true`, or `upn`), lower-cased, printable ASCII with an `@`, its domain one of the verifier's `principal_domains` (§13 decision 39 rulings 6, 22, 23) |
| machine OIDC | `app:` + the token's `azp`, else its `client_id` claim, verbatim: a client the verifier's `clients` lists, the token's `sub` that client's pinned identity; a token carrying a person's session claim (`auth_time`, `sid`, `nonce`, `scp`, `amr`) is never a machine's (§13 decision 39 ruling 21) |
```

The amendment removes the row's former "`preferred_username` by default": OIDC Core §5.7 says a
relying party must not rely on that claim being unique, and Keycloak's documented default is
the bare username, which has no `@` (§15 L46 measures it), so a default would refuse every
Keycloak person (§13 decision 39 ruling 23).

After the table's following paragraph ("Every example in this document that shows a principal
…"), add:

```markdown
A principal's trust domain is the list its verifier is in, `broker.identity.humans` or
`broker.identity.machines` (§13 decisions 16 and 39), and nothing in the credential decides it.
A token two verifiers would accept is refused. A person's delegated token never becomes a
machine principal, and no two OIDC issuers can give one human principal: each human verifier
names the `principal_domains` it is authoritative for, and two that overlap are refused.
```

In "The device-facing username", replace the identity-path table's OIDC row with:

```markdown
| OIDC | with `broker.directory`, the directory's `username_attribute`, read for the principal as a certificate's is; without it, the identity subject's declared `username:`. The `preferred_username` claim is never a username (§13 decision 39) |
```

In the rights table, replace the `revoke_others` cell's "by `sid` with OIDC (plan 7h)" with "or
an OIDC session by `sid` and issuer (§5.1.4; §13 decision 39)".

- [ ] **Step 2: §5.1.4, back-channel logout as built**

Replace "Revocation by an OIDC `sid` or `sub` arrives with plan 7h, and from a CRL or an OCSP
response with plan 7b, each as a mark of this kind where the certificate is still held (see
below)." with "Revocation from a CRL or an OCSP response arrived with plan 7b, as a mark of this
kind where the certificate is still held (see below); an OIDC back-channel logout, by `sid` or
`sub`, with plan 7h, as no mark (below)."

In "Over HTTP, as built", replace "a `sid` until plan 7h" with "a `sid` beside a principal or a
key"; after the third bullet add:

```markdown
- **`{"sid": …, "issuer": …}`**, under `revoke_others`, ends one OIDC session as a back-channel
  logout by `sid` does (below), its origin `api <caller>`. `issuer` may be omitted when exactly
  one human OIDC verifier is configured. Without the right it is refused 403
  `api_right_missing` and recorded.
```

After "Certificate status, as built" and its last paragraph, add:

```markdown
**Back-channel logout, as built (plan 7h; §13 decision 39).** An identity provider ends a
session by posting a logout token (OpenID Connect Back-Channel Logout 1.0) to `POST
/v1/logout`. It needs no client certificate and no `api:` right: it authenticates by the
provider's signature. The token is validated as an ID token is (§13 decision 39), against
the human OIDC verifiers alone (`aud` and `azp` as for an ID token), and then: `iat` no older
than 24h, `exp` honoured when present, a `jti`, the back-channel logout member in `events`, no
`nonce`, and a `sub`, a `sid`, or both. A `jti` seen before is answered 200 and does nothing.

A logout is not a standing mark: the person may log in again at once, and only an operator's
`port49 revoke` bans. It reaches, in order:

- **A logout record**, written first, kept `max_token_age` plus twice `clock_skew`. By `sid`, it
  refuses every token naming that issuer and `sid`; by `sub` alone, every token for that issuer
  and `sub` issued at or before the logout token's `iat` plus `clock_skew`. Every bearer
  request reads it; a mint reads it again after its last token write and deletes what it wrote
  if one appeared, as it reads the marks.
- **The person's unspent tokens**, found through the principals an owner record names: at each
  human OIDC mint and refresh the broker adds the minting principal to the record under
  `(issuer, sid)` and `(issuer, sub)`, before its first token write, for
  `max(session.max_session_age_default, 24h)`; a record keeps every principal written to it
  until each one's own expiry, so a rename under one `sub` is reached too. They are deleted one
  by one, each principal's own only, every session's: the token index holds no finer cut. A
  principal outside the accepting verifier's `principal_domains` is never reached.
- **The live contexts, twice.** By `sid`, those indexed under the issuer-qualified `sid`; by
  `sub` alone, every context of the principal. A context is shared per (principal, device)
  and holds the last login's credential (decision 15), so a `sub` logout ends a person's
  certificate-path contexts too, and a `sid` logout ends a context another of the person's
  sessions joined, or a certificate-path context an OIDC refresh extended under that `sid`.
  The person's next login, with a token minted after, lifts the mark (§5.6).
- **The receipts** of the principals behind those contexts.

One `revoke` record is written, `by: sid` or `by: sub`, origin `backchannel_logout <issuer>`
(§5.7). With no mark, a redemption that removed its token before the delete and writes its
context after the second pass writes it unrevoked: one store round trip, as for a self
revocation. A logout whose store writes fail is answered 503, so the provider may send it
again; whether it does is the provider's (§15, L45).
```

- [ ] **Step 3: §5.6, the OIDC refresh as built**

After the "The refresh on the certificate path" bullet of "As built (plan 7b …)", add a new
paragraph:

```markdown
**The refresh on the OIDC path, as built (plan 7h; §13 decision 39).** It is `POST
/v1/refresh/challenge` and `POST /v1/refresh`, each with the caller's bearer:

- **The nonce.** 32 random bytes, held in the store for 5m so any broker replica can take it,
  once; one per principal per 10s. The agent sends it as the `nonce` of a `prompt=login`
  authentication request.
- **The proof.** The new ID token is the refresh's bearer. Its `nonce` must be that challenge,
  unspent, issued to the same principal and issuer, and its `auth_time` no earlier than the
  challenge less `clock_skew`; else 401 `refresh_challenge_missing` or `refresh_not_fresh`, and
  nothing is extended.
- **The clock.** `auth_time` is the assertion's, never the broker's (decision 17).
- **The `sid`.** Each extended context is indexed under the new assertion's `sid` too, beside
  the old and before it is extended, so a logout of either session reaches it. A logout that
  lands during the refresh is caught by the refresh's reading of the logout records after its
  writes, which then marks every context it extended before answering 401.

Whether a provider moves `auth_time` and echoes the `nonce` on `prompt=login` is §15's L46
(Keycloak) and L47 (hosted providers).
```

- [ ] **Step 4: §5.7, the record fields, the revoke body, the reasons**

After the `auth.directory` bullet, add:

```markdown
- `auth.oidc`: on a broker event whose caller presented an OIDC token, `{issuer, sub, sid, amr,
  acr, auth_time}`, each from the verified token (`sid` the provider's own, not
  issuer-qualified); `amr` and `acr` are recorded and consulted by nothing (decision 13). A
  bearer that did not verify is recorded `auth: {method: oidc}` with no principal: none of its
  claims is a validated value (§13 decision 39).
```

In the `revoke` paragraph, replace "`by` is `principal` or `cert` for a standing mark, `self` for
a principal ending its own sessions, and `key` for one `(device, username)` ended;" with "`by`
is `principal` or `cert` for a standing mark, `self` for a principal ending its own sessions,
`key` for one `(device, username)` ended, and `sid` or `sub` for an OIDC session or subject
ended by a back-channel logout or by `/v1/tokens/revoke` (§5.1.4), which carry `oidc_issuer`
and `sid` or `sub`, and `principals` when the logout reached more than one principal (the
record's `principal` is then the first);", and add "`backchannel_logout <issuer>`" to
`origin`'s list after `api <principal>`.

In the reason table:

- `trust_domain_unresolved`: append "; or an OIDC token none of `broker.identity`'s verifiers
  accepts, or that two accept (a bad signature, an algorithm the verifier does not pin, an
  `iss`, `aud` or `azp` that does not match, an expired or not-yet-valid token, one issued
  longer ago than `max_token_age`, a human token without `auth_time`, a machine token from a
  client the verifier does not list, with another `sub` than the client's, or carrying a
  person's session claim) (§13 decision 39). When
  the issuer's keys cannot be had (none fetched, or none refreshed within `jwks_max_age`) the API
  answers 503 `identity_provider_unavailable`, to be retried, never a final 401. On `refresh`:
  also an OIDC refresh whose token's `nonce` is not the caller's unspent challenge (401
  `refresh_challenge_missing`), or whose `auth_time` is before it (401 `refresh_not_fresh`)".
- `identity_unmapped`: after "at the broker's bind, and on `mint`, `identity`, `explain` and
  `revoke`:" insert "an OIDC token that verified but whose principal claim is absent, not one
  string, not printable ASCII with an `@`, outside the verifier's `principal_domains`, or an
  `email` without `email_verified: true`, or a machine token with neither `azp` nor
  `client_id` (§13 decision 39); or".
- `credential_revoked`: after "on `mint`, a revocation by principal or by this certificate
  stands (§5.1.4)" insert ", or an OIDC logout refuses the token's session or subject".
- `session_expired`: after "On `mint`: the held connection's authentication is older than
  `session.max_session_age_default`," insert "or an OIDC token's `auth_time` is,".

- [ ] **Step 5: §13, decision 8 and the new decision 39**

In decision 8, replace "Human usernames come from the same directory query that resolves
groups, or the OIDC `preferred_username` claim;" with "Human usernames come from the same
directory query that resolves groups, or, with no directory, the identity subject's declared
`username` (decision 38 ruling 16; decision 39 ruling 7);".

After decision 38, add:

```markdown
**39. OIDC: a verifier per trust domain, a token validated per request, keys aged out, a logout
that leaves no mark.** *Plan 7h, 2026-10-06.* Rulings rest on reasoning unless they say data.

- **1. The lists.** `broker.identity.humans` and `.machines`. `x509` under `humans` (its
  `trust_anchor_file`, at most one) and `oidc` under either (`issuer` with `client_id`,
  `principal_claim` and `principal_domains` for humans; `audience` and `clients` for machines).
  `x509` under `machines` and `k8s` are refused, plans 8 and
  10. No `broker.identity` is `humans: [x509 from broker.client_ca_file]`; with it,
  `client_ca_file` is refused. An OIDC-only broker requests no client certificate and takes no
  `certificate_status`. Task 7.
- **2. One verifier per token.** A token goes to every verifier whose issuer equals its `iss`;
  exactly one must accept, two is `trust_domain_unresolved`. A human verifier needs `aud` ∋
  `client_id`, `azp` = `client_id` when present and when `aud` has several values, and refuses
  `typ: at+jwt`; a machine verifier needs `aud` ∋ `audience` and ruling 21's client checks.
  A bearer with an `events` claim is refused (RFC 8725 §2.8). Task 5.
- **3. The signature** (data: RFC 7515, 7518, 8725). Compact JWS only, 16 KiB at most;
  `algorithms` per verifier, default `[RS256]`, from `RS256`, `PS256`, `ES256`, `ES384`,
  `EdDSA`; `none` and `HS*` refused at load and at parse; algorithm and key type agree, and a
  JWK's own `alg` when it has one; `crit` refused; `jku`, `jwk`, `x5u`, `x5c` never used; a
  `kid` names one key, and with none the set holds one key of the type; JWKs with `use` not
  `sig`, `key_ops` without `verify`, or RSA under 2048 or over 8192 bits are skipped; a set
  of over 100 keys is refused. In-house on the standard library (OR-1), checked against the
  RFC examples, Project Wycheproof's vectors, an algorithm × key-type matrix and fuzzing.
  Task 3.
- **4. Keys** (data: OIDC Discovery §4.3). Discovery's `issuer` equals the configured one;
  `jwks_uri` is `https`, and is said when it changes; fetched with `ca_file` or the system
  roots, through the environment's proxy when one is set, no redirect, 1 MiB, 10s; refreshed
  every `jwks_refresh_interval` (1h) and on an unknown `kid` at most once a minute, on a
  context no caller's hang-up cancels; a successful fetch with a usable key replaces the set,
  and one with none is a failed fetch; the last good set is trusted until `jwks_max_age` (24h)
  after its fetch, then every token is 503 `identity_provider_unavailable`; persisted 0600 in
  the state directory and restored at start when younger than `jwks_max_age`, the staleness
  gauge carrying its age; a start never waits on the provider; readiness never follows it.
  OR-2 for the timings. Tasks 4 and 14.
- **5. The claims** (data: OIDC Core §2, §3.1.3.7). `iss` exact; `exp` required; `nbf` honoured;
  `iat` required and no older than `max_token_age` (2h); `sub` required; a human's
  `auth_time` required; `clock_skew` 60s (0s–5m); every claim read by its exact name, a claim
  named twice in different case refused; a date that is a JSON string refused. Task 5.
- **6. The principal.** Human: `user:` + `principal_claim` (required: `preferred_username`,
  `email` with `email_verified: true`, or `upn`), lower-cased, printable ASCII with an `@`, in
  the verifier's `principal_domains`. Machine: `app:` + `azp`, else `client_id`, verbatim, a
  listed client (ruling 21). Otherwise `identity_unmapped`. The claim must be one only the
  provider's administrators set; the start says so. Task 5.
- **7. The username and groups.** With a directory, the directory's, through `memberFor`, as a
  certificate's; without one, the identity subject's declared `username`. No username and no
  group is read from a token; spec §2 and decision 8 are amended to match decision 38 ruling
  16. Task 9.
- **8. A bearer per request, one credential per request.** No held connection on the OIDC
  path; a certificate-less connection is charged to its source while open and closed when
  idle, so the per-source cap bounds concurrent OIDC requests per address; a certificate and a
  bearer together are refused 400; the marks apply to a bearer caller's principal. Tasks 9 and
  10.
- **9. The session clock** (data: spec §5.6, decision 17). A human token's `auth_time`; a
  machine's `iat`. A request whose `auth_time` is older than
  `session.max_session_age_default` is refused `session_expired`, but for the refresh's own
  challenge and refresh. Task 9.
- **10. The credential.** `{method: oidc, iss, sub, sid, amr, acr}`, `sid` issuer-qualified
  (`store.SidKey`) so one issuer's logout never reaches another's session; `auth.oidc` on every
  record of a bearer caller; nothing of an unverified token is recorded. Tasks 2 and 9.
- **11. Owner records.** `(issuer, sid)` and `(issuer, sub)` to every principal minting under
  them (ruling 24), written before the first token write of each human OIDC mint and refresh
  (skipped while the principal's entry is under an hour old), for
  `max(session.max_session_age_default, 24h)` per principal; a machine writes none; a failed
  write refuses the mint `store_unavailable`. Tasks 8 and 9.
- **12. `POST /v1/logout`** (data: OIDC Back-Channel Logout 1.0 §2.4–§2.8; provisional on L45
  and L47). Form-encoded `logout_token`, 16 KiB; the human OIDC verifiers alone, `aud` and
  `azp` as for an ID token; Ruling 3's signature; `iat` (no older than 24h), `exp` when
  present, `jti`, `events`, no `nonce`, `sub` or `sid`, `typ` `logout+jwt` or `JWT` when
  present. A `jti` seen before (24h + 2 × `clock_skew`) is 200 and nothing; a token that does
  not validate is 400 `invalid_request`; a store failure is 503 with `Retry-After` and the
  `jti` given back, departing from BCL §2.8's 400, and a `jti` that cannot be given back is
  said with the manual ends. `Cache-Control: no-store`. Task 12.
- **13. A logout leaves no mark.** A logout record first (by `sid`: every token naming it; by
  `sub`: every token issued at or before the logout's `iat` + `clock_skew`; kept `max_token_age` +
  2 × `clock_skew`); then each owner principal's own unspent tokens, only principals in the
  verifier's `principal_domains`; then the contexts twice (by `sid`, or every context of each
  principal by `sub`); the receipts; one `revoke` record by `sid` or `sub`. A `sid` logout
  also ends a certificate-path context an OIDC refresh extended under it: fail closed. A mint
  reads the logout records before and after its writes. The residual window is a self
  revocation's. Tasks 8, 9 and 12.
- **14. Revocation by `sid` over HTTP**, under `revoke_others`, `{sid, issuer}`, as a logout by
  `sid`, origin `api <caller>`. Task 13.
- **15. The OIDC refresh** (data: spec §5.6; provisional on L46 and L47). A store-held nonce
  from `POST /v1/refresh/challenge` (5m, once, one per principal per 10s), sent as the `nonce`
  of a `prompt=login` authentication; the new ID token's `nonce` taken once, its principal and
  issuer the challenge's, its `auth_time` no earlier than the challenge less `clock_skew`; then
  the certificate path's steps with `auth_time` as the clock; the new `sid` indexed beside the
  old, before the extension; a logout read after the writes marks every context extended.
  Task 11.
- **16. `/v1/config`** lists `methods` and, per human OIDC verifier, `{issuer, client_id,
  scopes}`. Task 10.
- **17. The metrics.** `port49_oidc_tokens_total{issuer,outcome}`,
  `port49_oidc_keys_last_success_timestamp_seconds{issuer}`,
  `port49_oidc_keys_fetch_failures_total{issuer}`, `port49_oidc_logouts_total{outcome}`; no
  principal and no device. The last-success gauge exists from the start and a restore sets it,
  and its alert carries `or absent(...)`. Tasks 4, 5 and 12.
- **18. What is never logged:** a bearer or logout token, a signature, a refresh nonce, the
  `Authorization` header, any claim of a token that did not verify. Tasks 3 to 12.
- **19. `app:` principals can be revoked:** `normalPrincipal` takes `app:`, verbatim after the
  prefix. Task 2.
- **20. The lab is Keycloak** (L45, L46); hosted providers are L47, open (OR-3). Rulings 12's
  token shape, 13's `sid` and `sub` matching the ID token's, 15's `auth_time` and `nonce`, and
  21's claim sets are provisional on them. Tasks 15 and 16.
- **21. A machine verifier takes listed clients with a pinned `sub`** (data: RFC 9068 §2.2;
  OIDC Core §2; provisional on L46 and L47). `clients: [{client_id, sub}]`, required; the
  client (`azp`, else `client_id`) listed and the `sub` its pinned one; `azp` and `client_id`
  differing refused; a token carrying `auth_time`, `sid`, `nonce`, `scp` or `amr`, or an `idtyp`
  other than `app`, refused: a person's delegated token never becomes `app:`. Tasks 5 and 7.
- **22. `principal_domains`.** Each human `oidc` verifier lists the domains whose principals it
  may give, required; a principal outside them is `identity_unmapped`; two verifiers on
  different issuers with overlapping domains are refused at load; a logout reaches only
  principals in its verifier's domains. Tasks 5, 7 and 12.
- **23. `principal_claim` is required** (data: OIDC Core §5.7). No default; spec §2's
  "`preferred_username` by default" is withdrawn. Task 7.
- **24. Owner records hold every principal.** One record, a set of `{principal, expires_at}`
  merged by compare-and-set; a logout ends each. Two human verifiers on one issuer with
  different `principal_claim`s are refused. Tasks 7, 8, 9 and 12.
```

- [ ] **Step 6: §14, the assertions**

In the "Revocation reaches live sessions" bullet, replace "each invalidate the matching contexts
and no others" with "each invalidate the matching contexts and no other principal's (a `sub`
logout ends every context of its principal, decision 15)". After the `/v1/logout` clause of the
API-rights bullet ("`/v1/logout` succeeds with a valid logout token and no caller rights;") add
"a logout token replayed is answered 200 and does nothing; one that does not validate is 400 and
reaches nothing; a token naming a logged-out `sid` is refused at every endpoint; an OIDC token
two verifiers accept is refused; a person's delegated access token for a machine client is
refused, never `app:`; a token from one issuer naming a principal in another issuer's
`principal_domains` is refused, and that issuer's logout reaches none of the person's contexts;".

- [ ] **Step 7: §15, three new rows**

After L44's row add:

```markdown
| **L45** | The back-channel logout token a provider sends to port49's `/v1/logout`, per way a session ends: an RP-initiated logout at the provider's end-session endpoint, an administrator signing a user out of every session, and an administrator ending one session. For each: the JWS header (`alg`, `kid`, `typ`); which of `iss`, `aud`, `azp`, `iat`, `exp`, `jti`, `sub`, `sid`, `events` it carries, and that `nonce` is absent; whether its `sid` and its `sub` equal the ID token's; one token per session or per user; the request's content type; and what the provider does when the answer is 503, or 400, or the connection is refused (retry or not, the end-session endpoint's own answer, and how it reports the failure). | `POST /v1/logout`'s validation and answers, a logout by `sid` reaching the context the ID token authorized, and a logout by `sub` finding the owner record the ID token's `sub` wrote (§5.1.4; §13 decision 39 rulings 12 and 13, provisional on this row) | Keycloak (26.x) | open — added 2026-10-06 (plan 7h) |
| **L46** | Fresh authentication on a provider: with an SSO session live, whether a plain second authorization request reuses it (no credentials asked, `auth_time` unchanged: the control); whether one with `prompt=login` makes the person enter their credentials again; whether the new ID token's `auth_time` is the new authentication's; whether it carries the request's `nonce`; whether its `sid` is the old session's or a new one; and beside it, what a refresh-token grant's ID token carries (`auth_time` unchanged, `nonce`, `sid`); and `max_age=0` against `prompt=login`. Also: the ID token's `preferred_username` for a user created with a bare username; and which of `auth_time`, `sid`, `nonce`, `scp`, `amr`, `idtyp`, `azp`, `client_id` and `sub` a client-credentials access token carries, beside a person's access token from the same realm (a delegated one). | The OIDC refresh (§5.6; §13 decision 39 ruling 15, provisional on this row); spec §5.6's "the identity provider will correctly report the *original* `auth_time`"; ruling 21's delegated-token markers and pinned `sub`; ruling 23's withdrawn default | Keycloak (26.x) | open — added 2026-10-06 (plan 7h) |
| **L47** | L45's and L46's claims on hosted providers, and their access tokens' `azp`, `aud` and `sub` under the client-credentials grant. For Microsoft Entra ID also: a v2 access token's `aud` (the application's GUID, or its `api://` URI); whether an ID token carries `email_verified` (if not, `principal_claim: email` refuses every Entra person); and the `idtyp` and `scp` claims an app-only and a delegated access token carry. | As L45 and L46, for hosted providers; `app:` + `azp` and the delegated-token refusal (§13 decision 39 rulings 6 and 21) | Microsoft Entra ID, Okta | open — added 2026-10-06 (plan 7h); needs a tenant each (OR-3) |
```

- [ ] **Step 8: The design, §7, §12, §17**

In §7 "Trust domain separation", after the YAML example, add: "As built (plan 7h; policy engine
spec §13 decision 39): the lists are `broker.identity.humans` and `.machines`; an `x509` human
verifier takes `trust_anchor_file` (at most one), an `oidc` one `issuer`, `client_id`,
`principal_claim`, `principal_domains` and `algorithms`; an `oidc` machine verifier `issuer`,
`audience` and `clients`, each client with its pinned `sub`. Workload certificates and `k8s`
are refused until plans 8 and 10. A token two verifiers accept is refused; a person's
delegated token is never a machine's; two issuers never give one principal."

In §7 "Human identity", after the OIDC paragraph, add: "As built (plan 7h): the broker validates
a bearer ID token on every request, against keys it refreshes hourly, keeps in its state
directory, and stops trusting `jwks_max_age` (24h) after the last successful fetch. The agent's
public client is plan 9's."

In §12's failure matrix, add a row after "Directory unavailable":

```markdown
| Identity provider unreachable | New OIDC logins fail at the provider; tokens already held validate against the broker's last keys until `jwks_max_age` (24h) after the last successful fetch, then every OIDC request is refused 503 `identity_provider_unavailable` (plan 7h). Certificate logins, live device sessions and break-glass are unaffected; no logout arrives meanwhile |
```

In §17's surface, replace the `/v1/tokens/revoke` line's "OIDC sid with plan 7h" with "or an
OIDC sid (revoke_others)", and the `/v1/logout` line with:

```
POST  /v1/logout          OIDC back-channel logout — IdP-initiated, form-encoded logout_token; 200, 400 invalid_request, or 503 to retry (plan 7h)
```

In §17's error block, add:

```
503  identity_provider_unavailable    an OIDC token whose issuer's keys the broker cannot use (none fetched yet, or none refreshed within jwks_max_age); nothing was done; Retry-After: 30 (plan 7h)
401  refresh_not_fresh                an OIDC refresh whose new token's auth_time is before the refresh challenge: the provider did not authenticate the person again (prompt=login not honoured) (plan 7h)
400  bad_request                      also: a request carrying a client certificate and an Authorization header (plan 7h)
```

and change `refresh_challenge_missing`'s line to "/v1/refresh with no outstanding challenge on
this connection, or a stale one; on the OIDC path, a token whose nonce is not the caller's
unspent challenge", and `refresh_too_soon`'s (design l.1935) to "a refresh on this connection
less than 10s after the last; on the OIDC path, a second challenge for one principal within
10s, across replicas; Retry-After" (pre-flight M-12: OIDC pacing is per principal).

- [ ] **Step 9: Check and commit**

Run: `grep -n "plan 7h" docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md`
Expected: only the lines this task wrote (no "arrives with plan 7h" or "until plan 7h" left).

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: spec and design for OIDC and trust domains (decision 39); open L45, L46, L47

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: The vocabulary: `auth.oidc`, the revoke body, the API types, `app:` principals

**Files:**
- Modify: `internal/decision/log.go`
- Modify: `internal/broker/api/api.go`, `internal/broker/api/identity.go`,
  `internal/broker/api/revoke.go`
- Modify: `internal/store/store.go` (the key helpers only)
- Modify: `internal/broker/revoke.go` (`principalPrefixes`, `normalPrincipal`)
- Modify: `internal/policy/load.go` (`identityDomain`'s refusal text)
- Test: `internal/decision/log_test.go`, `internal/broker/api/api_test.go`,
  `internal/store/interface_test.go`, `internal/broker/revoke_test.go`

**Interfaces:**
- Consumes: Task 1's §5.7 text.
- Produces:
  - `decision.OIDC{Issuer, Sub, Sid string; AMR []string; ACR, AuthTime string}`, and
    `decision.Auth.OIDC *OIDC` (`json:"oidc,omitempty"`);
  - `decision.Revocation.OIDCIssuer`, `.Sid`, `.Sub` (`oidc_issuer`, `sid`, `sub`, omitempty),
    and `.Principals []string` (`principals`, omitempty: every principal a logout reached when
    the owner record named more than one; Ruling 24);
  - `api.OIDCProvider{Issuer, ClientID string; Scopes []string}` and `api.Config.OIDC
    []OIDCProvider` (`json:"oidc,omitempty"`);
  - `api.IdentityOIDC{Issuer, Sub, Sid string; AMR []string; ACR string}` and
    `api.Identity.OIDC *IdentityOIDC`;
  - `api.RevokeRequest.Issuer string` (`json:"issuer,omitempty"`);
  - `store.OIDCSid`, `store.OIDCSub` (`"sid"`, `"sub"`), `store.OIDCKey(kind, issuer, value
    string) string`, `store.SidKey(issuer, sid string) string`;
  - `normalPrincipal` taking `app:`.

- [ ] **Step 1: Write the failing tests**

In `internal/decision/log_test.go`:

```go
func TestAuthCarriesOIDC(t *testing.T) {
	rec := Record{Event: EventMint, Verdict: VerdictPermit, Reason: GrantsMatched, Principal: "user:alice@corp.example.com",
		Auth: &Auth{Method: "oidc", OIDC: &OIDC{Issuer: "https://sso.example.com/realms/corp", Sub: "8b2e",
			Sid: "3c1f", AMR: []string{"pwd", "otp"}, ACR: "1", AuthTime: "2026-10-06T09:00:00Z"}}}
	var buf bytes.Buffer
	if err := NewJSONLines(&buf).Write(rec); err != nil {
		t.Fatal(err)
	}
	want := `"auth":{"method":"oidc","oidc":{"issuer":"https://sso.example.com/realms/corp","sub":"8b2e","sid":"3c1f","amr":["pwd","otp"],"acr":"1","auth_time":"2026-10-06T09:00:00Z"}}`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("record %s does not carry %s", buf.String(), want)
	}
}

func TestRevocationNamesAnOIDCSession(t *testing.T) {
	rec := Record{Event: EventRevoke, Verdict: VerdictDeny, Reason: CredentialRevoked,
		Revocation: &Revocation{By: "sid", OIDCIssuer: "https://sso.example.com/realms/corp", Sid: "3c1f",
			At: "2026-10-06T10:00:00Z", Origin: "backchannel_logout https://sso.example.com/realms/corp"}}
	var buf bytes.Buffer
	if err := NewJSONLines(&buf).Write(rec); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"by":"sid"`, `"oidc_issuer":"https://sso.example.com/realms/corp"`, `"sid":"3c1f"`} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("record %s lacks %s", buf.String(), want)
		}
	}
	if strings.Contains(buf.String(), `"sub"`) || strings.Contains(buf.String(), `"principals"`) {
		t.Fatalf("an empty sub or principals is written: %s", buf.String())
	}
	rec.Revocation.Principals = []string{"user:alice@example.com", "user:alice2@example.com"}
	buf.Reset()
	if err := NewJSONLines(&buf).Write(rec); err != nil {
		t.Fatal(err)
	}
	if want := `"principals":["user:alice@example.com","user:alice2@example.com"]`; !strings.Contains(buf.String(), want) {
		t.Fatalf("record %s lacks %s", buf.String(), want)
	}
}
```

In `internal/broker/api/api_test.go`:

```go
func TestConfigNamesHumanOIDCVerifiers(t *testing.T) {
	b, err := json.Marshal(Config{Methods: []string{"x509", "oidc"},
		OIDC: []OIDCProvider{{Issuer: "https://sso.example.com/realms/corp", ClientID: "port49-cli",
			Scopes: []string{"openid", "email"}}}})
	if err != nil {
		t.Fatal(err)
	}
	want := `"oidc":[{"issuer":"https://sso.example.com/realms/corp","client_id":"port49-cli","scopes":["openid","email"]}]`
	if !strings.Contains(string(b), want) {
		t.Fatalf("%s lacks %s", b, want)
	}
	b, _ = json.Marshal(Config{Methods: []string{"x509"}})
	if strings.Contains(string(b), `"oidc"`) {
		t.Fatalf("a certificate-only config names oidc: %s", b)
	}
}

func TestRevokeRequestTakesAnIssuer(t *testing.T) {
	var r RevokeRequest
	if err := json.Unmarshal([]byte(`{"sid":"3c1f","issuer":"https://sso.example.com/realms/corp"}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Sid != "3c1f" || r.Issuer != "https://sso.example.com/realms/corp" {
		t.Fatalf("decoded %+v", r)
	}
}
```

In `internal/store/interface_test.go` (package `store_test`):

```go
func TestOIDCKeysAreIssuerQualified(t *testing.T) {
	a := store.SidKey("https://a.example.com", "s1")
	b := store.SidKey("https://b.example.com", "s1")
	if a == b {
		t.Fatal("one sid at two issuers is one key")
	}
	if store.SidKey("https://a.example.com", "s1") != store.OIDCKey(store.OIDCSid, "https://a.example.com", "s1") {
		t.Fatal("SidKey is not OIDCKey(OIDCSid, …)")
	}
	if store.OIDCKey(store.OIDCSid, "https://a.example.com", "x") == store.OIDCKey(store.OIDCSub, "https://a.example.com", "x") {
		t.Fatal("a sid and a sub with one value are one key")
	}
	// The separator cannot be forged by an issuer or a value that holds it.
	if store.OIDCKey(store.OIDCSid, "https://a.example.com s", "1") ==
		store.OIDCKey(store.OIDCSid, "https://a.example.com", "s 1") {
		t.Fatal("the key is ambiguous across its parts")
	}
	if store.SidKey("https://a.example.com", "") != "" {
		t.Fatal("an empty sid has a key: every OIDC login without one would share it (spec §5.6)")
	}
}
```

In `internal/broker/revoke_test.go`:

```go
func TestNormalPrincipalTakesAppVerbatim(t *testing.T) {
	got, err := normalPrincipal("app:Port49-CI")
	if err != nil || got != "app:Port49-CI" {
		t.Fatalf("app:Port49-CI → %q, %v; a client id is case-sensitive", got, err)
	}
	if got, _ := normalPrincipal("APP:svc"); got != "app:svc" {
		t.Fatalf("the prefix is not normalized: %q", got)
	}
	if got, _ := normalPrincipal("User:Alice@Example.com"); got != "user:alice@example.com" {
		t.Fatalf("a user: principal is still lower-cased: %q", got)
	}
	if _, err := normalPrincipal("app:"); err == nil {
		t.Fatal("an empty client id is a principal")
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/decision/ ./internal/broker/api/ ./internal/store/ ./internal/broker/ -run 'TestAuthCarriesOIDC|TestRevocationNamesAnOIDCSession|TestConfigNamesHumanOIDCVerifiers|TestRevokeRequestTakesAnIssuer|TestOIDCKeysAreIssuerQualified|TestNormalPrincipalTakesAppVerbatim' -count=1`
Expected: FAIL to compile (`OIDC`, `OIDCIssuer`, `OIDCProvider`, `Issuer`, `SidKey` undefined), and
`normalPrincipal("app:Port49-CI")` refused.

- [ ] **Step 3: Implement**

In `internal/decision/log.go`, beside `Directory`:

```go
// OIDC is what an OIDC caller's verified token said of how it
// authenticated (spec §5.1.4, §5.7; decision 39): the issuer, the subject,
// the provider's own session id, and amr and acr, recorded because how
// someone authenticated cannot be established afterwards, and consulted by
// nothing (decision 13). Only a verified token's claims are ever here.
type OIDC struct {
	Issuer   string   `json:"issuer"`
	Sub      string   `json:"sub"`
	Sid      string   `json:"sid,omitempty"`
	AMR      []string `json:"amr,omitempty"`
	ACR      string   `json:"acr,omitempty"`
	AuthTime string   `json:"auth_time,omitempty"`
}
```

and in `Auth`, after `Directory`:

```go
	// OIDC is the verified token's identity on a broker event whose caller
	// presented one (plan 7h). A bearer that did not verify has none.
	OIDC *OIDC `json:"oidc,omitempty"`
```

In `Revocation`, after `Serial`:

```go
	// OIDCIssuer and Sid or Sub name an OIDC session or subject a
	// back-channel logout or a revocation by sid ended (by "sid" or "sub").
	OIDCIssuer string `json:"oidc_issuer,omitempty"`
	Sid        string `json:"sid,omitempty"`
	Sub        string `json:"sub,omitempty"`
	// Principals is every principal a logout reached when its owner record
	// named more than one (a rename under one sub; Ruling 24); the record's
	// Principal is then the first.
	Principals []string `json:"principals,omitempty"`
```

In `internal/broker/api/api.go`, after `Config`'s fields:

```go
	// OIDC is each human OIDC verifier a public client may authenticate
	// against (plan 7h; design §17): discovery data, never fleet data.
	// Machine verifiers are not listed.
	OIDC []OIDCProvider `json:"oidc,omitempty"`
}

// OIDCProvider is one human OIDC verifier as GET /v1/config names it.
type OIDCProvider struct {
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}
```

(the `}` closing `Config` moves below the new field). In `internal/broker/api/identity.go`, after
`ConnectionEndsAt`:

```go
	// OIDC is the verified token's identity when the caller presented one
	// (plan 7h).
	OIDC *IdentityOIDC `json:"oidc,omitempty"`
}

// IdentityOIDC is what GET /v1/identity says of an OIDC caller's token.
type IdentityOIDC struct {
	Issuer string   `json:"issuer"`
	Sub    string   `json:"sub"`
	Sid    string   `json:"sid,omitempty"`
	AMR    []string `json:"amr,omitempty"`
	ACR    string   `json:"acr,omitempty"`
}
```

In `internal/broker/api/revoke.go`, replace the comment's "Sid is refused until OIDC (plan 7h)."
with "Sid, with Issuer when more than one human OIDC verifier is configured, ends one OIDC
session under revoke_others (plan 7h)." and add after `Sid`:

```go
	Issuer    string `json:"issuer,omitempty"`
```

In `internal/store/store.go`, after `CertKey`:

```go
// The kinds of OIDCKey (plan 7h; spec §13 decision 39).
const (
	OIDCSid = "sid"
	OIDCSub = "sub"
)

// OIDCKey names an OIDC session (kind OIDCSid) or subject (OIDCSub) at one
// issuer: the key of an owner record, a logout record, and, through
// SidKey, the context index by sid. Each part is length-prefixed, so no
// issuer or value can forge another's key. An empty value has no key.
func OIDCKey(kind, issuer, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("%s %d:%s %d:%s", kind, len(issuer), issuer, len(value), value)
}

// SidKey is the issuer-qualified sid a login context is indexed by
// (Credential.Sid): one issuer's logout never reaches a session another
// issuer authorized.
func SidKey(issuer, sid string) string { return OIDCKey(OIDCSid, issuer, sid) }
```

(`fmt` is imported already). In `internal/broker/revoke.go`:

```go
// principalPrefixes are the forms a verifier gives a principal (spec §2):
// user: for people, app: for an OIDC machine (plan 7h). spiffe:// and
// system:serviceaccount: are refused until their verifiers exist (plans 8
// and 10), rather than marked under a key nothing spells.
var principalPrefixes = []string{"user:", "app:"}
```

and in `normalPrincipal`, replace the loop's return with:

```go
		if strings.HasPrefix(strings.ToLower(p), pre) && len(p) > len(pre) {
			if pre == "app:" {
				return pre + p[len(pre):], nil // a client id is case-sensitive
			}
			return pre + strings.ToLower(p[len(pre):]), nil
		}
```

and its error example to `(user:alice@example.com, app:port49-ci)`.

In `internal/policy/load.go`'s `identityDomain`, the refusal of a `user:` identity with no `@`
names both human verifiers now:

```go
			return "", fmt.Errorf("identity %q: a human principal is `user:<email>`, as the x509 and OIDC "+
				"verifiers give it (spec §2)", id)
```

(A test asserting the old wording, if `grep -rn "one human verifier" internal/` finds one, takes
the new.)

- [ ] **Step 4: Run them to see them pass, and the packages**

Run: `go test ./internal/decision/ ./internal/broker/... ./internal/store/ ./internal/policy/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/decision/log.go internal/decision/log_test.go internal/broker/api/ internal/store/store.go \
  internal/store/interface_test.go internal/broker/revoke.go internal/broker/revoke_test.go internal/policy/load.go
git commit -m "feat(decision,api,store): auth.oidc, revocation by sid or sub, issuer-qualified sid keys, app: principals

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: The signature: compact JWS and JWK on the standard library

**Files:**
- Create: `internal/oidc/doc.go`
- Create: `internal/oidc/jws.go`, `internal/oidc/jwk.go`
- Create: `internal/oidc/oidctest/sign.go`
- Create: `internal/oidc/testdata/rfc7515-a2.json`, `rfc7515-a3.json`, `rfc8037-a4.json`
- Create: `internal/oidc/testdata/wycheproof/` (five vector files and a `README.md` naming their
  commit) (pre-flight M-1)
- Create: `internal/oidc/export_test.go` (package `oidc`: `NewJWSForTest`, tests only)
- Test: `internal/oidc/jws_test.go`, `internal/oidc/jwk_test.go`, `internal/oidc/wycheproof_test.go`,
  `internal/oidc/fuzz_test.go` (package `oidc_test`)

**Interfaces:**
- Consumes: nothing of port49's.
- Produces:
  - `oidc.Alg` and `RS256`, `PS256`, `ES256`, `ES384`, `EdDSA`;
  - `oidc.ParseAlgs(names []string) ([]Alg, error)`: the default `[RS256]` for none given;
  - `oidc.MaxToken` (16 KiB);
  - `oidc.Header{Alg Alg; Kid, Typ string}`, `oidc.JWS{Header Header; Payload []byte}`,
    `oidc.ParseCompact(raw string) (*JWS, error)`, `(*JWS).Verify(k Key, algs []Alg) error`;
  - `oidc.Key{Kid string; Alg Alg; Pub crypto.PublicKey}`, `(Key).Fits(a Alg) bool`,
    `oidc.ParseJWKS(b []byte) (keys []Key, skipped []string, err error)`;
  - the errors `ErrMalformed`, `ErrAlgorithm`, `ErrSignature`, `ErrCrit`;
  - `oidc.MaxRSABits` (8192) beside `minRSABits` (pre-flight M-1);
  - `oidctest.Sign(t testing.TB, alg oidc.Alg, key crypto.Signer, header, claims map[string]any)
    string` and `oidctest.JWK(kid string, alg oidc.Alg, pub crypto.PublicKey) map[string]any`;
  - tests only: `oidc.NewJWSForTest(alg Alg, input, sig []byte) *JWS` (`export_test.go`), so
    an arbitrary signing input (a Wycheproof `msg`) reaches `Verify`.

- [ ] **Step 1: The RFC examples and the Wycheproof vectors as test data**

**Fetch, never transcribe** (pre-flight M-1). Take each value from the RFC's text as published,
`curl -sO https://www.rfc-editor.org/rfc/rfc7515.txt` and `…/rfc8037.txt`, and copy it from the
file with an editor, not by retyping. A transcription error shows up as a failing
`TestTheRFCExamplesVerify`. That test is never loosened to pass: re-copy the value.

Into three JSON files, each `{"jwk": {...}, "jws": "..."}`:

- `internal/oidc/testdata/rfc7515-a2.json`: RFC 7515 Appendix A.2.1. `jwk` holds the example RSA
  key's `kty`, `n` and `e` **only** (not `d`, `p`, `q`, `dp`, `dq`, `qi`: a JWK carrying private
  members is skipped, Step 3). `jws` is the complete compact serialization at the end of A.2.1.
- `internal/oidc/testdata/rfc7515-a3.json`: Appendix A.3.1. `jwk` holds `kty`, `crv`, `x`, `y`
  only (not `d`). `jws` is A.3.1's complete compact serialization.
- `internal/oidc/testdata/rfc8037-a4.json`: RFC 8037 Appendix A.2's public key (`kty`, `crv`,
  `x`) and A.4's JWS.

A line-wrapped value in the RFC is joined with no whitespace.

**Project Wycheproof** (pre-flight M-1), the industry check for exactly the key-type and encoding
bugs an in-house verifier could have (OR-1). Five JSON files, no module, from
`https://github.com/C2SP/wycheproof` at one commit, its `testvectors_v1/` directory, into
`internal/oidc/testdata/wycheproof/`:

- `ecdsa_secp256r1_sha256_p1363_test.json` (ES256's `r‖s` form);
- `ecdsa_secp384r1_sha384_p1363_test.json` (ES384's);
- `rsa_signature_2048_sha256_test.json` (RS256, PKCS #1 v1.5);
- `rsa_pss_2048_sha256_mgf1_32_test.json` (PS256: a 32-byte salt is `SaltLengthEqualsHash`);
- `ed25519_test.json` (EdDSA).

```bash
rev=$(git ls-remote https://github.com/C2SP/wycheproof HEAD | cut -f1)
for f in ecdsa_secp256r1_sha256_p1363_test ecdsa_secp384r1_sha384_p1363_test \
  rsa_signature_2048_sha256_test rsa_pss_2048_sha256_mgf1_32_test ed25519_test; do
  curl -fsS -o internal/oidc/testdata/wycheproof/$f.json \
    https://raw.githubusercontent.com/C2SP/wycheproof/$rev/testvectors_v1/$f.json
done
```

`internal/oidc/testdata/wycheproof/README.md` names the source, the commit (`$rev`), the five
files, and the licence (Apache-2.0, as port49's). A refresh is a new commit of the five with the
README's commit updated.

- [ ] **Step 2: Write the failing tests**

`internal/oidc/jws_test.go`:

```go
package oidc_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// rfcExample is one RFC example: its public key as a JWK and its JWS.
func rfcExample(t *testing.T, file string) (oidc.Key, string) {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + file)
	if err != nil {
		t.Fatal(err)
	}
	var ex struct {
		JWK json.RawMessage `json:"jwk"`
		JWS string          `json:"jws"`
	}
	if err := json.Unmarshal(raw, &ex); err != nil {
		t.Fatal(err)
	}
	keys, skipped, err := oidc.ParseJWKS([]byte(`{"keys":[` + string(ex.JWK) + `]}`))
	if err != nil || len(keys) != 1 {
		t.Fatalf("%s: %d keys, skipped %v, %v", file, len(keys), skipped, err)
	}
	return keys[0], ex.JWS
}

// The RFCs' own examples verify, and a single changed byte does not.
func TestTheRFCExamplesVerify(t *testing.T) {
	for _, c := range []struct {
		file string
		alg  oidc.Alg
	}{{"rfc7515-a2.json", oidc.RS256}, {"rfc7515-a3.json", oidc.ES256}, {"rfc8037-a4.json", oidc.EdDSA}} {
		key, raw := rfcExample(t, c.file)
		j, err := oidc.ParseCompact(raw)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		if err := j.Verify(key, []oidc.Alg{c.alg}); err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		parts := strings.Split(raw, ".")
		sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sig[len(sig)/2] ^= 1
		bad, _ := oidc.ParseCompact(parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig))
		if err := bad.Verify(key, []oidc.Alg{c.alg}); !errors.Is(err, oidc.ErrSignature) {
			t.Fatalf("%s: a changed signature verifies: %v", c.file, err)
		}
	}
}

// Each of the five algorithms verifies a token its key signed, and refuses
// one signed by another key of the same type.
func TestEachAlgorithmVerifiesItsOwn(t *testing.T) {
	for _, alg := range []oidc.Alg{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA} {
		k1, k2 := oidctest.NewKey(t, alg), oidctest.NewKey(t, alg)
		raw := oidctest.Sign(t, alg, k1, map[string]any{"kid": "k1"}, map[string]any{"sub": "x"})
		j, err := oidc.ParseCompact(raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := j.Verify(oidc.Key{Kid: "k1", Pub: k1.Public()}, []oidc.Alg{alg}); err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if err := j.Verify(oidc.Key{Kid: "k1", Pub: k2.Public()}, []oidc.Alg{alg}); !errors.Is(err, oidc.ErrSignature) {
			t.Fatalf("%s: another key's verifies: %v", alg, err)
		}
	}
}

// Review Focus 1: none and an HMAC are refused before any key is used,
// including the classic confusion, an HS256 whose secret is the provider's
// RSA public key.
func TestNoneAndHMACAreRefusedBeforeAnyKey(t *testing.T) {
	rsaKey := oidctest.NewKey(t, oidc.RS256)
	pub := rsaKey.Public()
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	unsigned := enc(map[string]any{"alg": "none"}) + "." + enc(map[string]any{"sub": "x"}) + "."
	if _, err := oidc.ParseCompact(unsigned); !errors.Is(err, oidc.ErrMalformed) {
		t.Fatalf("an unsigned token parses: %v", err)
	}
	der, _ := x509.MarshalPKIXPublicKey(pub)
	input := enc(map[string]any{"alg": "HS256"}) + "." + enc(map[string]any{"sub": "x"})
	mac := hmac.New(sha256.New, der)
	mac.Write([]byte(input))
	confused := input + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	j, err := oidc.ParseCompact(confused)
	if err != nil {
		t.Fatal(err)
	}
	for _, algs := range [][]oidc.Alg{{oidc.RS256}, {oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}} {
		if err := j.Verify(oidc.Key{Pub: pub}, algs); !errors.Is(err, oidc.ErrAlgorithm) {
			t.Fatalf("an HS256 token under %v: %v", algs, err)
		}
	}
	for _, name := range []string{"none", "None", "HS256", "HS384", "HS512", "hs256", "RS1", "ES512"} {
		if _, err := oidc.ParseAlgs([]string{name}); err == nil {
			t.Fatalf("ParseAlgs accepted %s", name)
		}
	}
	if got, err := oidc.ParseAlgs(nil); err != nil || len(got) != 1 || got[0] != oidc.RS256 {
		t.Fatalf("the default is %v, %v", got, err)
	}
}

// A JWS whose header names its own key (jwk, jku, x5u, x5c) is verified only
// against the key the caller passes: the header names nothing that is used.
func TestAHeaderNamedKeyIsNeverUsed(t *testing.T) {
	real, attacker := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.RS256)
	raw := oidctest.Sign(t, oidc.RS256, attacker, map[string]any{
		"jwk": oidctest.JWK("a", oidc.RS256, attacker.Public()), "jku": "https://attacker.example/jwks",
		"x5u": "https://attacker.example/c.pem", "x5c": []string{"MIIB"}}, map[string]any{"sub": "x"})
	j, err := oidc.ParseCompact(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Verify(oidc.Key{Pub: real.Public()}, []oidc.Alg{oidc.RS256}); !errors.Is(err, oidc.ErrSignature) {
		t.Fatalf("the header's own key was used: %v", err)
	}
}

func TestACritHeaderIsRefused(t *testing.T) {
	k := oidctest.NewKey(t, oidc.ES256)
	raw := oidctest.Sign(t, oidc.ES256, k, map[string]any{"crit": []string{"exp"}, "exp": 1}, map[string]any{"sub": "x"})
	if _, err := oidc.ParseCompact(raw); !errors.Is(err, oidc.ErrCrit) {
		t.Fatalf("a crit header: %v", err)
	}
}

func TestAnEncryptedOrMalformedTokenIsRefused(t *testing.T) {
	k := oidctest.NewKey(t, oidc.ES256)
	good := oidctest.Sign(t, oidc.ES256, k, nil, map[string]any{"sub": "x"})
	parts := strings.Split(good, ".")
	for name, raw := range map[string]string{
		"five parts (JWE)":  "a.b.c.d.e",
		"two parts":         parts[0] + "." + parts[1],
		"padded":            parts[0] + "=." + parts[1] + "." + parts[2],
		"standard alphabet": strings.ReplaceAll(parts[0], "-", "+") + "+." + parts[1] + "." + parts[2],
		"header not object": base64.RawURLEncoding.EncodeToString([]byte(`["RS256"]`)) + "." + parts[1] + "." + parts[2],
		"no alg":            base64.RawURLEncoding.EncodeToString([]byte(`{"kid":"k"}`)) + "." + parts[1] + "." + parts[2],
		"oversized":         strings.Repeat("a", oidc.MaxToken+1),
		"empty signature":   parts[0] + "." + parts[1] + ".",
	} {
		if _, err := oidc.ParseCompact(raw); !errors.Is(err, oidc.ErrMalformed) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// The algorithm, the key's type, and a JWK's own alg must agree.
func TestAlgorithmAndKeyMustAgree(t *testing.T) {
	rsaKey, p256, p384 := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.ES256), oidctest.NewKey(t, oidc.ES384)
	es256 := oidctest.Sign(t, oidc.ES256, p256, nil, map[string]any{"sub": "x"})
	j, _ := oidc.ParseCompact(es256)
	for name, k := range map[string]oidc.Key{
		"an RSA key for ES256":     {Pub: rsaKey.Public()},
		"a P-384 key for ES256":    {Pub: p384.Public()},
		"a JWK whose alg is ES384": {Alg: oidc.ES384, Pub: p256.Public()},
	} {
		if err := j.Verify(k, []oidc.Alg{oidc.ES256, oidc.ES384}); !errors.Is(err, oidc.ErrAlgorithm) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := j.Verify(oidc.Key{Pub: p256.Public()}, []oidc.Alg{oidc.RS256}); !errors.Is(err, oidc.ErrAlgorithm) {
		t.Errorf("an algorithm the verifier does not pin: %v", err)
	}
}

// Every algorithm against every key type (pre-flight M-1): only the five
// pairs Ruling 3 names fit, a token verifies only under its own pair, and
// every other pair is ErrAlgorithm before any cryptography runs. A key of a
// type no algorithm takes (P-521) fits nothing.
func TestTheAlgorithmKeyTypeMatrix(t *testing.T) {
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]crypto.Signer{
		"RSA": oidctest.NewKey(t, oidc.RS256), "P-256": oidctest.NewKey(t, oidc.ES256),
		"P-384": oidctest.NewKey(t, oidc.ES384), "Ed25519": oidctest.NewKey(t, oidc.EdDSA), "P-521": p521,
	}
	fits := map[oidc.Alg]string{oidc.RS256: "RSA", oidc.PS256: "RSA", oidc.ES256: "P-256",
		oidc.ES384: "P-384", oidc.EdDSA: "Ed25519"}
	all := []oidc.Alg{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}
	pairs := 0
	for _, alg := range all {
		j, err := oidc.ParseCompact(oidctest.Sign(t, alg, keys[fits[alg]], nil, map[string]any{"sub": "x"}))
		if err != nil {
			t.Fatal(err)
		}
		for name, k := range keys {
			key := oidc.Key{Pub: k.Public()}
			own := name == fits[alg]
			if key.Fits(alg) != own {
				t.Errorf("%s with a %s key: Fits is %v", alg, name, !own)
			}
			err := j.Verify(key, all)
			switch {
			case own && err != nil:
				t.Errorf("%s under its own %s key: %v", alg, name, err)
			case !own && !errors.Is(err, oidc.ErrAlgorithm):
				t.Errorf("%s under a %s key: %v, not ErrAlgorithm", alg, name, err)
			}
			if own {
				pairs++
			}
		}
	}
	if pairs != 5 {
		t.Fatalf("%d pairs fit, not 5", pairs)
	}
	// One RSA key, two algorithms: a JWK that declares the other is refused.
	rs, _ := oidc.ParseCompact(oidctest.Sign(t, oidc.RS256, keys["RSA"], nil, map[string]any{"sub": "x"}))
	if err := rs.Verify(oidc.Key{Alg: oidc.PS256, Pub: keys["RSA"].Public()}, all); !errors.Is(err, oidc.ErrAlgorithm) {
		t.Fatalf("an RS256 token under a JWK declaring PS256: %v", err)
	}
}

// String formats nothing a token carries: until Verify returns nil its alg
// is attacker text, up to MaxToken of it (Ruling 18; pre-flight M-1).
func TestAJWSStringSaysNothingItCarries(t *testing.T) {
	enc := func(v any) string { b, _ := json.Marshal(v); return base64.RawURLEncoding.EncodeToString(b) }
	j, err := oidc.ParseCompact(enc(map[string]any{"alg": "RS256\nport49-broker: forged"}) + "." +
		enc(map[string]any{"sub": "x"}) + ".c2ln")
	if err != nil {
		t.Fatal(err)
	}
	if s := j.String(); strings.Contains(s, "forged") || strings.Contains(s, "RS256") {
		t.Fatalf("String says the unverified alg: %q", s)
	}
}
```

(`jws_test.go` imports `crypto`, `crypto/ecdsa`, `crypto/elliptic` and `crypto/rand` beside the
list above.)

`internal/oidc/wycheproof_test.go`:

```go
package oidc_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// wycheFile is Wycheproof's testvectors_v1 schema, as far as these five
// files use it.
type wycheFile struct {
	NumberOfTests int `json:"numberOfTests"`
	TestGroups    []struct {
		PublicKey struct {
			Modulus        string `json:"modulus"`        // RSA, hex
			PublicExponent string `json:"publicExponent"` // RSA, hex
		} `json:"publicKey"`
		PublicKeyDer string `json:"publicKeyDer"` // EC and Ed25519: a hex SubjectPublicKeyInfo
		Tests        []struct {
			TcID    int      `json:"tcId"`
			Comment string   `json:"comment"`
			Msg     string   `json:"msg"`
			Sig     string   `json:"sig"`
			Result  string   `json:"result"`
			Flags   []string `json:"flags"`
		} `json:"tests"`
	} `json:"testGroups"`
}

// wycheKey is a group's public key, taken through the JWK path a provider's
// key takes, so ParseJWKS's checks run on it too.
func wycheKey(t *testing.T, alg oidc.Alg, modulus, exponent, der string) oidc.Key {
	t.Helper()
	var pub crypto.PublicKey
	if alg == oidc.RS256 || alg == oidc.PS256 {
		n, err1 := hex.DecodeString(modulus)
		e, err2 := hex.DecodeString(exponent)
		if errors.Join(err1, err2) != nil || len(n) == 0 || len(e) == 0 {
			t.Fatal("a group with no RSA key: the schema differs from wycheFile; fix the reader")
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	} else {
		b, err := hex.DecodeString(der)
		if err == nil {
			pub, err = x509.ParsePKIXPublicKey(b)
		}
		if err != nil || len(b) == 0 {
			t.Fatalf("a group with no key (%v): the schema differs from wycheFile; fix the reader", err)
		}
	}
	keys, skipped, err := oidc.ParseJWKS(jwks(t, oidctest.JWK("w", "", pub)))
	if err != nil || len(keys) != 1 {
		t.Fatalf("the group's key is not a JWKS key: %v, skipped %v", err, skipped)
	}
	return keys[0]
}

// Project Wycheproof's vectors for the five algorithms (pre-flight M-1; OR-1):
// every valid signature verifies, and no invalid one does. "acceptable" is
// Wycheproof's word for a case either answer is safe for. Every vector in
// the file runs: a count that differs is a schema change to fix in
// wycheFile, never a vector to skip.
func TestWycheproof(t *testing.T) {
	for _, c := range []struct {
		file string
		alg  oidc.Alg
	}{
		{"ecdsa_secp256r1_sha256_p1363_test.json", oidc.ES256},
		{"ecdsa_secp384r1_sha384_p1363_test.json", oidc.ES384},
		{"rsa_signature_2048_sha256_test.json", oidc.RS256},
		{"rsa_pss_2048_sha256_mgf1_32_test.json", oidc.PS256},
		{"ed25519_test.json", oidc.EdDSA},
	} {
		t.Run(c.file, func(t *testing.T) {
			raw, err := os.ReadFile("testdata/wycheproof/" + c.file)
			if err != nil {
				t.Fatal(err)
			}
			var f wycheFile
			if err := json.Unmarshal(raw, &f); err != nil {
				t.Fatal(err)
			}
			ran := 0
			for _, g := range f.TestGroups {
				key := wycheKey(t, c.alg, g.PublicKey.Modulus, g.PublicKey.PublicExponent, g.PublicKeyDer)
				for _, tc := range g.Tests {
					msg, err1 := hex.DecodeString(tc.Msg)
					sig, err2 := hex.DecodeString(tc.Sig)
					if errors.Join(err1, err2) != nil {
						t.Fatalf("tc %d: %v", tc.TcID, errors.Join(err1, err2))
					}
					err := oidc.NewJWSForTest(c.alg, msg, sig).Verify(key, []oidc.Alg{c.alg})
					switch tc.Result {
					case "valid":
						if err != nil {
							t.Errorf("tc %d (%s): a valid signature is refused: %v", tc.TcID, tc.Comment, err)
						}
					case "invalid":
						if err == nil {
							t.Errorf("tc %d (%s; %v): an invalid signature verifies", tc.TcID, tc.Comment, tc.Flags)
						}
					case "acceptable":
					default:
						t.Fatalf("tc %d: result %q", tc.TcID, tc.Result)
					}
					ran++
				}
			}
			if ran == 0 || ran != f.NumberOfTests {
				t.Fatalf("ran %d of %d vectors: fix wycheFile, never skip a vector", ran, f.NumberOfTests)
			}
		})
	}
}
```

`internal/oidc/fuzz_test.go`:

```go
package oidc_test

import (
	"crypto"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// No input panics ParseCompact or Verify, and a JWS that parses came from
// exactly three parts within MaxToken (pre-flight M-1).
func FuzzParseCompact(f *testing.F) {
	signers := map[oidc.Alg]crypto.Signer{oidc.RS256: oidctest.NewKey(f, oidc.RS256),
		oidc.ES256: oidctest.NewKey(f, oidc.ES256), oidc.EdDSA: oidctest.NewKey(f, oidc.EdDSA)}
	var keys []oidc.Key
	for alg, s := range signers {
		f.Add(oidctest.Sign(f, alg, s, map[string]any{"kid": "k"}, map[string]any{"sub": "x"}))
		keys = append(keys, oidc.Key{Pub: s.Public()})
	}
	for _, seed := range []string{"", "a.b.c", "a.b.c.d.e", "...", "eyJhbGciOiJub25lIn0.e30."} {
		f.Add(seed)
	}
	all := []oidc.Alg{oidc.RS256, oidc.PS256, oidc.ES256, oidc.ES384, oidc.EdDSA}
	f.Fuzz(func(t *testing.T, raw string) {
		j, err := oidc.ParseCompact(raw)
		if err != nil {
			if j != nil {
				t.Fatal("an error and a JWS")
			}
			return
		}
		if j == nil || len(raw) > oidc.MaxToken || strings.Count(raw, ".") != 2 || j.Header.Alg == "" {
			t.Fatalf("parsed %d bytes, %d dots, alg %q", len(raw), strings.Count(raw, "."), j.Header.Alg)
		}
		for _, k := range keys {
			_ = j.Verify(k, all)
		}
	})
}

// No body panics ParseJWKS, and every key it keeps fits its own alg.
func FuzzParseJWKS(f *testing.F) {
	for _, seed := range []string{`{"keys":[]}`, `{"keys":[{"kty":"RSA","n":"","e":"AQAB"}]}`,
		`{"keys":[{"kty":"EC","crv":"P-256","x":"","y":""}]}`, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":""}]}`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		keys, _, err := oidc.ParseJWKS(b)
		if err != nil && keys != nil {
			t.Fatal("an error and keys")
		}
		for _, k := range keys {
			if k.Pub == nil || (k.Alg != "" && !k.Fits(k.Alg)) {
				t.Fatalf("kept %+v", k)
			}
		}
	})
}
```

`internal/oidc/jwk_test.go`:

```go
package oidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

func jwks(t *testing.T, keys ...map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestJWKSParsesTheThreeKinds(t *testing.T) {
	r, e, o := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.ES384), oidctest.NewKey(t, oidc.EdDSA)
	keys, skipped, err := oidc.ParseJWKS(jwks(t, oidctest.JWK("r", oidc.RS256, r.Public()),
		oidctest.JWK("e", "", e.Public()), oidctest.JWK("o", oidc.EdDSA, o.Public())))
	if err != nil || len(skipped) != 0 || len(keys) != 3 {
		t.Fatalf("%d keys, skipped %v, %v", len(keys), skipped, err)
	}
	if keys[0].Kid != "r" || keys[0].Alg != oidc.RS256 || !keys[0].Fits(oidc.RS256) || !keys[0].Fits(oidc.PS256) {
		t.Fatalf("the RSA key: %+v", keys[0])
	}
	if keys[1].Alg != "" || !keys[1].Fits(oidc.ES384) || keys[1].Fits(oidc.ES256) {
		t.Fatalf("the P-384 key: %+v", keys[1])
	}
	if !keys[2].Fits(oidc.EdDSA) {
		t.Fatalf("the Ed25519 key: %+v", keys[2])
	}
}

// Every key that cannot be a verification key under Ruling 3 is skipped with
// a reason, and the rest of the set stands.
func TestJWKSSkipsWhatIsNotAVerificationKey(t *testing.T) {
	good := oidctest.NewKey(t, oidc.ES256)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	withUse := func(m map[string]any, k string, v any) map[string]any { m[k] = v; return m }
	off := oidctest.JWK("off", "", other.Public())
	off["y"] = off["x"] // a point not on the curve
	keys, skipped, err := oidc.ParseJWKS(jwks(t,
		oidctest.JWK("good", oidc.ES256, good.Public()),
		withUse(oidctest.JWK("enc", "", other.Public()), "use", "enc"),
		withUse(oidctest.JWK("ops", "", other.Public()), "key_ops", []string{"encrypt"}),
		oidctest.JWK("small", "", &small.PublicKey),
		map[string]any{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"},
		withUse(oidctest.JWK("priv", "", other.Public()), "d", "AAAA"),
		map[string]any{"kty": "XYZ", "kid": "odd"},
		withUse(oidctest.JWK("hs", "", other.Public()), "alg", "HS256"),
		off,
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Kid != "good" {
		t.Fatalf("kept %+v", keys)
	}
	joined := strings.Join(skipped, "\n")
	for _, want := range []string{`"enc": use enc`, `"ops": key_ops`, `"small": RSA key of 1024 bits`,
		`"hmac": kty oct`, `"priv": carries private key material`, `"odd": kty XYZ`, `"hs": alg HS256`,
		`"off": not a point`} {
		if !strings.Contains(joined, want) {
			t.Errorf("no skip reason %q in:\n%s", want, joined)
		}
	}
}

func TestJWKSThatIsNotASetIsAnError(t *testing.T) {
	for _, body := range []string{`[]`, `{"keys": {}}`, `{}`, `not json`} {
		if _, _, err := oidc.ParseJWKS([]byte(body)); err == nil {
			t.Errorf("%s parsed", body)
		}
	}
}

// An RSA modulus over MaxRSABits is skipped: a provider-published 16384-bit
// key would make every verification under it expensive (pre-flight M-1).
func TestJWKSSkipsAnOversizedRSAKey(t *testing.T) {
	n := make([]byte, oidc.MaxRSABits/8+1)
	n[0], n[len(n)-1] = 0x80, 1
	_, skipped, err := oidc.ParseJWKS(jwks(t, map[string]any{"kty": "RSA", "kid": "big",
		"n": base64.RawURLEncoding.EncodeToString(n), "e": "AQAB"}))
	if err != nil || len(skipped) != 1 || !strings.Contains(skipped[0], `"big": RSA key of 8200 bits, over 8192`) {
		t.Fatalf("skipped %v, %v", skipped, err)
	}
}

// A set of more than MaxKeys keys is not a set port49 uses (pre-flight M-3):
// the fetch fails, and the last good set stands (Task 4).
func TestJWKSOverMaxKeysIsAnError(t *testing.T) {
	pub := oidctest.NewKey(t, oidc.ES256).Public()
	var many []map[string]any
	for i := range oidc.MaxKeys + 1 {
		many = append(many, oidctest.JWK(fmt.Sprint(i), "", pub))
	}
	if _, _, err := oidc.ParseJWKS(jwks(t, many...)); err == nil || !strings.Contains(err.Error(), "over 100 keys") {
		t.Fatalf("%d keys: %v", len(many), err)
	}
}
```

(`jwk_test.go` imports `encoding/base64` and `fmt` beside the list above.)

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/oidc/... -count=1`
Expected: FAIL to compile: package `oidc` does not exist.

- [ ] **Step 4: Implement**

`internal/oidc/doc.go`:

```go
// Package oidc reads OpenID Connect tokens for the broker (plan 7h; spec §13
// decision 39): a compact JWS verified on the standard library's
// cryptography, keys from one issuer's JWKS refreshed and aged out, an ID
// token or a client-credentials access token turned into a principal in the
// trust domain of the one verifier that accepts it, and a back-channel
// logout token validated per OpenID Connect Back-Channel Logout 1.0.
//
// What it never does: read a group, a role or a username from a token (the
// directory gives those, design §7); follow a key a token's header names
// (jku, jwk, x5u, x5c); accept none or an HMAC; or say anything a token
// that did not verify claims, its iss and kid included, since an
// unvalidated body is never logged. The daemon never imports it: it never
// sees a token.
package oidc
```

`internal/oidc/jws.go`:

```go
package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
)

// Alg is a JWS algorithm a verifier may pin (Ruling 3).
type Alg string

const (
	RS256 Alg = "RS256"
	PS256 Alg = "PS256"
	ES256 Alg = "ES256"
	ES384 Alg = "ES384"
	EdDSA Alg = "EdDSA"
)

var known = []Alg{RS256, PS256, ES256, ES384, EdDSA}

// MaxToken bounds a token before anything reads it.
const MaxToken = 16 << 10

var (
	// ErrMalformed is a token that is not one compact JWS: the wrong number
	// of parts (five is an encrypted token), a part that is not base64url
	// without padding, a header that is not a JSON object with an alg, no
	// signature, or more than MaxToken bytes.
	ErrMalformed = errors.New("oidc: not a compact JWS")
	// ErrAlgorithm is an algorithm the verifier does not pin, or one its key
	// is not for.
	ErrAlgorithm = errors.New("oidc: an algorithm the verifier does not accept for this key")
	// ErrSignature is a signature the key does not verify.
	ErrSignature = errors.New("oidc: the signature does not verify")
	// ErrCrit is a header naming a critical extension: none is understood,
	// so none may be ignored (RFC 7515 §4.1.11).
	ErrCrit = errors.New("oidc: the header names a critical extension")
)

// ParseAlgs is a verifier's algorithms list: RS256 alone when none is
// given (OpenID Connect Core §15.1), and a refusal naming why for none,
// an HMAC, or anything not in the five.
func ParseAlgs(names []string) ([]Alg, error) {
	if len(names) == 0 {
		return []Alg{RS256}, nil
	}
	var out []Alg
	for _, n := range names {
		switch {
		case strings.EqualFold(n, "none"):
			return nil, fmt.Errorf("%s is refused: an unsigned token is anyone's (RFC 8725 §3.2)", n)
		case strings.HasPrefix(strings.ToUpper(n), "HS"):
			return nil, fmt.Errorf("%s is refused: a shared-secret signature lets anyone holding the secret "+
				"sign as the provider (RFC 8725 §3.2)", n)
		case !slices.Contains(known, Alg(n)):
			return nil, fmt.Errorf("%s: one of RS256, PS256, ES256, ES384 or EdDSA", n)
		}
		if !slices.Contains(out, Alg(n)) {
			out = append(out, Alg(n))
		}
	}
	return out, nil
}

// Header is what port49 reads of a protected header. jku, jwk, x5u and x5c
// are not fields: a key a token names for itself is never used (RFC 8725
// §3.10).
type Header struct {
	Alg Alg    `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// JWS is one compact JWS, parsed, its signature not yet verified: nothing
// in Header or Payload may be trusted or said until Verify returns nil.
type JWS struct {
	Header  Header
	Payload []byte
	input   []byte
	sig     []byte
}

// String withholds the header, the payload and the signature: until Verify
// returns nil the alg is attacker text (Ruling 18).
func (j *JWS) String() string { return fmt.Sprintf("JWS{%d payload bytes}", len(j.Payload)) }

// ParseCompact splits raw into a JWS, refusing anything that is not one
// (ErrMalformed) and a crit header (ErrCrit). It verifies nothing.
func ParseCompact(raw string) (*JWS, error) {
	if len(raw) > MaxToken {
		return nil, fmt.Errorf("%w: over %d bytes", ErrMalformed, MaxToken)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: %d parts, not 3 (an encrypted token is refused)", ErrMalformed, len(parts))
	}
	dec := base64.RawURLEncoding.Strict()
	hb, err1 := dec.DecodeString(parts[0])
	pb, err2 := dec.DecodeString(parts[1])
	sig, err3 := dec.DecodeString(parts[2])
	if errors.Join(err1, err2, err3) != nil {
		return nil, fmt.Errorf("%w: a part is not base64url without padding", ErrMalformed)
	}
	if len(sig) == 0 {
		return nil, fmt.Errorf("%w: no signature", ErrMalformed)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(hb, &fields) != nil || fields == nil {
		return nil, fmt.Errorf("%w: the header is not a JSON object", ErrMalformed)
	}
	if _, ok := fields["crit"]; ok {
		return nil, ErrCrit
	}
	var h Header
	if json.Unmarshal(hb, &h) != nil || h.Alg == "" {
		return nil, fmt.Errorf("%w: the header has no alg string", ErrMalformed)
	}
	return &JWS{Header: h, Payload: pb, input: []byte(parts[0] + "." + parts[1]), sig: sig}, nil
}

// Verify checks j's signature with k: the header's alg must be one of
// algs, k must be a key of that algorithm's type, and k's own Alg, when
// its JWK named one, must be the same.
func (j *JWS) Verify(k Key, algs []Alg) error {
	a := j.Header.Alg
	if !slices.Contains(algs, a) || !k.Fits(a) || (k.Alg != "" && k.Alg != a) {
		return ErrAlgorithm
	}
	ok := false
	switch a {
	case RS256, PS256:
		pub := k.Pub.(*rsa.PublicKey)
		sum := sha256.Sum256(j.input)
		if a == RS256 {
			ok = rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], j.sig) == nil
		} else {
			ok = rsa.VerifyPSS(pub, crypto.SHA256, sum[:], j.sig,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256}) == nil
		}
	case ES256, ES384:
		pub := k.Pub.(*ecdsa.PublicKey)
		size := (pub.Curve.Params().BitSize + 7) / 8
		if len(j.sig) != 2*size {
			return ErrSignature
		}
		r, s := new(big.Int).SetBytes(j.sig[:size]), new(big.Int).SetBytes(j.sig[size:])
		if a == ES256 {
			sum := sha256.Sum256(j.input)
			ok = ecdsa.Verify(pub, sum[:], r, s)
		} else {
			sum := sha512.Sum384(j.input)
			ok = ecdsa.Verify(pub, sum[:], r, s)
		}
	case EdDSA:
		ok = ed25519.Verify(k.Pub.(ed25519.PublicKey), j.input, j.sig)
	}
	if !ok {
		return ErrSignature
	}
	return nil
}
```

`internal/oidc/jwk.go`:

```go
package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"

	"github.com/blanketfish/port49/internal/printsafe"
)

// Key is one verification key from a JWKS. Alg is the JWK's own alg, ""
// when it named none.
type Key struct {
	Kid string
	Alg Alg
	Pub crypto.PublicKey
}

// Fits reports whether k is a key of a's type: RSA for RS256 and PS256,
// P-256 for ES256, P-384 for ES384, Ed25519 for EdDSA.
func (k Key) Fits(a Alg) bool {
	switch pub := k.Pub.(type) {
	case *rsa.PublicKey:
		return a == RS256 || a == PS256
	case *ecdsa.PublicKey:
		return (a == ES256 && pub.Curve == elliptic.P256()) || (a == ES384 && pub.Curve == elliptic.P384())
	case ed25519.PublicKey:
		return a == EdDSA
	}
	return false
}

type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Use    string   `json:"use"`
	Alg    string   `json:"alg"`
	KeyOps []string `json:"key_ops"`
	Crv    string   `json:"crv"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
	D      string   `json:"d"`
}

// minRSABits is the least RSA modulus a key may have (RFC 7518 §3.3).
// MaxRSABits is the most: a larger key makes every verification under it
// expensive, and no provider needs one.
const (
	minRSABits = 2048
	MaxRSABits = 8192
)

// MaxKeys bounds a JWKS: a provider publishes a handful, and a set of more
// is refused whole, as a failed fetch (pre-flight M-3).
const MaxKeys = 100

// ParseJWKS reads a JWK Set. A key that cannot verify a token under
// decision 39 Ruling 3 is skipped, with one line in skipped naming its
// kid and why; the rest stand. A body that is not a set, or holds more
// than MaxKeys keys, is an error.
func ParseJWKS(b []byte) (keys []Key, skipped []string, err error) {
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(b, &set) != nil || set.Keys == nil {
		return nil, nil, errors.New("oidc: the JWKS is not a JSON object with a keys array")
	}
	if len(set.Keys) > MaxKeys {
		return nil, nil, fmt.Errorf("oidc: the JWKS holds %d keys, over %d keys", len(set.Keys), MaxKeys)
	}
	for _, raw := range set.Keys {
		var j jwk
		if json.Unmarshal(raw, &j) != nil {
			skipped = append(skipped, "a key that is not a JSON object")
			continue
		}
		k, why := j.key()
		if why != "" {
			skipped = append(skipped, fmt.Sprintf("%q: %s", printsafe.Line(j.Kid, 80), why))
			continue
		}
		keys = append(keys, k)
	}
	return keys, skipped, nil
}

// key is j as a verification key, or why it is not one.
func (j jwk) key() (Key, string) {
	switch {
	case j.D != "":
		return Key{}, "carries private key material; the provider has published a signing key, and no key from it is used"
	case j.Use != "" && j.Use != "sig":
		return Key{}, "use " + printsafe.Line(j.Use, 20) + ", not sig"
	case j.KeyOps != nil && !slices.Contains(j.KeyOps, "verify"):
		return Key{}, "key_ops without verify"
	case j.Alg != "" && !slices.Contains(known, Alg(j.Alg)):
		return Key{}, "alg " + printsafe.Line(j.Alg, 20) + " is not one port49 verifies"
	}
	k := Key{Kid: j.Kid, Alg: Alg(j.Alg)}
	dec := base64.RawURLEncoding.Strict()
	switch j.Kty {
	case "RSA":
		n, err1 := dec.DecodeString(j.N)
		e, err2 := dec.DecodeString(j.E)
		if errors.Join(err1, err2) != nil || len(e) == 0 || len(e) > 4 {
			return Key{}, "an RSA key whose n or e does not decode"
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		if pub.N.BitLen() < minRSABits {
			return Key{}, fmt.Sprintf("RSA key of %d bits, under %d", pub.N.BitLen(), minRSABits)
		}
		if pub.N.BitLen() > MaxRSABits {
			return Key{}, fmt.Sprintf("RSA key of %d bits, over %d", pub.N.BitLen(), MaxRSABits)
		}
		if pub.E < 3 || pub.E%2 == 0 {
			return Key{}, "an RSA exponent that is not odd and at least 3"
		}
		k.Pub = pub
	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		default:
			return Key{}, "crv " + printsafe.Line(j.Crv, 20) + ", not P-256 or P-384"
		}
		x, err1 := dec.DecodeString(j.X)
		y, err2 := dec.DecodeString(j.Y)
		size := (curve.Params().BitSize + 7) / 8
		if errors.Join(err1, err2) != nil || len(x) != size || len(y) != size {
			return Key{}, "an EC key whose x or y does not decode to its curve's size"
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, x...), y...))
		if err != nil {
			return Key{}, "not a point on " + j.Crv
		}
		k.Pub = pub
	case "OKP":
		x, err := dec.DecodeString(j.X)
		if j.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return Key{}, "an OKP key that is not an Ed25519 public key"
		}
		k.Pub = ed25519.PublicKey(x)
	default:
		return Key{}, "kty " + printsafe.Line(j.Kty, 20) + "; a shared secret is never a verification key"
	}
	if k.Alg != "" && !k.Fits(k.Alg) {
		return Key{}, "alg " + string(k.Alg) + " is not for this key's type"
	}
	return k, ""
}
```

`kty oct` and an unknown `kty` share the default branch: its text reads `kty oct; a shared
secret …` and `kty XYZ; a shared secret …`, which the skip test's `"hmac": kty oct` and `"odd":
kty XYZ` both match.

`internal/oidc/oidctest/sign.go`:

```go
// Package oidctest is an OpenID provider for tests: keys, signed tokens,
// and (Issuer, plan 7h Task 4) a TLS server publishing discovery and a
// JWKS. Never for production.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
)

// NewKey is a fresh key for alg: RSA 2048, P-256, P-384 or Ed25519.
func NewKey(t testing.TB, alg oidc.Alg) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	switch alg {
	case oidc.RS256, oidc.PS256:
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case oidc.ES256:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case oidc.ES384:
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case oidc.EdDSA:
		_, k, err = ed25519.GenerateKey(rand.Reader)
	default:
		t.Fatalf("oidctest: no key for %s", alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Sign is a compact JWS of claims under header (alg is set from alg),
// signed by key as alg says.
func Sign(t testing.TB, alg oidc.Alg, key crypto.Signer, header, claims map[string]any) string {
	t.Helper()
	h := map[string]any{"alg": string(alg)}
	for k, v := range header {
		h[k] = v
	}
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(h) + "." + enc(claims)
	var sig []byte
	var err error
	switch alg {
	case oidc.RS256:
		sum := sha256.Sum256([]byte(input))
		sig, err = key.Sign(rand.Reader, sum[:], crypto.SHA256)
	case oidc.PS256:
		sum := sha256.Sum256([]byte(input))
		sig, err = key.Sign(rand.Reader, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	case oidc.ES256, oidc.ES384:
		var digest []byte
		if alg == oidc.ES256 {
			s := sha256.Sum256([]byte(input))
			digest = s[:]
		} else {
			s := sha512.Sum384([]byte(input))
			digest = s[:]
		}
		priv := key.(*ecdsa.PrivateKey)
		r, s, e := ecdsa.Sign(rand.Reader, priv, digest)
		size := (priv.Curve.Params().BitSize + 7) / 8
		sig, err = append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...), e
	case oidc.EdDSA:
		sig, err = key.Sign(rand.Reader, []byte(input), crypto.Hash(0))
	}
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// JWK is pub as a JWK, with kid, and alg when not "".
func JWK(kid string, alg oidc.Alg, pub crypto.PublicKey) map[string]any {
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	m := map[string]any{"kid": kid, "use": "sig"}
	if alg != "" {
		m["alg"] = string(alg)
	}
	switch p := pub.(type) {
	case *rsa.PublicKey:
		m["kty"], m["n"], m["e"] = "RSA", b64(p.N.Bytes()), b64(big.NewInt(int64(p.E)).Bytes())
	case *ecdsa.PublicKey:
		size := (p.Curve.Params().BitSize + 7) / 8
		point, _ := p.Bytes() // 0x04 || X || Y
		m["kty"], m["crv"] = "EC", p.Curve.Params().Name
		m["x"], m["y"] = b64(point[1:1+size]), b64(point[1+size:])
	case ed25519.PublicKey:
		m["kty"], m["crv"], m["x"] = "OKP", "Ed25519", b64(p)
	}
	return m
}
```

`internal/oidc/export_test.go`:

```go
package oidc

// NewJWSForTest is a JWS over an arbitrary signing input, so a test vector
// whose message is not a compact JWS's header.payload (Wycheproof's) reaches
// Verify. It is compiled into tests alone.
func NewJWSForTest(alg Alg, input, sig []byte) *JWS {
	return &JWS{Header: Header{Alg: alg}, input: input, sig: sig}
}
```

- [ ] **Step 5: Run the tests to see them pass, and fuzz**

Run: `go test ./internal/oidc/... -count=1 -v -run 'TestTheRFCExamplesVerify|TestEachAlgorithm|TestNoneAndHMAC|TestAHeaderNamedKey|TestACritHeader|TestAnEncryptedOrMalformed|TestAlgorithmAndKey|TestTheAlgorithmKeyTypeMatrix|TestAJWSString|TestJWKS|TestWycheproof'`
Expected: PASS, every Wycheproof file reporting its full vector count. A Wycheproof vector that
fails is a bug in `jws.go` or `jwk.go`, never a vector to skip: stop and report it.

Run: `go test ./internal/oidc/ -run '^$' -fuzz=FuzzParseCompact -fuzztime=60s` and
`go test ./internal/oidc/ -run '^$' -fuzz=FuzzParseJWKS -fuzztime=60s`
Expected: no failure. A crasher lands in `testdata/fuzz/` and is committed with the fix as a
regression seed. Then `go vet ./internal/oidc/...`: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/oidc/
git commit -m "feat(oidc): compact JWS and JWK on the standard library, five pinned algorithms, no header-named keys

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: One issuer's keys: discovery, the JWKS, refresh, persistence, aging out

**Files:**
- Create: `internal/oidc/keyset.go`
- Create: `internal/oidc/oidctest/issuer.go`
- Modify: `internal/daemon/metrics/metrics.go`
- Test: `internal/oidc/keyset_test.go` (package `oidc_test`)

**Interfaces:**
- Consumes: Task 3's `Key`, `Alg`, `ParseJWKS`, `oidctest.NewKey`, `oidctest.Sign`, `oidctest.JWK`.
- Produces:
  - `oidc.KeySetConfig{Issuer string; Client *http.Client; Refresh, MaxAge time.Duration; Now
    func() time.Time; Save func([]byte) error; Load func() ([]byte, error); Say func(string,
    ...any); M *metrics.Metrics}`;
  - `oidc.NewClient(roots *x509.CertPool) *http.Client`: no redirect, 10s, TLS 1.2+, `nil` roots
    the system's, the environment's proxy (pre-flight I-5);
  - `oidc.ProxyFor(issuer string) (*url.URL, error)` and `oidc.DescribeProxy(u *url.URL)
    string` (the start line's words, a password redacted);
  - `oidc.KeyFileName(issuer string) string`: `oidc-<sha256(issuer)[:8] hex>.json`, which Task 7's
    collision lists and Task 14's `keyFile` both use (pre-flight M-11);
  - `oidc.NewKeySet(c KeySetConfig) *KeySet`: the last-success gauge set to 0 for the issuer
    at once (pre-flight I-4);
  - `(*KeySet).Restore() (n int, fetched time.Time, err error)`, `Fetch(ctx) error`, `Key(ctx,
    kid string, alg Alg) (Key, error)`, `Run(ctx)`, `Status() (keys []Key, fetched time.Time,
    lastErr error)`, `Issuer() string`;
  - `oidc.ErrUnavailable` (no usable set: 503) and `oidc.ErrUnknownKey` (401);
  - `oidc.NextWait(ok bool, prev time.Duration) time.Duration` (the refresh loop's wait);
  - `oidc.RefetchEvery` (1m);
  - `metrics.OIDCKeysLastSuccess *prometheus.GaugeVec{issuer}`,
    `metrics.OIDCKeysFetchFailures *prometheus.CounterVec{issuer}`;
  - `oidctest.Issuer`: `NewIssuer(t)`, `URL`, `Roots()`, `AddKey(t, kid, alg)`,
    `Unpublish(kid)`, `Fail(status int)`, `ServeJWKS(raw []byte)`, `Discovery(func(map[string]any))`,
    `Hold() (arrived <-chan struct{}, release func())`, `JWKSFetches() int64`, `Token(t, kid string, claims map[string]any) string`, `TokenWith(t, kid string,
    header, claims map[string]any) string`, `IDToken(t, kid, clientID, sub string, now
    time.Time, extra map[string]any) string`, `Close()`.

- [ ] **Step 1: The metrics**

In `internal/daemon/metrics/metrics.go`, beside the directory metrics:

```go
	// port49_oidc_keys_last_success_timestamp_seconds{issuer}: the Unix
	// time the keys held were fetched: 0 from the key set's creation until
	// a fetch or a restore, and after a restore the kept set's fetched_at,
	// so a restart during an outage keeps the alert firing (plan 7h,
	// pre-flight I-4). Alert on time() - it > jwks_max_age / 2 or absent(it),
	// with a for: of a few minutes to pass a start's first fetch.
	OIDCKeysLastSuccess *prometheus.GaugeVec
	// port49_oidc_keys_fetch_failures_total{issuer}: discovery or JWKS
	// fetches that failed.
	OIDCKeysFetchFailures *prometheus.CounterVec
```

and in `New`, registered with the rest:

```go
		OIDCKeysLastSuccess: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "port49_oidc_keys_last_success_timestamp_seconds",
			Help: "Unix time the OIDC issuer's held keys were fetched (restored included), 0 before any."}, []string{"issuer"}),
		OIDCKeysFetchFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "port49_oidc_keys_fetch_failures_total",
			Help: "OIDC discovery or JWKS fetches that failed, by configured issuer."}, []string{"issuer"}),
```

(`New`'s registration list gains both, as each directory metric is registered.)

- [ ] **Step 2: The test provider**

`internal/oidc/oidctest/issuer.go`:

```go
package oidctest

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/oidc"
)

// Issuer is an OpenID provider on an httptest TLS server: discovery at
// /.well-known/openid-configuration, a JWKS at /jwks, and tokens signed by
// the keys it holds. Its URL is its issuer.
type Issuer struct {
	URL string

	srv       *httptest.Server
	mu        sync.Mutex
	keys      map[string]held
	published map[string]bool
	status    int
	discovery func(map[string]any)
	raw       []byte
	gate      chan struct{} // non-nil: /jwks waits for it to close (Hold)
	arrive    func()
	fetches   atomic.Int64
}

type held struct {
	alg oidc.Alg
	key crypto.Signer
}

// NewIssuer starts a provider publishing one RS256 key, kid "k1".
func NewIssuer(t testing.TB) *Issuer {
	t.Helper()
	i := &Issuer{keys: map[string]held{}, published: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		i.mu.Lock()
		status, hook := i.status, i.discovery
		i.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
			return
		}
		doc := map[string]any{"issuer": i.URL, "jwks_uri": i.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"}}
		if hook != nil {
			hook(doc)
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		i.fetches.Add(1)
		i.mu.Lock()
		gate, arrive := i.gate, i.arrive
		i.mu.Unlock()
		if gate != nil {
			arrive()
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		i.mu.Lock()
		defer i.mu.Unlock()
		if i.status != 0 {
			w.WriteHeader(i.status)
			return
		}
		if i.raw != nil {
			_, _ = w.Write(i.raw)
			return
		}
		var keys []map[string]any
		for kid, h := range i.keys {
			if i.published[kid] {
				keys = append(keys, JWK(kid, h.alg, h.key.Public()))
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("GET /moved", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, i.URL+"/jwks", http.StatusFound)
	})
	i.srv = httptest.NewTLSServer(mux)
	i.URL = i.srv.URL
	i.AddKey(t, "k1", oidc.RS256)
	t.Cleanup(i.Close)
	return i
}

// Roots trusts the server's certificate.
func (i *Issuer) Roots() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(i.srv.Certificate())
	return p
}

// AddKey makes and publishes a key.
func (i *Issuer) AddKey(t testing.TB, kid string, alg oidc.Alg) {
	k := NewKey(t, alg)
	i.mu.Lock()
	defer i.mu.Unlock()
	i.keys[kid], i.published[kid] = held{alg: alg, key: k}, true
}

// Unpublish drops kid from the JWKS; the provider can still sign with it.
func (i *Issuer) Unpublish(kid string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.published, kid)
}

// Fail answers discovery and the JWKS with status; 0 answers them again.
func (i *Issuer) Fail(status int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.status = status
}

// ServeJWKS serves raw at /jwks in place of the keys; nil serves the keys.
func (i *Issuer) ServeJWKS(raw []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.raw = raw
}

// Discovery alters the discovery document before it is sent.
func (i *Issuer) Discovery(f func(map[string]any)) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.discovery = f
}

// Hold stalls every /jwks request until release is called; arrived closes
// when the first stalled request comes in. A test holds a fetch in flight.
func (i *Issuer) Hold() (arrived <-chan struct{}, release func()) {
	gate, in := make(chan struct{}), make(chan struct{})
	var once sync.Once
	i.mu.Lock()
	i.gate, i.arrive = gate, func() { once.Do(func() { close(in) }) }
	i.mu.Unlock()
	return in, func() {
		i.mu.Lock()
		i.gate, i.arrive = nil, nil
		i.mu.Unlock()
		close(gate)
	}
}

// JWKSFetches is how many times /jwks was asked.
func (i *Issuer) JWKSFetches() int64 { return i.fetches.Load() }

// Token signs claims with kid's key, the header naming kid.
func (i *Issuer) Token(t testing.TB, kid string, claims map[string]any) string {
	return i.TokenWith(t, kid, map[string]any{"kid": kid}, claims)
}

// TokenWith signs claims with kid's key under header as given.
func (i *Issuer) TokenWith(t testing.TB, kid string, header, claims map[string]any) string {
	t.Helper()
	i.mu.Lock()
	h, ok := i.keys[kid]
	i.mu.Unlock()
	if !ok {
		t.Fatalf("oidctest: no key %q", kid)
	}
	return Sign(t, h.alg, h.key, header, claims)
}

// IDToken is a human's ID token for clientID at now: iss, aud, sub, iat,
// exp (now+5m), auth_time (now), sid "s-"+sub, and extra, where a nil
// value deletes a claim.
func (i *Issuer) IDToken(t testing.TB, kid, clientID, sub string, now time.Time, extra map[string]any) string {
	c := map[string]any{"iss": i.URL, "aud": clientID, "sub": sub, "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "auth_time": now.Unix(), "sid": "s-" + sub}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return i.Token(t, kid, c)
}

// Close stops the server: the provider is unreachable.
func (i *Issuer) Close() { i.srv.Close() }
```

- [ ] **Step 3: Write the failing tests**

`internal/oidc/keyset_test.go`:

```go
package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }
func (c *clock) Set(t time.Time)     { c.mu.Lock(); c.now = t; c.mu.Unlock() }
func newClock() *clock               { return &clock{now: time.Now().Truncate(time.Second)} }

type said struct {
	mu    sync.Mutex
	lines []string
}

func (s *said) Say(format string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprintf(format, args...))
}
func (s *said) all() string { s.mu.Lock(); defer s.mu.Unlock(); return strings.Join(s.lines, "\n") }

func keySet(t *testing.T, iss *oidctest.Issuer, c *clock, s *said) *oidc.KeySet {
	t.Helper()
	return oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say,
		M: metrics.New(prometheus.NewRegistry())})
}

func TestAFetchReadsDiscoveryThenKeys(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(context.Background(), "k1", oidc.RS256); err != nil {
		t.Fatal(err)
	}
	keys, fetched, lastErr := ks.Status()
	if len(keys) != 1 || !fetched.Equal(c.Now()) || lastErr != nil {
		t.Fatalf("status: %d keys, fetched %v, %v", len(keys), fetched, lastErr)
	}
	// The jwks_uri is said at the first fetch, and not again while it stands
	// (pre-flight M-7).
	c.Add(time.Hour)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(s.all(), "keys from "+iss.URL+"/jwks"); n != 1 {
		t.Fatalf("the jwks_uri said %d times:\n%s", n, s.all())
	}
}

// The provider is reached through the environment's proxy (pre-flight I-5),
// and the start line names it without its password.
func TestTheClientUsesTheEnvironmentsProxy(t *testing.T) {
	tr, ok := oidc.NewClient(nil).Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("the provider's client ignores HTTPS_PROXY: a site whose egress is a proxy never fetches a key")
	}
	u := &url.URL{Scheme: "http", User: url.UserPassword("svc", "proxy-secret"), Host: "proxy.example.com:3128"}
	if got := oidc.DescribeProxy(u); strings.Contains(got, "proxy-secret") || !strings.Contains(got, "proxy.example.com:3128") {
		t.Fatalf("DescribeProxy(%v) = %q", u, got)
	}
	if got := oidc.DescribeProxy(nil); got != "directly (no HTTPS_PROXY)" {
		t.Fatalf("no proxy: %q", got)
	}
}

// A client that hangs up during the refetch it started does not poison it
// (pre-flight I-3): the fetch runs on, nothing stores its cancellation, and
// the next token under the rotated-in key is accepted at once, not a
// minute later.
func TestACallerHangingUpDoesNotPoisonTheRefetch(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	iss.AddKey(t, "k2", oidc.ES256)
	arrived, release := iss.Hold()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := ks.Key(ctx, "k2", oidc.ES256); done <- err }()
	<-arrived
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("the hung-up caller: %v", err)
	}
	release()
	if _, err := ks.Key(context.Background(), "k2", oidc.ES256); err != nil {
		t.Fatalf("the next token under the rotated-in key: %v", err)
	}
	if _, _, lastErr := ks.Status(); lastErr != nil {
		t.Fatalf("the caller's cancellation was stored as the issuer's: %v", lastErr)
	}
}

// The staleness gauge exists from the key set's creation and carries a
// restored set's age (pre-flight I-4): a broker restarted during an outage
// still alerts.
func TestTheLastSuccessGaugeSurvivesARestart(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	m := metrics.New(prometheus.NewRegistry())
	var saved []byte
	cfg := oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: m,
		Save: func(b []byte) error { saved = append([]byte(nil), b...); return nil }}
	ks := oidc.NewKeySet(cfg)
	if n := testutil.CollectAndCount(m.OIDCKeysLastSuccess); n != 1 {
		t.Fatalf("%d series before any fetch: absent() would be the only alert", n)
	}
	if v := testutil.ToFloat64(m.OIDCKeysLastSuccess.WithLabelValues(iss.URL)); v != 0 {
		t.Fatalf("before any fetch: %v", v)
	}
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetched := c.Now()
	iss.Fail(503)
	c.Add(10 * time.Hour)
	m2 := metrics.New(prometheus.NewRegistry())
	cfg.M, cfg.Save, cfg.Load = m2, nil, func() ([]byte, error) { return saved, nil }
	if _, _, err := oidc.NewKeySet(cfg).Restore(); err != nil {
		t.Fatal(err)
	}
	if v := testutil.ToFloat64(m2.OIDCKeysLastSuccess.WithLabelValues(iss.URL)); v != float64(fetched.Unix()) {
		t.Fatalf("after a restore: %v, want the kept set's %d", v, fetched.Unix())
	}
}

// A JWKS with nothing usable is a failed fetch (pre-flight M-2): the last
// good set stands, the good file is not overwritten, and it is counted.
func TestAJWKSWithNoUsableKeyKeepsTheLastGoodSet(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	m := metrics.New(prometheus.NewRegistry())
	saves := 0
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: m, Save: func([]byte) error { saves++; return nil }})
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`{"keys":[]}`, `{"keys":[{"kty":"oct","kid":"h","k":"c2VjcmV0"}]}`} {
		iss.ServeJWKS([]byte(body))
		c.Add(time.Hour)
		if err := ks.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "no key port49 can verify with") {
			t.Fatalf("%s: %v", body, err)
		}
		if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
			t.Fatalf("%s: the last good key: %v", body, err)
		}
	}
	if saves != 1 {
		t.Fatalf("%d saves: an unusable set was kept over the good one", saves)
	}
	if got := testutil.ToFloat64(m.OIDCKeysFetchFailures.WithLabelValues(iss.URL)); got != 2 {
		t.Fatalf("%v failures counted", got)
	}
}

// A skipped key is said when the set of skips changes, not at every fetch
// (pre-flight M-3): Keycloak publishes an RSA-OAEP enc key by default.
func TestASkipIsSaidWhenTheSkipsChange(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	good := oidctest.NewKey(t, oidc.RS256)
	encKey := func(kid string) map[string]any {
		k := oidctest.JWK(kid, "", oidctest.NewKey(t, oidc.RS256).Public())
		k["use"] = "enc"
		return k
	}
	serve := func(extra ...map[string]any) {
		raw, _ := json.Marshal(map[string]any{"keys": append([]map[string]any{oidctest.JWK("k1", oidc.RS256,
			good.Public())}, extra...)})
		iss.ServeJWKS(raw)
	}
	e1, e2 := encKey("enc-1"), encKey("enc-2")
	serve(e1)
	ks := keySet(t, iss, c, s)
	for range 3 {
		if err := ks.Fetch(context.Background()); err != nil {
			t.Fatal(err)
		}
		c.Add(time.Hour)
	}
	if n := strings.Count(s.all(), "is skipped"); n != 1 {
		t.Fatalf("one unchanged skip said %d times:\n%s", n, s.all())
	}
	serve(e1, e2)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(s.all(), "is skipped"); n != 3 {
		t.Fatalf("a changed set of skips is said whole: %d lines:\n%s", n, s.all())
	}
}

// Discovery's issuer must be the configured one, its jwks_uri https, and a
// redirect is never followed (OIDC Discovery §4.3; Ruling 4).
func TestDiscoveryIsCheckedAndRedirectsAreNotFollowed(t *testing.T) {
	for name, hook := range map[string]func(map[string]any){
		"another issuer": func(d map[string]any) { d["issuer"] = "https://evil.example" },
		"plain http":     func(d map[string]any) { d["jwks_uri"] = strings.Replace(d["jwks_uri"].(string), "https", "http", 1) },
		"a redirect":     func(d map[string]any) { d["jwks_uri"] = strings.TrimSuffix(d["jwks_uri"].(string), "/jwks") + "/moved" },
	} {
		iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
		iss.Discovery(hook)
		ks := keySet(t, iss, c, s)
		if err := ks.Fetch(context.Background()); err == nil {
			t.Errorf("%s: the fetch succeeded", name)
		}
		if _, err := ks.Key(context.Background(), "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
			t.Errorf("%s: a key with no good fetch: %v", name, err)
		}
	}
}

// Review Focus 2: a new kid is fetched, once a minute at most, however many
// tokens name an unknown one.
func TestANewKidIsFetchedOnceAMinute(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	c.Add(2 * time.Minute)
	iss.AddKey(t, "k2", oidc.ES256)
	if _, err := ks.Key(ctx, "k2", oidc.ES256); err != nil {
		t.Fatalf("a rotated-in key: %v", err)
	}
	n := iss.JWKSFetches()
	for range 50 {
		if _, err := ks.Key(ctx, "forged", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
			t.Fatalf("a forged kid: %v", err)
		}
	}
	if got := iss.JWKSFetches(); got != n {
		t.Fatalf("50 forged kids within the minute fetched %d times", got-n)
	}
	c.Add(oidc.RefetchEvery)
	_, _ = ks.Key(ctx, "forged", oidc.RS256)
	if got := iss.JWKSFetches(); got != n+1 {
		t.Fatalf("a minute later: %d fetches, want 1", got-n)
	}
}

func TestADroppedKeyIsRefusedAtOnce(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	iss.AddKey(t, "k2", oidc.RS256)
	iss.Unpublish("k1")
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("a key the provider dropped: %v", err)
	}
}

// Review Focus 2: with the provider gone, the last good set serves until
// jwks_max_age, then nothing does, and the line says when.
func TestAStaleSetRefusesAfterMaxAge(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	fetched := c.Now()
	iss.Fail(503)
	c.Add(23 * time.Hour)
	if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
		t.Fatalf("at 23h with the provider failing: %v", err)
	}
	if err := ks.Fetch(ctx); err == nil {
		t.Fatal("a failing provider fetched")
	}
	if !strings.Contains(s.all(), "keys not refreshed since "+fetched.UTC().Format(time.RFC3339)) ||
		!strings.Contains(s.all(), "accepted until "+fetched.Add(24*time.Hour).UTC().Format(time.RFC3339)) {
		t.Fatalf("the stale line:\n%s", s.all())
	}
	c.Add(time.Hour + time.Second)
	if _, err := ks.Key(ctx, "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("past jwks_max_age: %v", err)
	}
	iss.Fail(0)
	c.Add(oidc.RefetchEvery)
	if _, err := ks.Key(ctx, "k1", oidc.RS256); err != nil {
		t.Fatalf("the provider back: %v", err)
	}
}

// A failed fetch is said once an hour, not at every try.
func TestAFailedFetchIsSaidOnceAnHour(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	iss.Fail(503)
	for range 10 {
		c.Add(2 * time.Minute)
		_ = ks.Fetch(context.Background())
	}
	if n := strings.Count(s.all(), "keys not refreshed since"); n != 1 {
		t.Fatalf("%d lines in 20 minutes:\n%s", n, s.all())
	}
}

// Review Focus 3: a restart restores the persisted set, which serves until
// jwks_max_age after its own fetch, never longer.
func TestARestoredSetServesUntilMaxAge(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	var saved []byte
	cfg := oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: c.Now, Say: s.Say, M: metrics.New(prometheus.NewRegistry()),
		Save: func(b []byte) error { saved = append([]byte(nil), b...); return nil }}
	if err := oidc.NewKeySet(cfg).Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	fetched := c.Now()
	iss.Fail(503)
	c.Add(20 * time.Hour)
	cfg.Save = nil
	cfg.Load = func() ([]byte, error) { return saved, nil }
	ks := oidc.NewKeySet(cfg)
	n, at, err := ks.Restore()
	if err != nil || n != 1 || !at.Equal(fetched) {
		t.Fatalf("restore: %d keys fetched %v, %v", n, at, err)
	}
	if _, err := ks.Key(context.Background(), "k1", oidc.RS256); err != nil {
		t.Fatalf("a restored key: %v", err)
	}
	c.Add(4*time.Hour + time.Second)
	if _, err := ks.Key(context.Background(), "k1", oidc.RS256); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("a restored set past jwks_max_age: %v", err)
	}
	// A file for another issuer, or from the future, restores nothing.
	other := strings.Replace(string(saved), iss.URL, "https://other.example", 1)
	cfg.Load = func() ([]byte, error) { return []byte(other), nil }
	if _, _, err := oidc.NewKeySet(cfg).Restore(); err == nil {
		t.Fatal("another issuer's file restored")
	}
	c.Set(fetched.Add(-time.Hour))
	cfg.Load = func() ([]byte, error) { return saved, nil }
	if _, _, err := oidc.NewKeySet(cfg).Restore(); err == nil {
		t.Fatal("a file fetched in the future restored")
	}
}

// A kid two keys share, or no kid with two keys of the type, names no key:
// port49 never tries every key.
func TestAKeyIsChosenByKidAlone(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	iss.AddKey(t, "k1b", oidc.RS256)
	ks := keySet(t, iss, c, s)
	ctx := context.Background()
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("no kid among two RSA keys: %v", err)
	}
	if _, err := ks.Key(ctx, "", oidc.ES256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("no kid and no key of the type: %v", err)
	}
	iss.Unpublish("k1b")
	c.Add(time.Hour)
	if err := ks.Fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(ctx, "", oidc.RS256); err != nil {
		t.Fatalf("no kid and one RSA key: %v", err)
	}
	if _, err := ks.Key(ctx, "k1", oidc.ES256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("a kid whose key is not of the algorithm's type: %v", err)
	}
}

func TestTheRefreshWaitBacksOffToFiveMinutes(t *testing.T) {
	if got := oidc.NextWait(false, 0); got != 30*time.Second {
		t.Fatalf("the first failure waits %v", got)
	}
	w := 30 * time.Second
	for range 10 {
		w = oidc.NextWait(false, w)
	}
	if w != 5*time.Minute {
		t.Fatalf("the backoff reaches %v", w)
	}
	if got := oidc.NextWait(true, w); got != 0 {
		t.Fatalf("a success resets the backoff to %v", got)
	}
}

func TestAKidNamingTwoKeysIsRefused(t *testing.T) {
	iss, c, s := oidctest.NewIssuer(t), newClock(), &said{}
	a, b := oidctest.NewKey(t, oidc.RS256), oidctest.NewKey(t, oidc.RS256)
	raw, _ := json.Marshal(map[string]any{"keys": []any{oidctest.JWK("dup", "", a.Public()),
		oidctest.JWK("dup", "", b.Public())}})
	iss.ServeJWKS(raw)
	ks := keySet(t, iss, c, s)
	if err := ks.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Key(context.Background(), "dup", oidc.RS256); !errors.Is(err, oidc.ErrUnknownKey) {
		t.Fatalf("a kid two keys share: %v", err)
	}
}
```

- [ ] **Step 4: Run them to see them fail**

Run: `go test ./internal/oidc/ -run 'TestAFetch|TestDiscovery|TestANewKid|TestADropped|TestAStale|TestAFailedFetch|TestARestored|TestAKeyIsChosen|TestAKidNaming|TestTheRefreshWait|TestTheClientUses|TestACallerHangingUp|TestTheLastSuccessGauge|TestAJWKSWithNoUsable|TestASkipIsSaid' -count=1`
Expected: FAIL to compile: `NewKeySet`, `KeySetConfig`, `NewClient`, `DescribeProxy` undefined.

- [ ] **Step 5: Implement**

`internal/oidc/keyset.go`:

```go
package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/printsafe"
)

// ErrUnavailable is an issuer whose keys cannot be used: none fetched or
// restored yet, or none refreshed within jwks_max_age (Ruling 4). The API
// answers 503 identity_provider_unavailable, to be retried.
var ErrUnavailable = errors.New("oidc: the identity provider's keys are not available")

// ErrUnknownKey is a token whose kid names no key of a set fetched within
// the last RefetchEvery, or names two, or, with no kid, a set holding other
// than one key of the algorithm's type: 401.
var ErrUnknownKey = errors.New("oidc: no one key in the provider's set matches the token")

// RefetchEvery bounds the fetches an unknown kid triggers: one per issuer
// per minute, so a flood of forged kids costs the provider one request a
// minute (Ruling 4).
const RefetchEvery = time.Minute

const (
	fetchTimeout  = 10 * time.Second
	maxBody       = 1 << 20
	sayStaleEvery = time.Hour
)

// KeySetConfig is one issuer's key set (Ruling 4).
type KeySetConfig struct {
	Issuer string
	// Client fetches discovery and the JWKS (NewClient).
	Client *http.Client
	// Refresh is jwks_refresh_interval, MaxAge jwks_max_age.
	Refresh, MaxAge time.Duration
	Now             func() time.Time
	// Save keeps a fetched set across a restart, and Load reads it back
	// (Restore); nil keeps none.
	Save func([]byte) error
	Load func() ([]byte, error)
	Say  func(format string, args ...any)
	M    *metrics.Metrics
}

// NewClient is a provider's HTTP client: TLS 1.2 or later against roots
// (nil: the system's), fetchTimeout, no redirect followed, and the
// environment's proxy (HTTPS_PROXY, NO_PROXY), which DefaultTransport's
// clone keeps: a site whose egress is a proxy would otherwise never fetch a
// key (pre-flight I-5). The targets are the configured issuer and the
// jwks_uri its own discovery names, so no request goes where configuration
// did not send it.
func NewClient(roots *x509.CertPool) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	return &http.Client{Transport: tr, Timeout: fetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// ProxyFor is the proxy NewClient's transport takes to reach issuer: the
// environment's, or nil for none.
func ProxyFor(issuer string) (*url.URL, error) {
	req, err := http.NewRequest(http.MethodGet, issuer, nil)
	if err != nil {
		return nil, err
	}
	return http.ProxyFromEnvironment(req)
}

// DescribeProxy is the start line's words for u: its URL with any password
// redacted, or directly.
func DescribeProxy(u *url.URL) string {
	if u == nil {
		return "directly (no HTTPS_PROXY)"
	}
	return "through the proxy " + u.Redacted() + " (HTTPS_PROXY)"
}

// KeyFileName is the name of the file an issuer's fetched keys are kept in,
// in the broker's state directory (Ruling 4): config checks no other file
// collides with it, and port49d writes it.
func KeyFileName(issuer string) string {
	sum := sha256.Sum256([]byte(issuer))
	return "oidc-" + hex.EncodeToString(sum[:8]) + ".json"
}

// KeySet is one issuer's verification keys.
type KeySet struct {
	c KeySetConfig

	mu        sync.Mutex
	keys      []Key
	fetched   time.Time // when keys were fetched; zero before any
	lastTry   time.Time
	lastErr   error
	saidStale time.Time
	jwksURI   string        // the last fetch's, said when it changes (pre-flight M-7)
	skipped   []string      // the last fetch's skips, said when they change (pre-flight M-3)
	flight    chan struct{} // a fetch in progress; nil when none
}

// NewKeySet holds no key until Restore or Fetch. Its issuer's last-success
// gauge exists from now, at 0, so absent() never hides an issuer that has
// no keys (pre-flight I-4).
func NewKeySet(c KeySetConfig) *KeySet {
	if c.Say == nil {
		c.Say = func(string, ...any) {}
	}
	c.M.OIDCKeysLastSuccess.WithLabelValues(c.Issuer).Set(0)
	return &KeySet{c: c}
}

// Issuer is the configured issuer.
func (s *KeySet) Issuer() string { return s.c.Issuer }

// persisted is the file Save writes.
type persisted struct {
	Issuer    string          `json:"issuer"`
	FetchedAt time.Time       `json:"fetched_at"`
	JWKS      json.RawMessage `json:"jwks"`
}

// Restore loads the persisted set, when Load gives one for this issuer
// fetched no later than now and within MaxAge (Review Focus 3).
func (s *KeySet) Restore() (int, time.Time, error) {
	if s.c.Load == nil {
		return 0, time.Time{}, nil
	}
	raw, err := s.c.Load()
	if err != nil || len(raw) == 0 {
		return 0, time.Time{}, err
	}
	var p persisted
	if json.Unmarshal(raw, &p) != nil {
		return 0, time.Time{}, errors.New("the kept key file does not decode")
	}
	now := s.c.Now()
	switch {
	case p.Issuer != s.c.Issuer:
		return 0, time.Time{}, errors.New("the kept key file is another issuer's")
	case p.FetchedAt.After(now):
		return 0, time.Time{}, errors.New("the kept key file says it was fetched in the future")
	case now.Sub(p.FetchedAt) > s.c.MaxAge:
		return 0, p.FetchedAt, fmt.Errorf("the kept keys were fetched %s, past jwks_max_age",
			p.FetchedAt.UTC().Format(time.RFC3339))
	}
	keys, _, err := ParseJWKS(p.JWKS)
	if err != nil {
		return 0, time.Time{}, err
	}
	if len(keys) == 0 {
		return 0, time.Time{}, errors.New("the kept key file holds no usable key")
	}
	s.mu.Lock()
	s.keys, s.fetched = keys, p.FetchedAt
	s.mu.Unlock()
	// The gauge carries the kept set's age, so the staleness alert keeps
	// firing for a broker restarted during an outage (pre-flight I-4).
	s.c.M.OIDCKeysLastSuccess.WithLabelValues(s.c.Issuer).Set(float64(p.FetchedAt.Unix()))
	return len(keys), p.FetchedAt, nil
}

// Fetch reads discovery and the JWKS once; a fetch in progress is waited
// for and its outcome shared. The fetch is the issuer's, not the caller's:
// it runs on a context no caller's hang-up cancels, bounded by
// fetchTimeout, and each caller waits for it under its own ctx, returning
// ctx.Err() if that ends first. A caller's cancellation is never stored as
// the issuer's last error (pre-flight I-3).
func (s *KeySet) Fetch(ctx context.Context) error {
	s.mu.Lock()
	ch := s.flight
	if ch == nil {
		ch = make(chan struct{})
		s.flight, s.lastTry = ch, s.c.Now()
		go s.fetchOnce(context.WithoutCancel(ctx), ch)
	}
	s.mu.Unlock()
	select {
	case <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastErr
}

// fetchOnce is one fetch, its outcome recorded before ch closes. A success
// replaces the set whole, so a key the provider dropped is dropped. A
// failure, a set with no usable key among them (pre-flight M-2), keeps the
// last good set and says so once an hour. Skips and the jwks_uri are said
// when they change.
func (s *KeySet) fetchOnce(ctx context.Context, ch chan struct{}) {
	uri, body, keys, skipped, err := s.fetch(ctx)
	now := s.c.Now()
	s.mu.Lock()
	s.flight = nil
	s.lastErr = err
	if err == nil {
		s.keys, s.fetched = keys, now
	}
	fetched, held := s.fetched, len(s.keys)
	stale := err != nil && (s.saidStale.IsZero() || now.Sub(s.saidStale) >= sayStaleEvery)
	if stale {
		s.saidStale = now
	}
	sayURI := err == nil && uri != s.jwksURI
	saySkips := err == nil && !slices.Equal(skipped, s.skipped)
	if err == nil {
		s.saidStale, s.jwksURI, s.skipped = time.Time{}, uri, skipped
	}
	s.mu.Unlock()
	close(ch)

	iss := s.c.Issuer
	if err != nil {
		s.c.M.OIDCKeysFetchFailures.WithLabelValues(iss).Inc()
		if stale {
			s.sayStale(fetched, held, err, now)
		}
		return
	}
	s.c.M.OIDCKeysLastSuccess.WithLabelValues(iss).Set(float64(now.Unix()))
	if sayURI {
		s.c.Say("identity: %s: keys from %s", iss, printsafe.Line(uri, 300))
	}
	if saySkips {
		for _, why := range skipped {
			s.c.Say("identity: %s: a key in the JWKS is skipped: %s", iss, why)
		}
	}
	if s.c.Save != nil {
		file, _ := json.Marshal(persisted{Issuer: iss, FetchedAt: now, JWKS: body})
		if err := s.c.Save(file); err != nil {
			s.c.Say("identity: %s: the keys were fetched but could not be kept for a restart: %v", iss, err)
		}
	}
}

func (s *KeySet) sayStale(fetched time.Time, held int, err error, now time.Time) {
	iss, why := s.c.Issuer, printsafe.Line(err.Error(), 300)
	switch {
	case fetched.IsZero():
		s.c.Say("identity: %s: no keys fetched yet (%s); every token from it is refused "+
			"identity_provider_unavailable until a fetch succeeds", iss, why)
	case now.Sub(fetched) > s.c.MaxAge:
		s.c.Say("identity: %s: no key refreshed within broker.identity.jwks_max_age (%s; the last at %s); every "+
			"token from it is refused identity_provider_unavailable until a fetch succeeds; certificate logins "+
			"and live device sessions are unaffected; to accept the held keys meanwhile, raise "+
			"broker.identity.jwks_max_age (up to 720h) and restart port49-broker", iss, s.c.MaxAge,
			fetched.UTC().Format(time.RFC3339))
	default:
		s.c.Say("identity: %s: keys not refreshed since %s (the last error: %s); tokens signed by the %d keys "+
			"held are accepted until %s (broker.identity.jwks_max_age), then refused identity_provider_unavailable",
			iss, fetched.UTC().Format(time.RFC3339), why, held, fetched.Add(s.c.MaxAge).UTC().Format(time.RFC3339))
	}
}

// fetch is one discovery read and one JWKS read: the jwks_uri, the raw
// JWKS, its keys, and its skips. A JWKS with no usable key is an error, a
// failed fetch (pre-flight M-2): one bad publish never replaces the last
// good set or the kept file.
func (s *KeySet) fetch(ctx context.Context) (string, []byte, []Key, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	doc, err := s.get(ctx, strings.TrimSuffix(s.c.Issuer, "/")+"/.well-known/openid-configuration")
	if err != nil {
		return "", nil, nil, nil, err
	}
	var d struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if json.Unmarshal(doc, &d) != nil {
		return "", nil, nil, nil, errors.New("the discovery document does not decode")
	}
	if d.Issuer != s.c.Issuer {
		return "", nil, nil, nil, errors.New("the discovery document names another issuer (OpenID Connect Discovery §4.3)")
	}
	u, err := url.Parse(d.JWKSURI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", nil, nil, nil, errors.New("the discovery document's jwks_uri is not an https URL")
	}
	body, err := s.get(ctx, u.String())
	if err != nil {
		return "", nil, nil, nil, err
	}
	keys, skipped, err := ParseJWKS(body)
	switch {
	case err != nil:
		return "", nil, nil, nil, err
	case len(keys) == 0:
		return "", nil, nil, nil, fmt.Errorf("the JWKS holds no key port49 can verify with (%d skipped)", len(skipped))
	}
	return u.String(), body, keys, skipped, nil
}

func (s *KeySet) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.c.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			return nil, fmt.Errorf("GET %s: redirected (%s); a redirect is not followed", u, resp.Status)
		}
		return nil, fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", u, err)
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("GET %s: over %d bytes", u, maxBody)
	}
	return b, nil
}

// pick is the one key kid names, or with no kid the one key of alg's
// type, and whether there is exactly one and it fits alg.
func pick(keys []Key, kid string, alg Alg) (Key, bool) {
	var out []Key
	for _, k := range keys {
		if (kid != "" && k.Kid == kid) || (kid == "" && k.Fits(alg)) {
			out = append(out, k)
		}
	}
	if len(out) != 1 || !out[0].Fits(alg) {
		return Key{}, false
	}
	return out[0], true
}

// Key is the key a token's kid (or, with none, its algorithm's type)
// names, refetching once per RefetchEvery when the set has none or is
// stale, and joining a refetch already running. ErrUnavailable when no
// fresh set can be had; ErrUnknownKey when a fresh set has no one match;
// ctx.Err() when the caller's own context ends while it waits.
func (s *KeySet) Key(ctx context.Context, kid string, alg Alg) (Key, error) {
	type state struct {
		k                   Key
		ok, fresh, inFlight bool
		lastErr             error
		lastTry             time.Time
	}
	try := func() state {
		s.mu.Lock()
		defer s.mu.Unlock()
		k, ok := pick(s.keys, kid, alg)
		fresh := !s.fetched.IsZero() && s.c.Now().Sub(s.fetched) <= s.c.MaxAge
		return state{k, ok, fresh, s.flight != nil, s.lastErr, s.lastTry}
	}
	st := try()
	if st.ok && st.fresh {
		return st.k, nil
	}
	if st.inFlight || st.lastTry.IsZero() || s.c.Now().Sub(st.lastTry) >= RefetchEvery {
		if err := s.Fetch(ctx); err != nil && ctx.Err() != nil {
			return Key{}, ctx.Err()
		}
		if st = try(); st.ok && st.fresh {
			return st.k, nil
		}
	}
	if !st.fresh || st.lastErr != nil {
		return Key{}, ErrUnavailable
	}
	return Key{}, ErrUnknownKey
}

// Status is the set held, when it was fetched, and the last fetch's error.
func (s *KeySet) Status() ([]Key, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Key(nil), s.keys...), s.fetched, s.lastErr
}

// NextWait is the refresh loop's wait after a fetch: 0 after a success
// (Run waits Refresh), else 30s doubling to 5m.
func NextWait(ok bool, prev time.Duration) time.Duration {
	if ok {
		return 0
	}
	return min(max(2*prev, 30*time.Second), 5*time.Minute)
}

// Run fetches at once when the set is older than Refresh (or empty), then
// every Refresh, backing off after a failure, until ctx ends.
func (s *KeySet) Run(ctx context.Context) {
	var backoff time.Duration
	for {
		_, fetched, _ := s.Status()
		wait := s.c.Refresh - s.c.Now().Sub(fetched)
		if backoff > 0 {
			wait = backoff
		}
		if fetched.IsZero() && backoff == 0 {
			wait = 0
		}
		t := time.NewTimer(max(wait, 0))
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
		err := s.Fetch(ctx)
		if ctx.Err() != nil {
			return
		}
		backoff = NextWait(err == nil, backoff)
	}
}
```

Note `fetchOnce` holds no lock while it reads the network, and every caller, the one that
started it included, waits on `flight` under its own context. `Key`'s refetch is the same
`Fetch`, so a token arriving during the hourly refresh waits for it rather than fetching twice.
A fetch outlives a caller that hung up by at most `fetchTimeout`, and a shutdown by the same. A
`nil` `M` is not allowed: `metrics.New` is cheap, and the tests pass one.

- [ ] **Step 6: Run the tests to see them pass**

Run: `go test ./internal/oidc/ ./internal/daemon/metrics/ -count=1 -race`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/oidc/keyset.go internal/oidc/keyset_test.go internal/oidc/oidctest/issuer.go \
  internal/daemon/metrics/metrics.go
git commit -m "feat(oidc): one issuer's keys: discovery, refresh, one refetch a minute, kept across a restart, refused past jwks_max_age

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: The verifiers: one per token, the claims, the principal

**Files:**
- Create: `internal/oidc/config.go`, `internal/oidc/verify.go`
- Modify: `internal/daemon/metrics/metrics.go`
- Test: `internal/oidc/verify_test.go` (package `oidc_test`)

**Interfaces:**
- Consumes: Tasks 3 and 4 (`ParseCompact`, `JWS.Verify`, `KeySet.Key`, `ErrUnavailable`,
  `ErrUnknownKey`, `oidctest.Issuer`); `store.Credential`, `store.SidKey` (Task 2).
- Produces:
  - `oidc.Domain` (`Humans`, `Machines`), the claim names `ClaimPreferredUsername`,
    `ClaimEmail`, `ClaimUPN`;
  - `oidc.VerifierConfig{Domain Domain; Issuer, ClientID, Audience, PrincipalClaim string;
    PrincipalDomains []string; Clients []MachineClient; Scopes []string; Algorithms []Alg;
    CAFile string}` and `oidc.MachineClient{ClientID, Sub string}` (Rulings 21, 22);
  - `oidc.DomainOf(principal string) string`, `(VerifierConfig).Owns(principal string) bool`,
    `(VerifierConfig).Client(id string) (MachineClient, bool)`;
  - `oidc.MachineSessionClaims` (`auth_time`, `sid`, `nonce`, `scp`, `amr`);
  - `oidc.Timing{ClockSkew, MaxTokenAge, JWKSRefresh, JWKSMaxAge time.Duration}` and
    `oidc.DefaultTiming`;
  - `oidc.Config{X509AnchorFile string; Shorthand bool; OIDC []VerifierConfig; Timing Timing}`
    (what `internal/config` fills, Task 7);
  - `oidc.Verifier{VerifierConfig; Keys *KeySet}`, `oidc.Set{Verifiers []*Verifier; Timing
    Timing; Now func() time.Time; M *metrics.Metrics}`;
  - `(*Set).Verify(ctx, raw string) (Assertion, error)`, whose error wraps `ErrInvalid`,
    `ErrUnavailable` or `ErrUnmapped` and whose text is safe to log;
  - `(*Set).Humans() []*Verifier`, `(*Set).ByIssuer(iss string) []*Verifier`,
    `(*Set).HumanDomains(iss string) []string`;
  - `oidc.Assertion{Domain Domain; Principal, Issuer, Subject, Sid, Nonce, ACR string; AMR
    []string; AuthTime, IssuedAt, Expires time.Time}`, `(Assertion).Credential()
    store.Credential`, `(Assertion).String()` (the nonce withheld);
  - `oidc.ErrInvalid`, `oidc.ErrUnmapped`;
  - `metrics.OIDCTokens *prometheus.CounterVec{issuer,outcome}`.

- [ ] **Step 1: The metric**

In `internal/daemon/metrics/metrics.go`, beside Task 4's:

```go
	// port49_oidc_tokens_total{issuer, outcome}: OIDC bearer tokens by the
	// configured issuer ("unknown" for any other) and outcome: accepted,
	// invalid, expired, unavailable, unmapped, logged_out (plan 7h).
	OIDCTokens *prometheus.CounterVec
```

```go
		OIDCTokens: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_oidc_tokens_total",
			Help: "OIDC bearer tokens by configured issuer and outcome: accepted, invalid, expired, unavailable, unmapped, logged_out."},
			[]string{"issuer", "outcome"}),
```

- [ ] **Step 2: Write the failing tests**

`internal/oidc/verify_test.go`:

```go
package oidc_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
	"github.com/blanketfish/port49/internal/store"
)

const clientID = "port49-cli"

func human(iss *oidctest.Issuer, claim string) oidc.VerifierConfig {
	return oidc.VerifierConfig{Domain: oidc.Humans, Issuer: iss.URL, ClientID: clientID, PrincipalClaim: claim,
		PrincipalDomains: []string{"corp.example.com"}, Algorithms: []oidc.Alg{oidc.RS256}}
}

// machine lists two clients, each with the sub its client-credentials
// tokens carry (Ruling 21).
func machine(iss *oidctest.Issuer) oidc.VerifierConfig {
	return oidc.VerifierConfig{Domain: oidc.Machines, Issuer: iss.URL, Audience: "api://port49-svc",
		Clients:    []oidc.MachineClient{{ClientID: "Oxidized-01", Sub: "svc-sub"}, {ClientID: "svc-a", Sub: "s"}},
		Algorithms: []oidc.Alg{oidc.RS256}}
}

// newSet is a Set over iss's keys, one KeySet shared by every verifier.
func newSet(t *testing.T, iss *oidctest.Issuer, c *clock, vs ...oidc.VerifierConfig) *oidc.Set {
	t.Helper()
	m := metrics.New(prometheus.NewRegistry())
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()),
		Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
	set := &oidc.Set{Timing: oidc.DefaultTiming, Now: c.Now, M: m}
	for _, v := range vs {
		set.Verifiers = append(set.Verifiers, &oidc.Verifier{VerifierConfig: v, Keys: ks})
	}
	return set
}

func TestAHumansIDTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	raw := iss.IDToken(t, "k1", clientID, "8b2e", c.Now(), map[string]any{
		"preferred_username": "Alice@Corp.Example.com", "amr": []string{"pwd", "otp"}, "acr": "1", "nonce": "n0"})
	a, err := set.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != oidc.Humans || a.Principal != "user:alice@corp.example.com" || a.Subject != "8b2e" ||
		a.Sid != "s-8b2e" || !a.AuthTime.Equal(c.Now()) || a.Nonce != "n0" || a.ACR != "1" {
		t.Fatalf("assertion %+v", a)
	}
	cred := a.Credential()
	if cred.Method != "oidc" || cred.Iss != iss.URL || cred.Sub != "8b2e" || cred.Sid != store.SidKey(iss.URL, "s-8b2e") ||
		len(cred.AMR) != 2 || cred.Fingerprint != "" || cred.Issuer != "" || cred.Serial != "" {
		t.Fatalf("credential %+v", cred)
	}
}

func TestAMachinesAccessTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": []string{"api://port49-svc"}, "sub": "svc-sub",
		"azp": "Oxidized-01", "iat": c.Now().Unix(), "exp": c.Now().Add(time.Hour).Unix()})
	a, err := set.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if a.Domain != oidc.Machines || a.Principal != "app:Oxidized-01" || !a.AuthTime.Equal(c.Now()) {
		t.Fatalf("assertion %+v: a client id is kept verbatim, and auth_time is iat", a)
	}
}

// Review Focus 4: two machine verifiers at one issuer listing one client; a
// token whose aud names both audiences is two verifiers' and so no one's.
// A human and a machine verifier never both accept one token (Ruling 2): an
// ID token naming both keys is the human's alone, since a machine verifier
// refuses its auth_time and sid.
func TestATokenTwoVerifiersAcceptIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	other := machine(iss)
	other.Audience = "api://port49-other"
	set := newSet(t, iss, c, machine(iss), other)
	now := c.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": []string{"api://port49-svc", "api://port49-other"},
		"sub": "svc-sub", "azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	_, err := set.Verify(context.Background(), raw)
	if !errors.Is(err, oidc.ErrInvalid) || !strings.Contains(err.Error(), "two verifiers") {
		t.Fatalf("a token two machine verifiers accept: %v", err)
	}
	both := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername), machine(iss))
	id := iss.IDToken(t, "k1", clientID, "x", now, map[string]any{"aud": []string{clientID, "api://port49-svc"},
		"azp": clientID, "preferred_username": "alice@corp.example.com"})
	if a, err := both.Verify(context.Background(), id); err != nil || a.Domain != oidc.Humans {
		t.Fatalf("an ID token naming both keys: %+v %v", a, err)
	}
}

// Ruling 21, pre-flight C-1: a person's delegated access token for a machine
// client (aud the API, azp a listed client) is refused, whatever session
// claim marks it, and so is one whose azp and client_id disagree. The
// client's own client-credentials token is accepted, idtyp app included.
func TestADelegatedTokenIsNotAMachine(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	now := c.Now()
	base := func() map[string]any {
		return map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc-sub", "azp": "Oxidized-01",
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", base())); err != nil {
		t.Fatalf("the client's own token: %v", err)
	}
	for claim, v := range map[string]any{"sid": "s-1", "auth_time": now.Unix(), "scp": "port49.api",
		"nonce": "n-1", "amr": []string{"pwd"}, "idtyp": "user"} {
		m := base()
		m[claim] = v
		if _, err := set.Verify(context.Background(), iss.Token(t, "k1", m)); !errors.Is(err, oidc.ErrInvalid) ||
			!strings.Contains(err.Error(), claim) {
			t.Errorf("a machine token carrying %s: %v", claim, err)
		}
	}
	m := base()
	m["client_id"] = "svc-a"
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", m)); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("azp and client_id naming two clients: %v", err)
	}
	m = base()
	m["idtyp"] = "app"
	if a, err := set.Verify(context.Background(), iss.Token(t, "k1", m)); err != nil || a.Principal != "app:Oxidized-01" {
		t.Errorf("idtyp app: %+v %v", a, err)
	}
}

// Ruling 21: the client must be listed, and the token's sub must be the one
// pinned for it; a person's sub never is.
func TestAMachineSubIsPinned(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	now := c.Now()
	for name, k := range map[string]struct{ azp, sub, want string }{
		"an unlisted client":          {"someone-else", "svc-sub", "lists in clients"},
		"a listed client, wrong sub":  {"Oxidized-01", "alice-object-id", "pinned"},
		"another listed client's sub": {"Oxidized-01", "s", "pinned"},
	} {
		raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": k.sub, "azp": k.azp,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) ||
			!strings.Contains(err.Error(), k.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Ruling 22, pre-flight C-2: a verifier gives principals in its own domains
// alone, so a second issuer cannot mint as another's person, and no
// subdomain is implied.
func TestAnIssuerNamesOnlyItsOwnDomains(t *testing.T) {
	corp, contractor, c := oidctest.NewIssuer(t), oidctest.NewIssuer(t), newClock()
	m := metrics.New(prometheus.NewRegistry())
	set := &oidc.Set{Timing: oidc.DefaultTiming, Now: c.Now, M: m}
	for iss, domain := range map[*oidctest.Issuer]string{corp: "corp.example.com", contractor: "contractor.example.net"} {
		ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()),
			Refresh: time.Hour, MaxAge: 24 * time.Hour, Now: c.Now, M: m})
		vc := human(iss, oidc.ClaimEmail)
		vc.PrincipalDomains = []string{domain}
		set.Verifiers = append(set.Verifiers, &oidc.Verifier{VerifierConfig: vc, Keys: ks})
	}
	alice := map[string]any{"email": "alice@corp.example.com", "email_verified": true}
	if a, err := set.Verify(context.Background(), corp.IDToken(t, "k1", clientID, "a", c.Now(), alice)); err != nil ||
		a.Principal != "user:alice@corp.example.com" {
		t.Fatalf("corp's own: %+v %v", a, err)
	}
	_, err := set.Verify(context.Background(), contractor.IDToken(t, "k1", clientID, "a", c.Now(), alice))
	if !errors.Is(err, oidc.ErrUnmapped) || !strings.Contains(err.Error(), "principal_domains") {
		t.Fatalf("the contractor issuer naming corp's alice: %v", err)
	}
	eu := map[string]any{"email": "alice@eu.corp.example.com", "email_verified": true}
	if _, err := set.Verify(context.Background(), corp.IDToken(t, "k1", clientID, "a", c.Now(), eu)); !errors.Is(err, oidc.ErrUnmapped) {
		t.Fatalf("a subdomain: %v", err)
	}
}

// Every claim is read by its exact name, and a claim named twice in two
// cases is refused (pre-flight M-4); a date is a JSON number (M-5).
func TestClaimsAreReadByExactName(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	now := c.Now()
	base := func() map[string]any {
		return map[string]any{"iss": iss.URL, "aud": clientID, "sub": "x", "iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(), "auth_time": now.Unix(), "email": "alice@corp.example.com",
			"email_verified": true}
	}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", base())); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(map[string]any){
		"ISS in place of iss":     func(m map[string]any) { m["ISS"] = m["iss"]; delete(m, "iss") },
		"email in two cases":      func(m map[string]any) { m["Email"] = "mallory@corp.example.com" },
		"exp a string":            func(m map[string]any) { m["exp"] = fmt.Sprint(now.Add(time.Minute).Unix()) },
		"auth_time a string":      func(m map[string]any) { m["auth_time"] = fmt.Sprint(now.Unix()) },
		"EMAIL_VERIFIED in place": func(m map[string]any) { m["EMAIL_VERIFIED"] = true; delete(m, "email_verified") },
	} {
		m := base()
		edit(m)
		_, err := set.Verify(context.Background(), iss.Token(t, "k1", m))
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestAnotherClientsIDTokenIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	for name, extra := range map[string]map[string]any{
		"another aud":           {"aud": "other-app"},
		"two auds, no azp":      {"aud": []string{clientID, "other-app"}},
		"azp another client":    {"azp": "other-app"},
		"two auds, azp another": {"aud": []string{clientID, "other-app"}, "azp": "other-app"},
	} {
		extra["preferred_username"] = "alice@corp.example.com"
		if _, err := set.Verify(context.Background(), iss.IDToken(t, "k1", clientID, "x", c.Now(), extra)); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Review Focus 4: an access token is not a person's ID token, and a logout
// token is never a bearer.
func TestAnAccessTokenIsNotAHumansToken(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	claims := map[string]any{"iss": iss.URL, "aud": clientID, "sub": "x", "iat": c.Now().Unix(),
		"exp": c.Now().Add(time.Minute).Unix(), "auth_time": c.Now().Unix(), "preferred_username": "alice@corp.example.com"}
	for _, typ := range []string{"at+jwt", "application/at+jwt", "AT+JWT", "logout+jwt"} {
		raw := iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": typ}, claims)
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("typ %s: %v", typ, err)
		}
	}
	claims["events"] = map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", claims)); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("a token with events: %v", err)
	}
}

// Review Focus 6: skew is allowed, and no more.
func TestClockSkewIsAllowedAndNoMore(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	now := c.Now()
	ok := func(extra map[string]any) error {
		extra["preferred_username"] = "alice@corp.example.com"
		_, err := set.Verify(context.Background(), iss.IDToken(t, "k1", clientID, "x", now, extra))
		return err
	}
	if err := ok(map[string]any{"exp": now.Add(-30 * time.Second).Unix()}); err != nil {
		t.Errorf("expired 30s ago, within skew: %v", err)
	}
	if err := ok(map[string]any{"exp": now.Add(-61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) ||
		!strings.Contains(err.Error(), "expired") {
		t.Errorf("expired 61s ago: %v", err)
	}
	if err := ok(map[string]any{"iat": now.Add(30 * time.Second).Unix(), "auth_time": now.Unix()}); err != nil {
		t.Errorf("issued 30s ahead: %v", err)
	}
	if err := ok(map[string]any{"iat": now.Add(61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("issued 61s ahead: %v", err)
	}
	if err := ok(map[string]any{"nbf": now.Add(61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("not valid for 61s: %v", err)
	}
	if err := ok(map[string]any{"auth_time": now.Add(61 * time.Second).Unix()}); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("authenticated 61s ahead: %v", err)
	}
}

func TestATokenOlderThanMaxTokenAgeIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	now := c.Now()
	raw := iss.IDToken(t, "k1", clientID, "x", now, map[string]any{"preferred_username": "alice@corp.example.com",
		"iat": now.Add(-2*time.Hour - time.Second).Unix(), "exp": now.Add(time.Hour).Unix()})
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) ||
		!strings.Contains(err.Error(), "max_token_age") {
		t.Fatalf("a token issued 2h1s ago: %v", err)
	}
}

func TestRequiredClaims(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	for _, claim := range []string{"exp", "iat", "sub", "auth_time", "iss", "aud"} {
		raw := iss.IDToken(t, "k1", clientID, "x", c.Now(), map[string]any{"preferred_username": "alice@corp.example.com",
			claim: nil})
		if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("no %s: %v", claim, err)
		}
	}
}

func TestThePrincipalClaim(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	for _, k := range []struct {
		claim string
		extra map[string]any
		want  string // "" is ErrUnmapped
	}{
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": "alice@corp.example.com"}, "user:alice@corp.example.com"},
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": "alice"}, ""},
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": []string{"a@b"}}, ""},
		{oidc.ClaimPreferredUsername, map[string]any{"preferred_username": "al ice@b"}, ""},
		{oidc.ClaimPreferredUsername, map[string]any{}, ""},
		{oidc.ClaimEmail, map[string]any{"email": "Alice@Corp.Example.com", "email_verified": true}, "user:alice@corp.example.com"},
		{oidc.ClaimEmail, map[string]any{"email": "alice@corp.example.com", "email_verified": false}, ""},
		{oidc.ClaimEmail, map[string]any{"email": "alice@corp.example.com"}, ""},
		{oidc.ClaimEmail, map[string]any{"email": "alice@corp.example.com", "email_verified": "true"}, ""},
		{oidc.ClaimUPN, map[string]any{"upn": "alice@corp.example.com"}, "user:alice@corp.example.com"},
	} {
		set := newSet(t, iss, c, human(iss, k.claim))
		a, err := set.Verify(context.Background(), iss.IDToken(t, "k1", clientID, "x", c.Now(), k.extra))
		switch {
		case k.want == "" && !errors.Is(err, oidc.ErrUnmapped):
			t.Errorf("%s %v: %v %+v", k.claim, k.extra, err, a)
		case k.want != "" && (err != nil || a.Principal != k.want):
			t.Errorf("%s %v: %q %v", k.claim, k.extra, a.Principal, err)
		}
	}
}

func TestAMachineWithNoClientIsUnmapped(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	base := map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "s", "iat": c.Now().Unix(),
		"exp": c.Now().Add(time.Hour).Unix()}
	if _, err := set.Verify(context.Background(), iss.Token(t, "k1", base)); !errors.Is(err, oidc.ErrUnmapped) {
		t.Fatalf("no azp and no client_id: %v", err)
	}
	base["client_id"] = "svc-a"
	if a, err := set.Verify(context.Background(), iss.Token(t, "k1", base)); err != nil || a.Principal != "app:svc-a" {
		t.Fatalf("client_id alone: %q %v", a.Principal, err)
	}
}

// A refusal names no claim of a token that did not verify: not its iss, not
// its sub, not its kid (Global Constraints).
func TestARefusalNeverQuotesAnUnverifiedToken(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	forger := oidctest.NewIssuer(t)
	forger.AddKey(t, "kid-marker", oidc.RS256)
	for name, raw := range map[string]string{
		"an unknown issuer": forger.Token(t, "kid-marker", map[string]any{"iss": "https://iss-marker.example",
			"sub": "sub-marker", "aud": clientID}),
		"a forged signature": forger.TokenWith(t, "kid-marker", map[string]any{"kid": "k1"}, map[string]any{
			"iss": iss.URL, "sub": "sub-marker", "aud": clientID, "iat": c.Now().Unix(),
			"exp": c.Now().Add(time.Minute).Unix(), "auth_time": c.Now().Unix(), "preferred_username": "pu-marker@x"}),
	} {
		_, err := set.Verify(context.Background(), raw)
		if !errors.Is(err, oidc.ErrInvalid) {
			t.Fatalf("%s: %v", name, err)
		}
		for _, m := range []string{"iss-marker", "sub-marker", "kid-marker", "pu-marker"} {
			if strings.Contains(err.Error(), m) {
				t.Errorf("%s: the refusal %q quotes %s", name, err, m)
			}
		}
	}
}

func TestAnAlgorithmTheVerifierDoesNotPinIsRefused(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	iss.AddKey(t, "e1", oidc.ES256)
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	raw := iss.IDToken(t, "e1", clientID, "x", c.Now(), map[string]any{"preferred_username": "alice@corp.example.com"})
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("ES256 under algorithms [RS256]: %v", err)
	}
}

func TestAProviderNeverReachedIsUnavailable(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimPreferredUsername))
	raw := iss.IDToken(t, "k1", clientID, "x", c.Now(), map[string]any{"preferred_username": "alice@corp.example.com"})
	iss.Close()
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("no keys ever fetched: %v", err)
	}
}

func TestTheAssertionWithholdsItsNonce(t *testing.T) {
	a := oidc.Assertion{Principal: "user:a@b", Nonce: "nonce-marker"}
	for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
		if strings.Contains(fmt.Sprintf(verb, a), "nonce-marker") {
			t.Fatalf("%s prints the nonce", verb)
		}
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/oidc/ -run 'TestAHumans|TestAMachines|TestATokenTwo|TestADelegated|TestAMachineSubIsPinned|TestAnIssuerNamesOnly|TestClaimsAreReadByExactName|TestAnotherClient|TestAnAccessToken|TestClockSkew|TestATokenOlder|TestRequiredClaims|TestThePrincipalClaim|TestAMachineWithNo|TestARefusalNever|TestAnAlgorithmThe|TestAProviderNever|TestTheAssertion' -count=1`
Expected: FAIL to compile: `VerifierConfig`, `Set`, `Assertion` undefined.

- [ ] **Step 4: Implement**

`internal/oidc/config.go`:

```go
package oidc

import (
	"slices"
	"strings"
	"time"
)

// Domain is a trust domain (spec §13 decision 16): the list a verifier is in.
type Domain string

const (
	Humans   Domain = "humans"
	Machines Domain = "machines"
)

// The claims a human verifier may take its principal from (Ruling 6).
const (
	ClaimPreferredUsername = "preferred_username"
	ClaimEmail             = "email"
	ClaimUPN               = "upn"
)

// MachineSessionClaims mark a person's authentication or a delegated grant:
// a token carrying one is never a machine's (Ruling 21).
var MachineSessionClaims = []string{"auth_time", "sid", "nonce", "scp", "amr"}

// MachineClient is one client a machine verifier accepts, and the sub its
// client-credentials tokens carry: the client's own identity at the
// provider (RFC 9068 §2.2), which no person's token carries (Ruling 21).
type MachineClient struct {
	ClientID string
	Sub      string
}

// VerifierConfig is one oidc verifier of broker.identity (Ruling 1). A
// human's is keyed by ClientID and gives principals in PrincipalDomains; a
// machine's is keyed by Audience and takes the Clients it lists.
type VerifierConfig struct {
	Domain         Domain
	Issuer         string
	ClientID       string
	Audience       string
	PrincipalClaim string
	// PrincipalDomains are the domains whose user: principals a human
	// verifier may give, lower-cased (Ruling 22).
	PrincipalDomains []string
	// Clients are a machine verifier's (Ruling 21).
	Clients []MachineClient
	// Scopes are what /v1/config tells a public client to ask for, openid
	// first (Ruling 16).
	Scopes     []string
	Algorithms []Alg
	// CAFile is the provider's TLS anchor; "" is the system roots.
	CAFile string
}

// DomainOf is a user: principal's domain, after its last @; "" for any
// other principal.
func DomainOf(principal string) string {
	i := strings.LastIndexByte(principal, '@')
	if !strings.HasPrefix(principal, "user:") || i < 0 {
		return ""
	}
	return principal[i+1:]
}

// Owns reports whether principal is one this human verifier may give: a
// user: principal in its PrincipalDomains, exactly (Ruling 22).
func (v VerifierConfig) Owns(principal string) bool {
	d := DomainOf(principal)
	return d != "" && slices.Contains(v.PrincipalDomains, d)
}

// Client is the listed client named id, if a machine verifier lists it.
func (v VerifierConfig) Client(id string) (MachineClient, bool) {
	i := slices.IndexFunc(v.Clients, func(c MachineClient) bool { return c.ClientID == id })
	if i < 0 {
		return MachineClient{}, false
	}
	return v.Clients[i], true
}

// Timing is broker.identity's timing (OR-2).
type Timing struct {
	ClockSkew, MaxTokenAge, JWKSRefresh, JWKSMaxAge time.Duration
}

// DefaultTiming is OR-2's recommendation.
var DefaultTiming = Timing{ClockSkew: time.Minute, MaxTokenAge: 2 * time.Hour, JWKSRefresh: time.Hour,
	JWKSMaxAge: 24 * time.Hour}

// Config is broker.identity resolved: the one x509 human anchor ("" for
// none), whether it came from broker.client_ca_file with no
// broker.identity (Shorthand), the oidc verifiers, and the timing.
type Config struct {
	X509AnchorFile string
	Shorthand      bool
	OIDC           []VerifierConfig
	Timing         Timing
}
```

`internal/oidc/verify.go`:

```go
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

var (
	// ErrInvalid is a token no configured verifier accepts, or two do:
	// trust_domain_unresolved, 401 (Rulings 2, 3, 5).
	ErrInvalid = errors.New("oidc: no configured verifier accepts the token")
	// ErrUnmapped is a token that verified and names no usable principal:
	// identity_unmapped, 401 (Ruling 6).
	ErrUnmapped = errors.New("oidc: the token names no usable principal")
)

// refusal is a Verify error: its kind (ErrInvalid, ErrUnmapped,
// ErrUnavailable) and why, in words safe to log: an issuer from
// configuration, a check's name, a validated time, never a claim of a token
// that did not verify.
type refusal struct {
	kind error
	why  string
	// outcome is the metric's: invalid, expired, unavailable, unmapped.
	outcome string
}

func (r *refusal) Error() string { return r.why }
func (r *refusal) Unwrap() error { return r.kind }

func refuse(kind error, outcome, format string, args ...any) *refusal {
	return &refusal{kind: kind, outcome: outcome, why: fmt.Sprintf(format, args...)}
}

// Verifier is one oidc verifier and its issuer's keys, which the issuer's
// other verifier shares.
type Verifier struct {
	VerifierConfig
	Keys *KeySet
}

// Set is broker.identity's oidc verifiers.
type Set struct {
	Verifiers []*Verifier
	Timing    Timing
	Now       func() time.Time
	M         *metrics.Metrics
}

// Humans is the human verifiers, for /v1/config and logout tokens.
func (s *Set) Humans() []*Verifier {
	var out []*Verifier
	for _, v := range s.Verifiers {
		if v.Domain == Humans {
			out = append(out, v)
		}
	}
	return out
}

// ByIssuer is the verifiers whose issuer is iss, byte for byte.
func (s *Set) ByIssuer(iss string) []*Verifier {
	var out []*Verifier
	for _, v := range s.Verifiers {
		if v.Issuer == iss {
			out = append(out, v)
		}
	}
	return out
}

// HumanDomains is the principal_domains of iss's human verifiers: whose
// principals a logout from iss may reach (Ruling 22).
func (s *Set) HumanDomains(iss string) []string {
	var out []string
	for _, v := range s.ByIssuer(iss) {
		if v.Domain == Humans {
			out = append(out, v.PrincipalDomains...)
		}
	}
	return out
}

// Assertion is a verified token as port49 uses it. Every field is a
// validated value.
type Assertion struct {
	Domain    Domain
	Principal string
	Issuer    string
	Subject   string
	Sid       string // the provider's own; Credential qualifies it
	Nonce     string
	AMR       []string
	ACR       string
	AuthTime  time.Time
	IssuedAt  time.Time
	Expires   time.Time
}

// String withholds the nonce, which answers a refresh challenge (Ruling 18).
func (a Assertion) String() string {
	return fmt.Sprintf("Assertion{%s %s issuer %s sub %s sid %s auth_time %s}", a.Domain, a.Principal, a.Issuer,
		a.Subject, a.Sid, a.AuthTime.UTC().Format(time.RFC3339))
}

// GoString is String.
func (a Assertion) GoString() string { return a.String() }

// Credential is what a token and its login context record (spec §5.1.4;
// Ruling 10): the sid issuer-qualified, no certificate.
func (a Assertion) Credential() store.Credential {
	return store.Credential{Method: "oidc", Iss: a.Issuer, Sub: a.Subject, Sid: store.SidKey(a.Issuer, a.Sid),
		AMR: slices.Clone(a.AMR), ACR: a.ACR}
}

// Verify is Ruling 2: the token is offered to every verifier whose issuer
// is its iss, and exactly one must accept it.
func (s *Set) Verify(ctx context.Context, raw string) (Assertion, error) {
	a, iss, err := s.verify(ctx, raw)
	label := "unknown"
	if len(s.ByIssuer(iss)) > 0 {
		label = iss
	}
	outcome := "accepted"
	var r *refusal
	if errors.As(err, &r) {
		outcome = r.outcome
	}
	s.M.OIDCTokens.WithLabelValues(label, outcome).Inc()
	return a, err
}

func (s *Set) verify(ctx context.Context, raw string) (Assertion, string, error) {
	j, err := ParseCompact(raw)
	if err != nil {
		if errors.Is(err, ErrCrit) {
			return Assertion{}, "", refuse(ErrInvalid, "invalid", "it names a critical header extension")
		}
		return Assertion{}, "", refuse(ErrInvalid, "invalid", "it is not a compact JWS (an encrypted, unsigned or "+
			"malformed token, or over %d bytes)", MaxToken)
	}
	var head struct {
		Iss string `json:"iss"`
	}
	_ = json.Unmarshal(j.Payload, &head)
	vs := s.ByIssuer(head.Iss)
	if len(vs) == 0 {
		return Assertion{}, "", refuse(ErrInvalid, "invalid", "no configured verifier accepts its issuer")
	}
	var accepted []Assertion
	var first *refusal
	unavailable := false
	for _, v := range vs {
		a, err := v.verify(ctx, j, s.Timing, s.Now())
		var r *refusal
		switch {
		case err == nil:
			accepted = append(accepted, a)
		case errors.As(err, &r):
			if errors.Is(r, ErrUnavailable) {
				unavailable = true
			}
			if first == nil || errors.Is(r, ErrUnmapped) {
				first = r // a verifier that verified the signature says the more useful why
			}
		}
	}
	if first == nil {
		first = refuse(ErrInvalid, "invalid", "no configured verifier accepts it")
	}
	switch {
	case len(accepted) == 1:
		return accepted[0], head.Iss, nil
	case len(accepted) > 1:
		return Assertion{}, head.Iss, refuse(ErrInvalid, "invalid", "two verifiers of %s accept it, so neither "+
			"does (decision 39)", head.Iss)
	case unavailable && !errors.Is(first, ErrUnmapped):
		return Assertion{}, head.Iss, refuse(ErrUnavailable, "unavailable", "the keys of %s are not available "+
			"(none fetched, or none refreshed within broker.identity.jwks_max_age)", head.Iss)
	}
	return Assertion{}, head.Iss, first
}

// claims is what port49 reads of a payload, taken from it by exact name
// (exact); every field is checked before use. The dates are raw, so a JSON
// string is told from a number (pre-flight M-5).
type claims struct {
	Iss           string          `json:"iss"`
	Sub           string          `json:"sub"`
	Aud           json.RawMessage `json:"aud"`
	Azp           string          `json:"azp"`
	ClientID      string          `json:"client_id"`
	Exp           json.RawMessage `json:"exp"`
	Nbf           json.RawMessage `json:"nbf"`
	Iat           json.RawMessage `json:"iat"`
	AuthTime      json.RawMessage `json:"auth_time"`
	Nonce         string          `json:"nonce"`
	Sid           string          `json:"sid"`
	Idtyp         string          `json:"idtyp"`
	AMR           json.RawMessage `json:"amr"`
	ACR           json.RawMessage `json:"acr"`
	Events        json.RawMessage `json:"events"`
	EmailVerified json.RawMessage `json:"email_verified"`
}

// claimNames are claims' members, the names exact reads.
var claimNames = []string{"iss", "sub", "aud", "azp", "client_id", "exp", "nbf", "iat", "auth_time", "nonce", "sid",
	"idtyp", "amr", "acr", "events", "email_verified"}

// payload is a token's claims by exact name. A payload naming one claim
// twice in two cases is refused: encoding/json would read "ISS" as iss
// while the principal claim is read exactly, two rules for one token
// (pre-flight M-4).
func payload(b []byte) (map[string]json.RawMessage, error) {
	var all map[string]json.RawMessage
	if json.Unmarshal(b, &all) != nil || all == nil {
		return nil, errors.New("its claims are not a JSON object")
	}
	seen := make(map[string]bool, len(all))
	for k := range all {
		l := strings.ToLower(k)
		if seen[l] {
			return nil, errors.New("it names one claim twice, in two cases")
		}
		seen[l] = true
	}
	return all, nil
}

// exact decodes into v the members of all named in names, by exact name
// alone: encoding/json matches a field's name ignoring case, so only the
// exactly named members are handed to it.
func exact(all map[string]json.RawMessage, v any, names []string) error {
	pick := make(map[string]json.RawMessage, len(names))
	for _, n := range names {
		if raw, ok := all[n]; ok {
			pick[n] = raw
		}
	}
	b, err := json.Marshal(pick)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// humanAudience is OIDC Core §3.1.3.7's aud and azp rule for client_id, an
// ID token's and a logout token's alike (pre-flight M-6): aud holds it,
// several audiences need an azp, and an azp is it.
func humanAudience(auds []string, azp, clientID string) *refusal {
	switch {
	case !slices.Contains(auds, clientID):
		return refuse(ErrInvalid, "invalid", "its aud does not name client_id %s", clientID)
	case len(auds) > 1 && azp == "":
		return refuse(ErrInvalid, "invalid", "it names several audiences and no azp (OIDC Core §3.1.3.7)")
	case azp != "" && azp != clientID:
		return refuse(ErrInvalid, "invalid", "its azp is not client_id %s", clientID)
	}
	return nil
}

// verify is one verifier's whole check of j (Rulings 2, 3, 5, 6, 21, 22).
func (v *Verifier) verify(ctx context.Context, j *JWS, t Timing, now time.Time) (Assertion, error) {
	iss := v.Issuer
	if !slices.Contains(v.Algorithms, j.Header.Alg) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its algorithm is not one %s's %s verifier pins", iss, v.Domain)
	}
	key, err := v.Keys.Key(ctx, j.Header.Kid, j.Header.Alg)
	switch {
	case errors.Is(err, ErrUnavailable), err != nil && ctx.Err() != nil:
		// A caller's own deadline waiting on a refetch is the provider's
		// unavailability to it, to be retried, never a bad token.
		return Assertion{}, refuse(ErrUnavailable, "unavailable", "the keys of %s are not available", iss)
	case err != nil:
		return Assertion{}, refuse(ErrInvalid, "invalid", "no one key of %s matches its key id", iss)
	}
	if err := j.Verify(key, v.Algorithms); err != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its signature does not verify under the keys of %s", iss)
	}
	// From here every claim is the provider's, and may be said.
	typ := strings.ToLower(strings.TrimPrefix(strings.ToLower(j.Header.Typ), "application/"))
	if typ == "logout+jwt" || (v.Domain == Humans && typ == "at+jwt") {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its typ %q is not an ID token's (RFC 8725 §2.8)", typ)
	}
	all, err := payload(j.Payload)
	if err != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "%s", err.Error())
	}
	var c claims
	if exact(all, &c, claimNames) != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its claims are not a JSON object of the expected types")
	}
	if c.Events != nil {
		return Assertion{}, refuse(ErrInvalid, "invalid", "it carries an events claim: a logout token is never a bearer")
	}
	if c.Iss != iss {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its iss is not %s", iss)
	}
	auds, ok := audiences(c.Aud)
	if !ok {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its aud is absent or not a string or a list of strings")
	}
	switch v.Domain {
	case Humans:
		if r := humanAudience(auds, c.Azp, v.ClientID); r != nil {
			return Assertion{}, r
		}
	case Machines:
		if !slices.Contains(auds, v.Audience) {
			return Assertion{}, refuse(ErrInvalid, "invalid", "its aud does not name audience %s", v.Audience)
		}
	}
	exp, ok := numericDate(c.Exp)
	if !ok {
		return Assertion{}, refuse(ErrInvalid, "invalid", "it has no exp, or its exp is not a number")
	}
	if !now.Before(exp.Add(t.ClockSkew)) {
		return Assertion{}, refuse(ErrInvalid, "expired", "it expired at %s (broker.identity.clock_skew %s)",
			exp.UTC().Format(time.RFC3339), t.ClockSkew)
	}
	if nbf, ok := numericDate(c.Nbf); ok && now.Before(nbf.Add(-t.ClockSkew)) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "it is not valid until %s", nbf.UTC().Format(time.RFC3339))
	} else if len(c.Nbf) != 0 && !ok {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its nbf is not a time")
	}
	iat, ok := numericDate(c.Iat)
	switch {
	case !ok:
		return Assertion{}, refuse(ErrInvalid, "invalid", "it has no iat, or its iat is not a number")
	case iat.After(now.Add(t.ClockSkew)):
		return Assertion{}, refuse(ErrInvalid, "invalid", "it was issued at %s, ahead of the broker's clock by more "+
			"than broker.identity.clock_skew (%s)", iat.UTC().Format(time.RFC3339), t.ClockSkew)
	case now.Sub(iat) > t.MaxTokenAge:
		return Assertion{}, refuse(ErrInvalid, "expired", "issued %s ago, past broker.identity.max_token_age (%s)",
			now.Sub(iat).Round(time.Minute), t.MaxTokenAge)
	}
	if !printableID(c.Sub) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its sub is absent or not 1 to 255 printable ASCII characters")
	}
	if c.Sid != "" && !printableID(c.Sid) {
		return Assertion{}, refuse(ErrInvalid, "invalid", "its sid is not 1 to 255 printable ASCII characters")
	}
	a := Assertion{Domain: v.Domain, Issuer: iss, Subject: c.Sub, Sid: c.Sid, Nonce: c.Nonce, IssuedAt: iat,
		Expires: exp, AMR: amr(c.AMR), ACR: acr(c.ACR)}
	switch v.Domain {
	case Humans:
		at, ok := numericDate(c.AuthTime)
		switch {
		case !ok:
			return Assertion{}, refuse(ErrInvalid, "invalid", "it has no auth_time, so no session ceiling can be set "+
				"(spec §5.6)")
		case at.After(now.Add(t.ClockSkew)):
			return Assertion{}, refuse(ErrInvalid, "invalid", "its auth_time is ahead of the broker's clock by more "+
				"than broker.identity.clock_skew")
		}
		a.AuthTime = at
		p, why := humanPrincipal(all, v.PrincipalClaim, c.EmailVerified)
		if why != "" {
			return Assertion{}, refuse(ErrUnmapped, "unmapped", "%s (broker.identity.humans principal_claim %s)", why,
				v.PrincipalClaim)
		}
		if !v.Owns(p) {
			return Assertion{}, refuse(ErrUnmapped, "unmapped", "its principal %s is outside the principal_domains "+
				"of %s's human verifier (%s): an issuer gives only its own domains' people (decision 39 ruling 22)",
				printsafe.Line(p, 120), iss, strings.Join(v.PrincipalDomains, ", "))
		}
		a.Principal = p
	case Machines:
		// Ruling 21: a client-credentials token of a listed client, never a
		// person's delegated token for it.
		for _, name := range MachineSessionClaims {
			if _, ok := all[name]; ok {
				return Assertion{}, refuse(ErrInvalid, "invalid", "it carries %s, a person's session or delegated "+
					"grant: a person's token is never a machine's (decision 39 ruling 21)", name)
			}
		}
		if c.Idtyp != "" && c.Idtyp != "app" {
			return Assertion{}, refuse(ErrInvalid, "invalid", "its idtyp %q is not app: a person's token is never a "+
				"machine's (decision 39 ruling 21)", printsafe.Line(c.Idtyp, 20))
		}
		if c.Azp != "" && c.ClientID != "" && c.Azp != c.ClientID {
			return Assertion{}, refuse(ErrInvalid, "invalid", "its azp and client_id name two clients")
		}
		id := c.Azp
		if id == "" {
			id = c.ClientID
		}
		if !printableID(id) {
			return Assertion{}, refuse(ErrUnmapped, "unmapped", "it names no client: neither azp nor client_id is 1 to "+
				"255 printable ASCII characters")
		}
		mc, listed := v.Client(id)
		switch {
		case !listed:
			return Assertion{}, refuse(ErrInvalid, "invalid", "its client %s is not one %s's machine verifier "+
				"(audience %s) lists in clients", id, iss, v.Audience)
		case c.Sub != mc.Sub:
			return Assertion{}, refuse(ErrInvalid, "invalid", "its sub is not the one pinned for client %s: a token "+
				"another identity obtained through the client is not the client's (decision 39 ruling 21)", id)
		}
		a.Principal, a.AuthTime = "app:"+id, iat
	}
	return a, nil
}

func audiences(raw json.RawMessage) ([]string, bool) {
	var one string
	if json.Unmarshal(raw, &one) == nil && one != "" {
		return []string{one}, true
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil && len(many) > 0 {
		return many, true
	}
	return nil, false
}

// numericDate is a JWT NumericDate (RFC 7519 §2): a JSON number, never a
// string (pre-flight M-5), of whole or fractional seconds in a range a
// clock can hold.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	if len(raw) == 0 || raw[0] == '"' {
		return time.Time{}, false
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || f < 0 || f > math.MaxInt32*4 || math.IsNaN(f) {
		return time.Time{}, false
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
}

// printableID is 1 to 255 bytes of printable ASCII with no space: a sub, a
// sid or a client id, each of which becomes a store key or a principal.
func printableID(s string) bool {
	return s != "" && len(s) <= 255 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}

// humanPrincipal is user: and the claim's value lower-cased, or why not
// (Ruling 6).
func humanPrincipal(all map[string]json.RawMessage, claim string, verified json.RawMessage) (string, string) {
	var v string
	if json.Unmarshal(all[claim], &v) != nil || v == "" {
		return "", "the token has no " + claim + " string"
	}
	if claim == ClaimEmail {
		var ok bool
		if json.Unmarshal(verified, &ok) != nil || !ok {
			return "", "its email is not verified (email_verified is not true)"
		}
	}
	if len(v) > 255 || strings.IndexFunc(v, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 ||
		!strings.Contains(v, "@") {
		return "", "its " + claim + " is not printable ASCII with an @ (" + printsafe.Line(v, 80) + ")"
	}
	return "user:" + strings.ToLower(v), ""
}

// amr is the claim when it is up to 16 printable strings of up to 64
// bytes; anything else is not recorded (Ruling 10).
func amr(raw json.RawMessage) []string {
	var out []string
	if json.Unmarshal(raw, &out) != nil || len(out) > 16 {
		return nil
	}
	for _, m := range out {
		if len(m) > 64 || !printableID(m) {
			return nil
		}
	}
	return out
}

// acr is the claim when it is one printable string of up to 255 bytes.
func acr(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil || !printableID(s) {
		return ""
	}
	return s
}
```

A note on `humanPrincipal`'s refusal text: it is said only after the signature verified, so the
value is the provider's and `printsafe.Line` bounds it.

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test ./internal/oidc/... -count=1 -race`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/oidc/config.go internal/oidc/verify.go internal/oidc/verify_test.go internal/daemon/metrics/metrics.go
git commit -m "feat(oidc): verifiers per trust domain, exactly one accepting a token; claims within clock_skew and max_token_age; the principal claim

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: The logout token, per Back-Channel Logout 1.0 §2.6

**Files:**
- Create: `internal/oidc/logout.go`
- Modify: `internal/oidc/verify.go` (the signature checks shared)
- Test: `internal/oidc/logout_test.go` (package `oidc_test`)

**Interfaces:**
- Consumes: Task 5's `Set`, `Verifier`, `refuse`, `audiences`, `numericDate`, `printableID`,
  `payload`, `exact`, `humanAudience`.
- Produces:
  - `oidc.LogoutToken{Issuer, Subject, Sid, JTI string; IssuedAt, Expires time.Time; Domains
    []string}`, its `String()` withholding the `jti`; `Domains` is the accepting verifier's
    `PrincipalDomains`, whose principals alone the logout may reach (Ruling 22);
  - `oidc.BackchannelLogoutEvent`, `oidc.MaxLogoutAge` (24h);
  - `(*Set).VerifyLogout(ctx, raw string) (LogoutToken, error)`: its error wraps `ErrInvalid`
    (400) or `ErrUnavailable` (503);
  - `(*Verifier).signature(ctx, j *JWS) error`, shared with `verify`.

- [ ] **Step 1: Write the failing tests**

`internal/oidc/logout_test.go`:

```go
package oidc_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// logoutClaims is a Keycloak-shaped logout token for clientID at now; extra
// overrides, a nil value deleting.
func logoutClaims(iss *oidctest.Issuer, now time.Time, extra map[string]any) map[string]any {
	c := map[string]any{"iss": iss.URL, "aud": clientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": "j-1", "sub": "8b2e", "sid": "s-8b2e",
		"events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}}
	for k, v := range extra {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func logoutToken(t *testing.T, iss *oidctest.Issuer, now time.Time, extra map[string]any) string {
	return iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, logoutClaims(iss, now, extra))
}

func TestALogoutTokenVerifies(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	l, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if l.Issuer != iss.URL || l.Subject != "8b2e" || l.Sid != "s-8b2e" || l.JTI != "j-1" || !l.IssuedAt.Equal(c.Now()) {
		t.Fatalf("logout %+v", l)
	}
	// sid alone, sub alone, and no typ at all are each a logout token.
	for _, extra := range []map[string]any{{"sub": nil}, {"sid": nil}} {
		if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), extra)); err != nil {
			t.Errorf("%v: %v", extra, err)
		}
	}
	if _, err := set.VerifyLogout(context.Background(), iss.Token(t, "k1", logoutClaims(iss, c.Now(), nil))); err != nil {
		t.Errorf("no typ: %v", err)
	}
}

func TestALogoutTokenNeedsWhatBCLRequires(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	for name, extra := range map[string]map[string]any{
		"no jti":                {"jti": nil},
		"no events":             {"events": nil},
		"events without member": {"events": map[string]any{"http://example.com/other": map[string]any{}}},
		"member not an object":  {"events": map[string]any{oidc.BackchannelLogoutEvent: "yes"}},
		"a nonce":               {"nonce": "n"},
		"neither sub nor sid":   {"sub": nil, "sid": nil},
		"no iat":                {"iat": nil},
		"iat a string":          {"iat": fmt.Sprint(c.Now().Unix())},
		"another aud":           {"aud": "other-app"},
		"azp another client":    {"azp": "other-app"},
		"two auds, no azp":      {"aud": []string{clientID, "other-app"}},
		"issued 25h ago":        {"iat": c.Now().Add(-25 * time.Hour).Unix(), "exp": nil},
		"expired":               {"exp": c.Now().Add(-2 * time.Minute).Unix()},
		"issued ahead of skew":  {"iat": c.Now().Add(2 * time.Minute).Unix()},
	} {
		if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), extra)); !errors.Is(err, oidc.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), map[string]any{"exp": nil})); err != nil {
		t.Errorf("no exp, iat now: %v", err)
	}
	if _, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), map[string]any{"azp": clientID})); err != nil {
		t.Errorf("azp the client_id: %v", err)
	}
	// The accepting verifier's domains travel with the logout (Ruling 22).
	if l, err := set.VerifyLogout(context.Background(), logoutToken(t, iss, c.Now(), nil)); err != nil ||
		strings.Join(l.Domains, ",") != "corp.example.com" {
		t.Errorf("domains %v, %v", l.Domains, err)
	}
}

// An ID token is not a logout token, a typ that is not a logout's is
// refused, and a forged signature is refused like a bearer's.
func TestALogoutTokenIsNotAnotherJWT(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	idToken := iss.IDToken(t, "k1", clientID, "8b2e", c.Now(), map[string]any{"email": "a@b", "email_verified": true})
	if _, err := set.VerifyLogout(context.Background(), idToken); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("an ID token: %v", err)
	}
	at := iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "at+jwt"}, logoutClaims(iss, c.Now(), nil))
	if _, err := set.VerifyLogout(context.Background(), at); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("typ at+jwt: %v", err)
	}
	forger := oidctest.NewIssuer(t)
	forged := forger.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, logoutClaims(iss, c.Now(), nil))
	if _, err := set.VerifyLogout(context.Background(), forged); !errors.Is(err, oidc.ErrInvalid) {
		t.Errorf("a forged signature: %v", err)
	}
}

// A machine has no session to end: a logout token for a machine verifier's
// audience is no one's.
func TestAMachineVerifierTakesNoLogout(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, machine(iss))
	raw := logoutToken(t, iss, c.Now(), map[string]any{"aud": "api://port49-svc"})
	if _, err := set.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("a logout for a machine audience: %v", err)
	}
}

func TestALogoutWithTheProviderDownIsUnavailable(t *testing.T) {
	iss, c := oidctest.NewIssuer(t), newClock()
	set := newSet(t, iss, c, human(iss, oidc.ClaimEmail))
	raw := logoutToken(t, iss, c.Now(), nil)
	iss.Close()
	if _, err := set.VerifyLogout(context.Background(), raw); !errors.Is(err, oidc.ErrUnavailable) {
		t.Fatalf("keys never fetched: %v", err)
	}
}

func TestALogoutTokenWithholdsItsJTI(t *testing.T) {
	l := oidc.LogoutToken{Issuer: "https://i", Sid: "s", JTI: "jti-marker"}
	for _, verb := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(verb, l), "jti-marker") {
			t.Fatalf("%s prints the jti", verb)
		}
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/oidc/ -run 'TestALogout|TestAMachineVerifierTakesNoLogout' -count=1`
Expected: FAIL to compile: `VerifyLogout`, `LogoutToken`, `BackchannelLogoutEvent` undefined.

- [ ] **Step 3: Share the signature checks**

In `internal/oidc/verify.go`, replace the first block of `(*Verifier).verify` (from `iss :=
v.Issuer` through the `j.Verify` refusal) with:

```go
	iss := v.Issuer
	if err := v.signature(ctx, j); err != nil {
		return Assertion{}, err
	}
```

and add:

```go
// signature is Ruling 3 for one verifier: an algorithm it pins, the one
// key of its issuer's set the token's kid names, and a signature that key
// verifies. Its refusals name the configured issuer alone.
func (v *Verifier) signature(ctx context.Context, j *JWS) error {
	iss := v.Issuer
	if !slices.Contains(v.Algorithms, j.Header.Alg) {
		return refuse(ErrInvalid, "invalid", "its algorithm is not one %s's %s verifier pins", iss, v.Domain)
	}
	key, err := v.Keys.Key(ctx, j.Header.Kid, j.Header.Alg)
	switch {
	case errors.Is(err, ErrUnavailable), err != nil && ctx.Err() != nil:
		return refuse(ErrUnavailable, "unavailable", "the keys of %s are not available", iss)
	case err != nil:
		return refuse(ErrInvalid, "invalid", "no one key of %s matches its key id", iss)
	}
	if err := j.Verify(key, v.Algorithms); err != nil {
		return refuse(ErrInvalid, "invalid", "its signature does not verify under the keys of %s", iss)
	}
	return nil
}
```

- [ ] **Step 4: Implement the logout token**

`internal/oidc/logout.go`:

```go
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// BackchannelLogoutEvent is the events member a logout token carries
// (OpenID Connect Back-Channel Logout 1.0 §2.4).
const BackchannelLogoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// MaxLogoutAge bounds a logout token's iat: one older is refused, and a jti
// is remembered this long (Ruling 12).
const MaxLogoutAge = 24 * time.Hour

// LogoutToken is a validated logout token. Sid or Subject may be empty,
// never both. Expires is zero when the token carried no exp. Domains is the
// accepting verifier's principal_domains: a logout reaches no principal
// outside them (Ruling 22).
type LogoutToken struct {
	Issuer, Subject, Sid, JTI string
	IssuedAt, Expires         time.Time
	Domains                   []string
}

// String withholds the jti, which a replay check keys on (Ruling 18).
func (l LogoutToken) String() string {
	return fmt.Sprintf("LogoutToken{issuer %s sub %s sid %s iat %s}", l.Issuer, l.Subject, l.Sid,
		l.IssuedAt.UTC().Format(time.RFC3339))
}

// GoString is String.
func (l LogoutToken) GoString() string { return l.String() }

// VerifyLogout is Back-Channel Logout 1.0 §2.6 against the human verifiers
// whose issuer is the token's (Ruling 12): exactly one must accept it.
func (s *Set) VerifyLogout(ctx context.Context, raw string) (LogoutToken, error) {
	j, err := ParseCompact(raw)
	if err != nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it is not a compact JWS")
	}
	var head struct {
		Iss string `json:"iss"`
	}
	_ = json.Unmarshal(j.Payload, &head)
	var vs []*Verifier
	for _, v := range s.ByIssuer(head.Iss) {
		if v.Domain == Humans {
			vs = append(vs, v)
		}
	}
	if len(vs) == 0 {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "no human OIDC verifier accepts its issuer")
	}
	var got []LogoutToken
	var first *refusal
	for _, v := range vs {
		l, err := v.logout(ctx, j, s.Timing, s.Now())
		var r *refusal
		switch {
		case err == nil:
			got = append(got, l)
		case errors.As(err, &r) && (first == nil || errors.Is(r, ErrUnavailable)):
			first = r
		}
	}
	switch {
	case len(got) == 1:
		return got[0], nil
	case len(got) > 1:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "two human verifiers of %s accept it", head.Iss)
	case first == nil:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "no human OIDC verifier accepts it")
	}
	return LogoutToken{}, first
}

func (v *Verifier) logout(ctx context.Context, j *JWS, t Timing, now time.Time) (LogoutToken, error) {
	if err := v.signature(ctx, j); err != nil {
		return LogoutToken{}, err
	}
	switch typ := strings.ToLower(strings.TrimPrefix(strings.ToLower(j.Header.Typ), "application/")); typ {
	case "", "logout+jwt", "jwt":
	default:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its typ %q is not a logout token's", typ)
	}
	all, err := payload(j.Payload)
	if err != nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "%s", err.Error())
	}
	var c struct {
		Iss    string                     `json:"iss"`
		Sub    string                     `json:"sub"`
		Sid    string                     `json:"sid"`
		Jti    string                     `json:"jti"`
		Aud    json.RawMessage            `json:"aud"`
		Azp    string                     `json:"azp"`
		Iat    json.RawMessage            `json:"iat"`
		Exp    json.RawMessage            `json:"exp"`
		Events map[string]json.RawMessage `json:"events"`
	}
	if exact(all, &c, []string{"iss", "sub", "sid", "jti", "aud", "azp", "iat", "exp", "events"}) != nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its claims are not a JSON object of the expected types")
	}
	_, hasNonce := all["nonce"]
	auds, ok := audiences(c.Aud)
	if !ok {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its aud is absent or not a string or a list of strings")
	}
	if r := humanAudience(auds, c.Azp, v.ClientID); r != nil {
		return LogoutToken{}, r // BCL §2.6 step 3: aud and azp as for an ID token (pre-flight M-6)
	}
	switch {
	case c.Iss != v.Issuer:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its iss is not %s", v.Issuer)
	case hasNonce:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it carries a nonce, which a logout token must not "+
			"(Back-Channel Logout §2.4)")
	case !printableID(c.Jti):
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it has no jti")
	case c.Sub == "" && c.Sid == "":
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it names neither a sub nor a sid")
	case c.Sub != "" && !printableID(c.Sub), c.Sid != "" && !printableID(c.Sid):
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its sub or sid is not 1 to 255 printable ASCII characters")
	}
	member, ok := c.Events[BackchannelLogoutEvent]
	var obj map[string]json.RawMessage
	if !ok || json.Unmarshal(member, &obj) != nil || obj == nil {
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "its events claim has no back-channel logout member "+
			"holding a JSON object")
	}
	iat, ok := numericDate(c.Iat)
	switch {
	case !ok:
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it has no iat")
	case iat.After(now.Add(t.ClockSkew)):
		return LogoutToken{}, refuse(ErrInvalid, "invalid", "it was issued ahead of the broker's clock by more than "+
			"broker.identity.clock_skew")
	case now.Sub(iat) > MaxLogoutAge:
		return LogoutToken{}, refuse(ErrInvalid, "expired", "it was issued %s ago, more than %s", now.Sub(iat).Round(time.Minute),
			MaxLogoutAge)
	}
	l := LogoutToken{Issuer: v.Issuer, Subject: c.Sub, Sid: c.Sid, JTI: c.Jti, IssuedAt: iat,
		Domains: slices.Clone(v.PrincipalDomains)}
	if len(c.Exp) != 0 {
		exp, ok := numericDate(c.Exp)
		if !ok || !now.Before(exp.Add(t.ClockSkew)) {
			return LogoutToken{}, refuse(ErrInvalid, "expired", "it has expired")
		}
		l.Expires = exp
	}
	return l, nil
}
```

- [ ] **Step 5: Run the tests to see them pass**

Run: `go test ./internal/oidc/... -count=1 -race`
Expected: PASS, Task 5's tests included (the shared `signature` changed none of their answers).

- [ ] **Step 6: Commit**

```bash
git add internal/oidc/
git commit -m "feat(oidc): back-channel logout tokens validated per BCL 1.0 §2.6 against the human verifiers

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: `broker.identity`: the two lists, the shorthand, the timing

**Files:**
- Create: `internal/config/identity.go`
- Modify: `internal/config/config.go` (`BrokerConfig`, `checkBroker`)
- Test: `internal/config/identity_test.go`

**Interfaces:**
- Consumes: Task 5's `oidc.Config`, `oidc.VerifierConfig`, `oidc.Timing`, `oidc.DefaultTiming`;
  Task 3's `oidc.ParseAlgs`.
- Produces:
  - `BrokerConfig.Identity *oidc.Config` (`yaml:"-"`, always set once `checkBroker` passes) and
    `BrokerConfig.IdentitySet *identityYAML` (`yaml:"identity"`);
  - `BrokerConfig.ClientCAFile` is the resolved x509 anchor, `""` on an OIDC-only broker;
  - `checkIdentity(y *identityYAML, clientCAFile string) (*oidc.Config, error)`;
  - the YAML keys `principal_domains` (humans, required; Ruling 22), `clients: [{client_id,
    sub}]` (machines, required; Ruling 21), and `principal_claim` required (Ruling 23);
  - `principalDomains(at string, ds []string) ([]string, error)`, `identityIssuers(b
    *BrokerConfig) []string`, and `config.BrokerStateDir(b *BrokerConfig) string` (which
    Task 14's `brokerStateDir` calls);
  - each issuer's kept key file (`oidc.KeyFileName`) in `config.go`'s two collision lists
    (pre-flight M-11).

- [ ] **Step 1: Write the failing tests**

`internal/config/identity_test.go`:

```go
package config

import (
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/oidc"
)

// brokerWithIdentity is brokerBlock with client_ca_file replaced by an
// identity block.
func brokerWithIdentity(identity string) string {
	return strings.Replace(brokerBlock, "  client_ca_file: /etc/port49/clients-ca.pem\n", identity, 1)
}

const twoLists = `  identity:
    humans:
      - {type: x509, trust_anchor_file: /etc/port49/clients-ca.pem}
      - type: oidc
        issuer: https://sso.corp.example.com/realms/corp
        client_id: port49-cli
        principal_claim: email
        principal_domains: [Corp.Example.com, corp.example.com, eng.corp.example.com]
        scopes: [email]
    machines:
      - type: oidc
        issuer: https://sso.corp.example.com/realms/corp
        audience: "api://port49-svc"
        clients: [{client_id: oxidized, sub: 5f3c2d1e-0000-4000-8000-000000000049}]
`

func TestTheTwoListsLoad(t *testing.T) {
	c, err := loadWith(t, brokerWithIdentity(twoLists))
	if err != nil {
		t.Fatal(err)
	}
	id := c.Broker.Identity
	if id == nil || id.Shorthand || id.X509AnchorFile != "/etc/port49/clients-ca.pem" ||
		c.Broker.ClientCAFile != "/etc/port49/clients-ca.pem" || len(id.OIDC) != 2 || id.Timing != oidc.DefaultTiming {
		t.Fatalf("identity %+v", id)
	}
	h, m := id.OIDC[0], id.OIDC[1]
	if h.Domain != oidc.Humans || h.ClientID != "port49-cli" || h.PrincipalClaim != oidc.ClaimEmail ||
		strings.Join(h.PrincipalDomains, " ") != "corp.example.com eng.corp.example.com" ||
		strings.Join(h.Scopes, " ") != "openid email" || len(h.Algorithms) != 1 || h.Algorithms[0] != oidc.RS256 {
		t.Fatalf("human %+v: domains lower-cased, once each", h)
	}
	if m.Domain != oidc.Machines || m.Audience != "api://port49-svc" || m.PrincipalClaim != "" ||
		len(m.Clients) != 1 || m.Clients[0] != (oidc.MachineClient{ClientID: "oxidized", Sub: "5f3c2d1e-0000-4000-8000-000000000049"}) {
		t.Fatalf("machine %+v", m)
	}
}

// With no broker.identity, broker.client_ca_file is the one human verifier,
// exactly as before plan 7h.
func TestNoIdentityIsTheShorthand(t *testing.T) {
	c, err := loadWith(t, brokerBlock)
	if err != nil {
		t.Fatal(err)
	}
	if id := c.Broker.Identity; id == nil || !id.Shorthand || id.X509AnchorFile != "/etc/port49/clients-ca.pem" ||
		len(id.OIDC) != 0 {
		t.Fatalf("identity %+v", id)
	}
}

func TestAnOIDCOnlyBrokerLoadsWithoutCertificateStatus(t *testing.T) {
	block := `  identity:
    humans:
      - {type: oidc, issuer: "https://sso.corp.example.com/realms/corp", client_id: port49-cli,
         principal_claim: upn, principal_domains: [corp.example.com]}
`
	noStatus := strings.Replace(brokerWithIdentity(block), "  certificate_status: {disabled: true}\n", "", 1)
	c, err := loadWith(t, noStatus)
	if err != nil {
		t.Fatal(err)
	}
	if c.Broker.ClientCAFile != "" || c.Broker.CertificateStatus != nil || c.Broker.Identity.OIDC[0].PrincipalClaim != oidc.ClaimUPN {
		t.Fatalf("broker %+v identity %+v", c.Broker, c.Broker.Identity)
	}
	if _, err := loadWith(t, brokerWithIdentity(block)); err == nil ||
		!strings.Contains(err.Error(), "broker.certificate_status: no x509 verifier") {
		t.Fatalf("certificate_status on an OIDC-only broker: %v", err)
	}
}

func TestIdentityRefusals(t *testing.T) {
	iss := `issuer: "https://sso.corp.example.com/realms/corp"`
	// hum and mach are complete verifiers, so each case fails on the one
	// thing it names.
	hum := "type: oidc, " + iss + ", client_id: c, principal_claim: email, principal_domains: [corp.example.com]"
	mach := "type: oidc, " + iss + ", audience: a, clients: [{client_id: svc, sub: s1}]"
	other := `type: oidc, issuer: "https://contractor.example.net/realms/x", client_id: c, principal_claim: email`
	for name, c := range map[string]struct{ block, want string }{
		"client_ca_file beside identity": {strings.Replace(twoLists, "  identity:", "  client_ca_file: /etc/port49/clients-ca.pem\n  identity:", 1),
			"broker.client_ca_file: moved to broker.identity.humans[].trust_anchor_file"},
		"workload x509": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem}]\n    machines: [{type: x509, trust_anchor_file: /b.pem}]\n",
			"broker.identity.machines[0]: type x509 (workload certificates) is plan 8's"},
		"k8s": {"  identity:\n    machines: [{type: k8s}]\n", "broker.identity.machines[0]: type k8s is plan 10's"},
		"two anchors": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem}, {type: x509, trust_anchor_file: /b.pem}]\n",
			"broker.identity.humans: at most one x509 verifier"},
		"domains on an x509 verifier": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[0]: type x509 takes trust_anchor_file alone"},
		"none": {"  identity:\n    humans: []\n", "broker.identity accepts no one"},
		"HS256": {"  identity:\n    humans: [{" + hum + ", algorithms: [HS256]}]\n",
			"broker.identity.humans[0].algorithms: HS256 is refused"},
		"none alg": {"  identity:\n    humans: [{" + hum + ", algorithms: [none]}]\n",
			"broker.identity.humans[0].algorithms: none is refused"},
		"http issuer": {"  identity:\n    humans: [{type: oidc, issuer: \"http://sso.example.com\", client_id: c}]\n",
			"broker.identity.humans[0].issuer"},
		"ca_file unreadable": {"  identity:\n    humans: [{" + hum + ", ca_file: /nonexistent/port49-idp-ca.pem}]\n",
			"broker.identity.humans[0].ca_file /nonexistent/port49-idp-ca.pem"},
		"no client_id": {"  identity:\n    humans: [{type: oidc, " + iss + "}]\n", "broker.identity.humans[0].client_id is required"},
		"audience on a human": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, audience: a}]\n",
			"broker.identity.humans[0].audience"},
		"clients on a human": {"  identity:\n    humans: [{" + hum + ", clients: [{client_id: svc, sub: s1}]}]\n",
			"broker.identity.humans[0].clients is a machine verifier's"},
		"no principal_claim": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[0].principal_claim is required: one of preferred_username, email or upn"},
		"bad claim": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_claim: groups}]\n",
			"broker.identity.humans[0].principal_claim groups: one of preferred_username, email or upn"},
		"no principal_domains": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_claim: email}]\n",
			"broker.identity.humans[0].principal_domains is required"},
		"a domain with an @": {"  identity:\n    humans: [{type: oidc, " + iss + ", client_id: c, principal_claim: email, principal_domains: [a@corp.example.com]}]\n",
			"broker.identity.humans[0].principal_domains: a@corp.example.com is not a domain"},
		"domains overlap across issuers": {"  identity:\n    humans: [{" + hum + "}, {" + other + ", principal_domains: [Corp.Example.com]}]\n",
			"broker.identity.humans[1].principal_domains: corp.example.com is also broker.identity.humans[0]'s, at another issuer"},
		"two claims at one issuer": {"  identity:\n    humans: [{" + hum + "}, {type: oidc, " + iss + ", client_id: c2, principal_claim: upn, principal_domains: [corp.example.com]}]\n",
			"broker.identity.humans[1].principal_claim upn differs from broker.identity.humans[0]'s (email) at one issuer"},
		"client_id on a machine": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, client_id: c}]\n",
			"broker.identity.machines[0].client_id"},
		"domains on a machine": {"  identity:\n    machines: [{" + mach + ", principal_domains: [corp.example.com]}]\n",
			"broker.identity.machines[0].client_id, principal_claim, principal_domains and scopes are a human verifier's"},
		"no clients": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a}]\n",
			"broker.identity.machines[0].clients is required"},
		"a client without its sub": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: svc}]}]\n",
			"broker.identity.machines[0].clients[0].sub is required"},
		"one client at two issuers": {"  identity:\n    machines: [{" + mach + "}, {type: oidc, issuer: \"https://contractor.example.net/realms/x\", audience: a, clients: [{client_id: svc, sub: s9}]}]\n",
			"broker.identity.machines[1].clients: svc is also broker.identity.machines[0]'s, at another issuer"},
		"a client twice": {"  identity:\n    machines: [{type: oidc, " + iss + ", audience: a, clients: [{client_id: svc, sub: s1}, {client_id: svc, sub: s2}]}]\n",
			"broker.identity.machines[0].clients[1] repeats client_id svc"},
		"one key twice": {"  identity:\n    humans: [{" + hum + "}]\n    machines: [{type: oidc, " + iss + ", audience: c, clients: [{client_id: svc, sub: s1}]}]\n",
			"broker.identity.machines[0].audience c is broker.identity.humans[0]'s client_id"},
		"a verifier twice": {"  identity:\n    humans: [{" + hum + "}, {" + hum + "}]\n",
			"broker.identity.humans[1] repeats broker.identity.humans[0]"},
		"skew": {"  identity:\n    clock_skew: 10m\n    humans: [{" + hum + "}]\n",
			"broker.identity.clock_skew"},
		"max age under twice the refresh": {"  identity:\n    jwks_refresh_interval: 1h\n    jwks_max_age: 90m\n    humans: [{" + hum + "}]\n",
			"broker.identity.jwks_max_age 1h30m0s is under twice jwks_refresh_interval"},
		"unknown type": {"  identity:\n    humans: [{type: saml}]\n", "broker.identity.humans[0].type saml"},
	} {
		block := c.block
		cfg := brokerWithIdentity(block) // the client_ca_file case carries its own line in block
		if !strings.Contains(block, "x509") {
			cfg = strings.Replace(cfg, "  certificate_status: {disabled: true}\n", "", 1)
		}
		_, err := loadWith(t, cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v; want %q", name, err, c.want)
		}
	}
}

func TestIdentityTimingDefaultsAndBounds(t *testing.T) {
	block := `  identity:
    clock_skew: 0s
    max_token_age: 1h
    jwks_refresh_interval: 30m
    jwks_max_age: 72h
    humans: [{type: oidc, issuer: "https://sso.corp.example.com/realms/corp", client_id: c, principal_claim: email,
              principal_domains: [corp.example.com], algorithms: [ES256, RS256]}]
`
	c, err := loadWith(t, strings.Replace(brokerWithIdentity(block), "  certificate_status: {disabled: true}\n", "", 1))
	if err != nil {
		t.Fatal(err)
	}
	want := oidc.Timing{ClockSkew: 0, MaxTokenAge: time.Hour, JWKSRefresh: 30 * time.Minute, JWKSMaxAge: 72 * time.Hour}
	if c.Broker.Identity.Timing != want || len(c.Broker.Identity.OIDC[0].Algorithms) != 2 {
		t.Fatalf("identity %+v", c.Broker.Identity)
	}
}

// An issuer's kept key file collides with no file another key names
// (pre-flight M-11): it sits beside revocations_file in port49d.
func TestAKeptKeyFileCollidesWithNothing(t *testing.T) {
	cfg := strings.Replace(brokerWithIdentity(twoLists), "/var/lib/port49/revocations.json",
		"/var/lib/port49/"+oidc.KeyFileName("https://sso.corp.example.com/realms/corp"), 1)
	if _, err := loadWith(t, cfg); err == nil || !strings.Contains(err.Error(), "kept keys") {
		t.Fatalf("a revocations_file that is an issuer's kept key file: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/config/ -run 'TestTheTwoLists|TestNoIdentity|TestAnOIDCOnly|TestIdentityRefusals|TestIdentityTiming|TestAKeptKeyFile|TestABrokerBlockMissingAKeyIsRefused' -count=1`
Expected: FAIL: `Identity` is not a field of `BrokerConfig`, and `identity:` is an unknown key.

- [ ] **Step 3: Implement**

`internal/config/identity.go`:

```go
package config

import (
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/oidc"
)

// identityVerifierYAML is one entry of broker.identity.humans or .machines
// (plan 7h, Ruling 1).
type identityVerifierYAML struct {
	Type             string              `yaml:"type"`
	TrustAnchorFile  string              `yaml:"trust_anchor_file"`
	Issuer           string              `yaml:"issuer"`
	ClientID         string              `yaml:"client_id"`
	Audience         string              `yaml:"audience"`
	PrincipalClaim   string              `yaml:"principal_claim"`
	PrincipalDomains []string            `yaml:"principal_domains"`
	Clients          []machineClientYAML `yaml:"clients"`
	Scopes           []string            `yaml:"scopes"`
	Algorithms       []string            `yaml:"algorithms"`
	CAFile           string              `yaml:"ca_file"`
}

// machineClientYAML is one entry of a machine verifier's clients (Ruling
// 21): a client id, and the sub its client-credentials tokens carry.
type machineClientYAML struct {
	ClientID string `yaml:"client_id"`
	Sub      string `yaml:"sub"`
}

// identityYAML is broker.identity (spec §13 decisions 16 and 39).
type identityYAML struct {
	Humans              []identityVerifierYAML `yaml:"humans"`
	Machines            []identityVerifierYAML `yaml:"machines"`
	ClockSkew           *time.Duration         `yaml:"clock_skew"`
	MaxTokenAge         *time.Duration         `yaml:"max_token_age"`
	JWKSRefreshInterval *time.Duration         `yaml:"jwks_refresh_interval"`
	JWKSMaxAge          *time.Duration         `yaml:"jwks_max_age"`
}

// checkIdentity resolves broker.identity, or, with none, the shorthand:
// broker.client_ca_file as the one x509 human verifier.
func checkIdentity(y *identityYAML, clientCAFile string) (*oidc.Config, error) {
	if y == nil {
		if clientCAFile == "" {
			return nil, errors.New("config: broker.client_ca_file is required when broker: is present and " +
				"broker.identity is not; or list the verifiers under broker.identity")
		}
		return &oidc.Config{X509AnchorFile: clientCAFile, Shorthand: true, Timing: oidc.DefaultTiming}, nil
	}
	if clientCAFile != "" {
		return nil, errors.New("config: broker.client_ca_file: moved to broker.identity.humans[].trust_anchor_file; " +
			"set one or the other")
	}
	t, err := identityTiming(*y)
	if err != nil {
		return nil, err
	}
	out := &oidc.Config{Timing: t}
	for _, list := range []struct {
		domain oidc.Domain
		vs     []identityVerifierYAML
	}{{oidc.Humans, y.Humans}, {oidc.Machines, y.Machines}} {
		for i, v := range list.vs {
			at := fmt.Sprintf("broker.identity.%s[%d]", list.domain, i)
			switch {
			case v.Type == "x509" && list.domain == oidc.Machines:
				return nil, fmt.Errorf("config: %s: type x509 (workload certificates) is plan 8's; remove it", at)
			case v.Type == "k8s":
				return nil, fmt.Errorf("config: %s: type k8s is plan 10's; remove it", at)
			case v.Type == "x509":
				if out.X509AnchorFile != "" {
					return nil, errors.New("config: broker.identity.humans: at most one x509 verifier (the broker " +
						"verifies a chain against one anchor)")
				}
				if v.TrustAnchorFile == "" || v.Issuer != "" || v.ClientID != "" || v.Audience != "" ||
					v.PrincipalClaim != "" || v.PrincipalDomains != nil || v.Clients != nil || v.Scopes != nil ||
					v.Algorithms != nil || v.CAFile != "" {
					return nil, fmt.Errorf("config: %s: type x509 takes trust_anchor_file alone", at)
				}
				out.X509AnchorFile = v.TrustAnchorFile
			case v.Type == "oidc":
				vc, err := checkOIDCVerifier(at, list.domain, v)
				if err != nil {
					return nil, err
				}
				out.OIDC = append(out.OIDC, vc)
			default:
				return nil, fmt.Errorf("config: %s.type %s: one of x509 or oidc (k8s is plan 10's)", at, v.Type)
			}
		}
	}
	if out.X509AnchorFile == "" && len(out.OIDC) == 0 {
		return nil, errors.New("config: broker.identity accepts no one: list at least one verifier under humans " +
			"or machines")
	}
	if err := distinctVerifiers(out.OIDC, *y); err != nil {
		return nil, err
	}
	return out, nil
}

func checkOIDCVerifier(at string, d oidc.Domain, v identityVerifierYAML) (oidc.VerifierConfig, error) {
	u, err := url.Parse(v.Issuer)
	if v.Issuer == "" || err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.issuer must be an https URL with no query or fragment "+
			"(OpenID Connect Discovery §2)", at)
	}
	if v.TrustAnchorFile != "" {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.trust_anchor_file is x509's; an oidc verifier's "+
			"provider anchor is ca_file", at)
	}
	algs, err := oidc.ParseAlgs(v.Algorithms)
	if err != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.algorithms: %w", at, err)
	}
	if v.CAFile != "" {
		if err := readableFile(at+".ca_file", v.CAFile); err != nil {
			return oidc.VerifierConfig{}, fmt.Errorf("config: %w", err) // pre-flight M-11
		}
	}
	out := oidc.VerifierConfig{Domain: d, Issuer: v.Issuer, Algorithms: algs, CAFile: v.CAFile}
	switch d {
	case oidc.Humans:
		switch {
		case !printableKey(v.ClientID):
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.client_id is required: the public client's id, "+
				"which a person's ID token names in aud", at)
		case v.Audience != "":
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.audience is a machine verifier's; a human "+
				"verifier is keyed by client_id", at)
		case v.Clients != nil:
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.clients is a machine verifier's; a human verifier "+
				"names principal_domains", at)
		case v.PrincipalClaim == "":
			// No default (decision 39 ruling 23): OpenID Connect Core §5.7 says
			// preferred_username is not unique, and Keycloak's documented default is
			// a bare username (L46 measures it).
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.principal_claim is required: one of "+
				"preferred_username, email or upn, whichever only your provider's administrators can set", at)
		case !slices.Contains([]string{oidc.ClaimPreferredUsername, oidc.ClaimEmail, oidc.ClaimUPN}, v.PrincipalClaim):
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.principal_claim %s: one of preferred_username, "+
				"email or upn", at, v.PrincipalClaim)
		}
		domains, err := principalDomains(at, v.PrincipalDomains)
		if err != nil {
			return oidc.VerifierConfig{}, err
		}
		scopes := []string{"openid"}
		for _, s := range v.Scopes {
			if !printableKey(s) {
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s.scopes: a scope is printable ASCII with no space", at)
			}
			if !slices.Contains(scopes, s) {
				scopes = append(scopes, s)
			}
		}
		out.ClientID, out.PrincipalClaim, out.PrincipalDomains, out.Scopes = v.ClientID, v.PrincipalClaim, domains, scopes
	case oidc.Machines:
		switch {
		case !printableKey(v.Audience):
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.audience is required: the API identifier a "+
				"client-credentials token names in aud", at)
		case v.ClientID != "", v.PrincipalClaim != "", v.PrincipalDomains != nil, v.Scopes != nil:
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.client_id, principal_claim, principal_domains and "+
				"scopes are a human verifier's; a machine's principal is app:<azp>, a client listed in clients", at)
		case len(v.Clients) == 0:
			return oidc.VerifierConfig{}, fmt.Errorf("config: %s.clients is required: each client_id that may be a "+
				"machine principal, with its sub at the provider (decision 39 ruling 21)", at)
		}
		for i, c := range v.Clients {
			ca := fmt.Sprintf("%s.clients[%d]", at, i)
			switch {
			case !printableKey(c.ClientID):
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s.client_id is required", ca)
			case !printableKey(c.Sub):
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s.sub is required: the client's own identity at "+
					"the provider (Keycloak: the service-account user's id; Entra ID: the service principal's object "+
					"id), which its client-credentials tokens carry as sub and no person's token does", ca)
			case slices.ContainsFunc(out.Clients, func(m oidc.MachineClient) bool { return m.ClientID == c.ClientID }):
				return oidc.VerifierConfig{}, fmt.Errorf("config: %s repeats client_id %s", ca, c.ClientID)
			}
			out.Clients = append(out.Clients, oidc.MachineClient{ClientID: c.ClientID, Sub: c.Sub})
		}
		out.Audience = v.Audience
	}
	return out, nil
}

// principalDomains is a human verifier's principal_domains, lower-cased
// and once each (decision 39 ruling 22): at least one, each a domain with
// a dot, no @ and no leading dot. A domain is matched exactly: no
// subdomain is implied.
func principalDomains(at string, ds []string) ([]string, error) {
	if len(ds) == 0 {
		return nil, fmt.Errorf("config: %s.principal_domains is required: the domains whose people this verifier "+
			"may name (user:<name>@<domain>), so no other provider can name them", at)
	}
	var out []string
	for _, d := range ds {
		l := strings.ToLower(d)
		if !printableKey(l) || strings.ContainsAny(l, "@/") || strings.HasPrefix(l, ".") || !strings.Contains(l, ".") {
			return nil, fmt.Errorf("config: %s.principal_domains: %s is not a domain (a name with a dot, no @)", at, d)
		}
		if !slices.Contains(out, l) {
			out = append(out, l)
		}
	}
	return out, nil
}

// distinctVerifiers refuses a verifier listed twice; a human's client_id
// equal to a machine's audience at one issuer, since a token naming it
// would be both lists' and refused at every request (Ruling 2); two human
// verifiers at one issuer with different principal claims, which would give
// one sub two principals (Ruling 24); and two human verifiers at different
// issuers whose principal_domains overlap, which would let either issuer
// name the other's people (Ruling 22).
func distinctVerifiers(vs []oidc.VerifierConfig, y identityYAML) error {
	name := func(i int) string {
		if i < len(y.Humans) {
			return fmt.Sprintf("broker.identity.humans[%d]", i)
		}
		return fmt.Sprintf("broker.identity.machines[%d]", i-len(y.Humans))
	}
	// vs is in list order, humans first, and only the oidc entries; index
	// them back to their place in the file.
	var at []int
	for i, v := range y.Humans {
		if v.Type == "oidc" {
			at = append(at, i)
		}
	}
	for i, v := range y.Machines {
		if v.Type == "oidc" {
			at = append(at, len(y.Humans)+i)
		}
	}
	key := func(v oidc.VerifierConfig) string { return v.ClientID + v.Audience }
	for i := range vs {
		for j := range i {
			a, b := vs[j], vs[i]
			humans := a.Domain == oidc.Humans && b.Domain == oidc.Humans
			if a.Issuer != b.Issuer {
				if a.Domain == oidc.Machines && b.Domain == oidc.Machines {
					for _, c := range b.Clients {
						if slices.ContainsFunc(a.Clients, func(x oidc.MachineClient) bool { return x.ClientID == c.ClientID }) {
							return fmt.Errorf("config: %s.clients: %s is also %s's, at another issuer: two issuers "+
								"would give one principal (decision 39 ruling 22)", name(at[i]), c.ClientID, name(at[j]))
						}
					}
				}
				if !humans {
					continue
				}
				for _, d := range b.PrincipalDomains {
					if slices.Contains(a.PrincipalDomains, d) {
						return fmt.Errorf("config: %s.principal_domains: %s is also %s's, at another issuer: two issuers "+
							"would give one principal (decision 39 ruling 22)", name(at[i]), d, name(at[j]))
					}
				}
				continue
			}
			switch {
			case a.Domain == b.Domain && key(a) == key(b):
				return fmt.Errorf("config: %s repeats %s", name(at[i]), name(at[j]))
			case a.Domain != b.Domain && key(a) == key(b):
				return fmt.Errorf("config: %s.audience %s is %s's client_id: a token naming it would be both "+
					"lists', and refused", name(at[i]), b.Audience, name(at[j]))
			case humans && a.PrincipalClaim != b.PrincipalClaim:
				return fmt.Errorf("config: %s.principal_claim %s differs from %s's (%s) at one issuer: one sub would "+
					"be two principals (decision 39 ruling 24)", name(at[i]), b.PrincipalClaim, name(at[j]), a.PrincipalClaim)
			}
		}
	}
	return nil
}

func identityTiming(y identityYAML) (oidc.Timing, error) {
	t := oidc.DefaultTiming
	for _, b := range []struct {
		key      string
		v        *time.Duration
		into     *time.Duration
		min, max time.Duration
	}{
		{"clock_skew", y.ClockSkew, &t.ClockSkew, 0, 5 * time.Minute},
		{"max_token_age", y.MaxTokenAge, &t.MaxTokenAge, 5 * time.Minute, 24 * time.Hour},
		{"jwks_refresh_interval", y.JWKSRefreshInterval, &t.JWKSRefresh, 5 * time.Minute, 24 * time.Hour},
		{"jwks_max_age", y.JWKSMaxAge, &t.JWKSMaxAge, 10 * time.Minute, 30 * 24 * time.Hour},
	} {
		if b.v == nil {
			continue
		}
		if *b.v < b.min || *b.v > b.max {
			return oidc.Timing{}, fmt.Errorf("config: broker.identity.%s must be between %s and %s; got %s", b.key,
				b.min, b.max, *b.v)
		}
		*b.into = *b.v
	}
	if t.JWKSMaxAge < 2*t.JWKSRefresh {
		return oidc.Timing{}, fmt.Errorf("config: broker.identity.jwks_max_age %s is under twice jwks_refresh_interval "+
			"(%s): one missed refresh would refuse every token", t.JWKSMaxAge, t.JWKSRefresh)
	}
	return t, nil
}

// printableKey is a non-empty value of printable ASCII with no space, up to
// 255 bytes: a client id, an audience, a scope.
func printableKey(s string) bool {
	return s != "" && len(s) <= 255 && strings.IndexFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0
}
```

In `internal/config/config.go`, in `BrokerConfig` after `RefreshInterval`:

```go
	// Identity is broker.identity resolved (plan 7h): the verifier lists,
	// or the shorthand of client_ca_file alone. Always set once checked.
	// ClientCAFile is then its x509 anchor, "" on an OIDC-only broker.
	Identity    *oidc.Config  `yaml:"-"`
	IdentitySet *identityYAML `yaml:"identity"`
```

and change `ClientCAFile`'s comment to "ClientCAFile is the one trust anchor client certificates
are verified against: broker.client_ca_file when there is no broker.identity, else the x509
human verifier's trust_anchor_file, \"\" when there is none (plan 7h)."

In `checkBroker`, before `required` and before either collision list below is built:

```go
	id, err := checkIdentity(b.IdentitySet, b.ClientCAFile)
	if err != nil {
		return nil, err
	}
	b.Identity, b.ClientCAFile = id, id.X509AnchorFile
```

remove `{"broker.client_ca_file", b.ClientCAFile}` from `required`, and replace the
`certificate_status` block with:

```go
	switch {
	case b.CertificateStatus == nil && b.ClientCAFile != "":
		return nil, fmt.Errorf("config: broker.certificate_status is required when broker: is present: " +
			"name the CRLs or OCSP responder that say whether a client certificate is revoked, or set " +
			"certificate_status: {disabled: true} to check none (spec §5.1.4)")
	case b.CertificateStatus != nil && b.ClientCAFile == "":
		return nil, errors.New("config: broker.certificate_status: no x509 verifier is configured, so no client " +
			"certificate is checked; remove it")
	case b.CertificateStatus != nil:
		cs := *b.CertificateStatus
		if err := checkCertificateStatus(&cs, b); err != nil {
			return nil, err
		}
		b.CertificateStatus = &cs
	}
```

(`ri, err := refreshInterval(…)` below still compiles: `ri` is new.) Import
`github.com/blanketfish/port49/internal/oidc` in `config.go`.

Every other reader of `b.ClientCAFile` in `config.go` (`ownRevocationsFile`'s and the kept-CRL
path's lists of files that may not collide) already skips an empty path (`if o.path == ""`);
check each and add the skip where it is missing.

Both of those lists (`config.go` near l.1643 and l.1755) gain one entry per OIDC issuer, its kept
key file (pre-flight M-11):

```go
	for _, iss := range identityIssuers(b) {
		others = append(others, struct{ key, path string }{"broker.identity's kept keys for " + iss,
			filepath.Join(BrokerStateDir(b), oidc.KeyFileName(iss))})
	}
```

with, in `identity.go`:

```go
// identityIssuers is each OIDC issuer of b's identity, once.
func identityIssuers(b *BrokerConfig) []string {
	var out []string
	if b.Identity != nil {
		for _, v := range b.Identity.OIDC {
			if !slices.Contains(out, v.Issuer) {
				out = append(out, v.Issuer)
			}
		}
	}
	return out
}

// BrokerStateDir is where the broker keeps its own state: broker.state_dir
// on port49-broker, else the directory holding broker.revocations_file, as
// the kept CRLs are (plan 7b). port49d's brokerStateDir is this (Task 14).
func BrokerStateDir(b *BrokerConfig) string {
	if b.StateDir != "" {
		return b.StateDir
	}
	return filepath.Dir(b.RevocationsFile)
}
```

(`path/filepath` joins `identity.go`'s imports.) `checkIdentity` must have run before either
list is built, so `b.Identity` is set; if a list is built outside `checkBroker`, or ahead of
the call placed above, move the call ahead of it.

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./internal/config/ -count=1`
Expected: PASS, with `TestABrokerBlockMissingAKeyIsRefused` still naming `broker.client_ca_file`
(the shorthand's refusal says it).

- [ ] **Step 5: Commit**

```bash
git add internal/config/identity.go internal/config/identity_test.go internal/config/config.go
git commit -m "feat(config): broker.identity's humans and machines, the client_ca_file shorthand, and the OIDC timing

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: The store: once-only records, the OIDC owner, the logout record

**Files:**
- Modify: `internal/store/store.go`
- Modify: `internal/store/memory/memory.go`, `internal/store/crypt/crypt.go`,
  `internal/store/guard/guard.go`
- Create: `internal/store/etcd/oidc.go`
- Modify: `internal/store/etcd/keys.go`, `internal/store/etcd/roles.go`,
  `internal/store/etcd/roles_test.go`
- Create: `internal/store/storetest/oidc.go`
- Modify: `internal/store/storetest/storetest.go` (`Run`)
- Modify: `internal/daemon/authen/authen_test.go` (`noStore`)

**Interfaces:**
- Consumes: Task 2's `store.OIDCKey`.
- Produces, on `store.Store`:
  - `PutOnce(ctx, key string, value []byte, ttl time.Duration) (bool, error)`;
  - `TakeOnce(ctx, key string) ([]byte, error)`;
  - `PutOIDCOwner(ctx, key, principal string, ttl time.Duration) error`: adds principal to the
    record's set, or renews its entry, by compare-and-set (Ruling 24; pre-flight I-1);
  - `OIDCOwner(ctx, key string) (store.OIDCOwner, error)`: every live entry, sorted;
  - `PutLogout(ctx, l store.Logout, ttl time.Duration) error`;
  - `GetLogout(ctx, key string) (store.Logout, error)`;
- and `store.OIDCOwner{Principals []OwnerPrincipal}` with `(OIDCOwner).Entry(principal string)
  (OwnerPrincipal, bool)` and `(OIDCOwner).Names() []string`, `store.OwnerPrincipal{Principal
  string; WrittenAt, ExpiresAt time.Time}`, `store.Logout{Key string; At time.Time; Origin
  string}`, and the `storetest` properties `OncePutsOnceAndTakesOnce`, `OnceExpires`,
  `OnceRaces`, `OIDCOwnerKeepsEveryPrincipal`, `OIDCOwnerMergesUnderARace`,
  `LogoutKeepsTheLaterAndExpires`.

- [ ] **Step 1: Write the failing properties**

`internal/store/storetest/oidc.go`:

```go
package storetest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/store"
)

// OncePutsOnceAndTakesOnce: a once-only record is written only where none
// lives, and taken once (plan 7h, Rulings 12 and 15).
func OncePutsOnceAndTakesOnce(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	if ok, err := s.PutOnce(ctx, "jti a", []byte("v1"), time.Hour); err != nil || !ok {
		t.Fatalf("the first put: %v %v", ok, err)
	}
	if ok, err := s.PutOnce(ctx, "jti a", []byte("v2"), time.Hour); err != nil || ok {
		t.Fatalf("a second put wrote: %v %v", ok, err)
	}
	v, err := s.TakeOnce(ctx, "jti a")
	if err != nil || !bytes.Equal(v, []byte("v1")) {
		t.Fatalf("take: %q %v", v, err)
	}
	if _, err := s.TakeOnce(ctx, "jti a"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a second take: %v", err)
	}
	if ok, err := s.PutOnce(ctx, "jti a", []byte("v3"), time.Hour); err != nil || !ok {
		t.Fatalf("a put after the take: %v %v", ok, err)
	}
	if _, err := s.TakeOnce(ctx, "never"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("taking a key never put: %v", err)
	}
}

// OnceExpires: past its TTL a record is gone for a take and for a put.
func OnceExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	if ok, _ := s.PutOnce(ctx, "challenge x", []byte("v"), time.Minute); !ok {
		t.Fatal("the put")
	}
	mu.Lock()
	now = now.Add(2 * time.Minute)
	mu.Unlock()
	if _, err := s.TakeOnce(ctx, "challenge x"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an expired record was taken: %v", err)
	}
	if ok, err := s.PutOnce(ctx, "challenge x", []byte("w"), time.Minute); err != nil || !ok {
		t.Fatalf("a put over an expired record: %v %v", ok, err)
	}
}

// OnceRaces: of many concurrent puts one writes, and of many concurrent
// takes one gets the value.
func OnceRaces(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	for round := range 20 {
		key := "race " + string(rune('a'+round))
		var wrote, took atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, err := s.PutOnce(ctx, key, []byte("v"), time.Hour); err == nil && ok {
					wrote.Add(1)
				}
			}()
		}
		wg.Wait()
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.TakeOnce(ctx, key); err == nil {
					took.Add(1)
				}
			}()
		}
		wg.Wait()
		if wrote.Load() != 1 || took.Load() != 1 {
			t.Fatalf("round %d: %d puts wrote, %d takes took", round, wrote.Load(), took.Load())
		}
	}
}

// OIDCOwnerKeepsEveryPrincipal: an owner record holds every principal
// written under it, each with its own life and its last WrittenAt, and
// lapses with the last of them (plan 7h, Ruling 24; pre-flight I-1). A
// rename under one sub adds a principal; it never replaces one.
func OIDCOwnerKeepsEveryPrincipal(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	key := store.OIDCKey(store.OIDCSub, "https://sso.example.com", "8b2e")
	if _, err := s.OIDCOwner(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an owner never written: %v", err)
	}
	put := func(p string, ttl time.Duration) {
		t.Helper()
		if err := s.PutOIDCOwner(ctx, key, p, ttl); err != nil {
			t.Fatal(err)
		}
	}
	put("user:alice@example.com", time.Hour)
	advance(10 * time.Minute)
	put("user:alice@example.com", time.Hour)    // renewed: one entry, WrittenAt moves
	put("user:alice2@example.com", 2*time.Hour) // renamed: a second entry
	o, err := s.OIDCOwner(ctx, key)
	if err != nil || strings.Join(o.Names(), ",") != "user:alice2@example.com,user:alice@example.com" {
		t.Fatalf("owner %+v %v: both principals, sorted", o, err)
	}
	if a, ok := o.Entry("user:alice@example.com"); !ok || !a.WrittenAt.Equal(t0.Add(10*time.Minute)) ||
		!a.ExpiresAt.Equal(t0.Add(70*time.Minute)) {
		t.Fatalf("alice's entry %+v", a)
	}
	advance(61 * time.Minute) // alice's entry lapsed; alice2's stands
	if o, err := s.OIDCOwner(ctx, key); err != nil || strings.Join(o.Names(), ",") != "user:alice2@example.com" {
		t.Fatalf("after alice's entry lapsed: %+v %v", o, err)
	}
	advance(time.Hour)
	if _, err := s.OIDCOwner(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("an owner past every entry's life: %v", err)
	}
	if err := s.PutOIDCOwner(ctx, "", "user:x@example.com", time.Hour); !errors.Is(err, store.ErrNoKey) {
		t.Fatalf("an owner with no key: %v", err)
	}
}

// OIDCOwnerMergesUnderARace: concurrent writes of different principals
// under one key all land; a compare-and-set merge loses none.
func OIDCOwnerMergesUnderARace(t *testing.T, b Backend) {
	ctx := context.Background()
	s := b.New(t, func() time.Time { return t0 })
	key := store.OIDCKey(store.OIDCSid, "https://sso.example.com", "s-race")
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.PutOIDCOwner(ctx, key, fmt.Sprintf("user:p%d@example.com", i), time.Hour); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if o, err := s.OIDCOwner(ctx, key); err != nil || len(o.Principals) != 8 {
		t.Fatalf("%d of 8 principals kept: %v", len(o.Principals), err)
	}
}

// LogoutKeepsTheLaterAndExpires: of two logouts under one key the later
// At stands, with the longer life; past it the record is gone.
func LogoutKeepsTheLaterAndExpires(t *testing.T, b Backend) {
	ctx := context.Background()
	var mu sync.Mutex
	now := t0
	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
	key := store.OIDCKey(store.OIDCSub, "https://sso.example.com", "8b2e")
	if _, err := s.GetLogout(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a logout never written: %v", err)
	}
	if err := s.PutLogout(ctx, store.Logout{Key: key, At: t0, Origin: "backchannel_logout x"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.PutLogout(ctx, store.Logout{Key: key, At: t0.Add(-time.Minute), Origin: "older"}, 3*time.Hour); err != nil {
		t.Fatal(err)
	}
	l, err := s.GetLogout(ctx, key)
	if err != nil || !l.At.Equal(t0) || l.Origin != "backchannel_logout x" || l.Key != key {
		t.Fatalf("logout %+v %v: the later At stands", l, err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if _, err := s.GetLogout(ctx, key); err != nil {
		t.Fatalf("the longer life was not kept: %v", err)
	}
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	if _, err := s.GetLogout(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a logout past its life: %v", err)
	}
	if err := s.PutLogout(ctx, store.Logout{Key: "", At: t0}, time.Hour); err == nil {
		t.Fatal("a logout with no key was written")
	}
}
```

In `internal/store/storetest/storetest.go`'s `Run`, add to the third list, the one of
`func(*testing.T, Backend)` properties (`storetest.go:1043`, after `SwapLoginIsOneStep`'s
neighbours; pre-flight M-10):

```go
		{"OncePutsOnceAndTakesOnce", OncePutsOnceAndTakesOnce},
		{"OnceExpires", OnceExpires},
		{"OnceRaces", OnceRaces},
		{"OIDCOwnerKeepsEveryPrincipal", OIDCOwnerKeepsEveryPrincipal},
		{"OIDCOwnerMergesUnderARace", OIDCOwnerMergesUnderARace},
		{"LogoutKeepsTheLaterAndExpires", LogoutKeepsTheLaterAndExpires},
```

In `internal/store/etcd/roles_test.go`'s `TestCheckIdentityRefusesADaemonThatCanWriteTheLedgerRecord`
(l.168), add a read case and a write case for each of `on/`, `oo/` and `lo/`, as its `mb/` and
`mk/` cases are written (pre-flight M-10):

```go
	once, owner, logout := newKeys(prefix).family(famOnce), newKeys(prefix).family(famOIDCOwner),
		newKeys(prefix).family(famLogout)
```

and, in its table, for each `fam` of `once`, `owner`, `logout`:

```go
		{etcdtest.Grant{Role: RoleDaemon, Key: fam, RangeEnd: clientv3.GetPrefixRangeEnd(fam)},
			"it was allowed reading " + fam},
		{etcdtest.Grant{Role: RoleDaemon, Key: fam, RangeEnd: clientv3.GetPrefixRangeEnd(fam), Write: true},
			"it was allowed reading " + fam}, // a write grant is read-write: the reading probe runs first
```

(six rows, written out). Its doc comment gains "and on/, oo/ and lo/, the broker's OIDC records
(plan 7h)".

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/store/... -count=1`
Expected: FAIL to compile: `PutOnce`, `OIDCOwner`, `PutLogout` are not methods of `store.Store`.

- [ ] **Step 3: The interface**

In `internal/store/store.go`, in `Store` after `DeleteMembership`:

```go
	// PutOnce writes value under key for ttl when no live record is there,
	// in one atomic step, and reports whether it wrote (plan 7h): a logout
	// token's jti, a refresh challenge, a principal's refresh pacing. The
	// broker's role alone reads or writes them. value is plaintext:
	// identity, never a credential.
	PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// TakeOnce removes the live record under key and returns its value, in
	// one atomic step: of two callers one gets it and the other
	// ErrNotFound, as does a caller after it expired.
	TakeOnce(ctx context.Context, key string) ([]byte, error)
	// PutOIDCOwner records that principal minted under key (OIDCKey: an
	// issuer's sid or sub) until ttl from now: it adds principal to the
	// record's set, or renews its entry (WrittenAt the store's clock, the
	// later expiry kept), by compare-and-set, never replacing another
	// principal's entry; lapsed entries are dropped (Rulings 11, 24).
	PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error
	// OIDCOwner is the live entries under key, sorted by principal, or
	// ErrNotFound when none lives.
	OIDCOwner(ctx context.Context, key string) (OIDCOwner, error)
	// PutLogout keeps l under l.Key until ttl from now: of two writes, the
	// later At stands and the later expiry (Ruling 13). An empty key is
	// refused.
	PutLogout(ctx context.Context, l Logout, ttl time.Duration) error
	// GetLogout is the live logout record under key, or ErrNotFound.
	GetLogout(ctx context.Context, key string) (Logout, error)
```

and, after `Revocation`:

```go
// OIDCOwner is every principal minting under an OIDC sid or sub (plan 7h,
// Rulings 11 and 24): one (issuer, sub) can name more than one, across a
// rename, and a logout reaches each.
type OIDCOwner struct {
	Principals []OwnerPrincipal
}

// OwnerPrincipal is one principal of an owner record, when the store last
// wrote it, and when it lapses.
type OwnerPrincipal struct {
	Principal            string
	WrittenAt, ExpiresAt time.Time
}

// Entry is principal's entry, if the record holds one.
func (o OIDCOwner) Entry(principal string) (OwnerPrincipal, bool) {
	for _, e := range o.Principals {
		if e.Principal == principal {
			return e, true
		}
	}
	return OwnerPrincipal{}, false
}

// Names is the record's principals, in its order.
func (o OIDCOwner) Names() []string {
	out := make([]string, 0, len(o.Principals))
	for _, e := range o.Principals {
		out = append(out, e.Principal)
	}
	return out
}

// Logout is a back-channel logout's record (plan 7h, Ruling 13): its key
// (OIDCKey), when the logout took force (the logout token's iat), and who
// asked. By sid it refuses every token naming the session; by sub, every
// token issued at or before At plus clock_skew.
type Logout struct {
	Key    string
	At     time.Time
	Origin string
}

// ErrNoKey is a record written with an empty key.
var ErrNoKey = errors.New("store: a record with no key")
```

- [ ] **Step 4: Memory**

In `internal/store/memory/memory.go`, three maps in `Store` (made in `New` beside the others):

```go
	once   map[string]onceEntry
	owners map[string]map[string]store.OwnerPrincipal // key, then principal
	logout map[string]logoutEntry
```

```go
type onceEntry struct {
	value []byte
	exp   time.Time
}

type logoutEntry struct {
	l   store.Logout
	exp time.Time
}

func (s *Store) PutOnce(_ context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, store.ErrNoKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if e, ok := s.once[key]; ok && now.Before(e.exp) {
		return false, nil
	}
	s.once[key] = onceEntry{value: append([]byte(nil), value...), exp: now.Add(ttl)}
	s.wroteLocked()
	return true, nil
}

func (s *Store) TakeOnce(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.once[key]
	delete(s.once, key)
	if !ok || !s.now().Before(e.exp) {
		return nil, store.ErrNotFound
	}
	s.wroteLocked()
	return e.value, nil
}

func (s *Store) PutOIDCOwner(_ context.Context, key, principal string, ttl time.Duration) error {
	if key == "" {
		return store.ErrNoKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	set := s.owners[key]
	if set == nil {
		set = map[string]store.OwnerPrincipal{}
		s.owners[key] = set
	}
	for p, e := range set {
		if !now.Before(e.ExpiresAt) {
			delete(set, p)
		}
	}
	exp := now.Add(ttl)
	if e, ok := set[principal]; ok && e.ExpiresAt.After(exp) {
		exp = e.ExpiresAt
	}
	set[principal] = store.OwnerPrincipal{Principal: principal, WrittenAt: now, ExpiresAt: exp}
	s.wroteLocked()
	return nil
}

func (s *Store) OIDCOwner(_ context.Context, key string) (store.OIDCOwner, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var o store.OIDCOwner
	for _, e := range s.owners[key] {
		if now.Before(e.ExpiresAt) {
			o.Principals = append(o.Principals, e)
		}
	}
	if len(o.Principals) == 0 {
		return store.OIDCOwner{}, store.ErrNotFound
	}
	slices.SortFunc(o.Principals, func(a, b store.OwnerPrincipal) int { return strings.Compare(a.Principal, b.Principal) })
	return o, nil
}

func (s *Store) PutLogout(_ context.Context, l store.Logout, ttl time.Duration) error {
	if l.Key == "" {
		return store.ErrNoKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	next := logoutEntry{l: l, exp: now.Add(ttl)}
	if e, ok := s.logout[l.Key]; ok && now.Before(e.exp) {
		if e.l.At.After(l.At) {
			next.l = e.l
		}
		if e.exp.After(next.exp) {
			next.exp = e.exp
		}
	}
	s.logout[l.Key] = next
	s.wroteLocked()
	return nil
}

func (s *Store) GetLogout(_ context.Context, key string) (store.Logout, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.logout[key]
	if !ok || !s.now().Before(e.exp) {
		return store.Logout{}, store.ErrNotFound
	}
	return e.l, nil
}
```

and `sweepLocked` deletes the expired entries of the three maps, as it does `idem`'s (an owner
key whose every entry lapsed goes whole). `slices` and `strings` join `memory.go`'s imports if
it lacks them.

- [ ] **Step 5: Crypt, guard, the test fake**

In `internal/store/crypt/crypt.go`, beside `SupersededAt`'s pass-throughs:

```go
// PutOnce, TakeOnce, PutOIDCOwner, OIDCOwner, PutLogout and GetLogout pass
// through unsealed: each holds identity (an issuer, a sid, a sub, a
// principal, a time), never a credential, as the indexes do (plan 7h).
//
// Not sealed, on purpose (pre-flight M-9). A store writer could repoint an
// oo/ owner record, so a logout deletes another principal's unspent tokens
// (a denial, never a grant), or delete an lo/ logout record, so a logged-out
// session's token passes again. Both are what a store writer can already do
// to the marks (rv/, which pass through unsealed: crypt.go's PutRevocation)
// and to the tokens themselves, so sealing these would close no path the
// marks leave open. A logout, like a revocation, must not depend on the
// encryption key, and sealing the owner set would need a deterministic seal
// to merge entries by compare-and-set. The store's write access is the
// boundary here, as it is for the marks (spec §5.1.4).
func (w *wrapped) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	return w.inner.PutOnce(ctx, key, value, ttl)
}

func (w *wrapped) TakeOnce(ctx context.Context, key string) ([]byte, error) { return w.inner.TakeOnce(ctx, key) }

func (w *wrapped) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	return w.inner.PutOIDCOwner(ctx, key, principal, ttl)
}

func (w *wrapped) OIDCOwner(ctx context.Context, key string) (store.OIDCOwner, error) {
	return w.inner.OIDCOwner(ctx, key)
}

func (w *wrapped) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	return w.inner.PutLogout(ctx, l, ttl)
}

func (w *wrapped) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	return w.inner.GetLogout(ctx, key)
}
```

In `internal/store/guard/guard.go`, the pool table gains

```go
	"PutOnce": Token, "TakeOnce": Token, "PutOIDCOwner": Token, "OIDCOwner": Token, "PutLogout": Token,
	"GetLogout": Token,
```

and six methods in `SupersededAt`'s form, for example:

```go
func (g *guarded) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (ok bool, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { ok, e = g.inner.PutOnce(ctx, key, value, ttl); return })
	return
}

func (g *guarded) TakeOnce(ctx context.Context, key string) (v []byte, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { v, e = g.inner.TakeOnce(ctx, key); return })
	return
}

func (g *guarded) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutOIDCOwner(ctx, key, principal, ttl) })
}

func (g *guarded) OIDCOwner(ctx context.Context, key string) (o store.OIDCOwner, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { o, e = g.inner.OIDCOwner(ctx, key); return })
	return
}

func (g *guarded) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	return g.do(ctx, Token, func(ctx context.Context) error { return g.inner.PutLogout(ctx, l, ttl) })
}

func (g *guarded) GetLogout(ctx context.Context, key string) (l store.Logout, err error) {
	err = g.do(ctx, Token, func(ctx context.Context) (e error) { l, e = g.inner.GetLogout(ctx, key); return })
	return
}
```

In `internal/daemon/authen/authen_test.go`, `noStore` gains the six, each `panic("store
called")`, as its other methods are.

- [ ] **Step 6: etcd**

In `internal/store/etcd/keys.go`:

```go
	famOnce      = "on/" // on/<key>: a once-only record (plan 7h), the broker's alone
	famOIDCOwner = "oo/" // oo/<OIDCKey>: the principal minting under an OIDC sid or sub
	famLogout    = "lo/" // lo/<OIDCKey>: a back-channel logout's record
```

```go
func (k keys) once(key string) string      { return k.root + famOnce + esc(key) }
func (k keys) oidcOwner(key string) string { return k.root + famOIDCOwner + esc(key) }
func (k keys) logout(key string) string    { return k.root + famLogout + esc(key) }
```

In `internal/store/etcd/roles.go`, `daemonNever` gains `famOnce, famOIDCOwner, famLogout`, and
`CheckIdentity`'s probes gain a read and a write of each, as the membership families have.

`internal/store/etcd/oidc.go`:

```go
package etcd

import (
	"context"
	"slices"
	"strings"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/blanketfish/port49/internal/store"
)

// onceRec is on/<key> (plan 7h).
type onceRec struct {
	Value     []byte    `json:"value"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PutOnce writes key only where no live record is, by a compare on its
// revision.
func (s *Store) PutOnce(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, store.ErrNoKey
	}
	now := s.now()
	wrote := false
	err := cas(ctx, s.tok, s.tokLeases, s.k.once(key), func(r onceRec) bool { return now.Before(r.ExpiresAt) },
		func(r *onceRec, found bool) (bool, time.Time, bool, error) {
			if found {
				wrote = false
				return false, time.Time{}, false, nil
			}
			*r = onceRec{Value: value, ExpiresAt: now.Add(ttl)}
			wrote = true
			return true, r.ExpiresAt, false, nil
		})
	return wrote && err == nil, err
}

// TakeOnce deletes key if it is still the record read, and returns its
// value; a lost race reads again, and finds it gone.
func (s *Store) TakeOnce(ctx context.Context, key string) ([]byte, error) {
	k := s.k.once(key)
	for {
		var r onceRec
		mod, ok, err := getJSON(ctx, s.tok, k, &r)
		switch {
		case err != nil:
			return nil, err
		case !ok:
			return nil, store.ErrNotFound
		}
		resp, err := s.tok.Txn(ctx).If(unchanged(k, mod)).Then(clientv3.OpDelete(k)).Commit()
		if err != nil {
			return nil, unavailable(err)
		}
		if !resp.Succeeded {
			continue
		}
		if !s.now().Before(r.ExpiresAt) {
			return nil, store.ErrNotFound // expired: deleted all the same
		}
		return r.Value, nil
	}
}

// ownerRec is oo/<OIDCKey>: every principal minting under it (Ruling 24),
// and the latest of their expiries, which the record's lease follows.
type ownerRec struct {
	Principals []ownerEntry `json:"principals"`
	ExpiresAt  time.Time    `json:"expires_at"`
}

type ownerEntry struct {
	Principal string    `json:"principal"`
	WrittenAt time.Time `json:"written_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PutOIDCOwner merges principal into the record by a compare on its
// revision: a concurrent write of another principal is read again and kept,
// never overwritten (pre-flight I-1).
func (s *Store) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	if key == "" {
		return store.ErrNoKey
	}
	now := s.now()
	return cas(ctx, s.tok, s.tokLeases, s.k.oidcOwner(key), func(r ownerRec) bool { return now.Before(r.ExpiresAt) },
		func(r *ownerRec, found bool) (bool, time.Time, bool, error) {
			var live []ownerEntry
			if found {
				for _, e := range r.Principals {
					if now.Before(e.ExpiresAt) && e.Principal != principal {
						live = append(live, e)
					}
				}
			}
			exp := now.Add(ttl)
			if found {
				for _, e := range r.Principals {
					if e.Principal == principal && e.ExpiresAt.After(exp) {
						exp = e.ExpiresAt
					}
				}
			}
			next := ownerRec{Principals: append(live, ownerEntry{Principal: principal, WrittenAt: now, ExpiresAt: exp})}
			for _, e := range next.Principals {
				next.ExpiresAt = laterOf(next.ExpiresAt, e.ExpiresAt)
			}
			*r = next
			return true, next.ExpiresAt, false, nil
		})
}

func (s *Store) OIDCOwner(ctx context.Context, key string) (store.OIDCOwner, error) {
	var r ownerRec
	_, ok, err := getJSON(ctx, s.tok, s.k.oidcOwner(key), &r)
	if err != nil {
		return store.OIDCOwner{}, err
	}
	now := s.now()
	var o store.OIDCOwner
	for _, e := range r.Principals {
		if ok && now.Before(e.ExpiresAt) {
			o.Principals = append(o.Principals, store.OwnerPrincipal{Principal: e.Principal, WrittenAt: e.WrittenAt,
				ExpiresAt: e.ExpiresAt})
		}
	}
	if len(o.Principals) == 0 {
		return store.OIDCOwner{}, store.ErrNotFound
	}
	slices.SortFunc(o.Principals, func(a, b store.OwnerPrincipal) int { return strings.Compare(a.Principal, b.Principal) })
	return o, nil
}

// logoutRec is lo/<OIDCKey>.
type logoutRec struct {
	At        time.Time `json:"at"`
	Origin    string    `json:"origin"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Store) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	if l.Key == "" {
		return store.ErrNoKey
	}
	now := s.now()
	return cas(ctx, s.tok, s.tokLeases, s.k.logout(l.Key), func(r logoutRec) bool { return now.Before(r.ExpiresAt) },
		func(r *logoutRec, found bool) (bool, time.Time, bool, error) {
			next := logoutRec{At: l.At, Origin: l.Origin, ExpiresAt: now.Add(ttl)}
			if found {
				if r.At.After(l.At) {
					next.At, next.Origin = r.At, r.Origin
				}
				next.ExpiresAt = laterOf(next.ExpiresAt, r.ExpiresAt)
			}
			*r = next
			return true, next.ExpiresAt, false, nil
		})
}

func (s *Store) GetLogout(ctx context.Context, key string) (store.Logout, error) {
	var r logoutRec
	_, ok, err := getJSON(ctx, s.tok, s.k.logout(key), &r)
	switch {
	case err != nil:
		return store.Logout{}, err
	case !ok || !s.now().Before(r.ExpiresAt):
		return store.Logout{}, store.ErrNotFound
	}
	return store.Logout{Key: key, At: r.At, Origin: r.Origin}, nil
}
```

- [ ] **Step 7: Run the properties on every backend**

Run: `go test ./internal/store/... ./internal/daemon/authen/ -count=1 -race`
Expected: PASS: memory, crypt over memory, etcd and crypt over etcd (the etcd tests start their
own member through `etcdtest`, as 7d's do).

- [ ] **Step 8: Commit**

```bash
git add internal/store/ internal/daemon/authen/authen_test.go
git commit -m "feat(store): once-only records, the OIDC owner and the logout record, the broker's role alone

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: The broker takes a bearer: the caller, the checks, the owner, the logout reads

**Files:**
- Create: `internal/broker/oidc.go`
- Modify: `internal/broker/broker.go` (`Broker.Identity`, `authenticate`, `tokens`, `mintOne`,
  `revokedSince`), `internal/broker/identity_api.go`, `internal/broker/explain_api.go`,
  `internal/broker/revoke_api.go`
- Modify: `internal/token/minter.go` (`Request.OIDC`)
- Modify: `internal/broker/member_test.go` (its `revokedSince` call, l.427; pre-flight I-13)
- Test: `internal/broker/oidc_test.go`, and `internal/broker/fixture_test.go` (`withOIDC`,
  `bearer`)

**Interfaces:**
- Consumes: Task 5's `oidc.Set`, `Assertion`, `ErrInvalid`, `ErrUnmapped`, `ErrUnavailable`;
  Task 8's `PutOIDCOwner`, `OIDCOwner`, `GetLogout`; Task 2's `decision.OIDC`, `store.SidKey`,
  `store.OIDCKey`.
- Produces:
  - `Broker.Identity *oidc.Set` (nil: no OIDC verifier);
  - `caller{principal, legacy string; cred store.Credential; authTime time.Time; oidc
    *oidc.Assertion}` and `(caller).auth() *decision.Auth`;
  - `(*Broker).authenticate(w, r, event, nothing string) (caller, bool)` (was `(string,
    store.Credential, bool)`);
  - `bearerOf(r *http.Request) (raw string, present bool, err error)`;
  - `(*Broker).bearerCaller(w, r, event, nothing, raw string) (caller, bool)`;
  - `(*Broker).loggedOut(ctx, a oidc.Assertion) (store.Logout, bool, error)`: never for a
    machine (pre-flight M-16);
  - `(*Broker).noteOwner(ctx, a oidc.Assertion) error`, humans only (M-16), `ownerTTL()`,
    `ownerFresh` (1h);
  - `notAfter(t, now time.Time) time.Time`: a caller's `authTime` never later than now
    (pre-flight M-18);
  - `oidcAuth(a oidc.Assertion) *decision.OIDC`;
  - `answerLoggedOut(w, l store.Logout)`;
  - `(*Broker).revokedSince(w, r, c caller, items []api.MintItem) bool` (was `principal,
    cred`);
  - `token.Request.OIDC *decision.OIDC`, copied onto the permit record's `auth.oidc`;
  - the fixture's `withOIDC(t) *oidctest.Issuer` (a human verifier for `example.com` and a
    machine verifier listing `Oxidized-01` with `sub` `svc`), `addIssuer(t, iss, domain string,
    machine bool)` (Task 12 adds a second provider with it), `bearer(ctx, method, path, body,
    token) *httptest.ResponseRecorder` and `idToken(t, iss, extra)`.

- [ ] **Step 1: The fixture**

In `internal/broker/fixture_test.go`:

```go
// testClientID is the human OIDC verifier's client_id in withOIDC.
const testClientID = "port49-cli"

// withOIDC gives f's broker an OIDC set over a test provider, on f's clock:
// a human verifier (client_id port49-cli, principal from
// preferred_username, for example.com) and a machine verifier (audience
// api://port49-svc, client Oxidized-01 whose sub is svc).
func (f *fixture) withOIDC(t *testing.T) *oidctest.Issuer {
	t.Helper()
	iss := oidctest.NewIssuer(t)
	f.addIssuer(t, iss, "example.com", true)
	return iss
}

// addIssuer adds iss to f's OIDC set (making the set if there is none): a
// human verifier for domain, and, with machine, the machine verifier.
func (f *fixture) addIssuer(t *testing.T, iss *oidctest.Issuer, domain string, machine bool) {
	t.Helper()
	ks := oidc.NewKeySet(oidc.KeySetConfig{Issuer: iss.URL, Client: oidc.NewClient(iss.Roots()), Refresh: time.Hour,
		MaxAge: 24 * time.Hour, Now: f.b.Now, M: f.b.Metrics})
	if f.b.Identity == nil {
		f.b.Identity = &oidc.Set{Timing: oidc.DefaultTiming, Now: f.b.Now, M: f.b.Metrics}
	}
	f.b.Identity.Verifiers = append(f.b.Identity.Verifiers, &oidc.Verifier{VerifierConfig: oidc.VerifierConfig{
		Domain: oidc.Humans, Issuer: iss.URL, ClientID: testClientID, PrincipalClaim: oidc.ClaimPreferredUsername,
		PrincipalDomains: []string{domain}, Scopes: []string{"openid"}, Algorithms: []oidc.Alg{oidc.RS256}}, Keys: ks})
	if machine {
		f.b.Identity.Verifiers = append(f.b.Identity.Verifiers, &oidc.Verifier{VerifierConfig: oidc.VerifierConfig{
			Domain: oidc.Machines, Issuer: iss.URL, Audience: "api://port49-svc",
			Clients:    []oidc.MachineClient{{ClientID: "Oxidized-01", Sub: "svc"}},
			Algorithms: []oidc.Alg{oidc.RS256}}, Keys: ks})
	}
}

// idToken is alice's ID token from iss at f's now, sid s-alice, sub
// sub-alice; extra overrides, nil deleting.
func (f *fixture) idToken(t *testing.T, iss *oidctest.Issuer, extra map[string]any) string {
	t.Helper()
	c := map[string]any{"preferred_username": "alice@example.com", "amr": []string{"pwd", "otp"}, "acr": "1"}
	for k, v := range extra {
		c[k] = v
	}
	return iss.IDToken(t, "k1", testClientID, "sub-alice", f.b.Now(), c)
}

// bearer sends one request with no client certificate and token as its
// bearer through the broker's handler.
func (f *fixture) bearer(ctx context.Context, method, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	r.TLS = &tls.ConnectionState{}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}
```

(imports gain `internal/oidc` and `internal/oidc/oidctest`). `IDToken` gives `sid` "s-" + sub, so
alice's is `s-sub-alice`.

- [ ] **Step 2: Write the failing tests**

`internal/broker/oidc_test.go`:

```go
package broker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/token"
)

const mintLeaf1 = `{"devices":["leaf1"],"ttl_seconds":60}`

func TestAnOIDCPersonMints(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Principal != alicePrincipal || resp.Results[0].Verdict != decision.VerdictPermit {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	toks, err := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if err != nil || len(toks) != 1 {
		t.Fatalf("tokens %d %v", len(toks), err)
	}
	cred := toks[0].Credential
	if cred.Method != "oidc" || cred.Sub != "sub-alice" || cred.Sid != store.SidKey(iss.URL, "s-sub-alice") ||
		strings.Join(cred.AMR, ",") != "pwd,otp" || cred.ACR != "1" || cred.Fingerprint != "" {
		t.Fatalf("credential %+v", cred)
	}
	mints := eventsOf(f.records(t), decision.EventMint)
	auth := mints[len(mints)-1]["auth"].(map[string]any)
	o, _ := auth["oidc"].(map[string]any)
	if auth["method"] != "oidc" || o["issuer"] != iss.URL || o["sub"] != "sub-alice" || o["sid"] != "s-sub-alice" {
		t.Fatalf("the mint record's auth: %v", auth)
	}
	for _, key := range []string{store.SidKey(iss.URL, "s-sub-alice"), store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice")} {
		if own, err := f.st.OIDCOwner(context.Background(), key); err != nil || strings.Join(own.Names(), ",") != alicePrincipal {
			t.Fatalf("owner of %q: %+v %v", key, own, err)
		}
	}
}

// The session clock is the token's auth_time, not the request's (Ruling 9).
func TestTheOIDCSessionClockIsAuthTime(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	authAt := f.b.Now().Add(-2 * time.Hour)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, map[string]any{"auth_time": authAt.Unix()}))
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if len(toks) != 1 || !toks[0].AuthTime.Equal(authAt.Truncate(time.Second)) {
		t.Fatalf("token auth_time %v, want %v", toks[0].AuthTime, authAt)
	}
	old := f.idToken(t, iss, map[string]any{"auth_time": f.b.Now().Add(-13 * time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, old); w.Code != 401 ||
		!strings.Contains(w.Body.String(), string(decision.SessionExpired)) || !strings.Contains(w.Body.String(), "port49 login") {
		t.Fatalf("an authentication 13h ago: %d %s", w.Code, w.Body)
	}
	// An auth_time ahead of the broker's clock, within clock_skew, is now: a
	// session clock never starts in the future (pre-flight M-18).
	ahead := f.idToken(t, iss, map[string]any{"auth_time": f.b.Now().Add(30 * time.Second).Unix(),
		"iat": f.b.Now().Add(30 * time.Second).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", `{"devices":["nx1"],"ttl_seconds":60}`, ahead); w.Code != 200 {
		t.Fatalf("an auth_time 30s ahead: %d %s", w.Code, w.Body)
	}
	toks, _ = f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"})
	if len(toks) != 1 || toks[0].AuthTime.After(f.b.Now()) {
		t.Fatalf("a token's auth_time %v is after the broker's now %v", toks[0].AuthTime, f.b.Now())
	}
}

const machinePolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: backup, identity: ["app:Oxidized-01"], username: svc-backup, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: backup, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

func TestAMachineMintsAsApp(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withOIDC(t)
	now := f.b.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Principal != "app:Oxidized-01" || resp.Results[0].Username != "svc-backup" {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	// A machine has no session a provider logs out: it writes no owner
	// record (pre-flight M-16).
	if _, err := f.st.OIDCOwner(context.Background(), store.OIDCKey(store.OIDCSub, iss.URL, "svc")); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a machine's mint wrote an owner record: %v", err)
	}
}

func TestOneCredentialPerRequest(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	both := httptestRequest("POST", "/v1/tokens", mintLeaf1)
	both.TLS = f.state(f.alice)
	both.Header.Set("Authorization", "Bearer "+f.idToken(t, iss, nil))
	w := httptestServe(f, both)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "one credential per request") {
		t.Fatalf("a certificate and a bearer: %d %s", w.Code, w.Body)
	}
	for _, h := range []string{"Basic YWxpY2U6eA==", "Bearer", "Bearer a b", "bearer"} {
		q := httptestRequest("POST", "/v1/tokens", mintLeaf1)
		q.Header.Set("Authorization", h)
		w := httptestServe(f, q)
		if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.TrustDomainUnresolved)) {
			t.Errorf("Authorization %q: %d %s", h, w.Code, w.Body)
		}
	}
}
```

`httptestServe` and `httptestRequest` are two small helpers added to `fixture_test.go`:

```go
// httptestRequest is a request with no client certificate.
func httptestRequest(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	return r
}

// httptestServe serves r through f's broker.
func httptestServe(f *fixture, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}
```

The tests continue:

```go
// Review Focus 1, 4: a token the broker cannot verify is refused, recorded
// with no principal, and nothing of it is said.
func TestARefusedBearerIsRecordedWithNoPrincipalAndNotQuoted(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	forger := oidctest.NewIssuer(t)
	forged := forger.TokenWith(t, "k1", map[string]any{"kid": "k1"}, map[string]any{"iss": iss.URL, "aud": testClientID,
		"sub": "sub-marker", "preferred_username": "alice@example.com", "iat": f.b.Now().Unix(),
		"exp": f.b.Now().Add(time.Minute).Unix(), "auth_time": f.b.Now().Unix()})
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, forged)
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.TrustDomainUnresolved)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	last := recs[len(recs)-1]
	if last["principal"] != nil || last["auth"].(map[string]any)["method"] != "oidc" || last["auth"].(map[string]any)["oidc"] != nil {
		t.Fatalf("the refusal's record: %v", last)
	}
	for _, s := range []string{f.log.String(), said.String(), w.Body.String()} {
		if strings.Contains(s, "sub-marker") || strings.Contains(s, forged) {
			t.Fatalf("an unverified token's claim or the token itself was written: %s", s)
		}
	}
}

func TestAProviderOutageIsRetriable(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	raw := f.idToken(t, iss, nil)
	iss.Close()
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw)
	if w.Code != 503 || w.Header().Get("Retry-After") != "30" ||
		!strings.Contains(w.Body.String(), "identity_provider_unavailable") {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
}

func TestAnUnusablePrincipalClaimIsUnmapped(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss,
		map[string]any{"preferred_username": "alice"}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.IdentityUnmapped)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A standing mark refuses an OIDC caller as it refuses a certificate
// (Ruling 8): port49 revoke ends a person on both paths.
func TestAMarkRefusesTheOIDCPath(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	if err := f.st.PutRevocation(context.Background(), store.Revocation{Kind: store.RevocationPrincipal,
		Key: alicePrincipal, At: f.b.Now(), Origin: "admin_socket uid 0"}); err != nil {
		t.Fatal(err)
	}
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A logged-out sid is refused at every endpoint; a sub logout refuses only
// tokens issued before it (Ruling 13).
func TestALoggedOutSessionIsRefusedEverywhere(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	raw := f.idToken(t, iss, nil)
	if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"), At: f.b.Now(),
		Origin: "backchannel_logout " + iss.URL}, time.Hour); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/v1/tokens", mintLeaf1}, {"GET", "/v1/identity", ""},
		{"POST", "/v1/explain", `{"device":"leaf1"}`}, {"POST", "/v1/tokens/revoke", `{"mine":true}`},
	} {
		w := f.bearer(ctx, c.method, c.path, c.body, raw)
		if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) ||
			!strings.Contains(w.Body.String(), "identity provider ended this session") {
			t.Errorf("%s %s: %d %s", c.method, c.path, w.Code, w.Body)
		}
	}
	// By sub: a token issued at the logout is refused; one issued after it,
	// beyond clock_skew, is a new login and accepted.
	f2 := newFixture(t, 8)
	iss2 := f2.withOIDC(t)
	at := f2.b.Now()
	if err := f2.st.PutLogout(ctx, store.Logout{Key: store.OIDCKey(store.OIDCSub, iss2.URL, "sub-alice"), At: at},
		time.Hour); err != nil {
		t.Fatal(err)
	}
	if w := f2.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f2.idToken(t, iss2, nil)); w.Code != 401 {
		t.Fatalf("a token issued at the sub's logout: %d %s", w.Code, w.Body)
	}
	f2.advance(2 * time.Minute)
	if w := f2.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f2.idToken(t, iss2, nil)); w.Code != 200 {
		t.Fatalf("a token issued 2m after the sub's logout: %d %s", w.Code, w.Body)
	}
}

// hookStore runs before when a method named in it is called on the
// minter's store.
type hookStore struct {
	store.Store
	before map[string]func() error
}

func (h hookStore) PutToken(ctx context.Context, k store.TokenKey, t store.Token) (int, error) {
	if f := h.before["PutToken"]; f != nil {
		if err := f(); err != nil {
			return 0, err
		}
	}
	return h.Store.PutToken(ctx, k, t)
}

func (h hookStore) PutOIDCOwner(ctx context.Context, key, principal string, ttl time.Duration) error {
	if f := h.before["PutOIDCOwner"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.PutOIDCOwner(ctx, key, principal, ttl)
}

// Review Focus 7: a logout that lands while the mint writes is read after
// the last token write, and the mint's tokens are deleted.
func TestAMintRacingALogoutLeavesNoToken(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	ctx := context.Background()
	hooked := hookStore{Store: f.st, before: map[string]func() error{"PutToken": func() error {
		return f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss.URL, "s-sub-alice"), At: f.b.Now()}, time.Hour)
	}}}
	f.b.Minter = token.NewMinter(hooked, f.b.Log, rand.Reader, token.TagKey([]byte("k")), f.b.Now, 8)
	w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	if w.Code != 401 || !strings.Contains(w.Body.String(), string(decision.CredentialRevoked)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("%d tokens survived a logout that landed mid-mint", len(toks))
	}
}

// No token exists that a logout cannot find (Ruling 11): the owner write
// failing refuses the mint before a token is written.
func TestAnOwnerWriteFailureRefusesTheMint(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutOIDCOwner": func() error { return store.ErrUnavailable }}}
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	if w.Code != 503 || !strings.Contains(w.Body.String(), string(decision.StoreUnavailable)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("a token was written without its owner record")
	}
}

func TestIdentityAnswersAnOIDCCaller(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := f.bearer(context.Background(), "GET", "/v1/identity", "", f.idToken(t, iss, nil))
	var id api.Identity
	if err := json.Unmarshal(w.Body.Bytes(), &id); err != nil || w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if id.Principal != alicePrincipal || id.Method != "oidc" || id.OIDC == nil || id.OIDC.Issuer != iss.URL ||
		id.OIDC.Sid != "s-sub-alice" || id.AuthTime != f.b.Now().UTC().Format(time.RFC3339) {
		t.Fatalf("identity %+v", id)
	}
}

// With a directory, an OIDC principal's username and groups are the
// directory's, read as a certificate's are (Ruling 7; 7g's carry).
func TestAnOIDCPrincipalResolvesThroughTheDirectory(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	res := withDirectory(f, map[string]directory.Answer{alicePrincipal: answerFor(alicePrincipal, "alice2")}, nil)
	w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil))
	resp := decodeMint(t, w)
	if w.Code != 200 || resp.Results[0].Username != "alice2" || res.Calls.Load() != 1 {
		t.Fatalf("%d %s, calls %d", w.Code, w.Body, res.Calls.Load())
	}
}

// Without an OIDC verifier, a bearer is no one's.
func TestABearerWithNoOIDCIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	iss := oidctest.NewIssuer(t)
	raw := iss.IDToken(t, "k1", testClientID, "x", f.b.Now(), map[string]any{"preferred_username": "alice@example.com"})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, raw); w.Code != 401 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'TestAnOIDC|TestTheOIDCSession|TestAMachineMints|TestOneCredential|TestARefusedBearer|TestAProviderOutage|TestAnUnusable|TestAMarkRefuses|TestALoggedOut|TestAMintRacing|TestAnOwnerWrite|TestIdentityAnswers|TestABearerWithNo' -count=1`
Expected: FAIL to compile: `Broker.Identity` undefined.

- [ ] **Step 4: The minter's record**

In `internal/token/minter.go`, `Request` gains, after `Directory`:

```go
	// OIDC is the verified token's identity for the record's auth.oidc; nil
	// on the certificate path (plan 7h).
	OIDC *decision.OIDC
```

and the permit record's `Auth` becomes `&decision.Auth{Method: r.Subject.Credential.Method,
Directory: r.Directory, OIDC: r.OIDC}`.

- [ ] **Step 5: `internal/broker/oidc.go`**

```go
package broker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// caller is who a request is: from its connection's certificate, or from
// its bearer token (plan 7h; spec §13 decision 39). A record's principal
// and auth always describe one credential (decision 34).
type caller struct {
	principal string
	// legacy is a mapped certificate's pre-directory principal (pre-flight
	// I-16); "" on the OIDC path.
	legacy   string
	cred     store.Credential
	authTime time.Time
	// oidc is the verified token; nil on the certificate path.
	oidc *oidc.Assertion
}

// auth is a record's auth for c.
func (c caller) auth() *decision.Auth {
	a := &decision.Auth{Method: c.cred.Method, Fingerprint: c.cred.Fingerprint}
	if c.oidc != nil {
		a.OIDC = oidcAuth(*c.oidc)
	}
	return a
}

// oidcAuth is auth.oidc (spec §5.7): the provider's own sid, not the
// issuer-qualified key.
func oidcAuth(a oidc.Assertion) *decision.OIDC {
	return &decision.OIDC{Issuer: a.Issuer, Sub: a.Subject, Sid: a.Sid, AMR: a.AMR, ACR: a.ACR,
		AuthTime: decision.FormatTime(a.AuthTime)}
}

// errBearer is an Authorization header that is not one Bearer token.
var errBearer = errors.New("broker: the Authorization header is not one Bearer token")

// bearerOf is r's bearer token: present is whether r has an Authorization
// header at all, and err says it is not one "Bearer <token>".
func bearerOf(r *http.Request) (string, bool, error) {
	vals := r.Header.Values("Authorization")
	if len(vals) == 0 {
		return "", false, nil
	}
	scheme, tok, ok := strings.Cut(vals[0], " ")
	if len(vals) != 1 || !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" || strings.ContainsAny(tok, " \t,") {
		return "", true, errBearer
	}
	return tok, true, nil
}

// bearerCaller is authenticate on the OIDC path (Rulings 2–10, 13): the
// token verified by exactly one verifier, its auth_time within
// max_session_age, no mark on its principal, and no logout of its session
// or subject. A refusal is answered and recorded once under event, with
// no principal and no claim when the token did not verify.
func (b *Broker) bearerCaller(w http.ResponseWriter, r *http.Request, event, nothing, raw string) (caller, bool) {
	now := b.Now()
	deny := func(reason decision.Reason, principal string, a *oidc.Assertion) {
		rec := decision.Record{TS: now, Event: event, Verdict: decision.VerdictDeny, Reason: reason,
			Principal: principal, Auth: &decision.Auth{Method: "oidc"}}
		if a != nil {
			rec.Auth.OIDC = oidcAuth(*a)
		}
		b.emit(rec)
	}
	if b.Identity == nil {
		deny(decision.TrustDomainUnresolved, "", nil)
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved),
			"this broker accepts no OIDC token: no oidc verifier is configured under broker.identity")
		return caller{}, false
	}
	vctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	a, err := b.Identity.Verify(vctx, raw)
	cancel()
	switch {
	case errors.Is(err, oidc.ErrUnavailable):
		deny(decision.TrustDomainUnresolved, "", nil)
		b.sayOnce("oidc_unavailable", sayEvery, "identity: a bearer token was refused (identity_provider_unavailable): %s",
			printsafe.Line(err.Error(), 300))
		w.Header().Set("Retry-After", "30")
		writeError(w, http.StatusServiceUnavailable, "identity_provider_unavailable",
			"the broker cannot use your identity provider's keys right now, so it "+nothing+"; retry shortly")
		return caller{}, false
	case errors.Is(err, oidc.ErrUnmapped):
		deny(decision.IdentityUnmapped, "", nil)
		b.sayOnce("oidc_unmapped", sayEvery, "identity: a bearer token was refused (identity_unmapped): %s",
			printsafe.Line(err.Error(), 300))
		writeError(w, http.StatusUnauthorized, string(decision.IdentityUnmapped),
			"your token names no principal this broker can use; tell the operator")
		return caller{}, false
	case err != nil:
		deny(decision.TrustDomainUnresolved, "", nil)
		b.sayOnce("oidc_invalid", sayEvery, "identity: a bearer token was refused (trust_domain_unresolved): %s",
			printsafe.Line(err.Error(), 300))
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), err.Error())
		return caller{}, false
	}
	c := caller{principal: a.Principal, cred: a.Credential(), authTime: notAfter(a.AuthTime, now), oidc: &a}
	// The refresh's own requests are exempt (Ruling 9): a challenge grants
	// nothing, and the refresh's token is checked against its challenge.
	if event != decision.EventRefresh && b.MaxSessionAge > 0 && now.Sub(a.AuthTime) > b.MaxSessionAge {
		deny(decision.SessionExpired, a.Principal, &a)
		writeError(w, http.StatusUnauthorized, string(decision.SessionExpired), fmt.Sprintf(
			"your identity provider last authenticated you at %s, more than max_session_age (%s) ago; run "+
				"`port49 login` (it asks the provider to authenticate you again)",
			a.AuthTime.UTC().Format(time.RFC3339), b.MaxSessionAge))
		return caller{}, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	rv, revoked, err := b.revocation(ctx, a.Principal, c.cred)
	if err == nil && !revoked {
		var l store.Logout
		var out bool
		if l, out, err = b.loggedOut(ctx, a); err == nil && out {
			b.Metrics.OIDCTokens.WithLabelValues(a.Issuer, "logged_out").Inc()
			deny(decision.CredentialRevoked, a.Principal, &a)
			answerLoggedOut(w, l)
			return caller{}, false
		}
	}
	switch {
	case err != nil:
		deny(decision.StoreUnavailable, a.Principal, &a)
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
			"the broker could not read the revocations and logouts in force, so it "+nothing+"; try again")
		return caller{}, false
	case revoked:
		rec := revokedRecord(now, a.Principal, c.cred)
		rec.Event, rec.Auth = event, c.auth()
		b.emit(rec)
		answerRevoked(w, rv)
		return caller{}, false
	}
	return c, true
}

// notAfter is t, or now when t is later: an auth_time ahead of the broker's
// clock, within clock_skew, starts no session clock in the future
// (pre-flight M-18).
func notAfter(t, now time.Time) time.Time {
	if t.After(now) {
		return now
	}
	return t
}

// loggedOut is the logout refusing a: by its sid, or by its sub when it was
// issued at or before the sub's logout plus clock_skew (Ruling 13). A
// machine has no session a provider logs out, so none refuses it
// (pre-flight M-16); port49 revoke app:<client> does.
func (b *Broker) loggedOut(ctx context.Context, a oidc.Assertion) (store.Logout, bool, error) {
	if a.Domain != oidc.Humans {
		return store.Logout{}, false, nil
	}
	if key := store.SidKey(a.Issuer, a.Sid); key != "" {
		l, err := b.Store.GetLogout(ctx, key)
		switch {
		case err == nil:
			return l, true, nil
		case !errors.Is(err, store.ErrNotFound):
			return store.Logout{}, false, err
		}
	}
	l, err := b.Store.GetLogout(ctx, store.OIDCKey(store.OIDCSub, a.Issuer, a.Subject))
	switch {
	case errors.Is(err, store.ErrNotFound):
		return store.Logout{}, false, nil
	case err != nil:
		return store.Logout{}, false, err
	}
	return l, !a.IssuedAt.After(l.At.Add(b.Identity.Timing.ClockSkew)), nil
}

// answerLoggedOut is the 401 credential_revoked a logged-out session's
// request is answered.
func answerLoggedOut(w http.ResponseWriter, l store.Logout) {
	writeJSON(w, http.StatusUnauthorized, api.Error{Error: string(decision.CredentialRevoked), Detail: fmt.Sprintf(
		"your identity provider ended this session at %s (back-channel logout); log in again",
		l.At.UTC().Format(time.RFC3339))})
}

// ownerFresh is how long an owner record is left as it is before a mint
// writes it again (Ruling 11).
const ownerFresh = time.Hour

// ownerTTL is an owner record's life: as long as a context minted under it
// can be expected to live, at least a day.
func (b *Broker) ownerTTL() time.Duration { return max(b.MaxSessionAge, 24*time.Hour) }

// noteOwner records that a's principal mints under its sid and its sub,
// before the first token write (Ruling 11): a logout finds the tokens to
// delete through it. The record keeps every principal written to it
// (Ruling 24), so this adds a's beside any other; an entry for a's
// principal written within ownerFresh is left alone. A machine writes none
// (pre-flight M-16).
func (b *Broker) noteOwner(ctx context.Context, a oidc.Assertion) error {
	if a.Domain != oidc.Humans {
		return nil
	}
	for _, key := range []string{store.SidKey(a.Issuer, a.Sid), store.OIDCKey(store.OIDCSub, a.Issuer, a.Subject)} {
		if key == "" {
			continue
		}
		if o, err := b.Store.OIDCOwner(ctx, key); err == nil {
			if e, ok := o.Entry(a.Principal); ok && b.Now().Sub(e.WrittenAt) < ownerFresh {
				continue
			}
		}
		if err := b.Store.PutOIDCOwner(ctx, key, a.Principal, b.ownerTTL()); err != nil {
			return err
		}
	}
	return nil
}
```

`b.sayOnce(key, window, format, args...)` is the broker's rate-limited line (`certcheck.go`); `sayEvery`
is the listener's 10s.

- [ ] **Step 6: `authenticate` returns a caller**

In `internal/broker/broker.go`, add the field after `Directory`:

```go
	// Identity verifies OIDC bearer tokens (plan 7h): nil when no oidc
	// verifier is configured, and a bearer is then refused.
	Identity *oidc.Set
```

Change `authenticate`'s signature to `(w http.ResponseWriter, r *http.Request, event, nothing
string) (caller, bool)` and put first in its body:

```go
	raw, hasBearer, berr := bearerOf(r)
	hasCert := r.TLS != nil && (len(r.TLS.PeerCertificates) > 0 || len(r.TLS.VerifiedChains) > 0)
	switch {
	case hasBearer && hasCert:
		writeError(w, http.StatusBadRequest, "bad_request", "one credential per request: a client certificate or "+
			"an Authorization header, not both")
		return caller{}, false
	case hasBearer && berr != nil:
		b.emit(decision.Record{TS: b.Now(), Event: event, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "oidc"}})
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), berr.Error())
		return caller{}, false
	case hasBearer:
		return b.bearerCaller(w, r, event, nothing, raw)
	}
```

then the existing certificate path, its every `return "", store.Credential{}, false` becoming
`return caller{}, false`, and its two successful returns becoming

```go
		return caller{principal: principal, cred: cred, authTime: authTime}, true
```

(the no-directory one) and

```go
	return caller{principal: principal, legacy: legacy, cred: cred, authTime: authTime}, true
```

(the directory one).

- [ ] **Step 7: The mint**

In `tokens`:

```go
	c, ok := b.authenticate(w, r, decision.EventMint, "minted nothing")
	if !ok {
		return
	}
	principal, cred, authTime := c.principal, c.cred, c.authTime
	now := b.Now()
```

(the `authTime := b.authTime(r)` line goes). After the membership is read and before
`b.Minter.Reserve`:

```go
	// No token exists that a logout cannot find (Ruling 11).
	if c.oidc != nil {
		octx, ocancel := context.WithTimeout(r.Context(), holdTimeout)
		err := b.noteOwner(octx, *c.oidc)
		ocancel()
		if err != nil {
			b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
				Reason: decision.StoreUnavailable, Principal: principal, Auth: c.auth()})
			writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable),
				"the broker could not record your session for a logout to find, so it minted nothing; try again")
			return
		}
	}
```

Every `decision.Record` in `tokens` that names the caller takes `Auth: c.auth()` in place of its
`&decision.Auth{Method: cred.Method…}`. `mintOne`'s `cred store.Credential, authTime time.Time`
parameters become `c caller`, its body reading `c.cred` and `c.authTime`; its `deny` record's
auth is `&decision.Auth{Method: c.cred.Method, Directory: directoryAuth(answer), OIDC:
c.auth().OIDC}`, and its `token.Request` gains `OIDC: c.auth().OIDC`. Both
`b.revokedSince(w, r, principal, cred, …)` calls become `b.revokedSince(w, r, c, …)`.

`revokedSince` becomes:

```go
func (b *Broker) revokedSince(w http.ResponseWriter, r *http.Request, c caller, items []api.MintItem) bool {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	principal, cred := c.principal, c.cred
	rv, revoked, err := b.revocation(ctx, principal, cred, b.legacyOf(r))
	var l store.Logout
	var out bool
	if err == nil && !revoked && c.oidc != nil {
		l, out, err = b.loggedOut(ctx, *c.oidc)
	}
	switch {
	case err != nil:
		… as before …
	case revoked:
		… as before …
	case out:
		if b.unmint(ctx, principal, cred, items) == 0 {
			rec := revokedRecord(b.Now(), principal, cred)
			rec.Auth = c.auth()
			b.emit(rec)
		}
		answerLoggedOut(w, l)
		return true
	}
	return false
}
```

with the comment gaining "and, on the OIDC path, the logouts (Ruling 13)".

- [ ] **Step 8: Identity, explain, revoke**

- `identity_api.go`: `c, ok := b.authenticate(…)`; `principal, cred := c.principal, c.cred`;
  `at := c.authTime` (the `b.authTime(r)` call goes); the record's `Auth` is `c.auth()`; and
  `if c.oidc != nil { out.OIDC = &api.IdentityOIDC{Issuer: c.oidc.Issuer, Sub: c.oidc.Subject,
  Sid: c.oidc.Sid, AMR: c.oidc.AMR, ACR: c.oidc.ACR} }`.
- `explain_api.go`: `c, ok := b.authenticate(…)`; `asker, cred := c.principal, c.cred`, the
  local `caller` renamed `asker` throughout the handler (`callerMember` becomes
  `askerMember`), so no local shadows the new `caller` type (pre-flight M-19); the two
  caller-refusal records take `Auth: c.auth()`.
- `revoke_api.go`: `c, ok := b.authenticate(…)`; `asker := c.principal`, the local `caller`
  renamed `asker` throughout `tokensRevoke`, and the `caller string` parameters of
  `revokeOwnOrKey` and `holdOwnRevoke` renamed `asker` (M-19). The doc comments' word "caller"
  stays: it names the person, not the identifier.
- `member_test.go:427` (pre-flight I-13): `f.b.revokedSince(w, r, corpAlice, cred, nil)` becomes
  `f.b.revokedSince(w, r, caller{principal: corpAlice, cred: cred}, nil)`. A `grep -rn
  "revokedSince(" internal/broker/` after the change finds no call in the old form.

- [ ] **Step 9: Run the tests to see them pass, and the package**

Run: `go vet ./internal/broker/ && go test ./internal/broker/... ./internal/token/ -count=1 -race`
Expected: vet clean, and PASS: the new tests, and every certificate-path test unchanged
(`member_test.go`'s `revokedSince` test included, converted in Step 8).

- [ ] **Step 10: Commit**

```bash
git add internal/broker/ internal/token/minter.go
git commit -m "feat(broker): an OIDC bearer per request: one verifier, the session clock from auth_time, marks and logouts read before and after the mint, owner records first

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 10: The server: an OIDC-only broker, `/v1/config`, a bearer over a real connection

**Files:**
- Modify: `internal/broker/server.go` (`Server`), `internal/broker/broker.go` (`Broker.NoX509`,
  `config`)
- Test: `internal/broker/oidcserver_test.go`

**Interfaces:**
- Consumes: Task 9's `Broker.Identity`, `bearerCaller`; Task 2's `api.OIDCProvider`.
- Produces:
  - `Broker.NoX509 bool`: set on an OIDC-only broker (Ruling 1);
  - `Server(addr, cert, anchor)` accepting a nil `anchor` only when `NoX509` and `Identity` are
    set, and then requesting no client certificate; `NoX509` with a non-nil `anchor` is
    refused (pre-flight M-19);
  - `/v1/config`'s `methods` and `oidc` (Ruling 16).

- [ ] **Step 1: Write the failing tests**

`internal/broker/oidcserver_test.go`:

```go
package broker

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/testpki"
)

func TestConfigNamesTheHumanOIDCVerifiers(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	var c api.Config
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Methods, ",") != "x509,oidc" || len(c.OIDC) != 1 || c.OIDC[0].Issuer != iss.URL ||
		c.OIDC[0].ClientID != testClientID || strings.Join(c.OIDC[0].Scopes, ",") != "openid" {
		t.Fatalf("config %+v: the machine verifier is not listed, the human one is", c)
	}
	if strings.Contains(w.Body.String(), "api://port49-svc") {
		t.Fatalf("a machine audience is advertised: %s", w.Body)
	}
}

// An OIDC-only broker requests no certificate and offers no x509; a broker
// with neither an anchor nor an OIDC verifier is refused.
func TestAnOIDCOnlyServer(t *testing.T) {
	f := newFixture(t, 8)
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.b.Server("127.0.0.1:0", srvCert, nil); err == nil {
		t.Fatal("a broker with no anchor and no OIDC verifier was served")
	}
	f.withOIDC(t)
	f.b.NoX509 = true
	// NoX509 with an anchor would still verify client certificates: refused
	// (pre-flight M-19).
	if _, err := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool()); err == nil {
		t.Fatal("an OIDC-only broker was served with an anchor")
	}
	srv, err := f.b.Server("127.0.0.1:0", srvCert, nil)
	if err != nil {
		t.Fatal(err)
	}
	if srv.TLSConfig.ClientAuth != tls.NoClientCert || srv.TLSConfig.ClientCAs != nil {
		t.Fatalf("an OIDC-only broker requests %v", srv.TLSConfig.ClientAuth)
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	if !strings.Contains(w.Body.String(), `"methods":["oidc"]`) {
		t.Fatalf("config %s", w.Body)
	}
}

// A bearer over a real connection mints; the connection, which bound no
// principal, is closed once it goes idle and gives its source slot back.
func TestABearerMintsThroughTheListener(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	addr, _ := serveThrough(t, f, ListenerLimits{MaxPendingPerSource: 1, MaxPerPrincipal: 4,
		HandshakeTimeout: 10 * time.Second}, nil)
	mint := func() int {
		c, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		body := mintLeaf1
		req := "POST /v1/tokens HTTP/1.1\r\nHost: broker\r\nContent-Type: application/json\r\n" +
			"Authorization: Bearer " + f.idToken(t, iss, nil) + "\r\nContent-Length: " +
			strconv.Itoa(len(body)) + "\r\n\r\n" + body
		if _, err := io.WriteString(c, req); err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		// The broker closes it once idle: the next read ends, it does not time out.
		_, err = br.ReadByte()
		var ne net.Error
		if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
			t.Fatalf("a bearer's connection was held after its request: %v", err)
		}
		// The close that ended the read gives the slot back just after it.
		pending := f.b.Metrics.BrokerConnections.WithLabelValues("pending")
		for deadline := time.Now().Add(2 * time.Second); testutil.ToFloat64(pending) != 0; {
			if time.Now().After(deadline) {
				t.Fatalf("%v connections still pending", testutil.ToFloat64(pending))
			}
			time.Sleep(10 * time.Millisecond)
		}
		return resp.StatusCode
	}
	// With one pending slot per source, the second mint gets its slot only if
	// the first connection's slot was given back when the broker closed it.
	for i := range 2 {
		if code := mint(); code != 200 {
			t.Fatalf("mint %d: %d", i+1, code)
		}
	}
}
```

The client never closes the connection itself, so the second mint's slot can only come from the
broker's own close.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'TestConfigNamesTheHuman|TestAnOIDCOnlyServer|TestABearerMintsThroughTheListener' -count=1`
Expected: FAIL to compile (`NoX509` undefined), and `/v1/config` with no `oidc`.

- [ ] **Step 3: Implement**

In `internal/broker/broker.go`, after `Identity`:

```go
	// NoX509 is an OIDC-only broker (Ruling 1): no x509 verifier, so Server
	// requests no client certificate and /v1/config offers no x509.
	NoX509 bool
```

and `config` becomes:

```go
func (b *Broker) config(w http.ResponseWriter, _ *http.Request) {
	c := api.Config{MaxSessionAgeSeconds: int(b.MaxSessionAge / time.Second), BatchMax: b.BatchMax,
		CeilingWarningSeconds: int(b.CeilingWarning / time.Second)}
	if !b.NoX509 {
		c.Methods = append(c.Methods, "x509")
	}
	if b.Identity != nil {
		c.Methods = append(c.Methods, "oidc")
		for _, v := range b.Identity.Humans() {
			c.OIDC = append(c.OIDC, api.OIDCProvider{Issuer: v.Issuer, ClientID: v.ClientID,
				Scopes: slices.Clone(v.Scopes)})
		}
	}
	writeJSON(w, http.StatusOK, c)
}
```

(`slices` imported). A broker with OIDC whose verifiers are all machines lists `oidc` in
`methods` and no `oidc` entries: a client-credentials caller needs no discovery.

In `internal/broker/server.go`, `Server`'s anchor check becomes:

```go
	clientAuth := tls.VerifyClientCertIfGiven
	switch {
	case anchor != nil && b.NoX509:
		return nil, errors.New("broker: an OIDC-only broker (NoX509) takes no anchor: it would still verify " +
			"client certificates")
	case anchor == nil && b.NoX509 && b.Identity != nil:
		// An OIDC-only broker (Ruling 1): no certificate is requested, and
		// every caller authenticates by bearer.
		clientAuth = tls.NoClientCert
	case anchor == nil || anchor.Equal(x509.NewCertPool()):
		return nil, errors.New("broker: the broker trusts exactly one anchor; a nil pool would mean the system " +
			"roots, and an empty one trusts no one (an OIDC-only broker sets NoX509 and Identity)")
	}
```

and the `tls.Config` takes `ClientCAs: anchor, ClientAuth: clientAuth`. `VerifyConnection`
already returns nil for a connection with no certificate. The doc comment gains: "An OIDC-only
broker (NoX509, plan 7h) is served with a nil anchor and requests no certificate."

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./internal/broker/ -count=1 -race`
Expected: PASS, the existing `/v1/config` test (`Methods == ["x509"]`) included: a fixture with
no `Identity` lists x509 alone.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/server.go internal/broker/broker.go internal/broker/oidcserver_test.go
git commit -m "feat(broker): an OIDC-only broker requests no certificate; /v1/config names the human OIDC verifiers

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 11: The OIDC refresh: a broker-issued nonce, a fresh `auth_time`, the new `sid` indexed

**Files:**
- Create: `internal/broker/oidcrefresh.go`
- Modify: `internal/broker/sessionrefresh.go` (`refreshChallenge`, `refresh` dispatch; `extend`
  indexes a new sid)
- Modify: `internal/session/session.go` (`AddSid`)
- Test: `internal/broker/oidcrefresh_test.go`, `internal/session/session_test.go`

**Interfaces:**
- Consumes: Task 9's `authenticate` (a `caller` with `oidc`), `noteOwner`, `loggedOut`,
  `answerLoggedOut`; Task 8's `PutOnce`, `TakeOnce`; 7b's `RefreshSession`, `refreshNonceTTL`,
  `refreshEvery`.
- Produces:
  - `(*Broker).oidcChallenge(w, r)`, `(*Broker).oidcRefresh(w, r)`;
  - `oidcChallengeTTL` (5m), `challengeKey(nonce string) string`, `paceKey(principal string)
    string`;
  - `session.(*Manager).AddSid(ctx, principal, sid string, ref store.ContextRef) error`: adds an
    entry, unlike `Manager.Refresh`'s `ReindexSid`, which moves one;
  - `extend` (and so `RefreshSession`) indexing `cred.Sid` beside the context's own when they
    differ, **before** `RefreshContext` (pre-flight I-2);
  - `oidcRefresh`'s after-check marking every context it extended when a logout record
    appeared (I-2);
  - `hookStore.RefreshContext` (the test fake gains it);
  - `RefreshSession(ctx, m, answer, cred, at, via *decision.OIDC)`: the new last parameter,
    `nil` on the certificate path. `at` is the caller's `authTime`, which `bearerCaller` has
    already held to no later than now (pre-flight M-18).

- [ ] **Step 1: Write the failing tests**

`internal/session/session_test.go` gains:

```go
func TestAddSidIndexesBesideTheOld(t *testing.T) {
	st := memory.New(time.Now)
	m := New(st, time.Now, time.Hour, time.Hour)
	ctx := context.Background()
	ref := store.ContextRef{NAS: "leaf1", Username: "alice"}
	if err := st.IndexContext(ctx, "user:alice@example.com", "old", "", ref, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := m.AddSid(ctx, "user:alice@example.com", "new", ref); err != nil {
		t.Fatal(err)
	}
	for _, sid := range []string{"old", "new"} {
		if refs, _ := st.ContextsBySid(ctx, sid); len(refs) != 1 || refs[0] != ref {
			t.Fatalf("by sid %s: %v", sid, refs)
		}
	}
	if err := m.AddSid(ctx, "user:alice@example.com", "", ref); !errors.Is(err, ErrBlankRevocation) {
		t.Fatalf("an empty sid: %v", err)
	}
}
```

(with `errors`, `memory` and `store` in that file's imports as needed).

`internal/broker/oidcrefresh_test.go`:

```go
package broker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/store"
)

// oidcSession is a fixture with OIDC and alice's live context on leaf1,
// authenticated an hour ago, indexed under her first session's sid.
func oidcSession(t *testing.T) (*fixture, func(extra map[string]any) string, string) {
	t.Helper()
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	at := f.b.Now().Add(-time.Hour)
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, "", at, at.Add(12*time.Hour))
	if err := f.st.IndexContext(context.Background(), alicePrincipal, store.SidKey(iss.URL, "s-first"), "",
		store.ContextRef{NAS: "leaf1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	tok := func(extra map[string]any) string { return f.idToken(t, iss, extra) }
	return f, tok, iss.URL
}

func challenge(t *testing.T, f *fixture, token string) string {
	t.Helper()
	w := f.bearer(context.Background(), "POST", "/v1/refresh/challenge", "", token)
	var c api.RefreshChallenge
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &c) != nil || c.Nonce == "" {
		t.Fatalf("challenge: %d %s", w.Code, w.Body)
	}
	return c.Nonce
}

func TestAnOIDCRefreshExtendsFromTheNewAuthTime(t *testing.T) {
	f, tok, iss := oidcSession(t)
	nonce := challenge(t, f, tok(map[string]any{"auth_time": f.b.Now().Add(-time.Hour).Unix(), "sid": "s-first"}))
	f.advance(time.Minute)
	fresh := f.b.Now()
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"sid": "s-second", "auth_time": fresh.Unix()}))
	var resp api.RefreshResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if resp.AuthTime != fresh.UTC().Format(time.RFC3339) || len(resp.Sessions) != 1 || resp.Sessions[0].Outcome != "extended" {
		t.Fatalf("response %+v", resp)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
	if !c.AuthTime.Equal(fresh) || !c.SessionExpires.Equal(fresh.Add(12*time.Hour)) {
		t.Fatalf("context auth_time %v expires %v", c.AuthTime, c.SessionExpires)
	}
	// Ruling 15: a logout of either session still reaches it.
	for _, sid := range []string{"s-first", "s-second"} {
		if refs, _ := f.st.ContextsBySid(context.Background(), store.SidKey(iss, sid)); len(refs) != 1 {
			t.Fatalf("by sid %s: %v", sid, refs)
		}
	}
}

func TestARefreshNeedsItsChallenge(t *testing.T) {
	f, tok, _ := oidcSession(t)
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": "made-up"})); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("a nonce the broker never issued: %d %s", w.Code, w.Body)
	}
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(nil)); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("no nonce: %d %s", w.Code, w.Body)
	}
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Second)
	again := tok(map[string]any{"nonce": nonce, "auth_time": f.b.Now().Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", again); w.Code != 200 {
		t.Fatalf("the refresh: %d %s", w.Code, w.Body)
	}
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", again); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("the same token again: %d %s", w.Code, w.Body)
	}
}

// The provider must have authenticated the person after the challenge
// (prompt=login honoured): an older auth_time extends nothing.
func TestARefreshTheProviderDidNotReauthenticateIsNotFresh(t *testing.T) {
	f, tok, _ := oidcSession(t)
	before := f.b.Now()
	nonce := challenge(t, f, tok(nil))
	f.advance(time.Minute)
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"auth_time": before.Add(-2 * time.Minute).Unix()}))
	if w.Code != 401 || !strings.Contains(w.Body.String(), "refresh_not_fresh") ||
		!strings.Contains(w.Body.String(), "prompt=login was not honoured") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
	if !c.AuthTime.Equal(before.Add(-time.Hour)) {
		t.Fatalf("a refused refresh moved auth_time to %v", c.AuthTime)
	}
}

// Review Focus 6: within clock_skew of the challenge is fresh.
func TestARefreshWithinSkewOfTheChallengeIsFresh(t *testing.T) {
	f, tok, _ := oidcSession(t)
	at := f.b.Now()
	nonce := challenge(t, f, tok(nil))
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"auth_time": at.Add(-30 * time.Second).Unix()}))
	if w.Code != 200 {
		t.Fatalf("an auth_time 30s before the challenge: %d %s", w.Code, w.Body)
	}
}

func TestAChallengeIsItsPrincipalsAlone(t *testing.T) {
	f, tok, _ := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	carol := tok(map[string]any{"nonce": nonce, "preferred_username": "carol@example.com", "auth_time": f.b.Now().Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", carol); w.Code != 401 ||
		!strings.Contains(w.Body.String(), "refresh_challenge_missing") {
		t.Fatalf("carol answering alice's challenge: %d %s", w.Code, w.Body)
	}
}

// Ruling 9: a person whose session reached the ceiling can still ask for a
// challenge with the token they hold.
func TestAChallengeOutlivesTheSessionCeiling(t *testing.T) {
	f, tok, _ := oidcSession(t)
	old := tok(map[string]any{"auth_time": f.b.Now().Add(-13 * time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, old); w.Code != 401 {
		t.Fatalf("a mint 13h after authentication: %d %s", w.Code, w.Body)
	}
	nonce := challenge(t, f, old)
	f.advance(time.Minute)
	w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
		"auth_time": f.b.Now().Unix()}))
	if w.Code != 200 {
		t.Fatalf("the refresh after it: %d %s", w.Code, w.Body)
	}
}

func TestChallengesArePacedPerPrincipal(t *testing.T) {
	f, tok, _ := oidcSession(t)
	challenge(t, f, tok(nil))
	w := f.bearer(context.Background(), "POST", "/v1/refresh/challenge", "", tok(nil))
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("a second challenge within 10s: %d %s", w.Code, w.Body)
	}
	f.advance(11 * time.Second)
	challenge(t, f, tok(nil))
}

func TestAMachineHasNoSessionToRefresh(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, machinePolicy)
	iss := f.withOIDC(t)
	now := f.b.Now()
	raw := iss.Token(t, "k1", map[string]any{"iss": iss.URL, "aud": "api://port49-svc", "sub": "svc",
		"azp": "Oxidized-01", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if w := f.bearer(context.Background(), "POST", "/v1/refresh/challenge", "", raw); w.Code != 400 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestARefreshBodyIsEmpty(t *testing.T) {
	f, tok, _ := oidcSession(t)
	nonce := challenge(t, f, tok(nil))
	w := f.bearer(context.Background(), "POST", "/v1/refresh", `{"nonce":"x","signature":"y"}`,
		tok(map[string]any{"nonce": nonce, "auth_time": f.b.Now().Unix()}))
	if w.Code != 400 {
		t.Fatalf("a certificate-path body on the OIDC path: %d %s", w.Code, w.Body)
	}
}

func (h hookStore) RefreshContext(ctx context.Context, k store.ContextKey, r store.ContextRefresh, ttl time.Duration) error {
	if f := h.before["RefreshContext"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.RefreshContext(ctx, k, r, ttl)
}

// Pre-flight I-2: a logout that lands while a refresh extends the session
// never leaves an extended context alive to its new ceiling. The new sid is
// indexed before the extension, so a logout's RevokeBySid that runs after
// the index reaches the context; a logout whose passes ran before the index
// leaves only its record, and the refresh's after-check marks what it
// extended before it answers 401.
func TestALogoutDuringARefreshMarksTheExtendedContext(t *testing.T) {
	for name, during := range map[string]func(f *fixture, iss string) error{
		"the logout's passes run after the index": func(f *fixture, iss string) error {
			ctx := context.Background()
			if err := f.st.PutLogout(ctx, store.Logout{Key: store.SidKey(iss, "s-second"), At: f.b.Now()},
				time.Hour); err != nil {
				return err
			}
			_, err := f.b.Sessions.RevokeBySid(ctx, store.SidKey(iss, "s-second"))
			return err
		},
		"only the logout record stands": func(f *fixture, iss string) error {
			return f.st.PutLogout(context.Background(), store.Logout{Key: store.SidKey(iss, "s-second"), At: f.b.Now()},
				time.Hour)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, tok, iss := oidcSession(t)
			nonce := challenge(t, f, tok(nil))
			f.advance(time.Minute)
			fired := false
			f.b.Store = hookStore{Store: f.st, before: map[string]func() error{"RefreshContext": func() error {
				if fired {
					return nil
				}
				fired = true
				return during(f, iss)
			}}}
			w := f.bearer(context.Background(), "POST", "/v1/refresh", "{}", tok(map[string]any{"nonce": nonce,
				"sid": "s-second", "auth_time": f.b.Now().Unix()}))
			if w.Code != 401 || !strings.Contains(w.Body.String(), "credential_revoked") {
				t.Fatalf("a refresh a logout landed during: %d %s", w.Code, w.Body)
			}
			c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf1", Username: "alice"})
			if c.RevokedAt.IsZero() {
				t.Fatal("a context the refresh extended outlived a logout that landed during it")
			}
		})
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/session/ ./internal/broker/ -run 'TestAddSid|TestAnOIDCRefresh|TestARefreshNeeds|TestARefreshTheProvider|TestARefreshWithinSkew|TestAChallengeIsIts|TestAChallengeOutlives|TestChallengesArePaced|TestAMachineHasNoSession|TestARefreshBodyIsEmpty|TestALogoutDuringARefresh' -count=1`
Expected: FAIL: `AddSid` undefined; a bearer challenge answered 400 "a refresh is made on the held
connection".

- [ ] **Step 3: `AddSid`**

In `internal/session/session.go`:

```go
// AddSid indexes ref under sid beside the keys it already has (plan 7h,
// Ruling 15): an OIDC refresh's new session, so a back-channel logout of
// either the old or the new session reaches the context. It adds an entry;
// it is not Refresh's ReindexSid, which moves one
// (TestRefreshMovesAuthTimeKeepsWindowReindexesSid), and the old entry
// staying is what Ruling 15 rests on. An empty sid is ErrBlankRevocation:
// it would index every OIDC login without one.
func (m *Manager) AddSid(ctx context.Context, principal, sid string, ref store.ContextRef) error {
	if sid == "" {
		return ErrBlankRevocation
	}
	return m.store.IndexContext(ctx, principal, sid, "", ref, m.indexTTL)
}
```

- [ ] **Step 4: `extend` indexes the new sid**

In `internal/broker/sessionrefresh.go`'s `extend`, the `RefreshContext` call's
`store.ContextRefresh` gains `Sid: newSid(cred, c)`, and **before** that call (after the
`age` is resolved):

```go
	// The new sid is indexed before the extension (pre-flight I-2): a
	// logout's RevokeBySid that runs after this reaches the context whether
	// or not the extension has landed. An entry for a context the extension
	// then does not reach is harmless: it names a context of this person.
	if sid := newSid(cred, c); sid != "" && b.Sessions != nil {
		if err := b.Sessions.AddSid(ctx, principal, sid, ref); err != nil {
			return "", time.Time{}, err
		}
	}
```

A certificate-path context the OIDC refresh extends is indexed under the OIDC `sid` too, so that
session's logout ends it (pre-flight M-17): fail closed, as Rulings 13 and 15 say.

with

```go
// newSid is the refresh's own sid when it differs from the context's: an
// OIDC refresh under a new provider session (Ruling 15); "" otherwise,
// and always on the certificate path, whose credential has none.
func newSid(cred store.Credential, c store.Context) string {
	if cred.Sid == "" || cred.Sid == c.Credential.Sid {
		return ""
	}
	return cred.Sid
}
```

- [ ] **Step 5: The OIDC challenge and refresh**

At the top of `refreshChallenge` and of `refresh`:

```go
	if _, ok, _ := bearerOf(r); ok {
		b.oidcChallenge(w, r) // b.oidcRefresh(w, r) in refresh
		return
	}
```

`internal/broker/oidcrefresh.go`:

```go
package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/broker/api"
	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/store"
)

// oidcChallengeTTL is how long an OIDC refresh challenge may be answered: a
// person entering their credentials and a second factor at the provider
// (Ruling 15).
const oidcChallengeTTL = 5 * time.Minute

// challengeKey is a challenge's once-only key: its SHA-256, so the store
// never holds a nonce that answers it.
func challengeKey(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return "refresh_challenge " + hex.EncodeToString(sum[:])
}

// paceKey paces a principal's challenges across replicas.
func paceKey(principal string) string { return "refresh_pace " + principal }

// challengeRec is what a challenge's once-only record holds.
type challengeRec struct {
	Principal string    `json:"principal"`
	Issuer    string    `json:"issuer"`
	IssuedAt  time.Time `json:"issued_at"`
}

// oidcChallenge is POST /v1/refresh/challenge with a bearer (Ruling 15):
// a nonce held in the store for oidcChallengeTTL, one per principal per
// refreshEvery.
func (b *Broker) oidcChallenge(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventRefresh, "issued no challenge")
	if !ok {
		return
	}
	if c.oidc.Domain != oidc.Humans {
		writeError(w, http.StatusBadRequest, "bad_request", "a machine has no session to refresh: fetch a new token")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), holdTimeout)
	defer cancel()
	now := b.Now()
	first, err := b.Store.PutOnce(ctx, paceKey(c.principal), nil, refreshEvery)
	switch {
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, 0, "the broker could not issue a challenge; retry shortly")
		return
	case !first:
		b.Metrics.SessionRefreshes.WithLabelValues("too_soon").Inc()
		w.Header().Set("Retry-After", strconv.Itoa(int(refreshEvery/time.Second)))
		writeError(w, http.StatusTooManyRequests, "refresh_too_soon", "you asked for a challenge moments ago; wait and retry")
		return
	}
	raw := make([]byte, api.RefreshNonceLen)
	if _, err := rand.Read(raw); err != nil {
		writeError(w, http.StatusInternalServerError, "broker_error", "no randomness for a challenge")
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(raw)
	rec, _ := json.Marshal(challengeRec{Principal: c.principal, Issuer: c.oidc.Issuer, IssuedAt: now})
	if ok, err := b.Store.PutOnce(ctx, challengeKey(nonce), rec, oidcChallengeTTL); err != nil || !ok {
		b.refreshStoreError(w, now, c.principal, c.cred, 0, "the broker could not issue a challenge; retry shortly")
		return
	}
	writeJSON(w, http.StatusOK, api.RefreshChallenge{Nonce: nonce,
		ExpiresAt: now.Add(oidcChallengeTTL).UTC().Format(time.RFC3339)})
}

// oidcRefresh is POST /v1/refresh with a bearer (Ruling 15): the new ID
// token's nonce must be the caller's unspent challenge, and its auth_time
// no earlier than the challenge; then the caller's live sessions take the
// policy in force and are extended from that auth_time.
func (b *Broker) oidcRefresh(w http.ResponseWriter, r *http.Request) {
	c, ok := b.authenticate(w, r, decision.EventRefresh, "extended nothing")
	if !ok {
		return
	}
	now := b.Now()
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
	if t := strings.TrimSpace(string(body)); err != nil || (t != "" && t != "{}") {
		writeError(w, http.StatusBadRequest, "bad_request", "an OIDC refresh's body is empty: the new ID token is "+
			"its bearer, and its nonce answers the challenge")
		return
	}
	if c.oidc.Domain != oidc.Humans {
		writeError(w, http.StatusBadRequest, "bad_request", "a machine has no session to refresh: fetch a new token")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), holdTimeout)
	defer cancel()
	refuse := func(code, detail string) {
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Principal: c.principal, Auth: c.auth()})
		writeError(w, http.StatusUnauthorized, code, detail)
	}
	if c.oidc.Nonce == "" {
		refuse("refresh_challenge_missing", "the token carries no nonce: ask for a challenge and send it as the "+
			"nonce of a prompt=login authentication")
		return
	}
	raw, err := b.Store.TakeOnce(ctx, challengeKey(c.oidc.Nonce))
	switch {
	case errors.Is(err, store.ErrNotFound):
		refuse("refresh_challenge_missing", "the token's nonce is no live challenge of this broker's: ask for one "+
			"and answer it within 5m, once")
		return
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, refreshEvery, "the broker could not read your challenge; "+
			"ask for another and retry")
		return
	}
	var ch challengeRec
	if json.Unmarshal(raw, &ch) != nil || ch.Principal != c.principal || ch.Issuer != c.oidc.Issuer {
		refuse("refresh_challenge_missing", "the token's nonce answers a challenge issued to someone else")
		return
	}
	if c.oidc.AuthTime.Before(ch.IssuedAt.Add(-b.Identity.Timing.ClockSkew)) {
		refuse("refresh_not_fresh", "your identity provider did not authenticate you again (prompt=login was not "+
			"honoured); the session was not extended")
		return
	}
	if err := b.noteOwner(ctx, *c.oidc); err != nil {
		b.refreshStoreError(w, now, c.principal, c.cred, refreshEvery, "the broker could not record your new "+
			"session for a logout to find, so it extended nothing; retry")
		return
	}
	dctx, dcancel := context.WithTimeout(r.Context(), b.memberBudget())
	m, answer, err := b.memberFor(dctx, c.principal)
	dcancel()
	if err != nil {
		dref := directoryRefusal(err)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: dref.Reason,
			Principal: c.principal, Auth: c.auth()})
		b.answerRefusal(w, r, dref)
		return
	}
	rep, err := b.RefreshSession(ctx, m, answer, c.cred, c.authTime, c.auth().OIDC)
	switch {
	case errors.Is(err, directory.ErrUsernameTaken):
		dref := directoryRefusal(err)
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.emit(decision.Record{TS: now, Event: decision.EventRefresh, Verdict: decision.VerdictDeny, Reason: dref.Reason,
			Principal: c.principal, Auth: c.auth()})
		b.answerRefusal(w, r, dref)
		return
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, refreshEvery, partialRefreshText)
		return
	}
	// The marks and the logouts again, after the extension's writes, as on
	// the certificate path.
	rv, revoked, err := b.revocation(ctx, c.principal, c.cred)
	var l store.Logout
	var out bool
	if err == nil && !revoked {
		l, out, err = b.loggedOut(ctx, *c.oidc)
	}
	switch {
	case err != nil:
		b.refreshStoreError(w, now, c.principal, c.cred, refreshEvery, partialRefreshText)
	case revoked:
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		b.refuseRevokedAs(w, decision.EventRefresh, b.Now(), c.principal, c.cred, rv)
	case out:
		// A logout landed during the refresh (pre-flight I-2). Its passes may
		// have run before the new sid was indexed, and a logout leaves no
		// standing mark (Ruling 13), so what this refresh extended is marked
		// here, by the new sid and context by context, before the answer.
		at := b.Now()
		var failed error
		if b.Sessions != nil {
			if _, err := b.Sessions.RevokeBySid(ctx, c.cred.Sid); err != nil {
				failed = err
			}
		}
		for _, s := range rep.Sessions {
			if s.Outcome != "extended" {
				continue
			}
			if _, err := b.revokeOwnContext(ctx, c.principal, s.Ref, at); err != nil && failed == nil {
				failed = err
			}
		}
		if failed != nil {
			b.say("logout: a session %s's refresh extended could not be marked after a logout landed during it "+
				"(%v); revoke the principal with port49 revoke", c.principal, failed)
		}
		b.Metrics.SessionRefreshes.WithLabelValues("refused").Inc()
		answerLoggedOut(w, l)
	default:
		writeJSON(w, http.StatusOK, rep.response(b.MaxSessionAge))
	}
}
```

Ruling 10 puts `auth.oidc` on every broker record of a bearer caller, the refresh's per-context
records included. `RefreshSession` therefore takes the caller's `*decision.OIDC` as a last
parameter and hands it to `extend`, which sets `rec.Auth.OIDC` from it:

```go
func (b *Broker) RefreshSession(ctx context.Context, m policy.Member, answer *directory.Answer,
	cred store.Credential, at time.Time, via *decision.OIDC) (SessionRefreshReport, error)
```

The certificate path's call in `refresh` passes `nil`, `oidcRefresh` passes `c.auth().OIDC`, and
the five test calls (`identity_api_test.go:132`, `member_test.go:786`, `broker_test.go:783` and
`:862`, `reindex_test.go:383`) gain a trailing `nil`.

- [ ] **Step 6: Run the tests to see them pass**

Run: `go test ./internal/session/ ./internal/broker/ -count=1 -race`
Expected: PASS, the certificate-path refresh tests unchanged.

- [ ] **Step 7: Commit**

```bash
git add internal/session/ internal/broker/
git commit -m "feat(broker): the OIDC refresh: a store-held nonce answered by a prompt=login token, auth_time from it, the new sid indexed beside the old

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 12: Back-channel logout: `POST /v1/logout` and `Broker.Logout`

**Files:**
- Create: `internal/broker/logout.go`
- Modify: `internal/broker/broker.go` (the route), `internal/broker/revoke.go` (`RevokeReport`'s
  OIDC fields, `recordRevocation`, `ByLogoutSid`, `ByLogoutSub`),
  `internal/broker/revokeown.go` (the token step extracted), `internal/daemon/metrics/metrics.go`
- Test: `internal/broker/logout_test.go`; `internal/broker/oidc_test.go` (`hookStore.PutLogout`)

**Interfaces:**
- Consumes: Task 6's `VerifyLogout`, `LogoutToken`, `MaxLogoutAge`; Task 8's `PutLogout`,
  `OIDCOwner`, `PutOnce`, `TakeOnce`; Task 9's `hookStore`; 7a's `revokeOwnContext`,
  `unreachedOf`, `recordRevocation`, `detach`; the session manager's `RevokeBySid`.
- Produces:
  - `ByLogoutSid = "sid"`, `ByLogoutSub = "sub"`;
  - `RevokeReport.OIDCIssuer`, `.Sid`, `.Sub`, and `.Principals []string` (every owner
    principal a logout reached; `Request.Principal` is the first), which `recordRevocation`
    writes as `revocation.principals` when there are several (Ruling 24);
  - `(*Broker).Logout(ctx, lt oidc.LogoutToken, origin string) (RevokeReport, error)`: the
    error is a logout record that could not be written (nothing applied); a later step's is
    `RevokeReport.Err`. It reaches every principal of the owner record whose domain is in
    `lt.Domains`, and says each one outside them (Rulings 22, 24);
  - `(*Broker).RevokeSid(ctx, issuer, sid, origin string) (RevokeReport, error)`: `Logout` by
    `sid` at the broker's now, with `Domains: b.Identity.HumanDomains(issuer)`, for Task 13;
  - `(*Broker).deleteOwnTokens(ctx, principal string, only *store.TokenKey, note func(error))
    int`, which `RevokeOwn` now calls;
  - `(*Broker).logout(w, r)`, routed `POST /v1/logout`;
  - `jtiKey(issuer, jti string) string`;
  - `metrics.OIDCLogouts *prometheus.CounterVec{outcome}`.

- [ ] **Step 1: Write the failing tests**

In `internal/broker/oidc_test.go`, `hookStore` gains:

```go
func (h hookStore) PutLogout(ctx context.Context, l store.Logout, ttl time.Duration) error {
	if f := h.before["PutLogout"]; f != nil {
		if err := f(); err != nil {
			return err
		}
	}
	return h.Store.PutLogout(ctx, l, ttl)
}

func (h hookStore) TakeOnce(ctx context.Context, key string) ([]byte, error) {
	if f := h.before["TakeOnce"]; f != nil {
		if err := f(); err != nil {
			return nil, err
		}
	}
	return h.Store.TakeOnce(ctx, key)
}
```

`internal/broker/logout_test.go`:

```go
package broker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
	"github.com/blanketfish/port49/internal/store"
)

// logoutFor is a Keycloak-shaped logout token for alice from iss at f's
// now: sub sub-alice, and sid when not "".
func logoutFor(t *testing.T, f *fixture, iss *oidctest.Issuer, sid, jti string) string {
	t.Helper()
	now := f.b.Now()
	c := map[string]any{"iss": iss.URL, "aud": testClientID, "iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"jti": jti, "sub": "sub-alice", "events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}}
	if sid != "" {
		c["sid"] = sid
	}
	return iss.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, c)
}

// postLogout posts raw as a logout token, form-encoded, with no client
// certificate, as a provider does.
func (f *fixture) postLogout(raw string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(url.Values{"logout_token": {raw}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.TLS = &tls.ConnectionState{}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}

// oidcLoggedIn is alice minted for leaf1 and nx1 by OIDC, logged in on
// leaf1 (a context indexed under her session's sid, as the daemon indexes
// a login), with nx1's token unspent.
func oidcLoggedIn(t *testing.T) (*fixture, *oidctest.Issuer, string) {
	t.Helper()
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	tok := f.idToken(t, iss, nil)
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", `{"devices":["leaf1","nx1"],"ttl_seconds":60}`, tok); w.Code != 200 {
		t.Fatalf("mint: %d %s", w.Code, w.Body)
	}
	now := f.b.Now()
	f.liveContextAt(t, "leaf1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour))
	if err := f.st.IndexContext(context.Background(), alicePrincipal, store.SidKey(iss.URL, "s-sub-alice"), "",
		store.ContextRef{NAS: "leaf1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	_ = f.st.DeleteTokens(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}) // spent at login
	return f, iss, tok
}

func revokedAt(t *testing.T, f *fixture, device string) time.Time {
	t.Helper()
	c, err := f.st.GetContext(context.Background(), store.ContextKey{NAS: device, Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	return c.RevokedAt
}

// A logout by sid ends that session's context, deletes the person's unspent
// tokens, refuses the session's token from then on, and is one revoke
// record; it needed no certificate and no right (spec §2).
func TestALogoutBySidEndsThatSession(t *testing.T) {
	f, iss, tok := oidcLoggedIn(t)
	w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j1"))
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	if revokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("the session's context was not marked")
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 0 {
		t.Fatal("the person's unspent token on nx1 survived")
	}
	revs := eventsOf(f.records(t), decision.EventRevoke)
	rv := revs[len(revs)-1]["revocation"].(map[string]any)
	if rv["by"] != "sid" || rv["sid"] != "s-sub-alice" || rv["oidc_issuer"] != iss.URL ||
		rv["origin"] != "backchannel_logout "+iss.URL || revs[len(revs)-1]["principal"] != alicePrincipal {
		t.Fatalf("revoke record %v", revs[len(revs)-1])
	}
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, tok); w.Code != 401 {
		t.Fatalf("the ended session's token minted: %d %s", w.Code, w.Body)
	}
	fresh := f.idToken(t, iss, map[string]any{"sid": "s-new"})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, fresh); w.Code != 200 {
		t.Fatalf("a new login after the logout: %d %s", w.Code, w.Body)
	}
}

// Review Focus 7: tokens minted before the logout are found through the
// owner record and deleted.
func TestALogoutFindsTokensMintedBeforeIt(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j1")); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	keys, _ := f.st.TokensByPrincipal(context.Background(), alicePrincipal)
	for _, k := range keys {
		if toks, _ := f.st.Candidates(context.Background(), k); len(toks) != 0 {
			t.Fatalf("a token under %v survived the logout", k)
		}
	}
}

// A logout by sub alone ends every context of the person, a
// certificate-path one included (decision 15; Ruling 13).
func TestALogoutBySubEndsEveryContextOfThePerson(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	now := f.b.Now()
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, certKey(f.alice), now, now.Add(12*time.Hour))
	if w := f.postLogout(logoutFor(t, f, iss, "", "j-sub")); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, d := range []string{"leaf1", "nx1"} {
		if revokedAt(t, f, d).IsZero() {
			t.Fatalf("%s's context was not marked", d)
		}
	}
}

// Review Focus 5: the provider sending the same logout twice changes
// nothing the second time, even for a session opened between the two.
func TestALogoutReplayedIsANoOp(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	raw := logoutFor(t, f, iss, "", "j-replay")
	if w := f.postLogout(raw); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	f.advance(2 * time.Minute)
	now := f.b.Now()
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour)) // a login after the logout
	if w := f.postLogout(raw); w.Code != 200 {
		t.Fatalf("the replay: %d %s", w.Code, w.Body)
	}
	if !revokedAt(t, f, "nx1").IsZero() {
		t.Fatal("a replayed logout ended a session opened after it")
	}
	if got := testutil.ToFloat64(f.b.Metrics.OIDCLogouts.WithLabelValues("replayed")); got != 1 {
		t.Fatalf("replayed counted %v", got)
	}
}

// Review Focus 5: a logout for a session port49 never saw still refuses
// that session's tokens from then on.
func TestALogoutForAnUnseenSessionStillRefusesItsTokens(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	if w := f.postLogout(logoutFor(t, f, iss, "s-unseen", "j2")); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if got := testutil.ToFloat64(f.b.Metrics.OIDCLogouts.WithLabelValues("nothing")); got != 1 {
		t.Fatalf("nothing counted %v", got)
	}
	tok := f.idToken(t, iss, map[string]any{"sid": "s-unseen"})
	if w := f.bearer(context.Background(), "POST", "/v1/tokens", mintLeaf1, tok); w.Code != 401 {
		t.Fatalf("a token of the logged-out session: %d %s", w.Code, w.Body)
	}
}

// Review Focus 5: with the store down the logout is 503, its jti given
// back, and the provider's retry applies it.
func TestALogoutTheStoreFailedIsRetriable(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	real := f.b.Store
	f.b.Store = hookStore{Store: real, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable }}}
	raw := logoutFor(t, f, iss, "s-sub-alice", "j3")
	w := f.postLogout(raw)
	if w.Code != 503 || w.Header().Get("Retry-After") != "30" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body)
	}
	if !revokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("a logout whose record failed marked a context")
	}
	f.b.Store = real
	if w := f.postLogout(raw); w.Code != 200 || revokedAt(t, f, "leaf1").IsZero() {
		t.Fatalf("the retry: %d %s", w.Code, w.Body)
	}
}

func TestALogoutThatDoesNotValidateIs400AndReachesNothing(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	forger := oidctest.NewIssuer(t)
	forged := forger.TokenWith(t, "k1", map[string]any{"kid": "k1", "typ": "logout+jwt"}, map[string]any{
		"iss": iss.URL, "aud": testClientID, "iat": f.b.Now().Unix(), "jti": "j4", "sid": "s-sub-alice",
		"events": map[string]any{oidc.BackchannelLogoutEvent: map[string]any{}}})
	before := len(eventsOf(f.records(t), decision.EventRevoke))
	w := f.postLogout(forged)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_request"`) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !revokedAt(t, f, "leaf1").IsZero() || len(eventsOf(f.records(t), decision.EventRevoke)) != before {
		t.Fatal("a forged logout reached something")
	}
}

// Ruling 24, pre-flight I-1: a person renamed under one sub (alice@ to
// alice2@) is two principals on the owner record, and a sub logout ends
// both, and names both in its record.
func TestALogoutReachesEveryPrincipalOfTheSub(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	ctx := context.Background()
	now := f.b.Now()
	const alice2 = "user:alice2@example.com"
	if err := f.st.PutOIDCOwner(ctx, store.OIDCKey(store.OIDCSub, iss.URL, "sub-alice"), alice2, time.Hour); err != nil {
		t.Fatal(err)
	}
	f.liveContextAt(t, "nx1", "alice2", alice2, "", now, now.Add(12*time.Hour))
	if w := f.postLogout(logoutFor(t, f, iss, "", "j-rename")); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, k := range []store.ContextKey{{NAS: "leaf1", Username: "alice"}, {NAS: "nx1", Username: "alice2"}} {
		if c, err := f.st.GetContext(ctx, k); err != nil || c.RevokedAt.IsZero() {
			t.Fatalf("%v was not marked: %v", k, err)
		}
	}
	revs := eventsOf(f.records(t), decision.EventRevoke)
	rv := revs[len(revs)-1]["revocation"].(map[string]any)
	if fmt.Sprint(rv["principals"]) != "["+alice2+" "+alicePrincipal+"]" {
		t.Fatalf("revocation.principals %v", rv["principals"])
	}
}

// Ruling 22, pre-flight C-2: a second provider cannot mint as Alice, and its
// sub logout reaches none of her contexts or tokens, even through an owner
// record that names her (one left from before a configuration change).
func TestAnotherIssuersSubLogoutReachesNoneOfAlices(t *testing.T) {
	f, _, _ := oidcLoggedIn(t)
	contractor := oidctest.NewIssuer(t)
	f.addIssuer(t, contractor, "contractor.example.net", false)
	ctx := context.Background()
	impostor := contractor.IDToken(t, "k1", testClientID, "sub-alice", f.b.Now(),
		map[string]any{"preferred_username": "alice@example.com"})
	if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, impostor); w.Code != 401 ||
		!strings.Contains(w.Body.String(), string(decision.IdentityUnmapped)) {
		t.Fatalf("another issuer naming alice: %d %s", w.Code, w.Body)
	}
	key := store.OIDCKey(store.OIDCSub, contractor.URL, "sub-alice")
	if _, err := f.st.OIDCOwner(ctx, key); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the refused mint wrote an owner record: %v", err)
	}
	if err := f.st.PutOIDCOwner(ctx, key, alicePrincipal, time.Hour); err != nil {
		t.Fatal(err)
	}
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	if w := f.postLogout(logoutFor(t, f, contractor, "", "j-contractor")); w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !revokedAt(t, f, "leaf1").IsZero() {
		t.Fatal("another issuer's sub logout ended alice's context")
	}
	if toks, _ := f.st.Candidates(ctx, store.TokenKey{NAS: "nx1", Username: "alice"}); len(toks) != 1 {
		t.Fatal("another issuer's sub logout deleted alice's unspent token")
	}
	if !strings.Contains(said.String(), "outside this verifier's principal_domains") {
		t.Fatalf("the skipped principal was not said:\n%s", said.String())
	}
}

// Pre-flight M-13: a logout whose writes fail and whose jti cannot be given
// back says so, naming the session and how to end it by hand, since the
// provider's retry will be answered 200 "replayed".
func TestALogoutWhoseJTICannotBeGivenBackSaysSo(t *testing.T) {
	f, iss, _ := oidcLoggedIn(t)
	var said strings.Builder
	f.b.Say = func(format string, args ...any) { said.WriteString(fmt.Sprintf(format, args...) + "\n") }
	f.b.Store = hookStore{Store: f.st, before: map[string]func() error{
		"PutLogout": func() error { return store.ErrUnavailable },
		"TakeOnce":  func() error { return store.ErrUnavailable }}}
	if w := f.postLogout(logoutFor(t, f, iss, "s-sub-alice", "j-lost")); w.Code != 503 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !strings.Contains(said.String(), "could not be given back") ||
		!strings.Contains(said.String(), `POST /v1/tokens/revoke {"sid": "s-sub-alice"`) {
		t.Fatalf("the lost logout was not said with its manual end:\n%s", said.String())
	}
}

func TestALogoutRequestIsAForm(t *testing.T) {
	f := newFixture(t, 8)
	iss := f.withOIDC(t)
	raw := logoutFor(t, f, iss, "s", "j5")
	for name, req := range map[string]func() *httptest.ResponseRecorder{
		"json": func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(`{"logout_token":"`+raw+`"}`))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			f.b.Handler().ServeHTTP(w, r)
			return w
		},
		"two tokens": func() *httptest.ResponseRecorder {
			r := httptest.NewRequest("POST", "/v1/logout", strings.NewReader(url.Values{"logout_token": {raw, raw}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			f.b.Handler().ServeHTTP(w, r)
			return w
		},
		"oversized": func() *httptest.ResponseRecorder {
			return f.postLogout(strings.Repeat("a", 17<<10))
		},
	} {
		if w := req(); w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'TestALogout|TestAnotherIssuersSubLogout' -count=1`
Expected: FAIL to compile: `OIDCLogouts` undefined; `POST /v1/logout` is 404 or 405.

- [ ] **Step 3: The metric**

In `internal/daemon/metrics/metrics.go`:

```go
	// port49_oidc_logouts_total{outcome}: back-channel logouts: applied,
	// nothing (a valid logout that reached no context or token), replayed,
	// invalid, unavailable (the provider's keys), store_error, partial
	// (plan 7h).
	OIDCLogouts *prometheus.CounterVec
```

```go
		OIDCLogouts: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_oidc_logouts_total",
			Help: "OIDC back-channel logouts by outcome: applied, nothing, replayed, invalid, unavailable, store_error, partial."},
			[]string{"outcome"}),
```

- [ ] **Step 4: The revocation's OIDC fields, and the token step shared**

In `internal/broker/revoke.go`:

```go
	ByLogoutSid = store.OIDCSid // an OIDC session ended (plan 7h)
	ByLogoutSub = store.OIDCSub // every session of an OIDC subject ended
```

in the `By…` block; `RevokeReport` gains

```go
	// OIDCIssuer and Sid or Sub name what a ByLogoutSid or ByLogoutSub
	// revocation ended (plan 7h).
	OIDCIssuer, Sid, Sub string
	// Principals is every owner principal a logout reached (Ruling 24);
	// Request.Principal is the first.
	Principals []string
```

and `recordRevocation` sets `body.OIDCIssuer, body.Sid, body.Sub = rep.OIDCIssuer, rep.Sid,
rep.Sub`, and `body.Principals = rep.Principals` when there are more than one.

In `internal/broker/revokeown.go`, the token loop of `RevokeOwn` (from `keys, err :=
b.Store.TokensByPrincipal` through the end of its `for`) moves into:

```go
// deleteOwnTokens deletes principal's own unspent tokens, by ID, everywhere
// or on only, superseding each key it touched; it returns how many keys.
// A store error is told to note and the rest still run.
func (b *Broker) deleteOwnTokens(ctx context.Context, principal string, only *store.TokenKey, note func(error)) int {
	n := 0
	keys, err := b.Store.TokensByPrincipal(ctx, principal)
	note(err)
	for _, k := range keys {
		… the loop's body as it is, with rep.TokenKeys++ as n++ …
	}
	return n
}
```

and `RevokeOwn` calls `rep.TokenKeys = b.deleteOwnTokens(ctx, principal, only, note)`.

- [ ] **Step 5: `internal/broker/logout.go`**

```go
package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/printsafe"
	"github.com/blanketfish/port49/internal/store"
)

// maxLogoutBody bounds a logout request: a logout token is a few hundred
// bytes (Ruling 12).
const maxLogoutBody = 16 << 10

// jtiKey is a logout token's once-only key.
func jtiKey(issuer, jti string) string { return "logout_jti " + store.OIDCKey("jti", issuer, jti) }

// logout is POST /v1/logout (Ruling 12; OpenID Connect Back-Channel Logout
// 1.0 §2.5–§2.8): no certificate and no api: right, the provider's
// signature on the token the only authentication.
func (b *Broker) logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	count := func(outcome string) { b.Metrics.OIDCLogouts.WithLabelValues(outcome).Inc() }
	bad := func(why string) {
		count("invalid")
		b.sayOnce("logout_invalid", sayEvery, "logout: a logout request was refused: %s", printsafe.Line(why, 300))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": why})
	}
	retry := func(outcome, why string) {
		count(outcome)
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable",
			"error_description": why})
	}
	if b.Identity == nil || len(b.Identity.Humans()) == 0 {
		bad("this broker has no human OIDC verifier, so it takes no logout")
		return
	}
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	body, err := io.ReadAll(io.LimitReader(r.Body, maxLogoutBody+1))
	if mt != "application/x-www-form-urlencoded" || err != nil || len(body) > maxLogoutBody {
		bad("a logout is a form, application/x-www-form-urlencoded, of at most 16 KiB")
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form["logout_token"]) != 1 {
		bad("a logout carries exactly one logout_token")
		return
	}
	vctx, vcancel := context.WithTimeout(r.Context(), holdTimeout)
	lt, err := b.Identity.VerifyLogout(vctx, form["logout_token"][0])
	vcancel()
	switch {
	case errors.Is(err, oidc.ErrUnavailable):
		retry("unavailable", "the broker cannot use the identity provider's keys right now")
		return
	case err != nil:
		bad(err.Error())
		return
	}
	ctx, cancel := b.detach(r.Context())
	defer cancel()
	skew := b.Identity.Timing.ClockSkew
	first, err := b.Store.PutOnce(ctx, jtiKey(lt.Issuer, lt.JTI), nil, oidc.MaxLogoutAge+2*skew)
	switch {
	case err != nil:
		retry("store_error", "the broker's store did not answer; the logout was not applied")
		return
	case !first:
		count("replayed")
		w.WriteHeader(http.StatusOK)
		return
	}
	rep, err := b.Logout(ctx, lt, "backchannel_logout "+lt.Issuer)
	if err != nil || rep.Err != nil {
		// Taken back so the provider's retry applies it again; every step
		// is safe to run twice.
		_, terr := b.Store.TakeOnce(ctx, jtiKey(lt.Issuer, lt.JTI))
		outcome := "store_error"
		if err == nil {
			outcome = "partial"
		}
		b.say("logout: a logout token from %s could not be applied: the store did not answer; answered 503 so the "+
			"provider may retry; if it does not, revoke the principal with port49 revoke once the store returns",
			lt.Issuer)
		if terr != nil && !errors.Is(terr, store.ErrNotFound) {
			// The provider's retry will be answered 200 "replayed" and do
			// nothing (pre-flight M-13): say how to end it by hand.
			what, byHand := "sub "+printsafe.Line(lt.Subject, 80), "port49 revoke <principal>"
			if lt.Sid != "" {
				what = "sid " + printsafe.Line(lt.Sid, 80)
				byHand = fmt.Sprintf(`POST /v1/tokens/revoke {"sid": %q, "issuer": %q} or %s`, lt.Sid, lt.Issuer, byHand)
			}
			b.say("logout: the logout of %s from %s could not be given back for a retry (%s): the provider's retry "+
				"will be answered 200 and do nothing; end it by hand with %s", what, lt.Issuer,
				printsafe.Line(terr.Error(), 200), byHand)
		}
		retry(outcome, "the broker's store did not answer; the logout may be partly applied: retry")
		return
	}
	if len(rep.Contexts) == 0 && rep.TokenKeys == 0 {
		count("nothing")
	} else {
		count("applied")
	}
	w.WriteHeader(http.StatusOK)
}

// RevokeSid ends one OIDC session as a back-channel logout by sid does, at
// the broker's now (Ruling 14), reaching only principals in the issuer's
// human verifiers' domains (Ruling 22).
func (b *Broker) RevokeSid(ctx context.Context, issuer, sid, origin string) (RevokeReport, error) {
	return b.Logout(ctx, oidc.LogoutToken{Issuer: issuer, Sid: sid, IssuedAt: b.Now(),
		Domains: b.Identity.HumanDomains(issuer)}, origin)
}

// Logout is Ruling 13: the logout record first, then each owner principal's
// own unspent tokens, then the contexts twice, the receipts, and one revoke
// record. It leaves no standing mark. It reaches only owner principals in
// lt.Domains (Ruling 22), and every one of them (Ruling 24). The error is
// the logout record not written, when nothing was applied; a later step's
// is the report's Err, and the steps after it still run.
func (b *Broker) Logout(ctx context.Context, lt oidc.LogoutToken, origin string) (RevokeReport, error) {
	ctx, cancel := b.detach(ctx)
	defer cancel()
	now := b.Now()
	t := b.Identity.Timing
	rep := RevokeReport{By: ByLogoutSub, OIDCIssuer: lt.Issuer, Sub: lt.Subject,
		Request: RevokeRequest{Origin: origin}, Mark: store.Revocation{At: now}}
	key := store.OIDCKey(store.OIDCSub, lt.Issuer, lt.Subject)
	if lt.Sid != "" {
		rep.By, rep.Sid, rep.Sub, key = ByLogoutSid, lt.Sid, "", store.SidKey(lt.Issuer, lt.Sid)
	}
	if err := b.Store.PutLogout(ctx, store.Logout{Key: key, At: lt.IssuedAt, Origin: origin},
		t.MaxTokenAge+2*t.ClockSkew); err != nil {
		return RevokeReport{}, err
	}
	note := func(err error) {
		if err != nil && rep.Err == nil {
			rep.Err = err
		}
	}
	owner, err := b.Store.OIDCOwner(ctx, key)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		note(err)
	}
	// Every owner principal (Ruling 24), within the provider's domains alone
	// (Ruling 22): an entry outside them, left from before a configuration
	// change, is said and not reached.
	for _, p := range owner.Names() {
		if !slices.Contains(lt.Domains, oidc.DomainOf(p)) {
			b.say("logout: %s: the owner record names %s, outside this verifier's principal_domains (%s); it is not "+
				"reached", lt.Issuer, p, strings.Join(lt.Domains, ", "))
			continue
		}
		rep.Principals = append(rep.Principals, p)
	}
	if len(rep.Principals) > 0 {
		rep.Request.Principal = rep.Principals[0]
	}
	for _, p := range rep.Principals {
		rep.TokenKeys += b.deleteOwnTokens(ctx, p, nil, note)
	}
	seen := map[store.ContextRef]bool{}
	for pass := 0; pass < 2; pass++ {
		var refs []store.ContextRef
		switch {
		case rep.By == ByLogoutSid && b.Sessions != nil:
			refs, err = b.Sessions.RevokeBySid(ctx, key)
			note(err)
		default:
			for _, p := range rep.Principals {
				all, err := b.Store.ContextsByPrincipal(ctx, p)
				note(err)
				for _, ref := range all {
					marked, err := b.revokeOwnContext(ctx, p, ref, now)
					note(err)
					if marked {
						refs = append(refs, ref)
					}
				}
			}
		}
		for _, ref := range refs {
			if !seen[ref] {
				seen[ref] = true
				rep.Contexts = append(rep.Contexts, ref)
			}
		}
	}
	if rep.By == ByLogoutSub {
		for _, p := range rep.Principals {
			_, err := b.Store.DeleteReceiptsByPrincipal(ctx, p)
			note(err)
		}
	}
	rep.Unreached = b.unreachedOf(rep.Contexts)
	outcome := "applied"
	if rep.Err != nil {
		outcome = "partial"
	}
	b.recordRevocation(now, rep, decision.VerdictDeny, decision.CredentialRevoked, outcome)
	b.say("%s", rep.logoutText(lt.IssuedAt.Add(t.ClockSkew), b.ownerTTL()))
	return rep, nil
}

// logoutText is Logout's line (What the operator sees).
func (r RevokeReport) logoutText(cutoff time.Time, ownerTTL time.Duration) string {
	who := strings.Join(r.Principals, ", ")
	var where []string
	for _, ref := range r.Contexts {
		where = append(where, ref.NAS+"/"+ref.Username)
	}
	switch {
	case r.By == ByLogoutSid && who != "":
		return fmt.Sprintf("logout: %s ended session sid %s of %s: %d contexts marked (%s), tokens on %d keys deleted",
			r.OIDCIssuer, printsafe.Line(r.Sid, 80), who, len(r.Contexts), strings.Join(where, ", "), r.TokenKeys)
	case r.By == ByLogoutSid:
		return fmt.Sprintf("logout: %s ended session sid %s, which no mint is on record for; %d contexts marked; "+
			"its tokens are refused from now on", r.OIDCIssuer, printsafe.Line(r.Sid, 80), len(r.Contexts))
	case who != "":
		return fmt.Sprintf("logout: %s ended every session of sub %s, %s: %d contexts marked (%s), tokens on %d keys "+
			"deleted", r.OIDCIssuer, printsafe.Line(r.Sub, 80), who, len(r.Contexts), strings.Join(where, ", "), r.TokenKeys)
	}
	return fmt.Sprintf("logout: %s ended every session of sub %s: no principal is on record for it (no mint in the "+
		"last %s); tokens it issued before %s are refused from now on; to end a person's sessions at once use "+
		"port49 revoke", r.OIDCIssuer, printsafe.Line(r.Sub, 80), ownerTTL, cutoff.UTC().Format(time.RFC3339))
}
```

(`time` joins the imports.) In `Handler`, add `mux.HandleFunc("POST /v1/logout", b.logout)`.

The `RevokeBySid` path deletes the receipts of the principals behind the contexts it marks
(`session.Manager.mark`); the `sub` path marks with `revokeOwnContext`, which does not, so it
deletes each owner principal's receipts itself.

- [ ] **Step 6: Run the tests to see them pass**

Run: `go test ./internal/broker/ ./internal/daemon/metrics/ -count=1 -race`
Expected: PASS, `RevokeOwn`'s tests unchanged by the extraction.

- [ ] **Step 7: Commit**

```bash
git add internal/broker/ internal/daemon/metrics/metrics.go
git commit -m "feat(broker): back-channel logout: a bounded logout record, the person's tokens, the session's contexts twice, no standing mark

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 13: `POST /v1/tokens/revoke` by `sid`, under `revoke_others`

**Files:**
- Modify: `internal/broker/revoke_api.go`, `internal/broker/revoke.go` (`Text`)
- Test: `internal/broker/revoke_api_test.go`

**Interfaces:**
- Consumes: Task 12's `RevokeSid`, `ByLogoutSid`, `RevokeReport.OIDCIssuer`/`Sid`; Task 2's
  `api.RevokeRequest.Issuer`; 7c's `mayOthers`, `refuseRight`, `answerRevocation`.
- Produces: the `sid` form of `POST /v1/tokens/revoke` (Ruling 14), holding the asker's
  `holdOwnRevoke` slot (pre-flight M-15), and `RevokeReport.Text` for `ByLogoutSid` and
  `ByLogoutSub`. The handler's identifier is `asker` (Task 9's rename, pre-flight M-19).

- [ ] **Step 1: Write the failing tests**

In `internal/broker/revoke_api_test.go`:

```go
// A policy where carol, on call, holds revoke_others.
const onCallPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: oncall, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s, api: [revoke_others]}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: oncall, scope: all_devices, roles: [network_admin], max_privilege: admin}
`

func TestRevokeBySidNeedsTheRightAndEndsTheSession(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	iss := f.withOIDC(t)
	ctx := context.Background()
	now := f.b.Now()
	if w := f.bearer(ctx, "POST", "/v1/tokens", mintLeaf1, f.idToken(t, iss, nil)); w.Code != 200 {
		t.Fatalf("alice's mint: %d %s", w.Code, w.Body)
	}
	f.liveContextAt(t, "nx1", "alice", alicePrincipal, "", now, now.Add(12*time.Hour))
	if err := f.st.IndexContext(ctx, alicePrincipal, store.SidKey(iss.URL, "s-sub-alice"), "",
		store.ContextRef{NAS: "nx1", Username: "alice"}, time.Hour); err != nil {
		t.Fatal(err)
	}
	body := `{"sid":"s-sub-alice"}`
	// alice herself holds no right: 403, recorded, nothing ended.
	if w := f.bearer(ctx, "POST", "/v1/tokens/revoke", body, f.idToken(t, iss, nil)); w.Code != 403 ||
		!strings.Contains(w.Body.String(), "api_right_missing") {
		t.Fatalf("without the right: %d %s", w.Code, w.Body)
	}
	carol := iss.IDToken(t, "k1", testClientID, "sub-carol", now, map[string]any{"preferred_username": "carol@example.com"})
	w := f.bearer(ctx, "POST", "/v1/tokens/revoke", body, carol)
	var resp api.RevokeResponse
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if resp.By != "sid" || resp.Principal != alicePrincipal || resp.Standing || resp.Contexts != 1 || resp.TokenKeys != 1 ||
		!strings.Contains(resp.Text, "s-sub-alice") {
		t.Fatalf("response %+v", resp)
	}
	revs := eventsOf(f.records(t), decision.EventRevoke)
	if rv := revs[len(revs)-1]["revocation"].(map[string]any); rv["origin"] != "api user:carol@example.com" {
		t.Fatalf("origin %v", rv["origin"])
	}
}

// Pre-flight M-15: a revocation by sid takes the asker's one revocation
// slot, so a retry while one runs is 503 revocation_busy and ends nothing.
func TestRevokeBySidHoldsTheAskersSlot(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	iss := f.withOIDC(t)
	carol := iss.IDToken(t, "k1", testClientID, "sub-carol", f.b.Now(), map[string]any{"preferred_username": "carol@example.com"})
	release, ok := f.b.holdOwnRevoke("user:carol@example.com")
	if !ok {
		t.Fatal("the slot was taken")
	}
	w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", `{"sid":"s-sub-alice"}`, carol)
	release()
	if w.Code != 503 || !strings.Contains(w.Body.String(), "revocation_busy") {
		t.Fatalf("a sid revocation while carol's slot is held: %d %s", w.Code, w.Body)
	}
}

func TestRevokeBySidRefusesWhatItCannotName(t *testing.T) {
	f := newFixtureWithPolicy(t, 8, onCallPolicy)
	iss := f.withOIDC(t)
	carol := iss.IDToken(t, "k1", testClientID, "sub-carol", f.b.Now(), map[string]any{"preferred_username": "carol@example.com"})
	for _, body := range []string{
		`{"sid":"s","principal":"user:alice@example.com"}`,
		`{"sid":"s","mine":true}`,
		`{"sid":"s","device":"leaf1","username":"alice"}`,
		`{"sid":"s","issuer":"https://not-configured.example"}`,
		`{"issuer":"` + iss.URL + `"}`,
		`{"sid":"has space"}`,
	} {
		if w := f.bearer(context.Background(), "POST", "/v1/tokens/revoke", body, carol); w.Code != 400 {
			t.Errorf("%s: %d %s", body, w.Code, w.Body)
		}
	}
}
```

(imports gain `encoding/json`, `time`, `api`, `decision` and `store` if the file lacks them).

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'TestRevokeBySid|TestRevokeBySidHoldsTheAskersSlot' -count=1`
Expected: FAIL: a `sid` is answered 400 "revocation by OIDC sid arrives with OIDC (plan 7h)".

- [ ] **Step 3: Implement**

In `tokensRevoke`, replace the `case req.Sid != "":` refusal with:

```go
	case req.Sid != "" && (req.Mine || req.Principal != "" || byKey):
		writeError(w, http.StatusBadRequest, "bad_request", "name a sid alone, with its issuer when more than one "+
			"provider is configured")
		return
	case req.Issuer != "" && req.Sid == "":
		writeError(w, http.StatusBadRequest, "bad_request", "an issuer names a sid's provider; name the sid")
		return
```

and in the case after them, `case !req.Mine && !byKey && req.Principal == "", …`, add `req.Sid ==
""` to its first clause, so a body naming a sid alone is not refused as naming nothing:

```go
	case req.Sid == "" && !req.Mine && !byKey && req.Principal == "", byKey && (req.Device == "" || req.Username == ""):
```

Then after `pol := b.Policy.Load()` and the `mayOthers`/`refused` closures:

```go
	if req.Sid != "" {
		b.revokeSid(w, r, pol, asker, origin, req, mayOthers, refused)
		return
	}
```

with, in the same file:

```go
// revokeSid is the sid form (Ruling 14): one OIDC session ended as a
// back-channel logout by sid ends it, under revoke_others, its origin the
// caller. It holds the asker's one revocation slot while it runs, as a self
// or key revocation does (holdOwnRevoke): RevokeSid runs detached, so a
// caller retrying against a slow store would otherwise stack one detached
// logout per retry (pre-flight M-15).
func (b *Broker) revokeSid(w http.ResponseWriter, r *http.Request, pol *policy.Policy, asker, origin string,
	req api.RevokeRequest, mayOthers func() (bool, *BindRefusal), refused func(*BindRefusal, decision.Record)) {
	var humans []string
	if b.Identity != nil {
		for _, v := range b.Identity.Humans() {
			humans = append(humans, v.Issuer)
		}
	}
	issuer := req.Issuer
	switch {
	case len(humans) == 0:
		writeError(w, http.StatusBadRequest, "bad_request", "this broker has no human OIDC verifier, so no sid")
		return
	case issuer == "" && len(humans) > 1:
		writeError(w, http.StatusBadRequest, "bad_request", "name the sid's issuer: more than one human OIDC "+
			"verifier is configured")
		return
	case issuer == "":
		issuer = humans[0]
	case !slices.Contains(humans, issuer):
		writeError(w, http.StatusBadRequest, "bad_request", "the issuer is no human OIDC verifier's")
		return
	}
	if len(req.Sid) > 255 || strings.IndexFunc(req.Sid, func(r rune) bool { return r < 0x21 || r > 0x7e }) >= 0 {
		writeError(w, http.StatusBadRequest, "bad_request", "a sid is 1 to 255 printable ASCII characters")
		return
	}
	now := b.Now()
	rec := decision.Record{TS: now, Event: decision.EventRevoke, Revocation: &decision.Revocation{By: ByLogoutSid,
		OIDCIssuer: issuer, Sid: req.Sid, At: decision.FormatTime(now), Origin: origin}}
	switch ok, ref := mayOthers(); {
	case ref != nil:
		rec.Principal = asker
		refused(ref, rec)
		return
	case !ok:
		b.refuseRight(w, rec, policy.RightRevokeOthers, "ending an OIDC session")
		return
	}
	release, held := b.holdOwnRevoke(asker)
	if !held {
		writeBusy(w, "another revocation of yours is still running, so this session was not ended; try again once "+
			"it finishes")
		return
	}
	defer release()
	rep, err := b.RevokeSid(r.Context(), issuer, req.Sid, origin)
	if err != nil {
		b.logf("broker: a revocation of sid %s at %s asked by %s was not made: %v", printsafe.Line(req.Sid, 80),
			issuer, asker, err)
		w.Header().Set("Retry-After", "10")
		writeError(w, http.StatusServiceUnavailable, string(decision.StoreUnavailable), "the session's end could not "+
			"be recorded, so nothing was revoked; try again")
		return
	}
	b.answerRevocation(w, pol, rep, origin)
}
```

(`slices` and `printsafe` imported.)

In `internal/broker/revoke.go`'s `Text`, before `default:`:

```go
	case ByLogoutSid, ByLogoutSub:
		what := "session sid " + r.Sid
		if r.By == ByLogoutSub {
			what = "every session of sub " + r.Sub
		}
		owner := ""
		if r.Request.Principal != "" {
			owner = " (" + r.Request.Principal + ")"
		}
		fmt.Fprintf(&b, "ended %s at %s%s at %s: %d live context(s) marked, the unspent tokens under %d key(s) "+
			"deleted; its tokens are refused from now on; no revocation stands, so a new login works at once (to "+
			"stop that, revoke the principal)", what, r.OIDCIssuer, owner, at, len(r.Contexts), r.TokenKeys)
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `go test ./internal/broker/ -count=1 -race`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/revoke_api.go internal/broker/revoke.go internal/broker/revoke_api_test.go
git commit -m "feat(broker): /v1/tokens/revoke ends one OIDC session by sid under revoke_others

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 14: port49d and port49-broker run OIDC: the set, the kept keys, the start lines, the loops

**Files:**
- Create: `internal/port49d/identity.go`
- Modify: `internal/port49d/main.go` (`buildBrokerAnchor`, the certificate-status block, the
  loops), `internal/port49d/brokerd.go` (the certificate-status block, the loops)
- Modify: `deploy/compose/config/port49-broker.yaml`, `deploy/compose/README.md`
- Test: `internal/port49d/identity_test.go`, `internal/port49d/identity_linux_test.go`

**Interfaces:**
- Consumes: Task 7's `BrokerConfig.Identity`; Tasks 4 and 5's `oidc.NewKeySet`, `NewClient`,
  `Set`, `Verifier`; Task 10's `Broker.NoX509`; `writeOwnerOnly`, `ownedHere`
  (`statedir_linux.go`).
- Produces:
  - `openIdentity(cfg config.Config, stateDir string, m *metrics.Metrics, say func(string,
    ...any)) (*oidc.Set, error)`: nil without an oidc verifier; says in one line, at once, a
    state directory it cannot keep keys in (`ownStateDir`; pre-flight M-21);
  - `brokerStateDir(cfg config.Config) string`: `config.BrokerStateDir(cfg.Broker)` (Task 7);
  - `keyFile(stateDir, issuer string) string` (`oidc.KeyFileName`), `readOwnerOnly(path
    string) ([]byte, error)`;
  - `announceIdentity(w io.Writer, proc string, cfg config.Config, set *oidc.Set)`: naming each
    human verifier's domains, each machine client, and each issuer's proxy;
  - `runKeySets(ctx context.Context, set *oidc.Set)`.
- The tests that write a key file or run the process are Linux's (`identity_linux_test.go`;
  pre-flight M-22), since `ownedHere` and `writeOwnerOnly` are.

- [ ] **Step 1: Write the failing tests**

`internal/port49d/identity_test.go`:

```go
package port49d

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

// identityCfg is broker.identity with a human and a machine verifier at
// iss, its CA in a file, on a broker whose state is kept in dir.
func identityCfg(t *testing.T, iss *oidctest.Issuer, dir string) *oidc.Config {
	t.Helper()
	ca := writeFile(t, dir, "idp-ca.pem", iss.CertPEM())
	return &oidc.Config{X509AnchorFile: "/etc/port49/clients-ca.pem", Timing: oidc.DefaultTiming, OIDC: []oidc.VerifierConfig{
		{Domain: oidc.Humans, Issuer: iss.URL, ClientID: "port49-cli", PrincipalClaim: oidc.ClaimEmail,
			PrincipalDomains: []string{"corp.example.com"}, Scopes: []string{"openid", "email"},
			Algorithms: []oidc.Alg{oidc.RS256}, CAFile: ca},
		{Domain: oidc.Machines, Issuer: iss.URL, Audience: "api://port49-svc",
			Clients:    []oidc.MachineClient{{ClientID: "oxidized", Sub: "5f3c2d1e-0000-4000-8000-000000000049"}},
			Algorithms: []oidc.Alg{oidc.RS256}, CAFile: ca}}}
}

func TestTheIdentityStartLines(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := t.TempDir()
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	cfg.Broker.Identity.OIDC[1].CAFile = "" // the machine verifier trusts the system roots
	var out syncBuffer
	announceIdentity(&out, "port49-broker", cfg, nil)
	got := out.String()
	for _, want := range []string{
		"port49-broker: identity: humans: x509 (trust anchor /etc/port49/clients-ca.pem); oidc " + iss.URL +
			" (client_id port49-cli, principal from email in corp.example.com, email_verified required; algorithms RS256)\n",
		"port49-broker: identity: machines: oidc " + iss.URL + " (audience api://port49-svc; clients oxidized (sub " +
			"5f3c2d1e-0000-4000-8000-000000000049); principal app:<azp>; algorithms RS256)\n",
		"the principal claim must be one only the identity provider's administrators can set",
		"turn off \"trust email\"",
		"port49-broker: identity: " + iss.URL + " is fetched ",
		"port49-broker: identity: " + iss.URL + " is trusted through the system's root certificates (no ca_file)\n",
		"port49-broker: identity: keys refreshed every 1h0m0s; trusted without a refresh until 24h0m0s after the last " +
			"(broker.identity.jwks_max_age); clock_skew 1m0s; max_token_age 2h0m0s\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the start lines lack %q:\n%s", want, got)
		}
	}
	cfg.Broker.Identity = &oidc.Config{X509AnchorFile: "/etc/port49/clients-ca.pem", Shorthand: true}
	out = syncBuffer{}
	announceIdentity(&out, "port49d", cfg, nil)
	if !strings.Contains(out.String(), "identity: humans: x509 from broker.client_ca_file (no broker.identity is "+
		"configured); no OIDC verifier") {
		t.Fatalf("the shorthand's line:\n%s", out.String())
	}
}

func fmtLine(format string, args ...any) string { return fmt.Sprintf(format, args...) + "\n" }
```

`writeFile`, `brokerConfig`, `brokerReadyz`, `writeRunConfig`, `waitFor`, `minimalPolicy`,
`syncBuffer` and `directoryPolicy` are this package's test helpers already (`brokerConfig` writes
real lab certificates, so `buildBroker` runs). Add to `oidctest.Issuer`:

```go
// CertPEM is the server's TLS certificate, PEM, as an operator's ca_file
// holds it.
func (i *Issuer) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: i.srv.Certificate().Raw})
}
```

`internal/port49d/identity_linux_test.go`: every test that writes a key file or runs the
process, since `ownedHere` and `writeOwnerOnly` are Linux's (pre-flight M-22):

```go
//go:build linux

package port49d

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/blanketfish/port49/internal/broker"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc/oidctest"
)

func TestOpenIdentitySharesOneKeySetPerIssuer(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := t.TempDir()
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	set, err := openIdentity(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Verifiers) != 2 || set.Verifiers[0].Keys != set.Verifiers[1].Keys {
		t.Fatalf("verifiers %+v: one issuer, one key set", set.Verifiers)
	}
	if err := set.Verifiers[0].Keys.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(keyFile(dir, iss.URL)); err != nil {
		t.Fatalf("the fetched keys were not kept: %v", err)
	}
	cfg.Broker.Identity.OIDC = nil
	if set, err := openIdentity(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {}); err != nil || set != nil {
		t.Fatalf("no oidc verifier: %v %v", set, err)
	}
}

// Review Focus 3: a broker restarted while the provider is down validates
// from the kept keys.
func TestARestartDuringAnOutageKeepsTheKeys(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := t.TempDir()
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	first, err := openIdentity(cfg, dir, metrics.New(prometheus.NewRegistry()), func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Verifiers[0].Keys.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	raw := iss.IDToken(t, "k1", "port49-cli", "s", time.Now(), map[string]any{"email": "a@corp.example.com",
		"email_verified": true})
	iss.Close()
	var said strings.Builder
	second, err := openIdentity(cfg, dir, metrics.New(prometheus.NewRegistry()), func(f string, a ...any) {
		said.WriteString(fmtLine(f, a...))
	})
	if err != nil {
		t.Fatal(err)
	}
	if a, err := second.Verify(context.Background(), raw); err != nil || a.Principal != "user:a@corp.example.com" {
		t.Fatalf("after a restart with the provider down: %+v %v", a, err)
	}
	if !strings.Contains(said.String(), "restored 1 keys fetched") {
		t.Fatalf("the restore was not said:\n%s", said.String())
	}
}

// Pre-flight M-21: a state directory the broker cannot keep keys in is said
// at start, when an OIDC verifier is configured, not first at a save.
func TestAnUnusableStateDirIsSaidAtStart(t *testing.T) {
	iss := oidctest.NewIssuer(t)
	dir := t.TempDir()
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Identity = identityCfg(t, iss, dir)
	notADir := writeFile(t, dir, "a-file", []byte("x"))
	var said strings.Builder
	if _, err := openIdentity(cfg, filepath.Join(notADir, "state"), metrics.New(prometheus.NewRegistry()),
		func(f string, a ...any) { said.WriteString(fmtLine(f, a...)) }); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(said.String(), "cannot keep the providers' keys") {
		t.Fatalf("an unusable state directory was not said:\n%s", said.String())
	}
}

// Review Focus 3: a kept key file is the broker's own; a link, or one
// another user owns, is refused, since it names the keys the broker trusts.
func TestAKeyFileTheBrokerDidNotWriteIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := keyFile(dir, "https://sso.example.com")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnly(link); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("a link: %v", err)
	}
	if os.Geteuid() != 0 {
		t.Skip("the owner check needs root to chown (CI runs it as root)")
	}
	owned := keyFile(dir, "https://other.example.com")
	if err := os.WriteFile(owned, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(owned, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := readOwnerOnly(owned); err == nil {
		t.Fatal("a key file another user owns was read")
	}
}

// Readiness never follows the provider (design §12; the Global Constraint
// this test pins; pre-flight I-12). The real start path runs with its only
// issuer unreachable and no kept keys: the key-set loop runs and says it has
// none, and /readyz still answers 200 serving. It mirrors 7g's
// TestReadinessNeverFollowsTheDirectory, and fails on any code that adds a
// key-set condition to readiness.
func TestReadinessNeverFollowsTheProvider(t *testing.T) {
	var out syncBuffer
	e, o := stderr, stdout
	t.Cleanup(func() { stderr, stdout = e, o })
	stderr, stdout = &out, io.Discard
	iss := oidctest.NewIssuer(t)
	b := brokerConfig(t, minimalPolicy).Broker
	pki := filepath.Dir(b.ClientCAFile)
	ca := writeFile(t, pki, "idp-ca.pem", iss.CertPEM())
	issuer := iss.URL
	iss.Close() // unreachable from the start: nothing fetched, nothing kept
	cfgPath := writeRunConfig(t, b)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	clientCA := regexp.MustCompile(`(?m)^  client_ca_file: .*\n`)
	if !clientCA.Match(raw) {
		t.Fatal("the run config has no client_ca_file to replace")
	}
	identity := fmt.Sprintf("  identity:\n    humans:\n      - {type: x509, trust_anchor_file: %s}\n"+
		"      - {type: oidc, issuer: %q, client_id: port49-cli, principal_claim: email, "+
		"principal_domains: [example.com], ca_file: %s}\n", b.ClientCAFile, issuer, ca)
	if err := os.WriteFile(cfgPath, clientCA.ReplaceAllLiteral(raw, []byte(identity)), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, cfgPath) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
	})
	waitFor(t, &out, "port49d: broker listening on ")
	waitFor(t, &out, "identity: "+issuer+": no keys fetched yet")
	addr := regexp.MustCompile(`port49d: broker listening on (\S+)`).FindStringSubmatch(out.String())[1]
	if code, body := brokerReadyz(t, pki, addr); code != http.StatusOK || body != broker.ReadyServing {
		t.Fatalf("broker /readyz with the provider unreachable: %d %q", code, body)
	}
}
```

(`writeFile` returns the path it wrote. If `writeRunConfig`'s broker block spells
`client_ca_file` differently, match its spelling: the test fails loudly, never silently, when
the line is not found.)

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/port49d/ -run 'TestOpenIdentity|TestARestartDuringAnOutage|TestAnUnusableStateDir|TestTheIdentityStartLines|TestReadinessNeverFollowsTheProvider|TestAKeyFileTheBroker' -count=1`
Expected: FAIL to compile: `openIdentity`, `keyFile`, `announceIdentity` undefined.

- [ ] **Step 3: `internal/port49d/identity.go`**

```go
package port49d

import (
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/daemon/metrics"
	"github.com/blanketfish/port49/internal/oidc"
	"github.com/blanketfish/port49/internal/printsafe"
)

// brokerStateDir is where the broker keeps its own state (config's
// BrokerStateDir: broker.state_dir on port49-broker, else the directory
// holding broker.revocations_file, as the kept CRLs are; plan 7b).
func brokerStateDir(cfg config.Config) string { return config.BrokerStateDir(cfg.Broker) }

// keyFile is where an issuer's fetched keys are kept (Ruling 4): the name
// config's collision lists check (pre-flight M-11).
func keyFile(stateDir, issuer string) string { return filepath.Join(stateDir, oidc.KeyFileName(issuer)) }

// openIdentity builds broker.identity's OIDC set: one key set per issuer,
// shared by the issuer's verifiers, restored from stateDir and kept there.
// It fetches nothing: runKeySets does, so a start never waits on a
// provider (Ruling 4). Nil without an oidc verifier. A state directory it
// cannot keep keys in is said now, in one line, not first at a save an
// hour into a provider outage (pre-flight M-21); the broker still starts.
func openIdentity(cfg config.Config, stateDir string, m *metrics.Metrics, say func(string, ...any)) (*oidc.Set, error) {
	id := cfg.Broker.Identity
	if id == nil || len(id.OIDC) == 0 {
		return nil, nil
	}
	if err := ownStateDir(stateDir); err != nil {
		say("identity: the state directory %s cannot keep the providers' keys (%s): a restart during a provider "+
			"outage will refuse every OIDC token until a fetch succeeds", stateDir, printsafe.Line(err.Error(), 200))
	}
	set := &oidc.Set{Timing: id.Timing, Now: time.Now, M: m}
	byIssuer := map[string]*oidc.KeySet{}
	for i, v := range id.OIDC {
		ks := byIssuer[v.Issuer]
		if ks == nil {
			var roots *x509.CertPool
			if v.CAFile != "" {
				pem, err := os.ReadFile(v.CAFile)
				if err != nil {
					return nil, fmt.Errorf("config: broker.identity %s verifier %d: ca_file: %w", v.Domain, i, err)
				}
				roots = x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					return nil, fmt.Errorf("config: broker.identity %s verifier %d: ca_file %s holds no certificate",
						v.Domain, i, v.CAFile)
				}
			}
			path := keyFile(stateDir, v.Issuer)
			ks = oidc.NewKeySet(oidc.KeySetConfig{Issuer: v.Issuer, Client: oidc.NewClient(roots),
				Refresh: id.Timing.JWKSRefresh, MaxAge: id.Timing.JWKSMaxAge, Now: time.Now, Say: say, M: m,
				Save: func(b []byte) error { return writeOwnerOnly(path, b) },
				Load: func() ([]byte, error) { return readOwnerOnly(path) }})
			switch n, at, err := ks.Restore(); {
			case err != nil:
				say("identity: %s: the kept keys in %s are not used: %s", v.Issuer, path, printsafe.Line(err.Error(), 200))
			case n > 0:
				say("identity: %s: restored %d keys fetched %s from %s", v.Issuer, n, at.UTC().Format(time.RFC3339), path)
			}
			byIssuer[v.Issuer] = ks
		}
		set.Verifiers = append(set.Verifiers, &oidc.Verifier{VerifierConfig: v, Keys: ks})
	}
	return set, nil
}

// runKeySets runs each issuer's refresh loop until ctx ends.
func runKeySets(ctx context.Context, set *oidc.Set) {
	if set == nil {
		return
	}
	var wg sync.WaitGroup
	seen := map[*oidc.KeySet]bool{}
	for _, v := range set.Verifiers {
		if seen[v.Keys] {
			continue
		}
		seen[v.Keys] = true
		wg.Add(1)
		go func(ks *oidc.KeySet) { defer wg.Done(); ks.Run(ctx) }(v.Keys)
	}
	wg.Wait()
}

// announceIdentity is the start's identity lines (What the operator sees).
func announceIdentity(w io.Writer, proc string, cfg config.Config, _ *oidc.Set) {
	id := cfg.Broker.Identity
	if id == nil {
		return
	}
	if id.Shorthand {
		fmt.Fprintf(w, "%s: identity: humans: x509 from broker.client_ca_file (no broker.identity is configured); "+
			"no OIDC verifier\n", proc)
		return
	}
	var humans, machines []string
	if id.X509AnchorFile != "" {
		humans = append(humans, "x509 (trust anchor "+id.X509AnchorFile+")")
	}
	algs := func(as []oidc.Alg) string {
		var s []string
		for _, a := range as {
			s = append(s, string(a))
		}
		return strings.Join(s, ", ")
	}
	for _, v := range id.OIDC {
		switch v.Domain {
		case oidc.Humans:
			claim := "principal from " + v.PrincipalClaim + " in " + strings.Join(v.PrincipalDomains, ", ")
			if v.PrincipalClaim == oidc.ClaimEmail {
				claim += ", email_verified required"
			}
			humans = append(humans, fmt.Sprintf("oidc %s (client_id %s, %s; algorithms %s)", v.Issuer, v.ClientID,
				claim, algs(v.Algorithms)))
		case oidc.Machines:
			var clients []string
			for _, c := range v.Clients {
				clients = append(clients, fmt.Sprintf("%s (sub %s)", c.ClientID, c.Sub))
			}
			machines = append(machines, fmt.Sprintf("oidc %s (audience %s; clients %s; principal app:<azp>; "+
				"algorithms %s)", v.Issuer, v.Audience, strings.Join(clients, ", "), algs(v.Algorithms)))
		}
	}
	if len(humans) > 0 {
		fmt.Fprintf(w, "%s: identity: humans: %s\n", proc, strings.Join(humans, "; "))
	}
	if len(machines) > 0 {
		fmt.Fprintf(w, "%s: identity: machines: %s\n", proc, strings.Join(machines, "; "))
	}
	for _, v := range id.OIDC {
		if v.Domain == oidc.Humans {
			fmt.Fprintf(w, "%s: identity: the principal claim must be one only the identity provider's "+
				"administrators can set: a person who can edit their own would choose whose principal they are; on a "+
				"provider brokering another, turn off \"trust email\"\n", proc)
			break
		}
	}
	// Once per issuer: how it is reached (pre-flight I-5) and what anchors it.
	seen := map[string]bool{}
	for _, v := range id.OIDC {
		if seen[v.Issuer] {
			continue
		}
		seen[v.Issuer] = true
		how := "directly (no HTTPS_PROXY)"
		if u, err := oidc.ProxyFor(v.Issuer); err == nil {
			how = oidc.DescribeProxy(u)
		}
		fmt.Fprintf(w, "%s: identity: %s is fetched %s\n", proc, v.Issuer, how)
	}
	clear(seen)
	for _, v := range id.OIDC {
		if v.CAFile == "" && !seen[v.Issuer] {
			seen[v.Issuer] = true
			fmt.Fprintf(w, "%s: identity: %s is trusted through the system's root certificates (no ca_file)\n", proc,
				v.Issuer)
		}
	}
	fmt.Fprintf(w, "%s: identity: keys refreshed every %s; trusted without a refresh until %s after the last "+
		"(broker.identity.jwks_max_age); clock_skew %s; max_token_age %s\n", proc, id.Timing.JWKSRefresh,
		id.Timing.JWKSMaxAge, id.Timing.ClockSkew, id.Timing.MaxTokenAge)
}
```

`readOwnerOnly` is `writeOwnerOnly`'s reader, and like it is Linux's, since `ownedHere` is. In
`internal/port49d/statedir_linux.go`:

```go
// readOwnerOnly reads a kept file the broker wrote itself: a regular file
// owned by its user or root (ownedHere), or nothing when there is none.
func readOwnerOnly(path string) ([]byte, error) {
	if err := ownedHere(path, path, false); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}
```

and in `statedir_other.go`, beside `writeOwnerOnly`'s:

```go
// readOwnerOnly refuses off Linux, as ownStateDir does.
func readOwnerOnly(string) ([]byte, error) { return nil, ownStateDir("") }
```

- [ ] **Step 4: Wire it into both processes**

In `buildBrokerAnchor` (`internal/port49d/main.go`), the TLS load becomes:

```go
	var cert tls.Certificate
	var anchorCert *x509.Certificate
	if cfg.Broker.ClientCAFile != "" {
		cert, anchorCert, err = broker.LoadTLSAnchor(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile)
	} else {
		cert, err = keyfile.LoadX509KeyPair(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile)
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("broker TLS files (tls_cert_file %s, tls_key_file %s, client_ca_file %s): %w",
			cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile, err)
	}
```

(`main.go` imports `github.com/blanketfish/port49/internal/keyfile` for `keyfile.LoadX509KeyPair` if it
does not already; pre-flight M-22.) After `announceDirectory(…)`:

```go
	if b.Identity, err = openIdentity(cfg, brokerStateDir(cfg), m, func(format string, args ...any) {
		fmt.Fprintf(stderr, proc+": "+format+"\n", args...)
	}); err != nil {
		return nil, nil, nil, err
	}
	b.NoX509 = cfg.Broker.ClientCAFile == ""
	announceIdentity(stderr, proc, cfg, b.Identity)
	var anchor *x509.CertPool
	if anchorCert != nil {
		anchor = x509.NewCertPool()
		anchor.AddCert(anchorCert)
	}
	srv, err := b.Server(cfg.Broker.Listen, cert, anchor)
```

(in place of the two-line `anchor := …` it had). In `main.go`'s and `brokerd.go`'s
certificate-status blocks, the `cs := cfg.Broker.CertificateStatus` branch is entered only
when `cs != nil`, and with `cs == nil` the line is:

```go
		fmt.Fprintln(stderr, procOf(cfg)+": broker: no x509 verifier is configured, so no client certificate's "+
			"status is checked")
```

Beside each `go func() { defer wg.Done(); runPool(ctx, brk.Directory) }()` (both processes):

```go
	wg.Add(1)
	go func() { defer wg.Done(); runKeySets(ctx, brk.Identity) }()
```

(`main.go`'s start uses `statusDone` as its group there: use the same group its neighbours use.)

`/readyz` is not touched: no key set reaches `SetReady`.

- [ ] **Step 5: The compose example**

In `deploy/compose/config/port49-broker.yaml`, after the directory's commented block:

```yaml
  # OIDC (spec §13 decision 39) is off here: the trial authenticates people
  # by certificate alone (broker.client_ca_file above). To accept tokens
  # from an identity provider, replace client_ca_file with an identity
  # block; the provider's keys are kept in state_dir across a restart.
  # identity:
  #   humans:
  #     - {type: x509, trust_anchor_file: /etc/port49/broker/broker-ca.pem}
  #     - type: oidc
  #       issuer: https://sso.corp.example.com/realms/corp
  #       client_id: port49-cli                # the public client people log in with (plan 9)
  #       principal_claim: email               # required: preferred_username, email (needs email_verified) or upn
  #       principal_domains: [corp.example.com] # required: whose people this provider may name
  #       scopes: [email]
  #       # ca_file: /etc/port49/idp-ca.pem    # omit to trust the system roots
  #   machines:
  #     - type: oidc
  #       issuer: https://sso.corp.example.com/realms/corp
  #       audience: "api://port49-svc"
  #       clients:                             # required: each client, with its sub at the provider
  #         - {client_id: oxidized, sub: 5f3c2d1e-0000-4000-8000-000000000049}
  #   # clock_skew: 60s
  #   # max_token_age: 2h
  #   # jwks_refresh_interval: 1h
  #   # jwks_max_age: 24h                     # past it with no refresh, every OIDC request is refused 503
  # The provider posts back-channel logouts to https://<broker>:8443/v1/logout:
  # register that URL, with "backchannel logout session required" on.
```

and in `deploy/compose/README.md`, a short "OIDC" paragraph naming the block, the logout URL,
that the broker must reach the provider's discovery and JWKS URLs (through `HTTPS_PROXY` when
the site's egress is a proxy), and that each machine client's `sub` is read from the provider
(Keycloak: the client's "Service account roles" user id; Entra ID: the service principal's
object id).

- [ ] **Step 6: Run the tests to see them pass, and the whole tree**

Run: `go test ./internal/port49d/ -count=1 -race && GOOS=darwin go build ./internal/port49d/ && make test && make vet`
Expected: PASS; the package still builds off Linux (`identity.go` uses only `ownStateDir`,
`writeOwnerOnly` and `readOwnerOnly`, which have `statedir_other.go` forms; pre-flight M-22); vet
clean. (`GOOS=darwin go vet` of the package's tests already fails on `main` at
`coldstart_test.go`, which is not this plan's.)

- [ ] **Step 7: Commit**

```bash
git add internal/port49d/ deploy/compose/ internal/oidc/oidctest/issuer.go
git commit -m "feat(port49d): run broker.identity: one key set per issuer, kept in the state directory, refreshed in the background; an OIDC-only broker

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 15: (lab harness, on beehive) Keycloak, a login flow, a logout receiver; the L45 and L46 tests

**Files:**
- Create: `tests/lab/oidc/compose.yaml`, `tests/lab/oidc/keycloak/realm.json`,
  `tests/lab/oidc/keycloak/README.md`
- Create: `tests/lab/oidc_test.go` (the harness), `tests/lab/oidcflow_test.go` (the login flow),
  `tests/lab/l45_test.go`, `tests/lab/l46_test.go` (each `//go:build lab`)
- Modify: `Makefile` (`lab-oidc`), `tests/lab/README.md` ("Identity provider")

**Interfaces:**
- Consumes: `internal/testpki` (`NewCA`, `Issue`, `PEMs`); the lab's `dockerCmd`, `repoRoot`,
  `imageID`, `oneLineMax`, `labcreds.RedactNote`.
- Produces (for Task 16):
  - `startKeycloak(t) *keycloak`, with `URL` (the issuer), `HTTP *http.Client` (resolves
    `keycloak.port49.lab` to the published port, trusts the lab CA, follows no redirect),
    `Admin(t) string` (an admin token), `SetLogoutURL(t, url string)`,
    `UserID(t, username) string`, `LogoutUser(t, id)`, `DeleteSession(t, sid)`,
    `Version() string`, `CAFile`; `keycloakClient(ca) *http.Client`, `kcDial`, `waitDiscovery(t, k,
    within)`, `(*keycloak).adminFromEnv(t, path)`;
  - `(*keycloak).Login(t, user, pass string, extra url.Values) flowResult`, `Refresh(t,
    refreshToken string) flowResult`, `EndSession(t, idToken string)`, and
    `EndSessionStatus(t, idToken string) (int, error)`, which records the answer instead of
    failing (pre-flight I-11);
  - `kcServiceAccountID`: the fixed id of `port49-svc`'s service-account user, the `sub` its
    client-credentials tokens carry, which Task 16's `clients` pin names (Ruling 21);
  - `flowResult{IDToken, AccessToken, RefreshToken string; SawLoginForm bool}`;
  - `claimsOf(jwt string) (header, claims map[string]any)`: decode without verifying, lab
    inspection only;
  - `startReceiver(t, kc *keycloak) *receiver`: an HTTPS endpoint Keycloak posts logouts to,
    with `Answer(status int)`, `Stop()`, `Got() []received`, `URL`;
  - `writeOIDCResult(t, row, claim, observation, evidencePath string)`;
  - `make lab-oidc`.

- [ ] **Step 1: The provider**

`tests/lab/oidc/compose.yaml`:

```yaml
# Keycloak for plan 7h's lab (L45, L46): one realm imported at first start,
# HTTPS only, from the lab PKI tests/lab/oidc_test.go writes under
# tests/lab/logs/oidc (git-ignored) before `docker compose -p port49laboidc up`.
# The run's note records the version and the image ID it ran.
name: port49laboidc

services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.4
    command:
      - start-dev
      - --import-realm
      - --http-enabled=false
      - --https-port=18443
      - --https-certificate-file=/pki/keycloak.pem
      - --https-certificate-key-file=/pki/keycloak-key.pem
      - --hostname=https://keycloak.port49.lab:18443
      - --truststore-paths=/pki/lab-ca.pem
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
    # KC_BOOTSTRAP_ADMIN_PASSWORD, generated per run, never in this file
    env_file:
      - path: ../logs/oidc/admin.env
    volumes:
      - ./keycloak/realm.json:/opt/keycloak/data/import/realm.json:ro
      - ../logs/oidc/pki:/pki:ro
    extra_hosts:
      - "host.port49.lab:host-gateway"
    ports:
      - "127.0.0.1:18443:18443"
```

The tag is pinned; the run's note records `kc.sh --version` and the image ID (`imageID`), so the
version a note names is the one that ran.

`tests/lab/oidc/keycloak/realm.json`:

```json
{
  "realm": "port49-lab",
  "enabled": true,
  "sslRequired": "all",
  "accessTokenLifespan": 300,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 36000,
  "eventsEnabled": true,
  "adminEventsEnabled": true,
  "clients": [
    {
      "clientId": "port49-cli",
      "name": "port49 lab public client",
      "publicClient": true,
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false,
      "implicitFlowEnabled": false,
      "frontchannelLogout": false,
      "redirectUris": ["http://127.0.0.1:18749/callback"],
      "attributes": {
        "pkce.code.challenge.method": "S256",
        "backchannel.logout.url": "https://receiver.invalid/v1/logout",
        "backchannel.logout.session.required": "true",
        "backchannel.logout.revoke.offline.tokens": "true",
        "post.logout.redirect.uris": "http://127.0.0.1:18749/bye"
      }
    },
    {
      "clientId": "port49-svc",
      "name": "port49 lab service",
      "publicClient": false,
      "secret": "lab-only-svc-secret",
      "serviceAccountsEnabled": true,
      "standardFlowEnabled": false,
      "directAccessGrantsEnabled": false,
      "protocolMappers": [
        {
          "name": "port49 api audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.custom.audience": "api://port49-svc",
            "access.token.claim": "true",
            "id.token.claim": "false"
          }
        }
      ]
    }
  ],
  "users": [
    {
      "username": "alice",
      "email": "alice@corp.example.com",
      "emailVerified": true,
      "enabled": true,
      "firstName": "Alice",
      "lastName": "Lab",
      "credentials": [{"type": "password", "value": "lab-only-alice-password", "temporary": false}]
    },
    {
      "id": "5f3c2d1e-0000-4000-8000-000000000049",
      "username": "service-account-port49-svc",
      "enabled": true,
      "serviceAccountClientId": "port49-svc"
    }
  ]
}
```

The second user is `port49-svc`'s service account, imported with a fixed id, so the `sub` its
client-credentials tokens carry is known before Keycloak starts and Task 16's broker config can
pin it (`clients: [{client_id: port49-svc, sub: 5f3c2d1e-…-49}]`; Ruling 21). L46 asserts the
token's `sub` is that id; if Keycloak ignores a fixed id at import, the run stops there with that
said, a harness fix and never a loosened pin.

Both secrets are the lab's own, published with the repository, for a realm that lives as long
as one run on one host's loopback; `tests/lab/oidc/keycloak/README.md` says so in two lines, and
that the realm's `backchannel.logout.url` is replaced by each test (`SetLogoutURL`).

- [ ] **Step 2: The harness**

`tests/lab/oidc_test.go`:

```go
//go:build lab

package lab

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
	"github.com/blanketfish/port49/tests/lab/labcreds"
)

const (
	kcHost     = "keycloak.port49.lab"
	kcPort     = "18443"
	kcRealm    = "port49-lab"
	kcClient   = "port49-cli"
	kcRedirect = "http://127.0.0.1:18749/callback"
	rcvHost    = "host.port49.lab"
	rcvPort    = "18750"
	// kcServiceAccountID is realm.json's fixed id for port49-svc's service
	// account: its client-credentials tokens' sub (Ruling 21).
	kcServiceAccountID = "5f3c2d1e-0000-4000-8000-000000000049"
)

type keycloak struct {
	URL    string // the issuer
	HTTP   *http.Client
	CAFile string
	out    string // the run's output root
	dir    string // tests/lab/oidc
	pki    string // tests/lab/logs/oidc/pki
	admin  string // the admin password, generated per run, never printed
	ca     *testpki.CA
}

// startKeycloak writes the PKI and the admin password, brings Keycloak up
// and waits for the realm's discovery document: the realm import takes up
// to 90s at first start, and a container that is "up" may not have it yet.
func startKeycloak(t *testing.T) *keycloak {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	out, err := directoryOut() // PORT49_LAB_DIRECTORY_OUT, else the repository
	if err != nil {
		t.Fatal(err)
	}
	k := &keycloak{out: out, dir: filepath.Join(repo, "tests", "lab", "oidc"),
		pki: filepath.Join(repo, "tests", "lab", "logs", "oidc", "pki"), URL: "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm}
	if err := os.MkdirAll(k.pki, 0o755); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if k.ca, err = testpki.NewCA("port49 lab oidc CA", now.Add(-time.Hour), now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for name, leaf := range map[string]testpki.Leaf{
		"keycloak": {CommonName: kcHost, DNSNames: []string{kcHost}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)},
		"receiver": {CommonName: rcvHost, DNSNames: []string{rcvHost, "port49-broker"}, NotBefore: now.Add(-time.Hour),
			NotAfter: now.Add(48 * time.Hour)},
	} {
		c, err := k.ca.Issue(leaf)
		if err != nil {
			t.Fatal(err)
		}
		cert, key, err := testpki.PEMs(c)
		if err != nil {
			t.Fatal(err)
		}
		// Keycloak reads the files as its own uid: world-readable inside a
		// directory only this run writes, under a git-ignored path.
		writeLab(t, filepath.Join(k.pki, name+".pem"), cert, 0o644)
		writeLab(t, filepath.Join(k.pki, name+"-key.pem"), key, 0o644)
	}
	k.CAFile = filepath.Join(k.pki, "lab-ca.pem")
	writeLab(t, k.CAFile, k.ca.PEM(), 0o644)
	k.admin = randomSecret(t)
	writeLab(t, filepath.Join(filepath.Dir(k.pki), "admin.env"), []byte("KC_BOOTSTRAP_ADMIN_PASSWORD="+k.admin+"\n"), 0o600)

	k.HTTP = keycloakClient(k.ca)

	if o, err := k.compose("up", "-d").CombinedOutput(); err != nil {
		t.Fatalf("docker compose up: %v\n%s", err, tailOf(string(o), 2000))
	}
	t.Cleanup(func() {
		logs, _ := k.compose("logs", "--no-color", "keycloak").CombinedOutput()
		_ = os.WriteFile(filepath.Join(filepath.Dir(k.pki), "keycloak.log"), logs, 0o644)
		_, _ = k.compose("down", "-v").CombinedOutput()
	})
	waitDiscovery(t, k, 3*time.Minute)
	return k
}

// kcDial reaches keycloak.port49.lab at the published port on loopback.
func kcDial(ctx context.Context, network, addr string) (net.Conn, error) {
	if host, _, _ := net.SplitHostPort(addr); host == kcHost {
		addr = "127.0.0.1:" + kcPort
	}
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
}

// keycloakClient reaches Keycloak by its issuer's name through kcDial,
// trusts ca, and follows no redirect: the flow reads each one.
func keycloakClient(ca *testpki.CA) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.Pool(), MinVersion: tls.VersionTLS12},
		DialContext: kcDial}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// waitDiscovery waits for the realm's discovery document: the realm import
// takes up to 90s at first start, and a container that is "up" may not
// have it yet.
func waitDiscovery(t *testing.T, k *keycloak, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		resp, err := k.HTTP.Get(k.URL + "/.well-known/openid-configuration")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Keycloak's realm %s never answered discovery: %v", kcRealm, err)
		}
		time.Sleep(2 * time.Second)
	}
}

// adminFromEnv reads the admin password from the admin.env a run wrote.
func (k *keycloak) adminFromEnv(t *testing.T, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	k.admin = strings.TrimSpace(strings.TrimPrefix(string(b), "KC_BOOTSTRAP_ADMIN_PASSWORD="))
}

func (k *keycloak) compose(args ...string) *exec.Cmd {
	return dockerCmd(append([]string{"compose", "-p", "port49laboidc", "-f", filepath.Join(k.dir, "compose.yaml")}, args...)...)
}

// Version is what the running image says it is.
func (k *keycloak) Version() string {
	out, _ := k.compose("exec", "-T", "keycloak", "/opt/keycloak/bin/kc.sh", "--version").CombinedOutput()
	return oneLineMax(strings.TrimSpace(string(out)), 200) + "; image " + imageID("quay.io/keycloak/keycloak:26.4")
}

// Admin is a master-realm admin token, from the password this run made.
func (k *keycloak) Admin(t *testing.T) string {
	t.Helper()
	form := url.Values{"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"admin"},
		"password": {k.admin}}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	k.postForm(t, "https://"+kcHost+":"+kcPort+"/realms/master/protocol/openid-connect/token", form, &tok)
	return tok.AccessToken
}

// adminDo is one admin REST call; out, when not nil, is the JSON answer.
func (k *keycloak) adminDo(t *testing.T, method, path string, body any, out any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, "https://"+kcHost+":"+kcPort+"/admin/realms/"+kcRealm+path, rd)
	req.Header.Set("Authorization", "Bearer "+k.Admin(t))
	req.Header.Set("Content-Type", "application/json")
	resp, err := k.HTTP.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("%s %s: %s %s", method, path, resp.Status, oneLineMax(string(raw), 300))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: %v", method, path, err)
		}
	}
}

// SetLogoutURL points port49-cli's back-channel logout at u.
func (k *keycloak) SetLogoutURL(t *testing.T, u string) {
	t.Helper()
	var clients []map[string]any
	k.adminDo(t, "GET", "/clients?clientId="+kcClient, nil, &clients)
	if len(clients) != 1 {
		t.Fatalf("%d clients named %s", len(clients), kcClient)
	}
	c := clients[0]
	attrs, _ := c["attributes"].(map[string]any)
	attrs["backchannel.logout.url"] = u
	k.adminDo(t, "PUT", "/clients/"+c["id"].(string), c, nil)
}

func (k *keycloak) UserID(t *testing.T, username string) string {
	t.Helper()
	var users []map[string]any
	k.adminDo(t, "GET", "/users?exact=true&username="+url.QueryEscape(username), nil, &users)
	if len(users) != 1 {
		t.Fatalf("%d users named %s", len(users), username)
	}
	return users[0]["id"].(string)
}

// LogoutUser is an administrator signing a user out of every session.
func (k *keycloak) LogoutUser(t *testing.T, id string) { k.adminDo(t, "POST", "/users/"+id+"/logout", nil, nil) }

// DeleteSession is an administrator ending one session.
func (k *keycloak) DeleteSession(t *testing.T, sid string) { k.adminDo(t, "DELETE", "/sessions/"+sid, nil, nil) }

func (k *keycloak) postForm(t *testing.T, u string, form url.Values, out any) {
	t.Helper()
	resp, err := k.HTTP.PostForm(u, form)
	if err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("POST %s: %s %s", u, resp.Status, oneLineMax(string(raw), 300))
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("POST %s: %v", u, err)
	}
}

// claimsOf decodes a JWS's header and claims without verifying it: the lab
// inspects what the provider sent, and verifies nothing.
func claimsOf(jwt string) (map[string]any, map[string]any) {
	parts := strings.Split(jwt, ".")
	dec := func(s string) map[string]any {
		b, _ := base64.RawURLEncoding.DecodeString(s)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		return m
	}
	if len(parts) != 3 {
		return nil, nil
	}
	return dec(parts[0]), dec(parts[1])
}

// received is one request the receiver took, the logout token decoded
// (header and claims, never the signature).
type received struct {
	At          time.Time
	ContentType string
	Header      map[string]any
	Claims      map[string]any
	Answered    int
}

// receiver is an HTTPS endpoint Keycloak posts logout tokens to, answering
// each with the status Answer set (200 until set).
type receiver struct {
	URL    string
	srv    *http.Server
	mu     sync.Mutex
	status int
	got    []received
}

func startReceiver(t *testing.T, k *keycloak) *receiver {
	t.Helper()
	c, err := k.ca.Issue(testpki.Leaf{CommonName: rcvHost, DNSNames: []string{rcvHost}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	r := &receiver{URL: "https://" + rcvHost + ":" + rcvPort + "/v1/logout", status: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/logout", func(w http.ResponseWriter, req *http.Request) {
		_ = req.ParseForm()
		h, cl := claimsOf(req.PostForm.Get("logout_token"))
		r.mu.Lock()
		status := r.status
		r.got = append(r.got, received{At: time.Now(), ContentType: req.Header.Get("Content-Type"), Header: h,
			Claims: cl, Answered: status})
		r.mu.Unlock()
		w.WriteHeader(status)
	})
	ln, err := net.Listen("tcp", "0.0.0.0:"+rcvPort)
	if err != nil {
		t.Fatal(err)
	}
	r.srv = &http.Server{Handler: mux, TLSConfig: &tls.Config{Certificates: []tls.Certificate{c}}}
	go func() { _ = r.srv.ServeTLS(ln, "", "") }()
	t.Cleanup(r.Stop)
	return r
}

func (r *receiver) Answer(status int) { r.mu.Lock(); r.status = status; r.mu.Unlock() }
func (r *receiver) Stop()             { _ = r.srv.Close() }
func (r *receiver) Got() []received   { r.mu.Lock(); defer r.mu.Unlock(); return append([]received(nil), r.got...) }

// waitGot waits until the receiver holds more than n requests, or within.
func (r *receiver) waitGot(n int, within time.Duration) []received {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if g := r.Got(); len(g) > n {
			return g
		}
		time.Sleep(250 * time.Millisecond)
	}
	return r.Got()
}

// writeOIDCResult writes tests/lab/results/<row>-keycloak.md in spec §15
// rule 3's form, through labcreds.RedactNote.
func writeOIDCResult(t *testing.T, k *keycloak, row, claim, observation, evidencePath string) {
	t.Helper()
	dir := filepath.Join(k.out, "tests", "lab", "results")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# %s — keycloak\n\n", row)
	fmt.Fprintf(&b, "- **Date measured:** %s\n", time.Now().UTC().Format("2006-01-02"))
	fmt.Fprintf(&b, "- **Run:** %s\n", runLine()) // the commit and the test run, as 7g's notes carry (pre-flight M-23)
	fmt.Fprintf(&b, "- **Platform:** Keycloak, as a container on `tests/lab/oidc/compose.yaml` (no network device)\n")
	fmt.Fprintf(&b, "- **Image version:** %s\n", k.Version())
	fmt.Fprintf(&b, "- **Capture:** `%s`: one JSON line per request or token, with the JWS header and claims decoded "+
		"and the signature dropped (the wire is TLS, so a pcap would be encrypted).\n", evidencePath)
	fmt.Fprintf(&b, "- **Credentials:** none here or in the evidence: the admin password is generated per run and never "+
		"printed; the lab user's password and the service secret are the realm file's published lab values.\n")
	fmt.Fprintf(&b, "\n## Claim\n\n%s\n\n## Observation\n\n%s\n", claim, observation)
	if strings.Contains(b.String(), k.admin) {
		t.Fatalf("the %s note holds the admin password", row)
	}
	path := filepath.Join(dir, row+"-keycloak.md")
	if err := os.WriteFile(path, []byte(labcreds.RedactNote(b.String())), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s", path)
}

// oidcEvidence opens tests/lab/evidence/<name>.json and returns a line
// writer; a line is decoded JWS parts and what the step was, never a
// signature or a raw token.
func oidcEvidence(t *testing.T, k *keycloak, name string) (func(step string, v any), string) {
	t.Helper()
	dir := filepath.Join(k.out, "tests", "lab", "evidence")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	var mu sync.Mutex
	return func(step string, v any) {
		mu.Lock()
		defer mu.Unlock()
		b, _ := json.Marshal(map[string]any{"step": step, "value": v})
		_, _ = f.Write(append(b, '\n'))
	}, filepath.Join("tests", "lab", "evidence", name+".json")
}

func writeLab(t *testing.T, path string, body []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, body, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func randomSecret(t *testing.T) string {
	t.Helper()
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
```

- [ ] **Step 3: The login flow**

`tests/lab/oidcflow_test.go`:

```go
//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/base64"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"testing"
)

// flowResult is what one authorization-code flow (or refresh) returned,
// and whether Keycloak asked for the password on the way.
type flowResult struct {
	IDToken, AccessToken, RefreshToken string
	SawLoginForm                       bool
}

var formAction = regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)

// Login runs the authorization-code flow with PKCE as port49-cli, as plan
// 9's agent will: extra adds prompt, nonce or max_age. The browser's
// cookies persist across calls on k (one jar per keycloak), so a second
// Login is inside the first's SSO session.
func (k *keycloak) Login(t *testing.T, user, pass string, extra url.Values) flowResult {
	t.Helper()
	if k.HTTP.Jar == nil {
		jar, _ := cookiejar.New(nil)
		k.HTTP.Jar = jar
	}
	verifier := randomSecret(t) + randomSecret(t)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"response_type": {"code"}, "client_id": {kcClient}, "redirect_uri": {kcRedirect},
		"scope": {"openid email"}, "state": {randomSecret(t)},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	for k2, v := range extra {
		q[k2] = v
	}
	resp, err := k.HTTP.Get(k.URL + "/protocol/openid-connect/auth?" + q.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	res := flowResult{}
	if resp.StatusCode == http.StatusOK {
		m := formAction.FindSubmatch(body)
		if m == nil {
			t.Fatalf("authorize answered a page with no login form: %s", oneLineMax(string(body), 300))
		}
		res.SawLoginForm = true
		resp, err = k.HTTP.PostForm(html.UnescapeString(string(m[1])), url.Values{"username": {user},
			"password": {pass}, "credentialId": {""}})
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		resp.Body.Close()
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || err != nil || !strings.HasPrefix(loc.String(), kcRedirect) ||
		loc.Query().Get("code") == "" {
		t.Fatalf("no code: %s %s", resp.Status, resp.Header.Get("Location"))
	}
	var tok struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	k.postForm(t, k.URL+"/protocol/openid-connect/token", url.Values{"grant_type": {"authorization_code"},
		"code": {loc.Query().Get("code")}, "redirect_uri": {kcRedirect}, "client_id": {kcClient},
		"code_verifier": {verifier}}, &tok)
	res.IDToken, res.AccessToken, res.RefreshToken = tok.IDToken, tok.AccessToken, tok.RefreshToken
	return res
}

// Refresh is the refresh-token grant: no authentication at all.
func (k *keycloak) Refresh(t *testing.T, refresh string) flowResult {
	t.Helper()
	var tok struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	k.postForm(t, k.URL+"/protocol/openid-connect/token", url.Values{"grant_type": {"refresh_token"},
		"refresh_token": {refresh}, "client_id": {kcClient}, "scope": {"openid email"}}, &tok)
	return flowResult{IDToken: tok.IDToken, AccessToken: tok.AccessToken, RefreshToken: tok.RefreshToken}
}

// EndSession is an RP-initiated logout with id_token_hint, which must be
// answered 302 or 200.
func (k *keycloak) EndSession(t *testing.T, idToken string) {
	t.Helper()
	code, err := k.EndSessionStatus(t, idToken)
	if err != nil || (code != http.StatusFound && code != http.StatusOK) {
		t.Fatalf("end session: %d %v", code, err)
	}
}

// EndSessionStatus is EndSession that records Keycloak's answer instead of
// failing on it: what the end-session endpoint answers when its
// back-channel delivery fails is what L45 (d) measures, and a fatal there
// would lose the whole note (pre-flight I-11).
func (k *keycloak) EndSessionStatus(t *testing.T, idToken string) (int, error) {
	t.Helper()
	q := url.Values{"id_token_hint": {idToken}, "client_id": {kcClient},
		"post_logout_redirect_uri": {"http://127.0.0.1:18749/bye"}}
	resp, err := k.HTTP.Get(k.URL + "/protocol/openid-connect/logout?" + q.Encode())
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

// ServiceToken is the client-credentials grant as port49-svc.
func (k *keycloak) ServiceToken(t *testing.T) string {
	t.Helper()
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	k.postForm(t, k.URL+"/protocol/openid-connect/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {"port49-svc"}, "client_secret": {"lab-only-svc-secret"}}, &tok)
	return tok.AccessToken
}
```

- [ ] **Step 4: L45, the logout token**

`tests/lab/l45_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

const l45Claim = "The back-channel logout token Keycloak sends to port49's /v1/logout when (a) the person logs " +
	"out at the end-session endpoint, (b) an administrator signs the user out of every session, and (c) an " +
	"administrator ends one session: its JWS header (alg, kid, typ); which of iss, aud, azp, iat, exp, jti, sub, " +
	"sid and events it carries, and that nonce is absent; whether its sid and its sub are the ID token's; one token " +
	"per session or per user; the request's content type; and what Keycloak does, and what its end-session " +
	"endpoint answers, when the answer is 503, 400, or the connection is refused (policy engine spec §15 L45; §13 " +
	"decision 39 rulings 12 and 13)."

func TestL45LogoutToken(t *testing.T) {
	k := startKeycloak(t)
	rcv := startReceiver(t, k)
	k.SetLogoutURL(t, rcv.URL)
	ev, evPath := oidcEvidence(t, k, "L45-keycloak")
	var obs strings.Builder
	obs.WriteString("| way | requests | content type | header | claims present | nonce | sid = ID token's | " +
		"sub = ID token's | exp − iat |\n|---|---|---|---|---|---|---|---|---|\n")
	sidOf := func(id string) string { _, c := claimsOf(id); s, _ := c["sid"].(string); return s }
	subOf := func(id string) string { _, c := claimsOf(id); s, _ := c["sub"].(string); return s }
	// row records each logout token against the ID token of the session it
	// ended: its sid, and its sub, which the sub path's owner record is
	// keyed by (pre-flight M-23).
	row := func(way string, idToken string, got []received) {
		for _, g := range got {
			var names []string
			for n := range g.Claims {
				names = append(names, n)
			}
			slices.Sort(names)
			_, nonce := g.Claims["nonce"]
			sid, _ := g.Claims["sid"].(string)
			sub, _ := g.Claims["sub"].(string)
			exp, _ := g.Claims["exp"].(float64)
			iat, _ := g.Claims["iat"].(float64)
			fmt.Fprintf(&obs, "| %s | %d | `%s` | alg %v kid %v typ %v | %s | %v | %v | %v | %vs |\n", way, len(got),
				g.ContentType, g.Header["alg"], g.Header["kid"] != nil, g.Header["typ"], strings.Join(names, ", "), nonce,
				sid != "" && sid == sidOf(idToken), sub != "" && sub == subOf(idToken), exp-iat)
			ev(way, map[string]any{"header": g.Header, "claims": g.Claims, "content_type": g.ContentType})
		}
	}

	// (a) RP-initiated logout.
	a := k.Login(t, "alice", "lab-only-alice-password", nil)
	n := len(rcv.Got())
	k.EndSession(t, a.IDToken)
	row("(a) end-session endpoint", a.IDToken, rcv.waitGot(n, 20*time.Second)[n:])

	// (b) an administrator signs alice out of every session (two open).
	b1 := k.Login(t, "alice", "lab-only-alice-password", nil)
	k.HTTP.Jar = nil // a second browser: a second session
	b2 := k.Login(t, "alice", "lab-only-alice-password", nil)
	n = len(rcv.Got())
	k.LogoutUser(t, k.UserID(t, "alice"))
	time.Sleep(5 * time.Second)
	got := rcv.waitGot(n+1, 20*time.Second)[n:]
	row("(b) admin: sign out user (2 sessions)", b1.IDToken, got)
	fmt.Fprintf(&obs, "\n(b) sent %d token(s) for 2 sessions; sids %v and %v.\n\n", len(got), sidOf(b1.IDToken), sidOf(b2.IDToken))

	// (c) an administrator ends one session.
	k.HTTP.Jar = nil
	c := k.Login(t, "alice", "lab-only-alice-password", nil)
	n = len(rcv.Got())
	k.DeleteSession(t, sidOf(c.IDToken))
	row("(c) admin: end one session", c.IDToken, rcv.waitGot(n, 20*time.Second)[n:])

	// (d) what Keycloak does with 503, 400, and a refused connection, and
	// what its end-session endpoint answers then: recorded, never fatal, since
	// that answer is part of what this row measures (pre-flight I-11).
	for _, answer := range []int{http.StatusServiceUnavailable, http.StatusBadRequest, 0} {
		k.HTTP.Jar = nil
		d := k.Login(t, "alice", "lab-only-alice-password", nil)
		n = len(rcv.Got())
		if answer == 0 {
			rcv.Stop()
		} else {
			rcv.Answer(answer)
		}
		code, err := k.EndSessionStatus(t, d.IDToken)
		time.Sleep(2 * time.Minute) // a retry within two minutes would land here
		got := rcv.Got()[n:]
		fmt.Fprintf(&obs, "- answered %s: %d request(s) in 2 minutes; the end-session endpoint answered %d (%v).\n",
			map[int]string{503: "503", 400: "400", 0: "nothing (connection refused)"}[answer], len(got), code, err)
		ev(fmt.Sprintf("(d) answer %d", answer), map[string]any{"requests": len(got), "end_session_status": code})
		if answer == 0 {
			break
		}
		rcv.Answer(200)
	}
	logs, _ := k.compose("logs", "--no-color", "--since", "10m", "keycloak").CombinedOutput()
	for _, line := range strings.Split(string(logs), "\n") {
		if strings.Contains(strings.ToLower(line), "logout") && strings.Contains(strings.ToLower(line), "fail") {
			fmt.Fprintf(&obs, "- Keycloak's log: `%s`\n", oneLineMax(line, 240))
		}
	}
	writeOIDCResult(t, k, "L45", l45Claim, obs.String(), evPath)
}
```

- [ ] **Step 5: L46, fresh authentication**

`tests/lab/l46_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

const l46Claim = "On Keycloak, with an SSO session live: whether a plain second authorization request reuses it " +
	"(the control); whether one with prompt=login makes the person enter their password again; whether the new ID " +
	"token's auth_time is the new authentication's; whether it carries the request's nonce; whether its sid is the " +
	"old session's; what a refresh-token grant's ID token carries (auth_time, nonce, sid); max_age=0 against " +
	"prompt=login; the ID token's preferred_username for a user created as \"alice\"; and which of auth_time, sid, " +
	"nonce, scp, amr, idtyp, azp, client_id and sub a client-credentials access token carries beside a person's " +
	"access token (policy engine spec §15 L46; §5.6; §13 decision 39 rulings 15, 21 and 23)."

func TestL46FreshAuthentication(t *testing.T) {
	k := startKeycloak(t)
	ev, evPath := oidcEvidence(t, k, "L46-keycloak")
	var obs strings.Builder
	obs.WriteString("| step | password asked | auth_time | nonce | sid |\n|---|---|---|---|---|\n")
	at := func(id string) (float64, string, string) {
		_, c := claimsOf(id)
		a, _ := c["auth_time"].(float64)
		n, _ := c["nonce"].(string)
		s, _ := c["sid"].(string)
		return a, n, s
	}
	step := func(name string, r flowResult) (float64, string, string) {
		a, n, s := at(r.IDToken)
		fmt.Fprintf(&obs, "| %s | %v | %s | %q | %s |\n", name, r.SawLoginForm, time.Unix(int64(a), 0).UTC().Format(time.RFC3339), n, s)
		h, c := claimsOf(r.IDToken)
		ev(name, map[string]any{"header": h, "claims": c, "password_asked": r.SawLoginForm})
		return a, n, s
	}
	first := k.Login(t, "alice", "lab-only-alice-password", url.Values{"nonce": {"n-first"}})
	a1, _, s1 := step("1. first login, nonce n-first", first)
	time.Sleep(3 * time.Second)
	// 1b. The control (pre-flight I-7): a plain second login in the same
	// browser session reuses SSO, so no form is shown and auth_time stays.
	// Without it, step 2's "password asked" could be a cookie-jar fault, not
	// prompt=login, and Ruling 15's refresh_not_fresh would rest on nothing.
	reuse := k.Login(t, "alice", "lab-only-alice-password", url.Values{"nonce": {"n-reuse"}})
	ar, _, _ := step("1b. plain second login (control), nonce n-reuse", reuse)
	if reuse.SawLoginForm || ar != a1 {
		t.Fatalf("the control failed: a plain second login showed the form (%v) or moved auth_time (%v to %v): the "+
			"SSO session is not reused, so step 2 cannot show what prompt=login does; no note is written",
			reuse.SawLoginForm, a1, ar)
	}
	time.Sleep(3 * time.Second)
	again := k.Login(t, "alice", "lab-only-alice-password", url.Values{"prompt": {"login"}, "nonce": {"n-again"}})
	a2, n2, s2 := step("2. prompt=login, nonce n-again", again)
	time.Sleep(3 * time.Second)
	ref := k.Refresh(t, again.RefreshToken)
	a3, n3, s3 := step("3. refresh-token grant", ref)
	time.Sleep(3 * time.Second)
	maxAge := k.Login(t, "alice", "lab-only-alice-password", url.Values{"max_age": {"0"}, "nonce": {"n-maxage"}})
	a4, _, _ := step("4. max_age=0, nonce n-maxage", maxAge)
	fmt.Fprintf(&obs, "\n- prompt=login moved auth_time by %ds and asked for the password: %v; its nonce is the "+
		"request's: %v; its sid is the first login's: %v.\n", int(a2-a1), again.SawLoginForm, n2 == "n-again", s2 == s1)
	fmt.Fprintf(&obs, "- The refresh-token grant's auth_time is the last authentication's: %v (%ds after it); "+
		"its nonce: %q; its sid unchanged: %v.\n", a3 == a2, int(a3-a2), n3, s3 == s2)
	fmt.Fprintf(&obs, "- max_age=0 asked for the password: %v, and moved auth_time by %ds.\n", maxAge.SawLoginForm, int(a4-a2))
	// The row closes for Ruling 15 only if all three hold (Task 16 Step 5).
	fmt.Fprintf(&obs, "- **Ruling 15 may close on this run:** %v (the control held: true; prompt=login moved auth_time "+
		"forward: %v; the nonce was echoed: %v).\n", a2 > a1 && n2 == "n-again", a2 > a1, n2 == "n-again")

	// The principal claim (Ruling 23; pre-flight I-6) and the access tokens
	// (Ruling 21; pre-flight C-1): which session claims a client-credentials
	// token carries beside a person's, and the sub each names.
	_, ic := claimsOf(first.IDToken)
	fmt.Fprintf(&obs, "- The ID token's preferred_username for a user created as \"alice\": %q.\n", ic["preferred_username"])
	svc := k.ServiceToken(t)
	_, sc := claimsOf(svc)
	_, pc := claimsOf(again.AccessToken)
	ev("access tokens", map[string]any{"client_credentials": sc, "person": pc})
	obs.WriteString("\n| claim | client-credentials token | person's access token |\n|---|---|---|\n")
	var markers []string
	for _, name := range []string{"auth_time", "sid", "nonce", "scp", "amr", "idtyp", "azp", "client_id", "sub", "scope",
		"session_state", "aud"} {
		sv, sOK := sc[name]
		pv, pOK := pc[name]
		fmt.Fprintf(&obs, "| %s | %s | %s |\n", name, claimCell(sv, sOK), claimCell(pv, pOK))
		if sOK && slices.Contains([]string{"auth_time", "sid", "nonce", "scp", "amr"}, name) {
			markers = append(markers, name)
		}
	}
	fmt.Fprintf(&obs, "\n- Ruling 21's markers on the client-credentials token: %v (the ruling rests on none).\n", markers)
	fmt.Fprintf(&obs, "- The client-credentials token's sub is the service account's fixed id %s: %v.\n",
		kcServiceAccountID, sc["sub"] == kcServiceAccountID)
	writeOIDCResult(t, k, "L46", l46Claim, obs.String(), evPath)
	if sc["sub"] != kcServiceAccountID {
		t.Errorf("the service account's sub is %v, not realm.json's fixed id: Task 16's clients pin would refuse it; "+
			"fix the realm import, never the pin", sc["sub"])
	}
}

// claimCell is a claim's cell: its value when short, "present" when long, or
// "absent".
func claimCell(v any, ok bool) string {
	if !ok {
		return "absent"
	}
	if s := fmt.Sprint(v); len(s) <= 60 {
		return "`" + s + "`"
	}
	return "present"
}
```

- [ ] **Step 6: The make target and the README**

In `Makefile`, after `lab-directory`:

```make
# The identity-provider lab (plan 7h): Keycloak as a container, no devices.
# Needs Docker with Compose v2.24.4+; see tests/lab/README.md, "Identity provider".
lab-oidc:
	go test -tags lab ./tests/lab/ -run 'TestL45|TestL46' -count=1 -v -timeout 30m
```

(`.PHONY` gains `lab-oidc`.) `tests/lab/README.md` gains an "Identity provider" section: what
`make lab-oidc` brings up, the digest pin, that `host.port49.lab` must reach the host's port
18750 from the container (`host-gateway`), that the receiver and the broker's certificates come
from the run's own CA, that the evidence holds decoded JWS headers and claims, never a
signature, that `realm.json` fixes `port49-svc`'s service-account id so its `sub` can be pinned
(Ruling 21), and that L46 refuses to write its note when its SSO control (step 1b) fails.

- [ ] **Step 7: Review the harness, then commit**

Run: `go vet -tags lab ./tests/lab/ && go test -tags lab ./tests/lab/ -run 'TestL45|TestL46' -count=1 -list '.*'`
Expected: vet clean; both tests listed. (They are run in Task 16.)

The harness is reviewed before the run (7g's Phase 1), on its own diff.

```bash
git add tests/lab/oidc/ tests/lab/oidc_test.go tests/lab/oidcflow_test.go tests/lab/l45_test.go \
  tests/lab/l46_test.go Makefile tests/lab/README.md
git commit -m "test(lab): Keycloak, a scripted login flow and a logout receiver for L45 and L46

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 16: (lab, on beehive) L45 and L46 measured; an OIDC login and logout end to end

**Files:**
- Create: `tests/lab/compose/oidc.yaml`, `tests/lab/oidc_e2e_test.go` (`//go:build lab`)
- Modify: `internal/testpki/testpki.go` (`WriteLabWith`: the broker certificate names
  `port49-broker`), `internal/testpki/testpki_test.go` (pre-flight I-8)
- Create (by the runs): `tests/lab/results/L45-keycloak.md`, `L46-keycloak.md`,
  `oidc-e2e-arista_eos.md`; `tests/lab/evidence/L45-keycloak.json`, `L46-keycloak.json`, and
  `oidc-e2e-arista_eos.pcap` by `make evidence` from the raw capture (pre-flight M-23)
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15: L45, L46 closed or corrected; L47
  stays open), and any doc a result contradicts (register rule 4)

**Interfaces:**
- Consumes: Task 15's harness; the lab's compose stack (`startComposeWith`, `composeOptions`,
  `sliceBrokerURL`, `slicePKIDir`, `l.shell`, `l.runPermitted`, `l.runCmd`, `waitRecordsOf`,
  `l.capture`, `l.result`); Tasks 9–14 on the branch.
- Produces: the register's L45 and L46 rows closed on Keycloak, or the docs corrected where
  Keycloak contradicts them; the end-to-end note.

- [ ] **Step 1: Run L45 and L46**

On beehive, from a pinned worktree of the branch at the commit under test, with a background
stall watchdog armed (Running the lab, above):

Run: `df -h && sg docker -c 'docker compose version' && sg docker -c 'make lab-oidc'`
Expected: both tests PASS and write `tests/lab/results/L45-keycloak.md`, `L46-keycloak.md` and
their evidence. A harness failure (Keycloak never answering discovery, a login form that
changed, L46's SSO control failing, the service account's `sub` not the fixed id) is the
harness's to fix and rerun; a measurement that contradicts a ruling is a finding, Step 4.

- [ ] **Step 1b: The lab broker certificate names its compose host** (pre-flight I-8)

Keycloak posts its logouts to `https://port49-broker:8443/v1/logout` on the stack's network, and
checks the broker's certificate against that name. `WriteLabWith`'s broker leaf
(`internal/testpki/testpki.go:173`) carries the IP SAN `127.0.0.1` alone, so every logout POST
would fail its hostname check and the end-to-end note would record that logout does not work.

In `internal/testpki/testpki_test.go`:

```go
// The lab broker's certificate names the compose host as well as the
// loopback address: Keycloak reaches it as port49-broker (plan 7h).
func TestTheLabBrokerCertificateNamesItsComposeHost(t *testing.T) {
	dir := t.TempDir()
	if err := WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, LabServerCert), filepath.Join(dir, LabServerKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("port49-broker"); err != nil {
		t.Fatalf("port49-broker: %v", err)
	}
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("127.0.0.1: %v", err)
	}
}
```

Run it to see it fail (`go test ./internal/testpki/ -run TestTheLabBrokerCertificateNames
-count=1`: `x509: certificate is valid for 127.0.0.1, not port49-broker`), then in `WriteLabWith`'s
broker leaf add `DNSNames: []string{"port49-broker"}` beside `IPs`, and run `go test
./internal/testpki/ -count=1`: PASS (the file imports `crypto/tls`, `crypto/x509` and
`path/filepath` already). Commit:

```bash
git add internal/testpki/testpki.go internal/testpki/testpki_test.go
git commit -m "test(testpki): the lab broker certificate names port49-broker, for the provider's back-channel logout

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

- [ ] **Step 2: The end-to-end overlay**

`tests/lab/compose/oidc.yaml`:

```yaml
# Keycloak on the lab's compose stack (plan 7h, Task 16): the realm of
# tests/lab/oidc, its issuer https://keycloak.port49.lab:18443/realms/port49-lab,
# which the broker reaches on the stack's network by the alias and the test
# reaches on the published port. Everything under ${PORT49_COMPOSE_LOCAL}/oidc
# is written by TestOIDCEndToEnd before `up`.
services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.4
    command:
      - start-dev
      - --import-realm
      - --http-enabled=false
      - --https-port=18443
      - --https-certificate-file=/pki/keycloak.pem
      - --https-certificate-key-file=/pki/keycloak-key.pem
      - --hostname=https://keycloak.port49.lab:18443
      - --truststore-paths=/pki/broker-ca.pem
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: admin
    env_file:
      - path: ${PORT49_COMPOSE_LOCAL}/oidc/admin.env
    volumes:
      - ../../tests/lab/oidc/keycloak/realm.json:/opt/keycloak/data/import/realm.json:ro
      - ${PORT49_COMPOSE_LOCAL}/oidc/pki:/pki:ro
    networks:
      port49:
        aliases: [keycloak.port49.lab]
    ports:
      - "127.0.0.1:18443:18443"

  port49-broker:
    volumes:
      - ${PORT49_COMPOSE_LOCAL}/oidc/idp-ca.pem:/etc/port49-oidc/idp-ca.pem:ro
    depends_on:
      keycloak: {condition: service_started}
```

`service_started` is all the overlay asks: Keycloak's image carries no HTTP client for a
healthcheck, and the broker must not wait on the provider anyway (Ruling 4). The broker's first
fetches fail while Keycloak imports its realm (up to 90s), and its key set then refetches at
most once a minute, so the test's first mint retries on 503 `identity_provider_unavailable` for
up to 3 minutes (`mintBearerRetry`; pre-flight I-9) instead of failing on the race.

- [ ] **Step 3: The end-to-end test**

`tests/lab/oidc_e2e_test.go`:

```go
//go:build lab

package lab

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/testpki"
)

const oidcE2EClaim = "A person who logs in at Keycloak mints a token from the broker with the ID token as a bearer " +
	"and logs in to the device with it; a logout at Keycloak reaches the broker by back-channel and the open " +
	"session's next command is denied credential_revoked; a new login after it works; a prompt=login refresh " +
	"answering the broker's challenge extends the open session from the fresh auth_time, while a plain SSO login " +
	"answering one is refused refresh_not_fresh; and a client-credentials token of the listed client mints for " +
	"the machine subject (plan 7h Task 16; policy engine spec §14)."

// oidcE2EFiles gives the broker the identity block and the policy two OIDC
// subjects: alice by her verified email, and the lab service.
func oidcE2EFiles(files map[string]string) error {
	b := files["port49-broker.yaml"]
	i := strings.Index(b, "  client_ca_file:")
	if i < 0 {
		return fmt.Errorf("port49-broker.yaml has no client_ca_file to replace")
	}
	j := strings.Index(b[i:], "\n") + i + 1
	anchor := strings.TrimSpace(strings.TrimPrefix(b[i:j-1], "  client_ca_file:"))
	files["port49-broker.yaml"] = b[:i] + `  identity:
    humans:
      - {type: x509, trust_anchor_file: ` + anchor + `}
      - type: oidc
        issuer: https://keycloak.port49.lab:18443/realms/port49-lab
        client_id: port49-cli
        principal_claim: email
        principal_domains: [corp.example.com]
        ca_file: /etc/port49-oidc/idp-ca.pem
    machines:
      - type: oidc
        issuer: https://keycloak.port49.lab:18443/realms/port49-lab
        audience: "api://port49-svc"
        clients: [{client_id: port49-svc, sub: ` + kcServiceAccountID + `}]
        ca_file: /etc/port49-oidc/idp-ca.pem
` + b[j:]
	files["policy.yaml"] = strings.Replace(files["policy.yaml"], "subjects:\n", `subjects:
  - {name: oidc_alice, identity: ["user:alice@corp.example.com"], username: alice, token_ttl: 300s}
  - {name: oidc_svc, identity: ["app:port49-svc"], username: svc-backup, token_ttl: 300s}
`, 1)
	files["policy.yaml"] = strings.Replace(files["policy.yaml"], "grants:\n", `grants:
  - {subject: oidc_alice, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: oidc_svc, scope: all_devices, roles: [network_admin], max_privilege: admin}
`, 1)
	return nil
}

// oidcE2EPrepare writes Keycloak's PKI (its server certificate from a CA of
// this run's, the broker's CA as its truststore) and the admin password.
func oidcE2EPrepare(c *composeStack) error {
	dir := filepath.Join(c.local, "oidc")
	pki := filepath.Join(dir, "pki")
	if err := os.MkdirAll(pki, 0o755); err != nil {
		return err
	}
	now := time.Now()
	ca, err := testpki.NewCA("port49 lab oidc e2e CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		return err
	}
	leaf, err := ca.Issue(testpki.Leaf{CommonName: kcHost, DNSNames: []string{kcHost}, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		return err
	}
	cert, key, err := testpki.PEMs(leaf)
	if err != nil {
		return err
	}
	brokerCA, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
	if err != nil {
		return err
	}
	pass := make([]byte, 18)
	_, _ = rand.Read(pass)
	for path, body := range map[string][]byte{
		filepath.Join(pki, "keycloak.pem"): cert, filepath.Join(pki, "keycloak-key.pem"): key,
		filepath.Join(pki, "broker-ca.pem"): brokerCA, filepath.Join(dir, "idp-ca.pem"): ca.PEM(),
		filepath.Join(dir, "admin.env"): []byte("KC_BOOTSTRAP_ADMIN_PASSWORD=" + fmt.Sprintf("%x", pass) + "\n"),
	} {
		if err := os.WriteFile(path, body, 0o644); err != nil {
			return err
		}
	}
	e2eKeycloakCA = ca
	return nil
}

// e2eKeycloakCA is the run's Keycloak CA, for the test's own client.
var e2eKeycloakCA *testpki.CA

func TestOIDCEndToEnd(t *testing.T) {
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range sel {
		if p.name != "arista_eos" {
			continue
		}
		p := p
		t.Run(p.name, func(t *testing.T) { oidcEndToEnd(t, labFor(t, p)) })
		return
	}
	t.Skip("PORT49_LAB_PLATFORMS does not select arista_eos")
}

func oidcEndToEnd(t *testing.T, l *lab) {
	var failed []string
	fail := func(format string, args ...any) { failed = append(failed, fmt.Sprintf(format, args...)) }
	var obs strings.Builder
	cell := func(step, what string) { fmt.Fprintf(&obs, "| %s | %s |\n", step, wideCell(what)) }
	c := l.startComposeWith(t, composeOptions{Overlay: "oidc.yaml", Files: oidcE2EFiles, Prepare: oidcE2EPrepare})
	stop := l.capture(t, "oidc-e2e")
	defer stop()
	defer func() {
		note := "| step | observed |\n|---|---|\n" + obs.String()
		if len(failed) > 0 {
			note += "\n**Not as the claim says:**\n\n- " + strings.Join(failed, "\n- ") + "\n"
		}
		l.result(t, "oidc-e2e", oidcE2EClaim, note)
		if len(failed) > 0 {
			t.Errorf("OIDC end to end: %s", strings.Join(failed, "; "))
		}
	}()
	kc := &keycloak{URL: "https://" + kcHost + ":" + kcPort + "/realms/" + kcRealm, ca: e2eKeycloakCA}
	kc.HTTP = keycloakClient(e2eKeycloakCA)
	waitDiscovery(t, kc, 3*time.Minute)
	kc.adminFromEnv(t, filepath.Join(c.local, "oidc", "admin.env"))
	kc.SetLogoutURL(t, "https://port49-broker:8443/v1/logout")
	api := brokerClient(t)

	// ---- 1. Log in at Keycloak, mint with the ID token, log in to the device.
	// The first mint retries while the broker's key set has not yet fetched
	// Keycloak's keys (pre-flight I-9).
	first := kc.Login(t, "alice", "lab-only-alice-password", nil)
	tok, said := mintBearerRetry(t, api, first.IDToken, l.p.node, 3*time.Minute)
	cell("1a. Keycloak login, POST /v1/tokens with the ID token as bearer", said)
	if tok == "" {
		t.Fatalf("no token: %s", said)
	}
	sh, err := l.shell("alice", tok)
	if err != nil {
		t.Fatalf("SSH as alice: %v", err)
	}
	defer sh.Close()
	r := l.runPermitted(sh, "show version", 20*time.Second)
	cell("1b. SSH as alice with the token, `show version`", r.cell)
	if !r.permitted {
		fail("the first command: %s", r.cell)
	}

	// ---- 2. Log out at Keycloak; the broker hears it; the next command is denied.
	boff := fileSize(c.brokerLog)
	kc.EndSession(t, first.IDToken)
	recs := waitRecordsOf(c.brokerLog, boff, 30*time.Second, func(rs []map[string]any) bool {
		for _, rec := range rs {
			if str(rec, "event") == "revoke" && str(sub(rec, "revocation"), "by") == "sid" {
				return true
			}
		}
		return false
	})
	var rv map[string]any
	for _, rec := range recs {
		if str(rec, "event") == "revoke" {
			rv = rec
		}
	}
	cell("2a. RP-initiated logout at Keycloak; the broker's revoke record", fmt.Sprintf("%v", sub(rv, "revocation")))
	if rv == nil {
		fail("no revoke record by sid within 30s of the logout")
	}
	denied := l.runCmd(sh, "show clock")
	cell("2b. the open session's next command", denied.cell)
	if denied.permitted {
		fail("the session's command after the logout was permitted: %s", denied.cell)
	}
	if _, said := mintBearer(t, api, first.IDToken, l.p.node); !strings.Contains(said, "credential_revoked") {
		fail("the ended session's ID token minted again: %s", said)
	}

	// ---- 3. A new login after the logout works, and opens a live session
	// for the refresh to extend (pre-flight I-10).
	kc.HTTP = keycloakClient(e2eKeycloakCA) // a fresh browser
	second := kc.Login(t, "alice", "lab-only-alice-password", nil)
	tok2, said2 := mintBearer(t, api, second.IDToken, l.p.node)
	cell("3a. a new Keycloak login, a new mint", said2)
	if tok2 == "" {
		t.Fatalf("a login after the logout minted nothing: %s", said2)
	}
	sh2, err := l.shell("alice", tok2)
	if err != nil {
		t.Fatalf("SSH as alice with the second token: %v", err)
	}
	defer sh2.Close()
	r2 := l.runPermitted(sh2, "show version", 20*time.Second)
	cell("3b. SSH as alice with it, `show version`", r2.cell)
	if !r2.permitted {
		fail("the second session's first command: %s", r2.cell)
	}

	// ---- 4b. A plain SSO login answering a challenge is not fresh: Keycloak
	// does not authenticate again without prompt=login, so its auth_time
	// predates the challenge by more than clock_skew (75s after step 3a) and
	// the broker refuses it (Ruling 15; pre-flight I-10).
	time.Sleep(75 * time.Second)
	stale := refreshChallenge(t, api, second.IDToken)
	sso := kc.Login(t, "alice", "lab-only-alice-password", url.Values{"nonce": {stale}})
	code, body := postBearer(t, api, "/v1/refresh", sso.IDToken, "{}")
	cell("4b. a challenge, a plain SSO login with its nonce, `POST /v1/refresh`",
		fmt.Sprintf("password asked: %v; %d %s", sso.SawLoginForm, code, oneLineMax(body, 300)))
	if code != 401 || !strings.Contains(body, "refresh_not_fresh") {
		fail("a refresh the provider did not re-authenticate: %d %s", code, body)
	}

	// ---- 4. A prompt=login refresh answering the broker's challenge extends
	// the open session from the fresh auth_time.
	time.Sleep(11 * time.Second) // one challenge per principal per 10s
	nonce := refreshChallenge(t, api, second.IDToken)
	fresh := kc.Login(t, "alice", "lab-only-alice-password", url.Values{"prompt": {"login"}, "nonce": {nonce}})
	code, body = postBearer(t, api, "/v1/refresh", fresh.IDToken, "{}")
	cell("4. `POST /v1/refresh/challenge`, a prompt=login login with its nonce, `POST /v1/refresh`",
		fmt.Sprintf("password asked: %v; %d %s", fresh.SawLoginForm, code, oneLineMax(body, 300)))
	var refreshed struct {
		AuthTime string `json:"auth_time"`
		Sessions []struct {
			Device, Username, Outcome string
		} `json:"sessions"`
	}
	_, fc := claimsOf(fresh.IDToken)
	at, _ := fc["auth_time"].(float64)
	extended := 0
	if code == 200 && json.Unmarshal([]byte(body), &refreshed) == nil {
		for _, s := range refreshed.Sessions {
			if s.Outcome == "extended" && s.Device == l.p.node && s.Username == "alice" {
				extended++
			}
		}
	}
	switch {
	case code != 200:
		fail("the OIDC refresh: %d %s", code, body)
	case extended < 1:
		fail("the OIDC refresh extended no session: %s", oneLineMax(body, 300))
	case refreshed.AuthTime != time.Unix(int64(at), 0).UTC().Format(time.RFC3339):
		fail("the refresh's auth_time %s is not the fresh token's %s", refreshed.AuthTime,
			time.Unix(int64(at), 0).UTC().Format(time.RFC3339))
	}
	if r := l.runPermitted(sh2, "show clock", 20*time.Second); !r.permitted {
		fail("the extended session's next command: %s", r.cell)
	}

	// ---- 5. A machine mints with a client-credentials token of its listed
	// client, whose sub is the pinned service account (Ruling 21).
	svc := kc.ServiceToken(t)
	tok3, said3 := mintBearer(t, api, svc, l.p.node)
	cell("5. client-credentials token, POST /v1/tokens", said3)
	if tok3 == "" || !strings.Contains(said3, "app:port49-svc") {
		fail("the machine's mint: %s", said3)
	}
}

// mintBearerRetry is mintBearer retried every 10s while the broker answers
// 503 identity_provider_unavailable, up to within: the broker's first key
// fetches fail while Keycloak imports its realm (pre-flight I-9).
func mintBearerRetry(t *testing.T, c *http.Client, bearer, device string, within time.Duration) (string, string) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		tok, said := mintBearer(t, c, bearer, device)
		if tok != "" || !strings.Contains(said, "identity_provider_unavailable") || time.Now().After(deadline) {
			return tok, said
		}
		time.Sleep(10 * time.Second)
	}
}

// brokerClient trusts the compose stack's broker certificate.
func brokerClient(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join(root, slicePKIDir, testpki.LabCA))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}}}
}

func postBearer(t *testing.T, c *http.Client, path, bearer, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", sliceBrokerURL+path, bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// mintBearer mints one token for device with bearer, and says what it got
// without the token.
func mintBearer(t *testing.T, c *http.Client, bearer, device string) (string, string) {
	t.Helper()
	code, body := postBearer(t, c, "/v1/tokens", bearer, `{"devices":["`+device+`"],"ttl_seconds":300}`)
	var resp struct {
		Principal string `json:"principal"`
		Results   []struct {
			Verdict, Reason, Username, Login string
		} `json:"results"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &resp) != nil || len(resp.Results) != 1 {
		return "", fmt.Sprintf("%d %s", code, oneLineMax(body, 300))
	}
	r := resp.Results[0]
	return r.Login, fmt.Sprintf("200 %s: %s %s as %s", resp.Principal, r.Verdict, r.Reason, r.Username)
}

func refreshChallenge(t *testing.T, c *http.Client, bearer string) string {
	t.Helper()
	code, body := postBearer(t, c, "/v1/refresh/challenge", bearer, "")
	var ch struct {
		Nonce string `json:"nonce"`
	}
	if code != 200 || json.Unmarshal([]byte(body), &ch) != nil {
		t.Fatalf("challenge: %d %s", code, body)
	}
	return ch.Nonce
}
```

`keycloakClient`, `kcDial`, `waitDiscovery` and `adminFromEnv` are Task 15's.

Run: `sg docker -c 'PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run TestOIDCEndToEnd -count=1 -v -timeout 60m'`
Expected: PASS, and `tests/lab/results/oidc-e2e-arista_eos.md` with its capture.

- [ ] **Step 4: Read the notes against the rulings (register rule 4)**

For each of these, the note either confirms it or the doc is corrected, citing the note, and the
commit message says which:
- Ruling 12: Keycloak's token has `iss`, `aud` = `port49-cli`, `iat`, `jti`, `events` with the
  member, `sid` (session required), and no `nonce`. Whether it has `exp` and a `typ` is recorded
  (both are accepted either way). If it sends no `jti`, Ruling 12's "`jti` is required" refuses
  every Keycloak logout: that is a finding for Ryan, not a silent loosening.
- Ruling 13: the logout token's `sid` equals the ID token's `sid` (else a logout by sid reaches
  no context), and its `sub` equals the ID token's `sub` (else a logout by sub finds no owner
  record; pre-flight M-23).
- Ruling 21: the client-credentials token carries none of `auth_time`, `sid`, `nonce`, `scp`,
  `amr`, and its `sub` is the fixed service-account id. If Keycloak puts a marker on it, every
  Keycloak machine token is refused: a finding for Ryan, never a marker dropped from the list.
  The person's access token's markers are recorded beside it.
- Ruling 23: the ID token's `preferred_username` for a user created as `alice` (the bare name,
  if Keycloak's default holds), which spec §2's amended row cites.
- Ruling 12's 503: whether Keycloak retries. If it does not, the operator notes say a logout
  lost to a store outage must be replaced by `port49 revoke`, as they already do.
- Ruling 15: `prompt=login` asks for the password and moves `auth_time`; the `nonce` is the
  request's. If Keycloak did not move `auth_time`, every OIDC refresh is `refresh_not_fresh`:
  a finding for Ryan. The note's "Ruling 15 may close on this run" line must read true: the
  control (step 1b) held, `a2 > a1`, and the nonce was echoed (pre-flight I-7). The end-to-end
  note's 4b (a plain SSO login refused `refresh_not_fresh`) is the same property through the
  broker.
- Spec §5.6's claim that a refresh-token grant keeps the original `auth_time`: the L46 note
  confirms it, or §5.6 is corrected.

- [ ] **Step 5: Close the rows (register rule 3)**

In spec §15, L45's and L46's Status become `closed — measured <date>; tests/lab/results/L45-keycloak.md`
(and `L46-keycloak.md`), each with the one-line observation the note gives. L46 closes only if
its note says "Ruling 15 may close on this run: true" (pre-flight I-7); else it stays open and
the run's outcome goes to Ryan. L47 stays open. The decision 39 bullets marked "provisional on
L45/L46" lose that mark for Keycloak and keep it for L47's hosted providers.

The end-to-end capture holds the device's port49 token on `tcp/49`. Run `make evidence`
(`go run ./tests/lab/cmd/redact-pcap`), which writes the redacted
`tests/lab/evidence/oidc-e2e-arista_eos.pcap` from `tests/lab/captures/`, and commit only that
(pre-flight M-23); the raw capture is copied to `main`'s `tests/lab/captures/` below and never
committed.

```bash
make evidence
git add tests/lab/compose/oidc.yaml tests/lab/oidc_e2e_test.go tests/lab/results/ tests/lab/evidence/
git commit -m "test(lab): OIDC end to end on the compose stack; L45 and L46 measured on Keycloak

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L45 and L46 on Keycloak

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

Copy the raw capture to `main`'s `tests/lab/captures/` before removing the lab worktree.

---

### Task 17: Plan 7h as built

**Files:**
- Modify: `docs/superpowers/plans/README.md` (the status line; "Plan 7h — As built")
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (decision 39's "as built" amendments, if
  any task departed from a ruling)

**Interfaces:**
- Consumes: every task's report and review; Ryan's answers to OR-1 to OR-3.
- Produces: the roadmap's record of 7h, in 7g's "As built" shape.

- [ ] **Step 1: The as-built section**

After "Plan 7g — As built", add "### Plan 7h — As built", in 7g's order:
- **Executed from:** the plan file, the branch (`feature/oidc-and-trust-domains`), the base, and
  the ledger (`.superpowers/sdd/2026-10-06-07h-oidc-and-trust-domains/progress.md`).
- **Task by task:** what differs from the plan's text, with commit hashes, each controller ruling
  named.
- **The rulings as made:** decision 39's twenty-four, each "stood" or what changed, with where it
  is recorded.
- **Ryan's answers:** OR-1, OR-2 and OR-3, each with the answer.
- **The operator notes as built:** the plan's notes below, corrected by what the lab measured.
- **Lab:** L45 and L46 closed on Keycloak, or why not; L47 open.
- **The interfaces 7h added:** `oidc.*`; `store` methods `PutOnce`, `TakeOnce`,
  `PutOIDCOwner`, `OIDCOwner`, `PutLogout`, `GetLogout`, functions `OIDCKey`, `SidKey`, types
  `OIDCOwner`, `OwnerPrincipal`, `Logout`; `broker` `Identity`, `NoX509`, `caller`,
  `bearerCaller`, `Logout`, `RevokeSid`, `oidcChallenge`, `oidcRefresh`, `noteOwner`,
  `loggedOut`; `session.AddSid`; `config` `Identity`, `BrokerStateDir`; `decision.Revocation`'s
  `Principals`; the metrics.
- **Carried, for later plans:**
  - **8:** `x509` under `broker.identity.machines` (refused at load until then); a workload
    certificate's directory entry through `Resolver.Map`.
  - **9:** the agent's OIDC public client with PKCE: `/v1/config`'s `oidc`, the refresh
    challenge as the `nonce` of a `prompt=login` request, the ID token as each request's
    bearer, re-login on `credential_revoked` from a logout, and the provider's refresh token
    kept per design §7.
  - **10:** the `k8s` verifier under `machines`.
  - **12:** the alerts:
    - `time() - port49_oidc_keys_last_success_timestamp_seconds > jwks_max_age / 2 or
      absent(port49_oidc_keys_last_success_timestamp_seconds)`, with a `for:` of a few minutes;
    - `port49_oidc_logouts_total{outcome=~"store_error|partial"}` increasing;
    - `port49_oidc_tokens_total{outcome="unavailable"}` increasing;
    - and per-source admission sizing for an office behind one address (Ruling 8).
  - **Unassigned:** L47, the hosted providers (OR-3), with Entra's `idtyp`, `scp`, v2 `aud`
    and missing `email_verified` (pre-flight M-8, C-1).

- [ ] **Step 2: The status line**

In the roadmap's status paragraph, after 7g's entry: "**7h executed** <dates> on
`feature/oidc-and-trust-domains`, each task reviewed, L45 and L46 <closed on Keycloak | the
outcome>, L47 open (Plan 7h — As built, below); **merged** <date> as PR #<n>." The merge's own
values are written at the merge.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/plans/README.md docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: plan 7h as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

## Operator-facing notes (for the pull request body)

- **New: `broker.identity`** (spec §13 decision 39). Two lists, `humans` and `machines`:
  - **`x509` under `humans`:** `trust_anchor_file`, the one anchor (at most one). Without
    `broker.identity`, `broker.client_ca_file` is that verifier, as before; with it,
    `client_ca_file` is refused ("moved to broker.identity.humans[].trust_anchor_file").
  - **`oidc` under `humans`:** `issuer` (https), `client_id` (your public client),
    `principal_claim` (**required**, no default: `preferred_username`, `email` with
    `email_verified`, or `upn`), `principal_domains` (**required**: the domains whose people
    this provider may name, matched exactly, no subdomain implied), `scopes`, `algorithms`
    (default `[RS256]`; `RS256`, `PS256`, `ES256`, `ES384`, `EdDSA`; never `none` or an HMAC),
    `ca_file` (omit for the system roots; checked readable at load).
  - **`oidc` under `machines`:** `issuer`, `audience` (the API identifier your client-credentials
    tokens name), `clients` (**required**: `[{client_id, sub}]`, each client that may be a
    machine, with the `sub` its tokens carry: on Keycloak the client's service-account user id,
    on Entra ID the service principal's object id), `algorithms`, `ca_file`. The principal is
    `app:<azp>`, case kept.
  - **A person's token is never a machine's.** A token carrying `auth_time`, `sid`, `nonce`,
    `scp` or `amr`, an `idtyp` other than `app`, another `sub` than the client's, or an unlisted
    client is refused. So a person who signs into a machine client that also allows interactive
    grants cannot act as the service.
  - **Timing:** `clock_skew` (60s), `max_token_age` (2h), `jwks_refresh_interval` (1h),
    `jwks_max_age` (24h); OR-2.
  - **Refused at load:** `x509` under `machines` (plan 8), `k8s` (plan 10), a verifier listed
    twice, a human `client_id` equal to a machine `audience` at one issuer, two human verifiers
    at different issuers whose `principal_domains` overlap, two at one issuer with different
    `principal_claim`s, a missing `principal_claim`, `principal_domains` or `clients`.
  - **The kept key files** (`oidc-<hash>.json` in the state directory) may not collide with
    another configured file; a state directory the broker cannot keep keys in is said at start.
- **The principal claim must be one only your provider's administrators can set.** A person who
  can edit their own `preferred_username` chooses whose principal they are. On Keycloak, turn
  off "edit username"; `email` is safe only with email verification on (port49 requires
  `email_verified: true`). On a Keycloak realm that brokers another identity provider, turn
  off "trust email": it lets that provider assert any address. On Keycloak, whose
  `preferred_username` L46 records for a user created with a bare name, `email` is the usual
  choice. Microsoft Entra ID may send no `email_verified` (L47, open, measures it); if so,
  `principal_claim: email` refuses every Entra person, and `upn` is the claim there.
- **Each provider names its own people.** `principal_domains` keeps a second provider (a
  contractor realm, a brokered IdP) from minting as your staff: a token naming a principal
  outside its verifier's domains is refused `identity_unmapped`, and that provider's logout
  reaches none of your staff's sessions.
- **OIDC people need a username source.** With `broker.directory`, the directory gives it (the
  principal claim must equal the directory's `principal_attribute` value). Without one, list
  the person under an identity subject with `username:`. port49 never takes a username or a
  group from a token.
- **An OIDC-only broker** (no `x509` verifier) asks for no client certificate and takes no
  `certificate_status` (it is refused there).
- **Every OIDC request carries its token** (`Authorization: Bearer`). Its connection is closed
  when idle and counts against `broker.max_pending_conns_per_source` (16) while open: raise it
  for an office whose operators share one NAT address and run many requests at once.
- **The session clock is your provider's `auth_time`.** A token whose `auth_time` is older than
  `session.max_session_age_default` is refused `session_expired`: log in again. The ceiling
  per device counts from it.
- **Refresh:** `POST /v1/refresh/challenge`, then a `prompt=login` login at the provider with
  that nonce, then `POST /v1/refresh` with the new ID token. If the provider does not
  re-authenticate (`refresh_not_fresh`), nothing is extended. The agent does this from plan 9.
- **Back-channel logout:** register `https://<broker>/v1/logout` as the client's back-channel
  logout URL with "session required" on.
  - **By `sid`,** the broker ends the contexts that session authorized; **by `sub` alone**,
    every context of the person, certificate logins included (a context is shared per person and
    device).
  - Either way it deletes the person's unspent tokens and refuses that session's (or, by `sub`,
    every older) token from then on. No standing mark: the person can log in again at once.
    To ban, use `port49 revoke`.
  - A logout the provider sends twice does nothing the second time.
  - **If the store is down**, the broker answers 503 and the logout may be lost unless the
    provider retries (L45 records whether Keycloak does). Revoke the principal with `port49
    revoke` once the store is back. If the broker could not even give the logout back for a
    retry, it says so in one line naming the session and `POST /v1/tokens/revoke {"sid": …,
    "issuer": …}`: the provider's retry would be answered 200 and do nothing.
  - **A person renamed at the provider** (one `sub`, a new principal) is reached under both
    principals by a logout for a day after the rename.
  - **A `sub` logout** finds the person through the last day's mints: one for someone who has
    not minted in `max(max_session_age_default, 24h)` refuses their older tokens but reaches no
    open session; `port49 revoke` does.
  - On Junos, as with every revocation, the open session keeps what it had at login.
- **A provider outage.** Tokens people hold keep working against the keys the broker last
  fetched, kept in its state directory across a restart, until `jwks_max_age` (24h) after the
  last successful fetch. Past it every OIDC request is 503 `identity_provider_unavailable`.
  Certificate logins, live device sessions and break-glass are unaffected. Alert at half,
  `time() - port49_oidc_keys_last_success_timestamp_seconds > jwks_max_age / 2 or
  absent(port49_oidc_keys_last_success_timestamp_seconds)`, with a `for:` of a few minutes: the
  gauge carries a restored set's age, so a restart during the outage does not silence it.
  - **The 3am escape past `jwks_max_age`:** raise `broker.identity.jwks_max_age` (up to 720h)
    and restart; the kept file is judged against the new maximum. Restart port49-broker where
    you run one: a port49d restart also restarts device AAA.
  - **In the decision log** a provider outage's refusals read `trust_domain_unresolved` (the
    record has no field for an API code); tell them from bad tokens by the 503s'
    `identity_provider_unavailable`, the hourly "keys not refreshed" line, and
    `port49_oidc_tokens_total{outcome="unavailable"}`.
  - **A provider publishing a JWKS with no usable key** is treated as a failed fetch: the last
    good keys stand.
- **An egress proxy.** The broker reaches the provider through `HTTPS_PROXY` (and honours
  `NO_PROXY`) when set; the start says which, with any proxy password redacted.
- **Upgrade order.** Upgrade every broker replica before setting `broker.identity` or registering
  the back-channel logout URL: a replica from before 7h answers 404 to `/v1/logout`, and that
  logout is lost.
- **`port49 revoke app:<client_id>`** revokes a machine's OIDC client (case kept).
- **`POST /v1/tokens/revoke {"sid": …, "issuer": …}`** ends one OIDC session, under
  `revoke_others`.
- **`GET /v1/config`** now lists `oidc` providers (issuer, client_id, scopes) and `methods`.
- **New records:** `auth.oidc` (`issuer`, `sub`, `sid`, `amr`, `acr`, `auth_time`) on every broker
  record of an OIDC caller; `revoke` records `by: sid` or `by: sub` with `oidc_issuer`, origin
  `backchannel_logout <issuer>` or `api <caller>`. No reason code is new.
- **New API errors:** `503 identity_provider_unavailable`, `401 refresh_not_fresh`; `400
  bad_request` for a certificate and a bearer on one request.
- **New metrics:** `port49_oidc_tokens_total{issuer,outcome}`,
  `port49_oidc_keys_last_success_timestamp_seconds{issuer}`,
  `port49_oidc_keys_fetch_failures_total{issuer}`, `port49_oidc_logouts_total{outcome}`.
- **New record field:** `revocation.principals` when a logout reached more than one principal.
- **Lab:** measured on Keycloak 26.4 only (L45, L46). Microsoft Entra ID and Okta are L47, open.
  Unmeasured, and so only a caution until L47 closes: on Entra a v2 access token's `aud` may be
  the application's GUID rather than its `api://` URI, and an ID token may carry no
  `email_verified`.

## Self-review against the spec

**Coverage.** Each roadmap 7h item and each spec section the plan cites, with the task that
builds it:

| Requirement | Task |
|---|---|
| Decision 16's verifier lists; domain by verifier; a credential no verifier accepts refused | 1, 5, 7 |
| Design §7: OIDC tokens validated against the provider's JWKS | 3, 4, 5 |
| §2 principal table, OIDC rows (human and machine) | 5 |
| §2 username for OIDC (amended, Ruling 7) | 1, 9 |
| 7g carry: OIDC principals through `Resolver.Verify`/`Current` | 9 |
| §5.1.4 credential `oidc` fields; `amr`, `acr` recorded | 2, 5, 9 |
| §5.1.4 / roadmap: `/v1/logout` by `sid` or `sub` | 6, 12 |
| §2 `revoke_others` by `sid` | 13 |
| §5.6 `prompt=login` refresh, `auth_time` from the assertion; `sid` re-index | 11 |
| Decision 12: `exp` bounds the mint, not the session | 5, 9 (exp checked at each request; the session clock is `auth_time`) |
| Design §17 `/v1/config` issuer and client id | 10 |
| Design §17 "no API keys": tokens and certificates only | 9 (a bearer is a provider-signed token, never a port49 secret) |
| §14 "`/v1/logout` succeeds with a valid logout token and no caller rights" | 12 (`TestALogoutBySidEndsThatSession`) |
| §15: a register row for the logout token a provider sends; hosted providers open | 1, 15, 16 |
| Decision 16: a person never in the machine domain (Ruling 21, pre-flight C-1) | 5, 7, 16 (L46's claim sets) |
| No issuer names another's people; a logout stays in its domains (Ruling 22, C-2) | 5, 6, 7, 12 |
| §2's principal claim named, never defaulted (Ruling 23, I-6) | 1, 7 |
| A logout reaches every principal of a `sub` (Ruling 24, I-1) | 2, 7, 8, 9, 12 |
| The in-house JOSE checked against Wycheproof, a matrix and fuzzing (OR-1, M-1) | 3 |
| Every PR's operator notes | this section |

**Placeholders.** None but execution-time values: the lab's measured dates and versions, the PR
number and merge hash in Task 17, each written when it exists.

**Type consistency.** `caller` (Task 9) is what Tasks 11 to 13 read; `oidc.Assertion.Credential`
(Task 5) is what the mint stores; `store.SidKey` (Task 2) is the index key the logout (Task 12)
and the refresh (Task 11) both use; `Broker.RevokeSid` (Task 12) is Task 13's;
`RefreshSession`'s new last parameter (Task 11) is passed by every caller. After the
pre-flight: `oidc.VerifierConfig.PrincipalDomains` and `.Clients []oidc.MachineClient` (Task 5)
are what Task 7 fills from `principal_domains` and `clients`, Task 9's fixture and Task 14's
`identityCfg` build, and Task 14's start lines print; `oidc.LogoutToken.Domains` (Task 6) and
`(*oidc.Set).HumanDomains` (Task 5) are what `Broker.Logout` and `RevokeSid` filter by (Task 12);
`store.OIDCOwner{Principals []OwnerPrincipal}` with `Entry` and `Names` (Task 8) is what
`noteOwner` (Task 9) and `Logout` (Task 12) read; `RevokeReport.Principals` (Task 12) feeds
`decision.Revocation.Principals` (Task 2); `oidc.KeyFileName` (Task 4) is what Task 7's
collision lists and Task 14's `keyFile` name; `config.BrokerStateDir` (Task 7) is Task 14's
`brokerStateDir`; the handlers' `asker` (Task 9) is Task 13's.

**Review Focus.** Each of the eight has its test in the owning task, named in the section.
