# Plan roadmap

One plan per design §19 step group, written one at a time (see `CLAUDE.md`). This file is
the standing brief for each plan: what it builds, which spec sections it implements, what
earlier plans hand it, what it must leave for later, and which lab register entries close in
it. When writing plan N, start here, then read the cited sections, then the previous plan.

Status: **1 and 2 written**; 3–12 not yet. Plan 3 waits for plan 1's lab results.

---

## Plan 1 — Protocol core (§19 step 1) — `2026-09-06-01-protocol-core.md`

RFC 8907 wire, key trial, admission from a file inventory, per-source limits, in-memory
store, authentication/authorization/accounting handlers, decision log, config, `port49d`
binary, containerlab harness. Closes L1 (SSH transport only), L2, L5, L6, L8, L10.

## Plan 2 — Token model (§19 step 2) — `2026-09-06-02-token-model.md`

**Not executable as written.** It assumes the `(nas, port)` login-context key, which the lab
showed breaks every measured vendor; the key is now `(nas, username)` (spec §13 decision 15).
Rewrite it against `2026-09-20-plan-2-revision-notes.md` first. One item there, whether
`contexts_by_principal` may stay unencrypted now that its ref carries a username, is the
owner's security call.

**Builds:** the full token semantics on top of plan 1's store interface and handlers.

- Token format with the **device tag**: `tag ‖ secret`, `tag = base62(HMAC(k, device_id))[:6]`,
  24 random characters; daemon compares its own tag before any store access; `device_mismatch`
  under PAP/ASCII/HTTP, `token_not_found` under CHAP. Design §8 "Device binding".
- **Encryption at rest** for tokens, receipts, login context, and the idempotency record,
  with a key shared by broker and daemon and a two-key rotation window. Design §8.
- **Reusable tokens**: `reusable: true` on the subject, match-only redemption, no receipt,
  valid until TTL. Spec §13 decision 15 (provisional on L1, L7).
- **Enable tokens**: mint pair with `kind`, lookup on `$enab{level}$` platforms through
  `(nas, port)` → context → bound username → candidate set filtered to `kind: enable`;
  `token_kind_mismatch`; `enable: none | auto | token`; `enable: auto` refused at load where
  `enable_username` is not `principal`; `rem_addr` binding on enable. Spec §7, §5.6.
- **Candidate-set cap** (order of eight) refusing the mint, never the redemption. Design §8.
- **Full store record set**: `blob`, `contexts_by_principal`, `contexts_by_sid`,
  `contexts_by_cert`, `active_principals`, idempotency record, failure counters; atomic
  remove-and-write-receipt; the race loser reads the receipt and answers PASS. Design §12.
- **Login context in full**: the §5.1.1 shape (`refreshed_at`, `revoked_at`, `auth_time`,
  `session_expires`, `task_id`, `accounting_state`), teardown rows 1–7 including 3a
  (staleness) and the checks in the §5.3 pseudocode (username, revoked, expired, stale,
  privilege). Accounting annotation: `task_id` binding, `closing`, `foreign_session`. Spec
  §5.1.1, §5.3, §5.6, §5.8.
- A **mint function** callable in-process (no broker yet) that plan 3's minimal broker wraps.
- **`context_idle_ttl` is absolute, not idle.** Plan 1 sets it at `PutContext` and never
  extends it; `GetContext` does not touch it. Spec §5.6 says activity SHOULD extend it, so
  either the refresh happens here or the key is renamed to say what it does. Plan 2 owns the
  context shape, so it is named here.

**Hands to plan 3:** `token.Mint(device, username, kind, ttl, reusable)`, the encrypted store
records, the context refresh entry points.
**Leaves for later:** the broker API and its authorization (plan 7); blobs' compiled content
(plan 4, the engine produces them; plan 2 stores opaque bytes by hash).
**Lab:** none close here; L8 (password length) may need re-checking with the 30-character
tagged token.

## Plan 3 — Vertical slice (§19 step 3)

**Builds:** the first real identity reaching a real device with no shared password.

- A **minimal broker**: x509 client-certificate validation against one trust anchor over a
  **held mTLS connection**, literal-identity subjects, a file-backed policy with roles and
  grants and no scopes beyond `all_devices`, mint via plan 2, `/v1/tokens` and `/v1/config`
  only. Design §7 (certificate path), §17 "Minting", spec §13 decision 17.
- The **agent** `port49 login` and `port49 token` commands over that connection. Design §8
  "Two credentials, two lifetimes".
- **Borrowed ahead in simplest form** (say so in the plan): a hand-written admission snapshot
  and key group (plan 6), one blob written and read (plan 4), one platform's session
  attributes (plan 5).
- **eAPI / NX-API per-request authentication** measured in the lab with reusable tokens.
  Images for this are on hand (plan 1 Task 15 lists them with their vrnetlab kinds): Nexus
  9300v 10.4(2)F for NX-API and the L7 question; Catalyst 9000v 17.12 and C8000v 17.13 for
  IOS-XE, where the `$enab15$` enable path (L3) lives; vEOS 4.32.2F for eAPI.

**Lab:** closes L3 (enable `rem_addr`), L4 (fall-through on FAIL per platform, Junos
`authentication-order`), L7 (eAPI/NX-API per-request AAA), and the API-transport half of L1.
Decision 15 stops being provisional here. **Do not write this plan before plan 1's lab
results exist.**

## Plan 4 — Policy engine (§19 step 4)

Spec §3 (normalization), §4 (grammar, pipeline stages), §5.1–§5.5 (mint resolution, blob
compilation, refresh, credential identity, scopes and `attached_roles`, version comparison),
§5.4 (dominance), §5.7 (decision log in full, replay), §6 (privilege levels, attribute
layering, substitution at session authorization), §11 (the complete example as a test
corpus), §12 (`explain`, policy tests, access review, `grants remove --subject`), §14
"Matching and precedence" and "Decision log" assertions. Replaces plan 1's `author.Lab`
with the real `Authorizer`. Produces the compiled blob plan 2 stores.

**The accounting spool needs a sink that can fail.** Plan 1's at-least-once guarantee ends at
`decision.Emitter.Emit`, which returns nothing: the spool deletes its `.draining` file whether
or not the sink took the records. With stdout as the sink that is academic. Whichever plan
first gives the decision log a real sink — this one owns the log in full, but it travels with
the sink if it lands later — must give the spool a sink interface that returns an error, and
the spool must not advance `drainOffset` past a refusal. Without both, the durability contract
is enforced up to the last hop and not across it.

## Plan 5 — Platform adapters (§19 step 5)

Spec §8 in full: built-in adapters, entity classes, user overrides and layering, pinned
platform set, `redact` patterns (accounting redaction was deferred from plan 1 and MUST land
here), `capability`/`bits`/`bit_delivery`, the **Junos projection** under decision 22
(bits first, regexes second, refused shape), differential testing in containerlab,
`port49 platform export`. Spec §9 capability inference. **Lab:** L9, L11 (closed), L12; the
projection generator is not final until L12 closes.

**Inherits from plan 1:** every Junos login is answered `service_unsupported` on its session
authorization. `author.Handle` requires `service=shell` and L10 measured Junos sending
`service=junos-exec`, so plan 1 denies it by design — logins still work (the L10 notes show
it), but the decision log carries an `authorize_session` deny for each one. The adapter that
maps `junos-exec` is this plan; until it lands, that deny is expected and is not a finding.

## Plan 6 — Inventory service (§19 step 6)

Spec §10: file inventory in full, NetBox and Nautobot connectors, the versioned bundle,
`bundle/diff`, bounded-change safety, **quarantine** (silence, not FAIL — decision 20),
admission snapshot refresh in the daemon, key rotation reporting (`keys status`,
`keys diagnose`, unvalidated-source report), device records, address-added-as-security-event.
Design §10 "Device inventory".

## Plan 7 — Broker in full (§19 step 7)

Design §7 (OIDC public client with PKCE, certificate-to-directory mapping, directory
integration, trust domain by verifier lists), §10 (server pool, pre-warm, grace, replication
lag), §17 (the whole API surface, idempotency, batch mint, **`api:` rights** default
self-only, `/v1/refresh` with `prompt=login` and the cert-path signed-nonce refresh,
`/v1/logout` back-channel), spec §5.1.3 (scheduled refresh through `active_principals`),
§5.1.4 (revocation by `sid`, `sub`, CRL/OCSP), §5.6 session lifetime (ceiling warning,
grace window, `max_session_age` minimum across roles), the staleness ceiling end to end.

## Plan 8 — Workload certificates (§19 step 8)

Design §7 "Machine identity" option 2: enrollment, self-renewal, multi-identity subjects,
`username` declared on machine subjects, cross-domain username collision at mint. Unattended
config backup (Oxidized) as the day-one consumer.

## Plan 9 — Agent in full (§19 step 9)

`port49 ssh` with host-key verification and `port49 devices trust`, the OIDC public client,
the in-session re-auth flow, integration examples (design §17 "Integration examples").

## Plan 10 — Kubernetes path (§19 step 10)

Projected ServiceAccount token validation against the cluster JWKS; identity
`system:serviceaccount:<ns>:<name>`; the `k8s` verifier type. Design §7.

## Plan 11 — RFC 9887 TLS listener (§19 step 11)

Separate listener on 300, mutual TLS replacing the shared key, device records expressing
both. Design §11.

## Plan 12 — Deployment (§19 step 12)

Deployment artifacts, the **reference device AAA configuration per platform** (the thing that
disables fall-through on FAIL, design §12), load validation at the §5 target rate, the
failure-matrix tests of design §12 and §14, observability alarms with a metric behind each
(design §15).

Carried here from plan 1's review:

- **A global connection cap.** Today the only one is `EMFILE`, which is the worst possible
  cap: it fails `Accept` for admitted devices too, and it fails the spool's own `OpenFile`, so
  accounting starts answering ERROR. Plan 1 pulled forward the two cheap parts — the
  `accept_error` counter and log, and a 5s header deadline for a source that is not admitted.
  The cap itself, its sizing, and its alarm are this plan's.
- **Accounting throughput is bounded by one disk's fsync latency.** `Offer` holds one mutex
  across a `stat`, an open, a write, an fsync and a close, per record, for the whole fleet.
  The fix is a group commit — batch concurrent offers into one fsync — and it needs this
  plan's load numbers to size. Do not change it before there are numbers.
- **`key_validations_total{key_ref}` is a device-identity label in one deployment shape.** Key
  groups make `key_ref` a fleet-wide label with a handful of values, which is what the
  cardinality rule assumes. A deployment that pins a key per device (the tier-1 pin) turns it
  into one series per device — both a cardinality problem and, against design §15's "device
  identity never appears in metric labels", a correctness one. Say which it is and bound it
  when the alarms are written.

---

Plans 8–11 are small and may be merged into a neighbour when written. Renumber nothing;
leave a gap and say why in this file.
