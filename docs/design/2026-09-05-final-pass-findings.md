# port49 — Final cold-read findings

**Date:** 2026-09-05
**Read:** design doc (all 19 sections), policy engine spec (all 15 sections), deep-review findings, spec-review findings, Junos SRX lab results rev 8, README.
**Rule applied:** anything cited to an open lab entry (L1–L10) or marked provisional is not flagged. Anything the deep review marks resolved is not re-raised unless the resolution as written is wrong or missing.

---

## 1. Verdict

Not ready for a plan as-is, but close: five blocking items, each fixable in one editing session without reopening a §13 decision. The blockers are one deep-review resolution (A1, API authorization) that was agreed but never written into either document, one security contradiction (the mint record and traces carry the token handle while §5.7 forbids tokens in the log), one mechanism that cannot be built as described (the Junos projection silently widens permit-only roles), one design-level mechanism with no spec representation (the staleness ceiling), and one security-semantics ambiguity (the range of universal subjects versus the offboarding command). Everything else is stale text or an implementer trap.

---

## Status

| Item | Status |
|---|---|
| F1 | resolved 2026-09-06 — `api:` rights on the subject, default self-only; spec §2, design §17 |
| F2 | resolved 2026-09-06 — `token_sha256` in mint records and spans; spec §5.7, design §15 |
| F3 | resolved 2026-09-05 — decision 22, provisional on L12 |
| F4 | resolved 2026-09-06 — `refreshed_at`, teardown row 3a, `context_stale`, `staleness_ceiling` named |
| F5 | resolved 2026-09-06 — universal subjects **removed**; `attached_roles` on scopes, split by trust domain (decision 18 superseded) |
| S1–S12, S14–S16 | resolved 2026-09-06 as recommended, except S3: `device_mismatch` is **kept** via a keyed device tag in the token (design §8), Ryan's proposal |
| S13 | **open** — quarantine refusal shape (FAIL vs silence); deferred by Ryan |
| Noted | resolved 2026-09-06 except the two folded into S13 |

**F5 as resolved.** Ryan's objection to any subject-shaped form: `all_humans` will be read as
"everyone" and overused. Replaced by `attached_roles: {humans: [...], machines: [...]}` on a
scope — every grant reaching a device in the scope also carries those roles; nothing creates
access; a principal with no declared grant on the device is refused. `grants remove
--subject` also removes the emptied subject block; CI reports grant-less subjects.

**S3 as resolved.** Token = `tag ‖ secret`, `tag = base62(HMAC(k, device_id))[:6]` with the
key broker and daemons already share, 24 random characters after it. A daemon compares its
own tag before any store access, so a wrong-device presentation is `device_mismatch` with
certainty under PAP, ASCII, and HTTP APIs; CHAP still yields `token_not_found`.

---

## 2. Blocking

### F1. The broker API authorization model was agreed and never written

- **Where:** design §17 "Surface" and "Requirements"; spec §2. Deep review A1 resolution: *"Agreed by Ryan: default self-only, overridden per subject. To be written into design §17 and spec §2 with the cluster A edits."*
- **Quoted text as it stands:** design §17: `POST /v1/tokens/revoke   by handle, principal, or OIDC sid` and `POST /v1/explain   a hypothetical decision, without minting`. Spec §12: *"rendering the secret itself is a separately-authorized operation"*. Neither document contains `api:`, "self-only", or any statement of who may revoke, explain, sync, or render a key for someone other than themselves (grep: no hits).
- **What breaks, for whom:** as written, any principal who can complete an SSO login can `POST /v1/tokens/revoke {"principal": "alice@example.com"}` and tear down Alice's live router sessions mid-change. That is the exact outcome A1 identified, and the deep review marks it resolved. Design §19 step 7 lists "the API authorization model" as work to build, but there is nothing to build from.
- **Fix:** write the agreed resolution: an `api:` list on a subject (`revoke_others`, `explain_others`, `sync`, `keys_show`, `replay`), default self-only, `/v1/logout` exempt because it authenticates by `logout_token` signature, CI reports every subject that crosses. One paragraph in spec §2 and one requirement in design §17.

### F2. The mint record and traces carry the token handle, which §5.7 forbids

- **Where:** spec §5.7 "Correlation"; design §15 "Tracing".
- **Quoted:** spec §5.7: *"A `mint` record carries the token handle instead, since context does not exist yet; the daemon's redemption record joins the two."* Design §15: *"joined after the fact by `ctx_id` and token handle carried as span attributes."* Against spec §5.7 "Credentials never appear": *"The log MUST NOT contain a token, a password, a CHAP challenge or response, or any value from which a credential can be recovered."* And spec §2: *"`token` versus `handle`. The same thing."*
- **What breaks, for whom:** an implementer following the correlation paragraph writes live tokens, valid for up to `token_ttl` (900s in every example), into a log stream the design says is shipped and retained, and into sampled traces. Anyone with log-read access can log into any device a batch mint targeted.
- **Fix:** the mint record and span carry `token_sha256` per minted token; the `redeem` record carries the same hash beside `credential_sha256` (they differ under CHAP). Two sentence edits.

### F3. The Junos projection silently widens any role whose permits are narrower than its privilege level's capability

- **Where:** spec §8 "The projection model"; spec §6 "Abstract levels".
- **Quoted:** spec §8: *"Permits competing with no deny need no regex at all; the capability bits already cover them. That is why the wire payload stays small by construction."* Spec §6: *"`read_only_limited` differs from `readonly` in which commands port49 permits, not in what the device needs to be told."*
- **What breaks, for whom:** on a command-authorizing platform the per-command path carries the difference. On Junos there is no per-command path, so the projection is the only carrier, and the model as written emits nothing for a permit-only role: `read_only_limited` (`show version`, `show interfaces **`, `show ip route **`) renders as an empty wire and the effective set is the whole `view` capability. `explain` would report `class ∩ wire` with `wire` empty. The differential test in step 5 would catch it, but the plan needs the rendering rule before that step, and the spec has none for this shape. The lab file's own "working model" (broad deny baseline plus narrow `allow-commands` exceptions) handles exactly this shape; the spec's model (capability plus explicit denies plus dominating permits) handles the deny-beneath-a-permit shape instead. Because Junos lets any permit regex beat any deny regex, no single rendering handles both, and the spec does not say which shapes it refuses.
- **Fix:** state the per-role rendering rule and the refused shape. The minimal statement: a role with no explicit denies renders as a `.*` deny baseline plus `allow-commands` for every permit (every permit dominates `**`); a role with explicit denies renders under the capability model; a role whose permits are narrower than its level's capability *and* which carries denies beneath a permit is refused at load with the reason named. CI reports which model each role rendered under. This is a clarification of decision 4.3's resolution, not a new decision.

**Resolution (2026-09-05).** Ryan's call: trust the SRX experience, verify in containerlab
before the generator is final; and use Junos permission bits as the primary carrier, as
their fleet does (`local-user-name` template for most, `user-permissions` sent directly for
some). Written as spec §13 decision 22, *provisional on L12*: bits first (smallest covering
set within the level's ceiling, a bit dropped where a deny aligns with it — the realistic
readonly is `view view-configuration` plus a short `deny-commands`), regexes only for what
bits cannot separate; the narrow shape renders as `deny .*` plus one allow; the mixed shape
is refused at load. Adapter gains `bits:` (reach per bit, in rule form), `privilege:` as a
bit ceiling per level, and `bit_delivery: user_permissions | local_user_name`. The Junos
docs' `-regexps` family with deny-precedence is noted as a possible lift of the refused
shape, unmeasured. §8 rewritten, §6 cross-reference added, §14 assertion added, L12 added,
design §19 step 5 cites L12.

### F4. The staleness ceiling is a design-document mechanism with no representation in the spec

- **Where:** design §9 "Directory unavailable", design §12 failure matrix and "Consequences"; spec §5.1.1 context shape, §5.6 teardown table, §5.7 reason table.
- **Quoted:** design §9: *"Serve stale context up to a hard staleness ceiling, alarming throughout, then fail closed. The ceiling is a security parameter and MUST be explicit configuration."* Design §12: *"Broker unavailable … ⚠ unaffected within the staleness ceiling; ✗ beyond it."* Spec §5.8 even relies on it: *"let the staleness ceiling deny it later."* But the §5.1.1 context shape has no `refreshed_at` or equivalent, the §5.6 teardown table (rows 1–7) has no staleness row, and the reason-code table has no code for a context denied for staleness.
- **What breaks, for whom:** an implementer building the daemon from the spec (which is what it is for) has no field to compare, no rule to apply, and no reason to emit. The failure matrix's "✗ beyond it" is then false, and revocation-during-broker-outage is unbounded, which is the property design §12 says is deliberate. Operationally, when it does fire the operator sees a denial with no code and no `server_msg` guidance.
- **Fix:** add `refreshed_at` to the context shape (the broker writes it on every refresh), a teardown row at the appropriate authority (local, like row 3), a reason code (`context_stale`), the operator-facing `server_msg`, and name the config key. Keep the design's semantics; only the spec is missing them.

### F5. Universal subjects: "matched by some non-universal subject" is not "everyone who already has access", and offboarding leaves the subject behind

- **Where:** spec §5.5 "Universal subjects name their trust domain"; §13 decision 18; §12 "Access review".
- **Quoted:** §5.5 table: *"`all_humans` — every human principal that some non-universal subject also matches."* Decision 18: *"Universal subjects range over principals some ordinary subject already matches … everyone who already has access."* §12: *"`port49 grants remove --subject <name>` produces the pull request that deletes them all. … these two commands are the offboarding path for machine subjects and literal identities."*
- **What breaks, for whom:** a subject *matches* a principal whether or not it carries any grant. So a machine subject offboarded by `grants remove --subject` still matches its principal, and any permit-carrying grant to `all_machines` (the "baseline `show version`" case §5.5 endorses) still mints for it on every device in that grant's scope. Decision 18's claim *"a principal no subject matches cannot mint"* is true but does not cover this: the principal is matched, by a grant-less subject. The same gap widens scope for live subjects: `noc_tier1` with grants only on `dc_fabric` receives `all_humans` permits on `all_devices`. Whether that second case is intended is a policy question; the first case is an offboarding hole.
- **Fix:** define the range as principals holding at least one *grant* through a non-universal subject, and say whether the grant must select the device being minted for (recommended: yes, since that is what "already has access" means). Have `grants remove --subject` also propose removing the subject block, or have CI report grant-less subjects. Update the §14 universal-subject assertion.

---

## 3. Should fix

### S1. The store hard timeout is incompatible with the recommended store topology
Design §12: *"Hard timeouts (~50ms) on all store operations."* Design §13: *"Single global store (recommended default) … Cross-region latency on every cache miss."* A cross-region round trip is commonly 60–150ms; every redemption is uncached by rule. In the recommended default, a region without the store cannot redeem a token at all once the breaker opens. State the timeout as a deployment parameter sized to observed store RTT, and say in §13 that a global store implies a per-region timeout above that RTT.

### S2. The reason-code table is not closed, and the event count is stale
- `grants_matched` appears in the §5.7 mint example (`"reason": "grants_matched"`) and is not in the table.
- `denied_by_policy` (§5.2: *"`context_missing` is operationally very different from `denied_by_policy`"*) is a name the table does not contain; the policy denials are `no_rule_matched` and `no_permit_dominates_deny`.
- `credential_revoked` is in the table but cannot be emitted: §5.6 row 2 *deletes* context on revocation, so the next command is `context_missing`. Either revocation marks context revoked (retained, like the ceiling's grace window) and the code fires with a `server_msg` saying so, or the code goes. As written a revoked operator is indistinguishable from a locally-authenticated session in the alarm §5.7 says must be separately alertable.
- No success reason exists for `authorize_session`, `escalate`, or `mint`, yet design §15 exports *"decisions by event, verdict, and reason, using the same closed vocabulary as the log"*.
- The mint-time cross-domain username collision (§2: *"the broker checks at mint and refuses the later claimant with a reason naming both"*) has no code.
- §5.7 *"Device accounting shares this envelope as a sixth event"* — with `blob` in the table above it, `account` is the seventh.

### S3. `device_mismatch` cannot be observed under `(nas, username)` keying, and design §8 still calls it a high-signal event
Design §8 "Token format": *"Device binding becomes structural rather than a post-lookup comparison."* Design §8 "Device binding": *"Rejection on device mismatch is a high-signal detection event — it does not fire during normal operation."* And *"The receipt is also what makes device-mismatch rejection the high-signal detection event."* A token minted for A and presented from B is looked up under `(B, username)` and is simply absent, which is `token_not_found`. The daemon cannot tell the cases apart without a cross-NAS index. Either drop the reason code and the detection claim (recommended; single-use and binding still hold), or add a store index by token hash for the PAP/ASCII case and say CHAP presentations cannot be classified.

### S4. §5.3's evaluation pseudocode omits three checks the reason table requires
The flow lists only `context_missing`, rule matching, dominance, and pipe stages. The username binding (`username_mismatch`, §5.6 row 4), the session ceiling (`session_expired`), and the granted level (`privilege_exceeded`) are all daemon checks on the same path and are absent. An implementer coding from §5.3 ships without them. Add them, in order, before rule matching.

### S5. Where session attributes live, and who substitutes `{username}`
Spec §5.2: *"the daemon returns the AV pairs already stored in login context."* Spec §5.1.1: context holds *"the hash rather than a copy"*; attributes are in the blob. Design §9: *"Vendor attributes are rendered by the broker at mint … and written into login context."* Spec §6: values support `{username}`, `{principal}`, `{device}` substitution. A blob is one per platform and shared across users, so substitution must happen at redemption, in the daemon, from the token record's username and principal, and the rendered list either lives in context or is rendered per request. Say which; fix §5.2 and design §9 to match §5.1.1.

### S6. Enable-token redemption on `$enab{level}$` platforms has no lookup path
Tokens are keyed `(nas, username)`; the enable START carries `$enab15$`. The daemon must resolve `(nas, port)` → context → bound username → candidate set → `kind: enable`. Nothing states this. It also means an enable token is unredeemable on a line port49 did not authenticate, which is correct and worth saying. One paragraph in §7.

### S7. Username normalization is a key transformation, not a comparison, and §2 names the wrong reason
Spec §2: *"the daemon compares case-insensitively after stripping a domain prefix or UPN suffix. Without this, a user who types their address rather than their shortname is denied with `context_missing`."* The first failure is at redemption, where the store key `(nas, username)` must be canonicalized before lookup, and the code would be `token_not_found`. State that the broker writes the canonical form and the daemon canonicalizes the wire username before every store access.

### S8. Sequencing: step 3 borrows from steps 4–6, and three lab entries close nowhere
Design §19 step 3 needs a device admission snapshot and key group (file inventory, step 6), blob write and read (step 4), one platform's session attributes (step 5), and a store reachable by two processes (step 1's in-memory store is in-process). Say what the slice borrows. Step 2 builds reusable tokens, which decision 15 makes provisional on L7, and L7 closes in step 3. L3 (enable `rem_addr`), L5 (WATCHDOG), and L6 (accounting timing) are assigned to no step. The preamble's *"an engine built ahead of that evidence is built against a guess"* is violated by the document's own order.

### S9. Three Junos statements disagree with the lab file
- Spec §6 "Validation without semantics": *"A generated `deny-commands` regex (§8) will exceed this before anything else does, and it fails as a truncated or dropped attribute rather than a clean error."* The lab: silent truncation and silent drop *"are not reachable"*; the encoder cannot emit the argument. Reword to the encoder-level refusal §8 already states.
- Spec §8 under "Measured target behavior": *"Broad capability comes from the login class's `permissions` bits, not from a permit regex."* Rev 8 of the lab file contains no `permissions` measurement. It is a documented Junos property, not a measured one; cite it as such or add a register row.
- Spec §8: *"Starting on the wire means zero device provisioning."* Junos `local-user-name` maps to a template user whose login class must exist on the device, and the model itself depends on that class's `permissions`. Provisioning is not zero; it is one class per privilege level, which `platform export` already produces.

### S10. The certificate-path refresh cannot be a TLS re-authentication, and `auth_time` there is necessarily broker-stamped
Spec §5.6: *"on the certificate path performs a new proof-of-possession challenge. The broker never sets `auth_time` from its own clock."* Decision 17 makes the session a held TLS 1.3 connection. TLS 1.3 has no renegotiation and Go's `crypto/tls` does not implement post-handshake client authentication, so the challenge must be an application-level signed nonce over the held connection, and the only time available is the broker's verification time. State that, and narrow the "never from its own clock" rule to the OIDC path. Also name which endpoint `port49 login` calls at refresh; design §17 lists `/v1/refresh` and the §5.6 trace never mentions it.

### S11. The principal string per verifier is not defined
Spec §2 requires policy strings in the forms `user:alice@example.com`, `spiffe://…`, `system:serviceaccount:…`, `app:<client_id>`. Runtime examples (§5.1.1, §5.7) show `alice@example.com` with no prefix. Nothing says what a human x509 principal is (the mapping attribute?), what a workload certificate yields (SAN URI?), which OIDC claim becomes `app:<client_id>`, or whether the runtime string carries the prefix. The subject matcher cannot be written without this. Also §5.1.4 `credential.method cert | oidc` has no value for the Kubernetes verifier.

### S12. Stale lifetimes in the design document
Design §6 taxonomy: blob lives *"store, slightly beyond max `token_ttl`"* — decision 19 replaced this with the longest referencing context. Design §8 table: device token *"30–600s"* while every example uses `900s` and design §17 requests `ttl_seconds: 900`; an implementer clamping at 600 would break the examples.

### S13. Quarantine at 3am: what shape does the refusal take?
Spec §10: *"the daemon refuses it with `device_quarantined`."* If the daemon answers FAIL, correct reference configuration prevents local fallback and the operator is locked to console. If it drops the connection as for `device_unknown`, the device declares the server dead and falls to local. State which (recommended: the `device_unknown` shape), and that the clearing path is the policy change CI names plus the next sync. The `quarantined` column A11 asked for is absent from the §9 `devices capabilities` example.

### S14. `max_session_age` composition and transport
It is *"declared per role"*; a principal holds several roles. Min or max is unstated (recommend min). It must reach the daemon to compute `session_expires` at redemption, but the §5.1.2 blob example does not carry it and the token record is elided. On refresh, a new OIDC assertion carries a new `sid`; nothing says `contexts_by_sid` is re-indexed, so a later back-channel logout for the new session would miss the context.

### S15. The default pipe allowlist contains a literal that cannot match
Spec §4: `pipe: permit: [include **, exclude **, begin **, section **, json, count, no_more]`. Devices send `no-more`; the vector is compared literally. `no_more` never matches and the modifier fails closed everywhere. Snake_case applies to config keys, not to CLI literals.

### S16. "Principal names" where "device-facing usernames" is meant
Spec §5.6: *"Local account names MUST NOT collide with principal names. A device-local `bob` that is not the port49 principal `bob`…"* The colliding string is the username (§2 makes the two distinct and both load-bearing). Same slip in the reference-configuration requirement that follows.

---

## 4. Noted

- README: *"Not yet licensed"* while design §18 records Apache-2.0 as decided.
- Design §7 verifier lists use `client_id` for humans and `audience` for machines; both are the `aud` check. Say why the key differs or use one.
- `reusable` is absent from the design §6 subject row ("`token_ttl`, `enable`, `username`") and the spec §2 subject fields; design §1 and §6 still say "single-use" unconditionally.
- Design §12 matrix "Token store unavailable → New session ✗": nothing in §7's login path touches the store; probably ✓, as the daemons-unavailable row already says.
- Spec §8 `juniper_junos` example has no `privilege:` block though the field table says it is required always.
- Spec §8 `redact` is "if `commands`", but session-only platforms send command accounting too.
- Spec §10 inventory YAML `token: ${NETBOX_TOKEN}` versus the `secret_ref:` convention used for keys.
- Spec §10: *"CI MUST refuse a policy whose `accept` set is empty"* while `current` sits outside `accept`; say whether `current` is implicitly accepted.
- Design §12 record table: the broker also deletes tokens (`/v1/tokens/revoke`), and revoke-by-handle needs a handle→`(nas, username)` path the store does not provide.
- Spec §5.1.3 scheduled refresh must enumerate principals with live contexts; `contexts_by_principal` is keyed by principal, so that is a keyspace scan or a missing `active_principals` set.
- Spec §10: *"the body within the 4096-byte bound RFC 8907 sets"* — I could not find such a bound in RFC 8907 §4.1; if it is an implementation limit, say so, and note ASCII CONTINUE `user_msg` may be up to 65535.
- Idle TTL has no default named; with `max_session_age: never` it is the only bound.
- Design §17 API uses `status: ok | denied`; the log uses `permit | deny`; §17 says they are the same vocabulary.
- An OIDC-only deployment with no directory (the "PKI-less adoption" target) can use only literal-identity subjects, since groups are never taken from the credential. Worth one sentence in §7 or §10.
- Design §8 heading "Per-account TTL"; the object is a subject.
- Design §7 says the broker validates the chain *"then challenges the agent to prove possession"*; with mTLS the handshake already is the proof. Say whether the extra challenge exists at login or only at refresh (S10).

---

## 5. Checked and clean

- Every `§N` cross-reference between and within both documents resolves to the section that says what the citer claims (design §5–§19 and spec §1–§15 spot-checked exhaustively, including §5.1.1–§5.1.4, §5.6–§5.8, §13 decision sub-references).
- Every `L<N>` reference resolves; L11 is closed with a pointer to the lab file; the four claims in spec §5.6 "Gated on the lab" cite L1, L2, L3, L4 correctly; design §19's step-to-entry assignments name real entries.
- "Decision 2" and "decision 15" references resolve; "step 5" and "step 21" (rotation day) resolve.
- No camelCase in any YAML or JSON key in either document.
- Trust domain (decision 16): no runtime path infers domain from a string; the k8s identity is derived by its verifier; CI's load-time classification by string form is exactly what decision 16 permits.
- Reusable tokens (decision 15): the skipped paths are stated (match-only, no receipt, binding unchanged, no use counter); the context-key question is explicitly provisional on L1.
- Session-only platforms (decision 21): the controls that do not reach (revocation, ceiling, warning, username binding) are consistent across spec §5.6, decision 21, and design §9 "Reach"; the negative §14 assertion exists.
- Quarantine (decision 20): the remaining "refuse" statements (bounded change, address collision, over-shrinking snapshot) are the cases that should still refuse; joint validation says quarantine in §10, §5.7, §13, §14, and design §19.
- Store record table (design §12): every store operation named anywhere (token set, receipt, context, blob, three indexes, idempotency, failure counters) has a row; the remove-and-write atomicity claim matches between design §8 and §12; the encryption key is stated as shared by broker and daemon; the idempotency record is marked encrypted.
- Session refresh (decision 17): the OIDC-path trace agrees between spec §5.6 and design §7 (`prompt=login`, `auth_time` from the assertion, 12h default, grace window, refresh re-resolves policy).
- 240/255 byte budget, one argument per name, `allow-commands` versus `allow-commands-regexps` exclusivity, both attribute types on both channels, precedence matrix: consistent with the lab file.
- Deep-review cluster B items B1, B2, B5–B14, B16–B20 are present in the text as resolved. B4 and B15 are the partial ones (S2).
- Event vocabulary: five decision events plus `account` and `blob` agree between the §5.7 table and §14.
- Universal-subject CI reporting and the §14 assertions agree with §5.5 as written (the disagreement is with decision 18's intent, F5).
