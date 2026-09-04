# port49 — Spec review findings

**Date:** 2026-08-26
**Reviews:** [`2026-08-21-port49-design.md`](2026-08-21-port49-design.md),
[`2026-08-23-policy-engine-spec.md`](2026-08-23-policy-engine-spec.md)

Independent review of both design documents. Findings verified before recording; several are
errors introduced during the design session rather than reviewer speculation.

## Status

| Item | State |
|---|---|
| Cluster 1 — token and login-context data flow | **resolved** |
| Cluster 2 — matcher determinism | **resolved** |
| Cluster 3 — the CHAP consequence | **resolved** |
| Cluster 4 — remaining blocking issues | **resolved** |
| Inconsistencies — nine items of stale text | **resolved** |
| Architecture recommendations | open |
| Gaps — accounting resolved; key rotation and the mint API next | open |

Clusters are ordered by severity; cluster 1 is the core data flow of the product. Resolved
sections keep their original finding text beneath the resolution note.

---

## Cluster 1 — token and login-context data flow

> **Resolved.** Policy engine spec §5.1.1, §5.1.2, §5.6 and design document §8, §9.
Commits `8320715`, `f4ad48e`, `6d5189e`, `f4f579f`.

- **1.1** — the broker writes an immutable, content-addressed policy blob referenced by the
  token; the daemon creates login context on redemption holding the blob hash. Batch mints
  collapse to one blob per platform. The daemon maintains a `contexts_by_principal` index so
  the broker can find live contexts to refresh, which also makes policy-driven revocation
  reach active logins.
- **1.2** — context is created only on redemption and torn down by a later redemption, by an
  authentication START on the same line under a different username (including a rejected
  one), by exec accounting, or by TTL. Username and `rem_addr` are recorded and compared.
  Because method lists fall through only on ERROR, `enable: auto` is now a policy load error
  on platforms whose enable exchange does not carry a verifiable username. TTL is demoted to
  a backstop and lengthened to session lifetime.
- **1.3** — the receipt binds a hash of the **presented credential**, not `(nas, port, user)`
  alone. A CHAP re-prompt correctly fails rather than replaying.

### As reported

**1.1 Session context cannot be created at mint.** Spec §5.1 has the broker writing session
context as a precomputed value, but context is keyed on `(nas, port)` and the port — the
device's tty/vty string — does not exist until the device sends the authentication START. The
broker cannot know it.

The coherent flow is unstated: the broker writes the resolved payload into the **token
record**; the daemon copies it into `(nas, port)` context on successful redemption.

Related: design §6 says the broker performs background refresh of live session contexts, but
nothing defines how the broker discovers which contexts are live. Needs a mechanism (store
scan, or a daemon-published index).

**1.2 Session-context lifecycle is undefined, and the gap is an escalation path.** Nothing
says how the system learns a login has ended. Accounting START/STOP is the obvious signal and
is never mentioned for this purpose.

Concrete confused-deputy: vty lines are recycled. If a context for `(nas, vty5)` outlives its
session and another operator lands on vty5, the enable exchange arrives as `$enab15$` — which
by design cannot be verified against the context's stored username — resolves the previous
occupant's context, and under `enable: auto` ("any password accepted") escalates the new
occupant to the previous user's ceiling.

Also unresolved: unbounded refresh worsens the stale-context problem, bounded refresh kills
idle logins with `context_missing` mid-session. Neither is chosen.

Fix direction: tie context creation and teardown to the accounting task lifecycle, and
invalidate context on any new authentication for the same `(nas, port)`.

**1.3 The redemption receipt is a free pass as written.** Design §8 replays the stored decision
on an identical retry within ~30s, with the receipt keyed `(nas, port, user)` — and nothing
requires re-verifying the *presented credential*. Any authentication from the same
device/line/username inside the window therefore replays PASS with no token at all.

The receipt MUST bind to the presented credential (a hash of the token, or of the full
authentication payload) and replay only on match.

Also unspecified: a device that re-prompts generates a **fresh CHAP challenge**, so the retry
is not byte-identical. Define whether the receipt path recomputes against stored plaintext or
whether CHAP retries simply fail.

---

## Cluster 2 — matcher determinism

> **Resolved.** Policy engine spec §3, §4, §5.4 and design document §9.

- **2.1** — the vector is no longer lower-cased. Literals and entity classes compare
  case-insensitively, and regex compiles case-insensitive by default with `(?-i)` to opt
  out. Insensitive must be the default because a case-sensitive deny fails *open*. Leaving
  the vector unaltered also means accounting records what was typed.
- **2.2** — tuples are built per *command* position, with `**` contributing a zero for each
  position it absorbs. Resolution is **dominance**, a partial order: a permit applies only
  when it is ≥ every matching deny at every position and strictly greater somewhere.

  Three total orderings were tried and each failed on real policies. Lexicographic let a
  permit naming the first word beat any deny constraining a later argument, defeating
  exfiltration denies (`copy **` over `* * /^tftp:/`) and disruptive-form denies
  (`clear bgp **` over `* * all`). A sum of ranks and a run-collapsed distance metric each
  fixed some cases and broke others. The defect is common to all of them: collapsing the
  tuple to a single number forces an answer even where two rules genuinely disagree about
  which position matters. A partial order declines to rank incomparable rules, and the
  one-sided test — only the permit must prove itself — then resolves those cases safely.

  `@class` and `/re/` were also collapsed to a single rank, since neither is reliably
  narrower and an invented ordering let `interface @physical` beat
  `interface /^Ethernet1$/`.

### As reported

**2.1 Case normalization contradicts the shipped entity classes.** Spec §3 lower-cases the
command vector and states that regex terms match as written. Spec §8 then ships
`^Management[0-9]+$`, `^Loopback[0-9]+$`, `^Ethernet[0-9/.]+$`, `^Port-Channel[0-9]+$` —
patterns that can never match a lower-cased vector. So `deny: interface @management` silently
never fires, which is precisely the failure mode §4 claims to have eliminated. The design
doc's own example uses lowercase, contradicting the spec's.

Decide: class patterns match case-insensitively (likely correct, since they classify CLI
names), or lower-casing applies per term type. Then fix every example, and state the rule for
user-supplied leaf regex too.

**2.2 Specificity tuples are not defined across differing arity.** §4 ranks terms and §5.4
compares tuples lexicographically, but tuple *construction* is never defined when `**`
consumes multiple or zero positions. For `[show, bgp, summary]`, is `show **` scored `(4,0)`
or `(4,0,0)`? Does `show bgp **` beat `show * summary`? Is `show run` versus `show run **` a
tie, and therefore a deny?

Order-independence and the exactness of the CI diff both depend on this being total.
Specify scoring per **vector position**, with positions consumed by `**` scoring zero, plus an
explicit rule for zero-width `**`.

---

## Cluster 3 — the CHAP consequence

> **Resolved.** Design document §8 ("Tokens are encrypted at rest") and §12. Commit `6d5189e`.

Rather than making CHAP opt-in and accepting plaintext, **tokens are encrypted at rest** with
the key in the daemon's secret mount, alongside the RFC 8907 shared keys it already holds. A
store compromise alone yields nothing usable; rotation is trivial given sub-900s token
lifetimes. CHAP remains fully supported and conformance is intact.

Also recorded: `token_ttl` is an exposure window and not only a replay window, so batch mints
should size TTL to the sweep; the CHAP candidate set is bounded by store-enforced expiry
rather than by filtering; and match-and-delete is necessarily two steps, with the atomic
removal — not the verification — being the single-use authority.

### As reported

Keying tokens on `(nas, username)` exists to make CHAP verifiable, which requires the daemon
to read token **plaintext**. Neither document acknowledges the consequence: the token store
becomes a credential vault, and a store compromise yields live, usable credentials for every
pending token fleet-wide. Nothing is said about encryption at rest, access control, or hashing.

CHAP is genuinely rare for device login AAA. Making it **opt-in** would let handles be stored
hashed, so a store dump is worthless. At minimum the threat must be stated; better, make
plaintext storage conditional on CHAP being enabled.

Related: **atomic match-and-delete cannot be a single store primitive under CHAP** — the store
cannot compute `MD5(id ‖ secret ‖ challenge)`. The real operation is fetch-candidate-set →
daemon computes → atomic remove-if-present of the winning member, whose success is the
single-use authority. Still race-safe, but §12's interface description invites an implementer
to assume server-side matching. Spell out the two-step shape.

---

## Cluster 4 — remaining blocking issues

> **All resolved.**

- **4.1** — the device-facing username is resolved at mint from the same directory query that
  fetches groups (`sAMAccountName`, `uid`, or the OIDC `preferred_username`), and machine
  subjects declare one in policy since they have no directory entry. Usernames are unique
  across subjects and compared after case and domain normalization. Policy engine spec §2.
- **4.2** — platform data is **compiled into the blob** rather than distributed to daemons:
  the broker expands entity classes and embeds normalization parameters, so the daemon stays
  a pure executor and broker/daemon skew is impossible by construction. The governing line is
  *the bundle carries facts, the blob carries decisions*. Policy engine spec §5.1.2.

  Related: inventory, policy, and the pinned platform set are now published as **one versioned
  bundle**, which also closes the previously unspecified question of how policy reaches the
  broker. Policy engine spec §10.
- **4.3** — resolved by lab testing on an SRX rather than by design argument. Junos merges
  class and wire rules into one set, and a matching permit *regex* beats a matching deny
  regex from either origin. Broad capability comes from the class's `permissions` bits, not a
  permit regex, which is what lets denies apply cleanly beneath it.

  The 255-byte limit is a TACACS+ protocol constraint, not a Junos one — class config is not
  subject to it and was verified enforced past 255 with no truncation. So there are two
  channels: the wire (240 bytes, no provisioning, fully dynamic) and the class (unbounded,
  needs deployment and drift monitoring). **Wire-only by default; class-assisted only when the
  deny set exceeds the budget**, with CI reporting when a role crosses that line.

  Which permits are emitted follows from port49's own dominance rule: only permits that
  dominate their competing deny are safe to emit, because on the target any permit wins.

  Five generator constraints, none of which the device catches — the device validates config
  but not wire attributes, so the generator is the only validation layer. Policy engine spec
  §8.

### As reported

**4.1 The device-facing username is never defined.** Design §8 makes username binding a MUST
and the store key is `(nas, username)`, but principals are `CN=alice,OU=netops,O=example` and
`system:serviceaccount:netops:oxidized` — which nobody types at an SSH prompt. The examples log
in as `svc-config-backup`. What username does mint key the token under, and where does the
principal-to-username mapping live? This *is* the binding, and it is load-bearing for
accounting attribution.

**4.2 Platform knowledge is needed on the daemon's command path.** Design §9 states the daemon
never learns what a platform is, but normalization needs `pipe_token`, `expands_abbreviations`,
and `<cr>` handling, and matching needs entity-class regexes — all per-platform adapter data.

Either session context carries a fully compiled matcher (classes expanded, normalization
parameters embedded — then say so, and account for payload size at 170 logins/sec), or the
daemon loads platform files as a **second acknowledged cold dependency** alongside the
admission snapshot. The docs are explicit about the first exception and silent about this one.

**4.3 The 255-byte attribute limit makes Junos projection unusable.** A generated
`allow-commands`/`deny-commands` alternation exceeds 255 bytes for any realistic role. The spec
notices the limit and says "enforce at policy load" — which means the load *fails*, with no
remedy specified. Splitting across attributes, a Junos-side regexp list, or falling back to
login-class templates are the candidates. This needs a design answer, not a validator: as
written, the flagship session-only platform cannot carry a moderate role.

---

## Inconsistencies — stale text from mid-stream revisions

> **All nine resolved.** Several were corrected substantively rather than editorially — the
> failure matrix rows and the cross-region latency claim were understating real degradation,
> and the singleton claim required a new requirement to become true.
>
> 1. Both partial concept tables removed in favour of the single taxonomy in design §6.
> 2. Store-unavailable and 3. broker-unavailable rows are now `⚠` with their real conditions
>    stated — a warm cache entry, and the staleness ceiling respectively. The mitigation text
>    now says *degraded and uneven* rather than *active sessions continue*, since consecutive
>    commands in one login may land on different replicas.
> 4. The global-store row no longer claims cross-region cost is redemption-only, and the
>    p99 < 5ms target in §5 is explicitly conditional on a warm cache or same-region store.
> 5. Spec §1 no longer describes the design document's prior state; it now maps the three
>    evaluation points onto `aaa authorization exec` / `commands` / `config-commands`.
> 6. Decisions renumbered, with the two new decisions from cluster 4 appended.
> 7. The fossil test comment is replaced; all three CVE assertions now carry accurate ones.
> 8. Bare `priv-lvl` throughout, plus a new requirement that shipped attribute spellings be
>    lab-confirmed before an adapter is marked `VERIFIED`.
> 9. Local bundle persistence promoted to MUST and a shared object-store copy added, so a
>    daemon can *start* without the inventory service. Without that the singleton was a
>    startup dependency under another name.

### As reported

1. **Grant concept tables still list "level"** in both documents. Decision 3 removed
   grant-level privilege; grants carry only `max_privilege`. Actively contradicts spec §5.1.
2. **Failure matrix versus store mitigations.** "Token store unavailable → active login ✗"
   contradicts the mitigation text three paragraphs later ("active sessions continue"). Honest
   answer: continues only on replicas holding a warm cache entry for that session.
3. **"Broker unavailable → active login ✓ unaffected"** contradicts the staleness ceiling — a
   broker outage longer than the ceiling fails active sessions closed. "Unaffected" holds only
   inside the grace window.
4. **"Cross-region latency on redemption only, once per login"** is false. Session contexts
   live in the same shared store, so per-command authorization on a cache miss and every
   refresh write also cross regions. This bears directly on the p99 < 5ms target, which should
   be stated as conditional on a warm per-replica cache or a same-region store.
5. **Spec §1** claims the design document names only two evaluation points. It now names three.
6. **Decisions section numbering** runs 1, 2, 3, 4, 5, 7, 6.
7. **Stale test comment** — `svc_oxidized / show chassis hardware` is annotated "more specific
   permit beats the CVE deny," but the shipped deny is `show chassis cluster **`, which does
   not match at any position. A fossil of the earlier `show chassis *` case. Matters because
   policy examples teach semantics.
8. **`shell:priv-lvl` versus bare `priv-lvl`.** The `arista_eos` adapter uses the former; the
   Meinberg example and design §9 use the latter. In TACACS+ the shell-service REPLY attribute
   is bare `priv-lvl`; `shell:priv-lvl` is the RADIUS cisco-avpair spelling. Resolve in the
   containerlab matrix rather than by assertion — but the shipped example should not be wrong.
   (`shell:roles` genuinely is spelled that way on EOS and NX-OS.)
9. **The singleton claim versus cold start.** "The one component permitted to be a singleton,
   because nothing depends on it being up" conflicts with a new daemon replica staying unready
   until the inventory service answers, given that local persistence is only SHOULD. During an
   inventory outage you cannot add daemon capacity — no autoscale under load, no crash-loop
   recovery on fresh nodes. Either promote persistence to MUST with a shared object-store
   fallback, or soften the claim.

---

## Architecture recommendations

**Promote accounting to a first-class section.** ~~It is already load-bearing — capability
inference and the unauthorized-tier report consume it, enable attribution depends on it, and
context lifecycle (1.2) needs it — yet nothing specifies wire handling, `task_id` correlation,
delivery durability, or destination. The largest structural gap relative to the weight the
documents quietly place on it.~~

**Resolved** as two sections, §5.7 and §5.8 — see Gaps below. The reviewer's observation that
it was load-bearing turned out to be the finding: being load-bearing was itself the defect for
context lifecycle, and the fix was to unload it rather than to specify it more carefully.

**Design key rotation now.** ~~§2 names never-rotated shared secrets as a core problem, and the
`key_groups → key_ref → secret mount` scheme has no rotation story: no dual-key acceptance
during rollout, no per-device key option (the example maps `10.0.0.0/8` to one key, so
fleet-wide blast radius), no tooling. Dual-key try-both on the daemon is cheap and makes
rotation routine.~~

**Resolved.** Policy engine spec §10 ("Key rotation"), tooling in §12, decision 14 in §13,
assertions in §14, deployment and failure-model consequences in design §12 and §13.

A `key_ref` resolves to a set of versions and the daemon accepts every non-retired one, so
there is no cutover: add a version, provision devices at their own pace, retire the old one.
RFC 8907 carries no key identifier, so the daemon tries candidates and validates the
de-obfuscated body against the cleartext `length` field — reliable to about 10⁻⁶ before enum
checks. The reply must use the key that validated, not `current`, and the resolved key is
cached per connection.

The reviewer framed the gap as missing dual-key acceptance. The mechanism was the easy half;
the missing half was **evidence**. Nobody retires a key they cannot prove is unused, which is
why real deployments never finish a rotation — so the daemon records the validating version and
`port49 keys status` names the devices still on an old one. `retire_after` is then enforced
rather than advisory, which is the only thing that prevents an indefinitely accepted version,
with escalating alarms and a reviewed extension as the answer to the lockout it can cause. A
key mismatch is now a row of the failure matrix, since it is the one row a configuration change
can cause.

**Per-device keys were rejected, at Ryan's call.** Derivation narrows blast radius but port49
cannot write device configuration, so it cannot install the key it would derive — a
per-device key nobody can provision is worse than a shared key that rotates on schedule. Key
groups may be narrowed to a single device by deployments with their own automation; port49
does not claim that path. RFC 9887 mutual TLS is the real answer and is recorded as such.

**Specify the broker's mint API.** §16 declares the HTTP API to be the product, and it is never
specified — endpoint shapes, batch mint, error semantics, authentication of the call itself. An
outline is enough, but the implementation plan cannot be written without one.

**Specify policy distribution.** ~~How merged policy reaches the broker, how a change is
versioned and rolled out, and what happens to *live* session contexts when policy changes.~~

**Resolved.** Policy is published in the versioned bundle alongside inventory and the pinned
platform set (spec §10), so a consumer always runs on one nameable state of the world and
`bundle/diff` reviews all three together. Live contexts pick up a policy change because a
changed policy produces a different blob hash, which refresh writes into each affected
context (spec §5.1.3) — so policy-driven revocation reaches active logins, not only
directory-driven revocation.

---

## Gaps

- **Accounting** — ~~as above, the single largest omission for production use.~~

  **Resolved.** The reviewer treated this as one gap; it is two streams, and separating them
  answered both. The decision log is below; device accounting is policy engine spec §5.8,
  with §5.1.1, §5.1.4 and §5.6 rewritten around it.

  Wire handling: three record types on a flags octet, an empty `cmd` marking exec records
  exactly as it marks session authorization. Destination: the decision log's envelope,
  emitter and sink as `event: "account"`, defaulting to stdout JSON lines — never the token
  store, which is the only SPOF and would take the highest-volume traffic port49 handles.
  Durability: `SUCCESS` on a durable spool write, `ERROR` only when the spool refuses, which
  correctly means *ask another replica*; spool depth and drops are metrics. Correlation:
  `task_id` is device-local and collides across reboots, so login context carries a `ctx_id`
  that joins both streams from SSO login to typed command, and records that resolve to no
  context are recorded as `unattributed` rather than dropped.

  Two wire details would have broken reconciliation silently: the trailing `cmd-arg=<cr>`
  several vendors send, which offsets every join by one argument, and the fact that command
  accounting carries typed secrets verbatim — so adapters declare `redact` patterns applied
  before emit, preserving vector shape so the join still matches.

  **The larger correction came from Ryan.** Accounting had been teardown trigger 3 in §5.6
  and was allowed to delete login context. It is best-effort, device-generated, and delivered
  on a separate connection, so a logout STOP delayed past a line's reuse denies the *next*
  operator mid-session. Teardown is now ordered by **authority** rather than reliability —
  redemption, revocation, the session ceiling, a username conflict, idle TTL — and accounting
  only annotates. Two further decisions followed: credential expiry bounds the mint rather
  than the session (`auth_time + max_session_age` instead, warned in-session through
  `server_msg`, refreshed in place, with a grace window, since port49 can deny commands but
  cannot close a session), and login context records credential identity — OIDC `sid`,
  certificate issuer and serial — so revocation reaches live device sessions, which in turn
  extends the encryption-at-rest requirement from tokens to context.

  Still open: WATCHDOG behavior per platform and whether `server_msg` is actually displayed,
  both lab measurements.
- **Observability and audit.** ~~One metric is named across both documents. There is no
  **decision audit log** — every permit and deny with principal, device, rule, and role — which
  is the compliance artifact this product will be bought for.~~ No metrics inventory, no
  tracing.

  **Decision log resolved** — policy engine spec §5.7, with tooling in §12, a decision in §13
  and assertions in §14. One record per evaluation at four events, permits never suppressed.
  The record names the immutable blob it was decided against rather than narrating a
  rationale, so `port49 policy replay` can re-derive the verdict: a decision is verifiable
  rather than asserted, and a replay divergence detects log or blob tampering. Raw arguments
  are kept beside the normalized vector so a normalization bug cannot erase its own evidence,
  denial reasons are a closed vocabulary so operational denials are countable apart from
  policy ones, and no credential material is ever written — the credential appears only as
  the hash the receipt binds. Replaying a captured corpus against a candidate build also
  turns "did this release change anyone's access" into a diff.

  Metrics inventory and tracing remain open.
- **Abuse resistance.** No rate limiting on failed authentications, no per-NAS connection
  limits, no stated behavior for malformed-packet floods on an unauthenticated TCP listener.
- **Duplicate or overlapping addresses.** Device binding assumes source-to-device is injective.
  Snapshot validation for collisions, including CIDR overlap in the admission trie, is
  unspecified.
- **Internal API authentication.** The inventory service's snapshot API and `POST /v1/sync`,
  and broker-to-store, have no stated authentication. A compromised pod network should not be
  able to trigger syncs or read the fleet list.
- **Multi-tenancy** is absent. Fine to exclude — but say so in non-goals.
- **`everyone` spans trust domains** while a subject mixing human and machine identities is a
  load error. Probably intended for deny-only use, but a permit role granted to `everyone`
  quietly crosses the boundary §7 calls out as carrying much of the security value. State the
  asymmetry, or restrict `everyone` to deny-carrying roles.
- Minor: the `sshpass -p "$(port49 token …)"` example places a live token in argv, visible in
  `ps`. Single-use and short TTL mitigate it, but the canonical example should not model it.

---

## Verified correct

Checked and confirmed, so they need no revisiting: the RFC 8907 length analysis (1-byte
`user_len`/`port_len`/`rem_addr_len`/`data_len` in authentication START; 2-byte
`user_msg_len`/`data_len` in CONTINUE; CHAP challenge ≤ 238; 1-byte per-argument lengths and
`arg_cnt`; `=` versus `*` semantics); port 300 for RFC 9887; `shell:roles` on EOS and NX-OS;
`$enab15$` and `authen_service=ENABLE` behavior; Junos `local-user-name`, `allow-commands`,
`deny-commands`, and `show cli authorization`; and the AD `LDAP_MATCHING_RULE_IN_CHAIN` OID.

The failure model's *shape* is sound — the issues above are rows of the matrix disagreeing
with the mitigation text, not the philosophy.
