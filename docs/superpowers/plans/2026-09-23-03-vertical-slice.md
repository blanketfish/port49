# Plan 3: Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The first real identity reaching a real device with no shared password: an operator
runs `port49 login` with a client certificate, `port49 token leaf1` mints a token over the held
mTLS connection, and that token logs into a vEOS switch whose every command is then answered from
a compiled policy blob the broker wrote.

**Architecture:** A minimal broker runs **inside `port49d`**, on a second listener, because the
only store that exists is the in-process memory store (Decided 1). It validates a client
certificate against one trust anchor, maps it to a `user:<email>` principal, resolves a
file-backed policy (literal-identity subjects, roles, grants on `all_devices` only) into a
content-addressed blob, and mints through plan 2's `token.Minter`. The daemon's authorizer reads
that blob. A separate `port49` binary holds the operator's session as one mTLS connection in a
background agent and mints through it on every `port49 token`, fresh each time. Plan 2b's
revocation follow-ups are closed first, so the slice mints into a login path that never answers
PASS into a revoked context.

**Tech Stack:** Go 1.22, standard library (`crypto/tls`, `crypto/x509`, `net/http`), the plan-1,
2 and 2b packages, `gopkg.in/yaml.v3` (already a dependency). No new dependencies. Tasks 15–17
need containerlab and the vEOS and Catalyst 8000V images (`tests/lab/README.md`).

**Spec:** `docs/design/2026-08-21-port49-design.md` §7 (certificate path), §8 "Two credentials,
two lifetimes", §17 "Minting" and "Requirements", §19 step 3.
`docs/design/2026-08-23-policy-engine-spec.md` §2 (principal strings, subjects, the device-facing
username), §4 "Grammar", §5.1–§5.1.2 (mint, the blob), §5.6, §5.7, §6 "Abstract levels", §11,
§13 decisions 12, 16, 17, 19, §15 L1 and L7. Roadmap: `docs/superpowers/plans/README.md`,
"Plan 3". PR #7 body, "Follow-ups owed".
**Prerequisite:** plan 2b merged (PR #7). Branch `feature/vertical-slice` off `main` at `7a2d596`.

## Why this plan exists

Plans 1, 2 and 2b built every mechanism a token needs and exercised none of them with a credential
a person holds: the lab mints seed tokens at daemon start and writes them to a file. Design §19
puts the vertical slice here, before the policy engine and inventory, because the path from a
certificate to a device prompt is where the unknowns live. What the slice owes, from the roadmap:

- a minimal broker — x509 against one trust anchor, a held mTLS connection, literal-identity
  subjects, a file policy with roles and grants and only `all_devices`, `/v1/tokens` and
  `/v1/config`;
- the agent's `port49 login` and `port49 token`, including its reconnect behaviour: **every
  device connection gets a freshly minted token**, which is what removes most of the receipt
  idle-gap problem L15 measured (a client that reconnects presents a new credential, not a spent
  one), with the receipt bounds as the fallback rather than the answer;
- the borrowed-ahead simplest forms, each labelled in its package comment with the plan that
  replaces it: the admission snapshot and key group (plan 6), one blob written and read (plan 4),
  one platform's session attributes (plan 5);
- the first end-to-end lab run with a real credential; the API-transport half of L1; the eAPI
  `/login` flow by hand.

And PR #7's first follow-up, which the slice must not mint on top of: a login can still answer PASS
into a context that ends up revoked — a same-principal replace past the ceiling, an unreadable
replace, and a revocation landing mid-join. Every command after it is denied, so it fails closed,
but the log carries a permit for a principal security just revoked.

## Decided in this plan

Where the design leaves a shape open, this plan chooses, and says why here once:

1. **The broker runs inside `port49d`.** The only store is `memory` wrapped in `crypt`, in one
   process; design §19 step 2 promised "a store reachable by two processes" and plan 2 did not
   build one (Task 1 corrects the design). A second process would share nothing. The broker is a
   second listener in the daemon, off unless `broker:` is configured, and a networked store is owed
   before it becomes a process of its own (plan 7).
2. **`auth_time` is the time of the first request on the held connection**, which the agent sends
   the instant the handshake completes (`GET /v1/config`), so it is the handshake to within a round
   trip. Every mint on that connection carries it; a token's `session_expires` is therefore the
   handshake plus `max_session_age`, which is decision 17's "the key is exercised at handshake".
   The server does not close a held connection for idleness before `max_session_age`, and refuses a
   mint on one older than that with `session_expired`.
3. **Client certificates are verified twice.** At the handshake, `tls.VerifyClientCertIfGiven`
   against the one anchor, so an untrusted certificate fails `port49 login` immediately and
   `/v1/config` stays reachable without one (§17: unauthenticated by necessity). That needs the
   agent to present its certificate unconditionally (`GetClientCertificate`): Go's default sends
   none when the server's CA hint does not name the issuer, and the login would then succeed with
   no identity and fail at the first mint. And again per mint
   against the broker's clock, because a held connection outlives certificates: one that expired
   under it stops minting, `trust_domain_unresolved` (decision 12: credential expiry bounds the
   mint). Revocation (CRL/OCSP) is plan 7.
4. **The principal is `user:` plus the certificate's one rfc822Name SAN, lower-cased** (spec §2's
   human-x509 row with the email as the mapped attribute). Zero or several email SANs refuse
   (design §7: ambiguity fails closed). An email mapping is a weak mapping and design §7 requires it
   issuer-pinned; one trust anchor pins it by construction, and `LoadTLS` refuses an anchor file
   holding more than one certificate so that cannot widen silently.
5. **Human subjects declare `username:`.** Spec §2 derives a human's device-facing username from
   the directory; the slice has none. Borrowed from plan 7, which replaces it with the
   certificate-to-directory mapping. Usernames are unique across subjects and must already be
   canonical, checked at load.
6. **Privilege is `readonly` → 1 and `admin` → 15 on every platform; `operator` is refused at
   load.** Spec §6: a level with no mapping on a platform present is a load error, and the slice has
   no measured mapping for `operator`. Session attributes are rendered for **`arista_eos` only**,
   as `priv-lvl=N` — measured to be applied by vEOS on every lab run since 2026-09-20
   (`tests/lab/results/L16-arista_eos.md`; `shell:roles*` beside it is ignored there, so the lab's
   own reply has effectively been `priv-lvl` alone). Every other platform gets a blob with **no
   session attributes** (Question 2). Plan 5 replaces the table and the renderer.
7. **The blob is `{platform, privilege, attributes, permit, deny}`, and commands are
   deny-overrides.** Rules are a strict subset of spec §4: words (case-insensitive), `*`, and a
   trailing `**`, matched against the whole vector; `@class` and `/re/` are refused at load naming
   plan 4. A matching deny refuses whatever permit also matches — stricter than §5.4's
   specificity dominance, so it can only refuse a command dominance would permit, never the
   reverse. Plan 4 replaces the format and the matcher.
8. **A blob's store TTL is `max_session_age`, and it is emitted into the log once per hash per
   process.** A context's `session_expires` is `auth_time + max_session_age` with `auth_time` never
   later than the mint, so that outlives every context the blob can back; `PutBlob` keeps the later
   expiry, so a re-put never shortens it. The store and the "already emitted" set die together with
   the process, so once per process is once per store (decision 19).
9. **An unknown device and a device with no grant get the same answer**, per item,
   `no_grants_matched` (design §17: the mint API must not be a fleet enumeration oracle). The log
   record for the unknown one names the device and no platform, which is what tells an operator
   which it was.
10. **The candidate-set cap gets a reason code, `candidate_cap_reached`**, added to spec §5.7
    first (Task 1). The cap exists (plan 2) and refuses the mint, and design §17 requires every
    per-item refusal to use the log's closed vocabulary; none of the existing codes is true of it.
    `session_expired` is widened to cover the mint refused on a connection past the ceiling.
11. **The agent is a background process on a unix socket in a directory only its user can enter**
    (`$XDG_RUNTIME_DIR/port49/agent.sock`, else `/tmp/port49-<uid>/agent.sock`, directory mode
    0700 and refused otherwise). `port49 login` starts it and waits for it; `port49 token` asks it.
    It holds no token and writes none to disk: every `port49 token` is a mint. A transport failure
    is retried once, on a new connection, with the same `Idempotency-Key`, so a mint whose response
    was lost is replayed rather than cut again (design §17). The session ends at the first
    handshake plus `max_session_age` however many reconnects happen in between; the agent then
    exits.
12. **One uniform check after `JoinContext` closes PR #7's first two follow-ups.** After the join
    and its index bookkeeping, a login whose written context carries `revoked_at` answers FAIL
    `credential_revoked` with the token spent. A retransmission is answered from the live context,
    not the receipt's stored status: a revoked context refuses it `credential_revoked` whatever the
    receipt says, which also retires "a retransmitted refusal replays as `receipt_replayed`". The
    pre-read refusal stays: it is the case the login can see before writing anything, and it
    writes nothing.
13. **PR #7's third follow-up is carried to plan 7.** A join racing another principal's replace
    under the same username needs two principals sharing one username, which the slice's policy
    load refuses (usernames unique across subjects) and the minter can only produce from two
    policies; revocation by principal still reaches the context. Plan 7 owns the index.
14. **No scheduled refresh; `session.staleness_ceiling` stays 0.** Plan 2 handed "the refresh
    schedule" to plan 3, but the slice's policy is read once at start and the store dies with the
    process, so there is nothing a refresh could carry into a live context. Plan 7 owns §5.1.3 and
    the staleness default together, as its roadmap entry already says.
15. **The admission snapshot and key group are plan 1's file inventory**, which already is the
    hand-written snapshot and key group §19 describes. The broker reads the same
    `admission.Inventory` the daemon admits from, for a device's platform and address. Nothing new
    is written for it.
16. **Lab scope.** The end-to-end run is automated (`TestSliceEndToEnd`, vEOS only, Decided 6). The
    eAPI `/login` flow is by hand, as the roadmap says, on vEOS with a broker-minted token. "The
    API-transport half of L1" is read as the one API transport L1 still lists unmeasured — every
    non-SSH transport on IOS-XE — and is measured by hand over RESTCONF, with a **seeded** token:
    RESTCONF needs privilege 15, which the slice does not render for IOS-XE (Decided 6), and the
    `port` field is a property of the device, not of who minted the token. L1 stays open on its
    console clause either way.

## Questions for Ryan

None of these blocks a task; each has a recommendation the plan implements as written.

1. **May the slice accept a software key?** Design §7 puts the certificate path's private key on
   a hardware token, where a reconnect costs a touch and is therefore a human event. The slice
   loads the key from a PEM file (`--cert`/`--key`); PKCS#11/PIV is plan 9. With a file key, a
   reconnect is silent and proves only that the file was readable. *Recommendation:* accept it,
   labelled borrowed, and keep the agent's hard stop at the first handshake plus
   `max_session_age` so a file key cannot stretch a session past the ceiling.
2. **What should a broker-minted token do on a platform the slice renders no attributes for?**
   It mints, with a bare-permit session reply: NX-OS then lands the operator on `vdc-operator`
   (L18), Junos on the device's `remote` template, and IOS-XE on whatever a reply with no
   `priv-lvl` gives, which is unmeasured. The alternative is refusing those mints, which needs a
   new reason code. *Recommendation:* mint, least privilege, and say so in the mint record's blob;
   plan 5 fills the table.
3. **A policy edit needs a `port49d` restart, and a restart logs everyone out.** The policy is read
   once at start and the store is in memory, so every live context and unspent token goes with the
   process. *Recommendation:* accept for the slice; plan 4 brings reload and plan 7 refresh. The
   3am consequence is written into the `broker:` config comment so an operator is not surprised.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2 and 2b, and still binding:

- **Every context write outside login goes through a narrow setter.** The broker never writes a
  login context (spec §5.1.1); the daemon creates it at redemption.
- **Every claim about device behaviour cites a `tests/lab/results/` note or a decision log by
  name.** A claim with neither is marked *unmeasured* and the code must not depend on it.
- **One new reason code, and only after its spec row:** `candidate_cap_reached` (Task 1, then
  Task 3). `session_expired` and `credential_revoked` are widened in the spec, not duplicated.

New in this plan:

- **Everything borrowed ahead says so** in its package or type comment, naming the plan that
  replaces it: `internal/blob` and `author.Blob` (plan 4), the privilege table and
  `sessionAttributes` (plan 5), `internal/broker/policy` (plan 4), the subject `username:` (plan 7),
  the file key in `cmd/port49` (plan 9).
- **A token appears in the mint response and nowhere else** (design §17 "Write-once"): not in the
  decision log, not in the agent's log, not in argv, not in a file. `port49 token` writes it to
  stdout only. The lab's seed-token file is the one pre-existing exception and is untouched.
- **No API keys and no broker-issued session token** (design §17; decision 17). The agent's session
  is the TLS connection.
- **TLS 1.3 minimum** on the broker listener and in the agent.
- **No new dependencies.**
- **`gofmt -w` every file a step edits.** Whole files in this plan are gofmt-clean; where a step adds
  a field to an existing struct or const block, the alignment is gofmt's to settle, and `make vet`
  fails until it has.
- Branch `feature/vertical-slice`; never commit code to `main`.
- Every verification runs `make test && make vet`, `go test -race ./internal/...`, and
  `go vet -tags lab ./tests/lab/...`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```

---

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md   MOD  §5.6 revoked-login rule; §5.7 rows; §14 assertion; §15 L1, L7 (Task 18)
docs/design/2026-08-21-port49-design.md        MOD  §19 steps 2 and 3
docs/superpowers/plans/README.md               MOD  plan 2 hand-offs settled; plan 7 owes the carried items
internal/daemon/authen/authen.go               MOD  post-join revoked check; receiptContext; revoked()
internal/daemon/authen/authen_test.go          MOD  three revoked-result cases, replay, the retired-key test
internal/decision/reasons.go                   MOD  CandidateCapReached
internal/decision/log.go                       MOD  Record.Policy, Record.Blob; Policy, PolicyGrant, Blob
internal/decision/blob_test.go                 NEW
internal/token/minter.go                       MOD  Request.Policy onto the mint record
internal/token/policy_test.go                  NEW
internal/blob/blob.go                          NEW  the slice's blob: encode, hash, decode, rule subset, verdict
internal/blob/blob_test.go                     NEW
internal/daemon/author/blob.go                 NEW  author.Blob: answers from the context's blob, Lab fallback
internal/daemon/author/blob_test.go            NEW
internal/broker/policy/policy.go               NEW  Load: the file policy and its refusals
internal/broker/policy/resolve.go              NEW  Resolve, SubjectOf, the privilege table, sessionAttributes
internal/broker/policy/policy_test.go          NEW
internal/broker/policy/resolve_test.go         NEW
internal/broker/policy/labpolicy_test.go       NEW  the lab's policy file loads under `make test`
internal/testpki/testpki.go                    NEW  throwaway CA and leaves for tests and the lab
internal/testpki/testpki_test.go               NEW
internal/broker/identity.go                    NEW  Identity: verified certificate → principal and credential
internal/broker/identity_test.go               NEW
internal/broker/fixture_test.go                NEW  the broker test fixture
internal/broker/api/api.go                     NEW  the wire types, shared with the agent
internal/broker/broker.go                      NEW  Broker, Handler, /v1/tokens, /v1/config, heldConn
internal/broker/broker_test.go                 NEW
internal/broker/server.go                      NEW  Server, LoadTLS
internal/broker/server_test.go                 NEW
internal/config/config.go                      MOD  BrokerConfig, the broker: block
internal/config/broker_test.go                 NEW
cmd/port49d/main.go                            MOD  author.Blob; buildBroker; the broker listener
cmd/port49d/broker_test.go                     NEW
Makefile                                       MOD  build bin/port49 too
internal/agent/agent.go                        NEW  Agent: the held connection, Connect, Mint, Handler
internal/agent/socket.go                       NEW  SocketPath, PrivateDir, Listen, Client
internal/agent/agent_test.go                   NEW
cmd/port49/main.go                             NEW  login, token, agent
cmd/port49/main_test.go                        NEW
tests/lab/cmd/slice-pki/main.go                NEW
tests/lab/slice/policy.yaml                    NEW
tests/lab/slice/broker.yaml                    NEW
tests/lab/slice_test.go                        NEW  TestSliceEndToEnd
tests/lab/README.md                            MOD  "The vertical slice": the automated run and the two by-hand runs
tests/lab/results/slice-arista_eos.md          NEW  (Task 15, written by the test)
tests/lab/results/L7-login-arista_eos.md       NEW  (Task 16, by hand)
tests/lab/results/L1-restconf-cisco_iosxe.md   NEW  (Task 17, by hand)
tests/lab/evidence/*.pcap                      NEW  (Tasks 15–17, `make evidence`)
```

Eighteen tasks: **thirteen code** (2–14), **three lab** (15–17), **two docs** (1, 18). Task 1 comes
first, as plan 2b's spec commit did: Task 2 changes what a `redeem` answers and Task 9 emits a
reason code, and both need their spec rows first. Tasks 15–17 are one platform at a time with a
destroy after each, and none of them may start before Task 14 is merged into the branch.

---

### Task 1: The spec and the design say what the slice changes, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.6, §5.7, §14)
- Modify: `docs/design/2026-08-21-port49-design.md` (§19)
- Modify: `docs/superpowers/plans/README.md` (plan 2's hand-offs, plan 7)

**Interfaces:**
- Produces: the §5.7 row `candidate_cap_reached` (Task 3's constant, Task 9's refusal), the widened
  `session_expired` and `credential_revoked` rows (Tasks 9 and 2), and the §5.6 paragraph Task 2
  implements.

- [ ] **Step 1: §5.6 — one rule for a login whose result is revoked**

In `docs/design/2026-08-23-policy-engine-spec.md`, replace the whole paragraph that begins
`**A login into a revoked context is refused.**` and ends `whose every authorization is then denied
\`credential_revoked\`.` with:

```markdown
**A login into a revoked context is refused.** A login whose resulting context carries
`revoked_at` answers FAIL `credential_revoked` — the answer the `enable` gate gives for the same
state — and its token is spent, so a token the revocation was meant to stop gets no second try
(ruled 2026-09-23; made one rule in plan 3). There are four ways to get there. The context the login
would join is already revoked and the token was not minted after it: refused before anything is
written. The same principal's context past its ceiling, replaced carrying a revocation the token
predates; a context the sealing layer cannot open, replaced carrying its plaintext `revoked_at`; and
a revocation that lands between the login's read and its join, merged by the join: each has already
written the context when it is refused, and that context is revoked, so every authorization against
it is denied anyway until the idle TTL reclaims it. The `redeem` record carries the principal, the
`ctx_id` and `session.revoked_at`, the revocation that refused it. A retransmission is answered from
the live context, not from the status the receipt stored: while the context it names is revoked it is
refused `credential_revoked` again, never replayed as a PASS. A token minted after the revocation
joins and lifts it, by the table. A revocation that lands after the join's write is not seen by the
login, which answers PASS; its first authorization is denied `credential_revoked`.
```

- [ ] **Step 2: §5.7 — three rows**

Replace the `credential_revoked` row with:

```markdown
| `credential_revoked` | the context's `revoked_at` is set — CRL, OCSP, back-channel logout, or every grant withdrawn (§5.6); on `redeem`, a login whose resulting context is revoked because its token was not minted after the revocation, or a retransmission answered while the context it names is revoked (§5.6) |
```

Replace the `session_expired` row with:

```markdown
| `session_expired` | the session ceiling was reached; context retained through the grace window (§5.6). On `mint`: the held connection's authentication is older than `max_session_age`, and the caller must authenticate again (§13, decision 17) |
```

Directly after the `trust_domain_unresolved` row, add:

```markdown
| `candidate_cap_reached` | `mint`: `token.candidate_cap` unspent tokens already stand for this `(device, username)`; the mint is refused, never a redemption, and every token already issued stays usable (design document §8) |
```

- [ ] **Step 3: §14 — the assertion**

In §14, directly after the bullet that begins `- **Revocation is distinguishable**:`, add:

```markdown
- **A login into a revoked result is refused**: a login that writes a revoked context — a
  same-principal replace past the ceiling, an unreadable replace, or a revocation landing mid-join,
  each with a token minted before the revocation — answers FAIL `credential_revoked` with the token
  spent, and its retransmission is refused `credential_revoked`, never replayed as a PASS.
```

- [ ] **Step 4: design §19 — what step 2 did not build, and what step 3 closes**

In `docs/design/2026-08-21-port49-design.md` §19, in step 2, replace

```markdown
   encryption at rest, the store record set, and a store reachable by two processes (the
   in-memory store of step 1 is in-process). Reusable tokens are built here but stay
   provisional until L7 closes in step 3.
```

with

```markdown
   encryption at rest, the store record set, and a store reachable by two processes (the
   in-memory store of step 1 is in-process) — **the last not built**: plan 2 shipped the sealing
   layer over the in-process store, so step 3's broker runs inside `port49d`, and a store two
   processes can reach is owed before the broker becomes a process of its own (step 7).
   Reusable tokens are built here but stay provisional until L7 closes in step 3.
```

and in step 3 replace `each in its simplest form. L3, L4, and L7 close
   here.` with

```markdown
   each in its simplest form. L7 closes here, on the `/login` measurement; L3 closed in the lab
   work before it, and L4 stays open on `deadtime` and the transports it has not measured (policy
   engine spec, §15).
```

- [ ] **Step 5: the roadmap — plan 2's hand-offs settled, plan 7's list**

In `docs/superpowers/plans/README.md`, under "Plan 2 … Hands to plan 3", replace the bullet that
begins `- **\`session.staleness_ceiling\` defaults to 0` with:

```markdown
- **`session.staleness_ceiling` defaults to 0, so the `context_stale` check is dead in the
  shipping binary** until something calls `Refresh` on a schedule (spec §5.1.3). **Plan 3 did not
  wire it** (plan 3, Decided 14): the slice reads its policy once and its store dies with the
  process, so a refresh has nothing to carry. Plan 7 wires the schedule and sets the default in the
  same change — a ceiling with no refresher denies every context the moment it is set.
```

Under "Owed by plan 3 or plan 7", replace the bullet that begins `- **\`foreign\` has no metric` with:

```markdown
- **`foreign` has a metric** since plan 2b (`port49_accounting_attributions_total{attribution}`,
  ruled with no rate limit). Nothing further is owed here.
```

In "## Plan 7 — Broker in full", append after the existing paragraph:

```markdown
**Carried from plan 3:** a store two processes can reach, before the broker leaves `port49d`
(design §19 step 2); the scheduled refresh and the `staleness_ceiling` default, together; PR #7's
third follow-up — a join racing another principal's replace under one username can lose its sid or
certificate index entry (revocation by principal still reaches it); the certificate-to-directory
mapping replacing the slice's declared `username:`; policy reload.
```

- [ ] **Step 6: Check the edits read in place**

Run: `grep -n 'made one rule in plan 3\|candidate_cap_reached\|A login into a revoked result' docs/design/2026-08-23-policy-engine-spec.md && grep -n 'the last not built\|L7 closes here' docs/design/2026-08-21-port49-design.md && grep -n 'Carried from plan 3' docs/superpowers/plans/README.md`
Expected: one line per pattern, in the sections named above.

- [ ] **Step 7: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md docs/superpowers/plans/README.md
git commit -m "docs: one rule for a login into a revoked result, and the slice's reason codes

Spec §5.6 says every way a login can write a revoked context answers
credential_revoked, and a retransmission is answered from the live
context. §5.7 adds candidate_cap_reached and widens session_expired to
the mint. Design §19 says step 2 never built a two-process store and
that step 3 closes L7, not L3 and L4. The roadmap carries plan 3's
deferrals to plan 7.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: A login whose result is revoked is refused, and so is its retransmission

**Files:**
- Modify: `internal/daemon/authen/authen.go` (`redeem`, `receiptContextLive` → `receiptContext`, new `revoked`)
- Test: `internal/daemon/authen/authen_test.go`

**Interfaces:**
- Consumes: `store.JoinResult.Context` (plan 2b), `decision.FormatTime`, the fixture helpers
  `setup`, `setupStore`, `seedLoginWith`, `joinFixture`, `papStart`, `midRedemption`.
- Produces: `(*Session).receiptContext(ctx, ck, receiptCtxID string, enable bool, incumbent store.Context) (store.Context, bool, error)`
  replacing `receiptContextLive`; `(*Session).revoked(ctx, rec, principal, ctxID string, at time.Time) (wire.AuthenReply, bool)`.
  `authen.New` keeps its signature.

- [ ] **Step 1: Write the failing tests**

Append to `internal/daemon/authen/authen_test.go`:

```go
// PR #7's first follow-up. A login can write a context that is revoked in
// ways its pre-read cannot see: the same principal's context past its ceiling
// is replaced carrying a revocation the token predates, and a revocation that
// lands between the pre-read and the join is merged by it. (The third, a
// record under a retired key, is TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation.)
// Each must answer FAIL credential_revoked with the token spent and the
// revocation on the record — the enable gate's answer for the same state — and
// the retransmission must be refused the same way, never replayed as the PASS
// the receipt was written with.
func TestALoginWhoseContextEndsUpRevokedIsRefused(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	key := store.ContextKey{NAS: "leaf-01", Username: "alice"}
	for _, tt := range []struct {
		name            string
		setup           func(t *testing.T) (*fixture, wire.AuthenStart)
		ctxID, replaced string
	}{
		{"the same principal past its ceiling", func(t *testing.T) (*fixture, wire.AuthenStart) {
			f := setup(t)
			f.seedLoginWith(t, "token", 15, func(c *store.Context) {
				c.RevokedAt = revokedAt
				c.SessionExpires = f.now.Add(time.Minute)
			})
			f.now = f.now.Add(2 * time.Minute)
			return f, papStart("alice", "ssh", "198.51.100.4", f.tag()+"tok1tok1tok1tok1tok1tok1")
		}, "ctx1", "ctxL"},
		{"a revocation landing mid-join", func(t *testing.T) (*fixture, wire.AuthenStart) {
			f := setupStore(t, func(st *memory.Store) store.Store {
				return midRedemption{Store: st, during: func() { _ = st.SetRevokedAt(context.Background(), key, revokedAt) }}
			})
			return f, f.joinFixture(t, nil)
		}, "ctxL", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, start := tt.setup(t)
			reply, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			rec := f.records(t)[0]
			s := rec["session"].(map[string]any)
			if reply.Status != wire.AuthenStatusFail || rec["verdict"] != "deny" || rec["reason"] != "credential_revoked" ||
				rec["principal"] != "user:alice@example.com" || s["ctx_id"] != tt.ctxID {
				t.Fatalf("a login whose context ends up revoked must be refused credential_revoked: %+v %v", reply, rec)
			}
			if tt.replaced != "" && s["replaced_ctx_id"] != tt.replaced {
				t.Fatalf("the replace must still name what it displaced: %v", s)
			}
			ra, _ := s["revoked_at"].(string)
			if got, err := time.Parse(time.RFC3339Nano, ra); err != nil || !got.Equal(revokedAt) {
				t.Fatalf("the record must carry the revocation that refused it: %q %v", ra, err)
			}
			if left, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"}); len(left) != 0 {
				t.Fatalf("the token must be spent: %d left", len(left))
			}
			retry, _ := f.h.NewSession(f.peer).Start(context.Background(), start)
			r := f.records(t)
			if last := r[len(r)-1]; retry.Status != wire.AuthenStatusFail || last["reason"] != "credential_revoked" {
				t.Fatalf("the retransmission must be refused as revoked, not replayed: %+v %v", retry, last)
			}
		})
	}
}

// The control for the replace case: a token minted after the revocation is
// the broker having verified the credential again, and the replace it writes
// is not revoked (spec §13, decision 15). The uniform check must not refuse it.
func TestAReplacePastTheCeilingWithATokenMintedAfterTheRevocationAdmits(t *testing.T) {
	revokedAt := time.Unix(1_757_041_495, 0).Add(-time.Minute)
	f := setup(t)
	f.seedLoginWith(t, "token", 15, func(c *store.Context) {
		c.RevokedAt = revokedAt
		c.SessionExpires = f.now.Add(time.Minute)
	})
	secret := f.tag() + "aftraftraftraftraftraftr"
	if _, err := f.st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "a", Secret: []byte(secret), Kind: store.KindLogin, Username: "alice",
			Principal: "user:alice@example.com", MintedAt: revokedAt.Add(time.Second),
			ExpiresAt: f.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * time.Minute)
	reply, _ := f.h.NewSession(f.peer).Start(context.Background(), papStart("alice", "ssh", "198.51.100.4", secret))
	if rec := f.records(t)[0]; reply.Status != wire.AuthenStatusPass || rec["reason"] != "token_redeemed" {
		t.Fatalf("a token minted after the revocation must be admitted: %+v %v", reply, rec)
	}
	if c, _ := f.st.GetContext(context.Background(), store.ContextKey{NAS: "leaf-01", Username: "alice"}); !c.RevokedAt.IsZero() {
		t.Fatalf("the replace must not carry a revocation its token postdates: %+v", c)
	}
}
```

In `TestARevocationSurvivesATokenMintedBeforeIt`, replace

```go
			last := f.records(t)[len(f.records(t))-1]
			if retry.Status == wire.AuthenStatusPass || last["verdict"] != "deny" {
				t.Fatalf("a retransmission must not PASS: %+v %v", retry, last)
			}
```

with

```go
			last := f.records(t)[len(f.records(t))-1]
			if retry.Status != wire.AuthenStatusFail || last["reason"] != "credential_revoked" {
				t.Fatalf("a retransmission is refused as the login was, credential_revoked, not "+
					"receipt_replayed (PR #7's second follow-up): %+v %v", retry, last)
			}
```

In `TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation`, replace

```go
	if reply.Status != wire.AuthenStatusPass || rec["reason"] != "token_redeemed" || s["ctx_id"] != "ctx1" ||
		s["replaced_ctx_id"] != nil || s["replaced_unreadable"] != true {
		t.Fatalf("a context under a retired key must be replaced, not refused: %+v %v", reply, rec)
	}
```

with

```go
	// Replaced rather than refused before the token was read — and then
	// refused, because what the replace wrote carries a revocation this token
	// predates (the uniform check after the join; spec §5.6).
	if reply.Status != wire.AuthenStatusFail || rec["reason"] != "credential_revoked" || s["ctx_id"] != "ctx1" ||
		s["replaced_ctx_id"] != nil || s["replaced_unreadable"] != true {
		t.Fatalf("a context under a retired key is replaced, and a replace carrying a revocation is refused: %+v %v", reply, rec)
	}
```

and in that test's leading comment replace

```go
// keeps the plaintext revocation (the token was minted before it), and the
// record says what happened — replaced_unreadable, and no replaced_ctx_id,
// because that id is sealed.
```

with

```go
// keeps the plaintext revocation (the token was minted before it), the
// record says what happened — replaced_unreadable, and no replaced_ctx_id,
// because that id is sealed — and the login is refused credential_revoked,
// because the context it wrote is revoked (spec §5.6).
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/authen/ -run 'TestALoginWhoseContextEndsUpRevokedIsRefused|TestARevocationSurvivesATokenMintedBeforeIt|TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation|TestAReplacePastTheCeilingWithATokenMintedAfterTheRevocationAdmits' -count=1`
Expected: FAIL — both `TestALoginWhoseContextEndsUpRevokedIsRefused` subtests report `a login whose
context ends up revoked must be refused credential_revoked` with `reason:token_redeemed`;
`TestARevocationSurvivesATokenMintedBeforeIt/minted_before_the_revocation` reports
`receipt_replayed`; the retired-key test reports `token_redeemed`. The control PASSes already.

- [ ] **Step 3: `receiptContext` returns the live context, and a revoked one refuses the replay**

In `internal/daemon/authen/authen.go`, replace the whole `receiptContextLive` function and its
comment with:

```go
// receiptContext reports whether a replayed receipt may act, and returns the
// live context it would act on: whether the ctx_id it froze is still the live
// context's (spec §5.6). The join keeps ctx_id across one principal's logins,
// so a match is exactly "the context this receipt was written for", and a
// mismatch is a context replaced — another principal, past its ceiling,
// unreadable — or reclaimed since. A receipt for a context that no longer
// exists answers nothing that exists: PASS from it would admit a session whose
// authorizations answer from someone else's context, or raise that context
// with another principal's enable.
//
// The context is returned because a match is not the whole answer: a context
// revoked since the receipt was written — or revoked by the login that wrote
// it — admits nothing, and the caller refuses the replay on it.
//
// An enable already holds the live context from its gate; a login reads it.
// The error is a store error only — an absent or unopenable context is a
// plain no.
func (s *Session) receiptContext(ctx context.Context, ck store.ContextKey, receiptCtxID string,
	enable bool, incumbent store.Context) (store.Context, bool, error) {
	if enable {
		return incumbent, incumbent.CtxID == receiptCtxID, nil
	}
	c, err := s.h.store.GetContext(ctx, ck)
	s.h.metrics.StoreOps.WithLabelValues("get_context", storeOutcome(err)).Inc()
	var unreadable *store.UnreadableContextError
	switch {
	case err == nil:
		return c, c.CtxID == receiptCtxID, nil
	case errors.Is(err, store.ErrNotFound), errors.As(err, &unreadable):
		return store.Context{}, false, nil
	default:
		return store.Context{}, false, err
	}
}

// revoked refuses a login, or its retransmission, into a revoked context:
// FAIL `credential_revoked`, the enable gate's answer for the same state, with
// the revocation on the record so the refusal explains itself (spec §5.6).
func (s *Session) revoked(ctx context.Context, rec decision.Record, principal, ctxID string,
	at time.Time) (wire.AuthenReply, bool) {
	rec.Principal = principal
	rec.Session.CtxID = ctxID
	rec.Session.RevokedAt = decision.FormatTime(at)
	return s.fail(ctx, rec, decision.CredentialRevoked)
}
```

In the receipt branch of `redeem`, replace

```go
		switch ok, lerr := s.receiptContextLive(ctx, ck, r.CtxID, enable, incumbent); {
		case lerr != nil:
			return s.storeError(rec)
		case !ok:
			return s.fail(ctx, rec, decision.TokenSpent)
		}
```

with

```go
		switch live, ok, lerr := s.receiptContext(ctx, ck, r.CtxID, enable, incumbent); {
		case lerr != nil:
			return s.storeError(rec)
		case !ok:
			return s.fail(ctx, rec, decision.TokenSpent)
		case !live.RevokedAt.IsZero():
			// Answered from what the context says now, not from what the
			// receipt stored: a revoked context admits nothing, whether the
			// revocation landed after the login or the login wrote it (spec
			// §5.6). Refused before the extension, so it does not slide.
			return s.revoked(ctx, rec, live.Principal, live.CtxID, live.RevokedAt)
		}
```

In the race-loser branch, replace

```go
					switch ok, lerr := s.receiptContextLive(ctx, ck, r.CtxID, enable, incumbent); {
```

with

```go
					switch _, ok, lerr := s.receiptContext(ctx, ck, r.CtxID, enable, incumbent); {
```

and in the long comment above `ctxID := incumbent.CtxID`, replace `refused \`token_spent\`
(receiptContextLive)` with `refused \`token_spent\` (receiptContext)`.

- [ ] **Step 4: The pre-read refusal uses `revoked`, and its comment stops promising a PASS**

Replace

```go
	// revokedAt is set when the login would join a context whose revocation
	// its token, minted before it, cannot lift (store.CarryRevocation). Such a
	// login is refused `credential_revoked`, the enable gate's answer for the
	// same state (spec §5.6). The token is still spent, and the receipt
	// records the refusal: a retry of a token the revocation was meant to stop
	// must not get a second chance, and a retransmission replays FAIL, never
	// a PASS. A revocation that lands after this read is merged by the join
	// instead, and that login answers PASS into the revoked context; every
	// authorization after it is denied.
```

with

```go
	// revokedAt is set when the login would join a context whose revocation
	// its token, minted before it, cannot lift (store.CarryRevocation). Such a
	// login is refused `credential_revoked`, the enable gate's answer for the
	// same state (spec §5.6), before anything is written to the context. The
	// token is still spent, and the receipt records the refusal: a retry of a
	// token the revocation was meant to stop must not get a second chance.
	// This is the case the login can see before it writes; the check after
	// the join below catches the ones it cannot.
```

and replace

```go
	// Refused, and nothing is written to the context: it is revoked already,
	// and a join would only swap in a broker decision nobody may use.
	if !revokedAt.IsZero() {
		rec.Principal = winner.Principal
		rec.Session.CtxID = ctxID
		rec.Session.RevokedAt = decision.FormatTime(revokedAt)
		return s.fail(ctx, rec, decision.CredentialRevoked)
	}
```

with

```go
	// Refused, and nothing is written to the context: it is revoked already,
	// and a join would only swap in a broker decision nobody may use.
	if !revokedAt.IsZero() {
		return s.revoked(ctx, rec, winner.Principal, ctxID, revokedAt)
	}
```

- [ ] **Step 5: The uniform check after the join**

Replace

```go
	rec.Principal = winner.Principal
	rec.Session.CtxID = out.Context.CtxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}
```

with

```go
	// One check on what the login actually wrote (spec §5.6). The pre-read
	// refuses the case it can see before writing; three it cannot see end
	// here: the same principal's context past its ceiling, replaced carrying a
	// revocation the token predates; a record under a retired key, replaced
	// carrying its plaintext revocation; and a revocation that landed between
	// the pre-read and the join, merged by it. Each wrote a context whose every
	// authorization is denied, so a PASS would put a permit in the log for a
	// login that can do nothing, with nothing on it saying why. The token is
	// spent. The receipt says PASS, and a retransmission reads the live context
	// and is refused the same way (receiptContext).
	//
	// After the index bookkeeping, not before: the context exists and is
	// revoked, and a revocation of this credential must still reach it.
	//
	// A revocation that lands after the join's swap is not seen here, and that
	// login answers PASS; its first authorization is denied.
	if !out.Context.RevokedAt.IsZero() {
		return s.revoked(ctx, rec, winner.Principal, out.Context.CtxID, out.Context.RevokedAt)
	}
	rec.Principal = winner.Principal
	rec.Session.CtxID = out.Context.CtxID
	return s.finish(rec, wire.AuthenStatusPass, decision.TokenRedeemed)
}
```

- [ ] **Step 6: Run the package**

Run: `go test ./internal/daemon/authen/ -count=1 && go test -race ./internal/daemon/authen/ -count=1`
Expected: PASS, both.

- [ ] **Step 7: Commit**

```bash
git add internal/daemon/authen/authen.go internal/daemon/authen/authen_test.go
git commit -m "fix: refuse a login whose context ends up revoked, and its retransmission

One check after JoinContext: a same-principal replace past the ceiling,
an unreadable replace, and a revocation landing mid-join each wrote a
revoked context and answered PASS. They now answer credential_revoked
with the token spent. A retransmission is answered from the live
context, so it is refused credential_revoked too rather than replayed
from the receipt. Closes PR #7's first two follow-ups.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: The decision log carries a mint's policy, the blob event's body, and the cap's reason

**Files:**
- Modify: `internal/decision/reasons.go`
- Modify: `internal/decision/log.go` (`Record`; new `Policy`, `PolicyGrant`, `Blob`)
- Modify: `internal/token/minter.go` (`Request.Policy`; the mint record)
- Test: `internal/decision/blob_test.go`, `internal/token/policy_test.go`

**Interfaces:**
- Produces: `decision.CandidateCapReached Reason = "candidate_cap_reached"`;
  `decision.Record.Policy *decision.Policy` (`json:"policy,omitempty"`) and
  `decision.Record.Blob *decision.Blob` (`json:"blob,omitempty"`);
  `type Policy struct { Subject string; Grants []PolicyGrant }`,
  `type PolicyGrant struct { Scope string; Roles []string }`,
  `type Blob struct { Hash string; Body json.RawMessage }`;
  `token.Request.Policy *decision.Policy`, copied onto the minter's `mint` record. Task 7 builds
  `[]decision.PolicyGrant`; Task 9 sets `Request.Policy` and emits `Record.Blob`.

- [ ] **Step 1: Write the failing tests**

Create `internal/decision/blob_test.go`:

```go
package decision

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// The `blob` event carries the compiled blob itself, so replay depends on the
// log alone (spec §5.1.1; §13, decision 19). It is written as JSON, not as a
// quoted string: a reader queries its fields like any other record's.
func TestABlobEventCarriesTheBodyAsJSON(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventBlob,
		Blob: &Blob{Hash: "sha256:ab", Body: json.RawMessage(`{"platform":"arista_eos"}`)}})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	b, _ := m["blob"].(map[string]any)
	body, ok := b["body"].(map[string]any)
	if !ok || body["platform"] != "arista_eos" || b["hash"] != "sha256:ab" {
		t.Fatalf("blob event: %s", buf.String())
	}
}

// A mint record names the subject and the grants that allowed it (spec §5.7).
func TestAMintRecordCarriesItsPolicyBlock(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventMint, Verdict: VerdictPermit,
		Reason: GrantsMatched, Policy: &Policy{Subject: "netops",
			Grants: []PolicyGrant{{Scope: "all_devices", Roles: []string{"network_admin"}}}}})
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	p, _ := m["policy"].(map[string]any)
	g, _ := p["grants"].([]any)
	if p["subject"] != "netops" || len(g) != 1 || g[0].(map[string]any)["scope"] != "all_devices" {
		t.Fatalf("policy block: %s", buf.String())
	}
	if CandidateCapReached != "candidate_cap_reached" {
		t.Fatalf("the §5.7 spelling is candidate_cap_reached, got %q", CandidateCapReached)
	}
}
```

Create `internal/token/policy_test.go`:

```go
package token

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/decision"
)

// The minter writes the mint record, so the policy that allowed the mint has
// to reach it through the request: the broker knows the subject and the
// grants, the minter knows nothing of policy.
func TestAMintRecordCarriesThePolicyThatAllowedIt(t *testing.T) {
	m, _, log := minter(t)
	p := &decision.Policy{Subject: "netops", Grants: []decision.PolicyGrant{{Scope: "all_devices", Roles: []string{"network_admin"}}}}
	if _, err := m.Mint(context.Background(), Request{Subject: subject(), Device: "leaf-01", Platform: "arista_eos",
		TTL: time.Minute, Policy: p}); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if err := json.Unmarshal(log.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if pol, _ := rec["policy"].(map[string]any); pol["subject"] != "netops" {
		t.Fatalf("mint record: %s", log.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/decision/ ./internal/token/ -run 'TestABlobEventCarriesTheBodyAsJSON|TestAMintRecordCarriesItsPolicyBlock|TestAMintRecordCarriesThePolicyThatAllowedIt' -count=1`
Expected: FAIL to build — `unknown field Blob in struct literal of type Record`, `undefined: Policy`,
`unknown field Policy in struct literal of type Request`.

- [ ] **Step 3: The reason code**

In `internal/decision/reasons.go`, replace

```go
	TrustDomainUnresolved Reason = "trust_domain_unresolved"
```

with

```go
	TrustDomainUnresolved Reason = "trust_domain_unresolved"
	// CandidateCapReached: token.candidate_cap unspent tokens already stand
	// for this (device, username). The mint is refused, never a redemption
	// (design §8).
	CandidateCapReached   Reason = "candidate_cap_reached"
```

- [ ] **Step 4: The record fields**

In `internal/decision/log.go`, in `type Record struct`, replace

```go
	Mint        *Mint        `json:"mint,omitempty"`
```

with

```go
	Mint        *Mint        `json:"mint,omitempty"`
	Policy      *Policy      `json:"policy,omitempty"`
	Blob        *Blob        `json:"blob,omitempty"`
```

and directly after the `Mint` type add:

```go
// Policy is what a mint record says about why it was allowed (spec §5.7): the
// subject the principal matched and the grants that selected the device.
type Policy struct {
	Subject string        `json:"subject,omitempty"`
	Grants  []PolicyGrant `json:"grants,omitempty"`
}

// PolicyGrant is one grant that selected the device.
type PolicyGrant struct {
	Scope string   `json:"scope"`
	Roles []string `json:"roles"`
}

// Blob is the `blob` event's body: the compiled blob whole, emitted once per
// hash, so replay depends on the log alone and the store owes the auditor
// nothing (spec §5.1.1; §13, decision 19). Body is the exact bytes the hash
// names.
type Blob struct {
	Hash string          `json:"hash"`
	Body json.RawMessage `json:"body"`
}
```

- [ ] **Step 5: The request carries it to the record**

In `internal/token/minter.go`, in `type Request struct`, after `IdempotencyKey, BodyHash string`
add:

```go
	// Policy is the subject and grants that allowed this mint. The minter
	// judges none of it and copies it onto the mint record (spec §5.7).
	Policy *decision.Policy
```

and in the final `m.log.Emit(decision.Record{...})` of `Mint`, replace

```go
		IndexError: idemErr})
```

with

```go
		Policy:     r.Policy,
		IndexError: idemErr})
```

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/decision/ ./internal/token/ -count=1`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/decision/reasons.go internal/decision/log.go internal/decision/blob_test.go internal/token/minter.go internal/token/policy_test.go
git commit -m "feat: mint records carry their policy, and the blob event its body

Adds candidate_cap_reached after its spec row.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: The slice's blob — one format, content-addressed, and a matcher for a subset of §4

**Files:**
- Create: `internal/blob/blob.go`
- Test: `internal/blob/blob_test.go`

**Interfaces:**
- Produces:
  - `type Blob struct { Platform string; Privilege uint8; Attributes []string; Permit, Deny []string }`
  - `func Encode(b Blob) (body []byte, hash string, err error)`, `func HashOf(body []byte) string`
    (`"sha256:" + hex`)
  - `func Decode(hash string, body []byte) (Blob, error)`; `var ErrHashMismatch`
  - `func CheckRule(rule string) error`, `func Matches(rule string, vector []string) bool`
  - `type Verdict int` with `NoRuleMatched`, `Permitted`, `Denied`; `func (b Blob) Command(vector []string) Verdict`
  Task 5 reads blobs with `Decode` and `Command`; Task 6 validates rules with `CheckRule`; Task 7
  builds `Blob` values; Task 9 writes them with `Encode`.

- [ ] **Step 1: Write the failing tests**

Create `internal/blob/blob_test.go`:

```go
package blob

import (
	"errors"
	"strings"
	"testing"
)

func eos() Blob {
	return Blob{Platform: "arista_eos", Privilege: 15, Attributes: []string{"priv-lvl=15"},
		Permit: []string{"**"}, Deny: []string{"reload **", "show hostname"}}
}

// A blob is named by its content: the same decision encodes to the same bytes
// and the same hash, which is what lets a sweep collapse to one blob per
// platform (spec §5.1.1).
func TestEncodeIsContentAddressed(t *testing.T) {
	b1, h1, err := Encode(eos())
	if err != nil {
		t.Fatal(err)
	}
	b2, h2, _ := Encode(eos())
	if h1 != h2 || string(b1) != string(b2) || !strings.HasPrefix(h1, "sha256:") || h1 != HashOf(b1) {
		t.Fatalf("encode is not stable: %s %s", h1, h2)
	}
	other := eos()
	other.Platform = "cisco_nxos"
	if _, h3, _ := Encode(other); h3 == h1 {
		t.Fatal("two platforms must not share a blob")
	}
}

func TestDecodeRoundTripsAndRefusesATamperedBody(t *testing.T) {
	body, hash, _ := Encode(eos())
	got, err := Decode(hash, body)
	if err != nil || got.Platform != "arista_eos" || got.Privilege != 15 || len(got.Deny) != 2 {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	tampered := []byte(strings.Replace(string(body), `"reload **"`, `"reboot **"`, 1))
	if _, err := Decode(hash, tampered); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("a body that does not hash to its name must be refused: %v", err)
	}
	unknown := []byte(`{"platform":"arista_eos","extra":1}`)
	if _, err := Decode(HashOf(unknown), unknown); err == nil {
		t.Fatal("a blob with a field this daemon does not know must be refused, not half-read")
	}
}

// Spec §4: rules match the whole vector, words case-insensitively, `*` one
// argument, `**` zero or more and only at the end.
func TestMatches(t *testing.T) {
	for _, tt := range []struct {
		rule   string
		vector []string
		want   bool
	}{
		{"show **", []string{"show"}, true},
		{"show **", []string{"show", "version"}, true},
		{"show version", []string{"SHOW", "Version"}, true},
		{"show version", []string{"show", "version", "detail"}, false},
		{"show bgp summary", []string{"show", "bgp"}, false},
		{"clear counters *", []string{"clear", "counters", "Ethernet1"}, true},
		{"clear counters *", []string{"clear", "counters"}, false},
		{"**", nil, true},
		{"reload **", []string{"show", "reload"}, false},
	} {
		if got := Matches(tt.rule, tt.vector); got != tt.want {
			t.Errorf("Matches(%q, %q) = %v, want %v", tt.rule, tt.vector, got, tt.want)
		}
	}
}

// Everything outside the subset is refused by name rather than matched as a
// word: `@physical` read literally would silently never match (spec §4).
func TestCheckRuleRefusesWhatThePolicyEngineOwns(t *testing.T) {
	for _, ok := range []string{"show **", "clear counters *", "**", "show  version"} {
		if err := CheckRule(ok); err != nil {
			t.Errorf("CheckRule(%q): %v", ok, err)
		}
	}
	for rule, want := range map[string]string{
		"":                           "empty",
		"show ** detail":             "trailing-only",
		"interface @physical":        "plan 4",
		"interface /^Ethernet[0-9]/": "plan 4",
		"show int*":                  "whole term",
	} {
		if err := CheckRule(rule); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckRule(%q) = %v, want an error mentioning %q", rule, err, want)
		}
	}
}

// Deny-overrides: a matching deny refuses whatever permit also matches.
func TestCommandVerdicts(t *testing.T) {
	b := eos()
	for _, tt := range []struct {
		vector []string
		want   Verdict
	}{
		{[]string{"show", "version"}, Permitted},
		{[]string{"show", "hostname"}, Denied},
		{[]string{"reload", "now"}, Denied},
	} {
		if got := b.Command(tt.vector); got != tt.want {
			t.Errorf("Command(%q) = %v, want %v", tt.vector, got, tt.want)
		}
	}
	if got := (Blob{Permit: []string{"show **"}}).Command([]string{"configure"}); got != NoRuleMatched {
		t.Errorf("an unmatched command is NoRuleMatched, got %v", got)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/blob/ -count=1`
Expected: FAIL to build — `no non-test Go files in .../internal/blob`.

- [ ] **Step 3: Write the package**

Create `internal/blob/blob.go`:

```go
// Package blob is the compiled decision a token names (spec §5.1.1, §5.1.2),
// in the vertical slice's simplest form. BORROWED AHEAD from plan 4, which
// replaces the format, the rule grammar and the matcher: this one carries a
// platform, a privilege level, the session reply's attributes, and permit and
// deny rules in a strict subset of spec §4. It is content-addressed — the name
// is the hash of the bytes — so a blob is immutable and a sweep across one
// platform writes it once.
package blob

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Blob is one compiled decision for one platform.
type Blob struct {
	// Platform is the device platform the blob was compiled for. The
	// attributes are rendered for it, so two platforms never share a blob.
	Platform string `json:"platform"`
	// Privilege is the level the granted roles compose to, as the priv-lvl
	// number the device is told (spec §6). Zero: no role carried one.
	Privilege uint8 `json:"privilege"`
	// Attributes are the session authorization reply's AV pairs, exactly as
	// they go on the wire.
	Attributes []string `json:"attributes"`
	// Permit and Deny are command rules in the slice's subset of spec §4
	// (CheckRule), sorted, each normalized to single spaces.
	Permit []string `json:"permit"`
	Deny   []string `json:"deny"`
}

// ErrHashMismatch is a stored body that does not hash to the name it was
// stored under. It is a store fault, never a decision.
var ErrHashMismatch = errors.New("blob: body does not match its hash")

// HashOf names a body: "sha256:" and the hex digest of exactly these bytes.
func HashOf(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Encode renders b and names it. encoding/json writes struct fields in
// declaration order, so one Blob value always encodes to the same bytes; the
// caller (policy.Resolve) is what makes one decision one value, by sorting.
func Encode(b Blob) ([]byte, string, error) {
	body, err := json.Marshal(b)
	if err != nil {
		return nil, "", err
	}
	return body, HashOf(body), nil
}

// Decode parses a stored blob. A body that does not hash to its name is
// refused, and so is a field this daemon does not know: half-reading a
// decision a newer broker compiled is how a daemon and a broker come to
// disagree about a rule (spec §5.1.2).
func Decode(hash string, body []byte) (Blob, error) {
	if HashOf(body) != hash {
		return Blob{}, ErrHashMismatch
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	var b Blob
	if err := dec.Decode(&b); err != nil {
		return Blob{}, fmt.Errorf("blob: %s: %w", hash, err)
	}
	return b, nil
}

// CheckRule refuses a rule outside the slice's subset of spec §4: words, `*`
// for one argument, and `**` for zero or more in the last position. An entity
// class or a regex is refused by name — read as a word it would silently never
// match, which is the failure §4 makes a load error.
func CheckRule(rule string) error {
	terms := strings.Fields(rule)
	if len(terms) == 0 {
		return errors.New("blob: an empty rule matches nothing; remove it")
	}
	for i, t := range terms {
		switch {
		case t == "**" && i != len(terms)-1:
			return fmt.Errorf("blob: rule %q: `**` is trailing-only (spec §4)", rule)
		case strings.HasPrefix(t, "@"), len(t) > 1 && strings.HasPrefix(t, "/") && strings.HasSuffix(t, "/"):
			return fmt.Errorf("blob: rule %q: %q is an entity class or a regex, which the policy engine "+
				"compiles (plan 4); the vertical slice matches words, `*` and a trailing `**`", rule, t)
		case t != "*" && t != "**" && strings.Contains(t, "*"):
			return fmt.Errorf("blob: rule %q: %q puts a wildcard inside a word; a wildcard is a whole term (spec §4)", rule, t)
		}
	}
	return nil
}

// Matches reports whether rule matches the whole command vector: there is no
// implicit prefix match (spec §4). Words compare case-insensitively.
func Matches(rule string, vector []string) bool {
	terms := strings.Fields(rule)
	for i, t := range terms {
		if t == "**" {
			return true // trailing-only, by CheckRule
		}
		if i >= len(vector) {
			return false
		}
		if t != "*" && !strings.EqualFold(t, vector[i]) {
			return false
		}
	}
	return len(vector) == len(terms)
}

// Verdict is the slice's command decision.
type Verdict int

const (
	NoRuleMatched Verdict = iota
	Permitted
	Denied
)

// Command decides one command vector, deny-overrides: a matching deny refuses
// whatever permit also matches, and otherwise a matching permit allows. That
// is stricter than spec §5.4's specificity dominance, which plan 4 replaces it
// with: it can only refuse a command dominance would permit, never permit one
// dominance would refuse.
func (b Blob) Command(vector []string) Verdict {
	for _, r := range b.Deny {
		if Matches(r, vector) {
			return Denied
		}
	}
	for _, r := range b.Permit {
		if Matches(r, vector) {
			return Permitted
		}
	}
	return NoRuleMatched
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./internal/blob/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/blob/blob.go internal/blob/blob_test.go
git commit -m "feat: the slice's policy blob, content-addressed, with a subset of the rule grammar

Borrowed ahead from plan 4: platform, privilege, session attributes, and
permit/deny rules of words, * and a trailing **, deny-overrides.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 5: The daemon answers a broker-minted context from its blob

**Files:**
- Create: `internal/daemon/author/blob.go`
- Test: `internal/daemon/author/blob_test.go`

**Interfaces:**
- Consumes: `blob.Decode`, `blob.Blob.Command`, `store.Store.GetBlob`, `author.Authorizer`,
  `author.Lab`.
- Produces: `type Blob struct { Store store.Store; Fallback Authorizer }` implementing
  `author.Authorizer`. Task 11 wires `&author.Blob{Store: st, Fallback: &author.Lab{...}}` in
  `cmd/port49d`.

- [ ] **Step 1: Write the failing tests**

Create `internal/daemon/author/blob_test.go`:

```go
package author

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/store/memory"
)

func blobFixture(t *testing.T) (*Blob, store.Context) {
	t.Helper()
	st := memory.New(time.Now)
	body, hash, err := blob.Encode(blob.Blob{Platform: "arista_eos", Privilege: 15,
		Attributes: []string{"priv-lvl=15"}, Permit: []string{"**"}, Deny: []string{"show hostname"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.PutBlob(context.Background(), hash, body, time.Hour); err != nil {
		t.Fatal(err)
	}
	return &Blob{Store: st, Fallback: &Lab{SessionAttributes: []string{"lab-attr=1"}, DenyPrefixes: []string{"show clock"}}},
		store.Context{CtxID: "c", Username: "alice", BlobHash: hash}
}

// A context the broker minted names its blob, and the session reply is the
// blob's attributes — not the lab's.
func TestABlobContextIsAnsweredFromItsBlob(t *testing.T) {
	a, c := blobFixture(t)
	d := a.Session(context.Background(), c, nil)
	if !d.Permit || d.Reason != decision.ContextMatched || len(d.Attributes) != 1 || d.Attributes[0] != "priv-lvl=15" {
		t.Fatalf("session: %+v", d)
	}
	for _, tt := range []struct {
		vector []string
		permit bool
		reason decision.Reason
	}{
		{[]string{"show", "version"}, true, decision.PermitDominates},
		{[]string{"show", "hostname"}, false, decision.NoPermitDominatesDeny},
		// The lab's own deny list does not apply to a blob context.
		{[]string{"show", "clock"}, true, decision.PermitDominates},
	} {
		d := a.Command(context.Background(), c, tt.vector, nil)
		if d.Permit != tt.permit || d.Reason != tt.reason {
			t.Errorf("Command(%q) = %+v, want permit=%v %s", tt.vector, d, tt.permit, tt.reason)
		}
		if !d.Permit && !strings.HasPrefix(d.ServerMsg, "port49: ") {
			t.Errorf("a denial tells the operator why: %q", d.ServerMsg)
		}
	}
	if d := (&Blob{Store: a.Store, Fallback: a.Fallback}).Command(context.Background(),
		store.Context{BlobHash: c.BlobHash}, []string{"configure"}, nil); !d.Permit {
		t.Fatalf("`**` permits configure: %+v", d)
	}
}

// A blob the store cannot produce, or produces wrong, is blob_unavailable: a
// store fault, alertable on its own, never a policy verdict (spec §5.1.1).
func TestAMissingOrCorruptBlobIsBlobUnavailable(t *testing.T) {
	a, c := blobFixture(t)
	missing := c
	missing.BlobHash = blob.HashOf([]byte("nothing was stored under this"))
	if err := a.Store.PutBlob(context.Background(), "sha256:wrong", []byte(`{"platform":"x"}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	corrupt := c
	corrupt.BlobHash = "sha256:wrong"
	for name, cc := range map[string]store.Context{"missing": missing, "corrupt": corrupt} {
		if d := a.Session(context.Background(), cc, nil); d.Permit || d.Reason != decision.BlobUnavailable {
			t.Errorf("%s: session %+v", name, d)
		}
		if d := a.Command(context.Background(), cc, []string{"show", "version"}, nil); d.Permit || d.Reason != decision.BlobUnavailable {
			t.Errorf("%s: command %+v", name, d)
		}
	}
}

// A context with no blob — the lab's seeded tokens — is the fallback's.
func TestAContextWithNoBlobIsTheFallbacks(t *testing.T) {
	a, _ := blobFixture(t)
	c := store.Context{CtxID: "c", Username: "alice"}
	if d := a.Session(context.Background(), c, nil); !d.Permit || d.Attributes[0] != "lab-attr=1" {
		t.Fatalf("session: %+v", d)
	}
	if d := a.Command(context.Background(), c, []string{"show", "clock"}, nil); d.Permit {
		t.Fatalf("the lab's deny list applies to a seeded context: %+v", d)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/author/ -run 'Blob|Fallback' -count=1`
Expected: FAIL to build — `undefined: Blob`.

- [ ] **Step 3: Write the authorizer**

Create `internal/daemon/author/blob.go`:

```go
package author

import (
	"context"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
)

// Blob answers from the compiled blob a context names (spec §5.1.2): the
// session reply is the blob's attributes, and a command is the blob's rules.
// BORROWED AHEAD from plan 4, whose Authorizer replaces it along with the blob
// format (internal/blob).
//
// A context with no blob hash is Fallback's: the lab's seeded tokens are
// minted without one, and they keep the lab authorizer's answers. A context
// that names a blob the store cannot produce, or produces wrong, is denied
// blob_unavailable — a store fault, never a verdict — and nothing falls back:
// answering a broker-minted session from the lab's permissive list because the
// store hiccuped would be a permit nobody granted.
//
// There is no cache. The store is in-process (plan 3, Decided 1), so a cache
// would be a second copy of the same map; spec §5.1.1's per-replica cache is
// plan 4's, with a store worth caching in front of.
type Blob struct {
	Store    store.Store
	Fallback Authorizer
}

const blobUnavailableMsg = "port49: the policy for this session could not be read - run `port49 token` and log in again"

func (b *Blob) load(ctx context.Context, c store.Context) (blob.Blob, bool) {
	body, err := b.Store.GetBlob(ctx, c.BlobHash)
	if err != nil {
		return blob.Blob{}, false
	}
	bl, err := blob.Decode(c.BlobHash, body)
	return bl, err == nil
}

func (b *Blob) Session(ctx context.Context, c store.Context, args []string) Decision {
	if c.BlobHash == "" {
		return b.fallback().Session(ctx, c, args)
	}
	bl, ok := b.load(ctx, c)
	if !ok {
		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg}
	}
	return Decision{Permit: true, Reason: decision.ContextMatched, Attributes: append([]string(nil), bl.Attributes...)}
}

func (b *Blob) Command(ctx context.Context, c store.Context, vector []string, args []string) Decision {
	if c.BlobHash == "" {
		return b.fallback().Command(ctx, c, vector, args)
	}
	bl, ok := b.load(ctx, c)
	if !ok {
		return Decision{Reason: decision.BlobUnavailable, ServerMsg: blobUnavailableMsg}
	}
	switch bl.Command(vector) {
	case blob.Permitted:
		return Decision{Permit: true, Reason: decision.PermitDominates}
	case blob.Denied:
		return Decision{Reason: decision.NoPermitDominatesDeny, ServerMsg: "port49: denied by policy; see 'port49 explain'"}
	default:
		return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no rule permits this command; see 'port49 explain'"}
	}
}

// fallback is the authorizer for a context with no blob. A nil Fallback
// denies rather than panics: port49 never falls back to permitting everything.
func (b *Blob) fallback() Authorizer {
	if b.Fallback == nil {
		return denyAll{}
	}
	return b.Fallback
}

type denyAll struct{}

func (denyAll) Session(context.Context, store.Context, []string) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}

func (denyAll) Command(context.Context, store.Context, []string, []string) Decision {
	return Decision{Reason: decision.NoRuleMatched, ServerMsg: "port49: no policy for this session"}
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/daemon/author/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/daemon/author/blob.go internal/daemon/author/blob_test.go
git commit -m "feat: answer a broker-minted context from its compiled blob

Seeded contexts, which name no blob, keep the lab authorizer. A blob the
store cannot produce is blob_unavailable and falls back to nothing.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: The file policy loads, and refuses by name everything outside the slice

**Files:**
- Create: `internal/broker/policy/policy.go`
- Test: `internal/broker/policy/policy_test.go`

**Interfaces:**
- Consumes: `blob.CheckRule`, `username.Canonical`.
- Produces: `func Load(path string) (*Policy, error)`; `type Policy` (unexported fields `roles`,
  `subjects`, `byIdentity`, `grants`); the unexported file types `fileRole`, `fileSubject`,
  `fileGrant`; `var levels = map[string]uint8{"readonly": 1, "admin": 15}`; and
  `func (p *Policy) SubjectOf(principal string) (string, bool)` in a one-function `resolve.go`,
  which Task 7 replaces whole with `Resolve` beside it.

- [ ] **Step 1: Write the failing tests**

Create `internal/broker/policy/policy_test.go`:

```go
package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustLoad(t *testing.T, body string) *Policy {
	t.Helper()
	p, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// good is the shape spec §11 writes, cut down to what the slice reads.
const good = `
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: read_only, privilege: readonly, permit: ["show **"]}
  - {name: no_reload, deny: ["reload **"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com", "user:alice@corp.example"], username: alice,
     enable: token, token_ttl: 60s}
  - {name: noc, identity: ["user:bob@example.com"], username: bob, token_ttl: 900s}
  - {name: idle, identity: ["user:dave@example.com"], username: dave, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin, no_reload], max_privilege: admin}
  - {subject: noc, scope: all_devices, roles: [read_only]}
`

func TestAGoodPolicyLoads(t *testing.T) {
	p := mustLoad(t, good)
	if n, ok := p.SubjectOf("user:alice@corp.example"); !ok || n != "netops" {
		t.Fatalf("either identity resolves to the subject (spec §2): %q %v", n, ok)
	}
	if p.subjects["noc"].Enable != "none" {
		t.Fatalf("an unset enable is none — escalation is refused, never guessed (spec §7): %q", p.subjects["noc"].Enable)
	}
}

const roleOK = "roles:\n  - {name: r, privilege: admin, permit: [\"**\"]}\n"
const subjOK = "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 60s}\n"
const grantOK = "grants:\n  - {subject: s, scope: all_devices, roles: [r]}\n"

// Every refusal names what is wrong and, where the slice is the reason, which
// plan lifts it. A key the slice does not read is refused, not ignored: an
// ignored `scopes:` block would be a policy that looks scoped and is not.
func TestLoadRefusesByName(t *testing.T) {
	for _, tt := range []struct{ name, yaml, want string }{
		{"a scopes block", roleOK + subjOK + grantOK + "scopes:\n  - {name: dc, match: {}}\n", "roles, subjects and grants only"},
		{"a group subject", roleOK + "subjects:\n  - {name: s, group: G, username: a, token_ttl: 60s}\n", "field group"},
		{"operator", "roles:\n  - {name: r, privilege: operator}\n", "`operator` has no priv-lvl mapping"},
		{"an unknown level", "roles:\n  - {name: r, privilege: root}\n", "is not a privilege level"},
		{"an entity class", "roles:\n  - {name: r, deny: [\"interface @management\"]}\n", "plan 4"},
		{"a duplicate role", "roles:\n  - {name: r}\n  - {name: r}\n", "declared twice"},
		{"a machine identity", roleOK + "subjects:\n  - {name: s, identity: [\"spiffe://port49/x\"], username: a, token_ttl: 60s}\n", "plan 8"},
		{"no identity", roleOK + "subjects:\n  - {name: s, username: a, token_ttl: 60s}\n", "identity is required"},
		{"one identity, two subjects", roleOK + subjOK + "  - {name: t, identity: [\"user:a@example.com\"], username: b, token_ttl: 60s}\n", "listed by both"},
		{"an upper-case username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: Alice, token_ttl: 60s}\n", "already canonical"},
		{"a DOMAIN username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: 'CORP\\alice', token_ttl: 60s}\n", "already canonical"},
		{"a UPN username", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: alice@corp, token_ttl: 60s}\n", "already canonical"},
		{"a shared username", roleOK + subjOK + "  - {name: t, identity: [\"user:b@example.com\"], username: a, token_ttl: 60s}\n", "unique across subjects"},
		{"enable auto", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, enable: auto, token_ttl: 60s}\n", "restricted"},
		{"enable nonsense", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, enable: maybe, token_ttl: 60s}\n", "none or token"},
		{"a short token_ttl", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a, token_ttl: 10s}\n", "between 30s and 15m0s"},
		{"no token_ttl", roleOK + "subjects:\n  - {name: s, identity: [\"user:a@example.com\"], username: a}\n", "between 30s and 15m0s"},
		{"a grant to nobody", roleOK + subjOK + "grants:\n  - {subject: x, scope: all_devices, roles: [r]}\n", "subject \"x\" is not declared"},
		{"another scope", roleOK + subjOK + "grants:\n  - {subject: s, scope: dc_fabric, roles: [r]}\n", "one scope, all_devices"},
		{"an unknown role", roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [x]}\n", "role \"x\" is not declared"},
		{"a grant with no roles", roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices}\n", "at least one role"},
		{"max_privilege operator", roleOK + subjOK + "grants:\n  - {subject: s, scope: all_devices, roles: [r], max_privilege: operator}\n", "`operator` has no priv-lvl mapping"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(write(t, tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/policy/ -count=1`
Expected: FAIL to build — `no non-test Go files`, then `undefined: Load` once the package exists.

- [ ] **Step 3: Write the loader**

Create `internal/broker/policy/policy.go`:

```go
// Package policy is the vertical slice's file-backed policy (design §19 step
// 3): literal-identity subjects, roles, and grants on the one scope
// `all_devices`. BORROWED AHEAD from plan 4, which replaces it with the policy
// engine. The file is a strict subset of spec §11's format, so a file that
// loads here means the same thing to plan 4; everything outside the subset —
// scopes, groups, `api:` rights, entity classes, regexes, custom privilege
// levels, grant expiry — is refused at load by name rather than ignored. An
// ignored `scopes:` block would be a policy that reads as scoped and is not.
//
// It is read once, when port49d starts. There is no reload, and a restart
// empties the in-process store (plan 3, Question 3).
package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/username"
)

type fileRole struct {
	Name      string   `yaml:"name"`
	Privilege string   `yaml:"privilege"`
	Reason    string   `yaml:"reason"`
	Permit    []string `yaml:"permit"`
	Deny      []string `yaml:"deny"`
}

type fileSubject struct {
	Name     string   `yaml:"name"`
	Identity []string `yaml:"identity"`
	// Username is declared because the slice has no directory to derive a
	// human's from (spec §2). BORROWED AHEAD from plan 7, which derives it
	// through the certificate-to-directory mapping (design §7).
	Username string        `yaml:"username"`
	Enable   string        `yaml:"enable"`
	TokenTTL time.Duration `yaml:"token_ttl"`
}

type fileGrant struct {
	Subject      string   `yaml:"subject"`
	Scope        string   `yaml:"scope"`
	Roles        []string `yaml:"roles"`
	MaxPrivilege string   `yaml:"max_privilege"`
}

type file struct {
	Roles    []fileRole    `yaml:"roles"`
	Subjects []fileSubject `yaml:"subjects"`
	Grants   []fileGrant   `yaml:"grants"`
}

// Policy is a loaded, validated policy file.
type Policy struct {
	roles      map[string]fileRole
	subjects   map[string]fileSubject
	byIdentity map[string]string // identity → subject name
	grants     map[string][]fileGrant
}

// levels is the slice's privilege table: each abstract level (spec §6) to the
// priv-lvl number every platform is told. BORROWED AHEAD from plan 5, whose
// adapters map levels per platform. `operator` is absent on purpose: nothing
// in the lab has measured what it should be, and a level with no mapping is a
// load error (spec §6), not a guess.
var levels = map[string]uint8{"readonly": 1, "admin": 15}

// Design §8: device tokens live 30–900s.
const (
	minTokenTTL = 30 * time.Second
	maxTokenTTL = 900 * time.Second
)

// Load reads and validates the policy file at path.
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("policy: %s: %w; the vertical slice reads roles, subjects and grants only, "+
			"and refuses every other key rather than ignoring it (plan 3)", path, err)
	}
	p, err := build(f)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", path, err)
	}
	return p, nil
}

func build(f file) (*Policy, error) {
	p := &Policy{roles: map[string]fileRole{}, subjects: map[string]fileSubject{},
		byIdentity: map[string]string{}, grants: map[string][]fileGrant{}}
	for i, r := range f.Roles {
		if r.Name == "" {
			return nil, fmt.Errorf("roles[%d]: name is required", i)
		}
		if _, dup := p.roles[r.Name]; dup {
			return nil, fmt.Errorf("role %q is declared twice", r.Name)
		}
		if err := checkLevel(r.Privilege); err != nil {
			return nil, fmt.Errorf("role %q: privilege: %w", r.Name, err)
		}
		for _, rule := range append(append([]string(nil), r.Permit...), r.Deny...) {
			if err := blob.CheckRule(rule); err != nil {
				return nil, fmt.Errorf("role %q: %w", r.Name, err)
			}
		}
		p.roles[r.Name] = r
	}
	users := map[string]string{}
	for i, s := range f.Subjects {
		if s.Name == "" {
			return nil, fmt.Errorf("subjects[%d]: name is required", i)
		}
		if _, dup := p.subjects[s.Name]; dup {
			return nil, fmt.Errorf("subject %q is declared twice", s.Name)
		}
		if len(s.Identity) == 0 {
			return nil, fmt.Errorf("subject %q: identity is required: the vertical slice has no directory, so a "+
				"subject is a list of literal identities (spec §2)", s.Name)
		}
		for _, id := range s.Identity {
			if !strings.HasPrefix(id, "user:") || len(id) == len("user:") {
				return nil, fmt.Errorf("subject %q: identity %q: the vertical slice's one verifier is a human x509 "+
					"certificate, whose principal is `user:<email>` (spec §2); machine identities are plan 8's", s.Name, id)
			}
			if other, dup := p.byIdentity[id]; dup {
				return nil, fmt.Errorf("identity %q is listed by both subject %q and subject %q; a principal must "+
					"resolve to one subject", id, other, s.Name)
			}
			p.byIdentity[id] = s.Name
		}
		if !canonical(s.Username) {
			return nil, fmt.Errorf("subject %q: username %q must be printable ASCII and already canonical — lower "+
				"case, no DOMAIN\\ prefix, no @suffix — because the daemon looks tokens up by the canonical form of "+
				"what the device sends (spec §2)", s.Name, s.Username)
		}
		if other, dup := users[s.Username]; dup {
			return nil, fmt.Errorf("subjects %q and %q both claim username %q; usernames must be unique across "+
				"subjects, or two principals share one (nas, username) context (spec §2)", other, s.Name, s.Username)
		}
		users[s.Username] = s.Name
		switch s.Enable {
		case "":
			s.Enable = "none"
		case "none", "token":
		case "auto":
			return nil, fmt.Errorf("subject %q: `enable: auto` is restricted (spec §5.6, \"Why enable: auto is "+
				"restricted\") and the vertical slice does not offer it; use token or none", s.Name)
		default:
			return nil, fmt.Errorf("subject %q: enable %q: it must be none or token", s.Name, s.Enable)
		}
		if s.TokenTTL < minTokenTTL || s.TokenTTL > maxTokenTTL {
			return nil, fmt.Errorf("subject %q: token_ttl must be between %s and %s (design §8); got %s",
				s.Name, minTokenTTL, maxTokenTTL, s.TokenTTL)
		}
		p.subjects[s.Name] = s
	}
	for i, g := range f.Grants {
		if _, ok := p.subjects[g.Subject]; !ok {
			return nil, fmt.Errorf("grants[%d]: subject %q is not declared", i, g.Subject)
		}
		if g.Scope != "all_devices" {
			return nil, fmt.Errorf("grants[%d]: scope %q: the vertical slice has one scope, all_devices; scopes "+
				"are the policy engine's (plan 4)", i, g.Scope)
		}
		if len(g.Roles) == 0 {
			return nil, fmt.Errorf("grants[%d]: a grant needs at least one role", i)
		}
		for _, r := range g.Roles {
			if _, ok := p.roles[r]; !ok {
				return nil, fmt.Errorf("grants[%d]: role %q is not declared", i, r)
			}
		}
		if err := checkLevel(g.MaxPrivilege); err != nil {
			return nil, fmt.Errorf("grants[%d]: max_privilege: %w", i, err)
		}
		p.grants[g.Subject] = append(p.grants[g.Subject], g)
	}
	return p, nil
}

// checkLevel accepts an empty level (the role or grant sets none) or one the
// slice's table maps.
func checkLevel(name string) error {
	if name == "" {
		return nil
	}
	if _, ok := levels[name]; ok {
		return nil
	}
	if name == "operator" {
		return errors.New("`operator` has no priv-lvl mapping in the vertical slice, and a level with no mapping " +
			"is a load error (spec §6); platform adapters map it (plan 5)")
	}
	return fmt.Errorf("%q is not a privilege level; the vertical slice knows readonly and admin", name)
}

// canonical is the minter's own invariant (token.ErrUsernameNotCanonical),
// checked at load so an operator learns about `Alice` from the file and not
// from a refused mint.
func canonical(u string) bool {
	if u == "" {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] < 0x21 || u[i] > 0x7e {
			return false
		}
	}
	return username.Canonical(u) == u
}
```

- [ ] **Step 4: Add a stub `SubjectOf` so the test builds, and run**

`SubjectOf` belongs to Task 7 but the load test uses it. Create
`internal/broker/policy/resolve.go` with only:

```go
package policy

// SubjectOf names the subject a principal resolves to, if any.
func (p *Policy) SubjectOf(principal string) (string, bool) {
	name, ok := p.byIdentity[principal]
	return name, ok
}
```

Run: `go test ./internal/broker/policy/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/policy/
git commit -m "feat: the slice's file policy, refusing by name what it does not read

Literal-identity subjects with a declared username, roles with readonly
or admin, grants on all_devices. Borrowed ahead from plan 4.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 7: Policy resolves a principal on a platform into a mint and a blob

**Files:**
- Modify: `internal/broker/policy/resolve.go`
- Test: `internal/broker/policy/resolve_test.go`

**Interfaces:**
- Consumes: Task 6's `Policy`, `levels`; `blob.Blob`, `blob.Encode`; `decision.PolicyGrant`.
- Produces:
  ```go
  type Resolution struct {
      Subject, Username, Enable string
      TokenTTL                  time.Duration
      MaxPrivilege              uint8
      Grants                    []decision.PolicyGrant
      Blob                      blob.Blob
  }
  func (p *Policy) Resolve(principal, platform string) (Resolution, bool)
  func (p *Policy) SubjectOf(principal string) (string, bool)
  ```
  `false` means no subject, or a subject holding no grant: `no_grants_matched` (Task 9).

- [ ] **Step 1: Write the failing tests**

Create `internal/broker/policy/resolve_test.go`:

```go
package policy

import (
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/blob"
)

// Spec §5.1: roles are the union across the grants, privilege the max over the
// roles, max_privilege the max over the grants, and the attributes are
// rendered for the device's platform.
func TestResolveComposesTheGrantsForOnePlatform(t *testing.T) {
	p := mustLoad(t, good)
	r, ok := p.Resolve("user:alice@example.com", "arista_eos")
	if !ok || r.Subject != "netops" || r.Username != "alice" || r.Enable != "token" ||
		r.TokenTTL != 60*time.Second || r.MaxPrivilege != 15 {
		t.Fatalf("resolution: %+v %v", r, ok)
	}
	b := r.Blob
	if b.Platform != "arista_eos" || b.Privilege != 15 || len(b.Attributes) != 1 || b.Attributes[0] != "priv-lvl=15" ||
		len(b.Permit) != 1 || b.Permit[0] != "**" || len(b.Deny) != 1 || b.Deny[0] != "reload **" {
		t.Fatalf("blob: %+v", b)
	}
	if len(r.Grants) != 1 || r.Grants[0].Scope != "all_devices" || len(r.Grants[0].Roles) != 2 {
		t.Fatalf("grants on the record: %+v", r.Grants)
	}
}

// One platform's session attributes (plan 3, Decided 6): every other platform
// gets a blob with the same rules and no attributes, and a different hash.
func TestOnlyAristaEOSGetsSessionAttributes(t *testing.T) {
	p := mustLoad(t, good)
	eos, _ := p.Resolve("user:alice@example.com", "arista_eos")
	nx, _ := p.Resolve("user:alice@example.com", "cisco_nxos")
	if len(nx.Blob.Attributes) != 0 || nx.Blob.Privilege != 15 || len(nx.Blob.Deny) != 1 {
		t.Fatalf("nx-os blob: %+v", nx.Blob)
	}
	_, he, _ := blob.Encode(eos.Blob)
	_, hn, _ := blob.Encode(nx.Blob)
	if he == hn {
		t.Fatal("two platforms must not share a blob")
	}
	bob, _ := p.Resolve("user:bob@example.com", "arista_eos")
	if bob.Blob.Privilege != 1 || bob.Blob.Attributes[0] != "priv-lvl=1" || bob.MaxPrivilege != 0 || bob.Enable != "none" {
		t.Fatalf("readonly renders as level 1, and an absent max_privilege is no ceiling: %+v", bob)
	}
}

// The same decision is the same blob: rules are deduplicated, normalized and
// sorted, so role order and repetition across grants do not change the hash.
func TestTheSameDecisionIsTheSameBlob(t *testing.T) {
	p := mustLoad(t, `
roles:
  - {name: a, permit: ["show  version", "show **"]}
  - {name: b, permit: ["show **"], deny: ["reload **"]}
subjects:
  - {name: s, identity: ["user:a@example.com"], username: a, token_ttl: 60s}
  - {name: t, identity: ["user:b@example.com"], username: b, token_ttl: 60s}
grants:
  - {subject: s, scope: all_devices, roles: [a, b]}
  - {subject: s, scope: all_devices, roles: [b]}
  - {subject: t, scope: all_devices, roles: [b, a]}
`)
	s, _ := p.Resolve("user:a@example.com", "arista_eos")
	tt, _ := p.Resolve("user:b@example.com", "arista_eos")
	if len(s.Blob.Permit) != 2 || s.Blob.Permit[0] != "show **" || s.Blob.Permit[1] != "show version" {
		t.Fatalf("permits: %q", s.Blob.Permit)
	}
	_, h1, _ := blob.Encode(s.Blob)
	_, h2, _ := blob.Encode(tt.Blob)
	if h1 != h2 {
		t.Fatalf("one decision, two blobs: %+v vs %+v", s.Blob, tt.Blob)
	}
}

func TestNoSubjectOrNoGrantResolvesToNothing(t *testing.T) {
	p := mustLoad(t, good)
	if _, ok := p.Resolve("user:carol@example.com", "arista_eos"); ok {
		t.Fatal("a principal no subject lists resolves to nothing")
	}
	if _, ok := p.Resolve("user:dave@example.com", "arista_eos"); ok {
		t.Fatal("a subject with no grant resolves to nothing: attached nothing, declared nothing (spec §5.5)")
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/policy/ -run 'Resolve|Blob|Grant|Attributes' -count=1`
Expected: FAIL to build — `p.Resolve undefined`.

- [ ] **Step 3: Write `Resolve`**

Replace the contents of `internal/broker/policy/resolve.go` with:

```go
package policy

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/decision"
)

// Resolution is what one mint needs from policy for one principal on one
// device (spec §5.1): the subject, the device-facing username, the subject's
// ceilings, the grants that selected the device (for the mint record), and
// the compiled blob.
type Resolution struct {
	Subject, Username, Enable string
	TokenTTL                  time.Duration
	MaxPrivilege              uint8
	Grants                    []decision.PolicyGrant
	Blob                      blob.Blob
}

// SubjectOf names the subject a principal resolves to, if any.
func (p *Policy) SubjectOf(principal string) (string, bool) {
	name, ok := p.byIdentity[principal]
	return name, ok
}

// Resolve evaluates spec §5.1 for principal on a device of platform. Every
// grant is on all_devices, so every grant of the subject selects every device
// and the platform is the only fact about the device that matters. false is
// no_grants_matched: no subject lists the principal, or its subject holds no
// grant — the same answer either way (design §17).
func (p *Policy) Resolve(principal, platform string) (Resolution, bool) {
	name, ok := p.byIdentity[principal]
	if !ok {
		return Resolution{}, false
	}
	grants := p.grants[name]
	if len(grants) == 0 {
		return Resolution{}, false
	}
	s := p.subjects[name]
	res := Resolution{Subject: name, Username: s.Username, Enable: s.Enable, TokenTTL: s.TokenTTL}
	seen := map[string]bool{}
	permit, deny := map[string]bool{}, map[string]bool{}
	var level uint8
	for _, g := range grants {
		res.Grants = append(res.Grants, decision.PolicyGrant{Scope: g.Scope, Roles: append([]string(nil), g.Roles...)})
		// Max over the grants; an absent max_privilege is zero, which is no
		// ceiling at all (store.Context.PrivilegeCeiling), not a ceiling of zero.
		if l := levels[g.MaxPrivilege]; l > res.MaxPrivilege {
			res.MaxPrivilege = l
		}
		for _, rn := range g.Roles {
			if seen[rn] {
				continue
			}
			seen[rn] = true
			r := p.roles[rn]
			if l := levels[r.Privilege]; l > level {
				level = l
			}
			for _, x := range r.Permit {
				permit[normalize(x)] = true
			}
			for _, x := range r.Deny {
				deny[normalize(x)] = true
			}
		}
	}
	res.Blob = blob.Blob{Platform: platform, Privilege: level, Attributes: sessionAttributes(platform, level),
		Permit: sorted(permit), Deny: sorted(deny)}
	return res, true
}

// sessionAttributes renders the session authorization reply for one
// platform. BORROWED AHEAD from plan 5: `arista_eos` only, `priv-lvl=N`, which
// vEOS applies on every lab run since 2026-09-20
// (tests/lab/results/L16-arista_eos.md). Every other platform gets no
// attributes — the one reply no measured platform ends a session over — and
// plan 5's adapters fill them in (plan 3, Question 2).
func sessionAttributes(platform string, level uint8) []string {
	if platform == "arista_eos" && level > 0 {
		return []string{"priv-lvl=" + strconv.Itoa(int(level))}
	}
	return nil
}

func normalize(rule string) string { return strings.Join(strings.Fields(rule), " ") }

func sorted(set map[string]bool) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/broker/policy/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/broker/policy/resolve.go internal/broker/policy/resolve_test.go
git commit -m "feat: resolve a principal on a platform into its mint and its blob

Roles union across grants, privilege max over roles, max_privilege max
over grants, rules deduplicated and sorted so one decision is one blob.
Session attributes for arista_eos only, borrowed ahead from plan 5.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 8: Throwaway certificates, and a verified certificate becomes a principal

**Files:**
- Create: `internal/testpki/testpki.go`, `internal/testpki/testpki_test.go`
- Create: `internal/broker/identity.go`
- Test: `internal/broker/identity_test.go`

**Interfaces:**
- Produces (testpki, used by Tasks 9, 10, 11, 12, 14):
  ```go
  type CA struct { Cert *x509.Certificate; Key *ecdsa.PrivateKey }
  func NewCA(cn string, notBefore, notAfter time.Time) (*CA, error)
  type Leaf struct { CommonName string; Emails []string; IPs []net.IP; Client bool; NotBefore, NotAfter time.Time }
  func (ca *CA) Issue(l Leaf) (tls.Certificate, error)   // Leaf field set
  func (ca *CA) Pool() *x509.CertPool
  func (ca *CA) PEM() []byte
  func PEMs(c tls.Certificate) (certPEM, keyPEM []byte, err error)
  const LabCA, LabServerCert, LabServerKey, LabClientCert, LabClientKey = "broker-ca.pem", "broker.pem", "broker-key.pem", "client.pem", "client-key.pem"
  func WriteLab(dir, email string, now time.Time) error
  ```
- Produces (broker): `var ErrUntrusted error`;
  `func Identity(cs *tls.ConnectionState, now time.Time) (string, store.Credential, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/testpki/testpki_test.go`:

```go
package testpki

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// WriteLab's files are what the lab broker and the agent load: the server
// certificate must verify for 127.0.0.1, the client for clientAuth, both
// under the one CA, and the keys must not be readable by anyone else.
func TestWriteLabWritesAUsableSet(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if err := WriteLab(dir, "alice@slice.port49.test", now); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(dir, LabCA))
	if err != nil || !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("ca: %v", err)
	}
	srv, err := tls.LoadX509KeyPair(filepath.Join(dir, LabServerCert), filepath.Join(dir, LabServerKey))
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(srv.Certificate[0])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now}); err != nil || leaf.VerifyHostname("127.0.0.1") != nil {
		t.Fatalf("server certificate: %v", err)
	}
	cli, err := tls.LoadX509KeyPair(filepath.Join(dir, LabClientCert), filepath.Join(dir, LabClientKey))
	if err != nil {
		t.Fatal(err)
	}
	cl, _ := x509.ParseCertificate(cli.Certificate[0])
	if _, err := cl.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil || cl.EmailAddresses[0] != "alice@slice.port49.test" {
		t.Fatalf("client certificate: %v %v", err, cl.EmailAddresses)
	}
	for _, k := range []string{LabServerKey, LabClientKey} {
		if fi, err := os.Stat(filepath.Join(dir, k)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s must be 0600: %v", k, err)
		}
	}
}
```

Create `internal/broker/identity_test.go`:

```go
package broker

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

func TestIdentity(t *testing.T) {
	now := time.Now()
	ca, err := testpki.NewCA("test ca", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(emails ...string) *x509.Certificate {
		c, err := ca.Issue(testpki.Leaf{CommonName: "x", Emails: emails, Client: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		return c.Leaf
	}
	state := func(l *x509.Certificate) *tls.ConnectionState {
		return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{l, ca.Cert}}}
	}

	p, cred, err := Identity(state(leaf("Alice@Example.com")), now)
	if err != nil || p != "user:alice@example.com" {
		t.Fatalf("principal: %q %v", p, err)
	}
	if cred.Method != "cert" || cred.Issuer == "" || cred.Serial == "" || !strings.HasPrefix(cred.Fingerprint, "sha256:") {
		t.Fatalf("credential: %+v", cred)
	}

	for name, tt := range map[string]struct {
		cs  *tls.ConnectionState
		now time.Time
	}{
		"no connection state": {nil, now},
		"no verified chain":   {&tls.ConnectionState{}, now},
		"expired since":       {state(leaf("a@example.com")), now.Add(2 * time.Hour)},
		"no email SAN":        {state(leaf()), now},
		"two email SANs":      {state(leaf("a@example.com", "b@example.com")), now},
	} {
		if _, _, err := Identity(tt.cs, tt.now); !errors.Is(err, ErrUntrusted) {
			t.Errorf("%s: Identity = %v, want ErrUntrusted", name, err)
		}
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/testpki/ ./internal/broker/ -count=1`
Expected: FAIL to build — `no non-test Go files` for both packages.

- [ ] **Step 3: Write `testpki`**

Create `internal/testpki/testpki.go`:

```go
// Package testpki cuts throwaway certificates for tests and for the lab: one
// CA, and leaves for a TLS server and for a client. Nothing in a shipping
// binary imports it, and nothing it writes protects anything real — the lab
// broker listens on the loopback and the files land in a git-ignored
// directory.
package testpki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// CA is a self-signed certificate authority.
type CA struct {
	Cert *x509.Certificate
	Key  *ecdsa.PrivateKey
}

// NewCA makes a CA valid from notBefore to notAfter.
func NewCA(cn string, notBefore, notAfter time.Time) (*CA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn},
		NotBefore: notBefore, NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{Cert: cert, Key: key}, nil
}

// Leaf describes one certificate to issue. Client selects the clientAuth
// extended key usage; otherwise it is serverAuth.
type Leaf struct {
	CommonName          string
	Emails              []string
	IPs                 []net.IP
	Client              bool
	NotBefore, NotAfter time.Time
}

// Issue signs a leaf and returns it ready for crypto/tls, Leaf set.
func (ca *CA) Issue(l Leaf) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	sn, err := serial()
	if err != nil {
		return tls.Certificate{}, err
	}
	eku := x509.ExtKeyUsageServerAuth
	if l.Client {
		eku = x509.ExtKeyUsageClientAuth
	}
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: l.CommonName},
		EmailAddresses: l.Emails, IPAddresses: l.IPs, NotBefore: l.NotBefore, NotAfter: l.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// Pool is a certificate pool holding only this CA.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// PEM is the CA certificate, PEM-encoded.
func (ca *CA) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Cert.Raw})
}

// PEMs renders a leaf as a certificate file and a PKCS#8 key file.
func PEMs(c tls.Certificate) (certPEM, keyPEM []byte, err error) {
	der, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// The file names WriteLab writes, and tests/lab/slice/broker.yaml reads.
const (
	LabCA         = "broker-ca.pem"
	LabServerCert = "broker.pem"
	LabServerKey  = "broker-key.pem"
	LabClientCert = "client.pem"
	LabClientKey  = "client-key.pem"
)

// WriteLab writes the vertical slice's lab PKI into dir: one CA that is both
// the broker's client trust anchor and the issuer of its server certificate
// (for 127.0.0.1), and one client certificate for email. Everything is valid
// for a day from now. Keys are 0600.
func WriteLab(dir, email string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	ca, err := NewCA("port49 lab slice CA", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		return err
	}
	srv, err := ca.Issue(Leaf{CommonName: "port49 lab broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		return err
	}
	cli, err := ca.Issue(Leaf{CommonName: email, Emails: []string{email}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		return err
	}
	files := map[string][]byte{LabCA: ca.PEM()}
	for _, l := range []struct {
		c         tls.Certificate
		cert, key string
	}{{srv, LabServerCert, LabServerKey}, {cli, LabClientCert, LabClientKey}} {
		c, k, err := PEMs(l.c)
		if err != nil {
			return err
		}
		files[l.cert], files[l.key] = c, k
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return fmt.Errorf("testpki: %s: %w", name, err)
		}
	}
	return nil
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
}
```

- [ ] **Step 4: Write `Identity`**

Create `internal/broker/identity.go`:

```go
package broker

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/store"
)

// ErrUntrusted is a caller the trust anchor does not vouch for, now: no
// verified client certificate on the connection, one that has expired since
// the handshake, or one that maps to no principal or to several. It is
// `trust_domain_unresolved` in the log (spec §5.7).
var ErrUntrusted = errors.New("broker: no trusted client certificate")

// Identity maps the connection's verified client certificate to a principal
// (design §7): `user:` and the certificate's one rfc822Name SAN, lower-cased
// (spec §2, the human x509 row). Zero or several email SANs are refused —
// ambiguity fails closed (design §7). An email mapping is a weak mapping and
// must be issuer-pinned; the broker trusts exactly one anchor (LoadTLS), which
// pins it.
//
// It is called per request, against the broker's clock, because the session
// is a held connection and a certificate can expire under it: one that has
// stops minting (spec §13, decision 12), whatever the handshake said.
//
// The credential is identity, not a secret (spec §5.1.4): the certificate's
// fingerprint, issuer, serial and subject, which revocation by certificate
// indexes on.
func Identity(cs *tls.ConnectionState, now time.Time) (string, store.Credential, error) {
	if cs == nil || len(cs.VerifiedChains) == 0 || len(cs.VerifiedChains[0]) == 0 {
		return "", store.Credential{}, fmt.Errorf("%w: the connection presented no certificate the trust anchor verified", ErrUntrusted)
	}
	leaf := cs.VerifiedChains[0][0]
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return "", store.Credential{}, fmt.Errorf("%w: the certificate is valid %s to %s", ErrUntrusted,
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(leaf.EmailAddresses) != 1 {
		return "", store.Credential{}, fmt.Errorf("%w: the certificate carries %d email SANs; exactly one maps to a "+
			"principal", ErrUntrusted, len(leaf.EmailAddresses))
	}
	sum := sha256.Sum256(leaf.Raw)
	cred := store.Credential{Method: "cert", Fingerprint: "sha256:" + hex.EncodeToString(sum[:]),
		Issuer: leaf.Issuer.String(), Serial: leaf.SerialNumber.Text(16), Subject: leaf.Subject.String()}
	return "user:" + strings.ToLower(leaf.EmailAddresses[0]), cred, nil
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/testpki/ ./internal/broker/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/testpki/ internal/broker/identity.go internal/broker/identity_test.go
git commit -m "feat: map a verified client certificate to a user: principal

The one email SAN, lower-cased, checked against the broker's clock on
every request so a certificate that expires under a held connection
stops minting. testpki cuts the certificates tests and the lab use.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 9: `POST /v1/tokens` and `GET /v1/config`

**Files:**
- Create: `internal/broker/api/api.go`
- Create: `internal/broker/broker.go`
- Create: `internal/broker/fixture_test.go`
- Test: `internal/broker/broker_test.go`

**Interfaces:**
- Consumes: `policy.Policy.Resolve`, `policy.Policy.SubjectOf`, `Identity`, `blob.Encode`,
  `token.Minter.Mint`, `token.ErrIdempotencyConflict`, `*token.ErrTooManyOutstanding`,
  `store.Store.PutBlob`, `decision.Record{Policy, Blob}`, `decision.CandidateCapReached`,
  `metrics.Metrics.Decisions`, `admission.Device`, `testpki`.
- Produces:
  - package `api`: `Config{Methods []string; MaxSessionAgeSeconds, BatchMax int}`,
    `MintRequest{Devices []string; Enable bool; TTLSeconds int; Purpose string}`,
    `MintItem{Device, Verdict, Reason, Address, Platform, Username, Login, Enable, ExpiresAt string}`,
    `MintResponse{Principal, Subject string; Results []MintItem}`, `Error{Error, Detail string}`.
  - `type Broker struct { Policy *policy.Policy; Devices map[string]admission.Device; Minter *token.Minter; Store store.Store; Log decision.Emitter; Metrics *metrics.Metrics; Now func() time.Time; MaxSessionAge time.Duration; BatchMax int }`
  - `func (b *Broker) Handler() http.Handler`
  - `func withHeldConn(ctx context.Context) context.Context` — Task 10's `ConnContext`.

- [ ] **Step 1: Write the wire types**

Create `internal/broker/api/api.go`:

```go
// Package api is the broker's wire format (design §17), shared by the broker
// and every client of it — the agent first — so the two cannot drift. Every
// key is snake_case.
package api

// Config is GET /v1/config: discovery data, never fleet information.
type Config struct {
	Methods              []string `json:"methods"`
	MaxSessionAgeSeconds int      `json:"max_session_age_seconds"`
	BatchMax             int      `json:"batch_max"`
}

// MintRequest is POST /v1/tokens. TTLSeconds is a request, not an
// instruction: the broker clamps it to the subject's token_ttl.
type MintRequest struct {
	Devices    []string `json:"devices"`
	Enable     bool     `json:"enable"`
	TTLSeconds int      `json:"ttl_seconds"`
	Purpose    string   `json:"purpose"`
}

// MintItem is one device's answer. Verdict and Reason use the decision log's
// closed vocabulary (spec §5.7), so the response and the audit record agree.
type MintItem struct {
	Device    string `json:"device"`
	Verdict   string `json:"verdict"`
	Reason    string `json:"reason,omitempty"`
	Address   string `json:"address,omitempty"`
	Platform  string `json:"platform,omitempty"`
	Username  string `json:"username,omitempty"`
	Login     string `json:"login,omitempty"`
	Enable    string `json:"enable,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// MintResponse is POST /v1/tokens' 200: partial failure is per item, never at
// the top level (design §17).
type MintResponse struct {
	Principal string     `json:"principal"`
	Subject   string     `json:"subject,omitempty"`
	Results   []MintItem `json:"results"`
}

// Error is every non-200 body.
type Error struct {
	Error  string `json:"error"`
	Detail string `json:"detail,omitempty"`
}
```

- [ ] **Step 2: Write the fixture and the failing tests**

Create `internal/broker/fixture_test.go`:

```go
package broker

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/broker/policy"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/internal/token"
)

const testPolicy = `
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: no_reload, deny: ["reload **"]}
subjects:
  - {name: netops, identity: ["user:alice@example.com"], username: alice, enable: token, token_ttl: 60s}
  - {name: idle, identity: ["user:carol@example.com"], username: carol, token_ttl: 60s}
grants:
  - {subject: netops, scope: all_devices, roles: [network_admin, no_reload], max_privilege: admin}
`

type fixture struct {
	b     *Broker
	st    *memory.Store
	log   *bytes.Buffer
	now   time.Time
	ca    *testpki.CA
	alice tls.Certificate
}

// newFixture's clock starts at the real time: Task 10's handshakes verify
// certificates against it, and the fixture's certificates are cut around it.
func newFixture(t *testing.T, candidateCap int) *fixture {
	t.Helper()
	f := &fixture{log: &bytes.Buffer{}, now: time.Now().Truncate(time.Second)}
	clock := func() time.Time { return f.now }
	f.st = memory.New(clock)
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(testPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.ca, err = testpki.NewCA("port49 test ca", f.now.Add(-time.Hour), f.now.Add(48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	f.alice = f.client(t, "alice@example.com", f.now.Add(24*time.Hour))
	log := decision.NewJSONLines(f.log)
	f.b = &Broker{Policy: pol,
		Devices: map[string]admission.Device{
			"leaf1": {Name: "leaf1", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.11")}},
			"nx1":   {Name: "nx1", Platform: "cisco_nxos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.31")}},
		},
		Minter: token.NewMinter(f.st, log, rand.Reader, token.TagKey([]byte("k")), clock, candidateCap),
		Store:  f.st, Log: log, Metrics: metrics.New(prometheus.NewRegistry()), Now: clock,
		MaxSessionAge: 12 * time.Hour, BatchMax: 4}
	return f
}

func (f *fixture) client(t *testing.T, email string, notAfter time.Time) tls.Certificate {
	t.Helper()
	c, err := f.ca.Issue(testpki.Leaf{CommonName: email, Emails: []string{email}, Client: true,
		NotBefore: f.now.Add(-time.Hour), NotAfter: notAfter})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func (f *fixture) state(c tls.Certificate) *tls.ConnectionState {
	return &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Leaf, f.ca.Cert}}}
}

func (f *fixture) post(ctx context.Context, cs *tls.ConnectionState, body, key string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/tokens", strings.NewReader(body)).WithContext(ctx)
	r.TLS = cs
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, r)
	return w
}

func (f *fixture) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(f.log.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatal(err)
		}
		out = append(out, m)
	}
	return out
}

func decodeMint(t *testing.T, w *httptest.ResponseRecorder) api.MintResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var r api.MintResponse
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func eventsOf(recs []map[string]any, event string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if r["event"] == event {
			out = append(out, r)
		}
	}
	return out
}
```

Create `internal/broker/broker_test.go`:

```go
package broker

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/token"
)

// A batch is answered per item: a granted device gets a pair, an unknown one
// is refused exactly as an ungranted one would be, and each item has its own
// record (design §17).
func TestAMintAnswersEachDeviceOnItsOwn(t *testing.T) {
	f := newFixture(t, 8)
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","ghost"],"enable":true}`, ""))
	if resp.Principal != "user:alice@example.com" || resp.Subject != "netops" || len(resp.Results) != 2 {
		t.Fatalf("response: %+v", resp)
	}
	ok, ghost := resp.Results[0], resp.Results[1]
	if ok.Verdict != "permit" || len(ok.Login) != token.Len || len(ok.Enable) != token.Len || ok.Username != "alice" ||
		ok.Address != "172.100.100.11" || ok.Platform != "arista_eos" || ok.ExpiresAt == "" {
		t.Fatalf("permitted item: %+v", ok)
	}
	if ghost.Verdict != "deny" || ghost.Reason != "no_grants_matched" || ghost.Login != "" || ghost.Address != "" {
		t.Fatalf("an unknown device must look exactly like an ungranted one: %+v", ghost)
	}
	recs := f.records(t)
	mints := eventsOf(recs, "mint")
	if len(mints) != 2 || mints[0]["verdict"] != "permit" || mints[1]["reason"] != "no_grants_matched" {
		t.Fatalf("one mint record per item: %v", mints)
	}
	if p, _ := mints[0]["policy"].(map[string]any); p["subject"] != "netops" {
		t.Fatalf("the permit names its subject: %v", mints[0])
	}
	if strings.Contains(f.log.String(), ok.Login) || strings.Contains(f.log.String(), ok.Enable) {
		t.Fatal("a token reached the log")
	}
	c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
	if len(c) != 2 || c[0].AuthTime.IsZero() || c[0].Credential.Method != "cert" || c[0].BlobHash == "" {
		t.Fatalf("the tokens carry the handshake's auth_time, the certificate, and the blob: %+v", c)
	}
}

func TestAPrincipalWithoutAGrantIsDeniedPerItem(t *testing.T) {
	f := newFixture(t, 8)
	for _, email := range []string{"carol@example.com", "mallory@example.com"} {
		resp := decodeMint(t, f.post(context.Background(), f.state(f.client(t, email, f.now.Add(time.Hour))), `{"devices":["leaf1"]}`, ""))
		if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "no_grants_matched" {
			t.Fatalf("%s: %+v", email, it)
		}
	}
}

// The blob is written once, named by its content, readable by the daemon, and
// emitted into the log the first time it is written (spec §5.1.1).
func TestTheBlobIsWrittenAndEmittedOncePerHash(t *testing.T) {
	f := newFixture(t, 8)
	for i := 0; i < 2; i++ {
		decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1","nx1"]}`, ""))
	}
	recs := f.records(t)
	blobs := eventsOf(recs, "blob")
	if len(blobs) != 2 {
		t.Fatalf("two platforms, two blobs, each emitted once across two batches: %d", len(blobs))
	}
	for _, m := range eventsOf(recs, "mint") {
		mint, _ := m["mint"].(map[string]any)
		hash, _ := mint["blob"].(string)
		body, err := f.st.GetBlob(context.Background(), hash)
		if err != nil {
			t.Fatalf("mint names blob %q the store does not hold: %v", hash, err)
		}
		b, err := blob.Decode(hash, body)
		if err != nil {
			t.Fatal(err)
		}
		dev, _ := m["device"].(map[string]any)
		if dev["name"] == "leaf1" && (len(b.Attributes) != 1 || b.Attributes[0] != "priv-lvl=15") {
			t.Fatalf("leaf1's blob: %+v", b)
		}
	}
}

// No trusted certificate, or one that has expired under the held connection,
// is trust_domain_unresolved: 401, one record, nothing minted.
func TestAnUntrustedCallerIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	short := f.client(t, "alice@example.com", f.now.Add(time.Minute))
	for _, tt := range []struct {
		name  string
		state func() *tls.ConnectionState
	}{
		{"no certificate", func() *tls.ConnectionState { return nil }},
		{"expired since", func() *tls.ConnectionState { f.now = f.now.Add(2 * time.Minute); return f.state(short) }},
	} {
		w := f.post(context.Background(), tt.state(), `{"devices":["leaf1"]}`, "")
		var e api.Error
		_ = json.Unmarshal(w.Body.Bytes(), &e)
		if w.Code != 401 || e.Error != "trust_domain_unresolved" {
			t.Fatalf("%s: %d %s", tt.name, w.Code, w.Body.String())
		}
	}
	for _, m := range eventsOf(f.records(t), "mint") {
		if m["reason"] != "trust_domain_unresolved" {
			t.Fatalf("only refusals: %v", m)
		}
	}
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(c) != 0 {
		t.Fatal("nothing may be minted for an untrusted caller")
	}
}

// A held connection past max_session_age mints nothing: the caller must
// authenticate again (spec §13, decision 17), and the connection is closed so
// the next request is a new handshake.
func TestAConnectionPastTheCeilingIsRefused(t *testing.T) {
	f := newFixture(t, 8)
	ctx := withHeldConn(context.Background())
	decodeMint(t, f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	f.now = f.now.Add(12*time.Hour + time.Second)
	w := f.post(ctx, f.state(f.alice), `{"devices":["leaf1"]}`, "")
	var e api.Error
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if w.Code != 401 || e.Error != "session_expired" || w.Header().Get("Connection") != "close" {
		t.Fatalf("%d %v %s", w.Code, w.Header(), w.Body.String())
	}
	last := f.records(t)[len(f.records(t))-1]
	if last["event"] != "mint" || last["reason"] != "session_expired" || last["principal"] != "user:alice@example.com" {
		t.Fatalf("record: %v", last)
	}
}

// A retry with the same key and body replays the same tokens; the same key
// with another body is a conflict and mints nothing (design §17).
func TestIdempotency(t *testing.T) {
	f := newFixture(t, 8)
	body := `{"devices":["leaf1"]}`
	a := decodeMint(t, f.post(context.Background(), f.state(f.alice), body, "k1"))
	b := decodeMint(t, f.post(context.Background(), f.state(f.alice), body, "k1"))
	if a.Results[0].Login != b.Results[0].Login {
		t.Fatalf("a retry must replay, not mint again: %q vs %q", a.Results[0].Login, b.Results[0].Login)
	}
	if c, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(c) != 1 {
		t.Fatalf("one token minted, %d in the store", len(c))
	}
	if w := f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"],"enable":true}`, "k1"); w.Code != 409 {
		t.Fatalf("same key, different body: %d %s", w.Code, w.Body.String())
	}
}

func TestTheCandidateCapIsReportedPerItem(t *testing.T) {
	f := newFixture(t, 1)
	decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, ""))
	if it := resp.Results[0]; it.Verdict != "deny" || it.Reason != "candidate_cap_reached" {
		t.Fatalf("%+v", it)
	}
	last := f.records(t)[len(f.records(t))-1]
	if last["reason"] != "candidate_cap_reached" {
		t.Fatalf("record: %v", last)
	}
}

func TestMalformedBatchesAreRefusedWhole(t *testing.T) {
	f := newFixture(t, 8)
	for name, body := range map[string]string{
		"no devices":    `{"devices":[]}`,
		"over the cap":  `{"devices":["a","b","c","d","e"]}`,
		"unknown field": `{"devices":["leaf1"],"reusable":true}`,
		"not json":      `devices=leaf1`,
	} {
		if w := f.post(context.Background(), f.state(f.alice), body, ""); w.Code != 400 {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
	}
}

// /v1/config is unauthenticated by necessity and carries no fleet data.
func TestConfigIsDiscoveryOnly(t *testing.T) {
	f := newFixture(t, 8)
	w := httptest.NewRecorder()
	f.b.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/config", nil))
	var c api.Config
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil || w.Code != 200 ||
		len(c.Methods) != 1 || c.Methods[0] != "x509" || c.MaxSessionAgeSeconds != 43200 || c.BatchMax != 4 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "leaf1") {
		t.Fatal("discovery must not name a device")
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/broker/ -count=1`
Expected: FAIL to build — `undefined: Broker`, `undefined: withHeldConn`.

- [ ] **Step 4: Write the broker**

Create `internal/broker/broker.go`:

```go
// Package broker is the vertical slice's broker (design §19 step 3): POST
// /v1/tokens and GET /v1/config, over a held mutual-TLS connection, against
// one trust anchor and the file policy of internal/broker/policy, minting
// through plan 2's token.Minter. It runs inside port49d because the only store
// is in-process (plan 3, Decided 1). Plan 7 builds the broker in full: OIDC,
// the directory, the rest of §17, and the api: rights model — until then a
// principal can only ever mint for itself, which is §17's default.
//
// The broker never writes a login context: the daemon creates it at
// redemption (spec §5.1.1). It writes tokens (through the minter), blobs, and
// the idempotency record.
package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/blob"
	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/broker/policy"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/token"
)

// maxBody bounds a mint request. A batch is capped at BatchMax device names,
// so a megabyte is generous and an unbounded read is a memory hazard (§17).
const maxBody = 1 << 20

// Broker is the slice's broker. Every field is required.
type Broker struct {
	Policy *policy.Policy
	// Devices is the inventory by name: the admission snapshot the daemon
	// admits from (plan 3, Decided 15). A target is named, never addressed,
	// and a name inventory does not know is refused (design §17).
	Devices       map[string]admission.Device
	Minter        *token.Minter
	Store         store.Store
	Log           decision.Emitter
	Metrics       *metrics.Metrics
	Now           func() time.Time
	MaxSessionAge time.Duration
	BatchMax      int

	mu        sync.Mutex
	blobsSeen map[string]bool
}

// Handler routes the two endpoints the slice serves.
func (b *Broker) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/config", b.config)
	mux.HandleFunc("POST /v1/tokens", b.tokens)
	return mux
}

// heldConn is one connection's session state (design §7: on the certificate
// path the agent's session IS the connection). authTime is stamped by the
// first request on it, which the agent sends the moment the handshake
// completes, and never moves (plan 3, Decided 2).
type heldConn struct {
	once sync.Once
	at   time.Time
}

type heldConnKey struct{}

// withHeldConn gives a connection its session state. Server installs it as
// http.Server.ConnContext, so every request on one connection shares it.
func withHeldConn(ctx context.Context) context.Context {
	return context.WithValue(ctx, heldConnKey{}, &heldConn{})
}

// authTime is when this request's connection authenticated. A request with
// no held-connection state — a handler driven without Server — authenticated
// now.
func (b *Broker) authTime(r *http.Request) time.Time {
	h, ok := r.Context().Value(heldConnKey{}).(*heldConn)
	if !ok {
		return b.Now()
	}
	h.once.Do(func() { h.at = b.Now() })
	return h.at
}

func (b *Broker) config(w http.ResponseWriter, r *http.Request) {
	b.authTime(r) // the agent's first request after the handshake stamps the session
	writeJSON(w, http.StatusOK, api.Config{Methods: []string{"x509"},
		MaxSessionAgeSeconds: int(b.MaxSessionAge / time.Second), BatchMax: b.BatchMax})
}

func (b *Broker) tokens(w http.ResponseWriter, r *http.Request) {
	now := b.Now()
	authTime := b.authTime(r)
	principal, cred, err := Identity(r.TLS, now)
	if err != nil {
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.TrustDomainUnresolved, Auth: &decision.Auth{Method: "cert"}})
		writeError(w, http.StatusUnauthorized, string(decision.TrustDomainUnresolved), err.Error())
		return
	}
	if b.MaxSessionAge > 0 && now.Sub(authTime) > b.MaxSessionAge {
		b.emit(decision.Record{TS: now, Event: decision.EventMint, Verdict: decision.VerdictDeny,
			Reason: decision.SessionExpired, Principal: principal, Auth: &decision.Auth{Method: cred.Method}})
		// Closing the connection is what makes the next request a handshake,
		// and the handshake is the fresh authentication decision 17 requires.
		w.Header().Set("Connection", "close")
		writeError(w, http.StatusUnauthorized, string(decision.SessionExpired), fmt.Sprintf(
			"this connection authenticated at %s, more than max_session_age (%s) ago; authenticate again",
			authTime.UTC().Format(time.RFC3339), b.MaxSessionAge))
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeError(w, http.StatusBadRequest, "bad_request", "the request body could not be read or is over 1 MiB")
		return
	}
	var req api.MintRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "the body is not a mint request: "+err.Error())
		return
	}
	if len(req.Devices) == 0 || len(req.Devices) > b.BatchMax {
		writeError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf(
			"name between 1 and %d devices per request; page a larger sweep (design §17)", b.BatchMax))
		return
	}
	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	key := r.Header.Get("Idempotency-Key")

	resp := api.MintResponse{Principal: principal}
	resp.Subject, _ = b.Policy.SubjectOf(principal)
	for _, name := range req.Devices {
		item, err := b.mintOne(r.Context(), principal, cred, authTime, name, req, key, bodyHash)
		if errors.Is(err, token.ErrIdempotencyConflict) {
			writeError(w, http.StatusConflict, "idempotency_conflict",
				"this Idempotency-Key was used with a different body; the first request's result stands (design §17)")
			return
		}
		resp.Results = append(resp.Results, item)
	}
	writeJSON(w, http.StatusOK, resp)
}

// mintOne answers one device. The only error it returns is an idempotency
// conflict, which is the whole request's; every other refusal is an item.
func (b *Broker) mintOne(ctx context.Context, principal string, cred store.Credential, authTime time.Time,
	name string, req api.MintRequest, key, bodyHash string) (api.MintItem, error) {
	deny := func(reason decision.Reason, platform string) api.MintItem {
		b.emit(decision.Record{TS: b.Now(), Event: decision.EventMint, Verdict: decision.VerdictDeny, Reason: reason,
			Principal: principal, Auth: &decision.Auth{Method: cred.Method},
			Device: &decision.Device{Name: name, Platform: platform}})
		return api.MintItem{Device: name, Verdict: decision.VerdictDeny, Reason: string(reason)}
	}
	dev, ok := b.Devices[name]
	if !ok {
		// The same answer as a device with no grant: the API must not tell a
		// caller which devices exist (design §17). The record names the
		// device and no platform, which is what tells an operator which.
		return deny(decision.NoGrantsMatched, ""), nil
	}
	res, ok := b.Policy.Resolve(principal, dev.Platform)
	if !ok {
		return deny(decision.NoGrantsMatched, dev.Platform), nil
	}
	hash, err := b.putBlob(ctx, res.Blob)
	if err != nil {
		return deny(decision.StoreUnavailable, dev.Platform), nil
	}
	out, err := b.Minter.Mint(ctx, token.Request{
		Subject: token.Subject{Principal: principal, Username: res.Username, TokenTTL: res.TokenTTL,
			Enable: res.Enable, MaxPrivilege: res.MaxPrivilege, MaxSessionAge: b.MaxSessionAge,
			Credential: cred, AuthTime: authTime},
		Device: name, Platform: dev.Platform, BlobHash: hash, WithEnable: req.Enable,
		TTL:            time.Duration(req.TTLSeconds) * time.Second,
		IdempotencyKey: key, BodyHash: bodyHash,
		Policy: &decision.Policy{Subject: res.Subject, Grants: res.Grants}})
	var capped *token.ErrTooManyOutstanding
	switch {
	case errors.Is(err, token.ErrIdempotencyConflict):
		return api.MintItem{}, err
	case errors.As(err, &capped):
		return deny(decision.CandidateCapReached, dev.Platform), nil
	case err != nil:
		return deny(decision.StoreUnavailable, dev.Platform), nil
	}
	// The minter emitted the permit record; the counter is the broker's. An
	// idempotent replay is counted again: it is a permit answered.
	b.Metrics.Decisions.WithLabelValues(decision.EventMint, decision.VerdictPermit, string(decision.GrantsMatched)).Inc()
	item := api.MintItem{Device: name, Verdict: decision.VerdictPermit, Platform: dev.Platform,
		Username: out.Username, Login: out.Login, Enable: out.Enable, ExpiresAt: out.ExpiresAt.UTC().Format(time.RFC3339)}
	if len(dev.Addresses) > 0 {
		// A fact from the source of truth; the client must not trust it
		// further than an SSH host key (design §17).
		item.Address = dev.Addresses[0].String()
	}
	return item, nil
}

// putBlob writes a blob under its hash and emits it into the log the first
// time this process writes it (spec §5.1.1; §13, decision 19). Its store TTL is
// max_session_age: a context's session_expires is its auth_time plus that, and
// auth_time is never later than the mint, so no context this blob backs can
// outlive it. PutBlob keeps the later expiry, so a re-put never shortens it.
// The emitted set dies with the process, and so does the in-process store,
// so once per process is once per store (plan 3, Decided 8).
func (b *Broker) putBlob(ctx context.Context, bl blob.Blob) (string, error) {
	body, hash, err := blob.Encode(bl)
	if err != nil {
		return "", err
	}
	if err := b.Store.PutBlob(ctx, hash, body, b.MaxSessionAge); err != nil {
		return "", err
	}
	b.mu.Lock()
	if b.blobsSeen == nil {
		b.blobsSeen = map[string]bool{}
	}
	first := !b.blobsSeen[hash]
	b.blobsSeen[hash] = true
	b.mu.Unlock()
	if first {
		b.Log.Emit(decision.Record{TS: b.Now(), Event: decision.EventBlob, Blob: &decision.Blob{Hash: hash, Body: body}})
	}
	return hash, nil
}

// emit writes a refusal the broker decided itself, and counts it.
func (b *Broker) emit(r decision.Record) {
	b.Log.Emit(r)
	b.Metrics.Decisions.WithLabelValues(r.Event, r.Verdict, string(r.Reason)).Inc()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, errCode, detail string) {
	writeJSON(w, code, api.Error{Error: errCode, Detail: detail})
}
```

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/broker/ -count=1 && go test -race ./internal/broker/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/broker/
git commit -m "feat: the broker mints per item over POST /v1/tokens

Identity from the verified certificate on every request, policy
resolution, one blob per hash written and emitted once, the minter for
the tokens, idempotency by key and body, the candidate cap and the
session ceiling as their own reasons. GET /v1/config is discovery only.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 10: The broker serves over mutual TLS, and the session is the connection

**Files:**
- Create: `internal/broker/server.go`
- Modify: `internal/broker/fixture_test.go` (a locked clock)
- Test: `internal/broker/server_test.go`

**Interfaces:**
- Consumes: Task 9's `Broker`, `withHeldConn`; `testpki`.
- Produces: `func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) *http.Server`
  (serve with `ServeTLS(ln, "", "")`); `func LoadTLS(certFile, keyFile, anchorFile string) (tls.Certificate, *x509.CertPool, error)`.
  Task 11 calls both.

- [ ] **Step 1: Give the fixture a clock the race detector accepts**

The server tests move the clock between requests the server goroutine handles, and a socket is no
happens-before edge the race detector can see. In `internal/broker/fixture_test.go`, add `"sync"` to
the imports, add a field `mu sync.Mutex` to `type fixture struct`, replace

```go
	clock := func() time.Time { return f.now }
```

with

```go
	clock := func() time.Time {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.now
	}
```

and add below `newFixture`:

```go
// advance moves the clock under the lock, for tests where a server goroutine
// reads it. Single-goroutine tests may still assign f.now directly.
func (f *fixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}
```

- [ ] **Step 2: Write the failing tests**

Create `internal/broker/server_test.go`:

```go
package broker

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/store"
	"github.com/rhwendt/port49/internal/testpki"
)

func startServer(t *testing.T, f *fixture) string {
	t.Helper()
	now := f.b.Now()
	srvCert, err := f.ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	srv := f.b.Server("127.0.0.1:0", srvCert, f.ca.Pool())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { _ = srv.Close() })
	return "https://" + ln.Addr().String()
}

func clientWith(f *fixture, certs ...tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: certs, RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13}}}
}

// The agent's session is one connection (design §7): the first request after
// the handshake stamps auth_time, and every mint on the connection carries it
// however long after — which is what makes session_expires the handshake plus
// max_session_age (plan 3, Decided 2).
func TestEveryMintOnAHeldConnectionCarriesItsHandshakeTime(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	c := clientWith(f, f.alice)
	var reused []bool
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { reused = append(reused, i.Reused) }})
	do := func(method, path, body string) {
		t.Helper()
		req, _ := http.NewRequestWithContext(ctx, method, url+path, strings.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		// Read to EOF before closing, or the transport cannot reuse the
		// connection and every request is a new handshake.
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: %s", method, path, resp.Status)
		}
	}
	handshake := f.b.Now()
	do("GET", "/v1/config", "")
	for i := 0; i < 2; i++ {
		f.advance(time.Hour)
		do("POST", "/v1/tokens", `{"devices":["leaf1"]}`)
		// Read each mint while it is live: the token TTL is a minute, and the
		// hour between mints is the point.
		toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"})
		if len(toks) != 1 || !toks[0].AuthTime.Equal(handshake) {
			t.Fatalf("mint %d, %d live token(s): auth_time must be the handshake's %v, an hour or two on: %+v",
				i+1, len(toks), handshake, toks)
		}
	}
	if len(reused) != 3 || reused[0] || !reused[1] || !reused[2] {
		t.Fatalf("three requests, one connection: reused %v", reused)
	}
}

// An untrusted certificate fails at the handshake, so `port49 login` fails
// there rather than at the first mint (plan 3, Decided 3), and nothing is
// minted or recorded as a mint.
func TestACertificateFromAnotherCAFailsTheHandshake(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	now := f.b.Now()
	other, err := testpki.NewCA("someone else's CA", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := other.Issue(testpki.Leaf{CommonName: "m", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	// Presented whatever the broker's CA hint says, as the agent presents it
	// (Task 12): Go's default would send nothing for a certificate the hint
	// does not name, and the handshake would succeed with no identity.
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.ca.Pool(), MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &mallory, nil }}}}
	if resp, err := c.Get(url + "/v1/config"); err == nil {
		resp.Body.Close()
		t.Fatal("a certificate the anchor does not vouch for must fail the handshake")
	}
	if len(eventsOf(f.records(t), "mint")) != 0 {
		t.Fatalf("no mint was attempted: %v", f.records(t))
	}
}

// /v1/config needs no certificate; /v1/tokens does.
func TestWithoutACertificateOnlyConfigAnswers(t *testing.T) {
	f := newFixture(t, 8)
	url := startServer(t, f)
	c := clientWith(f)
	resp, err := c.Get(url + "/v1/config")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("config without a certificate: %v %v", resp, err)
	}
	resp.Body.Close()
	resp, err = c.Post(url+"/v1/tokens", "application/json", strings.NewReader(`{"devices":["leaf1"]}`))
	if err != nil || resp.StatusCode != 401 {
		t.Fatalf("a mint without a certificate: %v %v", resp, err)
	}
	resp.Body.Close()
}

// One trust anchor, exactly: a bundle would silently widen who the email
// mapping trusts (design §7, weak mappings are issuer-pinned).
func TestLoadTLSTakesExactlyOneAnchor(t *testing.T) {
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	p := func(n string) string { return filepath.Join(dir, n) }
	if _, _, err := LoadTLS(p(testpki.LabServerCert), p(testpki.LabServerKey), p(testpki.LabCA)); err != nil {
		t.Fatal(err)
	}
	two := filepath.Join(dir, "two.pem")
	a, _ := os.ReadFile(p(testpki.LabCA))
	other, _ := testpki.NewCA("second", time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err := os.WriteFile(two, append(a, other.PEM()...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadTLS(p(testpki.LabServerCert), p(testpki.LabServerKey), two); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("two anchors: %v", err)
	}
	if _, _, err := LoadTLS(p(testpki.LabServerCert), p(testpki.LabServerKey), p(testpki.LabServerKey)); err == nil {
		t.Fatal("a file with no certificate is not an anchor")
	}
}
```

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'HeldConnection|AnotherCA|WithoutACertificate|LoadTLS' -count=1`
Expected: FAIL to build — `f.b.Server undefined`, `undefined: LoadTLS`.

- [ ] **Step 4: Write the server**

Create `internal/broker/server.go`:

```go
package broker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// Server serves the broker over mutual TLS on addr; call ServeTLS(ln, "", "").
//
// The client certificate is requested and, when given, verified against the
// one anchor at the handshake (VerifyClientCertIfGiven): /v1/config is
// unauthenticated by necessity (design §17), and an untrusted certificate
// fails `port49 login` at once instead of at the first mint. /v1/tokens then
// checks the verified certificate again on every request (Identity).
//
// The agent's session IS the connection (design §7; spec §13, decision 17),
// so the server does not close one for being idle before max_session_age: an
// operator who mints at 09:00 and again at 15:00 is on one handshake.
// ConnContext gives each connection the state that stamps its auth_time.
// HTTP/1.1 only, so a connection is one ordered stream of requests.
//
// The handshake verifies validity against the broker's own clock, the one
// Identity checks per request against, so the two never disagree.
func (b *Broker) Server(addr string, cert tls.Certificate, anchor *x509.CertPool) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: b.Handler(),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			ClientCAs:    anchor,
			ClientAuth:   tls.VerifyClientCertIfGiven,
			NextProtos:   []string{"http/1.1"},
			Time:         b.Now,
		},
		ConnContext:       func(ctx context.Context, _ net.Conn) context.Context { return withHeldConn(ctx) },
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       b.MaxSessionAge,
	}
}

// LoadTLS reads the broker's server certificate and its one client trust
// anchor (design §19 step 3). The anchor file must hold exactly one
// certificate: one anchor is what pins the issuer of the email mapping
// (Identity), and a bundle would widen it without anyone deciding to.
func LoadTLS(certFile, keyFile, anchorFile string) (tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("broker: server certificate: %w", err)
	}
	raw, err := os.ReadFile(anchorFile)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file: %w", err)
	}
	var anchors []*x509.Certificate
	rest := raw
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file %s: %w", anchorFile, err)
		}
		anchors = append(anchors, c)
	}
	if len(anchors) != 1 {
		return tls.Certificate{}, nil, fmt.Errorf("broker: client_ca_file %s holds %d certificates; the vertical "+
			"slice trusts exactly one anchor (design §19 step 3)", anchorFile, len(anchors))
	}
	pool := x509.NewCertPool()
	pool.AddCert(anchors[0])
	return cert, pool, nil
}
```

- [ ] **Step 5: Run the package**

Run: `go test ./internal/broker/... -count=1 && go test -race ./internal/broker/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/broker/server.go internal/broker/server_test.go internal/broker/fixture_test.go
git commit -m "feat: serve the broker over mutual TLS with the session held in the connection

VerifyClientCertIfGiven against exactly one anchor, TLS 1.3, no idle
close before max_session_age, and auth_time stamped once per connection.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 11: `port49d` runs the broker when `broker:` is configured

**Files:**
- Modify: `internal/config/config.go` (`BrokerConfig`, `fileConfig.Broker`, `Config.Broker`, `Load`)
- Test: `internal/config/broker_test.go`
- Modify: `cmd/port49d/main.go` (`author.Blob`, `buildBroker`, the listener)
- Test: `cmd/port49d/broker_test.go`

**Interfaces:**
- Consumes: `policy.Load`, `broker.LoadTLS`, `(*broker.Broker).Server`, `author.Blob`,
  `author.Lab`, `admission.Inventory.Devices`.
- Produces: `type config.BrokerConfig struct { Listen, TLSCertFile, TLSKeyFile, ClientCAFile, PolicyFile string; BatchMax int }`
  (yaml `listen`, `tls_cert_file`, `tls_key_file`, `client_ca_file`, `policy_file`, `batch_max`);
  `config.Config.Broker *BrokerConfig` (nil: no broker);
  `func buildBroker(cfg config.Config, st store.Store, minter *token.Minter, log decision.Emitter, m *metrics.Metrics) (*http.Server, error)`.

- [ ] **Step 1: Write the failing config tests**

Create `internal/config/broker_test.go`:

```go
package config

import (
	"fmt"
	"strings"
	"testing"
)

const brokerBlock = `broker:
  listen: "127.0.0.1:8449"
  tls_cert_file: /etc/port49/broker.pem
  tls_key_file: /etc/port49/broker-key.pem
  client_ca_file: /etc/port49/clients-ca.pem
  policy_file: /etc/port49/policy.yaml
`

func loadWith(t *testing.T, extra string) (Config, error) {
	t.Helper()
	setKeyEnv(t)
	return Load(write(t, "port49d.yaml", fmt.Sprintf(sample, write(t, "inv.yaml", inv))+extra))
}

func TestNoBrokerBlockIsNoBroker(t *testing.T) {
	c, err := loadWith(t, "")
	if err != nil || c.Broker != nil {
		t.Fatalf("broker %+v err %v", c.Broker, err)
	}
}

func TestABrokerBlockLoads(t *testing.T) {
	c, err := loadWith(t, brokerBlock)
	if err != nil {
		t.Fatal(err)
	}
	if b := c.Broker; b == nil || b.Listen != "127.0.0.1:8449" || b.PolicyFile != "/etc/port49/policy.yaml" || b.BatchMax != 100 {
		t.Fatalf("broker: %+v", c.Broker)
	}
}

// Every file is required: a broker with no trust anchor is not a broker that
// trusts nobody, it is a config mistake, and it is refused at start.
func TestABrokerBlockMissingAKeyIsRefused(t *testing.T) {
	for _, key := range []string{"listen", "tls_cert_file", "tls_key_file", "client_ca_file", "policy_file"} {
		var kept []string
		for _, line := range strings.Split(brokerBlock, "\n") {
			if !strings.HasPrefix(strings.TrimSpace(line), key+":") {
				kept = append(kept, line)
			}
		}
		if _, err := loadWith(t, strings.Join(kept, "\n")); err == nil || !strings.Contains(err.Error(), "broker."+key) {
			t.Errorf("without %s: %v", key, err)
		}
	}
}

func TestBatchMaxIsBounded(t *testing.T) {
	if _, err := loadWith(t, brokerBlock+"  batch_max: 5000\n"); err == nil || !strings.Contains(err.Error(), "batch_max") {
		t.Fatalf("batch_max 5000: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/config/ -run 'Broker|BatchMax' -count=1`
Expected: FAIL — `c.Broker undefined`, and the block itself is refused `field broker not found`.

- [ ] **Step 3: The config block**

In `internal/config/config.go`, after `type TokenConfig struct {...}` add:

```go
// BrokerConfig is the vertical slice's broker (design §19 step 3), served by
// port49d on a second listener because the store is in-process (plan 3,
// Decided 1). Absent, port49d runs no broker, as before.
//
// The policy file is read once, at start, and the store is in memory: a
// policy edit needs a restart, and a restart ends every live login context
// and every unspent token — every operator logs in again (plan 3,
// Question 3). Plan 4 brings reload.
type BrokerConfig struct {
	Listen      string `yaml:"listen"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// ClientCAFile is the one trust anchor client certificates are verified
	// against. It must hold exactly one certificate (broker.LoadTLS).
	ClientCAFile string `yaml:"client_ca_file"`
	PolicyFile   string `yaml:"policy_file"`
	// BatchMax caps the devices in one mint request; a larger sweep pages
	// (design §17). Default 100.
	BatchMax int `yaml:"batch_max"`
}
```

In `type fileConfig struct`, after `Token          TokenConfig               \`yaml:"token"\`` add

```go
	Broker         *BrokerConfig             `yaml:"broker"`
```

In `type Config struct`, after `Token          TokenConfig` add

```go
	// Broker is nil when no broker: block is configured.
	Broker         *BrokerConfig
```

In `Load` — not in `Keyring`, which has a loop of the same spelling — directly before the loop
`for ref, ks := range c.Keys {` whose first line is `seen := map[int]bool{}`, add:

```go
	if f.Broker != nil {
		b := *f.Broker
		for _, req := range []struct{ key, v string }{
			{"broker.listen", b.Listen}, {"broker.tls_cert_file", b.TLSCertFile}, {"broker.tls_key_file", b.TLSKeyFile},
			{"broker.client_ca_file", b.ClientCAFile}, {"broker.policy_file", b.PolicyFile},
		} {
			if req.v == "" {
				return Config{}, fmt.Errorf("config: %s is required when broker: is present; remove the block to run "+
					"port49d without a broker", req.key)
			}
		}
		b.BatchMax = orI(b.BatchMax, 100)
		if b.BatchMax < 1 || b.BatchMax > 1000 {
			return Config{}, fmt.Errorf("config: broker.batch_max must be between 1 and 1000; got %d", b.BatchMax)
		}
		c.Broker = &b
	}
```

Run: `go test ./internal/config/ -count=1`
Expected: PASS.

- [ ] **Step 4: Write the failing wiring tests**

Create `cmd/port49d/broker_test.go`:

```go
package main

import (
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rhwendt/port49/internal/admission"
	"github.com/rhwendt/port49/internal/config"
	"github.com/rhwendt/port49/internal/daemon/metrics"
	"github.com/rhwendt/port49/internal/decision"
	"github.com/rhwendt/port49/internal/store/memory"
	"github.com/rhwendt/port49/internal/testpki"
)

func brokerConfig(t *testing.T, policyBody string) config.Config {
	t.Helper()
	dir := t.TempDir()
	if err := testpki.WriteLab(dir, "alice@example.com", time.Now()); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, []byte(policyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.Config{
		Session:   config.SessionConfig{MaxSessionAgeDefault: time.Hour},
		Inventory: admission.Inventory{Devices: []admission.Device{{Name: "leaf1", Platform: "arista_eos"}}},
		Broker: &config.BrokerConfig{Listen: "127.0.0.1:0", TLSCertFile: filepath.Join(dir, testpki.LabServerCert),
			TLSKeyFile: filepath.Join(dir, testpki.LabServerKey), ClientCAFile: filepath.Join(dir, testpki.LabCA),
			PolicyFile: pol, BatchMax: 10},
	}
}

const minimalPolicy = `
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
`

func buildWith(cfg config.Config) error {
	_, err := buildBroker(cfg, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	return err
}

func TestNoBrokerBlockBuildsNoBroker(t *testing.T) {
	srv, err := buildBroker(config.Config{}, nil, nil, nil, nil)
	if srv != nil || err != nil {
		t.Fatalf("%v %v", srv, err)
	}
}

func TestABrokerBuildsFromItsFiles(t *testing.T) {
	srv, err := buildBroker(brokerConfig(t, minimalPolicy), memory.New(time.Now), seedMinter(),
		decision.NewJSONLines(io.Discard), metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Addr != "127.0.0.1:0" || srv.TLSConfig.ClientAuth != tls.VerifyClientCertIfGiven ||
		srv.TLSConfig.MinVersion != tls.VersionTLS13 || srv.IdleTimeout != time.Hour {
		t.Fatalf("server: %+v", srv)
	}
}

// Everything that can fail on a typo fails before a listener opens.
func TestABrokerThatCannotLoadFailsTheStart(t *testing.T) {
	if err := buildWith(brokerConfig(t, "roles: [{name: r, privilege: operator}]\n")); err == nil ||
		!strings.Contains(err.Error(), "operator") {
		t.Fatalf("a bad policy: %v", err)
	}
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Broker.ClientCAFile = cfg.Broker.TLSKeyFile
	if err := buildWith(cfg); err == nil {
		t.Fatal("a trust anchor file with no certificate must fail the start")
	}
}
```

Run: `go test ./cmd/port49d/ -count=1`
Expected: FAIL to build — `undefined: buildBroker`.

- [ ] **Step 5: Wire it**

In `cmd/port49d/main.go`, add to the imports `"github.com/rhwendt/port49/internal/admission"`,
`"github.com/rhwendt/port49/internal/broker"` and `"github.com/rhwendt/port49/internal/broker/policy"`.

Add, above `func run`:

```go
// buildBroker loads what the broker needs and returns its server, or nil when
// no broker: block is configured. It runs before any listener opens, so a
// policy typo or an unreadable certificate ends the start with one line
// rather than surfacing at the first mint.
func buildBroker(cfg config.Config, st store.Store, minter *token.Minter, log decision.Emitter,
	m *metrics.Metrics) (*http.Server, error) {
	if cfg.Broker == nil {
		return nil, nil
	}
	pol, err := policy.Load(cfg.Broker.PolicyFile)
	if err != nil {
		return nil, err
	}
	cert, anchor, err := broker.LoadTLS(cfg.Broker.TLSCertFile, cfg.Broker.TLSKeyFile, cfg.Broker.ClientCAFile)
	if err != nil {
		return nil, err
	}
	devices := make(map[string]admission.Device, len(cfg.Inventory.Devices))
	for _, d := range cfg.Inventory.Devices {
		devices[d.Name] = d
	}
	b := &broker.Broker{Policy: pol, Devices: devices, Minter: minter, Store: st, Log: log, Metrics: m,
		Now: time.Now, MaxSessionAge: cfg.Session.MaxSessionAgeDefault, BatchMax: cfg.Broker.BatchMax}
	return b.Server(cfg.Broker.Listen, cert, anchor), nil
}
```

In `run`, replace

```go
	// The lab authorizer is the only authorizer until the policy engine lands
	// (plan 4); config.Load refuses a config without it, so it is never nil and
	// port49 never falls back to permitting everything.
	authz := &author.Lab{
		SessionAttributes: cfg.Lab.SessionAttributes,
		CommandAttributes: cfg.Lab.CommandAttributes,
		DenyPrefixes:      cfg.Lab.DenyPrefixes,
	}
```

with

```go
	// A context the broker minted names a compiled blob and is answered from
	// it (plan 3). A context with no blob — the lab's seeds — is answered by
	// the lab authorizer, which stays until the policy engine lands (plan 4);
	// config.Load refuses a config without it, so the fallback is never nil and
	// port49 never falls back to permitting everything.
	authz := &author.Blob{Store: st, Fallback: &author.Lab{
		SessionAttributes: cfg.Lab.SessionAttributes,
		CommandAttributes: cfg.Lab.CommandAttributes,
		DenyPrefixes:      cfg.Lab.DenyPrefixes,
	}}
```

Replace

```go
	// Plan 7's broker exposes Refresh, RevokeByPrincipal and RevokeBySID over
	// HTTP. Nothing in this binary calls them yet; the Manager is built here so
	// the wiring is proven by the compiler rather than by plan 7 discovering it.
	sessions := session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	_ = sessions
```

with

```go
	// Plan 7's broker exposes Refresh, RevokeByPrincipal and RevokeBySID over
	// HTTP; plan 3's serves /v1/tokens and /v1/config only, so nothing in this
	// binary calls them yet. The Manager is built here so the wiring is proven
	// by the compiler rather than by plan 7 discovering it.
	sessions := session.New(st, time.Now, cfg.ContextIdleTTL, cfg.Session.IndexTTL)
	_ = sessions

	brokerSrv, err := buildBroker(cfg, st, minter, log, m)
	if err != nil {
		stopSpool()
		<-spoolDone
		return err
	}
```

After the block that opens the TACACS+ listener and prints `port49d: listening on ...`, add:

```go
	brokerErr := make(chan error, 1)
	if brokerSrv != nil {
		bln, err := net.Listen("tcp", brokerSrv.Addr)
		if err != nil {
			ln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("broker listener on %s: %w", brokerSrv.Addr, err)
		}
		go func() { brokerErr <- brokerSrv.ServeTLS(bln, "", "") }()
		fmt.Fprintf(os.Stderr, "port49d: broker listening on %s\n", brokerSrv.Addr)
	}
```

In the `select`, after the `case err := <-metricsErr:` arm, add:

```go
	case err := <-brokerErr:
		runErr = fmt.Errorf("broker listener on %s: %w", cfg.Broker.Listen, err)
		cancel()
		<-serveErr
```

and directly after the `cancel()` that follows the `select`, add:

```go
	if brokerSrv != nil {
		shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
		_ = brokerSrv.Shutdown(shutdownCtx)
		done()
	}
```

- [ ] **Step 6: Run everything this touches**

Run: `go test ./internal/config/ ./cmd/port49d/ -count=1 && go build ./... && make vet`
Expected: PASS, and `make vet` prints nothing.

- [ ] **Step 7: Commit**

```bash
git add internal/config/config.go internal/config/broker_test.go cmd/port49d/main.go cmd/port49d/broker_test.go
git commit -m "feat: run the broker inside port49d when broker: is configured

The policy file and the TLS material load before any listener opens.
Broker-minted contexts are answered from their blob; seeded ones keep
the lab authorizer.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 12: The agent holds the session and mints fresh on every ask

**Files:**
- Create: `internal/agent/agent.go`, `internal/agent/socket.go`
- Test: `internal/agent/agent_test.go`

**Interfaces:**
- Consumes: `api.Config`, `api.MintRequest`, `api.MintResponse`, `api.MintItem`, `api.Error`;
  `testpki` (tests).
- Produces:
  ```go
  type Config struct { BrokerURL string; Cert tls.Certificate; BrokerCA *x509.CertPool; Now func() time.Time; Log io.Writer }
  func New(c Config) *Agent
  func (a *Agent) Connect(ctx context.Context) (api.Config, error)
  func (a *Agent) Mint(ctx context.Context, device string, enable bool, ttl time.Duration) (api.MintItem, error)
  func (a *Agent) SessionEndsAt() time.Time
  func (a *Agent) Handshakes() int64
  func (a *Agent) Handler() http.Handler          // POST /token, GET /status
  var ErrSessionOver, ErrNoAgent error
  type TokenRequest struct { Device string; Enable bool; TTLSeconds int }
  type Status struct { Broker, SessionEndsAt string; Handshakes int64 }
  func SocketPath() string
  func PrivateDir(dir string) error
  func Listen(path string) (net.Listener, error)
  type Client; func NewClient(socket string) *Client
  func (c *Client) Token(ctx context.Context, r TokenRequest) (api.MintItem, error)
  func (c *Client) Status(ctx context.Context) (Status, error)
  ```
  Task 13's `cmd/port49` uses all of it.

- [ ] **Step 1: Write the failing tests**

Create `internal/agent/agent_test.go`:

```go
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
	"github.com/rhwendt/port49/internal/testpki"
)

// fakeBroker speaks the broker's wire format and records every mint's
// Idempotency-Key. dropFirst hangs up on the first mint without answering;
// expired answers every mint 401 session_expired.
type fakeBroker struct {
	mu        sync.Mutex
	keys      []string
	dropFirst bool
	expired   bool
}

func (fb *fakeBroker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/config":
		writeJSON(w, 200, api.Config{Methods: []string{"x509"}, MaxSessionAgeSeconds: 60, BatchMax: 10})
	case "/v1/tokens":
		fb.mu.Lock()
		fb.keys = append(fb.keys, r.Header.Get("Idempotency-Key"))
		n, drop, expired := len(fb.keys), fb.dropFirst && len(fb.keys) == 1, fb.expired
		fb.mu.Unlock()
		if drop {
			c, _, _ := w.(http.Hijacker).Hijack()
			c.Close()
			return
		}
		if expired {
			writeJSON(w, 401, api.Error{Error: "session_expired"})
			return
		}
		var req api.MintRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeJSON(w, 200, api.MintResponse{Principal: "user:alice@example.com", Results: []api.MintItem{{
			Device: req.Devices[0], Verdict: "permit", Username: "alice", Login: fmt.Sprintf("login-%02d", n)}}})
	}
}

func (fb *fakeBroker) seen() []string {
	fb.mu.Lock()
	defer fb.mu.Unlock()
	return append([]string(nil), fb.keys...)
}

type rig struct {
	a   *Agent
	fb  *fakeBroker
	srv *httptest.Server
	mu  sync.Mutex
	now time.Time
}

func (r *rig) clock() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.now
}

func (r *rig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

func newRig(t *testing.T) *rig { return newRigSigned(t, false) }

// newRigSigned builds the rig. The fake broker verifies a client certificate
// only if one is given, as the real one does (Task 10). foreign gives the
// agent a certificate from a CA the broker does not trust, and skips Connect.
func newRigSigned(t *testing.T, foreign bool) *rig {
	t.Helper()
	now := time.Now()
	ca, err := testpki.NewCA("agent test ca", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	srvCert, err := ca.Issue(testpki.Leaf{CommonName: "broker", IPs: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	cli, err := ca.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if foreign {
		other, err := testpki.NewCA("someone else's CA", now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if cli, err = other.Issue(testpki.Leaf{CommonName: "alice", Emails: []string{"alice@example.com"}, Client: true,
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	r := &rig{fb: &fakeBroker{}, now: now}
	r.srv = httptest.NewUnstartedServer(r.fb)
	r.srv.TLS = &tls.Config{Certificates: []tls.Certificate{srvCert}, ClientCAs: ca.Pool(),
		ClientAuth: tls.VerifyClientCertIfGiven, MinVersion: tls.VersionTLS13}
	r.srv.StartTLS()
	t.Cleanup(r.srv.Close)
	r.a = New(Config{BrokerURL: r.srv.URL, Cert: cli, BrokerCA: ca.Pool(), Now: r.clock})
	if foreign {
		return r
	}
	if _, err := r.a.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

// A certificate the broker's anchor did not issue fails `port49 login` at the
// handshake, rather than logging in with no identity and failing at the first
// mint (plan 3, Decided 3). The broker only requests a certificate
// (VerifyClientCertIfGiven), so this holds only because the agent always
// presents its own.
func TestAnUntrustedCertificateFailsConnect(t *testing.T) {
	r := newRigSigned(t, true)
	if _, err := r.a.Connect(context.Background()); err == nil {
		t.Fatal("Connect with a certificate the broker does not trust must fail")
	}
}

// Every ask is a mint: the agent never hands back a token it handed out
// before, and every mint travels the one connection the handshake opened.
func TestEveryTokenIsAFreshMintOnTheHeldConnection(t *testing.T) {
	r := newRig(t)
	a, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	keys := r.fb.seen()
	if a.Login == b.Login || len(keys) != 2 || keys[0] == "" || keys[0] == keys[1] {
		t.Fatalf("two asks must be two mints under two keys: %q %q %q", a.Login, b.Login, keys)
	}
	if n := r.a.Handshakes(); n != 1 {
		t.Fatalf("one session, one handshake; got %d", n)
	}
}

// A dropped connection is re-established on the next ask: one more handshake,
// which on a hardware key is one more touch (design §7).
func TestADroppedConnectionIsReestablished(t *testing.T) {
	r := newRig(t)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatal(err)
	}
	r.srv.CloseClientConnections()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); err != nil {
		t.Fatalf("the ask after a drop must reconnect and mint: %v", err)
	}
	if n := r.a.Handshakes(); n != 2 {
		t.Fatalf("handshakes %d, want 2", n)
	}
}

// A mint whose response was lost is retried on a new connection under the SAME
// key, so the broker replays it rather than cutting a second pair (design §17).
func TestALostResponseIsRetriedUnderTheSameKey(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.dropFirst = true
	r.fb.mu.Unlock()
	item, err := r.a.Mint(context.Background(), "leaf1", false, 0)
	if err != nil {
		t.Fatal(err)
	}
	keys := r.fb.seen()
	if len(keys) != 2 || keys[0] != keys[1] || item.Login != "login-02" {
		t.Fatalf("keys %q item %+v", keys, item)
	}
}

// The session ends at the first handshake plus max_session_age, whatever
// happened in between; the broker is not asked (plan 3, Decided 11).
func TestTheSessionEndsAtTheCeiling(t *testing.T) {
	r := newRig(t)
	r.advance(61 * time.Second)
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("past the ceiling: %v", err)
	}
	if len(r.fb.seen()) != 0 {
		t.Fatal("a session past its ceiling must not reach the broker")
	}
}

func TestTheBrokersSessionExpiredEndsTheSession(t *testing.T) {
	r := newRig(t)
	r.fb.mu.Lock()
	r.fb.expired = true
	r.fb.mu.Unlock()
	if _, err := r.a.Mint(context.Background(), "leaf1", false, 0); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("401 session_expired: %v", err)
	}
}

// shortDir is a directory under /tmp: a unix socket path is limited to about
// 108 bytes, and t.TempDir can be longer.
func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "p49a")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// The socket's directory is its access control: created 0700, and one anyone
// else can enter is refused rather than narrowed.
func TestTheSocketDirectoryIsPrivate(t *testing.T) {
	base := shortDir(t)
	p := filepath.Join(base, "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v", fi.Mode().Perm())
	}
	wide := filepath.Join(base, "wide")
	if err := os.Mkdir(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(filepath.Join(wide, "agent.sock")); err == nil || !strings.Contains(err.Error(), "0700") {
		t.Fatalf("a directory others can enter: %v", err)
	}
}

func TestTheClientTalksToTheAgentOverItsSocket(t *testing.T) {
	r := newRig(t)
	base := shortDir(t)
	p := filepath.Join(base, "s", "agent.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: r.a.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	c := NewClient(p)
	item, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"})
	if err != nil || item.Login != "login-01" || item.Verdict != "permit" {
		t.Fatalf("%+v %v", item, err)
	}
	if st, err := c.Status(context.Background()); err != nil || st.Handshakes != 1 || st.SessionEndsAt == "" {
		t.Fatalf("status %+v %v", st, err)
	}
	r.advance(61 * time.Second)
	if _, err := c.Token(context.Background(), TokenRequest{Device: "leaf1"}); !errors.Is(err, ErrSessionOver) {
		t.Fatalf("an ended session through the socket: %v", err)
	}
	if _, err := NewClient(filepath.Join(base, "nobody.sock")).Token(context.Background(), TokenRequest{Device: "leaf1"}); !errors.Is(err, ErrNoAgent) {
		t.Fatalf("no agent: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/agent/ -count=1`
Expected: FAIL to build — `no non-test Go files`.

- [ ] **Step 3: Write the agent**

Create `internal/agent/agent.go`:

```go
// Package agent holds the operator's session on the certificate path (design
// §7; §8 "Two credentials, two lifetimes"): one mutual-TLS connection to the
// broker, opened with the operator's certificate, and a unix socket through
// which `port49 token` asks it to mint. The key is used at the handshake;
// every mint for the rest of the session travels over that connection, and
// no broker-issued session token exists (spec §13, decision 17).
//
// It holds no device token and writes none anywhere. Every ask is a mint, so
// a client that reconnects to a device presents a fresh credential rather
// than a spent one — which is what removes most of the receipt idle-gap
// problem the client matrix measured (spec §15, L15); the receipt bounds are
// the fallback, not the answer.
package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
)

// Config is what opens a session.
type Config struct {
	BrokerURL string
	Cert      tls.Certificate
	BrokerCA  *x509.CertPool
	Now       func() time.Time
	// Log receives the agent's own lines — reconnects, the session's end.
	// Never a token.
	Log io.Writer
}

// ErrSessionOver is a session past its ceiling, by the agent's clock or the
// broker's. The answer is `port49 login`.
var ErrSessionOver = errors.New("agent: the session has reached max_session_age; run `port49 login`")

// Agent is one operator session.
type Agent struct {
	broker     string
	client     *http.Client
	now        func() time.Time
	log        io.Writer
	handshakes atomic.Int64

	mu       sync.Mutex
	deadline time.Time
}

// New builds an agent. Nothing is dialed until Connect.
//
// The transport holds one connection (MaxConnsPerHost 1, no idle timeout):
// concurrent asks queue on it rather than opening a second handshake. When it
// drops, the next ask dials again, which is one more use of the key.
func New(c Config) *Agent {
	a := &Agent{broker: strings.TrimRight(c.BrokerURL, "/"), now: c.Now, log: c.Log}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = io.Discard
	}
	cert := c.Cert
	dialer := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: c.BrokerCA,
		// Always presented. Go's default presents a certificate only when the
		// broker's CA hint names its issuer, and otherwise sends none — so a
		// certificate from the wrong CA would log in with no identity at all
		// and fail at the first mint instead of here (plan 3, Decided 3).
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}}
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			if n := a.handshakes.Add(1); n > 1 {
				fmt.Fprintf(a.log, "port49 agent: reconnected to the broker (handshake %d)\n", n)
			}
			return conn, nil
		},
		MaxConnsPerHost:     1,
		MaxIdleConnsPerHost: 1,
	}
	a.client = &http.Client{Transport: tr, Timeout: 30 * time.Second}
	return a
}

// Connect opens the session: the handshake, which is the one use of the key
// (design §7), and GET /v1/config on the new connection, which is also what
// stamps the broker's auth_time for it. The session ends max_session_age from
// now, however many reconnects happen in between (plan 3, Decided 11).
func (a *Agent) Connect(ctx context.Context) (api.Config, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.broker+"/v1/config", nil)
	if err != nil {
		return api.Config{}, err
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return api.Config{}, fmt.Errorf("agent: connecting to the broker at %s: %w", a.broker, err)
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return api.Config{}, fmt.Errorf("agent: %s/v1/config answered %s", a.broker, resp.Status)
	}
	var c api.Config
	if err := json.NewDecoder(resp.Body).Decode(&c); err != nil {
		return api.Config{}, fmt.Errorf("agent: %s/v1/config: %w", a.broker, err)
	}
	if c.MaxSessionAgeSeconds <= 0 {
		return api.Config{}, fmt.Errorf("agent: %s names no max_session_age, so the session would have no end", a.broker)
	}
	a.mu.Lock()
	a.deadline = a.now().Add(time.Duration(c.MaxSessionAgeSeconds) * time.Second)
	a.mu.Unlock()
	return c, nil
}

// SessionEndsAt is when this session ends; zero before Connect.
func (a *Agent) SessionEndsAt() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.deadline
}

// Handshakes is how many connections this session has opened.
func (a *Agent) Handshakes() int64 { return a.handshakes.Load() }

// Mint asks the broker for a fresh token for one device. A transport failure
// is retried once, on a new connection, under the same Idempotency-Key, so a
// mint whose response was lost is replayed rather than cut again (design
// §17).
func (a *Agent) Mint(ctx context.Context, device string, enable bool, ttl time.Duration) (api.MintItem, error) {
	if ends := a.SessionEndsAt(); ends.IsZero() || !a.now().Before(ends) {
		return api.MintItem{}, ErrSessionOver
	}
	body, err := json.Marshal(api.MintRequest{Devices: []string{device}, Enable: enable, TTLSeconds: int(ttl / time.Second)})
	if err != nil {
		return api.MintItem{}, err
	}
	key, err := newKey()
	if err != nil {
		return api.MintItem{}, err
	}
	var resp *http.Response
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.broker+"/v1/tokens", bytes.NewReader(body))
		if err != nil {
			return api.MintItem{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		resp, err = a.client.Do(req)
		if err == nil {
			break
		}
		a.client.CloseIdleConnections()
		if attempt == 2 {
			return api.MintItem{}, fmt.Errorf("agent: the broker at %s is unreachable: %w", a.broker, err)
		}
	}
	defer drain(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if resp.StatusCode == http.StatusUnauthorized && e.Error == "session_expired" {
			return api.MintItem{}, ErrSessionOver
		}
		return api.MintItem{}, fmt.Errorf("agent: the broker answered %s: %s %s", resp.Status, e.Error, e.Detail)
	}
	var mr api.MintResponse
	if err := json.NewDecoder(resp.Body).Decode(&mr); err != nil {
		return api.MintItem{}, fmt.Errorf("agent: the broker's answer: %w", err)
	}
	if len(mr.Results) != 1 {
		return api.MintItem{}, fmt.Errorf("agent: asked for one device, the broker answered %d", len(mr.Results))
	}
	return mr.Results[0], nil
}

// TokenRequest is what `port49 token` sends the agent.
type TokenRequest struct {
	Device     string `json:"device"`
	Enable     bool   `json:"enable"`
	TTLSeconds int    `json:"ttl_seconds"`
}

// Status is GET /status on the agent's socket.
type Status struct {
	Broker        string `json:"broker"`
	SessionEndsAt string `json:"session_ends_at"`
	Handshakes    int64  `json:"handshakes"`
}

// Handler is the agent's socket: POST /token mints one device and answers the
// broker's item; GET /status says whose session this is and when it ends.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		var req TokenRequest
		dec := json.NewDecoder(io.LimitReader(r.Body, 1<<16))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil || req.Device == "" {
			writeJSON(w, http.StatusBadRequest, api.Error{Error: "bad_request", Detail: "name one device"})
			return
		}
		item, err := a.Mint(r.Context(), req.Device, req.Enable, time.Duration(req.TTLSeconds)*time.Second)
		switch {
		case errors.Is(err, ErrSessionOver):
			writeJSON(w, http.StatusGone, api.Error{Error: "session_over", Detail: err.Error()})
		case err != nil:
			writeJSON(w, http.StatusBadGateway, api.Error{Error: "broker_error", Detail: err.Error()})
		default:
			writeJSON(w, http.StatusOK, item)
		}
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, Status{Broker: a.broker,
			SessionEndsAt: a.SessionEndsAt().UTC().Format(time.RFC3339), Handshakes: a.Handshakes()})
	})
	return mux
}

// drain reads a response to its end before closing it. A body closed unread
// cannot give its connection back, and the next mint would be a new handshake:
// the held connection this package exists to keep.
func drain(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, body)
	body.Close()
}

func newKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
```

Create `internal/agent/socket.go`:

```go
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rhwendt/port49/internal/broker/api"
)

// ErrNoAgent is a socket nothing answers on. The answer is `port49 login`.
var ErrNoAgent = errors.New("agent: no agent is listening")

// SocketPath is where the agent listens by default:
// $XDG_RUNTIME_DIR/port49/agent.sock, or /tmp/port49-<uid>/agent.sock on a
// host without one.
func SocketPath() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "port49", "agent.sock")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("port49-%d", os.Getuid()), "agent.sock")
}

// PrivateDir makes dir at mode 0700, or accepts an existing one only at
// exactly that mode. The directory is the socket's whole access control —
// whoever can reach the socket can mint as this operator — so one anyone
// else can enter is refused rather than narrowed: it may already hold
// someone else's socket.
func PrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		return fmt.Errorf("agent: %s must be a directory at mode 0700, and it is %v; its mode is the socket's "+
			"access control", dir, fi.Mode().Perm())
	}
	return nil
}

// Listen opens the agent's socket at path, refusing to start beside a live
// agent and clearing a stale socket a dead one left.
func Listen(path string) (net.Listener, error) {
	if err := PrivateDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if c, err := net.Dial("unix", path); err == nil {
		c.Close()
		return nil, fmt.Errorf("agent: an agent is already listening at %s", path)
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Client is `port49 token`'s side of the socket.
type Client struct {
	socket string
	http   *http.Client
}

// NewClient talks to the agent at socket.
func NewClient(socket string) *Client {
	return &Client{socket: socket, http: &http.Client{Timeout: 90 * time.Second, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		}}}}
}

// Token asks the agent to mint one device.
func (c *Client) Token(ctx context.Context, r TokenRequest) (api.MintItem, error) {
	body, err := json.Marshal(r)
	if err != nil {
		return api.MintItem{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/token", bytes.NewReader(body))
	if err != nil {
		return api.MintItem{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return api.MintItem{}, fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		var item api.MintItem
		if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
			return api.MintItem{}, err
		}
		return item, nil
	case http.StatusGone:
		return api.MintItem{}, ErrSessionOver
	default:
		var e api.Error
		_ = json.NewDecoder(resp.Body).Decode(&e)
		return api.MintItem{}, fmt.Errorf("agent: %s: %s", e.Error, e.Detail)
	}
}

// Status asks the agent whose session it holds.
func (c *Client) Status(ctx context.Context) (Status, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://agent/status", nil)
	if err != nil {
		return Status{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Status{}, fmt.Errorf("%w at %s: %v", ErrNoAgent, c.socket, err)
	}
	defer resp.Body.Close()
	var s Status
	if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
		return Status{}, err
	}
	return s, nil
}
```

- [ ] **Step 4: Run the package**

Run: `go test ./internal/agent/ -count=1 && go test -race ./internal/agent/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/agent/
git commit -m "feat: an agent that holds the session and mints fresh on every ask

One mTLS connection per session, reconnected on a drop, retried under
the same Idempotency-Key, and ended at the first handshake plus
max_session_age. A unix socket in a 0700 directory is how port49 token
reaches it.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 13: `port49 login` and `port49 token`

**Files:**
- Create: `cmd/port49/main.go`
- Test: `cmd/port49/main_test.go`
- Modify: `Makefile` (`build`)

**Interfaces:**
- Consumes: everything Task 12 produces.
- Produces: the `port49` binary: `login` (starts `port49 agent` detached and waits for its socket),
  `token` (prints the login token on stdout, or the item with `--json`), and the internal `agent`
  subcommand `login` execs. Exit codes: 0 success, 1 refusal or failure, 2 usage. Task 14 parses
  `agent pid N` from `login`'s stdout.

- [ ] **Step 1: Write the failing tests**

Create `cmd/port49/main_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rhwendt/port49/internal/broker/api"
)

// fakeAgent answers the agent socket's POST /token with a fixed item, or with
// status and an error body when status is not 200. The socket protocol is the
// contract between `port49 token` and the agent; this tests the CLI's half.
func fakeAgent(t *testing.T, status int, item api.MintItem) string {
	t.Helper()
	d, err := os.MkdirTemp("", "p49c")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	p := filepath.Join(d, "agent.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == http.StatusOK {
			_ = json.NewEncoder(w).Encode(item)
			return
		}
		_ = json.NewEncoder(w).Encode(api.Error{Error: "session_over"})
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return p
}

var permit = api.MintItem{Device: "leaf1", Verdict: "permit", Username: "alice", Login: "LOGINTOKEN", Enable: "ENABLETOKEN"}

// stdout carries the login token and nothing else, so `$(port49 token leaf1)`
// is the credential; --json carries the whole item, enable token included.
func TestTokenPrintsTheLoginTokenAndNothingElse(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, permit)
	var out, errb bytes.Buffer
	if code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb); code != 0 || out.String() != "LOGINTOKEN\n" {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"token", "--json", "--socket", p, "leaf1"}, &out, &errb); code != 0 {
		t.Fatalf("code %d %s", code, errb.String())
	}
	var item api.MintItem
	if err := json.Unmarshal(out.Bytes(), &item); err != nil || item.Enable != "ENABLETOKEN" || item.Username != "alice" {
		t.Fatalf("json: %s %v", out.String(), err)
	}
}

func TestADenialIsAFailureWithItsReason(t *testing.T) {
	p := fakeAgent(t, http.StatusOK, api.MintItem{Device: "leaf1", Verdict: "deny", Reason: "no_grants_matched"})
	var out, errb bytes.Buffer
	code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb)
	if code != 1 || out.Len() != 0 || !strings.Contains(errb.String(), "leaf1: deny no_grants_matched") {
		t.Fatalf("code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}

func TestAnEndedSessionOrNoAgentSaysToLogIn(t *testing.T) {
	for name, p := range map[string]string{
		"ended":    fakeAgent(t, http.StatusGone, api.MintItem{}),
		"no agent": filepath.Join(t.TempDir(), "nobody.sock"),
	} {
		var out, errb bytes.Buffer
		if code := run([]string{"token", "--socket", p, "leaf1"}, &out, &errb); code != 1 || !strings.Contains(errb.String(), "port49 login") {
			t.Errorf("%s: code %d stderr %q", name, code, errb.String())
		}
	}
}

// login checks what it can before it starts anything.
func TestLoginRefusesWhatItCanCheckFirst(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	var out, errb bytes.Buffer
	if code := run([]string{"login", "--socket", sock}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "all required") {
		t.Fatalf("no flags: code %d %q", code, errb.String())
	}
	errb.Reset()
	code := run([]string{"login", "--broker", "https://127.0.0.1:1", "--cert", "/nonexistent.pem", "--key", "/nonexistent.pem",
		"--broker-ca", "/nonexistent.pem", "--socket", sock}, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "client certificate") {
		t.Fatalf("missing files: code %d %q", code, errb.String())
	}
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "port49 token") {
		t.Fatalf("code %d %q", code, errb.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49/ -count=1`
Expected: FAIL to build — `no non-test Go files`.

- [ ] **Step 3: Write the command**

Create `cmd/port49/main.go`:

```go
// Command port49 is the operator's CLI for the vertical slice (design §17,
// "Client libraries"; §19 step 3). `port49 login` starts the agent that holds
// the session — one mutual-TLS connection to the broker — and `port49 token
// DEVICE` mints through it, fresh every time. Plan 9 builds the rest: `port49
// ssh` with host-key verification, the OIDC client, and a key held on a
// hardware token.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/agent"
)

const usage = `usage:
  port49 login --broker URL --cert FILE --key FILE --broker-ca FILE [--socket PATH]
  port49 token [--enable] [--ttl DURATION] [--json] [--socket PATH] DEVICE
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "login":
		return login(args[1:], stdout, stderr)
	case "token":
		return tokenCmd(args[1:], stdout, stderr)
	case "agent":
		// What login starts; not for typing.
		return agentMain(args[1:], stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// sessionFlags are what the agent needs to open the session. The key is read
// from a file: BORROWED AHEAD from plan 9, which holds it on a hardware token
// (design §7; plan 3, Question 1).
type sessionFlags struct{ broker, cert, key, brokerCA, socket string }

func (s *sessionFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&s.broker, "broker", "", "the broker, https://host:port")
	fs.StringVar(&s.cert, "cert", "", "your client certificate (PEM)")
	fs.StringVar(&s.key, "key", "", "its private key (PEM)")
	fs.StringVar(&s.brokerCA, "broker-ca", "", "the CA that issued the broker's certificate (PEM)")
	fs.StringVar(&s.socket, "socket", agent.SocketPath(), "the agent's socket")
}

func (s *sessionFlags) args() []string {
	return []string{"--broker", s.broker, "--cert", s.cert, "--key", s.key, "--broker-ca", s.brokerCA, "--socket", s.socket}
}

func (s *sessionFlags) config(log io.Writer) (agent.Config, error) {
	if s.broker == "" || s.cert == "" || s.key == "" || s.brokerCA == "" {
		return agent.Config{}, errors.New("--broker, --cert, --key and --broker-ca are all required")
	}
	cert, err := tls.LoadX509KeyPair(s.cert, s.key)
	if err != nil {
		return agent.Config{}, fmt.Errorf("loading the client certificate: %w", err)
	}
	caPEM, err := os.ReadFile(s.brokerCA)
	if err != nil {
		return agent.Config{}, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return agent.Config{}, fmt.Errorf("%s holds no PEM certificate", s.brokerCA)
	}
	return agent.Config{BrokerURL: s.broker, Cert: cert, BrokerCA: pool, Now: time.Now, Log: log}, nil
}

// login starts the agent in its own session, detached, and waits until its
// socket answers. The handshake happens in the agent, so an untrusted
// certificate fails here (plan 3, Decided 3) and the agent's log says why.
func login(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf sessionFlags
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if _, err := sf.config(stderr); err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 2
	}
	ctx := context.Background()
	if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
		fmt.Fprintf(stdout, "port49: already logged in to %s; the session ends at %s\n", st.Broker, st.SessionEndsAt)
		return 0
	}
	dir := filepath.Dir(sf.socket)
	if err := agent.PrivateDir(dir); err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	logPath := filepath.Join(dir, "agent.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	defer logf.Close()
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, "port49 login:", err)
		return 1
	}
	cmd := exec.Command(self, append([]string{"agent"}, sf.args()...)...)
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(stderr, "port49 login: starting the agent:", err)
		return 1
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		select {
		case err := <-exited:
			tail, _ := os.ReadFile(logPath)
			fmt.Fprintf(stderr, "port49 login: the agent exited (%v); the end of %s:\n%s", err, logPath, lastLines(string(tail), 10))
			return 1
		case <-time.After(100 * time.Millisecond):
		}
		if st, err := agent.NewClient(sf.socket).Status(ctx); err == nil {
			fmt.Fprintf(stdout, "port49: logged in to %s; the session ends at %s (agent pid %d, log %s)\n",
				st.Broker, st.SessionEndsAt, cmd.Process.Pid, logPath)
			return 0
		}
	}
	_ = cmd.Process.Kill()
	fmt.Fprintf(stderr, "port49 login: the agent did not answer within 15s; see %s\n", logPath)
	return 1
}

// agentMain is the agent process: open the session, serve the socket, and
// exit at the session's end or on a signal.
func agentMain(args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sf sessionFlags
	sf.register(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := sf.config(stderr)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a := agent.New(cfg)
	conf, err := a.Connect(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", err)
		return 1
	}
	ln, err := agent.Listen(sf.socket)
	if err != nil {
		fmt.Fprintln(stderr, "port49 agent:", err)
		return 1
	}
	defer os.Remove(sf.socket)
	srv := &http.Server{Handler: a.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	fmt.Fprintf(stderr, "port49 agent: connected to %s; the session ends at %s (max_session_age %ds)\n",
		sf.broker, a.SessionEndsAt().UTC().Format(time.RFC3339), conf.MaxSessionAgeSeconds)
	timer := time.NewTimer(time.Until(a.SessionEndsAt()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		fmt.Fprintln(stderr, "port49 agent: signal received; exiting")
	case <-timer.C:
		fmt.Fprintln(stderr, "port49 agent: the session reached max_session_age; exiting - run `port49 login` to start another")
	}
	_ = srv.Close()
	return 0
}

// tokenCmd mints one device through the agent and prints the login token on
// stdout — the one place a token is ever written (design §17, write-once).
// Flags come before DEVICE.
func tokenCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 token", flag.ContinueOnError)
	fs.SetOutput(stderr)
	enable := fs.Bool("enable", false, "mint an enable token beside the login one (printed with --json)")
	ttl := fs.Duration("ttl", 0, "ask for this lifetime; the broker clamps it to your policy's token_ttl")
	asJSON := fs.Bool("json", false, "print the broker's whole answer as JSON, enable token included")
	socket := fs.String("socket", agent.SocketPath(), "the agent's socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	device := fs.Arg(0)
	item, err := agent.NewClient(*socket).Token(context.Background(),
		agent.TokenRequest{Device: device, Enable: *enable, TTLSeconds: int(*ttl / time.Second)})
	switch {
	case errors.Is(err, agent.ErrNoAgent):
		fmt.Fprintf(stderr, "port49 token: no agent at %s; run `port49 login`\n", *socket)
		return 1
	case errors.Is(err, agent.ErrSessionOver):
		fmt.Fprintln(stderr, "port49 token: the session has ended; run `port49 login`")
		return 1
	case err != nil:
		fmt.Fprintln(stderr, "port49 token:", err)
		return 1
	}
	if item.Verdict != "permit" {
		fmt.Fprintf(stderr, "port49 token: %s: %s %s\n", device, item.Verdict, item.Reason)
		return 1
	}
	if *asJSON {
		_ = json.NewEncoder(stdout).Encode(item)
		return 0
	}
	fmt.Fprintln(stdout, item.Login)
	return 0
}

func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n") + "\n"
}
```

- [ ] **Step 4: Build both binaries**

In `Makefile`, replace

```make
build:
	go build -o bin/port49d ./cmd/port49d
```

with

```make
build:
	go build -o bin/port49d ./cmd/port49d
	go build -o bin/port49 ./cmd/port49
```

- [ ] **Step 5: Run the tests and the build**

Run: `go test ./cmd/port49/ -count=1 && make build && ls bin/`
Expected: PASS; `bin/port49` and `bin/port49d` both listed.

- [ ] **Step 6: Commit**

```bash
git add cmd/port49/ Makefile
git commit -m "feat: port49 login and port49 token

login starts the agent detached and waits for its socket; token mints
through it and prints the login token on stdout, or the whole answer
with --json.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 14: The lab can run the slice end to end, and by hand

**Files:**
- Create: `tests/lab/cmd/slice-pki/main.go`
- Create: `tests/lab/slice/policy.yaml`, `tests/lab/slice/broker.yaml`
- Create: `tests/lab/slice_test.go`
- Create: `internal/broker/policy/labpolicy_test.go`
- Modify: `tests/lab/README.md` (a section "The vertical slice")

**Interfaces:**
- Consumes: `testpki.WriteLab` and its file-name constants; the harness's `eachPlatform`,
  `derivedConfig`, `platformSessionAttributes`, `stopDaemon`, `startDaemonWith`, `configPath`,
  `capture`, `mark`, `login`, `waitForRecords`, `recordsSince`, `summarize`, `resultOver`, `str`,
  `sub`, `strs`, `labcreds.TokenLen`; `bin/port49`'s `login`/`token` and the `agent pid N` line.
- Produces: `TestSliceEndToEnd` (writes `tests/lab/results/slice-arista_eos.md`), `go run
  ./tests/lab/cmd/slice-pki`, and the by-hand procedures Tasks 16 and 17 follow.

- [ ] **Step 1: The lab PKI command**

Create `tests/lab/cmd/slice-pki/main.go`:

```go
// Command slice-pki writes the vertical slice's lab certificates (plan 3): a
// CA, the broker's server certificate for 127.0.0.1, and one client
// certificate. They protect nothing — the lab broker listens on the loopback —
// and the default directory is git-ignored. TestSliceEndToEnd writes the same
// set for itself; this is for the by-hand runs in tests/lab/README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
)

func main() {
	out := flag.String("out", "tests/lab/logs/slice-pki", "directory to write into")
	email := flag.String("email", "alice@slice.port49.test", "the client certificate's email SAN")
	flag.Parse()
	if err := testpki.WriteLab(*out, *email, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "slice-pki:", err)
		os.Exit(1)
	}
	fmt.Printf("slice-pki: wrote %s (valid 24h)\n", *out)
}
```

- [ ] **Step 2: The lab policy and broker block**

Create `tests/lab/slice/policy.yaml`:

```yaml
# The vertical slice's lab policy (plan 3). One subject: the client certificate
# `go run ./tests/lab/cmd/slice-pki` cuts. It may do everything on every device
# except one command, so the end-to-end run can show a permit and a denial that
# only the compiled blob could have made: `show hostname` is in no deny list in
# port49d-lab.yaml, so a denial of it cannot have come from the lab authorizer.
#
# `slice01` is a username no seed uses, so nothing but a broker-minted token can
# log in under it.
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: slice_denies, deny: ["show hostname"]}
subjects:
  - {name: slice_operator, identity: ["user:alice@slice.port49.test"], username: slice01,
     enable: token, token_ttl: 60s}
grants:
  - {subject: slice_operator, scope: all_devices, roles: [network_admin, slice_denies], max_privilege: admin}
```

Create `tests/lab/slice/broker.yaml`:

```yaml
# The vertical slice's broker block (plan 3), appended to port49d-lab.yaml by
# TestSliceEndToEnd and by the by-hand runs in tests/lab/README.md. Paths are
# relative to the repository root, where port49d runs. The certificates come
# from `go run ./tests/lab/cmd/slice-pki`.
broker:
  listen: "127.0.0.1:8449"
  tls_cert_file: tests/lab/logs/slice-pki/broker.pem
  tls_key_file: tests/lab/logs/slice-pki/broker-key.pem
  client_ca_file: tests/lab/logs/slice-pki/broker-ca.pem
  policy_file: tests/lab/slice/policy.yaml
```

- [ ] **Step 3: Check the policy loads before anything depends on it**

Create `internal/broker/policy/labpolicy_test.go`:

```go
package policy

import (
	"path/filepath"
	"runtime"
	"testing"
)

// The lab's policy is loaded by a daemon only inside `make lab`. Loading it here
// means a typo in it fails `make test`, not a VM boot ten minutes in.
func TestTheLabPolicyLoads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "tests", "lab", "slice", "policy.yaml")
	p, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Resolve("user:alice@slice.port49.test", "arista_eos")
	if !ok || r.Username != "slice01" || len(r.Blob.Deny) != 1 || r.Blob.Deny[0] != "show hostname" {
		t.Fatalf("%+v %v", r, ok)
	}
}
```

Run: `go test ./internal/broker/policy/ -run TestTheLabPolicyLoads -count=1`
Expected: PASS.

- [ ] **Step 4: The end-to-end lab test**

Create `tests/lab/slice_test.go`:

```go
//go:build lab

package lab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/testpki"
	"github.com/rhwendt/port49/tests/lab/labcreds"
)

// The vertical slice (plan 3; design §19 step 3): the first login to a real
// device with a credential nobody wrote down. A client certificate opens a
// session with the broker inside port49d (`port49 login`), a token is minted
// over it (`port49 token`), the token logs into the device, and every
// authorization is answered from the blob the mint compiled. A second window
// asks for a second token and gets a fresh one.
//
// vEOS only: the slice renders session attributes for arista_eos alone (plan 3,
// Decided 6), and a login elsewhere would measure plan 5's missing adapter.

const (
	sliceUser      = "slice01"
	sliceEmail     = "alice@slice.port49.test"
	slicePrincipal = "user:" + sliceEmail
	slicePKIDir    = "tests/lab/logs/slice-pki"
	sliceBrokerURL = "https://127.0.0.1:8449"
	sliceDenied    = "show hostname"
)

const sliceClaim = "The vertical slice end to end: an operator's client certificate, validated by the broker " +
	"against one trust anchor, mints a device token over a held mTLS connection (`port49 login`, `port49 token`); " +
	"the token logs into the device; every authorization is answered from the compiled blob the mint wrote; and a " +
	"second `port49 token` mints a fresh token rather than handing back the first."

var agentPID = regexp.MustCompile(`agent pid (\d+)`)

func TestSliceEndToEnd(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		if l.p.name != "arista_eos" {
			t.Skipf("the slice renders session attributes for arista_eos only (plan 3, Decided 6); %s waits for plan 5", l.p.name)
		}
		port49 := filepath.Join(root, "bin", "port49")
		if _, err := os.Stat(port49); err != nil {
			t.Fatalf("%s is missing: run `make build` before `make lab` (%v)", port49, err)
		}
		pki := filepath.Join(root, slicePKIDir)
		if err := testpki.WriteLab(pki, sliceEmail, time.Now()); err != nil {
			t.Fatal(err)
		}
		brokerYAML, err := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := l.derivedConfig("slice", platformSessionAttributes[l.p.name], string(brokerYAML))
		if err != nil {
			t.Fatal(err)
		}
		if err := l.stopDaemon(); err != nil {
			t.Fatal(err)
		}
		if err := l.startDaemonWith(cfg, true); err != nil {
			t.Fatalf("port49d would not start with the broker block, so nothing was measured: %v", err)
		}
		defer func() {
			if err := l.stopDaemon(); err != nil {
				t.Errorf("could not stop the slice daemon: %v", err)
				return
			}
			std, err := l.configPath()
			if err != nil {
				t.Fatalf("derive this platform's daemon config: %v", err)
			}
			if err := l.startDaemonWith(std, true); err != nil {
				t.Fatalf("could not put port49d back on the lab config: %v", err)
			}
		}()

		stop := l.capture(t, "slice")
		defer stop()
		off := l.mark()

		sockDir, err := os.MkdirTemp("", "p49slice")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(sockDir)
		sock := filepath.Join(sockDir, "a", "agent.sock")
		out, err := exec.Command(port49, "login", "--broker", sliceBrokerURL,
			"--cert", filepath.Join(pki, testpki.LabClientCert), "--key", filepath.Join(pki, testpki.LabClientKey),
			"--broker-ca", filepath.Join(pki, testpki.LabCA), "--socket", sock).CombinedOutput()
		if err != nil {
			t.Fatalf("port49 login: %v\n%s", err, out)
		}
		defer stopSliceAgent(t, string(out))

		tok1 := sliceToken(t, port49, sock)
		outs, err := l.login(sliceUser, tok1, "show version", sliceDenied)
		if err != nil {
			t.Fatalf("SSH login as %s with the broker-minted token failed: %v\nrecords:%s", sliceUser, err, summarize(l.recordsSince(off)))
		}
		// A second window is a second device connection, and it gets a fresh
		// mint (plan 3, Decided 11).
		tok2 := sliceToken(t, port49, sock)
		if tok2 == tok1 {
			t.Fatal("port49 token handed back a token it had already handed out")
		}
		if _, err := l.login(sliceUser, tok2, "show version"); err != nil {
			t.Fatalf("the second window's login failed: %v\nrecords:%s", err, summarize(l.recordsSince(off)))
		}

		recs := l.waitForRecords(off, 30*time.Second, func(rs []map[string]any) bool {
			return len(sliceRecords(rs, "redeem", "token_redeemed")) >= 2 && len(sliceRecords(rs, "authorize_command", "no_permit_dominates_deny")) >= 1
		})
		raw, err := os.ReadFile(l.logPath)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), tok1) || strings.Contains(string(raw), tok2) {
			t.Fatal("a minted token is in the decision log")
		}
		obs, err := sliceObservation(recs, []string{tok1, tok2}, outs)
		if err != nil {
			t.Fatalf("%v\nrecords:%s", err, summarize(recs))
		}
		l.resultOver(t, "slice", "SSH, with tokens minted by the broker over a held mTLS connection "+
			"(`port49 login`, `port49 token`)", sliceClaim, obs)
	})
}

func sliceToken(t *testing.T, port49, sock string) string {
	t.Helper()
	cmd := exec.Command(port49, "token", "--socket", sock, "leaf1")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	tok := strings.TrimSpace(string(out))
	if err != nil || len(tok) != labcreds.TokenLen {
		t.Fatalf("port49 token leaf1: %v, %d characters on stdout; stderr: %s", err, len(tok), stderr.String())
	}
	return tok
}

func stopSliceAgent(t *testing.T, loginOut string) {
	m := agentPID.FindStringSubmatch(loginOut)
	if m == nil {
		t.Errorf("port49 login did not name the agent's pid, so it is still running: %q", loginOut)
		return
	}
	pid, _ := strconv.Atoi(m[1])
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Errorf("stopping the agent (pid %d): %v", pid, err)
	}
}

// sliceRecords are the records of one event and reason about slice01, or about
// the slice's principal for a mint.
func sliceRecords(recs []map[string]any, event, reason string) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if str(r, "event") != event || (reason != "" && str(r, "reason") != reason) {
			continue
		}
		if str(sub(r, "session"), "username") == sliceUser || str(r, "principal") == slicePrincipal {
			out = append(out, r)
		}
	}
	return out
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sliceObservation checks the chain the slice exists to show and renders it.
// Every link is read off a record; a missing link fails the test, because a
// run that did not produce it measured something else.
func sliceObservation(recs []map[string]any, tokens []string, outs []string) (string, error) {
	mints := sliceRecords(recs, "mint", "grants_matched")
	if len(mints) < 2 {
		return "", fmt.Errorf("want two permitted mints for %s, got %d", slicePrincipal, len(mints))
	}
	minted := map[string]bool{}
	for _, m := range mints {
		for _, h := range strs(sub(m, "mint"), "token_sha256") {
			minted[h] = true
		}
	}
	for i, tok := range tokens {
		if !minted[sha(tok)] {
			return "", fmt.Errorf("token %d's hash is on no mint record", i+1)
		}
	}
	hash := str(sub(mints[0], "mint"), "blob")
	var blobBody string
	for _, r := range recs {
		if str(r, "event") == "blob" && str(sub(r, "blob"), "hash") == hash {
			b, _ := json.Marshal(sub(r, "blob")["body"])
			blobBody = string(b)
		}
	}
	if blobBody == "" {
		return "", fmt.Errorf("no blob event carries %s", hash)
	}
	redeems := sliceRecords(recs, "redeem", "token_redeemed")
	for _, r := range redeems {
		if str(r, "principal") != slicePrincipal || !minted[str(sub(r, "auth"), "credential_sha256")] {
			return "", fmt.Errorf("a redeem does not join to a mint: %v", r)
		}
	}
	if str(sub(redeems[0], "session"), "ctx_id") != str(sub(redeems[1], "session"), "ctx_id") {
		return "", fmt.Errorf("the second window did not join the first's context")
	}
	deny := sliceRecords(recs, "authorize_command", "no_permit_dominates_deny")[0]
	if strings.Join(strs(sub(deny, "request"), "vector"), " ") != sliceDenied {
		return "", fmt.Errorf("the denial is of %v, not %q", strs(sub(deny, "request"), "vector"), sliceDenied)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Two `port49 token leaf1` calls over one `port49 login` session minted two different tokens for "+
		"principal `%s`, username `%s`, each on its own `mint` record naming blob `%s`. The `blob` event carried it:\n\n"+
		"```json\n%s\n```\n\n", slicePrincipal, sliceUser, hash, blobBody)
	b.WriteString("Every record for `slice01` in the run, in order (tokens appear as the hash the log carries):\n\n")
	b.WriteString("| event | verdict | reason | ctx_id | port | credential_sha256 / vector |\n|---|---|---|---|---|---|\n")
	for _, r := range recs {
		if str(sub(r, "session"), "username") != sliceUser {
			continue
		}
		detail := str(sub(r, "auth"), "credential_sha256")
		if v := strs(sub(r, "request"), "vector"); len(v) > 0 {
			detail = "`" + strings.Join(v, " ") + "`"
		} else if len(detail) > 12 {
			detail = "`" + detail[:12] + "…`"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | `%s` | `%s` | %s |\n", str(r, "event"), str(r, "verdict"), str(r, "reason"),
			str(sub(r, "session"), "ctx_id"), str(sub(r, "session"), "port"), detail)
	}
	fmt.Fprintf(&b, "\nBoth logins redeemed into ctx_id `%s`: the second window joined the first's context (spec §5.6).\n\n",
		str(sub(redeems[0], "session"), "ctx_id"))
	fmt.Fprintf(&b, "The device's reply to `%s`, which only the blob denies (`tests/lab/slice/policy.yaml`); the "+
		"decision record's server_msg was `%s`:\n\n```\n%s\n```\n", sliceDenied, str(deny, "server_msg"), strings.TrimSpace(orEmpty(outs, 1)))
	return b.String(), nil
}

func orEmpty(outs []string, i int) string {
	if i < len(outs) && strings.TrimSpace(outs[i]) != "" {
		return outs[i]
	}
	return emptyDeviceReply
}
```

- [ ] **Step 5: Document the slice in the lab README**

In `tests/lab/README.md`, after the section "## Transports other than SSH" and before "## Tokens",
add:

````markdown
## The vertical slice

Plan 3's broker runs inside `port49d` when the config carries a `broker:` block
(`tests/lab/slice/broker.yaml`), against the policy in `tests/lab/slice/policy.yaml` and
certificates from `go run ./tests/lab/cmd/slice-pki` (written to the git-ignored
`tests/lab/logs/slice-pki/`). `make build` builds `bin/port49` beside `bin/port49d`.

**Automated:** `TestSliceEndToEnd`, vEOS only. It restarts the daemon with the broker block, runs
`port49 login` and `port49 token leaf1`, logs in as `slice01` with the minted token, and writes
`results/slice-arista_eos.md`.

**By hand**, for the two measurements plan 3 does not automate. The daemon and topology are then
yours to start and stop, one platform at a time, destroyed afterwards:

```sh
make build
sudo -n setcap cap_net_bind_service=+ep bin/port49d
sudo -n containerlab deploy -t tests/lab/topologies/<eos|iosxe>.clab.yml
# the daemon config: the lab file, plus the broker block where the run needs a broker
cat tests/lab/port49d-lab.yaml tests/lab/slice/broker.yaml > tests/lab/logs/port49d-byhand.yaml
PORT49_LAB_KEY=labsecret PORT49_LAB_ENC_KEY=port49-lab-encryption-key-32byte \
  bin/port49d -config tests/lab/logs/port49d-byhand.yaml \
  > tests/lab/logs/decisions-byhand.jsonl 2> tests/lab/logs/port49d-byhand.log &
sudo -n tcpdump --immediate-mode -i any -U -n -s 0 -w tests/lab/captures/<note-name>.pcap 'tcp port 49' &
# ... the run ...
sudo -n pkill -INT -f 'tcpdump.*<note-name>'; kill -INT %1
make evidence
sudo -n containerlab destroy -t tests/lab/topologies/<eos|iosxe>.clab.yml --cleanup
```

A token never goes on a command line: `port49 token` writes it to stdout, a shell variable holds
it, and `printf` (a builtin, so no process of its own) feeds it to `curl` on stdin. The seed-token
file `/tmp/port49-lab-tokens.jsonl` is truncated at every daemon start; `make evidence` reads it,
so run `make evidence` before the next daemon start.
````

- [ ] **Step 6: Vet the lab code**

Run: `go vet -tags lab ./tests/lab/... && go build ./tests/lab/cmd/... && make test && make vet`
Expected: no output from `go vet`; PASS; `make vet` prints nothing.

- [ ] **Step 7: Commit**

```bash
git add tests/lab/cmd/slice-pki/ tests/lab/slice/ tests/lab/slice_test.go tests/lab/README.md internal/broker/policy/labpolicy_test.go
git commit -m "test: the lab can run the vertical slice end to end, and by hand

TestSliceEndToEnd logs into vEOS with a broker-minted token and checks
the chain mint, blob, redeem, authorization, and a fresh second mint.
The README gives the by-hand procedure the /login and RESTCONF runs use.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 15: Lab — the slice end to end on vEOS

**Platform:** vEOS (`eos`) only. **Needs:** Tasks 1–14 committed; the lab host (bare metal, KVM;
`tests/lab/README.md` "Why this needs bare metal"); `vrnetlab/arista_veos:4.32.2F` present. The lab
is single-occupant: nothing else may be deployed or listening while this runs.

- [ ] **Step 1: Confirm the lab is idle**

Run: `sudo -n containerlab inspect --all; ss -ltn '( sport = :49 or sport = :8449 )'`
Expected: no lab listed and no listener. Anything else running is someone else's measurement: stop
and ask, do not tear it down.

- [ ] **Step 2: Build and run the one test**

Run:
```bash
make build
PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/... -run 'TestSliceEndToEnd' -count=1 -v -timeout 60m
```
Expected: `--- PASS: TestSliceEndToEnd/arista_eos`, `wrote .../tests/lab/results/slice-arista_eos.md`,
and the run's teardown destroying the topology and writing `tests/lab/evidence/`. A FAIL is a
finding, not a test to loosen: read the records it prints, and if the device did something the
slice did not expect, write that down (the note, or a comment on the PR) before changing any code.

- [ ] **Step 3: Confirm it is torn down and the evidence is clean**

Run: `sudo -n containerlab inspect --all; ls tests/lab/evidence/ | grep slice; go run ./tests/lab/cmd/redact-pcap -scan`
Expected: no lab; `slice-arista_eos.pcap`; the scan passes.

- [ ] **Step 4: Read the note before committing it**

Open `tests/lab/results/slice-arista_eos.md`. Check by eye: the header names vEOS-lab 4.31.2F (image
tagged 4.32.2F) and the evidence file; the record table has a `redeem token_redeemed` for each
token, an `authorize_session permit`, `show version` permitted and `show hostname` denied
`no_permit_dominates_deny`; the device's reply to `show hostname` is quoted verbatim; no 30-character
token appears anywhere in it (`grep -E '[0-9A-Za-z]{30}' tests/lab/results/slice-arista_eos.md`
prints nothing but hashes, which are 64 characters).

- [ ] **Step 5: Commit**

```bash
git add tests/lab/results/slice-arista_eos.md tests/lab/evidence/slice-arista_eos.pcap
git commit -m "docs: the vertical slice's first end-to-end run, on vEOS

A certificate-backed session minted two tokens through port49 token;
both logged into leaf1 as slice01 and every authorization was answered
from the compiled blob. tests/lab/results/slice-arista_eos.md.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 16: Lab, by hand — the eAPI `/login` flow on vEOS (L7)

**Platform:** vEOS only, one deploy, destroyed at the end. **Measures:** L7's last open clause:
whether eAPI's `/login` session cookie changes how many TACACS+ authentications a sequence of API
requests costs. Every other L7 clause is measured (`tests/lab/results/L7-arista_eos.md`).

The questions, each answered off the decision log and the capture, never inferred from an HTTP
status alone:

1. Does `POST /login` run a TACACS+ authentication, with what `port`, `rem_addr` and `auth.method`?
2. Does a `POST /command-api` carrying the cookie authenticate again? Authorize the session again?
   Authorize the command? Account for it?
3. After `POST /logout`, is the cookie refused, and by whom — the device, or port49?

- [ ] **Step 1: Bring it up by hand**

Follow `tests/lab/README.md` "The vertical slice", "By hand", with `eos` and note name
`L7-login-arista_eos`, the broker block included. Then:

```bash
go run ./tests/lab/cmd/slice-pki
bin/port49 login --broker https://127.0.0.1:8449 --cert tests/lab/logs/slice-pki/client.pem \
  --key tests/lab/logs/slice-pki/client-key.pem --broker-ca tests/lab/logs/slice-pki/broker-ca.pem
# wait for breakglass to log in: the device is up
until ssh -o StrictHostKeyChecking=no -o BatchMode=no breakglass@172.100.100.11 'show version | include Software' ; do sleep 10; done
```

(`breakglass`'s password is `labcreds.BreakglassPassword`.) Expected: `port49: logged in to
https://127.0.0.1:8449; the session ends at … (agent pid N, log …)`. Keep N.

- [ ] **Step 2: `/login`, then three cookie requests, then `/logout`**

Each step records the decision-log line count first, so the records it caused can be read back
exactly:

```bash
LOG=tests/lab/logs/decisions-byhand.jsonl
JAR=tests/lab/logs/eapi-cookies.txt
mark() { wc -l < "$LOG"; }
since() { tail -n +"$(( $1 + 1 ))" "$LOG" | jq -c 'select(.session.username=="slice01") |
  {ts, event, verdict, reason, port: .session.port, rem_addr: .session.rem_addr,
   method: .auth.method, cred: (.auth.credential_sha256 // "" | .[0:12]), vector: .request.vector}'; }

TOKEN=$(bin/port49 token leaf1)
M0=$(mark)
printf '{"username":"slice01","password":"%s"}' "$TOKEN" |
  curl -sk -i -c "$JAR" -H 'Content-Type: application/json' --data-binary @- https://172.100.100.11/login
unset TOKEN
sleep 3; since "$M0"

for i in 1 2 3; do
  M=$(mark)
  curl -sk -i -b "$JAR" -H 'Content-Type: application/json' \
    --data '{"jsonrpc":"2.0","method":"runCmds","params":{"version":1,"cmds":["show version"],"format":"json"},"id":"p49-'"$i"'"}' \
    https://172.100.100.11/command-api | head -20
  sleep 3; since "$M"
  sleep 20
done

M=$(mark)
curl -sk -i -b "$JAR" -X POST https://172.100.100.11/logout
curl -sk -i -b "$JAR" -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","method":"runCmds","params":{"version":1,"cmds":["show version"],"format":"json"},"id":"p49-after"}' \
  https://172.100.100.11/command-api | head -20
sleep 3; since "$M"
```

Keep every request and every reply as printed (the `-i` headers included). Before they go into the
note, replace the `Session=` cookie value with `<redacted>`; nothing else is edited. The token never
reaches a terminal: `printf` is a shell builtin and `unset` clears it.

- [ ] **Step 3: Tear down**

Stop the capture and the daemon (`sudo -n pkill -INT -f 'tcpdump.*L7-login-arista_eos'; kill -INT %1`),
stop the agent (`kill <N>`), run `make evidence`, destroy the topology
(`sudo -n containerlab destroy -t tests/lab/topologies/eos.clab.yml --cleanup`), and confirm with
`sudo -n containerlab inspect --all` that nothing is left.

- [ ] **Step 4: Write the note**

Create `tests/lab/results/L7-login-arista_eos.md` in the shape `(*lab).result` writes, by hand:

```markdown
# L7-login — arista_eos

- **Date measured:** <the UTC date of the run>
- **Platform:** arista_eos (containerlab node `leaf1`, 172.100.100.11)
- **Image version:** vEOS-lab 4.31.2F (image tagged 4.32.2F) (`vrnetlab/arista_veos:4.32.2F`)
- **Topology:** `tests/lab/topologies/eos.clab.yml`
- **Capture:** `tests/lab/evidence/L7-login-arista_eos.pcap` (<N> packets, <D> of them device traffic)
- **Transport:** eAPI over HTTPS, `/login` session cookie; token minted by the slice's broker
- **Method:** by hand, plan 3 Task 16; the commands are in that task verbatim

## Claim

Whether eAPI's `/login` session cookie changes how many TACACS+ authentications a sequence of API
requests costs (spec §15, L7, the row's last open clause).

## Observation
```

Under "Observation", one subsection per question 1–3, each giving: the exact request (from Step 2's
output), the device's exact reply (status line and body, cookie redacted), and the `since` output
for that step verbatim. Then a table:

```markdown
| request | redeem | authorize_session | authorize_command | account | port | rem_addr |
|---|---|---|---|---|---|---|
```

with one row per request and the count of each record kind it caused. End with one sentence per
question stating the answer, and an *Unmeasured* line naming what this run did not do (at minimum:
a cookie past `receipt_idle_ttl`, NX-API's `nxapi_auth` cookie, HTTP keep-alive without a cookie).

Every negative — "no authentication", "the cookie was refused" — quotes the exact request and the
exact reply beside it (`CLAUDE.md`; `negativeFinding` in `tests/lab/harness_test.go` is the rule).
If `/login` itself did not work (a 404, a TLS failure, an HTTP 401 with no TACACS+ record), that is
the finding: write the request and the reply, say the clause is unmeasured, and stop.

- [ ] **Step 5: Commit the note and its evidence**

```bash
git add tests/lab/results/L7-login-arista_eos.md tests/lab/evidence/L7-login-arista_eos.pcap
git commit -m "docs: measure the eAPI /login cookie flow on vEOS (L7)

By hand, with a broker-minted token. tests/lab/results/L7-login-arista_eos.md.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 17: Lab, by hand — RESTCONF's `port` on IOS-XE (the API-transport half of L1)

**Platform:** Catalyst 8000V 17.13.01a (`iosxe`) only, one deploy, destroyed at the end.
**Measures:** L1's clause "every non-SSH transport on IOS-XE", over RESTCONF (plan 3, Decided 16):
what `port` and `rem_addr` a RESTCONF request carries at authentication and at authorization,
whether `port` differs between two concurrent requests, and how many exchanges one request costs.
**Token:** a **seeded** one — RESTCONF needs privilege 15, which the slice does not render for
IOS-XE — so the daemon runs the lab config with IOS-XE's `priv-lvl=15` substitution and no broker.

- [ ] **Step 1: Bring it up by hand, without the broker**

Follow `tests/lab/README.md` "The vertical slice", "By hand", with `iosxe` and note name
`L1-restconf-cisco_iosxe`, **except** build the daemon config from the lab file alone with IOS-XE's
attribute line (the harness's `platformSessionAttributes` does the same):

```bash
sed 's/^  session_attributes: .*/  session_attributes: ["priv-lvl=15"]/' tests/lab/port49d-lab.yaml \
  > tests/lab/logs/port49d-byhand.yaml
```

Wait until `breakglass` can log in to `172.100.100.41`.

- [ ] **Step 2: Turn on RESTCONF's AAA, recording what the device says**

In an interactive SSH session as `breakglass`, type each line and keep the device's reply to each:

```
show running-config | include ^ip http|^restconf
configure terminal
ip http secure-server
ip http authentication aaa login-authentication default
ip http authentication aaa exec-authorization default
restconf
end
show running-config | include ^ip http|^restconf
```

The vrnetlab launcher already configures `restconf` (`tests/lab/configs/iosxe-startup.cfg`, the
header), so the first `show` may list it. A line the device refuses is recorded with its exact
reply, and the run continues only if the final `show` lists all four settings.

- [ ] **Step 3: Can the host reach RESTCONF at all?**

Run: `curl -sk -o /dev/null -w '%{http_code}\n' https://172.100.100.41/restconf`
Expected: an HTTP status (401 without credentials). A connection refusal or timeout means the
launcher does not forward 443 to the VM: record the command and its exact output in the note as a
harness limit, mark the clause unmeasured, and go to Step 6.

- [ ] **Step 4: One request, its repeat, and two at once**

```bash
LOG=tests/lab/logs/decisions-byhand.jsonl
SEEDS=/tmp/port49-lab-tokens.jsonl
tok() { jq -r --arg u "$1" 'select(.nas=="xe1" and .username==$u) | .login' "$SEEDS"; }
get() { printf 'user = "%s:%s"\n' "$1" "$(tok "$1")" |
  curl -sk -i -K - -H 'Accept: application/yang-data+json' \
  https://172.100.100.41/restconf/data/Cisco-IOS-XE-native:native/hostname; }
since() { tail -n +"$(( $1 + 1 ))" "$LOG" | jq -c 'select(.device.name=="xe1") |
  {ts, event, verdict, reason, user: .session.username, port: .session.port,
   rem_addr: .session.rem_addr, method: .auth.method, vector: .request.vector}'; }

M=$(wc -l < "$LOG"); get alice01; sleep 3; since "$M"          # one request
M=$(wc -l < "$LOG"); get alice01; sleep 3; since "$M"          # the same credential again
M=$(wc -l < "$LOG"); get alice02 & get alice03 & wait; sleep 3; since "$M"   # two at once
```

`curl -K -` reads the credential from stdin, so it is never in argv. Keep every request, reply
(`-i` headers included) and `since` output verbatim.

- [ ] **Step 5: Tear down**

Stop the capture and the daemon, run `make evidence`, destroy the topology
(`sudo -n containerlab destroy -t tests/lab/topologies/iosxe.clab.yml --cleanup`), confirm with
`sudo -n containerlab inspect --all`.

- [ ] **Step 6: Write the note**

Create `tests/lab/results/L1-restconf-cisco_iosxe.md` with the same header as Task 16's note (node
`xe1`, 172.100.100.41, `Catalyst 8000V 17.13.01a (\`vrnetlab/cisco_c8000v:17.13.01a\`)`,
`tests/lab/topologies/iosxe.clab.yml`, evidence `tests/lab/evidence/L1-restconf-cisco_iosxe.pcap`,
**Transport:** RESTCONF over HTTPS, HTTP Basic, seeded token), a Claim of "What the `port` field
contains on IOS-XE's RESTCONF transport, whether it is unique per concurrent request and stable for
the request's life (spec §15, L1)", and under Observation: Step 2's configuration transcript;
then per request the exact request, the device's exact reply, and the `since` output; then a table

```markdown
| request | authentication `port` | authorization `port` | `rem_addr` | `auth.method` | exchanges |
|---|---|---|---|---|---|
```

and one sentence each on uniqueness across the concurrent pair, stability from authentication to
authorization, and what the repeat cost (a receipt replay, or a new redeem). End with *Unmeasured*:
NETCONF-YANG on IOS-XE, the console, and anything Step 3 stopped.

- [ ] **Step 7: Commit the note and its evidence**

```bash
git add tests/lab/results/L1-restconf-cisco_iosxe.md tests/lab/evidence/L1-restconf-cisco_iosxe.pcap
git commit -m "docs: measure the port field on IOS-XE RESTCONF (L1)

By hand, with a seeded token. tests/lab/results/L1-restconf-cisco_iosxe.md.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 18: The register says what Tasks 16 and 17 measured

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 rows L1 and L7, and their detail
  paragraphs)
- Modify: `docs/design/2026-08-21-port49-design.md` (§19 step 2's last sentence, if L7 closes)
- Modify: `docs/superpowers/plans/README.md` (plan 3's lab line)

The values below come from the two notes. `<DATE>` is the note's "Date measured"; nothing is
written that the note does not say (`CLAUDE.md`, lab register rule 1).

- [ ] **Step 1: L7 — close it, or say why not**

L7 closes when `tests/lab/results/L7-login-arista_eos.md` answers questions 1 and 2 from decision
records (whichever way the device behaved). Then replace the L7 row's Status cell with:

```markdown
closed — measured <DATE>; `tests/lab/results/L7-arista_eos.md`, `L7-cisco_nxos.md`, `L7-login-arista_eos.md`. Per-request HTTP Basic measured 2026-09-20 on both; the eAPI `/login` cookie flow measured <DATE> by hand: <the note's answer to question 2, one clause>; see below
```

In the "- **L7**" detail paragraph, append a paragraph beginning `**The \`/login\` cookie flow,
measured <DATE> by hand** (\`tests/lab/results/L7-login-arista_eos.md\`).` that carries the note's
table and its three answers, and in the row's *Unmeasured* sentence delete the words `the \`/login\`
session-cookie flow, which this row names explicitly and which is the obvious way a device would
avoid re-authenticating;`. If a clause the note answers contradicts text elsewhere in the row, fix
the text and say so in the commit message (`CLAUDE.md`, rule 4).

Then in the design, §19 step 2, replace `Reusable tokens are built here but stay provisional until
L7 closes in step 3.` with `The sliding receipt that replaced reusable tokens (policy engine spec,
§13, decision 15) was provisional on L7, which closed <DATE>.`

If the note says `/login` could not be measured, do none of that: append to the L7 Status cell `;
the \`/login\` flow was attempted <DATE> and not measured — \`tests/lab/results/L7-login-arista_eos.md\``
and leave the row open.

- [ ] **Step 2: L1 — record RESTCONF, keep the row open**

L1 stays open whatever Task 17 found: its console clause is unmeasured on every platform. If the
note measured RESTCONF, in the L1 Status cell replace `IOS-XE and the console unmeasured` with
`IOS-XE's RESTCONF measured <DATE> (\`tests/lab/results/L1-restconf-cisco_iosxe.md\`); the console
and IOS-XE's NETCONF unmeasured`, and in the "Per transport on vEOS" paragraph of the L1 detail add
the sentence `On IOS-XE, RESTCONF reports \`<the note's authentication port>\` at authentication and
\`<its authorization port>\` at authorization (<unique / not unique> across two concurrent
requests); \`tests/lab/results/L1-restconf-cisco_iosxe.md\`.` and remove `every non-SSH transport on
IOS-XE (this lab does not configure RESTCONF or NETCONF-YANG AAA there)` from the *Unmeasured* line,
replacing it with `NETCONF-YANG on IOS-XE`. If Step 3 of Task 17 stopped, add only
`; IOS-XE RESTCONF attempted <DATE>, not reachable from the host — \`tests/lab/results/L1-restconf-cisco_iosxe.md\``
to the Status cell.

- [ ] **Step 3: The roadmap's plan 3 lab line**

In `docs/superpowers/plans/README.md`, at the end of the "## Plan 3" section, add:

```markdown
**Lab, as run:** the slice end to end on vEOS (`tests/lab/results/slice-arista_eos.md`); L7
<closed | still open> on the `/login` measurement (`L7-login-arista_eos.md`); L1's RESTCONF clause
<measured | attempted> on IOS-XE (`L1-restconf-cisco_iosxe.md`), and L1 open on the console.
```

- [ ] **Step 4: Check and commit**

Run: `grep -n 'L7-login-arista_eos\|L1-restconf-cisco_iosxe' docs/design/2026-08-23-policy-engine-spec.md docs/superpowers/plans/README.md`
Expected: the new pointers, in the rows and paragraphs named above.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md docs/superpowers/plans/README.md
git commit -m "docs: close lab register entry L7; record L1's RESTCONF clause

L7's last clause, the eAPI /login cookie flow, measured on vEOS:
tests/lab/results/L7-login-arista_eos.md. L1 gains IOS-XE RESTCONF
(tests/lab/results/L1-restconf-cisco_iosxe.md) and stays open on the
console.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

(If L7 did not close, the subject is `docs: record lab register measurements for L1 and L7`, and
the body says which clause stayed unmeasured and why.)

---

## Self-review

**Roadmap coverage**

| Roadmap item | Task |
|---|---|
| Minimal broker: x509 against one trust anchor | 8 (`Identity`), 10 (`VerifyClientCertIfGiven`, `LoadTLS` exactly one anchor) |
| … over a held mTLS connection | 10 (`heldConn`, no idle close, auth_time per connection), 12 (one connection, `MaxConnsPerHost` 1) |
| … literal-identity subjects | 6 (identity lists, `user:` only), 8 (`user:` + email SAN) |
| … file-backed policy, roles and grants, only `all_devices` | 6, 7 |
| … mint via plan 2 | 9 (`token.Minter.Mint`, `Request.Policy` from 3) |
| … `/v1/tokens` and `/v1/config` only | 9 |
| Agent `port49 login` / `port49 token` over that connection | 12, 13 |
| Agent reconnect: mint a fresh token on reconnect | 12 (every ask a mint; a dropped connection re-dialed; lost response retried under one key), 14 (`TestSliceEndToEnd`'s second window), Decided 11 |
| Borrowed: admission snapshot and key group (plan 6) | Decided 15 — plan 1's file inventory already is it; 11 (`Devices` from `cfg.Inventory`) |
| Borrowed: one blob written and read (plan 4) | 4, 5, 9 (`putBlob`, the `blob` event) |
| Borrowed: one platform's session attributes (plan 5) | 7 (`sessionAttributes`, arista_eos) |
| First end-to-end lab run with a real credential | 14, 15 |
| API-transport half of L1 | 17, 18 (Decided 16 says which clause) |
| eAPI `/login` by hand | 16, 18 |
| PR #7 follow-up 1 (uniform check after `JoinContext`, all three cases, token consumed) | 1 (§5.6), 2 |
| PR #7 follow-up 2 (a refusal replays as `receipt_replayed`) | 2 (`receiptContext` returns the live context; the replay refuses a revoked one) |
| PR #7 follow-up 3 (index loss on a racing replace) | carried to plan 7 — Decided 13, Task 1 Step 5 |
| Plan 2's hand-off: refresh schedule + staleness default together | carried to plan 7 — Decided 14, Task 1 Step 5 |
| Plan 2's owed: `foreign` metric with broker metrics | already done by plan 2b — Task 1 Step 5 says so |
| Spec/design text the plan changes | 1 (§5.6, §5.7 ×3, §14, design §19), 18 (§15 L1, L7) |

**Placeholder scan:** none in code steps. Tasks 16–18 carry `<DATE>` and the note's measured values
as the only parameters, because they are what the lab has not yet said; each says exactly where the
value comes from and what to write when the measurement fails.

**Type consistency, checked:** `blob.CheckRule` (Task 4) is what Task 6 calls; `blob.Blob{Platform,
Privilege, Attributes, Permit, Deny}` is built only by `policy.Resolve` and read by `author.Blob` and
the broker's `putBlob`; `policy.Resolve(principal, platform string) (Resolution, bool)` and
`SubjectOf(principal) (string, bool)` have the same signatures in Tasks 6, 7, 9 and 14;
`decision.PolicyGrant{Scope, Roles}` is produced by `Resolve` and carried by `token.Request.Policy`;
`decision.Record.Blob` is written only by `putBlob`; `broker.Identity(cs, now)` returns
`(string, store.Credential, error)` in Tasks 8 and 9; `Broker`'s fields are the same in Tasks 9, 10
and 11; `withHeldConn` is Task 9's and Task 10's `ConnContext`; `api.*` types are shared by the broker
(9) and the agent (12) and nothing else defines their JSON; `agent.Config`, `Mint`, `SessionEndsAt`,
`Handshakes`, `Handler`, `Listen`, `PrivateDir`, `NewClient`, `Token`, `Status`, `ErrSessionOver`,
`ErrNoAgent` are used by Task 13 with Task 12's signatures; `testpki.WriteLab(dir, email, now)` and
its `Lab*` constants are used by Tasks 10, 11 and 14 alike; `receiptContext` replaces
`receiptContextLive` at both call sites and in the one comment that names it.

**Things an implementer must not miss.** Task 2 changes one existing test's expectation
(`TestAContextUnderARetiredKeyIsReplacedCarryingItsRevocation`: PASS becomes `credential_revoked`)
and tightens another (`TestARevocationSurvivesATokenMintedBeforeIt`'s retry): both are the spec
change of Task 1, not regressions. Task 6 creates `resolve.go` with `SubjectOf` alone and Task 7
replaces the file whole. Task 10 changes the fixture's clock to a locked one; tests that assign
`f.now` directly stay single-goroutine. Task 11's `Load` edit goes in `Load`, not in `Keyring`.
Task 13 is where `make build` starts building `bin/port49`; Task 14's lab test fails fast without
it. Tasks 15–17 are one platform each, idle-checked first and destroyed after; a lab FAIL is a
finding to write down before any code changes.

**Unmeasured, and not relied on:** what IOS-XE does with a session reply carrying no attributes
(Question 2; the slice mints there but the lab never logs in there with a broker token); what `port`
IOS-XE's RESTCONF carries (Task 17 measures it; no code reads it); whether any device honours an
eAPI cookie past the token's receipt window (Task 16's *Unmeasured* line).

---

## Execution

Runs on Go 1.22 with no new dependencies, on branch `feature/vertical-slice`. Eighteen tasks:
thirteen code (2–14), three lab (15–17), two docs (1, 18), one commit each. Tasks 1–14 need no
containerlab and go first, in order; Tasks 15–17 need the lab host, one platform at a time; Task 18
follows the notes it cites. The code gate, after Task 14 and again at the end, is `make test && make
vet`, `go test -race ./internal/...`, and `go vet -tags lab ./tests/lab/...`, reported with their
real output.
