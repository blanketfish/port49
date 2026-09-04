# port49 — Policy Engine Specification

**Status:** Draft
**Date:** 2026-08-23
**Companion to:** [`2026-08-21-port49-design.md`](2026-08-21-port49-design.md)

This document specifies the authorization engine: how a TACACS+ request becomes a
decision. The design document covers architecture and rationale; this one is meant to be
implementable.

Configuration keys are `snake_case` throughout.

---

## 1. Scope

The engine answers three questions, at three different moments:

| Point | Question | Component |
|---|---|---|
| **Mint** | May this principal reach this device at all? | broker |
| **Session** | What shell profile does this login get? | daemon |
| **Command** | May this command run here, now? | daemon |

The middle one is easily overlooked and must not be. The session point is the `service=shell`
authorization with an empty `cmd`, which returns `priv-lvl`, `shell:roles`,
`local-user-name`, `idletime`, and friends — and it is where a large share of real-world
TACACS+ deployments do *all* of their authorization, because platforms such as Junos have no
meaningful per-command path. It maps directly onto `aaa authorization exec` in device
configuration, as the other two map onto `aaa authorization commands` and
`config-commands`.

---

## 2. Concept model

The full taxonomy — every authored, imported, and runtime object, what creates each, and how
they compose — lives in the design document, §6. This section covers only the distinctions
that need argument rather than definition.

**Device is a fact; Scope is a selector.** Inventory is imported and describes reality.
Scopes are authored and describe intent. Keeping them separate is what makes
`match: {site: us_west}` mean something.

**Principal is runtime; Subject is policy.** A principal is `CN=alice,OU=netops,O=example`
or `system:serviceaccount:netops:oxidized`. A subject is how policy addresses a set of
them, and it has exactly two forms — an LDAP group, or one or more literal identities. That
single mechanism covers both directory-driven human access and hand-maintained service
accounts.

**A subject MAY list several identities.** Matching already resolves a set — an LDAP group
yields many principals — so accepting a list costs nothing and makes credential migration a
non-event:

```yaml
subjects:
  - name: svc_oxidized
    identity:
      - "spiffe://port49/host/oxidized-01"        # VM, workload certificate
      - "system:serviceaccount:netops:oxidized"   # Kubernetes, once migrated
    enable: token
    token_ttl: 900s
```

Both resolve to the same subject and therefore the same grants. An operator adds the second
identity, cuts over, and removes the first — with no window in which the workload is denied
and no policy change during the migration. It also covers a workload that legitimately runs
in two places at once.

Identities from different trust domains MUST remain distinguishable (§7 of the design
document): listing a human and a machine identity under one subject is a policy load error,
not a convenience.

### The device-facing username

A principal is not what anyone types at a login prompt. `CN=alice,OU=netops,O=example` is
the identity; `alice` is the username the device sends. The two are distinct strings and
both are load-bearing — the token store is keyed `(nas, username)`, username binding is a
MUST (design document §8), and accounting attributes to the principal behind it. The mapping
between them therefore has to be explicit.

**For human identities it is already resolved at mint**, by the same directory lookup that
fetches groups. No additional query:

| Identity path | Username source |
|---|---|
| LDAP or AD | `sAMAccountName` / `uid`, from the group-resolution query |
| OIDC | the `preferred_username` claim |
| certificate | via the certificate-to-directory mapping (§7 of the design document) |

**Machine identities have no directory entry**, so the subject declares one:

```yaml
subjects:
  - name: svc_oxidized
    identity: ["system:serviceaccount:netops:oxidized"]
    username: svc-config-backup        # what the device will present
```

**Usernames MUST be unique across subjects.** Two subjects claiming one username collide in
the `(nas, username)` store key and make the audit trail ambiguous; this is a policy load
error. Collision with a device-local account name is the same hazard described in §5.6 and
SHOULD be reported where port49 can observe it.

**Comparison is normalized.** The device sends whatever the operator typed — `alice`,
`DOMAIN\alice`, or `alice@corp.example.com`. The broker records a canonical form, and the
daemon compares case-insensitively after stripping a domain prefix or UPN suffix. Without
this, a user who types their address rather than their shortname is denied with
`context_missing` and no obvious cause.

**Privilege decides what the device will offer; the role decides what port49 will permit
within it.** The two are not independent axes — the effective permission set is the
intersection, and the role is always a subset. A backup account needs `admin` privilege so
`show running-config` is *reachable*, while command rules confine it to `show`. Set the
level too low and permitting rules become dead letters, because the device never submits
those commands. See §6.

---

### Terminology

The complete taxonomy — every authored, imported, and runtime object, and how they compose —
is in the design document, §6. It is maintained there rather than duplicated here so the two
cannot drift.

Four overloads are worth restating, because they are the ones that mislead implementers:

**`session` versus `session authorization`.** The first is the operator's 8–16 hour
authenticated state, held by the agent. The second is a TACACS+ exchange at login —
`service=shell` with an empty `cmd` — which returns the shell profile. They are unrelated
despite the shared word, and the protocol term is fixed by RFC 8907.

**`login context` is per *login*, not per session.** One operator session produces many
logins, each with its own context keyed `(nas, port)`.

**`token` versus `presented credential`.** The token is what port49 mints. The presented
credential is what arrives in the authentication packet — the token verbatim for PAP and
ASCII, but `ppp_id ‖ challenge ‖ response` for CHAP, which proves possession without
carrying it. The distinction is what lets one receipt rule (§5.6) cover all three types.

**`token` versus `handle`.** The same thing. *Handle* survives only where the design document
contrasts an opaque handle with a signed token; new text says token.

---

## 3. Request normalization

The matcher never sees raw wire data. A platform adapter converts an authorization request
into a canonical form:

```
principal      resolved from login context, not from the wire
device         resolved from source address via inventory
service        shell | <other>
privilege      priv_lvl from the request header
command        [cmd, arg1, arg2, ...]     lower-cased, <cr> stripped
pipeline       [[stage_cmd, arg, ...], ...]   split at the platform's pipe token
```

### Why normalization is its own layer

A command authorization request arrives tokenized, not as a string:

```
cmd=show  cmd-arg=running-config  cmd-arg=|  cmd-arg=redirect
cmd-arg=ftp://10.9.9.9/cfg  cmd-arg=<cr>
```

Reconstructing that into `"show running-config | redirect ftp://10.9.9.9/cfg"` and matching
a regex against it is the traditional approach and it is lossy: the `=` versus `*` flag is
discarded, embedded whitespace becomes indistinguishable from argument boundaries, and two
different requests can produce the same string. Matching the vector directly avoids the
entire class.

### Normalization rules

1. **Strip the trailing `<cr>`** where the platform sends one.
2. **Split at the pipe token** into a command and zero or more pipeline stages.
3. **Comparison is case-insensitive; the vector is not altered.** Device CLIs accept
   mixed-case keywords, so a case-sensitive match is bypassable with `SHOW run`. Literal
   terms and entity-class patterns therefore compare case-insensitively, and regex terms
   compile case-insensitive **by default**, with `(?-i)` available to opt into exactness
   where a device object really is case-sensitive (IOS ACL names, for instance).

   Insensitive must be the default because a case-sensitive deny fails *open*: a rule
   reading `deny: interface /^Management/` would otherwise be evaded by typing
   `interface management1`.

   The vector itself is left as received, so accounting records what the operator actually
   typed.
4. **Expand abbreviations** where `expands_abbreviations: false`. If a platform sends what
   the operator typed rather than the resolved command, `sh run` must be expanded to
   `show running-config` before matching, or `show **` is bypassable. Where port49 cannot
   expand reliably, the platform MUST be marked as such and the daemon MUST fail closed
   rather than match a possibly-abbreviated vector.
5. **Preserve argument boundaries.** Arguments are never re-joined.

---

## 4. Matching

### Grammar

A rule is a whitespace-separated sequence of terms, matched against the canonical command
vector.

| Term | Matches | Specificity |
|---|---|---|
| `word` | exactly that argument, case-insensitively | 3 (most specific) |
| `@class` | one argument in a platform-defined entity class (§8) | 2 |
| `/re/` | one argument matching the RE2 expression | 2 |
| `*` | exactly one argument, any value | 1 |
| `**` | zero or more arguments — **trailing position only** | 0 (least specific) |

**`@class` and `/re/` share a rank deliberately.** Neither is reliably narrower than the
other: a regex may name exactly one interface while a class holds forty-eight, or the
reverse. Ranking one above the other would be an invented ordering that is wrong half the
time, and it would let `interface @physical` silently beat
`interface /^Ethernet1$/`. Equal rank means neither dominates the other at that position, so
the conflict resolves conservatively (§5.4).

A corollary: `/^.*$/` is semantically identical to `*` but would rank higher, so CI SHOULD
flag a regex that is equivalent to `*` or to a literal and require the simpler spelling.
This is a lint concern rather than a soundness one, but an unlinted policy would let a rule
buy specificity by how it is written rather than by what it constrains.

```yaml
permit:
  - show **                          # show, and anything after it
  - show bgp summary                 # exactly that, nothing more
  - clear counters *                 # one argument
  - interface @physical              # platform-defined class
  - interface /^(ethernet|port-channel)[0-9/.]+$/
```

**Rules match the full vector.** There is no implicit prefix match — `show bgp summary`
does not match `show bgp summary detail` unless the rule ends in `**`. This is the
property that makes the engine safe by default and is the main practical difference from
unanchored regex.

**`**` is trailing-only** so matching stays linear. Mid-pattern wildcards would be needed
to express things like `show ** | redirect **`; splitting the pipeline out during
normalization removes that need entirely, which is why the split belongs in the adapter
rather than in the grammar.

**Regex is confined to a single argument.** RE2 (Go's `regexp`) has no catastrophic
backtracking, and a leaf regex can never span argument boundaries, so its blast radius is
one position. Regex terms are also the only construct that degrades the effective-permission
diff (§12), which is a reason to prefer literals, `@class`, and `*` where any will do.

**Entity classes solve cross-platform naming.** A rule reading
`deny: interface /^(management|mgmt)/` works on EOS and NX-OS and silently does nothing on
Junos, where the interface is `fxp0` — no error, no warning, the deny simply never matches.
Writing `deny: interface @management` instead delegates the spelling to the platform
adapter, which classifies rather than canonicalizes. We never need to know that `ge-0/0/1`
and `Ethernet1/1` are the same kind of thing; we only need each platform to say which of
its names are management interfaces. A rule referencing a class the platform does not
define is a **policy load error**, which makes the silent-no-match failure impossible.

### Pipeline stages

Output modifiers are matched separately and are **allow-listed, not deny-listed**. A
blocklist fails open on the next vendor extension; an allowlist does not.

Every role inherits a shipped default allowlist unless it declares its own:

```yaml
pipe:
  permit: [include **, exclude **, begin **, section **, json, count, no_more]
```

This matters because `show running-config | redirect ftp://…` is an exfiltration primitive
and `| append` is a write primitive, both wearing a read-only command's clothes. A role
whose only rule is `show **` permits both unless pipeline stages are evaluated.

Each stage of a chain is evaluated independently:
`show run | section bgp | include neighbor` is two stages, both checked.

**Platform caveat.** Some devices apply output modifiers locally *after* authorizing the
base command, so the pipeline never reaches port49. Those platforms MUST set
`pipe_authorized: false`, and port49 MUST NOT imply a protection it cannot deliver — the
control moves onto the device (disabling `copy`, `redirect`, file privileges). `port49
explain` MUST say so when asked about a pipeline rule on such a platform.

---

## 5. Evaluation

### 5.1 Mint (broker)

```
principal
  → subjects            match by LDAP group membership or any listed identity
  → grants              those whose subject matches AND whose scope matches this device
                        AND whose `expires` has not passed
  → roles               union across matching grants
  → privilege           max over granted roles (no grant-level override)
  → max_privilege       max over matching grants; absent means no escalation
  → effective rules     resolved permit/deny/pipe sets
  → av_pairs            rendered for this device's platform
```

Failure to match any grant means the device is unreachable for that principal, and the mint
fails **before an SSH connection is opened**.

### 5.1.1 Where the resolved policy waits

The broker computes this result, but the daemon needs it — and the key it will eventually
live under is not knowable at mint. Login context is keyed on `(nas, port)`, and the port
is the device's tty or vty string, which does not exist until the device opens the
authentication exchange. **The broker therefore cannot write login context.**

The resolved result is instead stored as an immutable, **content-addressed policy blob**,
referenced by the token:

```
blob:<sha256>            the fully compiled decision — see 5.1.2
token:(nas, username)    { handle, blob_hash, principal, ... }
```

On successful redemption the daemon creates login context, which holds **the hash rather
than a copy**:

```
ctx:(nas, port)
  ctx_id            01J9F3QK…            assigned at creation; correlates every record
  principal         alice@example.com
  username          alice                bound; compared on every later exchange
  rem_addr          198.51.100.4         bound; compared on enable
  privilege         15
  blob_hash         sha256:a3f9c1…
  credential        see 5.1.4
  auth_time         1757041495           when the human actually authenticated
  session_expires   1757070295           auth_time + max_session_age
  task_id           42                   from exec accounting, once observed (5.8)
  accounting_state  open | closing       advisory (5.8); never authorizes or denies
```

`ctx_id` is assigned once, at creation, and never changes. It is the join key between the two
record streams: every decision (§5.7) and every resolvable accounting record (§5.8) carries
it, which is what makes a single identifier reach from an OIDC login to a typed command.

**Why content-addressed.** A batch mint resolves to the same value for every device in one
scope — what varies is the rendered attributes, and those vary by *platform*, not by device.
A sweep across 10,000 devices spanning four platforms therefore produces **four** blobs, not
ten thousand. The blob is written once and referenced by every token that resolves to it.

**Why the context holds a hash.** Blobs are immutable, so each daemon replica caches them by
hash indefinitely with no invalidation problem. Per-command authorization is then one small
context read plus a local cache hit, rather than two store round trips — which is what keeps
the p99 target reachable.

**Lifetime.** A blob carries a TTL slightly exceeding the maximum token TTL, so it expires on
its own. No reference counting is required.

**Cost.** One additional store read at redemption, on the *login* path. The p99 < 5ms target
governs per-command authorization, which is unaffected.

### 5.1.2 The blob is fully compiled

Evaluating a command requires platform knowledge: normalization needs the pipe token, the
`<cr>` convention, and the abbreviation flag, while matching needs the actual regexes behind
each `@class`. The design document's claim that the daemon "never learns what a platform is"
therefore cannot hold for command authorization as literally as it does for attributes.

It is resolved by **compiling the platform into the blob** rather than shipping platform
definitions to the daemon. The broker already knows the device's platform at mint, so it
expands entity classes and embeds the normalization parameters:

```yaml
blob:a3f9c1…
  rules:
    permit: [[show, **], [interface, /^Ethernet[0-9/]+$/]]
    deny:   [[reload, **], [interface, /^mgmt[0-9]+$/]]     # @management, expanded
    pipe:   [[include, **], [section, **], [json]]
  normalize:
    pipe_token:            "|"
    strip_cr:              true
    expands_abbreviations: true
  enable_username:  "$enab{level}$"
  privilege:        operator
  max_privilege:    admin
  attributes:       ['shell:roles*"network-operator"']
```

The daemon becomes a pure executor: it normalizes with the given parameters and matches
against compiled rules. It never reads a platform file, never resolves a class, never decides
whether to strip a terminator.

**The governing distinction:**

> The inventory bundle (§10) carries **facts**. The blob carries **decisions**.

The daemon needs facts to accept a connection — which device this source address is, which
shared key to use. It needs a decision to authorize a command. Dialect data is used only
while evaluating a decision, so it travels with the decision.

**Why not distribute platform definitions to the daemon.** A shared bundle version would make
that safe in principle, but it has to actually be shared: a replica that has not refreshed, a
rolling upgrade in flight, or a pod started before the bundle rotated all reintroduce skew.
A hash-named blob is self-describing — whatever compiled it is what evaluates it, permanently
— so the failure cannot occur rather than merely being unlikely. It is also far easier to
debug: one blob dump shows exactly what was evaluated, with no need to recover which platform
version a daemon held at the time.

**Cost.** Blobs grow from a few hundred bytes to a few kilobytes. Because they are
content-addressed, deduplication is per policy-version and platform rather than per token, so
a 10,000-device fleet across four platforms yields a few dozen blobs.

**One escape hatch.** If a platform is found to require genuine abbreviation expansion, its
command vocabulary is too large to embed per blob; that table alone would ride in the
inventory bundle while everything else stays compiled. Most platforms expand server-side and
§3 already fails closed where expansion is unreliable, so this is recorded rather than
designed for.

### 5.1.3 Refreshing live context

The broker refreshes login context while a login remains active (design document §9), which
requires it to discover which contexts exist. Nothing in the store makes that discoverable by
itself, and scanning the keyspace is both store-specific and expensive at scale.

The daemon MUST therefore maintain an index as it creates and tears down context:

```
contexts_by_principal:(principal)   → set of (nas, port)
```

Refresh then means: the broker re-resolves for a principal whose group membership has
changed, writes a new blob if the result differs, and updates `blob_hash` in each of that
principal's live contexts. Contexts are small, so the update is cheap, and because blobs are
immutable a replica's cached copy of the old blob is never wrong — it is simply no longer
referenced.

This also makes **policy-driven revocation reach active sessions**, not only directory-driven
revocation. A policy change that removes a grant produces a different blob, and live contexts
pick it up on the next refresh.

### 5.1.4 Credential identity and revocation

Login context records which credential authorized it. Not to re-verify — **the daemon never
sees the credential.** The certificate or OIDC assertion is presented to the *broker* at mint;
the command exchange carries only `user`, `port`, `rem_addr`, and `priv_lvl`. A fingerprint
therefore cannot tighten per-command comparison, because the device has nothing to compare it
against.

What it buys instead is revocation that reaches a live device session, and attribution that
survives in the log. The test applied to each field is narrow: **does it enable an action
otherwise impossible?**

```
credential:
  method       cert | oidc

  # cert
  fingerprint  sha256:4c1e…        what an operator or tool actually pastes
  issuer       CN=Corp Issuing CA  }  a CRL or OCSP response names exactly
  serial       0x3f9a01…           }  these two
  subject      CN=alice,OU=…

  # oidc
  iss          https://sso.example.com
  sub          a7f3-…              revokes every session of a principal
  sid          9c2b-…              back-channel logout names this
  amr          ["pwd", "mfa"]      recorded, not yet acted upon
  acr          urn:…:loa2
```

**`sid` is the most valuable field here.** OIDC back-channel logout delivers a logout token
naming `sid` (or `sub`), so an SSO logout — a stolen laptop, an offboarding — reaches the
operator's live router sessions. Without it, that is not merely slow; it is impossible.

**`amr` and `acr` are recorded because they are unrecoverable later.** Nothing can establish
afterward how someone authenticated. They are not consulted by v1 evaluation; a role that
requires MFA is a natural extension and would be unimplementable retroactively without them.

**Certificate `notAfter` and the OIDC `exp` are deliberately absent.** They bound the *mint* —
the credential MUST be valid when the broker resolves it — and not the session. An ID token's
`exp` is commonly minutes, and treating it as a session ceiling would end a router session
every hour for no security gain. Session lifetime is port49 policy, held in
`session_expires` and derived from `auth_time` (§5.6).

**Consequence for the store.** Context now holds identity material — subject DNs, `sub`
claims, an operator's name. None of it is a credential, but it is PII-adjacent, so **login
context MUST receive the same encryption-at-rest treatment as tokens** (design document §8).
That obligation previously covered tokens alone.

### 5.2 Session authorization (daemon)

On `service=shell` with an empty `cmd`, the daemon returns the AV pairs already stored in
login context. No computation, no platform knowledge, one store read.

If login context is absent, the daemon fails closed and logs a distinct reason —
`context_missing` is operationally very different from `denied_by_policy` and the two must
never share a log line.

### 5.3 Command authorization (daemon)

```
normalize(request)
  → if no login context                → DENY (context_missing)
  → collect every matching rule, permit and deny alike
  → if no permit matches                 → DENY (default_deny)
  → if no permit dominates every
    matching deny (§5.4)                 → DENY (rule, role)
  → for each pipeline stage:
        if stage matches no pipe permit  → DENY (pipe_stage, stage_name)
  → PERMIT (rule, role)
```

Default is deny. Every decision carries the rule and role that produced it, which is what
makes `explain` able to name exactly one reason.

Requests for a `service` other than `shell` are denied by default with a distinct reason,
configurable per platform.

### 5.4 Composition across roles

> **Permit if some permit rule dominates every matching deny. Otherwise deny.**

There is exactly one deny mechanism. Permits and denies from every granted role are
collected into one set and resolved by specificity — but specificity is a **partial** order,
not a total one, and that is the point.

**Specificity tuples.** A rule matching an N-argument command produces an N-element tuple:
one slot per argument of the *command*, not per term of the rule, each holding the rank
(§4) of whatever term covered it. A trailing `**` contributes a `0` for every position it
absorbs.

```
command:    show     chassis    hardware
            ────     ───────    ────────
rule A:     show     chassis    hardware
                3          3           3      →  (3, 3, 3)
rule B:     show     chassis    **
                3          3           0      →  (3, 3, 0)
rule C:     show     **
                3          0           0      →  (3, 0, 0)
```

**Dominance.** Rule X dominates rule Y when X is greater than or equal to Y at *every*
position and strictly greater at *at least one*. This is all-or-nothing: losing a single
position is enough to fail, no matter how many others are won.

```
copy running-config tftp://evil/

permit copy **                     (3, 0, 0)
deny   * * /^(tftp|ftp|scp|http):/ (1, 1, 2)

does the permit dominate?   requires ≥ at EVERY position
  pos 1:  3 ≥ 1   ✓
  pos 2:  0 ≥ 1   ✗   ← fails here
→ no                                          result: DENY
```

The two rules disagree about which position matters — the permit named the command, the
deny named the destination — so no dominance relation exists and the deny stands.

**The test is one-sided.** A deny never has to dominate anything; it is the default and wins
by not being beaten. Only the permit must prove itself. That asymmetry is the safety
property: an exception is admitted only when it is unambiguously narrower, never merely
narrower in the places its author happened to care about.

```
show chassis hardware

permit show chassis hardware  (3, 3, 3)
deny   show chassis **        (3, 3, 0)
  pos 1: 3 ≥ 3 ✓   pos 2: 3 ≥ 3 ✓   pos 3: 3 ≥ 0 ✓, strictly greater
→ dominates                                   result: PERMIT
```

**The practical rule for authors:** an exception must be at least as precise as the rule it
excepts, at every position that rule constrained. Naming `copy running-config` does not buy
back an unrestricted destination — the destination must be named too:

```
permit copy running-config @backup_targets   (3, 3, 2)   → dominates, PERMIT
permit copy running-config *                 (3, 3, 1)   → pos 3 fails, DENY
```

**Why not a single score.** Lexicographic comparison, a sum of ranks, and a run-collapsed
distance metric were each evaluated and each fails on real policies, in different places.
Any scheme reducing the tuple to one comparable number *must* produce an answer even when
the rules genuinely disagree about which position matters — so some case always resolves
against intent. Under lexicographic ordering, for instance, a permit naming the first word
beats any deny constraining a later argument, defeating exfiltration and disruptive-form
denies outright. The vulnerability is in the collapsing, not the arithmetic. A partial order
that declines to rank incomparable rules is the only formulation that stays conservative in
every case.

**Ties and explain.** Where several rules of the same verdict match and `explain` must name
one, the tie is broken by lexicographic comparison of the tuples, then by declaration order.
This is presentation only and cannot change a decision.

Specificity is a property of the rule and the command, never of position in a file, so
**evaluation is order-independent**: reordering roles, grants, or rules within a role cannot
change any decision. Formatters, merge conflicts, and role refactors are provably safe.

Because rules insert into a trie and the result is a total function over command space, the
**effective-permission diff stays exact** — old versus new is a computable difference, not a
sample of whatever commands a test corpus happened to contain.

**Why not deny-overrides.** A global deny-wins rule is simpler to state, but it cannot
express an exception. Once `show chassis **` is denied — say, in response to a CVE — the
only remedy is to narrow the deny itself, which requires negation: *deny `show chassis`
anything except `hardware`*. The leaf regex is RE2, which has **no lookahead**, so
`/^(?!hardware$)/` does not compile, and the alternative is enumerating every subcommand
positively and being wrong the next time the vendor adds one. Deny-overrides therefore
needs an exception mechanism bolted on regardless; most-specific supplies one in the grammar
already present. This is not hypothetical — a broad `show chassis *` deny added for a CVE
breaking a backup account's `show chassis hardware` is the motivating case.

**What is given up, and what replaces it.** Under deny-overrides a deny is a guarantee.
Under most-specific it is a default that a more specific permit can override. The
replacement is not a second construct but **visibility**: CI MUST report every shadowed
deny, naming the rule, the subject, and the permit that beats it.

```
⚠ SHADOWED — this deny will NOT apply:
    svc_oxidized  permits "show chassis hardware"        (more specific)
    security_ir   permits "show chassis cluster status"  (more specific)
```

You learn the deny is incomplete when you write it, not when a backup run fails.

**Deliberate exemptions use the same mechanism.** A narrower permit is how an exception is
expressed, so incident response reaching one command under a broad prohibition needs no new
concept:

```yaml
roles:
  - name: cve_2026_xxxx
    reason: "CVE-2026-XXXX — SRX cluster subsystem"
    deny:  [show chassis cluster **]

  - name: cve_2026_xxxx_assess
    reason: "CVE-2026-XXXX — IR needs cluster state to assess exposure"
    permit: [show chassis cluster status]
```

**Two consequences for CI.** A deny may be inert if shadowed, so *"adding a deny is always
safe"* no longer holds; and a permit may override a deny, so *"only permit growth widens
access"* becomes the check that matters. Both are computable from the trie, and the gate is
stated directly: **this change makes command C permitted where it was denied.**

### 5.5 Scoping policy to device state

Scopes match device attributes (§10), and those attributes change. A scope keyed on a
*changing* fact makes the population it selects shrink as reality changes, which turns
mitigation into something that lapses on its own:

```yaml
scopes:
  - name: srx_unpatched
    match:
      platform: juniper_junos
      os_version: {lt: "21.4R3-S5"}
    on_missing: include        # no version data → assume vulnerable
    security_log: true         # membership changes log as security events

grants:
  - {subject: everyone, scope: srx_unpatched, roles: [cve_2026_xxxx]}
```

`everyone` is a built-in subject matching every principal. It is not a special deny path —
the same role and grant machinery, applied universally — which is why there is still only
one place to deny a command.

Three properties make this materially better than a curated device list:

- **Coverage includes devices that do not exist yet.** A device racked after the CVE lands
  is covered the moment it appears in inventory. Hand-maintained lists cannot do this.
- **Mitigation lifts per device as it is remediated**, so partial upgrades behave correctly
  and no coordinated removal step is required.
- **Scope size is the remediation burndown**, queryable rather than tracked in a spreadsheet.

The same shape covers other lifecycle states: `{tag: change_freeze}` to deny configuration
during a freeze, `{status: staged}` to restrict pre-production devices, `{status:
decommissioning}` for read-only on the way out.

**Two requirements this places on the implementation.**

`on_missing` MUST be explicit where an attribute is optional, and the safe direction differs
by rule type: for a deny-bearing scope, a missing attribute means *include* (assume
vulnerable); for a permit-bearing scope it means *exclude*. A broken inventory sync silently
lifting a mitigation is the failure to design against.

`security_log: true` marks a scope whose membership changes are security events. This is
required because a scope keyed on device state makes **source-of-truth write access
security-relevant** — whoever can edit `os_version` can lift a mitigation without touching
policy, and that field is often written by a discovery tool rather than a person. Version
data used for security scoping SHOULD come from an attested path.

### Version comparison

`lt` and `gte` on a version string use one generic comparator. Vendor version strings are not
semver — `21.4R3-S5`, `4.31.2F`, `10.2(5a)`, `15.2(4)E10` — and a semver library would
actively mis-order them, since semver treats a suffix after a dash as a *pre*-release and
would sort Junos service release `21.4R3-S5` **below** `21.4R3`.

Instead, tokenize into runs of digits and runs of letters, discarding separators
(`.`, `-`, `(`, `)`, `_`, `/`), upper-casing letters, then compare element by element:

| Comparison | Rule |
|---|---|
| digit run vs digit run | numeric |
| letter run vs letter run | **equality only** — never alphabetical, since `M > F` is meaningless |
| letter run vs digit run | incomparable |
| one sequence is a prefix of the other | the shorter is lower |

```
21.4R2-S9  → (21,4,R,2,S,9)
21.4R3     → (21,4,R,3)         position 3: 2 < 3   → R2-S9 is older
4.31.2F    → (4,31,2,F)
4.31.10F   → (4,31,10,F)        position 2: 2 < 10
17.09.04a  → (17,9,4,A)
17.09.04   → (17,9,4)           shorter is lower    → the rebuild is newer
10.2(5a)   → (10,2,5,A)
```

**An incomparable version is treated exactly as a missing one**, resolving through
`on_missing` — included in a deny-bearing scope, excluded from a permit-bearing one. If it
cannot be determined whether a device is patched, it is assumed not to be. This requires no
per-vendor configuration and fails in the safe direction.

Letters are compared by equality because their meaning is vendor-specific: in Arista's scheme
`F` and `M` mark lifecycle stage within one train, while Cisco's `E` and `S` are separately
built trains that are genuinely not orderable.

**Letters are reached only when every preceding number is equal**, which makes incomparability
rare in practice. Arista increments the third digit across the F-to-M transition, so
`4.31.5M` versus `4.31.2F` resolves at position 2 — `2 < 5` — and the letters never enter into
it. The genuine collision is `15.2(4)E10` versus `15.2(4)S10`, where the numeric prefixes match
and position 3 is `E` against `S`; refusing there is correct, because those are different code
bases rather than different points on one line.

**That cost MUST be visible.** Any scope resolving a version comparison MUST report the
devices it included because comparison failed:

```
srx_unpatched: 47 devices
  ⚠ 3 included because their version could not be compared to "21.4R3-S5"
      srx-fw-22 (21.4X75-D40), srx-lab-01 ("unknown"), srx-fw-31 (21.2R1-EVO)
```

The remedy is then obvious — an explicit version list, a regex, or exclusion by another
attribute. Silent inclusion is what makes this dangerous; reported inclusion makes it
ordinary.

Exact and regex matching on version strings remain available and require no comparator.

CI SHOULD report a scope that has matched no devices for an extended period — a mitigation
whose population has emptied is dead code, and saying so is how policy cleans itself up.

---

### 5.6 Login context lifecycle

**Creation.** Login context is created **only on successful token redemption**, by the
daemon, keyed `(nas, port)`. Nothing else creates it. A session port49 did not authenticate
therefore has no context and is denied — which is correct, since port49 has no basis on which
to authorize it.

The shape is given in §5.1.1; §5.1.4 covers the credential fields.

**Bound attributes.** `username` and `rem_addr` are recorded at creation and compared
thereafter:

| Exchange | Check |
|---|---|
| command authorization | `username` MUST match; a mismatch denies and invalidates |
| enable, `enable_username: principal` | `username` MUST match |
| enable, `$enab{level}$` platforms | `rem_addr` MUST match |

#### port49 denies commands; it cannot end a session

There is no server-to-device disconnect in TACACS+. Every mechanism below stops port49
*authorizing* — the TCP session stays up, a candidate configuration stays intact, an
in-progress commit is untouched. "Teardown" throughout this document means discarding state,
never dropping a connection. That bounds the worst case of every rule here: an operator is
told no, not cut off.

#### Teardown, ordered by authority

Earlier drafts listed triggers by *reliability* and let all of them delete state. That was
wrong. The bindings above are the security control; teardown is state hygiene. A signal port49
did not generate and cannot verify MUST NOT delete state.

| | Trigger | Authority |
|---|---|---|
| 1 | **Redemption** on the same `(nas, port)` | port49 performed it — overwrites unconditionally |
| 2 | **Revocation** — OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial; a policy change withdrawing every grant | authoritative, from the identity layer (§5.1.4) |
| 3 | **Session ceiling** — `session_expires` reached and the grace window elapsed | local, needs no external signal |
| 4 | **Username mismatch** on a command or enable exchange | a genuine conflict on that line — denies and invalidates |
| 5 | **Authentication START** on the same `(nas, port)` under a different username, *including one port49 rejects* | a failed authentication is still evidence a new session is beginning. With ASCII login the username arrives in a CONTINUE, so the check fires once it is known |
| 6 | **Idle TTL** | hygiene; bounds abandoned state |
| 7 | **Exec accounting** | **advisory only — annotates, never deletes** (§5.8) |

**Why accounting was demoted.** It is best-effort, device-generated, and delivered on a
separate connection that can be queued or bounced off another server first. A delayed logout
STOP therefore arrives after the line has been reused:

```
t0   Bob's session on ls01 vty0 ends
t1   device emits  STOP user=bob port=vty0 task_id=42   → delayed 4s
t2   Alice authenticates, redeems, ctx:(ls01, vty0) = { alice, … }
t3   the delayed STOP arrives  →  teardown fires on (ls01, vty0)
t4   Alice's next command  →  context_missing  →  denied mid-session
```

Fail-closed, so not dangerous — but a self-inflicted outage, and one whose two halves look
unrelated in a log. Matching on username fixes Bob-then-Alice and not Bob reconnecting to the
same line. Rather than patch it, accounting now sets `accounting_state: closing` and nothing
more; row 6 reclaims the state. §5.8 specifies the annotation, including the `task_id`
binding that makes it correct.

**Idle TTL is a backstop, not a control.** It SHOULD be extended by activity. A short TTL was
previously doing security work it cannot do — it narrows a window without closing it, while
denying idle operators mid-session with `context_missing`. Rows 1 through 5 close the window.

#### Session lifetime

`session_expires` is `auth_time + max_session_age`, where `auth_time` is when the human
actually authenticated (§5.1.4) and `max_session_age` is port49 policy, declared per role and
defaulting long. It is the compliance-relevant clock: *how long may a session run on the
strength of one authentication event.*

A session approaching the ceiling is **warned in the session**. The authorization REPLY
carries `server_msg`, which devices display, so the operator is told on the device before
anything stops working — and re-authentication does not require reconnecting, because the
broker can refresh live context (§5.1.3) through the `contexts_by_principal` index:

```
t+0h00   Alice authenticates (OIDC, amr=["pwd","mfa"]), mints, logs into core-sw01
         ctx { auth_time=T, session_expires=T+8h }

t+7h50   authorization REPLY carries server_msg:
           "port49: re-authenticate within 10m — run `port49 login`"

t+7h55   Alice runs `port49 login`; the broker verifies, finds her live contexts,
         writes auth_time=T2 and session_expires=T2+8h

t+7h56   her next command authorizes normally — no reconnect, candidate config intact
```

Past the ceiling, commands are denied with a `server_msg` naming the reason, and **context is
retained through a grace window** so a late `port49 login` resumes the session rather than
forcing a reconnect. Requirements:

- The warning window MUST be long enough to complete a change, not merely to notice the
  message. It and the grace window are both configurable.
- Refresh MUST NOT extend a session whose principal has lost the grant; refresh re-resolves
  policy, so a withdrawn grant produces a blob that denies.
- Denial at the ceiling is FAIL, not ERROR, so no fall-through to local authorization opens
  up (see below).
- `max_session_age: never` MUST be expressible. Some deployments have no such requirement,
  and a ceiling nobody asked for is an outage waiting to happen.

#### Why `enable: auto` is restricted

Method lists fall through to a later method only on **ERROR** (the server is unreachable), not
on **FAIL** (an explicit reject). So a session that authenticates locally rather than through
port49 implies port49 was *unreachable at that moment* — which means row 5 never fired,
because we never saw the START.

The remaining exposure is therefore: port49 unreachable when a session begins, reachable again
by the time that session issues `enable`, on a platform whose enable exchange carries
`$enab{level}$` rather than the principal. The stale context resolves and the new occupant
inherits the previous user's ceiling.

**`enable: auto` MUST NOT be available on a platform whose `enable_username` is not
`principal`.** Granting it there is a policy load error. Those platforms use `enable: token`
or `enable: none`, both of which require a credential the previous occupant's context cannot
supply. `rem_addr` comparison covers the same case as defense in depth, and a mismatch is a
high-signal event worth alerting on.

**Blast radius when it does occur** is limited by the command-authorization username check:
the escalated occupant obtains an elevated shell, but every command they run arrives with
their own username, mismatches the stored one, and is denied — and a denial is FAIL, so no
fallback to local authorization follows. The escalation converts into real access only on
devices where command authorization does not cover that privilege tier, which is precisely
what the accounting reconciliation in §9 exists to surface.

**Local account names MUST NOT collide with principal names.** A device-local `bob` that is
not the port49 principal `bob` matches on username and inherits the context. The reference AAA
configuration MUST require disjoint namespaces for break-glass and local accounts, and port49
SHOULD warn when it observes a local fallback succeed for a name it knows.

#### To be established in the lab

These are measurements, not assumptions, and belong in the containerlab matrix:

- Whether the enable START carries `rem_addr` on each platform, and what it contains — the
  field is free-form in RFC 8907 and devices are believed to send the bare address, but if any
  platform includes a source port it discriminates sessions from a shared jump host, which
  the address alone cannot.
- Method-list fall-through and `deadtime` behavior per platform, since both bound the exposure
  window above.
- How reliably and how late exec accounting START and STOP arrive per platform. This no
  longer decides correctness, since accounting is advisory — but it bounds how much a
  reconciliation report (§9) can conclude from silence, and it sizes the delay the
  `task_id` binding in §5.8 has to tolerate.
- Whether `server_msg` on an authorization REPLY is actually displayed to the operator on
  each platform, and at what length it is truncated. The re-authentication warning is
  useless if it is silently discarded.

---

### 5.7 The decision log

Every evaluation emits exactly one record. This is port49's own stream, produced by the
component that made the decision, and it is distinct from the accounting records a device
sends — those report what a device *did*, after the fact, only for the tiers it was
configured to report. The decision log records what port49 *decided*, for whom, and against
which rule. It is complete by construction, because every decision passes through us.

> **A decision record must be replayable.**

Blobs are content-addressed and immutable (§5.1.2). A record that names its blob can be
re-evaluated offline and must produce the same verdict. "Why" is therefore not prose port49
wrote at decision time — it is something a reader can verify.

A deny at the per-command point:

```json
{
  "ts": "2026-09-04T02:11:07.412Z",
  "event": "authorize_command",
  "verdict": "deny",
  "reason": "no_permit_dominates_deny",
  "principal": "alice@example.com",
  "auth": { "method": "oidc", "credential_sha256": "9f2c8b…" },
  "device": { "nas": "10.20.0.7", "name": "core-sw01", "platform": "arista_eos" },
  "session": { "ctx_id": "01J9F3QK…", "port": "vty0", "rem_addr": "198.51.100.4", "privilege": 15 },
  "request": {
    "raw": ["service=shell", "cmd=copy", "cmd-arg=running-config", "cmd-arg=tftp://10.9.9.9/x"],
    "vector": ["copy", "running-config", "tftp://10.9.9.9/x"]
  },
  "policy": {
    "bundle": 2291,
    "blob": "sha256:a3f9c1…",
    "matched_deny":    { "rule": ["*", "*", "/^tftp:/"], "specificity": [1,1,2], "role": "no-exfil" },
    "matched_permits": [{ "rule": ["copy", "**"],        "specificity": [3,0,0], "role": "net-operator" }]
  }
}
```

The record answers the question without anyone reading port49's source: Alice held a permit
for `copy`, a deny matched the destination more specifically, and dominance failed.

#### Three properties

**Log inputs and policy identity, not a narrative.** The matched rules are included because
they make a record readable on its own, but the blob hash is what makes it provable. A replay
that disagrees with the logged verdict is itself a finding — version skew, or tampering — so
`bundle` and `blob` are mandatory on every record that consulted policy.

**Keep the raw arguments alongside the normalized vector.** Normalization (§3) is where
matcher bugs live. A record holding only the vector erases the evidence of its own
normalization bug, and the two together are what make a projection or abbreviation defect
diagnosable from logs rather than reproducible only in a lab.

**Never suppress permits.** Sampling, or logging denies only, looks thrifty and destroys the
artifact: *what did Alice run on Tuesday* is answered entirely by permits. Volume is the cost
of the product, not a problem to optimize away.

#### Events

One envelope, five events, at each point a decision is made:

| `event` | Emitted by | Decides |
|---|---|---|
| `mint` | broker | which grants matched, which roles composed, which blob resulted |
| `redeem` | daemon | whether a presented credential is valid, and creates the context |
| `authorize_session` | daemon | the session and its returned attributes (§6) |
| `authorize_command` | daemon | one command vector |
| `escalate` | daemon | an `enable` exchange, attributed to the principal (§7) |

Device accounting shares this envelope as a sixth event, `account`, and is specified in §5.8.
It is not a decision — it is a report — so it carries no `policy` block and no verdict.

`escalate` exists as its own event because the device-facing username on those platforms is
`$enab{level}$`, not a person. The record carries the principal resolved from login context,
which is the only place that attribution is recoverable.

A `mint` record is the audit trail for *authority*, where the others are the trail for *use*:

```json
{
  "ts": "2026-09-04T02:04:55.108Z",
  "event": "mint",
  "verdict": "permit",
  "reason": "grants_matched",
  "principal": "alice@example.com",
  "auth": { "method": "oidc", "credential_sha256": "9f2c8b…" },
  "policy": {
    "bundle": 2291,
    "subject": "network-operators",
    "grants": [{ "scope": "campus", "roles": ["net-operator", "no-exfil"], "expires": null }],
    "blobs":  { "arista_eos": "sha256:a3f9c1…", "cisco_nxos": "sha256:77b0de…" }
  },
  "scope": { "devices": 412, "ttl_seconds": 900 }
}
```

#### Reason codes

`reason` is a closed vocabulary, so denials are countable and alertable without parsing prose:

| `reason` | Meaning |
|---|---|
| `permit_dominates` | a permit dominated every matching deny (§5.4) |
| `no_rule_matched` | nothing matched; deny by default |
| `no_permit_dominates_deny` | a deny matched and no permit dominated it |
| `context_missing` | no login context for `(nas, port)` — port49 did not authenticate this session |
| `username_mismatch` | the request's username differs from the one bound at redemption (§5.6) |
| `rem_addr_mismatch` | enable arrived from a different address than the bound one |
| `privilege_exceeded` | the request is above the session's granted level |
| `session_expired` | the session ceiling was reached; context retained through the grace window (§5.6) |
| `credential_revoked` | the authorizing credential was revoked — CRL, OCSP, or back-channel logout |
| `device_unknown` | the source address is not in the admission trie (§10) |
| `platform_unknown` | the device's platform has no adapter; generic fallback applied |
| `blob_unavailable` | the referenced blob could not be resolved |
| `no_grants_matched` | mint found no grant for this principal in scope |

A denial whose reason is `context_missing`, `device_unknown`, or `blob_unavailable` is an
operational condition rather than a policy outcome, and each MUST be separately alertable —
a rise in `context_missing` means sessions are being authenticated somewhere other than
port49. `session_expired` is a third category again: expected, and a signal that the
re-authentication warning is not reaching operators (§5.6).

#### Credentials never appear

The log MUST NOT contain a token, a password, a CHAP challenge or response, or any value from
which a credential can be recovered. The credential is identified by `credential_sha256`
only — the same hash the receipt binds (§5.1.1), which is what lets a retransmission be
recognized in the log as one decision retried rather than two decisions made.

#### Replay

`port49 policy replay <record>` re-evaluates a record against the blob it names and reports
agreement or divergence. It is the same evaluator the daemon runs, so a divergence is real.
Three uses:

1. **Answering an auditor** — reconstruct a decision from the record alone.
2. **Regression testing** — replay a captured corpus against a candidate build; any verdict
   that changes is either an intended fix or a regression, and both must be explained.
3. **Integrity checking** — a record whose replay disagrees indicates the log or the blob
   store has been altered.

Replay requires the blob, so blobs MUST be retained at least as long as the decision records
that reference them. They are small, immutable, and shared across every login that resolved
to the same policy.

#### Correlation

Every record resolved against a login context carries its `ctx_id` (§5.1.1). A `mint` record
carries the token handle instead, since context does not exist yet; the daemon's redemption
record joins the two. One chain therefore runs from an SSO login to a typed command:

```
mint (handle) → redemption (handle → ctx_id) → authorize_session
                                             → authorize_command ×N
                                             → escalate
                                             → account ×N          (§5.8)
```

---

### 5.8 Device accounting

Accounting is the third exchange in TACACS+ and the only one where the device reports rather
than asks. A record says *I did this*. There is no deny status in the reply, and the device
has already acted by the time it arrives.

Three record types, distinguished by a flags octet: START, WATCHDOG (still running), STOP.
A login, one command, and a logout — three separate exchanges, each acknowledged:

```
flags=START     user=alice  port=vty0  rem_addr=198.51.100.4  priv_lvl=1
  task_id=42  service=shell  cmd=  start_time=1757041495
        → REPLY status=SUCCESS

flags=STOP      user=alice  port=vty0  rem_addr=198.51.100.4  priv_lvl=15
  task_id=43  service=shell  cmd=show  cmd-arg=running-config  cmd-arg=<cr>
  start_time=1757041502  stop_time=1757041502
        → REPLY status=SUCCESS

flags=STOP      user=alice  port=vty0  priv_lvl=1
  task_id=42  service=shell  cmd=  elapsed_time=214
        → REPLY status=SUCCESS
```

Note the shape: an empty `cmd` marks the exec records — session start and session end —
exactly as it marks session authorization (§5.2). Command records are STOP-only, since a
command that already ran has no start to report.

#### What accounting is not

**It is not a complete record of what ran.** A device sends only the classes it was
configured to send. `aaa accounting commands 15` alone means every privilege-1 command is
invisible; console sessions, out-of-band access, and local-fallback logins produce nothing at
all. Silence is not evidence of inactivity, which is the whole reason §9 exists — the gap
between what port49 authorized and what it was told ran identifies tiers a device executes
without asking anyone.

**It is not enforcement, and MUST NOT be made to act like it.** Authorization and accounting
are separate exchanges; a device that cannot account still runs the command. Any attempt to
gate access on a successful accounting write is theatre that costs availability and buys
nothing.

**It is not trusted input.** Records are device-generated and unverifiable. They are recorded
and reported; they never delete state (§5.6) and never grant anything.

#### Destination

**Accounting shares the decision log's envelope, emitter, and sink**, as `event: "account"`.
The two streams are joined constantly — reconciliation, audit, incident review — and
splitting them means every consumer reassembles them. Default sink is JSON lines on stdout,
so a deployment's existing log pipeline handles retention, indexing, and shipping.

Accounting MUST NOT be written to the token store. The store is the only shared state and the
only single point of failure (design document §6), and accounting is the highest-volume
traffic port49 handles.

```json
{
  "ts": "2026-09-04T02:11:42.006Z",
  "event": "account",
  "flags": "stop",
  "attribution": "resolved",
  "principal": "alice@example.com",
  "device": { "nas": "10.20.0.7", "name": "core-sw01", "platform": "arista_eos" },
  "session": { "ctx_id": "01J9F3QK…", "port": "vty0", "rem_addr": "198.51.100.4" },
  "task_id": "43",
  "record": {
    "raw": ["task_id=43", "service=shell", "cmd=show", "cmd-arg=running-config", "cmd-arg=<cr>"],
    "vector": ["show", "running-config"],
    "priv_lvl": 15,
    "start_time": 1757041502,
    "stop_time": 1757041502
  }
}
```

`raw` and `vector` follow the same rule as the decision log: the record as received, plus the
normalized form the reconciliation join uses.

#### Durability

Reply `SUCCESS` once the record is durably handed to the local spool; reply `ERROR` only when
the spool cannot take it. RFC 8907 offers nothing else — there is no way for a server to
refuse a record on policy grounds.

`ERROR` means *not me, ask another replica*. Devices are not known to retry to the same
server, but most fall through to the next server in the group, which is the correct outcome
when this replica genuinely cannot record. It MUST NOT be used for anything else: an `ERROR`
returned for a malformed or unwelcome record makes every replica in turn try to accept it and
loses the record anyway.

The spool is a bounded local buffer with a disk-backed overflow, drained to the sink. Sizing,
and whether overflow blocks or discards oldest-first, are deployment settings. Spool depth and
drop count MUST be metrics — an accounting stream silently discarding records destroys the
reconciliation report without failing anything visibly.

#### Two wire details that break the join

**Strip the trailing `cmd-arg=<cr>`.** Several vendors terminate the argument list with a
literal `<cr>`. It is not an argument, and left in place every reconciliation join misses by
one position and every command looks unauthorized. Normalization (§3) removes it; the raw
record keeps it.

**Redact secrets before emit.** Command accounting carries typed text verbatim, so
`username bob secret Hunter2` arrives in full. This is the well-known way TACACS+ accounting
logs fill with plaintext passwords, and it is worse here than in a conventional deployment
because port49's stream is designed to be shipped and retained.

Platform adapters therefore declare redaction patterns, applied before emit:

```yaml
# platforms/arista_eos.yaml
redact:
  - {match: ['username', '*', 'secret', '**'],        from: 3}
  - {match: ['username', '*', 'password', '**'],      from: 3}
  - {match: ['enable', 'secret', '**'],               from: 2}
  - {match: ['**', 'key', '*'],                       from: -1}
```

Redaction replaces argument *values* with `«redacted»` and preserves the vector's shape and
length, so the reconciliation join still works on a redacted record. It applies to `raw` as
well — a rule that redacted only the normalized form would defeat itself.

Redaction is best-effort by nature and MUST NOT be presented otherwise: a pattern that misses
leaks. It is strictly better than emitting verbatim, and the honest mitigation is that
port49's own credentials are never typed at a device prompt in the first place.

#### Annotating login context

Exec accounting annotates context and never deletes it (§5.6). The annotation is still worth
getting right, and `task_id` is what makes it correct — it pairs a START with its STOP, and
context is already keyed on `(nas, port)`, so device-local uniqueness suffices:

```
exec START for (nas, port):
    ctx has no task_id and user matches   →  bind task_id (our own session's START)
    otherwise                             →  annotate foreign_session, alert

exec STOP for (nas, port):
    ctx.task_id set    →  accounting_state = closing, only on a task_id match
    ctx.task_id unset  →  accounting_state = closing, only on a username match
```

The unset branch covers `stop-only` accounting and a lost START. `closing` stops refresh
(§5.1.3) and is reported; the idle TTL reclaims the state. A record that matches neither is
logged as unattributable to that context and left alone.

An exec START whose `user` does not match the bound username is a **session port49 did not
authenticate** — a local fallback, a console login, or a name collision. That is precisely the
condition §5.6 requires a warning for, and it is high-signal: it means either port49 was
unreachable or a device-local account shares a principal's name.

#### Unresolvable records

A record port49 cannot tie to a context — no `ctx_id`, no principal — is still recorded, with
`attribution: "unattributed"` and `ctx_id: null`. It is never discarded. This is the primary
evidence that something authenticated outside port49, and a rate of unattributed records
above the deployment's break-glass baseline MUST be alertable.

#### Deliberately not specified here

**Sink implementations.** Beyond the stdout default, a sink is an integration, not a design
decision: syslog, an HTTP endpoint, a message bus. The envelope is the contract.

**WATCHDOG semantics per platform.** A WATCHDOG carrying no arguments is a keepalive; one
carrying arguments is an update. Which platforms send them, and how often, is a lab
measurement rather than a design choice.

---

## 6. Privilege levels and session attributes

### What a privilege level is

**Privilege decides what the device will offer. The role decides what port49 will let you
run. The effective permission set is the intersection, and the role is always a subset.**

A privilege level is the session's local access level on the device. It is not an
independent axis alongside command authorization, and it is also the policy that applies
when port49 is unreachable.

```
login  →  broker returns  priv-lvl=15, shell:roles*network-admin
              │
              ├─ gate 1: the DEVICE decides what this session can reach.
              │          priv-lvl governs what is present in the CLI at all;
              │          any device-local role carries its own permit/deny set.
              │
              └─ gate 2: for commands the device submits, port49 rules decide.
```

Command rules can only **narrow** what the level offered; they can never widen it. Returning
`priv-lvl=1` means the device will not offer `show running-config`, will never submit an
authorization request for it, and a rule permitting it is dead. Conversely, a backup account
needs `privilege: admin` so the command is *reachable*, while `permit: show **` is what
confines it once it is.

**The device-local role is not vestigial.** It governs two situations that port49 does not:

- **When port49 is unreachable.** Under `aaa authorization commands … group tacacs+ local`,
  the device falls back to local authorization, and the role assigned at login is what
  remains. This is the "active login" column of the design document's failure matrix — the
  device role *is* the degraded-mode policy.
- **Commands the device never submits.** With `aaa authorization commands 15` and no
  `commands 1`, everything below that tier is governed by the device role alone, always.

The device-local role SHOULD therefore be chosen as a sane approximation of the port49
role, not as a formality. Two CI checks make the relationship visible (§12).

### Abstract levels

Levels are an **ordered enum**. `readonly`, `operator`, and `admin` ship built in, are
reserved, and cannot be renamed or removed — that guarantees every shipped platform file
keeps working regardless of what an operator declares. Unused levels cost nothing.

Declaring `privilege_levels` **replaces the default ordering**, because order is what the
max-join uses:

```yaml
privilege_levels:
  - {name: readonly}
  - {name: read_only_limited, parent: readonly}
  - {name: operator}
  - {name: senior_operator,   parent: operator}
  - {name: admin}
```

`parent:` is the escape hatch that makes custom levels practical. A new level would
otherwise need a mapping for every platform in the fleet; `parent: operator` says *render as
`operator` on any platform that does not define this level explicitly*, resolved
transitively up the chain.

This also turns an existing wart into declared behavior. NX-OS is role-native with two
built-in roles, so `readonly` and `operator` render identically there — with `parent:` that
is visible and intentional rather than a surprise. Usually it is exactly right:
`read_only_limited` differs from `readonly` in *which commands port49 permits*, not in what
the device needs to be told. Platforms may still override where the distinction is real.

A level with no mapping and no resolvable `parent:` chain, on a platform present in
inventory, is a **policy load error**.

**Reordering the list is a breaking change.** Inserting a level mid-list changes every
max-join that crosses it, and the effective-permission diff MUST report that as a privilege
change rather than a cosmetic one.

The operator writes `privilege: readonly` on a role. Where multiple roles are granted, the
effective level is the **max** over the enum. A role with no `privilege` contributes
nothing.

### Three role shapes

Privilege is declared on the **role**, never overridden on a grant. An override has nowhere
to record *why* it exists, and — because the level also determines the device-local role
that applies when port49 is unreachable — burying one in a grant row silently changes
degraded-mode behavior. A named role can carry a `reason:`.

Composition, not variants, prevents role explosion. A role may carry only a privilege:

```yaml
roles:
  - name: read_only
    privilege: readonly
    permit: [show **]

  - name: elevated_session
    privilege: admin
    reason: "device exposes show running-config only at level 15"
    # no permit/deny — contributes a level and nothing else

grants:
  - {subject: svc_oxidized, scope: all_devices, roles: [read_only, elevated_session]}
```

Effective level is `max(readonly, admin)`; commands stay `show **`. One named elevation is
granted where needed rather than forking `read_only_admin`, `read_only_operator`, and so on.

| Shape | Carries | Example |
|---|---|---|
| commands + privilege | both | `read_only`, `bgp_operator` |
| commands only | contributes nothing to the max | `no_disruptive`, `cve_2026_xxxx` |
| privilege only | no rules | `elevated_session` |

### Attributes are transported, not understood

Vendor attributes are unbounded — F5 partitions, Palo Alto access domains, Fortinet
profiles, Nokia home directories, and whatever ships next quarter. port49 MUST NOT require
knowledge of any of them.

RFC 8907 already defines the wire format: `attribute=value` is mandatory,
`attribute*value` is optional. Every vendor attribute ever invented fits that. port49's
obligation is therefore to **transport faithfully and validate structurally**, never to
interpret. Unboundedness stops being a problem provided the schema accepts anything and
defaults to the non-breaking choice.

### Where attributes are declared

**Platform file**, for anything tied to a level. Operators may extend a shipped platform or
define their own in the policy repository, with no upstream change required:

```yaml
platforms:
  f5_bigip:
    authorizes: [session]
    privilege:
      readonly: ["F5-LTM-User-Role*700", "F5-LTM-User-Partition*all",
                 "F5-LTM-User-Console*1"]
      admin:    ["F5-LTM-User-Role*0",   "F5-LTM-User-Partition*all",
                 "F5-LTM-User-Console*1"]
```

Most vendor attributes live here, because most of them *are* the level expression.

**Role and grant**, keyed by platform, for anything that is not a level:

```yaml
roles:
  - name: read_only
    privilege: readonly
    permit: [show **]
    attributes:
      all: ["idletime*30", "timeout*480"]

grants:
  - subject: team_a
    scope: f5_fleet
    roles: [read_only]
    attributes:
      f5_bigip: ["F5-LTM-User-Partition*prod"]
```

Layering is **platform → role → grant**, most specific wins on a duplicate attribute name,
and CI MUST report the shadowing so an override never happens silently.

Values support a **fixed** substitution vocabulary — `{username}`, `{principal}`,
`{device}`, `{privilege}` — and nothing more. `home-directory*/home/{username}` is the
motivating case; a general template language would be a footgun.

### Validation without semantics

port49 cannot check what an attribute means. It MUST check everything else:

- Exactly one `=` or `*` separator, non-empty attribute name, no duplicate names.
- **Length.** The RFC's argument length field is one byte, so **255 bytes per attribute**,
  and `arg_cnt` is likewise one byte. A generated `deny-commands` regex (§8) will exceed
  this before anything else does, and it fails as a truncated or dropped attribute rather
  than a clean error. Enforce at policy load.
- Mandatory versus optional, with a warning on any mandatory attribute not recognized.

**Unknown attributes default to optional (`*`).** A mandatory attribute a device cannot
parse causes it to reject the entire session, breaking every login on that platform.
Defaulting to optional means adding a custom attribute cannot take down a fleet; declaring
one mandatory is then a deliberate, reviewable act.

**Not every level is natively representable.** NX-OS is role-native with two built-in roles,
so `readonly` and `operator` render identically and the distinction is carried entirely by
command authorization. That is acceptable, but it MUST be visible in the platform file
rather than silently surprising.

**Platforms that are not `priv-lvl`-native** (Junos maps to `local-user-name`) MUST declare
a mapping for every level. A missing mapping is a **policy load error in CI**, not a broken
login at 3am.

**Exact attribute spellings are lab-verified, not asserted.** The shipped adapters use bare
`priv-lvl` for the TACACS+ shell-service reply and `shell:roles` for EOS and NX-OS roles.
Those spellings — and every other attribute name in a shipped platform file — MUST be
confirmed against a real image in the containerlab matrix before that adapter is marked
`VERIFIED` (§8). A wrong attribute name fails silently as an ignored optional attribute, or
loudly as a rejected session if declared mandatory, and neither outcome should be discovered
in production.

### Diagnosing an unfamiliar vendor

Because port49 cannot validate semantics, it MUST make the outcome inspectable:

```
$ port49 explain --subject team_a --device f5-lb-01 --show-attributes
session attributes that would be returned:
  F5-LTM-User-Role*0            (optional)  ← platform f5_bigip, level admin
  F5-LTM-User-Partition*prod    (optional)  ← grant override, shadows platform "all"
  F5-LTM-User-Console*1         (optional)  ← platform f5_bigip, level admin
  idletime*30                   (optional)  ← role read_only
```

And when a device rejects session authorization immediately after attributes are returned,
port49 MUST name the likely cause rather than leaving it to be guessed: *"f5-lb-01 rejected
session authorization; 1 mandatory attribute was sent (`X=Y`) — an unsupported mandatory
attribute causes rejection."*

---

## 7. Escalation (`enable`)

Enable is a real workflow and must be supported, not designed around.

### What the wire looks like

Typing `enable` produces a **new authentication** — usually on a new TCP connection — with
`authen_service=ENABLE`, `priv_lvl` set to the requested level, `authen_type=ASCII` on
essentially every platform, and a username that is frequently `$enab15$` rather than the
principal.

Three consequences:

1. No token exists for it — the operator is already logged in and typing interactively.
2. The username does not identify the principal, so **login context MUST be keyed on
   `(nas, port)`**, with the username as a verified attribute rather than part of the key.
3. The enable password was never a second authentication. It is a shared device secret or a
   per-user password in the TACACS database. With certificate identity, whoever holds that
   TTY has already proven who they are — so enable is an *authorization* decision.

### Configuration

```yaml
subjects:
  - name: netops_admins
    group: "CN=netops-admins,OU=Groups,DC=example,DC=com"
    enable: token          # none | auto | token   (default: none)

grants:
  - {subject: netops_admins, scope: all_devices, roles: [network_admin],
     max_privilege: admin}
```

The **ceiling** (`max_privilege`) is an authorization fact and lives on the grant, resolved
as a max across matching grants. The **mechanism** (`enable`) is a property of the consumer
and lives on the subject, so two grants can never disagree about it.

| Mechanism | Behavior | Fits |
|---|---|---|
| `none` | Enable is refused. The login-time privilege is all there is. | Read-only pollers whose granted level already suffices. |
| `auto` | Daemon resolves `(nas, port)` → login context, checks the ceiling, PASSes. Any password accepted. **Available only where `enable_username: principal`** (§5.6). | Tools that insist on typing `enable` where plumbing a second secret is awkward. |
| `token` | A second minted token, supplied at the prompt. | Anything needing a discrete, attributable escalation record. |

### Automation

The mint returns a **pair**, because every relevant tool already has a second credential
field — `enable:` in Oxidized, `secret=` in Netmiko:

```python
tok  = port49.token(device)      # {"login": "p49_7K2Q…", "enable": "p49_R4XN…"}
conn = ConnectHandler(device_type="cisco_nxos", host=device,
                      username="svc-config-backup",
                      password=tok.login, secret=tok.enable)
```

Both are device-bound, single-use, and share a TTL. No tool changes.

Worth noting that `enable: none` is often the honest answer for backup accounts: they type
`enable` because the account landed at privilege 1. Granting the read-only role at `admin`
privilege removes the escalation entirely.

After a successful escalation, login context records the new privilege level, since
command rules may differ above and below the line, and accounting attributes the event to
the **real principal** even though the wire said `$enab15$`.

---

## 8. Platform adapters

A platform adapter is a small declarative file. Adapters ship built in, are verified in the
containerlab matrix where an image exists, and are both overridable and contributable.

```yaml
platforms:
  arista_eos:
    supports: [session, commands, config_commands]
    privilege:
      readonly: ["priv-lvl=1",  "shell:roles*network-operator"]
      operator: ["priv-lvl=7"]
      admin:    ["priv-lvl=15", "shell:roles*network-admin"]
    entity_classes:
      management: ['^Management[0-9]+$']
      loopback:   ['^Loopback[0-9]+$']
      physical:   ['^Ethernet[0-9/.]+$', '^Port-Channel[0-9]+$']
    enable_username: principal
    expands_abbreviations: true
    pipe_token: "|"
    pipe_authorized: true
    port_pattern: '^vty[0-9]+$'
```

Most devices need far less. A time server or a BMC that does authentication plus one
attribute is complete in four lines:

```yaml
  meinberg_lantime:
    supports: [session]
    privilege:
      readonly: ["priv-lvl=1"]
      admin:    ["priv-lvl=15"]
```

### Fields

| Field | Purpose | Required |
|---|---|---|
| `privilege` | level → attributes at session authorization | always |
| `supports` | capability declaration (see §9) | always |
| `entity_classes` | named sets of device entity names, referenced as `@class` in rules | if rules use classes |
| `enable_username` | `principal`, or a template such as `$enab{level}$` | if enable is supported |
| `expands_abbreviations` | whether the device sends resolved command words | if `commands` |
| `pipe_token` / `pipe_authorized` | modifier separator; whether it reaches us | if `commands` |
| `command_projection` | how rules render for session-only platforms (below) | if `session`-only |
| `redact` | patterns whose argument values are removed before an accounting record is emitted (§5.8) | if `commands` |
| `service` | authorization `service` value if not `shell` | rarely |
| `port_pattern` | expected `port` shape, used only for drift detection | optional |

### Entity classes

Entity classes **classify, they do not canonicalize**. port49 never needs to know that
`ge-0/0/1` and `Ethernet1/1` denote the same kind of thing — a general cross-vendor
canonical naming scheme is a substantial project in its own right and is not required here.
Each platform states only which of *its* names belong to which class:

```yaml
  cisco_nxos:
    entity_classes:
      management: ['^mgmt[0-9]+$']
  juniper_junos:
    entity_classes:
      management: ['^(fxp0|em0)$']
```

One rule — `deny: interface @management` — then means the same thing everywhere, and a
platform that fails to define a referenced class produces a load error rather than a silent
non-match.

The same construct extends naturally to VRFs, VLAN ranges, and protocol instances. A more
capable variant sources classes from **inventory** rather than regex — `@core_uplinks`
defined by interface tags in the source of truth, so the class reflects the network rather
than a naming convention. That is deliberately deferred: interface-level inventory is a far
larger dataset (10,000 devices times tens of ports) than the device-level sync in §10.

### Projection for session-only platforms

Platforms that do not authorize per command receive port49's decision **projected** into
their native model. Junos is the motivating case: `allow-commands` and `deny-commands` are
returned as attributes at session authorization, generated from the role's rules rather than
looked up from a static table.

```yaml
  juniper_junos:
    supports: [session]
    command_projection: junos_regex
```

A trie of literal prefixes converts to an alternation mechanically —
`[start, **]` and `[file, **]` become `(start.*|file.*)` — and Junos uses extended regex, so
the absence of lookahead is no constraint that our grammar does not already accept.

#### Measured target behavior

The following was established by lab testing rather than inferred from documentation, which
does not specify precedence, repetition, or length behavior.

**Class-resident and wire-delivered rules flatten into one merged set, and a matching permit
regex beats a matching deny regex — regardless of specificity and regardless of origin.**

| Deny | Allow | Origin | Result |
|---|---|---|---|
| `show chassis cluster status` | `show chassis .*` | both wire | all `show chassis` permitted |
| `show chassis .*` | `show chassis cluster status` | both wire | only the allowed command permitted |
| `show chassis cluster status` (wire) | `show chassis .*` (class) | split | all permitted |
| `show chassis .*` (class) | `show chassis cluster status` (wire) | split | only the allowed command permitted |

**Broad capability comes from the login class's `permissions` bits, not from a permit regex.**
This is what makes the model work: with no permit regex covering a command, a deny applies
cleanly against the capability baseline. Modelling the baseline as `allow-commands "show .*"`
would instead defeat every deny beneath it.

**Two delivery channels, both carrying either attribute:**

| | Ceiling | Provisioning | Changes |
|---|---|---|---|
| **Wire** (TACACS attributes) | 240 bytes, **one argument per name** | none | fully dynamic |
| **Class** (device config) | none — verified enforced past 255 with no truncation | deploy and monitor for drift | config push |

**Repeated attribute names collapse to the first, silently.** A policy needing two instances
of one name arrives incomplete with no signal.

**`allow-commands` and `allow-commands-regexps` are mutually exclusive.** The commit checker
rejects the combination in config; over the wire the device accepts it and then locks the user
out of everything.

**The device validates configuration but not wire attributes.** There is no device-side
backstop for anything port49 sends, which makes the generator the only validation layer that
exists — and makes the commit checker a free specification: any combination port49 might emit
should be commit-tested first, and anything the CLI refuses must never reach the wire.

#### The projection model

**Wire-only by default; class-assisted only when the deny set exceeds the wire budget.**

```
class:   permissions      view                       ← capability, not a regex
         deny-commands    <broad denies>             ← only if the wire budget is exceeded
wire:    deny-commands    <broad denies>             ← default home
         allow-commands   <narrow exceptions>
```

Starting on the wire means zero device provisioning and fully dynamic policy. Moving denies
into the class buys unbounded capacity at the cost of a config push and a drift-monitoring
obligation, so CI MUST report when a role crosses that line rather than letting it happen
quietly.

**Which permits are emitted follows from port49's own semantics.** Under dominance (§5.4) a
permit prevails only when it is strictly more specific than the deny it competes with — so
the permits worth emitting are exactly the ones that dominate. A permit that would not
dominate in port49 MUST NOT be emitted, because on the target it would win anyway and
silently void the deny. Permits competing with no deny need no regex at all; the capability
bits already cover them. That is why the wire payload stays small by construction.

#### Generator constraints

None of these are caught by the device. All MUST be enforced at policy load:

1. **One instance per attribute name.** Duplicates are silently discarded after the first.
2. **240 bytes for a wire attribute**, enforced in the encoder — the one-octet argument length
   makes it a protocol impossibility rather than a policy choice, so an over-length argument
   is never emitted at all.
3. **Never emit `allow-commands` together with `allow-commands-regexps`.**
4. **Never emit a permit broader than its intended grant.** An over-broad permit silently
   voids the entire deny baseline beneath it.
5. **Reject invalid or over-budget policy loudly at load time**, never silently at session
   time. A server that skips an attribute at session time produces a fail-open shape.

**Blast radius.** An invalid projection locks out every user authenticating against that
device simultaneously. Lockout is fail-closed, but deployments MUST have a break-glass path
independent of TACACS attributes — a local account or console access (design document §4).

#### Verification

`show cli authorization` is not available on all releases. Where it is absent, **`?`
completion substitutes**: denied commands are absent from completion rather than merely
rejected on execution, so the device exposes its computed effective set through it. That is
also how class-side enforcement past 255 bytes was confirmed.

**Differential testing is required, not optional.** Generate the attributes, apply them in
containerlab, and assert the device's effective set matches port49's own decisions across a
probe corpus covering every rule shape the generator can produce. Where equivalence cannot be
established for a shape, CI MUST refuse the policy rather than ship something unprovable.

The class baseline is part of the security model but lives outside port49's control, so
**drift MUST be detected**, not merely documented — completion output makes the device's
computed set observable by the same technique as capability inference (§9).

**Anchoring is a per-platform property.** Our rules match the full vector. A device treating
`start.*` as unanchored would also match `request start …`, diverging from our semantics.
That belongs in the adapter and is asserted in the lab, never assumed.

**Importing existing configuration.** Simple alternations of prefix patterns convert to
token rules mechanically; arbitrary regex does not. A migration tool MUST convert what it can
and **flag the remainder for human review rather than approximating**, because a
mistranslated deny is precisely the failure a migration must not introduce.

### User-editable, day one

Operators MUST be able to define and override platforms without an upstream change. A fleet
containing Supermicro BMCs, Meinberg time servers, and HPE gear cannot wait on releases —
that is the ticket-queue bottleneck the design exists to remove.

Built-ins ship embedded in the binary; user files live in the policy repository and merge
over them, per top-level key:

```yaml
# platforms/arista_eos.yaml — adds one class, inherits everything else
platforms:
  arista_eos:
    entity_classes:
      uplink: ['^Ethernet(49|50|51|52)$']
```

`replace: true` on a platform block discards the built-in and starts clean. `based_on:`
declares a variant, using the same vocabulary as `parent:` on privilege levels:

```yaml
  whitebox_nos:
    based_on: arista_eos
    entity_classes:
      management: ['^ma1$']
```

User files receive identical structural validation to shipped ones: required fields,
attribute syntax, the 255-byte limit, and entity-class patterns must compile under RE2.

### Knowing what is shipped

Embedded definitions must not be opaque.

**They are files.** Sources live at `platforms/*.yaml` in the repository — browsable and
diffable across tags without running anything.

**They are introspectable**, and honest about verification:

```
$ port49 platform list
PLATFORM           SOURCE     VERIFIED       SUPPORTS
arista_eos         built-in   containerlab   session,commands,config_commands
cisco_nxos         built-in   containerlab   session,commands,config_commands
juniper_junos      built-in   containerlab   session
f5_bigip           built-in   community      session
meinberg_lantime   local      —              session
```

A community-contributed adapter nobody has run against a real image MUST say so rather than
appearing identical to one verified on every commit. `platform show <name>` prints a
definition, `--effective` the merged result after overrides, and `platform export --all`
writes them to disk.

**Published documentation is generated from the embedded files** at release time, so it
cannot drift from the binary.

**And the platform set is pinned.** If `arista_eos.privilege.admin` gains an attribute in a
release, upgrading the binary silently changes what every EOS admin session receives — a
**binary upgrade becomes an unreviewed policy change**. Policy therefore pins a version:

```yaml
platform_set: 1.4.0
```

Upgrading the binary changes nothing about rendering. `port49 platform upgrade` moves the pin
and reports exactly what changes:

```
platform_set 1.4.0 → 1.5.0

  arista_eos.privilege.admin
    + shell:roles*network-admin        (was absent)
    affects 4,412 devices, 6 subjects

  juniper_junos.supports
    + config_commands                  ⚠ 2 roles have config rules
                                         that were previously dead
```

CI SHOULD also report override drift — an override that now matches the built-in and can be
removed, or a built-in change an override shadows — so local platform files do not rot
silently as upstream improves.

**`port49 platform export <name>`** emits a file suitable for an upstream pull request:
written for one fleet on day one, contributed once proven.

### Unknown platforms

An unknown **device** — one not in inventory — fails closed. That is an admission decision.

An unknown **platform** is different: the device is legitimately admitted, we simply lack a
dialect file. It receives a generic adapter (`priv-lvl` only, `supports: [session]`) and
raises an alarm. Someone will always rack something unmodeled, and that must not take down
their login.

---

## 9. Capability inference

`supports` conflates nothing — it states what a platform is *capable* of. What a given
device is *configured* to do is a separate, per-device fact, and it is the one that is
silently wrong in real fleets.

An IOS or EOS switch is capable of config-command authorization. Whether it performs it
depends on `aaa authorization config-commands` having been typed on that box. A device with
it disabled looks completely healthy while every `interface` and `router bgp` line goes
unauthorized and unaccounted.

**port49 MUST infer observed capability from traffic it already handles**, and MUST NOT ask
an operator to assert it:

| Observation | Conclusion |
|---|---|
| Received `service=shell` with empty `cmd` | performs session authorization |
| Received `cmd=<word>` requests | performs command authorization |
| Permitted `configure terminal`, then saw no authorization requests before the session's next exec command or its end | config-command authorization is probably disabled |

The third is evidence, not proof — an operator can enter config mode and immediately leave —
so it MUST be evaluated statistically over a window rather than per session.

**Reconciling accounting against authorization** generalizes the technique. Where command
accounting is enabled, a command appearing in an accounting record with no corresponding
authorization request proves the device decided it locally. The join is `ctx_id` plus the
normalized vector, over the single stream both events share (§5.7, §5.8) — which is why the
`<cr>` stripping and shape-preserving redaction in §5.8 are correctness requirements here and
not cosmetic:

```
⚠ UNAUTHORIZED TIER — leaf-04
    47 commands in accounting had no corresponding authorization request
    example: "show interfaces", "show version", "ping 10.0.0.1"
```

Every platform has a way to under-authorize silently, and each spells it differently — a
missing level on IOS (`aaa authorization commands 1`), a missing `config-commands` on NX-OS,
a level list instead of `all` on EOS. Reconciliation finds the gap without knowing which
spelling caused it, which is why it belongs here rather than in per-platform documentation.

This matters most in combination with privilege level. A session returned at `priv-lvl=2`
on a device configured only for `aaa authorization commands 15` submits **nothing** for
authorization — every command in that session is decided locally, and port49's rules, however
carefully written, are never consulted. The device looks entirely healthy throughout.

```
$ port49 devices capabilities
DEVICE      PLATFORM      SUPPORTS                          OBSERVED
leaf-01     arista_eos    session,commands,config_commands  session,commands,config_commands
leaf-04     arista_eos    session,commands,config_commands  session,commands   ⚠ config-commands off
pdu-dc1-a   generic       session                           session
ntp-01      meinberg      session                           —                  ⚠ never seen
```

Two checks fall out, and both are needed:

- **CI**: a granted role carries command rules that the platform's `supports` cannot
  enforce. Caught at review time.
- **Runtime**: the platform is capable but the device is not configured. Caught by drift
  detection.

**What silence can and cannot mean.** Every conclusion here reads a *gap* between two streams,
and accounting is best-effort — so a gap can also mean records were lost in transit or dropped
from a full spool. Reconciliation MUST therefore be qualified by the accounting stream's own
health over the same window: spool drops, `ERROR` replies, and unattributed-record counts
(§5.8). A report that cannot distinguish "the device did not ask" from "we did not receive"
will eventually accuse a correctly configured device, and once that happens nobody reads the
report again.

> **Principle.** Never require an operator to assert something the system can observe.
> Anything declared by hand about device behavior will eventually be wrong, and it will be
> wrong silently.

---

## 10. Device inventory

TACACS+ carries no device identity — the daemon observes a source address and nothing more.
Every device attribute the engine depends on comes from an inventory, and so does the shared
secret each NAS uses.

### The inventory service

Source-of-truth interaction belongs in its own workload, `port49-inventory`. This is the
same rule the architecture applies one layer down: the daemon never talks to the directory,
and neither the broker nor the daemon talks to NetBox.

Three properties justify the separate component:

- **Connector faults cannot reach the authentication path.** Connectors are a contributable
  surface (below); running them out of process means a third-party connector that leaks
  memory or chokes on a large response takes down a syncer, not authentication.
- **Source-of-truth credentials live in exactly one workload.**
- **It is the component permitted to be a singleton.** One replica, no leader election, no
  high-availability story — because nothing depends on it being up. Placing the singleton
  where availability does not matter is a deliberate architectural choice.

```
GET  /v1/bundle                      full bundle; ETag for cheap no-op refresh
GET  /v1/bundle/version              current version, for polling
GET  /v1/bundle/diff?from=<ver>      for CI and `port49 inventory diff`
POST /v1/sync                        on-demand trigger
GET  /v1/healthz
GET  /v1/devices/{address}           diagnostic only — MUST NOT be used on the hot path
```

**Consumers pull and cache; they never query per request.** A daemon calling this API per
connection would make the syncer a hot-path dependency and rebuild the problem the component
exists to prevent.

### One versioned bundle

Three things must reach the other components: device inventory, the policy repository, and
the pinned platform set (§8). Distributing them separately means they can disagree — a broker
evaluating policy `v88` against inventory `v1841` and platform set `1.4.0`, while another
replica holds a different combination. Nothing would report the mismatch.

They are therefore published as **one versioned bundle**:

```
bundle v2291
  inventory      device records, addresses, platforms, attributes
  policy         compiled roles, scopes, subjects, grants
  platform_set   1.4.0, as pinned by the policy repository
```

A consumer runs on exactly one bundle version at a time, so a decision is always attributable
to a single, nameable state of the world. `bundle/diff` then covers policy change, inventory
drift, and platform-set movement in one review artifact rather than three.

This also closes a gap the documents otherwise leave open: **how policy reaches the broker**
was previously unspecified.

**Consumers take what they need**, which is not the same thing:

| Component | Consumes | Why |
|---|---|---|
| broker | inventory, policy, platform set | resolves and compiles decisions |
| daemon | inventory only — addresses and `key_ref` | to admit a connection and select a key |

The daemon deliberately does **not** consume policy or platform definitions. It receives
compiled decisions through blobs (§5.1.2) instead, so a version mismatch between broker and
daemon cannot change how a command is evaluated. The bundle carries facts; the blob carries
decisions.

**The service emits key *references*, never key material.** A snapshot carries
`key_ref: prod_key`, and the daemon resolves that from its own secret mount. A compromised
inventory service leaks the fleet list, not the ability to speak to it.

### Admission and keys

Admission splits along where the risk actually sits. The address list is not the security
boundary — **the shared key is.** A device connecting from an admitted range without the
right key sends unreadable data and gets nowhere. Admitting a broad range therefore costs
little, provided key *assignment* is controlled.

| Layer | Holds | Source |
|---|---|---|
| Inventory (synced) | device exists, its addresses, platform, attributes | NetBox / Nautobot |
| Policy repository | key groups — which CIDR or attribute pattern maps to which key reference; default deny | reviewed in a pull request |
| Secret manager | the key material | environment, Vault, or equivalent |

```yaml
# policy repository — intent
key_groups:
  - {match: {cidr: 10.0.0.0/8},       key_ref: prod_key}
  - {match: {attributes: {env: lab}}, key_ref: lab_key}
  # anything matching no group is refused
```

A device racked in a known site is admitted automatically with the correct key. One
appearing in an unexpected range matches no key group and is refused. The fleet list is
maintained once, in the source of truth, while the admission *decision* stays in review.

RFC 9887 replaces the shared key with mutual TLS, so a device record MUST be able to express
both.

### Device records

```yaml
  - name: leaf-01
    addresses: [10.0.1.5, 10.0.1.6, 2001:db8::5]
    platform: arista_eos
    attributes: {site: dc1, role: leaf, os_version: "4.31.2F"}
```

**Every address a device may source from must be listed.** TACACS is commonly sourced from a
loopback or dedicated management interface that is not the device's primary address. A
device sourcing from an unlisted interface fails device binding, and the failure will not
obviously trace back to inventory. `ip tacacs source-interface` — or the platform equivalent
— MUST be pinned in the reference AAA configuration.

### Connectors and sync cadence

**NetBox and Nautobot** are the verified pair. Infrahub, Ansible inventory, and a plain file
follow the same snapshot contract. A file connector is required regardless, as the inventory
equivalent of the in-memory store — containerlab runs, CI policy tests, and `port49 explain`
against a hypothetical device all need an inventory that is not a live source of truth.

Four triggers, not one:

- **Scheduled full sync every 10 minutes.** That is the window a newly-racked device sits
  un-admittable if a webhook is missed, which is about the tolerance before it becomes a
  ticket.
- **Webhook-driven refresh.** Both products emit outbound webhooks on device create and
  update, giving seconds for the common case without polling harder.
- **`port49 inventory sync`** on demand.
- **Full sync at startup**, refusing to serve with no snapshot at all.

Four requirements:

**Version detection.** NetBox 4.x renamed `device_role` to `role`; Nautobot 2.0 did the same
and dropped `slug` from most models. The connector selects a mapping profile from the API
root version, with an explicit override available.

**GraphQL first.** At 10,000 devices, REST pagination is hundreds of round trips per sync.
Both products expose GraphQL; one query returns devices, addresses, platform, site, role,
and tags. REST remains a fallback for older installations.

**Bounded change per sync.** A sync that would remove more than `max_removed_percent` of the
fleet MUST refuse, retain the last good snapshot, and alarm. A partially-available source of
truth or a mistyped filter would otherwise silently deauthorize the fleet.

**Platform slug translation.** Real installations say `eos`, `arista-eos`, `arista_eos`, or
`veos`. Ship an alias table, allow overrides, and warn on unrecognized slugs rather than
falling back to generic in silence.

```yaml
inventory:
  sync:
    - name: netbox_prod
      type: netbox
      url: https://netbox.example.com
      token: ${NETBOX_TOKEN}
      interval: 10m
      filter: {status: active, has_primary_ip: true}
      map:
        site:       site.slug
        role:       device_role.slug
        platform:   platform.slug
        os_version: custom_fields.os_version
      safety:
        max_removed_percent: 10
```

### How a daemon refreshes its snapshot

The daemon consumes only the inventory portion of the bundle; "snapshot" below means that
portion, refreshed as a whole because the bundle is versioned as a whole.

```
every 30s:
  GET /v1/bundle/version
  if version == held.version:  done          ← the common case
  GET /v1/bundle  (If-None-Match: <etag>)
  parse → build index → validate → atomic pointer swap
```

**Build fully, then swap.** The snapshot is parsed and indexed into a prefix trie
(`address or CIDR → device, key_ref`) before anything is exchanged, then swapped by a single
atomic pointer store. Readers take no lock, and in-flight connections complete against the
snapshot they began with. Never mutate in place.

**Validate locally before swapping.** The service already applies bounded-change safety, but
the daemon MUST NOT trust the payload: reject a snapshot that fails to parse, that is empty,
or that drops more than the configured share; retain the previous one and alarm.

**The snapshot never expires.** Staleness is a metric and an alarm —
`inventory_snapshot_age_seconds` — never a fail-closed. An admission table with a TTL means a
prolonged syncer outage eventually halts all authentication fleet-wide, which is the
readiness-probe mistake of §12 of the design document in a different form. A stale device
list is a far smaller problem than no device list; revoking a specific device is a key
rotation, not a sync.

**Cold start is the one case where readiness gating is correct.** A daemon with no snapshot
genuinely cannot serve, so it remains unready and retries. This is safe precisely because,
unlike store health, only *new* pods lack a snapshot — existing replicas continue serving and
all endpoints are never lost at once.

**A daemon MUST be able to start without the inventory service**, or the claim that nothing
depends on that service being up is false. A fresh pod would otherwise stay unready for the
duration of an inventory outage, which means no autoscaling under load and no recovery from a
crash loop or a node replacement — precisely when capacity matters. Two mechanisms, in order:

1. **The last good bundle is persisted to local disk** (a MUST, not a SHOULD), so a restart in
   place needs nothing.
2. **A shared object-store location** holds the most recent bundle, written by the inventory
   service and readable by daemons. A pod scheduled onto a fresh node reads that and serves.

Both are cold and cached; neither puts the inventory service on a request path. Without at
least one of them, the singleton is not free after all — it is a startup dependency wearing a
different name.

**Key resolution stays local.** An unresolvable `key_ref` fails that device closed — not the
daemon — and alarms, because that is a misconfiguration worth hearing about on the first
device rather than the ten-thousandth.

**Every swap logs a summary** — `snapshot v1841 → v1842: +3 devices, -1, 2 changed` — so an
unexpected fleet change is visible in the daemon's own logs, not only in the service's.

### Source-of-truth write access is privilege-granting

If scopes match on synced attributes (§5.5), whoever can change a device's `role` or
`os_version` can move it into or out of a scope — with no policy change, no pull request, and
no diff. The policy file looks untouched.

Mitigations, designed in rather than documented afterward:

- Scope-membership changes MUST appear in the sync diff and be reviewable.
- A scope MUST be able to pin a device set explicitly instead of by attribute.
- Scopes carrying denies SHOULD set `security_log: true`, so membership changes are logged
  and alerted as security events rather than routine inventory churn.
- Attributes used for security scoping SHOULD come from an attested path rather than a
  hand-editable field.

> **Principle.** The source of truth supplies facts about devices; the policy repository
> supplies intent. The moment a source-of-truth tag can grant a permission, authorization has
> left code review — which is the outcome the design document's §9 exists to prevent.

---

## 11. Complete policy example

```yaml
platform_set: 1.4.0

privilege_levels:
  - {name: readonly}
  - {name: read_only_limited, parent: readonly}
  - {name: operator}
  - {name: admin}

key_groups:
  - {match: {cidr: 10.0.0.0/8},       key_ref: prod_key}
  - {match: {attributes: {env: lab}}, key_ref: lab_key}

scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric,   match: {site: [dc1, dc2], role: [leaf, spine]}}
  - name: srx_unpatched
    match: {platform: juniper_junos, os_version: {lt: "21.4R3-S5"}}
    on_missing: include
    security_log: true

roles:
  - name: read_only
    privilege: readonly
    permit:
      - show **
      - terminal length *

  - name: read_only_limited
    privilege: read_only_limited
    permit:
      - show version
      - show interfaces **
      - show ip route **

  - name: network_admin
    privilege: admin
    permit: ["**"]
    pipe:
      permit: ["**"]

  - name: bgp_operator
    privilege: operator
    permit:
      - show bgp **
      - clear bgp /^[0-9]+$/ **
      - clear bgp neighbor **
    deny:
      - clear bgp all

  - name: interface_tech
    privilege: operator
    permit:
      - configure **
      - interface @physical
      - shutdown
      - no shutdown
      - description **
      - end
    deny:
      - interface @management

  - name: elevated_session
    privilege: admin
    reason: "device exposes show running-config only at level 15"

  - name: no_disruptive
    deny:
      - reload **
      - write erase **

  - name: cve_2026_xxxx
    reason: "CVE-2026-XXXX — SRX cluster subsystem"
    deny:
      - show chassis cluster **

  - name: cve_2026_xxxx_assess
    reason: "CVE-2026-XXXX — IR needs cluster state to assess exposure"
    permit:
      - show chassis cluster status

subjects:
  - {name: netops_admins, group: "CN=netops-admins,OU=Groups,DC=example,DC=com",
     enable: token, token_ttl: 60s}
  - {name: noc_tier1,     group: "CN=noc-tier1,OU=Groups,DC=example,DC=com",
     enable: none,  token_ttl: 60s}
  - {name: security_ir,   group: "CN=security-ir,OU=Groups,DC=example,DC=com",
     enable: token, token_ttl: 60s}
  - {name: svc_oxidized,  identity: "system:serviceaccount:netops:oxidized",
     enable: token, token_ttl: 900s}

grants:
  - {subject: netops_admins, scope: all_devices,   roles: [network_admin], max_privilege: admin}
  - {subject: noc_tier1,     scope: all_devices,   roles: [read_only, no_disruptive]}
  - {subject: noc_tier1,     scope: dc_fabric,     roles: [interface_tech], expires: 2026-12-01}
  - {subject: svc_oxidized,  scope: all_devices,   roles: [read_only, elevated_session]}
  - {subject: security_ir,   scope: srx_unpatched, roles: [cve_2026_xxxx_assess]}
  - {subject: everyone,      scope: srx_unpatched, roles: [cve_2026_xxxx]}

tests:
  - {subject: noc_tier1,    device: leaf-01, command: "show version",   expect: permit}
  - {subject: noc_tier1,    device: leaf-01, command: "reload",         expect: deny}
  - {subject: noc_tier1,    device: leaf-01, command: "show run | redirect ftp://x",
     expect: deny}
  - {subject: svc_oxidized, device: leaf-01, command: "show running-config",
     expect: permit}
  - {subject: svc_oxidized, device: srx-fw-04, command: "show chassis hardware",
     expect: permit}      # the CVE deny is scoped to `cluster`, so no conflict arises
  - {subject: noc_tier1,    device: srx-fw-04, command: "show chassis cluster status",
     expect: deny}        # only the CVE deny matches
  - {subject: security_ir,  device: srx-fw-04, command: "show chassis cluster status",
     expect: permit}      # the assess permit dominates the CVE deny at every position
```

Three things this example is chosen to show.

**No vendor attribute string appears anywhere.** `interface @management` and
`privilege: readonly` carry all the platform-specific knowledge, resolved by the adapter.

**`svc_oxidized` composes two roles rather than overriding a level.** `read_only` supplies
the command rules, `elevated_session` supplies the privilege, and the reason the elevation
exists is recorded on the role that carries it.

**The CVE mitigation is three lines and self-limiting.** It applies to every principal on
every unpatched SRX including devices not yet racked, lapses per device as inventory reflects
the upgrade, and admits a deliberate, narrow exemption for incident response through the same
mechanism as everything else.

---

## 12. Tooling

Policy is reviewable only if reviewers see effect, not text.

**`port49 explain`** resolves a hypothetical decision and names exactly one reason,
including which role would grant a denied command. On a platform where the relevant control
cannot be enforced — `pipe_authorized: false`, or `supports` lacking `config_commands` — it
MUST say so rather than reporting a decision the device will not honor.

**Effective-permission diff in CI.** Because evaluation is order-free set algebra over token
trees, `permits ∖ denies` is a computable object and old-versus-new is an exact difference.
Leaf regex is the one construct that degrades this: a regex position is not enumerable, so
the diff reports *"argument 3 is regex-constrained and the constraint changed"* rather than
listing commands. This is contained, and is a reason to prefer literals and `*`.

**Policy tests** run in CI against a file-backed inventory, as in §11.

**Intersection checks.** Because the effective permission set is the intersection of what
the device offers and what port49 permits (§6), CI MUST report where the two disagree. Neither of these is visible in any existing TACACS+
system, and both are ordinary review questions once surfaced:

```
⚠ DEAD RULES — interface_tech permits commands its privilege cannot reach
    privilege: readonly  →  arista_eos priv-lvl=1
    unreachable: configure **, interface /^(ethernet|port-channel)/, shutdown
    the device will never submit these for authorization

⚠ FALLBACK EXPOSURE — svc_oxidized
    port49 rules confine it to:  show **
    device role on failure:      network-admin  (full administrative access)
    if port49 is unreachable, this subject has more access than policy grants
```

**Attribute shadowing.** Where a role or grant attribute overrides a platform attribute of
the same name (§6), CI MUST name both so the override is deliberate.

**`port49 devices capabilities`** reports the `supports`-versus-`observed` matrix from §9.

**Shadowed-deny report.** Because a more specific permit can override a deny (§5.4), CI MUST
name every shadowed deny, the subject it fails to bind, and the permit that beats it. This is
what replaces the guarantee deny-overrides would have provided.

**Privilege-expansion gate.** The check that matters under most-specific semantics is not
"did the permit set grow" but **"does this change make command C permitted where it was
denied"** — computable exactly from the trie.

**`port49 platform upgrade`** reports what a platform-set bump changes, so a binary upgrade
is never an unreviewed policy change (§8).

**`port49 policy replay`** re-evaluates a decision record against the blob it names (§5.7).
It is the same evaluator the daemon runs. Beyond answering an auditor, a captured corpus
replayed against a candidate build turns "did this release change anyone's access" into a
diff — which is the only form of that question a reviewer can actually check.

**Access review** is a rendering of the flat grant table, not an investigation.

---

## 13. Decisions

Questions left open in the first draft of this document and since resolved. Recorded here
because the reasoning matters more than the outcome.

**1. Precedence — specificity dominance, a partial order.** Deny-overrides is simpler to
state but cannot express an exception without negation, and RE2 has no lookahead. The
motivating case was real: a broad `show chassis *` deny added for a CVE broke a backup
account's `show chassis hardware`.

A permit therefore applies only when it dominates every matching deny — at least as specific
at every argument position, strictly more somewhere. The ordering is deliberately **partial**:
three total orderings were tried (lexicographic, sum of ranks, run-collapsed distance) and
each failed on real policies, because collapsing the tuple to one number forces an answer
even where two rules genuinely disagree about which position matters. Declining to rank
incomparable rules is what keeps the result conservative in every case.

There is exactly **one** deny mechanism; a shadowed deny is surfaced by CI rather than
prevented by a second construct. (§5.4)

**2. Grant shape — flat.** One row per subject × scope × roles. Greppable, renders directly
as the access-review report, and makes a fleet-wide emergency grant a single appended line
rather than a structural edit made under pressure. The cost is offboarding across scattered
rows, addressed by tooling. (§11)

**3. Privilege on the role, never overridden on a grant.** An override has nowhere to record
why it exists, and because the level also selects the device-local role that applies when
port49 is unreachable, an inline override silently changes degraded-mode behavior. Role
explosion is avoided by composition — a privilege-only role such as `elevated_session` —
rather than by variants. (§6)

**4. Privilege levels — shipped defaults plus user extension.** `readonly`, `operator`, and
`admin` are reserved and always present so shipped platform files always resolve; operators
declare their own ordering and add levels, with `parent:` supplying a rendering fallback so a
new level does not require a mapping for every vendor. (§6)

**5. Device admission — inventory for existence, policy repository for key assignment.** The
address list is not the security boundary; the key is. Splitting there means the fleet is
maintained once in the source of truth while the admission decision stays in review. (§10)

**6. Entity naming — classes, not canonicalization.** Adapters classify their own names into
`@management`, `@physical`, and similar rather than mapping every vendor into a common
scheme. A rule referencing an undefined class is a load error, which eliminates the silent
non-match. (§4, §8)

**7. Version comparison — one generic comparator, no per-vendor setting.** Tokenize into
digit and letter runs; digits compare numerically, letters by equality only. An incomparable
version folds into `on_missing` and is assumed unpatched, and the devices affected are always
reported rather than silently swept in. Fleets cluster at a few versions through natural
upgrade cycles, so the ambiguous case is rare — and when it fires, over-mitigating is the
right failure. (§5.5)

**8. The device-facing username — derived at mint, declared for machines.** Human usernames
come from the same directory query that resolves groups, or the OIDC `preferred_username`
claim; machine subjects declare one, since they have no directory entry. Unique across
subjects, and compared after case and domain normalization. (§2)

**9. Platform data — compiled into the decision, not distributed to daemons.** The broker
expands entity classes and embeds normalization parameters into a hash-named blob, so a
daemon and a broker can never disagree about how a rule is evaluated, even mid-upgrade. The
bundle carries facts; the blob carries decisions. (§5.1.2, §10)

**10. The decision log is separate from device accounting, and is replayable.** Two streams
with different guarantees: accounting reports what a device did, incompletely and only where
configured; the decision log records what port49 decided, completely, because every decision
passes through it. Records name the immutable blob they were decided against rather than
narrating a rationale, so a decision can be re-evaluated and verified instead of taken on
trust — and a divergence on replay is itself a finding. Permits are never sampled or
suppressed; the artifact is worthless without them. (§5.7)

**11. Accounting is advisory — it annotates login context and never deletes it.** Earlier
drafts ordered teardown triggers by reliability and let all of them delete state, which made
a best-effort, device-generated, separately-delivered signal load-bearing. A logout STOP
delayed past a line's reuse then denies the *next* operator mid-session: fail-closed, but a
self-inflicted outage whose two halves look unrelated in a log. Teardown is now ordered by
**authority** — port49's own redemption, revocation from the identity layer, the local
session ceiling, a username conflict, idle TTL — and accounting only sets
`accounting_state: closing`. The bindings were always the security control; teardown is state
hygiene, and hygiene must not be able to cause an outage. (§5.6, §5.8)

**12. Credential expiry bounds the mint, not the session.** An OIDC `exp` is commonly minutes
and a certificate's `notAfter` describes validity at authentication, so neither is a session
ceiling — using them as one would end a router session every hour for no security gain. The
session clock is `auth_time + max_session_age`, port49 policy, per-role, and `never` is
expressible. Because port49 can deny commands but has no way to close a session, reaching the
ceiling never drops a connection or abandons a candidate configuration: the operator is warned
in-session through `server_msg`, re-authenticates out of band while the session stays open, and
context survives a grace window so a late re-auth resumes rather than reconnects. (§5.1.4,
§5.6)

**13. Login context records credential identity for revocation, not for verification.** The
daemon never sees the credential — the command exchange carries only `user`, `port`,
`rem_addr`, and `priv_lvl` — so a fingerprint cannot tighten per-command comparison. It is
recorded because it enables actions otherwise impossible: OIDC `sid` makes back-channel logout
reach live device sessions, and certificate issuer and serial are exactly what a CRL or OCSP
response names. `amr` and `acr` are recorded but unused, because how someone authenticated
cannot be established after the fact. The cost is that context now holds PII-adjacent
material, so it inherits the encryption-at-rest requirement previously applied only to
tokens. (§5.1.4)

### Deferred, with reasons

Neither of these is an open question about the design. Both are closed for v1 on the
reasoning below.

**Inventory-sourced entity classes.** Defining `@core_uplinks` from interface tags in the
source of truth is better in principle than a regex, because *which* ports are uplinks is a
fact about the network rather than a naming convention. It is deferred because regex classes
cover what command rules actually reference — `@management`, `@loopback`, `@physical`, and
site-specific port ranges — while interface-level sync is a far larger dataset than the
device-level sync in §10: tens of ports per device against 10,000 devices, rather than 10,000
records. Revisit only when a rule proves inexpressible with regex classes, which is a concrete
trigger rather than a guess.

**Projection equivalence.** Which rule shapes render faithfully into a session-only platform's
native model — Junos `allow-commands` and `deny-commands` — cannot be settled on paper. It
requires a device image, a generated attribute pair, and a probe corpus compared against the
device's own view (`show cli authorization`). It is therefore a work item in sequencing step 4,
not a decision: the requirement is already specified in §8, and the outcome is a per-platform
list of shapes CI refuses. Recorded here only so it is not mistaken for an unresolved design
question.

---

## 14. Required test assertions

Beyond those already listed in the design document's §14:

**Matching and precedence**

- **Full-vector matching**: `show bgp summary` does not match `show bgp summary detail`.
- **Case insensitivity**: `SHOW RUN` matches `show run`; `interface MANAGEMENT1` matches
  `@management` defined as `^Management[0-9]+$`; a `(?-i)` regex matches case-sensitively;
  the vector reaching accounting is unaltered.
- **Dominance, permitting**: a permit of `show chassis hardware` (3,3,3) beats a deny of
  `show chassis **` (3,3,0), while `show chassis hardware detail` remains denied.
- **Dominance, denying**: each of these resolves to DENY because no permit dominates —
  `copy **` against `* * /^tftp:/`; `copy * *` against the same deny; `clear bgp **`
  against `* * all`; `interface @physical` against `interface /^Ethernet1$/`.
- **Dominance, buying it back**: `copy running-config @backup_targets` (3,3,2) dominates
  `* * /^tftp:/` (1,1,2) and permits, while `copy running-config *` (3,3,1) does not.
- **Equal tuples do not dominate**, so an equally specific permit and deny resolve to deny.
- **Class and regex are equally ranked**: neither dominates the other at a shared position.
- **Rank lint**: a regex equivalent to `*` or to a literal is flagged at policy load.
- **Order independence**: a policy file with roles, grants, and rules shuffled produces
  byte-identical decisions across the full test corpus.
- **Entity classes**: one rule using `@management` denies `Management1` on EOS, `mgmt0` on
  NX-OS, and `fxp0` on Junos; a rule referencing a class a platform does not define fails at
  load.
- **Pipeline enforcement**: `show run | redirect …` denied under a role permitting `show **`;
  chained stages each evaluated.
- **Abbreviation handling**: on a platform with `expands_abbreviations: false`, an
  abbreviated command either expands correctly or is denied — never silently unmatched.

**Attributes and privilege**

- **Session authorization returns correct attributes per platform**, with mandatory versus
  optional honored. A mandatory attribute a platform cannot parse causes the device to reject
  the session, so it must be caught in the lab.
- **Attribute layering**: platform → role → grant, most specific winning, shadowing reported.
- **255-byte argument limit** enforced at policy load, including generated projection
  attributes.
- **Unknown attributes default to optional.**
- **Privilege composition**: `max` across granted roles over the declared ordering;
  `parent:` resolves transitively; an unresolvable level fails at load.
- **Enable**: all three mechanisms, including the `$enab15$` username path resolving through
  login context keyed on `(nas, port)`.
- **Receipt binds the credential**: a retry presenting a different credential from the same
  device, line, and username is rejected, while a byte-identical retransmission replays.
- **CHAP verification**: a candidate set of several unspent tokens resolves to the one that
  produces the matching digest; the atomic removal, not the verification, decides single use,
  and two replicas racing the same token yield exactly one success.
- **CHAP re-prompt**: a fresh challenge does not match the receipt and correctly fails rather
  than replaying.
- **Encryption at rest**: a store dump contains no recoverable token; redemption succeeds
  across a key rotation window in which both keys are accepted.
- **`enable: auto` is refused at policy load** on a platform whose `enable_username` is not
  `principal`.
- **Context teardown**: a redemption overwrites; an authentication START with a different
  username invalidates even when rejected; an ASCII login invalidates once the username
  arrives in a CONTINUE; an exec accounting START for the port invalidates.
- **Context is never created without redemption** — a locally-authenticated session has none
  and is denied.
- **Username binding on the command path**: a request whose username differs from the stored
  one is denied and the context invalidated.
- **Username resolution**: a human principal's device-facing username is derived at mint from
  the directory or the OIDC claim; a machine subject uses its declared `username`; a subject
  with neither fails at policy load.
- **Username uniqueness**: two subjects declaring the same username fail at policy load.
- **Username normalization**: `alice`, `ALICE`, `DOMAIN\alice`, and `alice@corp.example.com`
  all match a canonical `alice`.
- **`rem_addr` binding on enable**: a mismatch is refused and alerted.
- **Recycled line**: a context now routinely outlives its session, since accounting no longer
  deletes it — so the assertion is that it is not inheritable by the next occupant of that
  line through command authorization, through enable under any of the three mechanisms, or
  through a local-fallback login.
- **Idle session survives**: a login quiet for longer than the former five-minute TTL still
  authorizes its next command.

**Decision log**

- **One record per evaluation**, at each of the four events, permits included — a corpus
  exercising the matcher produces exactly as many records as decisions.
- **Replay agreement**: every record in the corpus replays against its named blob and
  reproduces the logged verdict and reason.
- **Replay divergence is detected**: a record whose blob is substituted, or whose verdict is
  edited, is reported as divergent rather than silently accepted.
- **Raw arguments survive normalization**: a record's `raw` reproduces the arguments as
  received, including case and any pipe or abbreviation the normalizer rewrote.
- **No credential material**: a log dump over the full corpus — ASCII, PAP, CHAP, and enable
  — contains no token, password, challenge, or response, and `credential_sha256` matches the
  hash bound by the receipt.
- **Retransmission logs as one retried decision**, correlated by `credential_sha256`, not as
  two independent decisions.
- **Enable attribution**: an `escalate` record on a `$enab{level}$` platform names the
  principal from login context, never `$enab15$`.
- **Reason codes are closed**: every denial in the corpus carries a reason from the table, and
  the operational reasons are countable separately from policy denials.
- **Blob retention**: a blob referenced by a retained record is not collected.
- **Correlation chain**: one `ctx_id` joins the mint's redemption, the session, every command,
  any escalation, and every resolved accounting record for that login.

**Device accounting**

- **Record types**: START, WATCHDOG, and STOP each parse and emit; an empty `cmd` is
  recognized as an exec record and a populated one as a command record.
- **`<cr>` stripping**: a record terminated with `cmd-arg=<cr>` normalizes to the same vector
  as the authorization request for the same command, and the join matches. `raw` retains it.
- **Redaction**: `username bob secret Hunter2` emits with the secret removed, in both `raw`
  and `vector`, with the vector's length unchanged so the join still matches. A corpus of
  credential-bearing commands per platform emits no plaintext secret.
- **Durability**: `SUCCESS` follows a durable spool write; a full or unwritable spool returns
  `ERROR` and nothing else does; spool depth and drop count are exported as metrics.
- **Accounting never enforces**: an unreachable sink denies no command, and no code path
  gates an authorization reply on an accounting write.
- **Accounting never deletes context**: the late-STOP sequence in §5.6 leaves the new
  occupant's context intact and authorizing.
- **`task_id` binding**: an exec START binds `task_id`; a STOP bearing a different `task_id`
  does not annotate; a STOP matching it sets `accounting_state: closing`; with no bound
  `task_id`, a username match is required.
- **Foreign session detection**: an exec START whose username differs from the bound one is
  reported as a session port49 did not authenticate.
- **Unattributed records** are recorded rather than discarded, carry `ctx_id: null`, and are
  counted separately.

**Session lifetime and revocation**

- **Credential expiry does not bound the session**: a login authorized by an OIDC token with a
  five-minute `exp` still authorizes commands an hour later.
- **Mint requires validity**: an expired certificate or token is refused at mint.
- **Ceiling warning**: an authorization REPLY inside the warning window carries `server_msg`,
  and the message is confirmed displayed per platform in the lab matrix.
- **In-place refresh**: `port49 login` during the warning window extends `session_expires`
  without a reconnect, and the next command authorizes.
- **Refresh re-resolves policy**: a principal whose grant was withdrawn cannot extend a
  session into continued access.
- **Grace window**: a command past the ceiling is denied with `session_expired` while context
  is retained; a re-auth inside the grace window resumes the same session; past it, context is
  gone and the reason becomes `context_missing`.
- **`max_session_age: never`** is accepted and produces no ceiling.
- **Revocation reaches live sessions**: a back-channel logout naming `sid`, a `sub`-wide
  revocation, and a certificate appearing on a CRL each invalidate the matching contexts and
  no others.
- **Context encryption at rest**: a store dump contains no recoverable subject DN, `sub`
  claim, or principal name.

**Platform and projection**

- **Projection equivalence**: generated attributes produce the same decisions on a real device
  as port49's own evaluation, across a probe corpus covering every rule shape the generator
  can emit. Verified through `show cli authorization` where available and `?` completion
  where not. CI refuses shapes that cannot be proven equivalent.
- **Projection precedence**: the four-row matrix in §8 reproduces — a permit regex beats a
  deny regex from either origin, and a deny applies cleanly where no permit regex covers the
  command.
- **Projection generator constraints**: duplicate attribute names, an over-length argument,
  `allow-commands` with `allow-commands-regexps`, and a permit broader than its grant are each
  rejected at policy load rather than emitted.
- **Wire-to-class escalation**: a role whose deny set exceeds the wire budget is reported by
  CI as requiring a class baseline, and is never silently truncated.
- **Class drift detection**: a class baseline altered on the device is detected from the
  device's computed effective set.
- **Platform layering**: user files merge per top-level key; `replace: true` discards the
  built-in; `based_on:` inherits.
- **`platform_set` pinning**: changing the binary without moving the pin produces
  byte-identical rendered attributes.

**Inventory and capability**

- **Snapshot refresh**: atomic swap; in-flight connections complete against the prior
  snapshot; a malformed, empty, or over-shrinking snapshot is rejected and the previous one
  retained.
- **Snapshot never expires**: a daemon with a stale snapshot and an unreachable inventory
  service continues authenticating, alarming on age.
- **Cold start**: a daemon with no snapshot stays unready while existing replicas keep
  serving; a daemon restarted with the inventory service down starts from its persisted
  bundle, and one scheduled onto a fresh node starts from the shared object-store copy.
- **Unresolvable `key_ref`** fails that device closed, not the daemon.
- **Inventory sync safety**: a sync removing more than the configured share is refused and
  the previous snapshot retained.
- **Config-mode inference**: a device with config-command authorization disabled is detected
  and reported.
- **Accounting reconciliation**: commands present in accounting with no authorization request
  are reported as an unauthorized tier.
- **Unknown platform** falls back to generic and alarms; **unknown device** is refused.

**Scoping**

- **State-scoped mitigation**: a device leaving `srx_unpatched` on the next sync regains the
  denied command with no policy change.
- **`on_missing`**: a device lacking the scoped attribute is included for a deny-bearing
  scope and excluded for a permit-bearing one.
