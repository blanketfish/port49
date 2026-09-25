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

**`remote` and every `p49-*` name are reserved.** They are a Junos device's template users: a
session under one lands in that template's class whatever the reply says, so a subject the
projection told less than port49 permits (§13, decision 26) would run what the template's
class runs. A subject declaring one is a policy load error, and the broker refuses to mint for
one a directory derives (plan 5b pre-flight I9).

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
   compile case-insensitive **by default**, with `(?-i)` available to a permit to opt into
   exactness where a device object really is case-sensitive (IOS ACL names, for instance).
   A deny may not opt out: its `(?-i)` is refused at load (§4), because a case-sensitive
   deny is walked past by typing another case, while a case-sensitive permit only permits
   less.

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

   Failing closed is done in the matcher, with no expansion table (plan 4): on a platform
   marked `expands_abbreviations: false`, a **deny's** literal word also matches any
   non-empty proper prefix of itself, case-insensitively, so `rel` is denied by
   `deny: reload **`; a **permit's** word matches only as written, so `sh run` is not
   permitted by `permit: show **`. An abbreviation is therefore denied or matched as written
   and never slips past a deny. A deny's `@class` or `/re/` term is widened the same way:
   each branch of its pattern is read as `^`, a literal name and what follows the name, and
   the term also matches any non-empty prefix of the name followed by the same tail, so
   `int ma1` is denied by `deny: interface @management` where `@management` is
   `^Management[0-9]+$`. A deny pattern that cannot be read that way — unanchored, starting
   with anything but its literal name, or a name that runs on into a part that may be more
   of it — cannot have the abbreviations it would miss listed, so on a platform marked
   `expands_abbreviations: false` that is not measured session-only (the generic adapter
   declares only `session` and is widened on purpose) the term matches **any argument** in
   its position: an over-denial of the commands the deny's other terms reach, and no device
   is quarantined or login refused for it. `port49 policy test` reports each such term and
   platform as `deny_widened`, naming the term by its position (`term 3 (a regex)`, `term 3
   (@bad pattern #1)`), never its text, which may spell a secret out (§5.8), and `port49d` says
   it at start. A platform measured sending no
   per-command authorization (Junos, decision 21) widens nothing. The cost is an over-denial
   of a full word that is a prefix of a deny's word — `show ip` against `deny: show ipv6 **`
   — reported by name in the `server_msg`. `arista_eos`, `cisco_nxos` and `cisco_iosxe` are
   marked `true`, set from L21 (closed 2026-09-24): all three send the resolved words over interactive SSH (§15, L21;
   `tests/lab/results/L21-arista_eos.md`, `L21-cisco_nxos.md`, `L21-cisco_iosxe.md`).
   `juniper_junos`, which authorizes no command, and the generic adapter are unmeasured and
   stay `false`.
5. **Preserve argument boundaries.** Arguments are never re-joined.

   IOS-XE splits an interface name from its index: a typed `int Gi1` arrives as
   `GigabitEthernet`, `1`, where EOS and NX-OS send one argument (§15, L21;
   `tests/lab/results/L21-cisco_iosxe.md`), so `deny: interface GigabitEthernet1 **` would
   never match there. On a platform marked `splits_interface_names: true`, a **deny's** term at
   one position also matches two arguments — an argument and the next, where the next is an
   index (digits and `/ . :`) and the term matches the two joined — and the rest of the rule
   continues after both. That holds for a word, an `@class` and a `/re/` alike and needs
   nothing from a pattern's syntax, so nothing is refused for it; the decision names the deny
   as written. A deny's `*` is "any one argument", and is written where the interface goes, so
   it splits too: it also matches a name (letters and `-`) followed by an index, so
   `deny: default interface *` binds `default interface GigabitEthernet 1`. A **permit**
   matches only as written, so it is written as the device sends it: a permit word written
   joined (`permit: interface GigabitEthernet1 **`) never matches there, and `port49 policy
   test` reports it as `permit_joined_name` and `port49d` says it at start. `port49 explain`
   and the policy tests evaluate what the device sends, so on such a platform a typed argument
   of letters followed by an index is split in two before it is decided, with a note saying
   so; a word that is not an interface name (`hostname xe1`) reaches the device whole and may
   be decided otherwise.

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
A deny's regex that turns case-insensitivity off, with `(?-i)` or any flag group clearing
`i`, is a **policy load error**: port49 matches case-insensitively, and a case-sensitive
deny could be walked past by changing the case of what is typed. A permit may opt out.

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
  → max_privilege       max over matching grants; absent (zero on the token) means
                        NO CEILING, not a ceiling of zero — whether escalation is
                        offered at all is `enable`'s job (unset → enable_refused);
                        `store.Context.PrivilegeCeiling()` is the one reading of it
  → effective rules     resolved permit/deny/pipe sets
  → av_pairs            rendered for this device's platform
```

When some matching grants set `max_privilege` and others leave it unset, the ceiling is the
max of the ones that set it: a grant that states no ceiling does not lift the ceiling another
grant states. The result has no ceiling only when no matching grant sets one.

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
                           max_session_age, minted_at, expires, ... }
```

`max_session_age` rides in the token record because the daemon computes `session_expires`
at redemption and the blob is shared across principals; where a principal holds several roles
the broker writes the **minimum** over them.

`minted_at` is when the broker cut the token, on the broker's clock — the clock revocation stamps
`revoked_at` with. It is what decides whether a login may lift a revocation on the context it joins
(§5.6): `auth_time` cannot, because it is when the human authenticated at the IdP, which can be
hours before the mint.

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
  privilege         15                   the HIGHEST level granted on this device (5.3); raise-only;
                                         clamped to `max_privilege`
  blob_hash         sha256:a3f9c1…
  credential        see 5.1.4
  auth_time         1757041495           when the human actually authenticated
  session_expires   1757070295           auth_time + max_session_age
  refreshed_at      1757041495           last broker refresh (5.1.3); the staleness clock
  revoked_at        —                    set by revocation (5.6); denies until idle TTL reclaims
  policy_rev        7                    advanced only by a write to what the refresh decides
                                         (5.1.3): a join or replace, a revocation, a privilege
                                         change, a policy write. Accounting does not move it
  session_discriminators                 the platform's own per-session values, hashed, from
    [sha256(31048)[:16], …]              exec accounting (5.8). A SET, capped at 8: one
                                         context covers every concurrent session of one user
                                         (§13, decision 15). Not task_id: that restarts at 1
                                         per session on both Junos images, which sent
                                         session_pid 31048 and 31050 for two of them
                                         (§15, L17)
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
  accepted_attributes: [priv-lvl]    # the merged adapter's, where set (§6); omitted otherwise
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
inventory bundle while everything else stays compiled. EOS, NX-OS and IOS-XE send resolved
words over SSH (§15, L21, closed), other transports are unmeasured, and §3 already fails closed
where expansion is unreliable, so this is recorded rather than designed for.

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

#### Policy reload

A policy edit reaches every live session **without anyone logging out** (plan 4b). The file is
read on a timer and on `SIGHUP`, and a change is handled in four steps:

1. **Validate or keep the old.** The new file is loaded against the inventory exactly as at
   start: the load resolves and compiles every subject on every device the new policy
   selects, at every grant expiry, and §10's joint check runs on what that compile produces.
   A composition that fails is handled exactly as §10 says: the device is quarantined, or, only where no platform could pass, the whole
   policy is refused. So a reload that loads never leaves a live context whose policy cannot
   be compiled. A file that does not load is refused: the policy in force keeps serving, the
   refusal is logged once with the reason and the bundle still serving, counted in
   `port49_policy_reloads_total{outcome}` as `refused` (`applied` and `unchanged` beside it), and
   `port49_policy_file_refused` holds at 1 until a file loads or the old one is put back. A typo
   never takes the fleet down, and that includes a file that parses but that no platform can
   compile (§10). Nothing is half-applied. The timer is
   `broker.policy_watch_interval` (default 5s, 1s to 5m). A change it finds is loaded once
   two reads in a row agree, and what is loaded is the bytes those two reads agreed on, so an
   edit is in force within two intervals of its write; a `SIGHUP` loads what is on disk at
   once. A file that differs at every read never has two agree and never loads — two tools
   fighting over it, or a templater stamping the time — so after six reads running that
   differ it is said once, and `port49_policy_file_refused` holds at 1 until it settles and
   loads or the file in force is put back. Either way a file must be written atomically (a
   temporary file renamed over it): a writer stalled part-way for two intervals, or a `SIGHUP`
   sent mid-write, loads what is there, and a list cut short can load wider than the one
   intended.

   **Whoever can write the policy decides every operator's access,** so a policy file anyone
   else could have written is refused like one that does not load, at start as at a reload: a
   file, or the directory holding it, that is group- or world-writable or that is owned by
   neither the user `port49d` runs as nor root. A directory another user owns is refused even
   at mode 0755, because its owner can rename any file over the policy or change the mode. At
   start `port49d` does not start; at a reload the policy in force keeps serving. The check
   follows symlinks, at most 40. The file actually read and the directory holding it must be
   safe, and so must the directory holding every link the path passes through: the
   configured name's own, one half-way along the chain, and one standing for a directory.
   Whoever can write a link's directory can re-point it at any file that passes, such as a
   root-owned `policy.yaml.bak` from before a grant was withdrawn. The read is capped at
   1 MiB, and a refusal quotes at most 64 characters of any value it found. The mode of a
   directory holding a link is excused, and its owner still checked, when `fstatfs` on the
   opened directory reports its filesystem read-only. The excuse trusts whoever writes the
   mount's source: the kubelet, for a ConfigMap. It never applies to the directory holding the
   file itself, because a read-only bind of a host directory others can write lets them rename
   a stale policy over the file on the host. This is how a Kubernetes ConfigMap or Secret mount
   passes, as measured
   (`tests/lab/results/configmap-mounts.md`). Its mount root holds both links at mode 0777
   (01777 for a Secret, 02777 or 03777 with `fsGroup`), but the mount is read-only, even to root
   in the pod. The file (root's, 0644 or `defaultMode`) and its timestamped directory (root's,
   0755) pass on their own. The file's owner and mode are taken from
   the descriptor the policy is read through (`fstat`), not from a path checked beforehand, so
   a rename between the check and the read cannot put another file in its place. The check
   reads owners and mode bits alone: a POSIX ACL granting someone else write, or a writable
   directory further up the path, is not seen, and keeping those closed is the deployment's
   part (design document §13).
2. **Swap.** The loaded policy replaces the one in force in one step, so no mint sees one
   version's grants and another's quarantine. A mint in flight finishes on the policy it
   started with, and the swap waits for it.
3. **Re-run the joint checks.** The new policy's quarantine schedule, grant expiries included,
   replaces the old one whole (§10): a fix releases a device and a new failure quarantines one,
   with no restart, and the daemon closes a newly quarantined device's connections without a
   reply as it does at start.
4. **Refresh.** Every live context is re-resolved against the new policy for its principal on
   its device, and the answer is written into it by compare-and-set on the `policy_rev` that
   was read: the blob hash, the privilege ceiling (a held level above a lowered ceiling comes
   down to it, as at a join, §5.3) and the `enable` mechanism. A principal left with no grant
   on the device has that context **revoked** instead (§5.6 row 2), and its next command is
   denied `credential_revoked`; so is one whose subject's username changed, since the
   principal can no longer mint under the name the context is keyed by. A context the policy
   in force cannot be resolved or compiled for is revoked too, failing closed, with a
   `refresh` deny record (`blob_unavailable`), a process-log line naming the `ctx_id` and the
   fault, and a `failed` count; the pass goes on to the next context. That is an unexpected
   broker fault, not a bad file: step 1's load has already compiled every subject on every
   device, and what failed there quarantined its device or, where no platform could pass,
   refused the policy (the joint check, §10; §13 decision 20), so a compile fault here is
   never a reason to revoke the fleet. Such a context is revoked, so it is on the policy in
   force and counts as reached for `port49_policy_refresh_pending`; the `failed` count is the
   alarm. A context the refresher cannot open — sealed under a key that has left the two-key
   window, or failing authentication — cannot be judged against the policy in force and is
   not left on the one before, so it is revoked the same way and counted `failed`. Its owner
   is sealed, and the index entry that led to it may be stale, so its `refresh` deny record
   (`blob_unavailable`) names the device and the username its key holds and no principal. Every
   revocation a refresh makes is written as the revocation mark alone, with no compare, and
   the mark keeps the later of the one held and the one written (§5.6), so no write racing it
   can hold a withdrawn grant in force. A context on a device quarantined now is left as it is
   until the refresh that lifts the quarantine, and is recorded once per policy version
   (bundle), not at every pass. A narrowed rule denies the next command and a widened one
   permits it; a widened *level* reaches the device only at the next session authorization
   or `enable`, where levels are granted. That is on a platform that authorizes commands. One
   that does not (Junos, §13 decision 21) never asks port49 about a command, so a refresh
   cannot reach its live session: the context is still written or revoked, for the next login
   and any receipt replay, but the session keeps what it had at login until logout. The
   refresh counts those contexts on its process-log summary ("N of them on platforms that do
   not authorize commands keep their live session until logout") and names each one's
   `ctx_id` in the process log; the `refresh` record carries no field for it yet (plan 7's
   revocation by identity adds one, §5.7 first). `auth_time`, `session_expires`, `refreshed_at` and the
   idle TTL are not touched: nothing about the operator's authentication or the directory was
   re-verified, and a reload is not activity.

Every edit changes the bundle (§5.7), so every live context takes a new blob at a reload and
the records decided after it name the policy that was in force. The one exception is a login
redeeming a token kept across the reload (below): its context takes the superseded bundle's
blob, whose answer is the same, and whose `blob` record is already in the log (§5.1.1), so its
records still replay. A change the refresh makes is a `refresh` decision record (§5.7) naming
the context's `ctx_id`, so the record before a command's changed answer says why:

| The refresh | `verdict` | `reason` |
|---|---|---|
| wrote the policy in force into the context | `permit` | `grants_matched` |
| revoked it: no grant left on the device, or the subject's username changed | `deny` | `no_grants_matched` |
| revoked it: the policy in force could not be resolved or compiled for it | `deny` | `blob_unavailable` |
| revoked it: the context could not be opened (the record names no principal) | `deny` | `blob_unavailable` |
| left it as it was: the device is quarantined (recorded once per context per bundle) | `deny` | `device_quarantined` |

Each context is counted once per pass in `port49_context_refreshes_total{outcome}`: `updated`,
`unchanged`, `revoked`, `quarantined`, `failed`. A context already on the answer, and one a
store error stopped the pass at, has no record (§5.7).

**Unspent tokens are the other half.** A token carries the blob, ceiling and `enable`
mechanism of the policy that minted it, and a redemption writes them into the context it
creates or joins. So the refresh also deletes, per `(device, username)`, the unspent tokens a
superseded policy minted and the policy in force would not mint identically — otherwise a grant
removed at 10:00 returns at 10:05 on a device where the operator had no context yet, from a
token minted at 09:58. A token whose answer is unchanged, the bundle aside, is kept: a reload is
not a reason to make everyone mint again. A shortened `token_ttl` is a changed answer, since
those tokens would outlive what the policy now allows; a lengthened one is not. An idempotent
retry of a mint whose tokens were deleted this way is not replayed, because the replay would
hand back a token that no longer exists. It is minted afresh under the policy in force, and the
`mint` record's `index_error` says the replay was abandoned. A login in flight across the swap may still write the
superseded answer after the refresh has passed its context, so the refresh runs again a
settle interval (30s) after every reload, and after every pass at a grant's expiry.

**A grant's expiry is a scheduled edit.** A resolution changes with no edit to the file when a
grant expires (§5.1), so the refresh also runs at every expiry instant; otherwise a live context
would keep an expired grant's rules until the next edit. A pass judges every context at one
instant, so a grant that expires while a pass is running sends it round again at once, and the
next expiry is scheduled from the instant the last pass judged at, never from the clock after
it: an expiry between the two is due at once. A redemption in flight across an expiry pass has
the same race as one across a swap — it can write the expired grant after the pass visited its
context — so an expiry pass is settled 30s later exactly as a reload is.

**The store down during a reload** does not stop the swap: the new policy is in force for every
mint at once (and every mint fails `store_unavailable` until the store answers). The refresh
stops at its first store error, says how far it got, and runs again every 30s until it
finishes; a context not yet reached keeps its previous policy until then, and
`port49_policy_refresh_pending` holds at 1 from the swap, or from a grant's expiry, until the
settle pass after it completes, reaching every live context and leaving none behind — a
context skipped as busy, or a pass stopped by a store error, keeps it at 1 until a later pass
reaches that context — the alert for a policy in force that has not yet reached every live
session. It is never 0 while a settle pass is outstanding: until then a login in flight may
still write the superseded answer. A context revoked for a compile fault is
done: revoked is its answer under the policy in force, so it does not hold the gauge, and it is
counted `failed` in `port49_context_refreshes_total`, which is its alarm. The directory-driven scheduled
refresh through `active_principals` is plan 7's.

**A context that keeps changing does not stop the pass.** The compare-and-set is on
`policy_rev`, which only a write to what the refresh decides advances: a login's join or
replace, a revocation, a privilege raise or clamp, and a policy write (blob hash, ceiling,
`enable` mechanism). Accounting, which writes only `accounting_state` and the session
discriminators (§5.8), does not advance it, so a session running commands on a device that
reports every one never makes the refresh lose. A write that does advance it between the
refresh's read and its compare-and-set sends it back to read again, up to eight times. A
context still changing after that is left for the retry and the pass goes on to the next,
so one busy session cannot hold every session after it on the superseded policy. A
revocation is not left: it is written unconditionally (`revoked_at` alone), failing closed.

**The bound.** A narrowing is in force for every mint within two `broker.policy_watch_interval`s
of the file's write (10s at the default), and reaches a live context in the first pass after
that; the settle pass follows 30s later. It is delayed past that only where a login, an
`enable` or a revocation on that same context lands inside the refresh's read-to-write window
on all eight attempts, and then by 30s for each pass that happens in — an operator holds a
narrowed grant only by logging in or enabling continuously, on the one device. A withdrawal
is not delayed by a busy context at all. None of this bounds a live session on a platform that
does not authorize commands (step 4): there a narrowing or a withdrawal reaches the next login,
and the session in progress keeps its access until logout.

**A superseded policy's tokens are judged across the whole time it was in force.** A token
it minted carries the answer at the instant of the mint, and that answer changes at each grant
expiry inside the span, so the comparison is made at the start of the span and at every expiry
within it; a key is cleared if any of those answers differs from the policy in force.

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
       (ctx.privilege is the HIGHEST level port49 has granted this user on this device:
        the login START's level, raised by the `priv-lvl` a permitted session
        authorization carried and by an escalation, and never lowered by a grant — the
        only things that lower it are a join whose newer broker decision carries a lower
        `max_privilege`, which clamps it and puts `session.privilege_clamped` (`from`,
        `to`) on its `redeem` record, and a replace, which starts a new context at its
        login level (§5.6). The context covers every window of one operator (§5.6), so
        a second window granted less must not take the first window's enable away. It
        is clamped to the context's ceiling (`max_privilege`; zero is none), and it is
        still a bound: the device cannot exceed it without port49 having said yes
        somewhere. The session-authorization permit raises it in place, same ctx_id —
        measured on vEOS the session authorization arrives at priv_lvl 1, port49 grants
        15, and every later command arrives at 15; tests/lab/results/L1-arista_eos.md,
        L3-arista_eos.md. The level a session authorization REPLIES is policy's answer
        and never this field.
        Ruled 2026-09-23.)
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
one, the tie is broken by lexicographic comparison of the tuples, then by role name, then by
rule text. This is presentation only and cannot change a decision. It is not declaration
order, because the rule a record names is part of the record, and a shuffled policy must
produce byte-identical records (§14, "Order independence"). The permit a record names first is
the one that dominated, even where another permit's tuple sorts above it.

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
    on_missing: include
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
lifting a mitigation is the failure to design against. So a scope with at least one match
key that delivers a deny — it attaches a role carrying one, or a grant on it holds one — MUST
declare `on_missing`, and omitting it is a load error; any other scope defaults to `exclude`.
A scope with no match key, `all_devices`, selects every device and needs neither (plan 4).

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

**One operator, one device, one context — and a second login joins it.** The context is "this
principal's authorization on this device", not one connection: no wire field on authorization
tells two of one operator's windows apart on every platform — NX-OS sends `port` empty on every
command authorization and Junos never authorizes a command (§15, L1; L10, L14; decision 21). So a
second login by the same principal under the same username on the same device **joins** the live
context rather than replacing it (ruled 2026-09-23):

| field | on a join |
|---|---|
| `ctx_id` | kept — each `redeem` record still carries its own `credential_sha256` |
| `privilege` | kept; the new login's level only raises it, clamped to the new ceiling (§5.3); a clamp that lowers it puts `session.privilege_clamped` `{from, to}` on the `redeem` record |
| `session_discriminators`, `accounting_state` | kept |
| `blob_hash`, `max_privilege`, `enable` | from the newest login — the latest broker decision wins |
| `auth_time`, `session_expires` | the later of the two; no ceiling is later than any time — a join never shortens a window already granted, so after a join `session_expires` can exceed `auth_time + max_session_age` |
| `revoked_at` | kept, unless the new token was minted after it (§5.1.1 `minted_at`; §13, decision 15) |
| credential | the newest; every login is still indexed, so revocation by either login's `sid` or certificate reaches the context |
| `port`, `rem_addr` | the newest (informational) |
| `refreshed_at`, `last_touched_at` | now |

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
refused `credential_revoked` again. A token minted after the revocation joins and lifts it, by the
table, and a refusal made after the join has therefore marked its receipt failed (the receipt was
written PASS before the join): once the revocation is lifted, the retransmission replays the
refusal, FAIL `receipt_replayed`. It is not replayed as a PASS, with one exception: the concurrent
duplicate that lost the redemption race (below) is not checked, and if it reads the winner's receipt
before the winner's refusal marks it, it answers PASS. That takes two byte-identical presentations
inside one join; every authorization on the revoked context is denied, and the next retransmission
is refused (plan 3, pre-flight F16). A revocation that lands after the join's write is not seen by
the login, which answers PASS; its first authorization is denied `credential_revoked`.

A login is **not** a join, and writes a fresh context whose `redeem` record carries
`session.replaced_ctx_id`, in two cases: the live context belongs to **another principal** under
the same username, or it is **past `session_expires`**. A ceiling ending is not a credential
verified again, so the same principal's `revoked_at` carries across that replace by the rule in the
table. A context the idle TTL has reclaimed is absent, and the login writes a fresh one with nothing
to name. The join is a compare-and-set on the context's revision, so a revocation, an accounting
annotation, a privilege raise or a refresh that lands mid-login is merged rather than erased, and
two simultaneous logins both land.

**A replace unindexes what it displaced, before the new login is indexed**, so a later revocation
of the displaced credential does not reach the context that replaced it. What it unindexes
depends on whose context it was:

- **Another principal's**: every key the context was indexed under — its principal and every
  login's `sid` and certificate, including joined logins the record no longer names. Nothing of
  the displaced principal's is the new login's to keep. The cost is fail-open for the displaced
  principal, and it is accepted: their still-open windows now authorize against the new
  principal's context, and a revocation of them by `sid`, certificate or principal reaches
  nothing on this device. That needs two subjects under one username, which the uniqueness MUST
  of §2 already forbids.
- **An unreadable one**: the same whole clear, because its keys are sealed and cannot be compared
  (below). When it was the same principal's, its own keys go too, and the new login's index
  puts them back.
- **The same principal's, past its ceiling**: only the displaced login's `sid` and certificate
  that the new login does not share. A shared key is about to be indexed again, and unindexing it
  first would leave a moment in which a revocation by it finds nothing. An earlier joined login's
  `sid` stays, and a revocation of it can mark the new context: the same person, fail-closed.

An empty `sid` or certificate (no issuer or no serial) is never indexed or unindexed, and a
revocation by one is refused rather than run: every certificate login shares the empty `sid`, and
every OIDC login the empty certificate, so revoking by either would revoke them fleet-wide.

The unindex and the index are not one operation with the context write, and two races follow,
each needing logins under one username on one device within a few milliseconds. A second window
of the replacing principal that joins between the replace's write and its whole clear loses its
`sid` and certificate entries; revocation by principal still reaches the context. And two
principals replacing each other can leave the survivor indexed under the loser's keys only, so a
revocation of the loser marks it and one of the survivor misses it; that also needs the
uniqueness MUST broken.

A store port49 cannot reach fails the login `store_unavailable`, refused before the token is
spent. A record the store returns but port49 cannot open — sealed under a key that has left the
two-key window, or failing authentication — cannot be joined, and is **replaced fresh** through
the same compare-and-set: the replace carries the record's plaintext `revoked_at` by the rule in
the table, whoever its principal was, because the principal is sealed; the `redeem` record carries
`session.replaced_unreadable: true` and no `replaced_ctx_id`, because that id is sealed too; and
the unreadable login's index entries cannot be named, so the replace clears every key the context
was indexed under, as another principal's replace does, before the new login is indexed. Left in
place they would not age out at `index_ttl`: every extension of the replacing context re-stamps
them, so a revocation of the displaced credential would reach it for as long as it lives. Each such
login opens the record twice (the read before the token is spent and the join's own), so
`port49_crypt_open_failures_total{record="context"}` counts at least two per login. Every read of
such a record counts `port49_store_operations_total{outcome="unreadable"}`, not `outcome="error"`:
the store answered, and a key rotation must not read as a store outage.

A retransmitted login or `enable` replays its receipt only while the receipt's `ctx_id` is the live
context's, and, while that context is revoked, is refused `credential_revoked` instead (above). The
join keeps `ctx_id` across one principal's logins, so a match is exactly "the same
context"; after a replace or a reclaim the receipt names a context that no longer exists, and the
retransmission is answered `token_spent`, as a spent token is, without sliding the receipt. The
device prompts again. The one copy not checked is the concurrent duplicate that lost the
redemption race: it presented the winner's own credential, and the winner's context write is still
in flight. It replays the winner's receipt as it stands, so it can replay the winner's PASS even
where the winner is refused (pre-flight F16, above).

What remains of the old cost: both windows log one `ctx_id`, so a log reader tells them apart by
`port`, `rem_addr` and each `redeem` record's `credential_sha256`, not by `ctx_id`.

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
| 1 | **Login redemption** on the same `(nas, username)` | port49 performed it — joins the same principal's live context and replaces another principal's, logging the replace (above). An `enable` redemption is not this: it updates `privilege` in place and keeps `ctx_id` (§7). **That is a requirement on plan 2's escalate path, not a description of the tree** — see below |
| 2 | **Revocation** — OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial; a policy change withdrawing every grant on the device, or leaving a policy in force that cannot be resolved or compiled for the context, or a refresh finding a context it cannot open (§5.1.3, "Policy reload") | authoritative: from the identity layer (§5.1.4), or, for a policy change, from the policy in force, with a `refresh` record saying which (§5.7). Sets `revoked_at` rather than deleting, so the next command is denied `credential_revoked` with a `server_msg` saying so — distinguishable from a session port49 never saw. Row 6 reclaims the state |
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
does, measured (`tests/lab/results/L3-arista_eos.md`). Measured on vEOS-lab 4.31.2F
2026-09-22, one operator's whole sequence:

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
The converse — a second login writing `priv_lvl=1` over an enabled context — is closed by the join
above and by raise-only privilege (§5.3), 2026-09-23.

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
reclaims the state. §5.8 specifies the annotation, including the session-discriminator binding
that makes it correct.

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
`max_session_age`, which is an approximation but an enforced one: `port49 platform export
--classes` prints each class a projected platform's replies rest on with `idle-timeout` set to
`session.max_session_age_default` in whole minutes, rounded down (§8), and L24 measures whether
it ends an idle session a reply landed in that class; this lever is *provisional on L24*
(decision 21). And every revocation record
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
  `L4-juniper_vjunos-router.md`, `L4-arista_eos.md`, `L4-cisco_nxos.md`). Per-command
  authorization was measured 2026-09-24: a FAIL is final on vEOS, the N9Kv and IOS-XE under every
  list tried, `local` and `if-authenticated` included (`tests/lab/results/L4-error-*.md`). What
  closes the window is the reference AAA configuration per platform, which the lab register
  tracks as L4.
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

Method lists fall through to a later method when the server is unreachable, and not on **FAIL**
(an explicit reject). Whether an **ERROR** reply falls through is per platform, and it is not the
same as unreachable: measured 2026-09-24, an authentication ERROR falls through to `local` on vEOS
and the N9Kv and on Junos with `password` in `authentication-order`, and is final on IOS-XE and on
Junos with `tacplus` alone (`tests/lab/results/L4-error-*.md`). So a session that authenticates locally rather than through
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

**Local account names MUST NOT collide with device-facing usernames, and `enable` MUST NOT fall
back to a local secret.** A device-local `bob` that is not the port49 username `bob` matches on
username and inherits the context — and the context holds the highest level port49 has granted
`bob` on that device (§5.3). Every command such a session sends arrives under the same username and
is authorized at that level; so does every command of a port49 `bob` session that reached `enable`
through a local enable secret rather than through port49. The reference AAA configuration MUST
require disjoint namespaces for break-glass and local accounts and MUST NOT put a local fallback on
the enable method list, and port49 SHOULD warn when it observes a local fallback succeed for a
username it knows. The detection that exists is accounting: such a session's exec records carry a
discriminator port49 never saw begin and are attributed `foreign` (§5.8), counted in
`port49_accounting_attributions_total{attribution="foreign"}`. The configuration check is
`port49 devices check-config` (§12): it reads a device's configuration against its adapter and
fails on a device-local account named as a username port49 serves there, on an enable list
that falls back to a local secret, and on a `device_config` line the configuration lacks.

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
Two carve-outs, both on the `refresh` event (§5.1.3). A refresh that finds a context already
on the answer the policy in force gives writes nothing and records nothing: every edit changes
the bundle, so a reload's first pass records every live context, but the settle pass after it,
the retries and the pass at a grant's expiry find most contexts unchanged, and there is
nothing to explain. And a pass a store error stops records nothing for the context it stopped
at: nothing was written, the process log says how far the pass got, and
`port49_policy_refresh_pending` stays at 1. A context left for a quarantine is recorded once
per policy version (bundle), not at each pass that finds it so. Every revocation a refresh
makes is recorded.

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
`bundle` and `blob` are mandatory on every record that consulted policy. Until the inventory
service publishes versioned bundles (§10), `bundle` is the `sha256:` of the policy file the
blob was compiled from, a string; the blob carries it, so a daemon that never reads the policy
still logs it.

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

`reply.attributes` is what a permitted `authorize_session` returned, as sent — every
placeholder filled (§6). A replay re-derives it from the blob and the record's own
`session.username`, `principal` and `device.name` and compares, so an altered session reply is
a divergence like an altered verdict (plan 4).

**Never suppress permits.** Sampling, or logging denies only, looks thrifty and destroys the
artifact: *what did Alice run on Tuesday* is answered entirely by permits. Volume is the cost
of the product, not a problem to optimize away.

#### Events

One envelope. Six decision events, one at each point a decision is made, plus three report
events (`account`, `account_gap`, `blob`) that share the envelope and carry no verdict:

| `event` | Emitted by | Decides |
|---|---|---|
| `mint` | broker | which grants matched, which roles composed, which blob resulted |
| `redeem` | daemon | whether a presented credential is valid, and creates the context |
| `authorize_session` | daemon | the session and its returned attributes (§6) |
| `authorize_command` | daemon | one command vector |
| `escalate` | daemon | an `enable` exchange, attributed to the principal (§7) |
| `refresh` | broker | whether a live context takes the policy now in force, or is revoked (§5.1.3) |
| `blob` | broker | not a decision: the full compiled blob, emitted once per hash so replay depends on the log alone (§5.1.1) |

Device accounting shares this envelope as the eighth event, `account`, and is specified in
§5.8. It is not a decision — it is a report — so it carries no `policy` block and no verdict.
A ninth, `account_gap`, is a report too: accounting records port49 received and did not write,
`{"gap": {"stage": ..., "records": N, "since": ...}}`, one record per spool drop stage —
`offer_refused` (answered `ERROR`; the device may send the record again), `drain_unparseable`
and `drain_set_aside` (answered `SUCCESS`, and not in the log). An `offer_refused` drop is written
before the next drain pass's records; a drop during a pass is written when that pass ends,
after the records it sat among. `since` is the earliest arrival among the drops the record
counts, as far as the spool knows it: the refusal itself for `offer_refused`; a set-aside
record's own `ts`; for a line the drain could not read, the `ts` of the record before it in the
spool, which that line arrived no earlier than, or the drop time when there is none. A backlog
drained hours late is therefore charged to when it arrived, not to when it drained. A gap write
the log refuses is kept and written by the next pass, before its records. It is what lets a
reader of the log know the accounting stream has a hole, which reconciliation must know before
it says a device did not ask (§9). The count is held in memory, so a restart loses what was not
yet written, and port49d logs the held counts by stage when it shuts down;
`port49_accounting_spool_drops_total{stage}`
is the alarm, and this record is the log's own witness.

`escalate` exists as its own event because the device-facing username on those platforms is
`$enab{level}$`, not a person. The record carries the principal resolved from login context,
which is the only place that attribution is recoverable.

A `mint` record is the audit trail for *authority*, where the others are the trail for *use*:
it therefore carries **no `credential_sha256`**. That field is the hash of what was presented
on the wire, and at mint time nothing has been presented: the broker holds the subject's
identity, not a secret, so any hash it could compute would join to nothing — and a blank one
is worse than an absent one, because it is present on every mint record in the fleet and
joins everything to everything. `token_sha256` is what a mint record carries instead, and it
is what the redemption joins back to (see Correlation below).

```json
{
  "ts": "2026-09-04T02:04:55.108Z",
  "event": "mint",
  "verdict": "permit",
  "reason": "grants_matched",
  "principal": "user:alice@example.com",
  "auth": { "method": "oidc" },
  "policy": {
    "bundle": 2291,
    "subject": "network-operators",
    "grants": [{ "scope": "campus", "roles": ["net-operator", "no-exfil"], "expires": null }],
    "blobs":  { "arista_eos": "sha256:a3f9c1…", "cisco_nxos": "sha256:77b0de…" }
  },
  "scope": { "devices": 412, "ttl_seconds": 900 }
}
```

A `mint deny trust_domain_unresolved` for a client certificate the trust anchor verified —
refused later for expiry, a missing `clientAuth` usage, or not exactly one well-formed email
SAN — says whose certificate it was: `auth.fingerprint` (the certificate's `sha256:`, §5.1.4)
always, and `principal` when the one email SAN maps to one. Those fields are anchor-vouched,
not an unvalidated body. A connection with no verified chain names no one.

#### Reason codes

`reason` is a closed vocabulary, so denials are countable and alertable without parsing prose:

| `reason` | Meaning |
|---|---|
| `grants_matched` | `mint`: at least one declared grant selected the device; blob written. `refresh`: the policy in force was written into the live context |
| `no_grants_matched` | `mint`: no declared grant for this principal selects the device. `refresh`: none does any more, and the live context is revoked |
| `username_collision` | `mint`: the derived username is already held by a subject in another trust domain (§2) |
| `trust_domain_unresolved` | `mint`: no configured verifier accepted the credential (design document §7) |
| `candidate_cap_reached` | `mint`: `token.candidate_cap` unspent tokens already stand for this `(device, username)`; the mint is refused, never a redemption, and every token already issued stays usable (design document §8) |
| `context_matched` | `authorize_session`: context found, attributes returned |
| `escalation_granted` | `escalate`: the level was within `max_privilege` and the mechanism succeeded |
| `permit_dominates` | a permit dominated every matching deny (§5.4) |
| `pipe_stage_denied` | a pipeline stage matched no pipe permit (§4) |
| `service_unsupported` | the authorization `service` is not one the platform authorizes; on `redeem`, the authentication action or type is not one port49 serves (only `login` with ASCII, PAP, or CHAP) and the reply is `ERROR` |
| `store_unavailable` | any event: the store did not answer or returned an error. On `redeem` and on accounting the reply is `ERROR`; on an authorization it is `FAIL` — fail closed, a break-glass account's commands included (plan 4, owner's ruling 2026-09-24), because an authorization `ERROR` hands the N9Kv's command to its local role checks and permits every command under IOS-XE's `if-authenticated` (§15, L4). Whether the device then falls through to its next method is per platform and is not what this reason promises: an authentication `ERROR` is final on IOS-XE and on Junos with `tacplus` alone, and where it does fall through (vEOS, the N9Kv) the authorization `FAIL` that follows leaves break-glass logged in and unable to run a command (§15, L4; `tests/lab/results/L4-error-*.md`). So a store outage is not the break-glass case; an unreachable port49 is. The operator's escape is to stop port49d, or reject TCP 49 with a reset, so each device finds the connection refused and treats the server as down. A break-glass account then logs in with its local password, under a method list that ends in `local` (measured over SSH on all five images, §15 L4 and L17). A firewall that drops TCP 49 silently is unmeasured as an escape (a silent server costs 5s per command on the Cisco and Arista images, L4), and so is whether commands in a session already open fall to local authorization. port49d will do this itself by closing its TACACS+ listener while the store is unhealthy (owner's ruling 2026-09-24; arrives with the remote store, plan 6/7). The log line is the evidence an operator needs at 3am |
| `token_redeemed` | `redeem`: a presented credential matched an unspent token |
| `token_not_found` | `redeem`: the device tag matched but no unspent token for `(nas, username)` did — expired, spent, or mistyped |
| `token_spent` | `redeem`/`escalate`: the credential matched a receipt whose sliding window (`receipt_idle_ttl`) or absolute cap (`receipt_max_age`) had passed, or whose `ctx_id` is no longer the live context's — the context was replaced or reclaimed since, so the stored decision describes nothing that exists (§5.6); FAIL on the wire, distinguishable only in the log |
| `device_mismatch` | `redeem`: the presented token's device tag is not this device's (design document §8) — PAP and ASCII only; under CHAP the tag is not visible and the outcome is `token_not_found` |
| `credential_mismatch` | `redeem`: the receipt the store returned does not carry the credential hash the lookup asked for. Since 2026-09-20 the hash is *in* the receipt key (§13, decision 15), so a differing credential finds no receipt and redeems normally instead; this reason now covers only a store that answered with a record it was not asked for, which is a store fault and never a normal outcome |
| `receipt_replayed` | `redeem`: a byte-identical retransmission replayed the stored decision; not while the context it names is revoked — that is `credential_revoked` (§5.6). A login refused after its join replays as FAIL once the revocation is lifted |
| `token_kind_mismatch` | `redeem`/`escalate`: a login token presented at `enable`, or the reverse (§7) |
| `enable_refused` | `escalate`: the subject's mechanism is `none` |
| `ceiling_exceeded` | `escalate`: the requested level is above `max_privilege` |
| `no_rule_matched` | nothing matched; deny by default |
| `no_permit_dominates_deny` | a deny matched and no permit dominated it |
| `context_missing` | no login context for `(nas, username)` — port49 did not authenticate this session under that name |
| `username_mismatch` | the request's username differs from the one bound at redemption (§5.6). Reachable two ways, and a request under a name port49 never authenticated is neither of them — that is `context_missing`, because the username is the key. First, wherever the username is resolved from context rather than read off the wire: the `$enab{level}$` enable path through the `(nas, rem_addr)` index. Second, as a **store-fault guard** — the context lookup selects on the username, so a store answering with another principal's record fails the re-check that follows it and is denied rather than authorized. A correct store never produces the second |
| `rem_addr_mismatch` | enable arrived from a different address than the bound one |
| `privilege_exceeded` | the request is above the session's granted level |
| `session_expired` | the session ceiling was reached; context retained through the grace window (§5.6). On `mint`: the held connection's authentication is older than `max_session_age`, and the caller must authenticate again (§13, decision 17) |
| `context_stale` | the broker has been unreachable past `staleness_ceiling`; context retained, denies until refreshed (§5.1.1, design document §9) |
| `credential_revoked` | the context's `revoked_at` is set — CRL, OCSP, back-channel logout, every grant on the device withdrawn, a subject's username changed, the policy in force not compiling for the context, or a refresh finding a context it could not open, where the `refresh` record before it says which (§5.1.3, §5.6); on `redeem`, a login whose resulting context is revoked because its token was not minted after the revocation, or a retransmission answered while the context it names is revoked (§5.6) |
| `device_unknown` | the source address is not in the admission trie (§10) |
| `platform_unknown` | the device's platform has no adapter; generic fallback applied |
| `blob_unavailable` | the referenced blob could not be resolved from the store or any cache — a store fault, alarmed (§5.1.1) — or the context no longer fits the blob: a session attribute filled from it exceeds 255 bytes, or a filled-in value carries a separator (`=`, `*`) or a control character, either of which the broker refused at mint (§6), or the reply would send a `priv-lvl` above the context's `max_privilege`, a `priv-lvl` that is not a level 0 to 15, or an attribute the blob's `accepted_attributes` does not take — compositions the load quarantines (§6, §7). On `refresh`: the policy in force could not be resolved or compiled for this context — an unexpected broker fault, since the reload's load (§5.1.3 step 1) compiled every subject on every device, and what failed quarantined its device or refused the policy under the joint check (§10) — so the context is revoked, failing closed; the process log names the `ctx_id` and the fault, and it is counted `failed`. Also on `refresh`: the context could not be opened — sealed under a key that has left the two-key window, or failing authentication — so it is revoked through the monotonic revocation mark, the record names the device and the username its key holds and no principal (the owner and `ctx_id` are sealed, and the index entry that led to it may be stale), and it is counted `failed` |
| `blob_platform_mismatch` | the context's blob was compiled for a platform other than the one inventory gives the device — inventory changed since the mint, or the broker and the daemon read different inventories. Its dialect and attributes are another platform's, so it is never answered from; operational, alertable beside `blob_unavailable` |
| `device_quarantined` | the device is in inventory but failed joint validation against policy (§10); the connection is closed without a reply, as for `device_unknown`, until fixed. On `refresh`, a deny recorded once per context per policy version (bundle): the live context is left as it was until the quarantine lifts |
| `projection_fail_closed` | `authorize_session`, a permit: the session on a projected platform (§8) was answered with its composition's fail-closed reply — every command denied but what the projection proved — because the projection cannot tell the device that composition faithfully (§13, decision 26). The blob carries why (`fail_closed`: `refused_shape`, `configuration_mode`, `overflow`, `unwritable`, `secret_rule`, `unsound`, `argument_deny`, a deny Junos cannot match because it names an argument, or `configuration_deny`, a deny of a configuration statement, which deny-commands never reaches; decision 27). Every other subject on the device is answered as before; `policy test` and `policy diff` fail on the composition |

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

A secret an operator types into a command — `username bob secret Hunter2` — reaches port49 on
the command's authorization request as well as its accounting record, so both are redacted
before they are written, by the platform's `redact` patterns (§5.8). The decision is made on
the command as sent; only the record loses the secret. A redacted record carries
`"redacted": true` in its `request` (an `authorize_command`) or its `record` (an `account`),
and `port49 policy replay` reports it `unverifiable` rather than replaying the redacted words:
the command it decided is not in the log, by design.

The same rule applies to every other place port49 writes a command it received from a device,
a debug log included. That place writes the redacted form, or it does not write the command.
A denial's `server_msg` (§5.3) names the rule that decided and does not echo the command, and it
goes only to the session that typed the command. `port49 policy test` reads commands from the
policy's own test cases, not from a device.

A rule's text is redacted by the same patterns wherever it is echoed: a record's
`matched_deny` and `matched_permits`, and a denial's `server_msg`, which shows the value as
`<redacted>` because a console takes ASCII. A policy literal is no safer in a log than a typed
one — `deny snmp-server community public **` is a legitimate rule, and its value is a
community. A record whose echoed rules were redacted carries `"redacted": true` in its
`request` as well, and replay reports it `unverifiable`: the rules it logged are not the blob's.
Wildcards are not values and are echoed as written. The `blob` event is redacted the same way
(§5.8).

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

#### Three wire details that break the join

**Strip the trailing `cmd-arg=<cr>`.** Several vendors terminate the argument list with a
literal `<cr>`. It is not an argument, and left in place every reconciliation join misses by
one position and every command looks unauthorized. Normalization (§3) removes it; the raw
record keeps it.

**Redact secrets before emit.** Command accounting carries typed text verbatim, so
`username bob secret Hunter2` arrives in full. This is the well-known way TACACS+ accounting
logs fill with plaintext passwords, and it is worse here than in a conventional deployment
because port49's stream is designed to be shipped and retained.

Platform adapters therefore declare redaction patterns, applied before the record reaches the
spool — which is on disk — and before an authorization record is emitted (§5.7):

```yaml
# platforms/redact.yaml — the built-in patterns (abridged)
default:
  - {match: ['**'], after: secret}
  - {match: ['**'], after: password}
  - {match: ['**'], after: key}
  - {match: ['**'], after: key-string}
  - {match: ['**'], after: authentication-key}
  - {match: ['**'], after: message-digest-key}
  - {match: ['**'], after: pre-shared-key}
  - {match: ['**', snmp-server, community, '**'], after: community}
  - {match: ['**', snmp-server, host, '**'], after: host}
  - {match: ['**', snmp-server, user, '**'], after: auth}
  - {match: ['**', authentication, text, '**'], after: text}
  - {match: ['**'], after: area-password}
  - {match: ['**', ipsec, spi, '**'], after: spi}
  # ... HSRP, IS-IS, BGP, PIM and NHRP keywords; the file is the list
juniper_junos:
  - {match: ['**'], after: encrypted-password}
  - {match: ['**'], after: plain-text-password-value}
  - {match: ['**'], after: authentication-password}
  - {match: ['**'], after: privacy-password}
```

A pattern's `match` is words, `*` for one word and `**` for any number, anchored at both ends
as a rule is. Words are compared ignoring case, in `match` and `after` alike, as §4's rules are,
so a difference in case makes a pattern remove more and never less. A command it matches loses
every word after the first word equal to `after`, the command word included, or
every word from position `from` on (0 is the command word and is never removed; a negative
`from` counts from the end). A pattern's word matches its abbreviations too — any shorter
prefix of it, ignoring case — on every platform, whatever `expands_abbreviations` says, so
`usern x sec 0 X` and `snmp comm X` are redacted. That removes more rather than less, and it
does not trust the flag: L21 measured expansion for interactive SSH only, and a flag that is
wrong where redaction relies on it leaks a secret into a log that cannot take it back.
That holds for every argument: `tacacs-server k X`, `enable s 0 X`, `username bob pa X` are
redacted. The **command word** — the first word, or the word after a leading `do` — matches
a secret keyword's abbreviation only where it is three characters or more, one character (`k
X` in a key chain), or two characters followed by a bare digit, an encryption type (`sh 7 X` in
an EOS IPsec profile); the whole keyword always matches. So `sh ip int br`, `sh run` and `do sh
run` keep their arguments, where every exec `sh` would otherwise read as `shared-key`. The cost
is named: a two-character submode command word that is a secret keyword and is followed by
something other than a digit — `sh X` in an IPsec profile — is not redacted, where a device
sends it as typed; EOS and IOS-XE over interactive SSH send it expanded (L21). `idtoken` is
scoped to `license`, so `| i hostname` is not read as it; `token` is not scoped, because a
token need not be the last word (`management api gnmi token X vrf mgmt`, `token 0 X`), and an
argument `to` loses what follows it, an accepted cost.
Redaction therefore errs toward hiding: some non-secret arguments — `aaa authentication login
… none`, `area 0 …`, `ip domain name …` — are redacted, because a word that begins a secret
keyword (`authentication-key`, `area-password`, `domain-password`) counts as its
abbreviation. The record still carries the command word, so an auditor sees that an `aaa
authentication` change happened and can read the rest from the device.
Junos sends a whole command line as one `cmd`, so each element is split into words first.
Whatever the patterns say, a word holding a URL with a password in its userinfo —
`copy running-config scp://admin:X@10.0.0.9/r.cfg`, an archive `path`, in any scheme — has
the password replaced and keeps its scheme, user and host, so the record still shows where
a configuration went: no `after:` pattern can hide part of a word. So has a credential in its
query string — `X-Amz-Signature`, `X-Amz-Credential`, `X-Amz-Security-Token`, `sig`,
`signature`, `token`, `access_token`, `password`, `passwd`, `key` or `secret`, any case — its
name kept: a presigned URL's signature is a bearer credential until it expires. A WLC's
`security wpa psk set-key ...` and `wpa-psk ...` are redacted by the default list (`wpa-psk`
matches `wpa` as its abbreviation), though no 5a platform is a WLC.
The built-in patterns lead with `**`, because a secret sits anywhere in a line and NX-OS's
accounting `cmd` is the configuration path joined with ` ; ` and a result — `configure
terminal ; username bob password ... (SUCCESS)` (`tests/lab/results/L21-cisco_nxos.md`) — which
a pattern anchored at the command word never matches. A pattern whose `match` is `*` and `**`
alone matches every command, and with `from` it would remove the arguments of every record: it
is refused, and a secret is named by the word it follows, with `after`. Where a pattern removes
words from a record's `raw` pairs and not its vector, or the other way round, the form it
missed loses every argument, so a secret is never left in one of the two. Each pattern is
judged on its own: another pattern matching both forms does not excuse this one.

A value glued to its keyword, `key=X` or `password:X`, is matched as the keyword and the word
after it, and a keyword ending in the separator, `password: X`, as the keyword; a keyword's
leading `-` and `/` are not part of it, so `--password=X`, `/password:X` and `--password X` are
too; the word keeps its keyword, `key=«redacted»`. The cost is a single-letter option read as a
keyword's abbreviation: `ping -c 5 1.1.1.1` is recorded `ping -c «redacted» «redacted»`, and
`-s`, `-d`, `-a`, `-t`, `-h`, `-w` likewise, while `sshpass -p X` must stay redacted; it is
accepted. Redaction replaces argument *values* with `«redacted»` and preserves the vector's shape and
length, so the reconciliation join still works on a redacted record. It applies to `raw` as
well — a rule that redacted only the normalized form would defeat itself.

**A policy's own rule text is redacted too** (§5.7). A rule or pipe permit may legitimately
carry a value a pattern hides — `deny snmp-server community public **` — and it loads; `port49
policy test` and `port49d` at start report it as `rule_secret_literal`, naming the role and the
rule in its redacted form, so the operator knows the value lives in the policy file and reads
`«redacted»` everywhere else. Everywhere else means: every line `port49d` and its broker write
about a policy that loaded, and what `port49 policy test`, `policy diff`, `platform upgrade` and
`explain` print for one, since CI keeps it. Those redact every quoted value by every pattern that
applies anywhere under the policy, the file's own `platforms:` patterns included, erring toward
hiding; a quoted value is split as prose is, by whitespace and then by punctuation and a
regex's operators, an escape such as `\s` one separator, so the `"^snmp-server community X"` a
diff prints of a config check is read as its words, and text a built-in set ships as adapter
text prints as written (final review I3). `policy diff` and `platform upgrade` print an adapter
key's two values with a block's text redacted as `platform show` prints it (below); the sha256
an `acknowledge:` entry names is still taken over the value as written. A policy
that does not load is refused **closed**: its patterns never loaded, so the refusal — at start,
on a reload, or from those tools — quotes no value from the file. It names where and what: a rule
by its role, list and position and a term by its position, e.g. `role "admin": deny #2: term 3
is a regex that is one word; write the word instead`; a test row as `tests[N]` with its subject
and device, never its command; an adapter or redaction-pattern value, an attribute or an entity
class pattern by its key and index (`platforms.arista_eos.entity_classes.bad_comm[0] does not
compile: missing closing )`); a YAML type error, unknown field or repeated key by its line, and
an explicitly tagged scalar that does not decode (`!!int "…"`) or an alias to no anchor
(`deny: [*secret]`) by what it is, never the value. Names
the file declares or refers to — a role, a subject, a scope, a level, a device, a class, an
attribute name — are named. The operator finds the rest in the file. The `blob` event
(§5.7, "Replay") is logged with such rules and pipe permits redacted, and with the patterns of
an entity class a rule names where a value is redacted (`snmp-server community @bad **`)
replaced by `«redacted»`; it carries `"redacted": true`. The store keeps the blob verbatim, and
the hash beside it still names which blob it was. A redacted body does not hash to its name, so replay reports every record
naming it `unverifiable` — never a divergence, and never an agreement — until replay can read
the verbatim blob from outside the log. A blob with no such rule is logged byte for byte.

**A block's `device_config` line is redacted too.** An operator may hold a device to a line
that carries a value a pattern hides — `snmp-server community X ro` — and it loads; `port49
policy test` reports it as `device_config_secret_literal`, naming the line by its platform key
and index in its redacted form, and `port49 platform show` and `platform export` print it
redacted, as they do a block's `config_checks` `match` and `says`: export's output goes upstream,
and the operator restores the value from the policy file. A `device_config` line or a
`config_checks` `match` that holds the marker `«redacted»` is refused at load, naming the
platform, key and index — an export pasted back would otherwise hold the device to a line
nobody wrote, or run a check that matches nothing — and says to re-enter the value from the
policy. The rest of a block's text is printed the same way (final review I2): its `unreachable`
rules redacted as a rule is, its `fallback` text and note as prose, and its entity classes'
patterns as prose, every pattern of a class a rule names where a value is redacted reading
`«redacted»`, as the `blob` event writes it; and an `unreachable` rule, a `fallback` text or an
entity class pattern that holds the marker is refused at load the same way (an `unreachable`
rule named by its level alone, since a block's list merges into the set's). A regex escape, `\s` or `\S`, is not read as a word when a `match` is redacted, so a
check with no secret is exported as written. A block's `config_checks[i].match`
that carries such a value is reported the same way, as `device_config_secret_literal` naming
`platforms.<p>.config_checks[i].match`; its `says` is prose, redacted wherever it is printed
and never reported, since ordinary wording — "falls back to a local secret" — would trip it.
A line or a check a
built-in set ships is lab text and printed as written, though abbreviation matching reads its
`authentication` as `authentication-key`. `port49 devices check-config` redacts every
configuration line it prints the same way (§12).

**The built-in patterns are not part of a pinned platform set** (§8). Redaction changes what
the log keeps and never what anyone may do, so a pattern a release adds applies at upgrade.
They live in `platforms/redact.yaml` beside the sets: a `default` list every platform gets, and
per platform a list that **adds** to it and never replaces it. A policy file's
`platforms.<name>.redact` adds patterns too and never removes one, `replace: true` included;
because a pattern changes what the audit keeps, an edit to it is gated (§12). `port49 platform
show` prints both.

Redaction is best-effort by nature and MUST NOT be presented otherwise: a pattern that misses
leaks, and no keyword pattern catches a secret typed as a search term, so `show
running-config | include <secret>` is logged as typed. It is strictly better than emitting
verbatim, and the honest mitigation is that port49's own credentials are never typed at a
device prompt in the first place.

**Trim an accounting AV pair's key and value.** An accounting argument is not reliably
`key=value` with no spaces. Measured, vSRX 21.4R3.15 and vJunos-router 23.4R2-S2.1 send

```
session_pid = 31050
```

with a space on each side of the `=`, while every other argument in the same record —
`task_id=1`, `service=shell`, `cmd=login` — carries none
(`tests/lab/results/L17-juniper_vsrx.md`, `L17-juniper_vjunos-router.md`,
`L6-juniper_vsrx.md`, `L6-juniper_vjunos-router.md`). A reader that splits at the first
separator and keeps both halves verbatim therefore stores the key `session_pid ` and the
value ` 31050`, and a lookup for `session_pid` finds nothing. This is not cosmetic: on Junos
`session_pid` is the *only* AV pair that separates two concurrent sessions of one operator
(below), so the untrimmed reader silently binds nothing and every Junos session takes the
"no discriminator" branch. An accounting reader MUST trim both halves. The lab harness's own
first run of L17 published a table saying nothing distinguished two sessions, beside a record
dump that plainly did, which is how this was found.

The authorization path is deliberately left alone: no device in this lab has sent a spaced
argument on an authorization request, and trimming there would change what a rule matches.

#### Annotating login context

Exec accounting annotates context and never deletes it (§5.6). The context is found by
`(nas, username)` — the accounting record's own `user`, not its `port`, which is part of no
key (§5.6):

The context holds a **set** of session discriminators, not one, because under the
`(nas, username)` key (§13, decision 15) one context covers every concurrent session of one
operator on one device — measured, and recorded there as the accepted cost.

```
exec START for (nas, username):
    always  →  add this session's discriminator to the set; accounting_state = open
               (a START is never foreign: port49 is watching this session begin)

exec STOP or WATCHDOG for (nas, username):
    set non-empty, discriminator in it      →  accounting_state = closing (STOP only)
    set non-empty, discriminator not in it  →  annotate foreign, alert
    set empty, or no discriminator sent     →  accounting_state = closing, on the username alone
```

**`START|WATCHDOG` is a WATCHDOG here, not a START.** The flag combination `0x0a` is legal and
Cisco IOS sends interim updates with it. It reports on a session already running, so it adds no
discriminator, does not write `open`, and stays eligible for `foreign` — a device that set the
START bit on every record would otherwise switch the alert off for itself, silently. The
decision log already names these records `watchdog`, and the annotation must not disagree with
the line describing it.

This replaces a single-discriminator model in which a START bound the first value it saw and
every later START was `foreign`. Under that model an operator opening a second window on one
device pages somebody, which is the alert burying its own signal. **A START always adds**, so
the question `foreign` now asks is the one worth asking: a record arrived for a session whose
START port49 never saw, on a device where port49 *did* see other sessions of this user begin.
That is the local fallback, the console login and the name collision, and nothing else.

The set is **capped at 8**, oldest evicted first. Nine concurrent sessions of one user on one
device therefore push the first session's discriminator out, and that session's STOP is then
attributed `foreign` — a false alert, bounded and stated rather than discovered. Eight is well
above the ten-concurrent-login measurement §13 decision 15 records as the accepted cost of the
key, and the alternative — refusing to add past the cap — produces the same false alert and
loses the *newest* session instead of the oldest, which is the one still running.

**The set stores a hash, not the value.** Each entry is `sha256(discriminator)` truncated to
its first 16 bytes and hex-encoded. Equality is all a binding needs, and it is all the set is
ever asked for: nothing reads a discriminator back out, renders it, or joins on it — the
accounting record carries `task_id` in the clear for reconciliation (§5.7), as it always has.
Hashing is what lets the field be stored in the clear alongside the context's sealed identity
fields, and that matters here: on NX-OS the discriminator is `task_id`, whose measured value is
`172.100.100.1@pts/3` (`tests/lab/results/L1-cisco_nxos.md`), carrying the *client's source
address*. `rem_addr` is sealed so that a store dump cannot enumerate who was logged into which
device; storing that same address in the clear under another name would have undone it. A
16-byte truncated hash of a device-local identifier carries neither an identity nor a
credential, so it does not need the sealing layer — and not needing it is what makes a narrow,
under-lock setter possible at all (below).

**What the discriminator is, is per platform, and `task_id` is not it.** This section used to
say `task_id` pairs a START with its STOP because "context is already keyed on `(nas, port)`,
so device-local uniqueness suffices". Both halves are now wrong: the key no longer contains
`port`, and `task_id` is measured **not** device-unique — on both Junos images it restarts at
`1` per session, so two concurrent logins both sent `task_id=1`
(`tests/lab/results/L17-juniper_vsrx.md`, `L17-juniper_vjunos-router.md`; the per-session
restart is visible on its own in `L6-juniper_vsrx.md`, `L6-juniper_vjunos-router.md`). What is
measured to work: `session_pid` on Junos, which took two distinct values across two concurrent
sessions on both images (`31048`/`31050` on vSRX, `17244`/`17246` on vJunos-router) and was
stable from a session's START to its STOP; `task_id` on EOS (`27`/`28`), NX-OS
(`172.100.100.1@pts/3` and `@pts/4`) and IOS-XE (`4033`/`4034`), each distinct across two
concurrent sessions and stable start to stop (`tests/lab/results/L1-arista_eos.md`,
`L1-cisco_nxos.md`, `L1-cisco_iosxe.md`).

**Junos `session_pid` also survives the device's immediate reuse of an accounting `port`, and
that is measured.** One millisecond after one session's logout on `port='0'`, the next login on
`port='0'` carried a different `session_pid` — `14656` → `14695` on vJunos-router, with vSRX
showing the same boundary within one millisecond
(`docs/design/2026-09-20-login-context-key-options.md:108-111`, parsed from the committed
`tests/lab/evidence/L1-juniper_vjunos-router.pcap`). This is the measurement that makes the
discriminator worth binding at all: `port` is reused immediately and `session_pid` is not, so a
STOP arriving late for a closed session cannot be confused with the session that took its line.
The evidence is a design memo's parse of a committed capture rather than a
`tests/lab/results/` note; promoting it to a lab-register row is CLAUDE.md rule 3 work and has
not been done, so it is cited here as what it is.

Still unmeasured: whether `session_pid` survives a reboot or a pid wrap, and the discriminator
on every non-SSH transport. Both are tolerated rather than relied on — a discriminator that is
not in the set leaves a STOP `foreign` and a START simply adds, so the failure is a false alert
and never a wrong attribution. Choosing per platform is adapter work and is specified with the
adapters, not here.

**Which record is the exec record is also per platform.** On EOS, NX-OS and IOS-XE the exec
START and STOP carry no `cmd` argument at all, so "no command" identifies them. On both Junos
images they carry `cmd=login` and `cmd=logout`, alongside per-command records that carry the
typed command (`tests/lab/results/L6-juniper_vsrx.md`, `L6-juniper_vjunos-router.md`,
`L17-juniper_vsrx.md`, `L17-juniper_vjunos-router.md`). A reader that treats "no command" as
the only exec form annotates nothing at all on Junos. Per-command records never annotate, on
any platform.

The empty-set branch covers `stop-only` accounting and a lost START, and it does more than
decline to alert. **A record on an empty-set context is attributed `resolved`, so it is stamped
with the operator's `principal` and `ctx_id`** — it is joined to the login, in the audit trail,
on the strength of the username alone. That is the intended behaviour and it is the reason a
deployment that sends no STARTs at all still gets attributed accounting rather than a stream of
`unattributed`; but it is a weaker claim than the same record on a bound context, and a reader
comparing the two should know which one it is looking at. The exposure is bounded by its own
mechanism: one genuine exec START turns the check on for that context and everything after it
is compared against the set.

`closing` is
reported and nothing else — it does not stop refresh (§5.1.3), because a STOP from a previous
session on the same line under the same username would otherwise mark a live session closing and
let the staleness ceiling deny it later, which is the demotion's own defect in slow motion. Any
later START sets it back to `open`, which is what a reader checking for `closing` needs and is
why a START writes a value rather than clearing the field. The idle TTL reclaims the state. A record
that matches neither is logged as unattributable to that context and left alone.

With more than one session bound, `closing` means **"at least one session of this user closed"**
and not "this context is closing". That is all an advisory field nothing authorizes on needs to
mean. A STOP does **not** remove its discriminator from the set: that would cost a second store
write to narrow a field no decision reads, and it would turn a device's duplicate STOP into a
`foreign` alert.

An exec STOP or WATCHDOG whose discriminator is **not in a non-empty set** is a **session port49
did not authenticate** and is attributed `foreign`. That is precisely the condition §5.6 requires
a warning for, and it is high-signal: under one name port49 does authenticate, on a device where
port49 watched this user's other sessions begin, a record arrived for a session whose START it
never saw — so either port49 was unreachable and the device fell back locally, or someone reached
a console, or a device-local account shares a principal's name.

Every accounting record the spool accepts is counted in
`port49_accounting_attributions_total{attribution}`, and `foreign` is the series to alert on. The
label is the attribution alone — no device and no user; the decision record carries both. It is not
rate-limited: a burst of `foreign` is itself the signal. A record the spool refused is not counted,
because the device was answered ERROR and will send it again.

Two earlier readings of this paragraph are superseded. It first said "an exec START whose `user`
does not match the bound username", which under the `(nas, username)` key (§13, decision 15) is
unreachable: a START naming another user addresses another key, finds no context, and is
`unattributed`. It then said a second exec START carrying a different discriminator — which made
an operator's second window an alert. Neither is what the signal is worth firing on.

**Accounting does not extend the idle TTL.** The annotation writes the discriminator set and
`accounting_state` and touches neither the expiry nor `last_touched_at`, for the reason
`set_privilege` does not either (§5.6; the half-TTL extension is authorization's, Task 10): a
device that only ever sends accounting must not be able to hold a context open forever, and a
STOP — a record saying a session *ended* — keeping that session's context alive is the plainest
case of it. An operator working is extending the TTL through authorization; an operator who has
stopped working should let the idle TTL reclaim.

A record whose `user` is one the platform's adapter declares a **system user** — a device-local
account the platform's own machinery writes accounting under, rather than a logged-in operator —
is attributed `system` rather than `unattributed`: it is the device acting on its own behalf, not
a session port49 failed to authenticate, and counting it as either buries the signal both exist
for. The system-user list is per platform and is adapter data (§8). A platform adapter **MAY**
name system users, and a platform that declares none produces no `system` records.

**`juniper_junos` ships `root`, and that is measured.** The committed capture behind
`tests/lab/results/L1-juniper_vsrx.md` — `tests/lab/evidence/L1-juniper_vsrx.pcap`, decodable
with the published lab key — holds three accounting records under `user=root`, `port=non-tty`,
carrying their own `session_pid = 28771`:

```
ACCT flags=start user="root" port="non-tty" args=[task_id=1 service=shell session_pid = 28771 cmd=login]
ACCT flags=stop  user="root" port="non-tty" args=[task_id=2 service=shell session_pid = 28771 cmd=set alarm yellow alarm-id 0small-msg <cr>]
ACCT flags=stop  user="root" port="non-tty" args=[task_id=1 service=shell session_pid = 28771 elapsed_time=0 cmd=logout]
```

**There is no authentication and no authorization exchange for `root` anywhere in that file** —
`root` appears in accounting and nowhere else — and the run logged in only as `alice01`,
`alice02` and `alice03`. The command is vSRX's own alarm machinery. That is the definition above,
measured, on vSRX 21.4R3.15: the device acting on its own behalf, under a device-local account,
for a session port49 was never asked to authenticate. Without the entry those three records are
`unattributed`, and a stock vSRX with nothing wrong reports sessions port49 did not authenticate
— which is exactly the signal-burying `system` exists to prevent.

**Every other platform's list ships empty**, and vJunos-router is among them: the same decode of
`tests/lab/evidence/L1-juniper_vjunos-router.pcap` shows no `root` records at all, so the
behaviour is image-specific and unmeasured there. L17's narrower negative stands as written — under
*that* run's accounting event list, with `enhanced-accounting` committed, every record named the
logged-in operator (§15, L17) — and does not contradict this: it measured a different
configuration on a different day. One production observation remains **unmeasured in this lab**,
an NX-OS `admin` record carrying `task_id=vsh.bin.$port` after a cancelled `sudo`, and a
`tests/lab/results/` note reproducing it is what would add `cisco_nxos`.

`system` is reached only where `unattributed` would otherwise be — after `foreign` has already
been decided, on a record that resolved to no context at all. A device acting on its own behalf
is therefore never `foreign`, and the four attribution values `resolved`, `foreign`, `system`
and `unattributed` partition every accounting record.

**A console login as `root` on Junos is attributed `system`, and that is a known limitation.**
`root` is on `juniper_junos`'s list because the device's own machinery writes accounting under it
(above), and a person at the console logging in as `root` writes accounting under the same name.
port49 cannot tell the two apart from the record, so both are `system` and neither is `foreign`.
The record keeps the `port` the device sent, which is what lets a log reader see where the session
was. What `port` a Junos console session presents is unmeasured in this lab. Ruled 2026-09-23.

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
  device role *is* the degraded-mode policy. A reachable port49 whose store is down answers
  `FAIL`, not `ERROR` (§5.7), so the device role does not take over then.
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
transitively up the chain. A level with `parent:` MUST be listed after its parent in
`privilege_levels`. If a level were ordered before the level it renders as, the max-join could pick
a level that renders lower than one it passed over, so doing so is a policy load error.

This also turns an existing wart into declared behavior. NX-OS is role-native with two
built-in roles, so two of its levels render identically there — `operator` as `admin`, since
the owner's ruling of 2026-09-24 (decision 23) — and with `parent:` that is visible and
intentional rather than a surprise. Usually it is exactly right:
`read_only_limited` differs from `readonly` in *which commands port49 permits*, not in what
the device needs to be told. Platforms may still override where the distinction is real.
On a session-only platform that distinction has to reach the device anyway, because nothing
asks port49 per command; §8's projection carries it, and picks its rendering model per
grant from exactly this difference between a role's permits and its level's capability.

A level with no mapping and no resolvable `parent:` chain, on a platform present in
inventory, is a **policy load error**.

**Reordering the list is a breaking change.** Inserting a level mid-list changes every
max-join that crosses it, and the effective-permission diff MUST report that as a privilege
change rather than a cosmetic one: a subject whose level rises under the old order or the new
one is a raise (§12). **The reserved levels keep their relative order** — `readonly` before
`operator` before `admin` — and a `privilege_levels` that reorders them is refused at load
(owner's ruling 2026-09-24): nothing needs it, and it would make "higher" mean two things.
Custom levels go anywhere their `parent:` allows.

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
define their own in the policy file's `platforms:` block, with no upstream change required
(§8, "User-editable, day one"):

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
motivating case; a general template language would be a footgun. `{device}` is the device's
inventory name and `{privilege}` the abstract level the roles compose to (`admin`, not `15`).
An attribute is at most 255 bytes as written, checked at load, and again once filled in, at
mint, where the broker holds the same values the daemon will substitute.

**A placeholder goes only in an attribute listed as inert** (owner's rulings 2026-09-24,
reviews I3 and I4). Each platform's adapter lists the attribute names that carry privilege on
it — `priv-lvl` everywhere; `roles` on `arista_eos` and `shell:roles`, and `cisco-av-pair` which
can carry it, on `cisco_nxos` (L16); `local-user-name` and `user-permissions` on
`juniper_junos` (L18, decision 22), with the Junos command and configuration regexes
`allow-commands`, `deny-commands`, `allow-configuration`, `deny-configuration` and their
`-regexps` forms (vendor-documented, unmeasured, L18) — and the names it holds to carry none.
The inert list is seeded with this section's own motivating case, `home-directory`, and holds
what else the lab measured inert: `home-directory`, `idletime` and `timeout` on `arista_eos` and
`cisco_nxos`. vEOS and the N9Kv leave a session with any of the three beside admin's reply
unchanged — the same level or role, both ceiling commands still sent to port49, `show version`
still permitted (`tests/lab/results/L22-*.md`, "Inert candidates"). `cisco_iosxe` lists nothing
inert. The C8000V refuses the session for `home-directory`, `% Authorization failed.`
(`L22-cisco_iosxe.md`), so on IOS-XE it bears privilege like every other name, and a policy
that sends it there quarantines the device. It left a session unchanged for `idletime*30` and
`timeout*480`, and takes both (below), but a refused session there, repeated, stops it
answering SSH, break-glass included (L18), so both are held bearing on IOS-XE and a change to
either is gated. On `juniper_junos` all three are unmeasured, and only `home-directory` is
listed. A placeholder is allowed only in an attribute listed inert on its platform key, or
under `all` on every platform in the inventory, every platform the pinned set ships and every
platform a `platforms:` block declares: the inventory is not diffed, so the day a device of one
of those arrives it would be sent the placeholder with no review (final review M6), and since
`cisco_iosxe` ships holding `home-directory` bearing, `home-directory*/home/{username}` goes
under each platform's own key, never `all`; anywhere else — a privilege-bearing attribute
or one no adapter lists — it is refused at load. A substitution refuses only `=`, `*` and
control characters, so `priv-lvl={username}` would hide the level from every review tool, and
`allow-commands={principal}` would let a principal's text widen a session-only device's own
allow-list.

**`idletime` and `timeout` are numbers** (owner's ruling 2026-09-24, task 18 review I1). A
placeholder in either is refused at load on every platform, inert or not: a mint fills in an
identity, never a number a device takes. Only `home-directory` keeps placeholders. The lab
measured exactly `idletime*30` and `timeout*480`, so a literal value that is not a plain
decimal — no sign, no leading zero, 0 to 65535 — fails the joint check and quarantines the
device on every platform (§10), and on a platform that sets `accepted_attributes`
(`cisco_iosxe`) so does either attribute in the mandatory `=` form (`idletime=30`), which is
unmeasured there: it takes them only in the optional `*` form, as measured.
What a device makes of `0` is unmeasured: `timeout*0` passes the check, and it is no escalation, since per-command authorization still reaches the session
and on `cisco_iosxe` a change to either is gated (task 18 review N2).

### Validation without semantics

port49 cannot check what an attribute means. It MUST check everything else:

- Exactly one `=` or `*` separator, non-empty attribute name, no duplicate names.
- **Length.** The RFC's argument length field is one byte, so **255 bytes per attribute**,
  and `arg_cnt` is likewise one byte. A generated `deny-commands` regex (§8) will exceed
  this before anything else does. The encoder cannot emit an over-length argument at all, so
  the failure is never truncation on the device (L11); it is a refusal at policy load, which
  is where this MUST be caught.
- Mandatory versus optional, with a warning on any mandatory attribute not recognized.
- **What the device takes.** An adapter MAY list `accepted_attributes`, every attribute name
  the platform's session reply may carry. IOS-XE refused the session for every other
  attribute L18 tried, under either flag, and a run of refusals stops it answering SSH for
  about a minute, break-glass included (`tests/lab/results/L18-cisco_iosxe.md`). L22 saw the
  same for `home-directory`. It also found `idletime*30` and `timeout*480` accepted beside
  `priv-lvl=15` and inert (`tests/lab/results/L22-cisco_iosxe.md`), so the adapter lists
  `priv-lvl`, which is what port49 renders, and those two. Only those two values, optional,
  were measured; their values and form are held to that (above). A composition whose reply carries
  any other attribute fails the joint check and quarantines the device (§10): closed without a
  reply, it falls to local at once. Where an adapter sets
  `accepted_attributes`, a `priv-lvl` in the reply must also be one of the levels that
  adapter's `privilege` renders (1, 7 and 15 on `cisco_iosxe`): what the device lets any other
  level run is unmeasured, so a role or grant layering another fails the joint check the same
  way. The list rides in the blob (§5.1.2), omitted where the adapter sets none, so a blob
  written before it reads as no restriction; the daemon refuses a reply carrying a name the
  blob's list does not take (`blob_unavailable`, nothing sent), under whatever adapter the
  policy merged.
- **`priv-lvl`'s value is a level.** On every platform, a `priv-lvl` a level renders or a role
  or grant layers MUST be a decimal integer from 0 to 15, written plainly: no sign, no leading
  zero, since what a device makes of `07` is unmeasured. IOS-XE refused the session for
  `priv-lvl=99` rather than clamp or ignore it (`tests/lab/results/L18-cisco_iosxe.md`,
  variant 7). An adapter whose rendering sends another value is refused at load, and a
  composition whose reply carries one fails the joint check and quarantines the device (§10).
  The daemon refuses such a reply too (`blob_unavailable`, nothing sent).
- **An attribute name's case never loosens a check** (re-review 2, RR2-M1). What a device makes
  of a name's case is unmeasured, so a comparison that makes an attribute bear privilege, count
  toward the ceiling or read as `priv-lvl`, `idletime` or `timeout` ignores case, and one that
  exempts it — inert, or accepted — is exact: `PRIV-LVL=15` is judged as `priv-lvl=15`, and
  `f5-ltm-user-role*0` as the `F5-LTM-User-Role` a level renders. An adapter that spells one name
  in two cases across `privilege_attributes`, `inert_attributes`, `accepted_attributes`, its
  renderings and `priv-lvl` is refused at load, naming the platform, the key and both spellings.
- **No `priv-lvl` where the levels render a role and no `priv-lvl`** (task 4 review M4). On
  `cisco_nxos` a `priv-lvl` beside `shell:roles` is ignored, and alone it picks a role nobody
  named out of a per-release table, 15 to `network-admin` and 6 to `vdc-operator`
  (`tests/lab/results/L16-cisco_nxos.md`, findings 1 and 6). So on a platform whose adapter
  renders levels and none of them with `priv-lvl`, a composition whose reply carries one, from a
  role or a grant, under the platform's key or `all`, fails the joint check and quarantines the
  device (§10); key the attribute to the platforms that read it.

**Unknown attributes default to optional (`*`).** A mandatory attribute a device cannot
parse causes it to reject the entire session, breaking every login on that platform.
Defaulting to optional means adding a custom attribute cannot take down a fleet; declaring
one mandatory is then a deliberate, reviewable act.

**Not every level is natively representable.** NX-OS is role-native with two built-in roles,
so two levels render identically — `operator` as `admin` (decision 23) — and the distinction
is carried entirely by command authorization. That is acceptable, but it MUST be visible in the
platform file rather than silently surprising.

**On `arista_eos` and `cisco_nxos`, `operator` gets the device privilege `admin` gets**
(owner's ruling 2026-09-24, decision 23). Neither device can draw the operator line itself
while command authorization points at port49: vEOS at level 15 ran `clear counters`, `clear
ip bgp *` and `configure` as `network-operator`, and at level 1 its parser refused even
`clear counters`; on the N9Kv every role, `network-operator` included, ran all three and
changed configuration (`tests/lab/results/ceiling-arista_eos.md`, `ceiling-cisco_nxos.md`).
So `operator` renders as `priv-lvl=15` on EOS, as `admin` does, and on NX-OS, which renders
no level today, it carries admin's ceiling number, 15. **The difference between an operator
and an admin there is entirely port49's command rules.** An operator reading `show privilege`
sees 15; that is expected, and the rules are the fence. Two things follow for whoever writes
the device configuration:

- The device's command method list MUST NOT fall back to `none` or `if-authenticated`. Where
  port49 cannot answer, an operator session at 15 then runs everything; `local` is the only
  safe fallback, and there the device's local role is the policy (§15, L4).
- `readonly` still renders `priv-lvl=1` on EOS, where the parser enforces it (level 1 refused
  all three), so a readonly session is fenced by the device and by port49 both.
- `max_privilege: operator` does not limit device privilege there: it numbers 15, so `enable`
  can reach 15 under it. It still caps the level (§7), and `policy test` reports it as
  `ceiling_indistinct`.

IOS-XE is not in this rule: its level 7, given commands with `privilege exec level 7 ...`,
is exactly the operator rung, so the device can enforce it (`ceiling-cisco_iosxe.md`).
`operator` renders `priv-lvl=7` there, and the adapter's reference configuration carries
the lines level 7 depends on — a command method list for level 7, so the device asks port49
about a level-7 command at all, and `privilege exec level 7 clear counters`, the one command
the measured rung runs. The reference configuration MUST carry both. Without the `privilege
exec` line, operator is readonly (`ceiling-cisco_iosxe.md`, "Reading"). Without the level-7
command method list, the device runs a level-7 command without asking port49: with the
`privilege exec` line and no `aaa authorization commands 7`, operator's `clear counters` ran
and port49 saw no authorization request for it (`tests/lab/results/L22-carried-cisco_iosxe.md`).
With both in place, L22 measured `priv-lvl=7` as the rung: level 7, `clear counters` sent to
port49, `configure terminal` refused in the parser (`L22-cisco_iosxe.md`; decision 25).
`port49 devices check-config` catches the missing list: it requires every
`device_config` line of the adapter, and fails on one the configuration lacks (§12).

**The device role is the other half, and it is what binds when port49 cannot answer.** With
command authorization pointed at port49 no EOS or NX-OS role narrows anything (above); with
the method list fallen back to `local`, the role delivered at login is the policy — on vEOS
`network-operator` is refused `configure` and `network-admin` is not, and on the N9Kv
`network-operator` is refused a configuration command (`L16-arista_eos.md`,
`L16-cisco_nxos.md`, command authorization LOCAL). So where `operator` gets admin's level, it
gets readonly's role: `priv-lvl=15`, `roles=network-operator` on EOS and
`shell:roles*network-operator` on NX-OS, and an outage never hands an operator configuration
(decision 25). `admin` gets `network-admin`, `readonly` `network-operator` and, on EOS,
`priv-lvl=1`.

**Platforms that are not `priv-lvl`-native** (Junos maps to `local-user-name`) MUST declare
a mapping for every level. A missing mapping is a **policy load error in CI**, not a broken
login at 3am. On a projected platform (§8) the mapping is the level's ceiling in permission
bits, and under `bit_delivery: local_user_name` a template user per level; a level with no
bits on its parent chain is a load error on the device it lands on, as any level with no
mapping is.

**Exact attribute spellings are lab-verified, not asserted.** The shipped adapters use bare
`priv-lvl` for the TACACS+ shell-service reply, the bare `roles=` for EOS roles and
`shell:roles*` for NX-OS roles, and nothing but `priv-lvl` on IOS-XE. This paragraph said
`shell:roles` for EOS until plan 5: the lab shows vEOS ignores `shell:roles*` and refuses the
session on `shell:roles=`, and reads the bare `roles=` (`tests/lab/results/L16-arista_eos.md`,
2026-09-22). Those spellings — and every other attribute name in a shipped platform file — MUST be
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

The ceiling bounds what the session reply says, not only what the level renders to: §6
layering lets a role or grant set `priv-lvl` itself, and the device applies the reply. A
composition whose reply, after layering, sends a `priv-lvl` above its `max_privilege` fails
the joint check and quarantines the device on that platform (§10), naming the role or grant
and the attribute; and the daemon refuses a session reply above the context's ceiling
(`blob_unavailable`) rather than sending it and holding the session lower.

`priv-lvl` is not the only attribute the ceiling bounds (final review I1, 2026-09-24). On
`cisco_nxos` and `juniper_junos` the role *is* the privilege, and on `arista_eos` the role is
what the device's local authorization reads when port49 cannot answer (L22). The ceiling bounds
every attribute of the reply that can carry privilege on the platform: one its adapter or any
shipped set lists in `privilege_attributes`, one any of its levels renders there — that attribute
is the level (§6), whatever `accepted_attributes` lists (re-review RR-I1) — and one nobody
measured there, which counts as the highest. Otherwise it does not bound one the adapter lists
inert, or one a platform with
`accepted_attributes` accepts and does not list as bearing privilege — `idletime` and `timeout`
on `cisco_iosxe`, measured changing nothing and held to plain decimals (§6). A change to those
is still gated in the diff (§12): "gated in the diff" and "raises the ceiling" are separate
properties (owner's ruling 2026-09-24). A bounded attribute must be one the ceiling's level
renders there with the same value, or one whose value that attribute's `role_order` ranks
strictly below it, the reply rendered at the session's own level; a value `role_order` does not
rank counts as the highest, and an attribute the ceiling's level does not render at all is
above it. So `shell:roles*network-admin` from a readonly role under `max_privilege: readonly`
quarantines `cisco_nxos`, as `roles=network-admin` does `arista_eos` and any `local-user-name`
or unmeasured `idletime` does `juniper_junos` under set 1.0.0, which renders no level there.
Under set 1.1.0 the attributes the projection renders — the template, the bits, the regexes —
are not judged by this check: the projection itself holds them to the level's ceiling bits
(§8), and a role or grant may not set one (generator constraint 6). **Under a ceiling at
the highest level in `privilege_levels` nothing is bounded**: no level sits above it, so no
attribute can exceed it. The judgment of whether a value went up is the policy diff's (§12): the
joint check asks the one function the diff gate asks of a changed reply, so the two cannot
disagree about what raises a session. The daemon holds only `priv-lvl` to the context's
ceiling, which is all the token carries; the load's joint check is what holds every other
attribute, and a blob is minted only from a composition that passed it.

**The ceiling is a cap on the level, not only on its number.** A composition whose roles land
above its grants' `max_privilege` in `privilege_levels` fails the joint check on every platform,
however the platform numbers the two: a role at `admin` capped at `operator` is quarantined on
`arista_eos` and `cisco_nxos`, where both are 15 (decision 23), exactly as on IOS-XE. Where a
ceiling numbers the same as a higher level on a platform in inventory, `port49 policy test`
reports `ceiling_indistinct`: `max_privilege: operator` does not limit device privilege there,
`enable` can reach 15 under it, and port49's command rules are the only fence (owner's ruling
2026-09-24).

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
submits. The recorded level feeds `privilege_exceeded` for a request above it; the same in-place update happens when a permitted **session authorization** grants a `priv-lvl` (§5.3), because on vEOS the login START carries level 1, port49's session reply grants 15, and every command after it arrives at 15 (`tests/lab/results/L1-arista_eos.md`, `L3-arista_eos.md`) — a context that still held the login level would deny every one of them. Accounting and
the `escalate` record attribute the event to the **real principal** even though the wire said
`$enab15$`.

---

## 8. Platform adapters

A platform adapter is a small declarative file. Adapters ship built in, are verified in the
containerlab matrix where an image exists, and are both overridable and contributable.

```yaml
# platforms/1.0.0/arista_eos.yaml, abridged
platforms:
  arista_eos:
    verified: containerlab         # tests/lab/results/L22-arista_eos.md
    supports: [session, commands]  # config_commands is unmeasured (§9)
    privilege:
      readonly: ["priv-lvl=1",  "roles=network-operator"]
      operator: ["priv-lvl=15", "roles=network-operator"]  # admin's level, readonly's role (§6)
      admin:    ["priv-lvl=15", "roles=network-admin"]
    entity_classes:
      management: ['^Management[0-9]+$']
      loopback:   ['^Loopback[0-9]+$']
      physical:   ['^Ethernet[0-9/.]+$', '^Port-Channel[0-9]+$']
    enable_username: principal
    expands_abbreviations: true    # measured: tests/lab/results/L21-arista_eos.md
    pipe_token: "|"
    pipe_authorized: false         # measured: tests/lab/results/L2-arista_eos.md
    port_pattern: '^vty[0-9]+$'
```

The example said `pipe_authorized: true` until 2026-09-23, and the lab says otherwise: on vEOS
4.31.2F, NX-OS 10.4(2)F and IOS-XE 17.13.01a alike, a typed `show clock | include …` was sent to
port49 for authorization as `show clock` alone (`tests/lab/results/L2-arista_eos.md`,
`L2-cisco_nxos.md`, `L2-cisco_iosxe.md`, "Truncation length"). The device applied the modifier
itself, so on those images a pipe rule protects nothing and `explain` says so. Whether any
modifier ever reaches port49 on any platform is unmeasured.

The example's `operator` said `priv-lvl=7` until 2026-09-24. No lab run measured a vEOS session
at 7, and at 15 the device fences nothing port49 permits (`tests/lab/results/ceiling-arista_eos.md`),
so the owner ruled `operator` onto `admin`'s level on `arista_eos` and `cisco_nxos` (§6, decision
23). **Operator note:** on those two platforms an operator and an admin get the same device
privilege, and the whole difference is port49's per-command rules. A device command method list
that falls back to `none` or `if-authenticated` therefore runs an operator's every command when
port49 cannot answer; end it in `local` (§15, L4).

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
| `enable_username` | `principal`, or a template such as `$enab{level}$` (refused at load until a lab note shows a device sending it, §7) | if enable is supported |
| `expands_abbreviations` | whether the device sends resolved command words | if `commands` |
| `splits_interface_names` | whether the device sends an interface name and its index as two arguments (§3 rule 5); `true` on `cisco_iosxe` only (L21) | optional |
| `pipe_token` / `pipe_authorized` | modifier separator; whether it reaches us | if `commands` |
| `command_projection` | how rules render for session-only platforms (below): `junos_regex`, the one this build renders. Where it is set, `privilege` is each level's ceiling in permission bits, never attributes, and is required, and `supports` is `[session]`. Only a platform the pinned set projects is projected: a `platforms:` block, `replace: true` included, or a new platform that sets `command_projection`, `bits`, `carve_outs`, `bit_delivery` or `local_user_names` where the pinned set does not project that platform is refused at load, since no measurement sets a floor under a bit's reach there | if `session`-only |
| `bits` / `bit_delivery` | each permission bit's reach in rule form, an upper bound measured in the lab (L12), and whether bits travel as `user-permissions` or a `local-user-name` template (below). A session runs the union of its bits' reach. The bit `baseline` is what a class with no bits runs, held by every session and never sent or named in `privilege`. A block may add to a bit's reach, an edit the diff gates as widening (§12), and never take from it, and may not declare a bit the set does not | if `session`-only |
| `carve_outs` | the commands a bit alone makes available, whatever other bit reaches them: each rule held by that bit's own reach, measured in the lab (L12). The only subtraction from the union: a bit not held removes no command another bit reaches except these. A block may drop one and never add one. A `platforms:` block for a platform the pinned set does not project may not declare `carve_outs` at all, and is refused at load (`command_projection`): only a measured set subtracts reach | optional, with `bits` |
| `local_user_names` | under `bit_delivery: local_user_name`, each level's template user on the device, whose class `port49 platform export --classes` renders with the level's bits. Each is `p49-<name>`, in the set and in a block alike, and never `remote` or a platform system user such as `root`: a template the device already has under another class would put the session in that class, whatever bits the projection proved | with `local_user_name` |
| `redact` | patterns whose argument values are removed before an accounting or authorization record is written (§5.7, §5.8); a block **adds** to the built-in patterns in `platforms/redact.yaml` and never removes one, and an edit to it is gated (§12) | if the platform sends command accounting — session-only platforms included |
| `session_services` | the authorization `service` values this platform's sessions arrive with; a **list**, because the name is device-configurable on Junos | defaults per platform |
| `session_discriminator` | the accounting AV pair whose value separates two sessions of one user on one device (§5.8) | defaults per platform |
| `exec_commands` | the `cmd` values that mark an exec record rather than a per-command one; empty means "the exec record carries no `cmd` at all" (§5.8) | defaults per platform |
| `system_users` | usernames this platform's own machinery writes accounting under, attributed `system` (§5.8); `juniper_junos` ships `root`, every other adapter ships empty | optional |
| `port_pattern` | expected `port` shape, used only for drift detection | optional |
| `ceiling_levels` | the priv-lvl number each level stands for where the rendering sends no `priv-lvl` (NX-OS is sent a role and no level, L16), for the token's ceiling | if `privilege` sends no `priv-lvl` |
| `strip_cr` / `shows_server_msg` | whether commands end in `<cr>` (§3 rule 1); whether the device displays a denial's `server_msg` (L2) | defaults from the generic adapter |
| `privilege_attributes` / `inert_attributes` | the attribute names that carry privilege on the platform, and those held to carry none: the only names a placeholder may go in (§6), and the only ones whose change the diff does not gate (§12) | defaults from the generic adapter |
| `accepted_attributes` | where set, every attribute name the session reply may carry, and the reply's `priv-lvl` limited to the levels `privilege` renders; any other quarantines the device, and the list rides in the blob for the daemon to enforce (§6, "What the device takes") | optional |
| `role_order` | per attribute that names a role, its values lowest first, where the lab measured one fencing less than another: `roles` on `arista_eos` and `shell:roles` on `cisco_nxos` rank `network-operator` below `network-admin` (L16, command authorization LOCAL). A value it does not list is unranked and ranks above every value. The reply gate (§12) and the monotone rule (§8) read it | optional |
| `device_config` | the device configuration the adapter's renderings depend on, one line each, printed by `platform show` | optional |
| `unreachable` / `fallback` | per level, the commands the device refuses in its own parser, and what it gives a session on its own when port49 cannot answer: the dead-rule and fallback-exposure reports read them (§12) | optional |
| `local_accounts` / `config_checks` | patterns that find a device-local account in the device's configuration, and lines the configuration must not carry: `port49 devices check-config` reads them (§5.6) | optional |
| `verified` | `containerlab` or `community`; a built-in adapter's own claim, refused in a policy file | optional |

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
instead of emitting a regex: a readonly role that denies `show configuration **` would send
`view` without `view-configuration`, whose carve-out takes the configuration out of `view`, and
nothing on the wire has to be beaten by anything.

**On the measured adapter (set 1.1.0) that readonly fails closed**, and CI names it. `view`
reaches more than `show **` (`request flight-recorder **`, `test policy **` and the rest), and
every session runs the baseline (`help`, `file`, `request`, `start`, …;
`tests/lab/results/L12-bits-juniper_*.md`), so each command those reach and the grant does not
permit needs a wire deny. Those denies render to 469 bytes, past RFC 8907's 255; `save`, one of
them, is not a keyword on both images, so its deny cannot be sent (decision 27); and a deny
beneath a sent bit or the baseline guards the CLI only (L26c, below). The narrow shape cannot
carry a deny beneath a permit, so the subject gets the fail-closed reply (`refused_shape`).
What does project on set 1.1.0: `permit: [show **]` alone, as the narrow shape
(`user-permissions=view view-configuration`, `deny-commands .*`, `allow-commands` `show **`); a
narrow grant of a few show commands; and an admin `permit: [**]` with `deny: [restart **]`,
which no bit but `all` reaches — every bit but the ones that enter configuration mode, and the
deny (decision 26).

Bits reach the device one of two ways, both in use in real fleets and selected per adapter:

| `bit_delivery` | What is sent | Device provisioning |
|---|---|---|
| `user_permissions` | `user-permissions=<bits>` per session, chosen per grant | one template user (`remote` or named) whose class carries no bits of its own |
| `local_user_name` | `local-user-name=<template>`, one template per level, bits in its class | one class per level, rendered by `port49 platform export` |

`user_permissions` is the design's preference: zero per-level provisioning, and the bit set
follows the grant rather than the level. `local_user_name` is for deployments that already
provision classes and want the ceiling in device config where their compliance tooling can see
it. **The built-in adapter ships `user_permissions`** (set 1.1.0): on both images
`user-permissions` was applied over a bitless template, both bits of a two-bit value were, and
one session's value left another's permissions unchanged (`tests/lab/results/L12-juniper_*.md`).
Over a template whose class carried bits it had changed nothing
(`tests/lab/results/L18-juniper_*.md`, variants 9 and 10), and over a `remote` whose class held
`view`, merged cannot be told from ignored. So the reference configuration gives `remote` a
class with no bits, `p49-remote`, where every projected session lands: a session whose bits
were not applied runs nothing, and neither does one whose reply names a template the device
lacks (L18, variant 7).

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
refuse the policy, naming the grant, the two rules, and the platform, rather than rendering
the nearest shape; a daemon that loads it anyway answers that subject with the fail-closed
reply, never the nearest shape (decision 26). Junos documents a second attribute family,
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

This rendering rule is decision 22 and is **provisional on L9 and L12**: L9 for the regex
dialect every wire regex rests on (`JunosFacts`, below), L12 for the bits. The SRX tests measured
class-resident bits with wire regexes; `user-permissions` over TACACS+ is in production use
but has no capture, and neither has the reach of each bit, the `.*` baseline on the wire, nor
the `-regexps` family's precedence. The plan's containerlab step closes L12 before the
generator is final.

**As built (plan 5b).** The projection ships in platform set **1.1.0**; a policy that pins
none renders with 1.0.0 and Junos gets nothing, as before, so turning it on is a pin move
`port49 policy diff` gates like any adapter edit. `internal/projection` renders each
composition, and proves the reply before it is sent: every command the device would run under
it is one port49 permits. It reads the device as the lab measured it (L11): a command runs
where a matching allow beats every deny, or where the bits reach it and no deny matches. The
bits are a **union**: a command runs where any held bit's reach holds it, `baseline` always
held, unless a measured `carve_outs` entry of a bit not held takes it out —
`view-configuration`'s `show configuration **` out of `view`'s `show **`. Nothing else
subtracts: a bit not held never removes a command another bit reaches (plan 5b pre-flight C1).
The bits' reach and carve-outs are applied by the device's command parser, which reads a
command whatever its spacing, case or abbreviation, so both are matched as port49 matches a
deny, the widest reading. The proof's obligations, each checked from the rules' terms
(`engine.Contains`, `MayMeet`, `AlwaysDominates`), with a probe of every way the rules can be
told apart as its witness:

- **A bit is sent only where every command it reaches is decided by one rule of the grant**:
  held by a permit, or by a deny, which is then sent. Under `local_user_name` the template's
  class carries every bit of the level, so each must be; otherwise the grant goes narrow.
  Every baseline command no permit holds is denied on the wire.
- **A permit goes out as an allow only where it dominates every deny it meets**, since on the
  device the allow beats them all; one that does not is the refused shape, named with both
  rules. And only within the level's ceiling bits, a carve-out counted: a permit beyond them is
  not sent, so the device refuses what port49 would permit there — narrower, which fails
  closed, and reported.
- **A deny is left off the wire only where a measured carve-out of a bit not sent holds every
  command it matches**, and no allow meets it. No other bit boundary licenses it.
- **Bits that enter configuration mode** (a reach holding `configure`: `configure`, `all`)
  **are sent, and an allow meeting `configure` is sent, only for a grant of every command with
  no deny.** A statement typed there is governed by the class's configuration permissions,
  which no command regex reaches, so port49 could deny what the device runs. Under
  `user_permissions` such a composition is rendered again without those bits, and sent that way
  where the rest proves sound (decision 26, an admin composition with a deny); otherwise it gets the fail-closed
  reply.
- **The narrow shape's bits are the smallest set that reaches its allows**, preferring bits
  that do not enter configuration mode, so a narrow admin grant is not refused for `all`.
- **A rule whose text carries a value redaction hides is never projected**: the reply is written
  whole to the `authorize_session` record and the blob event (§5.7, §5.8).

**Junos matches keywords only** (decision 27; `tests/lab/results/L12-juniper_*.md`,
`L9-juniper_*.md`, both images). A `deny-commands` or `allow-commands` regex is matched against
a command's keywords as the CLI expands them, never its arguments: `^show interfaces fxp0(
.*)?$` did not refuse `show interfaces fxp0 terse` or `sh int fxp0 terse`, while `^show version(
*\|.*)?$` refused `show version`, `sh ver` and `show version | no-more`. port49 has no Junos
grammar, so the projection proves each rule against the set's **keyword tree**, captured in the
lab on every image the set measures (L26) and shipped as data
(`platforms/keywords/<set>/juniper_junos.yaml`), never set by a `platforms:` block. A rule is
keyword-only where its terms are words, optionally ending in `**`, and each word is a keyword
the tree lists at its place; a `*`, an entity class, a regex, and any word the tree does not
list there name an argument. A keyword-only deny is sent as written: the device refuses every
command whose keywords begin with it, which is at least what port49 denies. **A deny that names
an argument and meets a permit is one port49 needs enforced and the device never does**: that
subject gets the fail-closed reply (`argument_deny`), and `policy test` and `policy diff` fail,
naming the word and the whole command to deny instead — "Junos can't deny by argument: `fxp0`
in `deny show interfaces fxp0`; deny the whole command (`show interfaces`) or drop the rule".
port49 never widens a deny itself. **An allow is sent only where the device runs exactly what
port49 permits under it**: keyword-only, and no argument may be typed among its words (the tree
records where one may), since `allow show interfaces terse` would also run `show interfaces fxp0
terse`. Any other allow is left off the wire, so the device refuses what port49 permits there,
and `policy test` warns (`projection_argument_allow`). A keyword on one image only is not
proven, and a command path the capture did not reach proves nothing: both fail closed. **A word is
a keyword only on positive evidence**: the CLI offers it by completion at that place, and its own
`| display xml rpc` shows it a keyword (an element named as the word and no element holding it as
text, or a path still asking for a `<command>`). No RPC, an error asking for anything else, the
word as text, and a timeout all make it an argument, so a value under a command with no RPC
(`monitor traffic interface fxp0`) or under one that still needs an argument (`ping
routing-instance mgmt_junos`) is never proven a keyword. The capture runs nothing that acts or
streams: it walks only under `show`, after proving the pipe shows the RPC and runs nothing, so in
set 1.1.0 no word under another top-level command is proven. **The tree holds for the images it was
captured on** (vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15); on another release or hardware family
a word it proves a keyword may take an argument there, and a keyword deny would fail open. A hidden
argument, one completion never lists, is invisible to the capture. A new
capture ships in a new set, and the diff gates the pin move like any adapter edit.

**`deny-commands` never reaches configuration mode** (`tests/lab/results/L12-configuration-juniper_*.md`,
both images): in a class holding `configure`, `system` and `system-control`, `set system host-name
srx1` ran in configuration mode under `deny-commands=^set system host-name( .*)?$`, as in the
control. So no reply that lets the session enter configuration mode carries a deny (the
configuration-mode obligation below), and a deny that meets a permit, begins with a configuration
verb (`set`, `delete`, `edit`, `activate`, …) and is not an operational command the keyword tree
proves fails closed as `configuration_deny`, with a message saying so. `deny-configuration` is not
measured over the wire and not sent.

**A wire deny binds the CLI, never a native RPC** (`tests/lab/results/L12-netconf-juniper_*.md`,
`L26c-juniper_*.md`, both images). The token that opens the CLI opens NETCONF with the same
reply, and there a native RPC ran past every wire deny (`<get-configuration>` past `deny show
configuration **`); only a `<command>` RPC was refused. So a projected Junos device must run no
management service but the CLI's, checked as an allowlist: `devices check-config` passes it only
where nothing under `system services` is on but `ssh` and `telnet`, an unknown service included,
and `rest`, `web-management` and `extension-service` appear nowhere, reading only `show
configuration | display set | display inheritance | except "^set groups "` and refusing any
other input. That rules out NETCONF, the XML API (`xnm-ssh`, `xnm-ssl`, `xnm-clear-text`), REST,
J-Web, JET/gRPC/gNMI and `outbound-ssh`, outright, since Junos cannot turn them off per user.

That is necessary, not sufficient. From a projected CLI session, `xml-mode netconf
need-trailer` returns a NETCONF hello and a native RPC (`<get-software-information/>`) runs
past the wire denies, and `op url` is accepted. There RPC reach is the permission bits': `view`
without `view-configuration` got an empty `<configuration>`. `start shell` is refused by the
bits unless a shell permission is held, and the fail-closed reply's `deny-commands .*` refuses
`xml-mode` and `op` both (L26c). A wire deny does bind a `<command>…</command>` RPC: over NETCONF
the deny session refused one the control ran (L12-netconf). So
**a deny beneath a sent bit is not a boundary**, and in set 1.1.0 port49 fails closed on it
(`JunosFacts.DenyBindsRPCs` false). A composition whose only guard beneath a sent bit, or
beneath the baseline every session holds, is a wire deny is CLI-only safe: the capability shape
falls to the narrow one, whose `.*` refuses both entry points, and where that cannot carry it the
subject gets the fail-closed reply (`refused_shape`, its message naming RPC reach). A narrow
allow that would run `xml-mode` or `op` is refused the same way, and the fail-closed reply leaves
it off. What stays projectable: a deny no sent bit reaches, a bit a deny aligns with (dropped,
not denied), and the one carve-out measured over RPC, `view-configuration`'s `show configuration
**` out of `view` (the empty `<configuration>`). Every other carve-out is measured on the CLI at
most, so a deny it would cover is sent, and fails closed where it lies beneath a sent bit. Denying the entry points themselves, `xml-mode` and `op`, is future work
pending measurement on production devices; `start` is never denied, since admins need `start
shell` and the bits already refuse it.

What the regexes rest on is the device's regex dialect, measured by L9 and read into
`JunosFacts`: explicit `^` and `$` anchors on every regex; a deny's letters in lower case, since
the CLI refuses a keyword typed in upper case itself (`CaseSensitive` false;
`tests/lab/results/L9-juniper_*.md`); and a keyword deny narrower than `.*`, since on both images
every abbreviation of one, at several lengths and depths, piped and ambiguous, was refused or not
run under it while the control ran it (`DenyMatchesExpanded` true, which is about keyword
abbreviations only: arguments are never matched; `L9-abbreviations-juniper_*.md`). A projection
with no measurement gets the zero facts, which fail closed: a deny's letters in both cases
(`[sS][hH][oO][wW]`), and no deny but `.*`. A deny is written `^ *show +configuration( .*)?
*(\|.*)?$`, spaces allowed before and between its words and a pipe tail after, since the engine
strips a pipeline before matching and a deny anchored at its rule's last word would miss `clear
bgp all | no-more`; both images enforced that shape, plain and piped
(`L9-abbreviations-juniper_*.md`). The ERE's handling of arguments — a run of
spaces, an argument that may hold a space — no longer decides anything: a rule that names an
argument never reaches the wire (decision 27). A word is ASCII, carries no `{`, `}`, `"` or `\`, and escapes ERE's
operators; a regex or class pattern is carried only in the subset of RE2 that reads the same in
POSIX ERE (literals, bracket expressions, `.`, grouping, alternation, `*`, `+`, `?`, a repeat
of at most 8 written out, anchors at its ends), never as an empty group or alternative, and
anything else is refused. Every attribute is sent mandatory, once, and within RFC 8907's 255
bytes including its name; past that the subject gets the fail-closed reply, and for
`deny-commands` `policy test` prints the class line that would carry the denies on the device
instead, binding every subject at that template (`projection_overflow`). An allow is never
moved into a class: a class `allow-commands` runs for every subject at that template, past
their own denies (L11). A role or grant may not set an attribute the projection renders, in any
case or numbered variant the device reads (`allow-commands2`, `User-Permissions`), on a
projected platform or under `all` where one is. Each composition's shape, bits, what each regex
carries, what the bits refuse and what is beyond them is reported (`projection`), a
composition that gets the fail-closed reply is reported by subject, device and reason
(`projection_refused`), and `policy diff` reports a composition whose shape or bits moved
(§12). A composition is projected once per policy however many devices it lands on: 1,000
SRXs and 20 subjects load in about 0.2 s (`TestProjectionLoadTime`, bound 2 s).

#### Generator constraints

None of these are caught by the device. All MUST be enforced at policy load, where each
composition is projected:

1. **One instance per attribute name.** Duplicates are silently discarded after the first.
2. **240 bytes for a wire attribute**, enforced in the encoder — the one-octet argument length
   makes it a protocol impossibility rather than a policy choice, so an over-length argument
   is never emitted at all.
3. **Never emit `allow-commands` together with `allow-commands-regexps`.**
4. **Never emit a permit broader than its intended grant.** An over-broad permit silently
   voids the entire deny baseline beneath it.
5. **Never emit a partial or unproven reply, and say so loudly before it ships**, never
   silently at session time. A server that skips an attribute at session time produces a
   fail-open shape. A composition the projection cannot carry — over budget, the refused shape,
   or any other cause below — is not a policy the daemon refuses: CI refuses it (`policy test`
   and `policy diff` exit non-zero, naming the subject, the device and why), and a daemon that
   loads it answers that subject alone with the fail-closed reply (decision 26).
6. **Never emit an attribute a role or grant also sets.** The projection renders the template,
   the bits and the regexes; a hand-written one beside it is a second instance (1), and over it
   a regex nothing proved (4). Refused at load (plan 5b).
7. **Beside the projection, only an inert attribute.** Under a projected platform's key, a role
   or grant attribute is taken only where the adapter lists its name, as written, in
   `inert_attributes`: `shell:*`, a name the platform does not document, and a numbered or
   case variant are refused at load, since whether the device reads one is unmeasured. Under
   `all`, the same holds for each projected platform a device in the inventory has, save
   `idletime` and `timeout`: those are not sent there, since the device's idle limit is its
   login class's (decision 21), and `policy test` notes it. Spec §6's example
   (`all: ["idletime*30", "timeout*480"]`) loads on a projected set.
8. **Never emit a regex that names an argument.** Junos matches keywords only (decision 27), so
   a deny naming an argument is never enforced and an allow naming one never matches. A deny
   goes on the wire only where the set's keyword tree proves it keyword-only, and an allow only
   where it also proves no argument may be typed among its words. A deny that names an argument
   and meets a permit fails closed for that subject and fails CI; an allow is left off and
   warned about.

A composition the projection cannot tell the device faithfully — the refused shape, bits that
enter configuration mode where they cannot be dropped, an attribute past the budget, a rule it
cannot write, a rule redaction hides, a deny that names an argument (decision 27), or a reply
its witness finds unsound — is not a joint
check (§13, decision 26). That subject alone gets the **fail-closed reply**: `deny-commands`
`^.*$`, an allow for each permit that is within the level's ceiling bits that do not enter
configuration mode, dominates every deny it meets, does not meet `configure` and can be
written, and, where a deny binds no RPC, does not run `xml-mode` or `op`, and no other bit or template — under `user_permissions` the smallest of those bits
that reach the allows, under `local_user_name` no `local-user-name`, so the session lands in
the bitless `p49-remote`. Where the allows cannot go out whole none does. The reply is proven
as any other. The session is recorded `projection_fail_closed` (§5.7), and `policy test` and
`policy diff` exit non-zero on it, naming the subject, the device and why (§8, "CI MUST refuse
the policy"). **Operator note:** on set 1.1.0 a composition with a deny beneath a permit — the
realistic readonly with its `show configuration` deny included — gets the fail-closed reply on
Junos (the refused shape, and a deny beneath a bit binding no RPC, above); everyone else on the
device keeps working, and CI names each such subject before it ships.

**Blast radius.** A projection port49 cannot carry fails closed for the one subject it
belongs to (decision 26). A device whose template classes drift from the reference, or that
lacks them, can still lock out every user authenticating against it at once: a missing
template lands every session in `remote`. Lockout is fail-closed, but deployments MUST have a
break-glass path independent of TACACS attributes — a local account or console access (design
document §4).

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

**The reference classes are exported.** `port49 platform export --classes --config
port49d.yaml PLATFORM` prints, as `set` lines, the configuration a projected platform's
replies rest on: the adapter's `device_config` (on Junos `tacplus-options
strict-authorization`), the `remote` template user in the bitless class `p49-remote`, and under
`local_user_name` each level's template user and class with the level's bits, one per line as
`show configuration | display set` prints them. Each template class and user is written as a
replace — a `delete` before its `set` lines — so loading it clears what a device carried
directly under one: a class `allow-commands`, or a template user's local password. A replace does
not clear what reaches a template from above — a configuration group applied at a higher level,
or a deactivated or protected ancestor — so the export does not prove the template;
`devices check-config` does, and fails on each of those. No template user is
one that can log in locally: Juniper documents a template user as one with no authentication,
and L12 measures whether it refuses a local login; the reference adds a locked
`authentication encrypted-password "*"` only if that measurement finds it does not. Every class
carries `idle-timeout` from `session.max_session_age_default`, in whole minutes rounded down
(decision 21); the file is parsed strictly, as the daemon parses it, but only that key is used
and no key or secret is read, so none is needed to run it.
`port49 devices check-config --config port49d.yaml` holds a device to it (§12).

**Importing existing configuration.** Simple alternations of prefix patterns convert to
token rules mechanically; arbitrary regex does not. A migration tool MUST convert what it can
and **flag the remainder for human review rather than approximating**, because a
mistranslated deny is precisely the failure a migration must not introduce.

### User-editable, day one

Operators MUST be able to define and override platforms without an upstream change. A fleet
containing Supermicro BMCs, Meinberg time servers, and HPE gear cannot wait on releases —
that is the ticket-queue bottleneck the design exists to remove.

Built-ins ship embedded in the binary; an operator's blocks live in the policy file, under
its `platforms:` key, and merge over them per top-level key. A key whose value is a map —
`privilege`, `ceiling_levels`, `entity_classes` — merges per entry, so a block that adds one
class keeps the rest; a list or a value replaces the built-in's whole; `redact` adds and never
removes (§5.8); `unreachable` and `fallback` add and never remove what the set measured (§12):

```yaml
# in the policy file — adds one class, inherits everything else
platforms:
  arista_eos:
    entity_classes:
      uplink: ['^Ethernet(49|50|51|52)$']
```

`replace: true` on a platform block discards the built-in and starts from the generic adapter
(below), save what the set measured about the device, which the block must restate (below). `based_on:` declares a variant of a platform the pinned set ships, under a new name,
using the same vocabulary as `parent:` on privilege levels; a name the set does not ship starts
from the generic adapter. What port49d reads off the wire — `session_services`, the exec
records' commands and the system users — is still keyed by the platform's name until plan 6
carries it to a variant, so a variant would get an unknown platform's; `based_on:` a platform
whose facts differ from those — `juniper_junos`, whose sessions arrive as `junos-exec` and whose
exec records carry `cmd=login` — is refused at load, naming them (final review M8). A variant
of a platform whose only such fact is its session discriminator loads: without one the daemon
binds a record by username alone, the safe direction (§5.8).

```yaml
  whitebox_nos:
    based_on: arista_eos
    entity_classes:
      management: ['^ma1$']
```

The blocks are in the policy file, not a file beside it, so `port49 policy test` and `policy
diff` read exactly what the broker renders from, and a block goes through the same review.
They receive identical structural validation to shipped ones: required fields, attribute
syntax, the 255-byte limit, entity-class patterns compiling under RE2, a rendering the platform
accepts (`accepted_attributes`), and `enable_username` (§7). A block may not claim `verified`,
may not list inert an attribute one of its levels renders — that attribute is the level (§6)
— and may not be named `all` or `default`, which name every platform in `attributes:` and in
the redaction table. An explicitly empty `accepted_attributes: []` is refused, on any adapter:
the joint check would read it as "accept nothing" and a blob, which omits an empty list, as
"accept anything"; list the names, or remove the key.

A block's merged adapter renders **monotone** in the policy's `privilege_levels` order, by value,
because the reply gate lets a level's rendering go down only where its values did (§12): for
every two levels it renders or numbers, the lower one's `priv-lvl` (or `ceiling_levels` number)
is no higher than the higher one's, every attribute the lower one renders the higher one renders
too, and where their values differ the lower one's ranks below the higher one's in `role_order`
— an unranked value ranks above every value, so a higher level may render one and a lower level
may not. A block may add values to a `role_order` the set ships, anywhere in it, and may not
rank two values the set ranks the other way round — under `replace: true` and `based_on:`
included, since the device behind the name is the same device and the set's ranking is its lab
note's.

The rest of what the set measured about a device is likewise a floor or a ceiling a block only
tightens, for a platform the set ships and for a `based_on:` variant of one, `replace: true`
included; a block that would loosen one is refused at load, naming the key:

- `privilege_attributes` is a floor: a block may add a name and never remove one the set lists.
- `inert_attributes` is a ceiling: a block may drop a name and never list one the set does not
  hold inert (final review M5). A name the set lists in neither list bears privilege there, and
  one it holds bearing — `home-directory`, `idletime` and `timeout` on `cisco_iosxe` (§6) — is
  bearing for a reason; `replace: true` on `cisco_iosxe` restates `inert_attributes: []`, or it
  inherits the generic adapter's `home-directory` and the load fails.
- `accepted_attributes` is a ceiling: a block may narrow it and never widen or drop it, so
  `replace: true` on `cisco_iosxe` restates `[priv-lvl]` or the load fails — the device refuses
  the session for any other name and then stops answering SSH (L18).
- `supports` is a ceiling: a capability the set did not measure would make a rule read as
  enforced where the device never asks (§9).
- `pipe_authorized` and `expands_abbreviations` may not be set `true` where the set measured
  `false`, and `splits_interface_names` and `strip_cr` may not be set `false` where it measured
  `true`: each would let a command past a deny, or claim a rule the device does not enforce.
- `pipe_token` must equal the set's: the token cuts a command into stages before any rule reads
  it, so another one splits a deny's vector apart — `pipe_token: running-config` on
  `arista_eos` would let `copy running-config tftp:x` past `deny copy running-config **` — and
  there is no tighter value. With `supports`, these are every field of the normalization a blob
  carries (§5.1.2).

And on every block, a new platform's included, `inert_attributes` may not name an attribute any
shipped adapter lists in `privilege_attributes`: listed inert, a later change to it would pass
the diff ungated and take a placeholder, so one reviewed edit would blind the gate to it for
good. A `privilege` or `ceiling_levels` entry for a level `privilege_levels` does not declare is
refused by name: it renders nothing, and reads as a change.
A class pattern a deny names may not turn case-insensitivity off (`(?-i)`), on any platform: a
differently-cased interface name would walk past the deny (§4).

Four adapter fields are the daemon's rather than the policy's — `session_services`,
`session_discriminator`, `exec_commands` and `system_users` are read on the wire, including by
a daemon with no policy — and stay built in, `session_services` settable in `port49d.yaml` as
before, until plan 6's bundle carries adapters to the daemon. `enable_username` moved the other
way in plan 5, to the policy file, where the offline tools see it: `port49d.yaml` still loads
`principal`, the only value it ever took, with a notice saying where the key went, and
refuses any other value by name.

### Knowing what is shipped

Embedded definitions must not be opaque.

**They are files.** Sources live at `platforms/*.yaml` in the repository — browsable and
diffable across tags without running anything.

**They are introspectable**, and honest about verification:

```
$ port49 platform list --policy policy.yaml --inventory inventory.yaml
PLATFORM           SOURCE       VERIFIED       SUPPORTS
arista_eos         overridden   —              session,commands
cisco_iosxe        built-in     containerlab   session,commands
cisco_nxos         built-in     containerlab   session,commands
juniper_junos      built-in     —              session
meinberg_lantime   local        —              session
whitebox_nos       variant      —              session,commands
```

(`containerlab` where `tests/lab/results/L22-<platform>.md` shows the adapter's replies
applied as it says; the 2026-09 lab run is plan 5a's Task 17.)

A community-contributed adapter nobody has run against a real image MUST say so rather than
appearing identical to one verified on every commit, and so must a built-in adapter a block
changed: SOURCE says `overridden`, `variant` or `local`, and VERIFIED `—`. `platform show
<name>` prints a definition — the built-in, or with `--policy` the merged result — headed by
where it came from and followed by the built-in redaction patterns; `platform export <name>`
prints the file alone, as a block that pastes back into a policy — without `verified`, which a
block may not claim — and `platform export --all --dir DIR` writes one per platform, a
directory `platforms/` would accept. A set carries only
what the lab measured, so `--all` writes each `fallback` as the set measured it and drops a
block's note; `export <name>` writes the note under `fallback`, where the block wrote it, with
the comment `# operator note, not measured` on its line (§12). A block's `unreachable` rules the
set did not measure go the same way: `show` prints them apart as `unreachable_note`, `export
<name>` writes them back under `unreachable` commented `# operator-listed, not measured`, and
`--all` drops them (task 14 review M7).

**Published documentation is generated from the embedded files** at release time, so it
cannot drift from the binary.

**And the platform set is pinned.** If `arista_eos.privilege.admin` gains an attribute in a
release, upgrading the binary silently changes what every EOS admin session receives — a
**binary upgrade becomes an unreviewed policy change**. Policy therefore pins a version:

```yaml
platform_set: 1.0.0
```

The sets are directories, `platforms/<version>/`, and a released one is never edited; nor is
the generic adapter each set's files are laid over, which a `replace:` block and a platform no
set ships start from — a change to either ships as a new set. **A set that projects a
platform ships only if the device's commit checker takes every wire regex shape the projection
renders** (§8, "The device validates configuration but not wire attributes"; L9): if it rejects
one, that set ships Junos unprojected, which fails closed, rather than send a regex the device
may ignore or read otherwise. **A
policy that pins none renders with 1.0.0, the first set, on every binary** — so a policy
written before pinning existed never changes on upgrade, and moves forward only by pinning a
newer set. A set the binary does not ship is refused at load, by name. Upgrading the binary
changes nothing about rendering. It can change two things the pin does not hold. The first is
the four daemon fields above (`session_services`, `session_discriminator`, `exec_commands` and
`system_users`). They are built in and in no set, so they are unpinned until plan 6. A release
that changes `system_users` changes how accounting is attributed, and its release notes MUST
say so. The second is the redaction patterns (§5.8), which are unpinned by design.
`port49 platform upgrade --to V` moves the pin (with
`--write`, in the file, touching nothing else) and reports exactly what changes:

```
platform_set 1.0.0 -> 1.1.0
  platforms.arista_eos.privilege
    {"admin":["priv-lvl=15","roles=network-admin"],...} -> {...}
    affects 4412 devices, 6 subjects
    gated: add {platform: arista_eos, field: privilege, sha256: <64 hex digits>, reason: "..."} under acknowledge:
  generic.strip_cr
    true -> false
    affects 3 devices, 1 subjects
    gated: add {platform: generic, field: strip_cr, sha256: <64 hex digits>, reason: "..."} under acknowledge:
  shadowed: platforms.arista_eos.entity_classes: set 1.1.0 changes the built-in value and the policy's block keeps its own; compare the two
  port49 policy diff fails on the move until every gated entry above is under acknowledge: (spec §12); it also shows the replies the move changes
```

Every gated key the move changes, the generic adapter's included (§12), is printed with the
`acknowledge:` entry that clears it, ready to paste: the change that moves the pin carries them.

`port49 policy diff` on the file before and after is the gate: a pin move is an adapter edit
like any other (§12). CI also reports override drift — `platform_override_redundant`, a block
key that says what the pinned set already says and can be removed; and at upgrade, a built-in
change a block shadows — so local platform files do not rot silently as upstream improves.

**`port49 platform export <name>`** emits a file suitable for an upstream pull request:
written for one fleet on day one, contributed once proven. An upstream set takes measured text
only: a `fallback` line commented `# operator note, not measured`, or an `unreachable` rule
commented `# operator-listed, not measured`, is the operator's word, and is measured in the lab,
or removed, before the file is contributed.

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

**As built (plan 5b).** `port49 devices capabilities --policy FILE --inventory FILE [--since
DURATION] LOGFILE...` reads the decision log a daemon wrote (`-` for stdin) and prints, per
inventory device, its admission, what its adapter declares under `supports`, and what the log
shows it asked: `session` for an `authorize_session` record, `commands` for an
`authorize_command`, `config_commands` for an authorization request that followed a permitted
configuration entry (`configure …`) in the same context. `--since` bounds the window by the
newest record's time, never the wall clock. An admitted device with no record in the window
is noted **never seen** and exits 0: in a day's window every device nobody logged into is one,
and a job that pages on them is one nobody reads. It warns — and exits 1, for a job to page on
— on a contradiction between what a device declares and what it did:

- **config-commands probably off**: on a `commands` platform, at least 5 permitted configuration
  entries in the window and at least 80% of them followed by no authorization request in their
  context before the session's exec STOP or the window's end. An entry followed only by exec
  commands is read as followed, so the inference under-reports rather than accuses;
- **an unauthorized tier**: on a `commands` platform, command accounting records of contexts
  port49 authenticated (`attribution: resolved`) whose command text holds no authorized command
  of the same context. Holding, not equality, is the join, because NX-OS's accounting `cmd` is
  the configuration path joined with ` ; ` and a result (L21), so a shape the join does not
  expect reads as authorized. Printed as spec §9's block, with the device's unattributed, foreign
  and system counts beside it.

A capability observed that the adapter does not declare is a note, never a warning: it is a lab
measurement waiting to be made. The window's `account_gap` records (§5.7) qualify the whole
report: with any, it says so on its first line, an unauthorized tier is printed as possible, not
found, and does not set the exit code. CI's half is `report: unenforced_rules`: a subject whose
roles carry command rules on a platform that neither authorizes commands nor projects them —
Junos under set 1.0.0 — is told they decide nothing there.

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
  platform_set   1.0.0, as pinned by the policy repository
```

**A sync can make a valid policy invalid, and the bundle builder quarantines rather than
refuses.** Several load checks are joint over policy and inventory — a privilege level with no
mapping on a platform present in inventory (§6), a session reply whose `priv-lvl`, or any
other attribute that bears privilege there, exceeds the grants' `max_privilege` (§7), roles
landing above the ceiling's level (§7), `enable: auto` reaching a platform whose enable exchange
carries no principal (§5.6). A composition the Junos projection cannot carry is not one of
them: it gets that subject alone the fail-closed reply and never quarantines the device (§8;
§13, decision 26). A device racked tomorrow with a new platform can
fail them against a policy that was valid today. Refusing the whole bundle would block every
inventory change fleet-wide until someone edits policy, including the leaf racked in another
site — a ticket-queue bottleneck created by the safety mechanism. Instead the offending
device is published with `admission: quarantined` and the reason; the daemon logs
`device_quarantined` (§5.7), the alarm names it, CI reports the same list against the policy
change that would clear it, and `port49 devices capabilities` shows it. The rest of the fleet
moves.

A joint check that no platform could pass is the policy's own error, not a device's: a class
no platform defines, or a `max_privilege` no platform can number, refuses the policy at load.
One that fails for some platforms quarantines the devices on them. Until the inventory service
publishes bundles (plan 6), `port49d` applies quarantine when it loads the policy: each
quarantined device is logged at start with its cause, its mints are refused
`device_quarantined`, and its connections are closed without a reply (plan 4).

**A quarantined device gets silence, not FAIL.** The daemon closes the connection without a
reply, exactly as for `device_unknown`. The device then declares the server dead and falls to
its local method, which is the posture every platform documents for a port49 outage and the
one the reference AAA configuration and the runbook already cover. Answering FAIL would be a
new posture: the device believes AAA is healthy and refuses everyone, and only Junos with
`password` listed then tries local (§15, L4; `tests/lab/results/L4-*.md`). The close was
measured on vEOS, the N9Kv, IOS-XE and vJunos-router on 2026-09-24: it costs the device what a
refused connection does — break-glass logs in and runs its commands, a command in a session
already open runs on the local fall-through, and nothing waits out a silent server's
timeout; IOS-XE still asks per command and is told no at once, about 0.27s
(`tests/lab/results/quarantine-*.md`). Quarantine means port49 cannot compute a
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
platform_set: 1.0.0

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
  - {name: dc_fabric,   match: {site: [dc1, dc2], role: [leaf, spine]}, on_missing: exclude}
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
     username: svc-config-backup, enable: token, token_ttl: 900s}

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
  - {subject: svc_oxidized, device: leaf-01, level: admin}  # a session test
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

**Policy tests** run in CI against a file-backed inventory, as in §11. A test names a
`subject` (or a `principal`) and a `device`, and asserts one or both of:

- **a command:** `command:` with `expect: permit` or `deny`, and optionally the `reason:`;
- **the session:** `level:`, the level the subject's roles compose to on that device;
  `max_privilege:`, the ceiling its grants compose to there (`none` for no ceiling);
  `priv_lvl:`, the device privilege the session lands at — the `priv-lvl` the session reply
  sends after §6 layering, or, where it sends none, the number the platform gives the level
  (`none` where neither says); `enable:`, the subject's escalation mechanism (`none`,
  `auto` or `token`); and `reply:`, the exact session reply as a list, in order, with the
  placeholders empty (`[]` for none); and `api:`, the subject's broker API rights, which a test
  may assert alone, on any device, since they do not depend on one. A test with no `command:` is a session test and takes no `expect:`; it
  passes only where the subject would be minted a token for the device, with every value it
  names.

A session test is what acknowledges a privilege raise to the gate below.

**A policy with no tests passes `port49 policy test`, and says so:** it prints `report:
no_tests: ...` (owner's ruling 2026-09-24). Nothing in such a file acknowledges a shadowed deny
or an expansion, so the gates below fail on the first one; the line is there so a reviewer
sees an empty test list before that happens rather than after.

**Intersection checks.** Because the effective permission set is the intersection of what
the device offers and what port49 permits (§6), CI MUST report where the two disagree. Neither of these is visible in any existing TACACS+
system, and both are ordinary review questions once surfaced:

```
report: dead_rule: role "interface_tech": permit "configure terminal" cannot be reached at
  readonly (priv-lvl=1, roles=network-operator) on arista_eos: the device refuses every command
  it matches in its own parser and never asks port49 (unreachable: clear counters **, clear ip
  bgp **, configure terminal **, show users detail **; tests/lab/results/ceiling-arista_eos.md)

report: fallback_exposure: subject "svc_oxidized" at admin (priv-lvl=15, roles=network-admin)
  on arista_eos: port49's rules confine it to show **, terminal length *, and if port49 cannot
  answer and the device falls back to local it gets network-admin, of the commands measured:
  clear counters ran, clear ip bgp * passed authorization (BGP inactive on the lab node),
  configuration changed: more than the policy grants (spec §6, §12)
```

Both read the adapter (§8), and only what the lab measured. A **dead rule** is a permit every
command of which is in the adapter's `unreachable` list for the level the session renders at:
the commands the device refused in its parser at that level with port49 permitting everything
(`tests/lab/results/ceiling-*.md`). A **fallback exposure** is a subject whose composed rules
deny something, at a level whose adapter `fallback` says what the device gives a session on its
own when the method list falls back to `local`. The level is the one the reply *delivers*, not
the one the roles name: the lowest level, from the session's own up, whose rendering the reply
does not exceed as the ceiling check reads it (§7), so a readonly role that sends
`shell:roles*network-admin` is exposed as admin is (final review I1): `network-admin` at admin on EOS and NX-OS,
and on EOS `network-operator` at operator. `operator` gets readonly's role for this reason (§6), so it never gets
configuration where its device role binds. L16 measured that `network-operator` under LOCAL
command authorization refuses configuration. L22 measured what else it runs with port49d
stopped under an open session (`tests/lab/results/L22-*.md`):
- On vEOS it still ran `clear counters`, and `clear ip bgp *` passed authorization (`% BGP
  inactive`: the lab node runs no BGP). That is operator's EOS entry, which names only the
  commands measured.
- On the N9Kv it was refused both (`% Permission denied for the role`).
- On IOS-XE, local authorization refused every command a token session typed, at 15 and at 7,
  because a token user had no local account. That holds on a device that passes `port49
  devices check-config`'s local-account check (§5.6). A local account named like a port49
  username would authorize from its own privilege. So IOS-XE has no entry.

The report has no exemption for `operator`. It judges every level by that level's adapter
`fallback` entry. A level with no entry is not reported. That silence is measured for IOS-XE
at 7 and 15 and for NX-OS's `clear` commands. It is unmeasured elsewhere, which is not the
same as safe.
A `platforms:` block adds to both and takes nothing away, `replace: true` and `based_on:`
included: its `unreachable` rules are kept apart from the set's for the level, as the
adapter's `unreachable_note`, and its `fallback` text as its `fallback_note`, both of which only
port49 writes and a block may not set (task 14 review M7). A permit the set's rules make dead
is reported citing the lab note, as above; one only the block's rules make dead is reported as
the block's word, `(operator-listed unreachable, not measured: ...)`, citing no note. The report prints the set's text, or `what no platform set measured` for
a level the set measured nothing for, and then the block's text as `(operator note:
"...")`, quoted, so nothing in it can close the note or read as a measurement. An entry for a
level the policy does not declare is refused. The rules and the set's text are printed
unquoted, so the report redacts them itself (§5.8), and fallback text is prose: punctuation
beside a word separates it as whitespace does, so a value glued to `community)` is still
redacted.
Each is reported by `port49 policy test` and does not fail it: the answer is a review question,
not a wrong policy.

**Projection reports.** On a projected platform `port49 policy test` reports each
composition's projection, and `policy diff` repeats the ones that fail it. The codes, a new one
added here before any code emits it:

| Code | What it says | Fails `policy test` / `policy diff` |
|---|---|---|
| `projection` | the shape, the bits or template, what each regex carries, what the bits refuse, what is beyond the level's bits (§8) | no |
| `projection_refused` | a composition that gets the fail-closed reply, with the subject, every device and the reason (decision 26); for `argument_deny`, "Junos can't deny by argument: `<word>` in `deny <rule>`; deny the whole command (`<keywords>`) or drop the rule", and for `configuration_deny`, that the deny names a configuration statement deny-commands never reaches (decision 27) | yes |
| `projection_overflow` | a reply attribute past RFC 8907's length, with the class line for an overflowing deny set only (§8) | yes |
| `projection_argument_allow` | a permit whose allow is left off because Junos would not match it as port49 does: it names an argument, or an argument may be typed among its words (decision 27); the device refuses what port49 permits there | no, a warning |

**Attribute shadowing.** Where a role or grant attribute overrides a platform attribute of
the same name (§6), CI MUST name both so the override is deliberate.

**`port49 devices check-config`** reads a device's configuration, as `show running-config`
prints it, against the policy's adapter for its platform, and exits non-zero on a device-local
account named as a username port49 serves on that device — the collision §5.6 forbids — or on a
line the adapter's `config_checks` name: a command method list falling back to `none` or
`if-authenticated` (§6), an enable list falling back to a local secret (§5.6), a Junos
`authentication-order` with `password` in it (L4) — or on a `device_config` line the
configuration does not carry as a top-level line of its own, the absence no `config_checks`
entry can see: IOS-XE's level-7 command method list, without which a level-7 command is never
asked about (§6). On a projected platform it also reads the configuration, as `show
configuration | display set` prints it, against the reference `platform export --classes`
writes, and `--config port49d.yaml`, the classes' idle-timeout, is required: a reference line
the device lacks, and any line under a template class or template user the reference does not
write — a class `allow-commands`, a permission, a template password — fails it, the uid Junos
assigns aside (§8). A `platforms:` block adds to the set's `device_config`, `local_accounts` and
`config_checks` and never takes one away, `replace: true` and `based_on:` included: a block
that rewrites the set's line ending in `local` to end in `none` still has the set's line
required and its own reported by the set's check. A device configuration is full of secrets,
so every line of it the check prints, and every `device_config` line, is redacted by every
pattern that applies under the policy (§5.8), and a text it could not read to the end fails
the check without quoting it. The patterns are best-effort, so the check echoes a line only
for a check a set ships, which reads a method list or an authentication order: a block's check
may match any line, and its finding names the check by key and index,
`platforms.arista_eos.config_checks[2]`, with its `says` redacted, never the line. A device-local
account collides in any form the daemon reads as the served username — `NOC`, `CORP\noc`,
`noc@corp`, a quoted name (§2) — and a Junos account under `protect:` or `inactive:` is read.
The check never reports a device clean when it looked for nothing (final review I4): where the
adapter in force, resolved as the daemon resolves it, the set's generic adapter for a platform
with none included, has no `local_accounts`, `device_config` or `config_checks`, it exits 2,
`nothing checked: <platform> has no config checks`; where it lacks only `local_accounts`, or
only the lines, it says which was not checked beside the summary. port49 never logs into a
device; this reads a file a compliance tool fetched.

**`port49 devices capabilities`** reports the `supports`-versus-`observed` matrix from §9.

**Shadowed-deny report.** Because a more specific permit can override a deny (§5.4), CI MUST
name every shadowed deny, the subject it fails to bind, and the permit that beats it. This is
what replaces the guarantee deny-overrides would have provided. A shadow is acknowledged by
a policy test (§11) for that subject that expects `permit` on a command where that permit wins
over that deny — §11's `security_ir` test is one. `port49 policy test` names every shadowed
deny and exits non-zero on one no test acknowledges. Where the overlap turns on two regex or
class terms at one position it cannot be decided cheaply, and the shadow is reported as
possible rather than failed.

**Privilege-expansion gate.** The check that matters under most-specific semantics is not
"did the permit set grow" but **"does this change make command C permitted where it was
denied"** — computable exactly from the trie. `port49 policy diff --old FILE --new FILE`
evaluates both policies, for every subject on every device, over every command shape their
rules distinguish — each word, `*`, `**`, and each deny word's abbreviations — and reports each
command whose decision changed, each level or ceiling that changed (a privilege change, §6),
and each device the new policy quarantines. It exits non-zero on a command a deny refused that
the new policy permits, unless a policy test in the new policy exercises that permit over that
deny, on a newly quarantined device, on a subject whose mint the new policy's broker refuses
(`attribute_too_long`, `attribute_unsafe`), since the diff, `policy test` and `explain` run the
broker's mint checks and answer as it does, and on every composition the new policy gives a
projection's fail-closed reply, new or not (§13, decision 26). `port49 policy test` exits
non-zero on a device quarantined now or at a later expiry and on every fail-closed
composition too: the daemon still serves the rest (decision 20), and CI ships neither (plan 5b
pre-flight I10); `port49 platform upgrade` previews both.

**A privilege raise fails the gate too** (owner's rulings 2026-09-24). The gate compares what
the device gets and what port49 enforces, not level names, for each subject on each device at
each instant. Any of these is a raise:

- **the device privilege rose** — the `priv-lvl` the session reply sends after role and grant
  `attributes:` layering, or where it sends none the number the platform gives the level, so a
  role or grant attribute `priv-lvl=15`, or a custom level's `parent:` moved up, is a raise;
- **the ceiling rose or went away** — by its number on the platform or by its place in
  `privilege_levels`;
- **the level rose** — later in `privilege_levels` under the old order *or* the new one, so a
  reordering that lifts a level is a raise even when the name did not change; a level one
  version does not declare counts as below every level it does;
- **`enable` was switched on** — from unset or `none` to `auto` or `token`, which lets the
  session escalate to its ceiling, or with none to anything;
- **the session reply gained, changed or lost a privilege-bearing attribute** — the whole
  rendered reply is compared (placeholders empty), so any change to it is at least a reported
  line, and one that adds, changes or removes an attribute other than `priv-lvl` (which the first
  item judges) is a raise unless that attribute is one the platform's adapter lists as inert
  (§6). `local-user-name` on Junos, `shell:roles` on NX-OS and `roles` on EOS each change what the
  device lets the session do (L16, L18), and on a session-only platform the reply is the only
  fence, so removing one widens access too: without `deny-commands` a Junos session loses its
  only refusal, and without `local-user-name` it falls back to the device's template user (owner's
  ruling 2026-09-24, review C4). The gate cannot read the direction of such a change, so it fails
  closed. **On a projected platform the projection's own attributes are judged by what the
  device can do under them** (plan 5b pre-flight I14): a reply under which the device holds a
  bit it did not, or runs a command it did not, among one command per way either reply's rules
  can be told apart, is a raise; one that only narrows — a revoked permit, an added deny — is
  not, whatever its regexes say, and needs no `reply:` test. The proof that the device runs
  nothing port49 denies (§8) is what makes the direction readable. A projection that went away
  is a raise. **A fail-closed reply (§13, decision 26) is a narrowing, never a raise**, though it
  drops `local-user-name` and lands the session in the bitless `p49-remote`: this overrides, for
  that reply, the rule above that losing `local-user-name` is a raise. It still fails the diff as
  a fail-closed composition (above). That it narrows rests on the device honouring
  `deny-commands=^.*$` over the bitless class, which L9 (anchors, a malformed regex) and L12
  (the baseline under `.*`) measure; until they close, the set-release rule (§8) is what holds it.

One change's direction the gate can read: a level's own rendering moving down `role_order`
(§8). Where an attribute is the old level's rendering in the old reply and the new level's in
the new reply, one value each, and the new value ranks strictly below the old one in
`role_order` under both versions' adapters, it is a lowering: a subject moved from admin to
readonly on EOS is lowered because `network-operator` ranks below `network-admin`
(L16-arista_eos.md, command authorization LOCAL), not because readonly is below admin. The
level order proves nothing about what is rendered — a custom level's parent can put a level
above one whose rendering is stronger — so it is never read here. An unranked value, a changed
separator, an attribute gained or lost, and any attribute a role or grant layers are judged as
above: a raise. Which attributes bear privilege is read from both versions' adapters, the
stricter winning, so an edit that lists an attribute inert cannot hide a change to it in the
same diff.

Each fails unless a passing session test in the new policy, at that instant, on a device of the
group reported, asserts the new value of every dimension that rose: `priv_lvl:` for the device
privilege, `max_privilege:` for the ceiling, `level:` for the level, `enable:` for the mechanism,
`reply:` — the exact attribute list, in order, placeholders empty — for the session reply.
The devices a raise is reported on hold the same blobs, levels, numbers, `enable` and reply, so a
test on any one of them is the assertion for all. A lowering is reported and does not fail.

**The gate also compares principals, not only subjects** (owner's ruling 2026-09-24, review C3):
a subject is a name, and who holds its access is its `identity:` list and what the device sees
is its `username:`. For every principal either version lists, the diff reports one that now
resolves to a subject it did not (added to a subject, or moved from another), and a subject whose
`username:` changed. Each fails the gate unless a passing session test naming that `principal:`
in the new policy asserts the access it resolves to; for a `username:` change, a session test
naming one of the subject's principals. A principal removed from every subject is reported and
does not fail. A subject's `group:` changing is reported; group subjects mint for no one until the
directory arrives (plan 7), and the gate on them is that plan's.

**A broker API right gained fails the gate** (owner's ruling 2026-09-24, review M6). A subject's
`api:` rights (§2) let it act on other people's sessions, so the diff compares them per subject,
and per principal where a principal moves to a subject with rights its old one lacked. A right
gained fails unless a passing test in the new policy asserts the subject's whole right list with
`api:` — naming the subject or one of its principals for a subject's gain, naming the principal
for a principal's. A right lost is reported and does not fail.

**A regex-constrained change fails the gate too** (owner's ruling 2026-09-24). Regex and class
terms are matched only against the words the rules name, so a rule that carries one and changed,
or a permit that carries one and meets a deny that changed, is reported as regex-constrained
rather than enumerated (§4) — and because the diff cannot see which commands moved, the author
has to show it. Each of these widenings fails unless it is acknowledged, on a device of the group
it is reported on, at the instant it is reported:

- a permit carrying a regex or class term that the new policy added — by a passing test that
  expects `permit` on a command that permit decides;
- a deny carrying one that the new policy removed or rewrote — by a passing test that expects
  `permit` on a command that deny refused in the old policy and the new one permits;
- a permit carrying one that meets a deny the new policy removed or rewrote — by a passing test
  that expects `permit` on a command that deny refused in the old policy and that permit decides
  in the new one, keyed to that (permit, deny) pair.

**A test expecting `deny` never acknowledges a widening:** it cannot tell a rewrite that narrowed
the deny from one that widened it (owner's ruling 2026-09-24, on review I1: `/^(wri|rel)/ **`
rewritten as `/^wri/ **` frees `reload`, and a test that `write erase` is still refused says
nothing about it). A deny rewritten wider has no command to flip, so it is acknowledged the only
other way, **by the author in writing**: a top-level entry naming the exact removed or rewritten
rule, with its role and a reason,

```yaml
acknowledge:
  - {role: guard, rule: "/^(wri|rel)/ **", reason: "rewritten wider as /^(wri|rel|rep)/"}
```

which acknowledges that rule's removal and every permit meeting it. The entry is keyed to the
removed rule's text, so it matches nothing once that rule is gone from the old policy too, and
cannot quietly cover a later change. **A stale entry acknowledges nothing and is reported,**
`report: acknowledge_stale`: by `policy test` where the rule it names is still in the policy (so
it removed nothing), and by `policy diff` where no widening in the diff is the one it names. `port49 policy test` prints every entry and `policy diff`
prints the entry beside the change it acknowledges, so review sees the reason. An entry with no
reason is refused at load.

The narrowings — such a permit removed, such a deny added, or a permit meeting a deny the change
added — are reported and do not fail.

**A newly refused mint fails the gate, and no test acknowledges it.** A subject the new policy's
broker refuses to mint for (`attribute_too_long`, `attribute_unsafe`) is locked out of every
device the refusal covers; a test cannot make that intended, so the change must fix the attribute
(owner's ruling 2026-09-24, confirming plan 4's behaviour).

**An adapter edit fails the gate** (review M8, 2026-09-24). Once an operator can edit an
adapter (§8), the diff compares each platform's adapter key by key, for every platform either
version has an adapter for, whether or not the inventory has a device of it yet — the inventory
is not diffed, so the day a device arrives is no review — and whether the change is a
`platforms:` block or a moved `platform_set`. It compares the **effective** adapter, after
`replace:` and `based_on:` have been merged, so a block cannot change a key by changing where
the key is inherited from. A version with no adapter for a platform has the generic one, whose
`supports` is compared as no claim at all: the generic `session` is assumed, not measured, and an
unmeasured platform is not session-only. So a block that says only what the generic adapter
says still shows as an edit to `supports`, which makes the platform session-only and turns off
abbreviation matching on its denies (task 9 review I2). **The generic adapter is compared too,
as platform `generic`,** whether or not any device stands on it: it is what every device of a
platform with no adapter receives, and what a `replace:` block or a new platform starts from, so a
moved pin that changes it is gated key by key like any platform's, and acknowledged by
`{platform: generic, field: ..., sha256: ..., reason: ...}`. `generic` is therefore reserved as a
block name (owner's ruling 2026-09-24).

**Every adapter key is gated, fail closed, unless it is on a closed list of report-only keys.**
A gated key fails unless an `acknowledge:` entry names the platform, the key and the sha256 of
the key's new value with a reason, `{platform: arista_eos, field: entity_classes, sha256: <64 hex
digits>, reason: ...}`: a diff cannot vouch for its own reading when the change is to the
reading. The digest is taken over the value as `policy diff` prints it (canonical JSON), and the
diff prints the entry ready to paste. It binds the entry to that one edit: left in the file, it
names a value a later edit to the key does not write, so it acknowledges nothing and is reported
`acknowledge_stale`, like a deny's entry once its rule is gone (task 9 review C1). A key a later plan adds is gated until it is added
to that list. The gated keys therefore include:

- `supports`, `privilege`, `ceiling_levels` and `entity_classes`.
- The normalization keys, which change the vector rules match against: `expands_abbreviations`,
  `splits_interface_names`, `strip_cr`, `pipe_token` and `pipe_authorized`.
- The rendering keys of session-only platforms, which decide what the device enforces:
  `command_projection`, `bits`, `bit_delivery`, `carve_outs` and `local_user_names`.
- The keys the gate reads: `privilege_attributes`, `inert_attributes` and
  `accepted_attributes`.
- `enable_username`, `shows_server_msg`, and `redact`, which changes what the audit keeps.
- `local_accounts` and `config_checks`: an edit to either can silence `devices check-config`,
  which is the only detection §5.6 names.
- `device_config`: it is the configuration a device is held to, so a block that rewrites a line
  ending in `local` to end in `none` has the device authorize every command itself whenever
  port49 is unreachable, and would have check-config require the unsafe line (task 7 review H6,
  2026-09-24).

The report-only keys are reported and never fail:

- `port_pattern`: drift detection only.
- `verified`: the adapter's claim about the lab. A block may not set it.
- `unreachable`, `unreachable_note`, `fallback` and `fallback_note`: they feed only the dead-rule and fallback-exposure reports,
  which do not fail `policy test` either. An edit to one is reported in the diff, where the
  reviewer sees it.

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
that deletes them all (`--pr` opens it: a branch off the base as the remote has it, carrying the
edit and nothing else, pushed, and the review opened with `gh`, leaving the operator's checkout
untouched; a policy file that differs from the base's is refused, since the removal would be
computed from a file the pull request does not merge into) — and, when no grant on the subject remains, the subject block itself,
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
the key needed from it: two concurrent N9Kv sessions both reported `0`, so two operators on one
device collided and locked each other out; and vEOS, which does give two concurrent sessions
different vtys (`vty4`, `vty6`) from session authorization onward, says `ssh` for both at the
authentication START that writes the context. (Corrected 2026-09-23: this sentence said both vEOS
sessions reported `vty4`; `tests/lab/results/L1-arista_eos.md` (2026-09-20, `alice05` `vty4` /
`alice06` `vty6`), and again in the 2026-09-22 run.) The exclusion of the username was bought to
serve `$enab{level}$`, which has now been measured *not* to apply on either platform that has an
enable exchange: vEOS and **IOS-XE**, the platform the spelling is named after, both put the
operator's own username on the enable START with `service=enable` (L3, 2026-09-20). So the thing
the exclusion was paid for has not been observed on any device in this lab.
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

*The accepted cost, stated plainly.* One user's concurrent sessions on one device share a context.
**Since 2026-09-23 a second login by the same principal joins it** (§5.6, the join table): the
`ctx_id`, the privilege already granted, the bound session discriminators and a revocation the new
token predates are kept, and the newest broker decision supplies the policy blob, the ceiling and
the enable mechanism. The overwrite this paragraph used to accept reset the stored privilege
(window A, enabled to 15, was then denied `privilege_exceeded`), emptied the discriminator set
(window A's STOP became `foreign`), and wiped `revoked_at` (a token minted before a revocation
re-admitted the user). **A join lifts `revoked_at` only when the broker minted the new token after
the revocation** — the credential verified again, which is the one thing that may; a refresh never
does (§5.1.3). A login whose token predates the revocation is refused `credential_revoked` (§5.6).
Another principal under the same username, or a context past `session_expires`, is
still replaced, and §5.6 requires the replace to be logged. A log reader still cannot tell two
shells apart by `ctx_id`; no wire field distinguishes them on every platform, so this is not fixable
by a better key.

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

**Superseded 2026-09-22.** Plan 2 builds neither the index nor the reason code. `$enab{level}$`
becomes an explicit `platforms.<name>.enable_username: enab` option that `config.Load`
**refuses** (moved to `platform.Validate`, in the policy file's `platforms:` block, in plan 5,
§8), with an error naming what would lift the refusal: a `tests/lab/results/` note
showing a device sending that username form. Until such a note exists, the `(nas, rem_addr)`
secondary index, its ambiguity refusal and the §5.7 row that refusal would need are all
**deferred** — §5.6's bound-attributes table and teardown row 4, and §7's "How an enable token is
found", stay as the design of record for the day one arrives, describing a path no shipped
configuration can reach.

One thing plan 2 and plan 4 both gain from that run, and it is not about enable. **IOS-XE refuses
an authorization reply carrying an attribute it does not recognise, even sent as OPTIONAL**: the
session port49 permitted is ended by the device with `% Authorization failed.` (§15, L10 and
L18; `tests/lab/results/L18-cisco_iosxe.md`). Whatever attribute set an adapter sends to that
platform has to be a set the image accepts, and when it is not, port49's own log says `permit`
while the operator is locked out — there is no diagnostic on this side at all.

*API transports: a sliding receipt, not a `reusable` flag. Ruled 2026-09-22.* The receipt is
the retry tolerance of §5.1.1: a spent token presented again within the receipt's life is
answered from the stored decision, `receipt_replayed`. It was a fixed window (`receipt_ttl`,
30 s). It is now a **sliding** one. Every re-presentation of the same
`(nas, username, credential_sha256)` that is answered from the receipt extends the receipt by
`receipt_idle_ttl` (default **15m**), up to `receipt_max_age` (default **2h**) measured from
the first redemption. A presentation past either bound is FAIL on the wire, exactly as a
wrong password is, and `token_spent` in the log (§5.7). Revoking a principal deletes their
receipts as well as their contexts, so receipts are indexed by principal (plan 2). Interactive
logins present the token once and never slide; only a client that re-presents the credential
does, and it needs no flag to do so.

*Why not a flag.* The owner's rule: an operator running automation should not need to know
whether their client library keeps a session. The lab measured that the authentication count
for a job belongs to the **client**, not the transport — for ten tasks, pyeapi 10, NAPALM
`eos` 11, Ansible `eos` over `httpapi` 13, NAPALM `nxos` 28, and 1 for anything over one SSH
session or for Ansible `nxos` over `httpapi`, which keeps the `nxapi_auth` cookie (L15,
`tests/lab/results/L7-*.md`). NAPALM `nxos` crossed the fixed 30 s window at 38.8 s and
tasks 5–9 failed `token_not_found` with nothing changed in the operator's hand. A `reusable`
flag would have pushed that fact about a library into policy.

*Why 15 minutes and 2 hours.* No single device operation sets the idle window; the gap
between two presentations on **one device** does. Ansible's linear strategy finishes each
task on every host before any host starts the next, so with a large fleet a device sits idle
for the whole fleet's pass between its own tasks, and Ansible's persistent connection closes
after 30 s of idle regardless. An image copy followed by a verify, or `reload` then
`wait_for_connection`, leave a device quiet for five to ten minutes. The cap stops a looping
script, or an attacker, from keeping a captured token alive indefinitely. Both are
configurable; neither is per subject.

*Cost.* A captured token works against one device, under one username, while the job that
spent it is active plus `receipt_idle_ttl`, never past `receipt_max_age`. That is wider than
the fixed 30 s and far narrower than a token valid for its whole TTL. The mitigation that
removes most of the exposure belongs to plan 3: an agent that mints a fresh token on every
reconnect makes the sliding window rarely reached.

*Withdrawn.* `reusable: true`, match-without-delete redemption, and the use-counter
discussion. The earlier proposal to key API contexts on `(nas, port, rem_addr)` was already
withdrawn: `port` is constant or empty across SSH sessions too, and `rem_addr` is identical
for two concurrent sessions behind one bastion, so under `(nas, username)` an API transport
needs no separate context key at all. The eAPI `/login` cookie flow was measured by hand
2026-09-23: one authentication at `/login`, none for a request carrying the cookie
(`tests/lab/results/L7-login-arista_eos.md`); NX-API's `nxapi_auth` cookie by hand 2026-09-24,
the same shape — one authentication per cookie session, none per request carrying it, the cookie
ending after 10 minutes idle (`tests/lab/results/L7-nxapi-cookie-cisco_nxos.md`). Still
unmeasured: HTTP keep-alive on its own, and a linear-strategy playbook run against the lab with a
deliberate gap, which is the measurement the 15-minute default should be checked against
(L7, L15).

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
(§5.6) *Plan 5b:* `port49 platform export --classes` renders the idle-timeout (§8); that it
ends an idle session is *provisional on L24*, which measures whether it does. Revocation
records naming contexts are plan 7's.

**22. Session-only projection is bits first, regexes second, chosen per grant, with one
shape refused.** *Provisional on L9 and L12.* The generator picks the smallest permission-bit set
covering the composed grant's permits within the level's ceiling, drops a bit where a deny
aligns with it, and emits regexes only for what bits cannot separate: denies beneath a bit,
and permits that dominate a deny under §5.4. A grant narrower than any covering bit renders
as `deny .*` plus one allow alternation, since emitting nothing widens it to the bit. Bits
travel as `user-permissions` per session by default, or as a `local-user-name` template
where a deployment provisions classes. A permit narrower than the bits with a deny beneath
it is refused at load; the `-regexps` family's documented deny-precedence may lift that once
measured. The choice is made from the composed grant, never per role. (§8, §15) *As built in
plan 5b* (§8, "As built"): a reply is proven before it is sent, against a device model in which
the bits are a union and only measured carve-outs subtract; bits that enter configuration mode
are sent only for a grant of everything; the built-in adapter delivers bits as `user-permissions`,
which L12 measured applied over a bitless template on both images; the projection ships in set
1.1.0, where a deny beneath a sent bit fails closed, since no wire deny binds an RPC the session
reaches (L26c). "Refused at load" is
amended by decision 26: the refused shape gets that subject the fail-closed reply, and CI
refuses the policy.

**23. Where the device cannot draw the operator line, `operator` renders as `admin`'s level.**
*Owner's ruling 2026-09-24.* On `arista_eos` and `cisco_nxos`, with command authorization
pointed at port49, no role or level between readonly and admin narrows what port49 permits
(`tests/lab/results/ceiling-arista_eos.md`, `ceiling-cisco_nxos.md`), so rendering `operator`
lower would only make it readonly on EOS, and refusing it quarantined every EOS device a
policy landed there. `operator` gets level 15 on both, port49's per-command rules are the
fence, and the device's method list must not fall back to `none` or `if-authenticated`.
IOS-XE, whose level 7 can carry the rung, is left to plan 5's adapters; decision 25 renders it
there, and gives `operator` readonly's device role on EOS and NX-OS. (§6, §8)

**24. A policy edit reaches live sessions without a logout.** A restart ends every live
context and every unspent token, so without a live reload the only way to narrow an operator's
access was to log everyone out — and the edit most in need of reaching a live session, a grant
withdrawn, was the one that could not. The file is reloaded in place, refused whole if it does
not load, and carried into every live context by compare-and-set: a narrowing or a widening
applies from the next command, and a principal with no grant left on a device has that context
revoked. Unspent tokens whose answer changed are deleted, because a redemption would otherwise
write the superseded answer into a fresh context. (§5.1.3)

**25. A level renders as a device level and a device role, and each fences a different
failure.** *Plan 5, 2026-09.* While port49 answers, the device level is what the device
enforces below port49: level 1 refuses the disruptive commands in the parser on EOS and
IOS-XE, and nothing between 1 and 15 does on EOS or NX-OS (`tests/lab/results/ceiling-*.md`).
When port49 cannot answer and the method list falls back to `local`, the device role is the
policy (`L16-arista_eos.md`, `L16-cisco_nxos.md`, command authorization LOCAL). So `operator`
gets admin's level where the device cannot draw the line (decision 23) and readonly's role
everywhere a role binds — `roles=network-operator` beside `priv-lvl=15` on EOS,
`shell:roles*network-operator` on NX-OS — and an outage never hands an operator
configuration. On IOS-XE, whose level 7 is the operator rung once the device is told what 7
runs, `operator` is `priv-lvl=7`, the adapter carries the reference configuration it depends
on, and the device takes `priv-lvl` and, of the other attributes measured, only `idletime`
and `timeout`, so any other attribute quarantines it (`L18-cisco_iosxe.md`,
`L22-cisco_iosxe.md`). L22 measured each adapter's reply at every level applied as rendered,
and with port49 stopped under an open session on a method list falling back to `local`,
operator's reply refused a configuration change on all three platforms
(`tests/lab/results/L22-*.md`). On vEOS and the N9Kv admin's control configured, so there the
role is what fenced operator. On IOS-XE admin's control was refused too — every command, at 7
and at 15, since a token user has no local account (`L22-carried-cisco_iosxe.md`) — so there
it shows that a token session gets nothing from local, not that local fences level 7. (§6, §8)

**26. A composition the projection cannot carry fails closed for that subject alone.**
*Owner's ruling 2026-09-25*, replacing decision 20's quarantine for projection refusals. Where
the projection cannot safely tell a Junos device one subject's composition, only that subject
gets a fail-closed reply: no template bits beyond what is proven, `deny-commands=^.*$`, and only
the allows the generator can prove. Everyone else on the device keeps working. Decision 20's
quarantine (§10) stays for inventory drift and the other joint checks; it no longer applies to
projection refusals. `policy test` and `policy diff` exit non-zero on any such composition and
name the subject, the device and the reason, so CI refuses it before it ships (§8, "CI MUST
refuse the policy"). For an admin composition with a deny, the reply drops only
the bits that enter configuration mode where the rest is provably sound, which it can be under
`user_permissions`; otherwise it is the fail-closed reply. Every such session is recorded
`projection_fail_closed` (§5.7). The pre-flight review of plan 5b measured the alternative: spec
§11's own policy quarantined all three SRXs for every user, and `policy test` passed it. (§8,
§10)

**27. Junos matches keywords only, and port49 never widens a deny to fit.** *Owner's ruling
2026-09-25*, on plan 5b's Task 2 measurement (`tests/lab/results/L12-juniper_*.md`,
`L9-juniper_*.md`: vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15 agree). Junos matches a
`deny-commands` or `allow-commands` regex against a command's keywords as typed and expanded,
never against its arguments: `^show interfaces fxp0( .*)?$` did not stop `show interfaces fxp0
terse` or `sh int fxp0 terse`. port49 has no Junos grammar, so the proof of a keyword comes from
a keyword tree captured in the lab on every image a set measures and shipped with the set (L26),
in which a word is a keyword only on positive evidence from the device, never for want of evidence
against it (§8).
A deny whose every word is proven a keyword is sent as written, and so is one whose other words
are all proven keywords and which ends in a trailing `**`: the device refuses by keyword prefix, so
it refuses at least what port49 denies (`deny show configuration **` and `deny show chassis hardware
**` are keyword denies; whether one may guard a sent bit is §8's, since no wire deny binds an RPC). A deny naming any word not proven a keyword — a `*` or a `**` anywhere but that
trailing place, a trailing `**` after an argument, an entity class, a regex, or a word the tree
does not list there — cannot be enforced on Junos: `policy test` and `policy diff` fail, naming the word and the whole
command to deny instead, and at runtime that subject gets decision 26's fail-closed reply.
port49 never widens the deny itself. An allow naming an argument never matches on Junos, so it
fails closed: it is not sent, the user cannot run it, and `policy test` warns. A keyword on one
image only is not proven. The same day, both images showed that deny-commands never reaches
configuration mode (`L12-configuration-juniper_*.md`): no reply that can enter configuration mode
carries a deny, a deny of a configuration statement that is not a proven operational command fails
closed (`configuration_deny`) and fails CI, and `deny-configuration` is left for a later plan to
measure. `DenyMatchesExpanded` is true in set 1.1.0: a probe set of abbreviations, at several
lengths and depths, piped and ambiguous, was refused or not run under a keyword deny on both
images (`L9-abbreviations-juniper_*.md`). The ruling amends
decision 22's "regexes for what bits cannot separate" to regexes over keywords only. (§8, §12,
§15)

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
  `@management` defined as `^Management[0-9]+$`; a permit's `(?-i)` regex matches
  case-sensitively and a deny's is refused at load; the vector reaching accounting is
  unaltered.
- **Dominance, permitting**: a permit of `show chassis hardware` (3,3,3) beats a deny of
  `show chassis **` (3,3,0), while `show chassis hardware detail` remains denied.
- **Dominance, denying**: each of these resolves to DENY because no permit dominates —
  `copy **` against `* * /^tftp:/`; `copy * *` against the same deny; `clear bgp **`
  against `* * all`; `interface @physical` against `interface /^Ethernet1$/`.
- **Dominance, buying it back**: `copy running-config @backup_targets` (3,3,2) dominates
  `* * /^tftp:/` (1,1,2) and permits, while `copy running-config *` (3,3,1) does not.
- **Equal tuples do not dominate**, so an equally specific permit and deny resolve to deny.
- **Class and regex are equally ranked**: neither dominates the other at a shared position.
- **Rank lint**: a regex equivalent to `*` or to a literal is flagged at policy load, in the
  spellings an author writes — `^.*$`, `.*`, `^show$` in any case, and what they simplify to.
  Full regex equivalence is decidable but not cheaply: it takes building and comparing automata,
  which Go's RE2 does not expose, so the lint recognizes the common spellings and stops there
  (plan 4).
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
  `parent:` resolves transitively; an unresolvable level fails at load; a `privilege_levels`
  that reorders the reserved levels fails at load.
- **The ceiling caps the level**: an `admin` role capped at `operator` is quarantined on every
  platform, `arista_eos` and `cisco_nxos` included, where both number 15; there
  `max_privilege: operator` is reported `ceiling_indistinct`.
- **Session tests**: `level:`, `max_privilege:`, `priv_lvl:` and `enable:` each pass only on the
  value the mint would give, and a session test fails where no token would be minted.
- **The privilege gate sees what the device gets**: each of a role or grant attribute
  `priv-lvl=15`, a custom level's `parent:` moved up, a level raised under either order, a
  ceiling raised or removed, and `enable` switched on fails `port49 policy diff` until a session
  test asserts the raised value, on a device of that group, at that instant; a lowering passes.
- **The regex gate cannot be satisfied by a deny test**: `/^(wri|rel)/ **` rewritten as
  `/^wri/ **` fails `port49 policy diff` with a passing test that `write erase` is denied, and
  passes with a test that `reload` is now permitted on each device group or an `acknowledge:`
  entry naming the old rule with a reason; an entry with no reason fails at load.
- **Acknowledgments hold at their instant**: a test that passes only after a grant expires
  acknowledges no expansion or raise reported before it.
- **The gate sees the whole reply**: a grant attribute `local-user-name=super-user` on Junos,
  `shell:roles=network-admin` on NX-OS or `roles=network-admin` on EOS fails `port49 policy
  diff` on that platform's group until a `reply:` session test asserts the new reply, and so
  does removing one, `deny-commands` or `local-user-name` on Junos included.
- **Placeholders only in inert attributes**: `priv-lvl={username}`,
  `allow-commands={principal}`, `allow-configuration={username}` and a placeholder in an
  attribute no adapter lists (`note*{device}`) each fail at load; `home-directory*/home/{username}`
  loads under each platform that holds it inert and fails under `cisco_iosxe` and `all`
  (L22-cisco_iosxe.md).
- **The gate sees broker rights**: `api: [explain_others, revoke_others, replay]` added to a
  subject fails `port49 policy diff` until a test asserts the whole list with `api:`; a
  principal moved to a subject with more rights needs that assertion in its own test; a right
  lost passes.
- **The gate sees principals**: an identity moved to another person, identities swapped between
  subjects, and a `username:` change each fail `port49 policy diff` until a session test naming
  the principal passes; a subject test does not acknowledge them, and a principal removed passes.
- **Stale acknowledgments**: an `acknowledge:` entry naming a rule the policy still denies is
  reported `acknowledge_stale` and acknowledges nothing; `policy diff` reports every entry no
  widening used.
- **Enable**: all three mechanisms, including the `$enab15$` username path resolving through
  the `(nas, rem_addr)` secondary index, and its refusal when that index is ambiguous.
- **Receipt binds the credential**: the hash is in the key, so a byte-identical
  retransmission replays and a genuinely new login by the same user on the same device finds
  no receipt and redeems normally rather than being rejected `credential_mismatch`. A spent
  token replayed within `receipt_ttl` is honored only for the same
  `(nas, username, credential_sha256)`. A retransmitted login or enable replays only while the
  receipt's `ctx_id` is the live context's; after a replace or a reclaim it is `token_spent`,
  and into a revoked context it is `credential_revoked` (§5.6).
- **CHAP verification**: a candidate set of several unspent tokens resolves to the one that
  produces the matching digest; the atomic removal, not the verification, decides single use,
  and two replicas racing the same token yield exactly one success — **and the loser replays
  the winner's receipt as it stands**, with the same `ctx_id` as the winner (design document
  §8): PASS when the winner passed, FAIL `receipt_replayed` once the winner's refusal has
  marked it failed. A loser that reads the receipt before that mark answers PASS (§5.6,
  pre-flight F16).
- **CHAP re-prompt**: a fresh challenge does not match the receipt and correctly fails rather
  than replaying.
- **Encryption at rest**: a store dump contains no recoverable token; redemption succeeds
  across a key rotation window in which both keys are accepted.
- **`enable: auto` is refused at policy load** on a platform whose `enable_username` is not
  `principal`.
- **Context teardown**: a redemption by the same principal joins the live context and one by
  another principal replaces it (§5.6); an authentication START with a different
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

- **One record per evaluation**, at each of the six decision events, permits included — a corpus
  exercising the matcher produces exactly as many records as decisions. The two `refresh`
  carve-outs (§5.7) hold: a refresh that finds a context already on the answer the policy in
  force gives writes no record, and nor does a pass a store error stops, for the context it
  stopped at. Every revocation a refresh makes has its record.
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
- **Session-discriminator binding**: an exec START always adds the platform's session
  discriminator (`session_pid` on Junos, `task_id` elsewhere — §5.8, §15 L17) to the context's
  set, hashed; a second START of the same user adds a second entry rather than replacing the
  first; a ninth evicts the oldest. A STOP whose discriminator is in the set sets
  `accounting_state: closing`; with an empty set, a username match is required. A per-command
  record never annotates, and which records are exec records is per platform: `cmd=login` and
  `cmd=logout` on Junos, no `cmd` at all elsewhere.
- **Spaced AV pairs are read**: an argument sent as `session_pid = 31050` binds the same value
  as `session_pid=31050`, because Junos sends the former (§5.8, §15 L17). This holds for every
  AV pair the accounting reader consumes, not only the discriminator.
- **Foreign session detection**: an exec STOP or WATCHDOG whose discriminator is not in a
  non-empty set is attributed `foreign`. A START is never `foreign`, and neither is any record
  on a context whose set is empty. `START|WATCHDOG` (`0x0a`) counts as a WATCHDOG for every one
  of these rules: it adds no discriminator and can be `foreign`.
- **Accounting does not extend the idle TTL**: an annotation writes the discriminator set and
  `accounting_state` and moves neither the expiry nor `last_touched_at`.
- **System users**: a record naming a username the platform's adapter declares a system user is
  attributed `system`, never `foreign` and never `unattributed`. `juniper_junos` declares `root`
  (§5.8, measured in `tests/lab/evidence/L1-juniper_vsrx.pcap`); every other adapter declares
  none.
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
- **Policy reload reaches a live session with no logout**, on a platform that authorizes
  commands: an edit narrowing a role denies the next command in the same context, `ctx_id` unchanged; one widening it permits the next
  command; one withdrawing the principal's grant on the device marks the context revoked and
  the next command is denied `credential_revoked`; a lowered `max_privilege` lowers the held
  level, and the next command above it is denied `privilege_exceeded`.
- **A policy that does not load is refused whole**: the policy in force keeps serving, the
  refusal is logged once and counted, and `port49_policy_file_refused` is 1 until a file loads
  or the old one is put back.
- **Superseded tokens are deleted and unchanged ones kept**: after an edit, an unspent token
  whose answer changed no longer redeems, and one whose answer did not still does.
- **A refresh loses a race safely**: a write landing on a context between the refresh's read
  and its write is kept, and the refresh reads again and writes the new policy beside it.
- **A grant's expiry reaches a live context** at the expiry instant, with no edit.
- **A policy file someone else could have written is refused**: a group- or world-writable
  file or directory, or a file or directory owned by someone other than `port49d`'s user or
  root, refuses the start, and at a reload keeps the policy in force serving, logged once and
  counted in `port49_policy_reloads_total{outcome="refused"}`; the check follows a symlink to
  the file it reads, and is made on the descriptor the policy is read through. A link in a
  directory others can write is refused too, whether it is the configured name, one half-way
  along the chain, or one standing for a directory. So is a chain of more than 40 links, and a
  file over 1 MiB.
- **A superseded token is judged at every instant it could have been minted**: a token minted
  after a grant's expiry under the policy since replaced is deleted when its answer differs,
  though the answer before the expiry did not.
- **A busy context does not stop a refresh**: a context whose every compare-and-set conflicts
  is counted `failed`, or revoked unconditionally where the answer is a revocation, and every
  context after it is still refreshed; `port49_policy_refresh_pending` stays 1 until a later
  pass reaches the busy context. An accounting record landing between the refresh's read and
  its write does not conflict.
- **An expiry is settled like a reload**: the pass at a grant's expiry is followed by a settle
  pass 30s later, `port49_policy_refresh_pending` is 1 from the expiry until that settle pass
  completes, and an expiry that fell between the instant a pass judged at and its end is due
  at once.
- **A reload that fails the joint check for some devices revokes no context**: an edit whose
  composition fails on one platform's devices loads, quarantines those devices, and leaves
  their live contexts as they were; no context anywhere is revoked `blob_unavailable`. One
  that no platform could pass is refused, and the policy in force keeps serving.
- **A refresh that cannot compile revokes, and records it**: a context the policy in force
  cannot be resolved or compiled for is revoked, its `refresh` record is a deny
  `blob_unavailable` naming its `ctx_id`, the process log names the fault, it is counted
  `failed`, every context after it is still refreshed, and it does not hold
  `port49_policy_refresh_pending` at 1.
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
- **A policy refresh does not reach a session-only platform either, and says so**: an edit
  withdrawing a grant or narrowing a role, with a live Junos login open, revokes or rewrites
  that context, leaves the device session running with the access it had at login, and the
  refresh's process-log summary counts that context as keeping its live session until logout
  while the process log names its `ctx_id`.
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
  never emitted: the composition gets the fail-closed reply, and `policy test` and `policy diff`
  exit non-zero naming it (decision 26).
- **Projection shape selection**: a readonly grant denying `show configuration **` renders
  as `view` without `view-configuration` and no deny regex; a grant whose composed permits
  are narrower than any covering bit renders as `deny .*` plus one allow alternation and the
  device's effective set is exactly the permits (`read_only_limited` on Junos reaches three
  commands, not all of `view`); a grant never receives a bit outside its level's `privilege:`
  ceiling; the mixed shape gets that subject the fail-closed reply, and `policy test` and
  `policy diff` exit non-zero naming the grant, both rules, and the platform. A session-only
  platform without `bits:` is a load error.
- **A fail-closed composition binds only its subject** (decision 26): on a device where one
  subject's composition gets the fail-closed reply, the daemon loads the policy, the device is
  not quarantined, and every other subject on it is answered with its own projected reply.
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
- **A login into a revoked result is refused**: a login that writes a revoked context — a
  same-principal replace past the ceiling, an unreadable replace, or a revocation landing mid-join,
  each with a token minted before the revocation — answers FAIL `credential_revoked` with the token
  spent, and its retransmission is refused `credential_revoked` while the context is revoked and
  replays FAIL `receipt_replayed` after a later token lifts it — not a PASS, except for the
  concurrent duplicate of §5.6 (pre-flight F16).
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
| **L1** | What the `port` field contains, per platform **and per transport** — SSH, console, eAPI, NX-API, NETCONF. Whether it is unique per concurrent session and stable for its life. | The login context key (§5.1.1, §5.6) — this row is what re-cut it to `(nas, username)` on 2026-09-20, and `port` is now a recorded attribute rather than part of any key (§13, decision 15); reusable-token API sessions (§13, decision 15) | EOS, NX-OS, IOS-XE, Junos | open — SSH measured on EOS, Junos and NX-OS, and on **no platform is `port` the same value at authentication and at authorization**; eAPI, NX-API and NETCONF measured on EOS and NX-OS; IOS-XE's RESTCONF measured 2026-09-23 (`tests/lab/results/L1-restconf-cisco_iosxe.md`); the console and IOS-XE's NETCONF unmeasured; see below |
| **L2** | Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates. | The session-ceiling warning (§5.6); denial messages | all | open — displayed in full on EOS; **not measurable on the N9Kv today**, because every command is denied before the authorizer runs (L1); truncation length and IOS-XE unmeasured; see below. **Output modifiers (recorded 2026-09-23, plan 4):** in the truncation runs a typed `show clock \| include …` reached port49 as `show clock` alone on vEOS 4.31.2F, NX-OS 10.4(2)F and IOS-XE 17.13.01a (`tests/lab/results/L2-arista_eos.md`, `L2-cisco_nxos.md`, `L2-cisco_iosxe.md`, "Truncation length"), which is why no built-in platform's `pipe_authorized` is true (§8); whether any modifier reaches port49 anywhere is unmeasured |
| **L3** | Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. | `rem_addr` binding on `$enab{level}$` platforms (§5.6); the login context key, because an enable that carries a fixed username collapses `(nas, username)` to one context per device | EOS, NX-OS, IOS-XE | closed — measured 2026-09-21; `tests/lab/results/L3-arista_eos.md`, `L3-cisco_iosxe.md`, `L3-nxos-cisco_nxos.md`. Scope: NX-OS 10.x has no enable exchange (`feature privilege` was removed in 10.x; the owner confirmed the same on production Nexus 9000 hardware running 10.3(5)); NX-OS 9.x and earlier are unmeasured and out of scope. No measured image sends `$enab{level}$`. History: closed in error 2026-09-20 on a note with no transcript, reopened 2026-09-21. Measured: vEOS-lab 4.31.2F (image tagged 4.32.2F) and IOS-XE 17.13.01a both send the operator's own username with `service=enable` and a bare-address `rem_addr` (`tests/lab/results/L3-arista_eos.md`, re-measured 2026-09-22, which is where the image tag was found to overstate the running version; the image under the tag is `sha256:8ef33020ece8871b19ddfdddf7f3585b04d2ac3672845b0db88debe8e96ff9c9`, created 2026-09-15, the only one on the lab host; `L3-cisco_iosxe.md`). **NX-OS re-measured 2026-09-21 with the transcript it was missing** (`tests/lab/results/L3-nxos-cisco_nxos.md`): `disable`, `enable` and `enable 15` were each typed separately and each answered `% Invalid command at '^' marker.`, and `feature privilege` is itself refused by this image, so the conclusion the reopened note reached without evidence is confirmed with it |
| **L4** | Whether any method-list configuration falls through to local on FAIL rather than only on ERROR — specifically Junos `authentication-order` with `password` listed — and `deadtime` behavior. | The `enable: auto` exposure argument and "denial is FAIL, so no fall-through" (§5.6); the reference AAA configuration | Junos first; then all | open — measured 2026-09-20 on vJunos-router, vSRX, vEOS, the N9Kv and IOS-XE over SSH: both Junos images fall through on a FAIL when `password` is listed; vEOS, the N9Kv and IOS-XE never do (`tests/lab/results/L4-cisco_iosxe.md`, which this cell omitted until 2026-09-23); `deadtime`, other transports and authorization fall-through unmeasured. **2026-09-21 (L17):** committing `tacplus-options strict-authorization` on both Junos images changes none of the unreachable-server cells — break-glass still logged in under both orders with port49d down — so making a port49 denial binding does not cost the fall-through this row measures. **2026-09-24, ERROR and `deadtime`, all five images** (`tests/lab/results/L4-error-*.md`): an authentication ERROR is final on IOS-XE and on Junos with `tacplus` alone and falls through elsewhere, but on vEOS and the N9Kv port49's authorization FAIL during a store outage then leaves break-glass useless; a per-command ERROR is final on vEOS, falls through to local RBAC on the N9Kv, and under IOS-XE's `if-authenticated` permits every command; a silent server costs 5s per command on the Cisco and Arista images and nothing on Junos; only the N9Kv offers a dead time, and `deadtime 1` locks token logins out for its minute after the server returns. Plan 4 answers an authorization `store_unavailable` `FAIL`, never `ERROR`, for this reason (§5.7). Still open: other transports, a second server, the console; see below |
| **L5** | Which platforms send accounting WATCHDOG, how often, and with or without arguments. | §5.8 record handling | all | closed — measured 2026-09-20; `tests/lab/results/L5-arista_eos.md`, `L5-juniper_vjunos-router.md`, `L5-juniper_vsrx.md`, `L5-cisco_nxos.md`, `L5-cisco_iosxe.md`. No image sends a WATCHDOG over a 2m30s idle interactive session under the lab's accounting config, which sets no periodic update; a device configured for periodic updates is outside what was measured |
| **L6** | How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next. | The `task_id` binding tolerance (§5.8); what reconciliation may conclude from silence (§9); `ERROR` semantics | all | open — arrival and latency measured on EOS and Junos; retry unmeasured; see below |
| **L7** | Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests. | Reusable tokens (§13, decision 15); capability inference (§9) | EOS, NX-OS | closed — measured 2026-09-24; `tests/lab/results/L7-arista_eos.md`, `L7-login-arista_eos.md`, `L7-cisco_nxos.md`, `L7-nxapi-cookie-cisco_nxos.md`. eAPI and NX-API both measured 2026-09-20: one authentication per HTTP request on both, with per-command authorization and per-command accounting. Both cookies measured: eAPI `/login` 2026-09-23 and NX-API `nxapi_auth` 2026-09-24 — a request carrying the cookie runs no authentication and no session authorization, only its command authorizations (NX-API: the command plus `end`; `configure terminal` too for `cli_conf`). The `nxapi_auth` cookie expires after 10 minutes idle (`NXAPI timeout 10`), ends on `POST /logout`, and wins over a wrong Basic password sent beside it; NAPALM `nxos` never uses it (21 authentications for a six-call job) while Ansible `httpapi` does (one); see below |
| **L8** | The maximum password length each platform accepts at an interactive prompt. (PAP was split out to L19 on 2026-09-23.) | The 30-character handle (design document §8) | all | closed — measured 2026-09-23; `tests/lab/results/L8-cisco_nxos.md`, `L8-cisco_iosxe.md`; and 2026-09-20, `L8-arista_eos.md`, `L8-juniper_vjunos-router.md`, `L8-juniper_vsrx.md`. The 30-character handle logs in on all five images. Longest intact: **127 on the N9Kv**, which refuses 128 and above locally and never asks port49; at least 1024 on IOS-XE; at least 138 on vEOS and both Junos images, where nothing longer was tried; see below |
| **L9** | Whether Junos anchors `allow-commands` / `deny-commands` regexes, and which RE2 constructs its regex dialect rejects. Whether explicit `^` and `$` are taken, with the pipe tail `( *\|.*)?` refusing `show version | no-more`; whether a deny regex reads a command in the case and the abbreviation typed (`SHOW VERSION`, `sh ver`) or as the CLI expands it; whether a value with spaces is taken raw; whether a malformed wire regex (`^(show$`) is ignored, which fails open, or refuses the session; and whether the commit checker takes, as class configuration, every wire regex shape the projection renders — a shape it rejects ships the set Junos unprojected (§8, platform sets). Whether a regex is matched against a command's arguments at all, or its keywords only. Whether a keyword deny refuses every abbreviation of its command: several lengths and depths, piped, and one ambiguous at a level (`JunosFacts.DenyMatchesExpanded`; `L9-abbreviations-juniper_*.md`). | Projection generator constraints (§8); `JunosFacts` in `internal/projection`, each fact read in the direction that fails closed until measured; decision 27 | Junos | open — measured 2026-09-25 on vJunos-router and vSRX (`tests/lab/results/L9-juniper_*.md`): a regex is matched against a command's keywords as the CLI expands them, never its arguments (decision 27); the row closes with plan 5b's Task 20 |
| **L10** | Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter. | Adapter `VERIFIED` status (§8) | all shipped adapters | open — `shell` on EOS, `junos-exec` on Junos. **Reading 3's conclusion is corrected by L17 (2026-09-21):** a denied Junos session authorization is advisory under the configuration this lab deploys, not on this vendor — `tacplus-options strict-authorization` makes the same denial refuse the login; see below. The three per-command adapters' spellings are measured by plan 5a (tests/lab/results/L22-*.md); Junos's wait on L12 (plan 5b), so the row stays open |
| **L11** | Junos precedence, repetition, and length behavior for wire and class rules. | The projection model (§8) | Junos (SRX) | **closed** — measured 2026-09-03; results in `port49-junos-lab-tests-results.md` |
| **L12** | `user-permissions` over TACACS+: accepted with a bitless template, replaces rather than merges with the class, per-session, and two bits in one value. What each bit reaches, so `bits:` can be declared, and that `view` alone does not show the configuration. Whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits. Whether `deny-commands-regexps` beats `allow-commands-regexps` over the wire as documented, and whether numbered names (`allow-commands1`, `allow-commands2`) are distinct attributes. Whether `deny-commands` reaches a statement typed in configuration mode, and `run`. Whether a template user commits with no uid, and whether one with no authentication refuses a local login. What a class with no bits runs (`baseline`), and whether `deny-commands .*` refuses it. Whether deny-commands and the fail-closed reply bind a NETCONF RPC opened with the same token and reply (`<get-configuration>`, `<get-software-information>`; `L12-netconf-juniper_*.md`). Whether a deny naming an argument (`^show interfaces fxp0( .*)?$`) is enforced. Measured 2026-09-25 on both images: it is not (decision 27), and a deny-commands naming a configuration statement does not stop it in configuration mode (`L12-configuration-juniper_*.md`). | The projection rule, its default shape, and its refused shape (§8; §13, decision 22); the built-in `bit_delivery` and `bits` (set 1.1.0) | Junos (vSRX / vJunos-router in containerlab) | open — `user-permissions` and class bits are in production use; no capture yet |
| **L13** | How long a device waits for a TACACS+ reply, and what it does when a FAIL arrives after that — reports an authentication failure, or treats the server as unreachable and falls through to the next method or the next server. | port49 delays a FAIL on purpose: `limits.auth_failure_delay_base` doubling to `limits.auth_failure_delay_max`, **default 500ms and 2s**, which is the "answered with increasing delay" of design document §11. The ceiling was 5s until this row measured device reply timeouts; **2026-09-21 it was lowered to 2s**, which is under every timeout measured here, so a FAIL is always delivered inside it (`tests/lab/results/L13-*.md`). A ceiling above a device's timeout turns a denial into silence, and silence is the fall-through condition of §5.6 and L4. | all | open — measured 2026-09-20 over SSH on vJunos-router, vSRX, vEOS, N9Kv and Catalyst 8000V: about 3s on both Junos images, 5.0s on vEOS, about 6s on the N9Kv, which also retransmits, and above 12s on IOS-XE, which this sweep does not bound from above; past that timeout every platform that reached it takes the fall-through branch; other transports and the next-server case unmeasured; see below |
| **L14** | Whether a NETCONF session over SSH authenticates through TACACS+ the way an interactive login does; whether any authorization request is sent for the session or for an `<edit-config>`, and with what `service`, `cmd` and `cmd-arg`; what `port` and `rem_addr` contain; what accounting arrives for a NETCONF session and for a commit. | Adapter coverage for automation traffic (§8); the login context key (§5.1.1); what reconciliation may conclude from accounting (§9) | Junos, NX-OS, EOS | open — measured 2026-09-20 on vEOS, vJunos-router and vSRX; on the N9Kv the AAA half is measured and the RPC half is not, because the channel closes before any RPC is answered; IOS-XE and key-based SSH unmeasured. **2026-09-21 (L17):** a Junos NETCONF session on port 830 is refused outright when port49 denies its session authorization and `tacplus-options strict-authorization` is committed, so the statement reaches automation traffic and not only interactive logins; see below |
| **L16** | Role delivery over TACACS+ and its interaction with command authorization. Whether a custom role named in a reply attribute takes effect — verified by a command it forbids being refused, never by the device echoing the name back; whether the device still sends a per-command authorization request for a command its own role forbids; which wins when the device's role and port49 disagree, **in both directions**; two roles at once (NX-OS documents a union with permit winning); a role name the device does not have; no role attribute at all; the accepted spellings (`shell:roles=` / `shell:roles*`, bare or inside `cisco-av-pair`); and the `priv-lvl=N` to `priv-N` mapping under `feature privilege`. | The session-attribute model (§6) and adapter `privilege` blocks (§8) — a custom role is the NX-OS and EOS analogue of a Junos login class, which is what decision 22 projects into. Also what the decision log means (§5.7, §9): if a device can refuse a command port49 permitted, the log records a permit for a command that never ran. | EOS, NX-OS | open — added 2026-09-21. vEOS measured 2026-09-21 (`shell:roles*<name>` **does not deliver a role** — the device reports the session's role as `<unknown>` — port49's per-command deny binds, and a `cisco-av-pair*` attribute sent as OPTIONAL is refused outright) and **2026-09-22, which corrects the reading drawn from it**: EOS reads the **bare** attribute `roles=<name>`, which the first run never sent, under either argument flag; sent by its own name the role is applied, and under `aaa authorization commands ... local` it is the operator's real privilege. `priv-lvl` must be sent too — a reply with a role and no `priv-lvl` lands the session at level 1 — and an OPTIONAL `priv-lvl*N` **is** applied on this image. NX-OS measured 2026-09-21 (delivery: all three spellings work, an unknown name degrades to `network-operator`, and a delivered role's own rules do not bind while `aaa authorization commands` points at TACACS+) and 2026-09-22 (precedence: **`shell:roles` decides the role and a `priv-lvl` beside it is inert, in both directions**, so an NX-OS adapter sends the role and never the privilege level; with command authorization pointed at `local` instead, the delivered role does bind). Open on EOS: the `cisco-av-pair` ambiguity, and whether a role that permits everything carries a read-only one delivered beside it (the pair was measured, the permissive role alone was not). **2026-09-24, the disruptive commands** (`tests/lab/results/ceiling-*.md`, no row of its own yet): with port49 permitting every command, an NX-OS `network-operator` session ran `clear counters`, `clear ip bgp *` and a configuration change, and a vEOS `network-operator` session at level 15 ran `clear counters`, had `clear ip bgp *` parsed and passed (BGP cannot run on that image) and entered `configure`; only the privilege level binds there (level 1 is refused all three by the parser, never asking port49); see below |
| **L15** | How many TACACS+ authentication exchanges one unit of work costs per transport — one HTTP API request, one NETCONF session, one SSH login — whether a second unit of work presenting the same credential re-authenticates, and **what port49 then answers**. | Single-use tokens, and therefore whether reusable tokens are needed at all (§13, decision 15); the 30-character handle's blast radius (design §8) | EOS, NX-OS, Junos | open — measured 2026-09-20 on all four images: one exchange per API request and per NETCONF session, every time, and the repeat permitted out of the receipt rather than the store, which moves the question to `receipt_ttl`; IOS-XE and kept-alive connections unmeasured (the NX-API `nxapi_auth` cookie measured by hand 2026-09-24, `tests/lab/results/L7-nxapi-cookie-cisco_nxos.md`: one exchange per cookie session; the eAPI `/login` cookie measured by hand 2026-09-23: one exchange at `/login`, none per request after it; `tests/lab/results/L7-login-arista_eos.md`). **2026-09-21: the real clients were driven and the count is the client's, not the transport's** — one authentication per ten-task job for every SSH client that holds its connection and for Ansible `cisco.nxos` over `httpapi`, against 28 for NAPALM `nxos` over the same NX-API; and the `receipt_ttl` boundary was crossed for the first time, half a NAPALM job refused `token_not_found` 38.8s into a 30s TTL; see below |
| **L17** | Which `system tacplus-options` statements change what a port49 answer MEANS on Junos. Whether `strict-authorization` makes a DENIED session authorization refuse the login, on SSH and on NETCONF, and what it does to a local break-glass account while port49d is down. What AV pairs `enhanced-accounting` adds, to which record types, and whether any of them separates two concurrent sessions of one user or carries the client's source port. Which accounting records carry a user who is not the logged-in operator, and what port49 does with them. Whether `authorization-time-interval` re-authorizes a live session, and what a DENIED re-authorization does to one. | Whether port49 constrains a Junos session at all (L10 reading 3; L14) and what the reference AAA configuration in `tests/lab/configs/` must carry; the 3am break-glass argument (§5.6, L4); accounting attribution and what reconciliation may conclude (§5.8, §9); whether a revocation can reach a session that is already open (§5.6) | Junos (vSRX, vJunos-router) | open — added 2026-09-21 and measured the same day on **both** images, cell for cell: `tests/lab/results/L17-juniper_vsrx.md`, `L17-juniper_vjunos-router.md`. `strict-authorization` **does** make a port49 denial binding, on SSH and on NETCONF, and break-glass still gets in with port49d down under both authentication orders. `enhanced-accounting` adds `Port`, `Authentication-Type` and `User_Perms` to the `cmd=login` record only. No record named `root` under this lab's accounting event list. `authorization-time-interval` re-authorizes at exactly the configured interval and a DENIED re-authorization does **not** end the live session. Unmeasured: the other six `tacplus-options` leaves, a real `root` RPC record, production Junos 23.4R2-S8.7, and an interval other than the 15-minute minimum; see below |
| **L18** | How each platform treats a reply attribute it did not ask for: applied, ignored, or the session killed. Another vendor's attribute, an invented one, and a known attribute carrying a value the device cannot use, each in the OPTIONAL and the MANDATORY spelling. Per variant: whether the session opens and, when it does not, what the device says verbatim; what role or privilege the session ends up with; and whether the device still sends per-command authorization. | Whether an adapter may send one attribute list to a mixed fleet at all (§8). RFC 8907 §8.2 says an OPTIONAL argument a device does not understand SHOULD be ignored and a MANDATORY one MUST fail the authorization; `lab.session_attributes` in `tests/lab/port49d-lab.yaml` rested on the first half until IOS-XE disproved it (L10), and what an operator's typo costs (§6) rests on the same answer. Also decision 22's two Junos attributes (§13, gated on L12). | EOS, NX-OS, IOS-XE, Junos | open — added and measured 2026-09-22 on all five images, `tests/lab/l18_test.go`. **Three vendors answer three different ways, so §8 cannot have one rule.** vEOS follows §8.2 in both directions. The N9Kv and both Junos images honour neither half and ignore everything, mandatory included. IOS-XE refuses the session for anything it does not recognise under either flag — and a run of those refusals stops it answering SSH at all for about a minute, without sending port49 a packet. On Junos `local-user-name` is applied under either flag and **`user-permissions` does nothing**, which is decision 22's second attribute measured for the first time. **The per-command reply is measured too, 2026-09-22, and it does not follow the session reply:** the C8000V refuses EVERY command in the session — `Command authorization failed.` — for any of the three attributes under either flag, on authorizations port49 answered `permit`; vEOS ignores an optional unknown there and refuses every command on a MANDATORY one; the N9Kv ignores all of them. Junos has no per-command reply to ask it of (L10, L14; decision 21). Open: every non-SSH transport, and whether IOS-XE's SSH condition is the vty pool; see below |
| **L19** | The maximum password length each platform accepts via PAP, on every login path where the device uses PAP. | The 30-character handle (design document §8): an authentication START carries a PAP password in `data`, whose length field is one byte, so PAP can bound the handle where the ASCII prompt does not — and NX-OS uses PAP for every SSH login by default | all | open — added 2026-09-23, split from L8. On the N9Kv an SSH login is carried as PAP and 127 characters arrive (`tests/lab/results/L8-cisco_nxos.md`); PAP on any other path, and on EOS, Junos and IOS-XE, which this lab does not configure for it, is unmeasured; see below |
| **L20** | Whether a device answers a repeat API request without asking TACACS+; for how long; what it keys that answer on (the credential, the username, the client); whether a **wrong password** for the same user inside that window is also accepted; and whether a credential port49 would now refuse is re-checked inside it. | Whether a revocation in port49 reaches an API client at all (§5.1.4), and decision 15's bound on how long a spent token works — the receipt's `receipt_idle_ttl` and `receipt_max_age` act only on exchanges the device sends | IOS-XE; then every HTTP API transport | open — added 2026-09-23. IOS-XE RESTCONF answered a repeat of an already-spent token, 3s later, with `200 OK` and **zero** TACACS+ traffic (`tests/lab/results/L1-restconf-cisco_iosxe.md`), so a revocation in port49 cannot reach that repeat. **Measured 2026-09-24 on IOS-XE** (`tests/lab/results/L20-cisco_iosxe.md`): the cache is per credential (username and password), not per username or client address; a wrong password inside it goes to port49 and is refused; it lasts about 10s fixed from the authentication that filled it; and a cached credential is not re-checked, even with port49 answering every authentication ERROR. Open: every other HTTP API transport, so the row stays open; see below |
| **L21** | Whether each platform sends the command words the operator typed (`sh run`) or the resolved ones (`show running-config`) on a per-command authorization request, and on the accounting record for it. | `expands_abbreviations` per platform (§3 rule 4, §8): where it is `false` a deny's word matches its own abbreviations, which over-denies, and where it is wrongly `true` an abbreviation slips past a deny | EOS, NX-OS, IOS-XE | closed — measured 2026-09-24; `tests/lab/results/L21-arista_eos.md`, `L21-cisco_nxos.md`, `L21-cisco_iosxe.md`. All three images send the **resolved** words, on the request and on the accounting record, over interactive SSH: `sh ver` arrives as `cmd=show cmd-arg=version`, and `sh clock` was denied by a `show clock` deny on all three. Interface names differ: IOS-XE splits `Gi1` into `GigabitEthernet`, `1`; vEOS and the N9Kv join it (`Ethernet1`, `Ethernet1/1`). Other transports and releases are outside what was measured; see below |
| **L22** | What each per-command platform's device lets a session run at each level port49 renders — with port49 permitting every command, which of `clear counters`, `clear ip bgp *` and `configure terminal` it runs, refuses in its own parser, or sends port49 — and which level or role it reports, for the exact reply each built-in adapter sends; and, with port49 stopped under an open session on a command method list ending in `local`, whether operator's reply can change the configuration where admin's can, and whether it runs `clear counters` and `clear ip bgp *`; and, on IOS-XE with `privilege exec level 7 clear counters` configured and no `aaa authorization commands 7` list, whether a level-7 session runs `clear counters` without asking port49. | Decision 25; the adapters' `privilege`, `unreachable` and `fallback` (§8); the dead-rule and fallback-exposure reports (§12) | EOS, NX-OS, IOS-XE | closed — measured 2026-09-24; tests/lab/results/L22-arista_eos.md, L22-cisco_nxos.md, L22-cisco_iosxe.md. Each built-in adapter's reply at readonly, operator and admin was applied as the adapter says: on vEOS level 1 then 15 with network-operator, network-operator and network-admin; on the N9Kv network-operator, network-operator, network-admin, `clear counters` and `configure terminal` both sent to port49 at every level; on IOS-XE 17.13.01a levels 1, 7 and 15, level 7 sending `clear counters` and refusing `configure terminal` in the parser. With port49d stopped under an open session and the method list falling back to local, operator's reply could not change the configuration on any of the three, and admin's could on vEOS and the N9Kv. Beside it (`L22-carried-*.md`): vEOS's network-operator still ran `clear counters` and passed `clear ip bgp *` through authorization, the N9Kv's was refused both, and IOS-XE refused a token session every command at 7 and at 15, admin's included; on IOS-XE with no `aaa authorization commands 7` list, operator's `clear counters` ran without asking port49. Inert beside admin's reply: `home-directory`, `idletime` and `timeout` on vEOS and the N9Kv; `idletime*30` and `timeout*480` on IOS-XE, where they are accepted but held bearing (§6), and which refused the session for `home-directory`. By hand 2026-09-24: tests/lab/results/ceiling-*.md |
| **L23** | Whether `home-directory`, `idletime` and `timeout`, each beside readonly's reply, leave the session readonly's on EOS and NX-OS: the same identity, the same reach for `clear counters` and `configure terminal`, and a permitted `show version`. Beside admin's reply (L22) a raise is invisible (5a final review M3). | The inert lists of `arista_eos` and `cisco_nxos` (§6, §8) | EOS, NX-OS | closed — measured 2026-09-25; `tests/lab/results/L23-arista_eos.md`, `tests/lab/results/L23-cisco_nxos.md` |
| **L24** | Whether a Junos login class's `idle-timeout` ends an idle session a TACACS+ reply landed in that class, through `local-user-name` and through the `remote` template. | Decision 21's enforced approximation; `port49 platform export --classes` (§5.6, §8) | Junos | open |
| **L25** | Whether the N9Kv writes an accounting record under `admin` with task_id `vsh.bin.<port>` when a network-operator cancels the sudo prompt of a bare `show interface`, and what distinguishes it from a person's `admin` session, over SSH and over NX-API. | A `cisco_nxos` system user keyed on its task_id, never the username alone (§5.8) | NX-OS | open — a production observation with no note |
| **L26** | The Junos operational CLI keyword tree under `show`: at each command path, the words proven keywords — offered by completion there, and shown a keyword by `\| display xml rpc` (an element named as the word, none holding it as text, or a path still asking for a `<command>`) — and whether an argument may be typed there; anything without that evidence is an argument. The pipe is first proven to run nothing. Walked over the break-glass CLI, seeds first, bounded in breadth, depth, nodes and commands. Scope: the images captured, and no hidden argument. | Which denies and allows the projection may send (decision 27; §8); `platforms/keywords/<set>/juniper_junos.yaml` | Junos (vSRX / vJunos-router in containerlab) | open — added 2026-09-25 |

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
  | vEOS-lab 4.31.2F | `ssh` | **`vty4`** / `vty5` | `ssh` at start, `vty<n>` at stop |
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

  Concurrency did not rescue it either. Two overlapping N9Kv sessions both reported `0` — one denied
  `username_mismatch`, the other `context_missing`. (This paragraph also said two overlapping vEOS
  sessions both reported `vty4` at authorization. Corrected 2026-09-23: two overlapping vEOS sessions
  that each hold a shell get different vtys — `vty4` and `vty6` in the 2026-09-20 re-measure below
  (`tests/lab/results/L1-arista_eos.md`), and again in the 2026-09-22 run.)

  **Re-measured on vEOS after the re-key, 2026-09-20.** The `port` observations are unchanged — the device
  still says `ssh` at authentication and `vty<n>` at authorization, so two concurrent sessions cannot be
  told apart by it where the context is written — and the outcome is now the opposite. Both overlapping
  sessions were answered `permit context_matched` at their session authorization, under two distinct
  `ctx_id`s, with the device reporting a *different* vty for each (`vty4` and `vty6`) and neither
  matching the `ssh` they authenticated under. Off the wire, the AUTHOR RESPONSE that was `status=0x10 server_msg="port49: this session was not
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
  NX-API and NETCONF both report `0`, the same value SSH reports. On IOS-XE, RESTCONF reports
  `""` (empty) at authentication and `""` (empty) at authorization (not unique across two
  concurrent requests, which differed only by username); the START's and the REQUEST's byte
  lengths leave no room for a `port`, so the device sent it empty.
  `tests/lab/results/L1-restconf-cisco_iosxe.md`.
  `tests/lab/results/L1-arista_eos.md`, `L1-juniper_vjunos-router.md`, `L1-juniper_vsrx.md`,
  `L1-cisco_nxos.md`, `L1-cisco_iosxe.md`, `L7-arista_eos.md`, `L7-cisco_nxos.md`,
  `netconf-arista_eos.md`.
  *Unmeasured:* the console transport — though one incidental observation exists for IOS-XE,
  where a command typed at the serial console reported `port="tty0" rem_addr="async"` against
  `tty434`/`172.100.100.1` for a vty, so that platform distinguishes the console by `port` as
  vEOS distinguishes eAPI; NETCONF on the N9Kv beyond the authentication; and NETCONF-YANG on
  IOS-XE.
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

  **vEOS-lab 4.31.2F** (image tagged 4.32.2F), two concurrent enables, off the wire:

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

  | method list | port49 | vJunos-router 23.4R2-S2.1 | vSRX 21.4R3.15 | vEOS-lab 4.31.2F | Nexus 9300v 10.4(2)F | Catalyst 8000V 17.13.01a |
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

  **ERROR, silent servers and `deadtime`, 2026-09-24, all five images.** By hand, with port49d's
  lab fault switch (`lab.fault_file`, `author.LabFault`): `store_unavailable` makes authentication
  answer ERROR and authorization FAIL, as a real store outage does; `command_error` and
  `command_fail` answer every per-command authorization ERROR or FAIL. `tests/lab/results/
  L4-error-cisco_iosxe.md`, `L4-error-arista_eos.md`, `L4-error-cisco_nxos.md`,
  `L4-error-juniper_vjunos-router.md`, `L4-error-juniper_vsrx.md`.

  | cell | vJunos-router, vSRX | vEOS-lab 4.31.2F | Nexus 9300v 10.4(2)F | Catalyst 8000V 17.13.01a |
  |---|---|---|---|---|
  | authentication ERROR, list with a local method | local login | local login, **then thrown out by the exec authorization's FAIL** | local login, **then every command refused by FAIL** | **refused** |
  | authentication ERROR, no local method | **refused** | refused | local login, every command refused | refused |
  | command ERROR, `group … local` | — | refused | **falls through to local RBAC: runs** | refused |
  | command ERROR, `group …` | — | refused | refused | refused |
  | command ERROR, `if-authenticated` / `none` | — | `none`: refused | `none` not kept by the device | `if-authenticated`: **every command runs** |
  | command FAIL, any list | — | refused | refused | refused |
  | break-glass, server silent | 0.08–0.13s login, no command wait | 7.88s login, 5.06s per command | 5.21s login, ~5s per command | 0.06–5.06s login, 5.06s per command |
  | returned server skipped for | not at all | not at all | not at all; with `deadtime 1`, about a minute | not after RST; after timeouts, still skipped 45s after the first |
  | dead-time setting | none | none | `deadtime` in the server group | none on this image |

  Three consequences. **A store outage is not the break-glass case**: only an unreachable port49
  lets break-glass work on every image; with port49 up and its store failing, break-glass is
  refused on IOS-XE and Junos-`tacplus`, and logged in but useless on vEOS and the N9Kv, because
  the authorization that follows is answered FAIL (plan 4's ruling). **That FAIL is right**: an
  ERROR there would authorize every command on an IOS-XE `if-authenticated` list and hand the N9Kv
  to local RBAC. And **silence is the expensive failure** on the Cisco and Arista images — 5s per
  command, every session — where on Junos it is free. The N9Kv's `deadtime` removes that cost and
  replaces it with a minute in which the device refuses every token login without asking port49,
  which nothing in port49's log shows.

  *Still unmeasured:* a second server; the console; every transport but SSH; ERROR on a session
  (exec) authorization; `tacacs-server deadtime`, the N9Kv's global form.

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

  *Measured since* (added 2026-09-24 by plan 4, on the owner's rulings, and run the same day):

  - **Authentication `ERROR` fall-through,** with port49d up and its store down: the table
    above. It is final on IOS-XE and on Junos under `tacplus` alone; on vEOS and the N9Kv
    break-glass logs in and is then refused by the authorization FAIL that follows
    (`tests/lab/results/L4-error-*.md`).
  - **Authorization `FAIL` vs `ERROR`:** the table above. `FAIL` is final everywhere; `ERROR`
    runs every command under IOS-XE's `if-authenticated` and hands the N9Kv to local RBAC,
    which is why plan 4 answers authorization `store_unavailable` `FAIL` (§5.7).
  - **Role ceiling, per platform** (`tests/lab/results/ceiling-arista_eos.md`,
    `ceiling-cisco_iosxe.md`, `ceiling-cisco_nxos.md`): IOS-XE's parser refuses `clear
    counters`, `clear ip bgp *` and `configure` at levels 1 and 7, and one line
    (`privilege exec level 7 clear counters`) gives level 7 exactly the operator rung; vEOS
    refuses all three at level 1 and runs all three as `network-operator` at 15; on the N9Kv
    every role runs all three. So on EOS and NX-OS the operator rung is port49's per-command
    policy alone. *Owner's ruling 2026-09-24:* `operator` renders as level 15 on both, with
    port49's rules as the only fence (§6, decision 23); it no longer quarantines an EOS device.
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
- **L8** — the interactive prompt. EOS 2026-09-17 and Junos 2026-09-20: 138 characters arrive
  intact on all three, the longest length tried there (`tests/lab/results/L8-arista_eos.md`,
  `L8-juniper_vjunos-router.md`, `L8-juniper_vsrx.md`).

  **NX-OS and IOS-XE, re-measured 2026-09-23, and the N9Kv result corrects this entry.** It used
  to say NX-OS and IOS-XE "make it five images with 138 characters intact". The N9Kv note it
  cited said 64 at the time, and neither was right: the new sweep (30 to 1024, by
  `credential_sha256` on the refusal rather than by seeded tokens; `tests/lab/l8_test.go`) puts
  the Nexus 9300v 10.4(2)F boundary at **127 characters intact, 128 not sent at all**. From 128
  up the device never asks port49, and what the operator sees is byte-for-byte what a wrong
  password produces:

  ```
  [SSH banner]
  User Access Verification
  [keyboard-interactive prompt]
  name="" instruction="" questions=["Password: "]
  [SSH authentication result]
  ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password keyboard-interactive], no supported methods remain
  ```

  (verbatim from `tests/lab/results/L8-cisco_nxos.md`, for 128 characters and for a
  30-character probe port49 received and refused alike). Nothing reaches `show logging logfile`.
  Catalyst 8000V 17.13.01a passed every length tried, up to 1024, over ASCII
  (`L8-cisco_iosxe.md`). A real minted 30-character token logged in on both.

  So the 30-character handle clears every measured prompt, with 97 characters to spare on the
  tightest one. At 3am the N9Kv failure mode is the one to know: a handle that grew past 127
  would fail silently, with no port49 record to show it was ever tried.
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
  three single-variable runs on 2026-09-20, which `L10-cisco_iosxe.md` does not record; the
  refusal is recorded, variant by variant, in `tests/lab/results/L18-cisco_iosxe.md`
  (2026-09-22), and the lab harness now derives a daemon config for this platform carrying
  `priv-lvl=15` alone (`(*lab).configPath` in `tests/lab/harness_test.go`).

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

  **What plan 5 inherits from that, corrected 2026-09-21 by L17.** On these images port49's
  session authorization is *advisory* **under the configuration this lab deploys**: the device
  authenticates through TACACS+ and then assigns privilege from its own template whatever
  port49 answers. Read alongside L4 reading 1, where a Junos *authentication* FAIL is also not
  final when `password` is in `authentication-order`: on this vendor both halves of AAA are
  advisory unless the device is configured to make them binding.

  **It is a property of the configuration, not of the vendor, and the statement that changes
  it has now been measured.** This bullet used to end "until [the projection] lands, port49
  does not constrain a Junos session at all". That is withdrawn. With
  `set system tacplus-options strict-authorization` committed, the same denial that completed
  a login here refuses one outright — on SSH and on NETCONF, on both images (L17). What plan 5
  still owns is *graded* authority, which is the projection; what it does not own, and never
  did, is the ability to refuse a session, which is one statement in the device's
  configuration.
  *Unmeasured:* the attribute sets the other four platforms refuse — only IOS-XE has been probed
  with an attribute it does not know, so whether EOS, NX-OS and Junos merely ignore one or would refuse a
  different one is untested; and every non-SSH transport on IOS-XE.
- **L13** — 2026-09-20, SSH, all three images. port49's FAIL was delayed by a fixed 2s, 6s and
  12s (`auth_failure_delay_base` and `..._max` set equal, so the first failure carries the
  full delay), and the login timed from the client. `tests/lab/results/L13-arista_eos.md`,
  `L13-juniper_vjunos-router.md`, `L13-juniper_vsrx.md`.

  | FAIL delayed by | vJunos-router 23.4R2-S2.1 | vSRX 21.4R3.15 | vEOS-lab 4.31.2F | Catalyst 8000V 17.13.01a |
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
  and HTTP keep-alive are precisely the shapes that would lower the count. The first was
  measured 2026-09-23 and does lower it (below); the other two are unmeasured. Read every count
  in the table above as an upper bound.

  What the repeat then got is the finding decision 15 actually turns on, and it is in L15 below.

  **The eAPI `/login` cookie flow, measured 2026-09-23 by hand**
  (`tests/lab/results/L7-login-arista_eos.md`). vEOS-lab 4.31.2F (image tagged 4.32.2F), one
  token minted by the slice's broker, `POST /login`, three `POST /command-api` requests carrying
  the cookie 23s apart, `POST /logout`, then the cookie once more. Counts are from port49's
  decision log and the capture.

  | request | redeem | authorize_session | authorize_command | account | port | rem_addr |
  |---|---|---|---|---|---|---|
  | `POST /login` | 1 | 1 | 0 | 1 (start, task_id 1) | `command-api` | `172.100.100.1` |
  | `POST /command-api` `p49-1` | 0 | 0 | 1 | 1 (stop, task_id 9) | `command-api` | `172.100.100.1` |
  | `POST /command-api` `p49-2` | 0 | 0 | 1 | 1 (stop, task_id 10) | `command-api` | `172.100.100.1` |
  | `POST /command-api` `p49-3` | 0 | 0 | 1 | 1 (stop, task_id 11) | `command-api` | `172.100.100.1` |
  | `POST /logout` | 0 | 0 | 0 | 1 (stop, task_id 1) | `command-api` | `172.100.100.1` |
  | `POST /command-api` `p49-after` | 0 | 0 | 0 | 0 | — | — |

  1. **`POST /login` runs one TACACS+ authentication** (`redeem token_redeemed`, `auth.method`
     `ascii`, `port` `command-api`, `rem_addr` `172.100.100.1`), then a session authorization
     and an exec accounting start.
  2. **A request carrying the cookie does not authenticate again**, and does not authorize the
     session again: one command authorization (`permit_dominates`) and one accounting stop each,
     the same for all three requests, 23s and 46s after the first.
  3. **After `/logout` the device refuses the cookie itself**, `HTTP/1.1 401 Unauthorized` /
     `Unable to authenticate user: Bad session Id`, and sends port49d nothing for it; the only
     record in that step is `/logout`'s own accounting stop.

  This is the measured confirmation, for eAPI, that the table above is an upper bound: with a
  cookie, one authentication and one session authorization cover every later request, and the
  single-use token is spent once, at `/login`. Every record carried one `ctx_id`.

  *Unmeasured when this paragraph was written (2026-09-23):* the NX-API `nxapi_auth` cookie, the
  other half of the cookie clause this row names — measured 2026-09-24, next paragraph; an eAPI cookie used past `receipt_idle_ttl` or past its
  own `Expires` (24h); a denied command under a cookie; two cookie sessions from one token; HTTP
  keep-alive; the NX-API JSON-RPC dialect, which is a different code path on the device from
  `ins_api`; the unix-socket and plain-HTTP eAPI transports.

  **NX-API's `nxapi_auth` cookie, 2026-09-24** (`tests/lab/results/L7-nxapi-cookie-cisco_nxos.md`,
  by hand, N9Kv 10.4(2)F). A Basic request authenticates once and sets `nxapi_auth`; requests
  carrying it send port49 no authentication and no session authorization, only each command's
  authorization (`show hostname` then `end`). The cookie outlives the token: the device never
  re-asks, so a spent or revoked token keeps a live cookie working until 10 minutes idle or a
  `POST /logout` (`/api/aaaLogout.json` does not end it), and port49's per-command answer is the
  only check on that session. Sent with a wrong Basic password, the cookie still wins. NX-API also
  answers "Max sessions reached" as `ins_api` code `429` inside an HTTP `200` — after port49 has
  authenticated the request. Real clients split: NAPALM 5.2.0 `nxos` sent Basic on every request
  (21 authentications, 20 of them `receipt_replayed`), Ansible `cisco.nxos` `httpapi` used the cookie
  (one). With both cookies measured the row closes.

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
  about. (The eAPI cookie was driven by hand 2026-09-23: one authentication at `/login` and none
  for the requests carrying the cookie — L7 above, `tests/lab/results/L7-login-arista_eos.md`.)

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
  argument about that boundary is settled by decision 15's sliding receipt (`receipt_idle_ttl`, `receipt_max_age`),
  not by the exchange count; the linear-strategy gap that sizes the idle default is still unmeasured here.

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

  *Unmeasured:* forcing an eAPI cookie to expire and watching what the device does; HTTP
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

  **1. `shell:roles*<name>` does not deliver a role on vEOS** — and that is a finding about the
  attribute name, not about EOS. It was read as the latter until 2026-09-22; the block after this
  one has the correction, and the bare `roles=<name>` is applied. The device was asked, in the
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

  What this row then said, and said wrongly, was that *no* role reaches a vEOS session. Every
  variant of that run spelled the attribute `shell:roles`; none of them sent the name Arista
  reads. See the 2026-09-22 block below.

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

  **L18 narrows this on 2026-09-22 without settling it.** Two further OPTIONAL attributes this
  image does not read — `shell:roles*network-operator` and an invented `p49-nonsense*1` — are
  **ignored**, leaving the session identical to the same reply without them, while both in
  their MANDATORY spelling end it. So EOS does follow §8.2 in both directions as a rule, and
  `cisco-av-pair*` is an exception to it rather than the rule itself: the refusal is about that
  attribute, not about the optional flag. The quotes in its value remain the live hypothesis.
  `tests/lab/results/L18-arista_eos.md`.

  **4. Two roles at once, an absent role, and `priv-lvl=1` all behave identically to no
  attribute at all** on this image, which follows from 1: nothing in the `shell:roles` family
  reaches the session, so there is nothing for a union rule or a missing name to change.

  **vEOS re-measured 2026-09-22** (`tests/lab/results/L16-arista_eos.md`, the section "The bare
  `roles` attribute, and `priv-lvl` mandatory against optional", `tests/lab/l16_eos_roles_test.go`),
  eleven reply-attribute sets against one deploy and one token login each, then five of them again
  with the device's command authorization pointed at its own role database.

  **Why it was re-run.** The owner runs EOS in production against the bare attribute
  `roles=network-operator` sent MANDATORY, and reports that EOS also needs `priv-lvl` mandatory
  because an optional `priv-lvl*N` is ignored and level 1 assumed. The lab had never sent either.
  CLAUDE.md's rule about where TACACS+ instincts come from says settle it in the lab; this is that.

  | reply attributes | role the device reports | `show privilege` | prompt |
  |---|---|---|---|
  | `priv-lvl=15` alone (the control) | `<unknown>` | 15 | `leaf1#` |
  | `priv-lvl=15`, `roles=network-operator` | **`network-operator`** | 15 | `leaf1#` |
  | `priv-lvl=15`, `roles*network-operator` | **`network-operator`** | 15 | `leaf1#` |
  | `roles=network-operator` alone | **not readable at this level** | **1** | **`leaf1>`** |
  | `priv-lvl*2` alone | `<unknown>` | **2** | `leaf1#` |
  | `priv-lvl=2` alone | `<unknown>` | **2** | `leaf1#` |
  | `priv-lvl=15`, `roles=p49-noc` | **`p49-noc`** | 15 | `leaf1#` |
  | `priv-lvl=15`, `roles="p49-noc network-operator"` | **`"p49-noc network-operator"`** | 15 | `leaf1#` |
  | `priv-lvl=15`, `roles=p49-noc network-operator` | **`p49-noc network-operator`** | 15 | `leaf1#` |
  | `priv-lvl=15`, `roles=p49-noc,network-operator` | **`p49-noc,network-operator`** | 15 | `leaf1#` |
  | `priv-lvl=15`, `roles=p49-nosuchrole` | **`p49-nosuchrole`** | 15 | `leaf1#` |

  **1. The bare `roles=<name>` is applied, under either argument flag.** `network-operator` against
  `<unknown>` for the same reply with the attribute taken out, minutes apart on the same device.
  Optional and mandatory name the same role, so the mandatory form the owner runs is a choice and
  not a requirement here. **The 2026-09-21 conclusion was about the spelling `shell:roles` and was
  generalised to the platform; it should not have been.**

  **2. `priv-lvl` goes in the reply too, which is the opposite of the NX-OS rule.** A reply naming a
  role and no privilege level opens a session at **level 1**, at the unprivileged `leaf1>` prompt,
  where the device refuses `show users detail` outright — so the operator cannot read their own role
  and neither can this test. Whether the role arrived and is merely unreadable is **not** separated
  by that row; what is measured is that dropping `priv-lvl` costs the session its privilege level.
  On NX-OS `priv-lvl` beside a role is inert and an adapter drops it. **One reply cannot serve both
  platforms.**

  **3. An OPTIONAL `priv-lvl*N` IS applied on this image.** `priv-lvl*2` and `priv-lvl=2` both reach
  level 2. The owner's production reading — optional ignored, level 1 assumed — does not reproduce
  on vEOS-lab 4.31.2F. It may still hold on the hardware and release they run; nothing here
  contradicts that, and nothing here supports building an adapter rule on it.

  **4. The role value is taken literally: no quote stripping, no separator parsing.**
  `roles="p49-noc network-operator"` comes back **with the quotes inside the role name**, so a reply
  copied from an NX-OS server definition names a role no device has. The unquoted pair comes back as
  two space-separated names and the comma form as one comma-joined token. An adapter for EOS sends
  one role name and no quotes.

  **5. An unknown role name is not degraded — it is echoed back.** `roles=p49-nosuchrole` is what
  `show users detail` reports, where NX-OS silently substitutes `network-operator`. port49 cannot
  tell either way: the reply it sent and the record it wrote are identical to the working case.

  **6. port49's per-command deny binds under every one of these replies**, all eleven sessions,
  whatever role was named and whatever level was reported — as it did in the 2026-09-21 run.

  **Phase B: with `aaa authorization commands all default local`, the delivered role is real
  privilege.** `aaa authorization exec` stays pointed at port49 throughout, because a token operator
  has no local account.

  | reply attributes, command authorization LOCAL | role reported | `configure` |
  |---|---|---|
  | `priv-lvl=15`, `roles=network-admin` | `network-admin` | accepted |
  | `priv-lvl=15`, `roles=network-operator` | `network-operator` | **`% Authorization denied for command 'configure'`** |
  | `priv-lvl=15` alone | not readable | **`% Authorization denied for command 'configure': Unknown role`** |
  | `priv-lvl=15`, `roles=p49-nosuchrole` | `p49-nosuchrole` | **`% Authorization denied for command 'configure'`** |
  | `priv-lvl=15`, `roles=p49-noc network-operator` | `p49-noc network-operator` | **`% Authorization denied for command 'configure'`** |

  Same device, same minute, one attribute value apart, opposite outcomes, and **no command
  authorization reached port49 in any of them**. So the clause this row carried as unmeasured on EOS
  is answered: a delivered role's rules **do** bind when `aaa authorization commands` is not pointed
  at TACACS+ — which is the state a fleet is in before port49 is deployed, and the state it returns
  to if port49 leaves the command path.

  Two of those rows are worth reading twice. **The unknown role name is the 3am case and it lands on
  the safe side**: the session opens, `show clock` runs, and the device refuses to let it configure
  anything. And **the two-role reply was refused exactly as the read-only role alone was**, although
  `p49-noc` permits every command — so on this image a permissive role delivered beside a
  restrictive one did not carry the pair. *Not measured:* `p49-noc` alone under local command
  authorization, so "EOS does not do a union with permit winning" rests on the pair's refusal and on
  the role's own `20 permit command .*`, not on a measured contrast.

  **The adapter rule this supports: on EOS send the bare `roles=<name>` and `priv-lvl=N` together,
  one role name, no quotes.** Never `shell:roles` — it is ignored optional and ends the session
  mandatory. This is a different reply from the NX-OS one in both halves, which is the concrete
  argument for §8 adapters being per-platform rather than one attribute list with exceptions.

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

  **NX-OS precedence measured 2026-09-22** (`tests/lab/results/L16-cisco_nxos.md`, the section
  "Precedence: `priv-lvl` and `shell:roles` in the same reply"), Nexus 9300v 10.4(2)F, nine
  reply-attribute sets against one deploy and one token login each, then two of them again with
  the device's command authorization pointed at its own role database.

  Everything above sent the two attributes one at a time. **This asks which the device honours
  when a reply carries both**, which is the only shape that decides what an NX-OS adapter may
  send. It is not hypothetical: the owner's production Nexus 9000 (NX-OS 10.3(5)) has a
  read-only server definition that sends `priv-lvl=15` beside an attribute misnamed `roles`; the
  device rejects the misnamed one outright and every operator arrives `network-admin`.
  Correcting the name puts the two in conflict.

  | reply attributes | role the device names for that session |
  |---|---|
  | `priv-lvl=15`, `shell:roles*network-operator` | **`network-operator`** |
  | `priv-lvl=15`, `shell:roles=network-operator` | **`network-operator`** |
  | `priv-lvl=1`, `shell:roles*network-admin` | **`network-admin`** |
  | `priv-lvl=0`, `shell:roles=network-admin` | **`network-admin`** |
  | `shell:roles=network-operator` alone | **`network-operator`** |
  | `priv-lvl=15` alone | `network-admin` |
  | `priv-lvl=15`, `shell:roles=p49-noc` | **`p49-noc`** |
  | `priv-lvl=15`, `shell:roles=nonexistent-role` | **`network-operator`** |
  | `priv-lvl=6` alone | **`vdc-operator`** |

  **1. `shell:roles` decides the role and a `priv-lvl` beside it is inert, in both directions.**
  `priv-lvl=15` with `network-operator` is a read-only account; `priv-lvl=0` with `network-admin`
  is an administrator. So this is not "the more restrictive attribute wins": it is the role,
  whatever the privilege level says. The argument flag makes no difference — optional and
  mandatory name the same role — and the role alone, with no `priv-lvl` in the reply at all,
  opens a session and is delivered.

  **2. `priv-lvl` decides only when no role is sent, and then it picks a role nobody named.**
  `15` gives `network-admin` and `6` gives `vdc-operator`, which agrees with the owner's
  production reading on 10.3(5). Which role a level maps to is a property of the image, not
  something port49 chose or recorded.

  **3. An unknown role name still degrades the session to `network-operator` with `priv-lvl=15`
  beside it.** The privilege level does not fill the gap, and port49 cannot tell that it
  happened: the reply it sent and the record it wrote are identical to the case where the role
  exists.

  **4. The role is a label while port49 authorizes commands, and real privilege when the device
  does.** Under this lab's `aaa authorization commands default group port49 local`, all nine
  sessions configured the device — `network-operator` and `vdc-operator` included — because every
  command went to port49, which permitted it; the role was never consulted. That is finding 5
  above, reached from a second direction. With both command-authorization method lists pointed at
  `local` instead, the same reply that names `network-operator` is refused:

  ```
  hostname nx1
  % Permission denied for the role
  ```

  while `priv-lvl=15` with no role runs it. Note *where* the device enforces it: the
  `network-operator` session was admitted to configuration mode and refused the command inside
  it, so reaching `(config)#` is not evidence of privilege on this platform, and a probe that
  stopped at the prompt would have concluded the opposite.

  **5. The device asserts `privilege=1` on every authorization request** in all eleven sessions,
  whatever the reply carried. port49's `priv-lvl` is not echoed back on the next request, so
  nothing in the request stream says which reply a session got.

  **The adapter rule this supports: on NX-OS send `shell:roles` and never `priv-lvl`.** The role
  is what the device applies whenever both are present, so `priv-lvl` buys nothing; and leaving it
  in costs something real, because it is the attribute that governs the session on every other
  platform in this lab. An adapter that computes a privilege level and sends it here writes a
  privilege into the decision log that the device did not apply, and a reply carrying `priv-lvl`
  with no role is how a session silently lands on a role nobody named.

  *Unmeasured:* the `cisco-av-pair` ambiguity in EOS finding 3 — whether EOS refuses the name or
  the embedded quotes, and EOS finding 4 of 2026-09-22 (the quotes are kept, not stripped) makes
  the quotes the likelier half without settling it; `feature privilege` and its `priv-N` roles,
  which the N9Kv image does not have at all (L3); on **EOS**, `p49-noc` alone under local command
  authorization, which is what would turn "two roles are not a union here" from an inference into
  a measurement; and whether the owner's production EOS release ignores an OPTIONAL `priv-lvl*`
  where vEOS-lab 4.31.2F applies it.

  **A row's conclusion is only as wide as the variants behind it.** Both halves of this row have
  now published a claim broader than what was measured: NX-OS twice read "the session reached
  configuration mode" as a privilege probe while port49 was permitting every command, and EOS read
  "`shell:roles` does nothing" as "no role reaches this platform" without ever sending the
  attribute Arista documents. Neither was caught by a failing test — both tests passed and wrote
  their notes. What caught them was reading the generated paragraph against its own table, and in
  the EOS case an operator saying the lab disagreed with their fleet.

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
  section stands — only the release label on it was wrong**. Corrected 2026-09-23: the eleven
  EOS notes that still carried the old label in their headers (`L1`, `L2`, `L4`, `L5`, `L6`,
  `L7`, `L8`, `L10`, `L13`, `L16`, `netconf`), the EOS entries of the L1, L4 and L13 tables
  in this section and the L3 detail, now say vEOS-lab 4.31.2F (image tagged 4.32.2F). Every EOS note ran
  the one image, `vrnetlab/arista_veos:4.32.2F` — `tests/lab/topologies/eos.clab.yml` has named
  no other since plan 1 — and that image reports 4.31.2F in `L7-arista_eos.md`'s own eAPI
  replies (2026-09-21) as well as here. A tag can be rebuilt, so the tag alone does not prove the
  image was the same: `docker image inspect` on the lab host (2026-09-23) shows one image under
  it, `sha256:8ef33020ece8871b19ddfdddf7f3585b04d2ac3672845b0db88debe8e96ff9c9`, created 2026-09-15, before the first EOS note.

- **L17** — added and measured 2026-09-21, `tests/lab/junos_opts_test.go`, results in
  `tests/lab/results/L17-juniper_vsrx.md` and `L17-juniper_vjunos-router.md`. **vSRX 21.4R3.15
  and vJunos-router 23.4R2-S2.1 agree cell for cell on every item below**, and both offer the
  identical set of `tacplus-options` leaves.

  **The leaves the images offer**, from the device's own completion help, verbatim and
  unmeasured except where a row below says otherwise:

  ```
  authorization-time-interval  TACACS+ authorization refresh time interval (15..1440 minutes)
  enhanced-accounting  Include authentication method, remote port and user-privileges in 'login' accounting
  exclude-cmd-attribute  In start/stop requests, do not include 'cmd' attribute
  no-cmd-attribute-value  In start/stop requests, set 'cmd' attribute value to empty string
  no-strict-authorization  Don't deny login if authorization request fails
  service-name         TACACS+ service name
  strict-authorization  Deny login if authorization request fails
  timestamp-and-timezone  In start/stop accounting packets, include 'start-time', 'stop-time' and 'timezone' attributes
  ```

  **1. `strict-authorization` makes a port49 denial binding, and does not lock anyone out.**

  | | port49 permits | port49 denies `service_unsupported` |
  |---|---|---|
  | SSH login | logged in, class `p49-readonly` | **SSH authentication refused** — no prompt, ever |
  | NETCONF, port 830 | session opens, `<get-configuration>` answered | **refused** |

  This is the correction to L10 reading 3 above. Without the statement the identical denial
  completed the login and changed nothing; with it the login does not happen. **The denial is
  refused at SSH *authentication*, not at shell start**: the operator never reaches a prompt,
  and the client reports an ordinary authentication failure.

  Two things about that are worth an operator's attention. **The device logs nothing the
  operator can use**: `show log messages | match <user>` returned nothing for the refused
  login on either image, so "why was I refused" is answerable only from port49's own record.
  And **the session authorization arrives during SSH authentication, not when the shell
  starts** — measured by authenticating and then waiting before asking for a channel — so
  there is no window between the two exchanges in which port49 could change its mind about a
  login already in flight.

  **2. Break-glass survives it. This is the 3am answer and it is the reason the statement is
  safe to recommend.** With `strict-authorization` committed and **port49d not listening**, the
  local `breakglass` account logged in over SSH in 20ms (vSRX) and 30ms (vJunos-router) under
  **both** `authentication-order [ tacplus password ]` and `authentication-order tacplus`. The
  statement makes port49's answer binding without making port49 a single point of failure for
  the device: it governs what happens when the server *answers*, and L4 reading 3 still governs
  what happens when it does not.

  **3. `enhanced-accounting` adds three arguments, to the `cmd=login` record and nothing else.**
  Exactly as the device spells them, with values it sent:

  ```
  Port=39606                            the client's TCP SOURCE PORT
  Authentication-Type=remote
  User_Perms=view view-configuration    the class's permission bits, as text
  ```

  The owner's "login only" is confirmed: the `stop` records for interactive commands and for
  `logout` are byte-identical with and without the statement.

  **`Port` is the answer to "does anything separate two concurrent sessions of one user".** Two
  shells of one operator, opened back to back on one token (the second out of the receipt, §13
  decision 15), differ in `Port` (`45566` / `45554`), in `session_pid`, and in the TACACS+
  header's own `port` (`0` / `1`). They do **not** differ in `rem_addr`, `service`, `cmd`,
  `task_id`, `Authentication-Type`, `User_Perms` — or in **port49's own `ctx_id`, which is one
  value for both**, decision 15 behaving exactly as specified. Anything downstream that has to
  tell two shells of one operator apart must carry one of those three forward from the record.

  **`session_pid` is sent with or without the statement, and it is spelled with spaces**:
  `session_pid = 31050`, where every other argument in the same record is `key=value`. A
  parser that requires `key=` drops it silently. This test's first run did exactly that and
  published a table saying nothing separated two concurrent sessions, beside a record dump
  that plainly did.

  **4. No accounting record named `root`.** `show version`, `show chassis hardware`, a
  `configure`/`commit` and a NETCONF `<get-config>` were run by a token operator and **every
  record produced names that operator**. The production observation — that `show version`
  triggers an RPC running as root — did **not** reproduce here. That is a statement about this
  image under this lab's `accounting { events [ login change-log interactive-commands ] }` and
  is not a contradiction of what a production fleet sees: a fleet accounting for other event
  classes may well get records this event list never asks the device to send. What port49
  *would* do with such a record is unchanged and is the thing to fix if one appears: accounting
  attributes on `(nas, username)` (§5.8), so a record naming `root` is spooled
  `attribution: unattributed` with no `principal` and an empty `ctx_id` — the command
  attributed, its effect not.

  **5. `authorization-time-interval` re-authorizes a live session — and a DENIED
  re-authorization does not end it.** The minimum the statement accepts is **15 minutes**
  (`15..1440`). With it committed, a second `authorize_session` for a live, idle session
  arrived **15m00s after the login's own authorization, to the second, on both images and in
  both of the two cases run**. port49 answered it `deny`. The session carried on: it answered
  its prompt, and `show system users`, asked from a separate admin CLI while it was still
  open, still listed the login.

  **So the re-authorization is an audit event, not an enforcement point**, and it is the same
  answer with and without `strict-authorization` — that statement governs the *login*, not the
  refresh. Revocation still cannot reach a Junos session that is already open; the most it can
  do is refuse the next login.

  **A port49d restart denies every live Junos session's next re-authorization.** The denials
  above arrived as `deny context_missing` rather than `service_unsupported`, and the reason is
  worth carrying: switching port49's configuration restarts the daemon, the login context
  store is in memory (`internal/store/memory`), and the contexts do not survive. On a fleet
  with `authorization-time-interval` set, restarting port49d therefore hands every logged-in
  operator a denied re-authorization within the interval. On these images that costs nothing,
  because the denial does not end the session — but that is a measurement, not a guarantee,
  and it is the thing to re-measure before recommending the statement to anyone who has also
  made denials binding.

  *Unmeasured:* the other six leaves in the listing above, `exclude-cmd-attribute`,
  `no-cmd-attribute-value`, `timestamp-and-timezone` and `no-strict-authorization` in
  particular; any interval other than the 15-minute minimum; a genuine `root` RPC record, which
  this lab's event list did not produce; whether a denied re-authorization behaves the same on
  a session that is *busy* rather than idle; and production Junos 23.4R2-S8.7, which is the
  release the owner runs and is neither of the two measured here.

- **L18** — added and measured 2026-09-22, `tests/lab/l18_test.go`; results in
  `tests/lab/results/L18-arista_eos.md`, `L18-cisco_nxos.md`, `L18-cisco_iosxe.md`,
  `L18-juniper_vsrx.md`, `L18-juniper_vjunos-router.md`. Every cell in those notes is derived
  from the transcript printed above it rather than written: `session refused` when no session
  opened, otherwise one value compared against the variant named in the note's own
  `read against` column.

  | reply attribute | vEOS 4.31.2F | N9Kv 10.4(2)F | C8000V 17.13.01a | vSRX 21.4R3.15 | vJunos-router 23.4R2-S2.1 |
  |---|---|---|---|---|---|
  | known, MANDATORY | applied | applied | applied | applied | applied |
  | known, OPTIONAL | applied | applied | applied | applied | applied |
  | another vendor's, OPTIONAL | ignored | ignored | **session killed** | ignored | ignored |
  | another vendor's, MANDATORY | **session killed** | ignored | **session killed** | ignored | ignored |
  | invented, OPTIONAL | ignored | ignored | **session killed** | ignored | ignored |
  | invented, MANDATORY | **session killed** | ignored | **session killed** | ignored | ignored |
  | known, unusable value | dropped | applied (`network-operator`) | **session killed** | dropped | dropped |
  | no attributes at all | level 1 | `vdc-operator` | level 1 | `p49-readonly` | `p49-readonly` |
  | per-command authorization follows | yes | yes | yes | **never** | **never** |

  The known attribute is `priv-lvl` on the three Cisco-family platforms and `local-user-name`
  on Junos, which has no privilege level; the foreign one is whichever of `shell:roles` and
  `roles` the platform does not read, and IOS-XE and Junos were sent both. The invented one is
  `p49-nonsense`, spelled with this project's prefix so that a device which happened to know it
  would be a finding rather than a collision.

  **The same three questions on a PER-COMMAND authorization reply, measured 2026-09-22.** Until
  this row asked them they could not be asked: `Lab.Command` returned a bare permit, so there
  was no per-command reply to put an attribute in. `lab.command_attributes` now puts attributes
  on a PERMITTED command reply the way `lab.session_attributes` does on a session one — a lab
  stub, not a policy projection — and `author.Handler` already copied a decision's attributes
  onto the response for both paths, so nothing on the wire changed. Each variant sends the
  control's session reply byte for byte and differs from it only in what a permitted command
  authorization carries.

  | attribute on a permitted COMMAND reply | vEOS 4.31.2F | N9Kv 10.4(2)F | C8000V 17.13.01a | vSRX 21.4R3.15 | vJunos-router 23.4R2-S2.1 |
  |---|---|---|---|---|---|
  | invented, OPTIONAL (`p49-nonsense*1`) | ignored, commands ran | ignored, commands ran | **every command refused** | n/a | n/a |
  | invented, MANDATORY (`p49-nonsense=1`) | **every command refused** | ignored, commands ran | **every command refused** | n/a | n/a |
  | another vendor's, OPTIONAL | ignored, commands ran | ignored, commands ran | **every command refused** | n/a | n/a |

  The Junos cells are `n/a` and not `unmeasured`: no Junos session in this lab has ever produced
  a per-command authorization request at all (L10, L14; decision 21 is written on it), so there
  is no per-command reply to attach an attribute to. The question does not arise there rather
  than going unanswered, and every Junos variant records the request count that says so.

  **Every refusal in that table is a command port49 PERMITTED.** The decision log for those
  sessions holds `permit permit_dominates` for `terminal length 0`, `show privilege` and `show
  version`, and the operator got `Command authorization failed.` on the C8000V and `%
  Authorization denied for command 'terminal length 0'` on vEOS for the same three. **The
  session stays open and nothing runs in it** — the refusal begins at the paging command, which
  is the first reply to carry the attribute, so it is already in force before anything worth
  typing. That is a worse shape at 3am than the session refusals above it: a refused login says
  plainly that something is wrong, while here the login works, the server's own log says every
  authorization succeeded, and the operator is the only party who can see that it did not.

  **The session reply does not predict the command reply.** IOS-XE refuses the SESSION for any
  attribute it does not recognise, so a bad session reply never reaches the command path at all;
  give it a clean session reply and the same attribute on the COMMAND reply, and the session
  opens and every command is refused instead. vEOS applies one rule at two blast radii — an
  optional unknown costs nothing on either reply, a mandatory unknown costs the whole session on
  one and every command on the other. The N9Kv ignores all six, mandatory included, exactly as
  it ignores them on the session path. So §8's per-platform table has two halves, and measuring
  one says nothing about the other.

  **Three behaviours across three vendors, and no two agree, which is the whole answer to
  "may an adapter send one attribute list to a mixed fleet".** It may not. vEOS does what §8.2
  says in both directions, so the argument flag is a working switch there: an adapter that
  wants to be told an attribute did not land can send it mandatory and find out by losing the
  session. The N9Kv and both Junos images do neither half — a MANDATORY argument they do not
  understand opens the session anyway and delivers exactly what the same reply without it
  delivers — so on those three the flag buys nothing and a wrong attribute is invisible rather
  than fatal. IOS-XE refuses everything it does not recognise under either flag, which extends
  L10's 2026-09-20 measurement to a second foreign spelling and to an out-of-range value.

  **On IOS-XE the cost is the device and not the session.** After five consecutive refused
  authorizations the first run could not get an SSH connection at all: three attempts over 50
  seconds, every one refused at the authentication layer, and **no TACACS+ packet for any of
  them** in port49's decision log — the logins either side of them each have a redeem and a
  session authorization and these have nothing. The variant after them connected normally, so
  the device recovers on its own; a later run reproduced it in the recovering form, three
  connections with the first two refused before the device ran AAA. So the refusals never
  reach port49, nothing in its log says the device has stopped answering, the operator sees an
  SSH server refusing their password, and break-glass reaches the same SSH server and is
  refused with them. The trigger is one line in a server definition. *Inferred, not measured:*
  that the vty pool is the mechanism — no `login block-for` is configured.

  **The same typo costs the opposite thing on two platforms.** `priv-lvl=99` is dropped on
  vEOS, leaving the session at level 1 exactly as if nothing had been sent; on the N9Kv it
  lands the session on `network-operator`. With L16's `15`→`network-admin` and
  `0`/`1`/`6`→`vdc-operator`, and no attributes at all →`vdc-operator` measured here, a reply
  carrying a privilege level and no role picks a role nobody named out of a per-release table
  that is now known to have an out-of-range entry.

  **Decision 22's two attributes, measured over `junos-exec` for the first time, on both
  images and agreeing cell for cell.** `local-user-name` **is applied** under either flag: the
  session leaves the device's own `remote` template and lands in the class the reply names,
  carrying a `configure` bit the default class does not have. **`user-permissions` does
  nothing at all** — mandatory, optional, and sent beside `local-user-name`, `show cli
  authorization` comes back byte-identical to a reply carrying no attributes. `view` alone is
  *narrower* than the lab class's `view view-configuration`, so a permissions list that shrank
  would have been proof it landed, and it did not shrink; and the pair is indistinguishable
  from `local-user-name` alone. A template name the device does not have degrades silently to
  the default `remote` template, the same shape as an unknown role name on EOS and NX-OS.
  **This does not close L12**, which also asks about a bitless template, what each bit reaches,
  wire `deny-commands` precedence and numbered attribute names.

  **This narrows L16's open `cisco-av-pair` clause.** The reading drawn from the 2026-09-21
  vEOS run — that EOS refuses an OPTIONAL attribute it does not recognise — does not survive:
  two other optional unknowns, one of them invented, are ignored on that image. So the
  `cisco-av-pair*shell:roles="p49-noc"` refusal is about that attribute rather than about the
  optional flag, and the remaining hypothesis is the quotes in its value. One variant settles
  it and there was no deploy left to spend on it.

  *Unmeasured:* whether IOS-XE's SSH condition is the vty pool and how long it lasts under
  load; every non-SSH transport on every platform; and, on the per-command half, any attribute
  a device DOES read on that path — all six variants above carry something no vendor reads
  there, so nothing here says what a per-command reply can usefully deliver, only what it costs
  to get one wrong. The Junos notes for this row still carry a paragraph saying the per-command
  question cannot be asked because the config key does not exist; the key exists as of
  2026-09-22 and those two notes regenerate on the next Junos run, which this row did not spend
  a deploy on because the answer there is `n/a` either way.

- **L19** — added 2026-09-23, split from L8, which asked about the interactive prompt and PAP in
  one row although the lab reaches PAP only where a device chooses it for an SSH login. With `aaa
  authentication login ascii-authentication` left at its NX-OS default, every exchange from the
  N9Kv arrives as `auth.method=pap` — authentication, NX-API and NETCONF alike — so the NX-OS
  SSH figure in L8 (127 characters intact, 128 never sent) is a PAP figure too
  (`tests/lab/results/L8-cisco_nxos.md`). It was recorded here on 2026-09-20 as 138 characters
  intact under PAP; the 2026-09-23 sweep shows that was wrong.
  *Unmeasured:* PAP on any path other than an SSH login, and PAP on EOS, Junos and IOS-XE, which
  offer it but are not configured for it here — IOS-XE authenticates `ascii(1)` under this lab's
  configuration, like EOS and Junos and unlike the N9Kv.
- **L20** — added 2026-09-23 from L1's RESTCONF run on IOS-XE
  (`tests/lab/results/L1-restconf-cisco_iosxe.md`, "The same credential again"). Catalyst 8000V
  17.13.01a, `ip http authentication aaa login-authentication default`, one seeded token. The
  first RESTCONF request cost one authentication and one session authorization; the same Basic
  credential again, 3s later, got `200 OK` with **no TACACS+ traffic at all** — no decision
  record and no TCP connection from the device between 06:51:23.931Z and 06:51:30.006Z. So it
  was neither a receipt replay nor a redeem. What the device keyed that answer on, and for how
  long it would go on answering that way, are unmeasured.

  **Why it matters: revocation stops at port49.** Everything port49 does to end a token's life —
  single-use redemption, the receipt's `receipt_idle_ttl` and `receipt_max_age`, revocation by
  `sid` or `sub` (§5.1.4) — acts only on the next exchange the device sends. A device that
  answers a repeat without asking sends none, so for as long as it does, a spent token keeps
  working at the device and a revocation in port49 does not reach that repeat. The window is set
  by the device, port49 cannot shorten it, and nothing in port49's log shows it is open. Decision
  15's argument that a captured token lives only while the job is active plus
  `receipt_idle_ttl` holds for the transports L7 and L15 measured, where every repeat reaches
  port49; on IOS-XE RESTCONF it is bounded by this window instead, whose length is unmeasured.

  **The open question that decides how much this matters: a wrong password within the
  window.** If the device keyed its answer on the credential, only the holder of the spent token
  gets in. If it keyed it on the username, or on the client address and username, then *any*
  password for that user inside the window also gets `200`, and the device, not port49, is
  deciding who is authenticated. The run cannot tell these apart, and it decides whether RESTCONF
  on IOS-XE weakens the token model.

  *Unmeasured:* a wrong password for the same user inside the window; how long the window lasts;
  what the answer is keyed on (the credential, the username, the client address, the TLS
  connection); whether a credential port49 would now refuse is re-checked inside it; the same
  question on eAPI and NX-API with Basic credentials on a kept-alive connection, and on every
  other platform.

  **Measured on IOS-XE, 2026-09-24** (`tests/lab/results/L20-cisco_iosxe.md`, by hand, the
  RESTCONF configuration of L1's run). The question that decided how much this matters is
  answered **no**: a wrong password for the cached user, 3s after a successful request, went to
  port49 and was refused `401` — as did a wrong password for another user and for a user port49
  does not know. The cache is keyed on the credential: two users were cached at once, the same
  credential from a second client address was answered from the cache, and neither the user's
  own failed attempt nor another user's cleared or refreshed it. It lasts **about 10s, fixed
  from the authentication that filled it**: a single repeat at 9s was answered from the cache and
  one at 10s went to port49, and a credential repeated every 2.5s went to port49 every 10.07s.
  Inside it nothing is re-checked: with port49 answering every authentication ERROR, a credential
  cached 2s earlier kept getting `200` with no TACACS+ packet sent. So the device, not port49,
  decides for those 10s — but only for the holder of the exact credential, and past them the
  repeat reaches port49 as `receipt_replayed`, which `receipt_idle_ttl` bounds as decision 15
  intends.

  *Still unmeasured:* eAPI and NX-API with Basic credentials on a kept-alive connection;
  NETCONF-YANG on IOS-XE; whether any IOS-XE setting changes the 10s.
- **L21** — added 2026-09-23 by plan 4 and measured 2026-09-24 over interactive SSH on all three
  platforms it names (`tests/lab/results/L21-arista_eos.md`, `L21-cisco_nxos.md`,
  `L21-cisco_iosxe.md`). Typed `sh ver`, `sh ip int br`, `sho run`, `sh clock`, `show clock`,
  `conf t`, `hostn <name>`, an abbreviated interface, `desc`, `no desc`. **Every image resolves
  before it asks**: each abbreviation arrived as the full keywords (`cmd=show cmd-arg=version`,
  `cmd=show cmd-arg=running-config`, `cmd=configure cmd-arg=terminal`), and `sh clock` was denied
  by the lab's `show clock` deny on all three, with the same record the full spelling produced.
  The accounting record carries the resolved words too — as the command line on vEOS and IOS-XE,
  and on the N9Kv as the whole configuration path (`configure terminal ; interface Ethernet1/1 ;
  description p49-l21 (SUCCESS)`), written twice for a submode command, with no record at all
  for a `show`. Interface names are not uniform: IOS-XE sends `int Gi1` as two arguments,
  `GigabitEthernet` and `1`; vEOS and the N9Kv send one, `Ethernet1` and `Ethernet1/1`. So
  `expands_abbreviations` may be `true` for these three platforms over SSH, and a rule naming
  an interface has to be written per platform.

  *Outside what was measured:* eAPI, NX-API, NETCONF and RESTCONF; abbreviations inside a pipe;
  other releases.

Entries are added when a new claim is made, never removed. A closed entry keeps its row so a
later reader can find the evidence.
