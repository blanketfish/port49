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
them, and it has exactly two forms — an LDAP group (of people, `group:`; or of workloads,
`machine_group:`, §13 decision 41 ruling 5, plan 8b), or one or more literal identities. That
single mechanism covers both directory-driven human access and hand-maintained service
accounts. A group is named by its name (the entry's `broker.directory.group_name_attribute`, `cn` by
default), matched only while exactly one group under `broker.directory.groups_base_dn` has it,
or by its DN. A principal matches every subject whose group it is in, transitively under
`broker.directory.nested_groups`, and the one identity subject that lists it, if any; the
grants of all of them compose (§5.1; §13 decision 38).

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
string in no recognized form is itself a load error. A `spiffe://` identity must be a SPIFFE ID with a path, in the form SPIFFE ID §2 gives (lower-case
scheme and trust domain; path segments of `A-Z a-z 0-9 . - _`, never empty, `.` or `..`; no
trailing `/`; at most 2048 bytes): one outside it is a load error, never folded to fit (§13
decision 40 ruling 4). At runtime the domain is never read from
the string; it is whichever verifier validated the credential (design document §7).

**Each verifier produces the principal string, prefix included**, so the runtime string and
the policy string are the same string and the subject matcher is a comparison:

| Verifier | Principal string |
|---|---|
| human x509 | `user:` + the entry's `principal_attribute` (default `userPrincipalName`), lower-cased, from the certificate-to-directory mapping (design document §7); without `broker.directory`, `user:` + the certificate's one email SAN |
| human OIDC | `user:` + the claim `broker.identity.humans[].principal_claim` names (required, no default: `preferred_username`, `email` only with `email_verified: true`, or `upn`), lower-cased, printable ASCII with an `@`, its domain one of the verifier's `principal_domains` (§13 decision 39 rulings 6, 22, 23) |
| workload x509 | the leaf's one URI SAN, verbatim: a SPIFFE ID with a path (`spiffe://<trust domain>/<path>`, SPIFFE ID §2), its trust domain one of `broker.identity.machines[].spiffe_trust_domains`; the leaf not a CA. Zero or several URI SANs, another URI, an ID with no path, or an unlisted trust domain is `identity_unmapped` (§13 decision 40 rulings 3 and 4). Its email SANs are never read |
| port49-issued certificate | the principal the human OIDC verifier gave at the sign-in it was issued on, from the certificate's subject CN, never mapped again; the sign-in's issuer must still be a human verifier's whose `principal_domains` hold it (§13 decision 43 ruling 10) |
| Kubernetes | `system:serviceaccount:<namespace>:<name>` from the token's `sub` |
| machine OIDC | `app:` + the token's `azp`, else its `client_id` claim, verbatim: a client the verifier's `clients` lists, the token's `sub` that client's pinned identity; a token carrying a person's session claim (`auth_time`, `sid`, `nonce`, `scp`, `amr`) or an `idtyp` other than `app` is never a machine's (§13 decision 39 ruling 21) |

Every example in this document that shows a principal shows the prefixed form. §5.1.4's
`credential.method` takes `cert`, `oidc`, or `k8s`, matching the verifier types.

The amendment removes the human OIDC row's former "`preferred_username` by default": OIDC Core
§5.7 says a relying party must not rely on that claim being unique, and Keycloak's documented
default is the bare username, which has no `@` (§15 L46 measured `alice` for a user created as `alice`), so a default would refuse
every Keycloak user whose username has no `@` (§13 decision 39 ruling 23).

A principal's trust domain is the list its verifier is in, `broker.identity.humans` or
`broker.identity.machines` (§13 decisions 16 and 39), and nothing in the credential decides it.
A token two verifiers would accept is refused. A person's delegated token never becomes a
machine principal, and no two OIDC issuers can give one human principal: each human verifier
names the `principal_domains` it is authoritative for, and two that overlap are refused. Nor
can two issuers give one machine principal: `app:` carries no issuer, so two machine
verifiers on different issuers that list one `client_id` are refused.

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
| `revoke_others` | `/v1/tokens/revoke` naming another principal (a standing mark), or a `(device, username)` key whoever holds it; or an OIDC session by `sid` and issuer (§5.1.4; §13 decision 39) |
| `explain_others` | `/v1/explain` for a principal other than the caller |
| `sync` | reserved: no broker endpoint triggers a sync; the inventory service authorizes `POST /v1/sync` by its own `syncers` list (§10) |
| `keys_show` | reserved: nothing renders a device key's secret (§12) |
| `replay` | reserved: no endpoint reads the decision log |

A reserved right may be declared, and CI reports it and the gate fails on a gain as for any
other, but it grants nothing until an endpoint it guards exists (§13, decision 34). No right
reaches `/v1/tokens` or `/v1/refresh`: a mint is for the connection's principal, and a refresh is
a fresh authentication of the caller's own key (decision 17), so it extends the caller's
sessions alone. `/v1/identity` answers the caller alone. Rights are read from the policy in force
at each request, so a right withdrawn by a reload is gone at the next call; a group subject's
members hold its rights once the directory resolves them (plan 7g).

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
| OIDC | with `broker.directory`, the directory's `username_attribute`, read for the principal as a certificate's is; without it, the identity subject's declared `username:`. The `preferred_username` claim is never a username (§13 decision 39) |
| certificate | via the certificate-to-directory mapping (§7 of the design document) |
| workload certificate, mapped | its identity subject's declared `username:`; else the entry's `username_attribute`, found by the SPIFFE ID (§13 decision 41 ruling 4, plan 8b) |

With `broker.directory`, a `user:` identity subject declares no `username:`; the broker refuses
one at load. Without it, one is required, as before plan 7g.

**Machine identities have no directory entry**, so the subject declares one. A machine principal is
never sent to the directory, at mint or by the scheduled refresh, unless it is a workload
certificate whose verifier maps it (`broker.identity.machines[].directory`, §13 decision 41, plan
8b, 2026-10-09). Such a workload takes its identity subject's declared username when it declares
one, else its entry's `username_attribute` under §13 decision 38 ruling 3, and matches
`machine_group:` subjects. No machine principal matches a human `group:` subject, then or after
(§13 decisions 16 and 40 ruling 5):

```yaml
subjects:
  - name: svc_oxidized
    identity: ["system:serviceaccount:netops:oxidized"]
    username: svc-config-backup        # what the device will present
```

**Usernames MUST be unique across subjects, and CI can only check half of it.** Declared
machine usernames are checked against each other at load. Human usernames come from the
directory at mint, so a machine subject declaring `username: alice` collides with a human
`alice` only at runtime; the broker checks at bind, at mint and at every refresh, and refuses the
directory's claimant `username_collision` with a reason naming both: the declared username stands,
whichever came first, so a directory administrator who renames a person cannot take a workload's
contexts (§13 decision 38 ruling 3; decision 40 ruling 6). Two subjects claiming one username collide in
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

When several subjects compose and one of them offers escalation (`enable` `token` or `auto`), a
subject whose `enable` is `none` contributes to the ceiling that `enable` can reach only the
level its roles reach, capped by its own `max_privilege`: the level it already holds without
enabling, never its bare cap, and it never creates a ceiling where the subjects that offer
escalation state none. Otherwise a subject that cannot escalate, stating a high ceiling,
would hand it to another subject's `enable`, and the composition would reach a level no single
subject reaches; and its own login level never sits above the ceiling. A refusal that follows
from a cap not counted names it. The
composed `enable` is still the strongest single subject's.

**Several subjects compose.** A principal in two groups, or listed by an identity subject and
in a group, holds the union of their grants, as one subject's grants compose. What a subject
declares for itself composes so as never to weaken any one subject's demand: `token_ttl` is
the least, among the matching subjects with a grant on the device; `enable` is the mechanism
demanding the most proof among those that offer one (`token`, then `auto`, then `none`); `api:`
rights are the union. The joint checks of §10 run per subject at load; a composition of more
than one subject is checked at mint, and one a check refuses is `composition_refused` for that
principal on that device (§13 decision 38).

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
  refreshed_at      1757041495           last verification (5.1.3); the staleness clock
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

`refreshed_at` is written at creation (the membership's verification time, on a directory
login) and on every scheduled refresh that verified the membership (§5.1.3), and on a session
refresh (§5.6) as the earlier of the membership's verification and now; a policy refresh never
writes it. When `now - refreshed_at`
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
   compile (§10). So is a file that takes more than `inventory.max_removed_percent` of the devices in
   service under the policy in force (admitted, and not quarantined) out of service at the reload,
   counting the devices it newly refuses admission and the devices it newly quarantines together,
   or that admits no device at all whatever the bound (§10; §13 decision 34). A reload after which
   at least as many devices are in service as before it, counting only devices the inventory before
   it held, is not refused for the two together (a net release): a device the same reload adds
   never offsets one it takes out of service, so padding the inventory cannot pass the bound. A
   release never offsets a refusal: a file that newly refuses admission to more than the bound of
   the devices the policy in force admits, quarantined ones included, is refused whatever it
   releases (plan 6a's bound), since a refused device's tokens and contexts are deleted and a
   revert does not bring them back. A quarantine a grant
   expiry brings on later is not judged at the reload (`port49 policy diff` fails on it). A refused
   file also keeps any grant it withdrew: `port49 revoke` cuts a principal off whatever the file. A
   refused file stays on disk, and a start has no policy in force to bound against, so a restart
   would load it unguarded: port49d's refusal line says so, redacted as its other policy lines are
   (§5.8). Nothing is
   half-applied. The timer is
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
   alarm. A context the refresher cannot open because it fails authentication — a tampered
   record — cannot be judged against the policy in force and is not left on the one before,
   so it is revoked the same way and counted `failed`. One sealed under a key this port49d
   does not hold — a key that has left the two-key window, or a mis-set `PORT49_ENC_V1` — is
   not revoked: it is said, counted `failed` and left for the next pass. Revoking it would turn
   one key mistake into every session on the fleet ending, which fixing the key would not undo;
   no login can open it meanwhile, so it is denied anyway (§5.6). Its owner
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
   `ctx_id` in the process log, and the `refresh` record carries `session.unreached: true`
   (§5.7). `auth_time`, `refreshed_at` and the idle TTL are not touched, and `session_expires`
   only moves earlier, to `auth_time` plus the ceiling the policy in force gives (decision 33),
   named on the record as `session.session_expires`: nothing about the operator's
   authentication or the directory was re-verified, and a reload is not activity.

Every policy edit changes the bundle (§5.7), so every live context takes a new blob at a reload and
the records decided after it name the policy that was in force. The one exception is a login
redeeming a token kept across the reload (below): its context takes the superseded bundle's
blob, whose answer is the same, and whose `blob` record is already in the log (§5.1.1), so its
records still replay. A change the refresh makes is a `refresh` decision record (§5.7) naming
the context's `ctx_id`, so the record before a command's changed answer says why:

| The refresh | `verdict` | `reason` |
|---|---|---|
| wrote the policy in force into the context | `permit` | `grants_matched` |
| revoked it: no grant left on the device, the subject's username changed, or the device left the inventory | `deny` | `no_grants_matched` |
| revoked it: admission refuses the device — no key group admits it, two tie on it, or its key is not held (§10) | `deny` | `device_unknown` |
| revoked it: the policy in force could not be resolved or compiled for it | `deny` | `blob_unavailable` |
| revoked it: the context could not be opened, failing authentication (the record names no principal) | `deny` | `blob_unavailable` |
| left it as it was: the device is quarantined (recorded once per context per bundle) | `deny` | `device_quarantined` |
| revoked it: the principal's directory entry is gone, or no longer gives a usable principal or username | `deny` | `identity_unmapped` |
| revoked it: the principal now maps to two or more entries | `deny` | `identity_ambiguous` |
| revoked it: another entry, or a declared subject, now holds the principal's username | `deny` | `username_collision` |
| revoked it: the principal's subjects compose on the device to a reply a joint check refuses | `deny` | `composition_refused` |

A scheduled pass that stamps `refreshed_at` on a context whose answer did not change writes no
record.

Each context is counted once per pass in `port49_context_refreshes_total{outcome}`: `updated`,
`unchanged`, `revoked`, `quarantined`, `failed`, `unverified`. A context already on the answer, and one a
store error stopped the pass at, has no record (§5.7).

A swap that changed only the inventory — every policy since the last complete refresh read from
one policy file — leaves a context as it is when its blob differs from the new one only in the
bundle it names: the answer did not change, so nothing is written and nothing is recorded, and
the context goes on naming the bundle that compiled it, which is still true. A policy edit keeps
the rule above: every live context takes the new bundle's blob.

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

With several port49-broker processes on one store (plan 7e), the one holding the keyspace (the
runner) carries each policy into the live contexts; every process deletes the unspent tokens
its own policies minted that the policy in force would not give. port49d carries nothing: it
reloads its policy for admission, quarantine and redaction alone. With every broker stopped, an
edit changes admission at once and live contexts when a runner returns (§13, decision 36).

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
context skipped as busy, a context sealed under a key port49d does not hold, a principal whose
contexts could not be looked up, or a pass stopped by a store error, keeps it at 1 until a later
pass reaches that context — the alert for a policy in force that has not yet reached every live
session. It is never 0 while a settle pass is outstanding: until then a login in flight may
still write the superseded answer. A context revoked for a compile fault is
done: revoked is its answer under the policy in force, so it does not hold the gauge, and it is
counted `failed` in `port49_context_refreshes_total`, which is its alarm.

**The scheduled refresh** (plan 7g; §13 decision 38) runs every `broker.refresh_interval` (default
5m; approved by Ryan, OR-1, §13 decision 38) on the broker holding the keyspace. For
each `user:` principal in `active_principals` it reads the principal's directory entry and groups
again, from a server, never from grace; judges each live context against the policy in force with
that membership, writing as a policy refresh does; and stamps `refreshed_at` with the membership's
verification time on every context it judged, changed or not. A principal the directory did not
answer for is left as it is and unstamped, counted `unverified` in
`port49_context_refreshes_total`, and its sessions deny `context_stale` once
`session.staleness_ceiling` passes (§5.1.1). A principal whose entry is gone, is ambiguous or has
its username taken has every context revoked. A machine principal (`spiffe://`,
`system:serviceaccount:`, `app:`) is never sent to the directory unless it is a workload
certificate whose verifier maps it (§13 decision 41 ruling 6, plan 8b, 2026-10-09), which is
verified and stamped as a `user:` principal is: it is otherwise judged by the policy alone and
stamped with the pass's instant. Without `broker.directory`, the pass judges against the
policy alone and stamps its own instant: the ceiling then bounds a broker outage. A policy refresh
never stamps `refreshed_at`, and judges a group member by the membership last verified (held in
the store; design §12), or by no groups where none is held, where the directory refused the
principal, or where it was verified longer ago than `broker.directory.grace`: a policy refresh can
narrow on an old membership, never widen.

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

**A certificate port49 issued** (plan 9b; §13 decision 43) carries both halves: `method: cert`
with its fingerprint, issuer (the broker's issuing CA), serial and subject, and the `iss`, `sub`,
`sid`, `amr` and `acr` of the OIDC sign-in it was issued on, read from its one URI SAN. So a
back-channel logout naming that `sid` reaches the certificate's sessions, and a revocation by its
serial reaches them too. Its `notAfter` bounds the mint and the refresh, as any certificate's does,
and never a session.

**Consequence for the store.** Context now holds identity material — subject DNs, `sub`
claims, an operator's name. None of it is a credential, but it is PII-adjacent, so **login
context MUST receive the same encryption-at-rest treatment as tokens** (design document §8).
That obligation previously covered tokens alone.

**Revocation by principal or by certificate, as built (plan 7a; §13, decision 32).** An operator
revokes with `port49 revoke` over port49d's admin socket (§12), naming a principal, or one
certificate by its issuer and serial. A revocation is a **standing mark**, kept in the store and
in `broker.revocations_file`, so a restart forgets none, and it stands until an operator lifts it
(`port49 revoke --lift`). A principal's mark refuses every mint by that principal, on any
connection and with any certificate; a certificate's refuses every mint made with it, but does not
keep a context revoked: a login on the device whose token another of the principal's certificates
minted after the revocation joins the context and lifts `revoked_at` (§13, decision 15). A mark
does not expire, because the agent reconnects with the same key on its own, and a mark a fresh handshake
could outlive would be undone without anyone acting.

The mark is written first, and then the revocation reaches everything it names, in this order:
the held broker connections are closed; the unspent tokens are deleted, through
`tokens_by_principal` and `tokens_by_cert`, indexes the minter writes before each token, so no
token exists that a revocation cannot find; every live context indexed under the principal or the
certificate is marked `revoked_at` (§5.6, teardown row 2) and the receipts of the principals behind
them are deleted; and the context index is read and marked a second time. Tokens go before
contexts because a token redeemed on a device with no live context writes a fresh context the
revocation never saw; the second pass catches a redemption that was in flight. With the receipt
deleted and the token spent, a device's retransmission of a login made before the revocation is
answered `token_not_found`, not replayed and not `credential_revoked` (§5.6); deleting the receipt
also closes the one unchecked replay, the concurrent duplicate's (§5.6). A redemption that
removed its token before the delete and writes its context after the second pass writes it
revoked: a login's context write checks, in the same atomic step, that no mark stands for its
principal or its certificate (plan 7d; §13, decision 35), and the mark is written before
anything else. The daemon also reads the standing marks on every authorization, so a context a
revocation by principal or certificate never reached is denied anyway. A self or key
revocation leaves no mark, so for those the window of one store round trip stays. Deleting by
certificate deletes every unspent token under each `(device, username)` key that certificate
minted under, the same principal's other certificates' included: the store holds no finer cut,
and the error is toward denying. A principal is compared as `Identity` spells it, `user:` and the
lower-cased email.
The broker's listener holds the marks in memory too, so a connection made with a revoked
certificate, or by a revoked principal, is answered `credential_revoked` and closed as it binds,
and cannot close its owner's other connections. Its one request is answered as a mint under the
mark is, and recorded as one (§5.7), but reaches no handler and no store. A mint reads the marks
before anything else and again after its last token write, and deletes what it wrote if a mark
appeared: whichever of a mint and a revocation reads the other's write, no token minted under a
revoked credential survives. The store's marks are read at mint, not at the TLS handshake:
`port49 login` touches no store (design document §12). A revoked operator's `port49 login` is therefore
refused `credential_revoked` at the agent's first request, from the listener's copy, and a mark
that lands after the agent's connection bound refuses its next mint `credential_revoked`; either
ends the agent's session. Each revocation is one `revoke`
record (§5.7) naming what it reached and the live contexts it could not, on a platform that never
asks about a command (§13, decision 21) or on a device the inventory gives no platform. Revocation
from a CRL or an OCSP response arrived with plan 7b, as a mark of this kind where the certificate
is still held (see below); an OIDC back-channel logout, by `sid` or `sub`, with plan 7h, as no mark
(below).

**A workload certificate, as built (plan 8; §13 decision 40).** A workload certificate is a
certificate credential like a person's: `method: cert`, its fingerprint, issuer, serial and
subject, and the marks, `certificate_status` and the listener's copy apply to it unchanged. Its
principal is its SPIFFE ID, so a renewal, which brings a new serial under the same ID, needs
nothing from port49, and a mark by certificate does not follow it: to stop a workload, revoke its
principal (`port49 revoke --principal spiffe://…`), which refuses every certificate it renews to,
and revoke the certificate at its CA so it cannot be renewed. `port49 revoke` says so when the
certificate's issuer is the workload anchor's subject, or an issuer the broker has seen on a
verified workload chain. A workload certificate presented with less
than a quarter of its validity left is said once a day and counted in
`port49_workload_certificates_renewal_late_total`: its renewal is late, and expiry is refused
`trust_domain_unresolved` as a person's is.

**Over HTTP, as built (plan 7c; §13, decision 34).** `POST /v1/tokens/revoke` takes one of three
bodies, and is refused 400 for any other (a principal and a key together, `mine` beside a
principal, a `sid` beside a principal or a key, an unknown field):

- **`{"mine": true}`, or a principal equal to the caller's**, ends the caller's own sessions and
  leaves no mark. Its unspent tokens are deleted one by one, so another principal's under a
  shared `(device, username)` stay. Its live contexts are marked by compare-and-set on the
  revision read, so a context another principal's login replaced is never marked, and they are
  marked twice. Its receipts are deleted everywhere, even with a key named: the store has no
  finer cut, so a retransmission in flight on another device is answered `token_not_found`. With
  `device` and `username` beside `mine` it does that on that key alone, and only where the
  caller's own records name the key: it reads nothing of another principal's there, so its cost
  says nothing of who holds the key (design §17). Nothing stands after it:
  a token minted later joins the context and lifts the mark (decision 15), for every session
  open under that `(device, username)`. So if anyone else used the caller's token, the caller's
  next login on that device re-admits their session too: the response says to close such a
  session on the device, or ask an operator to revoke the principal, before logging in there
  again. A principal equal to the caller's is answered with a first line that says no mark was
  made, and that locking it takes an operator on the admin socket.
- **`{"principal": …}` naming another principal**, under `revoke_others`, is the revocation
  above, a standing mark, with origin `api <caller>`; without the right it is refused 403
  `api_right_missing` and recorded. The response names the target's subject. A lift is made on
  port49d's admin socket; with no `admin_socket` configured the response says lifting needs
  port49d stopped, the entry removed from this file, and a start.
- **`{"device": …, "username": …}`**, under `revoke_others`, ends whatever holds that key: every
  unspent token under it, and its live context whoever's it is, with the owner's receipts. It
  leaves no mark, so the owner's next login on that device re-admits any session still open
  there: the response says to close it on the device. Without the right it is refused 403
  `api_right_missing` and recorded with the key: the request's form, never the caller's rights,
  decides what it means, and the caller's own session on one key is `mine` with the key.
- **`{"sid": …, "issuer": …}`**, under `revoke_others`, ends one OIDC session as a back-channel
  logout by `sid` does (below), its origin `api <caller>`. `issuer` may be omitted when exactly
  one human OIDC verifier is configured. Without the right it is refused 403
  `api_right_missing` and recorded.

A lift and a revocation by certificate are the admin socket's alone. One that cannot take the
revocation slot within 10 s is answered `503 revocation_busy`, nothing revoked. A self or key
revocation takes no slot, and one caller has one in flight at a time: a caller's second self or
key revocation, while its first is still running, is answered `503 revocation_busy` at once,
with `Retry-After`, nothing revoked. Neither busy answer writes a record. The response
says what was reached, names the contexts on a platform that never asks about a command, and
repeats the text `port49 revoke` prints. The agent waits on a revocation past these bounds (the
slot's 10 s, the run's `RevokeTimeout`, the file's save) and never sends one twice once it began
writing it: one it sent and got no answer to may be in force, and `port49 revoke` says to check
`--list` or the decision log before running it again.

**Certificate status, as built (plan 7b; §13, decision 33).** The broker checks every client
certificate, and every certificate above it in its verified chain but its trust anchor, against the
sources `broker.certificate_status` names.

- **CRLs.** Each is read from a file or fetched over HTTP(S), polled every `refresh_interval`, and
  retried with backoff from 30s when a load fails. Each source names the CA certificate that signs
  it (`issuer_file`), which must be a trust anchor (either list's) or signed by one.
- **Verified before use.** A list is verified against that certificate before anything uses it: an
  unverified list never replaces the last good one, never moves its CRL number, and is never acted
  on.
- **What is refused.** A list older than the last good one (by number or by `ThisUpdate`); a delta
  list; one carrying a critical extension other than its authority key identifier, its number, or
  an issuing distribution point that says only `onlyContainsUserCerts`, a distribution point named
  by `fullName`, or both; one with an entry carrying a critical extension. An issuing distribution
  point saying anything else (`nameRelativeToCRLIssuer`, `onlySomeReasons` even when empty,
  `indirectCRL`, the CA or attribute scopes, a field port49 does not know) is refused, and so is
  one not in DER (its fields out of order, a default spelled out, bytes left over).
- **Which list applies.** It applies to a certificate when its issuer certificate is the one that
  verified it, and only until its `NextUpdate` (one with none, for `refresh_interval` from its
  `ThisUpdate`). A list scoped `onlyContainsUserCerts` covers leaves only, never an intermediate.
  A list whose issuing distribution point names a distribution point covers only a certificate
  whose CRL distribution points extension carries one of those names, byte for byte (RFC 5280
  §5.2.5); a certificate with no such extension, or another name, is not covered by it. A
  distribution point in the certificate that carries `reasons` or a `cRLIssuer` names nothing.
  A list that does not cover a certificate never says "not revoked" for it, but its revocation
  still stands (Precedence) (§13, decision 40, ruling 17).
- **Persistence.** The last good list of each source is kept beside `broker.revocations_file`, so a
  restart keeps it.
- **OCSP.** An answer is taken only when it verifies for the issuer, and its signer is the issuer or
  a delegate the issuer signed carrying `id-kp-OCSPSigning` inside its validity. Its serial must be
  the certificate's, its `ThisUpdate` no more than five minutes ahead, and its `NextUpdate`, when
  set, still to come; with none, its `ThisUpdate` must be within `refresh_interval`. It is cached
  until the earlier of its `NextUpdate` and an hour. Which responders apply to a certificate, and
  which failures are an outage rather than uncovered, is decision 40 ruling 7's.
- **Precedence.** A verified list from the issuer that names the serial is final, whether or not
  its scope covers the certificate (serials are unique per issuer, and an indirect list or an entry
  naming another issuer is refused); otherwise a fresh list covering the certificate decides, and
  then OCSP.

A certificate a source revokes is answered `credential_revoked` before its connection binds, as a
marked one is, and refused at every mint and refresh; so is every certificate under a revoked
intermediate.

When a list newly names a certificate something still holds (a held connection, a live context
indexed under it, an unspent token), the broker revokes it as `port49 revoke --cert` does, its
origin `crl <name>`. Everything it reaches is reached, and the mark outlives a list that later goes
stale. An OCSP response answering `revoked` for a leaf at bind, mint or refresh revokes it the same
way, its origin `ocsp <responder>`. A `certificateHold` entry, a revoked intermediate, and an entry
nothing holds write no mark: each is refused at every use. A mark whose origin is `crl …` or
`ocsp …` is answered as the CA's revocation and names no lift; an operator's mark names
`port49 revoke --lift`.

A status that cannot be established (a stale list, a responder that does not answer, an issuer no
source covers) is refused unless `on_unavailable: allow`. The refusal is answered as unavailable
(HTTP 503, retried but for an uncovered issuer, which is final at `port49 workload`, §13 decision 40 ruling 7), never as a final verdict, so it ends no agent's session. An unavailable status
never affects a live session: the daemon never reads certificate status (decision 13). The
configuration is required with a broker, and `disabled: true` is the explicit choice not to check.

**Back-channel logout, as built (plan 7h; §13 decision 39).** An identity provider ends a
session by posting a logout token (OpenID Connect Back-Channel Logout 1.0) to `POST
/v1/logout`. It needs no client certificate and no `api:` right: it authenticates by the
provider's signature. The token is validated as an ID token is (§13 decision 39), against
the human OIDC verifiers alone (`aud` and `azp` as for an ID token), and then: `iat` no older
than 24h, `exp` honoured when present, a `jti`, the back-channel logout member in `events`, no
`nonce`, and a `sub`, a `sid`, or both. A `jti` seen before is answered 200 and does nothing.

A logout is not a standing mark: the person may log in again, and only an operator's
`port49 revoke` bans. After a logout by `sub` (every Keycloak logout, below) a new login's token
is refused until the logout's `iat` plus `clock_skew` has passed: its `iat` cannot be told from
that of a token issued before the logout by a provider node whose clock runs ahead, so the
window fails closed. The refusal names the time from which a login is taken (§13 decision 39
ruling 13; Ryan's ruling B, 2026-10-07, measured by the L45 follow-up run). A logout token carrying both `sid` and `sub` is a logout by `sid` and then
a logout by `sub`, each as below: a provider's "sign out user" over several sessions sends one
token naming one session's `sid` and the person's `sub` (Keycloak, L45), which no claim tells
apart from ending one session, so port49 ends every session of that `sub`, failing closed at
the cost of a fresh login for a person who ended one session (§13 decision 39 ruling 13). A
logout by `sid` through `/v1/tokens/revoke` names no `sub`, and ends that session alone. Each
logout reaches, in order:

- **A logout record**, written first, kept `max_token_age` plus twice `clock_skew` (on a broker
  that issues certificates, `max(max_token_age, 24h)` plus twice `clock_skew`, 24h being the
  longest certificate it may issue; §13 decision 43 ruling 16). By `sid`, it
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

One `revoke` record is written per logout, `by: sid` or `by: sub` (both, `sid` first, for a
token carrying both), origin `backchannel_logout <issuer>` (§5.7). With no mark, a redemption that removed its token before the delete and writes its
context after the second pass writes it unrevoked: one store round trip, as for a self
revocation. A logout whose store writes fail is answered 503, so the provider may send it
again; whether it does is the provider's (§15, L45).

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

This is port49's evaluation. What a Junos device is told of it is §8's: on set 1.1.0 this deny
fails closed, since `cluster` is no proven keyword, and so would any deny beneath `view` (§11).

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

Two match keys read the device record rather than its attributes: `platform`, its platform, and
`name`, its inventory name, which pins a scope to named devices (§10). An attribute named either
is not read by a scope. `name` takes a string or a list, never a comparison.

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
| `refreshed_at` | the joining login's: the earlier of its token's `verified_at` and now (§13 decision 38) |
| `last_touched_at` | now |

**A login into a revoked context is refused.** A login whose resulting context carries
`revoked_at` answers FAIL `credential_revoked` — the answer the `enable` gate gives for the same
state — and its token is spent, so a token the revocation was meant to stop gets no second try
(ruled 2026-09-23; made one rule in plan 3). There are five ways to get there. The context the login
would join is already revoked and the token was not minted after it: refused before anything is
written. The same principal's context past its ceiling, replaced carrying a revocation the token
predates; a context the sealing layer cannot open, replaced carrying its plaintext `revoked_at`;
a revocation that lands between the login's read and its join, merged by the join; and a
revocation mark standing for the login's principal or certificate, on a token minted before it,
read in the same step as the write (plan 7d; §13, decision 35): each has already
written the context when it is refused, and that context is revoked, so every authorization against
it is denied anyway until the idle TTL reclaims it. The `redeem` record carries the principal, the
`ctx_id` and `session.revoked_at`, the revocation that refused it. A retransmission is answered from
the live context, not from the status the receipt stored: while the context it names is revoked it is
refused `credential_revoked` again (unless an operator's revocation deleted its receipt, below). A token minted after the revocation joins and lifts it, by the
table, and a refusal made after the join has therefore marked its receipt failed (the receipt was
written PASS before the join): once the revocation is lifted, the retransmission replays the
refusal, FAIL `receipt_replayed`. It is not replayed as a PASS: a join that leaves the context
revoked witnesses no login, and a login's PASS replays only for a login the context witnesses
(below; plan 7d). That holds for the concurrent duplicate that lost the redemption race too,
which plan 3 left unchecked (pre-flight F16). A revocation that lands after the join's write is not seen by
the login, which answers PASS; its first authorization is denied `credential_revoked`.

A login is **not** a join, and writes a fresh context whose `redeem` record carries
`session.replaced_ctx_id`, in two cases: the live context belongs to **another principal** under
the same username, or it is **past `session_expires`**. A ceiling ending is not a credential
verified again, so the same principal's `revoked_at` carries across that replace by the rule in the
table. A context the idle TTL has reclaimed is absent, and the login writes a fresh one with nothing
to name. The join is a compare-and-set on the context's revision, so a revocation, an accounting
annotation, a privilege raise or a refresh that lands mid-login is merged rather than erased, and
two simultaneous logins both land.

**A replace unindexes what it displaced, in the same step that writes the new login's context
and index**, so a later revocation of the displaced credential does not reach the context that
replaced it. What it unindexes depends on whose context it was:

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

The context write, the unindex and the index are one atomic step (plan 7d; §13, decision
35): it lands only while the context, the ref's index record and the marks the login read
are as read, and otherwise reads and decides again. So no window leaves a joined login's
`sid` unindexed, and no replace leaves the survivor under the loser's keys.

A store port49 cannot reach fails the login `store_unavailable`: before the token is spent
when the redemption fails, and after it when the step that writes the context fails. A
context and its index that cannot be written together are never written apart, so a login
is never admitted with a context no revocation can reach. An ERROR whose write timed out
may still have committed: the context is then indexed, so revocable, and a retransmission
replays the receipt; if it did not commit, the retransmission is `token_spent`. A record the
store returns but port49 cannot open — sealed under a key that has left the two-key window, or
failing authentication — cannot be joined, and is **replaced fresh** through the same
compare-and-set: the replace carries the record's plaintext `revoked_at` by the rule in the table,
whoever its principal was, because the principal is sealed; the `redeem` record carries
`session.replaced_unreadable: true` and no `replaced_ctx_id`, because that id is sealed too; and
the unreadable login's index entries cannot be named, so the replace clears every key the context
was indexed under, as another principal's replace does, in the same step as the new login's
index. Left in place they would not age out at `index_ttl`: every extension of the replacing
context re-stamps them, so a revocation of the displaced credential would reach it for as long as
it lives. Each such login opens the record twice (the read before the token is spent and the
join's own), so
`port49_crypt_open_failures_total{record="context"}` counts at least two per login. Every read of
such a record counts `port49_store_operations_total{outcome="unreadable"}`, not `outcome="error"`:
the store answered, and a key rotation must not read as a store outage.

A retransmitted login or `enable` replays its receipt only while the receipt's `ctx_id` is the live
context's, and, while that context is revoked, is refused `credential_revoked` instead (above),
unless an operator's revocation deleted the receipt, when it is `token_not_found` (§5.1.4). The
join keeps `ctx_id` across one principal's logins, so a match is exactly "the same
context"; after a replace or a reclaim the receipt names a context that no longer exists, and the
retransmission is answered `token_spent`, as a spent token is, without sliding the receipt. The
device prompts again.

**A login's PASS replays only for a login the context witnesses** (plan 7d; §13, decision 35).
The join writes a witness of the login it lands into the sealed context, in the same step as
the context and its index, and only into a context it leaves unrevoked: the first 8 bytes of
the login's `credential_sha256`, the context keeping the last eight. A receipt carries, sealed,
the principal, `sid` and certificate of the credential it was written for. A retransmitted login
that would replay PASS is answered instead:
- **`credential_revoked`** when a standing mark names the receipt's own principal or certificate,
  which the live context need not name, since a join keeps only its latest login's credential;
- **`token_spent`** when the live context does not witness the login: its join ERRORed and did
  not commit, is still in flight, or wrote a revoked context, or eight later logins evicted it.
  The index alone cannot tell these from a committed login, since an earlier login with the
  same `sid`, certificate or principal already reaches the context;
- **`token_spent`** when the index no longer reaches the context under that credential: its
  `sid` and its certificate, each it has, or its principal when it has neither. A replay
  answered PASS is then one a revocation of that credential can still reach. A `sid` a session
  refresh has rotated since is the case that meets this: the sealed context and the index name
  the new one, so a retransmission of the login before the rotation is `token_spent`. It fails
  closed and costs the device one prompt.

The concurrent duplicate that lost the redemption race presented the winner's own credential,
and replays the winner's receipt on these same checks: while the winner's join is in flight
the context does not witness it yet, so it is `token_spent`, and the device prompts again. An
`enable` writes no index and witnesses nothing; its retransmission, and its losing duplicate,
replay once the live context is the receipt's, unrevoked and unmarked.

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
| 2 | **Revocation** — an operator's `port49 revoke`, by principal or by certificate (§5.1.4); OIDC back-channel logout by `sid` or `sub`; a certificate appearing on a CRL or OCSP response by issuer and serial; a policy change withdrawing every grant on the device, or leaving a policy in force that cannot be resolved or compiled for the context, or a refresh finding a context it cannot open (§5.1.3, "Policy reload") | authoritative: from an operator or the identity layer (§5.1.4), or, for a policy change, from the policy in force, with a `refresh` record saying which (§5.7). Sets `revoked_at` rather than deleting, so the next command is denied `credential_revoked` with a `server_msg` saying so — distinguishable from a session port49 never saw. Row 6 reclaims the state |
| 3 | **Session ceiling** — `session_expires` reached and the grace window elapsed | local, needs no external signal: the daemon deletes the context at its first authorization past the window, and a refresh past it extends nothing (plan 7b) |
| 3a | **Staleness ceiling** — `now - refreshed_at` beyond `staleness_ceiling` because the broker has been unreachable that long, or the principal's directory membership has not been verified for that long (§5.1.3; design document §9) | local; denies `context_stale` with a `server_msg` naming the cause it cannot tell apart (a broker outage, or a membership the broker cannot verify), retains the context so recovery resumes it |
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
`session.max_session_age_default` in whole minutes, rounded down and at least one (§8), and it ends an idle
session a reply landed in that class: `idle-timeout 1` closed one at 1m0s through
`local-user-name` and through the `remote` template, on both Junos images (L24, closed;
`tests/lab/results/L24-juniper_*.md`). The largest value the device takes is unmeasured
(decision 21). And every revocation record
names the live contexts it could **not** reach, so an incident responder knows which devices
still need a manual disconnect.

#### Session lifetime

`session_expires` is `auth_time + max_session_age`, where `auth_time` is when the human
actually authenticated (§5.1.4) and `max_session_age` is port49 policy, declared per role,
composed as the **minimum** across a principal's roles, carried in the token record (§5.1.1),
and defaulting long. It is the compliance-relevant clock: *how long may a session run on the
strength of one authentication event.*

A session approaching the ceiling is **warned in the session** where the device allows it. The
authorization REPLY carries `server_msg`, so the operator is told on the device before anything
stops working; of the measured images only IOS-XE shows it on a permit (L34, closed), and
everywhere else the warning is `port49 token`'s (as built, below) — and re-authentication does
not require reconnecting, because the broker can refresh live context (§5.1.3) through the
`contexts_by_principal` index (illustrative; as built below):

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

**As built (plan 7b; §13, decision 33).**

- **The ceiling.** A role's `max_session_age` is a duration of at least 1m or `never`. The ceiling
  on a device is the least across the roles composing there, a role naming none taking
  `session.max_session_age_default`, and `never` only when every role says so. A device whose
  ceiling has passed since the connection authenticated is refused per item at mint,
  `session_expired`. The held connection keeps its own ceiling at
  `session.max_session_age_default` (decision 17), whatever a role says.
- **The token.** A token never outlives its ceiling: it expires at `token_ttl` after the mint or at
  the ceiling, whichever is first, and the mint item's `expires_at` says which. A login with a token
  whose ceiling has passed is refused at redeem, FAIL `session_expired`, before the token is spent
  and with no context written. On Junos that FAIL is the gate: a session authorization refused
  there does not stop the login, and the device never asks again (decision 21).
- **A policy edit.** It shortens a live context's ceiling and never lengthens it.
- **A refresh.** It sets the ceiling the policy in force gives, from the new `auth_time`, so a
  lengthened ceiling or `never` takes effect at the next refresh or login.
- **The warning.**
  - It rides on the `server_msg` of permitted session and command authorization replies, within
    `session.ceiling_warning` (default 30m) of `session_expires`, to the platforms §15 L34 found
    show it and still permit, and to any an operator lists in `session.ceiling_warning_platforms`.
  - L34 found one: `cisco_iosxe`. In a run with a 2m `session.ceiling_warning`, IOS-XE showed
    `port49: session ends in Nm - run 'port49 refresh'` before the prompt at login and with the
    output of `show version`, the one command the run checked, and the command still ran
    (`tests/lab/results/L34-cisco_iosxe.md`).
  - EOS, NX-OS and Junos showed nothing and are off the list
    (`tests/lab/results/L34-arista_eos.md`, `L34-cisco_nxos.md`, `L34-juniper_vjunos-router.md`,
    `L34-juniper_vsrx.md`). Their operators are warned of the ceiling only by the agent: `port49
    token`'s stderr, and each device's new end in `port49 refresh`'s output.
  - It also goes on `port49 token`'s stderr, from the mint's `session_expires_at`, on every
    platform.
- **Past the ceiling.** A context is denied `session_expired` and kept until the grace window
  (`session.grace_window`, default 10m) passes. Then it is deleted at its next authorization
  (teardown row 3), and no refresh resumes it. The delete and the refresh are compare-and-sets on
  the context's revision.
- **The refresh on the certificate path.** It is `POST /v1/refresh/challenge` and `POST
  /v1/refresh`:
  - **The nonce.** 32 random bytes, good for 60s, once, on the connection that asked, signed by the
    certificate's key over the connection's TLS exporter value, so it cannot be answered on another
    connection. A connection may refresh once per 10s.
  - **The clock.** `auth_time` is the broker's verification time, and the held connection's session
    clock moves with it.
  - **What it extends.** Each of the principal's live contexts first takes the policy in force: a
    withdrawn grant is revoked, and only a context the policy has just judged and kept is extended,
    inside its grace window, each a `refresh` record.
  - **Who triggers it.** `port49 refresh` and `port49 login` run it; the agent never runs it on its
    own.

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
(Keycloak: measured, it does, and a refresh-token grant keeps the last authentication's
`auth_time`) and L47 (hosted providers, open).

**A certificate port49 issued, as built (plan 9b; §13 decision 43 ruling 11).** After the sign-in
the agent holds the session on the certificate path, unchanged:

- **The clock.** `auth_time` is the broker's acceptance of the handshake or its verification of a
  refresh's signature; the provider's `auth_time` bounds issuance alone (5 minutes) and is recorded
  as `auth.oidc.auth_time`.
- **The fresh authentication event.** A refresh's key signature on the issued certificate is one,
  as on any certificate, while the certificate is valid. So `port49 refresh` and a new agent's
  refresh at login need no browser, and one sign-in gives at most `certificate_lifetime` of mints
  and refreshes.
- **The certificate's end** bounds the mint and the refresh, not a device session: what a last
  refresh extended runs to its own ceiling.
- **A back-channel logout** refuses the certificate through its `sid` for as long as it lives: on a
  broker that issues, a logout record stands `max(max_token_age, 24h) + 2×clock_skew`, 24h being
  the longest `certificate_lifetime` allowed (§13 decision 43 ruling 16).

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
`bundle` and `blob` are mandatory on every record that consulted policy.
`bundle` is the bundle's name (§10): `sha256:` over the policy file's hash and the inventory's
canonical form, a string, since plan 6a; before it, the policy file's hash. The blob carries it,
so a daemon that never reads the policy still logs it. A blob names the bundle it was compiled
under, which a later bundle that changed nothing for that context does not rewrite (§5.1.3).

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

`device.key_ref` and `device.key_version` are on every record of an exchange a key validated —
`redeem`, `authorize_session`, `authorize_command`, `escalate`, `account` — naming the key group
and the version that admitted it, so a rotation's phase-out is read from the log (§10, `port49
keys status`).

**Never suppress permits.** Sampling, or logging denies only, looks thrifty and destroys the
artifact: *what did Alice run on Tuesday* is answered entirely by permits. Volume is the cost
of the product, not a problem to optimize away.

#### Events

One envelope. Ten decision events, one at each point a decision is made, plus five report
events (`account`, `account_gap`, `blob`, `inventory_change`, `directory_forget`) that share the envelope and carry no verdict:

| `event` | Emitted by | Decides |
|---|---|---|
| `mint` | broker | which grants matched, which roles composed, which blob resulted. A record a sweep page writes through the mint (`POST /v1/tokens` by `scope`) carries `sweep: {scope, after}`; the revocation re-check's records after the mint do not (§13 decision 42 ruling 4) |
| `redeem` | daemon | whether a presented credential is valid, and creates the context |
| `authorize_session` | daemon | the session and its returned attributes (§6) |
| `authorize_command` | daemon | one command vector |
| `escalate` | daemon | an `enable` exchange, attributed to the principal (§7) |
| `refresh` | broker | whether a live context takes the policy now in force, or is revoked (§5.1.3); or, on a session refresh (`/v1/refresh`), whether it is extended, with `session.auth_time` and `session.session_expires` (§5.6); or, on a policy refresh, `session.session_expires` where the ceiling moved earlier. A context on a platform that never asks about a command carries `session.unreached: true` (decision 21) |
| `revoke` | broker | a revocation by principal or by certificate (§5.1.4): what it reached, and the live contexts it could not; a revocation lifted; or, over HTTP, a principal ending its own sessions (`by: self`) or a `(device, username)` key ended (`by: key`), neither leaving a mark |
| `identity` | broker | what `GET /v1/identity` resolved the caller to: `permit grants_matched` when its subject holds a grant unexpired now, else `deny no_grants_matched` (design document §17) |
| `explain` | broker | a hypothetical decision `POST /v1/explain` answered, about the caller or, under `explain_others`, another principal: its verdict and reason are the answer given, or `deny api_right_missing`. It authorizes nothing, and replay passes over it |
| `issue` | broker | whether a person's OIDC sign-in is exchanged for a port49-issued certificate (`POST /v1/certificate`; §13 decision 43 ruling 8): `permit certificate_issued`, carrying `certificate: {serial, issuer, fingerprint, not_after}` and `auth.oidc`, or a deny with the refusal's reason. A broker that cannot issue (`issuance_unavailable`) records nothing |
| `blob` | broker | not a decision: the full compiled blob, emitted once per hash so replay depends on the log alone (§5.1.1) |

Device accounting shares this envelope as the twelfth event, `account`, and is specified in
§5.8. It is not a decision — it is a report — so it carries no `policy` block and no verdict.
A thirteenth, `account_gap`, is a report too: accounting records port49 received and did not write,
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

A fourteenth, `inventory_change`, is a report too: one record per security-relevant change a bundle
swap made — `{"change": {"kind": "address_added", "address": ..., "from_bundle": ...,
"to_bundle": ...}}` for an address added to a device already in inventory, and `scope_joined`
or `scope_left` with `"scope"` for a device entering or leaving a scope with `security_log:
true` (§5.5, §10), `key_ref_changed` with `"from"` and `"to"` for a device's key assignment
changing, `admission_changed` with `"to": "admitted"` for a device already in inventory becoming
admitted, and `device_added` with `"to": "admitted"` for a device added and admitted, whose
addresses are new capture targets. Its `device` block names the device. It is what makes a
source-of-truth edit that moves privilege visible in the log it moved (§10), and
`port49_inventory_changes_total{kind}` is its alarm.

A fifteenth, `directory_forget`, is a report too: an operator ran `port49 directory forget
<principal>` on the broker's admin socket, deleting the principal's directory membership and with
it the entry the principal was pinned to (§13 decision 38) — `{"principal": ..., "forget":
{"entry_id": ..., "dn": ..., "verified_at": ..., "refused": true|absent, "origin": "admin_socket
uid N"}}`. `verified_at` is the record's last verification or refusal. The principal's next
verification pins the entry the directory gives it then, so this record is the trail for a
principal moving to another entry by an operator's hand.

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

Two fields carry what a directory contributed (plan 7g):

- `policy.subjects`: on `mint`, `refresh`, `identity` and `explain`, when the principal matches
  more than one subject, every one of them, sorted; `policy.subject` is then absent. With one
  subject, `policy.subject` alone, as before (§13 decision 38).
- `auth.directory`: on a broker event decided with a directory membership, `{source, verified_at,
  server, site}`: `source` is `fresh` (read from a directory server for this request) or `grace`
  (the store's, verified at `verified_at`, no server answering); `server` and `site` are where it
  was read. It names no group: `policy.subjects` says which subjects matched.
- `auth.oidc`: on a broker event whose caller presented an OIDC token, `{issuer, sub, sid, amr,
  acr, auth_time}`, each from the verified token (`sid` the provider's own, not
  issuer-qualified); `amr` and `acr` are recorded and consulted by nothing (decision 13). A
  bearer that did not verify is recorded `auth: {method: oidc}` with no principal: none of its
  claims is a validated value (§13 decision 39).

A `revoke` record (plan 7a) is written once per revocation or lift that takes force: `deny
credential_revoked` for a revocation, `permit revocation_lifted` for a lift. A revocation that took
force but did not finish is recorded too, with `error`. One that did not take force writes none (a
mark that could not be written, a lift that found no mark or could not delete it, a malformed
request, one that gave up waiting behind another; a refusal for a missing `api:` right is
recorded, below): `port49 revoke` reports it and exits 1. Its
`principal` is the revoked principal when the revocation is by principal. Its body is `"revocation": {"by", "issuer", "serial", "device", "username", "at",
"origin", "contexts", "token_keys", "connections", "unreached", "saved", "error"}`: `by`
is `principal` or `cert` for a standing mark, `self` for a principal ending its own sessions,
`key` for one `(device, username)` ended, and `sid` or `sub` for an OIDC session or subject
ended by a back-channel logout or by `/v1/tokens/revoke` (§5.1.4), which carry `oidc_issuer`
and `sid` or `sub`, and `principals` when the logout reached more than one principal (the
record's `principal` is then the first); `device` and `username` name a `key` revocation's key,
or a `self` one limited to a key; `issuer` and `serial` name a certificate (the serial in lower-case hex);
`at` is when the mark took force, an earlier mark's time when one already stood; `origin` is who
asked (`admin_socket uid <n>`, e.g. `admin_socket uid 0`, `api <principal>` over HTTP, `backchannel_logout <issuer>`, or `offline uid <n>` for a revoke written by `port49-broker revoke --offline` with every broker down); `contexts` how many live contexts were marked; `token_keys` how many
`(device, username)` keys had their unspent tokens deleted; `connections` how many held broker
connections were closed; `unreached` each marked context, `{"device", "username"}`, on a platform
that never asks about a command, or on a device the inventory gives no platform, so an incident
responder knows which sessions to close on the device (§5.6, "Where these controls do not
reach"); `saved` whether `broker.revocations_file` was written, present only for a standing mark; and `error` the first step that
did not finish, while the mark stands. A count of zero is absent. A `mint deny
credential_revoked` names whose credential it was as `trust_domain_unresolved` does: `principal`,
and `auth.fingerprint`. A mint that the check after its writes refuses has already recorded a
permit for each device it minted afresh; each is followed by a `deny credential_revoked` naming that
device, with `index_error` when its tokens could not be deleted, and the tokens that permit names
were never returned, so they are not counted as minted (`port49 capability`). A device it answered
by replaying an earlier mint recorded no permit in this request, so it gets no deny: its tokens are
deleted, and the earlier mint, whose tokens were returned, stays counted. A refused request with no
device minted afresh writes one `deny credential_revoked` naming no device.

A `self` or `key` revocation writes one record each time it runs; its `principal` is the caller
for `self`, and for `key` the owner of the context it found, if one was read. A record's `auth`
and `principal` always describe one credential, so a record about someone other than the caller
carries no `auth`. A `revoke deny api_right_missing` names the target as `principal` (or the key
as `device` and `username`, with no `principal`), carries no `auth`, and names the caller in
`origin`. An `explain` record names whom it was about as `principal`, carries no `auth`, names
the device (no platform where the answer is `no_grants_matched`) and the bundle that answered
(`policy.bundle`), and has `"explain": {"asked_by", "asked_by_fingerprint", "command",
"mint_error"}`: `asked_by` and `asked_by_fingerprint` are the caller's principal and certificate,
`command` is true when a command was asked, and the command itself is never recorded. Where the
broker would mint no token (`mint_error`, a mint item error), the record has no verdict and no
reason; `mint_error` is the answer. An API
call refused before its body is read, for a reason a mint is refused (`trust_domain_unresolved`,
`session_expired`, `credential_revoked`, `store_unavailable`, with their `mint` meanings), is
recorded under its own event: `identity`, `explain`, or `revoke`, the caller as `principal` with
its `auth`. So is one the broker's listener refuses as the connection binds, by the path the
refused request named; any other path is recorded `mint`.

#### Reason codes

`reason` is a closed vocabulary, so denials are countable and alertable without parsing prose:

| `reason` | Meaning |
|---|---|
| `grants_matched` | `mint`: at least one declared grant selected the device; blob written. `refresh`: the policy in force was written into the live context; or, on a session refresh, the context was extended. `identity`: the caller's subject holds a grant unexpired now |
| `no_grants_matched` | `mint`: no declared grant for this principal selects the device; or, on a sweep page by `scope`, the page holds no device: the scope is not declared, selects no device the principal holds a grant on, or the page is past the end, which are one answer and one record carrying `sweep` and `policy.bundle` and no device (§13 decision 42 ruling 2), after the mint gate has passed. `refresh`: none does any more, and the live context is revoked. `identity`: it holds none |
| `username_collision` | `mint`: the derived username is already held by a subject in another trust domain (§2); or the directory derives a username a policy subject declares (the declared one stands, whichever came first; §13 decision 38 ruling 3, decision 40 ruling 6), or a second directory entry holds the same username under `broker.directory.username_attribute` (§13 decision 38); or a workload under a directory mapping whose identity subject declares no username takes from its entry one a subject declares or a second entry holds (§13 decision 41 ruling 4, plan 8b). At the broker's bind and on `refresh` likewise; on `refresh` every context of the principal is revoked. The process log names both claimants |
| `identity_unmapped` | at the broker's bind, and on `mint`, `identity`, `explain`, `revoke` and `issue`: an OIDC token that verified but whose principal claim is absent, not one string, not printable ASCII with an `@`, outside the verifier's `principal_domains`, or an `email` without `email_verified: true`, or a machine token with neither `azp` nor `client_id` (§13 decision 39); or the client certificate maps to no directory entry under `broker.directory.certificate_mapping`; or the value the mapping reads is not in the certificate (no SID extension; zero or several UPN or email SANs); or a weak mapping's issuer is not one its `issuers:` pins (design §7); or a certificate the workload anchor verified names no workload: zero or several URI SANs, a URI that is not a SPIFFE ID with a path, a trust domain outside `broker.identity.machines[].spiffe_trust_domains`, or a leaf that is a CA (§13 decision 40), answered 401 at bind over HTTP, never as a TLS alert; or, under a workload certificate's directory mapping (§13 decision 41, plan 8b), its issuer is not one `broker.identity.machines[].directory.issuers` pins, no entry under `base_dn` holds its SPIFFE ID in the mapping's `attribute`, or the entry found holds that attribute with other than one value equal to the SPIFFE ID byte for byte; or, while that mapping is configured, a person's entry holds in the mapping's `attribute` any value beginning `spiffe://`, so it is a workload's (§13 decision 41 ruling 4); or the entry's `principal_attribute` or `username_attribute` is absent, has several values, is not printable ASCII, gives a principal with no `@`, or a username that is not already canonical or is reserved (§2); or the principal it gives is pinned to another entry, by `objectGUID` or `entryUUID` (else DN), for as long as that principal's membership record lives or until an operator runs `port49 directory forget` (§13 decision 38). The API answers 401 and the connection is closed. On `refresh`: the principal's entry is gone or no longer usable, and every context of it is revoked |
| `identity_ambiguous` | as `identity_unmapped`, when the certificate maps to two or more entries, or the server refuses the search for its size limit; or when a second entry holds the same `broker.directory.principal_attribute` value as the mapped entry, so two people would share one principal (§13 decision 38); or when two entries hold a workload's SPIFFE ID in the workload mapping's `attribute` (§13 decision 41, plan 8b); or when a uniqueness search (the username's, the principal's) does not return the entry itself, so the server's matching rule cannot prove the value is one entry's alone. Never resolved to the first entry (design §7). MUST be alertable on its own: two entries matching one identity is an impersonation path. On `refresh`: every context of the principal is revoked |
| `directory_unavailable` | at the broker's bind, and on `mint`, `identity`, `explain` and `revoke`: no directory server answered within `broker.directory.query_timeout`, and the membership the store holds for the principal or the certificate was verified longer ago than `broker.directory.grace`, or there is none, or it records the directory's refusal (grace never overrules one) (§13 decision 38); for a workload under a directory mapping, the membership stored for its SPIFFE ID (§13 decision 41 ruling 7, plan 8b), which `port49 workload` retries within `--deadline` and then exits 75. Nothing is minted. The API answers 503 with `Retry-After`, to be retried, and no agent session is ended. Never on a scheduled or policy refresh: a principal the directory does not answer for keeps its contexts unstamped, and `context_stale` takes over at the ceiling. On a session refresh (`/v1/refresh`), as on `mint`: nothing is extended |
| `composition_refused` | `mint`: the principal matches more than one subject, and their grants together compose on this device to a session reply a joint check refuses (§10): a level above the grants' ceiling, a reply over 255 bytes, an attribute the platform does not accept, or a blob the daemon would refuse. Refused for this principal on this device alone, never a quarantine. On `refresh`: the live context is revoked the same way. The process log names the subjects and the check |
| `trust_domain_unresolved` | `mint`: no configured verifier accepted the credential (design document §7); or the revocation status of the certificate or one above it could not be established (a stale CRL, an OCSP responder that did not answer, an issuer no configured source covers, which is final at `port49 workload`, §13 decision 40 ruling 7) and `broker.certificate_status.on_unavailable` is `refuse` (§5.1.4). The API then answers 503 `certificate_status_unavailable`, never a final 401, and to be retried but for an uncovered issuer. A certificate whose verified chains end at both the human and the workload trust anchor, or, on a broker with no human x509 verifier, do not end at the workload anchor (§13 decision 40 ruling 2), is refused at the TLS handshake, which leaves a log line and a `handshake_failures{identity_refused}` count, not a decision record. On `mint`, `refresh`, `identity`, `explain`, `revoke` and `issue` also: an OIDC token none of `broker.identity`'s verifiers accepts, or that two accept (a bad signature, an algorithm the verifier does not pin, an `iss`, `aud` or `azp` that does not match, an expired or not-yet-valid token, one issued longer ago than `max_token_age`, a human token without `auth_time`, a machine token from a client the verifier does not list, with another `sub` than the client's, or carrying a person's session claim or an `idtyp` other than `app`) (§13 decision 39); the API answers a final 401, never `certificate_status_unavailable`. When the issuer's keys cannot be had (none fetched, none refreshed within `jwks_max_age`, or a token's `kid` not in the kept set and the refetch failing) the API answers 503 `identity_provider_unavailable`, to be retried, never a final 401. On `refresh`: the refresh challenge was not answered by the connection's key, or the certificate's status could not be established as on `mint` (503); also an OIDC refresh whose token's `nonce` is not the caller's unspent challenge (401 `refresh_challenge_missing`), or whose `auth_time` is before it (401 `refresh_not_fresh`). On `issue`: a missing bearer, a client certificate presented, a sign-in older than the freshness bound, a nonce not naming the CSR's key, a spent sign-in, a bad CSR, a machine token, or a sign-in that cannot be carried in a certificate (§13 decision 43 ruling 8) |
| `candidate_cap_reached` | `mint`: `token.candidate_cap` unspent tokens already stand for this `(device, username)`; the mint is refused, never a redemption, and every token already issued stays usable (design document §8) |
| `context_matched` | `authorize_session`: context found, attributes returned |
| `escalation_granted` | `escalate`: the level was within `max_privilege` and the mechanism succeeded |
| `permit_dominates` | a permit dominated every matching deny (§5.4) |
| `pipe_stage_denied` | a pipeline stage matched no pipe permit (§4) |
| `service_unsupported` | the authorization `service` is not one the platform authorizes; on `redeem`, the authentication action or type is not one port49 serves (only `login` with ASCII, PAP, or CHAP) and the reply is `ERROR` |
| `store_unavailable` | any event: the store did not answer or returned an error, or, on `redeem`, port49d found the store restored from a snapshot and refuses every token redemption until a broker runner's purge is done (decision 36, the restore guard), or, on `mint` at port49-broker, the mint gate is closed (`port49_broker_mint_gate_closed`): the replica's mark on `meta/judged` has not landed since its policy swap (one store round trip), or, since its start, the replica has seen no takeover done for the bundle it serves, neither its own runner's nor one `meta/judged` records, not in doubt (up to `hold_ttl`/3 and the takeover on a first start or a start after a policy edit, plus up to `hold_ttl` when the previous run's lease must expire first, as after a crash; none on a rolling restart; decision 36, the purge at a takeover). This is the start gate and not a store fault, and an operator should not look at etcd for it. Its 503 carries `Retry-After`. `port49 workload` retries it; the agent does not, so `port49 token` exits saying to retry in 5s. On `redeem` and on accounting the reply is `ERROR`; on an authorization it is `FAIL` — fail closed, a break-glass account's commands included (plan 4, owner's ruling 2026-09-24), because an authorization `ERROR` hands the N9Kv's command to its local role checks and permits every command under IOS-XE's `if-authenticated` (§15, L4). Whether the device then falls through to its next method is per platform and is not what this reason promises: an authentication `ERROR` is final on IOS-XE and on Junos with `tacplus` alone, and where it does fall through (vEOS, the N9Kv) the authorization `FAIL` that follows leaves break-glass logged in and unable to run a command (§15, L4; `tests/lab/results/L4-error-*.md`). So a store outage is not the break-glass case; an unreachable port49 is. The operator's escape is to stop port49d, or reject TCP 49 with a reset, so each device finds the connection refused and treats the server as down. A break-glass account then logs in with its local password, under a method list that ends in `local` (measured over SSH on all five images, §15 L4 and L17). A firewall that drops TCP 49 silently is unmeasured as an escape (a silent server costs 5s per command on the Cisco and Arista images, L4), and so is whether commands in a session already open fall to local authorization. port49d will do this itself by closing its TACACS+ listener while the store is unhealthy (owner's ruling 2026-09-24; plan 7f). On etcd (plan 7d) it already closes every listener once its hold on the store is lost, or the token or context pool's circuit has stayed open, or every call on one has been refused, for `store.etcd.hold_ttl`, and opens them again when the store returns (§13, decision 35). Before then a store that does not answer, or a pool's open circuit, is answered within `store.packet_deadline`, never left for the device to time out (what each image does then: §15 L35). The log line is the evidence an operator needs at 3am |
| `token_redeemed` | `redeem`: a presented credential matched an unspent token |
| `token_not_found` | `redeem`: the device tag matched but no unspent token for `(nas, username)` did — expired, spent, or mistyped, or its receipt deleted by an operator's revocation (§5.1.4) |
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
| `session_expired` | the session ceiling was reached; context retained through the grace window (§5.6). On `mint`: the held connection's authentication is older than `session.max_session_age_default`; on every endpoint but the refresh's challenge and refresh, an OIDC token's `auth_time` is; either way the caller must authenticate again (§13, decision 17). Per item on `mint`: the device's ceiling (the least `max_session_age` of its roles, §5.6) has passed since the connection authenticated; run `port49 refresh`. On `refresh`: the context is past its grace window and is not extended. On `redeem`: the token's ceiling has passed; the login is refused FAIL, the token is not spent, and no context is written (§5.6). |
| `context_stale` | the broker has been unreachable past `staleness_ceiling`, or the principal's directory membership has not been verified for that long (§5.1.3); context retained, denies until refreshed (§5.1.1, design document §9) |
| `credential_revoked` | the context's `revoked_at` is set — CRL, OCSP, back-channel logout, every grant on the device withdrawn, a subject's username changed, the principal's directory entry gone, ambiguous or renamed to a username another holds, their subjects' composition refused, the policy in force not compiling for the context, or a refresh finding a context it could not open, where the `refresh` record before it says which (§5.1.3, §5.6); on `redeem`, a login whose resulting context is revoked because its token was not minted after the revocation, or a retransmission answered while the context it names is revoked (§5.6); on `mint`, a revocation by principal or by this certificate stands (§5.1.4), or an OIDC logout refuses the token's session or subject, or a CRL or OCSP response names the certificate or an intermediate above it, so nothing is minted and a held connection is closed; on `identity`, `explain` and `revoke`, an OIDC logout refuses the caller's token; on `refresh`, the caller's certificate is marked, or an OIDC logout refuses the caller's token, or a CRL or OCSP response names it or an intermediate above it, so nothing is extended; on `issue`, a mark on the principal or an OIDC logout refuses the sign-in's token, so nothing is issued; on `revoke`, a revocation's own record |
| `revocation_lifted` | `revoke`: an operator lifted a revocation (§5.1.4). Mints by the principal or certificate are made again; a context the revocation marked stays revoked until a login whose token was minted after the revocation joins it (§5.6; §13, decision 15): for a principal's mark, after the lift; for a certificate's, by any of the principal's other certificates at any time |
| `api_right_missing` | `revoke`, `explain`: the caller asked to act on another principal's tokens, sessions or decisions, or on a `(device, username)` whoever holds it, and its subject declares no `api:` right that unlocks it (§2). The API answers 403 `api_right_missing`; nothing is done |
| `certificate_issued` | `issue`: the broker issued a short-lived client certificate for the key the sign-in's `nonce` names (§13 decision 43 ruling 8) |
| `device_unknown` | the source address is not in the admission trie (§10). On an `unvalidated` record: a reload refused, removed, renamed, re-keyed or re-platformed the device an open connection was admitted as, so that admission is no longer one port49d knows, and the connection is reset with no strike (§10, "How a daemon refreshes its snapshot"). On `mint` and `refresh`: the device is in inventory and admission refuses it — no key group admits it, two tie on it, or its `key_ref` is one port49d holds no key for (§10) — so no token is minted for it and its live contexts are revoked: it cannot reach port49d, and a token for it would only be a login that falls to the device's local method (`tests/lab/results/quarantine-*.md`). As with a quarantine, a subject with no grant on the device is answered `no_grants_matched` first, so the API tells no caller which devices exist |
| `platform_unknown` | the device's platform has no adapter; generic fallback applied |
| `blob_unavailable` | the referenced blob could not be resolved from the store or any cache — a store fault, alarmed (§5.1.1) — or the context no longer fits the blob: a session attribute filled from it exceeds 255 bytes, or a filled-in value carries a separator (`=`, `*`) or a control character, either of which the broker refused at mint (§6), or the reply would send a `priv-lvl` above the context's `max_privilege`, a `priv-lvl` that is not a level 0 to 15, or an attribute the blob's `accepted_attributes` does not take — compositions the load quarantines (§6, §7). On `refresh`: the policy in force could not be resolved or compiled for this context — an unexpected broker fault, since the reload's load (§5.1.3 step 1) compiled every subject on every device, and what failed quarantined its device or refused the policy under the joint check (§10) — so the context is revoked, failing closed; the process log names the `ctx_id` and the fault, and it is counted `failed`. Also on `refresh`: the context could not be opened, failing authentication (one sealed under a key port49 does not hold is left unrevoked and unrecorded, §5.1.3) — so it is revoked through the monotonic revocation mark, the record names the device and the username its key holds and no principal (the owner and `ctx_id` are sealed, and the index entry that led to it may be stale), and it is counted `failed` |
| `blob_platform_mismatch` | the context's blob was compiled for a platform other than the one inventory gives the device — inventory changed since the mint, or the broker and the daemon read different inventories. Its dialect and attributes are another platform's, so it is never answered from; operational, alertable beside `blob_unavailable` |
| `device_quarantined` | the device is in inventory but failed joint validation against policy (§10); the connection is closed without a reply, as for `device_unknown`, until fixed. On `refresh`, a deny recorded once per context per policy version (bundle): the live context is left as it was until the quarantine lifts |
| `projection_fail_closed` | `authorize_session`, a permit: the session on a projected platform (§8) was answered with its composition's fail-closed reply — every command denied but what the projection proved — because the projection cannot tell the device that composition faithfully (§13, decision 26). The blob carries why (`fail_closed`: `refused_shape`, `configuration_mode`, `overflow`, `unwritable`, `secret_rule`, `unsound`, `argument_deny`, a deny Junos cannot match because it names an argument, or `configuration_deny`, a deny of a configuration statement, which deny-commands never reaches; decision 27). Every other subject on the device is answered as before; `policy test` and `policy diff` fail on the composition |

Every event has a success reason and at least one failure reason in this table, so
"decisions by event, verdict, and reason" (design document §15) is a complete metric. A
denial whose reason is `context_missing`, `context_stale`, `device_unknown`, or
`blob_unavailable` is an operational condition rather than a policy outcome, and each MUST be
separately alertable — a rise in `context_missing` means sessions are being authenticated
somewhere other than port49, and any `context_stale` means the broker has been down, or has not been able to verify the
principal's directory membership, longer than the ceiling. `credential_revoked` MUST be alertable on its own: a revoked operator still
typing is an incident signal. `identity_ambiguous` MUST be alertable on its own, as
`credential_revoked` is; a rise in `directory_unavailable` means no directory server has
answered for longer than `broker.directory.grace` for someone, or that no membership is stored
for them (never pre-warmed, or refused), so check the store before chasing a DC outage.
Alert at half the ceiling,
`time() - port49_directory_refresh_last_complete_timestamp_seconds > session.staleness_ceiling / 2`:
at the ceiling every live session denies `context_stale` from a reachable port49d, and the
escapes are `session.staleness_ceiling: 0s` with a port49d restart, or stopping port49d so
break-glass applies (L4). `session_expired` is a further category: expected, and a signal
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

A blob event redacted before it was written (§5.8) makes every record naming it unverifiable
from the log alone. `port49 policy replay --policy <file> --inventory <file>` recompiles such a
blob from the files for the record's principal and device at the blob event's time, and uses
it only when the files name the record's bundle and the recompiled blob hashes to the name the
record carries.

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
| `command_projection` | how rules render for session-only platforms (below): `junos_regex`, the one this build renders. Where it is set, `privilege` is each level's ceiling in permission bits, never attributes, and is required, and `supports` is `[session]`. Only a platform the pinned set projects is projected: a `platforms:` block, `replace: true` included, or a new platform that sets `command_projection`, `bits`, `carve_outs`, `bit_delivery`, `local_user_names` or `rpc_entry_denies` where the pinned set does not project that platform is refused at load, since no measurement sets a floor under a bit's reach there | if `session`-only |
| `bits` / `bit_delivery` | each permission bit's reach in rule form, an upper bound measured in the lab (L12), and whether bits travel as `user-permissions` or a `local-user-name` template (below). A session runs the union of its bits' reach. The bit `baseline` is what a class with no bits runs, held by every session and never sent or named in `privilege`. A block may add to a bit's reach, an edit the diff gates as widening (§12), and never take from it, and may not declare a bit the set does not | if `session`-only |
| `carve_outs` | the commands a bit alone makes available, whatever other bit reaches them: each rule held by that bit's own reach, measured in the lab (L12). The only subtraction from the union: a bit not held removes no command another bit reaches except these. A block may drop one and never add one. A `platforms:` block for a platform the pinned set does not project may not declare `carve_outs` at all, and is refused at load (`command_projection`): only a measured set subtracts reach | optional, with `bits` |
| `local_user_names` | under `bit_delivery: local_user_name`, each level's template user on the device, whose class `port49 platform export --classes` renders with the level's bits. Each is `p49-<name>`, in the set and in a block alike, and never `remote` or a platform system user such as `root`: a template the device already has under another class would put the session in that class, whatever bits the projection proved | with `local_user_name` |
| `rpc_entry_denies` | on a projected platform, the denies a reply adds where a wire deny is the only guard beneath a sent bit or the baseline, closing the CLI's ways into a native RPC for that session (decision 44). Set 1.2.0's `juniper_junos` carries `["junoscript **", "op **"]` (L26c-scripts: `op` reaches past the `junoscript` deny). Each is words and a trailing `**`. A block keeps the whole list or drops it with `[]`, and the platform then renders as set 1.1.0 does; a partial list is refused at load, because it leaves an entry open (`op url` reaches past the `junoscript` deny, L26c-scripts); it may never add one the set did not measure | optional |
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
them, is not a keyword on both images, so its deny cannot be sent (decision 27); and port49
treats a deny beneath a sent bit or the baseline as guarding the CLI only (*provisional on L26c*,
below). The narrow shape cannot
carry a deny beneath a permit, so the subject gets the fail-closed reply (`refused_shape`).
What does project on set 1.1.0: `permit: [show **]` alone, as the narrow shape
(`user-permissions=view view-configuration`, `deny-commands .*`, `allow-commands` `show **`); a
narrow grant of a few show commands; and an admin `permit: [**]` with `deny: [restart **]`,
which no bit but `all` reaches — the adapter's declared bits that do not enter configuration
mode, `user-permissions=clear network trace view view-configuration`, and the deny (decision
26). Only declared bits are sent: an admin expecting `maintenance` or any other bit set 1.1.0
does not declare does not get it.

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
default** and which is mutually exclusive with the plain family on the wire. L12 measured
that precedence over TACACS+ on both images (the `-regexps` deny beat its allow;
`tests/lab/results/L12-juniper_*.md`), so the refused shape is expressible in that family.
Generating it is not built: a per-grant family choice needs its own proof and the projection
differential (L12, open), so in set 1.1.0 the shape is refused.

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

This rendering rule is decision 22. It was provisional on L9 and L12 until both closed on
2026-09-29: L9 for the regex dialect every wire regex rests on (`JunosFacts`, below), L12 for the
bits. L12 measured, on both images, `user-permissions` applied over a bitless template, the reach
of each bit, the `.*` baseline on the wire, and the `-regexps` family's precedence
(`tests/lab/results/L12-juniper_*.md`, `L12-bits-juniper_*.md`); the projection differential
(plan 5b Task 19, `L12-projection-juniper_*.md`) then ran every shape set 1.1.0 renders on both
images, none wider than port49 permits, and the commit checker took every wire regex form it
renders.

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
text, or a path still asking for a `<command>`), or a deny naming it at that place refuses the
command, the CLI's caret under the word, while a paired control without the deny runs it — the
property itself (L26b, both images; how `show cli`, `show host`, `show ingress-replication`,
`show policy`, `show task`, `set cli` and `exit` are proven). No RPC, an error asking for anything else, the
word as text, and a timeout all make it an argument, so a value under a command with no RPC
(`monitor traffic interface fxp0`) or under one that still needs an argument (`ping
routing-instance mgmt_junos`) is never proven a keyword. The capture runs nothing that acts or
streams: it walks only under `show`, after proving the pipe shows the RPC and runs nothing, so in
set 1.1.0 no word under another top-level command is proven but `set cli`, which L26b proved by
its deny. **A `show configuration` hierarchy is never a keyword**: a deny naming one is not
enforced — every hierarchy each image offered ran under a deny naming it (L26b) — so on Junos an
operator denies all of `show configuration` or none of it, and `deny show configuration system`
fails closed as an argument deny. **A word is a keyword only where every run on every image proves
it**: the walk is not reproducible run to run (the vSRX rerun lost one word the first run proved
and gained two it did not; L26), so the set's tree intersects every committed run. **The tree holds for the images it was
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

**A wire deny does not bind a native NETCONF RPC** (`tests/lab/results/L12-netconf-juniper_*.md`,
both images). The token that opens the CLI opens NETCONF with the same reply, and there a native
RPC ran past every wire deny (`<get-configuration>` past `deny show configuration **`); only a
`<command>` RPC was refused. A CLI session reaches the same RPCs from inside itself:
`xml-mode netconf` opens NETCONF there, and a native RPC its deny did not name ran
(`L26c-juniper_*.md`). On SRX hardware `<get-configuration/>` through it returned the whole
configuration past a deny of `show configuration` beneath `view-configuration`
(`L26c-operator-juniper_srx.md`, operator-reported). **So `deny-commands` cannot keep the
configuration from a session that holds `view-configuration` and reaches an RPC.**

**A deny of `junoscript` closes the RPC entry points, per user** (`tests/lab/results/L26c-junoscript-juniper_*.md`,
both images, each refusal isolated against a control with the same bits and no deny). Junos
authorizes `xml-mode` as `junoscript`. `deny-commands "junoscript"`, sent by TACACS+ or set on the
class, refused `xml-mode netconf` and `junoscript netconf` from the CLI, and refused that user's
NETCONF on port 830 (`error: unknown command: xml-mode`). `show version` still ran, and the
control reached `<get-software-information/>` both ways. A deny naming `xml-mode` does not bind,
and a hidden command does not abbreviate. The deny closes NETCONF for the session whose reply
carries it and for no one else. *Provisional on L26c* for the other ways in: the NETCONF
subsystem on port 22, the SSH exec channel, an `op url` script, REST, the XML API (`xnm-ssh`,
`xnm-ssl`, `xnm-clear-text`), `outbound-ssh` and `scp` (plan 9b1, Task 3),
and the projected reply end to end (Task 9). An `op url` script is not closed by it: under the
deny its `jcs:invoke` reached `get-configuration` on both images, as the control's did
(`tests/lab/results/L26c-scripts-juniper_*.md`, 2026-10-11), so set 1.2.0 denies `op` beside it
(decision 44 ruling 2).

**Set 1.2.0 sends it** (the adapter key `rpc_entry_denies`; decision 44). Take a composition whose
only guard beneath a sent bit, or beneath the baseline every session holds, is a wire deny. It
keeps the capability shape, and its `deny-commands` carries the adapter's entry denies beside its
own. The CLI deny is then the boundary. That subject has no NETCONF, `xml-mode` or XML API session
on the device. A subject whose reply carries no such deny keeps them: an automation account
granted everything its bits reach, say. Over NETCONF a native RPC is bounded by the bits alone, so
no subject has both a deny beneath its bits and NETCONF.

**A readonly with a deny beneath `show **`** (decision 44 ruling 10). A grant that leaves a
baseline command to a deny carries baseline denies, and a readonly's are fourteen. Set 1.2.0
carries them beside the entry deny. Each change below renders only where the adapter has
`rpc_entry_denies`, so a set without it, or a block that drops it, renders as set 1.1.0 does.

- The baseline's `xml-mode **`, which no keyword tree proves, is sent as nothing beside
  `junoscript **`. Junos authorizes `xml-mode` as `junoscript`, and a deny naming `xml-mode` does
  not bind (`tests/lab/results/L26c-junoscript-juniper_*.md`). Bare `xml-mode` and `xml-mode
  netconf` are refused under the deny on both images, where the control is greeted
  (`tests/lab/results/L58-juniper_*.md`).
- Set 1.2.0's keyword tree proves `save` on both images (`L58-juniper_*.md`; L26b proved it on
  vJunos-router only): the deny refused it with the caret under `save`, where the control ran it
  (vJunos-router) or its CLI took `save` and stopped after it (vSRX). The `save` cells ran under
  a `permissions all` class; the same candidates typed under a `view` class with no deny are
  will be recorded in the note as "control (view)" when Task 9 reruns L58, information only.
- A reply's `word **` denies render as one alternative, ` *(help|quit|…)( .*)? *(\|.*)?`, the
  shape L26b's deny sessions were enforced in (`L26b-juniper_*.md`).
- A permit the bits reach but for a carve-out of a ceiling bit the reply does not send, where
  an allow of the permit would beat a deny beneath it, goes out as allows of those carve-outs.
  Each is within the ceiling and meets no deny. Whether an allow runs a command past the bits is
  unmeasured, so CI reports each as sent beyond them.
- Where the capability shape would send an allow its bits do not reach, and the narrow shape
  carries the grant with every allow reached and leaves off no more, the narrow shape is sent.

So a readonly granted `show **` less `show configuration **` gets `view`, a `deny-commands` of
170 bytes (its twelve `word **` denies and `junoscript` in one alternative, `set cli` and its
own deny), and allows of `show log`, `show firewall` and `show policer`, view-configuration's
other carve-outs. view-configuration is not sent: the grant decides none of its other reach
(`monitor`, `request mpls` and the rest). A readonly granted `show **` alone keeps the narrow
shape and both bits, as under set 1.1.0.

Where the reply must send an allow that meets an entry deny, the allow would beat it (L11), so the
entry is not closed. The composition then falls to the narrow shape, whose `.*` refuses every
entry point, or to the fail-closed reply (`refused_shape`, its message naming RPC reach). A narrow
allow that would run `xml-mode`, `junoscript` or `op` is refused the same way, and the fail-closed
reply leaves it off.

CI reports two warnings. `projection_netconf_closed` names each subject a reply closes NETCONF
for. `projection_deny_beneath_view_configuration` names each sent deny that meets `show
configuration` beneath a held `view-configuration`: the CLI refuses it and NETCONF is closed, but
the bit is what grants the configuration, so withholding the bit is the real fence.

**Set 1.1.0 is unchanged**, since a released set is never edited. It sends no entry deny, so a
composition whose only guard beneath a sent bit is a wire deny gets the narrow shape or the
fail-closed reply there, as before (option C).

**Management services.** Under set 1.1.0 a projected Junos device runs no management service but
the CLI's, checked as an allowlist. `devices check-config` passes it only where nothing under
`system services` is on but `ssh` and `telnet`, an unknown service included, and `rest`,
`web-management` and `extension-service` appear nowhere. Under set 1.2.0 the entry deny closes NETCONF per user (port 830 measured; the port-22 subsystem
*provisional on L26c*), so the check no longer requires it off, and it is a shorter allowlist.
Under `system services` it passes `netconf`, `ssh` and `telnet` with any statement beneath them,
and these services, which serve no management session (Junos's `[edit system services]`
hierarchy): `database-replication`, `dhcp`, `dhcp-local-server`, `dns`, `dynamic-dns`, `finger`,
`ftp`, `static-subscribers`, `subscriber-management` and `subscriber-management-helper`. Any other
statement there fails, the finding quoting it. That covers a service no one listed, such as
`service-deployment` (which speaks the JUNOScript XML API), `outbound-https`, `grpc-tunnel` or
`tftp-server`, and a name the list does not know: an allowlist does not fail open on a statement
nobody listed (plan 5b pre-flight C1). Anywhere in the hierarchy it still fails
`web-management`, `extension-service`, `rest`, the XML API (`xnm-ssh`, `xnm-ssl`,
`xnm-clear-text`) and `outbound-ssh`, until a lab cell measures the entry deny closing each
(*provisional on L26c*). REST was not measured: the lab's tunnel did not reach it, the control
included (`tests/lab/results/L26c-scripts-juniper_*.md`, 2026-10-11), so `rest` stays a finding.
Whether a deny of `show configuration` holds against a file read of `/config` through `ftp` or
`ssh sftp-server`, which pass, is unmeasured (*provisional on L26c*). Both sets read the capture §12 names.

**No carve-out leaves a deny off the wire in either set**: `view-configuration`'s `show
configuration **` out of `view` is measured on the CLI only. `start` is never denied, since admins
need `start shell` and the bits already refuse it.

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
   `all`, the same holds for each projected platform of the pinned set or the inventory, so
   the pin is refused in CI rather than a reload at the first sync that adds such a device, save
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
cannot write, a level the adapter maps to no bits (`unwritable`: its ceiling cannot be written
in the device's bits, so the reply allows only permits the bitless baseline itself runs), a rule redaction hides, a deny that names an argument (decision 27), or a reply
its witness finds unsound — is not a joint
check (§13, decision 26). That subject alone gets the **fail-closed reply**: `deny-commands`
`^.*$`, an allow for each permit that is within the level's ceiling bits that do not enter
configuration mode, dominates every deny it meets, does not meet `configure` and can be
written, and, where a deny binds no RPC, does not run `xml-mode`, `junoscript` or `op`, and no other bit or template — under `user_permissions` the smallest of those bits
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
and at least one, so a 30 s default exports `idle-timeout 1` (decision 21); the file is parsed strictly, as the daemon parses it, but only that key is used
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
from the generic adapter. A variant is the same device under another name, so everything
port49 keys by a shipped platform's name is read for it as its base's: the `session_services` it may arrive with, its
exec records' commands, its system users, its session discriminator (§5.8), the built-in
redaction patterns (§5.8) and the keyword tree (§8, decision 27). The admission index carries the
base's name beside each device's for the daemon (plan 6a). Keyed by its own name, a
`juniper_junos` variant would be refused every session `service_unsupported`, have its login
records read as commands, and have its records logged without Junos's own redaction patterns.

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
before. Plan 6a's bundle does not carry them to the daemon; a `based_on:` variant reads its
base's (§8, "User-editable, day one"). `enable_username` moved the other
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
`system_users`). They are built in and in no set, so they are unpinned; plan 6a's bundle does not carry them. A release
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
and a job that pages on them is one nobody reads. One whose only records are `unvalidated` is
noted **never validated** instead, with the count: it asked, and nothing it sent validated,
which a key mismatch causes. It warns — and exits 1, for a job to page on
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
found, and does not set the exit code. A log line that did not read as a record is counted on
the first line, and an unauthorized tier is then printed as possible too, since that line may
have held the authorization; it still sets the exit code, since a torn log is worth a look. CI's half is `report: unenforced_rules`: a subject whose
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
GET  /v1/bundle?sequence=<n>         bundle n from the service's history, for `port49 inventory export`
GET  /v1/bundle/version              current version, for polling
GET  /v1/bundle/diff?from=<ver>      for CI and `port49 inventory diff`
POST /v1/sync                        on-demand trigger
GET  /v1/devices/{address}           diagnostic only — MUST NOT be used on the hot path

POST /v1/webhook/{source}            not the API: webhook_listen, TLS without a client certificate (below)
```

**Consumers pull and cache; they never query per request.** A daemon calling this API per
connection would make the syncer a hot-path dependency and rebuild the problem the component
exists to prevent.

**The API is mutual TLS on every path** (plan 6b). The service verifies each client certificate
against one trust anchor and names the caller by the leaf's one URI SAN, verbatim, a workload's
identity (design document §7), or, where there is none, `user:` and its one email SAN,
lower-cased; a certificate with several of either is refused, since ambiguity fails closed. Two
lists in the service's configuration decide what a caller may do: `readers` may read the bundle,
its version, a diff and one device; `syncers` may do all of that and `POST /v1/sync`
(design document §17: reading a snapshot is not the right to trigger a sync). Probes read
`/healthz` and `/readyz` on the service's plain metrics listener, which carries no fleet data.

**Four triggers are built in two plans.** The schedule (each source's `interval`, default the
top-level `interval`, default 10 minutes; a sync of one source rebuilds the merged bundle from every
source's latest fetch), startup, and `port49 inventory sync` are plan 6b's, with the file connector;
the NetBox and Nautobot connectors and their webhooks are plan 6c's, written against the fixtures
L27 and L30 recorded (§13, decision 31).

**A webhook is authenticated by its signature, and only triggers a sync.** No product can present
a client certificate (the webhook L27 and L30 recorded has `ssl_verification` and `ca_file_path`,
nothing that holds one), so deliveries arrive on a listener of their own, `webhook_listen`: TLS
under the service's certificate, or `webhook_tls_cert_file`, and no client certificate; the API
stays mutual TLS on every path. Its one route is `POST /v1/webhook/<source>`. A delivery is taken
only for a source configured with `webhook_secret_env`, as `application/json`, at most 1 MiB, with
an `X-Hook-Signature` equal to HMAC-SHA512 of the body under that secret (L27, L30), and with a
`timestamp` within 5 minutes of the service's clock either way; one whose signature was taken in
the last 10 minutes triggers nothing. Anything else is refused (401, 413, 415 or 400; every 401
with the one body `{"error":"unauthorized"}`, so a caller cannot tell a configured source name from
another), counted (`port49_inventory_webhooks_total{source, outcome}`) and said once per source and
outcome, naming the sender's address and never the body, the signature or the secret; a failed TLS
handshake is counted (`outcome="tls_handshake"`), not logged. A taken delivery triggers a
sync of its source 2 s later, coalescing a burst; a source is synced from webhooks at most once
per 30 s, with at most one sync pending. Nothing in a delivery reaches the bundle: the sync reads
the source's API, so delivery order, which is not change order on Nautobot (L27, L30), orders
nothing, and the body's `timestamp` is read only for freshness. A refused or lost delivery costs at
most the source's `interval`, which still runs. Every measured release (NetBox 3.7.8 and 4.7.1,
Nautobot 1.6.32, 2.4.43 and 3.2.6) delivered to the listener under a private CA's certificate with
verification on, and a change reached the published bundle in 2.4–2.7 s from NetBox and 3.6–4.1 s
from Nautobot. None sends a delivery answered 401 or 503 again at its defaults (NetBox's
`RQ_RETRY_MAX` is 0; Nautobot's webhook task has no retry), so a refused delivery is covered by
the `interval` alone (§15 L33; `tests/lab/results/L33-netbox.md`, `L33-nautobot.md`). A delivery
that arrives as the service shuts down is accepted and triggers nothing, or is refused at connect;
by those settings it is not sent again either, which no run measured, and the next start's sync,
which reads every source, covers it.

### One versioned bundle

Three things must reach the other components: device inventory, the policy repository, and
the pinned platform set (§8). Distributing them separately means they can disagree — a broker
evaluating policy `v88` against inventory `v1841` and platform set `1.4.0`, while another
replica holds a different combination. Nothing would report the mismatch.

They therefore travel as **one versioned bundle**. The service publishes its inventory half, a
signed document naming the policy it was built against; each port49d joins it to its own
`broker.policy_file` (below; §13, decision 29):

```
bundle document, sequence 2291 (signed by the service)
  inventory       device records, addresses, platforms, attributes; no key assignment
  policy_sha256   sha256:…, the policy the service built it against, never the policy
  platform_set    1.0.0, as pinned by that policy
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
One that fails for some platforms quarantines the devices on them. port49d builds the bundle
itself from `broker.policy_file` and the inventory, whether `inventory_file` (plan 6a) or the
document plan 6b's inventory service publishes (§13, decision 29): each quarantined device is logged with its cause at start and at every reload that
loads, its mints are refused `device_quarantined`, and its connections are closed without a
reply (plan 4).

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
Clearing it is the policy or adapter change CI named: port49d applies it from its own
`broker.policy_file` at the reload (decision 29), and the service's next sync reports the device
no longer quarantined. Through the inventory service's syncs, on the same four images on
2026-09-30 (`tests/lab/results/quarantine-sync-*.md`), a sync introducing a device its platform
failed quarantined it, the rest of the sync applied, its connections were closed
`device_quarantined`, its mints refused, break-glass logged in and ran its commands, and the fix
admitted it again. Break-glass took 0.32 s on vEOS and 0.47 s on vJunos-router, but 16.7 s on the
N9Kv and 20.3 s on the C8000V. Those runs left single-connection on; the 2026-09-24 runs above,
with it off, took under a second. With single-connection on, IOS-XE and NX-OS
take a reset that comes after their request as transient and wait out their 5 s timeout on every
AAA exchange, unless the retry is refused at Accept before they write (§15 L31;
`tests/lab/results/L31-breakglass-cisco-singleconnection.md`). So the close is a key miss's without
the strike: the first connection's packet is recorded and the connection reset at once, and the
source's next connections inside a decline window are refused at Accept with a reset and no record
("A declined source is refused at Accept", under "Admission and keys"). With it, break-glass on a
quarantined device with single-connection on took 1.78 s on the C8000V and 2.61 s on the N9Kv,
against 1.28 s and 2.61 s for a key miss and 1.31 s and 2.66 s with port49d stopped (§15 L31,
`tests/lab/results/L31-cisco_iosxe.md`, `L31-cisco_nxos.md`).

A consumer runs on exactly one bundle version at a time, so a decision is always attributable
to a single, nameable state of the world. `bundle/diff` then covers policy change, inventory
drift, and platform-set movement in one review artifact rather than three.

**The bundle's name is a content hash.** `bundle` on every record and blob is `sha256:` over the
policy file's `sha256:` and the inventory's canonical form — its devices in name order, each
device's addresses sorted, its key groups if the inventory file still carries any — so every
port49d reading the same two files names the same bundle, and a reformatted inventory file is
the same bundle. The policy file's own hash is kept beside it, and port49d's lines name both.
The name does not cover port49d.yaml's `keys:`: two daemons holding different key names load
the same bundle and may refuse different devices (below), and each says so at load.
The loaded policy carries the admission index, the device table and the quarantine with it, and
one pointer swaps all four (§13, decision 28).

This also closes a gap the documents otherwise leave open: **how policy reaches the broker** was
previously unspecified. It reaches it from the broker's own `broker.policy_file`, reviewed and
deployed beside port49d (§13, decision 29). The service holds the source-of-truth credentials and
runs third-party connectors, and a compromise of it can already move devices between scopes and
add addresses; taking policy from it too would let it grant anyone anything. The bundle document
names the policy the service built it against (`policy_sha256`) and never carries one. port49d
builds the bundle it runs on from its own policy and the document's inventory, as it builds it from
two files. When the two hashes differ it still applies the inventory, against its own policy, says
so once per pair of hashes, and sets `port49_inventory_policy_mismatch` to 1 until they agree:
nothing the service sends changes the policy, and a policy rollout that reaches port49d before
the service never stalls inventory.

**The bundle document is signed** (§13, decision 30). It is the inventory in the canonical form
the bundle's name hashes, with its `sequence` (the service's publication count, an integer), the
`policy_sha256` and `platform_set` the service built it against, the device names each source
gave (`sources`), and `published_at`, sealed as `{"document": …, "key_id": "ed25519:…",
"signature": …}` with the service's ed25519 key over the document's exact bytes. The same sealed
bytes are what the API serves, what the service keeps in its state directory and writes to the
shared mirror, and what port49d persists, and port49d verifies them against the public keys in
`inventory.service.verify_key_files` wherever they came from. A document carries **no key
assignment**: no `key_groups`, and no device's `key_ref` pin. The service refuses a source that
has either, and port49d refuses a document that does (§10, "Admission and keys": key assignment is
reviewed policy). A pin is a policy key group matching the device by name (below). A document that
does not verify, does not parse, carries a key assignment, or names a device with a control
character or an unusable name is refused, said once, and alarmed
(`port49_inventory_bundle_refused`), and the bundle in force keeps serving.

**The service's state directory is its sequence's trust anchor, and read behind the fence.** It
reads `state_dir`'s published bundle and history behind the policy file's write fence, with a link
in a file's own name refused rather than followed, and its `policy_file` behind the same fence;
the mirror only as port49d does (below). It refuses to start rather than publish below what it
already published: on a `state_dir` copy it cannot open, on a published bundle older than its
history's newest, and, with `state_dir` empty, on a mirror copy it cannot open or a mirror mount
that does not answer in 10 s. Each refusal names the fix — add the old key to `verify_key_files`
after a rotation, mend the mount, or move the copy aside to start fresh. Beside a good `state_dir`,
a mirror it cannot open or read is said, `port49_inventory_mirror_behind` is 1, and the service
serves `state_dir`'s bundle.

**Consumers take what they need**, which is not the same thing:

| Component | Consumes | Why |
|---|---|---|
| broker | inventory (from the bundle), policy (its own `broker.policy_file`), platform set (the policy's pin) | resolves and compiles decisions |
| daemon | addresses, and the `key_ref` the bundle resolved from the policy's key groups | to admit a connection and select a key |

The daemon deliberately does **not** evaluate policy or platform definitions. It receives
compiled decisions through blobs (§5.1.2) instead, so a version mismatch between broker and
daemon cannot change how a command is evaluated. The bundle carries facts; the blob carries
decisions.

**The service emits no key assignment, and never key material.** A document carries a device's
facts and no `key_ref`: port49d resolves each device's `key_ref` from its own policy's key groups
and each `key_ref` from its own secret mount. A compromised inventory service leaks the fleet list,
not the ability to speak to it, and cannot choose a device's key.

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
# the policy file — key assignment is reviewed policy
key_groups:
  - {match: {cidr: 10.0.0.0/8},       key_ref: prod_key}
  - {match: {attributes: {env: lab}}, key_ref: lab_key}
  # anything matching no group is refused
```

A device racked in a known site is admitted automatically with the correct key. One
appearing in an unexpected range matches no key group and is refused. The fleet list is
maintained once, in the source of truth, while the admission *decision* stays in review.

`key_groups:` is a block of the policy file. An inventory file that still carries one is read
where the policy has none, with a notice at every load. Where both carry one, the policy's wins
and the notice names the inventory's as ignored, so the inventory's writer never assigns a key
beside the reviewed policy. To move the block, add it to the policy file, then delete it from
the inventory file: no device is refused at any step, and a restart or reload between the two
loads. Deleting it from the inventory first would leave every device refused, and the reload is
refused by the bound (below). A group matches on a CIDR, on attributes, or on a device name, exactly one; a CIDR
with host bits set is refused.

**A `key_ref` is a name: `^[a-z][a-z0-9_]{0,63}$`**, lowercase letters, digits and `_`, starting
with a letter, at most 64 characters. The shape holds wherever one is written: a key under
port49d.yaml's `keys:`, a key group in either file, and a pin on a device record. Every report
prints a `key_ref` (`port49 keys status`, the start notices, the decision log), so one that is not
a name, most likely a secret pasted where the name goes, is refused without being printed: a key
under `keys:` refuses the file by its line, a key group refuses its file by its position, and a
pin refuses that device alone (below). A secret that is all lowercase hex and 64 characters or
fewer matches the shape and cannot be told from a name; the shape narrows the mistake, it does not
close it.

**A device is refused on its own, never the daemon.** A device no group admits, one two groups tie
on (below), one assigned a `key_ref` port49d.yaml defines no key for, one pinning a `key_ref` that
is not a name (above; the pin is not printed), and one whose `transport` port49d does not serve
(below), are each refused admission: named at start and at every reload that loads, counted in
`port49_devices_admission_refused`, and each connection from them closed after its first header,
with nothing decrypted, no reply, no strike, and the report bucket `admission_refused`, and their
next connections refused at Accept inside a decline window (below). The rest of the
fleet loads. The broker refuses to mint for a refused device (`device_unknown`, §5.7), and a policy
refresh revokes its live contexts: it cannot reach port49d, so a token for it would only be a login
that silently falls to its local method (the close is a quarantine's, measured on four images:
`tests/lab/results/quarantine-*.md`). One case refuses the start rather than a device: a bundle that
admits none of a non-empty inventory — key groups declared in neither file, say — which no device
caused. The same bundle at a reload, of either file, is refused whatever
`inventory.max_removed_percent` says (below). port49d with no `broker:` block has no policy and
keeps plan 1's behaviour: the inventory file's key groups, read at start, and a start refused by
either fault.

RFC 9887 replaces the shared key with mutual TLS, so a device record MUST be able to express
both: `transport: tcp` (the default, RFC 8907 under a shared key) or `transport: tls`. Until
plan 11 serves RFC 9887, a device with `transport: tls` is refused admission, as is one whose
`transport` is neither; the file and the rest of the fleet load (above).

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
1  a device record pinning key_ref (inventory_file), or a policy key group matching the
   device's name
2  an attribute match
3  the longest matching CIDR prefix
```

**Two groups that tie for every device they could match — one prefix twice, one attribute set
twice — are a policy load error**, naming both. This follows the same rule as the matcher (§4):
where two rules genuinely disagree about which is more specific, refusing to guess is the only
conservative answer, and a device silently admitted under the wrong key group is admitted under
the wrong *key* — which fails at the worst moment and looks like an outage (design document §12).
A tie that exists only for some devices — `{site: campus}` and `{role: leaf}` on a device carrying
both, or two addresses of one device in two groups' prefixes — refuses that device as above, and
`port49 policy test` fails on it (plan 6a, owner decision 1): a sync can create one, and refusing
the policy there would block every inventory change fleet-wide.

The device-pinned tier exists so an overlap can be resolved explicitly rather than by
contorting the CIDR layout.

A pin in the policy is a key group matching one device name, `{match: {name: leaf-01}, key_ref:
prod_key}`: it matches on the name alone, never with a CIDR or attributes, and outranks every
attribute and CIDR group whatever the device's addresses. Two name groups for one device tie for
every device they could match and are a policy load error. With `inventory_file`, a record pin and a
name group that name different keys refuse that device alone. A key group on a `/32` is not a pin:
it is tier 3, every attribute group outranks it, and it follows the address rather than the device.
With the inventory service, a record carries no pin (§13, decision 30) and the policy name group is
the only tier 1; the inventory `key_groups` fallback above is `inventory_file`'s alone.

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

`retire_after` is a date, inclusive: `retire_after: 2026-10-01` admits through the end of that
day UTC, and from `2026-10-02T00:00:00Z` the version identifies a device and never admits one,
as a retired version does. It is written on `accept` versions only; `current` carries none, and
a `retired` version is refused already. A connection validated before the instant keeps its
version only until that instant: past it, every later packet on the connection is treated as a
new connection's first packet would be: a `matches_retired` record, a strike, and the
connection reset at once with no reply (below, "Devices presenting a key that does not
validate"). "For the connection's life" would have no bound, because a busy single-connect
connection resets its idle timer on every packet and so can stay open indefinitely. The device
sees the same reset a reload's withdrawal sends (below, "How a daemon refreshes its snapshot"),
measured on four images: the session survives, and a key miss's next connections meet the
strike's backoff as L28 measured (§15 L29, `tests/lab/results/L29-reload-*.md`); the reset at the
date itself is tested in code with an injected clock. port49d says at start, and `port49 policy test --config`
reports, a version whose date has passed and an `accept` version with none.

The key sets, `retire_after` included, live in port49d.yaml beside the references to their
secrets (`secret_env`), where they have been since plan 1, rather than in the policy file, which
CI and every operator can read. Retirement and extension are therefore reviewed changes of
port49d.yaml's repository. Moving key sets into the policy repository waits on secret references
that name no secret (`secret_ref:`, plan 12).

#### Phase-out has to be observable

Step 21 is the one that does not exist in current practice, and its absence is why rotations
get abandoned half-finished — nobody can prove the old key is unused, so it is never removed.
The daemon writes the `key_ref` and version that validated the exchange on every record it
makes for it (`device.key_ref`, `device.key_version`, §5.7), and `port49 keys status` reads them
from the decision log, which makes the question answerable:

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

A sixth, `admission_refused`, is a device the inventory names and admission refuses (above). The
device is not at fault, so it is kept apart from both the key report and the noise. A seventh,
`admission_withdrawn`, is a packet on an open connection whose device a reload renamed, moved to
another `key_ref`, or gave another platform or `based_on:` base ("How a daemon refreshes its
snapshot"); a reload that refuses or removes the device is recorded under `admission_refused` or
`unadmitted_source`, with no strike either way.

**Retired versions are retained for diagnosis and never for admission.** This is what turns
"something is wrong with leaf-19" into "leaf-19 was missed in the rotation". The rule is
absolute and MUST be enforced structurally rather than by convention:

> A retired key version may **identify** a device. It MUST NOT admit one, and MUST NOT be used
> to construct a reply.

How many retired versions are kept for diagnosis is configurable, and keeping none is valid
for a deployment that would rather not hold the material at all — at the cost of this column
reading `no known key matches` for every straggler.

**Cross-group probing is manual.** `port49 keys diagnose <device>` tests the key material of
every group port49d holds, retired versions included, on the last packet from that device that
no key it is assigned validated. That packet is in port49d's memory, one per admitted device,
kept only while `admin_socket` is configured and never logged, and `keys diagnose` asks for the
trial over that socket: a Unix socket, mode 0600, that refuses any peer whose uid is not
port49d's or root's, and serves this one read-only operation (plan 6a, owner decision 2). It
names a real misconfiguration exactly — a lab device presenting the production key, say, which
is a finding in its own right regardless of the rotation. It MUST NOT run automatically on
validation failure: the listener is unauthenticated, and probing every key group on every
malformed packet is a CPU amplifier available to anyone who can reach port 49.

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

**A key miss is closed at once, with a reset, and so is a source inside its backoff.** A connection
whose packet no accepted version validates — a first packet, or one past its version's
`retire_after` (above) — gets one `unvalidated` record, one strike against its source, and a TCP
reset at once, with no reply (`port49_connection_events_total{event="key_miss_closed"}`). A strike
earns the source a backoff, by default 100 ms doubling to 5 s (`limits.malformed_backoff_base`,
`limits.malformed_backoff_max`); a new connection from it inside that backoff is refused at Accept
with a reset, and leaves no record, only `port49_connection_events_total{event="held_refused"}`,
which carries no device label. So the log holds one record per strike, and attempts refused inside a
backoff are counted, not recorded. The refusal follows any strike, not a key miss alone: a
`malformed_after_validation`, `not_tacacs` or unadmitted source's strike refuses it the same way.
**A strike from a device's address resets every connection from that address for up to 5 s** (the
default ceiling): a second AAA client on the same address still on the old key mid-rotation, or a
shell on the device, strikes for the device, and the device's own connections inside that backoff
are refused too.

This replaces the first build's hold, measured on vEOS-lab 4.31.2F, Nexus 9300v 10.4(2)F,
Catalyst 8000V 17.13.01a and vJunos-router 23.4R2-S2.1 on 2026-09-30 (L28): holding a key miss
silent for the backoff stalled a break-glass session's three commands to 25–28 s on the Cisco and
Arista images and 5.9 s on vJunos-router, against 0.4–2.7 s with port49d stopped
(`tests/lab/results/L28-held-*.md`). Closing at once with a FIN still stalled the C8000V, which
waits out its own 5 s timeout on a server's FIN (`tests/lab/results/L28-fin-cisco_iosxe.md`). With
the reset, a device presenting an unknown, a retired or an expired key logs break-glass in and
runs its commands in the time port49d stopped gives, on all four images, and its token logins are
refused (`tests/lab/results/L28-arista_eos.md`, `L28-cisco_nxos.md`, `L28-cisco_iosxe.md`,
`L28-juniper_vjunos-router.md`).

**A declined source is refused at Accept, and takes no strike.** port49d declines a connection
through no fault of the device's when admission refuses the device (above), when the device is
quarantined ("A quarantined device gets silence, not FAIL"), or when a reload refused or removed it
under an open connection ("How a daemon refreshes its snapshot"). Such a connection is closed the
way a key miss is, without the strike: one `unvalidated` record for its packet, and a TCP reset at
once, with no reply. The source then gets a decline window on the strike's schedule and settings:
`limits.malformed_backoff_base`, doubling up to `limits.malformed_backoff_max`, with the count
starting over after `limits.malformed_window` with no decline. A new connection from the source
inside the window is refused at Accept with a reset and no record, and is counted as
`port49_connection_events_total{event="declined_refused"}`, which has no device label. The window
refuses only a connection whose first packet port49d would decline or strike anyway. At each Accept
inside the window, port49d asks admission in force and the policy again. If a reload has admitted the
source again, or its quarantine has ended, the window is dropped and the connection is served. So a
fix takes effect at the next connection, and a window never outlasts its reason. A decline is not a
strike: it never lengthens a strike's backoff, and never refuses a connection that would be served,
except one retry racing the reload that admits the source, which fails closed.
Once the source is admitted, its window and count are dropped at its first connection inside the
window; otherwise the count lapses after `limits.malformed_window`. As with a strike, the log holds
one record for
each connection that reached a packet, and connections refused inside a window are counted, not
recorded. A source the inventory does not name at all is struck rather than declined (above). It is
closed with a record, a strike and a reset at once, never held for the backoff, and its next
connections are refused at Accept for the strike's backoff (`held_refused`). A removed device's
retries are therefore `declined_refused` for at most one window, and only when the removal ended an
open connection. After that they are `held_refused`: its strikes are recorded `unadmitted_source`,
which is what tells them apart from a key miss's (`key_miss_closed`) or garbage
(`malformed_backoff`). The window exists because of how
IOS-XE and NX-OS behave with single-connection on. They take a reset that comes after their request
as transient and wait out their 5 s timeout on every AAA exchange. A reset that comes before they
write makes them fall to their local method at once (§15 L31,
`tests/lab/results/L31-breakglass-cisco-singleconnection.md`). With the window, break-glass on a
removed, refused or quarantined device took 1.28–1.78 s on the C8000V and 2.58–2.62 s on the N9Kv,
against a key miss's 1.28 s and 2.61 s: within the bar of the key miss plus 1.5 s, and at most 0.5 s
over it (`L31-cisco_iosxe.md`, `L31-cisco_nxos.md`).

#### Retirement is enforced, and that is the point

`retire_after` is a date, and past it the version is refused. This is the tension worth
stating plainly: **automatic retirement is what prevents a key living for nine years, and
retiring a key still in use locks those devices out.** Both halves are true, and the design
resolves it by making the deadline visible long before it arrives rather than by softening it.
The lockout's shape is measured (L28, on four images): a device still presenting the version
once it has passed has every token login refused, while break-glass logs in and runs its commands
as with port49d stopped (above, "A key miss is closed at once").

- Alarm severity escalates as `retire_after` approaches while devices still present the
  version, and the remaining device list is in the alarm.

  port49d exports `port49_key_version_devices{key_ref,version}` (devices whose latest validated
  connection used the version) and `port49_key_retirement_seconds{key_ref,version}` (seconds
  until `retire_after` passes, negative once it has). The device count covers **only devices
  seen since port49d started**. Keys are read only at start, so each step of a rotation
  restarts port49d, and every restart resets the count to 0 until devices reconnect. The idle
  stragglers are the ones that stay uncounted longest, and they are the devices a retirement
  locks out. A removed device keeps counting toward its last version until the next restart.
  `port49 keys status`, which reads the decision log, is the authority before a version is
  retired. The metric is not. An alert built on the metric should wait until port49d has been
  up long enough to cover the fleet's reconnect interval, for example:

  ```
  port49_key_version_devices > 0
    and on(key_ref, version) port49_key_retirement_seconds < 7 * 86400
    and on(job, instance) (time() - process_start_time_seconds) > 86400
  ```

  Seeding the count from the decision log at start, so a restart does not blank it, is future
  work.
- Retirement and extension are both reviewed changes, of port49d.yaml's repository (above). Extending is
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
    transport: tcp
```

**Every address a device may source from must be listed.** TACACS is commonly sourced from a
loopback or dedicated management interface that is not the device's primary address. A
device sourcing from an unlisted interface fails device binding, and the failure will not
obviously trace back to inventory. `ip tacacs source-interface` — or the platform equivalent
— MUST be pinned in the reference AAA configuration.

`name`, `platform`, `addresses` and `attributes` are the facts; `key_ref` pins a key (tier 1,
with `inventory_file` only; with the inventory service a pin is the policy's name group);
`transport` is above. An inventory is refused whole when it does not parse, names a device twice
or with no name, or gives one address to two devices.

### Connectors and sync cadence

**NetBox and Nautobot** are the verified pair. Infrahub, Ansible inventory, and a plain file
follow the same snapshot contract. A file connector is required regardless, as the inventory
equivalent of the in-memory store — containerlab runs, CI policy tests, and `port49 explain`
against a hypothetical device all need an inventory that is not a live source of truth.

Four triggers, not one (the webhook is plan 6c's, with the connectors):

- **Scheduled full sync, each source at its `interval` (default 10 minutes).** That is the window a newly-racked device sits
  un-admittable if a webhook is missed, which is about the tolerance before it becomes a
  ticket.
- **Webhook-driven refresh.** Both products emit outbound webhooks on device create and
  update, giving seconds for the common case without polling harder.
- **`port49 inventory sync`** on demand.
- **Full sync at startup**, refusing to serve with no snapshot at all.

Four requirements, as plan 6c builds them (§13, decision 31):

**Version detection.** NetBox 4.x renamed `device_role` to `role`; Nautobot 2.0 did the same
and dropped `slug` from most models. The connector reads the release from `/api/status/`
(`netbox-version`, `nautobot-version`), never `Api-Version` alone, which Nautobot 1.6 sets to `1.2`
(L27), at every sync, and selects a mapping profile by it: NetBox 3.7 is `netbox_3_7`, NetBox 4.x
`netbox_4`, Nautobot 1.6 `nautobot_1_6`, Nautobot 2.x and 3.x `nautobot_2` (L30: 3.2.6 answered every
L27 question as 2.4.43 did, less the device fields `cluster` and `software_image_files`, which no
profile reads). A release whose minor no lab run measured is read with its major's profile and
said; a major no lab run measured is refused unless the source names a `profile`, the explicit
override. A status naming the other product refuses the sync.

**GraphQL first.** At 10,000 devices, REST pagination is hundreds of round trips per sync.
Both products expose GraphQL; one query returns devices, addresses, platform, site, role,
and tags (L27). The connector asks for what its map, filter and address rule read, and reads
GraphQL's `errors` before its `data`, whatever the HTTP status: NetBox 4.7.1 refuses an unknown
argument with HTTP 200 and an `errors` list (L30). It pages by `pagination: {offset, limit}`, as
NetBox 4.7.1 took (L30), by `limit` and `offset`, as Nautobot 1.6.32, 2.4.43 and 3.2.6 took, and not
at all for NetBox 3.7, whose 3.7.8 took no paging shape tried and returned the whole list (L30); each
profile reads the other minors of its major the same way, and says such a release is unmeasured. A
GraphQL list is taken only when its length equals REST's `count` read before it and read after it,
and no device appears in it twice: a server cap, or a page boundary lost to a concurrent delete,
would otherwise look like devices removed. A page longer than the page size asked for, or a fetch
past 256 MiB, fails the sync. REST remains a fallback, taken when GraphQL answers 404 or the source
says `api: rest`: it reads `?depth=1` under the `nautobot_2` profile, since Nautobot 2.4.43 and 3.2.6
at default depth named no related object (L27, L30), and follows `next` (below); every page must
give the same `count`, and the total must equal it, with no device twice. REST does not
give interface addresses in the device list, so a source that asks for them reads GraphQL only:
`api: rest` with interfaces is refused at load, and a GraphQL 404 fails the sync rather than
falling back. The connector's own query read every device once on each measured release, over
GraphQL and REST, and every release's GraphQL list gives each device's `id`, a string, by which the
connector keys it, as it keys REST's (§15 L32; `tests/lab/results/L32-netbox.md`,
`L32-nautobot.md`).

**`next` is followed only on the configured base.** Every product builds `next` from the host the
request arrived under (L30), so behind a proxy that rewrites `Host` it can name another origin. A `next`
whose scheme, host and port are the source `url`'s is followed; one on another origin is rebuilt on
the `url`, its path and query kept, and said once; one whose path is not the `url`'s device list is
refused. No redirect is followed: the source's token is sent to `url` and nowhere else. A REST read
whose total differs from its last page's `count` fails the sync. Every measured release builds
`next` from `X-Forwarded-Host` when the proxy sends it and from `Host` otherwise, and takes `https`
only from `X-Forwarded-Proto`; behind a proxy that sends neither, each named its own
`http://<service>:8080`, and the connector rebuilt it on the `url`, said so once, and read every
device (§15 L32; `tests/lab/results/L32-netbox.md`, `L32-nautobot.md`).

**Bounded change per sync.** A sync in which a source takes more than its
`safety.max_removed_percent` of the devices it gave the last published bundle out of service —
removed, kept and newly refused admission under the service's policy, or kept with an address in
the bundle in force and none now (plan 6c: port49d admits by source address, so under an attribute
key group such a device stays "admitted" and is unreachable) — MUST refuse, retain the
last good snapshot, and alarm (`port49_inventory_sync_refused`). A source's bound defaults to the
top-level `safety.max_removed_percent`, default 10. An empty result, and one the service's policy
admits none of, are refused whatever the bound. A partially-available source of truth or a
mistyped filter would otherwise silently deauthorize the fleet. Each port49d bounds the document
again by its own `inventory.max_removed_percent`, counting the same three: a deliberate large
removal raises both.

**Platform slug translation.** Real installations say `eos`, `arista-eos`, `arista_eos`, or
`veos`. The connector ships an alias table (those, and the netutils drivers Nautobot reports in
`platform.network_driver`, such as `cisco_xe`), a source's `platform_aliases` adds to or overrides
it, and a slug neither knows is kept as the device's platform: the device is admitted and served by
the generic adapter (§8, "Unknown platforms"); each publication that changes the set of such
platforms says so, and `port49_inventory_generic_platform_devices` holds their devices' count
always, whatever the source, rather than falling back to generic in silence.

**Filters, maps and addresses run in the service.** A source's `filter` (`status`, default
`[active]`, compared in lower case so each recorded spelling matches — `"ACTIVE"` on NetBox 3.7.8,
`"active"` on 4.7.1, `{"name": "Active"}` on every Nautobot measured, L30; `tags`, every one named;
`has_primary_ip`) is applied to what was read, since the products' filter arguments differ per
release and L27 measured only `name`'s. Its `map` names, per attribute, a path the profile reads
(L27, L30): on NetBox `site.slug`, `role.slug`, `platform.slug`; on Nautobot 1.6 those and
`platform.network_driver`; on Nautobot 2.x and 3.x `location.name`, `role.name`, `platform.name`,
`platform.network_driver`; on every profile `status` and `custom_fields.<key>`. `platform` names the
device's platform. A device's addresses are its primary addresses (`primary_ip4`, `primary_ip6`;
`addresses.primary`, default true) and, where `addresses.interfaces` names interfaces or
`addresses.all_interfaces` asks for every one, those interfaces' addresses too; `primary: false` is
taken only beside interfaces. Interface addresses are opt-in, since every address listed admits its
source and an address on two devices refuses the sync; an interface's loopback, link-local,
multicast or unspecified address is left out, since it cannot source TACACS+ and repeats across
devices. An attribute a device does not give — a null custom field, or one that is an object or a
list — is left unset, never invented, and §5.5's `on_missing` decides what that means. A connector
returns no key assignment: nothing it reads can carry one (§13, decision 30).

**Every `Fetch` returns within `sync_timeout`.** Each request is under the sync's deadline, and a
connector that has not returned 5 s past it is abandoned: the sync fails, the source is marked
(`port49_inventory_source_hung{source}`), and it is not asked again until the abandoned call
returns.

```yaml
# port49-inventory.yaml
listen: ":8443"
metrics_listen: ":9050"
webhook_listen: ":8444"           # plan 6c: needed when a source has webhook_secret_env
tls_cert_file: /etc/port49-inventory/server.pem
tls_key_file: /etc/port49-inventory/server-key.pem
# webhook_tls_cert_file, webhook_tls_key_file: the webhook's own; default the API's
client_ca_file: /etc/port49-inventory/clients-ca.pem
readers: ["spiffe://example.com/port49d"]
syncers: ["user:alice@example.com", "spiffe://example.com/policy-ci"]
signing_key_file: /etc/port49-inventory/signing.key
policy_file: /etc/port49-inventory/policy.yaml
state_dir: /var/lib/port49-inventory
mirror_dir: /mnt/port49-bundle
interval: 10m                     # a source's default
safety: {max_removed_percent: 10}
sync:
  - name: lab_file
    type: file
    path: /etc/port49-inventory/inventory.yaml
  - name: netbox_prod
    type: netbox                  # or nautobot
    url: https://netbox.example.com
    ca_file: /etc/ssl/certs/ca-certificates.crt   # required; the CA that issues the source's certificate
    token_secret_env: PORT49_NETBOX_TOKEN         # read at start, never printed; secret_ref waits for plan 12
    webhook_secret_env: PORT49_NETBOX_WEBHOOK     # optional: turns the source's webhooks on
    # profile: netbox_4           # optional override of the detected profile
    # api: auto                   # auto (GraphQL, REST on a 404), graphql, rest
    # page_size: 500
    interval: 10m
    safety: {max_removed_percent: 10}
    filter: {status: [active], tags: [port49], has_primary_ip: true}
    map: {platform: platform.slug, site: site.slug, role: role.slug, os_version: custom_fields.os_version}
    addresses: {primary: true, interfaces: [Loopback0]}
    platform_aliases: {eos-lab: arista_eos}
```

A device whose name is not 1–255 bytes of printable ASCII without a space, or whose platform or
attributes carry a control character, is left out of the sync, said and counted: it could not
reach a record or a line safely, and the broker refuses to mint for such a name anyway.

### How a daemon refreshes its snapshot

The daemon consumes only the inventory portion of the bundle; "snapshot" below means that
portion, refreshed as a whole because the bundle is versioned as a whole.

```
every 30s (inventory.service.poll_interval):
  GET /v1/bundle/version
  if etag == held.etag:  done                     ← the common case
  GET /v1/bundle  (If-None-Match: <etag>)
  verify signature → parse → build index → validate → bound → atomic pointer swap → persist
```

**Build fully, then swap.** The snapshot is parsed and indexed into a prefix trie (`address or CIDR
→ device, key_ref`) before anything is exchanged, then swapped by a single atomic pointer store.
Readers take no lock. Never mutate in place. A connection does not complete against the snapshot it
began with: every packet asks admission in force for its source again, and a connection whose device
the new snapshot refuses, removes, renames, moves to another `key_ref`, or gives another platform or
wire platform (a `based_on:` edit or removal) is closed at that packet, after the header, with a TCP
reset and no reply, and no strike, since the change is port49d's and not the device's. One
`unvalidated` record names the device and `key_ref` the connection was admitted as, reason
`device_unknown` (§5.7), and why: `admission_refused`, `unadmitted_source`, or `admission_withdrawn`
for a rename, a new `key_ref` or a new platform;
`port49_connection_events_total{event="admission_closed"}` counts it. "Complete against the snapshot
they began with" would have no bound, because a busy single-connect connection resets its idle timer
on every packet and so can stay open indefinitely: a device moved off a compromised key would keep
speaking it, a removed one would keep being answered under its old name, and one given another
platform would be denied `blob_platform_mismatch` at every command, its records redacted under a
platform no longer in force (a deleted variant's name has no patterns but the default's). The same
reasoning ended a key version at `retire_after` on an open connection ("Version sets, and no
cutover"). What a device does with this reset was measured on vEOS, the N9Kv, the C8000V and
vJunos-router on 2026-09-30, each change a sync through the inventory service (§15 L29,
`tests/lab/results/L29-reload-*.md`): the session survives on all four. Where port49d no longer
serves the device, the command in flight is refused on vEOS (at once) and on the C8000V (after its
own 5 s when removed or refused), runs on the N9Kv and on vJunos-router (which authorizes commands locally, so the reset
hit accounting), the next token login is refused, and break-glass logs in — in up to 2.1 s on vEOS
and vJunos-router, and up to 30 s on the C8000V and 41 s on the N9Kv, against 1.3 s and 2.6 s with
port49d stopped. The slow cases came from the connections after the reset, which were closed only
after the device's request and never refused at Accept. A reset for a reload that refused or
removed the device now opens a decline window, so those connections are refused at Accept ("A
declined source is refused at Accept"), and break-glass with single-connection on took 1.28 s
removed and 1.78 s refused on the C8000V, and 2.62 s and 2.58 s on the N9Kv, against a key miss's
1.28 s and 2.61 s (§15 L31, `tests/lab/results/L31-cisco_iosxe.md`, `L31-cisco_nxos.md`). A
rename, re-key or re-platform opens none: that device is still admitted. Where port49d still serves the device under a new name or platform, its FAIL is
final on EOS, NX-OS and IOS-XE, so break-glass is not let in there, as with any served device (L4).

**Validate locally before swapping.** The service already applies bounded-change safety, but
the daemon MUST NOT trust the payload: reject a snapshot that fails to parse, that is empty,
or that drops more than the configured share; retain the previous one and alarm.

**The snapshot never expires.** Staleness is a metric and an alarm —
`port49_inventory_snapshot_age_seconds` — never a fail-closed. An admission table with a TTL means a
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
   place needs nothing: port49d writes each document it applies to
   `inventory.service.state_dir/bundle.json`, atomically, mode 0600, and reads it at start behind
   the policy file's write fence.
2. **A shared object-store location** holds the most recent bundle, written by the inventory
   service and readable by daemons. A pod scheduled onto a fresh node reads that and serves. The
   location is a directory the deployment mounts (`mirror_dir` on both sides): port49 speaks no
   object-store API. The copy is signed, so whoever can write the store can replay an older
   genuine bundle and never forge one; the start line names the sequence and publication time it
   started from, and a later pull replaces it (below). The mirror's file is opened without
   following a link in its own name and must be a regular file no larger than a document may be, so a mount that
   presents it through a symbolic link, as a Kubernetes ConfigMap mount does, is refused: that
   fails closed, and the mirror must be a real volume. The service writes it mode 0640, so port49d
   needs the mount's group, and never replaces it with a lower sequence than the copy there.

At start port49d verifies both copies and starts from the one published later (`published_at`,
which survives a sequence reset). It asks
the service at start only when it has neither, and until a bundle arrives it keeps its TACACS+
listener closed, so a device finds the connection refused and falls to its local method at once, measured over
SSH with port49d stopped (§15, L4; `tests/lab/results/quarantine-arista_eos.md`,
`quarantine-cisco_nxos.md`, `quarantine-cisco_iosxe.md`, `quarantine-juniper_vjunos-router.md`);
a second server is unmeasured (L4, open), and `/readyz` on the metrics listener answers 503. It says why
once per distinct reason and asks again every `poll_interval`.

Both are cold and cached; neither puts the inventory service on a request path. Without at
least one of them, the singleton is not free after all — it is a startup dependency wearing a
different name.

**Key resolution stays local.** An unresolvable `key_ref` fails that device closed — not the
daemon — and alarms, because that is a misconfiguration worth hearing about on the first
device rather than the ten-thousandth.

**Every swap logs a summary** — `snapshot v1841 → v1842: +3 devices, -1, 2 changed` — so an
unexpected fleet change is visible in the daemon's own logs, not only in the service's.

**With `inventory_file`, the snapshot is the file.** port49d watches it as it watches the policy
file (§5.1.3): it loads a changed file once two reads a watch interval apart agree, at once on
`SIGHUP`, and says a refusal once per distinct content. It validates as above and refuses an
empty file and one that removes more than `inventory.max_removed_percent` of the devices in
force (default 10; 100 turns the bound off), counting a device that goes from admitted to
refused as removed. Whatever the bound, it refuses a file whose bundle admits none of its
devices, as a start is refused (above): the bundle in force keeps serving,
`port49_inventory_file_refused` is 1, and the one line that says so names the deliberate path,
which is to stop port49d. It builds a bundle from the file and the policy in force,
swaps the two in one pointer, and runs the refresh a policy reload runs (§5.1.3): a device
removed from inventory has its live contexts revoked, and one leaving a scope is narrowed like
any other. `port49_inventory_snapshot_age_seconds` is the time since the file in force was last
read and found unchanged or loaded; `port49_inventory_file_refused` is 1 while the file on disk
is one port49d refused. `SIGHUP` also re-reads `inventory.max_removed_percent` from port49d.yaml,
so a deliberate large removal is: raise it, send `SIGHUP`, and lower it again.

**With `inventory.service`, the snapshot is the service's document**, and `inventory_file` is
absent: port49d.yaml naming both is refused, as is `inventory.service` without a `broker:` block.
A document is a reload like a file's: parsed against the policy in force, bounded by
`inventory.max_removed_percent` (`fix the source of truth, or, …`), swapped in one pointer, its
security changes written as `inventory_change` records, and followed by the refresh. It is applied
only when it is later than the document in force, by `published_at` and then `sequence`: an older
genuine document sent again, by whoever can answer as the service, is refused. `published_at` is
signed and survives a reset of the service's state, so a service that starts again from sequence 1
publishes later and is applied, and a sequence that goes backwards is applied only then. A refused one
is said once per document, `port49_inventory_bundle_refused` is 1 until the service confirms the
bundle in force or sends a new document, and `SIGHUP` tries the
document held again after the bound is raised. `SIGHUP` also re-reads
`inventory.service.verify_key_files`, read behind the write fence as the policy file is, since
whoever can write a verify key accepts any inventory it signs; so a signing-key rotation needs no
restart. `port49_inventory_snapshot_age_seconds` is the time since the service last confirmed the
document in force, or one was loaded; a start from the persisted copy or the mirror counts it from
that document's `published_at`, so a restart never makes an old snapshot look fresh; until a start
has a snapshot it has no age, and the gauge reads NaN, which no comparison matches, so the
staleness alert is `port49_inventory_snapshot_age_seconds > N or
port49_inventory_snapshot_age_seconds != port49_inventory_snapshot_age_seconds`. A copy refused
only because its `published_at` is ahead of port49d's clock is judged again at each pass of the
wait, so a host that booted with its clock behind starts from it once the clock is right; when the
clock was the only refusal, that start clears `port49_inventory_bundle_refused`. The mirror is
read under a 10 s deadline at start: a hung mount is passed over, said, and never holds up a start
from the persisted copy. A copy that could not be read — a mirror that hung, a read that failed, a
persisted copy the fence refuses — is said with why and is not a refusal; a mirror that could not
be read sets `port49_inventory_mirror_unreadable` to 1 until the next start. A document that was
read and failed verification or its checks, from either copy or the service, sets
`port49_inventory_bundle_refused`; so does one whose `published_at` is more than 5 minutes ahead of
port49d's clock, which would otherwise outrank every later copy.

**A reload of either source tries both together when both have moved.** At `SIGHUP`, and whenever
a load of one is refused while the other holds a settled version not in force, port49d builds the
bundle from both and bounds it against the bundle in force as one step, by `bundle.Check` and the
policy's bound together. The policy's bound judges what the policy does: against the policy in
force over the new inventory, so a device the inventory change takes out of service is the
inventory's, quarantined as decision 20 says, and the line names the policy file only when the
policy is the cause (if the policy in force does not parse over the new inventory, every device
is counted as the policy's). It passes and one swap applies both; it fails and neither is
applied, one line naming both. A whole-fleet re-address with its key group — where each file
alone admits none — then loads, and no bundle between the two revokes a context the final one
keeps.

**A policy reload is held to the same bound.** Key groups are policy, and a refused device's live
contexts are revoked and its tokens deleted, so a `key_groups` edit that misses the fleet would
otherwise log everyone out within seconds, and a revert would not bring the sessions back. A
policy reload that newly refuses admission to, or newly quarantines, together more than
`inventory.max_removed_percent` of the devices in service under the policy in force (admitted
and not quarantined) is refused, naming them, unless at least as many of the devices the
inventory held before it are in service after it (a net release; a device the reload adds never
offsets one it takes out; §13 decision 34). The net release never covers refusals: one that
newly refuses admission to more than the bound of the devices the policy in force admits,
quarantined ones included, is refused whatever it releases, as plan 6a's bound refused it,
since the tokens a refusal deletes do not come back on a revert. Either way the policy in force
keeps serving and `port49_policy_file_refused` is 1, and raising the bound and sending `SIGHUP`
applies a deliberate change. A policy reload whose bundle admits no device of a non-empty
inventory is refused whatever the bound, as a start is (above): the policy in force keeps
serving, the refusal is said once, and its line names the deliberate path to take the whole
fleet off, which is to stop port49d.

**The inventory file is privilege-granting, and read as the policy file is.** Its attributes and
names decide scope membership, its addresses are handed to SSH clients by the mint, and a
record's `key_ref` pins a key; a live reload makes an edit effective within seconds. So it is
read behind the policy file's fence (§5.1.3): refused, at start and at every reload, when the
file, the directory holding it, or a directory holding a symbolic link on its path could have
been written by anyone but port49d's user or root, when it is not a regular file, or when it is
larger than 64 MiB. Directories above those are not checked: the deployment must keep them
writable by root alone, as it must for the policy file's (plan 12). At a reload the refusal is said
once and the bundle in force keeps serving; at start it refuses the start. The deployment
documents owe the same warning for this path as for the policy file's (plan 12).

A test in the policy's `tests:` naming a device the inventory no longer has fails `port49
policy test`, and never a load or a reload: CI owns that fix, and an inventory change must not
wait on it.

### Source-of-truth write access is privilege-granting

If scopes match on synced attributes (§5.5), whoever can change a device's `role` or
`os_version` can move it into or out of a scope — with no policy change, no pull request, and
no diff. The policy file looks untouched.

Mitigations, designed in rather than documented afterward:

- Scope-membership changes MUST appear in the sync diff and be reviewable, and so MUST an
  address added to an existing device — the mint response carries that address back for the
  operator's SSH client to connect to, so a rogue address on a real device's record is a
  credential-capture path (design document §17). `port49 inventory diff` prints both, and every
  bundle swap writes one `inventory_change` record (§5.7) for each address added to a device
  already in inventory and each device joining or leaving a scope with `security_log: true`.
  A device's `key_ref` changing, and a device becoming admitted, are recorded the same way: a
  record's pin can move a device onto a weaker or a shared key.
- A scope MUST be able to pin a device set explicitly instead of by attribute:
  `match: {name: [leaf-01, leaf-02]}` reads the device's inventory name, as `platform` reads
  its platform (§5.5).
- Scopes carrying denies SHOULD set `security_log: true`, so membership changes are logged
  and alerted as security events rather than routine inventory churn.
- Attributes used for security scoping SHOULD come from an attested path rather than a
  hand-editable field.
- A connector's token MUST be able to read devices and nothing more. The service never writes
  to a source, and a token that can write turns a compromise of the service into one of the source
  of truth. A webhook's secret is readable by anyone the product lets read its webhooks (both
  products return `secret` from their webhook API, `tests/lab/sot/l30/*/webhooks.json`): it lets
  its holder trigger a sync, which is bounded and reads only the source, and nothing more.

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

**The CVE mitigation is three lines and self-limiting in port49's evaluation.** It applies to
every principal on every unpatched SRX including devices not yet racked, lapses per device as
inventory reflects the upgrade, and admits a deliberate, narrow exemption for incident response
through the same mechanism as everything else. **It does not reach an SRX.** Under the
example's own pin, set 1.0.0, Junos is not projected and never asks per command (decision 21),
so the device is told nothing of the deny. Pinned to set 1.1.0, it fails closed: `cluster` is
not a keyword the shipped tree proves (vJunos-router has no `show chassis cluster`; L26), so
every subject on an unpatched SRX gets the fail-closed reply (`argument_deny`, decision 27),
netops_admins included, and `policy test` fails naming each. A proven word does not rescue it:
`deny show chassis alarms **` lies beneath `view`, which every one of those subjects is sent,
and a deny beneath a sent bit is not a boundary until L26c closes (`refused_shape`, §8). What
a deny projects as on set 1.1.0 is one no sent bit reaches: with `deny: [restart **]` in place
of the cluster deny, netops_admins on srx-fw-04 get `user-permissions=clear network trace view
view-configuration` and `deny-commands=^ *restart( .*)? *(\|.*)?$`, and noc_tier1 and
svc_oxidized keep the narrow `show **` reply they get without it.

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
| `projection_netconf_closed` | on a platform whose pinned set carries `rpc_entry_denies`, a composition whose Junos reply refuses `junoscript`: the entry deny beneath a deny, or the narrow shape's `.*`. The subject has no NETCONF, `xml-mode` or XML API session on those devices (§8; decision 44) | no, a warning; `policy diff` prints the ones the change brings |
| `projection_deny_beneath_view_configuration` | a sent deny that meets `show configuration` beneath a held `view-configuration`: the CLI refuses it and NETCONF is closed, but the bit is what grants the configuration; withhold the bit instead (§8; decision 44) | no, a warning; `policy diff` prints the ones the change brings |

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
asked about (§6). On a projected platform it also reads the configuration, as `show configuration | display set |
display inheritance` prints it (the other pipe order expands the same, L57): groups' statements
expanded where they apply, one capture, refusing any other form (§8). It reads it against the reference
`platform export --classes` writes, and `--config port49d.yaml`, the classes' idle-timeout, is
required. A reference line the device lacks fails it. So does any line under a template class or
template user the reference does not write: a class `allow-commands`, a permission, a template
password. Exempt are the uid Junos assigns, a class's `idle-timeout`, `login-alarms` and
`login-tip`, and a user's `full-name`, which change nothing a session runs (decision 44).

**Configuration groups are judged by the lines they expand to.** The inherited capture prints a
group's statement under each class or user it lands on, and prints no `set groups` and no `set
apply-groups` line (`tests/lab/results/L57-juniper_*.md`, 2026-10-11). So the check judges every
expanded line under a template as a template line, whether a group or the template wrote it. A
permission, an `allow-` or `deny-commands`, an `allow-` or `deny-configuration` (or a `-regexps`
form), a template user's authentication or class, or a statement not known harmless fails; a
harmless one (`login-tip`) passes. A group widening a template is still caught. The capture
cannot name the group, so a failing line says it may come from a configuration group and gives
the pointer `show configuration system login | display inheritance`, whose curly form names the
group behind each inherited line (`## 'view-configuration' was inherited from group
'p49g-perm'`).

What Junos expands (L57, vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15; *provisional on L57*): a
group applied at the top lands under a class for a `<*>` and a `<p49-*>` path;
`apply-groups-except` at the class keeps the group off it; a group applied from inside another
group's definition commits and is not expanded in the inherited capture (whether a session holds
it is a separate L57 cell); a class's own leaf (`idle-timeout`) stands over a group's; a group's
`permissions` lands beside a class's own. A capture is refused as not inherited if any line has
`apply-groups` as a word at any level (`set apply-groups …`, `set system apply-groups …`, `set
system login class X apply-groups …`), or has any `set groups` line; `apply-groups-except` does not
count. That inheritance strips a class-level `apply-groups` as it strips the top-level ones is
*provisional on L57*. `apply-groups-except` survives inheritance at the class it names, and is
neither a sign of that nor a finding.

`--batch FILE...` checks many captures in one run, the CI form (decision 44 ruling 8). Each file
is checked against the inventory device its file name names: the name as it is where the
inventory has it (Oxidized's files, an FQDN), else the name with its last extension removed
(`srx-01.conf` is `srx-01`). Every file is checked whatever one before it found. The run exits 2
when any file's outcome was a usage or "nothing checked" one, else 1 when any file has a
finding or cannot be read.

A `platforms:` block adds to the set's `device_config`, `local_accounts` and
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
does not fail. A subject's `group:` changing fails the gate unless a passing session test naming
that subject asserts the access it resolves to, as a changed `username:` does: who holds a group
subject's access is the group. A new group subject is gated as a new subject's principals are
(§13 decision 38). `machine_group:` is gated the same way, and a subject moved between `group:` and
`machine_group:` with one value is a changed group (§13 decision 41 ruling 8, plan 8b).

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
  `command_projection`, `bits`, `bit_delivery`, `carve_outs`, `local_user_names` and
  `rpc_entry_denies`.
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

**`port49 keys status --policy <file> --inventory <file> --config <port49d.yaml> [--since D]
<log>...`** reads the decision log (§5.7, `device.key_ref`, `device.key_version`, and the
`unvalidated` records) and counts devices per key version, names those whose latest validated
exchange used a version other than `current`, with when, lists inventory devices never seen, and
lists sources whose packets validated against nothing — separating a retired version, unknown
material, an unadmitted source, a refused device, and traffic that is not TACACS+ at all (§10).
It reads no secret: `--config` gives the key names, versions and dates. It is the instrument a
rotation is driven by, and its output belongs in the pull request that retires a version.
**`port49 keys diagnose <device>`** asks port49d, over `admin_socket`, to try every key it holds
on the last packet from that device that did not validate, and names the group and version that
matched; it is manual because the equivalent automatic probe would be a CPU amplifier on an
unauthenticated listener (§10). **`port49 keys show --policy <file> --inventory <file> [--config
<port49d.yaml>] <device>`** resolves which `key_ref` a device matches, by which tier and group,
and, with `--config`, which version to provision; rendering the secret itself is a
separately-authorized operation this build does not offer, since a group key is shared across the
devices in its group. `keys show` and `keys status` name a key by its `key_ref` and version only, and
a `key_ref` has §10's shape (`^[a-z][a-z0-9_]{0,63}$`): one that is not a name is refused, not
printed, since it is most likely a secret pasted there, and neither command prints a
port49d.yaml parse error's text, only its line and a fixed category. A secret that is all
lowercase hex and 64 characters or fewer passes the shape.

**`port49 revoke (--principal <principal> | --cert <file> | --cert-issuer <dn> --cert-serial
<hex>) [--lift]`** and **`port49 revoke --list`** ask port49d, over `admin_socket`, to revoke a
principal or one certificate, to lift a revocation, or to list those in force (§5.1.4). The
socket answers port49d's user and root alone, the people who can already rewrite the policy. A
revocation prints what it reached and names each live context on a platform it cannot reach;
`--cert` reads the issuer and serial from the certificate itself, in the spelling the broker
compares, which is safer than typing a distinguished name. It exits 0 when the revocation, lift
or list is done; 1 when it did not take force (refused or unreachable), or when port49d did not
answer, the revocation then possibly in force (`--list` says); 3 when it took force and did not
finish or was not saved, the mark standing; and 2 on usage.

**`port49 revoke --mine [--device <name> --username <name>]`** and **`port49 revoke --via-agent
[--yes] (--principal <principal> | --device <name> --username <name>)`** send the revocation to
the broker through the operator's own agent (`POST /v1/tokens/revoke`, §5.1.4), under the
caller's `api:` rights (§2): `--mine` ends the caller's own sessions, or its session on one key,
and leaves no mark; `--via-agent --principal` revokes another principal as the admin socket
does, and needs `revoke_others` (naming the caller's own principal is `--mine`, and the answer's
first line says no mark was made and to ask an operator to use the admin socket);
`--via-agent --device --username` ends whatever holds that key, and needs `revoke_others` too.
`--via-agent --principal` asks `y/N` on a terminal first (`--yes` skips it; off a terminal it
does not ask), and prints the target's subject from the answer. A lift, a certificate and
`--list` stay the admin socket's; `--list` shows marks only, and says on stderr that a self or
key revocation, which leaves none, is named in the decision log. It exits as the admin-socket
form does: 0 done; 1 refused (`api_right_missing`, `revocation_busy`, declined at the prompt, no
agent), or sent and not answered by the broker or the agent, the revocation then possibly in
force (`--list`, or for a self or key revocation the decision log, says), since the agent waits
past the broker's own bounds and never sends a revocation twice; 3 in force but not finished or,
for a standing mark, not saved; 2 on usage.

**`port49 identity [--json]`** prints what the broker resolves the agent's principal to (`GET
/v1/identity`): subject, grants unexpired now, `api:` rights, and until when this connection
lasts before it must authenticate again (`connection_ends_at`; a device's own session ceiling may
end a session sooner).

**`port49 explain --device <name> [--command "<line>"] [--principal <principal>]`**, with no
`--policy` and `--inventory`, asks the broker through the agent (`POST /v1/explain`) and prints
its answer from the policy in force, redacted as the offline form's is; `--principal` naming
another principal needs `explain_others`, and `--subject` and `--show-attributes` are the offline
form's alone.

**`port49d init-revocations [--config <port49d.yaml>]`** creates `broker.revocations_file`,
empty, then its marker, once per install, behind the directory fence, reading nothing from
port49d.yaml but that path and the paths it must not collide with (no secret is resolved). The
file comes first, so a crash between the two leaves a file with no marker, which the next start
loads and marks. It runs as the user that owns the file's directory, port49d's, and refuses
otherwise, naming that user. Run it by hand or as a one-off job at install, never on a start
path. It exits 0 when it created both, or when the file is already there and loads ("already
initialized", nothing written); 1 when the file is there and does not load, or the marker is
there without it (a lost file is restored from backup, or replaced by `{"revocations": []}` on
purpose; §13, decision 32), when `broker.revocations_file` is a relative path (it would resolve
against the caller's directory, not port49d's), or when the file appeared while it ran (another
init-revocations is running or has just run; nothing written); 2 on usage.

**`port49d store-roles --config port49d.yaml --broker-config port49-broker.yaml`** prints the
`etcdctl` commands that create port49's two etcd roles and grant them, for the keyspace
`store.etcd.prefix` names (plan 7d; §13, decision 35).
Each flag defaults to its file under `/etc/port49/`. A 7d port49d.yaml naming both identities
is still read from `--config` alone, with a line saying to move the broker's; two files naming
different `store.etcd.prefix` are refused.
- **`port49_daemon`.** Read-write on the token, receipt, receipt-index, context, index-record,
  lookup and blob families (`t/`, `r/`, `rp/`, `c/`, `x/`, `ip/`, `is/`, `ic/`, `b/`), and
  read-only on the revocation marks (`rv/`), the ledger record (`lw/`, plan 7e) and five single
  keys of `meta/`, each granted by itself: `seal_keys` (read at a start), `witness` and `purged`
  (the restore guard), `judged_bundle` (the name of the bundle last judged, which the skew
  gauge reads; the runner writes it beside `meta/judged`) and `ping` (the store probe). It has
  no read on `meta/judged`, which holds the policy file, or on `meta/holder`, `meta/bundles/`
  or `meta/refresh_owed`. Nothing on the token indexes (`tp/`, `tc/`), the idempotency records
  (`id/`) or the superseded record (`sp/`). `CheckIdentity` probes a refused read of `meta/judged`.
- **`port49_broker`.** Read-write on the whole keyspace.
- **The users.** A user per component, named by the CN of the certificate `store.etcd.daemon`
  (in `--config`) and `store.etcd.broker` (in `--broker-config`) name, granted its role.
- **What a stolen daemon key yields under these roles:** decision 35's residual, replay of
  records it cannot forge. While port49d runs that is a deleted token for a holder of its
  secret, or a receipt's sliding bound; across a restart, a context put back while port49d was
  stopped: another login's (impersonation), or an earlier version of its own. It can
  also hide a context from the index until the next sweep re-indexes it, and deny by deleting.
  It cannot write a revocation mark, so it cannot lift a revocation by principal or
  certificate: this role is what makes that true, since a credential holding the whole
  keyspace could delete the marks. That holds for the daemon's credential, which since plan 7e
  is all a port49d host holds (decision 36): the broker's, whose role is the whole keyspace, is
  port49-broker's, and under `store.etcd.roles: unenforced` the daemon's is too.
- **The command itself.** It reads the config and those certificates, holds no etcd
  credential, and changes nothing. It refuses a CN or prefix holding a character outside
  `[A-Za-z0-9._@/-]`, one CN for both components, and a CN of `root` for either (etcd's
  administrator, past every role; config load refuses it first), printing nothing. Its output
  says to check a role that already exists with `etcdctl role get` first: `role add` fails on
  one and leaves its grants, and a grant on another range is added to a role, not replaced.
  It exits 0, 1 naming what it could not read or refused, or 2 on usage.

The output is run once, by etcd's root user.

`port49-broker --config port49-broker.yaml` is the broker on etcd (plan 7e; decision 36). Its
one subcommand, `revoke --offline`, revokes and lifts with every broker down. `port49 revoke
--socket <port49-broker's admin_socket>` revokes, lifts and lists on it.

**`port49 refresh`** re-authenticates the session the agent holds and extends every live context the
policy in force still grants (§5.6). The agent signs the broker's nonce with the certificate's key
over the held connection, and prints one line per device: extended to when, revoked (by the policy,
a mark or a fault; `port49 revoke --list` and the refresh record say which), past its grace window,
not judged, or on a platform the extension cannot reach. `port49 login` does the same while a
session is held for the same broker and certificate, and exits 1 naming the running agent's broker
otherwise; it also refreshes once after a new session connects. On a certificate port49 issued
(§13 decision 43 ruling 11) the refresh is the same key signature, with no browser.
`port49 token` warns on stderr when
the device's session ends within `session.ceiling_warning`. `port49 explain` prints a subject's
ceiling on a device.

**`port49 login`** takes `--broker`, `--broker-ca`, `--cert` and `--key` from the per-user config
file, `~/.port49/config.yaml` (or the file `$PORT49_CONFIG` names), for each one its flags leave
out, and from the system-wide `/etc/port49/config.yaml` the install ships for each one both leave
out. It reads a file only when nobody but the operator or root can write it or any directory above
it, and the system file only when it is root's (§13 decision 42 ruling 6, decision 43 ruling 24).

**`port49 login --oidc [--issuer URL] [--oidc-ca FILE] [--redirect-port N] [--no-browser]
[--sign-in]`**, or `method: oidc` in the config file, gets the person a certificate the broker
issues (§13 decision 43).
- **The sign-in.** At the identity provider `/v1/config` lists, by the authorization-code flow
  with PKCE and `prompt=login`, in a browser, or by pasting back the address it ended on.
- **The certificate.** For a key generated on this host (`~/.port49/issued/`, 0600),
  valid `certificate_lifetime`. The agent then holds the session as on the certificate path.
- **No sign-in** while a held certificate has more than a quarter of its life left, or while the
  provider does not answer and it is still valid; `--sign-in` forces one.

**`port49 devices trust [--fingerprint SHA256:…] [--address ADDR] [--port N] [--replace] DEVICE`**
pins the SSH host key the device presents, in `$XDG_CONFIG_HOME/port49/known_hosts` under its
inventory name.
- **The address.** One mint through the agent gives it; `--address` is the alternative.
- **When it pins.** Only against a `--fingerprint` the operator verified out of band, or a `yes`
  typed at a terminal. On the device's console (L53), NX-OS prints a SHA256 fingerprint beside the
  key; EOS, IOS-XE, vJunos-router and vSRX print the key itself (OpenSSH base64, and on IOS-XE hex
  DER too), so there the operator compares the key, or gives `--fingerprint` what `ssh-keygen -lf`
  prints for it.
- **An existing pin.** It is replaced only with `--replace` (decision 42 rulings 7–9).

**`port49 ssh [--port N] [--ssh PATH] [--ssh-config FILE] [-v] DEVICE [-- COMMAND…]`** mints a
token through the agent and logs in with the operator's OpenSSH (8.5 or later).
- **Host keys.** It refuses a device with no pinned key before minting, and hands ssh the pin as
  the only key it accepts.
- **The token** goes only to the device's own password prompt, once, through ssh's askpass.
- **Exit and warnings.** It exits with ssh's status, and warns on the terminal within
  `session.ceiling_warning` of the device's ceiling (decision 42 rulings 10 and 11).

**`port49 workload token … --scope NAME`** mints, page by page, every device the scope selects on
which the workload holds a grant, in place of a device list (decision 42 rulings 1–5).

**`port49 inventory diff --policy <file> [--new-policy <file>] <old-inventory> <new-inventory>`**
prints what a change to the inventory does to the bundle: devices added, removed and changed,
addresses added to existing devices, `key_ref` and admission changes, and every scope membership
change, the `security_log` ones marked — the review artifact §10 requires. It exits 1 when
port49d would refuse the new inventory (empty, a collision, admitting no device, or more removed
or newly refused than `--max-removed-percent`, default 10). `--config <port49d.yaml>` reads that
bound and the `key_ref`s the file defines instead, no secret read, so a device assigned an
undefined key is refused as port49d refuses it. With `--new-policy` naming a different policy,
port49d runs two bounded reloads; the diff shows each order step by step, each reload's changes
marked as that swap logs them, and exits 1 when neither order takes both, and when either order
takes its first file and refuses the second: port49d then stays on the bundle between until the
first file changes again. Without `--config`, a bundle with no key groups admits only pinned
devices, as port49d reads it, and every verdict says the `key_ref`s went unchecked against
port49d.yaml. An inventory decode error is printed as its line and a fixed category, and a bad
address or CIDR by its position, never its text.

**`port49 inventory sync --service <url> --ca <file> --cert <file> --key <file>`** asks the
inventory service to sync now (`POST /v1/sync`, the `syncers` right) and prints its outcome:
`published`, with the sequence, the swap's summary and every security change marked `!`;
`unchanged`; `refused`, with why; or `failed`. It exits 0 on `published` and `unchanged`, and 1
otherwise. **`port49 inventory diff --service <url> … --from <sequence>`** prints what changed
between that published bundle and the latest, as `inventory diff` prints two files, the
inventory's change judged under the policy the service holds now; the service keeps the last 64.
**`port49 inventory keygen --dir <dir>`** writes the service's signing key (`signing.key`, 0600)
and its public half (`signing.pub`), refuses to overwrite either, and prints the `key_id`.

**`port49 inventory export --service <url> --ca <file> --cert <file> --key <file> --verify-key
<file> [--verify-key <file>] [--from <sequence>] [--out <file>]`** reads the bundle the service
publishes, or bundle `<sequence>` from its history (`GET /v1/bundle?sequence=<n>`, the read right;
the service keeps the last 64), opens it against the verify keys as port49d does, and writes its
inventory in `inventory_file`'s schema to `--out`, written 0600 and never overwritten, or to
standard output, so the offline tools (`policy test`, `policy diff`, `inventory diff`, `explain`)
keep an `--inventory` when no source is a file. The file carries no key assignment, since no
document can. A document that does not open, or whose sequence is not `<sequence>`, is refused and
nothing is written.

**`port49 policy test --config <port49d.yaml>`** adds the key checks §10 requires of CI: it fails
on a key group naming a `key_ref` the file does not define, and on a device assigned one. It
reads §10's "a policy whose `accept` set is empty for a `key_ref` still assigned by a key group"
as that case: `current` is always accepted, so the set is empty only where the key is not
defined at all. It reports an `accept` version whose `retire_after` has passed and one with none.
Without `--config` it still fails on every device admission refuses where key groups are
declared: a tie, and a device no group admits, since port49d serves neither. It fails on a test
naming a device the inventory does not have, which a load no longer refuses (§10).
**`port49 policy diff`** fails on a device the new policy refuses admission or newly quarantines
and the old kept in service, naming it: the edit port49d's reload would refuse over
`inventory.max_removed_percent`, which counts the two together (§10).

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

**Rollback** is `git revert` of the policy change, deployed to port49d's `broker.policy_file`
and the service's `policy_file`, and `port49 inventory sync`; the bundle
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
come from the same directory query that resolves groups, or, with no directory, the identity
subject's declared `username` (decision 38 ruling 16; decision 39 ruling 7); machine subjects declare one, since they have no directory entry. *Amended by decision 41 ruling 4 (plan 8b, 2026-10-09):* a workload certificate whose verifier maps it through the directory takes its identity subject's declared username when it declares one, and its entry's `username_attribute` otherwise, under decision 38 ruling 3. Unique across
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
entry may still supply groups through the certificate-to-directory mapping. *Amended by decision
40 ruling 5:* a workload's directory groups, when built, come only through a machine-scoped group
subject, never a `group:` subject, which is a human subject (design document §7: a workload MUST
NOT inherit a human principal's grants), and through a mapping keyed on the workload's SPIFFE ID.
Plan 8 builds none; plan 8b owns it, with its own lab row (L50). *Built by plan 8b as decision 41
(2026-10-09):* opt-in per `x509` machine verifier, the `spiffe_id` mapping kind, the
`machine_group:` subject. (§2, design document §7)

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
(§5.6) *Plan 5b:* `port49 platform export --classes` renders the idle-timeout (§8), and it
ends an idle session: at 1m0s for `idle-timeout 1`, through `local-user-name` and the `remote`
template, on both Junos images (L24, closed; `tests/lab/results/L24-juniper_*.md`); the largest
value the device takes is unmeasured. Revocation
records naming contexts are plan 7a's (`unreached` on the `revoke` record, §5.7); a refresh's are
plan 7b's.

**22. Session-only projection is bits first, regexes second, chosen per grant, with one
shape refused.** *Measured: L9 and L12 closed 2026-09-29 (`L12-projection-juniper_*.md`).* The generator picks the smallest permission-bit set
covering the composed grant's permits within the level's ceiling, drops a bit where a deny
aligns with it, and emits regexes only for what bits cannot separate: denies beneath a bit,
and permits that dominate a deny under §5.4. A grant narrower than any covering bit renders
as `deny .*` plus one allow alternation, since emitting nothing widens it to the bit. Bits
travel as `user-permissions` per session by default, or as a `local-user-name` template
where a deployment provisions classes. A permit narrower than the bits with a deny beneath
it is refused at load; L12 measured the `-regexps` family's deny-precedence on both images, and
generating that family for the refused shape, which would lift it, is not built. The choice is made from the composed grant, never per role. (§8, §15) *As built in
plan 5b* (§8, "As built"): a reply is proven before it is sent, against a device model in which
the bits are a union and only measured carve-outs subtract; bits that enter configuration mode
are sent only for a grant of everything; the built-in adapter delivers bits as `user-permissions`,
which L12 measured applied over a bitless template on both images; the projection ships in set
1.1.0, where a deny beneath a sent bit fails closed, since port49 assumes no wire deny binds an
RPC the session reaches (option C, *provisional on L26c*; seen to hold for `<get-configuration/>`
beneath `view-configuration` on SRX hardware, operator-reported). "Refused at load" is
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
context and every unspent token on the memory store (on etcd, plan 7d, it ends every unspent
token and keeps the contexts; decision 35), so without a live reload the only way to narrow
an operator's access was to log everyone out — and the edit most in need of reaching a live
session, a grant withdrawn, was the one that could not. The file is reloaded in place,
refused whole if it does not load, and carried into every live context by compare-and-set: a
narrowing or a widening applies from the next command, and a principal with no grant left on
a device has that context revoked. Unspent tokens whose answer changed are deleted, because a redemption would otherwise
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
`user_permissions`; otherwise it is the fail-closed reply. A level the adapter maps to no bits,
its parents' included, is such a composition too (`unwritable`): its ceiling on Junos is none,
so its reply is `deny-commands=^.*$` with an allow only for a permit the bitless baseline itself runs (e.g. `show cli`), where on a platform that renders levels a missing
rendering stays decision 20's quarantine. Every such session is recorded
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
**` are keyword denies; whether one may guard a sent bit is §8's, which assumes no wire deny binds a native RPC until L26c
closes; a `<command>` RPC is bound). A deny naming any word not proven a keyword — a `*` or a `**` anywhere but that
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

**28. The bundle is one pointer, built in port49d.**
*Plan 6a, 2026-09-30.* The policy loaded against the inventory carries the admission index, the
device table, the quarantine and the policy, and `policy.Live` swaps it whole, so no mint, packet
or refresh sees one version's inventory and another's policy (§10). Its name is a content hash
(§10). port49d builds it from `inventory_file` and `broker.policy_file`, watches both, and bounds
an inventory reload as a sync is bounded. Key groups are policy. A device a group cannot admit is
refused on its own, never the daemon. An inventory-only swap leaves a context whose answer did
not change as it is (§5.1.3). Plan 6b adds the service as the other source of the same bundle's
inventory; the policy stays port49d's own (decision 29).

**29. port49d takes only the inventory from the service; the policy stays its own.** *Plan 6a
owner decision 3, built in plan 6b, 2026-09-30.* The service's bundle names the policy it was
built against and carries none. port49d builds its bundle from its own `broker.policy_file` and
the service's inventory, and a hash mismatch is said and alarmed (`port49_inventory_policy_mismatch`),
and the inventory is applied against port49d's own policy; the service's policy is never applied: the service holds third-party credentials and connectors, and a compromise of it
must not reach the grants.

**30. The bundle document is signed, and assigns no key.** *Plan 6b, 2026-09-30, owner decisions
1 to 3 at their defaults.* The service signs each document with ed25519 and port49d verifies every
copy — the API's, its own persisted one, the mirror's — against the keys in
`inventory.service.verify_key_files`, so a shared mirror mount's writers cannot forge an
inventory. A document carries neither key groups nor pins: key assignment is reviewed policy, and a
synced source's writer choosing a device's key is an escalation with no diff; a pin is a policy key
group matching the device's name, at tier 1 (§10). The service reads its own state and mirror against its own
`verify_key_files`, so rotating its signing key keeps its sequence and its bound. A service whose
signing key did not sign the bundle it holds re-seals that bundle under its key as the next
sequence, the fleet unchanged, at start and at each sync, so the rotation order is: add the new
public key to every port49d, add the old one to the service, switch the service's key and restart
it, wait until every port49d holds the re-sealed bundle N+1, and only then drop the old key.
The mirror is a directory the deployment mounts (`mirror_dir`), not an object-store API: no
object-store credential sits beside port49d, and the signature is what makes a shared mount safe to
read.

**31. A connector reads what the lab measured, and a webhook only says "look again".** *Plan 6c,
2026-10-01, rulings where §10 was silent, each the option that denies more.* The connectors select
a profile from `/api/status/` by the releases L27 and L30 measured, refuse a major none measured
unless a profile is named, read only the fields those runs recorded, read GraphQL's `errors`
before its `data`, take a list only when it equals REST's `count` before and after it with no
device twice, follow `next` only on the source's `url` (rebuilding it there otherwise) and no
redirect at all, filter in the service, take primary addresses, and interface addresses only where
named, leave an attribute a device does not give unset, and pass an unrecognized platform through,
said. A device left with no address counts against the bound in
the service and in port49d. A source of truth is `https` with a named CA, its token and
webhook secret named by `secret_env`-style keys until plan 12's `secret_ref`, and never printed.
A webhook arrives on its own TLS listener, since no product can present a client certificate, and
is authenticated by HMAC-SHA512 of its body; it carries nothing into the bundle and only triggers a
debounced sync of its source, so its order is irrelevant and its `timestamp` is read for freshness
alone. A `Fetch` past `sync_timeout` is abandoned and its source not asked again until it returns.
`port49 inventory export` verifies the bundle's signature before it writes.

**32. A revocation is a standing mark that reaches everything, and the broker's listener is
bounded per source and per principal.** *Plan 7a, 2026-10-01, rulings where the design was
silent, each the option that denies more.* A batch reserves its `Idempotency-Key` for every
device, put-if-absent, before its first mint; a duplicate still minting is answered `409
idempotency_in_progress` and never minted for; a reservation lives a minute and is completed or
released by its holder alone. The broker's listener completes each TLS handshake itself, within
10 s, and counts every failure by reason (`untrusted_chain`, `identity_refused`,
`server_cert_refused`, `timeout`, `client_closed`, `protocol`). A source holds at most
`broker.max_pending_conns_per_source` (16) connections not yet bound to a principal, and the next
is reset at accept; a principal holds at most `broker.max_conns_per_principal` (4) held
connections, and a new one closes the oldest of its own certificate, else the principal's oldest,
so dead connections never lock their owner out, one certificate cannot fill the listener, and a
flood from one certificate churns only its own slots. A source is one address (an IPv6 /64 is not
one source), and the global cap is taken before the per-source check, so at global saturation
connections wait in the backlog; plan 12 owns the global cap. A revocation by principal or by
certificate is a mark that stands until an operator lifts it, because the agent reconnects on its
own. A principal is compared as the broker spells it (`user:` and the lower-cased email), one
without a known prefix is refused, and a mark no subject names is written with a warning. The mark
is written first, and a mark that cannot be written revokes nothing and says so, naming the
fallback (remove the principal's grants from `broker.policy_file`, live within two watch
intervals, or stop port49d); then held connections
are closed, unspent tokens deleted, contexts marked and receipts deleted, and the contexts read and
marked a second time, catching a redemption in flight; the broker's listener holds the marks in
memory and answers a marked certificate's or principal's connection `credential_revoked` as it
binds, records it as a refused mint, and closes it (amended after plan 7a's lab: closed without an
answer, the agent survived the revocation on vEOS, the N9Kv and the C8000V; measured as amended in
`tests/lab/results/revoke-*.md`). A mint reads the
marks before anything else and after its last token write, and deletes what it wrote if one
appeared. The minter indexes every token by principal and by certificate before writing it, and
refuses the mint if it cannot. The marks are kept in `broker.revocations_file`, required with a
broker, and read behind the fence with its directory fenced whether or not the file exists. A
start never creates it: a missing file, or one that does not parse, refuses every start (amended
2026-10-02 by the owner's ruling on plan 7a's Task 9 review M1: as first built, an unmounted or
empty volume that passed the fence read as a first install and started with no marks).
`port49d init-revocations` creates it, empty, then a marker beside it (the file first, so a
crash between the two leaves a file a start loads and marks), once per install, run by hand or
as a one-off job as the user that owns its directory (port49d's), and never on a start path:
automation that ran it at every start and tolerated its refusal would re-create the file on the
next empty volume. It exits 0 writing nothing when the file is there and loads, and refuses when
the file is there and does not load, or when the marker is there without the file (a loss,
restored from backup, never re-created). A start still writes the marker beside a file that
loads with none: that creates no revocations file, and it makes a config-managed file's later
loss read as a loss rather than as a first install. Writing `{"revocations": []}` by hand stays
the way to start empty on purpose. Revocation is an admin-socket operation open to port49d's user
and root, and over HTTP `POST /v1/tokens/revoke` under `api:` rights (plan 7c; decision 34).
The store's marks are read at mint, not at the handshake, so `port49 login` still touches no
store; a revoked operator's login is refused at the agent's first request, from the listener's copy. *Amended by decision 36 (plan 7e):*
on etcd the store keeps the marks, each broker process a copy, and the file is retired; a lift
is port49-broker's admin socket's, or its offline command's. (§5.1.4, §5.7, §12; design document §11, §12, §17)

**33. A session ends where its roles say, warns before, refreshes by a signed nonce, and every
certificate's revocation status is checked at every use.** *Plan 7b, 2026-10-01, rulings where the
spec was silent, each the option that denies more; revised after its pre-flight review.*

- **The ceiling.** A role's `max_session_age` is a duration of at least 1m or `never`, the least
  across a device's roles governing, the default staying finite. A device whose ceiling has passed
  is refused per item at mint. The held connection keeps its own ceiling at the default (decision
  17). A policy edit shortens a live ceiling and never lengthens one; a refresh sets the ceiling the
  policy in force gives. A token expires at its ceiling if that comes before its `token_ttl`, and a
  login with a token past its ceiling is refused at redeem, `session_expired` (the final review's
  I-1: on Junos, where a refused session authorization does not stop the login, it is the gate).
- **The warning.** It rides on permits within `session.ceiling_warning` (30m), to the platforms L34
  finds show it (an allow-list) and any an operator lists (`session.ceiling_warning_platforms`),
  and on `port49 token`'s stderr everywhere. L34 closed 2026-10-01 with one platform on the list,
  `cisco_iosxe`; EOS, NX-OS and Junos showed nothing and are warned by `port49 token` alone
  (`tests/lab/results/L34-*.md`). The ruling stands as made: the list is what L34 fed.
- **Past the ceiling.** A context is kept through the grace window and deleted at its first
  authorization after it, by compare-and-set, and the store refuses to extend one past it.
- **The refresh.** On the certificate path it is a single-use 60s nonce, signed by the certificate's
  key over the connection's TLS exporter value, at most one per connection per 10s, with `auth_time`
  the broker's verification time. It extends only contexts the policy in force has just judged and
  kept, and only an operator's `port49 refresh` or `port49 login` triggers it.
- **Certificate status.**
  - **Configuration.** Required with a broker (`disabled: true` an explicit choice), every CRL
    source naming its signing CA (`issuer_file`), which the anchor must vouch for.
  - **CRLs.** A list is verified at load, before it may replace the last good one, move its number,
    or be acted on. A rollback, a delta, an unknown critical extension and a partitioned scope are
    refused. A list applies to a certificate whose verifying issuer is that source's issuer
    certificate, until its next update. It is persisted, and retried with backoff.
  - **The chain.** Every certificate but the anchor is checked.
  - **OCSP.** It is taken only from the issuer or an in-validity delegate with the OCSP-signing
    usage, for the right serial, fresh within five minutes' skew, and cached to its next update, at
    most an hour.
  - **Unknown.** A status that cannot be established is refused as unavailable (503, retried, no
    session ended) unless `on_unavailable: allow` (the owner to confirm, plan 7b D-7b-1).
  - **Revoked.** A revoked certificate is refused before it binds, at mint and at refresh. One a CRL
    newly names, or an OCSP response answers revoked, is revoked through decision 32's marks
    wherever it is still present, from a bounded queue, a store error deferring rather than
    marking.

(§5.1.4, §5.6, §5.7, §12; design document §7, §12, §17)

**34. A principal acts on itself unless a right says otherwise, ends its own sessions without a
mark, and a reload cannot take the fleet out of service.** *Plan 7c, 2026-10-02, rulings where
the design was silent, each the option that denies more.*

- **Rights.** `revoke_others` and `explain_others` unlock what §2 says; `sync`, `keys_show` and
  `replay` are reserved and grant nothing, since no broker endpoint they would guard exists. No
  right widens a mint or a refresh, and `/v1/identity` answers the caller alone. Rights are read
  from the policy in force at each request.
- **Self-revocation.** It deletes the caller's own unspent tokens one by one and marks its own
  contexts by compare-and-set, twice, deletes its receipts everywhere, and leaves no mark, so a
  token minted after it re-admits (decision 15). That re-admission is the join's: it lifts the
  mark for every session open under that `(device, username)`, a stranger's on a leaked token
  included, so the response tells the caller to close such a session on the device, or have an
  operator revoke the principal, before logging in there again. It closes no held connection.
- **Others.** Another principal under `revoke_others` is a standing mark through the admin
  socket's revocation, its origin `api <caller>`, and the response names the target's subject. A
  `(device, username)` under it is ended whoever holds it, with no mark, and the owner's next
  login there re-admits any session still open, which the response says to close. Without the
  right either form is refused 403: the request's form, not the caller's rights, decides what it
  means, so a withdrawn right fails loudly instead of narrowing to the caller's own; the caller's
  own session on one key is `mine` with the key. A lift and a certificate stay on the admin
  socket; an HTTP mark is still made with no `admin_socket` configured (revoking is the safe
  direction), and the response and port49d's start line say lifting it then needs port49d
  stopped and the file edited.
- **Records.** Every `identity`, `explain` and `revoke` call that is authorized or refused for a
  right is one record: the events `identity` and `explain` and the reason `api_right_missing`
  are added; a call refused before its body is read, or as its connection binds, is recorded
  under its own event with a mint's reasons; an explain never records its command. A record's
  `auth` and `principal` describe one credential: a record about someone other than the caller
  carries no `auth`, and names the caller in `origin` or in `explain.asked_by` and
  `explain.asked_by_fingerprint`.
- **Explain.** It answers as the broker mints and the daemon decides, from the policy in force,
  and its record names the bundle. An unknown device is answered exactly as a device with no
  grant, naming no platform, and a principal under a mark is `credential_revoked`. A caller's
  own denied command is answered, in its text, with the name of every role in the whole policy
  whose permits would match it, deliberately: a role catalogue, never who holds a role or where.
  Each role's permits are compiled once per platform per loaded policy, as projections are
  memoized, so a denied explain costs a match per role; a per-principal rate bound was not
  chosen, since its refusal would need a reason code this vocabulary lacks and every explain is one
  record.
- **Health.** `/healthz` and `/readyz` need no certificate and write no record; readiness is
  serving or not, never the store's health (design document §12).
- **The reload guard** (plan 4b, M3). A policy reload that newly refuses or newly quarantines,
  together, more than `inventory.max_removed_percent` of the devices in service is refused, the
  policy in force serving on, unless at least as many devices are in service after it as before
  (a net release, which an incident fix often is). The net exemption counts only devices present
  in the inventory before the reload: a device the same reload adds never offsets a device it
  newly quarantines or refuses, so padding the inventory cannot bypass the guard. The net
  exemption never exempts refusals: newly refused devices alone over the bound of the devices
  admitted, quarantined ones included, are refused whatever the reload releases (plan 6a's
  bound, unchanged), since a refusal deletes tokens a
  revert does not restore; the exemption applies only to the combined count. On a combined
  policy-and-inventory reload the guard judges the policy's effect alone, against the policy in
  force over the new inventory; a quarantine the inventory change causes stays decision 20's
  (task 10 review I1, M1; amended 2026-10-02). The refusal is
  printed redacted (§5.8), says to lower the bound again after a deliberate raise (it bounds
  inventory syncs too), and says the refused file is still on disk and a restart would load it
  unguarded: a start has no policy in force to bound against. An inventory-only reload stays
  decision 20's.
- **The revocations file.** A start never creates it (decision 32, amended the same day), and
  `port49d init-revocations` runs once, as the directory's owner, never on a start path. On
  etcd it is retired (decision 36).

(§2, §5.1.3, §5.1.4, §5.7, §12, §14; design document §12, §17)

**35. The shared store is etcd, every read is linearizable, a login lands with its index and
its revocation check in one step, and no field a login or an authorization trusts is written in
the clear.**
*Plan 7d, 2026-10-02: D1 answered by the owner (etcd); the rest rulings where the design was
silent, each the option that denies more, and the controller's rulings on plan 7d's pre-flight
review (the owner may override them).*

- **Backend.** etcd v3.6. Every acknowledged write survives a leader failover (Raft), so a
  redeemed token never comes back and a revocation mark is never lost. Every read is
  linearizable: a member cut off from the quorum answers nothing, never a stale context. The
  interface stays pluggable; a backend whose replication is asynchronous (Valkey, Redis) is
  acceptable only with its replay window stated (design document §13).
- **Expiry.** Each record carries its own expiry and is read against port49d's clock; etcd's
  leases only reclaim, at least `store.etcd.lease_grace` (5m) later. A revocation mark carries
  no lease, and never expires. A record that does not decode, or an entry whose key does not
  parse, is said by its key alone, never its value, and counted; none stops a revocation, the
  refresh or the sweep for any other record. An index record (`x/`) that does not decode is
  taken unread by a lookup, so a revocation over-reaches onto its ref and the context's own
  record decides; the walk behind `active_principals` and the sweep skip it, and the sweep
  deletes nothing against it; a login, an index write and the re-index write it whole again. A
  lookup or token-index entry whose key does not parse names no ref, so a lookup skips it and
  the sweep deletes it at its revision. A context record (`c/`) that does not decode is
  unreadable, as one the sealing layer cannot open is: a login replaces it, and the refresh and
  the re-index, which cannot revoke it, delete it at the revision they read. The re-index skips,
  logs and counts a ref it fails to re-index, and never fails a start. Any other record that
  does not decode is an error naming its key, never skipped: a revocation that skipped one
  would miss a live context. The marks still deny by principal or certificate throughout.
- **The login is one step.** A login's context write, its index entries, and a check that no
  revocation mark stands for its principal or its certificate that was not there when it
  read, are one transaction.
  - **A standing mark.** A mark that stands, for a token not minted after it, is written into
    the context as its revocation, and the login is refused `credential_revoked`.
  - **What that closes.** A context is never live and unindexed. A redemption racing a
    revocation by principal or certificate writes its context revoked, or is reached by the
    revocation's second pass.
  - **An index that cannot be written.** The login is refused ERROR `store_unavailable` (it
    was a PASS with `index_error`). An ERROR whose write may have committed is §5.6's.
  - **What it leaves.** A self or key revocation leaves no mark, so its window of one round
    trip stays (§5.1.4).
- **The context is sealed whole, bound to its key.**
  - **What is sealed.** Every field the authorizer trusts is sealed with the identity: the
    privilege, the ceiling, the policy blob, the enable mechanism, the maximum privilege, the
    clocks, and the revocation; so is the witness of its last eight logins, which a receipt's
    replay of a PASS requires (§5.6).
  - **Bound to its key.** The cipher's additional data is the context's key, so a record moved
    to another device or username will not open.
  - **The revocation in the clear.** `revoked_at` is kept in the clear as well, so revoking
    needs no key; a read takes the later of the two.
  - **The setters.** A narrow setter on a sealed field reads, opens, applies its rule, seals
    and rewrites on the revision it read. The idle clock and accounting's annotations stay
    plaintext and authorize nothing.
  - **The token and the receipt.** A token's secret, identity and every field a login trusts
    (its kind, expiry, policy blob, session age, enable mechanism, maximum privilege and
    clocks) are sealed, bound to the token's key and ID; a copy of the expiry stays in the
    clear for the store, and a token whose two expiries differ is dropped. A receipt is
    sealed, its first redemption included, bound to its whole key, kind and credential hash
    among it.
  - **Migration.** A token, receipt or context sealed before this does not open: a token is
    dropped, a context is denied and replaced at the next login. The memory store loses every
    record at the restart that installs it, and etcd holds none before plan 7d.
- **The ledger.** port49d keeps, per context key, the write it last made there or first read
  there, named by a write ID sealed into each record and drawn fresh on every write (Ruling
  T12-g). A context that opens at a key under another write (another login's record, or an
  earlier version of the same context, written back) is denied `store_unavailable`, replaced
  by the next login and revoked by the refresh. A record sealed before the write ID (form 2)
  does not open, and is replaced the same way.
  *Amended by decision 36 (plan 7e):* the write ID is a sealed write sequence, the ledger a
  high-water mark per key that every process follows, and the start's seal a base revision; a
  form-3 record does not open.
  - **One per process.** One ledger is shared by every sealing layer, so the daemon's reads
    and the broker's agree.
  - **Sealed after the start's reads.** A start reads every kept context before any listener
    binds, and then seals the ledger. A sealed ledger denies a context at any key it has not
    seen, unless this process wrote it. Before the seal, the first record read at an unseen
    key is admitted.
- **The standing marks are read on every request.** The daemon holds the marks in memory, with
  the store as the authority.
  - **Kept current.** They are loaded at start before any listener binds. A mark is added
    before its write is sent, so a write that commits and whose reply is lost leaves no gap,
    and is taken out again only when the store refused the write, wrote nothing, and the mark
    did not stand already. It is removed once its lift lands.
  - **What they deny.** An authorization, an `enable` and a receipt's replay are denied
    `credential_revoked` for a context whose principal or certificate a mark names, whatever
    the record says.
  - **The cost** per request is one in-memory lookup.
- **What store write access still yields.** A stolen daemon store credential cannot forge or
  move a token, receipt or context, raise a privilege past what port49 wrote, or, under the
  daemon's etcd role (below; §12, `port49d store-roles`), lift a revocation by principal or
  certificate: before that role a daemon credential can write the marks themselves.
  That holds for the daemon's credential, which since plan 7e is all a port49d host holds
  (decision 36): the broker's, whose role is the whole keyspace, is port49-broker's, and under
  `store.etcd.roles: unenforced` the daemon's is too.
  Deleting a record, or making a write conflict, is a denial, except that a write conflict
  on a policy refresh postpones its judgement. What it can do is replay:
  - **a context** port49 sealed earlier for the same key, but only across a restart. While
    port49d runs, the ledger admits only the write it last made at a key, or first read
    there, so an earlier version of the same context is denied as another login's is, and
    cannot undo a self or key revocation (no mark; decision 34) or a policy narrowing. A self
    or key revocation whose plaintext mark landed and whose seal did not is held by the
    ledger's revocation floor: every read takes the latest of the sealed time, the plaintext
    time and the floor, until a later write lands at the key (with several processes on one
    store, each holds the floor of every revocation whose plaintext mark its context feed
    delivered, and reads nothing before that feed has passed it; decision 36). The floor
    holds any revocation whose mark landed, the refresh's of a record put back included
    (Ruling T13b-a), so the session's own record put back after it is answered revoked too,
    and its owner logs in again. Across a
    restart it is the plaintext mark alone, which a put-back replaces, so that revocation's
    `incomplete` answer tells the user to run it again (final review 7d-2 I-1). The
    exception is the write before one in flight or of unknown outcome, admitted until a later
    write lands at the key or a read finds the one whose outcome was unknown, since the store
    may still hold it; put back then, it undoes that write until the next one lands. A read
    that raced a write of the same context, served before that write committed, is read
    again, not denied. That holds across a start after a store gone too, since that start
    keeps the ledger. **Across a restart it is impersonation:**
    (narrowed by decision 36: a start denies a record below the mark the ledger record holds at
    its key)
    the ledger admits the first record read at a key it has
    not seen until the start's reads seal it, so a record put back while port49d was stopped,
    or before the start's first read of its key, is taken as that key's: another login's
    context, until its sealed ceiling, if it has one, or the key's next login, or an earlier
    version of the same context, which undoes a revocation that leaves no mark (the start's
    refresh judges it against the policy in force). A principal or certificate mark still
    denies it;
  - **a token** port49 minted for the same key and ID, deleted since, which a holder of its
    secret can redeem until its sealed expiry;
  - **a receipt's sliding bound**, up to its sealed cap, or its refusal flag, which replays
    PASS only onto the live context that receipt's own principal holds unrevoked, and only
    for a login that context witnesses and the index still reaches it under (§5.6);
  - **the idle clock**: a context kept alive past its idle TTL, to its sealed ceiling if it
    has one, and indefinitely under `max_session_age: never`;
  - **accounting's annotations**: a context's session discriminators cleared, which
    suppresses the `foreign` attribution of its accounting records;
  - **the index**: a context whose index record is deleted is hidden from the refresh and
    from a revocation by sid or `--mine` until the re-index finds and re-indexes it; a
    revocation by principal or certificate still denies it through the marks. An index record
    rewritten to name another principal or another sid, or with a lookup entry deleted, is
    found by the same re-index, which compares the keys listed, each with its lookup entry in
    place, against the context's own sealed principal, sid and certificate; until the next
    re-index it hides the context as a deleted one does.

  That residual is carried, unassigned.
- **The index is plaintext.** The keys revocation reads (principal, device, username,
  certificate, sid) stay plaintext, because revocation must not depend on the encryption key
  (owner's ruling 2026-09-21). On a persistent store every snapshot holds them, and is
  protected as the store is (design document §8).
- **Hard timeouts and a circuit per pool.**
  - **Per call.** Every store call has its own deadline: `store.etcd.call_timeout` (500ms) on
    the token and context pools, and `store.etcd.bulk_timeout` (30s) on the bulk pool, which
    holds the four scans (`ActivePrincipals`, `DeleteReceiptsByPrincipal`, `ListRevocations`,
    `PurgeTokens`). A slow scan therefore trips no hot-path circuit, and the backend pages
    each scan.
  - **Per packet.** Every TACACS+ packet's store work has one too (`store.packet_deadline`,
    2s, 100ms to 2s, at least `call_timeout`). The bound is §15 L13's: the Junos images time
    out a reply at about 3s. So a device hears `store_unavailable` before its own timeout, and
    a redemption's write lands inside the policy refresh's 30s settle pass.
  - **The failure delay.** The packet deadline never shortens the authentication failure
    delay, which sleeps on the server's context. The delay counts from the packet's
    arrival, so the store's time is inside it: a FAIL arrives at max(`packet_deadline`,
    delay), 2s at the defaults, and every failure still costs its sender the whole delay.
  - **The circuit.** After `breaker.failures` (5) consecutive failures, a pool's circuit opens
    for `breaker.open_for` (5s) and then lets one call probe. A failure is any of:
    - a timeout;
    - a caller's deadline that struck mid-call;
    - an etcd error that is not a refusal by the roles.

    A caller that went away is none.
  - **No queue.** A call that cannot get an in-flight slot within its deadline is refused,
    never queued.
  - **Pools.** Token, context and bulk operations use separate slots and circuits; token and
    context operations use separate connections (design document §12).
- **A store gone is a store that is down.** port49d closes every listener when:
  - its store health checks fail `store.etcd.health.close_after` times in a row (decision 37);
  - it loses its hold on the keyspace;
  - the token or the context pool's circuit stays open for `store.etcd.hold_ttl`;
  - or every call on one of those pools is refused for that long (a role revoked at runtime):
    at least `breaker.failures` refusals, none more than `breaker.open_for` after the last.

  The bulk pool's circuit is alarmed, never a store gone: a slow scan while logins and
  commands are answered does not close the listeners. Held TACACS+ connections are reset.
  Devices then find the connection refused and use their local method: the owner's go-dark
  ruling of 2026-09-24, refined by decision 37. port49d then waits in-process for the store,
  `/readyz` 503, with no deadline, and starts again as below, retrying any error that start
  meets. It binds TACACS+ again only after `store.etcd.health.open_after` checks pass in a
  row (decision 37). Once it has served, it never exits for an outage.
  - **The ledger is the process's.** That start keeps the ledger (above) that the first
    start built and sealed: it is never rebuilt, so a start after a store gone does not reopen
    the first-read rule. A record written while port49d was dark, at a key it has not seen or
    under another `ctx_id` than the one it last wrote there, is denied and revoked as another
    login's record written back, which fails closed.
- **Identity.** Each component authenticates to etcd by its own client certificate, its CN
  etcd's user, under the roles `port49d store-roles` prints.
  - **The daemon's role cannot** read idempotency records, write the token indexes, write
    revocation marks, or write `meta/` (the keyspace hold and the seal-key record). That role
    is what makes "cannot lift a revocation by principal or certificate" (above) true: before
    it, a daemon credential is the whole keyspace's. That holds for the daemon's credential
    alone, which since plan 7e is all a port49d host holds (decision 36); under
    `store.etcd.roles: unenforced` the daemon's is the whole keyspace too.
  - **Neither identity is etcd's root.** A certificate whose CN is `root` is etcd's
    administrator, past every role. It is refused for the daemon and the broker alike: at
    config load, by `port49d store-roles`, and by the start check, which also refuses a user
    holding the `root` role.
  - **The start check.** port49d refuses to start when its daemon identity can do any of
    those, unless `store.etcd.roles: unenforced`, said at every start. It reads the daemon's
    own grants (its user's roles and their permissions) and refuses any grant that reaches an
    idempotency record or a token index, and any write grant outside the families the daemon
    writes, whatever its range. Probing reads and never-true writes is the backstop for auth
    being off, when etcd has no grants to read.
  - **Keys and certificates.** Key files load as the broker's key does (owner-only, no
    symlink). Every certificate's validity window, and the CA's, is checked at each start and
    named when it fails: never read as etcd not answering.
- **One port49d per keyspace in plan 7d.** *Amended by decision 36 (plan 7e):* any number of
  port49d serve a keyspace and hold nothing; the hold below is port49-broker's runner's. Read
  "port49d" in these sub-bullets as the runner, and "a second port49d" as another
  port49-broker replica; a runner that loses the hold stops its duties and keeps serving the
  API, where port49d closed its listeners.
  - **The hold.** port49d holds the keyspace on an etcd lease of `store.etcd.hold_ttl` (15s),
    as the broker. A second port49d waits for it, its listeners closed.
  - **A fence.** Every sixth of `hold_ttl` the holder reads its lock key and its lease's
    remaining TTL. It counts the hold lost when the key is gone or on another lease, the lease
    has expired, an answered read reported under half of `hold_ttl` left (judged at its
    send, however long the read took), or, with etcd not answering since, its estimate (the
    last answer's send time plus its TTL) has half of `hold_ttl` or less left. Reads are at
    most a third of `hold_ttl` apart. A read that kept the hold reported half of `hold_ttl`
    or more, and etcd's own count is never below the one it reports, rounded down to whole
    seconds; so the lease then had half or more, and the next decision, within a third,
    comes with at least a sixth of `hold_ttl` left before etcd can expire the lease and let
    another take the keyspace (1.67s at 10s, 2.5s at the default 15s). A port49d that takes
    the lock waits a third of `hold_ttl` before it serves, because a holder whose `meta/hold`
    was deleted sees it gone only within a third while etcd answers it, and the lock was free
    at once. A holder cut off from etcd as the key goes keeps serving until its fence loses
    the hold as it does when etcd stops answering, so the two can overlap briefly then.
  - **`hold_ttl` is 10s to 60s**, and a shorter one is refused at config load. etcd's client
    sends the next keepalive a third of the TTL after a response but checks only every
    500ms, so a healthy lease can report as little as ⌊2·`hold_ttl`/3 − 0.5s − a round
    trip⌋, which must not fall under half of `hold_ttl`. Below 10s that allows a round trip
    of 0.5s or less.
  - **The round trip a hold survives** (to the etcd leader) is the least of three bounds:
    - the keepalive bound just given: about 1.17s at 10s, 1.5s at 15s;
    - the fence read, a `Get` then a `TimeToLive`, two round trips within a sixth of
      `hold_ttl`: about 0.83s at 10s, 1.25s at 15s. One read that times out usually drops
      the hold;
    - `store.etcd.call_timeout` (500ms by default) on every token and context call, past
      which the circuits open and the store is gone after `hold_ttl` anyway.

    So at the defaults `call_timeout` binds: keep every etcd call well under it. A cross-site
    etcd raises `call_timeout`, `store.packet_deadline` and `hold_ttl` together. Past any
    bound port49d closes every listener: dark, never two port49d on one keyspace (design
    document §13).
- **A start on etcd.** *Amended by decision 36 (plan 7e):* on etcd the hold, the marks put
  back (step 2, from the runner's `broker.state_dir/marks.json`), the purge (step 5, only when
  the bundle in force is not the one last judged) and the carry (step 6) are the runner's at
  its takeover (decision 36, the runner and the purge at a takeover). port49-broker serves the
  API before that takeover, and refuses mints `store_unavailable` until it has seen one done
  for the bundle it serves (decision 36, the mint gate at a start). port49d's own start is
  decision 36's, and it purges nothing. As plan 7d built it: port49d waits for the store with
  every listener closed (up to
  `store.etcd.start_timeout`, 30s, then exits 1; `0` waits forever; after a store gone, no
  deadline), and then, retrying while the store errs:
  1. takes the hold;
  2. puts the revocations file's marks into the store (a mark in either stands);
  3. re-indexes every live context whose index record was deleted or rewritten in the store,
     or a lookup entry of it deleted, as it does after every index sweep; a ref it fails to
     re-index is said, counted and skipped (Expiry, above);
  4. applies every standing mark to the live contexts the store kept, by the revocation's two
     context passes, so a revocation a restart or an outage cut short reaches them before any
     listener opens. A kept context that will not open is still marked, and never stops the
     start;
  5. deletes every unspent token, as a restart always did, and marks every key superseded,
     so an idempotent replay mints again;
  6. carries the policy in force into every live context the store kept. What it leaves
     unjudged keeps `port49_policy_refresh_pending` at 1, and is one of:
     - **a context sealed under a key this port49d does not hold.** Every path denies it
       anyway, so it never stops the start, and a later pass judges it (§5.1.3);
     - **a context still changing after every attempt.** Another writer is changing it: a
       writer outside this port49d (its own API and TACACS+ listeners are closed at the
       start, and a touch moves no policy revision). Expect that rarely. It never stops the
       start, because holding the start on it would hand that writer a way to keep port49d
       dark. A refresh pass retries it at once after the listeners open, not at the next
       interval. Until then it answers from the policy last carried into it, and the marks
       are read on every request. A writer that keeps rewriting it keeps it on the grant last
       carried into it, through every pass; `port49_policy_refresh_pending` stays 1. That is
       the exposure such a writer has at runtime too (the residual, above);
     - **a principal whose contexts could not be looked up.** Those contexts would open
       unjudged, so they could serve a grant the policy in force withdrew. That holds the
       start exactly as an outage does: said, counted, and retried with the listeners closed.
       On etcd that lookup fails only as the store being unavailable;
  7. seals the ledger, the start having read every kept context;
  8. binds TACACS+.

  Live contexts survive a restart (what a device then sees: §15 L35). `store.backend: etcd`
  requires `admin_socket`, because editing `broker.revocations_file` with port49d stopped no
  longer lifts a mark the store also holds. A certificate a kept CRL newly names is marked by
  the certificate-status queue's first drain, which runs once the listeners are open.
- **Keys.** A record sealed under a key outside the window is said by its key id. A start
  whose store was last sealed under a current key this window lacks warns
  (`port49_crypt_store_key_unknown`), says that the sessions sealed under it are denied
  `store_unavailable` until a start holds that key again, and never refuses. Those records
  fail closed already, and none is revoked for it (§5.1.3): fixing the key and starting again
  brings them back.

(§5.1.4, §5.6, §5.7, §12, §14, §15; design document §8, §12, §13, §15, §17)

**36. The broker is its own process, any number of each on one keyspace; the ledger is a
sealed write sequence every process follows, and a ledger record the daemon cannot write.**
*Plan 7e, 2026-10-03, rulings where the design was silent, each the option that denies more
(the owner may override them).*

- **A sealed write sequence replaces the write ID.** Every context seal (form 4) carries a
  sequence: the highest of the revision the write compares on, the highest store revision
  this process has been told of, and one above the highest sequence it knows at the key. Each
  write that lands at a key is therefore sealed above every earlier one, and no store writer
  can forge it. A context sealed in form 3 does not open: denied, replaced at the next login,
  and revoked by the refresh as tampered. On etcd every live session ends once, at the
  upgrade.
- **The ledger is a high-water mark per key.** A read admits a record sealed at or above the
  highest sequence this process knows at its key, and raises it; below is denied
  `store_unavailable`, as decision 35's ledger denies a record not last written. A key it has
  no mark for admits a record sealed at or above the revision just past its start's scan of the
  contexts: anything at a key then was scanned. A login sealed by another process before that
  scan and committed after it is below it too, as a put-back is, and is denied on this process
  until the next write at its key. A read that raced a write is read again, up to twice. A
  write of unknown outcome needs nothing more: if it landed it is the higher, and if not, the
  record the mark names is still the store's.
- **No record is judged before this process's context feed has passed it.** A read waits until
  the feed has delivered every change through the record's revision, asking the store for the
  feed's progress, for at most the store's call timeout; a feed still behind then is
  `store_unavailable`, counted as a store failure, so a feed that has stopped takes port49d dark
  as a store that has stopped does. A record at the revision this process last knew at its key
  needs no wait. A put-back is a store write, so it commits above the write it hides, and once
  the feed has passed it the later write has raised the mark. Another process's later login is
  therefore admitted, and an earlier record put back is denied, whichever process wrote either
  and however late the feed. This rests on etcd never sending a progress notification ahead of
  an event it has not delivered, which etcd 3.4.24, 3.5.8 and every 3.6 guarantee; an older
  etcd is a known risk.
- **After an etcd restore** a process's next write seals above every record it knew, so its
  login is admitted and a restored record is denied. Restore with `--bump-revision`: without
  it, a process started after the restore seals below the mark a process that ran across it
  holds, and its logins are denied there until that process writes at the key, so restart
  every process.
- **Every process follows the store's contexts.** After its start's scan it watches the context
  family from that revision. Each change raises the key's mark, never lowers it, and makes no
  mark for a record below the base. A plaintext `revoked_at` at the mark's sequence is the
  key's revocation floor, cleared only by a later sequence, so a revocation whose seal failed
  holds on every process that saw its mark land. A watch whose revision was compacted seeds from
  the ledger record, as a start does, then scans again, raising only: a scan sees each key's
  latest record, and a login a put-back hid while the watch was down is in the record alone.
  A mark is kept while a record it saw could be live: to the latest sealed
  ceiling seen at the key and `session.grace_window`, and for good for a `never` context.
- **The ledger record.** The process that holds the keyspace writes each key's mark, its
  revocation floor and how long to keep it to `lw/<nas>/<user>`, about once a second, raising
  only, by a compare on the record's revision. The daemon's etcd role reads it and never writes
  it. Every start seeds its ledger from it before it scans, so a record put back while every
  process was stopped is denied at its key when the record holds a later mark there, and so is
  one put back while a process's watch was compacted. A floor at a key with no mark (a record
  the revoker could not open) is kept with no lease until the key's next login, which gives it
  the mark's keep; one at a key never logged into again stays, at most one per key. Left: a key
  written and put back within the record's lag, about a second, or while no process held the
  keyspace or its feed was down, and before one recorded it. `port49_ledger_pending` and
  `port49_ledger_behind` say when the record lags.
- **An earlier form says so.** A context sealed in form 3 is named as sealed by an earlier
  port49, expected once after the upgrade, never as altered.
- **The marks are followed too.** Every process loads the revocation marks with the revision
  they were read at, before it serves, and follows them from there. A mark that lands closes
  the held broker connections it names in this process; a lift removes it. A compacted watch
  loads them again and applies the difference.
- **What the broker remembers.** When a refresh or a revocation deleted a key's unspent tokens is
  kept in the store (`sp/`, the broker's role alone) for 20 minutes, past any token's
  `token_ttl` (at most 15m): an idempotent replay on any broker process mints afresh after it.
  Which blobs a process has emitted into its decision log stays the process's, bounded at
  4096: each process's log stays replayable alone, and forgetting costs a repeated `blob`
  record. Which quarantined contexts the refresh recorded stays the refresh's, pruned at every
  complete pass.
- **The records a mint writes while it holds the policy** are buffered and written once it lets
  go, in order, before its response: a log that stalls never stalls a reload. A blob counts as
  emitted once its record has landed.
- **An encryption key id** is 1 to 64 of `A-Z a-z 0-9 . _ -`, refused at load otherwise: it is
  in every sealed record's header and every line about one that will not open.
- **Two processes.** `port49-broker` serves the API and holds the broker's etcd identity alone;
  `port49d` serves TACACS+ and holds the daemon's identity and the device keys alone. Any
  number of each run on one keyspace. port49d holds no hold, and a second one serves beside the
  first. The in-process broker stays for `store.backend: memory` only; on etcd a `broker:`
  block in port49d.yaml is refused, naming the move. A stolen port49d host therefore holds the
  daemon's role alone, which cannot write a mark, `meta/`, the ledger record or the superseded
  record, and a stolen broker host holds no device key.
- **The configuration.** `port49-broker.yaml` is port49d.yaml's schema under the broker's role:
  it requires `broker:` (with `broker.state_dir`, where the persisted CRLs are kept),
  `store.backend: etcd` with `store.etcd.broker`, `encryption:`, an inventory, `key_refs:` (the
  names a policy may assign, no secrets) and `admin_socket`; it refuses `listen`, `keys:`,
  `store.etcd.daemon`, `accounting`, `limits`, the receipt windows, `platforms`, `policy:`,
  `broker.revocations_file`, and any `lab:` key but the seed tokens. port49d.yaml on etcd
  requires `policy: {file, watch_interval}` and refuses `broker:`, `store.etcd.broker` and
  `lab.seed_tokens`.
- **The runner.** The keyspace hold is the runner's: one port49-broker at a time. On taking it,
  it records the seal keys, re-indexes the contexts the index lost, puts back every revocation
  its copy of the marks holds and the store lacks, applies every standing mark to the kept
  contexts, purges the unspent tokens only as below, and carries the policy in force into every
  kept context; then it runs the sweep, the re-index, the ledger record's keeper, the context
  half of every refresh pass, and a full context pass whenever another replica asks for one.
  Every replica serves the API and the admin socket, runs the token half of its own reload's
  passes and certificate status, and follows the contexts and the marks. A runner that loses
  the hold stops those duties at once, keeps serving the API, and tries to take the hold again
  every 5s; a broker's readiness is never the store's. Its mints are another matter: each
  replica serves the API before its runner tries for the hold, and from its start until it has
  seen a takeover done for the bundle it serves (its own runner's, or one `meta/judged` names,
  not in doubt) its mint gate refuses every mint `store_unavailable` (§5.7), ready meanwhile.
- **The purge at a takeover.** The runner records in `meta/judged` the bundle in force, with its
  policy, when a pass leaves `port49_policy_refresh_pending` at 0 and every broker process
  serves that bundle, and at a takeover whose carry leaves nothing owed. A runner taking the
  hold with another bundle in force (an edit made while none ran, a runner gone before its
  settle pass, or a replica serving another bundle) purges every unspent token and records the
  instant for every key; with the same, it purges none, so a rolling restart of the brokers
  keeps everyone's tokens. A token minted in the moment between that instant and the purge is
  purged too, and its login fails `token_not_found`. A replica's own start never mints into
  that moment when the restore runbook was followed: its mint gate stays closed from the start
  until it has seen a takeover done for the bundle it serves, its own runner's or another's that `meta/judged` records, not in
  doubt. A rolling restart, `meta/judged` already naming the bundle, is never held; a first
  start, or one after a policy edit, refuses mints with a retryable `store_unavailable` for up
  to `hold_ttl`/3 and the takeover (plus up to `hold_ttl` when the previous run's lease must
  expire first, as after a crash), and a replica whose bundle the runner does not serve until
  a runner judges it. The runbook deletes `meta/judged`, which is what keeps the gate closed
  after a restore; a snapshot restored without that step brings back a `meta/judged` that names
  the bundle, the gate opens on it at once, and the restore guard and the runner's purge are
  the backstop (each such login fails `token_not_found`). The lab's seed tokens, minted before
  the gate and before "listening on", are not covered: the first takeover purges them. The
  tokens such a takeover would purge were minted under the very bundle
  it then records, so purging by mint time was not taken: it would keep, too, a token another
  replica minted after the instant under a bundle no runner judged. The moment stays for a
  token minted after the gate opened, under a bundle a later takeover finds unjudged (an edit
  whose runner stopped before its settle pass, or a replica serving another bundle). The gate
  at a start was found by plan 8's L49 (`tests/lab/results/L49-oxidized-juniper_vjunos-router.md`:
  run set 3's phase A lost its setup mint to the first takeover's purge, 5 to 21s after
  "listening on"; the note itself is from the re-run after the harness waited the window out),
  and ruled by the controller on recommendation (2026-10-08); Ryan may override. After an etcd restore, the unspent tokens
  (`<prefix>v1/t/`), `meta/judged` and `meta/judged_bundle` are deleted before any port49 process reaches the
  restored store (design §13's runbook): a restore brings back every token redeemed since the
  snapshot, unspent, and a port49d, one that ran across the restore too, would redeem it again
  until the first takeover purges, minutes later.
- **The restore witness.** The runner rewrites `meta/witness` (its name and the time, no
  secret) at most once a second, whenever the store has moved past it. Every broker follows
  it and keeps the highest `ModRevision` it has seen in `broker.state_dir/witness.json`. A
  restored key keeps its `ModRevision`, with or without `--bump-revision`, so a runner that
  reads the witness below its replica's record, at a takeover or while it runs, knows the
  store was restored: it takes `meta/judged` as absent and purges every unspent token, so
  the first takeover purges even when the runbook's delete of `meta/judged` was forgotten.
  It does not cover a port49d serving before that takeover: the runbook's token delete does,
  and so does port49d's own guard: a port49d that finds the witness below what it followed
  refuses every token redemption `store_unavailable` until a runner, once a purge of every
  unspent token is done, writes `meta/purged` (plan 7e Task 15d). A port49d started after the
  restore has followed nothing and cannot tell. It takes the store's witness as its record only once the purge is done. A
  replica with no record says it cannot tell, and goes by `meta/judged`; a snapshot taken
  within about a second of the last witness recorded is not caught.
- **The settle pass** is 30s or two policy watch intervals and 5s after a swap, whichever is
  longer, and the policies since the last settled pass are kept until it completes, so a token
  another replica minted under the replaced policy before it reloaded is judged.
- **Policy across replicas.** Every broker process records the bundle it serves, leased, and
  says when it is not the runner's (`port49_policy_bundle_matches_runner`). A replica that
  swaps, or starts, while it is not the runner asks the runner for a full context pass, which
  judges every live context against the policy in force; a replica that dies unreloaded is
  covered by a full pass the runner owes once its tokens have expired, `token_ttl` (at most
  15 minutes) after it last saw that replica's bundle. Until then the runner records no bundle
  as judged. Each port49d, whose role cannot write `meta/`, reads the bundle last judged and
  sets the same gauge, saying when its own policy differs.
- **The reload guard at a start.** A broker process whose policy file the reload guard would
  refuse against the policy `meta/judged` records stays not ready, mints nothing and takes no
  hold until the file is fixed, so a restart cannot load a file a running broker refused.
- **The daemon's start on etcd** waits for the store and checks its identity, reads (never
  writes) the seal-key record, loads the marks, seeds the ledger from the record and a scan, starts
  both feeds and binds. It reloads its policy file for admission, quarantine and redaction and
  carries nothing into live contexts. It checks the store's health every
  `store.etcd.health.interval` (decision 37), which replaced plan 7e's probe: under 7e's probe
  an idle port49d went dark about 2 minutes into a hang at `hold_ttl` 60s (`L37-*.md`); under
  the checks, within `close_after` × `interval` + `call_timeout`, idle or not (§15 L41), on a
  store or a context feed that has stopped; a run after a store gone keeps the ledger and the
  marks.
- **The revocations file is retired on etcd**, which persists the marks; it stays for the memory
  store, with `port49d init-revocations`. Each broker process keeps its own copy of the marks it
  followed, adding each mark and removing a mark only on a lift the watch delivered. The runner
  puts back any mark in its copy the store lacks, at a takeover and before its marks feed
  reloads, and says how many: an etcd restore's lost revocations are revoked again, and a lift
  a copy missed is revoked again too, which the line says how to lift. A put-back that fails
  refuses the reload, so the marks feed stays down and is tried again, rather than lifting
  what the restore lost.
- **A mark a reload finds missing stays in force on port49d.** The daemon's role cannot put a
  mark back, so each port49d keeps every mark it enforces that its marks feed's reload finds
  missing, until a lift its feed delivers or its restart, and says how many and which. An
  etcd restore under a running port49d therefore lifts nothing there before the runner puts
  the marks back; a lift made on a broker while that port49d's feed was down is kept too,
  which denies more. This amends "a compacted watch loads them again and applies the
  difference" above for port49d alone (final review 7e-1 C-1).
- **A reconnect is not a reload.** Both feeds ask etcd for progress notifications and resume a
  re-watch from the last change or progress delivered, so a reconnect within the compaction
  retention reloads nothing, and a lift made meanwhile arrives as a lift.
- **The sockets.** port49-broker's admin socket answers `port49 revoke` (revoke, lift, list).
  port49d's answers `port49 keys diagnose`, and, with no broker in it, a revocation there is
  refused naming port49-broker's socket.
- **Revoking with every broker down.** `port49-broker revoke --offline` revokes and lifts
  through the store on the broker's identity, with no API and no hold, in decision 32's order.
  With no broker host, a mark written as etcd's root under `rv/` is followed by every port49d,
  which denies the session's next command; tokens are deleted only by the next revocation that
  reaches them. The offline tool also stands the mark in that host's `broker.state_dir/marks.json`
  (and drops a lifted one), run as the user port49-broker runs as; the etcdctl path leaves no
  copy, so after an etcd restore every revocation made with every broker down is revoked again
  while every broker is stopped (design §13).

(§5.1.3, §5.1.4, §5.6, §5.7, §12, §14, §15; design document §6, §8, §12, §13, §15, §17,
§19)

**37. port49d goes dark on store health checks, N in a row; a replica answers commands from a
context cache it is told to keep; and port49 ships a container shape.** *Plan 7f, 2026-10-05.*

- **Health checks.** On etcd, port49d checks the store every `store.etcd.health.interval`
  (default 1s, 200ms to 10s, at least `store.etcd.call_timeout`).
  - **What a check is.** A linearizable read on each of its two etcd connections, made at once
    and bounded together by `call_timeout`. The context connection's read waits for the
    context feed (the feed fence).
  - **What fails it.** Any error, a refusal by the roles included.
  - **Where it runs.** Under the guard: it takes no slot and trips no circuit. It runs whether
    or not a device asks.
- **Closing.** `close_after` consecutive failures (default 5, 2 to 60) are a store gone (decision
  35): every listener closes and held connections are reset. Idle or loaded, port49d is dark
  within `close_after` × `interval` + `call_timeout` of the store stopping (5.5s at the
  defaults; measured at 4.8–5.5s on five images, read by a 250ms poll, §15 L41). This replaces decision 36's probe. The
  guard's `hold_ttl` rule stays as the backstop.
  - **What the defaults must survive.** Two conditions with quorum healthy, neither of which
    may close the listeners: a killed leader's election, and one member hung with its TCP
    connection alive (a defragmenting, wedged or partitioned member). port49d's tests assert
    the longest run of failed checks at the defaults stays below `close_after` under both.
    Both pings carry `WithRequireLeader`, so a member with no leader answers at once and the
    client retries another endpoint. A member that does not answer at all costs a check its
    `call_timeout`; clientv3's round-robin puts the next reads on other members. An operator
    with a defragmenting member should expect an occasional `outcome="fail"` and a nonzero
    `port49_store_health_failures`, not zero.
  - **Feed lag is a trigger.** The context connection's read waits for the context feed, so a
    feed more than `call_timeout` behind (a mass refresh burst, for example) fails the check,
    and `close_after` of them close every replica. The same reads are denied
    `store_unavailable` then. An operator who sees dark with etcd healthy looks at
    `port49_store_fence_timeouts_total`.
- **Reopening.** A run after a store gone waits for the store as at a start, re-reading its
  files. It binds TACACS+ only after `open_after` consecutive checks pass (default 3, 1 to 60);
  a failure starts the count again. A cold start is not gated.
- **Break-glass.** Nothing port49 answers changes. On IOS-XE, whose authentication `ERROR` is
  final (§15 L4, L35), break-glass is refused until port49d is dark, now at most
  `close_after` × `interval` + `call_timeout`.
- **The context cache (design §12).** It is off unless `store.etcd.context_cache.ttl` is set
  (100ms to 60s), with `max_entries` (default 65536). Only command and session authorization
  read through it: never a login, an enable, accounting or a token redemption.
  - **A hit:** the entry younger than the TTL, the context feed up, and no later record known
    at the key. What bounds a hit is the TTL, not the feed's `Up()`: `FollowContexts` marks the
    feed up before its watch is established, and a watch hung on a dead connection reads up.
    A hit is also refused while the feed is behind a read (`Fence.Behind()`, a fence wait in
    flight): that read goes to the store, a miss for the milliseconds a wait lasts.
  - **Eviction:**
    - a write through it evicts the key;
    - every change the context feed brings evicts its key, a delete included;
    - a compacted rescan clears it.

    So a revocation reaches a cached session at the feed's speed.
  - **Through an outage.** A read the store fails to answer (a timeout, an open circuit) is
    answered from the entry the ledger still knows, within the context's idle TTL, counted
    `stale` and said once. Never on a fence timeout: that is the store answering with a later
    record than the cached one, which may be a revocation, so the read is denied, nor while the
    feed is behind a read it timed out (an open circuit or saturated slots then is no outage). A
    revocation made during a true outage does not reach a cached session, until a read lands
    or the listeners close. The cache lives for one run.
  - **Blobs** were already cached compiled by hash (§5.1.1).
- **Who sets it.** Both `store.etcd.health` and `store.etcd.context_cache` are port49d's;
  port49-broker.yaml refuses them.
- **The container shape.**
  - **The image.** One image of the four static binaries, run as uid 65532.
  - **The stack.** A compose stack (`deploy/compose`) of port49d, port49-broker and three etcd
    members with client-certificate auth and port49's roles. It has one configuration volume
    per component (no container holds both etcd identities, and the device key is in port49d's
    alone), and a named volume per broker for `broker.state_dir`, created 0700 and owned by
    the broker's user from the image.
  - **The test.** A CI smoke test brings it up, logs a device in, recreates it with its volumes
    kept, and finds the session, a token minted before, and `broker.state_dir` kept.
  - **Not required.** It is one shape beside systemd and Kubernetes. Nothing requires it.
  - **Source addresses.** What a published port does to a device's source address is §15 L39
    (a).

**38. The directory: one entry per certificate or no principal, membership kept in the store,
every matching subject composes, and a scheduled refresh stamps refreshed_at.** *Plan 7g,
2026-10-05.*

- **The defaults.** `session.staleness_ceiling` 4h (`0s` disables it, said at every start),
  `broker.directory.grace` 4h and `broker.refresh_interval` 5m: approved by Ryan (2026-10-06), as
  OR-1. The runbook line: at the ceiling live sessions deny `context_stale` from a reachable
  port49d, so break-glass does not help on them; the escapes are `session.staleness_ceiling: 0s`
  with a port49d restart, or stopping port49d so devices fall back to break-glass (L4). Alert at
  half the ceiling (§5.7). Upgrade every broker before port49d: a new port49d beside an old
  broker that never stamps `refreshed_at` denies every session at the ceiling after its login.
  Design §9's "MUST be explicit configuration" is amended to match (Task 1); Task 15 builds the
  default.
- **1. The mapping is configured, and it is one of six.** `broker.directory.certificate_mapping`
  takes `kind` and `attribute` (each kind has a default). The strong kinds are `issuer_serial`
  (`altSecurityIdentities`, AD's `X509:<I>{issuer}<SR>{serial}` form, the issuer rendered from the
  leaf's raw DER with `DC=` included, never from `pkix.Name`; an RDN value is written in the form the
  DC's KDC matches, quoted with an inner quote doubled: a value holding a comma, a plus sign or
  an inner quote, or with a leading space, is quoted, and a backslash or a slash is written as
  it is, unquoted and unescaped, measured (L44 run 8 and the quirk CAs' run at ad1e4a9,
  `tests/lab/results/L44-windows_ad.md`: the KDC matched the unquoted value and refused the
  quoted one, where Microsoft's CertNameToStr page lists the backslash and slash
  inconsistently); the rest of CertNameToStr's set (empty, trailing white space, `= < > # ;`,
  newline) is as Microsoft documents it, and L44 did not measure it; an issuer with a
  multi-valued RDN is `identity_unmapped`, and L44 did not measure it (carried to the pre-beta
  review); `<SR>` is the serial's DER content bytes reversed, the sign byte DER keeps before a
  serial whose top bit is set included, measured in the same run) and `sid` (the SID extension,
  1.3.6.1.4.1.311.25.2, on `objectSid`). The weak kinds are `san_upn`, `san_email`, `subject_dn`
  and `cn`. A weak kind, or an `attribute` repointed on a strong one, is refused at load without
  `allow_weak: true` and a non-empty `issuers:` pin, which is checked at every mapping, before
  any search, comparing (OID, value) pairs. A value the kind cannot find is `identity_unmapped`;
  every value is escaped for the filter; a mapping key is a hash of the kind and the value's
  canonical form on both sides. Measured on Windows Server 2025 AD (L44, closed;
  `tests/lab/results/L44-windows_ad.md`), at `StrongCertificateBindingEnforcement` absent (as
  installed), 1 and 2, with the same outcome at each: for `issuer_serial`, the KDC issued a TGT
  for port49's form on AD CS's issuer, on an issuer with a comma (quoted) and on a serial whose
  top bit is set (sign byte included); it refused the issuer least significant RDN first, and
  the serial in certificate byte order. For `sid`, the `User` template's SID extension equalled
  alice's `objectSid`, and the KDC issued a TGT with no `altSecurityIdentities`; a certificate
  with a UPN SAN, no SID extension and no mapping was refused (certificate mismatch). Setting
  enforcement to 1 or 2 changed none of it on this build. Tasks 4 and 8.
  *Amended by decision 41 ruling 2 (plan 8b, 2026-10-09):* a seventh kind, `spiffe_id`, weak, is a
  workload certificate's alone, configured under `broker.identity.machines[].directory` and never
  here; `certificate_mapping.kind: spiffe_id` is refused at load.
- **2. Exactly one entry, or no principal.** One search under `base_dn` with a size limit of 2.
  Zero entries is `identity_unmapped`; two or more, or the server's size-limit-exceeded, is
  `identity_ambiguous` and never the first; a server fault is `directory_unavailable`. Task 8.
- **3. The principal and the username come from the entry, and each must be held by that entry
  alone.** The principal is `user:` + `principal_attribute` lower-cased (one value, printable
  ASCII, an `@`); the username is `username_attribute` lower-cased, canonical and not reserved;
  otherwise `identity_unmapped`. A second entry holding the principal's value is
  `identity_ambiguous`; a second holding the username is `username_collision`; both searches run
  with no `user_filter`, so an entry outside it counts. A derived username a policy subject
  declares is `username_collision`; the declared one stands. A principal is pinned to its entry by
  `objectGUID` or `entryUUID` (else DN), for the life of its membership record, `max(grace, 24h)`
  after its last verification or refusal; another entry claiming it is `identity_unmapped`, and a
  refusal keeps the pin. The escape is `port49 directory forget <principal>` on the broker's admin
  socket, which deletes the record and writes a `directory_forget` report (§5.7); it asks the
  directory nothing and grants nothing, so it is run only after confirming the new entry is the
  same person. The two attributes must be writable only by directory administrators; the
  uniqueness searches hold when they are not. This is a ruling, not a device claim, and is not
  provisional. Tasks 5, 8 and 13.
  *Amended by decision 41 rulings 2–4 (plan 8b, 2026-10-09):* a workload's principal is its SPIFFE
  ID, which its entry must hold byte for byte and alone; its username is its identity subject's
  declared one, else its entry's under this ruling; its pin and its forget are this ruling's.
- **4. The mapping runs once per held connection, at bind, and is pinned.** The order is the
  certificate checks, the certificate-key mark, `Status`, the mapping bounded by
  `query_timeout`, then the principal's mark, so a revoked certificate is answered 401
  `credential_revoked` before the directory is asked. Marks made against the legacy
  email-SAN principal still apply. A refusal is answered 401 `identity_unmapped`,
  `identity_ambiguous` or `username_collision`, or 503 `directory_unavailable` with `Retry-After:
  30`, which the agent retries with no session ended. Task 12.
- **5. A principal matches every subject that names it, and their grants compose.** The grants
  are unioned; `token_ttl` is the least among matching subjects with a grant on the device;
  `enable` the mechanism demanding the most proof (`token`, `auto`, `none`); `api:` rights the
  union. A composition of more than one subject is checked at mint with the joint checks of §10,
  and one a check refuses is `composition_refused` for that principal on that device, never a
  quarantine; the refresh revokes a live context the same way. The record lists them as
  `policy.subjects`. A subject with `enable: none` contributes to a composition in
  which another subject offers escalation only the level its roles reach, capped by its own
  `max_privilege`, never its bare cap, so a composition never reaches a
  ceiling no single subject reaches (Ruling PF7g-i; §5.1). Tasks 11 and 13.
- **6. Nested groups are a required choice of three.** `in_chain`
  (`member:1.2.840.113556.1.4.1941:=`), `recursive` (port49 walks, breadth-first, with a visited
  set and `max_depth` default 16, 1 to 64, a truncated walk only dropping memberships) and
  `direct`. There is no default: an absent `nested_groups` is refused at load, naming the three.
  Measured on OpenLDAP and Samba AD (L42, closed): Samba answers `in_chain` in full, loop included;
  OpenLDAP answers it empty with no error (fail closed: no group is granted), so `in_chain` is
  for Active Directory and OpenLDAP needs `recursive`. `memberOf` lists direct groups only on
  both. Windows Server 2025 AD (L44, closed; `tests/lab/results/L44-windows_ad.md`) answers
  `in_chain` in full: alice `g-leaf`, `g-mid`, `netops-oncall`; carol `netops-oncall`; dave
  `g-loop-a`, `g-loop-b` (the loop answered with no error), in 5 to 6ms, the same sets as
  `recursive`; `direct` and `memberOf` list direct groups only. Tasks 4 and 9.
- **7. A group subject's `group:` is a name or a DN, and a name must be unique.** A DN matches
  by `EqualFold`; a name matches only while exactly one group under `groups_base_dn` has it, and
  a name two groups share matches no one, said and counted. `groups_base_dn` defaults to
  `base_dn`. Ambiguity fails closed. Tasks 9 and 11.
- **8. Binding is one of three mechanisms, always over TLS.** `external` (the broker's own
  client certificate), `gssapi` (a keytab read through `keyfile.ReadSecret`, no SASL security
  layer, pure Go: OR-2; the AP-REQ asks `mutual-required`, as MIT's client does when it asks
  for mutual authentication, since a Windows DC answers an AP-REQ without it with 49,
  `tests/lab/results/L44-windows_ad.md`) and `simple` (the password from the environment by name, said at start
  as the weakest). `ca_file` is required, server names are verified, `ldap://` needs
  `start_tls`. Active Directory takes `external` only over StartTLS ([MS-ADTS] 5.1.1.2): over
  `ldaps://` it answers 7, so a 7 to an `external` bind over `ldaps://` is said with
  that remedy, `ldap://` with `start_tls`. On Active Directory a 49 to `external` is said as
  "the certificate is not mapped, or that DC's KDC is not answering" (the L44 note measured both).
  The password, the keytab and a ticket are never logged. Measured on OpenLDAP and
  Samba AD (L43, closed): OpenLDAP accepts EXTERNAL (by `olcAuthzRegexp`) and simple over LDAPS
  and refuses plain LDAP with 13; Samba accepts simple and refuses plain LDAP (8), refuses EXTERNAL
  (1, under `strong auth = yes`; port49 counts 1 as a server fault, so configure `simple` or `gssapi` against Samba), and refuses GSSAPI over LDAPS with no SASL security layer (8) under
  `ldap server require strong auth = yes`, accepting it under `allow_sasl_over_tls`. Measured on
  Windows Server 2025 AD (L44, closed; `tests/lab/results/L44-windows_ad.md`): `external` over
  StartTLS with port49's mapped certificate is accepted (`u:CORP\port49`, result 0), also under
  `LdapEnforceChannelBinding` 2; unmapped (no `altSecurityIdentities`, or a certificate from a
  CA in the DC's Root store but not in NTAuth), 49; mapped with the DC's KDC stopped, 49
  (accepted again when the KDC was back); over `ldaps://`, 7 (the mapped certificate;
  [MS-ADTS] 5.1.1.2 rejects EXTERNAL there). `gssapi` is accepted as installed, and refused (49) under `LdapEnforceChannelBinding`
  2, because port49 sends no channel binding token: against a DC that enforces it, use
  `external` or `simple`. It needs the SPN `ldap/<the URI's host>` on the DC's account, so the
  `uri` names the DC's own FQDN (an `ldap/localhost` SPN added to the DC's account did not
  stay).
  `simple` over LDAPS is accepted, also under `LdapEnforceChannelBinding` 2; over plain LDAP it
  is refused (8, strong auth required). Tasks 4 and 7.
- **9. The server pool.** Ranked same-site first, then `priority` descending, then file order;
  sticky until a server fault or an open breaker; a refused dial (network) is "this server did not
  answer" and fails over; a refused bind (LDAP 49, 48, 8, 13 or 7, a KDC's refusal) is no breaker
  fault but holds off every new bind across the pool, except under `external`, where a refusal
  holds off that server alone and the query fails over, and the pool holds off only once every
  server not open has refused (Ryan, 2026-10-07, on L44 OR-1: a Windows DC whose KDC is stopped
  answers a mapped certificate's EXTERNAL bind with 49, as it answers an unmapped one, L44 run 8,
  so one DC's Kerberos outage must not stop every bind; `external` offers no password, and its
  refusing servers are retried on the same per-server backoff, so the lockout bounds below
  hold), 1m doubling on a server's repeat refusal
  to 15m, each refusing server on its own backoff, one probe bind per step (refusers on one step take
  turns, the one whose own backoff ended first going first, so a repaired server is bound
  within about N × 15m at the cap), any accepted bind
  clearing it, bound connections still serving (the one service account, which AD locks out
  on failed binds counted across every DC; with N servers all refusing, at most N+4 failed
  binds in the first 30 minutes, then one per 15; gauge
  `port49_directory_bind_holdoff_seconds`); each search runs under its own context;
  breakers open after `failure_threshold` (3) and are tried again only by the health check
  (`probe_interval`, 60s); health checks every 30s, 2s each; failback after
  `stability_window` (5m); a site crossing is a logged, counted consistency event.
  `/readyz` never follows the directory: with every server down and every breaker open the broker
  stays ready and serves from grace (Task 16). Task 6.
- **10. Membership lives in the shared store, sealed, and grace reads it.** `mb/<principal>` is
  sealed (DN, entry id, username, group DNs, verified-unique names, mapping keys, `verified_at`,
  server, site); `mk/<hash>` indexes the principal a mapping key resolved to and binds nothing
  alone; a key two principals claim is written ambiguous. Every successful verification writes
  both. The broker's etcd role alone reads or writes them; port49d's role cannot, and
  `CheckIdentity` refuses a daemon role that can (Task 5). A refusal is written too, and grace
  never overrules it. The lease is `max(grace, 24h)`.
  When no server answers, a bind, mint or identity request uses the stored membership if
  `now - verified_at <= grace`; past it, or with none, `directory_unavailable`. Grace is read on
  its own budget, after the pool call's `query_timeout`. Why the store: a process cache would
  deny every operator a broker restart catches in an outage and let two replicas differ. The
  refusal-record rule is a ruling, not a device claim, and is not provisional. Tasks 5 and 10.
- **11. A grace mint never resets the staleness clock.** The token carries `VerifiedAt`; the
  login writes `refreshed_at` as the earlier of that and now; a join takes the joining login's.
  Tasks 3, 10 and 13.
- **12. The scheduled refresh.** Every `refresh_interval` (default 5m, 1m to 1h), for each
  `active_principals` entry, under `Policy.Hold()`: `user:` principals are verified fresh and
  their contexts judged and stamped with the membership's `VerifiedAt`; a machine principal is
  judged by `policy.MemberOf` and stamped with the pass's instant. A fault leaves the contexts
  unstamped, counted `unverified`; an entry gone, ambiguous or a username taken revokes every
  context. Tokens of narrowed or revoked principals are superseded. Without a directory the pass
  stamps its own instant. A policy-reload pass never stamps and judges by the stored membership,
  or by no groups where none is held, it is refused or it is older than grace. Tasks 14 and 15.
  *Amended by decision 41 ruling 6 (plan 8b, 2026-10-09):* a workload whose verifier maps it is
  verified and stamped as a `user:` principal is.
- **13. Rights and identity through groups.** `HasRightOf` is the union over every matching
  subject; `revoke_others` and `explain_others` work through a group from the membership
  verified at that request. A caller revoking only their own principal never asks the
  directory. Machine principals are never sent to it. `GET /v1/identity` answers the subjects,
  the group names and DNs, the username, and the membership's `verified_at` and source. Task 13.
  *Amended by decision 41 ruling 6 (plan 8b, 2026-10-09):* except a workload whose `x509`
  verifier has a `directory:` mapping, which is sent to it and whose `GET /v1/identity` answers
  the same fields.
- **14. `session.staleness_ceiling` defaults to 4h, with an explicit `0s` to disable it.** In
  one process, port49d's load refuses a `refresh_interval` above half the ceiling and a
  `directory.grace` above the ceiling; port49-broker's load never applies the ceiling, and its
  start line states its own values. The lab says `0s`. Approved by Ryan, OR-1 (2026-10-06).
  Task 15.
- **15. The diff gates a changed `group:`.** A subject whose `group:` changed fails the gate
  unless a passing session test naming it asserts the access it resolves to (§12); a new group
  subject is gated as a new subject's principals are. Task 11. *Amended by decision 41 ruling 8
  (plan 8b, 2026-10-09):* `machine_group:` is gated as `group:`, and a subject moved between the
  two keys is a change.
- **16. A directory-derived username never meets a declared human one.** With a directory, a
  `user:` identity subject declaring `username:` is refused at the broker's load; without one it
  is required; the offline tools load either. Task 11.
- **17. Group subjects with no directory mint for no one, and the start says so,** naming
  them. The policy still loads. Task 16.
- **18. What is never logged.** The bind password, the keytab, a ticket, a server's message
  beyond `printsafe.Line`'s 300 bytes, a certificate value the mapping found unprintable. A
  principal, a DN and a group DN may be logged, each through `printsafe.Line`. Tasks 7, 8 and 10.
- **19. The metrics.** No label names a device or a principal; `server` is the configured URI's `host:port`.
  `port49_directory_queries_total{server,outcome}`, `port49_directory_server_up`,
  `port49_directory_selected`, `port49_directory_site_crossings_total`,
  `port49_directory_lookups_total{outcome}`, `port49_directory_walks_truncated_total`,
  `port49_directory_group_names_ambiguous`, `port49_directory_prewarm_principals`,
  `port49_directory_prewarm_last_success_timestamp_seconds` and
  `port49_directory_refresh_last_complete_timestamp_seconds`; `port49_context_refreshes_total`
  gains `unverified`. Tasks 6, 9, 10, 15 and 16.
- **20. Pre-warm.** Every `prewarm.interval` (default 1h, `0s` off), starting 30s after the runner
  takes the keyspace, it verifies the members of every group a policy group subject names,
  enumerated under the nested mode, one query at a time on the sticky server, at most
  `prewarm.max_principals` (default 10000), writing each with every mapping key its entry
  answers to. An operator who has never logged in before can then log in during an outage
  within grace. Task 10. *Amended by decision 41 ruling 6 (plan 8b, 2026-10-09):* the members of
  every `machine_group:` are verified as workloads, by the SPIFFE ID their entry holds, and so is
  every `spiffe://` identity a subject lists, under their own `prewarm.max_principals`.

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

**39. OIDC: a verifier per trust domain, a token validated per request, keys aged out, a logout
that leaves no mark.** *Plan 7h, 2026-10-06.* Rulings rest on reasoning unless they say data.

- **1. The lists.** `broker.identity.humans` and `.machines`. `x509` under `humans` (its
  `trust_anchor_file`, at most one) and `oidc` under either (`issuer` with `client_id`,
  `principal_claim` and `principal_domains` for humans; `audience` and `clients` for machines).
  `x509` under `machines` is plan 8's (decision 40); `k8s` is refused, plan 10. No `broker.identity` is `humans: [x509 from broker.client_ca_file]`; with it,
  `client_ca_file` is refused. An OIDC-only broker requests no client certificate and takes no
  `certificate_status`. Task 7.
- **2. One verifier per token.** A token goes to every verifier whose issuer equals its `iss`;
  exactly one must accept, two is `trust_domain_unresolved`. A human verifier needs `aud` ∋
  `client_id`, `azp` = `client_id` when present and when `aud` has several values, and refuses
  `typ: at+jwt`; a machine verifier needs `aud` ∋ `audience` and ruling 21's client checks.
  A bearer with an `events` claim is refused (RFC 8725 §2.8). The header `typ`, compared
  case-insensitively with any `application/` prefix removed, is allowed, never denied (RFC 8725
  §3.11; Task 5 review): absent or `jwt` for a human verifier; absent, `jwt` or `at+jwt` for a
  machine verifier; any other `typ` is refused (measured on Keycloak, L45 closed; provisional
  on L47). A claim name
  outside printable ASCII is refused, as `encoding/json` would match it to another. Task 5.
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
  listed client (ruling 21; else `trust_domain_unresolved`). A claim absent or unusable is
  `identity_unmapped`. The claim must be one only the
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
- **12. `POST /v1/logout`** (data: OIDC Back-Channel Logout 1.0 §2.4–§2.8; measured on
  Keycloak, L45 closed; provisional on L47). Form-encoded `logout_token`, 16 KiB; the human OIDC verifiers alone, `aud` and
  `azp` as for an ID token; Ruling 3's signature; `iat` (no older than 24h), `exp` when
  present, `jti`, `events`, no `nonce`, `sub` or `sid`, `typ` `logout+jwt` or `JWT` when
  present. A `jti` seen before (24h + 2 × `clock_skew`) is 200 and nothing; a token that does
  not validate is 400 `invalid_request`; a store failure is 503 with `Retry-After` and the
  `jti` given back, departing from BCL §2.8's 400, and a `jti` that cannot be given back is
  said with the manual ends. `Cache-Control: no-store`. Task 12.
- **13. A logout leaves no mark.** A logout record first (by `sid`: every token naming it; by
  `sub`: every token issued at or before the logout's `iat` + `clock_skew`; kept `max_token_age` +
  2 × `clock_skew`, and on a broker that issues certificates `max(max_token_age, 24h)` + 2 ×
  `clock_skew`, decision 43 ruling 16); then each owner principal's own unspent tokens, only
  principals in the
  verifier's `principal_domains`; then the contexts twice (by `sid`, or every context of each
  principal by `sub`); the receipts; one `revoke` record by `sid` or `sub`. A `sid` logout
  also ends a certificate-path context an OIDC refresh extended under it: fail closed. A mint
  reads the logout records before and after its writes. The residual window is a self
  revocation's. A token carrying both `sid` and `sub` is a logout by `sid` and then one by
  `sub` (Ryan, 2026-10-07, on L45: an administrator's "sign out user" names one session's `sid`
  and the `sub`, indistinguishable from ending one session; failing closed ends them all); the
  answer is 503 when either logout record is not written. Tasks 8, 9 and 12; the fix branch
  `fix/logout-sid-and-sub`.
- **14. Revocation by `sid` over HTTP**, under `revoke_others`, `{sid, issuer}`, as a logout by
  `sid`, origin `api <caller>`. Task 13.
- **15. The OIDC refresh** (data: spec §5.6; measured on Keycloak, L46; provisional on L47). A store-held nonce
  from `POST /v1/refresh/challenge` (5m, once, one per principal per 10s), sent as the `nonce`
  of a `prompt=login` authentication; the new ID token's `nonce` taken once, its principal and
  issuer the challenge's, its `auth_time` no earlier than the challenge less `clock_skew`; then
  the certificate path's steps with `auth_time` as the clock; the new `sid` indexed beside the
  old, before the extension; a logout read after the writes marks every context extended.
  Task 11. A broker that issues certificates takes a person's ID token at `POST /v1/certificate`
  alone (decision 43 ruling 13), so there a person refreshes by a key signature.
- **16. `/v1/config`** lists `methods` and, per human OIDC verifier, `{issuer, client_id,
  scopes}`. Task 10. Plan 9b adds `issuance` (decision 43 ruling 18).
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
  21's claim sets are provisional on them. Tasks 15 and 16. L46 closed on Keycloak (2026-10-07), so
  rulings 15 and 21 stay provisional on L47 alone. L45 is measured but open: an administrator's
  "sign out user" over two sessions sent one logout token naming one session's `sid`, which ruling
  13's sid-first logout did not cover; ruled 2026-10-07 (ruling 13: a token carrying both is also
  a logout by `sub`), and L45 stays open until a run measures it.
- **21. A machine verifier takes listed clients with a pinned `sub`** (data: RFC 9068 §2.2;
  OIDC Core §2; measured on Keycloak, L46; provisional on L47). `clients: [{client_id, sub}]`, required; the
  client (`azp`, else `client_id`) listed and the `sub` its pinned one; `azp` and `client_id`
  differing refused; a token carrying `auth_time`, `sid`, `nonce`, `scp` or `amr`, or an `idtyp`
  other than `app`, refused: a person's delegated token never becomes `app:`. A token carrying
  `act` or `may_act` (RFC 8693 §4.1, delegation) is refused as well (Task 5 review). Tasks 5 and 7.
- **22. `principal_domains`.** Each human `oidc` verifier lists the domains whose principals it
  may give, required; a principal outside them is `identity_unmapped`; two verifiers on
  different issuers with overlapping domains are refused at load; a logout reaches only
  principals in its verifier's domains. Machines likewise: two machine verifiers on different
  issuers that list one `client_id` are refused at load, since `app:` + the client id names
  no issuer (Task 2 review). Tasks 5, 7 and 12.
- **23. `principal_claim` is required** (data: OIDC Core §5.7). No default; spec §2's
  "`preferred_username` by default" is withdrawn. Task 7.
- **24. Owner records hold every principal.** One record, a set of `{principal, expires_at}`
  merged by compare-and-set; a logout ends each. Two human verifiers on one issuer with
  different `principal_claim`s are refused. Tasks 7, 8, 9 and 12.

*Open for Ryan (plan 7h's OR-1 to OR-3); the build uses each recommendation until they rule.*
**OR-1:** the JOSE layer in-house on the standard library (ruling 3), not
`github.com/go-jose/go-jose/v4`. **OR-2:** the defaults of rulings 4 and 5 and the refresh
challenge: `clock_skew` 60s, `max_token_age` 2h, `jwks_refresh_interval` 1h, `jwks_max_age` 24h,
5m. **OR-3:** hosted providers are L47, open until measured on an Entra ID and an Okta tenant
(ruling 20); until then the operator notes say measured on Keycloak only.

**40. Workload certificates: one more anchor, the chain's end decides the domain, a SPIFFE ID or
no principal, no directory until plan 8b, and a renewal port49 does not need.** *Plan 8,
2026-10-07.* Rulings rest on reasoning unless they say data. Rulings 5 and 7, and mint by `scope`,
were the plan's open questions; the controller ruled each on recommendation at pre-flight, and
Ryan may override any.

- **1. The verifier.** `x509` under `broker.identity.machines`: `trust_anchor_file` (one
  certificate) and `spiffe_trust_domains` (required), nothing else; at most one. Task 3.
- **2. Exactly one anchor accepts.** The handshake verifies against one pool of both anchors; the
  domain is the anchor every verified chain ends at; chains ending at both are
  `trust_domain_unresolved`. Two anchor files holding one certificate, or one anchor signing the
  other directly, refuse the start; an anchor further down the other's hierarchy is refused only
  at a request whose chain shows it, so the two belong in unrelated hierarchies. On a broker with
  no human x509 verifier, a chain not ending at the workload anchor is `trust_domain_unresolved`.
  Tasks 4, 5 and 8.
- **3. The principal** (data: X.509-SVID §4.1, §5.1). The leaf's one URI SAN, verbatim, a SPIFFE
  ID with a path in a listed trust domain; the leaf not a CA; email SANs never read; else
  `identity_unmapped`, 401 at bind, never a TLS alert. Tasks 4 and 6.
- **4. The SPIFFE ID** (data: SPIFFE ID §2.1–§2.3). `spiffe://`, a trust domain of `a-z 0-9 . - _`,
  path segments of `A-Z a-z 0-9 . - _` (none empty, `.` or `..`), no trailing `/`, at most 2048
  bytes; upper case is refused, never folded. One parser for the policy, the verifier and a
  revocation. Task 2.
- **5. No directory for a workload in plan 8; its directory groups are plan 8b's, constrained.**
  Plan 8 builds no directory path for a workload: never `Resolver.Map`, `Verify` or `Current`;
  never a `group:` subject; the username declared. That is the default, and stays the default once
  plan 8b is built. Decision 16's mapping is deferred, not withdrawn: plan 8b builds it opt-in per
  verifier, keyed on the SPIFFE ID (no existing mapping kind survives a renewal or applies off AD
  CS), reaching only a machine-scoped group subject, never a human `group:` subject (design §7),
  with its own lab row, L50. Decisions 8 and 16 conflict only in the letter; §5.1.3 and decision 38
  ruling 13 record 7g's as-built for the machine principals of the time. *The controller's ruling
  on recommendation (plan 8's pre-flight Q1), deferring rather than cutting under the
  follow-the-spec rule; Ryan may cancel plan 8b.* Tasks 1 and 5. *Built by plan 8b as decision 41
  (2026-10-09); the default above stands.*
- **6. The declared username stands.** A directory-derived username a subject declares is
  `username_collision` for the directory's claimant, whichever came first. The authority is
  decision 38 ruling 3 (plan 7g, a95b9fc), which superseded §2's "later claimant" sentence; §2 is
  corrected to it, an editorial correction. Declaring a username a directory user holds locks that
  user out at the next refresh, and `username_collision` names both. Tasks 1 and 5.
- **7. One certificate status for both anchors, with no per-verifier opt-out.** Required with any
  x509 verifier; a CRL's issuer is an anchor or a CA one signed; an anchor no CRL covers is said at
  start, never a refused start (crossed anchors, ruling 2, are identity ambiguity, a security
  fault; an uncovered anchor is an availability one, and a refused start takes device AAA down for
  everyone). Decision 33 gives no opt-out, and one would weaken status checking: *the controller's
  ruling on recommendation (plan 8's pre-flight Q2)*, revisited only if L48, its CRL fetch trusted,
  measures step-ca's CRL unusable with port49. A 503 for an issuer no source covers is final at
  `port49 workload`, and its detail never says "try again". No source covers it when no CRL
  covers it and no OCSP responder applies: none is set, the certificate names none under
  `use_aia`, its AIA url is not http or https, or the responder answers `unauthorized` or a
  signed `unknown`. A responder that applies and fails (no answer, a bad signature or CertID, an
  answer past its next update) is an outage, retried as a stale list is. *As built in Task 14,
  ruled by the controller on the review's recommendation; Ryan may override* (6b6a1d0, f7b96b8,
  060d016). Tasks 3, 8 and 9.
- **8. The CA enrolls and renews; port49 relies.** A renewal gives the same principal; a mark by
  certificate does not follow it, and `port49 revoke` says so for the workload anchor's issuer and
  any issuer seen on a verified workload chain. Task 7; L48.
- **9. A late renewal is said, never enforced.** Under a quarter of the validity left: one line per
  certificate per 24h and `port49_workload_certificates_renewal_late_total` at each broker replica;
  a warning from `port49 workload`. Tasks 5 and 9.
- **10. The agentless client.** `port49 workload token` and `identity`: the broker reached over
  `https` only and trusted by `--broker-ca` alone (never the system's roots; a redirect is never
  followed), since the client presents the workload's certificate and takes tokens back; the
  files read each run, a
  mismatched pair read again up to three times; one request per `batch_max` page under its own
  `Idempotency-Key`, retried under it on 503 (but an uncovered status), 409
  `idempotency_in_progress`, 429, a failed connection, and a 502 or 504 (a proxy in front of the
  broker that could not reach it: the same failure as a refused connection, and the key makes the
  retry safe), within `--deadline` (2m), but never on a TLS verification failure either way (the
  broker's certificate not under `--broker-ca`, or the broker's alert refusing the workload's:
  wrong CA, a clock off, a chain at both anchors), which no retry mends and which exits 77 naming
  it; tokens to
  stdout or `--out` (0600, renamed into place; a device whose line would hold a control character
  is left out and said); exit 0 (all written), 1 (some written, some not), 2 (usage), 75
  (temporary: the pages minted are written, or the output itself could not be written, and the
  last `--out` stands) or 77 (nothing minted, final). Tasks 9
  and 10.
- **11. A workload's device sessions follow §5.6.** Two principals of one subject on one device
  replace each other's context, logged; the verdicts are the subject's. Tasks 5 and 11.
- **12. `/v1/config`'s `methods`** names a person's: `x509` only with a human anchor. Task 5.
- **13. The lab.** L48 (step-ca) and L49 (Oxidized on five images); `examples/oxidized` was
  provisional on L49, and both closed 2026-10-08 with the example corrected to them (§15). L50
  opens for plan 8b. Tasks 12 to 14.
- **14. What is logged.** A SPIFFE ID, through `printsafe.Line`; never a token; never an unverified
  chain's URI; no SPIFFE ID or device in a metric label. Tasks 5, 6, 9, 10 and 12.
- **15. Revocation and explain take `spiffe://`.** `normalPrincipal` accepts a SPIFFE ID verbatim;
  `system:serviceaccount:` stays plan 10's. Task 7.
- **16. A `spiffe://` identity no verifier can give mints for no one, and the start says so.** Task
  8.
- **17. A CRL scoped to a distribution point is taken, for the certificates that name it.**
  step-ca 0.30.2's CRL carries a critical issuing distribution point naming its own CRL URL by
  `fullName`, and its default leaves carry no CRL distribution point (L48,
  `tests/lab/results/L48-step_ca.md`). Plan 7b refused any such list, so with certificate status
  on every step-ca certificate was answered 503. The list is now taken (§ "Certificate status, as
  built") and applied only where RFC 5280 says it applies: a certificate whose CRL distribution
  point names it. A certificate it does not cover is undecided by it, and undecided fails closed,
  so nothing is weaker; a step-ca deployment adds the distribution point to its leaves with a
  provisioner template (`examples/oxidized`). A list's revocation of a serial stands whatever its
  scope, as the broker's marks already did for every new entry; a certificate distribution point
  that carries `reasons` or a `cRLIssuer` names nothing, since port49 follows no reason partition or
  indirect issuer; an issuing distribution point not in DER is refused. Ruled by the controller on
  the lab's evidence and the review of the change, Task 14.

*Ruled by the controller on recommendation (plan 8's pre-flight, 2026-10-07; Ryan may override
any).* **Q1:** a workload certificate's directory groups are deferred to plan 8b, constrained to
machine-scoped group subjects, not withdrawn (ruling 5). **Q2:** no per-verifier certificate-status
opt-out (ruling 7). **Q3:** mint by `scope` (design §17) is plan 9's, which writes its spec text
first.

**41. Workload directory groups: opt-in per verifier, keyed on the SPIFFE ID, reaching
`machine_group:` subjects alone.** *Plan 8b, 2026-10-09.* Rulings rest on reasoning unless they
say data. The plan's open choices (the workload asked per request, the username, `attribute`
required, the pin required, `broker.directory` reused) were ruled by the plan on reasoning and
are confirmed or overridden at its pre-flight; Ryan may override any.

- **1. Opt-in, per verifier.** `broker.identity.machines[]`'s `x509` verifier takes `directory:`.
  With it, every workload that verifier accepts is a directory principal: exactly one entry, or no
  principal (decision 38 ruling 2). Without it, decision 40 ruling 5 holds unchanged: no workload
  is sent to the directory, and one mints with every server down. `directory:` needs
  `broker.directory`, whose pool, bind, `base_dn`, `username_attribute`, nested mode, grace and
  pre-warm it uses; one `base_dn` keeps decision 38 ruling 3's username search spanning people and
  workloads. Tasks 3 and 5.
- **2. The mapping kind `spiffe_id`.** The block takes `kind: spiffe_id` (the one kind there),
  `attribute` (required: no schema has one for a SPIFFE ID), `allow_weak`, `issuers` and
  `user_filter` (default `broker.directory.user_filter`).
  - **The search.** `(&<user_filter>(<attribute>=<the SPIFFE ID, escaped>))` under `base_dn`, size
    limit 2. Zero entries is `identity_unmapped`; two is `identity_ambiguous`, never the first.
  - **The value.** The entry's `attribute` must hold exactly one value, equal to the SPIFFE ID byte
    for byte. A SPIFFE ID's path is case-sensitive (decision 40 ruling 4) and a directory's
    matching rule may not be, so an entry holding another case of the ID is `identity_unmapped`,
    never that workload.
  - **Uniqueness.** A second entry holding the ID, searched with no `user_filter`, is
    `identity_ambiguous`, as decision 38 ruling 3's principal search is. The search reads no
    values, so a second entry holding another case of the ID, which a case-insensitive matching
    rule returns, makes it `identity_ambiguous` too.
  - **Weak.** It binds a name, not a key, so it is weak under decision 38 ruling 1: refused at load
    without `allow_weak: true` and a non-empty `issuers:`. The pin compares the leaf's issuer, read
    from its DER, at every reading of the certificate (the bind and each request), before any
    search. An issuer not pinned is `identity_unmapped`, answered 401 at bind over HTTP (decision
    40 ruling 3).
  - **What it gives.** The principal stays the SPIFFE ID. The directory supplies the groups, and
    the username under ruling 4. No mapping key is written, since the principal is known before
    the search. `spiffe_id` under `broker.directory.certificate_mapping` is refused at load.
  - **Not the people's attributes.** `attribute` equal, case-insensitively, to
    `broker.directory.username_attribute` or `principal_attribute` is refused at load, naming both
    keys: a SPIFFE ID there would become a device username, or refuse a person (final review M-3).
  - Tasks 2 and 3.
- **3. The membership** is decision 38 rulings 3 and 10's, by the SPIFFE ID: `mb/<SPIFFE ID>`,
  sealed, pinned to the entry's `objectGUID` or `entryUUID` (else DN) for the record's life; a
  refusal written and never overruled by grace; a lease of `max(grace, 24h)`. `port49 directory
  forget spiffe://…` is the escape. Tasks 2 and 5.
- **4. The username** (amends decision 8 through decision 38 ruling 3).
  - **Declared wins.** The identity subject listing the SPIFFE ID gives it when that subject
    declares a `username:`, so turning the mapping on renames no workload.
  - **Else the entry's.** Otherwise the entry's `broker.directory.username_attribute` gives it,
    under ruling 3: lower-cased, canonical, not reserved, held by that entry alone (a second entry
    holding it is `username_collision`), and refused `username_collision` when any subject declares
    it. The declared one stands, whichever came first.
  - **The entry needs one regardless.** A mapped workload's entry always has exactly one canonical
    `username_attribute` value, unique among entries, even when its identity subject declares a
    username: the resolver never sees the subject, so the entry is refused `identity_unmapped` or
    `username_collision` otherwise (`TestAMappedWorkloadsEntryNeedsAUniqueUsernameWhateverItsSubjectDeclares`;
    final review M-4).
  - **Never on a group.** A `machine_group:` subject declares no `username:` (a load error): one
    name for many workloads would put them in one `(nas, username)` context.
  - **Who must declare.** Under the mapping, a subject whose identities are all `spiffe://` IDs
    need not declare one; a subject listing an `app:` identity still must. Since the offline tools
    do not know whether a mapping is configured, `port49 policy lint` reports such a subject as
    `workload_no_username` (advisory): it mints only under the mapping.
  - **One entry, one domain.** An entry whose workload `attribute` holds any value beginning
    `spiffe://` is a workload's. While a workload mapping is configured, the person path (a bind,
    a mint, the scheduled refresh, pre-warm) refuses such an entry `identity_unmapped`, so one
    entry never gives a `user:` principal and a workload one `(nas, username)` context, where
    whichever minted last would hold the other's grants. The refusal tests the prefix, byte for
    byte and case-sensitively, not an exact match to a configured trust domain or a well-formed ID,
    so it refuses more than a workload could claim. A value in another case (`SPIFFE://…`) is not
    refused here, and needs no refusal: only a byte-exact lower-case ID maps a workload (ruling 2),
    so such an entry can never be a workload's. The workload
    path need not mirror it: the person path is the one that grants by `principal_attribute`. An
    entry whose attribute holds no value beginning `spiffe://` (a `description`, say) stays a
    person's. *Added at plan 8b's pre-flight (I-2); the prefix test is re-review N-2's.*
  - **Judged again at the hold.** The mint and a session refresh judge the username again under
    the policy they hold, since a reload can land between the membership read and the hold (plan
    7g's final review M-1). For a workload that judgment is this ruling's, so its own subject's
    declaration is never its collision.
  - Tasks 2, 4 and 5.
- **5. The machine-scoped group subject.** `machine_group: <name or DN>`, matched as decision 38
  ruling 7 matches `group:`: a DN in canonical form, a name only while one group under
  `groups_base_dn` has it.
  - **Its domain is `machines`.** `attached_roles.machines` reach it, never `attached_roles.humans`.
  - **What matches it.** Only a workload resolved through ruling 1's mapping, never a `user:`
    principal. A `group:` subject never matches a workload.
  - **Load errors.** A subject with both `group:` and `machine_group:`, as one with either and
    `identity:`.
  - **Rights.** CI reports its `api:` rights as any subject's.
  - **No mapping.** With none configured, `machine_group:` subjects mint for no one and the start
    names them (as decision 38 ruling 17 for `group:`).
  - Tasks 4 and 6.
- **6. When the directory is asked.**
  - **Per request.** A mapped workload's membership is read by its SPIFFE ID, fresh or within
    grace (decision 38 ruling 10): at mint, at `/v1/identity`, at `/v1/explain`, and as a
    revocation's caller. A workload is never mapped at bind: its principal is known from the
    certificate, and the listener is unchanged.
  - **The scheduled refresh** verifies it from a server and stamps its contexts with the
    verification's time, as a `user:` principal's (ruling 12 widened). A policy refresh judges the
    stored membership.
  - **Pre-warm** verifies the members of every `machine_group:` as workloads. It reads each
    member's SPIFFE ID from `attribute`; one outside the verifier's `spiffe_trust_domains` is
    skipped and counted. It then verifies every `spiffe://` identity a subject lists, in those
    trust domains, so a workload granted by its own identity subject alone is kept warm too. So a
    workload that has not minted within grace can mint in an outage. The workloads take their own
    `prewarm.max_principals`, besides the people's, so one interval verifies up to twice it.
  - Tasks 2, 5 and 6.
- **7. The 3am case.** With the mapping configured, a directory outage past
  `broker.directory.grace` does two things:
  - **Mints stop.** The workload's mints are refused 503 `directory_unavailable` with
    `Retry-After: 30`. `port49 workload token` retries within `--deadline`, then exits 75
    (decision 40 ruling 10).
  - **Sessions go stale.** Its live device sessions go unstamped from the first scheduled refresh
    that cannot verify it, and deny `context_stale` once port49d's `session.staleness_ceiling` has
    passed since the last one that did, from a reachable port49d, where break-glass does not help;
    decision 38's escapes apply. The two clocks are separate: grace bounds a mint, the ceiling a
    session.

  Opting in trades plan 8's "mints with every DC down" for directory groups, and the start line
  says so. Tasks 5, 6 and 7.
- **8. The diff gate and CI.** Decision 38 ruling 15 covers `machine_group:` as `group:`.
  - A changed value fails the gate, as does a subject moved between `group:` and `machine_group:`
    with one value, until a passing session test naming the subject asserts its access.
  - A new `machine_group:` subject is gated as a new subject's principals are.
  - The CI report names the key.
  - Task 4.
- **9. What is logged.** A SPIFFE ID, a DN and an attribute's value, each through
  `printsafe.Line`; never a token; no SPIFFE ID or device in a metric label. A workload's lookups
  count in `port49_directory_lookups_total` as people's do. Tasks 2 and 6.
- **10. The lab.** "`attribute` must be writable only by directory administrators" is a requirement
  on the operator, said at start as ruling 3's is.
  - **Measured by L50, closed 2026-10-09.** Windows Server 2025 AD and Samba 4.17 AD gave the same
    matrix (tests/lab/results/L50-windows_ad.md, L50-samba_ad.md):
    - An ordinary domain user writes none of `uid`, `description`, `wWWHomePage`, `url`.
    - The entry itself (`SELF`) writes `wWWHomePage` and `url`, whatever the OU's ACL; not `uid` or
      `description`.
    - A member of Account Operators writes all four, whatever the OU's ACL.
    - A delegated OU administrator ("create, delete and manage user accounts") writes all four. An
      inherited deny on the OU refuses its direct write, but it adds an allow for itself on the
      entry and then writes; owning the entry alone does not let it write.
  - **So the docs say:**
    - On AD the attribute is `uid` or `description`, never `wWWHomePage` or `url`. The start line
      says so when `attribute` is either.
    - Whoever can change the entry's ACL decides a mapped workload's groups: domain administrators,
      Account Operators, and any delegate with full control over user objects in the entry's OU.
      Each is a directory administrator for this purpose; keep Account Operators empty and delegate
      the workloads' OU only to whom you would trust with the groups those workloads reach.
    - The docs prescribe no deny ACL: the measured one binds none of the measured writers that the
      default ACL does not already refuse. A narrower delegation, without write-DACL or
      take-ownership, was not measured, and the docs assert nothing about it (rule 1).
    - A write reaches the audit log only with directory-change auditing on (Windows events 5136 for
      an accepted write, 4662 for both, one sample of 5136 about 9 s after the write; Samba's
      `dsdb_json_audit` at level 5, turned on at runtime with `smbcontrol all debug`, a persistent
      `smb.conf` setting unmeasured); as installed, neither directory logs it. Whether a
      delegate's ACE change is itself logged was not measured.
  - Task 8.

**42. The agent in full, first part: sweeps by scope, the per-user config file, `port49 ssh` with
pinned host keys.** *Plan 9a, 2026-10-09.* Rulings rest on reasoning unless they say data. Plan
9a's pre-flight questions Q1–Q5 were answered as the plan recommended; Ryan may override any.
Plan 9 is split: 9b the OIDC public client, 9c hardware-backed keys and the broker certificate's
CRL check, 9d host keys from inventory and the Python and Ansible clients.

- **1. Mint by scope** (design §17: "a device name or a `scope`, resolved through inventory").
  - **The request.** `POST /v1/tokens` takes `scope` in place of `devices`, one or the other, and
    `after` to continue a sweep. `scope` is 1 to 253 printable ASCII characters, as a device name
    in a `devices` list always was. `after` is 1 to 255, the longest name the bundle admits for a
    device (`bundle.NameOK`), so the `next` of a page is always an `after` the broker accepts and a
    long inventory name never stalls a sweep. Anything else is `400 bad_request`: both keys (a
    `devices` key beside `scope` is refused even when empty), `after` without `scope`, neither.
  - **The page.** In the byte order of their inventory names, after `after`, at most `batch_max`:
    the devices the scope selects (§5.5) on which the caller's subjects hold a grant unexpired
    now. `next` names the page's last device when more remain, and is absent at the end.
  - **Per item.** Each device is answered exactly as the same device named would be: the same
    records, the same refusals, a quarantine or a refused admission included.
  - **When the page is resolved.** Against the policy in force when the request arrives, before
    the reservation, which needs the list. Each device is then minted under the hold. A reload
    between the two changes an item's answer, never the list.
  - Task 2.
- **2. No enumeration oracle.** These three are one answer, byte for byte, and one record:
  - a scope the policy does not declare;
  - a declared scope selecting no device the caller holds a grant on;
  - a page past the end.

  The answer is 200, `results: []`, no `next`; the record is one `mint` record, `deny
  no_grants_matched`, carrying the sweep and no device. A sweep never lists a device the caller
  holds no grant on, so it tells the caller nothing a mint by name would not. Any declared scope
  may be swept, intersected with the caller's grants (pre-flight Q3).

  **Nor a timing oracle, up to a logarithmic term.** A page walks only the devices the caller
  holds an unexpired grant on, from an index built once per policy, never the inventory. The
  swept scope filters that walk, and an undeclared scope is walked as one selecting nothing. So
  what a page costs depends on the caller's own grants, and on the swept scope's size only by
  the logarithm of it: each device visited is looked up in the scope's sorted list by binary
  search, which an undeclared scope, an empty list, skips. For a caller granted 50,000 devices
  and a declared scope of 10,000 that selects none of them, that is about 700,000 comparisons, on
  the order of a millisecond, which enough samples could tell from an undeclared name. The term is
  accepted as low impact; it is not claimed away. Task 2.
- **3. Paging and idempotency.**
  - **Its own request.** Each page is its own request under its own `Idempotency-Key`.
  - **A retry.** A retry under the key, with the same body, is resolved again. Devices minted
    under the key are replayed, never minted again. A reload between the page and its retry that
    adds a granted device below the page's end shifts the page by one. Its last device, minted
    under the key, is then not in the retry's answer, and the next page mints it again. The first
    token is never returned and expires at its TTL.
  - **The policy each page sees.** Each page is resolved against the policy in force when it is
    asked. A device added below the cursor during a sweep is in the next run's sweep; a device
    removed is not answered.
  - **The client** stops when `next` is absent, and refuses a `next` that does not advance past
    `after`: a fault, never a loop.
  - Tasks 2 and 3.
- **4. The record.** A record a sweep page writes through the mint carries `sweep: {scope,
  after}`:
  - each item's `mint` record, permit or deny;
  - the empty page's;
  - a refusal of the whole page by the mint path: the directory's, the store's, a username
    collision, the mint gate.

  Two kinds do not carry it: the `store_unavailable` refusal written when the revocation re-check
  fails after the page was minted, and the revoked or logged-out records that re-check writes.
  Task 2.
- **5. `port49 workload token --scope NAME`.**
  - It sweeps in place of `DEVICE…` and `--devices-file`; naming both is usage, exit 2.
  - Nothing selected for the workload exits 77, with one message for an undeclared scope and an
    ungranted one alike.
  - `examples/oxidized` takes `PORT49_SCOPE` in place of `OXIDIZED_NODES`.
  - Task 3.
- **6. The per-user config file** (plan 3's rulings, 2026-09-24).
  - **Where and what.** `~/.port49/config.yaml`, over the system-wide `/etc/port49/config.yaml`
    key by key (decision 43 ruling 24; plan 9a's `$XDG_CONFIG_HOME/port49/config.yaml` is refused,
    naming the move), holding `broker`, `broker_ca`, `cert` and `key`. Plan 9b adds `method`,
    `oidc_issuer`, `oidc_ca` and `oidc_redirect_port` (decision 43 ruling 19).
  - **Precedence.** `port49 login` takes from it each value its flags leave out; a flag always
    wins.
  - **Paths.** A relative path is taken from the file's directory, and `~/` is the home
    directory.
  - **Who can write it.** It is read only when this user or root owns it and every directory
    above it up to the home directory or `/`, none is writable by group or others (a sticky
    directory, as `/tmp` is, excepted), and it is no symlink. Whoever can write it chooses which
    broker the operator trusts.
  - **Strict.** An unknown key, or a second YAML document, is refused. `--config FILE` names
    another file, which must exist; a missing file at the default path is no file.
  - **The CA.** `broker_ca` stays required, from the flag or the file, and never falls back to the
    system roots. It pins the CA that issued the broker's certificate, not the leaf, so a renewal
    breaks nothing. A CA file the config file names is refused when group or others can write it.
  - **Not `port49 workload`.** A cron job states what it trusts on its own line.
  - Task 4.
- **7. Pinned host keys** (design §17).
  - **The file.** `$XDG_CONFIG_HOME/port49/known_hosts`, in OpenSSH's format, one line per key,
    whose host field is the device's inventory name. It is held to ruling 6's ownership rule.
  - **How `port49 ssh` uses it.** As ssh's only known-hosts source, with the device's name as
    `HostKeyAlias` and strict checking. A key is checked against the device it was pinned for,
    whatever address inventory gives today, so an address moved to another host fails before
    authentication.
  - **No pin.** A device with no pinned key is refused before anything is minted.
  - Tasks 5 and 6.
- **8. Names.** `port49 ssh` and `port49 devices trust` take device names of letters, digits, `.`,
  `_` and `-`, starting with a letter or a digit, 253 at most.
  - `known_hosts` reads `*`, `?`, `!`, `,` and `[` as patterns, and a leading `@` or `|` as a
    marker or a hash, so a name holding one could pin a key for other devices.
  - A name outside the set is refused with the reason; `port49 token` still serves it.
  - Task 5.
- **9. `port49 devices trust DEVICE`.**
  - **The address.** It comes from one mint through the agent, asking a 60s TTL; the token is
    never used and expires at its TTL. A device the caller holds no grant on is refused there, so
    trust is no oracle. `--address` skips the mint (pre-flight Q4).
  - **The key.** It is read by a key exchange abandoned before authentication: no username is
    offered and no credential is sent. L53 measured what the five platforms do with that: no
    TACACS+ exchange and no decision record; no count against IOS-XE `login block-for` or NX-OS
    `aaa authentication rejected`, the two limits measured (no other limit was); and a line in the
    device's log on EOS (`/var/log/secure`), IOS-XE, vJunos-router and vSRX, but none in NX-OS's
    logfile, which does record the refused-login control.
  - **When it pins.** Only when `--fingerprint` equals the SHA-256 fingerprint presented, or the
    operator answers `yes` on a terminal. Never on a non-terminal without `--fingerprint`.
  - **An existing pin.** It is replaced only with `--replace`.
  - Task 5.
- **10. `port49 ssh DEVICE [-- COMMAND…]`** (pre-flight Q1: the operator's OpenSSH, 8.5 or later).
  - **Why 8.5.** What was measured is in `tests/ssh-compat/2026-10-09-openssh-askpass.md`, in
    containers:
    - OpenSSH 8.0p1 and 8.2p1 ignore `SSH_ASKPASS_REQUIRE=force` and take the terminal prompt.
    - 8.4p1 honours `force`, as 8.5p1 does. Run with no controlling terminal and `DISPLAY` set,
      8.0p1 and 8.2p1 also ask the askpass.
    - On 8.0p1, 8.2p1 and 8.4p1, a keyboard-interactive prompt reaches the askpass as the
      server's bare text (`Password: `). 8.5p1 names the host, as `(<user>@<HostKeyAlias>)
      Password: `.

    What follows is reasoning from that, not measured (the note ran no jump host): with a bare
    prompt the askpass cannot tell the device's prompt from a jump host's, and could hand the token
    to a host that is not the device. 8.0p1 and 8.2p1 fail on `force` and, by the no-terminal
    route, on the prompt; 8.4p1 on the prompt alone. `port49 token` serves an older ssh.
  - **The command line.** `ssh_config` is honoured. The command line forces:
    - the pinned file, `HostKeyAlias`, `StrictHostKeyChecking yes`, no host-key update, no DNS or
      `KnownHostsCommand` source. The file's path and the address are quoted and `%`-escaped, since
      ssh expands `%` tokens and splits on whitespace there;
    - `PubkeyAuthentication no` (L51: every refused key counts against the device's attempt
      limit, and an IOS-XE `login block-for` locks the source address out);
    - `PreferredAuthentications keyboard-interactive,password`, one prompt each;
    - no multiplexing, no agent forwarding.
  - **The token's route.** It reaches ssh through ssh's askpass alone. That askpass is port49
    itself, which ssh runs with `SSH_ASKPASS_REQUIRE=force` and one argument; it asks `port49
    ssh` over a socket in the agent's 0700 directory. The token is never in argv or the
    environment. A port49 that ssh's children run otherwise (a `ProxyCommand`, a `Match exec`)
    inherits the socket's variable, and refuses to run as a command there when given two or more
    arguments. Given one, it acts as an askpass for that argument as the prompt, which moves no
    token, since that prompt is not the device's.
  - **A token that expired first.** When the device's prompt comes within 5s of the token's
    `expires_at` or after it, as behind a slow jump host, `port49 ssh` mints once more through the
    agent and answers with that token, still once. When no fresh token is had, nothing is sent,
    ssh is ended, and `port49 ssh` says why.
  - **Answered once, to one prompt.** The token is answered once, to the prompt naming
    `<username>@<device>`. OpenSSH 10.2p1 writes `alice@leaf1's password: ` and
    `(alice@leaf1) Password: `, observed against an `x/crypto/ssh` server while plan 9a was
    written (no note records it; Task 6's askpass tests pin the forms). L54 measured the second
    form, `(user@device) Password:`, which keyboard-interactive uses, on all five platforms, where
    the askpass answered it once; no platform took `password`, so the first form is not measured.
  - **Other prompts.** Any other prompt, a jump host's, is asked of the terminal as ssh would ask
    it: a password with echo off, and a yes/no question with echo on.
  - **A second ask.** A second ask for the device's password, which ssh makes when the device
    refuses the token and offers another method, ends the connection before ssh answers it. No
    second or empty password reaches the device's failed-login counters.
  - **Exit.** ssh's exit status is `port49 ssh`'s. A 255 is explained: before the token was sent,
    or after it.
  - Task 6.
- **11. The in-session warning** (decision 33).
  - **Before ssh starts.** Within `session.ceiling_warning` of the device's ceiling, `port49 ssh`
    says so, as `port49 token` does.
  - **During the session.** For a session that outlives that moment, it says so once, on the
    terminal, at that moment.
  - **After a refresh.** `port49 refresh` in another terminal extends the session in place (§5.6).
    The agent keeps the last refresh's per-device answer and serves it on `GET /status` as
    `sessions`. When the warning is due, `port49 ssh` asks first. A refresh that extended this
    device's session, and reached it, moves the warning to the new moment, so the line never
    names a ceiling that has moved.
  - **Where it matters.** EOS, NX-OS and Junos show port49's `server_msg` warning nowhere (§15
    L34), so there this line is the warning.
  - Task 6.
- **12. The lab.** L53 (host keys per platform) and L54 (`port49 ssh` per platform), both closed
  2026-10-09 on all five platforms (§15). Task 8.
- **13. Hardware-backed client keys, for plan 9c** (pre-flight Q2), all without cgo.
  - **PKCS#11 through `github.com/ebitengine/purego`.** It covers YubiKey PIV, smartcards and HSMs.
    The module is `dlopen`ed at run time with `CGO_ENABLED=0`, and CI tests it against SoftHSM2.
  - **TPM 2.0 through `github.com/google/go-tpm`.** It is pure Go. CI tests it against `swtpm` over
    the MS-simulator protocol, never `go-tpm-tools`' simulator, which is cgo.
  - **The macOS Secure Enclave through purego**, behind a spike task on a macOS host.
  - **What was checked (2026-10-09, from the module cache):**
    - cgo: `go-piv/piv-go/v2` v2.6.0 on Linux and macOS, `miekg/pkcs11` v1.1.2, `crypto11`
      v1.6.8 and `google/go-pkcs11` v0.3.0;
    - pure Go: `go-tpm` v0.9.8;
    - no cgo on Tier 1: `purego` v0.11.1, "beta software" by its README.
  - **Unverified, and 9c's first task measures it:** whether a module that starts threads
    (`libykcs11`) behaves under purego.
  - **What goes back to Ryan.** If the spike shows a persistent Secure Enclave key needs an
    entitlement an unsigned `port49` cannot have, macOS is served through PKCS#11, a YubiKey. The
    Secure Enclave is dropped only then, and only by Ryan, as is any other route the spike or 9c's
    measurement rules out.
- **14. Inventory-carried host keys and the Python and Ansible clients, for plan 9d** (pre-flight
  Q5).
  - **What moves to 9d:** both. Inventory's host-key fingerprint (design §17's MAY) goes through the
    bundle into the mint item, and `port49 ssh` checks it beside its pins.
  - **Why after L53:** its format follows what L53 shows devices present.
  - **Why the clients go with it:** third-party clients (Ansible's `network_cli`, Netmiko over
    paramiko) look a host key up by address. They can verify one only once the mint says which key
    to expect.
  - **Until then:** 9a's Netmiko example verifies against port49's own pins, written under the
    address for the one connection (Task 7).

**43. The agent in full, second part: port49-issued user certificates over an OIDC sign-in.**
*Plan 9b, 2026-10-10, on Ryan's direction of that day: design §7's "the broker MAY issue a
short-lived client certificate", made v1.* Rulings rest on reasoning unless they say data. Rulings
4 and 8 are measured on Keycloak (L55 closed) and provisional on L47 (hosted providers, open). Q1–Q3 (rulings 13, 9 and
12) were ruled as recommended on 2026-10-10 by the controller under Ryan's standing grant: a
person's bearer outside `/v1/certificate` retires at the pre-beta review, not now; the lifetime is
broker config, 12h, 1h–24h, per role later if asked; a new agent reuses the held key and
certificate while the certificate is valid.

- **1. The flow** (data: RFC 6749 §4.1, RFC 7636, RFC 8252, OIDC Core §3.1).
  - **What it is.** The authorization-code flow with PKCE, `S256` only, as a public client with no
    client secret.
  - **Where it runs.** `port49 login` runs it in its own process, never in the agent, which never
    listens on a TCP port and never holds an ID token.
  - **The provider's PKCE.** A provider whose discovery lists `code_challenge_methods_supported`
    without `S256` is refused. One that lists none is used, with `S256` sent. Keycloak (L55, closed)
    lists `plain` and `S256`, and for port49-cli set to require `S256` it refused a wrong verifier
    and no verifier (`400 invalid_grant`) and `code_challenge_method=plain`; what it does for a
    client set to require no method is not measured.
- **2. The provider** (data: OIDC Discovery §4).
  - **Which one.** The one `/v1/config`'s `oidc` lists, or the one `--issuer` or `oidc_issuer`
    names exactly. None listed is "this broker takes no OIDC login". Several and none named is a
    refusal that lists them.
  - **Its discovery document.** `issuer` must equal the configured issuer. `authorization_endpoint`
    and `token_endpoint` must be `https` URLs with a host and no credentials. Each member is read
    by its exact name.
  - **Reaching it.** No redirect is followed. `HTTPS_PROXY` is honoured, as the broker's key fetch
    honours it (decision 39 ruling 4). TLS is against `oidc_ca`, else the system's roots. The
    broker is never reached through a proxy.
- **3. The request.** It carries:
  - `response_type=code`, `client_id`, and `redirect_uri`;
  - `scope`: the verifier's scopes, `openid` first;
  - `state`: 32 random bytes;
  - `nonce`: the key binding, `base64url(SHA-256("port49 issue v1\0" ‖ PKIX(the new key)))`
    (`api.IssuanceNonce`), so the ID token names the one key it may be exchanged for;
  - `code_challenge`: S256 of a 32-byte verifier;
  - `prompt=login`: a sign-in is a fresh authentication.
- **4. The redirect** (data: RFC 8252 §7.3, RFC 9207; measured on Keycloak, L55 closed).
  - **The listener.** `http://127.0.0.1:<port>/callback`, on a listener bound to `127.0.0.1`
    alone. The port is ephemeral, or `oidc_redirect_port` for a provider that registers one. It
    answers `GET /callback` and nothing else.
  - **Keycloak's registration** (L55, closed). An ephemeral loopback port is admitted only for a
    redirect registered as `http://127.0.0.1/callback` or `http://127.0.0.1/*`. A fixed
    `http://127.0.0.1:<port>/callback` admits that port alone, and `http://127.0.0.1:*/callback`
    admits none. The client's ephemeral default stands (RFC 8252); a provider registered with a
    fixed port needs `oidc_redirect_port`.
  - **Another `state`.** An answer that does not carry this sign-in's `state` is answered 400 and
    waited past: anyone on the host can reach the port.
  - **This sign-in's answer.** The first answer carrying the `state` ends the wait. Its `iss`, when
    present, must be the issuer, and is required when discovery says the provider sends it. An
    `error` ends the sign-in with the provider's code.
  - **The page.** It holds no token, with `Cache-Control: no-store` and `Referrer-Policy:
    no-referrer`.
  - **The wait.** 5 minutes.
- **5. No browser.**
  - **When one is launched.** `$BROWSER` when set. On Linux, `xdg-open` only with `DISPLAY` or
    `WAYLAND_DISPLAY` set. On macOS, `open` outside an SSH session. `--no-browser` launches none.
    The authorization URL is always printed on stderr.
  - **The paste.** When stdin is a terminal, the address the browser ended on may be pasted back,
    and is not echoed.
  - **No way back.** With no browser opened, no terminal, and an ephemeral port, that is said at
    once, naming `ssh -t`, or a fixed port forwarded with `ssh -L`. With a fixed port the sign-in
    waits, and says how to forward it.
  - **No device grant.** The device authorization grant (RFC 8628) is not built: the paste covers
    the browser-less host with every property of the loopback flow; its user code is a phishing
    route (RFC 8628 §5.4); and a provider must enable it per client.
- **6. The exchange and the ID token, as the client reads it** (data: OIDC Core §3.1.3.7).
  - **The exchange.** The token endpoint, form-encoded, with `code_verifier` and no secret. A
    refresh token in the answer is dropped unread.
  - **What the client reads:** a compact JWS whose `alg` decision 39 ruling 3 accepts; `iss` exact;
    `aud` naming `client_id` and `azp` as decision 39 ruling 2 reads it; `nonce` equal to the
    request's; `sub`, `iat`, `exp` and `auth_time` present, `iat` no later than `exp`; every claim
    by its exact name.
  - **No signature check here, and no clock.** It came from the token endpoint over TLS (item 6),
    and the broker verifies it. A skew over 5 minutes between `iat` and this host's clock is
    warned, never refused.
- **7. The key.** `port49 login` generates an ECDSA P-256 key for each sign-in. Plan 9b keeps it
  in a file, `~/.port49/issued/<broker host>_<port>.key`, written 0600 through
  `userconfig.WritePrivate`, beside the certificate (`.pem`). Plan 9c generates it in a TPM, the
  Secure Enclave or a token behind the same `crypto.Signer`. It never leaves the host; the broker
  sees its public key, in a CSR whose signature proves it.
- **8. The exchange for a certificate:** `POST /v1/certificate`, the ID token as the bearer, `{csr}`
  base64url DER as the body, no client certificate. The broker refuses, recording each refusal as an
  `issue` deny:
  - a token any of decision 39 rulings 2–6 refuses, a marked principal, or a logged-out session,
    as a mint is refused;
  - a machine's token (400);
  - a sign-in that is not fresh, `401 sign_in_not_fresh`, `trust_domain_unresolved`, judged on two
    clocks: an `auth_time` more than 5 minutes (plus `clock_skew`) before the token's `iat`, the
    provider's own clock, which catches a provider that ignored `prompt=login` (measured on
    Keycloak, L55 closed: `auth_time` +0s from the sign-in, and +15s over a live SSO session); an
    `iat` more than that before the broker's now, a slow sign-in or two clocks apart, said as
    such; or an `auth_time` after the `iat` plus `clock_skew`. 5 minutes is the sign-in's own
    wait;
  - a CSR that does not parse, whose signature is not its key's, or whose key is not ECDSA
    P-256/P-384, Ed25519 or RSA 2048–8192 (400);
  - a `nonce` that is not `api.IssuanceNonce` of the CSR's key: `401 sign_in_not_bound` (measured
    on Keycloak, L55 closed: the provider echoed the 43-character nonce byte for byte);
  - a token exchanged already (the store keeps its SHA-256 for `max_token_age`): `401
    sign_in_spent`;
  - a sign-in that cannot be carried in a certificate (its principal or claims fail the issuer's
    rules). The human verifier's own checks keep every person's claim within them, so today the
    branch is reached only by an operator-configured issuer URL the certificate cannot carry (a
    space or a non-ASCII character in its path); the broker refuses such an issuer at config load
    once issuance is configured (plan 9b, Task 8): `401 sign_in_not_certifiable`,
    `trust_domain_unresolved`, "your sign-in's principal or claims cannot be carried in a
    certificate; tell the operator".

  Every refusal above comes before the sign-in is spent, so a refused sign-in is exchangeable
  after the cause is cured. Before the spend the broker also checks that it can issue now (the CA
  within its validity, the lifetime in range): if not, `503 issuance_unavailable`, unrecorded, and
  the token stays unspent so a retry may use it.

  Then it writes the owner record (decision 39 ruling 11), issues, and records an `issue` permit
  `certificate_issued` with the certificate's serial, issuer, fingerprint and end. A broker whose
  CA cannot issue answers `503 issuance_unavailable`, Retry-After 60, with no record: the fault is
  the broker's, and its start and its process log say which. A broker with no `issuance` answers
  `404 not_issuing`.
- **9. The certificate** (Q2).
  - Signed by the broker's issuing CA; serial 128 random bits; valid from a minute before issue for
    `broker.identity.issuance.certificate_lifetime` (default 12h, 1h–24h), never past the CA's end.
  - Subject CN the principal the human verifier gave; one URI SAN,
    `port49-sign-in:v1?iss=…&sub=…&sid=…&auth_time=…&iat=…&amr=…&acr=…`, carrying the sign-in, so
    the `sid` is bound to the serial under the CA's signature (R1); `clientAuth`; no email or DNS
    SAN.
  - A per-role lifetime is not built: no policy value varies by role yet, and plan 9c's
    `per_login_mfa` is where per-device strength arrives.
- **10. The broker trusts its own certificates, for people alone.**
  - Its issuing CAs (current, next, previous) join the handshake's pool. A chain ending at one of
    them is the `humans` domain; one ending there and at another anchor is refused.
  - The principal is the certificate's CN, never mapped through the directory (membership is still
    read at mint, as for an OIDC principal). The sign-in must still name an issuer whose human
    verifier's `principal_domains` hold the principal, or it is refused `trust_domain_unresolved`:
    a provider removed from the configuration takes its people's certificates with it.
  - `certificate_status` is not asked: the broker's marks are such a certificate's status.
  - The credential is `{method: cert, fingerprint, issuer, serial, subject, iss, sub, sid, amr,
    acr}`: a mint indexes its contexts under the certificate and the `sid`, and its records carry
    `auth.oidc`.
- **11. `auth_time`, `session_expires`, and the fresh authentication event** (decision 17;
  dissolves plan 9b's pre-flight D1).
  - The session is the held connection, as on every certificate path: `auth_time` is when the
    broker accepted the handshake, or verified a refresh's signature, and `session_expires =
    auth_time + max_session_age` (§5.6).
  - The provider's `auth_time` bounds issuance alone (ruling 8), and is recorded as
    `auth.oidc.auth_time` on every record the certificate makes.
  - A key signature on a port49-issued certificate is a fresh authentication event exactly as one
    on any certificate is, while the certificate is valid. Against today's file-key certificate
    path it is the same proof, possession of a key in a 0600 file, with a key at most
    `certificate_lifetime` old, generated at a sign-in that was itself a fresh authentication. Plan
    9c's hardware key adds presence, and its `per_login_mfa` adds a proof per login to the devices
    a policy level marks.
  - `notAfter` bounds the mint and the refresh, never a device session (§5.1.4). So one sign-in
    gives at most `certificate_lifetime` of mints and refreshes, and the device sessions a last
    refresh extended run to their own ceilings.
  - So a new agent refreshes once at login, as on the certificate path, and `port49 refresh` is a
    key signature with no browser.
- **12. `port49 login` on the OIDC path** (Q3).
  - **A held certificate** for this broker, valid, readable through `keyfile`, carrying a sign-in,
    and with more than a quarter of its life left (`api.LateRenewal`), is used with no sign-in and
    said. `--sign-in` forces a sign-in.
  - **Otherwise** it signs in, generates a key, asks `/v1/certificate`, writes the key and then the
    certificate, and prints whom it signed in as and the certificate's end.
  - **The provider unreachable:** a held certificate still valid, late or not, is used, saying so.
    With none, the login says the provider did not answer and that people already logged in are
    unaffected, and exits 1.
  - **An agent running** for this broker with the held certificate is refreshed (a key signature).
    One with another certificate or another broker exits 1 naming it, as today. `--sign-in` with an
    agent running exits 1: stop the agent first.
  - **A held certificate refused:** when the new agent's first refresh is answered
    `credential_revoked`, the login removes the key and certificate, says the broker's words, and
    exits 1; the next login signs in. When the agent cannot connect with a held certificate, the
    login says to run `port49 login --sign-in`.
- **13. One path for people** (Q1). A broker with `issuance` takes a person's ID token at `POST
  /v1/certificate` alone, and refuses it on every other endpoint, `401 trust_domain_unresolved`,
  recorded. A machine's token is unaffected. A broker with a human `oidc` verifier and no
  `issuance` keeps plan 7h's bearer path (decision 39 rulings 8 and 15) as built, which no port49
  client drives after plan 9b; retiring it is carried to the pre-beta review.
- **14. The issuing CA.**
  - **Custody.** `issuing-ca.pem` and `issuing-ca.key` (PKCS #8, 0600, `keyfile`'s owner-only rule)
    in the broker's state directory (`broker.state_dir`, or the directory of
    `broker.revocations_file`). The broker signs through a `crypto.Signer`, so a KMS or an HSM is
    a later swap of its source.
  - **Made once.** `port49d init-issuer` or `port49-broker init-issuer`, as the broker's user: a
    P-256 key and a self-signed CA certificate valid 5 years. On every further broker on one
    store, the operator copies both files. Each start prints the CA's fingerprint; a cross-replica
    check is carried to plan 12.
  - **Rotation with overlap** (R5). `rotate-issuer`, on one broker, stages `issuing-ca-next.pem`
    and `.key`. Only the certificate is copied to the other brokers, which trust it from their next
    start; the key stays on the broker that staged it until the promotion. Run again there, it
    promotes: the current certificate becomes `issuing-ca-previous.pem`, its key is overwritten,
    and the next becomes current; the operator copies the three files to the other brokers. A
    broker trusts every one of the three present and signs with the current. The previous is
    removed by hand after `certificate_lifetime`; trusting it longer admits nothing, since its key
    is gone.
  - **The promotion's guards** (pre-flight 2 m4). It is idempotent, so an interrupted one is
    finished by running it again. It is refused while an earlier rotation's
    `issuing-ca-previous.pem` is still there, whose certificates may still be valid, and on a
    broker that holds the staged certificate without its key. A staged file that is already the
    current CA, left by a finished promotion or copied from the promoting broker, is removed, and
    nothing is promoted or said to be.
  - **At 3am** (R4). A start never fails over these files. A missing or unusable key stops
    issuance alone: `503 issuance_unavailable`, and the certificates already issued are trusted. A
    missing or unusable CA certificate also stops their trust. Each is said at start, naming the
    file and `init-issuer`. `port49_issuing_ca_not_after_timestamp_seconds` is the CA's end, 0
    when none is loaded.
- **15. Revocation.** By principal (every certificate the person holds, issued or not) or by
  certificate (`--cert-issuer` the CA's DN, `--cert-serial` from the `issue` record), as decision
  32 built it. The short lifetime is the main control. No CRL is published: no device sees the
  certificate, and the broker trusts its own CA.
- **16. Back-channel logout** (decision 39 ruling 13). The certificate carries its sign-in's `sid`
  and `sub`; the owner record is written at issuance and at each mint. A logout by `sid`, or by
  `sub` for a sign-in whose `iat` is at or before the logout plus `clock_skew`, refuses the
  certificate's next request and refresh `credential_revoked` in the broker's logout words, and a
  refresh's own reading after its writes marks what it extended. The `sid` index reaches its device
  sessions. A logout leaves no mark: a sign-in after it is taken. The certificate carries no mark of
  its own, so the logout record is what refuses it: on a broker that issues, a logout record stands
  `max(max_token_age, 24h) + 2×clock_skew` (24h is the longest `certificate_lifetime` allowed, so a
  lifetime lowered since leaves no certificate unreached), not decision 39's `max_token_age +
  2×clock_skew`, and the recovery's lift time follows it. Every broker on one store configures
  `issuance` alike: one without it keeps the shorter record. A recovery for a logout the store
  could not write names the shorter path: revoke by serial every certificate issued to the principal
  before the logout, by every broker on the store (each broker's `issue` records; a logout by `sid`
  or by `sub` can cover several sign-ins), and lift the principal's mark after `max_token_age`;
  waiting out the full lift time stays the default.
- **17. The provider down at 3am.** People holding a certificate keep working until it ends: mints,
  refreshes, and new agents (ruling 12). Only a sign-in fails, and says so.
- **18. `/v1/config`.** A broker with `issuance` adds `issuance: {certificate_lifetime_seconds,
  available}`. `available` (bool) is false when the broker's issuing CA is unusable (ruling 8's
  `503 issuance_unavailable`): the client then says "the broker cannot issue certificates now (its
  issuing CA is unavailable); tell its operator" before any sign-in, so nobody types a password and
  approves MFA for a certain 503, and falls back to a valid held certificate as ruling 17 says. A
  config without the field (an older broker) means available.
  Decision 39 ruling 16's `oidc` list is unchanged. A broker with `tls_ca_bundle_file` adds
  `broker_ca_bundle` (ruling 25).
- **19. The config file and the flags** (amends decision 42 ruling 6).
  - **The file.** `config.yaml` gains `method` (`x509`, the default, or `oidc`), `oidc_issuer`,
    `oidc_ca` (held to ruling 6's ownership rule as `broker_ca` is, and read once) and
    `oidc_redirect_port`.
  - **The flags.** `port49 login` takes `--oidc`, `--issuer`, `--oidc-ca`, `--redirect-port`,
    `--no-browser` and `--sign-in`. `--cert` or `--key` beside `--oidc` is a usage error, and so
    are the OIDC flags without it. `broker_ca` stays required: it is the broker's TLS, on either
    path.
- **20. What is never logged or printed:** the ID token, the code, the verifier, the key, and a
  token response's body. The authorization URL is printed on the operator's terminal and handed to
  the browser: it carries `state`, the `nonce` (a public key's hash) and the `code_challenge`. It is
  not a credential, but its `state` must not leave this user, since whoever holds it can complete
  this sign-in with their own account (a login CSRF; RFC 6749 §10.12). So the login prints the
  principal it was issued for.
- **21. The agent.** Unchanged but in two points. Its process exits at the certificate's end when
  that comes before `max_session_age`, saying so; a request past it meets the broker's refusal of
  an expired certificate, as on every certificate path. It makes itself non-dumpable on Linux and
  denies a debugger on macOS, so no core file or crash report holds the key; one that cannot runs
  on and says so, since the key is a file this user reads already.
- **22. The record and the metrics.** The `issue` event (§5.7): a permit `certificate_issued`
  carries `certificate: {serial, issuer, fingerprint, not_after}` and `auth.oidc`; a deny carries
  the refusal's reason. `port49_certificates_issued_total{outcome}` (`issued`, `refused`,
  `unavailable`) and `port49_issuing_ca_not_after_timestamp_seconds`; no principal and no device.
- **23. The lab.** L55: Keycloak as this client meets it. L56: issued certificates end to end on
  Keycloak and vEOS. L47 (hosted providers) stays open. L55 and L56 closed 2026-10-11 (Keycloak 26.4.7;
  vEOS 4.31.2F).
- **24. The client's config, with no step per user** (Ryan, 2026-10-10, and the toil audit's H4;
  amends decision 42 ruling 6).
  - **The rule** (Ryan's, standing). A step too hard for a user or an operator to do at scale is
    not in the design, and what can be automated away from the user is. The cases weighed: 1,000
    devices, 50 operators, a new hire, a laptop rebuilt, and each CA rotated.
  - **Where.** `~/.port49/`, as `~/.ssh/` is, made 0700 when it is missing. It holds `config.yaml`
    and `issued/`, and no host-key pins: those stay in plan 9a's
    `$XDG_CONFIG_HOME/port49/known_hosts` until plan 9d takes them out of the user's flow.
    `$PORT49_CONFIG`, and over it `--config FILE`, name another personal file, which must exist.
  - **The system file.** `/etc/port49/config.yaml`, shipped by the install (a package, config
    management or MDM), takes the same keys, under the personal file key by key. A key the personal
    file sets wins, and a flag wins over both. The system file must be root's, and neither its group
    nor others may write it; the walk above it is ruling 6's. It holds what the install knows:
    `broker`, `broker_ca` (the CA beside it, as `/etc/port49/broker-ca.pem`), `method: oidc`, and
    where needed `oidc_issuer` and `oidc_ca`. The client id, the scopes and the certificate's
    lifetime come from the broker's `/v1/config` at each sign-in (decision 39 ruling 16; ruling 18),
    so no file holds a copy that can drift.
  - **A new user's first login** is `port49 login` and the sign-in at the provider. Nothing is per
    user: no file to write, no CA to fetch, no directory to make or `chmod`. Under plan 9a it was a
    config file of four keys, a CA file fetched, and on Ubuntu `chmod go-w ~/.config`, per user and
    per host; the OIDC path would have added up to four more keys.
  - **Each CA rotated, with no step by a user.** The issuing CA (ruling 14) is the broker's alone;
    no client holds it. The broker's TLS CA rotates through the bundle each agent keeps (ruling 25),
    and the install's config management ships the old and the new CA in `broker_ca`, one file per
    host, at the rotation's start, and the new alone at its end. A host config management reaches
    needs nothing of its user; the by-hand fix is for an unmanaged host alone.
  - **An expired or late certificate** is replaced by the next `port49 login`, which signs in and
    writes over the key and the certificate (ruling 12); a refused one is removed. No file is moved
    or deleted by hand.
  - **Plan 9a's file.** A `config.yaml` at `$XDG_CONFIG_HOME/port49/` (else `~/.config/port49/`),
    with none at `~/.port49/`, is refused in one line naming the move; it is never read, and never
    silently passed over.
  - **What a refusal says.** It names the exact path and the owner or mode it needs. It never
    suggests a `chmod` on a directory, which may be shared, as a group-writable `~/.config` is.
- **25. The broker's TLS CA rotates with no step by a user** (Ryan, 2026-10-10; completes ruling
  24).
  - **The bundle.** `broker.tls_ca_bundle_file` names the CAs clients are to trust for the
    broker's server certificate: the CA in use and, through a rotation, the next. The broker reads
    it at start and sends it on `GET /v1/config` as `broker_ca_bundle` (PEM). A bundle that cannot
    be read, holds anything but 1 to 4 CA certificates in at most 64 KiB, or does not verify the
    server certificate in use is not sent, said in one line, and the start goes on (R4's rule).
  - **The client.** The agent fetches `/v1/config` on the connection it has just verified, at every
    start, and keeps the bundle 0600 in `~/.port49/broker_ca/<host>_<port>.pem`, one per broker so
    no broker's bundle is trusted for another. A login trusts its `broker_ca` and the kept bundle
    together, and hands both to the agent it starts.
  - **Refused, and the file left as it was:** a bundle out of those bounds, or one that does not
    hold the CA this connection was verified to. A change is logged by fingerprint, old and new.
    A kept file that cannot be used is refused at login, naming it.
  - **A broker that sends no bundle clears it.** On a verified `/v1/config` with no
    `broker_ca_bundle`, a kept file that does not hold the CA this connection was verified to is
    removed, and one that does is cut to that CA alone, each said in one line. So the next login
    still verifies the broker, and any other CA the file held is gone.
  - **A broker that refused its own bundle is not one that sends none.** When
    `tls_ca_bundle_file` is configured and refused at start (unreadable, out of bounds, or without
    the server certificate's CA), `/v1/config` carries `broker_ca_bundle_refused: true`, and each
    agent leaves its kept file as it was, saying so in one line. So a typo in the bundle
    mid-rotation drops no CA a client holds, as the broker's own start line says.
  - **A rotation.** The operator adds the next CA to the bundle, and the install's config
    management adds it to every host's `broker_ca` at once (ruling 24); restarts the brokers; waits
    while people log in (every agent that starts keeps the new bundle: a day covers everyone who
    works daily, longer covers people away); then switches the server certificate to one the next
    CA issued; and later drops the old CA from the bundle and from `broker_ca`. No user does
    anything.
  - **A host away through the whole overlap** that config management reaches has the new
    `broker_ca` on its return. An unmanaged one meets a certificate no CA it trusts issued, and the
    refusal says on the same line: get the broker's CA from its operator and run `port49 login
    --broker-ca FILE` once; port49 keeps it current from then on. That is the last resort, not the
    rotation's path.
  - **What it does not do.** The bundle only adds trust beside `broker_ca`; it never removes the
    configured CA, which config management updates. So a rotation because the old CA is
    compromised also pushes the new `broker_ca` to every host at once: until then the old CA stays
    trusted there.
  - **What it costs** (pre-flight 2 I1). It carries trust only for the broker that sent it, over a
    connection verified to a CA the host already trusts, so a plain MITM pins nothing. But whoever
    holds the broker's server key, even briefly, can send a bundle that adds a CA of their own, and
    each agent that starts meanwhile trusts it for that broker. That outlives the compromise on a
    host that does not reconnect to the real broker, since a bundle is replaced only by a later
    one. The remedy is the real broker's next answer, a bundle or none, which every agent applies
    at its next start.

**44. Junos: a per-user `junoscript` deny, and check-config reads configuration groups.**
*Plan 9b1, 2026-10-11, on Ryan's rulings of that day.* Rulings rest on reasoning unless they say
data. Rulings 1, 2 and 6 are *provisional on L26c* until plan 9b1's Task 9 closes it; ruling 7 is
provisional on L57.

- **1. The entry deny** (data: `tests/lab/results/L26c-junoscript-juniper_*.md`). Take a
  composition whose only guard beneath a sent bit or the baseline is a wire deny. Under a set
  whose adapter carries `rpc_entry_denies`, it is projected in the capability shape with those
  denies added to its `deny-commands`, role `rpc_entry`. This replaces option C's narrow-or-closed
  answer for that set. Set 1.2.0's `juniper_junos` carries `["junoscript **", "op **"]`
  (ruling 2).
- **2. `op`.** Measured 2026-10-11 (`tests/lab/results/L26c-scripts-juniper_*.md`, cell b): under
  the `junoscript` deny an `op url` script's `jcs:invoke` reached `get-software-information` and
  `get-configuration` on vJunos-router and vSRX, as the control's did; set 1.2.0's list is
  `["junoscript **", "op **"]`. Denying `op` to a subject port49
  permits it is narrower, which is reported, not refused.
- **3. Who keeps NETCONF.** A subject whose reply carries no deny beneath a sent bit or the
  baseline. An allow the reply must send that meets an entry deny would beat it (L11), so that
  composition keeps the narrow or fail-closed answer. `junoscript` joins `xml-mode` and `op` as
  an entry a narrow allow may not open.
- **4. Two warnings** (Ryan's ruling). `projection_netconf_closed` and
  `projection_deny_beneath_view_configuration` (§12). Neither fails `policy test` or `policy diff`.
  `policy diff` prints the ones a change brings, since every unchanged warning on every diff is
  noise.
- **5. The key is adapter data** (§8, "the platform set is pinned"). `rpc_entry_denies` is read
  only on a projected platform. A block keeps the whole list or drops it with `[]`, and that
  platform then renders as set 1.1.0 does: ruling 10's render changes hang on the key too. A
  partial list is refused at load, because it leaves an entry open (L26c-scripts: `op url`
  reaches past the `junoscript` deny). It may never add one the set did not measure, as with
  `carve_outs`. `DefaultSet` is 1.2.0. A policy pinned to 1.1.0 renders
  byte for byte as before.
- **6. Services** (Ryan's ruling, narrowed for security; data L26c; an allowlist, plan 9b1
  controller ruling of 2026-10-12). Under set 1.2.0 check-config no longer requires NETCONF off.
  `netconf`, `ssh` and `telnet` pass under `system services` with any statement beneath them, and
  so do the services §8 names as serving no management session. Any other statement under `system
  services` fails, the finding quoting it, a service no one listed included: `service-deployment`
  speaks the JUNOScript XML API, and a denylist passed it. Anywhere in the hierarchy it still fails
  `web-management` and `extension-service`, and `rest`, the XML API (`xnm-ssh`, `xnm-ssl`,
  `xnm-clear-text`) and `outbound-ssh`, each until a lab cell measures the `junoscript` deny
  closing it (*provisional on L26c*). REST was not measured: the lab's tunnel did not reach it,
  the control included (`L26c-scripts-juniper_*.md`, 2026-10-11), so `rest` stays a finding.
  Whether a `show configuration` deny holds against a file read of `/config` through `ftp` or
  `ssh sftp-server` is unmeasured (*provisional on L26c*). Set 1.1.0's allowlist is unchanged.
- **7. Groups** (Ryan's rulings; data: `tests/lab/results/L57-juniper_*.md`, measured
  2026-10-11 on vJunos-router and vSRX). check-config reads `show configuration | display set |
  display inheritance` (the other pipe order expands the same) and judges the expanded lines under
  a template as template lines: a privilege or unlisted statement fails and a harmless one passes,
  whether a group or the template wrote it, so a group widening a template is caught. The
  inherited set form prints no `set groups` and no top-level `set apply-groups` lines, so
  check-config cannot name the group: a failing line says it may come from a configuration group
  and gives the pointer `show configuration system login | display inheritance`, whose curly form
  names the group per line. A capture is refused as not inherited if any line has `apply-groups`
  as a word at any level (`set apply-groups …`, `set system apply-groups …`, `set system login
  class X apply-groups …`) or any `set groups` line; `apply-groups-except` survives inheritance
  and is not a sign. That inheritance strips a class-level `apply-groups` is *provisional on
  L57*. Junos honours `apply-groups-except`, commits a group applied from inside another group's
  definition but does not expand it in the inherited capture (*provisional on L57*: a session
  cell shows whether the nested group applies, which check-config could not see), and adds a
  group's `permissions` beside a class's own. Neither `apply-groups` nor
  `apply-groups-except` is itself a finding. This replaces the ruling's first reading (name the
  group from its definition, `<pattern>` words matched, at its own line where the template writes
  the same statement), which assumed the inherited capture keeps the group definitions; L57 shows
  it keeps none.
- **8. Batch.** `--batch FILE...`, the device named by the file name where the inventory has it,
  else by the name less its last extension. Every file is checked. Exit 2 if any file's outcome
  was a usage or "nothing checked" one, else 1 if any had a finding or could not be read.
- **9. Unlisted statements fail.** Under a template, a statement on neither the privilege list
  nor the harmless list (§12) fails, from a group or written there. `allow-hidden-commands`,
  `login-script`, `logical-system`, `tenant` and `security-role` change what a session runs, and
  an allowlist does not fail open on a statement nobody listed (plan 5b pre-flight C1).
- **10. A readonly with a deny beneath `show **`** (Ryan's ruling of 2026-10-11, on plan 9b1's
  pre-flight; data: `L26c-junoscript-juniper_*.md`, `L26b-juniper_*.md`, `L58-juniper_*.md`).
  Without this ruling such a readonly fails closed under 1.2.0 as under 1.1.0: its baseline
  denies name `save` and `xml-mode`, which no proven keyword names, they render 333 bytes alone,
  and view-configuration's carve-outs take `show **` out of `view`'s reach, so `show **` would go
  out as an allow that beats the deny. Where the adapter carries `rpc_entry_denies`, and only
  there: the baseline's `xml-mode **` is sent as nothing beside `junoscript **`, which refuses it
  (Junos authorizes `xml-mode` as `junoscript`; the model reads it refused); set 1.2.0's tree
  proves `save`; `word **` denies render as one alternative; a permit the bits reach but for a
  carve-out of an unsent ceiling bit, whose allow would beat a deny beneath it, goes out as allows
  of those carve-outs, each within the ceiling and meeting no deny, reported as sent beyond the
  bits; and a capability reply sending an allow its bits do not reach yields to a narrow one
  that reaches every allow and leaves off no more. view-configuration is not sent to such a
  readonly, whose grant decides none of its other reach; ruling 4's warning stays an operator's
  and an admin's.

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
  §8), on a retransmission's checks: PASS once the winner's join has committed and the
  context witnesses it, `token_spent` while that join is in flight, and FAIL
  `receipt_replayed` once the winner's refusal has marked it failed (§5.6; plan 7d closes
  pre-flight F16's PASS).
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
  With `broker.directory`, a certificate mapping to zero entries is `identity_unmapped`, to two
  `identity_ambiguous`; a derived username a declared subject holds, or a second entry holds, is
  `username_collision`; a mapped value carrying filter metacharacters matches only its literal
  entry.
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

- **One record per evaluation**, at each of the ten decision events, permits included — a corpus
  exercising the matcher produces exactly as many records as decisions. The two `refresh`
  carve-outs (§5.7) hold: a refresh that finds a context already on the answer the policy in
  force gives writes no record, and nor does a pass a store error stops, for the context it
  stopped at. Every revocation a refresh makes has its record.
- **Replay agreement**: every record in the corpus replays against its named blob and
  reproduces the logged verdict and reason. A `revoke` record names no blob, and one by
  principal or certificate is checked against the marks it reports instead; `identity`,
  `explain`, and `self` or `key` revocations are passed over.
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
  invalidate the matching contexts and no other principal's (a `sub` logout ends every context of its principal, decision 15), and the next command on each is denied.
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
  its local method in the lab, and the named fix admits it: port49d takes the fix from its own
  `broker.policy_file` (decision 29), and the service's next sync reports the device clear.
  Passed through the inventory service's syncs on vEOS, the N9Kv, the C8000V and vJunos-router on
  2026-09-30 (plan 6b Task 19, `tests/lab/results/quarantine-sync-*.md`).
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
- **The entry deny** (decision 44): under set 1.2.0 an operator granted `**` less `show
  configuration **` renders the capability shape with `junoscript` in `deny-commands`; the device
  refuses `show configuration`, `xml-mode netconf` and that user's NETCONF on port 830, while a
  subject with no deny beneath its bits opens NETCONF; under set 1.1.0 the same policy fails
  closed as before. Under set 1.2.0 a readonly granted `show **` less `show configuration **`
  renders `view`, its denies with `junoscript` in 170 bytes, and allows of `show log`, `show
  firewall` and `show policer`; the device refuses `show configuration`, `xml-mode` and
  `xml-mode netconf`. A readonly granted `show **` alone renders as under 1.1.0 (ruling 10).
- **check-config reads groups** (decision 44): a group adding `permissions` to `p49-remote` fails
  at its expanded line, the finding pointing at `show configuration system login | display
  inheritance`; a group adding `login-tip` passes; a capture with `apply-groups` as a word on any
  line (top, `system`, or a class) or a `set groups` line is refused as not inherited, and one
  carrying only `apply-groups-except` is not; `--batch` checks every file.
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

- **Snapshot refresh**: atomic swap; an open connection whose device the new snapshot refuses,
  removes, renames, re-keys or re-platforms is reset at its next packet with no reply and no strike,
  and one whose device it leaves as it was is untouched; a malformed, empty, or over-shrinking
  snapshot is rejected and the previous one retained.
- **Snapshot never expires**: a daemon with a stale snapshot and an unreachable inventory
  service continues authenticating, alarming on age.
- **Cold start**: a daemon with no snapshot keeps its TACACS+ listener closed and `/readyz` at
  503, and retries, while existing replicas keep serving; a daemon restarted with the inventory
  service down starts from its persisted bundle, one scheduled onto a fresh node starts from the
  shared mirror's copy, and with both it starts from the one published later (`published_at`,
  which survives a sequence reset).
- **The document is verified everywhere**: a document the service did not sign — from the API,
  the persisted copy or the mirror — is refused and the bundle in force keeps serving; one carrying
  a key group, a `key_ref` pin, or a name with a control character is refused; a signing key
  added to `verify_key_files` takes effect at `SIGHUP`.
- **Policy mismatch**: a document built against another policy is applied against the policy in
  force, said, and alarmed, and changes no grant.
- **The service bounds each source**: a source that removes or newly refuses more than its bound
  of the devices it gave last time refuses the sync, and the last published bundle keeps being
  served; each daemon bounds the document again.
- **Both sources at once**: a whole-fleet re-address, where each source alone admits no device,
  loads at `SIGHUP` as one swap, and no live context on a device the final bundle admits is revoked.
- **API rights**: a reader cannot trigger a sync, a certificate the anchor does not verify gets no
  answer, and one with two URI SANs is refused.
- **A pin in the policy**: a key group matching a device's name assigns its key at tier 1, over an
  attribute group and over every address's CIDR group; two name groups for one device refuse the
  policy.
- **One rule for a usable device**: whatever the service publishes, port49d opens.
- **Connectors read what was measured**: the profile is chosen from `/api/status/`, and a major no
  lab run measured is refused unless a profile is named; GraphQL `errors` fail a fetch even on HTTP
  200; a GraphQL list whose length is not REST's `count` both before and after, a REST page whose
  `count` moved, or a list naming a device twice fails the sync and de-admits nothing; a sync that
  leaves more than the bound's share of a source's devices with no address is refused, by the
  service and by port49d; `next` is
  followed only on the source's `url` and otherwise rebuilt there, and no redirect is followed, so
  the token reaches no other host; a filter, a map path and an address rule each take the
  product's recorded spelling; the token appears in no line and no error.
- **A webhook only triggers**: an unsigned, mis-signed, stale (more than 5 minutes either way),
  oversized, non-JSON or repeated delivery, or one for a source without a webhook secret, triggers
  nothing and is said without its body, signature or secret; an authentic one triggers one sync of
  its source, a burst one sync, and a flood one sync per 30 s.
- **Every `Fetch` returns within `sync_timeout`**: a source that ignores its context is abandoned 5 s
  past the deadline, the sync fails and the bundle in force keeps serving, and the source is not
  asked again until the abandoned call returns.
- **Export verifies**: a bundle that does not open under the verify keys writes nothing, nor one
  whose sequence is not the one `--from` asked for; one that does writes a file `--inventory` loads
  to the same bundle.
- **Unresolvable `key_ref`** fails that device closed, not the daemon.
- **A device no key group admits**, and one two groups tie on, is refused admission on its own
  and its packets closed after the header as `admission_refused`; the rest of the fleet loads.
- **A declined source is refused at Accept**: after one recorded packet from a refused or quarantined
  device, or from one a reload refused or removed under an open connection, its next connection
  inside the decline window is reset at Accept with no record, counted `declined_refused`, and with
  no strike. A reload that admits it again, or the end of its quarantine, serves its next connection
  at once. An unadmitted source's packet is recorded, struck and reset at once, never held, and its
  next connection inside the backoff is reset at Accept and counted `held_refused`. So a removed
  device's retries are `declined_refused` for at most one window (only when the removal ended an
  open connection), and `held_refused` after that, with each strike recorded `unadmitted_source`.
- **An inventory-only reload** leaves a live context whose answer did not change unwritten and
  unrecorded, revokes one on a device removed from inventory, and writes one `inventory_change`
  record per address added, per `key_ref` change, per device newly admitted and per
  `security_log` scope membership change.
- **The key-group move never refuses the fleet:** with the block in both files the policy's
  wins; deleting it from the inventory first is refused by the bound; a restart between the two
  edits loads.
- **The inventory file's fence:** a group-writable inventory file refuses the start, and at a
  reload is refused once while the bundle in force keeps serving.
- **A `based_on:` variant** of `juniper_junos` is authorized as `junos-exec`, its `cmd=login`
  record read as an exec record, and its records redacted with Junos's patterns.

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
- **API rights**: a principal without `api:` can end its own sessions and delete its own
  unspent tokens, never another's, including another principal's under a shared `(device,
  username)`, and never marks a context another login replaced; `revoke_others` unlocks a
  standing mark on another principal and ending any `(device, username)`; `explain_others`
  unlocks explaining another principal; a request without the right, a `(device, username)`
  without `mine` included, is refused 403 `api_right_missing` and recorded with no `auth`; no
  right widens a mint or a refresh; an unknown device, and one outside the caller's grants that
  is quarantined or refused admission, is explained exactly as one with no grant; `/v1/logout`
  succeeds with a valid logout token and no caller rights;
  a logout token replayed is answered 200 and does nothing; one that does not validate is 400 and
  reaches nothing; a token naming a logged-out `sid` is refused at every endpoint; an OIDC token
  two verifiers accept is refused; a person's delegated access token for a machine client is
  refused, never `app:`; a token from one issuer naming a principal in another issuer's
  `principal_domains` is refused, and that issuer's logout reaches none of the person's contexts;
  every subject carrying `api:` appears
  in the CI report.
- **Workload certificates** (§13 decision 40): a certificate under the workload anchor mints as its
  one SPIFFE ID, never as a person, and with every directory server down; one whose chains end at
  both anchors is refused `trust_domain_unresolved`; one with zero or two URI SANs, an upper-case
  or path-less ID, or an unlisted trust domain is refused `identity_unmapped` at bind over HTTP; a
  renewed certificate mints as the same principal; a revocation by principal refuses every
  certificate of the workload, and one by certificate is said not to follow a renewal; a
  `spiffe://` principal and an `app:` principal of one subject mint one username; a directory
  username a subject declares is refused `username_collision` and the declared one mints; a
  scope's `attached_roles.machines` compose into a workload's grant and `attached_roles.humans` do
  not.
  Under a directory mapping (§13 decision 41, plan 8b): with no `directory:` the resolver is never
  asked for a workload; with it, a workload matches a `machine_group:` subject its entry's groups
  name and never a `group:` subject, and a `user:` principal never matches a `machine_group:`; an
  entry holding another case of the SPIFFE ID is `identity_unmapped` and two entries holding it
  `identity_ambiguous`; a workload whose subject declares the username its entry holds mints under
  it; an outage past grace refuses its mints `directory_unavailable`, `port49 workload` exits 75,
  and the scheduled refresh leaves its contexts unstamped; while a workload mapping is configured,
  a person's entry whose workload attribute holds a value beginning `spiffe://` is refused
  `identity_unmapped` on the person path (decision 41 ruling 4).
- **Port49-issued certificates** (§13 decision 43): a sign-in's ID token whose `nonce` names the
  CSR's key, `auth_time` within 5 minutes, is issued a certificate once, and a second exchange of
  the token is refused; a token whose `nonce` names another key, or a stale `auth_time`, is
  refused and recorded; the certificate mints as the sign-in's principal with `auth.oidc` on its
  records, never mapped through the directory; a chain ending at the issuing CA and another anchor
  is refused; a sign-in whose issuer no human verifier takes now is refused; a back-channel logout
  of its `sid` refuses its next mint and refresh `credential_revoked`, for as long as the certificate
  lives, and revokes its device sessions; a key signature refreshes it with no sign-in; a person's ID token at any other endpoint
  of a broker that issues is refused, and a machine's is not; a broker with no issuing CA key
  starts, answers a sign-in `issuance_unavailable`, and says so.
- **Staleness ceiling**: with the broker unreachable, a context authorizes until
  `staleness_ceiling` elapses since `refreshed_at`, then denies `context_stale` with a
  `server_msg`, and resumes on the first refresh after the broker returns.
- **Revocation is distinguishable**: a revoked context's next command is denied
  `credential_revoked`, not `context_missing`, until the idle TTL reclaims it.
- **A login into a revoked result is refused**: a login that writes a revoked context — a
  same-principal replace past the ceiling, an unreadable replace, or a revocation landing mid-join,
  each with a token minted before the revocation — answers FAIL `credential_revoked` with the token
  spent, and its retransmission is refused `credential_revoked` while the context is revoked and
  replays FAIL `receipt_replayed` after a later token lifts it — never a PASS, the concurrent
  duplicate of §5.6 included (plan 7d; pre-flight F16).
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

**Shared store** (plan 7d; §13, decision 35)

- **Every backend, every property**: each `storetest` property passes against the memory
  store, the sealing layer over it, the etcd backend, and the sealing layer over etcd.
- **The login is one step**: a login replacing another principal's context leaves it indexed
  under the new login's keys alone, whatever lands concurrently; a revocation mark that appears
  between a login's read and its write makes the write conflict and land revoked.
- **Quorum lost**: with two of three etcd members stopped, a store call fails with
  `store.ErrUnavailable` within its deadline, never answers from a stale member.
- **The seal**: a context record whose `revoked_at` is zeroed, privilege raised, blob swapped
  or ceiling removed in the store reads back as port49 wrote it, and one moved to another key
  does not open. A token whose trusted fields are raised in the store reads back as minted,
  one moved to another key or ID or whose expiry is extended is dropped, and a login receipt
  copied to the enable key does not open.
- **The ledger**: another login's context written back at a key is denied, and so is an
  earlier version of the same context put back after a later write landed, whichever process
  made either. Another process's later write at a key is admitted once this process's feed
  has delivered it. A key with no mark admits only a record sealed past the start's scan, and
  a put-back the feed or a rescan brings at such a key is denied. A process started after a
  put-back denies it when the ledger record holds a later mark at the key. With
  `--bump-revision`, a login after an etcd restore is admitted on every process and a
  restored record is denied; without it, a login on a process started after the restore is
  denied on one that ran across it. A form-3 context does not open, and is named as an
  earlier form.
- **The feed fence**: while this process's context feed lags or has stopped, a record put
  back over another process's later write, or over its revocation, is never admitted: the
  read waits and is `store_unavailable`, and once the feed delivers, it is denied. A ping
  through the fence fails while the feed is behind.
- **The feeds**: a context change raises its key's mark and never lowers it; a plaintext
  revocation at the mark's sequence is a floor a put-back cannot clear; a compacted watch
  seeds from the ledger record and scans again, and a put-back made in the gap over a later
  login the record holds is denied after it. A progress notification never precedes an event
  at or below its revision. A mark landing on one process closes that process's held
  connections it names, and a lift removes it.
- **The ledger record**: `port49_ledger_behind` is 1 while the keeper's context feed is down,
  and both ledger gauges are 0 once its duties stop.
- **The emits**: a log sink that stalls during a mint never stalls a reload, and every mint
  record follows its blob record.
- **The split**: port49d.yaml on etcd naming the broker's identity, or a `broker:` block, is
  refused; port49-broker.yaml naming `keys:` or the daemon's identity is refused. A login on
  one port49d is answered on another. A revocation made on one port49-broker closes the held
  connections it names on another, and every port49d denies the session's next command. A
  runner that stops, or is cut off from etcd without releasing its lease, is replaced within
  `hold_ttl` and a third; a takeover purges only when the bundle in force is not the one last
  judged, and a clean takeover records its bundle as judged. With every broker stopped, an
  open session's next command is answered, and a revocation made offline, or as etcd's root,
  denies it.
- **Across replicas**: a replica serving another bundle than the runner's says so, and its
  reload has the runner carry a context it made under the old policy. A start whose policy
  file the reload guard refuses against the judged bundle stays not ready and takes no hold. A
  mark in a broker's copy that the store lost is put back by the runner, named in its line,
  and a mark lifted through the watch is not. A port49d whose policy is not the bundle last
  judged says so.
- **The restore witness**: an etcd restore with `meta/judged` left as the snapshot's still
  purges, at the takeover or under a running runner, when a broker's `witness.json` recorded
  a later `meta/witness` than the store holds, with `--bump-revision` too; a token redeemed
  after the snapshot stays spent.
- **The index lost**: a context whose index record is deleted, or rewritten to name another
  principal or another sid, or whose lookup entry is deleted, is found, re-indexed and judged
  against the policy in force, and a revocation by principal or sid reaches it again. An index record that does not decode is skipped, logged and
  counted, and the rest are re-indexed.
- **The marks**: a context a standing mark names is denied `credential_revoked` at
  authorization, at `enable` and at a receipt's replay, whatever its record says; a lifted
  mark denies nothing.
- **The witness**: a retransmitted login replays PASS only once its join committed into an
  unrevoked context; one whose join ERRORed without committing, is in flight, or wrote a
  revoked context, and one whose `sid` a session refresh rotated since, is `token_spent`.
- **A restart on etcd**: a live context's next authorization is answered from it, an unspent
  token from before the restart is `token_not_found`, and a second port49d against the
  keyspace binds no listener.
- **A mark at start**: a context the store kept, whose principal a mark added with port49d
  stopped names, is revoked before any listener binds, and its next command is denied
  `credential_revoked`.
- **A store gone**: with the store hung past `store.etcd.hold_ttl`, port49d closes every
  listener, resets every held connection, and says why; when the store returns, the same
  process listens again. A start after a store gone that fails for any other reason is
  tried again, never an exit.
- **The failure delay**: a FAIL behind a `store.packet_deadline` shorter than the delay takes
  the whole delay, and a FAIL behind a slow store arrives at the delay, its store time
  inside it.
- **The bulk pool**: its circuit open for `store.etcd.hold_ttl` closes no listener.

- **Directory.** A grace mint's context has `refreshed_at` equal to the membership's
  verification time. A scheduled pass with no server answering stamps nothing and revokes
  nothing. A principal in two subjects holds the union of their grants, the least `token_ttl`
  and the most demanding `enable`. A group name two groups share matches no one. A recursive
  walk ends on a loop. A broker restarted in a directory outage mints within grace from the
  store and refuses past it. A principal the directory refused before an outage is refused
  through it. Two entries holding one `principal_attribute` value are both
  `identity_ambiguous`. A policy refresh never widens on a membership older than grace. An `app:`
  context survives a scheduled pass. An entry re-created with a new id is `identity_unmapped`
  until `port49 directory forget`. A marked certificate with every DC down is 401
  `credential_revoked`. `/readyz` stays ready with every DC down.

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
| **L2** | Whether `server_msg` on an authorization REPLY is displayed to the operator, and at what length it truncates. | The session-ceiling warning (§5.6); denial messages | all | open — measured 2026-10-01 on EOS, NX-OS and IOS-XE; Junos unmeasured. tests/lab/results/L2-arista_eos.md, L2-cisco_iosxe.md, L2-cisco_nxos.md, L2-juniper_vjunos-router.md, L2-juniper_vsrx.md, through a denial padded to 64–1000 bytes (`lab.deny_message_length`). **vEOS-lab 4.31.2F (image tagged 4.32.2F) and IOS-XE 17.13.01a: displayed in full** at every length; no truncation at or below 1000 bytes. **NX-OS 10.4(2)F: not displayed** at any length; the device prints its own `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)`, so no truncation length can be read. (This cell said the N9Kv was not measurable; `L2-cisco_nxos.md` measured it, and it was wrong.) **Junos: not measurable** on vJunos-router 23.4R2-S2.1 or vSRX 21.4R3.15: there is no per-command reply (decision 21), and a session denial carrying the message printed none of it and did not stop the login (a prompt at every length; `junos-session-service-juniper_*.md`, phase C). Truncation above 1000 bytes is unmeasured; see below. **Output modifiers (recorded 2026-09-23, plan 4; seen again 2026-10-01):** in the truncation runs a typed `show clock \| include …` reached port49 as `show clock` alone on vEOS 4.31.2F, NX-OS 10.4(2)F and IOS-XE 17.13.01a (`tests/lab/results/L2-arista_eos.md`, `L2-cisco_nxos.md`, `L2-cisco_iosxe.md`, "Output modifiers"), which is why no built-in platform's `pipe_authorized` is true (§8); whether any modifier reaches port49 anywhere is unmeasured |
| **L3** | Whether the enable START carries `rem_addr`, and what it contains — bare address, or address and source port. | `rem_addr` binding on `$enab{level}$` platforms (§5.6); the login context key, because an enable that carries a fixed username collapses `(nas, username)` to one context per device | EOS, NX-OS, IOS-XE | closed — measured 2026-09-21; `tests/lab/results/L3-arista_eos.md`, `L3-cisco_iosxe.md`, `L3-nxos-cisco_nxos.md`. Scope: NX-OS 10.x has no enable exchange (`feature privilege` was removed in 10.x; the owner confirmed the same on production Nexus 9000 hardware running 10.3(5)); NX-OS 9.x and earlier are unmeasured and out of scope. No measured image sends `$enab{level}$`. History: closed in error 2026-09-20 on a note with no transcript, reopened 2026-09-21. Measured: vEOS-lab 4.31.2F (image tagged 4.32.2F) and IOS-XE 17.13.01a both send the operator's own username with `service=enable` and a bare-address `rem_addr` (`tests/lab/results/L3-arista_eos.md`, re-measured 2026-09-22, which is where the image tag was found to overstate the running version; the image under the tag is `sha256:8ef33020ece8871b19ddfdddf7f3585b04d2ac3672845b0db88debe8e96ff9c9`, created 2026-09-15, the only one on the lab host; `L3-cisco_iosxe.md`). **NX-OS re-measured 2026-09-21 with the transcript it was missing** (`tests/lab/results/L3-nxos-cisco_nxos.md`): `disable`, `enable` and `enable 15` were each typed separately and each answered `% Invalid command at '^' marker.`, and `feature privilege` is itself refused by this image, so the conclusion the reopened note reached without evidence is confirmed with it |
| **L4** | Whether any method-list configuration falls through to local on FAIL rather than only on ERROR — specifically Junos `authentication-order` with `password` listed — and `deadtime` behavior. | The `enable: auto` exposure argument and "denial is FAIL, so no fall-through" (§5.6); the reference AAA configuration | Junos first; then all | open — measured 2026-09-20 on vJunos-router, vSRX, vEOS, the N9Kv and IOS-XE over SSH: both Junos images fall through on a FAIL when `password` is listed; vEOS, the N9Kv and IOS-XE never do (`tests/lab/results/L4-cisco_iosxe.md`, which this cell omitted until 2026-09-23); `deadtime`, other transports and authorization fall-through unmeasured. **2026-09-21 (L17):** committing `tacplus-options strict-authorization` on both Junos images changes none of the unreachable-server cells — break-glass still logged in under both orders with port49d down — so making a port49 denial binding does not cost the fall-through this row measures. **2026-09-24, ERROR and `deadtime`, all five images** (`tests/lab/results/L4-error-*.md`): an authentication ERROR is final on IOS-XE and on Junos with `tacplus` alone and falls through elsewhere, but on vEOS and the N9Kv port49's authorization FAIL during a store outage then leaves break-glass useless; a per-command ERROR is final on vEOS, falls through to local RBAC on the N9Kv, and under IOS-XE's `if-authenticated` permits every command; a silent server costs 5s per command on the Cisco and Arista images and nothing on Junos; only the N9Kv offers a dead time, and `deadtime 1` locks token logins out for its minute after the server returns. Plan 4 answers an authorization `store_unavailable` `FAIL`, never `ERROR`, for this reason (§5.7). Still open: other transports, a second server, the console; see below |
| **L5** | Which platforms send accounting WATCHDOG, how often, and with or without arguments. | §5.8 record handling | all | closed — measured 2026-09-20; `tests/lab/results/L5-arista_eos.md`, `L5-juniper_vjunos-router.md`, `L5-juniper_vsrx.md`, `L5-cisco_nxos.md`, `L5-cisco_iosxe.md`. No image sends a WATCHDOG over a 2m30s idle interactive session under the lab's accounting config, which sets no periodic update; a device configured for periodic updates is outside what was measured |
| **L6** | How reliably and how late exec accounting START and STOP arrive, and whether a device retries accounting to the same server or fails to the next. | The `task_id` binding tolerance (§5.8); what reconciliation may conclude from silence (§9); `ERROR` semantics | all | open — arrival and latency measured on EOS and Junos; retry unmeasured; see below |
| **L7** | Whether eAPI and NX-API run each HTTP request through AAA authentication, whether session cookies (`/login`) change that, and whether API commands produce per-command authorization requests. | Reusable tokens (§13, decision 15); capability inference (§9) | EOS, NX-OS | closed — measured 2026-09-24; `tests/lab/results/L7-arista_eos.md`, `L7-login-arista_eos.md`, `L7-cisco_nxos.md`, `L7-nxapi-cookie-cisco_nxos.md`. eAPI and NX-API both measured 2026-09-20: one authentication per HTTP request on both, with per-command authorization and per-command accounting. Both cookies measured: eAPI `/login` 2026-09-23 and NX-API `nxapi_auth` 2026-09-24 — a request carrying the cookie runs no authentication and no session authorization, only its command authorizations (NX-API: the command plus `end`; `configure terminal` too for `cli_conf`). The `nxapi_auth` cookie expires after 10 minutes idle (`NXAPI timeout 10`), ends on `POST /logout`, and wins over a wrong Basic password sent beside it; NAPALM `nxos` never uses it (21 authentications for a six-call job) while Ansible `httpapi` does (one); see below |
| **L8** | The maximum password length each platform accepts at an interactive prompt. (PAP was split out to L19 on 2026-09-23.) | The 30-character handle (design document §8) | all | closed — measured 2026-09-23; `tests/lab/results/L8-cisco_nxos.md`, `L8-cisco_iosxe.md`; and 2026-09-20, `L8-arista_eos.md`, `L8-juniper_vjunos-router.md`, `L8-juniper_vsrx.md`. The 30-character handle logs in on all five images. Longest intact: **127 on the N9Kv**, which refuses 128 and above locally and never asks port49; at least 1024 on IOS-XE; at least 138 on vEOS and both Junos images, where nothing longer was tried; see below |
| **L9** | Whether Junos anchors `allow-commands` / `deny-commands` regexes, and which RE2 constructs its regex dialect rejects. Whether explicit `^` and `$` are taken, with the pipe tail `( *\|.*)?` refusing `show version | no-more`; whether a deny regex reads a command in the case and the abbreviation typed (`SHOW VERSION`, `sh ver`) or as the CLI expands it; whether a value with spaces is taken raw; whether a malformed wire regex (`^(show$`) is ignored, which fails open, or refuses the session; and whether the commit checker takes, as class configuration, every wire regex shape the projection renders — a shape it rejects ships the set Junos unprojected (§8, platform sets). Whether a regex is matched against a command's arguments at all, or its keywords only. Whether a keyword deny refuses every abbreviation of its command: several lengths and depths, piped, and one ambiguous at a level (`JunosFacts.DenyMatchesExpanded`; `L9-abbreviations-juniper_*.md`). | Projection generator constraints (§8); `JunosFacts` in `internal/projection`, each fact read in the direction that fails closed until measured; decision 27 | Junos | closed — measured 2026-09-29; tests/lab/results/L12-projection-juniper_vjunos-router.md, L12-projection-juniper_vsrx.md (commit checker), with `L9-juniper_*.md` and `L9-abbreviations-juniper_*.md` (2026-09-25). On vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15, the two agreeing: a regex is matched against a command's keywords as the CLI expands them, never its arguments (decision 27); explicit `^` and `$` with the pipe tail are taken; a malformed deny `^(show$` opened the session and refused the probes; the CLI refuses upper case; a keyword deny refuses every abbreviation (`DenyMatchesExpanded` true); and the commit checker took, as class configuration, every wire regex form set 1.1.0 renders — `^.*$`, allow alternations, a keyword deny alone and two alternated, and the multi-word deny's ` +` alone and alternated — each read back unchanged. The constructs measured are those set 1.1.0 renders: anchors, groups, alternation, `.*`, `?`, `*`, ` +` and the escaped pipe. Other RE2 constructs (a bracket class, `.+`, case pairs, escapes the generator's code can write) are out of scope, since set 1.1.0 never renders them; a set, facts or generator change that renders one reopens this row |
| **L10** | Whether `service` arrives as `shell` or `junos-exec`, and the exact spelling of every attribute in a shipped adapter. | Adapter `VERIFIED` status (§8) | all shipped adapters | closed — measured 2026-09-29; tests/lab/results/L12-projection-juniper_vjunos-router.md, L12-projection-juniper_vsrx.md, L22-*.md, L12-juniper_*.md. `shell` on EOS, `junos-exec` on Junos. **Reading 3's conclusion is corrected by L17 (2026-09-21):** a denied Junos session authorization is advisory under the configuration this lab deploys, not on this vendor — `tacplus-options strict-authorization` makes the same denial refuse the login; see below. The three per-command adapters' spellings are measured by plan 5a (tests/lab/results/L22-*.md). Junos's: plan 5b's Task 2 applied `local-user-name`, `user-permissions`, `deny-commands`, `allow-commands` and `allow-commands2` as spelled on both images (`L12-juniper_*.md`), and set 1.1.0's projection sends `user-permissions`, `deny-commands` and `allow-commands` in the shapes it renders, applied as spelled on both images by the differential (`L12-projection-juniper_*.md`, 2026-09-29); 1.1.0 never renders `local-user-name`, which Task 2 measured |
| **L11** | Junos precedence, repetition, and length behavior for wire and class rules. | The projection model (§8) | Junos (SRX) | **closed** — measured 2026-09-03; results in `port49-junos-lab-tests-results.md` |
| **L12** | `user-permissions` over TACACS+: accepted with a bitless template, replaces rather than merges with the class, per-session, and two bits in one value. What each bit reaches, so `bits:` can be declared, and that `view` alone does not show the configuration. Whether a wire `deny-commands .*` plus one allow alternation yields exactly the permits. Whether `deny-commands-regexps` beats `allow-commands-regexps` over the wire as documented, and whether numbered names (`allow-commands1`, `allow-commands2`) are distinct attributes. Whether `deny-commands` reaches a statement typed in configuration mode, and `run`. Whether a template user commits with no uid, and whether one with no authentication refuses a local login. What a class with no bits runs (`baseline`), and whether `deny-commands .*` refuses it. Whether deny-commands and the fail-closed reply bind a NETCONF RPC opened with the same token and reply (`<get-configuration>`, `<get-software-information>`; `L12-netconf-juniper_*.md`). Whether a deny naming an argument (`^show interfaces fxp0( .*)?$`) is enforced. Measured 2026-09-25 on both images: it is not (decision 27), and a deny-commands naming a configuration statement does not stop it in configuration mode (`L12-configuration-juniper_*.md`). | The projection rule, its default shape, and its refused shape (§8; §13, decision 22); the built-in `bit_delivery` and `bits` (set 1.1.0) | Junos (vSRX / vJunos-router in containerlab) | closed — measured 2026-09-29; tests/lab/results/L12-projection-juniper_vjunos-router.md, L12-projection-juniper_vsrx.md. The projection differential (plan 5b Task 19): every shape set 1.1.0's built-in Junos adapter renders — 21 rule shapes, narrow, capability (bits alone, bits with one or two keyword denies, bits with a deny and allows) and fail-closed — ran on vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15, typed in full, abbreviated, piped and padded. No probe ran that port49 denies, none that the model says the reply refuses, every shape rendered its expected reply, identical on both images, and none quarantined the device. This holds with `system services netconf` removed, as set 1.1.0 and `devices check-config` require: over NETCONF a native RPC ran past every wire deny (below), so a device with NETCONF on is outside this result. Earlier measurements stand: `user-permissions` over a bitless template, per session, both bits of a two-bit value; each bit's reach, the baseline and `view-configuration`'s carve-out (`L12-juniper_*.md`, `L12-bits-juniper_*.md`); a deny naming an argument is not enforced, and deny-commands does not reach configuration mode (`L12-configuration-juniper_*.md`); over NETCONF a native RPC ran past every wire deny (`L12-netconf-juniper_*.md`; L26c) |
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
| **L24** | Whether a Junos login class's `idle-timeout` ends an idle session a TACACS+ reply landed in that class, through `local-user-name` and through the `remote` template. | Decision 21's enforced approximation; `port49 platform export --classes` (§5.6, §8) | Junos | closed — measured 2026-09-25; `tests/lab/results/L24-juniper_vjunos-router.md`, `L24-juniper_vsrx.md`. With `idle-timeout 1` on the class, an idle session closed 1m0s after its prompt with the device's `Idle timeout exceeded: closing session`, through `local-user-name` and through the `remote` template, on vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15. The largest `idle-timeout` the device takes is not this row's question and is unmeasured; see below |
| **L25** | Whether the N9Kv writes an accounting record under `admin` with task_id `vsh.bin.<port>` when a network-operator cancels the sudo prompt of a bare `show interface`, and what distinguishes it from a person's `admin` session, over SSH and over NX-API. | A `cisco_nxos` system user keyed on its task_id, never the username alone (§5.8) | NX-OS | open — a production observation, not reproduced. Measured 2026-09-25 on Nexus 9300v 10.4(2)F (`tests/lab/results/L25-cisco_nxos.md`): a network-operator's bare `show interface`, paged to its end, asked for no sudo password on this image, so there was no prompt to cancel and no record under `admin` followed. No system user ships, and plan 5b's Task 15 did not run |
| **L26** | The Junos operational CLI keyword tree under `show`: at each command path, the words proven keywords — offered by completion there, and shown a keyword by `\| display xml rpc` (an element named as the word, none holding it as text, or a path still asking for a `<command>`) — and whether an argument may be typed there; anything without that evidence is an argument. The pipe is first proven to run nothing. Walked over the break-glass CLI, seeds first, bounded in breadth, depth, nodes and commands. Scope: the images captured, and no hidden argument. | Which denies and allows the projection may send (decision 27; §8); `platforms/keywords/<set>/juniper_junos.yaml` | Junos (vSRX / vJunos-router in containerlab) | closed — measured 2026-09-25; `tests/lab/results/L26-juniper_vjunos-router.md`, `L26-juniper_vsrx.md`. The pipe ran nothing on either image, and neither walk stopped at a bound: vJunos-router 23.4R2-S2.1, 136 nodes and 755 keywords; vSRX 21.4R3.15, 118 nodes and 668. Both images were walked twice: vJunos-router's rerun reproduced its first tree byte for byte, and vSRX's runs disagreed, so a keyword is one only where every run on every image proves it: set 1.1.0's tree intersects every committed run (three trees), 528 keywords, and adds L26b's seven (535, frozen with the set). Nothing under `show configuration` is proven. Scope: these two images, and no hidden argument; see below |
| **L26b** | Whether a word is a keyword to `deny-commands`, by the deny itself: a deny naming the word at its path refuses the command, the CLI's caret under the word, while a paired control without the deny runs it with positive evidence. Probed: the words after `show` that L26 offered and did not prove (`cli`, `host`, `ingress-replication`, `policy`, `task`), `exit`, `save`, `set cli`, and every `show configuration` hierarchy the image offers. | The L26b overlays laid over L26's trees (`tests/lab/results/L26b-keywords-juniper_*.yaml`), and so set 1.1.0's keyword tree; whether a deny naming a `show configuration` hierarchy may be sent (decision 27; §8) | Junos (vSRX / vJunos-router in containerlab) | closed — measured 2026-09-25; `tests/lab/results/L26b-juniper_vjunos-router.md`, `L26b-juniper_vsrx.md`. Proven on both images: `show cli`, `show host`, `show ingress-replication`, `show policy`, `show task`, `set cli` and `exit`. `save` is proven on vJunos-router and unproven on vSRX, so it is not a keyword in the set. **A deny naming a `show configuration` hierarchy is not enforced**: every offered hierarchy, 32 on vJunos-router and 25 on vSRX, ran under a deny naming it; see below |
| **L26c** | Whether a projected Junos CLI session reaches a native RPC with the NETCONF service off: `xml-mode netconf need-trailer` and `xml-mode netconf`, then `<get-software-information/>`, `<get-configuration/>` and a `<command>` RPC; `op url`; `start shell`; the NETCONF subsystem on port 22 with `netconf ssh` deleted; and whether the fail-closed reply's `deny-commands .*` refuses those entry points. Beside it: whether a deny naming the entry points binds, with their abbreviations and through a class's own deny list; whether `deny-commands "junoscript"` also refuses NETCONF as an SSH subsystem on port 22 (with `netconf ssh` configured), NETCONF over the SSH exec channel (`ssh <device> xml-mode netconf need-trailer`), an `op url` script's `jcs:invoke` RPCs, REST (`/rpc/…`), the XML API (`xnm-ssh`, `xnm-ssl`, `xnm-clear-text`), `outbound-ssh` and `scp` of `/config/juniper.conf.gz`, each against a control; whether a port49-projected reply under set 1.2.0 carrying the entry deny keeps the CLI deny, refuses NETCONF, and leaves a no-deny subject's NETCONF working. | `JunosFacts.DenyBindsRPCs` (false): a deny beneath a sent bit or the baseline guards the CLI only; set 1.1.0 fails closed on it (§8, option C), and set 1.2.0 adds `rpc_entry_denies` (`junoscript **`) instead (decision 44 rulings 1–3, 6); which management services check-config fails under each set (§8) | Junos (vSRX / vJunos-router in containerlab) | open — measured 2026-09-25 on vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15 (`tests/lab/results/L26c-juniper_*.md`), the two agreeing: under a projected class (`view`, a rendered deny naming `show configuration`), `xml-mode netconf` returned a hello and `<get-software-information/>` ran, as in the control; `<get-configuration/>` returned an empty `<configuration>` there and in the control alike, `view` lacking `view-configuration`; a `<command>show configuration</command>` RPC was refused, which the control's own bits leave unisolated here (over NETCONF the deny refused one the control ran, `L12-netconf-juniper_*.md`); `op url` was accepted up to the copy; `start shell` was refused by the bits, as in the control; `deny-commands .*` refused `xml-mode` and `op url`; and with `netconf ssh` deleted port 22's NETCONF subsystem was refused in every class, break-glass included. The run failed its four `view`-only `get-configuration` cells (reclassified since as bits-limited, not rerun); the `xml-mode` probes ran before `netconf ssh` was deleted; and `view` alone cannot set a deny against RPC reach: a rerun is owed (L26c review I-1, I-4). The questions beside it are open. The owner reported on 2026-09-25, from SRX hardware (Junos 23.4R2-S8.7, no capture, `tests/lab/results/L26c-operator-juniper_srx.md`): `<get-configuration/>` through `xml-mode netconf` passed a deny of `show configuration` beneath `view-configuration`; a deny of `show version` refused `<get-software-information/>`; no sent deny naming `xml-mode` refused it, while `^.*$` did (with every other command); accounting recorded the entry as `cmd=xml-mode netconf <cr>`; and with the NETCONF service (`netconf ssh`, port 830) deactivated, `xml-mode netconf` from an SSH CLI session on port 22 still opened NETCONF and `<get-configuration/>` returned the configuration, so the management-services allowlist does not close `xml-mode`. On 2026-09-28 the owner reported the same with the deny set on the local class, and that `deny-commands "junoscript"`, set on the class or sent by TACACS+, refused `xml-mode netconf` while `show version` still ran: Junos appears to authorize `xml-mode` as `junoscript`. Without a capture these do not close the row. Measured 2026-09-30 on vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15 (`tests/lab/results/L26c-junoscript-juniper_*.md`), the two agreeing and each refusal isolated against a control with the same bits and no deny. `deny-commands "junoscript"`, sent by TACACS+ or set on the local class, refused `xml-mode netconf` and `junoscript netconf` while `show version` ran. It also refused that user's NETCONF on port 830 with `error: unknown command: xml-mode`, where the control reached `<get-software-information/>` both ways. A deny naming `xml-mode` did not bind. The abbreviated forms were refused in every class, so they say nothing about the deny. This confirms the owner's `junoscript` reports. Because the deny also ends that user's NETCONF, set 1.1.0 does not send it and option C stands there; set 1.2.0 sends it as `rpc_entry_denies` (decision 44), on the CLI `xml-mode netconf`, `junoscript netconf` and port 830 measured closed by it, and a deny naming `xml-mode` measured not to bind (the L26c-junoscript notes). The rest of the row stays open; plan 9b1 (2026-10-11) measures the rest in its Tasks 3 and 9 |
| **L27** | What NetBox and Nautobot's APIs return for a device, per product and major version: where the version is reported (`/api/status/`, the `API-Version` header on `/api/`); the field names for role, platform, site or location, primary address, custom fields and tags, over REST and over one GraphQL query; which GraphQL query shape each version takes, and whether one query returns every interface address; how REST paginates; and what a device create, update and delete webhook carries — its headers and body, and whether `X-Hook-Signature` is HMAC-SHA512 of the body under the webhook's secret. | Plan 6c's connectors: version detection and mapping profiles, GraphQL first with REST as the fallback, webhook authentication (§10, "Connectors and sync cadence") | NetBox 3.7 and 4.x; Nautobot 1.6 and 2.x | closed — measured 2026-09-30; tests/lab/results/L27-netbox.md, L27-nautobot.md. NetBox 3.7.8 and 4.7.1, Nautobot 1.6.32 and 2.4.43; fixtures in `tests/lab/sot/fixtures/`. One GraphQL query returned every interface address on all four, each in its own query shape; every webhook signature was HMAC-SHA512 of the body. *Unmeasured:* a non-null pagination `next` (each run held one device) and Nautobot 3.x, split to L30; see below |
| **L28** | What a device does when port49d cannot validate its key on a connection's first packet. For a key port49d does not hold, one it holds only as retired, and one past its `retire_after`: whether a break-glass login succeeds and how long it takes, how long a command in an open break-glass session takes, and whether a token login is refused. And that a second version accepted beside the current one lets the device work unchanged, and that the device given the current key works at once with no port49d change. Measured first with port49d holding the connection for the per-source backoff and closing it without a reply, then closing it at once with a FIN, then as port49d does now: one record and a strike, the connection reset at once with no reply, and the source's next connections inside its backoff refused at Accept with a reset (§10, "A key miss is closed at once"). An open connection passing its version's `retire_after` is L29's. | Key rotation's no-cutover claim and the retirement lockout's shape (§10 "Retirement is enforced"); the design document's "a key mismatch is indistinguishable from an outage" (§12); whether a key miss should be closed at once, as a quarantine is | EOS, NX-OS, IOS-XE, Junos | closed — measured 2026-09-30; tests/lab/results/L28-arista_eos.md, L28-cisco_nxos.md, L28-cisco_iosxe.md, L28-juniper_vjunos-router.md. The hold stalled break-glass on all four images (`L28-held-*.md`) and a FIN still stalled the C8000V (`L28-fin-cisco_iosxe.md`), so port49d now resets (branch H). With the reset, break-glass logs in and runs its commands in the time port49d stopped gives on all four, and every token login is refused, for an unknown, a retired and an expired key; a second accepted version logs token users in at v1, and the device given the new key logs in at v2 with no port49d change; see below |
| **L29** | What a device does when port49d resets a connection it holds open mid-session, at its first packet after a reload refused, removed, renamed, re-keyed or re-platformed its device (§10, "How a daemon refreshes its snapshot"): whether the session survives; whether the command in flight fails or falls to the local method, and how long it takes; whether the next command runs; and whether the next token login is refused and break-glass logs in, and how long each takes. The same reset, with a strike, ends an open connection at its first packet past its key version's `retire_after` (§10, "Version sets, and no cutover"). The device sees the same reset either way, so this row measures the device's side of both through the reload case (owner's ruling, 2026-09-30); that port49d resets an open connection at `retire_after` is tested in code with an injected clock (`internal/daemon/server/server_test.go`, `TestAnOpenConnectionDoesNotOutliveItsVersionsDate`, `TestAPacketPastItsDateIsClosedWithAReset`), and the strike's backoff that follows is L28's. | That ending a key version at `retire_after` on an open connection costs the device what a first-packet key miss does (§10; plan 6a Decided 7, amended in its Task 14), and that ending an open connection on a reload costs it what a quarantine's close does (§10; plan 6a final review I1) | EOS, NX-OS, IOS-XE, Junos | closed — measured 2026-09-30; tests/lab/results/L29-reload-arista_eos.md, L29-reload-cisco_nxos.md, L29-reload-cisco_iosxe.md, L29-reload-juniper_vjunos-router.md. vEOS-lab 4.31.2F, Nexus 9300v 10.4(2)F, Catalyst 8000V 17.13.01a and vJunos-router 23.4R2-S2.1, each reload a `port49 inventory sync` but the re-key, a policy edit; captures `tests/lab/evidence/L29-reload-<phase>-<platform>.pcap`. The session survived the reset on all four. Where port49d could no longer serve the device (removed, refused, or re-keyed onto a key it does not hold), the next token login was refused and break-glass logged in, in up to 2.1 s on vEOS and vJunos-router and up to 30 s on the C8000V and 41 s on the N9Kv (why: L31, since fixed by `fix/breakglass-reset`); where port49d still served the device (renamed, re-platformed), its FAIL is final on EOS, NX-OS and IOS-XE and break-glass was not let in (L4). vJunos-router held a connection open across some changes and not others: its note measures removed and refused, and its banner marks the three phases in which no connection was open, so no session could be affected. The midnight run was dropped by the same ruling; see below |
| **L30** | How NetBox and Nautobot page a device list that does not fit one page, and what Nautobot 3.x returns: for NetBox 3.7 and 4.x and Nautobot 1.6 and 2.x, a REST list holding more devices than its `limit`, whether `next` is an absolute URL, which host and scheme it carries behind a proxy, whether following it to the end returns every device once, and how GraphQL pages the same list, if at all; and for Nautobot 3.x, every L27 question (version source, field names, GraphQL shape, pagination, webhook body and signature). | Plan 6c's connectors: following `next` rather than building offsets, and whether Nautobot 3.x needs its own profile (§10, "Connectors and sync cadence") | NetBox 3.7 and 4.x; Nautobot 1.6, 2.x and 3.x | closed — measured 2026-09-30; tests/lab/results/L30-netbox.md, L30-nautobot.md. NetBox 3.7.8 and 4.7.1, Nautobot 1.6.32, 2.4.43 and 3.2.6, 120 devices paged 50 at a time, behind an nginx 1.27 reverse proxy as well as directly; fixtures in `tests/lab/sot/l30/`, checked by `TestL30FixturesAreWhatTheNotesSay`. On all five, `next` is absolute and names the host, port and scheme the request came in on (behind the proxy, the proxy's host and port and `X-Forwarded-Proto`'s scheme), and following it to `null` returned all 120 once. GraphQL returned all 120 unpaged on all five; it pages by `pagination: {offset, limit}` on NetBox 4.7.1, which answers `limit`/`offset` with HTTP 200 and an `errors` list, by `limit`/`offset` on every Nautobot, and by no shape tried on NetBox 3.7.8. Nautobot 3.2.6 answered every L27 question as 2.4.43 did, less the device fields `cluster` and `software_image_files`. *Unmeasured, outside the row's question:* which of `Host` and `X-Forwarded-Host` the products read (the proxy sent the same value in both), and following a proxied `next`; see below |
| **L31** | What break-glass costs on IOS-XE and NX-OS with single-connection on, when port49d resets a de-admitted device's connection after the device has written its request: a device removed from inventory (unadmitted), refused admission, or quarantined. For each: break-glass login plus three commands against port49d stopped, and whether the device's retries after the reset are refused at Accept before it writes. | That a de-admitted or quarantined device costs the device what a refused connection does, and falls to its local method at once (§10, "A quarantined device gets silence, not FAIL"; the reload paragraph under "How a daemon refreshes its snapshot"; §15 L29) | IOS-XE, NX-OS (single-connection on) | closed — measured 2026-09-30; tests/lab/results/L31-cisco_iosxe.md, L31-cisco_nxos.md, L31-arista_eos.md. With `fix/breakglass-reset` and single-connection on, break-glass login plus three commands took, removed, refused and quarantined, 1.28 s, 1.78 s and 1.78 s on the C8000V and 2.62 s, 2.58 s and 2.61 s on the N9Kv, against the rekeyed control's 1.28 s and 2.61 s and port49d stopped's 1.31 s and 2.66 s; every declined phase's retries were refused at Accept before the device wrote; vEOS, the no-regression check, took 0.33 s, 0.32 s and 0.32 s against 0.34 s and 0.37 s. Before the fix (observed 2026-09-30, cause analysed; tests/lab/results/L31-breakglass-cisco-singleconnection.md): Catalyst 8000V 17.13.01a and Nexus 9300v 10.4(2)F, from plan 6b's L29 and quarantine-sync captures (header flag `0x04`), break-glass took 30.1 s and 40.9 s removed, 20.6 s and 17.6 s refused, 20.3 s and 16.7 s quarantined, against 1.28 s and 2.62 s stopped, and 1.53 s and 2.6 s re-keyed, where a key miss's retries are refused at Accept |
| **L32** | What the inventory service's NetBox and Nautobot connectors read as built (plan 6c), from each measured release: the GraphQL list query with every field the connector asks for (`status`, `primary_ip4`, `primary_ip6`, the map's paths, every interface address), paged as the profile pages it, returning every device once and matching REST's `count`; the REST fallback (`?depth=1` under the `nautobot_2` profile) to a null `next`; and both through a TLS-terminating reverse proxy that sends the client's host as `Host` alone, and through one that sends the upstream's name as `Host` and the client's as `X-Forwarded-Host`: which header each release builds `next` from, and whether the connector reads every device through each, following `next` or rebuilding it on its `url`. | Plan 6c's connectors: the query per profile, the count check, following or rebuilding `next` (§10, "Connectors and sync cadence"; §13, decision 31) | NetBox 3.7 and 4.x; Nautobot 1.6, 2.x and 3.x | closed — measured 2026-10-01; tests/lab/results/L32-netbox.md, L32-nautobot.md. NetBox 3.7.8 and 4.7.1 build `next` from `X-Forwarded-Host` when the proxy sends it and from `Host` otherwise, and take `https` only from `X-Forwarded-Proto`; behind a proxy that sends neither, both named their own `http://netbox:8080`. Nautobot 1.6.32, 2.4.43 and 3.2.6 do the same, naming `http://nautobot:8080`. The connector as built read all 120 devices of each stack, once each, through all three TLS-terminating nginx 1.27 proxies (the client's host as `Host`; the upstream's as `Host` and the client's as `X-Forwarded-Host`; a bare `proxy_pass`), over GraphQL and over REST, 50 to a page; through the bare proxy it rebuilt every REST `next` on its `url`, said so once, and read all 120 on all five. Every release's GraphQL device list gives `id`, a string, which the connector keys the list by. *Unmeasured:* a proxy sending `X-Forwarded-Host` without `X-Forwarded-Proto`, a `next` naming another path, a GraphQL list above a server cap, and a list changing between pages; see below |
| **L33** | What NetBox and Nautobot do delivering a webhook to port49-inventory's `webhook_listen`, per measured release: whether each delivers to an `https` payload URL whose certificate a private CA issued (`ca_file_path`, `ssl_verification` on); whether port49-inventory authenticates every delivery as it arrives (HMAC-SHA512 of the body, `X-Hook-Signature`) and finds its `timestamp` inside the 5-minute window; how long a change takes from the API write to the published bundle; whether a delivery port49-inventory refuses (HTTP 401) is sent again; and, end to end on one device, how long a NetBox and a Nautobot change takes to reach port49d's admission through the webhook. | Plan 6c's webhook trigger: TLS on the webhook listener, the freshness window, the 401 answer (§10; §13, decision 31) | NetBox 3.7 and 4.x; Nautobot 1.6, 2.x and 3.x; vEOS-lab for the device run | closed — measured 2026-10-01; tests/lab/results/L33-netbox.md, L33-nautobot.md, L33-e2e-netbox-arista_eos.md, L33-e2e-nautobot-arista_eos.md. NetBox 3.7.8 and 4.7.1 and Nautobot 1.6.32, 2.4.43 and 3.2.6 each delivered to an `https` payload URL under a private CA's certificate, `ssl_verification` on, from the first change; port49-inventory authenticated every delivery, and none was stale. From the API write to the published bundle, the 2 s settle included, took 2.43–2.73 s on NetBox and 3.57–4.07 s on Nautobot. A delivery refused 401 was not sent again within 120 s on any release, nor one a stand-in listener answered 503 (port49-inventory itself never answers a delivery 503; final review M1): at their defaults neither product retries a webhook (NetBox's `RQ_RETRY_MAX` is 0; Nautobot's `process_webhook` has no retry). End to end on vEOS-lab 4.31.2F (image tagged 4.32.2F), a NetBox 4.7.1 change reached port49d's reload in 2.53–4.95 s and a Nautobot 3.2.6 change in 4.49–6.98 s; a status the default filter removes left the device with no grant, break-glass logged in, and the status restored let token logins in again. *Unmeasured:* a certificate from the worker's default trust store, a burst inside the 30 s gap, NetBox with `RQ_RETRY_MAX` set, and a delivery while port49-inventory shuts down or is down, which the next start's sync covers; see below |
| **L34** | Whether a device shows the `server_msg` port49 puts on a **permitted** authorization reply — the session reply at login, and a per-command reply — and still treats the reply as a permit: the command's output appears and the session goes on. | The session-ceiling warning (§5.6, plan 7b; decision 33): sent only to the platforms this row finds show it and still permit (`platform.CeilingWarning`, an allow-list), or that an operator lists | EOS, NX-OS, IOS-XE, Junos | closed — measured 2026-10-01; tests/lab/results/L34-cisco_iosxe.md, L34-arista_eos.md, L34-cisco_nxos.md, L34-juniper_vjunos-router.md, L34-juniper_vsrx.md. Inside a 2m `session.ceiling_warning`, the session permit at login and each command permit carried the warning (the records), and every image still treated the reply as a permit: the login reached a prompt and `show version`'s output appeared. **IOS-XE 17.13.01a: shown**, before the prompt at login and with `show version`'s output, the one command checked; on the allow-list. **vEOS-lab 4.31.2F (image tagged 4.32.2F): not shown**, at login or on a command. **NX-OS 10.4(2)F: not shown**, at login or on a command. **vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15: not shown** at login, and there is no per-command reply to show it (decision 21). EOS, NX-OS and Junos stay off the allow-list, and their operators are warned by `port49 token` (§5.6); see below |
| **L35** | What a device does when port49d's store hangs rather than refuses (etcd cut off from port49d, or past its quorum): each request's time from the device's send to port49d's reply, against the device's own TACACS+ timeout (§15 L4, L13); what it shows for `FAIL` (a command) and `ERROR` (a login) `store_unavailable`, against L4's store outage (`tests/lab/results/L4-error-*.md`); whether break-glass logs in while the store hangs; what it does once port49d closes its listeners on losing the store; and, once the store returns and port49d listens again, whether an open session's next command is answered from its context. | `store.packet_deadline`'s default and bound, and the store rows of the failure model (§13, decision 35; design document §12) | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | closed — measured 2026-10-03; tests/lab/results/L35-arista_eos.md, L35-cisco_nxos.md, L35-cisco_iosxe.md, L35-juniper_vjunos-router.md, L35-juniper_vsrx.md (run at 0eee340 from a pinned worktree, `hold_ttl` 60s; every step-3 cell valid on its first hang). With the store hung port49d answered every request in 500–502ms in the capture (each store call is bounded by `store.etcd.call_timeout`, 500ms), far inside every device's own timeout (about 3s on Junos, L13; 5s on the Cisco and Arista images, L4), so `store.packet_deadline`'s 2s default stands. **vEOS-lab 4.31.2F (image tagged 4.32.2F):** the open session's command `FAIL` in 501ms, `% Authorization denied for command 'show version': port49: authorization store unavailable`; a token login `ERROR` in 501ms, refused; break-glass `ERROR`, falls through to `local` and logs in, its command `FAIL` (`Authorization denied: port49: authorization store unavailable`), as on L4's store outage; the listeners closed 12s into a fresh hang; with them closed the open session's command ran under local authorization and break-glass logged in and ran `show version`; listening again 56s after the store returned, the session's next command permitted from the same `ctx_id`. **Nexus 9300v 10.4(2)F:** the command `FAIL` in 501ms, `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)`; a token login `ERROR` in 501ms on each of its two tries (password, then keyboard-interactive), refused; break-glass logs in and its command `FAIL`s, as L4; closed 25s into the hang; closed, the open session's command and break-glass ran; listening 38s after, same `ctx_id`. **Catalyst 8000V 17.13.01a:** the command `FAIL` in 501ms, and the device printed nothing, not even port49's text (as `L4-error-cisco_iosxe.md` (b)); a token login `ERROR` in 501ms, refused; break-glass `ERROR`, final, refused, as L4; closed 20s into the hang; **closed, the open session's command was refused `% Authorization failed.`**, the same refusal whether the session's last command was a permit or a `FAIL store_unavailable` and whichever of `show privilege` and `show version` is typed (`L38-cisco_iosxe.md`; `quarantine-cisco_iosxe.md`'s `show privilege`, which ran with port49d stopped, is unexplained by either); break-glass logged in and ran `show version`; listening 1m27s after, same `ctx_id`. **vJunos-router 23.4R2-S2.1 and vSRX3 21.4R3.15:** the open session ran on throughout (Junos authorizes no command with port49, decision 21); a token login `ERROR` in 500–501ms, refused; break-glass `ERROR`, falls through to `password` and logs in; closed 17s and 14s into the hang; closed, the session and break-glass ran; listening 55s and 53s after. On every image a restart on the same store kept the open session (the next command permitted from the same `ctx_id` on the three that authorize commands) and refused a token minted before it `token_not_found` (purged). Listening again takes the lost hold's lease (60s) to expire, then a third of `hold_ttl`. A `--bump-revision` restore under a running port49d (`L35-restore-arista_eos.md`, `-cisco_nxos.md`, `-cisco_iosxe.md`) found the ledger dropping the next login's write, fixed in 79812ef |
| **L36** | On etcd, whether a live Junos session's re-authorization (`authorization-time-interval`, 15 min) after a port49d restart is answered from the context the store kept, and whether a denial then ends the session. | The operator note on Junos re-authorization on etcd (plan 7d), and §15 L17's note on a restart's denied re-authorization | vJunos-router, vSRX | closed — measured 2026-10-04; tests/lab/results/L36-juniper_vjunos-router.md, L36-juniper_vsrx.md (run at 20fb9fa from a pinned worktree). Both images, `authorization-time-interval 15`, B stopped, A restarted: the device re-authorized the open session 15m0s after its login (14m59s after the restart), and A answered `PASS_ADD` from the context the store kept (`permit context_matched`); the session ran on. A second session logged in and revoked at once (`port49 revoke --principal` on the broker) was denied at its first re-authorization, 15m0s after its login: `AUTHOR` `FAIL` in 1ms, record `deny credential_revoked`; the device did not end the session, and the session's next `show version` printed an 83-byte error (first line `^`) on both images. On vJunos-router's first run (0cff0d0; `L36-juniper_vjunos-router.md`, "Earlier run", one observation, capture not kept) a session revoked after its first re-authorization sent no second request in 20 minutes; L40 is open on whether a second ever comes |
| **L37** | On the split deployment (plan 7e; two port49d replicas and port49-broker on one etcd, each device listing both replicas as TACACS+ servers): whether a session opened through one replica has its next command answered by the other once the first stops; whether, with every broker stopped, an open session runs on and a token minted before the stop logs in; whether a revocation made on port49-broker denies the session's next command on either replica; and how long after its store hangs a port49d with no hold closes its listeners. | The failure model's "Broker unavailable" and store rows on the split deployment (design §12), and decision 36 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | closed — measured 2026-10-04; tests/lab/results/L37-arista_eos.md, L37-cisco_nxos.md, L37-cisco_iosxe.md, L37-juniper_vjunos-router.md, L37-juniper_vsrx.md (EOS, NX-OS and IOS-XE run at 2a74f88, the Junos images at 20fb9fa, from pinned worktrees). With A stopped the device tried B and B answered the open session from the context A wrote (`permit`, the same `ctx_id`, `AUTHOR` `PASS_ADD` in 3ms) on vEOS, the N9Kv and the C8000V, after one refused connection to A (two on the C8000V); on Junos the question does not arise: an open session's command sent no TACACS+ at all (`L37-juniper_*.md` cell 2, the device opened no connection; a device fact, decision 21). A fresh login through B with A stopped was measured instead and logged in (`token_redeemed`, `permit context_matched`). Whether a Junos re-authorization for a session A wrote is answered by B is unmeasured. With the broker stopped the open session ran on and a token minted before the stop logged in on all five (`token_redeemed`). A revocation on port49-broker denied the session's next command `credential_revoked` on A and on B on vEOS, the N9Kv and the C8000V; on Junos, which authorizes no command, a token minted before it was refused on B (`token_not_found`: the revocation deleted it). On a hung store each port49d said its circuit open 43–50s in and closed its listeners 1m43s–2m0s in (circuit open to dark 59.9s–1m10s), inside the 125.5s bound the configuration gives, and break-glass then logged in on every image. Idle, the probe is what opens the circuit (5 failed pings, hold_ttl/6 apart), so an idle port49d goes dark in about 2 minutes at `hold_ttl` 60s; under load it should be about `hold_ttl` plus a probe period, which is derived from the guard's rule and not measured. That gap is plan 7f's. The L35 re-check on vEOS with the second server removed matched L35's step-3 cells (appended to L37-arista_eos.md) |
| **L38** | On IOS-XE, whether an open session's command runs under local authorization once port49 is unreachable, by the command (`show privilege`, `show version`) and by what port49 answered before it went away (nothing; a `FAIL store_unavailable`): `quarantine-cisco_iosxe.md` ran `show privilege` with port49d stopped, and `L35-cisco_iosxe.md` refused `show version` once port49d went dark on a hung store. | Design §12's IOS-XE cells for a store outage and an unreachable port49 | IOS-XE | closed — measured 2026-10-04; tests/lab/results/L38-cisco_iosxe.md (run at 2a74f88 from a pinned worktree). With both port49d replicas stopped, an open session's `show privilege` and `show version` were refused `% Authorization failed.` in both orders and in both columns, after a permit and after a `FAIL store_unavailable` (confirmed by a record and on the wire), so neither the command nor what came before changes the answer; the device opened three connections per command, every one refused, and sent no payload. Why `quarantine-cisco_iosxe.md`'s `show privilege` ran is unexplained: L38 rules out the command and the session's last answer, at the same privilege level (15) |
| **L39** | Whether port49d sees a device's true source address in each deployment shape: (a) Docker with a published port, with the userland proxy on and off; (b) Kubernetes behind a Service with `externalTrafficPolicy: Cluster` and with `Local`; (c) Kubernetes with host networking. Measured by the device-binding check passing or failing for a known device. | Design §13's source-address requirement, applied to plan 12's deployment shapes (roadmap, Plan 12) | any one device platform per shape; the observation is the server's, not the device's | open — (a) measured 2026-10-05, on vEOS-lab 4.31.2F (image tagged 4.32.2F) through deploy/compose (plan 7f), Docker 29.1.3, the device on the clab management bridge and port49d published on its gateway address, with the clab network's own masquerade of its subnet kept off the device's traffic (a RETURN rule, modelling a device off the host): tests/lab/results/L39-docker-proxy-on-arista_eos.md, tests/lab/results/L39-docker-proxy-off-arista_eos.md. With the userland proxy on, and with `userland-proxy: false`, port49d saw the device's own address (172.100.100.11) as the source and the redeem passed `token_redeemed`; in both modes the kernel's DNAT carried the connection (the capture keeps the device's sequence number and source port), and docker-proxy carried none, so a connection docker-proxy relays is unmeasured. A first run without the RETURN rule saw the compose gateway in both modes; that was the lab's own masquerade, not the published port, and is recorded in the notes as invalid. A device on another host is modelled, not measured. (b) and (c), Kubernetes, are plan 12's |
| **L40** | On Junos, whether `authorization-time-interval` re-authorizes a session more than once: after the first re-authorization (`L36-*.md` saw one, 15 minutes after login), whether a second request comes one interval later, and so whether a revocation made after the first reaches the session. | The operator note on Junos re-authorization on etcd (plans README, plan 7d's notes) and §15 L36 | vJunos-router, vSRX | open — added 2026-10-04 (plan 7e Task 17 review; L36 measured only the first re-authorization after login) |
| **L41** | On the compose deployment (decision 37), what a device does when port49d closes its TACACS+ listener mid-session on its store health checks, beside port49d stopped: how long after the store hangs an idle port49d closes it (against `close_after` × `interval` + `call_timeout`); an open session's next command once it is closed, and with port49d stopped; break-glass once it is closed; once the store returns, how long until port49d listens again (after `open_after` passes) and until the device asks it again; and whether the session's next command port49d is asked is answered from the context the store kept. | Decision 37's defaults and design §12's store rows (the go-dark timing and what follows it) | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | closed — measured 2026-10-05; tests/lab/results/L41-arista_eos.md, L41-cisco_nxos.md, L41-cisco_iosxe.md, L41-juniper_vjunos-router.md, L41-juniper_vsrx.md (run at 9620e03 from a pinned worktree). Dark time after the hang: EOS 5.5s, NX-OS 5s, IOS-XE 5.3s, vJunos-router 5s, vSRX 4.8s, 4.8–5.5s, at or inside decision 37's 5.5s (read by a 250ms poll of port49d's followed `docker logs` from the moment `docker compose pause` returned, so ±~0.25s; the test failed only above its 10.5s harness bound). Cell 3 beside cell 7: the open session's `show version` ran on EOS, NX-OS and both Junos images and was refused `% Authorization failed.` on IOS-XE, identically with the listener closed and with port49d stopped. Break-glass logged in with the listener closed on all five and with port49d stopped. Time to listening: 3.5s after the release on every image (the `open_after` passes said at the same moment). Until asked again: EOS 100ms, NX-OS 800ms, IOS-XE 300ms after listening, answered from the kept context (same `ctx_id`, `permit`); vJunos-router and vSRX send no command, a fresh login 300ms after listening succeeded |
| **L42** | Nested-group resolution, per directory. The fixture: a user three levels below a granted group (`alice` ∈ `g-leaf` ∈ `g-mid` ∈ `netops-oncall`), a loop (`dave` ∈ `g-loop-a` ∈ `g-loop-b` ∈ `g-loop-a`), and a user in the granted group directly (`carol` ∈ `netops-oncall`). For each user: which groups a search under the groups base returns with `member:1.2.840.113556.1.4.1941:=<user DN>` (`in_chain`), whether that search answers, errors or is refused on the loop, and how long it takes; whether the user entry's `memberOf` lists only its direct groups; what port49's `recursive` walk and `direct` read return; and whether a directory that does not implement the matching rule refuses the filter or answers it empty. | `broker.directory.nested_groups` and its three modes (§13 decision 38); design §10's "`memberOf` is not transitive" | OpenLDAP (slapd 2.5, `memberof` overlay), Samba AD (4.17) | closed — measured 2026-10-05; tests/lab/results/L42-openldap.md, tests/lab/results/L42-samba_ad.md |
| **L43** | Which bind mechanisms each directory accepts from port49-broker, and how each refusal reads: SASL EXTERNAL over LDAPS with a client certificate (OpenLDAP mapping it by `olcAuthzRegexp`); GSSAPI with a keytab and no SASL security layer, over LDAPS (Samba AD's KDC); simple bind over LDAPS; and a simple bind over plain LDAP to a directory configured to require TLS. | `broker.directory.bind` (§13 decision 38); design §10's three mechanisms | OpenLDAP (EXTERNAL, simple), Samba AD (EXTERNAL, GSSAPI, simple) | closed — measured 2026-10-05; tests/lab/results/L43-openldap.md, tests/lab/results/L43-samba_ad.md |
| **L44** | The Active Directory claims on a Windows DC: on L42's fixture and its loop, which groups `member:1.2.840.113556.1.4.1941:=<user DN>` returns and how the loop is answered; SASL EXTERNAL with a client certificate (over StartTLS, where a DC maps it, and over LDAPS, where it is rejected); GSSAPI with a keytab and no SASL security layer against the Windows KDC; whether `altSecurityIdentities` values written in port49's `X509:<I>{issuer}<SR>{serial}` form (issuer from the raw DER, `DC=` included) match the certificate the DC itself maps; whether the SID extension's value equals `objectSid`; and how KB5014754's strong-mapping enforcement treats each. | `broker.directory.nested_groups: in_chain`, the strong mappings `issuer_serial` and `sid`, and `broker.directory.bind` on AD (§13 decision 38) | Windows Server AD (Windows Server 2025 Standard Evaluation, build 26100.32230) | closed — measured 2026-10-07; tests/lab/results/L44-windows_ad.md |
| **L45** | The back-channel logout token a provider sends to port49's `/v1/logout`, per way a session ends: an RP-initiated logout at the provider's end-session endpoint, an administrator signing a user out of every session, and an administrator ending one session. For each: the JWS header (`alg`, `kid`, `typ`); which of `iss`, `aud`, `azp`, `iat`, `exp`, `jti`, `sub`, `sid`, `events` it carries, and that `nonce` is absent; whether its `sid` and its `sub` equal the ID token's; one token per session or per user; the request's content type; and what the provider does when the answer is 503, or 400, or the connection is refused (retry or not, the end-session endpoint's own answer, and how it reports the failure). | `POST /v1/logout`'s validation and answers, a logout by `sid` reaching the context the ID token authorized, and a logout by `sub` finding the owner record the ID token's `sub` wrote (§5.1.4; §13 decision 39 rulings 12 and 13, provisional on this row) | Keycloak (26.x) | closed — measured 2026-10-07; tests/lab/results/L45-keycloak.md, tests/lab/results/oidc-e2e-arista_eos.md. Measured on Keycloak 26.4.7. Ruling 12 holds: `iss`, `aud`, `iat`, `exp` (`iat`+120s), `jti`, `sid`, `sub`, `events` present, `nonce` absent, `typ` `logout+jwt`, form-encoded; `events` also carries Keycloak's `revoke_offline_access: true`. An RP-initiated logout and an administrator ending one session each send one token whose `sid` and `sub` are the ID token's. An administrator signing a user out of two sessions sent one token naming one session's `sid` and the user's `sub`, so ruling 13's sid-first logout left the other session; ruled 2026-10-07 that a token carrying both `sid` and `sub` is also a logout by `sub`. The follow-up run (oidc-e2e-arista_eos.md, cells 6a–6e) measured it: the one token wrote a revoke by `sid`, then by `sub`, and both sessions' ID tokens were refused `credential_revoked`. Its burst recheck (7a–7e) had eight administrator session ends sent back to back all reach the broker, a revoke by `sid` for each within 30s. A 503, a 400 and a refused connection each got one request and no retry; the end-session endpoint answered 302 in every case |
| **L46** | Fresh authentication on a provider: with an SSO session live, whether a plain second authorization request reuses it (no credentials asked, `auth_time` unchanged: the control); whether one with `prompt=login` makes the person enter their credentials again; whether the new ID token's `auth_time` is the new authentication's; whether it carries the request's `nonce`; whether its `sid` is the old session's or a new one; and beside it, what a refresh-token grant's ID token carries (`auth_time` unchanged, `nonce`, `sid`); and `max_age=0` against `prompt=login`. Also: the ID token's `preferred_username` for a user created with a bare username; and which of `auth_time`, `sid`, `nonce`, `scp`, `amr`, `idtyp`, `azp`, `client_id` and `sub` a client-credentials access token carries, beside a person's access token from the same realm (a delegated one). | The OIDC refresh (§5.6; §13 decision 39 ruling 15, provisional on this row); spec §5.6's "the identity provider will correctly report the *original* `auth_time`"; ruling 21's delegated-token markers and pinned `sub`; the Keycloak example in ruling 23's rationale | Keycloak (26.x) | closed — measured 2026-10-07; tests/lab/results/L46-keycloak.md. With an SSO session live a plain login reused it (no password, `auth_time` and `sid` unchanged); `prompt=login` and `max_age=0` each asked for the password, moved `auth_time` forward and echoed the request's `nonce`, keeping the `sid`; a refresh-token grant kept the last authentication's `auth_time` with no `nonce`. `preferred_username` for `alice` is `alice`. The client-credentials token carries none of `auth_time`, `sid`, `nonce`, `scp`, `amr`, `idtyp`, `client_id`; its `azp` is `port49-svc` and its `sub` the service account's fixed id |
| **L47** | L45's and L46's claims on hosted providers, and their access tokens' `azp`, `aud` and `sub` under the client-credentials grant. For Microsoft Entra ID also: a v2 access token's `aud` (the application's GUID, or its `api://` URI); whether an ID token carries `email_verified` (if not, `principal_claim: email` refuses every Entra person); and the `idtyp` and `scp` claims an app-only and a delegated access token carry. | As L45 and L46, for hosted providers; `app:` + `azp` and the delegated-token refusal (§13 decision 39 rulings 6 and 21) | Microsoft Entra ID, Okta | open — added 2026-10-06 (plan 7h); needs a tenant each (OR-3) |
| **L48** | A workload CA's behaviour with port49's workload verifier (plan 8). On step-ca: whether a certificate requested for a SPIFFE ID carries it as its one URI SAN, with `clientAuth`, not a CA; whether `step ca renew` keeps the ID and the key and changes the serial, and port49 mints for the renewed certificate with no change; when `step ca renew --daemon` renews, as a fraction of the lifetime; with step-ca stopped, whether port49 mints until `NotAfter` and refuses after, and when the late-renewal line comes; whether step-ca's CRL (`crl.enabled`) is DER, issued by the intermediate, and loaded by port49's `certificate_status` over https with the broker trusting step-ca's root (`SSL_CERT_FILE`), and whether a `step ca revoke` reaches port49 within `refresh_interval` and stops a renewal of the revoked certificate; whether a provisioner's x509 name policy allowing one URI refuses a request for another SPIFFE ID. | §13 decision 40 rulings 7–9 (ruling 7's revisit condition); the workload anchor's recommended placement (the intermediate); the README's advice to restrict the provisioner to the host's own ID | step-ca | closed — measured 2026-10-08; tests/lab/results/L48-step_ca.md. Measured on step-ca 0.30.2: the requested SPIFFE ID is the leaf's one URI SAN (with `serverAuth` beside `clientAuth` in step's default template); renew keeps the ID and the key with a new serial; `step ca renew --daemon` renewed at 0.66 of a 15m lifetime; with the CA down the late-renewal warning came at 0.79 (30s polls) and minting stopped at expiry, exit 77. step-ca's CRL carries a critical issuing distribution point naming its own URL and its default leaves no CRL distribution point, so a default leaf is undecided (503) and a leaf under `examples/oxidized/step-ca-workload.tpl` was refused `credential_revoked` 1m after `step ca revoke` (§13, decision 40, ruling 17). No step-ca name policy pins one SPIFFE ID: the provisioner's x509 `allow` was ignored, the authority's refuses a full URI at start; a fixed-`uris` template pins it by rewriting the request |
| **L49** | Oxidized as the day-one consumer of minted tokens (plan 8): the commands each model (`eos`, `nxos`, `ios`, `junos`) sends at login and during a backup, as port49 receives them; whether Oxidized reads a node's username and password from its CSV source at each `/reload` and uses them at the node's next run (`/node/next/<node>`); with a token past its TTL, how many authentications one node's run costs and what Oxidized records; that no token appears in Oxidized's log at its default level; and that a backup made with a minted token holds the device's configuration, the decision log naming the workload's principal. | `examples/oxidized` (the role and the wrapper's REST calls; §13 decision 40 ruling 13) | EOS, NX-OS, IOS-XE, Junos (vJunos-router, vSRX) | closed — measured 2026-10-08; tests/lab/results/L49-oxidized-arista_eos.md, L49-oxidized-cisco_iosxe.md, L49-oxidized-cisco_nxos.md, L49-oxidized-juniper_vjunos-router.md, L49-oxidized-juniper_vsrx.md. Oxidized 0.37.0 on all five: one authentication per run, a stale token refused in one (`token_spent`), the credential read at `/reload`, no token in Oxidized's log. vEOS offers no `password` method, so the example sets `keyboard-interactive` for the `eos` model alone. The example's role lacked `show vtp status` (ios) and `show inventory all` (nxos), now added. On Junos under set 1.0.0 a backup asks port49 about no command. Not measured: a level below `admin` |
| **L50** | Who can write the directory attribute a workload certificate's directory mapping reads (plan 8b; §13 decisions 16, 40 ruling 5 and 41 ruling 10): on Windows AD and on Samba AD, for a service account's entry in its own OU, and for each of `uid`, `description`, `wWWHomePage` and `url` holding a SPIFFE ID, whether the entry itself (`SELF`), a member of Account Operators, a delegated OU administrator ("create, delete and manage user accounts" on the OU) and an ordinary domain user can write it, under the default ACLs and under a candidate ACL plan 8b's docs might prescribe once this row closes (an inherited deny of write on that attribute on the OU for each writer that is not a domain administrator); and whether each write, accepted or refused, is in the directory's audit log as installed and with directory-change auditing turned on. Until it closes, no doc asserts who can write it (rule 1). Row text sharpened by plan 8b, 2026-10-09. | §13 decision 41 ruling 10 (the docs' ACL for the mapping's attribute) | Windows Server AD (L44's box), Samba AD | closed — measured 2026-10-09; tests/lab/results/L50-windows_ad.md, L50-samba_ad.md. Windows Server 2025 and Samba 4.17 alike: an ordinary user writes none of the four; `SELF` writes `wWWHomePage` and `url` whatever the OU's ACL; Account Operators write all four whatever it; a delegated OU administrator writes all four, and under the OU deny adds an allow for itself on the entry and writes (owning the entry alone does not). Neither directory logs a write as installed; with directory-change auditing on, both do. Decision 41 ruling 10 records what the docs say. |
| **L51** | What an SSH client offering several public keys before the password does to a port49 login (raised by the owner from production NX-OS experience): on each platform, whether each refused key counts against the device's SSH authentication-attempt limit (NX-OS `ssh login-attempts`, Junos `retry-options`, IOS-XE `ip ssh authentication-retries`, EOS's), how many keys an OpenSSH client with a loaded agent can offer before the password prompt never comes, whether a refused key reaches port49 as any TACACS+ exchange, whether the refusals lock the user or the source out afterwards and for how long, and which client-side settings (`IdentitiesOnly yes`, `PubkeyAuthentication no`, `PreferredAuthentications keyboard-interactive,password`) and device-side settings avoid it. Until it closes, the docs give no advice on it. | The operator docs for typing a minted token at an SSH password prompt (plan 13), the agent's and `port49 workload`'s guidance, and Oxidized's SSH settings (`examples/oxidized`) | NX-OS (first), EOS, IOS-XE, vJunos-router, vSRX | closed — measured 2026-10-09; tests/lab/results/L51-cisco_nxos.md, L51-arista_eos.md, L51-cisco_iosxe.md, L51-juniper_vjunos.md, L51-juniper_vsrx.md. OpenSSH 10.2p1 client. Every refused key counts as one attempt and sends no TACACS+; the password prompt never comes at 3 keys on NX-OS 10.4(2)F (`ssh login-attempts`, default 3), 4 on IOS-XE 17.13.01a (`ip ssh authentication-retries`, default 3), 6 on EOS 4.31.2F, and 2 × `retry-options tries-before-disconnect` on vJunos-router and vSRX (6 at the default). An agent certificate is two identities. On defaults no lockout follows. A login ban changes that: IOS-XE `login block-for` counts each refused key and blocks the source address, every user and break-glass included, for its period; NX-OS `aaa authentication rejected ... ban` does not count refused keys but bans a username after wrong tokens, the correct token refused at the device with no TACACS+ and no device log line. `PubkeyAuthentication no`, `IdentityAgent none` (on-disk default keys are still offered) and `PreferredAuthentications keyboard-interactive,password` each reach the prompt first try on all five, scoped by `Host`/`Match host`; each disables certificate login for those hosts. A `CertificateFile` with no `IdentityFile` under `IdentitiesOnly yes` offers the certificate alone, one attempt; adding the key's `IdentityFile` makes it two. |
| **L52** | Why a C8000V running IOS-XE 17.13.01a intermittently skips its TACACS+ method for SSH logins (found during L51, Addendum B of tests/lab/results/L51-cisco_iosxe.md): about four good logins, then 40–55 s in which `aaa authentication login default group port49 local` falls straight to `local` with no connection to port49d, `show tacacs` reporting the server alive with no timeouts, and repeating; unchanged without `single-connection`, without `ip tacacs source-interface`, without accounting, and with no keys offered. Whether it reproduces on another IOS-XE image or a hardware platform, and what the device's AAA state is during a failure window. Until it closes, the docs say only what the operator sees (a valid token refused, nothing in port49's log, `SSH2_USERAUTH` for `User ''`) and must not attribute it to port49 or to IOS-XE generally. | The operator docs' IOS-XE troubleshooting (plan 13) | IOS-XE (C8000V 17.13.01a first) | open — added 2026-10-09 |
| **L53** | The SSH host key each platform presents to `port49 devices trust`'s scan (plan 9a), and what the scan does to the device. The key: the host-key algorithm negotiated with a client offering every algorithm `x/crypto/ssh` knows but DSA, which OpenSSH 10 cannot use; whether a console command shows the same key or a fingerprint of it, which command, and in what form (OpenSSH base64, SHA-256, hex DER, MD5), so an operator can verify it out of band; whether the key is the same after a reload with the configuration saved, the device shown to have gone down and come back. The scan, a key exchange abandoned before authentication: whether it reaches port49 as any TACACS+ exchange, writes a device log line, or counts against the device's login-attempt or ban limits (IOS-XE `login block-for`, NX-OS `aaa authentication rejected`: a limit of two failures set, three scans, then a login; valid only where a control of two refused logins does trip the limit). | §13 decision 42 rulings 9 and 12; the operator docs' "verify the key on the console" (plan 13) | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | closed — measured 2026-10-09; tests/lab/results/L53-arista_eos.md, L53-cisco_nxos.md, L53-cisco_iosxe.md, L53-juniper_vjunos-router.md, L53-juniper_vsrx.md. The scan gets an RSA key (key type `ssh-rsa`, the key `port49 devices trust` pins) signed with `rsa-sha2-256` on all five, read off the wire against the scan's own offer. Every platform shows that key on a privileged console: EOS `show management ssh hostkey rsa public` and Junos (both) `file show /etc/ssh/ssh_host_rsa_key.pub` as an OpenSSH base64 blob; NX-OS `show ssh key` as the blob and a SHA256 fingerprint; IOS-XE `show ip ssh` as an OpenSSH (SECSH) blob and `show crypto key mypubkey rsa` as hex DER. Only NX-OS prints a SHA256 fingerprint and none prints MD5, so on the other four the operator compares the key, or runs `ssh-keygen -lf` on it. The ed25519 and ECDSA keys the EOS and Junos consoles also show are other keys, not the one scanned. The key is unchanged after a reload with the configuration saved: each device was seen down (no SSH banner) and back, and its uptime (EOS, IOS-XE, NX-OS) or boot time (Junos) shows it rebooted. A scan reaches port49 as no TACACS+ packet and no decision record on any platform, where the good `port49 ssh` login's window on the same count holds 120 to 270 packets. It does not count against IOS-XE `login block-for` or NX-OS `aaa authentication rejected` (each limit's control, two refused logins as the same user, did trip it, so the measurement holds); no other limit was measured. The device's log: each log was first shown to record a refused SSH login as a user that does not exist (the control), and lines are credited to the scan only by their own stamp inside the scan's window. By that: EOS writes `sshd: Connection closed by <scanner> port N [preauth]` to `/var/log/secure`; `show logging` does not record a refused login either, so it showed none; IOS-XE writes `%SSH-4-SSH2_UNEXPECTED_MSG`, `%SSH-5-SSH2_SESSION ... Failed` and `%SSH-5-SSH2_CLOSE` for a session with no user; vJunos-router and vSRX write the same `sshd ... Connection closed by <scanner> port N [preauth]` to `messages` (the lab config's `system syslog` stanza); NX-OS's logfile gains no line, and it does log the control. The IOS-XE `SSH2_USERAUTH: User ''` line is a refused login, not a scan (L52's signature). In the 2026-10-09 run set (harness commit `0a5e9d3`) all five passed their first run. The first vJunos-router run on the earlier harness commit `74ec202` did not serve SSH within 8 minutes of its reboot (the rerun passed; the cause was not investigated; not seen since). |
| **L54** | `port49 ssh` against each platform (plan 9a): which authentication method the device takes under `PreferredAuthentications keyboard-interactive,password` with public-key authentication off; that ssh's prompt for it names `<username>@<device>`, so port49's askpass answers it once and the login succeeds at the first try; that a command after `--` runs and its exit status is `port49 ssh`'s; that a pinned key the device does not hold is refused by ssh before any TACACS+ exchange, with the minted token never presented. | §13 decision 42 rulings 10 and 11 | EOS, NX-OS, IOS-XE, vJunos-router, vSRX | closed — measured 2026-10-09; tests/lab/results/L54-arista_eos.md, L54-cisco_nxos.md, L54-cisco_iosxe.md, L54-juniper_vjunos-router.md, L54-juniper_vsrx.md. On all five, `port49 ssh <device> -- show version` exits 0 with the output present; ssh tries `keyboard-interactive` once, the askpass is asked once and answers it, and port49d records one redeem. A pinned key the device does not hold is refused by ssh (`Host key verification failed`, exit 255) before any TACACS+ exchange: 0 TACACS+ packets (the good login's window on the same count holds 120 to 270) and no decision record but `mint` and `blob`, the token never presented. No platform ended a command that ran with exit 255, so the 255 message's policy wording needed no per-platform change. |
| **L55** | Keycloak as port49's public client meets it (plan 9b). **The redirect:** for port49-cli registered with `http://127.0.0.1:18749/callback`, `http://127.0.0.1/callback`, `http://127.0.0.1/*` and `http://127.0.0.1:*/callback` in turn, whether the admin API takes the registration and whether an authorization request naming `http://127.0.0.1:<port>/callback` is accepted (the login form shown) for the registered port and an ephemeral one (RFC 8252 §7.3), against a matcher seen to accept the realm's own redirect and refuse another host's. **PKCE:** with `S256`, on port49-cli as the realm file sets its `pkce.code.challenge.method` (recorded), whether a code exchanged with the right verifier, a wrong one and none is answered, and with which `error`; whether `code_challenge_method=plain` is accepted. **Discovery and the answer:** `code_challenge_methods_supported`, `authorization_response_iss_parameter_supported`, and whether the authorization response carries `iss` (RFC 9207). **The key binding:** whether a 43-character base64url `nonce` comes back in the ID token byte for byte, and whether a `prompt=login` sign-in's `auth_time` is within 10s of the sign-in. **`prompt=login` over a live SSO session:** in one browser, a sign-in with no `prompt`, then 15s later, the control, the same session with no `prompt` (whether the form is shown, and `auth_time` against the first), then a `prompt=login` sign-in (whether the form is shown, and whether `auth_time` moves on by 15s or more). | §13 decision 43 rulings 1, 3, 4 and 8; the operator notes' redirect registration (plan 13) | Keycloak (26.x) | closed — measured 2026-10-11; tests/lab/results/L55-keycloak.md. Measured on Keycloak 26.4.7 (a loopback authorization request with the realm's own redirect accepted and another host's refused, so the matcher is shown). The redirect: `http://127.0.0.1:18749/callback` admits port 18749 and refuses 41587; `http://127.0.0.1/callback` and `http://127.0.0.1/*` admit both; `http://127.0.0.1:*/callback` admits neither. PKCE: port49-cli's `pkce.code.challenge.method` is `S256`; the right verifier gets `200` with an `id_token` and `refresh_token`, a wrong one and none each `400 invalid_grant`, and `code_challenge_method=plain` is refused. Discovery lists `[plain S256]` and `authorization_response_iss_parameter_supported: true`, and the authorization response carries `iss`, the issuer. The key binding holds: a 43-character `nonce` came back byte for byte and `auth_time` was +0s from the sign-in. Over a live SSO session the control (no `prompt`, 15s later) showed no form and kept the first `auth_time`, while `prompt=login` showed the form and moved `auth_time` on by 15s. Not measured: a client set to require no PKCE method. |
| **L56** | Port49-issued certificates end to end on Keycloak and one device (plan 9b), with the real `port49` CLI. Whether: a broker started with `broker.identity.issuance` and no issuing CA says in `/v1/config` `issuance.available: false`, the CLI says before any sign-in that the broker cannot issue, its log names `init-issuer`, and after `port49-broker init-issuer` and a restart issues; `port49 login --oidc --no-browser` signs in through a scripted browser, asks the password, writes a 0600 key and its certificate, names the principal, starts the agent and refreshes once; `port49 token` mints and the device takes the token over SSH; `port49 refresh` extends the device session with no sign-in; `port49 login` after the agent stopped starts a new one with no sign-in and extends the device session; `port49 login --sign-in` at a terminal, the address pasted, issues a new certificate; an administrator's sign-out refuses the certificate's next mint in the broker's logout words and ends the agent, a `port49 login` over that certificate removes it, and a sign-in from the time the broker names works; with Keycloak stopped, `port49 token`, `port49 refresh` and a new agent over the held certificate work, and `port49 login --sign-in` says the provider did not answer and when the held certificate ends. No compact JWS, code or private key in the CLI's raw output or the agent's log (the PKCE verifier, which port49 draws and the lab never sees, is checked by the unit tests' `credentialsNowhere`). Each cell's assertion has a control that shows it can fail. | §13 decision 43 rulings 5, 8, 11, 12, 14, 16, 17 and 20; the operator notes (plan 13) | Keycloak (26.x); EOS | closed — measured 2026-10-11; tests/lab/results/L56-arista_eos.md. Measured with `bin/port49` on the compose stack, Keycloak 26.4.7 and vEOS 4.31.2F. With no issuing CA the CLI said "the broker cannot issue certificates now (its issuing CA is unavailable); tell its operator" before any sign-in (no password form was shown; the broker's 503 `issuance_unavailable` for an exchange is unit-tested), and the broker's start named the missing CA and `init-issuer`; after `init-issuer` and a restart `port49 login --oidc --no-browser` signed in (the password asked, a control with no `prompt=login` showed no form), wrote the 0600 key and certificate, named `user:alice@corp.example.com`, started the agent and refreshed once (`refreshed at`). `port49 token` was taken by the device over SSH (a token port49 never minted refused); `port49 refresh` extended the device session with no sign-in; `port49 login` after the agent stopped used the held certificate, and `port49 login --sign-in` with the address pasted issued a new one. An administrator's sign-out refused the certificate's next mint in the broker's logout words, ended the agent and removed the certificate at the next `port49 login`, and a sign-in from the named time worked. With Keycloak stopped, `port49 token` (taken by the device), `port49 refresh` and a new agent worked, and `port49 login --sign-in` said the provider did not answer and that `port49 login` without it uses the held certificate, valid until the time it names. No compact JWS, code or private key was in the CLI's raw output, the agent's log or the broker's logs. |
| **L57** | What a Junos configuration capture carries for configuration groups that reach port49's template classes. Under `show configuration \| display set \| display inheritance`, and the other order (`\| display inheritance \| display set`), against plain `display set`: whether a group applied at the top by `apply-groups` is expanded under `system login class p49-remote` for a `<*>` and a `<p49-*>` path; whether `apply-groups-except` at the class keeps a group's statements off it; whether a group applied from inside another group's definition commits, and is expanded; whether the `apply-groups` and `set groups` lines still print in the inherited capture; whether a class's own leaf (`idle-timeout`) stands over a group's; whether a group's `permissions` is added beside a class's own (a leaf-list). Whether a group applied on the class itself (class-level `apply-groups`) keeps that line in the inherited capture. And whether a TACACS+ session landing in `remote` holds what a nested group added (the nested-group session cell: `show cli authorization`, read only beside a `show configuration system host-name` control that printed the host name and a same-run `Current user` control under a class holding its own `view`). | `port49 devices check-config`'s group reading (§12; decision 44 rulings 7 and 9): which lines it trusts as expanded, and when it refuses a capture as not inherited | Junos (vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15) | open — added by plan 9b1 |
| **L58** | The two Junos baseline words a readonly's set 1.2.0 reply rests on, under the factored deny set 1.2.0 renders, one alternative naming both words (`^ *(save\|junoscript)( .*)?` and the pipe tail), each against a control with the same class and no deny (`permissions view`; the `save` cells `permissions all`, with the same candidates also typed under `view` as information). `save`: whether it is a keyword to deny-commands, a `save` command the control runs with `\| count`'s evidence refused under the deny with the caret under `save` (L26b proved it on vJunos-router; on vSRX its control took the hidden `save dhcp-security-snoop` and refused the file name after it, so nothing ran). `xml-mode`: whether bare `xml-mode` (the Junos XML protocol, greeting `<junoscript`) and `xml-mode netconf` are refused under it, where the control is greeted. | Set 1.2.0's keyword tree (`save`); decision 44 ruling 10's `xml-mode **` sent as nothing beside `junoscript **` | Junos (vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15) | closed — measured 2026-10-11; tests/lab/results/L58-juniper_vjunos-router.md, L58-juniper_vsrx.md. `save` proven on both: vJunos-router's control ran `save dhcp-security-snoop /var/tmp/p49-l58.snoop \| count`, vSRX's control's CLI took `save` and stopped after it, and the deny refused it with the caret under `save` on both. Bare `xml-mode` and `xml-mode netconf need-trailer` refused under the deny on both, the control greeted. |

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

  *Unmeasured until 2026-10-01:* the truncation length on any platform — EOS, NX-OS and IOS-XE all
  authorize the command word alone, so no long `server_msg` was ever built.

  The notes these paragraphs cite were replaced by the 2026-10-01 run; their earlier text is at
  `git show 52a81e7^:tests/lab/results/L2-<platform>.md` (the 61-character runs, and the output
  modifiers). The IOS-XE exec-channel finding is in commit b825b52's message, and the first IOS-XE
  note, which read the exec channels as "NOT displayed", is at `git show
  bfe59f1:tests/lab/results/L2-cisco_iosxe.md`.

  **Measured 2026-10-01 by plan 7b Task 12, on all five images.** The lab built the long message
  itself: `lab.deny_message_length: N` pads the denial of `show clock` with `0123456789` repeated
  to N bytes, at N = 64, 128, 200, 255, 256, 512 and 1000, each on a port49d of its own, so the
  last digit shown says where a device cut. On Junos, which authorizes no command, the run denied
  the session authorization instead (`lab.deny_session: true`).

  | Image | Displayed | Truncation |
  |---|---|---|
  | vEOS-lab 4.31.2F (image tagged 4.32.2F) | in full, after the device's `% Authorization denied for command 'show clock':` | none at or below 1000 bytes |
  | IOS-XE 17.13.01a | in full, alone | none at or below 1000 bytes |
  | NX-OS 10.4(2)F | never: the device prints `Error: AAA authorization failed AAA_AUTHOR_STATUS_METHOD=16(0x10)` | cannot be read |
  | vJunos-router 23.4R2-S2.1, vSRX 21.4R3.15 | never: the login reached a prompt at every length | cannot be read |

  `tests/lab/results/L2-arista_eos.md`, `L2-cisco_iosxe.md`, `L2-cisco_nxos.md`,
  `L2-juniper_vjunos-router.md`, `L2-juniper_vsrx.md`. NX-OS agrees with its 2026-09-20 result at
  every length. The Junos rows say nothing about display: a session denial does not stop a Junos
  login (`tests/lab/results/junos-session-service-juniper_*.md`, phase C), so it shows the
  operator nothing to read, and Junos sends no other reply. That clause stays open, and with it the
  row. Break-glass logged in on both Junos images before each length over 255 and after the last.
  *Unmeasured:* truncation above 1000 bytes on EOS and IOS-XE.
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
  **Set 1.1.0's Junos projection, 2026-09-29.** The projection differential (plan 5b Task 19,
  `L12-projection-juniper_vjunos-router.md`, `L12-projection-juniper_vsrx.md`) sent
  `user-permissions`, `deny-commands` and `allow-commands` as set 1.1.0 spells them, in the
  shapes it renders, and both images applied each as spelled. 1.1.0 never renders
  `local-user-name`; plan 5b's Task 2 measured it applied (`L12-juniper_*.md`).
  *Unmeasured:* the attribute sets the other four platforms refuse — only IOS-XE has been probed
  with an attribute it does not know, so whether EOS, NX-OS and Junos merely ignore one or would refuse a
  different one is untested; and every non-SSH transport on IOS-XE.
- **L9** — Junos, vJunos-router 23.4R2-S2.1 and vSRX 21.4R3.15, the two agreeing. 2026-09-25
  (`tests/lab/results/L9-juniper_*.md`, `L9-abbreviations-juniper_*.md`): a deny regex is matched
  against a command's keywords as the CLI expands them, never its arguments (decision 27);
  explicit `^` and `$` with the pipe tail are taken; a malformed `^(show$` opened the session and
  refused the probes; the CLI refuses upper case; a keyword deny refuses every abbreviation, so
  `DenyMatchesExpanded` is true. 2026-09-29 (plan 5b Task 19, `L12-projection-juniper_*.md`):
  the commit checker took, as a login class's own configuration, every wire regex form set 1.1.0
  renders (`^.*$`, allow alternations, one keyword deny, two alternated, and the multi-word
  deny's ` +` alone and alternated), each read back unchanged. Closed on the constructs 1.1.0
  renders; a set, facts or generator change that renders another reopens it.

- **L12** — Junos, both images, the two agreeing. 2026-09-25: `user-permissions` applied over a
  bitless template, per session; each bit's reach, the baseline and `view-configuration`'s
  carve-out; a deny naming an argument not enforced; over NETCONF a native RPC ran past every
  wire deny (`L12-juniper_*.md`, `L12-bits-juniper_*.md`, `L12-configuration-juniper_*.md`,
  `L12-netconf-juniper_*.md`). 2026-09-29, the projection differential (plan 5b Task 19,
  `L12-projection-juniper_vjunos-router.md`, `L12-projection-juniper_vsrx.md`): 21 rule shapes,
  covering every reply set 1.1.0's built-in adapter renders (narrow; capability with bits alone,
  bits short of `all`, one and two keyword denies, and a deny with allows; fail-closed), were
  typed in full, abbreviated, piped and padded. No probe ran that port49 denies or that the
  model says the reply refuses; every shape rendered its expected reply, identically on both
  images; none quarantined the device. It holds with `system services netconf` removed, as
  1.1.0 and `devices check-config` require. Decision 22 is no longer provisional.

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

  **On the memory store, a port49d restart denies every live Junos session's next
  re-authorization.** The denials
  above arrived as `deny context_missing` rather than `service_unsupported`, and the reason is
  worth carrying: switching port49's configuration restarts the daemon, the login context
  store is in memory (`internal/store/memory`), and the contexts do not survive. On a fleet
  with `authorization-time-interval` set, restarting port49d therefore hands every logged-in
  operator a denied re-authorization within the interval. On these images that costs nothing,
  because the denial does not end the session — but that is a measurement, not a guarantee,
  and it is the thing to re-measure before recommending the statement to anyone who has also
  made denials binding. On etcd (plan 7d) the store keeps the contexts across a restart;
  whether a Junos session's next re-authorization is then answered from its context is §15
  L36's (open). L35 measured the open session running on across a restart, not a
  re-authorization.

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
- **L24** — added by plan 5b and measured 2026-09-25 on vJunos-router 23.4R2-S2.1 and vSRX
  21.4R3.15 (`tests/lab/results/L24-juniper_vjunos-router.md`, `L24-juniper_vsrx.md`;
  `tests/lab/junos_bits_test.go`). Two classes carried `idle-timeout 1`; one session landed in
  its class by `local-user-name`, the other by the `remote` template with an empty reply. After
  its prompt each sat idle: the device warned `session will be closed in 10 seconds if there is
  no activity` and then printed `Idle timeout exceeded: closing session`, at 1m0s on both paths
  and both images. So a class's `idle-timeout` binds a session a TACACS+ reply lands in, which is
  what `platform export --classes` writes from `session.max_session_age_default` (decision 21).
  Both images committed `idle-timeout 720` (a 12h `max_session_age`) in plan 5b's Task 19
  (`L12-projection-juniper_*.md`). *Unmeasured:* the largest `idle-timeout` the device takes, so
  an export of a longer `max_session_age` may write a value the commit checker refuses.
- **L26** — added by plan 5b and measured 2026-09-25 (`tests/lab/results/L26-juniper_*.md`,
  trees in `L26-keywords-juniper_*.yaml`; `tests/lab/junos_keywords_test.go`). Over the
  break-glass CLI, `| display xml rpc` showed the RPCs of `show system uptime` and `show version`
  and none of their output, so it runs nothing; the walk then typed only under `show`, the
  prefixes of 17 seed commands first, then every path of up to two words, to four words. Neither
  image stopped at a bound. vJunos-router 23.4R2-S2.1: 136 nodes, 1291 commands, 755 keywords.
  vSRX 21.4R3.15: 118 nodes, 1161 commands, 668 keywords. Nothing under `show configuration` is
  proven, and `show cli`, `show route summary` and `show chassis cluster` (absent on
  vJunos-router) are not proven on both. **Both images were walked twice.** vJunos-router's rerun reproduced its first tree byte for
  byte; **vSRX's runs disagree.** The
  rerun (eb17886) used a classifier that no longer reads `syntax error, expecting <command>:
  <word>` as proof: it dropped `show rsvp interface`, a false keyword the first run proved, so
  `show rsvp` takes an argument; and it proved `show interfaces terse extensive` and `show system
  processes detail`, which the first run left out for a reason its log did not keep. So a keyword
  is one only where every run on every image proves it: `tests/lab/cmd/junos-keywords`
  intersects every committed run (the first vSRX run is kept as
  `L26-keywords-juniper_vsrx.run1.yaml`; its note and capture are as 8dff998 committed them),
  refuses a merge missing any, and lays the L26b overlays over them. The result is
  `platforms/keywords/1.1.0/juniper_junos.yaml`: 528 keywords from the runs and L26b's seven, 535
  in all, frozen with set 1.1.0 by its sha256 (`TestReleasedKeywordTreesAreFrozen`). What it
  proves for the denies this document uses: `deny show configuration **` and `deny show chassis
  hardware **` are keyword denies; §11's `deny show chassis cluster **` is not, since
  vJunos-router offers no `cluster`, so on Junos a composition it meets fails closed; `deny show
  route summary` and a deny naming any `show configuration` hierarchy are argument denies, and
  fail closed too. *Outside what was measured:* a
  hidden argument, one completion never lists; any word outside `show`, but L26b's `set cli` and
  `exit`; and any other release or hardware family.
- **L26b** — added by plan 5b and measured 2026-09-25 on vJunos-router 23.4R2-S2.1 and vSRX
  21.4R3.15 (`tests/lab/results/L26b-juniper_*.md`, overlays in `L26b-keywords-juniper_*.yaml`;
  `tests/lab/junos_keyword_deny_test.go`). L26 proves a keyword by its RPC; this row proves one
  by the property decision 27 is about. In a class holding `all`, a control session ran each
  probe with positive evidence (a `| count` line, `Screen length set to 0`, the session ending
  for `exit`), and a session whose reply denied the word at its path was refused, the CLI's
  caret under the word. Proven on both images: `show cli`, `show host`, `show
  ingress-replication`, `show policy`, `show task`, `set cli` and `exit`. `save` is proven on
  vJunos-router and not on vSRX, where the control's CLI takes a hidden head and refuses the file
  argument, so it is no keyword in the set. **Every `show configuration` hierarchy each image
  offered ran under a deny naming it**, 32 on vJunos-router and 25 on vSRX, and a sentinel `show
  configuration system | count` ran in every session: a hierarchy deny is not enforced, so on
  Junos `show configuration` is denied whole or not at all. The vSRX overlay was re-pinned by code
  to the rerun L26 tree (569c8c2), whose nodes and words it touches are the first run's.
- **L26c** — added by plan 5b and measured 2026-09-25 (`tests/lab/results/L26c-juniper_*.md`;
  `tests/lab/junos_rpc_reach_test.go`); open. From a projected CLI session (class `view`, a
  rendered deny naming `show configuration`), with `netconf ssh` still configured,
  `xml-mode netconf` and `xml-mode netconf need-trailer` open NETCONF inside the session and
  return a hello, on both images, as in the control. There a native RPC the deny did not name,
  `<get-software-information/>`, ran; the deny did bind a `<command>` RPC; and reach is bounded
  above by the bits (`view` alone got an empty `<configuration>`). `op url` was accepted up to the
  copy, with no RPC observed through it. The fail-closed reply's `deny-commands .*` refuses
  `xml-mode` and `op url`. Whether turning the management services off (§8's allowlist) is
  sufficient is **not measured**: no probe ran with only the services the allowlist leaves. Set
  1.1.0 fails closed on a deny beneath a sent bit (option C, `JunosFacts.DenyBindsRPCs` false),
  *provisional on L26c*: the conservative reading, which this row can only relax. It is why a
  broad Junos grant with a deny rarely projects under set 1.1.0; set 1.2.0 sends the `junoscript`
  entry deny instead (decision 44). Measured 2026-09-30 (`L26c-junoscript-juniper_*.md`): a deny
  naming `junoscript` refuses `xml-mode netconf`, `junoscript netconf` and port 830, and a deny
  naming `xml-mode` does not bind. **Open, and not asserted anywhere in this document:**
  whether a native RPC reached this way passes a deny that names what it reads; whether a deny
  naming `op` binds, with abbreviations and through a class's deny
  list; whether the `junoscript` deny closes the XML API (`xnm-ssh`, `xnm-ssl`,
  `xnm-clear-text`) and `outbound-ssh`; whether an RPC reaches past a deny beneath `view-configuration` (this run's `view` class
  cannot say); the SSH exec channel; `scp`. The owner has reported, on SRX hardware (23.4R2-S8.7,
  no capture, `tests/lab/results/L26c-operator-juniper_srx.md`), that `<get-configuration/>` passed a deny of `show configuration`
  beneath `view-configuration`, that a deny of `show version` refused `<get-software-information/>`,
  and that no TACACS+-sent deny naming `xml-mode` refused it; a lab measurement with a capture is
  still owed for each. The run failed four cells since reclassified, and its
  `xml-mode` probes ran before `netconf ssh` was deleted, so a rerun is owed (L26c review I-1,
  I-4).
- **L27** — added by plan 6a and measured 2026-09-30 on beehive, each product's two versions in
  its own Compose stack (`tests/lab/results/L27-netbox.md`, `L27-nautobot.md`; fixtures in
  `tests/lab/sot/fixtures/`, checked by `TestL27FixturesAreWhatTheNotesSay`). Per version: where
  the version is reported, the role field, the GraphQL shape that returned every interface
  address, and whether the webhook signature is HMAC-SHA512 of the body.

  | version | version source | role field | GraphQL shape that returned every interface address | signature HMAC-SHA512 of the body |
  |---|---|---|---|---|
  | NetBox 3.7.8 | `/api/status/` `netbox-version`; `Api-Version: 3.7` | `role` to write; REST reads carry `role` and `device_role`, the same object | `device_list(name: "…") { … role { slug } … }` | yes, 3 of 3 |
  | NetBox 4.7.1 | `/api/status/` `netbox-version`; `Api-Version: 4.7` | `role` only | `device_list(filters: {name: {exact: "…"}}) { … role { slug } … }` | yes, 3 of 3 |
  | Nautobot 1.6.32 | `/api/status/` `nautobot-version`; `Api-Version` is **`1.2`**, not the release | `device_role` (`/api/dcim/device-roles/`), with `site` | `devices(name: "…") { … device_role { slug } site { slug } … _custom_field_data … }` | yes, 3 of 3 |
  | Nautobot 2.4.43 | `/api/status/` `nautobot-version`; `Api-Version: 2.4` | `role` (`/api/extras/roles/`), with `location`; REST at default depth nests every related object as `{id, object_type, url}`, no name, and `?depth=1` inlines them | `devices(name: "…") { … role { name } location { name } … _custom_field_data … }` (no `slug`) | yes, 3 of 3 |

  So the version to pick a profile by is `/api/status/`, never `Api-Version` alone. REST paginates
  with `count`, `next`, `previous` and `results` on all four. Webhooks carry the change in the body;
  NetBox 4.7 drops `model`, `username` and `request_id` for `object_type` and `request`. Delivery
  order is not change order on Nautobot (both versions delivered `deleted` first in this run), so 6b
  orders by the body's `timestamp`, never by arrival. *Unmeasured, split to L30 (owned by plan 6b):*
  a non-null `next` (each run held one device when it paged), and Nautobot 3.x (Docker Hub carries a
  3.2 line the row does not name).
- **L28** — added by plan 6a and measured 2026-09-30 on vEOS-lab 4.31.2F, Nexus 9300v 10.4(2)F,
  Catalyst 8000V 17.13.01a and vJunos-router 23.4R2-S2.1 (`tests/lab/results/L28-arista_eos.md`,
  `L28-cisco_nxos.md`, `L28-cisco_iosxe.md`, `L28-juniper_vjunos-router.md`;
  `tests/lab/l28_test.go`). Each phase restarts port49d with the device still on the lab key and
  compares it with port49d stopped. Three builds were measured:

  | port49d | break-glass plus three commands, `unknown` phase | with port49d stopped | notes |
  |---|---|---|---|
  | holds the miss for the backoff, then closes | EOS 27.4 s, NX-OS 25.2 s, IOS-XE 27.6 s, vJunos-router 5.9 s | 0.39 s, 2.66 s, 1.28 s, 1.48 s | `L28-held-*.md` |
  | closes at once with a FIN | IOS-XE 11.0 s, and 5.02 s to log in (0.02 s stopped): it waits out its own 5 s timeout on the FIN | 1.28 s | `L28-fin-cisco_iosxe.md` |
  | resets at once (as built) | EOS 0.32 s, NX-OS 2.64 s, IOS-XE 1.27 s, vJunos-router 0.47 s | 0.37 s, 2.62 s, 1.28 s, 0.49 s | `L28-*.md` |

  Under the reset, the unknown, retired and expired phases each match the stopped phase on every
  image, and each token login is refused. With the old key accepted beside the new one
  (`retire_after: 2999-12-31`), token logins validate at v1 and the break-glass account is
  refused by port49 on EOS, NX-OS and IOS-XE, which is their configuration asking port49 first;
  vJunos-router logs it in. Given the new key, the device's token login validated at v2 at once,
  and `port49 keys status` over the run's log names the device on v2 and lists its
  unvalidated sources by diagnosis. On IOS-XE the harness's liveness probe before three phases
  reached port49 only at its second or third attempt (30–54 s); why is not established.
  *Unmeasured:* the mid-connection close, split to L29; transports other than SSH; vSRX.
- **L29** — added 2026-09-30 by plan 6a Task 21, split from L28. port49d resets an open connection
  at its first packet past its version's `retire_after`, as it does a first-packet miss (§10), and
  nothing about the device's reaction to that is measured: every L28 phase started port49d with the
  date already past or not yet reached. Measuring it needs a run that holds a connection open across
  00:00:00Z. The final fix wave added the reload case: a reload that refuses, removes, renames,
  re-keys or re-platforms a device resets its open connections at their next packet with no strike
  (§10, "How a daemon refreshes its snapshot"), also unmeasured; a `SIGHUP` between two commands in
  one session measures it. Owned by plan 6b, the next plan with a device lab run.

  **Reworded 2026-09-30** (owner's ruling): the midnight case is dropped. A reset of an open
  connection is the same TCP reset whether a reload or `retire_after` causes it, so the reload
  case measures the device's side of both; that port49d resets an open connection at its
  version's date is tested in code with an injected clock (`internal/daemon/server/server_test.go`),
  and what the strike after it costs the device's next connections is L28's. Plan 6b's
  `TestL29Midnight` stays in `tests/lab/`, gated by `PORT49_L29_MIDNIGHT`, and unused.

  **Measured 2026-09-30** by plan 6b Task 19 (`tests/lab/l29_test.go`, `TestL29Reload`), on the
  four images L28 ran, with single-connection set on each (NX-OS as its `?` allows: `key 0 <key>
  single-connection`, `results/single-connection-syntax-cisco_nxos.md`). Each phase opens a token
  session and runs `show version`, makes the change — a `port49 inventory sync` removing,
  renaming, re-platforming or refusing the device, or a policy edit re-keying it to a key it does
  not hold — waits for port49d's reload line, then runs the command in flight, a second command,
  the next token login, and break-glass plus three `show version`. A phase is a measurement only
  when port49d's `device_unknown` record and the capture both show a connection open at the
  instant port49d applied the reload and reset after it; an idle connection, opened before that
  instant and reset at its first packet after, counts. The reset hit an `author` packet on EOS,
  NX-OS and IOS-XE (two connections per phase on IOS-XE) and an `acct` packet on vJunos-router.

  | image | session | command in flight | second command | next token login | break-glass plus three commands (port49d stopped) |
  |---|---|---|---|---|---|
  | vEOS-lab 4.31.2F | survived | refused in 0.1 s every phase, `% Authorization denied … Unknown role`; EOS did not fall to local for it | refused, but ran on a new connection when re-platformed | refused, 0.5–2.7 s; logged in when re-platformed | 0.32–2.1 s when removed, refused or re-keyed (0.38 s); not let in when renamed or re-platformed |
  | Nexus 9300v 10.4(2)F | survived | ran in 0.7–0.8 s every phase, on a new connection or the fall-through | ran, but refused `AAA authorization failed` when renamed | refused, 1.9–9.9 s; logged in when re-platformed | 2.6 s re-keyed, 17.6 s refused, 40.9 s removed (2.62 s); not let in when renamed or re-platformed |
  | Catalyst 8000V 17.13.01a | survived | refused `% Authorization failed.` after 5.01 s when removed or refused, and in 0.5 s when re-keyed; ran in 0.5 s when renamed or re-platformed | as the first | refused, 4.0–14 s; logged in when re-platformed | 1.5 s re-keyed, 20.6 s refused, 30.1 s removed (1.28 s); not let in when renamed or re-platformed |
  | vJunos-router 23.4R2-S2.1 | survived | ran in 0.2 s every phase: Junos authorizes commands locally by class, so the reset hit accounting only | ran | refused, 5.1–6.6 s; logged in when re-platformed | 0.45–2.1 s every phase, renamed and re-platformed included (0.46 s) |

  Break-glass is not let in where port49d still serves the device under its new name or platform:
  port49d answers it FAIL, which EOS, NX-OS and IOS-XE take as final (L4); Junos with `password`
  listed tries local. Removed or refused, the N9Kv and the C8000V took up to 41 s and 30 s against
  their 2.6 s and 1.3 s with port49d stopped: with single-connection on, the two Cisco images wait
  out their 5 s timeout after a reset that follows their request, and those paths never refused the
  retries at Accept (before fix/breakglass-reset; L31,
  `tests/lab/results/L31-breakglass-cisco-singleconnection.md`; since the fix, 1.3–1.8 s and 2.6 s,
  `L31-cisco_iosxe.md`, `L31-cisco_nxos.md`); re-keyed, a first-packet
  key miss after the reset, they stayed at stopped times, as in L28. The quarantine's 2026-09-24
  runs held a local user's session and these a token user's, so the two are not compared command
  for command. Before two of the six C8000V phases the harness's liveness probe reached port49 only
  at its second or third attempt (30 s, 54 s), as in L28; why is still not established.

  vJunos-router held a connection open across some changes and not others. The evidence is the
  committed note, `L29-reload-juniper_vjunos-router.md` (run at 6fcce47): removed and refused
  measured, and a banner naming the three phases (renamed, re-platformed, re-keyed) in which no
  connection was open across the change — the device's accounting arrived on new connections, or
  the capture and port49d's record disagreed about an idle connection, which does not count — so no
  session could be affected. Three earlier vJunos runs, whose notes were replaced, were observed in
  the lab log to vary run to run in which phases held a connection open; they are not register
  evidence.
- **L30** — added 2026-09-30 by plan 6a's final fix wave, split from L27: its runs each held one
  device, so no list paged and `next` was always null, and Nautobot 3.x was not run. Plan 6c's
  pagination code and any Nautobot 3.x profile cite it until it closes.

  **Measured 2026-09-30** by plan 6b Task 2 on beehive (`tests/lab/results/L30-netbox.md`,
  `L30-nautobot.md`; fixtures in `tests/lab/sot/l30/`, checked by
  `TestL30FixturesAreWhatTheNotesSay`), each version in its own Compose stack with 120 devices,
  read at `limit=50` directly and through an nginx reverse proxy
  (`tests/lab/sot/compose/l30-proxy.conf`, sending the client's `Host` as `Host` and
  `X-Forwarded-Host`, and `X-Forwarded-Proto: https`).

  | version | `next` read directly | `next` through the proxy | `next` to `null` | GraphQL, unpaged | GraphQL paged shape | GraphQL `status` |
  |---|---|---|---|---|---|---|
  | NetBox 3.7.8 | absolute, the dialed scheme, host and port | `https://`, the proxy's host and port; every `results[].url` the same | 3 pages, 50/50/20, 120 once | 120 | none tried: `pagination` and `limit`/`offset` are 400 | `"ACTIVE"` |
  | NetBox 4.7.1 | absolute | as 3.7.8 | as 3.7.8 | 120 | `pagination: {offset, limit}`; `limit`/`offset` is **HTTP 200 with `errors`** and no names | `"active"` |
  | Nautobot 1.6.32 | absolute | as NetBox | as NetBox | 120 | `devices(limit, offset)` | `{"name": "Active"}` |
  | Nautobot 2.4.43 | absolute | as NetBox | as NetBox | 120 | `devices(limit, offset)` | `{"name": "Active"}` |
  | Nautobot 3.2.6 | absolute | as NetBox | as NetBox | 120 | `devices(limit, offset)` | `{"name": "Active"}` |

  Nautobot 3.2.6 answered every L27 question as 2.4.43 did: `/api/status/` `nautobot-version`
  (`Api-Version: 3.2`); `role` and `location`; REST at default depth naming no related object, and
  `?depth=1` inlining them; the `graphql_0` shape (no `slug`), returning every interface address;
  `count`/`next`/`previous`/`results`; webhooks carrying the change, out of change order (arrived
  updated, deleted, created, 3.2–3.4 s after the body's `timestamp`), each signed HMAC-SHA512 of the
  body. Its device drops `cluster` and `software_image_files`, fields L27's seed never set. So no
  separate 3.x profile is indicated by this row. A `next` names whatever host the request arrived
  under, so a connector that follows it verbatim goes where the response says: 6c follows `next`
  only when its scheme, host and port are the configured base's. *Unmeasured, outside the row's
  question:* which of `Host` and `X-Forwarded-Host` the products read (the proxy sent the same value
  in both); following a proxied `next` (only the first page was read through the proxy); a list
  changing between pages; a GraphQL list above any server cap.
- **L31** — added 2026-09-30 by plan 6b Task 21, from an analysis of plan 6b's L29 and
  quarantine-sync captures (`tests/lab/results/L31-breakglass-cisco-singleconnection.md`; flags and
  timings only, no payload). With single-connection on, the TACACS+ header's single-connect flag is
  `0x04` (`0x00` in L28's captures and the 2026-09-24 quarantine runs). A reset that follows the
  device's request is then taken as transient: IOS-XE reconnects and resends every ~200 ms until its
  5 s timeout, and NX-OS waits out ~5 s after each command's accounting, so every AAA exchange in a
  break-glass session costs ~5 s. A reset before the device writes — a refusal at Accept — makes
  both fall through at once. port49d's unadmitted path (`internal/daemon/server/conn.go:237-238`)
  holds the connection for the strike's backoff, up to 5 s, before the reset, and its refused and
  quarantined paths (`conn.go:233-234`, `:261-262`) reset at once but take no strike; none of the
  three refuses the retries at Accept, as the key-miss path does (`conn.go:181`,
  `internal/daemon/server/server.go:119`). The re-key in the same deploy, a key miss, stayed at 1.53 s
  on IOS-XE and 2.6 s on NX-OS. vEOS and vJunos-router with single-connection on are unaffected.
  Pre-existing behaviour, exposed by the 6b lab configuration. Until the fix (before
  fix/breakglass-reset), a Cisco device with single-connection on took 16–21 s per break-glass
  session when refused or quarantined and 30–41 s when removed; break-glass still logged in. The fix
  (`fix/breakglass-reset`) refuses the source's next connections at Accept for a short window on all
  three paths, strike-free for the refused and quarantined, and its run on IOS-XE and NX-OS with
  single-connection on closed the row.

  **Measured 2026-09-30** by fix/breakglass-reset Task 6 (`tests/lab/l31_test.go`,
  `TestL31BreakGlass`; `tests/lab/results/L31-cisco_iosxe.md`, `L31-cisco_nxos.md`,
  `L31-arista_eos.md`; captures `tests/lab/evidence/L31-<phase>-<platform>.pcap`), port49d built
  from `b998ae9`, on Catalyst 8000V 17.13.01a, Nexus 9300v 10.4(2)F and vEOS-lab 4.31.2F (image
  tagged 4.32.2F), each with single-connection on. The headers each device sent after the change
  had the single-connect flag (`0x04`) set and none clear: 4 per phase on the C8000V, 5 on the N9Kv,
  and 3–6 on vEOS. Each phase timed break-glass login plus three `show version` against the rekeyed
  control, a key miss, with the bar at the control plus 1.5 s and never 5 s:

  | image | stopped | rekeyed (control) | removed | refused | quarantined |
  |---|---|---|---|---|---|
  | Catalyst 8000V 17.13.01a | 1.31 s | 1.28 s | 1.28 s | 1.78 s | 1.78 s |
  | Nexus 9300v 10.4(2)F | 2.66 s | 2.61 s | 2.62 s | 2.58 s | 2.61 s |
  | vEOS-lab 4.31.2F | 0.37 s | 0.34 s | 0.33 s | 0.32 s | 0.32 s |

  Connections refused at Accept during break-glass, removed, refused and quarantined: 6, 10 and 8 on
  the C8000V (control 5), 11 in each phase on the N9Kv (control 11), and 11, 10 and 13 on vEOS
  (control 12). The refused connections left no record. Each declined phase left five `unvalidated`
  records on the C8000V against its 6–10 refusals, six on the N9Kv against 11 (plus one `account`
  record, as in the control, from the probe login before the change took effect; the notes count
  records from just before the change), and three on vEOS against 12–15 refusals since the change.
  The removed phase's records read `unadmitted_source`, the refused phase's `admission_refused`
  and the quarantined phase's `device_quarantined`, as §10 says. vEOS's 0.32–0.33 s sits inside
  the 0.32–2.1 s it took before the fix (`L29-reload-arista_eos.md`, `quarantine-sync-arista_eos.md`):
  no regression. The N9Kv's times are the key miss's; the C8000V's removed time is too, and its
  refused and quarantined times are 0.5 s over it, inside the bar, because IOS-XE retries 100–200 ms
  after a reset against a first window of 100 ms. A declined device now costs break-glass about
  what a refused connection does, where it cost 16–41 s.
- **L32** — added 2026-10-01 by plan 6c, for what L30 left unmeasured outside its question (which of
  `Host` and `X-Forwarded-Host` the products read; following a proxied `next`) and for the
  connector's own query, which asks for fields no L27 or L30 query asked together (`primary_ip6`
  and `status` beside the map's paths). The code does not depend on which header a release reads:
  it follows `next` on its `url` and rebuilds it otherwise (§10). Owned by plan 6c, Task 14.

  **Measured 2026-10-01** by plan 6c Task 14 on beehive (`tests/lab/l32_test.go`,
  `TestL32Connector`; `tests/lab/results/L32-netbox.md`, `L32-nautobot.md`; records in
  `tests/lab/sot/l32/<stack>/connector.json`), each release in its own Compose stack with 120
  devices, read by `sot.New` and `Fetch` as built at `eb862a4` (`page_size` 50, `filter: {status:
  [active]}`, primary addresses, and over GraphQL every interface's addresses), through three
  TLS-terminating nginx 1.27 proxies: `proxy_host` (the client's host as `Host`, no
  `X-Forwarded-Host`), `proxy_xfh` (`Host` the upstream's, `X-Forwarded-Host` the client's) and
  `proxy_plain` (a bare `proxy_pass`: `Host` the upstream's, no `X-Forwarded-*`); every proxy but
  the last sent `X-Forwarded-Proto: https`.

  | release | `next` via `proxy_host` | via `proxy_xfh` | via `proxy_plain` | GraphQL, 3 proxies | REST, 3 proxies | GraphQL `id` |
  |---|---|---|---|---|---|---|
  | NetBox 3.7.8 | the client's host (`Host`), `https` | the client's host (`X-Forwarded-Host`), `https` | `http://netbox:8080`, rebuilt on `url` and said | 120 each, 0.23–0.25 s | 120 each, 0.21–1.68 s | selectable, a string |
  | NetBox 4.7.1 | as 3.7.8 | as 3.7.8 | as 3.7.8 | 120 each, 0.26–0.81 s | 120 each, 0.29–0.46 s | selectable, a string |
  | Nautobot 1.6.32 | as NetBox | as NetBox | `http://nautobot:8080`, rebuilt on `url` and said | 120 each, 3.04–4.24 s | 120 each, 1.48–1.49 s | selectable, a string |
  | Nautobot 2.4.43 | as NetBox | as NetBox | as 1.6.32 | 120 each, 1.60–1.82 s | 120 each, 2.18–2.19 s | selectable, a string |
  | Nautobot 3.2.6 | as NetBox | as NetBox | as 1.6.32 | 120 each, 1.57–2.73 s | 120 each, 2.08–2.28 s | selectable, a string |

  So every release builds `next` from `X-Forwarded-Host` when sent, from `Host` otherwise, and takes
  `https` only from `X-Forwarded-Proto`. Where `next` named `url`'s origin the connector followed it;
  through `proxy_plain` it rebuilt every REST `next` on `url`, said so once, and read all 120, where
  a followed `next` would have failed (`netbox:8080` and `nautobot:8080` do not resolve on the host).
  GraphQL gave `leaf-01` its primary and interface addresses, REST its primary alone, as §10 says.
  Since every release gives `id`, the connector keys the GraphQL list by it, as REST's is (plan 6c
  Task 14's fix round, `e8bbe15`), so a device renamed between pages is caught as a repeat. *Not
  observed:* a proxy that sends `X-Forwarded-Host` but no `X-Forwarded-Proto`, or a `next` naming
  another path; a GraphQL list above any server cap; a list changing between pages, and a removal
  (each read was a new source, with nothing to confirm against); the `id` key's catch of a rename
  is replayed in `internal/sot/sottest`, not measured.
- **L33** — added 2026-10-01 by plan 6c. L27 and L30 recorded deliveries to a plain-HTTP listener;
  port49-inventory takes them only over TLS, so whether each release delivers to a private CA's
  certificate is unmeasured, and so is what a release does with a refused delivery. Owned by plan
  6c, Task 15, with the device run end to end.

  **Measured 2026-10-01** by plan 6c Task 15 on beehive (`tests/lab/l33_test.go`,
  `TestL33Webhooks`; `tests/lab/results/L33-netbox.md`, `L33-nautobot.md`; records in
  `tests/lab/sot/l33/<stack>/webhooks.json`), port49-inventory built from `c8a63d8` with the stack
  as its one source (`interval: 24h`, so every publication after the first is a webhook's) and
  `webhook_listen` under a certificate from the run's lab CA. Each release got a webhook to
  `https://port49-inventory.lab:18444/v1/webhook/l33` with `ssl_verification: true` and the CA as
  `ca_file_path`, three device changes 35 s apart, then one change delivered to two more webhooks:
  one under a wrong secret, and one to a stand-in listener answering every request `503
  {"error":"shutting_down"}`, a stand-in for a service going away. (This note first said
  port49-inventory answers so during shutdown; it never does: early in a shutdown it accepts a
  delivery that then triggers nothing, and after that refuses the connection. Corrected by plan 6c's
  final review, M1.) Seconds run from the API
  write to the service's `sync (webhook): published bundle` line, the 2 s settle included.

  | release | delivered over TLS, private CA | update | create | delete | 401 sent again | 503 sent again | retry setting |
  |---|---|---|---|---|---|---|---|
  | NetBox 3.7.8 | yes, from the first change | 2.44 s | 2.43 s | 2.65 s | no, in 120 s | no, in 120 s | `RQ_RETRY_MAX` unset, default 0 |
  | NetBox 4.7.1 | yes | 2.50 s | 2.60 s | 2.73 s | no | no | as 3.7.8 |
  | Nautobot 1.6.32 | yes | 3.57 s | 3.70 s | 4.01 s | no | no | none: `process_webhook` has no retry |
  | Nautobot 2.4.43 | yes | 4.07 s | 3.81 s | 3.78 s | no | no | as 1.6.32 |
  | Nautobot 3.2.6 | yes | 4.04 s | 3.76 s | 3.73 s | no | no | as 1.6.32 |

  Every delivery authenticated, none was stale, each change was one accepted delivery and one
  publication, and the wrong secret's was refused 401, counted and said once (`bad_signature`). So a
  delivery refused, or answered 503 (by the stand-in), is lost at the products' defaults, and the
  source's `interval` is what covers it, or, across a restart, the next start's sync (§10). End to end on vEOS-lab 4.31.2F (image tagged 4.32.2F; port49d, port49 and
  port49-inventory built from `1c0b8d1`; `tests/lab/sot_e2e_test.go`, `TestSoTDeviceEndToEnd`;
  `tests/lab/results/L33-e2e-netbox-arista_eos.md`,
  `L33-e2e-nautobot-arista_eos.md`; captures `tests/lab/evidence/L33-e2e-<product>-arista_eos.pcap`),
  the device in the source admitted a token login at start, and then:

  | source | change | to the publication | to port49d's reload | token login after | break-glass |
  |---|---|---|---|---|---|
  | NetBox 4.7.1 | `os_version` | 2.52 s | 4.49 s | logged in | not tried |
  | NetBox 4.7.1 | status `offline` (filtered out) | 2.55 s | 4.95 s | no token: the mint answered `no_grants_matched` | logged in |
  | NetBox 4.7.1 | status `active` again | 2.43 s | 2.53 s | logged in | not tried |
  | Nautobot 3.2.6 | `os_version` | 3.78 s | 4.49 s | logged in | not tried |
  | Nautobot 3.2.6 | status `offline` (filtered out) | 3.74 s | 4.92 s | no token: the mint answered `no_grants_matched` | logged in |
  | Nautobot 3.2.6 | status `active` again | 3.74 s | 6.98 s | logged in | not tried |

  The removed device's refusal was measured at the mint; what a device does on a connection after
  its removal is L29's. *Not observed:* a webhook certificate the worker's default trust store holds;
  a burst of changes inside the 30 s gap; NetBox with `RQ_RETRY_MAX` set; a delivery during
  port49-inventory's shutdown (accepted and not synced, or refused at connect) or while it is down,
  the common restart case, which the retry settings above say is not sent again and the next
  start's sync covers; the device run on NetBox 3.7, Nautobot 1.6 or 2.x.
- **L34** — added 2026-10-01 by plan 7b, before the warning was built, because L2 measured how a
  device shows a *denial's* `server_msg`, and a warning rides on a *permit*. A device could drop
  it, show it, or read a permit carrying text as something else.

  **Measured 2026-10-01** by plan 7b Task 12 on beehive (`tests/lab/session_test.go`,
  `TestSessionLifetime`), on all five images, port49d at a 6m `max_session_age` with
  `session.ceiling_warning: 2m` and every platform in `session.ceiling_warning_platforms`. A
  login and `show version` came 4m10s after `port49 login`, inside the warning. Every permit
  carried `port49: session ends in 2m - run 'port49 refresh'` (the records); `port49 token`
  printed the warning on stderr on every image.

  | Image | Session permit at login | Command permit | Still a permit |
  |---|---|---|---|
  | IOS-XE 17.13.01a | shown before the prompt | shown with `show version`'s output | yes |
  | vEOS-lab 4.31.2F (image tagged 4.32.2F) | not shown | not shown | yes |
  | NX-OS 10.4(2)F | not shown | not shown | yes |
  | vJunos-router 23.4R2-S2.1 | not shown | none sent (decision 21) | yes |
  | vSRX 21.4R3.15 | not shown | none sent (decision 21) | yes |

  `tests/lab/results/L34-cisco_iosxe.md`, `L34-arista_eos.md`, `L34-cisco_nxos.md`,
  `L34-juniper_vjunos-router.md`, `L34-juniper_vsrx.md`; captures
  `tests/lab/evidence/session-<platform>.pcap`. NX-OS ran at `4bd3100`, vJunos-router at
  `6dece62`, the rest at `ec50053`. So `cisco_iosxe` alone is on `platform.CeilingWarning`'s
  list. On IOS-XE the line was among `show version`'s output inside the 2m window, so a script
  reading command output there sees it too; that every command shows it over a full 30m window,
  and where the line falls relative to the output, were not measured.
- **L57** — added by plan 9b1 (`tests/lab/junos_groups_test.go`); open. Why it is a row:
  `devices check-config` used to refuse any capture carrying `apply-groups`, and the fleets port49
  serves template their logins through groups. Decision 44 trusts the device's own expansion,
  so what `display inheritance` prints in set form is a claim about the device, and is measured.
  Measured 2026-10-11 on vJunos-router and vSRX (`tests/lab/results/L57-juniper_*.md`; the row
  closes in plan 9b1's Task 9): both inherited set forms, either pipe order, expand `p49g-tip`
  (`<*>`) and `p49g-perm` (`<p49-*>`) under `p49-remote` and print no `set apply-groups` and no
  `set groups` line; plain `display set` prints both and expands nothing. `p49g-excepted` is kept
  off `p49-remote` by `apply-groups-except`, whose line survives inheritance. The nested group
  committed and was not expanded in any inherited capture. The class's own `idle-timeout 720` stands over the group's
  30, and `p49g-perm`'s `view-configuration` lands beside `p49-l57own`'s own `view`. The curly
  `show configuration system login | display inheritance` names the group per line (`## 'login-tip'
  was inherited from group 'p49g-tip'`); the note's curly row reads "not parsed", since the test
  reads set lines only. A session landing in `remote` got a syntax error for `show cli
  authorization` on both images, so what it holds was not read there. This contradicted decision
  44 ruling 7 and §12's first reading, which named the group from the definitions the capture was
  thought to keep; both now judge the expanded lines. The harness now also measures a class-level
  `apply-groups` (stripped by inheritance or not) and, with the nested inner group adding
  `permissions view`, a token session's `show cli authorization` beside a `show configuration
  system host-name` control (which must print the host name) and a same-run `Current user`
  control under a class holding its own `view`: **L57 closes in Task 9 only if that session cell
  was observed.** If it
  reads "applies", the nested group is a fail-open check-config cannot see, and ruling 7 changes
  before the row closes.
- **L58** — added by plan 9b1 (`tests/lab/junos_baseline_test.go`); closed 2026-10-11
  (`tests/lab/results/L58-juniper_vjunos-router.md`, `L58-juniper_vsrx.md`). Why it was a row: a
  readonly's reply carries the baseline's denies, and decision 44 ruling 10 sends `save **` as a
  proven keyword and `xml-mode **` as nothing. L26b left `save` unproven on vSRX, and L26c typed
  only `xml-mode netconf` under a `junoscript` deny. Under `^ *(save|junoscript)( .*)? *(\|.*)?$`
  the deny refused `save dhcp-security-snoop …` with its caret under `save` on both images, where
  vJunos-router's control ran it (`Count: 1 lines`) and vSRX's control's CLI took `save` and
  stopped after it (vSRX 21.4 has no `save` subcommand a session runs to the end); bare `xml-mode`
  and `xml-mode netconf need-trailer` were refused (`unknown command`), the control greeted
  (`<junoscript`, `<hello`). The `save` cells ran under a `permissions all` class
  (`p49-l58-save`), the entries under the `view` class; the `save` candidates typed under `view`
  with no deny are recorded in the note as "control (view)" when the test next runs, information
  only.

Entries are added when a new claim is made, never removed. A closed entry keeps its row so a
later reader can find the evidence.
