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
them, and it has exactly two forms — an LDAP group, or a literal identity. That single
mechanism covers both directory-driven human access and hand-maintained service accounts.

**Privilege level and command authorization are independent axes.** The level tells the
device what shell to construct; the role governs what may execute inside it. Welding them
together is a large part of why per-vendor read-only definitions are painful to maintain
today. A backup account can hold `admin` privilege — so `show running-config` returns in
full — while command rules confine it to `show`.

---

## 3. Request normalization

The matcher never sees raw wire data. A platform adapter converts an authorization request
into a canonical form:

```
principal      resolved from session context, not from the wire
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

| Term | Matches |
|---|---|
| `word` | exactly that argument, case-insensitively |
| `*` | exactly one argument, any value |
| `**` | zero or more arguments — **trailing position only** |
| `/re/` | exactly one argument matching the RE2 expression |

```yaml
permit:
  - show **                          # show, and anything after it
  - show bgp summary                 # exactly that, nothing more
  - clear counters *                 # one argument
  - interface /^(Ethernet|Port-Channel)[0-9/.]+$/
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
diff (§10), which is a reason to prefer literals and `*` where either will do.

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
  → subjects            match by LDAP group membership or literal identity
  → grants              those whose subject matches AND whose scope matches this device
                        AND whose `expires` has not passed
  → roles               union across matching grants
  → privilege           max over granted roles, or the grant's override
  → max_privilege       max over matching grants; absent means no escalation
  → effective rules     resolved permit/deny/pipe sets
  → av_pairs            rendered for this device's platform
```

The result is written to session context as a **precomputed value**. The daemon evaluates
against it and never consults inventory, policy, or the directory — preserving the design
document's rule that the daemon's only dependency is the token store.

Failure to match any grant means the device is unreachable for that principal, and the mint
fails **before an SSH connection is opened**.

### 5.2 Session authorization (daemon)

On `service=shell` with an empty `cmd`, the daemon returns the AV pairs already stored in
session context. No computation, no platform knowledge, one store read.

If session context is absent, the daemon fails closed and logs a distinct reason —
`context_missing` is operationally very different from `denied_by_policy` and the two must
never share a log line.

### 5.3 Command authorization (daemon)

```
normalize(request)
  → if no session context             → DENY (context_missing)
  → if command matches deny set        → DENY (rule, role)
  → if command matches no permit rule  → DENY (default_deny)
  → for each pipeline stage:
        if stage matches no pipe permit → DENY (pipe_stage, stage_name)
  → PERMIT (rule, role)
```

Default is deny. Every decision carries the rule and role that produced it, which is what
makes `explain` able to name exactly one reason.

Requests for a `service` other than `shell` are denied by default with a distinct reason,
configurable per platform.

### 5.4 Composition across roles

**Recommended: deny-overrides, order-independent.**

```
permits = ∪ permit rules across granted roles
denies  = ∪ deny  rules across granted roles

decision = match(permits) ∧ ¬match(denies)          default: deny
```

Union is commutative, so reordering roles, grants, or rules cannot change any decision.
That buys four things the design document already asks for:

- **The CI effective-permission diff becomes exact rather than sampled.** Under ordered
  first-match, the effective set depends on rule position and a diff can only report *"of
  the commands we tried, these changed."*
- **`explain` names exactly one reason.** No shadowed rules.
- **Reordering YAML is provably a no-op** — formatters, merge conflicts, and refactors
  cannot silently change permissions.
- **The broker can precompute the whole rule set at mint**, because an order-free result is
  a value. This is what keeps the daemon inventory-free.

Two useful properties follow: adding a deny can only reduce access, and only permit-set
growth can widen it — so *"is this change privilege-expanding?"* is a cheap, exact CI gate.

**Cost.** A deny cannot be carved out by adding a role. The idiomatic answer is to express
prohibitions as their own roles so they travel with the grant rather than hiding inside a
capability:

```yaml
roles:
  - name: bgp_operator
    permit: [show bgp **, clear bgp /^[0-9]+$/ **]
  - name: no_disruptive
    deny:   [clear bgp all, reload **, write erase **]

grants:
  - {subject: netops, scope: prod_edge, roles: [bgp_operator, no_disruptive]}
  - {subject: netops, scope: lab,       roles: [bgp_operator]}
```

> **OPEN DECISION.** The alternative is most-specific-match-wins (longest matching prefix,
> deny wins ties), which allows narrow carve-outs inside broad grants at the cost of
> requiring specificity computation in `explain` and overlap reasoning in the diff. See §13.

---

## 6. Privilege levels and AV pairs

### Abstract levels

Privilege levels are an **ordered enum** declared once:

```yaml
privilege_levels: [readonly, operator, admin]
```

The operator writes `privilege: readonly`. The platform adapter renders it. No vendor
attribute string appears in operator-authored policy.

Where multiple roles are granted, the effective level is the **max** over the ordered enum.

### Rendering

Attribute syntax follows RFC 8907 directly: `=` is mandatory, `*` is optional. No invented
key, no translation layer.

```yaml
platforms:
  arista_eos:
    privilege:
      readonly: ["shell:priv-lvl=1",  "shell:roles*network-operator"]
      operator: ["shell:priv-lvl=7"]
      admin:    ["shell:priv-lvl=15", "shell:roles*network-admin"]

  cisco_nxos:
    privilege:
      readonly: ['shell:roles*"network-operator"']
      operator: ['shell:roles*"network-operator"']
      admin:    ['shell:roles*"network-admin"']
```

**Mandatory versus optional is not cosmetic.** A device that does not understand a
*mandatory* attribute must reject the session outright. Sending `shell:roles` as mandatory
to a platform that does not parse it breaks every login on that platform. Which attributes
are mandatory per platform is exactly the knowledge that belongs in a shipped, tested file
rather than in each organization's collective memory.

**Not every level is natively representable.** NX-OS is role-native with two built-in
roles, so `readonly` and `operator` render identically and the distinction is carried
entirely by command authorization. That is acceptable — it is the two-axes property from §2
— but it must be visible in the platform file rather than silently surprising.

**Platforms that are not `priv-lvl`-native** (Junos maps to `local_user_name`) MUST declare
a mapping for every level. A missing mapping is a **policy load error in CI**, not a broken
login at 3am.

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
2. The username does not identify the principal, so **session context MUST be keyed on
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
| `auto` | Daemon resolves `(nas, port)` → session context, checks the ceiling, PASSes. Any password accepted. | Tools that insist on typing `enable` where plumbing a second secret is awkward. |
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

After a successful escalation, session context records the new privilege level, since
command rules may differ above and below the line, and accounting attributes the event to
the **real principal** even though the wire said `$enab15$`.

---

## 8. Platform adapters

A platform adapter is a small declarative file. Adapters ship with port49, are tested in the
containerlab matrix where an image exists, and are contributable.

```yaml
platforms:
  arista_eos:
    supports: [session, commands, config_commands]
    privilege:
      readonly: ["shell:priv-lvl=1",  "shell:roles*network-operator"]
      operator: ["shell:priv-lvl=7"]
      admin:    ["shell:priv-lvl=15", "shell:roles*network-admin"]
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
| `privilege` | level → AV pairs at session authorization | always |
| `supports` | capability declaration (see §9) | always |
| `enable_username` | `principal`, or a template such as `$enab{level}$` | if enable is supported |
| `expands_abbreviations` | whether the device sends resolved command words | if `commands` |
| `pipe_token` / `pipe_authorized` | modifier separator; whether it reaches us | if `commands` |
| `service` | authorization `service` value if not `shell` | rarely |
| `port_pattern` | expected `port` shape, used only for drift detection | optional |

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

### Admission and keys

RFC 8907 requires a shared key per NAS or NAS group. This is absent from the design
document and is a prerequisite for everything above.

```yaml
devices:
  admission:
    - {cidr: 10.0.0.0/8,       key: "${TACACS_KEY_PROD}"}
    - {cidr: 192.168.100.0/24, key: "${TACACS_KEY_LAB}", attributes: {env: lab}}
```

Sources outside an admission entry are refused at the transport layer. RFC 9887 (§11 of the
design document) replaces the key with mTLS, so a device record must be able to express
both.

### Records

```yaml
  - name: leaf-01
    addresses: [10.0.1.5, 10.0.1.6, 2001:db8::5]
    platform: arista_eos
    attributes: {site: dc1, role: leaf}
```

**Every address a device may source from must be listed.** TACACS is commonly sourced from
a loopback or dedicated management interface that is not the device's primary address. A
device that sources from an unlisted interface fails device binding, and the failure will
not obviously trace back to inventory. `ip tacacs source-interface` — or the platform
equivalent — MUST be pinned in the reference AAA configuration.

### Source-of-truth sync

Connectors pull on a schedule and produce a snapshot. **The broker loads snapshots; it never
queries a source of truth synchronously.** This is the same rule the design document applies
to the directory, for the same reason.

```yaml
inventory:
  sync:
    - name: netbox_prod
      type: netbox
      url: https://netbox.example.com
      token: ${NETBOX_TOKEN}
      interval: 15m
      filter: {status: active, has_primary_ip: true}
      map:
        site:     site.slug
        role:     device_role.slug
        platform: platform.slug
      safety:
        max_removed_percent: 10
```

Connectors: **NetBox and Nautobot** are the tested pair; Infrahub, Ansible inventory, and a
plain file follow the same snapshot contract. A file connector is required regardless, as
the inventory equivalent of the in-memory store — containerlab runs, CI policy tests, and
`port49 explain` against a hypothetical device all need an inventory that is not a live SoT.

Four requirements:

**Version detection.** NetBox 4.x renamed `device_role` → `role`; Nautobot 2.0 did the same
and dropped `slug` from most models. The connector selects a mapping profile from the API
root version, with an explicit override available.

**GraphQL first.** At 10,000 devices, REST pagination is hundreds of round trips per sync.
Both products expose GraphQL; one query returns devices, addresses, platform, site, role,
and tags. REST remains as a fallback for older installs.

**Bounded change per sync.** A sync that would remove more than `max_removed_percent` of the
fleet MUST refuse, retain the last good snapshot, and alarm. A partially-available SoT or a
mistyped filter would otherwise silently deauthorize the fleet.

**Platform slug translation.** Real installs say `eos`, `arista-eos`, `arista_eos`, or
`veos`. Ship an alias table, allow overrides, and warn on unrecognized slugs rather than
falling back to generic in silence.

### Security note: SoT write access is privilege-granting

If scopes match on synced attributes, then whoever can change a device's `role` in NetBox
can move it into or out of a scope — with no policy change, no PR, and no diff. The policy
file looks untouched.

Mitigations, designed in rather than documented afterward:

- Scope-membership changes MUST appear in the sync diff and be reviewable.
- A scope MUST be able to pin a device set explicitly instead of by attribute.
- SoT write access MUST be documented as privileged.

> **Principle.** The source of truth supplies facts about devices; the policy repository
> supplies intent. The moment an SoT tag can grant a permission, authorization has left code
> review — which is the outcome the design document's §9 exists to prevent.

---

## 11. Complete policy example

```yaml
privilege_levels: [readonly, operator, admin]

scopes:
  - {name: all_devices, match: {}}
  - {name: dc_fabric,   match: {site: [dc1, dc2], role: [leaf, spine]}}
  - {name: lab,         match: {env: lab}}

roles:
  - name: read_only
    privilege: readonly
    permit:
      - show **
      - terminal length *

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
      - interface /^(ethernet|port-channel)[0-9/.]+$/
      - shutdown
      - no shutdown
      - description **
      - end
    deny:
      - interface /^(management|mgmt)/

  - name: no_disruptive
    deny:
      - reload **
      - write erase **

subjects:
  - name: netops_admins
    group: "CN=netops-admins,OU=Groups,DC=example,DC=com"
    enable: token
    token_ttl: 60s

  - name: noc_tier1
    group: "CN=noc-tier1,OU=Groups,DC=example,DC=com"
    enable: none
    token_ttl: 60s

  - name: svc_oxidized
    identity: "system:serviceaccount:netops:oxidized"
    enable: token
    token_ttl: 900s

grants:
  - {subject: netops_admins, scope: all_devices, roles: [network_admin],
     max_privilege: admin}

  - {subject: noc_tier1, scope: all_devices, roles: [read_only, no_disruptive]}

  - {subject: noc_tier1, scope: dc_fabric, roles: [interface_tech],
     expires: 2026-12-01}

  - {subject: svc_oxidized, scope: all_devices, roles: [read_only],
     privilege: admin}

tests:
  - {subject: noc_tier1, device: leaf-01, command: "show version",   expect: permit}
  - {subject: noc_tier1, device: leaf-01, command: "reload",         expect: deny}
  - {subject: noc_tier1, device: leaf-01, command: "show run | redirect ftp://x",
     expect: deny}
  - {subject: svc_oxidized, device: leaf-01, command: "show running-config",
     expect: permit}
```

The `interface_tech` deny illustrates a real dialect problem: `management` is the EOS
spelling and `mgmt0` is the NX-OS one. Either the regex knows both, or interface naming is
something the adapter normalizes. See §13.

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

**`port49 devices capabilities`** reports the `supports`-versus-`observed` matrix from §9.

**Access review** is a rendering of the flat grant table, not an investigation.

---

## 13. Open decisions

1. **Precedence.** Deny-overrides (recommended, §5.4) versus most-specific-match-wins.
   Deny-overrides is order-free and makes the CI diff exact; most-specific allows narrow
   carve-outs inside broad grants.
2. **Grant shape.** Flat — subject, scope, roles, level, expiry, one row each — versus
   nested under a subject. Flat is greppable and renders directly as the access-review
   report; nested is less repetitive to author. The example in §11 assumes flat.
3. **Role default privilege.** Whether a role carries a default level that a grant may
   override (assumed in §11), or whether level is always set on the grant.
4. **Privilege levels.** Fixed shipped enum versus user-extensible with shipped defaults.
   Extensible costs a mapping per non-`priv-lvl`-native platform.
5. **Device admission location.** Policy repository versus inventory snapshot. It is the
   boundary between operator intent and imported fact, and blanket RFC 1918 admission blurs
   it.
6. **Entity-name normalization.** Whether the adapter normalizes interface and entity naming
   across platforms (`Management1` / `mgmt0`), or whether rules carry per-platform spellings.
   §11 shows the problem.

---

## 14. Required test assertions

Beyond those already listed in the design document's §14:

- **Session authorization returns correct AV pairs per platform**, with mandatory versus
  optional flags honored. A mandatory attribute a platform cannot parse must be caught here,
  not in production.
- **Case-insensitive literal matching**: `SHOW RUN` is treated as `show run`.
- **Abbreviation handling**: on a platform with `expands_abbreviations: false`, an
  abbreviated command either expands correctly or is denied — never silently unmatched.
- **Pipeline enforcement**: `show run | redirect …` denied under a role permitting `show **`.
- **Full-vector matching**: `show bgp summary` does not match `show bgp summary detail`.
- **Enable**: all three mechanisms, including the `$enab15$` username path resolving through
  session context on `(nas, port)`.
- **Config-mode inference**: a device with `aaa authorization config-commands` disabled is
  detected and reported.
- **Order independence**: a policy file with roles, grants, and rules shuffled produces
  byte-identical decisions across the full test corpus.
- **Inventory sync safety**: a sync removing more than the configured share is refused and
  the previous snapshot retained.
- **Unknown platform** falls back to generic and alarms; **unknown device** is refused.
