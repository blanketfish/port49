---
title: Roles and grants
description: Defining roles, granting them to people, groups and workloads, and reading why a grant applied.
---

# Roles and grants

A **role** is what may be done: command rules, a privilege level, optional attributes, a session length and
an optional per-login proof. A **subject** is who. A **grant** gives a subject some roles in a scope. The whole
vocabulary is in the [policy reference](../reference/config/policy.md); how rules are written and how a
change is reviewed is on [Policy](policy.md).

## Roles

```yaml
roles:
  - name: read_only
    privilege: readonly
    permit: ["show **", "terminal length *"]
    max_session_age: 8h
  - name: bgp_operator
    privilege: operator
    permit: ["show bgp **", "clear bgp neighbor **"]
    deny: ["clear bgp all"]
    per_login_mfa: {accept: [hardware_key_touch]}
```

`privilege` names a level from `privilege_levels:`. `readonly`, `operator` and `admin` always exist and keep
that order; you may add levels with a `parent:`, the level a platform renders one as where it has no
rendering of its own. A role's `permit` and `deny` lists follow the rules on [Policy](policy.md#writing-a-rule).
`attributes:` adds attribute strings to the reply, per platform or under `all`; a grant may add its own.

### `max_session_age`

`max_session_age` is how long a person's session on a device may last: a duration of at least `1m`, or
`never`. It is set per role, and a session's ceiling is the **least** of the roles that compose on that device.
A role that says nothing takes `session.max_session_age_default` from [port49d.yaml](../reference/config/port49d.md)
(12 hours unless you set it), and a `max_session_age:` with no value is refused. If every role says `never`,
so does the session.

`port49 explain` prints the result for a subject and device:

| Line | Meaning |
|---|---|
| `max_session_age 8h0m0s (the least of its roles')` | every role names a duration; this is the least |
| `max_session_age the lesser of 8h0m0s and session.max_session_age_default` | one role names no value |
| `max_session_age session.max_session_age_default (no role names a finite one)` | the default decides |
| `max_session_age never (every role says never)` | no ceiling |

Shortening a role reaches live sessions at the next policy refresh. Lengthening it, or choosing `never`, reaches
a person's sessions only when they run `port49 refresh` or log in again. `port49 policy diff` prints a
`session ceiling:` line for the change; see [Policy](policy.md#the-ceiling-line).

## Subjects

A subject is exactly one of three things, and never a mix:

| Form | Who it names | Needs |
|---|---|---|
| `group:` | a directory group of **people**, by name or DN | `broker.directory` configured |
| `machine_group:` | a group of **workloads**, by name or DN | a workload certificate verifier whose `directory` maps the workload to an entry |
| `identity:` | one or more literal principals: `user:<email>`, a SPIFFE ID, `system:serviceaccount:<namespace>:<name>`, or `app:<client_id>` | nothing |

```yaml
subjects:
  - name: netops
    group: "cn=netops,ou=groups,dc=example,dc=com"
    token_ttl: 300s
  - name: ci_runners
    machine_group: "cn=ci-runners,ou=groups,dc=example,dc=com"
    token_ttl: 120s
  - name: svc_backup
    identity: ["system:serviceaccount:netops:backup"]
    username: svc-config-backup
    token_ttl: 60s
```

A subject that has both `group:` and `machine_group:`, or either one with `identity:`, is refused: a subject is
one trust domain, so a person and a workload each get their own. A person never matches a `machine_group:`
subject and a workload never matches a `group:` subject, and `attached_roles.machines` reaches the machine
domain alone. `token_ttl` (30 to 900 seconds) is required on any subject a grant names.

### `machine_group:`

A `machine_group:` is the machine-side twin of `group:`: it names a group in the directory, but its members are
workloads. The broker resolves a workload through the verifier's directory mapping
(`broker.identity.machines[].directory`) and matches it to the subjects whose group it is in. With no mapping
configured, a `machine_group:` subject mints for no one, and port49d's start says so. Its members take the
username their own entry gives, or the one an `identity:` subject listing the same SPIFFE ID declares, so
a `machine_group:` subject declares no `username:` and one that does is refused: one name for many
workloads would put them all in one device login. See [Workloads](workloads.md).

### Usernames

The device sees a username, not a principal. For a person, the directory supplies it, so a `group:` subject
and an `identity:` subject for a `user:` principal declare none when `broker.directory` is on. A literal identity
for a machine declares one (`username: svc-config-backup` above), lowercase and printable ASCII, and
never `remote`, a `p49-` name or a platform's system user. A subject whose identities are all SPIFFE IDs
may leave it out where the directory mapping supplies one; `port49 policy test` reports it as
`workload_no_username` since an offline run cannot know.

### `api:` rights

A principal may always mint for itself, end its own sessions (`port49 revoke --mine`) and explain its own
decisions. Acting on **other people** is a right the subject declares:

```yaml
subjects:
  - name: netops_oncall
    group: "cn=netops-oncall,ou=groups,dc=example,dc=com"
    token_ttl: 300s
    api: [revoke_others, explain_others]
```

| Right | Lets the subject | Needs a key press |
|---|---|---|
| `revoke_others` | revoke another principal, a certificate, a `(device, username)` key or an OIDC session; list the revocations | yes, except the list |
| `lift_revocations` | lift a revocation by principal or certificate; list the revocations | yes, except the list |
| `explain_others` | `port49 explain --principal` another person | no |
| `forget_principals` | forget a principal's directory pin | yes |
| `reset_second_factor` | reset one principal's second factor, or everyone's | yes |
| `unlock_sign_in` | unlock a locked sign-in | yes |
| `import_enrollments` | import the enrollment store | yes |
| `sync`, `keys_show`, `replay` | nothing yet: reserved, declared and reported, granting nothing until an endpoint exists | n/a |

An admin-level right needs a press of the person's security key on top, bound to that one call, so an exposed
certificate or agent session alone authorizes nothing admin-level. On a broker with no attestation roots loaded
every admin call is refused; see [Hardware keys](../operate/hardware-keys.md). A right withdrawn by a policy
reload is gone at the next call.

An `api:` list reads like a grant of authority over other people's sessions, and CI treats it as one:
`port49 policy test` prints a `report: api_rights` line per subject and names the admin-level ones, and
`port49 policy diff` fails on a subject that **gains** a right until a session test asserts the subject's
whole list:

```yaml
tests:
  - {subject: netops_oncall, device: leaf1, api: [revoke_others, explain_others]}
```

A right the subject loses passes. A principal moved to a subject with more rights needs that assertion in a test
that names the principal.

## Grants

```yaml
grants:
  - {subject: netops, scope: dc_fabric, roles: [read_only]}
  - {subject: netops_oncall, scope: dc_fabric, roles: [bgp_operator], max_privilege: admin, expires: "2026-12-01"}
```

A grant names a declared subject and scope and at least one role, each listed once; two grants with the same
subject, scope and roles are refused, so merge them. `expires` is a date (the start of that day, UTC) or an
RFC 3339 time, after which the grant stops matching, and `port49 policy diff` and `policy test` read the policy
at every later expiry as well as now. `max_privilege` is a ceiling on the level a token from the grant may
carry, which is how far `enable` may take the session; with no `enable` on the subject, nothing escalates to it.
`enable` is `none` (the default), `auto` or `token`. A grant on a scope that is `on_missing: include` is refused (a scope with no
match key, or pinned by `name` alone, is the exception);
see [Policy](policy.md#the-include-scope-grant-refusal).

When one person matches several subjects, the grants of all of them compose: the roles are the union, the
level is the highest of the roles, the ceiling is the highest across the grants, and `max_session_age` is the
least. Reordering grants never changes a decision.

### `per_login_mfa`

A policy may ask for a second factor at **each login** to the devices it marks. This is a proof at the device
login, not the daily sign-in. Write it as `per_login_mfa:` on `defaults:`, a role or a scope:

```yaml
defaults:
  per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 15m}
scopes:
  - name: core
    match: {tier: core}
    on_missing: include             # the requirement holds on a device the inventory cannot describe
    security_log: true
    per_login_mfa: {accept: [hardware_key_touch], reuse_for: 5m}
  - name: core_access
    match: {tier: core}
    on_missing: exclude             # the grant is earned by data
```

The scope that carries the requirement is `include`, so a device whose `tier` is missing is still held to it.
A grant on an include scope is refused at load, so the grant goes on `core_access`, a second scope with the same
match (`grants: [{subject: netops, scope: core_access, roles: [read_only]}]`). For a policy with those two
scopes and a device `core1` with `tier: core`, `port49 policy test` prints, with nothing about `per_login_mfa`:

```text
platform_set: 1.0.0
keys: checked against the default key_secret_refs (env: variables starting PORT49_KEY_, file: under /run/port49/keys); pass --config to check port49d.yaml's
report: group_subject: subject "netops" is a group: subject: it mints only with broker.directory configured, through which the broker matches a person to the group; explain and policy tests evaluate it by name
PASS netops on core1: "show version" -> permit permit_dominates
1 tests, 0 failed; 0 shadowed denies, 0 unacknowledged; 0 quarantined, 0 projection refusals
```

`port49 explain` on `core1` still prints the requirement, `per_login_mfa accept hardware_key_touch (defaults ∩ scope core); reuse_for 5m (scope core); applies to humans`.

Do not put the requirement on an `on_missing: exclude` scope to be able to grant on it.
`port49 policy test` reports that shape as `per_login_mfa_on_missing_exclude`: a sync that drops `tier` lifts the
per-login proof from the device.

`accept` is a list of `hardware_key_touch` (a touch on the token holding the session key), `idp_mfa` (a fresh
identity-provider sign-in showing a second factor) or both. Leaving the block out means no requirement; there
is no `none`. `reuse_for` is how long one proof covers later logins, from `0m` (a proof at every login) to `8h`,
and `15m` when left out.

The levels stack and the strictest wins. On a device the requirement is the **intersection** of the `accept`
lists of every level that applies, with the least `reuse_for`, and a lower level never weakens a higher one.
An empty intersection is a load error naming both levels. A scope that selects by an attribute other than
`name` must declare `on_missing` and `security_log: true`, since whoever edits the attribute can lift the
requirement; `port49 policy test` also reports `per_login_mfa_on_missing_exclude` where an exclude scope
could lose it. A scope pinned by `name` needs neither.

A machine principal is exempt except under a level that sets `applies_to_machines: true`, and a workload proves
with `hardware_key_touch` alone, from a key and touch slot on one token. A mint under an unmet requirement is
answered `deny` with the reason `per_login_mfa_required` and a challenge; a requirement no method this broker
can verify satisfies is `per_login_mfa_unavailable` for that device. A requirement gates logins and refreshes,
never a live session: adding one revokes nothing. `port49 policy diff` fails, as `per_login_mfa_weakened`, on a weakening
that no session test asserts. The test must be new or changed against the old file; one carried over
unchanged does not count. Widening the scope above to `accept: [hardware_key_touch, idp_mfa]` prints
`per_login_mfa_weakened: netops on core1: accept [hardware_key_touch] reuse_for 5m (defaults ∩ scope core) -> accept [hardware_key_touch, idp_mfa] reuse_for 5m (defaults ∩ scope core); no session test asserts it: add {subject: netops, device: core1, per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 5m}}`
and exits 1.

## Reading why a grant applied

Offline, `port49 explain` shows the subject, the grants that matched, the roles (and which scope attached
each), the level, the ceiling, the session age and the `per_login_mfa` requirement for one device, with the
reason a command was permitted or denied:

```sh
port49 explain --policy policy.yaml --inventory inventory.yaml --subject netops --device leaf1
```

Signed in, `port49 identity` prints whom the broker resolves you to (your subject, grants, `api:` rights) and
`port49 explain --device NAME` asks the broker the same question from the policy in force. The `per_login_mfa`
line reads, for example, `per_login_mfa accept hardware_key_touch (defaults ∩ scope core); reuse_for 5m (scope core); applies to humans`, or `per_login_mfa none`: the default is never invisible.

For a review, `port49 access review --policy FILE --inventory FILE --subject NAME` prints one subject's grant
table, with the roles, ceiling, expiry and device count per row. To offboard a machine subject or a literal
identity, `port49 grants remove --subject NAME` prints the policy without the subject's grants and its block,
`--write` replaces the file, and `--pr` opens the pull request that carries the removal; the result must load
against the inventory before anything is written. People in a directory group are offboarded in the directory.
