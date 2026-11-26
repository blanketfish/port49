---
title: Roles and grants
description: Define roles, grant them to people, groups and workloads, and read why a grant applied.
---

# Roles and grants

Three blocks of the policy file decide who gets what: a role is what may be done (command rules, a privilege level, a
session length and an optional per-login proof), a subject is who, and a grant gives a subject some roles in a scope.
Every key is in the [policy reference](../reference/config/policy.md). [Policy](policy.md) shows how the pieces fit.

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

- `privilege` names a level from `privilege_levels:`. `readonly`, `operator` and `admin` always exist and keep that
  order. You may add levels with a `parent:`, the level a platform renders the new one as where it has no rendering.
- `baseline`, `reach_deny` and `rpc_entry` are port49's own rule names, so a role called any of them is refused at load.
- `permit` and `deny` follow the rules on [Policy](policy.md#writing-a-rule). `attributes:` adds attribute strings to
  the reply, and a grant may add its own.

### `max_session_age`

`max_session_age` is how long a person's session on a device may last: at least `1m`, or `never`. The ceiling is the
least across the roles that compose on that device. A role that says nothing takes `session.max_session_age_default`
(12 hours unless you set it in [port49d.yaml](../reference/config/port49d.md)), and if every role says `never`, so does
the session. `port49 explain` prints one of these lines:

```text
max_session_age 8h0m0s (the least of its roles')
max_session_age the lesser of 8h0m0s and session.max_session_age_default
max_session_age session.max_session_age_default (no role names a finite one)
max_session_age never (every role says never)
```

They mean: every role names a duration; one names none; the default decides; no ceiling. Shortening a role reaches live
sessions at the next policy refresh. Lengthening it, or `never`, reaches a person's sessions only when they run
`port49 refresh` or log in again. `port49 policy diff` prints a
[`session ceiling:` line](policy-review.md#the-ceiling-line) for the change.

## Subjects

A subject is exactly one of three things:

| Form | Who it names | Needs |
|---|---|---|
| `group:` | a directory group of people, by name or DN | `broker.directory` ([The directory](directory.md)) |
| `machine_group:` | a group of workloads, by name or DN | a workload verifier whose `directory` maps the workload to an entry |
| `identity:` | literal principals: `user:<email>`, a SPIFFE ID, `system:serviceaccount:<namespace>:<name>`, or `app:<client_id>` | nothing |

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

A subject with both `group:` and `machine_group:`, or either with `identity:`, is refused. A subject is one
[trust domain](../concepts/trust-domains.md): a person never matches a `machine_group:` subject, a workload never
matches a `group:` subject, and `attached_roles.machines` reaches the machine domain alone. `token_ttl` (30 to 900
seconds) is required on any subject a grant names.

### `machine_group:`

A `machine_group:` names a directory group whose members are workloads. The broker resolves a workload through
`broker.identity.machines[].directory`. With no mapping the subject mints for no one, and port49d's start says so. It
declares no `username:`, and one that does is refused, because one name for many workloads would put them all in one
device login. Members take the username their own entry gives, or the one an `identity:` subject listing the same SPIFFE ID declares. See [Workloads](workloads.md).

The device sees a username, not a principal. The directory supplies a person's, so a `group:` subject, and an
`identity:` subject for a `user:` principal, declare none when `broker.directory` is on. A literal machine identity
declares one (`username: svc-config-backup` above): lowercase printable ASCII, never `remote`, a `p49-` name or a
platform's system user. A subject whose identities are all SPIFFE IDs may leave it out where the directory mapping
supplies one, and an offline `port49 policy test` reports `workload_no_username`.

### `api:` rights

A principal may always mint for itself, end its own sessions (`port49 revoke --mine`) and explain its own decisions.
Acting on other people is a right the subject declares:

```yaml
subjects:
  - name: netops_oncall
    group: "cn=netops-oncall,ou=groups,dc=example,dc=com"
    token_ttl: 300s
    api: [revoke_others, explain_others]
```

The [policy reference](../reference/config/policy.md) lists every right. `revoke_others` and `lift_revocations` revoke
and lift, and both list the revocations. `explain_others` explains another person. `forget_principals`,
`reset_second_factor`, `unlock_sign_in` and `import_enrollments` manage directory pins, second factors, locked sign-ins
and the enrollment store. Everything but `explain_others` and the list needs a press of the person's security key, bound
to that one call, so an exposed certificate or agent session alone authorizes nothing admin-level. `sync`, `keys_show`
and `replay` are reserved and grant nothing. A broker with no attestation roots refuses every admin call ([Admin
access](admin-access.md)).

CI treats an `api:` list as a grant of authority over other people's sessions. `port49 policy test` prints a
`report: api_rights` line per subject, and `port49 policy diff` fails on a subject that gains a right until a session
test asserts the whole list ([Tests](policy-tests.md#session-tests)):

```yaml
tests:
  - {subject: netops_oncall, device: leaf1, api: [revoke_others, explain_others]}
```

A lost right passes. A principal moved to a subject with more rights needs the assertion in a test naming the principal.

## Grants

```yaml
grants:
  - {subject: netops, scope: dc_fabric, roles: [read_only]}
  - {subject: netops_oncall, scope: dc_fabric, roles: [bgp_operator], max_privilege: admin, expires: "2026-12-01"}
```

A grant names a declared subject and scope and at least one role, each listed once. Two grants with the same subject,
scope and roles are refused. `expires` is a date (the start of that day, UTC) or an RFC 3339 time after which the grant
stops matching, and `policy diff` and `policy test` read the policy at every later expiry as well as now.
`max_privilege` is a ceiling on the level a token from the grant may carry, which is how far `enable` may take the
session. With no `enable` on the subject (`none` by default, or `auto` or `token`), nothing escalates to it.

A grant on an `on_missing: include` scope is refused, except on a scope with no match key or pinned by `name` alone
([the include-scope refusal](policy-rules.md#the-include-scope-grant-refusal)). When one person matches several
subjects, the grants compose and reordering them never changes a decision: roles are the union, the level is the
highest of the roles, the `max_privilege` ceiling is the highest across the grants, and `max_session_age` is the least.

### `per_login_mfa`

A policy may ask for a second factor at each login to the devices it marks. This is a proof at the device login, not the
daily sign-in. Write `per_login_mfa:` on `defaults:`, a role or a scope:

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

The scope that carries the requirement is `include`, so a device whose `tier` is missing is still held to it. A grant on
an include scope is refused, so the grant goes on `core_access`, a second scope with the same match. `port49 explain` on
`core1` prints `per_login_mfa accept hardware_key_touch (defaults ∩ scope core); reuse_for 5m (scope core); applies to humans`.
Do not put the requirement on an `on_missing: exclude` scope to be able to grant on it: `port49 policy test` reports
`per_login_mfa_on_missing_exclude`, because a sync that drops `tier` lifts the proof from the device.

`accept` is `hardware_key_touch` (a touch on the token holding the session key), `idp_mfa` (a fresh identity-provider
sign-in showing a second factor) or both, and `reuse_for` runs from `0m` to `8h` (`15m` by default). Leaving the block
out means no requirement; there is no `none`. The strictest level wins: on a device the requirement is the intersection
of the `accept` lists of every level that applies, with the least `reuse_for`, and an empty intersection is a load error.
A scope that selects by an attribute other than `name` must declare `on_missing` and `security_log: true`. A machine
principal is exempt unless a level sets `applies_to_machines: true`, and then proves with `hardware_key_touch` alone. An
unmet requirement answers `deny` with `per_login_mfa_required`, or `per_login_mfa_unavailable` when no method this broker
can verify satisfies it. It gates logins and refreshes, never a live session: adding one revokes nothing.

`port49 policy diff` fails, as `per_login_mfa_weakened`, on a weakening that no session test asserts. The test must be
new or changed against the old file. Widening the scope above to `accept: [hardware_key_touch, idp_mfa]` prints this and
exits 1:

```text
per_login_mfa_weakened: netops on core1: accept [hardware_key_touch] reuse_for 5m (defaults ∩ scope core) -> accept [hardware_key_touch, idp_mfa] reuse_for 5m (defaults ∩ scope core); no session test asserts it: add {subject: netops, device: core1, per_login_mfa: {accept: [hardware_key_touch, idp_mfa], reuse_for: 5m}}
```

## Reading why a grant applied

`port49 explain --policy policy.yaml --inventory inventory.yaml --subject netops --device leaf1` shows the grants that
matched, the roles, the level, the ceiling, the session age and the `per_login_mfa` requirement for one device
([Reviewing a change](policy-review.md#port49-explain)). Signed in, `port49 identity` prints whom the broker resolves
you to (subject, grants, `api:` rights), and `port49 explain --device NAME` asks the broker from the policy in force.
`port49 access review --policy FILE --inventory FILE --subject NAME` prints one subject's grant table.

To offboard a machine subject or a literal identity, run `port49 grants remove --subject NAME`. It prints the policy
without the subject's grants and its block, `--write` replaces the file, and `--pr` opens the pull request that carries
the removal. The result must load against the inventory before anything is written. People in a directory group are
offboarded in the directory.
