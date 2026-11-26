---
title: Policy
description: Write the policy file that decides who may log in to which devices and what they may run, and check a change before it ships.
---

# Policy

The policy file decides who may log in to which devices and what they may run there. It is one YAML document in your
repository, so a change to access is a change to a file that someone reviews, tests and diffs before it ships.

port49d reads the file on its watch interval and at SIGHUP, and refuses a file that does not load. The tools that check
a change run offline against the policy and the inventory file, so CI can run them and nothing needs a broker. Every key
is in the [policy reference](../reference/config/policy.md).

| Page | Covers |
|---|---|
| [Rules and scopes](policy-rules.md) | how a permit and a deny combine, how a scope selects devices, `on_missing` |
| [Roles and grants](roles-and-grants.md) | roles, subjects, `api:` rights, grants, `per_login_mfa` |
| [Tests](policy-tests.md) | command and session tests, and how a test clears a diff finding |
| [Reviewing a change](policy-review.md) | `policy test`, `policy diff`, replay, explain, CI |
| [Platform sets](platform-sets.md) | pinning a platform set and moving the pin |

## The pieces

A decision is made in four steps, and each has a block in the file:

1. A subject says who: a directory group of people (`group:`), a group of workloads (`machine_group:`), or a list of
   literal identities (`identity:`).
2. A scope says where: a selector over inventory attributes, such as `site` or `os_version`.
3. A role says what: the command rules it permits and denies, a privilege level, and how long a session may last.
4. A grant ties a subject to a scope with roles.

This is a policy that decides one thing:

```yaml
platform_set: 1.3.0

keys:
  core:
    current: {version: 1, secret_ref: "file:/run/port49/keys/core-v1"}

key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: core}

scopes:
  - name: dc_fabric
    match: {site: [dc1, dc2], role: [leaf, spine]}
    on_missing: exclude

roles:
  - name: read_only
    privilege: readonly
    permit: ["show **", "terminal length *"]
    max_session_age: 8h

subjects:
  - name: netops
    group: "cn=netops,ou=groups,dc=example,dc=com"
    token_ttl: 300s

grants:
  - {subject: netops, scope: dc_fabric, roles: [read_only]}

tests:
  - {subject: netops, device: leaf1, command: "show version", expect: permit}
  - {subject: netops, device: leaf1, command: "configure terminal", expect: deny}
```

The `keys:` and `key_groups:` blocks say which shared secret admits which device. [Key rotation](key-rotation.md)
covers them. An unknown key, or a second document in the file, is refused, and the error names the key or the line.

## Writing a rule

A rule is a list of terms matched against the command, one term per argument:

| Term | Matches |
|---|---|
| `word` | that argument, ignoring case |
| `*` | exactly one argument, any value |
| `**` | any number of arguments; only as the last term |
| `@class` | one argument in a named set of entity names the platform defines |
| `/regex/` | one argument matching the RE2 expression |

A rule matches the whole command. `show bgp summary` does not match `show bgp summary detail` unless the rule ends in
`**`. [Rules and scopes](policy-rules.md) says what happens when a permit and a deny both match.

## Writing tests

The `tests:` block states what the policy should decide, and `port49 policy diff` reads passing tests as evidence that a
widening is intended. [Policy tests](policy-tests.md) has the keys and a worked example.

## Checking a change

Run these before every merge, and in CI:

```sh
port49 policy test --policy policy.yaml --inventory inventory.yaml
port49 explain --policy policy.yaml --inventory inventory.yaml --subject netops --device leaf1
```

To check, `policy test` ends with a count such as `2 tests, 0 failed` and exits 0. `explain` prints the subject, the
grants that matched, the roles, the level and the session age for that device.

### port49 policy diff

`port49 policy diff --old main-policy.yaml --new policy.yaml --inventory inventory.yaml` compares two versions of the
policy for every subject on every device. It exits 1 on a widening that no test or `acknowledge:` entry accounts for.
[Reviewing a change](policy-review.md#port49-policy-diff) lists what it catches and how CI runs it.
