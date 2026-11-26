---
title: Rules and scopes
description: How permit and deny rules match, how scopes select devices, and what happens when the inventory cannot describe a device.
---

# Rules and scopes

[Policy](policy.md#writing-a-rule) shows how a rule is written. This page covers how rules combine and how a scope
chooses devices.

## When a permit and a deny both match

When several roles apply, their permits and denies are pooled. A permit wins only if it is more specific than every
deny that matches the command, at every word. Otherwise the command is denied. Two examples:

- A permit of `show **` does not beat a deny of `show running-config **`, because the deny names more of the command.
- A permit of `copy **` against a deny of `* * /^(tftp|ftp):/`: the permit names the command and the deny names the
  destination. Each wins a different word, neither dominates, and the deny stands.

Prefer literals, `*` and classes to regexes. A regex is the one term whose reach `port49 policy diff` cannot
enumerate. A regex in a deny may not turn case-insensitivity off, because port49 matches ignoring case and a
case-sensitive deny could be walked past by changing the case of what is typed. A regex in a permit may.

### Output modifiers

Output modifiers after a pipe are judged apart from the command, against the role's `pipe:` list. The list defaults to
`include **`, `exclude **`, `begin **`, `section **`, `json`, `count` and `no-more`. A role that sets
`pipe: {permit: []}` allows no pipe at all.

## Scopes

A scope selects devices by inventory attribute. `match: {site: [dc1, dc2], role: [leaf, spine]}` is every device whose
`site` is `dc1` or `dc2` and whose `role` is `leaf` or `spine`. A scope with no `match` selects every device, and
`match: {name: core-sw01}` pins one.

A version key takes a comparison, such as `os_version: {lt: "4.31.2F"}`. The comparison orders vendor version strings
token by token, not as semver.

### `on_missing`

Sometimes the inventory cannot describe a device: the sync dropped its `os_version`, or its version string cannot be
ordered. The device then has no value for a match key, and `on_missing` says which way it goes: `include` puts it in the
scope, `exclude` leaves it out. The safe direction depends on what the scope does:

- A scope that delivers a deny is the one a broken sync could silently lift. A missing value should mean the device is
  affected: `on_missing: include`.
- A scope that gives access should leave out a device it cannot describe: `on_missing: exclude`.

port49 refuses to guess. A scope with a match key that delivers a deny must write `on_missing`, whether the deny comes
through `attached_roles` or through a grant whose role holds a deny. A file that leaves it out does not load. Any other
scope takes `on_missing: exclude`.

### The include-scope grant refusal

A grant on an `on_missing: include` scope is refused at load, whatever its roles carry. A grant is what lets a login
reach a device, even when its roles only deny, so on an include scope a device the inventory cannot describe would get a
session from the grant alone. The error reads:

```text
grants[1] (subject netops, scope eos_unpatched): scope "eos_unpatched" is on_missing: include and a grant lets
a login reach a device even when its roles only deny, so a device the inventory cannot describe would get a
session from this grant; put the grant on a separate scope with the same match and on_missing: exclude, and
put a mitigation's deny in the include scope's attached_roles (spec §5.5)
```

The fix is two scopes with the same match. The deny goes on the include scope and the grant on the exclude one:

```yaml
scopes:
  - name: eos_unpatched
    match: {platform: arista_eos, os_version: {lt: "4.31.2F"}}
    on_missing: include
    security_log: true
    attached_roles:
      humans: [no_running_config]   # a role of denies alone
  - name: eos_unpatched_known
    match: {platform: arista_eos, os_version: {lt: "4.31.2F"}}
    on_missing: exclude             # a grant is earned by data

roles:
  - name: no_running_config
    deny: ["show running-config **"]
```

An include scope may attach only roles that cannot widen access: no `permit`, no `privilege`, no `attributes`. A role
that carries one is refused at load, and the error says to put it on an exclude scope.

A scope with no match key, or one pinned by `name` alone, is the exception to both the grant refusal and the
attached-roles rule. It has no attribute a device could be missing, so it has nothing to include.

### `security_log`

Whoever can edit `os_version` can lift a mitigation without touching the policy, and a discovery tool often writes the
inventory, not a person. `security_log` makes a device joining or leaving a scope a security record in the log.

It defaults to true for a scope that delivers a deny, so the log says when a device left the mitigation. A scope with
`per_login_mfa` and a match key other than `name` must say `security_log: true` outright.

`security_log: false` on a deny-bearing scope is allowed, because the file chose it, and `port49 policy test` reports it:

```text
report: deny_scope_unlogged: scope "eos_unpatched" delivers a deny and says security_log: false: an edit of
os_version or platform that lifts the deny leaves no record (spec §5.5)
```

The report does not fail the run. Remove the line, or write `true`, unless you want the silence.
