---
title: Policy tests
description: Write command and session tests that pin what a policy permits and denies, and see how a test clears a policy diff finding.
---

# Policy tests

Tests are the policy's own statement of what it should decide. They do two jobs:

- `port49 policy test` runs every test and fails when one does not hold, so a change that breaks an intended decision
  fails CI.
- `port49 policy diff` reads the passing tests in the new file as the author's evidence that a widening of access is
  intended. A widening that no test, or [`acknowledge:`](policy-review.md#acknowledge) entry, accounts for fails the
  diff.

Tests go in the top-level `tests:` list. A command test has a `command:` and asks whether a subject would be permitted
that command on a device. A session test has no `command:` and asserts what a login to the device gets.

## Who and where

Every test names who it runs as and the device it runs against:

| Key | What it says | Example |
|---|---|---|
| `subject` | the subject the test runs as | `subject: netops` |
| `principal` | a principal identity, in any form `identity:` takes; the test runs as whichever subject it resolves to | `principal: "user:alice@example.com"` |
| `device` | an inventory device; required | `device: leaf1` |

Give `subject` or `principal`, exactly one. A device the inventory does not name fails the test.

A test is answered as the broker answers a mint, as `port49 explain` does: a subject with no grant on the device is a
deny, `no_grants_matched`, a device with no platform is refused, `device_unconfigured`, any subject on a quarantined
device is a deny, `device_quarantined`, and a mint the broker would refuse permits nothing.

## Command tests

| Key | What it says | Example |
|---|---|---|
| `command` | the command line, as a person would type it | `command: "show running-config"` |
| `expect` | `permit` or `deny`; required on a command test | `expect: deny` |
| `reason` | the reason code the decision must carry, from the [reason codes](../reference/reason-codes.md) | `reason: no_permit_dominates_deny` |

The command is evaluated on the words the device sends for it. Where a platform splits an interface name from its index
(IOS-XE), the test splits it the same way.

Without `reason:` a test checks only the verdict, so an `expect: deny` test passes whatever caused the deny, even a lost
grant or a quarantine. With `reason:` it also pins why. This one passes only while a deny rule refuses the command:

```yaml
tests:
  - {subject: netops, device: leaf1, command: "show running-config", expect: deny, reason: no_permit_dominates_deny}
```

`reason:` is checked on a permit test too (a permit carries `permit_dominates`). It must be a code from the closed
vocabulary, or the file does not load.

## Session tests

A session test takes no `expect` or `reason`. It names at least one of these keys, and passes where the subject would be
minted a token on the device with every value it names:

| Key | What it asserts | Example |
|---|---|---|
| `level` | the privilege level the subject is minted a token at | `level: operator` |
| `max_privilege` | the ceiling the token carries, a level or `none` | `max_privilege: none` |
| `priv_lvl` | the `priv-lvl` number (0 to 15) the reply carries, or `none`; `015` reads as 15 | `priv_lvl: 15` |
| `enable` | the subject's enable mode: `none`, `auto` or `token` | `enable: none` |
| `reply` | the exact session reply, in order; an empty list asserts an empty reply | `reply: ["priv-lvl=1", "roles=network-operator"]` |
| `api` | the subject's broker API rights, the whole list, in any order | `api: [explain_others]` |
| `per_login_mfa` | the effective per-login requirement, `none` or a mapping of `accept` and `reuse_for` | `per_login_mfa: none` |

A session test fails where no token would be minted, for example where the subject has no grant on the device. The one
exception is a test that asserts `api` and nothing else: API rights belong to the subject, not to a session, so that
test passes on any device.

## Clearing a diff finding

The test that clears each `policy diff` label is in the [diff's table](policy-review.md#port49-policy-diff). The test
must be in the new file and must pass. A test that asserts only `api` does not clear a `PRINCIPAL` or `USERNAME` change,
and a `USERNAME` change is cleared by a test naming any one of the subject's principals. A `PRINCIPAL` change whose new
subject gains API rights also needs `api:` with the subject's whole list. A test that expects `deny` never clears a widening, since it cannot tell a deny
rewritten narrower from one rewritten wider. Once a test clears a label, the diff still prints the change, in lowercase
and marked, and passes: `EXPANDS:` becomes `expands (a policy test exercises it):`, and `RAISES:` becomes
`raises (a session test asserts it):`.

## A worked example

The `read_only` role from [the policy](policy.md#the-pieces) gains a deny, and a test pins it:

```yaml
roles:
  - name: read_only
    privilege: readonly
    permit: ["show **", "terminal length *"]
    deny: ["show running-config **"]
    max_session_age: 8h

tests:
  - {subject: netops, device: leaf1, command: "show version", expect: permit}
  - {subject: netops, device: leaf1, command: "configure terminal", expect: deny}
  - {subject: netops, device: leaf1, command: "show running-config", expect: deny, reason: no_permit_dominates_deny}
```

A pull request now deletes the `deny:` line, which lets `netops` read the running configuration. The test that pinned
the deny fails first. `port49 policy test` on the new file prints:

```text
FAIL netops on leaf1: "show running-config" -> permit permit_dominates, want deny no_permit_dominates_deny
3 tests, 1 failed; 0 shadowed denies, 0 unacknowledged; 0 quarantined, 0 projection refusals
```

and exits 1. `port49 policy diff --old main-policy.yaml --new policy.yaml --inventory inventory.yaml` shows the
widening, one line per command form the deny used to cover, and exits 1:

```text
EXPANDS: netops on leaf1: "show running-config" was denied by "show running-config **" (read_only), now permitted by "show **" (read_only)
EXPANDS: netops on leaf1: "show running-config <any other argument>" was denied by "show running-config **" (read_only), now permitted by "show **" (read_only)
EXPANDS: netops on leaf1: "show running-config <any other argument> <any other argument>" was denied by "show running-config **" (read_only), now permitted by "show **" (read_only)
3 commands changed: 3 widen, 0 narrow; 3 unacknowledged expansions past a deny; 0 unacknowledged privilege raises; 0 unacknowledged per_login_mfa weakenings; 0 unacknowledged regex-constrained widenings; 0 unacknowledged principal or username changes; 0 devices newly quarantined, 0 released; 0 mints newly refused; 0 unresolved; 0 unacknowledged adapter edits; 0 projection refusals; 0 devices newly refused admission
```

If the change is intended, say so with a test. Turn the old test around:

```yaml
  - {subject: netops, device: leaf1, command: "show running-config", expect: permit}
```

Now `port49 policy test` prints `PASS netops on leaf1: "show running-config" -> permit permit_dominates` and exits 0.
`port49 policy diff` prints the same three changes as `expands (a policy test exercises it)` and exits 0. The reviewer
sees one changed test line beside the removed deny, so the widening is written down and tested. The
[CI job](policy-review.md#run-the-checks-in-ci) blocks the first version of the pull request and passes the second.

A privilege raise works the same way, with a session test. If the same pull request had changed `read_only`'s
`privilege: readonly` to `privilege: operator`, the diff would print the test it needs:

```text
RAISES: netops on leaf1: level readonly -> operator, max_privilege none -> none, priv_lvl 1 -> 15, enable none -> none, reply ["priv-lvl=1", "roles=network-operator"] -> ["priv-lvl=15", "roles=network-operator"]; no session test asserts it: add {subject: netops, device: leaf1, priv_lvl: 15, level: operator}
```

Paste `{subject: netops, device: leaf1, priv_lvl: 15, level: operator}` under `tests:`, and the line becomes
`raises (a session test asserts it): ...` and passes.
