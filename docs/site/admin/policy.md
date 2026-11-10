---
title: Policy
description: Writing the policy file that decides who may log in to which devices and what they may run, and checking a change before it ships.
---

# Policy

The policy file decides who may log in to which devices and what they may run there. It is one YAML
document that lives in your repository, so a change to access is a change to a file that someone reviews,
tests and diffs before it ships.

port49d reads the file on its watch interval and at SIGHUP, and refuses a file that does not load. The tools
that check a change run offline, against the policy and the inventory file, so CI can run them and nothing
needs a broker.

This page shows how the pieces of the file fit together, how to write tests for it and how to review a
change. Every key is in the [policy reference](../reference/config/policy.md).

## The pieces

A decision is made in four steps, and each has a block in the file:

1. A **subject** says who: a directory group of people (`group:`), a group of workloads
   (`machine_group:`), or a list of literal identities (`identity:`).
2. A **scope** says where: a selector over inventory attributes, such as `site` or `os_version`.
3. A **role** says what: the command rules it permits and denies, a privilege level, and how long a session
   may last.
4. A **grant** ties a subject to a scope with roles.

Roles and grants have [their own page](roles-and-grants.md). This is a policy that decides one thing:

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

The `keys:` and `key_groups:` blocks say which shared secret admits which device; they are covered in
[Key rotation](key-rotation.md). The `tests:` block is covered in [Writing tests](#writing-tests).

An unknown key, or a second document in the file, is refused, and the error names the key or the line.

## Writing a rule

A rule is a list of terms matched against the command, one term per argument:

| Term | Matches |
|---|---|
| `word` | that argument, ignoring case |
| `*` | exactly one argument, any value |
| `**` | any number of arguments; only as the last term |
| `@class` | one argument in a named set of entity names the platform defines |
| `/regex/` | one argument matching the RE2 expression |

A rule matches the whole command. `show bgp summary` does not match `show bgp summary detail` unless the
rule ends in `**`.

### When a permit and a deny both match

When several roles apply, their permits and denies are pooled. **A permit wins only if it is more specific
than every deny that matches the command, at every word; otherwise the command is denied.** Two examples:

- A permit of `show **` does not beat a deny of `show running-config **`, because the deny names more of the
  command.
- A permit of `copy **` against a deny of `* * /^(tftp|ftp):/`: the permit names the command and the deny names
  the destination. Each wins a different word, neither dominates, and the deny stands.

Prefer literals, `*` and classes to regexes. A regex is the one term whose reach `port49 policy diff` cannot
enumerate.

A regex in a deny may not turn case-insensitivity off. port49 matches ignoring case, so a case-sensitive deny
could be walked past by changing the case of what is typed. A regex in a permit may.

### Output modifiers

Output modifiers after a pipe are judged apart from the command, against the role's `pipe:` list. The list
defaults to `include **`, `exclude **`, `begin **`, `section **`, `json`, `count` and `no-more`. A role that
sets `pipe: {permit: []}` allows no pipe at all.

## Scopes

A scope selects devices by inventory attribute. `match: {site: [dc1, dc2], role: [leaf, spine]}` is every
device whose `site` is `dc1` or `dc2` and whose `role` is `leaf` or `spine`. A scope with no `match` selects
every device, and `match: {name: core-sw01}` pins one.

A version key takes a comparison, such as `os_version: {lt: "4.31.2F"}`. The comparison orders vendor version
strings token by token, not as semver.

### `on_missing`

Sometimes the inventory cannot describe a device: the sync dropped its `os_version`, or its version string
cannot be ordered. The device then has no value for a match key, and `on_missing` says which way it goes:
`include` puts it in the scope, `exclude` leaves it out.

The safe direction depends on what the scope does:

- A scope that **delivers a deny** is the one a broken sync could silently lift. A missing value should mean
  the device is *affected*: `on_missing: include`.
- A scope that **gives access** should leave out a device it cannot describe: `on_missing: exclude`.

port49 refuses to guess. A scope with a match key that delivers a deny must write `on_missing`, whether the
deny comes through `attached_roles` or through a grant whose role holds a deny. A file that leaves it out does
not load. Any other scope takes `on_missing: exclude`.

### The include-scope grant refusal

A **grant on an `on_missing: include` scope is refused at load**, whatever its roles carry. The reason: a
grant is what lets a login reach a device, even when its roles only deny. On an include scope, a device the
inventory cannot describe would get a session from the grant alone. (A scope with no match key, or one pinned
by `name` alone, is the exception; see the end of this section.)

The error reads:

```text
grants[1] (subject netops, scope eos_unpatched): scope "eos_unpatched" is on_missing: include and a grant lets
a login reach a device even when its roles only deny, so a device the inventory cannot describe would get a
session from this grant; put the grant on a separate scope with the same match and on_missing: exclude, and
put a mitigation's deny in the include scope's attached_roles (spec §5.5)
```

The fix is two scopes with the same match. The deny goes on the include scope, and the grant on the exclude
one:

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

An include scope may attach only roles that cannot widen access: no `permit`, no `privilege`, no
`attributes`. A role that carries one is refused at load, and the error says to put it on an exclude scope.

The exception, for both the grant refusal and the attached-roles rule, is a scope with no match key, or one
pinned by `name` alone. It has no attribute a device could be missing, so it has nothing to include.

### `security_log`

Whoever can edit `os_version` can lift a mitigation without touching the policy, and the inventory is often
written by a discovery tool rather than a person. `security_log` makes a device joining or leaving a scope a
security record in the log.

It **defaults to true** for a scope that delivers a deny, so the log says when a device left the mitigation.
A scope with `per_login_mfa` and a match key other than `name` must say `security_log: true` outright.

Writing `security_log: false` on a deny-bearing scope is allowed, because the file chose it, and
`port49 policy test` reports it:

```text
report: deny_scope_unlogged: scope "eos_unpatched" delivers a deny and says security_log: false: an edit of
os_version or platform that lifts the deny leaves no record (spec §5.5)
```

The report does not fail the run. Remove the line, or write `true`, unless you have a reason to want the
silence.

## Writing tests

Tests are the policy's own statement of what it should decide. They do two jobs:

- `port49 policy test` runs every test and fails when one does not hold, so a change that breaks an intended
  decision fails CI.
- `port49 policy diff` reads the **passing** tests in the new file as the author's evidence that a widening of
  access is intended. A widening no test (or [`acknowledge:`](#acknowledge) entry) accounts for fails the diff.

Tests go in the top-level `tests:` list. There are two kinds:

- A **command test** has a `command:`. It asks: would this subject be permitted this command on this device?
- A **session test** has no `command:`. It asserts what a login to the device gets: its privilege level, its
  ceiling, its reply attributes, the subject's API rights or its per-login MFA requirement.

### Who and where

Every test names who it runs as and the device it runs against:

| Key | What it says | Example |
|---|---|---|
| `subject` | the subject the test runs as | `subject: netops` |
| `principal` | a principal identity, in any form `identity:` takes; the test runs as whichever subject it resolves to | `principal: "user:alice@example.com"` |
| `device` | an inventory device; required | `device: leaf1` |

Give `subject` or `principal`, exactly one. A device the inventory does not name fails the test.

A test is answered in the order the broker answers a mint, as `port49 explain` does:

- a subject with no grant on the device is a deny, `no_grants_matched`;
- a device with no platform is refused, `device_unconfigured`;
- any subject on a quarantined device is a deny, `device_quarantined`;
- a mint the broker would refuse permits nothing.

### Command tests

| Key | What it says | Example |
|---|---|---|
| `command` | the command line, as a person would type it | `command: "show running-config"` |
| `expect` | `permit` or `deny`; required on a command test | `expect: deny` |
| `reason` | the reason code the decision must carry, from the [reason codes](../reference/reason-codes.md) | `reason: no_permit_dominates_deny` |

The command is evaluated on the words the device sends for it. Where a platform splits an interface name from
its index (IOS-XE), the test splits it the same way.

**What `reason:` adds.** Without it, a test checks only the verdict. An `expect: deny` test passes whatever
caused the deny, including a reason you did not mean: the subject lost its grant (`no_grants_matched`), or the
device was quarantined. With `reason:`, the test also pins *why*. For example, this test passes only while a
deny rule is what refuses the command:

```yaml
tests:
  - {subject: netops, device: leaf1, command: "show running-config", expect: deny, reason: no_permit_dominates_deny}
```

`reason:` is checked on a permit test too (a permit carries `permit_dominates`). It must be a code from the
closed vocabulary, or the file does not load.

### Session tests

A session test takes no `expect` or `reason`. It names at least one of these keys, and passes where the subject
would be minted a token on the device with every value it names:

| Key | What it asserts | Example |
|---|---|---|
| `level` | the privilege level the subject is minted a token at | `level: operator` |
| `max_privilege` | the ceiling the token carries, a level or `none` | `max_privilege: none` |
| `priv_lvl` | the `priv-lvl` number (0 to 15) the reply carries, or `none`; `015` reads as 15 | `priv_lvl: 15` |
| `enable` | the subject's enable mode: `none`, `auto` or `token` | `enable: none` |
| `reply` | the exact session reply, in order; an empty list asserts an empty reply | `reply: ["priv-lvl=1", "roles=network-operator"]` |
| `api` | the subject's broker API rights, the whole list, in any order | `api: [explain_others]` |
| `per_login_mfa` | the effective per-login requirement, `none` or a mapping of `accept` and `reuse_for` | `per_login_mfa: none` |

A session test fails where no token would be minted, for example where the subject has no grant on the
device. The one exception is a test that asserts `api` and nothing else: API rights belong to the subject, not
to a session, so that test passes on any device.

### How a test clears a `policy diff` label

Each label in the [`policy diff` table](#port49-policy-diff) is cleared by a different kind of test. The test
must be in the new file and must pass.

| Label | The test that clears it |
|---|---|
| `EXPANDS` | a command test with `expect: permit` on a command the change frees, on a device of that group. One test clears every command shape of the same deny and permit; in the example below, one test clears three lines. |
| `RAISES` | a session test asserting the new value. The diff prints the test to add. |
| `REGEX-CONSTRAINED` | a passing command test with `expect: permit` on a command the changed rule decides, or, for a deny, on a command it used to refuse. A wider deny whose freed commands you cannot name takes an [`acknowledge:`](#acknowledge) entry. |
| `API` | a session test whose `api:` lists the subject's whole new list. The diff prints the test to add. |
| `PRINCIPAL`, `USERNAME` | a session test naming the principal (`principal:`); a test that asserts only `api` does not count. A `USERNAME` change is cleared by a test naming any one of the subject's principals. A `PRINCIPAL` change whose new subject gains API rights also needs `api:` with the subject's whole list. |
| `per_login_mfa_weakened` | a session test with `per_login_mfa:` asserting the new requirement, which is **new or changed** against the old file. A test carried over unchanged does not count. |
| `SUBJECT` | a session test naming the subject. |

A test that expects `deny` never clears a widening, since it cannot tell a deny rewritten narrower from one
rewritten wider. `ADAPTER`, `QUARANTINES`, `REFUSED` and `UNRESOLVED` are not cleared by tests.

Once a test clears a label, the diff still prints the change, in lowercase and marked, and passes:
`EXPANDS:` becomes `expands (a policy test exercises it):`, and `RAISES:` becomes
`raises (a session test asserts it):`.

### A worked example

The `read_only` role from the policy above gains a deny, and a test pins it:

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

That is the version on `main`. A pull request now deletes the `deny:` line, which lets `netops` read the
running configuration. The first thing to fail is the test that pinned the deny. `port49 policy test` on the
new file prints:

```text
FAIL netops on leaf1: "show running-config" -> permit permit_dominates, want deny no_permit_dominates_deny
3 tests, 1 failed; 0 shadowed denies, 0 unacknowledged; 0 quarantined, 0 projection refusals
```

and exits 1. `port49 policy diff --old main-policy.yaml --new policy.yaml --inventory inventory.yaml` shows the
widening, one line per command shape the deny used to cover, and exits 1:

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

Now `port49 policy test` prints `PASS netops on leaf1: "show running-config" -> permit permit_dominates` and
exits 0, and `port49 policy diff` prints the same three changes as cleared and exits 0:

```text
expands (a policy test exercises it): netops on leaf1: "show running-config" was denied by "show running-config **" (read_only), now permitted by "show **" (read_only)
expands (a policy test exercises it): netops on leaf1: "show running-config <any other argument>" was denied by "show running-config **" (read_only), now permitted by "show **" (read_only)
expands (a policy test exercises it): netops on leaf1: "show running-config <any other argument> <any other argument>" was denied by "show running-config **" (read_only), now permitted by "show **" (read_only)
3 commands changed: 3 widen, 0 narrow; 0 unacknowledged expansions past a deny; 0 unacknowledged privilege raises; 0 unacknowledged per_login_mfa weakenings; 0 unacknowledged regex-constrained widenings; 0 unacknowledged principal or username changes; 0 devices newly quarantined, 0 released; 0 mints newly refused; 0 unresolved; 0 unacknowledged adapter edits; 0 projection refusals; 0 devices newly refused admission
```

The reviewer sees one changed test line beside the removed deny: the widening is written down and tested.
In CI, the job in [Run the checks in CI](#run-the-checks-in-ci) blocks the first version of the pull request
and passes the second.

A privilege raise works the same way, with a session test. If the same pull request had changed `read_only`'s
`privilege: readonly` to `privilege: operator`, the diff would print the test it needs:

```text
RAISES: netops on leaf1: level readonly -> operator, max_privilege none -> none, priv_lvl 1 -> 15, enable none -> none, reply ["priv-lvl=1", "roles=network-operator"] -> ["priv-lvl=15", "roles=network-operator"]; no session test asserts it: add {subject: netops, device: leaf1, priv_lvl: 15, level: operator}
```

Paste `{subject: netops, device: leaf1, priv_lvl: 15, level: operator}` under `tests:`, and the line becomes
`raises (a session test asserts it): ...` and passes.

## Checking a change

Four commands read the policy: `port49 policy test`, `port49 policy diff`, `port49 policy replay` and
`port49 explain`. They take `--policy FILE --inventory FILE` (`policy diff` takes `--old` and `--new` with one
`--inventory`). They never read a secret, and with the files given they never ask a broker. Every rule and
command they print is redacted as the daemon's records are.

### `port49 policy test`

```sh
port49 policy test --policy policy.yaml --inventory inventory.yaml [--config port49d.yaml]
```

It loads the policy against the inventory as port49d does, so every load error is a failure here. Then it
prints, in order: the platform set, the key check, the reports, the shadowed-deny report, one line per test, and
a summary. For the policy above, against an inventory whose `leaf1` is an `arista_eos` device with `site: dc1`
and `role: leaf`, it prints:

```text
platform_set: 1.3.0
keys: checked against the default key_secret_refs (env: variables starting PORT49_KEY_, file: under /run/port49/keys); pass --config to check port49d.yaml's
report: group_subject: subject "netops" is a group: subject: it mints only with broker.directory configured, through which the broker matches a person to the group; explain and policy tests evaluate it by name
PASS netops on leaf1: "show version" -> permit permit_dominates
PASS netops on leaf1: "configure terminal" -> deny no_rule_matched
2 tests, 0 failed; 0 shadowed denies, 0 unacknowledged; 0 quarantined, 0 projection refusals
```

It exits 1 when any of these holds:

- the policy does not load;
- a test fails;
- a deny is shadowed by a more specific permit and no test exercises it;
- a device is quarantined, now or at a later grant expiry;
- a composition gets a projection's fail-closed reply;
- admission refuses a device;
- a key problem exists: no `keys:` block, a `key_ref` the block does not define, or a `secret_ref` outside
  `key_secret_refs`.

Pass `--config` to check against your port49d.yaml's `key_secret_refs`, which is the only key it reads from that
file. Without it, the default allowance is used and the output says so.

Lines that begin `report:` are lint findings. They are review questions, not failures. They include
`deny_scope_unlogged` above, `no_tests` for a file with no tests, `grantless_subject`, `api_rights` for each
subject that holds an `api:` list, `group_subject`, `acknowledge_stale`, `dead_rule`, `fallback_exposure` and the
projection reports. Read them; they are what a reviewer would ask.

### `port49 policy diff`

```sh
port49 policy diff --old main-policy.yaml --new policy.yaml --inventory inventory.yaml
```

Run it in CI on every pull request that touches the policy ([Run the checks in CI](#run-the-checks-in-ci)). It compares the two files for every subject on
every device, over every command shape the rules distinguish, now and at every later grant expiry. It prints
each change, and exits 1 on a **widening** that no test or acknowledgment accounts for.

These labels fail the run. [Writing tests](#how-a-test-clears-a-policy-diff-label) shows the test that clears
each one.

| Label | The change | What clears it |
|---|---|---|
| `EXPANDS` | a command the old version refused with a deny, at a pipeline stage or on a quarantined device, that the new one permits | a passing test with `expect: permit` on that command, on a device of that group |
| `RAISES` | a privilege level, `priv_lvl`, `max_privilege` ceiling or `enable` mechanism that went up, or a reply that changed | a session test (no `command:`) asserting the new value |
| `REGEX-CONSTRAINED` | a permit with a regex or class term added, or a deny with one removed or rewritten | a passing `permit` test on a command that rule decides, or an `acknowledge:` entry for a deny |
| `API` | `api:` rights added to a subject | a session test with `api:` listing the subject's whole list |
| `PRINCIPAL`, `USERNAME` | an identity that now resolves to another subject, or a `username:` that changed | a session test naming the principal |
| `per_login_mfa_weakened` | a `per_login_mfa` requirement removed or loosened on a device | a session test asserting the new requirement that is **new or changed** against the old file; a test carried over unchanged does not count |
| `SUBJECT` | a subject's `group:` or `machine_group:` changed, or a new group subject was added | a session test naming the subject |
| `ADAPTER` | an edit to a platform adapter key that changes what port49 decides | an `acknowledge:` entry (below) |
| `QUARANTINES`, `REFUSED`, `UNRESOLVED` | a device newly quarantined, a mint or admission newly refused, a composition the diff could not compare | fix the cause; no test clears these |

A test that expects `deny` never acknowledges a widening. The last line of the output counts each kind. A
lowering, such as a narrower permit or a dropped right, prints and passes.

#### `acknowledge:`

Some widenings have no command to flip. A deny rewritten wider, such as `/^(wri|rel)/ **` as `/^wri/ **`, frees
commands the diff cannot list. An adapter edit changes what port49 reads. The author acknowledges these in
writing, in a top-level block that review reads beside the change:

```yaml
acknowledge:
  - {role: guard, rule: "/^(wri|rel)/ **", reason: "rewritten as /^wri/: rel* commands are allowed on purpose"}
  - {platform: juniper_junos, field: rpc_entry_denies, sha256: <sha256>, reason: "moved to set 1.2.0"}
```

There are two kinds of entry:

- A `role` and `rule` entry names the exact removed or rewritten rule.
- A `platform`, `field` and `sha256` entry names the digest `policy diff` prints for the key's new value, so it
  covers that edit and no later one.

`reason` is required in both. An entry that matches nothing is reported as `acknowledge_stale` and acknowledges
nothing; delete it. Do not use `acknowledge:` for an ordinary expansion: a literal deny removed is cleared by a
test, and an entry for it is reported stale.

#### The ceiling line

```text
session ceiling: netops on 1 devices: 8h0m0s or the default, whichever is less -> 24h0m0s (may lengthen: depends on session.max_session_age_default)
```

The `session ceiling:` line says that a subject's `max_session_age` changed: the least of its roles' values, on
how many devices, from what to what. It prints and does not fail the run, because a longer session is not a
wider permission. It is what you read when a change touches `max_session_age`.

A lengthened ceiling reaches live sessions only when they refresh. This line is not the `max_privilege` ceiling:
a raise of that is a `RAISES` and fails.

#### A new grant is a reviewer's call: the gate does not see it

The gate judges commands that a deny, a pipeline stage or a quarantine used to refuse. A new grant is none of
those. A subject that had no grant on a device and now has one gets a single line,

```text
access: netops gains every grant on leaf1, leaf2
```

and the diff exits 0. A new role on a device the subject already reaches is a `widens:` line per command shape
(`widens: netops on leaf1: "ping length" was no_rule_matched, now permitted by "ping *" (extra)`), and that
exits 0 too. No test is demanded for either.

Who gets access to what is a decision for the person reviewing the pull request. Read every `access:` and
`widens:` line, and run `port49 access review --policy FILE --inventory FILE --subject NAME` to see one
subject's grants, how many devices each reaches and when each expires.

Only a grant to an existing, unchanged subject is ungated. The gate still catches:

- a **new `group:` or `machine_group:` subject**, whatever its grants: it exits 1 on a
  `SUBJECT: NAME's none -> group ...` line until a session test names the subject (a new `identity:` subject is a
  `PRINCIPAL`);
- a grant that adds `api:` rights;
- a new identity for an existing subject, or a changed group;
- a `per_login_mfa` weakening that no new or changed session test asserts;
- a privilege raise on a device the subject already reached.

### Run the checks in CI

Run both checks in the CI of the repository that holds your policy, so a failed check blocks the merge:

- **`port49 policy test`** on every change.
- **`port49 policy diff`** on every pull request, with `--old` taken from the branch the pull request
  merges into (`git show origin/main:policy.yaml > /tmp/old-policy.yaml`) and `--new` the pull request's
  file.

Both exit 1 on a failure (and 2 on a usage error), so any nonzero exit fails the job. Neither reads a
secret or asks a broker, so the job needs no credentials. Here is a GitHub Actions job; any CI that can run
a shell works the same way:

```yaml
name: policy
on: pull_request
jobs:
  policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - name: Install port49
        env:
          PORT49_VERSION: "0.1.0"
        run: |
          base="https://github.com/blanketfish/port49/releases/download/v${PORT49_VERSION}"
          cd "$RUNNER_TEMP"
          curl -fsSLO "${base}/port49_${PORT49_VERSION}_linux_amd64.tar.gz"
          curl -fsSLO "${base}/SHA256SUMS"
          sha256sum --ignore-missing -c SHA256SUMS
          tar -xzf "port49_${PORT49_VERSION}_linux_amd64.tar.gz" port49
          echo "$RUNNER_TEMP" >> "$GITHUB_PATH"
          "$RUNNER_TEMP/port49" --version
      - name: port49 policy test
        run: port49 policy test --policy policy.yaml --inventory inventory.yaml
      - name: port49 policy diff
        run: |
          git fetch --depth=1 origin "$GITHUB_BASE_REF"
          git show FETCH_HEAD:policy.yaml > "$RUNNER_TEMP/old-policy.yaml"
          port49 policy diff --old "$RUNNER_TEMP/old-policy.yaml" --new policy.yaml --inventory inventory.yaml
```

The install step pins a release and checks it against the release's `SHA256SUMS`; raise
`PORT49_VERSION` when you upgrade. [Install the clients](../operate/install/clients.md#download-a-release)
has the same steps for a workstation. In the
[worked example](#a-worked-example), this job fails the pull request that deletes the deny at its
`policy test` step, and passes once the test is turned around.

### `port49 policy replay`

```sh
port49 policy replay [--line N] [--policy FILE --inventory FILE] decisions.jsonl
```

It re-runs the decisions in a [decision log](../reference/decision-log.md) against the policy blob each record
carries. Use it to check that this build still decides as the build that wrote the record did, or to audit a
past decision.

It prints each record that diverged and a summary,
`replayed N records: A agree, D diverge, U unverifiable; S not replayed`, and exits 1 if any diverged or could
not be verified. A record denied before policy ran is counted and not replayed.

- With `--policy` and `--inventory`, it rebuilds a blob a redacted record hid.
- With `--line N`, it replays one record and prints it either way.
- Give `-` instead of a file to read the log from standard input.

### `port49 explain`

`explain` answers one hypothetical question: what would port49 decide for this subject, on this device, for
this command?

```sh
port49 explain --policy policy.yaml --inventory inventory.yaml --subject netops --device leaf1 \
  --command "configure terminal"
```

```text
deny no_rule_matched
  subject     netops
  device      leaf1 (arista_eos)
  grants      dc_fabric [read_only]
  roles       read_only
  level       readonly; max_privilege none
  session     max_session_age 8h0m0s (the least of its roles')
  per_login_mfa none
  command     configure terminal
  rule        no permit matches
  permitted by none
note: arista_eos does not declare config_commands: whether a command typed in configuration mode is sent to port49 at all is unmeasured, so if this is a configuration-mode command the device may apply it whatever this answer says (spec §9, §12)
```

It prints exactly one reason from the [reason codes](../reference/reason-codes.md), and, for a denial, names the
role that would permit the command. It exits 0 whether the answer is permit or deny; a nonzero exit means a
policy or a name did not load.

Leave out `--command` to see the session instead, and add `--show-attributes` to see each session attribute and
where it came from.

`explain` also tells you when the platform cannot enforce the control you asked about, rather than reporting a
decision the device will not honor. On a platform that authorizes sessions only, the note says that a session
ceiling, a revocation, a username change and the session-ceiling warning act at the next authorization request:

- On Junos (`juniper_junos`), the device makes one after login only if `authorization-time-interval` is set.
  With it set, Junos asked again once an interval after login, a revoked principal was denied there, and the
  denial did not end the session ([L36-juniper_vjunos-router.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vjunos-router.md), [L36-juniper_vsrx.md](https://github.com/blanketfish/port49/blob/main/tests/lab/results/L36-juniper_vsrx.md)).
  On a projected Junos the note also names what ends an idle session: the class `idle-timeout` that
  `port49 platform export --classes` renders from `max_session_age`.
- On any other session-only platform, the device is not known to make one after login, and the note says not to
  rely on these controls there.

!!! warning "Unmeasured: a second re-authorization"
    Whether Junos re-authorizes an open session more than once, so whether a control made after the first ever reaches it, is unknown ([L40](../reference/lab-register.md#l40), open). Do not rely on these controls to end a live Junos session.

With neither `--policy` nor `--inventory`, `explain` asks the broker through your agent, from the policy in
force: `port49 explain --device leaf1 --command "show version"`. Explaining another person with `--principal`
needs `api: [explain_others]`. The broker's `explain` records carry hypothetical verdicts, so a dashboard of
denials should filter `event!="explain"`.

## Platform sets

The shipped adapters say what each platform's reply looks like, which commands it sends and how its privilege
is rendered. They come in numbered **platform sets**, and your policy pins one with `platform_set:`.

A policy that pins none renders with `1.0.0` on every later binary, so upgrading port49 never changes what a
policy renders. `port49 platform list` and `show` print the newest set unless you pass `--set` or the policy.

Only `juniper_junos` differs between the sets; the other shipped adapters are the same in every one.

| Set | What it adds |
|---|---|
| `1.0.0` | The first set. Junos is session-only and no level is rendered. |
| `1.1.0` | Junos renders your command rules into the session reply (`command_projection: junos_regex`): permission bits with each bit's reach, carve-outs and the smallest bits a grant needs. |
| `1.2.0` | `rpc_entry_denies: ["junoscript **", "op **"]` on Junos. Where a deny is the only guard beneath a sent bit, the reply adds these denies, which close the CLI's `xml-mode` and `op url` routes into a native RPC and that session's NETCONF. |
| `1.3.0` | `deny_reach_bits: [view-configuration]` on Junos. A reply may send the `view-configuration` bit where the grant permits a carve-out of it, with the rest of the bit's reach denied on the wire. It is read only where `rpc_entry_denies` is kept. |

The routes `rpc_entry_denies` closes, and the bits `deny_reach_bits` covers, were measured on the two Junos
images the [Junos page](devices/juniper-junos.md) lists, and the evidence table there links each note.

!!! warning "Unmeasured"
    Whether the `junoscript` deny also closes REST, the XML API, `outbound-ssh` and `scp` is unknown ([L59](../reference/lab-register.md#l59), open),
    and so is what these replies do on a Junos release or hardware family the lab did not run. Test a policy on
    the device before you rely on it there.

### `port49 platform upgrade`

A moved pin changes what the policy renders, so moving it is a reviewed change. Do not edit `platform_set`
by hand; run:

```sh
port49 platform upgrade --policy policy.yaml --inventory inventory.yaml --to 1.3.0
```

It prints exactly what the move changes:

- each adapter key that differs on a platform your inventory has, and how many devices and subjects it reaches;
- the `acknowledge:` entry each gated key needs, ready to paste;
- each key a `platforms:` block keeps its own value for while the built-in under it changes;
- what the move would quarantine or fail closed.

For a policy pinned to `1.1.0` and an inventory with one Junos device, the move to `1.3.0` prints:

```text
platform_set 1.1.0 -> 1.3.0
  platforms.juniper_junos.rpc_entry_denies
    null -> ["junoscript **","op **"]
    affects 1 devices, 0 subjects
    gated: add {platform: juniper_junos, field: rpc_entry_denies, sha256: <sha256>, reason: "..."} under acknowledge:
  platforms.juniper_junos.deny_reach_bits
    null -> ["view-configuration"]
    affects 1 devices, 0 subjects
    gated: add {platform: juniper_junos, field: deny_reach_bits, sha256: <sha256>, reason: "..."} under acknowledge:
  port49 policy diff fails on the move until every gated entry above is under acknowledge: (spec §12); it also shows the replies the move changes
```

(The `<sha256>` placeholders stand for the 64-character digests the tool prints; copy them from your own run.)

It writes nothing unless you add `--write`, which rewrites the pin in the file and nothing else. Then:

1. Commit the policy.
2. Let `port49 policy diff` show the replies the move changes.
3. Add the `acknowledge:` entries it asks for, each with a reason a reviewer can read.

The diff fails on the move until each gated key is acknowledged.
