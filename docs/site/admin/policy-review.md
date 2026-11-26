---
title: Reviewing a policy change
description: Check what a policy change grants or removes with policy test, policy diff, replay and explain, and run the checks in CI.
---

# Reviewing a policy change

Four commands read the policy: `port49 policy test`, `port49 policy diff`, `port49 policy replay` and `port49 explain`.
They take `--policy FILE --inventory FILE` (`policy diff` takes `--old` and `--new` with one `--inventory`). They never
read a secret, and with the files given they never ask a broker. Every rule and command they print is redacted as the
daemon's records are.

## port49 policy test

```sh
port49 policy test --policy policy.yaml --inventory inventory.yaml [--config port49d.yaml]
```

It loads the policy against the inventory as port49d does, so every load error is a failure here. Then it prints the
platform set, the key check, the reports, the shadowed-deny report, one line per test and a summary. For the policy on
[Policy](policy.md), against an inventory whose `leaf1` is an `arista_eos` device with `site: dc1` and `role: leaf`:

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

`--config` checks against your port49d.yaml's `key_secret_refs`, the only key it reads from that file. Without it the
default allowance is used and the output says so. Lines that begin `report:` are lint findings, which are review
questions and not failures: `deny_scope_unlogged`, `no_tests`, `grantless_subject`, `api_rights`, `group_subject`,
`acknowledge_stale`, `dead_rule`, `fallback_exposure` and the projection reports.

## port49 policy diff

```sh
port49 policy diff --old main-policy.yaml --new policy.yaml --inventory inventory.yaml
```

It compares the two files for every subject on every device, over every command form the rules distinguish, now and at
every later grant expiry. It prints each change and exits 1 on a widening that no test or acknowledgment accounts for.
Each label is cleared by a [test](policy-tests.md#clearing-a-diff-finding) in the new file that passes:

| Label | The change | The test that clears it |
|---|---|---|
| `EXPANDS` | a command the old version refused with a deny, at a pipeline stage or on a quarantined device, that the new one permits | a command test with `expect: permit` on a command the change frees, on a device of that group. One test clears every command form of the same deny and permit |
| `RAISES` | a privilege level, `priv_lvl`, `max_privilege` ceiling or `enable` mechanism that went up, or a reply that changed | a session test asserting the new value; the diff prints it |
| `REGEX-CONSTRAINED` | a permit with a regex or class term added, or a deny with one removed or rewritten | a passing `expect: permit` command test on a command the rule decides (for a deny, one it used to refuse), or an [`acknowledge:`](#acknowledge) entry for a deny whose freed commands you cannot name |
| `API` | `api:` rights added to a subject | a session test whose `api:` lists the subject's whole new list; the diff prints it |
| `PRINCIPAL`, `USERNAME` | an identity that now resolves to another subject, or a `username:` that changed | a session test naming the principal (for `USERNAME`, any one of the subject's principals). `api` alone does not count; a `PRINCIPAL` change whose new subject gains API rights also needs `api:` with the whole list |
| `per_login_mfa_weakened` | a `per_login_mfa` requirement removed or loosened on a device | a session test with `per_login_mfa:` asserting the new requirement, which is new or changed against the old file; a test carried over unchanged does not count |
| `SUBJECT` | a subject's `group:` or `machine_group:` changed, or a new group subject was added | a session test naming the subject |
| `ADAPTER` | an edit to a platform adapter key that changes what port49 decides | an [`acknowledge:`](#acknowledge) entry |
| `QUARANTINES`, `REFUSED`, `UNRESOLVED` | a device newly quarantined, a mint or admission newly refused, a composition the diff could not compare | fix the cause; no test clears these |

The last line of the output counts each kind. A lowering, such as a narrower permit or a dropped right, prints and
passes.

### acknowledge:

Some widenings have no command to flip. A deny rewritten wider, such as `/^(wri|rel)/ **` as `/^wri/ **`, frees
commands the diff cannot list. An adapter edit changes what port49 reads. The author acknowledges these in writing, in
a top-level block that review reads beside the change:

```yaml
acknowledge:
  - {role: guard, rule: "/^(wri|rel)/ **", reason: "rewritten as /^wri/: rel* commands are allowed on purpose"}
  - {platform: juniper_junos, field: rpc_entry_denies, sha256: <sha256>, reason: "moved to set 1.2.0"}
```

A `role` and `rule` entry names the exact removed or rewritten rule. A `platform`, `field` and `sha256` entry names the
digest `policy diff` prints for the key's new value, so it covers that edit and no later one. `reason` is required in
both. An entry that matches nothing is reported as `acknowledge_stale` and acknowledges nothing, so delete it. Do not use
`acknowledge:` for an ordinary expansion: a literal deny removed is cleared by a test, and an entry for it is reported
stale.

### The ceiling line

```text
session ceiling: netops on 1 devices: 8h0m0s or the default, whichever is less -> 24h0m0s (may lengthen: depends on session.max_session_age_default)
```

This line says that a subject's `max_session_age` changed: the least of its roles' values, on how many devices, from
what to what. It prints and does not fail the run, because a longer session is not a wider permission. A lengthened
ceiling reaches live sessions only when they refresh. It is not the `max_privilege` ceiling: a raise of that is a
`RAISES` and fails.

### A new grant is a reviewer's call

The gate judges commands that a deny, a pipeline stage or a quarantine used to refuse. A new grant is none of those. A
subject that had no grant on a device and now has one gets one line, and a new role on a device the subject already
reaches gets a `widens:` line per command form. Both exit 0 and neither demands a test:

```text
access: netops gains every grant on leaf1, leaf2
widens: netops on leaf1: "ping length" was no_rule_matched, now permitted by "ping *" (extra)
```

Read every `access:` and `widens:` line, and run `port49 access review --policy FILE --inventory FILE --subject NAME` to
see one subject's grants, how many devices each reaches and when each expires. The gate still catches:

- a new `group:` or `machine_group:` subject, whatever its grants: it exits 1 on a `SUBJECT: NAME's none -> group ...`
  line until a session test names the subject (a new `identity:` subject is a `PRINCIPAL`);
- a grant that adds `api:` rights;
- a new identity for an existing subject, or a changed group;
- a `per_login_mfa` weakening that no new or changed session test asserts;
- a privilege raise on a device the subject already reached.

## Run the checks in CI

Run `port49 policy test` on every change and `port49 policy diff` on every pull request, with `--old` taken from the
branch the pull request merges into. Both exit 1 on a failure (and 2 on a usage error), so any nonzero exit fails the
job and blocks the merge. Neither reads a secret or asks a broker, so the job needs no credentials. This is a GitHub
Actions job; any CI that can run a shell works the same way:

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

The install step pins a release and checks it against the release's `SHA256SUMS`. Raise `PORT49_VERSION` when you
upgrade. [Install the client](../use/install-client.md) has the same steps for a workstation.

## port49 policy replay

```sh
port49 policy replay [--line N] [--policy FILE --inventory FILE] decisions.jsonl
```

It re-runs the decisions in a [decision log](../reference/decision-log.md) against the policy blob each record carries,
to check that this build still decides as the build that wrote the record did, or to audit a past decision. It prints
each record that diverged and a summary, `replayed N records: A agree, D diverge, U unverifiable; S not replayed`, and
exits 1 if any diverged or could not be verified. A record denied before policy ran is counted and not replayed.

With `--policy` and `--inventory` it rebuilds a blob a redacted record hid. With `--line N` it replays one record and
prints it either way. `-` instead of a file reads the log from standard input.

## port49 explain

`explain` answers one hypothetical question: what would port49 decide for this subject, on this device, for this
command?

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

It prints exactly one reason from the [reason codes](../reference/reason-codes.md) and, for a denial, names the role that
would permit the command. It exits 0 whether the answer is permit or deny, and a nonzero exit means a policy or a name
did not load. Leave out `--command` to see the session instead, and add `--show-attributes` to see each session
attribute and where it came from.

`explain` also says when the platform cannot enforce the control you asked about. On a platform that authorizes sessions
only, a session ceiling, a revocation, a username change and the session-ceiling warning act at the next authorization
request. On Junos the device makes one after login only if `authorization-time-interval` is set
([Junos](devices/juniper-junos.md#what-the-lab-measured) has the measurements). On a projected Junos the note also names
the class `idle-timeout` that `port49 platform export --classes` renders from `max_session_age`. On any other
session-only platform the device is not known to make one, and the note says not to rely on these controls there.

!!! warning "Unmeasured: a second re-authorization"
    Whether Junos re-authorizes an open session more than once, so whether a control made after the first ever reaches it, is unknown ([L40](../reference/lab-register.md#l40), open). Do not rely on these controls to end a live Junos session.

With neither `--policy` nor `--inventory`, `explain` asks the broker through your agent, from the policy in force:
`port49 explain --device leaf1 --command "show version"`. Explaining another person with `--principal` needs
`api: [explain_others]`. The broker's `explain` records carry hypothetical verdicts, so a dashboard of denials should
filter `event!="explain"`.
