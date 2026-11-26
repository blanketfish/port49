---
title: Reviewing a policy change
description: Check what a policy change grants or removes with policy test, policy diff, replay and explain, and run the checks in CI.
---

# Reviewing a policy change

Four commands read the policy: `port49 policy test`, `port49 policy diff`, `port49 policy replay` and `port49 explain`.
They take `--policy FILE --inventory FILE` (`policy diff` takes `--old` and `--new` with one `--inventory`). They never
read a secret, and with the files given they never ask a broker. Everything they print is redacted as the daemon's
records are.

## port49 policy test

```sh
port49 policy test --policy policy.yaml --inventory inventory.yaml [--config port49d.yaml]
```

It loads the policy against the inventory as port49d does, so every load error is a failure. Then it prints the platform
set, the key check, the reports, the shadowed-deny report, one line per test and a summary. For the policy on
[Policy](policy.md), against an inventory whose `leaf1` is an `arista_eos` device with `site: dc1` and `role: leaf`:

```text
platform_set: 1.3.0
keys: checked against the default key_secret_refs (env: variables starting PORT49_KEY_, file: under /run/port49/keys); pass --config to check port49d.yaml's
report: group_subject: subject "netops" is a group: subject: it mints only with broker.directory configured, through which the broker matches a person to the group; explain and policy tests evaluate it by name
PASS netops on leaf1: "show version" -> permit permit_dominates
PASS netops on leaf1: "configure terminal" -> deny no_rule_matched
2 tests, 0 failed; 0 shadowed denies, 0 unacknowledged; 0 quarantined, 0 projection refusals
```

It exits 1 when the policy does not load, a test fails, a deny is shadowed by a more specific permit and no test
exercises it, a device is quarantined (now or at a later grant expiry), a composition gets a projection's fail-closed
reply, admission refuses a device, or a key is wrong: no `keys:` block, a `key_ref` the block does not define, or a
`secret_ref` outside `key_secret_refs`. `--config` checks against your port49d.yaml's `key_secret_refs`. Lines that begin
`report:` are lint findings, which are review questions and not failures.

## port49 policy diff

```sh
port49 policy diff --old main-policy.yaml --new policy.yaml --inventory inventory.yaml
```

It compares the two files for every subject on every device, over every command form the rules distinguish, now and at
every later grant expiry. It prints each change and exits 1 on a widening that no test or acknowledgment accounts for. A
lowering, such as a narrower permit or a dropped right, prints and passes. The last line counts each kind.

| Label | The change | What clears it |
|---|---|---|
| `EXPANDS` | a command a deny, pipeline stage or quarantine refused is now permitted | an `expect: permit` command test on a freed command |
| `RAISES` | a level, `priv_lvl`, `max_privilege` or `enable` went up, or a reply changed | a session test asserting the new value |
| `REGEX-CONSTRAINED` | a permit gained a regex or class term, or a deny lost or rewrote one | a passing `expect: permit` test on a command the rule decides, or an [`acknowledge:`](#acknowledge) entry |
| `API` | `api:` rights added to a subject | a session test listing the whole new `api:` |
| `PRINCIPAL`, `USERNAME` | an identity resolves to another subject, or a `username:` changed | a session test naming the principal |
| `per_login_mfa_weakened` | a `per_login_mfa` requirement removed or loosened | a session test asserting the new requirement, new or changed against the old file |
| `SUBJECT` | a subject's group changed, or a new group subject was added | a session test naming the subject |
| `ADAPTER` | an adapter key edit that changes what port49 decides | an [`acknowledge:`](#acknowledge) entry |
| `QUARANTINES`, `REFUSED`, `UNRESOLVED` | a device newly quarantined, a mint or admission newly refused, a composition not comparable | fix the cause; no test clears these |

[Policy tests](policy-tests.md#clearing-a-diff-finding) has the details, such as which test counts for a `PRINCIPAL`
change that gains API rights.

### acknowledge:

Some widenings have no command to flip: a deny rewritten wider, such as `/^(wri|rel)/ **` as `/^wri/ **`, or an adapter
edit. The author acknowledges these in a top-level block that review reads beside the change:

```yaml
acknowledge:
  - {role: guard, rule: "/^(wri|rel)/ **", reason: "rewritten as /^wri/: rel* commands are allowed on purpose"}
  - {platform: juniper_junos, field: rpc_entry_denies, sha256: <sha256>, reason: "moved to set 1.2.0"}
```

A `role` and `rule` entry names the exact removed or rewritten rule. A `platform`, `field` and `sha256` entry names the
digest `policy diff` prints for the key's new value, so it covers that edit and no later one. `reason` is required. An
entry that matches nothing is reported as `acknowledge_stale` and acknowledges nothing, so delete it. Do not use it for
an ordinary expansion: a test clears those.

### The ceiling line

```text
session ceiling: netops on 1 devices: 8h0m0s or the default, whichever is less -> 24h0m0s (may lengthen: depends on session.max_session_age_default)
```

This line says a subject's `max_session_age` changed. It prints and does not fail the run, because a longer session is
not a wider permission, and it reaches live sessions only when they refresh. A raise of the `max_privilege` ceiling is a
`RAISES` and fails.

### A new grant is a reviewer's call

A subject that had no grant on a device and now has one gets one line, and a new role on a device the subject already
reaches gets a `widens:` line per command form. Both exit 0 and demand no test:

```text
access: netops gains every grant on leaf1, leaf2
widens: netops on leaf1: "ping length" was no_rule_matched, now permitted by "ping *" (extra)
```

Read every such line, and run `port49 access review --policy FILE --inventory FILE --subject NAME` to see one subject's
grants, devices reached and expiries. The gate still catches a new `group:` or `machine_group:` subject (exit 1 on a
`SUBJECT` line until a session test names it; a new `identity:` subject is a `PRINCIPAL`), a grant that adds `api:`
rights, a new identity or changed group for an existing subject, a `per_login_mfa` weakening no new test asserts, and a
privilege raise on a device the subject already reached.

## Run the checks in CI

Run `port49 policy test` on every change and `port49 policy diff` on every pull request, with `--old` taken from the
branch it merges into. Both exit 1 on a failure and 2 on a usage error, so a nonzero exit fails the job. Neither reads a
secret or asks a broker, so the job needs no credentials. This is a GitHub Actions job; any CI that runs a shell works:

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

The install step pins a release and checks it against `SHA256SUMS`. Raise `PORT49_VERSION` when you upgrade.
[Install the client](../use/install-client.md) has the same steps for a workstation.

## port49 policy replay

```sh
port49 policy replay [--line N] [--policy FILE --inventory FILE] decisions.jsonl
```

It re-runs the decisions in a [decision log](../reference/decision-log.md) against the policy blob each record carries,
to check that this build still decides as the build that wrote the record did. It prints each record that diverged and
`replayed N records: A agree, D diverge, U unverifiable; S not replayed`, and exits 1 if any diverged or could not be
verified. A record denied before policy ran is counted and not replayed. `--policy` and `--inventory` rebuild a blob a
redacted record hid, `--line N` replays one record, and `-` reads standard input.

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

It prints one reason from the [reason codes](../reference/reason-codes.md) and, for a denial, names the role that would
permit the command. It exits 0 for permit and deny alike, and nonzero when a policy or a name did not load. Without
`--command` it shows the session, and `--show-attributes` adds where each attribute came from. With neither `--policy`
nor `--inventory` it asks the broker through your agent, from the policy in force. `--principal` needs
`api: [explain_others]`. The broker's `explain` records carry hypothetical verdicts, so a dashboard of denials should
filter `event!="explain"`.

On a platform that authorizes sessions only, the note says a session ceiling, a revocation, a username change and the
ceiling warning act at the next authorization request. On Junos the device makes one after login only if
`authorization-time-interval` is set ([Junos](devices/juniper-junos.md#what-the-lab-measured)). On any other session-only
platform the device is not known to make one, and the note says not to rely on these controls.

!!! warning "Unmeasured: a second re-authorization"
    Whether Junos re-authorizes an open session more than once, so whether a control made after the first ever reaches it, is unknown ([L40](../reference/lab-register.md#l40), open). Do not rely on these controls to end a live Junos session.
