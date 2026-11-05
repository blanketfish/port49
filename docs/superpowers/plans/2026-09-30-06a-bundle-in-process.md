# Plan 6a: The Bundle In Process, Key Rotation Reporting, and the Source-of-Truth Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** port49d runs on one versioned bundle — the inventory, the key groups and the policy, swapped
in one pointer — and reloads it when either file changes, with the bounded-change safety, the
security events and the refresh a sync needs. Key rotation becomes observable: `retire_after`
is enforced, every record names the key version that admitted it, and `port49 keys status`,
`keys show` and `keys diagnose` drive a rotation. A `based_on:` variant carries its base's wire
facts, `policy replay` verifies a redacted blob from the policy file, and the lab measures what
a device does on a key miss (L28) and what NetBox and Nautobot really return (L27), so plan 6b's
connectors are written against evidence.

**Architecture:** A new package, `internal/bundle`, names a bundle (`bundle.ID`: `sha256:` over the
policy file's hash and the inventory's canonical form) and builds it (`bundle.Parse`): the policy
loaded against the inventory, which now also resolves every device's key group into the admission
index (`policy.Policy.Admission`). The loaded `*policy.Policy` *is* the bundle in force: `policy.Live`
already swaps it in one pointer and holds mints across the swap (plan 4b), so the broker's device
table, the daemon's admission index, the quarantine list and the policy change together. The
reloader watches `inventory_file` as it watches the policy file, refuses a snapshot that is empty,
malformed or over-shrinking, and runs the plan 4b refresh after each swap. Key versions gain
`retire_after`; the daemon writes `device.key_ref`/`device.key_version` on every validated record,
and `port49 keys status` reads them from the log as `devices capabilities` reads it. `keys diagnose`
asks port49d over a local admin socket to try every key it holds on the last packet a device sent
that did not validate.

**Tech Stack:** Go 1.22+ (the module's own `go` line), the standard library,
`gopkg.in/yaml.v3` and `prometheus/client_golang` (both already dependencies). containerlab on the
lab host (beehive) for Task 20; Docker Compose on the same host for Task 2. No new module
dependencies.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §10 in full (the inventory service's
bundle, admission and keys, key rotation, device records, how a daemon refreshes its snapshot,
source-of-truth write access), §5.5 (scopes, `security_log`), §5.7 (the `bundle` field, the
events table, replay), §5.8 (redaction by platform), §8 ("User-editable, day one": `based_on:`),
§12 (`keys status`, `keys diagnose`, `keys show`, `inventory diff`, replay), §13 decisions 5, 14
and 20, §14 "Inventory and capability" and "Key rotation", §15. Design
`docs/design/2026-08-21-port49-design.md` §10 "Device inventory", §12 (the failure matrix's
inventory and key rows), §19 step 6. Roadmap `docs/superpowers/plans/README.md`, "Plan 6", plan
4's and plan 4b's "Hands to plan 6", and "Plan 5a", the `based_on:` and redaction items.

**Prerequisite:** plan 5b merged (PR #14, `ecb35ce`). Branch `feature/bundle-in-process` off `main`
at the commit that adds this file.

## Owner decisions needed

Each is written into this plan at its default, the option that denies more. A different ruling
changes only the task named.

1. **A key-group tie that exists only against the inventory refuses that device, not the policy
   or the snapshot.** Spec §10 says two groups matching in one tier is "a policy load error",
   and §14 tests it at load. Two groups naming the same prefix or the same attribute set tie for
   every device and stay load errors (Task 4). But `{site: campus}` and `{role: leaf}` tie only
   on a device that carries both, which a sync can create; refusing the policy there, or the
   snapshot, blocks every inventory change fleet-wide for one device, the bottleneck decision 20
   exists to avoid. **Default:** that device is refused admission (never admitted under a guessed
   key), named at load and on every reload, counted in `port49_devices_admission_refused`, and
   `port49 policy test` fails on it; the rest of the fleet loads. *Alternative:* refuse the
   policy (today's behaviour) or the snapshot. Tasks 4, 17.
2. **`port49 keys diagnose` reaches port49d over a local Unix socket, off by default.** Spec §10
   requires the probe to be manual and to name the matching group, and the only packet to probe
   is in port49d's memory. **Default:** `admin_socket:` in port49d.yaml, empty (off) unless set;
   the socket is mode 0600 and refuses any peer whose uid is not port49d's or root's
   (`SO_PEERCRED`, Linux only); it serves one read-only operation; the held packets are kept only
   while it is configured, one per admitted device, never logged. *Alternative:* an offline
   `--pcap` mode that needs the secrets on the operator's host. Task 16.
3. **(For plan 6b, recorded now because Task 11's design anticipates it.) Once the inventory
   service exists, port49d keeps reading the policy from its own `broker.policy_file` and takes
   only the inventory from the service.** Spec §10 has the broker consume policy from the
   bundle. The service holds the source-of-truth credentials and runs third-party connectors: a
   compromise of it can already move devices between scopes and add addresses (a
   credential-capture path, §10), and taking policy from it too would let it grant anyone
   anything. **Default:** port49d builds the bundle from its own policy file and the service's
   inventory, as it builds it from two files in this plan. The service's bundle carries the
   policy hash it was built against. When that hash differs from the policy in force, port49d
   still applies the service's inventory, against its own policy, and says the mismatch and
   raises an alarm: nothing the service sends ever changes the policy, and a policy rollout that
   reaches port49d before the service never stalls inventory sync. *Alternative:* the spec as
   written, the policy from the service over mutual TLS. Plan 6b.

## Revised after the pre-flight review (2026-09-30)

The pre-flight review (`.superpowers/sdd/2026-09-30-06a-bundle-in-process/preflight.md`) found
three critical and seven important problems. The controller ruled each; the plan below is written
to the rulings.

- **C1 (a `tests:` block no longer loaded; `Device` declared twice).** `Parse` fills a name index
  of the inventory first, and `admit` is a `Parse` step right after `buildKeyGroups`, before
  `buildTests`. The one `Device` is the existing `internal/policy/tests.go:357`, which reads the
  index through `device`. Task 4.
- **C2 (the live inventory file had no write fence).** `cmd/port49d/policyfile.go`'s checks are
  generalized in place (`readGuarded`), and with a broker the inventory file is read through them at
  start and at every reload, with its own size bound (64 MiB). A refused read keeps the last good inventory, is said once, and
  sets `port49_inventory_file_refused`. New Task 11a; Tasks 1 and 12.
- **C3 (the key-group migration refused the fleet).** When both files carry `key_groups`, the
  policy's block wins, and a notice names the ignored inventory block. The documented order (add
  the block to the policy, then delete it from the inventory) never refuses a device. Every other
  order is either harmless or stopped by the bound (I4). A start whose bundle admits no device at
  all is refused, since that is no device's fault. Tasks 4, 10, 12, with a test for each order,
  including a restart mid-migration.
- **I1 (the large-removal escape hatch did not exist).** `SIGHUP` re-reads
  `inventory.max_removed_percent` from port49d.yaml with the reload. Decided 6, the `Config`
  comment and `Check`'s text now say the same thing. Task 12 tests it by writing port49d.yaml and
  sending the reload. Tasks 7, 12.
- **I2 (the broker minted for a refused device).** `policy.Resolve` refuses a device that admission
  refuses (`ErrDeviceRefused`) wherever admission is assessed. The mint denies it `device_unknown`,
  an existing §5.7 reason whose meaning Task 1 extends to cover a device that admission refuses.
  The refresh revokes its contexts, and the supersede deletes its tokens. Tasks 1, 4, 11.
- **I3 (a policy test naming a removed device refused every reload).** `buildTests` no longer
  checks the device. `RunTests` fails a test on an absent device, so `port49 policy test` does, and
  `Parse` and a reload never do. Tasks 4, 17.
- **I4 (the bound ignored devices newly refused).** `bundle.Check` counts devices that go from
  admitted to refused toward the bound, as it counts removals, and names them. Task 7.
- **I5 (a key change was silent).** `key_ref_changed`, and `admission_changed` to `admitted`, are
  security changes, each with an `inventory_change` record and a counter. Tasks 1, 7, 13.
- **I6 (the L27 recorder).** There is now a legacy-twin map per product, the Nautobot `primary`
  PATCH names the device's UUID, each run has its own fixture directory, and the webhook listener
  binds the gateway of each stack's own network. Task 2.
- **I7 (tools that did not load the bundle).** `policy diff`, `platform upgrade` and `grants
  remove` load through `bundle.Parse` as port49d does. `offlineEnv` is removed. Task 6.
- **Minors:**
  - M1: the start hashes the bytes `config.Load` read. Task 12.
  - M2 and M3: Task 1 says where `retire_after` lives, and why, and how CI reads "an empty
    `accept` set".
  - M4: `devices capabilities` reads a variant's exec records as its base's. `serverMsg` needs no
    change, since port49d's redactor maps the name already. Task 9.
  - M5: inventory faults name `inventory_file`. Task 12.
  - M6: the admin socket's unwind closes the broker listener, and `Listen` refuses a socket another
    process answers on. Task 16.
  - M7: owner decision 3 now says the inventory is applied while the hashes differ.
  - M8: the §10 text says `bundle.ID` does not cover port49d.yaml's keys. Task 1.
  - M9: the replay, socket and redaction tests assert what they claim. Tasks 9, 16, 19.
  - M10: branch H's `Holding` covers every strike, which the note and the operator notes say.
    Task 20.
  - M11: the as-built notes state the crypt alarm's move and why. Task 21.
  - M12: the webhook listener binds each stack's own gateway. Task 2.
  - None is left.

**Re-review (same day).** Five further findings, each ruled:
- **N1 (a policy reload could log out the fleet).** A policy reload is held to the inventory's
  bound: `bundle.CheckAdmission` counts devices going from admitted to refused against
  `inventory.max_removed_percent`. A reload over the bound is refused, naming them; the policy in
  force keeps serving, with the alarm raised, and `SIGHUP` retries after the bound is raised.
  `port49 policy diff` fails on a newly refused device, and `port49 policy test` now fails on every
  refused device, a device no group admits included. Tasks 7, 12, 17; the real reload path is
  tested with a `key_groups` typo, and the sessions and tokens survive.
- **N2:** `port49 explain` says a refused device is refused, and why. Task 4.
- **N3:** the fence's §10 text names what it checks: the file, its directory, and each directory
  holding a link. Task 1.
- **N4:** `offlineEnv`'s own test goes with it. Task 6.
- **N5:** a device added and admitted is a security change (`device_added`), as Decided 9 says.
  Tasks 1, 7, 13.

## Why this plan is 6a, and what 6b is

The roadmap's brief for plan 6 is more than one branch: the bundle and every consumer of it, key
rotation reporting, the `based_on:` and replay debts, a separate `port49-inventory` service with
an HTTP API, three connectors, four sync triggers, and the daemon's pull-and-cache. **The seam is
the bundle's source.** Plan 6a builds everything that consumes a bundle, with the bundle built in
process from `inventory_file` and `broker.policy_file` — the "file connector" spec §10 requires
regardless — so each piece is tested against real code with no service to stand up. Plan 6b adds
the remote source: `cmd/port49-inventory`, the NetBox, Nautobot and file connectors, the four
triggers, the bundle document and its API, the daemon's 30 s pull, the persisted last good bundle,
the shared mirror and cold-start readiness, `port49 inventory sync`, and the §14 quarantine lab
assertion through a sync. 6b is written after 6a merges, against the fixtures Task 2 records.

**Go-dark on a store outage and the warm context cache are not in plan 6.** Both ride on the
remote store (plan 4's "Hands to plan 6": "plan 6 or 7, whichever brings the remote store"), and
design §19 step 6 builds none; plan 7 carries "a store two processes can reach". So do plan 4b's
remote-store items (unindexed contexts, per-call store deadlines, bounded emits under a hold, the
settle window, the broker's memory), and the `crypt_open_failures_total{record="token"}` alarm,
which is an encryption-at-rest rotation alarm, not a device-key one. Task 21 records the move.

## Decided in this plan

1. **The loaded policy is the bundle in force.** `bundle.Parse(policyRaw, inventory, env)` loads
   the policy against the inventory, and the result carries the admission index, the device
   table, the quarantine and the policy. `policy.Live` swaps it whole, so no mint, packet or
   refresh sees one version's inventory and another's policy. A new type beside it would need its
   own swap and its own hold, and plan 4b's reasoning about both would have to be repeated.
2. **The bundle's name is a content hash.** `bundle.ID` is `sha256:` over the policy file's
   `sha256:` and the inventory's canonical JSON (devices by name, addresses sorted), so every
   port49d reading the same two files names the same bundle, and a reformatted inventory file is
   the same bundle. `bundle` on every record and blob is this string (spec §5.7 already calls it a
   string until versioned bundles). Plan 6b may add a sequence number beside it; it will not
   change this one. The name does not cover port49d.yaml's `keys:`: two daemons with different
   key names load the same bundle and may refuse different devices, which each says at load. `policy.Policy.Source` keeps the policy file's own hash, which the reloader
   compares file versions by.
3. **An inventory-only swap does not churn live contexts.** A refresh whose priors all share the
   policy file in force reads a context's blob from the store and compares it with the new one,
   the bundle aside; equal, the context is left as it is and nothing is recorded. A policy edit
   keeps plan 4b's rule, every live context takes the new bundle's blob. Without this, every
   inventory change would write one `refresh` record and one blob per live context.
4. **Key groups move into the policy file, and the move never refuses the fleet.** `key_groups:` is
   a policy block, validated at load. An inventory file that still has one is read, with a notice
   at every load, where the policy has none. Where both have one, the policy's wins and the notice
   names the inventory's as ignored: the inventory's writer loses key assignment, which is the
   anti-escalation direction, and a restart or reload in the middle of the move loads. The
   documented order is to add the block to the policy file, then delete it from the inventory
   file. Deleting it from the inventory first leaves every device refused, so the reload is
   refused by the bound (Decided 6). port49d with no `broker:` block has no policy, keeps its plan 1
   behaviour and reads the inventory's key groups, once, at start: that mode is the lab's.
5. **A device is refused, not the daemon.** A device no group admits, one a tie refuses, and one
   assigned a `key_ref` port49d.yaml defines no key for are each refused admission on their own,
   named at start and at every reload, and their packets closed after the header with the new
   diagnosis `admission_refused` and no strike (spec §10: "fails that device closed — not the
   daemon"). Today `config.Load` refuses to start on either, which turns one stray device in a
   synced inventory into a total outage at the next restart. The legacy no-broker mode keeps
   today's start-time refusal. There is one exception: a start whose bundle admits none of a
   non-empty inventory is refused, naming the commonest cause. That happens, for example, when
   key groups are declared in neither file. It is no device's fault, and a daemon that admits
   nothing is a misconfiguration. Wherever admission is assessed (key groups declared, or
   port49d's key names known), the broker also refuses to mint for a refused device, denying it
   `device_unknown` (§5.7, extended in Task 1), and the refresh revokes its contexts. A refused
   device cannot reach port49d, so a token for it would only be a login that silently falls to
   the local method.
6. **The inventory file is watched, and a reload is bounded.** Two agreeing reads, `SIGHUP`, and a
   refusal said once per content, exactly as the policy file. A snapshot that does not parse,
   names a device twice or an address twice, is empty, or removes more than
   `inventory.max_removed_percent` of the devices in force (default 10; 100 turns it off) is
   refused, and the bundle in force keeps serving. Devices that stay in the inventory but go from
   admitted to refused count toward the bound as removals do: either way the device stops being
   served. An operator removing a fifth of the fleet on purpose raises
   `inventory.max_removed_percent` in port49d.yaml and sends `SIGHUP`. The reload re-reads that
   one key, so no restart is needed, which matters because a restart ends every live context. The
   inventory file is read behind the policy file's write fence (owner and mode checks, a size
   bound), because it decides scope membership, capture addresses and key pins within seconds.
   A test in the policy's `tests:` that names a device the inventory no longer has fails `port49
   policy test`, and never a reload.
7. **`retire_after` is a date and is inclusive.** `retire_after: 2026-10-01` admits through the end
   of that day UTC and refuses from `2026-10-02T00:00:00Z`: past it the version identifies and
   never admits, as a retired one does. It is allowed on `accept` versions only. A connection
   validated before the instant keeps its version only until that instant; past it, every later
   packet is treated as a new connection's would be (spec §10). A busy single-connect connection
   resets its idle timer on every packet, so "for its life" would have no bound. How a device
   reacts to that close is L29, open, split from L28 in Task 21. (Amended in Task 14's review.)
8. **Every validated record names its key.** `device.key_ref` and `device.key_version` on the
   redeem, authorization and accounting records; `keys status` groups the log by them. A new
   per-connection record would double the log.
9. **Security events are `inventory_change` records.** Every swap diffs the bundles. Each of these
   is one record and one `port49_inventory_changes_total{kind}` count: a device joining or leaving
   a `security_log: true` scope; an address added to a device already in inventory; a device's
   `key_ref` changed, since a pin in the inventory can move a device onto a weaker or shared key;
   and a device newly admitted, including one going from refused to admitted, since a device
   starts receiving port49's answers there. The spec says these changes "MUST appear in the sync
   diff and be reviewable" and are "logged and alerted as security events" (§10).
10. **A scope pins devices by name with `match: {name: [...]}`.** `name` reads the device's
    inventory name as `platform` reads its platform (spec §10: "A scope MUST be able to pin a
    device set explicitly"). A comparison on it is refused.
11. **A variant is read as its base wherever the name keys a fact.** Session services, exec-record
    commands, system users, the session discriminator, the built-in redaction patterns and the
    keyword tree. The redaction one is the security reason: `platforms/redact.yaml` lists Junos's
    own patterns under `juniper_junos`, so a `based_on: juniper_junos` variant keyed by its own
    name would log what Junos's patterns hide.
12. **Secrets stay `secret_env`.** Spec §10's `secret_ref: vault:...` resolvers are plan 12's; this
    plan changes no secret plumbing.

## What the operator sees

The owner's rule is to trace a mechanism on a bad day first.

- **After the upgrade, before any edit:** port49d starts as before. If the inventory file still
  carries `key_groups:`, one line says `port49d: policy: key_groups are read from the inventory
  file; move the block into the policy file, where key assignment is reviewed (spec §10)`. Every
  record now carries `"key_ref":"prod_key","key_version":3` in its `device` block, and `bundle` is
  the bundle id rather than the policy file's hash.
- **3am, someone adds a leaf in an unexpected range to the inventory file:** within two watch
  intervals, `port49d: inventory reloaded (inventory file changed): bundle sha256:9f… → sha256:4c…:
  +1 device(s), -0, 0 changed; 0 device(s) quarantined now, 0 before; 1 refused admission` and
  `port49d: admission: device leaf-77 (arista_eos) is refused: matches no key group, so no key
  admits it (spec §10)`. `port49_devices_admission_refused` is 1. The leaf's packets are closed
  after the header (`"diagnosis":"admission_refused"`) and it falls to its local method. Nothing
  else changed.
- **3am, a bad inventory edit drops half the fleet:** `port49d: inventory reload (inventory file
  changed) refused; still serving bundle sha256:9f…: the new inventory removes 41 of 80 devices and
  refuses 0 more (51%), more than inventory.max_removed_percent (10%); fix the file, or, if the
  change is meant, raise inventory.max_removed_percent in port49d.yaml and send SIGHUP`. `port49_inventory_file_refused` is 1 and
  `port49_inventory_snapshot_age_seconds` climbs. Everyone keeps working on the bundle in force.
- **Someone deletes `key_groups:` from the inventory before adding it to the policy:** the reload
  is refused, since every device would be newly refused, and the line names the order: add the
  block to the policy file first. Nothing stops serving.
- **Someone makes the inventory file group-writable:** `port49d: inventory reload (inventory file
  changed) refused; still serving bundle …: the file … is writable by group …`, once, with
  `port49_inventory_file_refused` at 1. At start the same file refuses the start.
- **Someone adds `10.66.0.1` to leaf-01's addresses:** the reload line, and an
  `{"event":"inventory_change","device":{"name":"leaf-01",...},"change":{"kind":"address_added",
  "address":"10.66.0.1",...}}` record; `port49_inventory_changes_total{kind="address_added"}` goes
  up. The same for a device joining or leaving a `security_log: true` scope.
- **During a rotation:** `port49 keys status --policy policy.yaml --inventory inventory.yaml
  --config /etc/port49/port49d.yaml --since 24h /var/log/port49/decisions.jsonl` prints each
  version's device count, names the devices still on the old one, and lists unvalidated sources
  with their diagnosis. `port49_key_version_devices{key_ref,version}` and
  `port49_key_retirement_seconds{key_ref,version}` are the alarm's inputs.
- **The date passes with leaf-19 still on v2:** leaf-19's packets are `matches_retired`; it falls
  to its local method (how fast is L28's measurement); `keys status` names it; with
  `admin_socket` set, `port49 keys diagnose leaf-19` prints `leaf-19 (10.20.4.9), packet held 30s
  ago: validates under prod_key v2 (retired); it is assigned prod_key: the device was missed in the
  rotation`.
- **A `based_on: juniper_junos` variant:** loads, and its sessions, records and redaction are
  Junos's.
- **`port49 policy replay --policy policy.yaml --inventory inventory.yaml decisions.jsonl`:** a
  record whose blob event was redacted replays against the blob recompiled from the files, checked
  against the hash the record names; without the files it stays `unverifiable`, as today.

## Global Constraints

Copied verbatim from `CLAUDE.md`, "Code conventions":

- Go 1.22+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- **snake_case everywhere it is data**: YAML keys, JSON log keys, config, metric names.
- Reason codes are the closed vocabulary of spec §5.7 (`internal/decision/reasons.go`).
  Never invent one; add to the spec table first.
- The log never contains a token, password, challenge, or response. Credentials appear only
  as `credential_sha256`. An unvalidated body is never logged.
- No device identity in metric labels.
- Verify before claiming done: run `make test && make vet` and report the real output.

Carried from plans 2–5b, and still binding:

- **Every claim about device or external-system behaviour cites a `tests/lab/results/` note or a
  register row.** A claim cited to an open row is unmeasured; do not "fix" a doc to assert it
  (CLAUDE.md, lab register rules 1–4). NetBox and Nautobot count (L27).
- **A released platform set is never edited.** This plan edits none.
- **A blob fails closed; a quarantined device is closed without a reply; nothing logs a token.**
- **Every context write outside login goes through a narrow setter.** This plan adds none.
- **Security first:** no privilege escalation, no impersonation, no secret in a log, fail closed.
  Where a task leaves a choice, take the one that denies more and say so in the commit.

New in this plan:

- **No new reason code.** A refused device's record carries the new *diagnosis*
  `admission_refused` (spec §10's report buckets, edited in Task 1) and no reason, as an
  unadmitted source's does. `inventory_change` is a report event, not a decision.
- **The code blocks are written against `ecb35ce`.** They are not generated from a green commit.
  Where the compiler or a test says a block is wrong about the tree — a helper's name, an import —
  fix the block minimally, keep the behaviour the step's test asserts, and say so in the task's
  report and its commit. Never weaken a test to make a block pass.
- **Every commit is preceded by `make test && make vet`**, and by `make build`. Report their real
  output.
- **The lab tasks follow "Running the lab" below.** No new dependencies. Branch
  `feature/bundle-in-process`; never commit code to `main`.
- Commit messages end with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  ```

## Running the lab (Tasks 2 and 20)

The lab host is beehive. Its containerlab holds one run at a time; Task 2 uses Docker Compose, not
containerlab, and may run while a code task is in progress, but never at the same time as Task 20
(both use the host's Docker). The owner has given standing consent for lab runs.

**Task 20 is a containerlab run** and follows plan 5b's "Running the lab" exactly: one platform per
`go test` run, the harness's boot budgets (vEOS 6 min, vJunos-router 8 min, N9Kv 15 min, IOS-XE per
`platforms` in `tests/lab/harness_test.go`) plus up to 8 min for TACACS+ readiness, a deadline on
every read where expiry is "not observed" and fails the run, and **a stall watchdog run by the
controller for the whole run** (`STALL=25` minutes, 40 on the N9Kv), which on a stall or a `go test
-timeout` panic destroys the topology, kills `bin/port49d` and any `tcpdump` on
`tests/lab/captures`. The watchdog script is plan 5b's, with `LOG`, `PID` and `TOPO` set for this
run:

```bash
make build
PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run '^TestL28KeyMiss$' -count=1 -v -timeout 90m \
  > tests/lab/logs/l28-eos.log 2>&1 &
echo $! > tests/lab/logs/l28-eos.pid
```

**Task 2 runs Docker Compose stacks** of NetBox and Nautobot. It has its own watchdog: a stack that
has not answered `GET /api/status/` within 10 minutes of `docker compose up -d`, or a recorder that
has not written a line to its log in 10 minutes, is a stall: `docker compose down -v` the stack and
report the log's last 40 lines. A stalled run is never read as a result.

**Evidence.** Task 20 runs `make evidence` after the run and commits the redacted captures under
`tests/lab/evidence/`, never `tests/lab/captures/`. If the run happened in a worktree, copy its raw
captures into the main checkout's `tests/lab/captures/` before removing the worktree, or the
labpcap audit fails. Task 2's evidence is its fixture files, which the recorder writes with no
credential in them (the API token is only ever a request header, which is not recorded). After every
run confirm that no `port49d` still holds `172.100.100.1:49`, that the topology is destroyed, and
that `docker compose ls` lists no port49 stack.

## File Structure

```
docs/design/2026-08-23-policy-engine-spec.md  MOD  §5.5, §5.7, §8, §10, §12, §13 d28, §14, §15 L27 L28 (Task 1); closed rows (Task 21)
docs/design/2026-08-21-port49-design.md       MOD  §10, §12's key-miss sentences (Task 1)
tests/lab/cmd/sot-record/main.go              NEW  records NetBox/Nautobot API facts into fixtures (Task 2)
tests/lab/sot/compose/*.yml, seeds            NEW  the stacks and what the recorder seeds (Task 2)
tests/lab/sot/fixtures/<product>-<version>/   NEW  recorded responses (Task 2)
tests/lab/sot_unit_test.go                    NEW  the fixtures parse and say what the notes say (Task 2)
internal/admission/admission.go               MOD  Transport, Resolved.Refused/WirePlatform, Tier, Assignment, Validate, Assign, NewTrie, ParseFile (Task 3)
internal/policy/file.go, load.go              MOD  key_groups, Env.KeyRefs/InventoryKeyGroups/Bundle, admit, Admission, Device, Source, Raw, Inventory (Tasks 4, 6)
internal/policy/scope.go                      MOD  the `name` match key (Task 5); Scopes, Selects (Task 7)
internal/bundle/bundle.go                     NEW  ID, Parse, Load (Task 6)
internal/bundle/diff.go                       NEW  Change, Report, Diff, Check, Summary, Security (Task 7)
internal/decision/log.go, reasons.go          MOD  Device.KeyRef/KeyVersion, Change, EventInventoryChange (Task 8)
internal/daemon/authen/authen.go              MOD  Peer.KeyRef/KeyVersion/WirePlatform, Wire (Task 8)
internal/daemon/author/author.go, acct/acct.go MOD records name the key (Task 8); wire facts by Peer.Wire (Task 9)
internal/platform/platform.go                 MOD  WireFactsDiffer removed (Task 9)
internal/policy/resolve.go, lint.go           MOD  keyword tree and redaction by WirePlatform (Task 9)
internal/daemon/server/server.go, conn.go     MOD  Admitter, admission_refused, KeySeen, Held (Tasks 10, 14, 16)
internal/keyring/keyring.go                   MOD  DiagAdmissionRefused (Task 10); RetireAt, Resolve(now), Seen (Task 14)
internal/keyring/held.go, diagnose.go         NEW  Held, Diagnose (Task 16)
internal/config/config.go                     MOD  broker mode admits from the policy, KeyRefs (Task 10); inventory block (Task 12);
                                                   retire_after, KeySets (Task 14); admin_socket (Task 16)
internal/daemon/metrics/metrics.go            MOD  admission refused (Task 10); inventory reloads/refused/age (Task 12);
                                                   inventory changes (Task 13); key collector (Task 14)
internal/broker/broker.go, refresh.go         MOD  devices from the held policy; the inventory-only compare (Task 11)
cmd/port49d/policyfile.go, _other.go          MOD  readGuarded, readInventoryFile; fencedInventory in main.go (Task 11a)
tests/lab/harness_test.go                     MOD  a private copy of inventory_file under a broker (Task 11a)
internal/capability/capability.go             MOD  a variant's exec records read as its base's (Task 9)
cmd/port49d/main.go, reload.go                MOD  parseBundle, live admission (Task 10); the inventory watch (Task 12);
                                                   security events (Task 13); key gauges (Task 14); admin socket (Task 16)
internal/keystatus/keystatus.go               NEW  Infer, Report (Task 15)
internal/daemon/admin/admin.go, peer_*.go     NEW  the admin socket (Task 16)
cmd/port49/keys.go                            NEW  keys status, show, diagnose (Tasks 15, 16)
cmd/port49/policy.go, main.go                 MOD  bundle.Load (Task 6); policy test --config and admission (Task 17);
                                                   inventory diff (Task 18); replay --policy (Task 19)
internal/replay/replay.go                     MOD  Source, ReplayWith (Task 19)
tests/lab/l28_test.go                         NEW  the key-miss and rotation measurement (Task 20)
tests/lab/results/L27-*.md, L28-*.md          NEW  written by the lab runs
docs/superpowers/plans/README.md              MOD  plan 6a as built, plan 6b's brief (Task 21)
```

Twenty-two tasks:
- **Task 1** is docs.
- **Task 2** is a lab measurement (L27), independent of the code; run it early, since plan 6b's
  plan is written from its fixtures.
- **Tasks 3–19, with 11a**, are code. Every one leaves `make test` green.
- **Task 20** is a lab measurement (L28) that needs Tasks 14 and 15.
- **Task 21** is lab closure and docs.

---

### Task 1: The spec and the design say what plan 6a builds, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`
- Modify: `docs/design/2026-08-21-port49-design.md`

No code. Every later task cites the text this one writes. Each edit is given as the text to find
and the text to put in its place; where a paragraph is new, the text it goes after.

- [ ] **Step 1: §10, "One versioned bundle".** Replace the sentence beginning "One that fails for
  some platforms quarantines the devices on them. Until the inventory service publishes bundles
  (plan 6), `port49d` applies quarantine when it loads the policy:" and running to "(plan 4)." with:

  ```markdown
  One that fails for some platforms quarantines the devices on them. port49d builds the bundle
  itself from `inventory_file` and `broker.policy_file` (plan 6a), and plan 6b's inventory service
  publishes it: each quarantined device is logged with its cause at start and at every reload that
  loads, its mints are refused `device_quarantined`, and its connections are closed without a
  reply (plan 4).
  ```

  After the paragraph beginning "A consumer runs on exactly one bundle version at a time", add:

  ```markdown
  **The bundle's name is a content hash.** `bundle` on every record and blob is `sha256:` over the
  policy file's `sha256:` and the inventory's canonical form — its devices in name order, each
  device's addresses sorted, its key groups if the inventory file still carries any — so every
  port49d reading the same two files names the same bundle, and a reformatted inventory file is
  the same bundle. The policy file's own hash is kept beside it, and port49d's lines name both.
  The name does not cover port49d.yaml's `keys:`: two daemons holding different key names load
  the same bundle and may refuse different devices (below), and each says so at load.
  The loaded policy carries the admission index, the device table and the quarantine with it, and
  one pointer swaps all four (§13, decision 28).
  ```

- [ ] **Step 2: §10, "Admission and keys".** Replace the YAML block's comment line `# policy
  repository — intent` with `# the policy file — key assignment is reviewed policy`, and after the
  paragraph ending "while the admission *decision* stays in review." add:

  ```markdown
  `key_groups:` is a block of the policy file. An inventory file that still carries one is read
  where the policy has none, with a notice at every load. Where both carry one, the policy's wins
  and the notice names the inventory's as ignored, so the inventory's writer never assigns a key
  beside the reviewed policy. To move the block, add it to the policy file, then delete it from
  the inventory file: no device is refused at any step, and a restart or reload between the two
  loads. Deleting it from the inventory first would leave every device refused, and the reload is
  refused by the bound (below). A group matches on a CIDR or on attributes, never both; a CIDR
  with host bits set is refused.

  **A device is refused on its own, never the daemon.** A device no group admits, one two groups
  tie on (below), and one assigned a `key_ref` port49d.yaml defines no key for, are each refused
  admission: named at start and at every reload that loads, counted in
  `port49_devices_admission_refused`, and every packet from them closed after the header, with
  nothing decrypted, no reply, no strike, and the report bucket `admission_refused` (below). The
  rest of the fleet loads. The broker refuses to mint for a refused device (`device_unknown`,
  §5.7), and a policy refresh revokes its live contexts: it cannot reach port49d, so a token for
  it would only be a login that silently falls to its local method. One case refuses the start
  rather than a device: a bundle that admits none of a non-empty inventory — key groups declared in
  neither file, say — which no device caused. port49d with no `broker:` block has no policy and
  keeps plan 1's behaviour: the inventory file's key groups, read at start, and a start refused by
  either fault.
  ```

  In "Key group matching is deterministic", replace the paragraph beginning "**Two groups matching
  in the same tier is a policy load error**, naming both." with:

  ```markdown
  **Two groups that tie for every device they could match — one prefix twice, one attribute set
  twice — are a policy load error**, naming both. This follows the same rule as the matcher (§4):
  where two rules genuinely disagree about which is more specific, refusing to guess is the only
  conservative answer, and a device silently admitted under the wrong key group is admitted under
  the wrong *key* — which fails at the worst moment and looks like an outage (design document §12).
  A tie that exists only for some devices — `{site: campus}` and `{role: leaf}` on a device carrying
  both, or two addresses of one device in two groups' prefixes — refuses that device as above, and
  `port49 policy test` fails on it (plan 6a, owner decision 1): a sync can create one, and refusing
  the policy there would block every inventory change fleet-wide.
  ```

  Replace "RFC 9887 replaces the shared key with mutual TLS, so a device record MUST be able to
  express both." with:

  ```markdown
  RFC 9887 replaces the shared key with mutual TLS, so a device record MUST be able to express
  both: `transport: tcp` (the default, RFC 8907 under a shared key) or `transport: tls`. `tls` is
  refused at load until plan 11 serves it.
  ```

- [ ] **Step 3: §10, "Key rotation".** In "Version sets, and no cutover", after the sentence ending
  "and there is no moment at which a device must already have been updated:" and its diagram, add:

  ```markdown
  `retire_after` is a date, inclusive: `retire_after: 2026-10-01` admits through the end of that
  day UTC, and from `2026-10-02T00:00:00Z` the version identifies a device and never admits one,
  as a retired version does. It is written on `accept` versions only; `current` carries none, and
  a `retired` version is refused already. A connection validated before the instant keeps its
  version only until that instant (amended in Task 14's review; spec §10 has the text). port49d
  says at start, and `port49 policy test --config` reports, a version whose date has passed and
  an `accept` version with none.

  The key sets, `retire_after` included, live in port49d.yaml beside the references to their
  secrets (`secret_env`), where they have been since plan 1, rather than in the policy file, which
  CI and every operator can read. Retirement and extension are therefore reviewed changes of
  port49d.yaml's repository. Moving key sets into the policy repository waits on secret references
  that name no secret (`secret_ref:`, plan 12).
  ```

  In "Phase-out has to be observable", replace "The daemon records which `key_ref` and version
  validated each connection, which makes the question answerable:" with:

  ```markdown
  The daemon writes the `key_ref` and version that validated the exchange on every record it
  makes for it (`device.key_ref`, `device.key_version`, §5.7), and `port49 keys status` reads them
  from the decision log, which makes the question answerable:
  ```

  In "Devices presenting a key that does not validate", after the paragraph on the fifth bucket
  (`malformed after validation`), add:

  ```markdown
  A sixth, `admission_refused`, is a device the inventory names and admission refuses (above). The
  device is not at fault, so it is kept apart from both the key report and the noise.
  ```

  Replace the paragraph beginning "**Cross-group probing is manual.**" with:

  ```markdown
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
  ```

- [ ] **Step 4: §10, "Device records" and "How a daemon refreshes its snapshot".** After the device
  record YAML block add `transport: tcp` as its last line, and after the paragraph beginning
  "**Every address a device may source from must be listed.**" add:

  ```markdown
  `name`, `platform`, `addresses` and `attributes` are the facts; `key_ref` pins a key (tier 1);
  `transport` is above. An inventory is refused whole when it does not parse, names a device twice
  or with no name, or gives one address to two devices.
  ```

  After the paragraph beginning "**Every swap logs a summary**", add:

  ```markdown
  **Until plan 6b, the snapshot is `inventory_file`.** port49d watches it as it watches the policy
  file (§5.1.3): it loads a changed file once two reads a watch interval apart agree, at once on
  `SIGHUP`, and says a refusal once per distinct content. It validates as above and refuses an
  empty file and one that removes more than `inventory.max_removed_percent` of the devices in
  force (default 10; 100 turns the bound off), counting a device that goes from admitted to
  refused as removed. It builds a bundle from the file and the policy in force,
  swaps the two in one pointer, and runs the refresh a policy reload runs (§5.1.3): a device
  removed from inventory has its live contexts revoked, and one leaving a scope is narrowed like
  any other. `port49_inventory_snapshot_age_seconds` is the time since the file in force was last
  read and found unchanged or loaded; `port49_inventory_file_refused` is 1 while the file on disk
  is one port49d refused. `SIGHUP` also re-reads `inventory.max_removed_percent` from port49d.yaml,
  so a deliberate large removal is: raise it, send `SIGHUP`, and lower it again.

  **A policy reload is held to the same bound.** Key groups are policy, and a refused device's live
  contexts are revoked and its tokens deleted, so a `key_groups` edit that misses the fleet would
  otherwise log everyone out within seconds, and a revert would not bring the sessions back. A
  policy reload that refuses admission to more than `inventory.max_removed_percent` of the devices
  the policy in force admits is refused, naming them; the policy in force keeps serving and
  `port49_policy_file_refused` is 1, and raising the bound and sending `SIGHUP` applies a deliberate
  change.

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
  ```

- [ ] **Step 5: §10, "Source-of-truth write access is privilege-granting".** Replace its first two
  bullets with:

  ```markdown
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
  ```

- [ ] **Step 6: §5.5 and §5.7.** In §5.5, after the `srx_unpatched` YAML block, add:

  ```markdown
  Two match keys read the device record rather than its attributes: `platform`, its platform, and
  `name`, its inventory name, which pins a scope to named devices (§10). An attribute named either
  is not read by a scope. `name` takes a string or a list, never a comparison.
  ```

  In §5.7, "Three properties", replace "Until the inventory service publishes versioned bundles
  (§10), `bundle` is the `sha256:` of the policy file the blob was compiled from, a string; the blob
  carries it, so a daemon that never reads the policy still logs it." with:

  ```markdown
  `bundle` is the bundle's name (§10): `sha256:` over the policy file's hash and the inventory's
  canonical form, a string, since plan 6a; before it, the policy file's hash. The blob carries it,
  so a daemon that never reads the policy still logs it. A blob names the bundle it was compiled
  under, which a later bundle that changed nothing for that context does not rewrite (§5.1.3).
  ```

  After the paragraph on `reply.attributes`, add:

  ```markdown
  `device.key_ref` and `device.key_version` are on every record of an exchange a key validated —
  `redeem`, `authorize_session`, `authorize_command`, `escalate`, `account` — naming the key group
  and the version that admitted it, so a rotation's phase-out is read from the log (§10, `port49
  keys status`).
  ```

  In the events table's lead sentence replace "plus three report events (`account`,
  `account_gap`, `blob`)" with "plus four report events (`account`, `account_gap`, `blob`,
  `inventory_change`)", and after the `account_gap` paragraph add:

  ```markdown
  A tenth, `inventory_change`, is a report too: one record per security-relevant change a bundle
  swap made — `{"change": {"kind": "address_added", "address": ..., "from_bundle": ...,
  "to_bundle": ...}}` for an address added to a device already in inventory, and `scope_joined`
  or `scope_left` with `"scope"` for a device entering or leaving a scope with `security_log:
  true` (§5.5, §10), `key_ref_changed` with `"from"` and `"to"` for a device's key assignment
  changing, `admission_changed` with `"to": "admitted"` for a device already in inventory becoming
  admitted, and `device_added` with `"to": "admitted"` for a device added and admitted, whose
  addresses are new capture targets. Its `device` block names the device. It is what makes a source-of-truth edit
  that moves privilege visible in the log it moved (§10), and
  `port49_inventory_changes_total{kind}` is its alarm.
  ```

  In the reason table, replace the `device_unknown` row's meaning with:

  ```markdown
  | `device_unknown` | the source address is not in the admission trie (§10). On `mint` and `refresh`: the device is in inventory and admission refuses it — no key group admits it, two tie on it, or its `key_ref` is one port49d holds no key for (§10) — so no token is minted for it and its live contexts are revoked: it cannot reach port49d, and a token for it would only be a login that falls to the device's local method. As with a quarantine, a subject with no grant on the device is answered `no_grants_matched` first, so the API tells no caller which devices exist |
  ```

  In §5.1.3, after the paragraph that says a refresh finding a context already on the answer
  writes nothing (the carve-out §5.7 repeats), add:

  ```markdown
  A swap that changed only the inventory — every policy since the last complete refresh read from
  one policy file — leaves a context as it is when its blob differs from the new one only in the
  bundle it names: the answer did not change, so nothing is written and nothing is recorded, and
  the context goes on naming the bundle that compiled it, which is still true. A policy edit keeps
  the rule above: every live context takes the new bundle's blob.
  ```

  In §5.7 "Replay", after its first paragraph, add:

  ```markdown
  A blob event redacted before it was written (§5.8) makes every record naming it unverifiable
  from the log alone. `port49 policy replay --policy <file> --inventory <file>` recompiles such a
  blob from the files for the record's principal and device at the blob event's time, and uses
  it only when the files name the record's bundle and the recompiled blob hashes to the name the
  record carries.
  ```

- [ ] **Step 7: §8, "User-editable, day one".** Replace the two sentences beginning "What port49d
  reads off the wire — `session_services`, the exec records' commands and the system users — is
  still keyed by the platform's name until plan 6 carries it to a variant" and running to "binds a
  record by username alone, the safe direction (§5.8)." with:

  ```markdown
  A variant is the same device under another name, so everything port49 keys by a shipped
  platform's name is read for it as its base's: the `session_services` it may arrive with, its
  exec records' commands, its system users, its session discriminator (§5.8), the built-in
  redaction patterns (§5.8) and the keyword tree (§8, decision 27). The admission index carries the
  base's name beside each device's for the daemon (plan 6a). Keyed by its own name, a
  `juniper_junos` variant would be refused every session `service_unsupported`, have its login
  records read as commands, and have its records logged without Junos's own redaction patterns.
  ```

- [ ] **Step 8: §12.** Replace the paragraph beginning "**`port49 keys status`** counts devices per
  accepted key version" with:

  ```markdown
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
  devices in its group.

  **`port49 inventory diff --policy <file> [--new-policy <file>] <old-inventory> <new-inventory>`**
  prints what a change to the inventory does to the bundle: devices added, removed and changed,
  addresses added to existing devices, `key_ref` and admission changes, and every scope membership
  change, the `security_log` ones marked — the review artifact §10 requires. It exits 1 when port49d
  would refuse the new inventory (empty, a collision, or more removed than
  `--max-removed-percent`, default 10).

  **`port49 policy test --config <port49d.yaml>`** adds the key checks §10 requires of CI: it fails
  on a key group naming a `key_ref` the file does not define, and on a device assigned one. It
  reads §10's "a policy whose `accept` set is empty for a `key_ref` still assigned by a key group"
  as that case: `current` is always accepted, so the set is empty only where the key is not
  defined at all. It reports an `accept` version whose `retire_after` has passed and one with none.
  Without `--config` it still fails on every device admission refuses where key groups are
  declared: a tie, and a device no group admits, since port49d serves neither. It fails on a test
  naming a device the inventory does not have, which a load no longer refuses (§10).
  **`port49 policy diff`** fails on a device the new policy refuses admission and the old admitted,
  naming it: the edit port49d's reload would refuse over `inventory.max_removed_percent` (§5.1.3).
  ```

- [ ] **Step 9: §13, a new decision, and §14.** After decision 27, add:

  ```markdown
  **28. The bundle is one pointer, built in port49d until the inventory service publishes it.**
  *Plan 6a, 2026-09-30.* The policy loaded against the inventory carries the admission index, the
  device table, the quarantine and the policy, and `policy.Live` swaps it whole, so no mint, packet
  or refresh sees one version's inventory and another's policy (§10). Its name is a content hash
  (§10). port49d builds it from `inventory_file` and `broker.policy_file`, watches both, and bounds
  an inventory reload as a sync is bounded. Key groups are policy. A device a group cannot admit is
  refused on its own, never the daemon. An inventory-only swap leaves a context whose answer did
  not change as it is (§5.1.3). Plan 6b adds the service as a second source of the same bundle;
  whether port49d then takes the policy from it is an owner decision recorded in plan 6a.
  ```

  In §14 "Inventory and capability", after "**Unresolvable `key_ref`** fails that device closed,
  not the daemon." add:

  ```markdown
  - **A device no key group admits**, and one two groups tie on, is refused admission on its own
    and its packets closed after the header as `admission_refused`; the rest of the fleet loads.
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
  ```

- [ ] **Step 10: §15, two new rows.** After L26c's row add:

  ```markdown
  | **L27** | What NetBox and Nautobot's APIs return for a device, per product and major version: where the version is reported (`/api/status/`, the `API-Version` header on `/api/`); the field names for role, platform, site or location, primary address, custom fields and tags, over REST and over one GraphQL query; which GraphQL query shape each version takes, and whether one query returns every interface address; how REST paginates; and what a device create, update and delete webhook carries — its headers and body, and whether `X-Hook-Signature` is HMAC-SHA512 of the body under the webhook's secret. | Plan 6b's connectors: version detection and mapping profiles, GraphQL first with REST as the fallback, webhook authentication (§10, "Connectors and sync cadence") | NetBox 3.7 and 4.x; Nautobot 1.6 and 2.x | open — added 2026-09-30 (plan 6a Task 2) |
  | **L28** | What a device does when port49d cannot validate its key, with port49d as built: it reads the body, records it, holds the connection for the per-source backoff (100 ms doubling to 5 s) and closes it without a reply. For a key port49d does not hold, and for one it holds only as retired: whether a break-glass login succeeds and how long it takes, how long a command in an open break-glass session takes, and whether a token login is refused. And that a second version accepted beside the current one lets the device work unchanged, and that the device given the current key works at once with no port49d change. | Key rotation's no-cutover claim and the retirement lockout's shape (§10 "Retirement is enforced"); the design document's "a key mismatch is indistinguishable from an outage" (§12); whether a key miss should be closed at once, as a quarantine is | EOS, NX-OS, IOS-XE, Junos | open — added 2026-09-30 (plan 6a Task 20) |
  ```

- [ ] **Step 11: the design document.** In §12's failure table, row **Device presents a retired or
  wrong key**, and in the paragraph beginning "**A key mismatch is indistinguishable from an
  outage, from the device's side.**", replace "A device presenting a retired or wrong key gets
  unreadable replies and declares the server dead, falling through to local authentication —
  which is the same behavior as a total port49 outage, confined to that device." with:

  ```markdown
  A device presenting a retired or wrong key gets no reply at all: port49d records the packet,
  holds the connection for the per-source backoff, and closes it. What the device then does —
  declare the server dead and fall through to local authentication, as in a total port49 outage
  confined to that device, and how long each attempt costs it — is measured by spec §15 L28, open.
  ```

  In §12's inventory row ("**Inventory service unavailable**"), append to the cell "✓ last good
  snapshot": "(until plan 6b, the snapshot is `inventory_file`, and a refused edit leaves the
  bundle in force serving)". In §10 "Device inventory", after the paragraph beginning "**Change per
  sync is bounded.**" add: "Until plan 6b builds the service, port49d builds the bundle from its own
  two files and bounds an inventory reload the same way (policy engine spec §10, decision 28)."

- [ ] **Step 12: Check nothing cites what this task removed**

Run: `grep -n "until plan 6\|plan 6 carries\|until plan 6's bundle\|key groups live in the inventory" docs/design/2026-08-23-policy-engine-spec.md`
Expected: no line claims a thing this plan builds is still unbuilt. A hit in a closed decision's
history, or one naming plan 6b, stays; any other is edited to say what plan 6a does.

- [ ] **Step 13: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs: the spec says what plan 6a builds, decision 28 and L27/L28 included

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: (lab, on beehive) What NetBox and Nautobot really return: L27

**Files:**
- Create: `tests/lab/sot/compose/netbox-3.7.yml`, `netbox-4.yml`, `nautobot-1.6.yml`, `nautobot-2.yml`
- Create: `tests/lab/cmd/sot-record/main.go`, `tests/lab/cmd/sot-record/seed.go`
- Create: `tests/lab/sot/fixtures/<product>-<version>/*.json` (written by the run)
- Create: `tests/lab/sot_unit_test.go`
- Create: `tests/lab/results/L27-netbox.md`, `tests/lab/results/L27-nautobot.md` (written from the run)

**Interfaces:**
- Consumes: nothing from the product code.
- Produces: fixtures plan 6b's connector tests replay, one directory per product and version, each
  with `status.json`, `api-root.json`, `seed.json`, `rest-device.json`, `rest-page.json`,
  `graphql.json` and `webhooks.json`; the two notes.

This task measures; it builds nothing port49 ships. Every value the notes state is read off a
recorded response. A call the version refuses is a finding, recorded with its status and body, and
never "fixed" by guessing a different call without recording that too.

- [ ] **Step 1: The stacks.** Each Compose file runs one product at one version with its database
  and cache, on `127.0.0.1` only, with a superuser and an API token created at start. Pin every
  image by digest in the file, and write the tag beside it in a comment, so the note can name the
  version exactly. For NetBox use `docker.io/netboxcommunity/netbox` (the newest `v3.7.*` and the
  newest `v4.*` tags on the day), `postgres:16-alpine` and `valkey/valkey:8-alpine`, following the
  netbox-docker release whose tag the file names in a comment; for Nautobot use
  `docker.io/networktocode/nautobot` (the newest `1.6.*` and `2.*` tags), with the same database and
  cache. `tests/lab/sot/compose/netbox-4.yml`:

  ```yaml
  # NetBox 4.x for L27 (plan 6a Task 2). Image tags: pin by digest, tag in the comment.
  # Superuser admin, API token from SUPERUSER_API_TOKEN, both set by the recorder's environment.
  name: port49-l27-netbox4
  services:
    netbox:
      image: docker.io/netboxcommunity/netbox:v4.X.Y@sha256:<digest>   # tag v4.X.Y
      depends_on: [postgres, redis]
      ports: ["127.0.0.1:18080:8080"]
      environment:
        DB_HOST: postgres
        DB_NAME: netbox
        DB_USER: netbox
        DB_PASSWORD: l27-lab-db
        REDIS_HOST: redis
        REDIS_CACHE_HOST: redis
        SECRET_KEY: l27-lab-secret-key-l27-lab-secret-key-l27-lab-secret-key
        SKIP_SUPERUSER: "false"
        SUPERUSER_NAME: admin
        SUPERUSER_EMAIL: admin@example.com
        SUPERUSER_PASSWORD: l27-lab-admin
        SUPERUSER_API_TOKEN: ${L27_TOKEN}
    netbox-worker:
      image: docker.io/netboxcommunity/netbox:v4.X.Y@sha256:<digest>
      command: ["/opt/netbox/venv/bin/python", "/opt/netbox/netbox/manage.py", "rqworker"]
      depends_on: [netbox]
      environment: {DB_HOST: postgres, DB_NAME: netbox, DB_USER: netbox, DB_PASSWORD: l27-lab-db,
                    REDIS_HOST: redis, REDIS_CACHE_HOST: redis,
                    SECRET_KEY: l27-lab-secret-key-l27-lab-secret-key-l27-lab-secret-key}
    postgres:
      image: postgres:16-alpine
      environment: {POSTGRES_DB: netbox, POSTGRES_USER: netbox, POSTGRES_PASSWORD: l27-lab-db}
    redis:
      image: valkey/valkey:8-alpine
  ```

  The `<digest>` and `X.Y` are filled on the day from `docker buildx imagetools inspect`; they are
  the measurement's subject, not a placeholder in the product. The worker is what delivers
  webhooks (NetBox queues them). Write `netbox-3.7.yml` the same way with a `v3.7.*` tag and
  `nautobot-1.6.yml`/`nautobot-2.yml` from Nautobot's image, whose environment names differ
  (`NAUTOBOT_DB_*`, `NAUTOBOT_REDIS_HOST`, `NAUTOBOT_SECRET_KEY`, `NAUTOBOT_CREATE_SUPERUSER`,
  `NAUTOBOT_SUPERUSER_API_TOKEN`), with `nautobot start` and a `nautobot worker` service (Celery
  delivers its webhooks). Each file listens on its own port: 18037, 18080, 18016, 18020.

- [ ] **Step 2: The recorder.** `tests/lab/cmd/sot-record/main.go` seeds one device with two
  interfaces and two addresses, then records the reads and a webhook round trip:

  ```go
  // Command sot-record measures what a NetBox or Nautobot API returns for a
  // device (spec §15, L27) and writes each response as a fixture under -out.
  // It records responses and never the request's Authorization header, so a
  // fixture carries no credential. Every call's outcome is recorded, a refusal
  // included: a call a version does not take is the finding.
  package main

  import (
  	"bytes"
  	"crypto/hmac"
  	"crypto/sha512"
  	"encoding/hex"
  	"encoding/json"
  	"flag"
  	"fmt"
  	"io"
  	"net"
  	"net/http"
  	"os"
  	"path/filepath"
  	"regexp"
  	"strings"
  	"sync"
  	"time"
  )

  type recorder struct {
  	base, token, product, out string
  	legacy                    bool
  	client                    *http.Client
  	ids                       map[string]any
  }

  // exchange is one recorded call: what was asked, and everything the server
  // answered but the headers that set cookies.
  type exchange struct {
  	Step    string            `json:"step"`
  	Method  string            `json:"method"`
  	Path    string            `json:"path"`
  	Request json.RawMessage   `json:"request,omitempty"`
  	Status  int               `json:"status"`
  	Headers map[string]string `json:"headers"`
  	Body    json.RawMessage   `json:"body"`
  }

  func (r *recorder) call(step, method, path string, body any) exchange {
  	var reqBody []byte
  	if body != nil {
  		reqBody, _ = json.Marshal(r.expand(body))
  	}
  	path = r.expandPath(path)
  	req, err := http.NewRequest(method, r.base+path, bytes.NewReader(reqBody))
  	if err != nil {
  		fail("%s: %v", step, err)
  	}
  	req.Header.Set("Authorization", "Token "+r.token)
  	req.Header.Set("Content-Type", "application/json")
  	req.Header.Set("Accept", "application/json")
  	resp, err := r.client.Do(req)
  	if err != nil {
  		fail("%s: %v", step, err)
  	}
  	defer resp.Body.Close()
  	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
  	x := exchange{Step: step, Method: method, Path: path, Status: resp.StatusCode, Headers: map[string]string{}}
  	if reqBody != nil {
  		x.Request = reqBody
  	}
  	for k := range resp.Header {
  		if k != "Set-Cookie" {
  			x.Headers[k] = resp.Header.Get(k)
  		}
  	}
  	if json.Valid(raw) {
  		x.Body = raw
  	} else {
  		x.Body, _ = json.Marshal(string(raw))
  	}
  	return x
  }

  // legacyTwin names, per product, for -prefer-legacy, the step an older
  // version took in place of each: NetBox 3.7's device_role and content_types
  // spellings, Nautobot 1.6's site and device_role. Each twin is a step that
  // product's seedFor defines.
  var legacyTwin = map[string]map[string]string{
  	"netbox":   {"device": "device_v3", "custom_field": "custom_field_v3"},
  	"nautobot": {"device": "device_v1", "role": "role_v1", "location": "site_v1", "site": "site_v1"},
  }

  // lookup is the recorded value of "step.field", or the legacy twin's where
  // -prefer-legacy is set and the twin succeeded.
  func (r *recorder) lookup(ref string) (any, bool) {
  	step, field, _ := strings.Cut(ref, ".")
  	if r.legacy {
  		if twin, ok := legacyTwin[r.product][step]; ok {
  			if got, ok := r.ids[twin+"."+field]; ok {
  				return got, true
  			}
  		}
  	}
  	got, ok := r.ids[ref]
  	return got, ok
  }

  var pathRef = regexp.MustCompile(`@[a-z0-9_]+\.[a-z]+`)

  // expandPath replaces every @step.field in a path, as expand does in a body.
  func (r *recorder) expandPath(p string) string {
  	return pathRef.ReplaceAllStringFunc(p, func(ref string) string {
  		got, ok := r.lookup(ref[1:])
  		if !ok {
  			fail("no recorded value for %s in %s", ref, p)
  		}
  		return fmt.Sprint(got)
  	})
  }

  // expand replaces every string "@name.field" in v with the value field had in
  // the response recorded as step name, so a later call can name an object an
  // earlier one created.
  func (r *recorder) expand(v any) any {
  	switch t := v.(type) {
  	case string:
  		if len(t) > 1 && t[0] == '@' {
  			if got, ok := r.lookup(t[1:]); ok {
  				return got
  			}
  			fail("no recorded value for %s", t)
  		}
  		return t
  	case map[string]any:
  		out := map[string]any{}
  		for k, x := range t {
  			out[k] = r.expand(x)
  		}
  		return out
  	case []any:
  		out := make([]any, len(t))
  		for i, x := range t {
  			out[i] = r.expand(x)
  		}
  		return out
  	}
  	return v
  }

  // remember records a created object's id and name as "<step>.id" and "<step>.name".
  func (r *recorder) remember(x exchange) {
  	var obj map[string]any
  	if json.Unmarshal(x.Body, &obj) == nil {
  		for _, f := range []string{"id", "name", "url"} {
  			if v, ok := obj[f]; ok {
  				r.ids[x.Step+"."+f] = v
  			}
  		}
  	}
  }

  func (r *recorder) write(name string, v any) {
  	b, err := json.MarshalIndent(v, "", "  ")
  	if err != nil {
  		fail("%s: %v", name, err)
  	}
  	if err := os.WriteFile(filepath.Join(r.out, name), append(b, '\n'), 0o644); err != nil {
  		fail("%s: %v", name, err)
  	}
  }

  func fail(format string, args ...any) {
  	fmt.Fprintf(os.Stderr, "sot-record: "+format+"\n", args...)
  	os.Exit(1)
  }

  // hook is one webhook delivery as it arrived.
  type hook struct {
  	At          time.Time         `json:"at"`
  	Headers     map[string]string `json:"headers"`
  	Body        json.RawMessage   `json:"body"`
  	SignatureOK bool              `json:"signature_is_hmac_sha512_of_body"`
  }

  func main() {
  	product := flag.String("product", "", "netbox or nautobot")
  	base := flag.String("url", "", "the API base, e.g. http://127.0.0.1:18080")
  	out := flag.String("out", "", "the fixture directory to write")
  	listen := flag.String("webhook-listen", "", "host:port the product can reach this recorder on")
  	legacy := flag.Bool("prefer-legacy", false, "name the objects an older version's spelling created")
  	flag.Parse()
  	token, secret := os.Getenv("L27_TOKEN"), os.Getenv("L27_WEBHOOK_SECRET")
  	if *product == "" || *base == "" || *out == "" || *listen == "" || token == "" || secret == "" {
  		fail("-product, -url, -out, -webhook-listen, L27_TOKEN and L27_WEBHOOK_SECRET are required")
  	}
  	if err := os.MkdirAll(*out, 0o755); err != nil {
  		fail("%v", err)
  	}
  	r := &recorder{base: *base, token: token, product: *product, out: *out, legacy: *legacy,
  		client: &http.Client{Timeout: 60 * time.Second}, ids: map[string]any{}}

  	var mu sync.Mutex
  	var hooks []hook
  	ln, err := net.Listen("tcp", *listen)
  	if err != nil {
  		fail("webhook listener: %v", err)
  	}
  	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
  		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
  		mac := hmac.New(sha512.New, []byte(secret))
  		mac.Write(body)
  		h := hook{At: time.Now().UTC(), Headers: map[string]string{}, Body: body,
  			SignatureOK: req.Header.Get("X-Hook-Signature") == hex.EncodeToString(mac.Sum(nil))}
  		if !json.Valid(body) {
  			h.Body, _ = json.Marshal(string(body))
  		}
  		for k := range req.Header {
  			h.Headers[k] = req.Header.Get(k)
  		}
  		mu.Lock()
  		hooks = append(hooks, h)
  		mu.Unlock()
  	}))

  	r.write("status.json", r.call("status", "GET", "/api/status/", nil))
  	r.write("api-root.json", r.call("api_root", "GET", "/api/", nil))
  	var seeded []exchange
  	for _, s := range seedFor(*product, r) {
  		x := r.call(s.step, s.method, s.path, s.body)
  		r.remember(x)
  		seeded = append(seeded, x)
  	}
  	r.write("seed.json", seeded)
  	r.write("rest-device.json", r.call("rest_device", "GET", "/api/dcim/devices/?name=leaf-01", nil))
  	r.write("rest-page.json", r.call("rest_page", "GET", "/api/dcim/devices/?limit=1", nil))
  	// NetBox serves GraphQL at /graphql/, Nautobot at /api/graphql/; a 404
  	// here is recorded like any other answer.
  	gqlPath := "/graphql/"
  	if *product == "nautobot" {
  		gqlPath = "/api/graphql/"
  	}
  	var gql []exchange
  	for i, q := range graphQLCandidates(*product) {
  		gql = append(gql, r.call(fmt.Sprintf("graphql_%d", i), "POST", gqlPath, map[string]any{"query": q}))
  	}
  	r.write("graphql.json", gql)

  	var hookCalls []exchange
  	for _, s := range webhookSteps(*product, "http://"+*listen+"/", secret) {
  		x := r.call(s.step, s.method, s.path, s.body)
  		r.remember(x)
  		hookCalls = append(hookCalls, x)
  	}
  	time.Sleep(20 * time.Second) // the worker delivers asynchronously
  	mu.Lock()
  	r.write("webhooks.json", map[string]any{"calls": hookCalls, "deliveries": hooks})
  	mu.Unlock()
  	fmt.Printf("sot-record: %s at %s: %d seed calls, %d GraphQL candidates, %d webhook deliveries\n",
  		*product, *base, len(seeded), len(gql), len(hooks))
  }
  ```

  The webhook secret is a lab value, and the fixture keeps `X-Hook-Signature` because it is what
  6b's verifier is tested against; the note says the secret is the lab's.

- [ ] **Step 3: What it seeds and asks.** `tests/lab/cmd/sot-record/seed.go` holds the calls per
  product, as the product documents them for the newest major version. A call an older version
  refuses is recorded as refused; then add the older version's spelling as a second step of its
  own (for example `role` then `device_role`), so both outcomes are in `seed.json`.

  ```go
  package main

  type step struct {
  	step, method, path string
  	body               map[string]any
  }

  // seedFor is one device, leaf-01, with a management interface and a loopback,
  // an address on each, the management one primary, a platform, a role, a site
  // or location, a custom field os_version and a tag: every fact spec §10's
  // connector maps. Each object is created by name and later calls name it by
  // the id the product returned ("@step.id").
  func seedFor(product string, r *recorder) []step {
  	if product == "nautobot" {
  		return []step{
  			{"location_type", "POST", "/api/dcim/location-types/", map[string]any{"name": "Site", "content_types": []any{"dcim.device"}}},
  			{"location", "POST", "/api/dcim/locations/", map[string]any{"name": "dc1", "location_type": "@location_type.id", "status": "Active"}},
  			{"site_v1", "POST", "/api/dcim/sites/", map[string]any{"name": "dc1", "slug": "dc1", "status": "active"}},
  			{"manufacturer", "POST", "/api/dcim/manufacturers/", map[string]any{"name": "Arista", "slug": "arista"}},
  			{"device_type", "POST", "/api/dcim/device-types/", map[string]any{"manufacturer": "@manufacturer.id", "model": "vEOS", "slug": "veos"}},
  			{"role", "POST", "/api/extras/roles/", map[string]any{"name": "leaf", "content_types": []any{"dcim.device"}}},
  			{"role_v1", "POST", "/api/dcim/device-roles/", map[string]any{"name": "leaf", "slug": "leaf"}},
  			{"platform", "POST", "/api/dcim/platforms/", map[string]any{"name": "eos", "slug": "eos", "network_driver": "arista_eos"}},
  			{"tag", "POST", "/api/extras/tags/", map[string]any{"name": "port49", "slug": "port49", "content_types": []any{"dcim.device"}}},
  			{"custom_field", "POST", "/api/extras/custom-fields/", map[string]any{"label": "os_version", "key": "os_version", "name": "os_version", "type": "text", "content_types": []any{"dcim.device"}}},
  			{"device", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "role": "@role.id", "location": "@location.id", "platform": "@platform.id", "status": "Active", "custom_fields": map[string]any{"os_version": "4.31.2F"}, "tags": []any{"@tag.id"}}},
  			{"device_v1", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "device_role": "@role_v1.id", "site": "@site_v1.id", "platform": "@platform.id", "status": "active", "custom_fields": map[string]any{"os_version": "4.31.2F"}}},
  			{"mgmt", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Management1", "type": "virtual", "status": "Active"}},
  			{"loopback", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Loopback0", "type": "virtual", "status": "Active"}},
  			{"prefix", "POST", "/api/ipam/prefixes/", map[string]any{"prefix": "10.0.0.0/8", "status": "Active"}},
  			{"mgmt_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.5/32", "status": "Active"}},
  			{"loop_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.6/32", "status": "Active"}},
  			{"mgmt_bind", "POST", "/api/ipam/ip-address-to-interface/", map[string]any{"ip_address": "@mgmt_ip.id", "interface": "@mgmt.id"}},
  			{"loop_bind", "POST", "/api/ipam/ip-address-to-interface/", map[string]any{"ip_address": "@loop_ip.id", "interface": "@loopback.id"}},
  			// A Nautobot detail URL takes the object's UUID, never its name.
  			{"primary", "PATCH", "/api/dcim/devices/@device.id/", map[string]any{"primary_ip4": "@mgmt_ip.id"}},
  		}
  	}
  	return []step{
  		{"site", "POST", "/api/dcim/sites/", map[string]any{"name": "dc1", "slug": "dc1"}},
  		{"manufacturer", "POST", "/api/dcim/manufacturers/", map[string]any{"name": "Arista", "slug": "arista"}},
  		{"device_type", "POST", "/api/dcim/device-types/", map[string]any{"manufacturer": "@manufacturer.id", "model": "vEOS", "slug": "veos"}},
  		{"role", "POST", "/api/dcim/device-roles/", map[string]any{"name": "leaf", "slug": "leaf", "color": "00ff00"}},
  		{"platform", "POST", "/api/dcim/platforms/", map[string]any{"name": "eos", "slug": "eos"}},
  		{"tag", "POST", "/api/extras/tags/", map[string]any{"name": "port49", "slug": "port49"}},
  		{"custom_field", "POST", "/api/extras/custom-fields/", map[string]any{"name": "os_version", "type": "text", "object_types": []any{"dcim.device"}}},
  		{"custom_field_v3", "POST", "/api/extras/custom-fields/", map[string]any{"name": "os_version", "type": "text", "content_types": []any{"dcim.device"}}},
  		{"device", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "role": "@role.id", "site": "@site.id", "platform": "@platform.id", "status": "active", "custom_fields": map[string]any{"os_version": "4.31.2F"}, "tags": []any{map[string]any{"slug": "port49"}}}},
  		{"device_v3", "POST", "/api/dcim/devices/", map[string]any{"name": "leaf-01", "device_type": "@device_type.id", "device_role": "@role.id", "site": "@site.id", "platform": "@platform.id", "status": "active", "custom_fields": map[string]any{"os_version": "4.31.2F"}, "tags": []any{map[string]any{"slug": "port49"}}}},
  		{"mgmt", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Management1", "type": "virtual"}},
  		{"loopback", "POST", "/api/dcim/interfaces/", map[string]any{"device": "@device.id", "name": "Loopback0", "type": "virtual"}},
  		{"mgmt_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.5/32", "assigned_object_type": "dcim.interface", "assigned_object_id": "@mgmt.id"}},
  		{"loop_ip", "POST", "/api/ipam/ip-addresses/", map[string]any{"address": "10.0.1.6/32", "assigned_object_type": "dcim.interface", "assigned_object_id": "@loopback.id"}},
  		{"primary", "PATCH", "/api/dcim/devices/@device.id/", map[string]any{"primary_ip4": "@mgmt_ip.id"}},
  	}
  }

  // graphQLCandidates are the query shapes to try, one device with every fact
  // and every interface's addresses. The run records which each version takes.
  func graphQLCandidates(product string) []string {
  	if product == "nautobot" {
  		return []string{
  			`{ devices(name: "leaf-01") { name platform { name network_driver } location { name } role { name } primary_ip4 { address } _custom_field_data tags { name } interfaces { name ip_addresses { address } } } }`,
  			`{ devices(name: "leaf-01") { name platform { slug } site { slug } device_role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
  		}
  	}
  	return []string{
  		`{ device_list(filters: {name: {exact: "leaf-01"}}) { name platform { slug } site { slug } role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
  		`{ device_list(filters: {name: "leaf-01"}) { name platform { slug } site { slug } role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
  		`{ device_list(name: "leaf-01") { name platform { slug } site { slug } device_role { slug } primary_ip4 { address } custom_fields tags { slug } interfaces { name ip_addresses { address } } } }`,
  	}
  }

  // webhookSteps configure a webhook to url with secret for device create,
  // update and delete, then make one of each: an update of leaf-01's
  // os_version, and a device leaf-02 created and deleted.
  func webhookSteps(product, url, secret string) []step {
  	hook := map[string]any{"name": "l27", "payload_url": url, "http_method": "POST", "http_content_type": "application/json", "secret": secret, "enabled": true}
  	var setup []step
  	switch product {
  	case "nautobot":
  		h := map[string]any{"content_types": []any{"dcim.device"}, "type_create": true, "type_update": true, "type_delete": true}
  		for k, v := range hook {
  			h[k] = v
  		}
  		setup = []step{{"webhook", "POST", "/api/extras/webhooks/", h}}
  	default:
  		v3 := map[string]any{"content_types": []any{"dcim.device"}, "type_create": true, "type_update": true, "type_delete": true}
  		for k, v := range hook {
  			v3[k] = v
  		}
  		setup = []step{
  			{"webhook", "POST", "/api/extras/webhooks/", hook},
  			{"event_rule", "POST", "/api/extras/event-rules/", map[string]any{"name": "l27", "object_types": []any{"dcim.device"}, "event_types": []any{"object_created", "object_updated", "object_deleted"}, "action_type": "webhook", "action_object_type": "extras.webhook", "action_object_id": "@webhook.id", "enabled": true}},
  			{"webhook_v3", "POST", "/api/extras/webhooks/", v3},
  		}
  	}
  	second := map[string]any{"name": "leaf-02", "device_type": "@device_type.id", "role": "@role.id", "site": "@site.id", "status": "active"}
  	if product == "nautobot" {
  		second = map[string]any{"name": "leaf-02", "device_type": "@device_type.id", "role": "@role.id", "location": "@location.id", "status": "Active"}
  	}
  	return append(setup,
  		step{"update", "PATCH", "/api/dcim/devices/@device.id/", map[string]any{"custom_fields": map[string]any{"os_version": "4.32.2F"}}},
  		step{"create_2", "POST", "/api/dcim/devices/", second},
  		step{"delete_2", "DELETE", "/api/dcim/devices/@create_2.id/", nil},
  	)
  }
  ```

  Where a version took the `_v1`/`_v3` step and refused the first, the steps after it named an
  object that does not exist: run that stack again from a fresh `docker compose up` with
  `-prefer-legacy`, which resolves the names in that product's `legacyTwin` map to the twin's
  value, and give the rerun its own directory — `-out tests/lab/sot/fixtures/<product>-<version>-legacy`
  — so neither run's fixtures overwrite the other's. Which spelling each version refused is the
  finding, and the note cites both directories.

- [ ] **Step 4: Run it, per product and version.** For each of the four stacks, with
  `tests/lab/sot/run.sh` (its `README.md` beside it lists every variable):

  ```bash
  tests/lab/sot/run.sh netbox-4          # likewise netbox-3.7, nautobot-1.6, nautobot-2
  tests/lab/sot/run.sh netbox-3.7 legacy # the -prefer-legacy rerun, fixtures/<stack>-legacy
  ```

  The script generates every database password, secret key, admin password and API token fresh per
  run into a 0600 env file outside the repository (the compose files read `${L27_…:?}` and hold no
  value), and never prints one. NetBox 4's token is v2: netbox-docker 5.1.1 provisions it from a
  12-character key, a 40-character token and a pepper, and the recorder sends
  `Authorization: Bearer nbt_<key>.<token>` (`-auth-scheme Bearer`); every other stack uses
  `Token <40 hex>`. The script brings the stack up, gives `/api/status/` 10 minutes, runs the
  recorder under a 10-minute timeout, logs to `tests/lab/logs/l27-<stack>.log` (the compose log beside
  it, credentials replaced by `<redacted>`), and runs `docker compose down -v` on every exit.
  Compose puts each stack on its own network, `<name>_default`, and the worker reaches the host on
  that network's gateway, so the listener binds it; the script reads it per stack. If the host firewall
  drops the worker's connection to it, the deliveries count is zero and the worker's log says
  so: open the port for that bridge and rerun the stack. Run the Task-level watchdog (above) beside each. Expected:
  the recorder's last line counts at least one webhook delivery. Zero deliveries is a finding (the
  worker's log says why); record it, never retry until one appears.

- [ ] **Step 5: The unit test that holds the notes to the fixtures.** `tests/lab/sot_unit_test.go`
  (its name ends `_unit_test.go`, so `make lab-unit` runs it):

  ```go
  //go:build lab

  package lab

  import (
  	"encoding/json"
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"
  )

  // TestL27FixturesAreWhatTheNotesSay reads every recorded fixture directory:
  // each file parses, no fixture carries the lab API token's header, and the
  // version each status.json reports is named in its product's note, so a note
  // cannot claim a version the run did not record.
  func TestL27FixturesAreWhatTheNotesSay(t *testing.T) {
  	dirs, _ := filepath.Glob(filepath.Join("sot", "fixtures", "*"))
  	if len(dirs) == 0 {
  		t.Skip("no L27 fixtures recorded yet")
  	}
  	for _, dir := range dirs {
  		product := strings.SplitN(filepath.Base(dir), "-", 2)[0]
  		note, err := os.ReadFile(filepath.Join("results", "L27-"+product+".md"))
  		if err != nil {
  			t.Fatalf("%s has fixtures and no note: %v", dir, err)
  		}
  		for _, name := range []string{"status.json", "api-root.json", "seed.json", "rest-device.json",
  			"rest-page.json", "graphql.json", "webhooks.json"} {
  			raw, err := os.ReadFile(filepath.Join(dir, name))
  			if err != nil {
  				t.Fatalf("%s: %v", dir, err)
  			}
  			if !json.Valid(raw) {
  				t.Fatalf("%s/%s is not JSON", dir, name)
  			}
  			if strings.Contains(string(raw), `"Authorization"`) {
  				t.Fatalf("%s/%s carries an Authorization header", dir, name)
  			}
  		}
  		var status struct {
  			Body map[string]any `json:"body"`
  		}
  		raw, _ := os.ReadFile(filepath.Join(dir, "status.json"))
  		if err := json.Unmarshal(raw, &status); err != nil {
  			t.Fatal(err)
  		}
  		version, _ := status.Body[product+"-version"].(string)
  		if version == "" || !strings.Contains(string(note), version) {
  			t.Errorf("%s reports %s-version %q, which L27-%s.md does not name", dir, product, version, product)
  		}
  	}
  }
  ```

  Run: `make lab-unit` — Expected: PASS once the notes exist (Step 6); before them, FAIL naming the
  missing note.

- [ ] **Step 6: Write the notes from the fixtures.** `tests/lab/results/L27-netbox.md` and
  `L27-nautobot.md`, each in the register's note form: date measured, product and exact version
  per stack (from `status.json`), image digests, the compose file, the fixture directory as the
  capture pointer, and one table per claim of the L27 row with a cell per version, each cell quoting
  the fixture field it was read from:

  | claim | 3.7 | 4.x |
  |---|---|---|
  | version reported by | `status.json` `netbox-version` = … ; `API-Version` header = … | … |
  | role field (REST) | `device_role` / `role` | … |
  | … | … | … |
  | one GraphQL query returns every interface address | candidate N: yes/no (`graphql.json` step `graphql_N`) | … |
  | webhook signature | `X-Hook-Signature` = HMAC-SHA512(body, secret): true/false | … |

  A cell the run could not fill says "not observed" and why. State the webhook secret is a lab
  value. Do not close L27 here: Task 21 does, and only for the versions measured.

- [ ] **Step 7: Commit**

```bash
git add tests/lab/sot tests/lab/cmd/sot-record tests/lab/sot_unit_test.go tests/lab/results/L27-*.md
git commit -m "test(lab): record what NetBox and Nautobot return for a device (L27)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---
### Task 3: Admission resolves one device at a time, and says why it refused one

**Files:**
- Modify: `internal/admission/admission.go`
- Test: `internal/admission/admission_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `Device.Transport string` (`""` or `"tcp"`; `"tls"` refused by `ParseFile`).
  - `Resolved{Device Device; KeyRef string; WirePlatform string; Refused string; Refusal string}` —
    `Refused` empty is admitted; `Refusal` is one of `RefusedNoGroup` (`"no_key_group"`),
    `RefusedTie` (`"key_group_tie"`), `RefusedUnknownKey` (`"key_ref_undefined"`); `WirePlatform`
    empty is `Device.Platform`.
  - `type Tier string` with `TierPin`, `TierAttribute`, `TierCIDR`;
    `type Assignment struct{ KeyRef string; Tier Tier; Group string }`.
  - `func (g KeyGroup) String() string` — `cidr 10.0.0.0/8 → prod_key`, `attributes {env: lab} →
    lab_key`.
  - `func Validate(devices []Device) error` — names present and unique, no address twice.
  - `func Assign(d Device, groups []KeyGroup) (Assignment, error)` — the zero `Assignment` when no
    group matches; an error only for a same-tier tie, text unchanged from today's.
  - `func NewTrie(entries []Resolved) (*Trie, error)` — indexes every entry's addresses, a refused
    one's included.
  - `func ParseFile(raw []byte, name string) (Inventory, error)`; `LoadFile` reads and calls it.
  - `Build(inv)` keeps its behaviour exactly: a device no group admits is left out.

- [ ] **Step 1: Write the failing tests.** Append to `internal/admission/admission_test.go`:

```go
func TestAssignNamesTheTierAndTheGroup(t *testing.T) {
	inv, err := LoadFile("testdata/inventory.yaml")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]Device{}
	for _, d := range inv.Devices {
		byName[d.Name] = d
	}
	for _, c := range []struct {
		device string
		want   Assignment
	}{
		{"leaf-01", Assignment{KeyRef: "prod_key", Tier: TierCIDR, Group: "cidr 10.0.0.0/8 → prod_key"}},
		{"lab-sw-1", Assignment{KeyRef: "lab_key", Tier: TierAttribute, Group: "attributes {env: lab} → lab_key"}},
		{"pinned-1", Assignment{KeyRef: "special_key", Tier: TierPin, Group: "key_ref pinned on the device record"}},
	} {
		got, err := Assign(byName[c.device], inv.KeyGroups)
		if err != nil || got != c.want {
			t.Errorf("%s: %+v, %v; want %+v", c.device, got, err, c.want)
		}
	}
	stray := Device{Name: "stray", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	if got, err := Assign(stray, inv.KeyGroups); err != nil || got != (Assignment{}) {
		t.Errorf("a device no group matches is the zero assignment, not an error: %+v, %v", got, err)
	}
}

func TestAssignRefusesATieOnTheDevice(t *testing.T) {
	groups := []KeyGroup{{Attributes: map[string]string{"site": "campus"}, KeyRef: "a"},
		{Attributes: map[string]string{"role": "leaf"}, KeyRef: "b"}}
	both := Device{Name: "both", Attributes: map[string]string{"site": "campus", "role": "leaf"}}
	if _, err := Assign(both, groups); err == nil || !strings.Contains(err.Error(), "attribute tier") {
		t.Fatalf("want the attribute-tier tie, got %v", err)
	}
}

// A refused device is still in the index, so its packets are told apart from
// an unknown source's (spec §10's admission_refused bucket).
func TestNewTrieIndexesARefusedDevice(t *testing.T) {
	d := Device{Name: "stray", Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}
	tr, err := NewTrie([]Resolved{{Device: d, Refused: "matches no key group"}})
	if err != nil {
		t.Fatal(err)
	}
	r, ok := tr.Lookup(netip.MustParseAddr("192.0.2.1"))
	if !ok || r.Refused == "" || r.Device.Name != "stray" {
		t.Fatalf("got %+v, %v", r, ok)
	}
	a := Device{Name: "a", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	b := Device{Name: "b", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}
	if _, err := NewTrie([]Resolved{{Device: a}, {Device: b}}); err == nil {
		t.Fatal("two devices on one address were indexed")
	}
}

func TestValidateNamesBothDevicesOfACollision(t *testing.T) {
	err := Validate([]Device{{Name: "a", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}},
		{Name: "b", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.1")}}})
	if err == nil || !strings.Contains(err.Error(), `"a"`) || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("want both named, got %v", err)
	}
	if err := Validate([]Device{{Name: "a"}, {Name: "a"}}); err == nil {
		t.Fatal("a repeated name passed")
	}
}

func TestParseFileTransport(t *testing.T) {
	parse := func(transport string) error {
		_, err := ParseFile([]byte("devices: [{name: a, platform: arista_eos, addresses: [10.0.0.1], transport: "+
			transport+"}]\n"), "inventory.yaml")
		return err
	}
	if err := parse("tcp"); err != nil {
		t.Fatalf("tcp: %v", err)
	}
	if err := parse("tls"); err == nil || !strings.Contains(err.Error(), "plan 11") {
		t.Fatalf("tls: %v", err)
	}
	if err := parse("udp"); err == nil || !strings.Contains(err.Error(), `transport "udp"`) {
		t.Fatalf("udp: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/admission/ -count=1`
Expected: FAIL to compile — `undefined: Assign`, `TierCIDR`, `NewTrie`, `Validate`, `ParseFile`,
and `unknown field Refused`.

- [ ] **Step 3: Write the implementation.** In `internal/admission/admission.go`, replace the
  `Device`, `Resolved` and `Build` declarations and `resolveKeyRef`, and add the rest; `KeyGroup`,
  `Inventory`, `Trie`, `Lookup` and `attrsMatch` stay as they are:

```go
// Transport is how a device speaks TACACS+ (spec §10: a device record MUST
// be able to express both).
const (
	TransportTCP = "tcp" // RFC 8907, obfuscated under a shared key; the default
	TransportTLS = "tls" // RFC 9887; refused at load until plan 11 serves it
)

type Device struct {
	Name       string
	Platform   string
	Addresses  []netip.Addr
	Attributes map[string]string
	KeyRef     string // tier 1 pin; empty when not pinned
	Transport  string // "" is TransportTCP
}

type Resolved struct {
	Device Device
	KeyRef string
	// WirePlatform is the shipped platform whose wire facts port49d reads for
	// this device (spec §8): its own, or the one a `based_on:` variant names.
	// Empty is Device.Platform.
	WirePlatform string
	// Refused says why a device in the inventory is not admitted — no key
	// group matches it, two tie on it, or its key_ref is one port49d holds no
	// key for (spec §10). Empty is admitted. A refused device is in the index
	// all the same, so its packets are told apart from an unknown source's.
	Refused string
	// Refusal is which of the three it is (RefusedNoGroup, RefusedTie,
	// RefusedUnknownKey), for a reader that decides by it: `port49 policy
	// test` fails on a tie and an unknown key and reports the other.
	Refusal string
}

// Why admission refused a device (spec §10).
const (
	RefusedNoGroup    = "no_key_group"
	RefusedTie        = "key_group_tie"
	RefusedUnknownKey = "key_ref_undefined"
)

// Tier is which rule assigned a device its key_ref, most specific first
// (spec §10, "Key group matching is deterministic").
type Tier string

const (
	TierPin       Tier = "pin"
	TierAttribute Tier = "attribute"
	TierCIDR      Tier = "cidr"
)

// Assignment is a device's key_ref, the tier that chose it and the rule that
// did, as `port49 keys show` prints it.
type Assignment struct {
	KeyRef string
	Tier   Tier
	Group  string
}

// String renders a group as `keys show` and the refusal lines name it.
func (g KeyGroup) String() string {
	if g.CIDR.IsValid() {
		return fmt.Sprintf("cidr %s → %s", g.CIDR, g.KeyRef)
	}
	keys := make([]string, 0, len(g.Attributes))
	for k := range g.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + g.Attributes[k]
	}
	return fmt.Sprintf("attributes {%s} → %s", strings.Join(parts, ", "), g.KeyRef)
}

// Validate refuses an inventory that cannot be used at all: a device with no
// name or a name used twice, and one address claimed by two devices.
//
// The device name is a namespace, not a label: store.TokenKey and
// store.ContextKey are keyed on it, so two devices sharing a name (the empty
// string included) share a token namespace, and a token minted for one
// redeems on the other. An address claimed twice would bind one device's
// sessions to another in every record (spec §10, "Addresses must resolve to
// one device"): the snapshot is refused, never a winner picked.
func Validate(devices []Device) error {
	named := make(map[string]bool, len(devices))
	for _, d := range devices {
		if d.Name == "" {
			return fmt.Errorf("admission: a device with addresses %v has no name; give every device a unique name", d.Addresses)
		}
		if named[d.Name] {
			return fmt.Errorf("admission: two devices are both named %q; device names are token namespaces and must be unique", d.Name)
		}
		named[d.Name] = true
	}
	owner := make(map[netip.Addr]string)
	for _, d := range devices {
		for _, a := range d.Addresses {
			if prev, dup := owner[a]; dup {
				return fmt.Errorf("admission: address %s claimed by both %q and %q", a, prev, d.Name)
			}
			owner[a] = d.Name
		}
	}
	return nil
}

// Assign is d's key_ref by tier (spec §10): a pin on the record, then an
// attribute group, then the longest matching CIDR, which every one of the
// device's addresses must agree on. No group matching is the zero
// Assignment, and the caller refuses the device. Two groups tying in one tier
// is an error naming both: refusing to guess is the only conservative answer,
// since a device admitted under the wrong group is admitted under the wrong
// key.
func Assign(d Device, groups []KeyGroup) (Assignment, error) {
	if d.KeyRef != "" {
		return Assignment{KeyRef: d.KeyRef, Tier: TierPin, Group: "key_ref pinned on the device record"}, nil // tier 1
	}
	var attrHits []KeyGroup
	for _, g := range groups {
		if len(g.Attributes) > 0 && attrsMatch(d.Attributes, g.Attributes) {
			attrHits = append(attrHits, g)
		}
	}
	if len(attrHits) > 1 {
		return Assignment{}, fmt.Errorf("admission: device %q matches key groups %q and %q in the attribute tier", d.Name, attrHits[0].KeyRef, attrHits[1].KeyRef)
	}
	if len(attrHits) == 1 {
		return Assignment{KeyRef: attrHits[0].KeyRef, Tier: TierAttribute, Group: attrHits[0].String()}, nil // tier 2
	}
	// Tier 3: each address resolves to its longest matching CIDR group, and
	// every address that matched must resolve to the same key_ref.
	var winners []KeyGroup
	for _, a := range d.Addresses {
		var hits []KeyGroup
		for _, g := range groups {
			if g.CIDR.IsValid() && g.CIDR.Contains(a) {
				hits = append(hits, g)
			}
		}
		sort.Slice(hits, func(i, j int) bool { return hits[i].CIDR.Bits() > hits[j].CIDR.Bits() })
		if len(hits) == 0 {
			continue
		}
		if len(hits) > 1 && hits[0].CIDR.Bits() == hits[1].CIDR.Bits() {
			return Assignment{}, fmt.Errorf("admission: device %q address %s matches key groups %q and %q at equal prefix length", d.Name, a, hits[0].KeyRef, hits[1].KeyRef)
		}
		winners = append(winners, hits[0])
	}
	if len(winners) == 0 {
		return Assignment{}, nil
	}
	for _, w := range winners[1:] {
		if w.KeyRef != winners[0].KeyRef {
			return Assignment{}, fmt.Errorf("admission: device %q: addresses resolve to different keys: %s (%s) and %s (%s)", d.Name, winners[0].CIDR, winners[0].KeyRef, w.CIDR, w.KeyRef)
		}
	}
	return Assignment{KeyRef: winners[0].KeyRef, Tier: TierCIDR, Group: winners[0].String()}, nil
}

// NewTrie indexes entries by every address each carries, a refused entry's
// included. Two entries on one address is an error: Validate refuses that
// inventory first, so reaching it here is a caller's defect.
func NewTrie(entries []Resolved) (*Trie, error) {
	t := &Trie{byAddr: make(map[netip.Addr]Resolved)}
	for _, r := range entries {
		for _, a := range r.Device.Addresses {
			if prev, dup := t.byAddr[a]; dup {
				return nil, fmt.Errorf("admission: address %s claimed by both %q and %q", a, prev.Device.Name, r.Device.Name)
			}
			t.byAddr[a] = r
		}
	}
	return t, nil
}

// Build is the admission index port49d with no broker reads (plan 1): the
// inventory file's own key groups, a tie refused whole, and a device no
// group admits left out of the index, as it always was. With a broker, the
// policy file assigns keys and refuses a device on its own
// (policy.Policy.Admission).
func Build(inv Inventory) (*Trie, error) {
	if err := Validate(inv.Devices); err != nil {
		return nil, err
	}
	entries := make([]Resolved, 0, len(inv.Devices))
	for _, d := range inv.Devices {
		as, err := Assign(d, inv.KeyGroups)
		if err != nil {
			return nil, err
		}
		if as.KeyRef == "" {
			continue // in inventory, but no group admits it: refused (spec §10)
		}
		entries = append(entries, Resolved{Device: d, KeyRef: as.KeyRef})
	}
	return NewTrie(entries)
}
```

  Delete `resolveKeyRef` (Assign replaces it). Add `"strings"` to the imports. In the file schema
  add `Transport string \`yaml:"transport"\`` to the device struct, and split `LoadFile`:

```go
func LoadFile(path string) (Inventory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Inventory{}, err
	}
	return ParseFile(raw, path)
}

// ParseFile is LoadFile for bytes already read, named by path in its errors:
// port49d loads exactly the bytes its watch agreed on (plan 6a).
func ParseFile(raw []byte, path string) (Inventory, error) {
	// KnownFields: an unknown key here is a typo with teeth. `keyref:` for
	// `key_ref:` silently un-pins a device onto a group key, and the first
	// packet from it reads `no_known_key_matches` — the 3am discovery this
	// package's doc says cannot happen.
	var f fileInventory
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return Inventory{}, fmt.Errorf("admission: %s: %w; check the key spelling against the inventory schema", path, err)
	}
	var inv Inventory
	for _, d := range f.Devices {
		switch d.Transport {
		case "", TransportTCP:
		case TransportTLS:
			return Inventory{}, fmt.Errorf("admission: %s: device %q: transport tls is RFC 9887, which port49d "+
				"does not serve until plan 11; remove the key or set it to tcp", path, d.Name)
		default:
			return Inventory{}, fmt.Errorf("admission: %s: device %q: transport %q is not tcp or tls", path, d.Name, d.Transport)
		}
		dev := Device{Name: d.Name, Platform: d.Platform, Attributes: d.Attributes, KeyRef: d.KeyRef, Transport: d.Transport}
		for _, s := range d.Addresses {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: device %q: %w", d.Name, err)
			}
			dev.Addresses = append(dev.Addresses, a)
		}
		inv.Devices = append(inv.Devices, dev)
	}
	for _, g := range f.KeyGroups {
		kg := KeyGroup{Attributes: g.Match.Attributes, KeyRef: g.KeyRef}
		if g.Match.CIDR != "" {
			p, err := netip.ParsePrefix(g.Match.CIDR)
			if err != nil {
				return Inventory{}, fmt.Errorf("admission: key group %q: %w", g.KeyRef, err)
			}
			kg.CIDR = p
		}
		if kg.KeyRef == "" {
			return Inventory{}, fmt.Errorf("admission: %s: a key group has no key_ref; every group must name the key it admits", path)
		}
		// A group with neither match term is not a narrow group, it is a
		// catch-all: attrsMatch against an empty want is vacuously true, so it
		// would claim every device in the attribute tier and quietly admit the
		// fleet under one key.
		if !kg.CIDR.IsValid() && len(kg.Attributes) == 0 {
			return Inventory{}, fmt.Errorf("admission: %s: key group %q matches on neither cidr nor attributes; give it one or remove it", path, kg.KeyRef)
		}
		inv.KeyGroups = append(inv.KeyGroups, kg)
	}
	return inv, nil
}
```

- [ ] **Step 4: Run the package's tests**

Run: `go test ./internal/admission/ -count=1`
Expected: PASS, the existing `TestLookupTiers`, `TestBuildRefusesAddressCollision` and
`TestBuildRefusesUnnamedOrDuplicateDevices` included.

- [ ] **Step 5: Run everything and commit**

Run: `make test && make vet && make build`
Expected: PASS; nothing outside the package calls `resolveKeyRef`.

```bash
git add internal/admission
git commit -m "feat(admission): assign one device at a time and keep a refused device in the index

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Key groups are policy, and the policy admits each device or says why not

**Files:**
- Modify: `internal/policy/file.go` (the `key_groups` block)
- Modify: `internal/policy/load.go` (`Env`, `Policy`, `Parse`, `refusedKeys`, `device`, `buildTests`)
- Modify: `internal/policy/resolve.go` (`ErrDeviceRefused`, `resolveNow`), `internal/policy/tests.go` (`RunTests`)
- Modify: `internal/policy/explain.go` (`Explanation.Refused`, `Explain`, `Render`)
- Create: `internal/policy/admit.go`
- Test: `internal/policy/admit_test.go`

**Interfaces:**
- Consumes: `admission.Assign`, `admission.NewTrie`, `admission.Resolved`, `admission.Assignment`,
  `admission.KeyGroup` (Task 3).
- Produces:
  - `policy.Env.KeyRefs []string` (nil: unknown, refuse none for it) and
    `policy.Env.InventoryKeyGroups []admission.KeyGroup`.
  - `func (p *Policy) Admission() *admission.Trie`
  - `func (p *Policy) Admitted(name string) (admission.Resolved, bool)`
  - `func (p *Policy) AdmissionRefusals() []admission.Resolved` (by name)
  - `func (p *Policy) KeyAssignment(name string) (admission.Assignment, bool)`
  - `func (p *Policy) KeyGroups() []admission.KeyGroup`
  - `func (p *Policy) Notices() []string`
  - `func (p *Policy) AdmissionAssessed() bool` — true where key groups are declared (either file) or
    `Env.KeyRefs` is known; only then does admission refuse anything a caller acts on.
  - `policy.ErrDeviceRefused`, returned by `Resolve` and `ResolveSubject` for a device admission
    refuses, where admission is assessed, after the grants check as for a quarantine.
  - The existing `func (p *Policy) Device(name string) (admission.Device, bool)`
    (`internal/policy/tests.go:357`) is unchanged, and `device` becomes an O(1) index read.
  - Each refused device's `Refusal` code and its text: `matches no key group, so no key admits it
    (spec §10)`; `is assigned key_ref <ref>, which port49d.yaml defines no key for, so it fails closed
    (spec §10)`; and a tie, `device "<name>" matches key groups ...`. Later tasks decide by the code
    and print the text.

- [ ] **Step 1: Write the failing tests.** Create `internal/policy/admit_test.go`:

```go
package policy

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
)

const keyGrouped = good + `
key_groups:
  - {match: {cidr: 10.0.0.0/8}, key_ref: prod_key}
  - {match: {attributes: {site: campus}}, key_ref: campus_key}
`

func TestKeyGroupsInThePolicyAssignAndAdmit(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"campus_key", "prod_key"}
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Admission().Lookup(netip.MustParseAddr("10.0.1.1"))
	if !ok || r.Refused != "" || r.KeyRef != "prod_key" || r.Device.Name != "leaf-01" {
		t.Fatalf("leaf-01: %+v, %v", r, ok)
	}
	// The attribute tier beats the CIDR tier (spec §10).
	if r, _ := p.Admitted("campus-sw-7"); r.KeyRef != "campus_key" || r.Refused != "" {
		t.Fatalf("campus-sw-7: %+v", r)
	}
	if as, _ := p.KeyAssignment("campus-sw-7"); as.Tier != admission.TierAttribute {
		t.Fatalf("campus-sw-7's tier: %+v", as)
	}
	if len(p.AdmissionRefusals()) != 0 {
		t.Fatalf("refused: %+v", p.AdmissionRefusals())
	}
	if d, ok := p.Device("nx-01"); !ok || d.Platform != "cisco_nxos" {
		t.Fatalf("Device: %+v, %v", d, ok)
	}
}

// A device no group admits is refused on its own; the policy loads and the
// rest of the fleet is admitted (spec §10; plan 6a Decided 5).
func TestADeviceNoGroupAdmitsIsRefusedNotThePolicy(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	refused := p.AdmissionRefusals()
	if len(refused) != 1 || refused[0].Device.Name != "stray" ||
		!strings.Contains(refused[0].Refused, "matches no key group") {
		t.Fatalf("refused: %+v", refused)
	}
	if r, ok := p.Admission().Lookup(netip.MustParseAddr("192.0.2.9")); !ok || r.Refused == "" {
		t.Fatalf("the refused device is not in the index as refused: %+v, %v", r, ok)
	}
}

func TestAKeyRefPort49dDoesNotHoldRefusesTheDevice(t *testing.T) {
	e := env()
	e.KeyRefs = []string{"prod_key"}
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("campus-sw-7"); !strings.Contains(r.Refused, "campus_key") {
		t.Fatalf("campus-sw-7: %+v", r)
	}
	if r, _ := p.Admitted("leaf-01"); r.Refused != "" {
		t.Fatalf("leaf-01: %+v", r)
	}
}

// Owner decision 1: a tie that exists only on one device refuses that device.
func TestAKeyGroupTieOnOneDeviceRefusesThatDevice(t *testing.T) {
	body := good + "key_groups:\n  - {match: {attributes: {site: campus}}, key_ref: a}\n" +
		"  - {match: {attributes: {role: leaf}}, key_ref: b}\n"
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "both", Platform: "arista_eos",
		Addresses:  []netip.Addr{netip.MustParseAddr("10.0.9.9")},
		Attributes: map[string]string{"site": "campus", "role": "leaf"}})
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("both"); !strings.Contains(r.Refused, "attribute tier") || r.Refusal != admission.RefusedTie {
		t.Fatalf("both: %+v", r)
	}
	if r, _ := p.Admitted("campus-sw-7"); r.KeyRef != "a" || r.Refused != "" {
		t.Fatalf("campus-sw-7: %+v", r)
	}
}

func TestKeyGroupLoadErrors(t *testing.T) {
	for _, c := range []struct{ name, groups, want string }{
		{"no key_ref", "  - {match: {cidr: 10.0.0.0/8}}\n", "key_ref is required"},
		{"no match", "  - {key_ref: k}\n", "matches on neither cidr nor attributes"},
		{"both terms", "  - {match: {cidr: 10.0.0.0/8, attributes: {a: b}}, key_ref: k}\n", "not both"},
		{"host bits", "  - {match: {cidr: 10.0.0.1/8}, key_ref: k}\n", "host bits"},
		{"one prefix twice", "  - {match: {cidr: 10.0.0.0/8}, key_ref: a}\n  - {match: {cidr: 10.0.0.0/8}, key_ref: b}\n",
			"tie for every device"},
		{"one attribute set twice", "  - {match: {attributes: {a: b}}, key_ref: a}\n  - {match: {attributes: {a: b}}, key_ref: b}\n",
			"tie for every device"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse([]byte(good+"key_groups:\n"+c.groups), env())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

// The inventory file's key groups apply, with a notice, until they are moved;
// where both files carry them the policy's win and the inventory's are named
// ignored, so no step of the move refuses a device (plan 6a Decided 4, C3).
func TestInventoryKeyGroupsApplyWithANoticeUntilMoved(t *testing.T) {
	e := env()
	e.InventoryKeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "prod_key"}}
	p, err := Parse([]byte(good), e)
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("leaf-01: %+v", r)
	}
	if n := p.Notices(); len(n) != 1 || !strings.Contains(n[0], "move the block into the policy file") {
		t.Fatalf("notices: %q", n)
	}
	// Both files: the policy's block wins, and the notice names the other.
	e.InventoryKeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "old_key"}}
	p, err = Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatalf("both files refused: %v", err)
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("the inventory's group won: %+v", r)
	}
	if n := p.Notices(); len(n) != 1 || !strings.Contains(n[0], "ignored") {
		t.Fatalf("notices: %q", n)
	}
}

// C1: a policy with a tests: block loads (good has one), and the tests
// resolve their devices through the index filled before buildTests.
func TestAPolicyWithTestsLoadsAndItsTestsFindTheirDevices(t *testing.T) {
	p := mustParse(t, good)
	if len(p.Tests()) == 0 {
		t.Fatal("good has tests")
	}
	for _, r := range p.RunTests(noon) {
		if r.Err != nil {
			t.Fatalf("%+v", r)
		}
	}
}

// I3: a test naming a device the inventory no longer has fails the test run,
// never the load, so an inventory change never waits on a policy edit.
func TestATestOnAnAbsentDeviceFailsTheRunNotTheLoad(t *testing.T) {
	body := strings.Replace(good, "device: leaf-01,", "device: leaf-gone,", 1)
	p, err := Parse([]byte(body), env())
	if err != nil {
		t.Fatalf("the load refused a test on an absent device: %v", err)
	}
	res := p.RunTests(noon)
	if len(res) == 0 || res[0].Err == nil || !strings.Contains(res[0].Err.Error(), `device "leaf-gone" is not in the inventory`) {
		t.Fatalf("%+v", res)
	}
}

// I2: where admission is assessed, a refused device resolves to
// ErrDeviceRefused after the grants check; where it is not (no key groups and
// no key names), nothing changes.
func TestARefusedDeviceDoesNotResolve(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	stray, _ := p.Device("stray")
	if _, err := p.Resolve("user:alice@example.com", stray, noon); !errors.Is(err, ErrDeviceRefused) {
		t.Fatalf("stray: %v", err)
	}
	if _, err := p.Resolve("user:nobody@example.com", stray, noon); !errors.Is(err, ErrNoGrants) {
		t.Fatalf("no grant is answered first: %v", err)
	}
	unassessed := mustParse(t, good)
	if unassessed.AdmissionAssessed() {
		t.Fatal("no key groups and no key names is assessed")
	}
	leaf, _ := unassessed.Device("leaf-01")
	if _, err := unassessed.Resolve("user:alice@example.com", leaf, noon); err != nil {
		t.Fatalf("an unassessed policy refused: %v", err)
	}
}
```

  (add `errors` to the file's imports).

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -run 'KeyGroup|Admits|KeyRefPort49d|TieOnOneDevice' -count=1`
Expected: FAIL to compile — `unknown field KeyRefs in struct literal`, `p.Admission undefined`.

- [ ] **Step 3: The file's block.** In `internal/policy/file.go`, add to `file` after `Acknowledge`:

```go
	KeyGroups       []fileKeyGroup          `yaml:"key_groups"`
```

  and below `fileAck`:

```go
// fileKeyGroup is one key_groups entry (spec §10): which CIDR or attribute
// pattern maps to which key_ref. Key assignment is reviewed policy, so it
// lives here and not in the inventory (plan 6a).
type fileKeyGroup struct {
	Match struct {
		CIDR       string            `yaml:"cidr"`
		Attributes map[string]string `yaml:"attributes"`
	} `yaml:"match"`
	KeyRef string `yaml:"key_ref"`
}
```

- [ ] **Step 4: `Env`, `Policy`, `Parse`.** In `internal/policy/load.go`, add to `Env` after
  `Devices`:

```go
	// KeyRefs are the key_refs port49d.yaml defines keys for, by name only:
	// a device assigned one outside them is refused admission (spec §10).
	// nil is not known — an offline tool given no --config — and refuses no
	// device for it.
	KeyRefs []string
	// InventoryKeyGroups are the key groups an inventory file still carries
	// (admission.Inventory.KeyGroups). They apply where this file has none,
	// with a notice; where it has its own, this file's win and the notice
	// names these ignored (plan 6a Decided 4).
	InventoryKeyGroups []admission.KeyGroup
```

  Add to `Policy` after `quarantine`:

```go
	// devIndex is the inventory by name, filled first thing in Parse, so
	// every step — buildTests included — finds a device in O(1).
	devIndex map[string]admission.Device
	// keyGroups assign each device its key_ref (spec §10), and admitted and
	// assigned are the answer for each inventory device, by name; trie
	// indexes admitted by address. notices are what a load says without
	// refusing (admit.go).
	keyGroups []admission.KeyGroup
	admitted  map[string]admission.Resolved
	assigned  map[string]admission.Assignment
	trie      *admission.Trie
	notices   []string
```

  In `Parse`, fill the index right after `p := &Policy{...}` is built:

```go
	p.devIndex = make(map[string]admission.Device, len(env.Devices))
	for _, d := range env.Devices {
		p.devIndex[d.Name] = d
	}
```

  and insert `p.buildKeyGroups, p.admit` into the step list right after `p.buildPlatforms`, so the
  list begins `p.buildPlatforms, p.buildKeyGroups, p.admit, p.buildLevels, ...`. `admit` needs only
  the inventory, the key groups and (Task 9) the platform blocks, all built by then, and everything
  after it can read admission. The final `p.checkDevices()` / `return p, nil` is unchanged.

  In `refusedKeys`, delete the `KeyGroups any \`yaml:"key_groups"\`` field and the `switch` case
  that refuses it (key groups now load here). Replace the private `device` method's linear scan
  (`load.go:1462`) with the index:

```go
func (p *Policy) device(name string) (admission.Device, bool) {
	d, ok := p.devIndex[name]
	return d, ok
}
```

  The one exported `Device` stays where it is, `internal/policy/tests.go:357`, reading through
  `device`; `admit.go` declares none. The callers of `device` are `buildTests` (`load.go:1372`, a
  `Parse` step, which runs after the index is filled), `review.go:47`, `explain.go:58`,
  `diff.go:847` and `:1172`, `tests.go:231` and `Device`: all read the index.

  **A test on an absent device fails the run, not the load (I3).** In `buildTests`, delete the
  check at `load.go:1372`–`1374` (`if _, ok := p.device(t.Device); !ok { return ... "is not in the
  inventory" }`). In `RunTests` (`tests.go:227`), replace `d, _ := p.device(t.Device)` with:

```go
		d, ok := p.device(t.Device)
		if !ok {
			// The inventory no longer names it: CI fails the test, and the
			// load that built this policy did not (plan 6a, I3).
			r.Err = fmt.Errorf("device %q is not in the inventory", t.Device)
			out = append(out, r)
			continue
		}
```

  and in its `switch` on the resolution's error, before the `err != nil` case:

```go
		case errors.Is(err, ErrDeviceRefused):
			r.Reason = decision.DeviceUnknown
```

  **A refused device does not resolve (I2).** In `resolve.go`, beside `ErrDeviceQuarantined`:

```go
// ErrDeviceRefused is a device the inventory names and admission refuses
// (spec §10): no key group admits it, two tie on it, or its key_ref is one
// port49d holds no key for. It cannot reach port49d, so nothing is minted for
// it, and a refresh revokes its contexts; the mint denies it device_unknown
// (spec §5.7). The wrapped message names the cause.
var ErrDeviceRefused = errors.New("policy: admission refuses the device")
```

  and in `resolveNow`, after the quarantine check:

```go
	if r, ok := p.admitted[d.Name]; ok && r.Refused != "" && p.AdmissionAssessed() {
		return Resolution{}, fmt.Errorf("%w: %s", ErrDeviceRefused, r.Refused)
	}
```

  `resolve` (no quarantine, read by the joint checks, the diff and lint) is unchanged, so what a
  policy would compile for a refused device is still reported.

  **`port49 explain` explains a refused device (N2).** In `internal/policy/explain.go`,
  `Explanation` gains, beside `Quarantined`:

```go
	// Refused is device_unknown on a device the inventory names and
	// admission refuses (spec §10), with why. Nothing else is filled in.
	Refused string
```

  `Explain`'s `switch` gains, after the `ErrDeviceQuarantined` case:

```go
	case errors.Is(err, ErrDeviceRefused):
		r, _ := p.admitted[d.Name]
		e.Refused = r.Refused
		return e, nil
```

  and `Render`, before its quarantine branch:

```go
	if e.Refused != "" {
		fmt.Fprintf(w, "deny %s\n  %s (%s) is in the inventory and admission refuses it: %s; nothing is minted "+
			"for it, and port49d closes its connections after the header (spec §10)\n", decision.DeviceUnknown,
			e.Device, e.Platform, e.Refused)
		return
	}
```

  Add to `admit_test.go`:

```go
func TestExplainSaysADeviceIsRefusedAndWhy(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	p, err := Parse([]byte(keyGrouped), e)
	if err != nil {
		t.Fatal(err)
	}
	x, err := p.Explain("alice", "", "stray", "show version", noon)
	if err != nil || !strings.Contains(x.Refused, "matches no key group") {
		t.Fatalf("%+v, %v", x, err)
	}
	var out strings.Builder
	x.Render(&out, false)
	if !strings.Contains(out.String(), "deny device_unknown") {
		t.Fatalf("%s", out.String())
	}
}
```

- [ ] **Step 5: `internal/policy/admit.go`:**

```go
package policy

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/blanketfish/port49/internal/admission"
)

// buildKeyGroups reads key_groups (spec §10). A group matches on a CIDR or on
// attributes, never both, since each tier is its own rule. Two groups that tie
// for every device they could match — one prefix twice, one attribute set
// twice — are the policy's own error and refused, naming both; a tie only
// some devices meet refuses those devices (admit; plan 6a owner decision 1).
func (p *Policy) buildKeyGroups(f file) error {
	switch {
	case len(f.KeyGroups) > 0 && len(p.env.InventoryKeyGroups) > 0:
		// Mid-migration: this file's block wins, so a reload or restart
		// between adding it here and deleting it there loads (plan 6a C3).
		p.notices = append(p.notices, fmt.Sprintf("key_groups: the inventory file's block (%d group(s)) is "+
			"ignored, since the policy file has its own; delete it from the inventory file (spec §10)",
			len(p.env.InventoryKeyGroups)))
	case len(f.KeyGroups) == 0:
		p.keyGroups = slices.Clone(p.env.InventoryKeyGroups)
		if len(p.keyGroups) > 0 {
			p.notices = append(p.notices, "key_groups are read from the inventory file; move the block into "+
				"the policy file, where key assignment is reviewed (spec §10)")
		}
		return nil
	}
	cidrs := map[netip.Prefix]string{}
	attrs := map[string]string{}
	for i, g := range f.KeyGroups {
		at := fmt.Sprintf("key_groups[%d]", i)
		if g.KeyRef == "" {
			return fmt.Errorf("%s: key_ref is required: every group names the key it admits", at)
		}
		kg := admission.KeyGroup{Attributes: g.Match.Attributes, KeyRef: g.KeyRef}
		if g.Match.CIDR != "" {
			pfx, err := netip.ParsePrefix(g.Match.CIDR)
			if err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			if pfx != pfx.Masked() {
				return fmt.Errorf("%s: cidr %s has host bits set; write %s", at, pfx, pfx.Masked())
			}
			kg.CIDR = pfx
		}
		switch {
		case kg.CIDR.IsValid() && len(kg.Attributes) > 0:
			return fmt.Errorf("%s: match on cidr or on attributes, not both: each tier is its own group (spec §10)", at)
		case !kg.CIDR.IsValid() && len(kg.Attributes) == 0:
			return fmt.Errorf("%s: matches on neither cidr nor attributes, so it would admit the whole fleet under %s; "+
				"give it one", at, kg.KeyRef)
		case kg.CIDR.IsValid():
			if prev, dup := cidrs[kg.CIDR]; dup {
				return fmt.Errorf("%s: %s and %s tie for every device in %s (spec §10); keep one", at, prev, kg, kg.CIDR)
			}
			cidrs[kg.CIDR] = kg.String()
		default:
			key := matchKey(kg.Attributes)
			if prev, dup := attrs[key]; dup {
				return fmt.Errorf("%s: %s and %s tie for every device they match (spec §10); keep one", at, prev, kg)
			}
			attrs[key] = kg.String()
		}
		p.keyGroups = append(p.keyGroups, kg)
	}
	return nil
}

// matchKey is an attribute set in one spelling, so two groups naming the
// same pairs in another order are seen to tie.
func matchKey(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%q=%q;", k, m[k])
	}
	return b.String()
}

// admit decides each inventory device's admission (spec §10): its key_ref by
// tier, or why it is refused — no group matches it, two tie on it, or its
// key_ref is not one port49d.yaml defines (Env.KeyRefs). A refused device is
// refused alone; the policy and the rest of the fleet load (plan 6a Decided 5).
// It is a Parse step, after buildKeyGroups and before buildTests.
func (p *Policy) admit(file) error {
	p.admitted = make(map[string]admission.Resolved, len(p.env.Devices))
	p.assigned = make(map[string]admission.Assignment, len(p.env.Devices))
	entries := make([]admission.Resolved, 0, len(p.env.Devices))
	for _, d := range p.env.Devices {
		r := admission.Resolved{Device: d, WirePlatform: d.Platform}
		as, err := admission.Assign(d, p.keyGroups)
		switch {
		case err != nil:
			r.Refused, r.Refusal = strings.TrimPrefix(err.Error(), "admission: "), admission.RefusedTie
		case as.KeyRef == "":
			r.Refused, r.Refusal = "matches no key group, so no key admits it (spec §10)", admission.RefusedNoGroup
		case p.env.KeyRefs != nil && !slices.Contains(p.env.KeyRefs, as.KeyRef):
			r.KeyRef, r.Refusal = as.KeyRef, admission.RefusedUnknownKey
			r.Refused = fmt.Sprintf("is assigned key_ref %s, which port49d.yaml defines no key for, so it fails "+
				"closed (spec §10)", as.KeyRef)
		default:
			r.KeyRef = as.KeyRef
		}
		p.assigned[d.Name] = as
		p.admitted[d.Name] = r
		entries = append(entries, r)
	}
	trie, err := admission.NewTrie(entries)
	if err != nil {
		return err
	}
	p.trie = trie
	return nil
}

// Admission is the address index port49d admits from: every inventory
// device, a refused one with its cause (spec §10).
func (p *Policy) Admission() *admission.Trie { return p.trie }

// Admitted is one device's admission, by inventory name.
func (p *Policy) Admitted(name string) (admission.Resolved, bool) {
	r, ok := p.admitted[name]
	return r, ok
}

// AdmissionRefusals are the inventory devices admission refuses, by name.
func (p *Policy) AdmissionRefusals() []admission.Resolved {
	var out []admission.Resolved
	for _, name := range sortedKeys(p.admitted) {
		if r := p.admitted[name]; r.Refused != "" {
			out = append(out, r)
		}
	}
	return out
}

// KeyAssignment is how a device's key_ref was chosen, for `port49 keys show`.
func (p *Policy) KeyAssignment(name string) (admission.Assignment, bool) {
	as, ok := p.assigned[name]
	return as, ok
}

// KeyGroups are the groups in force, whichever file they came from.
func (p *Policy) KeyGroups() []admission.KeyGroup { return slices.Clone(p.keyGroups) }

// Notices are what the load says without refusing: port49d prints each at
// start and at every reload that loads.
func (p *Policy) Notices() []string { return slices.Clone(p.notices) }

// AdmissionAssessed reports whether admission decides anything here: key
// groups are declared, in either file, or port49d's key names are known
// (Env.KeyRefs, which port49d always sets). An offline tool given neither —
// most of the test corpus — resolves every device as before.
func (p *Policy) AdmissionAssessed() bool { return len(p.keyGroups) > 0 || p.env.KeyRefs != nil }
```

  `errors` stays imported: `buildKeyGroups` no longer uses it, so drop it from `admit.go`'s imports
  if the compiler says it is unused.

- [ ] **Step 6: Run the package's tests**

Run: `go test ./internal/policy/ -count=1`
Expected: PASS. A test that loaded `key_groups:` in a policy and expected the "key groups live in
the inventory file" refusal now fails: find it with `grep -rn "until plan 6 moves them" internal
cmd` and delete that case, since the block now loads (plan 6a Decided 4).

- [ ] **Step 7: Run everything and commit**

Run: `make test && make vet && make build`
Expected: PASS. `testdata/spec11-inventory.yaml`'s key groups still load through the inventory
file wherever a caller passes them as `InventoryKeyGroups`; no caller does yet (Task 6), so they
change nothing today.

```bash
git add internal/policy
git commit -m "feat(policy): key groups are policy, and a device no group admits is refused on its own

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: A scope pins devices by name

**Files:**
- Modify: `internal/policy/scope.go` (`selects`)
- Modify: `internal/policy/load.go` (`buildScopes`)
- Test: `internal/policy/scope_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces: the `name` match key: `match: {name: [leaf-01, leaf-02]}` selects exactly those
  inventory devices; a comparison on `name` is a load error.

- [ ] **Step 1: Write the failing test.** Append to `internal/policy/scope_test.go`:

```go
// Spec §10: a scope MUST be able to pin a device set explicitly instead of by
// attribute. `name` reads the inventory name, as `platform` reads the
// platform; an attribute named `name` is not read.
func TestAScopePinsDevicesByName(t *testing.T) {
	body := strings.Replace(good, "  - {name: all_devices, match: {}}\n",
		"  - {name: all_devices, match: {}}\n  - {name: pinned, match: {name: [leaf-01, xe-01]}}\n", 1)
	body = strings.Replace(body, "tests:\n", "  - {subject: alice, scope: pinned, roles: [read_only]}\ntests:\n", 1)
	e := env()
	// campus-sw-7 carries an attribute named name, which a scope never reads.
	e.Devices[1].Attributes = map[string]string{"site": "campus", "name": "leaf-01"}
	p, err := Parse([]byte(body), e)
	if err != nil {
		t.Fatal(err)
	}
	s := p.scopes["pinned"]
	for _, d := range e.Devices {
		got, _ := s.selects(d)
		want := d.Name == "leaf-01" || d.Name == "xe-01"
		if got != want {
			t.Errorf("%s: selected %v, want %v", d.Name, got, want)
		}
	}
	_, err = Parse([]byte(strings.Replace(good, "match: {}", `match: {name: {lt: "m"}}`, 1)), env())
	if err == nil || !strings.Contains(err.Error(), "match.name pins devices by inventory name") {
		t.Fatalf("a comparison on name: %v", err)
	}
}
```

  `good` (in `load_test.go`) is `scopes:`, `roles:`, `subjects:`, `grants:`, then `tests:`, so the
  grant lands last in `grants:`.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/policy/ -run TestAScopePinsDevicesByName -count=1`
Expected: FAIL — `campus-sw-7: selected true, want false` (its attribute `name: leaf-01` is read)
and `leaf-01: selected false` (no attribute `name`), then no error for the comparison.

- [ ] **Step 3: Implement.** In `scope.go`'s `selects`, beside the `platform` special case:

```go
		value, present := d.Attributes[key]
		switch key {
		case "platform":
			value, present = d.Platform, d.Platform != ""
		case "name":
			// The inventory name, which pins a scope to named devices
			// (spec §10); an attribute of that name is not read.
			value, present = d.Name, true
		}
```

  In `load.go`'s `buildScopes`, inside the loop over match keys, after the empty-key check:

```go
			if key == "name" && v.Cmp != nil {
				return fmt.Errorf("scope %q: match.name pins devices by inventory name: list them, as a string "+
					"or a list, not a comparison (spec §10)", s.Name)
			}
```

- [ ] **Step 4: Run the tests, everything, and commit**

Run: `go test ./internal/policy/ -count=1 && make test && make vet`
Expected: PASS.

```bash
git add internal/policy
git commit -m "feat(policy): a scope pins devices by inventory name

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: A bundle has a name, and every tool loads the policy as port49d does

**Files:**
- Create: `internal/bundle/bundle.go`
- Test: `internal/bundle/bundle_test.go`
- Modify: `internal/policy/load.go` (`Env.Bundle`, `Policy.Source`, `raw`, `Raw`, `Inventory`)
- Modify: `cmd/port49/policy.go` (`policyFiles.load`, `policyDiff`, `grantsRemove`, `offlineEnv` removed),
  `cmd/port49/platform.go` (`platform upgrade`)
- Test: `cmd/port49/policy_test.go`
- Modify: `cmd/port49d/main.go` (`parsePolicy` becomes `parseBundle`), `cmd/port49d/reload.go`
- Modify: `cmd/port49d/reload_test.go` (file versions compare `Source`)

**Interfaces:**
- Consumes: `admission.Validate` (Task 3); `policy.Env.InventoryKeyGroups` (Task 4).
- Produces:
  - `func bundle.ID(policyRaw []byte, inv admission.Inventory) string`
  - `func bundle.Parse(policyRaw []byte, inv admission.Inventory, env policy.Env) (*policy.Policy, error)`
    — validates the inventory, sets `env.Devices`, `env.InventoryKeyGroups` and `env.Bundle`.
  - `func bundle.Load(policyPath, inventoryPath string, env policy.Env) (*policy.Policy, error)`
  - `policy.Env.Bundle string`; `(*Policy).Source string` (the policy file's `sha256:`);
    `func (p *Policy) Raw() []byte`; `func (p *Policy) Inventory() admission.Inventory`.
  - `cmd/port49d`: `func parseBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error)`.

- [ ] **Step 1: Write the failing tests.** Create `internal/bundle/bundle_test.go`:

```go
package bundle

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/policy"
)

const pol = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

func dev(name, addrs string, attrs map[string]string) admission.Device {
	d := admission.Device{Name: name, Platform: "arista_eos", Attributes: attrs}
	for _, a := range strings.Fields(addrs) {
		d.Addresses = append(d.Addresses, netip.MustParseAddr(a))
	}
	return d
}

// The name is the content: order and spelling do not change it, a fact does.
func TestIDIsTheContent(t *testing.T) {
	a := admission.Inventory{Devices: []admission.Device{dev("leaf-01", "10.0.0.2 10.0.0.1", nil),
		dev("leaf-02", "10.0.0.3", map[string]string{})}}
	b := admission.Inventory{Devices: []admission.Device{dev("leaf-02", "10.0.0.3", nil),
		dev("leaf-01", "10.0.0.1 10.0.0.2", nil)}}
	b.Devices[0].Transport = admission.TransportTCP
	if ID([]byte(pol), a) != ID([]byte(pol), b) {
		t.Fatal("reordering, an empty map and an explicit tcp changed the name")
	}
	c := admission.Inventory{Devices: []admission.Device{dev("leaf-01", "10.0.0.2 10.0.0.1", map[string]string{"site": "dc1"}),
		dev("leaf-02", "10.0.0.3", nil)}}
	if ID([]byte(pol), a) == ID([]byte(pol), c) {
		t.Fatal("an attribute did not change the name")
	}
	if ID([]byte(pol), a) == ID([]byte(pol+"\n"), a) {
		t.Fatal("the policy's bytes did not change the name")
	}
	if !strings.HasPrefix(ID([]byte(pol), a), "sha256:") {
		t.Fatal("the name is not a sha256: string")
	}
}

func TestParseNamesTheBundleAndKeepsThePolicysOwnHash(t *testing.T) {
	inv := admission.Inventory{Devices: []admission.Device{dev("leaf-01", "10.0.0.1", nil)}}
	p, err := Parse([]byte(pol), inv, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if p.Bundle != ID([]byte(pol), inv) || p.Source != engine.HashOf([]byte(pol)) {
		t.Fatalf("bundle %s source %s", p.Bundle, p.Source)
	}
	if string(p.Raw()) != pol || len(p.Inventory().Devices) != 1 {
		t.Fatal("the policy does not carry its bytes and its inventory")
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("leaf-01: %+v", r)
	}
	dup := admission.Inventory{Devices: []admission.Device{dev("a", "10.0.0.1", nil), dev("b", "10.0.0.1", nil)}}
	if _, err := Parse([]byte(pol), dup, policy.Env{}); err == nil || !strings.Contains(err.Error(), `"b"`) {
		t.Fatalf("a collision: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/bundle/ -count=1`
Expected: FAIL — `no non-test Go files` / `undefined: ID`.

- [ ] **Step 3: `policy` carries its name, its hash, its bytes and its inventory.** In
  `internal/policy/load.go`, `Env` gains after `InventoryKeyGroups`:

```go
	// Bundle names the bundle this policy is loaded into (bundle.ID), on
	// every blob and record (spec §5.7, §10). Empty is the policy file's own
	// sha256, as before plan 6a: a test, and a tool given one file.
	Bundle string
```

  `Policy`'s `Bundle` comment becomes "Bundle names the bundle this policy was loaded into, on
  every blob and record (spec §5.7, §10): `bundle.ID`, or the policy file's sha256 where the caller
  named none." and after it:

```go
	// Source is the policy file's own sha256, whatever bundle it is loaded
	// into: what port49d compares file versions by, and what a refresh reads
	// to tell an inventory-only swap from a policy edit (spec §5.1.3).
	Source string
	// raw is the file's bytes, so an inventory reload can load them again
	// against the new inventory (plan 6a).
	raw []byte
```

  In `Parse`, replace `p := &Policy{Bundle: engine.HashOf(raw), env: env}` with:

```go
	p := &Policy{Bundle: env.Bundle, Source: engine.HashOf(raw), raw: slices.Clone(raw), env: env}
	if p.Bundle == "" {
		p.Bundle = p.Source
	}
```

  And add to `admit.go`:

```go
// Raw is the policy file's bytes as loaded.
func (p *Policy) Raw() []byte { return slices.Clone(p.raw) }

// Inventory is the inventory this policy was loaded against, as read: the
// devices and any key groups the inventory file still carried.
func (p *Policy) Inventory() admission.Inventory {
	return admission.Inventory{Devices: slices.Clone(p.env.Devices), KeyGroups: slices.Clone(p.env.InventoryKeyGroups)}
}
```

- [ ] **Step 4: `internal/bundle/bundle.go`:**

```go
// Package bundle names and builds the bundle port49 runs on (spec §10; §13
// decision 28): the policy loaded against the inventory, which carries the
// admission index, the device table and the quarantine with it, and which
// policy.Live swaps whole. port49d builds it from inventory_file and
// broker.policy_file; plan 6b's inventory service publishes it. Diff and
// Check are what a swap and a review read.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/policy"
)

// ID names a bundle: "sha256:" over the policy file's sha256 and the
// inventory's canonical form, so every port49d reading the same two files
// names the same bundle, and a reformatted inventory file is the same bundle
// (spec §10). The platform set is the policy's pin, so the policy's hash
// covers it.
func ID(policyRaw []byte, inv admission.Inventory) string {
	sum := sha256.Sum256([]byte(engine.HashOf(policyRaw) + "\n" + engine.HashOf(canonical(inv))))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type canonDevice struct {
	Name       string            `json:"name"`
	Platform   string            `json:"platform"`
	Addresses  []string          `json:"addresses"`
	Attributes map[string]string `json:"attributes,omitempty"`
	KeyRef     string            `json:"key_ref,omitempty"`
	Transport  string            `json:"transport,omitempty"`
}

type canonGroup struct {
	CIDR       string            `json:"cidr,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	KeyRef     string            `json:"key_ref"`
}

// canonical is the inventory in one spelling: devices by name, each one's
// addresses sorted, an empty attribute map as none and `tcp` as the default
// it is. Key groups keep their order, which a reader of the file sees.
// encoding/json writes map keys sorted.
func canonical(inv admission.Inventory) []byte {
	devs := make([]canonDevice, 0, len(inv.Devices))
	for _, d := range inv.Devices {
		addrs := slices.Clone(d.Addresses)
		slices.SortFunc(addrs, func(a, b netip.Addr) int { return a.Compare(b) })
		c := canonDevice{Name: d.Name, Platform: d.Platform, KeyRef: d.KeyRef, Addresses: make([]string, len(addrs))}
		for i, a := range addrs {
			c.Addresses[i] = a.String()
		}
		if len(d.Attributes) > 0 {
			c.Attributes = d.Attributes
		}
		if d.Transport != admission.TransportTCP {
			c.Transport = d.Transport
		}
		devs = append(devs, c)
	}
	slices.SortFunc(devs, func(a, b canonDevice) int { return strings.Compare(a.Name, b.Name) })
	groups := make([]canonGroup, len(inv.KeyGroups))
	for i, g := range inv.KeyGroups {
		groups[i] = canonGroup{KeyRef: g.KeyRef}
		if g.CIDR.IsValid() {
			groups[i].CIDR = g.CIDR.String()
		}
		if len(g.Attributes) > 0 {
			groups[i].Attributes = g.Attributes
		}
	}
	b, err := json.Marshal(struct {
		Format    string        `json:"format"`
		Devices   []canonDevice `json:"devices"`
		KeyGroups []canonGroup  `json:"key_groups"`
	}{"port49-inventory/1", devs, groups})
	if err != nil {
		// Strings, and maps of strings, always encode.
		panic("bundle: an inventory does not encode: " + err.Error())
	}
	return b
}

// Parse builds the bundle: the inventory validated (admission.Validate), and
// the policy loaded against it under the bundle's name. env's Devices,
// InventoryKeyGroups and Bundle are set here; the caller sets the rest
// (KeyRefs, Now).
func Parse(policyRaw []byte, inv admission.Inventory, env policy.Env) (*policy.Policy, error) {
	if err := admission.Validate(inv.Devices); err != nil {
		return nil, err
	}
	env.Devices, env.InventoryKeyGroups, env.Bundle = inv.Devices, inv.KeyGroups, ID(policyRaw, inv)
	return policy.Parse(policyRaw, env)
}

// Load reads the two files and builds the bundle, as every offline tool does,
// so the bundle it names is the one port49d's records carry for those files.
func Load(policyPath, inventoryPath string, env policy.Env) (*policy.Policy, error) {
	inv, err := admission.LoadFile(inventoryPath)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(policyPath)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	p, err := Parse(raw, inv, env)
	if err != nil {
		return nil, fmt.Errorf("policy: %s: %w", policyPath, err)
	}
	return p, nil
}
```

- [ ] **Step 5: Run the package's tests**

Run: `go test ./internal/bundle/ ./internal/policy/ -count=1`
Expected: PASS.

- [ ] **Step 6: Every tool loads the bundle.** In `cmd/port49/policy.go` replace
  `policyFiles.load`:

```go
// load builds the bundle from the two files as port49d does (bundle.Load),
// so a bundle a tool names is the one port49d's records carry.
func (f *policyFiles) load() (*policy.Policy, error) {
	return bundle.Load(f.policy, f.inventory, policy.Env{})
}
```

  (import `github.com/blanketfish/port49/internal/bundle`). The other tools that load a policy against
  an inventory load it the same way, so every bundle string a tool prints is port49d's for those
  files, and a policy still reading its key groups from the inventory sees them (I7). Delete
  `offlineEnv` and replace its four callers:

  - `policyDiff` (`cmd/port49/policy.go:309`, `:314`): `before, err := bundle.Load(*oldPath,
    *inventory, policy.Env{})` and `after, err := bundle.Load(*newPath, *inventory, policy.Env{})`;
    the `admission.LoadFile` before them goes, since `bundle.Load` reads the inventory.
  - `grantsRemove` (`cmd/port49/policy.go:740`): `after, err := bundle.Parse(out, inv, policy.Env{})`,
    with `inv` the `admission.LoadFile` result it already has.
  - `platform upgrade` (`cmd/port49/platform.go:279`, `:293`): `before, err := bundle.Parse(raw,
    inv, policy.Env{})` and `after, err := bundle.Parse(moved, inv, policy.Env{})`.

  `grep -n 'offlineEnv\|policy.Load(\|policy.Parse(' cmd/port49/*.go | grep -v _test` then lists
  nothing. `offlineEnv`'s own test goes with it: in `cmd/port49/policy_test.go`'s
  `TestOfflineToolsReadTheAdaptersFromThePolicyFile` (`:467`), delete the first three lines, `if e :=
  offlineEnv(nil); e.Dialects != nil || !e.Now.IsZero() { t.Fatalf("%+v", e) }`. The rest of that
  test, which runs `policy test` on a file declaring an enable username, still holds, now through
  `bundle.Load`. `grep -rn offlineEnv cmd` then lists nothing. Add to `cmd/port49/policy_test.go`:

```go
// I7: every tool names the bundle port49d names for the same two files.
func TestPolicyDiffLoadsTheBundleAsPort49dDoes(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "policy.yaml")
	inv := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(pol, []byte("scopes: [{name: all_devices, match: {}}]\n"+
		"roles: [{name: r, privilege: readonly, permit: [show **]}]\n"+
		"subjects: [{name: s, identity: [\"user:alice@example.com\"], username: alice, token_ttl: 60s}]\n"+
		"grants: [{subject: s, scope: all_devices, roles: [r]}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte("devices: [{name: leaf-01, platform: arista_eos, addresses: [10.0.0.1]}]\n"+
		"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", pol, "--new", pol, "--inventory", inv}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	p, err := bundle.Load(pol, inv, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Admitted("leaf-01"); r.KeyRef != "prod_key" {
		t.Fatalf("the inventory's key groups were not read: %+v", r)
	}
	if !strings.HasPrefix(p.Bundle, "sha256:") || p.Bundle == p.Source {
		t.Fatalf("bundle %s source %s", p.Bundle, p.Source)
	}
}
```

  In `cmd/port49d/main.go` replace `parsePolicy` with:

```go
// parseBundle builds the bundle from the policy file's bytes and an
// inventory (bundle.Parse): a reload of either loads the one it read against
// the other in force, so the version it remembers refusing is the version it
// refused.
func parseBundle(cfg config.Config, raw []byte, inv admission.Inventory) (*policy.Policy, error) {
	pol, err := bundle.Parse(raw, inv, policy.Env{})
	if err != nil {
		return nil, fmt.Errorf("broker.policy_file %s: %w", cfg.Broker.PolicyFile, quotesCut{err})
	}
	return pol, nil
}
```

  and in `loadPolicy` call `parseBundle(cfg, raw, cfg.Inventory)`. In `cmd/port49d/reload.go`'s
  `load`, call `parseBundle(r.cfg, raw, old.Inventory())`, and compare file versions by `Source`:
  `v == old.Source` (twice: the bytes-in-force check and `pol.Source == old.Source` for
  "unchanged"), `v == r.broker.Policy.Load().Source` in `poll`, and print `Source` where the policy
  lines print a version. Change the applied line to name the bundle too:

```go
	fmt.Fprintf(stderr, "port49d: policy reloaded (%s): %s replaces %s (bundle %s); %d device(s) quarantined now, %d before\n",
		trigger, pol.Source, old.Source, pol.Bundle, quarantinedAt(pol, now), quarantinedAt(old, now))
```

  The reload tests compare file versions: `sed -i 's/Policy\.Load()\.Bundle/Policy.Load().Source/g'
  cmd/port49d/reload_test.go`.

- [ ] **Step 7: Run everything and commit**

Run: `make test && make vet && make build`
Expected: PASS. A test outside `reload_test.go` that compares a record's `bundle` with
`engine.HashOf(policy bytes)` for a policy port49d loaded (not one a test parsed directly) now
sees the bundle id; `grep -rn 'HashOf' cmd/port49d/*_test.go cmd/port49/*_test.go` finds any, and
each compares with `bundle.ID(raw, inventory)` instead.

```bash
git add internal/bundle internal/policy cmd/port49 cmd/port49d
git commit -m "feat(bundle): a bundle is named by its content, and every tool loads it as port49d does

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: What a swap changed, and whether port49d would take it

**Files:**
- Create: `internal/bundle/diff.go`
- Test: `internal/bundle/diff_test.go`
- Modify: `internal/policy/scope.go` (`Scopes`, `Selects`)

**Interfaces:**
- Consumes: `(*policy.Policy).Devices`, `Admitted`, `Quarantined`, `Bundle` (Tasks 4, 6).
- Produces:
  - `func (p *Policy) Scopes() []*Scope` (by name); `func (s *Scope) Selects(d admission.Device) bool`.
  - Kinds: `bundle.DeviceAdded`, `DeviceRemoved`, `PlatformChanged`, `AttributesChanged`,
    `AddressAdded`, `AddressRemoved`, `KeyRefChanged`, `AdmissionChanged`, `ScopeJoined`,
    `ScopeLeft` (the strings are the snake_case names: `"address_added"`, `"scope_joined"`, ...).
  - `type Change struct{ Kind, Device, Platform, Scope, Address, From, To string; Security bool }`
  - `type Report struct{ From, To string; Added, Removed, Changed int; Changes []Change }`
  - `func Diff(old, new *policy.Policy, now time.Time) Report`
  - `func (r Report) Summary() string` — `bundle <from> → <to>: +N device(s), -M, K changed`
  - `func (r Report) Security() []Change`
  - `func Check(old, new *policy.Policy, maxRemovedPercent int) error` — an inventory reload's bound:
    removals plus devices newly refused.
  - `func CheckAdmission(old, new *policy.Policy, maxRemovedPercent int) error` — a policy reload's
    bound: devices admitted under old and refused under new, the same message (N1).
  - `func NewlyRefused(old, new *policy.Policy) []admission.Resolved` — those devices, by name,
    for the refusal lines, `port49 policy diff` and Check.

- [ ] **Step 1: Write the failing tests.** Create `internal/bundle/diff_test.go`:

```go
package bundle

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
)

// A policy with a security_log scope, for the diff's security changes.
const withScopes = `
scopes:
  - {name: all_devices, match: {}}
  - {name: campus, match: {site: campus}, security_log: true}
  - {name: dc, match: {site: dc1}}
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: s, scope: campus, roles: [r]}, {subject: s, scope: dc, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

func mustBundle(t *testing.T, devices ...admission.Device) *policy.Policy {
	t.Helper()
	p, err := Parse([]byte(withScopes), admission.Inventory{Devices: devices}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiffSaysWhatChangedAndWhichChangesAreSecurity(t *testing.T) {
	old := mustBundle(t,
		dev("leaf-01", "10.0.1.1", map[string]string{"site": "dc1"}),
		dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}),
		dev("gone", "10.0.1.3", nil))
	new := mustBundle(t,
		dev("leaf-01", "10.0.1.1 10.66.0.1", map[string]string{"site": "campus"}),
		dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}),
		dev("fresh", "192.0.2.7", nil))
	rep := Diff(old, new, time.Now())
	if rep.Added != 1 || rep.Removed != 1 || rep.Changed != 1 {
		t.Fatalf("counts: %+v", rep)
	}
	want := map[string]bool{
		"device_added fresh": false, "device_removed gone": false, "attributes_changed leaf-01": false,
		"address_added leaf-01 10.66.0.1 security": false, "scope_joined leaf-01 campus security": false,
		"scope_left leaf-01 dc": false,
	}
	for _, c := range rep.Changes {
		key := c.Kind + " " + c.Device
		if c.Address != "" {
			key += " " + c.Address
		}
		if c.Scope != "" {
			key += " " + c.Scope
		}
		if c.Security {
			key += " security"
		}
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("missing %q in %+v", k, rep.Changes)
		}
	}
	if len(rep.Security()) != 2 {
		t.Fatalf("security: %+v", rep.Security())
	}
	// I5: a pin moving a device to another key, and a device becoming
	// admitted, are security changes.
	pinned := dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"})
	pinned.KeyRef = "lab_key"
	stray := dev("stray", "192.0.2.8", nil)
	before := mustBundle(t, dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}), stray)
	stray.Addresses = []netip.Addr{netip.MustParseAddr("10.0.1.8")}
	after := mustBundle(t, pinned, stray)
	var kinds []string
	for _, c := range Diff(before, after, time.Now()).Security() {
		kinds = append(kinds, c.Kind+" "+c.Device)
	}
	if got := strings.Join(kinds, ","); !strings.Contains(got, "key_ref_changed leaf-02") ||
		!strings.Contains(got, "admission_changed stray") {
		t.Fatalf("security: %s", got)
	}
	// N5: a device added and admitted is a security change; one added and
	// refused is not.
	added := mustBundle(t, dev("leaf-02", "10.0.1.2", map[string]string{"site": "dc1"}), dev("stray", "192.0.2.8", nil),
		dev("newbie", "10.0.1.9", nil), dev("outsider", "192.0.2.9", nil))
	kinds = nil
	for _, c := range Diff(before, added, time.Now()).Security() {
		kinds = append(kinds, c.Kind+" "+c.Device)
	}
	if got := strings.Join(kinds, ","); !strings.Contains(got, "device_added newbie") || strings.Contains(got, "outsider") {
		t.Fatalf("security: %s", got)
	}
}

// N1: a policy that refuses more than the bound of the devices admitted
// under the policy in force is refused, naming them.
func TestCheckAdmissionBoundsAPolicyThatRefusesTheFleet(t *testing.T) {
	devs := []admission.Device{dev("a", "10.0.3.1", nil), dev("b", "10.0.3.2", nil)}
	old := mustBundle(t, devs...)
	typo, err := Parse([]byte(strings.Replace(withScopes, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1)),
		admission.Inventory{Devices: devs}, policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	err = CheckAdmission(old, typo, 10)
	if err == nil || !strings.Contains(err.Error(), "refuses admission to 2 of 2 devices") || !strings.Contains(err.Error(), "a, b") {
		t.Fatalf("%v", err)
	}
	if err := CheckAdmission(old, typo, 100); err != nil {
		t.Fatalf("the bound off: %v", err)
	}
	if err := CheckAdmission(old, old, 10); err != nil {
		t.Fatalf("no change: %v", err)
	}
	if s := rep.Summary(); !strings.Contains(s, "+1 device(s), -1, 1 changed") || !strings.Contains(s, old.Bundle) {
		t.Fatalf("summary: %s", s)
	}
}

func TestCheckRefusesAnEmptyOrOverShrinkingInventory(t *testing.T) {
	var ten []admission.Device
	for i := 0; i < 10; i++ {
		ten = append(ten, dev(fmt.Sprintf("d%d", i), fmt.Sprintf("10.0.2.%d", i+1), nil))
	}
	old := mustBundle(t, ten...)
	if err := Check(old, mustBundle(t, ten[1:]...), 10); err != nil {
		t.Fatalf("one of ten at 10%%: %v", err)
	}
	err := Check(old, mustBundle(t, ten[2:]...), 10)
	if err == nil || !strings.Contains(err.Error(), "removes 2 of 10 devices and refuses 0 more (20%)") ||
		!strings.Contains(err.Error(), "send SIGHUP") {
		t.Fatalf("two of ten at 10%%: %v", err)
	}
	// I4: the same ten kept, two moved out of every key group, is the same
	// loss of service and is refused the same way, naming them.
	moved := append([]admission.Device(nil), ten...)
	moved[0].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	moved[1].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	err = Check(old, mustBundle(t, moved...), 10)
	if err == nil || !strings.Contains(err.Error(), "refuses 2 more") || !strings.Contains(err.Error(), "d0, d1") {
		t.Fatalf("two of ten newly refused at 10%%: %v", err)
	}
	if err := Check(old, mustBundle(t, ten[2:]...), 100); err != nil {
		t.Fatalf("the bound off: %v", err)
	}
	if err := Check(old, mustBundle(t), 100); err == nil || !strings.Contains(err.Error(), "names no device") {
		t.Fatalf("empty: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/bundle/ -run 'Diff|Check' -count=1`
Expected: FAIL to compile — `undefined: Diff`, `undefined: Check`.

- [ ] **Step 3: `policy` exposes its scopes.** Append to `internal/policy/scope.go`:

```go
// Scopes is every declared scope, by name: what the bundle diff compares
// membership of across a swap (spec §10).
func (p *Policy) Scopes() []*Scope {
	out := make([]*Scope, 0, len(p.scopes))
	for _, name := range sortedKeys(p.scopes) {
		out = append(out, p.scopes[name])
	}
	return out
}

// Selects reports whether the scope selects the device, as a grant reads it.
func (s *Scope) Selects(d admission.Device) bool {
	ok, _ := s.selects(d)
	return ok
}
```

- [ ] **Step 4: `internal/bundle/diff.go`:**

```go
package bundle

import (
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/admission"
	"github.com/blanketfish/port49/internal/policy"
)

// What a swap can change about a device (spec §10), as `port49 inventory
// diff` prints them and inventory_change records name the security ones.
const (
	DeviceAdded       = "device_added"
	DeviceRemoved     = "device_removed"
	PlatformChanged   = "platform_changed"
	AttributesChanged = "attributes_changed"
	AddressAdded      = "address_added"
	AddressRemoved    = "address_removed"
	KeyRefChanged     = "key_ref_changed"
	AdmissionChanged  = "admission_changed"
	ScopeJoined       = "scope_joined"
	ScopeLeft         = "scope_left"
)

// Change is one thing a swap changed. From and To are the before and after
// where the kind has them.
type Change struct {
	Kind, Device, Platform, Scope, Address, From, To string
	// Security marks what the log must carry as an inventory_change record:
	// an address added to a device already in inventory — the mint response
	// hands it to an SSH client, so a rogue one is a credential-capture path —
	// a device joining or leaving a scope with security_log: true (spec §5.5,
	// §10), a device's key_ref changing, and a device becoming admitted.
	Security bool
}

// Report is what one swap changed.
type Report struct {
	From, To                string
	Added, Removed, Changed int
	Changes                 []Change
}

// Diff compares two bundles. A scope is compared only where both declare it:
// a scope a policy edit added or removed is the policy diff's (spec §12).
func Diff(old, new *policy.Policy, now time.Time) Report {
	rep := Report{From: old.Bundle, To: new.Bundle}
	before, after := byName(old.Devices()), byName(new.Devices())
	names := unionNames(before, after)
	changed := map[string]bool{}
	add := func(c Change) {
		rep.Changes = append(rep.Changes, c)
		if _, was := before[c.Device]; was {
			if _, is := after[c.Device]; is {
				changed[c.Device] = true
			}
		}
	}
	for _, name := range names {
		o, inOld := before[name]
		n, inNew := after[name]
		switch {
		case !inOld:
			rep.Added++
			// An added device that is admitted starts being answered, and its
			// addresses are new capture targets: a security change, as a
			// device already in inventory becoming admitted is (N5).
			state := admissionState(new, name, now)
			add(Change{Kind: DeviceAdded, Device: name, Platform: n.Platform, To: state, Security: state == "admitted"})
		case !inNew:
			rep.Removed++
			add(Change{Kind: DeviceRemoved, Device: name, Platform: o.Platform})
		default:
			if o.Platform != n.Platform {
				add(Change{Kind: PlatformChanged, Device: name, Platform: n.Platform, From: o.Platform, To: n.Platform})
			}
			if !maps.Equal(o.Attributes, n.Attributes) {
				add(Change{Kind: AttributesChanged, Device: name, Platform: n.Platform, From: attrs(o.Attributes),
					To: attrs(n.Attributes)})
			}
			for _, a := range minus(n.Addresses, o.Addresses) {
				add(Change{Kind: AddressAdded, Device: name, Platform: n.Platform, Address: a.String(), Security: true})
			}
			for _, a := range minus(o.Addresses, n.Addresses) {
				add(Change{Kind: AddressRemoved, Device: name, Platform: n.Platform, Address: a.String()})
			}
			ro, _ := old.Admitted(name)
			rn, _ := new.Admitted(name)
			// A key_ref change moves the device onto another key — a pin in
			// the inventory can pick a weaker or a shared one — and a device
			// becoming admitted starts being answered: both are security
			// changes (plan 6a, I5).
			if ro.KeyRef != rn.KeyRef {
				add(Change{Kind: KeyRefChanged, Device: name, Platform: n.Platform, From: ro.KeyRef, To: rn.KeyRef,
					Security: true})
			}
			if so, sn := admissionState(old, name, now), admissionState(new, name, now); so != sn {
				add(Change{Kind: AdmissionChanged, Device: name, Platform: n.Platform, From: so, To: sn,
					Security: sn == "admitted"})
			}
		}
	}
	oldScopes := map[string]*policy.Scope{}
	for _, s := range old.Scopes() {
		oldScopes[s.Name] = s
	}
	for _, s := range new.Scopes() {
		os, ok := oldScopes[s.Name]
		if !ok {
			continue
		}
		security := s.SecurityLog || os.SecurityLog
		for _, name := range names {
			var was, is bool
			platform := ""
			if d, ok := before[name]; ok {
				was, platform = os.Selects(d), d.Platform
			}
			if d, ok := after[name]; ok {
				is, platform = s.Selects(d), d.Platform
			}
			switch {
			case is && !was:
				add(Change{Kind: ScopeJoined, Device: name, Platform: platform, Scope: s.Name, Security: security})
			case was && !is:
				add(Change{Kind: ScopeLeft, Device: name, Platform: platform, Scope: s.Name, Security: security})
			}
		}
	}
	rep.Changed = len(changed)
	return rep
}

// Summary is the one line port49d writes for a swap (spec §10, "Every swap
// logs a summary").
func (r Report) Summary() string {
	return fmt.Sprintf("bundle %s → %s: +%d device(s), -%d, %d changed", r.From, r.To, r.Added, r.Removed, r.Changed)
}

// Security is the changes the log carries as inventory_change records.
func (r Report) Security() []Change {
	var out []Change
	for _, c := range r.Changes {
		if c.Security {
			out = append(out, c)
		}
	}
	return out
}

// Check is what port49d refuses a new inventory for beyond Parse's refusals
// (spec §10, bounded change): an inventory with no device, and one that
// takes more than maxRemovedPercent of the devices in old out of service —
// removed, or kept and newly refused admission, which a dropped key-group
// block or a mistyped pin does to a whole fleet (plan 6a, I4). 100 turns the
// share off; nothing turns the empty check off.
func Check(old, new *policy.Policy, maxRemovedPercent int) error {
	if len(new.Devices()) == 0 {
		return errors.New("the new inventory names no device; an empty inventory admits nothing, so it is never " +
			"loaded (spec §10)")
	}
	was := len(old.Devices())
	if was == 0 || maxRemovedPercent >= 100 {
		return nil
	}
	after := byName(new.Devices())
	removed := 0
	for _, d := range old.Devices() {
		if _, ok := after[d.Name]; !ok {
			removed++
		}
	}
	refused := NewlyRefused(old, new)
	if gone := removed + len(refused); gone*100 > was*maxRemovedPercent {
		msg := fmt.Sprintf("the new inventory removes %d of %d devices and refuses %d more (%d%%), more than "+
			"inventory.max_removed_percent (%d%%)", removed, was, len(refused), gone*100/was, maxRemovedPercent)
		if len(refused) > 0 {
			msg += "; newly refused: " + names(refused) +
				" (if key_groups was deleted from the inventory file, add it to the policy file first)"
		}
		return errors.New(msg + "; fix the file, or, if the change is meant, raise inventory.max_removed_percent " +
			"in port49d.yaml and send SIGHUP, which re-reads it with the reload")
	}
	return nil
}

// CheckAdmission is a policy reload's bound (plan 6a, N1). Key groups are
// policy, so a policy edit can refuse the fleet — a CIDR typo, or the block
// deleted — and a refused device's contexts are revoked and its tokens
// deleted (I2): unbounded, one bad edit is a fleet-wide logout that a revert
// does not undo. It refuses a policy that newly refuses more than
// maxRemovedPercent of the devices admitted under old, naming them.
func CheckAdmission(old, new *policy.Policy, maxRemovedPercent int) error {
	was := len(old.Devices())
	refused := NewlyRefused(old, new)
	if was == 0 || maxRemovedPercent >= 100 || len(refused)*100 <= was*maxRemovedPercent {
		return nil
	}
	return fmt.Errorf("the new policy refuses admission to %d of %d devices (%d%%), more than "+
		"inventory.max_removed_percent (%d%%): %s; check key_groups, or, if the change is meant, raise "+
		"inventory.max_removed_percent in port49d.yaml and send SIGHUP, which re-reads it with the reload",
		len(refused), was, len(refused)*100/was, maxRemovedPercent, names(refused))
}

// NewlyRefused is every device in both bundles that old admits and new
// refuses, by name, where new assesses admission.
func NewlyRefused(old, new *policy.Policy) []admission.Resolved {
	if !new.AdmissionAssessed() {
		return nil
	}
	var out []admission.Resolved
	for _, r := range new.AdmissionRefusals() {
		if ro, ok := old.Admitted(r.Device.Name); ok && ro.Refused == "" {
			out = append(out, r)
		}
	}
	return out
}

// names is up to five devices by name, and how many more.
func names(rs []admission.Resolved) string {
	var n []string
	for i, r := range rs {
		if i == 5 {
			return strings.Join(n, ", ") + fmt.Sprintf(" and %d more", len(rs)-5)
		}
		n = append(n, r.Device.Name)
	}
	return strings.Join(n, ", ")
}

// admissionState is a device's admission in one word.
func admissionState(p *policy.Policy, name string, now time.Time) string {
	if r, _ := p.Admitted(name); r.Refused != "" {
		return "refused"
	}
	if _, q := p.Quarantined(name, now); q {
		return "quarantined"
	}
	return "admitted"
}

func byName(devices []admission.Device) map[string]admission.Device {
	out := make(map[string]admission.Device, len(devices))
	for _, d := range devices {
		out[d.Name] = d
	}
	return out
}

func unionNames(a, b map[string]admission.Device) []string {
	seen := map[string]bool{}
	for n := range a {
		seen[n] = true
	}
	for n := range b {
		seen[n] = true
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// minus is the addresses in a and not in b, sorted.
func minus(a, b []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, x := range a {
		if !slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	slices.SortFunc(out, func(x, y netip.Addr) int { return x.Compare(y) })
	return out
}

func attrs(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + m[k]
	}
	return "{" + strings.Join(parts, ", ") + "}"
}
```

  `maps` is in the standard library from Go 1.21; the module's `go 1.22` has it.

- [ ] **Step 5: Run the tests, everything, and commit**

Run: `go test ./internal/bundle/ -count=1 && make test && make vet`
Expected: PASS.

```bash
git add internal/bundle internal/policy
git commit -m "feat(bundle): diff two bundles, mark the security changes, and bound an inventory's shrink

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 8: Every validated record names its key, and the log has an inventory_change event

**Files:**
- Modify: `internal/decision/log.go` (`Device.KeyRef`, `Device.KeyVersion`, `Change`, `Record.Change`)
- Modify: `internal/decision/reasons.go` (`EventInventoryChange`)
- Modify: `internal/daemon/authen/authen.go` (`Peer`, `Wire`, `Device`)
- Modify: `internal/daemon/author/author.go`, `internal/daemon/acct/acct.go` (the record's device block)
- Modify: `internal/daemon/server/conn.go` (`dispatch` fills the peer)
- Test: `internal/daemon/server/server_test.go`, `internal/decision/log_test.go`

**Interfaces:**
- Consumes: `admission.Resolved.WirePlatform` (Task 3).
- Produces:
  - `decision.Device.KeyRef string` (`key_ref`), `KeyVersion int` (`key_version`), both omitempty.
  - `decision.EventInventoryChange = "inventory_change"`; `decision.Change{Kind, Scope, Address, From, To,
    FromBundle, ToBundle string}` with JSON keys `kind`, `scope`, `address`, `from`, `to`,
    `from_bundle`, `to_bundle`; `Record.Change *Change` (`change`).
  - `authen.Peer.KeyRef string`, `KeyVersion int`, `WirePlatform string`;
    `func (p Peer) Wire() string`; `func (p Peer) Device() *decision.Device`.

- [ ] **Step 1: Write the failing tests.** Append to `internal/daemon/server/server_test.go`:

```go
// Spec §5.7, §10: every record of a validated exchange names the key that
// validated it, which is what `port49 keys status` reads a rotation from.
func TestAValidatedExchangeNamesItsKey(t *testing.T) {
	log := &syncBuffer{}
	addr, _, _ := startServer(t, log)
	c := dial(t, addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, PrivLvl: 1, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Port: []byte("vty0"), RemAddr: []byte("198.51.100.4"),
		Data: []byte("p49_e2e")}.Encode(), 0)
	c.recv(t)
	if !waitFor(t, func() bool { return log.contains(`"event":"redeem"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"key_ref":"prod_key"`) || !log.contains(`"key_version":2`) {
		t.Fatalf("the redeem record does not name its key: %s", log.String())
	}
}
```

  and to `internal/decision/log_test.go`:

```go
func TestAnInventoryChangeRecordEncodes(t *testing.T) {
	var buf bytes.Buffer
	NewJSONLines(&buf).Emit(Record{TS: time.Unix(0, 0), Event: EventInventoryChange,
		Device: &Device{Name: "leaf-01", Platform: "arista_eos"},
		Change: &Change{Kind: "address_added", Address: "10.66.0.1", FromBundle: "sha256:a", ToBundle: "sha256:b"}})
	got := buf.String()
	for _, want := range []string{`"event":"inventory_change"`, `"kind":"address_added"`, `"address":"10.66.0.1"`,
		`"from_bundle":"sha256:a"`, `"to_bundle":"sha256:b"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if strings.Contains(got, "key_ref") {
		t.Errorf("a record no key validated names no key: %s", got)
	}
}
```

  (add `bytes`, `strings`, `time` to that test file's imports if it lacks them).

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/decision/ ./internal/daemon/server/ -run 'InventoryChange|NamesItsKey' -count=1`
Expected: FAIL — `undefined: EventInventoryChange`, then the redeem record carries no `key_ref`.

- [ ] **Step 3: The log.** In `internal/decision/log.go`, `Device` becomes:

```go
type Device struct {
	NAS      string `json:"nas"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	// KeyRef and KeyVersion name the key that validated the exchange: set on
	// every record of a validated exchange, and on none other (spec §5.7,
	// §10). `port49 keys status` reads a rotation's phase-out from them.
	KeyRef     string `json:"key_ref,omitempty"`
	KeyVersion int    `json:"key_version,omitempty"`
}
```

  `Record` gains, after `Gap`:

```go
	// Change is the inventory_change record's body (spec §5.7, §10).
	Change *Change `json:"change,omitempty"`
```

  and below `Gap`:

```go
// Change is one security-relevant change a bundle swap made (spec §10): an
// address added to a device already in inventory, or a device joining or
// leaving a scope with security_log: true. The record's device block names
// the device.
type Change struct {
	Kind    string `json:"kind"`
	Scope   string `json:"scope,omitempty"`
	Address string `json:"address,omitempty"`
	// From and To are a key_ref change's two key_refs, and an admission
	// change's two states.
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"`
	FromBundle string `json:"from_bundle"`
	ToBundle   string `json:"to_bundle"`
}
```

  In `reasons.go`'s event block, after `EventAccountGap`:

```go
	// EventInventoryChange is not a decision: a security-relevant change a
	// bundle swap made, written by the component that swapped (spec §5.7,
	// §10).
	EventInventoryChange = "inventory_change"
```

- [ ] **Step 4: The peer.** In `internal/daemon/authen/authen.go`, `Peer` becomes:

```go
type Peer struct {
	NAS      string
	NASAddr  string
	Platform string
	// KeyRef and KeyVersion are the key that validated this connection,
	// which every record of it names (spec §5.7).
	KeyRef     string
	KeyVersion int
	// WirePlatform is the shipped platform whose wire facts this device's
	// packets are read by: its own, or the base of a based_on variant (spec
	// §8). Empty is Platform.
	WirePlatform string
}

// Wire is the platform whose wire facts apply to this peer.
func (p Peer) Wire() string {
	if p.WirePlatform != "" {
		return p.WirePlatform
	}
	return p.Platform
}

// Device is the device block of every record this peer's exchanges write.
func (p Peer) Device() *decision.Device {
	return &decision.Device{NAS: p.NASAddr, Name: p.NAS, Platform: p.Platform, KeyRef: p.KeyRef, KeyVersion: p.KeyVersion}
}
```

  Replace `&decision.Device{NAS: s.peer.NASAddr, Name: s.peer.NAS, Platform: s.peer.Platform}` in
  `authen.go` with `s.peer.Device()`, and `&decision.Device{NAS: peer.NASAddr, Name: peer.NAS,
  Platform: peer.Platform}` in `author/author.go` and `acct/acct.go` with `peer.Device()`. In
  `internal/daemon/server/conn.go`'s `dispatch`, the peer becomes:

```go
	peer := authen.Peer{NAS: s.dev.Device.Name, NASAddr: s.src.String(), Platform: s.dev.Device.Platform,
		KeyRef: s.dev.KeyRef, KeyVersion: s.version, WirePlatform: s.dev.WirePlatform}
```

- [ ] **Step 5: Run the tests, everything, and commit**

Run: `go test ./internal/decision/ ./internal/daemon/... -count=1 && make test && make vet`
Expected: PASS. A test that compared a whole record's `device` block by string now sees the two
new keys: update its expected string, never drop the fields.

```bash
git add internal/decision internal/daemon
git commit -m "feat(decision): every validated record names its key; the inventory_change event

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---
### Task 9: A `based_on:` variant is read off the wire as its base, and redacted as it

**Files:**
- Modify: `internal/policy/load.go` (the `based_on` refusal), `internal/policy/admit.go` (`WirePlatform`)
- Modify: `internal/policy/resolve.go` (keyword tree and redaction), `internal/policy/lint.go`
- Modify: `internal/platform/platform.go` (delete `WireFactsDiffer`), `internal/platform/platform_test.go`
- Modify: `internal/daemon/author/author.go`, `internal/daemon/acct/acct.go` (`peer.Wire()`)
- Modify: `cmd/port49d/main.go` (`redactorFor`), `cmd/port49/capabilities.go`, `cmd/port49/platform.go`
- Modify: `internal/capability/capability.go` (`Device.WirePlatform`, `isExec`)
- Test: `internal/policy/platforms_test.go`, `internal/daemon/author/author_test.go`,
  `internal/daemon/acct/acct_test.go`, `cmd/port49d/redact_test.go`

**Interfaces:**
- Consumes: `authen.Peer.Wire()` (Task 8); `admission.Resolved.WirePlatform` (Task 3); `admit` (Task 4).
- Produces: `func (p *Policy) WirePlatform(name string) string` — the `based_on:` base of a variant,
  else `name`. `admit` sets `Resolved.WirePlatform` from it.

- [ ] **Step 1: Write the failing tests.** In `internal/policy/platforms_test.go`, delete the table
  case `{"based_on a platform whose wire facts a variant loses", ...}` and the comment above it (the
  refusal it asserts is lifted), and add:

```go
// A variant is the same device under another name: port49d reads its wire
// facts, redaction and keyword tree as its base's (spec §8; plan 6a).
func TestAJunosVariantLoadsAndIsReadAsJunos(t *testing.T) {
	e := env()
	e.Devices = append(e.Devices, admission.Device{Name: "srx-var-1", Platform: "srx_variant",
		Addresses: []netip.Addr{netip.MustParseAddr("10.0.5.50")}})
	p, err := Parse([]byte(good+"platforms:\n  srx_variant: {based_on: juniper_junos}\n"), e)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.WirePlatform("srx_variant"); got != "juniper_junos" {
		t.Fatalf("WirePlatform: %q", got)
	}
	if got := p.WirePlatform("arista_eos"); got != "arista_eos" {
		t.Fatalf("a shipped platform is its own: %q", got)
	}
	if r, _ := p.Admitted("srx-var-1"); r.WirePlatform != "juniper_junos" {
		t.Fatalf("the admission index does not carry the base: %+v", r)
	}
}
```

  In `internal/daemon/author/author_test.go`:

```go
// A juniper_junos variant arrives as junos-exec, as its base does; keyed by
// its own name it would get the fallback `shell` and be refused every
// session (spec §8; plan 6a).
func TestAVariantIsAuthorizedAsItsBase(t *testing.T) {
	h, log := setupOn(t, platform.Defaults())
	variant := authen.Peer{NAS: "leaf-01", NASAddr: "10.0.0.1", Platform: "srx_variant", WirePlatform: "juniper_junos"}
	resp := h.Handle(context.Background(), variant, req("alice", "", "service=junos-exec"))
	if resp.Status != wire.AuthorStatusPassAdd {
		t.Fatalf("a variant's session was refused: %+v", resp)
	}
	if r := lastRecord(t, log); r["reason"] != "context_matched" {
		t.Fatalf("%v", r)
	}
}
```

  In `internal/daemon/acct/acct_test.go`:

```go
// A juniper_junos variant's `cmd=logout` is its exec record, bound on
// session_pid, as Junos's is (spec §5.8, §8; plan 6a).
func TestAVariantsLogoutIsAnExecRecord(t *testing.T) {
	h, st, _, stop := setup(t)
	variant := authen.Peer{NAS: "leaf-01", NASAddr: "10.0.0.1", Platform: "srx_variant", WirePlatform: "juniper_junos"}
	putCtx(t, st, store.Context{CtxID: "ctx1", SessionDiscriminators: []string{store.HashDiscriminator("28913")}})
	h.Handle(context.Background(), variant, acct(wire.AcctFlagStop, "alice", "0", "task_id=1", "session_pid = 28913",
		"service=shell", "cmd=logout", "elapsed_time=0"))
	stop()
	if c := ctxOf(t, st); c.AccountingState != store.AccountingStateClosing {
		t.Fatalf("the variant's logout did not close the session: %+v", c)
	}
}
```

  In `cmd/port49d/redact_test.go`:

```go
// A variant keyed by its own name would get only the default redaction list,
// and Junos's own patterns (platforms/redact.yaml) would not apply to its
// records: a secret in the log (spec §5.8; plan 6a Decided 11).
func TestAVariantIsRedactedAsItsBase(t *testing.T) {
	pol, err := policy.Parse([]byte(minimalPolicy+"platforms:\n  srx_variant: {based_on: juniper_junos}\n"), policy.Env{})
	if err != nil {
		t.Fatal(err)
	}
	got := redactorFor(policy.NewLive(pol))("srx_variant")
	want := platform.Redactions("juniper_junos")
	if len(got) < len(want) || !reflect.DeepEqual(got[:len(want)], want) {
		t.Fatalf("the variant's patterns do not begin with Junos's: got %d, Junos %d", len(got), len(want))
	}
	if reflect.DeepEqual(platform.Redactions("srx_variant"), want) {
		t.Fatal("the default list equals Junos's, so this test proves nothing")
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ ./internal/daemon/... ./cmd/port49d/ -run 'Variant' -count=1`
Expected: FAIL — the policy refuses `based_on: juniper_junos` ("port49d reads juniper_junos's session
service"); `p.WirePlatform undefined`; the author test answers `service_unsupported`.

- [ ] **Step 3: Implement.** In `internal/policy/load.go`'s `buildPlatforms`, delete the block that
  calls `platform.WireFactsDiffer` and returns the refusal, and its comment. In
  `internal/platform/platform.go` delete `WireFactsDiffer` and its comment, and in
  `platform_test.go` delete `TestWireFactsDiffer`. Append to `internal/policy/admit.go`:

```go
// WirePlatform is the shipped platform whose facts port49 reads for name
// (spec §8): the one a `based_on:` block names, or name itself. A variant
// is the same device under another name, so its session services, exec
// records, system users, session discriminator, built-in redaction and
// keyword tree are its base's.
func (p *Policy) WirePlatform(name string) string {
	if b, ok := p.overrides[name]; ok && b.BasedOn != "" {
		return b.BasedOn
	}
	return name
}
```

  and in `admit`, set it: `r := admission.Resolved{Device: d, WirePlatform: p.WirePlatform(d.Platform)}`.
  In `internal/policy/resolve.go`'s `projectOnce`, read the keyword tree and the built-in patterns
  through it:

```go
	in := projection.Input{Platform: b.Platform, Dialect: dialect, Rules: b.Rules, Classes: b.Classes,
		Normalize: b.Normalize, Facts: projection.FactsFor(dialect.CommandProjection),
		Keywords: setKeywords(p.set, p.WirePlatform(b.Platform))}
	// The reply is logged whole, in the authorize_session record and the
	// blob event, so a rule redaction would hide is never sent (spec §5.8).
	patterns := append(platform.Redactions(p.WirePlatform(b.Platform)), dialect.Redact...)
```

  In `internal/policy/lint.go`, the `platform.Redactions(plat)` call becomes
  `platform.Redactions(p.WirePlatform(plat))`. In `internal/daemon/author/author.go` the service
  check becomes `h.authorizes(peer.Wire(), kv["service"])`; in `internal/daemon/acct/acct.go`,
  `platform.SessionDiscriminator(peer.Wire())`, `platform.IsExecRecord(peer.Wire(), ...)` and
  `h.isSystemUser(peer.Wire(), canonical)`. In `cmd/port49d/main.go`'s `redactorFor`:

```go
	return func(name string) []platform.Redaction {
		pol := live.Load()
		return append(platform.Redactions(pol.WirePlatform(name)), pol.Dialect(name).Redact...)
	}
```

  `internal/capability/capability.go`'s `Device` gains `WirePlatform string \`json:"wire_platform,omitempty"\``
  ("the base a variant's exec records are read as, spec §8; empty is Platform"), and its two
  `isExec(d.Platform, ...)` calls (`capability.go:219`, `:232`) read `isExec(d.wire(), ...)` with
  `func (d Device) wire() string { if d.WirePlatform != "" { return d.WirePlatform }; return d.Platform }`,
  so `devices capabilities` reads a Junos variant's `cmd=login` as its exec record (M4). The author
  handler's `serverMsg(peer.Platform, ...)` stays keyed by the variant's name: the redactor port49d
  hands it, `redactorFor`, maps the name through `WirePlatform` itself. In
  `cmd/port49/capabilities.go` each `capability.Device` gains `WirePlatform: p.WirePlatform(d.Platform)`,
  and the redactor becomes `append(platform.Redactions(p.WirePlatform(name)),
  p.Dialect(name).Redact...)`, and in `cmd/port49/platform.go`'s show path, where a policy is
  loaded (`p != nil`), list `platform.Redactions(p.WirePlatform(platformName))`; with no policy,
  `platformName` as today.

- [ ] **Step 4: Run the tests, everything, and commit**

Run: `go test ./internal/... ./cmd/... -count=1 && make test && make vet`
Expected: PASS. `grep -rn "WireFactsDiffer\|platform.Redactions(" internal cmd | grep -v _test` shows no
call keyed by a platform name a variant can carry except through `WirePlatform`.

```bash
git add internal cmd
git commit -m "feat(policy): a based_on variant is read off the wire, and redacted, as its base

A juniper_junos variant keyed by its own name would have its sessions refused,
its login records read as commands, and its records logged without Junos's
redaction patterns. The load's refusal of based_on: juniper_junos is lifted.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 10: port49d admits from the bundle in force, and closes a refused device at once

**Files:**
- Modify: `internal/daemon/server/server.go` (`Admitter`), `internal/daemon/server/conn.go`
  (`refused`, `refusedAdmission`)
- Modify: `internal/keyring/keyring.go` (`DiagAdmissionRefused`)
- Modify: `internal/daemon/metrics/metrics.go` (`DevicesAdmissionRefused`, `CountAdmissionRefused`)
- Modify: `internal/config/config.go` (broker mode admits from the policy; `KeyRefs`)
- Modify: `cmd/port49d/main.go` (`liveAdmission`, `parseBundle`'s `KeyRefs`, `sayPolicy`, the start line)
- Modify: `cmd/port49d/broker_test.go`, `cmd/port49d/redact_test.go` (devices carry a key)
- Test: `internal/daemon/server/server_test.go`, `internal/config/config_test.go`, `cmd/port49d/broker_test.go`

**Interfaces:**
- Consumes: `(*policy.Policy).Admission`, `AdmissionRefusals`, `Notices` (Task 4); `parseBundle` (Task 6).
- Produces:
  - `server.Admitter interface{ Lookup(netip.Addr) (admission.Resolved, bool) }`; `Deps.Admission
    Admitter`. `*admission.Trie` satisfies it.
  - `keyring.DiagAdmissionRefused Diagnosis = "admission_refused"`.
  - `metrics.DevicesAdmissionRefused` (`port49_devices_admission_refused`) and
    `func (m *Metrics) CountAdmissionRefused(count func() int)`.
  - `func (c config.Config) KeyRefs() []string` — sorted, never nil.
  - `cmd/port49d`: `type liveAdmission struct{ live *policy.Live }`.

- [ ] **Step 1: Write the failing tests.** Append to `internal/daemon/server/server_test.go`:

```go
// A device admission refuses — no key group admits it, two tie, or its
// key_ref is one port49d holds no key for — is closed after the header, at
// once, with nothing decrypted and no strike, and recorded apart from both
// the key report and noise (spec §10, admission_refused).
func TestARefusedDeviceIsClosedAtOnceAndNamed(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		dev := admission.Device{Name: "leaf-01", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}
		trie, err := admission.NewTrie([]admission.Resolved{{Device: dev,
			Refused: "matches no key group, so no key admits it (spec §10)"}})
		if err != nil {
			t.Fatal(err)
		}
		d.Admission = trie
		d.Limits = slowBackoff()
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"admission_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !log.contains(`"name":"leaf-01"`) || log.contains("p49_e2e") {
		t.Fatalf("the record names the device, and never the credential: %s", log.String())
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("admission_refused")); n != 1 {
		t.Fatalf("unvalidated{admission_refused} = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("malformed_backoff")); n != 0 {
		t.Fatalf("a refused device is not a strike: %v", n)
	}
}
```

  Append to `internal/config/config_test.go`:

```go
// With a broker the policy assigns keys, and a device no group admits is
// refused on its own at the policy load, never the daemon (spec §10; plan 6a
// Decided 5). Without one, TestLoadRefusesDeviceMatchingNoKeyGroup holds.
func TestWithABrokerAnOrphanIsTheDevicesProblemNotTheDaemons(t *testing.T) {
	setKeyEnv(t)
	orphan := write(t, "orphan.yaml", "devices:\n  - {name: orphan, addresses: [10.99.99.1]}\n")
	body := fmt.Sprintf(sample, orphan) + "broker: {listen: \"127.0.0.1:0\", tls_cert_file: c, tls_key_file: k, " +
		"client_ca_file: ca, policy_file: p}\n"
	cfg, err := Load(write(t, "f.yaml", body))
	if err != nil {
		t.Fatalf("a broker config refused an orphan device: %v", err)
	}
	if cfg.Admission != nil || len(cfg.Inventory.Devices) != 1 {
		t.Fatalf("admission %v, inventory %+v", cfg.Admission, cfg.Inventory)
	}
	if got := cfg.KeyRefs(); len(got) != 1 || got[0] != "prod_key" {
		t.Fatalf("KeyRefs: %q", got)
	}
	dup := write(t, "dup.yaml", "devices:\n  - {name: a, addresses: [10.0.0.1]}\n  - {name: b, addresses: [10.0.0.1]}\n")
	if _, err := Load(write(t, "g.yaml", strings.Replace(body, orphan, dup, 1))); err == nil {
		t.Fatal("an address claimed twice is the inventory's fault and refuses the start")
	}
}
```

  Append to `cmd/port49d/broker_test.go`:

```go
// port49d admits from the policy in force: a device the policy refuses is in
// the index as refused, and a reload's index reaches the next Accept.
func TestPort49dAdmitsFromThePolicyInForce(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	cfg.Inventory.Devices = append(cfg.Inventory.Devices, admission.Device{Name: "stray", Platform: "arista_eos",
		Addresses: []netip.Addr{netip.MustParseAddr("192.0.2.9")}})
	_, b, err := buildBroker(cfg, memory.New(time.Now), seedMinter(), decision.NewJSONLines(io.Discard),
		metrics.New(prometheus.NewRegistry()))
	if err != nil {
		t.Fatal(err)
	}
	r, ok := liveAdmission{b.Policy}.Lookup(netip.MustParseAddr("192.0.2.9"))
	if !ok || !strings.Contains(r.Refused, "matches no key group") {
		t.Fatalf("stray: %+v, %v", r, ok)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/daemon/server/ ./internal/config/ ./cmd/port49d/ -run 'Refused|Orphan|AdmitsFrom' -count=1`
Expected: FAIL — `cannot use trie (type *admission.Trie)` is fine, but the refused device is read
as admitted and gets `no_known_key_matches` after the backoff; `cfg.KeyRefs undefined`;
`undefined: liveAdmission`.

- [ ] **Step 3: The server.** In `internal/daemon/server/server.go`:

```go
// Admitter answers which device a source address is and which key_ref admits
// it (spec §10). port49d passes the policy in force's index, read at each
// Accept, so a reload reaches the next connection and a connection finishes
// on the index it began with; *admission.Trie is one.
type Admitter interface {
	Lookup(netip.Addr) (admission.Resolved, bool)
}
```

  `Deps.Admission` becomes `Admission Admitter`. In `Serve`, the lookup becomes:

```go
		dev, found := d.Admission.Lookup(src)
		cc := &conn{d: d, c: c, src: src, dev: dev, admitted: found && dev.Refused == "",
			refused: found && dev.Refused != "", keys: d.Keys[dev.KeyRef], sessions: map[uint32]*authen.Session{}}
```

  In `conn.go`, `conn` gains `refused bool // in inventory, and admission refused it (spec §10)`,
  and in `serve`, the unadmitted branch becomes:

```go
		if !s.admitted {
			if s.refused {
				s.refusedAdmission(h)
				return
			}
			s.unvalidated(h, nil, keyring.DiagUnadmittedSource, 0)
			s.backoff(ctx, "unadmitted_source")
			return
		}
```

  with, beside `quarantine`:

```go
// refusedAdmission records a packet from a device the inventory names and
// admission refuses — no key group admits it, two tie on it, or its key_ref is
// one port49d holds no key for — and closes the connection with nothing read
// past the header and no strike (spec §10). The fault is port49's
// configuration, not the device's, so the device falls to its local method at
// once, as for a quarantine; the start line and `port49 policy test` say why.
func (s *conn) refusedAdmission(h wire.Header) {
	s.d.Log.Emit(decision.Record{TS: s.d.Now(), Event: decision.EventUnvalidated,
		Device: &decision.Device{NAS: s.src.String(), Name: s.dev.Device.Name, Platform: s.dev.Device.Platform},
		Unvalidated: &decision.Unvalidated{Source: s.src.String(), Diagnosis: string(keyring.DiagAdmissionRefused),
			KeyRef: s.dev.KeyRef, Type: uint8(h.Type), SeqNo: h.SeqNo, SessionID: h.SessionID, Length: h.Length}})
	s.d.Metrics.Unvalidated.WithLabelValues(string(keyring.DiagAdmissionRefused)).Inc()
}
```

  In `internal/keyring/keyring.go`'s diagnosis block, after `DiagDeviceQuarantined`:

```go
	DiagAdmissionRefused Diagnosis = "admission_refused" // in inventory, and admission refused it (spec §10)
```

- [ ] **Step 4: The metric.** In `internal/daemon/metrics/metrics.go`, beside `DevicesQuarantined`:

```go
	// port49_devices_admission_refused: how many inventory devices the bundle
	// in force refuses admission — no key group admits them, two tie on
	// them, or their key_ref is one port49d holds no key for (spec §10). Each
	// is named at start and at every reload; the gauge names none.
	DevicesAdmissionRefused prometheus.GaugeFunc
	admissionRefused        atomic.Pointer[func() int]
```

```go
// CountAdmissionRefused sets what port49_devices_admission_refused reports.
func (m *Metrics) CountAdmissionRefused(count func() int) { m.admissionRefused.Store(&count) }
```

  In `New`, build it as `DevicesQuarantined` is built (a `GaugeFunc` reading the stored func, 0
  until set) and add it to `MustRegister`.

- [ ] **Step 5: The config.** In `internal/config/config.go`'s `Load`, replace the block from
  `inv, err := admission.LoadFile(c.InventoryFile)` through `trie, err := admission.Build(inv)` and
  the unmatched-device loop with:

```go
	inv, err := admission.LoadFile(c.InventoryFile)
	if err != nil {
		return Config{}, err
	}
	// Names and addresses are the inventory's own faults, and an inventory
	// that has one cannot be used at all: refused at start, as a reload
	// refuses it (spec §10).
	if err := admission.Validate(inv.Devices); err != nil {
		return Config{}, err
	}
	c.Inventory = inv
	if c.Broker != nil {
		// With a broker, key groups are the policy's (spec §10), and port49d
		// admits from the policy loaded against this inventory, which refuses
		// a device a group cannot admit on its own, never the daemon
		// (policy.Policy.Admission; plan 6a Decided 5).
		return c, nil
	}
	// No broker: plan 1's mode, the lab's. The inventory's own key groups
	// are read once, here, and a device none admits refuses the start.
	for _, g := range inv.KeyGroups {
		if _, ok := c.Keys[g.KeyRef]; !ok {
			return Config{}, fmt.Errorf("config: key group references key_ref %q which is not in keys", g.KeyRef)
		}
	}
	for _, d := range inv.Devices {
		if d.KeyRef != "" {
			if _, ok := c.Keys[d.KeyRef]; !ok {
				return Config{}, fmt.Errorf("config: device %q pins key_ref %q which is not in keys", d.Name, d.KeyRef)
			}
		}
	}
	trie, err := admission.Build(inv)
	if err != nil {
		return Config{}, err
	}
```

  keeping the unmatched-device loop and `c.Inventory, c.Admission = inv, trie` after it as they
  are. Add:

```go
// KeyRefs names every key_ref keys defines, sorted and never nil: a device
// the policy assigns any other is refused admission (spec §10). Names only.
func (c Config) KeyRefs() []string {
	out := make([]string, 0, len(c.Keys))
	for ref := range c.Keys {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}
```

  and update the `Inventory`/`Admission` field comment: "Admission is nil with a broker: port49d
  admits from the policy in force (policy.Policy.Admission)."

- [ ] **Step 6: port49d.** In `cmd/port49d/main.go`, `parseBundle` passes the key names:
  `bundle.Parse(raw, inv, policy.Env{KeyRefs: cfg.KeyRefs()})`. `loadPolicy`, the start's load,
  refuses a bundle that admits none of a non-empty inventory (plan 6a Decided 5, C3): no device
  caused that, and a daemon admitting nothing is a misconfiguration to say at start, not a fleet to
  close silently. After its `parseBundle`:

```go
	if n := len(pol.Devices()); n > 0 && len(pol.AdmissionRefusals()) == n {
		r := pol.AdmissionRefusals()[0]
		return nil, fmt.Errorf("broker.policy_file %s with inventory_file %s admits none of the %d device(s) in "+
			"the inventory (%s: %s); if key_groups was deleted from the inventory file, add it to the policy file",
			cfg.Broker.PolicyFile, cfg.InventoryFile, n, r.Device.Name, r.Refused)
	}
```

  A reload never reaches this: the bound (Task 12) refuses a snapshot that newly refuses the fleet.
  Add to `cmd/port49d/broker_test.go`:

```go
// C3: a restart in the middle of the key-group move loads (both files carry
// the block, the policy's wins), and a start whose bundle admits nothing is
// refused with the fix named.
func TestTheKeyGroupMoveNeverStopsAStartThatCouldServe(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy+"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n")
	cfg.Inventory.Devices[0].KeyRef = ""
	cfg.Inventory.Devices[0].Addresses = []netip.Addr{netip.MustParseAddr("10.0.0.1")}
	cfg.Inventory.KeyGroups = []admission.KeyGroup{{CIDR: netip.MustParsePrefix("10.0.0.0/8"), KeyRef: "lab_key"}}
	if err := buildWith(cfg); err != nil {
		t.Fatalf("both files carry the block: %v", err)
	}
	none := brokerConfig(t, minimalPolicy)
	none.Inventory.Devices[0].KeyRef = ""
	if err := buildWith(none); err == nil || !strings.Contains(err.Error(), "admits none of the 1 device(s)") {
		t.Fatalf("a bundle admitting nothing: %v", err)
	}
}
```

  Add:

```go
// liveAdmission is the policy in force's admission index, read at each
// Accept: a reload reaches the next connection, and a connection finishes on
// the index it began with (spec §10).
type liveAdmission struct{ live *policy.Live }

func (a liveAdmission) Lookup(addr netip.Addr) (admission.Resolved, bool) {
	return a.live.Load().Admission().Lookup(addr)
}
```

  In `run`, before `deps`:

```go
	admit := server.Admitter(cfg.Admission)
	if live != nil {
		admit = liveAdmission{live}
		m.CountAdmissionRefused(func() int { return len(live.Load().AdmissionRefusals()) })
	}
```

  and `deps := server.Deps{Admission: admit, ...}`. The listening line counts what is admitted:

```go
	admitted := len(cfg.Inventory.Devices)
	if live != nil {
		admitted -= len(live.Load().AdmissionRefusals())
	}
	fmt.Fprintf(stderr, "port49d: listening on %s, metrics on %s, %d devices admitted\n", ln.Addr(), mln.Addr(), admitted)
```

  In `sayPolicy`, after the quarantine loop:

```go
	// A device admission refuses is refused alone (spec §10): named, with
	// why, so the line says what to fix.
	for _, r := range pol.AdmissionRefusals() {
		say("port49d: admission: device %s (%s) is refused: %s", r.Device.Name, r.Device.Platform, r.Refused)
	}
	for _, n := range pol.Notices() {
		say("port49d: policy: %s", n)
	}
```

  The tests' inventory has no key group, so every device they load would now be refused and said.
  Give them a key: in `cmd/port49d/broker_test.go`'s `brokerConfig`, the device becomes
  `{Name: "leaf1", Platform: "arista_eos", KeyRef: "lab_key"}` and the config gains
  `Keys: map[string]config.KeySet{"lab_key": {Current: config.KeyVersion{Version: 1, SecretEnv: "UNUSED"}}}`;
  each device those tests append (`ntp1`, `xe1`, the second `leaf1` in `broker_test.go`, and `ntp1`
  in `redact_test.go`) gains `KeyRef: "lab_key"`.

- [ ] **Step 7: Run the tests, everything, and commit**

Run: `go test ./internal/daemon/... ./internal/config/ ./cmd/port49d/ -count=1 && make test && make vet && make build`
Expected: PASS.

```bash
git add internal cmd
git commit -m "feat(port49d): admit from the bundle in force, and close a refused device at once

A device no key group admits, or one assigned a key port49d does not hold, is
refused on its own with the new diagnosis admission_refused; with a broker,
config.Load no longer refuses the daemon's start for it (spec §10).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11: The broker reads its devices from the policy it holds, and an inventory-only swap leaves an unchanged context alone

**Files:**
- Modify: `internal/broker/broker.go` (drop `Devices`; `mintOne`, a refused device denied `device_unknown`)
- Modify: `internal/broker/refresh.go` (devices from the policies; a refused device's contexts revoked;
  `sameSource`; `sameButBundle`)
- Modify: `cmd/port49d/main.go` (`buildBroker`)
- Modify: `internal/broker/fixture_test.go`, `engine_test.go`, `refresh_test.go` (a `devices` field)
- Test: `internal/broker/refresh_test.go`

**Interfaces:**
- Consumes: `(*policy.Policy).Device`, `Devices`, `Source` (Tasks 4, 6).
- Consumes also: `policy.ErrDeviceRefused` (Task 4).
- Produces: `broker.Broker` has no `Devices` field: a mint, the refresh and its records read the
  device from the policy they hold, so a swap changes the device table with the policy. A device
  admission refuses is not live: no mint (`device_unknown`), its contexts revoked, its tokens
  superseded (plan 6a, I2).

- [ ] **Step 1: The fixture keeps its own device table.** In `internal/broker/fixture_test.go`, add
  `devices map[string]admission.Device` to `fixture`, set `f.devices = devices` in `newFixture`,
  and delete `Devices: devices,` from the `Broker` literal. Then:

```bash
sed -i 's/f\.b\.Devices\[/f.devices[/g' internal/broker/*_test.go
```

- [ ] **Step 2: Write the failing tests.** Append to `internal/broker/refresh_test.go`:

```go
// An inventory change that leaves a context's answer as it was writes nothing
// and records nothing: its blob differs from the new one only in the bundle
// it names (spec §5.1.3; plan 6a Decided 3). Every inventory change would
// otherwise rewrite and record every live context.
func TestAnInventoryOnlySwapLeavesAnUnchangedContextAlone(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	before := f.context(t, "leaf1", "alice")
	old := f.b.Policy.Load()
	extra := admission.Device{Name: "leaf9", Platform: "arista_eos", Addresses: []netip.Addr{netip.MustParseAddr("172.100.100.19")}}
	pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: append(old.Devices(), extra), Now: f.b.Now(),
		Bundle: "sha256:" + strings.Repeat("b", 64)})
	if err != nil {
		t.Fatal(err)
	}
	f.log.Reset()
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}})
	if err != nil || rep.Updated != 0 || rep.Unchanged != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if after := f.context(t, "leaf1", "alice"); after.BlobHash != before.BlobHash {
		t.Fatalf("the context was rewritten: %s → %s", before.BlobHash, after.BlobHash)
	}
	if strings.Contains(f.log.String(), `"event":"refresh"`) {
		t.Fatalf("an unchanged context was recorded: %s", f.log.String())
	}
}

// A policy edit keeps plan 4b's rule: every live context takes the new
// bundle's blob, and each is recorded.
func TestAPolicyEditStillRewritesEveryContext(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	rep, err := f.b.Refresh(context.Background(), f.reload(t, testPolicy+"\n# an edit\n"))
	if err != nil || rep.Updated != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
}

// I2: a device admission refuses is not live. The mint denies it
// device_unknown, after the grants check, and a refresh revokes its context
// and supersedes its tokens, as for a device the inventory no longer names.
func TestARefusedDeviceIsNotMintedForAndItsContextIsRevoked(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	old := f.b.Policy.Load()
	// leaf1 keeps its record, and a key group now admits only nx1's range.
	pol, err := policy.Parse([]byte(testPolicy+"key_groups: [{match: {cidr: 172.100.100.31/32}, key_ref: k}]\n"),
		policy.Env{Devices: old.Devices(), Now: f.b.Now(), KeyRefs: []string{"k"}})
	if err != nil {
		t.Fatal(err)
	}
	priors := []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}}
	it := decodeMint(t, f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")).Results[0]
	if it.Verdict != "deny" || it.Reason != "device_unknown" {
		t.Fatalf("a refused device was minted for: %+v", it)
	}
	rep, err := f.b.Refresh(context.Background(), priors)
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatal("the context on the refused device is live")
	}
}

// A device the inventory in force no longer names has its contexts revoked
// and its unspent tokens superseded (plan 4b's hand-off to plan 6).
func TestADeviceRemovedFromInventoryIsRevokedAndItsTokensGo(t *testing.T) {
	f := newFixture(t, 8)
	f.login(t, alice, "leaf1", "alice")
	f.post(context.Background(), f.state(f.alice), `{"devices":["leaf1"]}`, "")
	old := f.b.Policy.Load()
	var rest []admission.Device
	for _, d := range old.Devices() {
		if d.Name != "leaf1" {
			rest = append(rest, d)
		}
	}
	pol, err := policy.Parse([]byte(testPolicy), policy.Env{Devices: rest, Now: f.b.Now(), Bundle: "sha256:" + strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.Refresh(context.Background(), []Prior{{Policy: f.b.Policy.Swap(pol), At: f.b.Now()}})
	if err != nil || rep.Revoked != 1 {
		t.Fatalf("%+v, %v", rep, err)
	}
	if c := f.context(t, "leaf1", "alice"); c.RevokedAt.IsZero() {
		t.Fatal("the context on the removed device is live")
	}
	if toks, _ := f.st.Candidates(context.Background(), store.TokenKey{NAS: "leaf1", Username: "alice"}); len(toks) != 0 {
		t.Fatalf("%d token(s) for the removed device survive", len(toks))
	}
}
```

  (add `net/netip` to the file's imports). `f.post` and `f.state` are the fixture's mint helpers,
  as `login` uses them.

- [ ] **Step 3: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'InventoryOnly|PolicyEditStill|RemovedFromInventory' -count=1`
Expected: FAIL — to compile first, since the fixture still references `Devices` until Step 4 removes
the field; then `Updated 1, Unchanged 0` for the inventory-only swap.

- [ ] **Step 4: Implement.** In `internal/broker/broker.go`, delete the `Devices` field and its
  comment, and in `mintOne` read the device from the policy the request holds:

```go
	dev, ok := pol.Device(name)
```

  and, in the `switch` on `pol.Resolve`'s error, after the `ErrDeviceQuarantined` case:

```go
	case errors.Is(err, policy.ErrDeviceRefused):
		// Admission refuses this device (spec §10): its packets are closed
		// after the header, so a token for it would only be a login that
		// falls to its local method. Asked after the grants, as a
		// quarantine is, so no caller learns which devices exist.
		return deny(decision.DeviceUnknown, dev.Platform), nil
```

  In `refresh.go`'s `decideRefresh`, after the `ErrDeviceQuarantined` case:

```go
	case errors.Is(err, policy.ErrDeviceRefused):
		// Not live (spec §5.7, device_unknown): the device cannot reach
		// port49d, so the context is revoked as for a removed device.
		rec.Verdict, rec.Reason = decision.VerdictDeny, decision.DeviceUnknown
		return refreshStep{revoke: true, rec: rec, outcome: "revoked"}
```

  `mintedFor` already treats any `Resolve` error as "mints nothing", so the supersede deletes a
  refused device's tokens with no change.

  In `internal/broker/refresh.go`:

  `Refresh` computes, before its loop, whether every prior shares the policy file in force, and
  passes it down:

```go
	// sameSource is an inventory-only swap: every policy since the last
	// complete refresh was read from the file in force, so a context whose
	// blob differs from the new one only in the bundle it names is left as
	// it is (spec §5.1.3; plan 6a Decided 3).
	sameSource := true
	for _, pr := range priors {
		sameSource = sameSource && pr.Policy.Source == cur.Source
	}
```

  and `busy := b.refreshContexts(ctx, cur, rep.At, &rep, sameSource)`. `refreshContexts` and
  `refreshContext` take the `sameSource bool` and pass it on. In `supersedeTokens`, the device
  names are every name any policy in play knows, and each policy's answer is read on its own
  device record:

```go
	seen := map[string]bool{}
	for _, d := range cur.Devices() {
		seen[d.Name] = true
	}
	for _, pr := range priors {
		for _, d := range pr.Policy.Devices() {
			seen[d.Name] = true
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
```

  and inside the loop:

```go
			for _, name := range names {
				d, known := pr.Policy.Device(name)
				if !known {
					continue // the prior did not know it, so it minted nothing for it
				}
				for _, at := range instants {
					was, ok := mintedFor(pr.Policy, principal, d, at)
					if !ok {
						continue // nothing was minted then, so nothing is superseded
					}
					is, computed := current[[2]string{principal, name}]
					if !computed {
						// A device the inventory in force no longer names mints
						// nothing now, so every token for it is superseded.
						if nd, ok := cur.Device(name); ok {
							is.m, is.ok = mintedFor(cur, principal, nd, now)
						}
						current[[2]string{principal, name}] = is
					}
					if is.ok && was.keeps(is.m) {
						continue
					}
					keys[store.TokenKey{NAS: name, Username: was.username}] = true
				}
			}
```

  Every `b.Devices[ref.NAS].Platform` becomes `platformOf(cur, ref.NAS)`:

```go
// platformOf is a device's platform in the policy in force; empty for one
// its inventory does not name.
func platformOf(p *policy.Policy, name string) string {
	d, _ := p.Device(name)
	return d.Platform
}
```

  In `decideRefresh`, `dev, ok := cur.Device(ref.NAS)`, and its comment becomes "A context on a
  device the inventory in force no longer names: nothing can be minted for it, so it is revoked
  (plan 4b's hand-off: a device leaving inventory is a narrowing like any other)." In
  `refreshContext`, after `step := b.decideRefresh(...)` and its `sessionOnly` line, and before the
  `switch`:

```go
		if sameSource && step.write != nil && step.rec.Session.PrivilegeClamped == nil &&
			step.write.MaxPrivilege == c.MaxPrivilege && step.write.Enable == c.Enable &&
			b.sameButBundle(ctx, c.BlobHash, step.write.BlobHash, step.body) {
			// An inventory-only swap that left this context's answer as it
			// was: nothing is written and nothing recorded, and it goes on
			// naming the bundle that compiled it, which is still true.
			b.count(rep, "unchanged")
			return nil
		}
```

  and add:

```go
// sameButBundle reports whether the blob a context names is the new one but
// for the bundle, read from the store. A blob the store cannot give is not:
// the context takes the new one, failing toward the write.
func (b *Broker) sameButBundle(ctx context.Context, oldHash, newHash string, newBody []byte) bool {
	raw, err := b.Store.GetBlob(ctx, oldHash)
	if err != nil {
		return false
	}
	old, err := engine.Decode(oldHash, raw)
	if err != nil {
		return false
	}
	nb, err := engine.Decode(newHash, newBody)
	if err != nil {
		return false
	}
	old.Bundle = nb.Bundle
	_, h, err := engine.Encode(old)
	return err == nil && h == newHash
}
```

  In `cmd/port49d/main.go`'s `buildBroker`, delete the `devices` map, its duplicate-name check
  (`admission.Validate` in `bundle.Parse` refuses a repeated name) and `Devices: devices` from the
  `broker.Broker` literal.

- [ ] **Step 5: Run the tests, everything, and commit**

Run: `go test ./internal/broker/ ./cmd/port49d/ -count=1 && make test && make vet && make build`
Expected: PASS.

```bash
git add internal/broker cmd/port49d
git commit -m "feat(broker): devices come from the policy held, and an inventory-only swap leaves an unchanged context alone

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 11a: The inventory file is read behind the policy file's write fence

**Files:**
- Modify: `cmd/port49d/policyfile.go`, `cmd/port49d/policyfile_other.go` (`readGuarded`,
  `readInventoryFile`)
- Modify: `cmd/port49d/main.go` (`fencedInventory`, called at start with a broker)
- Modify: `tests/lab/harness_test.go` (`privatePolicy` copies `inventory_file` too)
- Test: `cmd/port49d/policyfile_test.go`, `cmd/port49d/broker_test.go`

**Interfaces:**
- Consumes: `admission.ParseFile`, `admission.Validate` (Task 3); `engine.HashOf`.
- Produces:
  - `func readGuarded(path string, max int64, what string) ([]byte, error)` — `readPolicyFile`'s
    checks (resolvePolicyPath's link walk, the directory and file owner and mode, a regular file,
    non-blocking open) with the size bound and the noun passed in. `readPolicyFile(path)` is
    `readGuarded(path, maxPolicySize, "policy file")`.
  - `const maxInventorySize = 64 << 20`; `func readInventoryFile(path string) ([]byte, error)`.
  - `func fencedInventory(cfg config.Config) (admission.Inventory, string, error)` — the inventory
    as the fence read it, and the version (`engine.HashOf` of those bytes) the reloader starts from.

The inventory file decides privilege once it is reloaded live (Task 12): its attributes and names
decide scope membership, its addresses are handed to SSH clients, and a record's `key_ref` pins a
key. `broker.policy_file` is read through `readPolicyFile` for exactly that reason (plan 4b), so the
inventory file is read through the same checks, at start and at every reload (C2). Without a
broker, port49d reads the inventory once at start and never again, as in plan 1, and the lab's
standing config reads the repository's file: the fence applies with a broker, where the file is
live.

- [ ] **Step 1: Write the failing tests.** Append to `cmd/port49d/policyfile_test.go`:

```go
// C2: the inventory file is read behind the policy file's fence, with its
// own size bound.
func TestTheInventoryFileIsFenced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "inventory.yaml")
	if err := os.WriteFile(path, []byte("devices: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readInventoryFile(path); err != nil || string(raw) != "devices: []\n" {
		t.Fatalf("a private file: %q, %v", raw, err)
	}
	if err := os.Chmod(path, 0o664); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventoryFile(path); err == nil || !strings.Contains(err.Error(), "the file "+path) {
		t.Fatalf("a group-writable file: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, maxInventorySize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readInventoryFile(path); err == nil || !strings.Contains(err.Error(), "not an inventory file") {
		t.Fatalf("an oversized file: %v", err)
	}
}
```

  and to `cmd/port49d/broker_test.go`:

```go
// C2 at start: with a broker, a group-writable inventory file refuses the
// start, and a private one is what the reloader starts from.
func TestAStartReadsTheInventoryBehindTheFence(t *testing.T) {
	cfg := brokerConfig(t, minimalPolicy)
	cfg.InventoryFile = filepath.Join(t.TempDir(), "inventory.yaml")
	body := "devices: [{name: leaf1, platform: arista_eos, key_ref: lab_key}]\n"
	if err := os.WriteFile(cfg.InventoryFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, v, err := fencedInventory(cfg)
	if err != nil || len(inv.Devices) != 1 || v != engine.HashOf([]byte(body)) {
		t.Fatalf("%+v %s %v", inv, v, err)
	}
	if err := os.Chmod(cfg.InventoryFile, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fencedInventory(cfg); err == nil || !strings.Contains(err.Error(), "inventory_file") {
		t.Fatalf("a world-writable inventory started: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49d/ -run 'Fence' -count=1`
Expected: FAIL to compile — `undefined: readInventoryFile`, `maxInventorySize`, `fencedInventory`.

- [ ] **Step 3: Generalize the read.** In `cmd/port49d/policyfile.go`, rename `readPolicyFile`'s
  body into `readGuarded(path string, max int64, what string) ([]byte, error)`, replacing
  `maxPolicySize` with `max` in its two uses and the refusal's text with
  `fmt.Errorf("%s is larger than %d bytes; it is not a%s %s", target, max, article(what), what)`
  (`article` returns `"n"` before a vowel, else `""`), and keep:

```go
// maxInventorySize bounds the inventory file's read. A 10,000-device
// inventory is a few megabytes; the bound is there so a link aimed at a
// multi-gigabyte file is not read into memory at every poll.
const maxInventorySize = 64 << 20

// readPolicyFile reads broker.policy_file behind the fence (readGuarded).
func readPolicyFile(path string) ([]byte, error) { return readGuarded(path, maxPolicySize, "policy file") }

// readInventoryFile reads inventory_file behind the same fence: with a broker
// it is reloaded live and decides scope membership, the addresses a mint
// hands out and key pins, so whoever can write it decides access within
// seconds, as for the policy file (spec §10; plan 6a C2).
func readInventoryFile(path string) ([]byte, error) {
	return readGuarded(path, maxInventorySize, "inventory file")
}
```

  The existing `TestPolicyFile...` tests keep passing: the policy file's refusal still reads "is
  larger than 1048576 bytes; it is not a policy file". In `policyfile_other.go`, add the matching
  refusal:

```go
// readInventoryFile refuses on every system but Linux, as readPolicyFile does.
func readInventoryFile(string) ([]byte, error) {
	return nil, errors.New("port49d reads inventory_file with a broker on Linux only: the check of who could " +
		"have written it is Linux's")
}
```

- [ ] **Step 4: The start reads through it.** In `cmd/port49d/main.go`:

```go
// fencedInventory reads inventory_file behind the fence (readInventoryFile)
// and returns it with the version the reloader starts from: the hash of the
// bytes loaded, so an edit between config.Load's read and this one is loaded,
// never skipped (plan 6a, M1). config.Load has read the file once already,
// plainly; with a broker these bytes replace what it read.
func fencedInventory(cfg config.Config) (admission.Inventory, string, error) {
	raw, err := readInventoryFile(cfg.InventoryFile)
	if err != nil {
		return admission.Inventory{}, "", fmt.Errorf("inventory_file %s: %w", cfg.InventoryFile, err)
	}
	inv, err := admission.ParseFile(raw, cfg.InventoryFile)
	if err != nil {
		return admission.Inventory{}, "", err
	}
	if err := admission.Validate(inv.Devices); err != nil {
		return admission.Inventory{}, "", fmt.Errorf("inventory_file %s: %w", cfg.InventoryFile, err)
	}
	return inv, engine.HashOf(raw), nil
}
```

  In `run`, right after `config.Load` and before anything reads `cfg.Inventory`, replace the
  `_, inventoryAtStart, _ := fileVersion(cfg.InventoryFile)` line with:

```go
	// With a broker the inventory is live, so it is read behind the policy
	// file's fence, and the reloader starts from the bytes loaded (M1).
	inventoryAtStart := ""
	if cfg.Broker != nil {
		inv, v, err := fencedInventory(cfg)
		if err != nil {
			return err
		}
		cfg.Inventory, inventoryAtStart = inv, v
	}
```

  (`inventoryAtStart` is already handed to the reloader: `r.inventory = inventoryAtStart`.)

- [ ] **Step 5: The lab's derived broker configs carry a private inventory.** In
  `tests/lab/harness_test.go`'s `privatePolicy`, after the policy copy and only when a
  `policy_file:` line was found (a broker config), copy the file the top-level `inventory_file:`
  line names into the same private directory the same way (`0700` directory, `0600` file) and
  point the line at the copy. The anchor is `"inventory_file: "` at the start of a line. The
  standing config, which has no broker, is untouched.

- [ ] **Step 6: Run the tests, everything, and commit**

Run: `go test ./cmd/port49d/ -count=1 && make test && make vet && make build && GOOS=darwin go build ./cmd/port49d/ && go vet -tags lab ./tests/lab/...`
Expected: PASS; the darwin build proves the stub.

```bash
git add cmd/port49d tests/lab/harness_test.go
git commit -m "feat(port49d): read the inventory file behind the policy file's write fence

With a broker the inventory is reloaded live and decides scope membership,
capture addresses and key pins, so it gets the policy file's owner, mode and
size checks at start and at every reload (plan 6a pre-flight C2).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 12: port49d reloads its inventory, bounded, and refreshes live sessions

**Files:**
- Modify: `internal/config/config.go` (`inventory.max_removed_percent`)
- Modify: `internal/daemon/metrics/metrics.go` (inventory reloads, refused, snapshot age)
- Modify: `cmd/port49d/reload.go` (the inventory watch; `swap`, `after`; `checkInventory` removed)
- Modify: `cmd/port49d/reload_test.go` (`TestAnInventoryEditIsSaidNotApplied` removed)
- Test: `cmd/port49d/reload_inventory_test.go`, `internal/config/config_test.go`

**Interfaces:**
- Consumes: `admission.ParseFile` (Task 3); `bundle.Diff`, `Check`, `Report.Summary` (Task 7);
  `parseBundle`, `(*policy.Policy).Raw`, `Inventory` (Task 6).
- Produces:
  - `config.Config.MaxRemovedPercent int` (default 10, 0–100); `func config.InventoryBound(raw []byte) (int, error)`.
  - `reloader.cfgPath`, `reloader.rereadBound()` (SIGHUP re-reads the bound), `inventoryVersion(path)`
    (the fenced read, Task 11a's `readInventoryFile`).
  - `metrics.InventoryReloads` (`port49_inventory_reloads_total{outcome}`), `InventoryFileRefused`
    (`port49_inventory_file_refused`), `InventorySnapshotAge`
    (`port49_inventory_snapshot_age_seconds`) and `func (m *Metrics) WatchInventoryAge(age func() float64)`.
  - `reloader.after(ctx context.Context, rep bundle.Report, pol *policy.Policy, now time.Time)` —
    what every swap runs; Task 13 adds to it.

- [ ] **Step 1: Write the failing tests.** Create `cmd/port49d/reload_inventory_test.go`:

```go
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

const twoDevices = `devices:
  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}
  - {name: leaf2, platform: arista_eos, addresses: [10.0.0.2], key_ref: lab_key}
`

func (rig *reloadRig) writeInventory(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(rig.cfg.InventoryFile, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (rig *reloadRig) pollTwice() {
	rig.with(func() {
		rig.r.poll(context.Background())
		rig.r.poll(context.Background())
	})
}

// An inventory edit is loaded once two reads agree, as a policy edit is, and
// the swap is said in one line (spec §10, "Every swap logs a summary").
func TestAnInventoryEditIsLoadedOnceTwoReadsAgree(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.with(func() { rig.r.poll(context.Background()) })
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatal("loaded on one read")
	}
	rig.with(func() { rig.r.poll(context.Background()) })
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatalf("not loaded: %s", rig.out.String())
	}
	out := rig.out.String()
	if !strings.Contains(out, "port49d: inventory reloaded (inventory file changed): bundle ") ||
		!strings.Contains(out, "+1 device(s), -0, 1 changed") {
		t.Fatalf("the swap line: %s", out)
	}
	if n := testutil.ToFloat64(rig.m.InventoryReloads.WithLabelValues("applied")); n != 1 {
		t.Fatalf("applied = %v", n)
	}
	if testutil.ToFloat64(rig.m.PolicyRefreshPending) != 1 {
		t.Fatal("the swap did not open a settle pass")
	}
}

// Spec §10, bounded change: a snapshot that drops more than the configured
// share is refused and the bundle in force keeps serving; said once.
func TestAnInventoryThatDropsTooManyDevicesIsRefused(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	rig.writeInventory(t, "devices:\n  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1], key_ref: lab_key}\n")
	rig.pollTwice()
	rig.pollTwice()
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatal("the over-shrinking inventory was applied")
	}
	out := rig.out.String()
	if strings.Count(out, "inventory reload (inventory file changed) refused; still serving bundle") != 1 ||
		!strings.Contains(out, "removes 1 of 2 devices and refuses 0 more (50%)") ||
		!strings.Contains(out, "raise inventory.max_removed_percent in port49d.yaml and send SIGHUP") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatal("port49_inventory_file_refused is not 1")
	}
	// I1, the operator's path, through the real reload: raise the bound in
	// port49d.yaml and send SIGHUP; nothing is set in memory.
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	if err := os.WriteFile(rig.r.cfgPath, []byte("inventory: {max_removed_percent: 100}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatalf("SIGHUP with the bound raised did not apply: %s", rig.out.String())
	}
	if testutil.ToFloat64(rig.m.InventoryFileRefused) != 0 {
		t.Fatal("port49_inventory_file_refused stayed 1")
	}
	if !strings.Contains(rig.out.String(), "inventory.max_removed_percent is now 100%") {
		t.Fatalf("the re-read bound was not said: %s", rig.out.String())
	}
}

// C2 on a reload: an inventory file others could write is refused once, the
// bundle in force keeps serving, and the alarm is set; put right, it loads.
func TestAnInventoryFileOthersCouldWriteIsRefusedAtAReload(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, twoDevices)
	if err := os.Chmod(rig.cfg.InventoryFile, 0o664); err != nil {
		t.Fatal(err)
	}
	rig.pollTwice()
	rig.pollTwice()
	if _, ok := rig.b.Policy.Load().Device("leaf2"); ok {
		t.Fatal("a group-writable inventory was applied")
	}
	if n := strings.Count(rig.out.String(), "inventory reload (inventory file changed) refused"); n != 1 ||
		testutil.ToFloat64(rig.m.InventoryFileRefused) != 1 {
		t.Fatalf("said %d times: %s", n, rig.out.String())
	}
	if err := os.Chmod(rig.cfg.InventoryFile, 0o600); err != nil {
		t.Fatal(err)
	}
	rig.pollTwice()
	if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
		t.Fatalf("the file put right was not loaded: %s", rig.out.String())
	}
}

// C3: the key-group move, in every order, never refuses the fleet. The
// inventory starts with the block and unpinned devices.
const withGroups = `devices:
  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1]}
  - {name: leaf2, platform: arista_eos, addresses: [10.0.0.2]}
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]
`
const withoutGroups = `devices:
  - {name: leaf1, platform: arista_eos, addresses: [10.0.0.1]}
  - {name: leaf2, platform: arista_eos, addresses: [10.0.0.2]}
`
const policyWithGroups = minimalPolicy + "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: lab_key}]\n"

func migrationRig(t *testing.T) *reloadRig {
	t.Helper()
	rig := newReloadRig(t, minimalPolicy)
	rig.writeInventory(t, withGroups)
	rig.pollTwice()
	if len(rig.b.Policy.Load().AdmissionRefusals()) != 0 {
		t.Fatalf("the starting point refuses: %+v", rig.b.Policy.Load().AdmissionRefusals())
	}
	return rig
}

func TestTheKeyGroupMoveInEveryOrder(t *testing.T) {
	admitsAll := func(t *testing.T, rig *reloadRig, when string) {
		t.Helper()
		pol := rig.b.Policy.Load()
		if len(pol.Devices()) != 2 || len(pol.AdmissionRefusals()) != 0 {
			t.Fatalf("%s: %d devices, refused %+v\n%s", when, len(pol.Devices()), pol.AdmissionRefusals(), rig.out.String())
		}
	}
	t.Run("policy first, as documented", func(t *testing.T) {
		rig := migrationRig(t)
		rig.write(t, policyWithGroups)
		rig.pollTwice()
		admitsAll(t, rig, "both files carry the block")
		if !strings.Contains(rig.out.String(), "is ignored, since the policy file has its own") {
			t.Fatalf("no notice: %s", rig.out.String())
		}
		rig.writeInventory(t, withoutGroups)
		rig.pollTwice()
		admitsAll(t, rig, "the move done")
	})
	t.Run("inventory first", func(t *testing.T) {
		rig := migrationRig(t)
		rig.writeInventory(t, withoutGroups)
		rig.pollTwice()
		admitsAll(t, rig, "the refused step")
		if !strings.Contains(rig.out.String(), "add it to the policy file first") {
			t.Fatalf("the refusal does not name the order: %s", rig.out.String())
		}
		rig.write(t, policyWithGroups)
		rig.pollTwice()
		admitsAll(t, rig, "the policy then carries it")
		// The policy reload clears the inventory's refusal, so the edit
		// refused before is tried again, against the new policy, and loads.
		rig.pollTwice()
		if !strings.Contains(rig.out.String(), "port49d: inventory reloaded") {
			t.Fatalf("the refused inventory was not retried: %s", rig.out.String())
		}
		admitsAll(t, rig, "the move done")
	})
	t.Run("both edits, then SIGHUP", func(t *testing.T) {
		rig := migrationRig(t)
		rig.write(t, policyWithGroups)
		rig.writeInventory(t, withoutGroups)
		rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
		admitsAll(t, rig, "after SIGHUP")
	})
}

func TestAnEmptyOrMalformedInventoryIsRefused(t *testing.T) {
	for _, body := range []string{"devices: []\n", "devices: [\n",
		"devices:\n  - {name: a, addresses: [10.0.0.1]}\n  - {name: b, addresses: [10.0.0.1]}\n"} {
		rig := newReloadRig(t, minimalPolicy)
		rig.r.cfg.MaxRemovedPercent = 100
		rig.writeInventory(t, twoDevices)
		rig.pollTwice()
		rig.writeInventory(t, body)
		rig.pollTwice()
		if _, ok := rig.b.Policy.Load().Device("leaf2"); !ok {
			t.Fatalf("%q was applied", body)
		}
	}
}

// A device removed from inventory has its live contexts revoked by the
// refresh the swap runs (plan 4b's hand-off to plan 6).
func TestAnInventoryReloadRevokesAContextOnARemovedDevice(t *testing.T) {
	rig := newReloadRig(t, minimalPolicy)
	k := rig.aliceLoggedIn(t)
	rig.r.cfg.MaxRemovedPercent = 100
	rig.writeInventory(t, "devices:\n  - {name: leaf2, platform: arista_eos, addresses: [10.0.0.2], key_ref: lab_key}\n")
	rig.pollTwice()
	c, err := rig.st.GetContext(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	if c.RevokedAt.IsZero() {
		t.Fatalf("the context on the removed leaf1 is live: %s", rig.out.String())
	}
}
```

  In `cmd/port49d/reload_test.go`, delete `TestAnInventoryEditIsSaidNotApplied` and its comment:
  the edit is now applied. Append to `internal/config/config_test.go`:

```go
func TestInventoryMaxRemovedPercent(t *testing.T) {
	setKeyEnv(t)
	i := write(t, "inv.yaml", inv)
	cfg, err := Load(write(t, "a.yaml", fmt.Sprintf(sample, i)))
	if err != nil || cfg.MaxRemovedPercent != 10 {
		t.Fatalf("default: %d, %v", cfg.MaxRemovedPercent, err)
	}
	cfg, err = Load(write(t, "b.yaml", fmt.Sprintf(sample, i)+"inventory: {max_removed_percent: 100}\n"))
	if err != nil || cfg.MaxRemovedPercent != 100 {
		t.Fatalf("100: %d, %v", cfg.MaxRemovedPercent, err)
	}
	if _, err := Load(write(t, "c.yaml", fmt.Sprintf(sample, i)+"inventory: {max_removed_percent: 150}\n")); err == nil {
		t.Fatal("150 loaded")
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./cmd/port49d/ ./internal/config/ -run 'Inventory' -count=1`
Expected: FAIL to compile — `rig.m.InventoryReloads undefined`, `cfg.MaxRemovedPercent undefined`.

- [ ] **Step 3: The config.** In `internal/config/config.go`, `fileConfig` gains
  `InventoryOpts inventoryYAML \`yaml:"inventory"\``, with:

```go
// inventoryYAML is how port49d bounds an inventory reload (spec §10). The
// pointer tells an absent key (the default) from an explicit 0, which refuses
// every removal.
type inventoryYAML struct {
	MaxRemovedPercent *int `yaml:"max_removed_percent"`
}
```

  `Config` gains:

```go
	// MaxRemovedPercent refuses an inventory reload that takes more than this
	// share of the devices in force out of service — removed, or kept and
	// newly refused admission (spec §10, bounded change): default 10, 100
	// turns the bound off. An empty inventory is refused whatever it says.
	// It is read at start and re-read at every SIGHUP (InventoryBound), so a
	// deliberate large removal is: raise it, send SIGHUP, lower it again.
	MaxRemovedPercent int
```

  and a reader for the one key, as `MaxSessionAge` reads its one:

```go
// InventoryBound reads inventory.max_removed_percent from a port49d.yaml's
// bytes, with Load's default and range: what port49d re-reads at SIGHUP. It
// resolves no secret and decodes as strictly as Load, so a typo is an error,
// never the default.
func InventoryBound(raw []byte) (int, error) {
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return 0, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", err)
	}
	return inventoryBound(f.InventoryOpts)
}

func inventoryBound(o inventoryYAML) (int, error) {
	if o.MaxRemovedPercent == nil {
		return 10, nil
	}
	if p := *o.MaxRemovedPercent; p < 0 || p > 100 {
		return 0, fmt.Errorf("config: inventory.max_removed_percent must be between 0 and 100; got %d", p)
	}
	return *o.MaxRemovedPercent, nil
}
```

  and `Load`, beside the other defaults:

```go
	if c.MaxRemovedPercent, err = inventoryBound(f.InventoryOpts); err != nil {
		return Config{}, err
	}
```

- [ ] **Step 4: The metrics.** In `internal/daemon/metrics/metrics.go`:

```go
	// port49_inventory_reloads_total{outcome}: attempts to put a changed
	// inventory_file in force (plan 6a) — "applied", "unchanged" (the same
	// devices, respelled), or "refused" (it did not parse, repeated a name or
	// an address, was empty, or removed more than max_removed_percent; the
	// bundle in force keeps serving). The watch counts a refused file once
	// per distinct content.
	InventoryReloads *prometheus.CounterVec
	// port49_inventory_file_refused: 1 while inventory_file on disk is one
	// port49d refused, or one that has changed at every read for six reads
	// running; 0 once a file loads or the file in force is put back.
	InventoryFileRefused prometheus.Gauge
	// port49_inventory_snapshot_age_seconds: how long since inventory_file was
	// last read and found in force, or loaded (spec §10). Staleness is an
	// alarm, never a fail-closed: the snapshot never expires.
	InventorySnapshotAge prometheus.GaugeFunc
	inventoryAge         atomic.Pointer[func() float64]
```

```go
// WatchInventoryAge sets what port49_inventory_snapshot_age_seconds reports.
func (m *Metrics) WatchInventoryAge(age func() float64) { m.inventoryAge.Store(&age) }
```

  In `New`:

```go
		InventoryReloads: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_reloads_total",
			Help: "Attempts to put a changed inventory file in force, by outcome."}, []string{"outcome"}),
		InventoryFileRefused: prometheus.NewGauge(prometheus.GaugeOpts{Name: "port49_inventory_file_refused",
			Help: "1 while the inventory file on disk is one port49d refused, or has not stopped changing."}),
```

  and after the struct, beside `DevicesQuarantined`:

```go
	m.InventorySnapshotAge = prometheus.NewGaugeFunc(prometheus.GaugeOpts{Name: "port49_inventory_snapshot_age_seconds",
		Help: "Seconds since the inventory file was last read and found in force, or loaded."}, func() float64 {
		if age := m.inventoryAge.Load(); age != nil {
			return (*age)()
		}
		return 0
	})
```

  and register all three.

- [ ] **Step 5: The reloader.** In `cmd/port49d/reload.go`, the struct's inventory fields become:

```go
	// inventory is the inventory file's version in force (inventoryVersion),
	// and invPending, invRefused and invChanging are what pending, refused
	// and changing are to the policy file, for the inventory file.
	inventory, invPending, invRefused string
	// cfgPath is port49d.yaml, whose inventory.max_removed_percent SIGHUP
	// re-reads (plan 6a, I1); run sets it.
	cfgPath string
	invChanging                       int
	// invSeen is when the inventory file was last read and found in force,
	// or loaded: port49_inventory_snapshot_age_seconds reads it at scrape.
	invSeen atomic.Int64
```

  (delete `inventorySaid`; import `sync/atomic`, `internal/admission` and `internal/bundle`).
  `newReloader` ends with:

```go
	r.invSeen.Store(start.UnixNano())
	m.WatchInventoryAge(func() float64 { return now().Sub(time.Unix(0, r.invSeen.Load())).Seconds() })
```

  and `run` sets `r.cfgPath = cfgPath` beside `r.inventory = inventoryAtStart`. Rename the present
  `poll` to `pollPolicy`, and add:

```go
// inventoryVersion is policyVersion for inventory_file: read behind the fence
// (readInventoryFile), so a file someone else could have written is a
// version of its own — refused, and said once — and putting its mode right
// is a change the watch sees.
func inventoryVersion(path string) ([]byte, string, error) {
	raw, err := readInventoryFile(path)
	if err != nil {
		return nil, "unreadable: " + err.Error(), err
	}
	return raw, engine.HashOf(raw), nil
}

// poll reads both files, the policy first.
func (r *reloader) poll(ctx context.Context) {
	r.pollPolicy(ctx)
	r.pollInventory(ctx)
}

// pollInventory is pollPolicy for inventory_file (spec §10): a changed file
// is loaded once two reads in a row agree, a refused one is said once, and
// one that never settles is said and alarmed.
func (r *reloader) pollInventory(ctx context.Context) {
	raw, v, err := inventoryVersion(r.cfg.InventoryFile)
	switch {
	case v == r.inventory:
		r.invSeen.Store(r.now().UnixNano())
		alarmed := r.invChanging >= stillChangingAfter
		r.invPending, r.invChanging = "", 0
		if r.invRefused != "" || alarmed {
			r.invRefused = ""
			r.metrics.InventoryFileRefused.Set(0)
			fmt.Fprintf(stderr, "port49d: inventory: inventory_file %s is the inventory in force again\n",
				r.cfg.InventoryFile)
		}
	case v == r.invRefused:
		r.invPending, r.invChanging = "", 0
	case v != r.invPending:
		r.invPending = v
		if r.invChanging++; r.invChanging == stillChangingAfter {
			r.metrics.InventoryFileRefused.Set(1)
			fmt.Fprintf(stderr, "port49d: inventory: inventory_file %s has changed at each of the last %d reads, "+
				"%s apart, so it is not loaded; still serving bundle %s; write it once, atomically\n",
				r.cfg.InventoryFile, stillChangingAfter, r.interval, r.broker.Policy.Load().Bundle)
		}
	default:
		r.invPending = ""
		r.loadInventory(ctx, "inventory file changed", raw, v, err)
	}
}

// loadInventory builds a bundle from raw, the inventory file read as version
// v, and the policy in force, and puts it in force if it loads and passes the
// bounded-change check (spec §10). One that does not changes nothing.
func (r *reloader) loadInventory(ctx context.Context, trigger string, raw []byte, v string, err error) {
	r.invChanging = 0
	old := r.broker.Policy.Load()
	var pol *policy.Policy
	if err == nil {
		var inv admission.Inventory
		if inv, err = admission.ParseFile(raw, r.cfg.InventoryFile); err == nil {
			// Named as the inventory's fault, not the policy file's, since
			// the policy in force loaded before (plan 6a, M5).
			if pol, err = bundle.Parse(old.Raw(), inv, policy.Env{KeyRefs: r.cfg.KeyRefs()}); err != nil {
				err = fmt.Errorf("inventory_file %s, loaded against the policy in force: %w", r.cfg.InventoryFile,
					quotesCut{err})
			} else {
				err = bundle.Check(old, pol, r.cfg.MaxRemovedPercent)
			}
		}
	} else {
		err = fmt.Errorf("inventory_file %s: %w", r.cfg.InventoryFile, err)
	}
	if err != nil {
		r.metrics.InventoryReloads.WithLabelValues("refused").Inc()
		r.metrics.InventoryFileRefused.Set(1)
		r.invRefused = v
		fmt.Fprintf(stderr, "port49d: inventory reload (%s) refused; still serving bundle %s: %s\n", trigger,
			old.Bundle, oneLine(err))
		return
	}
	r.inventory, r.invRefused = v, ""
	r.invSeen.Store(r.now().UnixNano())
	r.metrics.InventoryFileRefused.Set(0)
	if pol.Bundle == old.Bundle {
		// The same devices, respelled: nothing to swap.
		r.metrics.InventoryReloads.WithLabelValues("unchanged").Inc()
		return
	}
	r.metrics.InventoryReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	rep := bundle.Diff(old, pol, now)
	fmt.Fprintf(stderr, "port49d: inventory reloaded (%s): %s; %d device(s) quarantined now, %d before; %d refused "+
		"admission\n", trigger, rep.Summary(), quarantinedAt(pol, now), quarantinedAt(old, now),
		len(pol.AdmissionRefusals()))
	r.after(ctx, rep, pol, now)
}

// swap puts pol in force and opens its span, as a policy reload does: the
// replaced bundle's span ends when Swap returns, the next grant expiry is
// read from pol, and a settle pass is owed.
func (r *reloader) swap(pol *policy.Policy) time.Time {
	r.broker.Policy.Swap(pol)
	now := r.now()
	r.priors[len(r.priors)-1].Until = now
	r.priors = append(r.priors, broker.Prior{Policy: pol, At: now})
	r.expiry, _ = pol.NextChange(now)
	r.settle = now.Add(settleAfterReload)
	r.metrics.PolicyRefreshPending.Set(1)
	return now
}

// after is what every swap runs once its line is written: the lines a start
// would print, and the refresh that carries the bundle into live contexts.
func (r *reloader) after(ctx context.Context, rep bundle.Report, pol *policy.Policy, now time.Time) {
	sayPolicy(pol, now)
	r.refresh(ctx)
}
```

  `reload` loads the inventory too when it changed, so `SIGHUP` retries one refused before:

```go
func (r *reloader) reload(ctx context.Context, trigger string) {
	r.rereadBound()
	raw, v, err := policyVersion(r.cfg.Broker.PolicyFile)
	r.load(ctx, trigger, raw, v, err)
	iraw, iv, ierr := inventoryVersion(r.cfg.InventoryFile)
	if iv != r.inventory {
		r.loadInventory(ctx, trigger, iraw, iv, ierr)
	}
}

// rereadBound re-reads inventory.max_removed_percent from port49d.yaml, the
// one key SIGHUP re-reads, so a deliberate large removal needs no restart
// (plan 6a, I1). A file that does not read keeps the bound in force, said.
func (r *reloader) rereadBound() {
	if r.cfgPath == "" {
		return
	}
	raw, err := os.ReadFile(r.cfgPath)
	var n int
	if err == nil {
		n, err = config.InventoryBound(raw)
	}
	switch {
	case err != nil:
		fmt.Fprintf(stderr, "port49d: SIGHUP: inventory.max_removed_percent not re-read from %s (%s); keeping %d%%\n",
			r.cfgPath, oneLine(err), r.cfg.MaxRemovedPercent)
	case n != r.cfg.MaxRemovedPercent:
		fmt.Fprintf(stderr, "port49d: SIGHUP: inventory.max_removed_percent is now %d%% (was %d%%)\n", n,
			r.cfg.MaxRemovedPercent)
		r.cfg.MaxRemovedPercent = n
	}
}
```

  In `load`, delete the `r.checkInventory()` call, and replace the block from
  `r.broker.Policy.Swap(pol)` to the end with:

```go
	r.metrics.PolicyReloads.WithLabelValues("applied").Inc()
	now := r.swap(pol)
	// An inventory edit refused against the policy replaced — the key-group
	// move done in the wrong order, say — is tried again against this one at
	// the next polls (plan 6a, C3).
	r.invRefused = ""
	fmt.Fprintf(stderr, "port49d: policy reloaded (%s): %s replaces %s (bundle %s); %d device(s) quarantined now, %d before\n",
		trigger, pol.Source, old.Source, pol.Bundle, quarantinedAt(pol, now), quarantinedAt(old, now))
	r.after(ctx, bundle.Diff(old, pol, now), pol, now)
```

  Delete `checkInventory` and its comment.

  **A policy reload is bounded as an inventory reload is (N1).** In `load`, the new policy is held to
  `bundle.CheckAdmission` before it is swapped in:

```go
	} else if err == nil {
		pol, err = parseBundle(r.cfg, raw, old.Inventory())
		if err == nil {
			// Key groups are policy, and a refused device's sessions are
			// revoked and its tokens deleted (I2): a key_groups typo must not
			// log out the fleet (plan 6a, N1).
			err = bundle.CheckAdmission(old, pol, r.cfg.MaxRemovedPercent)
		}
	} else {
```

  An over-the-bound policy takes the existing refusal branch: the policy in force keeps serving,
  `port49_policy_file_refused` is 1, the version is remembered and said once, and the line names the
  devices. `SIGHUP` re-reads the bound (`rereadBound`) before it loads, so raising the bound and
  sending `SIGHUP` applies a deliberate change. Add to `cmd/port49d/reload_inventory_test.go`:

```go
// N1, through the real policy reload: a key_groups typo that would refuse the
// fleet is refused, and every live session and unspent token survives;
// raising the bound and sending SIGHUP applies it.
func TestAKeyGroupsTypoCannotLogOutTheFleet(t *testing.T) {
	rig := newReloadRig(t, policyWithGroups)
	rig.writeInventory(t, withoutGroups)
	rig.pollTwice()
	k := rig.aliceLoggedIn(t)
	tk := store.TokenKey{NAS: "leaf1", Username: "alice"}
	if _, err := rig.st.PutToken(context.Background(), tk, store.Token{ID: "t1", Secret: []byte("p49_t1"),
		Kind: store.KindLogin, Principal: "user:alice@example.com", ExpiresAt: rig.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	rig.write(t, strings.Replace(policyWithGroups, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	rig.pollTwice()
	rig.pollTwice()
	out := rig.out.String()
	if strings.Count(out, "policy reload (file changed) refused") != 1 ||
		!strings.Contains(out, "refuses admission to 2 of 2 devices") || !strings.Contains(out, "leaf1, leaf2") {
		t.Fatalf("the refusal: %s", out)
	}
	if testutil.ToFloat64(rig.m.PolicyFileRefused) != 1 {
		t.Fatal("port49_policy_file_refused is not 1")
	}
	if c, err := rig.st.GetContext(context.Background(), k); err != nil || !c.RevokedAt.IsZero() {
		t.Fatalf("the session was revoked: %+v, %v", c, err)
	}
	if toks, _ := rig.st.Candidates(context.Background(), tk); len(toks) != 1 {
		t.Fatalf("the token went: %d left", len(toks))
	}
	rig.r.cfgPath = filepath.Join(t.TempDir(), "port49d.yaml")
	if err := os.WriteFile(rig.r.cfgPath, []byte("inventory: {max_removed_percent: 100}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.with(func() { rig.r.reload(context.Background(), "SIGHUP") })
	if len(rig.b.Policy.Load().AdmissionRefusals()) != 2 {
		t.Fatalf("SIGHUP with the bound raised did not apply: %s", rig.out.String())
	}
}
```

  (import `time` and `internal/store` there.)

- [ ] **Step 6: Run the tests, everything, and commit**

Run: `go test ./cmd/port49d/ ./internal/config/ -count=1 -race && make test && make vet && make build`
Expected: PASS, `-race` included: the snapshot age is read at scrape from another goroutine.

```bash
git add internal/config internal/daemon/metrics cmd/port49d
git commit -m "feat(port49d): reload the inventory file, bounded, and refresh live sessions after it

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 13: A swap that moves privilege is written to the log as it happens

**Files:**
- Modify: `internal/daemon/metrics/metrics.go` (`InventoryChanges`)
- Modify: `cmd/port49d/reload.go` (`after`, `securityEvents`)
- Test: `cmd/port49d/reload_inventory_test.go`

**Interfaces:**
- Consumes: `bundle.Report.Security` (Task 7); `decision.EventInventoryChange`, `decision.Change`
  (Task 8); `reloader.after` (Task 12).
- Produces: `metrics.InventoryChanges` (`port49_inventory_changes_total{kind}`); one
  `inventory_change` record per security change of every swap.

- [ ] **Step 1: Write the failing test.** Append to `cmd/port49d/reload_inventory_test.go`:

```go
// Spec §10: an address added to a device already in inventory, and a device
// joining or leaving a security_log scope, are security events — one
// inventory_change record each, counted.
func TestASwapThatMovesPrivilegeIsLogged(t *testing.T) {
	watched := strings.Replace(minimalPolicy, "scopes: [{name: all_devices, match: {}}]",
		"scopes: [{name: all_devices, match: {}}, {name: watched, match: {name: [leaf2]}, security_log: true}]", 1)
	rig := newReloadRig(t, watched)
	var buf syncBuffer
	rig.b.Log = decision.NewJSONLines(&buf)
	rig.writeInventory(t, twoDevices)
	rig.pollTwice()
	got := buf.String()
	for _, want := range []string{`"event":"inventory_change"`, `"kind":"address_added"`, `"address":"10.0.0.1"`,
		`"kind":"scope_joined"`, `"scope":"watched"`, `"name":"leaf2"`} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %s in %s", want, got)
		}
	}
	if n := testutil.ToFloat64(rig.m.InventoryChanges.WithLabelValues("address_added")); n != 1 {
		t.Fatalf("address_added = %v", n)
	}
	if n := testutil.ToFloat64(rig.m.InventoryChanges.WithLabelValues("scope_joined")); n != 1 {
		t.Fatalf("scope_joined = %v", n)
	}
}
```

  (import `internal/decision`). `syncBuffer` is the package's test buffer.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./cmd/port49d/ -run TestASwapThatMovesPrivilegeIsLogged -count=1`
Expected: FAIL to compile — `rig.m.InventoryChanges undefined`.

- [ ] **Step 3: Implement.** In `metrics.go`:

```go
	// port49_inventory_changes_total{kind}: security-relevant changes a bundle
	// swap made (spec §10) — "address_added" (an address on a device already
	// in inventory, which a mint hands to an SSH client), "scope_joined" and
	// "scope_left" (a scope with security_log: true), "key_ref_changed" (a
	// device moved onto another key), "admission_changed" (a device already
	// in inventory newly admitted) and "device_added" (a device added and
	// admitted). Each is an inventory_change record naming the device; the
	// label is the kind only.
	InventoryChanges *prometheus.CounterVec
```

  built as `prometheus.NewCounterVec(prometheus.CounterOpts{Name: "port49_inventory_changes_total", Help:
  "Security-relevant changes a bundle swap made, by kind."}, []string{"kind"})` and registered. In
  `reload.go`, `after` becomes:

```go
func (r *reloader) after(ctx context.Context, rep bundle.Report, pol *policy.Policy, now time.Time) {
	if n := r.securityEvents(rep, now); n > 0 {
		fmt.Fprintf(stderr, "port49d: inventory: %d security change(s) written as inventory_change records "+
			"(spec §10)\n", n)
	}
	sayPolicy(pol, now)
	r.refresh(ctx)
}

// securityEvents writes one inventory_change record for each security change
// the swap made, and counts it (spec §5.7, §10). It returns how many.
func (r *reloader) securityEvents(rep bundle.Report, now time.Time) int {
	changes := rep.Security()
	for _, c := range changes {
		r.broker.Log.Emit(decision.Record{TS: now, Event: decision.EventInventoryChange,
			Device: &decision.Device{Name: c.Device, Platform: c.Platform},
			Change: &decision.Change{Kind: c.Kind, Scope: c.Scope, Address: c.Address, From: c.From, To: c.To,
				FromBundle: rep.From, ToBundle: rep.To}})
		r.metrics.InventoryChanges.WithLabelValues(c.Kind).Inc()
	}
	return len(changes)
}
```

- [ ] **Step 4: Run the tests, everything, and commit**

Run: `go test ./cmd/port49d/ -count=1 && make test && make vet`
Expected: PASS.

```bash
git add internal/daemon/metrics cmd/port49d
git commit -m "feat(port49d): write an inventory_change record for every swap that moves privilege

security_log scopes now emit, as spec §5.5 and §10 require.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 14: `retire_after` is enforced, and each key version's devices and deadline are metrics

**Files:**
- Modify: `internal/config/config.go` (`KeyVersion.RetireAfter`, `RetireAt`, `checkKeySets`, `KeySets`, notices)
- Modify: `internal/keyring/keyring.go` (`Version.RetireAt`, `Resolve(h, obf, now)`)
- Create: `internal/keyring/seen.go`
- Modify: `internal/keyring/keyring_test.go`, `internal/keyring/fuzz_test.go` (the `now` argument)
- Modify: `internal/daemon/server/server.go`, `conn.go` (`Deps.KeySeen`, `Resolve`'s clock)
- Modify: `internal/daemon/metrics/metrics.go` (`KeySample`, `WatchKeys`, the key collector)
- Modify: `cmd/port49d/main.go` (wiring)
- Test: `internal/keyring/seen_test.go`, `internal/config/config_test.go`,
  `internal/daemon/server/server_test.go`, `internal/daemon/metrics/metrics_test.go`

**Interfaces:**
- Consumes: nothing new.
- Produces:
  - `config.KeyVersion.RetireAfter string` (`retire_after`), `RetireAt time.Time`;
    `func config.KeySets(raw []byte) (map[string]KeySet, error)` — no secret read.
  - `keyring.Version.RetireAt time.Time`; `func (s Set) Resolve(h wire.Header, obfuscated []byte,
    now time.Time) Result`; `func (s Set) State(i int, now time.Time) string` (`current`, `accept`,
    `retired`).
  - `keyring.Seen` with `Mark(device, keyRef string, version int)` and `Count(keyRef string,
    version int) int`.
  - `server.Deps.KeySeen func(device, keyRef string, version int)`.
  - `metrics.KeySample{KeyRef string; Version int; Devices int; RetireAt time.Time}`,
    `func (m *Metrics) WatchKeys(sample func() []KeySample, now func() time.Time)`; series
    `port49_key_version_devices{key_ref,version}` and `port49_key_retirement_seconds{key_ref,version}`.

- [ ] **Step 1: Write the failing tests.** Create `internal/keyring/seen_test.go`:

```go
package keyring

import (
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

func TestSeenCountsEachDevicesLatestVersion(t *testing.T) {
	var s Seen
	s.Mark("leaf-01", "prod_key", 2)
	s.Mark("leaf-02", "prod_key", 2)
	s.Mark("leaf-01", "prod_key", 3)
	if s.Count("prod_key", 2) != 1 || s.Count("prod_key", 3) != 1 {
		t.Fatalf("v2 %d, v3 %d", s.Count("prod_key", 2), s.Count("prod_key", 3))
	}
}

// Spec §10: past retire_after a version identifies and never admits.
func TestAVersionPastItsDateIdentifiesAndNeverAdmits(t *testing.T) {
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 7}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("u"), Data: []byte("x")}.Encode()
	h.Length = uint32(len(body))
	obf := wire.Obfuscate(h, []byte("old"), body)
	at := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	set := Set{Ref: "prod_key", Versions: []Version{{Number: 3, Secret: []byte("new")}, {Number: 2, Secret: []byte("old"), RetireAt: at}}}
	if r := set.Resolve(h, obf, at.Add(-time.Second)); r.Diagnosis != DiagValidated || r.Version != 2 {
		t.Fatalf("before the instant: %+v", r)
	}
	if r := set.Resolve(h, obf, at); r.Diagnosis != DiagMatchesRetired || r.Version != 2 || r.Body != nil {
		t.Fatalf("at the instant: %+v", r)
	}
	if set.State(0, at) != "current" || set.State(1, at.Add(-time.Second)) != "accept" || set.State(1, at) != "retired" {
		t.Fatal("State")
	}
}
```

  Append to `internal/config/config_test.go`:

```go
// retire_after is a date, admitting through that day UTC (plan 6a Decided 7),
// on accept versions only; a passed one and a missing one are said at start.
func TestRetireAfter(t *testing.T) {
	setKeyEnv(t)
	i := write(t, "inv.yaml", inv)
	body := strings.Replace(fmt.Sprintf(sample, i), "accept:  [{version: 2, secret_env: T_PROD_V2}]",
		"accept:  [{version: 2, secret_env: T_PROD_V2, retire_after: 2000-01-01}]", 1)
	cfg, err := Load(write(t, "a.yaml", body))
	if err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC); !cfg.Keys["prod_key"].Accept[0].RetireAt.Equal(want) {
		t.Fatalf("RetireAt %v", cfg.Keys["prod_key"].Accept[0].RetireAt)
	}
	if !strings.Contains(strings.Join(cfg.Notices, "\n"), "retire_after 2000-01-01 has passed") {
		t.Fatalf("notices: %q", cfg.Notices)
	}
	if ks := cfg.Keyring()["prod_key"]; !ks.Versions[1].RetireAt.Equal(cfg.Keys["prod_key"].Accept[0].RetireAt) {
		t.Fatal("the keyring does not carry the date")
	}
	cfg, err = Load(write(t, "b.yaml", fmt.Sprintf(sample, i)))
	if err != nil || !strings.Contains(strings.Join(cfg.Notices, "\n"), "has no retire_after") {
		t.Fatalf("a missing date: %q, %v", cfg.Notices, err)
	}
	for _, bad := range []string{
		strings.Replace(fmt.Sprintf(sample, i), "current: {version: 3, secret_env: T_PROD_V3}",
			"current: {version: 3, secret_env: T_PROD_V3, retire_after: 2999-01-01}", 1),
		strings.Replace(body, "retire_after: 2000-01-01", "retire_after: soon", 1),
	} {
		if _, err := Load(write(t, "c.yaml", bad)); err == nil {
			t.Fatalf("loaded: %s", bad)
		}
	}
	sets, err := KeySets([]byte(body))
	if err != nil || len(sets["prod_key"].Accept) != 1 || sets["prod_key"].Accept[0].RetireAt.IsZero() {
		t.Fatalf("KeySets: %+v, %v", sets, err)
	}
}
```

  Append to `internal/daemon/server/server_test.go`:

```go
// A validated connection marks its device's key version, and an accept
// version past its date is refused as a retired one is.
func TestKeyVersionsAreMarkedAndADatePastRefuses(t *testing.T) {
	log := &syncBuffer{}
	var seen keyring.Seen
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Keys = map[string]keyring.Set{"prod_key": {Ref: "prod_key", Versions: []keyring.Version{
			{Number: 2, Secret: []byte("k2")}, {Number: 1, Secret: []byte("k1"), RetireAt: time.Now().Add(-time.Hour)}}}}
		d.KeySeen = seen.Mark
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.recv(t)
	if !waitFor(t, func() bool { return seen.Count("prod_key", 2) == 1 }) {
		t.Fatal("the validated version was not marked")
	}
	c = dial(t, ts.addr, []byte("k1"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"matches_retired"`) }) {
		t.Fatalf("a version past its date admitted: %s", log.String())
	}
}
```

  Append to `internal/daemon/metrics/metrics_test.go` (create it with `package metrics` if absent):

```go
func TestKeySeriesAreSampledAtScrape(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg)
	now := time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC)
	m.WatchKeys(func() []KeySample {
		return []KeySample{{KeyRef: "prod_key", Version: 3, Devices: 8},
			{KeyRef: "prod_key", Version: 2, Devices: 1, RetireAt: now.Add(48 * time.Hour)}}
	}, func() time.Time { return now })
	want := `
# HELP port49_key_retirement_seconds Seconds until a key version's retire_after passes; negative once it has.
# TYPE port49_key_retirement_seconds gauge
port49_key_retirement_seconds{key_ref="prod_key",version="2"} 172800
# HELP port49_key_version_devices Devices whose latest validated connection since start used this key version.
# TYPE port49_key_version_devices gauge
port49_key_version_devices{key_ref="prod_key",version="2"} 1
port49_key_version_devices{key_ref="prod_key",version="3"} 8
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "port49_key_version_devices",
		"port49_key_retirement_seconds"); err != nil {
		t.Fatal(err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/keyring/ ./internal/config/ ./internal/daemon/... -run 'Seen|PastItsDate|RetireAfter|KeyVersions|KeySeries' -count=1`
Expected: FAIL to compile — `undefined: Seen`, `unknown field RetireAt`, `too many arguments in
call to set.Resolve`, `undefined: KeySets`, `undefined: KeySample`.

- [ ] **Step 3: The keyring.** In `internal/keyring/keyring.go`, `Version` gains:

```go
	// RetireAt is the first instant this version is refused: past it, it
	// identifies a device and never admits one, as a retired version does
	// (spec §10, "Retirement is enforced"). Zero is never.
	RetireAt time.Time
```

  `Resolve` takes the time of the packet:

```go
func (s Set) Resolve(h wire.Header, obfuscated []byte, now time.Time) Result {
	if err := h.Validate(); err != nil {
		if errors.Is(err, wire.ErrUnencrypted) {
			return Result{Diagnosis: DiagUnencrypted}
		}
		return Result{Diagnosis: DiagNotTACACS}
	}
	for i, v := range s.Versions {
		body := wire.Obfuscate(h, v.Secret, obfuscated)
		if !Validates(h, body) {
			continue
		}
		if s.State(i, now) == "retired" {
			return Result{Diagnosis: DiagMatchesRetired, Version: v.Number}
		}
		return Result{Diagnosis: DiagValidated, Version: v.Number, Body: body}
	}
	return Result{Diagnosis: DiagNoKnownKey}
}

// State is version i's role at now: "current" (the first), "retired"
// (listed retired, or past its RetireAt), or "accept".
func (s Set) State(i int, now time.Time) string {
	v := s.Versions[i]
	switch {
	case v.Retired || (!v.RetireAt.IsZero() && !now.Before(v.RetireAt)):
		return "retired"
	case i == 0:
		return "current"
	}
	return "accept"
}
```

  (import `time`). Every existing call `set.Resolve(h, x)` in `keyring_test.go` and `fuzz_test.go`
  gains a third argument `time.Time{}` (the zero time retires nothing): `grep -n 'Resolve(' internal/keyring/*_test.go`
  lists them. Create `internal/keyring/seen.go`:

```go
package keyring

import "sync"

// Seen remembers, per device, the key_ref and version its latest validated
// connection used since port49d started: what port49_key_version_devices
// counts. Only admitted devices are marked, so it is bounded by the inventory.
type Seen struct {
	mu   sync.Mutex
	last map[string]seenAs
}

type seenAs struct {
	ref     string
	version int
}

// Mark records that device's latest validated connection used ref's version.
func (s *Seen) Mark(device, ref string, version int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.last == nil {
		s.last = map[string]seenAs{}
	}
	s.last[device] = seenAs{ref, version}
}

// Count is how many devices' latest validated connection used ref's version.
func (s *Seen) Count(ref string, version int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, a := range s.last {
		if a.ref == ref && a.version == version {
			n++
		}
	}
	return n
}
```

- [ ] **Step 4: The server.** `Deps` gains:

```go
	// KeySeen marks the key version each admitted device's connection
	// validated under (keyring.Seen.Mark); nil marks nothing.
	KeySeen func(device, keyRef string, version int)
```

  In `conn.go`'s `deobfuscate`, the trial takes the packet's time, and a validation is marked:

```go
		r := s.keys.Resolve(h, obf, s.d.Now())
```

```go
		s.version = r.Version
		if s.d.KeySeen != nil {
			s.d.KeySeen(s.dev.Device.Name, s.keys.Ref, r.Version)
		}
```

- [ ] **Step 5: The config.** `KeyVersion` becomes:

```go
type KeyVersion struct {
	Version   int    `yaml:"version"`
	SecretEnv string `yaml:"secret_env"`
	// RetireAfter is the last day, UTC, the version admits (spec §10):
	// accept versions only. RetireAt is it parsed, the first instant the
	// version is refused — midnight after that day. Zero is none.
	RetireAfter string    `yaml:"retire_after"`
	RetireAt    time.Time `yaml:"-"`
}
```

  Move the version checks out of `Load`'s key loop into one function both loaders use, and keep
  only the environment lookup in `Load`:

```go
// checkKeySets validates keys without reading a secret: every version
// numbered from 1 and once, a secret_env named, and retire_after a date on an
// accept version only. It returns the sets with RetireAt filled.
func checkKeySets(keys map[string]KeySet) (map[string]KeySet, error) {
	out := make(map[string]KeySet, len(keys))
	for ref, ks := range keys {
		seen := map[int]bool{}
		for _, v := range allVersions(ks) {
			if v.Version < 1 {
				return nil, fmt.Errorf("config: key %s: every version number must be 1 or greater", ref)
			}
			if seen[v.Version] {
				return nil, fmt.Errorf("config: key %s: version %d appears twice", ref, v.Version)
			}
			seen[v.Version] = true
			if v.SecretEnv == "" {
				return nil, fmt.Errorf("config: key %s version %d: secret_env is required", ref, v.Version)
			}
		}
		if ks.Current.RetireAfter != "" {
			return nil, fmt.Errorf("config: key %s: current version %d has retire_after; current is what devices "+
				"are provisioned with, so retire it by making another version current (spec §10)", ref, ks.Current.Version)
		}
		for _, v := range ks.Retired {
			if v.RetireAfter != "" {
				return nil, fmt.Errorf("config: key %s: retired version %d has retire_after; a retired version is "+
					"refused already", ref, v.Version)
			}
		}
		accept := make([]KeyVersion, len(ks.Accept))
		for i, v := range ks.Accept {
			if v.RetireAfter != "" {
				day, err := time.Parse("2006-01-02", v.RetireAfter)
				if err != nil {
					return nil, fmt.Errorf("config: key %s version %d: retire_after %q is not a date (YYYY-MM-DD)",
						ref, v.Version, v.RetireAfter)
				}
				v.RetireAt = day.AddDate(0, 0, 1) // admits through the named day, UTC
			}
			accept[i] = v
		}
		ks.Accept = accept
		out[ref] = ks
	}
	return out, nil
}

// KeySets reads port49d.yaml's keys: block as Load does, without reading a
// secret: the names, versions and dates `port49 keys status` and `port49
// policy test --config` read, in CI or anywhere else no key is.
func KeySets(raw []byte) (map[string]KeySet, error) {
	var f fileConfig
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && err != io.EOF {
		return nil, fmt.Errorf("config: %w; check the key spelling against the port49d.yaml schema", err)
	}
	return checkKeySets(f.Keys)
}
```

  In `Load`, before the key loop: `if c.Keys, err = checkKeySets(c.Keys); err != nil { return
  Config{}, err }`, and the loop keeps only the environment lookup and `c.secrets`. After it, the
  notices:

```go
	now := time.Now()
	for _, ref := range sortedKeySets(c.Keys) {
		for _, v := range c.Keys[ref].Accept {
			switch {
			case v.RetireAt.IsZero():
				c.Notices = append(c.Notices, fmt.Sprintf("key %s version %d has no retire_after; an indefinitely "+
					"accepted version is what rotation exists to prevent (spec §10)", ref, v.Version))
			case !now.Before(v.RetireAt):
				c.Notices = append(c.Notices, fmt.Sprintf("key %s version %d: retire_after %s has passed, so it "+
					"identifies devices and admits none; move it to retired, or remove it", ref, v.Version, v.RetireAfter))
			}
		}
	}
```

  with `sortedKeySets` returning the refs sorted. `Keyring()` copies the date: the accept loop's
  `keyring.Version{Number: v.Version, Secret: ..., RetireAt: v.RetireAt}`.

- [ ] **Step 6: The metrics.** In `metrics.go`:

```go
// KeySample is one key version at a scrape: how many devices' latest
// validated connection used it, and when it retires (zero: never).
type KeySample struct {
	KeyRef   string
	Version  int
	Devices  int
	RetireAt time.Time
}

type keyWatch struct {
	sample func() []KeySample
	now    func() time.Time
}

// keyCollector reports port49_key_version_devices{key_ref,version} and
// port49_key_retirement_seconds{key_ref,version} at each scrape (spec §10:
// "alarm severity escalates as retire_after approaches while devices still
// present the version"). Labels are the key_ref and the version only; the
// devices are named by `port49 keys status`.
type keyCollector struct {
	m                *Metrics
	devices, retires *prometheus.Desc
}

func (k keyCollector) Describe(ch chan<- *prometheus.Desc) { ch <- k.devices; ch <- k.retires }

func (k keyCollector) Collect(ch chan<- prometheus.Metric) {
	w := k.m.keys.Load()
	if w == nil {
		return
	}
	now := w.now()
	for _, s := range w.sample() {
		v := strconv.Itoa(s.Version)
		ch <- prometheus.MustNewConstMetric(k.devices, prometheus.GaugeValue, float64(s.Devices), s.KeyRef, v)
		if !s.RetireAt.IsZero() {
			ch <- prometheus.MustNewConstMetric(k.retires, prometheus.GaugeValue, s.RetireAt.Sub(now).Seconds(), s.KeyRef, v)
		}
	}
}

// WatchKeys sets what the key series report at each scrape.
func (m *Metrics) WatchKeys(sample func() []KeySample, now func() time.Time) {
	m.keys.Store(&keyWatch{sample: sample, now: now})
}
```

  `Metrics` gains `keys atomic.Pointer[keyWatch]`; `New` registers
  `keyCollector{m: m, devices: prometheus.NewDesc("port49_key_version_devices", "Devices whose latest
  validated connection since start used this key version.", []string{"key_ref", "version"}, nil),
  retires: prometheus.NewDesc("port49_key_retirement_seconds", "Seconds until a key version's
  retire_after passes; negative once it has.", []string{"key_ref", "version"}, nil)}` (import
  `strconv`, `time`).

- [ ] **Step 7: port49d.** In `run`, before `deps`:

```go
	keys := cfg.Keyring()
	seen := &keyring.Seen{}
	m.WatchKeys(func() []metrics.KeySample {
		var out []metrics.KeySample
		for _, ref := range cfg.KeyRefs() {
			for _, v := range keys[ref].Versions {
				out = append(out, metrics.KeySample{KeyRef: ref, Version: v.Number, Devices: seen.Count(ref, v.Number),
					RetireAt: v.RetireAt})
			}
		}
		return out
	}, time.Now)
```

  and `deps` takes `Keys: keys, KeySeen: seen.Mark`.

- [ ] **Step 8: Run the tests, everything, fuzz, and commit**

Run: `go test ./internal/keyring/ ./internal/config/ ./internal/daemon/... ./cmd/port49d/ -count=1 && make test && make vet && make fuzz`
Expected: PASS; `make fuzz` because `Resolve` is the first code an unauthenticated packet reaches.

```bash
git add internal cmd/port49d
git commit -m "feat(keys): retire_after is enforced, and each key version's devices and deadline are metrics

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---
### Task 15: `port49 keys status` and `port49 keys show`

**Files:**
- Create: `internal/keystatus/keystatus.go`
- Test: `internal/keystatus/keystatus_test.go`
- Create: `cmd/port49/keys.go`
- Modify: `cmd/port49/main.go` (usage, dispatch), `cmd/port49/policy.go` (`policyFiles.loadWith`)
- Test: `cmd/port49/keys_test.go`

**Interfaces:**
- Consumes: `decision.Device.KeyRef/KeyVersion` (Task 8); `config.KeySets`, `KeyVersion.RetireAt`
  (Task 14); `(*policy.Policy).Admitted`, `KeyAssignment` (Task 4); `readLogs` (plan 5b,
  `cmd/port49/capabilities.go`).
- Produces:
  - `keystatus.Device{Name, KeyRef string; Addresses []netip.Addr}`,
    `keystatus.Version{Number int; State string; RetireAt time.Time}`,
    `keystatus.Key{Ref string; Versions []Version}`, `keystatus.Options{From, Now time.Time}`,
    `keystatus.Row`, `keystatus.Source`, `keystatus.Report{Rows []Row; Unseen []Device; Sources []Source}`,
    `func Infer(recs []decision.Record, devices []Device, keys []Key, opt Options) Report`,
    `func (r Report) Write(w io.Writer, now time.Time)`, `func Describe(diagnosis string, version int) string`.
  - `cmd/port49`: `func (f *policyFiles) loadWith(keyRefs []string) (*policy.Policy, error)`,
    `func readKeySets(path string) (map[string]config.KeySet, error)`,
    `func keyRefsOf(sets map[string]config.KeySet) []string`, `func keysCmd(args []string, stdout, stderr io.Writer) int`.

- [ ] **Step 1: Write the failing tests.** Create `internal/keystatus/keystatus_test.go`:

```go
package keystatus

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/decision"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

func validated(at time.Time, device string, version int) decision.Record {
	return decision.Record{TS: at, Event: decision.EventAuthorizeCommand,
		Device: &decision.Device{Name: device, Platform: "arista_eos", KeyRef: "prod_key", KeyVersion: version}}
}

func unvalidated(at time.Time, source, diag string, version int) decision.Record {
	return decision.Record{TS: at, Event: decision.EventUnvalidated,
		Unvalidated: &decision.Unvalidated{Source: source, Diagnosis: diag, KeyRef: "prod_key", Version: version}}
}

// Spec §10, "Phase-out has to be observable": devices per version, the ones
// still on an old version named, and every unvalidated source bucketed.
func TestInferNamesTheDevicesARotationStallsOn(t *testing.T) {
	recs := []decision.Record{
		validated(t0.Add(-time.Hour), "leaf-19", 3), validated(t0.Add(-12*time.Minute), "leaf-19", 2),
		validated(t0.Add(-5*time.Minute), "leaf-01", 3),
		unvalidated(t0.Add(-30*time.Second), "10.20.4.9", "matches_retired", 1),
		unvalidated(t0.Add(-40*time.Second), "10.20.4.9", "matches_retired", 1),
		unvalidated(t0.Add(-2*time.Second), "203.0.113.7", "not_tacacs", 0),
		{TS: t0, Event: decision.EventUnvalidated, Unvalidated: &decision.Unvalidated{Source: "10.20.0.8",
			Diagnosis: "device_quarantined"}},
	}
	devices := []Device{
		{Name: "leaf-01", KeyRef: "prod_key", Addresses: []netip.Addr{netip.MustParseAddr("10.20.0.7")}},
		{Name: "leaf-19", KeyRef: "prod_key", Addresses: []netip.Addr{netip.MustParseAddr("10.20.4.9")}},
		{Name: "spine-02", KeyRef: "prod_key", Addresses: []netip.Addr{netip.MustParseAddr("10.20.7.3")}},
	}
	keys := []Key{{Ref: "prod_key", Versions: []Version{{Number: 3, State: "current"},
		{Number: 2, State: "accept", RetireAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)},
		{Number: 1, State: "retired"}}}}
	rep := Infer(recs, devices, keys, Options{Now: t0})
	if len(rep.Rows) != 3 || rep.Rows[0].Version != 3 || strings.Join(rep.Rows[0].Devices, ",") != "leaf-01" ||
		strings.Join(rep.Rows[1].Devices, ",") != "leaf-19" || len(rep.Rows[2].Devices) != 0 {
		t.Fatalf("rows: %+v", rep.Rows)
	}
	if len(rep.Unseen) != 1 || rep.Unseen[0].Name != "spine-02" {
		t.Fatalf("unseen: %+v", rep.Unseen)
	}
	if len(rep.Sources) != 2 || rep.Sources[0].Source != "203.0.113.7" || rep.Sources[1].Device != "leaf-19" ||
		rep.Sources[1].Attempts != 2 {
		t.Fatalf("sources (a quarantine is not a key matter): %+v", rep.Sources)
	}
	var out bytes.Buffer
	rep.Write(&out, t0)
	for _, want := range []string{"⚠ rotation not finished: leaf-19 (retire_after 2026-10-01)", "12m ago",
		"never seen in the log: spine-02", "matches retired v1", "not TACACS+ (header invalid)"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	if rep := Infer(recs, devices, keys, Options{Now: t0, From: t0.Add(-10 * time.Minute)}); len(rep.Rows[1].Devices) != 0 {
		t.Fatalf("--since kept an older record: %+v", rep.Rows[1])
	}
}
```

  Create `cmd/port49/keys_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/decision"
)

const keysPolicy = `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

const keysInventory = `devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.20.0.7]}
  - {name: leaf-19, platform: arista_eos, addresses: [10.20.4.9]}
`

const keysConfig = `keys:
  prod_key:
    current: {version: 3, secret_env: NEVER_READ_V3}
    accept:  [{version: 2, secret_env: NEVER_READ_V2, retire_after: 2026-10-01}]
`

func keysFiles(t *testing.T) (policyPath, inventoryPath, configPath, logPath string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	var log bytes.Buffer
	sink := decision.NewJSONLines(&log)
	now := time.Now()
	sink.Emit(decision.Record{TS: now.Add(-time.Minute), Event: decision.EventRedeem,
		Device: &decision.Device{Name: "leaf-01", Platform: "arista_eos", KeyRef: "prod_key", KeyVersion: 3}})
	sink.Emit(decision.Record{TS: now.Add(-2 * time.Minute), Event: decision.EventRedeem,
		Device: &decision.Device{Name: "leaf-19", Platform: "arista_eos", KeyRef: "prod_key", KeyVersion: 2}})
	return write("policy.yaml", keysPolicy), write("inventory.yaml", keysInventory),
		write("port49d.yaml", keysConfig), write("decisions.jsonl", log.String())
}

func TestKeysStatusNamesTheDeviceOnTheOldVersion(t *testing.T) {
	pol, inv, cfg, log := keysFiles(t)
	var out, errOut bytes.Buffer
	code := run([]string{"keys", "status", "--policy", pol, "--inventory", inv, "--config", cfg, log}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "rotation not finished: leaf-19") {
		t.Fatalf("%s", out.String())
	}
}

func TestKeysShowSaysWhichKeyAndWhy(t *testing.T) {
	pol, inv, cfg, _ := keysFiles(t)
	var out, errOut bytes.Buffer
	code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "--config", cfg, "leaf-19"}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, want := range []string{"leaf-19: key_ref prod_key, by the cidr tier (cidr 10.0.0.0/8 → prod_key)",
		"provision version 3", "also accepted: version 2, retire_after 2026-10-01", "the secret is not shown"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
	if code := run([]string{"keys", "show", "--policy", pol, "--inventory", inv, "nobody"}, &out, &errOut); code != 1 {
		t.Fatalf("an unknown device exits %d", code)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/keystatus/ ./cmd/port49/ -run 'Keys|Infer' -count=1`
Expected: FAIL to compile — `no non-test Go files in internal/keystatus`; the CLI prints usage.

- [ ] **Step 3: `internal/keystatus/keystatus.go`:**

```go
// Package keystatus reads a rotation's phase-out from the decision log (spec
// §10, "Phase-out has to be observable"; §12, `port49 keys status`): the key
// version each device's latest validated exchange used, which devices are
// still on a version other than current, which inventory devices the log
// never saw, and every source whose packets validated against nothing. It
// reads no secret.
package keystatus

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/decision"
)

// Device is an inventory device and the key_ref it is assigned.
type Device struct {
	Name, KeyRef string
	Addresses    []netip.Addr
}

// Version is one key version, as port49d.yaml declares it at the report's
// Now: "current", "accept", or "retired" (listed retired, or past RetireAt).
type Version struct {
	Number   int
	State    string
	RetireAt time.Time
}

// Key is one key_ref's versions.
type Key struct {
	Ref      string
	Versions []Version
}

// Options bound the report. A zero From reads every record.
type Options struct {
	From, Now time.Time
}

// Row is one key version: the devices whose latest validated exchange used
// it, and when the latest of those was.
type Row struct {
	KeyRef   string
	Version  int
	State    string
	RetireAt time.Time
	Devices  []string
	Last     time.Time
}

// Source is every unvalidated packet from one source address under one
// diagnosis.
type Source struct {
	Source, Device, KeyRef, Diagnosis string
	Version, Attempts                 int
	Last                              time.Time
}

// Report is the rotation's state as the log shows it.
type Report struct {
	Rows    []Row
	Unseen  []Device
	Sources []Source
}

type latest struct {
	ref     string
	version int
	at      time.Time
}

// Infer builds the report. A quarantined device's records are not a key
// matter and are left out of Sources.
func Infer(recs []decision.Record, devices []Device, keys []Key, opt Options) Report {
	byAddr := map[netip.Addr]string{}
	for _, d := range devices {
		for _, a := range d.Addresses {
			byAddr[a] = d.Name
		}
	}
	last := map[string]latest{}
	type srcKey struct{ source, diag string }
	srcs := map[srcKey]*Source{}
	for _, r := range recs {
		if !opt.From.IsZero() && r.TS.Before(opt.From) {
			continue
		}
		if r.Event == decision.EventUnvalidated && r.Unvalidated != nil {
			u := r.Unvalidated
			if u.Diagnosis == "device_quarantined" {
				continue
			}
			k := srcKey{u.Source, u.Diagnosis}
			s, ok := srcs[k]
			if !ok {
				s = &Source{Source: u.Source, Diagnosis: u.Diagnosis, KeyRef: u.KeyRef}
				if r.Device != nil && r.Device.Name != "" {
					s.Device = r.Device.Name
				} else if a, err := netip.ParseAddr(u.Source); err == nil {
					s.Device = byAddr[a]
				}
				srcs[k] = s
			}
			s.Attempts++
			if r.TS.After(s.Last) {
				s.Last = r.TS
				if u.Version > 0 {
					s.Version = u.Version
				}
			}
			continue
		}
		if r.Device == nil || r.Device.Name == "" || r.Device.KeyVersion == 0 {
			continue
		}
		if l, ok := last[r.Device.Name]; !ok || r.TS.After(l.at) {
			last[r.Device.Name] = latest{r.Device.KeyRef, r.Device.KeyVersion, r.TS}
		}
	}
	var rep Report
	type verKey struct {
		ref     string
		version int
	}
	rows := map[verKey]int{}
	sorted := append([]Key(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Ref < sorted[j].Ref })
	for _, k := range sorted {
		vs := append([]Version(nil), k.Versions...)
		sort.Slice(vs, func(i, j int) bool { return vs[i].Number > vs[j].Number })
		for _, v := range vs {
			rows[verKey{k.Ref, v.Number}] = len(rep.Rows)
			rep.Rows = append(rep.Rows, Row{KeyRef: k.Ref, Version: v.Number, State: v.State, RetireAt: v.RetireAt})
		}
	}
	names := make([]string, 0, len(last))
	for name := range last {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		l := last[name]
		i, ok := rows[verKey{l.ref, l.version}]
		if !ok {
			// A version the log names and port49d.yaml no longer declares.
			i = len(rep.Rows)
			rows[verKey{l.ref, l.version}] = i
			rep.Rows = append(rep.Rows, Row{KeyRef: l.ref, Version: l.version, State: "undeclared"})
		}
		rep.Rows[i].Devices = append(rep.Rows[i].Devices, name)
		if l.at.After(rep.Rows[i].Last) {
			rep.Rows[i].Last = l.at
		}
	}
	for _, d := range devices {
		if _, ok := last[d.Name]; !ok {
			rep.Unseen = append(rep.Unseen, d)
		}
	}
	sort.Slice(rep.Unseen, func(i, j int) bool { return rep.Unseen[i].Name < rep.Unseen[j].Name })
	for _, s := range srcs {
		rep.Sources = append(rep.Sources, *s)
	}
	sort.Slice(rep.Sources, func(i, j int) bool {
		if !rep.Sources[i].Last.Equal(rep.Sources[j].Last) {
			return rep.Sources[i].Last.After(rep.Sources[j].Last)
		}
		return rep.Sources[i].Source < rep.Sources[j].Source
	})
	return rep
}

// Write prints the report as spec §10 shows it.
func (r Report) Write(w io.Writer, now time.Time) {
	fmt.Fprintf(w, "%-12s %7s  %-10s %7s  %s\n", "KEY_REF", "VERSION", "STATE", "DEVICES", "LAST OLD-KEY USE")
	prev := ""
	for _, row := range r.Rows {
		ref := row.KeyRef
		if ref == prev {
			ref = ""
		}
		prev = row.KeyRef
		lastUse := "—"
		stalled := row.State != "current" && len(row.Devices) > 0
		if stalled {
			lastUse = ago(now, row.Last)
		}
		line := fmt.Sprintf("%-12s %7d  %-10s %7d  %s", ref, row.Version, row.State, len(row.Devices), lastUse)
		if stalled {
			line += "   ⚠ rotation not finished: " + strings.Join(row.Devices, ", ")
			if !row.RetireAt.IsZero() {
				line += fmt.Sprintf(" (retire_after %s)", row.RetireAt.AddDate(0, 0, -1).Format("2006-01-02"))
			}
		}
		fmt.Fprintln(w, line)
	}
	if len(r.Unseen) > 0 {
		names := make([]string, len(r.Unseen))
		for i, d := range r.Unseen {
			names[i] = d.Name
		}
		fmt.Fprintf(w, "never seen in the log: %s\n", strings.Join(names, ", "))
	}
	if len(r.Sources) == 0 {
		return
	}
	fmt.Fprintf(w, "\nUNVALIDATED SOURCES\n%-15s %-12s %-12s %8s  %-9s %s\n", "SOURCE", "DEVICE", "KEY_REF",
		"ATTEMPTS", "LAST", "DIAGNOSIS")
	for _, s := range r.Sources {
		dev, ref := s.Device, s.KeyRef
		if dev == "" {
			dev = "—"
		}
		if ref == "" {
			ref = "—"
		}
		fmt.Fprintf(w, "%-15s %-12s %-12s %8d  %-9s %s\n", s.Source, dev, ref, s.Attempts, ago(now, s.Last),
			Describe(s.Diagnosis, s.Version))
	}
}

// Describe is a diagnosis as the report words it (spec §10).
func Describe(diagnosis string, version int) string {
	switch diagnosis {
	case "matches_retired":
		return fmt.Sprintf("matches retired v%d", version)
	case "no_known_key_matches":
		return "no known key matches"
	case "unadmitted_source":
		return "unadmitted source"
	case "not_tacacs":
		return "not TACACS+ (header invalid)"
	case "unencrypted_refused":
		return "unencrypted — refused"
	case "malformed_after_validation":
		return "malformed after validation"
	case "admission_refused":
		return "in inventory, admission refused"
	}
	return diagnosis
}

func ago(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}
```

- [ ] **Step 4: `cmd/port49/keys.go`:**

```go
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/blanketfish/port49/internal/config"
	"github.com/blanketfish/port49/internal/keystatus"
)

// keysCmd is `port49 keys` (spec §12): status and show read files and the
// log offline; diagnose asks port49d.
func keysCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		switch args[0] {
		case "status":
			return keysStatus(args[1:], stdout, stderr)
		case "show":
			return keysShow(args[1:], stdout, stderr)
		}
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// readKeySets reads port49d.yaml's keys: block, no secret included.
func readKeySets(path string) (map[string]config.KeySet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return config.KeySets(raw)
}

// keyRefsOf is the key_refs sets defines, sorted and never nil.
func keyRefsOf(sets map[string]config.KeySet) []string {
	out := make([]string, 0, len(sets))
	for ref := range sets {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// statusKeys is each key's versions in the roles they hold at now.
func statusKeys(sets map[string]config.KeySet, now time.Time) []keystatus.Key {
	var out []keystatus.Key
	for _, ref := range keyRefsOf(sets) {
		ks := sets[ref]
		k := keystatus.Key{Ref: ref, Versions: []keystatus.Version{{Number: ks.Current.Version, State: "current"}}}
		for _, v := range ks.Accept {
			state := "accept"
			if !v.RetireAt.IsZero() && !now.Before(v.RetireAt) {
				state = "retired"
			}
			k.Versions = append(k.Versions, keystatus.Version{Number: v.Version, State: state, RetireAt: v.RetireAt})
		}
		for _, v := range ks.Retired {
			k.Versions = append(k.Versions, keystatus.Version{Number: v.Version, State: "retired"})
		}
		out = append(out, k)
	}
	return out
}

// keysStatus is `port49 keys status` (spec §10, §12).
func keysStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 keys status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	cfgPath := fs.String("config", "", "port49d.yaml: key names, versions and retire_after dates; no secret is read")
	since := fs.Duration("since", 0, "read only the records within this long of the newest one (default: all)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || *cfgPath == "" || fs.NArg() == 0 || *since < 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	sets, err := readKeySets(*cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "port49 keys status:", err)
		return 1
	}
	p, err := files.loadWith(keyRefsOf(sets))
	if err != nil {
		fmt.Fprintln(stderr, "port49 keys status:", err)
		return 1
	}
	recs, unread, err := readLogs(fs.Args())
	if err != nil {
		fmt.Fprintln(stderr, "port49 keys status:", err)
		return 1
	}
	opt := keystatus.Options{Now: time.Now()}
	if *since > 0 && len(recs) > 0 {
		newest := recs[0].TS
		for _, r := range recs {
			if r.TS.After(newest) {
				newest = r.TS
			}
		}
		opt.From = newest.Add(-*since)
	}
	var devices []keystatus.Device
	for _, d := range p.Devices() {
		r, _ := p.Admitted(d.Name)
		devices = append(devices, keystatus.Device{Name: d.Name, KeyRef: r.KeyRef, Addresses: d.Addresses})
	}
	keystatus.Infer(recs, devices, statusKeys(sets, opt.Now), opt).Write(stdout, opt.Now)
	if unread > 0 {
		fmt.Fprintf(stderr, "port49 keys status: %d line(s) could not be read as records and were skipped\n", unread)
	}
	return 0
}

// keysShow is `port49 keys show` (spec §12): which key_ref a device matches,
// by which tier and group, and which version to provision. It never renders
// the secret.
func keysShow(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 keys show", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var files policyFiles
	files.register(fs)
	cfgPath := fs.String("config", "", "port49d.yaml, for the versions; no secret is read")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if files.missing() || fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var sets map[string]config.KeySet
	var refs []string
	if *cfgPath != "" {
		var err error
		if sets, err = readKeySets(*cfgPath); err != nil {
			fmt.Fprintln(stderr, "port49 keys show:", err)
			return 1
		}
		refs = keyRefsOf(sets)
	}
	p, err := files.loadWith(refs)
	if err != nil {
		fmt.Fprintln(stderr, "port49 keys show:", err)
		return 1
	}
	name := fs.Arg(0)
	r, ok := p.Admitted(name)
	if !ok {
		fmt.Fprintf(stderr, "port49 keys show: device %q is not in the inventory\n", name)
		return 1
	}
	if r.Refused != "" {
		fmt.Fprintf(stdout, "%s: refused admission: %s\n", name, r.Refused)
		return 1
	}
	as, _ := p.KeyAssignment(name)
	fmt.Fprintf(stdout, "%s: key_ref %s, by the %s tier (%s)\n", name, r.KeyRef, as.Tier, as.Group)
	if ks, ok := sets[r.KeyRef]; ok {
		fmt.Fprintf(stdout, "  provision version %d (current)\n", ks.Current.Version)
		for _, v := range ks.Accept {
			line := fmt.Sprintf("  also accepted: version %d", v.Version)
			if v.RetireAfter != "" {
				line += ", retire_after " + v.RetireAfter
			}
			fmt.Fprintln(stdout, line)
		}
	}
	fmt.Fprintln(stdout, "  the secret is not shown: rendering it is a separately authorized operation this build "+
		"does not offer (spec §12)")
	return 0
}
```

  In `cmd/port49/policy.go`, `policyFiles` gains:

```go
// loadWith is load with the key_refs port49d.yaml defines
// (policy.Env.KeyRefs), so a device assigned any other is refused as port49d
// refuses it.
func (f *policyFiles) loadWith(keyRefs []string) (*policy.Policy, error) {
	return bundle.Load(f.policy, f.inventory, policy.Env{KeyRefs: keyRefs})
}
```

  and `load` becomes `return f.loadWith(nil)`. In `cmd/port49/main.go`, add to `usage`:

```
  port49 keys status --policy FILE --inventory FILE --config PORT49D_YAML [--since DURATION] LOGFILE...|-
  port49 keys show --policy FILE --inventory FILE [--config PORT49D_YAML] DEVICE
```

  and to `run`'s switch: `case "keys": return keysCmd(args[1:], stdout, stderr)`.

- [ ] **Step 5: Run the tests, everything, and commit**

Run: `go test ./internal/keystatus/ ./cmd/port49/ -count=1 && make test && make vet && make build`
Expected: PASS.

```bash
git add internal/keystatus cmd/port49
git commit -m "feat(keys): port49 keys status reads a rotation from the log, and keys show says which key and why

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 16: `port49 keys diagnose`, over a local admin socket

**Files:**
- Create: `internal/keyring/held.go`, `internal/keyring/diagnose.go`
- Test: `internal/keyring/diagnose_test.go`
- Create: `internal/daemon/admin/admin.go`, `peer_linux.go`, `peer_other.go`
- Test: `internal/daemon/admin/admin_test.go`, `internal/daemon/admin/admin_linux_test.go`
- Modify: `internal/daemon/server/server.go`, `conn.go` (`Deps.Held`)
- Modify: `internal/config/config.go` (`admin_socket`)
- Modify: `cmd/port49d/main.go`, `cmd/port49/keys.go`, `cmd/port49/main.go`
- Test: `internal/daemon/server/server_test.go`

**Interfaces:**
- Consumes: `keyring.Set.State` (Task 14); `(*policy.Policy).Admitted` (Task 4).
- Produces:
  - `keyring.Held` with `Put(device string, src netip.Addr, h wire.Header, body []byte, at time.Time)`
    and `Get(device string) (HeldPacket, bool)`; `keyring.HeldPacket{Source netip.Addr; Header wire.Header; Body []byte; At time.Time}`.
  - `keyring.Match{KeyRef string; Version int; State string}`; `keyring.Finding{Device, Source string;
    HeldAt time.Time; Assigned string; Matches []Match}`; `func Diagnose(held *Held, sets map[string]Set,
    device, assigned string, now time.Time) (Finding, bool)`; `func (f Finding) Text(now time.Time) string`.
  - `admin.Request{Op, Device string}`, `admin.Response{Error, Text string; Finding *keyring.Finding}`,
    `admin.Server{Held; Keys; Assigned func(string) string; Now func() time.Time}`,
    `func admin.Listen(path string) (net.Listener, error)`, `func (s *Server) Serve(ctx, ln) error`.
  - `server.Deps.Held *keyring.Held`; `config.Config.AdminSocket string` (`admin_socket`).

- [ ] **Step 1: Write the failing tests.** Create `internal/keyring/diagnose_test.go`:

```go
package keyring

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

func heldUnder(t *testing.T, secret string) *Held {
	t.Helper()
	h := wire.Header{MajorVersion: 0xc, Type: wire.TypeAuthen, SeqNo: 1, SessionID: 7}
	body := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("u"), Data: []byte("x")}.Encode()
	h.Length = uint32(len(body))
	var held Held
	held.Put("leaf-19", netip.MustParseAddr("10.20.4.9"), h, wire.Obfuscate(h, []byte(secret), body),
		time.Date(2026, 9, 30, 11, 59, 30, 0, time.UTC))
	return &held
}

var sets = map[string]Set{
	"prod_key": {Ref: "prod_key", Versions: []Version{{Number: 3, Secret: []byte("new")}, {Number: 2, Secret: []byte("old"), Retired: true}}},
	"lab_key":  {Ref: "lab_key", Versions: []Version{{Number: 1, Secret: []byte("lab")}}},
}

// Spec §10: keys diagnose names the group and version that match, retired
// versions and other groups' material included, and says so plainly.
func TestDiagnoseNamesWhatTheDeviceHolds(t *testing.T) {
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	f, ok := Diagnose(heldUnder(t, "old"), sets, "leaf-19", "prod_key", now)
	if !ok || len(f.Matches) != 1 || f.Matches[0] != (Match{KeyRef: "prod_key", Version: 2, State: "retired"}) {
		t.Fatalf("%+v, %v", f, ok)
	}
	if s := f.Text(now); !strings.Contains(s, "packet held 30s ago") || !strings.Contains(s, "missed in the rotation") {
		t.Fatalf("%s", s)
	}
	f, _ = Diagnose(heldUnder(t, "lab"), sets, "leaf-19", "prod_key", now)
	if s := f.Text(now); !strings.Contains(s, "holds lab_key's key, another group's") {
		t.Fatalf("%s", s)
	}
	f, _ = Diagnose(heldUnder(t, "nothing"), sets, "leaf-19", "prod_key", now)
	if s := f.Text(now); !strings.Contains(s, "validates under nothing port49d holds") {
		t.Fatalf("%s", s)
	}
	if _, ok := Diagnose(heldUnder(t, "old"), sets, "spine-02", "prod_key", now); ok {
		t.Fatal("a device with no held packet was diagnosed")
	}
}
```

  Create `internal/daemon/admin/admin_test.go`:

```go
package admin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/keyring"
)

func TestAnswerRefusesAnUnknownOpAndAnUnheldDevice(t *testing.T) {
	s := &Server{Held: &keyring.Held{}, Keys: map[string]keyring.Set{}, Now: time.Now}
	if r := s.answer(Request{Op: "keys_show", Device: "x"}); !strings.Contains(r.Error, "unknown op") {
		t.Fatalf("%+v", r)
	}
	if r := s.answer(Request{Op: "keys_diagnose", Device: "x"}); !strings.Contains(r.Error, "holds no unvalidated packet") {
		t.Fatalf("%+v", r)
	}
}

func TestListenRefusesAPathThatIsNotASocket(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.sock")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("%v", err)
	}
}
```

  Create `internal/daemon/admin/admin_linux_test.go`:

```go
//go:build linux

package admin

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/keyring"
)

// The socket is 0600 and answers its owner (SO_PEERCRED, plan 6a owner
// decision 2).
func TestTheSocketIsPrivateAndAnswersItsOwner(t *testing.T) {
	p := filepath.Join(t.TempDir(), "port49d.sock")
	ln, err := Listen(p)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(p)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, %v", fi.Mode(), err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{Held: &keyring.Held{}, Keys: map[string]keyring.Set{}, Now: time.Now}
	go s.Serve(ctx, ln)
	c, err := net.Dial("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	json.NewEncoder(c).Encode(Request{Op: "keys_diagnose", Device: "leaf-19"})
	var r Response
	// The answer is the diagnosis's own ("holds no unvalidated packet"),
	// never "refused: ...": the peer check ran and let our uid through.
	if err := json.NewDecoder(c).Decode(&r); err != nil || !strings.Contains(r.Error, "holds no unvalidated packet") {
		t.Fatalf("%+v, %v", r, err)
	}
	if _, err := Listen(p); err == nil || !strings.Contains(err.Error(), "another process answers") {
		t.Fatalf("a second Listen on a live socket: %v", err)
	}
}
```

  Append to `internal/daemon/server/server_test.go`:

```go
// A packet no key an admitted device is assigned validates is held, as it
// arrived, for keys diagnose; it is never logged (spec §10).
func TestAnUnvalidatedPacketIsHeldForDiagnosis(t *testing.T) {
	log := &syncBuffer{}
	held := &keyring.Held{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) { d.Held = held })
	c := dial(t, ts.addr, []byte("some-other-key"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	if !waitFor(t, func() bool { _, ok := held.Get("leaf-01"); return ok }) {
		t.Fatal("nothing held")
	}
	p, _ := held.Get("leaf-01")
	if p.Source.String() != "127.0.0.1" || !keyring.Validates(p.Header, wire.Obfuscate(p.Header, []byte("some-other-key"), p.Body)) {
		t.Fatalf("%+v", p)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/keyring/ ./internal/daemon/admin/ ./internal/daemon/server/ -run 'Diagnose|Answer|Listen|Socket|Held' -count=1`
Expected: FAIL to compile — `undefined: Held`, `Diagnose`, package `admin` has no Go files.

- [ ] **Step 3: `internal/keyring/held.go` and `diagnose.go`:**

```go
package keyring

import (
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// Held keeps, per admitted device, the last packet no key it is assigned
// validated: the header and the body as it arrived, obfuscated. It is what
// `port49 keys diagnose` tries other material on, by hand (spec §10); nothing
// tries it automatically. It is in memory only and never logged — the body is
// attacker-controlled bytes — and one entry per device bounds it by the
// inventory.
type Held struct {
	mu sync.Mutex
	m  map[string]HeldPacket
}

// HeldPacket is one held packet.
type HeldPacket struct {
	Source netip.Addr
	Header wire.Header
	Body   []byte
	At     time.Time
}

// Put holds a copy of body as device's latest unvalidated packet.
func (h *Held) Put(device string, src netip.Addr, hdr wire.Header, body []byte, at time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.m == nil {
		h.m = map[string]HeldPacket{}
	}
	h.m[device] = HeldPacket{Source: src, Header: hdr, Body: slices.Clone(body), At: at}
}

// Get is device's held packet.
func (h *Held) Get(device string) (HeldPacket, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p, ok := h.m[device]
	return p, ok
}
```

```go
package keyring

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
)

// Match is one key version a held packet validates under.
type Match struct {
	KeyRef  string `json:"key_ref"`
	Version int    `json:"version"`
	State   string `json:"state"`
}

// Finding is what the trial found for one device.
type Finding struct {
	Device   string    `json:"device"`
	Source   string    `json:"source"`
	HeldAt   time.Time `json:"held_at"`
	Assigned string    `json:"assigned"`
	Matches  []Match   `json:"matches"`
}

// Diagnose tries every version of every set — retired ones and other groups'
// included — on device's held packet (spec §10, "Cross-group probing is
// manual"). false is no packet held for it.
func Diagnose(held *Held, sets map[string]Set, device, assigned string, now time.Time) (Finding, bool) {
	p, ok := held.Get(device)
	if !ok {
		return Finding{}, false
	}
	f := Finding{Device: device, Source: p.Source.String(), HeldAt: p.At, Assigned: assigned}
	refs := make([]string, 0, len(sets))
	for ref := range sets {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	for _, ref := range refs {
		s := sets[ref]
		for i, v := range s.Versions {
			if Validates(p.Header, wire.Obfuscate(p.Header, v.Secret, p.Body)) {
				f.Matches = append(f.Matches, Match{KeyRef: ref, Version: v.Number, State: s.State(i, now)})
			}
		}
	}
	return f, true
}

// Text is the finding in one line. It claims no cause the packet cannot
// support: nothing matching may be the device's key or port49d's material,
// and it says so (spec §10, "What this cannot distinguish").
func (f Finding) Text(now time.Time) string {
	head := fmt.Sprintf("%s (%s), packet held %s ago", f.Device, f.Source, now.Sub(f.HeldAt).Round(time.Second))
	if len(f.Matches) == 0 {
		return head + ": validates under nothing port49d holds; the device's key, or the secret port49d reads for " +
			f.Assigned + ", is wrong, and a packet cannot say which (spec §10)"
	}
	parts := make([]string, len(f.Matches))
	for i, m := range f.Matches {
		parts[i] = fmt.Sprintf("%s v%d (%s)", m.KeyRef, m.Version, m.State)
	}
	text := head + ": validates under " + strings.Join(parts, ", ") + "; it is assigned " + f.Assigned
	switch m := f.Matches[0]; {
	case m.KeyRef == f.Assigned && m.State == "retired":
		text += ": the device was missed in the rotation"
	case m.KeyRef != f.Assigned:
		text += fmt.Sprintf(": the device holds %s's key, another group's", m.KeyRef)
	}
	return text
}
```

- [ ] **Step 4: `internal/daemon/admin`:**

```go
// Package admin is port49d's local admin socket (plan 6a owner decision 2):
// a Unix socket, mode 0600, that answers only port49d's own uid and root,
// and serves one read-only operation, keys_diagnose (spec §10). It is off
// unless admin_socket is set.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/blanketfish/port49/internal/keyring"
)

// Request is one line a client sends.
type Request struct {
	Op     string `json:"op"`
	Device string `json:"device"`
}

// Response is the one line port49d answers.
type Response struct {
	Error   string           `json:"error,omitempty"`
	Text    string           `json:"text,omitempty"`
	Finding *keyring.Finding `json:"finding,omitempty"`
}

// Server answers the socket.
type Server struct {
	Held     *keyring.Held
	Keys     map[string]keyring.Set
	Assigned func(device string) string
	Now      func() time.Time
}

const maxRequest = 4096

// Listen opens the socket at path, mode 0600. A stale socket at path — one
// nothing answers on — is removed. A socket another process answers on, a
// second port49d sharing the path, is refused and left alone, and so is
// anything at path that is not a socket.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket; port49d will not remove it", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("another process answers on %s; give each port49d its own admin_socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// The peer check below is the control; the mode is the second fence.
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve answers until ctx ends.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(c)
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	enc := json.NewEncoder(c)
	if err := peerAllowed(c); err != nil {
		_ = enc.Encode(Response{Error: "refused: " + err.Error()})
		return
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(c, maxRequest)).Decode(&req); err != nil {
		_ = enc.Encode(Response{Error: "a request is one JSON object"})
		return
	}
	_ = enc.Encode(s.answer(req))
}

func (s *Server) answer(req Request) Response {
	if req.Op != "keys_diagnose" {
		return Response{Error: fmt.Sprintf("unknown op %q; the one op is keys_diagnose", req.Op)}
	}
	assigned := ""
	if s.Assigned != nil {
		assigned = s.Assigned(req.Device)
	}
	f, ok := keyring.Diagnose(s.Held, s.Keys, req.Device, assigned, s.Now())
	if !ok {
		return Response{Error: fmt.Sprintf("port49d holds no unvalidated packet from %q since it started", req.Device)}
	}
	return Response{Text: f.Text(s.Now()), Finding: &f}
}
```

  `peer_linux.go`:

```go
//go:build linux

package admin

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// peerAllowed answers port49d's own uid and root only (SO_PEERCRED).
func peerAllowed(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a Unix socket")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if cred.Uid != 0 && int(cred.Uid) != os.Geteuid() {
		return fmt.Errorf("uid %d is neither port49d's (%d) nor root", cred.Uid, os.Geteuid())
	}
	return nil
}
```

  `peer_other.go`:

```go
//go:build !linux

package admin

import (
	"errors"
	"net"
)

// peerAllowed refuses everyone where the caller's uid cannot be read.
func peerAllowed(net.Conn) error {
	return errors.New("admin_socket needs Linux: it checks the caller's uid (SO_PEERCRED)")
}
```

- [ ] **Step 5: The server, the config, port49d and the CLI.** `server.Deps` gains:

```go
	// Held keeps each admitted device's last unvalidated packet for `port49
	// keys diagnose` (spec §10); nil keeps nothing. port49d sets it only with
	// admin_socket configured.
	Held *keyring.Held
```

  In `conn.go`'s `deobfuscate`, in the branch where the first packet did not validate, before the
  `unvalidated` call:

```go
			if s.d.Held != nil {
				s.d.Held.Put(s.dev.Device.Name, s.src, h, obf, s.d.Now())
			}
```

  `fileConfig` and `Config` gain `AdminSocket string` (`yaml:"admin_socket"`) with the comment:
  "AdminSocket is where port49d answers `port49 keys diagnose` (plan 6a owner decision 2): a Unix
  socket, 0600, for port49d's user and root. Empty, the default, is off, and no packet is held."
  and `Load` copies it. In `cmd/port49d/main.go`, after the TACACS+ listener binds and with the same
  unwinding as the broker listener's:

```go
	if cfg.AdminSocket != "" {
		held := &keyring.Held{}
		deps.Held = held
		aln, err := admin.Listen(cfg.AdminSocket)
		if err != nil {
			if bln != nil {
				bln.Close()
			}
			ln.Close()
			mln.Close()
			stopSpool()
			<-spoolDone
			return fmt.Errorf("admin_socket %s: %w", cfg.AdminSocket, err)
		}
		srv := &admin.Server{Held: held, Keys: keys, Now: time.Now, Assigned: func(name string) string {
			if live == nil {
				return ""
			}
			r, _ := live.Load().Admitted(name)
			return r.KeyRef
		}}
		go srv.Serve(ctx, aln)
		fmt.Fprintf(stderr, "port49d: admin socket on %s (port49 keys diagnose)\n", cfg.AdminSocket)
	}
```

  Place the block after the broker listener binds, so `bln` exists to close (M6), and before
  `go func() { serveErr <- server.Serve(ctx, ln, deps) }()`, since `deps` is a value that call
  copies. In `cmd/port49/keys.go`,
  `keysCmd` gains `case "diagnose": return keysDiagnose(args[1:], stdout, stderr)`, and:

```go
// keysDiagnose is `port49 keys diagnose` (spec §10, §12): port49d tries every
// key it holds on the device's last unvalidated packet and names what matched.
func keysDiagnose(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 keys diagnose", flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "/run/port49/port49d.sock", "port49d's admin_socket")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	c, err := net.DialTimeout("unix", *socket, 5*time.Second)
	if err != nil {
		fmt.Fprintf(stderr, "port49 keys diagnose: %v (is admin_socket set in port49d.yaml, and are you port49d's "+
			"user or root?)\n", err)
		return 1
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(c).Encode(admin.Request{Op: "keys_diagnose", Device: fs.Arg(0)}); err != nil {
		fmt.Fprintln(stderr, "port49 keys diagnose:", err)
		return 1
	}
	var resp admin.Response
	if err := json.NewDecoder(c).Decode(&resp); err != nil {
		fmt.Fprintln(stderr, "port49 keys diagnose:", err)
		return 1
	}
	if resp.Error != "" {
		fmt.Fprintln(stderr, "port49 keys diagnose:", resp.Error)
		return 1
	}
	fmt.Fprintln(stdout, resp.Text)
	return 0
}
```

  and `usage` gains `  port49 keys diagnose [--socket PATH] DEVICE`.

- [ ] **Step 6: Run the tests, everything, and commit**

Run: `go test ./internal/keyring/ ./internal/daemon/... ./cmd/... -count=1 -race && make test && make vet && make build && GOOS=darwin go vet ./internal/daemon/admin/`
Expected: PASS; the last command proves `peer_other.go` builds.

```bash
git add internal cmd
git commit -m "feat(keys): port49 keys diagnose, over a 0600 admin socket that answers only port49d's uid and root

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 17: `policy test` fails on every refused device and an undefined key; `policy diff` on a newly refused one

**Files:**
- Modify: `cmd/port49/policy.go` (`policyTest`, `keyReports`, `policyDiff`)
- Test: `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `(*policy.Policy).AdmissionRefusals`, `KeyGroups` (Task 4); `admission.Resolved.Refusal`
  codes (Task 3); `readKeySets`, `keyRefsOf`, `policyFiles.loadWith` (Task 15).
- Consumes also: `bundle.NewlyRefused` (Task 7).
- Produces: `policy test` lines `admission: <device> (<platform>) refused: <cause>` (failing, for
  every refused device, where admission is assessed), `keys: <text>` (failing) and `report: key
  <ref> version <n> ...` (reported); a trailing `N admission refusal(s), M key fault(s)` line when
  either is non-zero; exit 1 on either. `policy diff` lines `REFUSED: admission: <device>
  (<platform>) is newly refused: <cause>`, failing (N1).

- [ ] **Step 1: Write the failing tests.** Append to `cmd/port49/policy_test.go`:

```go
// Spec §10, §12: CI fails on every device admission refuses — a key-group tie
// (owner decision 1), a device no group admits, and, given port49d.yaml, one
// assigned a key_ref it does not define — since port49d serves none of them;
// retire_after problems are reported.
func TestPolicyTestJudgesAdmissionAndKeys(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	base := strings.Replace(keysPolicy, "key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]",
		"key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}, {match: {attributes: {site: lab}}, key_ref: lab_key}]", 1)
	inv := write("inventory.yaml", `devices:
  - {name: leaf-01, platform: arista_eos, addresses: [10.20.0.7]}
  - {name: stray, platform: arista_eos, addresses: [192.0.2.9]}
`)
	var out, errOut bytes.Buffer
	if code := run([]string{"policy", "test", "--policy", write("p.yaml", base), "--inventory", inv}, &out, &errOut); code != 1 {
		t.Fatalf("a device in no group passed the gate: exit %d\n%s%s", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), "admission: stray (arista_eos) refused: matches no key group") {
		t.Fatalf("%s", out.String())
	}
	out.Reset()
	cfg := write("port49d.yaml", keysConfig)
	code := run([]string{"policy", "test", "--policy", write("p.yaml", base), "--inventory", inv, "--config", cfg}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "keys: key group attributes {site: lab} → lab_key names key_ref lab_key") {
		t.Fatalf("an undefined key_ref: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "report: key prod_key version 2: retire_after 2026-10-01") &&
		!strings.Contains(out.String(), "report: key prod_key version 2 retires after 2026-10-01") {
		t.Fatalf("the date is not reported: %s", out.String())
	}
}
```

  and:

```go
// I3: a test on a device the inventory no longer has fails CI, where the
// load that port49d would make succeeds.
func TestPolicyTestFailsATestOnAnAbsentDevice(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.Join(dir, "p.yaml")
	inv := filepath.Join(dir, "i.yaml")
	body := keysPolicy + "tests: [{subject: s, device: leaf-gone, command: \"show version\", expect: permit}]\n"
	if err := os.WriteFile(pol, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inv, []byte(keysInventory), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "test", "--policy", pol, "--inventory", inv}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String()+errOut.String(), `device "leaf-gone" is not in the inventory`) {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
}
```

  (`keysPolicy`, `keysInventory` and `keysConfig` are `keys_test.go`'s.) The absent device reaches
  `policyTest` through `RunTests`' `Err` (Task 4), which the existing `r.Err != nil` branch
  (`cmd/port49/policy.go:227`) prints and counts as a failure: no new code here.

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./cmd/port49/ -run 'TestPolicyTestJudgesAdmissionAndKeys|TestPolicyTestFailsATestOnAnAbsentDevice' -count=1`
Expected: FAIL — `flag provided but not defined: -config`, and no `admission: stray` line.

- [ ] **Step 3: Implement.** In `policyTest`, register `cfgPath := fs.String("config", "",
  "port49d.yaml, for the key checks CI owes (spec §10); no secret is read")`, and load:

```go
	var sets map[string]config.KeySet
	var refs []string
	if *cfgPath != "" {
		var err error
		if sets, err = readKeySets(*cfgPath); err != nil {
			fmt.Fprintln(stderr, "port49 policy test:", err)
			return 1
		}
		refs = keyRefsOf(sets)
	}
	p, err := files.loadWith(refs)
```

  After the quarantine lines:

```go
	// Admission (spec §10). Every refused device fails the gate — a tie
	// (plan 6a owner decision 1), a device no group admits, and a key_ref
	// port49d.yaml defines no key for — since port49d serves none of them and
	// a policy edit that refuses the fleet must not pass CI (N1). A device in
	// an unexpected range is removed from the inventory, or given a group, in
	// review. A policy with no key groups, loaded with no --config, has
	// nothing to say here.
	admissionFails := 0
	if p.AdmissionAssessed() {
		for _, r := range p.AdmissionRefusals() {
			admissionFails++
			fmt.Fprintf(stdout, "admission: %s (%s) refused: %s\n", r.Device.Name, r.Device.Platform, r.Refused)
		}
	}
	keyFaults := 0
	for _, line := range keyReports(sets, p, now) {
		if strings.HasPrefix(line, "keys: ") {
			keyFaults++
		}
		fmt.Fprintln(stdout, line)
	}
```

  and before the final exit:

```go
	if admissionFails+keyFaults > 0 {
		fmt.Fprintf(stdout, "%d admission refusal(s), %d key fault(s)\n", admissionFails, keyFaults)
	}
	if failed > 0 || unacknowledged > 0 || quarantined > 0 || refused > 0 || admissionFails > 0 || keyFaults > 0 {
		return 1
	}
```

  Add:

```go
// keyReports are the key checks CI owes (spec §10, "Retirement is enforced"):
// a key group naming a key_ref port49d.yaml does not define fails, and an
// accept version past its retire_after, or with none, is reported. With no
// port49d.yaml there is nothing to check.
func keyReports(sets map[string]config.KeySet, p *policy.Policy, now time.Time) []string {
	if sets == nil {
		return nil
	}
	var out []string
	for _, g := range p.KeyGroups() {
		if _, ok := sets[g.KeyRef]; !ok {
			out = append(out, fmt.Sprintf("keys: key group %s names key_ref %s, which port49d.yaml does not define; "+
				"every device it matches fails closed", g, g.KeyRef))
		}
	}
	for _, ref := range keyRefsOf(sets) {
		for _, v := range sets[ref].Accept {
			switch {
			case v.RetireAt.IsZero():
				out = append(out, fmt.Sprintf("report: key %s version %d has no retire_after; an indefinitely accepted "+
					"version is what rotation exists to prevent", ref, v.Version))
			case !now.Before(v.RetireAt):
				out = append(out, fmt.Sprintf("report: key %s version %d: retire_after %s has passed; it admits no "+
					"device", ref, v.Version, v.RetireAfter))
			default:
				out = append(out, fmt.Sprintf("report: key %s version %d: retire_after %s", ref, v.Version, v.RetireAfter))
			}
		}
	}
	return out
}
```

  Update `policyTest`'s doc comment to name the two new failures and `--config`, and `usage`'s
  line to `port49 policy test --policy FILE --inventory FILE [--config PORT49D_YAML]`.

  **`policy diff` fails on a device the new policy refuses and the old admitted (N1).** In
  `policyDiff`, after `out.learn(before, after)`:

```go
	// A key_groups edit that refuses devices the old policy admitted is the
	// edit port49d's reload bound catches (bundle.CheckAdmission): CI fails
	// it first, naming each.
	newlyRefused := bundle.NewlyRefused(before, after)
	for _, r := range newlyRefused {
		fmt.Fprintf(stdout, "REFUSED: admission: %s (%s) is newly refused: %s\n", r.Device.Name, r.Device.Platform,
			r.Refused)
	}
```

  and add `|| len(newlyRefused) > 0` to its final failure condition (`policy.go:525`), and
  `%d devices newly refused admission` with `len(newlyRefused)` to its summary line. Add:

```go
func TestPolicyDiffFailsOnADeviceTheNewPolicyRefuses(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	old := write("old.yaml", keysPolicy)
	typo := write("new.yaml", strings.Replace(keysPolicy, "cidr: 10.0.0.0/8", "cidr: 11.0.0.0/8", 1))
	inv := write("inventory.yaml", keysInventory)
	var out, errOut bytes.Buffer
	code := run([]string{"policy", "diff", "--old", old, "--new", typo, "--inventory", inv}, &out, &errOut)
	if code != 1 || !strings.Contains(out.String(), "REFUSED: admission: leaf-01 (arista_eos) is newly refused") {
		t.Fatalf("exit %d:\n%s%s", code, out.String(), errOut.String())
	}
}
```

- [ ] **Step 4: Run the tests, everything, and commit**

Run: `go test ./cmd/port49/ -count=1 && make test && make vet`
Expected: PASS; the existing `policy test` tests are unchanged, since their inventories either
carry no key groups or admit every device.

```bash
git add cmd/port49
git commit -m "feat(policy): policy test fails on a key-group tie and an undefined key, and reports retire_after

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 18: `port49 inventory diff`

**Files:**
- Create: `cmd/port49/inventory.go`
- Modify: `cmd/port49/main.go`
- Test: `cmd/port49/inventory_test.go`

**Interfaces:**
- Consumes: `bundle.Load`, `bundle.Diff`, `bundle.Check`, `bundle.Change` (Tasks 6, 7).
- Produces: `port49 inventory diff --policy FILE [--new-policy FILE] [--max-removed-percent N]
  OLD_INVENTORY NEW_INVENTORY`: exit 0, or 1 when port49d would refuse the new inventory.

- [ ] **Step 1: Write the failing test.** Create `cmd/port49/inventory_test.go`:

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const diffPolicy = `
scopes:
  - {name: all_devices, match: {}}
  - {name: campus, match: {site: campus}, security_log: true}
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: s, scope: campus, roles: [r]}]
key_groups: [{match: {cidr: 10.0.0.0/8}, key_ref: prod_key}]
`

// Spec §10, §12: the review artifact for an inventory change, the security
// lines marked, and an exit that says whether port49d would take it.
func TestInventoryDiff(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pol := write("policy.yaml", diffPolicy)
	old := write("old.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1], attributes: {site: dc1}}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	new := write("new.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1, 10.66.0.1], attributes: {site: campus}}\n"+
		"  - {name: leaf-02, platform: arista_eos, addresses: [10.0.1.2]}\n")
	var out, errOut bytes.Buffer
	if code := run([]string{"inventory", "diff", "--policy", pol, old, new}, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s%s", code, out.String(), errOut.String())
	}
	for _, want := range []string{"+0 device(s), -0, 1 changed", "! address added leaf-01: 10.66.0.1",
		"! scope campus (security_log): leaf-01 joined"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
	half := write("half.yaml", "devices:\n  - {name: leaf-01, platform: arista_eos, addresses: [10.0.1.1]}\n")
	out.Reset()
	if code := run([]string{"inventory", "diff", "--policy", pol, old, half}, &out, &errOut); code != 1 ||
		!strings.Contains(out.String(), "refused: the new inventory removes 1 of 2 devices") {
		t.Fatalf("exit %d:\n%s", code, out.String())
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./cmd/port49/ -run TestInventoryDiff -count=1`
Expected: FAIL — exit 2 (usage).

- [ ] **Step 3: Implement.** `cmd/port49/inventory.go`:

```go
package main

import (
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/blanketfish/port49/internal/bundle"
	"github.com/blanketfish/port49/internal/policy"
)

func inventoryCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "diff" {
		return inventoryDiff(args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, usage)
	return 2
}

// inventoryDiff is `port49 inventory diff` (spec §10, §12): what a change to
// the inventory does to the bundle — devices, addresses, keys, admission and
// scope membership, the security lines marked `!` — and whether port49d
// would load it.
func inventoryDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("port49 inventory diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	polPath := fs.String("policy", "", "the policy the old inventory is loaded against")
	newPol := fs.String("new-policy", "", "the policy the new one is loaded against (default: --policy)")
	maxRemoved := fs.Int("max-removed-percent", 10, "port49d.yaml's inventory.max_removed_percent")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *polPath == "" || fs.NArg() != 2 || *maxRemoved < 0 || *maxRemoved > 100 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	if *newPol == "" {
		*newPol = *polPath
	}
	old, err := bundle.Load(*polPath, fs.Arg(0), policy.Env{})
	if err != nil {
		fmt.Fprintln(stderr, "port49 inventory diff: the old inventory:", err)
		return 1
	}
	new, err := bundle.Load(*newPol, fs.Arg(1), policy.Env{})
	if err != nil {
		fmt.Fprintf(stdout, "refused: port49d would not load the new inventory: %v\n", err)
		return 1
	}
	rep := bundle.Diff(old, new, time.Now())
	fmt.Fprintln(stdout, rep.Summary())
	for _, c := range rep.Changes {
		fmt.Fprintln(stdout, changeLine(c))
	}
	if err := bundle.Check(old, new, *maxRemoved); err != nil {
		fmt.Fprintf(stdout, "refused: %v\n", err)
		return 1
	}
	return 0
}

// changeLine is one change, `!` first where the log would carry it as a
// security event.
func changeLine(c bundle.Change) string {
	mark := " "
	if c.Security {
		mark = "!"
	}
	switch c.Kind {
	case bundle.DeviceAdded:
		return fmt.Sprintf("+ device %s (%s): %s", c.Device, c.Platform, c.To)
	case bundle.DeviceRemoved:
		return fmt.Sprintf("- device %s (%s)", c.Device, c.Platform)
	case bundle.AddressAdded:
		return fmt.Sprintf("%s address added %s: %s", mark, c.Device, c.Address)
	case bundle.AddressRemoved:
		return fmt.Sprintf("%s address removed %s: %s", mark, c.Device, c.Address)
	case bundle.ScopeJoined, bundle.ScopeLeft:
		verb, tag := "joined", ""
		if c.Kind == bundle.ScopeLeft {
			verb = "left"
		}
		if c.Security {
			tag = " (security_log)"
		}
		return fmt.Sprintf("%s scope %s%s: %s %s", mark, c.Scope, tag, c.Device, verb)
	}
	return fmt.Sprintf("%s %s %s: %s → %s", mark, c.Kind, c.Device, c.From, c.To)
}
```

  In `main.go`: `usage` gains `  port49 inventory diff --policy FILE [--new-policy FILE]
  [--max-removed-percent N] OLD_INVENTORY NEW_INVENTORY`, and `run` gains `case "inventory": return
  inventoryCmd(args[1:], stdout, stderr)`.

- [ ] **Step 4: Run the tests, everything, and commit**

Run: `go test ./cmd/port49/ -count=1 && make test && make vet && make build`
Expected: PASS.

```bash
git add cmd/port49
git commit -m "feat(inventory): port49 inventory diff, the review artifact for an inventory change

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 19: `port49 policy replay` verifies a redacted blob from the policy and inventory files

**Files:**
- Modify: `internal/replay/replay.go` (`Source`, `ReplayWith`, `program.at`, `withVerbatim`)
- Modify: `cmd/port49/policy.go` (`policyReplay`, `blobSource`), `cmd/port49/main.go` (usage)
- Test: `internal/replay/replay_test.go`, `cmd/port49/policy_test.go`

**Interfaces:**
- Consumes: `(*policy.Policy).Resolve`, `Device`, `Bundle` (Tasks 4, 6); `engine.Encode`, `Decode`, `Compile`.
- Produces: `type replay.Source func(rec decision.Record, compiledAt time.Time) ([]byte, bool)`;
  `func replay.ReplayWith(r io.Reader, only int, src Source) ([]Result, error)`; `Replay(r, only)` is
  `ReplayWith(r, only, nil)`. `port49 policy replay [--line N] [--policy FILE --inventory FILE]
  LOGFILE|-`.

- [ ] **Step 1: Write the failing test.** Append to `internal/replay/replay_test.go`:

```go
// Plan 5a's debt (spec §5.8): a redacted blob event leaves its records
// unverifiable from the log; a Source that supplies the verbatim blob, checked
// against the hash the record names, makes them verifiable again, and a
// Source that supplies the wrong bytes changes nothing.
func TestAVerbatimBlobFromOutsideTheLogReplaysARedactedBlobsRecords(t *testing.T) {
	log, _ := daemonLog(t)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	var rec decision.Record
	if err := rec.UnmarshalJSON([]byte(lines[0])); err != nil {
		t.Fatal(err)
	}
	verbatim := append([]byte(nil), rec.Blob.Body...)
	rec.Blob.Body = []byte(strings.Replace(string(rec.Blob.Body), "tftp", platform.Redacted, 1))
	rec.Blob.Redacted = true
	edited, _ := json.Marshal(rec)
	lines[0] = string(edited)
	redacted := strings.Join(lines, "\n")
	for _, c := range []struct {
		name string
		body []byte
		want Status
	}{{"verbatim", verbatim, Agree}, {"wrong", []byte(`{"version":1}`), Unverifiable}} {
		src := func(decision.Record, time.Time) ([]byte, bool) { return c.body, true }
		res, err := ReplayWith(strings.NewReader(redacted), 0, src)
		if err != nil {
			t.Fatal(err)
		}
		// daemonLog's last record, carol's, was decided before any policy
		// ran and is not_replayed whatever the source: it is left out.
		judged := 0
		for _, r := range res[:len(res)-1] {
			if r.Event == decision.EventBlob {
				continue
			}
			judged++
			if r.Status != c.want {
				t.Fatalf("%s: %+v", c.name, r)
			}
		}
		if judged < 5 {
			t.Fatalf("%s: only %d records judged; daemonLog writes five that consult the blob", c.name, judged)
		}
	}
}
```

- [ ] **Step 2: Run it to see it fail**

Run: `go test ./internal/replay/ -run TestAVerbatimBlob -count=1`
Expected: FAIL — `undefined: ReplayWith`.

- [ ] **Step 3: Implement in `replay.go`.** Add:

```go
// Source supplies a blob verbatim from outside the log (spec §5.7, §5.8):
// for a record naming a blob whose event was redacted, and the time that
// blob was compiled (its event's ts), the exact bytes, or false. Replay uses
// them only when they hash to the name the record carries.
type Source func(rec decision.Record, compiledAt time.Time) ([]byte, bool)
```

  Rename `Replay`'s body into `ReplayWith(r io.Reader, only int, src Source) ([]Result, error)`,
  whose `replayer` literal also sets `source: src, verbatim: map[string]*program{}`, and make
  `Replay` call `ReplayWith(r, only, nil)`. `replayer` gains `source Source` and `verbatim
  map[string]*program`; `program` gains `at time.Time`; `blob` takes the event's time —
  `func (rp *replayer) blob(n int, hash string, body []byte, redacted bool, at time.Time)` — sets
  `p := &program{redacted: redacted, at: at}`, and its caller in `read` passes `rec.TS`. `judge`
  becomes:

```go
func (rp *replayer) judge(nr numbered, p *program) {
	status, detail := one(nr.rec, rp.withVerbatim(nr.rec, p))
	rp.emit(nr, status, detail)
}

// withVerbatim is p, or, where p's blob event was redacted and a Source is
// set, the program compiled from the verbatim blob the Source gives for this
// record, checked against the hash the record names. A Source that cannot
// give it, or gives other bytes, leaves p, and the record stays unverifiable.
func (rp *replayer) withVerbatim(rec decision.Record, p *program) *program {
	if !p.redacted || rp.source == nil || rec.Policy == nil {
		return p
	}
	hash := rec.Policy.Blob
	if v, ok := rp.verbatim[hash]; ok {
		return v
	}
	body, ok := rp.source(rec, p.at)
	if !ok {
		return p
	}
	b, err := engine.Decode(hash, body)
	if err != nil {
		return p
	}
	prog, err := engine.Compile(b)
	if err != nil {
		return p
	}
	v := &program{blob: b, prog: prog, at: p.at}
	rp.verbatim[hash] = v
	return v
}
```

  (import `time`). In `cmd/port49/policy.go`, `policyReplay` registers the files — `var files
  policyFiles; files.register(fs)` — refuses one without the other with the usage, and:

```go
	var src replay.Source
	if files.policy != "" || files.inventory != "" {
		if files.missing() {
			fmt.Fprint(stderr, usage)
			return 2
		}
		p, err := files.load()
		if err != nil {
			fmt.Fprintln(stderr, "port49 policy replay:", err)
			return 1
		}
		src = blobSource(p)
	}
	results, err := replay.ReplayWith(in, *only, src)
```

  with:

```go
// blobSource recompiles a record's blob from the policy and inventory files,
// for the record's principal on its device at the time the blob was compiled
// (spec §5.8). It gives nothing where the files name another bundle: the blob
// is then not the one the record was decided by.
func blobSource(p *policy.Policy) replay.Source {
	return func(rec decision.Record, at time.Time) ([]byte, bool) {
		if rec.Policy == nil || rec.Policy.Bundle != p.Bundle || rec.Device == nil {
			return nil, false
		}
		d, ok := p.Device(rec.Device.Name)
		if !ok {
			return nil, false
		}
		res, err := p.Resolve(rec.Principal, d, at)
		if err != nil {
			return nil, false
		}
		body, _, err := engine.Encode(res.Blob)
		if err != nil {
			return nil, false
		}
		return body, true
	}
}
```

  `usage`'s replay line becomes `port49 policy replay [--line N] [--policy FILE --inventory FILE] LOGFILE|-`.

- [ ] **Step 4: A CLI test.** Append to `cmd/port49/policy_test.go`:

```go
func TestPolicyReplayTakesBothFilesOrNeither(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"policy", "replay", "--policy", "p.yaml", "-"}, &out, &errOut); code != 2 {
		t.Fatalf("one file exits %d", code)
	}
}
```

- [ ] **Step 5: Run the tests, everything, and commit**

Run: `go test ./internal/replay/ ./cmd/port49/ -count=1 && make test && make vet && make build`
Expected: PASS; `TestARedactedBlobEventLeavesItsRecordsUnverifiable` still passes (no Source).

```bash
git add internal/replay cmd/port49
git commit -m "feat(replay): verify a redacted blob's records against the blob recompiled from the files

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 20: (lab, on beehive) What a device does on a key miss, and a rotation end to end: L28

**Files:**
- Create: `tests/lab/l28_test.go`, `tests/lab/l28/policy.yaml`
- Create: `tests/lab/results/L28-<platform>.md` (written by the runs)
- Modify (branch H only): `internal/daemon/limits/limits.go`, `internal/daemon/server/server.go`,
  `conn.go`, `internal/daemon/metrics/metrics.go`

**Interfaces:**
- Consumes: `retire_after` (Task 14), `device.key_version` (Task 8), `port49 keys status` (Task 15),
  the harness's `derivedConfig`-style derivation, `startDaemonWith`, `stopDaemon`, `dial`,
  `loginWithin`, `nextLogin`, `mark`, `recordsSince`, `withAdminCLI`, `carriedConfigure`,
  `junosConfigureAdmin`, `result`.
- Produces: `TestL28KeyMiss`; one note per platform; on branch H, `(*limits.Limiter).Holding`.

- [ ] **Step 1: The minimal policy `keys status` reads.** `tests/lab/l28/policy.yaml` (no key groups:
  the lab inventory's apply, with the notice):

```yaml
# L28's policy for `port49 keys status` only: port49d runs the lab without a
# broker, so nothing mints from it.
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: readonly, permit: [show **]}]
subjects: [{name: s, identity: ["user:l28@example.com"], username: l28, token_ttl: 60s}]
grants: [{subject: s, scope: all_devices, roles: [r]}]
```

- [ ] **Step 2: The test.** `tests/lab/l28_test.go`:

```go
//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// L28 (spec §15): what a device does when port49d cannot validate its key,
// with port49d as built — it reads the body, records it, holds the
// connection for the per-source backoff and closes it without a reply — and
// a rotation end to end. Each phase restarts port49d on the lab config with
// its keys block replaced; the device keeps the lab key throughout until the
// rotation phase gives it the new one.
func TestL28KeyMiss(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		stop := l.capture(t, "L28")
		defer stop()
		if os.Getenv("PORT49_L28_NEW_KEY") == "" {
			t.Setenv("PORT49_L28_NEW_KEY", "l28-rotated-lab-key")
		}
		var obs strings.Builder
		for _, ph := range []struct{ name, keys, expect string }{
			{"unknown", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n", "no_known_key_matches"},
			{"retired", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n" +
				"    retired: [{version: 1, secret_env: PORT49_LAB_KEY}]\n", "matches_retired"},
			{"accepted", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n" +
				"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]\n", ""},
		} {
			obs.WriteString(l.l28Phase(t, ph.name, ph.keys, ph.expect))
		}
		obs.WriteString(l.l28Rotate(t))
		l.result(t, "L28", l28Claim, obs.String())
	})
}

const l28Claim = "What a device does when port49d cannot validate its key (unknown, and retired), and that a " +
	"second accepted version and then the device's own key change carry it through a rotation (spec §15 L28)."

// l28Anchor is the standing config's keys block, which each phase replaces.
const l28Anchor = "  lab_key:\n    current: {version: 1, secret_env: PORT49_LAB_KEY}\n"

func (l *lab) l28Config(t *testing.T, name, keys string) string {
	t.Helper()
	base, err := l.configPath()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), l28Anchor) {
		t.Fatalf("%s has no standing lab_key block; the key phases cannot be derived", base)
	}
	path := filepath.Join(root, "tests", "lab", "logs", "port49d-lab-"+l.p.name+"-l28-"+name+".yaml")
	if err := os.WriteFile(path, []byte(strings.Replace(string(raw), l28Anchor, keys, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func (l *lab) l28Restart(t *testing.T, cfg string) {
	t.Helper()
	if err := l.stopDaemon(); err != nil {
		t.Fatalf("stopping port49d: %v", err)
	}
	if err := l.startDaemonWith(cfg, true); err != nil {
		t.Fatalf("starting port49d on %s: %v", cfg, err)
	}
}

// l28Phase times a break-glass login, three commands in a break-glass
// session, and a token login, under one keys block, and reads what the log
// recorded for them.
func (l *lab) l28Phase(t *testing.T, name, keys, expect string) string {
	t.Helper()
	l.l28Restart(t, l.l28Config(t, name, keys))
	off := l.mark()
	t0 := time.Now()
	cl, bgErr := l.dial(breakglassUser, breakglassPassword, 120*time.Second)
	bgTook := time.Since(t0)
	bg := "logged in"
	if bgErr != nil {
		bg = "refused: " + bgErr.Error()
	} else {
		cl.Close()
	}
	t1 := time.Now()
	_, cmdErr := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version", "show version", "show version")
	cmdTook := time.Since(t1)
	cmd := "ran"
	if cmdErr != nil {
		cmd = "not observed: " + cmdErr.Error()
	}
	user, secret := l.nextLogin(t)
	t2 := time.Now()
	tc, tokErr := l.dial(user, secret, 120*time.Second)
	tokTook := time.Since(t2)
	tok := "logged in"
	if tokErr != nil {
		tok = "refused: " + tokErr.Error()
	} else {
		tc.Close()
	}
	recs := l.drainRecords(off, 10*time.Second)
	diags, versions := map[string]int{}, map[string]int{}
	for _, r := range recs {
		if u := sub(r, "unvalidated"); u != nil {
			diags[str(u, "diagnosis")]++
		}
		if d := sub(r, "device"); d != nil {
			if v, ok := d["key_version"].(float64); ok {
				versions[fmt.Sprintf("v%d", int(v))]++
			}
		}
	}
	if expect != "" && diags[expect] == 0 {
		t.Errorf("phase %s: no %s record reached the log: %v", name, expect, diags)
	}
	return fmt.Sprintf("### Phase: %s\n\n```yaml\n%s```\n\n| step | outcome | took |\n|---|---|---|\n"+
		"| break-glass login | %s | %s |\n| break-glass login plus three `show version` | %s | %s |\n"+
		"| token login (`%s`) | %s | %s |\n\nUnvalidated records by diagnosis: %v. Validated records by key "+
		"version: %v.\n\n", name, keys, bg, bgTook.Round(10*time.Millisecond), cmd, cmdTook.Round(10*time.Millisecond),
		user, tok, tokTook.Round(10*time.Millisecond), diags, versions)
}

// l28Rotate gives the device the new key while port49d accepts both, logs in
// with a token, and runs `port49 keys status` over the log.
func (l *lab) l28Rotate(t *testing.T) string {
	t.Helper()
	newKey := os.Getenv("PORT49_L28_NEW_KEY")
	var lines []string
	switch {
	case strings.HasPrefix(l.p.name, "juniper_"):
		l.junosConfigureAdmin(t, []string{"set system tacplus-server 172.100.100.1 secret \"" + newKey + "\""})
	case l.p.name == "cisco_iosxe":
		lines = []string{"tacacs server port49-host", "key 0 " + newKey}
	default:
		lines = []string{"tacacs-server host 172.100.100.1 key 0 " + newKey}
	}
	if lines != nil {
		l.carriedConfigure(t, lines...)
	}
	accepted := l.l28Config(t, "accepted", "  lab_key:\n    current: {version: 2, secret_env: PORT49_L28_NEW_KEY}\n"+
		"    accept: [{version: 1, secret_env: PORT49_LAB_KEY, retire_after: 2999-12-31}]\n")
	l.l28Restart(t, accepted)
	off := l.mark()
	user, secret := l.nextLogin(t)
	tc, err := l.dial(user, secret, 120*time.Second)
	tok := "logged in"
	if err != nil {
		tok = "refused: " + err.Error()
	} else {
		tc.Close()
	}
	recs := l.drainRecords(off, 10*time.Second)
	v2 := 0
	for _, r := range recs {
		if d := sub(r, "device"); d != nil && d["key_version"] == float64(2) {
			v2++
		}
	}
	status, _ := exec.Command(filepath.Join(root, "bin", "port49"), "keys", "status",
		"--policy", filepath.Join(root, "tests", "lab", "l28", "policy.yaml"),
		"--inventory", filepath.Join(root, "tests", "lab", "inventory-lab.yaml"),
		"--config", accepted, l.logPath).CombinedOutput()
	return fmt.Sprintf("### Rotation: the device given the new key\n\nToken login (`%s`) after the device's key "+
		"changed, with port49d accepting v1 and v2: %s; %d record(s) carried `key_version` 2.\n\n"+
		"`port49 keys status` over the run's log:\n\n```\n%s```\n", user, tok, v2, status)
}
```

  Destroying the topology after the run discards the device's key change (plan 5b, "Running the
  lab"). `labcreds.RedactNote` redacts the lab key where a transcript would carry it; the note
  carries no key value of its own.

- [ ] **Step 3: Run it, one platform per run.** For each of `eos`, `nxos`, `iosxe`, `vjunos`, with the
  watchdog:

```bash
make build
PORT49_LAB_PLATFORMS=eos go test -tags lab ./tests/lab/ -run '^TestL28KeyMiss$' -count=1 -v -timeout 90m \
  > tests/lab/logs/l28-eos.log 2>&1 &
echo $! > tests/lab/logs/l28-eos.pid
```

  Expected per platform: a note `tests/lab/results/L28-<platform>.md`; in phases `unknown` and
  `retired`, `no_known_key_matches` and `matches_retired` records, and no validated record; in
  `accepted`, validated records at `v1`; after the rotation, records at `v2` and `keys status`
  showing the device on v2. A phase whose expected record is absent fails the run: rerun it, and
  never commit a note from a failed run.

- [ ] **Step 4: Read the notes against quarantine's, and pick the branch.** For each platform,
  compare the `unknown` and `retired` phases' break-glass times with the same platform's quarantine
  close (`tests/lab/results/quarantine-<platform>.md`), where a closed connection cost what a
  refused one does.
  - **Branch K (keep):** on every platform, the break-glass login and its commands took no more
    than 4 s longer than under the quarantine close. The hold costs the device nothing an operator
    would feel; nothing changes. Say so in the notes.
  - **Branch H (the hold stalls):** on any platform, either took more than 4 s longer. A device
    missed in a rotation is then a silent server for the backoff's length at every attempt. Apply
    Step 5.

- [ ] **Step 5: (branch H only) Close a key miss at once, and refuse a held source at Accept.**
  Write the failing test in `internal/daemon/server/server_test.go`:

```go
// L28 branch H: a key miss from an admitted device is closed at once, and a
// source inside its backoff is refused at Accept rather than held silent,
// so a device missed in a rotation falls to its local method without
// waiting (tests/lab/results/L28-*.md).
func TestAKeyMissIsClosedAtOnceAndAHeldSourceRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) { d.Limits = slowBackoff() })
	c := dial(t, ts.addr, []byte("wrong"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	closedAtOnce(t, c)
	c = dial(t, ts.addr, []byte("k2"))
	closedAtOnce(t, c)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 1 {
		t.Fatalf("held_refused = %v", n)
	}
}
```

  Then in `internal/daemon/limits/limits.go`:

```go
// Holding reports whether src is inside the backoff its last strike earned:
// port49d refuses such a source at Accept, at once, rather than hold one of
// its connections silent (L28 branch H).
func (l *Limiter) Holding(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, ok := l.bad[src]
	if !ok || f.count == 0 {
		return false
	}
	return l.now().Before(f.last.Add(backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, f.count)))
}
```

  In `server.go`'s `Serve`, after `release, ok := d.Limits.Acquire(src)` succeeds:

```go
		if d.Limits.Holding(src) {
			release()
			d.Metrics.ConnectionEvents.WithLabelValues("held_refused").Inc()
			c.Close()
			continue
		}
```

  `Holding` refuses a source inside the backoff its last strike earned, whatever the strike: a key
  miss, and equally `malformed_after_validation`, `not_tacacs` or an unadmitted source's (M10).
  The L28 note and the operator-facing notes say so: on branch H, any source that struck is refused
  at Accept for its backoff, so it never holds a connection silent. And in `conn.go`'s
  `deobfuscate`, the first-packet miss strikes and closes instead of holding:

```go
		if r.Diagnosis != keyring.DiagValidated {
			// A retired version identifies the sender in the record and nothing
			// more: no admission, no reply. The strike is counted, and the next
			// connection inside its backoff is refused at Accept; this one is
			// closed at once, never held silent (L28 branch H).
			s.unvalidated(h, obf, r.Diagnosis, r.Version)
			s.d.Limits.Malformed(s.src)
			s.d.Metrics.ConnectionEvents.WithLabelValues("key_miss_closed").Inc()
			return nil, false
		}
```

  Name `held_refused` and `key_miss_closed` in the `ConnectionEvents` comment in `metrics.go`. Run
  `go test ./internal/daemon/... -count=1 && make test && make vet && make fuzz`, rerun L28 on the
  platform that stalled to confirm the times now match its quarantine close, and commit the code
  as `fix(server): close a key miss at once and refuse a held source at Accept (L28)`.

- [ ] **Step 6: Evidence and commit**

```bash
make evidence
git add tests/lab/l28_test.go tests/lab/l28 tests/lab/results/L28-*.md tests/lab/evidence/L28-*
git commit -m "test(lab): what a device does on a key miss, and a rotation end to end (L28)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 21: Close what the lab measured, and write plan 6a as built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L27, L28; §10 where L28 decides)
- Modify: `docs/design/2026-08-21-port49-design.md` (§12's key-miss sentences)
- Modify: `docs/superpowers/plans/README.md`

- [ ] **Step 1: L27.** For each product, if both of its versions' fixtures and note exist and the
  unit test passes, the product's cells are measured. The row closes only when all four versions
  are measured (register rule 5): edit its Status to `closed — measured <date>;
  tests/lab/results/L27-netbox.md, L27-nautobot.md` and add a "measured so far" paragraph under
  the register's per-row notes giving, per version, the version source, the role field, the
  GraphQL shape that returned every interface address (or none), and whether the webhook signature
  is HMAC-SHA512 of the body. Otherwise leave it open with that paragraph for what was measured.

- [ ] **Step 2: L28.** Close the row only if all four platforms have a note (rule 5), with the
  Status `closed — measured <date>; tests/lab/results/L28-arista_eos.md, L28-cisco_nxos.md,
  L28-cisco_iosxe.md, L28-juniper_vjunos-router.md`. Replace the design document §12 sentence Task 1
  wrote ("What the device then does ... is measured by spec §15 L28, open.") with what the notes
  say, citing them, and — on branch H — that port49d now closes a key miss at once and refuses a
  held source at Accept. If a note contradicts a doc, the doc is wrong: fix it, cite the note, and
  say so in the commit message (CLAUDE.md, lab register rule 4).

- [ ] **Step 3: The roadmap.** In `docs/superpowers/plans/README.md`, under "## Plan 6", replace the
  plan-6a paragraph's "written" status with "merged <date> (PR #N)", and add "### Plan 6a — As built"
  listing, as plan 5b's does: what shipped task by task where it differs from this plan; the owner
  decisions as ruled; which branch L28 took; the rows closed and left open; and "Carried, for later
  plans", including at least: the object-store mirror, persisted bundle and cold-start readiness
  (6b); the bundle document and its integer sequence (6b); owner decision 3's mismatch alarm (6b);
  `secret_ref:` resolvers, and key sets moving to the policy repository with them (plan 12);
  go-dark on a store outage, the warm context cache and plan 4b's remote-store items (plan 7); the
  `crypt_open_failures_total{record="token"}` alarm, which plan 2's hand-off gave to "plan 6 with
  key rotation reporting, or plan 7": plan 7, since it guards the encryption-at-rest rotation, not
  the device keys 6a reports on (M11); `key_ref` as a device label in per-device-pin deployments
  (plan 12, unchanged). Add to plan 4b's "Hands to plan 12" that `inventory_file`'s path is the
  deployment's to protect exactly as `broker.policy_file`'s is, since it is read behind the same
  fence and decides access within seconds (C2).

- [ ] **Step 4: Commit**

```bash
git add docs
git commit -m "docs: close lab register entries L27 and L28 as measured; plan 6a as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

  (Name only the rows actually closed in the subject line.)

---

## Operator-facing notes (for the pull request body)

- **Key groups move into the policy file.** Add the inventory file's `key_groups:` block to the
  policy file under the same key, then delete it from the inventory file. Until you add it, port49d
  reads it from the inventory file and says so at every start and reload. While both carry it, the
  policy's wins and a notice names the inventory's as ignored. Deleting it from the inventory
  first is refused by the bound, since it would refuse every device. If that wrong order is
  followed by a restart, the start is refused, saying the bundle admits none of the devices and
  naming the fix: add `key_groups` to the policy file. port49d with no `broker:` block (the lab's
  mode) keeps reading it from the inventory file.
- **A `key_ref` must be a name:** `^[a-z][a-z0-9_]{0,63}$`, in port49d.yaml's `keys:`, in a key
  group and in a device's pin. One that is not, most likely a secret pasted where the name goes, is
  refused without being printed: a `keys:` entry refuses port49d.yaml by its line, a key group
  its file by its position, and a pin refuses that device alone. Rename any key that is not
  lowercase letters, digits and `_` before upgrading. A YAML decode error in port49d.yaml or the
  inventory file prints its line and a category, never the file's text.
- **The inventory file is read like the policy file.** With a `broker:` block, it and its directory
  must be writable by port49d's user or root alone, it must be a regular file, and it must be
  64 MiB or smaller. Otherwise the start is refused, or a reload is refused once while the bundle
  in force keeps serving. Fix the modes before upgrading: an inventory file written by a
  config-management group is refused.
- **A device no key group admits no longer stops port49d.** With a `broker:` block, it is refused
  on its own: named at start and at every reload (`port49d: admission: device X (P) is refused:
  ...`), counted in `port49_devices_admission_refused`, and its packets closed after the header as
  `"diagnosis":"admission_refused"`. So is a device two groups tie on, and one assigned a `key_ref`
  `keys:` does not define. The broker refuses to mint for such a device (`device_unknown`), and a
  refresh revokes its live contexts. A start whose bundle admits no device at all is refused, naming
  the fix.
- **The inventory file is watched.** An edit is live within two `broker.policy_watch_interval`s,
  or at once on `SIGHUP`, and every live session is refreshed as after a policy edit: a removed
  device's contexts are revoked. An edit that is empty, malformed, repeats a name or an address, or
  takes more than `inventory.max_removed_percent` (default 10) of the devices out of service —
  removed, or kept and newly refused admission — is refused, said once, and
  `port49_inventory_file_refused` is 1. For a deliberate large removal, raise the bound in
  port49d.yaml and send `SIGHUP`, which re-reads it; then lower it again. A policy test naming a
  device the inventory no longer has fails `port49 policy test`, and never a reload.
- **A reload reaches open connections.** A device an inventory or policy reload refuses, removes,
  renames, moves to another `key_ref`, or gives another platform or `based_on:` base loses its
  open connections at their next packet: reset,
  with no reply and no strike, and one `unvalidated` record naming the device and key it was
  admitted as, reason `device_unknown` (`port49_connection_events_total{event="admission_closed"}`).
  Moving a device off a suspect key therefore stops that key on the device at once, not when its
  single-connect connection ends. What a device does with the reset is unmeasured (spec §15 L29).
- **Change the key groups and the inventory make-before-break.** Each file is loaded as its own
  swap, policy first, with a refresh between. To re-address devices together with their CIDR
  group, add the new group beside the old one, move the inventory, then drop the old group. Done
  in one step, the bundle between the two swaps revokes the contexts of devices the final one
  admits, and a whole-fleet re-address, where each file alone admits none, is refused at every
  reload until a restart loads the two together. `port49 inventory diff --new-policy` fails a change that would stop half-applied.
- **A policy reload is bounded too.** A policy whose `key_groups` would refuse admission to more
  than `inventory.max_removed_percent` of the devices admitted now is refused, naming them, and the
  policy in force keeps serving, with `port49_policy_file_refused` at 1; nobody is logged out.
  `port49 policy diff` fails on such an edit, and `port49 policy test` fails on any device
  admission refuses, so CI catches it first. `port49 explain` on a refused device says it is
  refused and why.
- **port49d.yaml must be a regular file**, at start and at `SIGHUP`, and so must the inventory
  file with no `broker:` block: a named pipe or a device there is refused rather than read. The
  admin socket's path is taken over only from a socket nothing listens on; one port49d cannot dial
  for any other reason, such as another user's, refuses the start by name.
- **New config keys:** `inventory: {max_removed_percent: N}`; `retire_after: YYYY-MM-DD` on `accept`
  key versions (admits through that day UTC); `admin_socket: /run/port49/port49d.sock` (off by
  default).
- **New metrics:** `port49_devices_admission_refused`, `port49_inventory_reloads_total{outcome}`,
  `port49_inventory_file_refused`, `port49_inventory_snapshot_age_seconds`,
  `port49_inventory_changes_total{kind}`, `port49_key_version_devices{key_ref,version}`,
  `port49_key_retirement_seconds{key_ref,version}`. `port49_key_version_devices` counts only
  devices seen since port49d started, and every restart (each rotation step is one) resets it to
  0 until devices reconnect, so the idle stragglers a retirement locks out are the last it counts.
  `port49 keys status`, which reads the decision log, is the authority before retiring a version;
  gate an alert on the metric on port49d's uptime (the example in spec §10, "Retirement is
  enforced"). A device a reload removes, refuses or moves to another `key_ref` drops out of the
  count at that swap.
- **The decision log:** `bundle` is now the bundle id (the policy file's hash and the inventory's,
  combined), not the policy file's hash; every validated record's `device` block carries `key_ref`
  and `key_version`; a new report event, `inventory_change`, records an address added to an existing
  device, a device's `key_ref` changing, a device newly admitted, and a device joining or leaving a
  `security_log: true` scope. Two new diagnoses: `admission_refused`, a device the inventory names
  and admission refuses, and `admission_withdrawn`, an open connection whose device a reload renamed,
  re-keyed or re-platformed.
- **New commands:** `port49 keys status`, `port49 keys show`, `port49 keys diagnose` (needs
  `admin_socket`), `port49 inventory diff`; `port49 policy test --config` adds the key checks;
  `port49 policy replay --policy --inventory` verifies a redacted blob's records.
  - `policy test --config` reads only port49d.yaml's `keys:` block. It is not a port49d.yaml
    validator: a file it passes can still refuse port49d's start.
  - `inventory diff` without `--config` does not check key_refs against port49d.yaml's keys; it
    says so on its output and does not fail for it. Pass `--config` in CI.
- **A scope can pin devices by name:** `match: {name: [leaf-01, leaf-02]}`.
- **`based_on: juniper_junos` now loads**, and the variant is read, and redacted, as Junos.
- **A key miss** (L28, closed): port49d resets the connection at once, with no reply, and refuses
  the source's next connections inside its backoff (by default 100 ms doubling to 5 s) with a
  reset too (`key_miss_closed`, `held_refused` in `port49_connection_events_total`). A device
  presenting an unknown, retired or expired key then has its token logins refused and its
  break-glass login and commands as fast as with port49d stopped, measured on EOS, NX-OS, IOS-XE
  and vJunos-router (`tests/lab/results/L28-*.md`). A packet past its key version's
  `retire_after` on an open connection is closed the same way; what a device does with that close
  is unmeasured (spec §15 L29, open).
  - The log carries one `unvalidated` record per strike. Attempts refused inside a backoff leave
    no record, only the `held_refused` count, which has no device label.
  - The refusal applies to any source that struck, whatever the strike, not a key miss alone. A
    strike from a device's address resets every connection from that address for up to 5 s. That
    includes a second AAA client on the same address still on the old key mid-rotation, or a
    shell on the device.

## Self-review against the spec

- **§10 "The inventory service", "Connectors and sync cadence", the object-store copy, cold start:**
  plan 6b, by the seam; L27 (Task 2) measures what 6b's connectors read.
- **§10 "One versioned bundle":** Tasks 6 (name, build), 11 (one pointer), 12 (reload), 10 (the
  daemon admits from it). Quarantine publication: the bundle carries it, and the daemon reads it
  from the same pointer (Task 10; plan 4b's `Live.Quarantined`). `bundle/diff`: Tasks 7, 18.
- **§10 "Admission and keys", "Addresses must resolve to one device", "Key group matching is
  deterministic":** Tasks 3, 4, 10, 17; owner decision 1 for the device-level tie. The key-group
  move is safe in every order (Tasks 4, 10, 12). A refused device is not minted for (Tasks 4, 11).
- **§10 "Source-of-truth write access" for the file itself:** the inventory file's write fence
  (Task 11a).
- **§10 "Key rotation":** try-and-validate and the per-connection cache are plan 1's, the cache now
  bounded by `retire_after` (Task 14); version sets gain `retire_after` (Task 14); phase-out
  (Tasks 8, 14, 15); unvalidated sources (Tasks 10, 15); retired never admits (Task 14's test);
  cross-group probing manual (Task 16); retirement enforced and CI (Tasks 14, 17); no per-device
  keys (nothing built).
- **§10 "Device records":** Task 3 (`transport`), Task 1 (text).
- **§10 "How a daemon refreshes its snapshot":** build then swap, validate locally, never expires,
  summary line, key resolution local (Tasks 10, 12); the pull, persistence and readiness are 6b's.
- **§10 "Source-of-truth write access":** Tasks 5 (pin), 7 and 13 (diff and events), 18 (review).
- **§14 "Inventory and capability" and "Key rotation":** snapshot refresh (Task 12), unresolvable
  `key_ref` (Tasks 4, 10), address collision (Tasks 3, 12), key group determinism (Tasks 3, 4),
  phase-out (Task 15), retirement (Tasks 14, 17), inventory sync safety (Tasks 7, 12); the §14
  quarantine-through-a-sync lab assertion is 6b's.
- **Plan 5a's debts:** replay (Task 19), `based_on:` wire facts (Task 9, with redaction).
- **Plan 4b's hand-off:** re-run the joint checks and `Refresh` on an inventory swap (Task 12); the
  inventory itself reloaded (Task 12); the remote-store items move to plan 7 (Task 21).
- **Reason codes:** none added. `device_unknown`'s meaning is extended to a refused device on `mint`
  and `refresh`, and a diagnosis (`admission_refused`) and a report event (`inventory_change`) are
  added, all in the spec first (Task 1). The final fix wave extended `device_unknown` to an open
  connection whose admission a reload withdrew and added the diagnosis `admission_withdrawn`, spec
  first too.
- **The pre-flight review:** every finding is resolved (the section at the top); none is left.
