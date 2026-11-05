# Plan 8b: Workload Directory Groups — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a workload certificate's directory entry supply its groups, opt-in per verifier and
keyed on its SPIFFE ID, reaching only a new machine-scoped group subject (`machine_group:`), never
a human `group:` subject, with the 3am cost of opting in said at start and pinned by tests.

- **Opt-in (ruling 1).** `broker.identity.machines[]`'s `x509` verifier takes a `directory:` block.
  - Without it, plan 8's behaviour is unchanged: no workload is sent to the directory, and one
    mints with every DC down. A test pins that.
  - With it, every workload that verifier accepts is a directory principal: exactly one entry, or
    no principal (decision 38 ruling 2).
- **The mapping kind `spiffe_id` (ruling 2).** One search for the entry whose `attribute` holds the
  workload's SPIFFE ID.
  - The value must be held byte for byte, since a SPIFFE ID's path is case-sensitive and a
    directory's matching rule may not be.
  - It is a weak kind under decision 38 ruling 1: `allow_weak: true` and an `issuers:` pin are
    required, and the pin is checked at every reading of the certificate, before any search.
  - The entry is pinned by `objectGUID` or `entryUUID`. `port49 directory forget` takes a
    `spiffe://` ID.
- **The username (ruling 4, amending decision 8 through decision 38 ruling 3).**
  - The identity subject listing the SPIFFE ID gives it, when that subject declares one, so opting
    in renames no workload.
  - Otherwise the entry's `username_attribute` gives it, under ruling 3's collision rules: the
    declared name stands.
  - A `machine_group:` subject declares none.
  - **One entry, one domain.** While the mapping is configured, an entry whose `attribute` holds a
    SPIFFE ID is a workload's: the person path refuses it `identity_unmapped`, so one entry never
    gives a person and a workload one `(nas, username)` context.
- **The machine-scoped group subject (ruling 5).** `machine_group: <name or DN>`, domain
  `machines`.
  - A workload resolved through the mapping matches it. A `user:` principal never does.
  - A `group:` subject never matches a workload.
  - A subject naming both keys is a load error.
  - Decision 38 ruling 15's diff gate and the CI report cover it.
- **The plumbing (ruling 6).**
  - The broker's `IsUser` gates become per domain: `memberFor`, `storedMemberOf`, `storedMember`
    and the scheduled refresh's judge.
  - `forget` takes `spiffe://`.
  - Pre-warm verifies as workloads the `machine_group:` members and every `spiffe://` identity a
    subject lists.
  - The membership record is `mb/<SPIFFE ID>`.
- **The 3am case (ruling 7).** With the mapping configured, a DC outage past
  `broker.directory.grace` has two effects:
  - the workload's mints are refused `directory_unavailable`, and `port49 workload` exits 75;
  - its live sessions deny `context_stale` at `session.staleness_ceiling`.

  The start line and the operator notes say so.
- **Lab L50 (ruling 10).** Who can write the attribute, on Windows Server AD (L44's box) and Samba
  AD (the L43 harness). It runs under the default ACLs and under the ACL the docs will prescribe,
  and checks whether a write reaches the audit log. Until L50 closes, no doc asserts that "only
  directory administrators can write it" (lab register rule 1).

**Architecture:**
- **`internal/directory`:**
  - `MapSPIFFEID`; `WorkloadMapping` on `Config.Workload`; `WorkloadMapping.Pinned`.
  - `Resolver.VerifyWorkload` and `CurrentWorkload` use the same `verify` and `grace` as a
    person's, through a `lookup.workload` flag. The flag reads the entry as `workloadIdentityOf`,
    checks the ID unique with `workloadUnique`, writes no mapping key, and leaves the
    declared-username check to the broker.
  - The person path refuses an entry holding a SPIFFE ID in the workload attribute (`notWorkload`).
  - `PrewarmAll` adds the machine groups and the listed `spiffe://` identities to pre-warm.
- **`internal/config`:**
  - `directory:` on the machine x509 verifier, as `oidc.X509Machine.Directory`.
  - It is resolved into `directory.Config.Workload` once `broker.directory` is read.
  - `spiffe_id` is refused under `certificate_mapping`.
- **`internal/policy`:**
  - `machine_group:` (`Subject.Group` with `Domain: machines`, and `Subject.GroupKey`).
  - `Member.Domain`; `Env.WorkloadDirectory`.
  - `subjectsOf` matches per domain (`groupDomainOf`).
  - `DeclaredFor`; the split of `GroupValues` and `GroupSubjects` from `MachineGroupValues` and
    `MachineGroupSubjects`.
  - `checkMinters` asks a `spiffe://`-only subject for no username under the mapping.
  - The diff compares `GroupKey`; `SubjectChange` gains `OldGroupKey` and `NewGroupKey`.
  - Lint's group-subject finding names the key and the config it mints under.
- **`internal/broker`:**
  - `workloadMapped` and `workloadMember` settle a workload's member and username.
  - `memberFor`, `storedMemberOf`, `storedMember` and the scheduled judge branch on them.
  - `heldCollision` is the hold-time collision check, shared by the mint and `RefreshSession`.
  - `CertCallerOf` checks the issuer pin; `Forget` widens.
- **`internal/port49d`:** `policyEnv` sets `WorkloadDirectory`. `announceDirectory` says the
  mapping, its 3am cost, its ACL requirement, and the `machine_group:` subjects that mint for no
  one. Pre-warm calls `PrewarmAll`.
- **`cmd/port49`:** the diff report names the key. Tests pin `port49 workload`'s exit 75 on
  `directory_unavailable`.
- **`tests/lab`:** `l50_test.go`, three Windows scripts and one Samba script.

**Tech Stack:** Go 1.26, module `github.com/blanketfish/port49`, no cgo, **no new module**
(`github.com/go-ldap/ldap/v3` as today). Lab: the L44 Windows Server 2025 DC (dockur/windows, by
digest, `tests/lab/windows_test.go`) and the L42/L43 Samba AD container
(`tests/lab/directory/samba`).

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §2 (subjects, the username table, "Machine identities have no directory entry");
  - §5.1.3 (the scheduled refresh);
  - §5.7 (the rows `identity_unmapped`, `identity_ambiguous`, `directory_unavailable` and
    `username_collision`);
  - §12 (the diff gate);
  - §13: decisions 8 and 16; decision 38 rulings 1, 2, 3, 7, 10, 12, 15, 17 and 20; decision 40
    rulings 2–5 and 10; the new decision 41;
  - §14 (workload certificates);
  - §15 (L50).
- `docs/design/2026-08-21-port49-design.md` §7 (certificate-to-directory mapping, machine identity,
  trust domain separation).
- The roadmap `docs/superpowers/plans/README.md`, "Plan 8b". It is the brief, and its open
  points are settled by the Rulings below.
- Plan 8 (`2026-10-07-08-workload-certificates.md`) for house style. This plan is written against
  `main` at `df198b2`.

**Prerequisite:** plan 8 and the purge-window fix merged (`main` at `df198b2`).

## Rulings where the brief is open

The brief leaves five choices to the plan. Each is ruled here on reasoning, written into decision
41 by Task 1, and listed under "Questions for the controller" for the pre-flight to confirm or
override.

- **R1. The workload's directory is asked per request, not mapped at bind.** A person's
  certificate is mapped at bind because the principal comes from the entry (decision 38 ruling 4).
  A workload's principal is its SPIFFE ID, known from the certificate (decision 40 ruling 3), so
  the listener is unchanged: `BindMap` still refuses a machine chain, and `Listener.Map` still
  skips one. `memberFor` reads the membership at each request by the SPIFFE ID, as it reads a
  person's by their principal: fresh, or within grace.
- **R2. The username: declared wins, else the entry's.** The identity subject listing the SPIFFE
  ID gives the username when it declares one, so turning `directory:` on renames no workload and
  breaks no existing `(nas, username)` context. Otherwise the entry's `username_attribute` gives it,
  under decision 38 ruling 3. A `machine_group:` subject declares none: one name for every member
  would put many workloads in one context, and two groups could declare two.
- **R3. `attribute` is required, with no default.** No schema has an attribute for a SPIFFE ID, and
  which one is safe depends on who can write it (L50).
- **R4. `issuers:` is required (weak kind), the leaf's issuer, as ruling 1 has it.** The workload
  anchor already bounds the chain (decision 40 ruling 2), but an anchor may sign several
  intermediates, and the pin is what decision 38 ruling 1 requires of every weak kind.
- **R5. The workload block reuses `broker.directory`** for its pool, bind, `base_dn`,
  `username_attribute`, nested mode, grace and pre-warm. It adds only `kind`, `attribute`,
  `allow_weak`, `issuers` and an optional `user_filter`. One `base_dn` keeps ruling 3's username
  uniqueness search spanning people and workloads.

## What this plan does not do

- **No mapping at bind for a workload** (R1). The listener, `BindMap` and `ErrUnwired` are
  untouched.
- **No new reason code.** Four §5.7 rows widen (Task 1); `internal/decision/reasons.go` is
  unchanged.
- **No new metric.** A workload's lookups count under `port49_directory_lookups_total{outcome}`, as
  a person's do.
- **No `k8s` or `app:` directory mapping.** Those principals stay off the directory (plan 10 owns
  `k8s`).
- **No claim about who can write the attribute.** That is L50 (Task 8). The docs prescribe an ACL
  only once L50 has measured it.

## What the operator sees

Every line below is printed by a task in this plan, and the tests named pin it.

- **A broker start with the mapping** (Task 6, `TestTheWorkloadMappingStartLines`):

  ```
  port49-broker: directory: workload certificates map by spiffe_id (weak, pinned to CN=Workloads Issuing CA,O=Corp) through uid under (objectClass=user); every workload this verifier accepts must have exactly one entry holding its SPIFFE ID, or it is refused identity_unmapped, and while the directory is down past grace it is refused directory_unavailable; username from the identity subject listing the SPIFFE ID, else from sAMAccountName; an entry holding a SPIFFE ID in uid is never a person's; machine_group subjects match them, group subjects never
  port49-broker: directory: a mapped workload mints only while a server answers or its membership was verified within grace (4h0m0s): past it its mints are refused directory_unavailable (port49 workload exits 75); its live device sessions go unstamped from the first scheduled refresh that cannot verify it, and deny context_stale once port49d's session.staleness_ceiling has passed since the last one that did; pre-warm every 1h0m0s keeps mapped workloads verified (machine_group members and each spiffe:// identity a subject lists, up to prewarm.max_principals (10000) besides the people's)
  port49-broker: directory: uid must be writable only by directory administrators: whoever can write it on an entry chooses which workload takes that entry's groups
  ```

  With `prewarm.interval: 0s` the second line ends `; pre-warm is off, so a workload that has not
  minted within grace is refused in an outage`. The first line carries ruling Q2's cost (pre-flight
  I-4); the second keeps the two clocks apart, grace for a mint and the staleness ceiling for a
  session (pre-flight M-1).
- **`machine_group:` subjects with no mapping** (Task 6):

  ```
  port49-broker: policy: 1 machine_group subjects (backup_hosts) mint for no one: no broker.identity.machines[].directory is configured
  ```
- **New config refusals** (Task 3):
  - `broker.identity.machines[].directory maps workload certificates through broker.directory, which is not configured: configure it, or remove directory to keep workloads off the directory`;
  - `broker.identity.machines[].directory.kind "issuer_serial": spiffe_id, the one kind a workload's mapping takes (spec §13 decision 41)`;
  - `broker.identity.machines[].directory.attribute is required: no schema has one for a SPIFFE ID; name the attribute your directory administrators reserve for it`;
  - `broker.identity.machines[].directory: spiffe_id is a weak mapping: set allow_weak: true and list the issuers it is pinned to (design §7)`;
  - `broker.identity.machines[].directory.issuers: a weak mapping is pinned to its issuers; list at least one (design §7)`;
  - `broker.directory.certificate_mapping.kind spiffe_id is a workload certificate's mapping: set it under broker.identity.machines[].directory`.
- **New policy load refusals** (Task 4):
  - `subject "x": group names people and machine_group names workloads; a subject is one trust domain, so give each its own subject (spec §2; §13 decision 41 ruling 5)`;
  - `subject "x": a machine_group's members take the username their identity subject declares, or their entry's (§13 decision 41 ruling 4); remove username`.
- **A workload refused** (Task 5): `401 identity_unmapped` (issuer not pinned, no entry, the value
  not byte for byte); `401 identity_ambiguous` (two entries); `401 username_collision` (an entry's
  username a subject declares, at a mint or a session refresh); `503 directory_unavailable` with
  `Retry-After: 30` (an outage past grace). The refusal record names the SPIFFE ID, the issuer
  pin's included (pre-flight M-4).
- **A person refused** (Task 2): `401 identity_unmapped`, detail `… the entry is a workload's (uid)
  …`, when the person's entry holds a SPIFFE ID in the mapping's attribute (one entry, one domain).
- **`port49 workload token` in an outage** (Task 7), on stderr, exit 75:

  ```
  port49 workload token: the broker did not answer within 2m0s (the last answer: 503 directory_unavailable: no directory server answered and no membership verified within the grace window is held; the agent retries): 1 of 1 devices were not minted; run again
  ```
- **`port49 policy diff`** (Task 4): `subject: backup's group "backup-hosts" -> machine_group "backup-hosts"`.
- **`port49 directory forget spiffe://corp.example.com/host/oxidized-01`** (Task 5) forgets a
  workload's pin as a person's. With no workload mapping it answers `no workload mapping is
  configured (broker.identity.machines[].directory) …` (pre-flight M-6).
- **`port49 policy lint`** (Task 4), for each group subject:
  - `subject "people" is a group: subject: it mints only with broker.directory configured, through which the broker matches a person to the group; explain and policy tests evaluate it by name`;
  - `subject "hosts" is a machine_group: subject: it mints only with broker.identity.machines[].directory configured (a workload certificate's directory mapping), through which the broker matches a workload to the group; explain and policy tests evaluate it by name`.

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, **no cgo**, **no new
  module**.
- snake_case everywhere it is data: YAML keys (`machine_group`, `allow_weak`, `user_filter`), JSON
  log keys, config, metric names.
- Reason codes are spec §5.7's closed vocabulary (`internal/decision/reasons.go`). **This plan adds
  none.** It widens `identity_unmapped`, `identity_ambiguous`, `directory_unavailable` and
  `username_collision` in the spec table first (Task 1).
- The log never contains a token, password, challenge or response. Credentials appear only as
  `credential_sha256`. **An unvalidated body is never logged.**
  - A SPIFFE ID, a DN, and the value an entry's attribute holds may be logged, each through
    `printsafe.Line`.
  - The bind password, keytab and tickets: as plan 7g.
- No device identity and no principal in a metric label.
- **Fail closed, never widen.** Each of these is a refusal or matches no one:
  - a subject naming both `group:` and `machine_group:`;
  - a workload matching a `group:` subject; a `user:` principal matching a `machine_group:`;
  - a value another case of the SPIFFE ID; two entries holding it (in any case the directory's
    matching rule equates); an issuer not pinned;
  - a person's entry holding a SPIFFE ID in the workload attribute (one entry, one domain).
- **Opt-in.** With no `directory:` on the machine verifier, every line of plan 8's behaviour holds:
  the resolver is never asked for a workload, and it mints with every DC down. Task 5 pins it.
- Verify with `make test && make vet`, and `make test-race` on every touched package, and report the
  real output. Every test that speaks to a real directory is a lab test (`//go:build lab`, Task 8),
  so `go test ./...` needs none.
- **Deployment is not prescriptive.** Nothing here requires Kubernetes or a directory.
- **Readiness never follows the directory.** `/readyz` is untouched (decision 38 ruling 9).
- **The lab register rules** (CLAUDE.md 1–4).
  - L50 is open. Until it closes, no doc, start line or note asserts who can or cannot write the
    attribute: a start line says the requirement ("must be writable only by directory
    administrators"), never the fact.
  - It closes in Task 8 only with notes for both platforms its row names (`windows_ad`,
    `samba_ad`).
- Conventional Commits, on branch `feature/workload-directory`. Commit messages end with:

  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  ```
- Implementers never run `git checkout`, `restore`, `reset`, `stash` or `clean`.

## Review Focus

The five inputs or conditions most likely to bite a person, and the test that pins each:

1. **A SPIFFE ID the directory matches case-insensitively.** AD's matching rules for most string
   attributes ignore case, while a SPIFFE ID's path does not
   (`spiffe://corp.example.com/host/Oxidized-01` is another workload).
   - **Expected:** the entry found for one ID holding another case of it is `identity_unmapped`,
     never that workload. Two entries the directory returns for one ID are `identity_ambiguous`,
     never the first, in two cases: both hold it exactly, or one holds another case of it that the
     directory's matching rule equates. The uniqueness search reads no values, so a case variant is
     never waved through as "not the same ID".
   - **Pinned by** Task 2's `TestAWorkloadEntryMustHoldItsIDByteForByte` and
     `TestTwoEntriesHoldingOneSPIFFEIDAreAmbiguous` (both cases).
2. **A workload whose own subject declares the username its entry also holds** (`svc-oxidized`
   declared, `sAMAccountName: svc-oxidized`), the natural configuration.
   - **Expected:** it mints as `svc-oxidized`, and its session refresh is extended, never refused
     `username_collision` against itself. Another workload whose entry holds a name some subject
     declares is refused, at the mint and at the refresh.
   - **Pinned by** Task 5's `TestAWorkloadsOwnDeclaredUsernameIsNoCollision`,
     `TestAnEntryUsernameASubjectDeclaresIsTheWorkloadsCollision` and
     `TestASessionRefreshSettlesAWorkloadsUsernameAsTheMintDoes`.
3. **One group named both ways, and a subject moved between the two keys.**
   - **The inputs:** `group: backup-hosts` and `machine_group: backup-hosts` in two subjects; a
     diff moving `group: backup-hosts` to `machine_group: backup-hosts`.
   - **Expected:** each subject matches only its own domain. The move fails the gate, though the
     value is unchanged.
   - **Pinned by** Task 4's `TestAMachineGroupMatchesAWorkloadAlone` and
     `TestAGroupMovedToMachineGroupIsGated`, and Task 5's
     `TestAWorkloadNeverMatchesAHumanGroup` and `TestAPersonNeverMatchesAMachineGroup`.
4. **A nightly cron job in a DC outage.** A workload that minted 24h ago has a membership record at
   the end of its `max(grace, 24h)` lease, verified far past grace.
   - **Expected:** with pre-warm on, its record is verified each hour, so it mints within grace.
     That holds whether its grants come from a `machine_group:` or from its own `spiffe://`
     identity subject alone (pre-flight I-3). With pre-warm off, the start says it will be refused.
     Either way the mint is never served from a record past grace.
   - **Pinned by** Task 6's `TestPrewarmVerifiesMachineGroupMembersAsWorkloads`,
     `TestPrewarmVerifiesIdentityOnlyWorkloads` and `TestTheWorkloadMappingStartLines`, and Task
     2's `TestAWorkloadInGraceAndPastIt`.
5. **A service account's entry read as a person.** A group is listed under `machine_group:` only,
   and its members' entries also hold a `userPrincipalName`.
   - **Expected:** human pre-warm never enumerates it, so no `mb/user:…` record is written for its
     members. Machine pre-warm writes `mb/spiffe://…` records only. A person's certificate that
     maps to such an entry is refused `identity_unmapped`, so the entry never gives a `user:`
     principal the workload's `(nas, username)` context (pre-flight I-2).
   - **Pinned by** Task 4's `TestAMachineGroupIsAMachinesSubject` (`GroupValues` excludes it),
     Task 6's `TestPrewarmVerifiesMachineGroupMembersAsWorkloads`, and Task 2's
     `TestOneEntryIsOneDomain`.

## Conflict scan: where tasks share a file or an interface

- `internal/directory/config.go`, `mapping.go`, `entry.go` and `resolver.go`: Task 2 alone.
  `prewarm.go`: Task 6 alone. Task 6 reads Task 2's `byWorkloadDN` and `lookup.workload`.
- `internal/oidc/config.go`, `internal/config/identity.go`, `directory.go` and `config.go`: Task 3
  alone.
- `internal/policy/file.go`, `load.go`, `member.go`, `diff.go`, `lint.go` and `lint_test.go`, and
  `cmd/port49/policy.go`: Task 4 alone.
- `internal/broker/member.go`, `scheduled.go`, `refresh.go` (`storedMember`), `broker.go` (the
  hold-time check), `sessionrefresh.go` (the same check in `RefreshSession`), `workload.go`
  (`CertCallerOf`) and `forget.go`: Task 5 alone.
- `internal/port49d/directory.go`: Task 6 alone.
- `cmd/port49/workload_test.go` and `internal/workload/client_test.go`: Task 7 alone, tests only.
- `tests/lab/`: Task 8 alone.
- The spec and design: Task 1 writes them; Task 8 closes L50 and fixes any text its results
  contradict.

Tasks 2, 3 and 4 touch disjoint packages and could run in parallel after Task 1; Task 5 needs all
three; Task 6 needs 2, 3 and 4; Task 7 needs 5; Task 8 needs 1–7 merged into the branch.

## File Structure

**Create:**
- `internal/directory/workload_test.go`: Task 2's tests.
- `internal/config/workload_directory_test.go`: Task 3's tests.
- `internal/policy/machine_group_test.go`: Task 4's tests.
- `internal/broker/workload_directory_test.go`: Task 5's tests.
- `internal/port49d/workload_directory_test.go`: Task 6's start-line tests.
- `tests/lab/l50_test.go`: L50 (`//go:build lab`).
- `tests/lab/directory/windows/scripts/l50_seed.ps1`, `write_as.ps1` and `audit.ps1`.
- `tests/lab/directory/samba/l50-seed.sh`.
- `tests/lab/results/L50-windows_ad.md` and `L50-samba_ad.md`, written by the run, and
  `tests/lab/evidence/L50-*.json`.

**Modify:**
- `docs/design/2026-08-23-policy-engine-spec.md` and `docs/design/2026-08-21-port49-design.md`
  (Task 1; Task 8 closes L50).
- `internal/directory/config.go`, `mapping.go`, `entry.go`, `resolver.go` (Task 2) and `prewarm.go`
  (Task 6).
- `internal/oidc/config.go`; `internal/config/identity.go`, `directory.go` and `config.go` (Task 3).
- `internal/policy/file.go`, `load.go`, `member.go`, `diff.go` and `lint.go`;
  `internal/policy/lint_test.go`; `cmd/port49/policy.go`; `cmd/port49/policy_test.go` (Task 4).
- `internal/broker/member.go`, `scheduled.go`, `refresh.go`, `broker.go`, `sessionrefresh.go`,
  `workload.go` and `forget.go` (Task 5).
- `internal/port49d/directory.go` (Task 6).
- `cmd/port49/workload_test.go` and `internal/workload/client_test.go` (Task 7).
- `tests/lab/windows_test.go` (`winScripts`, `winSecretParams`), `tests/lab/directory/samba/Dockerfile`,
  `tests/lab/README.md` and `Makefile` (`lab-l50`) (Task 8).

---

### Task 1: The spec says what plan 8b builds: decision 41, the amended rulings, four reason rows, L50 sharpened

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §2, §5.1.3, §5.7 (four rows), §12, §13
  (decisions 8, 16, 38, 40 amended; 41 new), §14, §15 (L50)
- Modify: `docs/design/2026-08-21-port49-design.md`: §7

**Interfaces:**
- Consumes: Rulings R1–R5 above.
- Produces: decision 41, rulings 1–10, which every later task cites; the widened reason rows; L50's
  sharpened claim (Task 8 measures it).

This task is docs only. Each step is an edit with the exact text. Where a step says "replace", the
old text is quoted and appears once; check with `grep -n` before editing. Every amendment carries
its provenance in the text.

- [ ] **Step 1: Decision 41, after decision 40**

Find the end of decision 40 with `grep -n "Q3:\*\* mint by \`scope\`" docs/design/2026-08-23-policy-engine-spec.md`.
The paragraph ends `first.`, and the next lines are `---` and `## 14. Required test assertions`.
Between that paragraph and the `---`, insert:

```markdown
**41. Workload directory groups: opt-in per verifier, keyed on the SPIFFE ID, reaching
`machine_group:` subjects alone.** *Plan 8b, 2026-10-09.* Rulings rest on reasoning unless they
say data. The plan's open choices (the workload asked per request, the username, `attribute`
required, the pin required, `broker.directory` reused) were ruled by the plan on reasoning and
are confirmed or overridden at its pre-flight; Ryan may override any.

- **1. Opt-in, per verifier.** `broker.identity.machines[]`'s `x509` verifier takes `directory:`.
  With it, every workload that verifier accepts is a directory principal: exactly one entry, or no
  principal (decision 38 ruling 2). Without it, decision 40 ruling 5 holds unchanged: no workload
  is sent to the directory, and one mints with every server down. `directory:` needs
  `broker.directory`, whose pool, bind, `base_dn`, `username_attribute`, nested mode, grace and
  pre-warm it uses; one `base_dn` keeps decision 38 ruling 3's username search spanning people and
  workloads. Tasks 3 and 5.
- **2. The mapping kind `spiffe_id`.** The block takes `kind: spiffe_id` (the one kind there),
  `attribute` (required: no schema has one for a SPIFFE ID), `allow_weak`, `issuers` and
  `user_filter` (default `broker.directory.user_filter`).
  - **The search.** `(&<user_filter>(<attribute>=<the SPIFFE ID, escaped>))` under `base_dn`, size
    limit 2. Zero entries is `identity_unmapped`; two is `identity_ambiguous`, never the first.
  - **The value.** The entry's `attribute` must hold exactly one value, equal to the SPIFFE ID byte
    for byte. A SPIFFE ID's path is case-sensitive (decision 40 ruling 4) and a directory's
    matching rule may not be, so an entry holding another case of the ID is `identity_unmapped`,
    never that workload.
  - **Uniqueness.** A second entry holding the ID, searched with no `user_filter`, is
    `identity_ambiguous`, as decision 38 ruling 3's principal search is. The search reads no
    values, so a second entry holding another case of the ID, which a case-insensitive matching
    rule returns, makes it `identity_ambiguous` too.
  - **Weak.** It binds a name, not a key, so it is weak under decision 38 ruling 1: refused at load
    without `allow_weak: true` and a non-empty `issuers:`. The pin compares the leaf's issuer, read
    from its DER, at every reading of the certificate (the bind and each request), before any
    search. An issuer not pinned is `identity_unmapped`, answered 401 at bind over HTTP (decision
    40 ruling 3).
  - **What it gives.** The principal stays the SPIFFE ID. The directory supplies the groups, and
    the username under ruling 4. No mapping key is written, since the principal is known before
    the search. `spiffe_id` under `broker.directory.certificate_mapping` is refused at load.
  - Tasks 2 and 3.
- **3. The membership** is decision 38 rulings 3 and 10's, by the SPIFFE ID: `mb/<SPIFFE ID>`,
  sealed, pinned to the entry's `objectGUID` or `entryUUID` (else DN) for the record's life; a
  refusal written and never overruled by grace; a lease of `max(grace, 24h)`. `port49 directory
  forget spiffe://…` is the escape. Tasks 2 and 5.
- **4. The username** (amends decision 8 through decision 38 ruling 3).
  - **Declared wins.** The identity subject listing the SPIFFE ID gives it when that subject
    declares a `username:`, so turning the mapping on renames no workload.
  - **Else the entry's.** Otherwise the entry's `broker.directory.username_attribute` gives it,
    under ruling 3: lower-cased, canonical, not reserved, held by that entry alone (a second entry
    holding it is `username_collision`), and refused `username_collision` when any subject declares
    it. The declared one stands, whichever came first.
  - **Never on a group.** A `machine_group:` subject declares no `username:` (a load error): one
    name for many workloads would put them in one `(nas, username)` context.
  - **Who must declare.** Under the mapping, a subject whose identities are all `spiffe://` IDs
    need not declare one; a subject listing an `app:` identity still must.
  - **One entry, one domain.** An entry whose workload `attribute` holds a SPIFFE ID is a
    workload's. While a workload mapping is configured, the person path (a bind, a mint, the
    scheduled refresh, pre-warm) refuses such an entry `identity_unmapped`, so one entry never gives
    a `user:` principal and a workload one `(nas, username)` context, where whichever minted last
    would hold the other's grants. The workload path need not mirror it: the person path is the
    one that grants by `principal_attribute`. An entry whose attribute holds a value that is no
    SPIFFE ID (a `description`, say) stays a person's. *Added at plan 8b's pre-flight (I-2).*
  - **Judged again at the hold.** The mint and a session refresh judge the username again under
    the policy they hold, since a reload can land between the membership read and the hold (plan
    7g's final review M-1). For a workload that judgment is this ruling's, so its own subject's
    declaration is never its collision.
  - Tasks 2, 4 and 5.
- **5. The machine-scoped group subject.** `machine_group: <name or DN>`, matched as decision 38
  ruling 7 matches `group:`: a DN in canonical form, a name only while one group under
  `groups_base_dn` has it.
  - **Its domain is `machines`.** `attached_roles.machines` reach it, never `attached_roles.humans`.
  - **What matches it.** Only a workload resolved through ruling 1's mapping, never a `user:`
    principal. A `group:` subject never matches a workload.
  - **Load errors.** A subject with both `group:` and `machine_group:`, as one with either and
    `identity:`.
  - **Rights.** CI reports its `api:` rights as any subject's.
  - **No mapping.** With none configured, `machine_group:` subjects mint for no one and the start
    names them (as decision 38 ruling 17 for `group:`).
  - Tasks 4 and 6.
- **6. When the directory is asked.**
  - **Per request.** A mapped workload's membership is read by its SPIFFE ID, fresh or within
    grace (decision 38 ruling 10): at mint, at `/v1/identity`, at `/v1/explain`, and as a
    revocation's caller. A workload is never mapped at bind: its principal is known from the
    certificate, and the listener is unchanged.
  - **The scheduled refresh** verifies it from a server and stamps its contexts with the
    verification's time, as a `user:` principal's (ruling 12 widened). A policy refresh judges the
    stored membership.
  - **Pre-warm** verifies the members of every `machine_group:` as workloads. It reads each
    member's SPIFFE ID from `attribute`; one outside the verifier's `spiffe_trust_domains` is
    skipped and counted. It then verifies every `spiffe://` identity a subject lists, in those
    trust domains, so a workload granted by its own identity subject alone is kept warm too. So a
    workload that has not minted within grace can mint in an outage. The workloads take their own
    `prewarm.max_principals`, besides the people's, so one interval verifies up to twice it.
  - Tasks 2, 5 and 6.
- **7. The 3am case.** With the mapping configured, a directory outage past
  `broker.directory.grace` does two things:
  - **Mints stop.** The workload's mints are refused 503 `directory_unavailable` with
    `Retry-After: 30`. `port49 workload token` retries within `--deadline`, then exits 75
    (decision 40 ruling 10).
  - **Sessions go stale.** Its live device sessions go unstamped from the first scheduled refresh
    that cannot verify it, and deny `context_stale` once port49d's `session.staleness_ceiling` has
    passed since the last one that did, from a reachable port49d, where break-glass does not help;
    decision 38's escapes apply. The two clocks are separate: grace bounds a mint, the ceiling a
    session.

  Opting in trades plan 8's "mints with every DC down" for directory groups, and the start line
  says so. Tasks 5, 6 and 7.
- **8. The diff gate and CI.** Decision 38 ruling 15 covers `machine_group:` as `group:`.
  - A changed value fails the gate, as does a subject moved between `group:` and `machine_group:`
    with one value, until a passing session test naming the subject asserts its access.
  - A new `machine_group:` subject is gated as a new subject's principals are.
  - The CI report names the key.
  - Task 4.
- **9. What is logged.** A SPIFFE ID, a DN and an attribute's value, each through
  `printsafe.Line`; never a token; no SPIFFE ID or device in a metric label. A workload's lookups
  count in `port49_directory_lookups_total` as people's do. Tasks 2 and 6.
- **10. The lab.** "`attribute` must be writable only by directory administrators" is a requirement
  on the operator, said at start as ruling 3's is.
  - **Measured by L50, open.** Whether a directory's default ACLs, or the ACL the docs prescribe,
    make it so is a directory-behaviour claim.
  - **Until it closes,** no doc asserts who can or cannot write it, and the docs prescribe no ACL as
    sufficient.
  - Task 8.
```

- [ ] **Step 2: Decisions 8, 16, 38 and 40 amended**

Decision 8: replace

```markdown
subject's declared `username` (decision 38 ruling 16; decision 39 ruling 7); machine subjects declare one, since they have no directory entry. Unique across
```

with

```markdown
subject's declared `username` (decision 38 ruling 16; decision 39 ruling 7); machine subjects declare one, since they have no directory entry. *Amended by decision 41 ruling 4 (plan 8b, 2026-10-09):* a workload certificate whose verifier maps it through the directory takes its identity subject's declared username when it declares one, and its entry's `username_attribute` otherwise, under decision 38 ruling 3. Unique across
```

Decision 16: replace

```markdown
Plan 8 builds none; plan 8b owns it, with its own lab row (L50). (§2, design document §7)
```

with

```markdown
Plan 8 builds none; plan 8b owns it, with its own lab row (L50). *Built by plan 8b as decision 41
(2026-10-09):* opt-in per `x509` machine verifier, the `spiffe_id` mapping kind, the
`machine_group:` subject. (§2, design document §7)
```

Decision 38 ruling 1: after the sentence `enforcement to 1 or 2 changed none of it on this build.
Tasks 4 and 8.` (`grep -n "changed none of it on this build. Tasks 4 and 8."`), append on the same
bullet:

```markdown
  *Amended by decision 41 ruling 2 (plan 8b, 2026-10-09):* a seventh kind, `spiffe_id`, weak, is a
  workload certificate's alone, configured under `broker.identity.machines[].directory` and never
  here; `certificate_mapping.kind: spiffe_id` is refused at load.
```

Decision 38 ruling 3: after `provisional. Tasks 5, 8 and 13.` (`grep -n "provisional. Tasks 5, 8 and
13."`), append on the same bullet:

```markdown
  *Amended by decision 41 rulings 2–4 (plan 8b, 2026-10-09):* a workload's principal is its SPIFFE
  ID, which its entry must hold byte for byte and alone; its username is its identity subject's
  declared one, else its entry's under this ruling; its pin and its forget are this ruling's.
```

Decision 38 ruling 12: replace

```markdown
  stamps its own instant. A policy-reload pass never stamps and judges by the stored membership,
  or by no groups where none is held, it is refused or it is older than grace. Tasks 14 and 15.
```

with

```markdown
  stamps its own instant. A policy-reload pass never stamps and judges by the stored membership,
  or by no groups where none is held, it is refused or it is older than grace. Tasks 14 and 15.
  *Amended by decision 41 ruling 6 (plan 8b, 2026-10-09):* a workload whose verifier maps it is
  verified and stamped as a `user:` principal is.
```

Decision 38 ruling 15: replace

```markdown
  subject is gated as a new subject's principals are. Task 11.
```

with

```markdown
  subject is gated as a new subject's principals are. Task 11. *Amended by decision 41 ruling 8
  (plan 8b, 2026-10-09):* `machine_group:` is gated as `group:`, and a subject moved between the
  two keys is a change.
```

Decision 38 ruling 20: replace

```markdown
  within grace. Task 10.
```

with

```markdown
  within grace. Task 10. *Amended by decision 41 ruling 6 (plan 8b, 2026-10-09):* the members of
  every `machine_group:` are verified as workloads, by the SPIFFE ID their entry holds, and so is
  every `spiffe://` identity a subject lists, under their own `prewarm.max_principals`.
```

Decision 40 ruling 5: replace

```markdown
  follow-the-spec rule; Ryan may cancel plan 8b.* Tasks 1 and 5.
```

with

```markdown
  follow-the-spec rule; Ryan may cancel plan 8b.* Tasks 1 and 5. *Built by plan 8b as decision 41
  (2026-10-09); the default above stands.*
```

- [ ] **Step 3: §2, the subjects and the username**

Replace

```markdown
them, and it has exactly two forms — an LDAP group, or one or more literal identities. That
```

with

```markdown
them, and it has exactly two forms — an LDAP group (of people, `group:`; or of workloads,
`machine_group:`, §13 decision 41 ruling 5, plan 8b), or one or more literal identities. That
```

Replace

```markdown
**Machine identities have no directory entry**, so the subject declares one. A machine principal is
never sent to the directory, at mint or by the scheduled refresh, until plan 8b builds a workload
certificate's opt-in directory mapping, and never matches a human `group:` subject, then or after
(§13 decisions 16 and 40 ruling 5):
```

with

```markdown
**Machine identities have no directory entry**, so the subject declares one. A machine principal is
never sent to the directory, at mint or by the scheduled refresh, unless it is a workload
certificate whose verifier maps it (`broker.identity.machines[].directory`, §13 decision 41, plan
8b, 2026-10-09). Such a workload takes its identity subject's declared username when it declares
one, else its entry's `username_attribute` under §13 decision 38 ruling 3, and matches
`machine_group:` subjects. No machine principal matches a human `group:` subject, then or after
(§13 decisions 16 and 40 ruling 5):
```

In the username table, after the row beginning `| certificate | via the certificate-to-directory
mapping`, add:

```markdown
| workload certificate, mapped | its identity subject's declared `username:`; else the entry's `username_attribute`, found by the SPIFFE ID (§13 decision 41 ruling 4, plan 8b) |
```

- [ ] **Step 4: §5.1.3, the scheduled refresh**

Replace

```markdown
`system:serviceaccount:`, `app:`) is never sent to the directory, until plan 8b builds a workload
certificate's opt-in directory mapping (§13 decisions 16 and 40 ruling 5): it is judged by the
policy alone and stamped with the pass's instant.
```

with

```markdown
`system:serviceaccount:`, `app:`) is never sent to the directory unless it is a workload
certificate whose verifier maps it (§13 decision 41 ruling 6, plan 8b, 2026-10-09), which is
verified and stamped as a `user:` principal is: it is otherwise judged by the policy alone and
stamped with the pass's instant.
```

- [ ] **Step 5: §5.7, four rows**

In the `identity_unmapped` row, replace

```markdown
or a leaf that is a CA (§13 decision 40), answered 401 at bind over HTTP, never as a TLS alert;
```

with

```markdown
or a leaf that is a CA (§13 decision 40), answered 401 at bind over HTTP, never as a TLS alert; or, under a workload certificate's directory mapping (§13 decision 41, plan 8b), its issuer is not one `broker.identity.machines[].directory.issuers` pins, no entry under `base_dn` holds its SPIFFE ID in the mapping's `attribute`, or the entry found holds that attribute with other than one value equal to the SPIFFE ID byte for byte; or, while that mapping is configured, a person's entry holds a SPIFFE ID in the mapping's `attribute`, so it is a workload's (§13 decision 41 ruling 4);
```

In the `identity_ambiguous` row, replace

```markdown
so two people would share one principal (§13 decision 38);
```

with

```markdown
so two people would share one principal (§13 decision 38); or when two entries hold a workload's SPIFFE ID in the workload mapping's `attribute` (§13 decision 41, plan 8b);
```

In the `directory_unavailable` row, replace

```markdown
(grace never overrules one) (§13 decision 38). Nothing is minted.
```

with

```markdown
(grace never overrules one) (§13 decision 38); for a workload under a directory mapping, the membership stored for its SPIFFE ID (§13 decision 41 ruling 7, plan 8b), which `port49 workload` retries within `--deadline` and then exits 75. Nothing is minted.
```

In the `username_collision` row, replace

```markdown
or a second directory entry holds the same username under `broker.directory.username_attribute` (§13 decision 38). At the broker's bind
```

with

```markdown
or a second directory entry holds the same username under `broker.directory.username_attribute` (§13 decision 38); or a workload under a directory mapping whose identity subject declares no username takes from its entry one a subject declares or a second entry holds (§13 decision 41 ruling 4, plan 8b). At the broker's bind
```

Run `grep -c "decision 41" docs/design/2026-08-23-policy-engine-spec.md`, and check the table still
renders: each row is one line, starting and ending with `|`.

- [ ] **Step 6: §12, the diff gate**

Replace

```markdown
subject's access is the group. A new group subject is gated as a new subject's principals are
(§13 decision 38).
```

with

```markdown
subject's access is the group. A new group subject is gated as a new subject's principals are
(§13 decision 38). `machine_group:` is gated the same way, and a subject moved between `group:` and
`machine_group:` with one value is a changed group (§13 decision 41 ruling 8, plan 8b).
```

- [ ] **Step 7: §14, workload certificates**

At the end of the "**Workload certificates** (§13 decision 40)" bullet (it ends `and
`attached_roles.humans` do\n  not.`), append:

```markdown
  Under a directory mapping (§13 decision 41, plan 8b): with no `directory:` the resolver is never
  asked for a workload; with it, a workload matches a `machine_group:` subject its entry's groups
  name and never a `group:` subject, and a `user:` principal never matches a `machine_group:`; an
  entry holding another case of the SPIFFE ID is `identity_unmapped` and two entries holding it
  `identity_ambiguous`; a workload whose subject declares the username its entry holds mints under
  it; an outage past grace refuses its mints `directory_unavailable`, `port49 workload` exits 75,
  and the scheduled refresh leaves its contexts unstamped.
```

- [ ] **Step 8: §15, L50 sharpened**

Replace the L50 row's claim cell (everything between `| **L50** | ` and `| §13 decision 40 ruling
5 (plan 8b's mapping kind) |`) with:

```markdown
Who can write the directory attribute a workload certificate's directory mapping reads (plan 8b; §13 decisions 16, 40 ruling 5 and 41 ruling 10): on Windows AD and on Samba AD, for a service account's entry in its own OU, and for each of `uid`, `description`, `wWWHomePage` and `url` holding a SPIFFE ID, whether the entry itself (`SELF`), a member of Account Operators, a delegated OU administrator ("create, delete and manage user accounts" on the OU) and an ordinary domain user can write it, under the default ACLs and under the ACL plan 8b's docs would prescribe (an inherited deny of write on that attribute on the OU for each writer that is not a domain administrator); and whether each write, accepted or refused, is in the directory's audit log as installed and with directory-change auditing turned on. Until it closes, no doc asserts who can write it (rule 1). Row text sharpened by plan 8b, 2026-10-09.
```

and replace the row's Depends-on cell `§13 decision 40 ruling 5 (plan 8b's mapping kind)` with `§13
decision 41 ruling 10 (the docs' ACL for the mapping's attribute)`. Leave Status `open`.

- [ ] **Step 9: Design §7**

Replace

```markdown
SPIFFE ID. Plan 8 builds no directory path for a workload, so its access is its identity
subject's; plan 8b owns the mapping (policy engine spec §13 decisions 16 and 40 ruling 5).
```

with

```markdown
SPIFFE ID. Plan 8 builds no directory path for a workload, so its access is its identity
subject's. Plan 8b builds the mapping, opt-in per verifier (policy engine spec §13 decision 41,
2026-10-09): `broker.identity.machines[].directory` with the weak, issuer-pinned `spiffe_id` kind,
whose entry must hold the SPIFFE ID byte for byte, and the `machine_group:` subject it alone
reaches. A workload under it mints only while a directory server answers or its membership is
within grace; who can write the attribute it reads is lab L50's to measure.
```

- [ ] **Step 10: Check and commit**

Run: `grep -n "decision 41" docs/design/2026-08-23-policy-engine-spec.md | wc -l` (expect 15 or
more) and `git diff --stat`. Expect two files.

```bash
git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git commit -m "docs(spec): decision 41, workload directory groups (plan 8b)

Opt-in per x509 machine verifier, the weak spiffe_id mapping kind, the
machine_group subject, the username (declared wins, else the entry's under
decision 38 ruling 3), the 3am case, and L50's claim sharpened. Amends
decisions 8, 16, 38 (rulings 1, 3, 12, 15, 20) and 40 ruling 5; widens four
section 5.7 rows; adds no reason code.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

**Operator notes (for plan 13):** none of their own; every later task's notes cite decision 41.

---

### Task 2: `internal/directory`: the `spiffe_id` mapping and the workload resolver

**Files:**
- Modify: `internal/directory/config.go` (`MapSPIFFEID`, `WorkloadMapping`, `Config.Workload`)
- Modify: `internal/directory/mapping.go` (`WorkloadMapping.Pinned`)
- Modify: `internal/directory/entry.go` (`usernameOf` factored out of `identityOf`;
  `entryAttrs` reads the workload attribute under a mapping; `notWorkload`; `workloadAttrs`,
  `workloadIdentityOf`, `workloadUnique`)
- Modify: `internal/directory/resolver.go` (`IsWorkload`, `lookup.workload`, `VerifyWorkload`,
  `CurrentWorkload`, `byWorkloadFilter`, `byWorkloadDN`; `verify`, `grace` and `pinned` take the
  workload path)
- Test: `internal/directory/workload_test.go`

**Interfaces:**
- Consumes: decision 41 rulings 2, 3 and 9 (Task 1).
- Produces, for Tasks 3, 5 and 6:
  - `const MapSPIFFEID MappingKind = "spiffe_id"`;
  - `type WorkloadMapping struct { Attribute string; Issuers []string; UserFilter string; TrustDomains []string }`;
  - `Config.Workload *WorkloadMapping` (nil: no mapping);
  - `func (w *WorkloadMapping) Pinned(leaf *x509.Certificate) error`;
  - `func IsWorkload(principal string) bool`;
  - `func (r *Resolver) VerifyWorkload(ctx context.Context, principal string) (Answer, error)`;
  - `func (r *Resolver) CurrentWorkload(ctx context.Context, principal string) (Answer, error)`;
  - `func (r *Resolver) byWorkloadDN(dn string) func(Searcher) (*ldap.Entry, error)` and
    `lookup.workload bool` (Task 6's pre-warm).

- [ ] **Step 1: Write the failing tests**

Create `internal/directory/workload_test.go`:

```go
package directory

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	wlID     = "spiffe://corp.example.com/host/oxidized-01"
	wlDN     = "CN=svc-oxidized-01,OU=Workloads,DC=corp"
	gBackup  = "CN=backup-hosts,OU=G,DC=corp"
	wlFilter = "(&(objectClass=user)(uid=" + wlID + "))"
)

// wlEntry is the workload's service account holding uid.
func wlEntry(uid ...string) *ldap.Entry {
	return entry(wlDN, map[string][]string{"uid": uid, "sAMAccountName": {"svc-oxidized-01"},
		"objectGUID": {"\x01\x02"}})
}

// newWorkloadWorld is newWorld with a workload mapping by uid, pinned to the
// world's issuer, and the workload's entry in backup-hosts.
func newWorkloadWorld(t *testing.T) *world {
	t.Helper()
	w := newWorld(t)
	w.r.Cfg.Workload = &WorkloadMapping{Attribute: "uid", Issuers: pin, UserFilter: "(objectClass=user)",
		TrustDomains: []string{"corp.example.com"}}
	e := wlEntry(wlID)
	w.dir.on(wlFilter, e)
	w.dir.on("(uid="+wlID+")", e)                   // workloadUnique
	w.dir.on("(sAMAccountName=svc-oxidized-01)", e) // usernameUnique
	w.dir.on(memberFilter(wlDN), grp(gBackup, "backup-hosts"))
	w.dir.on(uniqueFilter("backup-hosts"), grp(gBackup, "backup-hosts"))
	return w
}

// A workload is verified by its SPIFFE ID (decision 41 ruling 2): one search
// under base_dn by the workload filter, size limit 2; the principal is the ID,
// the username the entry's, the groups its groups, the entry pinned; no
// mapping key is written.
func TestAWorkloadIsVerifiedByItsSPIFFEID(t *testing.T) {
	w := newWorkloadWorld(t)
	a, err := w.r.VerifyWorkload(context.Background(), wlID)
	if err != nil || a.Principal != wlID || a.Username != "svc-oxidized-01" || a.Source != Fresh ||
		!slices.Equal(a.GroupNames, []string{"backup-hosts"}) || a.EntryID != "guid:0102" || len(a.MapKeys) != 0 {
		t.Fatalf("%+v %v", a, err)
	}
	first := w.dir.calls[0]
	if first.Filter != wlFilter || first.SizeLimit != 2 || first.BaseDN != "DC=corp" {
		t.Fatalf("the search: %+v", first)
	}
	if m, err := w.st.GetMembership(context.Background(), wlID); err != nil || m.Refused || m.EntryID != "guid:0102" {
		t.Fatalf("stored %+v %v", m, err)
	}
}

// A directory's matching rule may ignore case; a SPIFFE ID's path does not
// (decision 40 ruling 4). The entry found must hold the ID byte for byte, as
// its one value, or the workload is refused identity_unmapped, and the
// refusal is stored (Review Focus 1).
func TestAWorkloadEntryMustHoldItsIDByteForByte(t *testing.T) {
	for name, vals := range map[string][]string{
		"another case": {"spiffe://corp.example.com/host/Oxidized-01"},
		"two values":   {wlID, "spiffe://corp.example.com/host/oxidized-02"},
		"no value":     nil,
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorkloadWorld(t)
			w.dir.on(wlFilter, wlEntry(vals...))
			_, err := w.r.VerifyWorkload(context.Background(), wlID)
			if !errors.Is(err, ErrUnmapped) {
				t.Fatalf("%v", err)
			}
			if m, _ := w.st.GetMembership(context.Background(), wlID); !m.Refused {
				t.Fatalf("the refusal was not stored: %+v", m)
			}
		})
	}
	w := newWorkloadWorld(t)
	w.dir.on(wlFilter, wlEntry("spiffe://corp.example.com/host/Oxidized-01"))
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err == nil || !strings.Contains(err.Error(), "byte for byte") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// Two entries holding one SPIFFE ID, found by the uniqueness search with no
// user_filter, refuse it identity_ambiguous, never the first (decision 41
// ruling 2; Review Focus 1). Two cases: the twin holds the ID exactly, or
// another case of it that a case-insensitive matching rule returns for the
// ID. The search reads no values, so the variant is never waved through.
func TestTwoEntriesHoldingOneSPIFFEIDAreAmbiguous(t *testing.T) {
	for name, twin := range map[string]*ldap.Entry{
		"exact": entry("CN=alice,OU=Staff,DC=corp", map[string][]string{"uid": {wlID}}),
		"another case": entry("CN=svc-variant,OU=Staff,DC=corp",
			map[string][]string{"uid": {"spiffe://corp.example.com/host/Oxidized-01"}}),
	} {
		t.Run(name, func(t *testing.T) {
			w := newWorkloadWorld(t)
			w.dir.on("(uid="+wlID+")", wlEntry(wlID), twin)
			if _, err := w.r.VerifyWorkload(context.Background(), wlID); !errors.Is(err, ErrAmbiguous) ||
				!strings.Contains(err.Error(), "OU=Staff") {
				t.Fatalf("%v", err)
			}
		})
	}
}

// One entry, one domain (decision 41 ruling 4; pre-flight I-2): a service
// account holding both a userPrincipalName and a SPIFFE ID in the workload
// attribute is the workload's alone. Verify refuses it as a person,
// identity_unmapped naming the attribute; VerifyWorkload accepts it. A
// person whose uid holds no SPIFFE ID stays a person.
func TestOneEntryIsOneDomain(t *testing.T) {
	w := newWorkloadWorld(t)
	both := entry(wlDN, map[string][]string{"uid": {wlID}, "userPrincipalName": {"svc-oxidized-01@corp.example.com"},
		"sAMAccountName": {"svc-oxidized-01"}, "objectGUID": {"\x01\x02"}})
	w.dir.on(wlFilter, both)
	w.dir.on("(uid="+wlID+")", both)
	w.dir.on("(sAMAccountName=svc-oxidized-01)", both)
	w.dir.on("(&(objectClass=person)(userPrincipalName=svc-oxidized-01@corp.example.com))", both)
	w.dir.on("(userPrincipalName=svc-oxidized-01@corp.example.com)", both)
	_, err := w.r.Verify(context.Background(), "user:svc-oxidized-01@corp.example.com")
	if !errors.Is(err, ErrUnmapped) || !strings.Contains(err.Error(), "the entry is a workload's (uid)") {
		t.Fatalf("as a person: %v", err)
	}
	if a, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil || a.Principal != wlID {
		t.Fatalf("as a workload: %+v %v", a, err)
	}
	// alice's uid is a login name, no SPIFFE ID: she is still a person.
	a := entry(alice, map[string][]string{"userPrincipalName": {"alice@corp.example.com"},
		"sAMAccountName": {"alice"}, "mail": {"alice@corp.example.com"}, "uid": {"alice"}})
	w.dir.on("(&(objectClass=person)(userPrincipalName=alice@corp.example.com))", a)
	if _, err := w.r.Verify(context.Background(), alicePrincipal); err != nil {
		t.Fatalf("alice: %v", err)
	}
	// The person search reads the workload attribute, or the check sees nothing.
	if !slices.ContainsFunc(w.dir.calls, func(c *ldap.SearchRequest) bool {
		return c.Filter == "(&(objectClass=person)(userPrincipalName=alice@corp.example.com))" &&
			slices.Contains(c.Attributes, "uid")
	}) {
		t.Fatal("the person search does not read the workload attribute")
	}
}

// With no server answering, a workload is served from the store within
// grace and refused past it (decision 38 ruling 10; decision 41 ruling 7).
func TestAWorkloadInGraceAndPastIt(t *testing.T) {
	w := newWorkloadWorld(t)
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil {
		t.Fatal(err)
	}
	w.down()
	w.clk.Add(30 * time.Minute)
	a, err := w.r.CurrentWorkload(context.Background(), wlID)
	if err != nil || a.Source != Grace || !slices.Equal(a.GroupNames, []string{"backup-hosts"}) {
		t.Fatalf("within grace: %+v %v", a, err)
	}
	w.clk.Add(4 * time.Hour)
	if _, err := w.r.CurrentWorkload(context.Background(), wlID); !errors.Is(err, ErrUnavailable) ||
		!strings.Contains(err.Error(), "past directory.grace") {
		t.Fatalf("past grace: %v", err)
	}
}

// A workload's principal is pinned to its entry (decision 38 ruling 3):
// another entry claiming the ID later is identity_unmapped, naming forget.
func TestAWorkloadIsPinnedToItsEntry(t *testing.T) {
	w := newWorkloadWorld(t)
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil {
		t.Fatal(err)
	}
	moved := entry("CN=svc-new,OU=Workloads,DC=corp", map[string][]string{"uid": {wlID},
		"sAMAccountName": {"svc-new"}, "objectGUID": {"\x09\x09"}})
	w.dir.on(wlFilter, moved)
	w.dir.on("(uid="+wlID+")", moved)
	w.dir.on("(sAMAccountName=svc-new)", moved)
	_, err := w.r.VerifyWorkload(context.Background(), wlID)
	if !errors.Is(err, ErrUnmapped) || !strings.Contains(err.Error(), "port49 directory forget "+wlID) ||
		!strings.Contains(err.Error(), "a uid value moved") {
		t.Fatalf("%v", err)
	}
}

// The resolver leaves a workload's declared username to the broker (decision
// 41 ruling 4): a subject declaring the entry's username is no refusal here,
// fresh or in grace, since the subject may be the workload's own.
func TestTheResolverLeavesAWorkloadsDeclaredUsernameToTheBroker(t *testing.T) {
	w := newWorkloadWorld(t)
	w.r.Declared = func() map[string]string { return map[string]string{"svc-oxidized-01": "svc_oxidized"} }
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	w.down()
	if _, err := w.r.CurrentWorkload(context.Background(), wlID); err != nil {
		t.Fatalf("grace: %v", err)
	}
}

// Only a SPIFFE ID under a mapping is a workload to verify; Verify still
// takes user: alone (pre-flight I-10).
func TestOnlyAWorkloadUnderTheMappingIsVerified(t *testing.T) {
	w := newWorkloadWorld(t)
	if _, err := w.r.VerifyWorkload(context.Background(), alicePrincipal); !errors.Is(err, ErrNotUser) {
		t.Fatalf("a person: %v", err)
	}
	if _, err := w.r.Verify(context.Background(), wlID); !errors.Is(err, ErrNotUser) {
		t.Fatalf("Verify of a workload: %v", err)
	}
	w.r.Cfg.Workload = nil
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); !errors.Is(err, ErrNotUser) {
		t.Fatalf("no mapping: %v", err)
	}
	if !IsWorkload(wlID) || IsWorkload(alicePrincipal) || IsWorkload("SPIFFE://corp.example.com/x") {
		t.Fatal("IsWorkload")
	}
}

// The issuer pin (decision 41 ruling 2; decision 38 ruling 1): the leaf's
// issuer, read from its DER, must be one pinned.
func TestTheWorkloadIssuerPin(t *testing.T) {
	m := &WorkloadMapping{Attribute: "uid", Issuers: pin}
	if err := m.Pinned(leaf(t, nil)); err != nil {
		t.Fatalf("pinned: %v", err)
	}
	m.Issuers = []string{"CN=Other CA,DC=corp,DC=com"}
	if err := m.Pinned(leaf(t, nil)); err == nil || !strings.Contains(err.Error(), "is not one") {
		t.Fatalf("not pinned: %v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/directory/ -run 'Workload|SPIFFEID|OneDomain' -count=1`
Expected: FAIL to compile: `undefined: WorkloadMapping`, `VerifyWorkload`, `CurrentWorkload` and
`IsWorkload`.

- [ ] **Step 3: The config types**

In `internal/directory/config.go`, after `MapCN MappingKind = "cn"` inside the `const` block, add:

```go
	// MapSPIFFEID is a workload certificate's mapping (plan 8b; spec §13
	// decision 41 ruling 2): never broker.directory.certificate_mapping's, so
	// it is not in Kinds.
	MapSPIFFEID MappingKind = "spiffe_id"
```

After the `Mapping` type, add:

```go
// WorkloadMapping is broker.identity.machines[].directory resolved (plan 8b;
// spec §13 decision 41): a workload certificate's entry, found by the SPIFFE
// ID its attribute holds. It is weak (decision 38 ruling 1), so it is always
// issuer-pinned.
type WorkloadMapping struct {
	Attribute    string   // the entry attribute holding the SPIFFE ID; no default
	Issuers      []string // RFC 4514 DNs the leaf's issuer must be one of
	UserFilter   string   // resolved: the block's, else broker.directory.user_filter
	TrustDomains []string // the verifier's spiffe_trust_domains: what pre-warm takes from an entry
}
```

In `Config`, after `Mapping Mapping`, add:

```go
	// Workload is the workload certificate mapping, nil without one: then no
	// workload is ever sent to the directory (decision 40 ruling 5).
	Workload *WorkloadMapping
```

- [ ] **Step 4: The pin**

In `internal/directory/mapping.go`, after `ValidPin`, add:

```go
// Pinned is nil when leaf's issuer, read from its DER, is one w.Issuers pins
// (decision 41 ruling 2, as decision 38 ruling 1 pins every weak kind); else
// an error naming the issuer. The broker calls it at every reading of the
// certificate, before any search.
func (w *WorkloadMapping) Pinned(leaf *x509.Certificate) error {
	if pinned(leaf, w.Issuers) {
		return nil
	}
	return fmt.Errorf("its issuer %q is not one broker.identity.machines[].directory.issuers pins",
		printsafe.Line(nameString(leaf.RawIssuer), 300))
}
```

- [ ] **Step 5: The entry, read as a workload's**

In `internal/directory/entry.go`, replace the username half of `identityOf` (from `u, err :=
one(c.UsernameAttribute)` to the end of its `switch`) with a call, and add `usernameOf` beside it.
`identityOf` becomes:

```go
// identityOf derives the principal and username from e (Ruling 3).
func (c Config) identityOf(e *ldap.Entry) (Identity, error) {
	vs := e.GetAttributeValues(c.PrincipalAttribute)
	if len(vs) != 1 {
		return Identity{}, fmt.Errorf("%w: entry %s has %d values of %s; exactly one", ErrUnmapped,
			printsafe.Line(e.DN, 200), len(vs), c.PrincipalAttribute)
	}
	p := vs[0]
	if !asciiName(p) {
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not printable ASCII (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.PrincipalAttribute, len(p))
	}
	p = strings.ToLower(p)
	if !printable(p) || strings.ContainsAny(p, " \t") || !strings.Contains(p, "@") {
		return Identity{}, fmt.Errorf("%w: entry %s's %s is not a printable name with an @ (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.PrincipalAttribute, len(p))
	}
	u, err := c.usernameOf(e)
	if err != nil {
		return Identity{}, err
	}
	return Identity{DN: e.DN, EntryID: entryID(e), Principal: "user:" + p, Username: u}, nil
}

// usernameOf is e's username_attribute as a username (Ruling 3): one value,
// printable ASCII, lower-cased, canonical and not reserved.
func (c Config) usernameOf(e *ldap.Entry) (string, error) {
	vs := e.GetAttributeValues(c.UsernameAttribute)
	if len(vs) != 1 {
		return "", fmt.Errorf("%w: entry %s has %d values of %s; exactly one", ErrUnmapped,
			printsafe.Line(e.DN, 200), len(vs), c.UsernameAttribute)
	}
	u := vs[0]
	if !asciiName(u) {
		return "", fmt.Errorf("%w: entry %s's %s is not printable ASCII (%d bytes)", ErrUnmapped,
			printsafe.Line(e.DN, 200), c.UsernameAttribute, len(u))
	}
	u = strings.ToLower(u)
	switch {
	case !token.CanonicalUsername(u):
		return "", fmt.Errorf("%w: entry %s's %s is not a canonical username (printable ASCII, no "+
			"DOMAIN\\ prefix, no @suffix; %d bytes)", ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, len(u))
	case token.ReservedUsername(u):
		return "", fmt.Errorf("%w: entry %s's %s %q is reserved: the device's own account (spec §2)",
			ErrUnmapped, printsafe.Line(e.DN, 200), c.UsernameAttribute, u)
	}
	return u, nil
}
```

The messages are the ones `identityOf` had, so `entry_test.go` passes unchanged.

Replace `entryAttrs` with:

```go
// entryAttrs is what an entry search reads: the principal and username
// attributes, the mapping's, for KeysOf, both immutable ids, of which a
// directory holds one, and, under a workload mapping, its attribute, which
// notWorkload reads (decision 41 ruling 4).
func (c Config) entryAttrs() []string {
	attrs := []string{c.PrincipalAttribute, c.UsernameAttribute, c.Mapping.Attribute, "objectGUID", "entryUUID"}
	if c.Workload != nil {
		attrs = append(attrs, c.Workload.Attribute)
	}
	return attrs
}

// notWorkload is ErrUnmapped when e, read as a person's, holds a SPIFFE ID in
// the workload attribute (decision 41 ruling 4: one entry, one domain). Such
// an entry is a workload's: as a person's too, it would give a user:
// principal and a workload one (nas, username) context, and whichever minted
// last would hold the other's grants. A value that is no SPIFFE ID (an
// attribute such as description, set on people for other reasons) is no
// refusal. The scheme is compared in any case, failing closed.
func (c Config) notWorkload(e *ldap.Entry) error {
	if c.Workload == nil {
		return nil
	}
	for _, v := range e.GetAttributeValues(c.Workload.Attribute) {
		if strings.HasPrefix(strings.ToLower(v), spiffe.Scheme) {
			return fmt.Errorf("%w: entry %s: the entry is a workload's (%s): it holds a SPIFFE ID there, and one "+
				"entry is one trust domain, so it is never a person's principal (spec §13 decision 41 ruling 4)",
				ErrUnmapped, printsafe.Line(e.DN, 200), c.Workload.Attribute)
		}
	}
	return nil
}
```

After `principalUnique`, add:

```go
// workloadAttrs is what a workload entry search reads: the workload
// attribute, the username and both immutable ids (decision 41 ruling 2).
func (c Config) workloadAttrs() []string {
	return []string{c.Workload.Attribute, c.UsernameAttribute, "objectGUID", "entryUUID"}
}

// workloadIdentityOf is e as the workload it names (decision 41 rulings 2 and
// 4). With want, e's workload attribute must hold want as its one value, byte
// for byte: a SPIFFE ID's path is case-sensitive and a directory's matching
// rule need not be, so another case is no match. With no want (pre-warm), the
// value is read, and must be a SPIFFE ID in one of the verifier's trust
// domains. The username is usernameOf's.
func (c Config) workloadIdentityOf(e *ldap.Entry, want string) (Identity, error) {
	attr := c.Workload.Attribute
	vs := e.GetAttributeValues(attr)
	if len(vs) != 1 {
		return Identity{}, fmt.Errorf("%w: entry %s has %d values of %s; exactly one", ErrUnmapped,
			printsafe.Line(e.DN, 200), len(vs), attr)
	}
	p := vs[0]
	switch {
	case want != "" && p != want:
		return Identity{}, fmt.Errorf("%w: entry %s's %s is %s, which is not %s byte for byte: a SPIFFE ID's "+
			"path is case-sensitive, and the directory's matching rule found it anyway", ErrUnmapped,
			printsafe.Line(e.DN, 200), attr, printsafe.Line(p, 300), printsafe.Line(want, 300))
	case want == "":
		id, err := spiffe.ParseWorkload(p)
		if err != nil || !slices.Contains(c.Workload.TrustDomains, id.TrustDomain) {
			return Identity{}, fmt.Errorf("%w: entry %s's %s is not a SPIFFE ID in %s", ErrUnmapped,
				printsafe.Line(e.DN, 200), attr, strings.Join(c.Workload.TrustDomains, ", "))
		}
	}
	u, err := c.usernameOf(e)
	if err != nil {
		return Identity{}, err
	}
	return Identity{DN: e.DN, EntryID: entryID(e), Principal: p, Username: u}, nil
}

// workloadUnique is ErrAmbiguous when another entry under base_dn holds id's
// SPIFFE ID in the workload attribute, searched with no user_filter (decision
// 41 ruling 2, as principalUnique is decision 38 ruling 3's).
func (c Config) workloadUnique(s Searcher, id Identity) error {
	other, err := c.heldElsewhere(s, c.Workload.Attribute, id.Principal, id.DN)
	if err != nil || other == "" {
		return err
	}
	return fmt.Errorf("%w: %s %q is held by %s and by %s: two entries under one workload is an impersonation path",
		ErrAmbiguous, c.Workload.Attribute, printsafe.Line(id.Principal, 300), printsafe.Line(id.DN, 200),
		printsafe.Line(other, 200))
}
```

Add `"slices"` and `"github.com/blanketfish/port49/internal/spiffe"` to `entry.go`'s imports
(`internal/spiffe` is a standard-library-only leaf, so there is no cycle).

- [ ] **Step 6: The resolver**

In `internal/directory/resolver.go`:

1. After `IsUser`, add:

```go
// IsWorkload reports whether principal is a workload certificate's: a SPIFFE
// ID, as the verifier gives it, lower-case scheme (decision 40 ruling 4). The
// broker sends one to the directory only under a workload mapping
// (decision 41 ruling 1).
func IsWorkload(principal string) bool { return strings.HasPrefix(principal, spiffe.Scheme) }
```

2. In `lookup`, after `say string`, add:

```go
	// workload is a workload certificate's lookup (decision 41): the entry is
	// read by workloadIdentityOf, its SPIFFE ID checked by workloadUnique, no
	// mapping key is indexed, and no declared username is checked here, since
	// the broker settles a workload's username against its own subject
	// (ruling 4).
	workload bool
```

3. After `Verify`, add:

```go
// VerifyWorkload reads a workload's entry and groups from a server, never from
// grace (decision 41 ruling 2): the one entry whose workload attribute holds
// principal, under the workload user_filter. ErrNotUser without a workload
// mapping, or for a principal that is no SPIFFE ID.
func (r *Resolver) VerifyWorkload(ctx context.Context, principal string) (Answer, error) {
	if r.Cfg.Workload == nil || !IsWorkload(principal) {
		return Answer{}, fmt.Errorf("%w: %s is no workload under broker.identity.machines[].directory", ErrNotUser,
			printsafe.Line(principal, 300))
	}
	if r.static != nil {
		return r.answerStatic(principal)
	}
	w := r.Cfg.Workload
	filter := fmt.Sprintf("(&%s(%s=%s))", w.UserFilter, w.Attribute, ldap.EscapeFilter(principal))
	return r.verify(ctx, lookup{find: r.byWorkloadFilter(filter), want: principal, say: filter, workload: true})
}

// CurrentWorkload is the membership a workload's request uses: VerifyWorkload,
// else the store's within grace (decision 41 ruling 6).
func (r *Resolver) CurrentWorkload(ctx context.Context, principal string) (Answer, error) {
	if r.static != nil && r.Cfg.Workload != nil && IsWorkload(principal) {
		return r.answerStatic(principal)
	}
	a, err := r.VerifyWorkload(ctx, principal)
	if !errors.Is(err, ErrUnavailable) {
		return a, err
	}
	return r.grace(ctx, func(ctx context.Context) (store.Membership, error) {
		return r.Store.GetMembership(ctx, principal)
	}, err, principal, false)
}

// byWorkloadFilter finds the one entry filter matches under base_dn, reading
// the workload attributes.
func (r *Resolver) byWorkloadFilter(filter string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) { return r.Cfg.oneEntry(s, filter, r.Cfg.workloadAttrs()) }
}

// byWorkloadDN reads the entry at dn under the workload user_filter (pre-warm:
// a machine group's member).
func (r *Resolver) byWorkloadDN(dn string) func(Searcher) (*ldap.Entry, error) {
	return func(s Searcher) (*ldap.Entry, error) {
		res, err := s.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1,
			int(r.Cfg.QueryTimeout.Seconds()), false, r.Cfg.Workload.UserFilter, r.Cfg.workloadAttrs(), nil))
		switch {
		case ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject):
			return nil, fmt.Errorf("%w: no entry %s", ErrUnmapped, printsafe.Line(dn, 200))
		case err != nil:
			return nil, err
		case len(res.Entries) != 1:
			return nil, fmt.Errorf("%w: %s is not under the workload user_filter", ErrUnmapped, printsafe.Line(dn, 200))
		}
		return res.Entries[0], nil
	}
}
```

4. In `Map` and `Current`, pass `true` as `grace`'s new last argument.

5. In `verify`, replace the body of the `Pool.Do` closure from `e, err := q.find(s)` to `return
   err` with:

```go
		e, err := q.find(s)
		if err != nil {
			return err
		}
		if q.workload {
			id, err = r.Cfg.workloadIdentityOf(e, q.want)
		} else if err = r.Cfg.notWorkload(e); err == nil {
			// A person's entry must not be a workload's (decision 41
			// ruling 4): a bind, a mint, the scheduled refresh and pre-warm
			// all read a person through here.
			id, err = r.Cfg.identityOf(e)
		}
		if err != nil {
			return err
		}
		if !q.workload && q.want != "" && id.Principal != q.want {
			return fmt.Errorf("%w: the entry now gives %s", ErrUnmapped, id.Principal)
		}
		unique := r.Cfg.principalUnique
		if q.workload {
			unique = r.Cfg.workloadUnique
		}
		if err := unique(s, id); err != nil {
			refuse = id.Principal
			return err
		}
		if err := r.Cfg.usernameUnique(s, id); err != nil {
			refuse = id.Principal
			return err
		}
		if !q.workload {
			keys = r.Cfg.Mapping.KeysOf(e)
		}
		g, err = r.Cfg.groupsOf(s, id.DN)
		return err
```

   Then replace the pin and declared-username blocks after it:

```go
	if err == nil {
		// The pin (Ruling 3; pre-flight C-2): a principal the store holds
		// for another entry is refused, at a bind as on a re-verification.
		// No refusal is written for the principal here at a bind: it is
		// another person's, and its record (with its pin) stands. The line
		// is said once an hour per principal, naming the way out.
		attr := r.Cfg.PrincipalAttribute
		if q.workload {
			attr = r.Cfg.Workload.Attribute
		}
		if err = r.pinned(ctx, id, attr); errors.Is(err, ErrUnmapped) {
			r.sayOnce("pin:"+id.Principal, time.Hour, "%s", printsafe.Line(err.Error(), 900))
		}
	}
	if err == nil && !q.workload {
		if who, ok := r.declared()[id.Username]; ok {
			refuse = id.Principal
			err = fmt.Errorf("%w: the directory derives username %q for %s, which subject %q declares",
				ErrUsernameTaken, id.Username, id.Principal, who)
		}
	}
```

6. `pinned` takes the attribute it names. Change its signature to `func (r *Resolver) pinned(ctx
   context.Context, id Identity, attr string) error`, and in its message replace
   `r.Cfg.PrincipalAttribute` with `attr`.

7. `grace` gains the parameter `declared bool` after `who string`. Its declared-username check
   becomes `if subj, ok := r.declared()[m.Username]; declared && ok {`.

Add `"github.com/blanketfish/port49/internal/spiffe"` to `resolver.go`'s imports.

- [ ] **Step 7: Run the tests**

Run: `go test ./internal/directory/ -count=1`
Expected: PASS: every new test, and every existing one (`identityOf`'s messages are unchanged).

Run: `go vet ./internal/directory/ && go test -race ./internal/directory/ -count=1`
Expected: clean, PASS.

- [ ] **Step 8: Commit**

```bash
git add internal/directory/
git commit -m "feat(directory): the spiffe_id mapping and the workload resolver (decision 41)

VerifyWorkload and CurrentWorkload find a workload certificate's one entry
by the SPIFFE ID its attribute holds byte for byte, check it unique with no
user_filter, pin it, and serve it from grace; no mapping key is written, and
the declared-username check is the broker's. WorkloadMapping.Pinned is the
weak kind's issuer pin. Under a mapping, the person path refuses an entry
holding a SPIFFE ID in the workload attribute: one entry, one domain.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

**Operator notes (for plan 13):**
- A workload's entry must hold its SPIFFE ID, exactly as the certificate's URI SAN has it, as the
  one value of the mapping's `attribute`. Another case is refused `identity_unmapped`, as is a
  second value. Two entries holding one ID are both refused `identity_ambiguous`.
- An entry deleted and re-created is refused until `port49 directory forget spiffe://…` (Task 5),
  as a person's is.
- **One entry, one domain.** A service account whose entry holds a SPIFFE ID in the mapping's
  `attribute` is a workload. A person's certificate mapping to it is refused `identity_unmapped`
  ("the entry is a workload's"). Give a person who also runs a workload two entries.
- **Case.** A directory whose matching rule ignores case returns an entry holding another case of
  the ID; that makes the ID `identity_ambiguous`. Two workloads whose IDs differ only in case
  cannot both be mapped on such a directory.

---

### Task 3: `broker.identity.machines[].directory`

**Files:**
- Modify: `internal/oidc/config.go` (`WorkloadDirectory`, `X509Machine.Directory`)
- Modify: `internal/config/identity.go` (`workloadDirectoryYAML`; the machine x509 branch takes it;
  others refuse it)
- Modify: `internal/config/directory.go` (`checkWorkloadMapping`; `checkMapping` refuses
  `spiffe_id`; `prewarmYAML.MaxPrincipals`'s doc comment)
- Modify: `internal/config/config.go` (`checkBroker` resolves the block into
  `Directory.Workload`)
- Test: `internal/config/workload_directory_test.go`

**Interfaces:**
- Consumes: `directory.WorkloadMapping`, `directory.MapSPIFFEID` and `directory.ValidPin` (Task 2).
- Produces: `config.Config.Broker.Directory.Workload *directory.WorkloadMapping`, nil without the
  block (Tasks 5 and 6 read it).

- [ ] **Step 1: Write the failing tests**

Create `internal/config/workload_directory_test.go`:

```go
package config

import (
	"slices"
	"strings"
	"testing"
)

const mappedLists = `  identity:
    humans:
      - {type: x509, trust_anchor_file: /etc/port49/clients-ca.pem}
    machines:
      - type: x509
        trust_anchor_file: /etc/port49/workloads-ca.pem
        spiffe_trust_domains: [corp.example.com]
        directory:
          kind: spiffe_id
          attribute: uid
          allow_weak: true
          issuers: ["CN=Workloads Issuing CA,O=Corp"]
`

// withDirectoryBlock is cfg with a minimal broker.directory after
// certificate_status.
func withDirectoryBlock(t *testing.T, cfg string) string {
	t.Helper()
	ca := writeTemp(t, "ca.pem", testCAPEM(t))
	t.Setenv("PORT49_LDAP_PASSWORD", "x")
	return strings.Replace(cfg, "  certificate_status: {disabled: true}\n", `  certificate_status: {disabled: true}
  directory:
    servers:
      - {uri: "ldaps://dc-01.corp.example.com", priority: 100}
    ca_file: `+ca+`
    bind: {mechanism: simple, bind_dn: "CN=port49,DC=corp", password_env: PORT49_LDAP_PASSWORD}
    base_dn: "DC=corp,DC=example,DC=com"
    certificate_mapping: {kind: issuer_serial}
    nested_groups: in_chain
`, 1)
}

// The block resolves into broker.directory's Workload (decision 41 rulings 1
// and 2): user_filter defaults to broker.directory's, and the trust domains
// are the verifier's.
func TestAWorkloadDirectoryLoads(t *testing.T) {
	c, err := loadWith(t, withDirectoryBlock(t, brokerWithIdentity(mappedLists)))
	if err != nil {
		t.Fatal(err)
	}
	w := c.Broker.Directory.Workload
	if w == nil || w.Attribute != "uid" || !slices.Equal(w.Issuers, []string{"CN=Workloads Issuing CA,O=Corp"}) ||
		w.UserFilter != "(objectClass=person)" || !slices.Equal(w.TrustDomains, []string{"corp.example.com"}) {
		t.Fatalf("%+v", w)
	}
	own := strings.Replace(mappedLists, "          attribute: uid\n", "          attribute: uid\n          user_filter: \"(objectClass=user)\"\n", 1)
	c, err = loadWith(t, withDirectoryBlock(t, brokerWithIdentity(own)))
	if err != nil || c.Broker.Directory.Workload.UserFilter != "(objectClass=user)" {
		t.Fatalf("its own user_filter: %v", err)
	}
	// Without the block, no workload is mapped: plan 8's behaviour.
	plain := strings.Split(mappedLists, "        directory:\n")[0]
	c, err = loadWith(t, withDirectoryBlock(t, brokerWithIdentity(plain)))
	if err != nil || c.Broker.Directory.Workload != nil {
		t.Fatalf("no block: %+v %v", c.Broker.Directory, err)
	}
}

func TestWorkloadDirectoryRefusals(t *testing.T) {
	edit := func(old, new string) string { return strings.Replace(mappedLists, old, new, 1) }
	for name, c := range map[string]struct {
		lists string
		dir   bool
		want  string
	}{
		"no broker.directory": {mappedLists, false,
			"broker.identity.machines[].directory maps workload certificates through broker.directory, which is not configured"},
		"no kind":    {edit("          kind: spiffe_id\n", ""), true, `broker.identity.machines[].directory.kind "": spiffe_id`},
		"other kind": {edit("kind: spiffe_id", "kind: issuer_serial"), true, `directory.kind "issuer_serial": spiffe_id`},
		"no attribute": {edit("          attribute: uid\n", ""), true,
			"broker.identity.machines[].directory.attribute is required: no schema has one for a SPIFFE ID"},
		"a bad attribute": {edit("attribute: uid", "attribute: \"u id\""), true, "not an attribute descriptor"},
		"not weak":        {edit("          allow_weak: true\n", ""), true, "spiffe_id is a weak mapping: set allow_weak: true"},
		"no issuers": {edit("          issuers: [\"CN=Workloads Issuing CA,O=Corp\"]\n", ""), true,
			"directory.issuers: a weak mapping is pinned to its issuers"},
		"a bad pin": {edit("CN=Workloads Issuing CA,O=Corp", "no equals sign"), true, "is not an RFC 4514 DN"},
		"a bad user_filter": {edit("          attribute: uid\n", "          attribute: uid\n          user_filter: \"(objectClass=user\"\n"),
			true, "directory.user_filter"},
		"on a human x509": {"  identity:\n    humans: [{type: x509, trust_anchor_file: /a.pem, directory: {kind: spiffe_id}}]\n",
			true, "broker.identity.humans[0]: type x509 takes trust_anchor_file alone"},
		"on an oidc verifier": {"  identity:\n    machines: [{type: oidc, issuer: \"https://sso.corp.example.com/realms/corp\", audience: a, clients: [{client_id: svc, sub: s1}], directory: {kind: spiffe_id}}]\n",
			true, "broker.identity.machines[0].directory is an x509 machine verifier's"},
	} {
		cfg := brokerWithIdentity(c.lists)
		if c.dir {
			cfg = withDirectoryBlock(t, cfg)
		}
		if _, err := loadWith(t, cfg); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// spiffe_id is a workload's mapping, never a person's (decision 38 ruling 1
// amended by decision 41 ruling 2).
func TestSPIFFEIDIsNoPersonsMapping(t *testing.T) {
	_, err := checkMapping(mappingYAML{Kind: "spiffe_id", AllowWeak: true, Issuers: []string{"CN=X"}})
	if err == nil || !strings.Contains(err.Error(), "spiffe_id is a workload certificate's mapping: set it under "+
		"broker.identity.machines[].directory") {
		t.Fatalf("%v", err)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/config/ -run 'WorkloadDirectory|SPIFFEIDIsNoPersons' -count=1`
Expected: FAIL: the block is an unknown key (`field directory not found`), and `checkMapping`
lists the six kinds.

- [ ] **Step 3: `oidc.X509Machine.Directory`**

In `internal/oidc/config.go`, after the `X509Machine` type's `TrustDomains []string`, add a field,
and add the type after it:

```go
	// Directory is the verifier's directory: block as written (plan 8b; spec
	// §13 decision 41); nil without one. Config resolves it into
	// directory.Config.Workload once broker.directory is read.
	Directory *WorkloadDirectory
}

// WorkloadDirectory is broker.identity.machines[].directory as written.
type WorkloadDirectory struct {
	Kind, Attribute, UserFilter string
	AllowWeak                   bool
	Issuers                     []string
}
```

(The first line replaces the type's closing `}`.)

- [ ] **Step 4: The YAML and the verifier branches**

In `internal/config/identity.go`, add to `identityVerifierYAML` after `CAFile`:

```go
	Directory          *workloadDirectoryYAML `yaml:"directory"`
```

and after the type:

```go
// workloadDirectoryYAML is an x509 machine verifier's directory: (plan 8b;
// spec §13 decision 41).
type workloadDirectoryYAML struct {
	Kind       string   `yaml:"kind"`
	Attribute  string   `yaml:"attribute"`
	AllowWeak  bool     `yaml:"allow_weak"`
	Issuers    []string `yaml:"issuers"`
	UserFilter string   `yaml:"user_filter"`
}
```

In the machine x509 branch, replace `out.X509Machine = &oidc.X509Machine{AnchorFile:
v.TrustAnchorFile, TrustDomains: tds}` with:

```go
				out.X509Machine = &oidc.X509Machine{AnchorFile: v.TrustAnchorFile, TrustDomains: tds}
				if d := v.Directory; d != nil {
					out.X509Machine.Directory = &oidc.WorkloadDirectory{Kind: d.Kind, Attribute: d.Attribute,
						UserFilter: d.UserFilter, AllowWeak: d.AllowWeak, Issuers: d.Issuers}
				}
```

In the human x509 branch's refusal condition, add `|| v.Directory != nil` (its message, `type
x509 takes trust_anchor_file alone`, is unchanged). In `checkOIDCVerifier`, after the
`spiffe_trust_domains` refusal, add:

```go
	if v.Directory != nil {
		return oidc.VerifierConfig{}, fmt.Errorf("config: %s.directory is an x509 machine verifier's", at)
	}
```

- [ ] **Step 5: `checkWorkloadMapping`, and `spiffe_id` refused as a person's mapping**

In `internal/config/directory.go`, at the top of `checkMapping`, after `kind :=
directory.MappingKind(m.Kind)`, add:

```go
	if kind == directory.MapSPIFFEID {
		return directory.Mapping{}, fmt.Errorf("config: %skind spiffe_id is a workload certificate's mapping: set it "+
			"under broker.identity.machines[].directory", p)
	}
```

After `checkMapping`, add:

```go
// checkWorkloadMapping resolves an x509 machine verifier's directory: (plan 8b;
// spec §13 decision 41 rulings 1 and 2): spiffe_id alone, attribute required,
// weak so allow_weak and issuers required, user_filter defaulting to
// broker.directory's.
func checkWorkloadMapping(d oidc.WorkloadDirectory, trustDomains []string, userFilter string) (*directory.WorkloadMapping, error) {
	const p = "broker.identity.machines[].directory."
	switch {
	case directory.MappingKind(d.Kind) != directory.MapSPIFFEID:
		return nil, fmt.Errorf("config: %skind %q: spiffe_id, the one kind a workload's mapping takes (spec §13 "+
			"decision 41)", p, d.Kind)
	case d.Attribute == "":
		return nil, fmt.Errorf("config: %sattribute is required: no schema has one for a SPIFFE ID; name the "+
			"attribute your directory administrators reserve for it", p)
	case !descriptor.MatchString(d.Attribute):
		return nil, fmt.Errorf("config: %sattribute %q: not an attribute descriptor", p, d.Attribute)
	case !d.AllowWeak:
		return nil, fmt.Errorf("config: %s: spiffe_id is a weak mapping: set allow_weak: true and list the issuers "+
			"it is pinned to (design §7)", strings.TrimSuffix(p, "."))
	case len(d.Issuers) == 0:
		return nil, fmt.Errorf("config: %sissuers: a weak mapping is pinned to its issuers; list at least one "+
			"(design §7)", p)
	}
	for i, iss := range d.Issuers {
		if _, err := ldap.ParseDN(iss); err != nil || !strings.Contains(iss, "=") || !directory.ValidPin(iss) {
			return nil, fmt.Errorf("config: %sissuers[%d] %q is not an RFC 4514 DN", p, i, iss)
		}
	}
	w := &directory.WorkloadMapping{Attribute: d.Attribute, Issuers: d.Issuers, UserFilter: or(d.UserFilter, userFilter),
		TrustDomains: trustDomains}
	if _, err := ldap.CompileFilter(w.UserFilter); err != nil {
		return nil, fmt.Errorf("config: %suser_filter %q: %v", p, w.UserFilter, err)
	}
	return w, nil
}
```

The `not weak` message reads `broker.identity.machines[].directory: spiffe_id is a weak mapping:
…`. Add `"github.com/blanketfish/port49/internal/oidc"` to `directory.go`'s imports.

In the same file, give `prewarmYAML.MaxPrincipals` its doc comment (pre-flight M-5):

```go
	// MaxPrincipals bounds one pre-warm pass's principals. People and, under
	// a workload mapping, workloads (machine_group members and listed
	// spiffe:// identities) each take up to it, so one interval verifies up
	// to twice it (plan 8b; spec §13 decision 41 ruling 6).
	MaxPrincipals int            `yaml:"max_principals"`
```

- [ ] **Step 6: `checkBroker` resolves it**

In `internal/config/config.go`, in `checkBroker`, after the `if b.DirectorySet != nil { … }`
block, add:

```go
	// A workload certificate's directory (plan 8b; spec §13 decision 41 ruling
	// 1) reuses broker.directory's pool, bind and base_dn, so it needs one.
	if m := id.X509Machine; m != nil && m.Directory != nil {
		if b.Directory == nil {
			return nil, errors.New("config: broker.identity.machines[].directory maps workload certificates through " +
				"broker.directory, which is not configured: configure it, or remove directory to keep workloads off " +
				"the directory")
		}
		w, err := checkWorkloadMapping(*m.Directory, m.TrustDomains, b.Directory.UserFilter)
		if err != nil {
			return nil, err
		}
		b.Directory.Workload = w
	}
```

- [ ] **Step 7: Run the tests**

Run: `go test ./internal/config/ ./internal/oidc/ -count=1 && go vet ./internal/config/ ./internal/oidc/`
Expected: PASS, clean. `TestWorkloadVerifierRefusals` passes unchanged: its `an oidc key on it`
case still reads `takes trust_anchor_file and spiffe_trust_domains alone`.

- [ ] **Step 8: Commit**

```bash
git add internal/oidc/config.go internal/config/
git commit -m "feat(config): broker.identity.machines[].directory (decision 41)

The x509 machine verifier takes a directory: block, spiffe_id alone, attribute
required, weak so allow_weak and issuers required, user_filter defaulting to
broker.directory's; it needs broker.directory. spiffe_id under
certificate_mapping is refused.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

**Operator notes (for plan 13):**
- **Configuration.** Under the `x509` entry of `broker.identity.machines`:

  ```yaml
  directory:
    kind: spiffe_id
    attribute: <the attribute your directory administrators reserve>
    allow_weak: true
    issuers: [<the RFC 4514 DN of the CA that issues workload leaves>]
    user_filter: "(objectClass=user)"   # optional; default broker.directory.user_filter
  ```

  It needs `broker.directory`, whose servers, bind, `base_dn`, `username_attribute`, nested mode,
  grace and pre-warm it uses.
- **Which attribute, and its ACL,** waits for L50. Until then the docs name the requirement (only
  directory administrators may write it) and no attribute as safe.
- **Leaving it out** keeps plan 8's behaviour: no workload reaches the directory.

---

### Task 4: `internal/policy`: the `machine_group:` subject, matched per domain

**Files:**
- Modify: `internal/policy/file.go` (`fileSubject.MachineGroup`)
- Modify: `internal/policy/load.go` (`Env.WorkloadDirectory`; `buildSubjects`; `checkMinters`;
  `Subject.GroupKey`; `allSPIFFE`)
- Modify: `internal/policy/member.go` (`DomainHumans`, `DomainMachines`; `Member.Domain`;
  `subjectsOf` and `groupDomainOf`; `DeclaredFor`; `GroupValues`, `GroupSubjects`,
  `MachineGroupValues`, `MachineGroupSubjects`)
- Modify: `internal/policy/diff.go` (`SubjectChange.OldGroupKey`, `NewGroupKey`; `sameGroup`)
- Modify: `internal/policy/lint.go` (`FindingGroupSubject`'s text names the key and when it mints;
  the controller's ruling, pre-flight I-5)
- Modify: `cmd/port49/policy.go` (the diff report line; access review's `who`)
- Test: `internal/policy/machine_group_test.go`; `internal/policy/lint_test.go`
  (`TestLintSaysWhenAGroupSubjectMints`); `cmd/port49/policy_test.go`
  (`TestPolicyDiffNamesAMachineGroup`)

**Interfaces:**
- Consumes: decision 41 rulings 4, 5 and 8 (Task 1).
- Produces, for Tasks 5 and 6:
  - `const DomainHumans = "humans"` and `const DomainMachines = "machines"`;
  - `Member.Domain string`;
  - `Env.WorkloadDirectory DirectoryMode`;
  - `func (p *Policy) DeclaredFor(principal string) string`;
  - `func (p *Policy) MachineGroupValues() []string` and `func (p *Policy) MachineGroupSubjects()
    []string`;
  - `func (s *Subject) GroupKey() string` (`""`, `"group"` or `"machine_group"`);
  - `SubjectChange.OldGroupKey` and `NewGroupKey`.

- [ ] **Step 1: Write the failing tests**

Create `internal/policy/machine_group_test.go`:

```go
package policy

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

const machineYAML = `
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: ro, privilege: readonly, permit: ["show **"]}
  - {name: backup, privilege: admin, permit: ["show running-config"]}
subjects:
  - {name: netops_ro, group: netops-ro, token_ttl: 15m}
  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 15m}
  - {name: backup_dn, machine_group: "CN=Backup-DN,OU=G,DC=corp", token_ttl: 15m}
  - {name: shared_people, group: shared, token_ttl: 15m}
  - {name: shared_hosts, machine_group: shared, token_ttl: 15m}
grants:
  - {subject: netops_ro, scope: all_devices, roles: [ro]}
  - {subject: backup_hosts, scope: all_devices, roles: [backup]}
  - {subject: backup_dn, scope: all_devices, roles: [backup]}
  - {subject: shared_people, scope: all_devices, roles: [ro]}
  - {subject: shared_hosts, scope: all_devices, roles: [backup]}
`

func loadWorkloadText(t *testing.T, body string, mode DirectoryMode) (*Policy, error) {
	t.Helper()
	e := env()
	e.Directory, e.WorkloadDirectory = DirectoryOn, mode
	return Parse([]byte(body), e)
}

func machinePolicy(t *testing.T, mode DirectoryMode) *Policy {
	t.Helper()
	p, err := loadWorkloadText(t, machineYAML, mode)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

const wlPrincipal = "spiffe://corp.example.com/host/oxidized-01"

// everyGroup is in every group the policy names, by name and by DN.
func everyGroup(m Member) Member {
	m.GroupNames = []string{"backup-hosts", "netops-ro", "shared"}
	m.GroupDNs = []string{"cn=backup-dn,ou=G,dc=corp"}
	return m
}

// A machine_group subject matches a workload resolved through the mapping,
// and a group subject a person; never across (decision 41 ruling 5; Review
// Focus 3). One group named both ways matches each in its own domain.
func TestAMachineGroupMatchesAWorkloadAlone(t *testing.T) {
	p := machinePolicy(t, DirectoryOn)
	wl := everyGroup(Member{Principal: wlPrincipal, Domain: DomainMachines, Directory: true, Username: "svc"})
	if got := p.SubjectsOf(wl); !slices.Equal(got, []string{"backup_dn", "backup_hosts", "shared_hosts"}) {
		t.Fatalf("the workload: %v", got)
	}
	person := everyGroup(Member{Principal: "user:alice@corp.example.com", Directory: true, Username: "alice"})
	if got := p.SubjectsOf(person); !slices.Equal(got, []string{"netops_ro", "shared_people"}) {
		t.Fatalf("the person: %v", got)
	}
	// A domain the principal's form contradicts matches nothing, either way.
	for _, m := range []Member{
		everyGroup(Member{Principal: wlPrincipal, Domain: DomainHumans, Directory: true}),
		everyGroup(Member{Principal: wlPrincipal, Directory: true}),
		everyGroup(Member{Principal: "user:alice@corp.example.com", Domain: DomainMachines, Directory: true}),
		everyGroup(Member{Principal: wlPrincipal, Domain: DomainMachines}),
	} {
		if got := p.SubjectsOf(m); len(got) != 0 {
			t.Fatalf("%+v matched %v", m, got)
		}
	}
}

// With the mapping off, no machine_group subject matches anyone.
func TestNoMachineGroupMatchesWithTheMappingOff(t *testing.T) {
	p := machinePolicy(t, DirectoryOff)
	wl := everyGroup(Member{Principal: wlPrincipal, Domain: DomainMachines, Directory: true, Username: "svc"})
	if got := p.SubjectsOf(wl); len(got) != 0 {
		t.Fatalf("%v", got)
	}
}

// A workload resolves with the username its member carries, and the
// machine_group's grants.
func TestAMachineGroupResolvesWithItsMembersUsername(t *testing.T) {
	p := machinePolicy(t, DirectoryOn)
	wl := Member{Principal: wlPrincipal, Domain: DomainMachines, Directory: true, Username: "svc-oxidized-01",
		GroupNames: []string{"backup-hosts"}}
	res, err := p.ResolveMember(wl, device(t, p, "leaf-01"), now)
	if err != nil || res.Subject != "backup_hosts" || res.Username != "svc-oxidized-01" || !slices.Equal(res.Roles, []string{"backup"}) {
		t.Fatalf("%+v %v", res, err)
	}
	wl.Username = ""
	if _, err := p.ResolveMember(wl, device(t, p, "leaf-01"), now); !errors.Is(err, ErrNoUsername) {
		t.Fatalf("no username: %v", err)
	}
}

func TestOneSubjectOfBothDomainsIsALoadError(t *testing.T) {
	for name, c := range map[string]struct{ subject, want string }{
		"both keys": {`{name: a, group: g, machine_group: g, token_ttl: 5m}`,
			"group names people and machine_group names workloads; a subject is one trust domain"},
		"a machine_group and identities": {`{name: a, machine_group: g, identity: ["spiffe://corp.example.com/x"], token_ttl: 5m}`,
			"a subject is a group or a list of identities, not both"},
		"a username on a machine_group": {`{name: a, machine_group: g, username: svc, token_ttl: 5m}`,
			"a machine_group's members take the username their identity subject declares, or their entry's"},
		"an equals sign that is no DN": {`{name: a, machine_group: "CN=a,,", token_ttl: 5m}`,
			`machine_group "CN=a,," holds = but is not a DN`},
	} {
		_, err := loadWorkloadText(t, "subjects: ["+c.subject+"]\n"+minimalGrant, DirectoryOn)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

// A machine_group subject is a machines subject: attached_roles.machines
// reach it. Pre-warm and the start read the two kinds apart (Review Focus 5).
func TestAMachineGroupIsAMachinesSubject(t *testing.T) {
	p := machinePolicy(t, DirectoryOn)
	s, _ := p.Subject("backup_hosts")
	if s.Domain != DomainMachines || s.GroupKey() != "machine_group" {
		t.Fatalf("%+v", s)
	}
	if h, _ := p.Subject("netops_ro"); h.GroupKey() != "group" {
		t.Fatalf("%+v", h)
	}
	if !slices.Equal(p.GroupValues(), []string{"netops-ro", "shared"}) ||
		!slices.Equal(p.MachineGroupValues(), []string{"CN=Backup-DN,OU=G,DC=corp", "backup-hosts", "shared"}) ||
		!slices.Equal(p.GroupSubjects(), []string{"netops_ro", "shared_people"}) ||
		!slices.Equal(p.MachineGroupSubjects(), []string{"backup_dn", "backup_hosts", "shared_hosts"}) {
		t.Fatalf("%v %v %v %v", p.GroupValues(), p.MachineGroupValues(), p.GroupSubjects(), p.MachineGroupSubjects())
	}
}

// DeclaredFor is the username the identity subject listing a principal
// declares (decision 41 ruling 4).
func TestDeclaredFor(t *testing.T) {
	p, err := loadWorkloadText(t, `subjects: [{name: a, identity: ["`+wlPrincipal+`"], username: svc-oxidized, token_ttl: 5m}]`+
		"\n"+minimalGrant, DirectoryOn)
	if err != nil {
		t.Fatal(err)
	}
	if p.DeclaredFor(wlPrincipal) != "svc-oxidized" || p.DeclaredFor("spiffe://corp.example.com/other") != "" {
		t.Fatal("DeclaredFor")
	}
}

// Under the mapping, a spiffe://-only subject takes its entry's username and
// need not declare one; an app: identity still must (decision 41 ruling 4).
func TestASPIFFEOnlySubjectNeedsNoUsernameUnderTheMapping(t *testing.T) {
	spiffeOnly := `subjects: [{name: a, identity: ["` + wlPrincipal + `"], token_ttl: 5m}]` + "\n" + minimalGrant
	for _, mode := range []DirectoryMode{DirectoryOn, DirectoryUnknown} {
		if _, err := loadWorkloadText(t, spiffeOnly, mode); err != nil {
			t.Fatalf("mode %d: %v", mode, err)
		}
	}
	if _, err := loadWorkloadText(t, spiffeOnly, DirectoryOff); err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("off: %v", err)
	}
	withApp := `subjects: [{name: a, identity: ["` + wlPrincipal + `", "app:oxidized"], token_ttl: 5m}]` + "\n" + minimalGrant
	if _, err := loadWorkloadText(t, withApp, DirectoryOn); err == nil || !strings.Contains(err.Error(), "username is required") {
		t.Fatalf("an app: identity: %v", err)
	}
}

// A changed machine_group fails the gate until a session test names the
// subject; a new one is gated; a group moved to machine_group with one value
// is a change (decision 41 ruling 8; Review Focus 3).
func TestAChangedMachineGroupIsGated(t *testing.T) {
	before := loadDiff(t, `subjects: [{name: oncall, machine_group: backup-hosts, token_ttl: 5m}]`+grantOnCall)
	after := loadDiff(t, `subjects: [{name: oncall, machine_group: other-hosts, token_ttl: 5m}]`+grantOnCall)
	if d := Compare(before, after, noon); d.UnacknowledgedPrincipals() != 1 {
		t.Fatalf("%+v", d.Subjects)
	}
	tested := loadDiff(t, `subjects: [{name: oncall, machine_group: other-hosts, token_ttl: 5m}]`+grantOnCall+
		"\ntests: [{subject: oncall, device: leaf-01, level: readonly}]")
	if d := Compare(before, tested, noon); d.UnacknowledgedPrincipals() != 0 {
		t.Fatalf("acknowledged: %+v", d.Subjects)
	}
}

func TestAGroupMovedToMachineGroupIsGated(t *testing.T) {
	before := loadDiff(t, `subjects: [{name: oncall, group: backup-hosts, token_ttl: 5m}]`+grantOnCall)
	after := loadDiff(t, `subjects: [{name: oncall, machine_group: backup-hosts, token_ttl: 5m}]`+grantOnCall)
	d := Compare(before, after, noon)
	if d.UnacknowledgedPrincipals() != 1 || len(d.Subjects) != 1 || d.Subjects[0].OldGroupKey != "group" ||
		d.Subjects[0].NewGroupKey != "machine_group" {
		t.Fatalf("%+v", d.Subjects)
	}
	// An identity subject added is still gated by its principals, not as a group.
	added := loadDiff(t, `subjects: [{name: oncall, group: backup-hosts, token_ttl: 5m}, {name: x, identity: ["app:x"], username: x, token_ttl: 5m}]`+grantOnCall)
	for _, s := range Compare(before, added, noon).Subjects {
		if s.Subject == "x" {
			t.Fatalf("an identity subject reported as a group change: %+v", s)
		}
	}
}
```

In `internal/policy/lint_test.go`, add:

```go
// A group subject's finding names its key and the config it mints under
// (decision 41 ruling 5; pre-flight I-5): group: through broker.directory,
// machine_group: through a workload verifier's directory mapping. Neither
// says "plan 7".
func TestLintSaysWhenAGroupSubjectMints(t *testing.T) {
	p := mustParse(t, `
scopes: [{name: all_devices, match: {}}]
roles: [{name: ro, privilege: readonly, permit: [show **]}]
subjects:
  - {name: people, group: netops, token_ttl: 60s}
  - {name: hosts, machine_group: backup-hosts, token_ttl: 60s}
grants:
  - {subject: people, scope: all_devices, roles: [ro]}
  - {subject: hosts, scope: all_devices, roles: [ro]}
`)
	var got []string
	for _, f := range p.Lint(noon) {
		if f.Kind == FindingGroupSubject {
			got = append(got, f.Message)
		}
	}
	slices.Sort(got)
	want := []string{
		`subject "hosts" is a machine_group: subject: it mints only with broker.identity.machines[].directory ` +
			`configured (a workload certificate's directory mapping), through which the broker matches a workload ` +
			`to the group; explain and policy tests evaluate it by name`,
		`subject "people" is a group: subject: it mints only with broker.directory configured, through which ` +
			`the broker matches a person to the group; explain and policy tests evaluate it by name`,
	}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
```

In `cmd/port49/policy_test.go`, add:

```go
// The diff report names the key a group subject uses (decision 41 ruling 8).
func TestPolicyDiffNamesAMachineGroup(t *testing.T) {
	_, inv := policyFixture(t)
	dir := t.TempDir()
	body := func(key string) []byte {
		return []byte("scopes: [{name: all_devices, match: {}}]\nroles: [{name: ro, privilege: readonly, permit: [show **]}]\n" +
			"subjects: [{name: backup, " + key + ": backup-hosts, token_ttl: 5m}]\n" +
			"grants: [{subject: backup, scope: all_devices, roles: [ro]}]\n")
	}
	oldPol, newPol := filepath.Join(dir, "old.yaml"), filepath.Join(dir, "new.yaml")
	if err := os.WriteFile(oldPol, body("group"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPol, body("machine_group"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 1 ||
		!strings.Contains(out.String(), `subject: backup's group "backup-hosts" -> machine_group "backup-hosts"`) {
		t.Fatalf("code %d\n%s%s", code, out.String(), errb.String())
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/policy/ -run 'MachineGroup|DeclaredFor|SPIFFEOnly|BothDomains|WhenAGroupSubjectMints' -count=1`
Expected: FAIL to compile: `undefined: DomainMachines`, `Member.Domain`, `GroupKey`,
`MachineGroupValues`, `DeclaredFor`, `Env.WorkloadDirectory`. (Once it compiles,
`TestLintSaysWhenAGroupSubjectMints` fails on the text until Step 8.)

- [ ] **Step 3: The file and the environment**

In `internal/policy/file.go`'s `fileSubject`, after `Group`, add:

```go
	MachineGroup string        `yaml:"machine_group"`
```

In `internal/policy/load.go`'s `Env`, after `Directory DirectoryMode`, add:

```go
	// WorkloadDirectory is whether this process's workload verifier maps a
	// workload certificate through the directory (plan 8b; spec §13 decision
	// 41): on, off, or unknown to an offline tool, which then matches
	// machine_group subjects and asks a spiffe://-only subject for no username.
	WorkloadDirectory DirectoryMode
```

In `Subject`, replace the `Group string` line with:

```go
	// Group is a group subject's group: or machine_group: value; Domain says
	// which (humans for group:, machines for machine_group:).
	Group    string
```

and add, after the `Subject` type:

```go
// GroupKey is the key a group subject was written with: "group",
// "machine_group", or "" for an identity subject.
func (s *Subject) GroupKey() string {
	switch {
	case s.Group == "":
		return ""
	case s.Domain == DomainMachines:
		return "machine_group"
	}
	return "group"
}
```

- [ ] **Step 4: `buildSubjects`**

In `buildSubjects`, replace from `sub := &Subject{Name: s.Name, Group: s.Group, …` through the end
of the `switch` that sets `sub.Domain = "humans"` (it ends after the `remove username` error) with:

```go
		sub := &Subject{Name: s.Name, Group: cmp.Or(s.Group, s.MachineGroup), Identity: s.Identity,
			Username: s.Username, Enable: s.Enable, TokenTTL: s.TokenTTL, API: s.API}
		switch {
		case s.Group != "" && s.MachineGroup != "":
			return fmt.Errorf("subject %q: group names people and machine_group names workloads; a subject is one "+
				"trust domain, so give each its own subject (spec §2; §13 decision 41 ruling 5)", s.Name)
		case sub.Group != "" && len(s.Identity) > 0:
			return fmt.Errorf("subject %q: a subject is a group or a list of identities, not both (spec §2)", s.Name)
		case sub.Group == "" && len(s.Identity) == 0:
			return fmt.Errorf("subject %q: give it a group or an identity list (spec §2)", s.Name)
		case sub.Group != "":
			// A group: is resolved through the directory, whose members are
			// people, each username from the same query (spec §2). A
			// machine_group: is resolved through the workload mapping, whose
			// members are workloads (decision 41 ruling 5). Neither declares a
			// username: one name would be every member's.
			key := "group"
			sub.Domain = DomainHumans
			if s.MachineGroup != "" {
				sub.Domain, key = DomainMachines, "machine_group"
			}
			if strings.Contains(sub.Group, "=") {
				if _, err := ldap.ParseDN(sub.Group); err != nil {
					return fmt.Errorf("subject %q: %s %q holds = but is not a DN", s.Name, key, sub.Group)
				}
				sub.groupDN = directory.CanonicalDN(sub.Group)
			}
			switch {
			case s.Username != "" && key == "group":
				return fmt.Errorf("subject %q: a group's usernames come from the directory, one per member; "+
					"remove username", s.Name)
			case s.Username != "":
				return fmt.Errorf("subject %q: a machine_group's members take the username their identity subject "+
					"declares, or their entry's (§13 decision 41 ruling 4); remove username", s.Name)
			}
		}
```

Add `"cmp"` to the imports.

- [ ] **Step 5: `checkMinters`**

Replace the loop's first `if` in `checkMinters` with:

```go
		needsName := len(s.Identity) > 0 && s.Username == "" && (s.Domain == DomainMachines || p.env.Directory == DirectoryOff)
		// A workload certificate's entry gives its username where the
		// verifier maps it (decision 41 ruling 4); an offline tool does not
		// know, and asks for none. An app: identity has no entry.
		if needsName && s.Domain == DomainMachines && p.env.WorkloadDirectory != DirectoryOff && allSPIFFE(s.Identity) {
			needsName = false
		}
		if needsName {
			// A machine has no directory entry, so it declares its username
			// (spec §2). A human identity declares one too when no directory
			// supplies it (plan 7g, Ruling 16).
			return fmt.Errorf("subject %q: username is required: a grant names it, and an identity-list subject "+
				"has no directory to derive one from (spec §2; §14, \"Username resolution\")", s.Name)
		}
```

and after `checkMinters`, add:

```go
// allSPIFFE reports whether every identity is a workload certificate's.
func allSPIFFE(ids []string) bool {
	return !slices.ContainsFunc(ids, func(id string) bool { return !strings.HasPrefix(id, spiffe.Scheme) })
}
```

Replace the literals `"humans"` and `"machines"` that `identityDomain` returns, and the other
literals in `load.go`, with `DomainHumans` and `DomainMachines`. Leave `Attached`'s map keys, which
are YAML's `attached_roles.humans` and `.machines`; they are the same strings.

- [ ] **Step 6: `member.go`**

In `internal/policy/member.go`, before `Member`, add:

```go
// The trust domains, as a Subject's Domain and attached_roles name them.
const (
	DomainHumans   = "humans"
	DomainMachines = "machines"
)
```

In `Member`, after `Principal string`, add:

```go
	// Domain is the verifier's list the principal came from: DomainMachines
	// for a workload the broker resolved through the workload mapping
	// (decision 41), DomainHumans or "" for a person.
	Domain string
```

Replace the group loop in `subjectsOf` with:

```go
	// A group subject matches people and a machine_group subject workloads,
	// each only its own domain's (design §7; decision 41 ruling 5).
	if domain := p.groupDomainOf(m); domain != "" {
		for _, name := range sortedKeys(p.subs) {
			if sub := p.subs[name]; sub.Group != "" && sub.Domain == domain && sub.matches(m) {
				out = append(out, sub)
			}
		}
	}
```

and add, after `subjectsOf`:

```go
// groupDomainOf is the domain whose group subjects m may match: humans for a
// user: principal the directory resolved, machines for a workload's SPIFFE ID
// resolved through the workload mapping, "" otherwise. Both the member's
// domain and the principal's form must agree, so a mislabeled member matches
// no group at all.
func (p *Policy) groupDomainOf(m Member) string {
	switch {
	case !m.Directory:
		return ""
	case m.Domain != DomainMachines && strings.HasPrefix(m.Principal, "user:") && p.env.Directory != DirectoryOff:
		return DomainHumans
	case m.Domain == DomainMachines && strings.HasPrefix(m.Principal, spiffe.Scheme) &&
		p.env.WorkloadDirectory != DirectoryOff:
		return DomainMachines
	}
	return ""
}

// DeclaredFor is the username the identity subject listing principal declares,
// "" when none lists it or it declares none (decision 41 ruling 4).
func (p *Policy) DeclaredFor(principal string) string {
	if name, ok := p.byID[principal]; ok {
		return p.subs[name].Username
	}
	return ""
}
```

Replace `GroupValues` and `GroupSubjects` with the four:

```go
// GroupValues is every group: subject's value, once each, sorted: the people
// pre-warm enumerates (Ruling 20). A machine_group: is never in it.
func (p *Policy) GroupValues() []string { return p.groupValues(DomainHumans) }

// MachineGroupValues is every machine_group: subject's value, once each,
// sorted: the workloads pre-warm enumerates (decision 41 ruling 6).
func (p *Policy) MachineGroupValues() []string { return p.groupValues(DomainMachines) }

func (p *Policy) groupValues(domain string) []string {
	var out []string
	for _, s := range p.subs {
		if s.Group != "" && s.Domain == domain {
			out = append(out, s.Group)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// GroupSubjects is every group: subject's name, sorted.
func (p *Policy) GroupSubjects() []string { return p.groupSubjects(DomainHumans) }

// MachineGroupSubjects is every machine_group: subject's name, sorted.
func (p *Policy) MachineGroupSubjects() []string { return p.groupSubjects(DomainMachines) }

func (p *Policy) groupSubjects(domain string) []string {
	var out []string
	for _, name := range sortedKeys(p.subs) {
		if s := p.subs[name]; s.Group != "" && s.Domain == domain {
			out = append(out, name)
		}
	}
	return out
}
```

- [ ] **Step 7: The diff and its report**

In `internal/policy/diff.go`, add to `SubjectChange` after `OldGroup, NewGroup string`'s line:

```go
	// OldGroupKey and NewGroupKey are the keys the group was written with,
	// "group" or "machine_group" ("" for none): moving between them is a
	// changed group (decision 41 ruling 8).
	OldGroupKey, NewGroupKey string
```

Replace the `sameGroup` line with:

```go
		// A group given as a DN is the same group in any spelling; one moved
		// between group: and machine_group: is another (decision 41 ruling 8).
		sameGroup := was.GroupKey() == is.GroupKey() &&
			(was.Group == is.Group || (was.groupDN != "" && was.groupDN == is.groupDN))
```

and add `OldGroupKey: was.GroupKey(), NewGroupKey: is.GroupKey(),` to the `SubjectChange` literal.
A new subject's `was` is `&Subject{Username: is.Username}`, whose `GroupKey` is `""`. A new identity
subject keeps `""` on both sides, so it is not reported as a group change.

In `cmd/port49/policy.go`, replace

```go
		if s.OldGroup != s.NewGroup {
			fmt.Fprintf(stdout, "subject: %s's group %q -> %q; a group subject mints for no one until plan 7\n", s.Subject,
				s.OldGroup, s.NewGroup)
		}
```

with

```go
		if s.OldGroup != s.NewGroup || s.OldGroupKey != s.NewGroupKey {
			fmt.Fprintf(stdout, "subject: %s's %s %q -> %s %q\n", s.Subject, cmp.Or(s.OldGroupKey, "group"),
				s.OldGroup, cmp.Or(s.NewGroupKey, "group"), s.NewGroup)
		}
```

and in `port49 access review`, replace `who := "group " + s.Group` with `who := s.GroupKey() + " " +
s.Group`. Add `"cmp"` to the imports if absent.

- [ ] **Step 8: Lint's group-subject finding (the controller's ruling; pre-flight I-5)**

In `internal/policy/lint.go`, replace

```go
		if sub.Group != "" {
			add(FindingGroupSubject, "subject %q is a group: the broker matches a principal to a group through the "+
				"directory, which is plan 7's, so until then it mints for no one; explain and policy tests "+
				"evaluate it by name", name)
		}
```

with

```go
		if sub.Group != "" {
			// Lint reads the policy alone, so it says the condition, not
			// whether this deployment meets it; the start says that
			// (decision 38 ruling 17; decision 41 ruling 5).
			cond, who := "broker.directory configured", "a person"
			if sub.Domain == DomainMachines {
				cond, who = "broker.identity.machines[].directory configured (a workload certificate's directory "+
					"mapping)", "a workload"
			}
			add(FindingGroupSubject, "subject %q is a %s: subject: it mints only with %s, through which the broker "+
				"matches %s to the group; explain and policy tests evaluate it by name", name, sub.GroupKey(), cond, who)
		}
```

`spec11_test.go`'s finding list (`want` in `TestTheCompletePolicyExampleReportsWhatItShould`, line
204) still holds: it compares kinds, and its three group subjects are `group:`. No other test or
doc quotes the old text (`grep -rn "plan 7's, so until" internal cmd tests` finds only `lint.go`).
In that test's doc comment, replace `three group subjects nobody can mint for until plan 7` with
`three group subjects that mint only with broker.directory configured`. `TestLintReportsWhatAReviewerMustSee` asserts no group finding and is
unchanged.

- [ ] **Step 9: Run the tests**

Run: `go test ./internal/policy/ ./cmd/port49/ -count=1 && go vet ./internal/policy/ ./cmd/port49/`
Expected: PASS, clean. `TestAGroupSubjectNeverMatchesAMachine`, `TestAChangedGroupIsGated`,
`TestARespelledGroupDNIsNotAChange` and `TestTheCompletePolicyExampleReportsWhatItShould`'s kind list
pass unchanged.

- [ ] **Step 10: Commit**

```bash
git add internal/policy/ cmd/port49/policy.go cmd/port49/policy_test.go
git commit -m "feat(policy): machine_group subjects, matched per domain (decision 41)

A machine_group: subject is a machines subject a workload resolved through
the workload mapping matches, never a person; a group: subject never matches
a workload. Both keys on one subject is a load error, and a machine_group
declares no username. The diff gates a move between the two keys, and the
report names the key. Lint's group-subject finding names the key and the
config it mints under, in place of the stale "plan 7" text.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

**Operator notes (for plan 13):**
- **`machine_group:`** names a directory group of workloads, by name or DN, as `group:` names one of
  people. Grant it as any subject; `attached_roles.machines` reach it. A person in that group never
  gets its grants, and a workload in a `group:` group never gets that subject's.
- **One subject, one domain.** `group:` and `machine_group:` on one subject is a load error. A group
  holding both people and service accounts can be named by one subject of each kind.
- **No `username:` on a `machine_group:`.** A workload takes the username its own identity subject
  declares, else its entry's `username_attribute`.
- **CI.** `port49 policy diff` fails a changed `machine_group:`, or a subject moved between
  `group:` and `machine_group:`, until a session test naming the subject asserts its access.
- **Lint.** `port49 policy lint` reports each group subject with the config it needs:
  `broker.directory` for `group:`, `broker.identity.machines[].directory` for `machine_group:`.
  Lint reads the policy alone; the start says whether this deployment meets the condition.

---

### Task 5: The broker resolves a mapped workload: per-domain gates, the username, the pin, forget

**Files:**
- Modify: `internal/broker/member.go` (`member` sets `Domain`; `workloadMapped`, `workloadMember`;
  `memberFor`, `storedMemberOf`)
- Modify: `internal/broker/refresh.go` (`storedMember` → `storedWorkload`)
- Modify: `internal/broker/scheduled.go` (the judge's member)
- Modify: `internal/broker/member.go` (`heldCollision`, the hold-time check shared by the mint and
  the session refresh)
- Modify: `internal/broker/broker.go` (the mint's hold-time check calls `heldCollision`)
- Modify: `internal/broker/sessionrefresh.go` (`RefreshSession`'s hold-time check calls
  `heldCollision`; pre-flight I-1)
- Modify: `internal/broker/workload.go` (`CertCallerOf` checks the pin, the principal set first)
- Modify: `internal/broker/forget.go` (`spiffe://` taken; refused with no workload mapping)
- Test: `internal/broker/workload_directory_test.go`

**Interfaces:**
- Consumes:
  - Task 2: `directory.IsWorkload`, `Resolver.CurrentWorkload` and `VerifyWorkload`,
    `Config.Workload`, `WorkloadMapping.Pinned`.
  - Task 4: `policy.DomainMachines` and `DomainHumans`, `Member.Domain`, `Policy.DeclaredFor`.
- Produces:
  - `func (b *Broker) workloadMapped(principal string) bool`;
  - `func workloadMember(pol *policy.Policy, a directory.Answer) (policy.Member, error)`;
  - `func heldCollision(pol *policy.Policy, m policy.Member, answer *directory.Answer) (policy.Member, error)`;
  - `func (b *Broker) storedWorkload(ctx context.Context, principal string) (policy.Member, error)`.

- [ ] **Step 1: Write the failing tests**

Create `internal/broker/workload_directory_test.go`:

```go
package broker

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/decision"
	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/engine"
	"github.com/blanketfish/port49/internal/store"
	"github.com/blanketfish/port49/internal/testpki"
)

// mappedPolicy: a human group subject and a machine_group subject.
const mappedPolicy = `
scopes:
  - {name: all_devices, match: {}}
roles:
  - {name: network_admin, privilege: admin, permit: ["**"]}
  - {name: backup, privilege: admin, permit: ["show running-config", "show version"]}
subjects:
  - {name: ops, group: secret-group, token_ttl: 60s}
  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 60s}
grants:
  - {subject: ops, scope: all_devices, roles: [network_admin], max_privilege: admin}
  - {subject: backup_hosts, scope: all_devices, roles: [backup], max_privilege: admin}
`

const workloadDN = "CN=svc-oxidized-01,OU=Workloads,DC=corp"

// workloadAnswer is the directory's answer for workloadID.
func workloadAnswer(username string, groups ...string) directory.Answer {
	return directory.Answer{Membership: store.Membership{Principal: workloadID, DN: workloadDN, EntryID: "guid:0102",
		Username: username, GroupNames: groups}, Source: directory.Fresh}
}

// mapped gives f's broker a workload mapping (decision 41) pinned to wca, over
// a static resolver answering answers by principal, or err when it is set.
func (f *fixture) mapped(wca *testpki.CA, answers map[string]directory.Answer, err error) *directory.Resolver {
	r := directory.ForTestsStaticResolver(f.st, answers, err)
	r.Cfg.Grace = time.Hour
	r.Cfg.Workload = &directory.WorkloadMapping{Attribute: "uid", Issuers: []string{wca.Cert.Subject.String()},
		UserFilter: "(objectClass=user)", TrustDomains: []string{"corp.example.com"}}
	f.b.Directory = r
	return r
}

// processLog takes the process log until the test ends.
func processLog(t *testing.T) *lockedBuffer {
	t.Helper()
	logs := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	return logs
}

// Opt-in (decision 41 ruling 1; the brief's pin): with broker.directory and no
// workload mapping, a workload is plan 8's. It mints with every server down,
// the resolver is never asked, and a machine_group subject matches it not.
func TestWithoutTheMappingAWorkloadNeverReachesTheDirectory(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(workloadPolicy, "grants:\n",
		"  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: backup_hosts, scope: all_devices, roles: [network_admin], max_privilege: admin}\n")
	r := directory.ForTestsStaticResolver(f.st, nil, directory.ErrUnavailable)
	f.b.Directory = r // a directory for people, none for workloads
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Subject != "svc_oxidized" || resp.Results[0].Verdict != decision.VerdictPermit ||
		resp.Results[0].Username != "svc-oxidized" {
		t.Fatalf("%+v", resp)
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times for an unmapped workload", n)
	}
}

// A mapped workload mints through its machine_group, under its entry's
// username; no token reaches the decision log or the process log.
func TestAMappedWorkloadMintsThroughItsMachineGroup(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	r := f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "backup-hosts")}, nil)
	logs := processLog(t)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Principal != workloadID || resp.Subject != "backup_hosts" || len(resp.Results) != 1 ||
		resp.Results[0].Verdict != decision.VerdictPermit || resp.Results[0].Username != "svc-oxidized-01" {
		t.Fatalf("%+v", resp)
	}
	if r.Calls.Load() == 0 {
		t.Fatal("a mapped workload's mint never asked the directory")
	}
	login := resp.Results[0].Login
	if login == "" || strings.Contains(f.log.String(), login) || strings.Contains(logs.String(), login) {
		t.Fatal("a token is in a log")
	}
}

// Both directions (decision 41 ruling 5; Review Focus 3): a workload in a
// human group: subject's group gets none of it; a person in a machine_group's
// group gets none of it.
func TestAWorkloadNeverMatchesAHumanGroup(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "secret-group")}, nil)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Results[0].Verdict != decision.VerdictDeny || resp.Results[0].Reason != string(decision.NoGrantsMatched) {
		t.Fatalf("%+v", resp)
	}
}

func TestAPersonNeverMatchesAMachineGroup(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	alice := answerFor(alicePrincipal, "alice")
	alice.GroupNames, alice.GroupDNs = []string{"backup-hosts"}, nil
	f.mapped(wca, map[string]directory.Answer{alicePrincipal: alice}, nil)
	resp := decodeMint(t, f.post(context.Background(), f.state(f.alice), mintLeaf1, "k1"))
	if resp.Results[0].Verdict != decision.VerdictDeny || resp.Results[0].Reason != string(decision.NoGrantsMatched) {
		t.Fatalf("%+v", resp)
	}
}

// Declared wins (decision 41 ruling 4; Review Focus 2): a workload whose own
// subject declares the username its entry also holds mints under it, never
// refused against itself, and composes its identity and machine_group grants.
func TestAWorkloadsOwnDeclaredUsernameIsNoCollision(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: svc_oxidized, identity: [\""+workloadID+"\"], username: svc-oxidized, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}\n")
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized", "backup-hosts")}, nil)
	resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1"))
	if resp.Results[0].Verdict != decision.VerdictPermit || resp.Results[0].Username != "svc-oxidized" ||
		len(resp.Subjects) != 2 {
		t.Fatalf("%+v", resp)
	}
	// Its entry's name differs: the declared one is still the workload's.
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "backup-hosts")}, nil)
	resp = decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k2"))
	if resp.Results[0].Username != "svc-oxidized" {
		t.Fatalf("%+v", resp)
	}
}

// An entry's username a subject declares is the workload's collision; the
// declared one stands (decision 38 ruling 3, decision 41 ruling 4).
func TestAnEntryUsernameASubjectDeclaresIsTheWorkloadsCollision(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: netops, identity: [\"user:alice@example.com\"], username: alice, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: netops, scope: all_devices, roles: [network_admin]}\n")
	f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("alice", "backup-hosts")}, nil)
	res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), `"username_collision"`) {
		t.Fatalf("%s", answer(res))
	}
}

// The 3am case (decision 41 ruling 7): a mapped workload in an outage past
// grace is refused 503 directory_unavailable with Retry-After, recorded.
func TestADirectoryOutagePastGraceStopsAMappedWorkload(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	f.mapped(wca, nil, directory.ErrUnavailable)
	res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if res.Code != http.StatusServiceUnavailable || res.Header().Get("Retry-After") != "30" ||
		!strings.Contains(res.Body.String(), `"directory_unavailable"`) {
		t.Fatalf("%s", answer(res))
	}
	recs := eventsOf(f.records(t), decision.EventMint)
	if len(recs) != 1 || recs[0]["reason"] != string(decision.DirectoryUnavailable) || recs[0]["principal"] != workloadID {
		t.Fatalf("records %v", recs)
	}
}

// The issuer pin is read at every reading of the certificate, before any
// search: an issuer not pinned is identity_unmapped (decision 41 ruling 2).
func TestAnUnpinnedIssuerIsIdentityUnmapped(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	r := f.mapped(wca, map[string]directory.Answer{workloadID: workloadAnswer("svc-oxidized-01", "backup-hosts")}, nil)
	r.Cfg.Workload.Issuers = []string{"CN=Some Other CA"}
	res := f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")
	if res.Code != http.StatusUnauthorized || !strings.Contains(res.Body.String(), `"identity_unmapped"`) ||
		!strings.Contains(res.Body.String(), "directory.issuers") {
		t.Fatalf("%s", answer(res))
	}
	if n := r.Calls.Load(); n != 0 {
		t.Fatalf("the directory was asked %d times before the pin", n)
	}
	// The refusal names the workload refused (pre-flight M-4).
	recs := eventsOf(f.records(t), decision.EventMint)
	if len(recs) != 1 || recs[0]["reason"] != string(decision.IdentityUnmapped) || recs[0]["principal"] != workloadID {
		t.Fatalf("records %v", recs)
	}
}

// The session refresh judges the username at its hold as the mint does
// (decision 41 ruling 4; pre-flight I-1): a workload's own subject declaring
// its entry's name is no collision, and its refresh extends; another
// workload whose entry holds that name is still refused.
func TestASessionRefreshSettlesAWorkloadsUsernameAsTheMintDoes(t *testing.T) {
	f, wca, w := newWorkloadFixture(t)
	f.loadPolicy(t, strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: svc_oxidized, identity: [\""+workloadID+"\"], username: svc-oxidized, token_ttl: 60s}\ngrants:\n", 1)+
		"  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}\n")
	a := workloadAnswer("svc-oxidized", "backup-hosts")
	f.mapped(wca, map[string]directory.Answer{workloadID: a}, nil)
	if resp := decodeMint(t, f.post(context.Background(), chainState(w, wca), mintLeaf1, "k1")); resp.Results[0].Verdict != decision.VerdictPermit {
		t.Fatalf("the mint: %+v", resp)
	}
	// The device session the mint's token opened, as a redemption writes it;
	// then the refresh, as /v1/refresh calls it after memberFor (as
	// TestAReloadBetweenTheMemberAndTheHoldRefusesARefresh drives it).
	f.workloadContext(t, a, f.now)
	m, err := workloadMember(f.b.Policy.Load(), a)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := f.b.RefreshSession(context.Background(), m, &a, store.Credential{Method: "cert"}, f.b.Now(), nil)
	if err != nil || len(rep.Sessions) != 1 || rep.Sessions[0].Outcome != "extended" {
		t.Fatalf("its own declared username refused its refresh: %+v %v", rep, err)
	}
	other := a
	other.Principal = "spiffe://corp.example.com/host/other"
	om := policy.Member{Principal: other.Principal, Domain: policy.DomainMachines, Directory: true,
		Username: "svc-oxidized", GroupNames: other.GroupNames}
	if _, err := f.b.RefreshSession(context.Background(), om, &other, store.Credential{Method: "cert"}, f.b.Now(),
		nil); !errors.Is(err, directory.ErrUsernameTaken) {
		t.Fatalf("another workload's entry name: %v", err)
	}
}

// A reload between opting in and a workload's first verification (pre-flight
// M-2): with no membership stored, the policy pass judges it by its identity
// subject's declared username, so its live context is not revoked.
func TestAReloadBeforeAWorkloadsFirstVerificationKeepsItsDeclaredName(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	body := strings.Replace(mappedPolicy, "grants:\n",
		"  - {name: svc_oxidized, identity: [\""+workloadID+"\"], username: svc-oxidized, token_ttl: 60s}\ngrants:\n", 1) +
		"  - {subject: svc_oxidized, scope: all_devices, roles: [backup], max_privilege: admin}\n"
	f.loadPolicy(t, body)
	f.mapped(wca, nil, nil) // nothing stored for the workload
	f.workloadContext(t, workloadAnswer("svc-oxidized", "backup-hosts"), f.now)
	rep, err := f.b.Refresh(context.Background(), f.reloadDir(t, body))
	if err != nil || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "svc-oxidized"); !got.RevokedAt.IsZero() {
		t.Fatalf("revoked: %+v", got)
	}
}

// workloadContext writes the workload's live context on leaf1 as the policy
// in force compiles it for a, refreshed at refreshed.
func (f *fixture) workloadContext(t *testing.T, a directory.Answer, refreshed time.Time) {
	t.Helper()
	ctx := context.Background()
	pol := f.b.Policy.Load()
	dev, _ := pol.Device("leaf1")
	m, err := workloadMember(pol, a)
	if err != nil {
		t.Fatal(err)
	}
	res, err := pol.ResolveMember(m, dev, f.b.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, hash, err := engine.Encode(res.Blob)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.b.putBlobLogged(ctx, hash, body, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.PutContext(ctx, store.ContextKey{NAS: "leaf1", Username: m.Username}, store.Context{CtxID: "ctx_wl",
		Principal: workloadID, Username: m.Username, PrivLvl: 1, BlobHash: hash, MaxPrivilege: res.MaxPrivilege,
		Enable: res.Enable, AuthTime: f.now, SessionExpires: f.now.Add(12 * time.Hour), RefreshedAt: refreshed,
		LastTouchedAt: f.now}, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := f.st.IndexContext(ctx, workloadID, "", "", store.ContextRef{NAS: "leaf1", Username: m.Username},
		24*time.Hour); err != nil {
		t.Fatal(err)
	}
}

// The scheduled refresh verifies a mapped workload from a server and stamps
// its context with the verification (decision 41 ruling 6).
func TestTheScheduledPassVerifiesAMappedWorkload(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	a := workloadAnswer("svc-oxidized-01", "backup-hosts")
	answers := map[string]directory.Answer{workloadID: a}
	r := f.mapped(wca, answers, nil)
	f.workloadContext(t, a, f.now.Add(-time.Hour))
	f.advance(time.Minute)
	answers[workloadID] = f.verifiedNow(a)
	rep, err := f.b.RefreshDirectory(context.Background())
	if err != nil || rep.Unchanged != 1 || rep.Unverified != 0 || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "svc-oxidized-01"); !got.RefreshedAt.Equal(answers[workloadID].VerifiedAt) {
		t.Fatalf("refreshed_at %v, want the verification", got.RefreshedAt)
	}
	if r.Calls.Load() == 0 {
		t.Fatal("the pass never asked the directory for a mapped workload")
	}
}

// In an outage, the pass leaves a mapped workload's context unstamped and
// unrevoked, counted unverified: port49d denies it context_stale at the
// ceiling (decision 41 ruling 7; the daemon side is TestStaleContextDenies).
func TestAnOutageLeavesAMappedWorkloadUnstamped(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.loadPolicy(t, mappedPolicy)
	a := workloadAnswer("svc-oxidized-01", "backup-hosts")
	f.mapped(wca, nil, directory.ErrUnavailable)
	old := f.now.Add(-time.Hour)
	f.workloadContext(t, a, old)
	f.advance(time.Minute)
	rep, err := f.b.RefreshDirectory(context.Background())
	if err != nil || rep.Unverified != 1 || rep.UnverifiedPrincipals != 1 || rep.Revoked != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got := f.context(t, "leaf1", "svc-oxidized-01"); !got.RefreshedAt.Equal(old) || !got.RevokedAt.IsZero() {
		t.Fatalf("%+v", got)
	}
}

// forget takes a workload's SPIFFE ID verbatim (decision 41 ruling 3).
func TestForgetTakesASPIFFEID(t *testing.T) {
	f, wca, _ := newWorkloadFixture(t)
	f.mapped(wca, nil, nil)
	m := workloadAnswer("svc-oxidized-01").Membership
	m.VerifiedAt = f.now
	if err := f.st.PutMembership(context.Background(), m, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	out, err := f.b.Forget(context.Background(), workloadID, "test")
	if err != nil || !strings.Contains(out, "forgot "+workloadID) {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := f.st.GetMembership(context.Background(), workloadID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("still held: %v", err)
	}
	if _, err := f.b.Forget(context.Background(), "SPIFFE://corp.example.com/host/oxidized-01", "test"); err == nil {
		t.Fatal("an upper-case scheme was taken")
	}
	// With no workload mapping, no workload's membership is used: forget
	// says so rather than answer as if it forgot something (pre-flight M-6).
	f.b.Directory.Cfg.Workload = nil
	if _, err := f.b.Forget(context.Background(), workloadID, "test"); err == nil ||
		!strings.Contains(err.Error(), "no workload mapping is configured") {
		t.Fatalf("no mapping: %v", err)
	}
}
```

Add `"log"` and `"github.com/blanketfish/port49/internal/policy"` to the test file's imports.

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/broker/ -run 'Mapped|MappedWorkload|NeverMatches|OwnDeclared|EntryUsername|OutagePastGrace|UnpinnedIssuer|ForgetTakes|WithoutTheMapping|SessionRefreshSettles|FirstVerification' -count=1`
Expected: FAIL to compile: `undefined: workloadMember`.

- [ ] **Step 3: `member.go`**

In `internal/broker/member.go`, make `member` set the domain:

```go
// member is the policy's view of a person's directory answer.
func member(a directory.Answer) policy.Member {
	return policy.Member{Principal: a.Principal, Domain: policy.DomainHumans, Directory: true, Username: a.Username,
		GroupDNs: a.GroupDNs, GroupNames: a.GroupNames}
}

// workloadMapped reports whether principal is a workload this broker resolves
// through the directory (decision 41 ruling 1): a SPIFFE ID, with the x509
// machine verifier's directory: configured.
func (b *Broker) workloadMapped(principal string) bool {
	return b.Directory != nil && b.Directory.Cfg.Workload != nil && directory.IsWorkload(principal)
}

// workloadMember is a workload's directory answer as pol judges it (decision
// 41 ruling 4). Its username is the one its identity subject declares, when
// that subject declares one; else its entry's, refused
// directory.ErrUsernameTaken when a subject declares that, the declared one
// standing (decision 38 ruling 3).
func workloadMember(pol *policy.Policy, a directory.Answer) (policy.Member, error) {
	m := policy.Member{Principal: a.Principal, Domain: policy.DomainMachines, Directory: true, Username: a.Username,
		GroupDNs: a.GroupDNs, GroupNames: a.GroupNames}
	if u := pol.DeclaredFor(a.Principal); u != "" {
		m.Username = u
		return m, nil
	}
	if who, ok := pol.DeclaredUsernames()[a.Username]; ok && a.Username != "" {
		return policy.Member{Principal: a.Principal, Domain: policy.DomainMachines, Directory: true},
			fmt.Errorf("%w: the directory derives username %q for %s, which subject %q declares",
				directory.ErrUsernameTaken, a.Username, printsafe.Line(a.Principal, 300), who)
	}
	return m, nil
}

// heldCollision judges m's username again under pol, the policy a mint or a
// session refresh holds: a reload can land between the membership read and
// the hold, and declare the username the directory gave (final review M-1).
// A workload under the mapping is settled again by workloadMember, so its own
// subject's declaration is no collision and another's is (decision 41 ruling
// 4); the member it returns is the one to judge. Anyone else is refused
// directory.ErrUsernameTaken when a subject now declares its username.
func heldCollision(pol *policy.Policy, m policy.Member, answer *directory.Answer) (policy.Member, error) {
	if m.Domain == policy.DomainMachines && answer != nil {
		return workloadMember(pol, *answer)
	}
	if m.Directory && pol.DeclaredUsernames()[m.Username] != "" {
		return m, directory.ErrUsernameTaken
	}
	return m, nil
}
```

Replace `memberFor`'s body:

```go
func (b *Broker) memberFor(ctx context.Context, principal string) (policy.Member, *directory.Answer, error) {
	switch {
	case b.Directory != nil && directory.IsUser(principal):
		a, err := b.Directory.Current(ctx, principal)
		if err != nil {
			return policy.Member{}, nil, err
		}
		return member(a), &a, nil
	case b.workloadMapped(principal):
		// A workload is never mapped at bind: its principal is its SPIFFE
		// ID, and its membership is read here, as a person's is (decision
		// 41 ruling 6).
		a, err := b.Directory.CurrentWorkload(ctx, principal)
		if err != nil {
			return policy.Member{}, nil, err
		}
		m, err := workloadMember(b.Policy.Load(), a)
		if err != nil {
			return policy.Member{}, nil, err
		}
		return m, &a, nil
	}
	return policy.MemberOf(principal), nil, nil
}
```

Update its doc comment's last sentence to: `Without a directory, or for a machine principal the workload
mapping does not cover, it is MemberOf(principal) and the answer is nil (pre-flight I-10; decision
41 ruling 1).`

In `storedMemberOf`, add at the top:

```go
	if b.workloadMapped(principal) {
		if m, err := b.storedWorkload(ctx, principal); err == nil {
			return m
		}
		return policy.MemberOf(principal)
	}
```

Add `"fmt"` to `member.go`'s imports.

- [ ] **Step 4: `storedMember` and `storedWorkload`**

In `internal/broker/refresh.go`, at the top of `storedMember`, add:

```go
	if b.workloadMapped(principal) {
		return b.storedWorkload(ctx, principal)
	}
```

and after `storedMember`, add:

```go
// storedWorkload is storedMember for a workload under the mapping (decision 41
// ruling 6). A refusal has no groups and no username, so nothing it holds
// stands, as for a person. With none stored (opted in, not yet verified) it
// has no groups and the username its identity subject declares, if any: a
// reload before its first verification keeps what it held under that
// subject, never more (pre-flight M-2). Past grace it has no groups and the
// username it last had. Otherwise it is the stored membership. The username
// is settled by workloadMember under the policy in force; a collision is the
// refused member and directory.ErrUsernameTaken.
func (b *Broker) storedWorkload(ctx context.Context, principal string) (policy.Member, error) {
	none := policy.Member{Principal: principal, Domain: policy.DomainMachines, Directory: true}
	sm, ok, err := b.Directory.Stored(ctx, principal)
	switch {
	case err != nil:
		return policy.Member{}, err
	case !ok:
		none.Username = b.Policy.Load().DeclaredFor(principal)
		return none, nil
	case sm.Refused:
		return none, nil
	}
	if b.Now().Sub(sm.VerifiedAt) > b.Directory.Cfg.Grace {
		sm.GroupDNs, sm.GroupNames = nil, nil
	}
	m, err := workloadMember(b.Policy.Load(), directory.Answer{Membership: sm})
	if err != nil {
		return none, err
	}
	return m, nil
}
```

- [ ] **Step 5: The scheduled judge**

In `internal/broker/scheduled.go`, replace the judge's `member` function's body with:

```go
		member: func(ctx context.Context, principal string) (policy.Member, time.Time, error) {
			switch {
			case b.Directory != nil && directory.IsUser(principal):
				a, err := b.Directory.Verify(ctx, principal)
				if err != nil {
					return policy.Member{}, time.Time{}, b.verifyFailed(ctx, principal, err, &first)
				}
				// A declaration made by a reload since the answer was written is
				// the resolver's collision too (pre-flight M-11).
				if who, ok := b.Directory.DeclaredBy(a.Username); ok {
					return policy.Member{}, time.Time{}, fmt.Errorf("%w: the directory derives username %q for %s, "+
						"which subject %q declares", directory.ErrUsernameTaken, a.Username, principal, who)
				}
				return member(a), a.VerifiedAt, nil
			case b.workloadMapped(principal):
				// A mapped workload is verified and stamped as a person is
				// (decision 41 ruling 6); its username is settled under the
				// policy in force.
				a, err := b.Directory.VerifyWorkload(ctx, principal)
				if err != nil {
					return policy.Member{}, time.Time{}, b.verifyFailed(ctx, principal, err, &first)
				}
				m, err := workloadMember(b.Policy.Load(), a)
				if err != nil {
					return policy.Member{}, time.Time{}, err
				}
				return m, a.VerifiedAt, nil
			}
			return policy.MemberOf(principal), rep.At, nil
		},
```

Update `RefreshDirectory`'s doc comment: replace `A machine principal, and every principal without a
directory, is judged on the policy alone and stamped with the pass's instant.` with `A workload
under the mapping is verified as a person is (decision 41 ruling 6); any other machine principal,
and every principal without a directory, is judged on the policy alone and stamped with the pass's
instant.`

- [ ] **Step 6: The hold-time check, at the mint and at the session refresh (pre-flight I-1)**

Both holds judge the username again with `heldCollision` (Step 3), so a workload's own declared
username refuses neither its mint nor its session refresh.

In `internal/broker/broker.go`, replace

```go
	if m.Directory && pol.DeclaredUsernames()[m.Username] != "" {
		release()
		ref := directoryRefusal(directory.ErrUsernameTaken)
```

with

```go
	// A workload's username is settled again here (decision 41 ruling 4):
	// its own subject's declaration is no collision, another's is.
	if m, err = heldCollision(pol, m, answer); err != nil {
		release()
		ref := directoryRefusal(directory.ErrUsernameTaken)
```

The rest of that block is unchanged. (`m`, `answer` and `err` are the handler's, from
`b.memberFor` and `b.Minter.Reserve` above; this assigns, it declares nothing.)

In `internal/broker/sessionrefresh.go`'s `RefreshSession`, replace

```go
	if m.Directory && pol.DeclaredUsernames()[m.Username] != "" {
		return rep, directory.ErrUsernameTaken
	}
```

with

```go
	m, err := heldCollision(pol, m, answer)
	if err != nil {
		return rep, err
	}
```

(`m` is the parameter, reassigned; `err` is new here, and the `refs, err :=` that follows still
declares `refs`.) Both callers, `/v1/refresh` and the OIDC refresh, already answer
`directory.ErrUsernameTaken` as `username_collision`.

- [ ] **Step 7: The pin, and forget**

In `internal/broker/workload.go`'s `CertCallerOf`, replace

```go
		p, err := WorkloadPrincipal(leaf, b.Workload.TrustDomains)
		if err != nil {
			return cc, err
		}
		cc.Principal = p
```

with

```go
		p, err := WorkloadPrincipal(leaf, b.Workload.TrustDomains)
		if err != nil {
			return cc, err
		}
		// Set before the pin: the SPIFFE ID is validated, so a pin refusal's
		// record names the workload refused (pre-flight M-4).
		cc.Principal = p
		// The workload mapping is weak, so its issuer is pinned at every
		// reading of the certificate, before any search (decision 41 ruling 2).
		if b.Directory != nil && b.Directory.Cfg.Workload != nil {
			if err := b.Directory.Cfg.Workload.Pinned(leaf); err != nil {
				return cc, fmt.Errorf("%w: %v", ErrWorkloadUnmapped, err)
			}
		}
```

In `internal/broker/forget.go`, replace the `user:` check and the `normalPrincipal` refusal with:

```go
	// A person's principal, or a mapped workload's SPIFFE ID (decision 41
	// ruling 3), as the log spells it.
	lower := strings.ToLower(principal)
	if !strings.HasPrefix(lower, "user:") && !strings.HasPrefix(lower, spiffe.Scheme) {
		return "", fmt.Errorf("broker: %q is neither a user: principal nor a workload's spiffe:// ID; only a "+
			"directory principal has a membership", printsafe.Line(principal, 200))
	}
	normal, err := normalPrincipal(principal)
	if err != nil {
		return "", fmt.Errorf("broker: %q is not a principal as the log spells one: user: and an email, or a "+
			"workload's SPIFFE ID verbatim", printsafe.Line(principal, 300))
	}
	if directory.IsWorkload(normal) && b.Directory.Cfg.Workload == nil {
		// Nothing is held for a workload without the mapping, and nothing
		// would read it (pre-flight M-6). A record left from when one was
		// configured expires with its lease.
		return "", fmt.Errorf("broker: no workload mapping is configured (broker.identity.machines[].directory), so "+
			"no membership is held for %s to forget", printsafe.Line(normal, 300))
	}
```

Add `"github.com/blanketfish/port49/internal/directory"` and `"github.com/blanketfish/port49/internal/spiffe"`
to `forget.go`'s imports. Update `Forget`'s doc
comment's first line to: `Forget is \`port49 directory forget\` (Ruling 3's escape; decision 41
ruling 3 for a workload).`

- [ ] **Step 8: Run the tests**

Run: `go test ./internal/broker/ -count=1 && go vet ./internal/broker/`
Expected: PASS: every new test, and every existing one. `TestAWorkloadMintsWhileTheDirectoryIsDown`
and `TestAMachinePrincipalIsStampedAndKept` pass unchanged: the static resolver's `Cfg.Workload` is
nil. `TestAReloadBetweenTheMemberAndTheHoldRefusesARefresh` and its mint twin pass unchanged:
`heldCollision` keeps a person's rule.

Run: `go test -race ./internal/broker/ -count=1`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/broker/
git commit -m "feat(broker): a mapped workload's directory groups (decision 41)

memberFor, storedMemberOf, storedMember and the scheduled judge resolve a
workload under the mapping by its SPIFFE ID; workloadMember settles its
username (its subject's declared one wins, else its entry's, which a
declaration refuses). heldCollision judges it again at the mint's hold and
the session refresh's. CertCallerOf checks the issuer pin before any search,
naming the workload in the refusal; forget takes a spiffe:// ID. Without the
mapping nothing changes.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

**Operator notes (for plan 13):**
- **With the mapping, a workload mints only while the directory answers or within grace.** Past
  grace, its mints are refused `directory_unavailable` (503, `Retry-After: 30`), and its live device
  sessions go `context_stale` at `session.staleness_ceiling`. This holds even for a workload whose
  grants come from its identity subject alone, since the mapping makes every workload of that
  verifier a directory principal.
- **The username.** A workload whose identity subject declares `username:` keeps it, at mint and at
  session refresh. One with no such subject takes its entry's `username_attribute`. A name some
  subject declares is refused `username_collision`, naming both; the declared one stands.
- **Opting in.** A reload before a workload's first verification keeps its identity subject's
  grants under its declared username; one with no declared username is revoked until its next
  mint, as a person with no stored membership is.
- **`port49 directory forget spiffe://…`** frees a workload whose entry was deleted and re-created,
  as for a person. Run it only after confirming the new entry is that workload's.
- **The issuer pin.** A workload certificate whose issuer `issuers:` does not list is refused
  `identity_unmapped` at bind, before the directory is asked. The decision record names its SPIFFE
  ID, so the refused workload can be found.
- **`forget` with no mapping** answers that no workload mapping is configured, and deletes nothing.

---

### Task 6: port49d says the mapping and pre-warms machine groups

**Files:**
- Modify: `internal/directory/prewarm.go` (`PrewarmAll`; `prewarmWorkloads`; `Prewarm` delegates;
  `prewarm` takes a config and a lookup)
- Modify: `internal/port49d/directory.go` (`policyEnv`; `announceDirectory`; `prewarm`)
- Test: `internal/directory/workload_test.go` (`TestPrewarmVerifiesMachineGroupMembersAsWorkloads`,
  `TestPrewarmSkipsMachineGroupsWithoutAMapping`, `TestPrewarmVerifiesIdentityOnlyWorkloads`)
- Test: `internal/port49d/workload_directory_test.go`

**Interfaces:**
- Consumes:
  - Task 2: `lookup.workload`, `byWorkloadDN`, `Config.Workload`.
  - Task 3: `cfg.Broker.Directory.Workload`.
  - Task 4: `Policy.MachineGroupValues`, `MachineGroupSubjects`, `Env.WorkloadDirectory`.
  - Plan 8: `Policy.SPIFFEIdentities` (`internal/policy/member.go`), the identity-only workloads.
- Produces: `func (r *Resolver) PrewarmAll(ctx context.Context, groups, machineGroups, workloads
  []string) (PrewarmReport, error)`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/directory/workload_test.go`:

```go
// Pre-warm verifies a machine_group's members as workloads (decision 41
// ruling 6): the principal is the SPIFFE ID the member's attribute holds, in
// a listed trust domain, else the member is skipped and counted. A pre-warmed
// workload is served in an outage within grace though it never minted
// (Review Focus 4), and no mb/user: record is written for it (Review Focus 5).
func TestPrewarmVerifiesMachineGroupMembersAsWorkloads(t *testing.T) {
	w := newWorkloadWorld(t)
	w.r.Cfg.PrewarmMax = 10
	const stray = "CN=stray,OU=Workloads,DC=corp"
	w.dir.onBase(gBackup, "(objectClass=*)", entry(gBackup, map[string][]string{"member": {wlDN, stray}}))
	w.dir.onBase(wlDN, "(objectClass=user)", wlEntry(wlID))
	w.dir.onBase(stray, "(objectClass=user)", entry(stray, map[string][]string{
		"uid": {"spiffe://elsewhere.example/x"}, "sAMAccountName": {"stray"}}))
	rep, err := w.r.PrewarmAll(context.Background(), nil, []string{gBackup}, nil)
	if err != nil || rep.Groups != 1 || rep.Principals != 1 || rep.Failed != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if v := testutil.ToFloat64(w.r.M.DirectoryPrewarmPrincipals); v != 1 {
		t.Fatalf("port49_directory_prewarm_principals = %v", v)
	}
	if ps, _ := w.st.MembershipPrincipals(context.Background()); !slices.Equal(ps, []string{wlID}) {
		t.Fatalf("pre-warm wrote %v", ps)
	}
	w.clk.Add(time.Hour)
	w.down()
	a, err := w.r.CurrentWorkload(context.Background(), wlID)
	if err != nil || a.Source != Grace || !slices.Equal(a.GroupNames, []string{"backup-hosts"}) {
		t.Fatalf("%+v %v", a, err)
	}
}

// Without a workload mapping, neither machine groups nor workload identities
// are pre-warmed.
func TestPrewarmSkipsMachineGroupsWithoutAMapping(t *testing.T) {
	w := newWorld(t)
	rep, err := w.r.PrewarmAll(context.Background(), nil, []string{gBackup}, []string{wlID})
	if err != nil || rep.Groups != 0 || rep.Principals != 0 || len(w.dir.calls) != 0 {
		t.Fatalf("%+v %v %d searches", rep, err, len(w.dir.calls))
	}
}

// An identity-only workload, granted by its own spiffe:// subject and in no
// machine_group, is pre-warmed too (decision 41 ruling 6; pre-flight I-3):
// its last own verification is past grace, the pass verifies it, and it is
// served in an outage within grace of the pass. An identity outside the
// verifier's trust domains is not searched. The workloads share one
// prewarm.max_principals: past it the rest are capped.
func TestPrewarmVerifiesIdentityOnlyWorkloads(t *testing.T) {
	w := newWorkloadWorld(t)
	w.r.Cfg.PrewarmMax = 10
	if _, err := w.r.VerifyWorkload(context.Background(), wlID); err != nil { // its own last mint
		t.Fatal(err)
	}
	w.clk.Add(5 * time.Hour) // past grace (4h)
	rep, err := w.r.PrewarmAll(context.Background(), nil, nil, []string{"spiffe://elsewhere.example/x", wlID})
	if err != nil || rep.Principals != 1 || rep.Failed != 0 || rep.Capped {
		t.Fatalf("%+v %v", rep, err)
	}
	for _, c := range w.dir.calls {
		if strings.Contains(c.Filter, "elsewhere.example") {
			t.Fatalf("an identity outside the trust domains was searched: %s", c.Filter)
		}
	}
	w.clk.Add(time.Hour)
	w.down()
	if a, err := w.r.CurrentWorkload(context.Background(), wlID); err != nil || a.Source != Grace {
		t.Fatalf("in the outage: %+v %v", a, err)
	}
	// The budget: one principal, two workloads; the second (sorted) is capped.
	w = newWorkloadWorld(t)
	w.r.Cfg.PrewarmMax = 1
	rep, err = w.r.PrewarmAll(context.Background(), nil, nil,
		[]string{"spiffe://corp.example.com/host/oxidized-02", wlID})
	if err != nil || rep.Principals != 1 || rep.Failed != 0 || !rep.Capped {
		t.Fatalf("capped: %+v %v", rep, err)
	}
}
```

Add `"github.com/prometheus/client_golang/prometheus/testutil"` to that file's imports.

Create `internal/port49d/workload_directory_test.go`:

```go
package port49d

import (
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/directory"
	"github.com/blanketfish/port49/internal/policy"
)

func workloadMapping() *directory.WorkloadMapping {
	return &directory.WorkloadMapping{Attribute: "uid", Issuers: []string{"CN=Workloads Issuing CA,O=Corp"},
		UserFilter: "(objectClass=user)", TrustDomains: []string{"corp.example.com"}}
}

// The start says the mapping, what every workload of the verifier then needs
// (ruling Q2; pre-flight I-4), its 3am cost with the two clocks apart
// (pre-flight M-1) and its ACL requirement (decision 41 rulings 2, 7 and 10),
// never the fact L50 measures.
func TestTheWorkloadMappingStartLines(t *testing.T) {
	cfg := brokerConfig(t, directoryPolicy)
	cfg.Broker.Directory = directoryCfg("gssapi")
	cfg.Broker.Directory.Workload = workloadMapping()
	cfg.Broker.RefreshInterval = 5 * time.Minute
	var out syncBuffer
	announceDirectory(&out, "port49-broker", cfg, buildPolicy(t, cfg, directoryPolicy))
	got := out.String()
	for _, want := range []string{
		"port49-broker: directory: workload certificates map by spiffe_id (weak, pinned to CN=Workloads Issuing CA,O=Corp) " +
			"through uid under (objectClass=user); every workload this verifier accepts must have exactly one entry " +
			"holding its SPIFFE ID, or it is refused identity_unmapped, and while the directory is down past grace it " +
			"is refused directory_unavailable; username from the identity subject listing the SPIFFE ID, else from " +
			"sAMAccountName; an entry holding a SPIFFE ID in uid is never a person's; machine_group subjects match " +
			"them, group subjects never\n",
		"port49-broker: directory: a mapped workload mints only while a server answers or its membership was verified " +
			"within grace (4h0m0s): past it its mints are refused directory_unavailable (port49 workload exits 75); its " +
			"live device sessions go unstamped from the first scheduled refresh that cannot verify it, and deny " +
			"context_stale once port49d's session.staleness_ceiling has passed since the last one that did; pre-warm " +
			"every 1h0m0s keeps mapped workloads verified (machine_group members and each spiffe:// identity a subject " +
			"lists, up to prewarm.max_principals (10000) besides the people's)\n",
		"port49-broker: directory: uid must be writable only by directory administrators: whoever can write it on an " +
			"entry chooses which workload takes that entry's groups\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the start lines lack %q:\n%s", want, got)
		}
	}
	cfg.Broker.Directory.PrewarmInterval = 0
	var off syncBuffer
	announceDirectory(&off, "port49-broker", cfg, buildPolicy(t, cfg, directoryPolicy))
	if !strings.Contains(off.String(), "; pre-warm is off, so a workload that has not minted within grace is refused in an outage\n") {
		t.Errorf("pre-warm off is not said:\n%s", off.String())
	}
}

// machine_group subjects with no mapping mint for no one, and the start names
// them (decision 41 ruling 5); with no broker.directory too.
func TestMachineGroupSubjectsWithoutAMappingAreSaid(t *testing.T) {
	body := `
scopes: [{name: all_devices, match: {}}]
roles: [{name: r, privilege: admin, permit: ["**"]}]
subjects:
  - {name: s, identity: ["user:alice@example.com"], username: alice, token_ttl: 60s}
  - {name: backup_hosts, machine_group: backup-hosts, token_ttl: 5m}
grants: [{subject: s, scope: all_devices, roles: [r]}, {subject: backup_hosts, scope: all_devices, roles: [r]}]
`
	want := "port49d: policy: 1 machine_group subjects (backup_hosts) mint for no one: no " +
		"broker.identity.machines[].directory is configured\n"
	cfg := brokerConfig(t, body)
	var out syncBuffer
	announceDirectory(&out, "port49d", cfg, buildPolicy(t, cfg, body))
	if out.String() != want {
		t.Fatalf("no directory: got %q, want %q", out.String(), want)
	}
	cfg.Broker.Directory = directoryCfg("gssapi")
	cfg.Broker.RefreshInterval = 5 * time.Minute
	var dir syncBuffer
	announceDirectory(&dir, "port49d", cfg, buildPolicy(t, cfg, strings.Replace(body,
		`identity: ["user:alice@example.com"], username: alice,`, `identity: ["user:alice@example.com"],`, 1)))
	if !strings.Contains(dir.String(), want) {
		t.Fatalf("a directory, no mapping:\n%s", dir.String())
	}
}

// policyEnv says whether the workload verifier maps (decision 41 ruling 1).
func TestPolicyEnvSaysTheWorkloadMapping(t *testing.T) {
	cfg := brokerConfig(t, directoryPolicy)
	if e := policyEnv(cfg); e.Directory != policy.DirectoryOff || e.WorkloadDirectory != policy.DirectoryOff {
		t.Fatalf("no directory: %+v", e)
	}
	cfg.Broker.Directory = directoryCfg("gssapi")
	if e := policyEnv(cfg); e.Directory != policy.DirectoryOn || e.WorkloadDirectory != policy.DirectoryOff {
		t.Fatalf("a directory: %+v", e)
	}
	cfg.Broker.Directory.Workload = workloadMapping()
	if e := policyEnv(cfg); e.WorkloadDirectory != policy.DirectoryOn {
		t.Fatalf("a mapping: %+v", e)
	}
}
```

- [ ] **Step 2: Run them to see them fail**

Run: `go test ./internal/directory/ ./internal/port49d/ -run 'Prewarm.*Machine|PrewarmVerifiesIdentityOnly|WorkloadMapping|MachineGroupSubjects|PolicyEnvSays' -count=1`
Expected: FAIL to compile: `undefined: PrewarmAll`, and `policy.Env` has no `WorkloadDirectory` set
by `policyEnv` (FAIL at the assertion).

- [ ] **Step 3: `PrewarmAll`**

In `internal/directory/prewarm.go`, rename the body of `Prewarm` to a private method with this
signature and doc:

```go
// prewarm is one pre-warm pass over groups under c (r.Cfg, or r.Cfg with the
// workload user_filter for machine groups, so in_chain enumerates workloads
// under it), verifying each member through at(dn). It sets no metric.
func (r *Resolver) prewarm(ctx context.Context, c Config, groups []string, at func(dn string) lookup) (PrewarmReport, error) {
```

In that body:
- replace every `r.Cfg.` in the group-name search and the `membersOf` call with `c.` (`c.GroupsBaseDN`,
  `c.QueryTimeout`, `c.GroupFilter`, `c.GroupNameAttribute`, `c.membersOf`, `c.PrewarmMax`,
  `c.MaxDepth`);
- replace `r.verify(ctx, lookup{find: r.byDN(dn), say: dn})` with `r.verify(ctx, at(dn))`;
- delete the two metric lines before the final `return rep, nil`.

Then add:

```go
// Prewarm is PrewarmAll for people alone.
func (r *Resolver) Prewarm(ctx context.Context, groups []string) (PrewarmReport, error) {
	return r.PrewarmAll(ctx, groups, nil, nil)
}

// PrewarmAll verifies every member of groups as a person, and, under a
// workload mapping, every member of machineGroups and then every SPIFFE ID in
// workloads as a workload (decision 41 ruling 6), and writes each membership,
// so a principal that never asked can be served in an outage within grace
// (design §10; Ruling 20). People take at most prewarm.max_principals, and
// workloads, the two kinds together, as many again. machineGroups are the
// policy's machine_group: values and workloads its listed spiffe:// identities
// (pre-flight I-3: a workload granted by its own identity subject alone is in
// no group); without a mapping neither is read. A workload in both is
// verified twice, which costs one search pair and no grant.
func (r *Resolver) PrewarmAll(ctx context.Context, groups, machineGroups, workloads []string) (PrewarmReport, error) {
	rep, err := r.prewarm(ctx, r.Cfg, groups, func(dn string) lookup { return lookup{find: r.byDN(dn), say: dn} })
	if err != nil {
		return rep, err
	}
	if w := r.Cfg.Workload; w != nil {
		var wrep PrewarmReport
		if len(machineGroups) > 0 {
			wc := r.Cfg
			wc.UserFilter = w.UserFilter
			wrep, err = r.prewarm(ctx, wc, machineGroups, func(dn string) lookup {
				return lookup{find: r.byWorkloadDN(dn), say: dn, workload: true}
			})
		}
		if err == nil {
			err = r.prewarmWorkloads(ctx, slices.Sorted(slices.Values(workloads)), &wrep)
		}
		rep.Groups, rep.Principals, rep.Failed = rep.Groups+wrep.Groups, rep.Principals+wrep.Principals, rep.Failed+wrep.Failed
		rep.Capped = rep.Capped || wrep.Capped
		if err != nil {
			return rep, err
		}
	}
	r.M.DirectoryPrewarmPrincipals.Set(float64(rep.Principals))
	r.M.DirectoryPrewarmLastSuccess.Set(float64(r.Now().Unix()))
	return rep, nil
}

// prewarmWorkloads verifies each SPIFFE ID in ids, in the verifier's trust
// domains, as VerifyWorkload does, within what the machine groups left of
// prewarm.max_principals, adding to rep. An ID outside the trust domains is
// skipped unsearched: no workload certificate gives it (decision 40 ruling
// 16's start line names it). An outage stops the pass, as for people.
func (r *Resolver) prewarmWorkloads(ctx context.Context, ids []string, rep *PrewarmReport) error {
	left := r.Cfg.PrewarmMax - rep.Principals - rep.Failed
	for _, p := range ids {
		if id, err := spiffe.ParseWorkload(p); err != nil || !slices.Contains(r.Cfg.Workload.TrustDomains, id.TrustDomain) {
			continue
		}
		if left <= 0 {
			rep.Capped = true
			r.sayOnce("prewarmcap:workloads", time.Hour, "directory: pre-warm reached prewarm.max_principals (%d) "+
				"for workloads; the rest are not pre-warmed", r.Cfg.PrewarmMax)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		left--
		if _, err := r.VerifyWorkload(ctx, p); err != nil {
			if errors.Is(err, ErrUnavailable) {
				return err
			}
			rep.Failed++
			continue
		}
		rep.Principals++
	}
	return nil
}
```

Add `"slices"` and `"github.com/blanketfish/port49/internal/spiffe"` to `prewarm.go`'s imports.
`prewarm_test.go` calls `Prewarm` and passes unchanged.

- [ ] **Step 4: port49d**

In `internal/port49d/directory.go`, replace `policyEnv`'s `switch` with:

```go
	switch {
	case cfg.Broker == nil:
	case cfg.Broker.Directory != nil:
		env.Directory, env.WorkloadDirectory = policy.DirectoryOn, policy.DirectoryOff
		if cfg.Broker.Directory.Workload != nil {
			env.WorkloadDirectory = policy.DirectoryOn
		}
	default:
		env.Directory, env.WorkloadDirectory = policy.DirectoryOff, policy.DirectoryOff
	}
```

and its doc comment's last clause to `whether its broker resolves humans through a directory (Ruling
16), and workloads (decision 41 ruling 1)`.

In `announceDirectory`, replace the `if d == nil { … return }` block with:

```go
	machineGroups := func() {
		if d != nil && d.Workload != nil {
			return
		}
		if gs := pol.MachineGroupSubjects(); len(gs) > 0 {
			fmt.Fprintf(w, "%s: policy: %d machine_group subjects (%s) mint for no one: no "+
				"broker.identity.machines[].directory is configured\n", proc, len(gs), strings.Join(gs, ", "))
		}
	}
	if d == nil {
		if gs := pol.GroupSubjects(); len(gs) > 0 {
			fmt.Fprintf(w, "%s: policy: %d group subjects (%s) mint for no one: no broker.directory is configured\n",
				proc, len(gs), strings.Join(gs, ", "))
		}
		machineGroups()
		return
	}
```

and at the end of `announceDirectory`, after the grace line, add:

```go
	machineGroups()
	if wm := d.Workload; wm != nil {
		// Ruling Q2's cost (pre-flight I-4): every workload of the verifier,
		// identity-only ones included, needs its entry, and an outage stops it.
		fmt.Fprintf(w, "%s: directory: workload certificates map by spiffe_id (weak, pinned to %s) through %s under "+
			"%s; every workload this verifier accepts must have exactly one entry holding its SPIFFE ID, or it is "+
			"refused identity_unmapped, and while the directory is down past grace it is refused "+
			"directory_unavailable; username from the identity subject listing the SPIFFE ID, else from %s; an entry "+
			"holding a SPIFFE ID in %s is never a person's; machine_group subjects match them, group subjects never\n",
			proc, strings.Join(wm.Issuers, "; "), wm.Attribute, wm.UserFilter, d.UsernameAttribute, wm.Attribute)
		warm := fmt.Sprintf("pre-warm %s keeps mapped workloads verified (machine_group members and each spiffe:// "+
			"identity a subject lists, up to prewarm.max_principals (%d) besides the people's)", every(d.PrewarmInterval),
			d.PrewarmMax)
		if d.PrewarmInterval == 0 {
			warm = "pre-warm is off, so a workload that has not minted within grace is refused in an outage"
		}
		// Two clocks (pre-flight M-1): grace bounds a mint; port49d's
		// staleness ceiling, counted from the last pass that reached the
		// directory, bounds a session. Their defaults coincide; they need not.
		fmt.Fprintf(w, "%s: directory: a mapped workload mints only while a server answers or its membership was "+
			"verified within grace (%s): past it its mints are refused directory_unavailable (port49 workload exits "+
			"75); its live device sessions go unstamped from the first scheduled refresh that cannot verify it, and "+
			"deny context_stale once port49d's session.staleness_ceiling has passed since the last one that did; %s\n",
			proc, d.Grace, warm)
		fmt.Fprintf(w, "%s: directory: %s must be writable only by directory administrators: whoever can write it on "+
			"an entry chooses which workload takes that entry's groups\n", proc, wm.Attribute)
	}
```

In `prewarm`, replace `rep, err := r.Prewarm(ctx, live.Load().GroupValues())` with:

```go
		pol := live.Load()
		rep, err := r.PrewarmAll(ctx, pol.GroupValues(), pol.MachineGroupValues(),
			slices.Collect(maps.Keys(pol.SPIFFEIdentities())))
```

Add `"maps"` and `"slices"` to `directory.go`'s imports (`PrewarmAll` sorts the identities).

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/directory/ ./internal/port49d/ -count=1 && go vet ./internal/directory/ ./internal/port49d/`
Expected: PASS, clean. `TestGroupSubjectsWithoutADirectoryAreSaid` passes unchanged: its policy has
no `machine_group:`.

- [ ] **Step 6: Commit**

```bash
git add internal/directory/prewarm.go internal/directory/workload_test.go internal/port49d/
git commit -m "feat(port49d): say the workload mapping, its 3am cost, and pre-warm machine groups

policyEnv sets WorkloadDirectory; the start says the spiffe_id mapping, that
a mapped workload stops minting past grace and port49 workload exits 75, the
attribute's ACL requirement, and machine_group subjects that mint for no one.
PrewarmAll verifies machine_group members and the listed spiffe:// identities
as workloads, within their own prewarm.max_principals.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

**Operator notes (for plan 13):**
- **Read the start.** It names the mapping's attribute, pin and filter, says that every workload of
  the verifier then needs exactly one entry (identity-only ones too), says the 3am cost in full,
  and names `machine_group:` subjects that mint for no one.
- **Two clocks.** Past `broker.directory.grace` with no server, a mapped workload's mints are
  refused. Its live sessions are a separate clock: they deny `context_stale` once port49d's
  `session.staleness_ceiling` has passed since the last scheduled refresh that reached the
  directory. The defaults are both 4h; changing one does not move the other.
- **Keep pre-warm on** (`broker.directory.prewarm.interval`, default 1h) where workloads run on a
  schedule. A nightly job's own last mint is about 24h old in an outage, far past grace. Pre-warm
  re-verifies every `machine_group:` member and every `spiffe://` identity a subject lists each
  hour, so the job mints within grace whether its grants come from a group or its own subject.
- **Pre-warm's budget.** `prewarm.max_principals` bounds people and workloads separately, so one
  interval makes up to twice that many verifications. Size it, and the DCs' load, for both.
- **The runbook line, for a DC outage past grace with workloads mapped:**
  - Mapped workloads stop minting, and `port49 workload` exits 75.
  - Their sessions deny `context_stale` at the ceiling.
  - The escapes are decision 38's: `session.staleness_ceiling: 0s` with a port49d restart, or
    stopping port49d so devices fall back to break-glass.
  - Removing `directory:` from the verifier, and restarting, returns workloads to identity subjects
    alone. Their `machine_group:` grants then mint for no one.

---

### Task 7: The 3am case at the client: `port49 workload` retries `directory_unavailable` and exits 75

**Files:**
- Test: `internal/workload/client_test.go` (`TestADirectoryOutageIsRetriedToTheDeadline`)
- Test: `cmd/port49/workload_test.go` (`TestADirectoryOutageExitsTemporary`)

**Interfaces:**
- Consumes: Task 5's 503 `directory_unavailable` with `Retry-After: 30`; plan 8's `workload.do`,
  `retriable`, `ErrTemporary` and `exitTemporary` (unchanged).
- Produces: nothing new. These pin the 3am behaviour the start line and decision 41 ruling 7
  promise, which plan 8's retry rule already gives.

- [ ] **Step 1: Write the tests**

In `internal/workload/client_test.go`, add:

```go
// A mapped workload's broker in a DC outage past grace answers 503
// directory_unavailable (decision 41 ruling 7): retried under one key to the
// deadline, then temporary, every device unminted.
func TestADirectoryOutageIsRetriedToTheDeadline(t *testing.T) {
	f := &fakeBroker{batchMax: 10, answers: []func(http.ResponseWriter, api.MintRequest){
		refuse(http.StatusServiceUnavailable, "directory_unavailable", "30")}}
	h := newHarness(t, f, 24*time.Hour)
	_, err := h.client(t).Mint(context.Background(), MintOptions{Devices: devices(2)})
	var te *TemporaryError
	if !errors.As(err, &te) || !errors.Is(err, ErrTemporary) || len(te.Unminted) != 2 ||
		!strings.Contains(err.Error(), "503 directory_unavailable") || len(f.keys) < 2 {
		t.Fatalf("%v keys %v", err, f.keys)
	}
	for _, k := range f.keys {
		if k != f.keys[0] {
			t.Fatalf("a retry under another key: %v", f.keys)
		}
	}
}
```

In `cmd/port49/workload_test.go`, add:

```go
// The 3am case (decision 41 ruling 7): through a DC outage past grace the
// broker answers 503 directory_unavailable; port49 workload token retries to
// --deadline, writes nothing, and exits 75 so cron tries the next window.
func TestADirectoryOutageExitsTemporary(t *testing.T) {
	down := workloadBroker(t, func(w http.ResponseWriter, _ api.MintRequest) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(api.Error{Error: "directory_unavailable", Detail: "no directory server answered " +
			"and no membership verified within the grace window is held; the agent retries"})
	})
	var out, errb bytes.Buffer
	if code := run(append(append([]string{"workload", "token"}, down...), "leaf1"), &out, &errb); code != exitTemporary ||
		out.Len() != 0 || !strings.Contains(errb.String(), "503 directory_unavailable") ||
		!strings.Contains(errb.String(), "1 of 1 devices were not minted; run again") {
		t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errb.String())
	}
}
```

- [ ] **Step 2: Run them**

Run: `go test ./internal/workload/ ./cmd/port49/ -run 'DirectoryOutage' -count=1 -v`
Expected: PASS at once. Plan 8 built the retry, so these are pins, not new behaviour. If either
fails, the failure is a regression in plan 8's client: stop and report it, and do not change
`retriable`.

- [ ] **Step 3: Commit**

```bash
git add internal/workload/client_test.go cmd/port49/workload_test.go
git commit -m "test(workload): a directory outage past grace exits 75 (decision 41 ruling 7)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

**Operator notes (for plan 13):** `port49 workload token` exits 75 in a directory outage past grace,
as in a broker outage. The Oxidized wrapper (`examples/oxidized`) already reads 75 as "leave
Oxidized as it was and try the next window". Nothing in the wrapper changes.

- [ ] **Step 4: The whole branch**

Run: `make test && make vet && go test -race ./internal/directory/ ./internal/policy/ ./internal/broker/ ./internal/config/ ./internal/port49d/ -count=1`
Expected: PASS, clean. Report the real output, with the counts.

---

### Task 8: L50, who can write the attribute: Windows Server AD and Samba AD

**Files:**
- Create: `tests/lab/l50_test.go` (`//go:build lab`)
- Create: `tests/lab/directory/windows/scripts/l50_seed.ps1`, `write_as.ps1`, `audit.ps1`
- Create: `tests/lab/directory/samba/l50-seed.sh`
- Modify: `tests/lab/windows_test.go` (`winScripts`, `winSecretParams`)
- Modify: `tests/lab/directory/samba/Dockerfile` (copy `l50-seed.sh`, as `set-attr.sh` is copied)
- Modify: `Makefile` (`lab-l50`)
- Modify: `tests/lab/README.md` (a "L50" paragraph under "Directories")
- Produced by the run: `tests/lab/results/L50-windows_ad.md`, `tests/lab/results/L50-samba_ad.md`,
  `tests/lab/evidence/L50-windows_ad.json`, `tests/lab/evidence/L50-samba_ad.json`
- Modify after the run: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L50, decision 41
  ruling 10)

**Interfaces:**
- Consumes:
  - L44's harness: `newDirectories`, `startWindowsDC`, `winDC.run`, `evidence`, `writeResult`,
    `winScrub`, `oneLineMax` and `l44RequireOptIn`'s pattern.
  - L43's: `startDirectories`, `labDir.exec` and the Samba container's LDAPS URI and bind.
- Produces: the L50 notes. Status `closed` only if both notes exist (CLAUDE.md rule 3).

**This task runs on the lab host (beehive), under the standing consent for lab runs. The lab is
single-occupant.**

- [ ] **Step 1: Check the lab is free, and wait if it is not**

Another lab run (L51, on `lab/l51`, device images under containerlab) may be in progress. Run:

```bash
pgrep -af "^/tmp/go-build[^ ]*/lab\.test" ; echo "lab.test: $?"
sg docker -c 'docker ps --format "{{.Names}}"' | grep -E '^(clab-|port49lab)' ; echo "containers: $?"
flock -n ~/.cache/port49-lab/windows.lock true ; echo "windows.lock free: $?"
df -h / /var/lib/docker
```

The lab is free only if the first two print exit 1 (nothing found) and the lock check prints 0.
If any shows a run, do not start, stop or remove anything. Report to the controller ("lab busy:
<what is running>"), and wait for its word. Never kill another run's process or containers. Check
the disk has at least 60 GB free for the Windows VM.

- [ ] **Step 2: A pinned worktree**

From the main checkout:
`git worktree add --detach .worktrees/lab-l50 <the branch's head commit>`. Run everything from
there (the lab-run rule: never from the shared feature worktree). The notes and evidence are
written into the feature worktree, not this one (Step 7, pre-flight I-9). Start a background stall
watchdog before the run, and re-arm it on each wake. Its signals:
- the mtime of `.worktrees/lab-l50/tests/lab/logs/directory/` and of
  `.worktrees/workload-directory/tests/lab/evidence/L50-*.json`;
- `pgrep -f "^/tmp/go-build[^ ]*/lab\.test"`;
- `sg docker -c 'docker ps'` for `port49labwin`.

It wakes the agent after 10 minutes with no progress. Give every SSH read and step a deadline (the
harness's `w.run` takes `within`).

- [ ] **Step 3: The Windows scripts**

`tests/lab/directory/windows/scripts/l50_seed.ps1`:

```powershell
# L50: the writers and the target. A service account in OU=Workloads, an
# Account Operators member, a delegated OU administrator (the delegation
# wizard's "Create, delete, and manage user accounts" on OU=Workloads), and an
# ordinary user, every one with actor_password. Idempotent: a re-run resets
# the passwords and the delegation, and removes a previous run's prescribed
# denies, so a reused DC's "default" cells are measured at the default. It
# answers the OU's SDDL after that, the evidence of what "default" was.
param([string]$actor_password)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$base = $domain.DistinguishedName
$nb = $domain.NetBIOSName
$ou = "OU=Workloads,$base"
if (-not (Get-ADOrganizationalUnit -LDAPFilter '(ou=Workloads)' -SearchBase $base -SearchScope OneLevel)) {
  New-ADOrganizationalUnit -Name Workloads -Path $base -ProtectedFromAccidentalDeletion $false
}
$pw = ConvertTo-SecureString $actor_password -AsPlainText -Force
function Set-Actor([string]$name, [string]$path) {
  if (Get-ADUser -Filter "sAMAccountName -eq '$name'") {
    Set-ADAccountPassword -Identity $name -Reset -NewPassword $pw
    Enable-ADAccount -Identity $name
  } else {
    New-ADUser -Name $name -SamAccountName $name -Path $path -AccountPassword $pw -Enabled $true -PasswordNeverExpires $true
  }
}
Set-Actor 'svc-oxidized-01' $ou
Set-Actor 'l50-acctop' "CN=Users,$base"
Set-Actor 'l50-ouadmin' "CN=Users,$base"
Set-Actor 'l50-user' "CN=Users,$base"
Add-ADGroupMember -Identity 'Account Operators' -Members 'l50-acctop'
# The wizard's ACEs: create and delete user objects, full control over them.
dsacls $ou /G "$nb\l50-ouadmin:CCDC;user" | Out-Null
dsacls $ou /I:S /G "$nb\l50-ouadmin:GA;;user" | Out-Null
# A previous run's prescribed denies (audit.ps1 acl set), and nothing else:
# an explicit deny of WriteProperty on user objects for SELF, Account
# Operators or l50-ouadmin. Never dsacls /R, which strips a trustee's every
# ACE, Account Operators' default grants on the OU included (pre-flight I-8).
$schema = (Get-ADRootDSE).schemaNamingContext
$userClass = [guid](Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=user)' -Properties schemaIDGUID).schemaIDGUID
$sids = @('S-1-5-10', 'S-1-5-32-548', (Get-ADUser 'l50-ouadmin').SID.Value)
$acl = Get-Acl -Path "AD:$ou"
$stale = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
  $_.AccessControlType -eq 'Deny' -and $_.ActiveDirectoryRights -eq 'WriteProperty' -and
  $_.InheritedObjectType -eq $userClass -and $sids -contains $_.IdentityReference.Value })
foreach ($r in $stale) { $acl.RemoveAccessRuleSpecific($r) }
if ($stale.Count -gt 0) { Set-Acl -Path "AD:$ou" -AclObject $acl }
$sddl = (Get-Acl -Path "AD:$ou").Sddl
@{ ou = $ou; target = (Get-ADUser 'svc-oxidized-01').DistinguishedName; removed_denies = $stale.Count
   sddl = $sddl.Substring(0, [Math]::Min(4000, $sddl.Length)) }
```

`tests/lab/directory/windows/scripts/write_as.ps1`:

```powershell
# L50: one write of one attribute on one entry, bound as user with password,
# over LDAP to this DC. Answers written (and whether the value reads back),
# or refused with the exception's type and message. Never echoes the password.
# A refusal is a result, not a thrown error, so its key is never "error".
param([string]$dn, [string]$attribute, [string]$value, [string]$user, [string]$password)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$nb = (Get-ADDomain).NetBIOSName
$cred = New-Object System.Management.Automation.PSCredential("$nb\$user", (ConvertTo-SecureString $password -AsPlainText -Force))
try {
  Set-ADObject -Identity $dn -Replace @{ $attribute = $value } -Credential $cred -Server localhost
  $got = (Get-ADObject -Identity $dn -Properties $attribute).$attribute
  @{ written = $true; reads_back = ("$got" -ceq $value) }
} catch {
  @{ written = $false; refused_type = $_.Exception.GetType().FullName; refused = "$($_.Exception.Message)" }
}
```

`tests/lab/directory/windows/scripts/audit.ps1`:

```powershell
# L50: the audit trail. mode "on" turns Directory Service Changes auditing on
# and puts a success-and-failure SACL for Everyone's writes on OU=Workloads,
# inherited by its objects; "read" answers the Security log's 5136
# (attribute modified) and 4662 (an access) events since a moment, each cut
# at 600 characters; "acl" sets or clears the prescribed deny on attribute.
param([string]$mode, [string]$since, [string]$attribute, [string]$state)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$domain = Get-ADDomain
$nb = $domain.NetBIOSName
$ou = "OU=Workloads,$($domain.DistinguishedName)"
switch ($mode) {
  'on' {
    auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable | Out-Null
    $acl = Get-Acl -Path "AD:$ou" -Audit
    $everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule($everyone, 'WriteProperty',
      'Success,Failure', [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All)
    $acl.AddAuditRule($rule)
    Set-Acl -Path "AD:$ou" -AclObject $acl
    @{ audit = (auditpol /get /subcategory:"Directory Service Changes" | Out-String).Trim() }
  }
  'read' {
    $t = [DateTime]::Parse($since, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
    $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5136, 4662; StartTime = $t } -ErrorAction SilentlyContinue |
      ForEach-Object { $m = "$($_.Message)" -replace '\s+', ' '
        @{ id = $_.Id; time = $_.TimeCreated.ToUniversalTime().ToString('o'); message = $m.Substring(0, [Math]::Min(600, $m.Length)) } })
    @{ events = $evs }
  }
  'acl' {
    # The prescribed ACL under test: an inherited deny of write on attribute,
    # on OU=Workloads, for SELF, Account Operators and the delegated admin.
    # "clear" removes exactly the rules "set" adds, never another ACE: dsacls
    # /R would strip each trustee's every ACE on the OU, Account Operators'
    # default create/delete grants included (pre-flight I-8).
    $schema = (Get-ADRootDSE).schemaNamingContext
    $attrGuid = [guid](Get-ADObject -SearchBase $schema -LDAPFilter "(lDAPDisplayName=$attribute)" -Properties schemaIDGUID).schemaIDGUID
    $userClass = [guid](Get-ADObject -SearchBase $schema -LDAPFilter '(lDAPDisplayName=user)' -Properties schemaIDGUID).schemaIDGUID
    $acl = Get-Acl -Path "AD:$ou"
    foreach ($sid in @('S-1-5-10', 'S-1-5-32-548', (Get-ADUser 'l50-ouadmin').SID.Value)) {
      $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        (New-Object System.Security.Principal.SecurityIdentifier($sid)), 'WriteProperty', 'Deny', $attrGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents, $userClass)
      if ($state -eq 'set') { $acl.AddAccessRule($rule) } else { $acl.RemoveAccessRuleSpecific($rule) }
    }
    Set-Acl -Path "AD:$ou" -AclObject $acl
    $sddl = (Get-Acl -Path "AD:$ou").Sddl
    @{ ou = $ou; state = $state; sddl = $sddl.Substring(0, [Math]::Min(4000, $sddl.Length)) }
  }
}
```

In `tests/lab/windows_test.go`, add to `winScripts`: `"l50_seed": {"actor_password"}`, `"write_as":
{"dn", "attribute", "value", "user", "password"}`, `"audit": {"mode", "since", "attribute",
"state"}`. Add `"actor_password", "password"` to `winSecretParams`. Then run `go test -tags lab
./tests/lab/ -run TestWindowsScriptsNeverEchoASecret -count=1`. Expected: PASS: no script writes a
secret parameter.

- [ ] **Step 4: The Samba seed**

`tests/lab/directory/samba/l50-seed.sh`:

```sh
#!/bin/sh
# l50-seed.sh <password> [acl set|clear <attribute> | sddl]: L50's writers on
# Samba AD, as l50_seed.ps1 makes them on Windows. The password is read from
# $1 and never printed. With "acl", it sets or clears the prescribed deny of
# write on <attribute> on OU=Workloads for SELF, Account Operators and
# l50-ouadmin. With "sddl", it prints the OU's security descriptor, the
# evidence of what the "default" cells ran under (pre-flight I-8).
set -eu
pw=$1
sam=/var/lib/samba/private/sam.ldb
base=$(ldbsearch -H $sam -s base -b "" defaultNamingContext | sed -n 's/^defaultNamingContext: //p')
ou="OU=Workloads,$base"
if [ "${2:-}" = sddl ]; then
  samba-tool dsacl get --objectdn="$ou"
  exit 0
fi
if [ "${2:-}" = acl ]; then
  # --show-binary prints schemaIDGUID as a dashed GUID; anything else (empty,
  # or base64 from a "schemaIDGUID::" line) would make an ACE with no object
  # GUID, a deny of every property: fail loudly instead (pre-flight M-7).
  guid=$(ldbsearch -H $sam --show-binary -b "CN=Schema,CN=Configuration,$base" "(lDAPDisplayName=$4)" schemaIDGUID |
    sed -n 's/^schemaIDGUID: //p')
  case "$guid" in
    ????????-????-????-????-????????????) ;;
    *) echo "l50-seed.sh: no schemaIDGUID for $4 (read '$guid'); no ACE written" >&2; exit 2 ;;
  esac
  ouadmin=$(samba-tool user show l50-ouadmin --attributes=objectSid | sed -n 's/^objectSid: //p')
  case "$ouadmin" in
    S-1-5-21-*) ;;
    *) echo "l50-seed.sh: no objectSid for l50-ouadmin (read '$ouadmin'); no ACE written" >&2; exit 2 ;;
  esac
  for sid in PS AO "$ouadmin"; do
    ace="(OD;CI;WP;$guid;bf967aba-0de6-11d0-a285-00aa003049e2;$sid)"
    if [ "$3" = set ]; then samba-tool dsacl set --objectdn="$ou" --sddl="$ace" >/dev/null
    else samba-tool dsacl delete --objectdn="$ou" --sddl="$ace" >/dev/null; fi
  done
  exit 0
fi
samba-tool ou create "$ou" >/dev/null 2>&1 || true
for u in svc-oxidized-01 l50-acctop l50-ouadmin l50-user; do
  path=CN=Users
  [ "$u" = svc-oxidized-01 ] && path=OU=Workloads
  samba-tool user create "$u" "$pw" --userou="$path" >/dev/null 2>&1 || samba-tool user setpassword "$u" --newpassword="$pw" >/dev/null
done
samba-tool group addmembers "Account Operators" l50-acctop >/dev/null 2>&1 || true
sid=$(samba-tool user show l50-ouadmin --attributes=objectSid | sed -n 's/^objectSid: //p')
# The wizard's ACEs: create and delete user objects; full control over them.
samba-tool dsacl set --objectdn="$ou" --sddl="(OA;;CCDC;bf967aba-0de6-11d0-a285-00aa003049e2;;$sid)" >/dev/null
samba-tool dsacl set --objectdn="$ou" --sddl="(A;CIIO;GA;;bf967aba-0de6-11d0-a285-00aa003049e2;$sid)" >/dev/null
```

`samba-tool dsacl delete` exists in Samba 4.16 and later. If the image's version lacks it (run
`samba-tool dsacl --help` in the container), clear the ACEs by re-seeding the OU (`samba-tool ou
delete --force-subtree-delete`, then the seed), and say so in the note. In the Samba Dockerfile,
copy `l50-seed.sh` beside `set-attr.sh`, mode 0755.

- [ ] **Step 5: `tests/lab/l50_test.go`**

```go
//go:build lab

package lab

// TestL50WorkloadAttributeWriters is lab register row L50: who can write the
// attribute a workload certificate's directory mapping reads (spec §13
// decision 41 ruling 10), on Samba AD and on Windows Server AD. Run it, from a
// worktree pinned at the commit under test, with
//
//	PORT49_LAB_L50=1 go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$' -count=1 -v -timeout 240m
//
// PORT49_LAB_WINDOWS_REUSE runs on a kept DC, as L44's does.
```

with these pieces. Each body is short, and the steps above show what each does.

- `const l50Claim` is the L50 row's claim text, verbatim from §15 after Task 1.
- `var l50Attributes = []string{"uid", "description", "wWWHomePage", "url"}`.
- `var l50Writers = []string{"svc-oxidized-01" /* SELF */, "l50-acctop", "l50-ouadmin", "l50-user"}`.
- `type l50Cell struct { attr, writer, acl string; written, readsBack bool; code int; refused string }`.
  `code` is the LDAP result code on Samba, 0 when written, and -1 for Windows' typed refusal.
  `refused` is scrubbed and cut to 160 characters.
- `func l50Value(attr, writer, acl string) string` returns `"spiffe://corp.example.com/host/l50-" +
  attr + "-" + writer + "-" + acl`. Each write is distinct, so a reads-back is never an earlier
  write's.
- `func (l *labDir) l50Samba(t *testing.T, ev *evidenceLog, password string) (cells []l50Cell, notes string)`:
  1. Exec `l50-seed.sh <password>` in the Samba container, so the password is passed as an argument
     and never printed.
  2. Exec `l50-seed.sh <password> sddl` and put its output, cut to 4000 characters, in `notes`
     under "The OU's security descriptor before the default cells" (pre-flight I-8). The container
     is fresh each run (`startDirectories` runs `down -v` first), so this is the default.
  3. For each ACL state (`default`, then `l50-seed.sh <pw> acl set <attr>` per attribute, which is
     `prescribed`), for each attribute and writer: dial the Samba LDAPS URI with go-ldap. The TLS
     config is `l.d.pki.clientTLS(l.uri)`. A non-zero exit of `acl set` fails the test as the
     harness's fault (M-7: no ACE with an empty GUID is ever measured).
  4. Bind simple as `<writer>@corp.example.com` with the password, then `Modify` the target DN with
     `Replace(attr, l50Value(...))`.
  5. Record the result code (`ldapCode(err)`), or written. On written, read the value back with
     `Search` at base scope.
  6. Each step is `ev.mark`ed, and the password is never in a mark.
  7. After the cells, the audit (pre-flight I-7). The container runs `samba -i`, which logs to
     stdout, so the audit is read from `docker compose logs --no-color --since <t> samba`
     (`l.d.dockerCompose`), never from `/var/log/samba`. Take `t0`, run one accepted and one
     refused write again, and read the logs since `t0`: a `dsdbChange` record naming the target DN
     is "as installed: in the log", none is "as installed: not". Then
     `l.exec("smbcontrol", "samba", "debug", "dsdb_json_audit:5 dsdb_audit:5")`, take `t1`, and do
     the same.
  8. **The positive control.** After the smbcontrol, the accepted write must produce a `dsdbChange`
     line naming the target DN. If none appears, `t.Fatalf` as the harness's fault ("the audit
     control saw no dsdbChange after debug dsdb_json_audit:5"); never record "not audited" from a
     log the harness could not read. Each matching line is `ev.mark`ed, scrubbed (`winScrub`) and
     cut to 600 characters.
- `func (l *labDir) l50Windows(t *testing.T, ev *evidenceLog, password string) (cells []l50Cell, notes string)`:
  1. Run `w.run(t, "l50_seed", {"actor_password": password}, 5*time.Minute, &seed)`. Put
     `seed.removed_denies` and `seed.sddl` in `notes` under "The OU's security descriptor before the
     default cells": the evidence that a reused DC's default cells ran at the default (pre-flight
     I-8).
  2. Run the same matrix through `write_as`, with `acl` state changes through `audit` mode `acl`.
     The `acl clear` after the prescribed cells leaves the OU as the seed found it; its `sddl`
     answer is marked.
  3. For the audit, run `audit read` since the step's start, as installed. Then run `audit on`, one
     accepted and one refused write again, and `audit read`. A 5136 event naming the target DN and
     the attribute is "in the audit log"; none is "not". Record each event's id and time, never its
     message beyond 600 characters.
- `func l50Table(cells []l50Cell) string` writes the Markdown matrix with header `| attribute |
  writer | ACL | written | reads back | refusal |`. Then it writes one line per writer and ACL
  summarising which attributes it could write.
- The test (pre-flight I-6: the two phases never share a `tests/lab/logs/directory` tree, since
  `newDirectories` starts with `os.RemoveAll(d.dir)` and `startDirectories` calls it):
  1. `l50RequireOptIn(t)` skips unless `PORT49_LAB_L50=1`.
  2. Generate `password` (`winPassword()`) once, for both platforms.
  3. **Samba first, in its own subtest**, as `l44CompareCapabilities` runs its directories:
     `t.Run("samba_ad", func(t *testing.T) { … })`. Inside it:
     - `sd := startDirectories(t)`; `sd.runSel = "^TestL50WorkloadAttributeWriters$"`;
       `sd.extra = append(sd.extra, password)`, so `writeResult`'s secret check (`noteText`, which
       reads the `directories` it is given) refuses the actor password in the Samba note too.
     - `ev := evidence(t, sd, "L50-samba_ad")`; `cells, notes := sd.samba.l50Samba(t, ev, password)`;
       `ev.assertClean(t, password, sd.password)`.
     - `writeResult(t, sd, "L50", sd.samba, l50Claim, sd.samba.version(t),
       sd.samba.configNote()+notes+l50Table(cells), "tests/lab/evidence/L50-samba_ad.json")`.

     `startDirectories` registers its cleanup on the subtest, so the Samba containers are down
     (and `samba.log` kept) before the Windows phase starts.
  4. **Then Windows, after the Samba subtest returns**, pass or fail:
     `t.Run("windows_ad", func(t *testing.T) { … })`. Inside it:
     - `d := newDirectories(t)` (a fresh tree: its own PKI, `lab.env` and krb5 files);
       `d.runSel = "^TestL50WorkloadAttributeWriters$"`; `d.extra = append(d.extra, password)`.
     - `dc := startWindowsDC(t, d)`; `ev := evidence(t, d, "L50-windows_ad")`;
       `cells, notes := dc.l50Windows(t, ev, password)`; `ev.assertClean(t, password, d.password)`.
     - `writeResult(t, d, "L50", dc, l50Claim, <the DC's build from facts>, notes+l50Table(cells),
       "tests/lab/evidence/L50-windows_ad.json")`.
  5. Each platform's note is written even when the other fails, so a partial run leaves what it
     measured: a failed subtest does not stop its sibling.
  6. `newDirectories` for Windows removes the Samba phase's `tests/lab/logs/directory`, its
     `samba.log` included. The Samba audit lines the note relies on are in the Samba evidence
     (`l50Samba`'s items 7 and 8), which `evidence` writes under `directoryOut()`, not under
     `tests/lab/logs`, so nothing the note cites is lost.

`make lab-l50` runs the line above. Add the target after `lab-directory`:

```make
# L50 (plan 8b): who can write a workload mapping's attribute, on Samba AD and
# the Windows Server DC. Needs Docker with Compose v2.24.4+, KVM, the cached
# evaluation ISO and PORT49_LAB_L50=1; see tests/lab/README.md, "Directories".
lab-l50:
	PORT49_LAB_L50=1 go test -tags lab ./tests/lab/ -run '^TestL50WorkloadAttributeWriters$$' -count=1 -v -timeout 240m
```

and a README paragraph naming the run line, the four writers, the four attributes, the two ACL
states and the audit modes, the rule that `actor_password` is generated per run and never
printed, and that a run from a pinned worktree sets `PORT49_LAB_DIRECTORY_OUT` to the branch's
worktree so the notes land where they are committed.

- [ ] **Step 6: Unit-check and commit the harness**

Run: `go vet -tags lab ./tests/lab/ && go test -tags lab ./tests/lab/ -run 'TestWindowsScriptsNeverEchoASecret|TestL50' -count=1`.
Without `PORT49_LAB_L50`, `TestL50` skips. Expected: vet clean, PASS or SKIP.

```bash
git add tests/lab/l50_test.go tests/lab/directory/ tests/lab/windows_test.go tests/lab/README.md Makefile
git commit -m "test(lab): L50, who can write a workload mapping's attribute

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 7: Run it**

Immediately before starting, re-run Step 1's three checks (pre-flight M-8): L51 may have started
since. If any shows a run, do not start; report "lab busy" and wait, as Step 1 says.

From the pinned worktree, with the watchdog armed, and the notes and evidence written into the
feature worktree (pre-flight I-9: the harness's `PORT49_LAB_DIRECTORY_OUT`, read by
`directoryOut()`):

```bash
cd $HOME/git/port49/.worktrees/lab-l50
sg docker -c 'PORT49_LAB_DIRECTORY_OUT=$HOME/git/port49/.worktrees/workload-directory make lab-l50'
```

Wait in a foreground loop with a deadline, `pgrep -f "^/tmp/go-build[^ ]*/lab\.test"` every 60s,
up to 240 minutes. Re-arm the watchdog each wake.

Expected: two notes under `.worktrees/workload-directory/tests/lab/results/`, and two evidence
files under its `tests/lab/evidence/`; nothing new under `.worktrees/lab-l50/tests/lab/results/`
(check with `git -C .worktrees/lab-l50 status --short`). Each note has the date,
the platform and image version (Samba's `samba --version`; Windows' build from `facts`), the claim,
the matrix, the audit observations and the capture pointer. Read both notes in full before going on.
Neither holds a password: `writeResult` refuses one.

- [ ] **Step 8: Close the row, or keep it open, by rule 3**

- **Both notes exist and the matrix is complete for both platforms:** edit L50's Status in §15 to
  `closed — measured <date>; tests/lab/results/L50-windows_ad.md, tests/lab/results/L50-samba_ad.md`.
  Then edit decision 41 ruling 10 to state what was measured:
  - which writers could write which attributes, under each ACL, on each platform;
  - whether a write reaches the audit log as installed, and with auditing on.

  Cite both notes. If the prescribed ACL did not stop a writer (for example, an explicit allow in a
  user object's default security descriptor beating an inherited deny), ruling 10 says so, and says
  the docs prescribe nothing until a fix is measured.
- **One platform measured and the other not:** the row stays open (rule 3). Commit the one note, and
  say in the commit which platform is missing and why.
- **A result contradicts a doc** (for example, decision 41 or design §7 implying something the lab
  refutes): the doc is wrong (rule 4). Fix it, cite the note, and say so in the commit message.

The commit is made on `feature/workload-directory`, in its worktree, where Step 7 wrote the notes;
never in the detached `.worktrees/lab-l50`, where a commit would be orphaned and Step 9 deletes the
files (pre-flight I-9).

```bash
cd $HOME/git/port49/.worktrees/workload-directory
git branch --show-current   # expect feature/workload-directory
git add tests/lab/results/L50-*.md tests/lab/evidence/L50-*.json docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: close lab register entries L50

<what each platform measured, in two to four lines; any doc corrected and why>

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

(Use `docs: L50 measured on <platform>, still open` when the row stays open.)

- [ ] **Step 9: Leave the lab as found**

- Bring the Samba containers down; the harness's cleanup does it.
- Leave the Windows DC down unless `PORT49_LAB_WINDOWS_KEEP` was set.
- Copy any raw captures to the main checkout's `tests/lab/captures/` before removing the worktree.
  The L50 run writes no pcap: the wire is TLS, and the evidence is the client's JSON lines, as
  L42–L44's is. Check with `ls tests/lab/captures/`.
- Confirm the notes and evidence are committed on `feature/workload-directory` (Step 8) and that
  `git -C .worktrees/lab-l50 status --short` lists no L50 file, then
  `git worktree remove .worktrees/lab-l50`.
- Report to the controller that the lab is free.

**Operator notes (for plan 13), written only from the notes:**
- **Which attribute, and the ACL.** Name the attribute L50 found writable only by directory
  administrators under the prescribed ACL, on each platform. If none was, the docs say so, and say
  to use a dedicated schema attribute whose ACL the directory team owns.
- **The audit.** Say whether a write to it reaches the audit log as installed, and how to turn that
  on, from the notes' audit section.
- Until this task closes L50, the docs say only the requirement.

---

## Operator-facing notes (for the pull request body)

- **Workload directory groups** (decision 41), opt-in per verifier: `broker.identity.machines[]`'s
  `x509` entry takes `directory: {kind: spiffe_id, attribute: <yours>, allow_weak: true, issuers:
  [<the workload issuing CA's DN>]}`, with `broker.directory` configured.
- **Without it, nothing changes:** a workload never reaches the directory and mints with every DC
  down.
- **With it:**
  - **One entry per workload.** Each workload the verifier accepts, identity-only ones included,
    must have exactly one directory entry holding its SPIFFE ID, exactly, as the one value of
    `attribute`. Two entries holding one ID are both refused, and an entry deleted and re-created
    needs `port49 directory forget spiffe://…`.
  - **One entry, one domain.** An entry holding a SPIFFE ID in `attribute` is a workload's; a
    person's certificate that maps to it is refused `identity_unmapped`.
  - **Grants.** A new `machine_group: <group>` subject grants that group's workloads. A person in it
    never gets those grants, and a workload never gets a `group:` subject's.
  - **The username** is the workload's identity subject's declared one when it declares one, else
    its entry's `username_attribute`.
  - **The 3am cost.** A DC outage past `broker.directory.grace` (default 4h) stops mapped workloads
    minting (`directory_unavailable`, `port49 workload` exit 75), and their device sessions deny
    `context_stale` once port49d's `session.staleness_ceiling` has passed since the last refresh
    that reached the directory. Keep pre-warm on so scheduled jobs stay within grace: it verifies
    `machine_group:` members and every `spiffe://` identity a subject lists, up to
    `prewarm.max_principals` workloads besides as many people. The start says all of this.
- **Who can write `attribute`** decides which workload an entry's groups reach. Lab L50 measures it
  on Windows AD and Samba (see its notes). The docs prescribe an ACL only as measured.
- **CI.** `port49 policy diff` gates a changed `machine_group:` as a changed `group:`, including a
  move between the two keys. `port49 policy lint` names each group subject's key and the config it
  mints under.

## Self-review against the spec

**Coverage.** Each brief item and each spec ruling, with its task:
- **The constraint** (a machine principal matches only a machine-scoped group subject; one subject
  of both domains a load error; the diff gate and CI cover the machine form): Task 4. The broker's
  both-direction tests are in Task 5.
- **The mapping:**
  - opt-in per verifier, the SPIFFE-ID kind, exactly one entry: Tasks 2 and 3;
  - weak under ruling 1, pinned: Tasks 2, 3 and 5;
  - the `objectGUID`/`entryUUID` pin: Task 2;
  - the store record by SPIFFE ID: Task 2.
- **The username** (ruling 3 via decision 8; declared on the group subject, ruled out by R2): Tasks
  1, 4 and 5; judged again at both holds, the mint's and the session refresh's (`heldCollision`):
  Task 5.
- **One entry, one domain** (decision 41 ruling 4, added at pre-flight): Task 2's `notWorkload`
  and `TestOneEntryIsOneDomain`; the §5.7 row in Task 1.
- **The plumbing:**
  - per-domain gates (`memberFor`, `storedMemberOf`, `storedMember`, the scheduled judge): Task 5;
  - `forget` and `normalPrincipal`: Task 5;
  - pre-warm, machine groups and identity-only workloads: Task 6;
  - the membership record keyed by SPIFFE ID: Task 2.
- **Lint** (the controller's ruling): Task 4 Step 8.
- **The 3am case:**
  - the mint 503: Task 5;
  - exit 75: Task 7;
  - `context_stale` at the ceiling (broker unstamped): Task 5, with the daemon side the existing
    `TestStaleContextDenies`;
  - the start line: Task 6;
  - the operator notes: Tasks 5, 6, 7 and the PR notes.
- **Opt-in pinned by a test:** Task 5's `TestWithoutTheMappingAWorkloadNeverReachesTheDirectory`.
  Plan 8's `TestAWorkloadMintsWhileTheDirectoryIsDown` stays.
- **Lab L50, and "only directory administrators can write it" unasserted until it closes:** Task 8,
  and the Global Constraints. The harness's own soundness: the phases never share a logs tree
  (Step 5), the Samba audit reads the container's stdout with a positive control, the default
  cells run at a recorded default (the seeds remove only L50's own denies and record the SDDL),
  and the notes land in the branch's worktree (Steps 7–8).
- **The lab-free check:** Task 8 Step 1, repeated just before the run (Step 7).
- **Spec text first, with provenance:** Task 1. No §5.7 code is added; four rows widen.
- **Security:**
  - both domains on one subject: Task 4;
  - no cross-domain match, both directions: Tasks 4 and 5;
  - no token logged: Task 5's `TestAMappedWorkloadMintsThroughItsMachineGroup` checks the decision
    log and the process log;
  - snake_case: every new key (`machine_group`, `allow_weak`, `user_filter`, `kind`, `attribute`,
    `issuers`).
- **Decision 38 ruling 17's analogue** (`machine_group:` subjects with no mapping said): Task 6.

**Placeholders.**
- The only execution-time values are the measured dates, versions and matrices in Task 8's notes,
  and its closing commit's summary.
- Task 8's Go harness is given as declarations and step lists over existing helpers, in plan 8's
  lab-task style. Its PowerShell and shell are given whole.

**Type consistency.**
- `directory.WorkloadMapping{Attribute, Issuers, UserFilter, TrustDomains}` is built by Task 3's
  `checkWorkloadMapping`. Task 5's `mapped` and Task 6's `workloadMapping` build it in tests. Task 2
  reads it (`workloadAttrs`, `workloadIdentityOf`, `Pinned`), as do Task 5 (`workloadMapped`,
  `CertCallerOf`) and Task 6 (`announceDirectory`, `PrewarmAll`).
- `policy.Member.Domain` is set by Task 5's `member` (`DomainHumans`), `workloadMember` and
  `storedWorkload` (`DomainMachines`), and read by Task 4's `groupDomainOf`.
- `Subject.GroupKey()` (Task 4) is read by `diff.go`, `cmd/port49/policy.go`'s report and access
  review.
- `Policy.DeclaredFor` (Task 4) is read by Task 5's `workloadMember` and `storedWorkload` (the
  no-record fallback).
- `heldCollision(pol, m, answer)` (Task 5 Step 3) is called by the mint (`broker.go`) and by
  `RefreshSession` (`sessionrefresh.go`), each with the `m` and `answer` `memberFor` gave.
- `Config.notWorkload(e)` and the widened `entryAttrs` (Task 2 Step 5) are read by `verify`'s
  person branch (Task 2 Step 6).
- `Resolver.PrewarmAll(ctx, groups, machineGroups, workloads)` (Task 6) is called by `Prewarm`
  (`nil, nil`), by port49d's `prewarm` (`pol.SPIFFEIdentities()`'s keys), and by Task 6's tests.
  `prewarmWorkloads` calls Task 2's `VerifyWorkload`.
- `l50Samba` and `l50Windows` return `(cells []l50Cell, notes string)`; the test passes `notes` to
  `writeResult` (Task 8).
- `Resolver.grace`'s new `declared bool` is passed `true` by `Map` and `Current` and `false` by
  `CurrentWorkload` (Task 2).
- `Resolver.pinned`'s new `attr string` is passed by `verify` (Task 2).

**Review Focus.** Each of the five names its test in its owning task.

**Amendment 1 (pre-flight, 2026-10-09).** Every Important (I-1 to I-9) and Minor (M-1 to M-8)
finding of the pre-flight review is applied as the reviewer proposed, with one correction: M-3's
case-variant entry is asserted `identity_ambiguous`, not "neither matches nor ambiguous", because
the uniqueness search (`heldElsewhere`) reads no values and refuses any second entry the directory
returns, which is the fail-closed answer Review Focus 1 already promised. I-2's refusal fires on a
SPIFFE ID in the attribute, not on any value, so a `description`-style attribute set on people
refuses no one. The controller's lint ruling is Task 4 Step 8.

## Questions for the controller

Each comes with a recommendation; none blocks writing or executing the plan as written. **Ruled by
the controller, 2026-10-09: all six as recommended** (Q2's start-line cost is Task 6's line 1, added
by amendment 1; Q5 adds Ryan's production attribute if he names one).

1. **The username source (R2).** The brief allows "from the entry … or declared on the machine
   group subject". The plan rules: the identity subject's declared name wins, else the entry's, and
   never one on `machine_group:`. **Recommend: keep.** A group-declared name would put every member
   in one `(nas, username)` context, and two groups could declare two. "Declared wins" means
   turning the mapping on renames no workload.
2. **Every workload of a mapped verifier needs an entry (ruling 1).** With `directory:` on, a
   workload with an identity subject and no directory entry is refused `identity_unmapped`, and an
   outage stops even identity-only workloads past grace. The alternative is to treat "no entry" as
   "identity subjects only", which is softer but makes a deleted entry silently keep the identity
   grants. **Recommend: keep** (decision 38 ruling 2's "one entry or no principal"). The start line
   says it.
3. **`issuers:` required (R4)**, though the chain must already end at the workload anchor.
   **Recommend: keep.** It is ruling 1's rule for every weak kind, and it stops a second
   intermediate under the anchor from serving the mapping. The alternative, defaulting `issuers` to
   the anchor's subject, would accept every intermediate the anchor signs.
4. **`attribute` has no default (R3).** **Recommend: keep until L50,** then name the measured
   attribute in the docs. Still no default in code, since the safe choice is per directory.
5. **L50's attribute candidates and writers.** The plan measures `uid`, `description`,
   `wWWHomePage` and `url`. The writers are SELF, Account Operators, a delegated OU admin and an
   ordinary user. **Recommend: confirm.** Add a candidate now if Ryan prefers a specific attribute
   from production AD (for example an `extensionAttribute`, which needs the Exchange schema, absent
   on the lab DC).
6. **Should the start line name L50's status?** The plan's line states the requirement only, so no
   runtime line goes stale when L50 closes. **Recommend: keep.** The docs carry the measured facts.
