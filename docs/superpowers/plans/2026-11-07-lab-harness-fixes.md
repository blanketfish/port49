# Lab Harness Fixes (#47) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the lab harness on `main` measure again where plan 12 left it behind (issue #47, and #46's diagnosis), then rerun only the entries it touches.

**Architecture:** Harness-only changes under `tests/lab/`, plus one line of `tests/lab/README.md`. No product code, spec row, reason code or metric changes. Each fix is first a red `*_unit_test.go` that `make lab-unit` runs without a device. Two items cannot be settled from code (#46's missing hello and the NX-OS boot hang), so they get instrumentation and a lab run whose evidence is judged before any fix.

**Tech Stack:** Go 1.26, the existing `tests/lab` package (`//go:build lab`), `internal/policy`, `internal/admission`, `internal/directory`, `internal/fence`. No new module.

**Spec and history:**
- Issue #47 (and its two comments), issue #46.
- `docs/superpowers/plans/README.md`, "Pre-beta fixes — Task 26, the full lab regression".
- Decision 53 ruling 3 (`91e18f58`, plan 12a): the device key sets are the policy's, and port49d refuses a policy with no `keys:` block (`internal/port49d/main.go` `parseBundle`), or a device whose `key_ref` the block lacks (`internal/policy/admit.go:138`).
- Decision 53 ruling 11, the fence (plan 12), and `85356f41` ("the lab hands daemons private copies of every fenced file it keeps inside the repository"): `tests/lab/private_files_test.go`.
- `tests/lab/results/L76-nokia_srlinux.md` cell (k): a TACACS+ user's exec channels run on SR Linux 26.7.2.

## Root causes (investigation 2026-11-07, `main` `ffac5193`)

1. **No `keys:` block (L66, L80, and four entries the issue did not name).** There is no shared helper. Each harness that `91e18f58` fixed inlines the block (`l33_test.go`, `l67_test.go`, `l69_test.go`, `localbroker_test.go`, `slice/*.yaml`, `quarantine-sync/*.yaml`, `l29/policy.yaml`). These were missed:
   - `l66_test.go` `l66Policy`: no `keys:` (L66, five platforms).
   - **L80 (`TestQualify`).** `tests/qual/qual-policy.yaml` declares key `k` (`env:PORT49_KEY_RUN`). The lab inventory `tests/lab/inventory-lab.yaml` assigns `lab_key`, so `leaf1` and the rest are refused. The mock never sees this, because `internal/port49d/qual_test.go:263` writes its own inventory with `key_ref: k`.
   - `l78.go` `l78Policy` (TestL78, not in the manifest): no `keys:`. L78 records a refused reload as a measured row ("refused at load"), so the run would record the harness bug as data.
   - `projection_test.go` `projectionShape` (TestProjectionDifferential, not in the manifest): no `keys:`, and it starts port49d with a broker.
   - `l62/stack_test.go` `policyYAML` (L62, excluded from the manifest, run by hand): `key_groups` names `k`, and there is no `keys:`.
   - **L28's rotation cell runs a removed flag.** It runs `port49 keys status --config`, and `91e18f58` removed `--config` (`cmd/port49/policy.go` `policyFiles.register`), so the tool exits 2. `tests/lab/l28/policy.yaml` has no `keys:` either. L28 "passed" Task 26 because the test never checks the exit. The committed notes (`719721c7`) show `(exit: exit status 2)` at line 127 where the key table should be.
   - Not affected:
     - `junos_baseline_test.go` loads its policy offline, with no key groups, so the policy is never assessed.
     - `l60/broker_test.go` runs `internal/broker` in process, never `parseBundle`.
     - `oidc_e2e_test.go` and `oxidized_test.go` add to `deploy/compose`'s policy, which has `keys:`.
     - L29 and L31 assign `lab_key2` on purpose, as their measurement.
2. **The fence (L42-L43, L48).** `85356f41` stages files that a config's text names, through `stagePrivateFiles` and its `stagedKeys`, on the `derivedConfig`, qualify and `startDaemonWith` paths, and it stages the directory CA (`dirPKI.privateCA`). Two harnesses take neither path:
   - **L48.** `localbroker_test.go` `prepareLocalBroker` writes its own `port49d.yaml`, policy, inventory, revocations file and PKI under `tests/lab/logs/workload/local-broker{,-crl}` (`l48_test.go:433`, `:638`). `startBrokerProcess` then runs port49d on them. The workload anchor `r.anchor` is in `tests/lab/logs/host-w`. None of these files is staged, and `stagedKeys` has no `revocations_file` anyway.
   - **L43.** `directory_test.go` `bindExternal` hands the in-tree `brokerCert` and `brokerKey` to `directory.LoadCredentials` in process (`l43_test.go` `tryBind`). `bindGSSAPI` hands over the in-tree keytab and `krb5.conf` paths the same way. Only `CAFile` was staged.
3. **L76.** `933d45bb` and then `92fe55fc` (the L88 work of 2026-11-04, in `be92d427`) changed `lab.loginWithin` in `harness_test.go`. For `nokia_srlinux` it now runs `ptyCommands` with an `echo l88-end` added and the outputs shifted by one slot. The comment cites "(L76)" for "SR Linux's sshd does not run an exec command in sr_cli".
   - L76 never measured that. The words are L76's own INVALID hint at `l76_test.go:434`, a fallback guess. L76's note, cell (k), measured a TACACS+ user's first and second exec channels running.
   - `l76_test.go:431` also says L76 must not use `ptyCommands`, because `l.shell` waits for a Cisco or EOS prompt and sends `terminal length 0`.
   - So L76's `outs[0]` is no longer the session table that its exec channel printed. The fix restores exec for L76 and keeps L88's path for L88. No device claim changes.
4. **The NX-OS hang.**
   - The `within 8m0s` in the error is `tacacsReadyBudget` (`waitTACACSReady`). It expires after `waitDeviceReady` has already seen SSH authentication. So the device served SSH and never sent TACACS+, which matches the README's "the container log stops after `feature netconf`".
   - The code cannot show whether that is memory pressure, a slow boot or a stuck VM. So the harness gets the timing and host lines, and the timeout stays as it is.
5. **L80 and a dirty tree.** `treeDirty(root, codePaths...)` (`qualify_test.go:70` and `:639`, `l80_test.go:79`) covers all of `tests/lab`, including other entries' results and evidence. **Recommendation: scope the check, not the order.** The check exists so that bin/port49d and the harness are clean builds of HEAD (review I2, N4). Other entries' notes are no input to the qualify run: nothing reads them and nothing embeds them. Putting L80 first would only hold under a full run. It breaks under `-only`, a rerun or any manual order, and it would still refuse L80's own second batch. The scoped check still covers code, untracked files, and L80's, QUAL's and L78's own outputs (Task 8).
6. **#46, L73-nxos106.**
   - `cellF` reads `e.first`, the connections of cell (a)'s control login, or of its port-300 retry. `l73FirstHello` finds none with a parsed ClientHello.
   - The code does not say whether those connections were plain port 49, an incomplete stream or something else. The capture is the evidence, and it is never decoded by hand.
   - So Task 10 makes the INVALID line name each connection's kind, and the L73-nxos106 run is judged on that line.
7. **The local labpcap mismatch (comment on #47).** This is not a TLS question, and no task covers it. The run of `go test ./tests/lab/labpcap/` in the main checkout fails on 23 pairs. All are plain-TCP L88 (f) and (g) captures: 2 have no committed evidence, and 21 fail with `record 0: the record header changed` or with a record or packet count that differs. **No `L88-f-tls-*` pair fails.**
   - TLS captures are meant to be compared: `Verify` keeps port 300 byte for byte (`TestRedactKeepsTLSOnPort300AndRefusesPlainTACACS`).
   - The captures in main are stale copies. Their mtimes run from 2026-11-04 00:20 to 02:25, and many share the copy time 02:25:50.
   - The evidence was regenerated at 09:18Z (`e9a2c71b`) from later captures in the 12c worktree, which is gone.
   - The fix is outside this plan (see Open questions).

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case everywhere it is data. That covers YAML keys and the key names in the new `lab:` log lines (`phase=`, `mem_available_kb=`).
- Reason codes come only from spec §5.7. This plan adds none and changes no product code.
- No device identity in a metric label. This plan adds no metric.
- The log never holds a token, password, challenge or response.
- **Security rules, repeated in every implementer and lab-runner brief:**
  - Never print credential values, tokens, passwords, secrets, challenges or responses.
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, `run.env`, `/tmp/port49-lab-tokens.jsonl` or `~/.config/gh-tokens/*`. The L43 task copies a keytab and a key by path, through `labPrivateCopy`, and never prints them.
  - Never decode a TACACS+ body: no tcpdump `-x`, `-X` or `-A`, and no tshark `-x` or `-V`. Task 10's line is built from `l73Conn` fields that are counts and flags only.
  - Never grep `tests/lab/logs` or `tests/lab/captures`. Every recursive grep excludes `realm.json`, `*.env`, `*-key.pem` and `*.keytab`.
  - Read results notes and logs only through `grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g'`.
  - If a safety check refuses a command, stop and report it. Never rephrase the command.
- Tests: `TMPDIR` is a private 0700 directory, either `/tmp` or one under `~/.cache` (the implementer's own). Run each package in the foreground, with every call at or under 600000 ms. Before the final review, run `make test && make vet && make lab-unit` and report the real output.
- **Commits:** Conventional Commits, one per step that says "Commit", with an explicit pathspec. Every message ends with `Co-Authored-By: Claude <model name> <noreply@anthropic.com>` and nothing else.
- **Branch:** `fix/lab-harness-47`, from `main` `ffac5193`. Tasks 1 to 10 are sequential on one branch. Task 11 runs on beehive under the lab lock (`/tmp/port49-lab.lock`), with the stall watchdog. Before a lab worktree is removed, copy its raw pcaps to main's `tests/lab/captures/`.
- **Lab register:** spec §15 is untouched unless a rerun changes a row's status. A result that contradicts a doc fixes the doc, and the commit message says so.

---

### Task 1: Generated harness policies declare the lab key (L66, projection)

**Files:**
- Create:
  - `tests/lab/policy_keys.go`. It is `package lab` with no build tag, like `l78.go`, because `l78.go` uses it in Task 2. It holds:
    - `labPolicyKeys`, the block `keys:\n  lab_key:\n    current: {version: 1, secret_ref: env:PORT49_KEY_LAB}\n`;
    - a comment citing decision 53 ruling 3 and the environment the harness sets (`harness_test.go` `startDaemonWith` and `proc.start` set `PORT49_KEY_LAB`).
  - `tests/lab/policy_keys_unit_test.go` (`//go:build lab`).
- Modify:
  - `tests/lab/l66_test.go`: `l66Policy` ends with `labPolicyKeys`.
  - `tests/lab/projection_test.go`: the body that `projectionShape` builds inline moves out into `func projectionPolicy(set, roles string) string`, which ends with `labPolicyKeys`. `projectionShape` calls it.

- [ ] **Step 1: Write the failing tests** in `policy_keys_unit_test.go`.
  - `assertPolicyAdmits(t, name, text string, inv admission.Inventory, want []string)`:
    - write `text` to `t.TempDir()`;
    - load it with `policy.Load(path, policy.Env{Devices: inv.Devices, InventoryKeyGroups: inv.KeyGroups})`;
    - `t.Errorf` when `!p.KeysDeclared()`, with the words "port49d refuses a policy with no keys: block (decision 53 ruling 3)";
    - `t.Errorf` when the names in `p.AdmissionRefusals()` (`r.Device.Name`, `r.Refused`) differ from `want`.
  - `labRefusalsControl(t)` loads `tests/lab/slice/policy.yaml` against `inventory-lab.yaml`, which passed Task 26, and returns its refusal names, as the `want` for every case. That way a device the inventory refuses on purpose is not read as a bug.
  - `TestL66PolicyDeclaresTheLabKey`: `l66Policy(p.node)` for every row `p` of `platforms` whose `p.name` is a key of `l66Platforms` (`l66_test.go:522`), against `admission.LoadFile("inventory-lab.yaml")`.
  - `TestProjectionPolicyDeclaresTheLabKey`: `projectionPolicy(set, shape.roles)` for set 1.1.0 with each of `projectionShapes`, set 1.2.0 with `projectionShapes120`, and set 1.3.0 with `projectionShapes130` (`projection_test.go:156`, `:223`, `:240`).

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=$TMPDIR go test -tags lab ./tests/lab/ -run '^Test(L66|Projection)PolicyDeclaresTheLabKey$' -count=1`

  Expected: the build fails, because `projectionPolicy` is undefined. Once you add a stub that returns today's body, the tests fail with "port49d refuses a policy with no keys: block". Paste the red output in the report.

- [ ] **Step 3: Implement** as in Files. Don't change `l66Policy`'s scopes, subjects or grants: `TestL66PolicyGrantsTheOneNodeToTheSliceOperator` still holds.

- [ ] **Step 4: Run the tests and the existing L66 unit tests.**

  `TMPDIR=$TMPDIR go test -tags lab ./tests/lab/ -run '^Test(L66|Projection)' -count=1`. Expected: PASS.

  **Mutation check:** drop `labPolicyKeys` from `projectionPolicy` alone and see only that test go red. Then restore it.

- [ ] **Step 5: Commit.**

  `git add tests/lab/policy_keys.go tests/lab/policy_keys_unit_test.go tests/lab/l66_test.go tests/lab/projection_test.go && git commit -m "fix(lab): L66's and the projection run's policies declare the lab key (#47)"`

---

### Task 2: The qualify run's inventory uses the qual policy's key; L78 declares it (L80, L78)

The qual policy stays byte-for-byte what the mock loads (`internal/port49d/qual_test.go`), because the goldens are taken under it. The lab copy of the inventory therefore assigns the policy's key `k`, as the mock's inventory does. The policy is not given a lab key.

**Files:**
- Modify:
  - `tests/lab/qual_evidence.go` gets `func qualInventory(inv string) (string, error)`.
    - It replaces the one `key_ref: lab_key` with `key_ref: k`.
    - It returns an error naming the count when there is not exactly one.
    - Its comment cites `qual_test.go:263` and decision 53 ruling 3.
  - `tests/lab/qualify_test.go` `(*qualEnv).config`, after `privatePolicy`, rewrites the private copy `filepath.Join(priv, "inventory.yaml")` through `qualInventory`, at mode 0600. Every error is `q.t.Fatalf("INVALID: ...")`.
  - `tests/lab/policy_keys.go` gets `qualPolicyKeys`, the block `tests/qual/qual-policy.yaml` carries: `keys:\n  k:\n    current: {version: 1, secret_ref: env:PORT49_KEY_RUN}\n`.
  - `tests/lab/l78.go`: `l78Policy` ends with `qualPolicyKeys`.
- Test: `tests/lab/policy_keys_unit_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestTheQualPolicyAdmitsTheLabInventory`:
    - read `tests/qual/qual-policy.yaml`;
    - parse `inventory-lab.yaml` through `qualInventory` (`admission.ParseFile`);
    - `assertPolicyAdmits` with the control's refusals.
    - **Also a control that must fail:** the same policy against the unrewritten inventory refuses `leaf1` with "is assigned key_ref lab_key". That is the error Task 26 saw.
  - `TestQualPolicyKeysMatchesTheQualPolicy`: `qualPolicyKeys` is a substring of `tests/qual/qual-policy.yaml`, so the two cannot drift apart.
  - `TestL78PolicyDeclaresTheQualKey`: `l78Policy(s)` for every `s` in `l78Steps`, against the rewritten inventory.
  - `TestQualInventoryRewritesExactlyOneKeyRef`: zero `lab_key` lines is an error, two is an error, and one gives `key_ref: k`.

- [ ] **Step 2: Run them and see them fail.**

  `TMPDIR=$TMPDIR go test -tags lab ./tests/lab/ -run '^Test(TheQualPolicyAdmits|QualPolicyKeys|L78PolicyDeclares|QualInventory)' -count=1`

  Expected: the build fails, because `qualInventory` and `qualPolicyKeys` are undefined. With stubs in place, the L78 and admission tests fail.

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS, including `TestQualConfig*` and `qual_evidence_unit_test.go`. Then run `TMPDIR=$TMPDIR go test ./internal/port49d/ -run Qual -count=1`. Expected: PASS, which proves the mock is untouched.

- [ ] **Step 5: Commit.**

  `git add tests/lab/qual_evidence.go tests/lab/qualify_test.go tests/lab/l78.go tests/lab/policy_keys.go tests/lab/policy_keys_unit_test.go && git commit -m "fix(lab): the qualify run's inventory assigns the qual policy's key, and L78 declares it (#47)"`

---

### Task 3: L28's `keys status` reads a policy with the rotation's keys, and its exit counts

**Files:**
- Modify `tests/lab/l28_test.go`:
  - Add `func l28StatusPolicy(base, keys string) string`. It returns `tests/lab/l28/policy.yaml`'s text plus `"keys:\n" + keys`, where `keys` is the same block that `l28Config` is given for the `accepted` phase.
  - Write that block once, as a `const l28AcceptedKeys`, so that `l28Config(t, "accepted", l28AcceptedKeys)` and the status policy cannot differ.
  - `l28Rotate` writes the status policy into `labPrivateSub("l28-" + l.p.name)` at mode 0600.
  - It runs `port49 keys status --policy <that> --inventory tests/lab/inventory-lab.yaml <log>`, with no `--config`.
  - A non-zero exit is `t.Errorf("rotation: port49 keys status exited %v: %s", err, tailOf(...))`. The note still shows the output, but the test fails.
- Test: `tests/lab/policy_keys_unit_test.go`.

- [ ] **Step 1: Write the failing tests.**
  - `TestL28StatusPolicyCarriesTheAcceptedKeys`: `l28StatusPolicy` loads through `assertPolicyAdmits`. Its `lab_key` has current version 2 and accepts version 1 (read through the policy's key accessor, or a YAML unmarshal of `keys:`).
  - `TestL28StatusArgsNameNoRemovedFlag`: factor the argv into `l28StatusArgs(bin, policy, inventory, log string) []string`. The test asserts it holds no `--config`, and that every flag it holds is one `cmd/port49`'s `keys status` registers. Read that set by running `bin/port49 keys status -h` when `bin/port49` exists. Otherwise check against the literal `--policy`, `--inventory` and `--since`, with a comment that cites `cmd/port49/policy.go:36`.

- [ ] **Step 2: Run them and see them fail** (the functions are undefined, and then the policy has no `keys:`).

- [ ] **Step 3: Implement.**

- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add tests/lab/l28_test.go tests/lab/policy_keys_unit_test.go && git commit -m "fix(lab): L28's keys status reads a policy carrying the rotation's keys, and fails the test when it exits non-zero (#47)"`

---

### Task 4: L62's broker policy declares its key

**Files:**
- Modify `tests/lab/l62/stack_test.go`: `policyYAML` ends with `keys:\n  k:\n    current: {version: 1, secret_ref: file:/run/port49/keys/tacacs_v1}\n`. That is `deploy/compose/config/policy.yaml`'s block, the compose stack the L62 overlay runs on. port49-broker reads only the key names.
- Test: `tests/lab/l62/stack_unit_test.go`.

- [ ] **Step 1: Write the failing test.** `TestL62UnitPolicyDeclaresItsKey` loads `policyYAML` with `policy.Load` against one device at `172.30.49.10`. It asserts `KeysDeclared()` and that nothing is refused.
- [ ] **Step 2: Run it and see it fail.** `TMPDIR=$TMPDIR go test -tags lab ./tests/lab/l62/ -run '^TestL62UnitPolicy' -count=1`
- [ ] **Step 3: Implement.** Keep `TestL62UnitPolicyAndIssuerMatchTheLabRealm` green.
- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS.
- [ ] **Step 5: Commit.**

  `git add tests/lab/l62/stack_test.go tests/lab/l62/stack_unit_test.go && git commit -m "fix(lab): L62's broker policy declares its key (#47)"`

---

### Task 5: L48's local broker keeps every fenced file outside the tree

**Files:**
- Modify `tests/lab/localbroker_test.go`:
  - Add `func localBrokerDir(name string) (string, error)`, which is `labPrivateSub("local-broker-" + name)`.
  - `prepareLocalBroker` stages `anchorFile`, and `crlIssuer` when it is set, through `labPrivateCopy` before `localBrokerFiles` names them. A source outside the tree is copied too, which costs nothing and keeps one rule.
- Modify `tests/lab/l48_test.go:433` and `:638`: pass `localBrokerDir("l48")` and `localBrokerDir("l48-crl")` in place of `filepath.Join(filepath.Dir(r.s.dir), "local-broker…")`. An error is `r.t.Fatal`.
  - The broker's stderr and stdout (`port49d.err`, `port49d.out`) now live in the private directory.
  - `startBrokerProcess`'s failure message already prints their tail.
  - Copy both into `tests/lab/logs/workload/` at `t.Cleanup`, so the log keeps its place. The decision log holds no credential (spec §11), and the copy is 0644 like the other logs.
- Test: `tests/lab/l48_l49_unit_test.go`.

- [ ] **Step 1: Write the failing test.** `TestTheLocalBrokerKeepsEveryFencedFileOutsideTheTree`:
  - `r := labTree(t)` (group-writable root);
  - write a stand-in anchor PEM under `r/tests/lab/logs/host-w/`;
  - `dir, _ := localBrokerDir("unit")`, then `prepareLocalBroker(dir, anchor, "", "")`.
  - For every `^\s*\w+(_file|_path): (\S+)` value in the written `port49d.yaml`, assert `underRoot` is false.
  - `fence.Read` succeeds on each trust file: `trust_anchor_file`, `tls_cert_file` and the policy.
  - `config.Load` succeeds on the config.
  - **Control:** the same `prepareLocalBroker` with a `dir` under `r/tests/lab/logs` fails `fence.Read` on the policy. This is the lab's refusal.
- [ ] **Step 2: Run it and see it fail.** `localBrokerDir` is undefined. Once it is stubbed to return the in-tree directory, the outside-tree assertion fails.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS, including `l48_l49_unit_test.go:592`'s existing user of `prepareLocalBroker`.
- [ ] **Step 5: Commit.**

  `git add tests/lab/localbroker_test.go tests/lab/l48_test.go tests/lab/l48_l49_unit_test.go && git commit -m "fix(lab): L48's local broker runs from a private directory, its anchors staged, as the fence requires (#47)"`

---

### Task 6: L43's bind files are private copies

**Files:**
- Modify `tests/lab/private_files_test.go`: add `func (p *dirPKI) privateBroker() (cert, key string)`, modelled on `privateCA`. It returns `labPrivateCopy` of `p.brokerCert` and `p.brokerKey`, and panics with the path, never the content, on failure.
- Modify `tests/lab/directory_test.go`:
  - `bindExternal` uses `l.d.pki.privateBroker()`.
  - `bindGSSAPI` uses `labPrivateCopy(l.keytabFile)` and `labPrivateCopy(l.krb5File)`, through a `func (l *labDir) privateKerberos() (keytab, krb5 string)` that panics the same way.
  - The keytab is copied by path. It is never read into a string, a log or a note.
- Test: `tests/lab/config_files_unit_test.go`, next to `TestTheDirectoryCAIsStagedOutsideTheTree`.

- [ ] **Step 1: Write the failing test.** `TestTheDirectoryBindFilesAreStagedOutsideTheTree`:
  - `r := labTree(t)`;
  - write a testpki leaf and key as `broker.pem` and `broker-key.pem` under `r/tests/lab/logs/directory/pki`;
  - build `l := &labDir{d: &directories{pki: &dirPKI{brokerCert: ..., brokerKey: ...}}}`;
  - **control:** `directory.LoadCredentials(directory.Bind{Mechanism: "external", TLSCertFile: <in-tree>, TLSKeyFile: <in-tree>}, nil)` errors, which is the lab's refusal;
  - `directory.LoadCredentials(l.bindExternal(), nil)` succeeds, and both paths are outside `root`;
  - for GSSAPI, assert only that `bindGSSAPI()`'s `KeytabFile` and `KRB5Conf` are outside `root` and exist. Write the fixture keytab as bytes, never print it, and don't load it.
- [ ] **Step 2: Run it and see it fail** (`LoadCredentials` refuses the in-tree key).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS. `windows_test.go:1510`'s `labDir` uses the same `bindGSSAPI`, so it inherits the copy; check that it compiles.
- [ ] **Step 5: Commit.**

  `git add tests/lab/private_files_test.go tests/lab/directory_test.go tests/lab/config_files_unit_test.go && git commit -m "fix(lab): the directory bind's certificate, key, keytab and krb5.conf are private copies, as the fence requires (#47)"`

---

### Task 7: SR Linux logins use exec channels again; L88 keeps its pty path by name (L76)

**Files:**
- Modify `tests/lab/harness_test.go`:
  - Add `func loginPath(platform string) string`. It returns `"pty"` for `cisco_iosxe` (C8000V runs one exec channel per connection, as the existing comment says) and `"exec"` otherwise.
  - `loginWithin` switches on it. The `nokia_srlinux` branch and its comment go.
  - The comment on the switch cites `tests/lab/results/L76-nokia_srlinux.md` cell (k): a TACACS+ user's exec channels run in sr_cli on 26.7.2.
- Modify `tests/lab/l88_harness_test.go`:
  - Add `func (l *lab) l88LoginWithin(user, password string, per time.Duration, commands ...string) ([]string, error)`.
  - For `nokia_srlinux` it is today's branch, moved verbatim: `ptyCommands` with `echo l88-end` and the slot shift, with the comment "measured: L88 cell e".
  - Otherwise it calls `l.loginWithin`.
  - Its comment says L88 ran its SR Linux logins through this pty path, and that L76 (k) measured exec channels for a TACACS+ user. It claims nothing about why L88 chose the pty path.
- Modify `tests/lab/l88_test.go`: the seven `loginWithin` calls (`:492`, `:604`, `:858`, `:911`, `:1052`, `:1053`, `:1327`) call `l88LoginWithin`. L88's behavior is then byte-identical on every platform.
- Test: `tests/lab/l76_lab_unit_test.go`.

- [ ] **Step 1: Write the failing test.** `TestSRLinuxLoginsUseExecChannels` asserts:
  - `loginPath("nokia_srlinux") == "exec"`;
  - `loginPath("cisco_iosxe") == "pty"`;
  - `loginPath("arista_eos") == "exec"`.

  Add a source check as well: the body of `loginWithin` in `harness_test.go`, read as text, holds no `nokia_srlinux`. That keeps the next reader from routing it back.
- [ ] **Step 2: Run it and see it fail** (`loginPath` is undefined, and then the srlinux case says `pty`).
- [ ] **Step 3: Implement.** Then `grep -n "loginWithin(" tests/lab/l88_test.go` shows no call left.
- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS, including every `L76`, `L88` and `l76_row` unit test.
- [ ] **Step 5: Commit.**

  `git add tests/lab/harness_test.go tests/lab/l88_harness_test.go tests/lab/l88_test.go tests/lab/l76_lab_unit_test.go && git commit -m "fix(lab): SR Linux logins run exec channels again, as L76 measured; L88 keeps its pty path by name (#47)"`

  The commit body says the change was introduced in `933d45bb` and `92fe55fc`, and that "(L76)" there cited L76's INVALID hint, not a measurement.

---

### Task 8: The qualify and L80 dirty check covers code and the run's own outputs

**Files:**
- Modify `tests/lab/build_vcs.go`:
  - Add `var qualOwnOutputs`. For each prefix `L80-`, `QUAL-` and `L78-`, it holds:
    - `:(glob)tests/lab/results/<prefix>*`;
    - `:(glob)tests/lab/evidence/<prefix>*` (the pcaps and JSON files);
    - `:(glob)tests/lab/evidence/<prefix>*/**` (the evidence directories), because under `:(glob)` a `*` does not cross a `/`.
  - Add `func qualTreeDirty(dir string) (string, error)`. It joins:
    - `treeDirty(dir, codePaths + ":(exclude)tests/lab/results" + ":(exclude)tests/lab/evidence")`;
    - `treeDirty(dir, qualOwnOutputs...)`.

    It takes two calls, because a git exclude pathspec also removes a positive glob under it.
  - Its comment gives the reason: the check is the binary's and the harness's provenance (review I2, N4). Nothing reads or embeds other entries' notes. Running L80 first would hold only in a full run.
- Modify `tests/lab/qualify_test.go:70`, `tests/lab/qualify_test.go:639` and `tests/lab/l80_test.go:79` to call `qualTreeDirty(root)`.
- Test: `tests/lab/build_vcs_unit_test.go`, through its `gitRepo` helper.

- [ ] **Step 1: Write the failing test.** `TestQualTreeDirtyIgnoresOtherEntriesNotes`, on a committed tree:
  - a modified `tests/lab/results/L66-arista_eos.md` is clean;
  - an untracked `tests/lab/evidence/L66-x/new.txt` is clean;
  - a modified `tests/lab/results/QUAL-x.md` is dirty;
  - an untracked `tests/lab/evidence/L80-cisco_nxos/new.txt` is dirty (review N4);
  - a modified `tests/lab/qualify_test.go` is dirty;
  - a modified `internal/a.go` is dirty.

  Keep `TestTreeDirtySeesUntrackedFiles` as it is.
- [ ] **Step 2: Run it and see it fail** (`qualTreeDirty` is undefined).
- [ ] **Step 3: Implement.** Use `grep -n "treeDirty(root, codePaths" tests/lab/*.go` to check that the three call sites moved and no other caller is left.
- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS.
- [ ] **Step 5: Commit.**

  `git add tests/lab/build_vcs.go tests/lab/build_vcs_unit_test.go tests/lab/qualify_test.go tests/lab/l80_test.go && git commit -m "fix(lab): the qualify dirty check covers code and its own outputs, not other entries' notes (#47)"`

---

### Task 9: Boot timing and host load in the lab log (the NX-OS hang)

This task adds no timeout change. It adds data.

**Files:**
- Create `tests/lab/boot_timing_test.go` (`//go:build lab`):
  - `type hostSample struct { MemTotalKB, MemAvailableKB, SwapTotalKB, SwapFreeKB int64; Load1, Load5, Load15 float64; Running, Total int }`.
  - `func parseHostSample(meminfo, loadavg string) (hostSample, error)`. It reads `MemTotal`, `MemAvailable`, `SwapTotal` and `SwapFree` (kB) from `/proc/meminfo`, and the three loads and `running/total` from `/proc/loadavg`. A missing field is an error that names it.
  - `func readHostSample() (hostSample, error)` reads both files.
  - `func (s hostSample) line(name, phase string) string` returns `lab: <name>: host: phase=<phase> mem_total_kb=… mem_available_kb=… swap_total_kb=… swap_free_kb=… load1=… load5=… load15=… procs_running=… procs_total=…`.
  - `type bootClock struct { name string; start time.Time }` and `func (c bootClock) line(phase string, at time.Time) string`, which returns `lab: <name>: boot: phase=<phase> at=<RFC3339 UTC> since_deploy=<rounded to 1s>`.
  - Phases, a closed set (a `const` each): `deploy_start`, `deploy_done`, `ssh_banner`, `ssh_auth`, `tacacs_seen`. A missed gate prints `phase=<gate>_missed` at its deadline.
- Modify `tests/lab/harness_test.go`:
  - `(*lab).deploy` prints `deploy_start` and a `host` line (`phase=deploy_start`) before `l.up()`.
  - On `l.up()`'s error it prints a `host` line (`phase=failed`) before `l.diagnose()`. After "ready after", it prints a `host` line (`phase=ready`). A failed `/proc` read prints `lab: <name>: host: unreadable: <err>` and never fails the run.
  - `(*lab).up` takes the clock and prints:
    - `deploy_done` after `containerlab deploy` returns;
    - `ssh_banner`, or `ssh_banner_missed`, after `waitSSH`;
    - `ssh_auth`, or `ssh_auth_missed`, after `waitDeviceReady`;
    - `tacacs_seen`, or `tacacs_seen_missed`, after `waitTACACSReady`.
  - Each goes to `os.Stderr`, as the existing `lab:` lines do. The lines carry no credential and no device identity beyond the platform name the existing lines already print.
- Modify `tests/lab/README.md`, "NX-OS boot hang": one sentence saying that each deploy now logs `lab: <platform>: boot:` and `host:` lines. Give one example of each with invented numbers. A hang is to be read from them: `ssh_auth` with no `tacacs_seen` is the config apply, and `mem_available_kb` at `failed` against `deploy_start` shows host pressure. Don't raise the timeout without them.
- Test: `tests/lab/boot_timing_unit_test.go` (`//go:build lab`).

- [ ] **Step 1: Write the failing tests.**
  - `TestParseHostSampleReadsProc` uses fixed `/proc/meminfo` and `/proc/loadavg` texts. It checks every field, and that a `meminfo` without `MemAvailable` is an error naming it.
  - `TestBootAndHostLinesAreSnakeCaseKeyValues`: every `key=` in both lines matches `^[a-z0-9_]+$`, and the phase is one of the closed set.
- [ ] **Step 2: Run them and see them fail** (undefined).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS. Also run `TMPDIR=$TMPDIR go vet -tags lab ./tests/lab/`.
- [ ] **Step 5: Commit.**

  `git add tests/lab/boot_timing_test.go tests/lab/boot_timing_unit_test.go tests/lab/harness_test.go tests/lab/README.md && git commit -m "test(lab): each deploy logs its boot phases and the host's memory and load (#47)"`

---

### Task 10: L73's missing-hello INVALID names what cell (a) captured (#46)

This is a diagnostic only. The fix waits for the line it prints.

**Files:**
- Modify `tests/lab/l73_tlswire.go`: add `func l73ConnKinds(conns []l73Conn) string`. It has one entry per connection: `<server> <answer> tls|plain|other hello=<yes|no> server_hello=<yes|no> incomplete=<bool> device_records=<n> server_records=<n> device_bytes=<n>`.
  - `tls` is `DeviceRecords > 0`.
  - `plain` is `Plain != nil`, and only the presence is printed, never the headers.
  - It is built from counts and flags only. `l73SummaryLeaks` must pass over it.
- Modify `tests/lab/l73_test.go` `cellF`: the INVALID message appends `"; cell a's connections: " + l73ConnKinds(e.first)` and `l73Describe(e.first, e.firstSpan.Start)`.
- Test: `tests/lab/l73_tlswire_unit_test.go`.

- [ ] **Step 1: Write the failing test.** `TestL73ConnKindsNamesPlainIncompleteAndTLS` builds three `l73Conn`s:
  - plain port 49 with `Plain` set;
  - port 300 with `DeviceRecords` 2, `Incomplete` true and no `Hello`;
  - port 300 with `Hello` and `ServerHello` set.

  It asserts each kind's words, and that `l73SummaryLeaks` finds nothing in the output.
- [ ] **Step 2: Run it and see it fail** (undefined).
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run `make lab-unit`.** Expected: PASS.
- [ ] **Step 5: Commit.**

  `git add tests/lab/l73_tlswire.go tests/lab/l73_test.go tests/lab/l73_tlswire_unit_test.go && git commit -m "test(lab): L73's missing-hello INVALID names each of cell a's connections (#46)"`

---

### Task 11: Rerun the affected entries (beehive, lab lock, watchdog)

Before the first entry:
- `make build`, then `make test && make vet && make lab-unit`, with the real output in the report;
- commit everything, so the tree is clean;
- arm the stall watchdog.

Run one entry at a time with `make lab-regress LAB_REGRESS_ARGS="-only=<id>"`. Each entry's notes go in their own commit before the next entry runs, which also keeps L80's scoped check clean.

- [ ] **Step 1: The entries this plan fixed.** Each must pass.

  | id | fixed by | expect |
  |---|---|---|
  | `L66-eos`, `L66-vjunos`, `L66-vsrx`, `L66-nxos`, `L66-iosxe` | Task 1 | pass; notes rewritten |
  | `L80-nxos106` | Tasks 2, 8 | pass. Run it after at least one other entry has rewritten notes, to prove Task 8 |
  | `L28` | Task 3 | pass. Line 127 of each L28 note shows the `KEY_REF` table, not `(exit: …)` |
  | `L42-L43` | Task 6 | pass |
  | `L48` | Task 5 | pass |
  | `L76-srlinux` | Task 7 | pass |

  A failure here is reported with its line, not worked around. If L76 still finds no session row with exec channels restored, stop. The evidence (`a-1.txt`, filtered) is judged before any change. Don't guess at a device limitation.

  Commit each entry's notes on its own: `git add <the entry's notes and evidence> && git commit -m "docs: rerun <id> after the lab harness fixes (#47)"`.

- [ ] **Step 2: The entries not in the manifest that this plan touched.** Run them by hand, one platform each.
  - `PORT49_LAB_L78=1 PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^TestL78$' -count=1 -v -timeout 120m`. Every step must say "logged in" or a device refusal, and none may say "refused at load" with a `keys:` line.
  - `PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^TestProjectionDifferential$' -count=1 -v -timeout 120m`.
  - L62 is excluded (it needs the TPM and Ryan) and is not run here. Task 4's unit test is its check until the release run.

  Commit the notes as in Step 1.

- [ ] **Step 3: The diagnostic runs.** These change nothing until their evidence is judged.
  - `L73-nxos106`. If it fails again, copy the INVALID line's connection kinds (Task 10) into #46 as a comment, filtered.
    - Then judge, from that line and NX-OS `show tacacs-server`, which candidate it matches: plain port 49 first, an incomplete stream (a hello split or lost), or no port-300 connection.
    - The fix is a follow-up commit or plan. Cite the device's own debug before any "device limitation" (`debug tacacs+` per the issue).
  - `L5`, `L31`, `L64-L65-nxos`. Whatever the result, extract the `lab: … boot:` and `lab: … host:` lines from the run's stderr (they carry no credential) and add them to #47 as a comment. A pass is data too: it shows a normal boot's phases. Raise no budget in this plan.

- [ ] **Step 4: Spec §15.** No row changes status unless a rerun contradicts its note. If one does, edit the row as CLAUDE.md's lab-register rules say, cite the note, and commit it as `docs: …`.

- [ ] **Step 5: Roadmap.** In `docs/superpowers/plans/README.md`, under "Pre-beta fixes — Task 26", record the outcome:
  - which entries now pass;
  - the L28 notes corrected;
  - L73-nxos106's and the NX-OS diagnostics' state, with links to the #46 and #47 comments.

  Commit as `docs: the lab harness fixes' reruns (#47)`.

## Open questions

1. **The stale L88 captures in main** (item 7). The 23 captures in main's `tests/lab/captures/` are not the inputs of the committed evidence, and the matching captures are gone with the 12c worktree. There are two options:
   - move them aside locally (for example into `tests/lab/captures/stale-2026-11-04/`, which the `*.pcap` glob does not reach), so the local audit means something again;
   - leave them until L88's next run (`make lab-l88`) replaces both.

   Either is a local, git-ignored change. This plan does neither without the lead's say.
2. **L88's own SR Linux path.** Task 7 keeps L88's pty logins as they are, because L88 passed with them. Whether L88 needs them (L76 (k) says a TACACS+ user's exec channel works) is a question for L88's next SR Linux run, not for this plan.
