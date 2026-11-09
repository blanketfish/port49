# Small Fixes #53, #54, #55, #57, #58 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Five small fixes found in plans 13 and #52.
- `port49 explain` states decision 21's limit in full (#53).
- The gated group line of `port49 policy diff` is labelled like the other gated kinds (#54).
- The Python and Ansible second-factor error names no command that prints a token (#55).
- docgen's per-list identity keys can no longer drift from the verifier struct unnoticed (#57).
- The enrollment store's lost reason keeps its cause and remedy under a long path, and the askpass test no longer depends on TMPDIR's length (#58).

**Architecture:** Each task stands alone and touches its own files. No new reason code, warning, config key or metric. No lab run.

**Tech Stack:** Go 1.26 (`internal/policy`, `cmd/port49`, `internal/docgen`, `internal/store/enrollfile`, `internal/printsafe`), Python 3.10+ (`clients/python`, `clients/ansible`, `make test-python`), MkDocs pages under `docs/site`.

**Issues:** #53, #54, #55, #57, #58. #56 is out of scope: it is a feature with its own plan.

## Root causes (investigation 2026-11-09, `main` `408b27c1`)

1. **#53: explain states half of decision 21's limit.**
   - Decision 21 (spec §13, `docs/design/2026-08-23-policy-engine-spec.md:7348-7356`) does not quote a sentence. It says "`explain` states the limit". The limit is that the ceiling, revocation, username binding and the in-session warning all act at the next authorization request, which a session-only platform does not make. The 2026-11-07 correction adds that with `authorization-time-interval` set, Junos re-authorizes at the interval: one re-authorization was measured (L36), and L40 is open. §5.6 "Where these controls do not reach" (`:2113-2140`) says the same: "`port49 explain` MUST say so when asked about revocation or a ceiling on such a platform".
   - The issue's paraphrase ("one session's context, not every context") is not decision 21. Decision 21 is the text this plan follows.
   - explain already prints a note. `policy.Caveats` (`internal/policy/tests.go:112-122`) covers a command on a session-only platform. `explain.go:181-185` covers the session. Both name only "a revocation or a session ceiling". Neither names the username binding or the warning, cites decision 21, or names the `idle-timeout` bound and the `authorization-time-interval` exception.
   - Where it prints: a `note:` line on stdout, after the explanation, in the offline form (`cmd/port49/policy.go:129-130`). The broker form returns the same text (`RenderWithoutAttributes`, printed by `policy.go:110`). explain has no JSON output.
   - The spec11 fixture's Junos (`platform_set` 1.0.0) is not projected. 1.1.0 and later project it (`platforms/1.*/juniper_junos.yaml:21`). Both branches of `Caveats` are live.
2. **#54: the group line is always lowercase.**
   - `cmd/port49/policy.go:594-597` prints `subject: NAME's OLD -> NEW` whatever the gate says. Every group change is gated (`internal/policy/diff.go:609`, `Gated: ... || !sameGroup`).
   - The other gated kinds print upper case while unacknowledged, and `kind (a ... test asserts it)` once acknowledged: `PRINCIPAL`, `API`, `USERNAME`, `RAISES`, `ADAPTER` (`policy.go:574-624`, `:640-660`).
   - `docs/site/admin/policy.md:283` documents the lowercase line.
   - `cmd/port49/testdata` has no golden files. The diff tests match lines with `strings.Contains`.
3. **#55: the message names `port49 token`, and `port49 login` would be wrong too.**
   - `MFARequired.__str__` (`clients/python/src/port49/errors.py:77-81`) says "run `port49 token {device}` at a terminal". The Ansible lookup relays `str(e)` unchanged (`clients/ansible/.../plugins/lookup/token.py:351-353`), and has no text of its own to fix.
   - The issue suggests `port49 login`, but that is not the step. A per-login proof is given only by `prove` (`cmd/port49/mfa.go:116`), which only `mintProved` (`mfa.go:86`) calls. Its callers are `port49 token` (`cmd/port49/main.go:984`) and `port49 ssh` (`cmd/port49/ssh.go:911`). `port49 login` starts the agent's session and proves nothing for a device.
   - So the person's step that prints no token is `port49 ssh <device>`. It mints, proves and hands the token to ssh through askpass. Its proof covers the agent's further logins for `reuse_for`, as `port49 token`'s does, because both prove through the same agent.
   - The old text is quoted in these places:
     - `docs/site/agents/quick-start.md:62-68` and `:106-107`
     - `docs/site/agents/setup-runbook.md:134-136`
     - `clients/python/README.md:85`
     - `clients/ansible/ansible_collections/port49/client/README.md:86` and `:110`
     - `clients/python/tests/test_agent.py:112`
4. **#57: the loader has no key sets to derive from.**
   - `internal/docgen/schema.go:53-75` holds `humansOnlyKeys` and `machinesOnlyKeys` by hand.
   - `internal/config/identity.go` refuses keys in inline boolean chains, one per verifier type: `:181-183` (x509 machine), `:210-213` (x509 human), `:223-226` (directory_password), `:434-439` (oidc), `:724-725` (k8s). There is no table to read.
   - A new `identityVerifierYAML` field (`identity.go:33-57`) would show under both lists, and no test would fail.
5. **#58: a product bug, plus a test that depends on TMPDIR's length.**
   - The "link" the failing test looks for is the cause, `symbolic link`, not a docs or runbook link. A late file that is refused builds its reason in `pickUpLate` (`internal/store/enrollfile/enrollfile.go:131-139`): `store: the enrollment store is lost: <path>: it cannot be read (<fence error>): fix its owner and mode, or remove a link; this broker looks again ...`.
   - The fence's error names the path again (`internal/fence/fence_linux.go:297`, `linkRefused`; `:328`, an `fs.PathError`). `Broker.CheckEnrollmentStore` cuts the whole line at 300 bytes (`internal/broker/signin.go:939-940`, `printsafe.Line`).
   - With a path of about 120 bytes, the two copies of the path fill the 300 bytes. The cause and the remedy are cut off, which is the issue's output. An operator whose store lives at a deep path sees neither what is wrong nor what to do. Under the default TMPDIR the test passes only because the cut lands after "symbolic link".
   - `lostErr` (`enrollfile.go:193-198`) and `read` (`:97-98`) build the reason the same way.
   - `TestTheAskpassSocketIsNeverMadeInAnOpenDirectory` (`cmd/port49/ssh_fix_test.go:78-108`) makes its private directory with `privateDir(t)` (`t.TempDir()`). With the test's 47-byte name, a `~/.cache` TMPDIR pushes the socket past 107 bytes, and `listenAskpass` refuses it (`ssh.go:725-727`). The product check is right. The test's directory is too long.

## Rulings made in this plan

1. **#53: complete the existing note. Do not add a second one.** One helper, `sessionOnlyLimit`, gives decision 21's limit. The note's existing prefix (`... does not send per-command authorization (supports: ...)`) stays, so the line an operator already searches for is unchanged. It names all four controls. On a projected platform (Junos) it adds the `authorization-time-interval` exception, cited to L36 with L40 open, and the `idle-timeout` bound. It claims nothing L40 has not measured. Decision 21 gets an *As built* line.
2. **#54: `SUBJECT:` while unacknowledged, `subject (a session test asserts it):` once acknowledged.** This uses the same `s.Acknowledged` the `USERNAME` line uses. The tail says what acknowledges the change (`a session test naming the subject acknowledges it`) rather than claiming none exists, because `Acknowledged` also covers the username and API halves. Exact-line assertions in `cmd/port49/policy_test.go` act as the golden, because the package has no golden-file mechanism and one line does not justify adding it.
3. **#55: the step is `port49 ssh <device>`, not `port49 login`** (root cause 3). The message also says that an agent stops and asks a person, and that a workload's proof is a person's touch on its `touch_key`. One text covers both paths, because `MFARequired` cannot reliably tell an `Agent`'s from a `Workload`'s. `token.py` needs no code change, because its relay is `str(e)`. A unit test pins what it relays.
4. **#57: a test, not a derivation.** Deriving would mean rewriting the loader's per-type refusals (root cause 4) as tables, which is a security-relevant validation change made for a docs page. The test fails on exactly what the issue fears: a verifier key in none of `humansOnlyKeys`, `machinesOnlyKeys` and a new explicit `sharedIdentityKeys`, or in more than one, or a classified key no verifier has. `identityKeyBelongs` keeps its logic.
5. **#58: product bug. Cut the path, never the reason.**
   - The reason names the path once, cut from its start to its last 40 bytes (new `printsafe.Tail`; 56 in the first draft, cut to 40 in Task 5's fix round 2), so the file name survives.
   - The cause no longer repeats the fence's path. A link says so in a fixed sentence. An `fs.PathError` gives its errno text. Any other error keeps today's text.
   - So a link or an unreadable file at any depth gives a reason of at most 300 bytes, which the broker's cut leaves whole. The broker's 300-byte cut stays as the backstop.
6. **#58, the askpass test: a socket directory under `/tmp`, whatever TMPDIR is.** The directory is private (0700) and made by the test, as an agent's `XDG_RUNTIME_DIR` would be. The open-directory refusal is still asserted. A new case sets a long private directory on purpose and asserts that `listenAskpass` refuses it with its own words and leaves nothing behind.

## What an operator sees at 3am

| Event | Before | After |
|---|---|---|
| `port49 explain` on a Junos device | `note: ... a revocation or a session ceiling does not reach a live session there (spec §5.6)` | The same prefix, then all four controls, decision 21, and on a projected Junos the `authorization-time-interval` exception (L36, L40 open) and the `idle-timeout` bound |
| `port49 policy diff` with a group change and no session test | `subject: backup's group "g" -> machine_group "g"` among upper-case gated lines | `SUBJECT: backup's group "g" -> machine_group "g"; a session test naming the subject acknowledges it` |
| An Ansible play or Python script reaches a per-login MFA device | "run `port49 token leaf1` at a terminal" | "a person must give it, so an agent stops here and asks one: at a terminal, a person's `port49 ssh leaf1` proves it ..." |
| A link is planted at a deep enrollment-store path | `sign-in: the enrollment store is lost (store: ...: <path>: it cannot be read (<path>…)` with no cause and no remedy | `... lost (store: the enrollment store is lost: …<last 40 bytes of path>: it is a symbolic link, and the enrollment store is read only as a file of its own: fix its owner and mode, or remove a link; this broker looks again ...)` |

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case for data. Reason codes only from spec §5.7, and this plan adds none. Warnings only from spec §12, and this plan adds none: an explain `note:` is not a warning.
- No identity in a metric label. This plan adds no metric.
- The log never contains a credential, token, challenge or response. Credentials appear only as `credential_sha256`. The #55 text names no token-printing command. The #58 reason carries a path and an errno, never file content.
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, or key files.
  - Every recursive grep excludes them. grep is ugrep: use `-e PATTERN`, never `--` before a pattern. Never grep `tests/lab/logs` or `tests/lab/captures`.
  - If a safety check refuses a command, stop and report it. Never rephrase it.
  - Edit repo files with the Edit/Write tools, never sed, perl, python or heredocs.
- **Tests:** On this host `/tmp` is tmpfs, and the ACL tests that `mustpass` requires skip there. So `TMPDIR` is a short private directory on ext4: `export TMPDIR=$(mktemp -d ~/.cache/p49t.XXXX) && chmod 700 $TMPDIR`. Before the final review, run `make test && make vet && make docs` (`make test` runs `test-python`), then `make test-rest`, and report the real output. `git status --short` after `make docs` shows no diff. A failure under this TMPDIR that this plan does not name is reported, not fixed in passing.
- **Commits:**
  - Conventional Commits, one per task, with an explicit pathspec.
  - Every message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and nothing else. No `Claude-Session:` line, and no claude.ai URL anywhere: commits, PR body, comments.
- **Branch:** `fix/small-fixes-53-58`, from `main` `408b27c1`, in `.worktrees/small-fixes-53-58`. The tasks touch disjoint files and may run in any order.
- **Lab:** none needed. No device behavior changes, and no §15 row changes status. #53 cites L36 (closed) and L40 (open) as decision 21 already does.

## Review Focus

1. **#53 claims nothing unmeasured.** The note says one re-authorization was measured (L36) and that L40 is open. It does not say a revocation always reaches a Junos session. The non-projected branch names no Junos-only fact.
2. **#53 keeps one note per case.** `spec11_test.go:80` still sees exactly one caveat.
3. **#54 changes only the group line's label and tail.** The gate and the exit code are as before.
4. **#55 text names no command that prints a token,** in code, tests and docs. `port49 token` may still appear where a doc tells an agent never to run it.
5. **#57's test fails on a new field,** checked by the mutation step.
6. **#58 never drops the cause or the remedy.** Only the path is cut, from its start. The ELOOP case is tested before the `fs.PathError` case, because the link refusal wraps one.
7. **#58's askpass test still proves the open-directory refusal.**

---

### Task 1: explain states decision 21's limit in full (#53)

**Files:**
- Modify `internal/policy/tests.go`: add `sessionOnlyLimit`, and use it in both session-only branches of `Caveats` (`:114-122`).
- Modify `internal/policy/explain.go:181-185`: the session note uses it.
- Modify `internal/policy/explain_test.go:81-82`: the new text.
- Test: `internal/policy/projection_test.go` (projected) and `internal/policy/explain_test.go` (not projected).
- Modify `docs/design/2026-08-23-policy-engine-spec.md`: an *As built* line at the end of decision 21 (`:7365`, after "a refresh's are plan 7b's.").
- Modify `docs/site/admin/policy.md`: one sentence in `### port49 explain`.

- [ ] **Step 1: Write the failing tests.**

  In `explain_test.go`, after `TestExplainSaysWhatTheDeviceWillNotHonor`:

  ```go
  // Decision 21: on a platform that authorizes sessions only, explain names
  // every post-login control that does not reach a live session, for a
  // command and for the session alike (spec §5.6).
  func TestExplainStatesDecision21sLimit(t *testing.T) {
  	p := spec11(t, spec11Raw(t))
  	for _, line := range []string{"show chassis hardware", ""} {
  		_, out := explained(t, p, "svc_oxidized", "", "srx-fw-04", line, false)
  		mustContain(t, out, "note: juniper_junos does not send per-command authorization",
  			"a session ceiling, a revocation, a username change and the session-ceiling warning each act at the "+
  				"next authorization request", "§13 decision 21")
  		if strings.Contains(out, "authorization-time-interval") {
  			t.Errorf("%q: a platform that is not projected is told a Junos fact:\n%s", line, out)
  		}
  	}
  }
  ```

  In `projection_test.go`, after `TestExplainSaysWhatTheDeviceDoes`:

  ```go
  // Decision 21 on a projected Junos: the limit, the re-authorization L36
  // measured once with L40 open, and the idle-timeout that bounds a session.
  func TestExplainStatesDecision21sLimitOnAProjectedJunos(t *testing.T) {
  	p := parseProjected(t, platform.BitDeliveryUserPermissions, scopeOK+`roles:
    - {name: r, privilege: readonly, permit: ["show **"]}
  `+subjOK+grantOK)
  	for _, line := range []string{"show version", ""} {
  		e, err := p.Explain("s", "", "srx-fw-04", line, noon)
  		got := strings.Join(e.Caveats, "\n")
  		for _, want := range []string{"a session ceiling, a revocation, a username change and the session-ceiling warning",
  			"authorization-time-interval", "L36-juniper_", "L40, open", "idle-timeout", "§13 decision 21"} {
  			if err != nil || !strings.Contains(got, want) {
  				t.Errorf("%q: want %q in\n%s (%v)", line, want, got, err)
  			}
  		}
  	}
  }
  ```

  `strings` is already imported in both files.

- [ ] **Step 2: Run them and see them fail.** `go test ./internal/policy/ -run '^TestExplainStatesDecision21sLimit' -count=1`. Expected: both fail on the missing "a session ceiling, a revocation, a username change ..." text. Paste the red output.

- [ ] **Step 3: Implement.** In `tests.go`, above `Caveats`:

  ```go
  // sessionOnlyLimit is spec §13 decision 21's limit as explain and the policy
  // tests state it on a platform that does not authorize commands: the
  // post-login controls that do not reach a live session, and, on a projected
  // platform (Junos), the one request that does come and what bounds the rest.
  func sessionOnlyLimit(dialect platform.Dialect) string {
  	const controls = "a session ceiling, a revocation, a username change and the session-ceiling warning each act " +
  		"at the next authorization request"
  	if !dialect.Projected() {
  		return controls + ", and the device makes none after login, so none of them reaches a live session there " +
  			"(spec §5.6, §13 decision 21)"
  	}
  	return controls + ", which the device makes after login only where authorization-time-interval is set: one " +
  		"re-authorization an interval after login was measured, and port49 denies a revoked principal there without " +
  		"the device ending the session (tests/lab/results/L36-juniper_*.md; whether it asks again is L40, open). " +
  		"Otherwise none of them reaches a live session there, and what ends an idle one is the class idle-timeout " +
  		"port49 platform export --classes renders from max_session_age (spec §5.6, §13 decision 21)"
  }
  ```

  The two branches of `Caveats` become:

  ```go
  	if dialect.Projected() {
  		out = append(out, fmt.Sprintf("%s does not send per-command authorization (supports: %s): the device "+
  			"decides this command itself, from the session reply's projection of these rules (command_projection: %s); %s",
  			platformName, strings.Join(dialect.Supports, ", "), dialect.CommandProjection, sessionOnlyLimit(dialect)))
  	} else if !dialect.Authorizes("commands") {
  		out = append(out, fmt.Sprintf("%s does not send per-command authorization (supports: %s): the device "+
  			"never asks port49 about this command; %s", platformName, strings.Join(dialect.Supports, ", "),
  			sessionOnlyLimit(dialect)))
  	}
  ```

  `explain.go:181-185` becomes:

  ```go
  		if !dialect.Authorizes("commands") {
  			e.Caveats = append(e.Caveats, fmt.Sprintf("%s does not send per-command authorization (supports: %s): "+
  				"no command in this session is asked of port49; %s", d.Platform, strings.Join(dialect.Supports, ", "),
  				sessionOnlyLimit(dialect)))
  		}
  ```

  `explain_test.go:81-82` becomes `mustContain(t, out, "note: juniper_junos does not send per-command authorization", "none of them reaches a live session there")`.

- [ ] **Step 4: Docs.**
  - Spec, at the end of decision 21's paragraph: `*As built (issue #53, 2026-11-09):* explain's note names all four controls and this decision, and on a projected platform the re-authorization L36 measured (L40 open) and the class idle-timeout.`
  - `docs/site/admin/policy.md`: after "...rather than reporting a decision the device will not honor.", add: `On a platform that authorizes sessions only, such as Junos, that note says that a session ceiling, a revocation, a username change and the session-ceiling warning act at the next authorization request, which the device does not make after login unless `authorization-time-interval` is set.`
  - The page's output block is an Arista run, so its lines are unchanged. Confirm by running the command the block shows against a fixture that loads, or leave the block alone if none loads offline.

- [ ] **Step 5: Run** `go test ./internal/policy/ ./internal/broker/ ./cmd/port49/ -count=1 && make docs && git status --short`. Expected: PASS, and no generated page changes.

  **Mutation check:** make `sessionOnlyLimit` return the non-projected text for every dialect. `TestExplainStatesDecision21sLimitOnAProjectedJunos` must go red. Then restore.

- [ ] **Step 6: Commit.**

  `git add internal/policy/tests.go internal/policy/explain.go internal/policy/explain_test.go internal/policy/projection_test.go docs/design/2026-08-23-policy-engine-spec.md docs/site/admin/policy.md && git commit -m "fix(policy): explain states decision 21's session-only limit in full (#53)"`

---

### Task 2: the gated group line of `policy diff` is labelled as the other gated kinds (#54)

**Files:**
- Modify `cmd/port49/policy.go:594-597`.
- Modify `cmd/port49/policy_test.go`: `TestPolicyDiffNamesAMachineGroup` (`:1743-1764`) and `TestPolicyDiffNamesNoneForAMissingGroup` (`:1768-1793`).
- Modify `docs/site/admin/policy.md:283`.

- [ ] **Step 1: Write the failing tests.**
  - In `TestPolicyDiffNamesAMachineGroup`, the expected text becomes the whole line: `"\nSUBJECT: backup's group \"backup-hosts\" -> machine_group \"backup-hosts\"; a session test naming the subject acknowledges it\n"`.
  - In `TestPolicyDiffNamesNoneForAMissingGroup`, the two `want`s become `` `SUBJECT: backup's machine_group "backup-hosts" -> none;` `` and `` `SUBJECT: backup's none -> machine_group "backup-hosts";` ``.
  - Append to `TestPolicyDiffNamesAMachineGroup`:

  ```go
  	// Acknowledged by a session test naming the subject: lowercase, exit 0.
  	if err := os.WriteFile(newPol, append(body("machine_group"),
  		"tests:\n  - {subject: backup, device: leaf-01, level: readonly}\n"...), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	out.Reset()
  	if code := run([]string{"policy", "diff", "--old", oldPol, "--new", newPol, "--inventory", inv}, &out, &errb); code != 0 ||
  		!strings.Contains(out.String(), "\nsubject (a session test asserts it): backup's group \"backup-hosts\" -> "+
  			"machine_group \"backup-hosts\"\n") {
  		t.Fatalf("acknowledged: code %d\n%s%s", code, out.String(), errb.String())
  	}
  ```

  If the session test does not load or pass against `policyFixture`'s inventory, fix the test's fields (device, level) from that fixture. Never change the gate.

- [ ] **Step 2: Run them and see them fail.** `go test ./cmd/port49/ -run '^TestPolicyDiffNames(AMachineGroup|NoneForAMissingGroup)$' -count=1`. Expected: red on the `SUBJECT:` lines. Paste the output.

- [ ] **Step 3: Implement.** `policy.go:594-597` becomes:

  ```go
  		if s.OldGroup != s.NewGroup || s.OldGroupKey != s.NewGroupKey {
  			// Gated, as every group change is (internal/policy, principals).
  			label, tail := "SUBJECT", "; a session test naming the subject acknowledges it"
  			if s.Acknowledged {
  				label, tail = "subject (a session test asserts it)", ""
  			}
  			fmt.Fprintf(stdout, "%s: %s's %s -> %s%s\n", label, s.Subject, groupSide(s.OldGroupKey, s.OldGroup),
  				groupSide(s.NewGroupKey, s.NewGroup), tail)
  		}
  ```

- [ ] **Step 4: Docs.** `docs/site/admin/policy.md:283`: "on a lowercase `subject: NAME's none -> group ...` line" becomes "on a `SUBJECT: NAME's none -> group ...` line".

- [ ] **Step 5: Run** `go test ./cmd/port49/ ./internal/policy/ -count=1`. Expected: PASS.

- [ ] **Step 6: Commit.**

  `git add cmd/port49/policy.go cmd/port49/policy_test.go docs/site/admin/policy.md && git commit -m "fix(policy): policy diff labels a gated group change SUBJECT, as the other gated kinds (#54)"`

---

### Task 3: the second-factor error names a person's step, never a token-printing command (#55)

**Files:**
- Modify `clients/python/src/port49/errors.py:77-81` (`MFARequired.__str__`).
- Modify `clients/python/tests/test_agent.py:112`.
- Modify `clients/ansible/ansible_collections/port49/client/tests/unit/test_token.py`: a fake `mfa` device and one test.
- Modify these docs:
  - `docs/site/agents/quick-start.md:60-68` and `:106-107`
  - `docs/site/agents/setup-runbook.md:134-136`
  - `clients/python/README.md:85`
  - `clients/ansible/ansible_collections/port49/client/README.md:86` and `:110`

- [ ] **Step 1: Write the failing tests.**
  - `test_agent.py:112` becomes:

    ```python
            self.assertIn("port49 ssh core1", str(cm.exception))
            self.assertNotIn("port49 token", str(cm.exception))
            self.assertIn("asks one", str(cm.exception))
    ```

  - In `test_token.py`, `FakeAgent.token`, before `return TOK`:

    ```python
                if device == "mfa":
                    raise port49.MFARequired("per_login_mfa_required", "no proof", device,
                                             requirement={"accept": ["hardware_key_touch"]})
    ```

  - In `test_token.py`, in `class Plugin`:

    ```python
        def test_a_second_factor_names_no_token_printing_command(self):  # #55
            with self.assertRaises(AnsibleError) as cm:
                self.lookup(["mfa"])
            said = str(cm.exception)
            self.assertNotIn("port49 token", said)
            self.assertIn("port49 ssh mfa", said)
            self.assertIn("[per_login_mfa_required]", said)
            self.assertEqual(WARNINGS, [said])
    ```

- [ ] **Step 2: Run them and see them fail.** `make test-python`. Expected: the two tests fail on `port49 token`. Paste the red output.

- [ ] **Step 3: Implement.** `MFARequired.__str__` becomes:

  ```python
      def __str__(self):
          accept = ", ".join(self.requirement.get("accept", [])) or "a second factor"
          return clean(f"port49: {self.device}: asks for {accept} at each login, and it could not be given here "
                       f"({self.detail or self.code}); a person must give it, so an agent stops here and asks one: at "
                       f"a terminal, a person's `port49 ssh {self.device}` proves it, and the proof covers their "
                       f"agent's further logins for its reuse_for; a workload's proof is a person's touch on its "
                       f"touch_key")
  ```

  The class docstring is unchanged. `token.py` is unchanged: it relays `str(e)`.

- [ ] **Step 4: Docs.**
  - **`quick-start.md`, the bullet at `:60-68`:**
    - It opens "**A second factor is the one refusal whose message may not hold the code, and it names a person's step.**"
    - It quotes the new message, with `<device>` and `<methods>` in place of the values.
    - Keep "the Ansible lookup raises that same text with `[per_login_mfa_required]` appended when the detail does not hold the code".
    - It ends: "**`port49 ssh` is a person's path (rule 1). An agent runs neither it nor `port49 token`.** It stops and asks a human. Read `.code` and `.reason` in Python, not the advice."
  - **`quick-start.md:106-107`:** "never runs the `port49 token` that the `MFARequired` message suggests" becomes "never runs `port49 token`, nor the `port49 ssh` that the `MFARequired` message names for a person".
  - **`setup-runbook.md:134-136`:** "never runs the `port49 token` that the error's text suggests: that advice is for a person at a terminal" becomes "never runs `port49 token`, nor the `port49 ssh` that the error's text names: that step is a person's, at a terminal".
  - **`clients/python/README.md:85`:** the advice becomes "A person runs `port49 ssh DEVICE` at a terminal; one proof covers their agent's further logins for the requirement's `reuse_for_seconds`. An agent stops and asks a person."
  - **Ansible README `:86`:** "Run `port49 token <one such device>` before the play" becomes "Run `port49 ssh <one such device>` once before the play".
  - **Ansible README `:110`:** "(run `port49 token DEVICE` at a terminal first)" becomes "(a person runs `port49 ssh DEVICE` at a terminal first)".
  - **The grep:** `grep -rn --exclude=realm.json --exclude='*.env' --exclude='*-key.pem' --exclude='*.keytab' -e 'port49 token <' -e 'port49 token DEVICE' -e 'port49 token {' clients docs/site`. It must find nothing.

- [ ] **Step 5: Run** `make test-python && make docs && git status --short`. Expected: PASS, no generated diff.

  **Mutation check:** put `port49 token {self.device}` back in the message. Both new tests must go red. Then restore.

- [ ] **Step 6: Commit.**

  `git add clients/python/src/port49/errors.py clients/python/tests/test_agent.py clients/python/README.md clients/ansible/ansible_collections/port49/client/tests/unit/test_token.py clients/ansible/ansible_collections/port49/client/README.md docs/site/agents/quick-start.md docs/site/agents/setup-runbook.md && git commit -m "fix(clients): the second-factor error names a person's port49 ssh, never a token-printing command (#55)"`

---

### Task 4: every identity verifier key is classified for the config reference (#57)

**Files:**
- Modify `internal/docgen/schema.go:53-60`: add `sharedIdentityKeys`.
- Test: `internal/docgen/docgen_test.go`.

- [ ] **Step 1: Write the failing test** (add `"github.com/blanketfish/port49/internal/config"` to the imports):

  ```go
  // Every key of a broker.identity verifier is classified as the humans list's
  // alone, the machines list's alone, or both lists'. internal/config/identity.go
  // refuses the other list's keys inline, per type, so a new verifier field that
  // is in no set, or in two, fails here rather than showing under the wrong
  // list (#57).
  func TestEveryIdentityVerifierKeyIsClassified(t *testing.T) {
  	var all []Key
  	walk(reflect.TypeOf(config.FileSchema()), "", map[reflect.Type]bool{}, refusedNames(), &all)
  	seen := map[string]bool{}
  	for _, k := range all {
  		for _, list := range []string{"broker.identity.humans.[].", "broker.identity.machines.[]."} {
  			if rest, ok := strings.CutPrefix(k.Path, list); ok {
  				first, _, _ := strings.Cut(rest, ".")
  				seen[first] = true
  			}
  		}
  	}
  	if len(seen) == 0 {
  		t.Fatal("no broker.identity verifier keys: the schema walk changed")
  	}
  	sets := map[string]map[string]bool{"humansOnlyKeys": humansOnlyKeys, "machinesOnlyKeys": machinesOnlyKeys,
  		"sharedIdentityKeys": sharedIdentityKeys}
  	for key := range seen {
  		var in []string
  		for name, set := range sets {
  			if set[key] {
  				in = append(in, name)
  			}
  		}
  		if len(in) != 1 {
  			t.Errorf("verifier key %q is in %v: classify it in exactly one, from internal/config/identity.go's refusals", key, in)
  		}
  	}
  	for name, set := range sets {
  		for key := range set {
  			if !seen[key] {
  				t.Errorf("%s names %q, which no verifier has", name, key)
  			}
  		}
  	}
  }
  ```

- [ ] **Step 2: Run it and see it fail.** `go test ./internal/docgen/ -run '^TestEveryIdentityVerifierKeyIsClassified$' -count=1`. Expected: the build fails (`sharedIdentityKeys` undefined). Paste the output.

- [ ] **Step 3: Implement.** In the `var (...)` block of `schema.go`, after `machinesOnlyKeys`:

  ```go
  	// sharedIdentityKeys are the keys both lists take (x509, oidc and k8s alike
  	// on either side). Every verifier key is in exactly one of the three sets
  	// (TestEveryIdentityVerifierKeyIsClassified).
  	sharedIdentityKeys = map[string]bool{"type": true, "trust_anchor_file": true, "issuer": true, "algorithms": true,
  		"ca_file": true}
  ```

  If the first green run names another key, classify it by the loader's refusals (`identity.go:181-183`, `:210-213`, `:223-226`, `:434-439`, `:724-725`), and say so in the report. Do not change `identityKeyBelongs`, which reads only the two `*OnlyKeys` sets.

- [ ] **Step 4: Run** `go test ./internal/docgen/ -count=1 && make docs && git status --short`. Expected: PASS, no diff.

  **Mutation check:** delete `"type": true` from `sharedIdentityKeys` and see the test go red. Then add a field `X string \`yaml:"x_probe"\`` to `identityVerifierYAML` and see it go red again. Restore both.

- [ ] **Step 5: Commit.**

  `git add internal/docgen/schema.go internal/docgen/docgen_test.go && git commit -m "test(docgen): every identity verifier key is classified humans-only, machines-only or shared (#57)"`

---

### Task 5: the enrollment store's lost reason keeps its cause and remedy at any path length (#58)

**Files:**
- Modify `internal/printsafe/printsafe.go`: add `Tail`. Test in `internal/printsafe/printsafe_test.go`.
- Modify `internal/store/enrollfile/enrollfile.go`:
  - add `readFailure` and `(*File).shownPath`;
  - use them in `read` (`:97-98`), `pickUpLate` (`:131`, `:138-139`) and `lostErr` (`:197`).
- Test: `internal/store/enrollfile/enrollfile_test.go`.

- [ ] **Step 1: Write the failing tests.**

  In `printsafe_test.go`:

  ```go
  // Tail keeps the end: a path past the limit keeps its file name.
  func TestTailKeepsTheEnd(t *testing.T) {
  	if got := Tail("/a/b/enrollments.json", 64); got != "/a/b/enrollments.json" {
  		t.Fatalf("short: %q", got)
  	}
  	got := Tail("/"+strings.Repeat("d", 200)+"/enrollments.json", 32)
  	if !strings.HasPrefix(got, "…") || !strings.HasSuffix(got, "/enrollments.json") || len(got) > 32+len("…") {
  		t.Fatalf("long: %q", got)
  	}
  	if got := Tail("x\x1b[2J/f", 64); strings.ContainsRune(got, '\x1b') {
  		t.Fatalf("a control byte: %q", got)
  	}
  }
  ```

  Add `"strings"` to its imports if the file lacks it.

  In `enrollfile_test.go`:

  ```go
  // A late file refused at a deep path keeps its cause and its remedy whole in
  // the lost reason: the path is cut from its start, never the reason from its
  // end, so the broker's 300-byte line still says what is wrong and what to
  // do (#58).
  func TestALateRefusalAtALongPathKeepsItsCauseAndRemedy(t *testing.T) {
  	ctx := context.Background()
  	dir := filepath.Join(dirFor(t), strings.Repeat("d", 120), strings.Repeat("e", 120))
  	if err := os.MkdirAll(dir, 0o700); err != nil {
  		t.Fatal(err)
  	}
  	path := filepath.Join(dir, "enrollments.json")
  	running := openAt(t, path, keys())
  	real := filepath.Join(dir, "real.json")
  	written(t, real, keys())
  	lost := func(cause string) {
  		t.Helper()
  		_, err := running.GetEnrollmentMark(ctx)
  		if !errors.Is(err, store.ErrEnrollmentStoreLost) {
  			t.Fatalf("not lost: %v", err)
  		}
  		said := err.Error()
  		for _, want := range []string{cause, "fix its owner and mode, or remove a link", "looks again", "/enrollments.json"} {
  			if !strings.Contains(said, want) {
  				t.Errorf("%d bytes, want %q: %s", len(said), want, said)
  			}
  		}
  		if len(said) > 300 || strings.Contains(said, strings.Repeat("d", 120)) {
  			t.Errorf("%d bytes, the path not cut: %s", len(said), said)
  		}
  	}
  	if err := os.Symlink(real, path); err != nil {
  		t.Fatal(err)
  	}
  	lost("symbolic link")
  	if os.Geteuid() == 0 {
  		return // root reads a 0000 file
  	}
  	if err := os.Remove(path); err != nil {
  		t.Fatal(err)
  	}
  	if err := os.Rename(real, path); err != nil {
  		t.Fatal(err)
  	}
  	if err := os.Chmod(path, 0); err != nil {
  		t.Fatal(err)
  	}
  	lost("permission denied")
  }
  ```

- [ ] **Step 2: Run them and see them fail.** `go test ./internal/printsafe/ ./internal/store/enrollfile/ -run '^Test(TailKeepsTheEnd|ALateRefusalAtALongPathKeepsItsCauseAndRemedy)$' -count=1`. Expected: `Tail` undefined. After only `Tail` exists, the enrollfile test fails on byte count and on the path not being cut. Paste the red output.

- [ ] **Step 3: Implement.**

  In `printsafe.go`, after `Line`:

  ```go
  // Tail is Line keeping the end of s: past limit bytes its start is cut and
  // marked, so a path keeps its file name.
  func Tail(s string, limit int) string {
  	if len(s) <= limit {
  		return Line(s, limit)
  	}
  	return "…" + Line(s[len(s)-limit:], limit)
  }
  ```

  In `enrollfile.go` (add `"github.com/blanketfish/port49/internal/printsafe"` to the imports; `errors`, `io/fs` and `syscall` are there):

  ```go
  // shownPath is the path as a lost reason names it: its last 40 bytes (as built), so a
  // deep path never pushes the cause and the remedy past the broker's cut
  // (#58).
  func (f *File) shownPath() string { return printsafe.Tail(f.path, 56) }

  // readFailure is why the file at the path does not read, in words that do
  // not repeat the path, which the fence's own error names again (#58).
  func readFailure(err error) string {
  	var pe *fs.PathError
  	switch {
  	case errors.Is(err, syscall.ELOOP): // first: the link refusal wraps a PathError
  		return "it is a symbolic link, and the enrollment store is read only as a file of its own"
  	case errors.As(err, &pe):
  		return "it cannot be read (" + pe.Err.Error() + ")"
  	}
  	return "it cannot be read (" + err.Error() + ")"
  }
  ```

  The three call sites:
  - **`read`, `:97-98`:** `f.present, f.lost = true, readFailure(err)+": fix its owner and mode, restore it, or run `+"`port49 directory reset-second-factor --all`"`. Keep the backquoted command exactly as it is today.
  - **`pickUpLate`, `:131`:** `why = readFailure(err) + ": fix its owner and mode, or remove a link"`.
  - **`pickUpLate`, `:138-139`, and `lostErr`, `:197`:** `f.path` becomes `f.shownPath()`.

- [ ] **Step 4: Run.**
  - `go test ./internal/printsafe/ ./internal/store/enrollfile/ ./internal/broker/ -count=1`. Expected: PASS, including `TestALateFileThatCannotBeReadIsSaidAndRetriedAtTheNextLook` and `TestALinkAtThePathIsRefused`.
  - Then the issue's own test under a long TMPDIR: `L=$TMPDIR/$(printf 'x%.0s' {1..80}) && mkdir -m 700 $L && TMPDIR=$L go test ./internal/port49d/ -run '^TestARunningBrokerSaysALateUnreadableFileOnceAndFollowsTheFix$' -count=1 -timeout 30m`. Expected: PASS. Run it on `main` too, and paste its red result.

  **Mutation check:** swap the first two `case`s of `readFailure`. The link half of the new test must go red, because the reason no longer says `symbolic link`. Restore.

- [ ] **Step 5: Commit.**

  `git add internal/printsafe/printsafe.go internal/printsafe/printsafe_test.go internal/store/enrollfile/enrollfile.go internal/store/enrollfile/enrollfile_test.go && git commit -m "fix(enrollfile): a lost reason cuts the path, never its cause or remedy, at any path length (#58)"`

---

### Task 6: the askpass socket test does not depend on TMPDIR's length (#58)

**Files:**
- Modify `cmd/port49/ssh_fix_test.go:76-108`.

- [ ] **Step 1: Show it red.** With the Global Constraints TMPDIR (`~/.cache/p49t.XXXX`): `go test ./cmd/port49/ -run '^TestTheAskpassSocketIsNeverMadeInAnOpenDirectory$' -count=1`. Expected: `the askpass socket directory ... is too long for a Unix socket`. Paste it.

- [ ] **Step 2: Rewrite the test, and add the long-path case.**
  - Add a helper above the test:

    ```go
    // socketDir is a private directory short enough for a Unix socket whatever
    // TMPDIR is: one under /tmp, made 0700 here, as an agent's XDG_RUNTIME_DIR
    // would be (#58). t.TempDir adds the test's name, which a long TMPDIR
    // pushes past the socket's 107 bytes.
    func socketDir(t *testing.T) string {
    	t.Helper()
    	d, err := os.MkdirTemp("/tmp", "p49s")
    	if err != nil {
    		t.Fatal(err)
    	}
    	t.Cleanup(func() { os.RemoveAll(d) })
    	if err := os.Chmod(d, 0o700); err != nil {
    		t.Fatal(err)
    	}
    	return d
    }
    ```

  - In `TestTheAskpassSocketIsNeverMadeInAnOpenDirectory`, `base` becomes `base := socketDir(t)`, with its `MkdirTemp` and `Cleanup` lines removed.
  - In the same test, `listenAskpass(filepath.Join(privateDir(t), "agent.sock"))` becomes `listenAskpass(filepath.Join(socketDir(t), "agent.sock"))`. The open-directory assertions stay as they are.
  - Add:

    ```go
    // A private directory too long for a Unix socket is refused in the
    // product's own words, and nothing is made there (#58).
    func TestAnAskpassSocketPastAUnixSocketsLengthIsRefused(t *testing.T) {
    	long := filepath.Join(socketDir(t), strings.Repeat("l", 100))
    	if err := os.Mkdir(long, 0o700); err != nil {
    		t.Fatal(err)
    	}
    	if ln, _, err := listenAskpass(filepath.Join(long, "agent.sock")); err == nil ||
    		!strings.Contains(err.Error(), "too long for a Unix socket") {
    		if ln != nil {
    			ln.Close()
    		}
    		t.Fatalf("a socket past 107 bytes: %v", err)
    	}
    	if left, _ := filepath.Glob(filepath.Join(long, "askpass-*")); len(left) != 0 {
    		t.Fatalf("left behind: %v", left)
    	}
    }
    ```

  - `strings` is already imported.

- [ ] **Step 3: Run** `go test ./cmd/port49/ -run 'Askpass' -count=1`, under the same TMPDIR and again with `TMPDIR` unset. Expected: PASS both ways.

  **Mutation check:** in `listenAskpass` (`ssh.go:719`), comment out `agent.PrivateDir(dir)`. The open-directory test must still go red. Restore.

- [ ] **Step 4: Commit.**

  `git add cmd/port49/ssh_fix_test.go && git commit -m "test(ssh): the askpass socket tests use a short socket directory of their own (#58)"`

---

### Task 7: Final verification

- [ ] Under the Global Constraints TMPDIR, run `make test && make vet && make docs && git status --short`, then `make test-rest`, and paste the summary lines. `make test-rest` must pass from this one ext4 TMPDIR, `mustpass` included. A failure there that this plan does not name is reported, not fixed in passing.
- [ ] Run the #55 grep again (Task 3, Step 4).

## Operator-facing notes for the PR body

- **`port49 explain`:**
  - On a platform that authorizes sessions only (Junos), the note now names every post-login control that does not reach a live session: the ceiling, a revocation, a username change and the ceiling warning.
  - On Junos (`juniper_junos`, projected or not) it adds that with `authorization-time-interval` set, one re-authorization was measured (L36), and whether more come is open (L40). On a projected Junos it also names the class `idle-timeout` as what ends an idle session. Any other session-only platform is told the device is not known to re-authorize, so not to rely on these controls there.
  - The note's first words are unchanged.
- **`port49 policy diff`:** a group change no session test acknowledges now prints `SUBJECT:` with the hint, as `PRINCIPAL:` and `USERNAME:` do. An acknowledged one prints `subject (a session test asserts it):`. The gate and the exit code are unchanged.
- **Python client and Ansible lookup:**
  - A device that asks for a second factor at each login now says that a person must give it, and that an agent stops and asks one.
  - It names `port49 ssh <device>` as the person's step. It no longer names `port49 token`, which prints a token.
  - Code that matches the old text must match on `.code` (`per_login_mfa_required`) instead.
- **Enrollment store:** when the store's file is a link or cannot be read, the broker's line now always carries the cause and the remedy. The path is shown by its last 40 bytes, so the file name is kept. A directory above the file that cannot be searched is named, by its last 40 bytes. A file sealed under a key the broker does not hold names the key id by its last 12 bytes, says it is not held, and offers all three remedies: set `encryption.previous`, restore the file, or run `port49 directory reset-second-factor --all`.
- **Tests:** `make test-rest` passes from a single ext4 TMPDIR under `~/.cache`.

## Left for later

- A read error the fence words itself, such as a directory others can write or a file over the size limit, keeps the fence's own text, which names the path. Such a reason can exceed 300 bytes, the owner and mode texts even at a short path. Filed as #60, a fix in the fence, which the policy, secret and enrollment reads share.
- `socketDir` assumes `/tmp`. The tests that call it run on Linux only. A darwin test job would need `os.TempDir()` resolved through its link.
