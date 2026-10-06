# L44: Active Directory on a Windows Server DC — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Measure every claim in lab register row L44 on a real Windows Server domain controller
on beehive (the SER8 box). Answer plan 7g's two carried questions on the same DC. Close the row
and decision 38's L44 marks only if every cell is measured.

**Architecture:** The plan adds a third platform, `windows_ad`, to the 7g directory harness
(`tests/lab/directory_test.go`). It does not fork it.
- **The DC.** Windows Server 2025 Standard Evaluation runs as a KVM VM inside the pinned
  `dockurr/windows` container, on its own compose project (`port49labwin`). The VM is installed
  unattended from a cached ISO checked by SHA-256.
- **The setup.** Every step is a committed PowerShell script sent over SSH. Secrets travel on
  stdin, never on a command line.
- **The measurements.** L42's and L43's cells are measured through port49's own dialer, pool and
  resolver, as on Samba. The DC's own certificate mapping (KB5014754) is measured by PKINIT from
  MIT `kinit`, and by SASL EXTERNAL from port49's dialer, under each enforcement value.

**Tech Stack:**
- Go 1.26 (`//go:build lab`), with `golang.org/x/crypto/ssh` (already in go.mod), `embed`,
  `go-ldap` and `internal/directory`.
- `dockurr/windows` 6.06, Windows Server 2025 Evaluation (build 26100.32230), AD DS, AD CS.
- OpenSSH for Windows, PowerShell 5.1.
- MIT Kerberos 1.20 (`krb5-pkinit`) on Debian bookworm, Docker Compose v2.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §15 row **L44**, §13 decision 38 (items 1,
6, 8 and 9). The roadmap is `docs/superpowers/plans/README.md`: "Plan 7g — As built", the operator
notes, "Carried" and "Open for the final review". Also read `docs/design/2026-08-21-port49-design.md`
§7 (line ~371) and §10 ("Directory authentication").

## Global Constraints

- Go 1.26+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo. **No new module**:
  `golang.org/x/crypto/ssh`, `crypto/rsa` and `embed` are already available.
- Use snake_case everywhere it is data: JSON keys in scripts' results and in evidence lines, file
  names in `logs/`.
- Reason codes come only from spec §5.7. This plan adds none.
- The log, the evidence and the note never hold a password, keytab, ticket or private key. Secrets
  are generated at run time and kept only in 0600 files under `tests/lab/logs/windows`.
- Test output names a secret only by its key name (`admin_password`, `dsrm_password`,
  `port49_password`). Never use `set -x`.
- Never run `docker compose config` or `docker inspect` on project `port49labwin`: both print the
  environment, which holds the Administrator's password.
- Verify with `make test && make vet`, and report the real output.
- Branch `feature/l44-windows-ad`, worktree `/home/rwendt/git/port49/.worktrees/l44`. Use
  Conventional Commits, one per "Commit" step, each ending with:
  ```
  Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc
  ```
- **Stay disjoint from plan 7h** (`feature/oidc-and-trust-domains`). This plan never touches
  `internal/oidc`, `internal/broker`, `internal/store`, `internal/policy`, `internal/decision`,
  `internal/daemon/metrics`, `cmd/port49d` or port49d wiring.
  - Code: `tests/lab/` and, only through Task 7's defect path, `internal/directory/`.
  - Text shared with 7h: the `Makefile` (`.PHONY` plus a new target), `tests/lab/README.md` (a new
    subsection), the spec (§13 decision 38 and the §15 L44 row) and the roadmap README. Each gives
    a text conflict at merge, resolved by keeping both sides.
  - Every new top-level identifier in `package lab` starts with `win` or `l44`, so it cannot
    collide with 7h's `oidc*` harness.
- Every **lab run** follows the "Lab rules" section below.

## Rulings

These are this plan's decisions, each with its reason. None changes a spec ruling. A defect that
would change one goes through Task 7, spec first.

- **R1. Windows Server 2025 Evaluation, build 26100.32230, alone.**
  - Its January 2026 media already carries the September 2025 KB5014754 phase, which removed the
    `StrongCertificateBindingEnforcement` key. Its new-forest defaults are also the ones a new
    deployment meets: LDAP signing enforced, channel binding "when supported".
  - The only Windows Server 2022 evaluation ISO dates from March 2022. It predates KB5014754, so
    it would need online updates, which no run can reproduce.
  - OR-2 asks Ryan to confirm closing L44 on 2025 alone.
- **R2. `dockurr/windows` 6.06, pinned by digest, from a cached ISO checked by size and SHA-256.**
  The ISO is never fetched by dockur, which would download 8 GB on every run. The alternatives
  and the reasons are in `.superpowers/sdd/2026-10-06-l44-windows-server-ad/writer-notes.md`.
- **R3. Setup only over OpenSSH, with password authentication as the domain Administrator.**
  - The password gives a full logon with network credentials, which AD CS enrollment and
    `Install-AdcsCertificationAuthority` use.
  - Each script is one PowerShell script block. Parameters travel as JSON on the session's stdin;
    nothing secret is ever on a command line or in a file inside the VM.
- **R4. "The certificate the DC itself maps" is measured two ways.**
  - Through the KDC by PKINIT. That is KB5014754's own path, and MIT documents it against an AD
    KDC.
  - Through LDAPS by SASL EXTERNAL, Schannel's S4U2Self path, with the broker's certificate.
  - Each runs under `StrongCertificateBindingEnforcement` absent (as installed), `1` and `2`. On
    this build both values may be ignored; the run measures whether they are.
- **R5. Certificates from AD CS and from the harness's own CAs.**
  - **AD CS `OfflineRouter`** (a subject the harness supplies, so no SID extension): for
    `issuer_serial` on an issuer named `CN=corp-L44-CA,DC=corp,DC=example,DC=com`.
  - **AD CS `User`, requested as alice** (the SID extension): for `sid`.
  - **The lab users CA:** a serial whose top bit is set, to ask whether Windows keeps the DER
    sign byte in `<SR>`.
  - **A CA whose CN holds a comma:** plan 7g's carried question, whether Windows quotes a `,` in
    `<I>`.
  - Every key is RSA-2048 and stays on the host. The key type is no part of the claim.
- **R6. A setup failure is never a mapping result.**
  - These invalidate a cell: KDC events 19, 21 or 29 (no KDC certificate, or a client
    certificate that did not validate), a clock skew over 60 s, or a certificate that predates
    alice's account.
  - Such a cell is INVALID, re-run up to three times, and keeps the row open.
- **R7. The run that closes L44 is a fresh DC at the pinned commit.**
  `PORT49_LAB_WINDOWS_REUSE` is for developing the harness only. A note written from a reused DC
  says so, and Task 6 does not accept it.
- **R8. Plan 7g's two carried questions are answered with data, not code.**
  - **(a)** The run records `supportedCapabilities` on Windows, and on OpenLDAP and Samba for
    comparison. The warning itself stays parked for the final review.
  - **(b)** The run records the LDAP result Windows gives an EXTERNAL bind it refuses. If that
    result is 1, Task 7c widens `Refusal` for EXTERNAL alone, spec first (OR-1).

## Review Focus

1. **A secret reaching a log, the evidence or the note through a failed step.** A PowerShell
   exception or `ktpass` output that echoes a parameter must reach no `t.Fatalf`, line or file
   unscrubbed. Task 2 and Task 3 test that `winScrub` removes every secret, that `winSecrets`
   formats as key names, and that no script writes a secret parameter.
2. **A setup failure read as KB5014754's verdict.** A missing KDC certificate, an unknown
   revocation status, a skewed clock or a backdated certificate would each look like "refused".
   Task 2 tests `winKDCPrecondition`, `winSkewOK` and `winIssuedAfter`. Task 5 marks such a cell
   INVALID with `t.Errorf`.
3. **A stale `altSecurityIdentities` value from the previous case.** The attribute is multi-valued,
   so a leftover value would answer for the next case. Task 4's `setAltSec` reads the attribute
   back and asserts exactly the one value with `winOnlyValue`, which Task 2 tests.
4. **The VM image or the ISO drifting from the pins.** A moved tag or a replaced ISO behind the
   same URL would change the platform under the same name. Task 3 tests that the compose file pins
   the digest. Task 2 tests that `winISOOK` refuses a wrong size or sum. Every run checks the ISO.
5. **The harness refactor silently changing L42's or L43's output on the closed platforms.**
   Task 1 tests that the note's platform and credentials lines are unchanged for the containers,
   and re-runs `make lab-directory` to a scratch output to compare cells.

---

## Lab rules for this plan (binding on every run)

Adapted from plan 7h's lab rules (`.superpowers/sdd/2026-10-06-l44-windows-server-ad/lab-instructions-7h-copy.md`).

### Results and defects

- Follow CLAUDE.md's lab register rules 1–4.
- A result that contradicts a doc means the doc is wrong (rule 4).
- A result that shows port49 wrong is a defect. Fix it on the branch, with a unit test, in a
  `fix(directory)` commit (Task 7), and re-run from a worktree pinned to the fix.
- A cell whose precondition failed (R6) is re-run up to three times. After that it is recorded
  INVALID, and a row with an INVALID cell stays open.

### Where runs happen

- **Runs always use a detached worktree pinned at the commit under test:**
  `git -C /home/rwendt/git/port49 worktree add --detach /home/rwendt/git/port49/.worktrees/lab-l44 <sha>`.
  - Never run from `.worktrees/l44`, and never build in it, during a run.
  - Never touch `.worktrees/oidc` or `.worktrees/lab-7h`.
- **Copy before removing.** When a run is done, copy `tests/lab/results/L44-windows_ad.md` and
  `tests/lab/evidence/L44-windows_ad.json` back to `.worktrees/l44` before removing the pinned
  worktree. L44 takes no pcap: LDAPS and PKINIT are encrypted, and the evidence is the JSON lines.
  `make evidence` must still pass in `.worktrees/l44`.
- **Single occupant.** Before a run, `sg docker -c "docker ps --format '{{.Names}}'"` must show no
  other lab: no `clab-*`, no `port49lab*` and no Keycloak. 7h's lab waits for L44, and L44 waits
  for any lab already running.

### After every run, confirm

- `sg docker -c "docker compose -p port49labwin ps -a"` is empty and `docker volume ls` shows no
  `port49labwin_storage`.
- `docker compose -p port49labdir ps -a` is empty (the capability comparison).
- No `port49labwin-pkinit-run-*` container is left.
- The private keys and secrets under `tests/lab/logs/windows` are gone. The harness removes them
  unless `PORT49_LAB_WINDOWS_KEEP` is set.
- L44 stops no host service and edits nothing under `/etc`. It needs no `daemon.json` change,
  because dockur's ports go through docker-proxy.

### Disk, RAM and time

- **Disk.** Before each run, `df -h /` must show **at least 66 GiB free**: the 15 GiB floor plus
  about 51 GiB at peak. Stop and report below that.
  - 8.2 GB for the ISO cache (kept between runs, in `~/.cache/port49-lab/iso`).
  - About 17 GB transient while dockur extracts and rebuilds the ISO in its volume.
  - Up to about 25 GB for the VM disk (64 GB sparse).
  - 1 GB for the images.
  - The root LV has 19 GB free today. The controller grows it first with
    `sudo lvextend -r -L +80G /dev/ubuntu-vg/ubuntu-lv` (the VG has 828 GB free).
- **RAM.** The VM takes 6 GB plus QEMU's overhead. The comparison containers take under 1 GB.
  Beehive has 30 GB.
- **Time.** A fresh run takes about 1.5–2.5 h: download on first use, Setup, promotion, AD CS,
  then the measurements.

### Running and watching

- Run Docker through `sg docker -c "..."`. Bash calls that touch Docker need the sandbox disabled.
- **Watchdog.** A background stall watchdog runs for the whole run and is re-armed on every wake.
  - It watches the `go test -v` log and `docker compose -p port49labwin logs --tail 5 dc`.
  - The stall threshold is 40 minutes until the first SSH session answers (Windows Setup is
    silent for long stretches; the harness logs dockur's last line every 2 minutes). After that it
    is 25 minutes.
  - Wait on the run in a foreground loop with a deadline. Never end a turn waiting on a background
    notification.
  - On a hang, send `kill -QUIT` to the exact test process
    (`pgrep -f "^/tmp/go-build[^ ]*/lab\.test"`) for a goroutine dump.

### Secrets

- Never print, `cat`, `head`, `grep` or `jq` any of these: `windows.env`, `secrets.json`,
  `port49.keytab`, any `*-key.pem`, `tests/lab/logs/directory/lab.env`.
- Never run `docker compose config` or `docker inspect` on `port49labwin`.
- Never `set -x`.

### Results notes and stopping

- **Results notes** are written as `writeResult` writes them. Each has the date, the image and
  ISO versions with their digests, the run command at the pinned commit, the evidence pointer,
  the credentials statement and the observation tables.
- **Stop rule.** Stop and report, with the dockur log tail and the step that failed, if either of
  these holds:
  - the bring-up (Task 4 Step 6) fails three times: no SSH within 150 minutes, or the promotion,
    AD CS, LDAPS, keytab or enrollment step failing;
  - a DC comes up but a cell can never be measured.

  L44 stays open, and the fallback is Ryan's call. **Never weaken L44 to fit.**

---

## File structure

| File | What it is |
|---|---|
| `tests/lab/directory_test.go` (modify) | The 7g harness, extended (Task 1). It gains a third platform's fields, a `newDirectories` split from `startDirectories`, a `writeResult` that takes the platform's `labDir`, the root DSE's capabilities, and a platform-neutral `setAttr` and `objectSid` read. |
| `tests/lab/l42_test.go`, `tests/lab/l43_test.go` (modify) | L42's body moves into `labDir.l42Observe`. L43's mapping checks run on every directory with `altSecurityIdentities`. Output is unchanged. |
| `tests/lab/directory_unit_test.go` (modify) | Unit tests for Task 1. |
| `tests/lab/windows_test.go` (create) | The Windows platform. Task 2 adds the pure helpers (secrets, the PowerShell bootstrap, ISO check, `altSecurityIdentities` forms, CSRs, the PKINIT parser and the precondition judges). Task 3 adds the embedded scripts' registry. Task 4 adds the DC's bring-up, SSH runner and certificate issuance. |
| `tests/lab/windows_unit_test.go` (create) | Unit tests for Tasks 2, 3 and 5. They run in `make test` (`LAB_UNIT_TESTS`). |
| `tests/lab/directory/windows/compose.yaml` (create) | The `port49labwin` project: the `dc` service (dockur) and the `pkinit` tool. |
| `tests/lab/directory/windows/oem/install.bat` (create) | dockur's first-logon hook: sshd on, firewall off, Windows Update off. |
| `tests/lab/directory/windows/pkinit/Dockerfile` (create) | MIT `kinit` with PKINIT, on pinned Debian bookworm. |
| `tests/lab/directory/windows/scripts/*.ps1` (create, 15) | One setup or measurement step each, embedded into the test binary. |
| `tests/lab/l44_test.go` (create) | `TestL44WindowsAD` and its sections; `TestL44Bringup`. |
| `tests/lab/results/L44-windows_ad.md`, `tests/lab/evidence/L44-windows_ad.json` (created by the run) | The note and its evidence. |
| `Makefile` (modify) | `lab-windows`. |
| `tests/lab/README.md` (modify) | "Windows Server AD (L44)" under "Directories (plan 7g)". |
| `internal/directory/mapping.go`, `conn.go` and their tests (modify, **only on Task 7's defect path**) | |
| `docs/design/2026-08-23-policy-engine-spec.md`, `docs/design/2026-08-21-port49-design.md`, `docs/superpowers/plans/README.md` (modify, Task 8) | |

---

### Task 1: Extend the 7g harness for a third platform (no change to L42's or L43's output)

**Files:**
- Modify: `tests/lab/directory_test.go`, `tests/lab/l42_test.go`, `tests/lab/l43_test.go`
- Test: `tests/lab/directory_unit_test.go`

**Interfaces:**
- Consumes: the 7g harness as merged (`labDir`, `directories`, `dirPKI`, `writeResult`,
  `mappingChecks`, `mailCollision`, `aliceSID`, `bindGSSAPI`).
- Produces:
  - `labDir` gains these fields: `where string`, `credentials string`, `keytabFile string`,
    `krb5File string`, `loopRefused string`, `win *winDC`.
  - `directories` gains `runSel string` and `extra []string`.
  - `dirPKI` gains `ca *testpki.CA`.
  - New functions: `newDirectories(t) *directories`, `dirRunLine(sel string) string`,
    `writeResult(t, d, row string, l *labDir, claim, version, observation, evidencePath string)`
    and `noteHoldsSecret(note string, secrets ...string) bool`.
  - New `labDir` methods: `(l *labDir) l42Observe(t, ev) string`,
    `(l *labDir) capabilities(t) []string`, `(l *labDir) setAttr(t, dn, attr, value string)`,
    `(l *labDir) ldapObjectSID(t, filter string) string` and `(l *labDir) waitLDAPS(t, within)`.
  - `labSIDString(b []byte) (string, error)`.
  - `evidenceLine.DCEvents []string` (JSON `dc_events`).
  - `winDC` is declared in Task 4. Until then, Task 1 adds a placeholder type so the package
    compiles. Task 4 replaces it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/lab/directory_unit_test.go`:

```go
// The run line names the selection the note came from, so an L44 note never
// claims L42's command.
func TestDirectoryRunLineNamesTheSelection(t *testing.T) {
	if got := dirRunLine("TestL44"); !strings.Contains(got, "-run 'TestL44'") {
		t.Fatalf("%s", got)
	}
}

// The containers' notes keep the lines they were written with: the refactor
// for a third platform changes nothing a committed L42 or L43 note says.
func TestDirectoryNoteKeepsTheContainersLines(t *testing.T) {
	out := t.TempDir()
	d := &directories{out: out, password: "Aa1!pw", runSel: "TestL42|TestL43"}
	l := &labDir{name: platSamba, where: containerWhere, d: d}
	writeResult(t, d, "L42", l, "claim", "v", "obs", "tests/lab/evidence/x.json")
	b, err := os.ReadFile(filepath.Join(out, "tests", "lab", "results", "L42-samba_ad.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"- **Platform:** samba_ad, as a container on `tests/lab/directory/compose.yaml` (no network device)\n",
		"- **Credentials:** none appear here or in the evidence. The bind password is generated for each run and never printed; the keytab and every ticket stay on the host that ran it.\n",
		"-run 'TestL42|TestL43'",
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("note lacks %q", want)
		}
	}
}

// A note naming any of the run's secrets is refused, whichever secret it is.
func TestDirectoryNoteHoldsSecret(t *testing.T) {
	if !noteHoldsSecret("x Aa1!b y", "", "Aa1!b") || noteHoldsSecret("clean", "Aa1!b", "") {
		t.Fatal("noteHoldsSecret")
	}
}

// objectSid's binary form reads back as the SID string AD prints.
func TestDirectoryLabSIDString(t *testing.T) {
	b := []byte{1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 111, 0, 0, 0, 222, 0, 0, 0, 77, 1, 0, 0, 81, 4, 0, 0}
	if got, err := labSIDString(b); err != nil || got != "S-1-5-21-111-222-333-1105" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := labSIDString([]byte{1, 2, 0}); err == nil {
		t.Fatal("a short objectSid read as a SID")
	}
}
```

Also extend `TestDirectoryPKIShape`: after `writeDirectoryPKI`, add
`if p.ca == nil || !p.ca.Cert.IsCA { t.Fatal("dirPKI keeps no CA") }`.

- [ ] **Step 2: Run them and see them fail**

Run: `go test -tags lab ./tests/lab/ -run '^(TestDirectoryRunLineNamesTheSelection|TestDirectoryNoteKeepsTheContainersLines|TestDirectoryNoteHoldsSecret|TestDirectoryLabSIDString|TestDirectoryPKIShape)$' -count=1`

Expected: a build failure (`dirRunLine` takes no argument; `containerWhere`, `noteHoldsSecret`,
`labSIDString` and `p.ca` are undefined).

- [ ] **Step 3: Implement the harness changes in `tests/lab/directory_test.go`**

1. Add the fields. In `labDir`, after `d *directories`:

```go
	where       string // the note's Platform line after the name: what ran, and on what
	credentials string // the note's Credentials line; "" is the containers' line
	keytabFile  string // the broker's keytab for GSSAPI
	krb5File    string // the client krb5.conf naming the platform's KDC
	loopRefused string // the directory's refusal to make L42's loop, when it refused
	win         *winDC // the Windows DC's runner (L44); nil for the containers
```

In `directories`, after `said []string`:

```go
	runSel string   // the -run selection the notes name (dirRunLine)
	extra  []string // other secrets a note or the evidence must never hold (the Windows DC's)
```

In `dirPKI`, before `caFile`: `ca *testpki.CA // the lab CA: it signs the directories' server certificates`.
In `writeDirectoryPKI`, set `ca: ca` in the `&dirPKI{...}` literal.

2. Add, under the platform constants:

```go
// containerWhere is the Platform line of the two containers' notes.
const containerWhere = "as a container on `tests/lab/directory/compose.yaml` (no network device)"
```

3. Split `startDirectories`. `newDirectories` is everything from `repoRoot()` up to and including
the two `labDir` literals. Those literals now also set `where: containerWhere` and
`keytabFile: filepath.Join(d.dir, "out", "port49.keytab"), krb5File: filepath.Join(d.dir, "out", "krb5.conf")`,
and `d.runSel = "TestL42|TestL43"`.

```go
// newDirectories writes the run's PKI, bind password, lab.env and krb5.conf
// under a fresh tests/lab/logs/directory and describes the two containers,
// starting nothing: L44 builds its DC on the same PKI and password.
func newDirectories(t *testing.T) *directories {
	// (the body of startDirectories from repoRoot() to the end of the
	// d.samba literal, unchanged but for the fields above)
	return d
}

func startDirectories(t *testing.T) *directories {
	t.Helper()
	d := newDirectories(t)
	if os.Getenv("PORT49_LAB_DIRECTORY_KEEP") == "" {
		t.Cleanup(func() { d.down(t) })
	}
	// (the rest of the old body, from "Whatever an earlier run ..." on, unchanged)
	return d
}
```

4. `bindGSSAPI` reads the fields:

```go
func (l *labDir) bindGSSAPI() directory.Bind {
	return directory.Bind{Mechanism: "gssapi", KeytabFile: l.keytabFile, Principal: "port49@" + dirRealm, KRB5Conf: l.krb5File}
}
```

5. The run line, the secret check and `writeResult`:

```go
// dirRunLine is the commit the run was made at and the test selection.
func dirRunLine(sel string) string {
	sha := "unknown"
	if root, err := repoRoot(); err == nil {
		if out, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output(); err == nil {
			sha = strings.TrimSpace(string(out))
		}
	}
	return fmt.Sprintf("commit `%s`, `go test -tags lab ./tests/lab/ -run '%s'`", sha, sel)
}

// noteHoldsSecret reports whether note holds any non-empty secret.
func noteHoldsSecret(note string, secrets ...string) bool {
	for _, s := range secrets {
		if s != "" && strings.Contains(note, s) {
			return true
		}
	}
	return false
}
```

In `writeResult`:
- Change the signature to
  `func writeResult(t *testing.T, d *directories, row string, l *labDir, claim, version, observation, evidencePath string)`.
- Use `l.name` where `platform` was.
- The Platform line becomes `fmt.Fprintf(&b, "- **Platform:** %s, %s\n", l.name, l.where)`.
- The run line becomes `dirRunLine(d.runSel)`.
- The credentials line is `l.credentials` when it is non-empty, else the existing sentence.
- The secret check becomes:

```go
	if noteHoldsSecret(b.String(), append([]string{d.password}, d.extra...)...) {
		t.Fatalf("the %s-%s note holds a credential; it must hold none", row, l.name)
	}
```

6. Platform branches. In `version`, add `case platWindows: return l.win.version()` before
`default`. In `configNote`, put `if l.name == platWindows { return l.win.configNote() }` first.

7. The new `labDir` methods:

```go
// capabilities is the root DSE's supportedCapabilities, sorted, read through
// the broker's pool over LDAPS (plan 7g's carried question a).
func (l *labDir) capabilities(t *testing.T) []string {
	t.Helper()
	r := l.resolver(t, "direct")
	var out []string
	_, err := r.Pool.Do(context.Background(), func(s directory.Searcher) error {
		res, err := s.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 15, false,
			"(objectClass=*)", []string{"supportedCapabilities"}, nil))
		if err == nil && len(res.Entries) == 1 {
			out = res.Entries[0].GetAttributeValues("supportedCapabilities")
		}
		return err
	})
	if err != nil {
		t.Fatalf("%s: the root DSE's supportedCapabilities: %v", l.name, err)
	}
	slices.Sort(out)
	return out
}

// setAttr replaces one attribute of one entry: by the DC's own tools on Samba,
// by Set-ADObject on Windows. The value is never printed.
func (l *labDir) setAttr(t *testing.T, dn, attr, value string) {
	t.Helper()
	switch l.name {
	case platSamba:
		if out, err := l.exec("/lab/set-attr.sh", dn, attr, value); err != nil {
			t.Fatalf("setting %s on %s: %v\n%s", attr, dn, err, tailOf(out, 400))
		}
	case platWindows:
		l.win.setValues(t, dn, attr, []string{value})
	default:
		t.Fatalf("%s: setAttr is for directories with altSecurityIdentities", l.name)
	}
}

// ldapObjectSID is the objectSid of the one entry filter finds, read as bytes
// over LDAPS through the broker's pool: the attribute port49's sid mapping
// compares.
func (l *labDir) ldapObjectSID(t *testing.T, filter string) string {
	t.Helper()
	r := l.resolver(t, "direct")
	var raw []byte
	_, err := r.Pool.Do(context.Background(), func(s directory.Searcher) error {
		res, err := s.Search(ldap.NewSearchRequest(l.baseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, 15, false,
			filter, []string{"objectSid"}, nil))
		if err == nil && len(res.Entries) == 1 {
			raw = res.Entries[0].GetRawAttributeValue("objectSid")
		}
		return err
	})
	if err != nil || len(raw) == 0 {
		t.Fatalf("%s: objectSid of %s: %v (%d bytes)", l.name, filter, err, len(raw))
	}
	sid, err := labSIDString(raw)
	if err != nil {
		t.Fatalf("%s: objectSid of %s: %v", l.name, filter, err)
	}
	return sid
}

// labSIDString is objectSid's binary form as a SID string: revision 1, the
// count, the 48-bit authority big-endian, each sub-authority little-endian.
func labSIDString(b []byte) (string, error) {
	if len(b) < 8 || b[0] != 1 || len(b) != 8+4*int(b[1]) {
		return "", errors.New("a malformed objectSid")
	}
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = auth<<8 | uint64(b[2+i])
	}
	s := fmt.Sprintf("S-1-%d", auth)
	for i := 0; i < int(b[1]); i++ {
		s += fmt.Sprintf("-%d", binary.LittleEndian.Uint32(b[8+4*i:]))
	}
	return s, nil
}

// waitLDAPS waits for l's LDAPS to answer a root DSE read under the lab CA.
func (l *labDir) waitLDAPS(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		err := l.d.rootDSE(l)
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: LDAPS did not answer within %s: %v", l.name, within, err)
		}
		time.Sleep(2 * time.Second)
	}
}
```

Add `"encoding/binary"` to the imports.

8. `aliceSID` gains a Windows branch at its top:
`if l.name == platWindows { return l.ldapObjectSID(t, "(sAMAccountName=alice)") }`.

9. `evidenceLine` gains `DCEvents []string `json:"dc_events,omitempty"`` after `DurationMS`.

10. Add a placeholder so Task 1 compiles alone. Task 4 deletes it:

```go
// winDC is the Windows DC's runner (Task 4 of the L44 plan replaces this).
type winDC struct{}

func (*winDC) version() string                              { return "" }
func (*winDC) configNote() string                           { return "" }
func (*winDC) setValues(*testing.T, string, string, []string) {}

const platWindows = "windows_ad"
```

- [ ] **Step 4: Move L42's body and widen L43's mapping checks**

In `tests/lab/l42_test.go`, add the method below. Its body is the old loop body with `dir`
replaced by `l` and `d.password` by `l.d.password`, plus the `loopRefused` branch.

```go
// l42Observe is L42's table on l: each user under each nested mode, port49's
// recursive and direct walks asserted, then memberOf on alice's entry.
func (l *labDir) l42Observe(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	var obs strings.Builder
	obs.WriteString("| user | mode | groups returned | result | time |\n|---|---|---|---|---|\n")
	for _, mode := range []directory.Nested{"in_chain", "recursive", "direct"} {
		for _, user := range []string{"alice", "carol", "dave"} {
			ev.mark("L42 %s %s", user, mode)
			r := l.resolverWith(t, l.config(mode, l.groupsBaseDN, l.bindSimple(), sanEmail()), l.d.password, ev)
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			start := time.Now()
			a, err := r.Verify(ctx, l.principal(user))
			took := time.Since(start)
			cancel()
			groups := strings.Join(a.GroupNames, ", ")
			if groups == "" {
				groups = "(none)"
			}
			fmt.Fprintf(&obs, "| %s | %s | %s | %s | %s |\n", user, mode, groups, errOrOK(err), took.Round(time.Millisecond))
			if user == "dave" && l.loopRefused != "" {
				continue // the loop was never made: the observation says so below
			}
			if want, ok := l42Want[user][mode]; ok {
				if err != nil || !slices.Equal(a.GroupNames, want) {
					t.Errorf("%s %s: groups %v, err %v; port49's %s walk returns %v", user, mode, a.GroupNames, err, mode, want)
				}
			}
		}
	}
	if l.loopRefused != "" {
		fmt.Fprintf(&obs, "\nThe loop (`g-loop-a` ∈ `g-loop-b` ∈ `g-loop-a`) was not made: the directory refused it: `%s`.\n",
			oneLineMax(l.loopRefused, 300))
	}
	ev.mark("L42 memberOf on alice's entry")
	fmt.Fprintf(&obs, "\nmemberOf on alice's entry: %s\n", strings.Join(l.memberOf(t, "alice"), ", "))
	return obs.String()
}
```

`TestL42NestedGroups`'s subtest body becomes:

```go
			ev := evidence(t, d, "L42-"+dir.name)
			obs := dir.configNote() + dir.l42Observe(t, ev)
			ev.assertClean(t, d.password)
			writeResult(t, d, "L42", dir, l42Claim, dir.version(t), obs, "tests/lab/evidence/L42-"+dir.name+".json")
```

In `tests/lab/l43_test.go`:
- The `writeResult` call passes `dir` for the platform.
- In `mappingChecks`, both `if l.name == platSamba {` become `if l.name != platOpenLDAP {`. Both
  Samba and Windows hold `altSecurityIdentities` and `objectSid`.
- In `mailCollision`, `set` becomes `set := func(mail string) { l.setAttr(t, bobDN, "mail", mail) }`.

- [ ] **Step 5: Run the unit tests and the package build**

Run: `make lab-unit && go vet -tags lab ./tests/lab/`

Expected: PASS, with every `TestDirectory*` passing and no vet output.

- [ ] **Step 6: Regression run on the closed platforms (lab; follow "Lab rules")**

This checks that the refactor changed no cell on OpenLDAP or Samba. Commit Steps 1–5 first
(Step 7), then:

```bash
git -C /home/rwendt/git/port49 worktree add --detach /home/rwendt/git/port49/.worktrees/lab-l44 "$(git -C /home/rwendt/git/port49/.worktrees/l44 rev-parse HEAD)"
cd /home/rwendt/git/port49/.worktrees/lab-l44
mkdir -p /tmp/claude-1000/l44-regress
PORT49_LAB_DIRECTORY_OUT=/tmp/claude-1000/l44-regress sg docker -c "make lab-directory" 2>&1 | tail -40
for f in L42-openldap L42-samba_ad L43-openldap L43-samba_ad; do
  diff <(sed -n '/^## Observation/,$p' tests/lab/results/$f.md | sed -E 's/[0-9]+(\.[0-9]+)?(ms|s|µs)\b/T/g') \
       <(sed -n '/^## Observation/,$p' /tmp/claude-1000/l44-regress/tests/lab/results/$f.md | sed -E 's/[0-9]+(\.[0-9]+)?(ms|s|µs)\b/T/g') \
  && echo "$f: same cells"
done
```

Expected: `PASS`, and `same cells` for all four. A difference that is only a DN's case, a
generated SID or a serial is the run's own data, and you may note it. Any other difference is a
regression in this task: fix it before going on.

Clean up afterwards: `git -C /home/rwendt/git/port49 worktree remove --force .worktrees/lab-l44`,
then the "After every run, confirm" list.

- [ ] **Step 7: Commit**

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add tests/lab/directory_test.go tests/lab/l42_test.go tests/lab/l43_test.go tests/lab/directory_unit_test.go
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "test(lab): extend the directory harness for a third platform

The note takes its platform line, run selection and credentials line from the
platform; newDirectories writes the PKI without starting the containers; L42's
table is labDir.l42Observe; L43's mapping checks run wherever
altSecurityIdentities exists. The containers' notes are unchanged.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 2: The Windows platform's pure helpers

**Files:**
- Create: `tests/lab/windows_test.go` (`//go:build lab`)
- Create: `tests/lab/windows_unit_test.go` (`//go:build lab`)
- Modify: `tests/lab/directory_test.go` (delete Task 1's `const platWindows`, now declared here)

**Interfaces:**
- Consumes: `dirPKI` (Task 1, with `ca`), `directory.ADIssuerSerial`, `directory.SIDOf`,
  `directory.Mapping.Lookup`, `dirRealm`, `dirSerial`, `oneLineMax`.
- Produces:
  - Constants: `platWindows`, `winProject`, `winImage`, `winISOURL`, `winISOSHA256`,
    `winISOSize`, `winSSH`, `winKDC`, `winKDCInNet`, `winDCHost`, `winCAName`.
  - Secrets and the PowerShell channel: `winSecrets` (`AdminPassword`, `DSRMPassword`, `all()`),
    `winPassword() (string, error)`, `newWinSecrets() (*winSecrets, error)`,
    `winEnv(*winSecrets) string`, `winBootstrap`, `winCommand() string`,
    `winPayload(script string, params map[string]any) ([]byte, error)`,
    `winResult(out []byte) (json.RawMessage, error)` and
    `winScrub(s string, secrets ...string) string`.
  - The ISO: `winISOOK(path string, size int64, sum string) error`.
  - `altSecurityIdentities` forms: `winRDNs(raw []byte) ([][2]string, error)`, `winQuote(v string) string`,
    `winForm{forward, quoted, unreversed, signByte bool}.of(*x509.Certificate) (string, error)`,
    and the variables `winAltSecForward`, `winAltSecUnreversed`, `winAltSecQuoted` and
    `winAltSecSignByte`.
  - Certificates: `winUPNExtension(upn string) (pkix.Extension, error)`,
    `winCSR(cn, upn string) ([]byte, *rsa.PrivateKey, error)`,
    `(p *dirPKI) signServerCSR(csrPEM []byte, now time.Time) ([]byte, error)`,
    `winCommaCA(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error)`,
    `winPersonCert(parent *x509.Certificate, signer crypto.Signer, cn, upn string, serial *big.Int, now time.Time) (*x509.Certificate, *rsa.PrivateKey, error)`,
    `winHighBitSerial() *big.Int`, `pemCert(*x509.Certificate) []byte`, `pemKey(*rsa.PrivateKey) []byte`
    and `parsePEMCert([]byte) (*x509.Certificate, error)`.
  - PKINIT: `pkinitResult{ok bool; kdcErrs []string; last string; took time.Duration}`,
    `parseKinit(out string) pkinitResult`, `(pkinitResult) kdcSaid() string` and
    `winPKINITConf(kdc string) string`.
  - Judges: `winEvent{ID int; Provider, Time, Message string}`, `winKDCPrecondition(id int) bool`,
    `winSkewOK(dc, host time.Time, limit time.Duration) bool`,
    `winIssuedAfter(created time.Time, certs ...*x509.Certificate) error` and
    `winOnlyValue(vals []string, want string) bool`.

- [ ] **Step 1: Write the failing tests** in `tests/lab/windows_unit_test.go`

```go
//go:build lab

package lab

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/rhwendt/port49/internal/directory"
)

// A secret prints as its key names whatever the verb, so a log line that
// formats the struct leaks nothing.
func TestWindowsSecretsPrintAsNames(t *testing.T) {
	s, err := newWinSecrets()
	if err != nil {
		t.Fatal(err)
	}
	out := fmt.Sprintf("%v %+v %#v %s", s, s, s, s)
	for _, v := range s.all() {
		if v == "" || strings.Contains(out, v) {
			t.Fatalf("a secret is empty or printed: %s", out)
		}
	}
	if !strings.Contains(out, "admin_password") || !strings.Contains(out, "dsrm_password") {
		t.Fatalf("%s", out)
	}
}

// Every generated password meets Windows' complexity rule: four classes, and
// long enough for any domain policy this lab meets.
func TestWindowsPasswordMeetsComplexity(t *testing.T) {
	p, err := winPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(p) < 20 || !strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") ||
		!strings.ContainsAny(p, "0123456789") || !strings.ContainsAny(p, "!") {
		t.Fatalf("password of %d chars misses a class", len(p))
	}
	q, _ := winPassword()
	if p == q {
		t.Fatal("two passwords are the same")
	}
}

func TestWindowsEnvFile(t *testing.T) {
	s := &winSecrets{AdminPassword: "Aa1!x"}
	if got := winEnv(s); got != "USERNAME=Docker\nPASSWORD=Aa1!x\n" {
		t.Fatalf("%q", got)
	}
}

// The command line is the bootstrap and nothing else: no parameter, so no
// secret, ever reaches a process list.
func TestWindowsCommandIsTheBootstrapAlone(t *testing.T) {
	cmd := winCommand()
	const pre = "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand "
	if !strings.HasPrefix(cmd, pre) {
		t.Fatalf("%s", cmd)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(cmd, pre))
	if err != nil || len(raw)%2 != 0 {
		t.Fatalf("%v", err)
	}
	u := make([]uint16, len(raw)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	if got := string(utf16.Decode(u)); got != winBootstrap {
		t.Fatalf("decoded %q", got)
	}
}

// The payload carries the script and its params as JSON; the result is the
// last line of output, or the error the script threw.
func TestWindowsPayloadAndResult(t *testing.T) {
	b, err := winPayload("param($a) @{ b = $a }", map[string]any{"a": "x"})
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Script string         `json:"script"`
		Params map[string]any `json:"params"`
	}
	if json.Unmarshal(b, &p) != nil || p.Script == "" || p.Params["a"] != "x" {
		t.Fatalf("%s", b)
	}
	if r, err := winResult([]byte("noise\r\n{\"b\":\"x\"}\r\n")); err != nil || string(r) != `{"b":"x"}` {
		t.Fatalf("%s %v", r, err)
	}
	if _, err := winResult([]byte(`{"error":"Access is denied."}`)); err == nil || err.Error() != "Access is denied." {
		t.Fatalf("%v", err)
	}
	if _, err := winResult([]byte("\r\n")); err == nil {
		t.Fatal("no output read as a result")
	}
}

func TestWindowsScrub(t *testing.T) {
	got := winScrub("ktpass -pass Aa1!s3cret failed for Aa1!s3cret; dsrm Aa1!other", "Aa1!s3cret", "", "Aa1!other")
	if strings.Contains(got, "s3cret") || strings.Contains(got, "other") || !strings.Contains(got, "<secret>") {
		t.Fatalf("%s", got)
	}
}

// The ISO is the pinned one by size and SHA-256, or it is refused.
func TestWindowsISOCheck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.iso")
	if err := os.WriteFile(p, []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("abc"))
	good := hex.EncodeToString(sum[:])
	if err := winISOOK(p, 3, good); err != nil {
		t.Fatalf("the right file refused: %v", err)
	}
	if winISOOK(p, 4, good) == nil || winISOOK(p, 3, strings.Repeat("0", 64)) == nil || winISOOK(p+"x", 3, good) == nil {
		t.Fatal("a wrong size, a wrong sum or a missing file accepted")
	}
}

func TestWindowsQuote(t *testing.T) {
	for in, want := range map[string]string{
		"plain": "plain", "a,b": `"a,b"`, `say "hi"`: `"say ""hi"""`, " lead": `" lead"`, "trail ": `"trail "`,
		"a+b": `"a+b"`, "a=b": `"a=b"`, "a#b": `"a#b"`, "a;b": `"a;b"`, "a<b": `"a<b"`, "a>b": `"a>b"`, `a\b`: `"a\b"`, "": `""`,
	} {
		if got := winQuote(in); got != want {
			t.Errorf("winQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// Each offered form differs from port49's in the one respect it names, and
// the lab's reading of the issuer is port49's own.
func TestWindowsAltSecForms(t *testing.T) {
	now := time.Now()
	ca, caKey, err := winCommaCA(now)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := winPersonCert(ca, caKey, "alice", "alice@corp.example.com", new(big.Int).SetBytes([]byte{0x80, 0x01, 0x02}), now)
	if err != nil {
		t.Fatal(err)
	}
	const issuer = "DC=com,DC=example,DC=corp,CN=lab-users, comma-CA"
	for name, tc := range map[string]struct {
		f    func(*x509.Certificate) (string, error)
		want string
	}{
		"port49":     {winForm{}.of, "X509:<I>" + issuer + "<SR>020180"},
		"forward":    {winAltSecForward, "X509:<I>CN=lab-users, comma-CA,DC=corp,DC=example,DC=com<SR>020180"},
		"unreversed": {winAltSecUnreversed, "X509:<I>" + issuer + "<SR>800102"},
		"quoted":     {winAltSecQuoted, `X509:<I>DC=com,DC=example,DC=corp,CN="lab-users, comma-CA"<SR>020180`},
		"signbyte":   {winAltSecSignByte, "X509:<I>" + issuer + "<SR>02018000"},
	} {
		if got, err := tc.f(c); err != nil || got != tc.want {
			t.Errorf("%s: %q %v, want %q", name, got, err, tc.want)
		}
	}
	if got, _ := (winForm{}).of(c); got != directory.ADIssuerSerial(c) {
		t.Errorf("the lab's port49 form %q is not directory.ADIssuerSerial's %q", got, directory.ADIssuerSerial(c))
	}
}

// The UPN SAN reads back through port49's own san_upn lookup.
func TestWindowsUPNExtensionReadsBack(t *testing.T) {
	p, err := writeDirectoryPKI(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, key, err := winPersonCert(p.usersCA, p.usersKey, "alice", "alice@corp.example.com", winHighBitSerial(), time.Now())
	if err != nil || key.N.BitLen() != 2048 {
		t.Fatalf("%v", err)
	}
	l, err := directory.Mapping{Kind: directory.MapSANUPN, Attribute: "userPrincipalName"}.Lookup(c, "(objectClass=user)")
	if err != nil || !strings.Contains(l.Filter, "alice@corp.example.com") {
		t.Fatalf("%+v %v", l, err)
	}
	if _, err := directory.SIDOf(c); err == nil {
		t.Fatal("a person certificate from the harness carries a SID extension")
	}
}

func TestWindowsCSR(t *testing.T) {
	b, key, err := winCSR("alice", "alice@corp.example.com")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := parseCSR(b)
	if err != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != "alice" || key.N.BitLen() != 2048 {
		t.Fatalf("%v", err)
	}
	found := false
	for _, e := range csr.Extensions {
		found = found || e.Id.Equal(oidWinSAN)
	}
	if !found {
		t.Fatal("the request carries no SAN")
	}
}

// The DC's LDAPS certificate is signed by the lab CA for the names the lab's
// URIs and the DC use, on the key the DC generated.
func TestWindowsSignServerCSR(t *testing.T) {
	p, err := writeDirectoryPKI(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b, key, err := winCSR(winDCHost, "")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := p.signServerCSR(b, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := parsePEMCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"localhost", winDCHost, "127.0.0.1"} {
		if _, err := c.Verify(x509.VerifyOptions{Roots: p.ca.Pool(), DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if !key.PublicKey.Equal(c.PublicKey) {
		t.Error("the certificate is not on the request's key")
	}
}

func TestWindowsHighBitSerial(t *testing.T) {
	s := winHighBitSerial().Bytes()
	if len(s) != 9 || s[0]&0x80 == 0 {
		t.Fatalf("% x", s)
	}
}

func TestWindowsParseKinit(t *testing.T) {
	ok := "[7] 1.2: Received error from KDC: -1765328359/Additional pre-authentication required\nlab: kinit exit 0\n" +
		"Ticket cache: FILE:/tmp/krb5cc_0\n  krbtgt/CORP.EXAMPLE.COM@CORP.EXAMPLE.COM\n"
	if r := parseKinit(ok); !r.ok || r.kdcSaid() != "—" {
		t.Fatalf("%+v %q", r, r.kdcSaid())
	}
	bad := "[7] 1.2: Received error from KDC: -1765328359/Additional pre-authentication required\n" +
		"[7] 1.3: Received error from KDC: -1765328360/Preauthentication failed\n" +
		"kinit: Preauthentication failed while getting initial credentials\nlab: kinit exit 1\nklist: No credentials cache found\n"
	r := parseKinit(bad)
	if r.ok || !strings.Contains(r.kdcSaid(), "-1765328360/Preauthentication failed") || strings.Contains(r.kdcSaid(), "-1765328359") ||
		!strings.Contains(r.kdcSaid(), "kinit: Preauthentication failed") {
		t.Fatalf("%+v %q", r, r.kdcSaid())
	}
}

func TestWindowsPKINITConf(t *testing.T) {
	c := winPKINITConf(winKDCInNet)
	for _, want := range []string{"default_realm = CORP.EXAMPLE.COM", "kdc = 172.30.44.10:88", "pkinit_anchors = FILE:/l44/adcs-root.pem",
		"pkinit_kdc_hostname = dc1.corp.example.com"} {
		if !strings.Contains(c, want) {
			t.Errorf("lacks %q", want)
		}
	}
}

func TestWindowsJudges(t *testing.T) {
	for id, want := range map[int]bool{19: true, 21: true, 29: true, 39: false, 40: false, 41: false, 48: false, 49: false} {
		if winKDCPrecondition(id) != want {
			t.Errorf("event %d", id)
		}
	}
	now := time.Now()
	if !winSkewOK(now.Add(59*time.Second), now, time.Minute) || winSkewOK(now.Add(-61*time.Second), now, time.Minute) {
		t.Error("skew")
	}
	created := now.Add(-time.Hour)
	young := &x509.Certificate{NotBefore: now.Add(-time.Minute)}
	old := &x509.Certificate{NotBefore: now.Add(-2 * time.Hour)}
	if winIssuedAfter(created, young) != nil || winIssuedAfter(created, young, old) == nil {
		t.Error("backdating")
	}
	if !winOnlyValue([]string{"X509:<I>A<SR>01"}, "x509:<i>a<sr>01") || winOnlyValue([]string{"a", "b"}, "a") ||
		!winOnlyValue(nil, "") || winOnlyValue([]string{"a"}, "") {
		t.Error("winOnlyValue")
	}
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test -tags lab ./tests/lab/ -run '^TestWindows' -count=1`

Expected: a build failure, because `newWinSecrets`, `winCommand` and the other names are undefined.

- [ ] **Step 3: Implement** `tests/lab/windows_test.go`:

```go
//go:build lab

package lab

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf16"
)

// The Windows Server AD lab (L44): Windows Server 2025 Standard Evaluation as a
// KVM VM in dockur/windows on its own compose project, the first DC of
// corp.example.com, set up over SSH by the PowerShell scripts in
// directory/windows/scripts and measured by port49's own client and by MIT
// kinit's PKINIT.
const (
	platWindows = "windows_ad"
	winProject  = "port49labwin"
	// winImage is dockur/windows v6.06 (source commit 013ea27498e0), by digest.
	winImage = "dockurr/windows:6.06@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea"
	// The Windows Server 2025 evaluation ISO, build 26100.32230 (January 2026):
	// Microsoft's URL, as dockur's define.sh names it, and its size and SHA-256.
	winISOURL    = "https://software-static.download.prss.microsoft.com/dbazure/998969d5-f34g-4e03-ac9d-1f9786c66749/26100.32230.260111-0550.lt_release_svc_refresh_SERVER_EVAL_x64FRE_en-us.iso"
	winISOSHA256 = "7b052573ba7894c9924e3e87ba732ccd354d18cb75a883efa9b900ea125bfd51"
	winISOSize   = 8152356864

	winSSH      = "127.0.0.1:30022"  // the VM's sshd, published on loopback
	winKDC      = "127.0.0.1:30088"  // the KDC, for port49's GSSAPI
	winKDCInNet = "172.30.44.10:88"  // the KDC as the pkinit container reaches it
	winDCHost   = "dc1.corp.example.com"
	winCAName   = "corp-L44-CA"
)

// winSecrets is every password the DC is built with, generated for the run.
// It prints as its key names only, so no format verb can leak a value.
type winSecrets struct {
	AdminPassword string `json:"admin_password"` // the local, then the domain, Administrator's: dockur's PASSWORD
	DSRMPassword  string `json:"dsrm_password"`  // Directory Services Restore Mode
}

func (s *winSecrets) String() string             { return "windows secrets: admin_password, dsrm_password" }
func (s *winSecrets) GoString() string           { return s.String() }
func (s *winSecrets) Format(f fmt.State, _ rune) { fmt.Fprint(f, s.String()) }
func (s *winSecrets) all() []string              { return []string{s.AdminPassword, s.DSRMPassword} }

// winPassword is a password Windows' complexity rule accepts: the four
// classes first, then 24 random hex digits.
func winPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "Aa1!" + hex.EncodeToString(b), nil
}

func newWinSecrets() (*winSecrets, error) {
	a, err := winPassword()
	if err != nil {
		return nil, err
	}
	d, err := winPassword()
	if err != nil {
		return nil, err
	}
	return &winSecrets{AdminPassword: a, DSRMPassword: d}, nil
}

// winEnv is windows.env, the file compose hands dockur: the account Setup
// makes and the password it and the built-in Administrator get.
func winEnv(s *winSecrets) string { return "USERNAME=Docker\nPASSWORD=" + s.AdminPassword + "\n" }

// winBootstrap is the one command the SSH session runs. It reads
// {"script": ..., "params": {...}} from stdin, runs the script with the params
// splatted, and writes its result as one line of JSON, or {"error": ...} and
// exit 1. Params, secrets included, travel on stdin only.
const winBootstrap = `$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
  $in = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $p = @{}
  if ($in.params) { $in.params.psobject.Properties | ForEach-Object { $p[$_.Name] = $_.Value } }
  $r = & ([scriptblock]::Create($in.script)) @p
  [Console]::Out.WriteLine((ConvertTo-Json -InputObject $r -Depth 8 -Compress))
} catch {
  [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ error = $_.Exception.Message } -Compress))
  exit 1
}`

// winCommand is the bootstrap as powershell.exe's -EncodedCommand takes it:
// UTF-16LE, base64.
func winCommand() string {
	u := utf16.Encode([]rune(winBootstrap))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return "powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " +
		base64.StdEncoding.EncodeToString(b)
}

// winPayload is the stdin document for script with params.
func winPayload(script string, params map[string]any) ([]byte, error) {
	return json.Marshal(struct {
		Script string         `json:"script"`
		Params map[string]any `json:"params"`
	}{script, params})
}

// winResult reads the bootstrap's answer, the last non-empty line: the
// script's result, or the error it threw.
func winResult(out []byte) (json.RawMessage, error) {
	var line string
	for _, l := range strings.Split(strings.ReplaceAll(string(out), "\r\n", "\n"), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			line = s
		}
	}
	if line == "" {
		return nil, errors.New("the script wrote nothing")
	}
	var e struct {
		Error *string `json:"error"`
	}
	if json.Unmarshal([]byte(line), &e) == nil && e.Error != nil {
		return nil, errors.New(*e.Error)
	}
	if !json.Valid([]byte(line)) {
		return nil, fmt.Errorf("the script's last line is not JSON (%d bytes)", len(line))
	}
	return json.RawMessage(line), nil
}

// winScrub replaces every secret in s with <secret>: what a failed step's
// text may carry before it reaches a log, a t.Fatalf or a file.
func winScrub(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, "<secret>")
		}
	}
	return s
}

// winISOOK reports whether path is the pinned ISO: its size, then its SHA-256.
func winISOOK(path string, size int64, sum string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() != size {
		return fmt.Errorf("%s is %d bytes, want %d", path, fi.Size(), size)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fmt.Errorf("%s has SHA-256 %s, want %s", path, got, sum)
	}
	return nil
}

// winRDNTypes names the attribute types a CA's subject in this lab carries,
// as port49's ADIssuerSerial and Windows both write them.
var winRDNTypes = map[string]string{"2.5.4.3": "CN", "0.9.2342.19200300.100.1.25": "DC", "2.5.4.10": "O", "2.5.4.11": "OU",
	"2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "S"}

// winRDNs is a DER name's (type, value) pairs, most significant first.
func winRDNs(raw []byte) ([][2]string, error) {
	var seq pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &seq); err != nil || len(rest) > 0 {
		return nil, errors.New("a malformed name")
	}
	var out [][2]string
	for _, rdn := range seq {
		for _, atv := range rdn {
			name, ok := winRDNTypes[atv.Type.String()]
			if !ok {
				name = "OID." + atv.Type.String()
			}
			out = append(out, [2]string{name, fmt.Sprint(atv.Value)})
		}
	}
	return out, nil
}

// winQuote is an RDN value as CertNameToStr (CERT_X500_NAME_STR) writes it:
// quoted when it is empty, starts or ends with white space, or holds
// , + = " \ < > # ; or a newline, an inner quote doubled (Microsoft's
// CertNameToStrW reference).
func winQuote(v string) string {
	if v == "" || strings.ContainsAny(v, ",+=\"\\<>#;\n") || strings.TrimSpace(v) != v {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}

// winForm is an altSecurityIdentities X509IssuerSerialNumber value with each
// way it may differ from port49's own: the zero winForm is port49's form.
type winForm struct{ forward, quoted, unreversed, signByte bool }

func (f winForm) of(c *x509.Certificate) (string, error) {
	rdns, err := winRDNs(c.RawIssuer)
	if err != nil {
		return "", err
	}
	if f.forward {
		slices.Reverse(rdns)
	}
	parts := make([]string, len(rdns))
	for i, r := range rdns {
		v := r[1]
		if f.quoted {
			v = winQuote(v)
		}
		parts[i] = r[0] + "=" + v
	}
	b := c.SerialNumber.Bytes()
	if f.signByte && len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	if !f.unreversed {
		b = slices.Clone(b)
		slices.Reverse(b)
	}
	return "X509:<I>" + strings.Join(parts, ",") + "<SR>" + strings.ToUpper(hex.EncodeToString(b)), nil
}

// The forms the DC is offered beside port49's, each differing in one respect.
var (
	winAltSecForward    = winForm{forward: true}.of    // the issuer least significant RDN first, as Windows' UI prints it
	winAltSecUnreversed = winForm{unreversed: true}.of // the serial in certificate byte order
	winAltSecQuoted     = winForm{quoted: true}.of     // values quoted as CertNameToStr quotes them
	winAltSecSignByte   = winForm{signByte: true}.of   // the serial with its DER sign byte
)

var (
	oidWinSAN = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidWinUPN = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

// winUPNExtension is a subjectAltName holding one UPN otherName, a
// UTF8String, as AD CS writes it.
func winUPNExtension(upn string) (pkix.Extension, error) {
	inner, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		return pkix.Extension{}, err
	}
	other, err := asn1.Marshal(struct {
		ID    asn1.ObjectIdentifier
		Value asn1.RawValue
	}{oidWinUPN, asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner}})
	if err != nil {
		return pkix.Extension{}, err
	}
	other[0] = 0xa0 // [0] IMPLICIT, constructed: the GeneralName otherName choice
	names, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: other})
	return pkix.Extension{Id: oidWinSAN, Value: names}, err
}

// winCSR is a PKCS #10 request for cn, with a UPN SAN when upn is not "", on
// a new RSA-2048 key. RSA, because the User template and MIT's PKINIT client
// both take it, and the key type is no part of L44's claim.
func winCSR(cn, upn string) ([]byte, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	if upn != "" {
		ext, err := winUPNExtension(upn)
		if err != nil {
			return nil, nil, err
		}
		tmpl.ExtraExtensions = []pkix.Extension{ext}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), key, nil
}

func parseCSR(b []byte) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificateRequest(blk.Bytes)
}

func parsePEMCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func pemKey(k *rsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// signServerCSR is the DC's LDAPS certificate: the lab CA signs the key the
// DC generated, for the names the lab's URIs and the DC itself use, whatever
// the request asked for.
func (p *dirPKI) signServerCSR(csrPEM []byte, now time.Time) ([]byte, error) {
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: dirSerial(), Subject: pkix.Name{CommonName: winDCHost},
		DNSNames: []string{"localhost", winDCHost}, IPAddresses: testpkiLoopback(), NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.ca.Cert, csr.PublicKey, p.ca.Key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// winCommaCA is a CA named CN=lab-users\, comma-CA,DC=corp,DC=example,DC=com,
// written in DER most significant first: plan 7g's carried question, whether a
// Windows DC wants a `,` in <I> quoted.
func winCommaCA(now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	raw, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: oidDirDC, Value: "com"}}, {{Type: oidDirDC, Value: "example"}}, {{Type: oidDirDC, Value: "corp"}},
		{{Type: oidDirCN, Value: "lab-users, comma-CA"}}})
	if err != nil {
		return nil, nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), RawSubject: raw, NotBefore: now.Add(-time.Hour),
		NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

// winPersonCert is a client certificate for a person from parent: RSA-2048,
// clientAuth, a UPN SAN, NotBefore a minute ago (after the account exists:
// KB5014754's backdating check is no part of the claim), with serial.
func winPersonCert(parent *x509.Certificate, signer crypto.Signer, cn, upn string, serial *big.Int, now time.Time) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	ext, err := winUPNExtension(upn)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: cn}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: []pkix.Extension{ext}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

// winHighBitSerial is a 9-byte serial whose top bit is set: DER encodes it
// with a leading 00, and the question is whether <SR> keeps it.
func winHighBitSerial() *big.Int {
	b := make([]byte, 9)
	_, _ = rand.Read(b)
	b[0] |= 0x80
	return new(big.Int).SetBytes(b)
}

// pkinitResult is one kinit: whether the KDC issued a TGT and, if not, what
// it said, from MIT's trace and kinit's own last line.
type pkinitResult struct {
	ok      bool
	kdcErrs []string // "<code>/<text>" from each "Received error from KDC", in order
	last    string   // kinit's own last line
	took    time.Duration
}

var kdcErrRe = regexp.MustCompile(`Received error from KDC: (-?\d+/[^\r\n]*)`)

// preauthRequired is the KDC's ordinary first answer to an AS-REQ, on
// success too.
const preauthRequired = "-1765328359/"

func parseKinit(out string) pkinitResult {
	r := pkinitResult{ok: strings.Contains(out, "lab: kinit exit 0") && strings.Contains(out, "krbtgt/"+dirRealm+"@"+dirRealm)}
	for _, m := range kdcErrRe.FindAllStringSubmatch(out, -1) {
		r.kdcErrs = append(r.kdcErrs, oneLineMax(m[1], 160))
	}
	for _, line := range strings.Split(out, "\n") {
		if s := strings.TrimSpace(line); strings.HasPrefix(s, "kinit: ") {
			r.last = oneLineMax(s, 200)
		}
	}
	return r
}

// kdcSaid is what a cell shows: the KDC's errors past the ordinary first
// one, and kinit's last line on a failure; "—" when there is nothing.
func (r pkinitResult) kdcSaid() string {
	var parts []string
	for _, e := range r.kdcErrs {
		if !strings.HasPrefix(e, preauthRequired) {
			parts = append(parts, e)
		}
	}
	if !r.ok && r.last != "" {
		parts = append(parts, r.last)
	}
	if len(parts) == 0 {
		return "—"
	}
	return strings.Join(parts, "; ")
}

// winPKINITConf is the PKINIT client's krb5.conf: the realm's KDC on the
// project network, AD CS's root as the anchor, and pkinit_kdc_hostname, the
// one setting MIT's documentation names for an Active Directory KDC.
func winPKINITConf(kdc string) string {
	return fmt.Sprintf(`[libdefaults]
  default_realm = %[1]s
  dns_lookup_kdc = false
  dns_lookup_realm = false
  udp_preference_limit = 1

[realms]
  %[1]s = {
    kdc = %[2]s
    pkinit_anchors = FILE:/l44/adcs-root.pem
    pkinit_kdc_hostname = %[3]s
  }
`, dirRealm, kdc, winDCHost)
}

// winEvent is one event the DC logged.
type winEvent struct {
	ID       int    `json:"id"`
	Provider string `json:"provider"`
	Time     string `json:"time"`
	Message  string `json:"message"`
}

// winKDCPrecondition reports whether a KDC event says the run's setup failed
// rather than the mapping: 19 and 29 (the KDC has no certificate for PKINIT)
// and 21 (the client certificate did not validate: its chain or revocation).
func winKDCPrecondition(id int) bool { return id == 19 || id == 21 || id == 29 }

// winSkewOK reports whether the DC's clock is within limit of ours: past five
// minutes Kerberos refuses everything, and a skewed run would read that as a
// mapping's verdict.
func winSkewOK(dc, host time.Time, limit time.Duration) bool {
	d := dc.Sub(host)
	return d <= limit && d >= -limit
}

// winIssuedAfter is an error naming each certificate whose NotBefore is not
// after created, alice's whenCreated.
func winIssuedAfter(created time.Time, certs ...*x509.Certificate) error {
	var bad []string
	for _, c := range certs {
		if !c.NotBefore.After(created) {
			bad = append(bad, fmt.Sprintf("%q from %s", c.Subject.CommonName, c.NotBefore.UTC().Format(time.RFC3339)))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("certificates that predate the account (%s): %s", created.UTC().Format(time.RFC3339), strings.Join(bad, ", "))
	}
	return nil
}

// winOnlyValue reports whether vals is exactly want (none when want is ""),
// compared as AD compares altSecurityIdentities, case-insensitively.
func winOnlyValue(vals []string, want string) bool {
	if want == "" {
		return len(vals) == 0
	}
	return len(vals) == 1 && strings.EqualFold(vals[0], want)
}
```

Add `func testpkiLoopback() []net.IP { return testpki.Loopback() }` with its imports
(`net`, `internal/testpki`). The helper keeps the pure file's dependency explicit.

Delete Task 1's `const platWindows = "windows_ad"` from `directory_test.go`.

- [ ] **Step 4: Run them and see them pass**

Run: `go test -tags lab ./tests/lab/ -run '^TestWindows' -count=1 -v 2>&1 | tail -30 && make lab-unit && go vet -tags lab ./tests/lab/`

Expected: every `TestWindows*` PASSes, `make lab-unit` passes, and vet is silent.

- [ ] **Step 5: Commit**

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add tests/lab/windows_test.go tests/lab/windows_unit_test.go tests/lab/directory_test.go
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "test(lab): the Windows DC's pure helpers for L44

Secrets that print as key names, a PowerShell bootstrap that takes its
params on stdin, the ISO check, the altSecurityIdentities forms the DC is
offered beside port49's, the CSRs and certificates, MIT kinit's answer read
from its trace, and the judges that keep a setup failure from reading as a
mapping's verdict.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 3: The compose project, the first-logon hook, the PKINIT image and the scripts

**Files:**
- Create: `tests/lab/directory/windows/compose.yaml`, `tests/lab/directory/windows/oem/install.bat`,
  `tests/lab/directory/windows/pkinit/Dockerfile`
- Create: `tests/lab/directory/windows/scripts/{promote,ready,seed,reset,adcs,ldaps,keytab,trust,issue,enroll_as,set_attr,registry,events,facts,clock}.ps1`
- Modify: `tests/lab/windows_test.go` (`winScripts`, `winSecretParams`, `winScriptFS`)
- Test: `tests/lab/windows_unit_test.go`

**Interfaces:**
- Consumes: Task 2's constants.
- Produces:
  - `var winScriptFS embed.FS`, with every `directory/windows/scripts/*.ps1`.
  - `var winScripts map[string][]string`: each script's parameter names, in order.
  - `var winSecretParams []string`.
  - Each script's JSON result (keys below), which Task 4 reads.

- [ ] **Step 1: Write the failing tests** (append to `tests/lab/windows_unit_test.go`, and add
`"regexp"` and `"slices"` to its imports)

```go
// The DC's image is pinned by digest, the ISO is mounted read-only from the
// verified cache, and every published port is on loopback.
func TestWindowsComposePinsTheImage(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("directory", "windows", "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, "image: "+winImage+"\n") || !strings.Contains(s, ":/custom.iso:ro") {
		t.Fatal("compose.yaml does not pin the image or mount the ISO read-only")
	}
	for _, line := range strings.Split(s, "\n") {
		if m := regexp.MustCompile(`^\s+- "(\S+)"$`).FindStringSubmatch(line); m != nil && regexp.MustCompile(`^\d`).MatchString(m[1]) {
			if !strings.HasPrefix(m[1], "127.0.0.1:") {
				t.Errorf("a port published beyond loopback: %s", m[1])
			}
		}
	}
}

var (
	psParamRe = regexp.MustCompile(`(?m)^param\(([^)]*)\)\s*$`)
	psNameRe  = regexp.MustCompile(`\$([a-z_]+)`)
)

// Every script is in winScripts with the params its param() block declares,
// in order, and stops on its first error.
func TestWindowsScriptsTakeTheirParams(t *testing.T) {
	ents, err := winScriptFS.ReadDir("directory/windows/scripts")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, e := range ents {
		name := strings.TrimSuffix(e.Name(), ".ps1")
		src, _ := winScriptFS.ReadFile("directory/windows/scripts/" + e.Name())
		want, ok := winScripts[name]
		if !ok {
			t.Errorf("%s is not in winScripts", name)
			continue
		}
		seen[name] = true
		m := psParamRe.FindSubmatchIndex(src)
		if m == nil {
			t.Errorf("%s: no param() line", name)
			continue
		}
		var got []string
		for _, n := range psNameRe.FindAllStringSubmatch(string(src[m[2]:m[3]]), -1) {
			got = append(got, n[1])
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s declares %v, winScripts says %v", name, got, want)
		}
		if !strings.HasPrefix(strings.TrimLeft(string(src[m[1]:]), "\r\n"), "$ErrorActionPreference = 'Stop'") {
			t.Errorf("%s: the line after param() is not $ErrorActionPreference = 'Stop'", name)
		}
	}
	for name := range winScripts {
		if !seen[name] {
			t.Errorf("winScripts names %s, which has no script", name)
		}
	}
}

// No script writes a secret parameter anywhere: not to the output, a file or
// an exception's text.
func TestWindowsScriptsNeverEchoASecret(t *testing.T) {
	ents, _ := winScriptFS.ReadDir("directory/windows/scripts")
	echo := regexp.MustCompile(`(?i)write-|out-file|set-content|add-content|\bthrow\b|\becho\b`)
	for _, e := range ents {
		src, _ := winScriptFS.ReadFile("directory/windows/scripts/" + e.Name())
		for i, line := range strings.Split(string(src), "\n") {
			for _, p := range winSecretParams {
				v := "$" + p
				if !strings.Contains(line, v) || strings.HasPrefix(strings.TrimSpace(line), "param(") {
					continue
				}
				if echo.MatchString(line) || regexp.MustCompile(`"[^"]*`+regexp.QuoteMeta(v)).MatchString(line) {
					t.Errorf("%s:%d writes or interpolates %s", e.Name(), i+1, v)
				}
			}
		}
	}
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test -tags lab ./tests/lab/ -run '^TestWindows(Compose|Scripts)' -count=1`

Expected: a build failure (`winScriptFS`, `winScripts` and `winSecretParams` are undefined).

- [ ] **Step 3: Write `tests/lab/directory/windows/compose.yaml`**

```yaml
# The Windows Server AD lab (L44): Windows Server 2025 Standard Evaluation as a
# KVM VM inside dockur/windows, the first DC of corp.example.com, on a network
# of its own. Run from tests/lab/windows_test.go, which verifies the ISO and
# writes windows.env (the Administrator's password, 0600) and compose.env (the
# ISO's path) under tests/lab/logs/windows (git-ignored) first. Never run
# `docker compose config` or `docker inspect` on this project: both print the
# environment, and it holds the password.
name: port49labwin

services:
  dc:
    image: dockurr/windows:6.06@sha256:16fd7c39a3e48bb946d29c59dc6015942e5b900a1fa5d7e5552053bfc48ee2ea
    environment:
      HOST: DC1
      RAM_SIZE: 6G
      CPU_CORES: "4"
      DISK_SIZE: 64G
      SAMBA: "N"
    env_file:
      - path: ../../logs/windows/windows.env
        required: true
    devices:
      - /dev/kvm
      - /dev/net/tun
    cap_add:
      - NET_ADMIN
    ports:
      - "127.0.0.1:8006:8006"
      - "127.0.0.1:30022:22"
      - "127.0.0.1:30088:88/tcp"
      - "127.0.0.1:30389:389"
      - "127.0.0.1:30636:636"
    volumes:
      - storage:/storage
      - ${PORT49_LAB_WINDOWS_ISO:?the harness sets the verified ISO's path}:/custom.iso:ro
      - ./oem:/oem:ro
    stop_grace_period: 2m
    networks:
      lab:
        ipv4_address: 172.30.44.10

  # MIT kinit with PKINIT, run once per certificate by the test.
  pkinit:
    build: ./pkinit
    image: port49lab/pkinit:bookworm
    profiles: [tools]
    volumes:
      - ../../logs/windows/pkinit:/l44:ro
    networks:
      lab: {}

volumes:
  storage:

networks:
  lab:
    ipam:
      config:
        - subnet: 172.30.44.0/24
```

`tests/lab/directory/windows/oem/install.bat` (dockur copies `oem/` to `C:\OEM` and runs this at
the first logon, as the setup account, with UAC off):

```bat
@echo off
rem L44 (tests/lab/directory/windows): what the harness needs before it can
rem reach this VM. OpenSSH Server, which Windows Server 2025 installs stopped,
rem started and automatic; the firewall off, because the VM is reached only
rem through the container's ports published on the host's loopback; and
rem Windows Update off, so the build the run measures is the one the pinned
rem ISO installed.
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Set-NetFirewallProfile -All -Enabled False; Set-Service sshd -StartupType Automatic; Start-Service sshd; New-Item -Force -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' | Out-Null; Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate -Value 1 -Type DWord; Stop-Service wuauserv -Force; Set-Service wuauserv -StartupType Disabled"
echo lab: windows ready> C:\OEM\l44-ready.txt
```

`tests/lab/directory/windows/pkinit/Dockerfile`:

```dockerfile
# MIT Kerberos's kinit with the PKINIT plugin (L44): the client that asks the
# Windows DC's KDC for a TGT with a certificate, so the DC's own mapping
# (KB5014754) is what answers. Debian bookworm, pinned by digest.
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      krb5-user krb5-pkinit ca-certificates && rm -rf /var/lib/apt/lists/*
```

- [ ] **Step 4: Write the fifteen scripts** in `tests/lab/directory/windows/scripts/`

Rules for every script:
- The first non-comment line is `param(...)` on one line.
- The next line is `$ErrorActionPreference = 'Stop'`.
- Every native command's output goes to `Out-Null` or `$null`, and its `$LASTEXITCODE` is checked.
- The script ends with one hashtable, which is its result. Nothing else reaches the pipeline.

`clock.ps1`:

```powershell
# L44: the DC's clock, for the skew check and as the "since" of an events read.
param()
$ErrorActionPreference = 'Stop'
@{ utc_now = [DateTime]::UtcNow.ToString('o') }
```

`promote.ps1`:

```powershell
# L44: promote the VM to the first DC of a new forest, corp.example.com, with
# this build's defaults. The DSRM password arrives on stdin and is never printed.
param([string]$dsrm_password)
$ErrorActionPreference = 'Stop'
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { return @{ promoted = 'already' } }
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
$dsrm = ConvertTo-SecureString $dsrm_password -AsPlainText -Force
Install-ADDSForest -DomainName 'corp.example.com' -DomainNetbiosName 'CORP' -InstallDns `
  -SafeModeAdministratorPassword $dsrm -NoRebootOnCompletion -Force -WarningAction SilentlyContinue | Out-Null
# The reboot is left to a timer so this session can answer first.
shutdown.exe /r /t 15 /c 'L44: AD DS promotion' | Out-Null
@{ promoted = 'now' }
```

`ready.ps1`:

```powershell
# L44: whether AD DS answers after the promotion's reboot.
param()
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$d = Get-ADDomain
@{ domain_dn = $d.DistinguishedName; pdc = $d.PDCEmulator }
```

`seed.ps1`:

```powershell
# L44: L42's fixture, the shape tests/lab/directory/samba/seed.sh makes: the
# same people, nested groups, loop, shared group name and broker account.
# Passwords are random per account; port49's arrives on stdin.
param([string]$port49_password)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$base = 'DC=corp,DC=example,DC=com'
function New-LabSecret {
  $b = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  ConvertTo-SecureString ('Aa1!' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')) -AsPlainText -Force
}
foreach ($ou in 'Staff', 'Contractors', 'G', 'Users-Can-Create', 'Svc') {
  New-ADOrganizationalUnit -Name $ou -Path $base -ProtectedFromAccidentalDeletion $false
}
function Add-LabUser([string]$name, [string]$ou, [string]$mail) {
  New-ADUser -Name $name -SamAccountName $name -UserPrincipalName "$name@corp.example.com" -EmailAddress $mail `
    -Path "OU=$ou,$base" -AccountPassword (New-LabSecret) -Enabled $true
}
Add-LabUser alice Staff alice@corp.example.com
Add-LabUser carol Staff carol@corp.example.com
Add-LabUser dave Staff dave@corp.example.com
Add-LabUser bob Staff bob@corp.example.com
Add-LabUser eve Staff eve@corp.example.com
Add-LabUser eve2 Contractors eve@corp.example.com
$p49 = ConvertTo-SecureString $port49_password -AsPlainText -Force
New-ADUser -Name port49 -SamAccountName port49 -Path "OU=Svc,$base" -Enabled $true -PasswordNeverExpires $true `
  -AccountPassword $p49 -KerberosEncryptionType AES128,AES256
function Add-LabGroup([string]$name, [string]$ou) {
  New-ADGroup -Name $name -SamAccountName $name -GroupScope Global -GroupCategory Security -Path "OU=$ou,$base"
}
'g-leaf', 'g-mid', 'netops-oncall', 'g-loop-a', 'g-loop-b' | ForEach-Object { Add-LabGroup $_ G }
Add-ADGroupMember g-leaf -Members alice
Add-ADGroupMember g-mid -Members g-leaf
Add-ADGroupMember netops-oncall -Members carol, g-mid
Add-ADGroupMember g-loop-a -Members dave, g-loop-b
$loop = 'made'
try { Add-ADGroupMember g-loop-b -Members g-loop-a } catch { $loop = 'refused: ' + $_.Exception.Message }
# The second netops-oncall: sAMAccountName is unique domain-wide, so it is made
# under another and its CN renamed, as samba/seed.sh does.
Add-LabGroup netops-oncall-uc Users-Can-Create
Rename-ADObject "CN=netops-oncall-uc,OU=Users-Can-Create,$base" -NewName netops-oncall
# port49 binds GSSAPI to ldap/<the URI's host>, and the lab's URI host is localhost.
setspn.exe -S ldap/localhost DC1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "setspn ldap/localhost: exit $LASTEXITCODE" }
@{ loop = $loop; alice_created = (Get-ADUser alice -Properties whenCreated).whenCreated.ToUniversalTime().ToString('o') }
```

`reset.ps1`:

```powershell
# L44: what every run sets, on a fresh DC or a kept one: port49's password
# (this run's), alice's altSecurityIdentities (port49's form for the run's
# users-CA certificate, as samba/seed.sh writes it), bob's mail, no mapping on
# port49, and LDAP interface diagnostics at 2, so the DC logs its bind events.
param([string]$port49_password, [string]$alice_altsecid)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$p49 = ConvertTo-SecureString $port49_password -AsPlainText -Force
Set-ADAccountPassword port49 -Reset -NewPassword $p49
Set-ADUser alice -Replace @{ altSecurityIdentities = $alice_altsecid }
Set-ADUser bob -EmailAddress 'bob@corp.example.com'
Set-ADUser port49 -Clear altSecurityIdentities
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics' -Name '16 LDAP Interface Events' `
  -PropertyType DWord -Value 2 -Force | Out-Null
@{ reset = $true }
```

`adcs.ps1`:

```powershell
# L44: an enterprise root CA on the DC, so the DC maps certificates it issued
# (KB5014754's SID extension included); OfflineRouter published, for requests
# whose subject the harness supplies; and the DC's KerberosAuthentication
# certificate, which PKINIT needs. Idempotent: a kept DC answers the same.
param()
$ErrorActionPreference = 'Stop'
function ConvertTo-Pem($raw) {
  "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($raw, 'InsertLineBreaks') + "`n-----END CERTIFICATE-----`n"
}
if (-not (Get-Service CertSvc -ErrorAction SilentlyContinue)) {
  Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools | Out-Null
  Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName 'corp-L44-CA' `
    -CryptoProviderName 'RSA#Microsoft Software Key Storage Provider' -KeyLength 2048 -HashAlgorithmName SHA256 `
    -ValidityPeriod Years -ValidityPeriodUnits 1 -Force | Out-Null
}
$deadline = (Get-Date).AddMinutes(5)
while ((Get-Service CertSvc).Status -ne 'Running') {
  if ((Get-Date) -gt $deadline) { throw 'CertSvc did not start' }
  Start-Sleep 5
}
Import-Module ADCSAdministration
if (-not (Get-CATemplate | Where-Object Name -eq 'OfflineRouter')) { Add-CATemplate -Name OfflineRouter -Force }
$kdcEku = '1.3.6.1.5.2.3.5'
function Get-KdcCert {
  Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains $kdcEku } | Select-Object -First 1
}
if (-not (Get-KdcCert)) {
  certreq.exe -enroll -machine -q KerberosAuthentication | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "certreq -enroll KerberosAuthentication: exit $LASTEXITCODE" }
}
$kdc = Get-KdcCert
if (-not $kdc) { throw 'no certificate with the KDC Authentication EKU after enrollment' }
$ca = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like 'CN=corp-L44-CA*' } | Select-Object -First 1
if (-not $ca) { throw 'the enterprise CA certificate is not in the Root store' }
@{ ca_pem = (ConvertTo-Pem $ca.RawData); kdc_pem = (ConvertTo-Pem $kdc.RawData) }
```

`ldaps.ps1`:

```powershell
# L44: LDAPS on a certificate from the lab CA. "request" makes the DC's key
# and a request; "install" trusts the lab CA, accepts the certificate the
# harness signed, and makes it the one LDAPS serves by placing it in the NTDS
# service's own store (Microsoft's procedure for a third-party certificate),
# then asks NTDS to reload it.
param([string]$step, [string]$cert_pem, [string]$lab_ca_pem)
$ErrorActionPreference = 'Stop'
$dir = 'C:\l44'
New-Item -ItemType Directory -Force $dir | Out-Null
if ($step -eq 'request') {
  @(
    '[NewRequest]', 'Subject = "CN=dc1.corp.example.com"', 'KeyAlgorithm = RSA', 'KeyLength = 2048',
    'MachineKeySet = TRUE', 'Exportable = FALSE', 'RequestType = PKCS10',
    '[EnhancedKeyUsageExtension]', 'OID = 1.3.6.1.5.5.7.3.1'
  ) | Set-Content "$dir\ldaps.inf" -Encoding ascii
  Remove-Item "$dir\ldaps.req" -ErrorAction SilentlyContinue
  certreq.exe -new -q -machine "$dir\ldaps.inf" "$dir\ldaps.req" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "certreq -new: exit $LASTEXITCODE" }
  return @{ csr_pem = (Get-Content "$dir\ldaps.req" -Raw) }
}
Set-Content "$dir\lab-ca.cer" $lab_ca_pem -Encoding ascii
certutil.exe -f -addstore Root "$dir\lab-ca.cer" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -addstore Root: exit $LASTEXITCODE" }
Set-Content "$dir\ldaps.cer" $cert_pem -Encoding ascii
certreq.exe -accept -q -machine "$dir\ldaps.cer" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certreq -accept: exit $LASTEXITCODE" }
$t = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 "$dir\ldaps.cer").Thumbprint
$src = "HKLM\SOFTWARE\Microsoft\SystemCertificates\MY\Certificates\$t"
$dst = "HKLM\SOFTWARE\Microsoft\Cryptography\Services\NTDS\SystemCertificates\My\Certificates\$t"
reg.exe copy $src $dst /s /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw "reg copy to the NTDS store: exit $LASTEXITCODE" }
$root = [ADSI]'LDAP://localhost/RootDSE'
$root.Put('renewServerCertificate', 1)
$root.SetInfo()
@{ thumbprint = $t }
```

`keytab.ps1`:

```powershell
# L44: port49's keytab, as an operator makes one with ktpass: AES256, the
# principal port49@CORP.EXAMPLE.COM mapped onto the port49 account. ktpass sets
# the password it is given (this run's, unchanged) and the account's UPN to the
# principal. The keytab leaves as base64 in the result and its file is deleted.
param([string]$port49_password)
$ErrorActionPreference = 'Stop'
$out = Join-Path $env:TEMP ('l44-' + [guid]::NewGuid() + '.keytab')
try {
  & ktpass.exe -princ port49@CORP.EXAMPLE.COM -mapuser 'CORP\port49' -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL `
    -pass $port49_password -mapop set +answer -out $out *> $null
  if ($LASTEXITCODE -ne 0) { throw "ktpass: exit $LASTEXITCODE" }
  @{ keytab_b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($out)) }
} finally {
  Remove-Item $out -ErrorAction SilentlyContinue
}
```

`trust.ps1`:

```powershell
# L44: trust one of the harness's CAs as AD trusts an issuing CA for logon:
# the DC's Root store, NTAuth in the forest, and the DC's cached NTAuth.
param([string]$ca_pem, [string]$name)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force C:\l44 | Out-Null
$f = "C:\l44\$name.cer"
Set-Content $f $ca_pem -Encoding ascii
certutil.exe -f -addstore Root $f | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -addstore Root: exit $LASTEXITCODE" }
certutil.exe -f -dspublish $f NTAuthCA | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -dspublish NTAuthCA: exit $LASTEXITCODE" }
certutil.exe -f -enterprise -addstore NTAuth $f | Out-Null
if ($LASTEXITCODE -ne 0) { throw "certutil -enterprise -addstore NTAuth: exit $LASTEXITCODE" }
@{ trusted = $name }
```

`issue.ps1`:

```powershell
# L44: submit a request the harness made (its key never leaves the host) to
# the enterprise CA under a template, as the Administrator, and return the
# certificate.
param([string]$csr_pem, [string]$template)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force C:\l44 | Out-Null
$id = [guid]::NewGuid()
$in = "C:\l44\$id.req"; $out = "C:\l44\$id.cer"; $rsp = "C:\l44\$id.rsp"
try {
  Set-Content $in $csr_pem -Encoding ascii
  certreq.exe -submit -q -config "$env:COMPUTERNAME.corp.example.com\corp-L44-CA" -attrib "CertificateTemplate:$template" $in $out | Out-Null
  if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { throw "certreq -submit ${template}: exit $LASTEXITCODE" }
  @{ cert_pem = (Get-Content $out -Raw) }
} finally {
  Remove-Item $in, $out, $rsp -ErrorAction SilentlyContinue
}
```

`enroll_as.ps1`:

```powershell
# L44: a certificate for a user from the User template, requested AS that
# user, so the CA builds its subject from the account and writes KB5014754's
# SID extension from it: what an online template issues. The request travels
# over WinRM with CredSSP to this DC, under a session configuration only the
# user may use. The user's password is made here, used once and replaced; it
# never leaves this script. Everything it opens is closed in finally.
param([string]$csr_pem, [string]$user)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
function New-LabPlain {
  $b = New-Object byte[] 12
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
  'Aa1!' + (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}
$fqdn = "$env:COMPUTERNAME.corp.example.com"
$sid = (Get-ADUser $user).SID.Value
$plain = New-LabPlain
$sec = ConvertTo-SecureString $plain -AsPlainText -Force
Set-ADAccountPassword $user -Reset -NewPassword $sec
$cred = New-Object Management.Automation.PSCredential ("CORP\$user", $sec)
$rootSddl = (Get-Item WSMan:\localhost\Service\RootSDDL).Value
$name = 'l44enroll'
try {
  $i = $rootSddl.IndexOf('S:')
  $withUser = if ($i -ge 0) { $rootSddl.Insert($i, "(A;;GXGR;;;$sid)") } else { $rootSddl + "(A;;GXGR;;;$sid)" }
  Set-Item WSMan:\localhost\Service\RootSDDL -Value $withUser -Force
  Enable-WSManCredSSP -Role Server -Force | Out-Null
  Enable-WSManCredSSP -Role Client -DelegateComputer $fqdn -Force | Out-Null
  Register-PSSessionConfiguration -Name $name -SecurityDescriptorSddl "O:NSG:BAD:P(A;;GA;;;BA)(A;;GXGR;;;$sid)" `
    -Force -WarningAction SilentlyContinue | Out-Null
  $deadline = (Get-Date).AddMinutes(2)
  while (-not (Test-WSMan -ComputerName $fqdn -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) { throw 'WinRM did not come back' }
    Start-Sleep 3
  }
  $pem = Invoke-Command -ComputerName $fqdn -ConfigurationName $name -Credential $cred -Authentication Credssp `
    -ArgumentList $csr_pem, "$fqdn\corp-L44-CA" -ScriptBlock {
      param($csr, $config)
      $in = Join-Path $env:TEMP 'l44.req'; $out = Join-Path $env:TEMP 'l44.cer'
      Set-Content $in $csr -Encoding ascii
      certreq.exe -submit -q -config $config -attrib 'CertificateTemplate:User' $in $out | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "certreq -submit User: exit $LASTEXITCODE" }
      Get-Content $out -Raw
    }
  @{ cert_pem = "$pem" }
} finally {
  Unregister-PSSessionConfiguration -Name $name -Force -ErrorAction SilentlyContinue
  Disable-WSManCredSSP -Role Client -ErrorAction SilentlyContinue
  Disable-WSManCredSSP -Role Server -ErrorAction SilentlyContinue
  Set-Item WSMan:\localhost\Service\RootSDDL -Value $rootSddl -Force
  Set-ADAccountPassword $user -Reset -NewPassword (ConvertTo-SecureString (New-LabPlain) -AsPlainText -Force)
}
```

`set_attr.ps1`:

```powershell
# L44: replace one attribute of one entry with values, or clear it when values
# is empty; the values are read back and returned, so the harness asserts
# exactly what it set.
param([string]$dn, [string]$attribute, [string[]]$values)
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$vals = @($values | Where-Object { $_ })
if ($vals.Count -gt 0) { Set-ADObject -Identity $dn -Replace @{ $attribute = [string[]]$vals } }
else { Set-ADObject -Identity $dn -Clear $attribute }
@{ values = @((Get-ADObject -Identity $dn -Properties $attribute).$attribute | ForEach-Object { "$_" }) }
```

`registry.ps1`:

```powershell
# L44: set (or, with value -1, delete) one of the DC settings the run varies,
# restart the service that reads it and its dependents, and return what is in
# force after.
param([string]$name, [int]$value)
$ErrorActionPreference = 'Stop'
$known = @{
  StrongCertificateBindingEnforcement              = @('HKLM:\SYSTEM\CurrentControlSet\Services\Kdc', 'Kdc')
  UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = @('HKLM:\SYSTEM\CurrentControlSet\Services\Kdc', 'Kdc')
  LdapEnforceChannelBinding                        = @('HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters', 'NTDS')
}
if (-not $known.ContainsKey($name)) { throw "not a setting this lab varies: $name" }
$path, $svc = $known[$name]
if ($value -lt 0) { Remove-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue }
else { New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null }
Restart-Service $svc -Force
$deadline = (Get-Date).AddMinutes(3)
foreach ($s in @($svc, 'Kdc', 'NTDS', 'DNS') | Select-Object -Unique) {
  Start-Service $s -ErrorAction SilentlyContinue
  while ((Get-Service $s).Status -ne 'Running') {
    if ((Get-Date) -gt $deadline) { throw "$s did not come back" }
    Start-Sleep 2
  }
}
$now = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
$inForce = if ($null -eq $now) { 'absent' } else { "$now" }
@{ name = $name; value = $inForce; restarted = $svc }
```

`events.ps1`:

```powershell
# L44: what the DC logged since a moment (its own clock): the KDC's events
# (KB5014754's mapping events, and the PKINIT ones that mean the setup
# failed), Schannel's, and Directory Service's LDAP bind and channel-binding
# events. Each message is cut at 600 characters.
param([string]$since)
$ErrorActionPreference = 'Stop'
$t = [DateTime]::Parse($since, $null, [Globalization.DateTimeStyles]::RoundtripKind).ToLocalTime()
$filters = @(
  @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'; StartTime = $t },
  @{ LogName = 'System'; ProviderName = 'Kerberos-Key-Distribution-Center'; StartTime = $t },
  @{ LogName = 'System'; ProviderName = 'KDC'; StartTime = $t },
  @{ LogName = 'System'; ProviderName = 'Schannel'; StartTime = $t },
  @{ LogName = 'Directory Service'; StartTime = $t; Id = 1220, 2886, 2887, 2888, 2889, 3039, 3074, 3075 }
)
$out = @()
foreach ($f in $filters) {
  $out += @(Get-WinEvent -FilterHashtable $f -ErrorAction SilentlyContinue | ForEach-Object {
    $m = "$($_.Message)" -replace '\s+', ' '
    @{ id = $_.Id; provider = $_.ProviderName; time = $_.TimeCreated.ToUniversalTime().ToString('o');
       message = $m.Substring(0, [Math]::Min(600, $m.Length)) }
  })
}
@{ events = $out }
```

`facts.ps1`:

```powershell
# L44: what the note records about the DC: the build, its updates, the domain's
# modes, and every setting a cell depends on, as in force now.
param()
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
function Get-Reg([string]$path, [string]$name) {
  $v = (Get-ItemProperty -Path $path -Name $name -ErrorAction SilentlyContinue).$name
  if ($null -eq $v) { 'absent' } else { "$v" }
}
$ldap = @{}
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters').psobject.Properties |
  Where-Object Name -like 'ldap*' | ForEach-Object { $ldap[$_.Name] = "$($_.Value)" }
@{
  caption = $os.Caption; version = $os.Version; build = "$($cv.CurrentBuildNumber).$($cv.UBR)"
  display_version = "$($cv.DisplayVersion)"; edition = "$($cv.EditionID)"
  hotfixes = @(Get-HotFix | ForEach-Object { $_.HotFixID })
  domain_mode = "$((Get-ADDomain).DomainMode)"; forest_mode = "$((Get-ADForest).ForestMode)"
  utc_now = [DateTime]::UtcNow.ToString('o')
  strong_certificate_binding_enforcement = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'StrongCertificateBindingEnforcement'
  certificate_backdating_compensation = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' 'CertificateBackdatingCompensation'
  certificate_mapping_methods = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' 'CertificateMappingMethods'
  ntds_ldap_settings = $ldap
  lockout_threshold = (Get-ADDefaultDomainPasswordPolicy).LockoutThreshold
}
```

- [ ] **Step 5: Register the scripts in `tests/lab/windows_test.go`**

Add the `embed` import, `_ "embed"` style, as `"embed"`:

```go
// winScriptFS holds every setup and measurement step the DC runs.
//
//go:embed directory/windows/scripts/*.ps1
var winScriptFS embed.FS

// winScripts is each script's parameters, in the order its param() names
// them: ps refuses a parameter a script does not declare.
var winScripts = map[string][]string{
	"clock": nil, "promote": {"dsrm_password"}, "ready": nil, "seed": {"port49_password"},
	"reset": {"port49_password", "alice_altsecid"}, "adcs": nil, "ldaps": {"step", "cert_pem", "lab_ca_pem"},
	"keytab": {"port49_password"}, "trust": {"ca_pem", "name"}, "issue": {"csr_pem", "template"},
	"enroll_as": {"csr_pem", "user"}, "set_attr": {"dn", "attribute", "values"}, "registry": {"name", "value"},
	"events": {"since"}, "facts": nil,
}

// winSecretParams are the parameters that carry a secret: no script may
// write one (TestWindowsScriptsNeverEchoASecret).
var winSecretParams = []string{"dsrm_password", "port49_password"}
```

- [ ] **Step 6: Run the tests and see them pass**

Run: `go test -tags lab ./tests/lab/ -run '^TestWindows' -count=1 && make lab-unit && go vet -tags lab ./tests/lab/`

Expected: PASS, with vet silent.

- [ ] **Step 7: Commit**

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add tests/lab/directory/windows tests/lab/windows_test.go tests/lab/windows_unit_test.go
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "test(lab): the Windows DC's compose project and setup scripts for L44

dockurr/windows 6.06 by digest on its own network, ports on loopback only;
the first-logon hook that starts sshd; MIT kinit with PKINIT on pinned Debian;
and fifteen PowerShell steps, each taking its params on stdin and writing
none that is secret.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 4: The DC's bring-up, the SSH runner and the certificates (and the feasibility gate)

**Files:**
- Modify: `tests/lab/windows_test.go` (the `winDC` runner; replaces Task 1's placeholder in
  `directory_test.go`)
- Modify: `tests/lab/directory_test.go` (delete the placeholder `winDC`)
- Create: `tests/lab/l44_test.go` (`TestL44Bringup` only; Task 5 adds the measurement)
- Modify: `Makefile` (`.PHONY` and `lab-windows`), `tests/lab/README.md`
  ("Windows Server AD (L44)")

**Interfaces:**
- Consumes: Tasks 1–3.
- Produces:
  - `type winDC struct` with `dir`, `compose`, `sec`, `port49`, `state winState`,
    `facts winFacts`, `certs winCerts` and `adcsRoot *x509.Certificate`.
  - `startWindowsDC(t, d) *labDir`.
  - Commands: `(w *winDC) dockerCompose(args...) *exec.Cmd`,
    `(w *winDC) ps(ctx, name string, params map[string]any) (json.RawMessage, error)` and
    `(w *winDC) run(t, name string, params map[string]any, within time.Duration, into any)`.
  - Queries: `(w *winDC) clock(t) string`, `(w *winDC) checkSkew(t)` and
    `(w *winDC) events(t, since string) []winEvent`.
  - Changes: `(w *winDC) setValues(t, dn, attr string, vals []string)`,
    `(w *winDC) setAltSec(t, dn, value string)` and `(l *labDir) setRegistry(t, name string, value int) string`.
  - Certificates and PKINIT:
    `(w *winDC) kinit(t, label, principal string, c *x509.Certificate, key *rsa.PrivateKey) pkinitResult`,
    `(w *winDC) issue(t, cn, upn, template string) (*x509.Certificate, *rsa.PrivateKey)` and
    `(w *winDC) enrollAs(t, user string) (*x509.Certificate, *rsa.PrivateKey)`.
  - Notes: `(w *winDC) version() string`, `(w *winDC) configNote() string` and
    `(w *winDC) factsSection() string`.
  - `winCerts` fields: `brokerADCS`, `aliceADCS`, `aliceSID`, `aliceComma`, `aliceHighBit` and
    `dcKDC`, each `*x509.Certificate`; the keys `brokerKey`, `aliceADCSKey`, `aliceSIDKey`,
    `aliceCommaKey` and `aliceHighBitKey`; and the files `brokerCertFile` and `brokerKeyFile`.

- [ ] **Step 1: Write the bring-up** in `tests/lab/windows_test.go`.

Delete the placeholder `winDC` type and its three methods from `directory_test.go`. Then add:

```go
// winDC is the Windows Server DC the L44 run measures: a KVM VM in a dockur
// container on the compose project port49labwin, set up over SSH as the
// domain's Administrator, every step one script from directory/windows/scripts.
type winDC struct {
	dir, compose string // tests/lab/logs/windows; tests/lab/directory/windows/compose.yaml
	sec          *winSecrets
	port49       string // port49's password: the run's d.password
	reused       bool
	state        winState
	facts        winFacts
	certs        winCerts
	adcsRoot     *x509.Certificate
}

// winState is what a built DC keeps between runs (state.json, no secret).
type winState struct {
	Built        bool      `json:"built"`
	AliceCreated time.Time `json:"alice_created"`
	Loop         string    `json:"loop"`
}

// winFacts is what facts.ps1 answers.
type winFacts struct {
	Caption          string            `json:"caption"`
	Version          string            `json:"version"`
	Build            string            `json:"build"`
	DisplayVersion   string            `json:"display_version"`
	Edition          string            `json:"edition"`
	Hotfixes         []string          `json:"hotfixes"`
	DomainMode       string            `json:"domain_mode"`
	ForestMode       string            `json:"forest_mode"`
	UTCNow           string            `json:"utc_now"`
	StrongBinding    string            `json:"strong_certificate_binding_enforcement"`
	Backdating       string            `json:"certificate_backdating_compensation"`
	MappingMethods   string            `json:"certificate_mapping_methods"`
	NTDSLDAP         map[string]string `json:"ntds_ldap_settings"`
	LockoutThreshold int               `json:"lockout_threshold"`
}

// winCerts is the run's client certificates, each key on this host only.
type winCerts struct {
	brokerADCS, aliceADCS, aliceSID, aliceComma, aliceHighBit, dcKDC  *x509.Certificate
	brokerKey, aliceADCSKey, aliceSIDKey, aliceCommaKey, aliceHighBitKey *rsa.PrivateKey
	brokerCertFile, brokerKeyFile                                     string
}

func (w *winDC) dockerCompose(args ...string) *exec.Cmd {
	return dockerCmd(append([]string{"compose", "-p", winProject, "-f", w.compose, "--env-file",
		filepath.Join(w.dir, "compose.env")}, args...)...)
}

func (w *winDC) secrets() []string { return append(w.sec.all(), w.port49) }

// dial is one SSH connection as the Administrator, with a deadline on the
// handshake too. The host key is not checked: the VM is new each run and is
// reached only on loopback.
func (w *winDC) dial(timeout time.Duration) (*ssh.Client, error) {
	nc, err := net.DialTimeout("tcp", winSSH, timeout)
	if err != nil {
		return nil, err
	}
	_ = nc.SetDeadline(time.Now().Add(timeout))
	pw := w.sec.AdminPassword
	cfg := &ssh.ClientConfig{User: "Administrator", HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: timeout,
		Auth: []ssh.AuthMethod{ssh.Password(pw), ssh.KeyboardInteractive(func(_, _ string, q []string, _ []bool) ([]string, error) {
			a := make([]string, len(q))
			for i := range a {
				a[i] = pw
			}
			return a, nil
		})}}
	c, chans, reqs, err := ssh.NewClientConn(nc, winSSH, cfg)
	if err != nil {
		nc.Close()
		return nil, err
	}
	_ = nc.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

// ps runs one script on the DC with params on stdin and returns its result.
// Every error it returns has had the run's secrets scrubbed from it.
func (w *winDC) ps(ctx context.Context, name string, params map[string]any) (json.RawMessage, error) {
	want, ok := winScripts[name]
	if !ok {
		return nil, fmt.Errorf("no windows script %q", name)
	}
	for k := range params {
		if !slices.Contains(want, k) {
			return nil, fmt.Errorf("windows script %s takes no %q", name, k)
		}
	}
	src, err := winScriptFS.ReadFile("directory/windows/scripts/" + name + ".ps1")
	if err != nil {
		return nil, err
	}
	body, err := winPayload(string(src), params)
	if err != nil {
		return nil, err
	}
	c, err := w.dial(30 * time.Second)
	if err != nil {
		return nil, fmt.Errorf("windows %s: ssh: %s", name, winScrub(err.Error(), w.secrets()...))
	}
	defer c.Close()
	s, err := c.NewSession()
	if err != nil {
		return nil, fmt.Errorf("windows %s: session: %v", name, err)
	}
	defer s.Close()
	var out, errb bytes.Buffer
	s.Stdin, s.Stdout, s.Stderr = bytes.NewReader(body), &out, &errb
	done := make(chan error, 1)
	go func() { done <- s.Run(winCommand()) }()
	select {
	case err = <-done:
	case <-ctx.Done():
		c.Close()
		return nil, fmt.Errorf("windows %s: %w", name, ctx.Err())
	}
	res, rerr := winResult(out.Bytes())
	if rerr != nil {
		return nil, fmt.Errorf("windows %s: %s (stderr: %s)", name, winScrub(rerr.Error(), w.secrets()...),
			winScrub(oneLineMax(errb.String(), 300), w.secrets()...))
	}
	if err != nil {
		return nil, fmt.Errorf("windows %s: %s", name, winScrub(err.Error(), w.secrets()...))
	}
	return res, nil
}

// run is ps under a deadline, fatal on error: a setup step's failure is the
// harness's, never a measurement. into, when not nil, receives the result.
func (w *winDC) run(t *testing.T, name string, params map[string]any, within time.Duration, into any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	res, err := w.ps(ctx, name, params)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if into != nil {
		if err := json.Unmarshal(res, into); err != nil {
			t.Fatalf("windows %s: reading its result: %v", name, err)
		}
	}
}

// logTail is dockur's last n bytes of log: install progress, never a password.
func (w *winDC) logTail(n int) string {
	b, _ := w.dockerCompose("logs", "--no-color", "--tail", "20", "dc").CombinedOutput()
	return tailOf(strings.TrimSpace(string(b)), n)
}

// waitSSH waits for the VM's sshd to take the Administrator's password and
// run a script, saying every two minutes what dockur last said: Windows
// Setup is silent for long stretches.
func (w *winDC) waitSSH(t *testing.T, within time.Duration) {
	t.Helper()
	deadline, next := time.Now().Add(within), time.Now()
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_, err := w.ps(ctx, "clock", nil)
		cancel()
		if err == nil {
			return
		}
		if up, _ := w.dockerCompose("ps", "--status", "running", "-q", "dc").Output(); strings.TrimSpace(string(up)) == "" {
			t.Fatalf("windows: the dc container is not running; dockur: %s", w.logTail(1500))
		}
		if time.Now().After(deadline) {
			t.Fatalf("windows: no SSH session within %s (%s); dockur: %s", within, oneLineMax(err.Error(), 200), w.logTail(1500))
		}
		if time.Now().After(next) {
			t.Logf("windows: waiting for SSH; dockur: %s", oneLineMax(w.logTail(300), 300))
			next = time.Now().Add(2 * time.Minute)
		}
		time.Sleep(15 * time.Second)
	}
}

func (w *winDC) waitReady(t *testing.T, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		_, err := w.ps(ctx, "ready", nil)
		cancel()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("windows: AD DS did not answer within %s of the promotion's reboot: %v", within, err)
		}
		time.Sleep(15 * time.Second)
	}
}

// writeFile0600 writes body to path, owner-only.
func writeFile0600(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeJSON0600(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	writeFile0600(t, path, b)
}

// loadKept reads a kept DC's secrets and state, true when both are there, it
// was built, and its container runs.
func (w *winDC) loadKept() bool {
	var s winSecrets
	b, err := os.ReadFile(filepath.Join(w.dir, "secrets.json"))
	if err != nil || json.Unmarshal(b, &s) != nil {
		return false
	}
	st, err := os.ReadFile(filepath.Join(w.dir, "state.json"))
	if err != nil || json.Unmarshal(st, &w.state) != nil || !w.state.Built {
		return false
	}
	w.sec = &s
	up, _ := w.dockerCompose("ps", "--status", "running", "-q", "dc").Output()
	return strings.TrimSpace(string(up)) != ""
}

// ensureWindowsISO is the pinned evaluation ISO's path in the cache
// (PORT49_LAB_ISO_DIR, default ~/.cache/port49-lab/iso), downloaded from
// Microsoft on first use and checked by size and SHA-256 every time: a file
// that does not match is never handed to the VM.
func ensureWindowsISO(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("PORT49_LAB_ISO_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(home, ".cache", "port49-lab", "iso")
	}
	path := filepath.Join(dir, "windows-server-2025-eval-26100.32230.iso")
	if winISOOK(path, winISOSize, winISOSHA256) == nil {
		return path
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	part := path + ".part"
	t.Logf("windows: downloading the evaluation ISO (%d bytes) to %s", winISOSize, dir)
	resp, err := http.Get(winISOURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("windows: fetching the ISO: %v %v", err, resp)
	}
	defer resp.Body.Close()
	f, err := os.Create(part)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	next := int64(1 << 30)
	buf := make([]byte, 1<<20)
	for {
		k, rerr := resp.Body.Read(buf)
		if k > 0 {
			if _, err := f.Write(buf[:k]); err != nil {
				t.Fatal(err)
			}
			n += int64(k)
			if n >= next {
				t.Logf("windows: ISO %d MiB of %d", n>>20, winISOSize>>20)
				next += 1 << 30
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("windows: reading the ISO: %v", rerr)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := winISOOK(part, winISOSize, winISOSHA256); err != nil {
		_ = os.Remove(part)
		t.Fatalf("windows: the downloaded ISO is not the pinned one: %v", err)
	}
	if err := os.Rename(part, path); err != nil {
		t.Fatal(err)
	}
	return path
}

// winDiskCheck fails the run when / has less than need GiB free (Lab rules).
func winDiskCheck(t *testing.T, dir string, need uint64) {
	t.Helper()
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	if free := st.Bavail * uint64(st.Bsize) >> 30; free < need {
		t.Fatalf("windows: %d GiB free on the lab's filesystem, the run needs %d (grow the root LV first)", free, need)
	}
}

// startWindowsDC builds the DC on d's PKI and password and returns it as a
// directory. With PORT49_LAB_WINDOWS_REUSE set and a kept DC up, it re-runs
// only the per-run steps (R7: a reused DC never closes L44).
func startWindowsDC(t *testing.T, d *directories) *labDir {
	t.Helper()
	repo, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	w := &winDC{dir: filepath.Join(repo, "tests", "lab", "logs", "windows"),
		compose: filepath.Join(repo, "tests", "lab", "directory", "windows", "compose.yaml"), port49: d.password}
	w.reused = os.Getenv("PORT49_LAB_WINDOWS_REUSE") != "" && w.loadKept()
	if !w.reused {
		// A fresh tree: no secret, key or state of an earlier run serves this one.
		if err := os.RemoveAll(w.dir); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(w.dir, "pkinit"), 0o700); err != nil {
			t.Fatal(err)
		}
		if w.sec, err = newWinSecrets(); err != nil {
			t.Fatal(err)
		}
		writeJSON0600(t, filepath.Join(w.dir, "secrets.json"), w.sec)
		writeFile0600(t, filepath.Join(w.dir, "windows.env"), []byte(winEnv(w.sec)))
	}
	d.extra = append(d.extra, w.sec.all()...)
	iso := ensureWindowsISO(t)
	writeFile0600(t, filepath.Join(w.dir, "compose.env"), []byte("PORT49_LAB_WINDOWS_ISO="+iso+"\n"))
	if os.Getenv("PORT49_LAB_WINDOWS_KEEP") == "" {
		t.Cleanup(func() { w.down(t) })
	}
	if !w.reused {
		winDiskCheck(t, w.dir, 66)
		_ = w.dockerCompose("--profile", "tools", "down", "-v", "--remove-orphans", "-t", "120").Run()
		if b, err := w.dockerCompose("--profile", "tools", "build", "pkinit").CombinedOutput(); err != nil {
			t.Fatalf("building the pkinit image: %v\n%s", err, tailOf(string(b), 2000))
		}
		if b, err := w.dockerCompose("up", "-d", "dc").CombinedOutput(); err != nil {
			t.Fatalf("docker compose up dc: %v\n%s", err, tailOf(string(b), 2000))
		}
		w.waitSSH(t, 150*time.Minute)
		w.run(t, "promote", map[string]any{"dsrm_password": w.sec.DSRMPassword}, 30*time.Minute, nil)
		time.Sleep(90 * time.Second) // promote.ps1's timer reboots the VM 15s after it answers
		w.waitSSH(t, 40*time.Minute)
		w.waitReady(t, 20*time.Minute)
		var seed struct {
			Loop         string    `json:"loop"`
			AliceCreated time.Time `json:"alice_created"`
		}
		w.run(t, "seed", map[string]any{"port49_password": w.port49}, 15*time.Minute, &seed)
		w.state = winState{Built: true, AliceCreated: seed.AliceCreated, Loop: seed.Loop}
		writeJSON0600(t, filepath.Join(w.dir, "state.json"), w.state)
	}
	l := &labDir{name: platWindows, service: "dc", uri: "ldaps://localhost:30636", plainURI: "ldap://localhost:30389",
		bindDN: "CN=port49,OU=Svc," + dirBase, userFilter: "(&(objectCategory=person)(objectClass=user))",
		groupFilter: "(objectClass=group)", usernameAttr: "sAMAccountName", baseDN: dirBase, groupsBaseDN: "OU=G," + dirBase,
		image: winImage, d: d, win: w,
		where: "Windows Server 2025 Standard Evaluation as a KVM VM in `dockurr/windows`, on " +
			"`tests/lab/directory/windows/compose.yaml` (no network device)",
		credentials: "none appear here or in the evidence. The Administrator, DSRM and port49 passwords are generated for " +
			"each run, held only in 0600 files under `tests/lab/logs/windows`, and reach the VM on an SSH session's stdin, " +
			"never on a command line; alice's is made on the DC and never leaves it. The keytab and every private key stay " +
			"on the host that ran it, 0600, and are removed at the end of the run.",
		keytabFile: filepath.Join(w.dir, "port49.keytab"), krb5File: filepath.Join(w.dir, "krb5.conf")}
	if w.state.Loop != "made" {
		l.loopRefused = w.state.Loop
	}
	w.perRun(t, l)
	l.waitLDAPS(t, 3*time.Minute)
	l.checkFixture(t)
	return l
}

// perRun is what every run does, on a fresh DC or a kept one: the clock
// checked, port49's password and alice's mapping set, AD CS ensured, LDAPS on
// the run's certificate, the keytab, the run's CAs trusted, the client
// certificates issued, the facts read.
func (w *winDC) perRun(t *testing.T, l *labDir) {
	t.Helper()
	d := l.d
	w.checkSkew(t)
	w.run(t, "reset", map[string]any{"port49_password": w.port49,
		"alice_altsecid": directory.ADIssuerSerial(d.pki.alice)}, 5*time.Minute, nil)
	var adcs struct {
		CAPEM  string `json:"ca_pem"`
		KDCPEM string `json:"kdc_pem"`
	}
	w.run(t, "adcs", nil, 30*time.Minute, &adcs)
	var err error
	if w.adcsRoot, err = parsePEMCert([]byte(adcs.CAPEM)); err != nil {
		t.Fatalf("windows: the enterprise CA's certificate: %v", err)
	}
	if w.certs.dcKDC, err = parsePEMCert([]byte(adcs.KDCPEM)); err != nil {
		t.Fatalf("windows: the DC's KDC certificate: %v", err)
	}
	var req struct {
		CSRPEM string `json:"csr_pem"`
	}
	w.run(t, "ldaps", map[string]any{"step": "request"}, 5*time.Minute, &req)
	certPEM, err := d.pki.signServerCSR([]byte(req.CSRPEM), time.Now())
	if err != nil {
		t.Fatalf("windows: signing the DC's LDAPS request: %v", err)
	}
	w.run(t, "ldaps", map[string]any{"step": "install", "cert_pem": string(certPEM), "lab_ca_pem": string(d.pki.ca.PEM())},
		5*time.Minute, nil)
	var kt struct {
		KeytabB64 string `json:"keytab_b64"`
	}
	w.run(t, "keytab", map[string]any{"port49_password": w.port49}, 5*time.Minute, &kt)
	raw, err := base64.StdEncoding.DecodeString(kt.KeytabB64)
	if err != nil || len(raw) == 0 {
		t.Fatalf("windows: the keytab did not come back (%d bytes): %v", len(raw), err)
	}
	writeFile0600(t, l.keytabFile, raw)
	writeFile0600(t, l.krb5File, []byte(krb5Conf(winKDC)))
	comma, commaKey, err := winCommaCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, ca := range []struct {
		name string
		c    *x509.Certificate
	}{{"lab-users-ca", d.pki.usersCA}, {"lab-users-comma-ca", comma}} {
		w.run(t, "trust", map[string]any{"ca_pem": string(pemCert(ca.c)), "name": ca.name}, 5*time.Minute, nil)
	}
	writeFile0600(t, filepath.Join(w.dir, "pkinit", "krb5.conf"), []byte(winPKINITConf(winKDCInNet)))
	writeFile0600(t, filepath.Join(w.dir, "pkinit", "adcs-root.pem"), pemCert(w.adcsRoot))
	w.issueCerts(t, d, comma, commaKey)
	w.run(t, "facts", nil, 5*time.Minute, &w.facts)
}

// issueCerts issues the run's client certificates (R5) and checks none
// predates alice's account.
func (w *winDC) issueCerts(t *testing.T, d *directories, comma *x509.Certificate, commaKey *ecdsa.PrivateKey) {
	t.Helper()
	// AD CS backdates NotBefore ten minutes. A certificate older than alice's
	// account meets KB5014754's backdating check, which is no part of the claim.
	if wait := time.Until(w.state.AliceCreated.Add(11 * time.Minute)); wait > 0 {
		t.Logf("windows: waiting %s so AD CS's certificates do not predate alice's account", wait.Round(time.Second))
		time.Sleep(wait)
	}
	c := &w.certs
	c.brokerADCS, c.brokerKey = w.issue(t, "port49-broker", "", "OfflineRouter")
	c.aliceADCS, c.aliceADCSKey = w.issue(t, "alice", "alice@corp.example.com", "OfflineRouter")
	c.aliceSID, c.aliceSIDKey = w.enrollAs(t, "alice")
	now := time.Now()
	var err error
	if c.aliceComma, c.aliceCommaKey, err = winPersonCert(comma, commaKey, "alice", "alice@corp.example.com", dirSerial(), now); err != nil {
		t.Fatal(err)
	}
	if c.aliceHighBit, c.aliceHighBitKey, err = winPersonCert(d.pki.usersCA, d.pki.usersKey, "alice", "alice@corp.example.com",
		winHighBitSerial(), now); err != nil {
		t.Fatal(err)
	}
	if err := winIssuedAfter(w.state.AliceCreated, c.aliceADCS, c.aliceSID, c.aliceComma, c.aliceHighBit); err != nil {
		t.Fatalf("windows: precondition: %v", err)
	}
	c.brokerCertFile = filepath.Join(w.dir, "broker-adcs.pem")
	c.brokerKeyFile = filepath.Join(w.dir, "broker-adcs-key.pem")
	writeFile0600(t, c.brokerCertFile, pemCert(c.brokerADCS))
	writeFile0600(t, c.brokerKeyFile, pemKey(c.brokerKey))
}

// issue has the enterprise CA sign a request for cn (and upn) under template,
// the key made here.
func (w *winDC) issue(t *testing.T, cn, upn, template string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	csr, key, err := winCSR(cn, upn)
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		CertPEM string `json:"cert_pem"`
	}
	w.run(t, "issue", map[string]any{"csr_pem": string(csr), "template": template}, 5*time.Minute, &r)
	c, err := parsePEMCert([]byte(r.CertPEM))
	if err != nil {
		t.Fatalf("windows: the %s certificate for %s: %v", template, cn, err)
	}
	return c, key
}

// enrollAs is user's own User certificate, requested as user (enroll_as.ps1).
func (w *winDC) enrollAs(t *testing.T, user string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	csr, key, err := winCSR(user, "")
	if err != nil {
		t.Fatal(err)
	}
	var r struct {
		CertPEM string `json:"cert_pem"`
	}
	w.run(t, "enroll_as", map[string]any{"csr_pem": string(csr), "user": user}, 10*time.Minute, &r)
	c, err := parsePEMCert([]byte(r.CertPEM))
	if err != nil {
		t.Fatalf("windows: %s's User certificate: %v", user, err)
	}
	return c, key
}

// clock is the DC's UTC time, ISO 8601: the "since" of an events read, on
// the DC's own clock.
func (w *winDC) clock(t *testing.T) string {
	t.Helper()
	var r struct {
		UTCNow string `json:"utc_now"`
	}
	w.run(t, "clock", nil, time.Minute, &r)
	return r.UTCNow
}

// checkSkew fails the run, as a precondition, when the DC's clock is more
// than 60s from ours (R6).
func (w *winDC) checkSkew(t *testing.T) {
	t.Helper()
	dc, err := time.Parse(time.RFC3339Nano, w.clock(t))
	if err != nil {
		t.Fatalf("windows: the DC's clock: %v", err)
	}
	if now := time.Now(); !winSkewOK(dc, now, time.Minute) {
		t.Fatalf("windows: precondition: the DC's clock is %s from ours", dc.Sub(now).Round(time.Second))
	}
}

// events is what the DC logged since (its own clock).
func (w *winDC) events(t *testing.T, since string) []winEvent {
	t.Helper()
	var r struct {
		Events []winEvent `json:"events"`
	}
	w.run(t, "events", map[string]any{"since": since}, 2*time.Minute, &r)
	return r.Events
}

// setValues replaces attr on dn with vals (clears it when vals holds none)
// and asserts the DC holds exactly that afterwards (Review Focus 3).
func (w *winDC) setValues(t *testing.T, dn, attr string, vals []string) {
	t.Helper()
	var r struct {
		Values []string `json:"values"`
	}
	w.run(t, "set_attr", map[string]any{"dn": dn, "attribute": attr, "values": vals}, 2*time.Minute, &r)
	want := ""
	if len(vals) == 1 {
		want = vals[0]
	}
	if !winOnlyValue(r.Values, want) {
		t.Fatalf("windows: %s on %s holds %d value(s) after the set, not exactly the one asked", attr, dn, len(r.Values))
	}
}

// setAltSec gives dn exactly value as altSecurityIdentities, or none for "".
func (w *winDC) setAltSec(t *testing.T, dn, value string) {
	t.Helper()
	var vals []string
	if value != "" {
		vals = []string{value}
	}
	w.setValues(t, dn, "altSecurityIdentities", vals)
}

// setRegistry sets one of the DC settings the run varies (-1 deletes it),
// waits for LDAPS when NTDS restarted, and returns the value in force.
func (l *labDir) setRegistry(t *testing.T, name string, value int) string {
	t.Helper()
	var r struct {
		Value     string `json:"value"`
		Restarted string `json:"restarted"`
	}
	l.win.run(t, "registry", map[string]any{"name": name, "value": value}, 5*time.Minute, &r)
	if r.Restarted == "NTDS" {
		l.waitLDAPS(t, 3*time.Minute)
	}
	return r.Value
}

// kinit asks the DC's KDC for principal's TGT by PKINIT with c and key, from
// the Debian container on the project network, and reads the answer from
// MIT's trace, which is parsed and never printed. The key file is 0600 and
// removed after.
func (w *winDC) kinit(t *testing.T, label, principal string, c *x509.Certificate, key *rsa.PrivateKey) pkinitResult {
	t.Helper()
	base := filepath.Join(w.dir, "pkinit", label)
	writeFile0600(t, base+".pem", pemCert(c))
	writeFile0600(t, base+"-key.pem", pemKey(key))
	defer os.Remove(base + "-key.pem")
	script := fmt.Sprintf(`export KRB5_CONFIG=/l44/krb5.conf; KRB5_TRACE=/dev/stdout kinit -X X509_user_identity=FILE:/l44/%[1]s.pem,/l44/%[1]s-key.pem %[2]s </dev/null 2>&1; echo "lab: kinit exit $?"; klist 2>&1`,
		label, principal)
	start := time.Now()
	out, _ := w.dockerCompose("--profile", "tools", "run", "--rm", "-T", "pkinit", "sh", "-c", script).CombinedOutput()
	r := parseKinit(string(out))
	r.took = time.Since(start)
	return r
}

// down keeps dockur's log (0600; dockur prints no password) and takes the
// project down with its volumes, the VM's disk among them. Without
// PORT49_LAB_WINDOWS_KEEP it also removes every secret and key the run wrote.
func (w *winDC) down(t *testing.T) {
	t.Helper()
	if b, err := w.dockerCompose("logs", "--no-color", "dc").CombinedOutput(); err == nil {
		_ = os.WriteFile(filepath.Join(w.dir, "dc.log"), b, 0o600)
	}
	if b, err := w.dockerCompose("--profile", "tools", "down", "-v", "--remove-orphans", "-t", "120").CombinedOutput(); err != nil {
		t.Errorf("docker compose down (windows): %v\n%s", err, tailOf(string(b), 2000))
	}
	for _, f := range []string{"pkinit", "port49.keytab", "broker-adcs-key.pem", "secrets.json", "windows.env", "state.json"} {
		_ = os.RemoveAll(filepath.Join(w.dir, f))
	}
}

// version is the note's image line: the build the DC reports, the ISO and the image.
func (w *winDC) version() string {
	f := w.facts
	return fmt.Sprintf("%s (%s), build %s; ISO `%s` (SHA-256 `%s`); image `%s`%s", f.Caption, f.Edition, f.Build,
		path.Base(winISOURL), winISOSHA256, winImage, map[bool]string{true: "; **a reused DC (not a closing run, R7)**"}[w.reused])
}

// factsSection is the note's table of what the DC was, as the run found it.
func (w *winDC) factsSection() string {
	f := w.facts
	keys := make([]string, 0, len(f.NTDSLDAP))
	for k := range f.NTDSLDAP {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var ldapSet []string
	for _, k := range keys {
		ldapSet = append(ldapSet, fmt.Sprintf("`%s` = %s", k, f.NTDSLDAP[k]))
	}
	if len(ldapSet) == 0 {
		ldapSet = []string{"none set"}
	}
	var b strings.Builder
	b.WriteString("### The DC, as the run found it\n\n| fact | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| build | %s %s (%s), %s |\n", f.Caption, f.DisplayVersion, f.Edition, f.Build)
	fmt.Fprintf(&b, "| updates | %s |\n", strings.Join(f.Hotfixes, ", "))
	fmt.Fprintf(&b, "| domain and forest modes | %s, %s |\n", f.DomainMode, f.ForestMode)
	fmt.Fprintf(&b, "| `StrongCertificateBindingEnforcement` as installed | %s |\n", f.StrongBinding)
	fmt.Fprintf(&b, "| `CertificateBackdatingCompensation` | %s |\n", f.Backdating)
	fmt.Fprintf(&b, "| Schannel `CertificateMappingMethods` | %s |\n", f.MappingMethods)
	fmt.Fprintf(&b, "| NTDS LDAP settings in the registry | %s |\n", strings.Join(ldapSet, "; "))
	fmt.Fprintf(&b, "| account lockout threshold | %d |\n\n", f.LockoutThreshold)
	return b.String()
}

// configNote is what the DC was set up to do that the note's rows depend on.
func (w *winDC) configNote() string {
	return "### How this directory was configured\n\n" +
		"- Windows Server 2025 Standard Evaluation, installed unattended by `dockurr/windows` from the pinned ISO into a " +
		"KVM VM (6 GB, 4 vCPUs), and promoted to the first DC of a new forest `corp.example.com` by `Install-ADDSForest` " +
		"with this build's defaults.\n" +
		"- Set up only over OpenSSH (installed by Windows, started by `oem/install.bat`) as the domain's Administrator. The " +
		"Windows firewall is off and Windows Update disabled, so the build measured is the ISO's. Ports are published on " +
		"127.0.0.1 only.\n" +
		"- L42's fixture, made by `scripts/seed.ps1` with global security groups; the second `netops-oncall` is renamed in, " +
		"as on Samba.\n" +
		"- LDAPS serves a certificate from the lab CA (`localhost`, `dc1.corp.example.com`, 127.0.0.1), placed in the NTDS " +
		"service's own store; the lab CA is in the DC's Root store.\n" +
		"- The DC's account carries the extra SPN `ldap/localhost`, as on Samba; the client `krb5.conf` reaches the KDC at " +
		"127.0.0.1:30088 over TCP.\n" +
		"- `port49` is an ordinary domain user, AES only; its keytab is made with `ktpass` (AES256-SHA1, " +
		"`-mapuser CORP\\port49`), which also sets its UPN.\n" +
		"- AD CS: an enterprise root CA `corp-L44-CA` on the DC, `OfflineRouter` published for requests whose subject the " +
		"harness supplies, and the DC's `KerberosAuthentication` certificate enrolled for PKINIT. The lab users CA and a " +
		"second CA whose CN holds a comma are in the DC's Root store and in NTAuth.\n" +
		"- Alice's `User` certificate is requested as alice over WinRM with CredSSP, under a session configuration only she " +
		"may use; all of it is removed after, and her password for it is made on the DC, used once and replaced.\n" +
		"- During the KB5014754 table only, `UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = 1` on the KDC: the " +
		"harness's own CAs publish no CRL, and revocation is no part of the claim. Removed after.\n" +
		"- LDAP interface diagnostics at level 2 (`16 LDAP Interface Events`), so the DC logs bind and channel-binding events.\n" +
		"- PKINIT's client is MIT Kerberos 1.20 (`kinit`, Debian bookworm's `krb5-pkinit`) on the project network, with " +
		"`pkinit_kdc_hostname`, as MIT documents for an Active Directory KDC.\n\n"
}
```

Imports to add to `windows_test.go`: `bytes`, `context`, `net`, `net/http`, `os/exec`, `path`,
`path/filepath`, `syscall`, `testing`, `golang.org/x/crypto/ssh` and
`github.com/rhwendt/port49/internal/directory`.

- [ ] **Step 2: The feasibility gate test and the make target**

Create `tests/lab/l44_test.go`:

```go
//go:build lab

package lab

import (
	"testing"

	"github.com/rhwendt/port49/internal/directory"
)

// TestL44Bringup is the DC's bring-up alone, with no measurement: everything
// L44 needs before it measures anything. It writes no note. Run it with
// -run '^TestL44Bringup$'; make lab-windows runs TestL44WindowsAD alone.
func TestL44Bringup(t *testing.T) {
	d := newDirectories(t)
	dc := startWindowsDC(t, d)
	c := dc.win.certs
	if _, err := directory.SIDOf(c.aliceSID); err != nil {
		t.Errorf("alice's User certificate carries no SID extension: %v", err)
	}
	if _, err := directory.SIDOf(c.aliceADCS); err == nil {
		t.Errorf("alice's OfflineRouter certificate carries a SID extension; the matrix needs one without")
	}
	ev := evidence(t, d, "L44-bringup")
	if r := dc.tryBind(t, ev, "simple", dc.bindSimple(), d.password); !r.ok || r.read != 1 {
		t.Errorf("the simple bind over LDAPS, the lab's premise: %+v", r)
	}
	if r := dc.tryBind(t, ev, "gssapi", dc.bindGSSAPI(), ""); !r.ok {
		t.Logf("GSSAPI as installed: %s (measured in TestL44WindowsAD, not a bring-up failure)", r.text)
	}
	t.Logf("windows: %s; fixture loaded, LDAPS verified, keytab and certificates issued", dc.win.version())
}
```

In the `Makefile`, add `lab-windows` to `.PHONY`. After `lab-directory`, add:

```make
# The Windows Server AD lab (L44): Windows Server 2025 Evaluation as a KVM VM in
# dockurr/windows, set up as a DC over SSH; no network device. Needs /dev/kvm,
# Docker with Compose v2.24.4+ and 66 GiB free on / (tests/lab/README.md,
# "Windows Server AD (L44)"). A fresh run takes one and a half to two and a half
# hours, most of it Windows Setup.
lab-windows:
	go test -tags lab ./tests/lab/ -run '^TestL44WindowsAD$$' -count=1 -v -timeout 240m
```

In `tests/lab/README.md`, under "Directories (plan 7g)", add a subsection
"### Windows Server AD (L44)" stating:
- what runs (the compose project, the image digest, the ISO URL, size and SHA-256, the cache dir
  and `PORT49_LAB_ISO_DIR`);
- the disk, RAM and time needs from "Lab rules";
- `PORT49_LAB_WINDOWS_KEEP` and `PORT49_LAB_WINDOWS_REUSE`, with R7's warning;
- the files under `tests/lab/logs/windows`, and which hold secrets (`windows.env`,
  `secrets.json`, `port49.keytab`, `broker-adcs-key.pem`, `pkinit/*-key.pem`);
- the two commands never to run (`docker compose config` and `docker inspect` on
  `port49labwin`);
- the web viewer on `http://127.0.0.1:8006` for watching Setup;
- every accommodation in `configNote`, so a reader of the README alone sees them.

- [ ] **Step 3: Compile and unit-test**

Run: `make lab-unit && go vet -tags lab ./tests/lab/ && gofmt -l tests/lab`

Expected: PASS, with vet silent and gofmt printing nothing.

- [ ] **Step 4: Commit**

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add tests/lab/windows_test.go tests/lab/directory_test.go tests/lab/l44_test.go Makefile tests/lab/README.md
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "test(lab): bring up a Windows Server 2025 DC for L44

dockur installs the pinned evaluation ISO; the harness promotes it over SSH,
loads L42's fixture, installs AD CS, serves LDAPS on the lab CA's certificate,
makes port49's keytab with ktpass and issues the run's client certificates.
make lab-windows; TestL44Bringup is the bring-up alone.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

- [ ] **Step 5: Before the gate run, check the host**

```bash
df -h / | tail -1                      # at least 66G Avail; else the controller extends the LV first
ls -l /dev/kvm /dev/net/tun            # both present
sg docker -c "docker ps --format '{{.Names}}'"   # no other lab running
ss -ltn | grep -E ':(8006|30022|30088|30389|30636)\b' || echo "ports free"
```

Expected: at least 66 GiB available, both devices present, no lab containers, and `ports free`.

- [ ] **Step 6: The feasibility gate (lab; follow "Lab rules")**

```bash
git -C /home/rwendt/git/port49 worktree add --detach /home/rwendt/git/port49/.worktrees/lab-l44 "$(git -C /home/rwendt/git/port49/.worktrees/l44 rev-parse HEAD)"
cd /home/rwendt/git/port49/.worktrees/lab-l44
sg docker -c "go test -tags lab ./tests/lab/ -run '^TestL44Bringup$' -count=1 -v -timeout 240m" > /tmp/claude-1000/l44-bringup.log 2>&1
```

Start the background stall watchdog first (Lab rules). Then wait in a foreground loop with a
240-minute deadline, reading the log's tail (it holds no secret) every few minutes.

Expected: `--- PASS: TestL44Bringup`. The log shows the build from `version()`, and no other line
beyond the progress lines.

**If it fails,** read `tests/lab/logs/windows/dc.log` with `tail`; it holds no secret. Fix the
harness on `.worktrees/l44` in a `fix(lab):` commit, re-pin `lab-l44` at the fix, and run again.
The likely causes and their fixes, in order of likelihood:
- **No SSH, but dockur says Setup finished.** `install.bat` did not run. Check `C:\OEM` through
  the viewer at `http://127.0.0.1:8006`. Fallback: dockur's `COMMAND` variable with the same
  PowerShell line.
- **dockur did not detect the custom ISO.** Fallback, recorded in the note's configuration
  section: `VERSION: "2025"` and `VERIFY: "Y"` in place of the `/custom.iso` mount. dockur then
  downloads the same URL and checks the same SHA-256 (`define.sh`, `win2025-eval`).
- **`enroll_as` is refused,** by WinRM, CredSSP or the CA. Try three times. If it still fails,
  the SID cells will be INVALID (R6), and the plan continues. The SID extension is still compared
  on the DC's own certificate.
- **`ktpass` or GSSAPI fails** because of the key version or the salt. The keytab cell becomes
  INVALID after three tries; report the `ktpass` exit code and nothing more.

**Stop rule:** three failed bring-ups with no harness fix left means stop and report to the
controller, with the failing step and the dockur log tail. L44 stays open.

After the run, check the "After every run, confirm" list, then
`git -C /home/rwendt/git/port49 worktree remove --force .worktrees/lab-l44`.

---

### Task 5: The L44 measurement

**Files:**
- Modify: `tests/lab/l44_test.go` (adds `l44Claim`, `TestL44WindowsAD` and its sections)
- Test: `tests/lab/windows_unit_test.go` (the row builders)

**Interfaces:**
- Consumes:
  - Task 4: `startWindowsDC`, `winDC.kinit`, `setAltSec`, `setRegistry`, `events`, `clock`,
    `checkSkew` and `certs`.
  - Task 1: `l42Observe`, `capabilities`, `ldapObjectSID` and `writeResult`.
  - L43's helpers: `tryBind`, `tryPlain`, `refusalChecks`, `mappingChecks` and `certRequested`.
- Produces:
  - `l44MatrixRow(enforcement, what, held string, r pkinitResult, evs []winEvent) string`.
  - `l44ExternalRow(enforcement string, c l43Cell, evs []winEvent) string`.
  - `l44EventsCell(evs []winEvent) string`.
  - `l44PreconditionIDs(evs []winEvent) []int`.
  - The note `L44-windows_ad.md` and its evidence.

- [ ] **Step 1: Write the failing tests** (append to `tests/lab/windows_unit_test.go`)

```go
func TestL44EventsCell(t *testing.T) {
	evs := []winEvent{{ID: 39, Provider: "Microsoft-Windows-Kerberos-Key-Distribution-Center", Message: "No strong | mapping for alice"},
		{ID: 3075, Provider: "Microsoft-Windows-ActiveDirectory_DomainService", Message: "x"}}
	got := l44EventsCell(evs)
	if !strings.Contains(got, "KDC 39: No strong \\| mapping") || !strings.Contains(got, "DS 3075") || strings.Contains(got, " | ") {
		t.Fatalf("%q", got)
	}
	if l44EventsCell(nil) != "(none)" {
		t.Fatal("none")
	}
	if ids := l44PreconditionIDs([]winEvent{{ID: 21, Provider: "Microsoft-Windows-Kerberos-Key-Distribution-Center"}, {ID: 21, Provider: "Schannel"}}); len(ids) != 1 {
		t.Fatalf("%v: only a KDC's 19, 21 or 29 is a setup failure", ids)
	}
}

func TestL44MatrixRow(t *testing.T) {
	r := pkinitResult{ok: false, kdcErrs: []string{"-1765328359/Additional pre-authentication required", "-1765328318/KDC_ERR_CERTIFICATE_MISMATCH"},
		last: "kinit: Certificate mismatch while getting initial credentials", took: 1500 * time.Millisecond}
	row := l44MatrixRow("2", "AD CS `OfflineRouter`", "", r, nil)
	for _, want := range []string{"| 2 | AD CS `OfflineRouter` | (none) | refused |", "KDC_ERR_CERTIFICATE_MISMATCH", "| (none) | 1.5s |"} {
		if !strings.Contains(row, want) {
			t.Errorf("row lacks %q: %s", want, row)
		}
	}
	if !strings.Contains(l44MatrixRow("absent", "x", "X509:<I>A<SR>01", pkinitResult{ok: true}, nil), "**TGT issued**") {
		t.Error("an accepted cell does not say so")
	}
}
```

- [ ] **Step 2: Run them and see them fail**

Run: `go test -tags lab ./tests/lab/ -run '^TestL44(EventsCell|MatrixRow)$' -count=1`

Expected: a build failure (`l44EventsCell` and the other builders are undefined).

- [ ] **Step 3: Implement** (append to `tests/lab/l44_test.go`, adding imports `context`,
`crypto/rsa`, `crypto/x509`, `fmt`, `slices`, `strings` and `time`)

```go
const l44Claim = "The Active Directory claims on a Windows DC: on L42's fixture and its loop, which groups " +
	"`member:1.2.840.113556.1.4.1941:=<user DN>` returns and how the loop is answered; SASL EXTERNAL over LDAPS with a " +
	"client certificate; GSSAPI with a keytab and no SASL security layer against the Windows KDC; whether " +
	"`altSecurityIdentities` values written in port49's `X509:<I>{issuer}<SR>{serial}` form (issuer from the raw DER, " +
	"`DC=` included) match the certificate the DC itself maps; whether the SID extension's value equals `objectSid`; and " +
	"how KB5014754's strong-mapping enforcement treats each (policy engine spec §15 L44). Also measured, for two questions " +
	"plan 7g carried: whether the DC advertises the AD capability 1.2.840.113556.1.4.800, and the LDAP result an EXTERNAL " +
	"bind it refuses carries."

const adCapability = "1.2.840.113556.1.4.800"

// l44Case is one certificate offered to the DC's KDC by PKINIT, with the
// altSecurityIdentities alice holds while it is (none when altsec is nil).
type l44Case struct {
	label, what string
	cert        *x509.Certificate
	key         *rsa.PrivateKey
	altsec      func(*x509.Certificate) (string, error)
}

func TestL44WindowsAD(t *testing.T) {
	compare := l44CompareCapabilities(t) // first: the containers share tests/lab/logs/directory
	d := newDirectories(t)
	d.runSel = "^TestL44WindowsAD$"
	dc := startWindowsDC(t, d)
	ev := evidence(t, d, "L44-"+platWindows)
	var obs strings.Builder
	obs.WriteString(dc.configNote())
	obs.WriteString(dc.win.factsSection())
	obs.WriteString("### Nested groups: L42's fixture\n\n")
	obs.WriteString(dc.l42Observe(t, ev))
	obs.WriteString(dc.l44Capabilities(t, ev, compare))
	obs.WriteString(dc.l44Binds(t, ev))
	obs.WriteString(dc.l44SID(t, ev))
	obs.WriteString(dc.mappingChecks(t, ev))
	obs.WriteString(dc.l44Matrix(t, ev))
	ev.assertClean(t, append([]string{d.password}, d.extra...)...)
	writeResult(t, d, "L44", dc, l44Claim, dc.version(t), obs.String(), "tests/lab/evidence/L44-"+platWindows+".json")
}

// l44CompareCapabilities is the root DSE's supportedCapabilities on OpenLDAP
// and Samba AD, for plan 7g's carried question (a). Not a register cell: L42
// and L43 are closed.
func l44CompareCapabilities(t *testing.T) map[string][]string {
	out := map[string][]string{}
	t.Run("compare", func(t *testing.T) {
		d := startDirectories(t)
		for _, dir := range d.all() {
			out[dir.name] = dir.capabilities(t)
		}
	})
	return out
}

func (l *labDir) l44Capabilities(t *testing.T, ev *evidenceLog, compare map[string][]string) string {
	t.Helper()
	ev.mark("L44 root DSE supportedCapabilities")
	var b strings.Builder
	b.WriteString("\n### The AD capability (plan 7g's carried question a)\n\n" +
		"| directory | advertises `" + adCapability + "` | `in_chain` (L42) | supportedCapabilities |\n|---|---|---|---|\n")
	row := func(name, inChain string, caps []string) {
		fmt.Fprintf(&b, "| %s | %v | %s | %s |\n", name, slices.Contains(caps, adCapability), inChain, strings.Join(caps, ", "))
	}
	row(platWindows, "the table above", l.capabilities(t))
	row(platOpenLDAP, "answers empty, no error (`L42-openldap.md`)", compare[platOpenLDAP])
	row(platSamba, "answers in full (`L42-samba_ad.md`)", compare[platSamba])
	return b.String()
}

// l44Binds is L43's binds on the DC, EXTERNAL with the broker's AD CS
// certificate mapped and unmapped, and GSSAPI as installed and under
// LdapEnforceChannelBinding 2.
func (l *labDir) l44Binds(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	w := l.win
	since := w.clock(t)
	brokerDN := "CN=port49,OU=Svc," + dirBase
	adcsExt := directory.Bind{Mechanism: "external", TLSCertFile: w.certs.brokerCertFile, TLSKeyFile: w.certs.brokerKeyFile}
	cbt := w.facts.NTDSLDAP["LdapEnforceChannelBinding"]
	if cbt == "" {
		cbt = "absent (this build's default)"
	}
	var b strings.Builder
	b.WriteString("\n### Binds\n\n| mechanism | outcome | LDAP result | time |\n|---|---|---|---|\n")
	ev.mark("L44 simple over LDAPS")
	simple := l.tryBind(t, ev, "simple", l.bindSimple(), l.d.password)
	b.WriteString(simple.row("simple bind over LDAPS"))
	ev.mark("L44 simple over plain LDAP")
	plain := l.tryPlain(t, ev, "simple over plain LDAP, by hand")
	b.WriteString(plain.row("simple bind over plain LDAP, built by hand"))
	ev.mark("L44 gssapi, LdapEnforceChannelBinding %s", cbt)
	gss := l.tryBind(t, ev, "gssapi", l.bindGSSAPI(), "")
	b.WriteString(gss.row("GSSAPI over LDAPS, keytab, no SASL security layer, `LdapEnforceChannelBinding` " + cbt))

	w.setAltSec(t, brokerDN, directory.ADIssuerSerial(w.certs.brokerADCS))
	ev.mark("L44 external, AD CS certificate, port49's form on port49")
	e1 := l.tryBind(t, ev, "external", adcsExt, "")
	b.WriteString(e1.row("SASL EXTERNAL over LDAPS, the broker's AD CS certificate, `altSecurityIdentities` on port49 in port49's form"))
	w.setAltSec(t, brokerDN, "")
	ev.mark("L44 external, AD CS certificate, no mapping")
	e2 := l.tryBind(t, ev, "external, unmapped", adcsExt, "")
	b.WriteString(e2.row("SASL EXTERNAL over LDAPS, the same certificate, no `altSecurityIdentities` on port49 (carried question b)"))
	ev.mark("L44 external, a certificate from the lab directory CA")
	e3 := l.tryBind(t, ev, "external, lab CA", l.bindExternal(), "")
	b.WriteString(e3.row("SASL EXTERNAL over LDAPS, a certificate from the lab directory CA (in the DC's Root store, not in NTAuth), unmapped (carried question b)"))

	got := l.setRegistry(t, "LdapEnforceChannelBinding", 2)
	ev.mark("L44 gssapi, LdapEnforceChannelBinding %s", got)
	gss2 := l.tryBind(t, ev, "gssapi, channel binding 2", l.bindGSSAPI(), "")
	b.WriteString(gss2.row("GSSAPI over LDAPS, keytab, no SASL security layer, `LdapEnforceChannelBinding` " + got + " (port49 sends no channel binding token)"))
	w.setAltSec(t, brokerDN, directory.ADIssuerSerial(w.certs.brokerADCS))
	e4 := l.tryBind(t, ev, "external, channel binding 2", adcsExt, "")
	b.WriteString(e4.row("SASL EXTERNAL over LDAPS, mapped, `LdapEnforceChannelBinding` " + got))
	simple2 := l.tryBind(t, ev, "simple, channel binding 2", l.bindSimple(), l.d.password)
	b.WriteString(simple2.row("simple bind over LDAPS, `LdapEnforceChannelBinding` " + got))
	w.setAltSec(t, brokerDN, "")
	l.setRegistry(t, "LdapEnforceChannelBinding", -1)

	fmt.Fprintf(&b, "\nWhether the DC's LDAPS asked the client for a certificate (what EXTERNAL needs): %s.\n", l.certRequested(t))
	if !simple.ok || simple.read != 1 || !simple2.ok {
		t.Errorf("the simple bind over LDAPS is the lab's premise and was not accepted: %+v %+v", simple, simple2)
	}
	if plain.ok {
		t.Errorf("the DC accepted a simple bind over plain LDAP: %+v", plain)
	}
	refusals, bad := l.refusalChecks(t, ev)
	b.WriteString(refusals)
	fmt.Fprintf(&b, "\nWhat the DC logged during the binds: %s\n", l44EventsCell(w.events(t, since)))
	ev.assertClean(t, bad)
	return b.String()
}

// l44SID compares the SID extension of the certificates AD CS issued with
// the objectSid of the account each names, and runs port49's sid and
// issuer_serial mappings on them (port49's guarantees, asserted).
func (l *labDir) l44SID(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	w := l.win
	c := w.certs
	var b strings.Builder
	b.WriteString("\n### The SID extension and objectSid\n\n| certificate | SID extension | objectSid | equal |\n|---|---|---|---|\n")
	row := func(what string, cert *x509.Certificate, filter string) {
		ext, err := directory.SIDOf(cert)
		obj := l.ldapObjectSID(t, filter)
		cell := "`" + ext + "`"
		if err != nil {
			cell = "none: " + oneLineMax(err.Error(), 120)
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %v |\n", what, cell, obj, err == nil && ext == obj)
	}
	ev.mark("L44 SID extensions against objectSid")
	row("alice's, AD CS `User` template, requested as alice", c.aliceSID, "(sAMAccountName=alice)")
	row("the DC's own `KerberosAuthentication`", c.dcKDC, "(sAMAccountName=DC1$)")
	row("alice's, AD CS `OfflineRouter` (subject from the request)", c.aliceADCS, "(sAMAccountName=alice)")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	b.WriteString("\n| port49's mapping on the DC's certificates (asserted: port49's guarantees, not the DC's) | observed |\n|---|---|\n")
	ev.mark("L44 port49 sid mapping on alice's User certificate")
	r := l.resolverWith(t, l.config("direct", l.groupsBaseDN, l.bindSimple(), directory.Mapping{Kind: directory.MapSID, Attribute: "objectSid"}), l.d.password, ev)
	a, err := r.Map(ctx, c.aliceSID)
	if err != nil || a.Principal != l.principal("alice") {
		t.Errorf("sid did not map alice's User certificate to her: %+v %v", a, err)
	}
	fmt.Fprintf(&b, "| `sid`, alice's `User` certificate | %s as `%s` |\n", errOrOK(err), a.Principal)
	aliceDN := "CN=alice,OU=Staff," + dirBase
	w.setAltSec(t, aliceDN, directory.ADIssuerSerial(c.aliceADCS))
	ev.mark("L44 port49 issuer_serial mapping on alice's OfflineRouter certificate")
	r = l.resolverWith(t, l.config("direct", l.groupsBaseDN, l.bindSimple(), directory.Mapping{Kind: directory.MapIssuerSerial, Attribute: "altSecurityIdentities"}), l.d.password, ev)
	a, err = r.Map(ctx, c.aliceADCS)
	if err != nil || a.Principal != l.principal("alice") {
		t.Errorf("issuer_serial did not map alice's AD CS certificate to her: %+v %v", a, err)
	}
	fmt.Fprintf(&b, "| `issuer_serial`, alice's `OfflineRouter` certificate, alice holding port49's form | %s as `%s` |\n", errOrOK(err), a.Principal)
	if q, qerr := winAltSecQuoted(c.aliceComma); qerr == nil {
		w.setAltSec(t, aliceDN, q)
		ev.mark("L44 port49 issuer_serial on the comma CA's certificate, alice holding the quoted form")
		_, err = r.Map(ctx, c.aliceComma)
		fmt.Fprintf(&b, "| `issuer_serial`, the comma CA's certificate, alice holding the quoted form | %s |\n", errOrOK(err))
	}
	w.setAltSec(t, aliceDN, directory.ADIssuerSerial(l.d.pki.alice))
	return b.String()
}

// l44Matrix offers each certificate to the DC's KDC by PKINIT under each
// KB5014754 setting, alice holding only the altSecurityIdentities the case
// names, and the broker's AD CS certificate to LDAPS by EXTERNAL, recording
// what the KDC answered and logged. A setup failure marks the cell INVALID (R6).
func (l *labDir) l44Matrix(t *testing.T, ev *evidenceLog) string {
	t.Helper()
	w := l.win
	c := w.certs
	port49Form := func(x *x509.Certificate) (string, error) { return directory.ADIssuerSerial(x), nil }
	cases := []l44Case{
		{"adcs-none", "AD CS `OfflineRouter` (UPN SAN, no SID extension)", c.aliceADCS, c.aliceADCSKey, nil},
		{"adcs-port49", "the same, alice holding port49's form", c.aliceADCS, c.aliceADCSKey, port49Form},
		{"adcs-forward", "the same, alice holding the issuer least significant RDN first", c.aliceADCS, c.aliceADCSKey, winAltSecForward},
		{"adcs-unreversed", "the same, alice holding the serial in certificate byte order", c.aliceADCS, c.aliceADCSKey, winAltSecUnreversed},
		{"sid-none", "AD CS `User`, requested as alice (SID extension)", c.aliceSID, c.aliceSIDKey, nil},
		{"comma-port49", "a CA whose CN holds a comma (`lab-users, comma-CA`), alice holding port49's form", c.aliceComma, c.aliceCommaKey, port49Form},
		{"comma-quoted", "the same, alice holding the value quoted as CertNameToStr quotes it", c.aliceComma, c.aliceCommaKey, winAltSecQuoted},
		{"highbit-port49", "the lab users CA, a serial whose top bit is set, alice holding port49's form", c.aliceHighBit, c.aliceHighBitKey, port49Form},
		{"highbit-signbyte", "the same, alice holding the serial with its DER sign byte", c.aliceHighBit, c.aliceHighBitKey, winAltSecSignByte},
	}
	aliceDN := "CN=alice,OU=Staff," + dirBase
	brokerDN := "CN=port49,OU=Svc," + dirBase
	adcsExt := directory.Bind{Mechanism: "external", TLSCertFile: c.brokerCertFile, TLSKeyFile: c.brokerKeyFile}
	var b strings.Builder
	b.WriteString("\n### KB5014754: what the DC itself maps\n\n" +
		"Each certificate is offered to the KDC by PKINIT (MIT `kinit`) as `alice@CORP.EXAMPLE.COM`, alice holding exactly " +
		"the `altSecurityIdentities` the row names; the KDC is restarted after each `StrongCertificateBindingEnforcement` " +
		"change. The last row of each block is the broker's AD CS certificate by SASL EXTERNAL over LDAPS, port49's form on " +
		"its account.\n\n" +
		"| `StrongCertificateBindingEnforcement` | certificate | `altSecurityIdentities` held | outcome | the KDC said | DC events | time |\n" +
		"|---|---|---|---|---|---|---|\n")
	l.setRegistry(t, "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors", 1)
	defer l.setRegistry(t, "UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors", -1)
	for _, mode := range []int{-1, 1, 2} {
		inForce := l.setRegistry(t, "StrongCertificateBindingEnforcement", mode)
		w.checkSkew(t)
		for _, cs := range cases {
			held := ""
			if cs.altsec != nil {
				v, err := cs.altsec(cs.cert)
				if err != nil {
					t.Fatalf("%s: %v", cs.label, err)
				}
				held = v
			}
			w.setAltSec(t, aliceDN, held)
			since := w.clock(t)
			ev.mark("L44 pkinit %s, StrongCertificateBindingEnforcement %s", cs.label, inForce)
			r := w.kinit(t, cs.label, "alice@"+dirRealm, cs.cert, cs.key)
			evs := w.events(t, since)
			ev.add(evidenceLine{Event: "kinit", Label: cs.label + ", enforcement " + inForce, Error: r.kdcSaid(),
				DurationMS: ms(r.took), DCEvents: l44EventStrings(evs)})
			b.WriteString(l44MatrixRow(inForce, cs.what, held, r, evs))
			if ids := l44PreconditionIDs(evs); len(ids) > 0 {
				t.Errorf("L44 %s under %s: the KDC logged %v, a setup failure; the cell is INVALID (R6)", cs.label, inForce, ids)
			}
		}
		w.setAltSec(t, brokerDN, directory.ADIssuerSerial(c.brokerADCS))
		since := w.clock(t)
		ev.mark("L44 external under StrongCertificateBindingEnforcement %s", inForce)
		e := l.tryBind(t, ev, "external, enforcement "+inForce, adcsExt, "")
		evs := w.events(t, since)
		b.WriteString(l44ExternalRow(inForce, e, evs))
		w.setAltSec(t, brokerDN, "")
	}
	l.setRegistry(t, "StrongCertificateBindingEnforcement", -1)
	w.setAltSec(t, aliceDN, directory.ADIssuerSerial(l.d.pki.alice))
	return b.String()
}

// l44MatrixRow is one PKINIT cell.
func l44MatrixRow(enforcement, what, held string, r pkinitResult, evs []winEvent) string {
	outcome := "refused"
	if r.ok {
		outcome = "**TGT issued**"
	}
	if held == "" {
		held = "(none)"
	} else {
		held = "`" + held + "`"
	}
	return fmt.Sprintf("| %s | %s | %s | %s | %s | %s | %s |\n", enforcement, what, held, outcome,
		mdCell(r.kdcSaid()), l44EventsCell(evs), r.took.Round(time.Millisecond))
}

// l44ExternalRow is one EXTERNAL cell in the matrix.
func l44ExternalRow(enforcement string, c l43Cell, evs []winEvent) string {
	outcome := fmt.Sprintf("refused, LDAP result %d", c.code)
	if c.ok {
		outcome = "**bound**"
	}
	return fmt.Sprintf("| %s | the broker's AD CS certificate, SASL EXTERNAL over LDAPS | port49's form, on port49 | %s | %s | %s | %s |\n",
		enforcement, outcome, mdCell(c.text), l44EventsCell(evs), c.took.Round(time.Millisecond))
}

// l44EventsCell is a cell's events, each "<source> <id>: <message's first
// 160 characters>", pipes escaped; "(none)" when there are none.
func l44EventsCell(evs []winEvent) string {
	if len(evs) == 0 {
		return "(none)"
	}
	return mdCell(strings.Join(l44EventStrings(evs), "; "))
}

func l44EventStrings(evs []winEvent) []string {
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		src := e.Provider
		switch {
		case strings.Contains(src, "Kerberos-Key-Distribution-Center") || src == "KDC":
			src = "KDC"
		case strings.Contains(src, "DomainService") || strings.Contains(src, "Directory"):
			src = "DS"
		}
		out = append(out, fmt.Sprintf("%s %d: %s", src, e.ID, oneLineMax(e.Message, 160)))
	}
	return out
}

// l44PreconditionIDs is every KDC event among evs that means the setup
// failed, not the mapping (winKDCPrecondition).
func l44PreconditionIDs(evs []winEvent) []int {
	var out []int
	for _, e := range evs {
		if (strings.Contains(e.Provider, "Kerberos-Key-Distribution-Center") || e.Provider == "KDC") && winKDCPrecondition(e.ID) {
			out = append(out, e.ID)
		}
	}
	return out
}

func mdCell(s string) string { return strings.ReplaceAll(s, "|", `\|`) }
```

Notes for the implementer:
- `refusalChecks` and `mappingChecks` are L43's, and they are generic since Task 1.
- `mappingChecks` uses alice's users-CA mapping, which `reset.ps1` set and `l44SID` restores
  before returning.
- `tryBind` asserts that every refusal names its mechanism and result code (port49's side).

- [ ] **Step 4: Run them and see them pass**

Run: `make lab-unit && go vet -tags lab ./tests/lab/ && gofmt -l tests/lab`

Expected: PASS, with vet and gofmt silent.

- [ ] **Step 5: Commit**

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add tests/lab/l44_test.go tests/lab/windows_unit_test.go
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "test(lab): L44's measurement on the Windows DC

L42's fixture through port49's three nested modes; the root DSE's
capabilities beside OpenLDAP's and Samba's; simple, plain, GSSAPI (as
installed and under LdapEnforceChannelBinding 2) and EXTERNAL mapped and
unmapped; the SID extension against objectSid; and the DC's own mapping by
PKINIT and EXTERNAL under each StrongCertificateBindingEnforcement value.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

---

### Task 6: (lab, on beehive) Measure L44

**Files:**
- Create (by the run): `tests/lab/results/L44-windows_ad.md`, `tests/lab/evidence/L44-windows_ad.json`

**Interfaces:**
- Consumes: Tasks 1–5 at one commit, `<sha>`.
- Produces: the note and its evidence, and a verdict for each cell: measured, INVALID, or a
  defect (Task 7).

- [ ] **Step 1: Pre-flight**, Task 4 Step 5's checks again. Also check that `~/.cache/port49-lab/iso`
holds the ISO from the gate run; the harness re-checks its SHA-256.

- [ ] **Step 2: Run, fresh (R7), from the pinned worktree**

```bash
git -C /home/rwendt/git/port49 worktree add --detach /home/rwendt/git/port49/.worktrees/lab-l44 "$(git -C /home/rwendt/git/port49/.worktrees/l44 rev-parse HEAD)"
cd /home/rwendt/git/port49/.worktrees/lab-l44
sg docker -c "make lab-windows" > /tmp/claude-1000/l44-run.log 2>&1
```

Use the watchdog and a foreground wait with a 240-minute deadline, as in the "Lab rules".

Expected:
- `--- PASS: TestL44WindowsAD`, with `--- PASS: TestL44WindowsAD/compare`.
- `tests/lab/results/L44-windows_ad.md` and `tests/lab/evidence/L44-windows_ad.json` written in
  the pinned worktree.
- Its Image line carries no "reused" mark.

A `t.Errorf` from L42's `recursive` or `direct` assertions, from `mappingChecks` or from `l44SID`
says port49 is wrong: go to Task 7. A `t.Errorf` naming R6 marks an INVALID cell: re-run Step 2,
up to three times in total.

- [ ] **Step 3: Read the note against the claim, cell by cell**

Each cell of the L44 row needs an observation in the note.

| L44 cell | Where in the note | Measured when |
|---|---|---|
| `in_chain` on L42's fixture | "Nested groups", rows `in_chain` | three users' rows present, with a result and a time |
| how the loop is answered | dave's `in_chain` row, or the "loop was not made" line | either present |
| EXTERNAL over LDAPS | "Binds", the three EXTERNAL rows, and the matrix's EXTERNAL rows | a result in each |
| GSSAPI, keytab, no security layer | "Binds", both GSSAPI rows | a result in each |
| `altSecurityIdentities` in port49's form matches what the DC maps | the matrix: `adcs-port49`, `comma-*`, `highbit-*` | none INVALID under any value |
| SID extension = `objectSid` | "The SID extension and objectSid", alice's `User` row | a SID on both sides |
| KB5014754's treatment of each | the matrix, three blocks | none INVALID |
| carried (a) | "The AD capability" | three rows |
| carried (b) | the EXTERNAL rows' LDAP results | present |

Decide the defects, one rule each:
- **7a.** In the block where `adcs-port49` gets a TGT, if `comma-quoted` gets one and
  `comma-port49` does not, port49's `<I>` must quote.
- **7b.** Under the same condition, if `highbit-signbyte` gets a TGT and `highbit-port49` does
  not, port49's `<SR>` must keep the sign byte.
- **7c.** If the unmapped EXTERNAL rows are refused with LDAP result 1, run Task 7c (OR-1).
- **Rule 4.** A doc that says otherwise is fixed in Task 8.

- [ ] **Step 4: Copy back, confirm cleanup, remove the pinned worktree**

```bash
cp /home/rwendt/git/port49/.worktrees/lab-l44/tests/lab/results/L44-windows_ad.md /home/rwendt/git/port49/.worktrees/l44/tests/lab/results/
cp /home/rwendt/git/port49/.worktrees/lab-l44/tests/lab/evidence/L44-windows_ad.json /home/rwendt/git/port49/.worktrees/l44/tests/lab/evidence/
cd /home/rwendt/git/port49/.worktrees/l44 && make evidence && go test ./tests/lab/labpcap/ -count=1
```

Check the "After every run, confirm" list, then
`git -C /home/rwendt/git/port49 worktree remove --force .worktrees/lab-l44`.

- [ ] **Step 5: Commit the note**

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add tests/lab/results/L44-windows_ad.md tests/lab/evidence/L44-windows_ad.json
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "test(lab): L44 measured on Windows Server 2025 AD

Run at <sha>: <one line per cell from Step 3's table, as the note reads>.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

After any Task 7 fix, re-run Steps 1–5 at the fix's commit. The note committed last is the one
Task 8 cites.

---

### Task 7: (only on the defect path) Fixes a Windows result calls for

Each part runs only when Task 6 Step 3's rule for it held. A part that did not run is listed in
Task 8's as-built with the rows that ruled it out. Each part edits the spec first: a `docs:`
commit citing the note. Then comes the `fix(directory)` commit with its unit test, then Task 6 is
re-run at the fix.

**Files (by part):**
- 7a and 7b: modify `internal/directory/mapping.go` (`ADIssuerSerial`) and
  `internal/directory/mapping_test.go`.
- 7c: modify `internal/directory/conn.go` (`bind`) and `internal/directory/conn_test.go`.
- All parts: modify `docs/design/2026-08-23-policy-engine-spec.md` §13 decision 38 (item 1 for
  7a and 7b, items 8 and 9 for 7c) and `docs/design/2026-08-21-port49-design.md` §10 (7c).

**Interfaces:**
- 7a and 7b keep `directory.ADIssuerSerial(*x509.Certificate) string` and change only its
  output.
- 7c keeps `directory.Refusal(error) bool`. An EXTERNAL bind answered 1 now `errors.Is`
  `ErrBindRefused`.

- [ ] **7a, Step 1: The failing test** (append to `internal/directory/mapping_test.go`)

```go
// A Windows DC maps an issuer whose RDN value holds a comma only in the form
// CertNameToStr writes, the value quoted (L44, tests/lab/results/L44-windows_ad.md).
func TestADIssuerSerialQuotesAsWindowsDoes(t *testing.T) {
	ca, key := issuingCA(t, pkix.RDNSequence{{{Type: oidDC, Value: "com"}}, {{Type: oidDC, Value: "corp"}},
		{{Type: oidCN, Value: `corp, "east" CA`}}})
	if got := ADIssuerSerial(issue(t, ca, key, nil)); got != `X509:<I>DC=com,DC=corp,CN="corp, ""east"" CA"<SR>11AC0000000012` {
		t.Fatalf("%s", got)
	}
}
```

Run: `go test ./internal/directory/ -run TestADIssuerSerial -count=1`. Expected: FAIL (the value
is unquoted).

- [ ] **7a, Step 2: Implement** in `mapping.go`. In `ADIssuerSerial`, change
`typeName(atv.Type)+"="+fmt.Sprint(atv.Value)` to `typeName(atv.Type)+"="+adQuote(fmt.Sprint(atv.Value))`
and add:

```go
// adQuote is an RDN value as Windows' CertNameToStr writes it in
// altSecurityIdentities (L44): quoted when it is empty, starts or ends with
// white space, or holds , + = " \ < > # ; or a newline, an inner quote doubled.
func adQuote(v string) string {
	if v == "" || strings.ContainsAny(v, ",+=\"\\<>#;\n") || strings.TrimSpace(v) != v {
		return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
	}
	return v
}
```

Update `ADIssuerSerial`'s comment ("L44 measured Windows' quoting"). In
`tests/lab/windows_unit_test.go`, `TestWindowsAltSecForms`, the `port49` and `signbyte` cases now
expect the quoted issuer. The test that the lab's `winForm{}.of` equals `ADIssuerSerial` becomes
`winForm{quoted: true}.of`: the lab offers port49's (now quoted) form as `port49Form` through
`directory.ADIssuerSerial` itself.

Run: `go test ./internal/directory/ -count=1 && make lab-unit`. Expected: PASS.

- [ ] **7b, Step 1: The failing test**

```go
// A Windows DC maps a serial whose top bit is set only with its DER sign byte
// kept in <SR> (L44, tests/lab/results/L44-windows_ad.md).
func TestADIssuerSerialKeepsTheSignByte(t *testing.T) {
	c := leaf(t, func(c *x509.Certificate) { c.SerialNumber = new(big.Int).SetBytes([]byte{0x80, 0x01, 0x02}) })
	if got := ADIssuerSerial(c); !strings.HasSuffix(got, "<SR>02018000") {
		t.Fatalf("%s", got)
	}
}
```

Run it. Expected: FAIL (`<SR>020180`).

- [ ] **7b, Step 2: Implement.** In `ADIssuerSerial`, after `b := leaf.SerialNumber.Bytes()`:

```go
	// DER keeps a 00 before a serial whose top bit is set; Windows' <SR> is
	// the encoded bytes reversed, that 00 included (L44).
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
```

The existing `TestADIssuerSerial` (`0x1200000000AC11`) is unchanged. In
`tests/lab/windows_unit_test.go`, the `port49` case for the high-bit certificate now equals
`signbyte`'s. Run: `go test ./internal/directory/ -count=1 && make lab-unit`. Expected: PASS.

- [ ] **7c (OR-1), Step 1: The failing test** (append to `internal/directory/conn_test.go`)

```go
// An EXTERNAL bind the directory will not map is answered 1 (operations
// error) by Samba and Windows (L43, L44): the broker's certificate refused,
// not the server down, so it starts the hold-off and opens no breaker. On a
// simple bind, 1 is still neither.
func TestAnExternalBindAnsweredOneIsARefusal(t *testing.T) {
	ext := &Credentials{mech: "external", who: "CN=port49-broker"}
	err := bind(context.Background(), ldapBindServer(t, ldap.LDAPResultOperationsError, "unmapped"), Server{URI: "ldaps://dc-01"}, ext)
	var le *ldap.Error
	if !Refusal(err) || Fault(err) || !errors.As(err, &le) || le.ResultCode != ldap.LDAPResultOperationsError ||
		!strings.Contains(err.Error(), "bind external as CN=port49-broker: LDAP result 1") || strings.Contains(err.Error(), "unmapped") {
		t.Fatalf("%v", err)
	}
	simple, _ := LoadCredentials(Bind{Mechanism: "simple", BindDN: "CN=port49,DC=corp", PasswordEnv: "P"}, func(string) string { return "pw" })
	err = bind(context.Background(), ldapBindServer(t, ldap.LDAPResultOperationsError, ""), Server{URI: "ldaps://dc-01"}, simple)
	if Refusal(err) {
		t.Fatalf("a simple bind answered 1 became a refusal: %v", err)
	}
}
```

Run: `go test ./internal/directory/ -run TestAnExternalBindAnsweredOneIsARefusal -count=1`.
Expected: FAIL (`Refusal` is false).

- [ ] **7c, Step 2: Implement** in `bind` (`conn.go`). Replace the `errors.As(err, &le)` block's
return with:

```go
	if errors.As(err, &le) {
		cause := fmt.Errorf("bind %s as %s: LDAP result %d", cr.mech, cr.who, le.ResultCode)
		if le.ResultCode >= 200 && le.Err != nil {
			cause = fmt.Errorf("bind %s as %s: LDAP result %d: %v", cr.mech, cr.who, le.ResultCode, le.Err)
		}
		e := &ldap.Error{ResultCode: le.ResultCode, MatchedDN: le.MatchedDN, Err: cause}
		// An EXTERNAL bind a directory will not map is answered 1 by Samba
		// and Windows (L43, L44): the certificate refused, not the server down.
		if cr.mech == "external" && le.ResultCode == ldap.LDAPResultOperationsError {
			return fmt.Errorf("%w: %w", ErrBindRefused, e)
		}
		return e
	}
```

Update `Refusal`'s comment to name "or an EXTERNAL bind answered 1 (L43, L44)".

Spec first (`docs:` commit):
- Decision 38 item 9's list becomes "(LDAP 49, 48, 8, 13 or 7, 1 on an EXTERNAL bind (L43, L44),
  a KDC's refusal)".
- Item 8's "port49 counts 1 as a server fault, so configure `simple` or `gssapi` against Samba"
  becomes "port49 counts 1 on an EXTERNAL bind as a refusal (L44): the hold-off, not a dark pool".
- Design §10 item 1 is changed to match.

Run: `go test ./internal/directory/ -count=1 && make test && make vet`. Expected: PASS.

- [ ] **Each part, Step 3: Commit** (one `docs:` commit, then one `fix(directory)` commit per
part)

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "docs: <the rule> as a Windows DC measured it (L44)

tests/lab/results/L44-windows_ad.md: <the rows>. Rule 4: the doc followed the lab.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
git -C /home/rwendt/git/port49/.worktrees/l44 add internal/directory tests/lab/windows_unit_test.go
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "fix(directory): <7a: quote <I> values as Windows does | 7b: keep the serial's sign byte in <SR> | 7c: an EXTERNAL bind answered 1 is a refusal>

L44 (tests/lab/results/L44-windows_ad.md) <the rows that showed it>.

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

Then re-run Task 6 at the fix. Expected: the matrix's `comma-port49` (7a) or `highbit-port49`
(7b) row gets the TGT its quoted or sign-byte twin got. For 7c, `tryBind`'s refusal text is
unchanged.

---

### Task 8: Close L44 (or narrow it) and record what was built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md`: §15 row L44, and §13 decision 38
  items 1, 6 and 8 (and 9 if 7c ran).
- Modify: `docs/design/2026-08-21-port49-design.md`: §7 (the "A Windows DC's behaviour is
  register row L44's" sentence) and §10 items 1 and 2.
- Modify: `docs/superpowers/plans/README.md`: the status line; "Plan 7g — As built" (the "Lab"
  bullet, "Unassigned", the operator notes "Nested groups" and "The binds", and "Open for the
  final review" (a) and (b)); a new "L44 — As built" subsection after "Plan 7g — As built".

**Interfaces:** none (docs).

- [ ] **Step 1: The register row (rule 3)**

**If every cell in Task 6 Step 3's table is measured and none is INVALID,** set the L44 row as
follows.
- Platform: `Windows Server AD (Windows Server 2025 Standard Evaluation, build <build from the note>)`.
- Status: `closed — measured <date>; tests/lab/results/L44-windows_ad.md`.

**Otherwise the row stays open.** Its Status is then
`open — measured <date> except <the INVALID or unmeasured cells, and why>; tests/lab/results/L44-windows_ad.md`.

- [ ] **Step 2: Decision 38's L44 marks**, replaced only for the cells measured (rule 2). Each
sentence states what the note shows.
- **Item 1.** Replace "`issuer_serial` and `sid` are provisional on L44 (Windows Server AD)."
  with "Measured on Windows Server 2025 AD (L44, closed):", followed by:
  - for `issuer_serial`: whether the DC issued a TGT for port49's form, in every enforcement
    block, on AD CS's issuer, on a comma issuer (with 7a's outcome), and on a high-bit serial
    (with 7b's outcome);
  - for `sid`: whether the `User` certificate's SID extension equalled alice's `objectSid`, and
    whether the KDC accepted it with no `altSecurityIdentities`;
  - whether `StrongCertificateBindingEnforcement` 1 changed anything on this build.
- **Item 6.** Replace "On Windows Server AD, provisional on L44." with what `in_chain` returned
  for the three users, how the loop was answered, the time, and whether `memberOf` listed direct
  groups only.
- **Item 8.** Replace "On Windows Server AD, provisional on L44." with the EXTERNAL results
  (mapped, unmapped and their codes), GSSAPI as installed and under `LdapEnforceChannelBinding 2`,
  and the plain-LDAP simple bind's code.
- **Rule 4.** A result that contradicts any existing sentence of items 1, 6, 8 or 9 rewrites
  that sentence, and the commit message says so.

- [ ] **Step 3: The design.** In §7, replace "A Windows DC's behaviour is register row L44's, open
until measured." with the measured outcome, one sentence, citing the note. In §10 items 1 and 2,
replace "Windows Server AD is L44's" with the measured outcome, citing the note. If GSSAPI was
refused under `LdapEnforceChannelBinding 2`, item 2 gains: "port49 sends no channel binding token;
a DC that requires one (`LdapEnforceChannelBinding = 2`) refuses its GSSAPI bind: use `external`
or `simple` there (L44)."

- [ ] **Step 4: The roadmap README**
- **Status line.** After the "7h pre-flight" sentence, add "**L44 executed <date>** on
  `feature/l44-windows-ad`, each task reviewed; L44 <closed | narrowed> on Windows Server 2025
  AD (L44 — As built, below)."
- **"Plan 7g — As built".**
  - The "Lab" bullet's L44 sentence becomes the outcome.
  - "Unassigned: L44 ..." is deleted.
  - The operator notes gain Windows lines under "Nested groups need the right mode per directory"
    and "The binds", stating which `nested_groups` mode and which bind a Windows DC accepts.
  - If GSSAPI was refused under channel binding 2, add the CBT note and OR-3's outcome.
- **"Open for the final review".**
  - **(a)** becomes: "Measured (L44): `1.2.840.113556.1.4.800` is advertised by <Windows: yes/no>,
    <Samba: yes/no>, <OpenLDAP: yes/no>; a warning keyed on it would <tell in_chain's directories
    apart | not>." The warning stays parked.
  - **(b)** becomes the measured codes, and 7c's outcome (OR-1).
- **"L44 — As built".** One bullet per task with its commits, the deviations from this plan, the
  rulings R1–R8 as they stood, and the Ryan answers OR-1 to OR-3.

- [ ] **Step 5: Verify and commit**

Run: `make test && make vet` in `.worktrees/l44`, and report the real output. Expected: PASS.

```bash
git -C /home/rwendt/git/port49/.worktrees/l44 add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md docs/superpowers/plans/README.md
git -C /home/rwendt/git/port49/.worktrees/l44 commit -m "docs: close lab register entry L44 on Windows Server 2025 AD

tests/lab/results/L44-windows_ad.md. Decision 38 items 1, 6 and 8 state what
the DC measured; design §7 and §10 follow (rule 4 where they differed).

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_01KRDnCbmkhchGxXvV99W4mc"
```

If the row stays open, the subject is `docs: narrow lab register entry L44 to what Windows Server
2025 AD measured`.

---

## Questions for Ryan (each with a recommendation; the plan proceeds on the recommendation)

- **OR-1. Carried question (b): if a Windows DC answers an unmapped EXTERNAL bind with LDAP
  result 1, should `Refusal` count it?**
  - **Recommended: yes, for EXTERNAL only** (Task 7c), with the spec edited first.
  - Today, result 1 opens every DC's breaker, so the pool goes dark and grace serves; the operator
    sees "server down".
  - As a refusal, it starts PF7g-g's hold-off, which says "refused" with the code hourly. That
    names the real fault, an unmapped or rotated broker certificate. No lockout counter applies
    to a certificate.
  - If Windows answers 49, 48 or 7 instead, nothing changes, and the Samba note stands as
    Samba's alone.
- **OR-2. Close L44 on Windows Server 2025 alone?**
  - **Recommended: yes** (R1). The 2022 evaluation media predate KB5014754 entirely and would need
    online updates that no run can reproduce.
  - 2025's new-forest defaults differ from an upgraded 2022 domain's (signing enforcement; channel
    binding "when supported" against "never"). The operator notes say so.
  - The alternative is a new row, L48, for Windows Server 2022, opened and left for later.
- **OR-3. If GSSAPI is refused under `LdapEnforceChannelBinding = 2`, which is likely because
  port49 sends no channel binding token:**
  - **Recommended: document it** (Task 8), and carry "GSSAPI with channel binding" to the
    pre-beta review as a hardening item.
  - Adding CBT means changing go-ldap's GSSAPI client and the bind's design. That is a feature,
    not a lab fix, and L44 must stay disjoint from 7h.
  - Operators who enforce channel binding have `external` (which channel binding does not apply
    to) and `simple`.
