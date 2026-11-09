# Fence Short Texts (#60) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every refusal the file fence words itself gets a short form. Every line that cuts an error a fence read can carry uses that form, so a refusal keeps its cause, the value seen against the value wanted, its remedy and the tail of each path inside the cut, at any path length (#60). These lines are the enrollment store's 300-byte lost reason, the kept-CRL start lines (300) and the TLS listener's trust-follow lines (400). Every reader that is not cut keeps today's full text.

**Architecture:**
- `internal/fence` gains a typed error, `*fence.Refusal`.
  - Its `Error()` is today's text, byte for byte.
  - Its `Short()` is a bounded form with each path cut to its last 32 bytes.
- `fence.Brief(err)` puts the short form in place of the full one inside whatever wraps it.
- Users of the short form:
  - the enrollment store, and port49d's wrap of `enrollfile.Open`;
  - port49d's new `briefLine(err, limit)`, used at the five cut lines that can carry a fence error (Task 3).
- `certStatusConfig` stops repeating an issuer_file's path in front of a fence error that already names it.
- Nothing else changes.
- No new reason code, warning, config key or metric. No lab run.

**Tech Stack:** Go 1.26 (`internal/fence`, `internal/store/enrollfile`, `internal/port49d`), one MkDocs page under `docs/site`.

**Issue:** #60. It was found during #58 (plan `2026-11-09-small-fixes.md`, Task 5), which bounded only the reasons enrollfile words itself.

## Root causes (investigation 2026-11-09, `main` `1ace8f55`)

1. **The texts.** `internal/fence/fence_linux.go` words these refusals itself. Each names its full path, and some name two:

   | Text | Built at | Paths |
   |---|---|---|
   | owner (`... is owned by uid N; ... - chown it`) | `ownedByUsOrRoot`, `:523-533` | one |
   | owner unreadable (`...: cannot read its owner`) | `:526` | one |
   | mode (`... is mode M, writable by others than its owner; ... - ADVICE`) | `notWritableByOthersAdvising`, `:576-589` | one |
   | not a regular file | `readChecked`, `:352` | one |
   | over the size bound | `readChecked`, `:364` | one |
   | more than 40 links | `resolvePolicyPath`, `:420` | one |
   | a link in the file's own name | `linkRefused`, `:296-299` (wraps the ELOOP `PathError`) | two, the second inside the wrapped `PathError` |

   The owner and mode texts are each worded for four kinds of subject:
   - the file, or the secret file (`readIn` `:333`, `ReadSecret` `:178`);
   - the directory holding the file (`readIn` `:340`, `ReadSecret` `:214`);
   - `the directory D, holding the WHAT` (`CheckDir` `:291`);
   - the directory holding a link: `the directory D, holding the symbolic link L` (`:427`), which names two paths;
   - an ancestor: `the directory D (above P)` (`ancestorWritableByUsAlone` `:461`), which names two paths, and whose mode remedy is the long "or, if others share it, move the file under directories only root or uid N can write" (`:467-468`).

   `ReadSecret` has texts of its own: the secret mode (`:182-184`), the group (`groupIsOurs`), the ACL texts (`acl_linux.go`), the hard link (`:224`) and `within` (`:146-162`). Those reach no reader that cuts at 300 (root cause 3).

2. **Where the 300-byte cut takes them.** The enrollment store is the only fence caller whose text reaches it:
   - **At start.** `read` (`internal/store/enrollfile/enrollfile.go:94-99`) puts the fence's text inside `readFailure`'s `it cannot be read (...)` (`:168`). The fence's own words are not a `PathError`, so they go in whole, path included. `lostErr` (`:222-227`) then adds `store: the enrollment store is lost: <shown path>: `.
   - **Late, at a recheck.** `pickUpLate` (`:131-143`) builds the same text and adds `; this broker looks again at its next recheck, with no restart`.
   - **At `Open`.** A refusal from `fence.CheckDir` (the directory, an ancestor, a link's directory, more than 40 links) or a link at the path (`read`'s ELOOP case, `:92-93`) is an `Open` error. `openEnrollmentFile` (`internal/port49d/signin.go:256-262`) wraps it whole with `%v`.
   - **The cut.** All three reach `Broker.CheckEnrollmentStore` (`internal/broker/signin.go:939-940`) and `lostWhy` (`:975-980`), each `printsafe.Line(err.Error(), 300)`. From there the reason goes to two readers:
     - the broker's log line, `sign-in: the enrollment store is lost (%s): ...` (`markEnrollmentStore`, `:966-970`);
     - the admin CLI's stderr through `signin_admin.go:158`, `:184`, `:330`, `:340` and `:429` (`broker: the enrollment store is lost (%s): <lostRemedy>`).
   - The sign-in API's answer is the fixed `lostText` and carries no reason.
   - The issue's table (owner 400 bytes at a 32-byte path, ancestor 459) is this composition.

3. **Most other readers take the full text, and do not cut it.**
   - **Start errors:** port49d and the broker refuse to start, naming the path (`cmd`/`run`). The policy, inventory, file source, verify keys, the TLS and CA files, krb5.conf, the persisted bundle and the revocations file all report this way.
   - **Reload log lines:** the policy and inventory reloads, `l.refuse`.
   - **`tests/systemd/sdtest/sdtest.go`** matches these full texts in journal lines (`:122-129`, `:358-361`).
   - **`docs/site/operate/secrets.md:100`** quotes the group text.

   Five more log lines cut a line that can carry a fence text. Task 3 fixes them all:

   | Site | Cut | What the error is |
   |---|---|---|
   | `internal/port49d/main.go:1285`, port49d's in-process broker at start | 300 | `kept CRL NAME: <fence error>` from `certstatus.(*Checker).LoadPersisted` (`internal/certstatus/crl.go:452`, `fence.ReadNoLink` on `<state dir>/crl-NAME.der`, wrapped at `:463`) |
   | `internal/port49d/brokerd.go:771`, port49-broker at start | 300 | the same, from `broker.state_dir` |
   | `internal/port49d/tlslistener.go:574`, the TLS listener at start | 300 | the same, from `tls_listener.state_dir`. The lead's list missed this site, which is the same code |
   | `internal/port49d/tlslistener.go:215`, a trust follow after a rotation | 400 | `tls_listener.certificate_status.crls[N].issuer_file PATH: <fence error>`, from `followStatus` (`:598-602`) → `certStatusConfig` (`certstatus.go:35-39`) → `readIssuerFile` (`fence.Read`) |
   | `internal/port49d/tlslistener.go:218`, a trust follow with no rotation | 400 | the same |

   - **The kept-CRL lines.** Their wrapper names the source, not the path, so `fence.Brief` alone keeps them in the cut: `kept CRL ` + NAME + `: ` + at most 192 bytes.
   - **The trust-follow lines.** Their wrapper, `certStatusConfig`'s key, repeats the issuer_file's full path in front of a fence text that already names it. `Brief` alone is not enough there: at a 260-byte path the wrapper's copy of the path takes the line to 422 bytes, past the 400-byte cut. That wrapper is fixed too (ruling 9).
   - **Out of reach of this fix:** `certstatus/crl.go:508`, a CRL source `file:` read by `readCRLFile` (`:601`). It is not a fence read, and its texts do not name the path twice.

4. **`errors.Is` and `errors.As` today.**
   - Every fence text is a bare `fmt.Errorf` with no `%w`, except `linkRefused`, which wraps the `PathError{Op: "open", Err: ELOOP}`. The ACL texts' `%w` lives only in `ReadSecret`, which this plan does not touch.
   - Callers match these:
     - `errors.Is(err, fs.ErrNotExist)`: `certstatus/crl.go:453`, `enrollfile.go:90` and `:124`, `inventory/state.go:111`, `port49d/revocations.go:67`, `port49d/coldstart.go:40` and `keyfile.go:132`. That error is an `os` error the fence passes through unchanged.
     - `errors.Is(err, syscall.ELOOP)`: `enrollfile.go:92` and `:161`, and `fence.ReadNoLink` `:266`. It comes from `linkRefused` or the raw `Openat` error.
     - `errors.As(err, &*fs.PathError)`: `enrollfile.go:163` and `:165`. They are reached only after the ELOOP case.
   - The same holds after this plan, because:
     - a `Refusal` whose `err` is nil unwraps to nothing, as a bare `fmt.Errorf` does;
     - `linkRefused`'s `Refusal` unwraps to the same `PathError`;
     - no `os` error is touched.

## Rulings made in this plan

1. **The fence keeps its full texts. The short form is a second rendering of the same refusal, used only on a line that is cut.**
   - Why not shorten every text:
     - A start error and an uncut log line have room. There, the operator is best served by the whole path, not a tail.
     - `sdtest` and the docs quote the full texts.
     - The cut applies in six places: the enrollment store's reason, and the five lines of root cause 3.
   - What each reader sees:

     | Reader | Text |
     |---|---|
     | Start error, reload line, CLI that reads a file itself, `sdtest`'s journal match | Today's full text, byte for byte |
     | Broker's `sign-in: the enrollment store is lost (...)` line, and admin CLI stderr carrying `lostWhy` | `store: the enrollment store is lost: ` + the fence's short form (+ `; this broker looks again ...` when late) |
     | `certificate status: kept CRL NAME: ...` at start (port49d, port49-broker, the TLS listener) | `kept CRL NAME: ` + the fence's short form |
     | `tls_listener: WHY: the certificate status sources keep the issuers they had ...: ...` | `tls_listener.certificate_status.crls[N].issuer_file: ` + the fence's short form |
     | A start error from `certStatusConfig` (`crls[N].issuer_file` refused by the fence) | `...crls[N].issuer_file: ` + the fence's full text, which names the path whole. Before, the path came twice |
2. **The short form's shape:** `<subject with tailed paths>: <value seen>, wants <value wanted> - <remedy>`.
   - Each path is `printsafe.Tail(p, 32)`, at most 35 bytes.
   - A two-path text names both, each tailed.
   - Uids are printed whole. At 10 digits each, the longest form is the ancestor's mode refusal, at 191 bytes.
   - `Short()` caps the form at `shortMax = 192` with `printsafe.Line` as a backstop. The tests prove the cap is never reached.
   - The late reason puts 99 bytes around it (`store: the enrollment store is lost: ` 37, `; this broker looks again at its next recheck, with no restart` 62). That leaves at most 291 bytes against the cut of 300.
   - 32, not #58's 40: at 40 the ancestor's two tails take the late reason past 300.
3. **The enrollment store names the path once.** A fence refusal names its own paths, so the lost reason drops its own `<shown path>: ` prefix for that case, along with the `it cannot be read (...)` wrapper and its generic remedy.
   - The fence's remedy is specific (chown, chmod, shorten the chain).
   - The broker's line and `lostRemedy` already add the store-level remedies: restore, import, `reset-second-factor --all`.
   - The lost reason (`f.lost`) now holds the whole why, path included. Every reason that is not a fence refusal stays byte-identical to today (#58's texts and tests are unchanged).
4. **A link at the store's path keeps #58's words** (`it is a symbolic link, and the enrollment store is read only as a file of its own: fix its owner and mode, or remove a link`).
   - The ELOOP test stays first, before the `Refusal` test, because `linkRefused` is now a `Refusal` that wraps ELOOP.
   - That text already fits.
   - At `Open`, a link at the path goes through `Brief`, which gives the fence's short link text.
5. **`ReadSecret`'s own texts stay plain errors, with no short form.** Those are the secret mode, group, ACL, hard link and `within` texts. They reach start errors and reload lines only (root cause 3), and `Brief` returns them unchanged. The owner and mode helpers `ReadSecret` shares get a short form anyway.
6. **`fence.Brief` also tails an `fs.PathError`'s path.** An `Open` failure such as `open <dir>: permission denied` from `openDir` names a full path. `Brief` makes it `open …<tail>: permission denied`, so the start reason fits too.
7. **No new reason code, warning or config key is needed.** None is added.
8. **One helper for every cut line that can carry a fence error:** `briefLine(err error, limit int) string`, which is `printsafe.Line(fence.Brief(err), limit)`, in `internal/port49d/certstatus.go`. It is used at all five sites of root cause 3, so a later site has one call to copy. The cut lengths stay as they are: 300 for the kept CRL, 400 for the trust follow.
9. **`certStatusConfig` names an issuer_file's path only when the error does not name it already.**
   - An error whose own text already names the issuer_file's exact path (`strings.Contains(err.Error(), path)`: the fence's refusals of the file itself) gets the key `crls[N].issuer_file`, without the path. Any other error keeps `crls[N].issuer_file PATH`, as today: the PEM, CA and anchor texts, and a fence error that names an ancestor directory, a link or an `openDir` instead of the file. The path is never lost (ruling, fix round 1).
   - This is the trust-follow lines' fix: `Brief` cannot tail a path that the wrapper prints as plain text.
   - It also removes the doubled path from the start error, which still names the path whole in the fence's full text.
   - When the issuer_file is a link, the fence names the target it refused. The key then names the config entry and the fence names the file, which is what the operator has to fix.
10. **brokerd.go's site has no end-to-end test.** No port49d test harness starts port49-broker with `certificate_status` on: `brokerd_test.go:129` and `issuerrecord_linux_test.go:45` run it disabled. Building one is out of proportion to a one-call change. The site is pinned instead by a source test that every `LoadPersisted()` loop in port49d calls `briefLine(err, 300)`. That test is red for every site before Task 3. The other four sites each get an end-to-end red test.

## What an operator sees at 3am

The store is `/var/lib/port49/enrollments.json` (32 bytes, so its tail is the whole path), and port49 runs as uid 999. A restore left the file root's:

| | Text the broker logs, inside `sign-in: the enrollment store is lost (...)` |
|---|---|
| Before | `store: the enrollment store is lost: /var/lib/port49/enrollments.json: it cannot be read (the file /var/lib/port49/enrollments.json is owned by uid 0; whoever can write it decides who gets access, so it must belong to the user this process runs as (uid 999) or to root - chown it): fix its owner and mode, restore it, or run ` then cut at 300, with the command cut off |
| After | `store: the enrollment store is lost: the file /var/lib/port49/enrollments.json: owner uid 0, wants uid 999 or root - chown it` |

At a 260-byte path with a group-writable ancestor, found at a recheck:

| | Text |
|---|---|
| Before | 942 bytes, cut at 300 inside the first path |
| After | `store: the enrollment store is lost: the directory …<last 32 of D> above …<last 32 of the store's directory>: mode drwxrwxrwx, wants no group or other write - chmod go-w it, or move the file out from under it; this broker looks again at its next recheck, with no restart` (at most 290 bytes) |

Longest reason after the fix, at a 260-byte path, 10-digit uids and the late reason (`what` = `enrollments file`):

| Fence text | Before (#60 table) | After, late | After, at `Open` |
|---|---|---|---|
| not a regular file | 504 | 219 | — |
| over maxFile | 543 | 220 | — |
| file owner | 655 | 206 | — |
| file mode | 607 | 207 | — |
| directory mode (sticky) | 595 | 221 | 189 (`CheckDir`'s `, holding the enrollments file`) |
| ancestor mode | 942 | 290 | 228 |
| ancestor owner | — | 253 | 191 |
| more than 40 links | 508 | 210 | 148 |
| directory holding a link, mode (sticky) | over 942 | 274 | 212 |
| directory holding a link, owner | — | 264 | 202 |
| a link in the file's own name | — | #58's text | 169 |

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case for data. Reason codes come only from spec §5.7 and warnings only from spec §12. This plan adds neither, and adds no config key or metric.
- The log never contains a credential, token, challenge or response. Credentials appear only as `credential_sha256`. Short forms carry paths, uids, modes and sizes, never file content, and no error carries a file's bytes.
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, or key files.
  - Every recursive grep excludes them. grep is ugrep: use `-e PATTERN`, never `--` before a pattern. Never grep `tests/lab/logs` or `tests/lab/captures`.
  - If a safety check refuses a command, stop and report it. Never rephrase it.
  - Edit repo files with the Edit/Write tools, never sed, perl, python or heredocs.
  - Foreground runs only.
- **Tests:**
  - `TMPDIR` is one short private directory on ext4: `export TMPDIR=$(mktemp -d ~/.cache/p49t.XXXX) && chmod 700 $TMPDIR`. On this host `/tmp` is tmpfs, where the ACL tests that `mustpass` requires skip. `acl` is installed, so they run.
  - Before the final review, run `make test && make vet && make docs && make test-rest` from that TMPDIR, and `go test ./tests/ci/` for the docs edit. Report the real output.
  - `git status --short` after `make docs` shows no diff.
  - A failure under this TMPDIR that this plan does not name is reported, not fixed in passing.
- **Commits:**
  - Conventional Commits, one per task, with an explicit pathspec.
  - Every message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and nothing else. No `Claude-Session:` line, and no claude.ai URL anywhere: commits, PR body, comments.
- **Branch:** `fix/fence-texts-60`, from `main` `1ace8f55`, in `.worktrees/fence-texts-60`. Tasks run in order: Task 3 uses Task 2's test helper `deepEnrollDir`, and Task 4 quotes Task 2's text.
- **Lab:** none. No device behavior changes, and no §15 row is cited or changes status.

## Review Focus

1. **`Error()` is unchanged, byte for byte, for every converted text.** Diff each old `fmt.Errorf` format against its new `full` `fmt.Sprintf`. `linkRefused`'s `%w` becomes `%v` in `full`, which renders the same. `TestTheFullTextOfARefusalIsUnchanged` pins two of them exactly.
2. **`errors.Is` and `errors.As` are unchanged** (root cause 4). `Refusal.Unwrap` returns nil except in `linkRefused`. The new fence test asserts that ELOOP and `*fs.PathError` are seen for the link case and for no other case.
3. **Every short form keeps the cause, the value seen, the value wanted, the remedy and each path's tail** within `shortMax`, at 260 bytes with 10-digit uids and the longest `what`. Each class has a mutation.
4. **Non-fence lost reasons are byte-identical.** All #58 tests in `enrollfile_test.go` pass unchanged, except the two assertions Task 2 rewrites, which are named there.
5. **The ELOOP test still comes before the `Refusal` test** in `(*File).failed`.
6. **Every cut line that can carry a fence error goes through `briefLine`,** and only those lines do. `issuerKey` drops the path only for a fence error, so the PEM, CA and anchor errors still name it (`certstatus_test.go:248` passes unchanged).

---

### Task 1: the fence words a short form of each refusal it makes (#60)

**Files:**
- Create `internal/fence/refusal.go` (no build tag; it uses `printsafe`, which imports only the standard library):
  - `Refusal` and its methods;
  - `Brief`, `shown`, `shortPathMax` and `shortMax`.
- Create `internal/fence/refusal_test.go` (no build tag).
- Modify `internal/fence/fence_linux.go`:
  - add `subject`, `named` and `kindOf`;
  - convert the texts of root cause 1, except `ReadSecret`'s own.
- Create `internal/fence/short_linux_test.go`.

- [ ] **Step 1: Write the failing tests.**

  `internal/fence/refusal_test.go`:

  ```go
  package fence

  import (
  	"errors"
  	"fmt"
  	"io/fs"
  	"strings"
  	"testing"
  )

  // Brief puts a Refusal's Short in place of its full text inside whatever
  // wraps it, names a PathError's path by its tail, and leaves any other
  // error's text as it is (#60).
  func TestBriefShortensOnlyWhatTheFenceNames(t *testing.T) {
  	long := "/" + strings.Repeat("d", 250) + "/enrollments.json"
  	tail := "…" + long[len(long)-shortPathMax:]
  	r := &Refusal{full: "the file " + long + " is wrong", short: "the file " + shown(long) + ": wrong - fix it"}
  	if got, want := Brief(fmt.Errorf("verify_key_files[0]: %w", r)), "verify_key_files[0]: the file "+tail+": wrong - fix it"; got != want {
  		t.Errorf("a wrapped refusal: %q, want %q", got, want)
  	}
  	pe := &fs.PathError{Op: "open", Path: long, Err: fs.ErrPermission}
  	if got, want := Brief(fmt.Errorf("x: %w", pe)), "x: open "+tail+": permission denied"; got != want {
  		t.Errorf("a path error: %q, want %q", got, want)
  	}
  	if got := Brief(errors.New("plain")); got != "plain" {
  		t.Errorf("another error: %q", got)
  	}
  	if got := Brief(nil); got != "" {
  		t.Errorf("nil: %q", got)
  	}
  }
  ```

  `internal/fence/short_linux_test.go`:

  ```go
  //go:build linux

  package fence

  import (
  	"errors"
  	"fmt"
  	"io/fs"
  	"os"
  	"path/filepath"
  	"strconv"
  	"strings"
  	"syscall"
  	"testing"
  )

  const (
  	bigUID  = 4294967295                        // the longest uid a refusal names, as an owner
  	ourUID  = 4294967294                        // and as this process's
  	longest = "broker.directory.bind.krb5_conf" // the longest what a caller passes (internal/directory/conn.go)
  	pathLen = 260                               // the issue's long path (#60)
  )

  // deepDir makes a directory, mode 0755, such that name inside it is a path of
  // exactly n bytes, built from components of at most 50 bytes so its parents
  // are long too.
  func deepDir(t *testing.T, n int, name string) string {
  	t.Helper()
  	dir := safeDir(t)
  	for {
  		rest := n - len(dir) - 1 - len(name) // bytes still to add, each component with its slash
  		if rest == 0 {
  			return dir
  		}
  		if rest < 2 {
  			t.Fatalf("TMPDIR %s is too long for a %d-byte path", os.TempDir(), n)
  		}
  		k := min(rest-1, 50)
  		if rest-1-k == 1 {
  			k-- // never leave one byte, which no component can fill
  		}
  		dir = filepath.Join(dir, strings.Repeat("d", k))
  		if err := os.Mkdir(dir, 0o755); err != nil {
  			t.Fatal(err)
  		}
  	}
  }

  // ownedBy makes the fence see this process as ourUID, every inode as
  // ourUID's, and the inode at path as bigUID's: an owner refusal with the
  // longest values, as root or not.
  func ownedBy(t *testing.T, path string) {
  	t.Helper()
  	fi, err := os.Lstat(path)
  	if err != nil {
  		t.Fatal(err)
  	}
  	ino := fi.Sys().(*syscall.Stat_t).Ino
  	owner, euid := FileOwner, Geteuid
  	t.Cleanup(func() { FileOwner, Geteuid = owner, euid })
  	Geteuid = func() int { return ourUID }
  	FileOwner = func(fi fs.FileInfo) (uint32, bool) {
  		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == ino {
  			return bigUID, true
  		}
  		return ourUID, true
  	}
  }

  func chmodT(t *testing.T, p string, m fs.FileMode) {
  	t.Helper()
  	if err := os.Chmod(p, m); err != nil {
  		t.Fatal(err)
  	}
  }

  // policyFile writes minimalPolicy at p and gives it perm, whatever the umask.
  func policyFile(t *testing.T, p string, perm fs.FileMode) string {
  	t.Helper()
  	if err := os.WriteFile(p, []byte(minimalPolicy), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	chmodT(t, p, perm)
  	return p
  }

  func symlinkT(t *testing.T, target, link string) {
  	t.Helper()
  	if err := os.Symlink(target, link); err != nil {
  		t.Fatal(err)
  	}
  }

  // Every refusal the fence words itself has a Short that keeps the check that
  // failed, the value seen and the one wanted, the remedy and each path's tail,
  // within shortMax, at a 260-byte path with the longest uids and names a
  // caller gives. Its Error still names each path whole, and errors.Is and
  // errors.As see through it as before: only the link refusal wraps an error
  // (#60).
  func TestEveryFenceRefusalHasAShortFormThatKeepsItsCause(t *testing.T) {
  	defer func(f func(*os.File) (bool, error)) { ReadOnlyFS = f }(ReadOnlyFS)
  	ReadOnlyFS = func(*os.File) (bool, error) { return false, nil }
  	deepFile := func(t *testing.T, name string) string { return filepath.Join(deepDir(t, pathLen, name), name) }
  	const linkCase = "a link in the file's own name"
  	for _, c := range []struct {
  		name  string
  		build func(t *testing.T) ([]string, error)
  		wants []string
  	}{
  		{"file owner", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
  			ownedBy(t, p)
  			_, err := Read(p, maxPolicySize, "policy file")
  			return []string{p}, err
  		}, []string{"the file …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
  		{"file mode", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "policy.yaml"), 0o666)
  			_, err := Read(p, maxPolicySize, "policy file")
  			return []string{p}, err
  		}, []string{"the file …", ": mode -rw-rw-rw-, wants no group or other write - chmod go-w it"}},
  		{"directory mode", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
  			chmodT(t, filepath.Dir(p), 0o1777) // sticky: the ancestor walk excuses it, the holding directory's rule does not
  			_, err := Read(p, maxPolicySize, "policy file")
  			return []string{filepath.Dir(p)}, err
  		}, []string{"the directory …", ": mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
  		{"directory, asked by CheckDir", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
  			chmodT(t, filepath.Dir(p), 0o1777)
  			return []string{filepath.Dir(p)}, CheckDir(p, "revocations file")
  		}, []string{"the directory …", ", holding the revocations file: mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
  		{"ancestor mode", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
  			mid := filepath.Dir(filepath.Dir(p))
  			chmodT(t, mid, 0o777)
  			_, err := Read(p, maxPolicySize, "policy file")
  			return []string{mid, p}, err
  		}, []string{"the directory …", " above …", ": mode drwxrwxrwx, wants no group or other write - chmod go-w it, or move the file out from under it"}},
  		{"ancestor owner", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
  			mid := filepath.Dir(filepath.Dir(p))
  			ownedBy(t, mid)
  			_, err := Read(p, maxPolicySize, "policy file")
  			return []string{mid, p}, err
  		}, []string{"the directory …", " above …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
  		{"directory holding a link, mode", func(t *testing.T) ([]string, error) {
  			real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
  			open := deepDir(t, pathLen-len("/policy.yaml"), "etc")
  			symlinkT(t, filepath.Dir(real), filepath.Join(open, "etc"))
  			chmodT(t, open, 0o1777) // a link's directory is never excused by the sticky bit
  			_, err := Read(filepath.Join(open, "etc", "policy.yaml"), maxPolicySize, "policy file")
  			return []string{open, filepath.Join(open, "etc")}, err
  		}, []string{"the directory …", " holding the link …", ": mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
  		{"directory holding a link, owner", func(t *testing.T) ([]string, error) {
  			real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
  			open := deepDir(t, pathLen-len("/policy.yaml"), "etc")
  			symlinkT(t, filepath.Dir(real), filepath.Join(open, "etc"))
  			ownedBy(t, open)
  			_, err := Read(filepath.Join(open, "etc", "policy.yaml"), maxPolicySize, "policy file")
  			return []string{open, filepath.Join(open, "etc")}, err
  		}, []string{" holding the link …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
  		{"more than 40 links", func(t *testing.T) ([]string, error) {
  			dir := deepDir(t, pathLen, "l0")
  			policyFile(t, filepath.Join(dir, "policy.yaml"), 0o600)
  			for i := 0; i <= maxLinks; i++ { // l0 -> l1 -> ... -> l40 -> policy.yaml: 41 links
  				target := "l" + strconv.Itoa(i+1)
  				if i == maxLinks {
  					target = "policy.yaml"
  				}
  				symlinkT(t, target, filepath.Join(dir, "l"+strconv.Itoa(i)))
  			}
  			p := filepath.Join(dir, "l0")
  			_, err := Read(p, maxPolicySize, "policy file")
  			return []string{p}, err
  		}, []string{"the path …", ": more than 40 symbolic links, wants at most 40 - shorten the chain"}},
  		{"not a regular file", func(t *testing.T) ([]string, error) {
  			p := deepFile(t, "policy.yaml")
  			if err := syscall.Mkfifo(p, 0o600); err != nil {
  				t.Fatal(err)
  			}
  			_, err := Read(p, maxPolicySize, longest)
  			return []string{p}, err
  		}, []string{"the path …", ": a named pipe, wants a regular file - put the " + longest + " itself there"}},
  		{"over the size bound", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "policy.yaml"), 0o600)
  			if err := os.Truncate(p, maxInventorySize+1); err != nil {
  				t.Fatal(err)
  			}
  			_, err := Read(p, maxInventorySize, longest)
  			return []string{p}, err
  		}, []string{"the file …", ": larger than 67108864 bytes, the most a " + longest + " may be - restore it"}},
  		{linkCase, func(t *testing.T) ([]string, error) {
  			real := policyFile(t, filepath.Join(safeDir(t), "policy.yaml"), 0o600)
  			p := deepFile(t, "policy.yaml")
  			symlinkT(t, real, p)
  			_, err := ReadNoLink(p, maxPolicySize, longest)
  			return []string{p}, err
  		}, []string{"the file …", ": a symbolic link, wants the " + longest + " itself - put the file in place of the link"}},
  		{"secret file owner", func(t *testing.T) ([]string, error) {
  			p := policyFile(t, deepFile(t, "k1"), 0o600)
  			ownedBy(t, p)
  			_, err := ReadSecret(p, filepath.Dir(p), 1<<10)
  			return []string{p}, err
  		}, []string{"the secret file …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it"}},
  	} {
  		t.Run(c.name, func(t *testing.T) {
  			paths, err := c.build(t)
  			var r *Refusal
  			if !errors.As(err, &r) {
  				t.Fatalf("not a Refusal: %v", err)
  			}
  			short := Brief(err)
  			if short != r.Short() {
  				t.Errorf("Brief of a bare refusal is not its Short: %q", short)
  			}
  			if len(short) > shortMax {
  				t.Errorf("%d bytes, past %d: %s", len(short), shortMax, short)
  			}
  			for _, w := range c.wants {
  				if !strings.Contains(short, w) {
  					t.Errorf("want %q: %s", w, short)
  				}
  			}
  			for _, p := range paths {
  				if len(p) <= 2*shortPathMax {
  					t.Fatalf("the case's path is short: %s", p)
  				}
  				if !strings.Contains(err.Error(), p) {
  					t.Errorf("the full text does not name %s whole: %v", p, err)
  				}
  				if !strings.Contains(short, "…"+p[len(p)-shortPathMax:]) {
  					t.Errorf("%s is not named by its tail: %s", p, short)
  				}
  			}
  			var pe *fs.PathError
  			if link := c.name == linkCase; errors.Is(err, syscall.ELOOP) != link || errors.As(err, &pe) != link {
  				t.Errorf("errors.Is ELOOP %v, errors.As PathError %v, want both %v", errors.Is(err, syscall.ELOOP),
  					errors.As(err, &pe), link)
  			}
  		})
  	}
  }

  // A start error and a log line still name every path whole, in the words
  // they had (#60).
  func TestTheFullTextOfARefusalIsUnchanged(t *testing.T) {
  	p := policyAt(t, 0o666, 0o700)
  	_, err := Read(p, maxPolicySize, "policy file")
  	if want := "the file " + p + " is mode -rw-rw-rw-, writable by others than its owner; whoever can write it " +
  		"decides who gets access - chmod go-w it"; err == nil || err.Error() != want {
  		t.Errorf("mode: %v\nwant %s", err, want)
  	}
  	chmodT(t, p, 0o600)
  	ownedBy(t, p)
  	_, err = Read(p, maxPolicySize, "policy file")
  	if want := fmt.Sprintf("the file %s is owned by uid %d; whoever can write it decides who gets access, so it "+
  		"must belong to the user this process runs as (uid %d) or to root - chown it", p, bigUID, ourUID); err == nil ||
  		err.Error() != want {
  		t.Errorf("owner: %v\nwant %s", err, want)
  	}
  }
  ```

  Before writing, grep the package's tests for `deepDir`, `ownedBy`, `chmodT`, `policyFile`, `symlinkT`, `bigUID`, `ourUID`, `longest` and `pathLen`: `grep -n -e 'func deepDir' -e 'func ownedBy' -e 'func chmodT' -e 'func policyFile' -e 'func symlinkT' -e 'bigUID' -e 'ourUID' -e 'longest' -e 'pathLen' internal/fence/*_test.go`. Rename on a clash.

- [ ] **Step 2: Run them and see them fail.** `go test ./internal/fence/ -run '^Test(BriefShortensOnlyWhatTheFenceNames|EveryFenceRefusalHasAShortFormThatKeepsItsCause|TheFullTextOfARefusalIsUnchanged)$' -count=1`. Expected: `Refusal`, `Brief`, `shown`, `shortPathMax` and `shortMax` are undefined. Paste the red output.

- [ ] **Step 3: Implement.**

  `internal/fence/refusal.go`:

  ```go
  package fence

  import (
  	"errors"
  	"io/fs"
  	"strings"

  	"github.com/blanketfish/port49/internal/printsafe"
  )

  // shortPathMax is how much of a path a Short keeps: its last 32 bytes, the
  // file name and a directory or two. Two of them, the cause, the values and
  // the remedy stay within shortMax.
  const shortPathMax = 32

  // shortMax bounds a Short. The enrollment store's late reason puts 99 bytes
  // around it and the broker cuts that reason at 300 bytes
  // (internal/broker/signin.go, CheckEnrollmentStore), so a Short of at most
  // 192 bytes leaves the whole reason standing (#60).
  const shortMax = 192

  // Refusal is a refusal the fence words itself: an owner, a mode, a link, a
  // size or a file type that fails its rule. Error is the full text, naming
  // every path whole, for a start error, a log line or a command's stderr.
  // Short is the same check, the value seen against the one wanted and the
  // remedy, with each path cut to its last shortPathMax bytes, for a reason
  // that is cut short (#60). It wraps err when that is set, so errors.Is and
  // errors.As see through it as they saw through the fmt.Errorf it replaces.
  type Refusal struct {
  	full, short string
  	err         error
  }

  func (r *Refusal) Error() string { return r.full }

  // Short is the refusal in at most shortMax bytes.
  func (r *Refusal) Short() string { return printsafe.Line(r.short, shortMax) }

  func (r *Refusal) Unwrap() error { return r.err }

  // shown is a path as a Short names it.
  func shown(p string) string { return printsafe.Tail(p, shortPathMax) }

  // Brief is err's text for a line that is cut short. A Refusal's full text is
  // replaced by its Short, and an fs.PathError's path by its tail, inside
  // whatever err wraps them in. Any other error's text is unchanged.
  func Brief(err error) string {
  	if err == nil {
  		return ""
  	}
  	s := err.Error()
  	var r *Refusal
  	if errors.As(err, &r) {
  		return strings.Replace(s, r.Error(), r.Short(), 1)
  	}
  	var pe *fs.PathError
  	if errors.As(err, &pe) {
  		return strings.Replace(s, pe.Error(), pe.Op+" "+shown(pe.Path)+": "+pe.Err.Error(), 1)
  	}
  	return s
  }
  ```

  In `fence_linux.go`, after `article`:

  ```go
  // subject is what a refusal names: in full for its Error, and by its paths'
  // tails for its Short (#60).
  type subject struct{ full, short string }

  // named is the subject "kind path".
  func named(kind, p string) subject { return subject{kind + " " + p, kind + " " + shown(p)} }

  // kindOf names what a path that is not a regular file is, for a Short.
  func kindOf(m fs.FileMode) string {
  	switch {
  	case m.IsDir():
  		return "a directory"
  	case m&fs.ModeNamedPipe != 0:
  		return "a named pipe"
  	case m&fs.ModeSocket != 0:
  		return "a socket"
  	case m&fs.ModeDevice != 0:
  		return "a device"
  	}
  	return "not a regular file"
  }
  ```

  Then convert each text. Every `full` is the old format with the same arguments, so `Error()` is unchanged:

  - **`ownedByUsOrRoot(s subject, fi fs.FileInfo) error`:**
    - With no owner: `&Refusal{full: s.full + ": cannot read its owner", short: s.short + ": cannot read its owner"}`.
    - With the wrong owner: `full` is the old `"%s is owned by uid %d; whoever can write it decides who gets access, so it must belong to the user this process runs as (uid %d) or to root - chown it"` with `s.full, uid, euid`. `short` is `fmt.Sprintf("%s: owner uid %d, wants uid %d or root - chown it", s.short, uid, euid)`.
  - **`notWritableByOthersAdvising(s subject, fi fs.FileInfo, advice, shortAdvice string) error`:** `full` is the old text with `s.full`. `short` is `fmt.Sprintf("%s: mode %v, wants no group or other write - %s", s.short, mode, shortAdvice)`.
  - **The plain helpers:**
    - `notWritableByOthers(s, fi)` passes `"chmod go-w it", "chmod go-w it"`.
    - `writableByUsAlone(s subject, fi)` takes the subject.
    - `secretDirWritableByUsAlone(s subject, fi)` takes the subject.
    - `dirWritableByUsAlone(s, d, fi)` passes `"chmod go-w it", "chmod go-w it"` to `dirWritableByUsAloneAdvising(s subject, d *os.File, fi fs.FileInfo, advice, shortAdvice string)`.
  - **`ancestorWritableByUsAlone`:**
    - Its subject is `subject{"the directory " + dir + " (above " + path + ")", "the directory " + shown(dir) + " above " + shown(path)}`.
    - The full advice is as today.
    - `shortAdvice` is `"chmod go-w it, or move the file out from under it"`.
  - **`resolvePolicyPath`:**
    - The links refusal is `&Refusal{full: fmt.Sprintf("%s passes through more than %d symbolic links", path, maxLinks), short: fmt.Sprintf("the path %s: more than %d symbolic links, wants at most %d - shorten the chain", shown(path), maxLinks, maxLinks)}`.
    - The link's directory is `subject{"the directory " + resolved + ", holding the symbolic link " + next, "the directory " + shown(resolved) + " holding the link " + shown(next)}`.
  - **`CheckDir`:** `subject{"the directory " + dir + ", holding the " + what, "the directory " + shown(dir) + ", holding the " + what}`.
  - **`readIn`:** `named("the file", target)` and `named("the directory", dir)`.
  - **`ReadSecret`:** `ownedByUsOrRoot(named("the secret file", target), fi)` and `secretDirWritableByUsAlone(named("the directory", dir), di)`. `groupIsOurs` keeps its `what string` and is passed `"the secret file "+target` as today. The `within`, secret-mode, ACL and hard-link texts stay `fmt.Errorf` (ruling 5).
  - **`readChecked`:**
    - The not-regular text is `&Refusal{full: fmt.Sprintf("%s is not a regular file", target), short: fmt.Sprintf("the path %s: %s, wants a regular file - put the %s itself there", shown(target), kindOf(fi.Mode()), what)}`.
    - The size text is `&Refusal{full: fmt.Sprintf("%s is larger than %d bytes; it is not a%s %s", target, max, article(what), what), short: fmt.Sprintf("the file %s: larger than %d bytes, the most a%s %s may be - restore it", shown(target), max, article(what), what)}`.
  - **`linkRefused`:** `&Refusal{full: fmt.Sprintf("%s is a symbolic link; a%s %s is read only as a file of its own: %v", path, article(what), what, err), short: fmt.Sprintf("the file %s: a symbolic link, wants the %s itself - put the file in place of the link", shown(path), what), err: err}`. Update its comment: it is a `Refusal` wrapping err, so `errors.Is(err, syscall.ELOOP)` still holds.

  Keep the existing comments. Where a helper's doc says "what", say "s, the subject".

- [ ] **Step 4: Run.** `go test ./internal/fence/ -count=1`, then `go vet ./internal/fence/` and `gofmt -l internal/fence`. Expected: PASS, every existing fence test included, with no vet or gofmt output.

  **Mutation checks**, one per class. Restore after each.
  - **Ancestor remedy:** in `ancestorWritableByUsAlone`, pass the full advice as `shortAdvice`. `ancestor mode` must go red on length.
  - **Owner:** in `ownedByUsOrRoot`, build `short` from `s.full`. Every owner case must go red, on its tail or its length.
  - **Mode:** in `notWritableByOthersAdvising`, drop `wants no group or other write, `. `file mode`, `directory mode`, `ancestor mode` and both link-directory mode cases must go red.
  - **Link and size:**
    - Make `linkRefused` return a `Refusal` with no `err`. The link case must go red on ELOOP.
    - Separately, drop `- restore it` from the size text. `over the size bound` must go red.
  - **Links and file type:** drop `, wants at most %d` from the links text. `more than 40 links` must go red. Make `kindOf` return `"not a regular file"` always. `not a regular file` must go red.
  - **`Brief`:** delete its `fs.PathError` branch. `TestBriefShortensOnlyWhatTheFenceNames` must go red.

- [ ] **Step 5: Commit.**

  `git add internal/fence/refusal.go internal/fence/refusal_test.go internal/fence/fence_linux.go internal/fence/short_linux_test.go && git commit -m "feat(fence): every refusal the fence words itself has a short form that keeps its cause, values and remedy (#60)"`

---

### Task 2: the enrollment store's lost reason uses the fence's short form (#60)

**Files:**
- Modify `internal/store/enrollfile/enrollfile.go`:
  - add `(*File).failed`;
  - `lost` holds the whole why, path included;
  - change `read` (`:94-107`), `pickUpLate` (`:130-143`) and `lostErr` (`:222-227`).
- Modify `internal/store/enrollfile/enrollfile_test.go`, two assertions (Step 3).
- Create `internal/store/enrollfile/fence_linux_test.go`.
- Modify `internal/port49d/signin.go:256-262` (`openEnrollmentFile`). Add the `internal/fence` import.
- Create `internal/port49d/signin_fence_linux_test.go`.

- [ ] **Step 1: Write the failing tests.**

  `internal/store/enrollfile/fence_linux_test.go`:

  ```go
  //go:build linux

  package enrollfile

  import (
  	"context"
  	"errors"
  	"io/fs"
  	"os"
  	"path/filepath"
  	"strings"
  	"syscall"
  	"testing"

  	"github.com/blanketfish/port49/internal/fence"
  	"github.com/blanketfish/port49/internal/printsafe"
  	"github.com/blanketfish/port49/internal/store"
  )

  // deepStoreDir makes a private directory such that name inside it is a path
  // of exactly n bytes, built from components of at most 50 bytes so its
  // parents are long too.
  func deepStoreDir(t *testing.T, n int, name string) string {
  	t.Helper()
  	dir := dirFor(t)
  	for {
  		rest := n - len(dir) - 1 - len(name)
  		if rest == 0 {
  			return dir
  		}
  		if rest < 2 {
  			t.Fatalf("TMPDIR %s is too long for a %d-byte path", os.TempDir(), n)
  		}
  		k := min(rest-1, 50)
  		if rest-1-k == 1 {
  			k--
  		}
  		dir = filepath.Join(dir, strings.Repeat("d", k))
  		if err := os.Mkdir(dir, 0o700); err != nil {
  			t.Fatal(err)
  		}
  	}
  }

  // fenceSees makes the fence see this process as uid 4294967294, every inode
  // as its, and the inode at path as uid 4294967295's: an owner refusal with
  // the longest values, as root or not.
  func fenceSees(t *testing.T, path string) {
  	t.Helper()
  	fi, err := os.Lstat(path)
  	if err != nil {
  		t.Fatal(err)
  	}
  	ino := fi.Sys().(*syscall.Stat_t).Ino
  	owner, euid := fence.FileOwner, fence.Geteuid
  	t.Cleanup(func() { fence.FileOwner, fence.Geteuid = owner, euid })
  	fence.Geteuid = func() int { return 4294967294 }
  	fence.FileOwner = func(fi fs.FileInfo) (uint32, bool) {
  		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Ino == ino {
  			return 4294967295, true
  		}
  		return 4294967294, true
  	}
  }

  func chmodStore(t *testing.T, p string, m fs.FileMode) {
  	t.Helper()
  	if err := os.Chmod(p, m); err != nil {
  		t.Fatal(err)
  	}
  }

  // Every refusal the fence words itself reaches the broker's 300-byte cut
  // whole, with the store's own words around it, at a 260-byte path and the
  // longest uids. The reason keeps the check that failed, the value seen and
  // the one wanted, and the remedy, and names the path once (#60). The late
  // reason is the longest, so each case is found by a running handle. The
  // file owner, the likeliest after a restore, is also found at start.
  func TestAFenceRefusalReachesTheBrokersCutWhole(t *testing.T) {
  	ctx := context.Background()
  	cut := func(t *testing.T, err error, wants ...string) {
  		t.Helper()
  		if !errors.Is(err, store.ErrEnrollmentStoreLost) {
  			t.Fatalf("not lost: %v", err)
  		}
  		said := printsafe.Line(err.Error(), 300) // as Broker.CheckEnrollmentStore cuts it
  		if said != err.Error() {
  			t.Errorf("%d bytes, cut: %s", len(err.Error()), said)
  		}
  		for _, w := range wants {
  			if !strings.Contains(said, w) {
  				t.Errorf("want %q: %s", w, said)
  			}
  		}
  		if strings.Count(said, "enrollments.json") > 1 || strings.Contains(said, "cannot be read") {
  			t.Errorf("the path twice, or the generic words: %s", said)
  		}
  	}
  	const late = "; this broker looks again at its next recheck, with no restart"
  	for _, c := range []struct {
  		name  string
  		after func(t *testing.T, path string) // makes the refusal once the handle is open
  		wants []string
  	}{
  		{"file owner", func(t *testing.T, path string) { written(t, path, keys()); fenceSees(t, path) },
  			[]string{"lost: the file …", "/enrollments.json: owner uid 4294967295, wants uid 4294967294 or root - chown it" + late}},
  		{"file mode", func(t *testing.T, path string) { written(t, path, keys()); chmodStore(t, path, 0o666) },
  			[]string{"lost: the file …", ": mode -rw-rw-rw-, wants no group or other write - chmod go-w it" + late}},
  		{"directory mode", func(t *testing.T, path string) {
  			written(t, path, keys())
  			chmodStore(t, filepath.Dir(path), 0o1777)
  		}, []string{"lost: the directory …", ": mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it" + late}},
  		{"ancestor mode", func(t *testing.T, path string) {
  			written(t, path, keys())
  			chmodStore(t, filepath.Dir(filepath.Dir(path)), 0o777)
  		}, []string{"lost: the directory …", " above …", ": mode drwxrwxrwx, wants no group or other write - chmod go-w it, " +
  			"or move the file out from under it" + late}},
  		{"ancestor owner", func(t *testing.T, path string) {
  			written(t, path, keys())
  			fenceSees(t, filepath.Dir(filepath.Dir(path)))
  		}, []string{" above …", ": owner uid 4294967295, wants uid 4294967294 or root - chown it" + late}},
  		{"not a regular file", func(t *testing.T, path string) {
  			if err := syscall.Mkfifo(path, 0o600); err != nil {
  				t.Fatal(err)
  			}
  		}, []string{"lost: the path …", ": a named pipe, wants a regular file - put the enrollments file itself there" + late}},
  		{"over maxFile", func(t *testing.T, path string) {
  			written(t, path, keys())
  			if err := os.Truncate(path, maxFile+1); err != nil {
  				t.Fatal(err)
  			}
  		}, []string{"lost: the file …", ": larger than 67108864 bytes, the most an enrollments file may be - restore it" + late}},
  	} {
  		t.Run(c.name, func(t *testing.T) {
  			path := filepath.Join(deepStoreDir(t, 260, "enrollments.json"), "enrollments.json")
  			running := openAt(t, path, keys())
  			c.after(t, path)
  			_, err := running.GetEnrollmentMark(ctx)
  			cut(t, err, c.wants...)
  		})
  	}
  	t.Run("file owner at start", func(t *testing.T) {
  		path := filepath.Join(deepStoreDir(t, 260, "enrollments.json"), "enrollments.json")
  		written(t, path, keys())
  		fenceSees(t, path)
  		_, err := openAt(t, path, keys()).GetEnrollmentMark(ctx)
  		cut(t, err, "store: the enrollment store is lost: the file …",
  			"/enrollments.json: owner uid 4294967295, wants uid 4294967294 or root - chown it")
  		if strings.HasSuffix(err.Error(), late) {
  			t.Errorf("a start reason says it looks again: %v", err)
  		}
  	})
  }
  ```

  The ancestor cases name the store's directory, not the file, as the "above" path: `ReadNoLink` resolves the directory. So `/enrollments.json` is asserted only in the cases that name the file. The `Count(...) > 1` check proves the path is named at most once.

  `internal/port49d/signin_fence_linux_test.go`:

  ```go
  //go:build linux

  package port49d

  import (
  	"errors"
  	"os"
  	"path/filepath"
  	"strconv"
  	"strings"
  	"testing"

  	"github.com/blanketfish/port49/internal/store"
  )

  // deepEnrollDir makes a private directory such that name inside it is a path
  // of exactly n bytes, in components of at most 50 bytes.
  func deepEnrollDir(t *testing.T, n int, name string) string {
  	t.Helper()
  	dir := t.TempDir()
  	if err := os.Chmod(dir, 0o700); err != nil {
  		t.Fatal(err)
  	}
  	for {
  		rest := n - len(dir) - 1 - len(name)
  		if rest == 0 {
  			return dir
  		}
  		if rest < 2 {
  			t.Fatalf("TMPDIR %s is too long for a %d-byte path", os.TempDir(), n)
  		}
  		k := min(rest-1, 50)
  		if rest-1-k == 1 {
  			k--
  		}
  		dir = filepath.Join(dir, strings.Repeat("d", k))
  		if err := os.Mkdir(dir, 0o700); err != nil {
  			t.Fatal(err)
  		}
  	}
  }

  // A fence refusal at Open is lost in the fence's short words, which the
  // broker's 300-byte cut leaves whole at a 260-byte path (#60). The cases are
  // the store's directory, a link at its path, and more than 40 links on the
  // way to it.
  func TestAnEnrollmentFileRefusedAtOpenIsLostWithinTheCut(t *testing.T) {
  	for _, c := range []struct {
  		name  string
  		path  func(t *testing.T) string
  		wants []string
  	}{
  		{"its directory", func(t *testing.T) string {
  			dir := deepEnrollDir(t, 260, "enrollments.json")
  			if err := os.Chmod(dir, 0o1777); err != nil {
  				t.Fatal(err)
  			}
  			return filepath.Join(dir, "enrollments.json")
  		}, []string{"the directory …", ", holding the enrollments file: mode drwxrwxrwx (sticky), wants no group or other write - chmod go-w it"}},
  		{"a link at its path", func(t *testing.T) string {
  			dir := deepEnrollDir(t, 260, "enrollments.json")
  			real := filepath.Join(dir, "real.json")
  			if err := os.WriteFile(real, []byte("{}"), 0o600); err != nil {
  				t.Fatal(err)
  			}
  			p := filepath.Join(dir, "enrollments.json")
  			if err := os.Symlink(real, p); err != nil {
  				t.Fatal(err)
  			}
  			return p
  		}, []string{"the file …", "/enrollments.json: a symbolic link, wants the enrollments file itself - put the file in place of the link"}},
  		{"more than 40 links on the way", func(t *testing.T) string {
  			dir := deepEnrollDir(t, 260-len("/enrollments.json"), "l0")
  			if err := os.Mkdir(filepath.Join(dir, "real"), 0o700); err != nil {
  				t.Fatal(err)
  			}
  			for i := 0; i <= 40; i++ { // l0 -> ... -> l40 -> real: 41 links
  				target := "l" + strconv.Itoa(i+1)
  				if i == 40 {
  					target = "real"
  				}
  				if err := os.Symlink(target, filepath.Join(dir, "l"+strconv.Itoa(i))); err != nil {
  					t.Fatal(err)
  				}
  			}
  			return filepath.Join(dir, "l0", "enrollments.json")
  		}, []string{"the path …", ": more than 40 symbolic links, wants at most 40 - shorten the chain"}},
  	} {
  		t.Run(c.name, func(t *testing.T) {
  			_, err := openEnrollmentFile(c.path(t), signInTestKeys, nil)
  			if !errors.Is(err, store.ErrEnrollmentStoreLost) {
  				t.Fatalf("not lost: %v", err)
  			}
  			if len(err.Error()) > 300 {
  				t.Errorf("%d bytes, past the broker's cut: %v", len(err.Error()), err)
  			}
  			for _, w := range c.wants {
  				if !strings.Contains(err.Error(), w) {
  					t.Errorf("want %q: %v", w, err)
  				}
  			}
  		})
  	}
  }
  ```

  Before writing, grep each package's tests for the helper names: `grep -n -e 'func deepStoreDir' -e 'func fenceSees' -e 'func chmodStore' internal/store/enrollfile/*_test.go` and `grep -n -e 'func deepEnrollDir' internal/port49d/*_test.go`. Rename on a clash.

- [ ] **Step 2: Run them and see them fail.**
  - Run `go test ./internal/store/enrollfile/ -run '^TestAFenceRefusalReachesTheBrokersCutWhole$' -count=1`. Expected: the ancestor and link-directory cases are cut past 300, and every case has `cannot be read` and the path twice.
  - Run `go test ./internal/port49d/ -run '^TestAnEnrollmentFileRefusedAtOpenIsLostWithinTheCut$' -count=1`. Expected: the full text is past 300.
  - Paste both red outputs.

- [ ] **Step 3: Implement.**

  In `enrollfile.go`:

  - The `lost` field's comment becomes: `// why the file did not open, naming its path once; "" when it did, or none is there`.
  - Add, after `readFailure`:

    ```go
    // failed is the lost reason for a read of the file that failed with err. A
    // refusal the fence words itself is its Short: the check, the value seen and
    // the one wanted, and the remedy, each path by its tail, so the reason fits
    // the broker's cut at any path length (#60). A link at the path keeps the
    // store's own words, first, because the fence's link refusal is a Refusal
    // wrapping ELOOP. Any other failure names the shown path, readFailure and
    // remedy (#58).
    func (f *File) failed(err error, remedy string) string {
    	var r *fence.Refusal
    	if !errors.Is(err, syscall.ELOOP) && errors.As(err, &r) {
    		return r.Short()
    	}
    	return f.shownPath() + ": " + readFailure(f.path, err) + ": " + remedy
    }
    ```

  - **`read`, `:98-99`:** `f.present, f.lost = true, f.failed(err, "fix its owner and mode, restore it, or run `+"`port49 directory reset-second-factor --all`"+`")`. Keep the remedy's words exactly as today.
  - **`read`, `:105`:** `f.lost = f.shownPath() + ": " + why`.
  - **`pickUpLate`, `:131-143`:**
    - `why = f.failed(err, "fix its owner and mode, or remove a link")`.
    - In the `else` branch, after the `f.open` success return, `why = f.shownPath() + ": " + why`.
    - The returned error becomes `fmt.Errorf("%w: %s; this broker looks again at its next recheck, with no restart", store.ErrEnrollmentStoreLost, why)`.
  - **`lostErr`, `:226`:** `fmt.Errorf("%w: %s", store.ErrEnrollmentStoreLost, f.lost)`.
  - Update `shownPath`'s comment. It is the path as a reason the store words itself names it. A fence refusal names its own paths (`failed`).

  In `enrollfile_test.go`, the two assertions that read a fence refusal's words:
  - **`TestAnUnreadableOrOversizedFileIsLostNotAnOpenError`:** `check` takes a `want string`. `unreadable` passes `"cannot be read"`, and `oversized` passes `"larger than 67108864 bytes"`.
  - **`TestAFileTheFenceRefusesIsLostNamingTheReasonAndNothingOfItsContent`, `:434`:** `"writable by others"` becomes `"wants no group or other write"`.

  In `internal/port49d/signin.go`, `openEnrollmentFile`:

  ```go
  	f, err := enrollfile.Open(path, keys, time.Now)
  	if err != nil {
  		// The reason is cut at 300 bytes (Broker.CheckEnrollmentStore): the
  		// fence's short form keeps its cause and remedy at any path length (#60).
  		return nil, fmt.Errorf("%w: %s", store.ErrEnrollmentStoreLost, fence.Brief(err))
  	}
  ```

  It was `%v` before, so no error chain is lost.

- [ ] **Step 4: Run.**
  - `go test ./internal/store/enrollfile/ ./internal/port49d/ ./internal/broker/ ./internal/fence/ -count=1`. Expected: PASS, including every #58 test unchanged: `TestAnUnknownKeyReasonFitsTheCutAndKeepsItsRemedy`, `TestAnUnreadableFileAtStartAtALongPathKeepsItsCauseAndRemedy`, `TestAnAncestorThatCannotBeSearchedIsNamedInTheReason`, `TestALateRefusalAtALongPathKeepsItsCauseAndRemedy` and `TestALinkAtThePathIsRefused`.
  - Then #58's own port49d test under a long TMPDIR: `L=$TMPDIR/$(printf 'x%.0s' {1..80}) && mkdir -m 700 $L && TMPDIR=$L go test ./internal/port49d/ -run '^TestARunningBrokerSaysALateUnreadableFileOnceAndFollowsTheFix$' -count=1 -timeout 30m`. Expected: PASS.

  **Mutation checks.** Restore after each.
  - **The `Refusal` branch:** delete it from `failed`. The ancestor-mode and link-directory cases of the new enrollfile test must go red on length, and every case on `cannot be read`.
  - **The ELOOP guard:** drop `!errors.Is(err, syscall.ELOOP) &&` from `failed`. `TestALateRefusalAtALongPathKeepsItsCauseAndRemedy` must go red, because the link reason no longer says `fix its owner and mode, or remove a link`.
  - **`Brief`:** in `openEnrollmentFile`, go back to `%v` with `err`. The new port49d test must go red.

- [ ] **Step 5: Commit.**

  `git add internal/store/enrollfile/enrollfile.go internal/store/enrollfile/enrollfile_test.go internal/store/enrollfile/fence_linux_test.go internal/port49d/signin.go internal/port49d/signin_fence_linux_test.go && git commit -m "fix(enrollfile): a fence refusal reaches the broker's lost reason in its short form, at any path length (#60)"`

---

### Task 3: the kept-CRL and trust-follow lines keep a fence refusal whole within their cut (#60)

**Sites:**

| Site | Cut | Fix | Test |
|---|---|---|---|
| `internal/port49d/main.go:1285` | 300 | `briefLine(err, 300)` | end to end: `TestRunSaysAKeptCRLTheFenceRefusesWithinTheCut` |
| `internal/port49d/brokerd.go:771` | 300 | `briefLine(err, 300)` | source: `TestEveryCutLineThatCarriesAFenceErrorIsBrief` (ruling 10) |
| `internal/port49d/tlslistener.go:574` | 300 | `briefLine(err, 300)` | end to end: `TestTheTLSListenerSaysAKeptCRLTheFenceRefusesWithinTheCut` |
| `internal/port49d/tlslistener.go:215` | 400 | `briefLine(err, 400)`, and `issuerKey` (ruling 9) | end to end: `TestATrustFollowSaysAnIssuerFileTheFenceRefusesWithinTheCut`, rotated half |
| `internal/port49d/tlslistener.go:218` | 400 | `briefLine(err, 400)`, and `issuerKey` | the same test, first half |

`Brief` alone would be wrong at `:215` and `:218`, because their wrapper prints the issuer_file's path whole (root cause 3). `issuerKey` is that site's other half. Every site has a cut, and none needs a cut length changed.

**Files:**
- Modify `internal/port49d/certstatus.go`:
  - add `briefLine` and `issuerKey`;
  - use `issuerKey` in `certStatusConfig`'s `readIssuerFile` error branch (`:36-39`).
- Modify `internal/port49d/main.go:1285`, `internal/port49d/brokerd.go:771`, and `internal/port49d/tlslistener.go:215`, `:218` and `:574`.
- Modify `internal/port49d/tlslistener_test.go:871-903`. `newRotation` becomes `newRotationIn(t, dir)`, called by `newRotation` with `safeDir(t)`, which behaves as before.
- Create `internal/port49d/briefline_linux_test.go`. It uses Task 2's `deepEnrollDir`.

- [ ] **Step 1: Write the failing tests.**

  In `tlslistener_test.go`, split `newRotation`:

  ```go
  func newRotation(t *testing.T) *rotation { return newRotationIn(t, safeDir(t)) }

  // newRotationIn is newRotation with its issuer, CRL and state directory in
  // dir.
  func newRotationIn(t *testing.T, dir string) *rotation {
  	t.Helper()
  	r := &rotation{p: writeDevicePKI(t), sink: &lineSink{}}
  	now := time.Now()
  	// ... the rest of today's body, from r.issuer, r.crlFile = ..., unchanged
  }
  ```

  The only change is that `dir := safeDir(t)` becomes the parameter.

  `internal/port49d/briefline_linux_test.go`:

  ```go
  //go:build linux

  package port49d

  import (
  	"os"
  	"path/filepath"
  	"strings"
  	"testing"

  	"github.com/blanketfish/port49/internal/config"
  )

  // fenceMode is the end of the fence's short mode refusal of a 0666 file: the
  // value seen, the value wanted and the remedy (Task 1).
  const fenceMode = ": mode -rw-rw-rw-, wants no group or other write - chmod go-w it"

  // lineFrom is the line in said from prefix on. A line that ends on want was
  // not cut, because the remedy is a refusal's last words.
  func lineFrom(t *testing.T, said, prefix, want string) {
  	t.Helper()
  	for _, l := range strings.Split(said, "\n") {
  		if i := strings.Index(l, prefix); i >= 0 {
  			if !strings.HasSuffix(l, want) {
  				t.Errorf("%d bytes, cut or worded otherwise, want it to end %q: %s", len(l[i:]), want, l[i:])
  			}
  			return
  		}
  	}
  	t.Fatalf("no line with %q:\n%s", prefix, said)
  }

  // writeOpen writes p with mode 0666, whatever the umask.
  func writeOpen(t *testing.T, p string) {
  	t.Helper()
  	if err := os.WriteFile(p, []byte("not a list"), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	if err := os.Chmod(p, 0o666); err != nil {
  		t.Fatal(err)
  	}
  }

  // port49d's in-process broker says a kept CRL the fence refuses at a
  // 260-byte path with its cause, values and remedy, within the line's
  // 300-byte cut (main.go:1285; #60).
  func TestRunSaysAKeptCRLTheFenceRefusesWithinTheCut(t *testing.T) {
  	out := captureStderr(t)
  	b := brokerConfig(t, minimalPolicy).Broker
  	statusPKI(t, b)
  	dir := deepEnrollDir(t, 260, "crl-lab_ca.der")
  	b.RevocationsFile = filepath.Join(dir, "revocations.json") // the in-process broker keeps its lists beside it
  	if _, err := initRevocations(b.RevocationsFile, testInitConfig); err != nil {
  		t.Fatal(err)
  	}
  	writeOpen(t, filepath.Join(dir, "crl-lab_ca.der"))
  	b.CertificateStatus = &config.CertificateStatusConfig{CRLs: []config.CertificateStatusCRL{{Name: "lab_ca",
  		URL: "http://127.0.0.1:1/lab.crl", IssuerFile: b.ClientCAFile}}}
  	_, stop := startDaemon(t, writeRunConfig(t, b), out)
  	defer stop()
  	const said = "port49d: broker: certificate status: kept CRL lab_ca: the file …"
  	waitFor(t, out, said)
  	lineFrom(t, out.String(), said, fenceMode)
  }

  // The TLS listener says a kept CRL the fence refuses at a 260-byte path
  // within its 300-byte cut (tlslistener.go:574; #60).
  func TestTheTLSListenerSaysAKeptCRLTheFenceRefusesWithinTheCut(t *testing.T) {
  	dir := deepEnrollDir(t, 260-len("/crl-dev.der"), "state")
  	if err := os.Mkdir(filepath.Join(dir, "state"), 0o700); err != nil {
  		t.Fatal(err)
  	}
  	writeOpen(t, filepath.Join(dir, "state", "crl-dev.der"))
  	r := newRotationIn(t, dir)
  	lineFrom(t, r.sink.all(), "tls_listener: certificate status: kept CRL dev: the file …", fenceMode)
  }

  // A trust follow that finds the issuer_file refused by the fence, at a
  // 260-byte path, says the refusal whole within its 400-byte cut. It names
  // the config entry, then the fence's short form, never the path twice. That
  // holds with no rotation (tlslistener.go:218) and after one
  // (tlslistener.go:215) (#60).
  func TestATrustFollowSaysAnIssuerFileTheFenceRefusesWithinTheCut(t *testing.T) {
  	r := newRotationIn(t, deepEnrollDir(t, 260, "issuer.pem"))
  	if len(r.issuer) != 260 {
  		t.Fatalf("the issuer_file is %d bytes", len(r.issuer))
  	}
  	if err := os.Chmod(r.issuer, 0o666); err != nil {
  		t.Fatal(err)
  	}
  	const key = "tls_listener.certificate_status.crls[0].issuer_file: the file …"
  	r.l.reload("reload_interval")
  	lineFrom(t, r.sink.all(), "the certificate status sources keep the issuers they had: "+key, fenceMode)
  	if err := os.WriteFile(r.p.caFile, r.newCA.PEM(), 0o600); err != nil {
  		t.Fatal(err)
  	}
  	r.l.reload("reload_interval")
  	r.l.reload("reload_interval")
  	lineFrom(t, r.sink.all(), "declined status_unavailable until this is fixed: "+key, fenceMode)
  }

  // Every LoadPersisted loop in port49d says its errors through
  // briefLine(err, 300), and the trust follow through briefLine(err, 400), so
  // a fence refusal on a cut line keeps its cause, values and remedy (#60).
  // It is brokerd.go's only test: no harness starts port49-broker with
  // certificate_status on (ruling 10).
  func TestEveryCutLineThatCarriesAFenceErrorIsBrief(t *testing.T) {
  	const loop = "LoadPersisted() {"
  	for file, want := range map[string]struct{ loads, follows int }{
  		"main.go": {1, 0}, "brokerd.go": {1, 0}, "tlslistener.go": {1, 2},
  	} {
  		raw, err := os.ReadFile(file)
  		if err != nil {
  			t.Fatal(err)
  		}
  		src := string(raw)
  		if n := strings.Count(src, loop); n != want.loads {
  			t.Errorf("%s: %d LoadPersisted loops, want %d", file, n, want.loads)
  		}
  		for rest := src; strings.Contains(rest, loop); {
  			rest = rest[strings.Index(rest, loop)+len(loop):]
  			next := strings.SplitN(rest, "\n", 3) // the loop's first line
  			if len(next) < 2 || !strings.Contains(next[1], "briefLine(err, 300)") {
  				t.Errorf("%s: a LoadPersisted loop does not say its error through briefLine(err, 300): %q", file, next)
  			}
  		}
  		if n := strings.Count(src, "briefLine(err, 400)"); n != want.follows {
  			t.Errorf("%s: %d trust-follow lines through briefLine(err, 400), want %d", file, n, want.follows)
  		}
  	}
  }
  ```

  Before writing, grep the package's tests for `lineFrom`, `writeOpen` and `fenceMode`: `grep -n -e 'func lineFrom' -e 'func writeOpen' -e 'fenceMode' internal/port49d/*_test.go`. Rename on a clash. Check that `captureStderr`, `startDaemon`, `waitFor`, `statusPKI`, `brokerConfig`, `writeRunConfig`, `initRevocations` and `testInitConfig` are named as used here (`certstatus_test.go:167`, `run_test.go:240`, `broker_test.go:40-75`).

- [ ] **Step 2: Run them and see them fail.** `go test ./internal/port49d/ -run '^Test(RunSaysAKeptCRLTheFenceRefusesWithinTheCut|TheTLSListenerSaysAKeptCRLTheFenceRefusesWithinTheCut|ATrustFollowSaysAnIssuerFileTheFenceRefusesWithinTheCut|EveryCutLineThatCarriesAFenceErrorIsBrief)$' -count=1`. Expected red, each for its own reason:
  - **Both kept-CRL tests:** no line with `kept CRL ...: the file …`, because the line carries the full text, cut at 300 inside the path.
  - **The trust-follow test:** no line with `crls[0].issuer_file: the file …`, because the key repeats the path.
  - **The source test:** all three files, for both loops and follows.

  Paste the red output. If port49d refuses to start for another reason under the deep directory (a socket path too long, a state-directory check), stop and report it. Do not change the test's shape to get past it.

- [ ] **Step 3: Implement.**

  In `certstatus.go`, add `"errors"` and `"io/fs"` to the imports if they are missing, then add:

  ```go
  // briefLine is err on one line of at most limit bytes, with a fence refusal
  // in its short form (fence.Brief), so the cut never takes a refusal's cause,
  // values or remedy (#60). Every line that cuts an error a fence read can
  // carry says it through this.
  func briefLine(err error, limit int) string { return printsafe.Line(fence.Brief(err), limit) }

  // issuerKey names the issuer_file of CRL source i in an error. It gives the
  // path only when err does not name it already: a fence error names the file
  // itself, whole in its Error and by its tail in fence.Brief. So a cut line
  // never carries the path whole in front of the short form, and a start error
  // names the path once (#60).
  func issuerKey(i int, path string, err error) string {
  	var r *fence.Refusal
  	var pe *fs.PathError
  	if errors.As(err, &r) || errors.As(err, &pe) {
  		return fmt.Sprintf("crls[%d].issuer_file", i)
  	}
  	return fmt.Sprintf("crls[%d].issuer_file %s", i, path)
  }
  ```

  In `certStatusConfig`, the `readIssuerFile` error branch becomes `return certstatus.Config{}, fmt.Errorf("%s: %w", issuerKey(i, src.IssuerFile, err), err)`. `key` stays as it is for the anchor and CA errors below it.

  At the sites:
  - **`main.go:1285`:** `fmt.Fprintf(stderr, "port49d: broker: certificate status: %s\n", briefLine(err, 300))`.
  - **`brokerd.go:771`:** `brokerSay("broker: certificate status: %s", briefLine(err, 300))`.
  - **`tlslistener.go:574`:** `say("tls_listener: certificate status: %s", briefLine(err, 300))`.
  - **`tlslistener.go:215` and `:218`:** `printsafe.Line(err.Error(), 400)` becomes `briefLine(err, 400)`. `msg` (`:199`), which dedupes the line, stays `fmt.Sprint(err)`.

  If an edit leaves `printsafe` unused in a file, remove that import. `go vet` will say.

- [ ] **Step 4: Run.**
  - `go test ./internal/port49d/ -count=1`. Expected: PASS, including `certstatus_test.go`'s issuer_file test (`:236-255`, non-fence errors with the path, unchanged), `trustfiles_fence_linux_test.go`, and the TLS rotation tests on `newRotation`.
  - Then `grep -rn -e 'issuer_file ' --include='*_test.go' internal cmd tests`. No assertion may expect `issuer_file PATH: ` in front of a fence refusal. Report any you find, and do not fix it in passing.

  **Mutation checks**, one per site. Restore after each.
  - **`main.go:1285`:** back to `printsafe.Line(err.Error(), 300)`. `TestRunSaysAKeptCRLTheFenceRefusesWithinTheCut` and the source test must go red.
  - **`brokerd.go:771`:** back to `printsafe.Line(err.Error(), 300)`. The source test must go red, naming `brokerd.go`.
  - **`tlslistener.go:574`:** back to `printsafe.Line(err.Error(), 300)`. `TestTheTLSListenerSaysAKeptCRLTheFenceRefusesWithinTheCut` must go red.
  - **`tlslistener.go:218`:** back to `printsafe.Line(err.Error(), 400)`. The trust-follow test's first half must go red.
  - **`tlslistener.go:215`:** back to `printsafe.Line(err.Error(), 400)`. The trust-follow test's rotated half must go red.
  - **`issuerKey`:** always return the path form. The trust-follow test must go red, because the key repeats the path.

- [ ] **Step 5: Commit.**

  `git add internal/port49d/certstatus.go internal/port49d/main.go internal/port49d/brokerd.go internal/port49d/tlslistener.go internal/port49d/tlslistener_test.go internal/port49d/briefline_linux_test.go && git commit -m "fix(port49d): kept-CRL and trust-follow lines keep a fence refusal's cause and remedy within their cut (#60)"`

---

### Task 4: the troubleshooting page says what a lost reason naming a check means (#60)

**Files:**
- Modify `docs/site/operate/troubleshooting/index.md:306-308`, the **Do this:** paragraph of "Directory and password sign-in".

- [ ] **Step 1: Edit.** After `For a lost enrollment store, restore the file or run `port49 directory import` from the export.`, insert:

  > When the broker's line names a check instead (an owner, a mode, a link, a size), fix what it names. For example, after a restore left `/var/lib/port49/enrollments.json` owned by root, it reads `the file /var/lib/port49/enrollments.json: owner uid 0, wants uid 999 or root - chown it`. The line names each path by its last 32 bytes, so a deeper path starts with `…`. The file is `enrollments.json` in `broker.state_dir`, or beside `broker.revocations_file` when that is unset.

  Keep the existing `See [backup and restore](../backup-and-restore.md).` after it. The quoted text is what Task 2's code gives for a 32-byte path, which `printsafe.Tail` keeps whole, with uid 0 owning the file and port49 running as uid 999. Check it by reading the format in `ownedByUsOrRoot`.

- [ ] **Step 2: Run** `go test ./tests/ci/ -count=1` and `make docs`, then `git status --short`. Expected: PASS, and only the page changed.

- [ ] **Step 3: Commit.**

  `git add docs/site/operate/troubleshooting/index.md && git commit -m "docs(troubleshooting): a lost enrollment store's line names the failed check and its fix (#60)"`

---

### Task 5: Final verification

- [ ] Under the Global Constraints TMPDIR, run `make test && make vet && make docs && git status --short`, then `make test-rest`, then `go test ./tests/ci/`. Paste the summary lines. `make test-rest` must pass from this one ext4 TMPDIR, `mustpass` and the fence ACL tests included.
- [ ] Run `grep -rn -e 'fence.Brief' -e 'Short()' -e 'briefLine(' --include='*.go' internal cmd`. Expected:
  - `fence.Brief` only in `internal/port49d/signin.go`, `internal/port49d/certstatus.go` and the fence's own files;
  - `Short()` only in `internal/fence` and `enrollfile.go`;
  - `briefLine(` at the five sites of Task 3, its definition, and the source test.

## Operator-facing notes for the PR body

- **Enrollment store:** when the fence refuses the store's file or a directory on its way, the broker's `sign-in: the enrollment store is lost (...)` line now always carries what failed, at any path length. The same reason reaches the admin commands' errors. The line gives:
  - the check: the owner, the mode, a link, the size, or the file type;
  - the value seen against the value wanted, for example `owner uid 0, wants uid 999 or root`, or `mode drwxrwxr-x, wants no group or other write`;
  - the fix: `chown it`, `chmod go-w it`, `shorten the chain`, `restore it`.

  Each path is named once, by its last 32 bytes. A refusal that names two paths (a directory above the file, or a directory holding a link) names both. Before, an owner or mode refusal was cut off before its fix even at a short path.
- **Kept CRLs and the TLS listener's trust follow:** the same holds for these lines, whatever the path's length:
  - `certificate status: kept CRL NAME: ...` at start, from port49d's in-process broker, port49-broker and the TLS listener;
  - `tls_listener: ...: the certificate status sources keep the issuers they had ...: ...`, when a reload finds a CRL source's issuer_file refused.

  They carry the check, the value seen against the value wanted, and the fix. Before, a deep state directory or issuer_file path could cut the fix off.
- **issuer_file errors name the path once.** An issuer_file the fence refuses is now named `crls[N].issuer_file: <the fence's text>`, at start and at a reload. Before, the path came twice: once in the key, once in the fence's text. Other issuer_file errors (the PEM, CA and anchor checks, and a fence error that names an ancestor directory or a link rather than the file) still read `crls[N].issuer_file PATH: ...`.
- **Every other refusal is unchanged.** Start errors, uncut reload lines and the journal keep the fence's full text, with every path whole: the policy, inventory, secret, TLS and CA files.
- **Troubleshooting:** the "Directory and password sign-in" section says what such a line means.
- **No config, metric, reason code or warning changes.** No lab run.

## Left for later

- **`ReadSecret`'s own texts have no short form** (ruling 5). Give them one if a secret's refusal ever reaches a cut line. Any new cut line that can carry a fence error should go through `briefLine`, and be added to `TestEveryCutLineThatCarriesAFenceErrorIsBrief`.
- **port49-broker has no test harness with `certificate_status` on** (ruling 10). `brokerd.go:771` is pinned by the source test only. A harness for it would also cover the broker's other certificate-status start lines.
- **A kept CRL's NAME is not bounded here.** A source name over about 95 bytes, combined with the longest short form, still reaches the 300-byte cut. Names are operator-chosen and short in practice.
