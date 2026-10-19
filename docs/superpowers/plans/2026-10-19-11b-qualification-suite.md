# Qualification Suite Implementation Plan (plan 11b)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every vetted platform and firmware gets a mock device: a data profile, played by one Go engine against a real in-process port49d, that runs on every PR on any runner. The real lab gets a `make lab-regress` that reruns closed entries and diffs them against their notes, and a `make qual-vet` that turns a lab run into a reviewed profile.

**Architecture:** A mock device is a **profile** (YAML, snake_case) in three parts:
1. **Stimulus**, generated from closed lab evidence: what the device sends whatever port49 answers.
2. **Reaction table**: what it does next on each reply or alert.
3. **Acceptance rules**: which of port49's replies the device rejects.

`internal/devicemock` holds the engine that plays a profile as a TACACS+ client: plain 49, or RFC 9887 TLS with the measured ClientHello and flight delay. `internal/port49d`'s `TestQual` starts a real port49d per profile under one fixed qualification policy and mints fresh credentials. It checks port49's replies against a golden file and the profile's acceptance rules. A generator, `tests/qual/cmd/genprofile`, builds part 1 from a lab conformance run's evidence and pre-fills parts 2 and 3. A fleet mode runs N engines from N loopback addresses at once.

**Tech Stack:** Go 1.26 standard library (`crypto/tls`, `crypto/ecdh`, `net`), `gopkg.in/yaml.v3` (already in go.mod). No new module. containerlab and the existing `tests/lab` harness on beehive for the lab tier. GitHub Actions for the mock tier.

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §15 (the lab register: every device claim a mock makes cites a row and a results note), §5.7 (the decision-log records the generator reads), §13 (decision 52, written by Task 1). `docs/design/2026-08-21-port49-design.md` §14 (testing strategy: "nothing about device behavior is asserted elsewhere without citing an entry"). Roadmap brief: `docs/superpowers/plans/README.md`, "Plan 11b".

## Global Constraints

- Go 1.26+, module `github.com/rhwendt/port49`, `gofmt` and `go vet` clean, no cgo, no new module.
- snake_case for every data key: profile YAML, golden JSON, evidence JSON, manifest YAML, metric names.
- Reason codes come only from spec §5.7 (`internal/decision/reasons.go`). This plan adds none.
- No device identity in a metric label. Fleet mode adds no metric.
- **Mocks are never built by decoding TACACS+ bodies from captures.** No `tshark -x`/`-V`, no `tcpdump -X`/`-A`, and no body decode in Go. The sources are only the decision log's validated request records, the `*.tls.json` handshake summaries, the 12-byte headers (`l73PlainHeaders`) and the connection timing (`l73Conns`).
- **Credentials and tokens are minted fresh in each test**, never replayed from evidence.
- No credential, token, password, TOTP code, `token_sha256`, `credential_sha256` value or private key appears in a profile, a golden, an evidence file the generator reads, test output or a failure message. Certificates are generated per test, so no `cert_sha256` is ever a fixture.
- The plan never reads `/tmp/port49-lab-tokens.jsonl`, `*.env`, `*-key.pem`, `*.keytab`, `secrets.json` or realm.json passwords. Lab logs are read only through `grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g'`.
- Vendor images (cEOS, NX-OS, IOS XE, vJunos, XRd, IOL) **never** run on a hosted runner: that would be redistribution. Freely redistributable images (SR Linux) may.
- Every workflow's `runs-on` is one line, so moving between hosted and self-hosted (beehive) is a one-line change. The mock tier needs no special runner: no Docker, no KVM, no captures.
- CI runs `make check-darwin`: any test helper that is Linux-only (binding 127.0.0.2+, `syscall.Flock` file-descriptor passing) lives in a `_linux_test.go` or `_linux.go` file.
- The lab is single-occupant: `flock /tmp/port49-lab.lock` for the whole run, and the STOP sentinel `/tmp/port49-STOP-LAB` is checked before every entry and cell.
- The real lab tier runs before pre-beta and release tags and on any vendor image change, about monthly. It is **not** nightly.
- Commits: Conventional Commits, ending `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`, no session line, no claude.ai link.
- Verify with `make test && make vet` (on beehive, where the labpcap audit's captures are) before each task's commit, and report the real output.

## Design notes

### Credit

Ryan's idea came from **cisshgo** (https://github.com/tbotnz/cisshgo, MIT), a Go SSH server that imitates Cisco devices. Its platform behaviour is data (transcript files mapped by YAML), and it runs 50 simulated devices on consecutive ports at once. port49 takes two ideas from it:
- **behaviour is data, not code**;
- **fleet mode.**

The direction is reversed: cisshgo is the device's SSH server for an automation client, and port49's mock is the device acting as a **TACACS+ client** of port49d. No cisshgo code is copied.

### The profile's three parts (Ryan, 2026-10-19)

A transcript alone is not enough. A device branches on port49's replies, and the worst production failures are a device rejecting port49's output. So each profile, `tests/qual/profiles/<platform>/<firmware>.yaml`, has three parts.

1. **Stimulus** (data, generated from evidence). What the device sends no matter how port49 replies:
   - the ClientHello;
   - the flight delay;
   - the connection pattern;
   - each step's packet fields and attribute list;
   - the accounting records.
2. **Reaction table** (data, reviewed by hand, pre-filled by the generator). On each reply status or TLS alert, the next action and what the operator sees. Examples: GETPASS → CONTINUE; FAIL → stop; ERROR → the measured fallback (IOS XE 17.18.02 over TLS: break-glass fails); `unknown_ca` → give up; a reply with the single-connect flag → reuse the connection.
3. **Acceptance rules** (data, reviewed by hand). Constraints the device enforces on port49's replies: attribute and reply byte limits, the privilege range, the role names it honours, attribute names it refuses. **Every rule cites the results note that measured it, or is `status: unmeasured`.** An unmeasured rule is printed as a warning and never fails the suite (CLAUDE.md, lab register rule 1).

**The code escape hatch.** Go is written only when a device does something these three parts cannot express. Each case is listed in the profile's `engine_gaps`, naming the Go file that covers it, so the engine's gaps stay visible.

### What the mock asserts, and what it cannot

The engine plays the stimulus against a real port49d (`internal/port49d`'s `run`) and asserts:
- **The ClientHello parameters.** Two phases, because `crypto/tls` cannot reproduce a device's suite order, signature algorithms, x448 group or an IP-literal SNI:
  - (a) a **hello probe** writes the device's exact ClientHello, built byte by byte from the profile with a fresh random and a fresh key share. It reads port49's ServerHello and checks the version, suite and HelloRetryRequest against what port49 answered the real device.
  - (b) the **session** phase runs the TACACS+ exchange over `crypto/tls`, configured as close to the device as the standard library allows: versions, curve order, ALPN, the client chain, and SNI unless it is an IP literal.

  The probe abandons its handshake, which port49 strikes, so it runs on a daemon of its own. Rejected: uTLS. It is a new module, and the probe gives byte-exact fidelity where it matters, which is the server's choice given the offer.
- **The flight timing.** The device's measured wait between port49's server flight and its own reply (NX-OS 10.6(2)F: exactly 5.00 s) is played by a connection wrapper that delays the first write after a read. Per PR, every delay is scaled by 0.1, and port49d runs at `handshake_timeout: 1s`. That is the production default of 10 s scaled the same way, so the delay-to-timeout ratio is exactly production's. One test runs the real 5.00 s against the real 10 s default. One runs a delay past the timeout and expects `handshake_timeout`.
- **The connection pattern.** One connection per TACACS+ step (NX-OS: five per login), or single-connection with the measured reuse.
- **The request attribute lists**, from the decision log's validated request records (`request.raw`), with only lab-specific values made templates: `{user}`, `{rem_addr}`, `{task_id}`, `{start_time}`, `{stop_time}`.
- **The accounting records** (`record.raw`), the same way.
- **The failure cases the notes recorded**: an ERROR reply (the store down, through `lab.fault_file`), a wrong credential, an unknown CA at the handshake, and a delay past `handshake_timeout`.

The engine **cannot** know the device's packet header fields (`action`, `authen_type`, `service`, `authen_method`, `priv_lvl`) from today's records: no record carries them. Task 5 adds a `packet_fields` object to the validated request records. These are enum names with no secret, and spec §5.7 is edited first (decision 52 ruling 3). Header facts that the 12-byte headers alone show (packet count, the single-connect flag) come from `l73PlainHeaders` over plain 49.

### Goldens, and why a reply change does not need the lab before merge

port49's replies to each scenario are pinned in `tests/qual/golden/<platform>/<firmware>.json`. The generator writes the first golden from the lab run. An intentional port49 change rewrites it with `make qual-update` and a reviewed diff. A rewritten golden is marked `"pending_lab": true`; the qualified-platforms list shows it as `re-vet pending`; and the release-tag gate's `make lab-regress` clears it (decision 52 ruling 6). The acceptance rules gate every PR regardless: they are the device's truth, and a golden is only port49's.

### Fleet mode

`devicemock.Fleet` runs N engines at once, each dialling from its own loopback address (127.0.1.1, 127.0.1.2, …, which Linux routes without set-up) against one port49d with N inventory devices. It covers:
- many concurrent logins;
- a reload under load;
- the store going down under load.

It is its own tier (`make qual-fleet`), not on the per-PR path. Plan 12's load validation at the §5 target rate uses it.

### Not built: an SSH front (later work)

cisshgo's SSH server would let a test drive ssh → mock device → TACACS+. It is not worth it now:
- the mock's SSH CLI would be invented behaviour, not measured;
- what a device sends to TACACS+ on an SSH login is already the stimulus;
- the operator's ssh-to-device path is measured on real devices (L54, L64).

It is listed in the roadmap's "leaves for later".

### The tiers

| Tier | Runs | Where | Needs |
|---|---|---|---|
| Mock (`make qual`) | every PR | any runner (`qual.yml`, `runs-on` one line) | Go only |
| Fleet (`make qual-fleet`) | by hand, plan 12's load test | Linux | Go only |
| Free image (`lab-free.yml`) | dispatch and release tags (Q1) | hosted or beehive | Docker, containerlab, SR Linux |
| Real lab (`make lab-regress`, `make qual-vet`) | pre-beta, release tags, a vendor image change (~monthly) | beehive only | the vendor images, the lab lock |

## Review Focus

1. **A credential echoed back.** A fake server that puts the presented token into `server_msg` or `data` must not get it into the transcript, a golden, a failure message or `-v` output. Task 9's `TestTranscriptNeverHoldsTheCredential` and Task 13's `TestGenerateRefusesForbiddenKeys` pin it.
2. **A scaled delay that hides a real timeout.** The per-PR test passes at 0.1 scale while the real 5.00 s fails at the real default. Task 10's `TestQualNXOSRealFlightUnderTheDefault` runs the real numbers.
3. **An unmeasured acceptance rule failing the suite**, or a measured one silently passing. Task 7 pins both. Task 10 proves a violation fails against a real port49d, and that the same policy passes a profile without the rule.
4. **The lab lock between the runner and its children.** The runner holds the flock; a child `go test` that opened the lock file again would be refused, or would run beside another occupant. Task 2 passes the held descriptor to the child (`PORT49_LAB_LOCK_FD`), and a STOP sentinel stops the next entry, never a running cell.
5. **A profile citing evidence that does not back it.** This covers a missing results note, a note for another firmware, and a rule `measured` with no note. Task 6's loader refuses each one.

---

## File structure

**Created**
- `internal/devicemock/profile.go`: the profile types, `Load`, `Validate`.
- `internal/devicemock/accept.go`: the acceptance checker.
- `internal/devicemock/react.go`: the reaction table.
- `internal/devicemock/hello.go`: the ClientHello builder and ServerHello reader (hello probe).
- `internal/devicemock/tlsconf.go`: the session `tls.Config` and the flight-delay connection.
- `internal/devicemock/engine.go`: `Play`, the scenarios, the transcript.
- `internal/devicemock/fleet.go`: `Fleet`.
- `internal/devicemock/*_test.go` and `internal/devicemock/testdata/`: unit tests, fixture profiles and a fake TACACS+ server.
- `internal/port49d/qual_test.go`: `TestQual` and its helpers.
- `internal/port49d/qual_fleet_linux_test.go`: `TestQualFleet`.
- `tests/qual/qual-policy.yaml`: the one policy every conformance run and mock runs under.
- `tests/qual/profiles/`, `tests/qual/golden/`: the profiles and goldens.
- `tests/qual/cmd/genprofile/`: the generator.
- `tests/qual/cmd/qualified/`: the qualified-platforms list generator.
- `tests/qual/vet.sh`: `make qual-vet`.
- `tests/qual/README.md`: the contributor procedures.
- `tests/lab/regress.yaml`: the closed-entry manifest.
- `tests/lab/cmd/lab-regress/`: the runner.
- `tests/lab/cmd/notediff/`: the note differ.
- `tests/lab/occupancy_linux.go`: the inherited lock descriptor.
- `tests/lab/qualify_test.go`: `TestQualify`, the lab conformance run (tag `lab`).
- `tests/lab/qual_evidence.go`: the whitelisted evidence writer (untagged, pure).
- `tests/lab/qual_evidence_unit_test.go`: its unit tests.
- `.github/workflows/qual.yml`, `.github/workflows/lab-free.yml`.
- `docs/qualified-platforms.md`: generated.

**Modified**
- `internal/decision/log.go`: `PacketFields` on `Record`.
- `internal/daemon/authen`, `author`, `acct`: fill `packet_fields`.
- `docs/design/2026-08-23-policy-engine-spec.md`: §5.7, §13 decision 52, §15.
- `tests/lab/occupancy.go`: `labOccupyForRun` takes the inherited lock.
- `tests/lab/l73_dialect.go`: the XR dialect.
- `tests/lab/l76_cells.go`: R3-M1.
- `tests/lab/` regions harness: the M4 cells.
- `Makefile`: `qual`, `qual-update`, `qual-fleet`, `lab-regress`, `lab-qualify`, `qual-vet`.
- `tests/lab/README.md`.
- `docs/superpowers/plans/README.md`.

---

### Task 1: Spec — decision 52, `packet_fields`, the new lab row

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.7 record fields table; §13 after decision 51; §15 table)

**Interfaces:**
- Produces: decision 52 rulings 1–10 (cited by every later task), the `packet_fields` record object (Task 5), and register row **L78** (Task 15). L77 is earmarked for SONiC in the lab queue. If L77 is not yet in §15 when this task runs, still take L78 and leave L77 to SONiC.

- [ ] **Step 1: Write decision 52** after decision 51, in the existing decisions' voice:

```markdown
**52. The qualification suite: mock devices from closed evidence, the lab for vetting (plan 11b;
Ryan, 2026-10-17 and 2026-10-19).**

- **1. A mock is data.** Each vetted platform and firmware is one profile, three parts: stimulus
  (generated from evidence), reactions and acceptance rules (reviewed by hand at vetting). One
  engine, `internal/devicemock`, plays every profile; Go is written only for what a profile cannot
  say, and each such case is listed in the profile's `engine_gaps`. Credit: cisshgo (MIT).
- **2. Evidence, never bodies.** A profile is generated from the decision log's validated request
  records, the `*.tls.json` handshake summaries, the 12-byte headers and the connection timing.
  No TACACS+ body is decoded from a capture. Credentials are minted fresh per test.
- **3. `packet_fields`.** Each validated request record (`redeem`, `authenticate`,
  `authorize_session`, `authorize_command`, `account`) carries the request's header fields as
  enum names: `action`, `authen_type`, `service`, `authen_method`, `priv_lvl`. No user, port,
  address, data or argument: those are recorded where they were already, or never.
- **4. A device claim in a profile cites a results note.** An acceptance rule with no note is
  `unmeasured`: printed, never gating (§15 rule 1). A profile names the note for its firmware.
- **5. One qualification policy.** `tests/qual/qual-policy.yaml` is the policy of every
  conformance run and every mock run, so a golden from the lab is the mock's expectation.
- **6. Goldens.** port49's replies are pinned per profile; a reviewed `make qual-update` may change
  them in a PR, marking the golden `pending_lab`. The qualified-platforms list shows it as
  re-vet pending until the next lab run clears it. Acceptance rules gate every PR.
- **7. The tiers.** Mocks on every PR on any runner; the real lab before pre-beta and release tags
  and on any vendor image change, roughly monthly, not nightly. Vendor images never on a hosted
  runner; a freely redistributable image (SR Linux) may.
- **8. A new firmware gets its mock only after the lab vets it** (`make qual-vet`).
- **9. Time scale.** Per PR, device delays run at 0.1 against `handshake_timeout: 1s`, production's
  ratio; one test runs the real delay against the real default.
- **10. Not a register closure.** A conformance run re-measures rows already closed and cites them;
  it closes nothing by itself, and a row closes only as §15 says.
```

- [ ] **Step 2: Add `packet_fields` to §5.7's record fields.** Find the paragraph that documents `request.raw` and `request.service` (search `"service" AV pair` in §5.7). Add a row or paragraph in the same table style:

```markdown
| `packet_fields` | object | on `redeem`, `authenticate`, `authorize_session`, `authorize_command` and `account`: the request's header fields as names (`action`: login, chpass, sendauth; `authen_type`: ascii, pap, chap, mschap, mschapv2; `service`: none, login, enable, ppp, …; `authen_method`: not_set, none, krb5, line, enable, local, tacacsplus, guest, radius, krb4, rcmd; `priv_lvl`: 0–15). An unknown value is recorded as `unknown_<n>`. Never a user, a port, an address, data or an argument (decision 52 ruling 3). |
```

- [ ] **Step 3: Add row L78 to §15**, after L76:

```markdown
| **L78** | Whether Junos locks a user out when a *permit* session reply totals more than 255 bytes with every attribute at most 255 (port49 never sends one attribute over 255, §6 "Length"): the reply's total byte count at which the login is refused or the user is locked out, if any, and whether break-glass still logs in. L2's run sent a long *deny* `server_msg` only and neither confirms nor refutes this prior (`tests/lab/results/L2-juniper_vjunos-router.md`, "Break-glass around long session denials"). | The Junos profile's `max_reply_bytes` acceptance rule (decision 52 ruling 4); the projection budget (decision 48 ruling 4) | Junos (vJunos-router 23.4R2-S2.1, 26.2R1.7) | open — added 2026-10-19 by plan 11b; Ryan's production prior (a reply over 255 bytes locked the user out) is unmeasured |
```

- [ ] **Step 4: Check the edits render and cross-reference.**

Run: `grep -n '^\*\*52\.' docs/design/2026-08-23-policy-engine-spec.md && grep -c '^| \*\*L78\*\*' docs/design/2026-08-23-policy-engine-spec.md`
Expected: one line for decision 52, and `1`.

- [ ] **Step 5: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: decision 52, packet_fields and L78 for the qualification suite

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 2: `make lab-regress`, the runner and its lock

**Files:**
- Create: `tests/lab/regress.yaml`, `tests/lab/cmd/lab-regress/main.go`, `tests/lab/cmd/lab-regress/main_test.go`, `tests/lab/cmd/lab-regress/lock_linux.go`, `tests/lab/cmd/lab-regress/lock_other.go`, `tests/lab/occupancy_linux.go`, `tests/lab/occupancy_other.go`
- Modify: `tests/lab/occupancy.go` (`labOccupyForRun`), `Makefile`
- Test: `tests/lab/cmd/lab-regress/main_test.go`, `tests/lab/occupancy_unit_test.go` (exists; add a case)

**Interfaces:**
- Produces:
  - `type Entry struct { ID, Target, Run, Platforms string; Env map[string]string; Notes []string; MeasuredMinutes int }` (YAML keys `id`, `target`, `run`, `platforms`, `env`, `notes`, `measured_minutes`).
  - `func loadManifest(path string) ([]Entry, error)`.
  - `func (r *runner) runAll(entries []Entry) report`.
  - Env `PORT49_LAB_LOCK_FD`: the descriptor number of an already-held `/tmp/port49-lab.lock`.
  - `func labInheritedLock() (release func(), ok bool, err error)` in `tests/lab`.

The runner holds the lab lock for the whole run and hands the held descriptor to each child `go test`. The child's `labOccupyForRun` sees `PORT49_LAB_LOCK_FD`, checks that the descriptor really is that file and is held (`flock(LOCK_EX|LOCK_NB)` on the same open file description succeeds), and opens nothing. A child that finds the variable but a different file refuses to run.

- [ ] **Step 1: Write the manifest.** It is one entry per closed register row that has a harness, in the order `make lab` runs them. Write it from `grep -n '^lab-\|go test -tags lab' Makefile` and spec §15's closed rows. Start with these, then add every other closed row that has a `-run` selector in the Makefile or the lab README:

```yaml
# The closed lab entries `make lab-regress` reruns (plan 11b, decision 52 ruling 7).
# One entry per harness run. `run` is the go test -run pattern; `platforms` the
# PORT49_LAB_PLATFORMS value; `env` passes through (PORT49_LAB_REMEASURE re-measures a
# closed row); `notes` are the results notes the run rewrites, which notediff compares.
# measured_minutes is the last full run's wall time for the entry (Task 4).
entries:
  - {id: L1-L2-L13, target: lab, run: '^TestLoginRoundTrip$|^TestL1|^TestL2$|^TestL13', platforms: "eos,vjunos,vsrx,nxos,iosxe",
     notes: [tests/lab/results/L1-arista_eos.md, tests/lab/results/L2-arista_eos.md, tests/lab/results/L13-arista_eos.md]}
  - {id: L73-vjunos26, target: lab, run: '^TestL73$', platforms: vjunos26, notes: [tests/lab/results/L73-juniper_vjunos-router.md]}
  - {id: L73-iosxe1718, target: lab, run: '^TestL73$', platforms: iosxe1718, notes: [tests/lab/results/L73-cisco_iosxe.md]}
  - {id: L73-nxos106, target: lab, run: '^TestL73$', platforms: nxos106, notes: [tests/lab/results/L73-cisco_nxos.md]}
  - {id: L73-ceos436, target: lab, run: '^TestL73$', platforms: ceos436, notes: [tests/lab/results/L73-arista_ceos.md]}
  - {id: L76-srlinux, target: lab, run: '^TestL76$', platforms: srlinux, notes: [tests/lab/results/L76-nokia_srlinux.md]}
  - {id: L74-L75, target: lab-regions, run: '^TestRegions$', notes: [tests/lab/results/L74-regions.md, tests/lab/results/L75-regions.md]}
```

- [ ] **Step 2: Write the failing runner tests**

```go
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadManifestRefusesAnUnknownKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.yaml")
	os.WriteFile(p, []byte("entries:\n  - {id: L1, run: x, notez: []}\n"), 0o600)
	if _, err := loadManifest(p); err == nil || !strings.Contains(err.Error(), "notez") {
		t.Fatalf("an unknown key must be refused by name: %v", err)
	}
}

func TestTheStopSentinelStopsBeforeTheNextEntry(t *testing.T) {
	dir := t.TempDir()
	stop := filepath.Join(dir, "STOP")
	var ran []string
	r := &runner{stopPath: stop, exec: func(e Entry) error {
		ran = append(ran, e.ID)
		os.WriteFile(stop, nil, 0o600) // the operator asks to stop during the first entry
		return nil
	}}
	rep := r.runAll([]Entry{{ID: "a"}, {ID: "b"}})
	if len(ran) != 1 || ran[0] != "a" || rep.Stopped != "b" {
		t.Fatalf("ran %v, stopped before %q; the running entry finishes and the next never starts", ran, rep.Stopped)
	}
}

func TestAFailedEntryStopsTheRun(t *testing.T) {
	r := &runner{stopPath: filepath.Join(t.TempDir(), "none"), exec: func(e Entry) error {
		if e.ID == "a" {
			return os.ErrDeadlineExceeded
		}
		return nil
	}}
	rep := r.runAll([]Entry{{ID: "a"}, {ID: "b"}})
	if len(rep.Done) != 0 || rep.Failed != "a" {
		t.Fatalf("a failed entry ends the run, as make lab does: %+v", rep)
	}
}

func TestTheChildEnvironmentCarriesTheLockAndNoSecretVariable(t *testing.T) {
	t.Setenv("PORT49_LAB_TOKEN_DUMP", "x") // any variable naming a token is not passed on
	env := childEnv(Entry{Platforms: "eos", Env: map[string]string{"PORT49_LAB_REMEASURE": "L1"}}, 3)
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PORT49_LAB_LOCK_FD=3", "PORT49_LAB_PLATFORMS=eos", "PORT49_LAB_REMEASURE=L1"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("child env lacks %s", want)
		}
	}
	if strings.Contains(joined, "TOKEN_DUMP") {
		t.Fatal("a variable naming a token reached the child")
	}
}
```

- [ ] **Step 3: Run them to verify they fail**

Run: `go test ./tests/lab/cmd/lab-regress/ -count=1`
Expected: FAIL (`undefined: loadManifest`, `runner`, `childEnv`).

- [ ] **Step 4: Implement the runner**

```go
// Command lab-regress reruns the closed lab entries in tests/lab/regress.yaml on
// the lab host, under the lab lock, and diffs each rewritten results note
// against the committed one (plan 11b; spec §13 decision 52 ruling 7).
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	lockPath = "/tmp/port49-lab.lock"
	stopPath = "/tmp/port49-STOP-LAB"
)

type Entry struct {
	ID              string            `yaml:"id"`
	Target          string            `yaml:"target"`
	Run             string            `yaml:"run"`
	Platforms       string            `yaml:"platforms"`
	Env             map[string]string `yaml:"env"`
	Notes           []string          `yaml:"notes"`
	MeasuredMinutes int               `yaml:"measured_minutes"`
}

func loadManifest(path string) ([]Entry, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var m struct {
		Entries []Entry `yaml:"entries"`
	}
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return m.Entries, nil
}

type report struct {
	Done           []string
	Minutes        map[string]float64
	Stopped, Failed string
}

type runner struct {
	stopPath string
	exec     func(Entry) error
}

func (r *runner) runAll(entries []Entry) report {
	rep := report{Minutes: map[string]float64{}}
	for _, e := range entries {
		if _, err := os.Stat(r.stopPath); err == nil {
			rep.Stopped = e.ID
			return rep
		}
		start := time.Now()
		if err := r.exec(e); err != nil {
			rep.Failed = e.ID
			return rep
		}
		rep.Done = append(rep.Done, e.ID)
		rep.Minutes[e.ID] = time.Since(start).Minutes()
	}
	return rep
}

// childEnv is the child's environment: the caller's, less any variable whose
// name holds TOKEN, SECRET or PASSWORD, plus the held lock's descriptor and
// the entry's own settings.
func childEnv(e Entry, lockFD int) []string {
	var env []string
	for _, kv := range os.Environ() {
		name := strings.ToUpper(strings.SplitN(kv, "=", 2)[0])
		if strings.Contains(name, "TOKEN") || strings.Contains(name, "SECRET") || strings.Contains(name, "PASSWORD") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, fmt.Sprintf("PORT49_LAB_LOCK_FD=%d", lockFD))
	if e.Platforms != "" {
		env = append(env, "PORT49_LAB_PLATFORMS="+e.Platforms)
	}
	for k, v := range e.Env {
		env = append(env, k+"="+v)
	}
	return env
}

func main() {
	manifest := flag.String("manifest", "tests/lab/regress.yaml", "the closed-entry manifest")
	only := flag.String("only", "", "comma-separated entry ids; empty runs all")
	dry := flag.Bool("dry-run", false, "list the entries and the last measured minutes, run nothing")
	flag.Parse()
	entries, err := loadManifest(*manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	entries = pick(entries, *only)
	if *dry {
		total := 0
		for _, e := range entries {
			fmt.Printf("%-16s %-12s %4d min  %s\n", e.ID, e.Platforms, e.MeasuredMinutes, e.Run)
			total += e.MeasuredMinutes
		}
		fmt.Printf("total %d min (last measured)\n", total)
		return
	}
	lock, err := holdLock(lockPath, "lab-regress pid "+fmt.Sprint(os.Getpid()))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	r := &runner{stopPath: stopPath, exec: func(e Entry) error {
		target := e.Target
		if target == "" {
			target = "lab"
		}
		fmt.Printf("=== lab-regress %s (%s) ===\n", e.ID, target)
		cmd := exec.Command("go", "test", "-tags", "lab", "./tests/lab/", "-run", e.Run, "-count=1", "-v", "-timeout", "300m")
		cmd.Env = childEnv(e, 3)
		cmd.ExtraFiles = []*os.File{lock} // fd 3 in the child
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}
		return diffNotes(e.Notes)
	}}
	rep := r.runAll(entries)
	printReport(rep)
	if rep.Failed != "" || rep.Stopped != "" {
		os.Exit(1)
	}
}

func pick(all []Entry, only string) []Entry {
	if only == "" {
		return all
	}
	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		want[strings.TrimSpace(id)] = true
	}
	var out []Entry
	for _, e := range all {
		if want[e.ID] {
			out = append(out, e)
		}
	}
	return out
}

// diffNotes runs notediff (Task 3) on each note against HEAD; a changed
// observation is reported, not failed: the lab is the truth, and a change
// is for a person to read (CLAUDE.md, lab register rule 4).
func diffNotes(notes []string) error {
	for _, n := range notes {
		cmd := exec.Command("go", "run", "./tests/lab/cmd/notediff", "-note", n)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("notediff %s: %w", n, err)
		}
	}
	return nil
}

func printReport(rep report) {
	total := 0.0
	for _, id := range rep.Done {
		fmt.Printf("lab-regress: %-16s %6.1f min\n", id, rep.Minutes[id])
		total += rep.Minutes[id]
	}
	fmt.Printf("lab-regress: %d entr(y/ies) done in %.1f min", len(rep.Done), total)
	if rep.Stopped != "" {
		fmt.Printf("; stopped by %s before %s", stopPath, rep.Stopped)
	}
	if rep.Failed != "" {
		fmt.Printf("; %s FAILED, the entries after it were not run", rep.Failed)
	}
	fmt.Println()
}
```

`lock_linux.go` (`//go:build linux`):

```go
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// holdLock takes /tmp/port49-lab.lock exclusively and without waiting, as the
// lab's own labOccupy does, writes who into it, and returns the open file:
// its descriptor is passed to each child, which then holds the same lock.
func holdLock(path, who string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		holder, _ := os.ReadFile(path)
		f.Close()
		return nil, fmt.Errorf("the lab is occupied: %s holds %s; wait for it, never kill it", strings.TrimSpace(string(holder)), path)
	}
	_ = f.Truncate(0)
	_, _ = f.WriteAt([]byte(who+"\n"), 0)
	return f, nil
}
```

`lock_other.go` (`//go:build !linux`): `func holdLock(string, string) (*os.File, error) { return nil, errors.New("lab-regress runs on the Linux lab host only") }`.

- [ ] **Step 5: The child takes the inherited lock.** In `tests/lab/occupancy_linux.go` (`//go:build linux`):

```go
package lab

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// labInheritedLock adopts the lab lock a parent (lab-regress) holds and passed
// as PORT49_LAB_LOCK_FD. ok is false when the variable is unset. The
// descriptor must be labLockPath itself (same device and inode) and held:
// flock on the same open file description succeeds, and a fresh open by
// another process would not.
func labInheritedLock() (release func(), ok bool, err error) {
	v := os.Getenv("PORT49_LAB_LOCK_FD")
	if v == "" {
		return nil, false, nil
	}
	fd, err := strconv.Atoi(v)
	if err != nil || fd < 3 {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD=%q is not an inherited descriptor", v)
	}
	var have, want syscall.Stat_t
	if err := syscall.Fstat(fd, &have); err != nil {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d: %v", fd, err)
	}
	if err := syscall.Stat(labLockPath, &want); err != nil || have.Dev != want.Dev || have.Ino != want.Ino {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d is not %s", fd, labLockPath)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d is not held: %v", fd, err)
	}
	return func() {}, true, nil // the parent releases it
}
```

`tests/lab/occupancy_other.go` (`//go:build !linux`): `func labInheritedLock() (func(), bool, error) { return nil, false, nil }`.

In `labOccupyForRun`, before `labOccupy`:

```go
	if release, ok, err := labInheritedLock(); ok {
		if err != nil {
			return err
		}
		labHeld = release
		return nil
	}
```

- [ ] **Step 6: Add the occupancy unit case** to `tests/lab/occupancy_unit_test.go`. Put it in `occupancy_linux_unit_test.go` (`//go:build lab && linux`), and keep the name `*_unit_test.go` so `make lab-unit` runs it:

```go
func TestLabInheritedLockRefusesAnotherFile(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "notthelock")
	t.Setenv("PORT49_LAB_LOCK_FD", fmt.Sprint(f.Fd()))
	if _, ok, err := labInheritedLock(); !ok || err == nil {
		t.Fatalf("a descriptor that is not %s must be refused: ok %v err %v", labLockPath, ok, err)
	}
}
```

- [ ] **Step 7: Makefile**

```make
# The closed lab entries, rerun under the lab lock and diffed against their notes
# (plan 11b). Beehive only. LAB_REGRESS_ARGS passes -only, -dry-run.
lab-regress:
	go run ./tests/lab/cmd/lab-regress -manifest tests/lab/regress.yaml $(LAB_REGRESS_ARGS)
```

Add `lab-regress` to `.PHONY`.

- [ ] **Step 8: Run the tests**

Run: `go test ./tests/lab/cmd/lab-regress/ -count=1 && make lab-unit && GOOS=darwin go vet ./tests/lab/cmd/lab-regress/ && go run ./tests/lab/cmd/lab-regress -dry-run`
Expected: PASS, then the entry list with `total 0 min (last measured)`.

- [ ] **Step 9: Commit**

```bash
git add tests/lab/regress.yaml tests/lab/cmd/lab-regress tests/lab/occupancy.go tests/lab/occupancy_linux.go tests/lab/occupancy_other.go tests/lab/occupancy_linux_unit_test.go Makefile
git commit -m "test: make lab-regress reruns closed entries under one held lab lock

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 3: `notediff`, a results note compared with its committed copy

**Files:**
- Create: `tests/lab/cmd/notediff/main.go`, `tests/lab/cmd/notediff/main_test.go`

**Interfaces:**
- Produces: `func normalize(note string) []string` and `func changed(old, new []string) (removed, added []string)`. The command prints `notediff: <note>: unchanged` or the removed and added observation lines, and exits 0 either way. It exits 2 only on an I/O error.

A rerun rewrites volatile lines that are not observations: the date, the run commit, packet counts, timestamps, durations, ports, lab user numbers. `normalize` masks them so only a changed observation shows.

- [ ] **Step 1: Write the failing test**

```go
package main

import "testing"

func TestNormalizeMasksWhatARerunAlwaysChanges(t *testing.T) {
	a := normalize("- **Date measured:** 2026-10-18\n- **Run:** commit `7ff5249f`, x\nlogin took 21.2 s at 2026-10-18T06:22:54Z on port 48350 as alice03\n- (h) NX-OS opened 5 connections\n")
	b := normalize("- **Date measured:** 2026-11-20\n- **Run:** commit `0abc1234`, x\nlogin took 20.9 s at 2026-11-20T01:02:03Z on port 51111 as alice05\n- (h) NX-OS opened 5 connections\n")
	if r, ad := changed(a, b); len(r) != 0 || len(ad) != 0 {
		t.Fatalf("only volatile lines differ, yet: -%q +%q", r, ad)
	}
}

func TestChangedNamesAChangedObservation(t *testing.T) {
	a := normalize("- (h) NX-OS opened 5 connections\n")
	b := normalize("- (h) NX-OS opened 6 connections\n")
	if r, ad := changed(a, b); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("a changed count is an observation: -%q +%q", r, ad)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./tests/lab/cmd/notediff/ -count=1`
Expected: FAIL (`undefined: normalize`).

- [ ] **Step 3: Implement**

```go
// Command notediff compares a results note a lab rerun rewrote with the copy at
// HEAD, masking what every rerun changes, so the lines it prints are changed
// observations (plan 11b). It reports; it does not judge: the lab is the truth.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

var volatile = []struct {
	re  *regexp.Regexp
	rep string
}{
	{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z`), "<ts>"},
	{regexp.MustCompile(`\b\d{4}-\d{2}-\d{2}\b`), "<date>"},
	{regexp.MustCompile("commit `[0-9a-f]{7,40}`"), "commit `<sha>`"},
	{regexp.MustCompile(`\b\d+(\.\d+)? ?(ms|s|min)\b`), "<dur>"},
	{regexp.MustCompile(`\bport \d{4,5}\b`), "port <n>"},
	{regexp.MustCompile(`\balice\d{2}\b`), "alice<nn>"},
	{regexp.MustCompile(`\b\d+ packets\b`), "<n> packets"},
	{regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`), "<LONG>"},
}

func normalize(note string) []string {
	var out []string
	for _, l := range strings.Split(note, "\n") {
		for _, v := range volatile {
			l = v.re.ReplaceAllString(l, v.rep)
		}
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func changed(old, new []string) (removed, added []string) {
	count := map[string]int{}
	for _, l := range old {
		count[l]++
	}
	for _, l := range new {
		if count[l] > 0 {
			count[l]--
			continue
		}
		added = append(added, l)
	}
	for _, l := range old {
		if count[l] > 0 {
			count[l]--
			removed = append(removed, l)
		}
	}
	return removed, added
}

func main() {
	note := flag.String("note", "", "a results note path")
	flag.Parse()
	head, err := exec.Command("git", "show", "HEAD:"+*note).Output()
	if err != nil {
		fmt.Printf("notediff: %s: new (not at HEAD)\n", *note)
		return
	}
	now, err := os.ReadFile(*note)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	r, a := changed(normalize(string(head)), normalize(string(now)))
	if len(r) == 0 && len(a) == 0 {
		fmt.Printf("notediff: %s: unchanged\n", *note)
		return
	}
	fmt.Printf("notediff: %s: %d observation line(s) changed\n", *note, len(r)+len(a))
	for _, l := range r {
		fmt.Println("  - " + l)
	}
	for _, l := range a {
		fmt.Println("  + " + l)
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./tests/lab/cmd/notediff/ -count=1 && go run ./tests/lab/cmd/notediff -note tests/lab/results/L73-cisco_nxos.md`
Expected: PASS, then `notediff: tests/lab/results/L73-cisco_nxos.md: unchanged`.

- [ ] **Step 5: Commit**

```bash
git add tests/lab/cmd/notediff
git commit -m "test: notediff names a rerun's changed observations and masks the rest

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 4: Lab — the first full `make lab-regress`, timed

**Files:**
- Modify: `tests/lab/regress.yaml` (`measured_minutes` per entry), `tests/lab/README.md` (a "Regressions" section)

This task runs on beehive. It is the early measurement Ryan asked for: how long the real full run takes, which decides whether "pre-beta and release tags" can take a whole run or need `-only`. It may run while Tasks 5–11 are coded: they touch no lab file.

- [ ] **Step 1: Pre-flight.** The STOP sentinel is absent, nobody holds the lock (`flock -n /tmp/port49-lab.lock true`), `make build` is done, and every image in the manifest is present (`docker image inspect`). Start the stall watchdog: a background `sleep 1800; echo WATCHDOG`, re-armed each wake.

- [ ] **Step 2: Run it**

Run (600000 ms tool timeout; re-attach and keep waiting while it runs): `make lab-regress 2>&1 | tee /tmp/claude-lab-regress-$(date +%F).log`
Read the log only through: `grep -v -i 'password\|token\|secret\|eyJ' /tmp/claude-lab-regress-*.log | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g' | grep 'lab-regress\|notediff\|FAIL\|ok '`
Expected: one `lab-regress: <id> <n> min` line per entry and a total. Each notediff line is `unchanged`, or changed lines for a person to read.

- [ ] **Step 3: Record what was measured.** Write each entry's minutes into `measured_minutes`. Add a `## Regressions (plan 11b)` section to `tests/lab/README.md` that gives:
  - the date;
  - the commit;
  - the total wall time;
  - the slowest three entries;
  - how to run a subset (`make lab-regress LAB_REGRESS_ARGS=-only=L73-nxos106`).

Any changed observation is investigated before this task closes. The lab is the truth: a doc it contradicts is fixed and cited (CLAUDE.md rule 4), in its own `docs:` commit.

- [ ] **Step 4: Copy raw captures** from any worktree used to `tests/lab/captures/` on main, so the labpcap audit stays whole.

- [ ] **Step 5: Commit**

```bash
git add tests/lab/regress.yaml tests/lab/README.md
git commit -m "test: the first full lab-regress run, timed per entry

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 5: `packet_fields` on the validated request records

**Files:**
- Modify: `internal/decision/log.go`, the record builders in `internal/daemon/authen`, `internal/daemon/author` and `internal/daemon/acct` (find them with `grep -rn 'Event: *"redeem"\|Event: *"authorize_session"\|Event: *"authorize_command"\|Event: *"account"' internal/daemon`)
- Test: `internal/decision/log_test.go`, and each handler's existing record test file

**Interfaces:**
- Produces:

```go
// PacketFields is a validated request's header fields, as names (spec §5.7;
// §13 decision 52 ruling 3). Never a user, a port, an address, data or an
// argument.
type PacketFields struct {
	Action       string `json:"action,omitempty"`        // authen START only
	AuthenType   string `json:"authen_type"`
	Service      string `json:"service"`
	AuthenMethod string `json:"authen_method,omitempty"` // author and acct only
	PrivLvl      uint8  `json:"priv_lvl"`
}

func AuthenFields(s wire.AuthenStart) *PacketFields
func AuthorFields(r wire.AuthorRequest) *PacketFields
func AcctFields(r wire.AcctRequest) *PacketFields
```

and `Record.PacketFields *PacketFields \`json:"packet_fields,omitempty"\``.

- [ ] **Step 1: Write the failing test** in `internal/decision/log_test.go`:

```go
func TestPacketFieldsNameTheHeaderAndNothingElse(t *testing.T) {
	f := AuthenFields(wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, PrivLvl: 1, User: []byte("u"), Port: []byte("tty1"),
		RemAddr: []byte("192.0.2.1"), Data: []byte("SECRET-DATA")})
	b, _ := json.Marshal(Record{Event: "redeem", PacketFields: f})
	got := string(b)
	for _, want := range []string{`"action":"login"`, `"authen_type":"pap"`, `"service":"login"`, `"priv_lvl":1`} {
		if !strings.Contains(got, want) {
			t.Fatalf("%s lacks %s", got, want)
		}
	}
	for _, never := range []string{"SECRET-DATA", "tty1", "192.0.2.1", `"u"`} {
		if strings.Contains(got, never) {
			t.Fatalf("packet_fields carried %q: %s", never, got)
		}
	}
	if AuthorFields(wire.AuthorRequest{AuthenMethod: 0x7e}).AuthenMethod != "unknown_126" {
		t.Fatal("an unknown method is named unknown_<n>")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/decision/ -run TestPacketFieldsNameTheHeaderAndNothingElse -count=1`
Expected: FAIL (`undefined: AuthenFields`).

- [ ] **Step 3: Implement** in `internal/decision/packet.go`:

```go
package decision

import (
	"fmt"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

type PacketFields struct {
	Action       string `json:"action,omitempty"`
	AuthenType   string `json:"authen_type"`
	Service      string `json:"service"`
	AuthenMethod string `json:"authen_method,omitempty"`
	PrivLvl      uint8  `json:"priv_lvl"`
}

func named(m map[uint8]string, v uint8) string {
	if s, ok := m[v]; ok {
		return s
	}
	return fmt.Sprintf("unknown_%d", v)
}

var (
	actions  = map[uint8]string{wire.AuthenActionLogin: "login", wire.AuthenActionChPass: "chpass", wire.AuthenActionSendAuth: "sendauth"}
	types    = map[uint8]string{0: "not_set", wire.AuthenTypeASCII: "ascii", wire.AuthenTypePAP: "pap", wire.AuthenTypeCHAP: "chap", wire.AuthenTypeMSCHAP: "mschap", wire.AuthenTypeMSCHAPv2: "mschapv2"}
	services = map[uint8]string{wire.AuthenServiceNone: "none", wire.AuthenServiceLogin: "login", wire.AuthenServiceEnable: "enable", wire.AuthenServicePPP: "ppp", 5: "pt", 6: "rcmd", 7: "x25", 8: "nasi", 9: "fwproxy"}
	methods  = map[uint8]string{wire.AuthenMethodNotSet: "not_set", wire.AuthenMethodNone: "none", wire.AuthenMethodKRB5: "krb5", wire.AuthenMethodLine: "line", wire.AuthenMethodEnable: "enable", wire.AuthenMethodLocal: "local", wire.AuthenMethodTACACSPlus: "tacacsplus", wire.AuthenMethodGuest: "guest", wire.AuthenMethodRADIUS: "radius", wire.AuthenMethodKRB4: "krb4", wire.AuthenMethodRCMD: "rcmd"}
)

func AuthenFields(s wire.AuthenStart) *PacketFields {
	return &PacketFields{Action: named(actions, s.Action), AuthenType: named(types, s.AuthenType),
		Service: named(services, s.Service), PrivLvl: s.PrivLvl}
}

func AuthorFields(r wire.AuthorRequest) *PacketFields {
	return &PacketFields{AuthenType: named(types, r.AuthenType), Service: named(services, r.Service),
		AuthenMethod: named(methods, r.AuthenMethod), PrivLvl: r.PrivLvl}
}

func AcctFields(r wire.AcctRequest) *PacketFields {
	return &PacketFields{AuthenType: named(types, r.AuthenType), Service: named(services, r.Service),
		AuthenMethod: named(methods, r.AuthenMethod), PrivLvl: r.PrivLvl}
}
```

Add the `PacketFields` field to `Record` after `Request`. In each handler, where the record for a **validated** request is built, set `PacketFields: decision.AuthenFields(start)`, `AuthorFields(req)` or `AcctFields(req)`. An `unvalidated` record gets nothing.

- [ ] **Step 4: One record test per handler.** In each handler's existing record test, add an assertion that the record it already checks carries `packet_fields` with the request's `authen_type`. For example, in the authen handler's test that checks a `redeem` record:

```go
	if pf := rec.PacketFields; pf == nil || pf.AuthenType != "pap" || pf.Action != "login" {
		t.Fatalf("redeem record's packet_fields: %+v", rec.PacketFields)
	}
```

- [ ] **Step 5: Run**

Run: `go test ./internal/decision/ ./internal/daemon/... -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/decision internal/daemon
git commit -m "feat: validated request records carry packet_fields (decision 52 ruling 3)

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 6: `internal/devicemock` — the profile, its loader and validator

**Files:**
- Create: `internal/devicemock/profile.go`, `internal/devicemock/profile_test.go`, `internal/devicemock/testdata/notes/L99-fixture_junos.md`, `internal/devicemock/testdata/profiles/fixture_junos.yaml`, `internal/devicemock/testdata/profiles/fixture_plain.yaml`

**Interfaces:**
- Produces (every later task uses these names):

```go
type Profile struct {
	SchemaVersion int              `yaml:"schema_version"` // 1
	Platform      string           `yaml:"platform"`       // port49 inventory platform: cisco_nxos
	LabPlatform   string           `yaml:"lab_platform"`   // results-note platform name
	Firmware      string           `yaml:"firmware"`       // as the device reports it: 10.6(2)F
	Image         string           `yaml:"image"`          // the note's Image version line
	Vetted        Vetted           `yaml:"vetted"`
	Transports    []string         `yaml:"transports"`     // tcp, tls
	Scenarios     []string         `yaml:"scenarios"`      // the conformance scenarios this profile plays
	Stimulus      Stimulus         `yaml:"stimulus"`
	Reactions     []Reaction       `yaml:"reactions"`
	Acceptance    []AcceptanceRule `yaml:"acceptance"`
	EngineGaps    []EngineGap      `yaml:"engine_gaps"`
	Golden        string           `yaml:"golden"`         // relative to the repository root
}
type Vetted struct {
	Date     string   `yaml:"date"`
	Commit   string   `yaml:"commit"`
	Evidence string   `yaml:"evidence"` // tests/lab/evidence/QUAL-<platform>-<firmware>/
	Notes    []string `yaml:"notes"`
}
type Source struct {
	Note     string `yaml:"note"`     // tests/lab/results/...
	Register string `yaml:"register"` // L73
}
type Stimulus struct {
	TLS         *TLSStimulus `yaml:"tls"`
	Connections ConnPattern  `yaml:"connections"`
	Steps       []Step       `yaml:"steps"`
	Sources     []Source     `yaml:"sources"`
}
type TLSStimulus struct {
	ClientHello    Hello         `yaml:"client_hello"`
	ServerHello    ServerHello   `yaml:"server_hello"`    // what port49 answered the device in the lab
	FlightDelay    time.Duration `yaml:"flight_delay"`
	ClientChain    string        `yaml:"client_chain"`    // leaf, leaf_and_intermediate
	ServerIdentity string        `yaml:"server_identity"` // chain_only, ip, dns
	Sources        []Source      `yaml:"sources"`
}
type Hello struct {
	LegacyVersion       uint16   `yaml:"legacy_version"`
	SupportedVersions   []uint16 `yaml:"supported_versions"`
	CipherSuites        []uint16 `yaml:"cipher_suites"`
	SupportedGroups     []uint16 `yaml:"supported_groups"`
	SignatureAlgorithms []uint16 `yaml:"signature_algorithms"`
	SNI                 string   `yaml:"sni"` // "" none; "{server_ip}" the literal address
	ALPN                []string `yaml:"alpn"`
	PSKModes            []uint8  `yaml:"psk_key_exchange_modes"`
	Extensions          []uint16 `yaml:"extensions"` // in the device's order
}
type ServerHello struct {
	SelectedVersion   uint16 `yaml:"selected_version"`
	CipherSuite       uint16 `yaml:"cipher_suite"`
	HelloRetryRequest bool   `yaml:"hello_retry_request"`
}
type ConnPattern struct {
	Mode              string `yaml:"mode"`                // per_step, single_connection
	SingleConnectFlag bool   `yaml:"single_connect_flag"` // the device sets 0x04 in its first header
}
type Step struct {
	Name   string       `yaml:"name"`  // login, authorize_session, command_permitted, command_denied, account_start, account_stop
	Type   string       `yaml:"type"`  // authen, author, acct
	Fields PacketFields `yaml:"fields"`
	Port   string       `yaml:"port"`  // as recorded; "" none
	Args   []string     `yaml:"args"`  // with {user} {rem_addr} {task_id} {start_time} {stop_time}
	Flags  string       `yaml:"flags"` // acct: start, stop, watchdog
}
type PacketFields struct {
	Action       string `yaml:"action"`
	AuthenType   string `yaml:"authen_type"`
	Service      string `yaml:"service"`
	AuthenMethod string `yaml:"authen_method"`
	PrivLvl      uint8  `yaml:"priv_lvl"`
}
type Reaction struct {
	Step    string   `yaml:"step"`    // a step name or "*"
	On      string   `yaml:"on"`      // see reactOn
	Then    string   `yaml:"then"`    // see reactThen
	Outcome string   `yaml:"outcome"` // see outcomes; "" when the step goes on
	Status  string   `yaml:"status"`  // measured, unmeasured
	Sources []Source `yaml:"sources"`
}
type AcceptanceRule struct {
	ID      string   `yaml:"id"`
	Kind    string   `yaml:"kind"`    // max_attribute_bytes, max_reply_bytes, priv_lvl_range, attribute_refused, role_names
	Applies string   `yaml:"applies"` // authorize_session, command_permitted, any
	Max     int      `yaml:"max"`
	Min     int      `yaml:"min"`
	Names   []string `yaml:"names"`
	Effect  string   `yaml:"effect"`  // lockout, session_refused, attribute_ignored
	Status  string   `yaml:"status"`  // measured, unmeasured
	Sources []Source `yaml:"sources"`
	Note    string   `yaml:"note"`
}
type EngineGap struct {
	ID      string   `yaml:"id"`
	What    string   `yaml:"what"`
	Code    string   `yaml:"code"` // the Go file that covers it, or "" when uncovered
	Sources []Source `yaml:"sources"`
}

func Load(path, repoRoot string) (*Profile, error) // strict decode, then Validate
func (p *Profile) Validate(repoRoot string) error
```

- [ ] **Step 1: Write the fixtures.** `testdata/notes/L99-fixture_junos.md` is a stand-in results note for tests. Paths in fixtures are relative to `internal/devicemock/testdata` (the `repoRoot` the tests pass):

```markdown
# L99 — fixture_junos

- **Date measured:** 2026-10-19
- **Platform:** fixture_junos (a unit-test fixture, not a lab measurement)
- **Image version:** fixture 1.0
```

`testdata/profiles/fixture_plain.yaml`:

```yaml
schema_version: 1
platform: juniper_junos
lab_platform: fixture_junos
firmware: "1.0"
image: fixture 1.0
vetted: {date: 2026-10-19, commit: 0000000, evidence: "", notes: [notes/L99-fixture_junos.md]}
transports: [tcp]
scenarios: [token_login, wrong_credential, store_unavailable]
stimulus:
  connections: {mode: per_step, single_connect_flag: false}
  sources: [{note: notes/L99-fixture_junos.md, register: L99}]
  steps:
    - {name: login, type: authen, fields: {action: login, authen_type: pap, service: login, priv_lvl: 1}, port: "0"}
    - {name: authorize_session, type: author, fields: {authen_type: pap, service: login, authen_method: tacacsplus, priv_lvl: 1},
       port: "0", args: ["service=junos-exec"]}
    - {name: account_start, type: acct, flags: start, fields: {authen_type: pap, service: login, authen_method: tacacsplus, priv_lvl: 1},
       port: "0", args: ["task_id={task_id}", "start_time={start_time}", "service=shell"]}
reactions:
  - {step: login, on: authen_pass, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: login, on: authen_fail, then: stop, outcome: login_refused, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: login, on: authen_error, then: failover_local, outcome: falls_to_local, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: "*", on: author_pass_add, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: "*", on: author_pass_repl, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: "*", on: acct_success, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
acceptance: []
engine_gaps: []
golden: golden/fixture_plain.json
```

`testdata/profiles/fixture_junos.yaml` is the same file plus one rule:

```yaml
acceptance:
  - id: junos_reply_total
    kind: max_reply_bytes
    applies: authorize_session
    max: 255
    effect: lockout
    status: measured
    sources: [{note: notes/L99-fixture_junos.md, register: L99}]
    note: a fixture of L78's claim, measured here so the gate can be tested
```

- [ ] **Step 2: Write the failing tests**

```go
package devicemock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const root = "testdata"

func TestLoadAFixture(t *testing.T) {
	p, err := Load("testdata/profiles/fixture_junos.yaml", root)
	if err != nil {
		t.Fatal(err)
	}
	if p.Platform != "juniper_junos" || len(p.Stimulus.Steps) != 3 || p.Acceptance[0].Max != 255 {
		t.Fatalf("%+v", p)
	}
}

func refused(t *testing.T, edit func(string) string, want string) {
	t.Helper()
	raw, _ := os.ReadFile("testdata/profiles/fixture_junos.yaml")
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(edit(string(raw))), 0o600)
	_, err := Load(path, root)
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("want an error naming %q, got %v", want, err)
	}
}

func TestLoadRefuses(t *testing.T) {
	t.Run("an unknown key", func(t *testing.T) {
		refused(t, func(s string) string { return s + "camelCase: 1\n" }, "camelCase")
	})
	t.Run("a missing note", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "notes/L99-fixture_junos.md, register: L99}]\n    note:", "notes/L98-gone.md, register: L98}]\n    note:", 1) }, "L98-gone.md")
	})
	t.Run("a measured rule with no source", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "    sources: [{note: notes/L99-fixture_junos.md, register: L99}]\n    note:", "    note:", 1) }, "junos_reply_total")
	})
	t.Run("a note for another firmware", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, `firmware: "1.0"`, `firmware: "2.0"`, 1) }, "firmware")
	})
	t.Run("an unknown reaction", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "then: stop", "then: shrug", 1) }, "shrug")
	})
	t.Run("a credential-shaped value", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, `"service=junos-exec"`, `"credential_sha256=ab"`, 1) }, "credential_sha256")
	})
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/devicemock/ -count=1`
Expected: FAIL (`undefined: Load`).

- [ ] **Step 4: Implement `profile.go`.** Put in it the types above, plus:

```go
var (
	stepTypes  = set("authen", "author", "acct")
	stepNames  = set("login", "authorize_session", "command_permitted", "command_denied", "account_start", "account_stop")
	scenarios  = set("token_login", "wrong_credential", "store_unavailable", "single_connection", "unknown_ca", "flight_delay")
	reactOn    = set("authen_pass", "authen_fail", "authen_getpass", "authen_getuser", "authen_getdata", "authen_error",
		"author_pass_add", "author_pass_repl", "author_fail", "author_error", "acct_success", "acct_error",
		"conn_reset", "conn_closed", "reply_single_connect", "alert_unknown_ca", "alert_bad_certificate",
		"alert_certificate_expired", "alert_handshake_failure", "handshake_timeout")
	reactThen  = set("next_step", "continue_password", "stop", "retry", "failover_local", "failover_next_server",
		"give_up", "reuse_connection", "new_connection")
	outcomes   = set("", "login_ok", "login_refused", "falls_to_local", "break_glass_fails", "command_permitted",
		"command_denied", "accounted")
	ruleKinds  = set("max_attribute_bytes", "max_reply_bytes", "priv_lvl_range", "attribute_refused", "role_names")
	forbidden  = []string{"credential_sha256", "token_sha256", "cert_sha256", "password", "secret", "token=", "BEGIN "}
)

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func Load(path, repoRoot string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, f := range forbidden {
		if strings.Contains(string(raw), f) {
			return nil, fmt.Errorf("%s: holds %q; a profile never carries a credential or key", path, f)
		}
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var p Profile
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := p.Validate(repoRoot); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &p, nil
}

func (p *Profile) Validate(repoRoot string) error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d; this engine reads 1", p.SchemaVersion)
	}
	var errs []error
	note := func(where string, s Source) {
		if s.Note == "" || s.Register == "" {
			errs = append(errs, fmt.Errorf("%s: a source needs note and register", where))
			return
		}
		body, err := os.ReadFile(filepath.Join(repoRoot, s.Note))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %v", where, s.Note, err))
			return
		}
		// A note names its image version; the profile's firmware must be in it.
		if !strings.Contains(string(body), p.Firmware) {
			errs = append(errs, fmt.Errorf("%s: %s does not name firmware %q", where, s.Note, p.Firmware))
		}
	}
	for _, s := range p.Stimulus.Sources {
		note("stimulus", s)
	}
	if len(p.Stimulus.Sources) == 0 {
		errs = append(errs, errors.New("stimulus: no source"))
	}
	if p.Stimulus.TLS != nil {
		for _, s := range p.Stimulus.TLS.Sources {
			note("stimulus.tls", s)
		}
	}
	for i, s := range p.Stimulus.Steps {
		if !stepTypes[s.Type] || !stepNames[s.Name] {
			errs = append(errs, fmt.Errorf("steps[%d]: type %q name %q", i, s.Type, s.Name))
		}
	}
	for _, sc := range p.Scenarios {
		if !scenarios[sc] {
			errs = append(errs, fmt.Errorf("scenario %q is not in the conformance set", sc))
		}
	}
	for i, r := range p.Reactions {
		if !reactOn[r.On] || !reactThen[r.Then] || !outcomes[r.Outcome] {
			errs = append(errs, fmt.Errorf("reactions[%d]: on %q then %q outcome %q", i, r.On, r.Then, r.Outcome))
		}
		errs = append(errs, statusErr(fmt.Sprintf("reactions[%d]", i), r.Status, r.Sources)...)
		for _, s := range r.Sources {
			note(fmt.Sprintf("reactions[%d]", i), s)
		}
	}
	for _, a := range p.Acceptance {
		if !ruleKinds[a.Kind] {
			errs = append(errs, fmt.Errorf("acceptance %s: kind %q", a.ID, a.Kind))
		}
		errs = append(errs, statusErr("acceptance "+a.ID, a.Status, a.Sources)...)
		for _, s := range a.Sources {
			note("acceptance "+a.ID, s)
		}
	}
	return errors.Join(errs...)
}

// statusErr: a measured claim cites a note; an unmeasured one may cite the
// note that left it open, and never gates (decision 52 ruling 4).
func statusErr(where, status string, src []Source) []error {
	switch {
	case status == "measured" && len(src) == 0:
		return []error{fmt.Errorf("%s: measured with no source", where)}
	case status != "measured" && status != "unmeasured":
		return []error{fmt.Errorf("%s: status %q is neither measured nor unmeasured", where, status)}
	}
	return nil
}
```

Imports: `bytes`, `errors`, `fmt`, `os`, `path/filepath`, `strings`, `time`, `gopkg.in/yaml.v3`.

- [ ] **Step 5: Run the tests**

Run: `go test ./internal/devicemock/ -count=1 && GOOS=darwin go vet ./internal/devicemock/`
Expected: PASS, and the vet is clean.

- [ ] **Step 6: Commit**

```bash
git add internal/devicemock
git commit -m "feat(devicemock): the profile, loaded strictly and checked against its notes

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 7: The acceptance checker and the reaction table

**Files:**
- Create: `internal/devicemock/accept.go`, `internal/devicemock/react.go`, `internal/devicemock/accept_test.go`, `internal/devicemock/react_test.go`

**Interfaces:**
- Consumes: `Profile`, `AcceptanceRule`, `Reaction` (Task 6).
- Produces:

```go
type Violation struct {
	Rule, Step, Effect string
	Detail             string // lengths and attribute names only, never a value
	Measured           bool
}
func Check(rules []AcceptanceRule, step string, args [][]byte) (gate, warn []Violation)
func (p *Profile) React(step, on string) (Reaction, error)
```

- [ ] **Step 1: Write the failing tests**

```go
package devicemock

import (
	"strings"
	"testing"
)

func longArgs() [][]byte {
	return [][]byte{[]byte("local-user-name=p49-ro"), []byte("allow-commands=" + strings.Repeat("a", 140)),
		[]byte("deny-commands=" + strings.Repeat("d", 140))}
}

func TestAMeasuredRuleGatesAReplyOverItsLimit(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_junos.yaml", root)
	gate, warn := Check(p.Acceptance, "authorize_session", longArgs())
	if len(gate) != 1 || gate[0].Rule != "junos_reply_total" || gate[0].Effect != "lockout" || len(warn) != 0 {
		t.Fatalf("gate %+v warn %+v", gate, warn)
	}
	if strings.Contains(gate[0].Detail, "aaaa") {
		t.Fatal("a violation names lengths, never an attribute's value")
	}
}

func TestTheSameReplyPassesAProfileWithoutTheRule(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	if gate, warn := Check(p.Acceptance, "authorize_session", longArgs()); len(gate)+len(warn) != 0 {
		t.Fatalf("no rule, no violation: %+v %+v", gate, warn)
	}
}

func TestAnUnmeasuredRuleWarnsAndNeverGates(t *testing.T) {
	r := AcceptanceRule{ID: "junos_reply_total", Kind: "max_reply_bytes", Applies: "authorize_session", Max: 255,
		Effect: "lockout", Status: "unmeasured"}
	gate, warn := Check([]AcceptanceRule{r}, "authorize_session", longArgs())
	if len(gate) != 0 || len(warn) != 1 || warn[0].Measured {
		t.Fatalf("gate %+v warn %+v", gate, warn)
	}
}

func TestEachRuleKind(t *testing.T) {
	for _, c := range []struct {
		r    AcceptanceRule
		args []string
		hit  bool
	}{
		{AcceptanceRule{Kind: "max_attribute_bytes", Max: 10}, []string{"priv-lvl=15"}, true},
		{AcceptanceRule{Kind: "max_attribute_bytes", Max: 11}, []string{"priv-lvl=15"}, false},
		{AcceptanceRule{Kind: "priv_lvl_range", Min: 0, Max: 15}, []string{"priv-lvl=16"}, true},
		{AcceptanceRule{Kind: "priv_lvl_range", Min: 0, Max: 15}, []string{"priv-lvl=15"}, false},
		{AcceptanceRule{Kind: "attribute_refused", Names: []string{"shell:roles"}}, []string{"shell:roles*x"}, true},
		{AcceptanceRule{Kind: "role_names", Names: []string{"network-admin"}}, []string{"shell:roles*network-operator"}, true},
		{AcceptanceRule{Kind: "role_names", Names: []string{"network-admin"}}, []string{"shell:roles*network-admin"}, false},
	} {
		c.r.ID, c.r.Applies, c.r.Status = "r", "any", "measured"
		var args [][]byte
		for _, a := range c.args {
			args = append(args, []byte(a))
		}
		gate, _ := Check([]AcceptanceRule{c.r}, "authorize_session", args)
		if (len(gate) == 1) != c.hit {
			t.Errorf("%s %v: hit %v, want %v", c.r.Kind, c.args, len(gate) == 1, c.hit)
		}
	}
}

func TestReactFindsTheStepThenTheWildcardAndRefusesTheUnknown(t *testing.T) {
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	if r, err := p.React("login", "authen_error"); err != nil || r.Outcome != "falls_to_local" {
		t.Fatalf("%+v %v", r, err)
	}
	if r, err := p.React("authorize_session", "author_pass_add"); err != nil || r.Then != "next_step" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := p.React("login", "authen_getpass"); err == nil || !strings.Contains(err.Error(), "no reaction") {
		t.Fatal("an event the profile does not cover is an error the vetter fixes, never a default")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/devicemock/ -run 'Rule|Reply|React|Kind' -count=1`
Expected: FAIL (`undefined: Check`).

- [ ] **Step 3: Implement `accept.go`**

```go
package devicemock

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
)

type Violation struct {
	Rule, Step, Effect string
	Detail             string
	Measured           bool
}

// Check applies the profile's acceptance rules to one reply's arguments. A
// measured rule's violation gates; an unmeasured one is a warning that never
// fails the suite (decision 52 ruling 4).
func Check(rules []AcceptanceRule, step string, args [][]byte) (gate, warn []Violation) {
	for _, r := range rules {
		if r.Applies != "any" && r.Applies != step {
			continue
		}
		d := violates(r, args)
		if d == "" {
			continue
		}
		v := Violation{Rule: r.ID, Step: step, Effect: r.Effect, Detail: d, Measured: r.Status == "measured"}
		if v.Measured {
			gate = append(gate, v)
		} else {
			warn = append(warn, v)
		}
	}
	return gate, warn
}

func name(a []byte) string {
	if i := bytes.IndexAny(a, "=*"); i >= 0 {
		return string(a[:i])
	}
	return string(a)
}

func value(a []byte) string {
	if i := bytes.IndexAny(a, "=*"); i >= 0 {
		return string(a[i+1:])
	}
	return ""
}

func violates(r AcceptanceRule, args [][]byte) string {
	switch r.Kind {
	case "max_attribute_bytes":
		for _, a := range args {
			if len(a) > r.Max {
				return fmt.Sprintf("%s is %d bytes, over %d", name(a), len(a), r.Max)
			}
		}
	case "max_reply_bytes":
		total := 0
		for _, a := range args {
			total += len(a)
		}
		if total > r.Max {
			return fmt.Sprintf("the reply's %d attributes total %d bytes, over %d", len(args), total, r.Max)
		}
	case "priv_lvl_range":
		for _, a := range args {
			if name(a) == "priv-lvl" {
				n, err := strconv.Atoi(value(a))
				if err != nil || n < r.Min || n > r.Max {
					return fmt.Sprintf("priv-lvl outside %d..%d", r.Min, r.Max)
				}
			}
		}
	case "attribute_refused":
		for _, a := range args {
			if slices.Contains(r.Names, name(a)) {
				return fmt.Sprintf("%s is an attribute this device refuses", name(a))
			}
		}
	case "role_names":
		for _, a := range args {
			if name(a) == "shell:roles" || name(a) == "roles" {
				for _, role := range bytes.Fields([]byte(value(a))) {
					if !slices.Contains(r.Names, string(role)) {
						return fmt.Sprintf("%s names a role this device does not honour", name(a))
					}
				}
			}
		}
	}
	return ""
}
```

The `role_names` detail names the attribute and never the role. A role name is not a secret, but a violation's detail is kept to names and lengths throughout.

- [ ] **Step 4: Implement `react.go`**

```go
package devicemock

import "fmt"

// React is the profile's next action for an event at a step: the step's own
// entry first, then "*". An event with no entry is an error: the vetter adds
// it from the lab, and the engine never guesses (decision 52 ruling 1).
func (p *Profile) React(step, on string) (Reaction, error) {
	for _, want := range []string{step, "*"} {
		for _, r := range p.Reactions {
			if r.Step == want && r.On == on {
				return r, nil
			}
		}
	}
	return Reaction{}, fmt.Errorf("%s %s: no reaction for %s at %s; add it from the lab notes", p.Platform, p.Firmware, on, step)
}
```

- [ ] **Step 5: Run**

Run: `go test ./internal/devicemock/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/devicemock
git commit -m "feat(devicemock): acceptance rules gate when measured, and the reaction table

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 8: TLS — the hello probe, the session config and the flight delay

**Files:**
- Create: `internal/devicemock/hello.go`, `internal/devicemock/tlsconf.go`, `internal/devicemock/hello_test.go`, `internal/devicemock/tlsconf_test.go`

**Interfaces:**
- Consumes: `Hello`, `ServerHello`, `TLSStimulus` (Task 6).
- Produces:

```go
func BuildClientHello(h Hello, serverIP string) ([]byte, error) // one TLS record; fresh random, session id, key share
func Probe(ctx context.Context, d *net.Dialer, addr string, h Hello, serverIP string) (ServerHello, error)
type TLSMaterial struct {
	Client    tls.Certificate // generated per test
	ServerCAs *x509.CertPool
	ServerIP  string
}
func SessionConfig(s *TLSStimulus, m TLSMaterial) *tls.Config
func DelayFlight(c net.Conn, d time.Duration, sleep func(time.Duration)) net.Conn
var ErrNoBuilder = errors.New("devicemock: no builder for this extension")
```

- [ ] **Step 1: Write the failing tests**

```go
package devicemock

import (
	"bytes"
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func nxosHello() Hello {
	return Hello{LegacyVersion: 771, SupportedVersions: []uint16{772}, CipherSuites: []uint16{4866, 4867, 4865, 255},
		SupportedGroups: []uint16{29, 23, 30, 25, 24},
		SignatureAlgorithms: []uint16{1027, 1283, 1539, 2055, 2056, 2057, 2058, 2059, 2052, 2053, 2054, 1025, 1281, 1537},
		PSKModes: []uint8{1}, Extensions: []uint16{11, 10, 35, 22, 23, 13, 43, 45, 51}}
}

func TestBuildClientHelloKeepsTheDevicesOrderAndIsFreshEachTime(t *testing.T) {
	a, err := BuildClientHello(nxosHello(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := BuildClientHello(nxosHello(), "127.0.0.1")
	if bytes.Equal(a, b) {
		t.Fatal("two hellos are byte-identical: the random and the key share must be fresh")
	}
	got, err := parseClientHelloForTest(a)
	if err != nil {
		t.Fatal(err)
	}
	if !equalU16(got.CipherSuites, nxosHello().CipherSuites) || !equalU16(got.Extensions, nxosHello().Extensions) || got.SNI != "" {
		t.Fatalf("%+v", got)
	}
}

func TestBuildClientHelloSendsALiteralAddressAsSNIWhenTheDeviceDoes(t *testing.T) {
	h := nxosHello()
	h.SNI, h.Extensions = "{server_ip}", append([]uint16{0}, h.Extensions...)
	raw, _ := BuildClientHello(h, "172.100.100.1")
	if got, _ := parseClientHelloForTest(raw); got.SNI != "172.100.100.1" {
		t.Fatalf("Junos sends the literal address (L73 cell c): %q", got.SNI)
	}
}

func TestBuildClientHelloRefusesAnExtensionItCannotBuild(t *testing.T) {
	h := nxosHello()
	h.Extensions = append(h.Extensions, 41) // pre_shared_key: no device in the lab offered one
	if _, err := BuildClientHello(h, ""); err == nil {
		t.Fatal("an extension with no builder is an engine gap, named, never skipped")
	}
}

func TestProbeReadsAGoServersChoice(t *testing.T) {
	cert := selfSigned(t)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.(*tls.Conn).Handshake()
			c.Close()
		}
	}()
	sh, err := Probe(t.Context(), &net.Dialer{}, ln.Addr().String(), nxosHello(), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if sh.SelectedVersion != 772 || sh.CipherSuite != 4865 || sh.HelloRetryRequest {
		t.Fatalf("%+v: crypto/tls answers 1.3 with AES-128-GCM to the N9Kv's offer", sh)
	}
}

func TestDelayFlightDelaysOnlyTheFirstWriteAfterARead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	var slept atomic.Int64
	c := DelayFlight(a, 500*time.Millisecond, func(d time.Duration) { slept.Add(int64(d)) })
	go func() { buf := make([]byte, 8); for { if _, err := b.Read(buf); err != nil { return } } }()
	c.Write([]byte("hello")) // the ClientHello: no delay
	go b.Write([]byte("x"))
	c.Read(make([]byte, 1)) // the server's flight
	c.Write([]byte("fin"))  // the device's flight: delayed
	c.Write([]byte("data")) // later writes: no delay
	if got := time.Duration(slept.Load()); got != 500*time.Millisecond {
		t.Fatalf("slept %v in all, want one 500ms", got)
	}
}
```

Add `parseClientHelloForTest`, `equalU16` and `selfSigned` to `hello_test.go`. `parseClientHelloForTest` reads the record and handshake headers, the version, a 32-byte random, the session id, the suites, compression, then each extension's type, collecting `Extensions`, `CipherSuites` and the server_name's host. `selfSigned` uses `testpki.NewCA` and `Issue` with `testpki.Loopback()`. Write them out in full: they are the test's own reader, not the engine's.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./internal/devicemock/ -run 'Hello|Probe|Delay' -count=1`
Expected: FAIL (`undefined: BuildClientHello`).

- [ ] **Step 3: Implement `hello.go`**

```go
package devicemock

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

var ErrNoBuilder = errors.New("devicemock: no builder for this extension")

// hrrRandom is RFC 8446 §4.1.3's HelloRetryRequest random.
var hrrRandom = sha256.Sum256([]byte("HelloRetryRequest"))

func u16(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }

func vec16(b, body []byte) []byte { return append(u16(b, uint16(len(body))), body...) }

func vec8(b, body []byte) []byte { return append(append(b, byte(len(body))), body...) }

func curve(g uint16) ecdh.Curve {
	switch g {
	case 29:
		return ecdh.X25519()
	case 23:
		return ecdh.P256()
	case 24:
		return ecdh.P384()
	case 25:
		return ecdh.P521()
	}
	return nil
}

// BuildClientHello writes h as one handshake record, extensions in h's order,
// with a fresh random, session id and key share (for the first offered group
// the standard library can generate): the device's offer, never its bytes.
func BuildClientHello(h Hello, serverIP string) ([]byte, error) {
	var exts []byte
	for _, id := range h.Extensions {
		var body []byte
		switch id {
		case 0:
			name := strings.ReplaceAll(h.SNI, "{server_ip}", serverIP)
			if name == "" {
				return nil, errors.New("devicemock: extension 0 listed with no sni")
			}
			entry := vec16([]byte{0}, []byte(name))
			body = vec16(nil, entry)
		case 10:
			var g []byte
			for _, x := range h.SupportedGroups {
				g = u16(g, x)
			}
			body = vec16(nil, g)
		case 11:
			body = []byte{1, 0}
		case 13, 50:
			var s []byte
			for _, x := range h.SignatureAlgorithms {
				s = u16(s, x)
			}
			body = vec16(nil, s)
		case 16:
			var l []byte
			for _, p := range h.ALPN {
				l = vec8(l, []byte(p))
			}
			body = vec16(nil, l)
		case 22, 23, 35, 49:
			body = nil
		case 43:
			var v []byte
			for _, x := range h.SupportedVersions {
				v = u16(v, x)
			}
			body = vec8(nil, v)
		case 45:
			body = vec8(nil, h.PSKModes)
		case 51:
			var share []byte
			for _, g := range h.SupportedGroups {
				if c := curve(g); c != nil {
					k, err := c.GenerateKey(rand.Reader)
					if err != nil {
						return nil, err
					}
					share = vec16(u16(nil, g), k.PublicKey().Bytes())
					break
				}
			}
			if share == nil {
				return nil, fmt.Errorf("%w: key_share for groups %v", ErrNoBuilder, h.SupportedGroups)
			}
			body = vec16(nil, share)
		case 65281:
			body = []byte{0}
		default:
			return nil, fmt.Errorf("%w: %d", ErrNoBuilder, id)
		}
		exts = vec16(u16(exts, id), body)
	}
	random, sid := make([]byte, 32), make([]byte, 32)
	rand.Read(random)
	rand.Read(sid)
	var suites []byte
	for _, s := range h.CipherSuites {
		suites = u16(suites, s)
	}
	ch := u16(nil, h.LegacyVersion)
	ch = append(ch, random...)
	ch = vec8(ch, sid)
	ch = vec16(ch, suites)
	ch = append(ch, 1, 0) // compression: null only
	ch = vec16(ch, exts)
	hs := append([]byte{1, byte(len(ch) >> 16), byte(len(ch) >> 8), byte(len(ch))}, ch...)
	return vec16([]byte{22, 3, 1}, hs), nil
}

// Probe sends the device's ClientHello and reads port49's ServerHello, then
// closes: port49 counts the abandoned handshake against the source, so a
// probe runs on a daemon of its own (decision 52; spec §13 decision 50).
func Probe(ctx context.Context, d *net.Dialer, addr string, h Hello, serverIP string) (ServerHello, error) {
	hello, err := BuildClientHello(h, serverIP)
	if err != nil {
		return ServerHello{}, err
	}
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ServerHello{}, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write(hello); err != nil {
		return ServerHello{}, err
	}
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return ServerHello{}, fmt.Errorf("devicemock: no ServerHello: %w", err)
	}
	if hdr[0] == 21 {
		return ServerHello{}, fmt.Errorf("devicemock: port49 answered the hello with an alert")
	}
	body := make([]byte, binary.BigEndian.Uint16(hdr[3:]))
	if _, err := io.ReadFull(c, body); err != nil {
		return ServerHello{}, err
	}
	return readServerHello(body)
}

func readServerHello(b []byte) (ServerHello, error) {
	if len(b) < 4+2+32+1 || b[0] != 2 {
		return ServerHello{}, errors.New("devicemock: not a ServerHello")
	}
	p := b[4:]
	var sh ServerHello
	sh.SelectedVersion = binary.BigEndian.Uint16(p)
	sh.HelloRetryRequest = [32]byte(p[2:34]) == hrrRandom
	p = p[34:]
	p = p[1+int(p[0]):] // session id
	if len(p) < 5 {
		return ServerHello{}, errors.New("devicemock: short ServerHello")
	}
	sh.CipherSuite = binary.BigEndian.Uint16(p)
	p = p[3:] // suite and compression
	n := int(binary.BigEndian.Uint16(p))
	p = p[2:]
	if n > len(p) {
		return ServerHello{}, errors.New("devicemock: ServerHello extensions run past the record")
	}
	for p = p[:n]; len(p) >= 4; {
		id, l := binary.BigEndian.Uint16(p), int(binary.BigEndian.Uint16(p[2:]))
		if 4+l > len(p) {
			break
		}
		if id == 43 && l == 2 {
			sh.SelectedVersion = binary.BigEndian.Uint16(p[4:])
		}
		p = p[4+l:]
	}
	return sh, nil
}
```

- [ ] **Step 4: Implement `tlsconf.go`**

```go
package devicemock

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"sync"
	"time"
)

type TLSMaterial struct {
	Client    tls.Certificate
	ServerCAs *x509.CertPool
	ServerIP  string
}

var goCurves = map[uint16]tls.CurveID{29: tls.X25519, 23: tls.CurveP256, 24: tls.CurveP384, 25: tls.CurveP521}

// SessionConfig is the closest crypto/tls comes to the device: its versions,
// curve order (groups the library lacks, x448, are left out), ALPN and client
// chain. Suite order and signature algorithms are the library's; the hello
// probe carries the device's exactly. The server's certificate is checked as
// the device was measured to (server_identity); a literal-address SNI is
// never sent here (crypto/tls omits it), only by the probe: an engine gap
// each profile that has one lists.
func SessionConfig(s *TLSStimulus, m TLSMaterial) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{m.Client}, NextProtos: s.ClientHello.ALPN}
	if len(s.ClientHello.SupportedVersions) == 1 && s.ClientHello.SupportedVersions[0] == 772 {
		cfg.MinVersion = tls.VersionTLS13
	}
	for _, g := range s.ClientHello.SupportedGroups {
		if c, ok := goCurves[g]; ok {
			cfg.CurvePreferences = append(cfg.CurvePreferences, c)
		}
	}
	cfg.InsecureSkipVerify = true // replaced by the check below: chain always, names as measured
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("devicemock: no server certificate")
		}
		opts := x509.VerifyOptions{Roots: m.ServerCAs, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		switch s.ServerIdentity {
		case "ip", "dns":
			opts.DNSName = m.ServerIP
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
	return cfg
}

type flightConn struct {
	net.Conn
	delay        time.Duration
	sleep        func(time.Duration)
	mu           sync.Mutex
	read, waited bool
}

// DelayFlight delays the first write after the first read by d: in TLS 1.3
// the client's second flight, after port49's server flight. The rest pass.
func DelayFlight(c net.Conn, d time.Duration, sleep func(time.Duration)) net.Conn {
	if sleep == nil {
		sleep = time.Sleep
	}
	return &flightConn{Conn: c, delay: d, sleep: sleep}
}

func (c *flightConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.mu.Lock()
		c.read = true
		c.mu.Unlock()
	}
	return n, err
}

func (c *flightConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	wait := c.read && !c.waited
	if wait {
		c.waited = true
	}
	c.mu.Unlock()
	if wait {
		c.sleep(c.delay)
	}
	return c.Conn.Write(b)
}
```

- [ ] **Step 5: Run**

Run: `go test ./internal/devicemock/ -count=1 && GOOS=darwin go vet ./internal/devicemock/`
Expected: PASS, and the vet is clean.

- [ ] **Step 6: Commit**

```bash
git add internal/devicemock
git commit -m "feat(devicemock): the device's exact ClientHello as a probe, and its flight delay

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 9: The engine — `Play`, connection patterns, the transcript

**Files:**
- Create: `internal/devicemock/engine.go`, `internal/devicemock/engine_test.go`, `internal/devicemock/fakeserver_test.go`

**Interfaces:**
- Consumes: Tasks 6–8.
- Produces:

```go
type Target struct {
	Addr      string       // the listener
	Transport string       // tcp, tls
	Key       []byte       // tcp: the shared key, fresh per test
	TLS       *TLSMaterial // tls
	LocalAddr string       // the source address; "" for the default (fleet mode sets 127.0.1.N)
	Scale     float64      // delay scale: 1 real, 0.1 per PR
	Sleep     func(time.Duration)
}
type Login struct {
	User       string
	Credential []byte // minted per test; never copied into a Transcript
	RemAddr    string
}
type StepResult struct {
	Step, Event   string
	Args          []string // authorization reply arguments (no secret: priv-lvl, roles, classes)
	ServerMsgLen  int      // a length, never the text
	SingleConnect bool
	Conn          int // which connection carried it, from 1
}
type Transcript struct {
	Scenario string
	Steps    []StepResult
	Outcome  string
	Gate     []Violation
	Warn     []Violation
	Conns    int
}
func Play(ctx context.Context, p *Profile, scenario string, t Target, l Login) (Transcript, error)
func (tr Transcript) String() string
```

Scenarios and the steps they play:
- `token_login`: every step, in order.
- `wrong_credential`: `login` with a credential the engine makes from random bytes, which is never a token.
- `store_unavailable`: `login` (the harness has set the fault).
- `single_connection`: every step with the profile's single-connect pattern forced on.
- `unknown_ca` and `flight_delay`: TLS only, the handshake alone.

- [ ] **Step 1: Write the fake server** (`fakeserver_test.go`). It is a TACACS+ server that answers each request type with a configured status and arguments, echoes the request's `data` into `server_msg` when `echo` is set (Review Focus 1), counts connections, and honours the single-connect flag. Write it in full with `wire.DecodeHeader`, `wire.Obfuscate`, `wire.DecodeAuthenStart`, `wire.DecodeAuthenContinue`, `wire.AuthenReply.Encode`, `wire.AuthorResponse.Encode` and `wire.AcctReply.Encode`. Its type:

```go
type fake struct {
	ln                       net.Listener
	key                      []byte
	authen                   []uint8 // statuses in turn: e.g. {GetPass, Pass} for ASCII
	authorArgs               [][]byte
	echo, singleConnect      bool
	conns                    atomic.Int32
}
func newFake(t *testing.T, key []byte) *fake
```

- [ ] **Step 2: Write the failing engine tests**

```go
func TestTokenLoginPlaysEveryStepOneConnectionEach(t *testing.T) {
	key := []byte("fresh-key")
	f := newFake(t, key)
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	tr, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t), RemAddr: "198.51.100.4"})
	if err != nil {
		t.Fatal(err)
	}
	if tr.Outcome != "login_ok" || len(tr.Steps) != 3 || tr.Conns != 3 || f.conns.Load() != 3 {
		t.Fatalf("%s", tr)
	}
}

func TestAGatedViolationFailsThePlay(t *testing.T) {
	key := []byte("fresh-key")
	f := newFake(t, key)
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = longArgs()
	p, _ := Load("testdata/profiles/fixture_junos.yaml", root)
	tr, _ := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t)})
	if len(tr.Gate) != 1 || tr.Outcome != "rejected_by_device" {
		t.Fatalf("the device would lock the user out; the play says so: %s", tr)
	}
}

func TestTranscriptNeverHoldsTheCredential(t *testing.T) {
	key := []byte("fresh-key")
	f := newFake(t, key)
	f.authen, f.echo = []uint8{wire.AuthenStatusFail}, true // a server that echoes data into server_msg
	cred := freshCredential(t)
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	tr, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: key, Scale: 1},
		Login{User: "q", Credential: cred})
	all := tr.String() + fmt.Sprint(err) + fmt.Sprintf("%+v %#v", tr, tr)
	if strings.Contains(all, string(cred)) {
		t.Fatal("the credential reached the transcript or its error")
	}
	if tr.Steps[0].ServerMsgLen == 0 {
		t.Fatal("the echoed server_msg is measured by its length")
	}
}

func TestAnEventWithNoReactionIsAnError(t *testing.T) {
	key := []byte("fresh-key")
	f := newFake(t, key)
	f.authen = []uint8{wire.AuthenStatusGetPass} // the fixture covers no GETPASS
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	_, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t)})
	if err == nil || !strings.Contains(err.Error(), "no reaction for authen_getpass") {
		t.Fatalf("%v", err)
	}
}

func TestSingleConnectionReusesOnlyWhenTheServerAgrees(t *testing.T) {
	for _, agree := range []bool{true, false} {
		key := []byte("fresh-key")
		f := newFake(t, key)
		f.authen, f.singleConnect = []uint8{wire.AuthenStatusPass}, agree
		f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
		p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
		p.Reactions = append(p.Reactions, Reaction{Step: "*", On: "reply_single_connect", Then: "reuse_connection", Status: "unmeasured"})
		tr, err := Play(t.Context(), p, "single_connection", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: key, Scale: 1},
			Login{User: "q", Credential: freshCredential(t)})
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 1, false: 3}[agree]; tr.Conns != want {
			t.Fatalf("server agrees %v: %d connections, want %d", agree, tr.Conns, want)
		}
	}
}

func freshCredential(t *testing.T) []byte {
	b := make([]byte, 24)
	rand.Read(b)
	return []byte(hex.EncodeToString(b))
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/devicemock/ -run 'TokenLogin|Gated|Transcript|NoReaction|SingleConnection' -count=1`
Expected: FAIL (`undefined: Play`).

- [ ] **Step 4: Implement `engine.go`**

```go
package devicemock

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// … Target, Login, StepResult, Transcript as in Interfaces …

var codes = map[string]map[string]uint8{
	"action":        {"login": wire.AuthenActionLogin, "chpass": wire.AuthenActionChPass, "sendauth": wire.AuthenActionSendAuth},
	"authen_type":   {"not_set": 0, "ascii": wire.AuthenTypeASCII, "pap": wire.AuthenTypePAP, "chap": wire.AuthenTypeCHAP},
	"service":       {"none": wire.AuthenServiceNone, "login": wire.AuthenServiceLogin, "enable": wire.AuthenServiceEnable, "ppp": wire.AuthenServicePPP},
	"authen_method": {"not_set": wire.AuthenMethodNotSet, "none": wire.AuthenMethodNone, "line": wire.AuthenMethodLine, "enable": wire.AuthenMethodEnable, "local": wire.AuthenMethodLocal, "tacacsplus": wire.AuthenMethodTACACSPlus},
}

func code(kind, name string) (uint8, error) {
	if v, ok := codes[kind][name]; ok {
		return v, nil
	}
	return 0, fmt.Errorf("devicemock: %s %q has no wire value here", kind, name)
}

type conn struct {
	c      net.Conn
	n      int
	single bool // the server agreed to single-connection
}

type player struct {
	p      *Profile
	t      Target
	l      Login
	sc     string
	tr     Transcript
	cur    *conn
	reuse  bool
	nconns int
	now    time.Time
}

func Play(ctx context.Context, p *Profile, scenario string, t Target, l Login) (Transcript, error) {
	pl := &player{p: p, t: t, l: l, sc: scenario, now: time.Now()}
	pl.tr.Scenario = scenario
	defer pl.closeConn()
	steps := p.Stimulus.Steps
	switch scenario {
	case "wrong_credential":
		bogus := make([]byte, 24)
		rand.Read(bogus)
		pl.l.Credential = []byte(hex.EncodeToString(bogus))
		steps = steps[:1]
	case "store_unavailable":
		steps = steps[:1]
	case "unknown_ca", "flight_delay":
		_, err := pl.dial(ctx)
		pl.tr.Conns = pl.nconns
		if err != nil {
			pl.tr.Outcome = "handshake_refused"
			pl.tr.Steps = append(pl.tr.Steps, StepResult{Step: "handshake", Event: handshakeEvent(err)})
			return pl.tr, nil
		}
		pl.tr.Outcome = "handshake_ok"
		return pl.tr, nil
	}
	for _, s := range steps {
		res, err := pl.step(ctx, s)
		if err != nil {
			return pl.tr, err
		}
		pl.tr.Steps = append(pl.tr.Steps, res)
		r, err := p.React(s.Name, res.Event)
		if err != nil {
			return pl.tr, err
		}
		if res.SingleConnect {
			if rr, err := p.React(s.Name, "reply_single_connect"); err == nil && rr.Then == "reuse_connection" {
				pl.reuse = true
			}
		}
		if len(pl.tr.Gate) > 0 {
			pl.tr.Outcome = "rejected_by_device"
			return pl.tr, nil
		}
		switch r.Then {
		case "next_step", "reuse_connection", "new_connection":
			continue
		case "continue_password":
			return pl.tr, fmt.Errorf("devicemock: continue_password is handled inside the login step")
		default:
			pl.tr.Outcome = r.Outcome
			pl.tr.Conns = pl.nconns
			return pl.tr, nil
		}
	}
	pl.tr.Outcome = "login_ok"
	pl.tr.Conns = pl.nconns
	return pl.tr, nil
}
```

The rest of `engine.go`:

- **`dial(ctx)`**: a `net.Dialer` with `LocalAddr` set from `t.LocalAddr` when it is not empty. Over `tls`: wrap the connection in `DelayFlight(c, scaled(p.Stimulus.TLS.FlightDelay), t.Sleep)`, then `tls.Client(c, SessionConfig(...))` and `HandshakeContext`. It increments `nconns`.
- **`scaled(d)`**: `time.Duration(float64(d) * t.Scale)`.
- **`step(ctx, s)`**: picks the connection. With `pl.reuse` and an open conn it reuses; otherwise it closes and dials. A `single_connection` scenario, or `Connections.SingleConnectFlag`, sets `wire.FlagSingleConnect` on the first header. Then it builds the body:
  - authen: an `AuthenStart` with `Data` = the credential when `authen_type` is pap; empty for ascii, where an `authen_getpass` reply whose reaction is `continue_password` sends `AuthenContinue{UserMsg: credential}` at seq+2;
  - author: an `AuthorRequest` with `Args` = `expand(s.Args)`;
  - acct: an `AcctRequest` with `Flags` from `s.Flags`.

  The header is `{MajorVersion: 0xc, MinorVersion: 1 for pap/chap else 0, Type, SeqNo, Flags, SessionID: random, Length}`. Over tcp the body is obfuscated with `t.Key`; over tls the flags carry `wire.FlagUnencrypted` and the body is clear. It reads the reply, decodes it, and sets:
  - `Event`: `authen_pass`/`authen_fail`/…, `author_pass_add`/…, `acct_success`/`acct_error`, or `conn_reset`/`conn_closed` on a read error;
  - `Args` for an author reply;
  - `ServerMsgLen = len(server_msg)`;
  - `SingleConnect` from the reply header's flag.

  For a `authorize_session` or `command_permitted` reply it calls `Check(p.Acceptance, s.Name, reply.Args)` and appends to `tr.Gate` and `tr.Warn`.
- **`expand(args)`**: replaces `{user}`, `{rem_addr}`, `{task_id}` (`fmt.Sprintf("%d", pl.now.UnixNano()%100000)`), `{start_time}` and `{stop_time}` (`pl.now.Unix()`). It never puts the credential into an argument.
- **`handshakeEvent(err)`**: maps a `tls.AlertError` to `alert_unknown_ca` (48), `alert_bad_certificate` (42), `alert_certificate_expired` (45) or `alert_handshake_failure` (40); a reset to `conn_reset`; EOF to `conn_closed`.
- **`Transcript.String()`**: one line per step, `step event args=[…] server_msg=<n> bytes conn=<k>`, then the outcome, gates and warnings by rule id and detail. It is the only form tests print.

Neither the transcript nor any error is built from a request body. Errors name the step and the event only.

- [ ] **Step 5: Run**

Run: `go test ./internal/devicemock/ -count=1 -race && GOOS=darwin go vet ./internal/devicemock/`
Expected: PASS, and the vet is clean.

- [ ] **Step 6: Commit**

```bash
git add internal/devicemock
git commit -m "feat(devicemock): the engine plays a profile and reports what the device would do

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 10: `TestQual` — every profile against a real in-process port49d

**Files:**
- Create: `internal/port49d/qual_test.go`, `tests/qual/qual-policy.yaml`, `internal/devicemock/testdata/golden/fixture_plain.json`, `internal/devicemock/testdata/golden/fixture_junos.json`
- Test: `internal/port49d/qual_test.go`

**Interfaces:**
- Consumes: `devicemock.Load`, `Play`, `Probe`, `TLSMaterial`. From `internal/port49d`'s tests: `run(ctx, cfgPath)`, `stderr`/`stdout`, `syncBuffer`, `waitFor`, `brokerConfig`, `writeRunConfigWith`, `mint`, `devicePKI`-style issuance with `testpki`.
- Produces:
  - `func qualDaemon(t *testing.T, p *devicemock.Profile, o qualOpts) qualRun`, with `qualRun{tacacs string; tls *devicemock.TLSMaterial; key []byte; mint func() []byte; fault func(string)}`;
  - the golden format `{"pending_lab": bool, "scenarios": {"<name>": {"outcome": "...", "steps": [{"step","event","args"}]}}}`;
  - env `PORT49_QUAL_UPDATE=1` rewrites goldens and marks them `pending_lab`.

- [ ] **Step 1: The qualification policy.** `tests/qual/qual-policy.yaml`:

```yaml
# The qualification policy (plan 11b, decision 52 ruling 5): the one policy of every lab
# conformance run (TestQualify) and every mock (TestQual), so a golden from the lab is the
# mock's expectation. Changing it changes every golden: run `make qual-update`, review the
# diff, and the next release tag's lab run re-vets.
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: qual_admin, privilege: admin, permit: ["**"]}
  # show users is safe on every platform; never a command that changes a device here.
  - {name: qual_denies, deny: ["show users"]}
subjects:
  - {name: qual_operator, identity: ["user:alice@example.com", "user:alice@slice.port49.test"], username: qual01, token_ttl: 60s}
grants:
  - {subject: qual_operator, scope: all_devices, roles: [qual_admin, qual_denies], max_privilege: admin}
```

- [ ] **Step 2: Write the failing tests** in `internal/port49d/qual_test.go`:

```go
package port49d

// TestQual plays every profile in tests/qual/profiles against a real port49d
// under tests/qual/qual-policy.yaml (plan 11b; spec §13 decision 52). Per PR,
// at 0.1 time scale against handshake_timeout 1s: production's ratio.

func TestQual(t *testing.T) {
	paths, _ := filepath.Glob("../../tests/qual/profiles/*/*.yaml")
	if len(paths) == 0 {
		t.Skip("no profiles yet (Task 14 adds the first wave)")
	}
	for _, path := range paths {
		p, err := devicemock.Load(path, "../..")
		if err != nil {
			t.Fatal(err)
		}
		t.Run(p.Platform+"/"+p.Firmware, func(t *testing.T) { qualProfile(t, p, "../..") })
	}
}

func TestQualFixtureJunosRuleFailsWhatThePlainFixturePasses(t *testing.T) {
	// A Junos grant whose reply's attributes are each under 255 bytes and
	// together over it (port49 never sends one attribute over 255: spec §6, "Length").
	pol := qualPolicyWith(t, qualLongJunosRole)
	for _, c := range []struct {
		profile string
		gated   bool
	}{{"fixture_junos.yaml", true}, {"fixture_plain.yaml", false}} {
		p, err := devicemock.Load("../devicemock/testdata/profiles/"+c.profile, "../devicemock/testdata")
		if err != nil {
			t.Fatal(err)
		}
		run := qualDaemon(t, p, qualOpts{policy: pol, scale: 0.1})
		tr, err := devicemock.Play(t.Context(), p, "token_login", run.target(p), run.login())
		if err != nil {
			t.Fatalf("%s: %v\n%s", c.profile, err, tr)
		}
		total := 0
		for _, a := range tr.Steps[1].Args {
			total += len(a)
		}
		if total <= 255 {
			t.Fatalf("the fixture policy renders %d bytes; lengthen qualLongJunosRole until it passes 255", total)
		}
		if (len(tr.Gate) == 1) != c.gated {
			t.Fatalf("%s: gated %v, want %v\n%s", c.profile, len(tr.Gate) == 1, c.gated, tr)
		}
	}
}

func TestQualNXOSRealFlightUnderTheDefault(t *testing.T) {
	// The real numbers once: the N9Kv's 5.00 s flight (tests/lab/results/L73-cisco_nxos.md)
	// against the 10s default handshake_timeout. One connection, about 5 s.
	p := qualProfileOrSkip(t, "cisco_nxos", "10.6(2)F")
	run := qualDaemon(t, p, qualOpts{scale: 1, handshakeTimeout: 0}) // 0: the daemon's default
	tr, err := devicemock.Play(t.Context(), p, "flight_delay", run.target(p), run.login())
	if err != nil || tr.Outcome != "handshake_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
}

func TestQualAFlightPastTheTimeoutIsHandshakeTimeout(t *testing.T) {
	p := qualProfileOrSkip(t, "cisco_nxos", "10.6(2)F")
	run := qualDaemon(t, p, qualOpts{scale: 0.3, handshakeTimeout: time.Second}) // 1.5 s against 1 s
	tr, _ := devicemock.Play(t.Context(), p, "flight_delay", run.target(p), run.login())
	if tr.Outcome != "handshake_refused" || !run.logged(`"tls_outcome":"handshake_timeout"`) {
		t.Fatalf("a flight past handshake_timeout is refused as handshake_timeout\n%s", tr)
	}
}
```

Write `qualLongJunosRole` as a role with a `privilege: readonly`, ten narrow `permit` entries (`show interfaces terse`, `show route summary`, …) and ten `deny` entries (`show security **`, …). It is sized so juniper_junos's projection renders `allow-commands` and `deny-commands` each under 255 and together over 255. The precondition in the test fails loudly if it no longer does.

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/port49d/ -run '^TestQual' -count=1`
Expected: FAIL (`undefined: qualDaemon`).

- [ ] **Step 4: Implement the harness** in the same file.
  - **`qualDaemon`** points `stderr`/`stdout` at `syncBuffer`s and restores them in `t.Cleanup`. It calls `brokerConfig(t, policy)` (the qual policy unless `o.policy` is set). It writes an inventory with one device, `qdev`:
    - `platform: <p.Platform>`, `addresses: [127.0.0.1]`;
    - `transport: tls` when the profile's `transports` has `tls`, else a key group for 127.0.0.0/8 with a fresh 32-byte hex key in `T_RUN_SECRET`.

    For TLS it issues a device CA, a server certificate for 127.0.0.1 and a client certificate for `qdev` with `testpki`, all per test. It appends the `tls_listener:` block (as `devicePKI.block` writes it) with `handshake_timeout: <o.handshakeTimeout>` when that is not zero, plus `lab: {fault_file: <tmp>}`. It starts `run(ctx, cfg)` and waits for both listening lines.
  - **`run.mint()`** returns `mint(t, brokerAddr, pkiDir, "qdev")` as bytes.
  - **`run.fault(code)`** writes the fault file.
  - **`run.logged(s)`** searches the decision-log buffer.
  - **`run.target(p)`** and **`run.login()`** build `devicemock.Target` (`Scale: o.scale`) and `devicemock.Login{User: "qual01", Credential: run.mint(), RemAddr: "198.51.100.4"}`.
  - **`qualProfile(t, p, root)`** runs:
    - **every scenario in `p.Scenarios`** on a fresh daemon at scale 0.1 with `handshakeTimeout: time.Second`. Before `store_unavailable` it calls `run.fault("store_unavailable")`. Each play gets a fresh `run.login()`.
    - **the hello probe** for a TLS profile, on its own daemon: `devicemock.Probe(...)` must equal `p.Stimulus.TLS.ServerHello`.

    It compares each transcript with the golden `root/<p.Golden>`. With `PORT49_QUAL_UPDATE=1`, a differing golden is rewritten with `"pending_lab": true`. Otherwise a difference fails, naming the scenario and printing both transcripts' `String()`. Any `tr.Gate` fails, naming the rule. `tr.Warn` is logged as `unmeasured acceptance rule <id>: <detail>`.

The golden never holds a credential: it is built from `Transcript` fields only. Add an assertion that the golden bytes contain neither the minted credential nor `credential_sha256`.

- [ ] **Step 5: Write the fixture goldens** by running the fixture test once with `PORT49_QUAL_UPDATE=1`, then read them. They must hold statuses and reply args only.

- [ ] **Step 6: Run**

Run: `go test ./internal/port49d/ -run '^TestQual' -count=1 -v 2>&1 | grep -E '^(=== RUN|--- |PASS|FAIL|ok)'`
Expected: `TestQual` SKIP (no profiles yet), `TestQualFixtureJunosRuleFailsWhatThePlainFixturePasses` PASS, the two NX-OS tests SKIP until Task 14, `ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/port49d/qual_test.go tests/qual/qual-policy.yaml internal/devicemock/testdata/golden
git commit -m "test: TestQual plays each profile against a real port49d, goldens and acceptance gated

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 11: `make qual` and the mock tier's workflow

**Files:**
- Create: `.github/workflows/qual.yml`
- Modify: `Makefile`

- [ ] **Step 1: Makefile targets**

```make
# The mock tier (plan 11b): every profile against a real in-process port49d. No images,
# no captures, any runner. qual-update rewrites the goldens a port49 change moved
# (marked pending_lab until the next lab run).
qual:
	go test ./internal/devicemock/... ./tests/qual/... -count=1
	go test ./internal/port49d/ -run '^TestQual' -count=1 -timeout 20m

qual-update:
	PORT49_QUAL_UPDATE=1 go test ./internal/port49d/ -run '^TestQual$$' -count=1 -timeout 20m
```

- [ ] **Step 2: The workflow.** Keep `runs-on` one line (decision 52 ruling 7; the runner is still Ryan's to choose):

```yaml
# The mock tier (plan 11b): every vetted platform and firmware as a mock device against a
# real in-process port49d. Go only: no Docker, no images, no lab captures.
name: qual
on:
  push: {branches: [main]}
  pull_request:
permissions: {contents: read}
jobs:
  mocks:
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version-file: go.mod}
      - run: make qual
```

- [ ] **Step 3: Run it locally the way CI does**

Run: `make qual && make check-darwin`
Expected: `ok` for each package, and check-darwin is clean.

- [ ] **Step 4: Commit**

```bash
git add Makefile .github/workflows/qual.yml
git commit -m "ci: the mock tier runs on every PR on any runner

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 12: `TestQualify` — the lab conformance run and its whitelisted evidence

**Files:**
- Create: `tests/lab/qual_evidence.go`, `tests/lab/qual_evidence_unit_test.go`, `tests/lab/qualify_test.go`
- Modify: `Makefile` (`lab-qualify`), `tests/lab/README.md`

**Interfaces:**
- Consumes: `l73Conns`, `l73PlainHeaders`, `l73SummaryLeaks`, `l73Dialects`, the `l73Env` methods (`newL73Env`, `enrol`, `configure`, `capture`, `tokenLogin`, `restore`), and the lab harness (`labFor`, `eachSelected`, `l.derivedConfig`, `privatePolicy`, `l.recordsSince`, `l.mark`, `l.login`, `labcreds.Contains`).
- Produces:
  - `func qualRecord(r map[string]any) (map[string]any, bool)`: the whitelist;
  - `type qualRun struct { Platform, LabPlatform, Firmware, Image, Commit, Date string; Transports []string; Cells map[string]string; Registers map[string][]string }` written as `run.json`;
  - the evidence directory `tests/lab/evidence/QUAL-<lab_platform>-<firmware_slug>/` holding:
    - `run.json`;
    - `decisions.jsonl`;
    - `<cell>.conns.json` (plain 49: connections and 12-byte headers only);
    - `<cell>.tls.json` (TLS);
  - the note `tests/lab/results/QUAL-<lab_platform>.md`, one section per firmware.

**The conformance cells** run in this fixed order. Each cites the register row it re-measures, and it closes nothing (decision 52 ruling 10).

| Cell | What | Re-measures |
|---|---|---|
| `token_login` | a token login over SSH running `show version`: the START's fields and `port`, and the exchanges per login | L1, L15, L19 |
| `command_permitted` | `show version` authorized: the service and the command words sent | L10, L21 |
| `command_denied` | `show users` refused | L21 |
| `accounting` | the login's start and stop records | L6 |
| `wrong_credential` | a random string as password, refused, and what the device does with the FAIL | L13 |
| `store_unavailable` | `fault_file: store_unavailable`, then break-glass and its timing | L4, L28 |
| `single_connection` | the startup config's single-connection form | L15, L73 h |

The session reply's acceptance (roles, attributes the device refuses) is not re-measured here. Acceptance rules cite L16 (roles) and L18 (an attribute the device did not ask for) as those notes measured them.
| `tls_*` | for an L73 dialect that is not `HelpOnly`: enrol, configure TLS, and repeat `token_login` and `store_unavailable` over TLS, plus `unknown_ca` | L73 |

- [ ] **Step 1: Write the failing whitelist tests** (`qual_evidence_unit_test.go`, tag `lab`, so `make lab-unit` runs them):

```go
func TestQualRecordKeepsOnlyTheWhitelist(t *testing.T) {
	in := map[string]any{"event": "redeem", "verdict": "permit", "reason": "context_matched",
		"auth": map[string]any{"method": "token", "credential_sha256": "ab12"},
		"device": map[string]any{"name": "nx1", "platform": "cisco_nxos", "transport": "tls", "cert_sha256": "cd34"},
		"session": map[string]any{"username": "alice03", "port": "0", "rem_addr": "172.100.100.1", "privilege": 1.0, "ctx_id": "x"},
		"packet_fields": map[string]any{"action": "login", "authen_type": "pap", "service": "login", "priv_lvl": 1.0},
		"server_msg": "anything"}
	out, ok := qualRecord(in)
	if !ok {
		t.Fatal("a redeem record is kept")
	}
	b, _ := json.Marshal(out)
	for _, never := range []string{"credential_sha256", "cert_sha256", "ab12", "cd34", "ctx_id", "server_msg", "alice03"} {
		if strings.Contains(string(b), never) {
			t.Fatalf("kept %q: %s", never, b)
		}
	}
	for _, want := range []string{`"authen_type":"pap"`, `"port":"0"`, `"username":"{user}"`, `"rem_addr":"{rem_addr}"`} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("lacks %s: %s", want, b)
		}
	}
}

func TestQualRecordDropsMintAndUnvalidatedRecords(t *testing.T) {
	for _, ev := range []string{"mint", "unvalidated", "issue", "revoke"} {
		if _, ok := qualRecord(map[string]any{"event": ev}); ok {
			t.Fatalf("%s is not stimulus evidence", ev)
		}
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `make lab-unit`
Expected: FAIL (`undefined: qualRecord`).

- [ ] **Step 3: Implement `qual_evidence.go`** (untagged, pure):

```go
package lab

import "strings"

// qualRecord keeps what a profile is generated from (spec §13 decision 52
// ruling 2): the validated request records' event, verdict, reason, the
// request's service and attribute list, the reply's attributes, the
// accounting record's flags and attribute list, packet_fields, and the
// session's port and privilege. The lab user becomes {user} and the lab
// host's address {rem_addr}. Every hash, id, name, message and mint record
// is dropped: the generator cannot read what is not here.
func qualRecord(r map[string]any) (map[string]any, bool) {
	ev, _ := r["event"].(string)
	switch ev {
	case "redeem", "authenticate", "authorize_session", "authorize_command", "account":
	default:
		return nil, false
	}
	out := map[string]any{"event": ev}
	for _, k := range []string{"verdict", "reason", "flags", "attribution", "packet_fields"} {
		if v, ok := r[k]; ok {
			out[k] = v
		}
	}
	if d, ok := r["device"].(map[string]any); ok {
		out["device"] = map[string]any{"platform": d["platform"], "transport": d["transport"]}
	}
	if s, ok := r["session"].(map[string]any); ok {
		out["session"] = map[string]any{"port": s["port"], "privilege": s["privilege"], "username": "{user}", "rem_addr": "{rem_addr}"}
	}
	if q, ok := r["request"].(map[string]any); ok {
		out["request"] = map[string]any{"service": q["service"], "raw": templated(q["raw"])}
	}
	if q, ok := r["reply"].(map[string]any); ok {
		out["reply"] = map[string]any{"attributes": q["attributes"]}
	}
	if q, ok := r["record"].(map[string]any); ok {
		out["record"] = map[string]any{"raw": templated(q["raw"]), "priv_lvl": q["priv_lvl"]}
	}
	return out, true
}

// templated replaces the values a rerun always changes with the engine's
// placeholders: task_id, start_time, stop_time.
func templated(v any) any {
	xs, ok := v.([]any)
	if !ok {
		return v
	}
	out := make([]any, 0, len(xs))
	for _, x := range xs {
		s, _ := x.(string)
		for _, k := range []string{"task_id", "start_time", "stop_time"} {
			if strings.HasPrefix(s, k+"=") {
				s = k + "={" + k + "}"
			}
		}
		out = append(out, s)
	}
	return out
}
```

- [ ] **Step 4: Write `qualify_test.go`** (`//go:build lab`). The skeleton:

```go
// TestQualify is the conformance run a firmware is vetted by (plan 11b): the
// fixed cells, under tests/qual/qual-policy.yaml, on each selected platform.
// It writes whitelisted evidence the generator reads, and a note that cites
// the register rows each cell re-measures. It closes no row.
func TestQualify(t *testing.T) {
	eachSelected(t, true, func(t *testing.T, l *lab) {
		q := newQualEnv(t, l) // derived config: broker run, qual policy via privatePolicy, fault_file
		q.guard()             // the STOP sentinel before every cell
		q.cellTokenLogin()
		q.cellCommands()
		q.cellAccounting()
		q.cellWrongCredential()
		q.cellStoreUnavailable()
		q.cellSingleConnection()
		if d, ok := l73Dialects[l.p.name]; ok && !d.HelpOnly {
			q.tlsCells(newL73Env(t, l, d)) // enrol, configure, token_login and store_unavailable over TLS, unknown_ca
		}
		q.write() // leak gates (labcreds.Contains, l73SummaryLeaks), then evidence, then the note
	})
}
```

Write each cell method in full in this task. Follow the order and the cell-start offsets that `TestL73` (`tests/lab/l73_test.go:131-180`) and `TestLoginRoundTrip` (`harness_test.go:2282`) use: `l.mark()` before a cell, `l.recordsSince(off)` after, mapped through `qualRecord`. For plain 49, read the cell's capture from `tests/lab/captures/` with `l73Conns(raw, l.p.addr)` and keep only `Server`, `DevicePort`, `SYNAt`, `End`, `EndAt` and `Plain`; that is the 12-byte headers and nothing more. For TLS, keep `l73Conns`' summaries as `<cell>.tls.json` (already session-byte-free by type). `write()` refuses to write anything (INVALID) if any file holds a lab secret (`labcreds.Contains(body, q.secrets())`) or a long hex or base64 run (`l73SummaryLeaks`). Nothing reaches `evidence/` or `results/` before that gate passes.

- [ ] **Step 5: Makefile**

```make
# The conformance run a firmware is vetted by (plan 11b). One platform selector at a time.
lab-qualify:
	@test -n "$(P)" || { echo "usage: make lab-qualify P=<selector, e.g. nxos106>"; exit 2; }
	PORT49_LAB_PLATFORMS=$(P) go test -tags lab ./tests/lab/ -run '^TestQualify$$' -count=1 -v -timeout 180m
```

- [ ] **Step 6: Run the unit and vet checks**

Run: `make lab-unit && go vet -tags lab ./tests/lab/ && GOOS=darwin go vet -tags lab ./tests/lab/`
Expected: PASS, and both vets are clean.

- [ ] **Step 7: Commit**

```bash
git add tests/lab/qual_evidence.go tests/lab/qual_evidence_unit_test.go tests/lab/qualify_test.go Makefile tests/lab/README.md
git commit -m "test: TestQualify, the lab conformance run with whitelisted evidence

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 13: `genprofile`, evidence to profile

**Files:**
- Create: `tests/qual/cmd/genprofile/main.go`, `tests/qual/cmd/genprofile/gen.go`, `tests/qual/cmd/genprofile/gen_test.go`, `tests/qual/cmd/genprofile/testdata/QUAL-fixture-1.0/` (a hand-written evidence fixture: `run.json`, `decisions.jsonl` in `qualRecord`'s shape, `token_login.conns.json`, `token_login.tls.json`)

**Interfaces:**
- Consumes: the evidence layout (Task 12) and `devicemock.Profile` (Task 6).
- Produces:
  - `func Generate(evDir, repoRoot string) (*devicemock.Profile, Golden, error)`;
  - the command `go run ./tests/qual/cmd/genprofile -evidence <dir>`, which writes `tests/qual/profiles/<platform>/<firmware_slug>.yaml` and `tests/qual/golden/<platform>/<firmware_slug>.json`, then prints a review checklist.

What it derives:
- **Steps**: from `decisions.jsonl` of the `token_login` and `command_*` cells. The first `redeem` gives `login` (`packet_fields`, `session.port`). The first `authorize_session` gives `authorize_session` (`request.raw`). The `authorize_command` records give `command_permitted` and `command_denied` (by `verdict`). The `account` records give `account_start` and `account_stop` (by `flags`, `record.raw` templated).
- **Connections**: `mode: per_step` when the `token_login` cell's connections number at least its steps; `single_connection` when the `single_connection` cell carried every step on one connection; `single_connect_flag` from the first plain header's flags & 0x04.
- **TLS**: `client_hello` from the first `*.tls.json` connection's `client_hello` (`has_sni` with an SNI equal to the server's address becomes `{server_ip}`); `server_hello` from its `server_hello`; `flight_delay` as the minimum of `device_reply_at - server_flight_at` over every connection that has both, rounded to 10 ms.
- **Reactions (pre-filled)**: one entry per (step, event) the evidence shows, `status: measured`, citing the cell's note. Every `then` is `next_step`, except:
  - `authen_fail` → `stop`/`login_refused`;
  - `store_unavailable`'s `authen_error` → `failover_local`/`falls_to_local` when the cell's break-glass logged in, and `give_up`/`break_glass_fails` when it did not;
  - `unknown_ca` → `give_up`.
- **Acceptance (pre-filled)**: `priv_lvl_range` from the device's own `priv_lvl` values (status `unmeasured`: seeing values is not measuring a limit); nothing else. Rules are written by hand at vetting.
- **Golden**: per scenario, the reply events and the reply attributes the evidence shows.

- [ ] **Step 1: Write the failing tests**

```go
func TestGenerateTheFixture(t *testing.T) {
	p, g, err := Generate("testdata/QUAL-fixture-1.0", "testdata")
	if err != nil {
		t.Fatal(err)
	}
	if p.Stimulus.Steps[0].Fields.AuthenType != "pap" || p.Stimulus.TLS.FlightDelay != 5*time.Second ||
		p.Stimulus.Connections.Mode != "per_step" || g.Scenarios["token_login"].Outcome != "login_ok" {
		t.Fatalf("%+v %+v", p.Stimulus, g)
	}
	if err := p.Validate("testdata"); err != nil {
		t.Fatalf("a generated profile must load: %v", err)
	}
}

func TestGenerateRefusesForbiddenKeys(t *testing.T) {
	dir := copyFixture(t)
	f, _ := os.OpenFile(filepath.Join(dir, "decisions.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString(`{"event":"redeem","auth":{"credential_sha256":"00"}}` + "\n")
	f.Close()
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "credential_sha256") {
		t.Fatal("evidence holding a credential hash is refused, never filtered quietly")
	}
}

func TestGenerateNeverReadsACapture(t *testing.T) {
	dir := copyFixture(t)
	os.WriteFile(filepath.Join(dir, "x.pcap"), []byte("not read"), 0o600)
	if _, _, err := Generate(dir, "testdata"); err == nil || !strings.Contains(err.Error(), "x.pcap") {
		t.Fatal("a capture in the evidence directory is refused: profiles never come from bodies")
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./tests/qual/cmd/genprofile/ -count=1`
Expected: FAIL (`undefined: Generate`).

- [ ] **Step 3: Implement `gen.go` and `main.go`** as described above.
  - `Generate` lists the directory first and refuses any name outside `run.json`, `decisions.jsonl`, `*.conns.json` and `*.tls.json`. It refuses any file holding one of devicemock's forbidden strings.
  - `main` writes YAML with `yaml.NewEncoder`, indent 2, and prepends a header comment: `# Generated by genprofile from <evidence> at <commit>; stimulus is generated, reactions and acceptance are reviewed by hand (decision 52 ruling 1).`
  - It prints the review checklist:
    - every reaction against the note's cell text;
    - every acceptance rule's status;
    - every engine gap's `code`;
    - the golden's outcomes against the note.

- [ ] **Step 4: Run**

Run: `go test ./tests/qual/cmd/genprofile/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add tests/qual/cmd/genprofile
git commit -m "feat: genprofile builds a profile's stimulus from whitelisted lab evidence

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 14: Lab — vet the images in hand and commit the first wave of mocks

**Files:**
- Create: `tests/lab/evidence/QUAL-*/`, `tests/lab/results/QUAL-*.md`, `tests/qual/profiles/*/*.yaml`, `tests/qual/golden/*/*.json`

This task runs on beehive, under the lab lock, with the watchdog. Run one platform at a time.

The images are the ten `tests/lab/harness_test.go` rows that run TACACS+:
- `ceos436`, `nxos106`, `iosxe1718` and `vjunos26` (TLS and plain);
- `srlinux` (plain);
- `eos`, `vjunos`, `vsrx`, `nxos` and `iosxe` (plain, the older images).

`vjunosswitch26` was skipped in L73 and is skipped here too. XRd is Task 16.

- [ ] **Step 1: For each selector,** in that order, run `make lab-qualify P=<sel>`, then:

```
go run ./tests/qual/cmd/genprofile -evidence tests/lab/evidence/QUAL-<lab_platform>-<fw>
```

Read the logs only through the filter in Global Constraints.

- [ ] **Step 2: Review each profile by hand** against its note, then `tests/lab/results/L73-*.md` and `L4-*.md`.
  - Every reaction cites a note that says it.
  - Add the measured reactions the conformance run did not reach but L73 cell (i) did: alert, reset at Accept, the decline window, citing `L73-<platform>.md` cell (i).
  - IOS XE 17.18.02 over TLS: `authen_error` → `give_up`/`break_glass_fails` (`L73-cisco_iosxe.md` cell i).
  - Junos profiles get the acceptance rule below, which Task 15 measures:

```yaml
  - id: junos_reply_total
    kind: max_reply_bytes
    applies: authorize_session
    max: 255
    effect: lockout
    status: unmeasured
    sources: [{note: tests/lab/results/L2-juniper_vjunos-router.md, register: L2}]
    note: Ryan's production prior; L2 measured only long deny messages; L78 measures it
```

  - NX-OS profiles list the `shell:roles` names `L16-cisco_nxos.md` measured as `role_names` (measured, cited).
  - Each platform with an `L18-<platform>.md` note gets the measured handling of an attribute it did not ask for: `attribute_refused` where the note shows the session killed, with `effect: session_refused`.
  - Every profile with an IP-literal SNI (Junos) lists `engine_gaps: [{id: sni_ip_literal_in_session, what: "crypto/tls omits an IP-literal SNI; the hello probe sends it", code: internal/devicemock/hello.go}]`.

- [ ] **Step 3: Run the mocks**

Run: `make qual`
Expected: `ok`, with `TestQual/<platform>/<firmware>` passing for each of the ten. The two NX-OS timing tests now run: the real-delay one takes about 5 s.

- [ ] **Step 4: Copy raw captures** to main's `tests/lab/captures/` before removing any worktree. Run `make test && make vet` on beehive.

- [ ] **Step 5: Commit** (one commit per platform is fine; the profiles and goldens with their evidence and note):

```bash
git add tests/lab/evidence/QUAL-* tests/lab/results/QUAL-*.md tests/qual/profiles tests/qual/golden
git commit -m "test: vet ten images and add their mock devices

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 15: Lab — L78, a long permit reply on Junos

**Files:**
- Create: `tests/lab/l78_test.go` (tag `lab`), `tests/lab/l78_unit_test.go`, `tests/lab/results/L78-juniper_vjunos-router.md`
- Modify: the Junos profiles' `junos_reply_total` rule; spec §15 L78

The run uses a derived policy whose Junos session reply grows in steps (200, 240, 256, 300, 400, 600 bytes total, each attribute at most 255). At each step it does a token login. Break-glass is proved before each step and after the last, and the run stops at the first step that leaves break-glass refused. This is L2's method (`tests/lab/l2_test.go`). Run it on vjunos (23.4R2-S2.1) and vjunos26 (26.2R1.7).

- [ ] **Step 1: Write the unit test** for the step policy builder `l78Policy(total int) string`: each rendered attribute ≤ 255, and the total within 5 bytes of the target.
- [ ] **Step 2: Run it to see it fail** (`make lab-unit`), implement `l78Policy`, and run it to pass.
- [ ] **Step 3: Write `TestL78`** from `TestL2`'s break-glass loop. Record per step:
  - the total bytes;
  - whether the token login reached a prompt;
  - whether the session was locked out;
  - break-glass after.
- [ ] **Step 4: Run** `PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^TestL78$' -count=1 -v -timeout 90m`, then the same with `vjunos26`.
- [ ] **Step 5: Close or keep open** per CLAUDE.md rule 3.
  - Set the Junos profiles' rule to `status: measured` with the measured `max` and `effect`, citing `L78-juniper_vjunos-router.md`.
  - If no lockout was seen at any size, delete the rule, and say so in the note.
  - Run `make qual`.
- [ ] **Step 6: Commit** with `docs: close lab register entries L78` (or `test: L78 measured, ...` if a platform stays open).

---

### Task 16: XRd 26.1.1 — the XR dialect, help first, and a full L73 row

**Files:**
- Modify: `tests/lab/l73_dialect.go` (the `cisco_xrd` entry: `HelpOnly: false`, plus the XR line builders), `tests/lab/l73_dialect_unit_test.go`, `tests/lab/harness_test.go` (`helpOnlyPlatforms` loses `xrd261`), `tests/lab/configs/xrd-startup.cfg` (a TACACS+ server group and a break-glass method list, as the other startup configs carry)
- Create: `tests/lab/results/L73-cisco_xrd.md`, `tests/lab/evidence/L73-cisco_xrd/*`, then the XRd profile through Task 14's steps

**Interfaces:**
- Produces: `func l73XRApply(d l73DeviceTLS) []string`, `func l73XRUndo(d l73DeviceTLS) []string` and `func l73XREnrol(node string) (prep []l73Dialog, enroll, load l73Dialog)`, the same shapes as the Cisco ones.

**Help first** (the rule every dialect follows, `l73_dialect.go` comment at the EOS dialect): no line is typed that the image's own help has not listed.
- [ ] **Step 1: Extend the XR `Asks`** with the levels the apply and enrol lines will use. These are the server group, `tacacs-server host <ip> tls ?`, `crypto key generate ?`, `crypto ca trustpoint <name> ?` and `crypto ca enroll ?`, plus `commit ?`, since XR commits. Run `PORT49_LAB_PLATFORMS=xrd261 PORT49_L73_DIAG=help go test -tags lab ./tests/lab/ -run '^TestL73$'`, which records the help and ends INVALID by design. Read the help transcripts in `PORT49_L73_INVALID_DIR` through the filter.
- [ ] **Step 2: Write the unit tests** for `l73XRApply`, `l73XRUndo` and `l73XREnrol` from the help just recorded. Every keyword is one the help listed, the undo is the startup config's state (as `TestL73CiscoUndoIsTheStartupConfig` checks for IOS XE), and each change ends in `commit`. Run them to fail, implement, and run them to pass.
- [ ] **Step 3: Respect XRd's sshd rate limit** (60 sessions a minute, `L71-cisco_xrd.md`). Every cell's login loop paces at most one session a second.
- [ ] **Step 4: Run the full row**: `PORT49_LAB_PLATFORMS=xrd261 go test -tags lab ./tests/lab/ -run '^TestL73$' -count=1 -v -timeout 180m`. Write `L73-cisco_xrd.md` (cells a–j). L73 stays closed; this adds a platform note. Add the note to the L73 row's Status list in spec §15, and the evidence pointer.
- [ ] **Step 5: Vet XRd** with Task 14's steps 1–3 (`make lab-qualify P=xrd261`, genprofile, review, `make qual`).
- [ ] **Step 6: Commit**: `test: L73 measured on XRd 26.1.1 with an XR dialect, and its mock`.

---

### Task 17: The 11a carry-in (M4) — a late write after the heal

**Files:**
- Modify: the regions harness (`grep -ln 'TestRegions' tests/lab/*.go`), adding cells (j) and (k) to L74's cell list, `tests/lab/results/L74-regions.md`

From 11a's final review (`review-dialfix-r2.md` M4 and the controller's ruling of 2026-10-19), carried to this plan as a lab cell:
- **(j)** A lift sent to a region whose link to the directory etcd is stalled, not cut (netem `loss 100%` on the established connection, so the kernel keeps retransmitting). The lift reports "could not be lifted, and stands". The link then heals within the retransmission window. Measure whether the lift lands late, and whether `port49 store status` and the decision log say so.
- **(k)** The reverse: a revoke sent on a stalled link, delivered after an operator's lift elsewhere. Expected to fail closed: the mark re-created. Measure it.

- [ ] **Step 1: Unit-test the cell table rows** (the existing regions unit test file): (j) and (k) have claims, rely on netem `loss` not `blackhole`, and read the mark's state in the directory after the heal.
- [ ] **Step 2: Implement the two cells** in the existing harness style. Pick the stall timing so the heal falls inside TCP's retransmission window (`net.ipv4.tcp_retries2` default: about 15 minutes; heal at 20 s).
- [ ] **Step 3: Run** `make lab-regions` with `-run` narrowed to the two cells if the harness supports it, otherwise the whole of L74. Record the result as an addendum in `L74-regions.md`. L74 stays closed.
  - If (j) shows a lift landing after "could not be lifted": the doc claiming it stands is wrong. Fix the operator text in `port49 revoke --lift`'s message and the 11a stores notes, and cite the note.
  - If a security weakening appears (a revocation silently lost), stop and report it to Ryan.
- [ ] **Step 4: Commit**: `test: L74 cells j and k, a write delivered after the heal`.

---

### Task 18: The L76 carry-in (R3-M1) — the mixed-pair wording

**Files:**
- Modify: `tests/lab/l76_cells.go` (`l76WriteText`'s inner switch), `tests/lab/l76_unit_test.go`

From L76's final re-review 3 (`R3-M1`, parked "to the next L76 touch / qualification suite"). For the mixed pairs (exists, unknown) and (unknown, exists), the finding's sentence says the other channel "refused the same write" when its state is unknown. The finding is still raised. No rerun is needed: run 12 was (absent, absent).

- [ ] **Step 1: Write the failing unit test**

```go
func TestL76WriteTextNeverSaysRefusedForAnUnknownChannel(t *testing.T) {
	for _, pair := range [][2]string{{l76WriteExists, l76WriteUnknown}, {l76WriteUnknown, l76WriteExists}} {
		got := l76WriteText(l76Write{Name: "first", State: pair[0]}, l76Write{Name: "second", State: pair[1]})
		if strings.Contains(got, "refused the same write") {
			t.Fatalf("%v: %q says refused for a channel whose state is unknown", pair, got)
		}
		if !strings.Contains(got, "could not be determined") || !strings.Contains(got, "**Security finding:**") {
			t.Fatalf("%v: the finding is still raised and says the other channel is undetermined: %q", pair, got)
		}
	}
	// (exists, absent) keeps its measured wording.
	got := l76WriteText(l76Write{Name: "first", State: l76WriteExists}, l76Write{Name: "second", State: l76WriteAbsent})
	if !strings.Contains(got, "the second exec channel refused the same write") {
		t.Fatalf("%q", got)
	}
}
```

- [ ] **Step 2: Run it to fail** (`make lab-unit`). **Fix** in `l76WriteText`'s inner switch (`tests/lab/l76_cells.go:1075-1086`): make the two one-sided cases `first.State == l76WriteExists && second.State == l76WriteAbsent` and `second.State == l76WriteExists && first.State == l76WriteAbsent`. Add one case for a single write beside an unknown channel: "wrote on the <first|second> exec channel of one SSH login; whether the <other> exec channel wrote could not be determined." Every other mix falls to the existing "may have written" default. **Run it to pass.**
- [ ] **Step 3: Commit**: `fix(lab): L76's mixed write pairs no longer say refused for an unknown channel (R3-M1)`.

---

### Task 19: Fleet mode

**Files:**
- Create: `internal/devicemock/fleet.go`, `internal/devicemock/fleet_test.go`, `internal/port49d/qual_fleet_linux_test.go`
- Modify: `Makefile` (`qual-fleet`)

**Interfaces:**
- Produces:

```go
type Fleet struct {
	Profile     *Profile
	N           int
	Concurrency int // at most this many plays at once; 0 means N
	Scenario    string
}
type FleetResult struct {
	Plays    int
	Outcomes map[string]int // outcome to count
	Errors   int
	P50, P99 time.Duration  // per play
}
func (f Fleet) Run(ctx context.Context, target func(i int) Target, login func(i int) Login) FleetResult
func LoopbackSource(i int) string // 127.0.1.1 + i, wrapping into 127.0.2.x past 254
```

- [ ] **Step 1: Write the failing unit test** against the fake server (Task 9) with N=50 and concurrency 10: every play has the outcome `login_ok`, `Plays == 50`, and `P99 >= P50`. `LoopbackSource(0) == "127.0.1.1"`, and `LoopbackSource(254) == "127.0.2.1"`. Binding to a source address is not exercised here (darwin-safe).
- [ ] **Step 2: Implement** `Run`: a semaphore channel, a `sync.WaitGroup`, durations sorted for P50 and P99. A play's error counts in `Errors` and never prints its transcript. Run to pass.
- [ ] **Step 3: Write `TestQualFleet`** (`//go:build linux`; skips unless `PORT49_QUAL_FLEET=1`). One port49d, an inventory of N devices `q0001`…`qNNNN` at `LoopbackSource(i)`, the profile `arista_eos/4.36.3M` played over tcp. Three phases, each asserting the outcome counts:
  - (a) N=500 concurrent `token_login`s, all `login_ok`;
  - (b) the same with a policy file rewrite mid-run (the reload under load): all `login_ok`, and the decision log shows the refresh;
  - (c) `fault("store_unavailable")` mid-run: every play after the fault is `falls_to_local` per the profile's reaction, none hangs past 10 s, and clearing the fault returns plays to `login_ok`.

  Log the P50 and P99 per phase. It asserts no latency number: plan 12 sets the targets.
- [ ] **Step 4: Makefile**

```make
# Fleet mode (plan 11b): N mock devices from N loopback addresses against one port49d.
# Linux. Plan 12's load validation drives it at the §5 target rate.
qual-fleet:
	PORT49_QUAL_FLEET=1 go test ./internal/port49d/ -run '^TestQualFleet$$' -count=1 -v -timeout 30m
```

- [ ] **Step 5: Run** `make qual-fleet` and `make check-darwin`. Expected: PASS with the three phases' P50 and P99 logged, and darwin clean.
- [ ] **Step 6: Commit**: `test: fleet mode, N mock devices against one port49d`.

---

### Task 20: The free-image tier: SR Linux on a runner

**Files:**
- Create: `.github/workflows/lab-free.yml`

SR Linux (`ghcr.io/nokia/srlinux`) is freely redistributable. It may run on a hosted runner; no vendor image ever does (decision 52 ruling 7). The workflow installs containerlab, pulls the pinned SR Linux image, and runs `TestQualify` and `TestL76` for the `srlinux` selector. It fails if `notediff` reports a changed observation, or if `genprofile` output differs from the committed profile's stimulus.

- [ ] **Step 1: Write the workflow.** Its trigger follows Q1's answer; the default is `workflow_dispatch` and release tags:

```yaml
# The free-image tier (plan 11b): SR Linux, the one lab image that may run on a hosted
# runner (vendor images are never redistributed). runs-on is one line: beehive's
# self-hosted label is the other choice.
name: lab-free
on:
  workflow_dispatch:
  push: {tags: ['v*']}
permissions: {contents: read}
jobs:
  srlinux:
    runs-on: ubuntu-24.04
    timeout-minutes: 60
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version-file: go.mod}
      - run: bash -c "$(curl -sL https://get.containerlab.dev)" -- -v 0.71.1
      - run: docker pull ghcr.io/nokia/srlinux:26.7.2-519
      - run: make build
      - run: PORT49_LAB_PLATFORMS=srlinux go test -tags lab ./tests/lab/ -run '^(TestQualify|TestL76)$' -count=1 -v -timeout 50m
      - run: go run ./tests/lab/cmd/notediff -note tests/lab/results/L76-nokia_srlinux.md
      - run: go run ./tests/qual/cmd/genprofile -evidence tests/lab/evidence/QUAL-nokia_srlinux-26.7.2-519 && git diff --exit-code tests/qual/profiles
```

Check the containerlab version pin against the one beehive runs (`containerlab version`) and use that. Check that `TestL76` and `TestQualify` need no capture the runner lacks; the labpcap audit runs only under `make test`, never here.

- [ ] **Step 2: Validate the YAML**: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7 .github/workflows/lab-free.yml` if allowed; otherwise `python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' .github/workflows/lab-free.yml`.
- [ ] **Step 3: Commit**: `ci: the free-image tier runs SR Linux's qualification on dispatch and tags`.

---

### Task 21: The qualified-platforms list, generated

**Files:**
- Create: `tests/qual/cmd/qualified/main.go`, `tests/qual/cmd/qualified/qualified.go`, `tests/qual/cmd/qualified/qualified_test.go`, `docs/qualified-platforms.md`
- Modify: `Makefile` (`qualified-platforms`)

**Interfaces:**
- Produces: `func Build(repoRoot string) (string, error)`, the Markdown table:

| vendor | OS | version tested | TACACS+ 49 | TLS 300 | command authorization | accounting | mock | status |

A row exists only where a profile exists and every note it cites exists. `status` is one of:
- `qualified`: every conformance scenario's golden outcome is the expected one and the golden is not pending;
- `partial`: some scenario is absent or failed in the lab;
- `re-vet pending`: the golden is `pending_lab`.

Untested platforms are not listed.

- [ ] **Step 1: Write the failing test**

```go
func TestTheCommittedListIsTheGeneratedOne(t *testing.T) {
	got, err := Build("../../../..")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := os.ReadFile("../../../../docs/qualified-platforms.md")
	if got != string(want) {
		t.Fatal("docs/qualified-platforms.md is stale: run make qualified-platforms")
	}
}

func TestARowNeedsItsNotes(t *testing.T) {
	root := fixtureRepo(t) // a temp tree: one profile citing a note, the note removed
	if _, err := Build(root); err == nil || !strings.Contains(err.Error(), "note") {
		t.Fatal("a profile whose note is missing makes no row: the build fails naming it")
	}
}
```

- [ ] **Step 2: Run to fail, implement, run to pass.** `make qualified-platforms` runs `go run ./tests/qual/cmd/qualified > docs/qualified-platforms.md`.
- [ ] **Step 3: Commit**: `docs: the qualified-platforms list, generated from the profiles and notes`.

---

### Task 22: `make qual-vet` and the contributor procedures

**Files:**
- Create: `tests/qual/vet.sh`, `tests/qual/README.md`
- Modify: `Makefile` (`qual-vet`), `tests/lab/README.md` (a pointer)

`make qual-vet P=<selector>` is "vet a new firmware and add its mock" as one command. It refuses when:
- the STOP sentinel exists;
- the lab lock is held;
- the working tree has uncommitted changes under `tests/qual` or `tests/lab/results`.

Then it runs, in order:
1. `make lab-qualify P=<sel>`;
2. `genprofile` on the new evidence;
3. `make qual`;
4. `make qualified-platforms`;
5. it prints `git status --short` and `git diff --stat` for tests/qual, the note and the list, then the generator's review checklist.

It commits nothing: the review is a person's.

- [ ] **Step 1: Write `vet.sh`** (bash, `set -euo pipefail`) with those steps. Lab logs pass only through the Global Constraints filter.
- [ ] **Step 2: Write `tests/qual/README.md`** with three procedures:
  - **Vet a new firmware and add its mock.**
    1. Put the image on `/mnt/images`, and add its `platforms` row (selector, topology, image, version, a measured `boot`).
    2. `make qual-vet P=<sel>`.
    3. Review the profile's reactions and acceptance rules against the note (the checklist).
    4. Commit the evidence, the note, the profile, the golden and the list.

    No mock is added for an image the lab has not run (decision 52 ruling 8).
  - **Add a platform.**
    1. A `platforms` row and topology.
    2. A startup config with break-glass and the TACACS+ server group.
    3. For TLS, an `l73Dialects` row written help first.
    4. A port49 inventory platform: built in, or generic, which logs `platform_unknown`.

    Then vet as above. Any engine gap it needs is an `engine_gaps` entry, plus Go in `internal/devicemock` with a test.
  - **When a mock fails on a PR.**
    - A gate (acceptance rule): port49's reply would be rejected by the device. Fix port49, or, if the rule is wrong, re-measure it in the lab.
    - A golden difference: if port49 changed on purpose, `make qual-update` and review. The list shows re-vet pending until the next lab run.
    - A missing reaction: the vetter adds it from the notes.
- [ ] **Step 3: Run** `bash -n tests/qual/vet.sh`, and `make qual-vet P=` (no selector), which prints usage and exits 2.
- [ ] **Step 4: Commit**: `docs: make qual-vet and the procedures to vet a firmware and add a platform`.

---

### Task 23: Docs — the roadmap as built, and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` ("Plan 11b — As built", and the status line), `tests/lab/README.md`

- [ ] **Step 1: Write "Plan 11b — As built"** in the style of 11a's:
  - the task commits;
  - the rulings as recorded;
  - what the lab changed;
  - the full lab-regress time (Task 4);
  - L78's result;
  - XRd's L73 note;
  - the carried items.
- [ ] **Step 2: Hand-offs.**
  - **Plan 12**: the load test drives `make qual-fleet` at the §5 rate. The deployment shapes' smoke tests may use a mock device in place of vEOS.
  - **Plan 13**: the qualified-platforms page from `docs/qualified-platforms.md`; the contributor guide from `tests/qual/README.md`; `packet_fields` in the decision-log reference.
  - **Pre-beta review**: run `make lab-regress` in full.
- [ ] **Step 3: Operator-facing notes for the PR body:**
  - `packet_fields` on every validated request record;
  - `docs/qualified-platforms.md`;
  - nothing else operator-visible (no config key, reason code or metric).
- [ ] **Step 4: Run** `make test && make vet` on beehive and report the output.
- [ ] **Step 5: Commit**: `docs: plan 11b as built`.

---

## Questions for Ryan

- **Q1. When does the SR Linux job (Task 20) run?** On every PR it costs about 30 runner minutes a PR, and you raised the Actions spend limit on 2026-10-19 while deciding on runners. **Recommendation:** `workflow_dispatch` and release tags now. Move it to PRs that touch `internal/platform`, `internal/daemon` or `tests/qual`, with a path filter, once the runner is beehive or the repository is public (free minutes). The mock tier (`qual.yml`) runs on every PR either way.

## Self-review notes

- **Coverage of Ryan's 2026-10-19 design.**
  - Mocks per platform and firmware: Tasks 6–10 and 14.
  - Hello parameters: Task 8, the probe.
  - Timing with a scale, plus one real test: Task 10.
  - Connection pattern: Task 9.
  - Request attributes and accounting from validated records: Tasks 5, 12 and 13.
  - Failure cases: Tasks 9, 10 and 14.
  - Every PR on any runner: Task 11.
  - The real lab for tags and image changes: Tasks 2–4.
  - New firmware only after vetting, automated: Task 22.
  - Lab regressions under the lock and STOP, diffed, timed early: Tasks 2–4.
  - Vendor images never hosted, SR Linux allowed: Task 20.
  - `runs-on` one line: Tasks 11 and 20.
  - Carry-ins: XRd (Task 16), M4 (Task 17), R3-M1 (Task 18).
  - The qualified list: Task 21.
  - The three-part profile, the escape hatch, the generator's pre-fill and the acceptance-violation test: Tasks 6, 7, 10 and 13.
  - Fleet: Task 19.
  - The SSH front: later work.
  - cisshgo credited.
- **Security rules.**
  - No body decode: Task 12 keeps headers only; Task 13 refuses captures.
  - Fresh credentials: Tasks 9 and 10.
  - No hash in fixtures: Tasks 6, 12 and 13.
  - Certificates per test: Task 10.
  - Log filter: Global Constraints and Tasks 4 and 14.
  - Darwin: `_linux` files in Tasks 2 and 19.
