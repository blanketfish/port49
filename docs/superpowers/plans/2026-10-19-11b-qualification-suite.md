# Qualification Suite Implementation Plan (plan 11b)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every vetted platform and firmware gets a mock device: a data profile, played by one Go engine against a real in-process port49d, that runs on every PR on any runner. The real lab gets:
- `make lab-regress`, which reruns closed entries and diffs them against their notes;
- `make qual-vet`, which turns a lab run into a profile ready for review.

**Architecture:** A mock device is a **profile** (YAML, snake_case) in three parts:
1. **Stimulus**, generated from closed lab evidence: what the device sends whatever port49 answers.
2. **Reaction table**: what it does next on each reply or alert.
3. **Acceptance rules**: which of port49's replies the device rejects.

`internal/devicemock` holds the engine. It plays a profile as a TACACS+ client: plain 49, or RFC 9887 TLS with the measured ClientHello and flight delay.

`internal/port49d`'s `TestQual` starts a real port49d per profile. It runs under one qualification policy, one shared daemon fragment and the broker's mint path: the same three the lab conformance run uses. It checks port49's replies against a golden file and the profile's acceptance rules.

A generator, `tests/qual/cmd/genprofile`, builds part 1 from a lab conformance run's evidence and pre-fills parts 2 and 3. A fleet mode runs N engines from N loopback addresses at once.

**Tech Stack:** Go 1.26 standard library (`crypto/tls`, `crypto/ecdh`, `net`), `gopkg.in/yaml.v3` (already in go.mod), no new module; containerlab and the existing `tests/lab` harness on beehive for the lab tier; GitHub Actions for the mock tier.

**Spec:**
- `docs/design/2026-08-23-policy-engine-spec.md`:
  - §15, the lab register: every device claim a mock makes cites a row and a results note;
  - §5.7, the decision-log records the generator reads;
  - §13 decision 52, written by Task 1, and decision 48 ruling 4, made provisional on L78 by Task 1.
- `docs/design/2026-08-21-port49-design.md` §14, the testing strategy: "nothing about device behavior is asserted elsewhere without citing an entry".
- The roadmap brief: `docs/superpowers/plans/README.md`, "Plan 11b".

**Revision 1 (2026-10-19)** applies the pre-flight review (`.superpowers/sdd/qual-suite/preflight.md`: 5 Critical, 14 Important, 14 Minor) and the team lead's rulings on Q1 and Q2. **Revision 2** applies re-review 1 (1 Critical, 6 Important, 8 Minor):
- 12-character commits;
- notediff compares integers exactly;
- `tls_*` scenarios chosen by transport;
- two lab-free invocations;
- no tagged darwin vet;
- the guard test's want map;
- fleet tokens minted on the test goroutine;
- the L79 minors.

**Revision 3** applies re-review 2 (I-G and 6 Minor):
- goldens built from an explicit cell → scenario map, with `PlayedSteps` shared by `Play` and genprofile;
- the TLS cell runs the full sequence;
- `tls_unknown_ca` taken from its `tls.json` and `flight_delay` from `tls_token_login`, plus an eight-scenario fixture test;
- `run` JSON tags;
- notediff durations only with a unit, ranges included;
- the fleet reload waited for;
- the account port taken from the login's own records;
- `qualDaemon` keyed on `o.transport`.

**Revision 4** applies re-review 3 (2 Important, 1 Minor):
- `tls_unknown_ca` plays its login and records the class event `tls_refused`, since the handshake succeeds client-side and the alert races a reset;
- a received alert is read from `*net.OpError` "remote error";
- port49's `tls_refused` record is required and kept outcome-only;
- `single_connection` runs the full sequence;
- only the minted user is templated, so the login's own records are picked.

## Global Constraints

- **Toolchain.** Go 1.26+, module `github.com/rhwendt/port49`; `gofmt` and `go vet` clean; no cgo; no new module.
- **snake_case** for every data key: profile YAML, golden JSON, evidence JSON, manifest YAML, metric names.
- **Reason codes** come only from spec §5.7 (`internal/decision/reasons.go`). This plan adds none.
- **Metrics:** no device identity in a metric label. Fleet mode adds no metric.
- **Mocks are never built by decoding TACACS+ bodies from captures.** No `tshark -x`/`-V`, no `tcpdump -X`/`-A`, and no body decode in Go. The only sources are:
  - the decision log's validated request records;
  - the `*.tls.json` handshake summaries;
  - the 12-byte headers (`l73PlainHeaders`);
  - the connection timing (`l73Conns`).
- **Credentials and tokens are minted fresh in each test**, through the broker's mint path, and never replayed from evidence.
- **No credential material in any output.** No credential, token, password, TOTP code, `token_sha256`, `credential_sha256` value or private key appears in a profile, a golden, an evidence file the generator reads, test output or a failure message. Certificates are generated per test, so no `cert_sha256` is ever a fixture.
- **Files never read:** `/tmp/port49-lab-tokens.jsonl`, `*.env`, `*-key.pem`, `*.keytab`, `secrets.json`, and the passwords in realm.json.
- **Lab logs** are read only through `grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g'`.
- **Vendor images** (cEOS, NX-OS, IOS XE, vJunos, XRd, IOL) **never** run on a hosted runner: that would be redistribution. A freely redistributable image (SR Linux) may.
- **Runners.** Every workflow's `runs-on` is one line, so moving between hosted and self-hosted (beehive) is a one-line change. The mock tier needs no special runner: no Docker, no KVM, no captures.
- **Darwin.** CI runs `make check-darwin`. Any Linux-only helper (binding 127.0.1.x, descriptor passing, `syscall.Flock`) lives in a `_linux_test.go` or `_linux.go` file.
- **The lab is single-occupant.** Hold `flock /tmp/port49-lab.lock` for the whole run. Check the STOP sentinel `/tmp/port49-STOP-LAB` before every entry and every cell. A new lab test (`TestQualify`, `TestL78`) copies `TestL76`'s prologue (`tests/lab/l76_test.go:23-45`) and is opt-in.
- **Real-lab cadence.** The real lab tier runs before pre-beta and release tags and on any vendor image change, about monthly. It is **not** nightly.
- **Commits.** Conventional Commits, ending `Co-Authored-By: Claude <model name> <noreply@anthropic.com>`, with `<model name>` filled in by the implementing model. No session line and no claude.ai link.
- **Verification.** Verify with `make test && make vet` (on beehive, where the labpcap audit's captures are) before each task's commit, and report the real output.

## Design notes

### Credit

Ryan's idea came from **cisshgo** (https://github.com/tbotnz/cisshgo, MIT), a Go SSH server that imitates Cisco devices. Its platform behaviour is data (transcript files mapped by YAML), and it runs 50 simulated devices on consecutive ports at once.

port49 takes two ideas from it: **behaviour is data, not code**, and **fleet mode**. The direction is reversed: cisshgo is the device's SSH server for an automation client, and port49's mock is the device acting as a **TACACS+ client** of port49d. No cisshgo code is copied.

### The profile's three parts (Ryan, 2026-10-19)

A transcript alone is not enough. A device branches on port49's replies, and the worst production failures are a device rejecting port49's output. So each profile, `tests/qual/profiles/<platform>/<firmware_slug>.yaml`, has three parts.

1. **Stimulus** (data, generated from evidence). What the device sends no matter how port49 replies:
   - the ClientHello;
   - the flight delay;
   - the connection pattern;
   - each step's packet fields and attribute list;
   - the accounting records.
2. **Reaction table** (data, reviewed by hand, pre-filled by the generator). On each reply status or TLS alert, the next action and what the operator sees. Examples:
   - GETPASS → `send_credential`;
   - FAIL → `stop`;
   - ERROR → the measured fallback (IOS XE 17.18.02 over TLS: break-glass fails);
   - `alert_unknown_ca` → `give_up`;
   - a reply with the single-connect flag → `reuse_connection`.
3. **Acceptance rules** (data, reviewed by hand). Constraints the device enforces on port49's replies: attribute and reply byte limits, the privilege range, the role names it honours, the attribute names it refuses.
   - **A measured claim cites a results note whose `Image version:` line names this profile's firmware** (decision 52 ruling 4).
   - A claim measured only on another firmware is `unmeasured` here until a conformance run re-measures it.
   - An unmeasured rule may cite any note, as the one that left it open. It is printed as a warning and never fails the suite (CLAUDE.md, lab register rule 1).

**The code escape hatch.** Go is written only when a device does something these three parts cannot express. Each case is listed in the profile's `engine_gaps`, naming the Go file that covers it, so the engine's gaps stay visible.

### One policy, one fragment, one mint path (C1)

A golden made from the lab must be the mock's expectation. Three things guarantee it.

- **One policy.** `tests/qual/qual-policy.yaml` is the broker's `policy_file` in both the lab conformance run and the mock.
- **One fragment.** `tests/qual/qual-daemon.yaml` holds every daemon key that shapes a reply, and nothing else. Both configs merge it with `devicemock.MergeFragment`, and a test in each tier asserts the merged keys are byte-identical.
- **One mint path.** Every token is minted by the broker for subject `qual_operator`: in the lab through `port49 login` and `port49 token` (the slice's path, `tests/lab/slice_test.go:110-125`), and in the mock through `POST /v1/tokens` (`internal/port49d/run_test.go`'s `mint`). A context the broker minted carries a blob, so it is answered by the policy engine. The lab's `lab:` instrument answers only blob-less seed contexts (`internal/port49d/main.go:983-1000`).
  - The conformance config still drops `session_attributes`, `command_attributes`, `deny_prefixes` and the seeds from its `lab:` block, keeping only `fault_file`. A seed login therefore cannot answer at all.
  - The run refuses evidence holding a `redeem` with `auth.method: lab`.

### What the mock asserts, and what it cannot

The engine plays the stimulus against a real port49d (`internal/port49d`'s `run`) and asserts the following.

**The ClientHello parameters**, in two phases, because `crypto/tls` cannot reproduce a device's suite order, signature algorithms, x448 group or an IP-literal SNI.
- **The hello probe** writes the device's exact ClientHello, built byte by byte from the profile with a fresh random and a fresh key share. It reads port49's ServerHello and checks the version, the suite and any HelloRetryRequest against what port49 answered the real device. Extension 27 (compress_certificate, sent by cEOS) has a builder fed from the algorithms the TLS summary now records (I3).
- **The session phase** runs the TACACS+ exchange over `crypto/tls`, configured as close to the device as the standard library allows: versions, curve order, ALPN, the client chain, and SNI unless it is an IP literal.
- The probe abandons its handshake, which port49 strikes, so it runs on a daemon of its own.
- Rejected: uTLS. It is a new module, and the probe already gives byte-exact fidelity where it matters: the server's choice given the offer.

**The flight timing.** The device's measured wait between port49's server flight and its own reply (NX-OS 10.6(2)F: exactly 5.00 s) is played by a connection wrapper that delays the first write after a read.
- Per PR, every delay is scaled by 0.1 and port49d runs at `handshake_timeout: 1s`. That is the production default of 10 s scaled the same way, so the delay-to-timeout ratio is production's.
- The `flight_delay` scenario plays the **login step** on the delayed connection. It then asserts from port49's decision log that the device was served (a `redeem` over TLS, no TLS refusal record), not merely that the client finished writing its Finished (I2).
- One test runs the real 5.00 s against the real 10 s default. One runs a delay past the timeout and expects `handshake_timeout`.

**The connection pattern.** One connection per TACACS+ step (NX-OS: five per login), or single-connection with the measured reuse.

**The packet fields and request attribute lists**, from the decision log's validated request records:
- `packet_fields`, added by Task 5;
- `request.raw`;
- the header's version byte, from the 12-byte header summary (M4).

Only lab-specific values are made templates: `{user}`, `{rem_addr}`, `{task_id}`, `{start_time}`, `{stop_time}`.

**The accounting records** (`record.raw`), templated the same way.

**The failure cases the notes recorded:**
- an ERROR reply (the store down, through `lab.fault_file`);
- a wrong credential;
- an unknown CA at the handshake;
- a delay past `handshake_timeout`.

### Goldens, and why a reply change does not need the lab before merge

port49's replies to each scenario are pinned in `tests/qual/golden/<platform>/<firmware_slug>.json`. Their one format and one reader/writer are `internal/devicemock/golden.go` (I6). The generator writes the first golden from the lab run.

An intentional port49 change rewrites the golden with `make qual-update`, followed by a reviewed diff. A rewritten golden is marked `"pending_lab": true`. The qualified-platforms list shows it as `re-vet pending`, and the release-tag gate's lab run clears it (decision 52 ruling 6).

The acceptance rules gate every PR regardless: they are the device's truth, and a golden is only port49's.

### Fleet mode

`devicemock.Fleet` runs N engines at once against one port49d with N inventory devices. Each engine dials from its own loopback address (127.0.1.1, 127.0.1.2, …), which Linux routes with no set-up. It tests many concurrent logins, a reload under load, and the store going down under load.

It is its own tier (`make qual-fleet`), not on the per-PR path. Plan 12's load validation at the §5 target rate uses it.

### Not built: an SSH front (later work)

cisshgo's SSH server would let a test drive ssh → mock device → TACACS+. It is not worth building now:
- the mock's SSH CLI would be invented behaviour, not measured;
- what a device sends to TACACS+ on an SSH login is already the stimulus;
- the operator's ssh-to-device path is measured on real devices (L54, L64).

It is listed in the roadmap's "leaves for later".

### The tiers

| Tier | Runs | Where | Needs |
|---|---|---|---|
| Mock (`make qual`) | every PR | any runner (`qual.yml`) | Go only |
| Fleet (`make qual-fleet`) | by hand; plan 12's load test | Linux | Go only |
| Free image (`lab-free.yml`) | manual dispatch and release tags (Q1, ruled) | hosted or beehive; prerequisites proven first | Docker, containerlab, tcpdump, sudo, SR Linux |
| Real lab (`make lab-regress`, `make qual-vet`) | pre-beta, release tags, any vendor image change (~monthly) | beehive only | the vendor images, the lab lock |

### Rulings on the writer's questions (team lead, 2026-10-19)

- **Q1.** The SR Linux job runs on manual dispatch and release tags only. Path-filtered PRs come later, once the runner is beehive or the repository is public. That later move is a one-line trigger change (Task 20).
- **Q2.** If L78 sees no lockout on vJunos:
  - the Junos `junos_reply_total` rule stays **unmeasured** (not deleted);
  - decision 48's 255-byte budget stays;
  - decision 48 ruling 4 is marked *provisional on L78*;
  - L78 stays open for hardware Junos.

  Ryan's production experience on real Junos outranks a VM's silence until hardware is measured (CLAUDE.md, "About Ryan").

## Review Focus

1. **A credential echoed back.** A fake server that puts the presented token into `server_msg` or `data` must not get it into a transcript, a golden, a failure message or `-v` output. The daemon's decision log must not reach failure output either: it holds hashes. Pinned by Task 9's `TestTranscriptNeverHoldsTheCredential`, Task 10's `TestQualWaitForPrintsNoHash` and Task 13's `TestGenerateRefusesForbiddenKeys`.
2. **A scaled delay that hides a real timeout, or a client-side "ok" that hides a refusal.** Task 10's two timing tests judge from port49's decision log, at the real numbers and past the timeout.
3. **An unmeasured acceptance rule failing the suite, or a gate that never reaches a test failure.** Task 7 pins `Check`. Task 9's `Judge` and its unit test pin the path from gate to failure. Task 10 proves a violation fails against a real port49d, and that the same policy passes a profile without the rule.
4. **The lab lock between the runner and its children.** The runner builds the lab test binary once and passes the held descriptor straight to it, with no `go test` hop. A positive re-exec test proves the adoption (Task 2). A STOP sentinel stops the next entry, never a running cell.
5. **A profile citing evidence that does not back it.** This covers a missing note, a measured claim citing another firmware's note, and credential-shaped keys or values. Task 6's loader refuses each one, and loads a profile that uses the whole reaction vocabulary.

---

## File structure

**Created**

`internal/devicemock/`:
- `profile.go`: types, `Load`, `Validate`, `Slug`, the wire codes.
- `forbidden.go`: the key- and value-shaped credential check.
- `accept.go`: the acceptance checker.
- `react.go`: the reaction table.
- `hello.go`: the ClientHello builder and the ServerHello reader.
- `tlsconf.go`: the session `tls.Config` and the flight-delay conn.
- `engine.go`: `Play`, the scenarios, the transcript.
- `golden.go`: `Golden`, `LoadGolden`, `WriteGolden`, `GoldenFrom`, `Judge`.
- `fragment.go`: `MergeFragment`.
- `fleet.go`: `Fleet`.
- `*_test.go` and `testdata/`: unit tests, fixture profiles and notes, a fake TACACS+ server.

`internal/port49d/`:
- `qual_test.go`: `TestQual` and its helpers.
- `qual_fleet_linux_test.go`: `TestQualFleet`.

`tests/qual/`:
- `qual-policy.yaml`;
- `qual-daemon.yaml`: the shared daemon fragment;
- `profiles/`, `golden/`;
- `cmd/genprofile/`, `cmd/qualified/`;
- `vet.sh`, `README.md`.

`tests/lab/`:
- `regress.yaml`;
- `cmd/lab-regress/`;
- `cmd/notediff/`;
- `occupancy_linux.go`, `occupancy_other.go`, `occupancy_linux_unit_test.go`;
- `qual_evidence.go`: the whitelist, `qualConfig`, the cell table (untagged, pure);
- `qual_evidence_unit_test.go`;
- `qualify_test.go`: `TestQualify` (tag `lab`);
- `l78.go`, `l78_unit_test.go`, `l78_test.go`.

`.github/workflows/qual.yml`, `.github/workflows/lab-free.yml`.

`docs/qualified-platforms.md` (generated).

**Modified**
- `internal/decision/log.go` and a new `internal/decision/packet.go`.
- `internal/daemon/authen/authen.go:225` (`newRecord`, which covers `redeem` and `escalate`).
- `internal/daemon/author/author.go:244` (`authorize_command` and `authorize_session`).
- `internal/daemon/acct/acct.go:142`.
- `docs/design/2026-08-23-policy-engine-spec.md`: §5.7; §13 decisions 48 and 52; §15 L73, L74, L78, L79.
- `tests/lab/occupancy.go`: `labOccupyForRun` adopts an inherited lock.
- `tests/lab/l73_tlswire.go`: `l73Plain.Version` and `l73Hello.CompressCertAlgs`.
- `tests/lab/l73_dialect.go`, `tests/lab/harness_test.go`: the XR dialect.
- `tests/lab/l76_cells.go`: R3-M1.
- `tests/lab/l74_test.go`, `tests/lab/regions_test.go`: the L79 cells.
- `Makefile`, `tests/lab/README.md`, `docs/superpowers/plans/README.md`.

---

### Task 1: Spec — decision 52, `packet_fields`, L78 and L79, decision 48 made provisional

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§5.7, after the paragraph documenting `request.service`; §13 decision 48 ruling 4; §13 after decision 51; §15)

**Interfaces:**
- Produces:
  - decision 52's rulings 1–10, cited by every later task;
  - the `packet_fields` record object (Task 5);
  - register rows **L78** (Task 15) and **L79** (Task 17).

  L77 is earmarked for SONiC in the lab queue. Take L78 and L79 even if L77 is not yet in §15.

- [ ] **Step 1: Check the event vocabulary against the code** before writing it.

Run: `grep -n 'Event[A-Za-z]* *= "' internal/decision/reasons.go`
Expected: `redeem`, `authorize_session`, `authorize_command`, `escalate` and `account`, among the others. There is no `authenticate`. The text below names only events that exist.

- [ ] **Step 2: Write decision 52** after decision 51, in the existing decisions' voice:

```markdown
**52. The qualification suite: mock devices from closed evidence, the lab for vetting (plan 11b;
Ryan, 2026-10-17 and 2026-10-19).**

- **1. A mock is data.** Each vetted platform and firmware is one profile in three parts: stimulus
  (generated from evidence), reactions and acceptance rules (reviewed by hand at vetting). One
  engine, `internal/devicemock`, plays every profile; Go is written only for what a profile cannot
  say, and each such case is listed in the profile's `engine_gaps`. Credit: cisshgo (MIT).
- **2. Evidence, never bodies.** A profile is generated from the decision log's validated request
  records, the `*.tls.json` handshake summaries, the 12-byte headers and the connection timing.
  No TACACS+ body is decoded from a capture. Credentials are minted fresh per test.
- **3. `packet_fields`.** The `redeem`, `escalate`, `authorize_session`, `authorize_command` and
  `account` records carry the request's header fields as names: `action` (authentication only),
  `authen_type`, `service`, `authen_method` (authorization and accounting only) and `priv_lvl`. No
  user, port, address, data or argument: those are recorded where they already were, or never.
- **4. A device claim in a profile cites a results note.** A `measured` claim cites a note whose
  `Image version:` line names the profile's firmware. A claim measured on another firmware is
  `unmeasured` on this one until a conformance run re-measures it. An `unmeasured` claim may cite
  any note, as the one that left it open; it is printed and never gates (§15 rule 1).
- **5. One policy, one fragment, one mint path.** `tests/qual/qual-policy.yaml` is the broker's
  policy, `tests/qual/qual-daemon.yaml` every reply-shaping daemon key, and the broker's mint the
  only token source, in every conformance run and every mock run, so a golden from the lab is the
  mock's expectation.
- **6. Goldens.** port49's replies are pinned per profile; a reviewed `make qual-update` may change
  them in a PR, marking the golden `pending_lab`, shown as re-vet pending in the qualified-platforms
  list until the next lab run clears it. Acceptance rules gate every PR.
- **7. The tiers.** Mocks on every PR on any runner. The real lab before pre-beta and release tags
  and on any vendor image change, roughly monthly, not nightly. Vendor images never on a hosted
  runner; a freely redistributable image (SR Linux) may, on manual dispatch and release tags.
- **8. A new firmware gets its mock only after the lab vets it** (`make qual-vet`).
- **9. Time scale.** Per PR, device delays run at 0.1 against `handshake_timeout: 1s`, production's
  ratio; one test runs the real delay against the real default.
- **10. A conformance run re-measures rows, open or closed, and closes none.** It cites the rows each
  cell re-measures; a row closes only as §15 says.
```

- [ ] **Step 3: Make decision 48 ruling 4 provisional on L78** (I9). Ruling 4 ("The budget", search `Ryan's production experience that over 255 bytes locks the user`) rests on the prior L78 measures. Add to the end of ruling 4:

```markdown
  *Provisional on L78*: the lock-out above 255 bytes is Ryan's production experience on hardware
  Junos, unmeasured in the lab; the budget stays until hardware Junos is measured, whatever a
  VM shows (decision 52; plan 11b).
```

- [ ] **Step 3b: Make decision 51's lift wording provisional on L79** (rule 2). Find the decision 51 ruling that gives the operator text for a lift during a cut ("could not be lifted, and stands"; search `could not be lifted` in §13). Add to that ruling:

```markdown
  *Provisional on L79*: whether a lift reported as standing can still land after the heal, through
  the kernel's retransmission of the cut connection, is unmeasured (11a final review, dial-fix M4).
```

  If the search finds the wording only in the roadmap and the code, not in §13, add the same sentence to decision 51's text on revocation during a cut, and note in the commit message where it was put.

- [ ] **Step 4: Document `packet_fields` in §5.7** (I8). §5.7 documents record fields in prose, not in a table. After the paragraph that documents `request.service` (search `"service" AV pair`), add a paragraph:

```markdown
**`packet_fields`** is on the `redeem`, `escalate`, `authorize_session`, `authorize_command` and
`account` records: the validated request's header fields as names, never as numbers.
- `action` is on authentication only: `login`, `chpass`, `sendauth`.
- `authen_type` is `not_set`, `ascii`, `pap`, `chap`, `mschap` or `mschapv2`.
- `service` is `none`, `login`, `enable`, `ppp`, `pt`, `rcmd`, `x25`, `nasi` or `fwproxy`.
- `authen_method` is on authorization and accounting only: `not_set`, `none`, `krb5`, `line`,
  `enable`, `local`, `tacacsplus`, `guest`, `radius`, `krb4` or `rcmd`.
- `priv_lvl` is 0–15.

A value outside its list is recorded as `unknown_<n>`. The object carries no user, port, address,
data or argument, and an `unvalidated` record never carries it (decision 52 ruling 3).
```

- [ ] **Step 5: Add rows L78 and L79 to §15**, after L76:

```markdown
| **L78** | Whether Junos locks a user out when a *permit* session reply totals more than 255 bytes with every attribute at most 255 (port49 never sends one attribute over 255: §6, "Length"): the total at which the login is refused or the user locked out, if any, and whether break-glass still logs in. L2's run sent a long *deny* `server_msg` only, and neither confirms nor refutes this prior (`tests/lab/results/L2-juniper_vjunos-router.md`, "Break-glass around long session denials"). | §13 decision 48 ruling 4's budget (provisional on this row); the Junos profiles' `max_reply_bytes` acceptance rule (decision 52 ruling 4) | Junos: vJunos-router 23.4R2-S2.1 and 26.2R1.7, then hardware Junos | open — added 2026-10-19 by plan 11b. Ryan's production prior from hardware Junos (a reply over 255 bytes locked the user out) is unmeasured; a VM showing no lockout leaves the row open for hardware |
| **L79** | Whether a directory write sent from a region whose link is cut (iptables DROP, so the kernel keeps retransmitting) is delivered after the link heals within the retransmission window: (j) a lift reported "could not be lifted, and stands" that lands later; (k) a revoke reported failed that lands after an operator's lift elsewhere (expected fail-closed: the mark re-created). What `port49 store status` and the decision log say in each case. | §13 decision 51 (11a's final review, dial-fix M4); the operator text of `port49 revoke --lift` | three simulated regions (L74's harness, etcd 3.6.15) | open — added 2026-10-19 by plan 11b, carried from 11a |
```

- [ ] **Step 6: Check the edits**

Run: `grep -n '^\*\*52\.' docs/design/2026-08-23-policy-engine-spec.md && grep -c '^| \*\*L7[89]\*\*' docs/design/2026-08-23-policy-engine-spec.md && grep -c 'Provisional on L7[89]' docs/design/2026-08-23-policy-engine-spec.md && grep -c 'authenticate`' docs/design/2026-08-23-policy-engine-spec.md`
Expected: one line for decision 52, then `2`, then `2`, then `0`.

- [ ] **Step 7: Commit**

```bash
git add docs/design/2026-08-23-policy-engine-spec.md
git commit -m "docs: decision 52, packet_fields, L78 and L79; decision 48 ruling 4 provisional on L78

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 2: `make lab-regress`, the runner and its lock

**Files:**
- Create: `tests/lab/regress.yaml`
- Create: `tests/lab/cmd/lab-regress/main.go`, `manifest.go`, `manifest_test.go`, `lock_linux.go`, `lock_other.go`
- Create: `tests/lab/occupancy_linux.go`, `tests/lab/occupancy_other.go`, `tests/lab/occupancy_linux_unit_test.go`
- Modify: `tests/lab/occupancy.go` (`labOccupyForRun`), `Makefile`

**Interfaces:**
- Produces:
  - `type Entry struct { ID, Target, Run, Platforms string; Rows []string; Env map[string]string; Notes []string; MeasuredMinutes int }`, with YAML keys `id`, `target`, `run`, `platforms`, `rows`, `env`, `notes`, `measured_minutes`;
  - `func loadManifest(path, spec string) ([]Entry, error)`: refuses an entry whose `rows` include a closed row that its `PORT49_LAB_REMEASURE` does not name;
  - `func patternMatches(run string, tests []string) (matched, unmatchedAlternatives []string)`;
  - env `PORT49_LAB_LOCK_FD`: the descriptor number of an already-held lock;
  - `func labInheritedLock(path string) (release func(), ok bool, err error)` in `tests/lab`.

**How the lock is handed over.**
- The runner holds `/tmp/port49-lab.lock` for the whole run.
- It builds the lab test binary **once** (`go test -c -tags lab -o <tmp>/lab.test ./tests/lab/`).
- It runs that binary directly for each entry, with the lock as `ExtraFiles[0]` (fd 3). There is no `go test` process between them to drop or keep the descriptor (I4).
- The binary runs from `tests/lab/` as its working directory, as `go test` would run it.
- The child's `labOccupyForRun` sees `PORT49_LAB_LOCK_FD` and checks that the descriptor is the lock file (same device and inode) and is held. It opens nothing new.

- [ ] **Step 1: Write the manifest.** It lists **closed** rows only: lab-regress reruns closed entries, so every entry's `env` names its rows in `PORT49_LAB_REMEASURE`. Every `run` pattern is anchored and names tests exactly. The guard's entry names are the strings the tests pass to `l.capture` and `l.result` (`grep -n 'capture(t, "L\|result(t, "L' tests/lab/*.go`). Start with these entries, which are verified against the code:

```yaml
# The closed lab entries `make lab-regress` reruns (plan 11b, decision 52 ruling 7).
# One entry per harness run. run: an anchored go test -run pattern naming tests exactly
# (TestEveryManifestPatternMatchesATest checks it). rows: the §15 rows it re-measures;
# for a closed row env.PORT49_LAB_REMEASURE names its guard entry (loadManifest refuses
# otherwise). notes: every results note it rewrites, every platform's.
# measured_minutes: the last full run's wall time for the entry (Task 4).
entries:
  - id: L10
    run: '^TestL10ServiceAndAttributeSpellings$'
    platforms: eos,vjunos,vsrx,nxos,iosxe
    rows: [L10]
    env: {PORT49_LAB_REMEASURE: L10}
    notes: [tests/lab/results/L10-arista_eos.md, tests/lab/results/L10-cisco_iosxe.md, tests/lab/results/L10-cisco_nxos.md,
            tests/lab/results/L10-juniper_vjunos-router.md, tests/lab/results/L10-juniper_vsrx.md]
  - {id: L73-vjunos26, run: '^TestL73$', platforms: vjunos26, rows: [L73], env: {PORT49_LAB_REMEASURE: L73},
     notes: [tests/lab/results/L73-juniper_vjunos-router.md]}
  - {id: L73-iosxe1718, run: '^TestL73$', platforms: iosxe1718, rows: [L73], env: {PORT49_LAB_REMEASURE: L73},
     notes: [tests/lab/results/L73-cisco_iosxe.md]}
  - {id: L73-nxos106, run: '^TestL73$', platforms: nxos106, rows: [L73], env: {PORT49_LAB_REMEASURE: L73},
     notes: [tests/lab/results/L73-cisco_nxos.md]}
  - {id: L73-ceos436, run: '^TestL73$', platforms: ceos436, rows: [L73], env: {PORT49_LAB_REMEASURE: L73},
     notes: [tests/lab/results/L73-arista_ceos.md]}
  - {id: L76-srlinux, run: '^TestL76$', platforms: srlinux, rows: [L76], env: {PORT49_LAB_REMEASURE: L76},
     notes: [tests/lab/results/L76-nokia_srlinux.md]}
  - {id: L74-L75, target: lab-regions, run: '^TestRegions$', rows: [L74, L75], env: {PORT49_LAB_REMEASURE: "L74,L75"},
     notes: [tests/lab/results/L74-regions.md, tests/lab/results/L75-regions.md]}
```

Then add every other closed row that has a harness test. Read each closed row in §15 (`grep '^| \*\*L' … | grep '| closed'`), find its test (`grep -n 'capture(t, "L<N>' tests/lab/*.go`), and add an entry in the same shape. The unit tests in Step 2 refuse a wrong pattern or a missing `REMEASURE`.

- [ ] **Step 2: Write the failing tests** (`tests/lab/cmd/lab-regress/manifest_test.go`):

```go
package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const specPath = "../../../../docs/design/2026-08-23-policy-engine-spec.md"

func TestLoadManifestRefusesAnUnknownKey(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.yaml")
	os.WriteFile(p, []byte("entries:\n  - {id: L10, run: x, notez: []}\n"), 0o600)
	if _, err := loadManifest(p, specPath); err == nil || !strings.Contains(err.Error(), "notez") {
		t.Fatalf("an unknown key must be refused by name: %v", err)
	}
}

func TestLoadManifestRefusesAClosedRowWithoutRemeasure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "m.yaml")
	os.WriteFile(p, []byte("entries:\n  - {id: L10, run: '^TestL10ServiceAndAttributeSpellings$', rows: [L10]}\n"), 0o600)
	if _, err := loadManifest(p, specPath); err == nil || !strings.Contains(err.Error(), "PORT49_LAB_REMEASURE") {
		t.Fatalf("a closed row with no PORT49_LAB_REMEASURE fails at guardClosed; refuse it here: %v", err)
	}
}

func TestTheCommittedManifestLoads(t *testing.T) {
	if _, err := loadManifest("../../regress.yaml", specPath); err != nil {
		t.Fatal(err)
	}
}

// Every alternative of every pattern names at least one test, and no
// pattern matches a test its alternatives do not name exactly.
func TestEveryManifestPatternMatchesATest(t *testing.T) {
	entries, err := loadManifest("../../regress.yaml", specPath)
	if err != nil {
		t.Fatal(err)
	}
	var tests []string
	files, _ := filepath.Glob("../../*.go")
	re := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]*)\(`)
	for _, f := range files {
		b, _ := os.ReadFile(f)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			tests = append(tests, m[1])
		}
	}
	for _, e := range entries {
		matched, empty := patternMatches(e.Run, tests)
		if len(empty) > 0 {
			t.Errorf("%s: alternative(s) %v match no test", e.ID, empty)
		}
		for _, m := range matched {
			if !strings.Contains(e.Run, m) {
				t.Errorf("%s: %q also matches %s, which it does not name", e.ID, e.Run, m)
			}
		}
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
	t.Setenv("PORT49_LAB_TOKEN_DUMP", "x")
	env := childEnv(Entry{Platforms: "eos", Env: map[string]string{"PORT49_LAB_REMEASURE": "L10"}}, 3)
	joined := strings.Join(env, "\n")
	for _, want := range []string{"PORT49_LAB_LOCK_FD=3", "PORT49_LAB_PLATFORMS=eos", "PORT49_LAB_REMEASURE=L10"} {
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
Expected: FAIL (`undefined: loadManifest`, `patternMatches`, `runner`, `childEnv`).

- [ ] **Step 4: Implement `manifest.go`**

```go
package main

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

type Entry struct {
	ID              string            `yaml:"id"`
	Target          string            `yaml:"target"`
	Run             string            `yaml:"run"`
	Platforms       string            `yaml:"platforms"`
	Rows            []string          `yaml:"rows"`
	Env             map[string]string `yaml:"env"`
	Notes           []string          `yaml:"notes"`
	MeasuredMinutes int               `yaml:"measured_minutes"`
}

func loadManifest(path, spec string) ([]Entry, error) {
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
	specText, err := os.ReadFile(spec)
	if err != nil {
		return nil, err
	}
	for _, e := range m.Entries {
		names := strings.Split(e.Env["PORT49_LAB_REMEASURE"], ",")
		for _, row := range e.Rows {
			if !rowClosed(string(specText), row) {
				continue
			}
			if !slices.ContainsFunc(names, func(n string) bool { return n == row || strings.HasPrefix(n, row+"-") }) {
				return nil, fmt.Errorf("%s: row %s is closed, so env.PORT49_LAB_REMEASURE must name it "+
					"(tests/lab guardClosed refuses the run otherwise)", e.ID, row)
			}
		}
	}
	return m.Entries, nil
}

// rowClosed is tests/lab's registerRowClosed (harness_test.go:3371), which a
// command cannot import from a test file: the row's last cell starts "closed".
func rowClosed(spec, id string) bool {
	for _, ln := range strings.Split(spec, "\n") {
		if strings.HasPrefix(ln, "| **"+id+"** |") {
			cells := strings.Split(ln, "|")
			return len(cells) >= 3 && strings.HasPrefix(strings.TrimSpace(cells[len(cells)-2]), "closed")
		}
	}
	return false
}

// patternMatches reports the tests run matches, and the alternatives of an
// anchored ^(a|b)$ or ^a$ pattern that match none.
func patternMatches(run string, tests []string) (matched, unmatched []string) {
	re := regexp.MustCompile(run)
	for _, t := range tests {
		if re.MatchString(t) {
			matched = append(matched, t)
		}
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(run, "^"), "$")
	inner = strings.TrimSuffix(strings.TrimPrefix(inner, "("), ")")
	for _, alt := range strings.Split(inner, "|") {
		if !slices.Contains(tests, alt) {
			unmatched = append(unmatched, alt)
		}
	}
	return matched, unmatched
}
```

- [ ] **Step 5: Implement `main.go`**

```go
// Command lab-regress reruns the closed lab entries in tests/lab/regress.yaml on
// the lab host, under one held lab lock, and diffs each rewritten results note
// against HEAD (plan 11b; spec §13 decision 52 ruling 7).
package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	lockPath = "/tmp/port49-lab.lock"
	stopPath = "/tmp/port49-STOP-LAB"
	specPath = "docs/design/2026-08-23-policy-engine-spec.md"
)

type report struct {
	Done            []string
	Minutes         map[string]float64
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

// childEnv is the caller's environment, less any variable whose name holds
// TOKEN, SECRET or PASSWORD (L27_TOKEN among them: no manifest entry needs one,
// and an entry that did would name it in env), plus the held lock's
// descriptor and the entry's own settings.
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
	dry := flag.Bool("dry-run", false, "list the entries and their last measured minutes; run nothing")
	flag.Parse()
	entries, err := loadManifest(*manifest, specPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	entries = pick(entries, *only)
	if *dry {
		total := 0
		for _, e := range entries {
			fmt.Printf("%-16s %-28s %4d min  %s\n", e.ID, e.Platforms, e.MeasuredMinutes, e.Run)
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
	bin := filepath.Join(os.TempDir(), fmt.Sprintf("port49-lab-regress-%d.test", os.Getpid()))
	defer os.Remove(bin)
	if out, err := exec.Command("go", "test", "-c", "-tags", "lab", "-o", bin, "./tests/lab/").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "building the lab test binary: %v\n%s", err, out)
		os.Exit(1)
	}
	r := &runner{stopPath: stopPath, exec: func(e Entry) error {
		fmt.Printf("=== lab-regress %s ===\n", e.ID)
		cmd := exec.Command(bin, "-test.run", e.Run, "-test.count=1", "-test.v", "-test.timeout", "300m")
		cmd.Dir = "tests/lab" // as go test runs a package's binary
		cmd.Env = childEnv(e, 3)
		cmd.ExtraFiles = []*os.File{lock} // fd 3, straight into the test binary
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

// diffNotes reports each rewritten note's changed observations (Task 3). It
// reports and never fails: the lab is the truth, and a change is for a person
// to read (CLAUDE.md, lab register rule 4).
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
	fmt.Printf("lab-regress: %d entries done in %.1f min", len(rep.Done), total)
	if rep.Stopped != "" {
		fmt.Printf("; stopped by %s before %s", stopPath, rep.Stopped)
	}
	if rep.Failed != "" {
		fmt.Printf("; %s FAILED, the entries after it were not run", rep.Failed)
	}
	fmt.Println()
}
```

The `TestRegions` entry (`target: lab-regions`) runs through the same binary: `make lab-regions` is the same `go test -tags lab ./tests/lab/ -run '^TestRegions$'`.

`lock_linux.go` (`//go:build linux`):

```go
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

// holdLock takes path exclusively and without waiting, as tests/lab's
// labOccupy does, writes who into it, and returns the open file: its
// descriptor is each child's fd 3.
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

`lock_other.go` (`//go:build !linux`):

```go
package main

import (
	"errors"
	"os"
)

func holdLock(string, string) (*os.File, error) {
	return nil, errors.New("lab-regress runs on the Linux lab host only")
}
```

- [ ] **Step 6: The child adopts the inherited lock.** `tests/lab/occupancy_linux.go` (`//go:build linux`):

```go
package lab

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// labInheritedLock adopts the lock a parent (lab-regress) holds on path and
// passed as PORT49_LAB_LOCK_FD; ok is false when the variable is unset. The
// descriptor must be path itself (same device and inode). Flock with LOCK_NB
// on the same open file description succeeds when the parent holds it; on a
// description nobody holds it takes the lock instead, which is just as safe:
// either way this process now holds the lab, and a third process is refused.
func labInheritedLock(path string) (release func(), ok bool, err error) {
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
	if err := syscall.Stat(path, &want); err != nil || have.Dev != want.Dev || have.Ino != want.Ino {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d is not %s", fd, path)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, true, fmt.Errorf("PORT49_LAB_LOCK_FD %d is not held: %v", fd, err)
	}
	return func() {}, true, nil // the parent releases it
}
```

`tests/lab/occupancy_other.go` (`//go:build !linux`):

```go
package lab

func labInheritedLock(string) (func(), bool, error) { return nil, false, nil }
```

In `labOccupyForRun` (`tests/lab/occupancy.go`), before `labOccupy`:

```go
	if release, ok, err := labInheritedLock(path); ok {
		if err != nil {
			return err
		}
		labHeld = release
		return nil
	}
```

- [ ] **Step 7: The positive and negative adoption tests**, in `tests/lab/occupancy_linux_unit_test.go` (`//go:build lab && linux`; the `_unit_test.go` suffix puts them in `make lab-unit`). The positive case re-executes the test binary with the held lock as fd 3:

```go
package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLabInheritedLockIsAdoptedAndExcludesAThird(t *testing.T) {
	if os.Getenv("P49_LOCK_CHILD") == "1" {
		path := os.Getenv("P49_LOCK_PATH")
		if _, ok, err := labInheritedLock(path); !ok || err != nil {
			fmt.Println("CHILD: not adopted:", ok, err)
			os.Exit(3)
		}
		if _, err := labOccupy(path, "third"); err == nil {
			fmt.Println("CHILD: a fresh open took the lock the parent holds")
			os.Exit(4)
		}
		fmt.Println("CHILD: adopted")
		os.Exit(0)
	}
	path := filepath.Join(t.TempDir(), "lab.lock")
	f, _ := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestLabInheritedLockIsAdoptedAndExcludesAThird$")
	cmd.Env = append(os.Environ(), "P49_LOCK_CHILD=1", "P49_LOCK_PATH="+path, "PORT49_LAB_LOCK_FD=3")
	cmd.ExtraFiles = []*os.File{f}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func TestLabInheritedLockRefusesAnotherFile(t *testing.T) {
	f, _ := os.CreateTemp(t.TempDir(), "notthelock")
	defer f.Close()
	t.Setenv("PORT49_LAB_LOCK_FD", fmt.Sprint(f.Fd()))
	if _, ok, err := labInheritedLock(filepath.Join(t.TempDir(), "lab.lock")); !ok || err == nil {
		t.Fatalf("a descriptor that is not the lock file must be refused: ok %v err %v", ok, err)
	}
}
```

- [ ] **Step 8: Makefile**

```make
# The closed lab entries, rerun under the lab lock and diffed against their notes
# (plan 11b). Beehive only. LAB_REGRESS_ARGS passes -only=<ids> or -dry-run.
lab-regress:
	go run ./tests/lab/cmd/lab-regress -manifest tests/lab/regress.yaml $(LAB_REGRESS_ARGS)
```

Add `lab-regress` to `.PHONY`.

- [ ] **Step 9: Run the tests**

Run: `go test ./tests/lab/cmd/lab-regress/ -count=1 && make lab-unit && make check-darwin && go run ./tests/lab/cmd/lab-regress -dry-run`

`GOOS=darwin go vet -tags lab ./tests/lab/` is deliberately not run. It already fails on main at `tests/lab/l56_test.go:131` (`syscall.TIOCSPTLCK`), and `make check-darwin`'s untagged `go vet ./...` covers the new untagged `occupancy_*.go` files.
Expected: PASS, then the entry list with `total 0 min (last measured)`.

- [ ] **Step 10: Commit**

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
- Produces:
  - `func normalize(note string) []string`;
  - `func changed(old, new []string, tolerance float64) (removed, added []string)`.
- The command prints `notediff: <note>: unchanged` or the changed lines.
  - It exits 0, unless `-fail-on-change` is given and a line changed (exit 1).
  - It exits 2 on an I/O error.

**What is masked.** Only lines that are volatile by kind are masked (I1):
- the header lines `- **Date measured:**`, `- **Run:**` and `- **Capture:**`;
- timestamps;
- lab user numbers (`alice<nn>`);
- device source ports;
- packet counts;
- long runs.

Every number left on a line is an observation, and a line whose words are unchanged but whose numbers moved is reported. How a number counts as moved depends on its kind:
- **A duration** (a number followed by `ms`, `s` or `min`; in a range such as `81–85ms`, both ends), such as NX-OS's 5.00 s flight, L13's timeouts or L74's round trip, has moved when it changed by more than `tolerance` (default 20%).
- **Any other number** (a count, a byte length, an id) has moved when it changed at all: 5 → 6 connections and 40 → 41 are changes (I-A).

- [ ] **Step 1: Write the failing tests**

```go
package main

import "testing"

func TestNormalizeMasksOnlyWhatARerunAlwaysChanges(t *testing.T) {
	a := normalize("- **Date measured:** 2026-10-18\n- **Run:** commit `7ff5249f`, x\nlogin at 2026-10-18T06:22:54Z on port 48350 as alice03\n- (h) NX-OS opened 5 connections\n")
	b := normalize("- **Date measured:** 2026-11-20\n- **Run:** commit `0abc1234`, x\nlogin at 2026-11-20T01:02:03Z on port 51111 as alice05\n- (h) NX-OS opened 5 connections\n")
	if r, ad := changed(a, b, 0.2); len(r) != 0 || len(ad) != 0 {
		t.Fatalf("only volatile lines differ, yet: -%q +%q", r, ad)
	}
}

func TestAChangedTimingIsAnObservation(t *testing.T) {
	a := normalize("- operator fact: NX-OS waits exactly 5.00 s before its flight\n")
	b := normalize("- operator fact: NX-OS waits exactly 3.00 s before its flight\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("5.00 s to 3.00 s is a measured change: -%q +%q", r, ad)
	}
}

func TestATimingWithinToleranceIsNotReported(t *testing.T) {
	a := normalize("- token logins took about 21.2 s\n")
	b := normalize("- token logins took about 20.9 s\n")
	if r, ad := changed(a, b, 0.2); len(r)+len(ad) != 0 {
		t.Fatalf("1.4%% is run-to-run noise: -%q +%q", r, ad)
	}
}

func TestChangedNamesAChangedCount(t *testing.T) {
	a := normalize("- (h) NX-OS opened 5 connections\n")
	b := normalize("- (h) NX-OS opened 6 connections\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("a changed count is an observation: -%q +%q", r, ad)
	}
	a = normalize("- the reply was 40 bytes\n")
	b = normalize("- the reply was 41 bytes\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("integers compare exactly, whatever the tolerance: -%q +%q", r, ad)
	}
	a = normalize("- image SR Linux 26.7.2\n")
	b = normalize("- image SR Linux 26.8.2\n")
	if r, ad := changed(a, b, 0.2); len(r) != 1 || len(ad) != 1 {
		t.Fatalf("a bare decimal is a version, not a duration: -%q +%q", r, ad)
	}
}

func TestARangeIsTwoDurations(t *testing.T) {
	a := normalize("- break-glass landed in 81–85ms\n")
	b := normalize("- break-glass landed in 83–86ms\n")
	if r, ad := changed(a, b, 0.2); len(r)+len(ad) != 0 {
		t.Fatalf("both ends of a range carry its unit: -%q +%q", r, ad)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./tests/lab/cmd/notediff/ -count=1`
Expected: FAIL (`undefined: normalize`).

- [ ] **Step 3: Implement**

```go
// Command notediff compares a results note a lab rerun rewrote with the copy at
// HEAD. It masks only what every rerun changes, and compares the numbers on
// the remaining lines with a tolerance, so the lines it prints are changed
// observations (plan 11b). It reports; the lab is the truth.
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

var (
	volatileHeader = regexp.MustCompile(`^- \*\*(Date measured|Run|Capture):\*\*`)
	volatile       = []struct {
		re  *regexp.Regexp
		rep string
	}{
		{regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z`), "<ts>"},
		{regexp.MustCompile(`\balice\d{2}\b|\bl73u\d{2}\b|\bqual\d{2}\b`), "<user>"},
		{regexp.MustCompile(`\b(device_)?port \d{4,5}\b`), "port <n>"},
		{regexp.MustCompile(`\b\d+ packets\b`), "<n> packets"},
		{regexp.MustCompile(`[A-Za-z0-9_+/=.-]{24,}`), "<LONG>"},
	}
	// group 1 the value, group 2 a decimal part, group 3 a unit (kept in the skeleton).
	number = regexp.MustCompile(`(\d+(\.\d+)?)( ?(?:ms|min|s)\b)?`)
	// A range whose unit follows its second number ("81–85ms", "100-200 ms"):
	// the unit is copied onto the first, so both compare as durations.
	unitRange = regexp.MustCompile(`(\d+(?:\.\d+)?)(\s?[–-]\s?)(\d+(?:\.\d+)?)( ?(?:ms|min|s)\b)`)
)

func normalize(note string) []string {
	var out []string
	for _, l := range strings.Split(note, "\n") {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if m := volatileHeader.FindString(l); m != "" {
			out = append(out, m+" <volatile>")
			continue
		}
		for _, v := range volatile {
			l = v.re.ReplaceAllString(l, v.rep)
		}
		out = append(out, l)
	}
	return out
}

// num is one number on a line. A duration (a decimal, or a number followed
// by ms, s or min) is compared with the tolerance; every other number (a
// count, an id, a byte length) is compared exactly (re-review I-A).
type num struct {
	v        float64
	duration bool
}

// skeleton is a line with its numbers replaced, so two lines that differ only
// in their numbers pair up, and their numbers are then compared.
func skeleton(l string) (string, []num) {
	var nums []num
	l = unitRange.ReplaceAllString(l, "$1$4$2$3$4")
	s := number.ReplaceAllStringFunc(l, func(m string) string {
		sub := number.FindStringSubmatch(m)
		f, _ := strconv.ParseFloat(sub[1], 64)
		// A duration only when a unit follows: a bare decimal is a version or
		// an address part (26.7 vs 26.8), and compares exactly.
		nums = append(nums, num{v: f, duration: sub[3] != ""})
		return "#" + sub[3]
	})
	return s, nums
}

func within(a, b []num, tol float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].v == b[i].v {
			continue
		}
		if !a[i].duration || !b[i].duration {
			return false
		}
		if m := math.Max(math.Abs(a[i].v), math.Abs(b[i].v)); m == 0 || math.Abs(a[i].v-b[i].v)/m > tol {
			return false
		}
	}
	return true
}

func changed(old, new []string, tol float64) (removed, added []string) {
	pool := map[string][][]num{}
	lines := map[string][]string{}
	for _, l := range old {
		s, n := skeleton(l)
		pool[s] = append(pool[s], n)
		lines[s] = append(lines[s], l)
	}
	for _, l := range new {
		s, n := skeleton(l)
		hit := -1
		for i, o := range pool[s] {
			if within(o, n, tol) {
				hit = i
				break
			}
		}
		if hit < 0 {
			added = append(added, l)
			continue
		}
		pool[s] = append(pool[s][:hit], pool[s][hit+1:]...)
		lines[s] = append(lines[s][:hit], lines[s][hit+1:]...)
	}
	for _, ls := range lines {
		removed = append(removed, ls...)
	}
	return removed, added
}

func main() {
	note := flag.String("note", "", "a results note path")
	tol := flag.Float64("tolerance", 0.2, "the relative change in a number that counts as an observation")
	fail := flag.Bool("fail-on-change", false, "exit 1 when an observation changed (CI)")
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
	r, a := changed(normalize(string(head)), normalize(string(now)), *tol)
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
	if *fail {
		os.Exit(1)
	}
}
```

- [ ] **Step 4: Run the tests**

Run: `go test ./tests/lab/cmd/notediff/ -count=1 && go run ./tests/lab/cmd/notediff -note tests/lab/results/L73-cisco_nxos.md`
Expected: PASS, then `notediff: tests/lab/results/L73-cisco_nxos.md: unchanged`.

- [ ] **Step 5: Commit**

```bash
git add tests/lab/cmd/notediff
git commit -m "test: notediff names a rerun's changed observations, timings included

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 4: Lab — the first full `make lab-regress`, timed

**Files:**
- Modify: `tests/lab/regress.yaml` (each entry's `measured_minutes`) and `tests/lab/README.md` (a "Regressions" section)

This task runs on beehive. It is the early measurement Ryan asked for: how long the real full run takes. The answer decides whether "pre-beta and release tags" can take a whole run or needs `-only`. It may run while Tasks 5–11 are coded, since they touch no lab file.

- [ ] **Step 1: Pre-flight.**
  - The STOP sentinel is absent.
  - `flock -n /tmp/port49-lab.lock true` succeeds.
  - `make build` is done.
  - Every manifest image is present (`docker image inspect`).
  - `go run ./tests/lab/cmd/lab-regress -dry-run` lists the entries.

- [ ] **Step 2: Start the run in the background with a watchdog.** The run takes hours, so it is never a foreground command.
  - Start it with Bash `run_in_background: true`: `make lab-regress > /tmp/claude-lab-regress-$(date +%F).log 2>&1`.
  - Arm a stall watchdog as a second background command, `sleep 1800; echo WATCHDOG`, and re-arm it on every wake.
  - On each wake, read progress only through `grep -v -i 'password\|token\|secret\|eyJ' /tmp/claude-lab-regress-*.log | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g' | grep 'lab-regress\|notediff\|--- FAIL\|^ok '`.
  - A log that has not grown since the last wake is a stall: read the last filtered lines, and stop the run through the STOP sentinel.

  Expected: one `lab-regress: <id> <n> min` line per entry and a total. Each notediff line reads `unchanged`, or shows changed lines for a person to read.

- [ ] **Step 3: Settle what the run rewrote.**
  - **An entry whose notediff said `unchanged`:** put its notes and evidence back to HEAD (`git restore tests/lab/results/<notes> tests/lab/evidence/<files>`). A rerun with no change is not a commit.
  - **An entry with a changed observation:** investigate it before this task closes. If the change stands (the device changed, or the earlier note was wrong), the lab is the truth (CLAUDE.md rule 4):
    - commit the rewritten note and evidence;
    - fix and cite any doc it contradicts;
    - put both in one `docs:` commit that says so.

- [ ] **Step 4: Record the measurement.**
  - Write each entry's minutes into `measured_minutes`.
  - Add a `## Regressions (plan 11b)` section to `tests/lab/README.md` giving the date, the commit, the total wall time, the slowest three entries, and how to run a subset (`make lab-regress LAB_REGRESS_ARGS=-only=L73-nxos106`).
  - Copy the raw captures from any worktree you used into main's `tests/lab/captures/`, so the labpcap audit stays whole.

- [ ] **Step 5: Commit**

```bash
git add tests/lab/regress.yaml tests/lab/README.md
git commit -m "test: the first full lab-regress run, timed per entry

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 5: `packet_fields` on the validated request records

**Files:**
- Create: `internal/decision/packet.go`
- Modify: `internal/decision/log.go` (the `Record` field), `internal/daemon/authen/authen.go:225` (`newRecord`, shared by `redeem` and `escalate`), `internal/daemon/author/author.go:244` (shared by `authorize_command` and `authorize_session`), `internal/daemon/acct/acct.go:142`
- Test: `internal/decision/log_test.go`, plus each handler's existing record tests

**Interfaces:**
- Produces:
  - `type PacketFields struct { Action, AuthenType, Service, AuthenMethod string; PrivLvl uint8 }`, with JSON keys `action,omitempty`, `authen_type`, `service`, `authen_method,omitempty`, `priv_lvl`;
  - `func AuthenFields(wire.AuthenStart) *PacketFields`;
  - `func AuthorFields(wire.AuthorRequest) *PacketFields`;
  - `func AcctFields(wire.AcctRequest) *PacketFields`;
  - the `Record` field `PacketFields *PacketFields \`json:"packet_fields,omitempty"\``.

- [ ] **Step 1: Write the failing test** in `internal/decision/log_test.go`:

```go
func TestPacketFieldsNameTheHeaderAndNothingElse(t *testing.T) {
	f := AuthenFields(wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, PrivLvl: 1, User: []byte("u"), Port: []byte("tty1"),
		RemAddr: []byte("192.0.2.1"), Data: []byte("SECRET-DATA")})
	b, _ := json.Marshal(Record{Event: EventRedeem, PacketFields: f})
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
	if AcctFields(wire.AcctRequest{}).AuthenType != "not_set" {
		t.Fatal("authen_type 0 is not_set on authorization and accounting")
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `go test ./internal/decision/ -run TestPacketFieldsNameTheHeaderAndNothingElse -count=1`
Expected: FAIL (`undefined: AuthenFields`).

- [ ] **Step 3: Implement `internal/decision/packet.go`**

```go
package decision

import (
	"fmt"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// PacketFields is a validated request's header fields, as names (spec §5.7;
// §13 decision 52 ruling 3). Never a user, a port, an address, data or an
// argument.
type PacketFields struct {
	Action       string `json:"action,omitempty"` // authentication only
	AuthenType   string `json:"authen_type"`
	Service      string `json:"service"`
	AuthenMethod string `json:"authen_method,omitempty"` // authorization and accounting only
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

Add `PacketFields *PacketFields \`json:"packet_fields,omitempty"\`` to `Record`, after `Request`.

Then set it at the three sites, each of which is the one record builder for its events:
- `authen.go` `newRecord`: `rec.PacketFields = decision.AuthenFields(s.start)`. This covers `redeem` and `escalate`, which `newRecord` builds; the latter is rewritten at `:275`.
- `author.go:244`: `PacketFields: decision.AuthorFields(req)`. This covers `authorize_command` and `authorize_session`.
- `acct.go:142`: `PacketFields: decision.AcctFields(req)`.

An `unvalidated` record gets nothing.

- [ ] **Step 4: Add one assertion per handler.** In each handler's existing record test, add an assertion that the record it already checks carries `packet_fields`. For example, in the authen test that checks a `redeem` record:

```go
	if pf := rec.PacketFields; pf == nil || pf.AuthenType != "pap" || pf.Action != "login" {
		t.Fatalf("redeem record's packet_fields: %+v", rec.PacketFields)
	}
```

Add the same check for an `escalate` record (the `$enab15$` test), an `authorize_session` record, an `authorize_command` record and an `account` record (`AuthenMethod` set).

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
- Create: `internal/devicemock/profile.go`, `internal/devicemock/forbidden.go`, `internal/devicemock/profile_test.go`
- Create, in `internal/devicemock/testdata/`: `notes/L99-fixture_junos.md`, `notes/L99-fixture_junos-2.md`, `profiles/fixture_junos.yaml`, `profiles/fixture_plain.yaml`, `profiles/fixture_vocabulary.yaml`

**Interfaces:**
- Produces (every later task uses these names):

```go
type Profile struct {
	SchemaVersion int              `yaml:"schema_version"` // 1
	Platform      string           `yaml:"platform"`       // port49 inventory platform: cisco_nxos
	LabPlatform   string           `yaml:"lab_platform"`   // results-note platform name
	Firmware      string           `yaml:"firmware"`       // as the note's Image version line names it: 10.6(2)F
	Image         string           `yaml:"image"`
	Vetted        Vetted           `yaml:"vetted"`
	Transports    []string         `yaml:"transports"` // tcp, tls
	Scenarios     []string         `yaml:"scenarios"`
	Stimulus      Stimulus         `yaml:"stimulus"`
	Reactions     []Reaction       `yaml:"reactions"`
	Acceptance    []AcceptanceRule `yaml:"acceptance"`
	EngineGaps    []EngineGap      `yaml:"engine_gaps"`
	Golden        string           `yaml:"golden"` // relative to the repository root; "" for a fixture with none
}
type Vetted struct {
	Date     string   `yaml:"date"`
	Commit   string   `yaml:"commit"`
	Evidence string   `yaml:"evidence"` // tests/lab/evidence/QUAL-<firmware_slug>-<lab_platform>/
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
	ServerHello    ServerHello   `yaml:"server_hello"`
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
	CompressCertAlgs    []uint16 `yaml:"compress_certificate_algorithms"` // extension 27
	Extensions          []uint16 `yaml:"extensions"`                      // in the device's order
}
type ServerHello struct {
	SelectedVersion   uint16 `yaml:"selected_version"`
	CipherSuite       uint16 `yaml:"cipher_suite"`
	HelloRetryRequest bool   `yaml:"hello_retry_request"`
}
type ConnPattern struct {
	Mode              string `yaml:"mode"` // per_step, single_connection
	SingleConnectFlag bool   `yaml:"single_connect_flag"`
}
type Step struct {
	Name         string       `yaml:"name"` // login, authorize_session, command_permitted, command_denied, account_start, account_stop
	Type         string       `yaml:"type"` // authen, author, acct
	MinorVersion uint8        `yaml:"minor_version"` // from the 12-byte header summary, never derived
	Fields       PacketFields `yaml:"fields"`
	Port         string       `yaml:"port"`
	Args         []string     `yaml:"args"` // with {user} {rem_addr} {task_id} {start_time} {stop_time}
	Flags        string       `yaml:"flags"` // acct: start, stop, watchdog
}
type PacketFields struct {
	Action       string `yaml:"action"`
	AuthenType   string `yaml:"authen_type"`
	Service      string `yaml:"service"`
	AuthenMethod string `yaml:"authen_method"`
	PrivLvl      uint8  `yaml:"priv_lvl"`
}
type Reaction struct {
	Step    string   `yaml:"step"` // a step name, or "*"
	On      string   `yaml:"on"`
	Then    string   `yaml:"then"`
	Outcome string   `yaml:"outcome"`
	Status  string   `yaml:"status"` // measured, unmeasured
	Sources []Source `yaml:"sources"`
}
type AcceptanceRule struct {
	ID      string   `yaml:"id"`
	Kind    string   `yaml:"kind"`    // max_attribute_bytes, max_reply_bytes, priv_lvl_range, attribute_refused, role_names
	Applies string   `yaml:"applies"` // authorize_session, command_permitted, any
	Max     int      `yaml:"max"`
	Min     int      `yaml:"min"`
	Names   []string `yaml:"names"`
	Effect  string   `yaml:"effect"` // lockout, session_refused, attribute_ignored
	Status  string   `yaml:"status"`
	Sources []Source `yaml:"sources"`
	Note    string   `yaml:"note"`
}
type EngineGap struct {
	ID      string   `yaml:"id"`
	What    string   `yaml:"what"`
	Code    string   `yaml:"code"` // the Go file that covers it, or "" when uncovered
	Sources []Source `yaml:"sources"`
}

func Load(path, repoRoot string) (*Profile, error)
func (p *Profile) Validate(repoRoot string) error
func Slug(firmware string) string // "10.6(2)F" -> "10.6-2-F"
func ScenarioTransport(sc string) string // "tls" for tls_* and flight_delay, else "tcp"
func BaseScenario(sc string) string      // sc without "tls_"
var Codes map[string]map[string]uint8 // the wire values the engine can send, by field
```

- [ ] **Step 1: Write the fixtures.** Paths in a fixture are relative to `internal/devicemock/testdata`, which the tests pass as `repoRoot`.

`testdata/notes/L99-fixture_junos.md`:

```markdown
# L99 — fixture_junos

- **Date measured:** 2026-10-19
- **Platform:** fixture_junos (a unit-test fixture, not a lab measurement)
- **Image version:** fixture 1.0
```

`testdata/notes/L99-fixture_junos-2.md` is the same, with `- **Image version:** fixture 2.0`.

`testdata/profiles/fixture_plain.yaml`:

```yaml
schema_version: 1
platform: juniper_junos
lab_platform: fixture_junos
firmware: "1.0"
image: fixture 1.0
vetted: {date: 2026-10-19, commit: "0000000", evidence: "", notes: [notes/L99-fixture_junos.md]}
transports: [tcp]
scenarios: [token_login, wrong_credential, store_unavailable]
stimulus:
  connections: {mode: per_step, single_connect_flag: false}
  sources: [{note: notes/L99-fixture_junos.md, register: L99}]
  steps:
    - {name: login, type: authen, minor_version: 1, fields: {action: login, authen_type: pap, service: login, priv_lvl: 1}, port: "0"}
    - {name: authorize_session, type: author, minor_version: 0,
       fields: {authen_type: pap, service: login, authen_method: tacacsplus, priv_lvl: 1}, port: "0", args: ["service=junos-exec"]}
    - {name: account_start, type: acct, minor_version: 0, flags: start,
       fields: {authen_type: pap, service: login, authen_method: tacacsplus, priv_lvl: 1}, port: "0",
       args: ["task_id={task_id}", "start_time={start_time}", "service=shell"]}
reactions:
  - {step: login, on: authen_pass, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: login, on: authen_fail, then: stop, outcome: login_refused, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: login, on: authen_error, then: failover_local, outcome: falls_to_local, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: "*", on: author_pass_add, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: "*", on: author_pass_repl, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
  - {step: "*", on: acct_success, then: next_step, status: measured, sources: [{note: notes/L99-fixture_junos.md, register: L99}]}
acceptance: []
engine_gaps: []
golden: ""
```

`testdata/profiles/fixture_junos.yaml` is the same file with this `acceptance:`:

```yaml
acceptance:
  - id: junos_reply_total
    kind: max_reply_bytes
    applies: authorize_session
    max: 255
    effect: lockout
    status: measured
    sources: [{note: notes/L99-fixture_junos.md, register: L99}]
    note: a fixture of L78's claim, marked measured here so the gate itself can be tested
```

`testdata/profiles/fixture_vocabulary.yaml` is `fixture_plain.yaml` plus one reaction for every `On` value and every `Then` value in Step 4's sets, each `status: unmeasured` with no source (C3).

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

func TestLoadAcceptsTheWholeReactionVocabulary(t *testing.T) {
	if _, err := Load("testdata/profiles/fixture_vocabulary.yaml", root); err != nil {
		t.Fatalf("every on and then value must load (send_credential included): %v", err)
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
		refused(t, func(s string) string {
			return strings.Replace(s, "notes/L99-fixture_junos.md, register: L99}]\n    note:", "notes/L98-gone.md, register: L98}]\n    note:", 1)
		}, "L98-gone.md")
	})
	t.Run("a measured rule with no source", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "    sources: [{note: notes/L99-fixture_junos.md, register: L99}]\n    note:", "    note:", 1)
		}, "junos_reply_total")
	})
	t.Run("a measured claim citing another firmware's note", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, "notes/L99-fixture_junos.md, register: L99}]\n    note:", "notes/L99-fixture_junos-2.md, register: L99}]\n    note:", 1)
		}, "Image version")
	})
	t.Run("an unknown reaction", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "then: stop", "then: shrug", 1) }, "shrug")
	})
	t.Run("a credential-shaped key", func(t *testing.T) {
		refused(t, func(s string) string { return s + "token_sha256: x\n" }, "token_sha256")
	})
	t.Run("a credential-shaped value", func(t *testing.T) {
		refused(t, func(s string) string {
			return strings.Replace(s, `"service=junos-exec"`, `"credential_sha256=`+strings.Repeat("ab", 32)+`"`, 1)
		}, "credential")
	})
	t.Run("a PEM block", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "image: fixture 1.0", "image: \"-----BEGIN PRIVATE KEY-----\"", 1) }, "BEGIN")
	})
	t.Run("a field the engine cannot send", func(t *testing.T) {
		refused(t, func(s string) string { return strings.Replace(s, "authen_type: pap, service: login, priv_lvl: 1", "authen_type: mschap, service: login, priv_lvl: 1", 1) }, "mschap")
	})
}

func TestAnUnmeasuredRuleMayCiteAnotherFirmwaresNote(t *testing.T) {
	raw, _ := os.ReadFile("testdata/profiles/fixture_junos.yaml")
	s := strings.Replace(string(raw), "    status: measured\n    sources: [{note: notes/L99-fixture_junos.md", "    status: unmeasured\n    sources: [{note: notes/L99-fixture_junos-2.md", 1)
	path := filepath.Join(t.TempDir(), "p.yaml")
	os.WriteFile(path, []byte(s), 0o600)
	if _, err := Load(path, root); err != nil {
		t.Fatalf("an unmeasured claim may cite the note that left it open: %v", err)
	}
}

func TestSlug(t *testing.T) {
	for in, want := range map[string]string{"10.6(2)F": "10.6-2-F", "26.2R1.7": "26.2R1.7", "4.36.3M": "4.36.3M", "26.7.2-519": "26.7.2-519"} {
		if got := Slug(in); got != want {
			t.Errorf("Slug(%q) = %q, want %q", in, got, want)
		}
	}
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/devicemock/ -count=1`
Expected: FAIL (`undefined: Load`).

- [ ] **Step 4: Implement `forbidden.go`.** The check is key- and value-shaped (C3). A reaction named `send_credential` loads, and a key, value or block that is credential material does not:

```go
package devicemock

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var (
	forbiddenKey   = regexp.MustCompile(`(?i)(^|_)(sha256|password|secret|token|key)$`)
	forbiddenValue = []*regexp.Regexp{
		regexp.MustCompile(`[0-9a-fA-F]{40,}`),          // a hash or key in hex
		regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----`), // a PEM block
		regexp.MustCompile(`(?i)\b(credential|token)_sha256=`),
	}
	// Keys the schema itself defines and that match forbiddenKey's shape but
	// hold no secret.
	allowedKey = map[string]bool{"psk_key_exchange_modes": true}
)

// credentialShaped walks the document and names the first key or scalar that
// looks like credential material. It never prints the value.
func credentialShaped(n *yaml.Node, path string) error {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, c := range n.Content {
			if err := credentialShaped(c, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if forbiddenKey.MatchString(k) && !allowedKey[k] {
				return fmt.Errorf("%s.%s: a key named like credential material", path, k)
			}
			if err := credentialShaped(n.Content[i+1], path+"."+k); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
		for _, re := range forbiddenValue {
			if re.MatchString(n.Value) {
				return fmt.Errorf("%s: a value shaped like credential material (%s)", path, strings.SplitN(re.String(), "`", 2)[0])
			}
		}
	}
	return nil
}
```

- [ ] **Step 5: Implement `profile.go`.** Put the types above in it, plus:

```go
var (
	stepTypes = set("authen", "author", "acct")
	stepNames = set("login", "authorize_session", "command_permitted", "command_denied", "account_start", "account_stop")
	// A scenario's transport is its prefix: tls_* and flight_delay over RFC 9887,
	// the rest over 49 (re-review I-B; ScenarioTransport).
	scenarios = set("token_login", "wrong_credential", "store_unavailable", "single_connection",
		"tls_token_login", "tls_store_unavailable", "tls_unknown_ca", "flight_delay")
	reactOn   = set("authen_pass", "authen_fail", "authen_getpass", "authen_getuser", "authen_getdata", "authen_error",
		"author_pass_add", "author_pass_repl", "author_fail", "author_error", "acct_success", "acct_error",
		"conn_reset", "conn_closed", "reply_single_connect", "alert_unknown_ca", "alert_bad_certificate",
		"alert_certificate_expired", "alert_handshake_failure", "handshake_timeout")
	reactThen = set("next_step", "send_credential", "stop", "retry", "failover_local", "failover_next_server",
		"give_up", "reuse_connection", "new_connection")
	// outcomes: what a reaction ends in, and the engine's own ends of a play.
	outcomes  = set("", "login_ok", "login_refused", "falls_to_local", "break_glass_fails", "command_permitted",
		"command_denied", "accounted", "rejected_by_device", "handshake_ok", "handshake_refused")
	ruleKinds = set("max_attribute_bytes", "max_reply_bytes", "priv_lvl_range", "attribute_refused", "role_names")
)

// Codes are the wire values the engine sends for a step's field names. A
// name the engine cannot send (mschap, mschapv2, krb5, guest, radius) is
// refused by Validate, naming it: such a device is an engine gap, not a
// silent default.
var Codes = map[string]map[string]uint8{
	"action":        {"login": wire.AuthenActionLogin, "chpass": wire.AuthenActionChPass, "sendauth": wire.AuthenActionSendAuth},
	"authen_type":   {"not_set": 0, "ascii": wire.AuthenTypeASCII, "pap": wire.AuthenTypePAP, "chap": wire.AuthenTypeCHAP},
	"service":       {"none": wire.AuthenServiceNone, "login": wire.AuthenServiceLogin, "enable": wire.AuthenServiceEnable, "ppp": wire.AuthenServicePPP},
	"authen_method": {"not_set": wire.AuthenMethodNotSet, "none": wire.AuthenMethodNone, "line": wire.AuthenMethodLine, "enable": wire.AuthenMethodEnable, "local": wire.AuthenMethodLocal, "tacacsplus": wire.AuthenMethodTACACSPlus},
}

func set(xs ...string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ScenarioTransport is the transport a scenario runs over: "tls" for tls_* and
// flight_delay, "tcp" for the rest. The harness admits the device on that
// transport for that scenario, and genprofile splits records the same way
// (by device.transport).
func ScenarioTransport(sc string) string {
	if strings.HasPrefix(sc, "tls_") || sc == "flight_delay" {
		return "tls"
	}
	return "tcp"
}

// BaseScenario is sc without its tls_ prefix: what the engine plays.
func BaseScenario(sc string) string { return strings.TrimPrefix(sc, "tls_") }

var slugBad = regexp.MustCompile(`[^A-Za-z0-9.]+`)

// Slug is a firmware version as a path element: every run of characters
// other than letters, digits and dots becomes one dash, trimmed at the ends.
func Slug(firmware string) string {
	return strings.Trim(slugBad.ReplaceAllString(firmware, "-"), "-")
}

func Load(path, repoRoot string) (*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := credentialShaped(&doc, ""); err != nil {
		return nil, fmt.Errorf("%s: %w; a profile never carries a credential or key", path, err)
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

var imageLine = regexp.MustCompile(`(?m)^- \*\*Image version:\*\* (.*)$`)

func (p *Profile) Validate(repoRoot string) error {
	if p.SchemaVersion != 1 {
		return fmt.Errorf("schema_version %d; this engine reads 1", p.SchemaVersion)
	}
	var errs []error
	// cite checks one source. measured: the note's Image version line must
	// name this firmware (decision 52 ruling 4); unmeasured: the note need
	// only exist, as the one that left the claim open.
	cite := func(where string, s Source, measured bool) {
		if s.Note == "" || s.Register == "" {
			errs = append(errs, fmt.Errorf("%s: a source needs note and register", where))
			return
		}
		body, err := os.ReadFile(filepath.Join(repoRoot, s.Note))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %s: %v", where, s.Note, err))
			return
		}
		if !measured {
			return
		}
		// A note may hold several sections (addenda), each with its own line.
		named := false
		for _, m := range imageLine.FindAllStringSubmatch(string(body), -1) {
			named = named || strings.Contains(m[1], p.Firmware)
		}
		if !named {
			errs = append(errs, fmt.Errorf("%s: %s's Image version line does not name firmware %q; "+
				"a claim measured on another firmware is unmeasured here", where, s.Note, p.Firmware))
		}
	}
	if len(p.Stimulus.Sources) == 0 {
		errs = append(errs, errors.New("stimulus: no source"))
	}
	for _, s := range p.Stimulus.Sources {
		cite("stimulus", s, true)
	}
	if p.Stimulus.TLS != nil {
		for _, s := range p.Stimulus.TLS.Sources {
			cite("stimulus.tls", s, true)
		}
	}
	for i, s := range p.Stimulus.Steps {
		if !stepTypes[s.Type] || !stepNames[s.Name] {
			errs = append(errs, fmt.Errorf("steps[%d]: type %q name %q", i, s.Type, s.Name))
		}
		for field, v := range map[string]string{"action": s.Fields.Action, "authen_type": s.Fields.AuthenType,
			"service": s.Fields.Service, "authen_method": s.Fields.AuthenMethod} {
			if v == "" {
				continue
			}
			if _, ok := Codes[field][v]; !ok {
				errs = append(errs, fmt.Errorf("steps[%d]: %s %q has no wire value in this engine (an engine gap)", i, field, v))
			}
		}
	}
	for _, sc := range p.Scenarios {
		if !scenarios[sc] {
			errs = append(errs, fmt.Errorf("scenario %q is not in the conformance set", sc))
		} else if tr := ScenarioTransport(sc); !slices.Contains(p.Transports, tr) {
			errs = append(errs, fmt.Errorf("scenario %q needs transport %s, which the profile does not list", sc, tr))
		}
	}
	for i, r := range p.Reactions {
		if !reactOn[r.On] || !reactThen[r.Then] || !outcomes[r.Outcome] {
			errs = append(errs, fmt.Errorf("reactions[%d]: on %q then %q outcome %q", i, r.On, r.Then, r.Outcome))
		}
		errs = append(errs, statusErr(fmt.Sprintf("reactions[%d]", i), r.Status, r.Sources)...)
		for _, s := range r.Sources {
			cite(fmt.Sprintf("reactions[%d]", i), s, r.Status == "measured")
		}
	}
	for _, a := range p.Acceptance {
		if !ruleKinds[a.Kind] {
			errs = append(errs, fmt.Errorf("acceptance %s: kind %q", a.ID, a.Kind))
		}
		errs = append(errs, statusErr("acceptance "+a.ID, a.Status, a.Sources)...)
		for _, s := range a.Sources {
			cite("acceptance "+a.ID, s, a.Status == "measured")
		}
	}
	return errors.Join(errs...)
}

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

Imports: `bytes`, `errors`, `fmt`, `os`, `path/filepath`, `regexp`, `slices`, `strings`, `time`, `gopkg.in/yaml.v3`, `github.com/rhwendt/port49/internal/tacacs/wire`.

- [ ] **Step 6: Run the tests**

Run: `go test ./internal/devicemock/ -count=1 && GOOS=darwin go vet ./internal/devicemock/`
Expected: PASS; vet clean.

- [ ] **Step 7: Commit**

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
func roleNames(v string) []string // splits a roles value: spaces, with "..." quoting as NX-OS documents it
```

- [ ] **Step 1: Write the failing tests**

```go
package devicemock

import (
	"slices"
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
		{AcceptanceRule{Kind: "role_names", Names: []string{"network-admin", "p49-ro"}}, []string{`shell:roles*"network-admin p49-ro"`}, false},
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

func TestRoleNamesReadsQuotedAndBareValues(t *testing.T) {
	for in, want := range map[string][]string{
		`network-admin`:                  {"network-admin"},
		`"network-admin p49-ro"`:         {"network-admin", "p49-ro"},
		`network-admin  p49-ro`:          {"network-admin", "p49-ro"},
	} {
		if got := roleNames(in); !slices.Equal(got, want) {
			t.Errorf("roleNames(%q) = %q, want %q", in, got, want)
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

Run: `go test ./internal/devicemock/ -run 'Rule|Reply|React|Kind|RoleNames' -count=1`
Expected: FAIL (`undefined: Check`).

- [ ] **Step 3: Implement `accept.go`**

```go
package devicemock

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

type Violation struct {
	Rule, Step, Effect string
	Detail             string
	Measured           bool
}

// Check applies a profile's acceptance rules to one reply's arguments. A
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

// roleNames splits a roles value as the device reads it: names separated by
// spaces, the whole list optionally in double quotes, which NX-OS documents
// for more than one role.
func roleNames(v string) []string {
	return strings.Fields(strings.Trim(strings.TrimSpace(v), `"`))
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
			if n := name(a); n == "shell:roles" || n == "roles" {
				for _, role := range roleNames(value(a)) {
					if !slices.Contains(r.Names, role) {
						return fmt.Sprintf("%s names a role this device does not honour", n)
					}
				}
			}
		}
	}
	return ""
}
```

- [ ] **Step 4: Implement `react.go`**

```go
package devicemock

import "fmt"

// React is the profile's next action for an event at a step: the step's own
// entry first, then "*". An event with no entry is an error: the vetter adds
// it from the lab notes, and the engine never guesses (decision 52 ruling 1).
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
- Modify: `tests/lab/l73_tlswire.go` (`l73Hello.CompressCertAlgs`, `l73Plain.Version`), `tests/lab/l73_tlswire_unit_test.go`

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
var ErrNoBuilder error
```

- Produces in the lab: `l73Hello.CompressCertAlgs []uint16` with JSON key `compress_certificate_algorithms,omitempty` (I3), and `l73Plain.Version uint8` with JSON key `version` (M4).

- [ ] **Step 1: Record what the evidence lacks (lab side).** In `l73ParseClientHello` (`tests/lab/l73_tlswire.go:394`), when extension 27 is read, decode its body (a one-byte length, then two-byte algorithm ids) into `CompressCertAlgs`. In `l73PlainHeaders`, set `Version: b[0]`. Add unit cases to `l73_tlswire_unit_test.go`:
  - a hand-built hello carrying `27` with `[0x0002, 0x0001]` yields `CompressCertAlgs: [2 1]`;
  - a header with version byte `0xc1` yields `Version: 0xc1`.

  In the same step, update `TestL73SummaryTypesHaveNoRoomForSessionBytes`'s `want` map (`tests/lab/l73_tlswire_unit_test.go:299`) on purpose (I-E). That test pins the summary types' exact field sets, so it fails until both fields are added:

```go
		// compress_certificate's algorithm ids (RFC 8879): two-byte registry
		// codes the device offers, the same for every connection; no random,
		// key or secret can be carried in them (plan 11b, I3).
		"l73Hello.CompressCertAlgs": "[]uint16",
		// The 12-byte header's version octet (major<<4 | minor): one of four
		// values RFC 8907 defines; it carries no session byte (plan 11b, M4).
		"l73Plain.Version": "uint8",
```

  Run `make lab-unit` and confirm the new cases, and the guard test, fail. Implement, then run it again and confirm they pass. Both fields are ids and counts, never session bytes, so `l73SummaryLeaks` is unaffected.

- [ ] **Step 2: Write the failing engine tests**

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

func TestBuildClientHelloBuildsCompressCertificate(t *testing.T) {
	h := nxosHello()
	h.Extensions, h.CompressCertAlgs = append(h.Extensions, 27), []uint16{2, 1}
	raw, err := BuildClientHello(h, "")
	if err != nil {
		t.Fatalf("cEOS sends extension 27 (L73-arista_ceos evidence): %v", err)
	}
	if got, _ := parseClientHelloForTest(raw); !equalU16(got.CompressCertAlgs, []uint16{2, 1}) {
		t.Fatalf("%+v", got)
	}
}

func TestBuildClientHelloRefusesAnExtensionItCannotBuild(t *testing.T) {
	h := nxosHello()
	// pre_shared_key: cEOS offered one on a resumption (L73-arista_ceos, cell g);
	// the mock never resumes, and genprofile takes a full handshake's hello.
	h.Extensions = append(h.Extensions, 41)
	if _, err := BuildClientHello(h, ""); err == nil {
		t.Fatal("an extension with no builder is an engine gap, named, never skipped")
	}
}

// The suite crypto/tls picks for the N9Kv's offer is AES-128-GCM on a runner
// with AES hardware (hosted x86, Apple arm64); ChaCha20 would be chosen
// without it, which no supported runner lacks.
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
		t.Fatalf("%+v", sh)
	}
}

func TestDelayFlightDelaysOnlyTheFirstWriteAfterARead(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	var slept atomic.Int64
	c := DelayFlight(a, 500*time.Millisecond, func(d time.Duration) { slept.Add(int64(d)) })
	go func() {
		buf := make([]byte, 8)
		for {
			if _, err := b.Read(buf); err != nil {
				return
			}
		}
	}()
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

Write the helpers in `hello_test.go` in full:
- `parseClientHelloForTest(raw []byte) (Hello, error)` reads, in order:
  1. the 5-byte record header;
  2. the 4-byte handshake header;
  3. the version;
  4. 32 bytes of random;
  5. the session id;
  6. the suites into `CipherSuites`;
  7. compression;
  8. each extension's type, appended to `Extensions`, taking the host from extension 0 into `SNI` and the algorithms from extension 27 into `CompressCertAlgs`.
- `equalU16` is `slices.Equal`.
- `selfSigned(t)` is `testpki.NewCA("probe", …)` then `ca.Issue(testpki.Leaf{IPs: testpki.Loopback(), NotBefore: …, NotAfter: …})`.

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/devicemock/ -run 'Hello|Probe|Delay' -count=1`
Expected: FAIL (`undefined: BuildClientHello`).

- [ ] **Step 4: Implement `hello.go`**

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
func vec16(b, body []byte) []byte  { return append(u16(b, uint16(len(body))), body...) }
func vec8(b, body []byte) []byte   { return append(append(b, byte(len(body))), body...) }

func u16s(xs []uint16) []byte {
	var b []byte
	for _, x := range xs {
		b = u16(b, x)
	}
	return b
}

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
			body = vec16(nil, vec16([]byte{0}, []byte(name)))
		case 10:
			body = vec16(nil, u16s(h.SupportedGroups))
		case 11:
			body = []byte{1, 0}
		case 13, 50:
			body = vec16(nil, u16s(h.SignatureAlgorithms))
		case 16:
			var l []byte
			for _, p := range h.ALPN {
				l = vec8(l, []byte(p))
			}
			body = vec16(nil, l)
		case 22, 23, 35, 49:
			body = nil
		case 27:
			if len(h.CompressCertAlgs) == 0 {
				return nil, fmt.Errorf("%w: 27 with no compress_certificate_algorithms", ErrNoBuilder)
			}
			body = vec8(nil, u16s(h.CompressCertAlgs))
		case 43:
			body = vec8(nil, u16s(h.SupportedVersions))
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
	ch := u16(nil, h.LegacyVersion)
	ch = append(ch, random...)
	ch = vec8(ch, sid)
	ch = vec16(ch, u16s(h.CipherSuites))
	ch = append(ch, 1, 0) // compression: null only
	ch = vec16(ch, exts)
	hs := append([]byte{1, byte(len(ch) >> 16), byte(len(ch) >> 8), byte(len(ch))}, ch...)
	return vec16([]byte{22, 3, 1}, hs), nil
}

// Probe sends the device's ClientHello, reads port49's ServerHello and closes.
// port49 counts the abandoned handshake against the source, so a probe runs
// on a daemon of its own (spec §13 decisions 50 and 52).
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
		return ServerHello{}, errors.New("devicemock: port49 answered the hello with an alert")
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

- [ ] **Step 5: Implement `tlsconf.go`**

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
// curve order (x448, which the library lacks, is left out), ALPN and client
// chain. Suite order and signature algorithms are the library's; the hello
// probe carries the device's exactly. The server's certificate is checked as
// the device was measured to (server_identity). An IP-literal SNI is never
// sent here (crypto/tls omits it), only by the probe: an engine gap each
// profile that has one lists.
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
	cfg.InsecureSkipVerify = true // replaced by VerifyConnection: the chain always, names as measured
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("devicemock: no server certificate")
		}
		opts := x509.VerifyOptions{Roots: m.ServerCAs, Intermediates: x509.NewCertPool()}
		for _, c := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(c)
		}
		if s.ServerIdentity == "ip" || s.ServerIdentity == "dns" {
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

- [ ] **Step 6: Run**

Run: `go test ./internal/devicemock/ -count=1 && make lab-unit && GOOS=darwin go vet ./internal/devicemock/`
Expected: PASS; vet clean.

- [ ] **Step 7: Commit**

```bash
git add internal/devicemock tests/lab/l73_tlswire.go tests/lab/l73_tlswire_unit_test.go
git commit -m "feat(devicemock): the device's exact ClientHello as a probe, and its flight delay

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 9: The engine — `Play`, goldens and `Judge`

**Files:**
- Create: `internal/devicemock/engine.go`, `internal/devicemock/golden.go`, `internal/devicemock/fragment.go`, `internal/devicemock/engine_test.go`, `internal/devicemock/golden_test.go`, `internal/devicemock/fragment_test.go`, `internal/devicemock/fakeserver_test.go`

**Interfaces:**
- Consumes: Tasks 6–8.
- Produces:

```go
type Target struct {
	Addr      string       // the listener
	Transport string       // tcp, tls
	Key       []byte       // tcp: the shared key, fresh per test
	TLS       *TLSMaterial // tls
	LocalAddr string       // the source address; "" for the default (fleet mode: 127.0.1.N)
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
	Args          []string // authorization reply arguments (priv-lvl, roles, classes; no secret)
	ServerMsgLen  int      // a length, never the text
	SingleConnect bool
	Conn          int
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
// PlayedSteps is the step names Play plays for a scenario, in order:
// token_login, tls_token_login and single_connection play every stimulus
// step; wrong_credential, store_unavailable, tls_store_unavailable,
// flight_delay and tls_unknown_ca play login alone. Play
// uses it, and genprofile builds goldens to it, so the two cannot disagree.
func PlayedSteps(p *Profile, scenario string) []string

type GoldenStep struct {
	Step  string   `json:"step"`
	Event string   `json:"event"`
	Args  []string `json:"args,omitempty"`
}
type GoldenScenario struct {
	Outcome string       `json:"outcome"`
	Steps   []GoldenStep `json:"steps"`
}
type Golden struct {
	PendingLab bool                      `json:"pending_lab"`
	Scenarios  map[string]GoldenScenario `json:"scenarios"`
}
func LoadGolden(path string) (Golden, error)
func WriteGolden(path string, g Golden) error // indent 2, keys sorted, trailing newline
func GoldenFrom(tr Transcript) GoldenScenario
func Judge(tr Transcript, want GoldenScenario) (fails, warns []string)

func MergeFragment(base, fragment []byte) ([]byte, error) // the fragment's top-level keys replace base's
```

**Scenarios:**
- `token_login`: every step, in order.
- `wrong_credential`: `login` with a credential the engine makes from random bytes, which is never a token.
- `store_unavailable`: `login` (the harness has set the fault).
- `single_connection`: every step with the single-connect flag on.
- `tls_unknown_ca`: the handshake, then `login`. A TLS 1.3 client's handshake succeeds before port49 judges the certificate, so the refusal (an alert or a reset) is seen on the login and recorded as the class event `tls_refused`, with outcome `handshake_refused` (I-H).
- `tls_token_login`, `tls_store_unavailable`: as their plain names, over TLS.

`Play` plays `BaseScenario(scenario)` over `t.Transport`. The harness sets `t.Transport = ScenarioTransport(scenario)` and admits the device on that transport (I-B). `Play` returns an error when the two disagree.
- `flight_delay`: the `login` step on the delayed connection (I2).

**Order inside a step** (M5). The engine checks acceptance on the reply first. A gate ends the play `rejected_by_device` before any reaction is looked up, so a gate on an event no reaction covers still reports the gate.

- [ ] **Step 1: Write the fake server** (`fakeserver_test.go`). It answers each request type with a configured status and arguments. When `echo` is set it puts the request's `data` into `server_msg` (Review Focus 1). It counts connections and honours the single-connect flag.

```go
type fake struct {
	ln                  net.Listener
	key                 []byte
	authen              []uint8 // statuses in turn, e.g. {GetPass, Pass} for ASCII
	authorArgs          [][]byte
	echo, singleConnect bool
	conns               atomic.Int32
}

func newFake(t *testing.T, key []byte) *fake {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fake{ln: ln, key: key}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			go f.serve(c)
		}
	}()
	return f
}
```

`serve` loops while the connection is open:
1. Read a 12-byte header with `wire.DecodeHeader`, then the body, de-obfuscated with `wire.Obfuscate(h, f.key, body)`.
2. Answer by type:
   - **authen:** pop the next status from `f.authen`. A START or a CONTINUE is decoded with `wire.DecodeAuthenStart` or `wire.DecodeAuthenContinue`, and its data goes into `server_msg` when `echo` is set. The reply is `wire.AuthenReply{Status: s, ServerMsg: …}.Encode()` at `SeqNo+1`.
   - **author:** `wire.AuthorResponse{Status: wire.AuthorStatusPassAdd, Args: f.authorArgs}`.
   - **acct:** `wire.AcctReply{Status: wire.AcctStatusSuccess}`.
3. Set `wire.FlagSingleConnect` in the reply header when `f.singleConnect` is set and the request had it.
4. Close the connection unless both sides agreed to single-connection.

- [ ] **Step 2: Write the failing tests** (`engine_test.go`, `golden_test.go`, `fragment_test.go`):

```go
func freshCredential(t *testing.T) []byte {
	b := make([]byte, 24)
	rand.Read(b)
	return []byte(hex.EncodeToString(b))
}

func playFake(t *testing.T, profile string, f *fake, scenario string, cred []byte) (Transcript, error) {
	p, err := Load("testdata/profiles/"+profile, root)
	if err != nil {
		t.Fatal(err)
	}
	return Play(t.Context(), p, scenario, Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
		Login{User: "q", Credential: cred, RemAddr: "198.51.100.4"})
}

func TestTokenLoginPlaysEveryStepOneConnectionEach(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	tr, err := playFake(t, "fixture_plain.yaml", f, "token_login", freshCredential(t))
	if err != nil {
		t.Fatal(err)
	}
	if tr.Outcome != "login_ok" || len(tr.Steps) != 3 || tr.Conns != 3 || f.conns.Load() != 3 {
		t.Fatalf("%s", tr)
	}
}

func TestAGatedViolationEndsThePlayBeforeAnyReaction(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = longArgs()
	tr, err := playFake(t, "fixture_junos.yaml", f, "token_login", freshCredential(t))
	if err != nil || len(tr.Gate) != 1 || tr.Outcome != "rejected_by_device" {
		t.Fatalf("the device would lock the user out; the play says so: %v\n%s", err, tr)
	}
}

func TestTranscriptNeverHoldsTheCredential(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen, f.echo = []uint8{wire.AuthenStatusFail}, true
	cred := freshCredential(t)
	tr, err := playFake(t, "fixture_plain.yaml", f, "token_login", cred)
	all := tr.String() + fmt.Sprint(err) + fmt.Sprintf("%+v %#v", tr, tr)
	if strings.Contains(all, string(cred)) {
		t.Fatal("the credential reached the transcript or its error")
	}
	if tr.Steps[0].ServerMsgLen == 0 {
		t.Fatal("the echoed server_msg is measured by its length")
	}
}

func TestAnEventWithNoReactionIsAnError(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusGetPass} // fixture_plain covers no GETPASS
	_, err := playFake(t, "fixture_plain.yaml", f, "token_login", freshCredential(t))
	if err == nil || !strings.Contains(err.Error(), "no reaction for authen_getpass") {
		t.Fatalf("%v", err)
	}
}

func TestAnASCIILoginSendsTheCredentialOnGetPass(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusGetPass, wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Stimulus.Steps[0].Fields.AuthenType, p.Stimulus.Steps[0].MinorVersion = "ascii", 0
	p.Reactions = append(p.Reactions, Reaction{Step: "login", On: "authen_getpass", Then: "send_credential", Status: "unmeasured"})
	tr, err := Play(t.Context(), p, "token_login", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "login_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
}

func TestSingleConnectionReusesOnlyWhenTheServerAgrees(t *testing.T) {
	for _, agree := range []bool{true, false} {
		f := newFake(t, []byte("fresh-key"))
		f.authen, f.singleConnect = []uint8{wire.AuthenStatusPass}, agree
		f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
		p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
		p.Reactions = append(p.Reactions, Reaction{Step: "*", On: "reply_single_connect", Then: "reuse_connection", Status: "unmeasured"})
		tr, err := Play(t.Context(), p, "single_connection", Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1},
			Login{User: "q", Credential: freshCredential(t)})
		if err != nil {
			t.Fatal(err)
		}
		if want := map[bool]int{true: 1, false: 3}[agree]; tr.Conns != want {
			t.Fatalf("server agrees %v: %d connections, want %d", agree, tr.Conns, want)
		}
	}
}

// A real tls.Server that refuses the client's certificate in VerifyConnection,
// as port49's listener does: the client's Handshake returns nil (TLS 1.3), and
// the refusal reaches the first read as a *net.OpError "remote error", which
// handshakeEvent names; tls_unknown_ca plays its login and ends tls_refused.
func TestARefusedCertificateIsSeenOnTheLoginAsTLSRefused(t *testing.T) {
	ca, other := testCA(t, "trusted"), testCA(t, "untrusted")
	srvCert := issue(t, ca, false)
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{srvCert},
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAnyClientCert,
		VerifyConnection: func(tls.ConnectionState) error { return x509.UnknownAuthorityError{} }})
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { c.(*tls.Conn).Handshake(); c.Read(make([]byte, 1)); c.Close() }()
		}
	}()
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	p.Transports = []string{"tls"}
	p.Stimulus.TLS = &TLSStimulus{ClientHello: nxosHello(), ServerIdentity: "chain_only"}
	tr, err := Play(t.Context(), p, "tls_unknown_ca", Target{Addr: ln.Addr().String(), Transport: "tls", Scale: 1,
		TLS: &TLSMaterial{Client: issue(t, other, true), ServerCAs: ca.Pool(), ServerIP: "127.0.0.1"}},
		Login{User: "q", Credential: freshCredential(t)})
	if err != nil || tr.Outcome != "handshake_refused" || tr.Steps[0].Event != "tls_refused" {
		t.Fatalf("%v\n%s", err, tr)
	}
}

// testCA and issue are testpki.NewCA and (*CA).Issue for a 127.0.0.1 server
// leaf or a client leaf, per test. The names below are crypto/tls's own
// alert texts (alert.go), so the map is exact; the real-server test above
// proves the OpError shape end to end.
func TestHandshakeEventNamesARemoteAlert(t *testing.T) {
	for text, want := range map[string]string{
		"tls: bad certificate":               "alert_bad_certificate",
		"tls: unknown certificate authority": "alert_unknown_ca",
		"tls: expired certificate":           "alert_certificate_expired",
		"tls: handshake failure":             "alert_handshake_failure",
		"tls: something new":                 "alert_other",
	} {
		err := &net.OpError{Op: "remote error", Err: errors.New(text)}
		if got := handshakeEvent(err); got != want {
			t.Errorf("%q: %s, want %s", text, got, want)
		}
	}
}

// golden_test.go
func TestGoldenRoundTrips(t *testing.T) {
	g := Golden{PendingLab: true, Scenarios: map[string]GoldenScenario{"token_login": {Outcome: "login_ok",
		Steps: []GoldenStep{{Step: "login", Event: "authen_pass"}, {Step: "authorize_session", Event: "author_pass_add", Args: []string{"priv-lvl=15"}}}}}}
	path := filepath.Join(t.TempDir(), "g.json")
	if err := WriteGolden(path, g); err != nil {
		t.Fatal(err)
	}
	back, err := LoadGolden(path)
	if err != nil || !reflect.DeepEqual(back, g) {
		t.Fatalf("%+v %v", back, err)
	}
}

func TestJudgeTurnsAMeasuredGateIntoAFailureAndAnUnmeasuredOneIntoAWarning(t *testing.T) {
	want := GoldenScenario{Outcome: "login_ok"}
	tr := Transcript{Scenario: "token_login", Outcome: "rejected_by_device",
		Gate: []Violation{{Rule: "junos_reply_total", Effect: "lockout", Detail: "300 bytes", Measured: true}}}
	fails, _ := Judge(tr, want)
	if len(fails) == 0 || !strings.Contains(strings.Join(fails, "\n"), "junos_reply_total") {
		t.Fatalf("a measured gate fails, naming its rule: %q", fails)
	}
	tr = Transcript{Scenario: "token_login", Outcome: "login_ok",
		Warn: []Violation{{Rule: "junos_reply_total", Detail: "300 bytes"}}}
	fails, warns := Judge(tr, want)
	if len(fails) != 0 || len(warns) != 1 {
		t.Fatalf("an unmeasured rule warns and never fails: %q %q", fails, warns)
	}
}

func TestJudgeNamesAGoldenDifference(t *testing.T) {
	want := GoldenScenario{Outcome: "login_ok", Steps: []GoldenStep{{Step: "login", Event: "authen_pass"}}}
	tr := Transcript{Scenario: "token_login", Outcome: "login_refused", Steps: []StepResult{{Step: "login", Event: "authen_fail"}}}
	if fails, _ := Judge(tr, want); len(fails) == 0 {
		t.Fatal("a reply that moved from the golden fails")
	}
}

// fragment_test.go
func TestMergeFragmentReplacesTopLevelKeys(t *testing.T) {
	out, err := MergeFragment([]byte("listen: a\nsession:\n  staleness_ceiling: 0s\nlab:\n  x: 1\n"),
		[]byte("session:\n  staleness_ceiling: 0s\n  max_session_age_default: 1h\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Count(s, "session:") != 1 || !strings.Contains(s, "max_session_age_default: 1h") || !strings.Contains(s, "listen: a") {
		t.Fatalf("%s", s)
	}
}
```

- [ ] **Step 3: Run to verify they fail**

Run: `go test ./internal/devicemock/ -count=1`
Expected: FAIL (`undefined: Play`, `Golden`, `MergeFragment`).

- [ ] **Step 4: Implement `engine.go`**

```go
package devicemock

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/rhwendt/port49/internal/tacacs/wire"
)

// (Target, Login, StepResult, Transcript as in Interfaces.)

type player struct {
	p      *Profile
	t      Target
	l      Login
	tr     Transcript
	c      net.Conn
	reuse  bool
	nconns int
	now    time.Time
}

func Play(ctx context.Context, p *Profile, scenario string, t Target, l Login) (Transcript, error) {
	if ScenarioTransport(scenario) != t.Transport {
		return Transcript{}, fmt.Errorf("devicemock: scenario %s runs over %s, the target is %s", scenario, ScenarioTransport(scenario), t.Transport)
	}
	pl := &player{p: p, t: t, l: l, now: time.Now()}
	pl.tr.Scenario = scenario
	defer pl.closeConn()
	steps := p.Stimulus.Steps[:len(PlayedSteps(p, scenario))]
	switch BaseScenario(scenario) {
	case "wrong_credential":
		bogus := make([]byte, 24)
		rand.Read(bogus)
		pl.l.Credential = []byte(hex.EncodeToString(bogus))
		steps = steps[:1]
	case "store_unavailable", "flight_delay":
		steps = steps[:1]
	case "unknown_ca": // tls_unknown_ca
		// A TLS 1.3 client's Handshake returns nil once it has written its
		// Finished, before port49 judges the certificate (re-review I-H), so
		// the refusal is observed on the login that follows: a received alert,
		// or the reset port49 sends after it (which races the alert). Any of
		// those is the class event tls_refused.
		res, err := pl.step(ctx, steps[0])
		if err != nil || isRefusal(res.Event) {
			return pl.end("handshake_refused", StepResult{Step: steps[0].Name, Event: "tls_refused"}), nil
		}
		pl.tr.Steps = append(pl.tr.Steps, res)
		return pl.end("handshake_ok"), nil
	}
	for _, s := range steps {
		res, err := pl.step(ctx, s)
		if err != nil {
			if scenario == "flight_delay" || errors.Is(err, errConn) {
				return pl.end("handshake_refused", StepResult{Step: s.Name, Event: handshakeEvent(err)}), nil
			}
			return pl.tr, err
		}
		pl.tr.Steps = append(pl.tr.Steps, res)
		if len(pl.tr.Gate) > 0 { // the device rejects port49's reply before it reacts to it
			return pl.end("rejected_by_device"), nil
		}
		r, err := p.React(s.Name, res.Event)
		if err != nil {
			return pl.tr, err
		}
		if res.SingleConnect {
			if rr, err := p.React(s.Name, "reply_single_connect"); err == nil && rr.Then == "reuse_connection" {
				pl.reuse = true
			}
		}
		switch r.Then {
		case "next_step", "reuse_connection", "new_connection":
			continue
		default:
			return pl.end(r.Outcome), nil
		}
	}
	return pl.end("login_ok"), nil
}

func (pl *player) end(outcome string, extra ...StepResult) Transcript {
	pl.tr.Steps = append(pl.tr.Steps, extra...)
	pl.tr.Outcome, pl.tr.Conns = outcome, pl.nconns
	return pl.tr
}

func PlayedSteps(p *Profile, scenario string) []string {
	switch BaseScenario(scenario) {
	case "wrong_credential", "store_unavailable", "flight_delay", "unknown_ca":
		return []string{p.Stimulus.Steps[0].Name}
	}
	names := make([]string, len(p.Stimulus.Steps))
	for i, s := range p.Stimulus.Steps {
		names[i] = s.Name
	}
	return names
}
```

The rest of `engine.go`:

- **`errConn`**: a sentinel for a dial, handshake or read failure. Errors wrap it, with the step and the event and nothing else.
- **`dial(ctx)`**:
  - a `net.Dialer` whose `LocalAddr` is `&net.TCPAddr{IP: net.ParseIP(t.LocalAddr)}` when `t.LocalAddr` is not empty;
  - over `tls`, `c = DelayFlight(c, scaled(p.Stimulus.TLS.FlightDelay), t.Sleep)`, then `tls.Client(c, SessionConfig(p.Stimulus.TLS, *t.TLS))` and `HandshakeContext`;
  - it increments `nconns`.
- **`scaled(d)`**: `time.Duration(float64(d) * t.Scale)`.
- **`step(ctx, s)`**:
  - **The connection.** Reuse the open one when `pl.reuse`; otherwise close it and dial.
  - **The header.** `{MajorVersion: 0xc, MinorVersion: s.MinorVersion, Type, SeqNo: 1, Flags, SessionID: a random uint32, Length}`. The minor version is the step's measured value, never derived.
    - `Flags` carries `wire.FlagSingleConnect` when the scenario is `single_connection` or `Connections.SingleConnectFlag` is set.
    - Over tls it carries `wire.FlagUnencrypted` and the body is sent clear; over tcp the body is obfuscated with `t.Key`.
  - **authen.** An `AuthenStart` built from `Codes` (`action`, `authen_type`, `service`), `PrivLvl`, `User: l.User`, `Port: s.Port`, `RemAddr: l.RemAddr`, and `Data` = the credential when `authen_type` is pap, empty otherwise.
    - On a reply whose event's reaction is `send_credential`, it sends `AuthenContinue{UserMsg: credential}` at seq+2 within the same step, and the step's event is that second reply's.
  - **author.** An `AuthorRequest` with `Args` = `expand(s.Args)`, and the method from `Codes`.
  - **acct.** An `AcctRequest` with `Flags` from `s.Flags` (`start` → `wire.AcctFlagStart`, `stop` → `wire.AcctFlagStop`, `watchdog` → `wire.AcctFlagWatchdog`).
  - **The reply.** Read and decode it, then set:
    - `Event`: `authen_<pass|fail|getpass|getuser|getdata|error>`, `author_<pass_add|pass_repl|fail|error>` or `acct_<success|error>`;
    - `Args` for an author reply;
    - `ServerMsgLen = len(server_msg)`;
    - `SingleConnect` from the reply header's flag.
  - **Acceptance.** For an `authorize_session` or `command_permitted` reply, call `Check(p.Acceptance, s.Name, reply.Args)` and append to `tr.Gate` and `tr.Warn`.
- **`expand(args)`** replaces:
  - `{user}` → `l.User`;
  - `{rem_addr}` → `l.RemAddr`;
  - `{task_id}` → `pl.now.UnixNano()%100000`;
  - `{start_time}` and `{stop_time}` → `pl.now.Unix()`.

  It never puts the credential into an argument.
- **`handshakeEvent(err)`**:
  - **A received alert.** It arrives as a `*net.OpError` with `Op == "remote error"`, whose `Err` text is `tls: <description>`. `tls.AlertError` is QUIC's type and never matches here (re-review I-H). It maps by that text to `alert_<snake_case description>`: `bad certificate` → `alert_bad_certificate` (42, which crypto/tls sends for any `VerifyConnection` error, `internal/daemon/server/tls.go:262-268`), `unknown certificate authority` → `alert_unknown_ca`, `expired certificate` → `alert_certificate_expired`, `handshake failure` → `alert_handshake_failure`; any other description → `alert_other`.
  - **`isRefusal(event)`** is true for any `alert_*`, `conn_reset` or `conn_closed` event.
  - `syscall.ECONNRESET` and `syscall.EPIPE` map to `conn_reset` (a write after a reset that was already read gives EPIPE);
  - `io.EOF` maps to `conn_closed`;
  - a deadline maps to `handshake_timeout`.
- **`Transcript.String()`** prints one line per step (`step event args=[…] server_msg=<n> bytes conn=<k>`), then the outcome, then the gates and warnings by rule id and detail. It is the only form tests print.

- [ ] **Step 5: Implement `golden.go`**

```go
package devicemock

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// (GoldenStep, GoldenScenario, Golden as in Interfaces.)

func LoadGolden(path string) (Golden, error) {
	var g Golden
	raw, err := os.ReadFile(path)
	if err != nil {
		return g, err
	}
	return g, json.Unmarshal(raw, &g)
}

func WriteGolden(path string, g Golden) error {
	b, err := json.MarshalIndent(g, "", "  ") // map keys marshal sorted
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// GoldenFrom keeps what port49 answered: each step's event and reply
// arguments and the outcome. A Transcript holds no credential, so neither
// does a golden.
func GoldenFrom(tr Transcript) GoldenScenario {
	g := GoldenScenario{Outcome: tr.Outcome}
	for _, s := range tr.Steps {
		g.Steps = append(g.Steps, GoldenStep{Step: s.Step, Event: s.Event, Args: s.Args})
	}
	return g
}

// Judge is a play's verdict against its golden: each measured gate is a
// failure line naming its rule; each unmeasured rule a warning; a reply that
// moved from the golden a failure naming the scenario. TestQual fails on any
// failure line, so a dropped gate cannot pass silently.
func Judge(tr Transcript, want GoldenScenario) (fails, warns []string) {
	for _, v := range tr.Gate {
		fails = append(fails, fmt.Sprintf("%s: acceptance rule %s (%s): %s", tr.Scenario, v.Rule, v.Effect, v.Detail))
	}
	for _, v := range tr.Warn {
		warns = append(warns, fmt.Sprintf("%s: unmeasured acceptance rule %s: %s", tr.Scenario, v.Rule, v.Detail))
	}
	got := GoldenFrom(tr)
	if got.Outcome != want.Outcome || !slices.EqualFunc(got.Steps, want.Steps, func(a, b GoldenStep) bool {
		return a.Step == b.Step && a.Event == b.Event && slices.Equal(a.Args, b.Args)
	}) {
		fails = append(fails, fmt.Sprintf("%s: port49's replies moved from the golden (run make qual-update if on purpose)", tr.Scenario))
	}
	return fails, warns
}
```

- [ ] **Step 6: Implement `fragment.go`**

```go
package devicemock

import (
	"bytes"

	"gopkg.in/yaml.v3"
)

// MergeFragment puts fragment's top-level keys into base, replacing a key
// base already has: the one way the lab conformance config and the mock's
// config take the shared reply-shaping settings (decision 52 ruling 5).
func MergeFragment(base, fragment []byte) ([]byte, error) {
	var b, f yaml.Node
	if err := yaml.Unmarshal(base, &b); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(fragment, &f); err != nil {
		return nil, err
	}
	bm, fm := b.Content[0], f.Content[0]
	for i := 0; i+1 < len(fm.Content); i += 2 {
		replaced := false
		for j := 0; j+1 < len(bm.Content); j += 2 {
			if bm.Content[j].Value == fm.Content[i].Value {
				bm.Content[j+1] = fm.Content[i+1]
				replaced = true
			}
		}
		if !replaced {
			bm.Content = append(bm.Content, fm.Content[i], fm.Content[i+1])
		}
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&b); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
```

- [ ] **Step 7: Run**

Run: `go test ./internal/devicemock/ -count=1 -race && GOOS=darwin go vet ./internal/devicemock/`
Expected: PASS; vet clean.

- [ ] **Step 8: Commit**

```bash
git add internal/devicemock
git commit -m "feat(devicemock): the engine, one golden format, and Judge from gate to failure

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 10: `TestQual` — every profile against a real in-process port49d

**Files:**
- Create: `internal/port49d/qual_test.go`, `tests/qual/qual-policy.yaml`, `tests/qual/qual-daemon.yaml`, `internal/devicemock/testdata/profiles/fixture_nxos_flight.yaml`
- Test: `internal/port49d/qual_test.go`

**Interfaces:**
- Consumes:
  - from devicemock: `Load`, `Play`, `Probe`, `TLSMaterial`, `LoadGolden`, `WriteGolden`, `GoldenFrom`, `Judge`, `MergeFragment`;
  - from `internal/port49d`'s tests: `run(ctx, cfgPath)`, `stderr`/`stdout`, `syncBuffer`, `brokerConfig`, `writeRunConfigWith`, `mint`;
  - `testpki`.
- Produces:
  - `type qualOpts struct { policy string; scale float64; handshakeTimeout time.Duration; devices int; transport string; untrustedClient bool }`. `transport` is `devicemock.ScenarioTransport(sc)`; "" means the profile's first transport. `untrustedClient` issues the device's leaf from a CA the daemon does not trust (`tls_unknown_ca`);
  - `func qualDaemon(t *testing.T, p *devicemock.Profile, o qualOpts) *qualRun`, with methods `target(p, i)`, `login(i)`, `fault(code)`, `logged(sub) bool`, `addr`;
  - `func qualWaitFor(t *testing.T, buf *syncBuffer, want string, d time.Duration)`;
  - env `PORT49_QUAL_UPDATE=1` rewrites goldens as `pending_lab`.

- [ ] **Step 1: The policy and the shared fragment.** `tests/qual/qual-policy.yaml`:

```yaml
# The qualification policy (plan 11b, decision 52 ruling 5): the broker's policy in every lab
# conformance run (TestQualify) and every mock (TestQual), so a golden from the lab is the mock's
# expectation. Changing it changes every golden: run `make qual-update`, review the diff; the next
# release tag's lab run re-vets.
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: qual_admin, privilege: admin, permit: ["**"]}
  # show users is safe on every platform; never a command that changes a device here.
  - {name: qual_denies, deny: ["show users"]}
subjects:
  # Both identities: the mock's broker issues alice@example.com (testpki.WriteLabWith), the lab's
  # slice PKI alice@slice.port49.test (tests/lab/slice_test.go).
  - {name: qual_operator, identity: ["user:alice@example.com", "user:alice@slice.port49.test"], username: qual01, token_ttl: 60s}
grants:
  - {subject: qual_operator, scope: all_devices, roles: [qual_admin, qual_denies], max_privilege: admin}
```

`tests/qual/qual-daemon.yaml`:

```yaml
# Every daemon key that shapes a reply, shared byte for byte by the lab conformance run
# (tests/lab qualConfig) and the mock (internal/port49d qualDaemon), merged into each with
# devicemock.MergeFragment (decision 52 ruling 5). Nothing else goes here; nothing that shapes a
# reply goes anywhere else. Platform overrides would go here; there are none.
session:
  staleness_ceiling: 0s
```

- [ ] **Step 2: The NX-OS flight fixture** (M8), so the timing tests bite from this task. `internal/devicemock/testdata/profiles/fixture_nxos_flight.yaml` is a TLS profile:
  - `platform: cisco_nxos`, `firmware: "Nexus 9300v 10.6(2)F"`, `transports: [tls]`, `scenarios: [flight_delay]`;
  - the `client_hello` of Task 8's `nxosHello()`;
  - `server_hello: {selected_version: 772, cipher_suite: 4865, hello_retry_request: false}`;
  - `flight_delay: 5s`, `server_identity: chain_only`;
  - one `login` step (pap, minor version 1);
  - a reaction `{step: login, on: authen_pass, then: next_step, status: measured}`;
  - every source cites `tests/lab/results/L73-cisco_nxos.md` (register `L73`), whose Image version line names `10.6(2)F`. It loads with `repoRoot` `../..` from `internal/port49d`.

- [ ] **Step 3: Write the failing tests** in `internal/port49d/qual_test.go`:

```go
package port49d

// TestQual plays every profile in tests/qual/profiles against a real port49d
// under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml, with
// tokens the broker mints (plan 11b; spec §13 decision 52). Per PR, at 0.1
// time scale against handshake_timeout 1s: production's ratio.

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
		tr, err := devicemock.Play(t.Context(), p, "token_login", run.target(p, 0), run.login(0))
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
		fails, _ := devicemock.Judge(tr, devicemock.GoldenFrom(tr)) // against itself: only gates can fail
		if (len(fails) > 0) != c.gated {
			t.Fatalf("%s: failures %q, gated want %v\n%s", c.profile, fails, c.gated, tr)
		}
	}
}

func TestQualNXOSRealFlightUnderTheDefault(t *testing.T) {
	// The real numbers once: the N9Kv's 5.00 s flight (tests/lab/results/L73-cisco_nxos.md)
	// against the 10s default handshake_timeout, judged from port49's log: the device was
	// served, not merely finished writing (a TLS 1.3 client is done when it writes).
	p := qualFixture(t, "fixture_nxos_flight.yaml")
	run := qualDaemon(t, p, qualOpts{scale: 1}) // handshakeTimeout 0: the daemon's default
	tr, err := devicemock.Play(t.Context(), p, "flight_delay", run.target(p, 0), run.login(0))
	if err != nil || tr.Outcome != "login_ok" {
		t.Fatalf("%v\n%s", err, tr)
	}
	// login_ok needs a PASS over TLS, which only a served device gets; the log
	// check adds that no handshake timed out on the way.
	if run.logged(`"tls_outcome":"handshake_timeout"`) {
		t.Fatal("a handshake timed out at the real flight delay under the default")
	}
}

func TestQualAFlightPastTheTimeoutIsHandshakeTimeout(t *testing.T) {
	p := qualFixture(t, "fixture_nxos_flight.yaml")
	run := qualDaemon(t, p, qualOpts{scale: 0.3, handshakeTimeout: time.Second}) // 1.5 s against 1 s
	tr, _ := devicemock.Play(t.Context(), p, "flight_delay", run.target(p, 0), run.login(0))
	if tr.Outcome != "handshake_refused" || !run.logged(`"tls_outcome":"handshake_timeout"`) {
		t.Fatalf("a flight past handshake_timeout is refused as handshake_timeout\n%s", tr)
	}
	if ev := tr.Steps[len(tr.Steps)-1].Event; ev != "conn_reset" && ev != "conn_closed" {
		t.Fatalf("the device sees port49 end the connection: %q", ev)
	}
}

func TestQualWaitForPrintsNoHash(t *testing.T) {
	var buf syncBuffer
	buf.Write([]byte(`{"event":"redeem","auth":{"credential_sha256":"` + strings.Repeat("a", 64) + `"}}` + "\n"))
	msg := qualWaitMessage(&buf, "never")
	if strings.Contains(msg, "_sha256") || strings.Contains(msg, strings.Repeat("a", 64)) {
		t.Fatalf("a failure message carried a hash: %q", msg)
	}
	if !strings.Contains(msg, "redeem") {
		t.Fatalf("it still names the events seen: %q", msg)
	}
}

func TestQualSharesTheFragmentWithTheLab(t *testing.T) {
	p := qualFixture(t, "fixture_nxos_flight.yaml")
	run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second})
	frag, _ := os.ReadFile("../../tests/qual/qual-daemon.yaml")
	cfg, _ := os.ReadFile(run.cfgPath)
	merged, _ := devicemock.MergeFragment(frag, frag)
	for _, line := range strings.Split(strings.TrimSpace(string(merged)), "\n") {
		if !strings.Contains(string(cfg), line) {
			t.Fatalf("the mock's config lacks the shared fragment's %q", line)
		}
	}
}
```

Write `qualLongJunosRole` as a role with `privilege: readonly`, ten narrow `permit` entries (`show interfaces terse`, `show route summary`, …) and ten `deny` entries (`show security **`, …). Size it so that juniper_junos's projection renders `allow-commands` and `deny-commands` each under 255 and together over 255. The test's precondition fails loudly if it no longer does.

`qualPolicyWith(t, role)` writes the qual policy with `role` added and granted.

`qualFixture(t, name)` loads `../devicemock/testdata/profiles/<name>` with `repoRoot` `../..` for the NX-OS fixture, or `../devicemock/testdata` for the others.

- [ ] **Step 4: Run to verify they fail**

Run: `go test ./internal/port49d/ -run '^TestQual' -count=1`
Expected: FAIL (`undefined: qualDaemon`).

- [ ] **Step 5: Implement the harness** in the same file.

- **`qualDaemon`**:
  - **Output.** Point `stderr`/`stdout` at `syncBuffer`s, kept as `run.stderr` and `run.log` and restored in `t.Cleanup`.
  - **Broker.** `brokerConfig(t, policy)`, with the qual policy unless `o.policy` is set. Tokens come only from the broker's mint: there is no lab seed.
  - **Inventory.** One device per `max(o.devices, 1)`, named `q%04d` and addressed at `devicemock.LoopbackSource(i)` (Task 19) when `o.devices > 1`; otherwise one device, `q0000`, at 127.0.0.1. Each device takes `platform: <p.Platform>`.
    - **`o.transport == "tls"`** (the scenario's `ScenarioTransport`; "" means the profile's first transport) sets `transport: tls` on each device. Issue, per test with `testpki`, a device CA, a server certificate for 127.0.0.1, and one client certificate per device naming it. With **`o.untrustedClient`**, the client certificates come from a second CA that is not in `client_ca_file` (`tls_unknown_ca`).
    - **`o.transport == "tcp"`** gets a key group for 127.0.0.0/8 with a fresh 32-byte hex key in `T_RUN_SECRET`.
  - **Config.** Build the run config with `writeRunConfigWith(…)`. Append the `tls_listener:` block, with `handshake_timeout: <o.handshakeTimeout>` when it is not zero, and `lab: {fault_file: <tmp>}`. Then rewrite the file through `devicemock.MergeFragment(cfg, tests/qual/qual-daemon.yaml)` and record `run.cfgPath`.
  - **Start.** Run `run(ctx, cfg)` and wait for both listening lines with `qualWaitFor`.
- **`qualWaitFor(t, buf, want, d)`** polls for `want`. On timeout it fails with `qualWaitMessage(buf, want)`, never the buffer: that message lists the `event` and `reason` of the last 20 JSON lines and the non-JSON lines that contain no `_sha256` (I12).
- **`run.login(i)`** returns `devicemock.Login{User: "qual01", Credential: []byte(mint(t, brokerAddr, pkiDir, deviceName(i))), RemAddr: "198.51.100.4"}`. It mints fresh on every call; the token is never printed.
- **`run.target(p, i)`** returns a `devicemock.Target` with:
  - `Transport: o.transport`;
  - `Addr`: the RFC 9887 listener for `tls`, the plain one for `tcp`;
  - `Key` (tcp) or `TLS` (the device's own client certificate and the server CA pool);
  - `Scale: o.scale`;
  - `LocalAddr: LoopbackSource(i)` when `o.devices > 1`.
- **`run.fault(code)`** writes the fault file, and calls no `t` helper (fleet mode calls it from a goroutine): a write error is kept and checked by the test goroutine.
- **`run.logged(s)`** searches the decision-log buffer; **`run.said(s)`** searches port49d's stderr buffer.
- **`run.touchPolicy()`** is described in Task 19.
- **`qualProfile(t, p, root)`**:
  1. Load the golden (`root/<p.Golden>`; a missing file is an empty golden).
  2. For each scenario in `p.Scenarios`, start a fresh daemon at scale 0.1 with `handshakeTimeout: time.Second`. The device is admitted with `transport: devicemock.ScenarioTransport(sc)` (I-B): `qualOpts` gains `transport string`, which decides the inventory's `transport:` and whether the TLS material is issued; `run.target` sets the same. Before `store_unavailable` and `tls_store_unavailable`, call `run.fault("store_unavailable")`. For `tls_unknown_ca`, the device's client certificate is issued by a second CA that the daemon's `client_ca_file` does not hold. After the play, `qualProfile` also requires `run.logged(`"diagnosis":"tls_refused"`)` and `run.logged(`"tls_outcome":"unknown_ca"`)`. This way a port49 that accepted the untrusted device fails, even if the mock happened to see a reset for another reason. These are substring checks: nothing from that record is printed. Play the scenario with a fresh `run.login(0)`, then `fails, warns := devicemock.Judge(tr, g.Scenarios[sc])`.
     - Each warn is `t.Log`ged.
     - With `PORT49_QUAL_UPDATE=1`, a golden difference is rewritten: `g.Scenarios[sc] = GoldenFrom(tr)` and `g.PendingLab = true`. A gate still fails.
     - Otherwise each fail is `t.Error`ed, with `tr.String()` and the golden scenario printed.
  3. For a TLS profile, run the hello probe on its own daemon: `devicemock.Probe(...)` must equal `p.Stimulus.TLS.ServerHello`.
  4. On update, `devicemock.WriteGolden`. Then assert the golden bytes contain neither a minted credential (keep each minted value in a slice for this check only) nor `_sha256`.

- [ ] **Step 6: Run**

Run: `go test ./internal/port49d/ -run '^TestQual' -count=1 -v 2>&1 | grep -E '^(=== RUN|--- |PASS|FAIL|ok)'`
Expected:
- `TestQual` SKIPs (no profiles yet);
- `TestQualFixtureJunosRuleFailsWhatThePlainFixturePasses` PASSes;
- `TestQualNXOSRealFlightUnderTheDefault` PASSes in about 5 s;
- `TestQualAFlightPastTheTimeoutIsHandshakeTimeout`, `TestQualWaitForPrintsNoHash` and `TestQualSharesTheFragmentWithTheLab` PASS;
- `ok`.

- [ ] **Step 7: Commit**

```bash
git add internal/port49d/qual_test.go tests/qual/qual-policy.yaml tests/qual/qual-daemon.yaml internal/devicemock/testdata/profiles/fixture_nxos_flight.yaml
git commit -m "test: TestQual plays each profile against a real port49d under the shared policy and fragment

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 11: `make qual` and the mock tier's workflow

**Files:**
- Create: `.github/workflows/qual.yml`
- Modify: `Makefile`

- [ ] **Step 1: Makefile**

```make
# The mock tier (plan 11b): every profile against a real in-process port49d. No images,
# no captures, any runner. qual-update rewrites the goldens a port49 change moved, marked
# pending_lab until the next lab run.
qual:
	go test ./internal/devicemock/... ./tests/qual/... -count=1
	go test ./internal/port49d/ -run '^TestQual' -count=1 -timeout 20m

qual-update:
	PORT49_QUAL_UPDATE=1 go test ./internal/port49d/ -run '^TestQual$$' -count=1 -timeout 20m
```

- [ ] **Step 2: The workflow.** `runs-on` stays one line (decision 52 ruling 7): the runner is still Ryan's choice.

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
Expected: `ok` for each package; check-darwin clean.

- [ ] **Step 4: Commit**

```bash
git add Makefile .github/workflows/qual.yml
git commit -m "ci: the mock tier runs on every PR on any runner

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 12: `TestQualify` — the lab conformance run and its whitelisted evidence

**Files:**
- Create: `tests/lab/qual_evidence.go` (untagged, pure: `qualRecord`, `qualConfig`'s YAML transform, the cell table, the run record), `tests/lab/qual_evidence_unit_test.go`, `tests/lab/qualify_test.go`
- Modify: `Makefile` (`lab-qualify`), `tests/lab/README.md` (a "Qualification" section)

**Interfaces:**
- Consumes:
  - the lab harness: `platformSelection`, `labFor`, `labOccupyForRun`, `labGuardAt`, `l.capture`, `l.result`, `l.mark`, `l.recordsSince`, `l.loginWithin`, `l.dial`, `l.stopDaemon`, `l.startDaemonWith`, `l.awaitTACACS`, `l.configPath`, `privatePolicy`, `testpki.WriteLab`, `stopSliceAgent`, `agentPID`;
  - the L73 pieces: `l73Conns`, `l73SummaryLeaks`, `l73Dialects`, `newL73Env`, `l73DaemonYAML`, and the `l73Env` methods `enrol`, `configure`, `base`, `startOn`, `capture`, `restore`;
  - `labcreds.Contains`;
  - `devicemock.MergeFragment` and `devicemock.Slug`.
- Produces:
  - `func qualRecord(r map[string]any) (map[string]any, bool)`;
  - `func qualConfigYAML(lab, broker, fragment, policyPath string) (string, error)`;
  - `var qualCells []qualCell` (`{Name string; Rows []string}`);
  - `type qualRun struct { Platform, LabPlatform, Firmware, Image, Commit, Date string; Transports []string; Cells map[string]string; Registers map[string][]string }`, written as `run.json`.

**The evidence layout.** With `<slug>` = `devicemock.Slug(firmware)` and `<lp>` = the lab platform name:
- `tests/lab/evidence/QUAL-<slug>-<lp>/` holds `run.json`, `decisions.jsonl`, `<cell>.conns.json` (plain 49: connections and 12-byte headers only) and `<cell>.tls.json` (TLS).
- The capture is `l.capture(t, "QUAL-"+slug)`. Its redacted copy lands at `tests/lab/evidence/QUAL-<slug>-<lp>.pcap`, **beside** the directory and not in it, so the labpcap audit (`TestCommittedEvidenceMatchesTheCaptures`) finds it (I11) and genprofile never sees it.
- The note is `l.result(t, "QUAL-"+slug, …)`, written to `tests/lab/results/QUAL-<slug>-<lp>.md`. `registerRowClosed` sees no `L<N>` prefix, so the guard never refuses it.

**The conformance cells**, in a fixed order. Each cites the register rows it re-measures and closes none (decision 52 ruling 10).

| Cell | What | Re-measures |
|---|---|---|
| `token_login` | a broker-minted token login over SSH, running `show version` | L1, L15, L19 |
| `command_permitted` | `show version` authorized | L10, L21 |
| `command_denied` | `show users` refused | L21 |
| `accounting` | the login's start and stop records | L6 |
| `wrong_credential` | a random string as password, refused | L13 |
| `store_unavailable` | `fault_file: store_unavailable`, then break-glass | L4, L28 |
| `single_connection` | the startup config's single-connection form, then the plain sequence in one cell: `show version`, `show users`, the stop record | L15, L73 h |
| `tls_token_login` | (L73 dialects that are not `HelpOnly`) enrol, configure TLS, then the plain sequence in one cell: `show version`, `show users`, the stop record | L73 |
| `tls_store_unavailable` | the same over TLS with the fault | L73 i |
| `tls_unknown_ca` | the device presents a certificate from a CA port49 does not trust | L73 d |

Acceptance rules for the session reply (roles, attributes the device refuses) are not re-measured here. They cite L16 and L18 under decision 52 ruling 4.

- [ ] **Step 1: Write the failing pure tests** (`qual_evidence_unit_test.go`, tag `lab`, so `make lab-unit` runs them):

```go
func TestQualRecordKeepsOnlyTheWhitelist(t *testing.T) {
	in := map[string]any{"event": "redeem", "verdict": "permit", "reason": "context_matched",
		"auth": map[string]any{"method": "token", "credential_sha256": "ab12"},
		"device": map[string]any{"name": "nx1", "platform": "cisco_nxos", "transport": "tls", "cert_sha256": "cd34"},
		"session": map[string]any{"username": "qual01", "port": "0", "rem_addr": "172.100.100.1", "privilege": 1.0, "ctx_id": "x"},
		"packet_fields": map[string]any{"action": "login", "authen_type": "pap", "service": "login", "priv_lvl": 1.0},
		"server_msg": "anything"}
	out, ok := qualRecord(in, "qual01")
	if !ok {
		t.Fatal("a redeem record is kept")
	}
	b, _ := json.Marshal(out)
	for _, never := range []string{"credential_sha256", "cert_sha256", "ab12", "cd34", "ctx_id", "server_msg", "qual01"} {
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

func TestQualRecordKeepsEscalateAndDropsTheRest(t *testing.T) {
	if _, ok := qualRecord(map[string]any{"event": "escalate"}, "qual01"); !ok {
		t.Fatal("escalate is a validated request record")
	}
	for _, ev := range []string{"mint", "unvalidated", "issue", "revoke", "authenticate"} {
		if _, ok := qualRecord(map[string]any{"event": ev}, "qual01"); ok {
			t.Fatalf("%s is not stimulus evidence", ev)
		}
	}
}

// Only the minted user becomes {user}: a device's own account (SR Linux's root,
// on port unknown) keeps its name, so genprofile can tell the login's records
// from the device's (re-review 3 Minor). A lab system account is no secret.
func TestQualRecordTemplatesOnlyTheMintedUser(t *testing.T) {
	out, _ := qualRecord(map[string]any{"event": "account", "session": map[string]any{"username": "root", "port": "unknown"}}, "qual01")
	if b, _ := json.Marshal(out); !strings.Contains(string(b), `"username":"root"`) {
		t.Fatalf("%s", b)
	}
}

// port49's own tls_refused record is kept as diagnosis, transport and
// tls_outcome only: never its source, detail or cert_sha256 (re-review I-H).
func TestQualRecordKeepsATLSRefusalsOutcomeOnly(t *testing.T) {
	out, ok := qualRecord(map[string]any{"event": "unvalidated", "unvalidated": map[string]any{
		"source": "172.100.100.31:40001", "diagnosis": "tls_refused", "transport": "tls", "tls_outcome": "unknown_ca",
		"detail": "x509: certificate signed by unknown authority", "cert_sha256": strings.Repeat("c", 64)}}, "qual01")
	b, _ := json.Marshal(out)
	if !ok || string(b) != `{"diagnosis":"tls_refused","event":"unvalidated","tls_outcome":"unknown_ca","transport":"tls"}` {
		t.Fatalf("%v %s", ok, b)
	}
	if _, ok := qualRecord(map[string]any{"event": "unvalidated", "unvalidated": map[string]any{"diagnosis": "bad_key"}}, "qual01"); ok {
		t.Fatal("any other unvalidated record is dropped")
	}
}

func TestQualConfigAnswersFromThePolicyAlone(t *testing.T) {
	lab, _ := os.ReadFile(labConfigPath())
	broker, _ := os.ReadFile(filepath.Join(root, "tests", "lab", "slice", "broker.yaml"))
	frag, _ := os.ReadFile(filepath.Join(root, "tests", "qual", "qual-daemon.yaml"))
	out, err := qualConfigYAML(string(lab), string(broker), string(frag), "/x/qual-policy.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, never := range []string{"session_attributes", "command_attributes", "deny_prefixes", "seed_token", "slice/policy.yaml"} {
		if strings.Contains(out, never) {
			t.Fatalf("the conformance config keeps %q: a seed or the lab instrument could answer", never)
		}
	}
	for _, want := range []string{"policy_file: /x/qual-policy.yaml", "fault_file:", "staleness_ceiling: 0s"} {
		if !strings.Contains(out, want) {
			t.Fatalf("lacks %q", want)
		}
	}
}

func TestQualCellsCiteRows(t *testing.T) {
	for _, c := range qualCells {
		if len(c.Rows) == 0 {
			t.Errorf("%s cites no register row", c.Name)
		}
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `make lab-unit`
Expected: FAIL (`undefined: qualRecord`).

- [ ] **Step 3: Implement `qual_evidence.go`**

```go
package lab

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rhwendt/port49/internal/devicemock"
)

type qualCell struct {
	Name string
	Rows []string
}

var qualCells = []qualCell{
	{"token_login", []string{"L1", "L15", "L19"}},
	{"command_permitted", []string{"L10", "L21"}},
	{"command_denied", []string{"L21"}},
	{"accounting", []string{"L6"}},
	{"wrong_credential", []string{"L13"}},
	{"store_unavailable", []string{"L4", "L28"}},
	{"single_connection", []string{"L15", "L73"}},
	{"tls_token_login", []string{"L73"}},
	{"tls_store_unavailable", []string{"L73"}},
	{"tls_unknown_ca", []string{"L73"}},
}

type qualRun struct {
	Platform    string              `json:"platform"`
	LabPlatform string              `json:"lab_platform"`
	Firmware    string              `json:"firmware"`
	Image       string              `json:"image"`
	Commit      string              `json:"commit"`
	Date        string              `json:"date"`
	Transports  []string            `json:"transports"`
	Cells       map[string]string   `json:"cells"`     // cell -> start time, RFC 3339
	Registers   map[string][]string `json:"registers"` // cell -> rows
	BreakGlass  map[string]bool     `json:"break_glass"`
}

// qualRecord keeps what a profile is generated from (spec §13 decision 52
// ruling 2): event, verdict, reason, packet_fields, the request's service and
// attribute list, the reply's attributes, the accounting record's flags and
// attribute list, and the session's port and privilege. The minted user
// becomes {user}; any other username (a device's own account, such as SR
// Linux's root) is kept, so genprofile can pick the login's own records. The
// address becomes {rem_addr}. port49's tls_refused record keeps its
// diagnosis, transport and tls_outcome alone. Every hash, id, message, other
// unvalidated record and record that is not a validated request is dropped:
// the generator cannot read what is not here.
func qualRecord(r map[string]any, user string) (map[string]any, bool) {
	ev, _ := r["event"].(string)
	switch ev {
	case "redeem", "escalate", "authorize_session", "authorize_command", "account":
	case "unvalidated":
		u, _ := r["unvalidated"].(map[string]any)
		if u == nil || u["diagnosis"] != "tls_refused" {
			return nil, false
		}
		return map[string]any{"event": ev, "diagnosis": u["diagnosis"], "transport": u["transport"], "tls_outcome": u["tls_outcome"]}, true
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
		name := s["username"]
		if name == user {
			name = "{user}"
		}
		out["session"] = map[string]any{"port": s["port"], "privilege": s["privilege"], "username": name, "rem_addr": "{rem_addr}"}
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

// qualConfigYAML is the conformance run's port49d.yaml (decision 52 ruling 5):
// the lab file with the slice's broker block reading policyPath, the shared
// fragment merged in, and a lab: block holding fault_file alone, so no seed
// and no lab instrument can answer a request.
func qualConfigYAML(lab, broker, fragment, policyPath string) (string, error) {
	const want = "  policy_file: tests/lab/slice/policy.yaml\n"
	if !strings.Contains(broker, want) {
		return "", fmt.Errorf("tests/lab/slice/broker.yaml no longer reads tests/lab/slice/policy.yaml")
	}
	broker = strings.Replace(broker, want, "  policy_file: "+policyPath+"\n", 1)
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(lab+"\n"+broker), &doc); err != nil {
		return "", err
	}
	m := doc.Content[0]
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == "lab" {
			m.Content[i+1] = &yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
				{Kind: yaml.ScalarNode, Value: "fault_file"}, {Kind: yaml.ScalarNode, Value: "/tmp/port49-lab-qual-fault"}}}
		}
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return "", err
	}
	merged, err := devicemock.MergeFragment(out, []byte(fragment))
	return string(merged), err
}
```

- [ ] **Step 4: Write `qualify_test.go`** (`//go:build lab`). It is opt-in (I5): it skips unless `PORT49_LAB_QUALIFY=1`, which `make lab-qualify` sets, so `make lab` never runs it.

```go
// TestQualify is the conformance run a firmware is vetted by (plan 11b): the
// fixed cells, under tests/qual/qual-policy.yaml and tests/qual/qual-daemon.yaml
// with tokens the broker mints, on each selected platform, default or opt-in.
// It writes whitelisted evidence the generator reads and a note citing the rows
// each cell re-measures. It closes no row.
func TestQualify(t *testing.T) {
	if os.Getenv("PORT49_LAB_QUALIFY") != "1" {
		t.Skip("opt-in: make lab-qualify P=<selector>")
	}
	sel, _, err := platformSelection()
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 1 {
		t.Fatalf("one platform at a time: PORT49_LAB_PLATFORMS names %d", len(sel))
	}
	if err := labOccupyForRun(labLockPath, fmt.Sprintf("TestQualify pid %d", os.Getpid())); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if err := labGuardAt(l66StopSentinel, "/", l66DiskFloorMB); err != nil {
		t.Fatalf("INVALID: %v", err)
	}
	if out, err := exec.Command("docker", "ps", "--filter", "label=containerlab", "--format", "{{.Names}}").Output(); err != nil {
		t.Fatalf("INVALID: docker ps: %v", err)
	} else if s := strings.TrimSpace(string(out)); s != "" {
		t.Fatalf("INVALID: a containerlab topology is already up (%s): the lab is single-occupant", strings.ReplaceAll(s, "\n", ", "))
	}
	// The selection itself, default and opt-in rows alike: eachSelected keeps
	// only one kind (rowsFor), which would skip the five older images.
	for _, p := range sel {
		if helpOnlyPlatforms[p.sel] {
			t.Skipf("%s is help-only: it runs no TACACS+", p.sel)
		}
		t.Run(p.name, func(t *testing.T) { newQualEnv(t, labFor(t, p)).run() })
	}
}
```

`qualEnv`, in the same file, holds `t`, `l`, `slug`, `start` (`l.mark()`), `sock`, `agentOut`, `minted []string` (for the leak gate), `run qualRun`, `conns map[string][]l73Conn` and `secrets []string`. Write its methods in full:

```go
func newQualEnv(t *testing.T, l *lab) *qualEnv {
	slug := devicemock.Slug(l.p.version)
	q := &qualEnv{t: t, l: l, slug: slug, conns: map[string][]l73Conn{}}
	q.run = qualRun{Platform: inventoryPlatform(t, l.p.node), LabPlatform: l.p.name, Image: l.p.version,
		Firmware: l.p.version, Date: time.Now().UTC().Format("2006-01-02"), Commit: gitHead(t), Transports: []string{"tcp"},
		Cells: map[string]string{}, Registers: map[string][]string{}, BreakGlass: map[string]bool{}}
	return q
}

// Firmware is the platform row's version string as the results notes' Image version line
// carries it ("Nexus 9300v 10.6(2)F"), so ruling 4's check matches the note exactly and
// the slug is e.g. Nexus-9300v-10.6-2-F.
//
// inventoryPlatform is node's platform in tests/lab/inventory-lab.yaml (admission.LoadFile):
// the port49 platform the profile's mock is admitted as. gitHead is `git rev-parse --short=12 HEAD`:
// twelve hex characters, under l73SummaryLeaks' 32 and devicemock.Load's 40, so a recorded
// commit never trips a leak gate (re-review C-A). Every commit this plan records is that form.

// run starts port49d on the conformance config, opens the broker session as
// the slice does, and plays each cell under one capture.
func (q *qualEnv) run() {
	q.guard()
	cfg := q.config()
	if err := q.l.stopDaemon(); err != nil {
		q.t.Fatal(err)
	}
	if err := q.l.startDaemonWith(cfg, true); err != nil {
		q.t.Fatalf("INVALID: port49d would not start on the conformance config: %v", err)
	}
	if err := q.l.awaitTACACS(); err != nil {
		q.t.Fatal(err)
	}
	defer q.restoreDaemon()
	stop := q.l.capture(q.t, "QUAL-"+q.slug)
	q.login()
	defer stopSliceAgent(q.t, q.agentOut)
	q.cellTokenLogin()
	q.cellCommands()
	q.cellAccounting()
	q.cellWrongCredential()
	q.cellStoreUnavailable()
	q.cellSingleConnection()
	// TLS only on the L73 images: the older rows share a platform name (and so
	// an l73Dialects key) with them but carry no RFC 9887 client (L71).
	if d, ok := l73Dialects[q.l.p.name]; ok && !d.HelpOnly && optInPlatforms[q.l.p.sel] {
		q.tlsCells(d)
		q.run.Transports = append(q.run.Transports, "tls")
	}
	stop()
	q.write()
}
```

`q.config()` writes the conformance config, built by `qualConfigYAML(lab, slice broker, tests/qual/qual-daemon.yaml, <private copy of tests/qual/qual-policy.yaml>)`. It is passed through `privatePolicy(out, filepath.Join(root, "tests/lab/logs", "port49d-qual-"+q.l.p.name+"-policy"))`, so the policy and inventory sit behind the fence the way every broker run's do (`harness_test.go:958`). Write it to `tests/lab/logs/port49d-qual-<platform>.yaml` and return the path.

`q.restoreDaemon()` stops port49d and restarts it on `q.l.configPath()`, the way the slice's deferred function does (`slice_test.go:84-96`).

`q.login()` opens the broker session through the slice's PKI, exactly as `TestSliceEndToEnd` does (`slice_test.go:63-117`):
- `testpki.WriteLab(filepath.Join(root, slicePKIDir), sliceEmail, time.Now())`;
- `bin/port49 login --broker sliceBrokerURL --cert … --key … --broker-ca … --socket <tmp>/a/agent.sock`;
- the output is kept in `q.agentOut`.

`q.mint()` runs `sliceToken(q.t, port49, q.sock, q.l.p.node)`. It appends the token to `q.minted` and `q.secrets` and returns it; the token is never printed.

The plain cells, each started with `q.cell(name)` (which runs the STOP and disk guard, records the start time in `q.run.Cells`, and records the rows from `qualCells`):
- **`cellTokenLogin`**: `q.l.loginWithin("qual01", q.mint(), 150*time.Second, "show version")`. It fails INVALID if the login fails, printing `summarize(recordsSince)` (events and reasons only).
- **`cellCommands`**: a fresh mint, then `loginWithin(…, "show version", "show users")`. The records hold one permitted and one denied `authorize_command`.
- **`cellAccounting`**: waits up to 60 s for an `account` record with `flags: stop` since the login (`q.l.waitForRecords`).
- **`cellWrongCredential`**: `loginWithin("qual01", randomHex(q.t, 16), 60*time.Second)`. The login must fail. `randomHex` is L76's helper; the value goes into `q.secrets`.
- **`cellStoreUnavailable`**: write `store_unavailable` to `/tmp/port49-lab-qual-fault`, then try a token login (it must fail), then break-glass (`q.l.dial(breakglassUser, breakglassPassword, 120*time.Second)`). Record in `q.run.BreakGlass["store_unavailable"]` whether it logged in, and how long it took. Remove the fault file in a `defer`.
- **`cellSingleConnection`**: under the startup config's single-connection form, the same sequence as the TLS cell (re-review I-J), because the mock's `single_connection` plays every stimulus step:
  - a fresh mint;
  - `loginWithin("qual01", tok, 150*time.Second, "show version", "show users")`;
  - wait up to 60 s for that login's `account` stop record.

  When the platform row has no such form, the cell is recorded as not run, and genprofile leaves `single_connection` out of the profile's scenarios.

`q.tlsCells(d)` reuses L73's machinery with the conformance config as its base:
1. `e := newL73Env(q.t, q.l, d)`, then `e.enrol()`.
2. Build the daemon config with `l73DaemonYAML(<the conformance config text>, l73Daemon{…})`: this is how `e.daemon` builds it, but from `q.config()`'s text instead of `labConfigPath()`'s. Write it through `e.write`, set `e.cfg`, and call `e.startOn()`.
3. `e.configure(e.base())`.
4. Play `tls_token_login` as the plain `token_login`, `command_permitted`, `command_denied` and `accounting` cells together (re-review I-G):
   - a fresh mint, then `loginWithin("qual01", tok, 150*time.Second, "show version", "show users")`;
   - wait up to 60 s for that login's `account` stop record, as `cellAccounting` does.

   Command authorization and accounting are then covered over TLS, and the cell's window holds every step the mock's `tls_token_login` plays. Play `tls_store_unavailable` as the plain cell. Run `tls_unknown_ca` with port49's `client_ca_file` swapped to a CA that did not sign the device's leaf (`e.files` holds the untrusted root L73 cell d uses).
5. Each TLS cell's connections are `e.capture(cell)()`'s `[]l73Conn`, kept as `<cell>.tls.json`. Restore the device with `e.restore()`.

A unit test, `TestQualTLSDaemonYAMLKeepsTheBroker`, asserts `l73DaemonYAML` keeps the broker block's `policy_file` and adds `tls_listener:`.

`q.write()` builds every evidence file, then gates them all before writing any:
- `decisions.jsonl` is every record since `q.start`, mapped through `qualRecord(r, "qual01")`. Before mapping, the run is INVALID if any `redeem` has `auth.method == "lab"`: a seed answered.
- For each plain cell, `<cell>.conns.json` is `l73Conns(raw, l.p.addr)` over the cell's time window (`l73Window`), keeping only `Server`, `DevicePort`, `SYNAt`, `End`, `EndAt` and `Plain` (the 12-byte headers with their version byte). `raw` is the capture file `tests/lab/captures/QUAL-<slug>-<lp>.pcap`.
- `run.json`.

Every file must pass `labcreds.Contains(body, q.secrets)` (empty) and `l73SummaryLeaks` (empty). Only then is anything written to `tests/lab/evidence/QUAL-<slug>-<lp>/`, and the note goes through `q.l.result(q.t, "QUAL-"+q.slug, claim, observation)`. The note's observation lists:
- each cell's verdict and the rows it re-measures;
- break-glass timings;
- the TLS cells' handshake facts.

- [ ] **Step 5: Makefile**

```make
# The conformance run a firmware is vetted by (plan 11b). One platform selector at a time.
lab-qualify:
	@test -n "$(P)" || { echo "usage: make lab-qualify P=<selector, e.g. nxos106>"; exit 2; }
	PORT49_LAB_QUALIFY=1 PORT49_LAB_PLATFORMS=$(P) go test -tags lab ./tests/lab/ -run '^TestQualify$$' -count=1 -v -timeout 180m
```

- [ ] **Step 6: Run the unit and vet checks**

Run: `make lab-unit && go vet -tags lab ./tests/lab/ && make check-darwin`
Expected: PASS; vet and check-darwin clean. The tagged darwin vet is not run: l56's pre-existing break, as in Task 2 Step 9.

- [ ] **Step 7: Commit**

```bash
git add tests/lab/qual_evidence.go tests/lab/qual_evidence_unit_test.go tests/lab/qualify_test.go Makefile tests/lab/README.md
git commit -m "test: TestQualify, the lab conformance run under the qual policy, with whitelisted evidence

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 13: `genprofile`, evidence to profile

**Files:**
- Create: `tests/qual/cmd/genprofile/main.go`, `tests/qual/cmd/genprofile/gen.go`, `tests/qual/cmd/genprofile/gen_test.go`
- Create: `tests/qual/cmd/genprofile/testdata/QUAL-1.0-fixture_junos/`, a hand-written evidence fixture of a TLS-capable image, covering all ten cells:
  - `run.json`, with `transports: [tcp, tls]` and every cell's start time in `cells`;
  - `decisions.jsonl` in `qualRecord`'s shape, with `device.transport` set on each record:
    - the plain sequence across the `token_login`, `command_permitted`, `command_denied` and `accounting` windows (redeem, authorize_session, a permitted and a denied authorize_command, an account start and stop);
    - the same sequence over `tls` in the `tls_token_login` window;
    - a refused redeem in the `wrong_credential` window;
    - a `store_unavailable` redeem in the `store_unavailable` and `tls_store_unavailable` windows;
    - the full sequence (redeem, authorize_session, a permitted and a denied authorize_command, an account start and stop) in the `single_connection` window (re-review I-J);
    - an SR-Linux-like `account` start record with `username: root` on port `unknown` at the **start** of the `token_login` window, before the login's own records (re-review 3 Minor). `steps` must pick the `{user}` record's port, not this earlier one.
  - `token_login.conns.json`;
  - `tls_token_login.tls.json`, with two connections: a full handshake with `psk_identities: 0`, and a resumption with `psk_identities: 1`;
  - `tls_unknown_ca.tls.json`: one connection with **no** plaintext alert and `end: server-rst`, which is what the lab produces under TLS 1.3. The `decisions.jsonl` `tls_unknown_ca` window holds the whitelisted `unvalidated` record `{"event":"unvalidated","diagnosis":"tls_refused","transport":"tls","tls_outcome":"unknown_ca"}`.

**Interfaces:**
- Consumes: the evidence layout (Task 12), `devicemock.Profile`, `devicemock.Golden`, `devicemock.Slug`.
- Produces:
  - `func Generate(evDir, repoRoot string) (*devicemock.Profile, devicemock.Golden, error)`;
  - `func StimulusEqual(a, b *devicemock.Profile) bool`;
  - the command `go run ./tests/qual/cmd/genprofile -evidence <dir> [-check]`. It writes `tests/qual/profiles/<platform>/<slug>.yaml` and `tests/qual/golden/<platform>/<slug>.json`, then prints the review checklist.
    - With `-check` it writes nothing. It exits 1 when the generated stimulus differs from the committed profile's (I7).

- [ ] **Step 1: Write the failing tests**

```go
package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rhwendt/port49/internal/devicemock"
)

func TestGenerateTheFixture(t *testing.T) {
	p, g, err := Generate("testdata/QUAL-1.0-fixture_junos", "testdata")
	if err != nil {
		t.Fatal(err)
	}
	s := p.Stimulus
	if s.Steps[0].Fields.AuthenType != "pap" || s.Steps[0].MinorVersion != 1 || s.TLS.FlightDelay != 5*time.Second ||
		s.Connections.Mode != "per_step" || g.Scenarios["token_login"].Outcome != "login_ok" {
		t.Fatalf("%+v %+v", s, g)
	}
	if s.TLS.ClientHello.Extensions[len(s.TLS.ClientHello.Extensions)-1] == 41 {
		t.Fatal("the hello is a full handshake's (psk_identities 0), never a resumption's")
	}
	if err := p.Validate("testdata"); err != nil {
		t.Fatalf("a generated profile must load: %v", err)
	}
}

// Through Load, not only Validate: Load's credential check sees the written
// YAML, so a 40-hex commit or any hash that slipped in fails here (re-review C-A).
func TestAGeneratedProfileLoads(t *testing.T) {
	p, _, err := Generate("testdata/QUAL-1.0-fixture_junos", "testdata")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "p.yaml")
	if err := writeProfile(path, p, "testdata/QUAL-1.0-fixture_junos"); err != nil {
		t.Fatal(err)
	}
	if _, err := devicemock.Load(path, "testdata"); err != nil {
		t.Fatalf("a generated profile, as written, must load: %v", err)
	}
	if len(p.Vetted.Commit) != 12 {
		t.Fatalf("commits are recorded as 12 hex characters (git rev-parse --short=12): %q", p.Vetted.Commit)
	}
}

// The generated golden has every scenario, each in the shape Play plays it,
// and Judge passes a transcript of exactly that shape: so TestQual's verdict
// on a generated profile turns on port49's replies, never on a golden built
// to the wrong scenario (re-review I-G).
func TestTheGoldenCoversEveryScenarioInPlayedOrder(t *testing.T) {
	p, g, err := Generate("testdata/QUAL-1.0-fixture_junos", "testdata")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"token_login", "wrong_credential", "store_unavailable", "single_connection",
		"tls_token_login", "tls_store_unavailable", "tls_unknown_ca", "flight_delay"}
	if !slices.Equal(p.Scenarios, want) {
		t.Fatalf("scenarios %v, want all eight", p.Scenarios)
	}
	for _, sc := range want {
		gs, ok := g.Scenarios[sc]
		if !ok || gs.Outcome == "" {
			t.Fatalf("%s: no golden", sc)
		}
		var names []string
		for _, s := range gs.Steps {
			names = append(names, s.Step)
		}
		// All of them when the play runs to the end; a prefix when a reaction stops it.
		played := devicemock.PlayedSteps(p, sc)
		if len(names) > len(played) || !slices.Equal(names, played[:len(names)]) ||
			(gs.Outcome == "login_ok" && len(names) != len(played)) {
			t.Fatalf("%s: golden steps %v, Play plays %v", sc, names, played)
		}
		tr := devicemock.Transcript{Scenario: sc, Outcome: gs.Outcome}
		for _, s := range gs.Steps {
			tr.Steps = append(tr.Steps, devicemock.StepResult{Step: s.Step, Event: s.Event, Args: s.Args})
		}
		if fails, _ := devicemock.Judge(tr, gs); len(fails) != 0 {
			t.Fatalf("%s: %q", sc, fails)
		}
	}
	tl := g.Scenarios["token_login"]
	if len(tl.Steps) != 6 || tl.Steps[3].Step != "command_denied" || tl.Steps[3].Event != "author_fail" || tl.Steps[5].Event != "acct_success" {
		t.Fatalf("token_login is the union of four lab cells, in step order: %+v", tl.Steps)
	}
	if u := g.Scenarios["tls_unknown_ca"]; u.Outcome != "handshake_refused" || u.Steps[0].Step != "login" || u.Steps[0].Event != "tls_refused" {
		t.Fatalf("tls_unknown_ca is the class event on the login: %+v", u)
	}
	if fd, tls := g.Scenarios["flight_delay"], g.Scenarios["tls_token_login"]; fd.Outcome != tls.Outcome || fd.Steps[0].Event != tls.Steps[0].Event {
		t.Fatalf("flight_delay copies tls_token_login's login: %+v %+v", fd, tls)
	}
	for _, s := range p.Stimulus.Steps {
		if s.Port == "unknown" {
			t.Fatal("an account step took another channel's port; steps reads the login's own records")
		}
	}
}

func TestGeneratedReactionsCiteTheRunsOwnNote(t *testing.T) {
	p, _, _ := Generate("testdata/QUAL-1.0-fixture_junos", "testdata")
	for _, r := range p.Reactions {
		if r.Status == "measured" && (len(r.Sources) == 0 || !strings.Contains(r.Sources[0].Note, "QUAL-1.0-fixture_junos")) {
			t.Fatalf("a pre-filled measured reaction cites the run's own note: %+v", r)
		}
	}
}

func copyFixture(t *testing.T) string {
	dst := filepath.Join(t.TempDir(), "QUAL-1.0-fixture_junos")
	os.CopyFS(dst, os.DirFS("testdata/QUAL-1.0-fixture_junos"))
	return dst
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

func TestStimulusEqualIgnoresReviewedParts(t *testing.T) {
	a, _, _ := Generate("testdata/QUAL-1.0-fixture_junos", "testdata")
	b, _, _ := Generate("testdata/QUAL-1.0-fixture_junos", "testdata")
	b.Reactions, b.Acceptance, b.Vetted.Commit = nil, nil, "other"
	if !StimulusEqual(a, b) {
		t.Fatal("-check compares the generated stimulus only: reviewed parts and the header may differ")
	}
	b.Stimulus.Steps[0].Port = "tty9"
	if StimulusEqual(a, b) {
		t.Fatal("a changed stimulus is a difference")
	}
}
```

The fixture's `run.json` names `lab_platform: fixture_junos`, `firmware: "1.0"`, `image: fixture 1.0` and `commit: "a291b6c52513"` (twelve hex characters, as `gitHead` records).

`main.go`'s writer is `func writeProfile(path string, p *devicemock.Profile, evDir string) error` (the header comment, then YAML with indent 2), so the test writes exactly what the command writes. The fixture directory also holds `testdata/tests/lab/results/QUAL-1.0-fixture_junos.md`, with an `Image version:` line naming `fixture 1.0`.

- [ ] **Step 2: Run to verify they fail**

Run: `go test ./tests/qual/cmd/genprofile/ -count=1`
Expected: FAIL (`undefined: Generate`).

- [ ] **Step 3: Implement `gen.go`**

```go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/rhwendt/port49/internal/devicemock"
)

var allowedFiles = []string{"run.json", "decisions.jsonl", "*.conns.json", "*.tls.json"}

var forbidden = []string{"_sha256", "password", "secret", "BEGIN "}

// run is run.json as qualRun (Task 12) writes it: the same snake_case tags,
// so lab_platform decodes (encoding/json matches only case, not underscores).
type run struct {
	Platform    string            `json:"platform"`
	LabPlatform string            `json:"lab_platform"`
	Firmware    string            `json:"firmware"`
	Image       string            `json:"image"`
	Commit      string            `json:"commit"`
	Date        string            `json:"date"`
	Transports  []string          `json:"transports"`
	Cells       map[string]string `json:"cells"` // cell -> start time, RFC 3339
	BreakGlass  map[string]bool   `json:"break_glass"`
}

type conn struct {
	Server string `json:"server"`
	Plain  []struct {
		Version uint8 `json:"version"`
		Type    uint8 `json:"type"`
		SeqNo   uint8 `json:"seq_no"`
		Flags   uint8 `json:"flags"`
	} `json:"plain_tacacs_from_device"`
	Hello *struct {
		LegacyVersion    uint16   `json:"legacy_version"`
		Versions         []uint16 `json:"supported_versions"`
		Suites           []uint16 `json:"cipher_suites"`
		HasSNI           bool     `json:"has_sni"`
		SNI              string   `json:"sni"`
		Groups           []uint16 `json:"supported_groups"`
		SigAlgs          []uint16 `json:"signature_algorithms"`
		ALPN             []string `json:"alpn"`
		PSKIdentities    int      `json:"psk_identities"`
		PSKModes         []uint8  `json:"psk_key_exchange_modes"`
		CompressCertAlgs []uint16 `json:"compress_certificate_algorithms"`
		Extensions       []uint16 `json:"extensions"`
	} `json:"client_hello"`
	ServerHello *devicemock.ServerHello `json:"server_hello"`
	ServerFlightAt time.Time `json:"server_flight_at"`
	DeviceReplyAt  time.Time `json:"device_reply_at"`
}

// Generate builds a profile's stimulus and a first golden from one
// conformance run's evidence directory, and pre-fills the reactions it shows.
// It refuses any file it does not know, and any file holding a forbidden
// string, before it reads a record.
func Generate(evDir, repoRoot string) (*devicemock.Profile, devicemock.Golden, error) {
	var g devicemock.Golden
	entries, err := os.ReadDir(evDir)
	if err != nil {
		return nil, g, err
	}
	for _, e := range entries {
		ok := false
		for _, pat := range allowedFiles {
			if m, _ := filepath.Match(pat, e.Name()); m {
				ok = true
			}
		}
		if !ok {
			return nil, g, fmt.Errorf("%s: %s is not evidence genprofile reads (it never reads a capture)", evDir, e.Name())
		}
		body, err := os.ReadFile(filepath.Join(evDir, e.Name()))
		if err != nil {
			return nil, g, err
		}
		for _, f := range forbidden {
			if strings.Contains(string(body), f) {
				return nil, g, fmt.Errorf("%s/%s holds %q: refused, never filtered here", evDir, e.Name(), f)
			}
		}
	}
	var r run
	if err := readJSON(filepath.Join(evDir, "run.json"), &r); err != nil {
		return nil, g, err
	}
	recs, err := readRecords(filepath.Join(evDir, "decisions.jsonl"))
	if err != nil {
		return nil, g, err
	}
	slug := devicemock.Slug(r.Firmware)
	// The conformance note is no register row: it re-measures the rows its cells
	// cite (decision 52 ruling 10), so its sources name "QUAL" as the register.
	note := devicemock.Source{Note: fmt.Sprintf("tests/lab/results/QUAL-%s-%s.md", slug, r.LabPlatform), Register: "QUAL"}
	p := &devicemock.Profile{SchemaVersion: 1, Platform: r.Platform, LabPlatform: r.LabPlatform, Firmware: r.Firmware,
		Image: r.Image, Transports: r.Transports,
		Vetted: devicemock.Vetted{Date: r.Date, Commit: r.Commit, Evidence: evDir, Notes: []string{note.Note}},
		Golden: fmt.Sprintf("tests/qual/golden/%s/%s.json", r.Platform, slug)}
	p.Stimulus.Sources = []devicemock.Source{note}
	p.Stimulus.Steps = steps(recs)
	versions := headerVersions(filepath.Join(evDir, "token_login.conns.json"))
	for i := range p.Stimulus.Steps {
		p.Stimulus.Steps[i].MinorVersion = versions[p.Stimulus.Steps[i].Type] & 0x0f
	}
	p.Stimulus.Connections = connPattern(evDir, len(p.Stimulus.Steps))
	if tls, err := tlsStimulus(evDir, note); err != nil {
		return nil, g, err
	} else if tls != nil {
		p.Stimulus.TLS = tls
	}
	p.Reactions = prefillReactions(recs, r, note)
	p.Scenarios = scenarios(evDir, p.Stimulus.TLS != nil)
	if g, err = goldenFrom(p, recs, r.Cells, evDir); err != nil {
		return nil, g, err
	}
	return p, g, nil
}

// StimulusEqual compares what genprofile generates and nothing reviewed:
// stimulus, platform, firmware and transports.
func StimulusEqual(a, b *devicemock.Profile) bool {
	return a.Platform == b.Platform && a.Firmware == b.Firmware &&
		reflect.DeepEqual(a.Transports, b.Transports) && reflect.DeepEqual(a.Stimulus, b.Stimulus)
}
```

Write the helpers in the same file, in full.

- **`readJSON`** and **`readRecords`**: `json.Unmarshal` per line with a `bufio.Scanner`, buffer 1 MiB.
- **`steps(recs)`** reads each step's fields from the first matching record **within the `token_login` scenario's windows** (see `goldenFrom`), from the plain (`device.transport` not `tls`) records whose `session.username` is `{user}`, the minted login's (`qualRecord` keeps every other name). The same `{user}` filter applies in `goldenFrom`. The selection key is the template; no real username is written into a profile:

  | Record | Step |
  |---|---|
  | first `redeem` | `login`: `packet_fields`, `session.port` |
  | first `authorize_session` | `authorize_session`: `request.raw` |
  | first `authorize_command` with `verdict: permit` | `command_permitted` |
  | first `authorize_command` with `verdict: deny` | `command_denied` |
  | first `account` with `flags: start` | `account_start`: `record.raw`, already templated, and that record's own port |
  | first `account` with `flags: stop` | `account_stop`, the same way |

  The account steps' port is taken from that login's own start and stop records. SR Linux accounts its own `root` sessions and a second exec channel on port `unknown` (L76 cell c), sometimes a second before the login's `redeem`. So the first `account` record in a window is not necessarily the login's; the `{user}` filter is what picks the right one.

  Each step's `Fields` comes from `packet_fields`. A record with no `packet_fields` is an error: the run predates Task 5. A TLS-only device would read the TLS records; none exists today.
- **`headerVersions(path)`** takes the first header of each type from the plain connections. Its version byte's low nibble is the minor version (M4). It is empty for a TLS-only run; the minor version there is 1 for pap or chap and 0 otherwise. In that case each such step also gets an `engine_gaps` entry, `minor_version_inferred_over_tls`, because TLS hides the header.
- **`connPattern(evDir, n)`** returns `per_step` when `token_login.conns.json` holds at least `n` connections. It returns `single_connection` when `single_connection.conns.json` carried every step on one connection. `single_connect_flag` is the first header's `flags & 0x04`.
- **`tlsStimulus(evDir, note)`** returns nil when there is no `*.tls.json`. Otherwise:
  - `client_hello` is the first connection in `tls_token_login.tls.json` whose hello has `psk_identities == 0` (I3);
  - `sni` is `{server_ip}` when `has_sni` and the SNI is the server's host, else `""`;
  - `server_hello` is that connection's;
  - `flight_delay` is the minimum over every connection with both timestamps of `device_reply_at - server_flight_at`, rounded to 10 ms (`time.Duration(math.Round(float64(d)/1e7) * 1e7)`);
  - `client_chain` and `server_identity` are left to review, defaulting to `leaf_and_intermediate` and `chain_only`;
  - its source is `note`, with `Register: "QUAL"` as the stimulus has.
- **`prefillReactions(recs, r, note)`** writes one entry per (step, event) the records show, with `status: measured` and source `note`:
  - `authen_pass` → `next_step`;
  - `authen_getpass` → `send_credential`;
  - `authen_fail` → `stop`/`login_refused`;
  - `authorize_*` permit → `next_step`, deny → `next_step`;
  - `account` success → `next_step`;
  - the `store_unavailable` cell's `authen_error` → `failover_local`/`falls_to_local` when `r.BreakGlass["store_unavailable"]` is true, else `give_up`/`break_glass_fails`.

  Acceptance rules are never pre-filled beyond one: `priv_lvl_range` from the device's own `priv_lvl` values, marked `unmeasured`, since seeing values is not measuring a limit.
- **`scenarios(evDir, tls)`** lists the cells the run recorded (`token_login`, `wrong_credential`, `store_unavailable`, `single_connection`), plus `tls_token_login`, `tls_store_unavailable`, `tls_unknown_ca` and `flight_delay` when `tls`.
- **`goldenFrom(p, recs, cells, evDir) (devicemock.Golden, error)`** builds each scenario's golden from an explicit map of lab cells to scenarios (re-review I-G). A cell's window runs from its start time in `run.json`'s `cells` to the next cell's start. Records are filtered by `device.transport` first (I-B).

```go
// scenarioCells: which lab cells' windows make each mock scenario's golden, and
// over which transport. The mock's token_login plays every stimulus step, which
// the lab spreads over four cells; their records, in stimulus step order, are
// that golden. The TLS cell runs the same sequence (Task 12), so it is one cell.
var scenarioCells = map[string]struct {
	cells     []string
	transport string
}{
	"token_login":           {[]string{"token_login", "command_permitted", "command_denied", "accounting"}, "tcp"},
	"wrong_credential":      {[]string{"wrong_credential"}, "tcp"},
	"store_unavailable":     {[]string{"store_unavailable"}, "tcp"},
	"single_connection":     {[]string{"single_connection"}, "tcp"}, // the full sequence in one cell (Task 12)
	"tls_token_login":       {[]string{"tls_token_login"}, "tls"},
	"tls_store_unavailable": {[]string{"tls_store_unavailable"}, "tls"},
}
```

  For each mapped scenario:
  - Take the records of its cells' windows on its transport.
  - Pick one record per step the mock plays (`devicemock.PlayedSteps(p, sc)`, Task 9), in that order, by the table under `steps`. For example, a `redeem` with verdict `permit` is `authen_pass`, one with `deny` is `authen_fail`, and one whose reason is `store_unavailable` is `authen_error`; reply attributes are `reply.attributes`.
  - Set the outcome the way the reaction table ends it: `login_ok` when every step passed, else the pre-filled reaction's outcome for the first step that did not.

  Two scenarios are not built from request records:
  - **`tls_unknown_ca`** has outcome `handshake_refused` and one step, `login`, with the class event `tls_refused`: the device's refusal arrives as an alert or a reset that race (re-review I-H). Under TLS 1.3 the server's alert is encrypted, so `tls_unknown_ca.tls.json` never holds it. Its connection shows `end: server-rst` (or `server-fin`), and either confirms the class.
    - The cell's evidence also holds port49's own `unvalidated` record (`diagnosis: tls_refused`, `tls_outcome`; `internal/daemon/server/tls.go:321-325`). genprofile requires it, with `tls_outcome: unknown_ca`, and fails naming the cell when it is absent. `qualRecord` keeps only `diagnosis`, `transport` and `tls_outcome` from an `unvalidated` record whose diagnosis is `tls_refused`. It drops `source`, `detail` and `cert_sha256`, and every other `unvalidated` record as before.
    - That record carries no body and no session byte: its fields are the source address, the diagnosis, the transport, the outcome, a bounded printable `detail` (never a body, per its own doc comment) and the per-test leaf's fingerprint, of which only the outcome is kept.
  - **`flight_delay`** copies `tls_token_login`'s `login` step and that step's outcome (`login_ok` when it passed). The delay changes the timing, not port49's reply.

  A scenario in `scenarios(...)` with no golden is an error naming it, so a generated profile never reaches `TestQual` with an empty `want`.

`main.go`:
- **Without `-check`:**
  - It calls `Generate`.
  - It writes the profile with `writeProfile` (`yaml.NewEncoder`, indent 2), after a header comment: `# Generated by genprofile from <evidence> at <commit>; stimulus is generated, reactions and acceptance are reviewed by hand (decision 52 ruling 1).`
  - It writes the golden with `devicemock.WriteGolden`.
  - It prints the checklist:
    1. each reaction against the note's cell text;
    2. each acceptance rule's status, measured only when a note for this firmware measured it (ruling 4);
    3. every `engine_gaps` entry's `code`;
    4. the golden's outcomes against the note.
- **With `-check`:** it loads the committed profile with `devicemock.Load` and exits 1 with `genprofile: the generated stimulus differs from <path>` unless `StimulusEqual` holds.

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
- Create:
  - `tests/lab/evidence/QUAL-<slug>-<lp>/` and `tests/lab/evidence/QUAL-<slug>-<lp>.pcap`;
  - `tests/lab/results/QUAL-<slug>-<lp>.md`;
  - `tests/qual/profiles/*/*.yaml` and `tests/qual/golden/*/*.json`.

This task runs on beehive, under the lab lock, with the watchdog, one platform at a time. It vets the ten `tests/lab/harness_test.go` rows that run TACACS+:
- `ceos436`, `nxos106`, `iosxe1718` and `vjunos26` (TLS and plain);
- `srlinux` (plain);
- the older plain images: `eos`, `vjunos`, `vsrx`, `nxos` and `iosxe`.

`vjunosswitch26` is skipped, as L73 skipped it. XRd is Task 16.

- [ ] **Step 1: Run and generate, per selector**, in that order:
  1. `make lab-qualify P=<sel>`, run in the background with the watchdog, as in Task 4.
  2. `go run ./tests/qual/cmd/genprofile -evidence tests/lab/evidence/QUAL-<slug>-<lp>`.

  Read the logs only through the filter in Global Constraints.

- [ ] **Step 2: Review each profile by hand** against its own QUAL note. Decision 52 ruling 4 governs citations: a claim is `measured` only when its note's `Image version:` line names this firmware.
  - **Pre-filled reactions:** keep each one the note's cell text says, and fix each one it contradicts.
  - **L73 cell (i) on the four TLS images:** add the measured reactions the conformance run did not reach (the alert, the reset at Accept, the decline window), citing `L73-<platform>.md`. The L73 notes are for exactly these firmwares, so the reactions are `measured`.
  - **IOS XE 17.18.02 over TLS:** `authen_error` → `give_up`/`break_glass_fails` (`L73-cisco_iosxe.md` cell i, measured).
  - **Junos profiles (both firmwares):** add the rule below. It stays unmeasured whatever L78 shows on vJunos (Q2, ruled):

```yaml
  - id: junos_reply_total
    kind: max_reply_bytes
    applies: authorize_session
    max: 255
    effect: lockout
    status: unmeasured
    sources: [{note: tests/lab/results/L2-juniper_vjunos-router.md, register: L2}]
    note: Ryan's production prior from hardware Junos; L2 measured only long deny messages; L78 measures it
```

  - **NX-OS `role_names`:**
    - nxos (10.4(2)F): `measured`, citing `L16-cisco_nxos.md`, which is that firmware.
    - nxos106 (10.6(2)F): the same rule, `unmeasured`, citing the same note. L16 was measured on 10.4(2)F, not on this firmware.
  - **L18 (attributes the device did not ask for):** an `attribute_refused` rule with `effect: session_refused` where `L18-<platform>.md` shows the session killed. It is `measured` on the older image the note names and `unmeasured` on the newer one.
  - **Junos (the IP-literal SNI):** list `engine_gaps: [{id: sni_ip_literal_in_session, what: "crypto/tls omits an IP-literal SNI; the hello probe sends it", code: internal/devicemock/hello.go}]`.
  - **cEOS, if the hello has extension 27 and the evidence lacks its algorithms:** list `{id: compress_certificate_algorithms, what: "evidence predates the field", code: ""}` until the next run fills it.

- [ ] **Step 3: Run the mocks and time them**

Run: `time make qual`
Expected: `ok`, with `TestQual/<platform>/<firmware>` passing for each of the ten. Record `TestQual`'s wall time from `go test -v`'s `--- PASS: TestQual (Ns)` in the as-built (Task 23). Then run `make test` and confirm `internal/port49d` still finishes inside the Makefile's 20m `-timeout` (M9). If it does not, split `TestQual` into its own package's `go test` invocation in `make test`, and say so.

- [ ] **Step 4: Settle the captures.** Copy the raw captures to main's `tests/lab/captures/` before removing any worktree. Run `make test && make vet` on beehive; the labpcap audit checks the `QUAL-*.pcap` evidence.

- [ ] **Step 5: Commit** (one commit per platform is fine):

```bash
git add tests/lab/evidence/QUAL-* tests/lab/results/QUAL-*.md tests/qual/profiles tests/qual/golden
git commit -m "test: vet ten images and add their mock devices

Co-Authored-By: Claude <model name> <noreply@anthropic.com>"
```

---

### Task 15: Lab — L78, a long permit reply on Junos

**Files:**
- Create: `tests/lab/l78.go` (pure), `tests/lab/l78_unit_test.go`, `tests/lab/l78_test.go` (tag `lab`), `tests/lab/results/L78-juniper_vjunos-router.md`
- Modify: spec §15 L78 (a status addendum)

The run steps a derived policy's Junos session reply through totals of 200, 240, 256, 300, 400 and 600 bytes, with each attribute at most 255. At each step it does a broker-minted token login, using Task 12's conformance config and mint path. Break-glass is proved before each step and after the last, and the run stops at the first step that leaves break-glass refused. This is L2's method (`register_test.go`'s `TestL2Truncation`).

- [ ] **Step 1: Write the failing pure test**

```go
// This checks l78Split's arithmetic only: l78Rendered is built from it, so it
// cannot catch the projection rendering differently. The measured total is
// the authorize_session record's reply.attributes, which TestL78 records and
// the note cites.
func TestL78PolicyRendersEachTotalWithEveryAttributeUnder255(t *testing.T) {
	for _, total := range l78Totals {
		pol := l78Policy(total)
		allow, deny := l78Rendered(pol) // the two attribute values the policy's role renders, by construction
		if len("allow-commands=")+len(allow) > 255 || len("deny-commands=")+len(deny) > 255 {
			t.Fatalf("%d: an attribute over 255", total)
		}
		if got := len("local-user-name=p49-l78") + len("allow-commands=") + len(allow) + len("deny-commands=") + len(deny); got < total-5 || got > total+5 {
			t.Fatalf("%d: renders %d", total, got)
		}
	}
}
```

- [ ] **Step 2: Run it to fail** (`make lab-unit`).

- [ ] **Step 3: Implement `l78.go`**

```go
package lab

import (
	"fmt"
	"strings"
)

var l78Totals = []int{200, 240, 256, 300, 400, 600}

// l78Words is n distinct three-word show commands for the policy's lists:
// the projection renders each as a word list joined by "|".
func l78Words(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("show %s%02d detail", prefix, i)
	}
	return out
}

// l78Split chooses how many allow and deny words reach total bytes, each
// list's rendered value under 255.
func l78Split(total int) (allow, deny int) {
	const word = len("show xx00 detail") + 1
	budget := total - len("local-user-name=p49-l78") - len("allow-commands=") - len("deny-commands=")
	n := budget / word
	return (n + 1) / 2, n / 2
}

func l78Rendered(pol string) (allow, deny string) {
	a, d := l78Split(l78TotalOf(pol))
	return strings.Join(l78Words("al", a), "|"), strings.Join(l78Words("dn", d), "|")
}

func l78TotalOf(pol string) int {
	var n int
	fmt.Sscanf(pol[strings.Index(pol, "# total ")+len("# total "):], "%d", &n)
	return n
}

// l78Policy is the qual policy with the operator's role replaced by one whose
// Junos session reply totals about total bytes.
func l78Policy(total int) string {
	a, d := l78Split(total)
	return fmt.Sprintf(`# total %d
scopes: [{name: all_devices, match: {}}]
roles:
  - {name: l78, privilege: readonly, permit: [%s], deny: [%s]}
subjects:
  - {name: qual_operator, identity: ["user:alice@slice.port49.test"], username: qual01, token_ttl: 60s}
grants:
  - {subject: qual_operator, scope: all_devices, roles: [l78]}
`, total, quoteAll(l78Words("al", a)), quoteAll(l78Words("dn", d)))
}

func quoteAll(xs []string) string {
	q := make([]string, len(xs))
	for i, x := range xs {
		q[i] = fmt.Sprintf("%q", x)
	}
	return strings.Join(q, ", ")
}
```

The projection's real rendering decides the exact bytes. `TestL78` records the rendered total from the `authorize_session` record's `reply.attributes`, not from `l78Rendered`, and the note cites the recorded number.

- [ ] **Step 4: Run it to pass** (`make lab-unit`).

- [ ] **Step 5: Write `TestL78`** (`//go:build lab`). It copies `TestQualify`'s prologue: opt-in on `PORT49_LAB_L78=1`, one selector, `labOccupyForRun`, `labGuardAt`, `docker ps`. Per total:
  1. Write `l78Policy(total)` as the conformance config's policy, then SIGHUP port49d and wait for the refresh line.
  2. Prove break-glass (`l.dial(breakglassUser, breakglassPassword, 120*time.Second)`). If it is refused, stop and record "break-glass refused before <total>".
  3. Log in with a broker-minted token (`loginWithin("qual01", tok, 120*time.Second, "show version")`). Record whether the prompt appeared and the reply total from the record.
  4. Prove break-glass again.

  The note's table has columns total, reply bytes recorded, login, break-glass after.

- [ ] **Step 6: Run** `PORT49_LAB_L78=1 PORT49_LAB_PLATFORMS=vjunos go test -tags lab ./tests/lab/ -run '^TestL78$' -count=1 -v -timeout 90m`, in the background with the watchdog, then the same with `vjunos26`.

- [ ] **Step 7: Record per Q2 (ruled).**
  - **If a lockout is seen,** the Junos profiles' rule becomes `status: measured` with the measured `max` and `effect`, citing `L78-juniper_vjunos-router.md` (that note's Image version names the firmware).
  - **If no lockout is seen at any size,** the rule stays `unmeasured`, with its `note` reading "no lockout up to <N> bytes on vJunos <versions>; open for hardware Junos". The note records the same. L78 stays open for hardware Junos, and decision 48's budget stays provisional.

  Either way, add a dated addendum to L78's Status in §15. Then run `make qual`.

- [ ] **Step 8: Commit**: `test: L78 measured on vJunos 23.4 and 26.2; the row stays open for hardware Junos` (or `docs: close lab register entries L78` only if hardware is ever measured).

---

### Task 16: XRd 26.1.1 — the XR dialect, help first, and a full L73 row

**Files:**
- Modify: `tests/lab/l73_dialect.go` (the `cisco_xrd` entry: `HelpOnly: false`, every dialect field, the XR line builders), `tests/lab/l73_dialect_unit_test.go`, `tests/lab/harness_test.go` (`helpOnlyPlatforms` loses `xrd261`; `inventory-lab.yaml` gains `xrd1` at 172.100.100.61 as a generic platform), `tests/lab/configs/xrd-startup.cfg` (a TACACS+ server group named `port49` and a login method list with local fallback)
- Modify: spec §15 L73's Status (the platform list and the "Not measured: … XRd 26.1.1" clause, M10)
- Create: `tests/lab/results/L73-cisco_xrd.md`, `tests/lab/evidence/L73-cisco_xrd/*`; then the XRd profile through Task 14's steps

**Interfaces:**
- Produces:
  - `func l73XRApply(d l73DeviceTLS) []string`;
  - `func l73XRUndo(d l73DeviceTLS) []string`;
  - `func l73XREnrol(node string) (prep []l73Dialog, enroll, load l73Dialog)`, the same shapes as the Cisco ones;
  - a full `l73Dialect` for XR: `VersionCmd`, `VersionHas: "26.1.1"`, `LogCmd`, `ShowCmds`, `Fallback`, `Enrol`, `Revocation`, `InvalidCmds`, `Asks`.

XRd has no built-in inventory platform: it is generic, so port49d logs `platform_unknown` (PR #28). Its golden pins whatever the generic platform renders.

**Help first**, the rule every dialect follows (see the comment on the EOS dialect in `l73_dialect.go`): no line is typed that the image's own help has not listed.

- [ ] **Step 1: Ask the help.** Extend the XR `Asks` with every level the apply, undo and enrol lines will use:

  | Ask | Control words |
  |---|---|
  | `aaa group server tacacs+ port49` then `?` | `server` |
  | `tacacs-server host 192.0.2.71 tls ?` | `port` (the `Need`) |
  | `crypto key generate ?` | `rsa`, `ecdsa` |
  | `crypto ca trustpoint l73-dev ?` | the submode's words, through `DiagSubIn` |
  | `crypto ca enroll ?` | — |
  | `commit ?` | — |
  | `show running-config tacacs-server ?` | — |
  | `show logging ?` | — |

  Run `PORT49_LAB_PLATFORMS=xrd261 PORT49_L73_DIAG=help go test -tags lab ./tests/lab/ -run '^TestL73$' -count=1 -v`. The run records the help and ends INVALID by design. Read the help transcripts in `PORT49_L73_INVALID_DIR` through the filter.

- [ ] **Step 2: Write the unit tests**, from the help just recorded, then run them to fail, implement, and run them to pass.
  - `TestL73XRApplyUsesOnlyListedWords`: every keyword in `l73XRApply` and `l73XREnrol` appears in a recorded help answer, held as a fixture string in the test.
  - `TestL73XRUndoIsTheStartupConfig`: like `TestL73CiscoUndoIsTheStartupConfig`, it reads `configs/xrd-startup.cfg`.
  - `TestL73XRCommitsEachChange`: every apply and undo list ends in `commit`.

  Then fill every dialect field from the help, with nothing guessed:
  - `VersionCmd: "show version | include Version"`, if the help lists `include`;
  - `LogCmd`;
  - `ShowCmds`;
  - `Fallback`, naming `configs/xrd-startup.cfg`'s method list;
  - `Enrol`, the wording of the documented enrolment;
  - `Revocation`.

- [ ] **Step 3: Respect XRd's sshd rate limit** (60 sessions a minute, `L71-cisco_xrd.md`): every cell's login loop paces at most one session a second. Add `LoginDial` and a pacing check, with a unit test that the dialect's `RetryUnreached` loop sleeps at least 1 s between sessions.

- [ ] **Step 4: Run the full row**: `PORT49_LAB_REMEASURE=L73 PORT49_LAB_PLATFORMS=xrd261 go test -tags lab ./tests/lab/ -run '^TestL73$' -count=1 -v -timeout 180m`, in the background with the watchdog.
  - Write `L73-cisco_xrd.md`, covering cells a–j.
  - L73 stays closed. In its Status:
    - add `tests/lab/results/L73-cisco_xrd.md (XRd 26.1.1)` to the measured list;
    - rewrite the "Not measured" clause to drop XRd 26.1.1;
    - add a dated addendum giving XRd's cells (a)–(j) in the row's own style.

- [ ] **Step 5: Vet XRd** with Task 14's steps 1–3: `make lab-qualify P=xrd261`, genprofile, review, `make qual`.

- [ ] **Step 6: Commit**: `test: L73 measured on XRd 26.1.1 with an XR dialect, and its mock`.

---

### Task 17: L79 — a write delivered after the heal (the 11a M4 carry-in)

**Files:**
- Modify: `tests/lab/l74_test.go` (cells j and k after `l74CellI`, and `TestRegions`' call list), `tests/lab/l74_unit_test.go`, `tests/lab/regions_test.go` (no change unless a helper is needed)
- Create: `tests/lab/results/L79-regions.md`, `tests/lab/evidence/L79-regions/`
- Modify: spec §15 L79's Status

This comes from 11a's final dial-fix review (`review-dialfix-r2.md` M4) and the controller's ruling: carry it to this plan as a lab cell, with the reverse stray revoke. It is its own row, L79, opened by Task 1 (I10). L74's claim and its nine cells are untouched.

**How the cut is made.** The cut is the existing `regionCut(3, true)` (`regions_test.go:92`). It inserts iptables `DROP` rules in region 3's namespace, which drop its traffic with regions 1 and 2:

```
ip netns exec p49r3 iptables -I OUTPUT -d 10.149.0.11 -j DROP
ip netns exec p49r3 iptables -I INPUT  -s 10.149.0.11 -j DROP
(and the same for 10.149.0.12)
```

DROP, not REJECT, so the kernel keeps retransmitting an unacknowledged write. The heal is `regionCut(3, false)` (`-D` of the same rules). TCP retransmits for about 15 minutes at the default `net.ipv4.tcp_retries2=15`, so a heal at 20 s falls inside the window.

- [ ] **Step 1: Write the failing unit test** in `l74_unit_test.go`:

```go
func TestL79CellsAreTheirOwnRow(t *testing.T) {
	for _, c := range l79Cells {
		if c.Row != "L79" || c.Heal != 20*time.Second || c.Cut != "iptables" {
			t.Fatalf("%+v: L79's cells heal at 20s inside TCP's retransmission window, through regionCut", c)
		}
	}
	if len(l79Cells) != 2 || l79Cells[0].ID != "j" || l79Cells[1].ID != "k" {
		t.Fatal("cells j and k")
	}
}
```

- [ ] **Step 2: Implement** `l79Cells` (`{ID, Row, Claim string; Cut string; Heal time.Duration}`) and the two cells, in `l74_test.go`'s style.
  - **(j)** Revoke a principal from region 1, so the mark is in the directory. `w.cutRegion3().cutNow()`. From region 3, `port49 revoke --lift` with the 500 ms `call_timeout` returns non-zero, saying "could not be lifted, and stands". `healNow()` at +20 s. Poll the directory for the mark (`w.dirEndpoints()`, `etcdctl get`) for 60 s.
    - Record whether the mark was deleted after the heal (the late lift landed) and when.
    - Record what region 3's `port49 store status` and decision log said.
  - **(k)** Lift a mark from region 1. Under the cut, `port49 revoke` from region 3 reports failure. Heal at +20 s and poll for 60 s.
    - Record whether the mark reappeared. That is expected: it fails closed.
    - Record what an operator sees.

  Each cell's rows go through `writeRegionNote(t, w, "L79", …)` to `results/L79-regions.md`.

- [ ] **Step 3: Run** `make lab-regions` (it runs `TestRegions`, with L79 added to its cells) in the background with the watchdog.
  - Close L79 per CLAUDE.md rule 3: an L79 Status of `closed — measured <date>; tests/lab/results/L79-regions.md`.
  - **If (j) shows a lift landing after "could not be lifted":** the operator text is wrong. Fix `port49 revoke --lift`'s message and 11a's "Stores" notes in the roadmap, cite the note, and use a `fix:` commit for the message.
  - **If a revocation is silently lost (a security weakening):** stop and report it to Ryan before any fix.

- [ ] **Step 4: Commit, in two commits.**
  1. `test: L79 cells j and k on L74's harness`: `l74_test.go` and `l74_unit_test.go`.
  2. `docs: close lab register entries L79`: the note, the evidence, the §15 Status, and decision 51's provisional mark resolved (Task 1 Step 3b). That is "provisional on L79" removed, or the ruling corrected and cited if (j) contradicted it.

---

### Task 18: The L76 carry-in (R3-M1) — the mixed-pair wording

**Files:**
- Modify: `tests/lab/l76_cells.go` (`l76WriteText`'s inner switch, lines ~1075–1086), `tests/lab/l76_unit_test.go`

This is L76's final re-review 3, Minor 1 (`R3-M1`), parked "to the next L76 touch / qualification suite". For the mixed pairs (exists, unknown) and (unknown, exists), the finding's sentence says the other channel "refused the same write" although its state is unknown. The finding is still raised. No rerun is needed: run 12 was (absent, absent).

- [ ] **Step 1: Write the failing unit test**

```go
func TestL76WriteTextNeverSaysRefusedForAnUnknownChannel(t *testing.T) {
	for _, c := range []struct{ first, second, want string }{
		{l76WriteExists, l76WriteUnknown, "whether the second exec channel wrote could not be determined"},
		{l76WriteUnknown, l76WriteExists, "whether the first exec channel wrote could not be determined"},
	} {
		got := l76WriteText(l76Write{Name: "first", State: c.first}, l76Write{Name: "second", State: c.second})
		if strings.Contains(got, "refused the same write") {
			t.Fatalf("%s/%s says refused for a channel whose state is unknown: %q", c.first, c.second, got)
		}
		if !strings.Contains(got, c.want) || !strings.Contains(got, "**Security finding:**") {
			t.Fatalf("%s/%s: the finding is raised and names the undetermined channel: %q", c.first, c.second, got)
		}
	}
	got := l76WriteText(l76Write{Name: "first", State: l76WriteExists}, l76Write{Name: "second", State: l76WriteAbsent})
	if !strings.Contains(got, "the second exec channel refused the same write") {
		t.Fatalf("(exists, absent) keeps its measured wording: %q", got)
	}
}
```

- [ ] **Step 2: Run it to fail** (`make lab-unit`). Then fix the inner switch so that:
  - each one-sided case requires the other channel to be `l76WriteAbsent`;
  - two new cases cover one write beside an unknown channel: "wrote on the first exec channel of one SSH login; whether the second exec channel wrote could not be determined." and its mirror;
  - every other mix falls to the existing "may have written" default.

  Run it to pass.

- [ ] **Step 3: Commit**: `fix(lab): L76's mixed write pairs no longer say refused for an unknown channel (R3-M1)`.

---

### Task 19: Fleet mode

**Files:**
- Create: `internal/devicemock/fleet.go`, `internal/devicemock/fleet_test.go`, `internal/port49d/qual_fleet_linux_test.go`
- Modify: `Makefile` (`qual-fleet`)

**Interfaces:**
- Consumes: `Play` and the fake server (Task 9); `qualDaemon` with `qualOpts.devices` (Task 10).
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
	Outcomes map[string]int
	Errors   int
	P50, P99 time.Duration
}
func (f Fleet) Run(ctx context.Context, target func(i int) Target, login func(i int) Login) FleetResult
func LoopbackSource(i int) string
```

- [ ] **Step 1: Write the failing unit test**

```go
func TestLoopbackSource(t *testing.T) {
	for i, want := range map[int]string{0: "127.0.1.1", 253: "127.0.1.254", 254: "127.0.2.1", 507: "127.0.2.254"} {
		if got := LoopbackSource(i); got != want {
			t.Errorf("LoopbackSource(%d) = %s, want %s", i, got, want)
		}
	}
}

func TestFleetPlaysEveryDeviceWithinItsConcurrency(t *testing.T) {
	f := newFake(t, []byte("fresh-key"))
	f.authen = []uint8{wire.AuthenStatusPass}
	f.authorArgs = [][]byte{[]byte("local-user-name=p49-ro")}
	p, _ := Load("testdata/profiles/fixture_plain.yaml", root)
	res := Fleet{Profile: p, N: 50, Concurrency: 10, Scenario: "token_login"}.Run(t.Context(),
		func(int) Target { return Target{Addr: f.ln.Addr().String(), Transport: "tcp", Key: f.key, Scale: 1} },
		func(int) Login { return Login{User: "q", Credential: freshCredential(t)} })
	if res.Plays != 50 || res.Outcomes["login_ok"] != 50 || res.Errors != 0 || res.P99 < res.P50 {
		t.Fatalf("%+v", res)
	}
}
```

- [ ] **Step 2: Run to fail, then implement `fleet.go`**:

```go
package devicemock

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"
)

// LoopbackSource is fleet device i's source address: 127.0.1.1 to 127.0.1.254,
// then 127.0.2.1 and on. Linux answers all of 127.0.0.0/8 with no set-up.
func LoopbackSource(i int) string {
	return fmt.Sprintf("127.0.%d.%d", 1+i/254, 1+i%254)
}

func (f Fleet) Run(ctx context.Context, target func(i int) Target, login func(i int) Login) FleetResult {
	c := f.Concurrency
	if c <= 0 {
		c = f.N
	}
	sem := make(chan struct{}, c)
	var (
		mu    sync.Mutex
		wg    sync.WaitGroup
		res   = FleetResult{Outcomes: map[string]int{}}
		times []time.Duration
	)
	for i := range f.N {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			tr, err := Play(ctx, f.Profile, f.Scenario, target(i), login(i))
			d := time.Since(start)
			mu.Lock()
			defer mu.Unlock()
			res.Plays++
			times = append(times, d)
			if err != nil {
				res.Errors++ // never printed: a transcript names steps, but a fleet's are not read one by one
				return
			}
			res.Outcomes[tr.Outcome]++
		}()
	}
	wg.Wait()
	slices.Sort(times)
	if n := len(times); n > 0 {
		res.P50, res.P99 = times[n/2], times[min(n-1, n*99/100)]
	}
	return res
}
```

Run it to pass.

- [ ] **Step 3: Write `TestQualFleet`** (`//go:build linux`; it skips unless `PORT49_QUAL_FLEET=1`):

```go
func TestQualFleet(t *testing.T) {
	if os.Getenv("PORT49_QUAL_FLEET") != "1" {
		t.Skip("make qual-fleet")
	}
	const n = 500
	p, err := devicemock.Load("../../tests/qual/profiles/arista_eos/cEOS-lab-4.36.3M.yaml", "../..")
	if err != nil {
		t.Fatal(err)
	}
	run := qualDaemon(t, p, qualOpts{scale: 0.1, handshakeTimeout: time.Second, devices: n})
	fleet := devicemock.Fleet{Profile: p, N: n, Concurrency: 100, Scenario: "token_login"}
	phase := func(name string, mid func()) devicemock.FleetResult {
		// Mint every device's token here, on the test goroutine: mint's helpers
		// call t.Fatal, which is invalid from a worker (re-review I-F). Workers
		// only index this slice.
		logins := make([]devicemock.Login, n)
		for i := range n {
			logins[i] = run.login(i)
		}
		if mid != nil {
			go func() { time.Sleep(200 * time.Millisecond); mid() }() // mid never calls a t helper
		}
		res := fleet.Run(t.Context(), func(i int) devicemock.Target { return run.target(p, i) },
			func(i int) devicemock.Login { return logins[i] })
		t.Logf("%s: %d plays, outcomes %v, errors %d, p50 %s, p99 %s", name, res.Plays, res.Outcomes, res.Errors, res.P50, res.P99)
		return res
	}
	if res := phase("concurrent logins", nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("every device logs in: %v", res.Outcomes)
	}
	if res := phase("reload under load", run.touchPolicy); res.Outcomes["login_ok"] != n {
		t.Fatalf("a reload under load loses no login: %v", res.Outcomes)
	}
	// The 1 s watch and the push may land after the phase's plays end: wait for it.
	qualWaitFor(t, run.stderr, "port49d: policy refresh", 10*time.Second)
	res := phase("store down under load", func() { run.fault("store_unavailable") })
	if res.Outcomes["login_ok"]+res.Outcomes["falls_to_local"] != n || res.P99 > 10*time.Second {
		t.Fatalf("each play either logged in before the fault or fell to local after it, none hung: %+v", res)
	}
	run.fault("")
	if res := phase("store back", nil); res.Outcomes["login_ok"] != n {
		t.Fatalf("clearing the fault returns every play to login_ok: %v", res.Outcomes)
	}
}
```

`run.touchPolicy` rewrites the policy file with one more harmless deny (`show qual-reload-<n>`) added to `qual_denies`, a real change, and the broker's 1 s policy watch reloads it.

`run.said(sub)` searches port49d's stderr buffer, not the decision log. `port49d: policy refresh` is the prefix `internal/port49d/reload.go:1307-1309` writes after a reload refreshes contexts; `run_test.go`'s `TestRunServesAPolicyEditToALiveSessionWithNoLogout` waits on the same line.

`run.login` mints once per play, on the test goroutine before the phase starts; with 500 devices the broker's per-principal connection cap applies, so set `MaxConnsPerPrincipal` in `qualDaemon` to `max(4, o.devices)`. The test asserts no latency number: plan 12 sets the targets.

- [ ] **Step 4: Makefile**

```make
# Fleet mode (plan 11b): N mock devices from N loopback addresses against one port49d.
# Linux. Plan 12's load validation drives it at the §5 target rate.
qual-fleet:
	PORT49_QUAL_FLEET=1 go test ./internal/port49d/ -run '^TestQualFleet$$' -count=1 -v -timeout 30m
```

- [ ] **Step 5: Run** `make qual-fleet && make check-darwin`
Expected: PASS, with the four phases' P50 and P99 logged; darwin clean.

- [ ] **Step 6: Commit**: `test: fleet mode, N mock devices against one port49d`.

---

### Task 20: The free-image tier: SR Linux on a runner

**Files:**
- Create: `.github/workflows/lab-free.yml`

SR Linux (`ghcr.io/nokia/srlinux`) is freely redistributable, so it may run on a hosted runner. No vendor image ever does (decision 52 ruling 7). By Q1's ruling, the trigger is manual dispatch and release tags only.

The job first proves the harness's prerequisites on the runner (I7): the harness captures with tcpdump, binds 172.100.100.1:49, and uses `sudo -n` and the `docker` group. Then it runs `TestQualify` and `TestL76` for `srlinux`. It fails:
- if `notediff -fail-on-change` reports a changed observation;
- if `genprofile -check` finds the generated stimulus differs from the committed profile.

- [ ] **Step 1: Write the workflow**

```yaml
# The free-image tier (plan 11b): SR Linux, the one lab image that may run on a hosted runner
# (vendor images are never redistributed). runs-on is one line; beehive's self-hosted label is
# the other choice. Triggers per the 2026-10-19 ruling: dispatch and release tags. Moving to
# path-filtered PRs later is this one change to `on:`:
#   pull_request: {paths: ['internal/platform/**', 'internal/daemon/**', 'tests/qual/**']}
name: lab-free
on:
  workflow_dispatch:
  push: {tags: ['v*']}
permissions: {contents: read}
jobs:
  srlinux:
    runs-on: ubuntu-24.04
    timeout-minutes: 90
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with: {go-version-file: go.mod}
      - name: Prove the lab harness can run here
        run: |
          sudo -n true
          command -v tcpdump || sudo apt-get install -y tcpdump
          sudo -n tcpdump --version
          docker info >/dev/null
          id -nG | tr ' ' '\n' | grep -qx docker || sudo usermod -aG docker "$USER"
      - run: bash -c "$(curl -sL https://get.containerlab.dev)" -- -v 0.71.1
      - run: docker pull ghcr.io/nokia/srlinux:26.7.2-519
      - run: make build
      # Two processes, each with its own TestMain teardown: in one, TestL76 leaves srl1 up
      # and TestQualify's single-occupant docker ps check refuses to run (re-review I-C).
      - name: L76
        run: sg docker -c "PORT49_LAB_REMEASURE=L76 PORT49_LAB_PLATFORMS=srlinux go test -tags lab ./tests/lab/ -run '^TestL76$' -count=1 -v -timeout 40m"
      - name: The conformance run
        run: sg docker -c "PORT49_LAB_QUALIFY=1 PORT49_LAB_PLATFORMS=srlinux go test -tags lab ./tests/lab/ -run '^TestQualify$' -count=1 -v -timeout 40m"
      - run: go run ./tests/lab/cmd/notediff -fail-on-change -note tests/lab/results/L76-nokia_srlinux.md
      - run: go run ./tests/qual/cmd/genprofile -check -evidence tests/lab/evidence/QUAL-SR-Linux-26.7.2-519-nokia_srlinux
```

`genprofile -check` stays stable on SR Linux's `session.port`:
- all 35 `redeem` and `authorize_session` records in `tests/lab/evidence/L76-nokia_srlinux/decisions.jsonl` carry `ssh`;
- its `account` records carry `ssh` (22) or `unknown` (78; a second exec channel, L76 cell c), and `steps` takes the account steps' port from the login's own start and stop records (`ssh`), never from the first `account` record in the run (Task 13).

If a later run records a per-session value in the login's own records, template it as `{port}` in `qualRecord` and the engine.

Pin containerlab to the version beehive runs (`containerlab version`). If the prerequisite step cannot pass on a hosted runner (the 172.100.100.0/24 bridge, sudo), switch `runs-on` to beehive's self-hosted label and say so in the as-built. That is the one-line change the Global Constraints keep available.

- [ ] **Step 2: Validate the YAML**: `python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))' .github/workflows/lab-free.yml`.

  `gh workflow run lab-free.yml` dispatches only a workflow that is already on the default branch, so the first dispatch happens after this plan's PR merges. The controller runs it then (`gh workflow run lab-free.yml`, then `gh run list --workflow lab-free.yml --limit 1`) and records the result in the as-built entry (Task 23). If the prerequisites step fails on the hosted runner, `runs-on` moves to beehive in a one-line follow-up.
- [ ] **Step 3: Commit**: `ci: the free-image tier runs SR Linux's qualification on dispatch and tags`.

---

### Task 21: The qualified-platforms list, generated

**Files:**
- Create: `tests/qual/cmd/qualified/main.go`, `tests/qual/cmd/qualified/qualified.go`, `tests/qual/cmd/qualified/qualified_test.go`, `docs/qualified-platforms.md`
- Modify: `Makefile` (`qualified-platforms`)

**Interfaces:**
- Consumes: `devicemock.Load`, `devicemock.LoadGolden`.
- Produces: `func Build(repoRoot string) (string, error)`, which returns a Markdown table.

| vendor | OS | version tested | TACACS+ 49 | TLS 300 | command authorization | accounting | mock | status |

A row exists only where a profile exists and every note it cites exists. Untested platforms are not listed. The cells are defined from the golden:
- **TACACS+ 49:** `yes` when the profile's transports include `tcp` and the golden's `token_login` outcome is `login_ok`.
- **TLS 300:** `yes` when the transports include `tls` and the golden's `tls_token_login` outcome is `login_ok`; `—` without `tls`.
- **command authorization:** `yes` when the golden's `token_login` steps hold a `command_permitted` with event `author_pass_add` or `author_pass_repl`, and a `command_denied` with `author_fail`.
- **accounting:** `yes` when an `account_stop` step has event `acct_success`.
- **status:**
  - `re-vet pending` when the golden is `pending_lab`;
  - else `qualified` when every one of the four cells above that applies is `yes`;
  - else `partial`.

- [ ] **Step 1: Write the failing tests**

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

func TestStatusFromTheGolden(t *testing.T) {
	g := devicemock.Golden{Scenarios: map[string]devicemock.GoldenScenario{"token_login": {Outcome: "login_ok", Steps: []devicemock.GoldenStep{
		{Step: "command_permitted", Event: "author_pass_add"}, {Step: "command_denied", Event: "author_fail"}, {Step: "account_stop", Event: "acct_success"}}}}}
	if s := status([]string{"tcp"}, g); s != "qualified" {
		t.Fatalf("%s", s)
	}
	g.PendingLab = true
	if s := status([]string{"tcp"}, g); s != "re-vet pending" {
		t.Fatalf("%s", s)
	}
	g.PendingLab = false
	g.Scenarios["token_login"] = devicemock.GoldenScenario{Outcome: "login_refused"}
	if s := status([]string{"tcp"}, g); s != "partial" {
		t.Fatalf("%s", s)
	}
}

func TestARowNeedsItsNotes(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "tests/qual/profiles/x"), 0o755)
	raw, _ := os.ReadFile("../../../../internal/devicemock/testdata/profiles/fixture_plain.yaml")
	os.WriteFile(filepath.Join(dir, "tests/qual/profiles/x/1.0.yaml"), raw, 0o600) // its notes/ are absent here
	if _, err := Build(dir); err == nil || !strings.Contains(err.Error(), "L99-fixture_junos.md") {
		t.Fatal("a profile whose note is missing makes no row: the build fails naming it")
	}
}
```

- [ ] **Step 2: Run to fail, implement, run to pass.**
  - `Build` globs `tests/qual/profiles/*/*.yaml`, loads each with `devicemock.Load` (which fails on a missing note), and loads its golden.
  - The vendor and OS come from a fixed map of inventory platforms:
    - `arista_eos` → Arista EOS;
    - `cisco_nxos` → Cisco NX-OS;
    - `cisco_iosxe` → Cisco IOS XE;
    - `juniper_junos` → Juniper Junos;
    - `nokia_srlinux` → Nokia SR Linux;
    - `generic` with `lab_platform` `cisco_xrd` → Cisco IOS XR (XRd).
  - Rows are sorted by vendor, then version.
  - The page starts with a one-paragraph header naming the generator and saying that the list is what the lab measured, not what port49 claims.

  `make qualified-platforms` runs `go run ./tests/qual/cmd/qualified > docs/qualified-platforms.md`.
- [ ] **Step 3: Commit**: `docs: the qualified-platforms list, generated from the profiles and notes`.

---

### Task 22: `make qual-vet` and the contributor procedures

**Files:**
- Create: `tests/qual/vet.sh`, `tests/qual/README.md`
- Modify: `Makefile` (`qual-vet`), `tests/lab/README.md` (a pointer)

`make qual-vet P=<selector>` turns "vet a new firmware and add its mock" into one command.

It refuses when:
- the STOP sentinel exists;
- `flock -n /tmp/port49-lab.lock true` fails;
- the working tree has changes under `tests/qual` or `tests/lab/results`.

Then it runs, in order:
1. `make lab-qualify P=<sel>`;
2. `genprofile` on the new evidence;
3. `make qual`;
4. `make qualified-platforms`.

It ends by printing `git status --short` and `git diff --stat` for `tests/qual`, the note and the list, then genprofile's review checklist. It commits nothing: the review is a person's.

- [ ] **Step 1: Write `vet.sh`**

```bash
#!/usr/bin/env bash
# make qual-vet P=<selector>: vet a firmware and generate its mock for review (plan 11b).
set -euo pipefail
sel="${1:?usage: make qual-vet P=<selector>}"
[ -e /tmp/port49-STOP-LAB ] && { echo "qual-vet: /tmp/port49-STOP-LAB exists"; exit 1; }
flock -n /tmp/port49-lab.lock true || { echo "qual-vet: the lab is occupied ($(cat /tmp/port49-lab.lock))"; exit 1; }
git diff --quiet -- tests/qual tests/lab/results || { echo "qual-vet: commit or stash tests/qual and tests/lab/results first"; exit 1; }
log="/tmp/claude-qual-vet-${sel}-$(date +%s).log"
filter() { grep -v -i 'password\|token\|secret\|eyJ' | sed -E 's/[A-Za-z0-9_+\/=.-]{24,}/<LONG>/g'; }
make lab-qualify P="$sel" >"$log" 2>&1 || { tail -40 "$log" | filter; exit 1; }
filter <"$log" | grep -E '^(--- |ok |FAIL)'
ev=$(ls -td tests/lab/evidence/QUAL-*/ | head -1)
go run ./tests/qual/cmd/genprofile -evidence "$ev"
make qual
make qualified-platforms
git status --short -- tests/qual tests/lab/results tests/lab/evidence docs/qualified-platforms.md
git diff --stat -- tests/qual docs/qualified-platforms.md
echo "qual-vet: review the profile against its note (the checklist above), then commit."
```

```make
qual-vet:
	@test -n "$(P)" || { echo "usage: make qual-vet P=<selector>"; exit 2; }
	bash tests/qual/vet.sh $(P)
```

- [ ] **Step 2: Write `tests/qual/README.md`** with these procedures:
  - **Vet a new firmware and add its mock.**
    1. Put the image on `/mnt/images`.
    2. Add its `platforms` row: selector, topology, image, version (as the device reports it), and a measured `boot`.
    3. Run `make qual-vet P=<sel>`.
    4. Review the profile's reactions and acceptance rules against the note. A claim is measured only when a note for **this** firmware measured it (decision 52 ruling 4).
    5. Commit the evidence, the note, the profile, the golden and the list.

    No mock is added for an image the lab has not run (ruling 8).
  - **Add a platform.**
    1. Add a `platforms` row and a topology.
    2. Write a startup config with break-glass and the `port49` TACACS+ server group.
    3. For TLS, add an `l73Dialects` row written help first.
    4. Give it a port49 inventory platform: built in, or generic (which logs `platform_unknown`).
    5. Vet it as above.

    Any engine gap it needs becomes an `engine_gaps` entry, plus Go in `internal/devicemock` with a test.
  - **When a mock fails on a PR.**
    - **A gate (an acceptance rule).** The device would reject port49's reply. Fix port49, or, if the rule is wrong, re-measure it in the lab.
    - **A golden difference.** If port49 changed on purpose, run `make qual-update` and review the diff. The list shows re-vet pending until the next lab run.
    - **A missing reaction.** The vetter adds it from the notes.
  - **The release-tag gate.**
    1. `make lab-regress`.
    2. `make qual-vet` for every profile whose golden is pending.
    3. Commit.
- [ ] **Step 3: Run** `bash -n tests/qual/vet.sh`, then `make qual-vet P=` (it prints the usage and exits 2).
- [ ] **Step 4: Commit**: `docs: make qual-vet and the procedures to vet a firmware and add a platform`.

---

### Task 23: Docs — the roadmap as built, and the operator notes

**Files:**
- Modify: `docs/superpowers/plans/README.md` ("Plan 11b — As built", the status line), `tests/lab/README.md`

- [ ] **Step 1: Write "Plan 11b — As built"** in 11a's style. It covers:
  - the task commits;
  - the rulings as recorded;
  - what the lab changed;
  - the full lab-regress time (Task 4);
  - `TestQual`'s wall time (Task 14);
  - L78's result;
  - XRd's L73 note;
  - L79;
  - what was carried forward.
- [ ] **Step 2: Write the hand-offs.**
  - **Plan 12:**
    - the load test drives `make qual-fleet` at the §5 rate;
    - a deployment shape's smoke test may use a mock device in place of vEOS;
    - decision 48's budget is provisional on L78 (hardware Junos).
  - **Plan 13:**
    - the qualified-platforms page, from `docs/qualified-platforms.md`;
    - the contributor guide, from `tests/qual/README.md`;
    - `packet_fields` in the decision-log reference.
  - **Pre-beta review:** `make lab-regress` in full.
- [ ] **Step 3: Write the operator-facing notes for the PR body.**
  - `packet_fields` on every validated request record;
  - `docs/qualified-platforms.md`;
  - if Task 17 changed it, `port49 revoke --lift`'s message.

  Nothing else is operator-visible: no config key, reason code or metric.
- [ ] **Step 4: Run** `make test && make vet` on beehive and report the output.
- [ ] **Step 5: Commit**: `docs: plan 11b as built`.

---

## Self-review notes

### Coverage of Ryan's 2026-10-19 design

- **Mocks per platform and firmware:** Tasks 6–10 and 14.
- **Hello parameters, ext 27 included:** Task 8.
- **Timing:** the scaled delay, one real run, and judgment from port49's log (Task 10).
- **Connection pattern:** Task 9.
- **Packet fields and attributes from validated records, the version byte included:** Tasks 5, 8, 12 and 13.
- **Failure cases:** Tasks 9, 10 and 14.
- **Every PR, any runner:** Task 11.
- **The real lab for tags and image changes:** Tasks 2–4 and 22.
- **New firmware only after vetting, automated:** Task 22.
- **Lab regressions:** under the lock and STOP, diffed with timings kept, timed early (Tasks 2–4).
- **Vendor images never hosted; SR Linux on dispatch and tags:** Task 20.
- **`runs-on` on one line:** Tasks 11 and 20.
- **Carry-ins:**
  - XRd (Task 16);
  - M4 as L79 (Task 17);
  - R3-M1 (Task 18).
- **The qualified list:** Task 21.
- **The three-part profile and the escape hatch:** Tasks 6, 7 and 9.
- **The generator's pre-fill:** Task 13.
- **The acceptance-violation test, through `Judge`:** Tasks 9 and 10.
- **Fleet:** Task 19.
- **SSH front:** later work.
- **cisshgo:** credited.

### Security rules

- **No body decode:** Task 12 keeps headers only; Task 13 refuses captures and unknown files.
- **Fresh credentials through the broker:** Tasks 9, 10 and 12.
- **No hash in fixtures, output or failure messages:** Tasks 6, 10, 12 and 13.
- **Certificates per test:** Task 10.
- **Log filter:** Global Constraints; Tasks 4, 14 and 22.
- **Darwin:** the `_linux` files in Tasks 2 and 19.
