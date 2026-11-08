# Pin Re-seal on Encryption Rotation (#52) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A key rotation no longer strands directory pins. The scheduled directory pass re-seals each pin that opened under `encryption.previous`, by compare-and-swap. Three gauges say what is left, rotation's step 3 waits for zero, and the key-rotation page loses its forget-every-principal procedure (issue #52, as agreed with Ryan on 2026-11-07).

**Architecture:**
- `store.Membership` gets `Stale`, set by `crypt` as `SecondFactor.Stale` is.
- A new store listing, `MembershipSeals`, returns each live pin's principal, version and sealing key id in the same 500-record pages `MembershipPrincipals` reads. The crypt layer marks the entries under its current key.
- `placement.ResealPins` opens and rewrites only the pins not under the current key, through the existing `PutPin` compare. A pass with every pin on `current` costs N/500 range reads and no per-pin read.
- `broker.RefreshDirectory` calls it after the second-factor re-seal and sets three label-free gauges.
- One new alert, gated on the keyspace holder, and the docs.
- No reason code. No §12 warning. No config key. No lab run.

**Tech Stack:** Go 1.26. `internal/store` (memory, etcd, guard, crypt, placement, storetest), `internal/broker`, `internal/daemon/metrics`, `internal/port49d`, Prometheus rules (`make alerts-check`), `make docs`.

**Spec and history:**
- Issue #52.
- Spec §13 decision 47 ruling 11 (the second-factor re-seal), decision 51 R13 (the unleased pin), and design §15 (the store's metrics and alarms).
- `docs/site/admin/key-rotation.md` lines 154-213, the workaround this plan retires.
- The pre-flight `.superpowers/sdd/2026-11-08-pin-reseal/preflight.md` (M1-M2, S1-S4, notes 1-9) and the lead's rulings on it (2026-11-08), applied here.

## Root causes (investigation 2026-11-08, `main` `19ca91f5`)

1. **A pin is written once and never again while it holds.**
   - `placement.PutMembership` writes the directory only when the pin differs: `case st == pinHeld && samePin(pin, m): return p.Store.PutMembership(...)` (`internal/store/placement/placement.go:323`; `samePin` at `:215-217`).
   - The directory pin has no lease (`PutPin` writes `store.NoExpiry`, `internal/store/etcd/membership.go:62-64`).
   - So a pin keeps the key that was `current` at its first bind, forever.
2. **One `previous` slot.** `crypt.Keys{Current, Previous *Key}` (`internal/store/crypt/crypt.go:116-119`). A second rotation's step 1 drops K1, and `openMembership` (`crypt.go:1207`) then fails with `ErrUnknownKey` for every pin still under K1.
3. **The second-factor pass already has the shape to copy.**
   - `Broker.ResealSecondFactors` (`internal/broker/signin_admin.go:64-120`) does three things. It lists, reads, and swaps a `Stale` record at its `Rev`. It treats `ErrConflict` as "the next pass looks again". It counts an unopenable record and says it once an hour per principal, and never deletes it.
   - It runs from `enrollmentPass` (called at `internal/broker/scheduled.go:120-122`, defined at `:129-144`), the tail of `RefreshDirectory`.
   - On port49-broker, `RefreshDirectory` runs only in the runner's duties (`internal/port49d/runner.go:322` `scheduledDuty`, under the keyspace hold, plan 7e Ruling 6). On port49d it runs in the one process that mints (`internal/port49d/main.go:1591`). Neither ever runs it twice in one keyspace.
4. **Where pins live, per backend.**
   - Directory pins exist only on port49-broker with a directory store of its own (`!cfg.Stores.Shared`). There, `placement.Config.Members` is a `lazyMembers` over the directory etcd, sealed by `crypt.Wrap` (`internal/port49d/brokerd.go:386-395`, `internal/port49d/storeref.go:137-196`).
   - The backends are memory and etcd. `enrollfile` holds second factors, not memberships.
   - Both backends implement `PutPin`'s compare: etcd `casPin` on `ModRevision` (`internal/store/etcd/membership.go:97-140`), memory `stands` on `ver` (`internal/store/memory/memory.go:1668-1676`). `storetest` runs it on both (`MembershipPinIsCompareAndSet`, `internal/store/storetest/membership.go:602-646`).
   - `GetMembership` returns `Version` (etcd `:232-247`, memory `:1794`). `MembershipPrincipals` lists live, unforgotten records (etcd `:348-375`, which decodes each `membershipRec`, `Sealed` included, 500 at a time; memory `:1824`).
   - `placement.Members` has no listing method. `lazyMembers` needs one.
   - On a shared store, `placement` is not in the path. Membership is a leased record (`Resolver.TTL()` = max(grace, 24h), `internal/directory/resolver.go:86`) that every verification rewrites. That is the 24-hour wait already on the page (line 147-150).
5. **The cost of reading every pin (pre-flight M2).** Pins have no lease, so the directory holds one for every principal ever bound. One linearizable `Get` per pin, sequentially, every `refresh_interval`, at the tail of `RefreshDirectory`, would delay the next refresh. At 10,000 pins and 80 ms RTT that is about 13 minutes, which would fire `port49_directory_refresh_stale` with nothing wrong with LDAP. The listing already decodes each record's `Sealed`, whose header names its key id (`crypt.go` `SealedKeyID`). So the pass reads the key ids in bulk and opens only the records not under `current`.
6. **The stranded admin.** `adminRight` resolves the caller's own membership before the right (`internal/broker/admin_api.go:98-110`, `memberFor` at `:103`). An admin whose own pin does not open is refused there. `brokerSubcommands` (`internal/port49d/brokerd.go:47-66`) has no forget.
7. **A JSON failure carries plaintext (pre-flight note 7).** `openMembership` passes the raw `json.Unmarshal` error (`crypt.go:1216-1217`, `invalid character 'x' ...`) to `openErr`. The pin line would then log one authenticated plaintext byte. The second-factor path uses sentinels (`errSecondFactorBody`).

## Rulings made in this plan

1. **No offline `port49-broker forget`.** It goes under Left. With Tasks 4-5 in place, a pin strands only when step 3 is run against a nonzero gauge, or when a key is lost. The first case is undone by putting the key back as `previous` and restarting. Nothing is deleted, and the page already requires every old key file to be kept offline (line 220). In the second case, the cure is a forget by any admin whose own pin opens. That pin was re-sealed, because the pass covers every pin that opens. An offline forget would be a second path around the touch-gated, recorded API. It would need its own decision-log record and its own fence, so it is not worth adding before beta.
2. **The count's surface is three metrics plus the broker's lines.** There is no CLI field. `port49 store status` and the admin API stay as they are (see Left).
   - `port49_directory_pins_sealed_previous`
   - `port49_directory_pins_unopenable`
   - `port49_directory_pins_reseal_last_complete_timestamp_seconds`

   They extend design §15's store list. They are gauges with no label, so no principal or device is in a label. They are set only by a pass that completes, left unchanged by one that stops, and absent until the first pass and wherever the store holds no pins.
3. **A CAS conflict is counted under `sealed_previous`.** The writer between the read and the write sealed under its own `current`, which before step 2 finished everywhere may still be the old key. The gauge stays above 0 until a later pass reads the pin as not Stale. This errs toward waiting.
4. **One alert: `port49_directory_pins_unopenable > 0 and on(instance) port49_store_keyspace_held == 1`, ticket.**
   - One person cannot bind, mint or refresh, which is not a page. `sealed_previous > 0` is the normal state between step 2 and the next pass, so it gets no alert.
   - The gate (pre-flight S1): a replica that hands over the keyspace keeps its last gauge values until it restarts. Only the holder's value is current.
5. **The pass runs after every `RefreshDirectory`, whatever its outcome,** with or without password sign-in. Pins exist with any directory, so it is not gated on `PasswordSignIn`.
6. **The new spec decision is 57.** Decisions 47 ruling 11 and 51 R13 are amended in place, pointing at it.
7. **The bulk listing is a `store.Store` method, `MembershipSeals`** (pre-flight M2). It returns `{Principal, KeyID, Version}` per live, unforgotten record, on both backends. The crypt layer adds `Current`. The backends read the header with a new `store.SealedKeyID`. They cannot import `crypt`, because crypt's tests import `memory` and that would make a cycle. `crypt.SealedKeyID` becomes `LineKeyID(store.SealedKeyID(...))`, so there is still one parser.
8. **A pass names at most 20 unopenable principals** (pre-flight S4). A lost key strands every pin, and one line per principal per hour would flood the log and grow `sayOnce`'s map. The aggregate line says `; N more are not named`.
9. **`ResealPins` reports whether the store holds pins** (pre-flight note 2): `(store.PinReseal, bool, error)`. A router with no directory half answers `false`, and `pinPass` sets no gauge for it.

## What an operator sees at 3am

| Event | What happens | What they see |
|---|---|---|
| A normal pass, no rotation under way | One paged listing of the directory's pins, 500 a page. No pin is opened or written. | Nothing. `sealed_previous` 0, `unopenable` 0, and the timestamp moves. |
| The directory store stops answering mid-pass | The bounded listing, read or write returns `ErrUnavailable`, and the pass stops. Each pin is one CAS, so nothing is half-written. | `directory store: the re-seal of pins stopped: <error>; the next pass starts again`, once an hour. The gauges keep the last complete pass's values, and the timestamp does not move. |
| port49-broker restarts mid-pass | The duty's ctx ends the pass silently, and the next runner's first pass starts from the listing. | The gauges are absent until that pass completes. |
| Two brokers run the pass at once | In one region, only the hold holder runs it. Across regions, both runners read one directory: one CAS wins, and the other gets `ErrConflict` and counts it under `sealed_previous`. Neither overwrites the other. | One pass's `sealed_previous` reads 1 for that pin, then 0 at the next pass. |
| The runner hands over the keyspace | The old holder stops running passes and keeps its last gauge values. | The alert reads only the holder (`port49_store_keyspace_held == 1`), and the page says to read the holder. |
| A pin opens under neither key | It is counted under `unopenable` and left as it is: no write, no delete. Each pass opens it again, so `port49_crypt_open_failures_total{record="membership"}` rises once per pass per stranded pin. | For up to 20 principals per pass, `directory store: <principal>'s pin does not open (<error>): it is left as it is; put the key that sealed it back as encryption.previous and restart, or run `port49 directory forget <principal>``, once an hour per principal. Also `directory store: N pins open under neither encryption key; ...[; M more are not named]`, once an hour. The alert `port49_directory_pins_unopenable` fires on the holder. |
| Step 2 is half done across regions | A runner still on (K1, K2) reads a K2 pin as Stale and seals it back under K1. The second-factor pass does the same today. Every process holds both keys, so this is harmless. | The page says to wait for a pass that ends after the last step-2 restart. |

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case for data. The metric names above are snake_case (`TestEveryMetricNameIsSnakeCase`).
- Reason codes only from spec §5.7, and this plan adds none. Warnings only from spec §12, and this plan adds none: the new lines are broker log lines, not `policy test` warnings.
- No device or principal identity in a metric label (`TestNoMetricHasADeviceLabel`). The three gauges have no labels.
- The log never contains a credential, token, pin plaintext or key material. Credentials appear only as `credential_sha256`.
  - A pin line names the principal, as `refresh-verify:` lines do today, and the error through `printsafe.Line`. The error comes from crypt, names a key id at most, and after Task 2 never carries a decoded byte.
  - No line prints a DN, a username, a map key or a sealed byte.
  - Tests never print `Sealed`. They use `crypt.SealedKeyID`.
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, or key files.
  - Every recursive grep excludes them. grep is ugrep: use `-e PATTERN`, never `--` before a pattern. Never grep `tests/lab/logs` or `tests/lab/captures`.
  - If a safety check refuses a command, stop and report it. Never rephrase it.
- Tests: `TMPDIR` is a private 0700 directory under `~/.cache`. `internal/port49d` and the etcd store tests are slow, so give them `-timeout 30m` (the Makefile's own, `Makefile:104-114`). Before the final review, run `make test && make vet && make docs && make alerts-check` and report the real output. `git status` after `make docs` shows no diff.
- **Commits:**
  - Conventional Commits, one per "Commit" step, with an explicit pathspec.
  - Every message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and nothing else. No `Claude-Session:` line, and no claude.ai URL anywhere: commits, PR body, comments.
- **Branch:** `fix/pin-reseal-52`, from `main` `19ca91f5`, in `.worktrees/pin-reseal-52`. The tasks are sequential.
- **Lab:** none needed. The pass uses only `PutPin`'s existing compare and a listing that `storetest` runs on memory and etcd. No device behavior changes, and no §15 row changes status. L75 (f) measured pins across brokers and still holds.

## Review Focus

1. **The CAS is the only write.** `ResealPins` writes only through `p.putPin(ctx, pin, store.PinExpect{Version: pin.Version})`, with the version its own `GetMembership` read. Never through `PutMembership` (its `samePin` short-circuit would skip the write) or `Members.PutPin` with `Absent` or `Forgotten`.
2. **No pin is deleted or rewritten unless it opened Stale.** An unopenable pin and a pin forgotten since the listing (`ErrForgotten` is an `ErrNotFound`) get no write.
3. **Only non-current pins are opened.** An entry the crypt layer marks `Current` is skipped with no read. A backend with no crypt marks none, so it reads everything, which is correct and only slower.
4. **An outage stops the pass and leaves the gauges alone.** Only a complete pass on a store that holds pins sets them. A canceled ctx says nothing.
5. **`Stale` is computed in `openMembership` before `m.Sealed` is cleared**, exactly as `GetSecondFactor` computes it (`crypt/enrollments.go:121`).
6. **The page's step 3 condition is the gauge on a pass after the last step-2 restart**, read on the keyspace holder, with the 24-hour membership-lease wait kept.

---

### Task 1: Spec: decision 57, its amendments, and design §15

**Files:**
- Modify `docs/design/2026-08-23-policy-engine-spec.md`:
  - append decision 57 after decision 56 ruling 13 (before the `---` that precedes `## 14.`);
  - add an amendment line to decision 47 ruling 11 (the bullet `**11. Seal-key rotation.**`);
  - add an amendment line to decision 51's R13 bullet (`**Directory membership is split by write rate (R13).**`).
- Modify `docs/design/2026-08-21-port49-design.md` §15: one bullet in "The store (plan 7d) exports", and one in "Alert on any of".

- [ ] **Step 1: Decision 57.** Append:

  ```markdown
  **57. Directory pins are re-sealed at a key rotation (issue #52; Ryan 2026-11-07; plan
  `2026-11-08-pin-reseal`).** Amends decision 47 ruling 11 and decision 51 R13.

  1. **The pass.** The scheduled directory pass (`RefreshDirectory`, every `refresh_interval`; on
     port49-broker the runner's alone) re-seals the directory store's pins as it re-seals second
     factors. The store lists every live pin with its version and the key id its sealed part names,
     in pages (`MembershipSeals`); the pass opens only the pins not under `current`, so a pass with
     every pin on `current` reads no pin. The crypt layer marks a membership it opened under
     `encryption.previous` `Stale`, and the pass writes each Stale pin again, sealed under `current`,
     by `PutPin` at the version it read. A pin that a forget, a re-pin or another region's pass
     changed since the read stands (`ErrConflict`); the pass counts it as still under `previous` and
     the next pass reads it again. A directory store that does not answer ends the pass, said once an
     hour; the next pass starts from the listing. A single shared store keeps no pin without a lease
     (its membership record lives max(`broker.directory.grace`, 24h) and every verification rewrites
     it) and runs no pin pass.
  2. **A pin that opens under neither key** is never deleted or rewritten. It is counted, and said
     once an hour per principal, naming `encryption.previous` and `port49 directory forget`, for at
     most 20 principals a pass; the count's line says how many more are not named.
  3. **The count.** `port49_directory_pins_sealed_previous` (pins the last complete pass left under
     `previous`, conflicts included), `port49_directory_pins_unopenable` (pins that opened under
     neither key) and `port49_directory_pins_reseal_last_complete_timestamp_seconds`: gauges with no
     label, set by a pass that completes, unchanged by one that stops, absent until the first and
     where the store holds no pins. A replica that hands over the keyspace keeps its last values, so
     they are read on the holder (`port49_store_keyspace_held` 1). Rotation's step 3 waits, after
     step 2 has finished everywhere, for a pass that completed after the last step-2 restart with
     `port49_directory_pins_sealed_previous` 0. Alert: `port49_directory_pins_unopenable > 0 and
     on(instance) port49_store_keyspace_held == 1` (ticket).
  4. **No offline forget.** A pin is stranded only by a step 3 run against a nonzero gauge, which
     putting the key back as `previous` undoes, or by a lost key, which a forget by any admin whose
     own pin opens cures; the pass keeps every pin that opens on `current`. An offline forget would
     be a path around the touch-gated, recorded broker API.
  ```

- [ ] **Step 2: The amendments.**
  - At the end of decision 47 ruling 11, add: `*Amended by decision 57 (2026-11-08):* the same pass re-seals the directory store's pins.`
  - At the end of decision 51's R13 bullet, add: `*Amended by decision 57 (2026-11-08):* the scheduled pass writes again a pin that opened under `encryption.previous`, by a compare on its version, so a rotation strands none.`

- [ ] **Step 3: Design §15.**
  - After the `port49_crypt_store_key_unknown;` bullet of the store's list, add: `` `port49_directory_pins_sealed_previous`, `port49_directory_pins_unopenable` and `port49_directory_pins_reseal_last_complete_timestamp_seconds`, on port49-broker with a directory store of its own, read on the keyspace holder (spec decision 57); ``
  - After the alert bullet `` `port49_crypt_store_key_unknown` at 1; ``, add: `` `port49_directory_pins_unopenable` above 0 on the replica holding the keyspace: a pin a key rotation retired too early, whose principal cannot bind, mint or refresh (spec decision 57); ``

- [ ] **Step 4: Run `make docs && git status --short`.** The lab-register and reason pages read the spec, and no generated page may change. Then run `go test ./internal/docgen/ ./tests/ci/ -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md && git commit -m "docs: decision 57, directory pins are re-sealed at a key rotation (#52)"`

---

### Task 2: A membership opened under the previous key is `Stale`; a body that does not decode logs no byte

**Files:**
- Modify:
  - `internal/store/store.go` `Membership` (`:1284`): add after `Sealed` (before `Version`):
    ```go
    	// Stale is a record opened under the previous encryption key: the
    	// scheduled pass seals the directory's pin again (decision 57).
    	// Written by internal/store/crypt's reads; a write ignores it, and a
    	// broker snapshot's cached pins carry it as it was read.
    	Stale bool
    ```
  - `internal/store/crypt/crypt.go`:
    - In the `var (...)` block with `errMembershipMoved` (`:1161-1167`), add `errMembershipBody = errors.New("crypt: a membership's sealed part does not decode")`.
    - In `openMembership` (`:1207`), the JSON failure (`:1216-1217`) becomes `return store.Membership{}, w.openErr("membership", m.Sealed, errMembershipBody)`, so no decoded byte reaches a log line.
    - Immediately before the line `m.DN, m.EntryID, m.Username, m.GroupDNs, m.GroupNames, m.Sealed = ...` (`:1225`), add
      ```go
      	// Stale, as a second factor's is: opened under the previous key, so the
      	// scheduled pass seals the pin again before encryption.previous is
      	// retired (decision 57).
      	m.Stale = w.keys.Previous != nil && SealedKeyID(m.Sealed) == LineKeyID(w.keys.Previous.ID)
      ```
- Test: `internal/store/crypt/crypt_test.go`.

- [ ] **Step 1: Write the failing tests.**

  ```go
  // A membership sealed under the previous key opens Stale; written again it
  // is not, and with no previous key nothing is (decision 57).
  func TestAMembershipUnderThePreviousKeyIsStale(t *testing.T) {
  	ctx := context.Background()
  	inner := memory.New(time.Now)
  	k := keys() // Current v2, Previous v1
  	m := store.Membership{Principal: "user:alice@corp.example.com", EntryID: "uuid:1", MapKeys: []string{"k1"},
  		VerifiedAt: time.Now().Add(-time.Minute).UTC()}
  	if err := Wrap(inner, Keys{Current: *k.Previous}, nil).PutPin(ctx, m, store.PinExpect{Absent: true}); err != nil {
  		t.Fatal(err)
  	}
  	w := Wrap(inner, k, nil)
  	got, err := w.GetMembership(ctx, m.Principal)
  	if err != nil || !got.Stale || got.EntryID != "uuid:1" || got.Version == 0 {
  		t.Fatalf("under the previous key: stale %v, entry %q, version %d, %v", got.Stale, got.EntryID, got.Version, err)
  	}
  	if err := w.PutPin(ctx, got, store.PinExpect{Version: got.Version}); err != nil {
  		t.Fatal(err)
  	}
  	if got, err := w.GetMembership(ctx, m.Principal); err != nil || got.Stale {
  		t.Fatalf("written again under the current key: stale %v, %v", got.Stale, err)
  	}
  	if got, err := Wrap(inner, Keys{Current: k.Current}, nil).GetMembership(ctx, m.Principal); err != nil || got.Stale {
  		t.Fatalf("with no previous key: stale %v, %v", got.Stale, err)
  	}
  }

  // A sealed part that opens and does not decode is refused with a sentinel:
  // the decoder's own error would put a plaintext byte in the pin's log line.
  func TestAMembershipBodyThatDoesNotDecodeNamesNoByteOfIt(t *testing.T) {
  	ctx := context.Background()
  	inner := memory.New(time.Now)
  	k := keys()
  	p, at := "user:alice@corp.example.com", time.Now().Add(-time.Minute).UTC()
  	sealed, err := k.SealBound([]byte("x-not-json"), membershipAAD(p))
  	if err != nil {
  		t.Fatal(err)
  	}
  	if err := inner.PutMembership(ctx, store.Membership{Principal: p, VerifiedAt: at, Sealed: sealed}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	_, err = Wrap(inner, k, nil).GetMembership(ctx, p)
  	if !errors.Is(err, errMembershipBody) || strings.Contains(err.Error(), "invalid character") {
  		t.Fatalf("a body that does not decode: %v", err)
  	}
  }
  ```

  `"errors"` and `"strings"` are already in the file's imports.

- [ ] **Step 2: Run them and see them fail.** `TMPDIR=$TMPDIR go test ./internal/store/crypt/ -run '^TestAMembership(UnderThePreviousKeyIsStale|BodyThatDoesNotDecode)' -count=1`. Expected: the build fails (`got.Stale undefined`, `errMembershipBody undefined`). After adding only the field and the variable, the first test fails with `under the previous key: stale false`, and the second with `invalid character 'x'`. Paste the red output.

- [ ] **Step 3: Implement** as in Files.

- [ ] **Step 4: Run** `TMPDIR=$TMPDIR go test -timeout 30m ./internal/store/... -count=1`. Expected: PASS. A test that compares whole `Membership` values read under a two-key window may now see `Stale` and need it named. Fix the test's expectation, never the code.

  **Mutation check:** compare against `w.keys.Current.ID` instead, and see the first test go red. Then restore.

- [ ] **Step 5: Commit.**

  `git add internal/store/store.go internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go && git commit -m "feat(store): a membership opened under the previous encryption key is Stale, and an undecodable one names no byte (#52)"`

---

### Task 3: `MembershipSeals`, every live pin's version and key id in one paged listing

**Files:**
- Modify:
  - `internal/store/store.go`:
    - After `PinExpect`, add
      ```go
      // MembershipSeal is one live, unforgotten membership record as
      // MembershipSeals lists it (decision 57): its principal, its version (what
      // a PinExpect names), and the key id its sealed part names
      // (SealedKeyID). Current is the crypt layer's: the key id is its current
      // key's. A backend leaves it false.
      type MembershipSeal struct {
      	Principal, KeyID string
      	Version          uint64
      	Current          bool
      }

      // SealedKeyID is the key id the header of a record internal/store/crypt
      // sealed names (len(id) ‖ id ‖ ...), "" when it is too short to name one.
      // It is the raw header, which whoever can write the store writes:
      // crypt.SealedKeyID is the form a log line may echo.
      func SealedKeyID(sealed []byte) string {
      	if len(sealed) < 1 || len(sealed) < 1+int(sealed[0]) {
      		return ""
      	}
      	return string(sealed[1 : 1+int(sealed[0])])
      }
      ```
    - In `Store`, after `MembershipPrincipals` (`:1093`), add
      ```go
      	// MembershipSeals is MembershipPrincipals with each record's version and
      	// the key id its sealed part names, read in the same pages: the listing a
      	// re-seal pass reads, so that it opens only the records not under the
      	// current key (decision 57). Sorted by principal.
      	MembershipSeals(ctx context.Context) ([]MembershipSeal, error)
      ```
  - `internal/store/crypt/crypt.go`:
    - `SealedKeyID` (`:345-350`) becomes `return LineKeyID(store.SealedKeyID(sealed))`. Its behavior is unchanged.
    - After `MembershipPrincipals` (`:1253`), add
      ```go
      // MembershipSeals marks each record sealed under the current key: a re-seal
      // opens only the others (decision 57).
      func (w *wrapped) MembershipSeals(ctx context.Context) ([]store.MembershipSeal, error) {
      	ss, err := w.inner.MembershipSeals(ctx)
      	for i := range ss {
      		ss[i].Current = ss[i].KeyID == w.keys.Current.ID
      	}
      	return ss, err
      }
      ```
  - `internal/store/etcd/membership.go`: move the paging loop of `MembershipPrincipals` (`:348-375`) into a helper both use (add `"cmp"` to the imports):
    ```go
    // MembershipPrincipals pages mb/ (eachMembership).
    func (s *Store) MembershipPrincipals(ctx context.Context) ([]string, error) {
    	var out []string
    	if err := s.eachMembership(ctx, func(r membershipRec, _ int64) { out = append(out, r.Principal) }); err != nil {
    		return nil, err
    	}
    	sort.Strings(out)
    	return out, nil
    }

    // MembershipSeals pages mb/ as MembershipPrincipals does, with each record's
    // mod revision and the key id its sealed part names (decision 57).
    func (s *Store) MembershipSeals(ctx context.Context) ([]store.MembershipSeal, error) {
    	var out []store.MembershipSeal
    	if err := s.eachMembership(ctx, func(r membershipRec, mod int64) {
    		out = append(out, store.MembershipSeal{Principal: r.Principal, KeyID: store.SealedKeyID(r.Sealed),
    			Version: uint64(mod)})
    	}); err != nil {
    		return nil, err
    	}
    	slices.SortFunc(out, func(a, b store.MembershipSeal) int { return cmp.Compare(a.Principal, b.Principal) })
    	return out, nil
    }
    ```
    `eachMembership(ctx context.Context, fn func(r membershipRec, mod int64)) error` is today's loop, with these changes:
    - its doc comment is the old one ("pages mb/ as eachIndexed pages ix/: 500 at a time, a record that does not decode skipped and said");
    - `out = append(out, r.Principal)` becomes `fn(r, kv.ModRevision)`;
    - `return nil, unavailable(err)` becomes `return unavailable(err)`;
    - it ends with `return nil`.
  - `internal/store/memory/memory.go` (add `"cmp"` to the imports; `"slices"` is there), after `MembershipPrincipals` (`:1824`):
    ```go
    // MembershipSeals is MembershipPrincipals with each record's version and
    // the key id its sealed part names (decision 57).
    func (s *Store) MembershipSeals(context.Context) ([]store.MembershipSeal, error) {
    	s.mu.Lock()
    	defer s.mu.Unlock()
    	var out []store.MembershipSeal
    	for p := range s.memberships {
    		if e, ok := s.liveMembershipLocked(p); ok && e.forgottenAt.IsZero() {
    			out = append(out, store.MembershipSeal{Principal: p, KeyID: store.SealedKeyID(e.m.Sealed), Version: e.ver})
    		}
    	}
    	slices.SortFunc(out, func(a, b store.MembershipSeal) int { return cmp.Compare(a.Principal, b.Principal) })
    	return out, nil
    }
    ```
  - `internal/store/guard/guard.go`, after `MembershipPrincipals` (`:827`):
    ```go
    func (g *guarded) MembershipSeals(ctx context.Context) (ss []store.MembershipSeal, err error) {
    	err = g.do(ctx, Token, func(ctx context.Context) (e error) { ss, e = g.inner.MembershipSeals(ctx); return })
    	return
    }
    ```
  - `internal/store/placement/methods_test.go`: add `MembershipSeals` to `sessionMethods`, beside `MembershipPrincipals` (`:32`). The router's own `MembershipSeals` is the session store's, and `ResealPins` reads the directory's through `Members` (Task 4).
  - Any other type that implements `store.Store` in full, rather than by embedding, gets the same pass-through. `go build ./... && go vet ./...` names any that were missed.
  - `internal/store/storetest/membership.go` gets the conformance case below, registered in `storetest.go` `Run` after `{"MembershipPrincipalsListsTheLive", ...}` (`:1137`). The memory and etcd suites both run it.
- Test: `internal/store/storetest/membership.go`; `internal/store/crypt/crypt_test.go`.

- [ ] **Step 1: Write the failing tests.**

  In `storetest/membership.go`:

  ```go
  // MembershipSealsListsTheLive: every live, unforgotten record, with the key
  // id its sealed part's header names and the version GetMembership reads
  // (decision 57). An expired record and a forget's tombstone are not listed.
  func MembershipSealsListsTheLive(t *testing.T, b Backend) {
  	ctx := context.Background()
  	var mu sync.Mutex
  	now := t0
  	s := b.New(t, func() time.Time { mu.Lock(); defer mu.Unlock(); return now })
  	sealed := func(id string) []byte { return append([]byte{byte(len(id))}, id+"-not-a-ciphertext"...) }
  	const alice, bob, carol = "user:alice@corp.example.com", "user:bob@corp.example.com", "user:carol@corp.example.com"
  	if err := s.PutPin(ctx, store.Membership{Principal: bob, EntryID: "uuid:b", VerifiedAt: t0, Sealed: sealed("k2")},
  		store.PinExpect{Absent: true}); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.PutMembership(ctx, store.Membership{Principal: alice, EntryID: "uuid:a", VerifiedAt: t0,
  		Sealed: sealed("k1")}, time.Hour); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.PutMembership(ctx, store.Membership{Principal: "user:gone@corp.example.com", VerifiedAt: t0,
  		Sealed: sealed("k1")}, time.Minute); err != nil {
  		t.Fatal(err)
  	}
  	if err := s.PutPin(ctx, store.Membership{Principal: carol, EntryID: "uuid:c", VerifiedAt: t0, Sealed: sealed("k1")},
  		store.PinExpect{Absent: true}); err != nil {
  		t.Fatal(err)
  	}
  	if _, err := s.DeleteMembership(ctx, carol); err != nil {
  		t.Fatal(err)
  	}
  	mu.Lock()
  	now = now.Add(2 * time.Minute)
  	mu.Unlock()
  	got, err := s.MembershipSeals(ctx)
  	if err != nil || len(got) != 2 || got[0].Principal != alice || got[0].KeyID != "k1" ||
  		got[1].Principal != bob || got[1].KeyID != "k2" {
  		t.Fatalf("the listing: %+v, %v", got, err)
  	}
  	for _, e := range got {
  		m, err := s.GetMembership(ctx, e.Principal)
  		if err != nil || e.Version == 0 || e.Version != m.Version || e.Current {
  			t.Fatalf("%s listed at version %d (current %v), read at %d: %v", e.Principal, e.Version, e.Current, m.Version, err)
  		}
  	}
  }
  ```

  In `crypt_test.go`:

  ```go
  // The crypt layer marks the records sealed under its current key; the
  // others are what a re-seal opens (decision 57).
  func TestMembershipSealsMarkTheCurrentKey(t *testing.T) {
  	ctx := context.Background()
  	inner := memory.New(time.Now)
  	k := keys() // Current v2, Previous v1
  	at := time.Now().Add(-time.Minute).UTC()
  	for p, ks := range map[string]Keys{"user:old@corp.example.com": {Current: *k.Previous}, "user:new@corp.example.com": k} {
  		if err := Wrap(inner, ks, nil).PutPin(ctx, store.Membership{Principal: p, EntryID: "uuid:" + p, VerifiedAt: at},
  			store.PinExpect{Absent: true}); err != nil {
  			t.Fatal(err)
  		}
  	}
  	got, err := Wrap(inner, k, nil).MembershipSeals(ctx)
  	if err != nil || len(got) != 2 || !got[0].Current || got[0].KeyID != "v2" || got[1].Current || got[1].KeyID != "v1" {
  		t.Fatalf("the listing (new, then old): %+v, %v", got, err)
  	}
  }
  ```

- [ ] **Step 2: Run them and see them fail.**
  - `TMPDIR=$TMPDIR go test ./internal/store/crypt/ -run '^TestMembershipSealsMarkTheCurrentKey$' -count=1`
  - `TMPDIR=$TMPDIR go test -timeout 30m ./internal/store/memory/ ./internal/store/etcd/ -run 'MembershipSeals' -count=1`

  Expected: the build fails (`MembershipSeals` undefined). Paste the red output.

- [ ] **Step 3: Implement** as in Files.

- [ ] **Step 4: Run** `go build ./... && go vet ./... && TMPDIR=$TMPDIR go test -timeout 30m ./internal/store/... -count=1`. Expected: PASS, including `TestEveryStoreMethodIsPlaced` and every crypt `SealedKeyID` test.

  **Mutation check:** in memory's `MembershipSeals`, drop the `e.forgottenAt.IsZero()` test, and see `MembershipSealsListsTheLive` go red on memory. Then restore.

- [ ] **Step 5: Commit.**

  `git add internal/store/store.go internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go internal/store/etcd/membership.go internal/store/memory/memory.go internal/store/guard/guard.go internal/store/placement/methods_test.go internal/store/storetest/membership.go internal/store/storetest/storetest.go && git commit -m "feat(store): MembershipSeals lists each live pin's version and sealing key in pages (#52)"`

  If Step 4's vet named other full implementers, add their files to the pathspec.

---

### Task 4: `placement.ResealPins`, by compare-and-swap, opening only the non-current pins

**Files:**
- Modify:
  - `internal/store/store.go`: after `MembershipSeal`, add
    ```go
    // PinReseal is one complete pass of the directory pins' re-seal (decision
    // 57): pins sealed again under the current key, pins still under the
    // previous one (a write that met a newer pin, left for the next pass), and
    // pins that opened under neither key, left as they are.
    type PinReseal struct {
    	Sealed, Previous, Unopened int
    }
    ```
  - `internal/store/placement/placement.go` (add `"cmp"` to the imports):
    - `Members` (`:37-43`) gains `MembershipSeals(ctx context.Context) ([]store.MembershipSeal, error)`.
    - Add `ResealPins` after `PutPin` (`:295-300`):
      ```go
      // ResealPins is the scheduled re-seal of the directory's pins (decision
      // 57). The directory lists its pins with the key id each is sealed under;
      // only those not under the current key are read. Each that opened under
      // encryption.previous is written again, sealed under the current key, by a
      // compare on the version it was read at, so a pin a forget, a re-pin or
      // another region changed since the read stands; that one is counted in
      // Previous and the next pass reads it again. A pin that opens under
      // neither key is told to unopened and counted, and never written or
      // deleted. A directory that does not answer, or a ctx that ends, ends the
      // pass with that error: each pin is one compare, so nothing is left
      // half-written. held is false where the router has no directory of its
      // own, which holds no pins.
      func (p *placed) ResealPins(ctx context.Context, unopened func(principal string, err error)) (rep store.PinReseal,
      	held bool, err error) {
      	if p.c.Members == nil {
      		return rep, false, nil
      	}
      	if !p.reachable() {
      		return rep, true, fmt.Errorf("%w: the directory store does not answer", store.ErrUnavailable)
      	}
      	var seals []store.MembershipSeal
      	if err := bounded(ctx, p.c.BulkTimeout, func(ctx context.Context) (x error) {
      		seals, x = p.c.Members.MembershipSeals(ctx)
      		return
      	}); err != nil {
      		return rep, true, err
      	}
      	for _, s := range seals {
      		if s.Current {
      			continue // sealed under the current key: nothing to read
      		}
      		var pin store.Membership
      		err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
      			pin, x = p.c.Members.GetMembership(ctx, s.Principal)
      			return
      		})
      		switch {
      		case errors.Is(err, store.ErrNotFound):
      			continue // forgotten or gone since the listing (ErrForgotten is an ErrNotFound)
      		case errors.Is(err, store.ErrUnavailable), ctx.Err() != nil:
      			return rep, true, cmp.Or(err, ctx.Err())
      		case err != nil:
      			rep.Unopened++
      			if unopened != nil {
      				unopened(s.Principal, err)
      			}
      			continue
      		case !pin.Stale:
      			continue // written under the current key since the listing
      		}
      		switch err := p.putPin(ctx, pin, store.PinExpect{Version: pin.Version}); {
      		case err == nil:
      			rep.Sealed++
      		case errors.Is(err, store.ErrConflict):
      			rep.Previous++
      		default:
      			return rep, true, err
      		}
      	}
      	return rep, true, nil
      }
      ```
  - `internal/port49d/storeref.go`: `lazyMembers` gains `MembershipSeals`, in the shape of `DeleteMembership` (`:190`):
    ```go
    func (l *lazyMembers) MembershipSeals(ctx context.Context) ([]store.MembershipSeal, error) {
    	s, err := l.get()
    	if err != nil {
    		return nil, err
    	}
    	return s.MembershipSeals(ctx)
    }
    ```
- Create `internal/store/placement/reseal_test.go`.

- [ ] **Step 1: Write the failing tests** in `reseal_test.go` (`package placement`; imports `context`, `errors`, `fmt`, `slices`, `strings`, `testing`, `time`, `store`, `store/crypt`, `store/memory`).

  ```go
  const bob = "user:bob@example.com"

  // sealKey is a key named id whose bytes are id repeated: test keys only.
  func sealKey(id string) crypt.Key {
  	var b [32]byte
  	copy(b[:], strings.Repeat(id, 32))
  	return crypt.NewKey(id, b)
  }

  // window is encryption: current, and previous when one is given.
  func window(current string, previous ...string) crypt.Keys {
  	k := crypt.Keys{Current: sealKey(current)}
  	if len(previous) == 1 {
  		p := sealKey(previous[0])
  		k.Previous = &p
  	}
  	return k
  }

  // sealedRegion is a router over dir whose pins are sealed under ks, as
  // port49-broker builds it (brokerd.go, lazyMembers); wrap, when set, stands
  // between it and the sealed directory.
  func sealedRegion(dir *memory.Store, ks crypt.Keys, wrap func(Members) Members) *placed {
  	var members Members = crypt.Wrap(dir, ks, nil)
  	if wrap != nil {
  		members = wrap(members)
  	}
  	return Wrap(Config{Session: memory.New(clock), Directory: dir, Members: members, Marks: store.NewMarks(),
  		CallTimeout: time.Second, BulkTimeout: time.Second}).(*placed)
  }

  // reseal is one pass that must find the router holding pins.
  func reseal(t *testing.T, r *placed, unopened func(string, error)) (store.PinReseal, error) {
  	t.Helper()
  	rep, held, err := r.ResealPins(context.Background(), unopened)
  	if !held {
  		t.Fatal("a router with a directory of its own says it holds no pins")
  	}
  	return rep, err
  }

  func pinFor(principal, entry string) store.Membership {
  	return store.Membership{Principal: principal, EntryID: entry, MapKeys: []string{"key-" + entry}, VerifiedAt: t0}
  }

  func pinned(t *testing.T, r store.Store, ms ...store.Membership) {
  	t.Helper()
  	for _, m := range ms {
  		if err := r.PutMembership(context.Background(), m, time.Hour); err != nil {
  			t.Fatal(m.Principal, err)
  		}
  	}
  }

  // sealedUnder is the key id the directory's raw record for principal names.
  func sealedUnder(t *testing.T, dir *memory.Store, principal string) string {
  	t.Helper()
  	raw, err := dir.GetMembership(context.Background(), principal)
  	if err != nil {
  		t.Fatal(principal, err)
  	}
  	return crypt.SealedKeyID(raw.Sealed)
  }

  // opens fails the test for each principal whose pin does not open under ks.
  func opens(t *testing.T, dir *memory.Store, ks crypt.Keys, principals ...string) {
  	t.Helper()
  	m := crypt.Wrap(dir, ks, nil)
  	for _, p := range principals {
  		if got, err := m.GetMembership(context.Background(), p); err != nil || got.EntryID == "" {
  			t.Errorf("%s's pin does not open under current %s: %v", p, ks.Current.ID, err)
  		}
  	}
  }

  // reads is a directory that counts its pin reads.
  type reads struct {
  	Members
  	n int
  }

  func (r *reads) GetMembership(ctx context.Context, p string) (store.Membership, error) {
  	r.n++
  	return r.Members.GetMembership(ctx, p)
  }

  // The pass writes each pin under the previous key again under the current
  // one, keeping its entry and map keys, and a second pass reads and writes
  // nothing.
  func TestTheReSealPassMovesPinsOffThePreviousKey(t *testing.T) {
  	ctx := context.Background()
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
  	var rd *reads
  	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rd = &reads{Members: m}; return rd })
  	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{Sealed: 2}) {
  		t.Fatalf("the pass: %+v, %v", rep, err)
  	}
  	for _, p := range []string{alice, bob} {
  		if id := sealedUnder(t, dir, p); id != "k2" {
  			t.Errorf("%s's pin is under %q after the pass, want k2", p, id)
  		}
  	}
  	got, err := crypt.Wrap(dir, window("k2"), nil).GetMembership(ctx, alice)
  	if err != nil || got.EntryID != "uuid:a" || !slices.Equal(got.MapKeys, []string{"key-uuid:a"}) {
  		t.Fatalf("the re-sealed pin: entry %q, keys %v, %v", got.EntryID, got.MapKeys, err)
  	}
  	rd.n = 0
  	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{}) || rd.n != 0 {
  		t.Fatalf("a second pass: %+v, %d pin reads, %v (want none: every pin is on current)", rep, rd.n, err)
  	}
  }

  // Pre-flight M2: a pass over pins all sealed under the current key reads
  // the listing alone, never a pin.
  func TestAPassWithEveryPinOnCurrentReadsNoPin(t *testing.T) {
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k2"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
  	var rd *reads
  	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rd = &reads{Members: m}; return rd })
  	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{}) || rd.n != 0 {
  		t.Fatalf("the pass: %+v, %d pin reads, %v", rep, rd.n, err)
  	}
  }

  // A router with no directory of its own holds no pins: no pass, no count.
  func TestARouterWithNoDirectoryHoldsNoPins(t *testing.T) {
  	r := Wrap(Config{Session: memory.New(clock), Directory: memory.New(clock), Marks: store.NewMarks()}).(*placed)
  	if rep, held, err := r.ResealPins(context.Background(), nil); held || err != nil || rep != (store.PinReseal{}) {
  		t.Fatalf("held %v, %+v, %v", held, rep, err)
  	}
  }

  // CAS: a pin another region wrote between the pass's read and its write
  // stands, is counted as still under previous, and the next pass finds it
  // current.
  func TestTheReSealPassNeverOverwritesAPinChangedSinceItsRead(t *testing.T) {
  	ctx := context.Background()
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"))
  	other := sealedRegion(dir, window("k2", "k1"), nil)
  	var rc *racing
  	r := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rc = &racing{Members: m}; return rc })
  	rc.during = func() { // a refusal keeps the entry and changes the pin
  		refused := pinFor(alice, "uuid:a")
  		refused.Refused, refused.VerifiedAt = true, t0.Add(time.Minute)
  		if err := other.PutMembership(ctx, refused, time.Hour); err != nil {
  			t.Fatal(err)
  		}
  	}
  	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{Previous: 1}) {
  		t.Fatalf("the pass: %+v, %v (want the conflict counted under Previous)", rep, err)
  	}
  	got, err := crypt.Wrap(dir, window("k2"), nil).GetMembership(ctx, alice)
  	if err != nil || !got.Refused {
  		t.Fatalf("the other region's refusal was overwritten: %+v, %v", got, err)
  	}
  	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{}) {
  		t.Fatalf("the next pass: %+v, %v", rep, err)
  	}
  }

  // A pin under a key neither held is told, counted apart, and left exactly
  // as it was: never rewritten, never deleted.
  func TestTheReSealPassCountsAnUnopenablePinAndLeavesIt(t *testing.T) {
  	ctx := context.Background()
  	dir := memory.New(clock)
  	if err := crypt.Wrap(dir, window("k0"), nil).PutPin(ctx, pinFor(alice, "uuid:a"), store.PinExpect{Absent: true}); err != nil {
  		t.Fatal(err)
  	}
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(bob, "uuid:b"))
  	var told []string
  	rep, err := reseal(t, sealedRegion(dir, window("k2", "k1"), nil), func(p string, err error) {
  		if !errors.Is(err, crypt.ErrUnknownKey) {
  			t.Errorf("told %s with %v, want ErrUnknownKey", p, err)
  		}
  		told = append(told, p)
  	})
  	if err != nil || rep != (store.PinReseal{Sealed: 1, Unopened: 1}) || !slices.Equal(told, []string{alice}) {
  		t.Fatalf("the pass: %+v, told %v, %v", rep, told, err)
  	}
  	if id := sealedUnder(t, dir, alice); id != "k0" {
  		t.Fatalf("the unopenable pin was rewritten (now under %q)", id)
  	}
  }

  // stopping is a directory whose pin reads stop answering after the first n.
  type stopping struct {
  	Members
  	n int
  }

  func (s *stopping) GetMembership(ctx context.Context, p string) (store.Membership, error) {
  	if s.n == 0 {
  		return store.Membership{}, fmt.Errorf("%w: cut", store.ErrUnavailable)
  	}
  	s.n--
  	return s.Members.GetMembership(ctx, p)
  }

  // A directory that stops answering mid-pass ends it with ErrUnavailable;
  // the pins not reached are as they were and still open, and the next pass
  // finishes. A directory known cut is not called at all. A ctx that ends
  // mid-pass is the pass's error, never a nil one.
  func TestADirectoryCutMidPassEndsItAndLeavesNothingHalfWritten(t *testing.T) {
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
  	cut := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { return &stopping{Members: m, n: 1} })
  	rep, err := reseal(t, cut, nil)
  	if !errors.Is(err, store.ErrUnavailable) || rep != (store.PinReseal{Sealed: 1}) {
  		t.Fatalf("the cut pass: %+v, %v", rep, err)
  	}
  	if id := sealedUnder(t, dir, bob); id != "k1" {
  		t.Fatalf("bob's pin, after the pass stopped before it, is under %q", id)
  	}
  	opens(t, dir, window("k2", "k1"), alice, bob)
  	r := sealedRegion(dir, window("k2", "k1"), nil)
  	r.c.Reachable = func() bool { return false }
  	if _, err := reseal(t, r, nil); !errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("a pass with the directory known cut: %v", err)
  	}
  	r.c.Reachable = nil
  	ctx, cancel := context.WithCancel(context.Background())
  	var rc *racing
  	ended := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { rc = &racing{Members: m}; return rc })
  	rc.during = cancel
  	if _, _, err := ended.ResealPins(ctx, nil); !errors.Is(err, context.Canceled) {
  		t.Fatalf("a pass whose ctx ended after a read that answered: %v, want context.Canceled", err)
  	}
  	if rep, err := reseal(t, r, nil); err != nil || rep != (store.PinReseal{Sealed: 1}) {
  		t.Fatalf("the next pass: %+v, %v", rep, err)
  	}
  }

  // Issue #52 end to end: rotate, pass, rotate again, pass; every pin opens
  // under the last key alone.
  func TestTwoRotationsWithAPassBetweenStrandNoPin(t *testing.T) {
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
  	// First rotation, step 2 (k2, k1 previous), then the pass; step 3 drops k1.
  	if rep, err := reseal(t, sealedRegion(dir, window("k2", "k1"), nil), nil); err != nil || rep.Sealed != 2 {
  		t.Fatalf("the first rotation's pass: %+v, %v", rep, err)
  	}
  	opens(t, dir, window("k2"), alice, bob)
  	// Second rotation, step 1 (k2, k3 previous): k1 is gone and nothing strands.
  	opens(t, dir, window("k2", "k3"), alice, bob)
  	// Step 2 (k3, k2 previous), the pass, then step 3 (k3 alone).
  	if rep, err := reseal(t, sealedRegion(dir, window("k3", "k2"), nil), nil); err != nil || rep.Sealed != 2 {
  		t.Fatalf("the second rotation's pass: %+v, %v", rep, err)
  	}
  	opens(t, dir, window("k3"), alice, bob)
  }

  // The control: with no pass, the second rotation's step 1 strands every pin
  // (the bug #52 reports).
  func TestWithoutThePassTheSecondRotationStrandsPins(t *testing.T) {
  	ctx := context.Background()
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"))
  	if _, err := crypt.Wrap(dir, window("k2", "k3"), nil).GetMembership(ctx, alice); !errors.Is(err, crypt.ErrUnknownKey) {
  		t.Fatalf("a pin under k1 read under (k2, k3): %v, want ErrUnknownKey", err)
  	}
  }
  ```

- [ ] **Step 2: Run them and see them fail.** `TMPDIR=$TMPDIR go test ./internal/store/placement/ -run '^Test(TheReSealPass|APassWithEveryPin|ARouterWithNoDirectory|ADirectoryCutMidPass|TwoRotations|WithoutThePass)' -count=1`. Expected: the build fails (`ResealPins` undefined; `store.PinReseal` undefined if the type is not yet added). With a stub that returns `store.PinReseal{}, p.c.Members != nil, nil`, every test fails except the control, the no-directory test and the every-pin-on-current test. Paste the red output.

- [ ] **Step 3: Implement** as in Files. Then `go build ./...`: every `Members` test double embeds `Members` or `store.Store`, so it compiles unchanged.

- [ ] **Step 4: Run** `TMPDIR=$TMPDIR go test -timeout 30m ./internal/store/... ./internal/port49d/ -count=1`. Expected: PASS.

  **Mutation checks:** see each one go red, then restore it.
  - Read the pin again just before the write and use that version (`fresh, _ := p.c.Members.GetMembership(ctx, s.Principal)`, then `store.PinExpect{Version: fresh.Version}`): the CAS test fails, because the other region's refusal is overwritten.
  - Delete the `if s.Current { continue }` line: the every-pin-on-current test and the second-pass read count fail.
  - No mutation is listed for `case !pin.Stale`. Since the listing, it guards only a pin rewritten under `current` between the listing and the read, and the listing's `Current` skip shields it in every test above. Keep it for that race.
  - Make the unopenable case `return rep, true, err`: the unopenable test fails.
  - Drop `cmp.Or` (return `err`): the canceled-ctx assertion fails.

- [ ] **Step 5: Commit.**

  `git add internal/store/store.go internal/store/placement/placement.go internal/store/placement/reseal_test.go internal/port49d/storeref.go && git commit -m "feat(placement): the directory's pins are re-sealed under the current key by compare-and-swap (#52)"`

---

### Task 5: The scheduled pass runs it and gauges what is left

**Files:**
- Modify:
  - `internal/daemon/metrics/metrics.go`.
    - In the struct, after `DirectoryRefreshLastComplete` (`:414`):
      ```go
      	// The directory pins' re-seal (spec decision 57), each a vector with no
      	// labels, absent until a pass on a directory store of its own
      	// completes: port49_directory_pins_sealed_previous, the pins that pass
      	// left under encryption.previous (a write that met a newer pin
      	// included); port49_directory_pins_unopenable, those that opened under
      	// neither key; port49_directory_pins_reseal_last_complete_timestamp_seconds,
      	// when it ended. A replica that hands over the keyspace keeps its last
      	// values: read them on the holder. No principal.
      	DirectoryPinsSealedPrevious, DirectoryPinsUnopenable, DirectoryPinsResealLastComplete *prometheus.GaugeVec
      ```
    - In `New`, after `DirectoryRefreshLastComplete:`:
      ```go
      		DirectoryPinsSealedPrevious: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_pins_sealed_previous",
      			Help: "Directory pins the last complete re-seal pass left sealed under encryption.previous; remove " +
      				"encryption.previous only at 0, read on the keyspace holder from a pass that ended after the last " +
      				"restart of the rotation's step 2. Absent until a pass completes, and where the store holds no pins."}, nil),
      		DirectoryPinsUnopenable: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_pins_unopenable",
      			Help: "Directory pins the last complete re-seal pass could not open under either encryption key; " +
      				"their principals cannot bind, mint or refresh. Alert above 0 where port49_store_keyspace_held is 1."}, nil),
      		DirectoryPinsResealLastComplete: prometheus.NewGaugeVec(prometheus.GaugeOpts{
      			Name: "port49_directory_pins_reseal_last_complete_timestamp_seconds",
      			Help: "The Unix time the last complete re-seal pass of the directory pins ended; absent before one."}, nil),
      ```
    - Append the three to the `reg.MustRegister(...)` list after `m.DirectoryRefreshLastComplete`.
  - `internal/broker/scheduled.go`.
    - In `RefreshDirectory`, after the `if b.PasswordSignIn != nil { b.enrollmentPass(ctx) }` block (`:120-122`), add `b.pinPass(ctx)`.
    - Add after `enrollmentPass`:
      ```go
      // pinResealer is the store whose directory pins the scheduled pass seals
      // again: placement's, on a directory store of its own (decision 57).
      type pinResealer interface {
      	ResealPins(ctx context.Context, unopened func(principal string, err error)) (store.PinReseal, bool, error)
      }

      // pinLinesNamed is how many unopenable pins one pass names: a lost key
      // strands every pin, and the count's line says the rest.
      const pinLinesNamed = 20

      // pinPass is the directory pins' share of the scheduled pass (decision
      // 57): the re-seal, its gauges set from a pass that completed on a store
      // that holds pins and left as they were by one that stopped, each line said
      // at most once an hour. A shared store keeps no pin without a lease and
      // has none of it.
      func (b *Broker) pinPass(ctx context.Context) {
      	r, ok := b.Store.(pinResealer)
      	if !ok {
      		return
      	}
      	named := 0
      	rep, held, err := r.ResealPins(ctx, func(principal string, err error) {
      		if named++; named > pinLinesNamed {
      			return
      		}
      		b.sayOnce("pin_reseal "+principal, time.Hour, "directory store: %s's pin does not open (%s): it is left as "+
      			"it is; put the key that sealed it back as encryption.previous and restart, or run `port49 directory "+
      			"forget %s`", printsafe.Line(principal, 300), printsafe.Line(err.Error(), 300), printsafe.Line(principal, 300))
      	})
      	switch {
      	case !held, ctx.Err() != nil:
      		return
      	case err != nil:
      		b.sayOnce("pin_reseal_pass", time.Hour, "directory store: the re-seal of pins stopped: %s; the next pass "+
      			"starts again", printsafe.Line(err.Error(), 300))
      		return
      	}
      	b.Metrics.DirectoryPinsSealedPrevious.WithLabelValues().Set(float64(rep.Previous))
      	b.Metrics.DirectoryPinsUnopenable.WithLabelValues().Set(float64(rep.Unopened))
      	b.Metrics.DirectoryPinsResealLastComplete.WithLabelValues().Set(float64(b.Now().Unix()))
      	if rep.Sealed > 0 {
      		b.logf("directory store: the re-seal sealed %d pins under the current key; %d are left under "+
      			"encryption.previous", rep.Sealed, rep.Previous)
      	}
      	if rep.Unopened > 0 {
      		more := ""
      		if n := rep.Unopened - pinLinesNamed; n > 0 {
      			more = fmt.Sprintf("; %d more are not named", n)
      		}
      		b.sayOnce("pin_reseal_unopened", time.Hour, "directory store: %d pins open under neither encryption key; "+
      			"their principals cannot bind, mint or refresh until the key is back as encryption.previous or each "+
      			"is forgotten%s", rep.Unopened, more)
      	}
      }
      ```
- Regenerate `docs/site/reference/metrics.md` with `make docs`.
- Test: `internal/broker/signin_admin_test.go`, beside `TestTheScheduledPassChecksAndReSealsTheEnrollmentStore`.

- [ ] **Step 1: Write the failing tests.**

  ```go
  // resealing is a store as the scheduled pass sees it: ResealPins tells
  // each of unopened and answers rep, held, err.
  type resealing struct {
  	store.Store
  	rep      store.PinReseal
  	held     bool
  	err      error
  	unopened []string
  }

  func (r *resealing) ResealPins(_ context.Context, unopened func(string, error)) (store.PinReseal, bool, error) {
  	for _, p := range r.unopened {
  		unopened(p, errors.New("crypt: opening membership: crypt: sealed under an unknown key"))
  	}
  	return r.rep, r.held, r.err
  }

  // series fails the test unless each gauge has want series (0: absent).
  func series(t *testing.T, want int, gs ...*prometheus.GaugeVec) {
  	t.Helper()
  	for _, g := range gs {
  		if n := testutil.CollectAndCount(g); n != want {
  			t.Fatalf("a pin gauge has %d series, want %d", n, want)
  		}
  	}
  }

  // The scheduled pass re-seals the directory's pins (decision 57): a pass
  // that completes sets the three gauges and says what it did; one the store
  // stops changes none; a store with no pins has none of them.
  func TestTheScheduledPassReSealsPinsAndGaugesWhatIsLeft(t *testing.T) {
  	ctx := context.Background()
  	f, _ := newSignInFixture(t)
  	m := f.b.Metrics
  	gauges := []*prometheus.GaugeVec{m.DirectoryPinsSealedPrevious, m.DirectoryPinsUnopenable,
  		m.DirectoryPinsResealLastComplete}
  	if _, err := f.b.RefreshDirectory(ctx); err != nil {
  		t.Fatal(err)
  	}
  	series(t, 0, gauges...) // a shared store: no ResealPins
  	r := &resealing{Store: f.b.Store, held: false}
  	f.b.Store = r
  	if _, err := f.b.RefreshDirectory(ctx); err != nil {
  		t.Fatal(err)
  	}
  	series(t, 0, gauges...) // a router with no directory of its own
  	r.held, r.rep, r.unopened = true, store.PinReseal{Sealed: 3, Previous: 1, Unopened: 1},
  		[]string{"user:carol@example.com"}
  	if _, err := f.b.RefreshDirectory(ctx); err != nil {
  		t.Fatal(err)
  	}
  	ended := f.b.Now().Unix()
  	series(t, 1, gauges...)
  	if p, u, at := testutil.ToFloat64(m.DirectoryPinsSealedPrevious), testutil.ToFloat64(m.DirectoryPinsUnopenable),
  		testutil.ToFloat64(m.DirectoryPinsResealLastComplete); p != 1 || u != 1 || at != float64(ended) {
  		t.Fatalf("after a complete pass: sealed_previous %v, unopenable %v, last_complete %v", p, u, at)
  	}
  	f.now = f.now.Add(time.Hour)
  	r.rep, r.err, r.unopened = store.PinReseal{Sealed: 1}, fmt.Errorf("%w: cut", store.ErrUnavailable), nil
  	if _, err := f.b.RefreshDirectory(ctx); err != nil {
  		t.Fatal(err)
  	}
  	if p, at := testutil.ToFloat64(m.DirectoryPinsSealedPrevious),
  		testutil.ToFloat64(m.DirectoryPinsResealLastComplete); p != 1 || at != float64(ended) {
  		t.Fatalf("a stopped pass moved the gauges: sealed_previous %v, last_complete %v", p, at)
  	}
  	logs := f.logs()
  	for _, want := range []string{
  		"directory store: the re-seal sealed 3 pins under the current key; 1 are left under encryption.previous",
  		"directory store: user:carol@example.com's pin does not open",
  		"`port49 directory forget user:carol@example.com`",
  		"directory store: 1 pins open under neither encryption key",
  		"directory store: the re-seal of pins stopped",
  	} {
  		if !strings.Contains(logs, want) {
  			t.Errorf("the log lacks %q:\n%s", want, logs)
  		}
  	}
  	if strings.Contains(logs, "more are not named") {
  		t.Errorf("one unopenable pin was said as more than the named ones:\n%s", logs)
  	}
  }

  // Pre-flight S4: a lost key strands every pin, so a pass names at most 20
  // and counts the rest.
  func TestThePinPassNamesAtMostTwentyUnopenablePins(t *testing.T) {
  	f, _ := newSignInFixture(t)
  	var ps []string
  	for i := range 21 {
  		ps = append(ps, fmt.Sprintf("user:p%02d@example.com", i))
  	}
  	f.b.Store = &resealing{Store: f.b.Store, held: true, rep: store.PinReseal{Unopened: 21}, unopened: ps}
  	if _, err := f.b.RefreshDirectory(context.Background()); err != nil {
  		t.Fatal(err)
  	}
  	logs := f.logs()
  	if !strings.Contains(logs, "user:p19@example.com's pin does not open") ||
  		strings.Contains(logs, "user:p20@example.com's pin") ||
  		!strings.Contains(logs, "21 pins open under neither encryption key") ||
  		!strings.Contains(logs, "; 1 more are not named") {
  		t.Fatalf("the lines for 21 unopenable pins:\n%s", logs)
  	}
  }
  ```

  Add `"github.com/prometheus/client_golang/prometheus"` to the file's imports.

- [ ] **Step 2: Run them and see them fail.** `TMPDIR=$TMPDIR go test ./internal/broker/ -run '^Test(TheScheduledPassReSealsPins|ThePinPassNamesAtMostTwenty)' -count=1`. Expected: the build fails (`m.DirectoryPinsSealedPrevious` undefined). With the metrics in place and no `pinPass`, the first test fails at `a pin gauge has 0 series, want 1`, and the second at `the lines for 21 unopenable pins`. Paste the red output.

- [ ] **Step 3: Implement** as in Files, then run `make docs`. `docs/site/reference/metrics.md` gains the three series.

- [ ] **Step 4: Run** `TMPDIR=$TMPDIR go test ./internal/broker/ ./internal/daemon/... ./internal/docgen/ ./tests/ci/ -count=1`. Expected: PASS, including `TestMetricsPageIsCurrent`, `TestNoMetricHasADeviceLabel` and `TestEveryMetricNameIsSnakeCase`.

  **Mutation checks:** see each one go red, then restore it.
  - Set the gauges before the `err != nil` case: the test fails at "a stopped pass moved the gauges".
  - Drop the `named > pinLinesNamed` return: the second test fails.
  - Drop `!held` from the switch: the first test fails at the second `series(t, 0, ...)`.

- [ ] **Step 5: Commit.**

  `git add internal/daemon/metrics/metrics.go internal/broker/scheduled.go internal/broker/signin_admin_test.go docs/site/reference/metrics.md && git commit -m "feat(broker): the scheduled pass re-seals directory pins and gauges what is left (#52)"`

---

### Task 6: The alert `port49_directory_pins_unopenable`

**Files:**
- Modify:
  - `deploy/alerts/port49.rules.yaml`: in group `port49_store`, after `port49_crypt_token_open_failures`:
    ```yaml
          - alert: port49_directory_pins_unopenable
            expr: "port49_directory_pins_unopenable > 0 and on(instance) port49_store_keyspace_held == 1"
            labels: {severity: ticket}
            annotations:
              summary: "A directory pin opens under neither encryption key: its principal cannot bind, mint or refresh."
              runbook_url: "https://blanketfish.github.io/port49/reference/alerts/#port49_directory_pins_unopenable"
    ```
  - `deploy/helm/port49/files/port49.rules.yaml`: the same bytes as `deploy/alerts/port49.rules.yaml` (`TestTheChartCarriesTheSameRules`). Read the one and Write the other; no `cp`, no sed.
  - `deploy/alerts/port49.rules.test.yaml`: after the `port49_crypt_token_open_failures` cases, three cases (`interval: 1m`, eval at 5m):
    - **Fires:** `port49_directory_pins_unopenable{instance="a"}` `"1+0x30"` and `port49_store_keyspace_held{instance="a"}` `"1+0x30"`. `exp_labels: {instance: "a", severity: "ticket"}`, with both annotations as in the rule.
    - **Quiet, nothing stranded:** unopenable `"0+0x30"`, keyspace_held `"1+0x30"`. `exp_alerts: []`.
    - **Quiet, a replica that handed over:** unopenable `"1+0x30"`, keyspace_held `"0+0x30"`. `exp_alerts: []`.
  - `deploy/alerts/README.md`: after the `port49_crypt_token_open_failures` row:
    `` | design §15: "`port49_directory_pins_unopenable` above 0 on the replica holding the keyspace" | `port49_directory_pins_unopenable` | ticket | none | One principal is locked out until the key that sealed the pin is back as `encryption.previous` or the pin is forgotten; the pass never deletes it. Gated on `port49_store_keyspace_held == 1`, since a replica that handed over keeps its last value. | ``
  - `docs/site/operate/troubleshooting/index.md` "### Stores": add `[port49_directory_pins_unopenable](../../reference/alerts.md#port49_directory_pins_unopenable),` after the `port49_crypt_token_open_failures` link in the **ticket** list.
- Regenerate `docs/site/reference/alerts.md` (and the metrics page's alert link) with `make docs`.

- [ ] **Step 1: Write the failing test.** Add the three rule-test cases first. Run `make alerts-check`. Expected: FAIL, because no rule `port49_directory_pins_unopenable` exists. Also run `TMPDIR=$TMPDIR go test ./tests/ci/ -run '^TestEveryAlertIsInTheIndex$' -count=1`, which still passes. Paste the red output.
- [ ] **Step 2: Implement** the rule in both files, the README row and the index link, then run `make docs`.
- [ ] **Step 3: Run** `make alerts-check && TMPDIR=$TMPDIR go test ./tests/alerts/ ./internal/docgen/ ./tests/ci/ -count=1`. Expected: PASS. That covers `TestTheChartCarriesTheSameRules`, `TestEveryReadmeRowHasARuleAndEveryRuleARow`, `TestEveryAlertHasAPromtoolCase`, `TestEveryAlertIsInTheIndex`, `TestAlertsPageIsCurrent` and `TestMetricsPageIsCurrent`.

  **Mutation check:** drop `and on(instance) port49_store_keyspace_held == 1` from the expr in both files: the handed-over quiet case fails `make alerts-check`. Then restore.
- [ ] **Step 4: Commit.**

  `git add deploy/alerts/port49.rules.yaml deploy/helm/port49/files/port49.rules.yaml deploy/alerts/port49.rules.test.yaml deploy/alerts/README.md docs/site/operate/troubleshooting/index.md docs/site/reference/alerts.md docs/site/reference/metrics.md && git commit -m "feat(alerts): port49_directory_pins_unopenable, a pin a rotation retired too early (#52)"`

---

### Task 7: The key-rotation page, stores page and roadmap

**Files:**
- Modify:
  - `tests/ci/docs_content_16_test.go` (first, the red test);
  - `docs/site/admin/key-rotation.md`;
  - `docs/site/operate/stores.md` (the three steps at `:95-97`);
  - `docs/superpowers/plans/README.md`.

- [ ] **Step 1: Write the failing test.** In `mustSay["admin/key-rotation.md"]`, remove the strings that name the retired procedure:
  - `"Directory pins are never re-sealed"`
  - `"A store that holds pins can rotate again only after re-sealing them"`
  - `"Before step 1, re-seal"`
  - `"in place of K3"`
  - `"After step 2, no key choice opens every pin"`
  - `"The admin has to be able to open their own pin"`

  Then add:
  - `"port49_directory_pins_sealed_previous"`
  - `"port49_directory_pins_unopenable"`
  - `"port49_directory_pins_reseal_last_complete_timestamp_seconds"`
  - `"the re-seal of pins stopped"`
  - `"port49_store_keyspace_held"`
  - `"Rotating again"`

  Keep `"ErrUnknownKey"`, `record=\"membership\"`, `"port49 directory forget"`, `"forget_principals"` and `"no offline forget"`. The package has no `mustNotSay`, so the removal is enough.

  Run `TMPDIR=$TMPDIR go test ./tests/ci/ -run '^TestEveryPageSaysWhatItMust$' -count=1`. Expected: FAIL on the new strings. Paste it.

- [ ] **Step 2: Rewrite the page.**
  - Line 111: `port49 seals tokens, receipts, contexts and second-factor records at rest` becomes `port49 seals tokens, receipts, contexts, directory memberships and pins, and second-factor records at rest`.
  - Replace lines 154-213 (the two bullets from `- **Directory pins are never re-sealed.` through `...until its 24-hour lease ends.`) with this text. Keep lines 136-153 and the backups bullet (214-223) as they are.

  ```markdown
  - **Directory pins** (on a directory store of its own: a split, or more than one region) are re-sealed
    by the same scheduled pass. A pin has no expiry, so it never ages out. Instead, the runner lists every
    pin with the key it is sealed under, in pages of 500, and opens only the pins not under `current`. It
    writes each one still sealed under `previous` again under `current`, by a compare on the revision it
    read. A pin that a `port49 directory forget`, a re-pin or another region's runner changed in between
    is left as that writer wrote it, and the next pass reads it again. **After step 2 has finished
    everywhere, wait for a pass that ended after the last step-2 restart**
    (`port49_directory_pins_reseal_last_complete_timestamp_seconds` later than that restart) **with
    `port49_directory_pins_sealed_previous` at 0.** Read both on the replica that holds the keyspace
    (`port49_store_keyspace_held` 1). A replica that handed the keyspace over keeps the values of its
    last pass until it restarts. Any region's holder will do, because they all read the one directory
    store. The gauges are absent until a runner completes its first pass after it starts. They are also
    absent on a single shared store, where a membership record has a lease (the 24 hours above) and there
    is no pin to re-seal. A pass that moves pins says `directory store: the re-seal sealed N pins under
    the current key; M are left under encryption.previous`. If the directory store stops answering, the
    pass says `directory store: the re-seal of pins stopped: <error>; the next pass starts again` and
    changes no gauge. Each pin is one compare-and-swap, so nothing is left half-written.
  - **A pin that opens under neither key** is counted in `port49_directory_pins_unopenable` (alert
    [port49_directory_pins_unopenable](../reference/alerts.md#port49_directory_pins_unopenable), on the
    keyspace holder). It means a key was retired while it still sealed pins. Reading the pin fails with an
    unknown-key error (`ErrUnknownKey`). Each pass opens it again, so
    `port49_crypt_open_failures_total{record="membership"}` rises once per pass for each such pin. Bind,
    mint and refresh fail for that principal. From the code (not measured), sessions already open are
    denied `context_stale` once `session.staleness_ceiling` has passed. The pass never deletes or
    rewrites such a pin. It says `directory store: <principal>'s pin does not open (...)` once an hour,
    for at most 20 principals a pass; the count's line says how many more are not named. Put the retired
    key back as `previous` and restart: nothing was deleted, and the next pass re-seals the pin. If that
    key is gone, `port49 directory forget <principal>` frees the principal, and the person's next sign-in
    pins them again. Any admin with `forget_principals` whose own pin opens can run it, and every pin that
    opens is on `current` after a pass. Confirm that the person who signs in is the same person, as on
    [Stores](../operate/stores.md). There is no offline forget on `port49-broker`.
  - **Rotating again.** There is one `previous` slot, so a rotation's step 1 drops whatever key
    `previous` held. Begin a rotation only after the last one's step 3. The waits above gate that step,
    so every pin and second factor is then under `current`, and the new rotation strands nothing.
  ```

- [ ] **Step 3: The stores page.** Step 3 at `docs/site/operate/stores.md:97` becomes: ``3. Remove the old key from `encryption.previous`, everywhere, once [Key rotation](../admin/key-rotation.md#the-encryption-key)'s waits are over; on a split that includes `port49_directory_pins_sealed_previous` at 0 on the keyspace holder, from a pass after step 2.``

- [ ] **Step 4: Roadmap.** In `docs/superpowers/plans/README.md`, after "Plan 13 — As built" and before the closing `---`, add a section `## Fix #52 — pin re-seal on encryption rotation`. It holds:
  - the plan's path;
  - one line each for decision 57, the listing, the pass, the three gauges and the alert;
  - **Left** (as below).

  Then run `make docs` and `TMPDIR=$TMPDIR go test ./tests/ci/ ./internal/docgen/ -count=1`. Expected: PASS, and `git status --short` shows only the four files above.

- [ ] **Step 5: Commit.**

  `git add tests/ci/docs_content_16_test.go docs/site/admin/key-rotation.md docs/site/operate/stores.md docs/superpowers/plans/README.md && git commit -m "docs: key rotation waits for the pin re-seal, and the forget-every-pin procedure is gone (#52)"`

- [ ] **Step 6: Final verification.** Run `make test && make vet && make docs && make alerts-check && git status --short`. Report the real output; the status must be empty.

## Operator-facing notes (for the PR body)

- The scheduled directory pass on port49-broker now re-seals directory pins after an `encryption:` rotation, as it does second factors. A second rotation no longer strands pins.
- Outside a rotation, the pass costs one paged listing of the directory's pins, 500 a page, and opens none.
- New gauges: `port49_directory_pins_sealed_previous`, `port49_directory_pins_unopenable` and `port49_directory_pins_reseal_last_complete_timestamp_seconds`. They exist only on a split, after the first complete pass. Read them on the keyspace holder.
- New ticket alert: `port49_directory_pins_unopenable`, on the keyspace holder.
- New broker lines:
  - `directory store: the re-seal sealed N pins ...`
  - `directory store: the re-seal of pins stopped: ...`
  - `directory store: <principal>'s pin does not open ...` (at most 20 a pass)
  - `directory store: N pins open under neither encryption key ...[; M more are not named]`
- Rotation's step 3 now waits for `port49_directory_pins_sealed_previous` to read 0. The forget-every-principal procedure before a second rotation is gone.

## Left

1. **An offline `port49-broker forget`** (Ruling 1). After this plan, a pin strands only when step 3 runs against a nonzero gauge, which putting the key back undoes, or when a key is lost, which a forget by any admin whose pin opens cures. Revisit only if a lab or field case shows every admin stranded with the key lost.
2. **The count in `port49 store status` or the admin API.** The gauges and the broker lines answer at 3am. A status field would need a broker API change, and the runner is the only process that knows the count.
3. **A gauge for second factors still under `previous`.** The second-factor pass says only `could not open N`. Its step-3 condition stays "wait for a pass", as written today. A matching gauge is a small follow-up in the same shape.
4. **An alert on a pin re-seal that never completes.** `port49_directory_refresh_last_complete_timestamp_seconds` already alerts on a pass that never completes, and the pin pass is that pass's tail.
5. **Clearing a former holder's gauges when it hands over the keyspace.** The alert gate and the page's "read the holder" cover it. Deleting the series when the duties end would be a runner change with no operator gain.
