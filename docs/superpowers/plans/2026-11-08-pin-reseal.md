# Pin Re-seal on Encryption Rotation (#52) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A key rotation no longer strands directory pins. The scheduled directory pass re-seals each pin that opened under `encryption.previous`, by compare-and-swap. Three gauges say what is left, rotation's step 3 waits for zero, and the key-rotation page loses its forget-every-principal procedure (issue #52, as agreed with Ryan on 2026-11-07).

**Architecture:**
- `store.Membership` gets `Stale`, set by `crypt` as `SecondFactor.Stale` is.
- `placement` gets `ResealPins`, which lists the directory store's pins and rewrites the Stale ones through the existing `PutPin` compare.
- `broker.RefreshDirectory` calls it after the second-factor re-seal and sets three label-free gauges.
- One new alert, and the docs.
- No reason code. No §12 warning. No config key. No lab run.

**Tech Stack:** Go 1.26. `internal/store`, `internal/store/crypt`, `internal/store/placement`, `internal/broker`, `internal/daemon/metrics`, `internal/port49d`, Prometheus rules (`make alerts-check`), `make docs`.

**Spec and history:**
- Issue #52.
- Spec §13 decision 47 ruling 11 (the second-factor re-seal), decision 51 R13 (the unleased pin), and design §15 (the store's metrics and alarms).
- `docs/site/admin/key-rotation.md` lines 154-213, the workaround this plan retires.

## Root causes (investigation 2026-11-08, `main` `19ca91f5`)

1. **A pin is written once and never again while it holds.**
   - `placement.PutMembership` writes the directory only when the pin differs: `case st == pinHeld && samePin(pin, m): return p.Store.PutMembership(...)` (`internal/store/placement/placement.go:323`; `samePin` at `:214-217`).
   - The directory pin has no lease (`PutPin` writes `store.NoExpiry`, `internal/store/etcd/membership.go:62-64`).
   - So a pin keeps the key that was `current` at its first bind, forever.
2. **One `previous` slot.** `crypt.Keys{Current, Previous *Key}` (`internal/store/crypt/crypt.go:116-119`). A second rotation's step 1 drops K1, and `openMembership` (`crypt.go:1207`) then fails with `ErrUnknownKey` for every pin still under K1.
3. **The second-factor pass already has the shape to copy.**
   - `Broker.ResealSecondFactors` (`internal/broker/signin_admin.go:54-120`) does three things. It lists, reads, and swaps a `Stale` record at its `Rev`. It treats `ErrConflict` as "the next pass looks again". It counts an unopenable record and says it once an hour per principal, and never deletes it.
   - It runs from `enrollmentPass` (`internal/broker/scheduled.go:120-144`), the tail of `RefreshDirectory`.
   - On port49-broker, `RefreshDirectory` runs only in the runner's duties (`internal/port49d/runner.go:323` `scheduledDuty`, under the keyspace hold, plan 7e Ruling 6). On port49d it runs in the one process that mints (`internal/port49d/main.go:1591`). Neither ever runs it twice in one keyspace.
4. **Where pins live, per backend.**
   - Directory pins exist only on port49-broker with a directory store of its own (`!cfg.Stores.Shared`). There, `placement.Config.Members` is a `lazyMembers` over the directory etcd, sealed by `crypt.Wrap` (`internal/port49d/brokerd.go:386-395`, `internal/port49d/storeref.go:134-197`).
   - The backends are memory and etcd. `enrollfile` holds second factors, not memberships.
   - Both backends implement `PutPin`'s compare: etcd `casPin` on `ModRevision` (`internal/store/etcd/membership.go:97-140`), memory `stands` on `ver` (`internal/store/memory/memory.go:1666-1676`). `storetest` already runs it on both (`internal/store/storetest/membership.go:609-643`).
   - `GetMembership` returns `Version` (etcd `:229-243`, memory `:1794`), and `MembershipPrincipals` lists live, unforgotten records (etcd `:348`, memory `:1824`).
   - `placement.Members` has no listing method. `lazyMembers` needs one.
   - On a shared store, `placement` is not in the path. Membership is a leased record (`Resolver.TTL()` = max(grace, 24h), `internal/directory/resolver.go:86`) that every verification rewrites. That is the 24-hour wait already on the page (line 147-150).
5. **The stranded admin.** `adminRight` resolves the caller's own membership before the right (`internal/broker/admin_api.go:98-110`, `memberFor`). An admin whose own pin does not open is refused there. `brokerSubcommands` (`internal/port49d/brokerd.go:47-66`) has no forget.

## Rulings made in this plan

1. **No offline `port49-broker forget`.** It goes under Left. With Tasks 3-4 in place, a pin strands only when step 3 is run against a nonzero gauge, or when a key is lost. The first case is undone by putting the key back as `previous` and restarting. Nothing is deleted, and the page already requires every old key file to be kept offline (line 220). In the second case, the cure is a forget by any admin whose own pin opens. That pin was re-sealed, because the pass covers every pin that opens. An offline forget would be a second path around the touch-gated, recorded API. It would need its own decision-log record and its own fence, so it is not worth adding before beta.
2. **The count's surface is three metrics plus the broker's lines.** There is no CLI field. `port49 store status` and the admin API stay as they are (see Left).
   - `port49_directory_pins_sealed_previous`
   - `port49_directory_pins_unopenable`
   - `port49_directory_pins_reseal_last_complete_timestamp_seconds`

   They extend design §15's store list. They are gauges with no label, so no principal or device is in a label. They are set only by a pass that completes, left unchanged by one that stops, and absent until the first pass and on a shared store.
3. **A CAS conflict is counted under `sealed_previous`.** The writer between the read and the write sealed under its own `current`, which before step 2 finished everywhere may still be the old key. The gauge stays above 0 until a later pass reads the pin as not Stale. This errs toward waiting.
4. **One alert, `port49_directory_pins_unopenable > 0`, ticket.** One person cannot bind, mint or refresh, which is not a page. `sealed_previous > 0` is the normal state between step 2 and the next pass, so it gets no alert.
5. **The pass runs on every complete `RefreshDirectory`, with or without password sign-in.** Pins exist with any directory, so it is not gated on `PasswordSignIn`.
6. **The new spec decision is 57.** Decisions 47 ruling 11 and 51 R13 are amended in place, pointing at it.

## What an operator sees at 3am

| Event | What happens | What they see |
|---|---|---|
| The directory store stops answering mid-pass | The bounded read or write returns `ErrUnavailable`, and the pass stops. Each pin is one CAS, so nothing is half-written. | `directory store: the re-seal of pins stopped: <error>; the next pass starts again`, once an hour. The gauges keep the last complete pass's values, and the timestamp does not move. |
| port49-broker restarts mid-pass | The duty's ctx ends the pass silently, and the next runner's first pass starts from the listing. | The gauges are absent until that pass completes. |
| Two brokers run the pass at once | In one region, only the hold holder runs it. Across regions, both runners read one directory: one CAS wins, and the other gets `ErrConflict` and counts it under `sealed_previous`. Neither overwrites the other. | One pass's `sealed_previous` reads 1 for that pin, then 0 at the next pass. |
| A pin opens under neither key | It is counted under `unopenable` and left as it is: no write, no delete. | `directory store: <principal>'s pin does not open (<error>): it is left as it is; put the key that sealed it back as encryption.previous and restart, or run `port49 directory forget <principal>``, once an hour per principal. `directory store: N pins open under neither encryption key; ...`, once an hour. The alert `port49_directory_pins_unopenable` fires. |
| Step 2 is half done across regions | A runner still on (K1, K2) reads a K2 pin as Stale and seals it back under K1. The second-factor pass does the same today. Every process holds both keys, so this is harmless. | The page says to wait for a pass that ends after the last step-2 restart. |

## Global Constraints

- Go 1.26+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case for data. The metric names above are snake_case (`TestEveryMetricNameIsSnakeCase`).
- Reason codes only from spec §5.7, and this plan adds none. Warnings only from spec §12, and this plan adds none: the new lines are broker log lines, not `policy test` warnings.
- No device or principal identity in a metric label (`TestNoMetricHasADeviceLabel`). The three gauges have no labels.
- The log never contains a credential, token, pin plaintext or key material. Credentials appear only as `credential_sha256`.
  - A pin line names the principal, as `refresh-verify:` lines do today, and the error through `printsafe.Line`. The error comes from crypt and names a key id at most.
  - No line prints a DN, a username, a map key or a sealed byte.
  - Tests never print `Sealed`. They use `crypt.SealedKeyID`.
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, or key files.
  - Every recursive grep excludes them. grep is ugrep: use `-e PATTERN`, never `--` before a pattern. Never grep `tests/lab/logs` or `tests/lab/captures`.
  - If a safety check refuses a command, stop and report it. Never rephrase it.
- Tests: `TMPDIR` is a private 0700 directory under `~/.cache`. Before the final review, run `make test && make vet && make docs && make alerts-check` and report the real output. `git status` after `make docs` shows no diff.
- **Commits:**
  - Conventional Commits, one per "Commit" step, with an explicit pathspec.
  - Every message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and nothing else. No `Claude-Session:` line, and no claude.ai URL anywhere: commits, PR body, comments.
- **Branch:** `fix/pin-reseal-52`, from `main` `19ca91f5`, in `.worktrees/pin-reseal-52`. The tasks are sequential.
- **Lab:** none needed. The pass uses only `PutPin`'s existing compare, which `storetest` runs on memory and etcd. No device behavior changes, and no §15 row changes status. L75 (f) measured pins across brokers and still holds.

## Review Focus

1. **The CAS is the only write.** `ResealPins` writes only through `p.putPin(ctx, pin, store.PinExpect{Version: pin.Version})`. Never through `PutMembership` (its `samePin` short-circuit would skip the write) or `Members.PutPin` with `Absent` or `Forgotten`.
2. **No pin is deleted or rewritten unless it opened Stale.** An unopenable pin and a pin forgotten since the listing (`ErrForgotten` is an `ErrNotFound`) get no write.
3. **An outage stops the pass and leaves the gauges alone.** Only a complete pass sets them. A canceled ctx says nothing.
4. **`Stale` is computed in `openMembership` before `m.Sealed` is cleared**, exactly as `GetSecondFactor` computes it (`crypt/enrollments.go:121`).
5. **The page's step 3 condition is the gauge on a pass after the last step-2 restart**, read on the keyspace holder, with the 24-hour membership-lease wait kept.

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
     factors. The crypt layer marks a membership it opened under `encryption.previous` `Stale`. The
     pass lists the directory's pins and writes each Stale pin again, sealed under `current`, by
     `PutPin` at the version it read. A pin that a forget, a re-pin or another region's pass changed
     since the read stands (`ErrConflict`); the pass counts it as still under `previous` and the next
     pass reads it again. A directory store that does not answer ends the pass, said once an hour;
     the next pass starts from the listing. A single shared store keeps no pin without a lease (its
     membership record lives max(`broker.directory.grace`, 24h) and every verification rewrites it)
     and runs no pin pass.
  2. **A pin that opens under neither key** is never deleted or rewritten. It is counted, and said
     once an hour per principal, naming `encryption.previous` and `port49 directory forget`.
  3. **The count.** `port49_directory_pins_sealed_previous` (pins the last complete pass left under
     `previous`, conflicts included), `port49_directory_pins_unopenable` (pins that opened under
     neither key) and `port49_directory_pins_reseal_last_complete_timestamp_seconds`: gauges with no
     label, set by a pass that completes, unchanged by one that stops, absent until the first and on
     a shared store. Rotation's step 3 waits, after step 2 has finished everywhere, for a pass that
     completed after the last step-2 restart with `port49_directory_pins_sealed_previous` 0. Alert:
     `port49_directory_pins_unopenable` above 0 (ticket).
  4. **No offline forget.** A pin is stranded only by a step 3 run against a nonzero gauge, which
     putting the key back as `previous` undoes, or by a lost key, which a forget by any admin whose
     own pin opens cures; the pass keeps every pin that opens on `current`. An offline forget would
     be a path around the touch-gated, recorded broker API.
  ```

- [ ] **Step 2: The amendments.**
  - At the end of decision 47 ruling 11, add: `*Amended by decision 57 (2026-11-08):* the same pass re-seals the directory store's pins.`
  - At the end of decision 51's R13 bullet, add: `*Amended by decision 57 (2026-11-08):* the scheduled pass writes again a pin that opened under `encryption.previous`, by a compare on its version, so a rotation strands none.`

- [ ] **Step 3: Design §15.**
  - After the `port49_crypt_store_key_unknown;` bullet of the store's list, add: `` `port49_directory_pins_sealed_previous`, `port49_directory_pins_unopenable` and `port49_directory_pins_reseal_last_complete_timestamp_seconds`, on port49-broker with a directory store of its own (spec decision 57); ``
  - After the alert bullet `` `port49_crypt_store_key_unknown` at 1; ``, add: `` `port49_directory_pins_unopenable` above 0: a pin a key rotation retired too early, whose principal cannot bind, mint or refresh (spec decision 57); ``

- [ ] **Step 4: Run `make docs && git status --short`.** The lab-register and reason pages read the spec, and no generated page may change. Then run `go test ./internal/docgen/ ./tests/ci/ -count=1`. Expected: PASS.

- [ ] **Step 5: Commit.**

  `git add docs/design/2026-08-23-policy-engine-spec.md docs/design/2026-08-21-port49-design.md && git commit -m "docs: decision 57, directory pins are re-sealed at a key rotation (#52)"`

---

### Task 2: A membership opened under the previous key is `Stale`

**Files:**
- Modify:
  - `internal/store/store.go` `Membership` (`:1284`): add after `Sealed` (before `Version`):
    ```go
    	// Stale is a record opened under the previous encryption key: the
    	// scheduled pass seals the directory's pin again (decision 57).
    	// Written by internal/store/crypt; false when written.
    	Stale bool
    ```
  - `internal/store/crypt/crypt.go` `openMembership` (`:1207`): immediately before the line `m.DN, m.EntryID, m.Username, m.GroupDNs, m.GroupNames, m.Sealed = ...` (`:1225`), add
    ```go
    	// Stale, as a second factor's is: opened under the previous key, so the
    	// scheduled pass seals the pin again before encryption.previous is
    	// retired (decision 57).
    	m.Stale = w.keys.Previous != nil && SealedKeyID(m.Sealed) == LineKeyID(w.keys.Previous.ID)
    ```
- Test: `internal/store/crypt/crypt_test.go`.

- [ ] **Step 1: Write the failing test.**

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
  ```

- [ ] **Step 2: Run it and see it fail.** `TMPDIR=$TMPDIR go test ./internal/store/crypt/ -run '^TestAMembershipUnderThePreviousKeyIsStale$' -count=1`. Expected: the build fails (`got.Stale undefined`). After adding only the field, it fails with `under the previous key: stale false`. Paste the red output.

- [ ] **Step 3: Implement** as in Files.

- [ ] **Step 4: Run** `TMPDIR=$TMPDIR go test ./internal/store/... -count=1`. Expected: PASS. A test that compares whole `Membership` values read under a two-key window may now see `Stale` and need it named. Fix the test's expectation, never the code.

  **Mutation check:** compare against `w.keys.Current.ID` instead, and see the test go red. Then restore.

- [ ] **Step 5: Commit.**

  `git add internal/store/store.go internal/store/crypt/crypt.go internal/store/crypt/crypt_test.go && git commit -m "feat(store): a membership opened under the previous encryption key is Stale (#52)"`

---

### Task 3: `placement.ResealPins`, by compare-and-swap

**Files:**
- Modify:
  - `internal/store/store.go`: after `PinExpect`, add
    ```go
    // PinReseal is one complete pass of the directory pins' re-seal (decision
    // 57): pins sealed again under the current key, pins still under the
    // previous one (a write that met a newer pin, left for the next pass), and
    // pins that opened under neither key, left as they are.
    type PinReseal struct {
    	Sealed, Previous, Unopened int
    }
    ```
  - `internal/store/placement/placement.go`:
    - `Members` (`:37-43`) gains `MembershipPrincipals(ctx context.Context) ([]string, error)`.
    - Add `ResealPins` after `PutPin` (`:295-300`):
      ```go
      // ResealPins is the scheduled re-seal of the directory's pins (decision
      // 57): every pin that opened under encryption.previous is written again,
      // sealed under the current key, by a compare on the version it was read
      // at, so a pin a forget, a re-pin or another region changed since the
      // read stands; that one is counted in Previous and the next pass reads it
      // again. A pin that opens under neither key is told to unopened and
      // counted, and never written or deleted. A directory that does not answer
      // ends the pass with its error: each pin is one compare, so nothing is
      // left half-written. With no directory of its own there are no pins.
      func (p *placed) ResealPins(ctx context.Context, unopened func(principal string, err error)) (store.PinReseal, error) {
      	var rep store.PinReseal
      	if p.c.Members == nil {
      		return rep, nil
      	}
      	if !p.reachable() {
      		return rep, fmt.Errorf("%w: the directory store does not answer", store.ErrUnavailable)
      	}
      	var principals []string
      	if err := bounded(ctx, p.c.BulkTimeout, func(ctx context.Context) (x error) {
      		principals, x = p.c.Members.MembershipPrincipals(ctx)
      		return
      	}); err != nil {
      		return rep, err
      	}
      	for _, principal := range principals {
      		var pin store.Membership
      		err := bounded(ctx, p.c.CallTimeout, func(ctx context.Context) (x error) {
      			pin, x = p.c.Members.GetMembership(ctx, principal)
      			return
      		})
      		switch {
      		case errors.Is(err, store.ErrNotFound):
      			continue // forgotten or gone since the listing (ErrForgotten is an ErrNotFound)
      		case errors.Is(err, store.ErrUnavailable), ctx.Err() != nil:
      			return rep, err
      		case err != nil:
      			rep.Unopened++
      			if unopened != nil {
      				unopened(principal, err)
      			}
      			continue
      		case !pin.Stale:
      			continue
      		}
      		switch err := p.putPin(ctx, pin, store.PinExpect{Version: pin.Version}); {
      		case err == nil:
      			rep.Sealed++
      		case errors.Is(err, store.ErrConflict):
      			rep.Previous++
      		default:
      			return rep, err
      		}
      	}
      	return rep, nil
      }
      ```
  - `internal/port49d/storeref.go`: `lazyMembers` gains `MembershipPrincipals`, in the shape of `DeleteMembership` (`:190`):
    ```go
    func (l *lazyMembers) MembershipPrincipals(ctx context.Context) ([]string, error) {
    	s, err := l.get()
    	if err != nil {
    		return nil, err
    	}
    	return s.MembershipPrincipals(ctx)
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

  // The pass writes each pin under the previous key again under the current
  // one, keeping its entry and map keys, and a second pass writes nothing.
  func TestTheReSealPassMovesPinsOffThePreviousKey(t *testing.T) {
  	ctx := context.Background()
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
  	r := sealedRegion(dir, window("k2", "k1"), nil)
  	if rep, err := r.ResealPins(ctx, nil); err != nil || rep != (store.PinReseal{Sealed: 2}) {
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
  	if rep, err := r.ResealPins(ctx, nil); err != nil || rep != (store.PinReseal{}) {
  		t.Fatalf("a second pass: %+v, %v", rep, err)
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
  	if rep, err := r.ResealPins(ctx, nil); err != nil || rep != (store.PinReseal{Previous: 1}) {
  		t.Fatalf("the pass: %+v, %v (want the conflict counted under Previous)", rep, err)
  	}
  	got, err := crypt.Wrap(dir, window("k2"), nil).GetMembership(ctx, alice)
  	if err != nil || !got.Refused {
  		t.Fatalf("the other region's refusal was overwritten: %+v, %v", got, err)
  	}
  	if rep, err := r.ResealPins(ctx, nil); err != nil || rep != (store.PinReseal{}) {
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
  	rep, err := sealedRegion(dir, window("k2", "k1"), nil).ResealPins(ctx, func(p string, err error) {
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
  // finishes. A directory known cut is not called at all.
  func TestADirectoryCutMidPassEndsItAndLeavesNothingHalfWritten(t *testing.T) {
  	ctx := context.Background()
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
  	cut := sealedRegion(dir, window("k2", "k1"), func(m Members) Members { return &stopping{Members: m, n: 1} })
  	rep, err := cut.ResealPins(ctx, nil)
  	if !errors.Is(err, store.ErrUnavailable) || rep != (store.PinReseal{Sealed: 1}) {
  		t.Fatalf("the cut pass: %+v, %v", rep, err)
  	}
  	if id := sealedUnder(t, dir, bob); id != "k1" {
  		t.Fatalf("bob's pin, after the pass stopped before it, is under %q", id)
  	}
  	opens(t, dir, window("k2", "k1"), alice, bob)
  	r := sealedRegion(dir, window("k2", "k1"), nil)
  	r.c.Reachable = func() bool { return false }
  	if _, err := r.ResealPins(ctx, nil); !errors.Is(err, store.ErrUnavailable) {
  		t.Fatalf("a pass with the directory known cut: %v", err)
  	}
  	r.c.Reachable = nil
  	if rep, err := r.ResealPins(ctx, nil); err != nil || rep != (store.PinReseal{Sealed: 1}) {
  		t.Fatalf("the next pass: %+v, %v", rep, err)
  	}
  }

  // Issue #52 end to end: rotate, pass, rotate again, pass; every pin opens
  // under the last key alone.
  func TestTwoRotationsWithAPassBetweenStrandNoPin(t *testing.T) {
  	ctx := context.Background()
  	dir := memory.New(clock)
  	pinned(t, sealedRegion(dir, window("k1"), nil), pinFor(alice, "uuid:a"), pinFor(bob, "uuid:b"))
  	// First rotation, step 2 (k2, k1 previous), then the pass; step 3 drops k1.
  	if rep, err := sealedRegion(dir, window("k2", "k1"), nil).ResealPins(ctx, nil); err != nil || rep.Sealed != 2 {
  		t.Fatalf("the first rotation's pass: %+v, %v", rep, err)
  	}
  	opens(t, dir, window("k2"), alice, bob)
  	// Second rotation, step 1 (k2, k3 previous): k1 is gone and nothing strands.
  	opens(t, dir, window("k2", "k3"), alice, bob)
  	// Step 2 (k3, k2 previous), the pass, then step 3 (k3 alone).
  	if rep, err := sealedRegion(dir, window("k3", "k2"), nil).ResealPins(ctx, nil); err != nil || rep.Sealed != 2 {
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

- [ ] **Step 2: Run them and see them fail.** `TMPDIR=$TMPDIR go test ./internal/store/placement/ -run '^Test(TheReSealPass|ADirectoryCutMidPass|TwoRotations|WithoutThePass)' -count=1`. Expected: the build fails (`ResealPins` undefined, `store.PinReseal` undefined). With a stub that returns `store.PinReseal{}, nil`, every test but the control fails. Paste the red output.

- [ ] **Step 3: Implement** as in Files. Then `go build ./...`: every `Members` test double embeds `Members` or `store.Store`, so it compiles unchanged.

- [ ] **Step 4: Run** `TMPDIR=$TMPDIR go test ./internal/store/... ./internal/port49d/ -count=1`. Expected: PASS.

  **Mutation checks:** see each one go red, then restore it.
  - Write with `p.c.Members.PutPin(ctx, pinOf(pin), store.PinExpect{Absent: true})`: the CAS test fails.
  - Delete the `case !pin.Stale` line: the second-pass and next-pass assertions fail.
  - Make the unopenable case `return rep, err`: the unopenable test fails.

- [ ] **Step 5: Commit.**

  `git add internal/store/store.go internal/store/placement/placement.go internal/store/placement/reseal_test.go internal/port49d/storeref.go && git commit -m "feat(placement): the directory's pins are re-sealed under the current key by compare-and-swap (#52)"`

---

### Task 4: The scheduled pass runs it and gauges what is left

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
      	// when it ended. No principal.
      	DirectoryPinsSealedPrevious, DirectoryPinsUnopenable, DirectoryPinsResealLastComplete *prometheus.GaugeVec
      ```
    - In `New`, after `DirectoryRefreshLastComplete:`:
      ```go
      		DirectoryPinsSealedPrevious: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_pins_sealed_previous",
      			Help: "Directory pins the last complete re-seal pass left sealed under encryption.previous; remove " +
      				"encryption.previous only at 0, from a pass that ended after the last restart of the rotation's " +
      				"step 2. Absent until a pass completes, and on a shared store."}, nil),
      		DirectoryPinsUnopenable: prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "port49_directory_pins_unopenable",
      			Help: "Directory pins the last complete re-seal pass could not open under either encryption key; " +
      				"their principals cannot bind, mint or refresh. Alert above 0."}, nil),
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
      	ResealPins(ctx context.Context, unopened func(principal string, err error)) (store.PinReseal, error)
      }

      // pinPass is the directory pins' share of the scheduled pass (decision
      // 57): the re-seal, its gauges set from a pass that completed and left as
      // they were by one that stopped, each line said at most once an hour. A
      // shared store keeps no pin without a lease and has none of it.
      func (b *Broker) pinPass(ctx context.Context) {
      	r, ok := b.Store.(pinResealer)
      	if !ok {
      		return
      	}
      	rep, err := r.ResealPins(ctx, func(principal string, err error) {
      		b.sayOnce("pin_reseal "+principal, time.Hour, "directory store: %s's pin does not open (%s): it is left as "+
      			"it is; put the key that sealed it back as encryption.previous and restart, or run `port49 directory "+
      			"forget %s`", printsafe.Line(principal, 300), printsafe.Line(err.Error(), 300), printsafe.Line(principal, 300))
      	})
      	switch {
      	case ctx.Err() != nil:
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
      		b.sayOnce("pin_reseal_unopened", time.Hour, "directory store: %d pins open under neither encryption key; "+
      			"their principals cannot bind, mint or refresh until the key is back as encryption.previous or each "+
      			"is forgotten", rep.Unopened)
      	}
      }
      ```
- Regenerate `docs/site/reference/metrics.md` with `make docs`.
- Test: `internal/broker/signin_admin_test.go`, beside `TestTheScheduledPassChecksAndReSealsTheEnrollmentStore`.

- [ ] **Step 1: Write the failing test.**

  ```go
  // resealing is a store with directory pins as the scheduled pass sees it:
  // ResealPins tells each of unopened and answers rep, err.
  type resealing struct {
  	store.Store
  	rep      store.PinReseal
  	err      error
  	unopened []string
  }

  func (r *resealing) ResealPins(_ context.Context, unopened func(string, error)) (store.PinReseal, error) {
  	for _, p := range r.unopened {
  		unopened(p, errors.New("crypt: opening membership: crypt: sealed under an unknown key"))
  	}
  	return r.rep, r.err
  }

  // The scheduled pass re-seals the directory's pins (decision 57): a pass
  // that completes sets the three gauges and says what it did; one the store
  // stops changes none; a store with no pins has none of them.
  func TestTheScheduledPassReSealsPinsAndGaugesWhatIsLeft(t *testing.T) {
  	ctx := context.Background()
  	f, _ := newSignInFixture(t)
  	m := f.b.Metrics
  	if _, err := f.b.RefreshDirectory(ctx); err != nil {
  		t.Fatal(err)
  	}
  	for _, g := range []*prometheus.GaugeVec{m.DirectoryPinsSealedPrevious, m.DirectoryPinsUnopenable,
  		m.DirectoryPinsResealLastComplete} {
  		if n := testutil.CollectAndCount(g); n != 0 {
  			t.Fatalf("a store with no pins has %d series of a pin gauge", n)
  		}
  	}
  	r := &resealing{Store: f.b.Store, rep: store.PinReseal{Sealed: 3, Previous: 1, Unopened: 1},
  		unopened: []string{"user:carol@example.com"}}
  	f.b.Store = r
  	if _, err := f.b.RefreshDirectory(ctx); err != nil {
  		t.Fatal(err)
  	}
  	ended := f.b.Now().Unix()
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
  }
  ```

  Add `"github.com/prometheus/client_golang/prometheus"` to the file's imports.

- [ ] **Step 2: Run it and see it fail.** `TMPDIR=$TMPDIR go test ./internal/broker/ -run '^TestTheScheduledPassReSealsPins' -count=1`. Expected: the build fails (`m.DirectoryPinsSealedPrevious` undefined). With the metrics in place and no `pinPass`, it fails at "after a complete pass". Paste the red output.

- [ ] **Step 3: Implement** as in Files, then run `make docs`. `docs/site/reference/metrics.md` gains the three series.

- [ ] **Step 4: Run** `TMPDIR=$TMPDIR go test ./internal/broker/ ./internal/daemon/... ./internal/docgen/ ./tests/ci/ -count=1`. Expected: PASS, including `TestMetricsPageIsCurrent`, `TestNoMetricHasADeviceLabel` and `TestEveryMetricNameIsSnakeCase`.

  **Mutation check:** set the gauges before the `err != nil` case, and see "a stopped pass moved the gauges". Then restore.

- [ ] **Step 5: Commit.**

  `git add internal/daemon/metrics/metrics.go internal/broker/scheduled.go internal/broker/signin_admin_test.go docs/site/reference/metrics.md && git commit -m "feat(broker): the scheduled pass re-seals directory pins and gauges what is left (#52)"`

---

### Task 5: The alert `port49_directory_pins_unopenable`

**Files:**
- Modify:
  - `deploy/alerts/port49.rules.yaml`: in group `port49_store`, after `port49_crypt_token_open_failures`:
    ```yaml
          - alert: port49_directory_pins_unopenable
            expr: "port49_directory_pins_unopenable > 0"
            labels: {severity: ticket}
            annotations:
              summary: "A directory pin opens under neither encryption key: its principal cannot bind, mint or refresh."
              runbook_url: "https://blanketfish.github.io/port49/reference/alerts/#port49_directory_pins_unopenable"
    ```
  - `deploy/alerts/port49.rules.test.yaml`: after the `port49_crypt_token_open_failures` cases, a firing case (`port49_directory_pins_unopenable{instance="a"}` values `"1+0x30"`, eval 5m, labels `{instance: "a", severity: "ticket"}` and both annotations), and a quiet case (`"0+0x30"`, `exp_alerts: []`).
  - `deploy/alerts/README.md`: after the `port49_crypt_token_open_failures` row:
    `` | design §15: "`port49_directory_pins_unopenable` above 0" | `port49_directory_pins_unopenable` | ticket | none | One principal is locked out until the key that sealed the pin is back as `encryption.previous` or the pin is forgotten; the pass never deletes it. | ``
  - `docs/site/operate/troubleshooting/index.md` "### Stores": add `[port49_directory_pins_unopenable](../../reference/alerts.md#port49_directory_pins_unopenable),` after the `port49_crypt_token_open_failures` link in the **ticket** list.
- Regenerate `docs/site/reference/alerts.md` (and the metrics page's alert link) with `make docs`.

- [ ] **Step 1: Write the failing test.** Add the two rule-test cases first. Run `make alerts-check`. Expected: FAIL, because no rule `port49_directory_pins_unopenable` exists. Also run `TMPDIR=$TMPDIR go test ./tests/ci/ -run '^TestEveryAlertIsInTheIndex$' -count=1`, which still passes. Paste the red output.
- [ ] **Step 2: Implement** the rule, the README row and the index link, then run `make docs`.
- [ ] **Step 3: Run** `make alerts-check && TMPDIR=$TMPDIR go test ./internal/docgen/ ./tests/ci/ -count=1`. Expected: PASS (`TestEveryAlertIsInTheIndex`, `TestAlertsPageIsCurrent`, `TestMetricsPageIsCurrent`).
- [ ] **Step 4: Commit.**

  `git add deploy/alerts/port49.rules.yaml deploy/alerts/port49.rules.test.yaml deploy/alerts/README.md docs/site/operate/troubleshooting/index.md docs/site/reference/alerts.md docs/site/reference/metrics.md && git commit -m "feat(alerts): port49_directory_pins_unopenable, a pin a rotation retired too early (#52)"`

---

### Task 6: The key-rotation page, stores page and roadmap

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
    by the same scheduled pass. A pin has no expiry, so it never ages out. Instead, the runner reads every
    pin and writes each one still sealed under `previous` again under `current`, by a compare on the
    revision it read. A pin that a `port49 directory forget`, a re-pin or another region's runner changed
    in between is left as that writer wrote it, and the next pass reads it again. **After step 2 has
    finished everywhere, wait for a pass that ended after the last step-2 restart**
    (`port49_directory_pins_reseal_last_complete_timestamp_seconds` later than that restart) **with
    `port49_directory_pins_sealed_previous` at 0.** Read both on the replica that holds the keyspace
    (`port49_store_keyspace_held` 1). Any region's runner will do, because they all read the one
    directory store. The gauges are absent until a runner completes its first pass after it starts. They
    are also absent on a single shared store, where a membership record has a lease (the 24 hours above)
    and there is no pin to re-seal. A pass that moves pins says `directory store: the re-seal sealed N
    pins under the current key; M are left under encryption.previous`. If the directory store stops
    answering, the pass says `directory store: the re-seal of pins stopped: <error>; the next pass starts
    again` and changes no gauge. Each pin is one compare-and-swap, so nothing is left half-written.
  - **A pin that opens under neither key** is counted in `port49_directory_pins_unopenable` (alert
    [port49_directory_pins_unopenable](../reference/alerts.md#port49_directory_pins_unopenable)). It
    means a key was retired while it still sealed pins. Reading the pin fails with an unknown-key error
    (`ErrUnknownKey`), and `port49_crypt_open_failures_total{record="membership"}` rises. Bind, mint and
    refresh fail for that principal, and sessions already open are denied `context_stale` once
    `session.staleness_ceiling` has passed. The pass never deletes or rewrites such a pin; it says
    `directory store: <principal>'s pin does not open (...)` once an hour. Put the retired key back as
    `previous` and restart: nothing was deleted, and the next pass re-seals the pin. If that key is gone,
    `port49 directory forget <principal>` frees the principal, and the person's next sign-in pins them
    again. Any admin with `forget_principals` whose own pin opens can run it, and every pin that opens is
    on `current` after a pass. Confirm that the person who signs in is the same person, as on
    [Stores](../operate/stores.md). There is no offline forget on `port49-broker`.
  - **Rotating again.** There is one `previous` slot, so a rotation's step 1 drops whatever key
    `previous` held. Begin a rotation only after the last one's step 3. The waits above gate that step,
    so every pin and second factor is then under `current`, and the new rotation strands nothing.
  ```

- [ ] **Step 3: The stores page.** Step 3 at `docs/site/operate/stores.md:97` becomes: ``3. Remove the old key from `encryption.previous`, everywhere, once [Key rotation](../admin/key-rotation.md#the-encryption-key)'s waits are over; on a split that includes `port49_directory_pins_sealed_previous` at 0 from a pass after step 2.``

- [ ] **Step 4: Roadmap.** In `docs/superpowers/plans/README.md`, after "Plan 13 — As built" and before the closing `---`, add a section `## Fix #52 — pin re-seal on encryption rotation`. It holds:
  - the plan's path;
  - one line each for decision 57, the pass, the three gauges and the alert;
  - **Left** (as below).

  Then run `make docs` and `TMPDIR=$TMPDIR go test ./tests/ci/ ./internal/docgen/ -count=1`. Expected: PASS, and `git status --short` shows only the four files above.

- [ ] **Step 5: Commit.**

  `git add tests/ci/docs_content_16_test.go docs/site/admin/key-rotation.md docs/site/operate/stores.md docs/superpowers/plans/README.md && git commit -m "docs: key rotation waits for the pin re-seal, and the forget-every-pin procedure is gone (#52)"`

- [ ] **Step 6: Final verification.** Run `make test && make vet && make docs && make alerts-check && git status --short`. Report the real output; the status must be empty.

## Operator-facing notes (for the PR body)

- The scheduled directory pass on port49-broker now re-seals directory pins after an `encryption:` rotation, as it does second factors. A second rotation no longer strands pins.
- New gauges: `port49_directory_pins_sealed_previous`, `port49_directory_pins_unopenable` and `port49_directory_pins_reseal_last_complete_timestamp_seconds`. They exist only on a split, and only after the first complete pass.
- New ticket alert: `port49_directory_pins_unopenable`.
- New broker lines: `directory store: the re-seal sealed N pins ...`, `directory store: the re-seal of pins stopped: ...`, `directory store: <principal>'s pin does not open ...`, and `directory store: N pins open under neither encryption key ...`.
- Rotation's step 3 now waits for `port49_directory_pins_sealed_previous` to read 0. The forget-every-principal procedure before a second rotation is gone.

## Left

1. **An offline `port49-broker forget`** (Ruling 1). After this plan, a pin strands only when step 3 runs against a nonzero gauge, which putting the key back undoes, or when a key is lost, which a forget by any admin whose pin opens cures. Revisit only if a lab or field case shows every admin stranded with the key lost.
2. **The count in `port49 store status` or the admin API.** The gauges and the broker lines answer at 3am. A status field would need a broker API change, and the runner is the only process that knows the count.
3. **A gauge for second factors still under `previous`.** The second-factor pass says only `could not open N`. Its step-3 condition stays "wait for a pass", as written today. A matching gauge is a small follow-up in the same shape.
4. **An alert on a pin re-seal that never completes.** `port49_directory_refresh_last_complete_timestamp_seconds` already alerts on a pass that never completes, and the pin pass is that pass's tail.
