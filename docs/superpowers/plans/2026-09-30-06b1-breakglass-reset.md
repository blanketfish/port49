# Fix `fix/breakglass-reset`: A Declined Device Is Refused at Accept (L31) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Break-glass on IOS-XE and NX-OS with single-connection on costs what a key miss costs
(1.5–2.6 s), not 16–41 s, when port49d has removed, refused or quarantined the device.

**Architecture:** The unadmitted, refused and quarantined paths in `internal/daemon/server/conn.go`
take L28's shape. The first connection gets its record, then an immediate reset (`SetLinger(0)`),
with no hold. The source's next connections are refused at Accept, with a reset before the device
writes, for a short window. An unadmitted source gets that window from a strike, as a key miss
does, through `Limiter.Holding`. A refused or quarantined device, or one a reload refused or
removed under an open connection, takes no strike. It gets a separate **decline window** in the
limiter, on the strike's schedule. Accept honours the window only while admission in force and
the policy still decline the source, so a reload that admits the device again, or the end of its
quarantine, drops the window and the connection is served.

**Tech Stack:** Go 1.22+, the standard library, `prometheus/client_golang` (already a dependency).
containerlab on the lab host (beehive) for Task 6. **No new module dependencies.**

**Spec:** `docs/design/2026-08-23-policy-engine-spec.md` §10 ("A quarantined device gets silence,
not FAIL"; "A device is refused on its own"; "A key miss is closed at once"; "How a daemon
refreshes its snapshot"), §5.7 (reason codes and diagnoses: none added), §14 "Inventory and
capability", §15 L28 and L29 (closed), and L31 (open, closed here). The evidence is
`tests/lab/results/L31-breakglass-cisco-singleconnection.md` and
`.superpowers/sdd/2026-09-30-06b-inventory-service/breakglass-investigation.md`. The roadmap entry is
`docs/superpowers/plans/README.md`, "Fix `fix/breakglass-reset`". Design
`docs/design/2026-08-21-port49-design.md` §11 (listener limits).

**Revised 2026-09-30 after the pre-flight review** (`.superpowers/sdd/2026-09-30-06b1-breakglass-reset/preflight.md`):
all 5 MAJOR and 14 MINOR findings addressed in place.

**Prerequisite:** plan 6b merged (PR #17, `b537760`). Create branch `fix/breakglass-reset` off `main`
at the commit that adds this file, in the worktree `.worktrees/breakglass-reset`.

## Owner decisions needed

None. Every choice below takes the default that admits and answers nothing that is not admitted and
answered today.

## Decided in this plan

1. **The decline window uses the strike's schedule and settings, in a map of its own.** The first
   window is `limits.malformed_backoff_base` (100 ms by default). It doubles with each decline up to
   `limits.malformed_backoff_max` (5 s), and the count starts over after `limits.malformed_window`
   with no decline. That is the shape L28's re-key control measured at 1.53 s and 2.6 s
   (`L29-reload-rekeyed-cisco_*.md`). No new configuration knob.
2. **The window is "cleared on every reload" by checking the current state at Accept, with no
   reload hook.** Inside a window, Accept asks admission in force (it already looks the source up
   there) and the policy's quarantine question. Then it refuses the connection only if port49d would
   decline that connection's first packet anyway. If it would not, `Undecline` drops the window and
   the connection is served. This covers every reload path (file, `SIGHUP`, service pull, policy
   watch) and a quarantine that ends when a grant expires, which no reload marks. At 3am there is no
   hook for an operator to forget.
3. **New connection event `declined_refused`, separate from `held_refused`.** `held_refused` means a
   strike, which points at a key or a hostile source. A refused or quarantined device is neither, and
   an operator paged at 3am must be able to tell the two apart. Neither event has a device label.
4. **A reload that refuses or removes the device under an open connection opens the window too.**
   The device-side problem is the same: the command in flight is retried on a new connection. A
   rename, re-key or re-platform (`admission_withdrawn`) does not open the window, because that
   device is still admitted and its next connection is served.
5. **The unadmitted source keeps its strike** (spec §10). Its close becomes `keyMiss`'s: a record, a
   strike, and a reset at once, never the 0.1–5 s hold. This changes what a removed device's
   retries look like in metrics. When the removal ended an open connection, they are
   `declined_refused` for one window. After that, each new connection is a strike, and its retries
   are `held_refused`. It also changes what happens when a removed device is added back. Before,
   the hold only delayed the connection in flight. Now its next connections are refused at Accept
   for up to the backoff its last strike earned (5 s at most by default), and a strike is not
   re-checked against admission. Spec §10 already says "A strike from a device's address resets
   every connection from that address for up to 5 s".

**Security-neutral, argued.** No path decrypts, admits or answers anything new. The window only
refuses, and only a connection whose first packet port49d would refuse anyway (decision 2). Per
connection, the change is that the refusal happens earlier (at Accept, before any byte is read) and
leaves no record. Resource use falls: no descriptor is held for 5 s per unadmitted connection, and a
flooding source is refused at Accept.

## What the operator sees

| situation | before | after |
|---|---|---|
| Break-glass on a removed Cisco device, single-connection on | 30–41 s | the rekeyed control's time (lab-gated, Task 6) |
| Break-glass on a refused or quarantined Cisco device | 16–21 s | the same |
| Records from a declined device's retries | one per connection | one per window; the rest counted as `port49_connection_events_total{event="declined_refused"}` |
| A fix or re-admission of a refused or quarantined device | next connection served | next connection served (the window lapses when the reason does) |
| A removed device still polling | each connection held 0.1–5 s, then reset, and recorded | one window of `declined_refused` if the removal ended an open connection; then one `unadmitted_source` record and strike per backoff, its retries `held_refused` |
| A removed device added back | the connection in flight held for the backoff | its next connections refused at Accept for up to its last strike's backoff (≤ 5 s by default), then served |
| vEOS, vJunos-router | unaffected | unaffected (vEOS checked in Task 6) |

## Global Constraints

- Go 1.22+, module `github.com/blanketfish/port49`, `gofmt` and `go vet` clean, no cgo.
- snake_case for every metric name and label value: `declined_refused`.
- Reason codes and diagnoses are spec §5.7's closed vocabulary (`internal/decision/reasons.go`,
  `internal/keyring`). This plan adds none.
- The log never contains a token, password, challenge or response. An unvalidated body is never
  logged. No body is read on any path this plan touches.
- No device identity in metric labels.
- Verify before claiming done: `make test && make vet`, with the real output reported.
- Lab register rules 1–4 (CLAUDE.md). L31 closes only when both Cisco notes exist and pass.
- Commits: Conventional Commits, each ending with:

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
```

## File Structure

| File | Change |
|---|---|
| `docs/design/2026-08-23-policy-engine-spec.md` | §10 paragraphs, §14 bullet (Task 1); §15 L31 closed (Task 7) |
| `docs/design/2026-08-21-port49-design.md` | §11 listener-limits bullet (Task 1) |
| `internal/daemon/limits/limits.go` | `Decline`, `Declined`, `Undecline`; `Malformed` and `Holding` share `countLocked` and `inWindowLocked` (Task 2) |
| `internal/daemon/limits/limits_test.go` | decline tests (Task 2) |
| `internal/daemon/server/conn.go` | `unadmitted` (Task 3); `decline`; refused, quarantined and withdrawn paths (Task 4) |
| `internal/daemon/server/server.go` | Accept-time decline check, `declining` (Task 4) |
| `internal/daemon/metrics/metrics.go` | the `declined_refused` event in the event list (Task 4) |
| `internal/daemon/server/server_test.go` | `refusedAtAccept` (Task 3); new and updated tests (Tasks 3, 4) |
| `tests/lab/l29_shell_test.go` | `timeLogins` split out of `timedLogins` (Task 5) |
| `tests/lab/l31_test.go` | `TestL31BreakGlass` and its capture readers (Task 5) |
| `tests/lab/l31_unit_test.go` | the bar and the capture readers against committed evidence (Task 5) |
| `tests/lab/results/L31-*.md`, `tests/lab/evidence/L31-*.pcap` | written by the runs (Task 6) |
| `docs/superpowers/plans/README.md` | as built (Task 7) |

---

### Task 1: The spec and the design say what the fix builds, before the code does

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§10 at about lines 3939–3965, 4080–4086,
  4363, 4560–4570; §14 at about 6143)
- Modify: `docs/design/2026-08-21-port49-design.md` (§11, about line 1078)

**Interfaces:**
- Produces: the spec paragraph "A declined source is refused at Accept, and takes no strike", which
  Tasks 3, 4 and 7 cite, and the event name `declined_refused`.

- [ ] **Step 1: The new §10 paragraph.** In "Admission and keys", after the paragraph ending
  "`L28-juniper_vjunos-router.md`)." and before `#### Retirement is enforced, and that is the point`,
  insert:

```markdown
**A declined source is refused at Accept, and takes no strike.** port49d declines a connection
through no fault of the device's when admission refuses the device (above), when the device is
quarantined ("A quarantined device gets silence, not FAIL"), or when a reload refused or removed it
under an open connection ("How a daemon refreshes its snapshot"). Such a connection is closed the
way a key miss is, without the strike: one `unvalidated` record for its packet, and a TCP reset at
once, with no reply. The source then gets a decline window on the strike's schedule and settings:
`limits.malformed_backoff_base`, doubling up to `limits.malformed_backoff_max`, with the count
starting over after `limits.malformed_window` with no decline. A new connection from the source
inside the window is refused at Accept with a reset and no record, and is counted as
`port49_connection_events_total{event="declined_refused"}`, which has no device label. The window
refuses only a connection whose first packet port49d would decline anyway. At each Accept inside
the window, port49d asks admission in force and the policy again. If a reload has admitted the
source again, or its quarantine has ended, the window is dropped and the connection is served. So a
fix takes effect at the next connection, and a window never outlasts its reason. A decline is not a
strike: it never refuses a connection that would be served, and never lengthens a strike's backoff.
Once the source is admitted, its window is dropped at its first connection, and its count lapses
after `limits.malformed_window`. As with a strike, the log holds one record for
each connection that reached a packet, and connections refused inside a window are counted, not
recorded. A source the inventory does not name at all is struck rather than declined (above). It is
closed with a record, a strike and a reset at once, never held for the backoff, and its next
connections are refused at Accept for the strike's backoff (`held_refused`). A removed device's
retries are therefore `declined_refused` for at most one window, and only when the removal ended an
open connection. After that they are `held_refused`: its strikes are recorded `unadmitted_source`,
which is what tells them apart from a key miss's (`key_miss_closed`) or garbage
(`malformed_backoff`). The window exists because of how
IOS-XE and NX-OS behave with single-connection on. They take a reset that comes after their request
as transient and wait out their 5 s timeout on every AAA exchange. A reset that comes before they
write makes them fall to their local method at once (§15 L31,
`tests/lab/results/L31-breakglass-cisco-singleconnection.md`).
```

- [ ] **Step 2: The refused-device paragraph.** In "A device is refused on its own, never the
  daemon", replace

```markdown
`port49_devices_admission_refused`, and every packet from them closed after the header, with nothing
decrypted, no reply, no strike, and the report bucket `admission_refused` (below). The rest of the
```

  with

```markdown
`port49_devices_admission_refused`, and each connection from them closed after its first header,
with nothing decrypted, no reply, no strike, and the report bucket `admission_refused`, and their
next connections refused at Accept inside a decline window (below). The rest of the
```

- [ ] **Step 3: The quarantine paragraph.** In "A quarantined device gets silence, not FAIL", replace
  everything from `admitted it again. Break-glass took 0.32 s on vEOS` to the end of the paragraph
  (`...`tests/lab/results/L31-breakglass-cisco-singleconnection.md`).`) with

```markdown
admitted it again. Break-glass took 0.32 s on vEOS and 0.47 s on vJunos-router, but 16.7 s on the
N9Kv and 20.3 s on the C8000V. Those runs left single-connection on, and with it IOS-XE and NX-OS
take a reset that comes after their request as transient and wait out their 5 s timeout on every
AAA exchange, unless the retry is refused at Accept before they write (§15 L31;
`tests/lab/results/L31-breakglass-cisco-singleconnection.md`). So the close is a key miss's without
the strike: the first connection's packet is recorded and the connection reset at once, and the
source's next connections inside a decline window are refused at Accept with a reset and no record
("A declined source is refused at Accept", under "Admission and keys"). What that costs break-glass
on IOS-XE and NX-OS with single-connection on is L31's (open).
```

- [ ] **Step 4: The reload paragraph.** In "How a daemon refreshes its snapshot", replace

```markdown
port49d stopped, because the connections after the reset are closed only after the device's
request and never refused at Accept (§15 L31, open). Where port49d still serves the device under a new name or platform, its FAIL is
```

  with

```markdown
port49d stopped. The slow cases came from the connections after the reset, which were closed only
after the device's request and never refused at Accept. A reset for a reload that refused or
removed the device now opens a decline window, so those connections are refused at Accept ("A
declined source is refused at Accept"; §15 L31, open). A rename, re-key or re-platform opens none:
that device is still admitted. Where port49d still serves the device under a new name or platform, its FAIL is
```

- [ ] **Step 5: §14.** Under "Inventory and capability", after the bullet "**A device no key group
  admits**, and one two groups tie on, …", insert:

```markdown
- **A declined source is refused at Accept**: after one recorded packet from a refused or quarantined
  device, or from one a reload refused or removed under an open connection, its next connection
  inside the decline window is reset at Accept with no record, counted `declined_refused`, and with
  no strike. A reload that admits it again, or the end of its quarantine, serves its next connection
  at once. An unadmitted source's packet is recorded, struck and reset at once, never held, and its
  next connection inside the backoff is reset at Accept and counted `held_refused`. So a removed
  device's retries are `declined_refused` for at most one window (only when the removal ended an
  open connection), and `held_refused` after that, with each strike recorded `unadmitted_source`.
```

- [ ] **Step 6: The design.** In `docs/design/2026-08-21-port49-design.md` §11, after the bullet
  "**Malformed input closes the connection**, …", insert:

```markdown
- **A declined device is refused at Accept too.** A connection from a refused or quarantined device,
  or one a reload refused or removed, is recorded and reset at once. The source's next connections
  are refused at Accept with a reset for a short window, with no strike, and the window lapses when
  the device is admitted again (policy engine spec §10; §15 L31).
```

- [ ] **Step 7: Check and commit.** Run `grep -n "declined_refused\|decline window" docs/design/*.md`.
  Expected: hits in §10, §14 and the design's §11, and none that contradicts another.

```bash
git add docs/design
git commit -m "docs: spec a decline window that refuses a declined device's retries at Accept (L31)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 2: The limiter's decline window

**Files:**
- Modify: `internal/daemon/limits/limits.go`
- Test: `internal/daemon/limits/limits_test.go`

**Interfaces:**
- Produces, all safe for concurrent use:
  - `func (l *Limiter) Decline(src netip.Addr)`: counts a decline and opens its window.
  - `func (l *Limiter) Declined(src netip.Addr) bool`: reports whether `src` is inside its last
    decline's window.
  - `func (l *Limiter) Undecline(src netip.Addr)`: drops `src`'s window and count.
  - `Malformed` and `Holding` are unchanged in behaviour.

- [ ] **Step 1: Write the failing tests.** Append to `limits_test.go`:

```go
// A decline opens a window on the strike's schedule: the backoff base, then
// doubling (spec §10, "A declined source is refused at Accept").
func TestADeclineOpensAWindowOnTheStrikesSchedule(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a, b := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2")
	if l.Declined(a) {
		t.Fatal("declined before any decline")
	}
	l.Decline(a)
	if !l.Declined(a) || l.Declined(b) {
		t.Fatalf("after one decline of a: a %v, b %v", l.Declined(a), l.Declined(b))
	}
	now = now.Add(99 * time.Millisecond)
	if !l.Declined(a) {
		t.Fatal("the first window is the backoff base, 100ms")
	}
	now = now.Add(2 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the first window outlasted the backoff base")
	}
	l.Decline(a)
	now = now.Add(150 * time.Millisecond)
	if !l.Declined(a) {
		t.Fatal("the second window did not double to 200ms")
	}
}

// The window is capped at MalformedBackoffMax, and the count starts over once
// MalformedWindow has passed with no decline (decision 1's other two halves).
func TestADeclineWindowIsCappedAndStartsOver(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 10; i++ {
		l.Decline(a)
	}
	now = now.Add(time.Second - time.Millisecond)
	if !l.Declined(a) {
		t.Fatal("the capped window is MalformedBackoffMax, 1s")
	}
	now = now.Add(2 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the window outlasted MalformedBackoffMax")
	}
	now = now.Add(2 * time.Minute) // past MalformedWindow
	l.Decline(a)
	now = now.Add(101 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the count did not start over after MalformedWindow: the window was longer than the base")
	}
}

// A decline is not a strike: it puts the source in no strike's backoff and
// does not lengthen the next strike's.
func TestADeclineIsNotAStrike(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 5; i++ {
		l.Decline(a)
	}
	if l.Holding(a) {
		t.Fatal("a decline put the source in a strike's backoff")
	}
	if d := l.Malformed(a); d != 100*time.Millisecond {
		t.Fatalf("declines lengthened the first strike's backoff to %v", d)
	}
}

// Undecline drops the window and the count: a source declined again after it
// starts from the base.
func TestUndeclineDropsTheWindowAndTheCount(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(cfg(), func() time.Time { return now })
	a := netip.MustParseAddr("10.0.0.1")
	for i := 0; i < 5; i++ {
		l.Decline(a)
	}
	l.Undecline(a)
	if l.Declined(a) {
		t.Fatal("still declined after Undecline")
	}
	l.Decline(a)
	now = now.Add(101 * time.Millisecond)
	if l.Declined(a) {
		t.Fatal("the count survived Undecline: the next window was longer than the base")
	}
}
```

  In `TestSweepEvictsIdleEntries`, add `l.Decline(a)` after `l.Malformed(b)`. Change both length
  checks to include the new map: before, `len(l.declined) != 1` also fails, and the message prints
  `declined=%d`. After, `len(l.declined) != 0` also fails.

- [ ] **Step 2: Run them to see them fail.**
  Run `go test ./internal/daemon/limits/ -run 'Decline|Sweep' -count=1`.
  Expected: build failure, `l.Decline undefined` (and `l.declined undefined`).

- [ ] **Step 3: Implement.** In `limits.go`, add the field and initialise it:

```go
type Limiter struct {
	cfg      Config
	now      func() time.Time
	mu       sync.Mutex
	open     map[netip.Addr]int
	bad      map[netip.Addr]failure // malformed strikes per source
	declined map[netip.Addr]failure // declines per source (Decline): not strikes, a window of their own
	auth     map[string]failure     // key: nas + "\x00" + username
	writes   int                    // incremented on every Malformed/Decline/AuthFailure; triggers sweep at sweepEvery
}

func New(c Config, now func() time.Time) *Limiter {
	return &Limiter{cfg: c, now: now, open: map[netip.Addr]int{}, bad: map[netip.Addr]failure{},
		declined: map[netip.Addr]failure{}, auth: map[string]failure{}}
}
```

  Replace `Malformed` and `Holding` with these, and add the three new methods and two helpers:

```go
// Malformed records a malformed packet from src and returns how long to hold
// the connection before closing it: base * 2^(strikes-1), capped. Counts reset
// after MalformedWindow elapses with no new strikes.
func (l *Limiter) Malformed(src netip.Addr) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, l.countLocked(l.bad, src))
}

// Holding reports whether src is inside the backoff its last strike earned:
// port49d refuses such a source at Accept, at once, rather than hold one of
// its connections silent (L28 branch H).
func (l *Limiter) Holding(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inWindowLocked(l.bad, src)
}

// Decline records that port49d declined a packet from src through no fault
// of the source's: admission refuses its device, the device is quarantined,
// or a reload refused or removed it. It opens a window, on the strike's
// schedule, in which the source's next connections are refused at Accept
// before the device writes (spec §10, "A declined source is refused at
// Accept"; §15 L31). It is not a strike: Holding and Malformed never see it.
func (l *Limiter) Decline(src netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.countLocked(l.declined, src)
}

// Declined reports whether src is inside the window its last decline opened.
// The caller refuses the connection only while port49d still declines src,
// and otherwise calls Undecline: a window never outlasts its reason.
func (l *Limiter) Declined(src netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.inWindowLocked(l.declined, src)
}

// Undecline drops src's decline window and count, for a source port49d no
// longer declines: a reload admitted it again, or its quarantine ended.
func (l *Limiter) Undecline(src netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.declined, src)
}

// countLocked counts one more event from src in m and returns the count,
// which starts over once MalformedWindow has passed with none.
func (l *Limiter) countLocked(m map[netip.Addr]failure, src netip.Addr) int {
	f := m[src]
	now := l.now()
	if l.cfg.MalformedWindow > 0 && now.Sub(f.last) > l.cfg.MalformedWindow {
		f.count = 0
	}
	f.count++
	f.last = now
	m[src] = f
	l.writes++
	if l.writes%1024 == 0 {
		l.sweepLocked(now)
	}
	return f.count
}

// inWindowLocked reports whether src's last event in m is younger than the
// backoff its count earns.
func (l *Limiter) inWindowLocked(m map[netip.Addr]failure, src netip.Addr) bool {
	f, ok := m[src]
	if !ok || f.count == 0 {
		return false
	}
	return l.now().Before(f.last.Add(backoff(l.cfg.MalformedBackoffBase, l.cfg.MalformedBackoffMax, f.count)))
}
```

  In `sweepLocked`, sweep both source maps:

```go
	// Delete malformed-strike and decline entries older than MalformedWindow.
	if l.cfg.MalformedWindow > 0 {
		for _, m := range []map[netip.Addr]failure{l.bad, l.declined} {
			for src, f := range m {
				if now.Sub(f.last) > l.cfg.MalformedWindow {
					delete(m, src)
				}
			}
		}
	}
```

- [ ] **Step 4: Run the tests.** `go test ./internal/daemon/limits/ -count=1 -race`. Expected: PASS,
  including the unchanged `TestMalformedBackoffGrowsAndCaps`.

- [ ] **Step 5: Commit.**

```bash
git add internal/daemon/limits
git commit -m "feat(limits): a decline window, on the strike's schedule and not a strike

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 3: An unadmitted source is closed as a key miss is

**Files:**
- Modify: `internal/daemon/server/conn.go:228-240` (the `!s.admitted` block), plus a new method
  beside `keyMiss` (`:177-186`)
- Modify: `internal/daemon/metrics/metrics.go:24-25` (the `unadmitted_source` description)
- Test: `internal/daemon/server/server_test.go`

**Interfaces:**
- Consumes: `Limiter.Malformed`, `Limiter.Holding` (unchanged), and `reset(net.Conn)`
  (`conn.go:171`).
- Produces: `func (s *conn) unadmitted(h wire.Header)`, and a test helper
  `func refusedAtAccept(t *testing.T, d *net.Dialer, addr string)` that Task 4 uses.

- [ ] **Step 1: Write the failing test.** Add to `server_test.go`, after
  `TestUnadmittedSourceIsRecordedAndClosed`:

```go
// refusedAtAccept dials addr from d and asserts the connection is reset
// before anything is written on it, which is what a refusal at Accept looks
// like. On loopback that reset can reach the client before connect()
// returns, so the dial itself may fail with it (final review Minor 8). Nothing
// is sent, so nothing can be read or recorded.
func refusedAtAccept(t *testing.T, d *net.Dialer, addr string) {
	t.Helper()
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("want the connection refused at Accept with a reset, got %v", err)
		}
		return
	}
	t.Cleanup(func() { conn.Close() })
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the connection refused at Accept with a reset, got %d bytes, %v", n, err)
	}
}

// An unadmitted source is closed as a key miss is (L28 branch H; spec §15
// L31). It gets the record, a strike, and a reset at once, and is never held
// for the backoff. Its next connection is refused at Accept, before it
// writes: with single-connection on, IOS-XE and NX-OS wait out their 5 s
// timeout after a reset that follows their request.
func TestAnUnadmittedSourceIsResetAtOnceAndRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) { d.Limits = slowBackoff() })
	// 127.0.0.2 is loopback but not in the inventory.
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}
	conn, err := d.Dial("tcp", ts.addr)
	if err != nil {
		t.Skipf("cannot source from 127.0.0.2 on this host: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	c := &client{conn: conn, key: []byte("k2"), sid: 7, seq: 1}
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	began := time.Now()
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want a reset, got %v", err)
	}
	if held := time.Since(began); held > 500*time.Millisecond {
		t.Fatalf("the connection was held %s before the reset: an unadmitted source is not held for the backoff", held)
	}
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"unadmitted_source"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	refusedAtAccept(t, d, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 1 {
		t.Fatalf("held_refused = %v: the strike did not refuse the next connection at Accept", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("unadmitted_source")); n != 1 {
		t.Fatalf("unadmitted_source = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("unadmitted_source")); n != 1 {
		t.Fatalf("unvalidated{unadmitted_source} = %v: the connection refused at Accept left a record", n)
	}
}
```

- [ ] **Step 2: Run it to see it fail.**
  `go test ./internal/daemon/server/ -run TestAnUnadmittedSourceIsResetAtOnceAndRefusedAtAccept -count=1`.
  Expected: FAIL. Either `want a reset, got i/o timeout` (the 5 s hold outlasts the 2 s read
  deadline), or `held_refused = 0`.

- [ ] **Step 3: Implement.** In `conn.go`, add after `keyMiss`:

```go
// unadmitted closes a connection from a source the inventory does not name
// the way keyMiss closes a key miss (L28 branch H): the record, a strike, and
// a reset at once, never a hold for the backoff. The strike's backoff then
// refuses the source's next connections at Accept, before the device writes.
// With single-connection on, IOS-XE and NX-OS wait out their 5 s timeout
// after a reset that follows their request, and fall to their local method at
// once after one that comes before it (spec §15 L31).
func (s *conn) unadmitted(h wire.Header) {
	s.unvalidated(h, nil, keyring.DiagUnadmittedSource, 0)
	s.d.Limits.Malformed(s.src)
	reset(s.c)
	s.d.Metrics.ConnectionEvents.WithLabelValues("unadmitted_source").Inc()
}
```

  In `serve`, replace

```go
			s.unvalidated(h, nil, keyring.DiagUnadmittedSource, 0)
			s.backoff(ctx, "unadmitted_source")
			return
```

  with

```go
			s.unadmitted(h)
			return
```

  In `backoff`'s doc comment, delete the sentence about callers passing a diagnosis for an
  unadmitted source ("callers pass a diagnosis distinct from … in metrics."), since no caller does
  that now. The comment becomes: "event is the ConnectionEvents label."

  In `metrics.go`'s event list, change `(a strike from an address not in the inventory)` to
  `(a strike from an address not in the inventory: recorded and reset at once, L31)`. Change the
  `"held_refused"` entry, `(a source inside the backoff its last strike earned, reset at Accept, L28)`,
  to:

```go
	// "held_refused" (a source inside the backoff its last strike earned,
	// reset at Accept, L28; the strike is a key miss, garbage, or an address
	// the inventory does not name, a removed device's retries included, so
	// the event that opened it says which: "key_miss_closed",
	// "malformed_backoff" or "unadmitted_source"),
```

- [ ] **Step 4: Run the package.** `go test ./internal/daemon/server/ -count=1 -race`. Expected:
  PASS, including `TestUnadmittedSourceIsRecordedAndClosed`.

- [ ] **Step 5: Commit.**

```bash
git add internal/daemon/server internal/daemon/metrics
git commit -m "fix(server): close an unadmitted source as a key miss, refusing its retries at Accept (L31)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 4: Refused, quarantined and reload-declined devices open a decline window, honoured at Accept

**Files:**
- Modify: `internal/daemon/server/conn.go`: `refusedAdmission`'s doc (`:84-90`),
  `admissionWithdrawn` (`:121-135`), the refused branch (`:233-236`), and the quarantine block
  (`:247-264`); add `decline`
- Modify: `internal/daemon/server/server.go:119-135` (Accept), and add `declining`
- Modify: `internal/daemon/metrics/metrics.go` (the event list)
- Test: `internal/daemon/server/server_test.go`

**Interfaces:**
- Consumes: `Limiter.Decline`, `Declined`, `Undecline` (Task 2); `refusedAtAccept` (Task 3).
- Produces: `func (s *conn) decline()`; `func declining(d Deps, dev admission.Resolved, admitted bool) bool`;
  and the connection event `declined_refused`.

- [ ] **Step 1: Write the failing tests.** Add to `server_test.go`, after
  `TestARefusedEntryIsNeverValidatedUnderItsKey`:

```go
// A refused device's first connection is recorded and reset at once, and its
// next connection is refused at Accept, before it writes, with no record and
// no strike (spec §10, "A declined source is refused at Accept"; §15 L31).
func TestARefusedDevicesNextConnectionIsRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	lim := slowBackoff()
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		trie, err := admission.NewTrie([]admission.Resolved{{Device: leaf01,
			Refused: "matches no key group, so no key admits it (spec §10)", Refusal: admission.RefusedNoGroup}})
		if err != nil {
			t.Fatal(err)
		}
		d.Admission = trie
		d.Limits = lim
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the refused device's connection reset, got %v", err)
	}
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("admission_refused")); n != 1 {
		t.Fatalf("unvalidated{admission_refused} = %v: one record, for the first connection only", n)
	}
	if lim.Holding(netip.MustParseAddr("127.0.0.1")) ||
		testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")) != 0 {
		t.Fatal("a refused device took a strike")
	}
}

// The same for a quarantined device.
func TestAQuarantinedDevicesNextConnectionIsRefusedAtAccept(t *testing.T) {
	log := &syncBuffer{}
	now := time.Now()
	pol := quarantinePolicy(t, now.Add(-time.Hour), now.Add(-time.Minute), now.Add(time.Hour))
	lim := slowBackoff()
	ts := newTestServerWith(t, log, memory.New(time.Now), nil, func(d *Deps) {
		d.Quarantined = pol.Quarantined
		d.Limits = lim
	})
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	c.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.conn.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("want the quarantined device's connection reset, got %v", err)
	}
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")); n != 1 {
		t.Fatalf("unvalidated{device_quarantined} = %v: one record, for the first connection only", n)
	}
	if lim.Holding(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("a quarantined device took a strike")
	}
}

// A reload that admits a refused device again serves its next connection at
// once, inside the window its refusal opened: the window never outlasts its
// reason.
func TestAReloadThatAdmitsARefusedDeviceServesItInsideTheWindow(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
		store.Token{ID: "e2e", Secret: []byte("p49_e2e"), Kind: store.KindLogin, Principal: "user:alice@example.com",
			ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	adm := &swapAdmitter{}
	adm.swap(t, admission.Resolved{Device: leaf01, Refused: "matches no key group, so no key admits it (spec §10)",
		Refusal: admission.RefusedNoGroup})
	lim := slowBackoff()
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.Admission = adm
		d.Limits = lim
	})
	start := wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode()
	c := dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	closedAtOnce(t, c)
	if !lim.Declined(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("the refusal opened no decline window")
	}
	adm.swap(t, admission.Resolved{Device: leaf01, KeyRef: "prod_key"})
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, start, 0)
	if _, body := c.recv(t); body == nil {
		t.Fatal("no reply")
	} else if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
		t.Fatalf("the admitted device was not served: %+v", r)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 0 {
		t.Fatalf("declined_refused = %v: an admitted device was refused at Accept", n)
	}
	if lim.Declined(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("the window survived the admission")
	}
}

// A connection accepted while its device was refused, whose packet arrives
// only after a reload admitted the device, is declined on its Accept-time
// snapshot and reopens a window. The next Accept asks again and serves the
// device: a stale connection can never refuse an admitted one.
func TestAStaleRefusedConnectionCannotRefuseTheAdmittedDevice(t *testing.T) {
	log := &syncBuffer{}
	st := memory.New(time.Now)
	for _, id := range []string{"a", "b"} {
		if _, err := st.PutToken(context.Background(), store.TokenKey{NAS: "leaf-01", Username: "alice"},
			store.Token{ID: id, Secret: []byte("p49_" + id), Kind: store.KindLogin, Principal: "user:alice@example.com",
				ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	adm := &swapAdmitter{}
	adm.swap(t, admission.Resolved{Device: leaf01, Refused: "matches no key group, so no key admits it (spec §10)",
		Refusal: admission.RefusedNoGroup})
	lim := slowBackoff()
	ts := newTestServerWith(t, log, st, nil, func(d *Deps) {
		d.Admission = adm
		d.Limits = lim
	})
	login := func(c *client, tok string) {
		c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
			Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte(tok)}.Encode(), 0)
	}
	passes := func(c *client) {
		t.Helper()
		if _, body := c.recv(t); body == nil {
			t.Fatal("no reply")
		} else if r, _ := wire.DecodeAuthenReply(body); r.Status != wire.AuthenStatusPass {
			t.Fatalf("%+v", r)
		}
	}
	src := netip.MustParseAddr("127.0.0.1")

	// Accepted while refused, with nothing sent yet.
	stale := dial(t, ts.addr, []byte("k2"))
	if !waitFor(t, func() bool { return testutil.ToFloat64(ts.metrics.Connections.WithLabelValues("open")) == 1 }) {
		t.Fatal("the stale connection was never accepted")
	}
	adm.swap(t, admission.Resolved{Device: leaf01, KeyRef: "prod_key"})
	fresh := dial(t, ts.addr, []byte("k2"))
	login(fresh, "p49_a")
	passes(fresh)

	// The stale connection's packet is declined on its Accept-time snapshot,
	// and reopens a window. Its token is never read, so p49_b stays unspent.
	login(stale, "p49_b")
	closedAtOnce(t, stale)
	if !waitFor(t, func() bool { return log.contains(`"diagnosis":"admission_refused"`) }) {
		t.Fatalf("log: %s", log.String())
	}
	if !lim.Declined(src) {
		t.Fatal("the stale connection's decline opened no window")
	}
	// Both earlier connections release their per-NAS slots just after their
	// sockets close; wait for one, as TestAQuarantineTakesEffectAtTheExpiryAndEndsWithIt does.
	if !waitFor(t, func() bool {
		release, ok := lim.Acquire(src)
		if ok {
			release()
		}
		return ok
	}) {
		t.Fatal("no per-NAS slot came free")
	}
	third := dial(t, ts.addr, []byte("k2"))
	login(third, "p49_b")
	passes(third)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 0 {
		t.Fatalf("declined_refused = %v: the admitted device was refused at Accept", n)
	}
	if lim.Declined(src) {
		t.Fatal("the reopened window survived the admitted device's next Accept")
	}
}
```

  **Update `TestAQuarantineTakesEffectAtTheExpiryAndEndsWithIt`.** The fresh connection now meets the
  window the held connection's close opened. Replace

```go
	fresh := dial(t, ts.addr, []byte("k2"))
	login(fresh, 3, "p49_b")
	closedAtOnce(t, fresh)
	if !waitFor(t, func() bool {
		return testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")) == 2
	}) {
		t.Fatalf("unvalidated{device_quarantined} = %v", testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")))
	}
```

  with

```go
	// A new connection inside the decline window that close opened is refused
	// at Accept, before it writes, and leaves no record (spec §15 L31).
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if !waitFor(t, func() bool {
		return testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")) == 1
	}) {
		t.Fatalf("unvalidated{device_quarantined} = %v", testutil.ToFloat64(ts.metrics.Unvalidated.WithLabelValues("device_quarantined")))
	}
```

  Change the comment above the per-NAS slot wait from "The two connections just closed hold both of
  the source's per-NAS slots" to "The connections just closed hold the source's per-NAS slots". The
  final `again` connection is served even though the 5 s window is still open, because the
  quarantine has ended. Pin decision 2 by appending after `passes(again)`:

```go
	// The window was still open (5 s) and was dropped because the quarantine
	// ended, not because it expired.
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v after the quarantine ended", n)
	}
	if lim.Declined(netip.MustParseAddr("127.0.0.1")) {
		t.Fatal("the window survived the end of the quarantine")
	}
```

  **Reword `resetWithNoStrike`'s doc comment.** After this task the next connection can be refused
  at Accept by a decline window. Change "and no strike: the next connection from the source is not
  refused at Accept." to "and no strike: the source is not struck. Its next connection may meet a
  decline window, which each caller asserts."

  **Update `TestAReloadThatRefusesTheDeviceResetsItsOpenConnection`.** Replace its tail, from the
  comment `// The next connection is not held for a strike;` to the end of the function, with:

```go
	// The reset opens a decline window, not a strike: the next connection is
	// refused at Accept, before it writes (spec §15 L31), and counted as
	// declined, not held.
	refusedAtAccept(t, &net.Dialer{}, ts.addr)
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 1 {
		t.Fatalf("declined_refused = %v", n)
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("held_refused")); n != 0 {
		t.Fatalf("held_refused = %v: the reload's close struck the source", n)
	}
}
```

  **Extend `TestAReloadThatRemovesTheDeviceResetsItsOpenConnection`** with the same three
  assertions after `resetWithNoStrike(...)`: `refusedAtAccept`, `declined_refused` is 1, and
  `held_refused` is 0.

  **Extend `TestAReloadThatRenamesTheDeviceResetsItsOpenConnection`** after `resetWithNoStrike(...)`.
  A renamed device is still admitted, so it opens no window and its next connection is answered:

```go
	c = dial(t, ts.addr, []byte("k2"))
	c.send(t, wire.TypeAuthen, wire.AuthenStart{Action: wire.AuthenActionLogin, AuthenType: wire.AuthenTypePAP,
		Service: wire.AuthenServiceLogin, User: []byte("alice"), Data: []byte("p49_e2e")}.Encode(), 0)
	if _, body := c.recv(t); body == nil {
		t.Fatal("a renamed device's next connection got no reply")
	}
	if n := testutil.ToFloat64(ts.metrics.ConnectionEvents.WithLabelValues("declined_refused")); n != 0 {
		t.Fatalf("declined_refused = %v: a still-admitted device was declined", n)
	}
```

- [ ] **Step 2: Run them to see them fail.**
  `go test ./internal/daemon/server/ -run 'NextConnectionIsRefusedAtAccept|AdmitsARefusedDevice|StaleRefusedConnection|QuarantineTakesEffect|AReloadThat' -count=1`.
  Expected: FAIL.
  - The refused and quarantined tests fail at `refusedAtAccept`: the next connection is accepted
    and closed by the idle timeout, so the error reads `got 0 bytes, EOF`.
  - The re-admission and stale-connection tests fail with "opened no window".
  - The updated quarantine test fails at `refusedAtAccept` with `EOF`.
  - The refuse and remove reload tests fail the same way.

- [ ] **Step 3: Implement `decline` and use it.** In `conn.go`, add after `unadmitted`:

```go
// decline closes a connection port49d declines through no fault of the
// device's: admission refuses it, it is quarantined, or a reload refused or
// removed it. The close is a key miss's without the strike: a reset at once,
// and a window in which the source's next connections are refused at Accept,
// before the device writes (spec §10, "A declined source is refused at
// Accept"; §15 L31). The caller has written the record. The window is
// opened before the reset, so it is in force by the time the device sees the
// reset.
func (s *conn) decline() {
	s.d.Limits.Decline(s.src)
	reset(s.c)
}
```

  Replace `refusedAdmission`'s doc comment with:

```go
// refusedAdmission records a packet from a device the inventory names and
// admission refuses: no key group admits it, two tie on it, or its key_ref is
// one port49d holds no key for. Nothing is read past the header and there is
// no strike (spec §10); decline closes the connection. The fault is port49's
// configuration, not the device's, so the device falls to its local method at
// once, as for a quarantine; the start line and `port49 policy test` say why.
```

  In `serve`, make the refused branch:

```go
			if s.refused {
				s.refusedAdmission(h)
				s.decline()
				return
			}
```

  Replace the quarantine block's comment and body with:

```go
		// A quarantined device gets silence, not FAIL (spec §10; §13 decision
		// 20): one header read, nothing decrypted, no reply, so the device
		// declares the server dead and falls to its local method exactly as in
		// an outage. A server that stays silent costs the device ~5 s per
		// command on IOS-XE, EOS and NX-OS (tests/lab/results/L4-error-*.md),
		// so the close is a reset at once. With single-connection on, IOS-XE
		// and NX-OS also wait out that timeout after a reset that follows their
		// request, unless the retry is refused at Accept, so the close opens a
		// decline window (spec §15 L31). The device is not suspect, so it takes
		// no strike, and its connections inside the window are counted, not
		// recorded.
		if s.quarantined() {
			s.quarantine(h)
			s.decline()
			return
		}
```

  In `admissionWithdrawn`, replace the final `reset(s.c)` with:

```go
	if diag == keyring.DiagAdmissionWithdrawn {
		// Renamed, re-keyed or re-platformed: still admitted, so its next
		// connection is served and there is nothing to decline.
		reset(s.c)
		return
	}
	s.decline()
```

  and add to its doc comment, before "How a device takes this reset …": "A reload that refused or
  removed the device also opens a decline window (decline), as a refusal does."

- [ ] **Step 4: Honour the window at Accept.** In `server.go`, replace everything from the line
  `d.Metrics.Connections.WithLabelValues("open").Inc()` through the `if cc.admitted { … }` block with:

```go
		// Admitted is Refused == "", never an index hit or a key_ref alone: a
		// refused device is in the index, and is given no key (spec §10).
		dev, found := d.Admission.Lookup(src)
		admitted := found && dev.Refused == ""
		// A source inside a decline window is refused at Accept, before the
		// device writes, but only while port49d still declines it. A reload
		// that admits it again, or the end of its quarantine, drops the
		// window, and this connection is served (spec §10, "A declined source
		// is refused at Accept").
		if d.Limits.Declined(src) {
			if declining(d, dev, admitted) {
				release()
				d.Metrics.ConnectionEvents.WithLabelValues("declined_refused").Inc()
				reset(c)
				c.Close()
				continue
			}
			d.Limits.Undecline(src)
		}
		d.Metrics.Connections.WithLabelValues("open").Inc()

		cc := &conn{d: d, c: c, src: src, dev: dev, admitted: admitted,
			refused: found && dev.Refused != "", sessions: map[uint32]*authen.Session{}}
		if cc.admitted {
			cc.keys = d.Keys[dev.KeyRef]
		}
```

  and add after `Serve`:

```go
// declining reports whether port49d would decline a packet from dev as
// admission and the policy stand now: a source the inventory does not name, a
// device admission refuses, or a quarantined one. It is asked only at an
// Accept inside a decline window.
func declining(d Deps, dev admission.Resolved, admitted bool) bool {
	if !admitted {
		return true
	}
	if d.Quarantined == nil {
		return false
	}
	_, q := d.Quarantined(dev.Device.Name, d.Now())
	return q
}
```

  In `metrics.go`, add to the event list after the `"held_refused"` entry:
  `"declined_refused" (a source inside the decline window a refused or quarantined device, or a
  reload's refusal or removal, opened: reset at Accept while still declined, no strike, L31),`.

- [ ] **Step 5: Run the whole tree.** `make test && make vet`. Expected: exit 0. If a
  `cmd/port49d` test fails because it dials a declined source a second time inside the window,
  that is the spec change working. Make the test assert the refusal at Accept, or wait out
  `limits.malformed_backoff_base` in its config. Never weaken `declining`.

- [ ] **Step 6: Commit.**

```bash
git add internal/daemon/server internal/daemon/metrics
git commit -m "fix(server): refuse a refused or quarantined device's retries at Accept, strike-free (L31)

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 5: The lab test, `TestL31BreakGlass`

**Files:**
- Modify: `tests/lab/l29_shell_test.go` (`timedLogins` → `timeLogins`)
- Create: `tests/lab/l31_test.go`
- Create: `tests/lab/l31_unit_test.go`

**Interfaces:**
- Consumes: L29's harness, unchanged: `eachPlatform`, `l28Phase`, `l28Live`, `l28Reached`,
  `singleConnection`, `l29SingleSet`, `startInventory`, `serviceConfig`, `labSourceFrom`,
  `labInventoryText`, `labPlatformOf`, `l29Edit`, `l29Pin`, `l29RestoreStanding`, `l29Heartbeat`,
  `l29Budget`, `l29Built`, `l29Note` (the NOT A MEASUREMENT banner), `l29Packets`,
  `l29Connections`, `l29FromDevice`, `l29Tally`, `l29Clock`, `capture`, `captureLine`, `mark`,
  `errMark`, `waitForLine`, `drainRecords`, `privateDir`, `writeAtomic`, `oneLine`, `sub`, `str`,
  `labSubnet`; `labpcap.Parse` and `(*File).Decode`.
- Produces: `func (l *lab) timeLogins(t *testing.T) (rows string, bgTook time.Duration, bgOK bool)`;
  `func l31Bar(control time.Duration) time.Duration`;
  `func l31RefusedAtAccept(path, addr string, since time.Time) (int, error)`;
  `func l31SingleConnect(path, addr string, since time.Time) (set, unset int, err error)`.

- [ ] **Step 1: Write the failing unit test.** Create `tests/lab/l31_unit_test.go`. The test's
  working directory is `tests/lab`, so evidence paths are relative:

```go
//go:build lab

package lab

import (
	"testing"
	"time"
)

// The bar a declined phase's break-glass is held to: the same run's rekeyed
// control plus 1.5 s, and never 5 s or more, the devices' own AAA timeout.
func TestL31Bar(t *testing.T) {
	for _, c := range []struct{ control, want time.Duration }{
		{1530 * time.Millisecond, 3030 * time.Millisecond},
		{2600 * time.Millisecond, 4100 * time.Millisecond},
		{4 * time.Second, 5 * time.Second},
	} {
		if got := l31Bar(c.control); got != c.want {
			t.Errorf("l31Bar(%s) = %s, want %s", c.control, got, c.want)
		}
	}
}

// The capture readers, on committed evidence whose answers are known.
// Counted with tcpdump on 2026-09-30, keyed by the device's address and port
// (SYN from the device, RST from port49d, no device payload): the rekeyed
// phase's retries were refused at Accept, 13 connections on NX-OS and 10 on
// IOS-XE, and the refused phase's never were, 0 on both. The 2026-09-30 L29
// captures carry the single-connect flag, and L28's do not
// (tests/lab/results/L31-breakglass-cisco-singleconnection.md).
func TestL31CaptureReaders(t *testing.T) {
	for _, c := range []struct {
		addr, platform string
		rekeyed        int
	}{
		{"172.100.100.31", "cisco_nxos", 13},
		{"172.100.100.41", "cisco_iosxe", 10},
	} {
		rekeyed, err := l31RefusedAtAccept("evidence/L29-reload-rekeyed-"+c.platform+".pcap", c.addr, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		refused, err := l31RefusedAtAccept("evidence/L29-reload-refused-"+c.platform+".pcap", c.addr, time.Time{})
		if err != nil {
			t.Fatal(err)
		}
		if rekeyed != c.rekeyed || refused != 0 {
			t.Errorf("%s refused at Accept: rekeyed %d (tcpdump: %d), refused %d (tcpdump: 0)",
				c.platform, rekeyed, c.rekeyed, refused)
		}
	}
	const nx = "172.100.100.31"
	if set, _, err := l31SingleConnect("evidence/L29-reload-refused-cisco_nxos.pcap", nx, time.Time{}); err != nil || set == 0 {
		t.Fatalf("L29 refused capture: %d packets with the single-connect flag, %v", set, err)
	}
	if set, unset, err := l31SingleConnect("evidence/L28-cisco_nxos.pcap", nx, time.Time{}); err != nil || set != 0 || unset == 0 {
		t.Fatalf("L28 capture: single-connect set on %d, unset on %d, %v", set, unset, err)
	}
}
```

- [ ] **Step 2: Run it to see it fail.** `make lab-unit`. Expected: build failure, `undefined: l31Bar`.

- [ ] **Step 3: `timeLogins`.** In `tests/lab/l29_shell_test.go`, replace `timedLogins` with:

```go
// timedLogins is a token login, and a break-glass login with three `show
// version`, each timed as l28Phase times them, as two table rows.
func (l *lab) timedLogins(t *testing.T) string {
	t.Helper()
	rows, _, _ := l.timeLogins(t)
	return rows
}

// timeLogins is timedLogins plus the break-glass session's time and whether
// it logged in and ran its commands, for a test that holds it to a bar (L31).
func (l *lab) timeLogins(t *testing.T) (rows string, bgTook time.Duration, bgOK bool) {
	t.Helper()
	user, secret := l.nextLogin(t)
	t0 := time.Now()
	tok := "logged in"
	if c, err := l.dial(user, secret, 120*time.Second); err != nil {
		tok = "refused: " + oneLine(err.Error())
	} else {
		c.Close()
	}
	tokTook := time.Since(t0)
	t1 := time.Now()
	bg := "logged in and ran them"
	_, err := l.loginWithin(breakglassUser, breakglassPassword, 60*time.Second, "show version", "show version",
		"show version")
	if err != nil {
		bg = "not observed: " + oneLine(err.Error())
	}
	bgTook = time.Since(t1)
	return fmt.Sprintf("| next token login (`%s`) | %s in %s |\n| break-glass login plus three `show version` | %s in %s |\n",
		user, tok, tokTook.Round(10*time.Millisecond), bg, bgTook.Round(10*time.Millisecond)), bgTook, err == nil
}
```

- [ ] **Step 4: `tests/lab/l31_test.go`.** Create:

```go
//go:build lab

package lab

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/blanketfish/port49/internal/tacacs/wire"
	"github.com/blanketfish/port49/tests/lab/labpcap"
)

const l31Claim = "What break-glass costs on IOS-XE and NX-OS with single-connection on when port49d declines " +
	"the device (removed from the inventory, refused admission, or quarantined), now that the first " +
	"connection is reset at once and the source's next connections are refused at Accept for a short window: " +
	"break-glass login plus three commands, against port49d stopped and a key miss (the rekeyed control), and " +
	"whether the device's retries are refused at Accept before it writes (spec §15 L31)."

// l31Reading says once, in every note, what the records and captures can tell.
const l31Reading = "**Reading the records and the captures.** port49d records the first packet of a connection " +
	"it declines (`unadmitted_source`, `admission_refused` or `device_quarantined`; `no_known_key_matches` in the " +
	"rekeyed control) and resets it at once. A connection from the same source inside the window that close " +
	"opened is reset at Accept, before the device sends anything, and is not recorded: the capture's per-" +
	"connection table reads it as \"reset before the device sent on it (refused at Accept)\". The single-connect " +
	"count reads the flag byte of each TACACS+ header the device sent (0x04 is single-connection on), and no " +
	"body byte, on the connections the device opened after the change. The bar holds each declined phase's " +
	"break-glass to the rekeyed control's time plus 1.5 s, and never 5 s or more: no AAA exchange waited out " +
	"the device's timeout. IOS-XE retries about 100–200 ms after a reset, against a first window of 100 ms, " +
	"so one or two of its first retries may land after the window and be recorded before the doubling catches " +
	"up. The control has the same dynamics. The stopped control is measured before this test sets " +
	"single-connection, as in L29. With nothing listening, the SYN itself is refused, so the flag plays no " +
	"part there.\n\n"

// l31Phase is one way port49d stops serving the device under test, or the
// rekeyed control. diag is the diagnosis of the first recorded packet from
// the device after the change; change makes the change and returns what it
// did, for the note, and the port49d lines that say it is in force.
type l31Phase struct {
	name, diag string
	change     func(t *testing.T, l *lab, li *labInventory, policy string) (did string, wait []string)
}

// l31Result is one phase's section of the note and its break-glass time.
// measured is false when the phase stopped at a premise before its capture
// was read, so atAccept means nothing.
type l31Result struct {
	section, bgCell, tally string
	bg                     time.Duration
	bgOK, measured         bool
	atAccept               int
}

// l31Phases: the rekeyed control first, since the declined phases are held to
// its time; then the three declines L31 measured slow.
func l31Phases(src string) []l31Phase {
	sync := func(phase string) func(*testing.T, *lab, *labInventory, string) (string, []string) {
		return func(t *testing.T, l *lab, li *labInventory, _ string) (string, []string) {
			body, err := l29Edit(src, l.p.node, phase)
			if err != nil {
				t.Fatal(err)
			}
			li.writeSource(t, body)
			return "`port49 inventory sync`:\n\n```\n" + li.sync(t) + "```",
				[]string{"port49d: inventory reloaded (inventory service, bundle"}
		}
	}
	return []l31Phase{
		{"rekeyed", "no_known_key_matches", func(t *testing.T, l *lab, _ *labInventory, policy string) (string, []string) {
			raw, err := os.ReadFile(policy)
			if err != nil {
				t.Fatal(err)
			}
			writeAtomic(t, policy, []byte(l29Pin(string(raw), l.p.node)), 0o600)
			return "port49d's broker.policy_file given `- {match: {name: " + l.p.node + "}, key_ref: lab_key2}`, " +
				"a key the device does not hold (L29's rekeyed phase: a key miss)", []string{"port49d: policy reloaded"}
		}},
		{"removed", "unadmitted_source", sync("removed")},
		{"refused", "admission_refused", sync("refused")},
		{"quarantined", "device_quarantined", func(t *testing.T, l *lab, _ *labInventory, policy string) (string, []string) {
			raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "quarantine-sync", "policy.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			writeAtomic(t, policy, raw, 0o600)
			platform := labPlatformOf(labInventoryText(t), l.p.node)
			return "port49d's broker.policy_file replaced by `tests/lab/quarantine-sync/policy.yaml`, whose probe " +
					"grants quarantine " + l.p.node + "; the service's copy unchanged",
				[]string{"port49d: policy reloaded", "port49d: broker: device " + l.p.node + " (" + platform + ") is quarantined"}
		}},
	}
}

// l31Bar is the bar a declined phase's break-glass is held to: within 1.5 s
// of the same run's rekeyed control, and under 5 s, the device's own AAA
// timeout, so no exchange in the session waited one out.
func l31Bar(control time.Duration) time.Duration {
	return min(control+1500*time.Millisecond, 5*time.Second)
}

// TestL31BreakGlass times break-glass on the device with single-connection
// on, with port49d stopped, then under a key miss (the control), then with
// the device removed, refused and quarantined. It is run on IOS-XE and NX-OS,
// the images L31 measured slow, and on vEOS as a no-regression check.
//
// Every premise is asserted. If single-connection was not set, a change was
// not applied, the path under test recorded nothing, a Cisco device's packets
// lacked the single-connect flag, or the control was itself slow, the run
// fails and its note opens with the NOT A MEASUREMENT banner. A phase whose
// break-glass did not log in, or went over the bar, contradicts the fix: the
// run fails, and the note says the claim did not hold.
func TestL31BreakGlass(t *testing.T) {
	eachPlatform(t, func(t *testing.T, l *lab) {
		cisco := l.p.name == "cisco_iosxe" || l.p.name == "cisco_nxos"
		if !cisco && l.p.name != "arista_eos" {
			t.Skipf("L31 is IOS-XE and NX-OS, with vEOS as the no-regression check; %s is not run", l.p.name)
		}
		pr := l29Heartbeat(t)
		defer pr.end()
		var failed, contradicted []string
		fail := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			failed = append(failed, msg)
			t.Error(msg)
		}
		contradict := func(format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			contradicted = append(contradicted, msg)
			t.Error(msg)
		}
		src := labSourceFrom(t)
		policy := filepath.Join(privateDir(t, "l31-"+l.p.name), "policy.yaml")
		var obs strings.Builder
		fmt.Fprintf(&obs, "%s\n\n", l29Built())
		pr.at(t, "the stopped control")
		l29Budget(t, 10*time.Minute)
		fmt.Fprintf(&obs, "**Control, port49d stopped** (L28's `stopped` phase):\n\n%s", l.l28Phase(t, "stopped", "", ""))
		pr.at(t, "single-connection")
		single := l.singleConnection(t)
		fmt.Fprintf(&obs, "Single-connection: %s.\n\n", single)
		if !l29SingleSet(single) {
			fail("single-connection was not set on the device: L31 is single-connection on, so this run measured nothing")
		}
		li := l.startInventory(t, src, filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
		l29RestoreStanding(t, l)
		obs.WriteString(l31Reading)
		summary := "| phase | break-glass login plus three `show version` | bar | connections refused at Accept " +
			"after the change | records from the device |\n|---|---|---|---|---|\n"
		var control time.Duration
		for _, ph := range l31Phases(src) {
			r := l.l31Run(t, li, src, policy, ph, cisco, pr, fail)
			obs.WriteString(r.section)
			bar := "(the control)"
			switch {
			case ph.name == "rekeyed":
				control = r.bg
				if !r.bgOK || r.bg >= 5*time.Second {
					fail("the rekeyed control's break-glass did not log in under 5 s (%s): there is no fast path in this "+
						"run to hold the declined phases to", r.bgCell)
				}
			case !r.bgOK:
				contradict("%s: break-glass did not log in and run its commands (%s)", ph.name, r.bgCell)
			default:
				b := l31Bar(control)
				bar = b.Round(10 * time.Millisecond).String()
				if r.bg > b || r.bg >= 5*time.Second {
					contradict("%s: break-glass took %s, over the bar of %s (the rekeyed control's %s plus 1.5 s, "+
						"under 5 s)", ph.name, r.bg.Round(10*time.Millisecond), bar, control.Round(10*time.Millisecond))
				}
			}
			// The mechanism, not only the time: L31 asks whether the device's
			// retries are refused at Accept before it writes. Without one, a
			// fast phase would pass for some other reason nobody observed.
			if cisco && r.measured && r.atAccept == 0 {
				if ph.name == "rekeyed" {
					fail("rekeyed: no connection from the device was refused at Accept after the change: the control's " +
						"fast path did not run")
				} else {
					contradict("%s: no connection from the device was refused at Accept after the change (spec §15 L31)",
						ph.name)
				}
			}
			summary += fmt.Sprintf("| %s | %s | %s | %d | %s |\n", ph.name, r.bgCell, bar, r.atAccept, r.tally)
		}
		obs.WriteString("### Summary\n\n" + summary + "\n")
		if len(contradicted) > 0 {
			obs.WriteString("**The claim did not hold here.** The steps ran, and:\n\n")
			for _, m := range contradicted {
				obs.WriteString("- " + m + "\n")
			}
		}
		pr.end()
		l.l29Note(t, "L31", l31Claim, obs.String(), failed)
	})
}

// l31Run runs one phase from the lab source and policy as committed, on a
// freshly started port49d, and returns its section of the note.
func (l *lab) l31Run(t *testing.T, li *labInventory, src, policy string, ph l31Phase, cisco bool,
	pr *l29Progress, fail func(string, ...any)) l31Result {
	t.Helper()
	r := l31Result{bgCell: "not measured", tally: "none"}
	var b strings.Builder
	fmt.Fprintf(&b, "### Phase: %s\n\n", ph.name)
	pr.at(t, "phase %s: restoring the source and the policy", ph.name)
	l29Budget(t, 15*time.Minute)
	raw, err := os.ReadFile(filepath.Join(root, "tests", "lab", "l29", "policy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeAtomic(t, policy, raw, 0o600)
	li.writeSource(t, src)
	if out := li.sync(t); !strings.Contains(out, "published bundle") && !strings.HasPrefix(out, "unchanged:") {
		fail("%s: the sync restoring the lab source neither published it nor found it current: %s", ph.name, oneLine(out))
		r.section = b.String() + "Not measured: the lab source could not be restored.\n\n"
		return r
	}
	stop := l.capture(t, "L31-"+ph.name)
	defer stop()
	pr.at(t, "phase %s: port49d restarted on the service config, probing until the device asks it", ph.name)
	live := l.l28Live(t, l.serviceConfig(t, li, policy))
	fmt.Fprintf(&b, "%s\n\n", live)
	if !l28Reached(live) {
		fail("%s: no probe login reached port49d before the change", ph.name)
		r.section = b.String()
		return r
	}

	pr.at(t, "phase %s: the change", ph.name)
	off, errOff := l.mark(), l.errMark()
	did, waits := ph.change(t, l, li, policy)
	fmt.Fprintf(&b, "The change: %s\n\n", did)
	var applied time.Time
	for _, w := range waits {
		at, ok := l.waitForLine(t, errOff, w, 30*time.Second)
		if !ok {
			fail("%s: port49d did not say %q within 30s of the change: the change under test did not happen", ph.name, w)
			r.section = b.String()
			return r
		}
		applied = at
	}

	pr.at(t, "phase %s: the logins", ph.name)
	rows, bg, bgOK := l.timeLogins(t)
	r.bg, r.bgOK = bg, bgOK
	r.bgCell = "not observed in " + bg.Round(10*time.Millisecond).String()
	if bgOK {
		r.bgCell = "logged in and ran them in " + bg.Round(10*time.Millisecond).String()
	}
	recs := l29FromDevice(l.drainRecords(off, 10*time.Second), l.p.addr)
	r.tally = l29Tally(recs)
	if !l31Recorded(recs, ph.diag) {
		fail("%s: no record from the device with diagnosis %s after the change: the path under test did not run",
			ph.name, ph.diag)
	}

	// captureLine probes the live capture to flush it; stop() flushes again
	// and ends tcpdump. Only then is the file read, so no count comes from a
	// half-written tail.
	capLine := l.captureLine(t)
	stop()
	conns, _, _ := l29Connections(l.capAbs, l.p.addr, applied)
	if r.atAccept, err = l31RefusedAtAccept(l.capAbs, l.p.addr, applied); err != nil {
		fail("%s: the capture could not be read: %v", ph.name, err)
	}
	set, unset, err := l31SingleConnect(l.capAbs, l.p.addr, applied)
	switch {
	case err != nil:
		fail("%s: the capture's TACACS+ headers could not be read: %v", ph.name, err)
	case cisco && set == 0:
		fail("%s: no TACACS+ packet the device sent after the change carried the single-connect flag (0x04; %d "+
			"without it): this phase did not measure L31's variable", ph.name, unset)
	}
	r.measured = true
	fmt.Fprintf(&b, "port49d said the change was in force by %s (host UTC).\n\n| step | outcome |\n|---|---|\n%s\n",
		l29Clock(applied), rows)
	fmt.Fprintf(&b, "TACACS+ headers the device sent after the change: single-connect flag (0x04) set on %d, clear on "+
		"%d.\n\nRecords from the device since the change: %s\n\nConnections from the device refused at Accept since "+
		"the change: %d.\n\nConnections between the device and port 49 in this phase's capture:\n\n%s\nCapture: %s\n\n",
		set, unset, r.tally, r.atAccept, conns, capLine)
	r.section = b.String()
	return r
}

// l31Recorded reports whether any record carries an unvalidated diagnosis diag.
func l31Recorded(recs []map[string]any, diag string) bool {
	for _, r := range recs {
		if str(sub(r, "unvalidated"), "diagnosis") == diag {
			return true
		}
	}
	return false
}

// l31RefusedAtAccept counts the connections from addr to port 49 opened at or
// after since that port49d reset before the device sent anything on them,
// which is what a refusal at Accept looks like. It reads TCP flags and
// payload lengths only. `tcpdump -i any` sees each packet more than once,
// which the per-port flags absorb.
func l31RefusedAtAccept(path, addr string, since time.Time) (int, error) {
	pkts, err := l29Packets(path, addr)
	if err != nil {
		return 0, err
	}
	type conn struct{ syn, sent, rst bool }
	conns := map[uint16]*conn{}
	for _, p := range pkts {
		c := conns[p.port]
		if c == nil {
			c = &conn{}
			conns[p.port] = c
		}
		switch {
		case p.fromDevice && p.fl.SYN() && !p.at.Before(since):
			c.syn = true
		case p.fromDevice && p.fl.PayloadLen > 0:
			c.sent = true
		case !p.fromDevice && p.fl.Flags&0x04 != 0:
			c.rst = true
		}
	}
	n := 0
	for _, c := range conns {
		if c.syn && c.rst && !c.sent {
			n++
		}
	}
	return n, nil
}

// l31SingleConnect counts the TACACS+ packets the device sent in the capture
// at path, on connections it opened at or after since, by whether the
// header's single-connect flag (0x04) is set. That flag is the device-side
// variable L31 turns on. Only the 12-byte cleartext header is used: the
// decode is given no key, so no body is readable, and nothing from a body is
// kept or printed. A connection is known by the device's port, as in
// l31RefusedAtAccept.
func l31SingleConnect(path, addr string, since time.Time) (set, unset int, err error) {
	pkts, err := l29Packets(path, addr)
	if err != nil {
		return 0, 0, err
	}
	opened := map[uint16]bool{}
	for _, p := range pkts {
		if p.fromDevice && p.fl.SYN() && !p.at.Before(since) {
			opened[p.port] = true
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	f, err := labpcap.Parse(raw)
	if err != nil {
		return 0, 0, fmt.Errorf("%s: %w", path, err)
	}
	_, subnet, err := net.ParseCIDR(labSubnet)
	if err != nil {
		return 0, 0, err
	}
	d, err := f.Decode("", subnet)
	if err != nil {
		return 0, 0, err
	}
	for _, p := range d.Packets {
		if !p.FromDevice || !strings.HasPrefix(p.Conn, addr+":") || !opened[p.SrcPort] {
			continue
		}
		if p.Header.Flags&wire.FlagSingleConnect != 0 {
			set++
		} else {
			unset++
		}
	}
	return set, unset, nil
}
```

- [ ] **Step 5: Build and run the pure parts.**
  `make build && make lab-unit && go vet -tags lab ./tests/lab/`. Expected: PASS, including
  `TestL31Bar`, `TestL31CaptureReaders`, and every L29 unit test (`timedLogins`' callers are
  unchanged). If `TestL31CaptureReaders`' counts differ from the tcpdump figures in its comment, the
  reader is wrong. Fix the reader, not the bounds.

- [ ] **Step 6: Commit.**

```bash
git add tests/lab/l29_shell_test.go tests/lab/l31_test.go tests/lab/l31_unit_test.go
git commit -m "test(lab): TestL31BreakGlass, break-glass on a declined device against the rekeyed control

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 6: (lab, on beehive) Run L31 on NX-OS, IOS-XE and vEOS from a pinned worktree

**Files:**
- Create (by the runs): `tests/lab/results/L31-cisco_nxos.md`, `L31-cisco_iosxe.md`,
  `L31-arista_eos.md`; `tests/lab/evidence/L31-<phase>-<platform>.pcap`

**Interfaces:**
- Consumes: Tasks 3–5 as committed on `fix/breakglass-reset`.

The lab host holds one containerlab run at a time, and the owner has given standing consent for lab
runs. Follow plan 6b's "Running the lab" exactly. Run one platform per `go test`, with the harness's
boot budgets. The controller runs plan 5b's stall watchdog for the whole of each run: `STALL=25`
minutes (40 on the N9Kv), with `LOG`, `PID` and `TOPO` set for the run and
`pkill -f bin/port49-inventory` in its cleanup. Re-arm the watchdog on every wake. A "waiting"
notice proves nothing.

- [ ] **Step 1: Pin a detached worktree at the branch head.** The run never builds in the worktree
  a code task is editing, so a half-edited `bin/port49d` can never be measured:

```bash
cd ~/git/port49
SHA=$(git -C .worktrees/breakglass-reset rev-parse HEAD)
git worktree add --detach .worktrees/l31-lab "$SHA"
cd .worktrees/l31-lab && mkdir -p tests/lab/logs && make build && make lab-unit
```

  Expected: both succeed. The notes' `l29Built` line will name `$SHA`. `tests/lab/logs/` is
  git-ignored, so a fresh worktree does not have it. Without the `mkdir`, the run's log redirect
  fails before `go test` starts.

- [ ] **Step 2: Run one platform per command, NX-OS first, then IOS-XE, then vEOS.** For each `p` in
  `nxos`, `iosxe` and `eos`, in turn:

```bash
cd ~/git/port49/.worktrees/l31-lab
export PORT49_LAB_KEY=labsecret
PORT49_LAB_PLATFORMS=$p go test -tags lab ./tests/lab/ -run '^TestL31BreakGlass$' \
  -count=1 -v -timeout 120m > tests/lab/logs/l31-$p.log 2>&1 &
echo $!   # the watchdog's PID for this run; LOG is tests/lab/logs/l31-$p.log
```

  Arm the watchdog for this run's `PID` and `LOG` (and its `TOPO`) before waiting, and re-arm it on
  every wake. When the run ends:
  - run `make evidence`;
  - confirm no `port49d` holds `172.100.100.1:49`;
  - confirm `pgrep -f bin/port49-inventory` is empty;
  - confirm the topology is destroyed.

  Only then start the next platform.

  How to read each note:
  - **A premise banner at the top.** The run measured nothing. Fix the harness or the lab and
    re-run it; never read it as an answer.
  - **"The claim did not hold here".** This is a measurement, and the fix missed: either the bar,
    or the Cisco refusal at Accept. Stop and debug it with superpowers:systematic-debugging from
    the phase's capture and connection table. Change the fix on the branch, with a test, then
    re-pin and re-run.
  - **The Cisco notes** gate L31. The row stays open until both pass.
  - **The vEOS note** is the no-regression check. A banner or "claim did not hold" there blocks
    the merge the same way.

- [ ] **Step 3: Bring the results onto the branch, and keep the raw captures.** Copy the three notes
  and `tests/lab/evidence/L31-*.pcap` from `.worktrees/l31-lab` into `.worktrees/breakglass-reset`.
  Copy the raw `tests/lab/captures/L31-*.pcap` into the **main checkout's** `tests/lab/captures/`,
  or the labpcap audit fails. Then `git worktree remove .worktrees/l31-lab`.

- [ ] **Step 4: Commit on the branch,** after `make test && make vet` (expected: exit 0):

```bash
git add tests/lab/results/L31-cisco_nxos.md tests/lab/results/L31-cisco_iosxe.md \
  tests/lab/results/L31-arista_eos.md tests/lab/evidence/L31-*.pcap
git commit -m "test(lab): L31 measured on NX-OS, IOS-XE and vEOS with single-connection on

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

### Task 7: Close L31, and write the fix as built

**Files:**
- Modify: `docs/design/2026-08-23-policy-engine-spec.md` (§15 L31 row and its notes paragraph;
  the two "L31's (open)" sentences Task 1 wrote in §10)
- Modify: `docs/superpowers/plans/README.md`

- [ ] **Step 1: Close the row** (lab register rule 3), only if `L31-cisco_iosxe.md` and
  `L31-cisco_nxos.md` both exist with no banner and no "claim did not hold", and `L31-arista_eos.md`
  has neither either (the no-regression check, Task 6).
  - **Status:** set it to `closed — measured <date>; tests/lab/results/L31-cisco_iosxe.md,
    L31-cisco_nxos.md`, followed by a one-line reading. The reading gives break-glass removed,
    refused and quarantined against the rekeyed control and port49d stopped, per image, taken from
    the notes' summary tables.
  - **History:** keep the observed-before numbers and `L31-breakglass-cisco-singleconnection.md` in
    the row.
  - **Measured paragraph:** under the register's L31 notes paragraph, add a "Measured <date>"
    paragraph with:
    - the images and versions;
    - the single-connect flag counts;
    - connections refused at Accept per phase;
    - the records the declined phases left, against their connections;
    - vEOS's times, beside its 0.32–2.1 s from `L29-reload-arista_eos.md` and
      `quarantine-sync-arista_eos.md`.
  - **Pre-fix sentences:** mark the ones that now read as current "(before fix/breakglass-reset)":
    - in the L29 register notes, "those paths never refuse the retries at Accept" (about line 7921);
    - L31's own "Until the fix, a Cisco device with single-connection on takes 16–21 s …" (about
      line 7980).
  - **§10:** in the quarantine paragraph and the reload paragraph, replace "is L31's (open)" and
    "§15 L31, open" with the measured times, citing the notes. If a note contradicts a doc, the doc
    is wrong (rule 4): fix it, cite the note, and say so in the commit message.

  Commit the closing on its own (rule 3):

```bash
git add docs/design
git commit -m "docs: close lab register entry L31 as measured

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

  If L31 did not close, commit instead `docs: record L31's measurement` with the paragraph for what
  was measured, and the branch does not merge until the row closes.

- [ ] **Step 2: The roadmap.** In the "Fix `fix/breakglass-reset`" bullet, write "executed <date>"
  and what shipped where it differs from this plan. Add a short "### Fix `fix/breakglass-reset` —
  As built" section after "Plan 6b — As built": the tasks, the rows closed, and anything carried.
  Update the status line at the top to say 6c is next.

```bash
git add docs/superpowers/plans/README.md
git commit -m "docs: fix/breakglass-reset as built

Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>"
```

---

## Operator-facing notes (for the pull request body)

- **Break-glass is fast again on a Cisco device port49d stops serving.** With `single-connection`
  on, IOS-XE and NX-OS took 16–41 s per break-glass session when port49d had removed, refused or
  quarantined the device. Measured after the fix: <from the L31 notes>. vEOS and Junos were not
  affected before and are not now.
- **What changed on the wire.** port49d still records a declined device's packet and resets that
  connection at once, with no reply. What is new: for a short window afterwards, the device's next
  connections are reset at Accept, before the device sends anything. The window is 100 ms,
  doubling to 5 s, using the existing `limits.malformed_backoff_base`/`_max`/`_window` settings.
  There is no new setting.
- **Fewer records, same counts.** The connections refused inside a window write no `unvalidated`
  record. Count them with `port49_connection_events_total{event="declined_refused"}` (new, no device
  label). A declined device now logs about one record per window instead of one per connection.
  Read the two events this way:
  - `declined_refused` is a device port49d declines (refused or quarantined), or a removed device
    in the one window after its removal ended an open connection.
  - `held_refused` is a strike's backoff. After that first window, a removed device that still
    polls lands here too.
  - The event that opened a strike says which kind it is: `unadmitted_source` for an address the
    inventory does not name (a decommissioned switch still polling), `key_miss_closed` for a key,
    `malformed_backoff` for garbage.
  - The records name the device; the counters have no device label.
- **Fixes take effect at once.** The window lasts only while port49d still declines the device. A
  reload that admits it again, or a quarantine ending, serves its next connection with no wait.
- **An unknown source is no longer held.** A connection from an address not in the inventory is
  recorded, struck and reset at once. It used to be held open 0.1–5 s first.
- **A removed device you add back.** Before, only the connection in flight was held for the
  backoff. Now its next connections are refused at Accept for up to its last strike's backoff (5 s
  at most by default), and then it is served. A strike is not re-checked against admission, so
  allow those seconds after the reload.
- **Nothing is admitted or answered that was not before.** The window only refuses connections
  port49d would refuse anyway.

## Self-review against the spec

- Spec §10 "A quarantined device gets silence, not FAIL": the reply stays silence and the close
  stays a reset. The window is Task 4, and the text is Task 1 Step 3.
- "A device is refused on its own": still no strike, still `admission_refused`, and the window is
  added (Task 1 Step 2, Task 4).
- "A key miss is closed at once": the unadmitted source's strike already refused at Accept, and its
  close is now at once (Task 3).
- "How a daemon refreshes its snapshot": no strike on a reload's close. A refusal or removal opens
  the window, and a rename, re-key or re-platform does not (Task 4, decision 4).
- §5.7: no reason code or diagnosis added. The records use `unadmitted_source`, `admission_refused`,
  `device_quarantined` and `device_unknown`, as today.
- §14: the new bullet (Task 1 Step 5) is asserted by the Task 3 and Task 4 tests, including the
  stale-connection case (a connection accepted while refused cannot refuse the re-admitted device).
- §15 L31: measured by Task 6 and closed by Task 7 under rules 1–4. L28 and L29 stay closed as
  measured.
- No device label on `declined_refused`, and no body read on any path touched.
