# The etcd feeds' two legs never share a member while another is coming up (#64) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The context feed's and the marks feed's two watch legs are never placed on one etcd member while another member's connection is up or still being made. One hung member then never stalls a feed, from the first second of a watch.

**Architecture:** The fix is in the picker (`internal/store/etcd/balancer.go`). `hedgeCC.UpdateState` already reads every child's state and keeps only the ready ones. It now also counts the children still connecting (or idle, about to connect). When a leg's only choice is its peer's member and another child is still connecting, `placed` refuses the pick, and `Pick` returns `balancer.ErrNoSubConnAvailable`. gRPC holds the stream and picks again with the next picker, which arrives when that member is ready (the leg goes there) or has failed (the legs share, as today). `watchLegs`, its stall reopen and its relocation are unchanged. No new metric, log line, reason code, warning or config key. No lab run.

**Tech Stack:** Go 1.26, `go.etcd.io/etcd/client/v3` v3.6.15, `google.golang.org/grpc` v1.83.2 (`go.mod:17,23`), embedded etcd behind TCP proxies (`internal/store/etcd/etcdtest`), MkDocs checks in `go test ./tests/ci/`.

**Issue:** #64 (CI run 42563304174 on PR #63, `TestAContextFeedFollowsWhicheverMemberGoesDark`).

## Root cause (investigation 2026-11-09, `main` `1ace8f55`)

1. **The second leg takes the first leg's member when that member is the only one ready.**
   - The legs' openings are serialized: `clientLegs.open` holds `openMu` until the pick has recorded a member (`twoleg.go:378-419`), and leg 1's tried-set gets leg 0's as its peer before the pick (`twoleg.go:397-405`). The issue's first hypothesis, that leg 0 is placed before leg 1's choice is visible, is not the cause. Leg 0 opens first and has nothing to avoid by design. The trace shows leg 1 *did* see leg 0's member ("the other on 127.0.0.1:37265").
   - `hedgeCC.UpdateState` (`balancer.go:103-117`) builds the picker from the `Ready` children only. A child still `Connecting` is dropped, and with it the fact that a second member is milliseconds away.
   - `picker.placed` (`balancer.go:246-291`) then finds no ready member other than the peer's. Both fallbacks (`:269-284`) skip the peer's address, so it reaches `:285-290` ("begin again") and returns the peer's member. The comment at `:243-245` and `TestTheSecondLegSharesTheOnlyReadyMember` (`balancer_test.go:243-255`) record this as intended: "a pick never blocks".
   - In CI, the watch started 10 ms after the store opened. Only 37265's connection was ready, so both legs went there. On main the other two connections are usually ready first, which is why 10 runs passed.
2. **The legs did not "reopen together".** The `+502ms ... together on 127.0.0.1:37265` line is `check` (`twoleg.go:208-239`) finding the pair on the first tick (`feedIdle/2` = 500 ms), not a reopen. `check` then waits `relocateMin` (2 s, `twoleg.go:51`) before it moves leg 1. Member 0 was hung at +69 ms, so the feed was silent until the first of:
   - the stall reopen: each leg quiet for `feedStall` (2 s, `twoleg.go:41`) since its last response, seen on a 500 ms tick, then a probe read of up to `feedStall/2` (`twoleg.go:316-332`);
   - the relocation at +2.5 s.

   Both put a leg on another member, because each reopen avoids the leg's own last member (`twoleg.go:394-396`) and the peer's (`balancer.go:248-251`). The change written at +76 ms arrives about 2.1 to 3.5 s after the hang. The test allows 1.5 s.
3. **What an operator sees while the shared member is hung.** This is not the CI test's artificial case. It happens whenever a watch starts while one connection is up before the others: a port49d start, a rescan after a compaction, or both legs failing at once.
   - No change is lost. Each reopened leg replays from `through+1` (`twoleg.go:142`). The feed lags 2.0 to 3.5 s.
   - A login whose context was written in that window waits on the fence (`internal/store/crypt/fence.go:110-140`) for `call_timeout`, then is denied `store_unavailable`. That shows as `port49_store_calls_total{outcome="feed_behind"}` and `port49_store_fence_timeouts_total` (`guard.go:440-444`, `port49d/store.go:143`). A health check whose read meets a revision the feed has not reached fails too. Two or three failures stay below `close_after` (default 5), so the listeners stay open.
   - A revocation on the marks feed waits just as long if the marks legs share the member, since they use the same `followLegs` (`feed.go:236`).
   - **`context_stale` is not reached.** The issue suggests it may be, but that reason means `now - refreshed_at` beyond `session.staleness_ceiling` (default 4 h; spec §5.1.1 at `:560-567`, §5.7 at `:2716`). A feed lag of seconds never moves `refreshed_at`.
   - Logs, in order: `etcd: both legs of the contexts watch are on one member (<address>): ...` (only if a tick saw them first), then `etcd: a leg of a watch heard nothing for 2s while the store answers; it is opened again on another member` twice, then `etcd: the legs of the contexts watch are on different members again`. `port49_store_feed_legs_colocated{feed="contexts"}` goes 1, then 0.

## Rulings made in this plan

1. **A structural rule in the picker, not a retry or a sooner relocation.**
   - A leg never takes its peer's member while another child of the channel is `Connecting` or `Idle`. It waits for the next picker.
   - The other options lose:
     - Moving apart sooner (`relocateMin` lower, or a first move at detection) still shares a member for a tick, so it is a race.
     - Waiting for two ready connections before a watch starts is a timeout guess.
     - Pinning each leg to its own client (one `clientv3.Client` per endpoint) adds N clients per process, each with its own TLS, keepalives and auth, and leaves port49 to reimplement the balancer's failover.
   - The API is `balancer.ErrNoSubConnAvailable` (`google.golang.org/grpc@v1.83.2/balancer/balancer.go:266-268`): "gRPC will block the RPC until a new picker is available via UpdateState()" (`:318-323`). `picker_wrapper.go:159-160` continues the pick loop on it whatever failfast is.
   - `endpointsharding` sends `UpdateState` on every child change (`endpointsharding.go:255-285`). `pickfirst` keeps a failed child in sticky `TransientFailure` until it is ready again (gRFC A62, `pickfirst.go:161`). So the wait ends at most when the member's connection attempt ends. gRPC's minimum connect timeout is 20 s (`clientconn.go:61`), and clientv3 does not change it (`client.go:326-329`).
2. **Every other member failed: the legs share, as today.** This covers a cluster where only one member is reachable from this process, with quorum through the others. `port49_store_feed_legs_colocated` is 1, the log names the member, and `check` moves a leg once another member is ready (2 s doubling to 30 s, unchanged). The 10 m ticket is unchanged (design §15 `:2084-2086`, `docs/site/reference/alerts.md:443-455`).
3. **One endpoint: unchanged.** With one endpoint the channel has one child, so nothing is ever pending and the wait never applies. `watchLegs` gets `single` (`twoleg.go:474`): the legs share, are never moved, the gauge stays 0, and one line is logged at the watch's start (`twoleg.go:129-131`, `TestOneEndpointNeverRelocatesOrReportsColocation`). Spec §13 decision 37 says nothing about one endpoint. This plan adds one clause stating it (Task 3).
4. **What a waiting leg looks like.** A leg waiting for a member has no member (`member(i) == ""`). So `check` returns early (`twoleg.go:216-219`) and the gauge does not count it as together. The stall reopen skips it (`:316`), and no progress request is sent on it (`:250`, `:333`). The other leg carries the feed. That is the same redundancy as sharing, for at most one connect attempt.
   - Example: a member blackholed at port49d start keeps leg 1 waiting up to 20 s. Then it is `TransientFailure` and the legs share, with the gauge and the log, as in Ruling 2.
   - No new log line or metric. The wait is bounded and shows up as the colocation line when it ends that way.
5. **Only a leg waits.** A hedged call's copies (`withTried`) have no peer, so `avoid == ""` and they never reach the wait. The same holds for a plain call and for a leg whose peer is not placed yet. Hedging and the suspect rules are unchanged.
6. **The tests force the shape; they do not hunt the flake.** Two proxies are hung before the store dials. Their connections then stay `Connecting` (gRPC waits for the server's handshake), while member 0 is ready. On today's code, leg 1 lands on member 0 every time, within milliseconds. The `-count=20` runs in Task 4 check that the fix adds no new flake. They do not prove the fix: at the issue's rate (1 in 11), 20 green runs happen by chance about 15 % of the time. Task 1's test is the proof.
7. **No lab run.** No device behavior changes, and no §15 row changes status. Kind runs only in CI.
8. **The roadmap (`docs/superpowers/plans/README.md`) is the lead's to update when this merges.** The brief limits this plan to one file.

## What an operator sees at 3am

| Event | Before | After |
|---|---|---|
| port49d starts, one etcd connection up 10 ms before the others, then that member hangs | Both legs of the contexts (and marks) watch on it; feed silent 2.0 to 3.5 s; logins on contexts written then denied `store_unavailable`, `feed_behind` and fence timeouts counted; colocation log line and gauge 1 for about 2 s | Leg 1 waits milliseconds for the second member; the hang costs nothing; no colocation line |
| One member of three hung, legs apart | The leg on it reopens on the third member within about 2.5 s; the feed follows on the other leg throughout | Unchanged (Task 2 asserts it for each leg) |
| Only one member reachable from this node, quorum held through the others | Legs share it; gauge 1; ticket at 10 m | Unchanged, once the other connections have failed (at most 20 s after start) |
| One endpoint configured | Legs share; never moved; gauge 0; one log line at start | Unchanged |
| Every member dark (no quorum) | Legs left alone, revive with the store | Unchanged |

## Global Constraints

- Go 1.26+, `gofmt` and `go vet` clean, no cgo, module `github.com/blanketfish/port49`. Match the package's comment style: full sentences, the reason and the CI run or issue cited.
- snake_case for data. No reason code (spec §5.7), warning (§12), config key, metric or log line is added. No device identity anywhere. A test trace holds members and revisions only, never a key or a value (`twoleg.go:366-368`).
- **Security rules, repeated in every implementer brief:**
  - Never read `*.env`, `*-key.pem`, `*.keytab`, `realm.json`, or key files.
  - Every recursive grep excludes them. grep is ugrep: use `-e PATTERN`, never `--` before a pattern. Never grep `tests/lab/logs` or `tests/lab/captures`.
  - If a safety check refuses a command, stop and report it. Never rephrase it.
  - Edit repo files with the Edit/Write tools, never sed, perl, python or heredocs.
- **Tests:**
  - On this host `/tmp` is tmpfs. `TMPDIR` is one short private directory on ext4 under `~/.cache`: `export TMPDIR=$(mktemp -d ~/.cache/p64.XXXX) && chmod 700 $TMPDIR`. The host has `acl`.
  - Implementers run tests in the foreground only, at most 600000 ms per call. Use a focused, anchored `-run` on `./internal/store/etcd/`. The lead runs full packages.
  - Docs edits add `go test ./tests/ci/ -count=1`.
  - A failure this plan does not name is reported, not fixed in passing.
- **Commits:**
  - Conventional Commits, one per task, with an explicit pathspec.
  - Every message ends with `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>` and nothing else. No `Claude-Session:` line, and no claude.ai URL anywhere: commits, PR body, comments.
- **Branch:** `fix/etcd-feed-64`, from `main` `1ace8f55`, in `.worktrees/etcd-feed-64`. Tasks run in order.
- **Lab:** none (Ruling 7).

## Review Focus

1. **The wait is reached only by a leg whose peer holds the only ready member.** `avoid != ""`, and every ready address equals `avoid`, at the point the wait is added. A hedged copy, a plain call, and a leg whose peer is unplaced never wait (Ruling 5, Task 1's unit test).
2. **The wait always ends.** It returns only `ErrNoSubConnAvailable`, never an error that ends the stream. `pending` counts only `Connecting` and `Idle`, never `TransientFailure` or `Shutdown`. Trace one member blackholed at start, and one member whose connection keepalive kills, until the next picker.
3. **A waiting leg changes nothing in `watchLegs`.** No stall reopen, no progress request, no colocation flip while `member(i) == ""` (Ruling 4).
4. **The red test is red by placement, not timing.** On today's code it fails at the "leg 1 was placed ..." assertion, not at the delivery check.

---

### Task 1: a leg waits for a member still connecting rather than share its peer's (Rulings 1–6)

**Files:**
- Modify `internal/store/etcd/balancer.go`: `picker` gains `pending`; `hedgeCC.UpdateState` (`:103-117`) counts it; `Pick` (`:202-206`) and `placed` (`:242-291`) wait.
- Modify `internal/store/etcd/twoleg.go`: the comment at `:192-196` only.
- Modify `internal/store/etcd/dial_test.go`: `threeBehindProxies` (`:90-105`) gains a `threeBehindProxiesWith` form.
- Test `internal/store/etcd/balancer_test.go`: new test; the comment of `TestTheSecondLegSharesTheOnlyReadyMember` (`:243-245`).
- Test `internal/store/etcd/feed_dark_test.go`: trace placements per leg; `contextWatch` helper; new test.

**Interfaces:**
- `type picker struct { ready []endpointsharding.ChildState; pending int; next *atomic.Uint32; sus *suspects; now func() time.Time }`
- `func (p *picker) placed(cands []endpointsharding.ChildState, start int, t *tried) (endpointsharding.ChildState, bool)`
- `func threeBehindProxiesWith(t *testing.T, before func([]*etcdtest.Proxy)) (*Store, *etcdtest.Cluster, []*etcdtest.Proxy)`
- `func contextWatch(t *testing.T, s *Store) (put func(name string), delivered func(name string, within time.Duration) bool)`
- `type placement struct { n int; on, other string }`, `func (tr *legTrace_) at(leg int) placement`, `func (tr *legTrace_) waitPlaced(t *testing.T, leg, after int, d time.Duration) placement`

- [ ] **Step 1: The proxies can be hung before the store dials.** In `dial_test.go`, replace `threeBehindProxies` (`:90-105`) with:

  ```go
  func threeBehindProxies(t *testing.T) (*Store, *etcdtest.Cluster, []*etcdtest.Proxy) {
  	t.Helper()
  	return threeBehindProxiesWith(t, nil)
  }

  // threeBehindProxiesWith is threeBehindProxies with before run on the proxies
  // before the store dials them: a proxy hung there holds its member's
  // connection connecting (gRPC waits up to 20 s for the server's handshake)
  // until it is let go, while the others are ready.
  func threeBehindProxiesWith(t *testing.T, before func([]*etcdtest.Proxy)) (*Store, *etcdtest.Cluster, []*etcdtest.Proxy) {
  	t.Helper()
  	c := etcdtest.StartCluster(t)
  	var ps []*etcdtest.Proxy
  	var eps []string
  	for _, e := range c.Endpoints {
  		p := etcdtest.NewProxy(t, strings.TrimPrefix(e, "http://"))
  		ps, eps = append(ps, p), append(eps, "http://"+p.Addr())
  	}
  	if before != nil {
  		before(ps)
  	}
  	s, err := Open(Config{Endpoints: eps, Prefix: etcdtest.Prefix(), CallTimeout: 500 * time.Millisecond})
  	if err != nil {
  		t.Fatal(err)
  	}
  	t.Cleanup(func() { s.Close() })
  	return s, c, ps
  }
  ```

- [ ] **Step 2: The trace keeps each leg's latest placement.** In `feed_dark_test.go`:
  - Add the field `placed [2]placement // each leg's latest opening` to `legTrace_`.
  - Below it, add:

    ```go
    // placement is a leg's latest opening as the trace saw it: how many it has
    // had (across the watch's restarts, whose openings count from 1 again), its
    // member, and the other leg's member at its pick.
    type placement struct {
    	n         int
    	on, other string
    }
    ```

  - In `traceLegs`'s hook, `case "open"`, inside the `if ... ok {` block, after the `tr.apart, tr.last = ...` line, add:

    ```go
    				tr.placed[leg] = placement{n: tr.placed[leg].n + 1, on: a, other: b}
    ```

  - Below `waitApart`, add:

    ```go
    func (tr *legTrace_) at(leg int) placement {
    	tr.mu.Lock()
    	defer tr.mu.Unlock()
    	return tr.placed[leg]
    }

    // waitPlaced waits up to d for leg's opening number after+1 or later, and
    // returns it, or fails the test with the trace.
    func (tr *legTrace_) waitPlaced(t *testing.T, leg, after int, d time.Duration) placement {
    	t.Helper()
    	for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
    		if p := tr.at(leg); p.n > after {
    			return p
    		}
    	}
    	p := tr.at(leg)
    	tr.dump(t)
    	t.Fatalf("leg %d was not opened again within %v (latest: opening %d, on %q)", leg, d, p.n, p.on)
    	return placement{}
    }
    ```

  - Below `dump`, add `contextWatch`. It is the loop and the helpers `TestAContextFeedFollowsWhicheverMemberGoesDark` writes inline (`:90-131`). The existing tests are left as they are.

    ```go
    // contextWatch runs FollowContexts's loop over s.WatchContexts until the test
    // ends. put writes a context named name, trying again past a dark member;
    // delivered reports whether the feed brought it within d.
    func contextWatch(t *testing.T, s *Store) (put func(name string), delivered func(name string, within time.Duration) bool) {
    	t.Helper()
    	ctx, cancel := context.WithCancel(context.Background())
    	t.Cleanup(cancel)
    	var mu sync.Mutex
    	seen := map[string]bool{}
    	from := uint64(0)
    	go func() {
    		for ctx.Err() == nil {
    			mu.Lock()
    			after := from
    			mu.Unlock()
    			s.WatchContexts(ctx, after, func(c store.ContextChange) {
    				mu.Lock()
    				seen[c.Key.Username] = true
    				from = max(from, c.Rev)
    				mu.Unlock()
    			}, func(rev uint64) { mu.Lock(); from = max(from, rev); mu.Unlock() }, nil)
    			time.Sleep(time.Second)
    		}
    	}()
    	put = func(name string) {
    		k := store.ContextKey{NAS: "leaf-01", Username: name}
    		for i := 0; i < 20; i++ { // a write may meet the dark member: try again
    			c, cc := context.WithTimeout(ctx, 500*time.Millisecond)
    			err := s.PutContext(c, k, store.Context{CtxID: name, Principal: "user:x", Username: name}, time.Hour)
    			cc()
    			if err == nil {
    				return
    			}
    		}
    		t.Fatalf("could not write %s", name)
    	}
    	delivered = func(name string, within time.Duration) bool {
    		for end := time.Now().Add(within); time.Now().Before(end); time.Sleep(50 * time.Millisecond) {
    			mu.Lock()
    			ok := seen[name]
    			mu.Unlock()
    			if ok {
    				return true
    			}
    		}
    		return false
    	}
    	return put, delivered
    }
    ```

- [ ] **Step 3: Write the failing tests.**
  - In `feed_dark_test.go`, add `"github.com/blanketfish/port49/internal/store/etcd/etcdtest"` to the imports, and below `TestAContextFeedFollowsWhicheverMemberGoesDark` add:

    ```go
    // The second leg is never placed on the first leg's member while another
    // member's connection is still being made: it waits for that member. Members
    // 1 and 2 are hung before the store dials, so their connections stay
    // connecting while member 0 is ready. The old picker put leg 1 on member 0
    // at once, and member 0 then going dark stalled the feed until a leg moved,
    // 2 s or more (#64, CI 42563304174).
    func TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShareTheFirsts(t *testing.T) {
    	s, _, ps := threeBehindProxiesWith(t, func(ps []*etcdtest.Proxy) { ps[1].Hang(true); ps[2].Hang(true) })
    	tr := traceLegs(t)
    	put, delivered := contextWatch(t, s)
    	first := tr.waitPlaced(t, 0, 0, 5*time.Second)
    	if first.on != ps[0].Addr() {
    		tr.dump(t)
    		t.Fatalf("leg 0 was placed on %q with only member 0 (%s) ready", first.on, ps[0].Addr())
    	}
    	time.Sleep(time.Second) // the old picker placed leg 1 within milliseconds
    	if p := tr.at(1); p.n > 0 {
    		tr.dump(t)
    		t.Fatalf("leg 1 was placed on %s, the first leg's member, while members 1 and 2 were still connecting", p.on)
    	}
    	ps[1].Hang(false)
    	ps[2].Hang(false)
    	second := tr.waitPlaced(t, 1, 0, 5*time.Second)
    	if second.on == "" || second.on == first.on {
    		tr.dump(t)
    		t.Fatalf("leg 1 was placed on %q once members 1 and 2 were ready, leg 0 on %s", second.on, first.on)
    	}
    	ps[0].Hang(true) // the first leg's member going dark now costs nothing
    	tr.note("member 0 hung")
    	put("dark")
    	if !delivered("dark", 1500*time.Millisecond) {
    		tr.dump(t)
    		t.Fatal("member 0 dark, leg 1 apart: the feed had not brought a change written after it went dark in 1.5s")
    	}
    	ps[0].Hang(false)
    }
    ```

  - In `balancer_test.go`, below `TestTheSecondLegSharesTheOnlyReadyMember`, add:

    ```go
    // While another member is still connecting, the second leg does not take the
    // first's member: its pick waits, and gRPC picks again with the next picker,
    // once that member is ready or has failed (#64). A leg with nothing to
    // avoid, a hedged copy and a plain call still take the ready member.
    func TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShare(t *testing.T) {
    	p := readyPicker("a")
    	p.pending = 1
    	first := &tried{used: map[string]bool{}}
    	first.last.Store("a")
    	second := &tried{used: map[string]bool{}}
    	second.peer.Store(first)
    	if _, err := p.Pick(balancer.PickInfo{Ctx: withTriedSet(context.Background(), second)}); err != balancer.ErrNoSubConnAvailable {
    		t.Fatalf("the second leg's pick returned %v with another member connecting, want ErrNoSubConnAvailable", err)
    	}
    	if m := second.lastMember(); m != "" {
    		t.Fatalf("a pick that waits recorded member %q", m)
    	}
    	for name, ctx := range map[string]context.Context{
    		"a leg with no peer": withTriedSet(context.Background(), &tried{used: map[string]bool{}}),
    		"a hedged copy":      withTried(context.Background()),
    		"a plain call":       context.Background(),
    	} {
    		if addr, _ := pick(t, p, ctx); addr != "a" {
    			t.Fatalf("%s was placed on %q, want a", name, addr)
    		}
    	}
    }
    ```

  - Replace the comment of `TestTheSecondLegSharesTheOnlyReadyMember` (`:243-245`) with:

    ```go
    // With one member ready and every other failed (none connecting) the second
    // leg shares the first's: there is nothing to wait for, and watchLegs moves
    // a leg apart once another member is ready.
    ```

- [ ] **Step 4: Run them, expect red.**
  - First run `go test ./internal/store/etcd/ -count=1 -run '^TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShareTheFirsts$' -v`, with `balancer_test.go`'s new test temporarily commented out so the package builds. Expect FAIL at `leg 1 was placed on 127.0.0.1:<port>, the first leg's member, while members 1 and 2 were still connecting`.
    - If it fails anywhere else, stop and report the output: this test's premise (hung proxies hold connections `Connecting`) is wrong.
    - If it passes, stop and report.
  - Then restore the unit test. `go vet ./internal/store/etcd/` must fail on `p.pending` (unknown field).

- [ ] **Step 5: Implement.** In `balancer.go`:
  - Add `pending` to `picker` (`:172-177`):

    ```go
    type picker struct {
    	ready []endpointsharding.ChildState
    	// pending is how many of the channel's other members are connecting, or
    	// idle and about to: not ready yet, and not failed. A leg waits for one
    	// rather than share its peer's member (placed).
    	pending int
    	next    *atomic.Uint32 // the rotation, kept across the pickers of one channel
    	sus     *suspects
    	now     func() time.Time
    }
    ```

  - In `hedgeCC.UpdateState` (`:103-117`), replace the loop and the picker literal:

    ```go
    		var ready []endpointsharding.ChildState
    		pending := 0
    		for _, k := range kids {
    			switch st := k.State.ConnectivityState; {
    			case st == connectivity.Ready && len(k.Endpoint.Addresses) > 0:
    				ready = append(ready, k)
    			case st == connectivity.Connecting || st == connectivity.Idle:
    				pending++
    			}
    		}
    		if len(ready) > 0 {
    			s.Picker = &picker{ready: ready, pending: pending, next: &c.next, sus: &c.sus}
    			placingPickers.Add(1)
    		}
    ```

  - In `Pick`, replace `:203-206`:

    ```go
    	k := cands[start]
    	if t != nil {
    		var ok bool
    		if k, ok = p.placed(cands, start, t); !ok {
    			// gRPC holds the call and picks again with the channel's next
    			// picker: once a member connecting now is ready, or has failed.
    			return balancer.PickResult{}, balancer.ErrNoSubConnAvailable
    		}
    	}
    ```

  - Change `placed` to return `(endpointsharding.ChildState, bool)`. Each existing `return k` becomes `return k, true`. Replace its comment (`:242-245`) with:

    ```go
    // placed is the member among cands for a call with a tried-set: the first
    // from start that no earlier copy (or peer) has used, and false when the
    // call is to wait. Only a leg of a watch waits, and only when its peer's
    // member is the one ready and another member is still connecting: two legs
    // on one member go dark together (#64, CI 42563304174). With every other
    // member failed the legs share it, and watchLegs moves one apart once
    // another is ready (twoleg.go).
    ```

  - Immediately before `// Every candidate has had a copy: begin again.` (`:285`), add:

    ```go
    	// Here every ready member is the peer's (the loops above take any other).
    	if avoid != "" && p.pending > 0 {
    		return endpointsharding.ChildState{}, false
    	}
    ```

  - In `twoleg.go`, replace the comment at `:192-196` with:

    ```go
    		// Both legs on one member go dark together. The balancer shares a
    		// member only when every other member's connection has failed (a leg
    		// waits for one still connecting: balancer.go, #64), so a pair found on
    		// one is opened apart again once another is back: leg 1, from
    		// through+1, on whichever member is then free, and if none is, on the
    		// same again. The tries back off, so a cluster with one live member is
    		// not churned.
    ```

- [ ] **Step 6: Run, expect green.** Run `gofmt -l internal/store/etcd/ && go vet ./internal/store/etcd/`, then `go test ./internal/store/etcd/ -count=1 -run '^(TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShare|TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShareTheFirsts|TestTheSecondLegSharesTheOnlyReadyMember|TestAHedgedCallsCopiesAreEachPlacedOnAMemberNotYetUsed|TestTheSecondLegIsNotPlacedOnTheFirstsMemberWhenTheOthersAreSuspect|TestTheChannelsPickerIsThePlacingOneOnceAConnectionIsUp|TestAContextFeedFollowsWhicheverMemberGoesDark|TestTheMarksFeedFollowsWhicheverMemberGoesDark|TestAContextWatchIsLeftAloneWhileEveryMemberIsDark|TestAFeedFollowsTheLastTrustedMemberGoingDarkWhileTheOthersAreSuspect|TestOneEndpointNeverRelocatesOrReportsColocation)$' -v`. Expect PASS for each.

- [ ] **Step 7: Mutations.** Apply each one, run the named test, see it fail with the named message, then revert it. Paste each red line in the report.
  - **M1, the wait:** delete the `if avoid != "" && p.pending > 0 { ... }` block. Both new tests must fail: the unit test at "want ErrNoSubConnAvailable", the feed test at "leg 1 was placed on ...".
  - **M2, the count reaches the picker:** in `UpdateState`, delete the `case st == connectivity.Connecting || st == connectivity.Idle:` arm. The feed test must fail at "leg 1 was placed on ...". The unit test stays green, since it sets `pending` itself: this mutation proves the feed test sees the wiring.
  - **M3, the counted states:** change that arm to `case st == connectivity.TransientFailure:`. The feed test must fail at "leg 1 was placed on ...". This is the guard on Review Focus 2: a count of failed members would never let a leg share with every other member down. If a test passes here, write the case down for the reviewer.

- [ ] **Step 8: Commit.**

  `git add internal/store/etcd/balancer.go internal/store/etcd/twoleg.go internal/store/etcd/dial_test.go internal/store/etcd/balancer_test.go internal/store/etcd/feed_dark_test.go && git commit -m "fix(etcd): a feed's second leg waits for a member still connecting rather than share the first's (#64)"`

---

### Task 2: each leg leaves a hung member within the stall bound, for one the other leg is not on

**Files:**
- Test `internal/store/etcd/feed_dark_test.go`.

This test pins spec §13 decision 37's bound: "one silent for 2 s is opened again on a member neither leg is on, but only while a one-key read is answered" (`docs/design/2026-08-23-policy-engine-spec.md:8274-8277`). It uses a *hung* member, whose connection stays up and answers nothing, not a stopped one. It is expected green on arrival. Its mutations show it bites.

- [ ] **Step 1: Write the test.** Below the Task 1 test, add:

  ```go
  // A hung member (its connection up, nothing coming back) is left by the leg
  // on it within the stall decision 37 names: silent for feedStall while a read
  // is answered, seen on a tick (feedIdle/2), the probe (at most feedStall/2),
  // and the new opening's Created. It goes to a member neither leg is on. Each
  // leg in turn, so both are shown leaving one.
  func TestEachLegLeavesAHungMemberForOneTheOtherIsNotOn(t *testing.T) {
  	s, _, ps := threeBehindProxies(t)
  	tr := traceLegs(t)
  	put, delivered := contextWatch(t, s)
  	put("warm")
  	if !delivered("warm", 5*time.Second) {
  		t.Fatal("the watch delivered nothing on a healthy cluster")
  	}
  	tr.waitApart(t, 6*time.Second)
  	byAddr := map[string]*etcdtest.Proxy{}
  	for _, p := range ps {
  		byAddr[p.Addr()] = p
  	}
  	bound := feedStall + feedIdle/2 + feedStall/2 + 500*time.Millisecond
  	for _, leg := range []int{0, 1} {
  		was := tr.at(leg)
  		p := byAddr[was.on]
  		if p == nil {
  			tr.dump(t)
  			t.Fatalf("leg %d is on %q, which is no member's proxy", leg, was.on)
  		}
  		p.Hang(true)
  		tr.note("leg %d's member %s hung", leg, was.on)
  		hungAt := time.Now()
  		now := tr.waitPlaced(t, leg, was.n, bound)
  		tr.note("leg %d left it in %v", leg, time.Since(hungAt).Round(time.Millisecond))
  		p.Hang(false)
  		if now.on == was.on || now.on == now.other {
  			tr.dump(t)
  			t.Fatalf("leg %d was opened again on %s (it was on %s, the other leg on %s)", leg, now.on, was.on, now.other)
  		}
  		time.Sleep(3 * time.Second) // reconnect settles
  	}
  }
  ```

- [ ] **Step 2: Run, expect green.** Run `go test ./internal/store/etcd/ -count=1 -run '^TestEachLegLeavesAHungMemberForOneTheOtherIsNotOn$' -v`. Expect PASS, with each leg leaving in about 2.0 to 3.0 s. If it fails, stop and report the trace: that is a second defect, not this plan's to fix in passing.

- [ ] **Step 3: Mutations.** Apply each one, run the test, see it fail, then revert it. Paste the red lines.
  - **M4, the stall bound:** in `twoleg.go:316`, change `quiet >= feedStall` to `quiet >= 3*feedStall`. The new test must fail at "leg 0 was not opened again within 4s".
  - **M5, the probe gate:** in `twoleg.go:326`, change `if err == nil {` to `if err != nil {`. A hung member's leg is then never reopened while the store answers. The new test must fail at "was not opened again within".
  - **M6, a reopen avoids the other leg:** in `balancer.go`'s first loop in `placed` (`:259`), delete `&& addr != avoid`. `TestAHedgedCallsCopiesAreEachPlacedOnAMemberNotYetUsed` must fail at "both legs went to" or "a leg reopened went to". The rotation is cycled 12 and 6 times there, so it is deterministic. The new test may or may not catch it: which wrong member a mutant takes depends on the shared rotation. Record whether it did.

- [ ] **Step 4: Commit.**

  `git add internal/store/etcd/feed_dark_test.go && git commit -m "test(etcd): each leg of the context feed leaves a hung member within the stall, for one the other leg is not on (#64)"`

---

### Task 3: the design and the spec say when the legs share a member

**Files:**
- Modify `docs/design/2026-08-21-port49-design.md:2028-2029`.
- Modify `docs/design/2026-08-23-policy-engine-spec.md:8275-8277` (§13 decision 37, "The feeds run as two legs").

The operator pages already match. `docs/site/reference/alerts.md:443-455`, `docs/site/reference/metrics.md:284` and `deploy/alerts/README.md:63` say "port49 reaches only one etcd member for this feed", and that is now the only case left, apart from the start-up wait. `docs/site/operate/troubleshooting/index.md:239` only links the alert. None changes.

- [ ] **Step 1: The design.** Replace `etcd member (one member was ready first, or one recovered after both were placed together): the` with `etcd member (every other member's connection had failed when a leg was placed: a leg waits for a member still connecting rather than share, #64): the`.

- [ ] **Step 2: The spec.** In decision 37's "The feeds run as two legs" bullet, replace:

  ```
      a one-key read is answered: with every member dark (no quorum) a stream is left to revive when
      the store returns. The token pool's other watches (memberships, logouts) are one leg still.
  ```

  with:

  ```
      a one-key read is answered: with every member dark (no quorum) a stream is left to revive when
      the store returns. A leg is never placed on the other's member while another member's
      connection is up or still being made: it waits for that member (#64). The legs share one only
      when every other member's connection has failed, which `port49_store_feed_legs_colocated` shows
      until one is moved apart, or when the client has one endpoint, where they always share and
      are never moved. The token pool's other watches (memberships, logouts) are one leg still.
  ```

- [ ] **Step 3: The grep.** Run `grep -rn --exclude=realm.json --exclude='*.env' --exclude='*-key.pem' --exclude='*.keytab' -e 'ready first' -e 'one was up first' -e 'a pick never blocks' docs internal deploy`. It must find nothing.

- [ ] **Step 4: Run** `go test ./tests/ci/ -count=1 && make docs && git status --short`. Expect PASS, and no generated diff.

- [ ] **Step 5: Commit.**

  `git add docs/design/2026-08-21-port49-design.md docs/design/2026-08-23-policy-engine-spec.md && git commit -m "docs: a feed's legs share an etcd member only when every other member's connection has failed (#64)"`

---

### Task 4: Final verification

- [ ] **The flake check (Ruling 6).** Under the Global Constraints TMPDIR, run each command separately, in the foreground, each under 600000 ms. Each test takes about 6 to 15 s, so 20 runs fit with `-race`:
  - `go test -race ./internal/store/etcd/ -count=20 -timeout 590s -run '^TestAContextFeedFollowsWhicheverMemberGoesDark$'`
  - `go test -race ./internal/store/etcd/ -count=20 -timeout 590s -run '^TestTheMarksFeedFollowsWhicheverMemberGoesDark$'`
  - `go test -race ./internal/store/etcd/ -count=20 -timeout 590s -run '^TestTheSecondLegWaitsForAMemberStillConnectingRatherThanShareTheFirsts$'`
  - `go test -race ./internal/store/etcd/ -count=20 -timeout 590s -run '^TestEachLegLeavesAHungMemberForOneTheOtherIsNotOn$'`

  Paste each `ok`/`FAIL` line. Any FAIL is reported with its trace, not retried.
- [ ] **The lead runs** `make test && make vet && make docs && make test-rest && go test ./tests/ci/ -count=1 && git status --short` under that TMPDIR, and pastes the summary lines. A failure this plan does not name is reported, not fixed in passing.
- [ ] Run Task 3 Step 3's grep again.

## Operator-facing notes for the PR body

- **etcd: a feed's two watch legs no longer start on one member.** At a port49d start, or a watch restart, the context and marks feeds could put both legs on the first member whose connection came up. If that member then hung, the feed was silent for 2 to 3.5 s. Logins on contexts written in that window were denied `store_unavailable` (counted as `feed_behind` and in `port49_store_fence_timeouts_total`), and a revocation arrived as late. No change was lost, and `context_stale` was never involved. The second leg now waits, usually milliseconds, for another member's connection.
- **When the legs still share a member:** only when every other member's connection has failed, or when you configured one endpoint. `port49_store_feed_legs_colocated` and its 10-minute ticket mean what they meant: this node reaches only one etcd member for that feed. A member that is blackholed at start can hold the second leg waiting for up to 20 s (gRPC's connect timeout) before the gauge shows the share.
- No config, metric, alert or log line changes. No lab run.

## Left for later

- **Relocation still waits 2 s after the legs are found together.** That state is now reached only when every other member had failed, so a member's recovery is what ends it, and 2 s on top of a recovery costs little. The design's "as soon as another member is ready (tried again after 2 s, doubling to 30 s)" (`:2030-2031`) describes it loosely. Tightening it means telling `watchLegs` of a picker change, a separate change.
- **`TestAContextFeedFollowsWhicheverMemberGoesDark` and its marks twin repeat `contextWatch`'s loop inline.** Folding them onto the helper is a cleanup with no behavior change.
